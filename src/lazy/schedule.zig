//! The resolver's decisions, without threads, clocks or a store: which chunk is fetched next,
//! from which source, with which neighbours; when a read gives up; when a source is down. The
//! threaded driver (`resolver.zig`) and the simulation call it under one lock with the time in
//! milliseconds, and do the fetching, the hashing and the store work themselves.
//!
//! A *pending* entry is one chunk someone wants: a reader (on demand), the readahead or the
//! fill. Readers of the same chunk share one entry. An entry is *queued* until a fetch slot
//! takes it into a *job*, *fetching* while the job runs, and then *landed* (it is in the store),
//! queued again (that source failed; the next one is asked), or *failed*. Each entry asks the
//! sources in order (peers, then the registry), skipping a source that lied about its object
//! and a down source that is not due for its probe; when every source failed in a round, the
//! next round starts `lazy_down_fail_ms` after the last, until the entry's deadline.
//!
//! A source that failed (timed out, or failed) for a whole `lazy_read_deadline_ms` with no
//! success between is *down*: entries that can use only down sources give up `lazy_down_fail_ms`
//! after they were asked for, and the source is asked once per `lazy_down_probe_ms` (a probe)
//! until it answers. `not_found` is an answer, not a failure.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const lazy = @import("lazy.zig");

const sources_max = constants.lazy_sources_max;
const pending_max = constants.lazy_pending_max;
const slots = constants.lazy_slots;
const job_chunks_max = constants.lazy_job_chunks_max;

pub const Purpose = enum(u8) { on_demand, readahead, fill };

pub const State = enum(u8) { free, queued, fetching, landed, failed };

pub const Failure = enum(u8) { none, unavailable, store_full, stopped };

/// What a job's fetch did for one of its chunks.
pub const Result = enum(u8) {
    landed,
    /// Already in the store when the slot looked: nothing was fetched.
    local,
    lied,
    not_found,
    timed_out,
    failed,
    /// The store lock was held (gc): try again, not the source's fault.
    busy,
    store_full,
    /// The object's chunks do not make its content: the index is wrong about it.
    content_mismatch,
};

/// A pending entry, named so a reader can tell when its entry was reused.
pub const Ticket = struct { index: u16, generation: u32 };

pub const Pending = struct {
    state: State,
    purpose: Purpose,
    failure: Failure,
    /// A reader waited on it at some point: its failure is shown (`E1203`, `E1206`).
    wanted: bool,
    in_job: bool,
    /// A reader found the stored copy damaged: the slot fetches it even though a file of that
    /// name is there, and `put_chunk` replaces the bad copy.
    refetch: bool,
    waiters: u16,
    generation: u32,
    object: lazy.ObjectIndex,
    chunk: u32,
    requested_ms: u64,
    /// When the latest reader of it began: the base of the all-sources-down rule.
    asked_ms: u64,
    deadline_ms: u64,
    round_ms: u64,
    /// Sources asked in this round.
    tried: u8,
    outcomes: [sources_max]lazy.Outcome,
};

pub const Job = struct {
    active: bool,
    source: u8,
    count: u8,
    /// For the registry: the compressed range covering every entry's location, in order.
    offset: u64,
    length: u32,
    timeout_ms: u32,
    /// When the job was taken: a failure counts from the start of the attempt that failed.
    started_ms: u64,
    entries: [job_chunks_max]u16,
};

const SourceState = struct {
    failing_since_ms: ?u64,
    /// The last answer's time: a failure of an attempt begun before it counts from it.
    answered_ms: u64,
    down: bool,
    probe_at_ms: u64,
};

/// Per object of the catalog, sized at start.
pub const ObjectState = struct {
    /// Sources that lied about this object: never asked for it again.
    bad: u8,
    /// Its chunks do not make its content: every read of it fails.
    broken: bool,
    /// Consecutive chunk reads so far, for readahead.
    streak: u8,
    next_chunk: u32,
    /// Seen whole in the store: counted once in `report.objects_local`.
    whole: bool,
    /// The index's locations for it are malformed: the registry is not asked for it.
    no_registry: bool,
};

/// Who asks for a chunk, and since when: a reader's read is bounded by `lazy_read_deadline_ms`
/// from its own start, however often it asks again.
pub const Ask = struct {
    purpose: Purpose,
    began_ms: u64,
    refetch: bool = false,
};

pub const Schedule = struct {
    catalog: lazy.Catalog,
    objects: []ObjectState,
    chunk_bytes: u32,
    names: [sources_max][]const u8,
    /// Peers first, then the registry when there is one.
    sources_count: u8,
    registry: ?u8,
    sources: [sources_max]SourceState,
    pending: [pending_max]Pending,
    jobs: [slots]Job,
    events: [pending_max]lazy.Event,
    events_head: u32,
    events_count: u32,
    stopping: bool,
    /// Counts entries that landed or failed, so whoever ticks knows to wake the readers.
    settled: u64,
    /// When a reader last asked for a chunk that was not local (or when the resolver started):
    /// the fill waits until `lazy_fill_idle_ms` after it.
    demand_ms: u64,
    report: lazy.Report,

    /// `objects` holds one entry per catalog object.
    pub fn init(
        schedule: *Schedule,
        catalog: lazy.Catalog,
        objects: []ObjectState,
        chunk_bytes: u32,
        names: []const []const u8,
        registry: bool,
    ) void {
        assert(objects.len == catalog.objects.len);
        assert(names.len <= sources_max);
        assert(names.len >= @intFromBool(registry));
        const count: u32 = @intCast(names.len);
        const peers: u8 = @intCast(count - @intFromBool(registry));
        schedule.* = .{
            .catalog = catalog,
            .objects = objects,
            .chunk_bytes = chunk_bytes,
            .names = @splat(""),
            .sources_count = @intCast(count),
            .registry = if (registry) peers else null,
            .sources = @splat(.{
                .failing_since_ms = null,
                .answered_ms = 0,
                .down = false,
                .probe_at_ms = 0,
            }),
            .pending = undefined,
            .jobs = undefined,
            .events = undefined,
            .events_head = 0,
            .events_count = 0,
            .stopping = false,
            .settled = 0,
            .demand_ms = 0,
            .report = std.mem.zeroes(lazy.Report),
        };
        for (&schedule.pending) |*entry| entry.* = std.mem.zeroes(Pending);
        for (&schedule.jobs) |*job| job.* = std.mem.zeroes(Job);
        for (names, 0..) |name, at| schedule.names[at] = name;
        @memset(objects, .{
            .bad = 0,
            .broken = false,
            .streak = 0,
            .next_chunk = 0,
            .whole = false,
            .no_registry = false,
        });
        schedule.report.objects_total = @intCast(catalog.objects.len);
        for (catalog.objects) |*object| schedule.report.bytes_total += object.wanted.size;
    }

    /// Joins the entry for this chunk, or makes one. Null when the table is full: for a reader,
    /// only when every entry is a reader's or in a job (speculative entries make room for it);
    /// readahead and fill skip the chunk.
    pub fn request(
        schedule: *Schedule,
        object: lazy.ObjectIndex,
        chunk: u32,
        ask: Ask,
        now: u64,
    ) ?Ticket {
        assert(object < schedule.catalog.objects.len);
        assert(chunk < schedule.catalog.objects[object].wanted.hashes.len);
        assert(ask.began_ms <= now);
        const deadline_ms = ask.began_ms + constants.lazy_read_deadline_ms;
        if (ask.purpose == .on_demand) schedule.demand_ms = @max(schedule.demand_ms, now);
        if (schedule.find(object, chunk)) |index| {
            const entry = &schedule.pending[index];
            if (ask.purpose == .on_demand) {
                // A reader that joins brings its own deadline: it never inherits an older one.
                entry.purpose = .on_demand;
                entry.wanted = true;
                entry.waiters += 1;
                entry.deadline_ms = @max(entry.deadline_ms, deadline_ms);
                entry.asked_ms = @max(entry.asked_ms, ask.began_ms);
            }
            if (ask.refetch) entry.refetch = true;
            return .{ .index = index, .generation = entry.generation };
        }
        const index = schedule.find_free() orelse
            (if (ask.purpose == .on_demand) schedule.evict() else null) orelse return null;
        const entry = &schedule.pending[index];
        assert(entry.state == .free);
        entry.* = .{
            .state = .queued,
            .purpose = ask.purpose,
            .failure = .none,
            .wanted = ask.purpose == .on_demand,
            .in_job = false,
            .refetch = ask.refetch,
            .waiters = @intFromBool(ask.purpose == .on_demand),
            .generation = entry.generation +% 1,
            .object = object,
            .chunk = chunk,
            .requested_ms = now,
            .asked_ms = ask.began_ms,
            .deadline_ms = deadline_ms,
            .round_ms = now,
            .tried = 0,
            .outcomes = @splat(.not_tried),
        };
        if (schedule.objects[object].broken) schedule.fail(index, .unavailable);
        return .{ .index = index, .generation = entry.generation };
    }

    /// Frees a queued fill entry, else a queued readahead entry, for a reader: neither has a
    /// waiter, and either is asked for again later.
    fn evict(schedule: *Schedule) ?u16 {
        assert(pending_max <= std.math.maxInt(u16));
        assert(schedule.find_free() == null);
        var found: ?u16 = null;
        for (&schedule.pending, 0..) |*entry, at| {
            if (entry.state != .queued) continue;
            if (entry.purpose == .on_demand) continue;
            assert(entry.waiters == 0);
            assert(!entry.in_job);
            found = @intCast(at);
            if (entry.purpose == .fill) break;
        }
        const index = found orelse return null;
        schedule.pending[index].state = .free;
        return index;
    }

    fn find(schedule: *const Schedule, object: lazy.ObjectIndex, chunk: u32) ?u16 {
        assert(object < schedule.catalog.objects.len);
        assert(pending_max <= std.math.maxInt(u16));
        for (&schedule.pending, 0..) |*entry, index| {
            const live = entry.state == .queued or entry.state == .fetching;
            if (live and entry.object == object and entry.chunk == chunk) return @intCast(index);
        }
        return null;
    }

    fn find_free(schedule: *const Schedule) ?u16 {
        assert(pending_max > 0);
        assert(pending_max <= std.math.maxInt(u16));
        for (&schedule.pending, 0..) |*entry, index| {
            if (entry.state == .free) return @intCast(index);
        }
        return null;
    }

    pub fn entry_of(schedule: *const Schedule, ticket: Ticket) *const Pending {
        assert(ticket.index < pending_max);
        const entry = &schedule.pending[ticket.index];
        assert(entry.generation == ticket.generation);
        assert(entry.state != .free);
        return entry;
    }

    /// A reader is done with its entry (it landed, failed, or the reader gave up).
    pub fn release(schedule: *Schedule, ticket: Ticket) void {
        assert(ticket.index < pending_max);
        const entry = &schedule.pending[ticket.index];
        assert(entry.generation == ticket.generation);
        assert(entry.waiters > 0);
        entry.waiters -= 1;
        schedule.free_if_done(ticket.index);
    }

    fn free_if_done(schedule: *Schedule, index: u16) void {
        const entry = &schedule.pending[index];
        assert(entry.state != .free);
        const final = entry.state == .landed or entry.state == .failed;
        if (final and entry.waiters == 0 and !entry.in_job) entry.state = .free;
        if (entry.state == .fetching) assert(entry.in_job);
    }

    /// A reader read chunk `chunk` of `object`: after two consecutive chunks, the next
    /// `lazy_readahead_chunks` are asked for (those already local are skipped by the slot).
    pub fn note_read(schedule: *Schedule, object: lazy.ObjectIndex, chunk: u32, now: u64) void {
        assert(object < schedule.objects.len);
        const state = &schedule.objects[object];
        const count = schedule.catalog.objects[object].wanted.hashes.len;
        assert(chunk < count);
        if (schedule.stopping) return;
        // The same chunk again (FUSE reads a chunk in several pieces when nothing caches it):
        // neither a step forward nor a jump, so the streak stands.
        if (state.streak > 0 and chunk + 1 == state.next_chunk) return;
        state.streak = if (chunk == state.next_chunk) state.streak +| 1 else 1;
        state.next_chunk = chunk + 1;
        if (state.streak < 2) return;
        var ahead: u32 = 1;
        while (ahead <= constants.lazy_readahead_chunks) : (ahead += 1) {
            const next = chunk + ahead;
            if (next >= count) break;
            if (schedule.find(object, next) != null) continue;
            const ask: Ask = .{ .purpose = .readahead, .began_ms = now };
            _ = schedule.request(object, next, ask, now) orelse break;
        }
    }

    fn fail(schedule: *Schedule, index: u16, failure: Failure) void {
        const entry = &schedule.pending[index];
        if (entry.state != .fetching) assert(entry.state == .queued);
        assert(failure != .none);
        entry.state = .failed;
        schedule.settled += 1;
        entry.failure = failure;
        if (entry.wanted and failure == .unavailable) {
            schedule.emit(.unavailable, entry.object, entry.chunk, "", &entry.outcomes);
        }
        if (entry.wanted and failure == .store_full) {
            schedule.emit(.store_full, entry.object, entry.chunk, "", &entry.outcomes);
        }
        if (entry.wanted) schedule.report.errors += 1;
        schedule.free_if_done(index);
    }

    fn emit(
        schedule: *Schedule,
        kind: lazy.Event.Kind,
        object: lazy.ObjectIndex,
        chunk: u32,
        source: []const u8,
        outcomes: *const [sources_max]lazy.Outcome,
    ) void {
        assert(object < schedule.catalog.objects.len);
        assert(schedule.events_count <= pending_max);
        if (schedule.events_count == pending_max) {
            schedule.report.events_dropped += 1;
            return;
        }
        const at = (schedule.events_head + schedule.events_count) % pending_max;
        schedule.events[at] = .{
            .kind = kind,
            .object = object,
            .id = schedule.catalog.objects[object].wanted.id,
            .chunk = chunk,
            .source = source,
            .outcomes = outcomes.*,
            .sources_count = schedule.sources_count,
            .names = &schedule.names,
        };
        schedule.events_count += 1;
    }

    pub fn pop_event(schedule: *Schedule) ?lazy.Event {
        assert(schedule.events_count <= pending_max);
        assert(schedule.events_head < pending_max);
        if (schedule.events_count == 0) return null;
        const event = schedule.events[schedule.events_head];
        schedule.events_head = (schedule.events_head + 1) % pending_max;
        schedule.events_count -= 1;
        return event;
    }

    /// Whether source `source` can be asked for chunks of `object` at all.
    fn serves(schedule: *const Schedule, source: u8, object: lazy.ObjectIndex) bool {
        assert(source < schedule.sources_count);
        assert(object < schedule.objects.len);
        if (schedule.objects[object].bad & bit(source) != 0) return false;
        if (schedule.registry) |registry| {
            if (source == registry) {
                if (schedule.objects[object].no_registry) return false;
                return schedule.catalog.objects[object].locations.len > 0;
            }
        }
        return true;
    }

    /// The source an entry asks next, now, if any.
    fn candidate(schedule: *const Schedule, entry: *const Pending, now: u64) ?u8 {
        assert(entry.state == .queued);
        assert(schedule.sources_count <= sources_max);
        var source: u8 = 0;
        while (source < schedule.sources_count) : (source += 1) {
            if (entry.tried & bit(source) != 0) continue;
            if (!schedule.serves(source, entry.object)) continue;
            const state = &schedule.sources[source];
            if (state.down and now < state.probe_at_ms) continue;
            return source;
        }
        return null;
    }

    /// Whether some source not down could still serve the entry (else it gives up early).
    fn has_live_source(schedule: *const Schedule, entry: *const Pending) bool {
        assert(entry.object < schedule.objects.len);
        assert(schedule.sources_count <= sources_max);
        var source: u8 = 0;
        while (source < schedule.sources_count) : (source += 1) {
            if (!schedule.serves(source, entry.object)) continue;
            if (!schedule.sources[source].down) return true;
        }
        return false;
    }

    /// The time a reader that began at `began_ms` stops waiting on the ticket's entry: its own
    /// read deadline, or `lazy_down_fail_ms` from its start while every source it could use is
    /// down. A later reader joining the entry never moves an earlier reader's bound.
    pub fn reader_deadline(schedule: *const Schedule, ticket: Ticket, began_ms: u64) u64 {
        const entry = schedule.entry_of(ticket);
        assert(began_ms < 1 << 62);
        assert(entry.state != .free);
        if (schedule.has_live_source(entry)) return began_ms + constants.lazy_read_deadline_ms;
        return began_ms + constants.lazy_down_fail_ms;
    }

    fn has_any_source(schedule: *const Schedule, object: lazy.ObjectIndex) bool {
        assert(object < schedule.objects.len);
        assert(schedule.sources_count <= sources_max);
        var source: u8 = 0;
        while (source < schedule.sources_count) : (source += 1) {
            if (schedule.serves(source, object)) return true;
        }
        return false;
    }

    /// Fails what is past its deadline or has no source left, starts new rounds, and returns
    /// when it next needs a look (a deadline, a round or a probe), or null.
    pub fn tick(schedule: *Schedule, now: u64) ?u64 {
        assert(schedule.sources_count <= sources_max);
        assert(schedule.events_count <= pending_max);
        var wake: ?u64 = null;
        var source_index: u8 = 0;
        // Stopping ticks at time 0: no source's health is judged then.
        while (!schedule.stopping and source_index < schedule.sources_count) : (source_index += 1) {
            schedule.note_down(source_index, now);
        }
        for (&schedule.pending, 0..) |*entry, at| {
            const index: u16 = @intCast(at);
            if (entry.state != .queued and entry.state != .fetching) continue;
            if (schedule.stopping) {
                schedule.fail(index, .stopped);
                continue;
            }
            schedule.tick_entry(index, now);
            if (entry.state == .queued or entry.state == .fetching) {
                wake = earliest(wake, entry.deadline_ms);
                // A round already due has a candidate source, so a free slot takes it.
                const round_end = entry.round_ms + constants.lazy_down_fail_ms;
                if (entry.state == .queued and entry.tried != 0 and round_end > now) {
                    wake = earliest(wake, round_end);
                }
            }
        }
        // Only a probe still to come is a reason to wake: one already due is taken by the next
        // free slot, and returning `now` for it would hide the deadlines behind it.
        for (schedule.sources[0..schedule.sources_count]) |*source| {
            if (source.down and source.probe_at_ms > now) {
                wake = earliest(wake, source.probe_at_ms);
            }
        }
        if (wake) |at| assert(at > now);
        return wake;
    }

    fn tick_entry(schedule: *Schedule, index: u16, now: u64) void {
        const entry = &schedule.pending[index];
        if (entry.state != .fetching) assert(entry.state == .queued);
        assert(!schedule.stopping);
        if (!schedule.has_any_source(entry.object)) {
            // A fetching entry keeps its job's chance to land, but never past its deadline:
            // a deadline already passed must not become the next wake.
            if (entry.state == .queued or now >= entry.deadline_ms) {
                schedule.fail(index, .unavailable);
            }
            return;
        }
        if (!schedule.has_live_source(entry)) {
            entry.deadline_ms = @min(entry.deadline_ms, entry.asked_ms +
                constants.lazy_down_fail_ms);
            schedule.mark_down_outcomes(entry);
        }
        if (now >= entry.deadline_ms) {
            // A fetching entry fails too: its reader stops waiting. The job ends later and
            // lands its bytes all the same.
            schedule.fail(index, .unavailable);
            return;
        }
        if (entry.state != .queued or entry.tried == 0) return;
        if (schedule.candidate(entry, now) != null) return;
        if (now >= entry.round_ms + constants.lazy_down_fail_ms) {
            entry.tried = 0;
            entry.round_ms = now;
        }
    }

    fn mark_down_outcomes(schedule: *const Schedule, entry: *Pending) void {
        assert(entry.object < schedule.objects.len);
        assert(schedule.sources_count <= sources_max);
        var source: u8 = 0;
        while (source < schedule.sources_count) : (source += 1) {
            if (!schedule.sources[source].down) continue;
            if (entry.outcomes[source] == .not_tried) entry.outcomes[source] = .down;
        }
    }

    /// The next job for fetch slot `slot`, or null. Slots below `lazy_fetches_max` take
    /// on-demand entries (oldest first), then readahead; the rest take fill entries only.
    pub fn next_job(schedule: *Schedule, slot: u32, now: u64) ?*const Job {
        assert(slot < slots);
        assert(!schedule.jobs[slot].active);
        if (schedule.stopping) return null;
        const first = schedule.pick(slot, now) orelse return null;
        const entry = &schedule.pending[first];
        const source = schedule.candidate(entry, now).?;
        const job = &schedule.jobs[slot];
        job.* = .{
            .active = true,
            .source = source,
            .count = 0,
            .offset = 0,
            .length = 0,
            .timeout_ms = attempt_timeout(entry, now),
            .started_ms = now,
            .entries = undefined,
        };
        schedule.take(job, first);
        if (schedule.registry == source) schedule.coalesce(slot, now);
        const state = &schedule.sources[source];
        if (state.down) state.probe_at_ms = now + constants.lazy_down_probe_ms;
        assert(job.count >= 1);
        return job;
    }

    fn attempt_timeout(entry: *const Pending, now: u64) u32 {
        assert(now < entry.deadline_ms);
        assert(entry.state == .queued);
        const left = entry.deadline_ms - now;
        return @intCast(@min(left, constants.lazy_attempt_timeout_ms));
    }

    fn pick(schedule: *const Schedule, slot: u32, now: u64) ?u16 {
        assert(slot < slots);
        assert(pending_max <= std.math.maxInt(u16));
        const fill_slot = slot >= constants.lazy_fetches_max;
        var best: ?u16 = null;
        for (&schedule.pending, 0..) |*entry, at| {
            if (entry.state != .queued) continue;
            if (fill_slot != (entry.purpose == .fill)) continue;
            if (schedule.candidate(entry, now) == null) continue;
            if (best) |b| {
                const other = &schedule.pending[b];
                if (rank(entry) > rank(other)) continue;
                if (rank(entry) == rank(other) and entry.requested_ms >= other.requested_ms) {
                    continue;
                }
            }
            best = @intCast(at);
        }
        return best;
    }

    fn rank(entry: *const Pending) u8 {
        assert(entry.state == .queued);
        assert(@backingInt(entry.purpose) <= 2);
        return @backingInt(entry.purpose);
    }

    fn take(schedule: *Schedule, job: *Job, index: u16) void {
        const entry = &schedule.pending[index];
        assert(entry.state == .queued);
        assert(job.count < job_chunks_max);
        entry.state = .fetching;
        entry.in_job = true;
        entry.tried |= bit(job.source);
        job.entries[job.count] = index;
        job.count += 1;
        if (schedule.registry == job.source) {
            const where = schedule.location(entry);
            if (job.count == 1) {
                job.offset = where.offset;
                job.length = where.length;
            } else {
                assert(where.offset == job.offset + job.length);
                job.length += where.length;
            }
        }
    }

    fn location(schedule: *const Schedule, entry: *const Pending) lazy.Location {
        const object = &schedule.catalog.objects[entry.object];
        assert(entry.chunk < object.locations.len);
        const result = object.locations[entry.chunk];
        assert(result.length > 0);
        return result;
    }

    /// Adds the queued entries that continue the job's range, while they fit.
    fn coalesce(schedule: *Schedule, slot: u32, now: u64) void {
        const job = &schedule.jobs[slot];
        assert(job.count == 1);
        assert(schedule.registry == job.source);
        const fill_slot = slot >= constants.lazy_fetches_max;
        // A fill request is kept short: a reader that arrives waits behind it for the shared
        // registry client (docs/decisions/2026-11-18-s2-fill-idle.md).
        const range_max = if (fill_slot)
            constants.lazy_fill_range_bytes_max
        else
            constants.lazy_range_bytes_max;
        while (job.count < job_chunks_max) {
            const end = job.offset + job.length;
            var found: ?u16 = null;
            for (&schedule.pending, 0..) |*entry, at| {
                if (entry.state != .queued) continue;
                if (fill_slot != (entry.purpose == .fill)) continue;
                if (schedule.candidate(entry, now) != job.source) continue;
                const where = schedule.location(entry);
                if (where.offset != end) continue;
                if (job.length + where.length > range_max) continue;
                found = @intCast(at);
                break;
            }
            schedule.take(job, found orelse return);
        }
    }

    /// Whether the fill may take work now: no reader has asked a source for a chunk for
    /// `lazy_fill_idle_ms`. Else the time it may, for a fill slot's wake-up.
    pub fn fill_idle_at(schedule: *const Schedule, now: u64) ?u64 {
        assert(schedule.demand_ms < 1 << 62);
        assert(now < 1 << 62);
        const idle_at = schedule.demand_ms + constants.lazy_fill_idle_ms;
        if (now >= idle_at) return null;
        return idle_at;
    }

    /// The job in `slot` ended; `results[i]` is what happened to its entry `i`, `sent` the
    /// bytes the source sent.
    pub fn job_done(
        schedule: *Schedule,
        slot: u32,
        results: []const Result,
        sent: u64,
        now: u64,
    ) void {
        const job = &schedule.jobs[slot];
        assert(job.active);
        assert(results.len == job.count);
        schedule.report.source_bytes[job.source] += sent;
        schedule.note_health(job.source, results, job.started_ms, now);
        for (job.entries[0..job.count], results) |index, result| {
            const entry = &schedule.pending[index];
            assert(entry.in_job);
            entry.in_job = false;
            schedule.settle(index, job.source, result, now);
        }
        job.active = false;
    }

    fn note_health(
        schedule: *Schedule,
        source: u8,
        results: []const Result,
        started_ms: u64,
        now: u64,
    ) void {
        assert(source < schedule.sources_count);
        assert(started_ms <= now);
        const state = &schedule.sources[source];
        var answered = false;
        var failed = false;
        for (results) |result| switch (result) {
            .landed, .lied, .not_found, .content_mismatch, .store_full => answered = true,
            .timed_out, .failed => failed = true,
            .local, .busy => {},
        };
        if (answered) {
            state.failing_since_ms = null;
            state.answered_ms = now;
            state.down = false;
        } else if (failed) {
            if (state.failing_since_ms == null) {
                state.failing_since_ms = @max(started_ms, state.answered_ms);
            }
            schedule.note_down(source, now);
        }
    }

    /// A source failing, with no answer, since a whole `lazy_read_deadline_ms` ago is down. Checked
    /// as time passes, not only when a job ends: a read that fails on its deadline leaves its
    /// source down, so the next read gives up in `lazy_down_fail_ms` (the demo's cut network).
    fn note_down(schedule: *Schedule, source: u8, now: u64) void {
        assert(source < schedule.sources_count);
        const state = &schedule.sources[source];
        const since = state.failing_since_ms orelse return;
        assert(since <= now);
        if (state.down or now - since < constants.lazy_read_deadline_ms) return;
        state.down = true;
        state.probe_at_ms = now + constants.lazy_down_probe_ms;
    }

    fn settle(schedule: *Schedule, index: u16, source: u8, result: Result, now: u64) void {
        const entry = &schedule.pending[index];
        if (entry.state != .failed) assert(entry.state == .fetching);
        assert(source < schedule.sources_count);
        if (entry.state == .failed) {
            // The reader gave up, but a lie is still a lie: the source is not asked for this
            // object again, and it is named.
            if (result == .lied) {
                schedule.mark_bad(entry.object, entry.chunk, source, &entry.outcomes);
            }
            return schedule.free_if_done(index);
        }
        entry.state = .queued;
        switch (result) {
            .landed, .local => schedule.land(index, result),
            .lied => schedule.lied(index, source),
            .not_found => entry.outcomes[source] = .not_found,
            .timed_out => entry.outcomes[source] = .timed_out,
            .failed => entry.outcomes[source] = .failed,
            // The store was busy (a gc): the source keeps its turn, but not before the next
            // round, so a long gc is not met with a fetch loop.
            .busy => entry.round_ms = @max(entry.round_ms, now),
            .store_full => schedule.fail(index, .store_full),
            .content_mismatch => {
                schedule.objects[entry.object].broken = true;
                entry.outcomes[source] = .failed;
                schedule.fail(index, .unavailable);
            },
        }
    }

    fn land(schedule: *Schedule, index: u16, result: Result) void {
        const entry = &schedule.pending[index];
        assert(entry.state == .queued);
        if (result != .local) assert(result == .landed);
        entry.state = .landed;
        schedule.settled += 1;
        if (result == .landed) {
            const wanted = &schedule.catalog.objects[entry.object].wanted;
            const length = chunk_length(wanted, schedule.chunk_bytes, entry.chunk);
            if (entry.purpose == .fill) {
                schedule.report.fetched_fill_bytes += length;
            } else {
                schedule.report.fetched_on_demand_bytes += length;
            }
        }
        schedule.free_if_done(index);
    }

    fn lied(schedule: *Schedule, index: u16, source: u8) void {
        const entry = &schedule.pending[index];
        assert(entry.state == .queued);
        assert(source < schedule.sources_count);
        entry.outcomes[source] = .lied;
        schedule.mark_bad(entry.object, entry.chunk, source, &entry.outcomes);
    }

    /// The first lie of `source` about `object` is named (`W1202`); it is not asked again.
    fn mark_bad(
        schedule: *Schedule,
        object: lazy.ObjectIndex,
        chunk: u32,
        source: u8,
        outcomes: *const [sources_max]lazy.Outcome,
    ) void {
        assert(source < schedule.sources_count);
        const state = &schedule.objects[object];
        if (state.bad & bit(source) != 0) return;
        state.bad |= bit(source);
        schedule.emit(.lied, object, chunk, schedule.names[source], outcomes);
    }

    /// Ends every queued entry (`Stopped`) and takes no more jobs.
    pub fn stop(schedule: *Schedule) void {
        assert(!schedule.stopping);
        schedule.stopping = true;
        _ = schedule.tick(0);
        assert(schedule.stopping);
    }

    /// A read refused for want of disk: `E1206`.
    pub fn store_full(schedule: *Schedule, object: lazy.ObjectIndex, chunk: u32) void {
        assert(object < schedule.objects.len);
        assert(chunk < schedule.catalog.objects[object].wanted.hashes.len);
        const outcomes: [sources_max]lazy.Outcome = @splat(.not_tried);
        schedule.emit(.store_full, object, chunk, "", &outcomes);
        schedule.report.errors += 1;
    }

    /// A read refused before any source was asked: the pending table is full, or the store
    /// cannot give back a chunk it holds (unreadable, or a whole object that is damaged). Still
    /// an event, so no failed read goes unexplained.
    pub fn refuse(schedule: *Schedule, object: lazy.ObjectIndex, chunk: u32) void {
        assert(object < schedule.objects.len);
        assert(chunk < schedule.catalog.objects[object].wanted.hashes.len);
        const outcomes: [sources_max]lazy.Outcome = @splat(.not_tried);
        schedule.emit(.unavailable, object, chunk, "", &outcomes);
        schedule.report.errors += 1;
    }

    /// A reader stops waiting at its own deadline while its entry goes on for a later reader:
    /// its failure is shown and counted, and its ticket is released. The last reader of an
    /// entry fails the entry itself, so no one is left fetching for nobody.
    pub fn give_up(schedule: *Schedule, ticket: Ticket) void {
        const entry = &schedule.pending[ticket.index];
        assert(entry.generation == ticket.generation);
        assert(entry.waiters > 0);
        if (entry.state == .queued or entry.state == .fetching) {
            if (entry.waiters == 1) {
                schedule.fail(ticket.index, .unavailable);
            } else {
                schedule.emit(.unavailable, entry.object, entry.chunk, "", &entry.outcomes);
                schedule.report.errors += 1;
            }
        }
        schedule.release(ticket);
    }

    /// `object` is whole in the store: counted once, so `objects_local` never goes down.
    pub fn mark_whole(schedule: *Schedule, object: lazy.ObjectIndex) void {
        assert(object < schedule.objects.len);
        if (schedule.objects[object].whole) return;
        schedule.objects[object].whole = true;
        schedule.report.objects_local += 1;
        schedule.report.bytes_local += schedule.catalog.objects[object].wanted.size;
        assert(schedule.report.objects_local <= schedule.report.objects_total);
        assert(schedule.report.bytes_local <= schedule.report.bytes_total);
    }

    /// Whether a reader holding `ticket` has something to look at (its entry landed or failed).
    pub fn settled_for(schedule: *const Schedule, ticket: Ticket) bool {
        const entry = schedule.entry_of(ticket);
        assert(entry.state != .free);
        assert(entry.waiters > 0);
        return entry.state == .landed or entry.state == .failed;
    }

    /// Fill entries waiting for a slot.
    pub fn queued_fill(schedule: *const Schedule) u32 {
        var count: u32 = 0;
        for (&schedule.pending) |*entry| {
            count += @intFromBool(entry.state == .queued and entry.purpose == .fill);
        }
        assert(count <= pending_max);
        return count;
    }

    pub fn jobs_active(schedule: *const Schedule) u32 {
        var count: u32 = 0;
        for (&schedule.jobs) |*job| count += @intFromBool(job.active);
        assert(count <= slots);
        return count;
    }
};

pub fn chunk_length(wanted: *const lazy.Wanted, chunk_bytes: u32, chunk: u32) u64 {
    assert(chunk_bytes > 0);
    assert(chunk < wanted.hashes.len);
    const start = @as(u64, chunk) * chunk_bytes;
    assert(start < wanted.size);
    return @min(@as(u64, chunk_bytes), wanted.size - start);
}

fn bit(source: u8) u8 {
    assert(source < sources_max);
    assert(sources_max <= 8);
    return @as(u8, 1) << @intCast(source);
}

fn earliest(current: ?u64, candidate_ms: u64) u64 {
    assert(candidate_ms < 1 << 62);
    return if (current) |at| @min(at, candidate_ms) else candidate_ms;
}

comptime {
    assert(slots == constants.lazy_fetches_max + constants.lazy_fill_fetches_max);
    assert(job_chunks_max <= std.math.maxInt(u8));
}
