//! The chunk resolver: `schedule.zig`'s decisions carried out with threads, sources and the
//! store. `Resolver.read` is what the FUSE server calls; `start` spawns one thread per fetch
//! slot (`lazy_slots`), in the supervising `zbx`, never in a setup child.
//!
//! The work is cut into steps that take the time as an argument and never wait, so the
//! simulation (`sim.zig`) runs the same code on one thread with a simulated clock:
//!
//!   - a reader: `read_begin` (from the store, or a ticket to wait on), then `read_poll` until it
//!     is done; `read` is the two with a condition wait between.
//!   - a fetch slot: `slot_take` (under the lock: the next job, or the fill's plan), `slot_fetch`
//!     (no lock: the source, inflating, hashing and the store) and `slot_finish` (under the lock).
//!
//! Locks: `mutex` guards the schedule; `store_mutex` serialises every store call (the store's
//! temporary names and counters are not shared safely). The store lock is never taken while
//! `mutex` is held, and sources are called with neither.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const flate = std.compress.flate;
const constants = @import("../constants.zig");
const layout = @import("../store/layout.zig");
const lazy = @import("lazy.zig");
const land_mod = @import("land.zig");
const schedule_mod = @import("schedule.zig");
const index_mod = @import("index.zig");
const inflate_range = index_mod.inflate_range;
const range_trailer_bytes = index_mod.range_trailer_bytes;

const Schedule = schedule_mod.Schedule;
const Ticket = schedule_mod.Ticket;
const Result = schedule_mod.Result;
const Store = layout.Store;

const slots = constants.lazy_slots;
const job_chunks_max = constants.lazy_job_chunks_max;

pub const Options = struct {
    store: *Store,
    catalog: lazy.Catalog,
    /// Asked in order, before the registry. At most `lazy_sources_max - 1`.
    peers: []const lazy.Source,
    /// The layer blob, when the image came from a registry with a lazy index.
    registry: ?lazy.Range,
    log: lazy.Log,
    free: lazy.FreeBytes,
    /// Fetch the rest of the image in the background, in catalog order.
    fill: bool,
};

pub const InitError = error{ OutOfMemory, TooManySources };

/// What a reader step decided.
pub const Step = union(enum) {
    /// The chunk is in `out`, verified, this many bytes.
    done: u32,
    failed: lazy.ReadError,
    /// Wait for a wake-up or until this time (ms), then `read_poll` again.
    wait: Waiting,
};

/// A reader's wait: its entry, when to look again, and when the read began (which bounds it).
pub const Waiting = struct { ticket: Ticket, until_ms: u64, began_ms: u64 };

/// One slot's job, copied out of the schedule so the fetch runs without the lock.
pub const Work = struct {
    job: schedule_mod.Job,
    purposes: [job_chunks_max]schedule_mod.Purpose,
    objects: [job_chunks_max]lazy.ObjectIndex,
    chunks: [job_chunks_max]u32,
    results: [job_chunks_max]Result,
    /// The entry was asked for again because the reader found its stored copy damaged.
    refetch: [job_chunks_max]bool,
    /// The chunk's put made its object whole.
    whole: [job_chunks_max]bool,
    sent: u64,
};

const SlotMemory = struct {
    /// `lazy_range_bytes_max`, and room for the trailer `inflate_range` writes after a range.
    range: []u8,
    chunk: []u8,
    put: []u8,
    window: *[flate.max_window_len]u8,
};

/// What `init` allocates, all of it, before any fetch: per slot a range, a chunk, the store's
/// copy buffer and an inflate window. The supervisor accepted the estimate (about 93 MiB here;
/// docs/decisions/2026-11-14-s2-resolver-choices.md); a bound that pushes it past this fails
/// the build.
pub const memory_bytes: u64 = slots * slot_bytes;
const slot_bytes: u64 = constants.lazy_range_bytes_max + range_trailer_bytes +
    constants.store_chunk_bytes + constants.store_io_buffer_bytes + flate.max_window_len;
const memory_bytes_max: u64 = 96 * 1024 * 1024;

const FillCursor = struct {
    object: lazy.ObjectIndex,
    chunk: u32,
    /// Objects found whole in this pass.
    whole: u32,
    paused_until_ms: u64,
    done: bool,
    /// A fill slot is planning from a copy of this cursor (without the lock).
    planning: bool,
};

pub const Resolver = struct {
    options: Options,
    sources_count: u8,
    names: [constants.lazy_sources_max][]const u8,
    schedule: Schedule,
    objects: []schedule_mod.ObjectState,
    memory: [slots]SlotMemory,
    fill: FillCursor,
    io: ?Io,
    mutex: Io.Mutex,
    store_mutex: Io.Mutex,
    /// Readers wait here for their entry; signalled when a job ends or the resolver stops.
    readers: Io.Condition,
    /// Slots wait here for work; signalled when an entry is queued or the resolver stops.
    workers: Io.Condition,
    threads: [slots]?std.Thread,

    /// Allocates every buffer the resolver will use; nothing is allocated after.
    pub fn init(resolver: *Resolver, gpa: std.mem.Allocator, options: Options) InitError!void {
        const registry: u32 = @intFromBool(options.registry != null);
        if (options.peers.len + registry > constants.lazy_sources_max) return error.TooManySources;
        assert(options.store.chunk_bytes > 0);
        resolver.options = options;
        resolver.sources_count = @intCast(options.peers.len + registry);
        resolver.names = @splat("");
        for (options.peers, 0..) |peer, at| resolver.names[at] = peer.name;
        if (options.registry) |range| resolver.names[options.peers.len] = range.name;
        resolver.objects = try gpa.alloc(schedule_mod.ObjectState, options.catalog.objects.len);
        errdefer gpa.free(resolver.objects);
        var made: u32 = 0;
        errdefer for (resolver.memory[0..made]) |memory| free_slot(gpa, memory);
        while (made < slots) : (made += 1) {
            resolver.memory[made] = try alloc_slot(gpa, options.store);
        }
        resolver.schedule.init(
            options.catalog,
            resolver.objects,
            options.store.chunk_bytes,
            resolver.names[0..resolver.sources_count],
            options.registry != null,
        );
        resolver.fill = .{
            .object = 0,
            .chunk = 0,
            .whole = 0,
            .paused_until_ms = 0,
            .done = !options.fill,
            .planning = false,
        };
        resolver.check_index();
        resolver.count_whole();
        resolver.io = null;
        resolver.mutex = .init;
        resolver.store_mutex = .init;
        resolver.readers = .init;
        resolver.workers = .init;
        resolver.threads = @splat(null);
    }

    /// Drops the registry hint of each object whose locations the resolver cannot use: not one
    /// per chunk, a range of no bytes or longer than `lazy_range_bytes_max`, or one that runs
    /// past the end of a blob's offsets. The index is untrusted; its peers still serve.
    fn check_index(resolver: *Resolver) void {
        const objects = resolver.options.catalog.objects;
        assert(resolver.objects.len == objects.len);
        for (objects, resolver.objects) |*object, *state| {
            assert(!state.no_registry);
            // The catalog's builder gives a chaining value per chunk, or none (`lazy.Object`).
            if (object.chaining.len > 0) assert(object.chaining.len == object.wanted.hashes.len);
            if (object.chaining.len > 0) assert(object.chaining.len >= 2);
            if (!locations_usable(object)) state.no_registry = true;
        }
    }

    fn locations_usable(object: *const lazy.Object) bool {
        assert(object.wanted.hashes.len <= constants.store_chunks_max);
        if (object.locations.len == 0) return true;
        if (object.locations.len != object.wanted.hashes.len) return false;
        for (object.locations) |location| {
            if (location.length == 0) return false;
            if (location.length > constants.lazy_range_bytes_max) return false;
            if (location.offset > std.math.maxInt(u64) - @as(u64, location.length)) return false;
        }
        return true;
    }

    /// Objects already whole in the store start `objects_local` (without the fill, nothing
    /// else would count them).
    fn count_whole(resolver: *Resolver) void {
        const objects = resolver.options.catalog.objects;
        assert(resolver.schedule.report.objects_local == 0);
        for (objects, 0..) |*object, at| {
            if (land_mod.object_is_whole(resolver.options.store, &object.wanted)) {
                resolver.schedule.mark_whole(@intCast(at));
            }
        }
        assert(resolver.schedule.report.objects_local <= objects.len);
    }

    fn alloc_slot(gpa: std.mem.Allocator, store: *const Store) error{OutOfMemory}!SlotMemory {
        assert(store.chunk_bytes <= constants.lazy_range_bytes_max);
        assert(store.chunk_bytes > 0);
        const range = try gpa.alloc(u8, constants.lazy_range_bytes_max + range_trailer_bytes);
        errdefer gpa.free(range);
        const chunk = try gpa.alloc(u8, store.chunk_bytes);
        errdefer gpa.free(chunk);
        const put = try gpa.alloc(u8, constants.store_io_buffer_bytes);
        errdefer gpa.free(put);
        const window = try gpa.create([flate.max_window_len]u8);
        return .{ .range = range, .chunk = chunk, .put = put, .window = window };
    }

    fn free_slot(gpa: std.mem.Allocator, memory: SlotMemory) void {
        assert(memory.range.len == constants.lazy_range_bytes_max + range_trailer_bytes);
        assert(memory.put.len == constants.store_io_buffer_bytes);
        gpa.free(memory.range);
        gpa.free(memory.chunk);
        gpa.free(memory.put);
        gpa.destroy(memory.window);
    }

    /// After `stop` (or when `start` was never called).
    pub fn deinit(resolver: *Resolver, gpa: std.mem.Allocator) void {
        for (resolver.threads) |thread| assert(thread == null);
        assert(resolver.objects.len == resolver.options.catalog.objects.len);
        for (resolver.memory) |memory| free_slot(gpa, memory);
        gpa.free(resolver.objects);
        resolver.* = undefined;
    }

    /// The name of source `index`: peers in order, then the registry.
    pub fn source_name(resolver: *const Resolver, index: u8) []const u8 {
        assert(index < resolver.sources_count);
        assert(resolver.names[index].len > 0);
        return resolver.names[index];
    }

    pub fn source_count(resolver: *const Resolver) u8 {
        assert(resolver.sources_count <= constants.lazy_sources_max);
        assert(resolver.schedule.sources_count == resolver.sources_count);
        return resolver.sources_count;
    }

    /// Spawns the fetch threads. `io` is the parent's (`std.Io.Threaded`).
    pub fn start(resolver: *Resolver, io: Io) std.Thread.SpawnError!void {
        assert(resolver.io == null);
        for (resolver.threads) |thread| assert(thread == null);
        resolver.io = io;
        // The fill waits `lazy_fill_idle_ms` from the start too: the container's first reads
        // come right after it.
        resolver.schedule.demand_ms = now_ms(io);
        errdefer resolver.stop();
        for (&resolver.threads, 0..) |*thread, slot| {
            const slot_index: u32 = @intCast(slot);
            thread.* = try std.Thread.spawn(.{}, slot_loop, .{ resolver, slot_index });
        }
    }

    /// Ends every wait (`Stopped`) and joins the fetch threads. Fetches in flight end within
    /// their attempt timeout. Readers in `read` wake and return `Stopped`; the caller (the FUSE
    /// server) joins its reader threads after this and before `deinit`, which frees what they
    /// read into.
    pub fn stop(resolver: *Resolver) void {
        const io = resolver.io.?;
        assert(resolver.threads.len == slots);
        resolver.mutex.lockUncancelable(io);
        if (!resolver.schedule.stopping) resolver.schedule.stop();
        resolver.readers.broadcast(io);
        resolver.workers.broadcast(io);
        resolver.mutex.unlock(io);
        resolver.drain_events();
        for (&resolver.threads) |*thread| {
            if (thread.*) |running| running.join();
            thread.* = null;
        }
    }

    pub fn report(resolver: *Resolver) lazy.Report {
        const io = resolver.io.?;
        resolver.mutex.lockUncancelable(io);
        defer resolver.mutex.unlock(io);
        const result = resolver.schedule.report;
        assert(result.objects_total == resolver.options.catalog.objects.len);
        assert(result.objects_local <= result.objects_total);
        return result;
    }

    /// Chunk `chunk` of object `object`, verified, into `out` (at least the chunk's length).
    /// Blocks until it is local or the read gives up (`lazy_read_deadline_ms` from its start at
    /// most, however often the chunk has to be asked for again).
    pub fn read(
        resolver: *Resolver,
        object: lazy.ObjectIndex,
        chunk: u32,
        out: []u8,
    ) lazy.ReadError!usize {
        const io = resolver.io.?;
        assert(object < resolver.options.catalog.objects.len);
        var step = resolver.read_begin(object, chunk, out, now_ms(io));
        while (true) {
            switch (step) {
                .done => |length| return length,
                .failed => |err| return err,
                .wait => |waiting| {
                    resolver.wait_until(waiting.ticket, waiting.until_ms);
                    step = resolver.read_poll(waiting, out, now_ms(io));
                },
            }
        }
    }

    /// Sleeps until the entry settles or `until_ms`. The entry is checked under the lock, so a
    /// broadcast between the reader's poll and this wait is not lost; the entry's deadline
    /// bounds the sleep too.
    fn wait_until(resolver: *Resolver, ticket: Ticket, until_ms: u64) void {
        const io = resolver.io.?;
        assert(until_ms < 1 << 62);
        resolver.mutex.lockUncancelable(io);
        defer resolver.mutex.unlock(io);
        if (resolver.schedule.stopping) return;
        if (resolver.schedule.settled_for(ticket)) return;
        const now = now_ms(io);
        const until = @min(until_ms, resolver.schedule.entry_of(ticket).deadline_ms);
        if (until <= now) return;
        const wait: Io.Timeout = .{ .duration = .{
            .raw = .fromMilliseconds(@intCast(until - now)),
            .clock = .awake,
        } };
        resolver.readers.waitTimeout(io, &resolver.mutex, wait) catch {};
    }

    /// A reader's first step. `out` holds at least the chunk's length.
    pub fn read_begin(
        resolver: *Resolver,
        object: lazy.ObjectIndex,
        chunk: u32,
        out: []u8,
        now: u64,
    ) Step {
        const wanted = &resolver.options.catalog.objects[object].wanted;
        assert(chunk < wanted.hashes.len);
        const chunk_bytes = resolver.options.store.chunk_bytes;
        assert(out.len >= schedule_mod.chunk_length(wanted, chunk_bytes, chunk));
        return resolver.look(object, chunk, out, now, now);
    }

    /// From the store, else an ask. `began` is when the read began: every ask of the read is
    /// bounded by `lazy_read_deadline_ms` from it, so a chunk that keeps going missing (a gc, a
    /// disk that damages what it is given) cannot hold a reader longer than that.
    fn look(
        resolver: *Resolver,
        object: lazy.ObjectIndex,
        chunk: u32,
        out: []u8,
        now: u64,
        began: u64,
    ) Step {
        assert(began <= now);
        assert(object < resolver.options.catalog.objects.len);
        if (resolver.read_store(object, chunk, out)) |length| {
            // Local already (resolved before, or another image's): no fetch, but the read still
            // counts towards sequential readahead.
            resolver.lock();
            resolver.schedule.note_read(object, chunk, now);
            resolver.wake_workers();
            resolver.unlock();
            return .{ .done = @intCast(length) };
        } else |err| switch (err) {
            error.NotLocal => return resolver.ask(object, chunk, now, began, false),
            // `put_chunk` replaces a chunk file that does not hash right: fetch it again.
            error.Damaged => return resolver.ask(object, chunk, now, began, true),
            // A put never replaces a whole object, and a store that refuses reads is not the
            // sources' to fix: the read fails, and an event says so.
            error.ObjectDamaged, error.Unreadable => return resolver.refuse(object, chunk),
        }
    }

    /// The read fails before any source is asked; an `E1203` event says so.
    fn refuse(resolver: *Resolver, object: lazy.ObjectIndex, chunk: u32) Step {
        assert(object < resolver.options.catalog.objects.len);
        assert(chunk < resolver.options.catalog.objects[object].wanted.hashes.len);
        resolver.lock();
        resolver.schedule.refuse(object, chunk);
        resolver.unlock();
        resolver.drain_events();
        return .{ .failed = error.Unavailable };
    }

    fn ask(
        resolver: *Resolver,
        object: lazy.ObjectIndex,
        chunk: u32,
        now: u64,
        began: u64,
        refetch: bool,
    ) Step {
        assert(object < resolver.options.catalog.objects.len);
        assert(began <= now);
        const until_ms = began + constants.lazy_read_deadline_ms;
        if (now >= until_ms) return resolver.refuse(object, chunk);
        const free = resolver.options.free.query(resolver.options.free.context);
        resolver.lock();
        if (resolver.schedule.stopping) {
            resolver.unlock();
            return .{ .failed = error.Stopped };
        }
        if (free < constants.lazy_store_free_bytes_min / 4) {
            resolver.schedule.store_full(object, chunk);
            resolver.unlock();
            resolver.drain_events();
            return .{ .failed = error.StoreFull };
        }
        const asked: schedule_mod.Ask = .{
            .purpose = .on_demand,
            .began_ms = began,
            .refetch = refetch,
        };
        const ticket = resolver.schedule.request(object, chunk, asked, now);
        // Every entry is a reader's or in a job: more readers than the table holds. An event.
        if (ticket == null) resolver.schedule.refuse(object, chunk);
        var until: u64 = until_ms;
        if (ticket) |held| {
            const own = resolver.schedule.reader_deadline(held, began);
            until = @min(own, resolver.schedule.entry_of(held).deadline_ms);
        }
        resolver.wake_workers();
        resolver.unlock();
        if (ticket) |held| {
            return .{ .wait = .{ .ticket = held, .until_ms = until, .began_ms = began } };
        }
        resolver.drain_events();
        return .{ .failed = error.Unavailable };
    }

    /// A reader's next step, after a wake-up or its time.
    pub fn read_poll(resolver: *Resolver, waiting: Waiting, out: []u8, now: u64) Step {
        assert(out.len > 0);
        assert(waiting.began_ms <= now);
        const ticket = waiting.ticket;
        resolver.lock();
        _ = resolver.schedule.tick(now);
        const entry = resolver.schedule.entry_of(ticket);
        const own_deadline = resolver.schedule.reader_deadline(ticket, waiting.began_ms);
        const object = entry.object;
        const chunk = entry.chunk;
        const state = entry.state;
        const failure = entry.failure;
        const until_ms = @min(entry.deadline_ms, own_deadline);
        // A later reader may have pushed the entry's deadline out; this one keeps its own.
        const late = (state == .queued or state == .fetching) and now >= own_deadline;
        if (late) resolver.schedule.give_up(ticket);
        if (state == .landed or state == .failed) resolver.schedule.release(ticket);
        resolver.unlock();
        resolver.drain_events();
        if (late) return .{ .failed = error.Unavailable };
        switch (state) {
            .free => unreachable,
            .queued, .fetching => return .{ .wait = .{
                .ticket = ticket,
                .until_ms = until_ms,
                .began_ms = waiting.began_ms,
            } },
            .failed => return .{ .failed = read_error(failure) },
            // Gone again (a gc) or damaged since it landed: looked at again, in the same bound.
            .landed => return resolver.look(object, chunk, out, now, waiting.began_ms),
        }
    }

    fn read_error(failure: schedule_mod.Failure) lazy.ReadError {
        assert(failure != .none);
        return switch (failure) {
            .none => unreachable,
            .unavailable => error.Unavailable,
            .store_full => error.StoreFull,
            .stopped => error.Stopped,
        };
    }

    /// The chunk from the store, verified (`read_local` hashes it). Without the store lock: a
    /// read uses none of the store's temporary names or counters, and holding the lock across
    /// a chunk's read and hash would stall every slot's put behind it.
    fn read_store(
        resolver: *Resolver,
        object: lazy.ObjectIndex,
        chunk: u32,
        out: []u8,
    ) land_mod.ReadError!usize {
        const entry = &resolver.options.catalog.objects[object];
        assert(chunk < entry.wanted.hashes.len);
        assert(out.len > 0);
        const store_lock: land_mod.StoreLock = .{
            .context = resolver,
            .lock = lock_store_opaque,
            .unlock = unlock_store_opaque,
        };
        const store = resolver.options.store;
        return land_mod.read_local(store, &entry.wanted, entry.chaining, chunk, out, &store_lock);
    }

    fn lock_store_opaque(context: *anyopaque) void {
        const resolver: *Resolver = @ptrCast(@alignCast(context));
        resolver.lock_store();
    }

    fn unlock_store_opaque(context: *anyopaque) void {
        const resolver: *Resolver = @ptrCast(@alignCast(context));
        resolver.unlock_store();
    }

    fn slot_loop(resolver: *Resolver, slot: u32) void {
        const io = resolver.io.?;
        assert(slot < slots);
        var work: Work = undefined;
        while (true) {
            resolver.mutex.lockUncancelable(io);
            const taken = while (true) {
                if (resolver.schedule.stopping) break false;
                const now = now_ms(io);
                const settled = resolver.schedule.settled;
                const wake = resolver.schedule.tick(now);
                // A deadline the tick failed is news to its readers.
                if (resolver.schedule.settled != settled) resolver.readers.broadcast(io);
                if (resolver.slot_take(slot, &work, now)) break true;
                const wake_fill = if (slot < constants.lazy_fetches_max)
                    wake
                else if (resolver.schedule.fill_idle_at(now)) |at|
                    earliest(wake, at)
                else
                    wake;
                const wait_ms = if (wake_fill) |at|
                    @max(at, now + 1) - now
                else
                    constants.lazy_down_probe_ms;
                const timeout: Io.Timeout = .{ .duration = .{
                    .raw = .fromMilliseconds(@intCast(@min(wait_ms, constants.lazy_down_probe_ms))),
                    .clock = .awake,
                } };
                resolver.workers.waitTimeout(io, &resolver.mutex, timeout) catch {};
            };
            resolver.mutex.unlock(io);
            resolver.drain_events();
            if (!taken) return;
            resolver.slot_fetch(slot, &work);
            resolver.lock();
            resolver.slot_finish(slot, &work, now_ms(io));
            resolver.readers.broadcast(io);
            resolver.wake_workers();
            resolver.unlock();
            resolver.drain_events();
        }
    }

    /// Under the lock: the slot's next job, copied into `work`. A fill slot with nothing queued
    /// plans the next stretch of the fill first. The plan reads the store, so it drops the
    /// lock; it moves a copy of the fill's cursor, and only one slot plans at a time, so the
    /// cursor itself changes only under the lock.
    pub fn slot_take(resolver: *Resolver, slot: u32, work: *Work, now: u64) bool {
        assert(slot < slots);
        assert(!resolver.schedule.jobs[slot].active);
        const fill_slot = slot >= constants.lazy_fetches_max;
        // The fill yields to readers: no fill request starts until none has asked for
        // `lazy_fill_idle_ms`, queued fill entries included.
        if (fill_slot) {
            if (resolver.schedule.fill_idle_at(now) != null) return false;
        }
        if (resolver.schedule.next_job(slot, now)) |job| {
            resolver.copy_work(job, work);
            return true;
        }
        if (!fill_slot) return false;
        if (!resolver.fill_due(now)) return false;
        var plan: FillPlan = undefined;
        plan.cursor = resolver.fill;
        resolver.fill.planning = true;
        resolver.unlock();
        resolver.fill_plan(slot, &plan, now);
        resolver.lock();
        resolver.fill_commit(&plan, now);
        if (resolver.schedule.stopping) return false;
        const job = resolver.schedule.next_job(slot, now) orelse return false;
        resolver.copy_work(job, work);
        return true;
    }

    fn fill_due(resolver: *const Resolver, now: u64) bool {
        assert(resolver.fill.object <= resolver.options.catalog.objects.len);
        assert(resolver.fill.whole <= resolver.options.catalog.objects.len);
        if (resolver.fill.done or resolver.fill.planning) return false;
        if (now < resolver.fill.paused_until_ms) return false;
        return resolver.schedule.queued_fill() == 0;
    }

    /// Under the lock: the plan's cursor becomes the fill's, and its chunks are queued.
    fn fill_commit(resolver: *Resolver, plan: *const FillPlan, now: u64) void {
        assert(resolver.fill.planning);
        assert(plan.count <= job_chunks_max);
        resolver.fill = plan.cursor;
        resolver.fill.planning = false;
        for (plan.whole[0..plan.whole_count]) |object| resolver.schedule.mark_whole(object);
        if (resolver.schedule.stopping) return;
        for (plan.objects[0..plan.count], plan.chunks[0..plan.count]) |object, chunk| {
            const asked: schedule_mod.Ask = .{ .purpose = .fill, .began_ms = now };
            _ = resolver.schedule.request(object, chunk, asked, now) orelse break;
        }
    }

    fn copy_work(resolver: *const Resolver, job: *const schedule_mod.Job, work: *Work) void {
        assert(job.active);
        assert(job.count >= 1);
        work.job = job.*;
        work.sent = 0;
        for (job.entries[0..job.count], 0..) |index, at| {
            const entry = &resolver.schedule.pending[index];
            work.purposes[at] = entry.purpose;
            work.objects[at] = entry.object;
            work.chunks[at] = entry.chunk;
            work.refetch[at] = entry.refetch;
            work.whole[at] = false;
            work.results[at] = .failed;
        }
    }

    /// Under the lock: the job's results go back into the schedule.
    pub fn slot_finish(resolver: *Resolver, slot: u32, work: *const Work, now: u64) void {
        assert(slot < slots);
        assert(resolver.schedule.jobs[slot].active);
        const count = work.job.count;
        for (work.results[0..count], work.purposes[0..count], 0..) |result, purpose, at| {
            if (purpose == .fill and result == .store_full) {
                resolver.fill.paused_until_ms = now + constants.lazy_down_probe_ms;
            }
            if (work.whole[at]) resolver.schedule.mark_whole(work.objects[at]);
        }
        resolver.schedule.job_done(slot, work.results[0..count], work.sent, now);
    }

    /// Without the lock: asks the job's source, checks and keeps what it sent.
    pub fn slot_fetch(resolver: *Resolver, slot: u32, work: *Work) void {
        assert(slot < slots);
        assert(work.job.count >= 1);
        const count = work.job.count;
        var missing: u32 = 0;
        for (0..count) |at| {
            // A chunk a reader found damaged is fetched even though its file is there.
            if (!work.refetch[at] and resolver.chunk_is_local(work.objects[at], work.chunks[at])) {
                work.results[at] = .local;
            } else {
                missing += 1;
            }
        }
        if (missing == 0) return;
        if (resolver.options.registry != null and work.job.source == resolver.peer_count()) {
            resolver.fetch_range(slot, work);
        } else {
            assert(count == 1);
            resolver.fetch_peer(slot, work);
        }
    }

    fn peer_count(resolver: *const Resolver) u8 {
        assert(resolver.options.peers.len < constants.lazy_sources_max);
        assert(resolver.sources_count >= resolver.options.peers.len);
        return @intCast(resolver.options.peers.len);
    }

    fn fetch_peer(resolver: *Resolver, slot: u32, work: *Work) void {
        const peer = resolver.options.peers[work.job.source];
        assert(work.job.count == 1);
        const wanted = &resolver.options.catalog.objects[work.objects[0]].wanted;
        const chunk = work.chunks[0];
        const length = schedule_mod.chunk_length(wanted, resolver.options.store.chunk_bytes, chunk);
        const buffer = resolver.memory[slot].chunk[0..@intCast(length)];
        const request: lazy.Request = .{
            .chunk = wanted.hashes[chunk],
            .length = @intCast(length),
            .object = wanted.id,
            .index = chunk,
            .timeout_ms = work.job.timeout_ms,
        };
        const fetched = peer.fetch(peer.context, &request, buffer) catch |err| {
            work.results[0] = result_of(err);
            return;
        };
        work.sent = @min(fetched.length, buffer.len);
        // A short answer is a failed fetch, never a lie: only bytes that hash wrong are.
        if (fetched.length != buffer.len) {
            work.results[0] = .failed;
            return;
        }
        work.results[0] = resolver.keep(slot, work, 0, buffer);
        if (work.results[0] == .lied) peer.lied(peer.context, &request, fetched.peer);
    }

    fn result_of(err: lazy.FetchError) Result {
        return switch (err) {
            error.NotFound => .not_found,
            error.TimedOut => .timed_out,
            error.Failed => .failed,
        };
    }

    fn fetch_range(resolver: *Resolver, slot: u32, work: *Work) void {
        const range = resolver.options.registry.?;
        assert(work.job.length <= constants.lazy_range_bytes_max);
        assert(work.job.length > 0);
        const span = resolver.missing_span(work);
        assert(span.length <= work.job.length);
        const buffer = resolver.memory[slot].range[0..span.length];
        const got = range.fetch(range.context, span.offset, buffer, work.job.timeout_ms);
        defer @memset(resolver.memory[slot].range[0 .. span.length + range_trailer_bytes], 0);
        const length = got catch |err| {
            for (work.results[0..work.job.count]) |*slot_result| {
                if (slot_result.* != .local) slot_result.* = result_of(err);
            }
            return;
        };
        work.sent = @min(length, buffer.len);
        var segment_end: u64 = 0;
        for (span.first..span.end) |at| {
            const object = &resolver.options.catalog.objects[work.objects[at]];
            const location = object.locations[work.chunks[at]];
            const segment_start = segment_end;
            segment_end += location.length;
            if (work.results[at] == .local) continue;
            if (segment_end > work.sent) {
                // A short answer: this chunk's bytes did not all come. A failed fetch, not a
                // lie (lazy.zig: only bytes that hash wrong are).
                work.results[at] = .failed;
                continue;
            }
            const stored_length = location.length;
            work.results[at] =
                resolver.inflate_and_keep(slot, work, @intCast(at), segment_start, stored_length);
        }
    }

    const Span = struct { first: u32, end: u32, offset: u64, length: u64 };

    /// The part of the job's range that holds its missing chunks: the chunks already local at
    /// either end are not asked for. A readahead entry is queued again after its chunk landed
    /// (the schedule does not look in the store), and a range that began with it would fetch
    /// it a second time (demo-s2 step 5 sent 19.0 MiB for 16 MiB). One local in the middle is
    /// still fetched: the range is one request.
    fn missing_span(resolver: *const Resolver, work: *const Work) Span {
        const count = work.job.count;
        var span: Span = .{ .first = count, .end = 0, .offset = work.job.offset, .length = 0 };
        for (work.results[0..count], 0..) |result, at| {
            if (result == .local) continue;
            span.first = @min(span.first, @as(u32, @intCast(at)));
            span.end = @intCast(at + 1);
        }
        assert(span.first < span.end); // `slot_fetch` fetches only with a chunk missing.
        for (0..span.end) |at| {
            const object = &resolver.options.catalog.objects[work.objects[at]];
            const location = object.locations[work.chunks[at]];
            if (at < span.first) span.offset += location.length else span.length += location.length;
        }
        assert(span.offset + span.length <= work.job.offset + work.job.length);
        return span;
    }

    /// Inflates the chunk whose compressed bytes are at `offset` in the slot's range buffer.
    /// `inflate_range` writes its trailer over the next chunk's first bytes, so they are kept
    /// and put back.
    fn inflate_and_keep(
        resolver: *Resolver,
        slot: u32,
        work: *Work,
        at: u32,
        offset: u64,
        length: u32,
    ) Result {
        const memory = &resolver.memory[slot];
        const wanted = &resolver.options.catalog.objects[work.objects[at]].wanted;
        const chunk_bytes = resolver.options.store.chunk_bytes;
        const size = schedule_mod.chunk_length(wanted, chunk_bytes, work.chunks[at]);
        assert(size <= memory.chunk.len);
        assert(length > 0);
        const from: usize = @intCast(offset);
        const range = memory.range[from..][0 .. length + range_trailer_bytes];
        const saved = range[length..][0..range_trailer_bytes].*;
        const out = memory.chunk[0..@intCast(size)];
        const inflated = inflate_range(range, length, out, memory.window);
        range[length..][0..range_trailer_bytes].* = saved;
        inflated catch return .lied;
        return resolver.keep(slot, work, at, out);
    }

    /// Checks `bytes` and keeps them; the free-space rule first.
    fn keep(
        resolver: *Resolver,
        slot: u32,
        work: *Work,
        at: u32,
        bytes: []const u8,
    ) Result {
        const object = &resolver.options.catalog.objects[work.objects[at]];
        assert(at < work.job.count);
        const free = resolver.options.free.query(resolver.options.free.context);
        const floor = if (work.purposes[at] == .fill)
            constants.lazy_store_free_bytes_min
        else
            constants.lazy_store_free_bytes_min / 4;
        // The free-space rule waits for the hash: a lie is a lie whatever the disk holds.
        const chunk_bytes = resolver.options.store.chunk_bytes;
        const length = schedule_mod.chunk_length(&object.wanted, chunk_bytes, work.chunks[at]);
        if (bytes.len != length) return .lied;
        if (!lazy.Digest.of(bytes).eql(object.wanted.hashes[work.chunks[at]])) return .lied;
        // The plain hash comes from the index and is not tied to the tree; the chaining value
        // is (`land.anchored`). `land` checks both again: the pair.
        if (!land_mod.anchored(object.chaining, work.chunks[at], chunk_bytes, bytes)) return .lied;
        if (free < floor) return .store_full;
        resolver.lock_store();
        defer resolver.unlock_store();
        const put = resolver.memory[slot].put;
        const store = resolver.options.store;
        const chunk = work.chunks[at];
        const landed = land_mod.land(store, put, &object.wanted, object.chaining, chunk, bytes);
        return switch (landed) {
            .landed => .landed,
            .whole => whole: {
                work.whole[at] = true;
                break :whole .landed;
            },
            .lied => unreachable, // Hashed just above.
            .content_mismatch => .content_mismatch,
            .store_full => .store_full,
            .busy => .busy,
            .failed => .failed,
        };
    }

    fn chunk_is_local(resolver: *Resolver, object: lazy.ObjectIndex, chunk: u32) bool {
        const wanted = &resolver.options.catalog.objects[object].wanted;
        assert(chunk < wanted.hashes.len);
        resolver.lock_store();
        defer resolver.unlock_store();
        return land_mod.is_local(resolver.options.store, wanted, chunk);
    }

    const FillPlan = struct {
        /// A copy of the fill's cursor, moved by the plan and committed under the lock.
        cursor: FillCursor,
        count: u32,
        objects: [job_chunks_max]lazy.ObjectIndex,
        chunks: [job_chunks_max]u32,
        /// Objects the plan found whole (or made, when empty), for `objects_local`.
        whole_count: u32,
        whole: [looks_max]lazy.ObjectIndex,
    };

    /// The chunks a plan looks at, at most, per call.
    const looks_max = constants.lazy_pending_max;

    /// Without the lock: the next chunks the fill needs, from the plan's cursor, at most a
    /// job's worth; empty objects are made on the way (with `slot`'s copy buffer).
    fn fill_plan(resolver: *Resolver, slot: u32, plan: *FillPlan, now: u64) void {
        const objects = resolver.options.catalog.objects;
        assert(plan.cursor.object <= objects.len);
        assert(slot >= constants.lazy_fetches_max);
        plan.count = 0;
        plan.whole_count = 0;
        var looked: u32 = 0;
        resolver.lock_store();
        defer resolver.unlock_store();
        while (plan.count < job_chunks_max and looked < looks_max) : (looked += 1) {
            if (plan.cursor.object == objects.len) {
                fill_pass_ended(&plan.cursor, objects.len, now);
                return;
            }
            resolver.fill_look(slot, plan);
        }
        assert(plan.count <= job_chunks_max);
        assert(plan.whole_count <= looks_max);
    }

    /// One step of the plan's cursor: one object found whole, or one chunk looked at.
    fn fill_look(resolver: *Resolver, slot: u32, plan: *FillPlan) void {
        const store = resolver.options.store;
        const cursor = &plan.cursor;
        const wanted = &resolver.options.catalog.objects[cursor.object].wanted;
        assert(cursor.chunk <= wanted.hashes.len);
        assert(plan.whole_count < looks_max);
        if (cursor.chunk == 0 and land_mod.object_is_whole(store, wanted)) {
            plan.whole[plan.whole_count] = cursor.object;
            plan.whole_count += 1;
            cursor.whole += 1;
            cursor.object += 1;
            return;
        }
        if (wanted.hashes.len == 0) {
            const free = resolver.options.free.query(resolver.options.free.context);
            if (free >= constants.lazy_store_free_bytes_min) {
                const put = resolver.memory[slot].put;
                if (land_mod.land_empty(store, put, wanted) == .whole) {
                    plan.whole[plan.whole_count] = cursor.object;
                    plan.whole_count += 1;
                    cursor.whole += 1;
                }
            }
            cursor.object += 1;
            return;
        }
        if (!land_mod.is_local(store, wanted, cursor.chunk)) {
            plan.objects[plan.count] = cursor.object;
            plan.chunks[plan.count] = cursor.chunk;
            plan.count += 1;
        }
        cursor.chunk += 1;
        if (cursor.chunk == wanted.hashes.len) {
            cursor.chunk = 0;
            cursor.object += 1;
        }
    }

    /// The cursor reached the end: done when every object was whole, else a new pass later.
    fn fill_pass_ended(cursor: *FillCursor, objects_count: usize, now: u64) void {
        assert(cursor.object == objects_count);
        assert(cursor.chunk == 0);
        if (cursor.whole == objects_count) {
            cursor.done = true;
            return;
        }
        cursor.object = 0;
        cursor.whole = 0;
        cursor.paused_until_ms = now + constants.lazy_down_probe_ms;
    }

    /// Hands queued events to the log, without the lock.
    pub fn drain_events(resolver: *Resolver) void {
        assert(resolver.sources_count <= constants.lazy_sources_max);
        var batch: [16]lazy.Event = undefined;
        while (true) {
            resolver.lock();
            var count: usize = 0;
            while (count < batch.len) : (count += 1) {
                batch[count] = resolver.schedule.pop_event() orelse break;
            }
            resolver.unlock();
            const log = resolver.options.log;
            for (batch[0..count]) |*event| log.event(log.context, event);
            if (count < batch.len) return;
        }
    }

    fn wake_workers(resolver: *Resolver) void {
        assert(resolver.schedule.sources_count == resolver.sources_count);
        if (resolver.io) |io| resolver.workers.broadcast(io);
    }

    // Without `start` (the simulation) there is one thread and no lock to take.
    fn lock(resolver: *Resolver) void {
        if (resolver.io) |io| resolver.mutex.lockUncancelable(io);
    }

    fn unlock(resolver: *Resolver) void {
        if (resolver.io) |io| resolver.mutex.unlock(io);
    }

    fn lock_store(resolver: *Resolver) void {
        if (resolver.io) |io| resolver.store_mutex.lockUncancelable(io);
    }

    fn unlock_store(resolver: *Resolver) void {
        if (resolver.io) |io| resolver.store_mutex.unlock(io);
    }
};

fn earliest(current: ?u64, candidate: u64) u64 {
    assert(candidate < std.math.maxInt(u64));
    return if (current) |held| @min(held, candidate) else candidate;
}

fn now_ms(io: Io) u64 {
    const now = Io.Clock.awake.now(io);
    const ms = now.toMilliseconds();
    assert(ms >= 0);
    return @intCast(ms);
}

comptime {
    assert(slots >= 2);
    assert(constants.lazy_store_free_bytes_min / 4 > 0);
    assert(memory_bytes <= memory_bytes_max);
}
