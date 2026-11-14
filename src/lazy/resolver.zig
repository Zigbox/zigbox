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
    done: usize,
    failed: lazy.ReadError,
    /// Wait for a wake-up or until this time (ms), then `read_poll` again.
    wait: Waiting,
};

pub const Waiting = struct { ticket: Ticket, until_ms: u64 };

/// One slot's job, copied out of the schedule so the fetch runs without the lock.
pub const Work = struct {
    job: schedule_mod.Job,
    purposes: [job_chunks_max]schedule_mod.Purpose,
    objects: [job_chunks_max]lazy.ObjectIndex,
    chunks: [job_chunks_max]u32,
    results: [job_chunks_max]Result,
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
        while (made < slots) : (made += 1) resolver.memory[made] = try alloc_slot(gpa, options.store);
        resolver.schedule.init(
            options.catalog,
            resolver.objects,
            options.store.chunk_bytes,
            resolver.names[0..resolver.sources_count],
            options.registry != null,
        );
        resolver.fill = .{ .object = 0, .chunk = 0, .whole = 0, .paused_until_ms = 0, .done = !options.fill };
        resolver.io = null;
        resolver.mutex = .init;
        resolver.store_mutex = .init;
        resolver.readers = .init;
        resolver.workers = .init;
        resolver.threads = @splat(null);
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
        errdefer resolver.stop();
        for (&resolver.threads, 0..) |*thread, slot| {
            thread.* = try std.Thread.spawn(.{}, slot_loop, .{ resolver, @as(u32, @intCast(slot)) });
        }
    }

    /// Ends every wait (`Stopped`) and joins the threads. Fetches in flight end within their
    /// attempt timeout.
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
        var result = resolver.schedule.report;
        result.objects_local = resolver.fill.whole;
        assert(result.objects_total == resolver.options.catalog.objects.len);
        assert(result.objects_local <= result.objects_total);
        return result;
    }

    /// Chunk `chunk` of object `object`, verified, into `out` (at least the chunk's length).
    /// Blocks until it is local or the read gives up (`lazy_read_deadline_ms` at most).
    pub fn read(resolver: *Resolver, object: lazy.ObjectIndex, chunk: u32, out: []u8) lazy.ReadError!usize {
        const io = resolver.io.?;
        assert(object < resolver.options.catalog.objects.len);
        var step = resolver.read_begin(object, chunk, out, now_ms(io));
        while (true) {
            switch (step) {
                .done => |length| return length,
                .failed => |err| return err,
                .wait => |waiting| {
                    resolver.wait_until(waiting.until_ms);
                    step = resolver.read_poll(waiting.ticket, out, now_ms(io));
                },
            }
        }
    }

    fn wait_until(resolver: *Resolver, until_ms: u64) void {
        const io = resolver.io.?;
        const now = now_ms(io);
        assert(until_ms < 1 << 62);
        if (until_ms <= now) return;
        resolver.mutex.lockUncancelable(io);
        defer resolver.mutex.unlock(io);
        if (resolver.schedule.stopping) return;
        const wait: Io.Timeout = .{ .duration = .{
            .raw = .fromMilliseconds(@intCast(until_ms - now)),
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
        assert(out.len >= schedule_mod.chunk_length(wanted, resolver.options.store.chunk_bytes, chunk));
        if (resolver.read_store(object, chunk, out)) |length| return .{ .done = length };
        return resolver.ask(object, chunk, now);
    }

    fn ask(resolver: *Resolver, object: lazy.ObjectIndex, chunk: u32, now: u64) Step {
        assert(object < resolver.options.catalog.objects.len);
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
        const ticket = resolver.schedule.request(object, chunk, .on_demand, now);
        resolver.wake_workers();
        resolver.unlock();
        if (ticket) |held| {
            return .{ .wait = .{ .ticket = held, .until_ms = now + constants.lazy_read_deadline_ms } };
        }
        // The table is full: more readers than the FUSE server has threads. Wait a little.
        return .{ .failed = error.Unavailable };
    }

    /// A reader's next step, after a wake-up or its time.
    pub fn read_poll(resolver: *Resolver, ticket: Ticket, out: []u8, now: u64) Step {
        assert(out.len > 0);
        resolver.lock();
        _ = resolver.schedule.tick(now);
        const entry = resolver.schedule.entry_of(ticket);
        const object = entry.object;
        const chunk = entry.chunk;
        const state = entry.state;
        const failure = entry.failure;
        const deadline = entry.deadline_ms;
        if (state == .landed or state == .failed) resolver.schedule.release(ticket);
        resolver.unlock();
        resolver.drain_events();
        switch (state) {
            .free => unreachable,
            .queued, .fetching => return .{ .wait = .{ .ticket = ticket, .until_ms = deadline } },
            .failed => return .{ .failed = read_error(failure) },
            .landed => {
                if (resolver.read_store(object, chunk, out)) |length| {
                    resolver.lock();
                    resolver.schedule.note_read(object, chunk, now);
                    resolver.wake_workers();
                    resolver.unlock();
                    return .{ .done = length };
                }
                // Gone again (a gc, a damaged file): ask once more, a fresh entry.
                return resolver.ask(object, chunk, now);
            },
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

    /// The chunk from the store, verified, or null.
    fn read_store(resolver: *Resolver, object: lazy.ObjectIndex, chunk: u32, out: []u8) ?usize {
        const wanted = &resolver.options.catalog.objects[object].wanted;
        assert(chunk < wanted.hashes.len);
        resolver.lock_store();
        defer resolver.unlock_store();
        const length = land_mod.read_local(resolver.options.store, wanted, chunk, out) catch
            return null;
        // The pair of `land`'s check: no byte reaches a reader that did not hash right here.
        assert(lazy.Digest.of(out[0..length]).eql(wanted.hashes[chunk]));
        return length;
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
                const wake = resolver.schedule.tick(now);
                if (resolver.slot_take(slot, &work, now)) break true;
                const wait_ms = if (wake) |at| @max(at, now + 1) - now else constants.lazy_down_probe_ms;
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
    /// plans the next stretch of the fill first (which needs the store, so it drops the lock).
    pub fn slot_take(resolver: *Resolver, slot: u32, work: *Work, now: u64) bool {
        assert(slot < slots);
        assert(!resolver.schedule.jobs[slot].active);
        if (resolver.schedule.next_job(slot, now)) |job| {
            resolver.copy_work(job, work);
            return true;
        }
        if (slot < constants.lazy_fetches_max) return false;
        if (resolver.fill.done or now < resolver.fill.paused_until_ms) return false;
        if (resolver.schedule.queued_fill() > 0) return false;
        resolver.unlock();
        var plan: FillPlan = undefined;
        resolver.fill_plan(&plan, now);
        resolver.lock();
        for (plan.objects[0..plan.count], plan.chunks[0..plan.count]) |object, chunk| {
            _ = resolver.schedule.request(object, chunk, .fill, now) orelse break;
        }
        const job = resolver.schedule.next_job(slot, now) orelse return false;
        resolver.copy_work(job, work);
        return true;
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
            work.results[at] = .failed;
        }
    }

    /// Under the lock: the job's results go back into the schedule.
    pub fn slot_finish(resolver: *Resolver, slot: u32, work: *const Work, now: u64) void {
        assert(slot < slots);
        assert(resolver.schedule.jobs[slot].active);
        const count = work.job.count;
        for (work.results[0..count], work.purposes[0..count]) |result, purpose| {
            if (purpose == .fill and result == .store_full) {
                resolver.fill.paused_until_ms = now + constants.lazy_down_probe_ms;
            }
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
            if (resolver.chunk_is_local(work.objects[at], work.chunks[at])) {
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
        const object = &resolver.options.catalog.objects[work.objects[0]];
        const buffer = resolver.memory[slot].chunk;
        const got = peer.fetch(peer.context, object.wanted.id, work.chunks[0], buffer, work.job.timeout_ms);
        const length = got catch |err| {
            work.results[0] = switch (err) {
                error.NotFound => .not_found,
                error.TimedOut => .timed_out,
                error.Failed => .failed,
            };
            return;
        };
        assert(length <= buffer.len);
        work.sent = length;
        work.results[0] = resolver.keep(slot, work, 0, buffer[0..length]);
        if (work.results[0] == .lied) peer.lied(peer.context, object.wanted.id, work.chunks[0]);
    }

    fn fetch_range(resolver: *Resolver, slot: u32, work: *Work) void {
        const range = resolver.options.registry.?;
        assert(work.job.length <= constants.lazy_range_bytes_max);
        assert(work.job.length > 0);
        const buffer = resolver.memory[slot].range[0..work.job.length];
        const got = range.fetch(range.context, work.job.offset, buffer, work.job.timeout_ms);
        defer @memset(resolver.memory[slot].range[0 .. work.job.length + range_trailer_bytes], 0);
        const length = got catch |err| {
            const result: Result = switch (err) {
                error.NotFound => .not_found,
                error.TimedOut => .timed_out,
                error.Failed => .failed,
            };
            for (work.results[0..work.job.count]) |*slot_result| {
                if (slot_result.* != .local) slot_result.* = result;
            }
            return;
        };
        assert(length <= buffer.len);
        work.sent = length;
        var segment_end: u64 = 0;
        for (0..work.job.count) |at| {
            const object = &resolver.options.catalog.objects[work.objects[at]];
            const location = object.locations[work.chunks[at]];
            const segment_start = segment_end;
            segment_end += location.length;
            if (work.results[at] == .local) continue;
            if (segment_end > length) {
                work.results[at] = .lied; // A short answer: this chunk's bytes did not come.
                continue;
            }
            work.results[at] = resolver.inflate_and_keep(slot, work, at, segment_start, location.length);
        }
    }

    /// Inflates the chunk whose compressed bytes are at `offset` in the slot's range buffer.
    /// `inflate_range` writes its trailer over the next chunk's first bytes, so they are kept
    /// and put back.
    fn inflate_and_keep(resolver: *Resolver, slot: u32, work: *Work, at: usize, offset: u64, length: u32) Result {
        const memory = &resolver.memory[slot];
        const wanted = &resolver.options.catalog.objects[work.objects[at]].wanted;
        const size = schedule_mod.chunk_length(wanted, resolver.options.store.chunk_bytes, work.chunks[at]);
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
    fn keep(resolver: *Resolver, slot: u32, work: *const Work, at: usize, bytes: []const u8) Result {
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
        if (free < floor) return .store_full;
        resolver.lock_store();
        defer resolver.unlock_store();
        const put = resolver.memory[slot].put;
        return switch (land_mod.land(resolver.options.store, put, &object.wanted, work.chunks[at], bytes)) {
            .landed => .landed,
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
        count: u32,
        objects: [job_chunks_max]lazy.ObjectIndex,
        chunks: [job_chunks_max]u32,
    };

    /// Without the lock: the next chunks the fill needs, from its cursor, at most a job's worth;
    /// empty objects are made on the way. Looks at most `lazy_pending_max` chunks per call.
    fn fill_plan(resolver: *Resolver, plan: *FillPlan, now: u64) void {
        const objects = resolver.options.catalog.objects;
        assert(resolver.fill.object <= objects.len);
        plan.count = 0;
        var looked: u32 = 0;
        resolver.lock_store();
        defer resolver.unlock_store();
        while (plan.count < job_chunks_max and looked < constants.lazy_pending_max) : (looked += 1) {
            if (resolver.fill.object == objects.len) {
                resolver.fill_pass_ended(now);
                return;
            }
            resolver.fill_look(plan);
        }
        assert(plan.count <= job_chunks_max);
    }

    /// One step of the fill's cursor: one object found whole, or one chunk looked at.
    fn fill_look(resolver: *Resolver, plan: *FillPlan) void {
        const store = resolver.options.store;
        const cursor = &resolver.fill;
        const wanted = &resolver.options.catalog.objects[cursor.object].wanted;
        assert(cursor.chunk <= wanted.hashes.len);
        if (cursor.chunk == 0 and land_mod.object_is_whole(store, wanted)) {
            cursor.whole += 1;
            cursor.object += 1;
            return;
        }
        if (wanted.hashes.len == 0) {
            const free = resolver.options.free.query(resolver.options.free.context);
            if (free >= constants.lazy_store_free_bytes_min) {
                if (land_mod.land_empty(store, resolver.memory[slots - 1].put, wanted) == .landed) {
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
    fn fill_pass_ended(resolver: *Resolver, now: u64) void {
        const cursor = &resolver.fill;
        assert(cursor.object == resolver.options.catalog.objects.len);
        assert(cursor.chunk == 0);
        if (cursor.whole == resolver.options.catalog.objects.len) {
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
            for (batch[0..count]) |*event| resolver.options.log.event(resolver.options.log.context, event);
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

fn now_ms(io: Io) u64 {
    const now = Io.Clock.awake.now(io);
    const ms = now.toMilliseconds();
    assert(ms >= 0);
    return @intCast(ms);
}

/// Slice 2's `index.inflate_range` (src/lazy/index.zig on claude/s2-slice2), copied unchanged
/// until that branch merges; then this and the two constants go, and the call above uses it.
/// Inflates one compressed range (whole deflate blocks from an empty history) to exactly
/// `out.len` bytes. `range` holds the `length` compressed bytes and `range_trailer_bytes` of
/// room after them, which this overwrites with an empty final block.
pub fn inflate_range(
    range: []u8,
    length: usize,
    out: []u8,
    window: *[flate.max_window_len]u8,
) error{Malformed}!void {
    assert(length >= 1);
    assert(range.len >= length + range_trailer_bytes);
    range[length..][0..range_trailer_bytes].* = range_trailer;
    var input: std.Io.Reader = .fixed(range[0 .. length + range_trailer_bytes]);
    var inflate: flate.Decompress = .init(&input, .raw, window);
    inflate.reader.readSliceAll(out) catch return error.Malformed;
    if (inflate.reader.takeByte()) |_| {
        return error.Malformed;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.Malformed,
    }
}

pub const range_trailer = [2]u8{ 0x03, 0x00 };
pub const range_trailer_bytes: u32 = range_trailer.len;

comptime {
    assert(slots >= 2);
    assert(constants.lazy_store_free_bytes_min / 4 > 0);
    assert(memory_bytes <= memory_bytes_max);
}
