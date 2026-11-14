//! The resolver's simulation: the real `Resolver` (its reader and slot steps, on one thread),
//! the real store on the simulated file system, a simulated clock, and seeded sources that are
//! slow, cut, missing chunks or lying (wrong bytes, wrong lengths, wrong offsets, short
//! answers). The `lazy_resolver` fuzzer runs one seed per iteration; the unit tests run fixed
//! scenarios.
//!
//! The properties, checked as the run goes and at its end:
//!   1. A read that succeeds returns the object's true bytes (whatever the sources sent).
//!   2. A read that fails ends within `lazy_read_deadline_ms` of its start, and within
//!      `lazy_down_fail_ms` when every source it could use was down when it started; it has
//!      its coded event (`unavailable` or `store_full`).
//!   3. A lying source never changes a chunk in the store: every chunk file and object holds
//!      the true bytes, and the store is whole (`test_support.check_whole`), after a crash at a
//!      write point too.
//!   4. With honest sources that answer in time and a disk with room, every read succeeds and
//!      the fill makes every object whole.
//!   5. A source that sent wrong bytes is named in a `lied` event, and a peer is told.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const fs_sim = @import("../store/fs_sim.zig");
const layout = @import("../store/layout.zig");
const object_mod = @import("../store/object.zig");
const support = @import("../store/test_support.zig");
const xattrs = @import("../store/xattrs.zig");
const lazy = @import("lazy.zig");
const resolver_mod = @import("resolver.zig");
const land = @import("land.zig");
const chunks_mod = @import("../store/chunks.zig");

const Digest = lazy.Digest;
const Resolver = resolver_mod.Resolver;
const Prng = std.Random.DefaultPrng;

const root_path = "/data/store";
const chunk_bytes: u32 = 64;
const objects_max = 12;
const chunks_per_object_max = 6;
const content_bytes_max = objects_max * chunks_per_object_max * chunk_bytes;
const peers_max = 3;
const readers_max = constants.lazy_fuse_threads;
const reads_per_reader_max = 12;
const events_max = 1024;
/// A stored deflate block's header: BFINAL 0, BTYPE 00, padding, LEN, NLEN.
const stored_header_bytes = 5;
const blob_bytes_max = content_bytes_max + objects_max * chunks_per_object_max * stored_header_bytes;

const attrs: object_mod.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };

/// How one source behaves for a run.
pub const Behaviour = struct {
    latency_max_ms: u32 = 200,
    /// Per mille of calls answered after `lazy_attempt_timeout_ms` or more.
    slow_per_mille: u16 = 0,
    not_found_per_mille: u16 = 0,
    failed_per_mille: u16 = 0,
    lie_per_mille: u16 = 0,
    /// Every call in [cut_from_ms, cut_to_ms) times out.
    cut_from_ms: u64 = 0,
    cut_to_ms: u64 = 0,
};

pub const Scenario = struct {
    peers: u8,
    registry: bool,
    behaviours: [peers_max + 1]Behaviour,
    fill: bool,
    /// The disk reports this many free bytes (the resolver's floors are checked against it).
    free_bytes: u64 = constants.lazy_store_free_bytes_min * 4,
    /// The disk's real limit (ENOSPC), or null.
    bytes_max: ?u64 = null,
    crash_mutation: ?u32 = null,
    /// A gc removes an object or chunk now and then.
    gc_per_mille: u16 = 0,
    /// Every source honest and in time, room on disk: property 4 applies.
    honest: bool,
};

const SimSource = struct {
    sim: *Sim,
    index: u8,
    behaviour: Behaviour,
    lied_told: u32,
};

const Reader = struct {
    state: enum { idle, waiting, done },
    next_at_ms: u64,
    reads_left: u32,
    object: lazy.ObjectIndex,
    chunk: u32,
    began_ms: u64,
    all_down_at_start: bool,
    waiting: resolver_mod.Waiting,
    out: [chunk_bytes]u8,
};

const Event = struct { event: lazy.Event, at_ms: u64 };

pub const Sim = struct {
    prng: Prng,
    now_ms: u64,
    elapsed_ms: u64,
    gc_at_ms: u64,
    crashes: u32,
    lies_sent: [peers_max + 1]u32,
    /// Per source, a bit per object it lied about.
    lied_objects: [peers_max + 1]u16,
    scenario: Scenario,
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: layout.Store,
    content: [content_bytes_max]u8,
    content_len: usize,
    hashes: [objects_max * chunks_per_object_max]Digest,
    objects: [objects_max]lazy.Object,
    starts: [objects_max]usize,
    locations: [objects_max * chunks_per_object_max]lazy.Location,
    objects_count: u32,
    blob: [blob_bytes_max]u8,
    blob_len: usize,
    sources: [peers_max + 1]SimSource,
    peer_interfaces: [peers_max]lazy.Source,
    resolver: Resolver,
    readers: [readers_max]Reader,
    work: [constants.lazy_slots]resolver_mod.Work,
    ends_ms: [constants.lazy_slots]?u64,
    events: [events_max]Event,
    events_count: u32,
    reads_ok: u32,
    reads_failed: u32,
};

pub fn object_bytes(sim: *const Sim, object: lazy.ObjectIndex) []const u8 {
    assert(object < sim.objects_count);
    const size = sim.objects[object].wanted.size;
    return sim.content[sim.starts[object]..][0..@intCast(size)];
}

fn chunk_bytes_of(sim: *const Sim, object: lazy.ObjectIndex, chunk: u32) []const u8 {
    const bytes = object_bytes(sim, object);
    const start = @as(usize, chunk) * chunk_bytes;
    assert(start < bytes.len);
    return bytes[start..@min(bytes.len, start + chunk_bytes)];
}

/// Random objects, their catalog entries and the blob of stored deflate blocks they are in.
fn make_objects(sim: *Sim) void {
    const random = sim.prng.random();
    sim.objects_count = random.intRangeAtMost(u32, 1, objects_max);
    sim.content_len = 0;
    sim.blob_len = 0;
    var hashes_used: usize = 0;
    for (0..sim.objects_count) |at| {
        const size = if (random.uintLessThan(u8, 8) == 0)
            0
        else
            random.intRangeAtMost(usize, 1, chunks_per_object_max * chunk_bytes);
        const bytes = sim.content[sim.content_len..][0..size];
        random.bytes(bytes);
        if (size > 0) bytes[0] = @intCast(at); // Distinct objects.
        sim.starts[at] = sim.content_len;
        sim.content_len += size;
        var reader = object_mod.Reader.init(chunk_bytes);
        const hashes = sim.hashes[hashes_used..][0..chunks_per_object_max];
        if (size > 0) _ = reader.update(bytes, hashes);
        const whole = reader.finish(hashes);
        const count = reader.count;
        const wanted: lazy.Wanted = .{
            .id = object_mod.object_id(whole, attrs),
            .attrs = attrs,
            .size = size,
            .content = whole,
            .hashes = sim.hashes[hashes_used..][0..count],
        };
        const locations = sim.locations[hashes_used..][0..count];
        for (locations, 0..) |*location, chunk| location.* = append_block(sim, bytes, @intCast(chunk));
        sim.objects[at] = .{ .wanted = wanted, .locations = if (sim.scenario.registry) locations else &.{} };
        hashes_used += count;
    }
    assert(sim.content_len <= content_bytes_max);
}

fn append_block(sim: *Sim, bytes: []const u8, chunk: u32) lazy.Location {
    const start = @as(usize, chunk) * chunk_bytes;
    const piece = bytes[start..@min(bytes.len, start + chunk_bytes)];
    assert(piece.len > 0);
    const at = sim.blob_len;
    const length: u16 = @intCast(piece.len);
    sim.blob[at] = 0;
    std.mem.writeInt(u16, sim.blob[at + 1 ..][0..2], length, .little);
    std.mem.writeInt(u16, sim.blob[at + 3 ..][0..2], ~length, .little);
    @memcpy(sim.blob[at + stored_header_bytes ..][0..piece.len], piece);
    sim.blob_len += stored_header_bytes + piece.len;
    return .{ .offset = at, .length = @intCast(stored_header_bytes + piece.len) };
}

fn start_store(sim: *Sim) void {
    sim.host.init(1, &.{});
    sim.files.init(sim.prng.random().int(u64));
    sim.host.store_fs = &sim.files;
    sim.files.put_dir("/data", 0o755);
    support.make_store_directories(&sim.files, root_path);
    sim.store.at(sim.host.interface(), root_path);
    sim.store.chunk_bytes = chunk_bytes;
    sim.files.faults.bytes_max = sim.scenario.bytes_max;
    sim.files.faults.crash_mutation = sim.scenario.crash_mutation;
}

/// Lays out a run for `scenario` and starts the resolver (without threads).
pub fn setup(sim: *Sim, seed: u64, scenario: Scenario) void {
    assert(scenario.peers <= peers_max);
    sim.prng = .init(seed);
    sim.now_ms = 0;
    sim.scenario = scenario;
    start_store(sim);
    make_objects(sim);
    for (&sim.sources, 0..) |*source, at| {
        source.* = .{ .sim = sim, .index = @intCast(at), .behaviour = scenario.behaviours[at], .lied_told = 0 };
    }
    for (sim.peer_interfaces[0..scenario.peers], 0..) |*peer, at| {
        peer.* = .{ .context = &sim.sources[at], .name = peer_names[at], .fetch = peer_fetch, .lied = peer_lied };
    }
    const options: resolver_mod.Options = .{
        .store = &sim.store,
        .catalog = .{ .objects = sim.objects[0..sim.objects_count] },
        .peers = sim.peer_interfaces[0..scenario.peers],
        .registry = if (scenario.registry) .{
            .context = &sim.sources[scenario.peers],
            .name = "registry",
            .fetch = registry_fetch,
        } else null,
        .log = .{ .context = sim, .event = log_event },
        .free = .{ .context = sim, .query = free_bytes },
        .fill = scenario.fill,
    };
    sim.resolver.init(std.heap.page_allocator, options) catch @panic("out of memory");
    sim.ends_ms = @splat(null);
    sim.gc_at_ms = next_gc(sim);
    sim.crashes = 0;
    sim.lies_sent = @splat(0);
    sim.lied_objects = @splat(0);
    sim.events_count = 0;
    sim.reads_ok = 0;
    sim.reads_failed = 0;
    for (&sim.readers) |*reader| {
        reader.state = .idle;
        reader.next_at_ms = sim.prng.random().uintLessThan(u64, 5_000);
        reader.reads_left = sim.prng.random().intRangeAtMost(u32, 1, reads_per_reader_max);
        reader.chunk = 0;
        reader.object = 0;
    }
}

const peer_names = [peers_max][]const u8{ "peer a", "peer b", "peer c" };

fn source_of(context: *anyopaque) *SimSource {
    const source: *SimSource = @ptrCast(@alignCast(context));
    assert(source.index <= peers_max);
    return source;
}

/// How a call goes: the time it takes, or the error it ends in.
fn plan_call(source: *SimSource, deadline_ms: u32) lazy.FetchError!void {
    const sim = source.sim;
    const behaviour = source.behaviour;
    const random = sim.prng.random();
    assert(deadline_ms > 0);
    if (sim.now_ms >= behaviour.cut_from_ms and sim.now_ms < behaviour.cut_to_ms) {
        sim.elapsed_ms = deadline_ms;
        return error.TimedOut;
    }
    var latency: u64 = random.intRangeAtMost(u64, 1, @max(1, behaviour.latency_max_ms));
    if (per_mille(random, behaviour.slow_per_mille)) {
        latency = constants.lazy_attempt_timeout_ms + random.uintLessThan(u64, 10_000);
    }
    if (latency > deadline_ms) {
        sim.elapsed_ms = deadline_ms;
        return error.TimedOut;
    }
    sim.elapsed_ms = latency;
    if (per_mille(random, behaviour.failed_per_mille)) return error.Failed;
}

fn per_mille(random: std.Random, value: u16) bool {
    assert(value <= 1000);
    return random.uintLessThan(u16, 1000) < value;
}

fn peer_fetch(context: *anyopaque, id: Digest, index: u32, out: []u8, deadline_ms: u32) lazy.FetchError!usize {
    const source = source_of(context);
    const sim = source.sim;
    try plan_call(source, deadline_ms);
    const random = sim.prng.random();
    if (per_mille(random, source.behaviour.not_found_per_mille)) return error.NotFound;
    const object = find_object(sim, id) orelse return error.NotFound;
    const truth = chunk_bytes_of(sim, object, index);
    assert(out.len >= truth.len);
    @memcpy(out[0..truth.len], truth);
    if (!per_mille(random, source.behaviour.lie_per_mille)) return truth.len;
    sim.lies_sent[source.index] += 1;
    sim.lied_objects[source.index] |= @as(u16, 1) << @intCast(object);
    return lie(random, out, truth.len);
}

/// Wrong bytes, or a wrong length, or both.
fn lie(random: std.Random, out: []u8, length: usize) usize {
    assert(length > 0);
    assert(out.len >= length);
    switch (random.uintLessThan(u8, 3)) {
        0 => {
            out[random.uintLessThan(usize, length)] ^= 1 + random.uintLessThan(u8, 255);
            return length;
        },
        1 => return random.uintLessThan(usize, length),
        else => {
            if (length == out.len) return length - 1;
            out[length] = random.int(u8);
            return length + 1;
        },
    }
}

fn peer_lied(context: *anyopaque, id: Digest, index: u32) void {
    const source = source_of(context);
    assert(find_object(source.sim, id) != null);
    assert(index < chunks_per_object_max);
    source.lied_told += 1;
}

fn find_object(sim: *const Sim, id: Digest) ?lazy.ObjectIndex {
    assert(sim.objects_count <= objects_max);
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        if (object.wanted.id.eql(id)) return @intCast(at);
    }
    return null;
}

fn registry_fetch(context: *anyopaque, offset: u64, out: []u8, deadline_ms: u32) lazy.FetchError!usize {
    const source = source_of(context);
    const sim = source.sim;
    assert(out.len > 0);
    try plan_call(source, deadline_ms);
    if (offset >= sim.blob_len) return error.Failed;
    const random = sim.prng.random();
    var from: usize = @intCast(offset);
    const lying = per_mille(random, source.behaviour.lie_per_mille);
    if (lying and random.boolean()) {
        // A wrong offset: the blob from somewhere else.
        from = random.uintLessThan(usize, sim.blob_len);
    }
    const length = @min(out.len, sim.blob_len - from);
    @memcpy(out[0..length], sim.blob[from..][0..length]);
    if (lying) sim.lies_sent[source.index] += 1;
    if (lying and random.boolean()) return lie(random, out, length);
    return length;
}

fn log_event(context: *anyopaque, event: *const lazy.Event) void {
    const sim: *Sim = @ptrCast(@alignCast(context));
    assert(event.object < sim.objects_count);
    if (sim.events_count == events_max) return;
    sim.events[sim.events_count] = .{ .event = event.*, .at_ms = sim.now_ms };
    sim.events_count += 1;
}

fn free_bytes(context: *anyopaque) u64 {
    const sim: *Sim = @ptrCast(@alignCast(context));
    assert(sim.scenario.free_bytes < 1 << 62);
    return sim.scenario.free_bytes;
}


fn next_gc(sim: *Sim) u64 {
    assert(sim.scenario.gc_per_mille <= 1000);
    if (sim.scenario.gc_per_mille == 0) return std.math.maxInt(u64);
    const gap = 1_000_000 / @as(u64, sim.scenario.gc_per_mille);
    return sim.now_ms + 1 + sim.prng.random().uintLessThan(u64, gap);
}

/// Runs the readers, the slots and the fill until the readers are done and the fill has had
/// its time, then stops the resolver and checks the store.
pub fn run(sim: *Sim) void {
    const end_ms: u64 = 300_000;
    while (true) {
        faults(sim);
        finish_jobs(sim);
        step_readers(sim);
        take_jobs(sim);
        const next = next_time(sim) orelse break;
        assert(next > sim.now_ms);
        if (next > end_ms) break;
        sim.now_ms = next;
    }
    sim.resolver.schedule.stop();
    _ = sim.resolver.schedule.tick(sim.now_ms);
    for (&sim.ends_ms, 0..) |*end, slot| {
        if (end.* == null) continue;
        sim.resolver.slot_finish(@intCast(slot), &sim.work[slot], sim.now_ms);
        end.* = null;
    }
    sim.resolver.drain_events();
    for (&sim.readers) |*reader| {
        if (reader.state == .waiting) poll(sim, reader);
        assert(reader.state != .waiting);
    }
    check_end(sim);
    sim.resolver.deinit(std.heap.page_allocator);
}

/// A crash is followed by a restart (the resolver keeps going, as after a remount), and a gc
/// removes a whole object or one chunk file now and then.
fn faults(sim: *Sim) void {
    assert(sim.now_ms < 1 << 62);
    if (sim.files.crashed) {
        sim.files.restart();
        sim.crashes += 1;
        support.check_whole(&sim.files, root_path, chunk_bytes) catch @panic("store not whole after a crash");
    }
    if (sim.now_ms < sim.gc_at_ms) return;
    sim.gc_at_ms = next_gc(sim);
    const random = sim.prng.random();
    const object = random.uintLessThan(u32, sim.objects_count);
    const wanted = &sim.objects[object].wanted;
    var path_storage: @import("../store/fs.zig").PathBuf = undefined;
    if (land.object_is_whole(&sim.store, wanted)) {
        sim.files.remove_path(sim.store.object_path(&path_storage, wanted.id));
        return;
    }
    if (wanted.hashes.len == 0) return;
    const chunk = random.uintLessThan(u32, @intCast(wanted.hashes.len));
    const path = chunks_mod.partial_chunk(&sim.store, &path_storage, wanted.id, chunk);
    _ = sim.store.fs.lstat(path) catch return;
    sim.files.remove_path(path);
}

fn finish_jobs(sim: *Sim) void {
    assert(sim.now_ms < 1 << 62);
    var finished = false;
    for (&sim.ends_ms, 0..) |*end, slot| {
        const at = end.* orelse continue;
        if (at > sim.now_ms) continue;
        sim.resolver.slot_finish(@intCast(slot), &sim.work[slot], sim.now_ms);
        end.* = null;
        finished = true;
    }
    if (finished) sim.resolver.drain_events();
}

/// Every free slot takes what it can; its fetch runs now and its result is told at its end.
fn take_jobs(sim: *Sim) void {
    assert(!sim.resolver.schedule.stopping);
    _ = sim.resolver.schedule.tick(sim.now_ms);
    for (&sim.ends_ms, 0..) |*end, at| {
        if (end.* != null) continue;
        const slot: u32 = @intCast(at);
        if (!sim.resolver.slot_take(slot, &sim.work[slot], sim.now_ms)) continue;
        sim.elapsed_ms = 0;
        sim.resolver.slot_fetch(slot, &sim.work[slot]);
        end.* = sim.now_ms + @max(1, sim.elapsed_ms);
    }
    sim.resolver.drain_events();
}

fn next_time(sim: *Sim) ?u64 {
    const now = sim.now_ms;
    var next: ?u64 = null;
    for (sim.ends_ms) |end| {
        if (end) |at| next = earliest(next, at);
    }
    for (&sim.readers) |*reader| switch (reader.state) {
        .idle => next = earliest(next, reader.next_at_ms),
        .waiting => next = earliest(next, reader.waiting.until_ms),
        .done => {},
    };
    if (sim.resolver.schedule.tick(now)) |wake| next = earliest(next, wake);
    const fill = &sim.resolver.fill;
    if (!fill.done) next = earliest(next, @max(fill.paused_until_ms, now + 10));
    if (sim.gc_at_ms != std.math.maxInt(u64) and next != null) next = earliest(next, sim.gc_at_ms);
    const at = next orelse return null;
    // A wake that is due now (a probe with nothing to probe) moves time on a little.
    return if (at <= now) now + 10 else at;
}

fn earliest(current: ?u64, candidate: u64) u64 {
    assert(candidate < std.math.maxInt(u64));
    return if (current) |held| @min(held, candidate) else candidate;
}

fn step_readers(sim: *Sim) void {
    assert(sim.objects_count > 0);
    for (&sim.readers) |*reader| switch (reader.state) {
        .idle => if (reader.next_at_ms <= sim.now_ms) begin(sim, reader),
        .waiting => poll(sim, reader),
        .done => {},
    };
}

/// A new read: often the next chunk of the object just read (a sequential reader, which sets
/// off readahead), else a chunk anywhere.
fn begin(sim: *Sim, reader: *Reader) void {
    const random = sim.prng.random();
    assert(reader.reads_left > 0);
    const object = reader.object;
    const sequential = object < sim.objects_count and
        reader.chunk + 1 < sim.objects[object].wanted.hashes.len and random.uintLessThan(u8, 4) != 0;
    if (sequential) {
        reader.chunk += 1;
    } else {
        reader.object = random.uintLessThan(u32, sim.objects_count);
        const count: u32 = @intCast(sim.objects[reader.object].wanted.hashes.len);
        if (count == 0) {
            reader.next_at_ms = sim.now_ms + 1 + random.uintLessThan(u64, 2_000);
            return; // An empty file: nothing to read through the resolver.
        }
        reader.chunk = random.uintLessThan(u32, count);
    }
    reader.began_ms = sim.now_ms;
    reader.all_down_at_start = all_down(sim);
    const step = sim.resolver.read_begin(reader.object, reader.chunk, &reader.out, sim.now_ms);
    settle(sim, reader, step);
}

fn all_down(sim: *const Sim) bool {
    const schedule = &sim.resolver.schedule;
    assert(schedule.sources_count > 0);
    for (schedule.sources[0..schedule.sources_count]) |source| {
        if (!source.down) return false;
    }
    return true;
}

fn poll(sim: *Sim, reader: *Reader) void {
    assert(reader.state == .waiting);
    const ticket = reader.waiting.ticket;
    const step = sim.resolver.read_poll(ticket, &reader.out, sim.now_ms);
    if (step == .wait and !std.meta.eql(step.wait.ticket, ticket)) {
        // Landed and gone again (a gc): a fresh entry, a fresh deadline.
        reader.began_ms = sim.now_ms;
        reader.all_down_at_start = all_down(sim);
    }
    settle(sim, reader, step);
}

fn settle(sim: *Sim, reader: *Reader, step: resolver_mod.Step) void {
    assert(reader.reads_left > 0);
    switch (step) {
        .wait => |waiting| {
            assert(waiting.until_ms > sim.now_ms or sim.resolver.schedule.stopping);
            reader.state = .waiting;
            reader.waiting = waiting;
            return;
        },
        .done => |length| {
            // Property 1.
            const truth = chunk_bytes_of(sim, reader.object, reader.chunk);
            assert(length == truth.len);
            if (!std.mem.eql(u8, reader.out[0..length], truth)) @panic("a read returned wrong bytes");
            sim.reads_ok += 1;
        },
        .failed => |err| failed(sim, reader, err),
    }
    reader.reads_left -= 1;
    reader.state = if (reader.reads_left == 0) .done else .idle;
    reader.next_at_ms = sim.now_ms + 1 + sim.prng.random().uintLessThan(u64, 3_000);
}

/// Property 2: a failure is on time and has its event.
fn failed(sim: *Sim, reader: *const Reader, err: lazy.ReadError) void {
    assert(sim.now_ms >= reader.began_ms);
    sim.reads_failed += 1;
    if (sim.scenario.honest) @panic("a read failed with honest sources");
    if (err == error.Stopped) return;
    const took = sim.now_ms - reader.began_ms;
    if (took > constants.lazy_read_deadline_ms) @panic("a read failed after its deadline");
    if (reader.all_down_at_start and all_down(sim) and took > constants.lazy_down_fail_ms) {
        @panic("a read with every source down failed late");
    }
    const kind: lazy.Event.Kind = if (err == error.StoreFull) .store_full else .unavailable;
    if (find_event(sim, kind, reader.object, reader.chunk) == null) @panic("a failed read has no event");
}

pub fn find_event(sim: *const Sim, kind: lazy.Event.Kind, object: lazy.ObjectIndex, chunk: u32) ?*const Event {
    assert(sim.events_count <= events_max);
    for (sim.events[0..sim.events_count]) |*logged| {
        const event = &logged.event;
        if (event.kind == kind and event.object == object and event.chunk == chunk) return logged;
    }
    return null;
}

/// Properties 3, 4 and 5, once the run has ended.
fn check_end(sim: *Sim) void {
    assert(sim.resolver.schedule.jobs_active() == 0);
    if (sim.files.crashed) {
        sim.files.restart();
        sim.crashes += 1;
    }
    support.check_whole(&sim.files, root_path, chunk_bytes) catch @panic("store not whole");
    check_chunks(sim);
    check_lies(sim);
    if (!sim.scenario.honest) return;
    if (sim.reads_failed != 0) @panic("a read failed with honest sources");
    if (sim.scenario.fill) {
        for (sim.objects[0..sim.objects_count]) |*object| {
            if (!land.object_is_whole(&sim.store, &object.wanted)) @panic("the fill left an object");
        }
    }
}

/// Every chunk the store holds, whole object or chunk file, is the true chunk.
fn check_chunks(sim: *Sim) void {
    var out: [chunk_bytes]u8 = undefined;
    assert(sim.objects_count > 0);
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        for (0..object.wanted.hashes.len) |chunk| {
            const index: u32 = @intCast(chunk);
            const length = land.read_local(&sim.store, &object.wanted, index, &out) catch |err| switch (err) {
                error.NotLocal => continue,
                error.Damaged, error.Unreadable => @panic("the store holds a damaged chunk"),
            };
            const truth = chunk_bytes_of(sim, @intCast(at), index);
            if (!std.mem.eql(u8, out[0..length], truth)) @panic("the store holds a wrong chunk");
        }
    }
}

/// Property 5: a peer that sent wrong bytes is told each time and named once per object;
/// no source that sent only true bytes is named.
fn check_lies(sim: *const Sim) void {
    assert(sim.resolver.schedule.events_dropped == 0);
    assert(sim.events_count < events_max);
    var named: [peers_max + 1]u16 = @splat(0);
    for (sim.events[0..sim.events_count]) |*logged| {
        if (logged.event.kind != .lied) continue;
        const source = source_by_name(sim, logged.event.source);
        if (sim.lies_sent[source] == 0) @panic("an honest source was named a liar");
        const bit = @as(u16, 1) << @intCast(logged.event.object);
        if (named[source] & bit != 0) @panic("a lie was named twice for one object");
        named[source] |= bit;
    }
    for (sim.sources[0..sim.scenario.peers], 0..) |*source, at| {
        if (named[at] != sim.lied_objects[at]) @panic("a peer's lie was not named");
        if (source.lied_told != sim.lies_sent[at]) @panic("a peer was not told of its lie");
    }
}

fn source_by_name(sim: *const Sim, name: []const u8) u8 {
    assert(name.len > 0);
    for (peer_names[0..sim.scenario.peers], 0..) |peer, at| {
        if (std.mem.eql(u8, peer, name)) return @intCast(at);
    }
    assert(std.mem.eql(u8, name, "registry"));
    return sim.scenario.peers;
}

/// A seed's scenario: one honest run in four, the rest with faults at random strengths.
pub fn random_scenario(random: std.Random) Scenario {
    var scenario: Scenario = .{
        .peers = random.uintAtMost(u8, peers_max),
        .registry = random.boolean(),
        .behaviours = @splat(.{}),
        .fill = random.uintLessThan(u8, 4) != 0,
        .honest = random.uintLessThan(u8, 4) == 0,
    };
    if (scenario.peers == 0) scenario.registry = true;
    for (&scenario.behaviours) |*behaviour| {
        behaviour.latency_max_ms = random.intRangeAtMost(u32, 1, 3_000);
    }
    if (scenario.honest) return scenario;
    for (&scenario.behaviours) |*behaviour| random_behaviour(random, behaviour);
    switch (random.uintLessThan(u8, 6)) {
        0 => scenario.free_bytes = random.uintLessThan(u64, constants.lazy_store_free_bytes_min * 2),
        1 => scenario.bytes_max = random.uintLessThan(u64, content_bytes_max * 2),
        2 => scenario.crash_mutation = random.uintLessThan(u32, 400),
        3 => scenario.gc_per_mille = random.intRangeAtMost(u16, 1, 100),
        else => {},
    }
    return scenario;
}

fn random_behaviour(random: std.Random, behaviour: *Behaviour) void {
    assert(behaviour.latency_max_ms > 0);
    behaviour.slow_per_mille = some_per_mille(random);
    behaviour.not_found_per_mille = some_per_mille(random);
    behaviour.failed_per_mille = some_per_mille(random);
    behaviour.lie_per_mille = some_per_mille(random);
    if (random.uintLessThan(u8, 3) == 0) {
        behaviour.cut_from_ms = random.uintLessThan(u64, 60_000);
        behaviour.cut_to_ms = behaviour.cut_from_ms + random.uintLessThan(u64, 120_000);
    }
    assert(behaviour.cut_to_ms >= behaviour.cut_from_ms);
}

/// Mostly none, sometimes always, else anything: the extremes are where loops break.
fn some_per_mille(random: std.Random) u16 {
    const value: u16 = switch (random.uintLessThan(u8, 6)) {
        0, 1, 2 => 0,
        3 => 1000,
        else => random.uintAtMost(u16, 1000),
    };
    assert(value <= 1000);
    return value;
}

/// Large (the simulated file system's pool): one, reused.
var sim_state: Sim = undefined;

/// The `lazy_resolver` fuzzer: one seeded run.
pub fn fuzz_lazy_resolver(seed: u64) void {
    var prng: Prng = .init(seed);
    const scenario = random_scenario(prng.random());
    setup(&sim_state, seed, scenario);
    run(&sim_state);
    assert(sim_state.reads_ok + sim_state.reads_failed > 0 or sim_state.objects_count > 0);
}

fn honest_scenario(peers: u8, registry: bool, fill: bool) Scenario {
    assert(peers <= peers_max);
    assert(peers > 0 or registry);
    return .{ .peers = peers, .registry = registry, .behaviours = @splat(.{}), .fill = fill, .honest = true };
}

test "sim: honest sources serve every read and the fill makes every object whole" {
    for ([_]u8{ 0, 1, 2, 3 }) |peers| {
        for ([_]bool{ false, true }) |registry| {
            if (peers == 0 and !registry) continue;
            setup(&sim_state, 7 + peers, honest_scenario(peers, registry, true));
            run(&sim_state);
            try std.testing.expect(sim_state.reads_ok > 0);
            try std.testing.expectEqual(@as(u32, 0), sim_state.reads_failed);
        }
    }
}

test "sim: a peer that always lies is named once per object, told every time, and bypassed" {
    var scenario = honest_scenario(1, true, true);
    scenario.honest = false;
    scenario.behaviours[0].lie_per_mille = 1000;
    setup(&sim_state, 11, scenario);
    run(&sim_state);
    try std.testing.expect(sim_state.lies_sent[0] > 0);
    try std.testing.expectEqual(@as(u32, 0), sim_state.reads_failed);
    try std.testing.expectEqual(sim_state.lies_sent[0], sim_state.sources[0].lied_told);
}

test "sim: a registry that is cut fails reads on time, with their events" {
    var scenario = honest_scenario(0, true, false);
    scenario.honest = false;
    scenario.behaviours[0].cut_to_ms = std.math.maxInt(u64);
    setup(&sim_state, 13, scenario);
    run(&sim_state);
    try std.testing.expectEqual(@as(u32, 0), sim_state.reads_ok);
    try std.testing.expect(sim_state.reads_failed > 0);
}

test "sim: a disk below the floor refuses reads with store_full" {
    var scenario = honest_scenario(1, false, true);
    scenario.honest = false;
    scenario.free_bytes = 0;
    setup(&sim_state, 17, scenario);
    run(&sim_state);
    try std.testing.expectEqual(@as(u32, 0), sim_state.reads_ok);
    var store_full: u32 = 0;
    for (sim_state.events[0..sim_state.events_count]) |logged| {
        store_full += @intFromBool(logged.event.kind == .store_full);
    }
    try std.testing.expect(store_full > 0);
}

test "sim: seeds" {
    var seed: u64 = 0;
    while (seed < 40) : (seed += 1) fuzz_lazy_resolver(seed);
}
