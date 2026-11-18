//! The resolver's simulation: the real `Resolver` (its reader and slot steps, on one thread),
//! the real store on the simulated file system, a simulated clock, and seeded sources that are
//! slow, cut, missing chunks, short (a failed fetch, never a lie) or lying (wrong bytes, wrong
//! offsets); and a gc that removes, damages or makes unreadable what the store holds. The
//! `lazy_resolver` fuzzer runs one seed per iteration; the unit tests run fixed scenarios.
//!
//! The properties, checked as the run goes and at its end:
//!   1. A read that succeeds returns the object's true bytes (whatever the sources sent).
//!   2. A read that fails ends within `lazy_read_deadline_ms` of its start (however often it
//!      asks again, and whoever else waits on its chunk), and within
//!      `lazy_down_fail_ms` when every source it could use was down when it started; it has
//!      its coded event (`unavailable` or `store_full`).
//!   3. A lying source never changes a chunk in the store: every chunk file and object holds
//!      the true bytes, and the store is whole (`test_support.check_whole`), after a crash at a
//!      write point too.
//!   4. With honest sources that answer in time and a disk with room, every read succeeds and
//!      the fill makes every object whole.
//!   5. A source that sent wrong bytes is named in a `lied` event, and a peer is told; a
//!      source is named only for an object it sent wrong bytes of.
//!
//! A forged catalog (`Scenario.forged`) lists, for one chunk of a many-chunk object, the plain
//! hash of other bytes, which every source serves: bytes that match the listed hash but not
//! the chunk's chaining value, so not the tree. Property 1 and 3 then say no reader and no
//! store file ever holds them.

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
const Schedule = @import("schedule.zig").Schedule;
const land = @import("land.zig");
const chunks_mod = @import("../store/chunks.zig");
const chaining_mod = @import("chaining.zig");

const Digest = lazy.Digest;
const Resolver = resolver_mod.Resolver;
const Prng = std.Random.DefaultPrng;

const root_path = "/data/store";
/// BLAKE3's piece, the smallest run a chaining value is defined for (`chaining.Subtree`).
const chunk_bytes: u32 = chaining_mod.piece_bytes;
const objects_max = 12;
const chunks_per_object_max = 6;
const content_bytes_max = objects_max * chunks_per_object_max * chunk_bytes;
const peers_max = 3;
const readers_max = constants.lazy_fuse_threads;
const reads_per_reader_max = 12;
const events_max = 1024;
const damaged_max = 8;
/// A stored deflate block's header: BFINAL 0, BTYPE 00, padding, LEN, NLEN.
const stored_header_bytes = 5;
const blob_bytes_max = content_bytes_max +
    objects_max * chunks_per_object_max * stored_header_bytes;

const attrs: object_mod.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };

/// How one source behaves for a run.
pub const Behaviour = struct {
    latency_max_ms: u32 = 200,
    /// Per mille of calls answered after `lazy_attempt_timeout_ms` or more.
    slow_per_mille: u16 = 0,
    not_found_per_mille: u16 = 0,
    failed_per_mille: u16 = 0,
    lie_per_mille: u16 = 0,
    /// Per mille of answers cut short: a failed fetch, never a lie.
    short_per_mille: u16 = 0,
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
    /// Of those faults, per mille that damage a stored chunk or make it unreadable instead.
    damage_per_mille: u16 = 0,
    /// Every source honest and in time, room on disk: property 4 applies.
    honest: bool,
    /// The catalog lists a forged hash for one chunk of a many-chunk object, and every source
    /// serves the bytes it names (the module doc). Never with `honest`.
    forged: bool = false,
};

const SimSource = struct {
    sim: *Sim,
    index: u8,
    behaviour: Behaviour,
    lied_told: u32,
    /// Fetches asked of this source.
    calls: u32,
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
/// A store file the sim damaged: a chunk file, or the whole object when `chunk` is null.
const Damage = struct { object: u32, chunk: ?u32 };
const PathBuf = @import("../store/fs.zig").PathBuf;

pub const Sim = struct {
    prng: Prng,
    now_ms: u64,
    elapsed_ms: u64,
    gc_at_ms: u64,
    /// Store files damaged or made unreadable on purpose: removed before the store is checked.
    damaged: [damaged_max]Damage,
    damaged_count: u8,
    crashes: u32,
    lies_sent: [peers_max + 1]u32,
    /// Per source, a bit per object it lied about.
    lied_objects: [peers_max + 1]u16,
    /// A bit per object the registry sent a wrong segment of.
    registry_wrong: u16,
    scenario: Scenario,
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: layout.Store,
    content: [content_bytes_max]u8,
    content_len: u32,
    hashes: [objects_max * chunks_per_object_max]Digest,
    chaining: [objects_max * chunks_per_object_max]Digest,
    /// The forged chunk (`Scenario.forged`), when the run has one, and the bytes served for it.
    forged: ?struct { object: lazy.ObjectIndex, chunk: u32 },
    forged_bytes: [chunk_bytes]u8,
    objects: [objects_max]lazy.Object,
    starts: [objects_max]u32,
    locations: [objects_max * chunks_per_object_max]lazy.Location,
    objects_count: u32,
    blob: [blob_bytes_max]u8,
    blob_len: u32,
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
        sim.content_len += @intCast(size);
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
        for (locations, 0..) |*location, chunk| {
            location.* = append_block(sim, bytes, @intCast(chunk));
        }
        const served: []const lazy.Location = if (sim.scenario.registry) locations else &.{};
        const values = sim.chaining[hashes_used..][0..count];
        for (values, 0..) |*value, chunk| {
            value.* = chaining_mod.run_value(chunk_bytes_in(bytes, chunk), chunk, chunk_bytes);
        }
        sim.objects[at] = .{
            .wanted = wanted,
            .locations = served,
            .chaining = if (count < 2) &.{} else values,
        };
        hashes_used += count;
    }
    assert(sim.content_len <= content_bytes_max);
    sim.forged = null;
    if (sim.scenario.forged) forge(sim);
}

fn chunk_bytes_in(bytes: []const u8, chunk: usize) []const u8 {
    const start = chunk * chunk_bytes;
    assert(start < bytes.len);
    return bytes[start..@min(bytes.len, start + chunk_bytes)];
}

/// Lists the hash of other bytes for one chunk of the first many-chunk object: what an index
/// whose chaining values are true but whose plain hashes are forged gives the resolver.
fn forge(sim: *Sim) void {
    assert(sim.scenario.forged);
    assert(!sim.scenario.honest);
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        if (object.chaining.len < 2) continue;
        const chunk: u32 = sim.prng.random().uintLessThan(u32, @intCast(object.chaining.len));
        const truth = chunk_bytes_of(sim, @intCast(at), chunk);
        const forged = sim.forged_bytes[0..truth.len];
        @memcpy(forged, truth);
        forged[forged.len - 1] ^= 0x5a;
        // The hashes are the sim's own array; the catalog's slice points into it.
        const first = (@intFromPtr(object.wanted.hashes.ptr) - @intFromPtr(&sim.hashes)) /
            @sizeOf(Digest);
        sim.hashes[first + chunk] = Digest.of(forged);
        sim.forged = .{ .object = @intCast(at), .chunk = chunk };
        return;
    }
}

/// The forged bytes, if `object`'s chunk `chunk` is the forged one.
fn forged_of(sim: *const Sim, object: lazy.ObjectIndex, chunk: u32) ?[]const u8 {
    const forged = sim.forged orelse return null;
    if (forged.object != object) return null;
    if (forged.chunk != chunk) return null;
    return sim.forged_bytes[0..chunk_bytes_of(sim, object, chunk).len];
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
    sim.blob_len += @intCast(stored_header_bytes + piece.len);
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
        source.* = .{
            .sim = sim,
            .index = @intCast(at),
            .behaviour = scenario.behaviours[at],
            .lied_told = 0,
            .calls = 0,
        };
    }
    for (sim.peer_interfaces[0..scenario.peers], 0..) |*peer, at| {
        peer.* = .{
            .context = &sim.sources[at],
            .name = peer_names[at],
            .fetch = peer_fetch,
            .lied = peer_lied,
        };
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
    sim.registry_wrong = 0;
    sim.damaged_count = 0;
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
    source.calls += 1;
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

fn peer_fetch(
    context: *anyopaque,
    request: *const lazy.Request,
    out: []u8,
) lazy.FetchError!lazy.Fetched {
    const source = source_of(context);
    const sim = source.sim;
    assert(out.len == request.length);
    try plan_call(source, request.timeout_ms);
    const random = sim.prng.random();
    if (per_mille(random, source.behaviour.not_found_per_mille)) return error.NotFound;
    const object = find_object(sim, request.object) orelse return error.NotFound;
    const peer = peer_token(source);
    if (forged_of(sim, object, request.index)) |forged| {
        // Bytes that match the listed (forged) hash: a lie only the chaining value shows.
        assert(Digest.of(forged).eql(request.chunk));
        @memcpy(out, forged);
        sim.lies_sent[source.index] += 1;
        sim.lied_objects[source.index] |= @as(u16, 1) << @intCast(object);
        return .{ .length = @intCast(out.len), .peer = peer };
    }
    const truth = chunk_bytes_of(sim, object, request.index);
    assert(out.len == truth.len);
    assert(Digest.of(truth).eql(request.chunk));
    @memcpy(out, truth);
    if (per_mille(random, source.behaviour.short_per_mille)) {
        return .{ .length = random.uintLessThan(u32, @intCast(out.len)), .peer = peer };
    }
    const length: u32 = @intCast(out.len);
    const lying = per_mille(random, source.behaviour.lie_per_mille);
    if (!lying) return .{ .length = length, .peer = peer };
    sim.lies_sent[source.index] += 1;
    sim.lied_objects[source.index] |= @as(u16, 1) << @intCast(object);
    flip(random, out);
    return .{ .length = length, .peer = peer };
}

fn peer_token(source: *const SimSource) lazy.PeerToken {
    assert(source.index <= peers_max);
    assert(peers_max < 0x100);
    return 0x5eed_0000 + @as(lazy.PeerToken, source.index);
}

/// Wrong bytes: one of them changed.
fn flip(random: std.Random, out: []u8) void {
    assert(out.len > 0);
    assert(out.len <= blob_bytes_max);
    out[random.uintLessThan(usize, out.len)] ^= 1 + random.uintLessThan(u8, 255);
}

fn peer_lied(context: *anyopaque, request: *const lazy.Request, peer: lazy.PeerToken) void {
    const source = source_of(context);
    assert(find_object(source.sim, request.object) != null);
    assert(request.index < chunks_per_object_max);
    if (peer != peer_token(source)) @panic("a lie was told to the wrong peer");
    source.lied_told += 1;
}

fn find_object(sim: *const Sim, id: Digest) ?lazy.ObjectIndex {
    assert(sim.objects_count <= objects_max);
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        if (object.wanted.id.eql(id)) return @intCast(at);
    }
    return null;
}

fn registry_fetch(
    context: *anyopaque,
    offset: u64,
    out: []u8,
    timeout_ms: u32,
) lazy.FetchError!usize {
    const source = source_of(context);
    const sim = source.sim;
    assert(out.len > 0);
    try plan_call(source, timeout_ms);
    if (offset >= sim.blob_len) return error.Failed;
    const random = sim.prng.random();
    var from: usize = @intCast(offset);
    const lying = per_mille(random, source.behaviour.lie_per_mille);
    if (lying and random.boolean()) {
        // A wrong offset: the blob from somewhere else.
        from = random.uintLessThan(usize, sim.blob_len);
    }
    var length = @min(out.len, sim.blob_len - from);
    @memcpy(out[0..length], sim.blob[from..][0..length]);
    if (overlay_forged(sim, from, out[0..length])) sim.lies_sent[source.index] += 1;
    if (lying) {
        sim.lies_sent[source.index] += 1;
        if (random.boolean()) flip(random, out[0..length]);
    }
    if (per_mille(random, source.behaviour.short_per_mille)) {
        length = random.uintLessThan(usize, length);
    }
    note_wrong_segments(sim, offset, out[0..length]);
    return length;
}

/// Writes the forged bytes over the forged chunk's stored block, when the answer from `from`
/// holds all of it: the registry serves what the forged index names. True if it did.
fn overlay_forged(sim: *const Sim, from: usize, answer: []u8) bool {
    const forged = sim.forged orelse return false;
    if (!sim.scenario.registry) return false;
    const location = sim.objects[forged.object].locations[forged.chunk];
    if (location.offset < from) return false;
    const start: usize = @intCast(location.offset - from);
    if (start + location.length > answer.len) return false;
    const bytes = forged_of(sim, forged.object, forged.chunk).?;
    assert(location.length == stored_header_bytes + bytes.len);
    @memcpy(answer[start + stored_header_bytes ..][0..bytes.len], bytes);
    return true;
}

/// The objects a registry answer holds a wrong segment of: the only ones it may be named for.
fn note_wrong_segments(sim: *Sim, offset: u64, answer: []const u8) void {
    assert(offset < sim.blob_len);
    assert(answer.len <= blob_bytes_max);
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        for (object.locations) |location| {
            if (location.offset < offset) continue;
            const start: usize = @intCast(location.offset - offset);
            if (start + location.length > answer.len) continue;
            const sent = answer[start..][0..location.length];
            const truth = sim.blob[@intCast(location.offset)..][0..location.length];
            if (!std.mem.eql(u8, sent, truth)) sim.registry_wrong |= @as(u16, 1) << @intCast(at);
        }
    }
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
}

fn teardown_unrun(sim: *Sim) void {
    assert(!sim.resolver.schedule.stopping);
    assert(sim.objects_count > 0);
    sim.resolver.schedule.stop();
    teardown(sim);
}

/// The object with the most chunks.
fn longest_object(sim: *const Sim) u32 {
    assert(sim.objects_count > 0);
    var best: u32 = 0;
    for (sim.objects[0..sim.objects_count], 0..) |*object, at| {
        if (object.wanted.hashes.len > sim.objects[best].wanted.hashes.len) best = @intCast(at);
    }
    assert(sim.objects[best].wanted.hashes.len >= 3);
    return best;
}

/// Frees what `setup` took; after `run` and any checks of the resolver's state.
fn teardown(sim: *Sim) void {
    assert(sim.resolver.schedule.stopping);
    assert(sim.objects_count > 0);
    sim.resolver.deinit(std.heap.page_allocator);
}

/// A crash is followed by a restart (the resolver keeps going, as after a remount), and a gc
/// removes a whole object or one chunk file now and then, or damages one or makes it unreadable.
fn faults(sim: *Sim) void {
    assert(sim.now_ms < 1 << 62);
    if (sim.files.crashed) {
        sim.files.restart();
        sim.crashes += 1;
        repair(sim);
        support.check_whole(&sim.files, root_path, chunk_bytes) catch
            @panic("store not whole after a crash");
    }
    if (sim.now_ms < sim.gc_at_ms) return;
    sim.gc_at_ms = next_gc(sim);
    const random = sim.prng.random();
    const object = random.uintLessThan(u32, sim.objects_count);
    const wanted = &sim.objects[object].wanted;
    var path_storage: PathBuf = undefined;
    var chunk: ?u32 = null;
    var path: [:0]const u8 = undefined;
    if (land.object_is_whole(&sim.store, wanted)) {
        path = sim.store.object_path(&path_storage, wanted.id);
    } else {
        if (wanted.hashes.len == 0) return;
        chunk = random.uintLessThan(u32, @intCast(wanted.hashes.len));
        path = chunks_mod.partial_chunk(&sim.store, &path_storage, wanted.id, chunk.?);
    }
    const stat = sim.store.fs.lstat(path) catch return;
    if (!per_mille(random, sim.scenario.damage_per_mille)) return sim.files.remove_path(path);
    if (sim.damaged_count == damaged_max or stat.size == 0) return;
    if (random.boolean()) {
        sim.files.flip_byte(path, random.uintLessThan(u32, @intCast(stat.size)));
    } else {
        sim.files.set_unreadable(path);
    }
    sim.damaged[sim.damaged_count] = .{ .object = object, .chunk = chunk };
    sim.damaged_count += 1;
}

/// Removes what `faults` damaged, as a gc would: the store holds only whole files after.
fn repair(sim: *Sim) void {
    assert(sim.damaged_count <= damaged_max);
    assert(!sim.files.crashed);
    for (sim.damaged[0..sim.damaged_count]) |damage| {
        const wanted = &sim.objects[damage.object].wanted;
        var path_storage: PathBuf = undefined;
        const path = if (damage.chunk) |chunk|
            chunks_mod.partial_chunk(&sim.store, &path_storage, wanted.id, chunk)
        else
            sim.store.object_path(&path_storage, wanted.id);
        _ = sim.store.fs.lstat(path) catch continue;
        sim.files.remove_path(path);
    }
    sim.damaged_count = 0;
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
        // The fill yields: no fill request starts within `lazy_fill_idle_ms` of a reader's ask.
        if (sim.work[slot].purposes[0] == .fill) {
            assert(sim.resolver.schedule.fill_idle_at(sim.now_ms) == null);
        }
        sim.elapsed_ms = 0;
        sim.resolver.slot_fetch(slot, &sim.work[slot]);
        end.* = sim.now_ms + @max(1, sim.elapsed_ms);
    }
    sim.resolver.drain_events();
}

/// The next time anything is due. A wake that is due now (a down source's probe with nothing
/// to probe) does not hold time back, nor does it jump past anything else.
fn next_time(sim: *Sim) ?u64 {
    const now = sim.now_ms;
    var next: ?u64 = null;
    var stalled = false;
    for (sim.ends_ms) |end| {
        if (end) |at| next = later(next, at, now, &stalled);
    }
    for (&sim.readers) |*reader| switch (reader.state) {
        .idle => next = later(next, reader.next_at_ms, now, &stalled),
        .waiting => next = later(next, reader_wake(sim, reader), now, &stalled),
        .done => {},
    };
    if (sim.resolver.schedule.tick(now)) |wake| next = later(next, wake, now, &stalled);
    const fill = &sim.resolver.fill;
    if (!fill.done) next = later(next, @max(fill.paused_until_ms, now + 10), now, &stalled);
    if (next == null and !stalled) return null;
    if (sim.gc_at_ms != std.math.maxInt(u64)) next = later(next, sim.gc_at_ms, now, &stalled);
    return next orelse now + 10;
}

/// When a waiting reader looks again: at once when its entry settled (the broadcast), else at
/// its time or its entry's deadline, whichever is first.
fn reader_wake(sim: *Sim, reader: *const Reader) u64 {
    assert(reader.state == .waiting);
    const schedule = &sim.resolver.schedule;
    if (schedule.stopping or schedule.settled_for(reader.waiting.ticket)) return sim.now_ms + 1;
    const entry = schedule.entry_of(reader.waiting.ticket);
    return @min(reader.waiting.until_ms, entry.deadline_ms);
}

fn later(current: ?u64, candidate: u64, now: u64, stalled: *bool) ?u64 {
    if (current) |at| assert(at > now);
    if (candidate <= now) {
        stalled.* = true;
        return current;
    }
    return earliest(current, candidate);
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
        reader.chunk + 1 < sim.objects[object].wanted.hashes.len and
        random.uintLessThan(u8, 4) != 0;
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
    // Landed and gone again (a gc) asks again, but the read keeps its start: its bound holds
    // across every ask.
    const step = sim.resolver.read_poll(reader.waiting, &reader.out, sim.now_ms);
    if (step == .wait) assert(step.wait.began_ms == reader.began_ms);
    settle(sim, reader, step);
}

fn settle(sim: *Sim, reader: *Reader, step: resolver_mod.Step) void {
    assert(reader.reads_left > 0);
    switch (step) {
        .wait => |waiting| {
            if (!sim.resolver.schedule.stopping) assert(waiting.until_ms > sim.now_ms);
            reader.state = .waiting;
            reader.waiting = waiting;
            return;
        },
        .done => |length| {
            // Property 1.
            const truth = chunk_bytes_of(sim, reader.object, reader.chunk);
            assert(length == truth.len);
            const right = std.mem.eql(u8, reader.out[0..length], truth);
            if (!right) @panic("a read returned wrong bytes");
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
    const event = find_event(sim, kind, reader.object, reader.chunk);
    if (event == null) @panic("a failed read has no event");
}

pub fn find_event(
    sim: *const Sim,
    kind: lazy.Event.Kind,
    object: lazy.ObjectIndex,
    chunk: u32,
) ?*const Event {
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
    repair(sim);
    support.check_whole(&sim.files, root_path, chunk_bytes) catch @panic("store not whole");
    check_chunks(sim);
    check_lies(sim);
    if (!sim.scenario.honest) return;
    if (sim.reads_failed != 0) @panic("a read failed with honest sources");
    if (sim.scenario.fill) {
        for (sim.objects[0..sim.objects_count]) |*object| {
            const whole = land.object_is_whole(&sim.store, &object.wanted);
            if (!whole) @panic("the fill left an object");
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
            const chaining = object.chaining;
            const read = land.read_local(&sim.store, &object.wanted, chaining, index, &out, null);
            const length = read catch |err| switch (err) {
                error.NotLocal => continue,
                error.Damaged, error.ObjectDamaged, error.Unreadable => {
                    @panic("the store holds a damaged chunk");
                },
            };
            const truth = chunk_bytes_of(sim, @intCast(at), index);
            if (!std.mem.eql(u8, out[0..length], truth)) @panic("the store holds a wrong chunk");
        }
    }
}

/// Property 5: a peer that sent wrong bytes is told each time and named once per object;
/// no source that sent only true bytes is named.
fn check_lies(sim: *const Sim) void {
    assert(sim.resolver.schedule.report.events_dropped == 0);
    assert(sim.events_count < events_max);
    var named: [peers_max + 1]u16 = @splat(0);
    for (sim.events[0..sim.events_count]) |*logged| {
        if (logged.event.kind != .lied) continue;
        const source = source_by_name(sim, logged.event.source);
        if (sim.lies_sent[source] == 0) @panic("an honest source was named a liar");
        if (source == sim.scenario.peers) {
            const wrong = sim.registry_wrong & (@as(u16, 1) << @intCast(logged.event.object));
            if (wrong == 0) @panic("the registry was named for an object it sent true");
        }
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
        0 => {
            const free_max = constants.lazy_store_free_bytes_min * 2;
            scenario.free_bytes = random.uintLessThan(u64, free_max);
        },
        1 => scenario.bytes_max = random.uintLessThan(u64, content_bytes_max * 2),
        2 => scenario.crash_mutation = random.uintLessThan(u32, 400),
        3 => {
            scenario.gc_per_mille = random.intRangeAtMost(u16, 1, 100);
            scenario.damage_per_mille = some_per_mille(random);
        },
        else => {},
    }
    scenario.forged = random.uintLessThan(u8, 6) == 0;
    return scenario;
}

fn random_behaviour(random: std.Random, behaviour: *Behaviour) void {
    assert(behaviour.latency_max_ms > 0);
    behaviour.slow_per_mille = some_per_mille(random);
    behaviour.not_found_per_mille = some_per_mille(random);
    behaviour.failed_per_mille = some_per_mille(random);
    behaviour.lie_per_mille = some_per_mille(random);
    behaviour.short_per_mille = some_per_mille(random);
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
    teardown(&sim_state);
    if (sim_state.objects_count == 0) assert(sim_state.reads_ok + sim_state.reads_failed > 0);
}

fn honest_scenario(peers: u8, registry: bool, fill: bool) Scenario {
    assert(peers <= peers_max);
    if (!registry) assert(peers > 0);
    return .{
        .peers = peers,
        .registry = registry,
        .behaviours = @splat(.{}),
        .fill = fill,
        .honest = true,
    };
}

test "sim: honest sources serve every read and the fill makes every object whole" {
    for ([_]u8{ 0, 1, 2, 3 }) |peers| {
        for ([_]bool{ false, true }) |registry| {
            if (peers == 0 and !registry) continue;
            setup(&sim_state, 7 + peers, honest_scenario(peers, registry, true));
            run(&sim_state);
            teardown(&sim_state);
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
    teardown(&sim_state);
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
    teardown(&sim_state);
    try std.testing.expectEqual(@as(u32, 0), sim_state.reads_ok);
    try std.testing.expect(sim_state.reads_failed > 0);
}

test "sim: a disk below the floor refuses reads with store_full" {
    var scenario = honest_scenario(1, false, true);
    scenario.honest = false;
    scenario.free_bytes = 0;
    setup(&sim_state, 17, scenario);
    run(&sim_state);
    teardown(&sim_state);
    try std.testing.expectEqual(@as(u32, 0), sim_state.reads_ok);
    var store_full: u32 = 0;
    for (sim_state.events[0..sim_state.events_count]) |logged| {
        store_full += @intFromBool(logged.event.kind == .store_full);
    }
    try std.testing.expect(store_full > 0);
}

test "sim: a chunk read again is served from the store, with no second fetch" {
    setup(&sim_state, 19, honest_scenario(1, true, true));
    run(&sim_state);
    defer teardown(&sim_state);
    var calls: u32 = 0;
    for (sim_state.sources[0..2]) |source| calls += source.calls;
    try std.testing.expect(calls > 0);
    const resolver = &sim_state.resolver;
    for (0..sim_state.objects_count) |object| {
        const count = sim_state.objects[object].wanted.hashes.len;
        for (0..count) |chunk| {
            for (0..3) |_| {
                var out: [chunk_bytes]u8 = @splat(0xaa);
                const at: u32 = @intCast(chunk);
                const step = resolver.read_begin(@intCast(object), at, &out, 400_000);
                const truth = chunk_bytes_of(&sim_state, @intCast(object), at);
                try std.testing.expectEqual(truth.len, step.done);
                try std.testing.expectEqualSlices(u8, truth, out[0..truth.len]);
            }
        }
    }
    var after: u32 = 0;
    for (sim_state.sources[0..2]) |source| after += source.calls;
    try std.testing.expectEqual(calls, after);
    for (&resolver.schedule.pending) |*entry| try std.testing.expect(entry.state == .free);
}

test "schedule: a chunk read again keeps the sequential streak" {
    setup(&sim_state, 23, honest_scenario(1, false, false));
    defer teardown_unrun(&sim_state);
    const schedule = &sim_state.resolver.schedule;
    const object = longest_object(&sim_state);
    schedule.note_read(object, 0, 0);
    schedule.note_read(object, 0, 0);
    schedule.note_read(object, 0, 0);
    try std.testing.expectEqual(@as(u8, 1), schedule.objects[object].streak);
    schedule.note_read(object, 1, 0);
    schedule.note_read(object, 1, 0);
    try std.testing.expectEqual(@as(u8, 2), schedule.objects[object].streak);
    var queued: u32 = 0;
    for (&schedule.pending) |*entry| queued += @intFromBool(entry.state == .queued);
    try std.testing.expect(queued > 0); // Readahead started.
}

test "sim: reads through stored chunks extend the sequential streak" {
    setup(&sim_state, 41, honest_scenario(1, true, true));
    run(&sim_state);
    defer teardown(&sim_state);
    const schedule = &sim_state.resolver.schedule;
    schedule.stopping = false; // Running again, over a store the fill made whole.
    defer schedule.stop();
    const object = longest_object(&sim_state);
    const count = sim_state.objects[object].wanted.hashes.len;
    var chunk: u32 = 0;
    while (chunk < count) : (chunk += 1) {
        var out: [chunk_bytes]u8 = @splat(0xaa);
        const step = sim_state.resolver.read_begin(object, chunk, &out, 400_000);
        try std.testing.expect(step == .done);
    }
    try std.testing.expectEqual(@as(u8, @intCast(count)), schedule.objects[object].streak);
}

/// A FUSE READ of any size at any offset, as slice 4 passes it on: one read per chunk it
/// touches, in order. Sequential access is seen from where reads start, never from their size.
fn fuse_read(schedule: *Schedule, object: u32, offset: u64, length: u64) void {
    assert(length > 0);
    assert(offset + length <= schedule.catalog.objects[object].wanted.size);
    var chunk = offset / chunk_bytes;
    while (chunk <= (offset + length - 1) / chunk_bytes) : (chunk += 1) {
        schedule.note_read(object, @intCast(chunk), 0);
    }
}

fn queued_count(schedule: *const Schedule) u32 {
    var count: u32 = 0;
    for (&schedule.pending) |*entry| count += @intFromBool(entry.state == .queued);
    assert(count <= schedule.pending.len);
    return count;
}

test "schedule: a small unaligned read starts no readahead" {
    setup(&sim_state, 29, honest_scenario(1, false, false));
    defer teardown_unrun(&sim_state);
    const schedule = &sim_state.resolver.schedule;
    const object = longest_object(&sim_state);
    fuse_read(schedule, object, chunk_bytes + 37, 4);
    fuse_read(schedule, object, 5, 4);
    try std.testing.expectEqual(@as(u8, 1), schedule.objects[object].streak);
    try std.testing.expectEqual(@as(u32, 0), queued_count(schedule));
}

test "schedule: a read across two chunks counts as a step forward" {
    setup(&sim_state, 31, honest_scenario(1, false, false));
    defer teardown_unrun(&sim_state);
    const schedule = &sim_state.resolver.schedule;
    const object = longest_object(&sim_state);
    fuse_read(schedule, object, chunk_bytes - 4, 8);
    try std.testing.expectEqual(@as(u8, 2), schedule.objects[object].streak);
    try std.testing.expect(queued_count(schedule) > 0);
}

test "schedule: a sequential run of quarter-chunk reads starts readahead on the second chunk" {
    setup(&sim_state, 37, honest_scenario(1, false, false));
    defer teardown_unrun(&sim_state);
    const schedule = &sim_state.resolver.schedule;
    const object = longest_object(&sim_state);
    const quarter = chunk_bytes / 4; // 256 KiB of a 1 MiB chunk.
    var offset: u64 = 0;
    while (offset < chunk_bytes) : (offset += quarter) fuse_read(schedule, object, offset, quarter);
    try std.testing.expectEqual(@as(u32, 0), queued_count(schedule));
    fuse_read(schedule, object, offset, quarter);
    try std.testing.expectEqual(@as(u8, 2), schedule.objects[object].streak);
    try std.testing.expect(queued_count(schedule) > 0);
}

test "sim: a forged chunk hash with a true chaining value never reaches a reader or the store" {
    // Goal: an index whose plain chunk hash is forged (its chaining values true, so the tree
    // checks pass) cannot get the bytes the forged hash names served or kept. Method: every
    // source serves the forged bytes for the forged chunk, and with peers and the registry,
    // with and without the fill, the run's properties hold: no read returns them (property 1)
    // and no store file holds them (3); each source is named a liar. Without the chaining
    // check in `keep` and `land`, the first read of that chunk returns the forged bytes.
    var forged_runs: u32 = 0;
    for ([_]u8{ 0, 1, 2 }) |peers| {
        for ([_]bool{ false, true }) |fill| {
            var scenario = honest_scenario(peers, true, fill);
            scenario.honest = false;
            scenario.forged = true;
            setup(&sim_state, 101 + peers, scenario);
            const has_forged = sim_state.forged != null;
            run(&sim_state);
            teardown(&sim_state);
            if (!has_forged) continue;
            forged_runs += 1;
            // The fill asks for every chunk, so some source served the forged bytes.
            var lies: u32 = 0;
            for (sim_state.lies_sent) |sent| lies += sent;
            if (fill) try std.testing.expect(lies > 0);
        }
    }
    try std.testing.expect(forged_runs > 0);
}

test "sim: seeds" {
    var seed: u64 = 0;
    while (seed < 40) : (seed += 1) fuzz_lazy_resolver(seed);
}

test "sim: regression seeds" {
    // Goal: seeds that once broke the resolver stay fixed.
    // Method: run each through the fuzzer's own body. 11207900475674901063 is iteration 2418 of
    // `zig build fuzz -- lazy_resolver 2087983757`: every source was marked bad for an object
    // while its entry was fetching, so the entry outlived its deadline and tripped `tick`.
    fuzz_lazy_resolver(11207900475674901063);
    // 2326231968809022906 is iteration 4509 of the same run: a chunk file made unreadable
    // failed `put_chunk` without filling its failure, and `land` read the garbage errno.
    fuzz_lazy_resolver(2326231968809022906);
}
