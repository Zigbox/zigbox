//! Directed tests of the resolver: the threaded path (`start`, `read`, `stop`) over fake
//! in-memory sources, and the schedule's and resolver's bounds, damage handling, deadlines and
//! verdicts on one thread (the simulation's steps, driven by hand).
//!
//! The threaded tests run real threads, mutexes and conditions, but on a clock that runs
//! `time_scale` times faster than the real one (`Scaled`), so `lazy_read_deadline_ms` is
//! faithful and still short. The store is the real store on `SimFs`, behind a lock (`locked_fs`):
//! the simulated file system is not shared safely between threads, and the resolver's readers
//! read the store without its store lock.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const layout = @import("../store/layout.zig");
const object_mod = @import("../store/object.zig");
const support = @import("../store/test_support.zig");
const xattrs = @import("../store/xattrs.zig");
const chunks_mod = @import("../store/chunks.zig");
const lazy = @import("lazy.zig");
const land_mod = @import("land.zig");
const resolver_mod = @import("resolver.zig");
const schedule_mod = @import("schedule.zig");

const Digest = lazy.Digest;
const Resolver = resolver_mod.Resolver;
const Step = resolver_mod.Step;
const Work = resolver_mod.Work;
const Schedule = schedule_mod.Schedule;
const PathBuf = fs_mod.PathBuf;
const testing = std.testing;

const root_path = "/data/store";
const chunk_bytes: u32 = 64;
const objects_max = 6;
const chunks_max = 4;
const content_bytes_max = objects_max * chunks_max * chunk_bytes;
/// A stored deflate block's header: BFINAL 0, BTYPE 00, padding, LEN, NLEN.
const stored_header_bytes = 5;
const blob_bytes_max = content_bytes_max + objects_max * chunks_max * stored_header_bytes;
/// One past `lazy_sources_max`, for the refusal at init.
const peers_max = constants.lazy_sources_max + 1;
const events_max = 256;
const free_bytes_plenty: u64 = 4 << 30;
/// `SimFs` holds `sim_fs_handles_max` open files: three readers and one put stay below it.
const readers_count = 3;
/// The fake clock runs this many times faster than the real one.
const time_scale = 10;
/// How late (fake ms) a threaded wake-up may come: real scheduling latency, scaled.
const wake_slack_ms = 2000;
/// Real ms a threaded test waits for a condition before it fails.
const wait_real_ms_max = 5000;
const deadline_ms = constants.lazy_read_deadline_ms;
const peer_token: lazy.PeerToken = 7;
const misbehave_always = std.math.maxInt(u32);

const attrs: object_mod.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };

const peer_names = [peers_max][]const u8{
    "peer a", "peer b", "peer c", "peer d", "peer e", "peer f", "peer g", "peer h", "peer i",
};

const Behaviour = enum { honest, slow, failing, not_found, short, lying };

const FakeSource = struct {
    behaviour: Behaviour,
    /// Calls that misbehave before the source turns honest.
    misbehave_calls: u32,
    calls: std.atomic.Value(u32),
    lied_told: std.atomic.Value(u32),
};

const FakeRange = struct {
    short: bool,
    calls: std.atomic.Value(u32),
    /// The bytes asked for, over every call.
    asked: std.atomic.Value(u64),
};

const Fixture = struct {
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    files_lock: std.atomic.Mutex,
    store: layout.Store,
    content: [content_bytes_max]u8,
    starts: [objects_max]u32,
    firsts: [objects_max]u32,
    hashes: [objects_max * chunks_max]Digest,
    locations: [objects_max * chunks_max]lazy.Location,
    objects: [objects_max]lazy.Object,
    objects_count: u32,
    blob: [blob_bytes_max]u8,
    blob_len: u32,
    peers: [peers_max]FakeSource,
    peer_sources: [peers_max]lazy.Source,
    registry: FakeRange,
    events: [events_max]lazy.Event,
    events_count: std.atomic.Value(u32),
    put_buffer: [8192]u8,
    resolver: Resolver,
};

var fixture: Fixture = undefined;

/// The store on `SimFs`, and objects of `sizes` bytes (each at most `chunks_max` chunks).
fn setup(sizes: []const u32) void {
    assert(sizes.len <= objects_max);
    assert(sizes.len > 0);
    fixture.host.init(1, &.{});
    fixture.files.init(sizes.len);
    fixture.host.store_fs = &fixture.files;
    fixture.files.put_dir("/data", 0o755);
    support.make_store_directories(&fixture.files, root_path);
    fixture.store.at(fixture.host.interface(), root_path);
    fixture.store.chunk_bytes = chunk_bytes;
    fixture.files_lock = .unlocked;
    fixture.store.fs = .{ .context = &fixture.files, .vtable = &locked_vtable };
    fixture.events_count = .init(0);
    make_objects(sizes);
    for (&fixture.peers, &fixture.peer_sources, peer_names) |*peer, *source, name| {
        peer.* = .{
            .behaviour = .honest,
            .misbehave_calls = 0,
            .calls = .init(0),
            .lied_told = .init(0),
        };
        source.* = .{ .context = peer, .name = name, .fetch = peer_fetch, .lied = peer_lied };
    }
    fixture.registry = .{ .short = false, .calls = .init(0), .asked = .init(0) };
}

fn make_objects(sizes: []const u32) void {
    var prng = std.Random.DefaultPrng.init(sizes.len);
    var content_len: u32 = 0;
    var hashes_used: u32 = 0;
    fixture.blob_len = 0;
    for (sizes, 0..) |size, at| {
        assert(size > 0);
        assert(size <= chunks_max * chunk_bytes);
        const bytes = fixture.content[content_len..][0..size];
        prng.random().bytes(bytes);
        bytes[0] = @intCast(at); // Distinct objects.
        fixture.starts[at] = content_len;
        fixture.firsts[at] = hashes_used;
        content_len += size;
        var reader = object_mod.Reader.init(chunk_bytes);
        const hashes = fixture.hashes[hashes_used..][0..chunks_max];
        _ = reader.update(bytes, hashes);
        const whole = reader.finish(hashes);
        const count = reader.count;
        const locations = fixture.locations[hashes_used..][0..count];
        for (locations, 0..) |*location, chunk| {
            location.* = append_block(bytes, @intCast(chunk));
        }
        fixture.objects[at] = .{
            .wanted = .{
                .id = object_mod.object_id(whole, attrs),
                .attrs = attrs,
                .size = size,
                .content = whole,
                .hashes = fixture.hashes[hashes_used..][0..count],
            },
            .locations = locations,
            // This fixture's 64-byte chunks are below BLAKE3's piece; its sources are the
            // test's, so nothing is anchored here (the sim and `fuse/resolver_tests` are).
            .chaining = &.{},
        };
        hashes_used += count;
    }
    fixture.objects_count = @intCast(sizes.len);
}

fn append_block(bytes: []const u8, chunk: u32) lazy.Location {
    const start = @as(usize, chunk) * chunk_bytes;
    const piece = bytes[start..@min(bytes.len, start + chunk_bytes)];
    assert(piece.len > 0);
    const at = fixture.blob_len;
    const length: u16 = @intCast(piece.len);
    fixture.blob[at] = 0;
    std.mem.writeInt(u16, fixture.blob[at + 1 ..][0..2], length, .little);
    std.mem.writeInt(u16, fixture.blob[at + 3 ..][0..2], ~length, .little);
    @memcpy(fixture.blob[at + stored_header_bytes ..][0..piece.len], piece);
    fixture.blob_len += @intCast(stored_header_bytes + piece.len);
    return .{ .offset = at, .length = @intCast(stored_header_bytes + piece.len) };
}

fn truth(object: lazy.ObjectIndex, chunk: u32) []const u8 {
    assert(object < fixture.objects_count);
    const size: u32 = @intCast(fixture.objects[object].wanted.size);
    const bytes = fixture.content[fixture.starts[object]..][0..size];
    const start = @as(usize, chunk) * chunk_bytes;
    assert(start < bytes.len);
    return bytes[start..@min(bytes.len, start + chunk_bytes)];
}

fn object_of(id: Digest) lazy.ObjectIndex {
    for (fixture.objects[0..fixture.objects_count], 0..) |*object, at| {
        if (object.wanted.id.eql(id)) return @intCast(at);
    }
    unreachable; // The resolver asks only for objects of the catalog.
}

fn open_resolver(peers: u32, registry: bool, fill: bool) InitError!void {
    assert(peers <= peers_max);
    const range: lazy.Range = .{
        .context = &fixture.registry,
        .name = "registry",
        .fetch = range_fetch,
    };
    try fixture.resolver.init(testing.allocator, .{
        .store = &fixture.store,
        .catalog = .{ .objects = fixture.objects[0..fixture.objects_count] },
        .peers = fixture.peer_sources[0..peers],
        .registry = if (registry) range else null,
        .log = .{ .context = &fixture, .event = log_event },
        .free = .{ .context = &fixture, .query = free_query },
        .fill = fill,
    });
}

const InitError = resolver_mod.InitError;

fn close_resolver() void {
    fixture.resolver.deinit(testing.allocator);
}

fn peer_fetch(
    context: *anyopaque,
    request: *const lazy.Request,
    out: []u8,
) lazy.FetchError!lazy.Fetched {
    const source: *FakeSource = @ptrCast(@alignCast(context));
    const call = source.calls.fetchAdd(1, .monotonic);
    assert(out.len == request.length);
    const bytes = truth(object_of(request.object), request.index);
    assert(bytes.len == out.len);
    assert(bytes.len > 1);
    @memcpy(out, bytes);
    if (call >= source.misbehave_calls) return .{ .length = request.length, .peer = peer_token };
    switch (source.behaviour) {
        .honest => {},
        .slow => {
            // Sleeps the whole attempt on the (scaled) clock, as a peer that never answers.
            const io = fixture.resolver.io.?;
            Io.sleep(io, .fromMilliseconds(request.timeout_ms), .awake) catch {};
            return error.TimedOut;
        },
        .failing => return error.Failed,
        .not_found => return error.NotFound,
        .short => return .{ .length = request.length - 1, .peer = peer_token },
        .lying => out[0] ^= 0xff,
    }
    return .{ .length = request.length, .peer = peer_token };
}

fn peer_lied(context: *anyopaque, request: *const lazy.Request, peer: lazy.PeerToken) void {
    const source: *FakeSource = @ptrCast(@alignCast(context));
    assert(request.length > 0);
    assert(peer == peer_token);
    _ = source.lied_told.fetchAdd(1, .monotonic);
}

fn range_fetch(context: *anyopaque, offset: u64, out: []u8, timeout_ms: u32) lazy.FetchError!usize {
    const range: *FakeRange = @ptrCast(@alignCast(context));
    assert(timeout_ms > 0);
    assert(out.len > 0);
    _ = range.calls.fetchAdd(1, .monotonic);
    _ = range.asked.fetchAdd(out.len, .monotonic);
    if (offset >= fixture.blob_len) return error.Failed;
    const length: usize = @min(out.len, fixture.blob_len - offset);
    @memcpy(out[0..length], fixture.blob[@intCast(offset)..][0..length]);
    if (range.short) return length - 1;
    return length;
}

fn log_event(context: *anyopaque, event: *const lazy.Event) void {
    assert(context == @as(*anyopaque, &fixture));
    const at = fixture.events_count.fetchAdd(1, .monotonic);
    assert(at < events_max);
    fixture.events[at] = event.*;
}

fn free_query(context: *anyopaque) u64 {
    assert(context == @as(*anyopaque, &fixture));
    return free_bytes_plenty;
}

/// Events of `kind` logged so far (about `source`, when it is not empty).
fn events_of(kind: lazy.Event.Kind, source: []const u8) u32 {
    const count = fixture.events_count.load(.monotonic);
    assert(count <= events_max);
    var found: u32 = 0;
    for (fixture.events[0..count]) |*event| {
        if (event.kind != kind) continue;
        if (source.len > 0 and !std.mem.eql(u8, event.source, source)) continue;
        found += 1;
    }
    return found;
}

fn land_chunk(object: lazy.ObjectIndex, chunk: u32) land_mod.Landed {
    const wanted = &fixture.objects[object].wanted;
    const bytes = truth(object, chunk);
    return land_mod.land(&fixture.store, &fixture.put_buffer, wanted, &.{}, chunk, bytes);
}

// The locked file system: every call of `SimFs`'s table, one at a time.

const locked_vtable: fs_mod.VTable = locked: {
    var table: fs_mod.VTable = undefined;
    const info = @typeInfo(fs_mod.VTable).@"struct";
    for (info.field_names, info.field_types) |name, Pointer| {
        @field(table, name) = locked(name, @typeInfo(Pointer).pointer.child);
    }
    break :locked table;
};

fn files_lock() void {
    while (!fixture.files_lock.tryLock()) std.Thread.yield() catch {};
}

fn files_unlock() void {
    fixture.files_lock.unlock();
}

fn inner(comptime name: []const u8) @FieldType(fs_mod.VTable, name) {
    return @field(fixture.files.interface().vtable.*, name);
}

fn locked(comptime name: []const u8, comptime F: type) *const F {
    const info = @typeInfo(F).@"fn";
    const P = info.param_types;
    const R = info.return_type.?;
    return switch (P.len) {
        1 => &struct {
            fn call(c: P[0].?) R {
                files_lock();
                defer files_unlock();
                return inner(name)(c);
            }
        }.call,
        2 => &struct {
            fn call(c: P[0].?, a: P[1].?) R {
                files_lock();
                defer files_unlock();
                return inner(name)(c, a);
            }
        }.call,
        3 => &struct {
            fn call(c: P[0].?, a: P[1].?, b: P[2].?) R {
                files_lock();
                defer files_unlock();
                return inner(name)(c, a, b);
            }
        }.call,
        4 => &struct {
            fn call(c: P[0].?, a: P[1].?, b: P[2].?, d: P[3].?) R {
                files_lock();
                defer files_unlock();
                return inner(name)(c, a, b, d);
            }
        }.call,
        5 => &struct {
            fn call(c: P[0].?, a: P[1].?, b: P[2].?, d: P[3].?, e: P[4].?) R {
                files_lock();
                defer files_unlock();
                return inner(name)(c, a, b, d, e);
            }
        }.call,
        else => @compileError("fs.VTable." ++ name ++ ": add a forwarder for its arity"),
    };
}

// The scaled clock: `std.testing.io` with `now`, timed waits and sleeps `time_scale` times
// faster. Mutexes and conditions stay the real ones.

const Scaled = struct {
    var inner_io: Io = undefined;
    var table: Io.VTable = undefined;
    var base_ns: i96 = 0;

    fn io() Io {
        inner_io = testing.io;
        table = inner_io.vtable.*;
        table.now = now;
        table.futexWait = futex_wait;
        table.sleep = sleep;
        base_ns = inner_io.vtable.now(inner_io.userdata, .awake).nanoseconds;
        return .{ .userdata = inner_io.userdata, .vtable = &table };
    }

    fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
        const real = inner_io.vtable.now(userdata, clock);
        if (clock != .awake) return real;
        assert(real.nanoseconds >= base_ns);
        return .{ .nanoseconds = base_ns + (real.nanoseconds - base_ns) * time_scale };
    }

    /// The same wait, as a real duration.
    fn real_timeout(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Timeout {
        const fake_ns: i96, const clock: Io.Clock = switch (timeout) {
            .none => return .none,
            .duration => |d| .{ d.raw.nanoseconds, d.clock },
            .deadline => |d| .{ d.raw.nanoseconds - now(userdata, d.clock).nanoseconds, d.clock },
        };
        const scale: i96 = if (clock == .awake) time_scale else 1;
        const real_ns = @divFloor(@max(fake_ns, 0), scale);
        return .{ .duration = .{ .raw = .{ .nanoseconds = real_ns }, .clock = clock } };
    }

    fn futex_wait(
        userdata: ?*anyopaque,
        ptr: *const u32,
        expected: u32,
        timeout: Io.Timeout,
    ) Io.Cancelable!void {
        return inner_io.vtable.futexWait(userdata, ptr, expected, real_timeout(userdata, timeout));
    }

    fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
        return inner_io.vtable.sleep(userdata, real_timeout(userdata, timeout));
    }
};

fn now_ms(io: Io) u64 {
    const ms = Io.Clock.awake.now(io).toMilliseconds();
    assert(ms >= 0);
    return @intCast(ms);
}

/// Sleeps a real millisecond.
fn nap() void {
    Io.sleep(testing.io, .fromMilliseconds(1), .awake) catch {};
}

fn stop_resolver() void {
    fixture.resolver.stop();
    close_resolver();
}

/// One reader thread's read of one chunk.
const ReadOne = struct {
    object: lazy.ObjectIndex,
    chunk: u32,
    length: u32 = 0,
    failure: ?lazy.ReadError = null,
    began_ms: u64 = 0,
    elapsed_ms: u64 = 0,
    out: [chunk_bytes]u8 = @splat(0),
};

fn read_one(job: *ReadOne) void {
    const io = fixture.resolver.io.?;
    const began = now_ms(io);
    job.began_ms = began;
    if (fixture.resolver.read(job.object, job.chunk, &job.out)) |length| {
        job.length = @intCast(length);
    } else |err| {
        job.failure = err;
    }
    job.elapsed_ms = now_ms(io) - began;
}

/// One reader thread's read of every chunk of the catalog, from its own starting object.
const ReadAll = struct {
    first: u32,
    good: u32 = 0,
    wrong: u32 = 0,
    failed: u32 = 0,
};

fn read_all(job: *ReadAll) void {
    const count = fixture.objects_count;
    for (0..count) |step| {
        const object: lazy.ObjectIndex = @intCast((job.first + step) % count);
        const chunks = fixture.objects[object].wanted.hashes.len;
        for (0..chunks) |chunk| {
            var out: [chunk_bytes]u8 = @splat(0xaa);
            const length = fixture.resolver.read(object, @intCast(chunk), &out) catch {
                job.failed += 1;
                continue;
            };
            const expected = truth(object, @intCast(chunk));
            if (std.mem.eql(u8, expected, out[0..length])) job.good += 1 else job.wrong += 1;
        }
    }
}

/// Reader threads, joined before their results are looked at.
fn Crew(comptime Job: type, comptime function: fn (*Job) void) type {
    return struct {
        threads: [readers_count]std.Thread = undefined,
        spawned: u32 = 0,

        fn spawn(crew: *@This(), jobs: *[readers_count]Job) std.Thread.SpawnError!void {
            errdefer crew.join();
            for (jobs) |*job| {
                crew.threads[crew.spawned] = try std.Thread.spawn(.{}, function, .{job});
                crew.spawned += 1;
            }
        }

        fn join(crew: *@This()) void {
            for (crew.threads[0..crew.spawned]) |thread| thread.join();
            crew.spawned = 0;
        }
    };
}

/// Entries some reader waits on now.
fn entries_waited_on() u32 {
    const resolver = &fixture.resolver;
    const io = resolver.io.?;
    resolver.mutex.lockUncancelable(io);
    defer resolver.mutex.unlock(io);
    var count: u32 = 0;
    for (&resolver.schedule.pending) |*entry| {
        const live = entry.state == .queued or entry.state == .fetching;
        count += @intFromBool(live and entry.waiters > 0);
    }
    return count;
}

fn objects_local_now() u32 {
    return fixture.resolver.report().objects_local;
}

test "resolver threads: concurrent readers get the true bytes while the fill runs" {
    // Goal: with `start`, readers on several threads, the slots and the fill all at once,
    // every read returns the object's true bytes and every object ends whole.
    // Method: three reader threads read every chunk of four objects, each from another
    // starting object, over an honest peer and the registry, with the fill on.
    setup(&.{ 4 * chunk_bytes, 3 * chunk_bytes + 5, chunk_bytes, 2 * chunk_bytes - 1 });
    try open_resolver(1, true, true);
    try fixture.resolver.start(Scaled.io());
    defer stop_resolver();
    var jobs: [readers_count]ReadAll = undefined;
    for (&jobs, 0..) |*job, at| job.* = .{ .first = @intCast(at) };
    var crew: Crew(ReadAll, read_all) = .{};
    try crew.spawn(&jobs);
    crew.join();
    var chunks_total: u32 = 0;
    for (fixture.objects[0..fixture.objects_count]) |*object| {
        chunks_total += @intCast(object.wanted.hashes.len);
    }
    for (&jobs) |*job| {
        try testing.expectEqual(chunks_total, job.good);
        try testing.expectEqual(@as(u32, 0), job.wrong);
        try testing.expectEqual(@as(u32, 0), job.failed);
    }
    // A reader may read a chunk the moment it lands, before its slot marks the object whole.
    var waited: u32 = 0;
    while (objects_local_now() < fixture.objects_count and waited < wait_real_ms_max) {
        nap();
        waited += 1;
    }
    const report = fixture.resolver.report();
    try testing.expectEqual(fixture.objects_count, report.objects_local);
    try testing.expectEqual(@as(u64, 0), report.errors);
    try testing.expectEqual(@as(u32, 0), fixture.events_count.load(.monotonic));
}

test "resolver threads: a read fails on its deadline when its only source is slow" {
    // Goal: a reader whose source never answers fails with `Unavailable` at its deadline
    // (`lazy_read_deadline_ms`), not much later, and not before the source has failed for a
    // whole deadline (it is then down), with its `unavailable` event.
    // Method: three readers, each of its own chunk, over one peer that sleeps out every
    // attempt timeout; the elapsed time is on the scaled clock, so the deadline is the real one.
    setup(&.{3 * chunk_bytes});
    fixture.peers[0].behaviour = .slow;
    fixture.peers[0].misbehave_calls = misbehave_always;
    try open_resolver(1, false, false);
    try fixture.resolver.start(Scaled.io());
    defer stop_resolver();
    var jobs: [readers_count]ReadOne = undefined;
    for (&jobs, 0..) |*job, at| job.* = .{ .object = 0, .chunk = @intCast(at) };
    var crew: Crew(ReadOne, read_one) = .{};
    try crew.spawn(&jobs);
    crew.join();
    // The source is down once it has failed for a whole deadline from its first job's start,
    // and then every entry gives up at once: a reader that began a few ms after the first may
    // end those ms before its own deadline, never before the first reader's.
    var first_ms: u64 = std.math.maxInt(u64);
    for (&jobs) |*job| first_ms = @min(first_ms, job.began_ms);
    for (&jobs) |*job| {
        try testing.expectEqual(@as(?lazy.ReadError, error.Unavailable), job.failure);
        try testing.expect(job.began_ms + job.elapsed_ms >= first_ms + deadline_ms);
        try testing.expect(job.elapsed_ms < deadline_ms + wake_slack_ms);
        if (job.began_ms == first_ms) try testing.expect(job.elapsed_ms >= deadline_ms);
    }
    try testing.expectEqual(@as(u32, readers_count), events_of(.unavailable, ""));
    const count = fixture.events_count.load(.monotonic);
    for (fixture.events[0..count]) |*event| {
        try testing.expectEqual(lazy.Outcome.timed_out, event.outcomes[0]);
        try testing.expectEqual(@as(u8, 1), event.sources_count);
    }
    try testing.expectEqual(@as(u64, readers_count), fixture.resolver.report().errors);
}

test "resolver threads: stop ends every waiting read with Stopped" {
    // Goal: `stop` while readers wait on a slow source wakes them all with `Stopped` long
    // before their deadline, joins the fetch threads, and `deinit` follows safely.
    // Method: three readers wait on chunks a slow peer never serves; once each has an entry
    // with a waiter, `stop` runs; the readers are joined, then the resolver is freed.
    setup(&.{3 * chunk_bytes});
    fixture.peers[0].behaviour = .slow;
    fixture.peers[0].misbehave_calls = misbehave_always;
    try open_resolver(1, false, false);
    try fixture.resolver.start(Scaled.io());
    var jobs: [readers_count]ReadOne = undefined;
    for (&jobs, 0..) |*job, at| job.* = .{ .object = 0, .chunk = @intCast(at) };
    var crew: Crew(ReadOne, read_one) = .{};
    crew.spawn(&jobs) catch |err| {
        stop_resolver();
        return err;
    };
    var waited: u32 = 0;
    while (entries_waited_on() < readers_count and waited < wait_real_ms_max) {
        nap();
        waited += 1;
    }
    const waiting = entries_waited_on();
    fixture.resolver.stop();
    crew.join();
    for (fixture.resolver.threads) |thread| try testing.expect(thread == null);
    close_resolver();
    try testing.expectEqual(@as(u32, readers_count), waiting);
    for (&jobs) |*job| {
        try testing.expectEqual(@as(?lazy.ReadError, error.Stopped), job.failure);
        try testing.expect(job.elapsed_ms < deadline_ms);
    }
}

test "resolver threads: a fetch that fails fast is tried again when its round ends" {
    // Goal: after a source fails at once, the slots wake when the entry's round ends
    // (`lazy_down_fail_ms`) and ask again; they do not sleep until the next probe
    // (`lazy_down_probe_ms`) or the deadline. Removing the round wake from `tick` fails this.
    // Method: one peer fails its first call and then serves; one read on the scaled clock lands
    // within the round and well before the probe interval.
    setup(&.{chunk_bytes});
    fixture.peers[0].behaviour = .failing;
    fixture.peers[0].misbehave_calls = 1;
    try open_resolver(1, false, false);
    const io = Scaled.io();
    try fixture.resolver.start(io);
    defer stop_resolver();
    var out: [chunk_bytes]u8 = @splat(0);
    const began = now_ms(io);
    const length = try fixture.resolver.read(0, 0, &out);
    const elapsed = now_ms(io) - began;
    try testing.expectEqualSlices(u8, truth(0, 0), out[0..length]);
    try testing.expectEqual(@as(u32, 2), fixture.peers[0].calls.load(.monotonic));
    try testing.expect(elapsed >= constants.lazy_down_fail_ms);
    comptime assert(constants.lazy_down_fail_ms + wake_slack_ms < constants.lazy_down_probe_ms);
    try testing.expect(elapsed < constants.lazy_down_fail_ms + wake_slack_ms);
}

// The schedule's pending table, alone.

const long_chunks = constants.lazy_pending_max + 8;
var long_hashes: [long_chunks]Digest = undefined;
var long_objects: [1]lazy.Object = undefined;
var long_states: [1]schedule_mod.ObjectState = undefined;
var schedule_state: Schedule = undefined;

/// A schedule over one object of more chunks than the pending table holds.
fn schedule_setup() *Schedule {
    const zero = std.mem.zeroes(Digest);
    @memset(&long_hashes, zero);
    long_objects[0] = .{
        .wanted = .{
            .id = zero,
            .attrs = attrs,
            .size = @as(u64, long_chunks) * chunk_bytes,
            .content = zero,
            .hashes = &long_hashes,
        },
        .locations = &.{},
        .chaining = &.{},
    };
    const names = [_][]const u8{"peer a"};
    schedule_state.init(.{ .objects = &long_objects }, &long_states, chunk_bytes, &names, false);
    return &schedule_state;
}

/// Fills the table: `bound` entries of `purpose`, the last `last` instead.
fn fill_table(
    schedule: *Schedule,
    purpose: schedule_mod.Purpose,
    last: schedule_mod.Purpose,
) !void {
    var chunk: u32 = 0;
    while (chunk < constants.lazy_pending_max) : (chunk += 1) {
        const which = if (chunk + 1 == constants.lazy_pending_max) last else purpose;
        const ask: schedule_mod.Ask = .{ .purpose = which, .began_ms = 0 };
        try testing.expect(schedule.request(0, chunk, ask, 0) != null);
    }
}

fn queued_of(schedule: *const Schedule, purpose: schedule_mod.Purpose) u32 {
    var count: u32 = 0;
    for (&schedule.pending) |*entry| {
        count += @intFromBool(entry.state == .queued and entry.purpose == purpose);
    }
    return count;
}

test "schedule: a reader gets a ticket from a table full of speculative entries" {
    // Goal: speculative entries (fill, readahead) never keep a reader out: with the table full
    // of them, an on-demand request still gets a ticket, and a fill entry goes first.
    // Method: fill the table to `lazy_pending_max` with fill, then readahead, then readahead
    // with one fill entry; each time a speculative request one past the bound gets nothing and
    // an on-demand one gets a ticket.
    const bound = constants.lazy_pending_max;
    const on_demand: schedule_mod.Ask = .{ .purpose = .on_demand, .began_ms = 0 };
    for ([_]schedule_mod.Purpose{ .fill, .readahead }) |purpose| {
        const schedule = schedule_setup();
        try fill_table(schedule, purpose, purpose);
        try testing.expectEqual(bound, queued_of(schedule, purpose));
        const extra: schedule_mod.Ask = .{ .purpose = purpose, .began_ms = 0 };
        try testing.expect(schedule.request(0, bound, extra, 0) == null);
        const ticket = schedule.request(0, bound, on_demand, 0).?;
        try testing.expectEqual(schedule_mod.Purpose.on_demand, schedule.entry_of(ticket).purpose);
        try testing.expectEqual(bound - 1, queued_of(schedule, purpose));
    }
    const schedule = schedule_setup();
    try fill_table(schedule, .readahead, .fill);
    _ = schedule.request(0, bound, on_demand, 0).?;
    try testing.expectEqual(@as(u32, 0), queued_of(schedule, .fill));
    try testing.expectEqual(bound - 1, queued_of(schedule, .readahead));
}

test "schedule: a reader past a table full of readers is refused with an event" {
    // Goal: with every entry a reader's, the request one past the bound gets no ticket, and
    // `refuse` (what the resolver then calls) leaves an `unavailable` event and an error.
    // Method: `lazy_pending_max` on-demand requests (the last at the bound) all get tickets;
    // the next gets null; then `refuse`.
    const bound = constants.lazy_pending_max;
    const schedule = schedule_setup();
    try fill_table(schedule, .on_demand, .on_demand);
    try testing.expectEqual(bound, queued_of(schedule, .on_demand));
    const on_demand: schedule_mod.Ask = .{ .purpose = .on_demand, .began_ms = 0 };
    try testing.expect(schedule.request(0, bound, on_demand, 0) == null);
    try testing.expectEqual(bound, queued_of(schedule, .on_demand));
    try testing.expectEqual(@as(u32, 0), schedule.events_count);
    schedule.refuse(0, bound);
    const event = schedule.pop_event().?;
    try testing.expectEqual(lazy.Event.Kind.unavailable, event.kind);
    try testing.expectEqual(bound, event.chunk);
    try testing.expectEqual(@as(u64, 1), schedule.report.errors);
    try testing.expect(schedule.pop_event() == null);
}

test "schedule: events past a full ring are counted as dropped" {
    // Goal: an event the ring has no room for is never silent: `events_dropped` counts it.
    // Method: `lazy_pending_max` refusals fill the ring with nothing dropped; three more are
    // dropped; one popped makes room for exactly one more.
    const bound = constants.lazy_pending_max;
    const schedule = schedule_setup();
    var chunk: u32 = 0;
    while (chunk < bound) : (chunk += 1) schedule.refuse(0, chunk);
    try testing.expectEqual(bound, schedule.events_count);
    try testing.expectEqual(@as(u64, 0), schedule.report.events_dropped);
    for (0..3) |_| schedule.refuse(0, bound);
    try testing.expectEqual(@as(u64, 3), schedule.report.events_dropped);
    try testing.expectEqual(@as(u32, 0), schedule.pop_event().?.chunk);
    schedule.refuse(0, bound + 1);
    try testing.expectEqual(@as(u64, 3), schedule.report.events_dropped);
    schedule.refuse(0, bound + 2);
    try testing.expectEqual(@as(u64, 4), schedule.report.events_dropped);
    try testing.expectEqual(@as(u64, bound + 5), schedule.report.errors);
}

test "resolver: eight sources are accepted and nine refused" {
    // Goal: `init` holds `lazy_sources_max`, counting the registry as a source.
    // Method: init with 7 peers and the registry, and 8 peers alone (accepted, then freed);
    // with 8 peers and the registry, and 9 peers alone, `TooManySources`.
    comptime assert(constants.lazy_sources_max == 8);
    setup(&.{chunk_bytes});
    try open_resolver(7, true, false);
    try testing.expectEqual(@as(u8, 8), fixture.resolver.source_count());
    close_resolver();
    try open_resolver(8, false, false);
    try testing.expectEqual(@as(u8, 8), fixture.resolver.source_count());
    close_resolver();
    try testing.expectError(error.TooManySources, open_resolver(8, true, false));
    try testing.expectError(error.TooManySources, open_resolver(9, false, false));
}

// The resolver on one thread: no `start`, its reader and slot steps driven by hand.

/// Runs every job the slots take at `now` to its end; how many ran.
fn pump(now: u64) u32 {
    const resolver = &fixture.resolver;
    var work: Work = undefined;
    var ran: u32 = 0;
    var progress = true;
    while (progress) {
        progress = false;
        for (0..constants.lazy_slots) |at| {
            const slot: u32 = @intCast(at);
            if (resolver.schedule.jobs[slot].active) continue;
            if (!resolver.slot_take(slot, &work, now)) continue;
            resolver.slot_fetch(slot, &work);
            resolver.slot_finish(slot, &work, now);
            resolver.drain_events();
            ran += 1;
            progress = true;
        }
        assert(ran <= constants.lazy_pending_max);
    }
    return ran;
}

/// A read at `now`: begun, every job it needs run, polled.
fn read_at(object: lazy.ObjectIndex, chunk: u32, out: []u8, now: u64) Step {
    const step = fixture.resolver.read_begin(object, chunk, out, now);
    if (step != .wait) return step;
    _ = pump(now);
    return fixture.resolver.read_poll(step.wait, out, now);
}

fn expect_true_read(object: lazy.ObjectIndex, chunk: u32, now: u64) !void {
    var out: [chunk_bytes]u8 = @splat(0xaa);
    const step = read_at(object, chunk, &out, now);
    try testing.expect(step == .done);
    try testing.expectEqualSlices(u8, truth(object, chunk), out[0..step.done]);
}

test "resolver: a lie on a job that ends after its read's deadline is still named" {
    // Goal: a source that sends wrong bytes is named (`lied` event, marked bad for the object)
    // even when its job ends after the reader gave up, and the peer is told once.
    // Method: one lying peer; the job is taken and fetched, the read is polled at its deadline
    // (Unavailable), and only then does the job finish.
    setup(&.{chunk_bytes});
    fixture.peers[0].behaviour = .lying;
    fixture.peers[0].misbehave_calls = misbehave_always;
    try open_resolver(1, false, false);
    defer close_resolver();
    const resolver = &fixture.resolver;
    var out: [chunk_bytes]u8 = @splat(0);
    const step = resolver.read_begin(0, 0, &out, 0);
    var work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &work, 0));
    resolver.slot_fetch(0, &work);
    try testing.expectEqual(schedule_mod.Result.lied, work.results[0]);
    const late = resolver.read_poll(step.wait, &out, deadline_ms);
    try testing.expectEqual(lazy.ReadError.Unavailable, late.failed);
    try testing.expectEqual(@as(u32, 0), events_of(.lied, ""));
    resolver.slot_finish(0, &work, deadline_ms + 1);
    resolver.drain_events();
    try testing.expectEqual(@as(u32, 1), events_of(.lied, "peer a"));
    try testing.expectEqual(@as(u32, 1), events_of(.unavailable, ""));
    try testing.expect(resolver.objects[0].bad & 1 != 0);
    try testing.expectEqual(@as(u32, 1), fixture.peers[0].lied_told.load(.monotonic));
    for (&resolver.schedule.pending) |*entry| try testing.expect(entry.state == .free);
}

test "resolver: a source that lied about an object is named so in each later read's E1203" {
    // Goal: the `unavailable` event of the read that was lied to says `lied`, and that of a
    // later read of the same object, which never asks the source again, says `lied_before`
    // rather than `not_tried` ("not asked"); both fail at once, with no deadline passed.
    // Method: one lying peer and a two-chunk object; read chunk 0 (one job, a lie), then
    // chunk 1, both at 1 ms; the peer is asked once.
    setup(&.{2 * chunk_bytes});
    fixture.peers[0].behaviour = .lying;
    fixture.peers[0].misbehave_calls = misbehave_always;
    try open_resolver(1, false, false);
    defer close_resolver();
    const resolver = &fixture.resolver;
    var out: [chunk_bytes]u8 = @splat(0);
    const step = resolver.read_begin(0, 0, &out, 0);
    try testing.expectEqual(schedule_mod.Result.lied, try one_job());
    const first = resolver.read_poll(step.wait, &out, 1);
    try testing.expectEqual(lazy.ReadError.Unavailable, first.failed);
    const again = resolver.read_begin(0, 1, &out, 1);
    const later = resolver.read_poll(again.wait, &out, 1);
    try testing.expectEqual(lazy.ReadError.Unavailable, later.failed);
    resolver.drain_events();
    try testing.expectEqual(@as(u32, 1), events_of(.lied, "peer a"));
    try testing.expectEqual(@as(u32, 2), events_of(.unavailable, ""));
    const expected = [2]lazy.Outcome{ .lied, .lied_before };
    var seen: u32 = 0;
    for (fixture.events[0..fixture.events_count.load(.monotonic)]) |*event| {
        if (event.kind != .unavailable) continue;
        try testing.expectEqual(seen, event.chunk);
        try testing.expectEqual(@as(u8, 1), event.sources_count);
        try testing.expectEqual(expected[seen], event.outcomes[0]);
        seen += 1;
    }
    try testing.expectEqual(@as(u32, 2), seen);
    try testing.expectEqual(@as(u32, 1), fixture.peers[0].calls.load(.monotonic));
}

test "resolver: a read that arrives mid-fill is served before the next fill request" {
    // Goal: the supervisor's condition on `lazy_fill_idle_ms` (S2 slice 6): the fill takes no
    // request until no reader has asked for `lazy_fill_idle_ms`; a read that arrives while a fill
    // request is in flight is taken next, and no fill request starts until the idle time has
    // passed again since that read.
    // Method: one peer (no coalescing), the fill on, a fake clock driven by hand: the fill
    // slot is refused before the idle time, takes one chunk at it, and while that is in flight
    // a read of a chunk the fill queued arrives.
    setup(&.{ 4 * chunk_bytes, 4 * chunk_bytes });
    try open_resolver(1, false, true);
    defer close_resolver();
    const resolver = &fixture.resolver;
    const fill_slot = constants.lazy_fetches_max;
    const idle = constants.lazy_fill_idle_ms;
    var work: Work = undefined;
    try testing.expect(!resolver.slot_take(fill_slot, &work, idle - 1));
    try testing.expect(resolver.slot_take(fill_slot, &work, idle));
    try testing.expectEqual(schedule_mod.Purpose.fill, work.purposes[0]);
    try testing.expect(resolver.schedule.queued_fill() > 0);
    resolver.slot_fetch(fill_slot, &work);
    // Mid-fill: a read of object 1's last chunk, which the fill has queued.
    const arrived = idle + 1;
    var out: [chunk_bytes]u8 = @splat(0);
    const step = resolver.read_begin(1, 3, &out, arrived);
    try testing.expect(step == .wait);
    resolver.slot_finish(fill_slot, &work, arrived + 1);
    for (fill_slot..constants.lazy_slots) |slot| {
        try testing.expect(!resolver.slot_take(@intCast(slot), &work, arrived + 1));
        try testing.expect(!resolver.slot_take(@intCast(slot), &work, arrived + idle - 1));
    }
    var read_work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &read_work, arrived + 1));
    try testing.expectEqual(schedule_mod.Purpose.on_demand, read_work.purposes[0]);
    try testing.expectEqual(@as(lazy.ObjectIndex, 1), read_work.objects[0]);
    try testing.expectEqual(@as(u32, 3), read_work.chunks[0]);
    resolver.slot_fetch(0, &read_work);
    resolver.slot_finish(0, &read_work, arrived + 2);
    const done = resolver.read_poll(step.wait, &out, arrived + 2);
    try testing.expect(done == .done);
    try testing.expectEqualSlices(u8, truth(1, 3), out[0..done.done]);
    // Idle again since the read: the fill goes on.
    try testing.expect(resolver.slot_take(fill_slot, &work, arrived + idle));
    try testing.expectEqual(schedule_mod.Purpose.fill, work.purposes[0]);
    resolver.slot_fetch(fill_slot, &work);
    resolver.slot_finish(fill_slot, &work, arrived + idle);
}

test "resolver: objects_local counts each whole object once and never goes down" {
    // Goal: with the fill off, `objects_local` counts an object whole at init, counts an
    // object once when its last chunk lands, and does not drop when a gc removes an object.
    // Method: object 0 is landed whole before init; object 1 is read chunk by chunk (its last
    // chunk twice); object 0 is removed from the store and read again.
    setup(&.{ 2 * chunk_bytes, 2 * chunk_bytes });
    try testing.expectEqual(land_mod.Landed.landed, land_chunk(0, 0));
    try testing.expectEqual(land_mod.Landed.whole, land_chunk(0, 1));
    try open_resolver(1, false, false);
    defer close_resolver();
    const report = &fixture.resolver.schedule.report;
    try testing.expectEqual(@as(u32, 1), report.objects_local);
    try expect_true_read(1, 0, 0);
    try testing.expectEqual(@as(u32, 1), report.objects_local);
    try expect_true_read(1, 1, 0);
    try testing.expectEqual(@as(u32, 2), report.objects_local);
    try expect_true_read(1, 1, 0);
    try testing.expectEqual(@as(u32, 2), report.objects_local);
    var path: PathBuf = undefined;
    fixture.files.remove_path(fixture.store.object_path(&path, fixture.objects[0].wanted.id));
    try testing.expect(!land_mod.object_is_whole(&fixture.store, &fixture.objects[0].wanted));
    try testing.expectEqual(@as(u32, 2), report.objects_local);
    try expect_true_read(0, 0, 0);
    try expect_true_read(0, 1, 0);
    try testing.expectEqual(@as(u32, 2), report.objects_local);
    try testing.expectEqual(@as(u32, 4), fixture.peers[0].calls.load(.monotonic));
}

/// The next job's source at `now` for a read of chunk 0 of `object` the peer did not find.
fn source_after_not_found(object: lazy.ObjectIndex, now: u64) !?u8 {
    const resolver = &fixture.resolver;
    var out: [chunk_bytes]u8 = @splat(0);
    const step = resolver.read_begin(object, 0, &out, now);
    var work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &work, now));
    try testing.expectEqual(@as(u8, 0), work.job.source);
    resolver.slot_fetch(0, &work);
    try testing.expectEqual(schedule_mod.Result.not_found, work.results[0]);
    resolver.slot_finish(0, &work, now);
    const source: ?u8 = if (resolver.slot_take(0, &work, now)) work.job.source else null;
    if (source != null) {
        resolver.slot_fetch(0, &work);
        resolver.slot_finish(0, &work, now);
    }
    // Without the registry, the next round asks the peer again, which serves now.
    fixture.peers[0].misbehave_calls = 0;
    const round = now + constants.lazy_down_fail_ms;
    // The poll ticks the schedule, which starts the next round; the slots do not tick.
    var done = resolver.read_poll(step.wait, &out, round);
    if (source == null) {
        try testing.expect(done == .wait);
        _ = pump(round);
        done = resolver.read_poll(step.wait, &out, round);
    }
    try testing.expect(done == .done);
    try testing.expectEqualSlices(u8, truth(object, 0), out[0..done.done]);
    return source;
}

test "resolver: an index location it cannot use drops the registry for that object" {
    // Goal: `init` drops the registry hint of an object whose locations are unusable (a range
    // of no bytes, one longer than `lazy_range_bytes_max`, or not one per chunk); the registry
    // is never asked for it and the peer serves its reads. A good object keeps the registry.
    // Method: four objects, three with one fault each; a peer that does not find chunk 0 the
    // first time; the slot's next source is the registry only for the good object.
    setup(&.{ 2 * chunk_bytes, 2 * chunk_bytes, 2 * chunk_bytes, 2 * chunk_bytes });
    fixture.locations[fixture.firsts[1] + 1].length = 0;
    fixture.locations[fixture.firsts[2]].length = constants.lazy_range_bytes_max + 1;
    fixture.objects[3].locations = fixture.objects[3].locations[0..1];
    fixture.peers[0].behaviour = .not_found;
    try open_resolver(1, true, false);
    defer close_resolver();
    const no_registry = [_]bool{ false, true, true, true };
    for (no_registry, fixture.resolver.objects) |expected, state| {
        try testing.expectEqual(expected, state.no_registry);
    }
    for (0..fixture.objects_count) |at| {
        const object: lazy.ObjectIndex = @intCast(at);
        fixture.peers[0].misbehave_calls = misbehave_always;
        const registry_calls = fixture.registry.calls.load(.monotonic);
        const now = @as(u64, object) * deadline_ms;
        const source = try source_after_not_found(object, now);
        const used: u32 = fixture.registry.calls.load(.monotonic) - registry_calls;
        if (no_registry[at]) {
            try testing.expect(source == null);
            try testing.expectEqual(@as(u32, 0), used);
        } else {
            try testing.expectEqual(@as(?u8, 1), source);
            try testing.expectEqual(@as(u32, 1), used);
        }
    }
}

test "resolver: a damaged chunk file is fetched again and replaced" {
    // Goal: a chunk file whose bytes do not hash right is not served; the chunk is fetched
    // again, the put replaces the file, and the read returns the true bytes.
    // Method: land chunk 0 of a two-chunk object as a chunk file, flip one of its bytes, read.
    setup(&.{2 * chunk_bytes});
    try testing.expectEqual(land_mod.Landed.landed, land_chunk(0, 0));
    var path: PathBuf = undefined;
    const id = fixture.objects[0].wanted.id;
    fixture.files.flip_byte(chunks_mod.partial_chunk(&fixture.store, &path, id, 0), 3);
    try open_resolver(1, false, false);
    defer close_resolver();
    var out: [chunk_bytes]u8 = @splat(0);
    const wanted = &fixture.objects[0].wanted;
    const damaged = land_mod.read_local(&fixture.store, wanted, &.{}, 0, &out, null);
    try testing.expectError(error.Damaged, damaged);
    try expect_true_read(0, 0, 0);
    try testing.expectEqual(@as(u32, 1), fixture.peers[0].calls.load(.monotonic));
    const length = try land_mod.read_local(&fixture.store, wanted, &.{}, 0, &out, null);
    try testing.expectEqualSlices(u8, truth(0, 0), out[0..length]);
    try testing.expectEqual(@as(u32, 0), fixture.events_count.load(.monotonic));
}

test "resolver: chunks a gc removed are fetched again, never taken as damage" {
    // Goal: the supervisor's condition on the gc sweep of S2 slice 5: gc removes an unheld
    // object's `partial/<id>/` outright (a restore brings back its tree, not its chunks), and a
    // lazy read of the object afterwards fetches the chunks again with no event, no lie and no
    // damage. Method: land chunk 0 of a two-chunk object, remove its chunk directory as gc's
    // apply does, then read both chunks.
    setup(&.{2 * chunk_bytes});
    try testing.expectEqual(land_mod.Landed.landed, land_chunk(0, 0));
    var path: PathBuf = undefined;
    const id = fixture.objects[0].wanted.id;
    const chunk = chunks_mod.partial_chunk(&fixture.store, &path, id, 0);
    const directory = chunk[0..std.mem.lastIndexOfScalar(u8, chunk, '/').?];
    fixture.files.remove_path(chunk);
    fixture.files.remove_path(directory);
    try testing.expect(fixture.files.kind_of(directory) == null);
    try open_resolver(1, false, false);
    defer close_resolver();
    try expect_true_read(0, 0, 0);
    try expect_true_read(0, 1, 0);
    try testing.expectEqual(@as(u32, 2), fixture.peers[0].calls.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), fixture.events_count.load(.monotonic));
}

test "resolver: a damaged whole object fails the read at once with an event" {
    // Goal: a chunk of a whole object that does not hash right fails its read at once
    // (`Unavailable`, an `unavailable` event, an error counted), with no source asked: a put
    // never replaces a whole object. Its other chunks still read.
    // Method: land a two-chunk object whole, flip a byte of its chunk 0, read both chunks.
    setup(&.{2 * chunk_bytes});
    _ = land_chunk(0, 0);
    try testing.expectEqual(land_mod.Landed.whole, land_chunk(0, 1));
    var path: PathBuf = undefined;
    fixture.files.flip_byte(fixture.store.object_path(&path, fixture.objects[0].wanted.id), 3);
    try open_resolver(1, false, false);
    defer close_resolver();
    var out: [chunk_bytes]u8 = @splat(0);
    const step = fixture.resolver.read_begin(0, 0, &out, 0);
    try testing.expectEqual(lazy.ReadError.Unavailable, step.failed);
    try testing.expectEqual(@as(u32, 1), events_of(.unavailable, ""));
    try testing.expectEqual(@as(u64, 1), fixture.resolver.schedule.report.errors);
    try expect_true_read(0, 1, 0);
    try testing.expectEqual(@as(u32, 0), fixture.peers[0].calls.load(.monotonic));
}

test "resolver: a reader that joins later keeps its own deadline, and so does the first" {
    // Goal: a reader joining an entry later gets its own full deadline (the entry's is the
    // later of the two), and the first reader still fails at its own deadline.
    // Method: reader A at 0 and reader B at 10000 wait on one chunk whose job never ends;
    // A is polled just before and at its deadline, B at A's deadline and at its own.
    setup(&.{chunk_bytes});
    try open_resolver(1, false, false);
    defer close_resolver();
    const resolver = &fixture.resolver;
    const joined_ms = 10_000;
    var out_a: [chunk_bytes]u8 = @splat(0);
    var out_b: [chunk_bytes]u8 = @splat(0);
    const a = resolver.read_begin(0, 0, &out_a, 0).wait;
    var work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &work, 0));
    const b = resolver.read_begin(0, 0, &out_b, joined_ms).wait;
    try testing.expectEqual(joined_ms + deadline_ms, b.until_ms);
    const joined = resolver.schedule.entry_of(a.ticket);
    try testing.expectEqual(joined_ms + deadline_ms, joined.deadline_ms);
    try testing.expect(resolver.read_poll(a, &out_a, deadline_ms - 1) == .wait);
    const a_late = resolver.read_poll(a, &out_a, deadline_ms);
    try testing.expectEqual(lazy.ReadError.Unavailable, a_late.failed);
    try testing.expectEqual(@as(u32, 1), events_of(.unavailable, ""));
    try testing.expect(resolver.read_poll(b, &out_b, deadline_ms) == .wait);
    try testing.expect(resolver.read_poll(b, &out_b, joined_ms + deadline_ms - 1) == .wait);
    const b_late = resolver.read_poll(b, &out_b, joined_ms + deadline_ms);
    try testing.expectEqual(lazy.ReadError.Unavailable, b_late.failed);
    try testing.expectEqual(@as(u32, 2), events_of(.unavailable, ""));
    try testing.expectEqual(@as(u64, 2), resolver.schedule.report.errors);
    resolver.slot_fetch(0, &work);
    resolver.slot_finish(0, &work, joined_ms + deadline_ms + 1);
    for (&resolver.schedule.pending) |*entry| try testing.expect(entry.state == .free);
}

/// Takes, fetches and finishes one job for chunk 0 of object 0; its result.
fn one_job() !schedule_mod.Result {
    const resolver = &fixture.resolver;
    var work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &work, 0));
    resolver.slot_fetch(0, &work);
    resolver.slot_finish(0, &work, 0);
    resolver.drain_events();
    return work.results[0];
}

test "resolver: a short answer is a failed fetch, never a lie" {
    // Goal: a source that sends fewer bytes than asked has failed the fetch: the outcome is
    // `failed`, the source is not marked bad or named in a `lied` event, and a peer is not told.
    // Method: a peer that answers one byte short, then a registry that does; one job each.
    setup(&.{chunk_bytes});
    fixture.peers[0].behaviour = .short;
    fixture.peers[0].misbehave_calls = misbehave_always;
    try open_resolver(1, false, false);
    var out: [chunk_bytes]u8 = @splat(0);
    const step = fixture.resolver.read_begin(0, 0, &out, 0);
    try testing.expectEqual(schedule_mod.Result.failed, try one_job());
    const entry = fixture.resolver.schedule.entry_of(step.wait.ticket);
    try testing.expectEqual(lazy.Outcome.failed, entry.outcomes[0]);
    try testing.expectEqual(@as(u8, 0), fixture.resolver.objects[0].bad);
    try testing.expectEqual(@as(u32, 0), fixture.peers[0].lied_told.load(.monotonic));
    const late = fixture.resolver.read_poll(step.wait, &out, deadline_ms);
    try testing.expectEqual(lazy.ReadError.Unavailable, late.failed);
    try testing.expectEqual(@as(u32, 0), events_of(.lied, ""));
    close_resolver();

    fixture.registry.short = true;
    try open_resolver(0, true, false);
    defer close_resolver();
    const again = fixture.resolver.read_begin(0, 0, &out, 0);
    try testing.expectEqual(schedule_mod.Result.failed, try one_job());
    const range_entry = fixture.resolver.schedule.entry_of(again.wait.ticket);
    try testing.expectEqual(lazy.Outcome.failed, range_entry.outcomes[0]);
    try testing.expectEqual(@as(u8, 0), fixture.resolver.objects[0].bad);
    try testing.expectEqual(@as(u32, 0), events_of(.lied, ""));
    try testing.expectEqual(@as(u32, 1), fixture.registry.calls.load(.monotonic));
}

test "resolver: a range does not fetch again the chunks at its ends that are already local" {
    // Goal: readahead queues a chunk again after it landed (the schedule does not look in the
    // store); a range job that begins or ends with such a chunk asks the registry for the
    // missing chunks alone, so no byte is fetched twice (demo-s2 step 5).
    // Method: chunk 1 lands; readahead entries for chunks 1, 2 and 3 coalesce into one job;
    // the registry is asked for chunks 2 and 3 only.
    setup(&.{4 * chunk_bytes});
    try open_resolver(0, true, false);
    defer close_resolver();
    const resolver = &fixture.resolver;
    var out: [chunk_bytes]u8 = @splat(0);
    _ = resolver.read_begin(0, 1, &out, 0);
    try testing.expectEqual(schedule_mod.Result.landed, try one_job());
    const first = fixture.locations[fixture.firsts[0] + 1];
    try testing.expectEqual(@as(u64, first.length), fixture.registry.asked.load(.monotonic));
    for (1..4) |chunk| {
        const ask: schedule_mod.Ask = .{ .purpose = .readahead, .began_ms = 0 };
        try testing.expect(resolver.schedule.request(0, @intCast(chunk), ask, 0) != null);
    }
    var work: Work = undefined;
    try testing.expect(resolver.slot_take(0, &work, 0));
    try testing.expectEqual(@as(u8, 3), work.job.count);
    resolver.slot_fetch(0, &work);
    resolver.slot_finish(0, &work, 0);
    resolver.drain_events();
    const results = [_]schedule_mod.Result{ .local, .landed, .landed };
    try testing.expectEqualSlices(schedule_mod.Result, &results, work.results[0..3]);
    const second = fixture.locations[fixture.firsts[0] + 2].length;
    const third = fixture.locations[fixture.firsts[0] + 3].length;
    const asked = fixture.registry.asked.load(.monotonic);
    try testing.expectEqual(@as(u64, first.length) + second + third, asked);
    try testing.expectEqual(@as(u64, second) + third, work.sent);
}

test "resolver threads: stop waits for the fetches in flight, and the report counts their bytes" {
    // Goal: `stop` returns only once every fetch in flight has been answered and counted, so a
    // report made after it holds every byte the sources sent: the summary of a lazy run, made
    // after `lazy_server`'s `ended` stops the resolver, agrees with the registry's count.
    // Method: the fill alone over the registry; stop once it has asked, then compare the bytes
    // the registry was asked for (it answers every ask whole) with the report's.
    setup(&.{ 4 * chunk_bytes, 4 * chunk_bytes, 3 * chunk_bytes });
    try open_resolver(0, true, true);
    try fixture.resolver.start(Scaled.io());
    var waited: u32 = 0;
    while (fixture.registry.calls.load(.monotonic) == 0 and waited < wait_real_ms_max) {
        nap();
        waited += 1;
    }
    fixture.resolver.stop();
    try testing.expect(fixture.registry.calls.load(.monotonic) > 0);
    const report = fixture.resolver.report();
    try testing.expectEqual(fixture.registry.asked.load(.monotonic), report.source_bytes[0]);
    close_resolver();
}
