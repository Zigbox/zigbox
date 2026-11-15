//! The `fuse_serve` fuzzer: `zig build fuzz -- fuse_serve`. The lazy server's serving threads
//! (`fuse/serve.zig`) share one chunk cache (`fuse/cache.zig`), each reading chunks through its
//! own source. Each iteration builds a root of a few files, starts the real number of serving
//! threads (`lazy_fuse_threads`) over a fake `/dev/fuse` that hands out a queue of requests
//! (`INIT`, then `READ`, `GETATTR` and `READDIRPLUS`), and checks every reply as it is written.
//! One seed class runs at the real bounds: the store's chunk size, a file of up to 2.9 MiB, and
//! reads of up to `fuse_read_bytes_max` at offsets across chunks. Small chunk sizes make the cache
//! evict while other threads wait on it.
//!
//! The seed fixes the tree and the requests; the threads' interleaving is the scheduler's.
//!
//! Properties:
//!   1. Every request is answered exactly once, with its own `unique`, and nothing else is sent.
//!   2. A `READ` returns exactly the file's bytes at that offset (the oracle is the fixture's
//!      content), whatever the other threads read, evict or wait for at the same time.
//!   3. A `READ` of an object whose chunks fail is `EIO` with no data, and leaves the other
//!      objects' reads correct.
//!   4. `GETATTR` gives the node's size, and a listing of the root holds its entries.
//!   5. `stop` and `wait` join every thread, and no chunk read is left running.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const xattrs = @import("store/xattrs.zig");
const tree = @import("store/tree.zig");
const abi = @import("fuse/abi.zig");
const nodes = @import("fuse/nodes.zig");
const ops = @import("fuse/ops.zig");
const serve = @import("fuse/serve.zig");
const fixture_mod = @import("fuse/fixture.zig");
const cache_mod = @import("fuse/cache.zig");

const Digest = @import("store/digest.zig").Digest;
const threads = constants.lazy_fuse_threads;

const files_max = 6;
const nodes_room = 16;
const arena_limit = 8 * 1024;
const requests_max = 64;
const request_slot_bytes = 128;
const small_chunks_per_file_max = 6;
const big_bytes_min = 1024 * 1024 + 1;
const big_bytes_max = 2900 * 1024;
const small_file_bytes_max = 4096;
/// Yields the main thread waits for the replies before calling the run hung.
const spins_max = 1 << 30;

const Kind = enum(u8) { init, read, getattr, readdirplus };

const Request = struct {
    kind: Kind,
    nodeid: u64,
    offset: u64,
    size: u32,
    len: u32,
};

var fixture: fixture_mod.Fixture = undefined;
var pool: [fixture_mod.content_bytes]u8 = undefined;
var region: [nodes.memory_bytes(nodes_room, arena_limit)]u8 align(8) = undefined;
var table: nodes.Table = undefined;
var cache_memory: [cache_mod.memory_bytes(constants.store_chunk_bytes)]u8 align(8) = undefined;
var cache: cache_mod.Cache = undefined;
var thread_memory: [threads * serve.thread_memory_bytes]u8 align(8) = undefined;
var sources: [threads]ops.Chunks = undefined;
var bytes: [requests_max][request_slot_bytes]u8 = undefined;
var requests: [requests_max]Request = undefined;
var answered: [requests_max]std.atomic.Value(bool) = undefined;
var file_ids: [files_max]u64 = undefined;
/// What each request's reply was, written by the thread that sent it, read after the join.
var outcomes: [requests_max]Outcome = undefined;

const Outcome = enum(u8) { none, answered, data, failed, listing };

/// The queue the fake device hands out, and what the threads did with it.
var queue: struct {
    count: u32 = 0,
    next: std.atomic.Value(u32) = .init(0),
    answers: std.atomic.Value(u32) = .init(0),
    reading: std.atomic.Value(u32) = .init(0),
    overlapped: std.atomic.Value(bool) = .init(false),
} = .{};

/// What the iterations reached, so the test can see that no property was checked vacuously.
var reached: struct {
    real_bounds: u32 = 0,
    reads_with_data: u32 = 0,
    reads_failed: u32 = 0,
    reads_across_chunks: u32 = 0,
    listings: u32 = 0,
    overlapped: u32 = 0,
} = .{};

pub fn fuzz_fuse_serve(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const real = random.uintLessThan(u32, 4) == 0;
    const chunk_choices = [_]u32{ 8, 64, 4096 };
    const chunk_bytes = if (real)
        constants.store_chunk_bytes
    else
        chunk_choices[random.uintLessThan(usize, chunk_choices.len)];
    const root = make_root(random, real, chunk_bytes);
    table.init(nodes.carve(&region, nodes_room, arena_limit));
    table.build(fixture.source(), root) catch unreachable; // Room for the largest root.
    const file_count = table.node_count - 1;
    assert(file_count >= 1);
    for (file_ids[0..file_count], 0..) |*id, index| {
        id.* = abi.root_id + 1 + index;
        assert(table.node(id.*).?.kind == .file);
    }
    if (random.uintLessThan(u32, 3) == 0) {
        fixture.failing = table.node(file_ids[random.uintLessThan(usize, file_count)]).?.digest;
    }
    const io = std.Io.Threaded.global_single_threaded.io();
    cache.init(io, cache_memory[0..@intCast(cache_mod.memory_bytes(chunk_bytes))], chunk_bytes);
    const server: ops.Server = .{ .table = &table, .cache = &cache, .chunk_bytes = chunk_bytes };
    make_requests(random, file_count, chunk_bytes);
    for (&sources) |*source| source.* = .{ .context = &fixture, .read = read_chunk };
    var serving = serve.Serving.init(&server, device(), &sources, &thread_memory);
    serving.handshake() catch unreachable; // The first request is a well formed INIT.
    serving.start() catch unreachable; // A fuzz run that cannot spawn threads is not a finding.
    var spins: u64 = 0;
    while (queue.answers.load(.acquire) < queue.count) : (spins += 1) {
        assert(spins < spins_max); // A request never answered: a thread lost or hung.
        std.Thread.yield() catch {};
    }
    serving.stop();
    serving.wait();
    assert(serving.started == 0);
    assert(queue.reading.load(.acquire) == 0);
    for (answered[0..queue.count]) |*one| assert(one.load(.acquire));
    tally();
    if (real) reached.real_bounds += 1;
    if (queue.overlapped.load(.acquire)) reached.overlapped += 1;
}

fn tally() void {
    assert(queue.count >= 1);
    assert(outcomes[0] == .answered); // INIT.
    for (outcomes[0..queue.count]) |outcome| {
        switch (outcome) {
            .none => unreachable, // Every request was answered.
            .answered => {},
            .data => reached.reads_with_data += 1,
            .failed => reached.reads_failed += 1,
            .listing => reached.listings += 1,
        }
    }
}

/// A root of 1 to `files_max` files of random content; at the real bounds, the first is big.
fn make_root(random: std.Random, real: bool, chunk_bytes: u32) Digest {
    fixture.init(chunk_bytes);
    const count = random.intRangeAtMost(u32, 1, files_max);
    _ = fixture.begin();
    var used: u32 = 0;
    for (0..count) |index| {
        const length = if (real and index == 0)
            random.intRangeAtMost(u32, big_bytes_min, big_bytes_max)
        else if (real)
            random.uintAtMost(u32, small_file_bytes_max)
        else
            random.uintAtMost(u32, small_chunks_per_file_max * chunk_bytes);
        assert(used + length <= pool.len);
        const content = pool[used..][0..length];
        random.bytes(content);
        used += length;
        const name = [2]u8{ 'f', '0' + @as(u8, @intCast(index)) }; // Rising: sorted.
        _ = fixture.file(&name, content, 0o644, &xattrs.empty) catch unreachable; // Room.
    }
    assert(fixture.file_count == count);
    const own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    return fixture.finish_root(own) catch unreachable; // A handful of entries.
}

/// The queue: `INIT` first, then requests for the root and its files.
fn make_requests(random: std.Random, file_count: u32, chunk_bytes: u32) void {
    assert(file_count >= 1);
    assert(file_count <= files_max);
    const count = random.intRangeAtMost(u32, 2, requests_max);
    requests[0] = .{ .kind = .init, .nodeid = 0, .offset = 0, .size = 0, .len = 0 };
    for (1..count) |index| {
        const pick = random.uintLessThan(u32, 8);
        const nodeid = file_ids[random.uintLessThan(usize, file_count)];
        const kind: Kind = if (pick < 5) .read else if (pick < 7) .getattr else .readdirplus;
        requests[index] = switch (kind) {
            .read => random_read(random, nodeid, chunk_bytes),
            .getattr => .{ .kind = .getattr, .nodeid = nodeid, .offset = 0, .size = 0, .len = 0 },
            .readdirplus => .{
                .kind = .readdirplus,
                .nodeid = abi.root_id,
                .offset = 0,
                .size = 4096,
                .len = 0,
            },
            .init => unreachable,
        };
    }
    for (0..count) |index| encode(@intCast(index));
    queue = .{ .count = count };
    for (&answered) |*one| one.* = .init(false);
    @memset(&outcomes, .none);
}

/// A read at an offset near a chunk boundary of the file, or anywhere in it.
fn random_read(random: std.Random, nodeid: u64, chunk_bytes: u32) Request {
    const size = table.node(nodeid).?.size;
    const boundary = random.uintAtMost(u64, size / chunk_bytes) * chunk_bytes;
    const near = boundary -| random.uintAtMost(u64, 16);
    const offset = if (random.boolean()) near else random.uintAtMost(u64, size + 8);
    const wanted = random.intRangeAtMost(u32, 1, constants.fuse_read_bytes_max);
    if (offset % chunk_bytes + wanted > chunk_bytes) reached.reads_across_chunks += 1;
    assert(wanted <= constants.fuse_read_bytes_max);
    assert(offset <= size + 8);
    return .{ .kind = .read, .nodeid = nodeid, .offset = offset, .size = wanted, .len = 0 };
}

fn encode(index: u32) void {
    const request = &requests[index];
    assert(index < requests_max);
    const unique = @as(u64, index) + 1;
    const out = &bytes[index];
    const written = switch (request.kind) {
        .init => fixture_mod.request(out, .init, 0, unique, &.{std.mem.asBytes(&init_in)}),
        .getattr => fixture_mod.request(out, .getattr, request.nodeid, unique, &.{
            std.mem.asBytes(&std.mem.zeroes(abi.GetattrIn)),
        }),
        .read, .readdirplus => read: {
            var in = std.mem.zeroes(abi.ReadIn);
            in.offset = request.offset;
            in.size = request.size;
            const opcode: abi.Opcode = if (request.kind == .read) .read else .readdirplus;
            break :read fixture_mod.request(out, opcode, request.nodeid, unique, &.{
                std.mem.asBytes(&in),
            });
        },
    };
    request.len = @intCast(written.len);
    assert(request.len <= request_slot_bytes);
}

const init_in: abi.InitIn = .{
    .major = abi.major_version,
    .minor = abi.minor_version,
    .max_readahead = 128 * 1024,
    .flags = 0,
};

// The fake device.

fn device() serve.Device {
    assert(queue.count >= 1);
    assert(requests[0].kind == .init);
    return .{ .context = &queue, .receive = receive, .send = send };
}

fn receive(context: *anyopaque, buffer: []u8) serve.ReceiveError!u32 {
    assert(context == @as(*anyopaque, &queue));
    assert(buffer.len == constants.fuse_request_bytes);
    const index = queue.next.fetchAdd(1, .acq_rel);
    if (index >= queue.count) {
        std.Thread.yield() catch {};
        return error.Again;
    }
    const length = requests[index].len;
    @memcpy(buffer[0..length], bytes[index][0..length]);
    return length;
}

fn send(context: *anyopaque, reply: []const u8) void {
    assert(context == @as(*anyopaque, &queue));
    const out = fixture_mod.reply_header(reply);
    assert(out.len == reply.len);
    assert(out.unique >= 1);
    assert(out.unique <= queue.count);
    const index: u32 = @intCast(out.unique - 1);
    const already = answered[index].swap(true, .acq_rel);
    assert(!already); // Each request answered once.
    outcomes[index] = check_reply(&requests[index], out, reply[@sizeOf(abi.OutHeader)..]);
    _ = queue.answers.fetchAdd(1, .acq_rel);
}

fn check_reply(request: *const Request, out: abi.OutHeader, data: []const u8) Outcome {
    assert(request.len > 0);
    switch (request.kind) {
        .init => {
            assert(out.@"error" == 0);
            return .answered;
        },
        .read => return check_read(request, out, data),
        .getattr => {
            assert(out.@"error" == 0);
            const attr = std.mem.bytesToValue(abi.AttrOut, data[0..@sizeOf(abi.AttrOut)]);
            assert(attr.attr.size == table.node(request.nodeid).?.size);
            return .answered;
        },
        .readdirplus => {
            assert(out.@"error" == 0);
            assert(data.len >= @sizeOf(abi.Direntplus)); // The root holds a file at least.
            assert(data.len <= request.size);
            return .listing;
        },
    }
}

fn check_read(request: *const Request, out: abi.OutHeader, data: []const u8) Outcome {
    const found = table.node(request.nodeid).?;
    const content = fixture.content_of(found.digest).?;
    assert(content.len == found.size);
    const failing = if (fixture.failing) |failing| failing.eql(found.digest) else false;
    if (request.offset >= content.len) {
        assert(out.@"error" == 0);
        assert(data.len == 0);
        return .answered;
    }
    if (failing) {
        assert(-out.@"error" == @backingInt(abi.Errno.io));
        assert(data.len == 0);
        return .failed;
    }
    assert(out.@"error" == 0);
    const length = @min(request.size, content.len - request.offset);
    assert(std.mem.eql(u8, data, content[@intCast(request.offset)..][0..@intCast(length)]));
    return .data;
}

/// A serving thread's chunk source: the fixture's content, read-only, safe from every thread
/// (the fixture's own `read` counts its reads, which is not).
fn read_chunk(context: *anyopaque, wanted: ops.Object, index: u32, out: []u8) ops.ChunkError!u32 {
    assert(context == @as(*anyopaque, &fixture));
    assert(out.len >= fixture.chunk_bytes);
    if (queue.reading.fetchAdd(1, .acq_rel) > 0) queue.overlapped.store(true, .release);
    defer _ = queue.reading.fetchSub(1, .acq_rel);
    if (fixture.failing) |failing| {
        if (failing.eql(wanted.id)) return error.Unavailable;
    }
    const content = fixture.content_of(wanted.id) orelse return error.Unavailable;
    const start = @as(u64, index) * fixture.chunk_bytes;
    if (start >= content.len) return error.Unavailable;
    const length: u32 = @intCast(@min(content.len - start, fixture.chunk_bytes));
    @memcpy(out[0..length], content[@intCast(start)..][0..length]);
    return length;
}

test "fuse_serve fuzzer: seeds at small and real bounds reach every property" {
    // Goal: the multi-threaded server runs clean over a shared cache and is not vacuous.
    // Method: sixty seeds (about a quarter at the real chunk size), then counts of real-bounds
    // iterations, reads with data, failed reads, reads across chunks and listings, each above
    // zero. Overlapping chunk reads depend on the scheduler, so they are counted, not required.
    errdefer std.debug.print("reached: {any}\n", .{reached});
    reached = .{};
    for (0..60) |seed| fuzz_fuse_serve(seed);
    try std.testing.expect(reached.real_bounds > 3);
    try std.testing.expect(reached.reads_with_data > 100);
    try std.testing.expect(reached.reads_failed > 5);
    try std.testing.expect(reached.reads_across_chunks > 100);
    try std.testing.expect(reached.listings > 20);
}
