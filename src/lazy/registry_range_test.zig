//! Tests of the registry `Range` source over the simulated wire: closed ranges, the `206` check,
//! the refusals, and several resolver threads sharing one client.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const client_mod = @import("../registry/client.zig");
const digest_mod = @import("../registry/digest.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const reference_mod = @import("../registry/reference.zig");
const registry_range = @import("registry_range.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;

const blob_bytes = 300_000;

/// What the simulated registry does with the next requests.
const Mode = enum {
    ranges,
    whole,
    wrong_start,
    missing,
    /// The first range request is a 401 (the token ran out) whose body is `challenge_bytes`
    /// long; the token service gives a fresh token; ranges as `ranges` after.
    expired,
    /// Every range answer is a 206 of one byte.
    drip,
};

/// A 401's body, longer than any range a test asks for and one byte past the error bound.
var challenge_body: [constants.push_error_body_bytes + 1]u8 = @splat('x');
const token_answer = "{\"token\":\"fresh\"}";
const realm = "Bearer realm=\"https://auth.test/token\",service=\"registry.test\"";

const World = struct {
    blob: [blob_bytes]u8,
    mode: Mode,
    /// The Content-Range of the answer being served.
    range_text: [64]u8,
    /// Every Range header seen was closed and in bounds.
    closed: bool,
    sim: net_sim.SimNet,
    workspace: client_mod.Workspace,
    client: client_mod.Client,
    reference: reference_mod.Reference,
    diag: Diag,
    range: registry_range.RegistryRange,
    /// The 401's body length (`expired`).
    challenge_bytes: u32,
    /// Answers of each kind served.
    requests: u32,
    unauthorized: u32,
    token_requests: u32,
    /// The test's clock (`clock`), and how far each answer moves it.
    now_ms: u64,
    advance_ms: u64,

    fn setup(self: *World, seed: u64, mode: Mode) !void {
        self.challenge_bytes = 0;
        self.requests = 0;
        self.unauthorized = 0;
        self.token_requests = 0;
        self.now_ms = 1;
        self.advance_ms = 0;
        for (&self.blob, 0..) |*byte, at| byte.* = @truncate(at *% 31 +% (at >> 9));
        self.mode = mode;
        self.closed = true;
        self.sim.init(seed, .{ .context = self, .answer = answer });
        self.client = client_mod.Client.init(self.sim.interface(), &self.workspace, "x86_64");
        try reference_mod.parse("registry.test/lazy/app:1", &self.reference);
        self.diag.reset();
        try client_mod.candidates(&self.client, &self.reference, &self.client.places, &self.diag);
        self.client.winner = 0;
        const blob = digest_mod.Sha256.of(&self.blob);
        self.range.init(&self.client, &self.reference, blob, testing.io);
    }
};

/// The tests run one at a time; the world is too large for the stack.
var world: World = undefined;

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const self: *World = @ptrCast(@alignCast(context));
    assert(received.len == 0);
    self.requests += 1;
    self.now_ms += self.advance_ms;
    if (std.mem.eql(u8, request.host, "auth.test")) {
        self.token_requests += 1;
        served.* = .{ .status = 200, .body = token_answer };
        return;
    }
    if (self.mode == .expired and self.unauthorized == 0) {
        self.unauthorized += 1;
        const body = challenge_body[0..@as(usize, self.challenge_bytes)];
        served.* = .{ .status = 401, .www_authenticate = realm, .body = body };
        return;
    }
    const last = request.range_last orelse {
        self.closed = false;
        served.* = .{ .status = 200, .body = &self.blob };
        return;
    };
    if (last < request.range_from) self.closed = false;
    switch (self.mode) {
        .missing => served.* = .{ .status = 404 },
        .whole => served.* = .{ .status = 200, .body = &self.blob },
        .ranges, .wrong_start, .expired, .drip => {
            const from: usize = @intCast(request.range_from);
            const asked: usize = @intCast(@min(last + 1, blob_bytes));
            const end = if (self.mode == .drip) @min(from + 1, asked) else asked;
            const shown = if (self.mode == .wrong_start) from + 1 else from;
            const text = std.fmt.bufPrint(&self.range_text, "bytes {d}-{d}/{d}", .{
                shown, end - 1, blob_bytes,
            }) catch unreachable; // Three numbers fit.
            served.* = .{ .status = 206, .body = self.blob[from..end], .content_range = text };
        },
    }
}

test "registry range: a closed range gives exactly the bytes asked for" {
    // Goal: the request names both ends, a 206 for that range fills `out`, and a range that
    // runs past the blob's end comes back short rather than failing.
    try world.setup(1, .ranges);
    const source = world.range.source();
    var out: [5000]u8 = undefined;
    const got = try source.fetch(source.context, 1234, &out, 5000);
    try testing.expectEqual(@as(usize, out.len), got);
    try testing.expectEqualSlices(u8, world.blob[1234..][0..out.len], &out);
    const tail = try source.fetch(source.context, blob_bytes - 100, &out, 5000);
    try testing.expectEqual(@as(usize, 100), tail);
    try testing.expectEqualSlices(u8, world.blob[blob_bytes - 100 ..], out[0..100]);
    try testing.expect(world.closed);
    try testing.expectEqual(@as(u64, 0), world.range.failures.load(.monotonic));
}

test "registry range: an answer that is not a 206 for the range asked is never taken" {
    // Goal: a registry that ignores Range (200), answers for another range, or does not hold
    // the blob gives no bytes; the last is `NotFound`, the others `Failed`.
    var out: [64]u8 = undefined;
    const cases = [_]struct { mode: Mode, expected: anyerror }{
        .{ .mode = .whole, .expected = error.Failed },
        .{ .mode = .wrong_start, .expected = error.Failed },
        .{ .mode = .missing, .expected = error.NotFound },
    };
    for (cases, 0..) |case, seed| {
        try world.setup(seed + 10, case.mode);
        const source = world.range.source();
        try testing.expectError(case.expected, source.fetch(source.context, 10, &out, 5000));
        try testing.expect(world.range.diag.code != null);
        try testing.expectEqual(@as(u64, 1), world.range.failures.load(.monotonic));
    }
}

const threads_count = 4;
const fetches_per_thread = 16;

fn fetch_many(index: usize, ok: *std.atomic.Value(u32)) void {
    const source = world.range.source();
    var out: [700]u8 = undefined;
    for (0..fetches_per_thread) |round| {
        const offset = (index * 7919 + round * 104_729) % (blob_bytes - out.len);
        const got = source.fetch(source.context, offset, &out, 60_000) catch continue;
        if (got != out.len) continue;
        if (!std.mem.eql(u8, world.blob[offset..][0..out.len], &out)) continue;
        _ = ok.fetchAdd(1, .monotonic);
    }
}

test "registry range: resolver threads share one client, one fetch at a time" {
    // Goal: fetches from several threads at once each get their own range whole: the turn
    // keeps the client's state to one request at a time.
    try world.setup(20, .ranges);
    var ok: std.atomic.Value(u32) = .init(0);
    var threads: [threads_count]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, fetch_many, .{ index, &ok });
    }
    for (threads) |thread| thread.join();
    try testing.expectEqual(@as(u32, threads_count * fetches_per_thread), ok.load(.monotonic));
    try testing.expect(!world.range.busy);
    try testing.expect(world.closed);
}

/// The test's clock: `World.now_ms`, which each answer moves by `advance_ms`.
fn world_now_ms(context: *const anyopaque) u64 {
    const self: *const World = @ptrCast(@alignCast(context));
    assert(self.now_ms > 0);
    return self.now_ms;
}

fn world_clock() client_mod.Clock {
    return .{ .context = &world, .now_ms = world_now_ms };
}

test "registry range: a 401 whose body is longer than the range gets a fresh token" {
    // Goal: a token that runs out mid-run is fetched again for a range of any size: the 401's
    // body is bounded by the error bound, never by the range's length. Method: a 64-byte range
    // whose first answer is a 401 with a body of 4096 bytes, then the token, then the 206;
    // and a 401 one byte over the error bound, which fails with a coded line.
    try world.setup(30, .expired);
    world.challenge_bytes = constants.push_error_body_bytes;
    const source = world.range.source();
    var out: [64]u8 = undefined;
    const got = try source.fetch(source.context, 777, &out, 5000);
    try testing.expectEqual(@as(usize, out.len), got);
    try testing.expectEqualSlices(u8, world.blob[777..][0..out.len], &out);
    try testing.expectEqual(@as(u32, 1), world.unauthorized);
    try testing.expectEqual(@as(u32, 1), world.token_requests);
    try testing.expectEqual(@as(u64, 0), world.range.failures.load(.monotonic));

    try world.setup(31, .expired);
    world.challenge_bytes = constants.push_error_body_bytes + 1;
    try testing.expectError(error.Failed, source.fetch(source.context, 777, &out, 5000));
    try testing.expect(world.range.diag.code != null);
    try testing.expectEqual(@as(u32, 0), world.token_requests);
}

test "registry range: the token a 401 asks for comes out of the range's own time" {
    // Goal: a 401 does not give a range a second full timeout. Method: the test's clock moves
    // by the whole timeout with the 401; the range fails without asking for a token.
    try world.setup(32, .expired);
    world.challenge_bytes = 10;
    world.advance_ms = 5000;
    var out: [64]u8 = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const deadline = client_mod.Deadline.after(world_clock(), 5000);
    const blob = digest_mod.Sha256.of(&world.blob);
    const got = client_mod.fetch_range(
        &world.client,
        &world.reference,
        blob,
        0,
        &out,
        deadline,
        5000,
        &diag,
    );
    try testing.expectError(error.Failed, got);
    try testing.expect(diag.code != null);
    try testing.expectEqual(@as(u32, 1), world.unauthorized);
    try testing.expectEqual(@as(u32, 0), world.token_requests);
}

test "registry range: a registry that drips one byte per answer is cut off" {
    // Goal: the index fetch ends within one request's time however the registry splits its
    // answers. Method: 206s of one byte, each moving the clock a second; 2000 bytes would take
    // 2000 answers, and the fetch stops after `net_request_timeout_ms` of them. An honest
    // registry gives the same 2000 bytes in one answer.
    try world.setup(33, .drip);
    world.advance_ms = 1000;
    var out: [2000]u8 = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const blob = digest_mod.Sha256.of(&world.blob);
    const dripped = registry_range.fetch_whole(
        &world.client,
        &world.reference,
        blob,
        100,
        &out,
        world_clock(),
        &diag,
    );
    try testing.expectError(error.Failed, dripped);
    try testing.expect(diag.code != null);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "ran past its 120 seconds limit") != null);
    const answers_max = constants.net_request_timeout_ms / 1000;
    try testing.expect(world.requests <= answers_max);
    try testing.expect(world.requests >= answers_max - 1);

    try world.setup(34, .ranges);
    diag.reset();
    const clock = world_clock();
    try registry_range.fetch_whole(&world.client, &world.reference, blob, 100, &out, clock, &diag);
    try testing.expectEqualSlices(u8, world.blob[100..][0..out.len], &out);
    try testing.expectEqual(@as(u32, 1), world.requests);
}
