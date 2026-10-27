//! The simulator's network: a registry in memory behind the `net.zig` interface, driven by a
//! seeded PRNG that can fail a request, cut a connection, or deliver a body in odd pieces. It
//! stands for the wire only; what a registry says is a `Responder` the test supplies (the test
//! registry of `src/testing/vm/registry_fixture.zig`, behind `test_registry.zig`).
//!
//! It follows the same rules as the real network (`host_real_net.zig`): the bounds are checked
//! against the declared length before a body byte is read and again as bytes arrive, a body that
//! ends before its declared length is `Truncated`, and the bearer token is used and never kept
//! by the code under test. The log it keeps (for assertions) holds the token, because a test asks
//! "was the token sent on the retry"; nothing prints the log.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const net = @import("net.zig");

/// What a registry answers for one request.
pub const Served = struct {
    status: u16 = 200,
    /// The declared length; null means the body's own length.
    content_length: ?u64 = null,
    www_authenticate: []const u8 = "",
    retry_after: []const u8 = "",
    content_type: []const u8 = "",
    content_digest: []const u8 = "",
    location: []const u8 = "",
    content_range: []const u8 = "",
    body: []const u8 = "",
    /// How many body bytes arrive before the connection drops; null means all of them.
    deliver: ?u64 = null,
};

pub const Responder = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, request: *const net.Request, served: *Served) void,
};

pub const Faults = struct {
    /// Every request fails with `fail_error` with this probability, per thousand.
    fail_per_mille: u16 = 0,
    /// One-shot: the request with this zero-based index fails with `fail_error`.
    fail_request: ?u32 = null,
    fail_error: net.Error = error.ConnectFailed,
    /// Bodies are delivered in pieces of 1 to this many bytes, chosen by the PRNG.
    chunk_bytes_max: u32 = 4096,
    /// Every body ends after this fraction of it, per thousand, with this probability.
    cut_per_mille: u16 = 0,
};

pub const log_entries_max = 32;

pub const Logged = struct {
    scheme: net.Scheme,
    host: [64]u8,
    host_len: u8,
    port: u16,
    target: [160]u8,
    target_len: u8,
    /// The first bytes of the token the request carried, empty for none. For tests only: the
    /// fixture's token is shorter than this, and `bearer_len` is the real length.
    bearer: [96]u8,
    bearer_len: u32,
    status: u16,
    /// The offset a resumed download asked for; zero for none.
    range_from: u64,

    pub fn target_text(entry: *const Logged) []const u8 {
        return entry.target[0..entry.target_len];
    }

    pub fn host_text(entry: *const Logged) []const u8 {
        return entry.host[0..entry.host_len];
    }

    pub fn bearer_text(entry: *const Logged) []const u8 {
        return entry.bearer[0..@min(entry.bearer_len, entry.bearer.len)];
    }
};

pub const SimNet = struct {
    responder: Responder,
    prng: std.Random.Xoshiro256,
    faults: Faults,
    /// Requests made so far (also the next request's index).
    requests: u32,
    log: [log_entries_max]Logged,
    errno_value: u16,

    pub fn init(sim: *SimNet, seed: u64, responder: Responder) void {
        sim.responder = responder;
        sim.prng = std.Random.Xoshiro256.init(seed);
        sim.faults = .{};
        sim.requests = 0;
        sim.errno_value = 0;
        assert(sim.requests == 0);
    }

    pub fn interface(sim: *SimNet) net.Net {
        return .{ .context = sim, .vtable = &vtable };
    }

    /// The log entry of request `index`; null past what is kept.
    pub fn logged(sim: *const SimNet, index: u32) ?*const Logged {
        assert(sim.requests <= std.math.maxInt(u32));
        if (index >= sim.requests) return null;
        if (index >= log_entries_max) return null;
        return &sim.log[index];
    }

    const vtable: net.VTable = .{ .get = get, .last_errno = last_errno };

    fn from_context(context: *anyopaque) *SimNet {
        const sim: *SimNet = @ptrCast(@alignCast(context));
        assert(sim.requests <= std.math.maxInt(u32));
        return sim;
    }

    fn last_errno(context: *anyopaque) u16 {
        return from_context(context).errno_value;
    }

    fn roll(sim: *SimNet, per_mille: u16) bool {
        assert(per_mille <= 1000);
        if (per_mille == 0) return false;
        return sim.prng.random().uintLessThan(u16, 1000) < per_mille;
    }

    fn record(sim: *SimNet, request: *const net.Request, index: u32) void {
        if (index >= log_entries_max) return;
        const entry = &sim.log[index];
        const host_len = @min(request.host.len, entry.host.len);
        const target_len = @min(request.target.len, entry.target.len);
        @memcpy(entry.host[0..host_len], request.host[0..host_len]);
        @memcpy(entry.target[0..target_len], request.target[0..target_len]);
        const kept = @min(request.bearer.len, entry.bearer.len);
        @memcpy(entry.bearer[0..kept], request.bearer[0..kept]);
        entry.scheme = request.scheme;
        entry.host_len = @intCast(host_len);
        entry.target_len = @intCast(target_len);
        entry.port = request.port;
        entry.bearer_len = @intCast(request.bearer.len);
        entry.status = 0;
        entry.range_from = request.range_from;
    }

    fn injected(sim: *SimNet, index: u32) ?net.Error {
        if (sim.faults.fail_request) |wanted| {
            if (wanted == index) return sim.faults.fail_error;
        }
        if (sim.roll(sim.faults.fail_per_mille)) return sim.faults.fail_error;
        return null;
    }

    fn get(
        context: *anyopaque,
        request: *const net.Request,
        head: *net.Head,
        sink: net.Sink,
    ) net.Error!void {
        const sim = from_context(context);
        const index = sim.requests;
        sim.requests += 1;
        sim.errno_value = 0;
        sim.record(request, index);
        if (sim.injected(index)) |err| {
            sim.errno_value = if (err == error.ConnectFailed) 111 else 0;
            return err;
        }
        var served: Served = .{};
        sim.responder.answer(sim.responder.context, request, &served);
        assert(served.status >= 100);
        assert(served.status <= 599);
        fill_head(head, &served);
        if (index < log_entries_max) sim.log[index].status = served.status;
        const declared = served.content_length orelse served.body.len;
        if (declared > request.body_bytes_max) return error.TooLarge;
        if (head.www_authenticate.present and head.www_authenticate.truncated) {
            return error.BadResponse;
        }
        var deliver = @min(served.deliver orelse served.body.len, served.body.len);
        if (sim.roll(sim.faults.cut_per_mille)) {
            deliver = sim.prng.random().uintAtMost(u64, deliver);
        }
        try sim.send(served.body[0..deliver], head, sink);
        if (head.body_len < declared) return error.Truncated;
    }

    /// Hands the body to the sink in pieces, as a socket would.
    fn send(sim: *SimNet, body: []const u8, head: *net.Head, sink: net.Sink) net.Error!void {
        assert(sim.faults.chunk_bytes_max > 0);
        var at: usize = 0;
        while (at < body.len) {
            const wanted = sim.prng.random().intRangeAtMost(u32, 1, sim.faults.chunk_bytes_max);
            const end = @min(at + wanted, body.len);
            sink.write(sink.context, body[at..end]) catch return error.SinkFailed;
            head.body_len += end - at;
            at = end;
        }
        assert(at == body.len);
        assert(head.body_len == body.len);
    }
};

fn fill_head(head: *net.Head, served: *const Served) void {
    assert(head.body_len == 0);
    head.status = served.status;
    head.content_length = served.content_length orelse served.body.len;
    if (served.www_authenticate.len > 0) head.www_authenticate.set(served.www_authenticate);
    if (served.retry_after.len > 0) head.retry_after.set(served.retry_after);
    if (served.content_type.len > 0) head.content_type.set(served.content_type);
    if (served.content_digest.len > 0) head.content_digest.set(served.content_digest);
    if (served.location.len > 0) head.location.set(served.location);
    if (served.content_range.len > 0) head.content_range.set(served.content_range);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const Script = struct {
    served: Served,

    fn answer(context: *anyopaque, request: *const net.Request, served: *Served) void {
        const script: *Script = @ptrCast(@alignCast(context));
        _ = request;
        served.* = script.served;
    }

    fn responder(script: *Script) Responder {
        return .{ .context = script, .answer = answer };
    }
};

fn sample_request() net.Request {
    return .{
        .scheme = .https,
        .host = "registry.test",
        .port = 443,
        .target = "/v2/",
        .accept = "",
        .bearer = "",
        .body_bytes_max = 16,
        .idle_timeout_ms = 1000,
        .total_timeout_ms = 0,
    };
}

test "a body is delivered whole, in pieces, and the head is filled" {
    // Goal: the sink sees exactly the body however the PRNG cuts it, and the headers arrive.
    var script: Script = .{ .served = .{
        .content_type = "text/plain",
        .www_authenticate = "Bearer realm=\"x\"",
        .body = "0123456789",
    } };
    var sim: SimNet = undefined;
    sim.init(1, script.responder());
    sim.faults.chunk_bytes_max = 3;
    var storage: [16]u8 = undefined;
    var sink: net.BufferSink = .{ .buffer = &storage };
    var head: net.Head = .{};
    const request = sample_request();
    try sim.interface().get(&request, &head, sink.sink());
    try testing.expectEqualStrings("0123456789", sink.bytes());
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqual(@as(?u64, 10), head.content_length);
    try testing.expectEqualStrings("text/plain", head.content_type.slice().?);
    try testing.expectEqualStrings("Bearer realm=\"x\"", head.www_authenticate.slice().?);
    try testing.expect(head.location.slice() == null);
    try testing.expectEqual(@as(u32, 1), sim.requests);
}

test "a body over the bound, a cut body and a failing sink are told apart" {
    // Goal: TooLarge by declared length (before any byte), Truncated when the body ends early,
    // and SinkFailed when the sink refuses.
    var script: Script = .{ .served = .{ .body = "0123456789abcdefg" } };
    var sim: SimNet = undefined;
    sim.init(2, script.responder());
    var storage: [32]u8 = undefined;
    var sink: net.BufferSink = .{ .buffer = &storage };
    var head: net.Head = .{};
    const request = sample_request();
    try testing.expectError(error.TooLarge, sim.interface().get(&request, &head, sink.sink()));
    try testing.expectEqual(@as(u32, 0), sink.len);

    script.served = .{ .body = "0123456789", .deliver = 4 };
    try testing.expectError(error.Truncated, sim.interface().get(&request, &head, sink.sink()));
    try testing.expectEqual(@as(u64, 4), head.body_len);

    script.served = .{ .body = "0123456789" };
    var tiny: [4]u8 = undefined;
    var small: net.BufferSink = .{ .buffer = &tiny };
    try testing.expectError(error.SinkFailed, sim.interface().get(&request, &head, small.sink()));
}

test "an injected failure hits the chosen request and the log keeps what was sent" {
    // Goal: fail_request is one-shot and exact; the log has the host, target and bearer.
    var script: Script = .{ .served = .{ .body = "ok" } };
    var sim: SimNet = undefined;
    sim.init(3, script.responder());
    sim.faults.fail_request = 1;
    sim.faults.fail_error = error.TimedOut;
    var storage: [16]u8 = undefined;
    var sink: net.BufferSink = .{ .buffer = &storage };
    var head: net.Head = .{};
    var request = sample_request();
    request.bearer = "FAKEtoken";
    try sim.interface().get(&request, &head, sink.sink());
    try testing.expectError(error.TimedOut, sim.interface().get(&request, &head, sink.sink()));
    sink.len = 0;
    try sim.interface().get(&request, &head, sink.sink());
    const second = sim.logged(1).?;
    try testing.expectEqualStrings("registry.test", second.host_text());
    try testing.expectEqualStrings("FAKEtoken", second.bearer_text());
    try testing.expectEqual(@as(u16, 0), second.status);
    try testing.expectEqual(@as(u16, 200), sim.logged(2).?.status);
    try testing.expect(sim.logged(3) == null);
}
