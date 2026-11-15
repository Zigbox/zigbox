//! Tests of a pinned fetch (`fetch.zig`) against the simulated file system and network.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const fetch_mod = @import("fetch.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const digest_mod = @import("../registry/digest.zig");
const blobs_mod = @import("../registry/blobs.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");

const Fetcher = fetch_mod.Fetcher;
const Sha256 = digest_mod.Sha256;

const payload = "hello, fetch\n";

var test_fs: fs_sim.SimFs = undefined;
var test_net: net_sim.SimNet = undefined;
var test_fetcher: Fetcher = undefined;

/// The test server: each path answers one way.
fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    _ = context;
    _ = received;
    const routes = [_]struct { []const u8, net_sim.Served }{
        .{ "/hello.txt", .{ .body = payload } },
        .{ "/r/hello.txt", .{ .status = 302, .location = "/hello.txt" } },
        .{ "/loop", .{ .status = 302, .location = "/loop" } },
        .{ "/missing", .{ .status = 404, .body = "not here" } },
        .{ "/big", .{ .content_length = constants.build_fetch_bytes_max + 1, .body = "x" } },
        .{ "/down", .{ .status = 302, .location = "http://cdn.test/hello.txt" } },
        .{ "/plain", .{ .status = 301, .location = "http://127.0.0.1:8080/hello.txt" } },
        .{ "/local", .{ .status = 307, .location = "https://localhost/hello.txt" } },
        .{ "/away", .{ .status = 308, .location = "https://cdn.test/hello.txt" } },
        .{ "/nowhere", .{ .status = 302 } },
        .{ "/protocol", .{ .status = 302, .location = "//cdn.test/hello.txt" } },
    };
    for (routes) |route| {
        if (std.mem.eql(u8, request.target, route[0])) {
            served.* = route[1];
            return;
        }
    }
    served.* = .{ .status = 500 };
}

fn setup(seed: u64) blobs_mod.Blobs {
    test_fs.init(seed);
    test_fs.put_dir("/s", 0o755);
    var unused: u8 = 0;
    test_net.init(seed, .{ .context = &unused, .answer = answer });
    const blobs: blobs_mod.Blobs = .{ .fs = test_fs.interface(), .root = "/s" };
    test_fetcher.init(blobs, test_net.interface());
    return blobs;
}

fn final_content(blobs: blobs_mod.Blobs, digest: Sha256) ?[]const u8 {
    var path: fs_mod.PathBuf = undefined;
    return test_fs.content_of(blobs.final_path(&path, digest));
}

fn partial_kind(blobs: blobs_mod.Blobs, digest: Sha256) ?fs_mod.FileKind {
    var path: fs_mod.PathBuf = undefined;
    return test_fs.kind_of(blobs.partial_path(&path, digest));
}

test "a fetch lands in blobs/sha256 under its hash, and a present blob is never asked for" {
    // Goal: one request, the bytes under their SHA-256, no partial file; then a second fetch of
    // the same hash, from any URL, makes no request at all.
    // Method: the simulated network counts requests; the second URL would fail if asked.
    const blobs = setup(1);
    const digest = Sha256.of(payload);
    const first = try test_fetcher.fetch("https://h.test/hello.txt", digest);
    try testing.expectEqual(fetch_mod.Outcome.downloaded, first);
    try testing.expectEqual(@as(u32, 1), test_net.requests);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    try testing.expect(partial_kind(blobs, digest) == null);
    const again = try test_fetcher.fetch("https://mirror.test/missing", digest);
    try testing.expectEqual(fetch_mod.Outcome.cached, again);
    try testing.expectEqual(@as(u32, 1), test_net.requests);
}

test "a mismatch leaves nothing in blobs/sha256 nor in blobs/partial, and names what came" {
    // Goal: the bytes that hash to something else are removed; the reason holds the received
    // hash for E0821.
    const blobs = setup(2);
    const wrong = Sha256.of("something else");
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/hello.txt", wrong));
    try testing.expect(test_fetcher.reason == .mismatch);
    try testing.expect(test_fetcher.reason.mismatch.eql(Sha256.of(payload)));
    try testing.expect(final_content(blobs, wrong) == null);
    try testing.expect(final_content(blobs, Sha256.of(payload)) == null);
    try testing.expect(partial_kind(blobs, wrong) == null);
}

test "redirects are followed within the bound, and never to http or to loopback" {
    // Goal: each rule of the brief, one route each: a relative redirect is followed; a loop
    // stops after build_fetch_redirects_max hops; https to http, a protocol-relative location,
    // no location, and a public host to a loopback one are refused; loopback http may go on.
    const digest = Sha256.of(payload);
    const blobs = setup(3);
    _ = try test_fetcher.fetch("https://h.test/r/hello.txt", digest);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    try testing.expectEqual(@as(u32, 2), test_net.requests);
    _ = setup(4);
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/loop", digest));
    try testing.expect(test_fetcher.reason == .redirects);
    try testing.expectEqual(constants.build_fetch_redirects_max + 1, test_net.requests);
    const refusals = [_]struct { []const u8, fetch_mod.Refusal }{
        .{ "https://h.test/down", .http },
        .{ "https://h.test/plain", .http },
        .{ "https://h.test/local", .loopback },
        .{ "https://h.test/nowhere", .malformed },
        .{ "https://h.test/protocol", .malformed },
    };
    for (refusals) |row| {
        _ = setup(5);
        try testing.expectError(error.Failed, test_fetcher.fetch(row[0], digest));
        try testing.expect(test_fetcher.reason == .refused);
        try testing.expectEqual(row[1], test_fetcher.reason.refused);
    }
    _ = setup(6);
    _ = try test_fetcher.fetch("http://127.0.0.1:8080/plain", digest);
    try testing.expectEqual(@as(u32, 2), test_net.requests);
}

test "a status, a body over the bound and a network error are told apart, and leave no file" {
    // Goal: E0820's three kinds of reason, each with nothing left in the blob directories.
    const digest = Sha256.of(payload);
    var blobs = setup(7);
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/missing", digest));
    try testing.expectEqual(@as(u16, 404), test_fetcher.reason.status);
    try testing.expect(partial_kind(blobs, digest) == null);
    blobs = setup(8);
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/big", digest));
    try testing.expect(test_fetcher.reason == .too_large);
    try testing.expect(partial_kind(blobs, digest) == null);
    blobs = setup(9);
    test_net.faults.fail_request = 0;
    test_net.faults.fail_error = error.UnknownHost;
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/hello.txt", digest));
    try testing.expectEqual(error.UnknownHost, test_fetcher.reason.network);
    try testing.expect(final_content(blobs, digest) == null);
}

test "a crash at every write of a fetch leaves no half blob, and the next fetch completes" {
    // Goal: blobs/sha256/<hex> is absent or whole after a crash at any write point, and a
    // fetch after the restart puts the whole file there.
    // Method: crash at write point 0, 1, ... until a fetch passes every write point uncut.
    const digest = Sha256.of(payload);
    var crash_at: u32 = 0;
    while (crash_at < 64) : (crash_at += 1) {
        const blobs = setup(10 + crash_at);
        test_fs.faults.crash_mutation = crash_at;
        const outcome = test_fetcher.fetch("https://h.test/hello.txt", digest);
        const crashed = test_fs.crashed;
        test_fs.restart();
        if (final_content(blobs, digest)) |content| {
            try testing.expectEqualStrings(payload, content);
        }
        if (!crashed) {
            _ = try outcome;
            break;
        }
        test_fetcher.init(blobs, test_net.interface());
        _ = try test_fetcher.fetch("https://h.test/hello.txt", digest);
        try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    } else return error.TestUnexpectedResult;
    try testing.expect(crash_at > 3);
}
