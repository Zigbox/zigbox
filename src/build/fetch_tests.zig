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
/// The second download of the interleaving test, on its own network, into the same store.
var other_net: net_sim.SimNet = undefined;
var other_fetcher: Fetcher = undefined;
/// What the interrupt stub answers: the signal the build was asked to stop with, 0 for none.
var interrupt_value: u8 = 0;

/// Each download's own partial file, as `Store.tmp_path` names them.
const partial = "/s/tmp/1-0";
const partial_other = "/s/tmp/1-1";

/// The test server: each path answers one way. `/c<n>` redirects to `/c<n-1>`, and `/c0` is the
/// file.
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
        .{ "/numeric", .{ .status = 302, .location = "https://0x7f.1/hello.txt" } },
        .{ "/away", .{ .status = 308, .location = "https://cdn.test/hello.txt" } },
        .{ "/nowhere", .{ .status = 302 } },
        .{ "/protocol", .{ .status = 302, .location = "//cdn.test/hello.txt" } },
        .{ "/c0", .{ .body = payload } },
        .{ "/c1", .{ .status = 302, .location = "/c0" } },
        .{ "/c2", .{ .status = 302, .location = "/c1" } },
        .{ "/c3", .{ .status = 302, .location = "/c2" } },
        .{ "/c4", .{ .status = 302, .location = "/c3" } },
        .{ "/c5", .{ .status = 302, .location = "/c4" } },
    };
    for (routes) |route| {
        if (std.mem.eql(u8, request.target, route[0])) {
            served.* = route[1];
            return;
        }
    }
    if (std.mem.eql(u8, request.target, "/stop")) {
        interrupt_value = 2; // Ctrl-C arrives as the answer does.
        served.* = .{ .body = payload };
        return;
    }
    if (std.mem.eql(u8, request.target, "/nested")) {
        // Another download of the same pin runs, start to end, while this one's file is open.
        var unused: u8 = 0;
        other_net.init(99, .{ .context = &unused, .answer = answer });
        other_fetcher.init(test_fetcher.blobs, other_net.interface(), test_interrupt);
        const url = "https://mirror.test/hello.txt";
        const outcome = other_fetcher.fetch(url, Sha256.of(payload), partial_other);
        served.* = if (outcome) |_| .{ .body = payload } else |_| .{ .status = 500 };
        return;
    }
    served.* = .{ .status = 500 };
}

fn interrupt_signal(context: *anyopaque) u8 {
    _ = context;
    return interrupt_value;
}

var interrupt_context: u8 = 0;
const test_interrupt: fetch_mod.Interrupt = .{
    .context = &interrupt_context,
    .signal = interrupt_signal,
};

fn setup(seed: u64) blobs_mod.Blobs {
    test_fs.init(seed);
    test_fs.put_dir("/s", 0o755);
    test_fs.put_dir("/s/tmp", 0o755);
    interrupt_value = 0;
    var unused: u8 = 0;
    test_net.init(seed, .{ .context = &unused, .answer = answer });
    const blobs: blobs_mod.Blobs = .{ .fs = test_fs.interface(), .root = "/s" };
    test_fetcher.init(blobs, test_net.interface(), test_interrupt);
    return blobs;
}

fn final_content(blobs: blobs_mod.Blobs, digest: Sha256) ?[]const u8 {
    var path: fs_mod.PathBuf = undefined;
    return test_fs.content_of(blobs.final_path(&path, digest));
}

/// True when neither download's partial file is there.
fn no_partial() bool {
    return test_fs.kind_of(partial) == null and test_fs.kind_of(partial_other) == null;
}

test "a fetch lands in blobs/sha256 under its hash, and a present blob is never asked for" {
    // Goal: one request, the bytes under their SHA-256, no partial file; then a second fetch of
    // the same hash, from any URL, makes no request at all.
    // Method: the simulated network counts requests; the second URL would fail if asked.
    const blobs = setup(1);
    const digest = Sha256.of(payload);
    const first = try test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectEqual(fetch_mod.Outcome.downloaded, first);
    try testing.expectEqual(@as(u32, 1), test_net.requests);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    try testing.expect(no_partial());
    const again = try test_fetcher.fetch("https://mirror.test/missing", digest, partial);
    try testing.expectEqual(fetch_mod.Outcome.cached, again);
    try testing.expectEqual(@as(u32, 1), test_net.requests);
}

test "a mismatch leaves nothing in blobs/sha256 nor in blobs/partial, and names what came" {
    // Goal: the bytes that hash to something else are removed; the reason holds the received
    // hash for E0821.
    const blobs = setup(2);
    const wrong = Sha256.of("something else");
    const failed = test_fetcher.fetch("https://h.test/hello.txt", wrong, partial);
    try testing.expectError(error.Failed, failed);
    try testing.expect(test_fetcher.reason == .mismatch);
    try testing.expect(test_fetcher.reason.mismatch.eql(Sha256.of(payload)));
    try testing.expect(final_content(blobs, wrong) == null);
    try testing.expect(final_content(blobs, Sha256.of(payload)) == null);
    try testing.expect(no_partial());
}

test "redirects are followed within the bound, and never to http or to loopback" {
    // Goal: each rule of the brief, one route each: a relative redirect is followed; a loop
    // stops after build_fetch_redirects_max hops; https to http, a protocol-relative location,
    // no location, and a public host to a loopback one are refused; loopback http may go on.
    const digest = Sha256.of(payload);
    const blobs = setup(3);
    _ = try test_fetcher.fetch("https://h.test/r/hello.txt", digest, partial);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    try testing.expectEqual(@as(u32, 2), test_net.requests);
    _ = setup(4);
    const failed = test_fetcher.fetch("https://h.test/loop", digest, partial);
    try testing.expectError(error.Failed, failed);
    try testing.expect(test_fetcher.reason == .redirects);
    try testing.expectEqual(constants.build_fetch_redirects_max + 1, test_net.requests);
    const refusals = [_]struct { []const u8, fetch_mod.Refusal }{
        .{ "https://h.test/down", .http },
        .{ "https://h.test/plain", .http },
        .{ "https://h.test/local", .loopback },
        .{ "https://h.test/numeric", .loopback },
        .{ "https://h.test/nowhere", .malformed },
        .{ "https://h.test/protocol", .malformed },
    };
    for (refusals) |row| {
        _ = setup(5);
        try testing.expectError(error.Failed, test_fetcher.fetch(row[0], digest, partial));
        try testing.expect(test_fetcher.reason == .refused);
        try testing.expectEqual(row[1], test_fetcher.reason.refused);
    }
    _ = setup(6);
    _ = try test_fetcher.fetch("http://127.0.0.1:8080/plain", digest, partial);
    try testing.expectEqual(@as(u32, 2), test_net.requests);
}

test "a status, a body over the bound and a network error are told apart, and leave no file" {
    // Goal: E0820's three kinds of reason, each with nothing left in the blob directories.
    const digest = Sha256.of(payload);
    var blobs = setup(7);
    const missing = test_fetcher.fetch("https://h.test/missing", digest, partial);
    try testing.expectError(error.Failed, missing);
    try testing.expectEqual(@as(u16, 404), test_fetcher.reason.status);
    try testing.expect(no_partial());
    blobs = setup(8);
    const big = test_fetcher.fetch("https://h.test/big", digest, partial);
    try testing.expectError(error.Failed, big);
    try testing.expect(test_fetcher.reason == .too_large);
    try testing.expect(no_partial());
    blobs = setup(9);
    test_net.faults.fail_request = 0;
    test_net.faults.fail_error = error.UnknownHost;
    const failed = test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectError(error.Failed, failed);
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
        const outcome = test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
        const crashed = test_fs.crashed;
        test_fs.restart();
        if (final_content(blobs, digest)) |content| {
            try testing.expectEqualStrings(payload, content);
        }
        if (!crashed) {
            _ = try outcome;
            break;
        }
        // The crashed download's file may be left: gc removes it; the next one has its own.
        test_fetcher.init(blobs, test_net.interface(), test_interrupt);
        _ = try test_fetcher.fetch("https://h.test/hello.txt", digest, partial_other);
        try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    } else return error.TestUnexpectedResult;
    try testing.expect(crash_at > 3);
}

test "two downloads of one pin, one inside the other, each write their own file" {
    // Goal: a second download of the same pin that starts and ends while the first one's file
    // is open neither truncates nor renames the first's bytes (MUST 1 of the 3b review): both
    // end, the blob is whole, and neither partial file is left.
    // Method: the server, asked for `/nested`, runs a second Fetcher to the end before it
    // answers the first; the first's body then lands in its own file and replaces the blob with
    // the same bytes.
    const blobs = setup(20);
    const digest = Sha256.of(payload);
    const outcome = try test_fetcher.fetch("https://h.test/nested", digest, partial);
    try testing.expectEqual(fetch_mod.Outcome.downloaded, outcome);
    try testing.expectEqual(@as(u32, 1), other_net.requests);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    try testing.expect(no_partial());
}

test "a blob whose bytes are not its name is downloaded again, and replaced" {
    // Goal: `has` re-hashes, so a damaged or a short blob is not a hit: the next fetch asks the
    // server and puts the right bytes there. Method: other bytes, then a prefix, under the name.
    const digest = Sha256.of(payload);
    for ([_][]const u8{ "damaged\n", payload[0 .. payload.len - 1] }) |bad| {
        const blobs = setup(21);
        test_fs.put_dir("/s/blobs", 0o755);
        test_fs.put_dir("/s/blobs/sha256", 0o755);
        var path: fs_mod.PathBuf = undefined;
        test_fs.put_file(blobs.final_path(&path, digest), 0o644, bad);
        try testing.expect(!test_fetcher.has(digest));
        const outcome = try test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
        try testing.expectEqual(fetch_mod.Outcome.downloaded, outcome);
        try testing.expectEqual(@as(u32, 1), test_net.requests);
        try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
        try testing.expect(test_fetcher.has(digest));
    }
}

test "exactly build_fetch_redirects_max redirects are followed, and one more is refused" {
    // Goal: the bound is exact. Method: `/c<n>` is a chain of n redirects to the file.
    comptime std.debug.assert(constants.build_fetch_redirects_max == 4);
    const digest = Sha256.of(payload);
    const blobs = setup(22);
    _ = try test_fetcher.fetch("https://h.test/c4", digest, partial);
    try testing.expectEqual(@as(u32, 5), test_net.requests);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    _ = setup(23);
    try testing.expectError(error.Failed, test_fetcher.fetch("https://h.test/c5", digest, partial));
    try testing.expect(test_fetcher.reason == .redirects);
    try testing.expectEqual(@as(u32, 5), test_net.requests);
    try testing.expect(no_partial());
}

test "a body of exactly the bound is taken, and one byte over is refused with no file left" {
    // Goal: `bytes_max` is inclusive. Method: lower the bound to the payload's length, then to
    // one byte less (the 1 GiB bound itself is the same comparison; the real network's chunked
    // framing is tested at its exact bound in host_real_net.zig).
    const digest = Sha256.of(payload);
    const blobs = setup(24);
    test_fetcher.bytes_max = payload.len;
    _ = try test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectEqualStrings(payload, final_content(blobs, digest).?);
    const short = setup(25);
    test_fetcher.bytes_max = payload.len - 1;
    const result = test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectError(error.Failed, result);
    try testing.expect(test_fetcher.reason == .too_large);
    try testing.expect(final_content(short, digest) == null);
    try testing.expect(no_partial());
}

test "a head over its bound is an answer that is not usable HTTP, not a file too large" {
    // Goal: TooLarge before any status is `network = BadResponse`. Method: the simulated
    // network fails the first request with TooLarge before it fills the head.
    const digest = Sha256.of(payload);
    _ = setup(26);
    test_net.faults.fail_request = 0;
    test_net.faults.fail_error = error.TooLarge;
    const result = test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectError(error.Failed, result);
    try testing.expectEqual(error.BadResponse, test_fetcher.reason.network);
    try testing.expect(no_partial());
}

test "Ctrl-C stops a download before a request and inside the body, and leaves no file" {
    // Goal: the interrupt is read before each request and at each piece of the body; the
    // reason carries the signal (E0808). Method: the flag set before the fetch, then set by the
    // server as it answers `/stop`.
    const digest = Sha256.of(payload);
    _ = setup(27);
    interrupt_value = 15;
    var result = test_fetcher.fetch("https://h.test/hello.txt", digest, partial);
    try testing.expectError(error.Failed, result);
    try testing.expectEqual(@as(u8, 15), test_fetcher.reason.interrupted);
    try testing.expectEqual(@as(u32, 0), test_net.requests);
    try testing.expect(no_partial());
    const blobs = setup(28);
    result = test_fetcher.fetch("https://h.test/stop", digest, partial);
    try testing.expectError(error.Failed, result);
    try testing.expectEqual(@as(u8, 2), test_fetcher.reason.interrupted);
    try testing.expect(final_content(blobs, digest) == null);
    try testing.expect(no_partial());
}

test "loopback is every spelling the resolver takes, and nothing else" {
    // Goal: names_loopback catches the numeric forms of 127/8 and 0.0.0.0, not just the text.
    const yes = [_][]const u8{
        "localhost", "LOCALHOST.", "a.localhost", "127.0.0.1",  "127.1",
        "127.9.9.9", "0x7f.0.0.1", "0x7F.1",      "2130706433", "0177.0.0.1",
        "0.0.0.0",   "0",          "127.0.0.1.",
    };
    for (yes) |host| try testing.expect(fetch_mod.names_loopback(host));
    const no = [_][]const u8{
        "1.2.3.4",     "example.com", "128.0.0.1", "localhost.example", "127.0.0.256",
        "1.127.0.0.1", "0x80.0.0.1",  "08.0.0.1",  "4294967296",
    };
    for (no) |host| try testing.expect(!fetch_mod.names_loopback(host));
}
