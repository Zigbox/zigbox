//! Tests of demo-s2's disk-backed registry against real sockets on 127.0.0.1: a push in pieces
//! and a pull back, `Range`, the counter by kind, the throttle with connections served at once,
//! the byte flip and "down".

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const http = @import("http_s2.zig");
const registry_mod = @import("registry_disk_s2.zig");

const Registry = registry_mod.Registry;
const response_bytes_max = 1024 * 1024;

const Fixture = struct {
    tmp: std.testing.TmpDir,
    registry: *Registry,

    fn init(bytes_per_second: u64) !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var path: [128:0]u8 = undefined;
        const format = ".zig-cache/tmp/{s}/registry";
        const root = try std.mem.printSentinel(&path, format, .{tmp.sub_path}, 0);
        const registry = try std.testing.allocator.create(Registry);
        errdefer std.testing.allocator.destroy(registry);
        try registry.init(root, bytes_per_second);
        try registry.start();
        return .{ .tmp = tmp, .registry = registry };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.registry.deinit();
        std.testing.allocator.destroy(fixture.registry);
        fixture.tmp.cleanup();
    }
};

fn connect(port: u16) !i32 {
    const created = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
    const socket: i32 = @intCast(created);
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connected = linux.connect(socket, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(connected) != .SUCCESS) {
        _ = linux.close(socket);
        return error.ConnectFailed;
    }
    return socket;
}

/// Sends `head` and `body`, reads the response to its end.
fn exchange(port: u16, head: []const u8, body: []const u8, out: []u8) ![]u8 {
    assert(out.len > 0);
    const socket = try connect(port);
    defer _ = linux.close(socket);
    if (!http.write_all(socket, head) or !http.write_all(socket, body)) return error.SendFailed;
    var never: std.atomic.Value(bool) = .init(false);
    var length: usize = 0;
    while (length < out.len) {
        const got = http.read_some(socket, out[length..], &never) orelse break;
        length += got;
    }
    return out[0..length];
}

fn status_of(response: []const u8) u16 {
    if (response.len < 12) return 0;
    return std.fmt.parseInt(u16, response[9..12], 10) catch 0;
}

fn header_of(response: []const u8, name: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return "";
    // A response's head reads like a request's past the first line, which `header` skips.
    const parsed: http.Request = .{
        .method = .other,
        .path = "",
        .query = "",
        .head = response[0..end],
        .early = "",
    };
    return parsed.header(name) orelse "";
}

fn body_of(response: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return "";
    return response[end + 4 ..];
}

fn send(port: u16, comptime format: []const u8, args: anytype, body: []const u8, out: []u8) ![]u8 {
    var head: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&head, format, args);
    return exchange(port, text, body, out);
}

/// Pushes `bytes` in two pieces, as zbx does: POST, PATCH, PUT with the last piece.
fn push_blob(port: u16, bytes: []const u8, out: []u8) ![71]u8 {
    assert(bytes.len >= 2);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    var digest: [71]u8 = undefined;
    _ = try std.fmt.bufPrint(&digest, "sha256:{s}", .{std.fmt.bytesToHex(hash, .lower)});
    const opened = try send(port, "POST /v2/t/blobs/uploads/ HTTP/1.1\r\n" ++
        "Content-Length: 0\r\n\r\n", .{}, "", out);
    try std.testing.expectEqual(@as(u16, 202), status_of(opened));
    var location: [128]u8 = undefined;
    const where = try std.fmt.bufPrint(&location, "{s}", .{header_of(opened, "Location")});
    const half = bytes.len / 2;
    const patched = try send(port, "PATCH {s} HTTP/1.1\r\nContent-Range: 0-{d}\r\n" ++
        "Content-Length: {d}\r\n\r\n", .{ where, half - 1, half }, bytes[0..half], out);
    try std.testing.expectEqual(@as(u16, 202), status_of(patched));
    var range: [32]u8 = undefined;
    const wanted = try std.fmt.bufPrint(&range, "0-{d}", .{half - 1});
    try std.testing.expectEqualStrings(wanted, header_of(patched, "Range"));
    const closed = try send(port, "PUT {s}?digest={s} HTTP/1.1\r\nContent-Range: {d}-{d}\r\n" ++
        "Content-Length: {d}\r\n\r\n", .{
        where, &digest, half, bytes.len - 1, bytes.len - half,
    }, bytes[half..], out);
    try std.testing.expectEqual(@as(u16, 201), status_of(closed));
    try std.testing.expectEqualStrings(&digest, header_of(closed, "Docker-Content-Digest"));
    return digest;
}

fn pattern(buffer: []u8) void {
    for (buffer, 0..) |*byte, index| byte.* = @truncate(index *% 7 +% index / 251);
}

test "registry_disk_s2: push in pieces, pull whole and by range, counted by kind" {
    // Goal: what zbx pushes is served back byte for byte, a closed range as 206, and the counter
    // tells chunks from the index, whole blobs and manifests.
    // Method: push a 200 KiB blob and a manifest, read both back, a range and the registered
    // index range, and check the snapshot after each.
    var fixture: Fixture = try .init(1 << 30);
    defer fixture.deinit();
    const port = fixture.registry.port;
    const out = try std.testing.allocator.alloc(u8, response_bytes_max);
    defer std.testing.allocator.free(out);
    var blob: [200 * 1024]u8 = undefined;
    pattern(&blob);
    const digest = try push_blob(port, &blob, out);
    const whole = try send(port, "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n", .{&digest}, "", out);
    try std.testing.expectEqual(@as(u16, 200), status_of(whole));
    try std.testing.expectEqualSlices(u8, &blob, body_of(whole));
    const get_range = "GET /v2/t/blobs/{s} HTTP/1.1\r\nRange: bytes={s}\r\n\r\n";
    const ranged = try send(port, get_range, .{ &digest, "70000-70099" }, "", out);
    try std.testing.expectEqual(@as(u16, 206), status_of(ranged));
    try std.testing.expectEqualSlices(u8, blob[70000..70100], body_of(ranged));
    const content_range = header_of(ranged, "Content-Range");
    try std.testing.expectEqualStrings("bytes 70000-70099/204800", content_range);
    fixture.registry.add_index_range(digest[7..], 10, 19);
    const index = try send(port, get_range, .{ &digest, "10-19" }, "", out);
    try std.testing.expectEqual(@as(u16, 206), status_of(index));
    const past = try send(port, get_range, .{ &digest, "1-204800" }, "", out);
    try std.testing.expectEqual(@as(u16, 416), status_of(past));
    const manifest = "{\"layers\":[]}";
    const put_head = "PUT /v2/t/manifests/v1 HTTP/1.1\r\nContent-Type: application/x\r\n" ++
        "Content-Length: {d}\r\n\r\n";
    const put = try send(port, put_head, .{manifest.len}, manifest, out);
    try std.testing.expectEqual(@as(u16, 201), status_of(put));
    const got = try send(port, "GET /v2/t/manifests/v1 HTTP/1.1\r\n\r\n", .{}, "", out);
    try std.testing.expectEqualStrings(manifest, body_of(got));
    try std.testing.expectEqualStrings("application/x", header_of(got, "Content-Type"));
    const head = try send(port, "HEAD /v2/t/manifests/v1 HTTP/1.1\r\n\r\n", .{}, "", out);
    try std.testing.expectEqual(@as(u16, 200), status_of(head));
    const snapshot = fixture.registry.snapshot();
    try std.testing.expectEqual(@as(u64, blob.len), snapshot.whole);
    try std.testing.expectEqual(@as(u64, 100), snapshot.chunks);
    try std.testing.expectEqual(@as(u64, 10), snapshot.index);
    try std.testing.expectEqual(@as(u64, manifest.len), snapshot.manifests);
    try std.testing.expectEqual(@as(u64, blob.len + 110 + manifest.len), snapshot.total);
    var copy: [registry_mod.manifest_bytes_max]u8 = undefined;
    try std.testing.expectEqualStrings(manifest, fixture.registry.manifest_of("t", "v1", &copy).?);
    const control = try send(port, "GET /control/reset HTTP/1.1\r\n\r\n", .{}, "", out);
    try std.testing.expect(std.mem.startsWith(u8, body_of(control), "served 0 chunks 0 "));
}

const Pull = struct {
    port: u16,
    digest: *const [71]u8,
    length: u64 = 0,

    fn run(pull: *Pull) void {
        const out = std.heap.page_allocator.alloc(u8, response_bytes_max) catch return;
        defer std.heap.page_allocator.free(out);
        const get = "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n";
        const got = send(pull.port, get, .{pull.digest}, "", out) catch return;
        pull.length = body_of(got).len;
    }
};

test "registry_disk_s2: one throttle for every connection, served at once" {
    // Goal: the limit is global and has no burst, and connections are served concurrently.
    // Method: at 2 MiB/s, pull a 256 KiB blob from three threads at once: all three finish, and
    // the 768 KiB take at least 768/2048 s less one piece's slot.
    var fixture: Fixture = try .init(2 * 1024 * 1024);
    defer fixture.deinit();
    const out = try std.testing.allocator.alloc(u8, response_bytes_max);
    defer std.testing.allocator.free(out);
    const blob = try std.testing.allocator.alloc(u8, 256 * 1024);
    defer std.testing.allocator.free(blob);
    pattern(blob);
    const digest = try push_blob(fixture.registry.port, blob, out);
    var pulls: [3]Pull = @splat(.{ .port = fixture.registry.port, .digest = &digest });
    var threads: [3]std.Thread = undefined;
    const started = registry_mod.now_ns();
    for (&threads, &pulls) |*thread, *pull| thread.* = try std.Thread.spawn(.{}, Pull.run, .{pull});
    for (threads) |thread| thread.join();
    const elapsed = registry_mod.now_ns() - started;
    for (pulls) |pull| try std.testing.expectEqual(blob.len, pull.length);
    try std.testing.expect(elapsed >= 360 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u64, 3 * blob.len), fixture.registry.snapshot().whole);
}

test "registry_disk_s2: the flip and down" {
    // Goal: step 6's fault changes exactly one byte of one blob in transit and nothing on disk;
    // step 7's drops connections with no answer, and the registry serves again when up.
    // Method: arm the flip, compare a pull with the original, turn it off, then go down and up.
    var fixture: Fixture = try .init(1 << 30);
    defer fixture.deinit();
    const port = fixture.registry.port;
    const out = try std.testing.allocator.alloc(u8, response_bytes_max);
    defer std.testing.allocator.free(out);
    var blob: [100_000]u8 = undefined;
    pattern(&blob);
    const digest = try push_blob(port, &blob, out);
    fixture.registry.set_flip(digest[7..], 66_000);
    _ = try send(port, "GET /control/flip-on HTTP/1.1\r\n\r\n", .{}, "", out);
    const flipped = try send(port, "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n", .{&digest}, "", out);
    const body = body_of(flipped);
    try std.testing.expectEqual(blob.len, body.len);
    var differing: usize = 0;
    for (blob, body) |want, got| differing += @intFromBool(want != got);
    try std.testing.expectEqual(@as(usize, 1), differing);
    try std.testing.expectEqual(blob[66_000] ^ 0xff, body[66_000]);
    _ = try send(port, "GET /control/flip-off HTTP/1.1\r\n\r\n", .{}, "", out);
    const honest = try send(port, "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n", .{&digest}, "", out);
    try std.testing.expectEqualSlices(u8, &blob, body_of(honest));
    _ = try send(port, "GET /control/down HTTP/1.1\r\n\r\n", .{}, "", out);
    const dropped = try send(port, "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n", .{&digest}, "", out);
    try std.testing.expectEqual(@as(usize, 0), dropped.len);
    _ = try send(port, "GET /control/up HTTP/1.1\r\n\r\n", .{}, "", out);
    const back = try send(port, "GET /v2/t/blobs/{s} HTTP/1.1\r\n\r\n", .{&digest}, "", out);
    try std.testing.expectEqualSlices(u8, &blob, body_of(back));
    var copy: [100_000]u8 = undefined;
    try fixture.registry.read_blob(digest[7..], 0, &copy);
    try std.testing.expectEqualSlices(u8, &blob, &copy);
}
