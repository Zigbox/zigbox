//! The test registry over TCP: `registry_fixture.zig` behind a blocking HTTP/1.1 server on
//! 127.0.0.1, run on a thread of the test that starts it. It is what lets the real network code
//! (sockets, the head parser, chunked bodies, deadlines) talk to the fixture with no internet.
//!
//! One request per connection (`Connection: close`), as the client sends it. Every read has a
//! timeout so a broken test cannot hang the build, and every size is bounded. Modes, each of which
//! the real network tests need (`Server.mode`):
//!   - `chunked`: bodies are sent with `Transfer-Encoding: chunked`, in pieces of 7 bytes;
//!   - `stall`: the request is read and never answered, to test the client's timeouts;
//!   - `garbage`: the answer is not HTTP; `fat_head`: its head is over the bound;
//!   - `refuse_tunnel`: `CONNECT` is answered 407.
//! Without `refuse_tunnel`, `CONNECT host:port` is answered `200` and then nothing, which is what
//! a proxy tunnel to a peer that does not speak TLS looks like.
//! The requests it saw are kept (`log`), readable once `stop` has joined the thread.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const fixture_mod = @import("registry_fixture.zig");

pub const log_entries_max = 32;
const request_bytes_max = 8192;
const read_timeout_ms = 5000;

pub const Logged = struct {
    line: [160]u8 = undefined,
    line_len: u8 = 0,
    bearer_len: u32 = 0,
    proxy_authorization: bool = false,

    pub fn text(entry: *const Logged) []const u8 {
        return entry.line[0..entry.line_len];
    }
};

pub const Mode = enum { normal, chunked, stall, garbage, fat_head, refuse_tunnel };

pub const Server = struct {
    listener: i32 = -1,
    port: u16 = 0,
    fixture: *fixture_mod.Fixture = undefined,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    mode: Mode = .normal,
    requests: std.atomic.Value(u32) = .init(0),
    log: [log_entries_max]Logged = @splat(.{}),

    /// Listens on 127.0.0.1 with an ephemeral port; `port` is set. Serving starts at `serve`.
    pub fn bind(server: *Server) !void {
        const kind = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
        const created = linux.socket(linux.AF.INET, kind, 0);
        if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
        server.listener = @intCast(created);
        var address: linux.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, 0),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        const bound = linux.bind(server.listener, @ptrCast(&address), @sizeOf(@TypeOf(address)));
        if (linux.errno(bound) != .SUCCESS) return error.BindFailed;
        if (linux.errno(linux.listen(server.listener, 16)) != .SUCCESS) return error.ListenFailed;
        var length: linux.socklen_t = @sizeOf(@TypeOf(address));
        const named = linux.getsockname(server.listener, @ptrCast(&address), &length);
        if (linux.errno(named) != .SUCCESS) return error.SocketFailed;
        server.port = std.mem.bigToNative(u16, address.port);
        assert(server.port != 0);
    }

    pub fn serve(server: *Server, fixture: *fixture_mod.Fixture) !void {
        assert(server.listener >= 0);
        server.fixture = fixture;
        server.thread = try std.Thread.spawn(.{}, run, .{server});
    }

    /// Stops serving and joins the thread; the log is stable afterwards.
    pub fn stop(server: *Server) void {
        server.stopping.store(true, .release);
        if (server.thread) |thread| thread.join();
        server.thread = null;
        if (server.listener >= 0) _ = linux.close(server.listener);
        server.listener = -1;
    }

    /// Closes the listener and keeps the port, so that connecting to it is refused.
    pub fn unbind(server: *Server) void {
        assert(server.thread == null);
        if (server.listener >= 0) _ = linux.close(server.listener);
        server.listener = -1;
    }

    fn run(server: *Server) void {
        while (!server.stopping.load(.acquire)) {
            var entries = [1]linux.pollfd{
                .{ .fd = server.listener, .events = linux.POLL.IN, .revents = 0 },
            };
            const ready = linux.poll(&entries, 1, 20);
            if (linux.errno(ready) != .SUCCESS or ready == 0) continue;
            const accepted = linux.accept4(server.listener, null, null, linux.SOCK.CLOEXEC);
            if (linux.errno(accepted) != .SUCCESS) continue;
            const client: i32 = @intCast(accepted);
            server.handle(client);
            _ = linux.close(client);
        }
    }

    fn handle(server: *Server, client: i32) void {
        var request: [request_bytes_max]u8 = undefined;
        const length = read_head(client, &request, &server.stopping) orelse return;
        const text = request[0..length];
        const index = server.requests.fetchAdd(1, .acq_rel);
        const line_end = std.mem.indexOf(u8, text, "\r\n").?;
        const line = text[0..line_end];
        const bearer = header_value(text, "authorization");
        if (index < log_entries_max) {
            const entry = &server.log[index];
            const kept = @min(line.len, entry.line.len);
            @memcpy(entry.line[0..kept], line[0..kept]);
            entry.line_len = @intCast(kept);
            entry.bearer_len = if (bearer) |value| @intCast(value.len) else 0;
            entry.proxy_authorization = header_value(text, "proxy-authorization") != null;
        }
        switch (server.mode) {
            .stall => return server.wait_for_stop(),
            .garbage => return write_all(client, "this is not http\r\n\r\n"),
            .fat_head => return write_fat_head(client),
            else => {},
        }
        if (std.mem.startsWith(u8, line, "CONNECT ")) {
            if (server.mode == .refuse_tunnel) {
                write_all(client, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
            } else {
                write_all(client, "HTTP/1.1 200 Connection established\r\n\r\n");
            }
            return;
        }
        const target = request_target(line) orelse return write_all(client, status_only(400));
        var answer: fixture_mod.Answer = .{};
        var token: []const u8 = "";
        if (bearer) |value| {
            if (std.mem.startsWith(u8, value, "Bearer ")) token = value["Bearer ".len..];
        }
        const query: fixture_mod.Query = .{
            .host = "127.0.0.1",
            .target = target,
            .bearer = token,
            .range_from = range_start(header_value(text, "range")),
        };
        server.fixture.answer(query, &answer);
        server.respond(client, &answer);
    }

    fn wait_for_stop(server: *Server) void {
        while (!server.stopping.load(.acquire)) {
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 10_000_000 }, null);
        }
    }

    fn respond(server: *Server, client: i32, answer: *const fixture_mod.Answer) void {
        var head: [2048]u8 = undefined;
        var writer = std.Io.Writer.fixed(&head);
        write_head(&writer, answer, server.mode == .chunked) catch unreachable; // The buffer fits.
        write_all(client, writer.buffered());
        const delivered = @min(answer.deliver orelse answer.body.len, answer.body.len);
        if (server.mode == .chunked) {
            // A body that was cut ends without its last chunk, as a dropped connection does.
            return write_chunked(client, answer.body[0..delivered], delivered == answer.body.len);
        }
        write_all(client, answer.body[0..delivered]);
    }
};

fn write_head(
    writer: *std.Io.Writer,
    answer: *const fixture_mod.Answer,
    chunked: bool,
) std.Io.Writer.Error!void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ answer.status, reason(answer.status) });
    const optional = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "Content-Type", .value = answer.content_type },
        .{ .name = "WWW-Authenticate", .value = answer.www_authenticate },
        .{ .name = "Retry-After", .value = answer.retry_after },
        .{ .name = "Docker-Content-Digest", .value = answer.content_digest },
        .{ .name = "Location", .value = answer.location },
        .{ .name = "Content-Range", .value = answer.content_range },
    };
    for (optional) |header| {
        if (header.value.len > 0) try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (chunked) return writer.writeAll("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    const declared = answer.content_length orelse answer.body.len;
    try writer.print("Content-Length: {d}\r\nConnection: close\r\n\r\n", .{declared});
}

fn write_fat_head(client: i32) void {
    write_all(client, "HTTP/1.1 200 OK\r\nX-Fat: ");
    var piece: [1024]u8 = undefined;
    @memset(&piece, 'x');
    for (0..20) |_| write_all(client, &piece);
    write_all(client, "\r\nContent-Length: 0\r\n\r\n");
}

fn write_chunked(client: i32, body: []const u8, complete: bool) void {
    var at: usize = 0;
    while (at < body.len) {
        const piece = body[at..@min(at + 7, body.len)];
        var size: [16]u8 = undefined;
        const line = std.fmt.bufPrint(&size, "{x}\r\n", .{piece.len}) catch unreachable; // Short.
        write_all(client, line);
        write_all(client, piece);
        write_all(client, "\r\n");
        at += piece.len;
    }
    if (complete) write_all(client, "0\r\n\r\n");
}

/// The offset of a `Range: bytes=N-` header; zero for none or for anything else.
fn range_start(value: ?[]const u8) u64 {
    const text = value orelse return 0;
    const prefix = "bytes=";
    if (!std.mem.startsWith(u8, text, prefix)) return 0;
    const rest = std.mem.trimEnd(u8, text[prefix.len..], "- ");
    return std.fmt.parseInt(u64, rest, 10) catch 0;
}

fn status_only(status: u16) []const u8 {
    assert(status == 400);
    return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

fn reason(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        206 => "Partial Content",
        416 => "Range Not Satisfiable",
        307 => "Temporary Redirect",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        else => "Status",
    };
}

fn write_all(client: i32, bytes: []const u8) void {
    var at: usize = 0;
    while (at < bytes.len) {
        const rest = bytes[at..];
        const rc = linux.sendto(client, rest.ptr, rest.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) != .SUCCESS) return; // The client went away: nothing to tell it.
        at += rc;
    }
}

/// Reads until the blank line that ends a request head; its length, or null on a timeout, a
/// close or an oversize head.
fn read_head(client: i32, buffer: []u8, stopping: *const std.atomic.Value(bool)) ?usize {
    var length: usize = 0;
    var waited: u32 = 0;
    while (length < buffer.len) {
        if (stopping.load(.acquire)) return null;
        var entries = [1]linux.pollfd{.{ .fd = client, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&entries, 1, 50);
        if (linux.errno(ready) != .SUCCESS) return null;
        if (ready == 0) {
            waited += 50;
            if (waited >= read_timeout_ms) return null;
            continue;
        }
        const room = buffer[length..];
        const got = linux.recvfrom(client, room.ptr, room.len, 0, null, null);
        if (linux.errno(got) != .SUCCESS or got == 0) return null;
        length += got;
        if (std.mem.indexOf(u8, buffer[0..length], "\r\n\r\n")) |end| return end + 4;
    }
    return null;
}

/// The value of the header `name` (lower case) in a request head, or null.
fn header_value(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // The request line.
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

/// The target of `GET <target> HTTP/1.x`, or null for anything else.
fn request_target(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "GET ")) return null;
    const rest = line[4..];
    const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    if (!std.mem.startsWith(u8, rest[space..], " HTTP/1.")) return null;
    return rest[0..space];
}

test "header_value and request_target read a request head" {
    // Goal: the two little parsers the server rests on, with the cases it will meet.
    const head = "GET /v2/x/manifests/1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc\r\n\r\n";
    try std.testing.expectEqualStrings("Bearer abc", header_value(head, "authorization").?);
    try std.testing.expectEqualStrings("h", header_value(head, "HOST").?);
    try std.testing.expect(header_value(head, "accept") == null);
    try std.testing.expectEqualStrings("/v2/x/manifests/1", request_target(head[0..31]).?);
    try std.testing.expect(request_target("POST /x HTTP/1.1") == null);
    try std.testing.expect(request_target("GET /x") == null);
}
