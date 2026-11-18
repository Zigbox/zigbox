//! The HTTP/1.1 pieces of demo-s2's disk-backed registry (`registry_disk_s2.zig`): reading a
//! request head and body from a socket, the few headers it reads, a closed `Range`, and writing
//! a response head. One request per connection: every response says `Connection: close`, which
//! is what zbx sends too. Raw Linux calls, as `registry_server.zig` does.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

pub const head_bytes_max = 8192;
/// How long a request may take to arrive between two reads.
pub const read_timeout_ms: u32 = 10_000;
const poll_ms: i32 = 50;

pub const Method = enum { get, head, post, patch, put, other };

pub const Request = struct {
    method: Method,
    /// The path, without the query.
    path: []const u8,
    query: []const u8,
    /// The whole head, for `header`.
    head: []const u8,
    /// Body bytes that arrived with the head.
    early: []const u8,

    pub fn header(request: *const Request, name: []const u8) ?[]const u8 {
        assert(name.len > 0);
        assert(request.head.len > 0);
        var lines = std.mem.splitSequence(u8, request.head, "\r\n");
        _ = lines.next(); // The request line.
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
        return null;
    }

    /// The body's length; 0 without the header, null when it is not a number.
    pub fn content_length(request: *const Request) ?u64 {
        const text = request.header("Content-Length") orelse return 0;
        assert(text.len <= head_bytes_max);
        return std.fmt.parseInt(u64, text, 10) catch null;
    }
};

/// Parses a head that `read_head` found complete; null when it is not a request.
pub fn parse(buffer: []const u8, head_len: usize) ?Request {
    assert(head_len <= buffer.len);
    assert(head_len >= 4);
    const head = buffer[0 .. head_len - 4];
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
    var parts = std.mem.splitScalar(u8, head[0..line_end], ' ');
    const method_text = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    if (target.len == 0 or target[0] != '/') return null;
    const question = std.mem.indexOfScalar(u8, target, '?');
    const methods = [_]struct { []const u8, Method }{
        .{ "GET", .get },     .{ "HEAD", .head }, .{ "POST", .post },
        .{ "PATCH", .patch }, .{ "PUT", .put },
    };
    var method: Method = .other;
    for (methods) |pair| {
        if (std.mem.eql(u8, method_text, pair[0])) method = pair[1];
    }
    return .{
        .method = method,
        .path = if (question) |at| target[0..at] else target,
        .query = if (question) |at| target[at + 1 ..] else "",
        .head = head,
        .early = buffer[head_len..],
    };
}

/// The value of `name` in a query string (`a=1&b=2`), or an empty slice.
pub fn query_value(query: []const u8, name: []const u8) []const u8 {
    assert(name.len > 0);
    assert(query.len <= head_bytes_max);
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..equals], name)) return pair[equals + 1 ..];
    }
    return "";
}

pub const Range = struct { first: u64, last: u64 };

/// A closed `bytes=a-b` inside a body of `size` bytes; null for any other form or a range past
/// the end (the registry answers 416).
pub fn parse_range(text: []const u8, size: u64) ?Range {
    assert(text.len <= head_bytes_max);
    const prefix = "bytes=";
    if (!std.mem.startsWith(u8, text, prefix)) return null;
    const spec = text[prefix.len..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    const first = std.fmt.parseInt(u64, spec[0..dash], 10) catch return null;
    const last = std.fmt.parseInt(u64, spec[dash + 1 ..], 10) catch return null;
    if (first > last or last >= size) return null;
    assert(last - first < size);
    return .{ .first = first, .last = last };
}

/// Reads until the blank line that ends a head; the head's length (with the blank line), or
/// null on a timeout, a close, a stop or an oversize head. `filled` is what was read in all.
pub fn read_head(
    socket: i32,
    buffer: *[head_bytes_max]u8,
    filled: *usize,
    stopping: *const std.atomic.Value(bool),
) ?usize {
    assert(socket >= 0);
    filled.* = 0;
    while (filled.* < buffer.len) {
        const got = read_some(socket, buffer[filled.*..], stopping) orelse return null;
        filled.* += got;
        if (std.mem.indexOf(u8, buffer[0..filled.*], "\r\n\r\n")) |end| return end + 4;
    }
    return null;
}

/// One `recv` of at most `room.len` bytes once the socket is readable; null on a timeout, a
/// close or a stop.
pub fn read_some(socket: i32, room: []u8, stopping: *const std.atomic.Value(bool)) ?usize {
    assert(room.len > 0);
    var waited: u32 = 0;
    while (!stopping.load(.acquire)) {
        var entries = [1]linux.pollfd{.{ .fd = socket, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&entries, 1, poll_ms);
        if (linux.errno(ready) != .SUCCESS) return null;
        if (ready == 0) {
            waited += poll_ms;
            if (waited >= read_timeout_ms) return null;
            continue;
        }
        const got = linux.recvfrom(socket, room.ptr, room.len, 0, null, null);
        if (linux.errno(got) != .SUCCESS or got == 0) return null;
        assert(got <= room.len);
        return got;
    }
    return null;
}

/// Sends all of `bytes`; false when the peer went away.
pub fn write_all(socket: i32, bytes: []const u8) bool {
    assert(socket >= 0);
    var at: usize = 0;
    while (at < bytes.len) {
        const rest = bytes[at..];
        const sent = linux.sendto(socket, rest.ptr, rest.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(sent) != .SUCCESS) return false;
        at += sent;
    }
    assert(at == bytes.len);
    return true;
}

/// Headers a response carries besides the status line and `Content-Length`.
pub const Head = struct {
    status: u16,
    length: u64 = 0,
    content_type: []const u8 = "",
    digest: []const u8 = "",
    location: []const u8 = "",
    range: []const u8 = "",
    content_range: []const u8 = "",
    upload_uuid: []const u8 = "",
};

pub const response_head_bytes_max = 1024;

/// Renders `head` into `buffer`.
pub fn render_head(head: Head, buffer: *[response_head_bytes_max]u8) []const u8 {
    assert(head.status >= 200);
    assert(head.status < 600);
    var writer: std.Io.Writer = .fixed(buffer);
    writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n", .{
        head.status, reason(head.status), head.length,
    }) catch unreachable; // A status line and two short headers fit.
    const optional = [_][2][]const u8{
        .{ "Content-Type", head.content_type },
        .{ "Docker-Content-Digest", head.digest },
        .{ "Location", head.location },
        .{ "Range", head.range },
        .{ "Content-Range", head.content_range },
        .{ "Docker-Upload-UUID", head.upload_uuid },
    };
    for (optional) |pair| {
        if (pair[1].len == 0) continue;
        assert(pair[1].len < 256); // Paths, digests and ranges: the buffer holds them all.
        writer.print("{s}: {s}\r\n", .{ pair[0], pair[1] }) catch unreachable; // See above.
    }
    writer.writeAll("Accept-Ranges: bytes\r\n\r\n") catch unreachable; // Room is left for it.
    return writer.buffered();
}

fn reason(status: u16) []const u8 {
    assert(status >= 200);
    return switch (status) {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        206 => "Partial Content",
        400 => "Bad Request",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        else => "Error",
    };
}

test "http_s2: a request head, its headers, query and range" {
    // Goal: the registry reads what zbx sends: method, path, query, headers, a closed range.
    // Method: parse a hand-written PATCH with early body bytes and check each piece; then the
    // range forms that must be refused.
    const text = "PATCH /v2/lazy/blobs/uploads/3?a=1&digest=sha256:ab HTTP/1.1\r\n" ++
        "Host: x\r\ncontent-length: 5\r\nRange: bytes=2-9\r\n\r\nhello";
    const head_len = std.mem.indexOf(u8, text, "\r\n\r\n").? + 4;
    const request = parse(text, head_len).?;
    try std.testing.expectEqual(Method.patch, request.method);
    try std.testing.expectEqualStrings("/v2/lazy/blobs/uploads/3", request.path);
    try std.testing.expectEqualStrings("sha256:ab", query_value(request.query, "digest"));
    try std.testing.expectEqualStrings("", query_value(request.query, "mount"));
    try std.testing.expectEqual(@as(?u64, 5), request.content_length());
    try std.testing.expectEqualStrings("hello", request.early);
    const range = parse_range(request.header("range").?, 10).?;
    try std.testing.expectEqual(@as(u64, 2), range.first);
    try std.testing.expectEqual(@as(u64, 9), range.last);
    try std.testing.expect(parse_range("bytes=2-10", 10) == null);
    try std.testing.expect(parse_range("bytes=5-", 10) == null);
    try std.testing.expect(parse_range("bytes=5-4", 10) == null);
    try std.testing.expect(parse("garbage\r\n\r\n", 11) == null);
}

test "http_s2: a response head" {
    // Goal: the head carries the status, the length and only the headers that are set.
    // Method: render a 206 and look for each line.
    var buffer: [response_head_bytes_max]u8 = undefined;
    const head: Head = .{ .status = 206, .length = 8, .content_range = "bytes 2-9/10" };
    const text = render_head(head, &buffer);
    try std.testing.expect(std.mem.startsWith(u8, text, "HTTP/1.1 206 Partial Content\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, text, "Content-Length: 8\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Content-Range: bytes 2-9/10\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Location") == null);
    try std.testing.expect(std.mem.endsWith(u8, text, "\r\n\r\n"));
}
