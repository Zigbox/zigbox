//! demo-m9's file server for the pinned fetches (steps 7 and 8): plain HTTP/1.1 on
//! 127.0.0.1:`port`, run in the guest from the directory whose files it serves. Built for the
//! guest with the harness (static, no libc) and served to it like the M10 fixtures.
//!
//! One request per connection (`Connection: close`), one at a time. Each request is logged as
//! one line on standard output, `<method> <target>`, so the demo counts requests by counting
//! lines. Routes:
//!   - `/<name>`: the file `<name>` of the current directory (no `/` in it), or 404;
//!   - `/r/<name>`: 302 to `/<name>`;
//!   - `/loop`: 302 to itself, for the redirect bound.
//! Every size is bounded; a request over the bound or not parsed is answered 400.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

pub const port = 8080;
const request_bytes_max = 4096;
const name_bytes_max = 128;
const body_bytes_max = 1 << 20;
const read_timeout_ms = 5000;

var body: [body_bytes_max]u8 = undefined;

pub fn main() u8 {
    const listener = listen() orelse {
        say(2, "fixture-http: cannot listen on 127.0.0.1:8080\n");
        return 1;
    };
    assert(listener >= 0);
    while (true) {
        const accepted = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(accepted) != .SUCCESS) continue;
        const client: i32 = @intCast(accepted);
        assert(client != listener);
        handle(client);
        _ = linux.close(client);
    }
}

fn listen() ?i32 {
    const created = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(created) != .SUCCESS) return null;
    const listener: i32 = @intCast(created);
    const on: u32 = 1;
    const option = linux.SO.REUSEADDR;
    _ = linux.setsockopt(listener, linux.SOL.SOCKET, option, @ptrCast(&on), @sizeOf(u32));
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(bound) != .SUCCESS) return null;
    if (linux.errno(linux.listen(listener, 16)) != .SUCCESS) return null;
    assert(listener >= 0);
    assert(address.port != 0);
    return listener;
}

fn handle(client: i32) void {
    assert(client >= 0);
    var request: [request_bytes_max]u8 = undefined;
    const length = read_head(client, &request) orelse return answer(client, "400 Bad Request");
    assert(length <= request.len);
    const line = request[0 .. std.mem.indexOf(u8, request[0..length], "\r\n") orelse length];
    log(line);
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    const method = words.next() orelse return answer(client, "400 Bad Request");
    const target = words.next() orelse return answer(client, "400 Bad Request");
    if (!std.mem.eql(u8, method, "GET")) return answer(client, "405 Method Not Allowed");
    if (std.mem.eql(u8, target, "/loop")) return redirect(client, "/loop");
    if (std.mem.startsWith(u8, target, "/r/")) return redirect(client, target["/r".len..]);
    if (target.len < 2 or target[0] != '/') return answer(client, "404 Not Found");
    const name = target[1..];
    if (std.mem.indexOfScalar(u8, name, '/') != null) return answer(client, "404 Not Found");
    if (name.len > name_bytes_max or name[0] == '.') return answer(client, "404 Not Found");
    const size = read_file(name) orelse return answer(client, "404 Not Found");
    var head: [128]u8 = undefined;
    const format = "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n";
    // The buffer holds the head with the longest length a `usize` prints.
    const text = std.fmt.bufPrint(&head, format, .{size}) catch unreachable;
    send(client, text);
    send(client, body[0..size]);
}

/// Reads `name` from the current directory into `body`; null if it is missing or too big.
fn read_file(name: []const u8) ?usize {
    assert(name.len > 0);
    assert(name.len <= name_bytes_max);
    var path: [name_bytes_max + 1]u8 = undefined;
    @memcpy(path[0..name.len], name);
    path[name.len] = 0;
    const opened = linux.open(path[0..name.len :0], .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return null;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    var size: usize = 0;
    while (size < body.len) {
        const got = linux.read(fd, body[size..].ptr, body.len - size);
        if (linux.errno(got) != .SUCCESS) return null;
        if (got == 0) return size;
        size += got;
    }
    return null; // At the bound: the file may be bigger.
}

fn redirect(client: i32, location: []const u8) void {
    assert(location.len > 0);
    assert(location[0] == '/');
    var head: [request_bytes_max + 128]u8 = undefined;
    const format = "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n" ++
        "Connection: close\r\n\r\n";
    // The location is part of a request head, so it is shorter than the buffer.
    send(client, std.fmt.bufPrint(&head, format, .{location}) catch unreachable);
}

fn answer(client: i32, status: []const u8) void {
    assert(client >= 0);
    assert(status.len > 0);
    var head: [128]u8 = undefined;
    const format = "HTTP/1.1 {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    // Every status this server sends is a short literal.
    send(client, std.fmt.bufPrint(&head, format, .{status}) catch unreachable);
}

/// Reads up to the end of the head; null on a timeout, a close or a head over the bound.
fn read_head(client: i32, buffer: []u8) ?usize {
    assert(client >= 0);
    assert(buffer.len > 0);
    var length: usize = 0;
    var waited: u32 = 0;
    while (length < buffer.len) {
        var entries = [1]linux.pollfd{.{ .fd = client, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&entries, 1, 50);
        if (linux.errno(ready) != .SUCCESS) return null;
        if (ready == 0) {
            waited += 50;
            if (waited >= read_timeout_ms) return null;
            continue;
        }
        const room = buffer[length..];
        const got = linux.read(client, room.ptr, room.len);
        if (linux.errno(got) != .SUCCESS or got == 0) return null;
        length += got;
        if (std.mem.indexOf(u8, buffer[0..length], "\r\n\r\n")) |end| return end + 4;
    }
    return null;
}

/// One log line per request: the request line, cut at the bound, then a newline.
fn log(line: []const u8) void {
    var buffer: [256]u8 = undefined;
    const kept = @min(line.len, buffer.len - 1);
    @memcpy(buffer[0..kept], line[0..kept]);
    buffer[kept] = '\n';
    say(1, buffer[0 .. kept + 1]);
}

fn say(fd: i32, text: []const u8) void {
    assert(fd >= 1);
    assert(fd <= 2);
    assert(text.len > 0);
    _ = linux.write(fd, text.ptr, text.len);
}

fn send(client: i32, text: []const u8) void {
    assert(client >= 0);
    var at: usize = 0;
    while (at < text.len) {
        const written = linux.write(client, text[at..].ptr, text.len - at);
        if (linux.errno(written) != .SUCCESS or written == 0) return;
        at += written;
    }
}
