//! The network half of the host interface, which the registry client is written against.
//! `host.zig` hands one out (`Host.network`): the real one is `host_real_net.zig` (sockets, DNS,
//! TLS, the proxy), the simulator's is `net_sim.zig` (a registry in memory with faults). Code
//! above this file does not know which it has (docs/STYLE.md, layer 4).
//!
//! One call is one HTTP GET and one response: the vtable does not follow redirects, retry, or
//! authenticate. Those are the client's (`client.zig`), written once, so the simulator exercises
//! the code that runs in production. What the vtable does own is everything a wire can do wrong:
//! the connection (DNS, connect, the proxy, TLS), the timeouts, and the bounds. It stops reading
//! at `body_bytes_max`, refuses a head larger than the bound, and reports a body that ends before
//! its declared length as `Truncated`.
//!
//! A bearer token is passed in and sent, and never stored, returned or put in an error.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const reference = @import("reference.zig");

pub const Scheme = reference.Scheme;

/// What a call can fail with. Each is a distinct condition with its own diagnostic; the real
/// errno of a failed system call is in `Net.last_errno`.
pub const Error = error{
    /// The name does not resolve.
    UnknownHost,
    /// The address refused or could not be reached.
    ConnectFailed,
    /// The proxy refused the tunnel, or is not a proxy.
    ProxyFailed,
    /// The certificate chain does not lead to a trusted root.
    TlsUntrusted,
    TlsExpired,
    TlsHostMismatch,
    /// Any other failure of the handshake or the record layer.
    TlsFailed,
    /// No CA certificates could be loaded, so no HTTPS peer can be verified.
    NoCertificates,
    /// A wait for the peer ran out of time.
    TimedOut,
    /// The connection ended before the body did.
    Truncated,
    /// A body, or a head, over its bound.
    TooLarge,
    /// The peer did not speak HTTP, or sent a head that cannot be used.
    BadResponse,
    /// The sink refused bytes (its own failure is the caller's to explain).
    SinkFailed,
    /// The request asks for what this build cannot do (an IPv6 literal, for example).
    Unsupported,
    IoFailed,
};

pub const Request = struct {
    scheme: Scheme,
    /// A DNS name or an IPv4 address, without a port.
    host: []const u8,
    port: u16,
    /// The path and the query, starting with '/'.
    target: []const u8,
    /// The Accept header's value; empty for none.
    accept: []const u8,
    /// The bearer token; empty for none. Never logged, never returned.
    bearer: []const u8,
    /// The most body bytes to take; one more is `TooLarge`.
    body_bytes_max: u64,
    /// How long any one wait (connect, handshake, the next bytes) may take.
    idle_timeout_ms: u32,
    /// How long the whole call may take; zero for no limit (a blob is bounded by progress).
    total_timeout_ms: u32,
    /// A resumed download: ask for the bytes from this offset on (`Range: bytes=N-`). Zero asks
    /// for the whole body and sends no header.
    range_from: u64 = 0,
};

/// A header value kept whole, or marked cut: a value past its bound is never half-used.
pub fn HeaderValue(comptime capacity: u32) type {
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        len: u32 = 0,
        present: bool = false,
        truncated: bool = false,

        pub fn set(value: *Self, text: []const u8) void {
            assert(value.len == 0);
            value.present = true;
            if (text.len > capacity) {
                value.truncated = true;
                return;
            }
            @memcpy(value.bytes[0..text.len], text);
            value.len = @intCast(text.len);
        }

        /// The value; null when the header was absent or too long to keep.
        pub fn slice(value: *const Self) ?[]const u8 {
            assert(value.len <= capacity);
            if (!value.present) return null;
            if (value.truncated) return null;
            return value.bytes[0..value.len];
        }
    };
}

pub const Head = struct {
    status: u16 = 0,
    /// The declared length of the body this response carries.
    content_length: ?u64 = null,
    www_authenticate: HeaderValue(constants.registry_challenge_bytes_max) = .{},
    retry_after: HeaderValue(constants.registry_header_bytes_max) = .{},
    content_type: HeaderValue(constants.registry_header_bytes_max) = .{},
    content_digest: HeaderValue(constants.registry_header_bytes_max) = .{},
    location: HeaderValue(constants.registry_url_bytes_max) = .{},
    /// "bytes first-last/total" of a 206 answer.
    content_range: HeaderValue(constants.registry_header_bytes_max) = .{},
    /// Body bytes handed to the sink.
    body_len: u64 = 0,

    pub fn reset(head: *Head) void {
        head.* = .{};
        assert(head.status == 0);
        assert(head.body_len == 0);
    }
};

/// Where body bytes go as they arrive. A sink that returns an error stops the call.
pub const Sink = struct {
    context: *anyopaque,
    write: *const fn (context: *anyopaque, bytes: []const u8) error{SinkFull}!void,
};

pub const VTable = struct {
    get: *const fn (
        context: *anyopaque,
        request: *const Request,
        head: *Head,
        sink: Sink,
    ) Error!void,
    /// The errno of the last failed system call, zero if none (for the verbose cause).
    last_errno: *const fn (context: *anyopaque) u16,
};

pub const Net = struct {
    context: *anyopaque,
    vtable: *const VTable,

    /// One GET. On success `head` is the response and its body went to `sink`; whatever the
    /// status, a body over `body_bytes_max` is `TooLarge`.
    pub fn get(net: Net, request: *const Request, head: *Head, sink: Sink) Error!void {
        assert(request.host.len > 0);
        assert(request.port != 0);
        assert(request.target.len > 0);
        assert(request.target[0] == '/');
        assert(request.target.len <= constants.registry_url_bytes_max);
        assert(request.bearer.len <= constants.registry_token_bytes_max);
        assert(request.idle_timeout_ms > 0);
        assert(request.body_bytes_max > 0);
        head.reset();
        try net.vtable.get(net.context, request, head, sink);
        assert(head.status >= 100);
        assert(head.status <= 599);
        assert(head.body_len <= request.body_bytes_max);
        if (head.content_length) |declared| assert(declared >= head.body_len);
    }

    pub fn last_errno(net: Net) u16 {
        const errno = net.vtable.last_errno(net.context);
        assert(errno < 4096);
        return errno;
    }
};

/// A sink that fills a buffer and refuses what does not fit.
pub const BufferSink = struct {
    buffer: []u8,
    len: u32 = 0,

    pub fn sink(self: *BufferSink) Sink {
        return .{ .context = self, .write = write };
    }

    pub fn bytes(self: *const BufferSink) []const u8 {
        assert(self.len <= self.buffer.len);
        return self.buffer[0..self.len];
    }

    fn write(context: *anyopaque, data: []const u8) error{SinkFull}!void {
        const self: *BufferSink = @ptrCast(@alignCast(context));
        assert(self.len <= self.buffer.len);
        if (data.len > self.buffer.len - self.len) return error.SinkFull;
        @memcpy(self.buffer[self.len..][0..data.len], data);
        self.len += @intCast(data.len);
    }
};

/// Splits `http://host:port/path?query` or `https://...` into its parts. Only what a registry
/// sends is accepted: no userinfo, no fragment, a DNS name or IPv4 host.
pub const Url = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    /// Path and query, starting with '/'.
    target: []const u8,
};

pub const UrlError = error{ BadUrl, UnsupportedScheme };

pub fn parse_url(text: []const u8) UrlError!Url {
    assert(text.len <= constants.registry_url_bytes_max * 2);
    var scheme: Scheme = .https;
    var rest: []const u8 = undefined;
    if (std.mem.startsWith(u8, text, "https://")) {
        rest = text["https://".len..];
    } else if (std.mem.startsWith(u8, text, "http://")) {
        scheme = .http;
        rest = text["http://".len..];
    } else return error.UnsupportedScheme;
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |at| rest[0..at] else rest;
    const target = if (slash) |at| rest[at..] else "/";
    if (target.len > constants.registry_url_bytes_max) return error.BadUrl;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return error.BadUrl;
        if (byte == '#') return error.BadUrl;
    }
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return error.BadUrl;
    var host = authority;
    var port: u16 = if (scheme == .http) 80 else 443;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.BadUrl;
        if (port == 0) return error.BadUrl;
    }
    if (host.len == 0 or host.len > 253) return error.BadUrl;
    for (host) |byte| {
        const name = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-';
        if (!name) return error.BadUrl;
    }
    assert(target[0] == '/');
    return .{ .scheme = scheme, .host = host, .port = port, .target = target };
}

/// The URL without its query, for a message: a redirect to a CDN carries a signature in its
/// query, and a token must never reach a log.
pub fn without_query(text: []const u8) []const u8 {
    assert(text.len <= constants.registry_url_bytes_max * 2);
    const cut = std.mem.indexOfAny(u8, text, "?#") orelse return text;
    assert(cut <= text.len);
    return text[0..cut];
}

const testing = std.testing;

test "parse_url takes what a registry sends and nothing else" {
    // Goal: schemes, ports, targets and the refusals (userinfo, fragments, spaces, no host).
    const plain = try parse_url("http://127.0.0.1:5000/token?service=a&scope=b");
    try testing.expectEqual(Scheme.http, plain.scheme);
    try testing.expectEqualStrings("127.0.0.1", plain.host);
    try testing.expectEqual(@as(u16, 5000), plain.port);
    try testing.expectEqualStrings("/token?service=a&scope=b", plain.target);
    const secure = try parse_url("https://auth.docker.io/token");
    try testing.expectEqual(@as(u16, 443), secure.port);
    try testing.expectEqualStrings("/token", secure.target);
    const bare = try parse_url("https://ghcr.io");
    try testing.expectEqualStrings("/", bare.target);
    try testing.expectError(error.UnsupportedScheme, parse_url("ftp://x/y"));
    try testing.expectError(error.UnsupportedScheme, parse_url("/relative"));
    try testing.expectError(error.BadUrl, parse_url("https://u:p@host/x"));
    try testing.expectError(error.BadUrl, parse_url("https://host/x#frag"));
    try testing.expectError(error.BadUrl, parse_url("https://host/x y"));
    try testing.expectError(error.BadUrl, parse_url("https:///x"));
    try testing.expectError(error.BadUrl, parse_url("https://host:0/x"));
    try testing.expectError(error.BadUrl, parse_url("https://host:99999/x"));
    try testing.expectError(error.BadUrl, parse_url("https://[::1]/x"));
}

test "without_query drops signatures" {
    // Goal: a URL shown to a person never carries its query.
    try testing.expectEqualStrings("https://cdn/x", without_query("https://cdn/x?sig=abc"));
    try testing.expectEqualStrings("https://cdn/x", without_query("https://cdn/x"));
    try testing.expectEqualStrings("", without_query("?a"));
}

test "a header value is kept whole or marked cut" {
    // Goal: the boundary: exact fit is kept, one more is absent, and absent is not empty.
    var value: HeaderValue(8) = .{};
    try testing.expect(value.slice() == null);
    value.set("12345678");
    try testing.expectEqualStrings("12345678", value.slice().?);
    var over: HeaderValue(8) = .{};
    over.set("123456789");
    try testing.expect(over.slice() == null);
    try testing.expect(over.present);
    var empty: HeaderValue(8) = .{};
    empty.set("");
    try testing.expectEqualStrings("", empty.slice().?);
}

test "a buffer sink fills exactly and then refuses" {
    // Goal: the sink never writes past its buffer.
    var storage: [4]u8 = undefined;
    var sink: BufferSink = .{ .buffer = &storage };
    const s = sink.sink();
    try s.write(s.context, "ab");
    try s.write(s.context, "cd");
    try testing.expectError(error.SinkFull, s.write(s.context, "e"));
    try testing.expectEqualStrings("abcd", sink.bytes());
}
