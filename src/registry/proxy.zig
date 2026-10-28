//! HTTPS proxies from the environment, as curl, Go and Docker read them: `HTTPS_PROXY` (or
//! `https_proxy`) names a proxy, `NO_PROXY` (or `no_proxy`) lists hosts that bypass it. Pure
//! text functions; `host_real_net.zig` reads the variables and opens the tunnel.
//!
//! A proxy URL is `http://[user:password@]host:port`; the port defaults to 80, and only the
//! `http` scheme (a proxy reached in plain HTTP, which then CONNECTs) is supported. NO_PROXY is a
//! comma-separated list of: `*` (everything), a host name or a `.suffix` (matching that name and
//! the names under it, on a label boundary), an IPv4 address, an IPv4 range `a.b.c.d/n`, each with
//! an optional `:port`. IPv6 entries are not matched.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Proxy = struct {
    host: []const u8,
    port: u16,
    /// `user:password` as written in the URL; empty for none. Never shown.
    userinfo: []const u8,
};

pub const ParseError = error{ BadProxy, UnsupportedProxy };

pub fn parse_proxy(text: []const u8) ParseError!Proxy {
    assert(text.len <= constants.net_proxy_url_bytes_max);
    var rest = text;
    if (std.mem.indexOf(u8, text, "://")) |at| {
        if (!std.ascii.eqlIgnoreCase(text[0..at], "http")) return error.UnsupportedProxy;
        rest = text[at + 3 ..];
    }
    assert(rest.len <= text.len);
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    var authority = if (slash) |at| rest[0..at] else rest;
    if (slash) |at| {
        if (at + 1 != rest.len) return error.BadProxy; // A proxy URL has no path.
    }
    var userinfo: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        userinfo = authority[0..at];
        authority = authority[at + 1 ..];
    }
    var host = authority;
    var port: u16 = 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.BadProxy;
        if (port == 0) return error.BadProxy;
    }
    if (host.len == 0) return error.BadProxy;
    if (host.len > 253) return error.BadProxy;
    for (host) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-' or byte == '_';
        if (!ok) return error.UnsupportedProxy; // IPv6 literals, spaces, control bytes.
    }
    assert(host.len > 0);
    assert(port != 0);
    return .{ .host = host, .port = port, .userinfo = userinfo };
}

/// Whether `host` and `port` bypass the proxy under the NO_PROXY list `list`.
pub fn bypasses(list: []const u8, host: []const u8, port: u16) bool {
    assert(list.len <= constants.net_no_proxy_bytes_max);
    assert(host.len > 0);
    assert(list.len == std.mem.trim(u8, list, "\x00").len);
    var entries = std.mem.splitScalar(u8, list, ',');
    while (entries.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t");
        if (entry.len == 0) continue;
        if (matches(entry, host, port)) return true;
    }
    return false;
}

fn matches(entry: []const u8, host: []const u8, port: u16) bool {
    assert(entry.len > 0);
    assert(host.len > 0);
    if (std.mem.eql(u8, entry, "*")) return true;
    var name = entry;
    if (std.mem.lastIndexOfScalar(u8, entry, ':')) |colon| {
        const wanted = std.fmt.parseInt(u16, entry[colon + 1 ..], 10) catch return false;
        if (wanted != port) return false;
        name = entry[0..colon];
    }
    if (name.len == 0) return false;
    if (std.mem.indexOfScalar(u8, name, '/')) |slash| {
        return in_range(name[0..slash], name[slash + 1 ..], host);
    }
    if (name[0] == '*') name = name[1..]; // "*.example.com" means the same as ".example.com".
    if (name.len == 0) return true;
    if (name[0] == '.') {
        return std.ascii.endsWithIgnoreCase(host, name) or
            std.ascii.eqlIgnoreCase(host, name[1..]);
    }
    if (std.ascii.eqlIgnoreCase(host, name)) return true;
    if (host.len <= name.len) return false;
    const boundary = host[host.len - name.len - 1] == '.';
    return boundary and std.ascii.endsWithIgnoreCase(host, name);
}

fn ipv4(text: []const u8) ?u32 {
    assert(text.len <= constants.net_no_proxy_bytes_max);
    var value: u32 = 0;
    var parts: u32 = 0;
    var pieces = std.mem.splitScalar(u8, text, '.');
    while (pieces.next()) |piece| {
        const octet = std.fmt.parseInt(u8, piece, 10) catch return null;
        value = value << 8 | octet;
        parts += 1;
    }
    if (parts != 4) return null;
    assert(parts == 4);
    return value;
}

fn in_range(network: []const u8, bits_text: []const u8, host: []const u8) bool {
    assert(network.len > 0);
    assert(host.len > 0);
    const base = ipv4(network) orelse return false;
    const address = ipv4(host) orelse return false;
    const bits = std.fmt.parseInt(u8, bits_text, 10) catch return false;
    if (bits > 32) return false;
    if (bits == 0) return true;
    const shift: u5 = @intCast(32 - bits);
    return base >> shift == address >> shift;
}

const testing = std.testing;

test "a proxy URL: scheme, userinfo, port and what is refused" {
    // Goal: the forms in the wild parse; others are refused with their kind.
    const plain = try parse_proxy("http://127.0.0.1:43707");
    try testing.expectEqualStrings("127.0.0.1", plain.host);
    try testing.expectEqual(@as(u16, 43707), plain.port);
    try testing.expectEqualStrings("", plain.userinfo);
    const bare = try parse_proxy("proxy.corp:3128/");
    try testing.expectEqualStrings("proxy.corp", bare.host);
    try testing.expectEqual(@as(u16, 3128), bare.port);
    const authed = try parse_proxy("HTTP://user:p%40ss@proxy.corp");
    try testing.expectEqualStrings("user:p%40ss", authed.userinfo);
    try testing.expectEqual(@as(u16, 80), authed.port);
    try testing.expectError(error.UnsupportedProxy, parse_proxy("https://proxy.corp:3128"));
    try testing.expectError(error.UnsupportedProxy, parse_proxy("socks5://proxy:1080"));
    try testing.expectError(error.UnsupportedProxy, parse_proxy("http://[::1]:3128"));
    try testing.expectError(error.BadProxy, parse_proxy("http://:3128"));
    try testing.expectError(error.BadProxy, parse_proxy("http://host:0"));
    try testing.expectError(error.BadProxy, parse_proxy("http://host:99999"));
    try testing.expectError(error.BadProxy, parse_proxy("http://host/path"));
    try testing.expectError(error.BadProxy, parse_proxy(""));
}

test "NO_PROXY: names, suffixes, ports, addresses, ranges and the star" {
    // Goal: each entry form matches what curl would match and nothing near it.
    const list = "localhost, .internal.corp,10.0.0.0/8,192.168.1.5,example.org:8443,registry.local";
    try testing.expect(bypasses(list, "localhost", 443));
    try testing.expect(bypasses(list, "a.internal.corp", 443));
    try testing.expect(bypasses(list, "internal.corp", 443));
    try testing.expect(!bypasses(list, "notinternal.corp", 443));
    try testing.expect(bypasses(list, "10.20.30.40", 443));
    try testing.expect(!bypasses(list, "11.0.0.1", 443));
    try testing.expect(bypasses(list, "192.168.1.5", 80));
    try testing.expect(!bypasses(list, "192.168.1.6", 80));
    try testing.expect(bypasses(list, "example.org", 8443));
    try testing.expect(!bypasses(list, "example.org", 443));
    try testing.expect(bypasses(list, "REGISTRY.local", 443));
    try testing.expect(bypasses(list, "x.registry.local", 443));
    try testing.expect(!bypasses(list, "myregistry.local", 443));
    try testing.expect(!bypasses(list, "registry-1.docker.io", 443));
    try testing.expect(bypasses("*", "anything", 1));
    try testing.expect(bypasses("*.svc.cluster.local", "a.svc.cluster.local", 1));
    try testing.expect(!bypasses("", "docker.io", 443));
    try testing.expect(!bypasses(" , ,", "docker.io", 443));
    try testing.expect(bypasses("0.0.0.0/0", "8.8.8.8", 53));
    try testing.expect(!bypasses("10.0.0.0/33", "10.0.0.1", 1));
}
