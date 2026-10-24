//! The text part of a D-Bus connection: the bus address, and the SASL EXTERNAL handshake
//! (https://dbus.freedesktop.org/doc/dbus-specification.html, "Server Addresses" and
//! "Authentication Protocol"). Pure functions over bytes; the client in `client.zig` does the
//! reading and writing.
//!
//! EXTERNAL proves who the caller is by the credentials of the socket, so the only thing sent is
//! the user id, as hex of its decimal text: uid 1000 is "31303030".

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const repeat = @import("../test_util.zig").repeat;

pub const AddressError = error{
    /// The address is empty.
    Empty,
    /// A transport other than `unix:path=`: abstract sockets, tcp, launchd, systemd activation.
    Unsupported,
    /// The path is longer than a socket address can hold, or the address longer than the bound.
    TooLong,
    /// A `%` escape that is not two hex digits, or a NUL in the path.
    BadEscape,
};

const unix_prefix = "unix:";
const path_key = "path=";

/// The socket path in a bus address, written into `buffer`. Only the first address of a
/// `;`-separated list is read, and it must be `unix:path=...` (keys after a comma, such as
/// `guid=`, are ignored). The value may use `%xx` escapes, which are decoded.
pub fn socket_path(
    buffer: *[constants.dbus_socket_path_bytes_max]u8,
    address: []const u8,
) AddressError![]const u8 {
    assert(buffer.len == constants.dbus_socket_path_bytes_max);
    if (address.len == 0) return error.Empty;
    if (address.len > constants.dbus_address_bytes_max) return error.TooLong;
    const first = address[0 .. std.mem.indexOfScalar(u8, address, ';') orelse address.len];
    if (!std.mem.startsWith(u8, first, unix_prefix)) return error.Unsupported;
    var pairs = std.mem.splitScalar(u8, first[unix_prefix.len..], ',');
    while (pairs.next()) |pair| {
        if (!std.mem.startsWith(u8, pair, path_key)) continue;
        return decode_path(buffer, pair[path_key.len..]);
    }
    return error.Unsupported; // unix:abstract=, unix:runtime=, unix:dir=, ...
}

fn decode_path(
    buffer: *[constants.dbus_socket_path_bytes_max]u8,
    escaped: []const u8,
) AddressError![]const u8 {
    assert(escaped.len <= constants.dbus_address_bytes_max);
    var length: usize = 0;
    var at: usize = 0;
    while (at < escaped.len) {
        if (length == buffer.len) return error.TooLong;
        if (escaped[at] != '%') {
            buffer[length] = escaped[at];
            at += 1;
        } else {
            if (at + 3 > escaped.len) return error.BadEscape;
            buffer[length] = std.fmt.parseInt(u8, escaped[at + 1 ..][0..2], 16) catch
                return error.BadEscape;
            at += 3;
        }
        length += 1;
    }
    if (length == 0) return error.Empty;
    if (std.mem.indexOfScalar(u8, buffer[0..length], 0) != null) return error.BadEscape;
    assert(length <= buffer.len);
    assert(length > 0);
    return buffer[0..length];
}

/// What the server answered to `AUTH`.
pub const Reply = union(enum) {
    /// `OK <guid>`: the server accepts. The guid is not used.
    ok,
    /// `REJECTED <mechanisms>`: it does not accept EXTERNAL for this user.
    rejected,
    /// `ERROR ...`, or a line this client does not know.
    other,
};

/// The bytes that open a connection: the NUL byte the protocol starts with, then the `AUTH
/// EXTERNAL <hex uid>` line. Sent as one write.
pub fn request(buffer: *[64]u8, uid: u32) []const u8 {
    assert(buffer.len >= "\x00AUTH EXTERNAL ".len + 20 + 2);
    var digits: [10]u8 = undefined;
    // Cannot fail: a u32 has at most ten decimal digits.
    const text = std.fmt.bufPrint(&digits, "{d}", .{uid}) catch unreachable;
    var length: usize = 0;
    const head = "\x00AUTH EXTERNAL ";
    @memcpy(buffer[0..head.len], head);
    length = head.len;
    const hex = "0123456789abcdef";
    for (text) |digit| {
        buffer[length] = hex[digit >> 4];
        buffer[length + 1] = hex[digit & 15];
        length += 2;
    }
    buffer[length] = '\r';
    buffer[length + 1] = '\n';
    length += 2;
    assert(length <= buffer.len);
    assert(buffer[0] == 0);
    return buffer[0..length];
}

/// Sent after `OK`: the connection now speaks messages.
pub const begin = "BEGIN\r\n";

/// Classifies one reply line, without its CRLF.
pub fn parse_reply(line: []const u8) Reply {
    assert(line.len <= constants.dbus_auth_line_bytes_max);
    assert(std.mem.indexOfScalar(u8, line, '\n') == null);
    if (std.mem.eql(u8, line, "OK") or std.mem.startsWith(u8, line, "OK ")) return .ok;
    if (std.mem.eql(u8, line, "REJECTED") or std.mem.startsWith(u8, line, "REJECTED ")) {
        return .rejected;
    }
    return .other;
}

const testing = std.testing;

test "the AUTH line carries the uid as hex of its decimal text" {
    // Goal: the bytes the bus expects, from the specification's own example form.
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("\x00AUTH EXTERNAL 31303030\r\n", request(&buffer, 1000));
    try testing.expectEqualStrings("\x00AUTH EXTERNAL 30\r\n", request(&buffer, 0));
    const longest = request(&buffer, 4294967295);
    try testing.expectEqualStrings("\x00AUTH EXTERNAL 34323934393637323935\r\n", longest);
}

test "replies: OK and REJECTED are told apart from anything else" {
    // Goal: only the two words the protocol defines are believed, and not as prefixes of others.
    try testing.expectEqual(Reply.ok, parse_reply("OK 1234deadbeef"));
    try testing.expectEqual(Reply.ok, parse_reply("OK"));
    try testing.expectEqual(Reply.rejected, parse_reply("REJECTED EXTERNAL"));
    try testing.expectEqual(Reply.other, parse_reply("OKAY"));
    try testing.expectEqual(Reply.other, parse_reply("ERROR \"nope\""));
    try testing.expectEqual(Reply.other, parse_reply(""));
    try testing.expectEqual(Reply.other, parse_reply("ok"));
}

test "bus addresses: unix:path is read, everything else is refused by name" {
    // Goal: the one transport supported, with its keys, escapes and lists, and the refusals.
    var buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    const plain = "unix:path=/run/user/1000/bus";
    try testing.expectEqualStrings("/run/user/1000/bus", try socket_path(&buffer, plain));
    const with_guid = "unix:path=/run/user/1000/bus,guid=0123456789abcdef";
    try testing.expectEqualStrings("/run/user/1000/bus", try socket_path(&buffer, with_guid));
    const listed = "unix:path=/a/b;unix:abstract=x";
    try testing.expectEqualStrings("/a/b", try socket_path(&buffer, listed));
    try testing.expectEqualStrings("/a b", try socket_path(&buffer, "unix:path=/a%20b"));
    try testing.expectError(error.Unsupported, socket_path(&buffer, "unix:abstract=/tmp/dbus"));
    try testing.expectError(error.Unsupported, socket_path(&buffer, "tcp:host=localhost,port=1"));
    try testing.expectError(error.Unsupported, socket_path(&buffer, "unix:runtime=yes"));
    try testing.expectError(error.Unsupported, socket_path(&buffer, "unixx:path=/a"));
    try testing.expectError(error.Empty, socket_path(&buffer, ""));
    try testing.expectError(error.Empty, socket_path(&buffer, "unix:path="));
    try testing.expectError(error.BadEscape, socket_path(&buffer, "unix:path=/a%2"));
    try testing.expectError(error.BadEscape, socket_path(&buffer, "unix:path=/a%zz"));
    try testing.expectError(error.BadEscape, socket_path(&buffer, "unix:path=/a%00b"));
}

test "a socket path past the kernel's limit is refused at the boundary" {
    // Goal: 107 bytes fit sun_path with its NUL, 108 do not.
    var buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    const fits = "unix:path=/" ++ repeat('a', constants.dbus_socket_path_bytes_max - 1);
    const found = try socket_path(&buffer, fits);
    try testing.expectEqual(@as(usize, constants.dbus_socket_path_bytes_max), found.len);
    const over = fits ++ "a";
    try testing.expectError(error.TooLong, socket_path(&buffer, over));
    const huge = "unix:path=/" ++ repeat('a', constants.dbus_address_bytes_max);
    try testing.expectError(error.TooLong, socket_path(&buffer, huge));
}
