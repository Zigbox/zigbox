//! What the macOS `zbx` and the guest's init say to each other over vsock, one line at a time.
//! Shared by both sides (and so free of anything but `std`): the guest is a Linux program, the
//! host a macOS one. The version in the answer is the VM image's, so the host can tell that the
//! guest it reached is the one it shipped.
//!
//!     host:  hello\n                     guest: zbx-vm/1 <image version>\n
//!     host:  shutdown\n                  guest: bye\n   (then it syncs and powers off)

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const hello_request = "hello\n";
pub const shutdown_request = "shutdown\n";
pub const shutdown_reply = "bye\n";
pub const reply_prefix = "zbx-vm/1 ";

comptime {
    assert(hello_request.len < constants.vm_line_bytes_max);
    assert(reply_prefix.len + constants.vm_image_version_bytes + 1 <= constants.vm_line_bytes_max);
}

/// True for exactly the text an image version is: lowercase hex digits, no more, no fewer.
pub fn is_version(text: []const u8) bool {
    if (text.len != constants.vm_image_version_bytes) return false;
    for (text) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// The guest's answer to `hello`: the prefix, the version and a newline.
pub fn render_hello_reply(buffer: []u8, version: []const u8) []const u8 {
    assert(is_version(version));
    assert(buffer.len >= reply_prefix.len + version.len + 1);
    const fmt = "{s}{s}\n";
    const arguments = .{ reply_prefix, version };
    // Cannot fail: the buffer was asserted to hold the prefix, the version and a newline.
    const written = std.fmt.bufPrint(buffer, fmt, arguments) catch unreachable;
    assert(written.len == reply_prefix.len + constants.vm_image_version_bytes + 1);
    return written;
}

/// The version in a guest's answer; null for anything `render_hello_reply` does not write.
pub fn parse_hello_reply(line: []const u8) ?[]const u8 {
    if (line.len != reply_prefix.len + constants.vm_image_version_bytes + 1) return null;
    if (!std.mem.startsWith(u8, line, reply_prefix)) return null;
    if (line[line.len - 1] != '\n') return null;
    const version = line[reply_prefix.len .. line.len - 1];
    if (!is_version(version)) return null;
    return version;
}

test "the guest's answer round-trips and nothing else parses" {
    // Goal: parse accepts only what render writes. Method: a good reply, then each way to
    // damage it (prefix, length, case, newline, junk after).
    var buffer: [64]u8 = @splat(0xaa);
    const reply = render_hello_reply(&buffer, "0123456789abcdef");
    try std.testing.expectEqualStrings("zbx-vm/1 0123456789abcdef\n", reply);
    try std.testing.expectEqualStrings("0123456789abcdef", parse_hello_reply(reply).?);
    try std.testing.expect(parse_hello_reply("zbx-vm/2 0123456789abcdef\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcde\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdeF\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdef") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdef\n\n") == null);
    try std.testing.expect(parse_hello_reply("") == null);
}
