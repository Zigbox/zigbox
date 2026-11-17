//! What the guest helper says about a token it resolved: its class and its length, never a byte
//! of it. The helper's output is saved under the demo user's home, which step 5 searches for the
//! token shapes, and is printed through the mask, which replaces them; a line that carried a
//! shape would fail both. Pure; the harness's unit tests feed it throwaway tokens
//! (checks_m6d_tests.zig).

const std = @import("std");
const assert = std.debug.assert;
const scan = @import("scan.zig");

pub const Class = enum {
    /// Starts with `ya29.` (scan.shapes[0]), the shape step 5 searches, and has bytes after it.
    google_access,
    /// Anything else: step 5's search by shape would not find it.
    unknown,
};

pub const line_bytes_max = 128;

pub fn classify(token: []const u8) Class {
    assert(token.len > 0);
    if (token.len <= scan.shapes[0].len) return .unknown;
    if (!std.mem.startsWith(u8, token, scan.shapes[0])) return .unknown;
    return .google_access;
}

/// `shapes: <label> token: <class>, <n> bytes`. `label` is the helper's own word for the token
/// (`federated`, `access`), never anything read from it.
pub fn shape_line(buffer: *[line_bytes_max]u8, label: []const u8, token: []const u8) []const u8 {
    assert(label.len > 0);
    assert(label.len <= 32);
    const class = classify(token);
    const line = std.fmt.bufPrint(buffer, "shapes: {s} token: {t}, {d} bytes", .{
        label, class, token.len,
    }) catch unreachable; // 8 + 32 + 9 + 13 + 2 + 20 + 6 bytes at most.
    assert(std.mem.indexOf(u8, line, scan.shapes[0]) == null);
    return line;
}
