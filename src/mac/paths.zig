//! Where the macOS zbx keeps the VM's files, all below the user's Library:
//!
//!     ~/Library/Application Support/zbx/vm-settings    the size set by `zbx vm config`
//!     ~/Library/Application Support/zbx/vm/<version>/  the unpacked kernel and initramfs
//!     ~/Library/Application Support/zbx/vm/control.sock, host.lock, console.log, host.log
//!
//! Pure: the home directory is an argument, so tests use a directory of their own.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Text = struct {
    bytes: [constants.vm_path_bytes_max]u8 = undefined,
    length: u32 = 0,

    pub fn slice(text: *const Text) []const u8 {
        assert(text.length > 0);
        return text.bytes[0..text.length];
    }

    pub fn set(text: *Text, comptime format: []const u8, args: anytype) error{TooLong}!void {
        const written = std.fmt.bufPrint(&text.bytes, format, args) catch return error.TooLong;
        text.length = @intCast(written.len);
        assert(text.length > 0);
    }
};

pub const Paths = struct {
    base: Text = .{},
    vm_dir: Text = .{},
    socket: Text = .{},
    lock: Text = .{},
    console_log: Text = .{},
    host_log: Text = .{},
    settings: Text = .{},
    image_dir: Text = .{},
    kernel: Text = .{},
    initramfs: Text = .{},

    pub fn init(paths: *Paths, home: []const u8, version: []const u8) error{TooLong}!void {
        assert(home.len > 0);
        assert(home[0] == '/');
        assert(version.len > 0);
        try paths.base.set("{s}/Library/Application Support/zbx", .{home});
        const base = paths.base.slice();
        try paths.vm_dir.set("{s}/vm", .{base});
        const vm_dir = paths.vm_dir.slice();
        try paths.socket.set("{s}/control.sock", .{vm_dir});
        try paths.lock.set("{s}/host.lock", .{vm_dir});
        try paths.console_log.set("{s}/console.log", .{vm_dir});
        try paths.host_log.set("{s}/host.log", .{vm_dir});
        try paths.settings.set("{s}/vm-settings", .{base});
        try paths.image_dir.set("{s}/{s}", .{ vm_dir, version });
        const image_dir = paths.image_dir.slice();
        try paths.kernel.set("{s}/Image", .{image_dir});
        try paths.initramfs.set("{s}/initramfs.cpio", .{image_dir});
        assert(std.mem.startsWith(u8, paths.socket.slice(), vm_dir));
    }
};

test "paths nest below the home directory and a long home is refused" {
    // Goal: the layout in the file comment. Method: a typical home, then one too long to hold
    // the longest file name in a buffer.
    var paths: Paths = .{};
    try paths.init("/Users/ada", "0123456789abcdef");
    try std.testing.expectEqualStrings(
        "/Users/ada/Library/Application Support/zbx/vm/control.sock",
        paths.socket.slice(),
    );
    try std.testing.expectEqualStrings(
        "/Users/ada/Library/Application Support/zbx/vm/0123456789abcdef/Image",
        paths.kernel.slice(),
    );
    try std.testing.expectEqualStrings(
        "/Users/ada/Library/Application Support/zbx/vm-settings",
        paths.settings.slice(),
    );
    const long = "/" ++ @import("../test_util.zig").repeat('h', constants.vm_path_bytes_max);
    try std.testing.expectError(error.TooLong, paths.init(long, "0123456789abcdef"));
}
