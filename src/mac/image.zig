//! The VM image carried inside this binary (the kernel and the initramfs, embedded by the build)
//! and its unpacking into the user's Library. The version is a digest over both, so a binary
//! cannot carry a version that is not its own image, and an upgrade is a file swap: a new binary
//! unpacks a new directory beside the old one.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const files = @import("files.zig");
const protocol = @import("../vm_protocol.zig");
const paths_mod = @import("paths.zig");

pub const kernel_bytes = @embedFile("vm_kernel");
pub const initramfs_bytes = @embedFile("vm_initramfs");
pub const version = @embedFile("vm_image_version");

comptime {
    assert(version.len == constants.vm_image_version_bytes);
    assert(kernel_bytes.len > 0);
    assert(initramfs_bytes.len > 0);
    assert(kernel_bytes.len <= constants.vm_image_file_bytes_max);
    assert(initramfs_bytes.len <= constants.vm_image_file_bytes_max);
}

/// Makes sure the image's directory holds exactly this binary's kernel and initramfs: a missing,
/// short or damaged file (an interrupted unpack, a changed byte) is written again.
pub fn ensure(paths: *const paths_mod.Paths) files.Error!void {
    assert(protocol.is_version(version));
    try files.make_directories(paths.image_dir.slice());
    try ensure_file(paths.kernel.slice(), kernel_bytes);
    try ensure_file(paths.initramfs.slice(), initramfs_bytes);
}

fn ensure_file(path: []const u8, expected: []const u8) files.Error!void {
    assert(expected.len > 0);
    if (matches(path, expected)) return;
    try files.write_file_atomically(path, expected, 0o600);
    assert(matches(path, expected));
}

/// True if the file at `path` holds exactly `expected`, compared in chunks.
pub fn matches(path: []const u8, expected: []const u8) bool {
    var chunk: [64 * 1024]u8 = undefined;
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = files.terminate(&terminated, path) catch return false;
    const descriptor = std.c.open(text.ptr, .{ .ACCMODE = .RDONLY });
    if (descriptor < 0) return false;
    defer files.close(descriptor);
    var offset: usize = 0;
    while (offset < expected.len) {
        const wanted = @min(chunk.len, expected.len - offset);
        const count = std.c.read(descriptor, &chunk, wanted);
        if (count <= 0) return false;
        const got: usize = @intCast(count);
        if (!std.mem.eql(u8, chunk[0..got], expected[offset..][0..got])) return false;
        offset += got;
    }
    // Nothing more: a file longer than the image is not the image.
    const extra = std.c.read(descriptor, &chunk, 1);
    return extra == 0;
}

test "matches is true only for a file that holds exactly the expected bytes" {
    // Goal: the check that decides whether the unpacked image is rewritten. Method: a file
    // that is equal, one byte changed, shorter, longer and missing.
    var directory: [96]u8 = undefined;
    const base = try std.fmt.bufPrint(&directory, "/tmp/zbx-image-test-{d}", .{files.now_ms()});
    try files.make_directories(base);
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/file", .{base});
    const expected = "kernel bytes, long enough to differ";
    try files.write_file_atomically(path, expected, 0o600);
    try std.testing.expect(matches(path, expected));
    try std.testing.expect(!matches(path, "kernel bytes, long enough to differ!"));
    try std.testing.expect(!matches(path, "kernel bytes"));
    try files.write_file_atomically(path, "kernel bytes, long enough to diffeR", 0o600);
    try std.testing.expect(!matches(path, expected));
    try files.write_file_atomically(path, expected ++ "x", 0o600);
    try std.testing.expect(!matches(path, expected));
    try std.testing.expect(!matches("/nonexistent/zbx-image", expected));
}
