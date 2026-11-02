//! Zigbox's images for the demo VM: the module's pinned Ubuntu 24.04 base
//! (`zigbox_vm.image.ubuntu_noble`) and the Alpine rootfs pin (`alpine.zon`).

const std = @import("std");
const vm = @import("zigbox_vm");

pub const Pin = vm.Pin;
pub const hex_len = vm.image.hex_len;
pub const ensure_pin = vm.image.ensure_pin;
pub const make_overlay = vm.image.make_overlay;
pub const ensure_cache_disk = vm.image.ensure_raw_disk;

/// The base image of the VM.
pub fn ensure(init: std.process.Init, cache_dir: []const u8, log: *std.Io.Writer) ![]const u8 {
    return ensure_pin(init, cache_dir, log, vm.image.ubuntu_noble);
}

test "the pinned Alpine rootfs is a dated 3.20 release with a SHA-256" {
    // Goal: the rootfs pin cannot become a moving target ("latest-stable") or a bad hash.
    const alpine = @import("alpine.zon");
    try std.testing.expect(std.mem.startsWith(u8, alpine.url, "https://"));
    try std.testing.expect(std.mem.indexOf(u8, alpine.url, "/v3.20/releases/x86_64/") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine.file_name, "minirootfs-3.20.") != null);
    try std.testing.expect(std.mem.endsWith(u8, alpine.url, alpine.file_name));
    try std.testing.expectEqual(@as(usize, hex_len), alpine.sha256.len);
    for (alpine.sha256) |byte| {
        try std.testing.expect(std.ascii.isHex(byte));
        try std.testing.expect(!std.ascii.isUpper(byte));
    }
}
