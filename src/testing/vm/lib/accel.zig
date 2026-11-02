//! The accelerator choice: KVM when /dev/kvm is usable, TCG (software emulation, about eight
//! times slower) only when asked for by name. Software emulation is never chosen silently.

const std = @import("std");
const Io = std.Io;

pub const Accel = enum { kvm, tcg };

pub const Error = error{ BadAccel, NoKvm };

/// Opens /dev/kvm read-write: usable means the accelerator will work.
pub fn kvm_usable(io: Io) bool {
    const options: Io.Dir.OpenFileOptions = .{ .mode = .read_write };
    const file = Io.Dir.openFileAbsolute(io, "/dev/kvm", options) catch return false;
    file.close(io);
    return true;
}

/// `requested` is `auto`, `kvm` or `tcg`; `auto` means KVM, and fails without it.
pub fn choose(requested: []const u8, kvm_available: bool) Error!Accel {
    if (std.mem.eql(u8, requested, "tcg")) return .tcg;
    if (std.mem.eql(u8, requested, "kvm")) return if (kvm_available) .kvm else error.NoKvm;
    if (!std.mem.eql(u8, requested, "auto")) return error.BadAccel;
    return if (kvm_available) .kvm else error.NoKvm;
}

test "accelerator choice: KVM when usable, TCG only when asked, otherwise a clear error" {
    // Goal: software emulation is never silently chosen, and KVM is never requested without it.
    try std.testing.expectEqual(Accel.kvm, try choose("auto", true));
    try std.testing.expectError(error.NoKvm, choose("auto", false));
    try std.testing.expectEqual(Accel.tcg, try choose("tcg", false));
    try std.testing.expectEqual(Accel.tcg, try choose("tcg", true));
    try std.testing.expectEqual(Accel.kvm, try choose("kvm", true));
    try std.testing.expectError(error.NoKvm, choose("kvm", false));
    try std.testing.expectError(error.BadAccel, choose("hvf", true));
}
