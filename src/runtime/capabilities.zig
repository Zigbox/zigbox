//! The capabilities a container's processes keep, from `policy/capabilities.zon`, as the bit
//! mask the kernel's calls take, and the helpers the real host and the simulator share to apply
//! and to check it. The list is reviewed as a file; this module only turns names into numbers
//! (a name the kernel does not have is a build error) and says what "every other capability"
//! means.

const std = @import("std");
const assert = std.debug.assert;
const policy_file = @import("policy/capabilities.zon");

const linux = std.os.linux;

/// The highest capability number this build knows (`CAP_CHECKPOINT_RESTORE`). A newer kernel
/// has more; `last_cap` below is where the kernel's own count is read.
pub const last_known: u32 = linux.CAP.LAST_CAP;

/// The capabilities kept, one bit each, by capability number.
pub const keep_mask: u64 = blk: {
    var mask: u64 = 0;
    for (policy_file.keep) |entry| {
        if (!@hasDecl(linux.CAP, entry.name)) {
            @compileError("capabilities.zon: unknown " ++ entry.name);
        }
        mask |= @as(u64, 1) << @field(linux.CAP, entry.name);
    }
    break :blk mask;
};

/// The names, for the tests and the doc: in the order of the file.
pub const kept_count: usize = policy_file.keep.len;

/// Whether the capability is kept.
pub fn is_kept(capability: u32) bool {
    assert(capability < 64);
    return keep_mask & (@as(u64, 1) << @intCast(capability)) != 0;
}

comptime {
    assert(kept_count == @popCount(keep_mask)); // No capability is listed twice.
    // The two the brief names as dropped and the one that would defeat the rest.
    assert(!is_kept(linux.CAP.NET_RAW));
    assert(!is_kept(linux.CAP.MKNOD));
    assert(!is_kept(linux.CAP.SYS_ADMIN));
    assert(is_kept(linux.CAP.CHOWN));
}

const testing = std.testing;

test "the kept set is Docker's default without NET_RAW and MKNOD, and has no SYS_ADMIN" {
    // Goal: the list in the file is the one the brief asks for, by number, so a reviewer's edit
    // to the file that adds or drops a capability shows up here.
    const expected = [_]u32{
        linux.CAP.CHOWN,
        linux.CAP.DAC_OVERRIDE,
        linux.CAP.FOWNER,
        linux.CAP.FSETID,
        linux.CAP.KILL,
        linux.CAP.SETGID,
        linux.CAP.SETUID,
        linux.CAP.SETPCAP,
        linux.CAP.NET_BIND_SERVICE,
        linux.CAP.SYS_CHROOT,
        linux.CAP.AUDIT_WRITE,
        linux.CAP.SETFCAP,
    };
    var mask: u64 = 0;
    for (expected) |capability| mask |= @as(u64, 1) << @intCast(capability);
    try testing.expectEqual(mask, keep_mask);
    try testing.expectEqual(@as(usize, 12), kept_count);
    for (0..last_known + 1) |capability| {
        const want = std.mem.indexOfScalar(u32, &expected, @intCast(capability)) != null;
        try testing.expectEqual(want, is_kept(@intCast(capability)));
    }
}
