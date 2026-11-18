//! `numa-probe`: demo-m2b's step 6 helper, copied into the Alpine rootfs as `/numa-probe` and run
//! inside `zbx run`. It makes each of the six memory-policy calls once, with arguments the kernel
//! accepts for an unprivileged process, and prints one line per call: `<call> ok`, or
//! `<call> E<NAME>` with the errno's name. Under zbx's seccomp allowlist the four policy calls
//! print `ok`, and `move_pages` and `migrate_pages`, which stay out, print `EPERM` (the filter's
//! answer). Static, no libc, x86_64 like the test VM's guest; exits 0 whatever the calls say, so
//! the harness judges the lines (checks_m2b.zig), not the status.

const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

/// `MPOL_DEFAULT` and `MPOL_BIND` (include/uapi/linux/mempolicy.h).
const mpol_default: usize = 0;
const mpol_bind: usize = 2;
/// The bits of a node mask the calls are told about: one word.
const mask_bits: usize = @bitSizeOf(usize);
/// Node 0 alone, which every machine has.
const node_zero: usize = 1;
/// One page, the range `mbind` and `set_mempolicy_home_node` act on.
const page_bytes: usize = std.heap.page_size_min;
/// The longest line this program prints: a call's name, a space, an errno name and a newline.
const line_bytes_max: usize = 64;

const Call = enum {
    mbind,
    set_mempolicy,
    set_mempolicy_home_node,
    get_mempolicy,
    move_pages,
    migrate_pages,
};

pub fn main() u8 {
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const protection: linux.PROT = .{ .READ = true, .WRITE = true };
    const mapped = linux.mmap(null, page_bytes, protection, flags, -1, 0);
    if (linux.errno(mapped) != .SUCCESS) {
        say("mmap", linux.errno(mapped));
        return 1;
    }
    assert(mapped % page_bytes == 0);
    inline for (comptime std.enums.values(Call)) |call| {
        say(@tagName(call), linux.errno(make(call, mapped)));
    }
    return 0;
}

/// Makes `call` once: the page bound to node 0 (`set_mempolicy_home_node` needs a bound range),
/// the process's default policy, a query, and the two page movers from node 0 to node 0 (no
/// pages), which an allowed call answers with success.
fn make(comptime call: Call, page: usize) usize {
    assert(page != 0);
    const mask: usize = node_zero;
    const at = @intFromPtr(&mask);
    var mode: i32 = -1;
    var status: i32 = 0;
    return switch (call) {
        .mbind => linux.syscall6(.mbind, page, page_bytes, mpol_bind, at, mask_bits, 0),
        .set_mempolicy => linux.syscall3(.set_mempolicy, mpol_default, 0, 0),
        .set_mempolicy_home_node => linux.syscall4(
            .set_mempolicy_home_node,
            page,
            page_bytes,
            0,
            0,
        ),
        .get_mempolicy => linux.syscall5(.get_mempolicy, @intFromPtr(&mode), 0, 0, 0, 0),
        .move_pages => linux.syscall6(.move_pages, 0, 0, 0, 0, @intFromPtr(&status), 0),
        .migrate_pages => linux.syscall4(.migrate_pages, 0, mask_bits, at, at),
    };
}

fn say(name: []const u8, result: linux.E) void {
    assert(name.len > 0);
    var buffer: [line_bytes_max]u8 = undefined;
    const errno = if (result == .SUCCESS) "" else std.enums.tagName(linux.E, result) orelse "?";
    const said = if (result == .SUCCESS) "ok" else "E";
    const format = "{s} {s}{s}\n";
    // The longest call name and the longest errno name fit in `line_bytes_max`.
    const line = std.fmt.bufPrint(&buffer, format, .{ name, said, errno }) catch unreachable;
    assert(line.len <= line_bytes_max);
    _ = linux.write(1, line.ptr, line.len);
}
