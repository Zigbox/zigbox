//! demo-m10's workload: a dynamically linked program in the container image whose only
//! `DT_NEEDED` entry is `libzbxgpu.so.1`, as `nvidia-smi` needs the driver's libraries. The
//! library is not in the image and not on any default path; it is in the CDI mount, so the
//! loader finds it only through the cache the built-in `ldconfig` step wrote. It links no libc
//! (the target's `gnu` ABI only names the glibc loader as the interpreter).

const std = @import("std");
const linux = std.os.linux;

extern fn zbxgpu_answer() u32;

/// Prints `zbxgpu-probe: answer 42` when the loader resolved the library. A missing library
/// never reaches here: the loader itself refuses to start the program.
pub fn main() u8 {
    const value = zbxgpu_answer();
    std.debug.assert(value > 0);
    var buffer: [64]u8 = undefined;
    const format = "zbxgpu-probe: answer {d}\n";
    // The buffer holds the longest line: the prefix and ten digits of a u32.
    const text = std.fmt.bufPrint(&buffer, format, .{value}) catch unreachable;
    std.debug.assert(text.len < buffer.len);
    const written = linux.write(1, text.ptr, text.len);
    if (written != text.len) return 1;
    return 0;
}
