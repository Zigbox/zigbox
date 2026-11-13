//! The fake vendor's driver library for demo-m10: a shared object whose soname is
//! `libzbxgpu.so.1`, like a real driver library, put on the host in `/opt/zbx-gpu-lib`. It links
//! no libc, so it loads under any glibc dynamic loader of the guest's architecture.

const std = @import("std");

/// The value the probe prints, so the demo can tell this library's code ran.
pub const answer: u32 = 42;

/// The probe calls this through the dynamic loader. It returns a constant on purpose: the
/// demo checks that the loader found the library through `/etc/ld.so.cache`, not what it computes.
export fn zbxgpu_answer() u32 {
    comptime std.debug.assert(answer > 0);
    comptime std.debug.assert(answer < 1000);
    return answer;
}
