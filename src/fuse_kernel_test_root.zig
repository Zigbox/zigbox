//! The root of the FUSE kernel test alone (`fuse/kernel_tests.zig`), built for the guest and run
//! there by `demo-s2-lazy`. It sits in `src/` so the test's imports of its siblings resolve.

test {
    _ = @import("fuse/kernel_tests.zig");
}
