//! The `zigbox_package` module: write `.deb` and `.rpm` packages and the apt and dnf repositories
//! around them, reproducibly, with the standard library alone.
pub const deb = @import("package/deb.zig");
pub const rpm = @import("package/rpm.zig");

test {
    _ = @import("package/model.zig");
    _ = @import("package/archive.zig");
    _ = @import("package/deb.zig");
    _ = @import("package/rpm.zig");
}
