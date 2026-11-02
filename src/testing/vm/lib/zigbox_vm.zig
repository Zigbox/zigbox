//! Zigbox's VM test harness as a module: boot a throwaway Ubuntu 24.04 guest under QEMU (KVM, or
//! TCG when asked), provision it with cloud-init, run commands on its root console, copy files
//! in, and power it off. A dependent package gets it with
//! `b.dependency("zigbox", .{}).module("zigbox_vm")`; docs/vm-module.md shows a whole run.
//!
//! Nothing here knows about zbx or a milestone: what the guest is given (files, packages,
//! sysctls, its user and subuid range, linger, cgroup delegation) is the caller's `Config` and
//! `Seed`. Standard library only, no libc; the one external program is QEMU (`qemu-img` and
//! `qemu-system-x86_64`), and the guest's own `curl` for `copy_in`.

pub const accel = @import("accel.zig");
pub const cloud_init = @import("cloud_init.zig");
pub const http_server = @import("http_server.zig");
pub const image = @import("image.zig");
pub const limits = @import("limits.zig");
pub const session = @import("session.zig");

pub const Accel = accel.Accel;
pub const Config = cloud_init.Config;
pub const Pin = image.Pin;
pub const Route = session.Route;
pub const Seed = session.Seed;
pub const Session = session.Session;
pub const now_ms = session.now_ms;

test {
    _ = @import("accel.zig");
    _ = @import("cloud_init.zig");
    _ = @import("http_server.zig");
    _ = @import("image.zig");
    _ = @import("limits.zig");
    _ = @import("session.zig");
}
