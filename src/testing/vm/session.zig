//! Zigbox's side of the VM session (`zigbox_vm.Session`): the files a demo serves to its guest,
//! by the paths the demo scripts fetch them from, and the seed every demo boots with.

const std = @import("std");
const Io = std.Io;
const vm = @import("zigbox_vm");
const cloud_init = @import("cloud_init.zig");

pub const Session = vm.Session;
pub const Accel = vm.Accel;
pub const now_ms = vm.now_ms;
pub const clean_output = vm.session.clean_output;

pub const Files = struct {
    /// The `zbx` under test, served at /zbx.
    binary: []const u8,
    /// A rootfs tarball for the guest to unpack (the M1 demo), served at /rootfs.tar.gz; empty
    /// for none.
    rootfs: []const u8 = "",
    /// An older `zbx` for the upgrade test, served at /zbx-old; empty for none.
    old_binary: []const u8 = "",
    /// A CA certificate bundle for the guest to trust, served at /ca.crt; empty for none. A
    /// development aid for a host whose network inspects TLS (the guest's `zbx` then says E0504).
    ca_file: []const u8 = "",
    /// A raw disk image the guest sees as a second disk (`/dev/vdb`), kept between runs: the
    /// M4 demo's blob cache. Empty for none.
    cache_disk: []const u8 = "",
    /// demo-m0's experiment: provision a Delegate= drop-in for user managers.
    delegate_dropin: bool = false,
};

/// Renders the demo seed and starts the session with `files`. `session` must not move
/// afterwards (its server borrows from it).
pub fn start(
    session: *Session,
    init: std.process.Init,
    out: *Io.Writer,
    overlay: []const u8,
    accel: Accel,
    files: Files,
) !void {
    const arena = init.arena.allocator();
    const config = if (files.delegate_dropin)
        &cloud_init.config_with_delegate
    else
        &cloud_init.config;
    const user_data_buffer = try arena.alloc(u8, vm.limits.user_data_bytes_max);
    const meta_data_buffer = try arena.alloc(u8, vm.limits.meta_data_bytes_max);
    const routes = try arena.alloc(vm.Route, 4);
    var count: usize = 0;
    const named = [_]vm.Route{
        .{ .path = "/zbx", .body = files.binary },
        .{ .path = "/zbx-old", .body = files.old_binary },
        .{ .path = "/ca.crt", .body = files.ca_file },
        .{ .path = "/rootfs.tar.gz", .body = files.rootfs },
    };
    std.debug.assert(files.binary.len > 0);
    for (named) |route| {
        if (route.body.len == 0) continue;
        routes[count] = route;
        count += 1;
    }
    const disks = try arena.alloc([]const u8, 1);
    disks[0] = files.cache_disk;
    const disk_count: usize = if (files.cache_disk.len > 0) 1 else 0;
    try session.start(init, out, overlay, accel, .{
        .user_data = try vm.cloud_init.render_user_data(config, user_data_buffer),
        .meta_data = try vm.cloud_init.render_meta_data(config, meta_data_buffer),
        .files = routes[0..count],
        .disks = disks[0..disk_count],
    });
}
