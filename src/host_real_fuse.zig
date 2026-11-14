//! The lazy server's kernel side: opening `/dev/fuse`, mounting it, and the device the serving
//! threads read and write (`fuse/serve.zig`). Like `host_real.zig`, a place that may name
//! syscalls. `mount` runs in the container's single-threaded setup child, in its user and mount
//! namespaces; the device runs in the parent's serving threads.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const serve = @import("fuse/serve.zig");

pub const OpenError = error{
    /// No `/dev/fuse`, or not ours to open: the kernel has no FUSE, or the node is 0600.
    Unavailable,
};

/// Opens `/dev/fuse` for one connection, close-on-exec.
pub fn open_device() OpenError!linux.fd_t {
    const opened = linux.open("/dev/fuse", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.Unavailable;
    return @intCast(opened);
}

/// The mount options for descriptor `fd`: the root is a directory, owned by the namespace's root,
/// open to every user in it (the container's users read the image), with the kernel checking
/// modes (the server checks none).
pub const options_format = "fd={d},rootmode=40000,user_id=0,group_id=0,allow_other," ++
    "default_permissions";
/// Holds the options with a descriptor of ten digits and the terminator.
pub const options_bytes = options_format.len + 16;

pub fn options(buffer: *[options_bytes]u8, fd: linux.fd_t) [:0]const u8 {
    assert(fd >= 0);
    // The format and a ten-digit number fit by construction.
    return std.mem.printSentinel(buffer, options_format, .{fd}, 0) catch unreachable;
}

/// Mounts the connection of `fd` on `target`, read-only, `nosuid` and `nodev`: `SUCCESS`, or the
/// errno of the refusal. The three go as mount flags: the FUSE option string takes none of them.
pub fn mount(fd: linux.fd_t, target: [:0]const u8) linux.E {
    var buffer: [options_bytes]u8 = undefined;
    const data = options(&buffer, fd);
    const flags: u32 = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV;
    const mounted = linux.mount("zbx-lazy", target, "fuse", flags, @intFromPtr(data.ptr));
    return linux.errno(mounted);
}

/// The device over a descriptor the parent received. `fd` lives at least as long as the
/// returned value is used.
pub fn device(fd: *const linux.fd_t) serve.Device {
    return .{ .context = @constCast(fd), .receive = receive, .send = send };
}

fn receive(context: *anyopaque, buffer: []u8) serve.ReceiveError!u32 {
    const fd: *const linux.fd_t = @ptrCast(@alignCast(context));
    assert(buffer.len <= std.math.maxInt(u32));
    const got = linux.read(fd.*, buffer.ptr, buffer.len);
    return switch (linux.errno(got)) {
        .SUCCESS => @intCast(got),
        .INTR, .AGAIN, .NOENT => error.Again,
        else => error.Ended, // ENODEV: the connection is over.
    };
}

fn send(context: *anyopaque, bytes: []const u8) void {
    const fd: *const linux.fd_t = @ptrCast(@alignCast(context));
    assert(bytes.len >= 16);
    // One write is one reply: the kernel takes it whole or not at all. `ENOENT` is a request
    // the kernel took back (interrupted), `ENODEV` an ended connection: nobody waits for either.
    _ = linux.write(fd.*, bytes.ptr, bytes.len);
}

test "the mount options name the descriptor and the namespace's root" {
    var buffer: [options_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "fd=2147483647,rootmode=40000,user_id=0,group_id=0,allow_other,default_permissions",
        options(&buffer, std.math.maxInt(i32)),
    );
}
