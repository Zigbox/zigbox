//! The lazy server's kernel side: opening `/dev/fuse`, mounting it, and the device the serving
//! threads read and write (`fuse/serve.zig`). Like `host_real.zig`, a place that may name
//! syscalls. `mount` runs in the container's single-threaded setup child, in its user and mount
//! namespaces; the device runs in the parent's serving threads.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const serve = @import("fuse/serve.zig");

pub const OpenError = error{
    /// No `/dev/fuse`, or not ours to open: the kernel has no FUSE, or the node is 0600.
    Unavailable,
};

/// Opens `/dev/fuse` for one connection, close-on-exec.
pub fn open_device() OpenError!linux.fd_t {
    const opened = linux.open("/dev/fuse", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.Unavailable;
    const fd: linux.fd_t = @intCast(opened);
    assert(fd >= 0);
    assert(fd <= std.math.maxInt(i32));
    return fd;
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
    const text = std.mem.printSentinel(buffer, options_format, .{fd}, 0) catch unreachable;
    assert(text.len < options_bytes);
    assert(std.mem.startsWith(u8, text, "fd="));
    return text;
}

/// Mounts the connection of `fd` on `target`, read-only, `nosuid` and `nodev`: `SUCCESS`, or the
/// errno of the refusal. The three go as mount flags: the FUSE option string takes none of them.
pub fn mount(fd: linux.fd_t, target: [:0]const u8) linux.E {
    assert(fd >= 0);
    assert(target.len > 0);
    var buffer: [options_bytes]u8 = undefined;
    const data = options(&buffer, fd);
    const flags: u32 = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV;
    const mounted = linux.mount("zbx-lazy", target, "fuse", flags, @intFromPtr(data.ptr));
    return linux.errno(mounted);
}

pub const DeviceError = error{
    /// The descriptor's flags could not be read or set (`fcntl`): not an open descriptor.
    Unusable,
};

/// The device over a descriptor the parent received, which this makes non-blocking: a read
/// waits at most `fuse_poll_ms` (`poll`), and a request another thread took first is `Again`,
/// never a read that blocks. `fd` lives at least as long as the returned value is used.
pub fn device(fd: *const linux.fd_t) DeviceError!serve.Device {
    assert(fd.* >= 0);
    const flags = linux.fcntl(fd.*, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return error.Unusable;
    const nonblock: u32 = @bitCast(linux.O{ .NONBLOCK = true });
    assert(nonblock != 0);
    const set = linux.fcntl(fd.*, linux.F.SETFL, flags | nonblock);
    if (linux.errno(set) != .SUCCESS) return error.Unusable;
    return .{ .context = @constCast(fd), .receive = receive, .send = send };
}

fn receive(context: *anyopaque, buffer: []u8) serve.ReceiveError!u32 {
    const fd: *const linux.fd_t = @ptrCast(@alignCast(context));
    assert(fd.* >= 0);
    assert(buffer.len >= constants.fuse_request_bytes);
    assert(buffer.len <= std.math.maxInt(u32));
    var poll_set = [1]linux.pollfd{.{ .fd = fd.*, .events = linux.POLL.IN }};
    const waited = linux.poll(&poll_set, 1, @intCast(constants.fuse_poll_ms));
    switch (linux.errno(waited)) {
        .SUCCESS => if (waited == 0) return error.Again,
        .INTR => return error.Again,
        else => return error.Ended,
    }
    // Ready to read, a hang-up, or an error: the read says which.
    const got = linux.read(fd.*, buffer.ptr, buffer.len);
    return switch (linux.errno(got)) {
        .SUCCESS => if (got == 0) error.Ended else @intCast(got),
        .INTR, .AGAIN, .NOENT => error.Again,
        else => error.Ended, // ENODEV: the connection is over.
    };
}

fn send(context: *anyopaque, bytes: []const u8) void {
    const fd: *const linux.fd_t = @ptrCast(@alignCast(context));
    assert(fd.* >= 0);
    assert(bytes.len >= 16);
    assert(bytes.len <= constants.fuse_reply_bytes);
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
