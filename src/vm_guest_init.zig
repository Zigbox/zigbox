//! The VM's PID 1: a small static Linux program, no libc. It mounts what a Linux userland
//! expects, tells the console it is up, and answers the macOS `zbx` on a vsock port: `hello`
//! with the image version, `shutdown` with a clean power-off. Later slices start the Linux
//! `zbx` from here; this slice only proves the guest is up and which image it is.
//!
//! PID 1 must never return: the kernel panics if it does. Every failure here is written to the
//! console (the host keeps it in console.log) and ends in a power-off, which the host sees as
//! a stopped machine.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const protocol = @import("vm_protocol.zig");

pub const panic = std.debug.FullPanic(panic_handler);

fn panic_handler(message: []const u8, first_trace_addr: ?usize) noreturn {
    assert(message.len < constants.output_bytes_max);
    _ = first_trace_addr;
    log("zbx-init: panic: ", message);
    power_off();
}

const version_path = "/etc/zbx-image-version";
const accepts_max: u32 = 1 << 20;
const backlog: u32 = 4;
const address_any: u32 = 0xffff_ffff;

const Mount = struct {
    source: [:0]const u8,
    target: [:0]const u8,
    kind: [:0]const u8,
};

/// In order: /proc and /sys first, because the cgroup tree is below /sys.
const mounts = [_]Mount{
    .{ .source = "proc", .target = "/proc", .kind = "proc" },
    .{ .source = "sysfs", .target = "/sys", .kind = "sysfs" },
    .{ .source = "devtmpfs", .target = "/dev", .kind = "devtmpfs" },
    .{ .source = "tmpfs", .target = "/run", .kind = "tmpfs" },
    .{ .source = "tmpfs", .target = "/tmp", .kind = "tmpfs" },
    .{ .source = "cgroup2", .target = "/sys/fs/cgroup", .kind = "cgroup2" },
};

pub fn main() void {
    assert(mounts.len > 0);
    assert(constants.vm_guest_port > 0);
    log("zbx-init: starting", "");
    for (mounts) |mount| mount_one(&mount);
    var version_buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const version = read_version(&version_buffer);
    log("zbx-init: image ", version);
    const listener = listen_on_vsock();
    log("zbx-init: listening on vsock", "");
    serve(listener, version);
    power_off();
}

fn log(prefix: []const u8, detail: []const u8) void {
    assert(prefix.len < 256);
    assert(prefix.len > 0);
    const newline = "\n";
    _ = linux.write(2, prefix.ptr, prefix.len);
    if (detail.len > 0) _ = linux.write(2, detail.ptr, detail.len);
    _ = linux.write(2, newline, newline.len);
}

fn power_off() noreturn {
    assert(version_path.len > 0);
    linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    // The kernel did not power off; PID 1 may not return, so wait for the host to stop us.
    while (true) _ = linux.pause();
}

fn mount_one(mount: *const Mount) void {
    assert(mount.source.len > 0);
    assert(mount.kind.len > 0);
    assert(mount.target.len > 1);
    assert(mount.target[0] == '/');
    // The directory may exist in the initramfs already; EEXIST is the normal answer.
    _ = linux.mkdir(mount.target, 0o755);
    const result = linux.mount(mount.source, mount.target, mount.kind, 0, 0);
    if (linux.errno(result) != .SUCCESS) log("zbx-init: could not mount ", mount.target);
}

/// The image version from the initramfs; a bad file is fatal, because a guest that does not know
/// which image it is cannot be told from another by the host.
fn read_version(buffer: *[constants.vm_line_bytes_max]u8) []const u8 {
    assert(buffer.len == constants.vm_line_bytes_max);
    assert(version_path.len > 0);
    const opened = linux.open(version_path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(opened) != .SUCCESS) {
        log("zbx-init: no ", version_path);
        power_off();
    }
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    const count = linux.read(descriptor, buffer, buffer.len);
    if (linux.errno(count) != .SUCCESS) power_off();
    const text = std.mem.trimEnd(u8, buffer[0..count], "\n");
    if (!protocol.is_version(text)) {
        log("zbx-init: bad image version in ", version_path);
        power_off();
    }
    return text;
}

fn listen_on_vsock() i32 {
    assert(backlog > 0);
    assert(address_any == 0xffff_ffff);
    const opened = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM, 0);
    if (linux.errno(opened) != .SUCCESS) {
        log("zbx-init: no vsock (is the kernel built with it?)", "");
        power_off();
    }
    const listener: i32 = @intCast(opened);
    const address: linux.sockaddr.vm = .{
        .port = constants.vm_guest_port,
        .cid = address_any,
        .flags = 0,
    };
    const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.vm));
    if (linux.errno(bound) != .SUCCESS) power_off();
    if (linux.errno(linux.listen(listener, backlog)) != .SUCCESS) power_off();
    return listener;
}

/// Answers one connection at a time, for as long as the machine lives. The bound is a count of
/// connections no real host reaches; it only keeps the loop finite on paper.
fn serve(listener: i32, version: []const u8) void {
    assert(listener >= 0);
    assert(accepts_max > 0);
    assert(listener >= 0);
    assert(protocol.is_version(version));
    var accepted: u32 = 0;
    while (accepted < accepts_max) : (accepted += 1) {
        const result = linux.accept(listener, null, null);
        if (linux.errno(result) != .SUCCESS) continue;
        const connection: i32 = @intCast(result);
        defer _ = linux.close(connection);
        if (answer(connection, version) == .shutdown) return;
    }
}

const Outcome = enum { go_on, shutdown };

fn answer(connection: i32, version: []const u8) Outcome {
    assert(version.len == constants.vm_image_version_bytes);
    assert(connection >= 0);
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const length = read_line(connection, &line) orelse return .go_on;
    const request = line[0..length];
    if (std.mem.eql(u8, request, protocol.hello_request)) {
        var reply: [constants.vm_line_bytes_max]u8 = undefined;
        const text = protocol.render_hello_reply(&reply, version);
        _ = linux.write(connection, text.ptr, text.len);
        return .go_on;
    }
    if (std.mem.eql(u8, request, protocol.shutdown_request)) {
        _ = linux.write(connection, protocol.shutdown_reply, protocol.shutdown_reply.len);
        log("zbx-init: shutting down", "");
        return .shutdown;
    }
    return .go_on;
}

/// Reads up to and including the first newline; null if the line is too long or the peer left.
fn read_line(connection: i32, buffer: *[constants.vm_line_bytes_max]u8) ?usize {
    assert(buffer.len == constants.vm_line_bytes_max);
    assert(connection >= 0);
    var length: usize = 0;
    while (length < buffer.len) {
        const count = linux.read(connection, buffer[length..].ptr, 1);
        if (linux.errno(count) != .SUCCESS) return null;
        if (count == 0) return null;
        length += 1;
        if (buffer[length - 1] == '\n') return length;
    }
    return null;
}
