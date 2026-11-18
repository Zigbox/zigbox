//! demo-s2's guest tool, static x86_64 with no libc, embedded in the harness and served to the
//! guest:
//!
//! - `tool gen <root> v1|v2` writes the fixture's files (`fixture_s2.zig`) into the unpacked
//!   Alpine rootfs at `<root>`. Generating 3 GiB in the guest costs seconds; sending it from the
//!   runner would cost minutes over QEMU's user network.
//! - `tool forward <port> <registry port>` listens on 127.0.0.1:<port> and relays each
//!   connection to the runner's registry (10.0.2.2:<registry port>). zbx speaks plain HTTP only
//!   to a loopback registry, so the guest's zbx reaches the runner's through this relay.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const fixture = @import("fixture_s2.zig");

const relays_max = 64;
const relay_buffer_bytes = 64 * 1024;
const host_address: u32 = 0x0a000202; // 10.0.2.2, the runner as QEMU's user network shows it.

pub fn main(init: std.process.Init) u8 {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch return usage();
    if (args.len == 4 and std.mem.eql(u8, args[1], "gen")) {
        const variant: fixture.Variant = if (std.mem.eql(u8, args[3], "v2")) .v2 else .v1;
        generate(args[2], variant) catch |err| return fail("gen", @errorName(err));
        return 0;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "forward")) {
        const port = std.fmt.parseInt(u16, args[2], 10) catch return usage();
        const target = std.fmt.parseInt(u16, args[3], 10) catch return usage();
        forward(port, target) catch |err| return fail("forward", @errorName(err));
        return 0;
    }
    return usage();
}

fn usage() u8 {
    say("usage: tool gen <root> v1|v2 | tool forward <port> <registry port>\n");
    return 2;
}

fn fail(what: []const u8, why: []const u8) u8 {
    var buffer: [128]u8 = undefined;
    say(std.fmt.bufPrint(&buffer, "tool {s}: {s}\n", .{ what, why }) catch "tool: failed\n");
    return 1;
}

fn say(text: []const u8) void {
    _ = linux.write(2, text.ptr, text.len);
}

fn generate(root_path: [:0]const u8, variant: fixture.Variant) !void {
    const open_flags: linux.O = .{ .DIRECTORY = true, .CLOEXEC = true };
    const opened = linux.openat(linux.AT.FDCWD, root_path, open_flags, 0);
    if (linux.errno(opened) != .SUCCESS) return error.RootNotFound;
    const root: i32 = @intCast(opened);
    defer _ = linux.close(root);
    var buffer: [fixture.path_bytes_max]u8 = undefined;
    var directory: u32 = 0;
    while (directory < fixture.directory_count) : (directory += 1) {
        var path: [fixture.path_bytes_max + 1:0]u8 = undefined;
        const name = fixture.directory_at(directory, &buffer);
        const relative = try std.mem.printSentinel(&path, "{s}", .{name[1..]}, 0);
        const made = linux.mkdirat(root, relative, 0o755);
        if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) return error.MkdirFailed;
    }
    var index: u32 = 0;
    while (index < fixture.file_count) : (index += 1) {
        try write_file(root, fixture.file_at(index, variant));
    }
}

fn write_file(root: i32, file: fixture.File) !void {
    assert(file.size > 0);
    var path: [fixture.path_bytes_max + 1:0]u8 = undefined;
    const relative = try std.mem.printSentinel(&path, "{s}", .{file.path()[1..]}, 0);
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true };
    const opened = linux.openat(root, relative, flags, file.mode);
    if (linux.errno(opened) != .SUCCESS) return error.CreateFailed;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    _ = linux.fchmod(fd, file.mode); // Past the umask.
    switch (file.kind) {
        .config => try write_all(fd, fixture.config_text),
        .start => try write_all(fd, fixture.start_text),
        .stream => {
            var stream: fixture.Stream = .init(file.stream, file.size);
            var block: [fixture.block_bytes]u8 = undefined;
            var written: u64 = 0;
            while (true) {
                const bytes = stream.next(&block);
                if (bytes.len == 0) break;
                try write_all(fd, bytes);
                written += bytes.len;
            }
            assert(written == file.size);
        },
    }
}

fn write_all(fd: i32, bytes: []const u8) !void {
    assert(fd >= 0);
    var at: usize = 0;
    while (at < bytes.len) {
        const written = linux.write(fd, bytes[at..].ptr, bytes.len - at);
        if (linux.errno(written) != .SUCCESS or written == 0) return error.WriteFailed;
        at += written;
    }
}

var relays: std.atomic.Value(u32) = .init(0);

fn forward(port: u16, target: u16) !void {
    assert(port != 0);
    const created = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
    const listener: i32 = @intCast(created);
    const one: u32 = 1;
    _ = linux.setsockopt(listener, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), 4);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(bound) != .SUCCESS) return error.BindFailed;
    if (linux.errno(linux.listen(listener, 64)) != .SUCCESS) return error.ListenFailed;
    while (true) {
        const accepted = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(accepted) != .SUCCESS) continue;
        const client: i32 = @intCast(accepted);
        if (relays.load(.acquire) >= relays_max) {
            _ = linux.close(client); // Over the bound: the client sees a dropped connection.
            continue;
        }
        _ = relays.fetchAdd(1, .acq_rel);
        const spawn: std.Thread.SpawnConfig = .{ .stack_size = 1024 * 1024 };
        const thread = std.Thread.spawn(spawn, relay, .{ client, target }) catch {
            _ = relays.fetchSub(1, .acq_rel);
            _ = linux.close(client);
            continue;
        };
        thread.detach();
    }
}

fn relay(client: i32, target: u16) void {
    defer _ = relays.fetchSub(1, .acq_rel);
    defer _ = linux.close(client);
    const created = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(created) != .SUCCESS) return;
    const upstream: i32 = @intCast(created);
    defer _ = linux.close(upstream);
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, target),
        .addr = std.mem.nativeToBig(u32, host_address),
    };
    const connected = linux.connect(upstream, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(connected) != .SUCCESS) return;
    pump(client, upstream);
}

/// Copies both ways until both directions have ended; a side's end is passed on as a shutdown
/// of the other side's write, and an error on either ends both.
fn pump(client: i32, upstream: i32) void {
    assert(client != upstream);
    var open = [2]bool{ true, true }; // client -> upstream, upstream -> client
    var buffer: [relay_buffer_bytes]u8 = undefined;
    while (open[0] or open[1]) {
        var entries = [2]linux.pollfd{
            .{ .fd = if (open[0]) client else -1, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (open[1]) upstream else -1, .events = linux.POLL.IN, .revents = 0 },
        };
        const ready = linux.poll(&entries, 2, -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) return;
        for (0..2) |direction| {
            if (entries[direction].revents == 0) continue;
            const from = if (direction == 0) client else upstream;
            const to = if (direction == 0) upstream else client;
            const got = linux.recvfrom(from, &buffer, buffer.len, 0, null, null);
            if (linux.errno(got) != .SUCCESS) return;
            if (got == 0) {
                open[direction] = false;
                _ = linux.shutdown(to, linux.SHUT.WR);
                continue;
            }
            if (!send_all(to, buffer[0..got])) return;
        }
    }
}

fn send_all(socket: i32, bytes: []const u8) bool {
    assert(bytes.len > 0);
    var at: usize = 0;
    while (at < bytes.len) {
        const rest = bytes[at..];
        const sent = linux.sendto(socket, rest.ptr, rest.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(sent) != .SUCCESS) return false;
        at += sent;
    }
    return true;
}
