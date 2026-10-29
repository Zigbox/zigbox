//! The guest's port agent (milestone M4b, slice 4): a process of `zbx guest serve`, running as the
//! Mac user, that does two things for the Mac. It tells the host which ports `pasta` publishes in
//! the guest, when that changes, and it carries a Mac connection to such a port. The protocol is
//! in `vm_ports.zig`.
//!
//! The news is event driven: a `pasta` process is found in /proc when the host asks (`scan`, which
//! it does when a command ended and while one runs), and each one found is watched through a
//! pidfd, which becomes readable the moment `pasta` ends, so a port closed by a stopped
//! container, a crash or a kill is reported at once, with no polling.
//!
//! Only the host (CID 2) is served. The agent's processes carry the name `zbx-ports`, which the
//! guest's init leaves out when it counts the processes that keep the machine awake.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const ports = @import("vm_ports.zig");
const vm_protocol = @import("vm_protocol.zig");

/// The process name init skips.
pub const process_name = "zbx-ports";

fn failed(result: usize) bool {
    return linux.errno(result) != .SUCCESS;
}

const pasta_max: u32 = constants.publish_count_max * 2;

const Watched = struct {
    pid: i32,
    pidfd: i32,
};

const State = struct {
    listener: i32,
    /// The host's connection that wants the news, or -1.
    control: i32 = -1,
    watched: [pasta_max]Watched = @splat(.{ .pid = 0, .pidfd = -1 }),
    published: ports.PortSet = .{},
};

var state: State = undefined;
var proc_buffer: [8192]u8 = undefined;
var cmdline_buffer: [8192]u8 = undefined;

/// Becomes the agent; returns only if it cannot start.
pub fn run() void {
    assert(process_name.len < 16); // The kernel keeps fifteen characters of a process name.
    _ = linux.prctl(@backingInt(linux.PR.SET_NAME), @intFromPtr(process_name.ptr), 0, 0, 0);
    const listener = listen() orelse return;
    assert(listener >= 0);
    state = .{ .listener = listener };
    // Children (the connections being carried) leave no zombies.
    const ignore: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = linux.SA.NOCLDWAIT,
    };
    _ = linux.sigaction(.CHLD, &ignore, null);
    const pipes: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &pipes, null);
    serve();
}

fn listen() ?i32 {
    assert(constants.vm_ports_port > 0);
    const opened = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(opened)) return null;
    const handle: i32 = @intCast(opened);
    const address: linux.sockaddr.vm = .{
        .port = constants.vm_ports_port,
        .cid = 0xffff_ffff,
        .flags = 0,
    };
    if (failed(linux.bind(handle, @ptrCast(&address), @sizeOf(linux.sockaddr.vm)))) return null;
    if (failed(linux.listen(handle, 16))) return null;
    assert(handle >= 0);
    return handle;
}

fn serve() void {
    assert(state.listener >= 0);
    const turns_max: u64 = 1 << 50; // A machine that lives long still makes progress.
    var turns: u64 = 0;
    while (turns < turns_max) : (turns += 1) {
        var entries: [2 + pasta_max]linux.pollfd = undefined;
        var count: usize = 0;
        entries[count] = .{ .fd = state.listener, .events = linux.POLL.IN, .revents = 0 };
        entries[count + 1] = .{ .fd = state.control, .events = linux.POLL.IN, .revents = 0 };
        count += 2;
        for (state.watched) |watched| {
            if (watched.pidfd < 0) continue;
            entries[count] = .{ .fd = watched.pidfd, .events = linux.POLL.IN, .revents = 0 };
            count += 1;
        }
        assert(count <= entries.len);
        _ = linux.poll(&entries, @intCast(count), -1);
        if (entries[0].revents != 0) accept_one();
        if (entries[1].revents != 0) read_control();
        var ended = false;
        for (entries[2..count]) |entry| {
            if (entry.revents != 0) ended = true;
        }
        if (ended) refresh(true);
    }
}

fn accept_one() void {
    assert(state.listener >= 0);
    var peer: linux.sockaddr.vm = undefined;
    var length: u32 = @sizeOf(linux.sockaddr.vm);
    const result = linux.accept4(state.listener, @ptrCast(&peer), &length, linux.SOCK.CLOEXEC);
    if (failed(result)) return;
    assert(length <= @sizeOf(linux.sockaddr.vm)); // The kernel fills no more than it was given.
    const connection: i32 = @intCast(result);
    assert(connection != state.control);
    if (!vm_protocol.from_host(peer.cid)) {
        _ = linux.close(connection);
        return;
    }
    var line: [32]u8 = undefined;
    const got = read_line(connection, &line) orelse return close_quietly(connection);
    if (std.mem.eql(u8, got, ports.watch_request)) {
        if (state.control >= 0) _ = linux.close(state.control);
        state.control = connection;
        refresh(false);
        send_ports(false);
        return;
    }
    const port = ports.parse_connect(got) orelse return close_quietly(connection);
    carry(connection, port);
}

fn close_quietly(descriptor: i32) void {
    assert(descriptor > 2); // Never the standard streams.
    assert(descriptor >= 0);
    _ = linux.close(descriptor);
}

/// A line of at most `buffer.len` bytes, read a byte at a time so that nothing after it is taken
/// (the bytes of the carried connection follow the request). Null after two seconds of silence.
fn read_line(descriptor: i32, buffer: []u8) ?[]const u8 {
    assert(buffer.len >= 16);
    var length: usize = 0;
    while (length < buffer.len) {
        var entry = [1]linux.pollfd{.{ .fd = descriptor, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&entry, 1, 2000) <= 0) return null;
        const got = linux.read(descriptor, buffer[length..].ptr, 1);
        if (failed(got) or got != 1) return null;
        length += 1;
        if (buffer[length - 1] == '\n') return buffer[0..length];
    }
    assert(length == buffer.len); // The loop ends only by filling the buffer.
    return null;
}

/// The host sent `scan`, or hung up.
fn read_control() void {
    assert(state.control != state.listener);
    assert(state.control >= 0);
    var line: [32]u8 = undefined;
    const got = read_line(state.control, &line) orelse {
        close_quietly(state.control);
        state.control = -1;
        return;
    };
    assert(got.len <= line.len);
    if (std.mem.eql(u8, got, ports.scan_request)) {
        refresh(false);
        send_ports(true);
    }
}

/// The set to the host: as news, or as the answer to a `scan`.
fn send_ports(answer: bool) void {
    assert(state.published.count <= constants.vm_ports_max);
    if (state.control < 0) return;
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const text = if (answer)
        ports.render_scanned(&buffer, &state.published)
    else
        ports.render_ports(&buffer, &state.published);
    assert(text.len > 0);
    const sent = linux.write(state.control, text.ptr, text.len);
    if (failed(sent) or sent != text.len) {
        close_quietly(state.control);
        state.control = -1;
    }
}

/// Looks at the processes: a `pasta` that is new gets a pidfd, one that ended is dropped, and the
/// published set is made again. With `announce`, a change is sent to the host.
fn refresh(announce: bool) void {
    assert(state.listener >= 0);
    var found: ports.PortSet = .{};
    var live: [pasta_max]i32 = @splat(0);
    var live_count: usize = 0;
    scan_processes(&found, &live, &live_count);
    assert(live_count <= pasta_max);
    for (&state.watched) |*watched| {
        if (watched.pidfd < 0) continue;
        if (contains(live[0..live_count], watched.pid)) continue;
        _ = linux.close(watched.pidfd);
        watched.* = .{ .pid = 0, .pidfd = -1 };
    }
    for (live[0..live_count]) |pid| watch(pid);
    const changed = !std.mem.eql(u16, found.slice(), state.published.slice());
    state.published = found;
    assert(state.published.count <= constants.vm_ports_max);
    if (announce and changed) send_ports(false);
}

fn contains(pids: []const i32, pid: i32) bool {
    for (pids) |member| {
        if (member == pid) return true;
    }
    return false;
}

fn watch(pid: i32) void {
    assert(pid > 0);
    assert(pid != 1); // Init is never watched.
    var free: ?*Watched = null;
    for (&state.watched) |*watched| {
        if (watched.pidfd >= 0 and watched.pid == pid) return;
        if (watched.pidfd < 0 and free == null) free = &watched.*;
    }
    const slot = free orelse return;
    assert(slot.pidfd < 0); // The slot found was a free one.
    const opened = linux.pidfd_open(pid, 0);
    if (failed(opened)) return;
    slot.* = .{ .pid = pid, .pidfd = @intCast(opened) };
}

fn scan_processes(found: *ports.PortSet, live: *[pasta_max]i32, live_count: *usize) void {
    assert(live_count.* <= live.len);
    assert(found.count <= constants.vm_ports_max);
    const opened = linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (failed(opened)) return;
    const handle: i32 = @intCast(opened);
    defer _ = linux.close(handle);
    while (true) {
        const bytes = linux.getdents64(handle, &proc_buffer, proc_buffer.len);
        if (failed(bytes) or bytes == 0) return;
        var at: usize = 0;
        while (at < bytes) {
            const reclen = std.mem.readInt(u16, proc_buffer[at + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(proc_buffer[at + 19 .. at + reclen], 0);
            at += reclen;
            assert(at <= bytes); // The kernel's records fill the buffer exactly.
            const pid = std.fmt.parseInt(i32, name, 10) catch continue;
            if (pid <= 1) continue;
            if (!is_pasta(name)) continue;
            if (live_count.* == live.len) continue;
            if (!add_command_line_ports(name, found)) continue;
            live[live_count.*] = pid;
            live_count.* += 1;
        }
    }
}

fn read_proc(pid_name: []const u8, file: []const u8, buffer: []u8) ?[]const u8 {
    assert(pid_name.len > 0);
    assert(file.len > 0);
    var path: [48:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&path, "/proc/{s}/{s}", .{ pid_name, file }) catch return null;
    const opened = linux.open(&path, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(opened)) return null;
    const handle: i32 = @intCast(opened);
    defer _ = linux.close(handle);
    const got = linux.read(handle, buffer.ptr, buffer.len);
    if (failed(got)) return null;
    assert(got <= buffer.len);
    return buffer[0..got];
}

fn is_pasta(pid_name: []const u8) bool {
    assert(pid_name.len > 0);
    var comm: [32]u8 = undefined;
    const name = read_proc(pid_name, "comm", &comm) orelse return false;
    assert(name.len <= comm.len);
    return std.mem.startsWith(u8, name, "pasta");
}

fn add_command_line_ports(pid_name: []const u8, found: *ports.PortSet) bool {
    assert(pid_name.len > 0);
    const cmdline = read_proc(pid_name, "cmdline", &cmdline_buffer) orelse return false;
    assert(cmdline.len <= cmdline_buffer.len);
    return ports.published_ports(cmdline, found);
}

// ---- Carrying a connection --------------------------------------------------------------------

/// Forks a process that connects to `port` in the guest and copies bytes until both sides end.
fn carry(connection: i32, port: u16) void {
    assert(connection >= 0);
    assert(port > 0);
    assert(connection != state.listener);
    const forked = linux.fork();
    if (failed(forked)) return close_quietly(connection);
    if (forked != 0) return close_quietly(connection);
    _ = linux.close(state.listener);
    if (state.control >= 0) _ = linux.close(state.control);
    for (state.watched) |watched| {
        if (watched.pidfd >= 0) _ = linux.close(watched.pidfd);
    }
    const default: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.DFL },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.CHLD, &default, null);
    const target = connect_local(port) orelse {
        _ = linux.write(connection, ports.connect_failed.ptr, ports.connect_failed.len);
        linux.exit_group(1);
    };
    _ = linux.write(connection, ports.connect_ok.ptr, ports.connect_ok.len);
    pump(connection, target);
    linux.exit_group(0);
}

fn connect_local(port: u16) ?i32 {
    assert(port > 0);
    const opened = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(opened)) return null;
    const handle: i32 = @intCast(opened);
    assert(handle >= 0);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (failed(linux.connect(handle, @ptrCast(&address), @sizeOf(linux.sockaddr.in)))) {
        _ = linux.close(handle);
        return null;
    }
    return handle;
}

/// Copies both ways until each side has ended; an end on one side is passed on as a half close.
fn pump(first: i32, second: i32) void {
    assert(first >= 0);
    assert(first != second);
    var buffer: [constants.vm_relay_buffer_bytes]u8 = undefined;
    const sides = [2]i32{ first, second };
    var open = [2]bool{ true, true };
    var turns: u64 = 0;
    const turns_max: u64 = 1 << 50; // A transfer that lasts still makes progress.
    while ((open[0] or open[1]) and turns < turns_max) : (turns += 1) {
        var entries: [2]linux.pollfd = undefined;
        for (0..2) |side| {
            entries[side] = .{
                .fd = if (open[side]) sides[side] else -1,
                .events = linux.POLL.IN,
                .revents = 0,
            };
        }
        _ = linux.poll(&entries, 2, -1);
        for (0..2) |side| {
            if (entries[side].revents == 0) continue;
            const got = linux.read(sides[side], &buffer, buffer.len);
            if (failed(got) or got == 0) {
                open[side] = false;
                _ = linux.shutdown(sides[1 - side], linux.SHUT.WR);
                continue;
            }
            if (!write_all(sides[1 - side], buffer[0..got])) return;
        }
    }
}

fn write_all(descriptor: i32, bytes: []const u8) bool {
    assert(descriptor >= 0);
    var done: usize = 0;
    while (done < bytes.len) {
        const sent = linux.write(descriptor, bytes[done..].ptr, bytes.len - done);
        if (failed(sent) or sent == 0) return false;
        done += sent;
    }
    assert(done == bytes.len);
    return true;
}
