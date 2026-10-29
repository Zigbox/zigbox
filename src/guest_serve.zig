//! `zbx guest serve`: the Linux zbx's forwarding mode, run inside the macOS VM as the guest user
//! (never as root) and only there. It listens on a vsock port; per connection it forks a session
//! that reads the `start` frame (docs: forward_protocol.zig), runs `zbx <arguments>` as itself
//! with a pty if the Mac's stdin was a terminal and pipes if not, relays the streams, signals and
//! window size, and ends with an `exit` frame.
//!
//! It is daemon-less in the spec's sense: it lives exactly as long as the VM, started by the
//! guest's init, and keeps nothing between commands. It does not touch the container runtime: a
//! forwarded command is the same program a Linux user would type.
//!
//! When the connection closes before the command has ended (the Mac's `zbx` was killed, or the
//! Mac went away) the command's session gets SIGHUP, as a closed terminal gives it (M1), and
//! SIGKILL `vm_hangup_grace_ms` later.
//!
//! Raw system calls, no libc, no Host: this is a small program of its own, and what it relays is
//! tested through `forward_protocol.zig` and by running it.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const protocol = @import("forward_protocol.zig");

const program_path = "/usr/bin/zbx";
const default_path = "PATH=/usr/bin:/bin";

const tiocgwinsz: u32 = 0x5413;
const tiocswinsz: u32 = 0x5414;
const tiocsctty: u32 = 0x540e;
const tiocgptn: u32 = 0x80045430;
const tiocsptlck: u32 = 0x40045431;

const Winsize = extern struct { rows: u16, columns: u16, x_pixels: u16 = 0, y_pixels: u16 = 0 };

fn failed(result: usize) bool {
    return linux.errno(result) != .SUCCESS;
}

/// What the init tells this process: the user it runs as, through the environment it was given.
const Identity = struct {
    name: []const u8,
    home: []const u8,
};

pub fn main(arguments: []const []const u8, environ: std.process.Environ) u8 {
    assert(arguments.len >= 2);
    assert(std.mem.eql(u8, arguments[0], "guest"));
    if (!std.mem.eql(u8, arguments[1], "serve")) return 2;
    var ready_fd: i32 = -1;
    if (arguments.len == 4 and std.mem.eql(u8, arguments[2], "--ready-fd")) {
        ready_fd = std.fmt.parseInt(i32, arguments[3], 10) catch return 2;
    }
    const identity: Identity = .{
        .name = environ.getPosix("USER") orelse return 2,
        .home = environ.getPosix("HOME") orelse return 2,
    };
    const listener = listen_on_vsock() orelse return 2;
    ignore_child_exits();
    if (ready_fd >= 0) {
        _ = linux.write(ready_fd, "1", 1);
        _ = linux.close(ready_fd);
    }
    accept_forever(listener, &identity);
    return 0;
}

fn listen_on_vsock() ?i32 {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    const opened = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(opened)) return null;
    const listener: i32 = @intCast(opened);
    const address: linux.sockaddr.vm = .{
        .port = constants.vm_forward_port,
        .cid = 0xffff_ffff,
        .flags = 0,
    };
    if (failed(linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.vm)))) return null;
    if (failed(linux.listen(listener, 8))) return null;
    return listener;
}

/// Children of this process are not waited for: a session that ends leaves no zombie.
fn ignore_child_exits() void {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    const action: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = linux.SA.NOCLDWAIT,
    };
    _ = linux.sigaction(.CHLD, &action, null);
    const pipes: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &pipes, null);
}

/// One session per connection, for as long as the machine lives; the bound only keeps the loop
/// finite on paper.
fn accept_forever(listener: i32, identity: *const Identity) void {
    assert(@intFromPtr(identity) != 0);
    assert(@sizeOf(u64) == 8);
    const accepts_max: u64 = 1 << 40;
    var accepted: u64 = 0;
    while (accepted < accepts_max) : (accepted += 1) {
        const result = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (failed(result)) continue;
        const connection: i32 = @intCast(result);
        const child = linux.fork();
        if (failed(child)) {
            _ = linux.close(connection);
            continue;
        }
        if (child == 0) {
            _ = linux.close(listener);
            // The service reaps nothing by itself; a session waits for its own command.
            const default: linux.Sigaction = .{
                .handler = .{ .handler = linux.SIG.DFL },
                .mask = linux.sigemptyset(),
                .flags = 0,
            };
            _ = linux.sigaction(.CHLD, &default, null);
            const code = session(connection, identity);
            linux.exit_group(code);
        }
        _ = linux.close(connection);
    }
}

// ---- Reading and writing frames --------------------------------------------------------------

fn read_exact(descriptor: i32, buffer: []u8) bool {
    assert(buffer.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    var done: usize = 0;
    while (done < buffer.len) {
        const count = linux.read(descriptor, buffer[done..].ptr, buffer.len - done);
        if (linux.errno(count) == .INTR) continue;
        if (failed(count)) return false;
        if (count == 0) return false;
        done += count;
    }
    return true;
}

fn write_all(descriptor: i32, bytes: []const u8) bool {
    assert(bytes.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    var done: usize = 0;
    while (done < bytes.len) {
        const count = linux.write(descriptor, bytes[done..].ptr, bytes.len - done);
        if (linux.errno(count) == .INTR) continue;
        if (linux.errno(count) == .AGAIN) {
            wait_writable(descriptor);
            continue;
        }
        if (failed(count)) return false;
        done += count;
    }
    return true;
}

fn wait_writable(descriptor: i32) void {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    var entry = [1]linux.pollfd{.{ .fd = descriptor, .events = linux.POLL.OUT, .revents = 0 }};
    _ = linux.poll(&entry, 1, 100);
}

fn send_frame(connection: i32, kind: protocol.Kind, payload: []const u8) bool {
    assert(payload.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    var header: [constants.forward_header_bytes]u8 = undefined;
    protocol.render_header(&header, kind, @intCast(payload.len));
    if (!write_all(connection, &header)) return false;
    return write_all(connection, payload);
}

// ---- A session -------------------------------------------------------------------------------

/// Working memory of one session: the first frame's bytes and what is parsed out of it.
const Command = struct {
    payload: [constants.forward_start_bytes_max]u8 = undefined,
    arguments: [constants.args_count_max][]const u8 = undefined,
    environment: [constants.forward_env_count_max][]const u8 = undefined,
    /// NUL-terminated copies for execve.
    text: [constants.forward_start_bytes_max + 2048]u8 = undefined,
    argv: [constants.args_count_max + 2:null]?[*:0]const u8 = undefined,
    envp: [constants.forward_env_count_max + 8:null]?[*:0]const u8 = undefined,
    directory: [constants.path_bytes_max + 1:0]u8 = undefined,
    home: [constants.vm_home_bytes_max + 1:0]u8 = undefined,
};

var command_storage: Command = undefined;

/// A line on the console (the host keeps it in console.log) saying why a session ended early.
fn note(text: []const u8) void {
    assert(text.len < 200);
    const prefix = "zbx guest: ";
    _ = linux.write(2, prefix, prefix.len);
    _ = linux.write(2, text.ptr, text.len);
    _ = linux.write(2, "\n", 1);
}

fn end_early(why: []const u8) u8 {
    note(why);
    return 1;
}

fn session(connection: i32, identity: *const Identity) u8 {
    assert(@intFromPtr(identity) != 0);
    assert(@sizeOf(u64) == 8);
    const command = &command_storage;
    var header: [constants.forward_header_bytes]u8 = undefined;
    if (!read_exact(connection, &header)) return end_early("no first frame");
    const first = protocol.parse_header(&header) orelse return end_early("bad first header");
    if (first.kind != .start) return end_early("first frame is not start");
    if (!read_exact(connection, command.payload[0..first.length])) return end_early("short start");
    const start = protocol.parse_start(
        command.payload[0..first.length],
        &command.arguments,
        &command.environment,
    ) orelse return end_early("bad start frame");
    prepare_exec(command, &start, identity) orelse return end_early("cannot prepare");
    const child = launch(connection, command, &start) orelse return end_early("cannot launch");
    return relay(connection, &child);
}

const Child = struct {
    pid: i32,
    /// The pty master, or -1.
    master: i32,
    stdin_write: i32,
    stdout_read: i32,
    stderr_read: i32,
    pidfd: i32,
};

/// Builds the NUL-terminated argv and environment of the command in `command.text`.
fn prepare_exec(command: *Command, start: *const protocol.Start, identity: *const Identity) ?void {
    assert(@intFromPtr(command) != 0);
    assert(@intFromPtr(start) != 0);
    var used: usize = 0;
    var argc: usize = 0;
    command.argv[argc] = copy_string(&command.text, &used, "zbx") orelse return null;
    argc += 1;
    for (start.arguments) |argument| {
        command.argv[argc] = copy_string(&command.text, &used, argument) orelse return null;
        argc += 1;
    }
    command.argv[argc] = null;
    var envc: usize = 0;
    var line: [512]u8 = undefined;
    const base = [_][]const u8{
        default_path,
        std.fmt.bufPrint(&line, "HOME={s}", .{identity.home}) catch return null,
    };
    for (base) |entry| {
        command.envp[envc] = copy_string(&command.text, &used, entry) orelse return null;
        envc += 1;
    }
    var user: [128]u8 = undefined;
    const extras = [_][]const u8{
        std.fmt.bufPrint(&user, "USER={s}", .{identity.name}) catch return null,
        "ZBX_CGROUP_ROOT=" ++ constants.vm_cgroup_root,
    };
    for (extras) |entry| {
        command.envp[envc] = copy_string(&command.text, &used, entry) orelse return null;
        envc += 1;
    }
    for (start.environment) |entry| {
        const equals = std.mem.indexOfScalar(u8, entry, '=').?;
        if (!protocol.environment_name_allowed(entry[0..equals])) continue;
        if (envc + 1 >= command.envp.len) break;
        command.envp[envc] = copy_string(&command.text, &used, entry) orelse return null;
        envc += 1;
    }
    command.envp[envc] = null;
    // The directory: the Mac's, if the guest has it; the guest user's home if not.
    const wanted = start.working_directory;
    const fits = wanted.len > 0 and wanted.len < command.directory.len;
    const length = if (fits) wanted.len else @min(identity.home.len, command.directory.len - 1);
    const source = if (fits) wanted else identity.home[0..length];
    @memcpy(command.directory[0..length], source);
    command.directory[length] = 0;
    const home_length = @min(identity.home.len, command.home.len - 1);
    @memcpy(command.home[0..home_length], identity.home[0..home_length]);
    command.home[home_length] = 0;
}

fn copy_string(text: []u8, used: *usize, source: []const u8) ?[*:0]const u8 {
    assert(text.len < 1 << 31);
    assert(@intFromPtr(used) != 0);
    if (used.* + source.len + 1 > text.len) return null;
    @memcpy(text[used.*..][0..source.len], source);
    text[used.* + source.len] = 0;
    const result: [*:0]const u8 = @ptrCast(text[used.*..].ptr);
    used.* += source.len + 1;
    return result;
}

/// Forks the command with a pty or with pipes. In the parent, the ends it keeps.
fn launch(connection: i32, command: *Command, start: *const protocol.Start) ?Child {
    assert(@intFromPtr(command) != 0);
    assert(@intFromPtr(start) != 0);
    _ = connection;
    var child: Child = .{
        .pid = 0,
        .master = -1,
        .stdin_write = -1,
        .stdout_read = -1,
        .stderr_read = -1,
        .pidfd = -1,
    };
    var slave: i32 = -1;
    var pipes: [3][2]i32 = undefined;
    if (start.terminal) {
        child.master = open_pty(&slave, start.rows, start.columns) orelse return null;
    } else {
        for (&pipes) |*pair| {
            if (failed(linux.pipe2(pair, .{ .CLOEXEC = true }))) return null;
        }
    }
    const forked = linux.fork();
    if (failed(forked)) return null;
    if (forked == 0) run_child(command, start.terminal, slave, &pipes);
    child.pid = @intCast(forked);
    if (start.terminal) {
        _ = linux.close(slave);
    } else {
        _ = linux.close(pipes[0][0]);
        _ = linux.close(pipes[1][1]);
        _ = linux.close(pipes[2][1]);
        child.stdin_write = pipes[0][1];
        child.stdout_read = pipes[1][0];
        child.stderr_read = pipes[2][0];
    }
    const opened = linux.pidfd_open(child.pid, 0);
    if (!failed(opened)) child.pidfd = @intCast(opened);
    return child;
}

fn open_pty(slave_out: *i32, rows: u16, columns: u16) ?i32 {
    assert(@intFromPtr(slave_out) != 0);
    assert(rows <= std.math.maxInt(u16));
    const flags: linux.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
    const opened = linux.open("/dev/ptmx", flags, 0);
    if (failed(opened)) return null;
    const master: i32 = @intCast(opened);
    var unlock: u32 = 0;
    if (failed(linux.ioctl(master, tiocsptlck, @intFromPtr(&unlock)))) return null;
    var number: u32 = 0;
    if (failed(linux.ioctl(master, tiocgptn, @intFromPtr(&number)))) return null;
    var path: [32:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&path, "/dev/pts/{d}", .{number}) catch return null;
    const slave = linux.open(&path, flags, 0);
    if (failed(slave)) return null;
    slave_out.* = @intCast(slave);
    var size: Winsize = .{ .rows = rows, .columns = columns };
    _ = linux.ioctl(master, tiocswinsz, @intFromPtr(&size));
    return master;
}

/// In the forked child: its own session, the terminal or pipes as its standard streams, then
/// `zbx`. Never returns.
fn run_child(command: *Command, terminal: bool, slave: i32, pipes: *[3][2]i32) noreturn {
    assert(@intFromPtr(command) != 0);
    assert(@intFromPtr(pipes) != 0);
    _ = linux.setsid();
    if (terminal) {
        _ = linux.ioctl(slave, tiocsctty, 0);
        _ = linux.dup2(slave, 0);
        _ = linux.dup2(slave, 1);
        _ = linux.dup2(slave, 2);
    } else {
        _ = linux.dup2(pipes[0][0], 0);
        _ = linux.dup2(pipes[1][1], 1);
        _ = linux.dup2(pipes[2][1], 2);
    }
    if (failed(linux.chdir(&command.directory))) _ = linux.chdir(&command.home);
    _ = linux.execve(program_path, &command.argv, &command.envp);
    const message = "zbx guest: cannot run /usr/bin/zbx\n";
    _ = linux.write(2, message, message.len);
    linux.exit_group(127);
}

// ---- Relaying ------------------------------------------------------------------------------

/// The streams of one command and the connection, until the command has ended and been
/// reported, or the connection is gone.
fn relay(connection: i32, child: *const Child) u8 {
    assert(@intFromPtr(child) != 0);
    assert(@sizeOf(u64) == 8);
    var open_streams: u32 = 0;
    var streams = [2]i32{ child.stdout_read, child.stderr_read };
    if (child.master >= 0) streams = .{ child.master, -1 };
    for (streams) |stream| {
        if (stream >= 0) open_streams += 1;
    }
    var data: [constants.forward_data_bytes_max]u8 = undefined;
    var exited = false;
    var iterations: u32 = 0;
    const iterations_max: u32 = 1 << 30; // A command that lives long still makes progress.
    while (iterations < iterations_max) : (iterations += 1) {
        var entries: [4]linux.pollfd = undefined;
        entries[0] = .{ .fd = connection, .events = linux.POLL.IN, .revents = 0 };
        entries[1] = .{ .fd = child.pidfd, .events = linux.POLL.IN, .revents = 0 };
        entries[2] = .{ .fd = streams[0], .events = linux.POLL.IN, .revents = 0 };
        entries[3] = .{ .fd = streams[1], .events = linux.POLL.IN, .revents = 0 };
        if (exited) entries[1].fd = -1;
        _ = linux.poll(&entries, 4, -1);
        const kinds = [2]protocol.Kind{ .stdout, .stderr };
        for (0..2) |index| {
            const entry = &entries[2 + index];
            if (entry.revents == 0) continue;
            if (!forward_output(connection, entry.fd, kinds[index], &data)) {
                streams[index] = -1;
                open_streams -= 1;
            }
        }
        if (entries[1].revents != 0) exited = true;
        if (exited and open_streams == 0) return finish(connection, child);
        if (exited and drained(&streams)) return finish(connection, child);
        if (entries[0].revents != 0) {
            if (!handle_client(connection, child)) return hang_up(child);
        }
    }
    unreachable; // The loop returns from inside; its bound is only a guard.
}

/// True if no stream has data waiting (the command is gone, so nothing will add any).
fn drained(streams: *const [2]i32) bool {
    assert(@intFromPtr(streams) != 0);
    assert(@sizeOf(u64) == 8);
    for (streams) |stream| {
        if (stream < 0) continue;
        var entry = [1]linux.pollfd{.{ .fd = stream, .events = linux.POLL.IN, .revents = 0 }};
        _ = linux.poll(&entry, 1, 0);
        if (entry[0].revents & linux.POLL.IN != 0) return false;
    }
    return true;
}

/// Sends what `descriptor` has as one frame. False when the stream has ended.
fn forward_output(connection: i32, descriptor: i32, kind: protocol.Kind, data: []u8) bool {
    assert(data.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    const count = linux.read(descriptor, data.ptr, data.len);
    if (linux.errno(count) == .INTR or linux.errno(count) == .AGAIN) return true;
    if (failed(count)) return false; // A pty master says EIO when the slave is closed.
    if (count == 0) return false;
    _ = send_frame(connection, kind, data[0..count]); // A gone client shows as a hangup next.
    return true;
}

/// Reads one frame from the Mac and acts on it. False when the connection is gone or broken.
fn handle_client(connection: i32, child: *const Child) bool {
    assert(@intFromPtr(child) != 0);
    assert(@sizeOf(u64) == 8);
    var header_bytes: [constants.forward_header_bytes]u8 = undefined;
    if (!read_exact(connection, &header_bytes)) return false;
    const header = protocol.parse_header(&header_bytes) orelse return false;
    var payload: [constants.forward_data_bytes_max]u8 = undefined;
    if (header.kind == .start or header.length > payload.len) return false;
    if (!read_exact(connection, payload[0..header.length])) return false;
    switch (header.kind) {
        .stdin => write_to_command(child, payload[0..header.length]),
        .stdin_eof => end_of_input(child),
        .signal => _ = linux.kill(child.pid, @fromBackingInt(@intCast(payload[0]))),
        .window => {
            var size: Winsize = .{
                .rows = std.mem.readInt(u16, payload[0..2], .little),
                .columns = std.mem.readInt(u16, payload[2..4], .little),
            };
            if (child.master >= 0) _ = linux.ioctl(child.master, tiocswinsz, @intFromPtr(&size));
        },
        else => return false, // Output and exit frames only go the other way.
    }
    return true;
}

fn write_to_command(child: *const Child, bytes: []const u8) void {
    assert(@intFromPtr(child) != 0);
    assert(bytes.len < 1 << 31);
    const target = if (child.master >= 0) child.master else child.stdin_write;
    if (target >= 0) _ = write_all(target, bytes);
}

fn end_of_input(child: *const Child) void {
    assert(@intFromPtr(child) != 0);
    assert(@sizeOf(u64) == 8);
    if (child.master >= 0) {
        _ = write_all(child.master, "\x04"); // The terminal's end of file.
    } else if (child.stdin_write >= 0) {
        _ = linux.close(child.stdin_write);
    }
}

/// The command ended: say how, and leave.
fn finish(connection: i32, child: *const Child) u8 {
    assert(@intFromPtr(child) != 0);
    assert(@sizeOf(u64) == 8);
    var status: u32 = 0;
    var rusage: linux.rusage = undefined;
    _ = linux.wait4(child.pid, @ptrCast(&status), 0, &rusage);
    var payload: [2]u8 = undefined;
    const signaled = (status & 0x7f) != 0;
    const value: u8 = if (signaled) @intCast(status & 0x7f) else @intCast((status >> 8) & 0xff);
    protocol.render_exit(&payload, .{ .signaled = signaled, .value = value });
    _ = send_frame(connection, .exit, &payload);
    close_gracefully(connection);
    return 0;
}

/// Closes the sending side and reads what the Mac still sends until it closes its own, for a
/// moment at most. Closing a socket that holds unread data resets the connection, and the reset
/// can reach the Mac before it has read the exit frame (a command that ends at once, with the
/// Mac's end-of-input frame still in flight).
fn close_gracefully(connection: i32) void {
    assert(connection >= 0);
    assert(constants.vm_hangup_grace_ms > 0);
    _ = linux.shutdown(connection, linux.SHUT.WR);
    var scratch: [constants.forward_data_bytes_max]u8 = undefined;
    var entry = [1]linux.pollfd{.{ .fd = connection, .events = linux.POLL.IN, .revents = 0 }};
    var rounds: u32 = 0;
    while (rounds < 64) : (rounds += 1) {
        entry[0].revents = 0;
        if (linux.poll(&entry, 1, @intCast(constants.vm_hangup_grace_ms)) == 0) return;
        const count = linux.read(connection, &scratch, scratch.len);
        if (failed(count) or count == 0) return;
    }
}

/// The connection went before the command ended: the command's session gets SIGHUP, and SIGKILL
/// after a grace period if it is still there.
fn hang_up(child: *const Child) u8 {
    assert(@intFromPtr(child) != 0);
    assert(@sizeOf(u64) == 8);
    const group: i32 = -child.pid;
    _ = linux.kill(group, .HUP);
    if (child.pidfd >= 0) {
        var entry = [1]linux.pollfd{.{ .fd = child.pidfd, .events = linux.POLL.IN, .revents = 0 }};
        _ = linux.poll(&entry, 1, @intCast(constants.vm_hangup_grace_ms));
        if (entry[0].revents != 0) return 1;
    }
    _ = linux.kill(group, .KILL);
    return 1;
}
