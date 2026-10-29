//! Forwarding a command into the VM. The macOS `zbx` is a forwarder: it makes sure the machine
//! runs (lazily booting it), gets a vsock connection to `zbx guest serve` through the host
//! process (the descriptor is handed over the control socket, so the data never passes through
//! the host), sends the command line, working directory, the environment that matters and the
//! terminal's size, and then relays standard input, output and error, the signals and window
//! changes, until the guest says how the command ended. Its exit code is the command's.
//!
//! When this process dies, by any signal, the connection closes and the guest treats that as a
//! hangup of the command. When the connection dies first, this process says so (E1009) and ends
//! with 125 if the command was a `run`.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const commands = @import("commands.zig");
const constants = @import("../constants.zig");
const control = @import("control.zig");
const diagnose = @import("diagnose.zig");
const files = @import("files.zig");
const protocol = @import("../forward_protocol.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const Error = error{Failed};

extern "c" fn ioctl(descriptor: i32, request: c_ulong, ...) c_int;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn cfmakeraw(attributes: *c.termios) void;

const tiocgwinsz: c_ulong = 0x40087468;

/// Environment variables that change how the command behaves and that the guest cannot know.
const forwarded_names = [_][:0]const u8{
    "TERM",       "NO_COLOR",    "LANG",     "LC_ALL",     "ZBX_REGISTRY_MIRRORS",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
    "no_proxy",
};

/// Where the signal handler leaves what it caught, for the relay loop to send.
var signal_pipe: [2]i32 = .{ -1, -1 };

fn on_signal(signal: c.SIG) callconv(.c) void {
    const byte: u8 = @intCast(@backingInt(signal));
    _ = c.write(signal_pipe[1], @ptrCast(&byte), 1);
}

const caught = [_]c.SIG{ .INT, .TERM, .HUP, .QUIT, .WINCH };

fn catch_signals() Error!void {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    if (c.pipe(&signal_pipe) != 0) return error.Failed;
    for (signal_pipe) |descriptor| {
        const flags = c.fcntl(descriptor, c.F.GETFL);
        _ = c.fcntl(descriptor, c.F.SETFL, flags | @as(c_int, @bitCast(c.O{ .NONBLOCK = true })));
    }
    const action: c.Sigaction = .{
        .handler = .{ .handler = on_signal },
        .mask = std.mem.zeroes(c.sigset_t),
        .flags = 0,
    };
    for (caught) |signal| _ = c.sigaction(signal, &action, null);
}

/// The Linux number of a signal this process caught, or null for the window change.
fn guest_signal(number: u8) ?u8 {
    assert(number <= std.math.maxInt(u8));
    assert(@sizeOf(u64) == 8);
    return switch (number) {
        @backingInt(c.SIG.INT) => 2,
        @backingInt(c.SIG.TERM) => 15,
        @backingInt(c.SIG.HUP) => 1,
        @backingInt(c.SIG.QUIT) => 3,
        else => null,
    };
}

const Size = struct { rows: u16, columns: u16 };

fn terminal_size() Size {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    var size: c.winsize = undefined;
    for ([_]i32{ 1, 0, 2 }) |descriptor| {
        if (ioctl(descriptor, tiocgwinsz, &size) == 0 and size.col > 0) {
            return .{ .rows = size.row, .columns = size.col };
        }
    }
    return .{ .rows = 24, .columns = 80 };
}

/// What the relay needs to give back to the terminal when it ends.
const Terminal = struct {
    saved: c.termios,
    raw: bool,

    fn enter(pty: bool) Terminal {
        assert(@sizeOf(usize) == 8);
        assert(@sizeOf(u64) == 8);
        var saved: c.termios = undefined;
        // Raw mode only with a pty: otherwise the Mac's terminal keeps its line editing.
        const raw_wanted = pty and c.tcgetattr(0, &saved) == 0;
        if (!raw_wanted) return .{ .saved = saved, .raw = false };
        var raw = saved;
        cfmakeraw(&raw);
        // Output is processed by the guest's terminal, not twice.
        _ = c.tcsetattr(0, .FLUSH, &raw);
        return .{ .saved = saved, .raw = true };
    }

    fn leave(terminal: *const Terminal) void {
        assert(@intFromPtr(terminal) != 0);
        assert(@sizeOf(u64) == 8);
        // NOW, not a drain: a terminal that has stopped reading (flow control) must not keep
        // this process from ending.
        if (terminal.raw) _ = c.tcsetattr(0, .NOW, &terminal.saved);
    }
};

// ---- The connection ----------------------------------------------------------------------------

/// A vsock connection to the guest's command service, from the host process.
fn open_connection(ctx: *const commands.Context, diag: *Diag) Error!i32 {
    assert(ctx.paths.socket.length > 0);
    assert(diag.code == null);
    var attempts: u32 = 0;
    while (attempts < 2) : (attempts += 1) {
        _ = try commands.ensure_running(ctx, diag);
        if (ask_host(ctx)) |descriptor| return descriptor;
        // The machine may have been stopped for being idle between the check and the request:
        // once more, which boots a fresh one.
    }
    diagnose.service_silent(diag, ctx.paths.console_log.slice());
    return error.Failed;
}

fn ask_host(ctx: *const commands.Context) ?i32 {
    assert(@intFromPtr(ctx) != 0);
    assert(@sizeOf(u64) == 8);
    const socket = files.connect_unix(ctx.paths.socket.slice()) catch return null;
    defer files.close(socket);
    files.write_all(socket, control.connect_request) catch return null;
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const received = files.receive_with_descriptors(socket, &line) catch return null;
    if (!std.mem.eql(u8, line[0..received.length], control.connect_ok)) return null;
    if (received.descriptor_count != 2) return null;
    // The second descriptor is left open for as long as this process lives: the host watches it
    // to learn that this command's client ended, and then lets the connection go.
    watch_descriptor = received.descriptors[1];
    return received.descriptors[0];
}

// ---- The command ---------------------------------------------------------------------------

/// The command line as given, after the program name, with how the run is to be reported.
pub const Command = struct {
    words: []const []const u8,
    json: bool,
    /// A `run` ends with 125 when this process loses the connection; anything else with 2.
    is_run: bool,
};

const Frames = struct {
    payload: [constants.forward_start_bytes_max]u8 = undefined,
    arguments: [constants.args_count_max][]const u8 = undefined,
    environment: [constants.forward_env_count_max][]const u8 = undefined,
    names: [constants.forward_env_count_max][constants.env_name_bytes_max + 1:0]u8 = undefined,
    values: [constants.forward_env_count_max][1024]u8 = undefined,
    directory: [constants.path_bytes_max + 1]u8 = undefined,
};

var frames: Frames = undefined;

/// The write end of the pipe the host watches (see `ask_host`); never closed before exit.
var watch_descriptor: i32 = -1;

fn send_frame(descriptor: i32, kind: protocol.Kind, payload: []const u8) bool {
    assert(payload.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    var header: [constants.forward_header_bytes]u8 = undefined;
    protocol.render_header(&header, kind, @intCast(payload.len));
    files.write_all(descriptor, &header) catch return false;
    if (payload.len == 0) return true;
    files.write_all(descriptor, payload) catch return false;
    return true;
}

/// Adds `NAME=value` for a name this process has set, if there is room.
fn add_environment(count: *usize, name: []const u8) void {
    assert(@intFromPtr(count) != 0);
    assert(name.len < 1 << 31);
    if (count.* == constants.forward_env_count_max) return;
    if (!protocol.environment_name_allowed(name)) return;
    if (name.len > constants.env_name_bytes_max) return;
    @memcpy(frames.names[count.*][0..name.len], name);
    frames.names[count.*][name.len] = 0;
    const value = c.getenv(&frames.names[count.*]) orelse return;
    const text = std.mem.span(value);
    var entry = std.fmt.bufPrint(&frames.values[count.*], "{s}={s}", .{ name, text }) catch return;
    if (std.mem.indexOfScalar(u8, entry, 0) != null) entry = entry[0..0];
    if (entry.len == 0) return;
    frames.environment[count.*] = entry;
    count.* += 1;
}

/// The names the command line asks for: `-e NAME` and `--env NAME` without a value take the
/// variable from the environment of the process that runs `zbx`, which is this one.
fn add_named_environment(count: *usize, words: []const []const u8) void {
    assert(@intFromPtr(count) != 0);
    assert(@sizeOf(u64) == 8);
    var index: usize = 0;
    while (index + 1 < words.len) : (index += 1) {
        const word = words[index];
        if (!std.mem.eql(u8, word, "-e") and !std.mem.eql(u8, word, "--env")) continue;
        const next = words[index + 1];
        if (std.mem.indexOfScalar(u8, next, '=') == null) add_environment(count, next);
    }
}

/// Which of the command's streams are terminals, as the Mac has them: a pty only when standard
/// input and output both are (a redirected one must stay a pipe, as it is on Linux), and standard
/// error a pipe of its own unless it is a terminal beside a pty.
const Streams = struct {
    pty: bool,
    stderr_pipe: bool,

    fn of_this_process() Streams {
        const pty = c.isatty(0) == 1 and c.isatty(1) == 1;
        return .{ .pty = pty, .stderr_pipe = !pty or c.isatty(2) != 1 };
    }
};

fn start_frame(command: *const Command, streams: Streams) ?[]const u8 {
    assert(command.words.len > 0);
    assert(command.words.len <= constants.args_count_max);
    var count: usize = 0;
    for (forwarded_names) |name| add_environment(&count, name);
    add_named_environment(&count, command.words);
    var directory: []const u8 = "";
    if (c.getcwd(&frames.directory, frames.directory.len)) |_| {
        directory = std.mem.sliceTo(&frames.directory, 0);
    }
    const size = terminal_size();
    return protocol.render_start(&frames.payload, &.{
        .pty = streams.pty,
        .stderr_pipe = streams.stderr_pipe,
        .rows = size.rows,
        .columns = size.columns,
        .working_directory = directory,
        .arguments = command.words,
        .environment = frames.environment[0..count],
    });
}

/// Runs `command` in the VM. Returns the command's exit code; a failure is in `diag`.
pub fn run(ctx: *const commands.Context, command: *const Command, diag: *Diag) Error!u8 {
    assert(command.words.len > 0);
    assert(diag.code == null);
    const streams = Streams.of_this_process();
    const payload = start_frame(command, streams) orelse {
        diag.raise(.E0008);
        diag.while_("reading the command line", .{});
        diag.cause("the command line and environment are more than {d} bytes", .{
            constants.forward_start_bytes_max,
        });
        diag.fix(.{ .sentence = "pass fewer or shorter arguments" });
        return error.Failed;
    };
    const connection = try open_connection(ctx, diag);
    defer files.close(connection);
    try catch_signals();
    if (!send_frame(connection, .start, payload)) {
        return lost(command, diag, "the guest did not take the command");
    }
    const screen = Terminal.enter(streams.pty);
    defer screen.leave();
    return relay(connection, command, diag);
}

fn lost(command: *const Command, diag: *Diag, what: []const u8) Error {
    assert(@intFromPtr(command) != 0);
    assert(what.len > 0);
    diagnose.connection_lost(diag, what);
    return error.Failed;
}

/// Standard input to the guest, its output and error to ours, signals both ways, until the exit
/// frame (the command's code) or the end of the connection (a failure).
fn relay(connection: i32, command: *const Command, diag: *Diag) Error!u8 {
    assert(@intFromPtr(command) != 0);
    assert(@intFromPtr(diag) != 0);
    var data: [constants.forward_data_bytes_max]u8 = undefined;
    var stdin_open = true;
    var turns: u64 = 0;
    const turns_max: u64 = 1 << 40; // A command that lives long still makes progress.
    while (turns < turns_max) : (turns += 1) {
        var entries = [3]c.pollfd{
            .{ .fd = connection, .events = c.POLL.IN, .revents = 0 },
            .{ .fd = signal_pipe[0], .events = c.POLL.IN, .revents = 0 },
            .{ .fd = if (stdin_open) 0 else -1, .events = c.POLL.IN, .revents = 0 },
        };
        const ready = c.poll(&entries, entries.len, -1);
        if (ready < 0) {
            if (c.errno(ready) == .INTR) continue;
            return lost(command, diag, "waiting for the guest failed");
        }
        if (entries[1].revents != 0) send_signals(connection);
        if (entries[2].revents != 0) stdin_open = forward_input(connection, &data);
        if (entries[0].revents != 0) {
            if (try take_frame(connection, command, diag)) |code| return code;
        }
    }
    unreachable; // The loop returns from inside; its bound is only a guard.
}

fn send_signals(connection: i32) void {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    var bytes: [8]u8 = undefined;
    const count = c.read(signal_pipe[0], &bytes, bytes.len);
    if (count <= 0) return;
    for (bytes[0..@intCast(count)]) |number| {
        if (number == @backingInt(c.SIG.WINCH)) {
            var payload: [4]u8 = undefined;
            const size = terminal_size();
            protocol.render_window(&payload, size.rows, size.columns);
            _ = send_frame(connection, .window, &payload);
        } else if (guest_signal(number)) |linux_number| {
            _ = send_frame(connection, .signal, &.{linux_number});
        }
    }
}

/// True while standard input has more.
fn forward_input(connection: i32, data: []u8) bool {
    assert(data.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    const count = c.read(0, data.ptr, data.len);
    if (count < 0) return c.errno(count) == .INTR;
    if (count == 0) {
        _ = send_frame(connection, .stdin_eof, &.{});
        return false;
    }
    _ = send_frame(connection, .stdin, data[0..@intCast(count)]);
    return true;
}

/// Reads one frame of the guest's; the command's exit code if it was the exit frame.
fn take_frame(connection: i32, command: *const Command, diag: *Diag) Error!?u8 {
    assert(@intFromPtr(command) != 0);
    assert(@intFromPtr(diag) != 0);
    var header_bytes: [constants.forward_header_bytes]u8 = undefined;
    if (!read_exact(connection, &header_bytes)) return lost(command, diag, "the guest hung up");
    const header = protocol.parse_header(&header_bytes) orelse {
        return lost(command, diag, "the guest sent something that is not a frame");
    };
    var payload: [constants.forward_data_bytes_max]u8 = undefined;
    if (header.length > payload.len) {
        return lost(command, diag, "the guest sent a frame that is too big");
    }
    if (!read_exact(connection, payload[0..header.length])) {
        return lost(command, diag, "the guest hung up");
    }
    switch (header.kind) {
        .stdout => files.write_all(1, payload[0..header.length]) catch {},
        .stderr => files.write_all(2, payload[0..header.length]) catch {},
        .exit => {
            const exit = protocol.parse_exit(payload[0..2]).?; // The header fixed the size at 2.
            return if (exit.signaled) 128 +| exit.value else exit.value;
        },
        else => return lost(command, diag, "the guest sent a frame meant for the other side"),
    }
    return null;
}

fn read_exact(descriptor: i32, buffer: []u8) bool {
    assert(buffer.len < 1 << 31);
    assert(@sizeOf(u64) == 8);
    var done: usize = 0;
    while (done < buffer.len) {
        const count = c.read(descriptor, buffer[done..].ptr, buffer.len - done);
        if (count < 0 and c.errno(count) == .INTR) continue;
        if (count <= 0) return false;
        done += @intCast(count);
    }
    return true;
}

test "a Linux signal number is given for the signals zbx forwards, and none for the others" {
    // Goal: macOS and Linux number SIGHUP, SIGINT, SIGQUIT and SIGTERM alike, but the table must
    // not rely on it. Method: each caught signal.
    try std.testing.expectEqual(@as(?u8, 2), guest_signal(@backingInt(c.SIG.INT)));
    try std.testing.expectEqual(@as(?u8, 15), guest_signal(@backingInt(c.SIG.TERM)));
    try std.testing.expectEqual(@as(?u8, 1), guest_signal(@backingInt(c.SIG.HUP)));
    try std.testing.expectEqual(@as(?u8, 3), guest_signal(@backingInt(c.SIG.QUIT)));
    try std.testing.expectEqual(@as(?u8, null), guest_signal(@backingInt(c.SIG.WINCH)));
    try std.testing.expectEqual(@as(?u8, null), guest_signal(0));
}

test "named environment: only -e NAME without a value, only allowed names" {
    // Goal: `-e NAME` takes the Mac's variable; `-e NAME=value` and names the guest owns do not.
    // Method: set a variable for this process and ask for it three ways.
    _ = setenv("ZBX_TEST_FORWARD", "kept", 1);
    var count: usize = 0;
    add_named_environment(&count, &.{ "run", "-e", "ZBX_TEST_FORWARD", "-e", "A=b", "-e", "PATH" });
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("ZBX_TEST_FORWARD=kept", frames.environment[0]);
}
