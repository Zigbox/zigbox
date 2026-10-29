//! The process that owns the virtual machine (`zbx vm serve`). Virtualization.framework machines
//! live inside the process that made them, so there is one host process per user, detached from
//! the terminal, holding a lock, a control socket and the machine. It boots the guest from the
//! unpacked image, waits for the guest's answer on vsock, tells the process that started it, and
//! then answers `status` and `stop` on the control socket until the machine is off.
//!
//! The process is single-threaded apart from the framework's own queue. Everything it waits for
//! has a bound in `constants.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const control = @import("control.zig");
const diagnose = @import("diagnose.zig");
const files = @import("files.zig");
const image = @import("image.zig");
const paths_mod = @import("paths.zig");
const protocol = @import("../vm_protocol.zig");
const settings = @import("settings.zig");
const vz = @import("vz.zig");
const Diag = @import("../diag/diag.zig").Diag;

const command_line = "console=hvc0 earlycon panic=-1 quiet loglevel=4";
const handshake_step_ms: u32 = 100;
const accept_step_ms: u32 = 100;
const answer_timeout_ms: u32 = 1000;
const accepts_max: u32 = 1 << 24;

/// Set by the signal handler on SIGTERM, SIGINT or SIGHUP: the host then stops the machine as
/// `zbx vm stop` does, so `kill <pid>` (the fix E1004 names) and a closed terminal are clean.
var stop_requested = std.atomic.Value(bool).init(false);

fn on_signal(signal: std.c.SIG) callconv(.c) void {
    _ = signal;
    stop_requested.store(true, .release);
}

/// Routes the signals above to `on_signal` and ignores SIGPIPE (a client that left).
pub fn install_signal_handlers() void {
    const handler: std.c.Sigaction = .{
        .handler = .{ .handler = on_signal },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    const ignore: std.c.Sigaction = .{
        .handler = .{ .handler = std.c.SIG.IGN },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    _ = std.c.sigaction(.TERM, &handler, null);
    _ = std.c.sigaction(.INT, &handler, null);
    _ = std.c.sigaction(.HUP, &handler, null);
    _ = std.c.sigaction(.PIPE, &ignore, null);
    assert(!stop_requested.load(.acquire));
}

pub const Request = struct {
    paths: *const paths_mod.Paths,
    values: settings.Settings,
};

const Running = struct {
    machine: vz.Machine,
    listener: i32,
    version: [constants.vm_image_version_bytes]u8,
    booted_ms: u64,
    values: settings.Settings,
};

/// Boots the machine. On success returns it, with the lock and the listening socket held by the
/// process; on failure the reason is in `diag`.
pub fn boot(request: *const Request, diag: *Diag) error{Failed}!Running {
    assert(request.paths.lock.length > 0);
    assert(request.values.cpus >= 1);
    assert(diag.code == null);
    const paths = request.paths;
    const lock = files.lock_exclusive(paths.lock.slice()) catch {
        diagnose.directory(diag, "taking the VM lock", paths.lock.slice(), files.reason());
        return error.Failed;
    };
    if (lock == null) {
        diagnose.host_locked(diag, null);
        return error.Failed;
    }
    note_pid(lock.?);
    image.ensure(paths) catch {
        diagnose.directory(diag, "unpacking the VM image", paths.image_dir.slice(), files.reason());
        return error.Failed;
    };
    const console = open_console(paths, diag) orelse return error.Failed;
    const listener = files.listen_unix(paths.socket.slice()) catch {
        const doing = "opening the control socket";
        diagnose.directory(diag, doing, paths.socket.slice(), files.reason());
        return error.Failed;
    };
    const started_ms = files.now_ms();
    var machine = create_machine(request, console, diag) orelse return error.Failed;
    const version = handshake(&machine, paths, diag) orelse return error.Failed;
    assert(protocol.is_version(&version));
    const booted_ms = files.now_ms();
    log("booted in {d} ms", .{booted_ms - started_ms});
    return .{
        .machine = machine,
        .listener = listener,
        .version = version,
        .booted_ms = booted_ms,
        .values = request.values,
    };
}

/// The pid goes into the lock file so that a process that finds the lock held can name the holder.
fn note_pid(lock: i32) void {
    assert(lock >= 0);
    var text: [24]u8 = undefined;
    // Cannot fail: a pid is at most ten digits and the buffer holds 24 bytes.
    const written = std.fmt.bufPrint(&text, "{d}\n", .{std.c.getpid()}) catch unreachable;
    _ = std.c.ftruncate(lock, 0);
    files.write_all(lock, written) catch {};
}

fn open_console(paths: *const paths_mod.Paths, diag: *Diag) ?i32 {
    assert(paths.vm_dir.length > 0);
    assert(paths.console_log.length > 0);
    assert(diag.code == null);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    // Cannot fail: `Paths.init` made every path shorter than the buffer.
    const path = files.terminate(&terminated, paths.console_log.slice()) catch unreachable;
    const flags: std.c.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
    const descriptor = std.c.open(path.ptr, flags, @as(std.c.mode_t, 0o600));
    if (descriptor < 0) {
        const doing = "opening the console log";
        diagnose.directory(diag, doing, paths.console_log.slice(), "cannot be written");
        return null;
    }
    return descriptor;
}

fn create_machine(request: *const Request, console: i32, diag: *Diag) ?vz.Machine {
    assert(request.values.memory_bytes >= constants.vm_memory_bytes_min);
    assert(console >= 0);
    assert(diag.code == null);
    const paths = request.paths;
    var kernel: [constants.vm_path_bytes_max:0]u8 = undefined;
    var initramfs: [constants.vm_path_bytes_max:0]u8 = undefined;
    const spec: vz.BootSpec = .{
        // Cannot fail: `Paths.init` made every path shorter than the buffer.
        .kernel_path = files.terminate(&kernel, paths.kernel.slice()) catch unreachable,
        // Same.
        .initramfs_path = files.terminate(&initramfs, paths.initramfs.slice()) catch unreachable,
        .command_line = command_line,
        .console_descriptor = console,
        .cpus = request.values.cpus,
        .memory_bytes = request.values.memory_bytes,
    };
    var failure: vz.Failure = .{};
    var machine = vz.Machine.create(&spec, &failure) catch |err| {
        explain_failure(diag, err, &failure, paths);
        return null;
    };
    machine.start(&failure) catch |err| {
        explain_failure(diag, err, &failure, paths);
        return null;
    };
    return machine;
}

/// Turns what the framework said into one diagnostic.
fn explain_failure(
    diag: *Diag,
    err: vz.Error,
    failure: *const vz.Failure,
    paths: *const paths_mod.Paths,
) void {
    assert(diag.code == null);
    assert(paths.console_log.length > 0);
    assert(diag.code == null);
    if (err == error.Unsupported) return diagnose.not_allowed(diag, null);
    var plain: [constants.vm_line_bytes_max]u8 = undefined;
    const said: ?diagnose.Framework = if (failure.silent) null else .{
        .domain = failure.info.domain(),
        .code = failure.info.code,
        .description = diagnose.plain_text(&plain, failure.info.description()),
    };
    if (said) |framework| {
        if (diagnose.is_entitlement_text(framework.description)) {
            return diagnose.not_allowed(diag, framework);
        }
    }
    const step: diagnose.Step = switch (failure.stage) {
        .configure => .configuring,
        .validate => .validating,
        .start => .starting,
        .connect => .connecting,
        .stop => .stopping,
    };
    diagnose.start_failed(diag, step, said, paths.console_log.slice());
}

/// Asks the guest who it is until it answers; its version, or null with `diag` set.
const Version = [constants.vm_image_version_bytes]u8;

fn handshake(machine: *vz.Machine, paths: *const paths_mod.Paths, diag: *Diag) ?Version {
    assert(constants.vm_boot_timeout_ms > handshake_step_ms);
    assert(paths.console_log.length > 0);
    assert(diag.code == null);
    const deadline = files.now_ms() + constants.vm_boot_timeout_ms;
    while (files.now_ms() < deadline) {
        const state = machine.state();
        if (state == .stopped or machine.errored()) break;
        if (ask_hello(machine)) |version| return version;
        files.sleep_ms(handshake_step_ms);
    }
    diagnose.no_answer(diag, paths.console_log.slice(), constants.vm_boot_timeout_ms);
    return null;
}

fn ask_hello(machine: *vz.Machine) ?Version {
    assert(constants.vm_guest_port > 0);
    var failure: vz.Failure = .{};
    const connection = machine.connect(constants.vm_guest_port, &failure) catch return null;
    defer files.close(connection);
    files.write_all(connection, protocol.hello_request) catch return null;
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const reply = files.read_line(connection, &line, answer_timeout_ms) catch return null;
    const version = protocol.parse_hello_reply(reply) orelse return null;
    return version[0..constants.vm_image_version_bytes].*;
}

/// Serves the control socket until the machine is off. Returns the process's exit code.
pub fn run(running: *Running, paths: *const paths_mod.Paths) u8 {
    assert(running.version.len == constants.vm_image_version_bytes);
    assert(running.listener >= 0);
    assert(paths.socket.length > 0);
    var accepted: u32 = 0;
    while (accepted < accepts_max) : (accepted += 1) {
        if (running.machine.state() == .stopped or running.machine.errored()) {
            log("the machine stopped on its own", .{});
            break;
        }
        if (stop_requested.load(.acquire)) {
            log("asked to stop by a signal", .{});
            shut_down(running);
            break;
        }
        const ready = files.wait_readable(running.listener, accept_step_ms) catch false;
        if (!ready) continue;
        const connection = std.c.accept(running.listener, null, null);
        if (connection < 0) continue;
        const stop = answer(running, connection);
        files.close(connection);
        if (stop) {
            shut_down(running);
            break;
        }
    }
    cleanup(paths, running);
    return constants.exit_ok;
}

fn answer(running: *Running, connection: i32) bool {
    assert(running.values.cpus >= 1);
    assert(connection >= 0);
    assert(running.listener >= 0);
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const request_line = files.read_line(connection, &line, answer_timeout_ms) catch return false;
    const request = control.parse_request(request_line) orelse return false;
    var reply: [constants.vm_line_bytes_max]u8 = undefined;
    switch (request) {
        .status => {
            const status = status_of(running, .running);
            files.write_all(connection, control.render_status(&reply, &status)) catch {};
            return false;
        },
        .stop => {
            files.write_all(connection, control.render_stopping()) catch {};
            return true;
        },
    }
}

fn status_of(running: *const Running, state: control.State) control.Status {
    assert(running.listener >= 0);
    assert(running.values.cpus >= 1);
    const now = files.now_ms();
    return .{
        .state = state,
        .pid = @intCast(std.c.getpid()),
        .cpus = running.values.cpus,
        .memory_bytes = running.values.memory_bytes,
        .version = running.version,
        .uptime_ms = now - running.booted_ms,
    };
}

/// Asks the guest to power off, waits for the machine to be off, and stops it by force if it
/// does not do so in time.
fn shut_down(running: *Running) void {
    assert(running.values.cpus >= 1);
    assert(running.listener >= 0);
    assert(constants.vm_stop_timeout_ms > 0);
    var failure: vz.Failure = .{};
    if (running.machine.connect(constants.vm_guest_port, &failure)) |connection| {
        defer files.close(connection);
        files.write_all(connection, protocol.shutdown_request) catch {};
        var line: [constants.vm_line_bytes_max]u8 = undefined;
        _ = files.read_line(connection, &line, answer_timeout_ms) catch {};
    } else |_| {}
    const deadline = files.now_ms() + constants.vm_stop_timeout_ms;
    while (files.now_ms() < deadline) {
        if (running.machine.state() == .stopped) return;
        files.sleep_ms(constants.vm_poll_step_ms);
    }
    log("the guest did not power off in time; stopping it", .{});
    running.machine.force_stop(&failure) catch {};
}

fn cleanup(paths: *const paths_mod.Paths, running: *const Running) void {
    assert(running.listener >= 0);
    assert(paths.socket.length > 0);
    assert(running.listener >= 0);
    files.close(running.listener);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    // Cannot fail: `Paths.init` made every path shorter than the buffer.
    const path = files.terminate(&terminated, paths.socket.slice()) catch unreachable;
    _ = std.c.unlink(path.ptr);
}

pub fn log(comptime format: []const u8, args: anytype) void {
    assert(format.len > 0);
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "host: " ++ format ++ "\n", args) catch return;
    files.write_all(2, text) catch {};
}
