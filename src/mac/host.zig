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
const dns = @import("dns.zig");
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
    assert(@sizeOf(usize) == 8);
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
    network_up: bool,
    /// The idle stop: the last time anything ran or asked to run, the last time the guest was
    /// asked, and how long nothing may run before the machine is stopped.
    last_busy_ms: u64,
    last_check_ms: u64,
    idle_timeout_ms: u32,
};

/// The idle timeout: the constant, or the number of milliseconds in the environment variable
/// `ZBX_VM_IDLE_TIMEOUT_MS` (for tests, so that the stop can be seen in seconds).
fn idle_timeout() u32 {
    assert(@sizeOf(usize) == 8);
    assert(@sizeOf(u64) == 8);
    const text = std.c.getenv(constants.vm_idle_timeout_variable) orelse {
        return constants.vm_idle_timeout_ms;
    };
    const parsed = std.fmt.parseInt(u32, std.mem.span(text), 10);
    const value = parsed catch return constants.vm_idle_timeout_ms;
    if (value < constants.vm_idle_timeout_ms_min or value > constants.vm_idle_timeout_ms_max) {
        return constants.vm_idle_timeout_ms;
    }
    return value;
}

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
    const network_up = setup_guest(&machine, paths, diag) orelse return error.Failed;
    const ready_ms = files.now_ms();
    const network_word = if (network_up) "up" else "down";
    log("set up in {d} ms, network {s}", .{ ready_ms - booted_ms, network_word });
    return .{
        .machine = machine,
        .listener = listener,
        .version = version,
        .booted_ms = booted_ms,
        .values = request.values,
        .network_up = network_up,
        .last_busy_ms = ready_ms,
        .last_check_ms = ready_ms,
        .idle_timeout_ms = idle_timeout(),
    };
}

/// The pid goes into the lock file so that a process that finds the lock held can name the holder.
fn note_pid(lock: i32) void {
    assert(@sizeOf(usize) == 8);
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
        if (state == .stopped or state == .errored) break;
        if (machine.poisoned()) break; // A connect timed out: the machine is not used again.
        if (ask_hello(machine)) |version| return version;
        files.sleep_ms(handshake_step_ms);
    }
    diagnose.no_answer(diag, paths.console_log.slice(), constants.vm_boot_timeout_ms);
    return null;
}

fn ask_hello(machine: *vz.Machine) ?Version {
    assert(@intFromPtr(machine) != 0);
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

/// Tells the guest the time and who the commands run as, and waits for it to be ready: true if
/// it has a network, false if it has none, null with `diag` set if it could not finish.
fn setup_guest(machine: *vz.Machine, paths: *const paths_mod.Paths, diag: *Diag) ?bool {
    assert(paths.console_log.length > 0);
    assert(diag.code == null);
    const entry = std.c.getpwuid(std.c.getuid()) orelse {
        diagnose.setup_failed(diag, "user", paths.console_log.slice());
        return null;
    };
    const name = std.mem.span(entry.name orelse "");
    const home_text = std.c.getenv("HOME") orelse "";
    var dns_buffer: [64]u8 = undefined;
    var spec: protocol.Setup = .{
        .seconds = wall_clock_seconds(),
        .uid = entry.uid,
        .gid = entry.gid,
        .name = name,
        .home = std.mem.span(home_text),
        .dns = dns.resolvers(&dns_buffer),
    };
    if (!protocol.name_ok(spec.name) or !protocol.home_ok(spec.home) or spec.uid == 0) {
        diagnose.setup_failed(diag, "user", paths.console_log.slice());
        return null;
    }
    spec.seconds = wall_clock_seconds();
    var failure: vz.Failure = .{};
    const connection = machine.connect(constants.vm_guest_port, &failure) catch {
        diagnose.no_answer(diag, paths.console_log.slice(), constants.vm_control_timeout_ms);
        return null;
    };
    defer files.close(connection);
    var request: [constants.vm_line_bytes_max]u8 = undefined;
    files.write_all(connection, protocol.render_setup(&request, &spec)) catch {};
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const reply = files.read_line(connection, &line, constants.vm_setup_timeout_ms) catch {
        diagnose.setup_failed(diag, "answer", paths.console_log.slice());
        return null;
    };
    const parsed = protocol.parse_setup_reply(reply) orelse {
        diagnose.setup_failed(diag, "answer", paths.console_log.slice());
        return null;
    };
    switch (parsed) {
        .ok => |ok| return ok.network_up,
        .failed => {
            const word = std.mem.trimEnd(u8, reply[protocol.setup_failed_prefix.len..], "\n");
            diagnose.setup_failed(diag, word, paths.console_log.slice());
            return null;
        },
    }
}

fn wall_clock_seconds() u64 {
    var spec: std.c.timespec = undefined;
    const result = std.c.clock_gettime(.REALTIME, &spec);
    assert(result == 0);
    assert(spec.sec > 0);
    return @intCast(spec.sec);
}

/// Serves the control socket until the machine is off. Returns the process's exit code.
pub fn run(running: *Running, paths: *const paths_mod.Paths) u8 {
    assert(running.version.len == constants.vm_image_version_bytes);
    assert(running.listener >= 0);
    assert(paths.socket.length > 0);
    var accepted: u32 = 0;
    while (accepted < accepts_max) : (accepted += 1) {
        if (running.machine.state() == .stopped or running.machine.state() == .errored) {
            log("the machine stopped on its own", .{});
            break;
        }
        if (stop_requested.load(.acquire)) {
            log("asked to stop by a signal", .{});
            shut_down(running);
            break;
        }
        if (stop_when_idle(running)) {
            log("idle for {d} ms; stopping", .{running.idle_timeout_ms});
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
        .connect => {
            running.last_busy_ms = files.now_ms(); // Someone is about to run a command.
            pass_connection(running, connection);
            return false;
        },
    }
}

/// Opens a vsock connection to the guest's command service and hands the descriptor to the
/// client with the answer, so that the data never passes through this process.
fn pass_connection(running: *Running, connection: i32) void {
    assert(connection >= 0);
    assert(running.listener >= 0);
    var failure: vz.Failure = .{};
    const guest = running.machine.connect(constants.vm_forward_port, &failure) catch {
        files.write_all(connection, "fail service\n") catch {};
        return;
    };
    defer files.close(guest);
    files.send_with_descriptor(connection, control.connect_ok, guest) catch {};
}

/// Asks the guest every `vm_idle_check_ms` whether the user's processes run; true once none
/// has for the idle timeout. A guest that does not answer is not idle.
fn stop_when_idle(running: *Running) bool {
    assert(running.idle_timeout_ms >= constants.vm_idle_timeout_ms_min);
    assert(running.listener >= 0);
    const now = files.now_ms();
    if (now - running.last_check_ms < constants.vm_idle_check_ms) return false;
    running.last_check_ms = now;
    if (guest_busy(&running.machine)) running.last_busy_ms = now;
    return now - running.last_busy_ms >= running.idle_timeout_ms;
}

fn guest_busy(machine: *vz.Machine) bool {
    assert(@intFromPtr(machine) != 0);
    assert(constants.vm_guest_port > 0);
    var failure: vz.Failure = .{};
    const connection = machine.connect(constants.vm_guest_port, &failure) catch return true;
    defer files.close(connection);
    files.write_all(connection, protocol.busy_request) catch return true;
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const reply = files.read_line(connection, &line, answer_timeout_ms) catch return true;
    const count = protocol.parse_busy_reply(reply) orelse return true;
    return count > 0;
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
        .network_up = running.network_up,
        .uptime_ms = now - running.booted_ms,
    };
}

/// Asks the guest to power off, waits for the machine to be off, and stops it by force if it
/// does not do so in time.
fn shut_down(running: *Running) void {
    if (running.machine.poisoned()) return; // The process exits next; that ends the machine.
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
