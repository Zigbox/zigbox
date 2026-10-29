//! `zbx vm start | stop | status | config`: the commands that talk to the process that owns the
//! virtual machine (or start it). The user never has to start the machine: from the next slice a
//! command that needs it starts it. `start` stays as an optional pre-warm.
//!
//! Every command prints its result on stdout, text or one JSON object (`--output json`), and
//! returns a failure as a diagnostic in `diag`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const control = @import("control.zig");
const diagnose = @import("diagnose.zig");
const files = @import("files.zig");
const image = @import("image.zig");
const paths_mod = @import("paths.zig");
const protocol = @import("../vm_protocol.zig");
const render = @import("../diag/render.zig");
const settings = @import("settings.zig");
const settings_file = @import("settings_file.zig");
const spec = @import("../runtime/spec.zig");
const vz = @import("vz.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const Error = error{Failed};

pub const Context = struct {
    paths: *const paths_mod.Paths,
    json: bool,
    mode: render.Mode,
    color: bool,
};

/// What a look at the control socket found.
pub const Probe = union(enum) {
    /// No host: nothing listens and nobody holds the lock.
    absent,
    answering: control.Status,
    /// A host of another release, whose answer this one cannot read.
    other_format,
    /// Somebody holds the lock and does not answer (starting up, or stuck), with its pid if known.
    held: ?u32,
};

extern "c" fn _NSGetExecutablePath(buffer: [*]u8, size: *u32) i32;

pub fn print(text: []const u8) void {
    assert(text.len < constants.output_bytes_max);
    assert(constants.output_bytes_max > 0);
    files.write_all(1, text) catch {};
}

fn print_diag_warning(ctx: *const Context, diag: *const Diag) void {
    assert(diag.entry().severity == .warning);
    assert(diag.code != null);
    if (ctx.mode == .json) assert(!ctx.color);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, ctx.mode, ctx.color, &buffer);
    files.write_all(2, text) catch {};
}

// ---- Looking at the host ---------------------------------------------------------------------

/// Asks the host for its status, waiting at most `timeout_ms` for the answer.
pub fn probe(paths: *const paths_mod.Paths, timeout_ms: u32) Probe {
    assert(paths.lock.length > 0);
    assert(timeout_ms <= constants.vm_boot_timeout_ms);
    assert(paths.socket.length > 0);
    assert(timeout_ms > 0);
    const connection = files.connect_unix(paths.socket.slice()) catch return lock_probe(paths);
    defer files.close(connection);
    files.write_all(connection, control.status_request) catch return lock_probe(paths);
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const reply = files.read_line(connection, &line, timeout_ms) catch return lock_probe(paths);
    const parsed = control.parse_reply(reply) orelse return lock_probe(paths);
    switch (parsed) {
        .status => |status| return .{ .answering = status },
        .stopping => return .{ .held = null },
        .other_format => return .other_format,
    }
}

/// No answer on the socket: either nobody is there (a killed host leaves a socket file but not
/// the lock, because the kernel drops the lock with the process) or somebody is, and is silent.
fn lock_probe(paths: *const paths_mod.Paths) Probe {
    assert(paths.lock.length > 0);
    assert(paths.lock.length > 0);
    const taken = files.lock_exclusive(paths.lock.slice()) catch return .absent;
    if (taken) |descriptor| {
        files.close(descriptor);
        return .absent;
    }
    var text: [32]u8 = undefined;
    const content = files.read_file(paths.lock.slice(), &text) catch return .{ .held = null };
    const pid = std.fmt.parseInt(u32, std.mem.trim(u8, content, " \n"), 10) catch null;
    return .{ .held = pid };
}

/// Waits until the host is gone: no answer, no lock. False if it is still there after `limit_ms`.
fn wait_gone(paths: *const paths_mod.Paths, limit_ms: u32) bool {
    assert(paths.lock.length > 0);
    assert(limit_ms > 0);
    assert(limit_ms <= constants.vm_boot_timeout_ms + constants.vm_stop_timeout_ms);
    const deadline = files.now_ms() + limit_ms;
    while (files.now_ms() < deadline) {
        switch (probe(paths, constants.vm_poll_step_ms * 5)) {
            .absent => return true,
            else => files.sleep_ms(constants.vm_poll_step_ms),
        }
    }
    return false;
}

/// Writes into a buffer the caller sized for the longest document; a short one is a bug.
fn put(writer: *std.Io.Writer, comptime format: []const u8, args: anytype) void {
    assert(writer.end <= writer.buffer.len);
    assert(writer.end <= writer.buffer.len);
    // Cannot fail: every caller's buffer holds the longest document its format can make.
    writer.print(format, args) catch unreachable;
}

fn put_all(writer: *std.Io.Writer, text: []const u8) void {
    assert(writer.end <= writer.buffer.len);
    assert(writer.end <= writer.buffer.len);
    // Cannot fail: same.
    writer.writeAll(text) catch unreachable;
}

// ---- status ----------------------------------------------------------------------------------

pub fn run_status(ctx: *const Context, host_cpus: u32, diag: *Diag) Error!void {
    assert(ctx.paths.socket.length > 0);
    assert(host_cpus >= 1);
    assert(diag.code == null);
    const loaded = try settings_file.load(ctx.paths, host_cpus, diag);
    switch (probe(ctx.paths, constants.vm_control_timeout_ms)) {
        .absent => print_status(ctx, null, loaded.values),
        .answering => |status| print_status(ctx, status, loaded.values),
        .other_format => print_other(ctx),
        .held => |pid| {
            diagnose.host_locked(diag, pid);
            return error.Failed;
        },
    }
}

const another_release = "another release's (zbx vm stop replaces it)";

/// A host of another release runs: what can be said of it without reading its answer.
fn print_other(ctx: *const Context) void {
    assert(ctx.paths.socket.length > 0);
    const text = "{{\"schema\":\"zbx.vm.status/1\",\"state\":\"running\",\"image_version\":" ++
        "\"{s}\",\"vm_image_version\":null,\"image_match\":false,\"pid\":null,\"cpus\":null," ++
        "\"memory_bytes\":null,\"uptime_ms\":null,\"configured\":null,\"idle_timeout_ms\":{d}}}\n";
    var buffer: [512]u8 = undefined;
    const written = if (ctx.json)
        std.fmt.bufPrint(&buffer, text, .{ image.version, constants.vm_idle_timeout_ms })
    else
        std.fmt.bufPrint(&buffer, "vm: running\n  image    {s}\n", .{another_release});
    print(written catch unreachable); // Cannot fail: both texts fit 512 bytes.
}

fn print_status(ctx: *const Context, status: ?control.Status, configured: settings.Settings) void {
    assert(configured.cpus >= 1);
    assert(configured.memory_bytes > 0);
    var buffer: [1024]u8 = undefined;
    const text = if (ctx.json)
        status_json(&buffer, status, configured)
    else
        status_text(&buffer, status, configured);
    assert(text.len > 0);
    assert(text[text.len - 1] == '\n'); // One line, or lines, each ended.
    print(text);
}

fn status_text(buffer: []u8, status: ?control.Status, configured: settings.Settings) []const u8 {
    assert(configured.cpus >= 1);
    assert(buffer.len >= 512);
    var writer: std.Io.Writer = .fixed(buffer);
    const next_boot = "  config   {d} cpus, {d} MiB, {d} GiB disk at the next boot\n";
    const running = status orelse {
        put(&writer, "vm: stopped\n  image    {s}\n", .{image.version});
        put(&writer, next_boot, .{
            configured.cpus, configured.memory_bytes >> 20, configured.disk_bytes >> 30,
        });
        return writer.buffered();
    };
    const same: []const u8 = if (std.mem.eql(u8, &running.version, image.version))
        "this zbx's"
    else
        "ANOTHER version";
    put(&writer, "vm: {s}\n", .{@tagName(running.state)});
    put(&writer, "  image    {s} ({s})\n", .{ &running.version, same });
    put(&writer, "  cpus     {d}\n  memory   {d} MiB\n", .{
        running.cpus, running.memory_bytes >> 20,
    });
    put(&writer, "  pid      {d}\n", .{running.pid});
    put(&writer, "  network  {s}\n", .{if (running.network_up) "up" else "down"});
    const seconds = running.uptime_ms / 1000;
    put(&writer, "  uptime   {d}.{d} s\n", .{ seconds, running.uptime_ms % 1000 / 100 });
    const differs = configured.cpus != running.cpus or
        configured.memory_bytes != running.memory_bytes;
    if (differs) put(&writer, next_boot, .{
        configured.cpus, configured.memory_bytes >> 20, configured.disk_bytes >> 30,
    });
    return writer.buffered();
}

fn status_json(buffer: []u8, status: ?control.Status, configured: settings.Settings) []const u8 {
    assert(configured.memory_bytes >= constants.vm_memory_bytes_min);
    assert(buffer.len >= 512);
    var writer: std.Io.Writer = .fixed(buffer);
    const state = if (status) |running| @tagName(running.state) else "stopped";
    put(&writer, "{{\"schema\":\"zbx.vm.status/1\",\"state\":\"{s}\",", .{state});
    put(&writer, "\"image_version\":\"{s}\",", .{image.version});
    if (status) |running| {
        const match = std.mem.eql(u8, &running.version, image.version);
        put(&writer, "\"vm_image_version\":\"{s}\",", .{&running.version});
        put(&writer, "\"image_match\":{},\"pid\":{d},", .{ match, running.pid });
        put(&writer, "\"cpus\":{d},\"memory_bytes\":{d},", .{ running.cpus, running.memory_bytes });
        put(&writer, "\"uptime_ms\":{d},", .{running.uptime_ms});
        put(&writer, "\"network\":\"{s}\",", .{if (running.network_up) "up" else "down"});
    } else {
        put_all(&writer, "\"vm_image_version\":null,\"image_match\":null,\"pid\":null,");
        put_all(&writer, "\"cpus\":null,\"memory_bytes\":null,\"uptime_ms\":null,");
        put_all(&writer, "\"network\":null,");
    }
    put(&writer, "\"configured\":{{\"cpus\":{d},\"memory_bytes\":{d},", .{
        configured.cpus, configured.memory_bytes,
    });
    put(&writer, "\"disk_bytes\":{d}}},", .{configured.disk_bytes});
    put(&writer, "\"idle_timeout_ms\":{d}}}\n", .{constants.vm_idle_timeout_ms});
    return writer.buffered();
}

// ---- stop ------------------------------------------------------------------------------------

pub fn run_stop(ctx: *const Context, host_cpus: u32, diag: *Diag) Error!void {
    assert(ctx.paths.socket.length > 0);
    assert(host_cpus >= 1);
    assert(diag.code == null);
    const loaded = try settings_file.load(ctx.paths, host_cpus, diag);
    switch (probe(ctx.paths, constants.vm_control_timeout_ms)) {
        // Stopping what is not running is done already: the same result, exit 0.
        .absent => {},
        .held => |pid| {
            diagnose.host_locked(diag, pid);
            return error.Failed;
        },
        .answering, .other_format => try request_stop(ctx.paths, diag),
    }
    print_status(ctx, null, loaded.values);
}

/// Sends `stop` and waits for the host to be gone.
fn request_stop(paths: *const paths_mod.Paths, diag: *Diag) Error!void {
    assert(paths.lock.length > 0);
    assert(paths.socket.length > 0);
    assert(diag.code == null);
    const connection = files.connect_unix(paths.socket.slice()) catch return error.Failed;
    defer files.close(connection);
    files.write_all(connection, control.stop_request) catch {};
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    _ = files.read_line(connection, &line, constants.vm_control_timeout_ms) catch {};
    const wait_ms = constants.vm_stop_timeout_ms + constants.vm_control_timeout_ms;
    if (wait_gone(paths, wait_ms)) return;
    diagnose.host_locked(diag, null);
    return error.Failed;
}

// ---- start -----------------------------------------------------------------------------------

pub fn run_start(ctx: *const Context, host_cpus: u32, diag: *Diag) Error!void {
    assert(ctx.paths.vm_dir.length > 0);
    assert(host_cpus >= 1);
    assert(diag.code == null);
    const loaded = try settings_file.load(ctx.paths, host_cpus, diag);
    const status = try ensure_running(ctx, diag);
    print_status(ctx, status, loaded.values);
    if (!status.network_up) print_network_warning(ctx);
}

/// Makes sure a machine of this image runs, starting it if it does not, and returns its status.
/// Two commands racing to start it start one: the host holds the lock, the other's host process
/// says so and ends, and that command finds the winner answering.
pub fn ensure_running(ctx: *const Context, diag: *Diag) Error!control.Status {
    assert(ctx.paths.vm_dir.length > 0);
    assert(diag.code == null);
    files.make_directories(ctx.paths.vm_dir.slice()) catch {
        const doing = "making the VM directory";
        diagnose.directory(diag, doing, ctx.paths.vm_dir.slice(), files.reason());
        return error.Failed;
    };
    var found = probe(ctx.paths, constants.vm_control_timeout_ms);
    if (found == .held) found = wait_for_answer(ctx.paths);
    switch (found) {
        .answering => |status| {
            assert(status.pid > 0); // A host that answers is a process.
            if (std.mem.eql(u8, &status.version, image.version)) return status;
            try replace(ctx, &status.version, diag);
        },
        .other_format => try replace(ctx, "another release", diag),
        .held => |pid| {
            diagnose.host_locked(diag, pid);
            return error.Failed;
        },
        .absent => {},
    }
    launch(ctx.paths, diag) catch |launch_failed| {
        // A host that lost the race to another says so; the winner is what this command needs.
        const winner = wait_for_answer(ctx.paths);
        if (winner == .answering) {
            diag.reset();
            return winner.answering;
        }
        return launch_failed;
    };
    switch (probe(ctx.paths, constants.vm_control_timeout_ms)) {
        .answering => |status| {
            assert(status.pid > 0);
            // The host that was just started is ours.
            assert(std.mem.eql(u8, &status.version, image.version));
            return status;
        },
        else => {
            diagnose.host_locked(diag, null);
            return error.Failed;
        },
    }
}

fn print_network_warning(ctx: *const Context) void {
    assert(ctx.paths.socket.length > 0);
    var warning: Diag = undefined;
    warning.reset();
    diagnose.no_network(&warning);
    print_diag_warning(ctx, &warning);
}

fn wait_for_answer(paths: *const paths_mod.Paths) Probe {
    assert(paths.socket.length > 0);
    assert(paths.socket.length > 0);
    const deadline = files.now_ms() + constants.vm_boot_timeout_ms;
    var found: Probe = .{ .held = null };
    while (files.now_ms() < deadline) {
        found = probe(paths, constants.vm_control_timeout_ms);
        if (found != .held) return found;
        files.sleep_ms(constants.vm_poll_step_ms);
    }
    return found;
}

/// A machine of another image version is not driven: say so (W1001), stop it, go on.
fn replace(ctx: *const Context, running_version: []const u8, diag: *Diag) Error!void {
    assert(running_version.len > 0);
    assert(diag.code == null);
    var warning: Diag = undefined;
    warning.reset();
    diagnose.replacing(&warning, running_version, image.version);
    print_diag_warning(ctx, &warning);
    try request_stop(ctx.paths, diag);
}

/// Starts the host process, detached, and waits for what it reports: that the guest answered, or
/// the diagnostic of why it did not.
fn launch(paths: *const paths_mod.Paths, diag: *Diag) Error!void {
    assert(paths.socket.length > 0);
    assert(paths.host_log.length > 0);
    assert(diag.code == null);
    var pipe_ends: [2]i32 = undefined;
    if (std.c.pipe(&pipe_ends) != 0) {
        diagnose.directory(diag, "starting the VM host", "pipe", files.reason());
        return error.Failed;
    }
    defer files.close(pipe_ends[0]);
    const old_log = paths.host_log_old.slice();
    _ = files.rotate_if_large(paths.host_log.slice(), old_log, constants.vm_host_log_bytes_max);
    const child = std.c.fork();
    if (child < 0) {
        files.close(pipe_ends[1]);
        diagnose.directory(diag, "starting the VM host", "fork", "cannot start a process");
        return error.Failed;
    }
    if (child == 0) exec_host(paths, pipe_ends[1]);
    files.close(pipe_ends[1]);
    var report: [constants.diag_carry_bytes_max + 1]u8 = undefined;
    const length = read_report(pipe_ends[0], &report);
    if (length > 0 and report[0] == report_ok) return;
    if (length > 1 and report[0] == report_failed) {
        if (diag.decode(report[1..length])) return error.Failed;
    }
    diagnose.start_failed(diag, .starting, null, paths.console_log.slice());
    return error.Failed;
}

pub const report_ok: u8 = 'K';
pub const report_failed: u8 = 'F';

fn read_report(descriptor: i32, buffer: []u8) usize {
    assert(buffer.len <= constants.diag_carry_bytes_max + 1);
    assert(descriptor >= 0);
    assert(buffer.len > 1);
    var length: usize = 0;
    const limit_ms = constants.vm_boot_timeout_ms + constants.vm_control_timeout_ms;
    const deadline = files.now_ms() + limit_ms;
    while (length < buffer.len and files.now_ms() < deadline) {
        const step_ms = constants.vm_control_timeout_ms;
        const ready = files.wait_readable(descriptor, step_ms) catch return length;
        if (!ready) continue;
        const count = std.c.read(descriptor, buffer[length..].ptr, buffer.len - length);
        if (count <= 0) break;
        length += @intCast(count);
        assert(length <= buffer.len);
    }
    assert(length <= buffer.len);
    return length;
}

/// In the forked child: new session, no terminal, output to the host log, then `zbx vm serve`.
fn exec_host(paths: *const paths_mod.Paths, report_fd: i32) noreturn {
    assert(paths.vm_dir.length > 0);
    assert(report_fd >= 0);
    assert(paths.host_log.length > 0);
    _ = std.c.setsid();
    var log_path: [constants.vm_path_bytes_max:0]u8 = undefined;
    const log_text = files.terminate(&log_path, paths.host_log.slice()) catch std.c._exit(127);
    const log_flags: std.c.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true };
    const log_fd = std.c.open(log_text.ptr, log_flags, @as(std.c.mode_t, 0o600));
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY });
    if (log_fd < 0 or null_fd < 0) std.c._exit(127);
    _ = std.c.dup2(null_fd, 0);
    _ = std.c.dup2(log_fd, 1);
    _ = std.c.dup2(log_fd, 2);
    var executable: [constants.vm_path_bytes_max:0]u8 = undefined;
    var size: u32 = constants.vm_path_bytes_max;
    if (_NSGetExecutablePath(&executable, &size) != 0) std.c._exit(127);
    var descriptor_text: [12:0]u8 = @splat(0);
    const digits = std.fmt.bufPrint(&descriptor_text, "{d}", .{report_fd}) catch std.c._exit(127);
    descriptor_text[digits.len] = 0;
    const argv = [_:null]?[*:0]const u8{
        &executable, "vm", "serve", "--report-fd", &descriptor_text,
    };
    _ = std.c.execve(&executable, &argv, std.c.environ);
    std.c._exit(127);
}

// ---- config ----------------------------------------------------------------------------------

pub const ConfigRequest = struct {
    cpus: ?[]const u8 = null,
    memory: ?[]const u8 = null,
    disk: ?[]const u8 = null,
};

/// What this Mac allows: the constants, the framework's limits and the Mac's CPUs and memory.
pub fn bounds_here(host_cpus: u32) settings.Bounds {
    assert(host_cpus >= 1);
    const limits = vz.limits();
    const framework: settings.Bounds = .{
        .cpus_min = limits.cpus_min,
        .cpus_max = limits.cpus_max,
        .memory_bytes_min = limits.memory_bytes_min,
        .memory_bytes_max = limits.memory_bytes_max,
    };
    return settings.bounds_of(framework, host_cpus, files.host_memory_bytes());
}

pub fn run_config(
    ctx: *const Context,
    request: ConfigRequest,
    host_cpus: u32,
    diag: *Diag,
) Error!void {
    assert(ctx.paths.settings.length > 0);
    assert(host_cpus >= 1);
    assert(diag.code == null);
    const loaded = try settings_file.load(ctx.paths, host_cpus, diag);
    const bounds = bounds_here(host_cpus);
    var values = loaded.values;
    var source = loaded.source;
    if (request.cpus != null or request.memory != null or request.disk != null) {
        const disk_now = files.file_size(ctx.paths.store_disk.slice());
        values = try apply_request(request, values, bounds, disk_now, ctx.paths.store_disk.slice(), diag);
        try settings_file.save(ctx.paths, values, diag);
        source = .settings;
    }
    var running: ?control.Status = null;
    if (probe(ctx.paths, constants.vm_poll_step_ms * 5) == .answering) {
        running = probe(ctx.paths, constants.vm_control_timeout_ms).answering;
    }
    print_config(ctx, values, source, bounds, running);
}

fn apply_request(
    request: ConfigRequest,
    current: settings.Settings,
    bounds: settings.Bounds,
    disk_now: u64,
    disk_path: []const u8,
    diag: *Diag,
) Error!settings.Settings {
    assert(bounds.memory_bytes_min <= bounds.memory_bytes_max);
    assert(bounds.cpus_min <= bounds.cpus_max);
    assert(diag.code == null);
    var values = current;
    if (request.cpus) |text| {
        values.cpus = std.fmt.parseInt(u32, text, 10) catch {
            diagnose.size_out_of_range(diag, .not_a_size, "--cpus", text, bounds);
            return error.Failed;
        };
    }
    if (request.memory) |text| {
        values.memory_bytes = spec.parse_size(text, 1, 1 << 50) catch {
            diagnose.size_out_of_range(diag, .not_a_size, "--memory", text, bounds);
            return error.Failed;
        };
    }
    if (request.disk) |text| {
        values.disk_bytes = spec.parse_size(text, 1, 1 << 50) catch {
            diagnose.size_out_of_range(diag, .not_a_size, "--disk", text, bounds);
            return error.Failed;
        };
    }
    if (settings.check(values, bounds)) |problem| {
        const option: []const u8 = switch (problem) {
            .cpus_below, .cpus_above => "--cpus",
            .disk_below, .disk_above, .disk_unaligned => "--disk",
            else => "--memory",
        };
        const given = (if (option[2] == 'c') request.cpus else if (option[2] == 'd')
            request.disk
        else
            request.memory) orelse "";
        diagnose.size_out_of_range(diag, problem, option, given, bounds);
        return error.Failed;
    }
    // The disk file only grows: the file system on it cannot be shrunk without losing data.
    if (request.disk != null and values.disk_bytes < disk_now) {
        diagnose.disk_shrink(diag, values.disk_bytes, disk_now, disk_path);
        return error.Failed;
    }
    return values;
}

fn print_config(
    ctx: *const Context,
    values: settings.Settings,
    source: settings_file.Source,
    bounds: settings.Bounds,
    running: ?control.Status,
) void {
    assert(bounds.memory_bytes_min <= bounds.memory_bytes_max);
    assert(bounds.cpus_min <= bounds.cpus_max);
    assert(values.cpus >= 1);
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const differs = if (running) |status|
        status.cpus != values.cpus or status.memory_bytes != values.memory_bytes
    else
        false;
    if (ctx.json) {
        put(&writer, "{{\"schema\":\"zbx.vm.config/1\",\"cpus\":{d},", .{values.cpus});
        put(&writer, "\"memory_bytes\":{d},\"disk_bytes\":{d},", .{
            values.memory_bytes, values.disk_bytes,
        });
        put(&writer, "\"source\":\"{s}\",", .{@tagName(source)});
        put(&writer, "\"bounds\":{{\"cpus_min\":{d},\"cpus_max\":{d},", .{
            bounds.cpus_min, bounds.cpus_max,
        });
        put(&writer, "\"memory_bytes_min\":{d},\"memory_bytes_max\":{d},", .{
            bounds.memory_bytes_min, bounds.memory_bytes_max,
        });
        put(&writer, "\"disk_bytes_min\":{d},\"disk_bytes_max\":{d}}},", .{
            bounds.disk_bytes_min, bounds.disk_bytes_max,
        });
        put(&writer, "\"applies\":\"{s}\",", .{if (differs) "next_boot" else "running_machine"});
        if (differs) {
            const status = running.?;
            put(&writer, "\"running\":{{\"cpus\":{d},\"memory_bytes\":{d}}}}}\n", .{
                status.cpus, status.memory_bytes,
            });
        } else {
            put_all(&writer, "\"running\":null}\n");
        }
    } else {
        put(&writer, "vm config: {d} cpus, {d} MiB, {d} GiB disk ({s})\n", .{
            values.cpus, values.memory_bytes >> 20, values.disk_bytes >> 30, @tagName(source),
        });
        put(&writer, "  allowed  {d} to {d} cpus, ", .{ bounds.cpus_min, bounds.cpus_max });
        put(&writer, "{d} to {d} MiB, ", .{
            bounds.memory_bytes_min >> 20, bounds.memory_bytes_max >> 20,
        });
        put(&writer, "disk {d} to {d} GiB (it only grows)\n", .{
            bounds.disk_bytes_min >> 30, bounds.disk_bytes_max >> 30,
        });
        if (differs) {
            put_all(&writer, "  note     the running machine keeps its size; ");
            put_all(&writer, "these apply after zbx vm stop\n");
        }
    }
    print(writer.buffered());
}

test "status text and JSON name the state, the image and the configured size" {
    // Goal: the two renderings of a stopped and of a running machine. Method: both, with the
    // JSON checked as JSON and for the schema's required members.
    const test_util = @import("../test_util.zig");
    var buffer: [1024]u8 = undefined;
    const configured: settings.Settings = .{ .cpus = 4, .memory_bytes = 2 << 30 };
    const stopped = status_json(&buffer, null, configured);
    try std.testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, stopped, "\n")));
    try std.testing.expect(std.mem.indexOf(u8, stopped, "\"state\":\"stopped\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stopped, "\"pid\":null") != null);
    const running: control.Status = .{
        .state = .running,
        .pid = 9,
        .cpus = 2,
        .memory_bytes = 1 << 30,
        .version = image.version.*,
        .network_up = true,
        .uptime_ms = 1530,
    };
    const live = status_json(&buffer, running, configured);
    try std.testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, live, "\n")));
    try std.testing.expect(std.mem.indexOf(u8, live, "\"image_match\":true") != null);
    var text_buffer: [1024]u8 = undefined;
    const text = status_text(&text_buffer, running, configured);
    try std.testing.expect(std.mem.indexOf(u8, text, "vm: running") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "uptime   1.5 s") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "at the next boot") != null);
}

test "the status document is exactly what the schema describes, network included" {
    // Goal: a golden for zbx.vm.status/1 with the network member (additive, null when stopped).
    // Method: a fixed running status with the network up and down, and the stopped one.
    var buffer: [1024]u8 = undefined;
    const configured: settings.Settings = .{ .cpus = 4, .memory_bytes = 2 << 30 };
    const base: control.Status = .{
        .state = .running,
        .pid = 9,
        .cpus = 4,
        .memory_bytes = 2 << 30,
        .version = "0123456789abcdef".*,
        .network_up = true,
        .uptime_ms = 1530,
    };
    const up = status_json(&buffer, base, configured);
    const expected_head = "{\"schema\":\"zbx.vm.status/1\",\"state\":\"running\",";
    try std.testing.expect(std.mem.startsWith(u8, up, expected_head));
    const tail = "\"vm_image_version\":\"0123456789abcdef\",\"image_match\":false,\"pid\":9," ++
        "\"cpus\":4,\"memory_bytes\":2147483648,\"uptime_ms\":1530,\"network\":\"up\"," ++
        "\"configured\":{\"cpus\":4,\"memory_bytes\":2147483648,\"disk_bytes\":68719476736}," ++
        "\"idle_timeout_ms\":300000}\n";
    try std.testing.expect(std.mem.endsWith(u8, up, tail));
    var down = base;
    down.network_up = false;
    var other: [1024]u8 = undefined;
    const down_json = status_json(&other, down, configured);
    try std.testing.expect(std.mem.indexOf(u8, down_json, "\"network\":\"down\"") != null);
    const stopped = status_json(&other, null, configured);
    try std.testing.expect(std.mem.indexOf(u8, stopped, "\"network\":null") != null);
    const test_util = @import("../test_util.zig");
    try std.testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, up, "\n")));
}
