//! `zbx exec NAME [-e NAME[=VALUE]] [--user USER[:GROUP]] [--workdir DIR] -- COMMAND...`: a
//! command in a running container (`runtime/exec.zig` does the work). The command gets a
//! pseudo-terminal when zbx's standard input and output are both terminals, and zbx's own
//! streams otherwise. zbx exits with the command's code, or 128 plus its signal, and keeps its
//! own failures to the codes of a run (125, and 126 or 127 for a command that cannot run or is
//! not there). `--output json` ends with an `exec_exit` line on stderr (`zbx schema exec`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const run_env = @import("run_env.zig");
const Diag = @import("diag/diag.zig").Diag;
const exec = @import("runtime/exec.zig");
const run = @import("runtime/run.zig");

const Host = host_mod.Host;

pub const Args = struct {
    name: []const u8,
    command: []const []const u8,
    env: []const run_env.Setting,
    user: ?[]const u8,
    workdir: ?[]const u8,
    json: bool,
    warn: run.Warn,
};

/// The memory of one exec: the library's handle and the `-e` values.
pub const Workspace = struct {
    handle: exec.Handle,
    env: run_env.Storage,
};

pub const Error = error{
    /// The command did not start, or zbx lost it; the diagnostic says why.
    Failed,
};

/// Runs the exec and returns the exit code: the command's own, or 128 plus its signal.
pub fn run_exec(host: Host, args: *const Args, workspace: *Workspace, diag: *Diag) Error!u8 {
    assert(diag.code == null);
    assert(args.command.len > 0);
    run_env.check_set(host, args.env, diag) catch return error.Failed;
    const resolved = run_env.resolve(host, args.env, &.{}, &workspace.env, diag) catch
        return error.Failed;
    const spec: exec.Spec = .{
        .name = args.name,
        .command = args.command,
        .env = resolved.env,
        .user = args.user,
        .workdir = args.workdir,
        // A terminal for the command only when both ends of zbx are one, as `docker exec -it`.
        .terminal = host.input_is_terminal() and host.is_terminal(.stdout),
    };
    const handle = &workspace.handle;
    exec.start(host, &spec, .{ .warn = args.warn }, handle, diag) catch return error.Failed;
    const exit = exec.wait(handle);
    const code = exit.code() orelse {
        diag.* = handle.lost_diag; // The only reason a command that started has no code.
        return error.Failed;
    };
    report(host, args, handle, exit);
    return code;
}

/// The end of the exec: with `--output json`, the `exec_exit` line; in text, a line only when
/// the command died with its container, which the command's own output would not say.
fn report(host: Host, args: *const Args, handle: *const exec.Handle, exit: exec.Exit) void {
    assert(exit.code() != null);
    assert(handle.status == .stopped);
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    if (args.json) {
        write_exit(&writer, handle, exit) catch return;
    } else if (handle.container_ended) {
        writer.print("zbx: exec: the container {s} ended, and the command with it\n", .{
            handle.name.slice(),
        }) catch return;
    }
    const text = writer.buffered();
    if (text.len > 0) host.write_all(.stderr, text) catch return;
}

/// `{"exec_exit":{"container":"web","reason":"exited","code":0,"container_ended":false}}`, and
/// `"signal":N` for a command killed by one.
pub fn write_exit(
    writer: *std.Io.Writer,
    handle: *const exec.Handle,
    exit: exec.Exit,
) std.Io.Writer.Error!void {
    assert(exit != .lost);
    const name = handle.name.slice();
    assert(name.len <= constants.container_name_bytes_max);
    // A run name is lowercase letters, digits and '-': nothing in it needs escaping.
    try writer.print("{{\"exec_exit\":{{\"container\":\"{s}\",", .{name});
    switch (exit) {
        .exited => |code| try writer.print("\"reason\":\"exited\",\"code\":{d}", .{code}),
        .signaled => |number| {
            const format = "\"reason\":\"signal\",\"signal\":{d},\"code\":{d}";
            try writer.print(format, .{ number, exit.code().? });
        },
        .lost => unreachable, // Asserted above.
    }
    try writer.print(",\"container_ended\":{s}}}}}\n", .{
        if (handle.container_ended) "true" else "false",
    });
}
