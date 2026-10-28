//! What the parts of the M4 demo share: the commands as the user `demo` runs them, the wrappers
//! that run `zbx` in a project directory with the registry mirror named, and the failure line.
//! The parts: main_m4.zig (the spec's steps), accept_m4.zig (the acceptance checks and the upgrade
//! test) and agent_m4.zig (the scripted agent).

const std = @import("std");
const Io = std.Io;
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

/// `zbx` as the demo user, in the project directory, with the mirror named: the images come from
/// `mirror.gcr.io` first, as in CI, so the anonymous Docker Hub allowance is not what the demo
/// depends on.
pub const z = H.as_demo ++ "/home/demo/z";
pub const project = "/home/demo/project";
/// The scripted agent's own wrapper and project directory (its own `zbx.lock`), the same store.
pub const za = H.as_demo ++ "/home/demo/za";
pub const agent_project = "/home/demo/agent-project";
/// The older `zbx` of the upgrade test (the merged M3).
pub const zbx_old = H.as_demo ++ "/home/demo/zbx-old";
pub const rootfs_dir = "/home/demo/alpine";
pub const store_dir = "/home/demo/.local/share/zbx/store";
pub const state_dir = "/home/demo/.local/state/zbx";

/// The wrapper's text for `program` (a path in the guest): `cd` to `directory`, name the mirror,
/// and run it.
pub fn wrapper_for(
    comptime directory: []const u8,
    comptime with_ca: bool,
    comptime program: []const u8,
) []const u8 {
    const ca = if (with_ca) " SSL_CERT_FILE=/home/demo/ca.crt" else "";
    return "#!/bin/sh\n" ++
        "cd " ++ directory ++ " || exit 125\n" ++
        "export ZBX_REGISTRY_MIRRORS=mirror.gcr.io" ++ ca ++ "\n" ++
        // no-bus-env: the wrapper inherits the environment of its caller, which has the prefix.
        "exec " ++ program ++ " \"$@\"\n";
}

fn wrapper_text(comptime directory: []const u8, comptime with_ca: bool) []const u8 {
    return wrapper_for(directory, with_ca, "/home/demo/zbx");
}

pub fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("{s}: {s} FAILED: {s} ({s})\n", .{
        harness.demo_name, step, what, @errorName(err),
    });
    return err;
}

/// Writes the two wrappers (`z` and `za`) and the project directories.
pub fn write_wrappers(session: *Session, out: *Io.Writer, with_ca: bool) !void {
    const made = try session.run(
        "runuser -u demo -- mkdir -p " ++ project ++ " " ++ agent_project,
        limits.command_timeout_kvm_s,
    );
    if (made.status != 0) return error.PrepareFailed;
    const plain = [_][]const u8{ wrapper_text(project, false), wrapper_text(agent_project, false) };
    const with = [_][]const u8{ wrapper_text(project, true), wrapper_text(agent_project, true) };
    const paths = [_][]const u8{ "/home/demo/z", "/home/demo/za" };
    for (paths, if (with_ca) with else plain) |path, text| try H.put_file(session, path, text);
    if (with_ca) {
        const fetch = try std.fmt.allocPrint(
            session.scratch_allocator(),
            "curl -fsS -o /home/demo/ca.crt http://10.0.2.2:{d}/ca.crt",
            .{session.server.port},
        );
        const fetched = try session.run(fetch, limits.command_timeout_kvm_s);
        if (fetched.status != 0) return error.PrepareFailed;
    }
    const owned = try session.run(
        "chown demo:demo /home/demo/z /home/demo/za && ls -l /home/demo/z /home/demo/za",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the wrappers that run zbx in the project directories", owned);
    if (owned.status != 0) return error.PrepareFailed;
}

/// Runs `command`, shows it, and returns its two streams (valid until the next command).
pub fn run_shown(session: *Session, out: *Io.Writer, command: []const u8) !H.SplitResult {
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    return result;
}

/// Like `run_shown`, and fails the step unless the command ended with `want`.
pub fn expect_exit(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    command: []const u8,
    want: u8,
) !H.SplitResult {
    const result = try run_shown(session, out, command);
    if (result.status != want) return fail_step(out, step, command, error.ExitCodeWrong);
    return result;
}

/// `command` built into the session's arena.
pub fn format(session: *Session, comptime pattern: []const u8, args: anytype) ![]const u8 {
    return std.fmt.allocPrint(session.scratch_allocator(), pattern, args);
}
