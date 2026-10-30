//! The diagnostics of `zbx exec`: where a refusal or a failed step becomes a coded `Diag`
//! (E0220 to E0224 and W0207; E0202 for a command that is not there or cannot run, E0207 and
//! E0208 for the hardening, as a run's). Only the parent calls this; the children send a step
//! and an errno. Nothing here prints.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const errors = @import("../diag/errors.zig");
const Diag = @import("../diag/diag.zig").Diag;
const exec_plan = @import("exec_plan.zig");
const records = @import("records.zig");
const scope_mod = @import("scope.zig");
const scope_text = @import("scope_text.zig");
const text_util = @import("../text.zig");

const linux = std.os.linux;

/// What the diagnostics say about the exec they belong to.
pub const Info = struct {
    /// The container's name, as checked (a run name).
    name: []const u8,
    /// The container's PID 1 as the host sees it.
    pid: u32,
};

pub const Failure = struct {
    err: host_mod.Error,
    errno: u16,
};

const dmesg_policy = "sudo dmesg | grep -iE 'apparmor|seccomp|selinux'";

fn execing(diag: *Diag, info: Info) void {
    assert(info.name.len > 0);
    assert(diag.code != null);
    diag.while_("running a command in the container {s}", .{info.name});
    diag.context("name", "{s}", .{info.name});
    if (info.pid > 0) diag.context("pid", "{d}", .{info.pid});
}

/// ZBX-E0220: the container has a record and is not running; `state` says how it is.
pub fn not_running(diag: *Diag, name: []const u8, lost: bool, record: *const records.Parsed) void {
    assert(diag.code == null);
    assert(name.len > 0);
    diag.raise(.E0220);
    diag.while_("looking for the container {s}", .{name});
    if (lost) {
        diag.cause("the container {s} is lost: its record says it runs, and nothing of it is " ++
            "left", .{name});
    } else switch (record.exit) {
        .exited => |code| diag.cause("the container {s} is stopped: it exited with code {d}", .{
            name, code,
        }),
        .signaled => |number| diag.cause("the container {s} is stopped: it was killed by " ++
            "signal {d}", .{ name, number }),
        .start_failed => diag.cause("the container {s} is stopped: it never started", .{name}),
        .running, .lost => diag.cause("the container {s} is stopped", .{name}),
    }
    diag.context("name", "{s}", .{name});
    diag.context("state", "{s}", .{if (lost) "lost" else "stopped"});
    diag.fix(.{ .sentence = "see the containers and their states:", .command = "zbx ps --all" });
    diag.fix(.{
        .sentence = "start it again, then exec into it:",
        .command = "zbx run -d --name web alpine -- sleep 1000",
        .template = true,
    });
    assert(diag.code.? == .E0220);
}

/// ZBX-E0221: the container's environment could not be read, or a namespace opened or joined,
/// or the command forked into it.
pub fn join_failed(diag: *Diag, info: Info, operation: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0221);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    if (failure.err == error.NotFound or failure.errno == @backingInt(linux.E.NOMEM)) {
        diag.cause("the container's first process ended while zbx was joining it", .{});
        diag.fix(.{ .sentence = "see whether it still runs:", .command = "zbx ps --all" });
    } else if (failure.err == error.AccessDenied) {
        diag.cause("a security policy, or a /proc mounted with hidepid, refuses it", .{});
        diag.fix(.{ .sentence = "look for the policy that denies it:", .command = dmesg_policy });
    }
    diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
    execing(diag, info);
    assert(diag.code.? == .E0221);
}

/// ZBX-E0222: the command could not be put in the container's cgroup; `problem` says why.
pub fn cgroup_failed(
    diag: *Diag,
    info: Info,
    scope: []const u8,
    problem: *const scope_mod.Problem,
) void {
    assert(diag.code == null);
    assert(scope.len > 0);
    diag.raise(.E0222);
    // The real cause last: the default output shows the newest one.
    diag.cause("the command was not started: it never runs outside the container's limits", .{});
    scope_text.problem_causes(diag, problem);
    diag.context("scope", "{s}", .{scope});
    diag.fix(.{ .sentence = "check the cgroup setup:", .command = "zbx doctor" });
    execing(diag, info);
    assert(diag.code.? == .E0222);
}

/// ZBX-E0223: the working directory is not in the container.
pub fn workdir_missing(diag: *Diag, info: Info, workdir: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(workdir.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = text_util.sanitise(&storage, workdir);
    diag.raise(.E0223);
    errors.cause_host_error(diag, "entering the working directory", failure.err, failure.errno);
    diag.cause("the container has no directory {s} to start the command in", .{echo});
    diag.context("dir", "{s}", .{echo});
    diag.fix_with("make it first:", "zbx exec {s} -- mkdir -p {s}", .{ info.name, echo });
    diag.fix(.{ .sentence = "or name one the container has: --workdir /" });
    execing(diag, info);
    assert(diag.code.? == .E0223);
}

/// ZBX-E0224: the pseudo-terminal could not be made, sized, made the command's, or zbx's own
/// terminal made raw.
pub fn terminal_failed(diag: *Diag, info: Info, operation: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0224);
    errors.cause_host_error(diag, operation, failure.err, failure.errno);
    diag.fix_with("run it without a terminal:", "zbx exec {s} -- <command> < /dev/null", .{
        info.name,
    });
    diag.mark_last_fix_template();
    execing(diag, info);
    assert(diag.code.? == .E0224);
}

/// ZBX-E0207 and ZBX-E0208: the command could not drop to the container's capabilities, or
/// `no_new_privs` or the filter could not be set. It never runs with more than the container.
pub fn hardening_failed(diag: *Diag, info: Info, step: exec_plan.Step, failure: Failure) void {
    assert(diag.code == null);
    const capability = step.kind == .restrict_capabilities or step.kind == .clear_ambient;
    diag.raise(if (capability) .E0207 else .E0208);
    errors.cause_host_error(diag, exec_plan.describe(step), failure.err, failure.errno);
    diag.cause("the command was not started: it never runs with more than the container", .{});
    if (failure.err == error.AccessDenied) {
        diag.fix(.{ .sentence = "look for the policy that denies it:", .command = dmesg_policy });
    }
    diag.fix(.{ .sentence = "check what this host allows:", .command = "zbx doctor" });
    execing(diag, info);
    assert(diag.fixes.count > 0);
}

/// ZBX-E0202: the command is not in the container, or cannot be run there.
pub fn command_failed(diag: *Diag, info: Info, plan: *const exec_plan.Plan, failure: Failure) void {
    assert(diag.code == null);
    diag.raise(.E0202);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const program = text_util.sanitise(&storage, plan.program());
    const by_path = std.mem.indexOfScalar(u8, plan.program(), '/') != null;
    if (failure.err == error.NotFound) diag.mark_command_missing();
    switch (failure.err) {
        error.NotFound => if (by_path) {
            diag.cause("'{s}' is not in the container", .{program});
        } else {
            diag.cause("no file named '{s}' in the command's PATH in the container", .{program});
        },
        error.AccessDenied => diag.cause("'{s}' is not executable (permission denied)", .{program}),
        else => if (failure.errno == @backingInt(linux.E.NOEXEC)) {
            diag.cause("'{s}' is not a program this machine can run (exec format error)", .{
                program,
            });
        } else {
            errors.cause_host_error(diag, "execve", failure.err, failure.errno);
        },
    }
    diag.context("cmd", "{s}", .{program});
    diag.fix_with("look in the container:", "zbx exec {s} -- ls /bin /usr/bin", .{info.name});
    diag.fix_with("or use the program's full path:", "zbx exec {s} -- /bin/sh", .{info.name});
    execing(diag, info);
    assert(diag.code.? == .E0202);
}

/// The diagnostic of a failed step of the plan, by its kind.
pub fn step_failed(
    diag: *Diag,
    info: Info,
    plan: *const exec_plan.Plan,
    index: u8,
    failure: Failure,
) void {
    assert(diag.code == null);
    assert(index < plan.count);
    const step = plan.steps[index];
    switch (step.kind) {
        .exec => command_failed(diag, info, plan, failure),
        .enter_workdir => workdir_missing(diag, info, plan.text(plan.workdir), failure),
        .open_terminal, .attach_terminal => {
            terminal_failed(diag, info, exec_plan.describe(step), failure);
        },
        .restrict_capabilities, .clear_ambient, .set_no_new_privs, .install_seccomp => {
            hardening_failed(diag, info, step, failure);
        },
        else => join_failed(diag, info, exec_plan.describe(step), failure),
    }
    if (step.kind == .open_namespace or step.kind == .join_namespace) {
        diag.context("ns", "{s}", .{step.namespace.file_name()});
    }
    diag.context("step", "{s} ({d} of {d})", .{ @tagName(step.kind), index + 1, plan.count });
    assert(diag.code != null);
}

/// ZBX-W0207: the exec's entry in the container's history was not written.
pub fn history_not_kept(diag: *Diag, name: []const u8, path: []const u8, failure: Failure) void {
    assert(diag.code == null);
    assert(name.len > 0);
    diag.raise(.W0207);
    errors.cause_host_error(diag, "writing the exec history", failure.err, failure.errno);
    diag.context("name", "{s}", .{name});
    diag.context("path", "{s}", .{path});
    diag.fix(.{
        .sentence = "look at the state directory's disk:",
        .command = "df -h \"${XDG_STATE_HOME:-$HOME/.local/state}\"",
    });
    assert(diag.code.? == .W0207);
}
