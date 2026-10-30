//! The two children of `zbx exec` (`exec_plan.zig` has the order and why): the joiner, which
//! joins the container's namespaces and forks the command, and the command, which waits to be
//! put in the container's cgroup and then drops to what the container has and runs.
//!
//! Like a run's child (`child.zig`) they allocate nothing and format no text: every path and the
//! exec image were made by the parent. A failure is four bytes in the report pipe (`sync.zig`)
//! naming the step and the errno; the parent builds the diagnostic.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const capabilities = @import("capabilities.zig");
const exec_plan = @import("exec_plan.zig");
const seccomp = @import("seccomp.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;
const Plan = exec_plan.Plan;
const Step = exec_plan.Step;

/// What both children need, in the parent's memory; each child sees its own copy.
pub const Context = struct {
    host: Host,
    plan: *const Plan,
    /// The parent writes one byte once the command is in the container's cgroup.
    ready: host_mod.Pipe,
    /// The children write records; the parent reads them to the end.
    report: host_mod.Pipe,
    /// The namespace files the parent opened, by `host_mod.NamespaceKind`; null for one that is
    /// not joined.
    namespaces: [6]?host_mod.Handle,
    /// With a terminal: the peer the command takes as its three streams.
    peer: ?host_mod.Handle,
};

pub const go_ahead: u8 = 1;

const Error = host_mod.Error || error{
    /// The parent closed the ready pipe without the go-ahead: it gave up or died.
    ParentGone,
};

/// The joiner's body. Returns its exit code; the command it forks goes on as the parent's child.
pub fn joiner_entry(context: *anyopaque) u8 {
    const child: *const Context = @ptrCast(@alignCast(context));
    const host = child.host;
    const plan = child.plan;
    assert(plan.count == plan.steps_expected());
    assert(child.ready.read != child.report.read);
    // The parent's ends: closed here so that end of file reaches both sides.
    host.close(child.ready.write);
    host.close(child.report.read);
    const first = plan.first_of(.joiner);
    for (plan.steps[first..plan.count], first..) |step, index| {
        if (exec_plan.side_of(step.kind) != .joiner) break;
        host.begin_step(@intCast(index));
        joiner_step(child, step) catch {
            fail(child, @intCast(index), host.last_errno());
            return constants.child_exit_setup_failed;
        };
    }
    host.begin_step(host_mod.step_none);
    return constants.exit_ok;
}

fn joiner_step(child: *const Context, step: Step) Error!void {
    assert(child.plan.count > 0);
    const host = child.host;
    assert(exec_plan.side_of(step.kind) == .joiner);
    switch (step.kind) {
        .joiner_die_with_parent => try host.die_with_parent(),
        .join_namespace => {
            const handle = child.namespaces[@backingInt(step.namespace)].?;
            try host.join_namespace(handle, step.namespace);
        },
        .fork_command => {
            const pid = try host.fork_child(true, command_entry, @constCast(child));
            const bytes = sync.encode_forked(pid);
            try host.write_handle_all(child.report.write, &bytes);
        },
        else => unreachable, // The other sides' steps.
    }
}

/// The command's body. A command that starts never returns (the real host) or ends the child
/// (the simulator); the result is the exit code of one that did not.
pub fn command_entry(context: *anyopaque) u8 {
    const child: *const Context = @ptrCast(@alignCast(context));
    const host = child.host;
    const plan = child.plan;
    assert(plan.count == plan.steps_expected());
    const first = plan.first_of(.command);
    var errno_override: u16 = 0;
    for (plan.steps[first..plan.count], first..) |step, index| {
        if (exec_plan.side_of(step.kind) != .command) break;
        host.begin_step(@intCast(index));
        command_step(child, step, &errno_override) catch |err| {
            if (err == error.ParentGone) return constants.child_exit_setup_failed;
            const errno = if (errno_override != 0) errno_override else host.last_errno();
            fail(child, @intCast(index), errno);
            return constants.child_exit_setup_failed;
        };
    }
    host.begin_step(host_mod.step_none);
    assert(plan.steps[plan.count - 3].kind == .exec); // Only the simulator gets here.
    return constants.exit_ok;
}

fn command_step(child: *const Context, step: Step, errno_override: *u16) Error!void {
    assert(errno_override.* == 0);
    const host = child.host;
    const plan = child.plan;
    assert(exec_plan.side_of(step.kind) == .command);
    switch (step.kind) {
        .die_with_parent, .rearm_death_signal => try host.die_with_parent(),
        .await_release => try await_release(child),
        .attach_terminal => try host.attach_terminal(child.peer.?),
        // The directory must be there: unlike a run, exec makes nothing in the container.
        .enter_workdir => try host.change_directory(plan.text(plan.workdir)),
        .seal_descriptors => try host.seal_descriptors(),
        .restrict_capabilities => try host.restrict_capabilities(capabilities.keep_mask),
        .clear_ambient => try host.clear_ambient(),
        .set_user => try host.set_user(plan.user_uid, plan.user_gid),
        .set_no_new_privs => try host.no_new_privs(),
        .install_seccomp => try host.install_seccomp(&seccomp.program),
        .exec => try exec(child, errno_override),
        else => unreachable, // The other sides' steps.
    }
}

/// A failed step, told to the parent. If the write fails there is nobody to tell.
fn fail(child: *const Context, step: u8, errno_raw: u16) void {
    assert(errno_raw < 4096);
    assert(step < child.plan.count);
    // A failure made inside host.zig has no errno; EIO stands for it.
    const errno = if (errno_raw != 0) errno_raw else constants.errno_io;
    const record: sync.Record = .{ .kind = .failure, .step = step, .errno = errno };
    const bytes = record.encode();
    child.host.write_handle_all(child.report.write, &bytes) catch return;
}

/// Waits for the go-ahead. No byte, only end of file, means the parent will not continue.
fn await_release(child: *const Context) Error!void {
    var byte: [1]u8 = undefined;
    const count = try child.host.read_some(child.ready.read, &byte);
    child.host.close(child.ready.read);
    if (count == 0) return error.ParentGone;
    assert(count == 1);
    assert(byte[0] == go_ahead);
}

/// Tries each candidate path in turn, as a shell does; a file that is there but cannot be run is
/// reported over a missing one (the same rule as a run's command).
fn exec(child: *const Context, errno_override: *u16) Error!void {
    const plan = child.plan;
    assert(plan.candidates_count > 0);
    assert(plan.argv[0] != null);
    const argv: host_mod.CStrings = @ptrCast(&plan.argv);
    const envp: host_mod.CStrings = @ptrCast(&plan.envp);
    var missing_errno: u16 = 0;
    var denied_errno: u16 = 0;
    for (plan.candidate_slice()) |candidate| {
        const path = plan.text(candidate);
        child.host.exec(.{ .path = path, .argv = argv, .envp = envp }) catch |err| switch (err) {
            error.NotFound => {
                missing_errno = child.host.last_errno();
                continue;
            },
            error.AccessDenied => {
                denied_errno = child.host.last_errno();
                continue;
            },
            else => return err,
        };
        return; // The simulator's way of saying the command started.
    }
    if (denied_errno != 0) {
        errno_override.* = denied_errno;
        return error.AccessDenied;
    }
    assert(missing_errno != 0); // Every candidate was tried, and none was there.
    errno_override.* = missing_errno;
    return error.NotFound;
}
