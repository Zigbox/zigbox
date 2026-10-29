//! The child's side of a run: the body `host.spawn` runs in the new process. It walks the plan's
//! child steps in order, each through `host.zig`, and ends in `exec`.
//!
//! After `clone3` this code allocates nothing and formats no text: every path, the hostname and
//! the exec image were made by the parent in the plan. A failure is four bytes in the report
//! pipe (`sync.zig`), and the child ends; the parent builds the diagnostic.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const capabilities = @import("capabilities.zig");
const plan_mod = @import("plan.zig");
const seccomp = @import("seccomp.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;
const Step = plan_mod.Step;

/// Everything the child needs, handed over by the parent. It lives in the parent's memory and
/// the child sees its own copy.
pub const Context = struct {
    host: Host,
    plan: *const Plan,
    /// The parent writes one byte when the id maps are in place; the child reads it.
    ready: host_mod.Pipe,
    /// The child writes records; the parent reads them to the end.
    report: host_mod.Pipe,
};

const Error = host_mod.Error || error{
    /// The parent closed the ready pipe without the go-ahead byte: it gave up or died.
    ParentGone,
};

/// A step failure's errno when it is not the one the last call left in the host (the exec step
/// tries several paths and reports the most telling failure, not the last).
const State = struct {
    errno_override: u16,
    /// The generated /etc files whose steps failed (bit n for `netfiles.File` n): the rest of
    /// that file's steps are skipped, and the one note says what went wrong.
    failed_etc: u8,
};

pub const go_ahead: u8 = 1;

/// The body of the child. Returns the exit code of a child that did not reach its command; a
/// command that started never returns (the real host) or ends the child (the simulator).
pub fn entry(context: *anyopaque) u8 {
    const child: *const Context = @ptrCast(@alignCast(context));
    const host = child.host;
    assert(child.plan.count == child.plan.steps_expected());
    assert(child.ready.read != child.report.read); // Two distinct pipes.
    // The parent's ends of the pipes are closed here so that end of file reaches both sides.
    host.close(child.ready.write);
    host.close(child.report.read);
    var state: State = .{ .errno_override = 0, .failed_etc = 0 };
    for (child.plan.steps[0..child.plan.count], 0..) |*step, index| {
        if (plan_mod.side_of(step.kind) != .child) continue;
        if (skipped(step, &state)) continue;
        host.begin_step(@intCast(index));
        state.errno_override = 0;
        run_step(child, step, &state) catch |err| {
            if (err == error.ParentGone) return constants.child_exit_setup_failed;
            const raw = if (state.errno_override != 0) state.errno_override else host.last_errno();
            // A failure made inside host.zig has no errno; EIO stands for it.
            const errno = if (raw != 0) raw else constants.errno_io;
            const record: sync.Record = .{
                .kind = if (step.tolerant) .note else .failure,
                .step = @intCast(index),
                .errno = errno,
            };
            write_record(child, record);
            if (step.tolerant) {
                const group = plan_mod.group_of(step);
                if (group > 0) state.failed_etc |= @as(u8, 1) << @intCast(group - 1);
                continue;
            }
            return constants.child_exit_setup_failed;
        };
    }
    host.begin_step(host_mod.step_none);
    // Only the simulator gets here: the real host's `exec` never returns.
    assert(child.plan.steps[child.plan.count - 3].kind == .exec);
    return constants.exit_ok;
}

/// A step of a generated /etc file whose file already failed is not tried: the failure was
/// noted once. Removing the staged copy is the exception, since a copy left in /dev would
/// still be writable; it runs whatever happened before.
fn skipped(step: *const Step, state: *const State) bool {
    assert(plan_mod.side_of(step.kind) == .child);
    const group = plan_mod.group_of(step);
    assert(group <= 2);
    if (group == 0) return false;
    if (step.kind == .unstage_etc_file) return false;
    return state.failed_etc & (@as(u8, 1) << @intCast(group - 1)) != 0;
}

/// Tells the parent. If this write fails there is nobody to tell and nothing more to do: the
/// child ends with the setup-failure code either way.
fn write_record(child: *const Context, record: sync.Record) void {
    assert(record.step < child.plan.count);
    assert(record.errno != 0);
    const bytes = record.encode();
    child.host.write_handle_all(child.report.write, &bytes) catch return;
}

fn run_step(child: *const Context, step: *const Step, state: *State) Error!void {
    const host = child.host;
    const plan = child.plan;
    assert(plan_mod.side_of(step.kind) == .child);
    const target = plan.text(step.target);
    if (plan_mod.is_state(step.kind)) return run_state_step(host, plan, step, target);
    if (plan_mod.is_mount(step.kind)) return run_mount_step(host, plan, step, target);
    switch (step.kind) {
        .die_with_parent => try host.die_with_parent(),
        .await_release => try await_release(child),
        .set_hostname => try host.set_hostname(plan.hostname()),
        .make_mounts_private => try mount(host, .make_private, target, null),
        .bind_rootfs => try mount(host, .bind_tree, target, plan.text(step.source)),
        .mount_overlay => try mount(host, .overlay, target, plan.text(step.source)),
        .mount_proc => try mount(host, .proc, target, null),
        .mount_dev => try mount(host, .dev_tmpfs, target, null),
        .mount_shm => try mount(host, .shm_tmpfs, target, null),
        .mount_pts => try mount(host, .devpts, target, null),
        .bind_device => try mount(host, .bind_file, target, plan.text(step.source)),
        .make_proc_dir, .make_dev_dir => try host.make_directory(target, true),
        // The rootfs may already have them (Alpine has both): only a missing one is made.
        .make_tmp_dir, .make_run_dir => try host.make_directory(target, true),
        .mount_tmp => try mount(host, .tmp_tmpfs, target, null),
        .mount_run => try mount(host, .run_tmpfs, target, null),
        .remount_readonly => try mount(host, .remount_readonly, target, null),
        .restrict_capabilities => try host.restrict_capabilities(capabilities.keep_mask),
        .clear_ambient => try host.clear_ambient(),
        .set_no_new_privs => try host.no_new_privs(),
        .install_seccomp => try host.install_seccomp(&seccomp.program),
        .make_shm_dir, .make_pts_dir => try host.make_directory(target, false),
        .make_sys_dir => try host.make_directory(target, true),
        .bind_sys => try mount(host, .bind_tree, target, plan.text(step.source)),
        .bring_up_loopback => try host.bring_up_loopback(),
        .mount_sysfs => try mount(host, .sysfs, target, null),
        .make_etc_dir => try host.make_directory(target, true),
        .create_etc_file => try host.create_file(target, true),
        .stage_etc_file => try host.write_file_mode(target, plan.text(step.source), 0o644),
        .bind_etc_file => try mount(host, .bind_file, target, plan.text(step.source)),
        .remount_etc_file => try mount(host, .remount_readonly, target, null),
        .unstage_etc_file => try unstage(host, target),
        .remount_sys => try mount(host, .remount_readonly_tree, target, null),
        .enter_workdir => try enter_workdir(host, target),
        .set_user => try host.set_user(plan.user_uid, plan.user_gid),
        .create_device_file => try host.create_file(target, false),
        .link_dev => try host.symlink(plan.text(step.source), target),
        .enter_rootfs, .enter_new_root => try host.change_directory(target),
        .pivot_root => try host.pivot_root(target, plan.text(step.source)),
        .detach_old_root => try host.unmount_detach(target),
        .seal_descriptors => try host.seal_descriptors(),
        .exec => try exec(child, state),
        // Handled by `run_state_step` and `run_mount_step` above.
        .make_state_data, .make_state_stage, .bind_state, .remount_state => unreachable,
        .make_state_target, .move_state, .remove_state_stage => unreachable,
        .make_mount_stage_dir, .make_mount_stage_file, .copy_secret => unreachable,
        .bind_mount_dir, .bind_mount_file, .remount_mount, .remount_mount_tree => unreachable,
        .make_mount_target_dir, .make_mount_target_file, .move_mount => unreachable,
        .remove_mount_stage_dir, .remove_mount_stage_file, .mount_user_tmpfs => unreachable,
        .make_pipes, .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => unreachable,
        .run_newuidmap, .run_newgidmap, .spawn_keeper, .start_scope => unreachable,
        .start_pasta, .await_pasta => unreachable, // The parent's steps.
        .release_child, .await_report, .reap => unreachable, // The parent's steps.
    }
}

fn run_state_step(
    host: Host,
    plan: *const Plan,
    step: *const Step,
    target: [:0]const u8,
) host_mod.Error!void {
    assert(plan_mod.is_state(step.kind));
    switch (step.kind) {
        // The container's root makes the volume's `data` in its own user namespace, so that it
        // is the owner as the container sees it; an existing one is the volume's files.
        .make_state_data => try host.make_directory(target, true),
        .make_state_stage => try host.make_directory(target, false),
        .bind_state => try mount(host, .bind_tree, target, plan.text(step.source)),
        .remount_state => try mount(host, .remount_readonly, target, null),
        .make_state_target => try make_parents(host, target),
        .move_state => try mount(host, .move, target, plan.text(step.source)),
        .remove_state_stage => try host.remove_directory(target),
        else => unreachable, // `is_state` said so.
    }
}

fn run_mount_step(
    host: Host,
    plan: *const Plan,
    step: *const Step,
    target: [:0]const u8,
) host_mod.Error!void {
    assert(plan_mod.is_mount(step.kind));
    switch (step.kind) {
        .make_mount_stage_dir => try host.make_directory(target, false),
        .make_mount_stage_file => try host.create_file(target, false),
        .copy_secret => try copy_secret(host, plan.text(step.source), target),
        .bind_mount_dir => try mount(host, .bind_tree, target, plan.text(step.source)),
        .bind_mount_file => try mount(host, .bind_file, target, plan.text(step.source)),
        .remount_mount => try mount(host, .remount_readonly, target, null),
        .remount_mount_tree => try mount(host, .remount_readonly_tree, target, null),
        .make_mount_target_dir => try make_parents(host, target),
        .make_mount_target_file => try make_file_target(host, target),
        .move_mount => try mount(host, .move, target, plan.text(step.source)),
        .remove_mount_stage_dir => try host.remove_directory(target),
        .remove_mount_stage_file => try host.remove_file(target),
        .mount_user_tmpfs => try mount(host, .user_tmpfs, target, plan.text(step.source)),
        else => unreachable, // `is_mount` said so.
    }
}

/// Removes the staged copy of a generated file. A copy that was never written (the file's steps
/// stopped before) is not there, which is fine.
fn unstage(host: Host, target: [:0]const u8) host_mod.Error!void {
    assert(target.len > 0);
    assert(target[0] == '/');
    host.remove_file(target) catch |err| {
        if (err != error.NotFound) return err;
    };
}

/// Copies the host's file `source` to `target` (a new file in the container's /dev) with mode
/// 0400. The child is the container's root, so the copy is owned by it. The copy is the only
/// place the bytes are kept: this buffer, on the child's stack, is wiped when it is done.
fn copy_secret(host: Host, source: [:0]const u8, target: [:0]const u8) host_mod.Error!void {
    assert(source.len > 0);
    assert(target.len > 0);
    var bytes: [constants.secret_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    const content = try host.read_file(source, &bytes);
    assert(content.len <= constants.secret_bytes_max);
    try host.write_file_mode(target, content, 0o400);
}

/// Makes the file `target` and the directories above it that are missing; a file that is there
/// is left as it is (the mount covers it).
fn make_file_target(host: Host, target: [:0]const u8) host_mod.Error!void {
    assert(target.len > 1);
    assert(target[0] == '/');
    const slash = std.mem.lastIndexOfScalar(u8, target, '/').?;
    if (slash > 0) {
        var parent: [constants.path_bytes_max + 1]u8 = undefined;
        if (slash >= parent.len) return error.PathTooLong;
        @memcpy(parent[0..slash], target[0..slash]);
        parent[slash] = 0;
        try make_parents(host, parent[0..slash :0]);
    }
    try host.create_file(target, true);
}

/// Makes the directory and the ones above it that are missing, then goes there.
fn enter_workdir(host: Host, path: [:0]const u8) host_mod.Error!void {
    try make_parents(host, path);
    try host.change_directory(path);
}

/// Makes the directory and the ones above it that are missing. The prefixes are cut from the
/// path in a buffer on the stack: the child formats nothing and allocates nothing.
fn make_parents(host: Host, path: [:0]const u8) host_mod.Error!void {
    assert(path.len > 0);
    assert(path[0] == '/');
    var prefix: [constants.path_bytes_max + 1]u8 = undefined;
    if (path.len >= prefix.len) return error.PathTooLong;
    var at: usize = 1;
    while (at <= path.len) : (at += 1) {
        const end = at == path.len or path[at] == '/';
        if (!end) continue;
        @memcpy(prefix[0..at], path[0..at]);
        prefix[at] = 0;
        if (at > 1) try host.make_directory(prefix[0..at :0], true);
    }
}

fn mount(
    host: Host,
    kind: host_mod.MountKind,
    target: [:0]const u8,
    source: ?[:0]const u8,
) host_mod.Error!void {
    assert(target.len > 0);
    assert(target[0] != 0);
    const has_source = kind == .bind_tree or kind == .bind_file or kind == .overlay or
        kind == .move or kind == .user_tmpfs;
    assert((source != null) == has_source);
    try host.mount(.{ .kind = kind, .target = target, .source = source });
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

/// Tries each candidate path in turn, as a shell does for a name without a slash. A file that
/// is missing moves on to the next candidate; a file that is there but cannot be run is
/// reported over a missing one, since it is the more telling failure.
fn exec(child: *const Context, state: *State) Error!void {
    const plan = child.plan;
    assert(plan.candidates_count > 0);
    assert(plan.argv[0] != null);
    const argv: host_mod.CStrings = @ptrCast(&plan.argv);
    const envp: host_mod.CStrings = @ptrCast(&plan.envp);
    var missing: ?Error = null;
    var missing_errno: u16 = 0;
    var denied: ?Error = null;
    var denied_errno: u16 = 0;
    for (plan.candidate_slice()) |candidate| {
        const path = plan.text(candidate);
        child.host.exec(.{ .path = path, .argv = argv, .envp = envp }) catch |err| switch (err) {
            error.NotFound => {
                missing = err;
                missing_errno = child.host.last_errno();
                continue;
            },
            error.AccessDenied => {
                denied = err;
                denied_errno = child.host.last_errno();
                continue;
            },
            else => return err, // The file is there and cannot be run: that is the answer.
        };
        return; // The simulator's way of saying the command started.
    }
    if (denied) |err| {
        assert(denied_errno != 0);
        state.errno_override = denied_errno;
        return err;
    }
    // Every candidate was tried and none was there, so `missing` was set by the last of them.
    assert(missing_errno != 0);
    state.errno_override = missing_errno;
    return missing.?;
}
