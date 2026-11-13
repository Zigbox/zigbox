//! The child's side of the CDI devices (M10): the steps `bind_cdi_nodes`, `stage_cdi_mounts`,
//! `move_cdi_mounts` and `run_ldconfig` each loop over the items `Plan.cdi` holds. The child
//! formats nothing: the one number in a stage's name is cut into a stack buffer.
//!
//! A failure in an item is reported as `errno | index << 8` (`errno_with_index`), so that the
//! parent's diagnostic names the item. The errnos a kernel gives here are below 256.

const std = @import("std");
const assert = std.debug.assert;
const cdi = @import("cdi.zig");
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const plan_mod = @import("plan.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;
const Error = host_mod.Error;

/// What the step reports for an item that failed: the kernel's errno and the item's index.
pub fn errno_with_index(errno: u16, index: usize) u16 {
    assert(index < 256);
    assert(errno != 0);
    assert(errno < 256);
    return errno | @as(u16, @intCast(index)) << 8;
}

pub fn errno_of(report: u16) u16 {
    return report & 0xff;
}

pub fn index_of(report: u16) u32 {
    return report >> 8;
}

/// Runs `action`, and when it fails notes which item it was for.
fn fail_at(host: Host, err: Error, index: usize, override: *u16) Error {
    const errno = host.last_errno();
    const code = if (errno != 0 and errno < 256) errno else constants.errno_io;
    override.* = errno_with_index(code, index);
    return err;
}

const stage_buffer_bytes = constants.path_bytes_max + 1;

/// The stage name of mount `index` below `base` (the rootfs, or empty in the new root).
fn stage_name(buffer: *[stage_buffer_bytes]u8, base: []const u8, index: usize) ?[:0]const u8 {
    assert(index < constants.cdi_run_mounts_max);
    var digits: [3]u8 = undefined;
    var number = index;
    var count: usize = 0;
    while (true) {
        digits[count] = '0' + @as(u8, @intCast(number % 10));
        count += 1;
        number /= 10;
        if (number == 0) break;
    }
    const prefix = plan_mod.cdi_stage_prefix;
    const total = base.len + prefix.len + count;
    if (total >= buffer.len) return null;
    @memcpy(buffer[0..base.len], base);
    @memcpy(buffer[base.len..][0..prefix.len], prefix);
    for (0..count) |at| buffer[base.len + prefix.len + at] = digits[count - 1 - at];
    buffer[total] = 0;
    return buffer[0..total :0];
}

/// Each node made below the rootfs (a file to mount on, with its parents) and bound from the
/// host's node of the same path.
pub fn bind_nodes(host: Host, plan: *const Plan, override: *u16) Error!void {
    const resolved = plan.cdi.?;
    assert(resolved.nodes_count > 0);
    assert(resolved.nodes_count <= constants.cdi_run_nodes_max);
    const rootfs = plan.text(plan.cdi_rootfs);
    for (resolved.nodes[0..resolved.nodes_count], 0..) |node, index| {
        const path = resolved.text(node);
        var buffer: [stage_buffer_bytes]u8 = undefined;
        if (rootfs.len + path.len >= buffer.len) return error.PathTooLong;
        @memcpy(buffer[0..rootfs.len], rootfs);
        @memcpy(buffer[rootfs.len..][0..path.len], path);
        buffer[rootfs.len + path.len] = 0;
        const inside = buffer[0 .. rootfs.len + path.len :0];
        bind_node(host, inside, path) catch |err| return fail_at(host, err, index, override);
    }
}

fn bind_node(host: Host, inside: [:0]const u8, path: [:0]const u8) Error!void {
    assert(inside.len > path.len);
    assert(path[0] == '/');
    const slash = std.mem.lastIndexOfScalar(u8, inside, '/').?;
    try make_parents(host, inside[0..slash]);
    try host.create_file(inside, true);
    try host.mount(.{ .kind = .bind_file, .target = inside, .source = path });
}

/// Makes `path` and the directories above it that are missing, from a copy on the stack.
fn make_parents(host: Host, path: []const u8) Error!void {
    var prefix: [stage_buffer_bytes]u8 = undefined;
    if (path.len >= prefix.len) return error.PathTooLong;
    var at: usize = 1;
    while (at <= path.len) : (at += 1) {
        if (at != path.len and path[at] != '/') continue;
        @memcpy(prefix[0..at], path[0..at]);
        prefix[at] = 0;
        try host.make_directory(prefix[0..at :0], true);
    }
}

/// Each mount bound to a hidden name below the rootfs's /dev and made read-only, as a volume
/// is; it moves to its place once the new root is entered.
pub fn stage_mounts(host: Host, plan: *const Plan, override: *u16) Error!void {
    const resolved = plan.cdi.?;
    assert(resolved.mounts_count > 0);
    assert(resolved.mounts_count <= constants.cdi_run_mounts_max);
    const rootfs = plan.text(plan.cdi_rootfs);
    for (resolved.mounts[0..resolved.mounts_count], 0..) |item, index| {
        var buffer: [stage_buffer_bytes]u8 = undefined;
        const stage = stage_name(&buffer, rootfs, index) orelse return error.PathTooLong;
        const source = resolved.text(item.host);
        stage_mount(host, stage, source, resolved.mount_is_dir[index]) catch |err| {
            return fail_at(host, err, index, override);
        };
    }
}

fn stage_mount(host: Host, stage: [:0]const u8, source: [:0]const u8, is_dir: bool) Error!void {
    if (is_dir) {
        try host.make_directory(stage, false);
        try host.mount(.{ .kind = .bind_tree, .target = stage, .source = source });
        try host.mount(.{ .kind = .remount_readonly_tree, .target = stage, .source = null });
    } else {
        try host.create_file(stage, false);
        try host.mount(.{ .kind = .bind_file, .target = stage, .source = source });
        try host.mount(.{ .kind = .remount_readonly, .target = stage, .source = null });
    }
}

/// Each staged mount moved onto its path in the new root, which is made if it is not there, and
/// the hidden name removed.
pub fn move_mounts(host: Host, plan: *const Plan, override: *u16) Error!void {
    const resolved = plan.cdi.?;
    assert(resolved.mounts_count > 0);
    assert(resolved.mounts_count <= constants.cdi_run_mounts_max);
    for (resolved.mounts[0..resolved.mounts_count], 0..) |item, index| {
        var buffer: [stage_buffer_bytes]u8 = undefined;
        const stage = stage_name(&buffer, "", index) orelse return error.PathTooLong;
        const target = resolved.text(item.container);
        move_mount(host, stage, target, resolved.mount_is_dir[index]) catch |err| {
            return fail_at(host, err, index, override);
        };
    }
}

fn move_mount(host: Host, stage: [:0]const u8, target: [:0]const u8, is_dir: bool) Error!void {
    if (is_dir) {
        try make_parents(host, target);
    } else {
        const slash = std.mem.lastIndexOfScalar(u8, target, '/').?;
        if (slash > 0) try make_parents(host, target[0..slash]);
        try host.create_file(target, true);
    }
    try host.mount(.{ .kind = .move, .target = target, .source = stage });
    if (is_dir) try host.remove_directory(stage) else try host.remove_file(stage);
}

const ldconfig_paths = [_][:0]const u8{ "/sbin/ldconfig", "/usr/sbin/ldconfig" };

/// The image's own `ldconfig`, given the directories, so that the libraries the mounts brought
/// are found. An image without one, or one that fails, is a note, and the command gets
/// `LD_LIBRARY_PATH` instead (`exec` reads `State.ld_failed`).
pub fn run_ldconfig(host: Host, plan: *const Plan, override: *u16) Error!void {
    const resolved = plan.cdi.?;
    assert(resolved.dirs_count > 0);
    assert(resolved.dirs_count <= constants.cdi_run_dirs_max);
    var argv: [constants.cdi_run_dirs_max + 2]?[*:0]const u8 = undefined;
    argv[0] = "ldconfig";
    for (resolved.dirs[0..resolved.dirs_count], 1..) |dir, at| argv[at] = resolved.text(dir).ptr;
    argv[resolved.dirs_count + 1] = null;
    var output: [64]u8 = undefined;
    var last: Error = error.NotFound;
    for (ldconfig_paths) |path| {
        const request: host_mod.ExecRequest = .{
            .path = path,
            .argv = @ptrCast(&argv),
            .envp = @ptrCast(&plan.envp),
            .timeout_seconds = constants.cdi_ldconfig_seconds_max,
        };
        const result = host.run_helper(request, &output) catch |err| {
            last = err;
            continue;
        };
        // A killed run is a failed one, even when the helper itself had ended with 0.
        if (!result.timed_out) switch (result.status) {
            .exited => |code| if (code == 0) return,
            .signaled => {},
        };
        override.* = constants.errno_io;
        return error.IoFailed;
    }
    return last;
}
