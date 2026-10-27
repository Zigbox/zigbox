//! The plan: everything a container run does, as a fixed list of steps built by a pure function
//! from the run's input (docs/briefs/M1-shell.md, "Setup as a plan").
//!
//! The list interleaves the two processes in the order things happen: the parent creates the
//! pipes and the child (`spawn`), writes the id maps and lets the child go; the child sets up the
//! container and runs the command; the parent collects the child's report and waits. Each step
//! belongs to one side (`side_of`) and is one call into `host.zig` (a few are two tiny ones), so
//! the simulator can fail exactly one step and the diagnostic can name it by its index and kind.
//!
//! Everything the child needs is made here, in the parent, before `spawn`: every path, the map
//! lines, the hostname, and the whole exec image (argv, environment and the path candidates).
//! The child therefore never allocates or formats text. The plan holds pointers into itself
//! (the exec image), so it is built in place and never moved or copied.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const spec = @import("spec.zig");

pub const Side = enum { parent, child };

/// What a step does. Parent steps first in the declaration, then the child's.
pub const Kind = enum {
    // The parent.
    make_pipes,
    spawn,
    deny_setgroups,
    write_gid_map,
    write_uid_map,
    run_newuidmap,
    run_newgidmap,
    /// In a plan built with a scope: forks the scope's keeper (`Host.start_keeper`), which is
    /// put in the scope beside the container so that the scope cannot be removed while zbx
    /// has still to read its counters.
    spawn_keeper,
    /// Asks the user's systemd manager for the container's scope and waits for its job; only in
    /// a plan built with a scope.
    start_scope,
    release_child,
    await_report,
    reap,
    // The child.
    die_with_parent,
    await_release,
    set_hostname,
    make_mounts_private,
    bind_rootfs,
    /// In a plan that runs a tree from the store: the overlay replaces the bind of a rootfs.
    mount_overlay,
    make_proc_dir,
    mount_proc,
    make_dev_dir,
    mount_dev,
    create_device_file,
    bind_device,
    make_shm_dir,
    mount_shm,
    make_pts_dir,
    mount_pts,
    link_dev,
    /// The host's /sys bound read-only (the M4 decision, until M5's network namespace gives the
    /// container a sysfs of its own). Tolerant: a host that will not bind it gives a container
    /// without /sys, with a note.
    make_sys_dir,
    bind_sys,
    remount_sys,
    /// Only in a plan with a working directory: makes it (and its parents) if the image lacks
    /// it, and goes there. After the new root is entered.
    enter_workdir,
    /// Only in a read-only plan: scratch space on tmpfs, then the rootfs itself read-only.
    make_tmp_dir,
    mount_tmp,
    make_run_dir,
    mount_run,
    remount_readonly,
    enter_rootfs,
    pivot_root,
    detach_old_root,
    enter_new_root,
    seal_descriptors,
    /// The hardening, in the order the kernel needs it: capabilities first (dropping the bounding
    /// set needs CAP_SETPCAP), then `no_new_privs` (a filter needs it once CAP_SYS_ADMIN is
    /// gone), and the filter last, so that it is the last thing the child does but `execve`.
    restrict_capabilities,
    clear_ambient,
    /// Only in a plan for an image that runs as a user: becomes that user and group, after the
    /// capabilities are restricted (so the bounding set is already as it will stay) and before
    /// the filter.
    set_user,
    set_no_new_privs,
    install_seccomp,
    exec,
};

pub fn side_of(kind: Kind) Side {
    const side: Side = switch (kind) {
        .make_pipes, .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => .parent,
        .run_newuidmap, .run_newgidmap, .spawn_keeper, .start_scope => .parent,
        .release_child, .await_report, .reap => .parent,
        else => .child,
    };
    // The kinds are declared parent first, so the order of the enum says which side a kind is.
    assert((side == .parent) == (@backingInt(kind) <= @backingInt(Kind.reap)));
    return side;
}

/// The devices bound from the host into the container's `/dev`.
pub const devices = [constants.container_devices_count][]const u8{
    "null", "zero", "full", "random", "urandom", "tty",
};

pub const Link = struct {
    name: []const u8,
    target: []const u8,
};

/// The symlinks of the container's `/dev`. `ptmx` points into the private devpts.
pub const links = [constants.container_links_count]Link{
    .{ .name = "fd", .target = "/proc/self/fd" },
    .{ .name = "stdin", .target = "/proc/self/fd/0" },
    .{ .name = "stdout", .target = "/proc/self/fd/1" },
    .{ .name = "stderr", .target = "/proc/self/fd/2" },
    .{ .name = "ptmx", .target = "pts/ptmx" },
};

/// The child's steps: twenty-six that happen once (four of them the hardening, three the /sys),
/// and two per device and one per link. A read-only plan has `read_only_steps_count` more, one
/// with a working directory, one with a user.
pub const child_steps_count: u32 = 26 + 2 * constants.container_devices_count +
    constants.container_links_count;

/// The steps a scope adds to the parent's: the keeper and the scope itself.
pub const scope_steps_count: u32 = 2;

/// The steps a read-only rootfs adds: `/tmp` and `/run` on tmpfs, and the remount.
pub const read_only_steps_count: u32 = 5;

/// Steps of a plan with the single-id map: the parent has eight (it denies setgroups and
/// writes both maps itself), the child has `child_steps_count`.
pub const steps_count_single: u32 = 8 + child_steps_count;

/// Steps of a plan that uses the helpers: the parent has seven (one step per helper). A plan with
/// a scope has two more (the keeper and the scope), whichever map it uses.
pub const steps_count_full: u32 = 7 + child_steps_count;

/// How the container's ids are mapped to the host's.
pub const Mapping = union(enum) {
    /// Only the container's root, to the user's own id. Written directly, with setgroups denied.
    single,
    /// Root to the user's own id, and ids 1 to 65536 to a range of subordinate ids, written by
    /// the setuid helpers.
    full: Helpers,
};

pub const Helpers = struct {
    /// Paths of `newuidmap` and `newgidmap`.
    newuidmap: []const u8,
    newgidmap: []const u8,
    /// The first subordinate id of the range for users and for groups.
    uid_start: u32,
    gid_start: u32,
};

/// A string stored in the plan's text area. NUL-terminated there, `len` without the NUL.
pub const Text = struct {
    offset: u32,
    len: u32,
};

pub const Step = struct {
    kind: Kind,
    /// The step's main text: a path, or for the map steps the bytes to write.
    target: Text,
    /// A second text: the source of a bind, the destination of a link.
    source: Text,
    /// Which device or link the step is about.
    index: u8,
    /// A failure of this step is noted and the run goes on (the devpts mount).
    tolerant: bool,
};

/// What a scoped run needs from the user's systemd manager: the version it reported (which
/// decides unit property or cgroupfs file for each limit) and the limits.
pub const ScopeInput = struct {
    version: u32,
    limits: spec.Limits,
};

pub const User = spec.User;

pub const Input = struct {
    rootfs: []const u8,
    name: []const u8,
    command: []const []const u8,
    term: ?[]const u8,
    /// The user and group ids of zbx itself, the ones the container's root maps to.
    uid: u32,
    gid: u32,
    mapping: Mapping,
    /// Null: no scope, as in M1 (no `start_scope` step, and no limits).
    scope: ?ScopeInput = null,
    /// The rootfs is remounted read-only, with tmpfs at `/tmp` and `/run`.
    read_only: bool = false,
    /// Added to the container's environment, replacing a default of the same name.
    env: []const spec.Label = &.{},
    /// The directory the command starts in; made if the image lacks it. Empty: the root.
    workdir: []const u8 = "",
    /// The user and group the command runs as; null (or 0 and 0) leaves it root.
    user: ?User = null,
    /// Set for a run of a tree from the store: `rootfs` is then the empty directory the overlay
    /// is mounted on, and the layers are these.
    overlay: ?Overlay = null,
};

/// The layers of an overlay (docs/briefs/M3-store.md, "Materialize and run"). The lower layer
/// is the tree's materialized directory and is never written: a container's writes go to the
/// upper layer by copy-up. A read-only run has no upper layer (and no work directory); the
/// kernel wants two lower layers then, so the second is an empty directory.
pub const Overlay = struct {
    lower: []const u8,
    upper: ?[]const u8,
    work: ?[]const u8,
    /// An empty directory; set exactly when there is no upper layer.
    empty: ?[]const u8,
};

const empty_text: Text = .{ .offset = 0, .len = 0 };

pub const Plan = struct {
    steps: [constants.plan_steps_max]Step,
    count: u32,
    /// Whether the ids are mapped through the helpers (`Mapping.full`).
    full: bool,
    /// Whether the rootfs is remounted read-only.
    read_only: bool,
    /// Whether the rootfs is an overlay of a tree from the store.
    overlay: bool,
    /// Whether the command starts in a working directory, and whether it runs as a user.
    has_workdir: bool,
    workdir: Text,
    has_user: bool,
    user_uid: u32,
    user_gid: u32,
    /// Whether the plan has a `start_scope` step, and what it is made with.
    scoped: bool,
    scope_name: Text,
    scope_description: Text,
    scope_version: u32,
    scope_limits: spec.Limits,
    paths: [constants.plan_paths_bytes_max]u8,
    paths_len: u32,
    name: Text,
    /// Where the command is looked for: its own path if it has a slash, else one path per
    /// directory of the container's PATH.
    candidates: [constants.candidates_max]Text,
    candidates_count: u32,
    strings: [constants.exec_strings_bytes_max]u8,
    strings_len: u32,
    argv: [constants.command_words_count_max + 1]?[*:0]const u8,
    envp: [constants.environment_count_max + constants.env_vars_count_max + 1]?[*:0]const u8,

    /// Builds the plan in place. The input must have passed the checks in `spec.zig`.
    pub fn build(plan: *Plan, input: *const Input) void {
        assert(spec.rootfs_problem(input.rootfs) == null);
        assert(spec.name_problem(input.name) == null);
        assert(spec.command_problem(input.command) == null);
        assert(spec.env_problem(input.env, input.command) == null);
        plan.count = 0;
        plan.full = input.mapping == .full;
        plan.scoped = input.scope != null;
        plan.read_only = input.read_only;
        plan.overlay = input.overlay != null;
        plan.has_workdir = input.workdir.len > 0;
        plan.has_user = if (input.user) |user| user.uid != 0 or user.gid != 0 else false;
        plan.user_uid = if (input.user) |user| user.uid else 0;
        plan.user_gid = if (input.user) |user| user.gid else 0;
        plan.paths_len = 0;
        plan.strings_len = 0;
        plan.candidates_count = 0;
        // Offset 0 is the empty text, so a step with nothing to say has a valid reference.
        assert(plan.add_text(&.{""}).offset == 0);
        plan.name = plan.add_text(&.{input.name});
        plan.workdir = plan.add_text(&.{input.workdir});
        plan.build_scope(input);
        plan.build_exec_image(input);
        plan.push_parent_start(input);
        assert(plan.count == plan.first_child());
        plan.push_child_steps(input.rootfs, input.overlay);
        plan.push(.await_report, empty_text, empty_text, 0);
        plan.push(.reap, empty_text, empty_text, 0);
        assert(plan.count == plan.steps_expected());
        plan.check();
    }

    /// Structural invariants of a built plan, also checked by the tests and the fuzzer.
    pub fn check(plan: *const Plan) void {
        assert(plan.count == plan.steps_expected());
        assert(plan.count <= constants.plan_steps_max);
        assert(plan.steps[0].kind == .make_pipes);
        assert(plan.steps[1].kind == .spawn);
        assert(plan.steps[plan.count - 1].kind == .reap);
        assert(plan.steps[plan.count - 2].kind == .await_report);
        // The child's steps are one contiguous run, between `release_child` and `await_report`.
        const child_start = plan.first_child();
        assert(plan.steps[child_start - 1].kind == .release_child);
        assert((plan.steps[child_start - 2].kind == .start_scope) == plan.scoped);
        assert((plan.steps[child_start - 3].kind == .spawn_keeper) == plan.scoped);
        for (plan.steps[0..child_start]) |step| assert(side_of(step.kind) == .parent);
        for (plan.steps[child_start .. plan.count - 2]) |step| {
            assert(side_of(step.kind) == .child);
        }
        assert(plan.steps[plan.count - 3].kind == .exec);
        // The exec image points into the plan itself: a copy of the plan would break it.
        const first_argument = plan.argv[0].?;
        assert(@intFromPtr(first_argument) >= @intFromPtr(&plan.strings[0]));
        assert(@intFromPtr(first_argument) < @intFromPtr(&plan.strings[0]) + plan.strings.len);
        assert(plan.candidates_count > 0);
    }

    pub fn steps_expected(plan: *const Plan) u32 {
        assert(plan.count <= constants.plan_steps_max);
        const base = if (plan.full) steps_count_full else steps_count_single;
        const read_only: u32 = if (plan.read_only) read_only_steps_count else 0;
        const extras: u32 = @as(u32, @intFromBool(plan.has_workdir)) + @intFromBool(plan.has_user);
        return base + scope_steps_count * @intFromBool(plan.scoped) + read_only + extras;
    }

    /// The index of the first of the child's steps: after the parent's start, which ends with
    /// `release_child`.
    pub fn first_child(plan: *const Plan) u32 {
        assert(plan.count <= constants.plan_steps_max);
        const parent: u32 = if (plan.full) 5 else 6;
        return parent + scope_steps_count * @intFromBool(plan.scoped);
    }

    /// The unit name and description of a scoped plan: "zbx-<name>.scope" and "zbx: <name>".
    fn build_scope(plan: *Plan, input: *const Input) void {
        plan.scope_name = empty_text;
        plan.scope_description = empty_text;
        plan.scope_version = 0;
        plan.scope_limits = .{};
        const scope = input.scope orelse return;
        assert(scope.version > 0);
        assert(spec.limits_problem(scope.limits) == null);
        const parts = [_][]const u8{ constants.scope_prefix, input.name, constants.scope_suffix };
        plan.scope_name = plan.add_text(&parts);
        plan.scope_description = plan.add_text(&.{ "zbx: ", input.name });
        plan.scope_version = scope.version;
        plan.scope_limits = scope.limits;
        assert(plan.text(plan.scope_name).len <= constants.scope_name_bytes_max);
    }

    pub fn text(plan: *const Plan, ref: Text) [:0]const u8 {
        assert(ref.offset + ref.len < plan.paths_len);
        assert(plan.paths[ref.offset + ref.len] == 0);
        return plan.paths[ref.offset..][0..ref.len :0];
    }

    pub fn hostname(plan: *const Plan) []const u8 {
        const name = plan.text(plan.name);
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        return name;
    }

    pub fn candidate_slice(plan: *const Plan) []const Text {
        assert(plan.candidates_count > 0);
        assert(plan.candidates_count <= plan.candidates.len);
        return plan.candidates[0..plan.candidates_count];
    }

    /// Appends the parts as one NUL-terminated text. There is always room: the inputs are
    /// bounded by `spec.zig` and the arena by a comptime relationship in `constants.zig`.
    fn add_text(plan: *Plan, parts: []const []const u8) Text {
        var length: u32 = 0;
        for (parts) |part| length += @intCast(part.len);
        assert(plan.paths_len + length + 1 <= plan.paths.len);
        const offset = plan.paths_len;
        var at = offset;
        for (parts) |part| {
            @memcpy(plan.paths[at..][0..part.len], part);
            at += @intCast(part.len);
        }
        plan.paths[at] = 0;
        plan.paths_len = at + 1;
        assert(at - offset == length);
        return .{ .offset = offset, .len = length };
    }

    fn push(plan: *Plan, kind: Kind, target: Text, source: Text, index: u8) void {
        assert(plan.count < constants.plan_steps_max);
        assert(target.offset + target.len < plan.paths_len);
        assert(source.offset + source.len < plan.paths_len);
        plan.steps[plan.count] = .{
            .kind = kind,
            .target = target,
            .source = source,
            .index = index,
            .tolerant = kind == .mount_pts or kind == .bind_sys or kind == .remount_sys,
        };
        plan.count += 1;
    }

    fn push_parent_start(plan: *Plan, input: *const Input) void {
        plan.push(.make_pipes, empty_text, empty_text, 0);
        plan.push(.spawn, empty_text, empty_text, 0);
        switch (input.mapping) {
            .single => plan.push_direct_maps(input),
            .full => |helpers| plan.push_helper_maps(input, helpers),
        }
        // The scope exists before the child may run its first step, and so before its command;
        // the keeper is forked first, so that it can be put in the scope with the child.
        if (plan.scoped) plan.push(.spawn_keeper, empty_text, empty_text, 0);
        if (plan.scoped) plan.push(.start_scope, plan.scope_name, plan.scope_description, 0);
        plan.push(.release_child, empty_text, empty_text, 0);
        assert(plan.steps[plan.count - 1].kind == .release_child);
        assert(side_of(plan.steps[plan.count - 1].kind) == .parent);
    }

    /// The parent writes the maps itself: setgroups denied first, then the group and user map.
    fn push_direct_maps(plan: *Plan, input: *const Input) void {
        var line: [constants.id_map_line_bytes_max]u8 = undefined;
        plan.push(.deny_setgroups, plan.add_text(&.{"deny"}), empty_text, 0);
        // Cannot fail: "0 4294967295 1\n" is 15 bytes and the buffer is 32.
        const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{input.gid}) catch unreachable;
        plan.push(.write_gid_map, plan.add_text(&.{gid_line}), empty_text, 0);
        // Cannot fail: same bound as above.
        const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{input.uid}) catch unreachable;
        plan.push(.write_uid_map, plan.add_text(&.{uid_line}), empty_text, 0);
    }

    /// The helpers write them: each is told the child's pid when it runs, and these words.
    fn push_helper_maps(plan: *Plan, input: *const Input, helpers: Helpers) void {
        var words: [constants.helper_map_bytes_max]u8 = undefined;
        const range = constants.subid_range_min;
        const format = "0 {d} 1 1 {d} {d}";
        // Cannot fail: six numbers of at most ten digits and the spaces fit 64 bytes.
        const uid_words = std.fmt.bufPrint(
            &words,
            format,
            .{ input.uid, helpers.uid_start, range },
        ) catch
            unreachable; // Same bound as above.
        plan.push(
            .run_newuidmap,
            plan.add_text(&.{helpers.newuidmap}),
            plan.add_text(&.{uid_words}),
            0,
        );
        // Cannot fail: same bound as above.
        const gid_words = std.fmt.bufPrint(
            &words,
            format,
            .{ input.gid, helpers.gid_start, range },
        ) catch
            unreachable; // Same bound as above.
        plan.push(
            .run_newgidmap,
            plan.add_text(&.{helpers.newgidmap}),
            plan.add_text(&.{gid_words}),
            0,
        );
    }

    fn push_child_steps(plan: *Plan, rootfs_text: []const u8, overlay: ?Overlay) void {
        assert(plan.count == plan.first_child()); // After the parent's start.
        assert(rootfs_text.len > 0);
        const rootfs = plan.add_text(&.{rootfs_text});
        const dev = plan.add_text(&.{ rootfs_text, "/dev" });
        const proc = plan.add_text(&.{ rootfs_text, "/proc" });
        plan.push(.die_with_parent, empty_text, empty_text, 0);
        plan.push(.await_release, empty_text, empty_text, 0);
        plan.push(.set_hostname, plan.name, empty_text, 0);
        plan.push(.make_mounts_private, plan.add_text(&.{"/"}), empty_text, 0);
        if (overlay) |layers| {
            plan.push(.mount_overlay, rootfs, plan.overlay_options(layers), 0);
        } else {
            plan.push(.bind_rootfs, rootfs, rootfs, 0);
        }
        plan.push(.make_proc_dir, proc, empty_text, 0);
        plan.push(.mount_proc, proc, empty_text, 0);
        plan.push(.make_dev_dir, dev, empty_text, 0);
        plan.push(.mount_dev, dev, empty_text, 0);
        plan.push_devices(rootfs_text);
        plan.push_dev_mounts(rootfs_text);
        plan.push_links(rootfs_text);
        plan.push_sys(rootfs_text);
        if (plan.read_only) plan.push_read_only(rootfs, rootfs_text);
        const here = plan.add_text(&.{"."});
        plan.push(.enter_rootfs, rootfs, empty_text, 0);
        plan.push(.pivot_root, here, here, 0);
        plan.push(.detach_old_root, here, empty_text, 0);
        plan.push(.enter_new_root, plan.add_text(&.{"/"}), empty_text, 0);
        if (plan.has_workdir) plan.push(.enter_workdir, plan.workdir, empty_text, 0);
        plan.push(.seal_descriptors, empty_text, empty_text, 0);
        plan.push(.restrict_capabilities, empty_text, empty_text, 0);
        plan.push(.clear_ambient, empty_text, empty_text, 0);
        if (plan.has_user) plan.push(.set_user, empty_text, empty_text, 0);
        plan.push(.set_no_new_privs, empty_text, empty_text, 0);
        plan.push(.install_seccomp, empty_text, empty_text, 0);
        plan.push(.exec, empty_text, empty_text, 0);
        assert(plan.steps[plan.count - 1].kind == .exec);
        assert(plan.count == plan.steps_expected() - 2); // The parent's two last steps remain.
    }

    /// The mount data of an overlay: `userxattr` (a mount made from a user namespace keeps its
    /// metadata in user.* attributes), then the layers. The paths hold no comma, colon or
    /// backslash (`spec.overlay_path_problem`), which the kernel would read as separators.
    fn overlay_options(plan: *Plan, layers: Overlay) Text {
        assert(spec.overlay_path_problem(layers.lower) == null);
        assert((layers.upper == null) == (layers.work == null));
        assert((layers.upper == null) == (layers.empty != null));
        if (layers.upper) |upper| {
            assert(spec.overlay_path_problem(upper) == null);
            assert(spec.overlay_path_problem(layers.work.?) == null);
            const work = layers.work.?;
            return plan.add_text(&.{
                "userxattr,lowerdir=", layers.lower, ",upperdir=", upper, ",workdir=", work,
            });
        }
        assert(spec.overlay_path_problem(layers.empty.?) == null);
        return plan.add_text(&.{ "userxattr,lowerdir=", layers.lower, ":", layers.empty.? });
    }

    /// `/tmp` and `/run` as tmpfs (their mount points are made first, while the rootfs is still
    /// writable), then the rootfs bind mount read-only.
    fn push_read_only(plan: *Plan, rootfs: Text, rootfs_text: []const u8) void {
        assert(plan.read_only);
        assert(rootfs_text.len > 0);
        const start = plan.count;
        defer assert(plan.count == start + read_only_steps_count);
        const tmp = plan.add_text(&.{ rootfs_text, "/tmp" });
        const run = plan.add_text(&.{ rootfs_text, "/run" });
        plan.push(.make_tmp_dir, tmp, empty_text, 0);
        plan.push(.mount_tmp, tmp, empty_text, 0);
        plan.push(.make_run_dir, run, empty_text, 0);
        plan.push(.mount_run, run, empty_text, 0);
        plan.push(.remount_readonly, rootfs, empty_text, 0);
    }

    fn push_devices(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + 2 * constants.container_devices_count);
        for (devices, 0..) |name, index| {
            const inside = plan.add_text(&.{ rootfs, "/dev/", name });
            const outside = plan.add_text(&.{ "/dev/", name });
            plan.push(.create_device_file, inside, empty_text, @intCast(index));
            plan.push(.bind_device, inside, outside, @intCast(index));
        }
    }

    fn push_dev_mounts(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + 4);
        const shm = plan.add_text(&.{ rootfs, "/dev/shm" });
        const pts = plan.add_text(&.{ rootfs, "/dev/pts" });
        plan.push(.make_shm_dir, shm, empty_text, 0);
        plan.push(.mount_shm, shm, empty_text, 0);
        plan.push(.make_pts_dir, pts, empty_text, 0);
        plan.push(.mount_pts, pts, empty_text, 0);
    }

    /// The host's /sys, bound recursively and made read-only.
    fn push_sys(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + 3);
        const inside = plan.add_text(&.{ rootfs, "/sys" });
        plan.push(.make_sys_dir, inside, empty_text, 0);
        plan.push(.bind_sys, inside, plan.add_text(&.{"/sys"}), 0);
        plan.push(.remount_sys, inside, empty_text, 0);
    }

    fn push_links(plan: *Plan, rootfs: []const u8) void {
        const start = plan.count;
        defer assert(plan.count == start + constants.container_links_count);
        for (links, 0..) |link, index| {
            const inside = plan.add_text(&.{ rootfs, "/dev/", link.name });
            const target = plan.add_text(&.{link.target});
            plan.push(.link_dev, inside, target, @intCast(index));
        }
    }

    // ---- The exec image ----

    fn add_string(plan: *Plan, parts: []const []const u8) [*:0]const u8 {
        var length: u32 = 0;
        for (parts) |part| length += @intCast(part.len);
        assert(length <= constants.exec_strings_bytes_max);
        assert(plan.strings_len + length + 1 <= plan.strings.len);
        const start = plan.strings_len;
        var at = start;
        for (parts) |part| {
            @memcpy(plan.strings[at..][0..part.len], part);
            at += @intCast(part.len);
        }
        plan.strings[at] = 0;
        plan.strings_len = at + 1;
        assert(at - start == length);
        return @ptrCast(&plan.strings[start]);
    }

    fn build_exec_image(plan: *Plan, input: *const Input) void {
        for (input.command, 0..) |word, index| plan.argv[index] = plan.add_string(&.{word});
        plan.argv[input.command.len] = null;
        var count: usize = 0;
        const path_variable = "PATH=" ++ constants.container_path;
        if (!overridden(input.env, "PATH")) {
            plan.envp[count] = plan.add_string(&.{path_variable});
            count += 1;
        }
        if (!overridden(input.env, "HOME")) {
            plan.envp[count] = plan.add_string(&.{"HOME=/root"});
            count += 1;
        }
        if (!overridden(input.env, "HOSTNAME")) {
            plan.envp[count] = plan.add_string(&.{ "HOSTNAME=", input.name });
            count += 1;
        }
        if (input.term) |term| {
            assert(term.len <= constants.term_bytes_max);
            if (!overridden(input.env, "TERM")) {
                plan.envp[count] = plan.add_string(&.{ "TERM=", term });
                count += 1;
            }
        }
        assert(count <= constants.environment_count_max);
        for (input.env) |variable| {
            plan.envp[count] = plan.add_string(&.{ variable.key, "=", variable.value });
            count += 1;
        }
        plan.envp[count] = null;
        assert(count <= constants.environment_count_max + constants.env_vars_count_max);
        plan.build_candidates(input.command[0], search_path_of(input.env));
    }

    /// The PATH a program is looked for in: the image's if the caller set one, else the default.
    fn search_path_of(env: []const spec.Label) []const u8 {
        for (env) |variable| {
            if (std.mem.eql(u8, variable.key, "PATH") and variable.value.len > 0) {
                return variable.value;
            }
        }
        return constants.container_path;
    }

    fn overridden(env: []const spec.Label, name: []const u8) bool {
        assert(name.len > 0);
        for (env) |variable| {
            if (std.mem.eql(u8, variable.key, name)) return true;
        }
        return false;
    }

    /// A program with a slash in its name is run as named; any other is looked up in the
    /// container's PATH, in order, as a shell does.
    fn build_candidates(plan: *Plan, program: []const u8, search_path: []const u8) void {
        assert(program.len > 0);
        if (std.mem.indexOfScalar(u8, program, '/') != null) {
            plan.candidates[0] = plan.add_text(&.{program});
            plan.candidates_count = 1;
            return;
        }
        var directories = std.mem.splitScalar(u8, search_path, ':');
        while (directories.next()) |directory| {
            if (directory.len == 0 or directory[0] != '/') continue;
            if (plan.candidates_count == constants.candidates_max) break;
            // The image's own PATH may be long and the words long: the room is checked.
            const room = plan.paths.len - plan.paths_len;
            if (directory.len + 1 + program.len + 1 + 1024 > room) break;
            plan.candidates[plan.candidates_count] = plan.add_text(&.{ directory, "/", program });
            plan.candidates_count += 1;
        }
        assert(plan.candidates_count > 0);
        if (search_path.ptr == constants.container_path.ptr) {
            assert(plan.candidates_count == constants.container_path_dirs_count);
        }
    }
};

// ---- Naming a step ----

/// A short phrase for the step, for the cause line of a diagnostic: "mounting a fresh /proc".
/// Formats into `buffer`, so it is for the parent only.
pub fn describe(step: *const Step, buffer: []u8) []const u8 {
    assert(buffer.len >= 128);
    const name = switch (step.kind) {
        .create_device_file, .bind_device => devices[step.index],
        .link_dev => links[step.index].name,
        else => "",
    };
    const phrase: []const u8 = switch (step.kind) {
        .make_pipes => "creating the pipes between zbx and the container",
        .spawn => "creating the container's namespaces",
        .deny_setgroups => "denying setgroups in the container's user namespace",
        .write_gid_map => "writing the container's gid map",
        .write_uid_map => "writing the container's uid map",
        .run_newuidmap => "running newuidmap to write the container's uid map",
        .run_newgidmap => "running newgidmap to write the container's gid map",
        .spawn_keeper => "starting the process that keeps the container's cgroup scope alive",
        .start_scope => "starting the container's cgroup scope",
        .release_child => "letting the container continue",
        .await_report => "waiting for the container to start its command",
        .reap => "waiting for the container to end",
        .die_with_parent => "asking the kernel to end the container if zbx dies",
        .await_release => "waiting for zbx to write the container's id maps",
        .set_hostname => "setting the container's hostname",
        .make_mounts_private => "making the container's mounts private",
        .bind_rootfs => "bind-mounting the rootfs onto itself",
        .mount_overlay => "mounting the overlay filesystem of the tree",
        .make_proc_dir => "creating /proc in the rootfs",
        .mount_proc => "mounting a fresh /proc",
        .make_dev_dir => "creating /dev in the rootfs",
        .mount_dev => "mounting a tmpfs on /dev",
        .make_shm_dir => "creating /dev/shm",
        .mount_shm => "mounting a tmpfs on /dev/shm",
        .make_pts_dir => "creating /dev/pts",
        .mount_pts => "mounting devpts on /dev/pts",
        .make_sys_dir => "creating /sys in the rootfs",
        .bind_sys => "binding the host's /sys",
        .remount_sys => "making /sys read-only",
        .enter_workdir => "entering the image's working directory",
        .set_user => "becoming the image's user",
        .enter_rootfs => "entering the rootfs directory",
        .pivot_root => "pivot_root into the rootfs",
        .detach_old_root => "unmounting the old root",
        .enter_new_root => "changing to the new root",
        .seal_descriptors => "closing the descriptors the command must not inherit",
        .exec => "starting the command",
        .create_device_file => "creating the mount point /dev/",
        .bind_device => "bind-mounting /dev/",
        .link_dev => "creating the link /dev/",
        .make_tmp_dir => "creating /tmp in the rootfs",
        .mount_tmp => "mounting a tmpfs on /tmp",
        .make_run_dir => "creating /run in the rootfs",
        .mount_run => "mounting a tmpfs on /run",
        .remount_readonly => "making the rootfs read-only",
        .restrict_capabilities => "dropping the capabilities the container does not keep",
        .clear_ambient => "clearing the ambient capabilities",
        .set_no_new_privs => "setting no_new_privs",
        .install_seccomp => "installing the seccomp filter",
    };
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ phrase, name }) catch phrase;
}

comptime {
    assert(steps_count_single <= constants.plan_steps_max);
    assert(steps_count_full + 1 == steps_count_single);
    assert(devices.len == constants.container_devices_count);
    assert(links.len == constants.container_links_count);
    // The failure record names a step in one byte, and a step's kind must be nameable too.
    assert(steps_count_single <= std.math.maxInt(u8));
    assert(std.meta.fieldNames(Kind).len <= 64);
}

const testing = std.testing;

fn test_input(command: []const []const u8) Input {
    return .{
        .rootfs = "/srv/alpine",
        .name = "web-1",
        .command = command,
        .term = "xterm",
        .uid = 1000,
        .gid = 1001,
        .mapping = .single,
    };
}

const test_helpers: Helpers = .{
    .newuidmap = "/usr/bin/newuidmap",
    .newgidmap = "/usr/bin/newgidmap",
    .uid_start = 100000,
    .gid_start = 200000,
};

test "with the helpers the parent has one step per map, and the words are the ranges" {
    // Goal: the full mapping's plan. It has one step fewer than the single-id plan (no
    // setgroups), the helper steps come first after spawn, and each carries the helper's path and
    // "0 <own id> 1 1 <first subordinate id> 65536".
    var plan: Plan = undefined;
    var input = test_input(&.{"sh"});
    input.mapping = .{ .full = test_helpers };
    plan.build(&input);
    try testing.expectEqual(steps_count_full, plan.count);
    try testing.expectEqual(@as(u32, 50), plan.count);
    try testing.expectEqual(Kind.run_newuidmap, plan.steps[2].kind);
    try testing.expectEqual(Kind.run_newgidmap, plan.steps[3].kind);
    try testing.expectEqual(Kind.release_child, plan.steps[4].kind);
    try testing.expectEqualStrings("/usr/bin/newuidmap", plan.text(plan.steps[2].target));
    try testing.expectEqualStrings("0 1000 1 1 100000 65536", plan.text(plan.steps[2].source));
    try testing.expectEqualStrings("/usr/bin/newgidmap", plan.text(plan.steps[3].target));
    try testing.expectEqualStrings("0 1001 1 1 200000 65536", plan.text(plan.steps[3].source));
    for (plan.steps[0..plan.count]) |step| {
        try testing.expect(
            step.kind != .deny_setgroups,
        ); // Never written: the helpers need no deny.
        try testing.expect(step.kind != .write_uid_map);
    }
}

test "the plan has the steps in order, parent and child interleaved, and all within bounds" {
    // Goal: the shape every other module relies on. Method: build once and walk it; each step
    // belongs to the side the order says, the device and link steps repeat per device and link,
    // and only the devpts mount and the two of /sys are tolerant.
    var plan: Plan = undefined;
    const input = test_input(&.{ "/bin/sh", "-c", "true" });
    plan.build(&input);
    try testing.expectEqual(steps_count_single, plan.count);
    try testing.expectEqual(@as(u32, 51), plan.count);
    var tolerant: u32 = 0;
    var devices_seen: u32 = 0;
    var links_seen: u32 = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (step.tolerant) {
            tolerant += 1;
            const allowed = step.kind == .mount_pts or step.kind == .bind_sys or
                step.kind == .remount_sys;
            try testing.expect(allowed);
        }
        if (step.kind == .bind_device) devices_seen += 1;
        if (step.kind == .link_dev) links_seen += 1;
    }
    try testing.expectEqual(@as(u32, 3), tolerant);
    try testing.expectEqual(constants.container_devices_count, devices_seen);
    try testing.expectEqual(constants.container_links_count, links_seen);
    // The mounts come in the order the kernel needs: private, bind, proc, dev, ... pivot, exec.
    const order = [_]Kind{
        .make_mounts_private, .bind_rootfs, .mount_proc, .mount_dev,
        .mount_shm,           .mount_pts,   .pivot_root, .exec,
    };
    var at: usize = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (at < order.len and step.kind == order[at]) at += 1;
    }
    try testing.expectEqual(order.len, at);
}

test "the plan's paths and texts are what the kernel will be given" {
    // Goal: every derived path, the map lines with the right ids, and the hostname.
    var plan: Plan = undefined;
    const input = test_input(&.{"sh"});
    plan.build(&input);
    try testing.expectEqualStrings("web-1", plan.hostname());
    var seen_bind = false;
    for (plan.steps[0..plan.count]) |step| {
        switch (step.kind) {
            .deny_setgroups => try testing.expectEqualStrings("deny", plan.text(step.target)),
            .write_gid_map => try testing.expectEqualStrings("0 1001 1\n", plan.text(step.target)),
            .write_uid_map => try testing.expectEqualStrings("0 1000 1\n", plan.text(step.target)),
            .mount_proc => {
                try testing.expectEqualStrings("/srv/alpine/proc", plan.text(step.target));
            },
            .mount_pts => {
                try testing.expectEqualStrings("/srv/alpine/dev/pts", plan.text(step.target));
            },
            .bind_device => {
                if (step.index == 0) {
                    try testing.expectEqualStrings("/srv/alpine/dev/null", plan.text(step.target));
                    try testing.expectEqualStrings("/dev/null", plan.text(step.source));
                    seen_bind = true;
                }
            },
            .pivot_root => {
                try testing.expectEqualStrings(".", plan.text(step.target));
                try testing.expectEqualStrings(".", plan.text(step.source));
            },
            .link_dev => {
                if (step.index == 4) {
                    try testing.expectEqualStrings("/srv/alpine/dev/ptmx", plan.text(step.target));
                    try testing.expectEqualStrings("pts/ptmx", plan.text(step.source));
                }
            },
            else => {},
        }
    }
    try testing.expect(seen_bind);
}

test "the exec image is a clean environment, and a bare program is looked up in PATH" {
    // Goal: the command gets exactly PATH, HOME, HOSTNAME and TERM, and the candidates are the
    // PATH directories in order for a bare name, or the one path for a name with a slash.
    var plan: Plan = undefined;
    var input = test_input(&.{ "ls", "-l" });
    plan.build(&input);
    try testing.expectEqualStrings("ls", std.mem.span(plan.argv[0].?));
    try testing.expectEqualStrings("-l", std.mem.span(plan.argv[1].?));
    try testing.expect(plan.argv[2] == null);
    const path_variable = "PATH=" ++ constants.container_path;
    try testing.expectEqualStrings(path_variable, std.mem.span(plan.envp[0].?));
    try testing.expectEqualStrings("HOME=/root", std.mem.span(plan.envp[1].?));
    try testing.expectEqualStrings("HOSTNAME=web-1", std.mem.span(plan.envp[2].?));
    try testing.expectEqualStrings("TERM=xterm", std.mem.span(plan.envp[3].?));
    try testing.expect(plan.envp[4] == null);
    try testing.expectEqual(constants.container_path_dirs_count, plan.candidates_count);
    try testing.expectEqualStrings("/usr/local/sbin/ls", plan.text(plan.candidates[0]));
    try testing.expectEqualStrings("/bin/ls", plan.text(plan.candidates[5]));

    input.term = null;
    input.command = &.{"./tool"};
    plan.build(&input);
    try testing.expect(plan.envp[3] == null);
    try testing.expectEqual(@as(u32, 1), plan.candidates_count);
    try testing.expectEqualStrings("./tool", plan.text(plan.candidates[0]));
}

test "Spec.env adds variables after the defaults and replaces a default of the same name" {
    // Goal: the caller's environment reaches the exec image, in order, and PATH can be replaced
    // without a second PATH. Method: one added variable, then one that replaces TERM and PATH.
    var plan: Plan = undefined;
    var input = test_input(&.{"ls"});
    input.env = &.{.{ .key = "APP", .value = "a=b c" }};
    plan.build(&input);
    try testing.expectEqualStrings("TERM=xterm", std.mem.span(plan.envp[3].?));
    try testing.expectEqualStrings("APP=a=b c", std.mem.span(plan.envp[4].?));
    try testing.expect(plan.envp[5] == null);
    input.env = &.{ .{ .key = "TERM", .value = "dumb" }, .{ .key = "PATH", .value = "/x" } };
    plan.build(&input);
    try testing.expectEqualStrings("HOME=/root", std.mem.span(plan.envp[0].?));
    try testing.expectEqualStrings("HOSTNAME=web-1", std.mem.span(plan.envp[1].?));
    try testing.expectEqualStrings("TERM=dumb", std.mem.span(plan.envp[2].?));
    try testing.expectEqualStrings("PATH=/x", std.mem.span(plan.envp[3].?));
    try testing.expect(plan.envp[4] == null);
}

test "the longest rootfs, name, command and ids still build a valid plan" {
    // Goal: the bounds in constants.zig are enough for the worst case at once, and every path
    // derived from the longest rootfs is a valid path.
    const repeat = @import("../test_util.zig").repeat;
    var plan: Plan = undefined;
    const word = repeat('w', constants.command_word_bytes_max);
    const words: [8][]const u8 = @splat(word);
    const input: Input = .{
        .rootfs = repeat('r', constants.rootfs_bytes_max),
        .name = repeat('n', constants.container_name_bytes_max),
        .command = &words,
        .term = repeat('t', constants.term_bytes_max),
        .uid = std.math.maxInt(u32) - 1,
        .gid = std.math.maxInt(u32) - 1,
        .mapping = .{ .full = .{
            .newuidmap = "/usr/local/bin/newuidmap",
            .newgidmap = "/usr/local/bin/newgidmap",
            .uid_start = std.math.maxInt(u32) - constants.subid_range_min,
            .gid_start = std.math.maxInt(u32) - constants.subid_range_min,
        } },
    };
    plan.build(&input);
    for (plan.steps[0..plan.count]) |step| {
        try testing.expect(plan.text(step.target).len <= constants.path_bytes_max);
        try testing.expect(plan.text(step.source).len <= constants.path_bytes_max);
    }
    try testing.expect(plan.paths_len <= constants.plan_paths_bytes_max);
    try testing.expect(plan.strings_len <= constants.exec_strings_bytes_max);
}

test "describe names every step and adds the device or link" {
    // Goal: no step lacks a phrase for its diagnostic, and the indexed ones say which device.
    var plan: Plan = undefined;
    const input = test_input(&.{"sh"});
    plan.build(&input);
    var buffer: [160]u8 = undefined;
    for (plan.steps[0..plan.count]) |*step| {
        const phrase = describe(step, &buffer);
        try testing.expect(phrase.len > 10);
        if (step.kind == .bind_device and step.index == 5) {
            try testing.expectEqualStrings("bind-mounting /dev/tty", phrase);
        }
        if (step.kind == .link_dev and step.index == 1) {
            try testing.expectEqualStrings("creating the link /dev/stdin", phrase);
        }
    }
}

test "a plan with a scope has the start_scope step before the go-ahead, with its names" {
    // Goal: the scope's place in the plan: after the maps (single or helpers) and before
    // release_child, so the child is in its cgroup before it may run anything; the unit and its
    // description are made from the container's name; a plan without one is unchanged.
    var plan: Plan = undefined;
    var input = test_input(&.{"sh"});
    input.scope = .{ .version = 255, .limits = .{ .pids = 64 } };
    plan.build(&input);
    try testing.expectEqual(steps_count_single + 2, plan.count);
    try testing.expectEqual(Kind.spawn_keeper, plan.steps[plan.first_child() - 3].kind);
    try testing.expectEqual(Kind.start_scope, plan.steps[plan.first_child() - 2].kind);
    try testing.expectEqual(Kind.release_child, plan.steps[plan.first_child() - 1].kind);
    const step = plan.steps[plan.first_child() - 2];
    try testing.expectEqualStrings("zbx-web-1.scope", plan.text(step.target));
    try testing.expectEqualStrings("zbx: web-1", plan.text(step.source));
    try testing.expectEqual(@as(u32, 255), plan.scope_version);
    try testing.expectEqual(@as(?u32, 64), plan.scope_limits.pids);
    var buffer: [160]u8 = undefined;
    try testing.expectEqualStrings(
        "starting the container's cgroup scope",
        describe(&plan.steps[plan.first_child() - 2], &buffer),
    );

    input.mapping = .{ .full = test_helpers };
    plan.build(&input);
    try testing.expectEqual(steps_count_full + 2, plan.count);
    try testing.expectEqual(Kind.spawn_keeper, plan.steps[4].kind);
    try testing.expectEqual(Kind.start_scope, plan.steps[5].kind);

    input.scope = null;
    plan.build(&input);
    try testing.expectEqual(steps_count_full, plan.count);
    try testing.expect(!plan.scoped);
}

const store_cache = "/home/alice/.local/share/zbx/store/cache/b3abc";
const state_containers = "/home/alice/.local/state/zbx/containers/web-1";

fn overlay_input(read_only: bool) Input {
    var input = test_input(&.{"sh"});
    input.rootfs = state_containers ++ "/merged";
    input.read_only = read_only;
    input.overlay = if (read_only) .{
        .lower = store_cache,
        .upper = null,
        .work = null,
        .empty = state_containers ++ "/empty",
    } else .{
        .lower = store_cache,
        .upper = state_containers ++ "/upper",
        .work = state_containers ++ "/work",
        .empty = null,
    };
    return input;
}

test "a run of a tree mounts the overlay where a rootfs is bound, and has as many steps" {
    // Goal: the overlay is a replacement, not an addition. Method: build with and without; the
    // step count is the same, the bind is gone, the overlay's target is the merged directory
    // and its data names the three layers.
    var plain: Plan = undefined;
    plain.build(&test_input(&.{"sh"}));
    var plan: Plan = undefined;
    plan.build(&overlay_input(false));
    try testing.expectEqual(plain.count, plan.count);
    var found: ?Step = null;
    for (plan.steps[0..plan.count]) |step| {
        try testing.expect(step.kind != .bind_rootfs);
        if (step.kind == .mount_overlay) found = step;
    }
    const step = found.?;
    try testing.expectEqualStrings(state_containers ++ "/merged", plan.text(step.target));
    try testing.expectEqualStrings(
        "userxattr,lowerdir=" ++ store_cache ++ ",upperdir=" ++ state_containers ++ "/upper" ++
            ",workdir=" ++ state_containers ++ "/work",
        plan.text(step.source),
    );
    // Everything the container sets up is inside the merged directory.
    try testing.expect(
        std.mem.startsWith(
            u8,
            plan.text(plan.steps[plan.first_child() + 5].target),
            state_containers,
        ),
    );
}

test "a read-only run of a tree has no upper layer, and a second empty lower one" {
    // Goal: `--read-only` with a digest is an overlay without an upper. Method: the data has
    // two lower layers and neither upperdir nor workdir.
    var plan: Plan = undefined;
    plan.build(&overlay_input(true));
    for (plan.steps[0..plan.count]) |step| {
        if (step.kind != .mount_overlay) continue;
        const data = plan.text(step.source);
        try testing.expectEqualStrings(
            "userxattr,lowerdir=" ++ store_cache ++ ":" ++ state_containers ++ "/empty",
            data,
        );
        try testing.expect(std.mem.indexOf(u8, data, "upperdir") == null);
        try testing.expect(std.mem.indexOf(u8, data, "workdir") == null);
    }
}

fn under_store(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "/zbx/store/") != null;
}

test "no step ever mounts a path of the store writable, or makes anything in it" {
    // Goal: "running a container never writes into the shared store", at the plan. Method: for
    // a writable and a read-only run of a tree, every step's target and source is checked: the
    // store's path appears in exactly one place, the lowerdir of the overlay; nothing is bound,
    // remounted, created or linked in it; and the upper and work layers are elsewhere.
    for ([_]bool{ false, true }) |read_only| {
        var plan: Plan = undefined;
        plan.build(&overlay_input(read_only));
        var mentions: u32 = 0;
        for (plan.steps[0..plan.count]) |step| {
            const target = plan.text(step.target);
            const source = plan.text(step.source);
            try testing.expect(!under_store(target)); // Nothing is made, bound or mounted there.
            if (!under_store(source)) continue;
            try testing.expectEqual(Kind.mount_overlay, step.kind);
            mentions += 1;
            // The store's path is the lower layer, and only that.
            const lower = "lowerdir=" ++ store_cache;
            try testing.expect(std.mem.indexOf(u8, source, lower) != null);
            if (std.mem.indexOf(u8, source, "upperdir=")) |at| {
                try testing.expect(!under_store(source[at..]));
            }
            if (std.mem.indexOf(u8, source, "workdir=")) |at| {
                try testing.expect(!under_store(source[at..]));
            }
        }
        try testing.expectEqual(@as(u32, 1), mentions);
    }
}

test "a path the kernel would split is not a layer" {
    // Goal: the mount data is text split at commas and colons. Method: each separator.
    try testing.expectEqual(@as(?u8, ','), spec.overlay_path_problem("/a,b"));
    try testing.expectEqual(@as(?u8, ':'), spec.overlay_path_problem("/a:b"));
    try testing.expectEqual(@as(?u8, '\\'), spec.overlay_path_problem("/a\\b"));
    try testing.expectEqual(@as(?u8, null), spec.overlay_path_problem("/home/alice/.local/state"));
}

fn index_of(plan: *const Plan, kind: Kind) ?usize {
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == kind) return index;
    }
    return null;
}

test "/sys is bound read-only from the host, in every plan, before the pivot" {
    // Goal: the M4 decision. Method: the three steps are there, in order, with the host's /sys
    // as the source and the rootfs's as the target, whether or not the rootfs is read-only.
    var plan: Plan = undefined;
    var input = test_input(&.{"sh"});
    plan.build(&input);
    const made = index_of(&plan, .make_sys_dir).?;
    try testing.expectEqual(Kind.bind_sys, plan.steps[made + 1].kind);
    try testing.expectEqual(Kind.remount_sys, plan.steps[made + 2].kind);
    try testing.expectEqualStrings("/srv/alpine/sys", plan.text(plan.steps[made + 1].target));
    try testing.expectEqualStrings("/sys", plan.text(plan.steps[made + 1].source));
    try testing.expect(made + 2 < index_of(&plan, .pivot_root).?);
    input.read_only = true;
    plan.build(&input);
    try testing.expect(index_of(&plan, .remount_sys).? < index_of(&plan, .remount_readonly).?);
}

test "a working directory and a user add one step each, after the root is entered" {
    // Goal: the image's config at run. Method: the steps exist only when asked for, the user
    // comes after the capabilities and before no_new_privs, root alone adds nothing.
    var plan: Plan = undefined;
    var input = test_input(&.{"sh"});
    plan.build(&input);
    const plain = plan.count;
    try testing.expect(index_of(&plan, .enter_workdir) == null);
    try testing.expect(index_of(&plan, .set_user) == null);
    input.workdir = "/srv/app";
    input.user = .{ .uid = 0, .gid = 0 };
    plan.build(&input);
    try testing.expectEqual(plain + 1, plan.count);
    try testing.expect(index_of(&plan, .set_user) == null);
    try testing.expect(index_of(&plan, .enter_new_root).? < index_of(&plan, .enter_workdir).?);
    try testing.expectEqualStrings(
        "/srv/app",
        plan.text(plan.steps[index_of(&plan, .enter_workdir).?].target),
    );
    input.user = .{ .uid = 33, .gid = 44 };
    plan.build(&input);
    try testing.expectEqual(plain + 2, plan.count);
    try testing.expectEqual(@as(u32, 33), plan.user_uid);
    try testing.expectEqual(@as(u32, 44), plan.user_gid);
    try testing.expect(index_of(&plan, .clear_ambient).? < index_of(&plan, .set_user).?);
    try testing.expect(index_of(&plan, .set_user).? < index_of(&plan, .set_no_new_privs).?);
    plan.check();
}

test "an image's PATH decides where a bare command is looked for" {
    // Goal: python:3.12-slim's PATH starts with /usr/local/bin and has seven directories.
    var plan: Plan = undefined;
    var input = test_input(&.{"python"});
    const path = "/opt/py/bin:/usr/local/bin:relative:/usr/bin::/bin";
    const env = [_]spec.Label{.{ .key = "PATH", .value = path }};
    input.env = &env;
    plan.build(&input);
    try testing.expectEqual(@as(u32, 4), plan.candidates_count);
    try testing.expectEqualStrings("/opt/py/bin/python", plan.text(plan.candidates[0]));
    try testing.expectEqualStrings("/bin/python", plan.text(plan.candidates[3]));
    plan.check();
}
