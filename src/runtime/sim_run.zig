//! Support for running containers against the simulator: a host with a rootfs, the checks that
//! nothing leaked onto the host model, and the checks of a container that started. Shared by the
//! unit tests, the golden tests and the run fuzzer, so all three judge a run by the same rules.
//! The checks return a description of the first thing wrong (null if nothing is), so a test can
//! show it and the fuzzer can assert on it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const sim_world = @import("../sim_world.zig");
const capabilities = @import("capabilities.zig");
const plan_mod = @import("plan.zig");

const cli = @import("../cli.zig");
const records = @import("records.zig");

const HostSim = host_sim.HostSim;

pub const rootfs_path = "/srv/alpine";
pub const regular_file_path = "/srv/file";

pub const home_path = "/home/alice";
pub const runs_path = "/home/alice/.local/state/zbx/runs";
pub const bundles_path = "/home/alice/.local/state/zbx/bundles";

/// The environment of a user whose home is `home_path`, with and without a terminal.
pub const env_home = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = home_path },
    .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
};
pub const env_home_term = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = home_path },
    .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
    .{ .name = "TERM", .value = "xterm-256color" },
};

/// What every simulated host has: its own status file (the single-thread check reads it), the
/// rootfs directory, a plain file where a directory is expected, the user's passwd entry, and
/// the sysctl the user-namespace check reads.
const common_files = [_]host_sim.File{
    .{ .path = "/proc/self/status", .content = "Name:\tzbx\nThreads:\t1\n" },
    .{ .path = rootfs_path, .content = "", .mode = 0o040755 },
    .{ .path = regular_file_path, .content = "", .mode = 0o100644 },
    .{ .path = "/etc/passwd", .content = "alice:x:1000:1000::/home/alice:/bin/bash\n" },
    .{ .path = "/proc/sys/user/max_user_namespaces", .content = "63488\n" },
};

/// A host that can map a full range of ids: ranges for the user and setuid-root helpers.
pub const files = common_files ++ [_]host_sim.File{
    .{ .path = "/etc/subuid", .content = "alice:100000:65536\n" },
    .{ .path = "/etc/subgid", .content = "alice:100000:65536\n" },
    .{ .path = "/usr/bin/newuidmap", .content = "", .mode = 0o104755 },
    .{ .path = "/usr/bin/newgidmap", .content = "", .mode = 0o104755 },
};

/// A host with neither: the single-id map and a warning.
pub const files_single = common_files;

/// The same, for a host built from a doctor fixture (`doctor_fixtures.Spec.extra_files`).
pub const extra_files = [_]host_sim.File{ files[1], files[2] };

/// Starts the simulator with `files` and a container host: the devices, the rootfs tree with a
/// shell in it, the host's own three mounts, and the user's home.
pub fn init(sim: *HostSim, seed: u64) void {
    start(sim, seed, &files);
}

/// Like `init`, for a host that cannot map a full range of ids.
pub fn init_single(sim: *HostSim, seed: u64) void {
    start(sim, seed, &files_single);
}

pub fn start(sim: *HostSim, seed: u64, host_files: []const host_sim.File) void {
    sim.init(seed, host_files);
    sim.world.seed_container_host(rootfs_path);
    sim.world.add_node(home_path, .dir);
    sim.environment_variables = &env_home;
}

/// Puts the record `view` in the simulated runs directory, as a finished run would have.
pub fn put_record(sim: *HostSim, view: *const records.View) void {
    sim.world.add_node(runs_path, .dir);
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = records.render(view, &buffer);
    var path: [128]u8 = undefined;
    // Cannot fail: the runs path and a container name fit in 128 bytes.
    const where = std.fmt.bufPrint(&path, runs_path ++ "/{s}.zon", .{view.name}) catch unreachable;
    assert(sim.world.write_file(where, text) == null);
}

/// A finished run called `name`, started at `started`, for tests that need something to bundle.
pub fn sample_view(name: []const u8, begun: u64) records.View {
    return .{
        .name = name,
        .rootfs = rootfs_path,
        .command = &.{ "/bin/sh", "-c", "echo hi" },
        .labels = &.{.{ .key = "app", .value = "web" }},
        .started = begun,
        .ended = begun + 2,
        .exit = .{ .exited = 3 },
        .ids = .full,
        .zbx_version = "0.0.0",
    };
}

/// A plan for the oracle's own questions (which step is where). The steps are the same for every
/// command and name; the id mapping changes them by one step, and so does the scope that a host
/// with a user bus gives (which is every simulated host unless its model says otherwise).
pub fn sample_plan(plan: *plan_mod.Plan, full: bool) void {
    sample_plan_with(plan, full, true);
}

/// Like `sample_plan`, for a run with (`scoped`) or without a scope.
pub fn sample_plan_with(plan: *plan_mod.Plan, full: bool, scoped: bool) void {
    sample_plan_ro(plan, full, scoped, false);
}

/// Like `sample_plan_with`, for a run with (`read_only`) or without a read-only rootfs.
pub fn sample_plan_ro(plan: *plan_mod.Plan, full: bool, scoped: bool, read_only: bool) void {
    sample_plan_image(plan, full, scoped, read_only, false);
}

/// Like `sample_plan_ro`, for a run of a tree from the store (`image`): the overlay replaces the
/// bind of the rootfs, and there are as many steps.
pub fn sample_plan_image(
    plan: *plan_mod.Plan,
    full: bool,
    scoped: bool,
    read_only: bool,
    image: bool,
) void {
    const mapping: plan_mod.Mapping = if (full) .{ .full = .{
        .newuidmap = "/usr/bin/newuidmap",
        .newgidmap = "/usr/bin/newgidmap",
        .uid_start = 100000,
        .gid_start = 100000,
    } } else .single;
    plan.build(&.{
        .rootfs = rootfs_path,
        .name = "oracle",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = mapping,
        .scope = if (scoped) .{ .version = 255, .limits = .{} } else null,
        .read_only = read_only,
        .overlay = if (image) .{
            .lower = "/store/cache/b3",
            .upper = if (read_only) null else "/state/up",
            .work = if (read_only) null else "/state/work",
            .empty = if (read_only) "/state/empty" else null,
        } else null,
    });
}

/// The index of the first step of `kind` in a read-only plan for a full id mapping.
pub fn step_index_read_only(kind: plan_mod.Kind) u32 {
    var plan: plan_mod.Plan = undefined;
    sample_plan_ro(&plan, true, true, true);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == kind) return @intCast(index);
    }
    unreachable; // Every kind asked for is in a read-only plan.
}

/// The index of the first step of `kind` in the plan for `full` or single-id mapping.
pub fn step_index(kind: plan_mod.Kind, full: bool) u32 {
    var plan: plan_mod.Plan = undefined;
    sample_plan(&plan, full);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == kind) return @intCast(index);
    }
    unreachable; // Every kind asked for is in the plan of its mapping.
}

pub const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    pub fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

/// Runs the command line `args` (with the program name first) against the simulator.
pub fn run_cli(sim: *HostSim, args: []const [:0]const u8) u8 {
    var iterator: SliceIterator = .{ .items = args };
    return cli.run_from_iterator(sim.interface(), &iterator);
}

/// What the host looked like before a run, for the leak check.
pub const Baseline = struct {
    table: sim_world.MountTable,
    hostname: host_mod.Text,
    /// Scopes the run may leave: a manager that will not stop one is a warning, not a leak.
    scopes_allowed: u32 = 0,
};

pub fn baseline(sim: *const HostSim) Baseline {
    return .{ .table = sim.world.tables[0], .hostname = sim.world.hostnames[0] };
}

fn tables_equal(first: *const sim_world.MountTable, second: *const sim_world.MountTable) bool {
    if (first.count != second.count) return false;
    if (first.private != second.private) return false;
    for (first.slice(), second.slice()) |*one, *other| {
        if (!one.target.eql(other.target.slice())) return false;
        if (one.kind != other.kind) return false;
    }
    return true;
}

/// Null if the run left the host as it found it: no mount in the host's table, the host's
/// hostname, no child alive or unreaped, no descriptor held, SIGPIPE as it was, and the run
/// ended in the host's process. Otherwise what leaked.
pub fn leak(sim: *const HostSim, before: *const Baseline) ?[]const u8 {
    if (!tables_equal(&sim.world.tables[0], &before.table)) return "the host's mounts changed";
    const name = sim.world.hostnames[0].slice();
    if (!std.mem.eql(u8, name, before.hostname.slice())) return "the host's hostname changed";
    if (sim.world.unreaped_children() != 0) return "a container process was left unreaped";
    if (sim.open_count() != 0) return "a descriptor was left open";
    if (sim.world.broken_pipe_ignored) return "SIGPIPE was left ignored";
    if (sim.world.current != 0) return "the run ended in a child";
    if (sim.world.bus.scope_count() > before.scopes_allowed) {
        return "a cgroup scope was left behind";
    }
    return null;
}

/// What a container whose command started must look like to the model.
pub const Started = struct {
    name: []const u8,
    /// Whether the devpts mount worked (it can be refused, and is then skipped).
    devpts: bool,
    /// Whether the ids were mapped through the helpers (else the single-id map was written).
    full: bool = true,
    /// The run was `--read-only`.
    read_only: bool = false,
    /// A run of a tree from the store: the merged directory it pivoted into, which is an
    /// overlay mount where a rootfs run has a bind mount.
    merged: ?[]const u8 = null,
};

/// Null if the child process the last run created reached its command in the state the plan
/// promises: its own mount table with the container's mounts and no host mount left, its own
/// hostname, a root, no old root, descriptors sealed, and an exec of a file.
pub fn started(sim: *const HostSim, expected: Started) ?[]const u8 {
    const child = &sim.world.processes[1];
    if (!child.execd) return "the command was not started";
    if (!child.sealed) return "the descriptors were not sealed before exec";
    if (!child.die_with_parent) return "the child was not tied to its parent";
    if (child.old_root_attached) return "the old root was not detached";
    const root = child.root orelse return "the child never pivoted";
    const want_root = expected.merged orelse rootfs_path;
    if (!root.eql(want_root)) return "the child pivoted into the wrong root";
    // The helpers leave setgroups alone (programs in the container may need it); the direct
    // write of the single-id map must deny it first.
    if (child.maps.setgroups_denied == expected.full) return "setgroups is wrong for this map";
    if (!child.maps.gid_map) return "no gid map";
    if (!child.maps.uid_map) return "no uid map";
    if (child.table == 0) return "the child shares the host's mounts";
    if (child.uts == 0) return "the child shares the host's hostname";
    const hostname = sim.world.hostnames[child.uts].slice();
    if (!std.mem.eql(u8, hostname, expected.name)) return "the child's hostname is wrong";
    if (hardening(child)) |problem| return problem;
    return container_mounts(
        &sim.world.tables[child.table],
        want_root,
        if (expected.merged != null) .overlay else .bind_tree,
        expected.devpts,
        expected.read_only,
    );
}

/// The capabilities, no_new_privs and the filter are all in place when the command starts.
fn hardening(child: *const sim_world.Process) ?[]const u8 {
    assert(child.execd);
    assert(child.sealed);
    const kept = child.capabilities orelse return "the capabilities were not restricted";
    if (kept != capabilities.keep_mask) return "the wrong capabilities were kept";
    if (!child.ambient_cleared) return "the ambient capabilities were not cleared";
    if (!child.no_new_privs) return "no_new_privs was not set";
    if (!child.seccomp) return "no seccomp filter was installed";
    return null;
}

fn container_mounts(
    table: *const sim_world.MountTable,
    root_path: []const u8,
    root_kind: host_mod.MountKind,
    devpts: bool,
    read_only: bool,
) ?[]const u8 {
    if (!table.private) return "the mounts were not made private";
    if (!table.has(root_kind, root_path)) return "the rootfs was not mounted as the plan says";
    var buffer: [constants.sim_path_bytes_max]u8 = undefined;
    const proc = join(&buffer, root_path, "/proc");
    if (!table.has(.proc, proc)) return "no /proc";
    if (!table.has(.dev_tmpfs, join(&buffer, root_path, "/dev"))) return "no /dev";
    if (!table.has(.shm_tmpfs, join(&buffer, root_path, "/dev/shm"))) return "no /dev/shm";
    if (table.has(.devpts, join(&buffer, root_path, "/dev/pts")) != devpts) {
        return "/dev/pts is wrong";
    }
    for (plan_mod.devices) |device| {
        var path_buffer: [constants.sim_path_bytes_max]u8 = undefined;
        const name = std.fmt.bufPrint(&path_buffer, "{s}/dev/{s}", .{ root_path, device }) catch
            unreachable; // The root path and a device name are short.
        if (!table.has(.bind_file, name)) return "a device is not bound";
    }
    const tmp = table.has(.tmp_tmpfs, join(&buffer, root_path, "/tmp"));
    if (tmp != read_only) return "/tmp is wrong";
    const run = table.has(.run_tmpfs, join(&buffer, root_path, "/run"));
    if (run != read_only) return "/run is wrong";
    const root = table.find(root_path) orelse return "the rootfs is not a mount";
    if (table.mounts[root].read_only != read_only) return "the rootfs is not as read-only as asked";
    for (table.slice()) |*mount| {
        if (!mount.target.under(root_path)) return "a host mount is still visible";
        if (mount.kind == .proc and !mount.own_pid_namespace) return "/proc shows the host";
    }
    return null;
}

fn join(
    buffer: *[constants.sim_path_bytes_max]u8,
    root_path: []const u8,
    suffix: []const u8,
) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ root_path, suffix }) catch
        unreachable; // The root path and a suffix are short.
}

test "tables_equal compares counts, order of content and privacy" {
    // Goal: the leak check is not vacuous: a changed table is different from the baseline.
    var sim: HostSim = undefined;
    init(&sim, 1);
    const before = baseline(&sim);
    try std.testing.expect(leak(&sim, &before) == null);
    sim.world.tables[0].private = true;
    try std.testing.expect(leak(&sim, &before) != null);
    sim.world.tables[0].private = false;
    sim.world.tables[0].count -= 1;
    try std.testing.expect(leak(&sim, &before) != null);
}
