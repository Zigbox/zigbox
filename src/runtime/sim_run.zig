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
const spec_mod = @import("spec.zig");

const cli = @import("../cli.zig");
const records = @import("records.zig");

const HostSim = host_sim.HostSim;

pub const rootfs_path = "/srv/alpine";
pub const regular_file_path = "/srv/file";
pub const mount_dir_path = "/srv/data";
pub const mount_file_path = "/srv/note";
pub const secret_path = "/srv/key";
pub const secret_marker = "secret-marker-THETA-91";

/// The container model's view of the host paths above, which the child binds from.
pub fn add_mount_sources(sim: *HostSim) void {
    sim.world.add_node(mount_dir_path, .dir);
    sim.world.add_node(mount_file_path, .file);
    sim.world.add_node(secret_path, .file);
}

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
    // The root of a cgroup v2 hierarchy that offers the controllers a limit needs, as on any
    // host with systemd. `init_hybrid` takes it away.
    .{ .path = cgroup_root_controllers_path, .content = cgroup_root_controllers },
    // What `--bind` and `--secret` of the tests and the fuzzers mount (M6): a directory, a file
    // and a file with a marker in it that must reach nothing but the container.
    .{ .path = mount_dir_path, .content = "", .mode = 0o040755 },
    .{ .path = mount_file_path, .content = "a note\n", .mode = 0o100644 },
    .{ .path = secret_path, .content = secret_marker ++ "\n", .mode = 0o100600 },
    // pasta, for `--net user` (the simulator's pasta is `sim_world.World.start_program`), and
    // the lowest port a user may bind, as Ubuntu 24.04 has it.
    .{ .path = "/usr/bin/pasta", .content = "", .mode = 0o100755 },
    .{ .path = "/proc/sys/net/ipv4/ip_unprivileged_port_start", .content = "1024\n" },
};

const cgroup_root_controllers_path = "/sys/fs/cgroup/cgroup.controllers";
const cgroup_root_controllers = "cpuset cpu io memory hugetlb pids rdma misc\n";

/// `files` without the cgroup v2 root: a host with the cgroup v1 or hybrid layout, as a Claude
/// Code cloud container has it (the v1 hierarchies own cpu, memory and pids; cgroup2 is mounted
/// below /sys/fs/cgroup/unified with only hugetlb, so there is no root `cgroup.controllers`).
pub const files_hybrid = without_path(&files, cgroup_root_controllers_path);

fn without_path(
    comptime list: []const host_sim.File,
    comptime path: []const u8,
) [list.len - 1]host_sim.File {
    var result: [list.len - 1]host_sim.File = undefined;
    var count: usize = 0;
    for (list) |file| {
        if (std.mem.eql(u8, file.path, path)) continue;
        result[count] = file;
        count += 1;
    }
    assert(count == result.len); // The path was in the list exactly once.
    return result;
}

/// The path of a run's pasta log in the simulated state directory.
pub const logs_path = "/home/alice/.local/state/zbx/logs";

/// A host that can map a full range of ids: ranges for the user and setuid-root helpers.
pub const files = common_files ++ [_]host_sim.File{
    .{ .path = "/etc/subuid", .content = "alice:100000:65536\n" },
    .{ .path = "/etc/subgid", .content = "alice:100000:65536\n" },
    .{ .path = "/usr/bin/newuidmap", .content = "", .mode = 0o104755 },
    .{ .path = "/usr/bin/newgidmap", .content = "", .mode = 0o104755 },
};

/// A host that can map a full range of ids and has no pasta (`common_files` ends with pasta and
/// the port sysctl).
pub const files_without_pasta = common_files[0 .. common_files.len - 2] ++
    files[common_files.len..];

/// A host with neither: the single-id map and a warning.
pub const files_single = common_files;

/// The same, for a host built from a doctor fixture (`doctor_fixtures.Spec.extra_files`).
pub const extra_files = [_]host_sim.File{ files[1], files[2] };

/// Starts the simulator with `files` and a container host: the devices, the rootfs tree with a
/// shell in it, the host's own three mounts, and the user's home.
pub fn init(sim: *HostSim, seed: u64) void {
    start(sim, seed, &files);
}

/// Like `init`, for a host with no cgroup v2 at /sys/fs/cgroup (`files_hybrid`).
pub fn init_hybrid(sim: *HostSim, seed: u64) void {
    start(sim, seed, &files_hybrid);
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
    sample_plan_image(plan, full, scoped, read_only, false, .none);
}

/// Like `sample_plan_ro`, for a run of a tree from the store (`image`): the overlay replaces the
/// bind of the rootfs, and there are as many steps.
pub fn sample_plan_image(
    plan: *plan_mod.Plan,
    full: bool,
    scoped: bool,
    read_only: bool,
    image: bool,
    network: spec_mod.Network,
) void {
    sample_plan_mounts(plan, full, scoped, read_only, image, network, &.{});
}

/// Like `sample_plan_image`, with other mounts.
pub fn sample_plan_mounts(
    plan: *plan_mod.Plan,
    full: bool,
    scoped: bool,
    read_only: bool,
    image: bool,
    network: spec_mod.Network,
    mounts: []const plan_mod.MountInput,
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
        .network = network,
        .mounts = mounts,
        .pasta = if (network == .user) .{
            .path = "/usr/bin/pasta",
            .log = logs_path ++ "/oracle.pasta.log",
            .publish = &.{.{ .host = 8080, .container = 80 }},
        } else null,
        .overlay = if (image) .{
            .net = "/state/net",
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
    if (sim.world.pasta_alive() != 0) return "pasta was left running or unreaped";
    if (sim.world.ports_listening() != 0) return "a published port was left listening";
    if (sim.open_count() != 0) return "a descriptor was left open";
    if (sim.world.broken_pipe_ignored) return "SIGPIPE was left ignored";
    if (sim.world.current != 0) return "the run ended in a child";
    if (sim.world.bus.scope_count() > before.scopes_allowed) {
        return "a cgroup scope was left behind";
    }
    if (cgroupfs_directories(sim) > 0) return "a cgroup directory was left behind";
    return null;
}

/// The delegated cgroup directory the cgroupfs driver makes its cgroups in (tests set
/// `ZBX_CGROUP_ROOT` to it), and its environment: a user with no bus.
pub const cgroup_root = "/sys/fs/cgroup/zbx";
pub const env_cgroupfs = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = home_path },
    .{ .name = "ZBX_CGROUP_ROOT", .value = cgroup_root },
};

/// A host of the macOS VM: no user bus, a delegated cgroup directory to make cgroups in.
pub fn init_cgroupfs(sim: *HostSim, seed: u64) void {
    init(sim, seed);
    sim.world.add_node(cgroup_root, .dir);
    sim.environment_variables = &env_cgroupfs;
}

/// How many cgroups of containers are below the delegated directory.
pub fn cgroupfs_directories(sim: *const HostSim) u32 {
    var count: u32 = 0;
    for (sim.world.nodes[0..sim.world.nodes_count]) |*node| {
        const inside = node.path.under(cgroup_root) and !node.path.eql(cgroup_root);
        if (inside) count += 1;
    }
    return count;
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
    /// What the container could reach: `none` and `user` have a network namespace of their own
    /// with `lo` up and a sysfs; `host` shares the host's and binds the host's /sys.
    network: spec_mod.Network = .none,
    /// The /sys and /etc steps all ran. A failure injected into one of them is skipped with a
    /// note, and the container then lacks what the step would have made.
    network_mounts: bool = true,
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
    const isolated = expected.network.isolated();
    if (child.new_net != isolated) return "the network namespace is not as asked";
    if (child.loopback_up != isolated) return "the loopback interface is not as asked";
    return container_mounts(
        &sim.world.tables[child.table],
        want_root,
        if (expected.merged != null) .overlay else .bind_tree,
        expected.devpts,
        expected.read_only,
        if (expected.network_mounts) isolated else null,
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
    isolated: ?bool,
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
    if (isolated) |own_network| {
        if (network_mounts(table, root_path, own_network)) |problem| return problem;
    }
    const root = table.find(root_path) orelse return "the rootfs is not a mount";
    if (table.mounts[root].read_only != read_only) return "the rootfs is not as read-only as asked";
    for (table.slice()) |*mount| {
        if (!mount.target.under(root_path)) return "a host mount is still visible";
        if (mount.kind == .proc and !mount.own_pid_namespace) return "/proc shows the host";
    }
    return null;
}

/// /sys is a sysfs of the container's own when it has its own network namespace and the host's,
/// bound, when it has not; the two generated /etc files are read-only binds either way.
fn network_mounts(
    table: *const sim_world.MountTable,
    root_path: []const u8,
    isolated: bool,
) ?[]const u8 {
    assert(root_path.len > 0);
    assert(table.count <= constants.sim_mounts_max);
    var buffer: [constants.sim_path_bytes_max]u8 = undefined;
    const sys = join(&buffer, root_path, "/sys");
    if (table.has(.sysfs, sys) != isolated) return "/sys is not as the network asks";
    if (table.has(.bind_tree, sys) == isolated) return "/sys is not as the network asks";
    const sys_index = table.find(sys) orelse return "/sys is not a mount";
    if (!table.mounts[sys_index].read_only) {
        // A bind of the host's /sys is made read-only by the remount.
        return "/sys is writable";
    }
    for ([_][]const u8{ "/etc/hosts", "/etc/resolv.conf" }) |name| {
        const path = join(&buffer, root_path, name);
        if (!table.has(.bind_file, path)) return "a generated /etc file is not bound";
        const index = table.find(path).?; // `has` found it.
        if (!table.mounts[index].read_only) return "a generated /etc file is writable";
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

/// The user's state directory in the simulated host (`XDG_DATA_HOME` unset, HOME as above).
pub const state_root = "/home/alice/.local/share/zbx/state";

/// Gives the simulator a file tree for the state directory (`tree`, which the caller owns),
/// with the user's data directory's parents, and puts the volumes `names` in the container
/// model: their directories, where the container's child makes `data` (the two models are
/// separate; on a real host they are one file system).
pub fn prepare_state(sim: *HostSim, tree: *SimFs, names: []const []const u8) void {
    tree.init(1);
    sim.store_fs = tree;
    const parents = [_][]const u8{
        "/home",
        "/home/alice",
        "/home/alice/.local",
        "/home/alice/.local/share",
        "/home/alice/.local/share/zbx",
    };
    for (parents) |parent| tree.put_dir(parent, 0o755);
    var path: [constants.sim_path_bytes_max]u8 = undefined;
    for (names) |name| {
        const text = std.fmt.bufPrint(&path, state_root ++ "/{s}", .{name}) catch
            unreachable; // Test names are short.
        sim.world.add_node(text, .dir);
    }
}

const SimFs = @import("../store/fs_sim.zig").SimFs;
