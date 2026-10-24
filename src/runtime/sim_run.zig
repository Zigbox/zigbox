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
const plan_mod = @import("plan.zig");

const cli = @import("../cli.zig");

const HostSim = host_sim.HostSim;

pub const rootfs_path = "/srv/alpine";
pub const regular_file_path = "/srv/file";

/// What the simulated host has: its own status file (the single-thread check reads it), the
/// rootfs directory, and a plain file where a directory is expected.
pub const files = [_]host_sim.File{
    .{ .path = "/proc/self/status", .content = "Name:\tzbx\nThreads:\t1\n" },
    .{ .path = rootfs_path, .content = "", .mode = 0o040755 },
    .{ .path = regular_file_path, .content = "", .mode = 0o100644 },
};

/// The same, for a host built from a doctor fixture (`doctor_fixtures.Spec.extra_files`).
pub const extra_files = [_]host_sim.File{ files[1], files[2] };

/// Starts the simulator with `files` and a container host: the devices, the rootfs tree with a
/// shell in it, and the host's own three mounts.
pub fn init(sim: *HostSim, seed: u64) void {
    sim.init(seed, &files);
    sim.world.seed_container_host(rootfs_path);
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
    return null;
}

/// What a container whose command started must look like to the model.
pub const Started = struct {
    name: []const u8,
    /// Whether the devpts mount worked (it can be refused, and is then skipped).
    devpts: bool,
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
    if (!root.eql(rootfs_path)) return "the child pivoted into the wrong root";
    if (!child.maps.setgroups_denied) return "setgroups was not denied";
    if (!child.maps.gid_map) return "no gid map";
    if (!child.maps.uid_map) return "no uid map";
    if (child.table == 0) return "the child shares the host's mounts";
    if (child.uts == 0) return "the child shares the host's hostname";
    const hostname = sim.world.hostnames[child.uts].slice();
    if (!std.mem.eql(u8, hostname, expected.name)) return "the child's hostname is wrong";
    return container_mounts(&sim.world.tables[child.table], expected.devpts);
}

fn container_mounts(table: *const sim_world.MountTable, devpts: bool) ?[]const u8 {
    if (!table.private) return "the mounts were not made private";
    if (!table.has(.bind_tree, rootfs_path)) return "the rootfs was not bind-mounted";
    if (!table.has(.proc, rootfs_path ++ "/proc")) return "no /proc";
    if (!table.has(.dev_tmpfs, rootfs_path ++ "/dev")) return "no /dev";
    if (!table.has(.shm_tmpfs, rootfs_path ++ "/dev/shm")) return "no /dev/shm";
    if (table.has(.devpts, rootfs_path ++ "/dev/pts") != devpts) return "/dev/pts is wrong";
    for (plan_mod.devices) |device| {
        var buffer: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, rootfs_path ++ "/dev/{s}", .{device}) catch
            unreachable; // The rootfs path and a device name are short.
        if (!table.has(.bind_file, path)) return "a device is not bound";
    }
    for (table.slice()) |*mount| {
        if (!mount.target.under(rootfs_path)) return "a host mount is still visible";
        if (mount.kind == .proc and !mount.own_pid_namespace) return "/proc shows the host";
    }
    return null;
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
