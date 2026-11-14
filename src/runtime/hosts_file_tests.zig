//! `--hosts-file` (Zigcube's ZB-6) against the simulator: the caller's file is bound at
//! /etc/hosts read-only instead of the generated one, and every refusal is one coded line,
//! E0612, before anything starts. The VM (`demo-c4`) shows the real thing: a rewrite in place
//! seen by `zbx exec`, a rename over it not.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;
const rootfs = sim_run.rootfs_path;
const hosts_path = "/srv/mesh/hosts";

fn no_leak(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

/// `zbx run --net NET --hosts-file PATH`, with a file at `hosts_path`.
fn run_with(sim: *HostSim, net: [:0]const u8, path: [:0]const u8) u8 {
    const args = [_][:0]const u8{
        "zbx",    "run",   "--rootfs", rootfs, "--net", net, "--hosts-file", path,
        "--name", "box-1", "--",       "sh",
    };
    return sim_run.run_cli(sim, &args);
}

const host_files = sim_run.files ++ [_]host_sim.File{
    .{ .path = hosts_path, .content = "127.0.0.1 localhost\n" },
    .{ .path = "/srv/mesh/dir", .content = "", .mode = 0o040755 },
};

fn prepared(sim: *HostSim, seed: u64) void {
    sim_run.start(sim, seed, &host_files);
    sim.world.add_node("/srv/mesh", .dir);
    sim.world.add_node(hosts_path, .file);
    sim.world.add_node("/srv/mesh/dir", .dir);
}

test "--hosts-file: the file is bound read-only at /etc/hosts and nothing is staged for it" {
    // Goal: the success path. Method: run with a file; the command starts, /etc/hosts of the
    // container is a read-only bind, the other two generated files are as before, and nothing
    // leaks.
    var sim: HostSim = undefined;
    prepared(&sim, 81);
    const before = sim_run.baseline(&sim);
    const code = run_with(&sim, "none", hosts_path);
    if (code != 0) std.debug.print("stderr: {s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    const problem = sim_run.started(&sim, .{ .name = "box-1", .devpts = true, .network = .none });
    if (problem) |text| std.debug.print("the container is wrong: {s}\n", .{text});
    try testing.expect(problem == null);
    const table = &sim.world.tables[sim.world.processes[1].table];
    var path: [64]u8 = undefined;
    // 64 bytes hold the rootfs path and the suffix.
    const inside = std.fmt.bufPrint(&path, "{s}/etc/hosts", .{rootfs}) catch unreachable;
    const found = table.find(inside).?;
    try testing.expect(table.mounts[found].read_only);
    try no_leak(&sim, &before);
}

test "--hosts-file: every refusal is E0612 on one line and starts nothing" {
    // Goal: the refusals. Method: a container with a network, a relative path, a missing file
    // and a directory are each refused with the code; no process is started and nothing leaks.
    const cases = [_]struct { net: [:0]const u8, path: [:0]const u8 }{
        .{ .net = "host", .path = hosts_path },
        .{ .net = "none", .path = "mesh/hosts" },
        .{ .net = "none", .path = "/srv/mesh/absent" },
        .{ .net = "none", .path = "/srv/mesh/dir" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        prepared(&sim, 82);
        const before = sim_run.baseline(&sim);
        const code = run_with(&sim, case.net, case.path);
        try testing.expect(code >= 125);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0612") != null);
        try testing.expect(!sim.world.processes[1].execd);
        try no_leak(&sim, &before);
    }
    try testing.expect(@backingInt(codes.Code.E0612) != 0);
}
