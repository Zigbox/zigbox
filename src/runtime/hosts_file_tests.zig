//! `--hosts-file` (Zigcube's ZB-6) against the simulator: the caller's file is bound at
//! /etc/hosts read-only instead of the generated one, and every refusal is one coded line,
//! E0612, before anything starts. The VM (`demo-c4`) shows the real thing: a rewrite in place
//! seen by `zbx exec`, a rename over it not.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
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
    .{ .path = "/srv/mesh/locked", .content = "127.0.0.1 localhost\n", .readable = false },
};

fn prepared(sim: *HostSim, seed: u64) void {
    sim_run.start(sim, seed, &host_files);
    sim.world.add_node("/srv/mesh", .dir);
    sim.world.add_node(hosts_path, .file);
    sim.world.add_node("/srv/mesh/dir", .dir);
    sim.world.add_node("/srv/mesh/locked", .file);
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
    // Goal: the refusals. Method: a container with a network, a relative path, a missing file,
    // a directory and a file this user cannot read are each refused with the code; no process
    // is started and nothing leaks.
    const cases = [_]struct { net: [:0]const u8, path: [:0]const u8 }{
        .{ .net = "host", .path = hosts_path },
        .{ .net = "none", .path = "mesh/hosts" },
        .{ .net = "none", .path = "/srv/mesh/absent" },
        .{ .net = "none", .path = "/srv/mesh/dir" },
        .{ .net = "none", .path = "/srv/mesh/locked" },
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

test "--hosts-file: a bind of the given file that fails is a failed start, not a note" {
    // Goal: the hosts bind is not tolerant, unlike the generated files' steps. Method: fail the
    // first call of each plan step in turn until the failure lands on the bind of the given file
    // (`-v` names the step); that run is an error, exit 125, starts no command and leaks nothing.
    const args = [_][:0]const u8{
        "zbx",    "-v",    "run", "--rootfs", rootfs, "--net", "none", "--hosts-file", hosts_path,
        "--name", "box-1", "--",  "sh",
    };
    var found = false;
    for (0..constants.plan_steps_max) |index| {
        var sim: HostSim = undefined;
        prepared(&sim, 83);
        const before = sim_run.baseline(&sim);
        sim.faults.fail_step = @intCast(index);
        sim.faults.fail_step_errno = 1;
        const code = sim_run.run_cli(&sim, &args);
        const err = sim.stderr();
        if (std.mem.indexOf(u8, err, "step   bind_etc_file") == null) continue;
        if (!std.mem.startsWith(u8, err, "error[")) continue; // A generated file's note.
        try testing.expectEqual(@as(u8, 125), code);
        try testing.expect(!sim.world.processes[1].execd);
        try no_leak(&sim, &before);
        found = true;
        break;
    }
    try testing.expect(found);
}

test "--hosts-file: a look that fails is worded by its cause, not always as permission" {
    // Goal: only a permission error reads "cannot be read by this user". Method: fail each host
    // call of a run in turn, once with an I/O error and once with EACCES, until the failure
    // lands on the hosts file's stat and on its first read. An I/O error there names the path
    // problem or the failed read; EACCES names this user. Each is E0612 and starts nothing.
    const errors = [_]host_mod.Error{ error.IoFailed, error.AccessDenied };
    const wanted = [_][2][]const u8{
        .{ "cannot be followed to a file", "could not be read (a file system error" },
        .{ "cannot be read by this user", "cannot be read by this user" },
    };
    for (errors, wanted) |err, words| {
        var found_stat = false;
        var found_read = false;
        for (0..calls_walked_max) |index| {
            var sim: HostSim = undefined;
            prepared(&sim, 84);
            sim.faults.fail_call_index = sim.call_count + @as(u32, @intCast(index));
            sim.faults.fail_call_error = err;
            _ = run_with(&sim, "none", hosts_path);
            const stderr = sim.stderr();
            if (std.mem.indexOf(u8, stderr, "ZBX-E0612") == null) continue;
            try testing.expect(!sim.world.processes[1].execd);
            if (err == error.IoFailed) {
                try testing.expect(std.mem.indexOf(u8, stderr, "by this user") == null);
            }
            if (std.mem.indexOf(u8, stderr, words[0]) != null) found_stat = true;
            if (std.mem.indexOf(u8, stderr, words[1]) != null) found_read = true;
            if (found_stat and found_read) break;
        }
        try testing.expect(found_stat);
        try testing.expect(found_read);
    }
}

/// How many host calls of a run the wording test fails in turn; the hosts file is looked at
/// well before this many.
const calls_walked_max = 400;
