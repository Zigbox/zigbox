//! A simulation of the run gate through the whole command line: over many seeded policy files
//! (valid, empty, requiring, broken), a run the policy refuses never starts a container (no
//! scope is made, nothing on stdout) and leaves nothing in the user's files.

const std = @import("std");
const testing = std.testing;
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("../runtime/sim_run.zig");

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;

const policy_path = "/home/alice/.config/zbx/policy.zon";

/// One policy text for `choice`, and whether the gate must refuse a run of a directory under it.
const Case = struct { text: []const u8, refuses: bool };

fn case_of(choice: u32) Case {
    return switch (choice % 8) {
        0 => .{ .text = ".{ .version = 1 }", .refuses = false },
        1 => .{ .text = ".{ .version = 1, .require_signature = true }", .refuses = true },
        2 => .{ .text = ".{ .version = 1, .require_signature = false }", .refuses = false },
        3 => .{ .text = "not a policy", .refuses = true },
        4 => .{ .text = ".{ .version = 1, .extra = true }", .refuses = true },
        5 => .{ .text = ".{ .version = 2 }", .refuses = true },
        6 => .{
            .text = ".{ .version = 1, .keys = .{}, .require_signature = true }",
            .refuses = true,
        },
        else => .{ .text = "", .refuses = true },
    };
}

test "over random policies, a refused run starts nothing and leaves nothing" {
    // Goal: the gate stands in front of the start for every policy file. Method: 64 seeds, each
    // picks a policy; refusal is exit 125 with no scope and no output; a policy that asks nothing
    // lets the run begin (a scope is made). Either way the files of the host are as they were.
    var seed: u32 = 0;
    while (seed < 64) : (seed += 1) {
        sim_run.init(&sim, 6 + seed);
        files.init(1);
        sim.store_fs = &files;
        files.put_dir("/home", 0o755);
        files.put_dir("/home/alice", 0o755);
        files.put_dir("/home/alice/.config", 0o755);
        files.put_dir("/home/alice/.config/zbx", 0o700);
        const picked = case_of(seed * 5 + seed / 8);
        files.put_file(policy_path, 0o644, picked.text);
        const before = files.live_count();
        const args = [_][:0]const u8{
            "zbx", "run", "--rootfs", sim_run.rootfs_path, "--", "/bin/true",
        };
        const exit = sim_run.run_cli(&sim, &args);
        if (picked.refuses) {
            try testing.expectEqual(@as(u8, 125), exit);
            try testing.expectEqual(@as(usize, 0), sim.stdout().len);
            try testing.expect(sim.world.bus.scope_started == null);
        }
        try testing.expectEqual(before, files.live_count());
    }
}
