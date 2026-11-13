//! A simulation of the run gate through the whole command line: over many seeded policy files
//! (valid, empty, requiring, broken), a run the policy refuses never starts a container (no
//! scope is made, nothing on stdout) and leaves nothing in the user's files. The library's start
//! (`start_gate.zig`) is driven over the same policies and must agree.

const std = @import("std");
const testing = std.testing;
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("../runtime/sim_run.zig");
const Diag = @import("../diag/diag.zig").Diag;
const run = @import("../runtime/run.zig");
const start_gate = @import("start_gate.zig");

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var gate_ws: start_gate.Workspace = undefined;
var handle: run.Handle = undefined;

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
        const picked = case_of(seed * 5 + seed / 8);
        host_with(seed, picked);
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

/// A host whose user has the policy file `picked` says.
fn host_with(seed: u32, picked: Case) void {
    sim_run.init(&sim, 6 + seed);
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir("/home/alice/.config", 0o755);
    files.put_dir("/home/alice/.config/zbx", 0o700);
    files.put_file(policy_path, 0o644, picked.text);
}

test "over random policies, the library's start refuses what zbx run refuses" {
    // Goal: the library's door has the same gate. Method: the 64 seeds above; `zigbox.start` of
    // the same directory is refused with a trust code (E0904 or E0905) and starts no scope
    // exactly when `zbx run` would, and leaves the host's files as they were.
    var seed: u32 = 0;
    while (seed < 64) : (seed += 1) {
        const picked = case_of(seed * 5 + seed / 8);
        host_with(seed, picked);
        const before = files.live_count();
        const spec: run.Spec = .{
            .rootfs = sim_run.rootfs_path,
            .name = "lib-sim",
            .command = &.{"/bin/true"},
        };
        var diag: Diag = undefined;
        diag.reset();
        const started = start_gate.start(sim.interface(), &spec, .{}, &handle, &gate_ws, &diag);
        if (picked.refuses) {
            try testing.expectError(error.StartFailed, started);
            const name = @tagName(diag.code.?);
            try testing.expect(std.mem.eql(u8, name, "E0904") or std.mem.eql(u8, name, "E0905"));
            try testing.expect(sim.world.bus.scope_started == null);
        } else if (diag.code) |code| {
            try testing.expect(!std.mem.startsWith(u8, @tagName(code), "E090"));
        }
        try testing.expectEqual(before, files.live_count());
    }
}
