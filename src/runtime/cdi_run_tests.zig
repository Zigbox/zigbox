//! A CDI device in a run, against the simulator (docs/briefs/M10-gpu.md, slice 2): the name is
//! resolved from the spec the host has, the record keeps the name and not the node, `ps` shows
//! what was asked, and a run asks for the library cache once.

const std = @import("std");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const spec =
    \\{"cdiVersion":"0.6.0","kind":"vendor.example/gpu","devices":[
    \\ {"name":"0","containerEdits":{"deviceNodes":[{"path":"/dev/fake0"}]}}]}
;

/// A `HostSim` is large; the test binary's static data is near its bound, so it is on the heap.
fn sim_get() *HostSim {
    return testing.allocator.create(HostSim) catch @panic("out of memory");
}

fn setup(sim: *HostSim) void {
    const files = sim_run.files ++ [_]host_sim.File{
        .{ .path = "/dev/fake0", .content = "", .mode = 0o020666 },
    };
    sim_run.start(sim, 3, &files);
    sim.world.add_node("/dev/fake0", .file);
    sim.world.add_node("/etc/cdi", .dir);
    std.debug.assert(sim.world.write_file("/etc/cdi/example.json", spec) == null);
}

test "a CDI name is kept in the record, and ps shows it as asked, without a node" {
    // Goal: a record never holds what the specs resolve to, so a start after a reboot resolves
    // again. Method: run with a name, read `ps --output json`.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup(sim);
    const run = [_][:0]const u8{
        "zbx",      "run",                  "--rootfs", sim_run.rootfs_path, "--name", "c-1",
        "--device", "vendor.example/gpu=0", "--",       "/bin/sh",
    };
    const code = sim_run.run_cli(sim, &run);
    if (code != 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    const record = sim.world.read_written(sim_run.runs_path ++ "/c-1.zon").?;
    const line = ".devices = \"vendor.example/gpu=0\",";
    try testing.expect(std.mem.indexOf(u8, record, line) != null);
    try testing.expect(std.mem.indexOf(u8, record, "/dev/fake0") == null);
    const ps = [_][:0]const u8{ "zbx", "ps", "--all", "--output", "json" };
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(sim, &ps));
    const out = sim.stdout();
    const shown = "\"devices\":[{\"asked\":\"vendor.example/gpu=0\"}]";
    try testing.expect(std.mem.indexOf(u8, out, shown) != null);
}
