//! A CDI device in a run, against the simulator (docs/briefs/M10-gpu.md, slice 2): the name is
//! resolved from the spec the host has, the record keeps the name and not the node, `ps` shows
//! what was asked, and a run asks for the library cache once.

const std = @import("std");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");
const host_mod = @import("../host.zig");
const cdi = @import("cdi.zig");
const run_lib = @import("run.zig");
const Diag = @import("../diag/diag.zig").Diag;

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

const library_spec =
    \\{"cdiVersion":"0.6.0","kind":"vendor.example/gpu","devices":[
    \\ {"name":"0","containerEdits":{"deviceNodes":[{"path":"/dev/fake0"}],"mounts":[
    \\  {"hostPath":"/srv/data","containerPath":"/opt/vendor/lib"},
    \\  {"hostPath":"/srv/note","containerPath":"/opt/vendor/note.conf"}],
    \\  "hooks":[{"hookName":"createContainer","path":"/usr/bin/nvidia-cdi-hook",
    \\   "args":["nvidia-cdi-hook","update-ldcache","--folder","/opt/vendor/lib"]}]}}]}
;

fn setup_with(sim: *HostSim, content: []const u8) void {
    setup(sim);
    sim_run.add_mount_sources(sim);
    std.debug.assert(sim.world.write_file("/etc/cdi/example.json", content) == null);
}

const library_run = [_][:0]const u8{
    "zbx",      "run",                  "--rootfs", sim_run.rootfs_path, "--name", "c-2",
    "--device", "vendor.example/gpu=0", "--",       "/bin/sh",
};

test "mounts are staged and moved, and a missing ldconfig puts the directory on the path" {
    // Goal: the library half of a CDI device. Method: a directory and a file mount, and the
    // update-ldcache hook; the simulator has no ldconfig, so the fallback is taken. The mounts
    // are in the new root at their paths and the hidden stage names are gone; the command
    // has LD_LIBRARY_PATH with the directory, and W0208 is said once.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup_with(sim, library_spec);
    const code = sim_run.run_cli(sim, &library_run);
    if (code != 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    const child = &sim.world.processes[1];
    const table = &sim.world.tables[child.table];
    const directory = table.find(sim_run.rootfs_path ++ "/opt/vendor/lib").?;
    try testing.expectEqual(@as(?host_mod.MountKind, .bind_tree), table.mounts[directory].kind);
    try testing.expect(table.mounts[directory].read_only);
    const file = table.find(sim_run.rootfs_path ++ "/opt/vendor/note.conf").?;
    try testing.expectEqual(@as(?host_mod.MountKind, .bind_file), table.mounts[file].kind);
    try testing.expect(table.find("/dev/.zbx-cdi-0") == null);
    try testing.expect(table.find("/dev/.zbx-cdi-1") == null);
    const want = "LD_LIBRARY_PATH=/opt/vendor/lib";
    try testing.expect(std.mem.indexOf(u8, child.envp(), want) != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0208"));
}

test "the CDI directories come before the library path the image or the user has" {
    // Goal: the fallback keeps the user's directories, after the vendor's. Method: the same run
    // with -e LD_LIBRARY_PATH.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup_with(sim, library_spec);
    const run = [_][:0]const u8{
        "zbx",      "run",                  "-e",     "LD_LIBRARY_PATH=/opt/app/lib",
        "--rootfs", sim_run.rootfs_path,    "--name", "c-3",
        "--device", "vendor.example/gpu=0", "--",     "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(sim, &run));
    const envp = sim.world.processes[1].envp();
    const want = "LD_LIBRARY_PATH=/opt/vendor/lib:/opt/app/lib";
    try testing.expect(std.mem.indexOf(u8, envp, want) != null);
}

test "--read-only with a device that has mounts is refused with one line; nodes alone are fine" {
    // Goal: a read-only root has no place to make the mount targets, so the run says so before
    // anything starts. Method: the library spec, then the node-only spec of `setup`.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup_with(sim, library_spec);
    const run = [_][:0]const u8{
        "zbx",     "run", "--read-only", "--rootfs",             sim_run.rootfs_path,
        "--name",  "c-4", "--device",    "vendor.example/gpu=0", "--",
        "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 125), sim_run.run_cli(sim, &run));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0227]: "));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "--read-only") != null);
    try testing.expect(!sim.world.processes[1].execd);
    std.debug.assert(sim.world.write_file("/etc/cdi/example.json", spec) == null);
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(sim, &run));
}

test "a resolved set given to the library gets the host check: kinds noted, absent nodes refused" {
    // Goal: `Spec.cdi` skips discovery, not the look at the host. Method: a set with a directory
    // mount starts (the target is a tree bind, not a file), and a set with a node the host lacks
    // is refused with E0225 before anything starts.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup_with(sim, spec);
    const handle = try std.heap.page_allocator.create(run_lib.Handle);
    defer std.heap.page_allocator.destroy(handle);
    const given = try testing.allocator.create(cdi.Resolved);
    defer testing.allocator.destroy(given);
    given.reset();
    given.mounts[0] = .{ .host = given.keep("/srv/data").?, .container = given.keep("/opt/v").? };
    given.mount_is_dir[0] = false; // Wrong on purpose: the run must correct it.
    given.mounts_count = 1;
    var diag: Diag = undefined;
    diag.reset();
    const run: run_lib.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "g-1",
        .command = &.{"/bin/sh"},
        .devices = &.{.{ .path = "vendor.example/gpu=0" }},
        .cdi = given,
    };
    try run_lib.start(sim.interface(), &run, .{}, handle, &diag);
    handle.session.release_output();
    const table = &sim.world.tables[sim.world.processes[1].table];
    const at = table.find(sim_run.rootfs_path ++ "/opt/v").?;
    try testing.expectEqual(@as(?host_mod.MountKind, .bind_tree), table.mounts[at].kind);
    // A node the host lacks.
    const sim_two = sim_get();
    defer testing.allocator.destroy(sim_two);
    setup_with(sim_two, spec);
    given.reset();
    given.nodes[0] = given.keep("/dev/absent0").?;
    given.nodes_count = 1;
    diag.reset();
    const result = run_lib.start(sim_two.interface(), &run, .{}, handle, &diag);
    try testing.expectError(error.StartFailed, result);
    try testing.expectEqual(@as(?@TypeOf(diag.code.?), .E0225), diag.code);
    try testing.expect(!sim_two.world.processes[1].execd);
}

test "/var/run/cdi wins over /etc/cdi for the same device" {
    // Goal: the reference order, the later directory overrides. Method: the same name in both
    // directories, with a variable only the /var/run one sets.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup(sim);
    sim.world.add_node("/var/run/cdi", .dir);
    const other =
        \\{"cdiVersion":"0.6.0","kind":"vendor.example/gpu","devices":[
        \\ {"name":"0","containerEdits":{"env":["WON=var-run"],
        \\  "deviceNodes":[{"path":"/dev/fake0"}]}}]}
    ;
    std.debug.assert(sim.world.write_file("/var/run/cdi/example.json", other) == null);
    const code = sim_run.run_cli(sim, &library_run_plain);
    if (code != 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    const envp = sim.world.processes[1].envp();
    try testing.expect(std.mem.indexOf(u8, envp, "WON=var-run") != null);
}

const library_run_plain = [_][:0]const u8{
    "zbx",      "run",                  "--rootfs", sim_run.rootfs_path, "--name", "c-5",
    "--device", "vendor.example/gpu=0", "--",       "/bin/sh",
};

test "a directory with more than 64 spec files is refused with one line" {
    // Goal: discovery is bounded and says so. Method: 65 files in /etc/cdi.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup(sim);
    var name: [32]u8 = undefined;
    for (0..65) |at| {
        const format = "/etc/cdi/s{d:0>3}.json";
        // 32 bytes hold the longest name.
        const path = std.fmt.bufPrint(&name, format, .{at}) catch unreachable;
        std.debug.assert(sim.world.write_file(path, spec) == null);
    }
    try testing.expectEqual(@as(u8, 125), sim_run.run_cli(sim, &library_run_plain));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0226]: "));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "64") != null);
}

fn write_specs(sim: *HostSim, directory: []const u8, count: usize, first: usize) void {
    var name: [48]u8 = undefined;
    for (first..first + count) |at| {
        const path = std.fmt.bufPrint(&name, "{s}/s{d:0>3}.json", .{ directory, at }) catch unreachable;
        std.debug.assert(sim.world.write_file(path, spec) == null);
    }
}

test "exactly 64 spec files in a directory resolve the device" {
    // Goal: the bound is at 64, not below. Method: example.json from setup plus 63 more is 64.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup(sim);
    write_specs(sim, "/etc/cdi", 63, 0);
    const code = sim_run.run_cli(sim, &library_run_plain);
    if (code != 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
}

test "the spec file count sums across directories" {
    // Goal: 64 is the count over all directories. Method: 40 in /var/run/cdi, then /etc/cdi has
    // example.json plus 23 more (64 in all) and works; one more file there is E0226 on /etc/cdi.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    setup(sim);
    sim.world.add_node("/var/run/cdi", .dir);
    write_specs(sim, "/var/run/cdi", 40, 0);
    write_specs(sim, "/etc/cdi", 23, 0);
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(sim, &library_run_plain));
    write_specs(sim, "/etc/cdi", 1, 500);
    try testing.expectEqual(@as(u8, 125), sim_run.run_cli(sim, &library_run_plain));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0226]: ") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "/etc/cdi") != null);
}
