//! `--gpu all|dri` in a run, against the simulator (docs/briefs/M10-gpu.md, slice 3): the
//! keyword becomes devices at the start, the record keeps what was asked, and a host with
//! nothing to give is E0228 before anything is made. The VM shows the same on a real kernel.

const std = @import("std");
const host_sim = @import("../host_sim.zig");
const gpu = @import("gpu.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const char_mode: u32 = 0o020660;

const nvidia_spec =
    \\{"cdiVersion":"0.6.0","kind":"nvidia.com/gpu","devices":[
    \\ {"name":"0","containerEdits":{"deviceNodes":[{"path":"/dev/nvidia0"}]}}]}
;

/// A `HostSim` is large; the test binary's static data is near its bound, so it is on the heap.
fn sim_get() *HostSim {
    return testing.allocator.create(HostSim) catch @panic("out of memory");
}

const Host = struct {
    /// Render nodes group 44 can open (the user is in it), then ones it cannot.
    open: u32,
    locked: u32,
    kfd: bool,
    spec: bool,
};

const render_names = [_][]const u8{
    "/dev/dri/renderD128", "/dev/dri/renderD129", "/dev/dri/renderD130",
};

/// The files of a simulated host: the run's own, the nodes `host` has, and the spec.
const Files = struct {
    items: [sim_run.files.len + 8]host_sim.File,
    count: u32,

    fn add(files: *Files, file: host_sim.File) void {
        files.items[files.count] = file;
        files.count += 1;
    }
};

fn setup(sim: *HostSim, files: *Files, host: Host) void {
    files.count = 0;
    for (sim_run.files) |file| files.add(file);
    for (render_names[0 .. host.open + host.locked], 0..) |path, index| {
        const gid: u32 = if (index < host.open) 44 else 99;
        files.add(.{ .path = path, .content = "", .mode = char_mode, .gid = gid });
    }
    files.add(.{ .path = "/dev/dri/card0", .content = "", .mode = char_mode, .gid = 44 });
    if (host.kfd) files.add(.{ .path = "/dev/kfd", .content = "", .mode = char_mode, .gid = 44 });
    if (host.spec) files.add(.{ .path = "/dev/nvidia0", .content = "", .mode = 0o020666 });
    sim_run.start(sim, 5, files.items[0..files.count]);
    sim.groups[0] = 44;
    sim.groups_count = 1;
    sim.world.add_node("/dev/dri", .dir);
    for (files.items[sim_run.files.len..files.count]) |file| {
        // A directory listing shows written files only, so the render nodes are written.
        if (std.mem.startsWith(u8, file.path, "/dev/dri/")) {
            std.debug.assert(sim.world.write_file(file.path, "") == null);
        } else sim.world.add_node(file.path, .file);
    }
    if (host.spec) {
        sim.world.add_node("/etc/cdi", .dir);
        std.debug.assert(sim.world.write_file("/etc/cdi/nvidia.json", nvidia_spec) == null);
    }
}

fn run_gpu(sim: *HostSim, word: [:0]const u8) u8 {
    const line = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--name", "g-1", "--gpu", word, "--", "/bin/sh",
    };
    return sim_run.run_cli(sim, &line);
}

fn bound(sim: *HostSim, path: []const u8) bool {
    const table = &sim.world.tables[sim.world.processes[1].table];
    var target: [128]u8 = undefined;
    const made = std.fmt.bufPrint(&target, "{s}{s}", .{ rootfs, path }) catch
        unreachable; // A short root and a device path fit 128 bytes.
    return table.find(made) != null;
}

test "--gpu dri binds the render nodes the user can open and /dev/kfd, not card0 nor a locked one" {
    // Goal: the dri semantics. Method: two openable nodes, one locked, card0 and kfd.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    var files: Files = undefined;
    setup(sim, &files, .{ .open = 2, .locked = 1, .kfd = true, .spec = false });
    const code = run_gpu(sim, "dri");
    if (code != 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(bound(sim, "/dev/dri/renderD128"));
    try testing.expect(bound(sim, "/dev/dri/renderD129"));
    try testing.expect(bound(sim, "/dev/kfd"));
    try testing.expect(!bound(sim, "/dev/dri/renderD130"));
    try testing.expect(!bound(sim, "/dev/dri/card0"));
    // The record keeps what was asked, not what was resolved.
    const record = sim.world.read_written(sim_run.runs_path ++ "/g-1.zon").?;
    try testing.expect(std.mem.indexOf(u8, record, ".devices = \"gpu=dri\",") != null);
    try testing.expect(std.mem.indexOf(u8, record, "renderD128") == null);
}

test "--gpu all is the NVIDIA CDI devices when a spec has them, and the render nodes otherwise" {
    // Goal: the rule of the brief, both ways. Method: a host with a spec and nodes, then nodes.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    var files: Files = undefined;
    setup(sim, &files, .{ .open = 1, .locked = 0, .kfd = false, .spec = true });
    try testing.expectEqual(@as(u8, 0), run_gpu(sim, "all"));
    try testing.expect(bound(sim, "/dev/nvidia0"));
    try testing.expect(!bound(sim, "/dev/dri/renderD128"));
    const record = sim.world.read_written(sim_run.runs_path ++ "/g-1.zon").?;
    try testing.expect(std.mem.indexOf(u8, record, ".devices = \"gpu=all\",") != null);
    setup(sim, &files, .{ .open = 1, .locked = 0, .kfd = false, .spec = false });
    try testing.expectEqual(@as(u8, 0), run_gpu(sim, "all"));
    try testing.expect(bound(sim, "/dev/dri/renderD128"));
}

test "--gpu with nothing to give is E0228, naming what was found and the fix" {
    // Goal: no GPU is a refusal before anything is made, and a node the user cannot open is
    // counted. Method: an empty host, then one with only a locked node.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    var files: Files = undefined;
    setup(sim, &files, .{ .open = 0, .locked = 0, .kfd = false, .spec = false });
    try testing.expectEqual(@as(u8, 125), run_gpu(sim, "all"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0228") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "zbx doctor") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "none openable") == null);
    setup(sim, &files, .{ .open = 0, .locked = 1, .kfd = false, .spec = false });
    try testing.expectEqual(@as(u8, 125), run_gpu(sim, "dri"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "1 found, none openable by you") != null);
}

test "--gpu takes all or dri only, and a repeat is refused" {
    // Goal: the value is checked while the command line is read.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    var files: Files = undefined;
    setup(sim, &files, .{ .open = 1, .locked = 0, .kfd = false, .spec = false });
    try testing.expectEqual(@as(u8, 125), run_gpu(sim, "nvidia"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0225") != null);
    const twice = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--gpu", "dri", "--gpu", "dri", "--", "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 125), sim_run.run_cli(sim, &twice));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0225") != null);
}

test "look_dri and expand serve a caller that has no command line" {
    // Goal: the library path (CS4): Zigcube's agent looks at its own host and expands the ask.
    const sim = sim_get();
    defer testing.allocator.destroy(sim);
    var files: Files = undefined;
    setup(sim, &files, .{ .open = 2, .locked = 1, .kfd = true, .spec = false });
    var dri: gpu.Dri = undefined;
    gpu.look_dri(sim.interface(), &dri);
    try testing.expectEqual(@as(u32, 3), dri.count);
    try testing.expectEqual(@as(u32, 1), dri.unopenable);
    try testing.expectEqualStrings("/dev/dri/renderD128", dri.path(0));
    try testing.expectEqualStrings("/dev/kfd", dri.path(2));
}
