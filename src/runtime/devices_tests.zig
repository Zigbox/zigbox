//! `--device` in a run, against the simulator (docs/briefs/M10-gpu.md, slice 1): a node of the
//! host bound into the container's /dev, the refusals before anything starts, the record, and
//! the supplementary groups kept in both mapping modes. The VM shows the kernel agrees (a node
//! 0660 root:render opens for a member of render and is refused to anyone else).

const std = @import("std");
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const host_mod = @import("../host.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const run_lib = @import("run.zig");
const Diag = @import("../diag/diag.zig").Diag;
const SimFs = @import("../store/fs_sim.zig").SimFs;
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const render = "/dev/dri/renderD128";
const char_mode: u32 = 0o020660;

/// A host with a render node that group 44 can open and a block device nobody can use.
const device_files = [_]host_sim.File{
    .{ .path = render, .content = "", .mode = char_mode, .gid = 44 },
    .{ .path = "/dev/dri/card0", .content = "", .mode = char_mode, .gid = 44 },
    .{ .path = "/dev/sda", .content = "", .mode = 0o060660, .gid = 6 },
    .{ .path = "/dev/locked", .content = "", .mode = 0o020600, .readable = false },
};

fn setup(sim: *HostSim, seed: u64, files: []const host_sim.File) void {
    sim_run.start(sim, seed, files);
    sim.groups[0] = 44;
    sim.groups_count = 1;
    // The bind's source is looked up in the world's tree, as the host's own files are.
    for (device_files) |file| sim.world.add_node(file.path, .file);
}

fn run(sim: *HostSim, words: []const [:0]const u8) u8 {
    var items: [32][:0]const u8 = undefined;
    items[0] = "zbx";
    for (words, 1..) |word, index| items[index] = word;
    return sim_run.run_cli(sim, items[0 .. words.len + 1]);
}

fn record_of(sim: *const HostSim, name: []const u8) ?[]const u8 {
    var path: [128]u8 = undefined;
    const format = sim_run.runs_path ++ "/{s}.zon";
    const text = std.fmt.bufPrint(&path, format, .{name}) catch unreachable; // Short.
    return sim.world.read_written(text);
}

const two = [_][:0]const u8{
    "run",            "--rootfs", rootfs,    "--name", "d-1", "--device", render, "--device",
    "/dev/dri/card0", "--",       "/bin/sh",
};

const none = [_][:0]const u8{ "run", "--rootfs", rootfs, "--name", "n-1", "--", "/bin/sh" };

fn with_files(comptime base: []const host_sim.File) [base.len + device_files.len]host_sim.File {
    return base[0..base.len].* ++ device_files;
}

test "a run binds each device into /dev at its own path, and says the groups carry over once" {
    // Goal: the success path. Method: two devices; each is a file bind in the container's
    // mount table, in a /dev/dri the run made; W0209 once; the host's nodes untouched.
    const files = with_files(&sim_run.files);
    var sim: HostSim = undefined;
    setup(&sim, 1, &files);
    try testing.expectEqual(@as(u8, 0), run(&sim, &two));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0209"));
    const table = &sim.world.tables[sim.world.processes[1].table];
    inline for (.{ render, "/dev/dri/card0" }) |path| {
        const at = table.find(rootfs ++ path).?;
        try testing.expectEqual(@as(?host_mod.MountKind, .bind_file), table.mounts[at].kind);
    }
    try testing.expect(sim.world.find_node(rootfs ++ "/dev/dri") != null);
}

test "a device the host does not show, cannot open or is not a character device is E0225" {
    // Goal: every refusal comes before anything is made, with one line saying why.
    const files = with_files(&sim_run.files);
    const cases = [_]struct { path: [:0]const u8, words: []const u8 }{
        .{ .path = "/dev/nothing", .words = "is not on this host" },
        .{ .path = "/dev/sda", .words = "not a character device" },
        .{ .path = "/dev/locked", .words = "you cannot open" },
    };
    var sim: HostSim = undefined;
    for (cases) |case| {
        setup(&sim, 2, &files);
        const line = [_][:0]const u8{
            "run", "--rootfs", rootfs, "--name", "x-1", "--device", case.path, "--", "/bin/sh",
        };
        try testing.expectEqual(@as(u8, 125), run(&sim, &line));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0225") != null);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.words) != null);
        var target: [128]u8 = undefined;
        const format = rootfs ++ "{s}";
        const made = std.fmt.bufPrint(&target, format, .{case.path}) catch unreachable; // Short.
        try testing.expect(sim.world.find_node(made) == null);
    }
}

test "a path --device does not take is E0225 at the command line" {
    // Goal: the text rules (below /dev, no '..', not one of M1's six, once each) are refused
    // while the command line is read.
    const files = with_files(&sim_run.files);
    const bad = [_][:0]const u8{ "/etc/passwd", "/dev/null", "/dev/../etc/x", "/dev/a:b" };
    var sim: HostSim = undefined;
    for (bad) |path| {
        setup(&sim, 3, &files);
        const line = [_][:0]const u8{ "run", "--rootfs", rootfs, "--device", path, "--", "sh" };
        try testing.expectEqual(@as(u8, 125), run(&sim, &line));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0225") != null);
    }
    setup(&sim, 3, &files);
    const twice = [_][:0]const u8{
        "run", "--rootfs", rootfs, "--device", render, "--device", render, "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &twice));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "given twice") != null);
}

test "the record keeps the devices, and a run without devices writes what it always did" {
    // Goal: additive records. A run with devices is version 10 with `.devices`; one without has
    // no such line, is version 9, and says nothing about groups.
    const files = with_files(&sim_run.files);
    var sim: HostSim = undefined;
    setup(&sim, 4, &files);
    try testing.expectEqual(@as(u8, 0), run(&sim, &two));
    const record = record_of(&sim, "d-1").?;
    try testing.expect(std.mem.indexOf(u8, record, ".version = 10,") != null);
    const line = ".devices = \"/dev/dri/renderD128 /dev/dri/card0\",";
    try testing.expect(std.mem.indexOf(u8, record, line) != null);
    var parsed: records.Parsed = undefined;
    try records.parse(record, &parsed);
    try testing.expectEqualStrings(
        "/dev/dri/renderD128 /dev/dri/card0",
        parsed.devices_text(),
    );
    var plain: HostSim = undefined;
    setup(&plain, 4, &files);
    try testing.expectEqual(@as(u8, 0), run(&plain, &none));
    const old = record_of(&plain, "n-1").?;
    try testing.expect(std.mem.indexOf(u8, old, ".version = 9,") != null);
    try testing.expect(std.mem.indexOf(u8, old, ".devices") == null);
    try testing.expectEqual(@as(usize, 0), plain.stderr().len);
    try records.parse(old, &parsed);
    try testing.expectEqual(@as(usize, 0), parsed.devices_text().len);
}

test "the plan of a run without devices has no device step, and one with has two each" {
    // Goal: a run that asks for nothing is the plan it was. Method: build both, count steps.
    var base: plan_mod.Plan = undefined;
    const input: plan_mod.Input = .{
        .rootfs = rootfs,
        .name = "plan",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = .single,
        .network = .none,
    };
    base.build(&input);
    try testing.expectEqual(base.count, base.steps_expected());
    var more_input = input;
    more_input.devices = &.{ render, "/dev/dri/card0" };
    var more: plan_mod.Plan = undefined;
    more.build(&more_input);
    try testing.expectEqual(more.count, more.steps_expected());
    try testing.expectEqual(base.count + 2 * plan_mod.user_device_steps_count, more.count);
}

test "a run with devices keeps its groups in both mapping modes, and one without drops them" {
    // Goal: the rule the brief makes, and that it is not hard-coded either way. Method: start a
    // container through the library (the command line refuses `--user` for a directory) that
    // becomes a user, in the full-range map (1000:1000) and in the single-id map (the only user
    // it can be is 0:0, for which no step becomes a user), each with and without devices; the simulator counts the child's
    // setgroups calls. With devices there are none; without, exactly one in the full map and
    // none in the single-id map, where there is nothing to drop. The user is checked, so the
    // count is of a step that ran.
    const full = with_files(&sim_run.files);
    const single = with_files(&sim_run.files_single);
    const cases = [_]struct { files: []const host_sim.File, uid: u32 }{
        .{ .files = &full, .uid = 1000 },
        .{ .files = &single, .uid = 0 },
    };
    // On the heap: the simulator's tables already fill the test binary's static data.
    const disk = try std.heap.page_allocator.create(SimFs);
    defer std.heap.page_allocator.destroy(disk);
    const handle = try std.heap.page_allocator.create(run_lib.Handle);
    defer std.heap.page_allocator.destroy(handle);
    var sim: HostSim = undefined;
    for (cases) |case| {
        for ([_]bool{ true, false }) |with_devices| {
            setup(&sim, 5, case.files);
            disk.init(5);
            disk.put_dir("/home", 0o755);
            disk.put_dir("/home/alice", 0o755);
            sim.log_fs = disk;
            var diag: Diag = undefined;
            diag.reset();
            const spec: run_lib.Spec = .{
                .rootfs = rootfs,
                .name = "g-1",
                .command = &.{"/bin/sh"},
                .user = .{ .uid = case.uid, .gid = case.uid },
                .devices = if (with_devices) &.{.{ .path = render }} else &.{},
            };
            try run_lib.start(sim.interface(), &spec, .{}, handle, &diag);
            handle.session.release_output();
            const child = sim.world.find_process(handle.pid).?;
            // The single-id map has only root, and root is not a step: no user is set, no
            // groups are dropped, with or without devices. Only the full map can fail here.
            const user: ?[2]u32 = if (case.uid == 0) null else .{ case.uid, case.uid };
            try testing.expectEqual(user, child.user_set);
            const expected: u32 = if (with_devices or case.uid == 0) 0 else 1;
            try testing.expectEqual(expected, sim.world.setgroups_calls);
        }
    }
}
