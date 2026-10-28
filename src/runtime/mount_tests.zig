//! The other mounts in a run, against the simulator (docs/briefs/M6-state.md, "Other mounts"):
//! a tmpfs, a bind of a directory and of a file, and a secret, each made where the container
//! reads its path; the plan's order of steps; the record that names them and never holds a
//! secret's bytes; and every refusal before anything starts. The VM shows the kernel agrees
//! (a secret mode 0400, a bind that cannot be written, a tmpfs gone after the run).

const std = @import("std");
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const MountKind = @import("../host.zig").MountKind;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const secret_marker = "secret-marker-THETA-91";

/// A host that has a directory, a file and a secret to mount.
const host_files = sim_run.files ++ [_]host_sim.File{
    .{ .path = "/srv/data", .content = "", .mode = 0o040755 },
    .{ .path = "/srv/note", .content = "a note\n", .mode = 0o100644 },
    .{ .path = "/srv/key", .content = secret_marker ++ "\n", .mode = 0o100600 },
    .{ .path = "/srv/socket", .content = "", .mode = 0o140755 },
};

fn setup(sim: *HostSim, seed: u64) void {
    sim_run.start(sim, seed, &host_files);
    // The container's model of the host's tree, which the child binds from.
    sim.world.add_node("/srv/data", .dir);
    sim.world.add_node("/srv/note", .file);
    sim.world.add_node("/srv/key", .file);
}

fn run(sim: *HostSim, words: []const [:0]const u8) u8 {
    var items: [32][:0]const u8 = undefined;
    items[0] = "zbx";
    for (words, 1..) |word, index| items[index] = word;
    return sim_run.run_cli(sim, items[0 .. words.len + 1]);
}

fn record_of(sim: *const HostSim, name: []const u8) ?[]const u8 {
    var path: [128]u8 = undefined;
    // Cannot fail: the runs path and a test name fit in 128 bytes.
    const format = sim_run.runs_path ++ "/{s}.zon";
    const text = std.fmt.bufPrint(&path, format, .{name}) catch unreachable; // Same bound.
    return sim.world.read_written(text);
}

const head = [_][:0]const u8{ "run", "--rootfs", rootfs, "--name", "r-1" };

/// A run of `sh` with `middle` among its options.
fn line_with(comptime middle: []const [:0]const u8) []const [:0]const u8 {
    return &(head ++ middle[0..middle.len].* ++ [_][:0]const u8{ "--", "sh" });
}

const all_four = [_][:0]const u8{
    "run",                 "--rootfs",    rootfs,                      "--name",          "m-1",
    "--tmpfs",             "/scratch:8m", "--bind",                    "/srv/data:/data", "--bind",
    "/srv/note:/etc/note", "--secret",    "/srv/key:/run/secrets/key", "--",              "/bin/sh",
};

test "a run makes a tmpfs, two binds and a secret where the container reads their paths" {
    // Goal: the whole success path. Method: one run with all four; then the container's mounts
    // (each at its path, binds and the secret read-only, the tmpfs sized), the staging names in
    // /dev gone, nothing left on the host, and no descriptor open.
    var sim: HostSim = undefined;
    setup(&sim, 1);
    const before = sim_run.baseline(&sim);
    try testing.expectEqual(@as(u8, 0), run(&sim, &all_four));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    if (sim_run.leak(&sim, &before)) |problem| {
        std.debug.print("leak: {s}\n", .{problem});
        return error.TestUnexpectedResult;
    }
    const table = &sim.world.tables[sim.world.processes[1].table];
    const scratch = table.find(rootfs ++ "/scratch").?;
    try testing.expectEqual(@as(?MountKind, .user_tmpfs), table.mounts[scratch].kind);
    const data = table.find(rootfs ++ "/data").?;
    try testing.expectEqual(@as(?MountKind, .bind_tree), table.mounts[data].kind);
    try testing.expect(table.mounts[data].read_only);
    inline for (.{ "/etc/note", "/run/secrets/key" }) |target| {
        const at = table.find(rootfs ++ target).?;
        try testing.expectEqual(@as(?MountKind, .bind_file), table.mounts[at].kind);
        try testing.expect(table.mounts[at].read_only);
    }
    for (0..4) |index| {
        var stage: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&stage, rootfs ++ "/dev/.zbx-mount-{d}", .{index}) catch
            unreachable; // Short.
        try testing.expect(sim.world.find_node(name) == null);
        try testing.expect(sim.world.find_written(name) == null);
    }
    // Nothing of the host's was created: the sources are as they were.
    try testing.expectEqual(@as(?u32, null), sim.world.find_node("/srv/missing"));
}

test "a secret's bytes are in nothing zbx wrote, and its path is in the record" {
    // Goal: the brief's rule for secrets. Method: a run with a secret whose file holds a marker;
    // the marker is searched in stdout, stderr, every file written (the run record), and in the
    // bundle of the run; the record names the mount, with the path.
    var sim: HostSim = undefined;
    setup(&sim, 2);
    try testing.expectEqual(@as(u8, 0), run(&sim, &all_four));
    const record = record_of(&sim, "m-1").?;
    const line = ".mounts = \"tmpfs:/scratch:8388608 bind:/srv/data:/data " ++
        "bind:/srv/note:/etc/note secret:/srv/key:/run/secrets/key\",";
    try testing.expect(std.mem.indexOf(u8, record, line) != null);
    var parsed: records.Parsed = undefined;
    try records.parse(record, &parsed);
    try testing.expectEqual(@as(u8, 4), parsed.mounts_count);
    try testing.expectEqualStrings("/run/secrets/key", parsed.mount_at(3).target);
    // The bundle of the run, with and without redaction: the tar inside the gzip is searched.
    const plain = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(plain);
    const redacted: []const [:0]const u8 = &.{ "bundle", "m-1" };
    const plain_args: []const [:0]const u8 = &.{ "bundle", "--no-redact", "m-1" };
    for ([_][]const [:0]const u8{ redacted, plain_args }) |args| {
        sim.stdout_len = 0;
        try testing.expectEqual(@as(u8, 0), run(&sim, args));
        const path = std.mem.trimEnd(u8, sim.stdout(), "\n");
        const tar = try gunzip(sim.world.read_written(path).?, plain);
        try testing.expect(tar.len > 1024);
        const shown = std.mem.indexOf(u8, tar, "secret:/srv/key:/run/secrets/key") != null;
        try testing.expectEqual(args.len == 3, shown);
        try testing.expect(std.mem.indexOf(u8, tar, secret_marker) == null);
    }
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), secret_marker) == null);
    for (sim.world.written[0..sim.world.written_count]) |*file| {
        try testing.expect(std.mem.indexOf(u8, file.content[0..file.len], secret_marker) == null);
    }
}

fn gunzip(gz: []const u8, plain: []u8) ![]const u8 {
    const flate = std.compress.flate;
    var input: std.Io.Reader = .fixed(gz);
    var window: [flate.max_window_len]u8 = undefined;
    var decompress: flate.Decompress = .init(&input, .gzip, &window);
    var output = std.Io.Writer.fixed(plain);
    _ = try decompress.reader.streamRemaining(&output);
    return output.buffered();
}

test "the steps of the other mounts: staged before the new root, moved after, by shape" {
    // Goal: the plan's order. Method: the plan of one mount of each shape; the kinds in order,
    // which side of `enter_new_root` each is on, and the count `steps_expected` proves.
    var plan: plan_mod.Plan = undefined;
    const inputs = [_]plan_mod.MountInput{
        .{ .shape = .tmpfs, .source = "", .target = "/scratch", .size_bytes = 4096 },
        .{ .shape = .bind_dir, .source = "/srv/data", .target = "/data", .size_bytes = 0 },
        .{ .shape = .bind_file, .source = "/srv/note", .target = "/etc/note", .size_bytes = 0 },
        .{ .shape = .secret, .source = "/srv/key", .target = "/run/key", .size_bytes = 0 },
    };
    const input: plan_mod.Input = .{
        .rootfs = "/srv/alpine",
        .name = "m-1",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = .single,
        .mounts = &inputs,
    };
    plan.build(&input);
    var order: [32]plan_mod.Kind = undefined;
    var count: usize = 0;
    var pivot: ?usize = null;
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == .enter_new_root) pivot = index;
        if (!plan_mod.is_mount(step.kind)) continue;
        order[count] = step.kind;
        count += 1;
        const after = switch (step.kind) {
            .make_mount_target_dir, .make_mount_target_file, .move_mount => true,
            .remove_mount_stage_dir, .remove_mount_stage_file, .mount_user_tmpfs => true,
            else => false,
        };
        try testing.expectEqual(after, pivot != null);
    }
    const K = plan_mod.Kind;
    const expected = [_]K{
        // Before: the directory, the file, the secret.
        .make_mount_stage_dir,  .bind_mount_dir,          .remount_mount_tree,
        .make_mount_stage_file, .bind_mount_file,         .remount_mount,
        .copy_secret,           .bind_mount_file,         .remount_mount,
        // After: the tmpfs, the directory, the file, the secret.
        .make_mount_target_dir, .mount_user_tmpfs,        .make_mount_target_dir,
        .move_mount,            .remove_mount_stage_dir,  .make_mount_target_file,
        .move_mount,            .remove_mount_stage_file, .make_mount_target_file,
        .move_mount,            .remove_mount_stage_file,
    };
    try testing.expectEqualSlices(K, &expected, order[0..count]);
    try testing.expectEqual(plan.steps_expected(), plan.count);
    // The tmpfs's options are the size, world-writable and sticky.
    var options: [constants.tmpfs_options_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("mode=1777,size=4096", plan_mod.tmpfs_options(&options, 4096));
}

test "every refusal comes before anything is made: the host, the targets and the count" {
    // Goal: a mount that cannot be made starts nothing and creates nothing. Method: a missing
    // bind source (never made), a socket, a directory as a secret, a target over /proc, two
    // mounts on one path, a mount over a state volume's path, and nine mounts.
    const Case = struct { words: []const [:0]const u8, code: []const u8 };
    const cases = [_]Case{
        .{ .words = line_with(&.{ "--bind", "/srv/missing:/d" }), .code = "E0210" },
        .{ .words = line_with(&.{ "--bind", "/srv/socket:/d" }), .code = "E0210" },
        .{ .words = line_with(&.{ "--secret", "/srv/data:/d" }), .code = "E0210" },
        .{ .words = line_with(&.{ "--secret", "/srv/key:/proc/k" }), .code = "E0012" },
        .{ .words = line_with(&.{ "--tmpfs", "/etc/hosts" }), .code = "E0012" },
        .{ .words = line_with(&.{ "--tmpfs", "/t:1k" }), .code = "E0012" },
        .{ .words = line_with(&.{ "--bind", "/srv/data" }), .code = "E0012" },
        .{ .words = line_with(&.{ "--tmpfs", "/t", "--tmpfs", "/t" }), .code = "E0013" },
        .{ .words = line_with(&.{ "--state", "v:/data", "--tmpfs", "/data/x" }), .code = "E0013" },
        .{ .words = line_with(&.{ "--tmpfs", "/data/x", "--state", "v:/data" }), .code = "E0013" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        setup(&sim, 3);
        const before = sim_run.baseline(&sim);
        try testing.expectEqual(@as(u8, 125), run(&sim, case.words));
        var wanted: [16]u8 = undefined;
        const format = "error[ZBX-{s}]";
        const header = std.fmt.bufPrint(&wanted, format, .{case.code}) catch unreachable; // Short.
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), header));
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expect(record_of(&sim, "r-1") == null);
        try testing.expectEqual(@as(?u32, null), sim.world.find_node("/srv/missing"));
        try testing.expect(sim_run.leak(&sim, &before) == null);
    }
    // Nine mounts are one too many.
    var sim: HostSim = undefined;
    setup(&sim, 4);
    var words: [32][:0]const u8 = undefined;
    const targets = [_][:0]const u8{
        "/t0", "/t1", "/t2", "/t3", "/t4", "/t5", "/t6", "/t7", "/t8",
    };
    var count: usize = 0;
    for (head) |word| {
        words[count] = word;
        count += 1;
    }
    for (targets) |target| {
        words[count] = "--tmpfs";
        words[count + 1] = target;
        count += 2;
    }
    words[count] = "--";
    words[count + 1] = "sh";
    try testing.expectEqual(@as(u8, 125), run(&sim, words[0 .. count + 2]));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0013]"));
    // Eight are fine.
    sim_run.start(&sim, 5, &host_files);
    words[count - 2] = "--";
    words[count - 1] = "sh";
    try testing.expectEqual(@as(u8, 0), run(&sim, words[0..count]));
}

test "a mount step the kernel refuses is one coded error and starts nothing" {
    // Goal: E0211 for each kind of step. Method: fail every step of the plan in turn, one run
    // each, by the simulator's step fault; the runs that end in E0211 are the mount steps
    // (twenty: a tmpfs two, the three others six each), and each leaves nothing behind.
    var sim: HostSim = undefined;
    var tried: u32 = 0;
    for (0..constants.plan_steps_max) |index| {
        setup(&sim, 7);
        const before = sim_run.baseline(&sim);
        sim.faults.fail_step = @intCast(index);
        sim.faults.fail_step_errno = 13;
        const code = run(&sim, &all_four);
        if (!std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0211]")) continue;
        try testing.expectEqual(@as(u8, 125), code);
        try testing.expect(sim_run.leak(&sim, &before) == null);
        tried += 1;
    }
    try testing.expectEqual(@as(u32, 20), tried);
}
