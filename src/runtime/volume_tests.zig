//! State volumes in a run, against the simulator (docs/briefs/M6-state.md): the volume made in
//! the container's user namespace by its root, mounted where the container reads its path, the
//! record noted, the lock held for the run's whole life and let go on every way a run ends, a
//! second writer refused naming the holder, readers shared. The VM shows the kernel agrees
//! (postgres's data owned by 999 inside, a row kept across a SIGKILL); these tests show the code
//! does what its plan says on every path.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const host_sim = @import("../host_sim.zig");
const Diag = @import("../diag/diag.zig").Diag;
const lifecycle = @import("lifecycle.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");
const SimFs = @import("../store/fs_sim.zig").SimFs;
const lock = @import("../state/lock.zig");
const record_mod = @import("../state/record.zig");
const volume = @import("../state/volume.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const root = sim_run.state_root;
const pg_lock = root ++ "/pgdata/lock";
const target = "/var/lib/postgresql/data";

var files: SimFs = undefined;
var handle: run.Handle = undefined;

fn setup(sim: *HostSim, seed: u64) void {
    sim_run.init(sim, seed);
    sim_run.prepare_state(sim, &files, &.{ "pgdata", "cfg" });
}

fn run_line(sim: *HostSim, words: []const [:0]const u8) u8 {
    var items: [24][:0]const u8 = undefined;
    items[0] = "zbx";
    for (words, 1..) |word, index| items[index] = word;
    return sim_run.run_cli(sim, items[0 .. words.len + 1]);
}

/// The volume's lock is free: an exclusive try works (and is undone).
fn expect_free(sim: *HostSim, path: [:0]const u8) !void {
    var text: lock.HolderText = undefined;
    lock.holder_text(1, "test", &text);
    const fd = try lock.take(sim.interface(), path, .exclusive, &text, 0);
    lock.release(sim.interface(), fd);
}

fn expect_held(sim: *HostSim, path: [:0]const u8) !void {
    var text: lock.HolderText = undefined;
    lock.holder_text(1, "test", &text);
    try testing.expectError(error.Busy, lock.take(sim.interface(), path, .exclusive, &text, 0));
}

test "a run makes the volume as the container's root, mounts it at its path and notes it" {
    // Goal: the whole success path. Method: a run with one volume; then the model's view of the
    // data directory (made by the child, in its user namespace, as root), the container's
    // mounts (the volume at its path, the stage in /dev gone), the volume's record, the run
    // record, the lock free, nothing left open.
    var sim: HostSim = undefined;
    setup(&sim, 1);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--name", "pg", "--state", "pgdata:" ++ target,
        "--",  "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 0), run_line(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    if (sim_run.leak(&sim, &before)) |problem| {
        std.debug.print("leak: {s}\n", .{problem});
        return error.TestUnexpectedResult;
    }
    const data = sim.world.find_node(root ++ "/pgdata/data").?;
    try testing.expect(sim.world.nodes[data].made_as_namespace_root);
    const child = &sim.world.processes[1];
    const table = &sim.world.tables[child.table];
    try testing.expect(table.has(.bind_tree, sim_run.rootfs_path ++ target));
    try testing.expect(!table.mounts[table.find(sim_run.rootfs_path ++ target).?].read_only);
    try testing.expect(sim.world.find_node(sim_run.rootfs_path ++ "/dev/.zbx-state-0") == null);
    try testing.expect(sim.world.find_node(sim_run.rootfs_path ++ target) != null);
    var record: record_mod.Record = undefined;
    try record_mod.parse(files.content_of(root ++ "/pgdata/state.zon").?, &record);
    try testing.expectEqualStrings("pg", record.container_slice());
    try testing.expectEqualStrings(target, record.target_slice());
    const run_record = sim.world.read_written(sim_run.runs_path ++ "/pg.zon").?;
    try testing.expect(std.mem.indexOf(u8, run_record, ".state = \"pgdata:" ++ target) != null);
    try expect_free(&sim, pg_lock);
}

test "the mount steps follow the plan: data, stage, bind, then in the new root the move" {
    // Goal: the volume is moved into place after the new root is entered, so its path is read
    // as the container reads it. Method: the plan of a run with a read-write and a read-only
    // volume, step by step.
    const plan_mod = @import("plan.zig");
    var plan: plan_mod.Plan = undefined;
    const inputs = [_]plan_mod.StateInput{
        .{ .name = "pgdata", .data = root ++ "/pgdata/data", .target = target, .read_only = false },
        .{ .name = "cfg", .data = root ++ "/cfg/data", .target = "/etc/app", .read_only = true },
    };
    const input: plan_mod.Input = .{
        .rootfs = "/srv/alpine",
        .name = "pg",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = .single,
        .state = &inputs,
    };
    plan.build(&input);
    var order: [16]plan_mod.Kind = undefined;
    var count: usize = 0;
    var pivot: ?usize = null;
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == .enter_new_root) pivot = index;
        if (!plan_mod.is_state(step.kind)) continue;
        order[count] = step.kind;
        count += 1;
        const after = step.kind == .make_state_target or step.kind == .move_state or
            step.kind == .remove_state_stage;
        try testing.expectEqual(after, pivot != null);
    }
    const expected = [_]plan_mod.Kind{
        .make_state_data,    .make_state_stage,   .bind_state,        .make_state_data,
        .make_state_stage,   .bind_state,         .remount_state,     .make_state_target,
        .move_state,         .remove_state_stage, .make_state_target, .move_state,
        .remove_state_stage,
    };
    try testing.expectEqualSlices(plan_mod.Kind, &expected, order[0..count]);
    try testing.expectEqual(plan.steps_expected(), plan.count);
}

test "a second writer is refused naming the holder; readers share; a writer keeps readers out" {
    // Goal: one writer at a time. Method: the lock held as a run would hold it, then each kind
    // of run against it; a refused run starts nothing and leaves nothing open.
    var sim: HostSim = undefined;
    setup(&sim, 2);
    files.put_dir(root, 0o755);
    files.put_dir(root ++ "/pgdata", 0o755);
    var text: lock.HolderText = undefined;
    lock.holder_text(4242, "pg-1", &text);
    const writer = try lock.take(sim.interface(), pg_lock, .exclusive, &text, 0);
    const rw = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--name", "pg-2", "--state", "pgdata:/data",
        "--",  "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &rw));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0706") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "pg-1") != null);
    try testing.expectEqual(@as(u32, 0), sim.world.unreaped_children());
    try testing.expect(sim.world.processes[1].state == .unused);
    const ro = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--name", "pg-3", "--state", "pgdata:/data:ro",
        "--",  "/bin/sh",
    };
    sim.stderr_len = 0;
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &ro));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0706") != null);
    lock.release(sim.interface(), writer);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    // Readers: one holds it shared; another reader runs, a writer is refused.
    const reader = try lock.take(sim.interface(), pg_lock, .shared, &text, 0);
    sim.stderr_len = 0;
    try testing.expectEqual(@as(u8, 0), run_line(&sim, &ro));
    const child = &sim.world.processes[1];
    const table = &sim.world.tables[child.table];
    const mounted = table.find(sim_run.rootfs_path ++ "/data").?;
    try testing.expect(table.mounts[mounted].read_only);
    sim_run.init(&sim, 3);
    sim.store_fs = &files;
    sim.world.add_node(root ++ "/pgdata", .dir);
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &rw));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "mounted read-only by other") != null);
    lock.release(sim.interface(), reader);
    try expect_free(&sim, pg_lock);
}

test "the lock is let go on every way a run ends" {
    // Goal: a clean exit, an exit code, a killed container and a start that fails each free
    // the volume. Method: one run per way, then an exclusive try and no descriptor left.
    const Way = struct { status: @import("../host.zig").ExitStatus, code: u8, missing: bool };
    const ways = [_]Way{
        .{ .status = .{ .exited = 0 }, .code = 0, .missing = false },
        .{ .status = .{ .exited = 3 }, .code = 3, .missing = false },
        .{ .status = .{ .signaled = 9 }, .code = 137, .missing = false },
        // The volume's directory is missing in the container's model: the child's first state
        // step fails (E0713), after the lock was taken.
        .{ .status = .{ .exited = 0 }, .code = 125, .missing = true },
    };
    for (ways) |way| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 4);
        sim_run.prepare_state(&sim, &files, if (way.missing) &.{} else &.{"pgdata"});
        sim.world.command_exit = way.status;
        const args = [_][:0]const u8{
            "run", "--rootfs", sim_run.rootfs_path, "--net", "none", "--state", "pgdata:/data",
            "--",  "/bin/sh",
        };
        try testing.expectEqual(way.code, run_line(&sim, &args));
        if (way.missing) try testing.expect(std.mem.indexOf(u8, sim.stderr(), "E0713") != null);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
        try expect_free(&sim, pg_lock);
    }
}

fn spec(mounts: []const volume.Mount) run.Spec {
    return .{
        .rootfs = sim_run.rootfs_path,
        .name = "pg",
        .command = &.{ "/bin/sh", "-c", "sleep 1000" },
        .state = mounts,
    };
}

const pg_mount = [_]volume.Mount{.{ .name = "pgdata", .target = target, .read_only = false }};

test "the volume is held for the run's whole life, and let go after zbx stop and --timeout" {
    // Goal: the lock from before the container starts until it is reaped, with `stop` from
    // another process and with the run's own time. Method: the library, a long command.
    var sim: HostSim = undefined;
    setup(&sim, 5);
    sim.world.command_runs_ms = 3_600_000;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &spec(&pg_mount), .{ .detached = true }, &handle, &diag);
    try expect_held(&sim, pg_lock);
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "pg", &ref, &state);
    _ = try lifecycle.stop(&ref, 1000, lifecycle.kill_wait_ms);
    try expect_held(&sim, pg_lock); // Until the supervisor has reaped it.
    _ = run.wait(&handle);
    try expect_free(&sim, pg_lock);
    // --timeout.
    setup(&sim, 6);
    sim.world.command_runs_ms = 3_600_000;
    diag.reset();
    try run.start(sim.interface(), &spec(&pg_mount), .{ .timeout_ms = 1000 }, &handle, &diag);
    try expect_held(&sim, pg_lock);
    _ = run.wait(&handle);
    try testing.expect(run.timed_out(&handle));
    try expect_free(&sim, pg_lock);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a killed zbx leaves no lock: the kernel closes its descriptors, the child dies with it" {
    // Goal: SIGKILL of zbx or of a detached run's supervisor. Method: a run holding the volume,
    // then the machine's view of a process that died (every descriptor it had is closed); the
    // container's child was tied to its parent, so it does not outlive the lock.
    var sim: HostSim = undefined;
    setup(&sim, 7);
    sim.world.command_runs_ms = 3_600_000;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &spec(&pg_mount), .{ .detached = true }, &handle, &diag);
    try expect_held(&sim, pg_lock);
    try testing.expect(sim.world.processes[1].die_with_parent);
    files.restart();
    try expect_free(&sim, pg_lock);
    // The lock file is left; it is only a file, and the next run takes it.
    try testing.expect(files.kind_of(pg_lock) != null);
    handle.session.release_keeper();
}

test "a detached run's supervisor holds the volume and lets go when the container ends" {
    // Goal: `run -d`: the supervisor (not the caller) starts and waits, so it is the holder.
    // Method: the supervisor's half of the command line, then the lock and the descriptors.
    var sim: HostSim = undefined;
    setup(&sim, 8);
    sim.world.fork_role = .supervisor;
    sim.world.command_runs_ms = 5000;
    const args = [_][:0]const u8{
        "run",          "-d", "--rootfs", sim_run.rootfs_path, "--name", "pg", "--state",
        "pgdata:/data", "--", "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 0), run_line(&sim, &args));
    try testing.expectEqual(@as(?u8, 0), sim.world.exited_with);
    try expect_free(&sim, pg_lock);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a bad --state is refused before anything is made" {
    // Goal: the command line's checks, each with its code. Method: one value per rule; the
    // state directory stays empty.
    const Case = struct { value: [:0]const u8, code: codes.Code };
    const cases = [_]Case{
        .{ .value = "Pg:/data", .code = .E0705 },
        .{ .value = ".x:/data", .code = .E0705 },
        .{ .value = "pgdata", .code = .E0005 },
        .{ .value = "pgdata:data", .code = .E0005 },
        .{ .value = "pgdata:/proc/x", .code = .E0005 },
        .{ .value = "pgdata:/a/../b", .code = .E0005 },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        setup(&sim, 9);
        const args = [_][:0]const u8{
            "run", "--rootfs", sim_run.rootfs_path, "--state", case.value, "--", "/bin/sh",
        };
        try testing.expectEqual(@as(u8, 125), run_line(&sim, &args));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), codes.full_name(case.code)) != null);
        try testing.expect(files.kind_of(root) == null);
    }
    var sim: HostSim = undefined;
    setup(&sim, 10);
    const twice = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--state", "a:/x", "--state", "a:/y", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &twice));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "already mounted") != null);
    sim.stderr_len = 0;
    const nested = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--state", "a:/x", "--state", "b:/x/y", "--",
        "sh",
    };
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &nested));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0005") != null);
}

test "a volume record from a newer zbx is refused, and the lock is let go" {
    // Goal: E0712, never a misread record. Method: a record with version 9.
    var sim: HostSim = undefined;
    setup(&sim, 11);
    files.put_dir(root, 0o755);
    files.put_dir(root ++ "/pgdata", 0o755);
    files.put_file(root ++ "/pgdata/state.zon", 0o644, ".{\n    .version = 9,\n}\n");
    const args = [_][:0]const u8{
        "run", "--rootfs", sim_run.rootfs_path, "--state", "pgdata:/data", "--", "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 125), run_line(&sim, &args));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0712") != null);
    try expect_free(&sim, pg_lock);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    _ = records;
}
