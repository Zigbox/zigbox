//! Container logs end to end against the simulator (docs/briefs/M6b-dev-loop.md, "zbx logs"): a
//! foreground run's output on the terminal and in its log, a detached run's supervisor writing
//! it, the cap, a log that cannot be written, removal with the run record (prune and a name
//! used again), and `zbx logs` in text, with `--stream` and `--tail`, and in JSON. The VM shows
//! the same with a real server; these show the code does what its rules say on every path.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const host_sim = @import("../host_sim.zig");
const logfile = @import("logfile.zig");
const records = @import("records.zig");
const sim_run = @import("sim_run.zig");
const sim_world = @import("../sim_world.zig");
const run = @import("run.zig");
const zigbox = @import("../zigbox.zig");
const Diag = @import("../diag/diag.zig").Diag;
const SimFs = @import("../store/fs_sim.zig").SimFs;

const HostSim = host_sim.HostSim;
const testing = std.testing;

var disk: SimFs = undefined;

fn setup(sim: *HostSim, seed: u64) void {
    sim_run.init(sim, seed);
    disk.init(seed);
    disk.put_dir("/home", 0o755);
    disk.put_dir("/home/alice", 0o755);
    sim.log_fs = &disk;
}

const chunks = [_]sim_world.OutChunk{
    .{ .stream = .stdout, .bytes = "first line\nsecond " },
    .{ .stream = .stderr, .bytes = "warning: one\n" },
    .{ .stream = .stdout, .bytes = "line\nthird line\n" },
    .{ .stream = .stderr, .bytes = "warning: two\nwarning: three\n" },
};

const run_args = [_][:0]const u8{
    "zbx", "run", "--name", "web", "--rootfs", sim_run.rootfs_path, "--", "/bin/sh",
};

fn logs(sim: *HostSim, extra: []const [:0]const u8) u8 {
    var args: [8][:0]const u8 = undefined;
    args[0] = "zbx";
    args[1] = "logs";
    args[2] = "web";
    for (extra, 0..) |word, at| args[3 + at] = word;
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(sim, args[0 .. 3 + extra.len]);
}

test "a foreground run shows its output as it always did, and keeps it in its log" {
    // Goal: the terminal gets the bytes in order, unchanged, and `zbx logs` shows the same bytes.
    var sim: HostSim = undefined;
    setup(&sim, 1);
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    const expected = "first line\nsecond warning: one\nline\nthird line\n" ++
        "warning: two\nwarning: three\n";
    try testing.expectEqualStrings("first line\nsecond line\nthird line\n", sim.stdout());
    try testing.expectEqualStrings("warning: one\nwarning: two\nwarning: three\n", sim.stderr());
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{}));
    try testing.expectEqualStrings(expected, sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    try testing.expectEqual(@as(u32, 0), disk.open_count());
}

test "--stream shows one stream, --tail the last lines, and both together" {
    var sim: HostSim = undefined;
    setup(&sim, 2);
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--stream", "stderr" }));
    try testing.expectEqualStrings(
        "warning: one\nwarning: two\nwarning: three\n",
        sim.stdout(),
    );
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--tail", "2" }));
    try testing.expectEqualStrings("warning: two\nwarning: three\n", sim.stdout());
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--tail", "0" }));
    try testing.expectEqualStrings("", sim.stdout());
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--tail", "100" }));
    try testing.expectEqual(@as(usize, 6), std.mem.count(u8, sim.stdout(), "\n"));
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--tail", "1", "--stream", "stdout" }));
    try testing.expectEqualStrings("third line\n", sim.stdout());
}

test "--output json is one zbx.logs/1 object per record" {
    var sim: HostSim = undefined;
    setup(&sim, 3);
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--output", "json" }));
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, sim.stdout(), "\n"), '\n');
    var count: u32 = 0;
    while (lines.next()) |line| : (count += 1) {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        const object = parsed.value.object;
        try testing.expectEqualStrings("zbx.logs/1", object.get("schema").?.string);
        const stream = object.get("stream").?.string;
        try testing.expect(std.mem.eql(u8, stream, "stdout") or std.mem.eql(u8, stream, "stderr"));
        try testing.expect(object.get("time").?.integer > 0);
        try testing.expect(object.get("dropped_bytes") == null);
        if (count == 1) {
            try testing.expectEqualStrings("warning: one\n", object.get("text").?.string);
        }
    }
    try testing.expectEqual(@as(u32, 4), count);
}

test "a detached run's supervisor writes the log and the terminal gets nothing" {
    var sim: HostSim = undefined;
    setup(&sim, 4);
    sim.world.fork_role = .supervisor;
    sim.world.out_script = &chunks;
    const detached = [_][:0]const u8{
        "zbx", "run", "-d", "--name", "web", "--rootfs", sim_run.rootfs_path, "--", "/bin/sh",
    };
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &detached));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    sim.world.fork_role = .parent;
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--stream", "stdout" }));
    try testing.expectEqualStrings("first line\nsecond line\nthird line\n", sim.stdout());
}

test "--follow on a container that has ended shows its log and exits 0" {
    var sim: HostSim = undefined;
    setup(&sim, 5);
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{"--follow"}));
    try testing.expectEqual(@as(usize, 6), std.mem.count(u8, sim.stdout(), "\n"));
}

test "a container with a record and no log, and one that does not exist, are coded errors" {
    var sim: HostSim = undefined;
    setup(&sim, 6);
    try testing.expectEqual(@as(u8, 1), logs(&sim, &.{}));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0402") != null);
    const view = sim_run.sample_view("web", 1000);
    sim_run.put_record(&sim, &view);
    try testing.expectEqual(@as(u8, 1), logs(&sim, &.{}));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0217") != null);
    try testing.expectEqual(@as(u8, 1), logs(&sim, &.{ "--tail", "many" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0219") != null);
    try testing.expectEqual(@as(u8, 1), logs(&sim, &.{ "--stream", "both" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0219") != null);
}

test "a log that cannot be made is one warning, and the run goes on" {
    // Goal: "If the log cannot be written, the run still runs, and says so once."
    var sim: HostSim = undefined;
    setup(&sim, 7);
    disk.crashed = true; // A disk that fails every call.
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0204"));
}

test "a log that fails while the container runs is one warning, and the terminal is unharmed" {
    var sim: HostSim = undefined;
    setup(&sim, 8);
    sim.world.out_script = &chunks;
    // The disk takes the header and the first write, then is full.
    disk.faults.bytes_max = 16 + 12 + 18 + 5;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0204"));
    try testing.expectEqualStrings("first line\nsecond line\nthird line\n", sim.stdout());
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "warning: three\n") != null);
}

test "a log over the cap starts at a whole record and says how much was dropped" {
    // Goal: the reader's side of the cap, through the command. Method: write records through the
    // writer with a small segment on the simulated disk, then read them with `zbx logs`.
    var sim: HostSim = undefined;
    setup(&sim, 9);
    const view = sim_run.sample_view("web", 1000);
    sim_run.put_record(&sim, &view);
    var runs: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &runs));
    const dir = logfile.dir_of(&runs).?;
    var writer: logfile.Writer = undefined;
    const options: logfile.WriterOptions = .{
        .segment_bytes_max = 16 + 4 * (12 + 8) + 4,
        .record_bytes_max = 8,
    };
    try writer.open(disk.interface(), &dir, "web", options);
    var at: u32 = 0;
    while (at < 30) : (at += 1) {
        var text: [8]u8 = undefined;
        // Cannot fail: "rec", four digits and a newline are the eight bytes of the buffer.
        _ = std.fmt.bufPrint(&text, "rec{d:0>4}\n", .{at}) catch unreachable;
        try writer.append(.stdout, 5000 + at, text[0..8]);
    }
    writer.close();
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--output", "json" }));
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, sim.stdout(), "\n"), '\n');
    const first = lines.next().?;
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, first, .{});
    defer parsed.deinit();
    const dropped = parsed.value.object.get("dropped_bytes").?.integer;
    try testing.expect(dropped > 0);
    try testing.expectEqual(@as(i64, 0), @mod(dropped, 8));
    const text = parsed.value.object.get("text").?.string;
    try testing.expect(std.mem.startsWith(u8, text, "rec"));
    var seen: u32 = 1;
    while (lines.next()) |_| seen += 1;
    try testing.expect(seen < 30);
    // In text mode the same fact is one warning, and the bytes are whole records.
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{}));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0205"));
    try testing.expect(std.mem.endsWith(u8, sim.stdout(), "rec0029\n"));
}

fn old_run(sim: *HostSim, name: []const u8, started: u64) !void {
    const view = sim_run.sample_view(name, started);
    sim_run.put_record(sim, &view);
    var runs: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &runs));
    const dir = logfile.dir_of(&runs).?;
    var writer: logfile.Writer = undefined;
    try writer.open(disk.interface(), &dir, name, .{});
    try writer.append(.stdout, started, "old output\n");
    writer.close();
}

test "a run's log is removed when its record is pruned, and a name used again starts empty" {
    // Goal: removal with the run record. Method: as many finished runs as records are kept, each
    // with a log; one more run makes the oldest record go, and its log with it, while the
    // others stay. The new run has the name of a finished one: the old output is gone.
    var sim: HostSim = undefined;
    setup(&sim, 10);
    sim.world.out_script = &chunks;
    var name_storage: [constants.runs_max][16]u8 = undefined;
    var at: u32 = 0;
    while (at < constants.runs_max) : (at += 1) {
        const name = try std.fmt.bufPrint(&name_storage[at], "r-{d:0>2}", .{at});
        try old_run(&sim, name, 1000 + at);
    }
    try old_run(&sim, "web", 5000);
    // 34 records, 32 kept: the run below replaces "web", so the two oldest go.
    try old_run(&sim, "r-99", 6000);
    const logs_dir = sim_run.logs_path;
    try testing.expect(disk.kind_of(logs_dir ++ "/r-00.log") != null);
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expect(disk.kind_of(logs_dir ++ "/r-00.log") == null);
    try testing.expect(disk.kind_of(logs_dir ++ "/r-01.log") == null);
    try testing.expect(disk.kind_of(logs_dir ++ "/r-02.log") != null);
    try testing.expect(disk.kind_of(logs_dir ++ "/r-99.log") != null);
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--stream", "stderr" }));
    try testing.expectEqualStrings("warning: one\nwarning: two\nwarning: three\n", sim.stdout());
}

var library_handle: run.Handle = undefined;

test "a library caller reads the log of a run it started, with its own storage" {
    // Goal: Zigcube's agent path. Method: `start` and `wait` as the agent does, no terminal copy
    // (the default), then `open_log` and a reader of the caller's own: every byte the container
    // wrote, in order, nothing on the host's terminal.
    var sim: HostSim = undefined;
    setup(&sim, 12);
    sim.world.out_script = &chunks;
    var diag: Diag = undefined;
    diag.reset();
    const spec: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "agent-1",
        .command = &.{"/bin/sh"},
    };
    try run.start(sim.interface(), &spec, .{}, &library_handle, &diag);
    _ = run.wait(&library_handle);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    var reader: zigbox.LogReader = undefined;
    try zigbox.open_log(&reader, sim.interface(), "agent-1");
    defer reader.close();
    var total: usize = 0;
    var seen: u32 = 0;
    while (true) {
        switch (reader.next()) {
            .record => |found| {
                total += found.payload.len;
                seen += 1;
            },
            else => break,
        }
    }
    try testing.expectEqual(@as(u32, 4), seen);
    try testing.expectEqual(@as(usize, 18 + 13 + 16 + 28), total);
    try testing.expectEqual(@as(u64, 0), reader.dropped_bytes);
    try testing.expectError(error.NoLog, zigbox.open_log(&reader, sim.interface(), "nobody"));
}

test "a library caller that keeps no log leaves the container's output where it was" {
    var sim: HostSim = undefined;
    setup(&sim, 13);
    sim.world.out_script = &chunks;
    var diag: Diag = undefined;
    diag.reset();
    const spec: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "agent-2",
        .command = &.{"/bin/sh"},
    };
    try run.start(sim.interface(), &spec, .{ .keep_log = false }, &library_handle, &diag);
    _ = run.wait(&library_handle);
    var reader: zigbox.LogReader = undefined;
    try testing.expectError(error.NoLog, zigbox.open_log(&reader, sim.interface(), "agent-2"));
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a log larger than one write of the host is shown whole" {
    // Goal: a regression the VM found (the output buffer was written in one call over the host's
    // bound of 16 KiB). Method: twelve records of 4000 bytes, shown in text and as the last line.
    var sim: HostSim = undefined;
    setup(&sim, 14);
    try old_run(&sim, "web", 1000);
    var runs: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &runs));
    const dir = logfile.dir_of(&runs).?;
    var writer: logfile.Writer = undefined;
    try writer.open(disk.interface(), &dir, "web", .{});
    var big: [4000]u8 = undefined;
    for (0..12) |at| {
        @memset(&big, 'a' + @as(u8, @intCast(at)));
        big[3999] = '\n';
        try writer.append(.stdout, 1000, &big);
    }
    writer.close();
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{}));
    try testing.expectEqual(@as(usize, 48_000), sim.stdout().len);
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{ "--tail", "1" }));
    try testing.expectEqual(@as(usize, 4000), sim.stdout().len);
    try testing.expectEqual(@as(u8, 'l'), sim.stdout()[0]);
}

test "a tty on stdout means no pipe on stdout; a tty on both leaves the log with a notice" {
    // Goal: a foreground run at a terminal keeps its terminal. Method: the host says stdout is a
    // terminal: the session makes a pipe for stderr only; then both are: no pipe at all, the
    // container's output is not in the log, and `zbx logs` says why instead of showing nothing.
    var sim: HostSim = undefined;
    setup(&sim, 15);
    sim.terminal = true;
    sim.terminal_only = .stdout;
    var diag: Diag = undefined;
    diag.reset();
    const spec: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "tty-1",
        .command = &.{"/bin/sh"},
    };
    try run.start(sim.interface(), &spec, .{ .mirror = true }, &library_handle, &diag);
    try testing.expect(library_handle.session.output_read[0] == null);
    try testing.expect(library_handle.session.output_read[1] != null);
    _ = run.wait(&library_handle);
    try testing.expectEqual(@as(u32, 0), sim.open_count());

    setup(&sim, 16);
    sim.terminal = true;
    sim.world.out_script = &chunks;
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &run_args));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len); // The container had the terminal.
    try testing.expectEqual(@as(u8, 0), logs(&sim, &.{}));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0206"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "standard output and error") != null);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}
