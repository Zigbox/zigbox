//! Tests of a container run against the simulator, from the command line down: the exit code,
//! the state of the model afterwards, the diagnostics, and a failure injected into every step of
//! the plan. The VM demo is what shows that the real kernel agrees (docs/briefs/M1-shell.md);
//! these tests show that the code does what its plan says and cleans up after itself.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const plan_mod = @import("plan.zig");
const repeat = @import("../test_util.zig").repeat;
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const container_path = constants.container_path;

fn run(sim: *HostSim, args: []const [:0]const u8) u8 {
    return sim_run.run_cli(sim, args);
}

fn started_ok(sim: *const HostSim, name: []const u8) !void {
    const problem = sim_run.started(sim, .{ .name = name, .devpts = true });
    if (problem) |text| {
        std.debug.print("the container is wrong: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

fn no_leak(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

test "a run gives the command the container the plan promises, and leaves the host alone" {
    // Goal: the whole success path. Method: run a shell with a name and TERM set; the command
    // ends 42. The model must show the child in its own namespaces with the container's mounts
    // and no host mount, a clean environment and the exact argv, and zbx ends with 42 and says
    // nothing on stderr. The host's mounts, hostname, processes and descriptors are unchanged.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    const before = sim_run.baseline(&sim);
    sim.world.command_exit = .{ .exited = 42 };
    sim.environment_variables = &sim_run.env_home_term;
    const args = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "/bin/sh", "-c", "exit 42",
    };
    try testing.expectEqual(@as(u8, 42), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try no_leak(&sim, &before);
    try started_ok(&sim, "web-1");

    const child = &sim.world.processes[1];
    try testing.expectEqualStrings("/bin/sh\n-c\nexit 42\n", child.argv());
    try testing.expectEqualStrings(
        "PATH=" ++ constants.container_path ++ "\nHOME=/root\nHOSTNAME=web-1\n" ++
            "TERM=xterm-256color\n",
        child.envp(),
    );
    try testing.expect(child.exec_path.eql(rootfs ++ "/bin/sh"));
    try testing.expectEqualStrings("simhost", sim.world.hostnames[0].slice());
}

test "the environment has no TERM unless the host has one, and nothing else of the host's" {
    // Goal: the clean environment. Method: the host has secrets and a TERM that is too long to
    // copy; the command gets only PATH, HOME and HOSTNAME.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 2);
    const long_term = repeat('x', constants.term_bytes_max + 1);
    sim.environment_variables = &.{
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = "hunter2" },
        .{ .name = "TERM", .value = long_term },
        .{ .name = "HOME", .value = "/home/alice" },
    };
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "a", "--", "sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    const envp = sim.world.processes[1].envp();
    try testing.expectEqualStrings(
        "PATH=" ++ constants.container_path ++ "\nHOME=/root\nHOSTNAME=a\n",
        envp,
    );
    try testing.expect(std.mem.indexOf(u8, envp, "hunter2") == null);
    try testing.expect(sim.world.processes[1].exec_path.eql(rootfs ++ "/bin/sh"));
}

test "a command that exits n ends zbx with n; one killed by signal s ends it with 128 plus s" {
    // Goal: exit-code propagation at both ends of the range, with the note naming the signal on
    // stderr in text mode and the container_exit line in JSON mode, and nothing else.
    const Case = struct { status: host_mod.ExitStatus, code: u8 };
    const cases = [_]Case{
        .{ .status = .{ .exited = 0 }, .code = 0 },
        .{ .status = .{ .exited = 1 }, .code = 1 },
        .{ .status = .{ .exited = 2 }, .code = 2 },
        .{ .status = .{ .exited = 70 }, .code = 70 },
        .{ .status = .{ .exited = 255 }, .code = 255 },
        .{ .status = .{ .signaled = 2 }, .code = 130 },
        .{ .status = .{ .signaled = 9 }, .code = 137 },
        .{ .status = .{ .signaled = 15 }, .code = 143 },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 3);
        sim.world.command_exit = case.status;
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "/bin/sh" };
        try testing.expectEqual(case.code, run(&sim, &args));
        switch (case.status) {
            .exited => try testing.expectEqual(@as(usize, 0), sim.stderr().len),
            .signaled => |number| {
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "\n"));
                var expected: [80]u8 = undefined;
                const name = std.enums.tagName(std.os.linux.SIG, @fromBackingInt(number)).?;
                const note = try std.fmt.bufPrint(&expected, "zbx: the container was killed by " ++
                    "signal {d} (SIG{s})\n", .{ number, name });
                try testing.expectEqualStrings(note, sim.stderr());
            },
        }

        sim_run.init(&sim, 3);
        sim.world.command_exit = case.status;
        const json = [_][:0]const u8{
            "zbx", "--output", "json", "run", "--rootfs", rootfs, "--", "/bin/sh",
        };
        try testing.expectEqual(case.code, run(&sim, &json));
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "\n"));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"container_exit\":{"));
        var number_text: [16]u8 = undefined;
        const code_text = try std.fmt.bufPrint(&number_text, "\"code\":{d}}}}}\n", .{case.code});
        try testing.expect(std.mem.endsWith(u8, sim.stderr(), code_text));
    }
}

test "a generated name is zbx- and six hex digits, and is the container's hostname" {
    // Goal: the default name. Method: several seeds; each name is valid, has the shape, and
    // the child's hostname is that name; two seeds give two names.
    var names: [4][constants.container_name_bytes_max]u8 = undefined;
    var lengths: [4]usize = undefined;
    for (&names, &lengths, 0..) |*storage, *length, seed| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 100 + seed);
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "/bin/sh" };
        try testing.expectEqual(@as(u8, 0), run(&sim, &args));
        const hostname = sim.world.hostnames[sim.world.processes[1].uts].slice();
        try testing.expect(std.mem.startsWith(u8, hostname, constants.container_name_prefix));
        try testing.expectEqual(@as(usize, 10), hostname.len);
        for (hostname[4..]) |digit| {
            try testing.expect(std.ascii.isDigit(digit) or (digit >= 'a' and digit <= 'f'));
        }
        @memcpy(storage[0..hostname.len], hostname);
        length.* = hostname.len;
    }
    try testing.expect(!std.mem.eql(u8, names[0][0..lengths[0]], names[1][0..lengths[1]]));
}

test "bad input is refused before anything is created" {
    // Goal: a user error costs nothing: no process, no pipe, no mount. Each case has its code
    // and exit 125 (zbx's own failure, never 1), and the simulator's world is untouched.
    const long_rootfs = "/" ++ repeat('r', constants.rootfs_bytes_max);
    const Case = struct { args: []const [:0]const u8, code: codes.Code };
    const cases = [_]Case{
        .{
            .args = &.{ "zbx", "run", "--rootfs", rootfs, "--name", "Web", "--", "sh" },
            .code = .E0206,
        },
        .{
            .args = &.{ "zbx", "run", "--rootfs", rootfs, "--name=", "--", "sh" },
            .code = .E0206,
        },
        .{
            .args = &.{ "zbx", "run", "--rootfs", rootfs, "--name", "-a", "--", "sh" },
            .code = .E0206,
        },
        .{ .args = &.{ "zbx", "run", "--rootfs", "/srv/nope", "--", "sh" }, .code = .E0201 },
        .{ .args = &.{ "zbx", "run", "--rootfs", "/srv/file", "--", "sh" }, .code = .E0201 },
        .{ .args = &.{ "zbx", "run", "--rootfs=", "--", "sh" }, .code = .E0201 },
        .{ .args = &.{ "zbx", "run", "--rootfs", long_rootfs, "--", "sh" }, .code = .E0201 },
        .{ .args = &.{ "zbx", "run", "--rootfs", rootfs, "--", "" }, .code = .E0006 },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 4);
        const before = sim_run.baseline(&sim);
        try testing.expectEqual(@as(u8, 125), run(&sim, case.args));
        var header: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&header, "error[{s}]: ", .{codes.full_name(case.code)});
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), text));
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error["));
        try testing.expect(sim.world.processes[1].state == .unused);
        try no_leak(&sim, &before);
    }
}

test "a command that cannot be run is E0202 and names what was looked up" {
    // Goal: the three ways exec fails for a user: no such file (by path and by PATH), a file that
    // is not a program, and a missing loader being the same as a missing file.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 5);
    sim.world.add_node(rootfs ++ "/bin/directory", .dir);
    const Case = struct { command: [:0]const u8, words: []const []const u8, exit: u8 };
    // A command that is not there exits 127, one that is there and cannot run exits 126.
    const cases = [_]Case{
        .{
            .command = "/bin/nothere",
            .exit = 127,
            .words = &.{ "'/bin/nothere' is missing from the rootfs", "also needs its loader" },
        },
        .{
            .command = "nothere",
            .exit = 127,
            .words = &.{ "no file named 'nothere' in the container's PATH", container_path },
        },
        .{
            .command = "/bin/directory",
            .exit = 126,
            .words = &.{"is not a program this machine can run"},
        },
    };
    for (cases) |case| {
        sim_run.init(&sim, 5);
        sim.world.add_node(rootfs ++ "/bin/directory", .dir);
        const before = sim_run.baseline(&sim);
        const args = [_][:0]const u8{ "zbx", "-v", "run", "--rootfs", rootfs, "--", case.command };
        try testing.expectEqual(case.exit, run(&sim, &args));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0202]: "));
        for (case.words) |word| try testing.expect(std.mem.indexOf(u8, sim.stderr(), word) != null);
        try no_leak(&sim, &before);
        // The container was set up and torn down: the child ended with the setup-failure code.
        const child = &sim.world.processes[1];
        const failed: host_mod.ExitStatus = .{ .exited = constants.child_exit_setup_failed };
        try testing.expectEqual(failed, child.exit.?);
    }
}

test "when /dev/pts is refused the run goes on, the step is skipped and noted" {
    // Goal: the tolerant step. Method: the model refuses devpts. The command still starts, the
    // container has no /dev/pts mount, and --verbose says what was skipped.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 6);
    sim.world.devpts_refused = true;
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{ "zbx", "-v", "run", "--rootfs", rootfs, "--", "/bin/sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    const note = "zbx: note: skipped mounting devpts on /dev/pts: refused by the kernel (EPERM)\n";
    try testing.expectEqualStrings(note, sim.stderr());
    try no_leak(&sim, &before);
    try testing.expect(sim_run.started(&sim, .{ .name = "x", .devpts = false }) != null); // Name.
    const child = &sim.world.processes[1];
    const hostname = sim.world.hostnames[child.uts].slice();
    try testing.expect(sim_run.started(&sim, .{ .name = hostname, .devpts = false }) == null);

    // Without --verbose the note is not printed.
    sim_run.init(&sim, 6);
    sim.world.devpts_refused = true;
    const quiet = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "/bin/sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &quiet));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

fn expected_code(kind: plan_mod.Kind) ?codes.Code {
    return switch (kind) {
        .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => .E0203,
        .run_newuidmap, .run_newgidmap => .E0204,
        .exec => .E0202,
        .mount_pts => null,
        else => .E0205,
    };
}

test "a failure injected into every step is a diagnostic naming that step, and cleans up" {
    // Goal: the property the run fuzzer checks at scale, walked once over the whole plan. For
    // each step in turn the first call of that step fails with EPERM. The result is the code
    // for the step (E0203 for the namespaces and their maps, E0202 for the command, E0205 for
    // the rest; the devpts mount alone is skipped), the verbose output names the step, the exit
    // code is 125 (126 for the command), and nothing leaked: the child is reaped, no descriptor
    // is open and the host's mounts and hostname are as they were.
    var plan: plan_mod.Plan = undefined;
    sim_run.sample_plan(&plan, true);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 7);
        const before = sim_run.baseline(&sim);
        sim.faults.fail_step = @intCast(index);
        sim.faults.fail_step_errno = 1;
        const args = [_][:0]const u8{
            "zbx", "-v", "run", "--rootfs", rootfs, "--name", "walk", "--", "/bin/sh",
        };
        const code = run(&sim, &args);
        try testing.expect(sim.step_fault_fired); // The step really made a fallible call.
        try no_leak(&sim, &before);
        if (expected_code(step.kind)) |expected| {
            var header: [32]u8 = undefined;
            const full = codes.full_name(expected);
            const text = try std.fmt.bufPrint(&header, "error[{s}]: ", .{full});
            try testing.expect(std.mem.startsWith(u8, sim.stderr(), text));
            var line: [80]u8 = undefined;
            const context = try std.fmt.bufPrint(&line, "  step   {s} ({d} of {d})\n", .{
                @tagName(step.kind), index + 1, plan.count,
            });
            try testing.expect(std.mem.indexOf(u8, sim.stderr(), context) != null);
            // 125 for zbx's own failure; a command that cannot run (EPERM, not missing) is 126.
            try testing.expectEqual(@as(u8, if (expected == .E0202) 126 else 125), code);
            try testing.expect(sim.world.processes[1].state != .running);
        } else {
            try testing.expectEqual(@as(u8, 0), code);
            try testing.expect(std.mem.indexOf(u8, sim.stderr(), "skipped") != null);
        }
    }
}

test "interrupted reads, writes and waits are retried and the run succeeds" {
    // Goal: EINTR is not a failure. Method: a third of the pipe reads, pipe writes and waits are
    // interrupted, over many seeds; the run still ends with the command's code and no leak.
    for (0..60) |seed| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, seed);
        const before = sim_run.baseline(&sim);
        sim.faults.interrupt_per_mille = 300;
        sim.world.command_exit = .{ .exited = 7 };
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "i", "--", "sh" };
        try testing.expectEqual(@as(u8, 7), run(&sim, &args));
        try no_leak(&sim, &before);
        try testing.expect(sim.interrupts_injected > 0 or seed > 0);
    }
}

test "when the parent gives up before the go-ahead the child never runs a step" {
    // Goal: the sync protocol. A failed id-map write ends the run; the child, blocked waiting
    // for the go-ahead, is killed and reaped without having mounted anything.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 8);
    const before = sim_run.baseline(&sim);
    sim.faults.fail_step = sim_run.step_index(.run_newgidmap, true);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "x", "--", "sh" };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    const child = &sim.world.processes[1];
    try testing.expect(child.state == .reaped);
    try testing.expect(!child.execd);
    try testing.expectEqual(@as(u32, 3), sim.world.tables[1].count); // Copied, never changed.
    const killed: host_mod.ExitStatus = .{ .signaled = constants.signal_kill };
    try testing.expectEqual(killed, child.exit.?);
    try no_leak(&sim, &before);
}

test "the fix fits the failure: process limits, the rootfs's owner, or the host's policy" {
    // Goal: a fix that does not apply is worse than none. Method: three failures with three
    // different fixes: a refused clone (EAGAIN) names the process limit; a rootfs that cannot
    // get its /proc directory names the directory and not the kernel log; a refused /proc
    // mount names the kernel log.
    const Case = struct {
        kind: plan_mod.Kind,
        errno: u16,
        present: []const u8,
        absent: []const u8,
    };
    const cases = [_]Case{
        .{ .kind = .spawn, .errno = 11, .present = "ulimit -u", .absent = "dmesg" },
        .{ .kind = .make_proc_dir, .errno = 13, .present = "mkdir -p", .absent = "dmesg" },
        .{ .kind = .mount_proc, .errno = 1, .present = "dmesg", .absent = "mkdir" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 9);
        sim.faults.fail_step = sim_run.step_index(case.kind, true);
        sim.faults.fail_step_errno = case.errno;
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "sh" };
        const code = run(&sim, &args);
        try testing.expect(code != 0);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.present) != null);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.absent) == null);
    }
}

fn expect_starts_with(text: []const u8, prefix: []const u8) !void {
    if (!std.mem.startsWith(u8, text, prefix)) {
        std.debug.print(
            "expected the text to start with:\n{s}\nbut it is:\n{s}\n",
            .{ prefix, text },
        );
        return error.TestUnexpectedResult;
    }
}

test "a host without ranges or helpers gets the single-id map after one warning" {
    // Goal: the fallback. The warning comes first on stderr (before the container's output), is
    // W0201 with the doctor's fix, the run goes on with the setgroups-denied direct maps, and in
    // JSON mode the warning is one JSON line.
    var sim: HostSim = undefined;
    sim_run.init_single(&sim, 10);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "solo", "--", "sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try expect_starts_with(
        sim.stderr(),
        "warning[ZBX-W0201]: mapping only your own id into the container\n",
    );
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "fix ") != null);
    try no_leak(&sim, &before);
    const problem = sim_run.started(&sim, .{ .name = "solo", .devpts = true, .full = false });
    try testing.expect(problem == null);
    try testing.expectEqual(@as(u32, 0), sim.world.helper_runs);

    sim_run.init_single(&sim, 10);
    const json = [_][:0]const u8{
        "zbx",
        "--output",
        "json",
        "run",
        "--rootfs",
        rootfs,
        "--",
        "sh",
    };
    try testing.expectEqual(@as(u8, 0), run(&sim, &json));
    try expect_starts_with(sim.stderr(), "{\"code\":\"ZBX-W0201\",\"severity\":\"warning\"");
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, sim.stderr(), "\n"));
}

test "a host with ranges and helpers maps the full range through them, once each" {
    // Goal: the default. Both helpers run once, setgroups is left alone, nothing is said.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 11);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "full", "--", "sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u32, 2), sim.world.helper_runs);
    const problem = sim_run.started(&sim, .{ .name = "full", .devpts = true, .full = true });
    try testing.expect(problem == null);
}

test "a helper that refuses or cannot run is E0204, naming it and how it ended" {
    // Goal: the helper path's failures. A refusal prints the helper's own words; a helper that
    // cannot be run says so; a range that does not cover the request is refused by the helper
    // (the model checks the numbers, as the real one does); the child is reaped each time.
    const Case = struct { exit: ?u8, start: u32, words: []const u8 };
    const cases = [_]Case{
        .{
            .exit = 1,
            .start = 100000,
            .words = "newuidmap exited with status 1: newuidmap: write to uid_map failed",
        },
        .{
            .exit = 127,
            .start = 100000,
            .words = "newuidmap could not be run (/usr/bin/newuidmap)",
        },
        .{ .exit = null, .start = 300000, .words = "newuidmap exited with status 1" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 12);
        const before = sim_run.baseline(&sim);
        sim.world.helper_fails_with = case.exit;
        sim.world.subid_start = case.start;
        const args = [_][:0]const u8{ "zbx", "-v", "run", "--rootfs", rootfs, "--", "sh" };
        try testing.expectEqual(@as(u8, 125), run(&sim, &args));
        try expect_starts_with(sim.stderr(), "error[ZBX-E0204]: writing the id maps failed\n");
        if (std.mem.indexOf(u8, sim.stderr(), case.words) == null) {
            std.debug.print("missing {s} in:\n{s}\n", .{ case.words, sim.stderr() });
            return error.TestUnexpectedResult;
        }
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "helper /usr/bin/newuidmap") != null);
        try no_leak(&sim, &before);
        try testing.expect(!sim.world.processes[1].execd);
    }
}

fn expect_signals(sim: *const HostSim, expected: []const u8) !void {
    try testing.expectEqualSlices(u8, expected, sim.world.received[0..sim.world.received_count]);
}

test "a signal PID 1 has no handler for ends the container as the signal would have" {
    // Goal: the SigCgt rule in the simulator. A plain `sleep` (no handlers) given SIGINT, SIGTERM,
    // SIGHUP or SIGQUIT is sent SIGKILL instead, and zbx ends with 128 plus the signal that was
    // asked for, with the note naming it, not 137.
    const Case = struct { number: u8, name: []const u8 };
    const cases = [_]Case{
        .{ .number = 2, .name = "SIGINT" },
        .{ .number = 15, .name = "SIGTERM" },
        .{ .number = 1, .name = "SIGHUP" },
        .{ .number = 3, .name = "SIGQUIT" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 13);
        const before = sim_run.baseline(&sim);
        sim.world.script[0] = case.number;
        sim.world.script_len = 1;
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "sleep", "1000" };
        try testing.expectEqual(constants.exit_signal_offset + case.number, run(&sim, &args));
        try expect_signals(&sim, &.{constants.signal_kill});
        var note: [96]u8 = undefined;
        const format = "zbx: the container was killed by signal {d} ({s})\n";
        const text = try std.fmt.bufPrint(&note, format, .{ case.number, case.name });
        try testing.expectEqualStrings(text, sim.stderr());
        try no_leak(&sim, &before);
        try testing.expect(!sim.world.signals_blocked);
    }
}

test "a signal PID 1 handles or ignores is passed on as it is, and the container goes on" {
    // Goal: a shell that catches SIGINT keeps working: it gets the SIGINT, not a SIGKILL, and
    // then ends however it ends. The same for a signal it ignores on purpose. Several signals
    // arrive in order; after one the container cannot handle, the rest do not matter.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 14);
    sim.world.script = .{ 2, 2, 15, 0, 0, 0, 0, 0 };
    sim.world.script_len = 3;
    sim.world.command_caught = 1 << 1; // SIGINT.
    sim.world.command_ignored = 1 << 14; // SIGTERM.
    sim.world.command_exit = .{ .exited = 5 };
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "sh" };
    try testing.expectEqual(@as(u8, 5), run(&sim, &args));
    try expect_signals(&sim, &.{ 2, 2, 15 });
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);

    sim_run.init(&sim, 14);
    sim.world.script = .{ 2, 15, 1, 0, 0, 0, 0, 0 };
    sim.world.script_len = 3;
    sim.world.command_caught = 1 << 1;
    sim.world.command_exit = .{ .exited = 5 };
    // SIGINT is handled; SIGTERM is not, so the container is killed in its place, and the
    // SIGHUP after it finds nothing to signal.
    try testing.expectEqual(@as(u8, 128 + 15), run(&sim, &args));
    try expect_signals(&sim, &.{ 2, constants.signal_kill });
}

test "the library: start, inspect, signal and wait, with a warning handed over as it happens" {
    // Goal: the contract-shaped surface used directly, as Zigcube's agent will. Status moves
    // from running to stopped; a signal can be sent through the handle; the exit reason says how
    // it ended; the warning reaches the caller's function before the command starts.
    const lib = @import("run.zig");
    const Collector = struct {
        count: u32 = 0,
        code: ?codes.Code = null,

        fn call(context: *anyopaque, diag: *const @import("../diag/diag.zig").Diag) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
            self.code = diag.code;
        }
    };
    var sim: HostSim = undefined;
    sim_run.init_single(&sim, 15);
    sim.world.script[0] = 2;
    sim.world.script_len = 1;
    var collector: Collector = .{};
    const spec: lib.Spec = .{
        .rootfs = rootfs,
        .name = "lib-1",
        .command = &.{ "sleep", "1000" },
        .labels = &.{ .{ .key = "app", .value = "web" }, .{ .key = "tier", .value = "" } },
    };
    var handle: lib.Handle = undefined;
    var diag: @import("../diag/diag.zig").Diag = undefined;
    diag.reset();
    try lib.start(sim.interface(), &spec, .{
        .warn = .{ .context = &collector, .call = Collector.call },
    }, &handle, &diag);
    try testing.expectEqual(lib.Status.running, lib.inspect(&handle));
    try testing.expectEqual(@as(u32, 1), collector.count);
    try testing.expectEqual(@as(?codes.Code, .W0201), collector.code);
    try testing.expectEqualStrings("lib-1", handle.name_slice());
    const reason = lib.wait(&handle);
    try testing.expectEqual(lib.Status.stopped, lib.inspect(&handle));
    try testing.expectEqual(@as(u8, 2), reason.signaled);
    try testing.expectEqual(@as(?u8, 130), reason.code());
    try testing.expectEqual(@as(u32, 1), collector.count);

    // The record says how it ended and keeps the labels.
    const text = sim.world.read_written(sim_run.runs_path ++ "/lib-1.zon").?;
    try testing.expect(std.mem.indexOf(u8, text, ".exit = .{ .signaled = 2 }") != null);
    const labels = ".labels = .{ .{ \"app\", \"web\" }, .{ \"tier\", \"\" } }";
    try testing.expect(std.mem.indexOf(u8, text, labels) != null);
    try testing.expect(std.mem.indexOf(u8, text, ".ids = .single") != null);

    // A refusal is a diagnostic and a start_failed reason that carries it.
    var bad: lib.Handle = undefined;
    diag.reset();
    const refused: lib.Spec = .{ .rootfs = "/srv/nope", .name = null, .command = &.{"sh"} };
    try testing.expectError(
        error.StartFailed,
        lib.start(sim.interface(), &refused, .{}, &bad, &diag),
    );
    const failed = lib.failed_start(&diag);
    try testing.expectEqual(codes.Code.E0201, failed.start_failed.code.?);
    try testing.expectEqual(@as(?u8, null), failed.code());
}

test "labels that do not fit are refused before anything starts" {
    // Goal: the label bounds are checked at the door, with E0008 naming the label.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 16);
    const lib = @import("run.zig");
    var handle: lib.Handle = undefined;
    var diag: @import("../diag/diag.zig").Diag = undefined;
    diag.reset();
    const spec: lib.Spec = .{
        .rootfs = rootfs,
        .name = null,
        .command = &.{"sh"},
        .labels = &.{ .{ .key = "ok", .value = "" }, .{ .key = "bad key", .value = "" } },
    };
    try testing.expectError(
        error.StartFailed,
        lib.start(sim.interface(), &spec, .{}, &handle, &diag),
    );
    try testing.expectEqual(codes.Code.E0008, diag.code.?);
    try testing.expect(sim.world.processes[1].state == .unused);
}

fn record_text(sim: *const HostSim, name: []const u8) ?[]const u8 {
    var path: [128]u8 = undefined;
    const format = sim_run.runs_path ++ "/{s}.zon";
    // Cannot fail: the runs path and a test name fit in 128 bytes.
    const text = std.fmt.bufPrint(&path, format, .{name}) catch unreachable;
    return sim.world.read_written(text);
}

test "every run leaves a record: running while it runs is not seen, the end is" {
    // Goal: the record of a finished run, a refused start and a lost wait, read back.
    const records = @import("records.zig");
    var sim: HostSim = undefined;
    sim_run.init(&sim, 17);
    sim.world.now = 1_760_000_100;
    sim.world.command_exit = .{ .exited = 42 };
    const args = [_][:0]const u8{
        "zbx",
        "run",
        "--rootfs",
        rootfs,
        "--name",
        "rec-1",
        "--",
        "sh",
        "-c",
        "x",
    };
    try testing.expectEqual(@as(u8, 42), run(&sim, &args));
    var parsed: records.Parsed = undefined;
    try records.parse(record_text(&sim, "rec-1").?, &parsed);
    try testing.expectEqual(@as(u32, 1), parsed.version);
    try testing.expectEqual(@as(u64, 1_760_000_100), parsed.started);
    try testing.expectEqual(@as(?u64, 1_760_000_100), parsed.ended);
    try testing.expectEqual(records.Exit{ .exited = 42 }, parsed.exit);
    try testing.expectEqual(@as(?records.IdsMode, .full), parsed.ids);

    // A start that fails after the record began leaves a record that says so.
    sim_run.init(&sim, 17);
    const missing = [_][:0]const u8{
        "zbx",
        "run",
        "--rootfs",
        rootfs,
        "--name",
        "rec-2",
        "--",
        "nothere",
    };
    try testing.expectEqual(@as(u8, 127), run(&sim, &missing));
    try records.parse(record_text(&sim, "rec-2").?, &parsed);
    try testing.expectEqual(records.Exit{ .start_failed = .E0202 }, parsed.exit);

    // A refusal before anything began leaves none.
    sim_run.init(&sim, 17);
    const refused = [_][:0]const u8{
        "zbx",
        "run",
        "--rootfs",
        "/srv/nope",
        "--name",
        "rec-3",
        "--",
        "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &refused));
    try testing.expect(record_text(&sim, "rec-3") == null);

    // A wait that fails is a lost run.
    sim_run.init(&sim, 17);
    sim.faults.fail_step = sim_run.step_index(.reap, true);
    const lost = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "rec-4", "--", "sh" };
    try testing.expectEqual(@as(u8, 125), run(&sim, &lost));
    try records.parse(record_text(&sim, "rec-4").?, &parsed);
    try testing.expectEqual(records.Exit.lost, parsed.exit);
}

test "upgrade: a missing, empty, older, newer or damaged records directory never fails a run" {
    // Goal: the production-readiness upgrade test for run records. Method: runs against a state
    // directory that does not exist (the first run on a machine), one that is empty, one with a
    // record in the format before the version field, a newer-format one and a damaged one. Every
    // run ends with the command's code; the unreadable ones are skipped with one W0203 warning;
    // the older record is untouched.
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "upg", "--", "sh" };
    var sim: HostSim = undefined;
    sim_run.init(&sim, 18);
    try testing.expectEqual(@as(u8, 0), run(&sim, &args)); // Neither .local nor zbx exists yet.
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expect(record_text(&sim, "upg") != null);

    sim_run.init(&sim, 18);
    sim.world.add_node(sim_run.runs_path, .dir); // The directory exists and is empty.
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);

    sim_run.init(&sim, 18);
    sim.world.add_node(sim_run.runs_path, .dir);
    const legacy = ".{\n    .name = \"legacy\",\n    .started = 500,\n}\n";
    const future = ".{\n    .version = 7,\n    .name = \"future\",\n    .started = 600,\n}\n";
    try testing.expect(sim.world.write_file(sim_run.runs_path ++ "/legacy.zon", legacy) == null);
    try testing.expect(sim.world.write_file(sim_run.runs_path ++ "/future.zon", future) == null);
    try testing.expect(
        sim.world.write_file(sim_run.runs_path ++ "/damaged.zon", "\x00\x01 garbage") == null,
    );
    // Skipped records are only noticed when pruning has something to do; with few records there
    // is nothing to prune, so no run is slowed or stopped by reading them.
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expect(record_text(&sim, "legacy") != null);
    try testing.expect(record_text(&sim, "future") != null);

    // Past the limit the scan reads them all, skips what it cannot read, and says so once.
    sim_run.init(&sim, 18);
    sim.world.add_node(sim_run.runs_path, .dir);
    var name: [96]u8 = undefined;
    for (0..constants.runs_max) |number| {
        const path = try std.fmt.bufPrint(
            &name,
            sim_run.runs_path ++ "/old-{d:0>2}.zon",
            .{number},
        );
        var body: [96]u8 = undefined;
        const format = ".{{\n    .name = \"old-{d:0>2}\",\n    .started = {d},\n}}\n";
        const text = try std.fmt.bufPrint(&body, format, .{ number, 1000 + number });
        try testing.expect(sim.world.write_file(path, text) == null);
    }
    try testing.expect(sim.world.write_file(sim_run.runs_path ++ "/future.zon", future) == null);
    try testing.expect(
        sim.world.write_file(sim_run.runs_path ++ "/damaged.zon", "garbage") == null,
    );
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try expect_starts_with(
        sim.stderr(),
        "warning[ZBX-W0203]: skipped a run record that can't be read\n",
    );
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
    try testing.expect(record_text(&sim, "upg") != null);
    try testing.expect(record_text(&sim, "future") == null); // Unreadable ones go first.
    try testing.expect(record_text(&sim, "damaged") == null);
    try testing.expect(record_text(&sim, "old-00") == null); // 35 records: the oldest 3 go.
    try testing.expect(record_text(&sim, "old-01") != null);
}

test "a record that cannot be kept is a warning, never a failed run" {
    // Goal: the failure modes of keeping state: a full disk, no place for it at all, and a
    // state directory that cannot be made. Each warns once (W0202) and the run ends with the
    // command's own code.
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "full", "--", "sh" };
    var sim: HostSim = undefined;
    sim_run.init(&sim, 19);
    sim.world.disk_full = true;
    sim.world.command_exit = .{ .exited = 9 };
    try testing.expectEqual(@as(u8, 9), run(&sim, &args));
    try expect_starts_with(sim.stderr(), "warning[ZBX-W0202]: can't save the run record\n");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
    try testing.expect(
        std.mem.indexOf(u8, sim.stderr(), "no space left on the device (ENOSPC)") != null,
    );

    sim_run.init(&sim, 19);
    sim.environment_variables = &.{};
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try expect_starts_with(sim.stderr(), "warning[ZBX-W0202]: can't save the run record\n");
    try testing.expect(
        std.mem.indexOf(u8, sim.stderr(), "neither XDG_STATE_HOME nor HOME") != null,
    );

    sim_run.init(&sim, 19);
    sim.environment_variables = &.{.{ .name = "HOME", .value = "/home/nobody" }}; // Not there.
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try expect_starts_with(sim.stderr(), "warning[ZBX-W0202]: can't save the run record\n");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
}

test "run is in the help text, with its options and its exit codes" {
    // Goal: the help names run's flags (the snapshot test compares the whole text).
    var sim: HostSim = undefined;
    sim_run.init(&sim, 20);
    const args = [_][:0]const u8{ "zbx", "help" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    const words = [_][]const u8{ "--rootfs <dir>", "--name <name>", "ends the options" };
    for (words) |word| {
        try testing.expect(std.mem.indexOf(u8, sim.stdout(), word) != null);
    }
}
