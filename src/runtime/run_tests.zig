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
    sim.environment_variables = &.{.{ .name = "TERM", .value = "xterm-256color" }};
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
    // and exit 1, and the simulator's world is untouched.
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
        try testing.expectEqual(@as(u8, 1), run(&sim, case.args));
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
    const Case = struct { command: [:0]const u8, words: []const []const u8 };
    const cases = [_]Case{
        .{
            .command = "/bin/nothere",
            .words = &.{ "'/bin/nothere' does not exist in the rootfs", "dynamic loader" },
        },
        .{
            .command = "nothere",
            .words = &.{ "no file named 'nothere' in the container's PATH", container_path },
        },
        .{ .command = "/bin/directory", .words = &.{"is not a program this machine can run"} },
    };
    for (cases) |case| {
        sim_run.init(&sim, 5);
        sim.world.add_node(rootfs ++ "/bin/directory", .dir);
        const before = sim_run.baseline(&sim);
        const args = [_][:0]const u8{ "zbx", "-v", "run", "--rootfs", rootfs, "--", case.command };
        try testing.expectEqual(@as(u8, 1), run(&sim, &args));
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
    // code is the blame's, and nothing leaked: the child is reaped, no descriptor is open and
    // the host's mounts and hostname are as they were.
    var plan: plan_mod.Plan = undefined;
    const input: plan_mod.Input = .{
        .rootfs = rootfs,
        .name = "walk",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
    };
    plan.build(&input);
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
            try testing.expectEqual(codes.exit_code(codes.entry(expected).blame), code);
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
    var plan: plan_mod.Plan = undefined;
    plan.build(&.{
        .rootfs = rootfs,
        .name = "x",
        .command = &.{"sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
    });
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind != .write_uid_map) continue;
        sim.faults.fail_step = @intCast(index);
    }
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "x", "--", "sh" };
    try testing.expectEqual(@as(u8, 2), run(&sim, &args));
    const child = &sim.world.processes[1];
    try testing.expect(child.state == .reaped);
    try testing.expect(!child.execd);
    try testing.expectEqual(@as(u32, 3), sim.world.tables[1].count); // Copied, never changed.
    const killed: host_mod.ExitStatus = .{ .signaled = constants.signal_kill };
    try testing.expectEqual(killed, child.exit.?);
    try no_leak(&sim, &before);
}

fn step_index(kind: plan_mod.Kind) u32 {
    var plan: plan_mod.Plan = undefined;
    plan.build(&.{
        .rootfs = rootfs,
        .name = "x",
        .command = &.{"sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
    });
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == kind) return @intCast(index);
    }
    unreachable; // Every kind asked for here is in every plan.
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
        sim.faults.fail_step = step_index(case.kind);
        sim.faults.fail_step_errno = case.errno;
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--", "sh" };
        const code = run(&sim, &args);
        try testing.expect(code != 0);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.present) != null);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.absent) == null);
    }
}
