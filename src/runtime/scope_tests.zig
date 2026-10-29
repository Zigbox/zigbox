//! A container run and its cgroup scope, against the simulator and its user bus, from the command
//! line down: which scope a run gets and what it is made with, what a run does without one, and
//! each way the bus or systemd can refuse (docs/briefs/M2-limits.md, slice 1). The run fuzzer
//! checks the same properties over random scenarios; these tests state the cases one by one.

const std = @import("std");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;

fn run(sim: *HostSim, args: []const [:0]const u8) u8 {
    return sim_run.run_cli(sim, args);
}

fn expect_leak_free(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

test "a run gets a scope named for it, with the container in it before it runs" {
    // Goal: the scope exists, with the right name and the container's pid, Delegate and the four
    // kinds of accounting, in the user's app.slice; it was started while the container was
    // still waiting for the go-ahead; and it is gone when the container is.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u32, 1), sim.world.bus.scopes_started);
    const scope = &sim.world.bus.last_scope;
    try testing.expectEqualStrings("zbx-web-1.scope", scope.name.slice());
    try testing.expectEqual(sim.world.processes[1].pid, scope.pid);
    try testing.expect(scope.delegate);
    try testing.expectEqual(@as(u32, 4), scope.accounting);
    try testing.expectEqualStrings("app.slice", scope.slice.slice());
    try testing.expect(scope.memory_max == null);
    try testing.expect(scope.tasks_max == null);
    try testing.expect(sim.world.scope_started_before_child_ran);
    try expect_leak_free(&sim, &before); // Including: no scope left behind.
}

test "the limit flags become the scope's properties, in either spelling" {
    // Goal: --memory 128m is MemoryMax 128 MiB with MemorySwapMax 0, --pids 64 is TasksMax 65
    // (the scope's keeper takes one), --cpus 0.5 is 500000 microseconds of CPU per second;
    // "--flag=value" is the same as "--flag value".
    var sim: HostSim = undefined;
    sim_run.init(&sim, 2);
    const spaced = [_][:0]const u8{
        "zbx",    "run", "--rootfs", rootfs,  "--memory", "128m", "--pids", "64",
        "--cpus", "0.5", "--name",   "web-1", "--",       "sh",
    };
    try testing.expectEqual(@as(u8, 0), run(&sim, &spaced));
    var scope = sim.world.bus.last_scope;
    try testing.expectEqual(@as(?u64, 128 << 20), scope.memory_max);
    try testing.expectEqual(@as(?u64, 0), scope.memory_swap_max);
    try testing.expectEqual(@as(?u64, 65), scope.tasks_max);
    try testing.expectEqual(@as(?u64, 500_000), scope.cpu_quota_usec);

    sim_run.init(&sim, 3);
    const inline_form = [_][:0]const u8{
        "zbx",         "run",    "--rootfs", rootfs, "--memory=1g", "--pids=1",
        "--cpus=1.25", "--name", "web-1",    "--",   "sh",
    };
    try testing.expectEqual(@as(u8, 0), run(&sim, &inline_form));
    scope = sim.world.bus.last_scope;
    try testing.expectEqual(@as(?u64, 1 << 30), scope.memory_max);
    try testing.expectEqual(@as(?u64, 2), scope.tasks_max);
    try testing.expectEqual(@as(?u64, 1_250_000), scope.cpu_quota_usec);
}

test "a limit given twice is refused, not silently ignored" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 4);
    const args = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--pids", "4", "--pids", "8", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0003]: "));
    try testing.expectEqual(@as(u32, 0), sim.world.bus.scopes_started);
}

test "a limit value that is not acceptable is E0306 before anything starts" {
    // Goal: each way a value is wrong gives the one coded refusal, exit 125, and nothing was
    // created: no process, no scope, no record.
    const bad = [_]struct { flag: [:0]const u8, value: [:0]const u8 }{
        .{ .flag = "--memory", .value = "0" },
        .{ .flag = "--memory", .value = "" },
        .{ .flag = "--memory", .value = "lots" },
        .{ .flag = "--memory", .value = "1m" },
        .{ .flag = "--memory", .value = "2000g" },
        .{ .flag = "--memory", .value = "-5m" },
        .{ .flag = "--pids", .value = "0" },
        .{ .flag = "--pids", .value = "9999999999" },
        .{ .flag = "--pids", .value = "1.5" },
        .{ .flag = "--cpus", .value = "0" },
        .{ .flag = "--cpus", .value = "0.0001" },
        .{ .flag = "--cpus", .value = "5000" },
        .{ .flag = "--cpus", .value = "half" },
    };
    var sim: HostSim = undefined;
    for (bad) |case| {
        sim_run.init(&sim, 5);
        const before = sim_run.baseline(&sim);
        const args = [_][:0]const u8{
            "zbx", "run", "--rootfs", rootfs, case.flag, case.value, "--", "sh",
        };
        try testing.expectEqual(@as(u8, 125), run(&sim, &args));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0306]: "));
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error["));
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expectEqual(@as(u32, 0), sim.world.bus.connections);
        try testing.expectEqual(@as(u32, 0), sim.world.written_count);
        try expect_leak_free(&sim, &before);
    }
}

test "without a user bus a run with no limits warns once and goes on, as M1 did" {
    // Goal: W0301 names why, the run has no scope step, and the command's own code is the exit.
    const absences = [_]struct { name: []const u8, set_up: *const fn (*HostSim) void }{
        .{ .name = "no socket", .set_up = no_socket },
        .{ .name = "no environment", .set_up = no_environment },
        .{ .name = "no systemd on the bus", .set_up = no_systemd },
        .{ .name = "auth refused", .set_up = auth_refused },
    };
    for (absences) |absence| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 6);
        absence.set_up(&sim);
        sim.world.command_exit = .{ .exited = 9 };
        const before = sim_run.baseline(&sim);
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "a", "--", "sh" };
        try testing.expectEqual(@as(u8, 9), run(&sim, &args));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "warning[ZBX-W0301]: "));
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
        try testing.expectEqual(@as(u32, 0), sim.world.bus.scopes_started);
        try expect_leak_free(&sim, &before);
    }
}

fn no_socket(sim: *HostSim) void {
    sim.world.bus.model.present = false;
}

fn no_environment(sim: *HostSim) void {
    sim.environment_variables = &.{.{ .name = "HOME", .value = sim_run.home_path }};
}

fn no_systemd(sim: *HostSim) void {
    sim.world.bus.model.systemd_present = false;
}

fn auth_refused(sim: *HostSim) void {
    sim.world.bus.model.auth = .reject;
}

test "without a user bus a run with a limit is refused, E0307, and creates nothing" {
    // Goal: a limit nobody would enforce is refused, naming why the scope cannot be made.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 7);
    no_socket(&sim);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--pids", "64", "--", "sh" };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0307]: "));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "the bus socket does not exist") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "["));
    try testing.expect(sim.world.processes[1].state == .unused);
    try testing.expectEqual(@as(u32, 0), sim.world.written_count); // No record.
    try expect_leak_free(&sim, &before);
}

test "each way the scope step can fail is its own code, exit 125, and cleans up" {
    // Goal: after a perfect probe, a bus or a systemd that fails the step gives the code the
    // table in the E03xx pages promises, the container never runs a command, and the scope the
    // model may have started is gone with its process.
    const Fault = struct { code: []const u8, set_up: *const fn (*HostSim) void };
    const cases = [_]Fault{
        .{ .code = "E0301", .set_up = fault_no_socket },
        .{ .code = "E0302", .set_up = fault_auth },
        .{ .code = "E0302", .set_up = fault_hello },
        .{ .code = "E0301", .set_up = fault_no_systemd },
        .{ .code = "E0304", .set_up = fault_refused },
        .{ .code = "E0305", .set_up = fault_taken },
        .{ .code = "E0304", .set_up = fault_job_failed },
        .{ .code = "E0304", .set_up = fault_job_never },
        .{ .code = "E0303", .set_up = fault_garbage },
        .{ .code = "E0303", .set_up = fault_silent },
        .{ .code = "E0303", .set_up = fault_hang_up },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 8);
        sim.world.bus.model.quiet_connections = 1;
        sim.world.bus.model.perfect_from = 2;
        case.set_up(&sim);
        const before = sim_run.baseline(&sim);
        const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "x", "--", "sh" };
        try testing.expectEqual(@as(u8, 125), run(&sim, &args));
        var header: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&header, "error[ZBX-{s}]: ", .{case.code});
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), text));
        try testing.expect(!sim.world.processes[1].execd);
        try expect_leak_free(&sim, &before);
    }
}

fn fault_no_socket(sim: *HostSim) void {
    sim.world.bus.model.present = false;
}

fn fault_auth(sim: *HostSim) void {
    sim.world.bus.model.auth = .reject;
}

fn fault_hello(sim: *HostSim) void {
    sim.world.bus.model.hello_error = "org.freedesktop.DBus.Error.AccessDenied";
}

fn fault_no_systemd(sim: *HostSim) void {
    sim.world.bus.model.systemd_present = false;
}

fn fault_refused(sim: *HostSim) void {
    sim.world.bus.model.start_error = "org.freedesktop.DBus.Error.AccessDenied";
}

fn fault_taken(sim: *HostSim) void {
    sim.world.bus.model.unit_taken = true;
}

fn fault_job_failed(sim: *HostSim) void {
    sim.world.bus.model.job_result = "failed";
}

fn fault_job_never(sim: *HostSim) void {
    sim.world.bus.model.job_removed = false;
}

fn fault_garbage(sim: *HostSim) void {
    sim.world.bus.model.misbehave = .{ .at_call = 3, .how = .garbage_reply };
}

fn fault_silent(sim: *HostSim) void {
    sim.world.bus.model.misbehave = .{ .at_call = 3, .how = .silent };
}

fn fault_hang_up(sim: *HostSim) void {
    sim.world.bus.model.misbehave = .{ .at_call = 3, .how = .hang_up };
}

test "a taken scope name is refused and the other container's scope is left alone" {
    // Goal: "fail" mode: never reuse, never steal. Method: a second run with the name of a
    // running scope (one the model already holds) is E0305, and the first scope stays.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 9);
    sim.world.bus.scopes[0] = .{
        .active = true,
        .uid = 1000,
        .name = .{},
        .pid = 4242,
        .keeper_pid = 0,
        .slice = .{},
        .delegate = true,
        .memory_max = null,
        .memory_swap_max = null,
        .tasks_max = null,
        .cpu_quota_usec = null,
        .accounting = 4,
        .exited = false,
        .container_gone = false,
        .keeper_gone = false,
    };
    sim.world.bus.scopes[0].name.print("zbx-web-1.scope", .{});
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh" };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0305]: "));
    try testing.expectEqual(@as(u32, 1), sim.world.bus.scope_count());
    try testing.expectEqual(@as(u32, 4242), sim.world.bus.scopes[0].pid);
}

test "a systemd too old for a property gets the limit in the scope's cgroup files" {
    // Goal: systemd 230 has no MemoryMax: the run still gets its memory limit, written to
    // memory.max (and memory.swap.max) in the scope's cgroup, while the pids limit, which 230
    // has, is a property.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 10);
    sim.world.bus.model.version = "230.1";
    const args = [_][:0]const u8{
        "zbx",      "run", "--rootfs", rootfs, "--name", "web-1",
        "--memory", "64m", "--pids",   "8",    "--",     "sh",
    };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    const scope = &sim.world.bus.last_scope;
    try testing.expect(scope.memory_max == null);
    try testing.expectEqual(@as(?u64, 9), scope.tasks_max);
    try testing.expectEqual(@as(usize, 0), scope.slice.len); // app.slice needs 247.
    // The scope and its files are gone after the run; the world kept what memory.max held.
    try testing.expectEqualStrings("67108864", sim.world.ended_memory_max.?.slice());
    try testing.expectEqual(@as(u32, 0), sim.world.bus.scope_count());
}

test "a failure of the cgroup write names the file and cleans up" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 11);
    sim.world.bus.model.version = "230.1";
    const base = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/zbx-web-1.scope";
    sim.world.add_node(base ++ "/memory.max", .dir);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--memory", "64m", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0308]: "));
    try expect_leak_free(&sim, &before);
}

test "the user's own bus address is used when the environment has one" {
    // Goal: DBUS_SESSION_BUS_ADDRESS wins over the runtime directory, as the decision says.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 12);
    sim.world.bus.model.socket_path = "/tmp/custom-bus";
    sim.environment_variables = &.{
        .{ .name = "HOME", .value = sim_run.home_path },
        .{ .name = "DBUS_SESSION_BUS_ADDRESS", .value = "unix:path=/tmp/custom-bus,guid=ab" },
    };
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "a", "--", "sh" };
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expectEqual(@as(u32, 1), sim.world.bus.scopes_started);
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

// ---- The cgroupfs driver (the macOS VM: no systemd) -------------------------------------------

const limited_run = [_][:0]const u8{
    "zbx",    "run", "--rootfs", rootfs,  "--memory", "128m", "--pids", "64",
    "--cpus", "0.5", "--name",   "web-1", "--",       "sh",
};

test "without a bus and with a delegated directory, a run makes its own cgroup and removes it" {
    // Goal: the cgroupfs driver's whole run. Method: a host with ZBX_CGROUP_ROOT and no bus; the
    // limits are written as files of the container's cgroup, the container and the keeper were
    // moved in before the container ran, no warning is printed, and the cgroup is gone after.
    var sim: HostSim = undefined;
    sim_run.init_cgroupfs(&sim, 40);
    const before = sim_run.baseline(&sim);
    try testing.expectEqual(@as(u8, 0), run(&sim, &limited_run));
    if (sim.stderr().len > 0) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u32, 0), sim.world.bus.connections); // No bus was asked.
    const directory = sim_run.cgroup_root ++ "/zbx-web-1.scope";
    const world = &sim.world;
    try testing.expectEqualStrings("134217728", world.read_written(directory ++ "/memory.max").?);
    try testing.expectEqualStrings("65", world.read_written(directory ++ "/pids.max").?);
    try testing.expectEqualStrings("50000 100000", world.read_written(directory ++ "/cpu.max").?);
    try testing.expect(world.read_written(directory ++ "/cgroup.procs") != null);
    try testing.expect(sim.world.scope_started_before_child_ran);
    try expect_leak_free(&sim, &before); // Including: no cgroup directory left behind.
}

test "a systemd host is untouched by the variable: with a bus the bus is used" {
    // Goal: behaviour on a host with systemd is unchanged. Method: both the bus's address and the
    // variable; the scope comes from the bus and no directory is made.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 41);
    sim.world.add_node(sim_run.cgroup_root, .dir);
    const both = [_]host_sim.EnvironmentVariable{
        .{ .name = "HOME", .value = sim_run.home_path },
        .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
        .{ .name = "ZBX_CGROUP_ROOT", .value = sim_run.cgroup_root },
    };
    sim.environment_variables = &both;
    try testing.expectEqual(@as(u8, 0), run(&sim, &limited_run));
    try testing.expectEqual(@as(u32, 1), sim.world.bus.scopes_started);
    try testing.expectEqual(@as(u32, 0), sim_run.cgroupfs_directories(&sim));
}

test "a fault at any call of a cgroupfs run is coded or clean, and its cgroup goes or is reported" {
    // Goal: ENOSPC, EPERM and a plain I/O error on mkdir, write and rmdir, and a crash between
    // steps (the one-shot fault fails the n-th host call, whichever it is). Method: count the
    // calls of a good run, then fail each call in turn with each error; the run must end 0, or
    // 125 with one coded diagnostic, and the cgroup directory must be gone or the
    // warning W0302 must say it is not (the other leaks a fault can cause are the run's, and
    // are the same under the bus driver).
    var counting: HostSim = undefined;
    sim_run.init_cgroupfs(&counting, 42);
    try testing.expectEqual(@as(u8, 0), run(&counting, &limited_run));
    const calls = counting.call_count;
    try testing.expect(calls > 10);
    const Error = @import("../host.zig").Error;
    const errors = [_]Error{ error.NoSpace, error.AccessDenied, error.IoFailed };
    var sim: HostSim = undefined;
    for (errors) |err| {
        var index: u32 = 0;
        while (index < calls) : (index += 1) {
            sim_run.init_cgroupfs(&sim, 42);
            sim.faults.fail_call_index = index;
            sim.faults.fail_call_error = err;
            const code = run(&sim, &limited_run);
            testing.expect(code == 0 or code >= 125) catch |failure| {
                const words = "call {d} failing with {s}: exit {d}\n";
                std.debug.print(words, .{ index, @errorName(err), code });
                return failure;
            };
            const diagnosed = std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E") != null;
            if (code == 125) try testing.expect(diagnosed);
            // A cgroup is removed, or the failure to remove it was said (a warning).
            const left = sim_run.cgroupfs_directories(&sim);
            const warned = std.mem.indexOf(u8, sim.stderr(), "ZBX-W0302") != null;
            if (left > 0) try testing.expect(warned);
        }
    }
}

test "the cgroupfs steps each have a code: make and join are E0309, a leftover is W0302" {
    // Goal: the three ways the driver fails are reported by the coded diagnostics the registry
    // describes. Method: the delegated directory is missing (make), is read-only for the user
    // (made by a fault on the make step) and cannot be removed (a fault at the last call).
    var sim: HostSim = undefined;
    sim_run.init(&sim, 43); // The directory does not exist: its parent is missing.
    sim.environment_variables = &sim_run.env_cgroupfs;
    try testing.expectEqual(@as(u8, 125), run(&sim, &limited_run));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0309]: ") != null);
}
