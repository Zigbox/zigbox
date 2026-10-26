//! How a container ended and what is left afterwards, against the simulator (docs/briefs/M2-limits
//! .md, slice 2): the OOM and process-limit reasons read from the scope's cgroup, the report
//! lines and JSON, the run record's version 2 fields, the scope's cleanup, and the fallback to
//! the user's own bus when an inherited address turns this user away. The run fuzzer checks the
//! same properties over random scenarios.

const std = @import("std");
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const records = @import("records.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const record_path = sim_run.runs_path ++ "/web-1.zon";

fn run(sim: *HostSim, args: []const [:0]const u8) u8 {
    return sim_run.run_cli(sim, args);
}

fn parsed_record(sim: *const HostSim) !records.Parsed {
    var parsed: records.Parsed = undefined;
    try records.parse(sim.world.read_written(record_path).?, &parsed);
    return parsed;
}

test "an OOM kill in the cgroup is the reason, exit 137, whatever PID 1 did" {
    // Goal: the supervisor's decision: any oom_kill above 0 makes the reason oom, with the real
    // signal's exit code and the report line, even when the command exited 0. Verbose output
    // shows what PID 1 did, so nothing is hidden. The record says oom, with the limit.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    sim.world.oom_kills = 1;
    sim.world.command_exit = .{ .exited = 0 };
    const args = [_][:0]const u8{
        "zbx",      "-v",   "run", "--rootfs", rootfs, "--name", "web-1",
        "--memory", "128m", "--",  "sh",
    };
    try testing.expectEqual(@as(u8, 137), run(&sim, &args));
    const text = sim.stderr();
    const line = "zbx: killed: out of memory (limit 128 MiB)\n";
    try testing.expect(std.mem.indexOf(u8, text, line) != null);
    const note = "zbx: note: the container's first process exited with code 0\n";
    try testing.expect(std.mem.indexOf(u8, text, note) != null);
    const parsed = try parsed_record(&sim);
    try testing.expectEqual(records.EndReason.oom, parsed.reason);
    try testing.expectEqual(records.Exit{ .exited = 0 }, parsed.exit);
    try testing.expectEqual(@as(?u64, 128 << 20), parsed.limits.memory_bytes);
    try testing.expectEqualStrings("zbx-web-1.scope", parsed.scope_slice());
    try testing.expect(!parsed.detached);
    try testing.expectEqual(@as(u32, 0), sim.world.bus.scope_count());
}

test "an OOM kill with no --memory has no limit to name" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 2);
    sim.world.oom_kills = 2;
    sim.world.command_exit = .{ .signaled = 9 };
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh" };
    try testing.expectEqual(@as(u8, 137), run(&sim, &args));
    try testing.expectEqualStrings("zbx: killed: out of memory\n", sim.stderr());
}

test "a process limit that was hit is the reason, and the command keeps its own exit code" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 3);
    sim.world.pids_max_hits = 5;
    sim.world.command_exit = .{ .exited = 3 };
    const args = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--pids", "64", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 3), run(&sim, &args));
    try testing.expectEqualStrings(
        "zbx: stopped: process limit reached (limit 64)\n",
        sim.stderr(),
    );
    const parsed = try parsed_record(&sim);
    try testing.expectEqual(records.EndReason.pid_limit, parsed.reason);
    try testing.expectEqual(records.Exit{ .exited = 3 }, parsed.exit);
    try testing.expectEqual(@as(?u32, 64), parsed.limits.pids);
}

test "both counters moved: OOM outranks the process limit" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 4);
    sim.world.oom_kills = 1;
    sim.world.pids_max_hits = 1;
    const args = [_][:0]const u8{
        "zbx",      "run", "--rootfs", rootfs, "--name", "web-1",
        "--memory", "64m", "--pids",   "8",    "--",     "sh",
    };
    try testing.expectEqual(@as(u8, 137), run(&sim, &args));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "killed: out of memory") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "process limit") == null);
}

test "the JSON container_exit names the reason for every way a container ends" {
    // Goal: "reason" is oom, pid_limit, signal or exited, with the fields that go with it.
    const Case = struct {
        oom: u32 = 0,
        pids: u32 = 0,
        exit: @import("../host.zig").ExitStatus,
        extra: []const []const u8 = &.{},
        want: []const u8,
    };
    const cases = [_]Case{
        .{
            .exit = .{ .exited = 7 },
            .want = "{\"container_exit\":{\"reason\":\"exited\",\"code\":7}}\n",
        },
        .{
            .exit = .{ .signaled = 15 },
            .want = "{\"container_exit\":{\"reason\":\"signal\",\"signal\":15,\"code\":143}}\n",
        },
        .{
            .oom = 1,
            .exit = .{ .exited = 0 },
            .extra = &.{ "--memory", "128m" },
            .want = "{\"container_exit\":{\"reason\":\"oom\"," ++
                "\"limit_bytes\":134217728,\"code\":137}}\n",
        },
        .{
            .oom = 1,
            .exit = .{ .exited = 0 },
            .want = "{\"container_exit\":{\"reason\":\"oom\",\"limit_bytes\":null,\"code\":137}}\n",
        },
        .{
            .pids = 1,
            .exit = .{ .exited = 2 },
            .extra = &.{ "--pids", "16" },
            .want = "{\"container_exit\":{\"reason\":\"pid_limit\",\"limit\":16,\"code\":2}}\n",
        },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 5);
        sim.world.oom_kills = case.oom;
        sim.world.pids_max_hits = case.pids;
        sim.world.command_exit = case.exit;
        var args: [16][:0]const u8 = undefined;
        const head = [_][:0]const u8{
            "zbx", "--output", "json", "run", "--rootfs", rootfs, "--name", "web-1",
        };
        @memcpy(args[0..head.len], &head);
        var count: usize = head.len;
        for (case.extra) |word| {
            args[count] = @ptrCast(word);
            count += 1;
        }
        args[count] = "--";
        args[count + 1] = "sh";
        _ = run(&sim, args[0 .. count + 2]);
        try testing.expectEqualStrings(case.want, sim.stderr());
    }
}

test "plain exits and signals keep M1's reporting" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 6);
    sim.world.command_exit = .{ .signaled = 15 };
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh" };
    try testing.expectEqual(@as(u8, 143), run(&sim, &args));
    try testing.expectEqualStrings(
        "zbx: the container was killed by signal 15 (SIGTERM)\n",
        sim.stderr(),
    );
    const parsed = try parsed_record(&sim);
    try testing.expectEqual(records.EndReason.signal, parsed.reason);
}

test "a cgroup the manager removed before it could be read gives the plain exit" {
    // Goal: the race is survivable. The counters cannot be read, nothing is claimed, and
    // nothing is left behind or warned about.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 7);
    sim.world.bus.model.scope_removal = .promptly;
    sim.world.oom_kills = 1;
    sim.world.command_exit = .{ .exited = 4 };
    const args = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--memory", "64m", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 4), run(&sim, &args));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u32, 0), sim.world.bus.scope_count());
}

test "a scope that lingers is stopped, and one that cannot be stopped is a warning" {
    // Goal: the cleanup. A scope the manager keeps (it has not noticed the last process go) is
    // stopped with StopUnit and the run says nothing. A refusal, a stop job that does not end
    // in done, and a cgroup that stays after a stop are ZBX-W0302, and the exit code is still
    // the container's.
    const Case = struct { set_up: *const fn (*HostSim) void, cause: []const u8 };
    const cases = [_]Case{
        .{ .set_up = lingers, .cause = "" },
        .{ .set_up = stop_refused, .cause = "AccessDenied" },
        .{ .set_up = stop_canceled, .cause = "'canceled'" },
        .{ .set_up = cgroup_stays, .cause = "still there" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 8);
        case.set_up(&sim);
        sim.world.command_exit = .{ .exited = 9 };
        const args = [_][:0]const u8{
            "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh",
        };
        try testing.expectEqual(@as(u8, 9), run(&sim, &args));
        if (case.cause.len == 0) {
            try testing.expectEqual(@as(usize, 0), sim.stderr().len);
            try testing.expectEqual(@as(u32, 0), sim.world.bus.scope_count());
        } else {
            const text = sim.stderr();
            try testing.expect(std.mem.startsWith(u8, text, "warning[ZBX-W0302]: "));
            try testing.expect(std.mem.indexOf(u8, text, case.cause) != null);
        }
    }
}

fn lingers(sim: *HostSim) void {
    sim.world.bus.model.scope_removal = .never;
}

fn stop_refused(sim: *HostSim) void {
    sim.world.bus.model.scope_removal = .never;
    sim.world.bus.model.stop_error = "org.freedesktop.DBus.Error.AccessDenied";
}

fn stop_canceled(sim: *HostSim) void {
    sim.world.bus.model.scope_removal = .never;
    sim.world.bus.model.stop_result = "canceled";
}

fn cgroup_stays(sim: *HostSim) void {
    sim.world.bus.model.scope_removal = .never;
    sim.world.cgroup_stays = true;
}

// ---- The inherited bus ----------------------------------------------------------------------

const roots_bus = "/run/user/0/bus";

fn inherited(sim: *HostSim) void {
    sim.environment_variables = &.{
        .{ .name = "HOME", .value = sim_run.home_path },
        .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
        .{ .name = "DBUS_SESSION_BUS_ADDRESS", .value = "unix:path=" ++ roots_bus },
    };
}

test "an inherited address that turns this user away falls back to the user's own bus" {
    // Goal: `su`/`sudo` leave another user's DBUS_SESSION_BUS_ADDRESS. Permission denied at
    // connect, or a refused authentication, tries /run/user/<uid>/bus once; the run gets its
    // scope, and --verbose says which address worked.
    for ([_]bool{ false, true }) |rejects| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 9);
        inherited(&sim);
        sim.world.bus.model.foreign_socket = roots_bus;
        sim.world.bus.model.foreign_rejects = rejects;
        const args = [_][:0]const u8{
            "zbx", "-v", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh",
        };
        try testing.expectEqual(@as(u8, 0), run(&sim, &args));
        const why = if (rejects)
            "it did not accept this user's authentication"
        else
            "access denied";
        var expected: [160]u8 = undefined;
        const note = try std.fmt.bufPrint(
            &expected,
            "zbx: note: the bus at {s} turned this user away ({s}); connected to " ++
                "/run/user/1000/bus instead\n",
            .{ roots_bus, why },
        );
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), note) != null);
        try testing.expectEqual(@as(u32, 1), sim.world.bus.scopes_started);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "warning[") == null);
    }
}

test "the fallback is not tried when it would be pointless, and is tried only once" {
    // Goal: a missing socket (a stale address) is not permission trouble; an address that
    // already is the user's own has nowhere else to go; and when the second address fails too,
    // the diagnostic tells both stories.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 10);
    inherited(&sim);
    const args = [_][:0]const u8{ "zbx", "run", "--rootfs", rootfs, "--name", "web-1", "--", "sh" };
    // The inherited socket does not exist: no retry, so the run warns that it has no scope.
    try testing.expectEqual(@as(u8, 0), run(&sim, &args));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "warning[ZBX-W0301]: "));
    try testing.expectEqual(@as(u32, 0), sim.world.bus.scopes_started);

    // The user's own socket is the one refused: the same address twice would change nothing.
    sim_run.init(&sim, 11);
    sim.environment_variables = &.{
        .{ .name = "HOME", .value = sim_run.home_path },
        .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
    };
    sim.world.bus.model.foreign_socket = "/run/user/1000/bus";
    const limited = [_][:0]const u8{
        "zbx", "run", "--rootfs", rootfs, "--pids", "8", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &limited));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "turned this user away") == null);

    // Both refuse: the inherited one for permission, the user's own because nobody listens.
    sim_run.init(&sim, 12);
    inherited(&sim);
    sim.world.bus.model.foreign_socket = roots_bus;
    sim.world.bus.model.refuses = true;
    try testing.expectEqual(@as(u8, 125), run(&sim, &limited));
    const text = sim.stderr();
    try testing.expect(std.mem.startsWith(u8, text, "error[ZBX-E0307]: "));
}

test "the fallback's two stories appear in the verbose cause chain" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 13);
    inherited(&sim);
    sim.world.bus.model.foreign_socket = roots_bus;
    sim.world.bus.model.refuses = true;
    const args = [_][:0]const u8{
        "zbx", "-v", "run", "--rootfs", rootfs, "--pids", "8", "--", "sh",
    };
    try testing.expectEqual(@as(u8, 125), run(&sim, &args));
    const text = sim.stderr();
    const first = "the inherited bus at /run/user/0/bus turned this user away";
    try testing.expect(std.mem.indexOf(u8, text, first) != null);
    try testing.expect(std.mem.indexOf(u8, text, "tried /run/user/1000/bus") != null);
}

// ---- Run record version 2 ---------------------------------------------------------------------

test "a version 1 record reads unchanged, with the version 2 fields defaulted" {
    // Goal: the upgrade test. The text below is what version 1 zbx wrote (no reason, limits,
    // scope or detached); the current reader gives the same name, times and exit, no limits, no
    // scope, not detached, and the reason its exit implies.
    const v1 =
        \\.{
        \\    .version = 1,
        \\    .name = "web-1",
        \\    .rootfs = "/srv/alpine",
        \\    .command = .{ "/bin/sh", "-c", "exit 3" },
        \\    .command_truncated = false,
        \\    .labels = .{ .{ "app", "web" } },
        \\    .started = 1760000000,
        \\    .ended = 1760000042,
        \\    .exit = .{ .exited = 3 },
        \\    .ids = .full,
        \\    .zbx = "0.0.0",
        \\}
        \\
    ;
    var parsed: records.Parsed = undefined;
    try records.parse(v1, &parsed);
    try testing.expectEqual(@as(u32, 1), parsed.version);
    try testing.expectEqualStrings("web-1", parsed.name_slice());
    try testing.expectEqualStrings("/srv/alpine", parsed.rootfs_slice());
    try testing.expectEqual(@as(u64, 1_760_000_000), parsed.started);
    try testing.expectEqual(@as(?u64, 1_760_000_042), parsed.ended);
    try testing.expectEqual(records.Exit{ .exited = 3 }, parsed.exit);
    try testing.expectEqual(@as(?records.IdsMode, .full), parsed.ids);
    try testing.expectEqual(records.EndReason.exited, parsed.reason);
    try testing.expect(!parsed.detached);
    try testing.expectEqual(@as(usize, 0), parsed.scope_slice().len);
    try testing.expect(!parsed.limits.any());
    // A signal in a version 1 record implies the signal reason; a run that never ended, none.
    const gpa = testing.allocator;
    const exited = ".{ .exited = 3 }";
    const signaled = try std.mem.replaceOwned(u8, gpa, v1, exited, ".{ .signaled = 9 }");
    defer testing.allocator.free(signaled);
    try records.parse(signaled, &parsed);
    try testing.expectEqual(records.EndReason.signal, parsed.reason);
    const running = try std.mem.replaceOwned(u8, gpa, v1, exited, ".running");
    defer testing.allocator.free(running);
    try records.parse(running, &parsed);
    try testing.expectEqual(records.EndReason.none, parsed.reason);
}

test "a version 2 record round-trips, and version 3 is newer" {
    var view = sim_run.sample_view("web-1", 1000);
    view.reason = .pid_limit;
    view.limits = .{ .memory_bytes = 64 << 20, .pids = 16, .cpu_millis = 500 };
    view.scope = "zbx-web-1.scope";
    view.detached = true;
    var buffer: [constants.record_bytes_max]u8 = undefined;
    const text = records.render(&view, &buffer);
    var parsed: records.Parsed = undefined;
    try records.parse(text, &parsed);
    try testing.expectEqual(@as(u32, 3), parsed.version);
    try testing.expectEqual(records.EndReason.pid_limit, parsed.reason);
    try testing.expectEqual(view.limits, parsed.limits);
    try testing.expectEqualStrings("zbx-web-1.scope", parsed.scope_slice());
    try testing.expect(parsed.detached);
    const gpa = testing.allocator;
    const newer = try std.mem.replaceOwned(u8, gpa, text, ".version = 3,", ".version = 4,");
    defer testing.allocator.free(newer);
    try testing.expectError(error.Newer, records.parse(newer, &parsed));
    const reason = ".reason = .pid_limit";
    const damaged = try std.mem.replaceOwned(u8, gpa, text, reason, ".reason = .exploded");
    defer testing.allocator.free(damaged);
    try testing.expectError(error.Malformed, records.parse(damaged, &parsed));
}
