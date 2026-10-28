//! Tests of `--net user` and `--publish` against the simulator (M5 slice 3): pasta started with
//! the command line docs/demos/m5.md settles, the container let go only once pasta is ready, the
//! ports released on every exit path, and each refusal a coded diagnostic with nothing left
//! behind. The simulator's pasta is `sim_world.World.start_program`; the VM shows the real one.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");
const run = @import("run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;
const rootfs = sim_run.rootfs_path;

fn no_leak(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

/// The pasta of the last run, the third process of the model (zbx, the container, then pasta).
fn pasta_of(sim: *const HostSim) *const @import("../sim_world.zig").Process {
    const pasta = &sim.world.processes[2];
    std.debug.assert(pasta.pasta);
    return pasta;
}

const spec_publish = [_]@import("spec.zig").Publish{.{ .host = 8080, .container = 80 }};

fn user_spec(name: []const u8) run.Spec {
    return .{
        .rootfs = rootfs,
        .name = name,
        .command = &.{ "/bin/sh", "-c", "exec httpd -f" },
        .network = .user,
        .publish = &spec_publish,
    };
}

/// Storage for a handle: far too big for a test's stack.
var handle: run.Handle = undefined;

test "--net user: pasta joins the container's namespaces, configured before the child runs" {
    // Goal: the success path. Method: a run with --publish; pasta's argv is exactly the settled
    // command line with the container's PID last; the container has a namespace of its own with
    // lo up and the generated files; its resolv.conf names pasta's DNS address; the JSON line
    // says user and lists the forward; nothing is left once it ends.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 31);
    const before = sim_run.baseline(&sim);
    const args = [_][:0]const u8{
        "zbx",    "--output", "json", "run", "--publish", "8080:80", "--rootfs", rootfs,
        "--name", "web-1",    "--",   "sh",
    };
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &args));
    const problem = sim_run.started(&sim, .{ .name = "web-1", .devpts = true, .network = .user });
    if (problem) |text| std.debug.print("the container is wrong: {s}\n", .{text});
    try testing.expect(problem == null);
    try testing.expectEqual(@as(u32, 1), sim.world.pasta_starts);
    var expected: [512]u8 = undefined;
    const argv = try std.fmt.bufPrint(&expected, "pasta\n--config-net\n--quiet\n--foreground\n" ++
        "--pid\n/proc/self/fd/1\n--udp-ports\nnone\n--tcp-ns\nnone\n--udp-ns\nnone\n" ++
        "--no-map-gw\n--dns-forward\n169.254.1.1\n--tcp-ports\n8080:80\n{d}\n", .{
        sim.world.processes[1].pid,
    });
    try testing.expectEqualStrings(argv, pasta_of(&sim).argv());
    const line = "\"network\":\"user\",\"published\":[{\"host\":8080,\"container\":80}]}";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), line) != null);
    const log = sim.world.read_written(sim_run.logs_path ++ "/web-1.pasta.log").?;
    try testing.expectEqualStrings(@import("../sim_world.zig").pasta_ready_output, log);
    try no_leak(&sim, &before);
}

test "--net user: resolv.conf names pasta's DNS address, not the host's stub" {
    // Goal: DNS through pasta on a systemd-resolved host. Method: the plan's resolv.conf text for
    // `user`, built for a host whose own file names 127.0.0.53.
    const plan_mod = @import("plan.zig");
    var plan: plan_mod.Plan = undefined;
    sim_run.sample_plan_image(&plan, true, true, false, false, .user);
    const text = plan.text(plan.etc_texts[1]);
    try testing.expect(std.mem.indexOf(u8, text, "nameserver 169.254.1.1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "127.0.0.53") == null);
    try testing.expect(plan.isolated());
    try testing.expectEqual(@as(usize, 1), plan.publish_slice().len);
}

test "ports are released on every exit path the simulator can show" {
    // Goal: the brief's list: a clean exit, `zbx stop`, `--timeout`, SIGKILL of the container,
    // and SIGKILL of zbx itself. Method: start through the library with a command that runs a
    // while; the port is listened on while it runs; each path ends it; afterwards no pasta is
    // alive or unreaped and no port is listened on.
    const Path = enum { clean, stop, timeout, kill_container, kill_zbx };
    for (std.enums.values(Path)) |path| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 40 + @as(u64, @backingInt(path)));
        const before = sim_run.baseline(&sim);
        sim.world.command_runs_ms = 60_000;
        sim.world.command_caught = 1 << 14; // SIGTERM, which `stop` and the timeout send.
        sim.world.term_exits = path == .stop;
        var diag: Diag = undefined;
        diag.reset();
        const options: run.StartOptions = .{
            .timeout_ms = if (path == .timeout) 1000 else 0,
            .grace_ms = 500,
        };
        try run.start(sim.interface(), &user_spec("web-1"), options, &handle, &diag);
        try testing.expectEqual(@as(u32, 1), sim.world.ports_listening());
        const container = sim.world.processes[1].pid;
        switch (path) {
            .clean, .timeout => {},
            // What `zbx stop` does from another process: SIGTERM to PID 1, which handles it.
            .stop => try testing.expect(sim.world.kill(container, 15) == null),
            .kill_container => try testing.expect(sim.world.kill(container, 9) == null),
            .kill_zbx => {
                sim.world.kill_supervisor();
                try testing.expectEqual(@as(u32, 0), sim.world.ports_listening());
                try testing.expectEqual(@as(u32, 0), sim.world.pasta_alive());
                continue; // zbx is gone: nobody waits, closes or cleans up after it.
            },
        }
        const reason = run.wait(&handle);
        try testing.expect(reason.code() != null);
        if (path == .timeout) try testing.expect(run.timed_out(&handle));
        try no_leak(&sim, &before);
    }
}

test "a pasta too old to notice its namespace go is still ended by zbx" {
    // Goal: "zbx also reaps it". Method: a pasta that never exits by itself; after the command
    // ends, wait has killed and reaped it, and the port is free.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 50);
    const before = sim_run.baseline(&sim);
    sim.world.pasta_stays = true;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &user_spec("web-1"), .{}, &handle, &diag);
    _ = run.wait(&handle);
    try testing.expectEqual(@as(u32, 0), sim.world.ports_listening());
    try testing.expectEqual(@as(u8, 9), pasta_of(&sim).exit.?.signaled);
    try no_leak(&sim, &before);
}

/// A refused run: the code, exit 125, a command that never started, no pasta, port or anything
/// else left behind.
fn expect_refused(sim: *HostSim, args: []const [:0]const u8, code: codes.Code) !void {
    const before = sim_run.baseline(sim);
    try testing.expectEqual(@as(u8, 125), sim_run.run_cli(sim, args));
    var name: [16]u8 = undefined;
    const tag = try std.fmt.bufPrint(&name, "[{s}]", .{codes.full_name(code)});
    if (std.mem.indexOf(u8, sim.stderr(), tag) == null) std.debug.print("{s}\n", .{sim.stderr()});
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), tag) != null);
    try testing.expect(!sim.world.processes[1].execd);
    try no_leak(sim, &before);
}

const publish_8080 = [_][:0]const u8{
    "zbx", "run", "--publish", "8080:80", "--rootfs", rootfs, "--name", "web-1", "--", "sh",
};

test "a pasta that fails, says nothing or says something else is refused by code" {
    // Goal: readiness. Method: each way pasta can fail to become ready is E0603 with its own
    // cause, pasta is reaped, and the container never ran its command.
    const Behaviour = @import("../sim_world.zig").PastaBehaviour;
    const Case = struct { behaviour: Behaviour, cause: []const u8 };
    const cases = [_]Case{
        .{ .behaviour = .fails, .cause = "pasta: Couldn't set up tap device in namespace" },
        .{ .behaviour = .silent, .cause = "within 10000 ms" },
        .{ .behaviour = .garbled, .cause = "something other than its process id" },
    };
    for (cases, 0..) |case, index| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 60 + index);
        sim.world.pasta_behaviour = case.behaviour;
        const args = [_][:0]const u8{
            "zbx", "-v", "run", "--net", "user", "--rootfs", rootfs, "--", "sh",
        };
        try expect_refused(&sim, &args, .E0603);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.cause) != null);
        try testing.expectEqual(@as(u32, 1), sim.world.pasta_starts);
    }
}

test "pasta missing, too old, a port in use and a port too low are refused by code" {
    // Goal: the 06xx refusals. Method: each condition in the model, run from the command line.
    var sim: HostSim = undefined;
    sim_run.start(&sim, 70, sim_run.files_without_pasta);
    try expect_refused(&sim, &publish_8080, .E0601);
    try testing.expectEqual(@as(u32, 0), sim.world.pasta_starts);

    sim_run.init(&sim, 71);
    sim.world.pasta_version_line = "pasta 2023_12_30.f091893\n";
    try expect_refused(&sim, &publish_8080, .E0602);
    try testing.expectEqual(@as(u32, 0), sim.world.pasta_starts);

    // A version line with no date (Ubuntu 24.04's build) is not refused.
    sim_run.init(&sim, 72);
    sim.world.pasta_version_line = "pasta unknown version\n";
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &publish_8080));

    sim_run.init(&sim, 73);
    sim.world.ports_taken[0] = 8080;
    sim.world.ports_taken_count = 1;
    try expect_refused(&sim, &publish_8080, .E0604);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "host port 8080") != null);

    // Below the bound read from the sysctl: refused before pasta starts.
    sim_run.init(&sim, 74);
    const low = [_][:0]const u8{
        "zbx", "run", "--publish", "80:80", "--rootfs", rootfs, "--", "sh",
    };
    try expect_refused(&sim, &low, .E0605);
    try testing.expectEqual(@as(u32, 0), sim.world.pasta_starts);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "(1024)") != null);
    // At the bound it is allowed.
    const at = [_][:0]const u8{
        "zbx", "run", "--publish", "1024:80", "--rootfs", rootfs, "--", "sh",
    };
    sim_run.init(&sim, 75);
    try testing.expectEqual(@as(u8, 0), sim_run.run_cli(&sim, &at));

    // A host whose bound cannot be read: pasta's own bind is refused, and that is E0605 too.
    const no_bound = sim_run.files_without_pasta.* ++ [_]host_sim.File{
        .{ .path = "/usr/bin/pasta", .content = "", .mode = 0o100755 },
    };
    sim_run.start(&sim, 76, &no_bound);
    try expect_refused(&sim, &low, .E0605);
    try testing.expectEqual(@as(u32, 1), sim.world.pasta_starts);
}

test "a failure injected into each of pasta's steps is a diagnostic naming it, and cleans up" {
    // Goal: the two parent steps fail cleanly at every call. Method: fail the first call of each
    // with EAGAIN; the run is refused with a coded diagnostic and nothing is left.
    const plan_mod = @import("plan.zig");
    var plan: plan_mod.Plan = undefined;
    sim_run.sample_plan_image(&plan, true, true, false, false, .user);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind != .start_pasta and step.kind != .await_pasta) continue;
        var sim: HostSim = undefined;
        sim_run.init(&sim, 80 + index);
        sim.faults.fail_step = @intCast(index);
        sim.faults.fail_step_errno = 11;
        try expect_refused(&sim, &publish_8080, .E0603);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "pasta") != null);
    }
}
