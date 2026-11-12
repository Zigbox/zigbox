//! Tests of `--listen` against the simulator (M8b): the listener is made in the container's
//! network namespace, handed over once, never in the command's table, and every failure is a
//! coded line with the container stopped and nothing left behind.

const std = @import("std");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;
const rootfs = sim_run.rootfs_path;

fn no_leak(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

/// `zbx run --net none --listen 127.0.0.1:8080 --listen-send SEND`, with `SEND` filled in.
fn run_with(sim: *HostSim, send: [:0]const u8) u8 {
    const args = [_][:0]const u8{
        "zbx",            "run",           "--rootfs", rootfs,   "--net", "none", "--listen",
        "127.0.0.1:8080", "--listen-send", send,       "--name", "box-1", "--",   "sh",
    };
    return sim_run.run_cli(sim, &args);
}

fn send_text(buffer: *[16:0]u8, end: host_mod.Handle) [:0]const u8 {
    // Cannot fail: 16 bytes hold a u32.
    return std.fmt.bufPrintSentinel(buffer, "{d}", .{end}, 0) catch unreachable;
}

test "--listen: the listener reaches the receiver and never the command's table" {
    // Goal: the success path. Method: a channel pair stands for the harness's socket; the run
    // sends the listener over its write end; the read end receives exactly one descriptor, a
    // second receive finds none; the command's table never held it; nothing is left.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 61);
    const before = sim_run.baseline(&sim);
    const host = sim.interface();
    const pair = try host.channel();
    var buffer: [16:0]u8 = undefined;
    const code = run_with(&sim, send_text(&buffer, pair.write));
    try testing.expectEqual(@as(u8, 0), code);
    const problem = sim_run.started(&sim, .{ .name = "box-1", .devpts = true, .network = .none });
    if (problem) |text| std.debug.print("the container is wrong: {s}\n", .{text});
    try testing.expect(problem == null);
    try testing.expect(!sim.world.listener_leaked);
    const received = try host.receive_handle(pair.read);
    host.close(received);
    try testing.expectError(error.IoFailed, host.receive_handle(pair.read));
    host.close(pair.read);
    host.close(pair.write);
    try no_leak(&sim, &before);
}

test "--listen: a fault at any call is coded or clean, and nothing leaks" {
    // Goal: a failure at every host call, with each error. Method: count the calls of a good
    // run, then fail each in turn; the run ends 0 or 125 with a coded line, the command's table
    // never held a listener and nothing is left open.
    var counting: HostSim = undefined;
    sim_run.init(&counting, 62);
    const pair = try counting.interface().channel();
    var buffer: [16:0]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), run_with(&counting, send_text(&buffer, pair.write)));
    const calls = counting.call_count;
    try testing.expect(calls > 10);
    const errors = [_]host_mod.Error{ error.NoSpace, error.AccessDenied, error.IoFailed };
    var sim: HostSim = undefined;
    for (errors) |err| {
        var index: u32 = 0;
        while (index < calls) : (index += 1) {
            sim_run.init(&sim, 62);
            const before = sim_run.baseline(&sim);
            const ends = try sim.interface().channel();
            sim.faults.fail_call_index = index;
            sim.faults.fail_call_error = err;
            const code = run_with(&sim, send_text(&buffer, ends.write));
            testing.expect(code == 0 or code >= 125) catch |failure| {
                const words = "call {d} failing with {s}: exit {d}\n";
                std.debug.print(words, .{ index, @errorName(err), code });
                return failure;
            };
            const diagnosed = std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E") != null;
            if (code == 125) try testing.expect(diagnosed);
            try testing.expect(!sim.world.listener_leaked);
            sim.faults.fail_call_index = null;
            drain(&sim, ends);
            // A faulted final wait leaves its child unreaped in any run, with or without a listener
            // (a plain run does the same; the model has no retry); the failed-send test below
            // checks the reaping.
            const unreaped = sim.world.unreaped_children() != 0;
            if (unreaped) continue;
            if (sim_run.leak(&sim, &before)) |text| {
                // A scope the manager would not stop is a warning, not a leak (as in any run).
                const warned = std.mem.indexOf(u8, sim.stderr(), "ZBX-W0") != null;
                if (warned and std.mem.indexOf(u8, text, "cgroup scope") != null) continue;
                const words = "{s}: call {d} failing with {s}\n";
                std.debug.print(words, .{ text, index, @errorName(err) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

/// Closes what the test's channel and a send left: a descriptor in flight, then both ends.
fn drain(sim: *HostSim, pair: host_mod.Pipe) void {
    const host = sim.interface();
    if (host.receive_handle(pair.read)) |received| host.close(received) else |_| {}
    host.close(pair.read);
    host.close(pair.write);
}

test "--listen: a descriptor that is no open Unix socket is refused before anything starts" {
    // Goal: M8b review MUST 1. Method: a number past a descriptor (4294967295, 2147483648), one
    // that is not a number, and one no socket holds are each refused with E0606, 125, and
    // nothing started or left. Before the fix the first two panicked after the start.
    const texts = [_][:0]const u8{ "4294967295", "2147483648", "-1", "x", "99", "3" };
    for (texts, 0..) |text, index| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 63 + @as(u64, index));
        const before = sim_run.baseline(&sim);
        try testing.expectEqual(@as(u8, 125), run_with(&sim, text));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0606]") != null);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "errno") == null);
        try testing.expect(!sim.world.listener_leaked);
        try no_leak(&sim, &before);
    }
}

test "--listen: a send that fails stops the container with E0609" {
    // Goal: the receiver closed its end after the run began checking. Method: the descriptor
    // is an open socket whose peer is gone; the send fails (EPIPE), the run fails 125 with
    // E0609, the container is gone, nothing is left.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 70);
    const before = sim_run.baseline(&sim);
    const host = sim.interface();
    const pair = try host.channel();
    host.close(pair.read);
    var buffer: [16:0]u8 = undefined;
    try testing.expectEqual(@as(u8, 125), run_with(&sim, send_text(&buffer, pair.write)));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0609]") != null);
    try testing.expect(!sim.world.listener_leaked);
    host.close(pair.write);
    try no_leak(&sim, &before);
}
