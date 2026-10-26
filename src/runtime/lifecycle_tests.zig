//! The library's lifecycle operations against the simulator: list, adopt, stop, wait for a
//! container another process started, and the changes a watcher reports (docs/briefs/M2-limits.md,
//! slice 4). A container "started by another process" is one this test starts and never waits for
//! until the end: the operations under test only use its record and the kernel's view of it.

const std = @import("std");
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const Diag = @import("../diag/diag.zig").Diag;
const lifecycle = @import("lifecycle.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;

const hour_ms: u32 = 3_600_000;

/// A handle is large; the tests run one at a time.
var handle: run.Handle = undefined;
var entries: [8]lifecycle.Entry = undefined;

fn spec(name: []const u8) run.Spec {
    return .{
        .rootfs = sim_run.rootfs_path,
        .name = name,
        .command = &.{ "/bin/sh", "-c", "sleep 1000" },
        .labels = &.{.{ .key = "zcube.replica", .value = "r-1" }},
    };
}

fn start(sim: *HostSim, name: []const u8) !void {
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &spec(name), .{ .detached = true }, &handle, &diag);
    try testing.expectEqual(run.Status.running, run.inspect(&handle));
}

fn running_sim(seed: u64) HostSim {
    var sim: HostSim = undefined;
    sim_run.init(&sim, seed);
    sim.world.command_runs_ms = hour_ms;
    return sim;
}

test "a running container is listed with its record, labels and pid" {
    // Goal: list() finds a container by its record and checks that it is alive. Method: start
    // one, list: running, with the command, the label, the pid of its PID 1 and its scope.
    var sim = running_sim(1);
    try start(&sim, "web-1");
    const count = try lifecycle.list(sim.interface(), &entries);
    try testing.expectEqual(@as(u32, 1), count);
    const entry = &entries[0];
    try testing.expectEqual(lifecycle.State.running, entry.state);
    try testing.expectEqualStrings("web-1", entry.name());
    const record = &entry.record;
    try testing.expect(record.detached);
    try testing.expectEqual(handle.pid, record.pid);
    try testing.expect(record.pid > 1);
    try testing.expectEqualStrings("zbx-web-1.scope", record.scope_slice());
    try testing.expectEqual(@as(u8, 3), record.command_words);
    try testing.expectEqualStrings("sleep 1000", record.command_word(2));
    try testing.expectEqual(@as(u8, 1), record.labels_count);
    try testing.expectEqualStrings("zcube.replica", record.label(0)[0]);
    try testing.expectEqualStrings("r-1", record.label(0)[1]);
}

test "a container is found again by name and stopped by a process that did not start it" {
    // Goal: re-adoption. The ref comes from the record and the kernel alone; stop signals PID 1
    // by the rule (no handler: SIGKILL at once), the owner reaps it, and the record says how.
    var sim = running_sim(2);
    try start(&sim, "web-1");
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "web-1", &ref, &state);
    try testing.expectEqual(lifecycle.State.running, state);
    try testing.expectEqual(handle.pid, ref.pid);
    const how = try lifecycle.stop(&ref, 1000);
    try testing.expectEqual(lifecycle.Stopped.killed, how);
    // The supervisor's side: it reaps the container and finishes the record.
    const reason = run.wait(&handle);
    try testing.expectEqual(@as(u8, 137), reason.code().?);
    var again: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "web-1", &ref, &again);
    try testing.expectEqual(lifecycle.State.stopped, again);
    try testing.expectEqual(lifecycle.Stopped.already_stopped, try lifecycle.stop(&ref, 1000));
    try testing.expectError(error.NoSuchContainer, lifecycle.adopt(sim.interface(), "nope", &ref, &again));
}

test "a PID 1 that handles SIGTERM gets it and the grace period; one that ignores it is killed after" {
    // Goal: stop's two outcomes with a handler. Method: PID 1 catches TERM and exits on it
    // (graceful), then one that catches it and carries on (killed once the grace is up, which the
    // simulated clock measures).
    var sim = running_sim(3);
    sim.world.command_caught = 1 << 14; // Signal 15.
    sim.world.term_exits = true;
    try start(&sim, "web-1");
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "web-1", &ref, &state);
    try testing.expectEqual(lifecycle.Stopped.graceful, try lifecycle.stop(&ref, 5000));
    try testing.expectEqual(@as(u8, 15), sim.world.received[0]);
    _ = run.wait(&handle);

    var stubborn = running_sim(4);
    stubborn.world.command_caught = 1 << 14;
    try start(&stubborn, "web-1");
    try lifecycle.adopt(stubborn.interface(), "web-1", &ref, &state);
    const began = stubborn.world.now_ms;
    try testing.expectEqual(lifecycle.Stopped.killed, try lifecycle.stop(&ref, 2000));
    try testing.expect(stubborn.world.now_ms - began >= 2000); // It waited the grace out.
    try testing.expectEqual(@as(u8, 15), stubborn.world.received[0]);
    try testing.expectEqual(@as(u8, 9), stubborn.world.received[1]);
    _ = run.wait(&handle);
}

test "a record that says running when nothing is left is lost; one that ended is stopped" {
    var sim = running_sim(5);
    try start(&sim, "web-1");
    // The container and its supervisor vanish without a word (the machine rebooted, say).
    sim.world.processes[1].state = .reaped;
    sim.world.processes[0].state = .reaped;
    const count = try lifecycle.list(sim.interface(), &entries);
    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectEqual(lifecycle.State.lost, entries[0].state);
}

test "a watcher reports a container once when it starts and once when it stops" {
    // Goal: the event stream. Method: poll before anything, after the start, again (nothing
    // new), after the stop (stopped, with the reason from the finished record), and again.
    var sim = running_sim(6);
    var watcher: lifecycle.Watcher = undefined;
    watcher.init();
    var events: [4]lifecycle.Event = undefined;
    const host = sim.interface();
    try testing.expectEqual(@as(u32, 0), try lifecycle.poll(host, &watcher, &entries, &events));
    try start(&sim, "web-1");
    try testing.expectEqual(@as(u32, 1), try lifecycle.poll(host, &watcher, &entries, &events));
    try testing.expectEqual(lifecycle.EventKind.started, events[0].kind);
    try testing.expectEqualStrings("web-1", events[0].name.slice());
    try testing.expectEqual(@as(u32, 0), try lifecycle.poll(host, &watcher, &entries, &events));
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(host, "web-1", &ref, &state);
    _ = try lifecycle.stop(&ref, 100);
    _ = run.wait(&handle);
    try testing.expectEqual(@as(u32, 1), try lifecycle.poll(host, &watcher, &entries, &events));
    try testing.expectEqual(lifecycle.EventKind.stopped, events[0].kind);
    try testing.expectEqual(records.EndReason.signal, events[0].reason);
    try testing.expectEqual(@as(u32, 0), try lifecycle.poll(host, &watcher, &entries, &events));
}

test "a watcher that meets an ended container reports it started and stopped, and is bounded" {
    var sim = running_sim(7);
    try start(&sim, "web-1");
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "web-1", &ref, &state);
    _ = try lifecycle.stop(&ref, 100);
    _ = run.wait(&handle);
    var watcher: lifecycle.Watcher = undefined;
    watcher.init();
    var one: [1]lifecycle.Event = undefined;
    // Two events are due (started, stopped) and one fits: nothing is lost, it comes next time.
    try testing.expectEqual(@as(u32, 0), try lifecycle.poll(sim.interface(), &watcher, &entries, &one));
    var two: [2]lifecycle.Event = undefined;
    try testing.expectEqual(@as(u32, 2), try lifecycle.poll(sim.interface(), &watcher, &entries, &two));
    try testing.expectEqual(lifecycle.EventKind.started, two[0].kind);
    try testing.expectEqual(lifecycle.EventKind.stopped, two[1].kind);
}

test "a scope with no record is listed, named for its scope" {
    var sim = running_sim(8);
    const app = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice";
    sim.world.add_node(app, .dir);
    sim.world.put_raw(app ++ "/zbx-ghost.scope", "x");
    sim.world.put_raw(app ++ "/other.scope", "x");
    const count = try lifecycle.list(sim.interface(), &entries);
    try testing.expectEqual(@as(u32, 1), count);
    try testing.expect(!entries[0].has_record);
    try testing.expectEqualStrings("ghost", entries[0].name());
    try testing.expectEqual(lifecycle.State.running, entries[0].state);
}

test "an identity check refuses a pid that is not a container's PID 1" {
    // Goal: NSpid is read exactly: a host process (one pid), or a nested process that is not
    // PID 1, is not a container.
    try testing.expect(lifecycle.innermost_pid_is_one("Name:\tx\nNSpid:\t4242\t1\n"));
    try testing.expect(lifecycle.innermost_pid_is_one("NSpid:\t4242\t77\t1\n"));
    try testing.expect(!lifecycle.innermost_pid_is_one("NSpid:\t4242\n"));
    try testing.expect(!lifecycle.innermost_pid_is_one("NSpid:\t4242\t7\n"));
    try testing.expect(!lifecycle.innermost_pid_is_one("Name:\tx\n"));
    try testing.expect(!lifecycle.innermost_pid_is_one(""));
}

test "run --timeout stops a container that runs too long: SIGTERM, the grace, SIGKILL" {
    // Goal: the time given to a run. The command would run an hour; with 1000 ms it is sent
    // SIGTERM (which it handles and ignores), and SIGKILL after the 500 ms grace.
    var sim = running_sim(9);
    sim.world.command_caught = 1 << 14;
    var diag: Diag = undefined;
    diag.reset();
    const options: run.StartOptions = .{ .timeout_ms = 1000, .grace_ms = 500 };
    try run.start(sim.interface(), &spec("web-1"), options, &handle, &diag);
    const began = sim.world.now_ms;
    const reason = run.wait(&handle);
    try testing.expect(run.timed_out(&handle));
    try testing.expectEqual(@as(u8, 137), reason.code().?);
    try testing.expect(sim.world.now_ms - began >= 1500);
    try testing.expect(sim.world.now_ms - began < 5000);
    try testing.expectEqual(@as(u8, 15), sim.world.received[0]);
    try testing.expectEqual(@as(u8, 9), sim.world.received[1]);
}

test "a container that ends before its time is not timed out" {
    var sim = running_sim(10);
    sim.world.command_runs_ms = 300;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &spec("web-1"), .{ .timeout_ms = 1000 }, &handle, &diag);
    _ = run.wait(&handle);
    try testing.expect(!run.timed_out(&handle));
    try testing.expectEqual(@as(usize, 0), sim.world.received_count);
}
