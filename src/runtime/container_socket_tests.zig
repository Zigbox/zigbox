//! `zigbox.container_socket` (Zigcube's ZB-5) in the simulator: a worker that did not start the
//! container makes sockets in its network namespace. The VM (`demo-c4`) shows the real thing:
//! a listener on 127.77.x.y that a process inside reaches. Here the model says which network
//! namespace each socket was made in, and the tests check the helper's steps, its reaping and
//! that nothing is left open.

const std = @import("std");
const host_mod = @import("../host.zig");
const codes = @import("../diag/codes.zig");
const container_socket = @import("container_socket.zig");
const exec = @import("exec.zig");
const lifecycle = @import("lifecycle.zig");
const host_sim = @import("../host_sim.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");
const spec = @import("spec.zig");
const Diag = @import("../diag/diag.zig").Diag;

const HostSim = host_sim.HostSim;
const testing = std.testing;

var supervisor_handle: run.Handle = undefined;

/// The supervisor's start of `web`, detached, with the network `network`; its handle is dropped,
/// so the worker below knows the container only by its record, as a restarted agent would.
fn supervisor_starts(sim: *HostSim, seed: u64, network: spec.Network) !void {
    return supervisor_starts_into(sim, seed, network, &supervisor_handle);
}

fn supervisor_starts_into(
    sim: *HostSim,
    seed: u64,
    network: spec.Network,
    handle: *run.Handle,
) !void {
    sim_run.init(sim, seed);
    sim.world.add_node(sim_run.home_path, .dir);
    sim.world.command_runs_ms = 60_000;
    var diag: Diag = undefined;
    diag.reset();
    const container: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web",
        .command = &.{"/bin/sh"},
        .network = network,
    };
    try run.start(sim.interface(), &container, .{ .detached = true }, handle, &diag);
    handle.* = undefined;
}

fn make(sim: *HostSim, diag: *Diag) container_socket.Error!u32 {
    std.debug.assert(diag.code == null);
    return container_socket.open(sim.interface(), "web", .tcp4, diag);
}

test "a socket is made in the container's network namespace and nothing is left" {
    // Goal: ZB-5's main case. Method: a worker makes three sockets in turn, closing each; each
    // was made in the container's namespace, not the host's, the helper is reaped each time,
    // and the worker holds nothing after the last close.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 71, .none);
    const children = sim.world.unreaped_children();
    var diag: Diag = undefined;
    for (0..3) |_| {
        diag.reset();
        const socket = try make(&sim, &diag);
        try testing.expect(sim.world.made_in_container_net(socket));
        try testing.expectEqual(@as(u32, 1), sim.world.open_listeners());
        try testing.expectEqual(children, sim.world.unreaped_children());
        sim.interface().close(socket);
        try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
    }
    try testing.expect(sim.world.current == 0);
}

test "sockets made together are all the worker's until it closes them" {
    // Goal: no cap in Zigbox: each socket is one descriptor of the caller's. Method: hold as
    // many as the model has slots for at once, then close them all.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 72, .none);
    var diag: Diag = undefined;
    var held: [3]u32 = undefined;
    for (&held) |*socket| {
        diag.reset();
        socket.* = try make(&sim, &diag);
    }
    try testing.expect(held[0] != held[1]);
    try testing.expect(held[1] != held[2]);
    for (held) |socket| sim.interface().close(socket);
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
}

test "a container on the host's network is refused with E0610" {
    // Goal: a socket "in" a --net host container would be the host's. Method: start one with
    // `host`; the call is refused before any helper is forked, with one coded line.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 73, .host);
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.SocketFailed, make(&sim, &diag));
    try testing.expectEqual(codes.Code.E0610, diag.code.?);
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
}

test "a container on pasta's network (--net user) is refused with E0610" {
    // Goal: a socket in a --net user container would be on pasta's network, which Zigcube's
    // mesh does not route; it is refused rather than made there. Method: start one with
    // `user`; the call is refused before any helper is forked, with one coded line naming the
    // network.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 80, .user);
    const children = sim.world.unreaped_children();
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.SocketFailed, make(&sim, &diag));
    try testing.expectEqual(codes.Code.E0610, diag.code.?);
    var found = false;
    for (diag.pairs.slice()) |pair| {
        if (!std.mem.eql(u8, pair.key_slice(), "net")) continue;
        found = std.mem.eql(u8, pair.value.slice(), "user");
    }
    try testing.expect(found);
    try testing.expectEqual(children, sim.world.unreaped_children());
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
}

test "an unknown or ended container is refused with E0402 or E0220" {
    // Goal: the lookup is exec's. Method: a name with no record gets E0402; once PID 1 is
    // killed, `web` gets E0220. Neither forks a helper.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 74, .none);
    var diag: Diag = undefined;
    diag.reset();
    const other = container_socket.open(sim.interface(), "nope", .tcp4, &diag);
    try testing.expectError(error.SocketFailed, other);
    try testing.expectEqual(codes.Code.E0402, diag.code.?);
    // The container's PID 1 ends: `web` is stopped, and the helper is not forked for it.
    const container = sim.world.processes[1].pid;
    try testing.expect(sim.world.kill(container, 9) == null);
    diag.reset();
    try testing.expectError(error.SocketFailed, make(&sim, &diag));
    try testing.expectEqual(codes.Code.E0220, diag.code.?);
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
}

test "a pid reused between the lookup and the namespace opens is E0220, not a stranger's socket" {
    // Goal: the recheck after `open_namespace`. Method: the lookup finds `web` running; at the
    // first namespace open its PID 1 has ended and an ordinary host process holds the pid, in
    // namespaces of its own. The opens succeed (they name the stranger's namespaces), so only
    // the recheck can tell; the call must be E0220, fork no helper and leave nothing open.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 81, .none);
    const children = sim.world.unreaped_children();
    const slots_before = used_process_slots(&sim);
    const open_before = sim.open_count();
    sim.world.reuse_pid_at_open = sim.world.processes[1].pid;
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.SocketFailed, make(&sim, &diag));
    try testing.expectEqual(codes.Code.E0220, diag.code.?);
    // The hook fired: the opens ran against the reused pid.
    try testing.expect(sim.world.reuse_pid_at_open == null);
    try testing.expectEqual(children, sim.world.unreaped_children());
    try testing.expectEqual(slots_before, used_process_slots(&sim));
    try testing.expectEqual(open_before, sim.open_count());
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
    for (sim.world.namespace_handles) |entry| try testing.expect(entry == null);
}

/// Process slots in use: a forked helper takes one and keeps it until it is reaped and gone.
fn used_process_slots(sim: *const HostSim) u32 {
    var count: u32 = 0;
    for (&sim.world.processes) |*process| {
        if (process.state != .unused) count += 1;
    }
    return count;
}

test "every step of the helper failing is E0611, names the step, and leaks nothing" {
    // Goal: the helper's four steps. Method: fail the first call of each step in turn with
    // EPERM; the call is E0611, the diagnostic names the step, the helper is reaped, and the
    // worker holds no socket.
    var sim: HostSim = undefined;
    const names = [_][]const u8{ "join_user", "join_net", "make_socket", "send_socket" };
    for (names, 0..) |name, step| {
        try supervisor_starts(&sim, 75, .none);
        const children = sim.world.unreaped_children();
        sim.faults.fail_step = @intCast(step);
        sim.faults.fail_step_errno = 1;
        var diag: Diag = undefined;
        diag.reset();
        try testing.expectError(error.SocketFailed, make(&sim, &diag));
        try testing.expectEqual(codes.Code.E0611, diag.code.?);
        var found = false;
        for (diag.pairs.slice()) |pair| {
            if (!std.mem.eql(u8, pair.key_slice(), "step")) continue;
            found = std.mem.eql(u8, pair.value.slice(), name);
        }
        try testing.expect(found);
        try testing.expectEqual(children, sim.world.unreaped_children());
        try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
    }
}

test "a fault at any host call is one coded diagnostic or a socket, and nothing leaks" {
    // Goal: every exit path. Method: count the calls of a good run, then fail each in turn with
    // each error; the call either returns a socket or fails with a coded diagnostic, and the
    // worker holds no socket, no descriptor of the call's and no zombie afterwards: a faulted
    // wait is tried again, so the helper is reaped on every path.
    var counting: HostSim = undefined;
    try supervisor_starts(&counting, 76, .none);
    const first = counting.call_count;
    var diag: Diag = undefined;
    diag.reset();
    const good = try make(&counting, &diag);
    counting.interface().close(good);
    const calls = counting.call_count - first;
    try testing.expect(calls > 5);
    const errors = [_]host_mod.Error{ error.NoSpace, error.AccessDenied, error.IoFailed };
    var sim: HostSim = undefined;
    for (errors) |err| {
        for (0..calls) |index| {
            try supervisor_starts(&sim, 76, .none);
            const children = sim.world.unreaped_children();
            const open_before = sim.open_count();
            sim.faults.fail_call_index = sim.call_count + @as(u32, @intCast(index));
            sim.faults.fail_call_error = err;
            diag.reset();
            if (make(&sim, &diag)) |socket| {
                sim.interface().close(socket);
            } else |_| {
                try testing.expect(diag.code != null);
            }
            sim.faults.fail_call_index = null;
            try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
            try testing.expectEqual(open_before, sim.open_count());
            try testing.expectEqual(children, sim.world.unreaped_children());
        }
    }
}

var worker_handle: exec.Handle = undefined;

/// The call a worker makes: no terminal, no history entry, a handle of its own.
fn worker_execs(sim: *HostSim, diag: *Diag) exec.Error!void {
    std.debug.assert(diag.code == null);
    const command: exec.Spec = .{ .name = "web", .command = &.{"/bin/sh"}, .terminal = false };
    const options: exec.Options = .{ .keep_history = false };
    return exec.start(sim.interface(), &command, options, &worker_handle, diag);
}

test "exec joins the network namespace of a --net none container, with its loopback up (ZB-7)" {
    // Goal: ZB-7, what Zigcube's per-replica probes rely on: a command from `exec` sees the
    // container's own loopback, so `wget 127.0.0.1:P` reaches the container's listener and not
    // the host's. Method: start `web` with `none`; the exec'd command's process is in a new
    // network namespace with `lo` up; for a `--net host` container it joins none (the host's
    // network is the container's, so there is nothing to join). The VM (demo-c4) runs `ip addr`
    // and `wget 127.0.0.1` for real.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 77, .none);
    var diag: Diag = undefined;
    diag.reset();
    try worker_execs(&sim, &diag);
    const inside = sim.world.find_process(worker_handle.pid.?).?;
    try testing.expect(inside.new_net);
    try testing.expect(inside.loopback_up);
    _ = exec.wait(&worker_handle);
    try supervisor_starts(&sim, 78, .host);
    diag.reset();
    try worker_execs(&sim, &diag);
    try testing.expect(!sim.world.find_process(worker_handle.pid.?).?.new_net);
    _ = exec.wait(&worker_handle);
}

test "a socket outlives the supervisor's handle and an adoption by a restarted agent (ZB-8)" {
    // Goal: ZB-8: the socket is a descriptor of the caller's, not state of the agent's. Method:
    // make a socket, drop the starter's `run.Handle` (done in `supervisor_starts`), adopt the
    // container by name as a restarted agent does; the socket is still open and still the
    // container's, a second one is made after the adoption, and closing the first leaves the
    // second.
    var sim: HostSim = undefined;
    try supervisor_starts(&sim, 79, .none);
    var diag: Diag = undefined;
    diag.reset();
    const before = try make(&sim, &diag);
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    try lifecycle.adopt(sim.interface(), "web", &ref, &state);
    try testing.expectEqual(lifecycle.State.running, state);
    try testing.expect(sim.world.made_in_container_net(before));
    try testing.expectEqual(@as(u32, 1), sim.world.open_listeners());
    diag.reset();
    const after = try make(&sim, &diag);
    try testing.expect(sim.world.made_in_container_net(after));
    try testing.expectEqual(@as(u32, 2), sim.world.open_listeners());
    sim.interface().close(before);
    try testing.expectEqual(@as(u32, 1), sim.world.open_listeners());
    sim.interface().close(after);
    try testing.expectEqual(@as(u32, 0), sim.world.open_listeners());
}

/// One worker thread of a supervisor: a simulator (its own host), the container's handle while
/// it starts, and what went wrong, if anything.
const Worker = struct {
    sim: HostSim,
    handle: run.Handle,
    failed: bool,
};

const workers_count = 4;
const worker_rounds = 8;
const worker_options: std.Thread.SpawnConfig = .{ .stack_size = 256 * 1024 };
var workers: [workers_count]Worker = undefined;

fn worker_main(worker: *Worker, seed: u64) void {
    var diag: Diag = undefined;
    for (0..worker_rounds) |round| {
        supervisor_starts_into(&worker.sim, seed + round, .none, &worker.handle) catch {
            worker.failed = true;
            return;
        };
        const children = worker.sim.world.unreaped_children();
        const open_before = worker.sim.open_count();
        diag.reset();
        const socket = make(&worker.sim, &diag) catch {
            worker.failed = true;
            return;
        };
        if (!worker.sim.world.made_in_container_net(socket)) worker.failed = true;
        if (worker.sim.world.unreaped_children() != children) worker.failed = true;
        worker.sim.interface().close(socket);
        if (worker.sim.world.open_listeners() != 0) worker.failed = true;
        if (worker.sim.open_count() != open_before) worker.failed = true;
    }
}

test "many threads make sockets at the same time, each with a host of its own (ZB-5)" {
    // Goal: brief slice 1's multi-threaded caller: `container_socket` keeps no module-level
    // state, so threads of one process, each with a `Host` of its own (the contract's rule),
    // call it at once. Method: four threads each start a container and make, check and close
    // a socket in it, many times, against a simulator of their own; a shared static, or a
    // result that is another thread's, fails it. The VM (demo-c4) runs the real call from two
    // threads of the supervisor at once.
    for (&workers) |*worker| worker.failed = false;
    var threads: [workers_count]std.Thread = undefined;
    for (&threads, &workers, 0..) |*thread, *worker, index| {
        const seed: u64 = 1000 + 100 * @as(u64, index);
        thread.* = try std.Thread.spawn(worker_options, worker_main, .{ worker, seed });
    }
    for (threads) |thread| thread.join();
    for (workers) |worker| try testing.expect(!worker.failed);
}
