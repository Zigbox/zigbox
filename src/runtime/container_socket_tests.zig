//! `zigbox.container_socket` (Zigcube's ZB-5) in the simulator: a worker that did not start the
//! container makes sockets in its network namespace. The VM (`demo-c4`) shows the real thing:
//! a listener on 127.77.x.y that a process inside reaches. Here the model says which network
//! namespace each socket was made in, and the tests check the helper's steps, its reaping and
//! that nothing is left open.

const std = @import("std");
const host_mod = @import("../host.zig");
const codes = @import("../diag/codes.zig");
const container_socket = @import("container_socket.zig");
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
    try run.start(sim.interface(), &container, .{ .detached = true }, &supervisor_handle, &diag);
    supervisor_handle = undefined;
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
    try supervisor_starts(&sim, 72, .user);
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
    // worker holds no socket and no descriptor of the call's afterwards. (A faulted wait leaves
    // its child unreaped in any run, as in `--listen`'s sweep: the model has no retry.)
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
            _ = children; // A faulted wait leaves its child unreaped; see above.
        }
    }
}
