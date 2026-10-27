//! The D-Bus client against the simulator's bus (src/sim_bus.zig): every way the conversation
//! with the user's systemd can go, and the failure it leaves in `Connection.failure`. What these
//! tests cannot show is that the simulator and a real bus agree; `zig build dbus-live` runs the
//! same client against a real `dbus-daemon`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const client = @import("client.zig");
const host_mod = @import("../host.zig");
const HostSim = @import("../host_sim.zig").HostSim;
const sim_bus = @import("../sim_bus.zig");
const systemd = @import("systemd.zig");

const testing = std.testing;
const bus_path = "/run/user/1000/bus";

const Session = struct {
    sim: HostSim,
    connection: client.Connection,

    fn start(session: *Session) void {
        session.sim.init(1, &.{});
        session.connection.init(session.sim.interface());
    }

    /// Connect, authenticate and say Hello.
    fn open(session: *Session) client.CallError!void {
        const connection = &session.connection;
        try connection.connect(bus_path);
        try connection.authenticate(1000);
        try connection.hello();
    }
};

fn expect_failure(session: *const Session, kind: client.FailureKind, stage: client.Stage) !void {
    try testing.expectEqual(kind, session.connection.failure.kind);
    try testing.expectEqual(stage, session.connection.failure.stage);
}

fn start_a(session: *Session) client.CallError!void {
    return systemd.start_scope(&session.connection, &scope_request("zbx-a.scope", 5));
}

fn scope_request(name: []const u8, pid: u32) systemd.ScopeRequest {
    return .{
        .name = name,
        .description = "zbx: test",
        .pid = pid,
        .keeper_pid = pid + 1,
        .slice = "app.slice",
        .memory_max = 128 * 1024 * 1024,
        .memory_swap_zero = true,
        .tasks_max = 64,
        .cpu_quota_usec = 500_000,
    };
}

test "Hello, the manager's version, and a scope with its limits" {
    // Goal: the whole successful conversation: connect, authenticate, Hello (and the
    // NameAcquired signal after it, which is dropped), Version, StartTransientUnit and the wait
    // for JobRemoved. The model then holds the scope with the properties that were sent.
    var session: Session = undefined;
    session.start();
    try session.open();
    var version: systemd.Version = undefined;
    try systemd.read_version(&session.connection, &version);
    try testing.expectEqual(@as(u32, 255), version.number);
    try testing.expectEqualStrings("255.4-1ubuntu8.4", version.text.slice());
    try systemd.start_scope(&session.connection, &scope_request("zbx-web.scope", 777));
    const scope = session.sim.world.bus.find_scope("zbx-web.scope").?;
    try testing.expectEqual(@as(u32, 777), scope.pid);
    try testing.expect(scope.delegate);
    try testing.expectEqualStrings("app.slice", scope.slice.slice());
    try testing.expectEqual(@as(?u64, 128 * 1024 * 1024), scope.memory_max);
    try testing.expectEqual(@as(?u64, 0), scope.memory_swap_max);
    try testing.expectEqual(@as(?u64, 64), scope.tasks_max);
    try testing.expectEqual(@as(?u64, 500_000), scope.cpu_quota_usec);
    try testing.expectEqual(@as(u32, 4), scope.accounting);
    session.connection.close();
    try testing.expectEqual(@as(u32, 0), session.sim.open_count());
}

test "a bus that is not there, refuses, or is somewhere else is a connect failure" {
    // Goal: no_bus for each way a socket can be unusable, with the errno of the kernel.
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.present = false;
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .no_bus, .connect);
    try testing.expectEqual(@as(u16, 2), session.connection.failure.errno);

    session.start();
    session.sim.world.bus.model.refuses = true;
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .no_bus, .connect);
    try testing.expectEqual(@as(u16, 111), session.connection.failure.errno);

    session.start();
    session.sim.world.bus.model.socket_path = "/elsewhere/bus";
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .no_bus, .connect);
    try testing.expectEqual(@as(u32, 0), session.sim.open_count());
}

test "a bus that does not accept the user, or answers with something else" {
    // Goal: auth_refused carries the line the bus sent, for the diagnostic.
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.auth = .reject;
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .auth_refused, .auth);
    try testing.expectEqualStrings("REJECTED EXTERNAL", session.connection.failure.name.slice());
    session.connection.close();

    session.start();
    session.sim.world.bus.model.auth = .other;
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .auth_refused, .auth);
    session.connection.close();
    try testing.expectEqual(@as(u32, 0), session.sim.open_count());
}

test "Hello refused is a remote error from the bus" {
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.hello_error = "org.freedesktop.DBus.Error.AccessDenied";
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .remote, .hello);
    try testing.expectEqualStrings(
        "org.freedesktop.DBus.Error.AccessDenied",
        session.connection.failure.name.slice(),
    );
    try testing.expectEqualStrings("Connection refused", session.connection.failure.text.slice());
    session.connection.close();
}

test "no systemd on the bus is ServiceUnknown, and a taken scope name is UnitExists" {
    // Goal: the two remote errors the callers tell apart, by name.
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.systemd_present = false;
    try session.open();
    var version: systemd.Version = undefined;
    try testing.expectError(error.Failed, systemd.read_version(&session.connection, &version));
    try expect_failure(&session, .remote, .call);
    const unknown = "org.freedesktop.DBus.Error.ServiceUnknown";
    try testing.expectEqualStrings(unknown, session.connection.failure.name.slice());
    session.connection.close();

    session.start();
    session.sim.world.bus.model.unit_taken = true;
    try session.open();
    try testing.expectError(error.Failed, start_a(&session));
    try testing.expectEqualStrings(
        "org.freedesktop.systemd1.UnitExists",
        session.connection.failure.name.slice(),
    );
    try testing.expectEqual(@as(u32, 0), session.sim.world.bus.scope_count());
    session.connection.close();
}

test "a unit systemd refuses, and a job that does not end in done" {
    // Goal: a refusal is remote at the call; a failed job is remote at the job stage, with its
    // result as the name, and leaves no scope.
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.start_error = "org.freedesktop.DBus.Error.AccessDenied";
    try session.open();
    try testing.expectError(error.Failed, start_a(&session));
    try expect_failure(&session, .remote, .call);
    session.connection.close();

    session.start();
    session.sim.world.bus.model.job_result = "failed";
    try session.open();
    try testing.expectError(error.Failed, start_a(&session));
    try expect_failure(&session, .remote, .job);
    try testing.expectEqualStrings("failed", session.connection.failure.name.slice());
    try testing.expectEqual(@as(u32, 0), session.sim.world.bus.scope_count());
    session.connection.close();
}

test "a JobRemoved that never comes is a timeout, bounded in poll steps" {
    // Goal: the wait ends. Method: the model sends the reply and no signal.
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.job_removed = false;
    try session.open();
    try testing.expectError(error.Failed, start_a(&session));
    try expect_failure(&session, .timeout, .job);
    session.connection.close();
}

test "a bus that misbehaves is a protocol failure, a timeout or a hang-up, never a crash" {
    // Goal: each Misbehaviour, on the Hello call (call 0) and on Version (call 1), ends the call
    // with a failure of the right kind and no descriptor left open.
    const cases = [_]struct { how: sim_bus.Misbehaviour, kind: client.FailureKind }{
        .{ .how = .garbage_reply, .kind = .protocol },
        .{ .how = .oversized_reply, .kind = .protocol },
        .{ .how = .truncated_reply, .kind = .protocol },
        .{ .how = .hang_up, .kind = .protocol },
        .{ .how = .silent, .kind = .timeout },
    };
    for (cases) |case| {
        var session: Session = undefined;
        session.start();
        session.sim.world.bus.model.misbehave = .{ .at_call = 0, .how = case.how };
        try testing.expectError(error.Failed, session.open());
        try expect_failure(&session, case.kind, .hello);
        session.connection.close();
        try testing.expectEqual(@as(u32, 0), session.sim.open_count());
    }
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.misbehave = .{ .at_call = 0, .how = .wrong_serial };
    try testing.expectError(error.Failed, session.open());
    try expect_failure(&session, .timeout, .hello); // The reply it waits for never comes.
    session.connection.close();
}

test "short reads from the socket do not change the conversation" {
    // Goal: messages arrive in pieces on a real socket; the client reassembles them.
    var session: Session = undefined;
    session.start();
    session.sim.faults.short_read_per_mille = 1000;
    try session.open();
    var version: systemd.Version = undefined;
    try systemd.read_version(&session.connection, &version);
    try systemd.start_scope(&session.connection, &scope_request("zbx-b.scope", 9));
    try testing.expectEqual(@as(u32, 1), session.sim.world.bus.scope_count());
    session.connection.close();
}

test "a failed write or read on the socket is an io failure" {
    // Goal: the host's error is kept with its errno.
    var session: Session = undefined;
    session.start();
    session.sim.faults.write_error_per_mille = 0;
    session.sim.faults.fail_call_index = 3; // The AUTH write: connect is call 0.
    session.sim.faults.fail_call_error = error.AccessDenied;
    try testing.expectError(error.Failed, session.open());
    try testing.expectEqual(client.FailureKind.io, session.connection.failure.kind);
    try testing.expectEqual(host_mod.Error.AccessDenied, session.connection.failure.err);
    session.connection.close();
}

test "the job signal reaches only a connection that subscribed" {
    // Goal: the client does not rely on systemd telling the creator of a job. Method: the model
    // sends JobRemoved only to a subscriber; a start with the subscription skipped waits for a
    // signal that never comes (a timeout at the job stage), and the real start works and ends
    // unsubscribed.
    var session: Session = undefined;
    session.start();
    try session.open();
    const connection = &session.connection;
    try connection.add_match("type='signal',member='JobRemoved'"); // The rule alone is not enough.
    var body: [2048]u8 = undefined;
    const request = scope_request("zbx-a.scope", 5);
    const marshalled = try systemd.marshal_scope(&body, &request);
    const reply = try connection.call(.{
        .destination = "org.freedesktop.systemd1",
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "StartTransientUnit",
        .signature = "ssa(sv)a(sa(sv))",
        .body = marshalled,
    }, .call);
    var path_buffer: [96]u8 = undefined;
    var reader = reply.body_reader();
    const job = try reader.object_path();
    @memcpy(path_buffer[0..job.len], job);
    try testing.expectError(error.Failed, connection.wait_job(path_buffer[0..job.len]));
    try expect_failure(&session, .timeout, .job);
    session.connection.close();

    session.start();
    try session.open();
    try start_a(&session);
    try testing.expect(!session.sim.world.bus.conns[0].subscribed); // Unsubscribed after.
}

test "a refused Subscribe is a remote failure of the call, before any scope exists" {
    var session: Session = undefined;
    session.start();
    session.sim.world.bus.model.subscribe_error = "org.freedesktop.DBus.Error.AccessDenied";
    try session.open();
    try testing.expectError(error.Failed, start_a(&session));
    try expect_failure(&session, .remote, .call);
    try testing.expectEqual(@as(u32, 0), session.sim.world.bus.scopes_started);
}

test "stopping a scope: gone, stopped by the job, refused, or its job failing" {
    // Goal: StopUnit's four outcomes. A unit the manager does not know is the good one.
    var session: Session = undefined;
    session.start();
    try session.open();
    try systemd.watch_jobs(&session.connection);
    const connection = &session.connection;
    const unknown = try systemd.stop_scope(connection, "zbx-x.scope");
    try testing.expectEqual(systemd.Stopped.gone, unknown);
    try start_a(&session);
    try systemd.watch_jobs(connection);
    const stopped = try systemd.stop_scope(connection, "zbx-a.scope");
    try testing.expectEqual(systemd.Stopped.stopped, stopped);
    try testing.expect(session.sim.world.bus.find_scope("zbx-a.scope") == null);
    try start_a(&session);
    try systemd.watch_jobs(connection);
    session.sim.world.bus.model.stop_error = "org.freedesktop.DBus.Error.AccessDenied";
    try testing.expectError(error.Failed, systemd.stop_scope(connection, "zbx-a.scope"));
    try expect_failure(&session, .remote, .call);
    session.sim.world.bus.model.stop_error = null;
    session.sim.world.bus.model.stop_result = "canceled";
    try testing.expectError(error.Failed, systemd.stop_scope(connection, "zbx-a.scope"));
    try expect_failure(&session, .remote, .job);
    try testing.expect(session.sim.world.bus.find_scope("zbx-a.scope") != null);
}
