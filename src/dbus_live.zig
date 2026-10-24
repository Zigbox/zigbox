//! `zig build dbus-live`: the D-Bus client against a real bus, to prove that what the simulator
//! accepts a real `dbus-daemon` accepts too. It is a build-host tool, not part of `zbx` and not
//! part of `zig build test` (which never depends on the host): start a private bus and run it
//! inside, as in
//!
//!     dbus-run-session -- zig build dbus-live
//!
//! What it does, in order, each step printing what it saw:
//!   1. connects to $DBUS_SESSION_BUS_ADDRESS, authenticates with EXTERNAL, says Hello;
//!   2. calls `GetId` and `ListNames` (a string and an array reply);
//!   3. adds a match rule, takes a name with `RequestName` and reads the `NameAcquired` and
//!      `NameOwnerChanged` signals the bus sends for it: a method call, AddMatch and signals;
//!   4. sends `StartTransientUnit` and `Properties.Get(Version)` to `org.freedesktop.systemd1`,
//!      which a plain bus does not have: the daemon validates the marshalling of what it routes,
//!      so `ServiceUnknown` (and not a dropped connection) means the bytes are well-formed;
//!   5. waits for a `JobRemoved` signal that a second connection emits: the job wait.
//! Any surprise is a failed assertion or a nonzero exit.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const auth = @import("dbus/auth.zig");
const client = @import("dbus/client.zig");
const host_real = @import("host_real.zig");
const message_mod = @import("dbus/message.zig");
const systemd = @import("dbus/systemd.zig");
const wire = @import("dbus/wire.zig");

var out: *std.Io.Writer = undefined;

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &buffer);
    out = &file_writer.interface;
    defer out.flush() catch {};
    var real: host_real.HostReal = .{ .environ = init.minimal.environ };
    const host = real.interface();
    const variable = "DBUS_SESSION_BUS_ADDRESS";
    const address = host.environment(variable, constants.dbus_address_bytes_max) orelse {
        try out.print("dbus-live: no bus: run `dbus-run-session -- zig build dbus-live`\n", .{});
        return 2;
    };
    var path_buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    const path = try auth.socket_path(&path_buffer, address);
    try out.print("dbus-live: bus at {s}\n", .{path});
    const uid = host.uid();

    var first: client.Connection = undefined;
    first.init(host);
    try open(&first, path, uid);
    var second: client.Connection = undefined;
    second.init(host);
    try open(&second, path, uid);
    try step_calls(&first);
    try step_name_and_signals(&first, &second);
    try step_systemd_missing(&first);
    try step_job_wait(&first, &second);
    try step_malformed_dropped(host, path, uid);
    first.close();
    second.close();
    try out.print("dbus-live: all steps passed\n", .{});
    assert(real.open_count == 0);
    return 0;
}

fn open(conn: *client.Connection, path: []const u8, uid: u32) !void {
    conn.connect(path) catch return report(conn, "connect");
    conn.authenticate(uid) catch return report(conn, "authenticate");
    conn.hello() catch return report(conn, "hello");
    try out.print("dbus-live: connected, authenticated, Hello answered\n", .{});
}

fn report(conn: *const client.Connection, what: []const u8) error{LiveFailed} {
    const failure = &conn.failure;
    out.print("dbus-live: {s} failed: {s} at {s}; name={s} text={s} wire={any}\n", .{
        what,
        @tagName(failure.kind),
        @tagName(failure.stage),
        failure.name.slice(),
        failure.text.slice(),
        failure.wire,
    }) catch {};
    return error.LiveFailed;
}

const bus_destination = "org.freedesktop.DBus";

fn bus_call(member: []const u8, signature: []const u8, body: []const u8) client.Call {
    return .{
        .destination = bus_destination,
        .path = "/org/freedesktop/DBus",
        .interface = bus_destination,
        .member = member,
        .signature = signature,
        .body = body,
    };
}

/// GetId returns a string; ListNames an array of strings that includes the bus itself and us.
fn step_calls(conn: *client.Connection) !void {
    const id = conn.call(bus_call("GetId", "", ""), .call) catch return report(conn, "GetId");
    var reader = id.body_reader();
    const text = try reader.string();
    assert(std.mem.eql(u8, id.signature, "s"));
    assert(text.len > 0);
    try out.print("dbus-live: GetId -> {s}\n", .{text});
    const names = conn.call(bus_call("ListNames", "", ""), .call) catch
        return report(conn, "ListNames");
    assert(std.mem.eql(u8, names.signature, "as"));
    var list = names.body_reader();
    const end = try list.array_begin(4);
    var count: u32 = 0;
    var saw_bus = false;
    while (list.at < end) : (count += 1) {
        const name = try list.string();
        if (std.mem.eql(u8, name, bus_destination)) saw_bus = true;
        assert(count < 4096);
    }
    assert(saw_bus);
    try out.print("dbus-live: ListNames -> {d} names, the bus among them\n", .{count});
}

/// The first connection matches NameOwnerChanged; the second takes a name; the first reads the
/// signals the bus sends for it. (A signal that arrives while a call waits for its reply is
/// dropped by the call, so the receiver makes no call of its own meanwhile.)
fn step_name_and_signals(conn: *client.Connection, other: *client.Connection) !void {
    conn.add_match("type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'") catch
        return report(conn, "AddMatch");
    var body_buffer: [128]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    writer.string("org.zbx.LiveTest");
    writer.uint32(0);
    const reply = other.call(bus_call("RequestName", "su", try writer.finish()), .call) catch
        return report(other, "RequestName");
    var result = reply.body_reader();
    const code = try result.uint32();
    assert(code == 1); // DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER.
    try out.print("dbus-live: RequestName -> primary owner\n", .{});
    var budget = client.Budget.for_timeout(constants.dbus_call_timeout_ms);
    var seen: u32 = 0;
    while (true) : (seen += 1) {
        assert(seen < 16);
        const message = conn.next_message(.call, &budget) catch return report(conn, "signal");
        if (message.kind != .signal) continue;
        if (!std.mem.eql(u8, message.member.?, "NameOwnerChanged")) continue;
        var args = message.body_reader();
        const name = args.string() catch continue;
        if (!std.mem.eql(u8, name, "org.zbx.LiveTest")) continue;
        break;
    }
    try out.print("dbus-live: signal NameOwnerChanged received for the new name\n", .{});
}

/// A bus without systemd: both systemd calls must come back as ServiceUnknown.
fn step_systemd_missing(conn: *client.Connection) !void {
    var version: systemd.Version = undefined;
    if (systemd.read_version(conn, &version)) |_| {
        return error.LiveFailed; // There is a systemd on this bus: not the test's premise.
    } else |_| {}
    try expect_remote(conn, "Version");
    const request: systemd.ScopeRequest = .{
        .name = "zbx-live.scope",
        .description = "zbx: live",
        .pid = 4242,
        .slice = "app.slice",
        .memory_max = 128 * 1024 * 1024,
        .memory_swap_zero = true,
        .tasks_max = 64,
        .cpu_quota_usec = 500_000,
    };
    if (systemd.start_scope(conn, &request)) |_| return error.LiveFailed else |_| {}
    try expect_remote(conn, "StartTransientUnit");
}

/// The bus answered with an error of its own (ServiceUnknown, or a failed activation where a
/// service file names systemd1): it parsed the message and routed it. A malformed message would
/// have ended the connection or come back as a protocol error.
fn expect_remote(conn: *const client.Connection, what: []const u8) !void {
    const name = conn.failure.name.slice();
    const from_bus = std.mem.startsWith(u8, name, "org.freedesktop.DBus.Error.");
    const invalid = std.mem.eql(u8, name, "org.freedesktop.DBus.Error.InvalidArgs");
    if (conn.failure.kind != .remote or !from_bus or invalid) return report(conn, what);
    try out.print("dbus-live: {s} was routed by the bus: {s}\n", .{ what, name });
}

/// The second connection emits a JobRemoved signal; the first, matching it, waits for it.
fn step_job_wait(waiter: *client.Connection, emitter: *client.Connection) !void {
    const rule = "type='signal',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'";
    waiter.add_match(rule) catch return report(waiter, "AddMatch JobRemoved");
    var body_buffer: [256]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    writer.uint32(77);
    writer.object_path("/org/freedesktop/systemd1/job/77");
    writer.string("zbx-live.scope");
    writer.string("done");
    var bytes_buffer: [512]u8 = undefined;
    const bytes = try message_mod.encode(&bytes_buffer, .{
        .kind = .signal,
        .serial = 9000,
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "JobRemoved",
        .signature = "uoss",
        .body = try writer.finish(),
    });
    try emitter.host.write_handle_all(emitter.handle, bytes);
    const result = waiter.wait_job("/org/freedesktop/systemd1/job/77") catch
        return report(waiter, "wait_job");
    assert(std.mem.eql(u8, result, "done"));
    try out.print("dbus-live: JobRemoved received through the match, result {s}\n", .{result});
}

/// The control for step 4: a body whose first string claims more bytes than the message has is
/// not routed. The bus disconnects the client, which is how a real bus treats a malformed
/// message, so "was routed" above means something.
fn step_malformed_dropped(host: @import("host.zig").Host, path: []const u8, uid: u32) !void {
    var conn: client.Connection = undefined;
    conn.init(host);
    defer conn.close();
    try open(&conn, path, uid);
    var body_buffer: [2048]u8 = undefined;
    const good = try systemd.marshal_scope(&body_buffer, &.{
        .name = "zbx-live.scope",
        .description = "zbx: live",
        .pid = 4242,
        .slice = null,
        .memory_max = null,
        .memory_swap_zero = false,
        .tasks_max = null,
        .cpu_quota_usec = null,
    });
    std.mem.writeInt(u32, body_buffer[0..4], 0x7fff, .little); // The name's length.
    if (conn.call(.{
        .destination = "org.freedesktop.systemd1",
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "StartTransientUnit",
        .signature = "ssa(sv)a(sa(sv))",
        .body = good,
    }, .call)) |_| {
        return error.LiveFailed; // A malformed message was answered.
    } else |_| {}
    if (conn.failure.kind == .remote) {
        const name = conn.failure.name.slice();
        const invalid = "org.freedesktop.DBus.Error.InvalidArgs";
        if (!std.mem.eql(u8, name, invalid)) return report(&conn, "control");
    }
    const how = @tagName(conn.failure.kind);
    try out.print("dbus-live: a malformed body was not routed ({s})\n", .{how});
}
