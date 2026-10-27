//! The simulator's user bus and systemd: a server for the D-Bus conversation `src/dbus/` has with
//! the user's systemd manager. It speaks the same wire format, built with the same marshaller
//! (so the real `dbus-daemon` check in `zig build dbus-live` is what proves the two agree), and
//! models what the client must handle: an absent bus, a refused user, Hello and AddMatch, the
//! manager's `Version`, `StartTransientUnit` with its job and the `JobRemoved` signal, a taken
//! unit name, a refused unit, a failed job, and a bus that misbehaves.
//!
//! No randomness and no time: a test or fuzzer sets `Model` and the conversation follows. A
//! scope the manager starts is recorded (`Bus.scopes`) for the world to give its cgroup
//! files, and ends when the world says its process is gone.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const auth = @import("dbus/auth.zig");
const message_mod = @import("dbus/message.zig");
const text_util = @import("text.zig");
const wire = @import("dbus/wire.zig");

pub const errno_noent: u16 = 2;
pub const errno_pipe: u16 = 32;
pub const errno_refused: u16 = 111;
pub const errno_access: u16 = 13;

/// What goes wrong with the bus after it has accepted the user, on the call numbered `at_call`
/// (zero-based, counting method calls after authentication).
pub const Misbehaviour = enum {
    /// The reply is bytes that are not a message.
    garbage_reply,
    /// The reply's header claims a body past the size bound.
    oversized_reply,
    /// The reply is cut short and the connection closes.
    truncated_reply,
    /// The connection closes with no reply.
    hang_up,
    /// No reply is ever sent (the client times out).
    silent,
    /// The reply is to a different call than the one made.
    wrong_serial,
};

pub const Model = struct {
    /// The first this many connections get a perfect bus whatever else the model says, so that a
    /// run's probe can succeed and its scope step meet the fault.
    quiet_connections: u32 = 0,
    /// From this connection on (zero-based) the bus is perfect again, so that a fault meets
    /// one connection of a run: the scope step's, and not the cleanup after it.
    perfect_from: ?u32 = null,
    /// The socket exists. False models a user without a session bus.
    present: bool = true,
    /// The socket exists and nothing accepts on it.
    refuses: bool = false,
    /// Where the socket is; null means /run/user/<uid>/bus.
    socket_path: ?[]const u8 = null,
    /// What the server answers to AUTH.
    auth: enum { accept, reject, other } = .accept,
    /// A D-Bus error name Hello answers with, if it refuses the connection.
    hello_error: ?[]const u8 = null,
    /// `org.freedesktop.systemd1` has an owner on this bus.
    systemd_present: bool = true,
    version: []const u8 = "255.4-1ubuntu8.4",
    /// A scope of that name already exists, started by someone else.
    unit_taken: bool = false,
    /// A D-Bus error name `StartTransientUnit` answers with.
    start_error: ?[]const u8 = null,
    /// How the unit's job ends. Anything but "done" leaves no scope.
    job_result: []const u8 = "done",
    /// Whether `JobRemoved` is sent at all (false: the client must time out).
    job_removed: bool = true,
    misbehave: ?struct { at_call: u32, how: Misbehaviour } = null,
    /// When a scope whose last process has gone leaves the manager: at the next time anyone
    /// connects to the bus (a real manager takes a moment, and the cgroup is readable until it
    /// does), at once (the cgroup is gone before the parent can read it), or never (it lingers
    /// until `StopUnit`).
    scope_removal: enum { lazily, promptly, never } = .lazily,
    /// A D-Bus error name `Subscribe` answers with.
    subscribe_error: ?[]const u8 = null,
    /// A D-Bus error name `StopUnit` answers with.
    stop_error: ?[]const u8 = null,
    /// How a stop job ends. Anything but "done" leaves the scope where it is.
    stop_result: []const u8 = "done",
    /// A socket that exists but is another user's: where the inherited address of a `su` or
    /// `sudo` points. A connection to it is refused (`foreign_rejects` false: EACCES at connect)
    /// or accepted and then refused at authentication.
    foreign_socket: ?[]const u8 = null,
    foreign_rejects: bool = false,
};

pub const scopes_max: u32 = 2;

/// A scope the manager started, as recorded from the request.
pub const Scope = struct {
    active: bool,
    uid: u32,
    name: text_util.Bounded(constants.scope_name_bytes_max + 8),
    pid: u32,
    /// The scope's keeper: the second of `PIDs`, zero when the request had one pid.
    keeper_pid: u32,
    slice: text_util.Bounded(32),
    delegate: bool,
    memory_max: ?u64,
    memory_swap_max: ?u64,
    tasks_max: ?u64,
    cpu_quota_usec: ?u64,
    accounting: u32,
    /// Its last process has gone; the unit stays until the model removes it.
    exited: bool,
    /// The container's process (`pid`) and the keeper have each gone. The scope is empty, and
    /// `exited`, when both have (a scope without a keeper has only the first to wait for).
    container_gone: bool,
    keeper_gone: bool,
};

const inbox_bytes: u32 = 8192;
const outbox_bytes: u32 = 4096;
const conns_max: u32 = 2;
const first_job: u32 = 1000;

const Phase = enum { auth, begin, messages };

const quiet_model: Model = .{};

const error_service_unknown = "org.freedesktop.DBus.Error.ServiceUnknown";
const error_invalid_args = "org.freedesktop.DBus.Error.InvalidArgs";
const error_unit_exists = "org.freedesktop.systemd1.UnitExists";
const error_no_such_unit = "org.freedesktop.systemd1.NoSuchUnit";
const systemd_name = "org.freedesktop.systemd1";
const bus_interface = "org.freedesktop.DBus";

const Conn = struct {
    used: bool,
    /// Whether the model's faults are off for this connection (`Model.quiet_connections`).
    quiet: bool,
    uid: u32,
    phase: Phase,
    inbox: [inbox_bytes]u8,
    inbox_len: u32,
    /// The line `take_line` returned: kept here, not in a static, so two simulators on two
    /// threads share nothing.
    line: [inbox_bytes]u8,
    outbox: [outbox_bytes]u8,
    out_start: u32,
    out_end: u32,
    matched: bool,
    /// The connection called `Manager.Subscribe` and has not called `Unsubscribe`.
    subscribed: bool,
    /// The socket belongs to another user: authentication always fails.
    foreign: bool,
    hung_up: bool,
    server_serial: u32,
    calls: u32,
};

pub const Bus = struct {
    model: Model,
    conns: [conns_max]Conn,
    scopes: [scopes_max]Scope,
    /// The last scope started, kept after it ends so a test can read what it was made with.
    last_scope: Scope,
    /// Scopes started so far.
    scopes_started: u32,
    next_job: u32,
    /// Connections made so far, counted by the model.
    connections: u32,
    /// Set by a write that started a scope: its index, for the world to give it files.
    scope_started: ?u32,
    /// Set by a write that stopped a scope: its index, for the world to take its files away.
    scope_stopped: ?u32,

    pub fn init(bus: *Bus) void {
        bus.model = .{};
        for (&bus.conns) |*conn| conn.used = false;
        for (&bus.scopes) |*scope| scope.active = false;
        bus.next_job = first_job;
        bus.connections = 0;
        bus.scopes_started = 0;
        bus.last_scope.active = false;
        bus.scope_started = null;
        bus.scope_stopped = null;
        assert(bus.open_count() == 0);
        assert(bus.scope_count() == 0);
    }

    /// The model a connection is served by: the perfect one while it is quiet.
    fn active(bus: *const Bus, conn: *const Conn) *const Model {
        return if (conn.quiet) &quiet_model else &bus.model;
    }

    pub fn open_count(bus: *const Bus) u32 {
        var count: u32 = 0;
        for (&bus.conns) |*conn| {
            if (conn.used) count += 1;
        }
        return count;
    }

    pub fn scope_count(bus: *const Bus) u32 {
        var count: u32 = 0;
        for (&bus.scopes) |*scope| {
            if (scope.active) count += 1;
        }
        return count;
    }

    pub fn find_scope(bus: *const Bus, name: []const u8) ?*const Scope {
        for (&bus.scopes) |*scope| {
            if (scope.active and std.mem.eql(u8, scope.name.slice(), name)) return scope;
        }
        return null;
    }

    /// The process is gone. If that leaves its scope with no process, the index of the scope,
    /// once: telling the bus again about the same process (a zombie that is then reaped) finds
    /// the scope already `exited` and returns null.
    pub fn process_ended(bus: *Bus, pid: u32) ?u32 {
        assert(pid > 0);
        assert(bus.scopes.len == scopes_max);
        for (&bus.scopes, 0..) |*scope, index| {
            if (!scope.active) continue;
            const is_container = scope.pid == pid;
            const is_keeper = scope.keeper_pid != 0 and scope.keeper_pid == pid;
            if (!is_container and !is_keeper) continue;
            if (is_container) scope.container_gone = true;
            if (is_keeper) scope.keeper_gone = true;
            if (scope.exited) return null;
            const keeper_left = scope.keeper_pid != 0 and !scope.keeper_gone;
            if (!scope.container_gone or keeper_left) return null;
            scope.exited = true;
            return @intCast(index);
        }
        return null;
    }

    /// Connects: the errno of a refusal, or the connection's index.
    pub fn connect(bus: *Bus, path: []const u8, uid: u32) union(enum) { index: u32, errno: u16 } {
        var expected_buffer: [48]u8 = undefined;
        const expected = bus.model.socket_path orelse
            // Cannot fail: "/run/user/4294967295/bus" is 24 bytes.
            std.fmt.bufPrint(&expected_buffer, "/run/user/{d}/bus", .{uid}) catch unreachable;
        const later = if (bus.model.perfect_from) |from| bus.connections >= from else false;
        const quiet = bus.connections < bus.model.quiet_connections or later;
        const model = if (quiet) &quiet_model else &bus.model;
        const foreign = model.foreign_socket != null and
            std.mem.eql(u8, path, model.foreign_socket.?);
        if (foreign and !model.foreign_rejects) return .{ .errno = errno_access };
        const there = foreign or (model.present and std.mem.eql(u8, path, expected));
        if (!there) return .{ .errno = errno_noent };
        if (model.refuses) return .{ .errno = errno_refused };
        for (&bus.conns, 0..) |*conn, index| {
            if (conn.used) continue;
            conn.used = true;
            conn.quiet = quiet;
            bus.connections += 1;
            conn.uid = uid;
            conn.phase = .auth;
            conn.inbox_len = 0;
            conn.out_start = 0;
            conn.out_end = 0;
            conn.matched = false;
            conn.subscribed = false;
            conn.foreign = foreign;
            conn.hung_up = false;
            conn.server_serial = 1;
            conn.calls = 0;
            return .{ .index = @intCast(index) };
        }
        return .{ .errno = 24 }; // EMFILE: the model holds two connections.
    }

    pub fn close(bus: *Bus, index: u32) void {
        assert(index < conns_max);
        assert(bus.conns[index].used);
        bus.conns[index].used = false;
    }

    /// The client writes. An errno if the connection is gone; otherwise the bytes are taken and
    /// answered into the outbox.
    pub fn write(bus: *Bus, index: u32, bytes: []const u8) ?u16 {
        const conn = &bus.conns[index];
        assert(conn.used);
        if (conn.hung_up) return errno_pipe;
        if (conn.inbox_len + bytes.len > inbox_bytes) return errno_pipe;
        @memcpy(conn.inbox[conn.inbox_len..][0..bytes.len], bytes);
        conn.inbox_len += @intCast(bytes.len);
        bus.process(conn);
        return null;
    }

    pub const ReadResult = union(enum) { count: u32, timeout, end_of_file };

    /// The client reads what the server has queued. Nothing queued is a timeout (the model has
    /// no time), or the end of file if the server hung up.
    pub fn read(bus: *Bus, index: u32, buffer: []u8) ReadResult {
        assert(buffer.len > 0);
        const conn = &bus.conns[index];
        assert(conn.used);
        const available = conn.out_end - conn.out_start;
        if (available == 0) return if (conn.hung_up) .end_of_file else .timeout;
        const count: u32 = @min(available, @as(u32, @intCast(buffer.len)));
        @memcpy(buffer[0..count], conn.outbox[conn.out_start..][0..count]);
        conn.out_start += count;
        if (conn.out_start == conn.out_end) {
            conn.out_start = 0;
            conn.out_end = 0;
        }
        return .{ .count = count };
    }

    // ---- The server ----

    fn process(bus: *Bus, conn: *Conn) void {
        var rounds: u32 = 0;
        while (rounds < 64 and !conn.hung_up) : (rounds += 1) {
            switch (conn.phase) {
                .auth => {
                    const line = take_line(conn) orelse return;
                    bus.handle_auth(conn, line);
                },
                .begin => {
                    const line = take_line(conn) orelse return;
                    if (std.mem.eql(u8, line, "BEGIN")) {
                        conn.phase = .messages;
                    } else {
                        conn.hung_up = true;
                    }
                },
                .messages => if (!bus.take_message(conn)) return,
            }
        }
    }

    /// A CRLF-terminated line from the inbox, copied out of the way of the shift that drops it.
    fn take_line(conn: *Conn) ?[]const u8 {
        const end = std.mem.indexOf(u8, conn.inbox[0..conn.inbox_len], "\r\n") orelse return null;
        const storage = &conn.line;
        assert(end <= storage.len);
        @memcpy(storage[0..end], conn.inbox[0..end]);
        drop(conn, @intCast(end + 2));
        return storage[0..end];
    }

    fn drop(conn: *Conn, count: u32) void {
        assert(count <= conn.inbox_len);
        const kept = conn.inbox_len - count;
        std.mem.copyForwards(u8, conn.inbox[0..kept], conn.inbox[count..conn.inbox_len]);
        conn.inbox_len = kept;
    }

    fn handle_auth(bus: *Bus, conn: *Conn, line: []const u8) void {
        var expected_buffer: [64]u8 = undefined;
        const request = auth.request(&expected_buffer, conn.uid);
        const wanted = request[0 .. request.len - 2]; // The line without its CRLF.
        const matches = std.mem.eql(u8, line, wanted);
        if (conn.foreign) return send_text(conn, "REJECTED EXTERNAL\r\n");
        switch (bus.active(conn).auth) {
            .accept => {
                if (matches) {
                    send_text(conn, "OK 0123456789abcdef0123456789abcdef\r\n");
                    conn.phase = .begin;
                } else {
                    send_text(conn, "REJECTED EXTERNAL\r\n");
                }
            },
            .reject => send_text(conn, "REJECTED EXTERNAL\r\n"),
            .other => send_text(conn, "ERROR \"no\"\r\n"),
        }
    }

    fn send_text(conn: *Conn, text: []const u8) void {
        if (conn.out_end + text.len > outbox_bytes) {
            conn.hung_up = true;
            return;
        }
        @memcpy(conn.outbox[conn.out_end..][0..text.len], text);
        conn.out_end += @intCast(text.len);
    }

    /// One whole message from the inbox, handled. False if more bytes are needed.
    fn take_message(bus: *Bus, conn: *Conn) bool {
        if (conn.inbox_len < message_mod.fixed_header_bytes) return false;
        const prefix = conn.inbox[0..message_mod.fixed_header_bytes];
        const total = message_mod.frame_length(prefix) catch {
            conn.hung_up = true;
            return false;
        };
        if (conn.inbox_len < total) return false;
        var copy: [inbox_bytes]u8 = undefined;
        @memcpy(copy[0..total], conn.inbox[0..total]);
        drop(conn, total);
        const call = message_mod.parse(copy[0..total]) catch {
            conn.hung_up = true; // A real bus disconnects a client that sends garbage.
            return false;
        };
        if (call.kind != .method_call) return true;
        bus.handle_call(conn, &call);
        return true;
    }

    fn handle_call(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        const number = conn.calls;
        conn.calls += 1;
        if (bus.active(conn).misbehave) |fault| {
            if (fault.at_call == number) return bus.misbehave(conn, call, fault.how);
        }
        const interface = call.interface orelse "";
        const member = call.member.?;
        const on_bus = std.mem.eql(u8, interface, "org.freedesktop.DBus");
        if (on_bus and std.mem.eql(u8, member, "Hello")) return bus.hello(conn, call);
        if (on_bus and std.mem.eql(u8, member, "AddMatch")) return bus.add_match(conn, call);
        const destination = call.destination orelse "";
        const to_systemd = std.mem.eql(u8, destination, systemd_name);
        if (!to_systemd or !bus.active(conn).systemd_present) {
            return send_error(conn, call, error_service_unknown, "No owner for the name");
        }
        const properties = std.mem.eql(u8, interface, "org.freedesktop.DBus.Properties");
        if (properties and std.mem.eql(u8, member, "Get")) return bus.get_property(conn, call);
        if (std.mem.eql(u8, member, "StartTransientUnit")) {
            return bus.start_transient_unit(conn, call);
        }
        if (std.mem.eql(u8, member, "StopUnit")) return bus.stop_unit(conn, call);
        if (std.mem.eql(u8, member, "Subscribe") or std.mem.eql(u8, member, "Unsubscribe")) {
            return bus.subscription(conn, call, member[0] == 'S');
        }
        send_error(conn, call, "org.freedesktop.DBus.Error.UnknownMethod", "No such method");
    }

    fn hello(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        if (bus.active(conn).hello_error) |name| {
            return send_error(conn, call, name, "Connection refused");
        }
        var body_buffer: [64]u8 = undefined;
        var writer = wire.Writer.init(&body_buffer);
        writer.string(":1.42");
        send_return(conn, call, "s", writer.finish() catch unreachable); // 11 bytes in 64.
        // A real bus follows Hello with NameAcquired for the unique name: a signal to drop.
        const acquired = writer.finish() catch unreachable; // The same short name.
        send_signal(conn, .{
            .path = "/org/freedesktop/DBus",
            .interface = bus_interface,
            .member = "NameAcquired",
            .signature = "s",
            .body = acquired,
        });
    }

    fn add_match(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        if (!std.mem.eql(u8, call.signature, "s")) {
            return send_error(conn, call, error_invalid_args, "Expected a string");
        }
        var body = call.body_reader();
        const rule = body.string() catch {
            return send_error(conn, call, error_invalid_args, "Bad rule");
        };
        if (std.mem.indexOf(u8, rule, "JobRemoved") != null) conn.matched = true;
        _ = bus;
        send_return(conn, call, "", "");
    }

    fn get_property(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        var body = call.body_reader();
        const bad = error_invalid_args;
        if (!std.mem.eql(u8, call.signature, "ss")) {
            return send_error(conn, call, bad, "Expected ss");
        }
        const interface = body.string() catch return send_error(conn, call, bad, "Bad interface");
        const property = body.string() catch return send_error(conn, call, bad, "Bad property");
        const is_version = std.mem.eql(u8, property, "Version");
        if (!std.mem.eql(u8, interface, "org.freedesktop.systemd1.Manager") or !is_version) {
            const unknown = "org.freedesktop.DBus.Error.UnknownProperty";
            return send_error(conn, call, unknown, "No such property");
        }
        var out_buffer: [128]u8 = undefined;
        var writer = wire.Writer.init(&out_buffer);
        writer.variant_begin("s");
        writer.string(bus.active(conn).version);
        send_return(conn, call, "v", writer.finish() catch unreachable); // Short version text.
    }

    fn start_transient_unit(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        const bad = error_invalid_args;
        if (!std.mem.eql(u8, call.signature, "ssa(sv)a(sa(sv))")) {
            return send_error(conn, call, bad, "Expected ssa(sv)a(sa(sv))");
        }
        var scope: Scope = undefined;
        parse_scope(call, &scope) catch return send_error(conn, call, bad, "Malformed properties");
        const model = bus.active(conn);
        if (model.start_error) |name| return send_error(conn, call, name, "Refused");
        if (model.unit_taken or bus.find_scope(scope.name.slice()) != null) {
            return send_error(conn, call, error_unit_exists, "Unit already exists");
        }
        const job = bus.next_job;
        bus.next_job += 1;
        const done = std.mem.eql(u8, model.job_result, "done");
        if (done) {
            const slot = for (&bus.scopes, 0..) |*candidate, index| {
                if (!candidate.active) break index;
            } else return send_error(conn, call, "org.freedesktop.systemd1.LimitsExceeded", "Full");
            bus.scopes[slot] = scope;
            bus.scopes[slot].uid = conn.uid;
            bus.last_scope = bus.scopes[slot];
            bus.scopes_started += 1;
            bus.scope_started = @intCast(slot);
        }
        var path_buffer: [64]u8 = undefined;
        // Cannot fail: "/org/freedesktop/systemd1/job/" and ten digits fit 64 bytes.
        const job_format = "/org/freedesktop/systemd1/job/{d}";
        const path = std.fmt.bufPrint(&path_buffer, job_format, .{job}) catch
            unreachable; // Same bound as above.
        var body_buffer: [128]u8 = undefined;
        var writer = wire.Writer.init(&body_buffer);
        writer.object_path(path);
        send_return(conn, call, "o", writer.finish() catch unreachable); // Short path.
        if (!model.job_removed) return;
        send_job_removed(conn, job, path, scope.name.slice(), model.job_result);
    }

    /// `Subscribe` and `Unsubscribe`: JobRemoved reaches only a connection that subscribed (and
    /// has the match rule). The strictness is the point: a client that forgets to subscribe
    /// waits for ever.
    fn subscription(bus: *Bus, conn: *Conn, call: *const message_mod.Message, on: bool) void {
        assert(conn.used);
        assert(call.member != null);
        if (on) {
            if (bus.active(conn).subscribe_error) |name| {
                return send_error(conn, call, name, "Access denied");
            }
        }
        conn.subscribed = on;
        send_return(conn, call, "", "");
    }

    /// `StopUnit(name, mode)`: a unit that is not there is `NoSuchUnit`; otherwise a job that
    /// ends the model's way, and with "done" the scope is gone.
    fn stop_unit(bus: *Bus, conn: *Conn, call: *const message_mod.Message) void {
        assert(conn.used);
        assert(bus.scope_stopped == null);
        const bad = error_invalid_args;
        if (!std.mem.eql(u8, call.signature, "ss")) return send_error(conn, call, bad, "ss");
        var reader = call.body_reader();
        const name = reader.string() catch return send_error(conn, call, bad, "Bad name");
        const mode = reader.string() catch return send_error(conn, call, bad, "Bad mode");
        if (!std.mem.eql(u8, mode, "fail")) return send_error(conn, call, bad, "Bad mode");
        const model = bus.active(conn);
        const slot = for (&bus.scopes, 0..) |*scope, index| {
            if (scope.active and std.mem.eql(u8, scope.name.slice(), name)) break index;
        } else return send_error(conn, call, error_no_such_unit, "Unit is not loaded");
        if (model.stop_error) |error_name| return send_error(conn, call, error_name, "Refused");
        const job = bus.next_job;
        bus.next_job += 1;
        var path_buffer: [64]u8 = undefined;
        const job_format = "/org/freedesktop/systemd1/job/{d}";
        // Cannot fail: the prefix and ten digits fit 64 bytes.
        const path = std.fmt.bufPrint(&path_buffer, job_format, .{job}) catch unreachable;
        var body_buffer: [128]u8 = undefined;
        var writer = wire.Writer.init(&body_buffer);
        writer.object_path(path);
        send_return(conn, call, "o", writer.finish() catch unreachable); // Short path.
        if (std.mem.eql(u8, model.stop_result, "done")) bus.scope_stopped = @intCast(slot);
        if (!model.job_removed) return;
        send_job_removed(conn, job, path, name, model.stop_result);
    }

    fn misbehave(bus: *Bus, conn: *Conn, call: *const message_mod.Message, how: Misbehaviour) void {
        _ = bus;
        switch (how) {
            .silent => {},
            .hang_up => conn.hung_up = true,
            .garbage_reply => send_text(conn, "this is not a d-bus message, not even close.."),
            .oversized_reply => {
                var header = [_]u8{ 'l', 2, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
                std.mem.writeInt(u32, header[4..8], constants.dbus_message_bytes_max + 1, .little);
                send_text(conn, &header);
            },
            .truncated_reply => {
                var buffer: [256]u8 = undefined;
                const whole = encode_reply(&buffer, conn, call, "s", &.{ 2, 0, 0, 0, 'o', 'k', 0 });
                send_text(conn, whole[0 .. whole.len - 3]);
                conn.hung_up = true;
            },
            .wrong_serial => {
                var buffer: [256]u8 = undefined;
                const bytes = message_mod.encode(&buffer, .{
                    .kind = .method_return,
                    .serial = take_serial(conn),
                    .reply_serial = call.serial +% 1000,
                }) catch unreachable; // A header-only message in 256 bytes.
                send_text(conn, bytes);
            },
        }
    }
};

/// The `JobRemoved` signal, if this connection asked for it.
fn send_job_removed(
    conn: *Conn,
    job: u32,
    path: []const u8,
    unit: []const u8,
    result: []const u8,
) void {
    assert(conn.used);
    assert(path.len > 0);
    if (!conn.matched or !conn.subscribed) return;
    var signal_buffer: [256]u8 = undefined;
    var writer = wire.Writer.init(&signal_buffer);
    writer.uint32(job);
    writer.object_path(path);
    writer.string(unit);
    writer.string(result);
    const body = writer.finish() catch unreachable; // Bounded names in 256 bytes.
    send_signal(conn, .{
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "JobRemoved",
        .signature = "uoss",
        .body = body,
    });
}

fn take_serial(conn: *Conn) u32 {
    const serial = conn.server_serial;
    conn.server_serial += 1;
    return serial;
}

fn encode_reply(
    buffer: []u8,
    conn: *Conn,
    call: *const message_mod.Message,
    signature: []const u8,
    body: []const u8,
) []const u8 {
    return message_mod.encode(buffer, .{
        .kind = .method_return,
        .serial = take_serial(conn),
        .reply_serial = call.serial,
        .signature = signature,
        .body = body,
    }) catch unreachable; // Replies are small and the buffers are 2 KiB.
}

fn send_return(
    conn: *Conn,
    call: *const message_mod.Message,
    signature: []const u8,
    body: []const u8,
) void {
    var buffer: [2048]u8 = undefined;
    Bus.send_text(conn, encode_reply(&buffer, conn, call, signature, body));
}

fn send_error(
    conn: *Conn,
    call: *const message_mod.Message,
    name: []const u8,
    text: []const u8,
) void {
    var body_buffer: [256]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    writer.string(text);
    var buffer: [2048]u8 = undefined;
    const bytes = message_mod.encode(&buffer, .{
        .kind = .error_reply,
        .serial = take_serial(conn),
        .reply_serial = call.serial,
        .error_name = name,
        .signature = "s",
        .body = writer.finish() catch unreachable, // Short text in 256 bytes.
    }) catch unreachable; // Same.
    Bus.send_text(conn, bytes);
}

const Signal = struct {
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    signature: []const u8,
    body: []const u8,
};

fn send_signal(conn: *Conn, signal: Signal) void {
    var buffer: [2048]u8 = undefined;
    const bytes = message_mod.encode(&buffer, .{
        .kind = .signal,
        .serial = take_serial(conn),
        .path = signal.path,
        .interface = signal.interface,
        .member = signal.member,
        .signature = signal.signature,
        .body = signal.body,
    }) catch unreachable; // Short signals in 2 KiB.
    Bus.send_text(conn, bytes);
}

/// Reads the scope out of a `StartTransientUnit` body, strictly: a property of a type the
/// client does not send, or a body with anything left over, is an error.
fn parse_scope(call: *const message_mod.Message, scope: *Scope) wire.WireError!void {
    var reader = call.body_reader();
    scope.* = .{
        .active = true,
        .uid = 0,
        .name = .{},
        .pid = 0,
        .keeper_pid = 0,
        .slice = .{},
        .delegate = false,
        .memory_max = null,
        .memory_swap_max = null,
        .tasks_max = null,
        .cpu_quota_usec = null,
        .accounting = 0,
        .exited = false,
        .container_gone = false,
        .keeper_gone = false,
    };
    scope.name.append_sanitised(try reader.string(), constants.scope_name_bytes_max + 8);
    if (!std.mem.eql(u8, try reader.string(), "fail")) return error.BadValue;
    const end = try reader.array_begin(8);
    var count: u32 = 0;
    while (reader.at < end) {
        count += 1;
        if (count > constants.scope_properties_max) return error.TooLong;
        try reader.align_to(8);
        const name = try reader.string();
        const kind = try reader.signature();
        try read_property(&reader, scope, name, kind);
    }
    if (reader.at != end) return error.BadValue;
    const aux_end = try reader.array_begin(8);
    if (reader.at != aux_end) return error.BadValue;
    if (reader.remaining() != 0) return error.BadValue;
    if (scope.pid == 0) return error.BadValue;
}

fn read_property(
    reader: *wire.Reader,
    scope: *Scope,
    name: []const u8,
    kind: []const u8,
) wire.WireError!void {
    if (std.mem.eql(u8, kind, "s")) {
        const value = try reader.string();
        if (std.mem.eql(u8, name, "Slice")) scope.slice.append_sanitised(value, 32);
    } else if (std.mem.eql(u8, kind, "b")) {
        const value = try reader.boolean();
        if (std.mem.eql(u8, name, "Delegate")) scope.delegate = value;
        if (std.mem.endsWith(u8, name, "Accounting") and value) scope.accounting += 1;
    } else if (std.mem.eql(u8, kind, "t")) {
        const value = try reader.uint64();
        if (std.mem.eql(u8, name, "MemoryMax")) scope.memory_max = value;
        if (std.mem.eql(u8, name, "MemorySwapMax")) scope.memory_swap_max = value;
        if (std.mem.eql(u8, name, "TasksMax")) scope.tasks_max = value;
        if (std.mem.eql(u8, name, "CPUQuotaPerSecUSec")) scope.cpu_quota_usec = value;
    } else if (std.mem.eql(u8, kind, "au")) {
        const array_end = try reader.array_begin(4);
        var seen: u32 = 0;
        while (reader.at < array_end) : (seen += 1) {
            const pid = try reader.uint32();
            if (!std.mem.eql(u8, name, "PIDs")) continue;
            switch (seen) {
                0 => scope.pid = pid,
                1 => scope.keeper_pid = pid,
                else => return error.TooLong, // The container and its keeper, no more.
            }
        }
    } else {
        return error.Unsupported;
    }
}
