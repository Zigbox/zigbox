//! A D-Bus client over a `Host` socket: connect, authenticate (SASL EXTERNAL), say Hello, call
//! methods, and wait for the signal that ends a systemd job. One connection, one thread, every
//! wait bounded in poll steps (`constants.dbus_*`). It reads only what zbx asks about; every
//! other message the bus sends is read, checked for well-formedness and dropped.
//!
//! Failures are not diagnostics here. A failed step returns `error.Failed` and leaves the facts
//! in `Connection.failure` (what step, what kind, the remote error's name and text), which
//! `runtime/scope.zig` turns into a coded diagnostic. That keeps this file free of wording.
//!
//! The connection owns its two 16 KiB buffers, so it is initialised in place (`init`) and is
//! best kept off a deep stack. A `Message` returned by `call` or `next_message` points into the
//! receive buffer and is valid until the next call on the same connection.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const auth = @import("auth.zig");
const message_mod = @import("message.zig");
const wire = @import("wire.zig");

const Host = host_mod.Host;
const Message = message_mod.Message;

/// What went wrong, in terms a diagnostic can explain.
pub const FailureKind = enum {
    /// No connection: the socket is missing, refused or not ours to open.
    no_bus,
    /// The bus did not accept this user (SASL rejected, or it said something else).
    auth_refused,
    /// The peer sent something that is not a well-formed answer, or hung up.
    protocol,
    /// No answer within the bound.
    timeout,
    /// The peer answered with a D-Bus error; `name` and `text` hold it.
    remote,
    /// Writing to or reading from the socket failed.
    io,
};

/// Which step of the conversation failed.
pub const Stage = enum { connect, auth, hello, add_match, call, job };

pub const Text = text_util.Bounded(constants.dbus_error_text_bytes_max);

pub const Failure = struct {
    kind: FailureKind,
    stage: Stage,
    err: host_mod.Error,
    errno: u16,
    wire: ?wire.WireError,
    /// The remote error's name, or the SASL line the bus sent.
    name: Text,
    /// The remote error's message.
    text: Text,
};

pub const CallError = error{Failed};

/// A `JobRemoved` signal: the job's object path and its result ("done", "failed", ...).
pub const JobRemoved = struct {
    path: text_util.Bounded(96),
    result: text_util.Bounded(24),
};

/// How many polls and messages a wait may spend.
pub const Budget = struct {
    timeouts_left: u32,
    messages_left: u32,

    pub fn for_timeout(timeout_ms: u32) Budget {
        assert(timeout_ms >= constants.dbus_poll_step_ms);
        assert(timeout_ms % constants.dbus_poll_step_ms == 0);
        return .{
            .timeouts_left = @divExact(timeout_ms, constants.dbus_poll_step_ms),
            .messages_left = constants.dbus_messages_per_wait_max,
        };
    }
};

pub const Call = struct {
    destination: []const u8,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    /// The body's signature and its bytes, marshalled from offset zero.
    signature: []const u8 = "",
    body: []const u8 = "",
};

pub const Connection = struct {
    host: Host,
    handle: host_mod.Handle,
    is_open: bool,
    next_serial: u32,
    receive: [constants.dbus_message_bytes_max]u8,
    receive_start: u32,
    receive_end: u32,
    send: [constants.dbus_message_bytes_max]u8,
    jobs: [constants.dbus_job_results_max]JobRemoved,
    jobs_count: u32,
    failure: Failure,

    /// Initialises in place; the connection is not open yet.
    pub fn init(conn: *Connection, host: Host) void {
        conn.host = host;
        conn.handle = 0;
        conn.is_open = false;
        conn.next_serial = 1;
        conn.receive_start = 0;
        conn.receive_end = 0;
        conn.jobs_count = 0;
        conn.failure = .{
            .kind = .io,
            .stage = .connect,
            .err = error.IoFailed,
            .errno = 0,
            .wire = null,
            .name = .{},
            .text = .{},
        };
        assert(!conn.is_open);
        assert(conn.jobs_count == 0);
    }

    pub fn close(conn: *Connection) void {
        if (!conn.is_open) return;
        assert(conn.jobs_count <= conn.jobs.len);
        conn.host.close(conn.handle);
        conn.is_open = false;
        assert(!conn.is_open);
    }

    fn fail(conn: *Connection, kind: FailureKind, stage: Stage) CallError {
        assert(conn.failure.name.len <= constants.dbus_error_text_bytes_max);
        conn.note(kind, stage);
        assert(conn.failure.stage == stage);
        return error.Failed;
    }

    /// Records a failure without returning: the caller fills in its details, then fails.
    fn note(conn: *Connection, kind: FailureKind, stage: Stage) void {
        assert(conn.jobs_count <= conn.jobs.len);
        conn.failure.kind = kind;
        conn.failure.stage = stage;
        conn.failure.err = error.IoFailed;
        conn.failure.errno = 0;
        conn.failure.wire = null;
        conn.failure.name = .{};
        conn.failure.text = .{};
        assert(conn.failure.kind == kind);
    }

    fn fail_io(conn: *Connection, kind: FailureKind, stage: Stage, err: host_mod.Error) CallError {
        assert(kind != .protocol);
        assert(kind != .remote);
        const errno = if (err == error.TimedOut) 0 else conn.host.last_errno();
        conn.note(kind, stage);
        conn.failure.err = err;
        conn.failure.errno = errno;
        assert(conn.failure.errno < 4096);
        return error.Failed;
    }

    fn fail_wire(conn: *Connection, stage: Stage, problem: wire.WireError) CallError {
        assert(conn.failure.name.len <= constants.dbus_error_text_bytes_max);
        conn.note(.protocol, stage);
        conn.failure.wire = problem;
        assert(conn.failure.wire != null);
        return error.Failed;
    }

    // ---- Connecting ----

    /// Opens the socket at `socket_path`.
    pub fn connect(conn: *Connection, socket_path: []const u8) CallError!void {
        assert(!conn.is_open);
        assert(socket_path.len > 0);
        assert(socket_path.len <= constants.dbus_socket_path_bytes_max);
        conn.handle = conn.host.socket_connect(socket_path) catch |err| {
            return conn.fail_io(.no_bus, .connect, err);
        };
        conn.is_open = true;
        // A write to a bus that has hung up is a signal unless the caller has asked for an error
        // (`Host.ignore_broken_pipe`): the run's session does, for its whole length.
    }

    /// SASL EXTERNAL as `uid`: the NUL byte and the AUTH line, the server's answer, then BEGIN.
    pub fn authenticate(conn: *Connection, uid: u32) CallError!void {
        assert(conn.is_open);
        assert(conn.receive_end == 0);
        assert(conn.receive_start == 0);
        var line_buffer: [64]u8 = undefined;
        conn.write_all(auth.request(&line_buffer, uid), .auth) catch |err| return err;
        var budget = Budget.for_timeout(constants.dbus_call_timeout_ms);
        const line = try conn.read_line(&budget);
        switch (auth.parse_reply(line)) {
            .ok => {},
            .rejected, .other => {
                conn.note(.auth_refused, .auth);
                conn.failure.name.append_sanitised(line, constants.dbus_error_text_bytes_max);
                return error.Failed;
            },
        }
        try conn.write_all(auth.begin, .auth);
    }

    /// One CRLF-terminated line from the receive buffer, without the CRLF. The bytes after it
    /// stay buffered.
    fn read_line(conn: *Connection, budget: *Budget) CallError![]const u8 {
        assert(conn.receive_start == 0);
        assert(budget.timeouts_left > 0);
        const limit = constants.dbus_auth_line_bytes_max + 2;
        while (true) {
            const have = conn.receive[0..conn.receive_end];
            if (std.mem.indexOf(u8, have, "\r\n")) |end| {
                if (end > constants.dbus_auth_line_bytes_max) {
                    return conn.fail_wire(.auth, error.TooLong);
                }
                conn.receive_start = @intCast(end + 2);
                return have[0..end];
            }
            if (conn.receive_end >= limit) return conn.fail_wire(.auth, error.TooLong);
            try conn.read_more(.auth, budget, limit);
        }
    }

    // ---- Reading ----

    /// Reads more bytes into the receive buffer, up to `wanted_end` bytes in all.
    fn read_more(conn: *Connection, stage: Stage, budget: *Budget, wanted_end: u32) CallError!void {
        assert(wanted_end <= conn.receive.len);
        assert(conn.receive_end < wanted_end);
        assert(conn.is_open);
        assert(conn.receive_start <= conn.receive_end);
        const room = conn.receive[conn.receive_end..wanted_end];
        while (true) {
            const count = conn.host.read_timeout(
                conn.handle,
                room,
                constants.dbus_poll_step_ms,
            ) catch |err| {
                if (err != error.TimedOut) return conn.fail_io(.io, stage, err);
                if (budget.timeouts_left == 0) return conn.fail(.timeout, stage);
                budget.timeouts_left -= 1;
                continue;
            };
            if (count == 0) return conn.fail_wire(stage, error.Truncated); // The peer hung up.
            conn.receive_end += count;
            return;
        }
    }

    /// The next whole message. Bytes of messages already returned are dropped first.
    pub fn next_message(conn: *Connection, stage: Stage, budget: *Budget) CallError!Message {
        assert(conn.receive_start <= conn.receive_end);
        assert(conn.is_open);
        if (budget.messages_left == 0) return conn.fail_wire(stage, error.TooLong);
        budget.messages_left -= 1;
        conn.compact();
        while (conn.receive_end < message_mod.fixed_header_bytes) {
            try conn.read_more(stage, budget, message_mod.fixed_header_bytes);
        }
        const prefix = conn.receive[0..message_mod.fixed_header_bytes];
        const total = message_mod.frame_length(prefix) catch |err| {
            return conn.fail_wire(stage, err);
        };
        while (conn.receive_end < total) try conn.read_more(stage, budget, total);
        const parsed = message_mod.parse(conn.receive[0..total]) catch |err| {
            return conn.fail_wire(stage, err);
        };
        conn.receive_start = total;
        assert(conn.receive_start <= conn.receive_end);
        assert(total >= message_mod.fixed_header_bytes);
        return parsed;
    }

    fn compact(conn: *Connection) void {
        assert(conn.receive_start <= conn.receive_end);
        assert(conn.receive_end <= conn.receive.len);
        if (conn.receive_start == 0) return;
        const kept = conn.receive_end - conn.receive_start;
        const unread = conn.receive[conn.receive_start..conn.receive_end];
        std.mem.copyForwards(u8, conn.receive[0..kept], unread);
        conn.receive_start = 0;
        conn.receive_end = kept;
        assert(conn.receive_end <= conn.receive.len);
    }

    // ---- Writing ----

    fn write_all(conn: *Connection, bytes: []const u8, stage: Stage) CallError!void {
        assert(conn.is_open);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.dbus_message_bytes_max);
        conn.host.write_handle_all(conn.handle, bytes) catch |err| {
            return conn.fail_io(.io, stage, err);
        };
    }

    // ---- Calling ----

    /// Calls a method and waits for its reply. A D-Bus error reply is a failure of kind
    /// `remote`. Signals that arrive meanwhile are noted (`JobRemoved`) or dropped.
    pub fn call(conn: *Connection, request: Call, stage: Stage) CallError!Message {
        assert(conn.is_open);
        assert(request.member.len > 0);
        const serial = conn.next_serial;
        assert(serial != 0);
        conn.next_serial += 1;
        const bytes = message_mod.encode(&conn.send, .{
            .kind = .method_call,
            .serial = serial,
            .path = request.path,
            .destination = request.destination,
            .interface = request.interface,
            .member = request.member,
            .signature = request.signature,
            .body = request.body,
        }) catch |err| return conn.fail_wire(stage, err);
        try conn.write_all(bytes, stage);
        var budget = Budget.for_timeout(constants.dbus_call_timeout_ms);
        while (true) {
            const reply = try conn.next_message(stage, &budget);
            switch (reply.kind) {
                .signal => conn.note_signal(&reply),
                .method_call => {}, // A peer asking us something: we answer nothing.
                .method_return, .error_reply => {
                    if (reply.reply_serial.? != serial) continue;
                    if (reply.kind == .method_return) return reply;
                    return conn.remote_error(&reply, stage);
                },
            }
        }
    }

    fn remote_error(conn: *Connection, reply: *const Message, stage: Stage) CallError {
        assert(reply.kind == .error_reply);
        assert(reply.error_name != null);
        conn.note(.remote, stage);
        const limit = constants.dbus_error_text_bytes_max;
        conn.failure.name.append_sanitised(reply.error_name.?, limit);
        if (std.mem.startsWith(u8, reply.signature, "s")) {
            var body = reply.body_reader();
            if (body.string()) |text| conn.failure.text.append_sanitised(text, limit) else |_| {}
        }
        return error.Failed;
    }

    /// Remembers a `JobRemoved` signal; any other signal is dropped. When the list is full the
    /// oldest is dropped: a job zbx waits for was queued after it asked, so it is the newest.
    fn note_signal(conn: *Connection, signal: *const Message) void {
        assert(signal.kind == .signal);
        assert(conn.jobs_count <= conn.jobs.len);
        const member = signal.member orelse return;
        if (!std.mem.eql(u8, member, "JobRemoved")) return;
        if (!std.mem.eql(u8, signal.signature, "uoss")) return;
        var body = signal.body_reader();
        _ = body.uint32() catch return;
        const path = body.object_path() catch return;
        _ = body.string() catch return; // The unit's name.
        const result = body.string() catch return;
        if (conn.jobs_count == conn.jobs.len) {
            std.mem.copyForwards(JobRemoved, conn.jobs[0 .. conn.jobs.len - 1], conn.jobs[1..]);
            conn.jobs_count -= 1;
        }
        const slot = &conn.jobs[conn.jobs_count];
        slot.* = .{ .path = .{}, .result = .{} };
        slot.path.append_sanitised(path, 96);
        slot.result.append_sanitised(result, 24);
        conn.jobs_count += 1;
        assert(conn.jobs_count <= conn.jobs.len);
    }

    /// Says Hello to the bus. The reply is the connection's unique name, which starts with ':'.
    pub fn hello(conn: *Connection) CallError!void {
        const reply = try conn.call(.{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "Hello",
        }, .hello);
        assert(reply.kind == .method_return);
        var body = reply.body_reader();
        const name = body.string() catch |err| return conn.fail_wire(.hello, err);
        if (!std.mem.eql(u8, reply.signature, "s")) return conn.fail_wire(.hello, error.BadValue);
        if (name.len == 0) return conn.fail_wire(.hello, error.BadValue);
        if (name[0] != ':') return conn.fail_wire(.hello, error.BadValue);
    }

    /// Asks the bus to send this connection the signals the rule matches.
    pub fn add_match(conn: *Connection, rule: []const u8) CallError!void {
        assert(rule.len > 0);
        assert(rule.len < 400);
        var body_buffer: [512]u8 = undefined;
        var writer = wire.Writer.init(&body_buffer);
        writer.string(rule);
        const body = writer.finish() catch |err| return conn.fail_wire(.add_match, err);
        _ = try conn.call(.{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "AddMatch",
            .signature = "s",
            .body = body,
        }, .add_match);
    }

    /// Waits for the `JobRemoved` of the job at `job_path` and returns its result text, which
    /// points into the connection.
    pub fn wait_job(conn: *Connection, job_path: []const u8) CallError![]const u8 {
        assert(job_path.len > 0);
        assert(conn.is_open);
        var budget = Budget.for_timeout(constants.dbus_job_timeout_ms);
        while (true) {
            for (conn.jobs[0..conn.jobs_count]) |*job| {
                if (std.mem.eql(u8, job.path.slice(), job_path)) return job.result.slice();
            }
            const next = try conn.next_message(.job, &budget);
            if (next.kind == .signal) conn.note_signal(&next);
        }
    }
};

// ---- Tests ---------------------------------------------------------------------------------
//
// The client is exercised against the simulator's bus in `src/dbus/client_tests.zig`, which
// needs a host; this file's tests are the pure pieces.

const testing = std.testing;

test "a budget is whole poll steps" {
    // Goal: waits are counted in steps, so a wait is bounded by construction.
    const call_budget = Budget.for_timeout(constants.dbus_call_timeout_ms);
    try testing.expectEqual(@as(u32, 20), call_budget.timeouts_left);
    try testing.expectEqual(constants.dbus_messages_per_wait_max, call_budget.messages_left);
    const job_budget = Budget.for_timeout(constants.dbus_job_timeout_ms);
    try testing.expect(job_budget.timeouts_left > call_budget.timeouts_left);
}
