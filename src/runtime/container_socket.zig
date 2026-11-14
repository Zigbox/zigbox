//! `container_socket`: a new, unconnected IPv4 TCP socket made in a running container's network
//! namespace (Zigcube's ZB-5; `docs/decisions/2026-11-14-zigcube-c4-requests.md` is the
//! contract).
//!
//! The caller is any thread of a process that did not start the container. It finds the
//! container as `exec` does (record and /proc), opens the container's user and network
//! namespace files, and forks a helper with `Host.fork_child`: a single-threaded child of the
//! caller, in the caller's own PID namespace, which is never the container's. The workload
//! therefore cannot see, signal or trace it. The helper joins the user namespace, then the
//! network namespace, makes the socket and sends it back over a Unix socketpair with
//! `SCM_RIGHTS`; it exits and is reaped by pid, so no other child of the caller is touched.
//!
//! The helper uses no `PR_SET_PDEATHSIG` (it fires when the creating thread exits, not the
//! process) and cannot block: three system calls and a send into a socket with an empty buffer.
//! A failure is a four-byte record in a report pipe (`sync.zig`) naming the step and the errno.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const exec = @import("exec.zig");
const exec_diagnose = @import("exec_diagnose.zig");
const lifecycle = @import("lifecycle.zig");
const records = @import("records.zig");
const socket_diagnose = @import("socket_diagnose.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;
const Step = socket_diagnose.Step;

pub const Error = error{SocketFailed};

/// The kinds of socket there are. Only IPv4 TCP: IPv6, UDP and Unix sockets are not offered.
pub const Kind = enum { tcp4 };

/// What the helper needs, in the caller's memory; the fork gives it its own copy.
const Context = struct {
    host: Host,
    /// Null when the container shares the caller's user namespace: nothing to join.
    user: ?host_mod.Handle,
    net: host_mod.Handle,
    /// The caller's end is `read`, the helper's `write`.
    channel: host_mod.Pipe,
    report: host_mod.Pipe,
    /// The socket between the helper's two last steps; the helper writes its own copy.
    socket: host_mod.Handle,
};

/// Makes a socket in the running container `name` and returns it: a descriptor of the caller's,
/// close-on-exec, that the caller owns and closes. Callable from any thread, many times, each
/// thread with a `Host` of its own; each call forks and reaps one helper, and leaves nothing
/// open on success or failure.
pub fn open(host: Host, name: []const u8, kind: Kind, diag: *Diag) Error!host_mod.Handle {
    assert(diag.code == null);
    assert(name.len > 0);
    assert(kind == .tcp4);
    var record: records.Parsed = undefined;
    exec.find_running(host, name, &record, diag) catch return error.SocketFailed;
    // A record that predates the network field (null) is judged by its namespaces below.
    if (record.network) |network| switch (network) {
        .none => {},
        .host => return refuse(diag, name, .host),
        .user => return refuse(diag, name, .user),
    };
    const user = host.open_namespace(record.pid, .user) catch |err| {
        step_diag(diag, name, .join_user, host, err);
        return error.SocketFailed;
    };
    defer if (user) |opened| host.close(opened);
    const net = host.open_namespace(record.pid, .net) catch |err| {
        step_diag(diag, name, .join_net, host, err);
        return error.SocketFailed;
    };
    defer if (net) |opened| host.close(opened);
    // The pid was the container's PID 1 when the lookup ran; it could have ended and the pid
    // been reused before the namespace files were opened. Asked again now that they are open
    // (they pin the namespaces they name), a yes means they are the container's.
    if (!lifecycle.alive(host, record.pid, record.scope_slice())) {
        exec_diagnose.not_running(diag, name, false, &record);
        return error.SocketFailed;
    }
    const opened_net = net orelse return refuse(diag, name, .host);
    return run_helper(host, name, user, opened_net, diag);
}

fn refuse(diag: *Diag, name: []const u8, why: socket_diagnose.NoNetwork) Error {
    assert(diag.code == null);
    socket_diagnose.no_socket_network(diag, name, why);
    assert(diag.code.? == .E0610);
    return error.SocketFailed;
}

fn step_diag(diag: *Diag, name: []const u8, step: Step, host: Host, err: host_mod.Error) void {
    assert(diag.code == null);
    socket_diagnose.step_failed(diag, name, step, .{ .err = err, .errno = host.last_errno() });
    assert(diag.code.? == .E0611);
}

fn run_helper(
    host: Host,
    name: []const u8,
    user: ?host_mod.Handle,
    net: host_mod.Handle,
    diag: *Diag,
) Error!host_mod.Handle {
    if (user) |opened| assert(opened != net);
    const channel = host.channel() catch |err| {
        step_diag(diag, name, .start_helper, host, err);
        return error.SocketFailed;
    };
    const report = host.pipe() catch |err| {
        host.close(channel.read);
        host.close(channel.write);
        step_diag(diag, name, .start_helper, host, err);
        return error.SocketFailed;
    };
    var context: Context = .{
        .host = host,
        .user = user,
        .net = net,
        .channel = channel,
        .report = report,
        .socket = 0,
    };
    const pid = host.fork_child(false, helper_entry, &context) catch |err| {
        close_all(host, &context);
        step_diag(diag, name, .start_helper, host, err);
        return error.SocketFailed;
    };
    // The helper has its own copies of its ends: ours would keep the ends from ever closing.
    host.close(channel.write);
    host.close(report.write);
    return collect(host, name, pid, &context, diag);
}

fn close_all(host: Host, context: *const Context) void {
    host.close(context.channel.read);
    host.close(context.channel.write);
    host.close(context.report.read);
    host.close(context.report.write);
}

/// Reaps the helper, then takes what it left: a socket on the channel, or a record on the report
/// pipe. Closes the caller's ends either way.
fn collect(
    host: Host,
    name: []const u8,
    pid: host_mod.Pid,
    context: *const Context,
    diag: *Diag,
) Error!host_mod.Handle {
    defer host.close(context.channel.read);
    defer host.close(context.report.read);
    const status = reap(host, pid) catch |err| {
        step_diag(diag, name, .reap_helper, host, err);
        return error.SocketFailed;
    };
    if (status == .exited) {
        if (status.exited == constants.exit_ok) {
            return host.receive_handle(context.channel.read) catch |err| {
                step_diag(diag, name, .send_socket, host, err);
                return error.SocketFailed;
            };
        }
    }
    const record = read_failure(host, context.report.read) orelse sync.Record{
        .kind = .failure,
        .step = @backingInt(Step.send_socket),
        .errno = constants.errno_io,
    };
    const step = std.enums.fromInt(Step, record.step) orelse Step.send_socket;
    const err = host_mod.error_for_errno(record.errno);
    socket_diagnose.step_failed(diag, name, step, .{ .err = err, .errno = record.errno });
    return error.SocketFailed;
}

/// Waits for the helper. A wait that fails is tried once more, so that a passing fault does not
/// leave the helper a zombie; one that fails twice is a real error, such as `ECHILD` when the
/// caller ignores SIGCHLD and the kernel reaped the helper itself.
fn reap(host: Host, pid: host_mod.Pid) host_mod.Error!host_mod.ExitStatus {
    assert(pid > 0);
    return host.wait_for(pid) catch return host.wait_for(pid);
}

/// The failure record the helper wrote, if it wrote one. Read only after the helper failed and
/// was reaped, so its record, if any, is already in the pipe: the read never waits for end of
/// file, which a copy of the write end in another thread's child (forked between our `pipe`
/// and its `exec`, or never exec'ing) could hold off for as long as that child lives.
fn read_failure(host: Host, report_read: host_mod.Handle) ?sync.Record {
    var bytes: [constants.sync_record_bytes]u8 = undefined;
    var length: usize = 0;
    for (0..bytes.len + constants.eintr_retries_max) |_| {
        if (length == bytes.len) break;
        const count = host.read_timeout(report_read, bytes[length..], report_wait_ms) catch {
            return null;
        };
        if (count == 0) return null;
        length += count;
    }
    if (length != bytes.len) return null;
    const record = sync.Record.decode(&bytes) orelse return null;
    assert(record.kind == .failure);
    return record;
}

/// How long the read of a reaped helper's record may wait: its bytes are there or never come.
const report_wait_ms: u32 = 1;

/// The helper's body: a failure is a record, then exit code `child_exit_setup_failed`.
fn helper_entry(raw: *anyopaque) u8 {
    const context: *Context = @ptrCast(@alignCast(raw));
    const host = context.host;
    assert(context.channel.read != context.report.read);
    // The caller's ends: closed here so that end of file reaches both sides.
    host.close(context.channel.read);
    host.close(context.report.read);
    for (socket_diagnose.helper_steps) |step| {
        host.begin_step(@backingInt(step));
        helper_step(context, step) catch {
            fail(context, step, host.last_errno());
            host.begin_step(host_mod.step_none);
            return constants.child_exit_setup_failed;
        };
    }
    host.begin_step(host_mod.step_none);
    return constants.exit_ok;
}

fn helper_step(context: *Context, step: Step) host_mod.Error!void {
    const host = context.host;
    if (context.user) |user| assert(user != context.net);
    switch (step) {
        // A container in the caller's own user namespace: nothing to join.
        .join_user => if (context.user) |user| try host.join_namespace(user, .user),
        .join_net => try host.join_namespace(context.net, .net),
        .make_socket => {
            context.socket = try host.tcp4_socket();
        },
        .send_socket => {
            try host.send_handle(context.channel.write, context.socket);
            host.close(context.socket);
        },
        .start_helper, .reap_helper => unreachable, // Not in `helper_steps`: the caller's.
    }
}

fn fail(context: *const Context, step: Step, errno_raw: u16) void {
    assert(errno_raw < 4096);
    const errno = if (errno_raw != 0) errno_raw else constants.errno_io;
    const record: sync.Record = .{ .kind = .failure, .step = @backingInt(step), .errno = errno };
    const bytes = record.encode();
    context.host.write_handle_all(context.report.write, &bytes) catch return;
}
