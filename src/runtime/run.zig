//! Runs a container in the foreground: checks the request, builds the plan, executes the
//! parent's steps through the host, and returns how the command ended. The child's steps are in
//! `child.zig`. Nothing here prints; a refusal is a coded `Diag` and the CLI renders it.
//!
//! Process model (docs/briefs/M1-shell.md): this process stays in the host PID namespace as the
//! parent. `clone3` creates a child in new user, mount, PID, UTS and IPC namespaces. The child is
//! PID 1 of its namespace, sets the container up and runs the command; there is no init shim.
//! Two pipes carry the synchronisation: the parent tells the child when the id maps are written
//! (`ready`), and the child tells the parent about a failed or skipped step (`report`).
//!
//! Where later milestones attach: `stop` with a grace period is `signal` plus a timer around
//! `reap`; `list` and re-adoption read the run record, keyed by name; the event stream is the
//! `report` pipe kept open for the container's life; a detached run is `spawn` without `reap`,
//! with the parent's job done by a supervisor. None of them changes the plan's steps.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const child_mod = @import("child.zig");
const diagnose = @import("diagnose.zig");
const plan_mod = @import("plan.zig");
const spec_mod = @import("spec.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;
const Spec = spec_mod.Spec;

/// The run did not start the command; the reason is in the `Diag`.
pub const Error = error{StartFailed};

pub const Note = text_util.Bounded(160);

/// How a run that started its command ended.
pub const Outcome = struct {
    status: host_mod.ExitStatus,
    name: [constants.container_name_bytes_max]u8,
    name_len: u8,
    /// Steps that were allowed to fail and did (the devpts mount), as one-line sentences.
    notes: [constants.sync_records_max]Note,
    notes_count: u32,

    pub fn name_slice(outcome: *const Outcome) []const u8 {
        assert(outcome.name_len > 0);
        assert(outcome.name_len <= constants.container_name_bytes_max);
        return outcome.name[0..outcome.name_len];
    }

    pub fn note_slice(outcome: *const Outcome) []const Note {
        assert(outcome.notes_count <= constants.sync_records_max);
        if (outcome.notes_count > 0) assert(outcome.notes[0].len > 0);
        return outcome.notes[0..outcome.notes_count];
    }

    /// The exit code zbx ends with: the command's own, or 128 plus the signal that killed it.
    pub fn exit_code(outcome: *const Outcome) u8 {
        switch (outcome.status) {
            .exited => |code| return code,
            .signaled => |number| {
                assert(number > 0);
                assert(number < constants.signal_number_max);
                return constants.exit_signal_offset + number;
            },
        }
    }
};

/// Runs the container described by `container`. On success the command ran and `outcome` says how
/// it ended; on `StartFailed` it did not, and `diag` says why.
pub fn run(host: Host, container: *const Spec, outcome: *Outcome, diag: *Diag) Error!void {
    assert(diag.code == null);
    var name_storage: [constants.container_name_bytes_max]u8 = undefined;
    const name = try choose_name(host, container.name, &name_storage, diag);
    try check_command(container.command, diag);
    try check_rootfs(host, container.rootfs, diag);

    const input: plan_mod.Input = .{
        .rootfs = container.rootfs,
        .name = name,
        .command = container.command,
        .term = host.environment("TERM", constants.term_bytes_max),
        .uid = host.uid(),
        .gid = host.gid(),
    };
    var plan: Plan = undefined;
    plan.build(&input);
    // Namespace setup must happen before any thread exists (docs/SPEC.md, M1 acceptance).
    if (builtin.mode == .debug) assert_single_threaded(host);

    var session: Session = undefined;
    session.start(host, &plan);
    try session.execute(diag, .{ .name = name, .rootfs = container.rootfs });
    session.fill(outcome, name);
    assert(outcome.name_len == name.len);
}

fn choose_name(
    host: Host,
    given: ?[]const u8,
    storage: *[constants.container_name_bytes_max]u8,
    diag: *Diag,
) Error![]const u8 {
    assert(storage.len == constants.container_name_bytes_max);
    assert(diag.code == null);
    if (given) |name| {
        if (spec_mod.name_problem(name)) |problem| {
            diagnose.name_invalid(diag, name, problem);
            return error.StartFailed;
        }
        @memcpy(storage[0..name.len], name);
        return storage[0..name.len];
    }
    const prefix = constants.container_name_prefix;
    var random: [constants.container_name_hex_digits / 2]u8 = undefined;
    // A name is a label, not an identity: if the system has no randomness, a fixed name is
    // still a valid one, and failing a run over it would be worse.
    host.random_bytes(&random) catch @memset(&random, 0);
    const hex = "0123456789abcdef";
    @memcpy(storage[0..prefix.len], prefix);
    for (random, 0..) |byte, index| {
        storage[prefix.len + 2 * index] = hex[byte >> 4];
        storage[prefix.len + 2 * index + 1] = hex[byte & 15];
    }
    const length = prefix.len + constants.container_name_hex_digits;
    assert(spec_mod.name_problem(storage[0..length]) == null);
    return storage[0..length];
}

fn check_command(command: []const []const u8, diag: *Diag) Error!void {
    // The command line parser refuses a missing program; a caller of the library must too.
    assert(command.len > 0);
    assert(command[0].len > 0);
    if (spec_mod.command_problem(command)) |problem| {
        diagnose.command_too_big(diag, problem);
        return error.StartFailed;
    }
    assert(command.len > 0);
}

fn check_rootfs(host: Host, rootfs: []const u8, diag: *Diag) Error!void {
    if (spec_mod.rootfs_problem(rootfs)) |problem| {
        diagnose.rootfs_unusable(diag, rootfs, .{ .problem = problem });
        return error.StartFailed;
    }
    assert(rootfs.len > 0);
    assert(diag.code == null);
    const found = host.stat(rootfs) catch |err| {
        const failure: diagnose.Failure = .{ .step = 0, .err = err, .errno = host.last_errno() };
        diagnose.rootfs_unusable(diag, rootfs, .{ .unreadable = failure });
        return error.StartFailed;
    };
    if (found.mode & std.posix.S.IFMT != std.posix.S.IFDIR) {
        diagnose.rootfs_unusable(diag, rootfs, .not_a_directory);
        return error.StartFailed;
    }
    assert(rootfs.len <= constants.rootfs_bytes_max);
}

// ---- The single-thread assertion ----------------------------------------------------------

/// The thread count in the text of /proc/self/status, or null if there is no such line.
pub fn threads_in_status(status: []const u8) ?u32 {
    assert(status.len <= constants.status_bytes_max);
    const key = "Threads:";
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        const value = std.mem.trim(u8, line[key.len..], " \t");
        return std.fmt.parseInt(u32, value, 10) catch null;
    }
    return null;
}

/// Debug builds only: the process has exactly one thread before `clone3`. An unreadable status
/// is not a reason to stop (a debug aid must not break a run), but a count is believed.
fn assert_single_threaded(host: Host) void {
    var buffer: [constants.status_bytes_max]u8 = undefined;
    const status = host.read_file("/proc/self/status", &buffer) catch return;
    const threads = threads_in_status(status) orelse return;
    assert(threads > 0); // This process is one of them.
    assert(threads == 1);
}

// ---- The parent ----------------------------------------------------------------------------

/// Which ends of the two pipes this process still holds.
const Open = struct {
    ready_read: bool,
    ready_write: bool,
    report_read: bool,
    report_write: bool,

    fn any(open: Open) bool {
        assert(@sizeOf(Open) == 4); // Four flags, one per pipe end.
        return open.ready_read or open.ready_write or open.report_read or open.report_write;
    }
};

const Session = struct {
    host: Host,
    plan: *const Plan,
    child: child_mod.Context,
    pid: ?host_mod.Pid,
    open: Open,
    report: sync.Report,
    status: ?host_mod.ExitStatus,

    fn start(session: *Session, host: Host, plan: *const Plan) void {
        assert(plan.count == plan_mod.steps_count);
        assert(plan.candidates_count > 0);
        session.host = host;
        session.plan = plan;
        session.child = .{ .host = host, .plan = plan, .ready = undefined, .report = undefined };
        session.pid = null;
        session.open = .{
            .ready_read = false,
            .ready_write = false,
            .report_read = false,
            .report_write = false,
        };
        session.report.reset();
        session.status = null;
        assert(!session.open.any());
        assert(session.pid == null);
    }

    /// Runs the parent's steps in order. A step that fails ends the run: the child is killed and
    /// reaped, every descriptor closed, and the diagnostic names the step. After the last step,
    /// a failure the child reported is diagnosed the same way.
    fn execute(session: *Session, diag: *Diag, info: diagnose.RunInfo) Error!void {
        const host = session.host;
        const plan = session.plan;
        assert(diag.code == null);
        assert(session.pid == null);
        for (plan.steps[0..plan.count], 0..) |*step, index| {
            if (plan_mod.side_of(step.kind) != .parent) continue;
            host.begin_step(@intCast(index));
            session.parent_step(step) catch |err| {
                const failure: diagnose.Failure = .{
                    .step = @intCast(index),
                    .err = err,
                    .errno = host.last_errno(),
                };
                host.begin_step(host_mod.step_none);
                session.abandon();
                diagnose.step_failed(host, diag, plan, info, failure);
                return error.StartFailed;
            };
        }
        host.begin_step(host_mod.step_none);
        session.finish();
        if (session.report.failure) |record| {
            const failure: diagnose.Failure = .{
                .step = record.step,
                .err = host_mod.error_for_errno(record.errno),
                .errno = record.errno,
            };
            diagnose.step_failed(host, diag, plan, info, failure);
            return error.StartFailed;
        }
        assert(session.status != null);
    }

    fn parent_step(session: *Session, step: *const plan_mod.Step) host_mod.Error!void {
        const host = session.host;
        const plan = session.plan;
        assert(plan_mod.side_of(step.kind) == .parent);
        if (step.kind != .make_pipes and step.kind != .spawn) assert(session.pid != null);
        switch (step.kind) {
            .make_pipes => try session.make_pipes(),
            .spawn => try session.spawn(),
            .deny_setgroups => try host.write_id_map(
                session.pid.?,
                .setgroups,
                plan.text(step.target),
            ),
            .write_gid_map => try host.write_id_map(
                session.pid.?,
                .gid_map,
                plan.text(step.target),
            ),
            .write_uid_map => try host.write_id_map(
                session.pid.?,
                .uid_map,
                plan.text(step.target),
            ),
            .release_child => try session.release_child(),
            .await_report => try session.await_report(),
            .reap => try session.reap(),
            else => unreachable, // The child's steps.
        }
    }

    fn make_pipes(session: *Session) host_mod.Error!void {
        assert(!session.open.any());
        const ready = try session.host.pipe();
        const report = session.host.pipe() catch |err| {
            session.host.close(ready.read);
            session.host.close(ready.write);
            return err;
        };
        assert(ready.read != report.read);
        assert(ready.write != report.write);
        session.child.ready = ready;
        session.child.report = report;
        session.open = .{
            .ready_read = true,
            .ready_write = true,
            .report_read = true,
            .report_write = true,
        };
    }

    fn spawn(session: *Session) host_mod.Error!void {
        const host = session.host;
        assert(session.open.any());
        assert(session.pid == null);
        const flags: host_mod.SpawnFlags = .{
            .user = true,
            .mount = true,
            .pid = true,
            .uts = true,
            .ipc = true,
        };
        session.pid = try host.spawn(flags, child_mod.entry, &session.child);
        // From here a write to the ready pipe may find no reader; that is an error to report.
        host.ignore_broken_pipe(true);
        // The child has its own copies of these. Closing ours is what makes end of file reach
        // the child if this process dies, and the parent if the child's command starts.
        host.close(session.child.ready.read);
        session.open.ready_read = false;
        host.close(session.child.report.write);
        session.open.report_write = false;
    }

    fn release_child(session: *Session) host_mod.Error!void {
        assert(session.open.ready_write);
        const byte = [1]u8{child_mod.go_ahead};
        assert(session.pid != null);
        try session.host.write_handle_all(session.child.ready.write, &byte);
        session.host.close(session.child.ready.write);
        session.open.ready_write = false;
        assert(!session.open.ready_read); // The spawn step closed the other end.
    }

    /// Reads the report pipe to its end: until the child's command starts (the pipe closes on
    /// `exec`) or the child ends after a failure.
    fn await_report(session: *Session) host_mod.Error!void {
        assert(session.open.report_read);
        var bytes: [constants.sync_record_bytes * constants.sync_records_max]u8 = undefined;
        var length: u32 = 0;
        var calls: u32 = 0;
        while (calls < constants.sync_read_calls_max) : (calls += 1) {
            // A full buffer still needs one read to see the end of file.
            var extra: [1]u8 = undefined;
            const room: []u8 = if (length == bytes.len) &extra else bytes[length..];
            const count = try session.host.read_some(session.child.report.read, room);
            if (count == 0) break;
            if (length == bytes.len) return error.Stalled; // More records than a child can write.
            length += count;
        } else return error.Stalled;
        session.host.close(session.child.report.read);
        session.open.report_read = false;
        // Records come only from our own child; a malformed one is a bug, not an operating error.
        const well_formed = session.report.parse(bytes[0..length]);
        assert(well_formed);
    }

    fn reap(session: *Session) host_mod.Error!void {
        const pid = session.pid.?;
        assert(!session.open.any()); // The child's command started, so nothing is left to close.
        session.status = try session.host.wait_for(pid);
        session.pid = null;
        assert(session.status != null);
    }

    /// After a failed step: the child is killed (it may be blocked waiting for us) and reaped,
    /// and every descriptor closed. Errors here are ignored: there is nothing left to do about
    /// them, and the step's own failure is what the user needs to see.
    fn abandon(session: *Session) void {
        const host = session.host;
        if (session.pid) |pid| {
            host.signal(pid, constants.signal_kill) catch {};
            _ = host.wait_for(pid) catch {};
            session.pid = null;
        }
        session.close_all();
        host.ignore_broken_pipe(false);
        assert(!session.open.any());
        assert(session.pid == null);
    }

    fn close_all(session: *Session) void {
        const host = session.host;
        assert(session.pid == null); // The child is gone before its pipes are closed.
        if (session.open.ready_read) host.close(session.child.ready.read);
        if (session.open.ready_write) host.close(session.child.ready.write);
        if (session.open.report_read) host.close(session.child.report.read);
        if (session.open.report_write) host.close(session.child.report.write);
        session.open = .{
            .ready_read = false,
            .ready_write = false,
            .report_read = false,
            .report_write = false,
        };
    }

    /// The parent's steps all ran: nothing is open, no child is left, SIGPIPE is as it was.
    fn finish(session: *Session) void {
        assert(session.pid == null);
        assert(!session.open.any());
        session.host.ignore_broken_pipe(false);
    }

    fn fill(session: *const Session, outcome: *Outcome, name: []const u8) void {
        assert(name.len > 0);
        assert(session.report.failure == null);
        outcome.status = session.status.?;
        outcome.name_len = @intCast(name.len);
        @memcpy(outcome.name[0..name.len], name);
        outcome.notes_count = 0;
        for (session.report.note_slice()) |record| {
            const note = &outcome.notes[outcome.notes_count];
            note.* = .{};
            var buffer: [160]u8 = undefined;
            const text = diagnose.skipped_note(session.plan, record.step, record.errno, &buffer);
            note.print("{s}", .{text});
            outcome.notes_count += 1;
        }
    }
};

const testing = std.testing;

test "threads_in_status reads the Threads line and nothing else" {
    // Goal: the debug assertion believes a count only when the line is well formed.
    const typical = "Name:\tzbx\nThreads:\t1\nVmRSS: 3 kB\n";
    try testing.expectEqual(@as(?u32, 1), threads_in_status(typical));
    try testing.expectEqual(@as(?u32, 12), threads_in_status("Threads:   12\n"));
    try testing.expectEqual(@as(?u32, null), threads_in_status("Name:\tzbx\n"));
    try testing.expectEqual(@as(?u32, null), threads_in_status("Threads:\tmany\n"));
    try testing.expectEqual(@as(?u32, null), threads_in_status(""));
    try testing.expectEqual(@as(?u32, 2), threads_in_status("Threads: 2"));
    try testing.expectEqual(@as(?u32, null), threads_in_status("xThreads: 2\n"));
}
