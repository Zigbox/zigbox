//! The parent's side of a run, as a state machine over the plan's parent steps: make the pipes,
//! create the child, write the id maps (directly, or through the helpers), let the child go,
//! read its report; and later wait for it, forwarding signals. `run.zig` drives it and owns the
//! library surface; the child's side is `child.zig`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const child_mod = @import("child.zig");
const diagnose = @import("diagnose.zig");
const plan_mod = @import("plan.zig");
const scope_mod = @import("scope.zig");
const signals = @import("signals.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;

/// The run did not start the command; the reason is in the `Diag`.
pub const Error = error{StartFailed};

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

/// How a helper ended, kept for the diagnostic.
const HelperRecord = struct {
    status: host_mod.ExitStatus,
    output: [constants.helper_output_bytes_max]u8,
    output_len: u32,
};

pub const Session = struct {
    host: Host,
    plan: *const Plan,
    child: child_mod.Context,
    pid: ?host_mod.Pid,
    open: Open,
    report: sync.Report,
    helper: ?HelperRecord,
    /// Why the scope step failed, for its diagnostic.
    scope_problem: ?scope_mod.Problem,
    /// The first signal zbx replaced with SIGKILL because PID 1 had no handler for it.
    substituted: ?u8,

    pub fn start(session: *Session, host: Host, plan: *const Plan) void {
        assert(plan.count == plan.steps_expected());
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
        session.helper = null;
        session.scope_problem = null;
        session.substituted = null;
        assert(!session.open.any());
        assert(session.pid == null);
    }

    /// Runs the parent's steps up to the container's command starting: everything but `reap`,
    /// which `wait` does. A step that fails ends the run: the child is killed and reaped, every
    /// descriptor closed, and the diagnostic names the step. A failure the child reported is
    /// diagnosed the same way.
    pub fn execute(session: *Session, diag: *Diag, info: diagnose.RunInfo) Error!void {
        const host = session.host;
        const plan = session.plan;
        assert(diag.code == null);
        assert(session.pid == null);
        for (plan.steps[0..plan.count], 0..) |*step, index| {
            if (plan_mod.side_of(step.kind) != .parent) continue;
            if (step.kind == .reap) continue;
            host.begin_step(@intCast(index));
            session.parent_step(step) catch |err| {
                const failure: diagnose.Failure = .{
                    .step = @intCast(index),
                    .err = err,
                    .errno = host.last_errno(),
                };
                host.begin_step(host_mod.step_none);
                session.abandon();
                diagnose.step_failed(host, diag, plan, info, failure, session.details());
                return error.StartFailed;
            };
        }
        host.begin_step(host_mod.step_none);
        if (session.report.failure) |record| {
            session.abandon();
            const failure: diagnose.Failure = .{
                .step = record.step,
                .err = host_mod.error_for_errno(record.errno),
                .errno = record.errno,
            };
            diagnose.step_failed(host, diag, plan, info, failure, .{});
            return error.StartFailed;
        }
        session.finish();
    }

    /// What the diagnostic of a failed step may need besides the step itself.
    fn details(session: *const Session) diagnose.Details {
        assert(session.plan.scoped == (session.plan.scope_name.len > 0));
        const scope: ?*const scope_mod.Problem = if (session.scope_problem) |*problem|
            problem
        else
            null;
        return .{ .helper = session.helper_end(), .scope = scope };
    }

    fn helper_end(session: *const Session) ?diagnose.HelperEnd {
        // A pointer into the session, not a copy: the output is read after this returns.
        if (session.helper) |*record| {
            assert(record.output_len <= record.output.len);
            return .{ .status = record.status, .output = record.output[0..record.output_len] };
        }
        return null;
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
            .run_newuidmap, .run_newgidmap => try session.run_helper(step),
            .start_scope => try session.start_scope(),
            .release_child => try session.release_child(),
            .await_report => try session.await_report(),
            .reap => unreachable, // `wait` does it.
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

    /// Runs `newuidmap` or `newgidmap` for the child: its name, the child's pid, and the words
    /// of the map the plan holds. A helper that does not end with status 0 is a failed step
    /// whose details stay in `helper` for the diagnostic.
    fn run_helper(session: *Session, step: *const plan_mod.Step) host_mod.Error!void {
        const plan = session.plan;
        const path = plan.text(step.target);
        var storage: [constants.helper_map_bytes_max + 16]u8 = undefined;
        var argv: [constants.helper_words_max]?[*:0]const u8 = undefined;
        const base = std.fs.path.basename(path);
        argv[0] = @ptrCast(path.ptr + (path.len - base.len));
        var used: usize = 0;
        var count: usize = 1;
        const pid = session.pid.?;
        // Cannot fail: a pid has at most ten digits and the storage holds 16 bytes more.
        const pid_text = std.fmt.bufPrint(storage[used..], "{d}", .{pid}) catch unreachable;
        storage[pid_text.len] = 0;
        argv[count] = @ptrCast(&storage[0]);
        count += 1;
        used = pid_text.len + 1;
        var words = std.mem.splitScalar(u8, plan.text(step.source), ' ');
        while (words.next()) |word| {
            assert(word.len > 0);
            assert(count + 1 < argv.len);
            @memcpy(storage[used..][0..word.len], word);
            storage[used + word.len] = 0;
            argv[count] = @ptrCast(&storage[used]);
            count += 1;
            used += word.len + 1;
        }
        argv[count] = null;
        const none = [_:null]?[*:0]const u8{};
        var record: HelperRecord = undefined;
        const result = try session.host.run_helper(.{
            .path = path,
            .argv = @ptrCast(&argv),
            .envp = &none,
        }, &record.output);
        record.status = result.status;
        record.output_len = result.output_len;
        session.helper = record;
        switch (result.status) {
            .exited => |code| if (code == 0) return,
            .signaled => {},
        }
        return error.IoFailed;
    }

    /// Asks for the container's scope with the child's pid in it (scope.zig) and waits for the
    /// job. The child is blocked waiting for `release_child`, so it runs nothing until the scope
    /// and its limits exist. The bus connection lives for this step only.
    fn start_scope(session: *Session) host_mod.Error!void {
        assert(session.plan.scoped);
        assert(session.scope_problem == null);
        var problem: scope_mod.Problem = undefined;
        if (scope_mod.start(session.host, session.plan, session.pid.?, &problem)) return;
        session.scope_problem = problem;
        return error.IoFailed;
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

    // ---- Waiting ----

    /// Waits for the container to end, forwarding the signals zbx catches. The signals are
    /// blocked while it waits, so one that arrives between two looks waits in the queue and is
    /// read next: none is lost, and no handler runs. The loop ends only when the child does
    /// (`wait_event` returns its exit); a flood of signals is cut off by killing it.
    pub fn wait(session: *Session) host_mod.Error!host_mod.ExitStatus {
        const host = session.host;
        assert(session.pid != null);
        assert(!session.open.any());
        try host.block_signals(true);
        var received: u32 = 0;
        const status = while (true) {
            const event = host.wait_event(session.pid.?) catch |err| {
                host.block_signals(false) catch {};
                return err;
            };
            switch (event) {
                .exited => |ended| break ended,
                .signal => |number| {
                    received += 1;
                    assert(received < std.math.maxInt(u32));
                    session.forward(number, received > constants.forwarded_signals_max);
                },
            }
        };
        session.pid = null;
        host.block_signals(false) catch {}; // The child is gone; a mask that stays is harmless.
        return session.reported_status(status);
    }

    /// What zbx reports: a container that died of the SIGKILL zbx sent in place of a signal
    /// died of that signal, as it would have without PID 1's protection.
    fn reported_status(session: *const Session, status: host_mod.ExitStatus) host_mod.ExitStatus {
        const replaced = session.substituted orelse return status;
        assert(replaced != constants.signal_kill);
        switch (status) {
            .signaled => |number| {
                if (number == constants.signal_kill) return .{ .signaled = replaced };
            },
            .exited => {},
        }
        return status;
    }

    /// Sends `number` to the container as the rule says (signals.zig), and notes a replacement.
    fn forward(session: *Session, number: u8, flooded: bool) void {
        assert(number > 0);
        assert(session.pid != null);
        session.send(number, flooded) catch {}; // The container may just have ended.
    }

    /// Delivers a signal to the container's PID 1, replacing it with SIGKILL when PID 1 has no
    /// handler for it (or when `force` says to end the container).
    pub fn send(session: *Session, number: u8, force: bool) host_mod.Error!void {
        const host = session.host;
        const pid = session.pid.?;
        assert(pid > 1);
        assert(number > 0);
        assert(number < 65);
        const state: ?host_mod.SignalState = host.signal_state(pid) catch null;
        const action: signals.Action = if (force) .kill else signals.decide(state, number);
        switch (action) {
            .forward => try host.signal(pid, number),
            .kill => {
                if (session.substituted == null) session.substituted = number;
                try host.signal(pid, constants.signal_kill);
            },
        }
    }

    /// After a failed step: the child is killed (it may be blocked waiting for us) and reaped,
    /// and every descriptor closed. Errors here are ignored: there is nothing left to do about
    /// them, and the step's own failure is what the user needs to see.
    pub fn abandon(session: *Session) void {
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

    /// The command started: nothing is open, the child runs, SIGPIPE is as it was.
    fn finish(session: *Session) void {
        assert(session.pid != null);
        assert(!session.open.any());
        session.host.ignore_broken_pipe(false);
    }
};
