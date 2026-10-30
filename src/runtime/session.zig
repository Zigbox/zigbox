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
const doctor = @import("../doctor.zig");
const pasta_mod = @import("pasta.zig");
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

/// What `Session.cleanup_scope` found.
pub const Cleanup = union(enum) {
    /// There was no scope to see to.
    none,
    done: scope_mod.Cleaned,
    failed,
};

/// The process that keeps the container's scope alive (`Host.start_keeper`), and the write end
/// of the pipe it waits on: closing that ends it.
const Keeper = struct {
    pid: host_mod.Pid,
    hold: host_mod.Handle,
};

/// pasta, from its step until `release_pasta`: its pid, and the read end of the pipe its ready
/// line comes on (until `await_pasta` has read it).
const Pasta = struct {
    pid: host_mod.Pid,
    ready: ?host_mod.Handle,
};

/// How a pasta that never became ready ended, kept for the diagnostic.
pub const PastaEnd = diagnose.PastaEnd;

pub const Session = struct {
    host: Host,
    plan: *const Plan,
    child: child_mod.Context,
    pid: ?host_mod.Pid,
    open: Open,
    report: sync.Report,
    helper: ?HelperRecord,
    /// The caller's room for the doctor's facts, for the diagnostic of a refused namespace.
    facts: *doctor.Facts,
    /// Why the scope step failed, for its diagnostic.
    scope_problem: ?scope_mod.Problem,
    /// The scope's cgroup directory (empty if unknown), and whether a scope may exist that
    /// `cleanup_scope` has to see to.
    scope_directory: scope_mod.Directory,
    scope_up: bool,
    /// The scope's keeper, from its step until `release_keeper`. While it lives the scope has a
    /// process in it, so the manager cannot remove the scope's cgroup and take its counters
    /// (`memory.events`, `pids.events`) with it before `run.zig` has read them.
    keeper: ?Keeper,
    /// pasta, for a plan with `--net user`, while it runs; and how it ended if it failed.
    pasta: ?Pasta,
    pasta_end: ?PastaEnd,
    /// The first signal zbx replaced with SIGKILL because PID 1 had no handler for it.
    substituted: ?u8,
    /// The container's PID 1 as the host sees it: set when it is spawned and never cleared, so
    /// that another thread can stop the container while this one waits for it.
    container_pid: u32,
    /// The container has been reaped: nothing is left to signal. Set by `wait`.
    reaped: std.atomic.Value(bool),
    /// `wait` stopped the container because the time given to it ran out.
    timed_out: bool,
    /// The container's standard output and error are pipes this process reads (the log).
    capture: bool,
    /// The read ends of those pipes, until the stream ends; and the write ends, from the pipes'
    /// making until the child has its copies.
    output_read: [2]?host_mod.Handle,
    output_write: [2]?host_mod.Handle,

    pub fn start(
        session: *Session,
        host: Host,
        plan: *const Plan,
        facts: *doctor.Facts,
        capture: bool,
    ) void {
        assert(plan.count == plan.steps_expected());
        assert(plan.candidates_count > 0);
        session.host = host;
        session.plan = plan;
        session.facts = facts;
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
        session.scope_directory = .{};
        session.scope_up = false;
        session.keeper = null;
        session.pasta = null;
        session.pasta_end = null;
        session.substituted = null;
        session.container_pid = 0;
        session.reaped = std.atomic.Value(bool).init(false);
        session.timed_out = false;
        session.capture = capture;
        session.output_read = .{ null, null };
        session.output_write = .{ null, null };
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
            diagnose.step_failed(host, diag, plan, info, failure, .{ .facts = session.facts });
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
        return .{
            .helper = session.helper_end(),
            .scope = scope,
            .facts = session.facts,
            .pasta = session.pasta_end,
        };
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
            .spawn_keeper => try session.spawn_keeper(),
            .start_scope => try session.start_scope(),
            .start_pasta => try session.start_pasta(),
            .await_pasta => try session.await_pasta(),
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
        if (!session.capture) return;
        session.make_output_pipes() catch |err| {
            session.close_all();
            return err;
        };
    }

    fn make_output_pipes(session: *Session) host_mod.Error!void {
        assert(session.capture);
        assert(session.output_read[0] == null);
        for (0..2) |at| {
            const pipe = try session.host.pipe();
            session.output_read[at] = pipe.read;
            session.output_write[at] = pipe.write;
        }
    }

    /// Closes the write ends the parent holds: the child has its own, and ours would keep the
    /// reader from ever seeing the end of the output.
    fn close_output_write(session: *Session) void {
        for (&session.output_write) |*end| {
            if (end.*) |handle| session.host.close(handle);
            end.* = null;
        }
    }

    /// For a caller that leaves a started run without waiting for it (a test): lets go of the
    /// pipes the container's output would have been read from.
    pub fn release_output(session: *Session) void {
        session.close_output_read();
    }

    fn close_output_read(session: *Session) void {
        for (&session.output_read) |*end| {
            if (end.*) |handle| session.host.close(handle);
            end.* = null;
        }
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
            .net = session.plan.isolated(),
            .output = if (session.capture) .{
                .stdout = session.output_write[0].?,
                .stderr = session.output_write[1].?,
            } else null,
        };
        session.pid = try host.spawn(flags, child_mod.entry, &session.child);
        session.container_pid = session.pid.?;
        session.close_output_write();
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

    /// Forks the scope's keeper, which blocks on a pipe until `release_keeper` closes it (see
    /// `Host.start_keeper`). It is forked after the child and before the scope, so that the
    /// child has no copy of the pipe and the scope request can name the keeper's pid.
    fn spawn_keeper(session: *Session) host_mod.Error!void {
        const host = session.host;
        assert(session.plan.scoped);
        assert(session.keeper == null);
        const hold = try host.pipe();
        const pid = host.start_keeper(hold.read) catch |err| {
            host.close(hold.read);
            host.close(hold.write);
            return err;
        };
        host.close(hold.read); // The keeper has its own copy; ours would keep it from seeing EOF.
        session.keeper = .{ .pid = pid, .hold = hold.write };
        assert(pid != session.pid.?);
    }

    /// Lets the keeper go and reaps it: its pipe is closed, which is its end of file. The scope
    /// then loses its last process (when the container is gone too) and the manager removes it.
    /// It is killed as well, so that a keeper that did not see the end of file (the kernel
    /// stopped it, say) cannot make the wait for it last: it is zbx's own child, so its pid is
    /// not reused before it is reaped here. Nothing here can fail in a way that helps anyone, so
    /// errors are not reported: a keeper left behind ends with zbx anyway.
    pub fn release_keeper(session: *Session) void {
        const host = session.host;
        const keeper = session.keeper orelse return;
        session.keeper = null;
        host.close(keeper.hold);
        host.signal(keeper.pid, constants.signal_kill) catch {};
        _ = host.wait_for(keeper.pid) catch {};
        assert(session.keeper == null);
    }

    /// Starts pasta for the child (`pasta.zig` has its command line): its stdout is a pipe whose
    /// write end only pasta holds once this returns, so that its end of file means pasta ended.
    fn start_pasta(session: *Session) host_mod.Error!void {
        const host = session.host;
        const plan = session.plan;
        assert(plan.has_pasta);
        assert(session.pasta == null);
        const ready = try host.pipe();
        var arguments: pasta_mod.Arguments = undefined;
        pasta_mod.build(&arguments, plan.publish_slice(), session.pid.?);
        const none = [_:null]?[*:0]const u8{};
        const request: host_mod.ExecRequest = .{
            .path = plan.text(plan.pasta_path),
            .argv = arguments.argv_z(),
            .envp = &none,
        };
        const log = plan.text(plan.pasta_log);
        const pid = host.start_program(request, ready.write, log) catch |err| {
            host.close(ready.read);
            host.close(ready.write);
            return err;
        };
        host.close(ready.write);
        session.pasta = .{ .pid = pid, .ready = ready.read };
        assert(pid != session.pid.?);
    }

    /// Reads pasta's ready line (its PID, once the interface is configured and the ports are
    /// bound) within `pasta_ready_timeout_ms`. A pasta that ends first, says something else or
    /// says nothing in time is a failed step: it is reaped (killed first if it still runs), and
    /// `pasta_end` says how it went for the diagnostic.
    fn await_pasta(session: *Session) host_mod.Error!void {
        const host = session.host;
        const pasta = &session.pasta.?;
        const read_end = pasta.ready.?;
        const read = read_ready(host, read_end, pasta.pid);
        host.close(read_end);
        pasta.ready = null;
        const outcome = read catch |err| {
            session.release_pasta(); // A pipe of ours that cannot be read: nothing to wait for.
            return err;
        };
        switch (outcome) {
            .ready => return,
            .ended => {
                const status = host.wait_for(pasta.pid) catch |err| {
                    session.pasta = null; // Not ours to wait for any more, whatever happened.
                    return err;
                };
                session.pasta = null;
                session.pasta_end = .{ .exited = status };
                return error.IoFailed;
            },
            .timed_out, .garbled => {
                session.pasta_end = if (outcome == .timed_out) .timed_out else .garbled;
                session.release_pasta();
                return if (outcome == .timed_out) error.TimedOut else error.IoFailed;
            },
        }
    }

    const ReadyOutcome = enum { ready, ended, timed_out, garbled };

    /// The ready pipe until a decision: a line that is `pid`, an end of file, anything else, or
    /// the time is up. Each read returns a byte or more, an end of file or a timeout, so the
    /// loop's bound covers a ready line read a byte at a time.
    fn read_ready(
        host: Host,
        read_end: host_mod.Handle,
        pid: host_mod.Pid,
    ) host_mod.Error!ReadyOutcome {
        var line: [constants.pasta_ready_line_bytes_max]u8 = undefined;
        var length: u32 = 0;
        const started = host.monotonic_ms();
        for (0..constants.pasta_ready_reads_max) |_| {
            const spent = host.monotonic_ms() -| started;
            if (spent >= constants.pasta_ready_timeout_ms) return .timed_out;
            const left: u32 = @intCast(constants.pasta_ready_timeout_ms - spent);
            const count = host.read_timeout(read_end, line[length..], left) catch |err| {
                if (err == error.TimedOut) continue;
                return err;
            };
            if (count == 0) return .ended;
            length += count;
            assert(length <= line.len);
            switch (pasta_mod.read_ready(line[0..length])) {
                .pid => |found| return if (found == pid) .ready else .garbled,
                .garbled => return .garbled,
                .partial => {},
            }
        }
        return .timed_out;
    }

    /// Ends pasta and reaps it: the container is gone or never ran, and the host's ports go with
    /// pasta. It is killed outright (it holds nothing a clean exit would save), and it is zbx's
    /// own child, so its pid is not reused before this reaps it. Errors are not reported: a
    /// pasta that cannot be signalled has already ended, and one left over ends by itself once
    /// the container's namespace is gone.
    pub fn release_pasta(session: *Session) void {
        const host = session.host;
        const pasta = session.pasta orelse return;
        session.pasta = null;
        if (pasta.ready) |read_end| host.close(read_end);
        host.signal(pasta.pid, constants.signal_kill) catch {};
        _ = host.wait_for(pasta.pid) catch {};
        assert(session.pasta == null);
    }

    /// Asks for the container's scope with the child's pid in it (scope.zig) and waits for the
    /// job. The child is blocked waiting for `release_child`, so it runs nothing until the scope
    /// and its limits exist. The bus connection lives for this step only.
    fn start_scope(session: *Session) host_mod.Error!void {
        assert(session.plan.scoped);
        assert(session.scope_problem == null);
        var problem: scope_mod.Problem = undefined;
        const pid = session.pid.?;
        const keeper_pid = session.keeper.?.pid;
        const started = scope_mod.start(
            session.host,
            session.plan,
            pid,
            keeper_pid,
            &session.scope_directory,
            &problem,
        );
        if (started) {
            session.scope_up = true;
            return;
        }
        // The scope exists, or may: the request went out and the answer was lost, or the job
        // ended badly. A refusal (a taken name above all: that scope is someone else's) means
        // there is nothing of ours to clean up.
        session.scope_up = switch (problem) {
            .bus => |failure| switch (failure.kind) {
                .remote => failure.stage == .job,
                .timeout, .io, .protocol => failure.stage == .call or failure.stage == .job,
                .no_bus, .auth_refused => false,
            },
            .bus_retried, .no_address, .bad_address, .scope_left => false,
            .no_cgroup_path, .cgroup_write => true,
            // The cgroup exists unless making it was what failed.
            .cgroupfs => |failure| failure.step != .make,
        };
        session.scope_problem = problem;
        return error.IoFailed;
    }

    /// After the container has ended (or never ran): makes sure the scope is gone. A scope that
    /// is not is a problem for the caller to warn about (ZBX-W0302).
    pub fn cleanup_scope(session: *Session, problem: *scope_mod.Problem) Cleanup {
        assert(session.pid == null);
        assert(session.scope_up == (session.scope_up and session.plan.scoped));
        if (!session.scope_up) return .none;
        session.scope_up = false;
        const name = session.plan.text(session.plan.scope_name);
        const directory = session.scope_directory.slice();
        const how = scope_mod.cleanup(session.host, name, directory, problem) orelse
            return .failed;
        return .{ .done = how };
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

    /// How long `wait` lets the container run, and then how it stops it.
    pub const WaitOptions = struct {
        /// Total wall time in milliseconds; zero is for ever.
        timeout_ms: u32 = 0,
        /// After the time is up: SIGTERM (as the forwarding rule sends it), then SIGKILL this
        /// many milliseconds later if the container is still there.
        grace_ms: u32 = constants.stop_grace_ms_default,
        /// Where the container's output goes while it runs (the session must have been started
        /// to capture it). Null: it is read and dropped.
        sink: ?Sink = null,
    };

    /// Takes what the container wrote. False: stop reading that stream, so the container's
    /// next write to it fails as a write to a closed pipe does.
    pub const Sink = struct {
        context: *anyopaque,
        call: *const fn (context: *anyopaque, stream: host_mod.Stream, bytes: []const u8) bool,
    };

    /// Waits for the container to end, forwarding the signals zbx catches. The signals are
    /// blocked while it waits, so one that arrives between two looks waits in the queue and is
    /// read next: none is lost, and no handler runs. The loop ends only when the child does
    /// (`wait_event` returns its exit); a flood of signals is cut off by killing it. When the
    /// options give a time, the container is stopped when it is up: SIGTERM, a grace period,
    /// SIGKILL (`timed_out` says so).
    pub fn wait(session: *Session, options: WaitOptions) host_mod.Error!host_mod.ExitStatus {
        const host = session.host;
        assert(session.pid != null);
        assert(!session.open.any());
        try host.block_signals(true);
        var received: u32 = 0;
        const began = host.monotonic_ms();
        var stage: enum { running, terminated, killed } = .running;
        var deadline: u64 = began + options.timeout_ms;
        const status = while (true) {
            const timed = stage != .killed and (stage != .running or options.timeout_ms > 0);
            const left: u64 = if (timed) deadline -| host.monotonic_ms() else 0;
            const slice_ms: u32 = if (timed) @intCast(@max(left, 1)) else 0;
            const event = session.next_event(slice_ms, options.sink) catch |err| {
                host.block_signals(false) catch {};
                return err;
            };
            switch (event) {
                .output => unreachable, // `next_event` takes output itself.
                .exited => |ended| break ended,
                .signal => |number| {
                    received += 1;
                    assert(received < std.math.maxInt(u32));
                    session.forward(number, received > constants.forwarded_signals_max);
                },
                .timeout => switch (stage) {
                    .running => {
                        session.timed_out = true;
                        session.forward(constants.signal_term, false);
                        stage = .terminated;
                        deadline = host.monotonic_ms() + options.grace_ms;
                    },
                    .terminated => {
                        // The grace is up: a real SIGKILL, reported as one.
                        host.signal(session.pid.?, constants.signal_kill) catch {};
                        stage = .killed;
                    },
                    .killed => unreachable, // A wait with no time cannot time out.
                },
            }
        };
        session.pid = null;
        session.reaped.store(true, .release);
        session.drain_output(options.sink);
        host.block_signals(false) catch {}; // The child is gone; a mask that stays is harmless.
        return session.reported_status(status);
    }

    /// The next event that is not output: while the container's streams have bytes, they are
    /// handed to the sink. `slice_ms` is the time left to wait (zero: for ever), counted over
    /// all the output taken on the way.
    fn next_event(session: *Session, slice_ms: u32, sink: ?Sink) host_mod.Error!host_mod.Event {
        const host = session.host;
        const began = host.monotonic_ms();
        for (0..constants.wait_timeout_ms_max) |_| {
            var watch: [2]host_mod.Handle = undefined;
            var which: [2]u8 = undefined;
            var count: u32 = 0;
            for (session.output_read, 0..) |end, at| {
                const handle = end orelse continue;
                watch[count] = handle;
                which[count] = @intCast(at);
                count += 1;
            }
            if (count == 0) return host.wait_event(session.pid.?, slice_ms);
            var left: u32 = 0;
            if (slice_ms > 0) {
                const spent = host.monotonic_ms() -| began;
                if (spent >= slice_ms) return .timeout;
                left = @intCast(slice_ms - spent);
            }
            const event = try host.wait_event_watching(session.pid.?, left, watch[0..count]);
            switch (event) {
                .output => |mask| {
                    for (0..count) |index| {
                        if (mask >> @intCast(index) & 1 == 1) session.pump(which[index], sink);
                    }
                },
                else => return event,
            }
        }
        unreachable; // The bound is a day of milliseconds; every pass takes output or returns.
    }

    /// Reads once from one stream and hands the bytes on. The end of the stream closes it.
    fn pump(session: *Session, at: u8, sink: ?Sink) void {
        const host = session.host;
        const handle = session.output_read[at].?;
        var buffer: [constants.log_pump_bytes]u8 = undefined;
        const count = host.read_some(handle, &buffer) catch 0;
        if (count == 0) return session.end_stream(at);
        const keep = if (sink) |target| target.call(target.context, stream_of(at), buffer[0..count]) else true;
        if (!keep) session.end_stream(at);
    }

    fn stream_of(at: u8) host_mod.Stream {
        assert(at < 2);
        return if (at == 0) .stdout else .stderr;
    }

    fn end_stream(session: *Session, at: u8) void {
        const handle = session.output_read[at] orelse return;
        session.host.close(handle);
        session.output_read[at] = null;
    }

    /// The container is gone: what it wrote and nobody has read yet is handed on, within a bound
    /// of time for a stream that something else still holds open.
    fn drain_output(session: *Session, sink: ?Sink) void {
        const host = session.host;
        for (0..2) |index| {
            const at: u8 = @intCast(index);
            for (0..constants.log_drain_reads_max) |_| {
                const handle = session.output_read[at] orelse break;
                var buffer: [constants.log_pump_bytes]u8 = undefined;
                const count = host.read_timeout(handle, &buffer, constants.log_drain_ms) catch 0;
                if (count == 0) {
                    session.end_stream(at);
                    break;
                }
                const keep = if (sink) |target|
                    target.call(target.context, stream_of(at), buffer[0..count])
                else
                    true;
                if (!keep) session.end_stream(at);
            }
            session.end_stream(at);
        }
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
        session.release_pasta();
        session.release_keeper();
        session.close_all();
        host.ignore_broken_pipe(false);
        assert(!session.open.any());
        assert(session.pid == null);
    }

    fn close_all(session: *Session) void {
        const host = session.host;
        session.close_output_write();
        session.close_output_read();
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
