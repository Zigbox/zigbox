//! The runtime library: run a container in the foreground, or under a caller that supervises it.
//! Its shape follows the `Runtime` contract of Zigcube's HANDOFF.md, so the two map one to one
//! when Zigcube's agent links this module (`zigbox`): `start`, `wait`, `signal`, `inspect`, a
//! `Spec`, a `Handle`, a `Status` and an `ExitReason`. Nothing here prints. A refusal is a coded
//! `Diag`; a warning is handed to the caller's `Warn` as it happens, before the container's
//! command can write a byte, so a terminal user sees it first.
//!
//! Process model (docs/briefs/M1-shell.md): the caller's process stays in the host PID namespace
//! as the parent. `clone3` creates a child in new user, mount, PID, UTS and IPC namespaces. The
//! child is PID 1 of its namespace, sets the container up and runs the command; there is no init
//! shim. Two pipes carry the synchronisation: the parent tells the child when the id maps are
//! written (`ready`), and the child tells the parent about a failed or skipped step (`report`).
//!
//! The parts of the contract that come in M2, and where each attaches (none changes the plan's
//! steps, the pipes or the record format):
//!   - `stop` with a grace period is `signal(SIGTERM)`, a timer around `wait`, then
//!     `signal(SIGKILL)`. `wait` already takes signals as events, so the timer is one more.
//!   - `list` reads the records directory (`records.zig`), which already keeps one record per run
//!     by name; no registry is added.
//!   - Re-adoption after a restart reads a record whose exit is `.running`, finds the container's
//!     PID 1 by the pid the record will gain in a later version (the version field is there for
//!     that), and waits on it through a pidfd instead of `wait4`.
//!   - The event stream is the `report` pipe kept open for the container's life, with more record
//!     kinds (`sync.zig`) for started, stopped and limit events.
//!   - A detached run is `start` without `wait` in a supervisor process that is not the caller.
//!   - `oom` and `pid_limit` are in `ExitReason` since slice 2 of M2: `wait` reads the scope's
//!     `memory.events` and `pids.events` the moment PID 1 is reaped.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const codes = @import("../diag/codes.zig");
const render = @import("../diag/render.zig");
const diagnose = @import("diagnose.zig");
const ids = @import("ids.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const scope_mod = @import("scope.zig");
const scope_text = @import("scope_text.zig");
const session_mod = @import("session.zig");
const spec_mod = @import("spec.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;
const Session = session_mod.Session;

pub const Spec = spec_mod.Spec;
pub const Label = spec_mod.Label;
pub const Limits = spec_mod.Limits;

/// The run did not start the command; the reason is in the `Diag`.
pub const Error = session_mod.Error;

/// Where a run is. `starting` is only seen from inside `start`.
pub const Status = enum { starting, running, stopped };

/// How the container's PID 1 ended, before the cgroup's counters are looked at.
pub const Ended = union(enum) {
    exited: u8,
    signaled: u8,

    pub fn code(ended: Ended) u8 {
        assert(@backingInt(ended) <= 1);
        switch (ended) {
            .exited => |value| return value,
            .signaled => |number| {
                assert(number > 0);
                assert(number < constants.signal_number_max);
                return constants.exit_signal_offset + number;
            },
        }
    }
};

/// The kernel's OOM killer killed something in the container's cgroup. The exit code is 137
/// whatever PID 1 did, so a script can tell; `ended` keeps what PID 1 did, for `--verbose`.
pub const Oom = struct {
    /// The `--memory` limit; null if there was none (an ancestor's limit, or the machine's).
    limit_bytes: ?u64,
    ended: Ended,
};

/// The container hit its process limit (a fork was refused). The exit code is PID 1's own.
pub const PidLimit = struct {
    limit: ?u32,
    ended: Ended,
};

/// Why a run ended.
pub const ExitReason = union(enum) {
    oom: Oom,
    pid_limit: PidLimit,
    exited: u8,
    /// Killed by this signal. A container that died of the SIGKILL zbx sent in place of a signal
    /// PID 1 had no handler for is reported with that signal.
    signaled: u8,
    /// The command never started; the diagnostic says why.
    start_failed: Diag,
    /// zbx could not wait for the container to the end (`Handle.lost_diag` says why).
    lost,

    /// The process exit code that stands for this: the command's own, or 128 plus its signal.
    /// Null if the command did not run to an end.
    pub fn code(reason: *const ExitReason) ?u8 {
        switch (reason.*) {
            .exited => |value| return value,
            .signaled => |number| {
                assert(number > 0);
                assert(number < constants.signal_number_max);
                return constants.exit_signal_offset + number;
            },
            .oom => return constants.exit_signal_offset + constants.signal_kill,
            .pid_limit => |hit| return hit.ended.code(),
            .start_failed, .lost => return null,
        }
    }

    /// The word the JSON `container_exit.reason` and the run record use.
    pub fn word(reason: *const ExitReason) []const u8 {
        assert(@intFromPtr(reason) != 0);
        return switch (reason.*) {
            .oom => "oom",
            .pid_limit => "pid_limit",
            .exited => "exited",
            .signaled => "signal",
            .start_failed => "start_failed",
            .lost => "lost",
        };
    }
};

/// A warning, handed over as it happens. The diagnostic is only valid during the call.
pub const Warn = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, diag: *const Diag) void,
};

pub const StartOptions = struct {
    warn: ?Warn = null,
};

pub const Note = text_util.Bounded(160);

/// A running (or finished) container. It holds pointers into itself and into the `Spec`'s
/// strings (the command and labels, for the record written at the end): neither may move or be
/// freed until `wait` has returned.
pub const Handle = struct {
    host: Host,
    status: Status,
    plan: Plan,
    session: Session,
    name: [constants.container_name_bytes_max]u8,
    name_len: u8,
    rootfs: [constants.rootfs_bytes_max]u8,
    rootfs_len: u16,
    command: []const []const u8,
    labels: []const Label,
    started: u64,
    mapping: records.IdsMode,
    /// Where the record goes; null if there is nowhere (a warning said so).
    record_dir: ?records.Dir,
    warn: ?Warn,
    record_warned: bool,
    /// Steps that were allowed to fail and did (the devpts mount), as sentences.
    notes: [constants.sync_records_max + 1]Note,
    notes_count: u32,
    /// The limits the run was started with, for the exit report and the record.
    limits: spec_mod.Limits,
    /// Why the run ended, as the record says it; `none` until it has.
    end_reason: records.EndReason,
    /// Why `wait` returned `.lost`.
    lost_diag: Diag,

    pub fn name_slice(handle: *const Handle) []const u8 {
        assert(handle.name_len > 0);
        assert(handle.name_len <= constants.container_name_bytes_max);
        return handle.name[0..handle.name_len];
    }

    pub fn rootfs_slice(handle: *const Handle) []const u8 {
        assert(handle.rootfs_len > 0);
        return handle.rootfs[0..handle.rootfs_len];
    }

    pub fn note_slice(handle: *const Handle) []const Note {
        assert(handle.notes_count <= handle.notes.len);
        if (handle.notes_count > 0) assert(handle.notes[0].len > 0);
        return handle.notes[0..handle.notes_count];
    }

    fn report(handle: *const Handle, diag: *const Diag) void {
        assert(diag.code != null);
        if (handle.warn) |warn| warn.call(warn.context, diag);
    }
};

pub fn inspect(handle: *const Handle) Status {
    assert(handle.name_len > 0);
    return handle.status;
}

/// Starts the container described by `container`. On return the command has started and
/// `handle` is running; on `StartFailed` it did not, `diag` says why, and the run record (if one
/// was begun) says so too. `handle` is set up in place and must not move afterwards.
pub fn start(
    host: Host,
    container: *const Spec,
    options: StartOptions,
    handle: *Handle,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    handle.host = host;
    handle.status = .starting;
    handle.warn = options.warn;
    handle.record_warned = false;
    handle.notes_count = 0;
    handle.limits = container.limits;
    handle.end_reason = .none;
    handle.name_len = 0; // Set by `choose_name`; a caller can tell whether it ever was.
    handle.command = container.command;
    handle.labels = container.labels;
    try choose_name(host, container.name, handle, diag);
    try check_command(container.command, container.labels, diag);
    try check_rootfs(host, container.rootfs, handle, diag);
    try check_limits(container.limits, diag);

    var choice: ids.Choice = undefined;
    ids.choose(host, &choice);
    if (choice.warned) handle.report(&choice.warning);
    handle.mapping = if (choice.warned) .single else .full;
    // After the checks that need nothing from the host, and before anything is created: a run
    // with a limit and no way to enforce it is refused here, with nothing to clean up.
    const scope_input = try prepare_scope(handle, container.limits, diag);
    const input: plan_mod.Input = .{
        .rootfs = handle.rootfs_slice(),
        .name = handle.name_slice(),
        .command = container.command,
        .term = host.environment("TERM", constants.term_bytes_max),
        .uid = host.uid(),
        .gid = host.gid(),
        .mapping = choice.mapping,
        .scope = scope_input,
    };
    handle.plan.build(&input);
    // Namespace setup must happen before any thread exists (docs/SPEC.md, M1 acceptance).
    if (builtin.mode == .debug) assert_single_threaded(host);

    handle.started = host.time_now();
    begin_record(handle);
    handle.session.start(host, &handle.plan);
    const info: diagnose.RunInfo = .{
        .name = handle.name_slice(),
        .rootfs = handle.rootfs_slice(),
    };
    handle.session.execute(diag, info) catch |err| {
        assert(diag.code != null);
        handle.status = .stopped;
        save_record(handle, .{ .start_failed = diag.code.? }, host.time_now(), diag);
        finish_scope(handle);
        return err;
    };
    collect_notes(handle);
    handle.status = .running;
    assert(handle.session.pid != null);
}

/// Waits for the container to end, forwarding the signals this process receives. Call it once.
pub fn wait(handle: *Handle) ExitReason {
    assert(handle.status == .running);
    const host = handle.host;
    host.begin_step(@intCast(handle.plan.count - 1)); // The `reap` step.
    const result = handle.session.wait();
    host.begin_step(host_mod.step_none);
    handle.status = .stopped;
    const status = result catch |err| {
        const failure: diagnose.Failure = .{
            .step = @intCast(handle.plan.count - 1),
            .err = err,
            .errno = host.last_errno(),
        };
        handle.session.abandon();
        handle.lost_diag.reset();
        const info: diagnose.RunInfo = .{
            .name = handle.name_slice(),
            .rootfs = handle.rootfs_slice(),
        };
        diagnose.step_failed(host, &handle.lost_diag, &handle.plan, info, failure, .{});
        save_record(handle, .lost, host.time_now(), &handle.lost_diag);
        finish_scope(handle); // `abandon` ended the container.
        return .lost;
    };
    // First thing after the reap: the manager removes the cgroup once it is empty.
    const events = if (handle.plan.scoped)
        scope_mod.read_events(host, handle.session.scope_directory.slice())
    else
        scope_mod.Events{ .oom_kill = null, .pids_max = null };
    const ended: Ended = switch (status) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
    };
    const reason = classify(ended, events, handle.limits);
    handle.end_reason = switch (reason) {
        .oom => .oom,
        .pid_limit => .pid_limit,
        .exited => .exited,
        .signaled => .signal,
        .start_failed, .lost => unreachable, // `classify` makes only the four above.
    };
    const exit: records.Exit = switch (ended) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
    };
    save_record(handle, exit, host.time_now(), null);
    finish_scope(handle);
    return reason;
}

/// What the container's end was, given what the cgroup counted. An OOM kill outranks a process
/// limit; either outranks how PID 1 ended, which stays in the reason.
pub fn classify(ended: Ended, events: scope_mod.Events, limits: spec_mod.Limits) ExitReason {
    if (ended == .signaled) assert(ended.signaled > 0);
    if (limits.memory_bytes) |bytes| assert(bytes >= constants.limit_memory_bytes_min);
    if ((events.oom_kill orelse 0) > 0) {
        return .{ .oom = .{ .limit_bytes = limits.memory_bytes, .ended = ended } };
    }
    if ((events.pids_max orelse 0) > 0) {
        return .{ .pid_limit = .{ .limit = limits.pids, .ended = ended } };
    }
    return switch (ended) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
    };
}

/// Sees that the scope is gone now that the container has ended; if it is not, a warning.
fn finish_scope(handle: *Handle) void {
    assert(handle.status == .stopped);
    assert(handle.session.pid == null); // The container is gone: reaped or abandoned.
    var problem: scope_mod.Problem = undefined;
    if (handle.session.cleanup_scope(&problem)) return;
    var warning: Diag = undefined;
    warning.reset();
    const name = handle.plan.text(handle.plan.scope_name);
    diagnose.scope_not_cleaned(&warning, name, &problem);
    handle.report(&warning);
}

/// Sends a signal to the container's PID 1 as the forwarding rule says: a signal it has no
/// handler for is replaced by SIGKILL, so the signal's default action still happens.
pub fn signal(handle: *Handle, number: u8) host_mod.Error!void {
    assert(handle.status == .running);
    assert(number > 0);
    try handle.session.send(number, false);
}

/// The exit reason of a run that did not start, from the diagnostic that said why.
pub fn failed_start(diag: *const Diag) ExitReason {
    assert(diag.code != null);
    return .{ .start_failed = diag.* };
}

// ---- Checks --------------------------------------------------------------------------------

fn choose_name(host: Host, given: ?[]const u8, handle: *Handle, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (given) |name| {
        if (spec_mod.name_problem(name)) |problem| {
            diagnose.name_invalid(diag, name, problem);
            return error.StartFailed;
        }
        @memcpy(handle.name[0..name.len], name);
        handle.name_len = @intCast(name.len);
        return;
    }
    const prefix = constants.container_name_prefix;
    var random: [constants.container_name_hex_digits / 2]u8 = undefined;
    // A name is a label, not an identity: if the system has no randomness, a fixed name is
    // still a valid one, and failing a run over it would be worse.
    host.random_bytes(&random) catch @memset(&random, 0);
    const hex = "0123456789abcdef";
    @memcpy(handle.name[0..prefix.len], prefix);
    for (random, 0..) |byte, index| {
        handle.name[prefix.len + 2 * index] = hex[byte >> 4];
        handle.name[prefix.len + 2 * index + 1] = hex[byte & 15];
    }
    const length = prefix.len + constants.container_name_hex_digits;
    handle.name_len = @intCast(length);
    assert(spec_mod.name_problem(handle.name_slice()) == null);
}

fn check_command(command: []const []const u8, labels: []const Label, diag: *Diag) Error!void {
    // The command line parser refuses a missing program; a caller of the library must too.
    assert(command.len > 0);
    assert(command[0].len > 0);
    if (spec_mod.command_problem(command)) |problem| {
        diagnose.command_too_big(diag, problem);
        return error.StartFailed;
    }
    if (spec_mod.labels_problem(labels)) |index| {
        diagnose.label_too_big(diag, index);
        return error.StartFailed;
    }
}

fn check_rootfs(host: Host, rootfs: []const u8, handle: *Handle, diag: *Diag) Error!void {
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
    @memcpy(handle.rootfs[0..rootfs.len], rootfs);
    handle.rootfs_len = @intCast(rootfs.len);
}

/// The limits of a library caller, against the bounds the flags are held to.
fn check_limits(limits: spec_mod.Limits, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(diag.code == null);
    const found = spec_mod.limits_problem(limits) orelse return;
    var value: [constants.limit_text_bytes_max]u8 = undefined;
    const number: u64 = switch (found.kind) {
        .memory => limits.memory_bytes.?,
        .pids => limits.pids.?,
        .cpus => limits.cpu_millis.?,
    };
    // Cannot fail: a u64 has at most 20 digits and the buffer holds 24.
    const text = std.fmt.bufPrint(&value, "{d}", .{number}) catch unreachable;
    diagnose.limit_invalid(diag, found.kind, text, found.problem);
    return error.StartFailed;
}

/// Decides whether this run has a scope. It has one if the user's systemd manager answers; if
/// it does not, a run with a limit is refused (a limit nobody enforces is worse than none) and
/// a run without goes on, warning once, as M1 did.
fn prepare_scope(handle: *Handle, limits: spec_mod.Limits, diag: *Diag) Error!?plan_mod.ScopeInput {
    assert(diag.code == null);
    var found: scope_mod.Probe = undefined;
    var problem: scope_mod.Problem = undefined;
    if (scope_mod.probe(handle.host, &found, &problem)) {
        if (found.via.refused != null) {
            const note = &handle.notes[handle.notes_count];
            var buffer: [160]u8 = undefined;
            note.* = .{};
            note.print("{s}", .{scope_text.fallback_note(&found.via, &buffer)});
            handle.notes_count += 1;
        }
        return .{ .version = found.version, .limits = limits };
    }
    if (limits.any()) {
        diagnose.limit_without_cgroup(diag, &problem, limits);
        return error.StartFailed;
    }
    var warning: Diag = undefined;
    warning.reset();
    diagnose.running_without_scope(&warning, &problem);
    handle.report(&warning);
    return null;
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

// ---- The run record ------------------------------------------------------------------------

/// Writes the record that says the run began, and prunes the oldest. Nothing here can stop the
/// run: a record that cannot be kept is a warning (ZBX-W0202, ZBX-W0203).
fn begin_record(handle: *Handle) void {
    assert(handle.status == .starting);
    assert(handle.name_len > 0);
    var dir: records.Dir = undefined;
    if (!records.locate(handle.host, &dir)) {
        handle.record_dir = null;
        warn_not_saved(handle, null, null);
        return;
    }
    handle.record_dir = dir;
    records.ensure(handle.host, &dir) catch |err| {
        handle.record_dir = null;
        warn_not_saved(
            handle,
            dir.text(),
            .{ .step = 0, .err = err, .errno = handle.host.last_errno() },
        );
        return;
    };
    save_record(handle, .running, null, null);
    if (handle.record_dir == null) return;
    var skipped: records.Skipped = undefined;
    records.prune(handle.host, &dir, handle.name_slice(), &skipped) catch return;
    if (skipped.count == 0) return;
    var warning: Diag = undefined;
    warning.reset();
    diagnose.records_skipped(&warning, dir.text(), &skipped);
    handle.report(&warning);
}

/// The diagnostic as the JSON line `--output json` prints, for the record. One too big to keep
/// is replaced by an object that names its code and says it was cut.
fn diagnostic_json(diag: *const Diag, buffer: *[constants.diag_json_bytes_max]u8) []const u8 {
    assert(diag.code != null);
    var big: [constants.output_bytes_max]u8 = undefined;
    const line = std.mem.trimEnd(u8, render.render(diag, .json, false, &big), "\n");
    if (line.len <= buffer.len) {
        @memcpy(buffer[0..line.len], line);
        return buffer[0..line.len];
    }
    const format = "{{\"code\":\"{s}\",\"truncated\":true}}";
    // Cannot fail: a code name and a few words fit the buffer.
    return std.fmt.bufPrint(buffer, format, .{codes.full_name(diag.code.?)}) catch unreachable;
}

fn save_record(handle: *Handle, exit: records.Exit, ended: ?u64, why: ?*const Diag) void {
    const dir = handle.record_dir orelse return;
    assert(handle.name_len > 0);
    if (exit == .running) assert(ended == null);
    var json: [constants.diag_json_bytes_max]u8 = undefined;
    const view: records.View = .{
        .name = handle.name_slice(),
        .rootfs = handle.rootfs_slice(),
        .command = handle.command,
        .labels = handle.labels,
        .started = handle.started,
        .ended = if (exit == .running) null else ended,
        .exit = exit,
        .ids = handle.mapping,
        .reason = handle.end_reason,
        .limits = handle.limits,
        .scope = if (handle.plan.scoped) handle.plan.text(handle.plan.scope_name) else "",
        .zbx_version = build_options.version,
        .diagnostic = if (why) |found| diagnostic_json(found, &json) else "",
    };
    records.save(handle.host, &dir, &view) catch |err| {
        const failure: diagnose.Failure = .{
            .step = 0,
            .err = err,
            .errno = handle.host.last_errno(),
        };
        warn_not_saved(handle, dir.text(), failure);
    };
}

/// Tells the caller once per run that the record is not being kept.
fn warn_not_saved(handle: *Handle, directory: ?[]const u8, failure: ?diagnose.Failure) void {
    if (handle.record_warned) return;
    if (directory) |text| assert(text.len > 0);
    handle.record_warned = true;
    var warning: Diag = undefined;
    warning.reset();
    diagnose.record_not_saved(&warning, directory, failure);
    handle.report(&warning);
}

fn collect_notes(handle: *Handle) void {
    assert(handle.notes_count <= 1); // The bus note, if the inherited bus was not the one used.
    assert(handle.session.report.note_slice().len + handle.notes_count <= handle.notes.len);
    for (handle.session.report.note_slice()) |record| {
        const note = &handle.notes[handle.notes_count];
        note.* = .{};
        var buffer: [160]u8 = undefined;
        const text = diagnose.skipped_note(&handle.plan, record.step, record.errno, &buffer);
        note.print("{s}", .{text});
        handle.notes_count += 1;
    }
}

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
