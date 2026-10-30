//! A container after it has started, for a caller that may not be its parent: what is running,
//! how to stop one, how to find one again after the process that started it is gone, and what
//! changed since the last look. The operations of Zigcube's `Runtime` contract that `run.zig`
//! (start, wait, signal, inspect) does not cover.
//!
//! Everything is found from the run records (`records.zig`, version 3 has the host pid of the
//! container's PID 1) and the kernel, never from memory of this process, so a new process sees
//! the containers an earlier one started:
//!
//!   - `list` reads the records and checks which containers are alive, and adds the zbx scopes
//!     that are running without a record.
//!   - `adopt` makes a `Ref` to a running container by its name; `stop`, `signal` and `wait`
//!     work on a `Ref`, which a run's own `Handle` also gives (`ref_of`).
//!   - `Watcher.poll` compares what is there with what it saw last time and reports the changes.
//!
//! "Alive" is checked, not assumed: the pid answers `kill(pid, 0)`; its innermost pid is 1
//! (`NSpid` in `/proc/<pid>/status`, so it is a container's PID 1 and not a stranger that got
//! the number); and when the run had a scope, `/proc/<pid>/cgroup` names it and the scope's
//! `cgroup.events` says `populated 1`.
//!
//! Waiting is polling. `stop` and `wait` on a `Ref` of another process look every
//! `poll_step_ms`; `Watcher.poll` does not wait at all, and a status change is seen by the first
//! poll after it, so a caller that polls every `constants.events_poll_ms_max` sees every change
//! within that time (the record is written by the supervisor a moment after the cgroup empties:
//! until then a stopped container is reported by its pid alone).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const run = @import("run.zig");
const records = @import("records.zig");
const signals = @import("signals.zig");
const text_util = @import("../text.zig");

const Host = host_mod.Host;
const ExitReason = run.ExitReason;

/// Where a container is, as `list` finds it.
pub const State = enum {
    /// Its PID 1 is alive (or its supervisor is, finishing the record).
    running,
    /// It ended; the record says how.
    stopped,
    /// The record says it runs and nothing of it is left: its supervisor died with it unrecorded.
    lost,
};

/// One container: its record (or, for a scope without one, what the scope's name gives) and
/// where it is now.
pub const Entry = struct {
    state: State,
    /// False for a running scope that has no record of its own.
    has_record: bool,
    record: records.Parsed,

    /// The state as the contract's `Status`: `lost` is the `ExitReason` `.lost`, and a stopped
    /// container's reason is read from its record. (Kept as a method, not a field: an
    /// `ExitReason` can hold a `Diag`, 5.6 KiB, and `ps` lists dozens.)
    pub fn status(entry: *const Entry) run.Status {
        return switch (entry.state) {
            .running => .running,
            .lost => .{ .stopped = .lost },
            .stopped => .{ .stopped = exit_reason_of(&entry.record) },
        };
    }

    pub fn name(entry: *const Entry) []const u8 {
        return entry.record.name_slice();
    }
};

pub const ListError = error{
    /// Neither XDG_STATE_HOME nor HOME names a directory to keep records in.
    NoState,
    /// The runs directory could not be read.
    Unreadable,
};

/// Fills `out` with the containers, newest first, and returns how many (at most `out.len`).
/// A record that cannot be read or is newer than this reader is left out.
pub fn list(host: Host, out: []Entry) ListError!u32 {
    assert(out.len > 0);
    assert(out.len <= constants.runs_max + constants.scopes_listed_max);
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return error.NoState;
    var listing: host_mod.DirListing = undefined;
    listing.reset();
    records.names(host, &dir, &listing) catch |err| {
        // A state directory that was never made has no records; its scopes may still run.
        if (err != error.NotFound) return error.Unreadable;
        listing.reset();
    };
    var count: u32 = 0;
    for (0..listing.count) |at| {
        const stem = records.name_of(listing.name(@intCast(at))) orelse continue;
        if (count == out.len) break;
        const entry = &out[count];
        records.load(host, &dir, stem, &entry.record) catch continue;
        entry.has_record = true;
        entry.state = state_of(host, &entry.record);
        count += 1;
    }
    count = add_orphan_scopes(host, out, count);
    sort_newest_first(out[0..count]);
    return count;
}

fn newer(a: Entry, b: Entry) bool {
    assert(a.record.name_len > 0);
    assert(b.record.name_len > 0);
    return a.record.started > b.record.started;
}

fn sort_newest_first(entries: []Entry) void {
    assert(entries.len <= constants.scopes_listed_max + constants.runs_max);
    defer if (entries.len >= 2) assert(!newer(entries[entries.len - 1], entries[0]));
    // Insertion sort: at most a few dozen entries, and no allocation.
    var at: usize = 1;
    while (at < entries.len) : (at += 1) {
        var back = at;
        while (back > 0 and newer(entries[back], entries[back - 1])) : (back -= 1) {
            std.mem.swap(Entry, &entries[back], &entries[back - 1]);
        }
    }
}

/// The state a record's container is in now.
pub fn state_of(host: Host, record: *const records.Parsed) State {
    assert(record.name_len > 0);
    assert(record.scope_len <= constants.scope_name_bytes_max);
    if (alive(host, record.pid, record.scope_slice())) return .running;
    if (record.exit != .running) return .stopped;
    // The record was never finished. A supervisor that is still there is finishing it.
    if (record.supervisor != 0 and process_exists(host, record.supervisor)) return .running;
    return .lost;
}

fn process_exists(host: Host, pid: u32) bool {
    assert(pid > 0);
    host.signal(pid, 0) catch |err| return err == error.AccessDenied;
    return true;
}

/// Whether `pid` is the PID 1 of a container of ours, still running. See the module doc.
pub fn alive(host: Host, pid: u32, scope: []const u8) bool {
    assert(scope.len <= constants.scope_name_bytes_max);
    assert(pid != host.own_pid()); // We are never the PID 1 of a container we look at.
    if (pid == 0) return false;
    host.signal(pid, 0) catch return false;
    var buffer: [constants.status_bytes_max]u8 = undefined;
    var path: [48]u8 = undefined;
    // Cannot fail: "/proc/" and "/status" are 13 bytes and a pid at most ten digits.
    const status_path = std.fmt.bufPrint(&path, "/proc/{d}/status", .{pid}) catch unreachable;
    const status = host.read_file(status_path, &buffer) catch return false;
    if (!innermost_pid_is_one(status)) return false;
    // A PID 1 that ended and has not been reaped answers `kill(pid, 0)` and keeps its status
    // file. The scope's `populated` used to tell it from a live one; the scope's keeper keeps
    // the scope populated until the owner has read its counters, so the process says it itself.
    if (is_zombie(status)) return false;
    if (scope.len == 0) return true;
    // Cannot fail: "/proc/" and "/cgroup" are 14 bytes and a pid at most ten digits.
    const cgroup_path = std.fmt.bufPrint(&path, "/proc/{d}/cgroup", .{pid}) catch unreachable;
    const cgroup = host.read_file(cgroup_path, &buffer) catch return false;
    if (std.mem.indexOf(u8, cgroup, scope) == null) return false;
    return populated(host, cgroup);
}

/// `State:\tZ (zombie)` (or `X`, dead): the process ended and its parent has not collected it.
pub fn is_zombie(status: []const u8) bool {
    assert(status.len <= constants.status_bytes_max);
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        const key = "State:";
        if (!std.mem.startsWith(u8, line, key)) continue;
        const state = std.mem.trimStart(u8, line[key.len..], " \t");
        return state.len > 0 and (state[0] == 'Z' or state[0] == 'X');
    }
    return false;
}

/// PF_EXITING in a task's flags (`include/linux/sched.h`): `do_exit` sets it in `exit_signals`,
/// before anything else of the exit, and it is never cleared.
pub const task_flag_exiting: u64 = 0x00000004;

/// `/proc/<pid>/stat` says the process is exiting: PF_EXITING in its flags, field 9. The name in
/// field 2 is in parentheses and may hold spaces and parentheses itself, so the fields are
/// counted from the last `)`. A line that does not parse is not taken as exiting.
pub fn is_exiting(stat: []const u8) bool {
    assert(stat.len <= constants.status_bytes_max);
    const name_end = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return false;
    assert(name_end < stat.len);
    // After the name: state (3), ppid, pgrp, session, tty_nr, tpgid (8), flags (9).
    var fields = std.mem.tokenizeScalar(u8, stat[name_end + 1 ..], ' ');
    for (0..6) |_| _ = fields.next() orelse return false;
    const flags_text = fields.next() orelse return false;
    const flags = std.fmt.parseInt(u64, flags_text, 10) catch return false;
    return flags & task_flag_exiting != 0;
}

/// `NSpid:\t<host pid>\t...\t1`: more than one pid, the last is 1.
pub fn innermost_pid_is_one(status: []const u8) bool {
    assert(status.len <= constants.status_bytes_max);
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        const key = "NSpid:";
        if (!std.mem.startsWith(u8, line, key)) continue;
        var fields = std.mem.tokenizeAny(u8, line[key.len..], " \t");
        var last: []const u8 = "";
        var seen: u32 = 0;
        while (fields.next()) |field| : (seen += 1) last = field;
        return seen >= 2 and std.mem.eql(u8, last, "1");
    }
    return false;
}

/// The scope's `cgroup.events` says `populated 1`; if it cannot be read, the pid and the cgroup
/// line already agreed, so the container counts as alive.
fn populated(host: Host, cgroup: []const u8) bool {
    assert(cgroup.len <= constants.status_bytes_max);
    assert(cgroup.len > 0);
    const relative = @import("scope.zig").unified_path(cgroup) orelse return true;
    var path: [constants.cgroup_path_bytes_max + 48]u8 = undefined;
    const format = "/sys/fs/cgroup{s}/cgroup.events";
    const where = std.fmt.bufPrint(&path, format, .{relative}) catch return true;
    var events: [256]u8 = undefined;
    const text = host.read_file(where, &events) catch return true;
    const count = @import("scope.zig").event_value(text, "populated") orelse return true;
    return count == 1;
}

/// Adds the zbx scopes that are in the user's app.slice and have no record in `out`. They are
/// what a container looks like after its record was pruned or when another state directory
/// holds it. The directory is the standard one for the user's manager; a host that puts scopes
/// elsewhere shows none.
fn add_orphan_scopes(host: Host, out: []Entry, count_in: u32) u32 {
    assert(count_in <= out.len);
    assert(out.len <= constants.runs_max + constants.scopes_listed_max);
    var path: [128]u8 = undefined;
    const format = "/sys/fs/cgroup/user.slice/user-{d}.slice/user@{d}.service/app.slice";
    const uid = host.uid();
    const base = std.fmt.bufPrintSentinel(&path, format, .{ uid, uid }, 0) catch return count_in;
    var listing: host_mod.DirListing = undefined;
    listing.reset();
    host.list_directory(base, &listing) catch return count_in;
    var count = count_in;
    for (0..listing.count) |at| {
        const entry_name = listing.name(@intCast(at));
        const prefix = constants.scope_prefix;
        const suffix = constants.scope_suffix;
        if (!std.mem.startsWith(u8, entry_name, prefix)) continue;
        if (!std.mem.endsWith(u8, entry_name, suffix)) continue;
        if (entry_name.len <= prefix.len + suffix.len) continue;
        if (count == out.len) break;
        const stem = entry_name[prefix.len .. entry_name.len - suffix.len];
        if (stem.len > constants.container_name_bytes_max) continue;
        if (has_scope(out[0..count], entry_name)) continue;
        orphan(&out[count], stem, entry_name);
        count += 1;
    }
    return count;
}

fn has_scope(entries: []const Entry, scope: []const u8) bool {
    assert(scope.len > 0);
    assert(entries.len <= constants.runs_max + constants.scopes_listed_max);
    for (entries) |*entry| {
        if (std.mem.eql(u8, entry.record.scope_slice(), scope)) return true;
    }
    return false;
}

fn orphan(entry: *Entry, stem: []const u8, scope: []const u8) void {
    assert(stem.len <= constants.container_name_bytes_max);
    assert(stem.len > 0);
    assert(scope.len <= constants.scope_name_bytes_max);
    entry.state = .running;
    entry.has_record = false;
    const record = &entry.record;
    record.version = 0;
    @memcpy(record.name[0..stem.len], stem);
    record.name_len = @intCast(stem.len);
    record.rootfs_len = 0;
    record.started = 0;
    record.ended = null;
    record.exit = .running;
    record.ids = null;
    record.diagnostic_len = 0;
    record.reason = .none;
    record.detached = false;
    record.timed_out = false;
    @memcpy(record.scope[0..scope.len], scope);
    record.scope_len = @intCast(scope.len);
    record.limits = .{};
    record.pid = 0;
    record.supervisor = 0;
    record.command_len = 0;
    record.command_words = 0;
    record.labels_len = 0;
    record.labels_count = 0;
    record.network = null;
    record.publish_count = 0;
    record.env_names_len = 0;
    record.env_names_count = 0;
    record.state_len = 0;
    record.state_count = 0;
    record.mounts_len = 0;
    record.mounts_count = 0;
    record.user = null;
}

// ---- A container by reference ---------------------------------------------------------------

/// What `stop`, `signal` and `wait` need to reach a container: small, and copyable. A run's own
/// `Handle` gives one (`run.ref`), `adopt` makes one for a container another process started.
pub const Ref = struct {
    host: Host,
    pid: u32,
    name: text_util.Bounded(constants.container_name_bytes_max),
    scope: text_util.Bounded(constants.scope_name_bytes_max),
    /// For the container this process started and waits for: the flag `wait` sets once it has
    /// reaped it, after which the pid means nothing. Null for an adopted one.
    reaped: ?*const std.atomic.Value(bool),

    fn is_gone(ref: *const Ref) bool {
        assert(ref.pid > 0);
        assert(ref.scope.slice().len <= constants.scope_name_bytes_max);
        if (ref.reaped) |flag| return flag.load(.acquire);
        return !alive(ref.host, ref.pid, ref.scope.slice());
    }
};

pub const AdoptError = error{
    NoState,
    /// No record of that name.
    NoSuchContainer,
    /// The record cannot be used (damaged, newer, unreadable).
    BadRecord,
};

/// Finds the container called `name`. It need not be running: `state` says. The ref of a
/// stopped container is a ref to nothing (`stop` on it is a no-op).
pub fn adopt(host: Host, name: []const u8, ref: *Ref, state: *State) AdoptError!void {
    assert(name.len <= constants.arg_bytes_max);
    assert(@intFromPtr(ref) != @intFromPtr(state));
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return error.NoState;
    var record: records.Parsed = undefined;
    records.load(host, &dir, name, &record) catch |err| {
        return if (err == error.NotFound) error.NoSuchContainer else error.BadRecord;
    };
    state.* = state_of(host, &record);
    ref.host = host;
    ref.pid = record.pid;
    ref.name = .{};
    ref.name.print("{s}", .{name});
    ref.scope = .{};
    ref.scope.print("{s}", .{record.scope_slice()});
    ref.reaped = null;
}

/// How a `stop` went.
pub const Stopped = enum {
    /// It was not running.
    already_stopped,
    /// It ended within the grace period, after the signal.
    graceful,
    /// It was still there after the grace period and was sent SIGKILL.
    killed,
};

pub const StopError = error{
    /// The container could not be signalled (not ours to signal).
    NotPermitted,
    /// It was still there `kill_wait_ms` after SIGKILL: the kernel has not finished with it.
    Stuck,
};

pub const poll_step_ms: u32 = 20;
pub const kill_wait_ms: u32 = 5000;

/// SIGTERM to the container, then SIGKILL after `grace_ms` if it is still there. SIGTERM goes
/// the way a forwarded signal does (`signals.decide`): a PID 1 that has no handler for it would
/// ignore it, so it gets SIGKILL at once. Returns when the container is gone or SIGKILL has
/// been waited for. For a container this process waits for, "gone" is `wait` having reaped it:
/// stop it from another thread than the one in `wait`.
pub fn stop(
    ref: *const Ref,
    grace_ms: u32,
    kill_wait: u32,
) (StopError || host_mod.Error)!Stopped {
    const host = ref.host;
    assert(ref.pid > 0);
    assert(grace_ms <= constants.wait_timeout_ms_max);
    if (ref.is_gone()) return .already_stopped;
    const state: ?host_mod.SignalState = host.signal_state(ref.pid) catch null;
    const action = signals.decide(state, constants.signal_term);
    const signo = if (action == .forward) constants.signal_term else constants.signal_kill;
    deliver(ref, signo) catch |err| {
        if (err == error.NotFound) return .already_stopped;
        if (err == error.AccessDenied) return error.NotPermitted;
        return err;
    };
    if (action == .kill) return if (wait_gone(ref, kill_wait)) .killed else error.Stuck;
    if (wait_gone(ref, grace_ms)) return .graceful;
    deliver(ref, constants.signal_kill) catch |err| {
        if (err == error.NotFound) return .graceful;
        if (err == error.AccessDenied) return error.NotPermitted;
        return err;
    };
    if (wait_gone(ref, kill_wait)) return .killed;
    return error.Stuck;
}

fn deliver(ref: *const Ref, number: u8) host_mod.Error!void {
    assert(number > 0);
    assert(ref.pid > 0);
    try ref.host.signal(ref.pid, number);
}

/// Polls until the container is gone, up to `limit_ms`.
fn wait_gone(ref: *const Ref, limit_ms: u32) bool {
    assert(limit_ms <= constants.wait_timeout_ms_max + kill_wait_ms);
    assert(poll_step_ms > 0);
    const host = ref.host;
    const began = host.monotonic_ms();
    while (true) {
        if (ref.is_gone()) return true;
        const spent = host.monotonic_ms() - began;
        if (spent >= limit_ms) return false;
        const left: u64 = limit_ms - spent;
        host.sleep_ms(@intCast(@min(left, poll_step_ms)));
    }
}

/// A signal for the container, as the forwarding rule sends it.
pub fn signal(ref: *const Ref, number: u8) host_mod.Error!void {
    assert(number > 0);
    assert(ref.pid > 0);
    const state: ?host_mod.SignalState = ref.host.signal_state(ref.pid) catch null;
    const action = signals.decide(state, number);
    try deliver(ref, if (action == .forward) number else constants.signal_kill);
}

pub const WaitResult = union(enum) {
    /// The container is gone; the record says how it ended.
    ended: records.Parsed,
    /// `limit_ms` passed with the container still there.
    timeout,
};

/// Waits for a container this process did not start to end, then reads its record (waiting a
/// little for the supervisor to finish it, `record_settle_ms`).
pub fn wait_adopted(ref: *const Ref, limit_ms: u32, result: *WaitResult) records.LoadError!void {
    assert(ref.name.slice().len > 0);
    assert(ref.reaped == null); // A container of this process is waited for by `run.wait`.
    if (!wait_gone(ref, limit_ms)) {
        result.* = .timeout;
        return;
    }
    var dir: records.Dir = undefined;
    if (!records.locate(ref.host, &dir)) return error.NotFound;
    var record: records.Parsed = undefined;
    const began = ref.host.monotonic_ms();
    while (true) {
        try records.load(ref.host, &dir, ref.name.slice(), &record);
        if (record.exit != .running) break;
        if (ref.host.monotonic_ms() - began >= record_settle_ms) break;
        ref.host.sleep_ms(poll_step_ms);
    }
    result.* = .{ .ended = record };
}

pub const record_settle_ms: u32 = 3000;

/// How a record says the run ended, as the contract's `ExitReason`. A run that never started
/// carries only its code in the record, so its reason is a diagnostic with that code and one
/// cause that says where the rest is.
pub fn exit_reason_of(record: *const records.Parsed) ExitReason {
    assert(record.name_len > 0);
    assert(record.version <= constants.record_version);
    const ended: run.Ended = switch (record.exit) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
        .running, .lost => return .lost,
        .start_failed => |code| {
            var diag: @import("../diag/diag.zig").Diag = undefined;
            diag.reset();
            diag.raise(code);
            diag.cause("the run did not start; its record keeps the diagnostic", .{});
            return .{ .start_failed = diag };
        },
    };
    return switch (record.reason) {
        .oom => .{ .oom = .{ .limit_bytes = record.limits.memory_bytes, .ended = ended } },
        .pid_limit => .{ .pid_limit = .{ .limit = record.limits.pids, .ended = ended } },
        else => switch (ended) {
            .exited => |code| .{ .exited = code },
            .signaled => |number| .{ .signaled = number },
        },
    };
}

// ---- Changes --------------------------------------------------------------------------------

pub const EventKind = enum { started, stopped, lost };

pub const Event = struct {
    name: text_util.Bounded(constants.container_name_bytes_max),
    kind: EventKind,
    /// How it ended, for `stopped`.
    reason: records.EndReason,
    exit: records.Exit,
};

/// What a watcher remembers of a container between two polls.
const Seen = struct {
    name: text_util.Bounded(constants.container_name_bytes_max),
    started: u64,
    state: State,
};

/// The memory of `poll`: what it saw last time. A fresh watcher has seen nothing, so its first
/// poll reports every running container as started.
pub const Watcher = struct {
    seen: [constants.runs_max + constants.scopes_listed_max]Seen,
    count: u32,

    pub fn init(watcher: *Watcher) void {
        assert(watcher.seen.len > 0);
        assert(constants.runs_max > 0);
        watcher.count = 0;
    }

    fn find(watcher: *const Watcher, entry: *const Entry) ?*Seen {
        assert(watcher.count <= watcher.seen.len);
        assert(entry.record.name_len > 0);
        for (watcher.seen[0..watcher.count]) |*one| {
            const same = std.mem.eql(u8, one.name.slice(), entry.name());
            if (same and one.started == entry.record.started) return @constCast(one);
        }
        return null;
    }
};

/// Looks once and writes the changes since the last look to `out`; returns how many. `scratch`
/// is room for `list`. It does not wait. A change is a container that appeared running (or
/// already ended), and one that went from running to stopped or lost; containers that vanish
/// from the list (their record was pruned) are forgotten without an event. At most `out.len`
/// changes are reported per poll: the rest are found by the next one.
pub fn poll(host: Host, watcher: *Watcher, scratch: []Entry, out: []Event) ListError!u32 {
    assert(out.len > 0);
    const found = try list(host, scratch);
    var reported: u32 = 0;
    var next: Watcher = undefined;
    next.count = 0;
    for (scratch[0..found]) |*entry| {
        if (next.count == next.seen.len) break;
        const before = watcher.find(entry);
        if (needed_events(before, entry) > out.len - reported) {
            // It does not fit now: remember what we had, so the next poll reports it.
            if (before) |one| {
                next.seen[next.count] = one.*;
                next.count += 1;
            }
            continue;
        }
        reported = emit(out, reported, before, entry);
        next.seen[next.count] = .{
            .name = .{},
            .started = entry.record.started,
            .state = entry.state,
        };
        next.seen[next.count].name.print("{s}", .{entry.name()});
        next.count += 1;
    }
    watcher.* = next;
    assert(reported <= out.len);
    return reported;
}

fn needed_events(before: ?*Seen, entry: *const Entry) usize {
    assert(entry.record.name_len > 0);
    if (entry.state == .stopped) assert(entry.record.exit != .running);
    assert(entry.record.name_len <= constants.container_name_bytes_max);
    const was: ?State = if (before) |one| one.state else null;
    if (was == null) return if (entry.state == .running) 1 else 2;
    if (was.? == .running and entry.state != .running) return 1;
    return 0;
}

fn emit(out: []Event, at: u32, before: ?*Seen, entry: *const Entry) u32 {
    assert(at <= out.len);
    assert(needed_events(before, entry) <= out.len - at);
    var index = at;
    const was: ?State = if (before) |one| one.state else null;
    if (was == null) {
        out[index] = event(entry, .started);
        index += 1;
    }
    if (entry.state != .running and (was == null or was.? == .running)) {
        out[index] = event(entry, if (entry.state == .lost) .lost else .stopped);
        index += 1;
    }
    return index;
}

fn event(entry: *const Entry, kind: EventKind) Event {
    assert(entry.record.name_len > 0);
    if (kind == .stopped) assert(entry.state == .stopped);
    assert(entry.record.name_len <= constants.container_name_bytes_max);
    var made: Event = .{
        .name = .{},
        .kind = kind,
        .reason = entry.record.reason,
        .exit = entry.record.exit,
    };
    made.name.print("{s}", .{entry.name()});
    return made;
}

/// A reference to the container a `Handle` started: for `stop` and `signal` from another thread
/// than the one in `run.wait`. Valid while the handle is.
pub fn ref_of(handle: *run.Handle) Ref {
    assert(handle.status != .starting);
    assert(handle.session.container_pid > 0);
    var made: Ref = .{
        .host = handle.host,
        .pid = handle.session.container_pid,
        .name = .{},
        .scope = .{},
        .reaped = &handle.session.reaped,
    };
    made.name.print("{s}", .{handle.name_slice()});
    if (handle.plan.scoped) made.scope.print("{s}", .{handle.plan.text(handle.plan.scope_name)});
    return made;
}
