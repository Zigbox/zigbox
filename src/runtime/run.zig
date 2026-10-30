//! The runtime library: run a container in the foreground, or under a caller that supervises it.
//! Its shape follows the `Runtime` contract of Zigcube's HANDOFF.md, so the two map one to one
//! when Zigcube's agent links this module (`zigbox`): `start`, `wait`, `signal`, `inspect`, a
//! `Spec`, a `Handle`, a `Status` and an `ExitReason`. Nothing here prints. A refusal is a coded
//! `Diag`; a warning is handed to the caller's `Warn` as it happens, before the container's
//! command can write a byte, so a terminal user sees it first.
//!
//! Process model (docs/briefs/M1-shell.md): the caller's process stays in the host PID namespace
//! as the parent. `clone3` creates a child in new user, mount, PID, UTS, IPC and (unless the
//! host's network is shared, `--net host`) network namespaces. The
//! child is PID 1 of its namespace, sets the container up and runs the command; there is no init
//! shim. Two pipes carry the synchronisation: the parent tells the child when the id maps are
//! written (`ready`), and the child tells the parent about a failed or skipped step (`report`).
//!
//! Storage belongs to the caller. A `Handle` holds the plan, the doctor's `Facts` and the run's
//! state, about 480 KiB (`constants.handle_bytes_max`); the caller passes it by pointer to `start`
//! and may not move it until `wait` returns. The library has no module-level state but the real
//! host's per-thread errno and the panic handler's settings (`diag/panic.zig`, which only the `zbx`
//! program sets), so two callers on two threads each use their own (tested). The stack stays small:
//! the plan is built in place in the handle, and what a start or a wait puts on the stack is a few
//! buffers of at most `record_bytes_max` (32 KiB) and `output_bytes_max` (16 KiB). A thread that
//! starts and waits for a container needs about 128 KiB of stack beyond the handle in a debug build
//! (96 KiB was not enough in the test; the test uses 256 KiB), less in a release build.
//!
//! The rest of the contract is in `lifecycle.zig` (list, adopt by name, stop with a grace
//! period, a poll for changes) and in `StartOptions`: `detached` (the record says a supervisor
//! outlives the caller; the process split itself is the caller's, `cli.zig`'s `run -d`),
//! `timeout_ms`/`grace_ms` (a run that lasts too long is sent SIGTERM and then SIGKILL).
//! `oom` and `pid_limit` are in `ExitReason`: `wait` reads the scope's `memory.events` and
//! `pids.events` as soon as PID 1 is reaped. The manager removes a transient scope the moment
//! it is empty, so a container whose PID 1 exits right after the OOM killer ran would take its
//! counters with it; a scope therefore has a second process, the keeper (`Host.start_keeper`),
//! forked before the scope is requested, put in `PIDs` beside the container's, and released by
//! `wait` after the counters are read. The keeper takes one pid of the scope's `TasksMax`, which
//! is `--pids` plus one, so the container has exactly the pids it asked for. The thread that
//! calls `start` must be the one that calls `wait`: the kernel ends the keeper when that thread
//! ends.

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
const doctor = @import("../doctor.zig");
const ids = @import("ids.zig");
const image_diagnose = @import("../image_diagnose.zig");
const image_mod = @import("image.zig");
const netfiles = @import("netfiles.zig");
const pasta_mod = @import("pasta.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const scope_mod = @import("scope.zig");
const scope_text = @import("scope_text.zig");
const session_mod = @import("session.zig");
const spec_mod = @import("spec.zig");
const volumes_mod = @import("volumes.zig");
const mounts_mod = @import("mounts.zig");

const Host = host_mod.Host;
const Plan = plan_mod.Plan;
const Session = session_mod.Session;

pub const Spec = spec_mod.Spec;
/// The memory a run of a tree from the store prepares it in (`StartOptions.image_workspace`).
pub const ImageWorkspace = image_mod.Workspace;
pub const Label = spec_mod.Label;
pub const Limits = spec_mod.Limits;

/// The run did not start the command; the reason is in the `Diag`.
pub const Error = session_mod.Error;

/// Where a run is. `starting` is only seen from inside `start`.
/// Where a handle's run is. The union is the contract's `Status`; the plain phase is what the
/// handle keeps in its own field.
pub const Phase = enum { starting, running, stopped };

pub const Status = union(enum) {
    starting,
    running,
    /// How it ended; known once `wait` has returned (or the start failed).
    stopped: ExitReason,
};

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
    /// Total wall time for the run in milliseconds, then SIGTERM; zero is no limit.
    timeout_ms: u32 = 0,
    /// The run is a detached one: the record says so (`zbx run -d` supervises it).
    detached: bool = false,
    /// After SIGTERM, how long before SIGKILL (for the timeout and for `stop`'s default).
    grace_ms: u32 = constants.stop_grace_ms_default,
    /// The memory a run of a tree from the store (`Spec.image`) prepares it in, about 17 MiB:
    /// the caller's, in static or heap storage. Required exactly when `image` is set.
    image_workspace: ?*image_mod.Workspace = null,
};

pub const Note = text_util.Bounded(160);

/// A running (or finished) container. It holds pointers into itself and into the `Spec`'s
/// strings (the command and labels, for the record written at the end): neither may move or be
/// freed until `wait` has returned.
pub const Handle = struct {
    host: Host,
    status: Phase,
    /// How the run ended; set when `status` becomes `.stopped`.
    ended: ExitReason,
    plan: Plan,
    session: Session,
    name: [constants.container_name_bytes_max]u8,
    name_len: u8,
    rootfs: [constants.rootfs_bytes_max]u8,
    rootfs_len: u16,
    /// A run of a tree from the store: the tree, the layers and whether it is read-only.
    has_image: bool,
    image: image_mod.Prepared,
    /// Where a pruned run's layers are removed from; null if the caller gave none.
    image_workspace: ?*image_mod.Workspace,
    command: []const []const u8,
    labels: []const Label,
    /// The names (never the values) of the `-e` variables, for the record.
    env_names: []const []const u8,
    started: u64,
    mapping: records.IdsMode,
    /// Where the record goes; null if there is nowhere (a warning said so).
    record_dir: ?records.Dir,
    warn: ?Warn,
    wait_options: Session.WaitOptions,
    detached: bool,
    /// The container's PID 1 as the host sees it, once it is running; zero before.
    pid: u32,
    record_warned: bool,
    /// Steps that were allowed to fail and did (the devpts mount), as sentences.
    notes: [constants.sync_records_max + 2]Note,
    notes_count: u32,
    /// The limits the run was started with, for the exit report and the record.
    limits: spec_mod.Limits,
    /// What the container could reach, for the exit report.
    network: spec_mod.Network,
    /// The host's ports forwarded to the container's (`--publish`), for the exit report.
    publish: [constants.publish_count_max]spec_mod.Publish,
    publish_count: u32,
    /// For `--net user`: where pasta is, and the file its output goes to (empty: none).
    pasta_path: text_util.Bounded(constants.pasta_path_bytes_max),
    pasta_log: text_util.Bounded(constants.state_path_bytes_max + 80),
    /// Why the run ended, as the record says it; `none` until it has.
    end_reason: records.EndReason,
    /// Why `wait` returned `.lost`.
    lost_diag: Diag,
    /// The state volumes, held from before the container is created until it has ended.
    volumes: volumes_mod.Held,
    /// The other mounts (they point into the `Spec`, like the command) and what the host showed
    /// of each.
    mounts: []const mounts_mod.Mount,
    resolution: mounts_mod.Resolution,
    /// The user the command runs as; null is root. Kept for the record and the exit report.
    user: ?spec_mod.User,
    /// This run's own room for the doctor's facts (200 KiB), so that runs on two threads share
    /// nothing. It is why a `Handle` is large: keep it off the stack.
    facts: doctor.Facts,

    pub fn name_slice(handle: *const Handle) []const u8 {
        assert(handle.name_len > 0);
        assert(handle.name_len <= constants.container_name_bytes_max);
        return handle.name[0..handle.name_len];
    }

    pub fn rootfs_slice(handle: *const Handle) []const u8 {
        assert(handle.rootfs_len > 0);
        return handle.rootfs[0..handle.rootfs_len];
    }

    pub fn publish_slice(handle: *const Handle) []const spec_mod.Publish {
        assert(handle.publish_count <= constants.publish_count_max);
        if (handle.publish_count > 0) assert(handle.network == .user);
        return handle.publish[0..handle.publish_count];
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

/// Whether `wait` had to stop the container because its time (`StartOptions.timeout_ms`) was up.
pub fn timed_out(handle: *const Handle) bool {
    assert(handle.status != .starting);
    assert(handle.name_len > 0);
    return handle.session.timed_out;
}

pub fn inspect(handle: *const Handle) Status {
    assert(handle.name_len > 0);
    return switch (handle.status) {
        .starting => .starting,
        .running => .running,
        .stopped => .{ .stopped = handle.ended },
    };
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
    handle.image_workspace = options.image_workspace;
    handle.detached = options.detached;
    handle.pid = 0;
    handle.wait_options = .{ .timeout_ms = options.timeout_ms, .grace_ms = options.grace_ms };
    handle.record_warned = false;
    handle.notes_count = 0;
    handle.limits = container.limits;
    handle.network = container.network;
    handle.publish_count = 0;
    handle.pasta_path = .{};
    handle.pasta_log = .{};
    handle.end_reason = .none;
    handle.name_len = 0; // Set by `choose_name`; a caller can tell whether it ever was.
    handle.volumes.count = 0;
    handle.mounts = &.{};
    handle.user = container.user;
    handle.command = container.command;
    handle.labels = container.labels;
    handle.env_names = container.env_names;
    try choose_name(host, container.name, handle, diag);
    try check_command(container, diag);
    try check_root(host, container, options, handle, diag);
    try check_limits(container.limits, diag);
    try check_network(host, container, handle, diag);
    try resolve_mounts(host, container, handle, diag);

    const choice = try choose_ids(host, container, handle, diag);
    // After the checks that need nothing from the host, and before anything is created: a run
    // with a limit and no way to enforce it is refused here, with nothing to clean up.
    const scope_input = try prepare_scope(handle, container.limits, diag);
    if (container.image) |image| try prepare_image(handle, container, image, options, diag);
    // The volumes last, so that nothing above can fail with them held; from here every way out
    // of `start` that is not a running container lets them go.
    volumes_mod.take(host, container.state, handle.name_slice(), &handle.volumes, diag) catch
        return error.StartFailed;
    errdefer volumes_mod.release(host, &handle.volumes);
    build_plan(host, container, choice, scope_input, handle);
    // Namespace setup must happen before any thread exists (docs/SPEC.md, M1 acceptance).
    if (builtin.mode == .debug) assert_single_threaded(host);

    handle.started = host.time_now();
    begin_record(handle);
    handle.session.start(host, &handle.plan, &handle.facts);
    handle.session.execute(diag, run_info(handle)) catch |err| {
        handle.ended = failed_start(diag); // Asserts that the diagnostic has a code.
        handle.status = .stopped;
        save_record(handle, .{ .start_failed = diag.code.? }, host.time_now(), diag);
        finish_scope(handle);
        return err;
    };
    collect_notes(handle);
    handle.status = .running;
    assert(handle.session.pid != null);
    handle.pid = handle.session.container_pid;
    // Again, now that the container's pid is known: this is what a later process finds it by.
    save_record(handle, .running, null, null);
}

/// Holds the mounts to their rules and looks at them on the host (`mounts.resolve`): the handle
/// then keeps them with a `--mount`'s source resolved, which the plan and the record use.
fn resolve_mounts(host: Host, container: *const Spec, handle: *Handle, diag: *Diag) Error!void {
    assert(handle.mounts.len == 0);
    assert(container.mounts.len <= constants.mounts_max);
    const writable: mounts_mod.Writable = .{
        .project = container.project,
        .user = container.user,
        .user_text = container.user_text,
    };
    const resolution = &handle.resolution;
    mounts_mod.resolve(host, container.state, container.mounts, writable, resolution, diag) catch
        return error.StartFailed;
    handle.mounts = resolution.mounts[0..container.mounts.len];
}

/// Builds the plan in place in the handle. The host's resolv.conf is read here, in the parent,
/// when the container shares the host's network: the child formats and reads nothing.
fn build_plan(
    host: Host,
    container: *const Spec,
    choice: ids.Choice,
    scope_input: ?plan_mod.ScopeInput,
    handle: *Handle,
) void {
    assert(handle.name_len > 0);
    assert(handle.status == .starting);
    var resolv: netfiles.Buffer = undefined;
    const host_resolv = host_resolv_conf(host, container.network, &resolv, handle);
    const input: plan_mod.Input = .{
        .rootfs = handle.rootfs_slice(),
        .name = handle.name_slice(),
        .command = container.command,
        .term = host.environment("TERM", constants.term_bytes_max),
        .uid = host.uid(),
        .gid = host.gid(),
        .mapping = choice.mapping,
        .scope = scope_input,
        .read_only = container.read_only,
        .env = container.env,
        .workdir = container.workdir,
        .user = container.user,
        .overlay = if (handle.has_image) handle.image.overlay() else null,
        .network = container.network,
        .host_resolv = host_resolv,
        .pasta = if (container.network == .user) .{
            .path = handle.pasta_path.slice(),
            .log = handle.pasta_log.slice(),
            .publish = handle.publish_slice(),
        } else null,
        .state = handle.volumes.input_slice(),
        .mounts = handle.resolution.inputs[0..handle.mounts.len],
    };
    handle.plan.build(&input);
    assert(handle.plan.count == handle.plan.steps_expected());
}

/// The host's `/etc/resolv.conf`, for a container that shares the host's network: whole lines,
/// within the bound. A file that cannot be read gives none, and a note says so. Other modes
/// need none.
fn host_resolv_conf(
    host: Host,
    network: spec_mod.Network,
    out: *netfiles.Buffer,
    handle: *Handle,
) []const u8 {
    assert(handle.notes_count < handle.notes.len);
    if (network != .host) return "";
    var raw: netfiles.Buffer = undefined;
    const found = host.read_prefix("/etc/resolv.conf", &raw) catch |err| {
        const note = &handle.notes[handle.notes_count];
        note.* = .{};
        note.print("the host's /etc/resolv.conf could not be read ({s}): no nameserver", .{
            @errorName(err),
        });
        handle.notes_count += 1;
        return "";
    };
    return netfiles.whole_lines(out, found.bytes);
}

/// What the diagnostics say about this run.
fn run_info(handle: *const Handle) diagnose.RunInfo {
    return .{
        .name = handle.name_slice(),
        .rootfs = handle.rootfs_slice(),
        .tree = if (handle.has_image) handle.image.tree_text() else "",
    };
}

/// A run's root is a directory (checked now) or a tree of the store (prepared later, once the
/// ids and the scope are known).
fn check_root(
    host: Host,
    container: *const Spec,
    options: StartOptions,
    handle: *Handle,
    diag: *Diag,
) Error!void {
    handle.has_image = container.image != null;
    if (container.image == null) return check_rootfs(host, container.rootfs, handle, diag);
    assert(container.rootfs.len == 0); // A directory or a tree, not both.
    assert(options.image_workspace != null);
}

/// Waits for the container to end, forwarding the signals this process receives. Call it once.
pub fn wait(handle: *Handle) ExitReason {
    assert(handle.status == .running);
    const host = handle.host;
    host.begin_step(@intCast(handle.plan.count - 1)); // The `reap` step.
    const result = handle.session.wait(handle.wait_options);
    host.begin_step(host_mod.step_none);
    // The container is gone (or zbx lost it, and `abandon` below ends it): pasta goes now, and
    // the host's ports with it, before anything else is done.
    handle.session.release_pasta();
    handle.status = .stopped;
    const status = result catch |err| {
        const failure: diagnose.Failure = .{
            .step = @intCast(handle.plan.count - 1),
            .err = err,
            .errno = host.last_errno(),
        };
        handle.session.abandon();
        handle.lost_diag.reset();
        const info = run_info(handle);
        diagnose.step_failed(host, &handle.lost_diag, &handle.plan, info, failure, .{
            .facts = &handle.facts,
        });
        save_record(handle, .lost, host.time_now(), &handle.lost_diag);
        finish_scope(handle); // `abandon` ended the container.
        volumes_mod.release(host, &handle.volumes);
        handle.ended = .lost;
        return .lost;
    };
    // Right after the reap, while the keeper still holds the scope: the manager removes the
    // cgroup as soon as nothing is left in it, and its counters go with it.
    const events = if (handle.plan.scoped)
        scope_mod.read_events(host, handle.session.scope_directory.slice())
    else
        scope_mod.Events{ .oom_kill = null, .pids_max = null };
    // The keeper has held the scope open until now; with the counters read it can go, and the
    // manager removes the scope.
    handle.session.release_keeper();
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
    // The container is reaped: its volumes are free for the next run.
    volumes_mod.release(host, &handle.volumes);
    handle.ended = reason;
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
    const name = if (handle.plan.scoped) handle.plan.text(handle.plan.scope_name) else "";
    switch (handle.session.cleanup_scope(&problem)) {
        .none => return,
        .done => |how| {
            const note = &handle.notes[handle.notes_count];
            note.* = .{};
            var buffer: [160]u8 = undefined;
            note.print("{s}", .{scope_text.cleanup_note(name, how, &buffer)});
            handle.notes_count += 1;
        },
        .failed => {
            var warning: Diag = undefined;
            warning.reset();
            diagnose.scope_not_cleaned(&warning, name, &problem);
            handle.report(&warning);
        },
    }
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

/// Resolves the tree, materializes it and makes the container's directory (`image.zig`); the
/// merged directory is then the rootfs. Anything that goes wrong is the run's start failing.
fn prepare_image(
    handle: *Handle,
    container: *const Spec,
    image: []const u8,
    options: StartOptions,
    diag: *Diag,
) Error!void {
    assert(handle.has_image);
    const workspace = options.image_workspace.?;
    // The container's own id map warns about a one-id host; the store's child would say it twice.
    image_mod.prepare(
        handle.host,
        &handle.facts,
        workspace,
        image,
        handle.name_slice(),
        container.read_only,
        null,
        &handle.image,
        diag,
    ) catch return error.StartFailed;
    const merged = handle.image.merged.text();
    if (merged.len > constants.rootfs_bytes_max) {
        diagnose.rootfs_unusable(diag, merged, .{ .problem = .too_long });
        return error.StartFailed;
    }
    @memcpy(handle.rootfs[0..merged.len], merged);
    handle.rootfs_len = @intCast(merged.len);
}

fn check_command(container: *const Spec, diag: *Diag) Error!void {
    const command = container.command;
    const labels = container.labels;
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
    if (spec_mod.env_problem(container.env, command)) |index| {
        diagnose.env_too_big(diag, index);
        return error.StartFailed;
    }
    // The caller (cli.zig) built `env_names` from the options it already checked.
    assert(spec_mod.env_names_problem(container.env_names) == null);
    if (spec_mod.workdir_problem(container.workdir)) {
        diagnose.workdir_unusable(diag);
        return error.StartFailed;
    }
}

/// The id map this host gives the container, with the warning if it is the single one, and the
/// refusal if the image's user needs more.
fn choose_ids(host: Host, container: *const Spec, handle: *Handle, diag: *Diag) Error!ids.Choice {
    assert(diag.code == null);
    var choice: ids.Choice = undefined;
    ids.choose(host, &handle.facts, &choice);
    if (choice.warned) handle.report(&choice.warning);
    handle.mapping = if (choice.warned) .single else .full;
    try check_user(container, choice.warned, diag);
    return choice;
}

/// An image that runs as a user needs the ids mapped; the single-id map has only root.
fn check_user(container: *const Spec, single: bool, diag: *Diag) Error!void {
    assert(diag.code == null);
    const user = container.user orelse return;
    if (single and (user.uid != 0 or user.gid != 0)) {
        image_diagnose.needs_id_map(diag, user.uid, user.gid);
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

/// A run with `--net user`: the forwards are a list pasta can make, pasta is there and new
/// enough, and no host port is below what the host lets a user bind. Everything is refused here,
/// before anything is created. The path of pasta's log is chosen too.
fn check_network(host: Host, container: *const Spec, handle: *Handle, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(handle.publish_count == 0);
    if (container.publish.len > 0) assert(container.network == .user);
    if (container.network != .user) return;
    if (spec_mod.publish_problem(.user, container.publish)) |problem| {
        diagnose.publish_list_invalid(diag, problem);
        return error.StartFailed;
    }
    @memcpy(handle.publish[0..container.publish.len], container.publish);
    handle.publish_count = @intCast(container.publish.len);
    doctor.gather_net(host, &handle.facts);
    const pasta = &handle.facts.pasta;
    if (!pasta.found) {
        diagnose.pasta_missing(diag, container.network);
        return error.StartFailed;
    }
    // A version line with no date ("unknown version", as Ubuntu 24.04's build prints) cannot be
    // judged, and is not refused (docs/demos/m5.md).
    if (pasta_mod.version_date(pasta.version.slice())) |date| {
        if (date < constants.pasta_version_min_date) {
            diagnose.pasta_too_old(diag, pasta.path.slice(), pasta.version.slice());
            return error.StartFailed;
        }
    }
    try check_low_ports(host, handle, diag);
    handle.pasta_path.print("{s}", .{pasta.path.slice()});
    choose_pasta_log(host, handle);
    assert(handle.pasta_path.len > 0);
}

/// A host port below `net.ipv4.ip_unprivileged_port_start` is refused before pasta is started,
/// with the bound in the message. A bound that cannot be read leaves it to pasta's own bind.
fn check_low_ports(host: Host, handle: *const Handle, diag: *Diag) Error!void {
    assert(diag.code == null);
    var buffer: [32]u8 = undefined;
    const text = host.read_file("/proc/sys/net/ipv4/ip_unprivileged_port_start", &buffer) catch
        return;
    const bound = std.fmt.parseInt(u32, std.mem.trim(u8, text, " \n"), 10) catch return;
    for (handle.publish_slice()) |forward| {
        if (forward.host < bound) {
            diagnose.pasta_port_refused(diag, forward.host, bound, "");
            return error.StartFailed;
        }
    }
}

/// pasta's log: `<state>/zbx/logs/<name>.pasta.log`, beside the runs directory. A run with no
/// state directory, or one where the directory cannot be made, has none: pasta's stderr then
/// goes to /dev/null, and a failure's diagnostic says so.
fn choose_pasta_log(host: Host, handle: *Handle) void {
    assert(handle.pasta_log.len == 0);
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return;
    var logs: records.Dir = undefined;
    if (!logs_dir_of(&dir, &logs)) return;
    records.ensure(host, &logs) catch return;
    handle.pasta_log.print("{s}/{s}{s}", .{
        logs.text(), handle.name_slice(), constants.pasta_log_suffix,
    });
    assert(handle.pasta_log.len > logs.len);
}

/// The logs directory beside a runs directory: the same path with "logs" for its last part.
fn logs_dir_of(runs: *const records.Dir, out: *records.Dir) bool {
    const text = runs.text();
    if (!std.mem.endsWith(u8, text, "/runs")) return false;
    out.* = runs.*;
    @memcpy(out.path[out.len - "runs".len .. out.len], "logs");
    assert(out.path[out.len] == 0);
    assert(std.mem.endsWith(u8, out.text(), "/logs"));
    return true;
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
    var pruned: records.Pruned = undefined;
    records.prune(handle.host, &dir, handle.name_slice(), &skipped, &pruned) catch return;
    reclaim_layers(handle, &pruned);
    remove_pasta_logs(handle, &dir, &pruned);
    if (skipped.count == 0) return;
    var warning: Diag = undefined;
    warning.reset();
    diagnose.records_skipped(&warning, dir.text(), &skipped);
    handle.report(&warning);
}

/// A record that was pruned takes its pasta log with it, if it had one. Best effort: a log that
/// stays is a small file the next run of that name empties.
fn remove_pasta_logs(handle: *Handle, dir: *const records.Dir, pruned: *const records.Pruned) void {
    var logs: records.Dir = undefined;
    if (!logs_dir_of(dir, &logs)) return;
    for (0..pruned.count) |index| {
        var path: [constants.state_path_bytes_max + 96]u8 = undefined;
        const name = pruned.name(@intCast(index));
        const format = "{s}/{s}" ++ constants.pasta_log_suffix;
        // Cannot fail: a bounded directory and a run name of at most 63 bytes.
        const text = std.fmt.bufPrintSentinel(&path, format, .{ logs.text(), name }, 0) catch
            unreachable; // Same bound as above.
        handle.host.remove_file(text) catch {};
    }
}

/// A record that was pruned no longer needs the layers kept for it: they go, from inside the
/// store's namespace. A layer that cannot be removed is a warning, never a failed run.
fn reclaim_layers(handle: *Handle, pruned: *const records.Pruned) void {
    const workspace = handle.image_workspace orelse return;
    for (0..pruned.count) |index| {
        var diag: Diag = undefined;
        diag.reset();
        image_mod.remove_container(
            handle.host,
            &handle.facts,
            workspace,
            pruned.name(@intCast(index)),
            &diag,
        ) catch {
            if (diag.code == null) continue;
            handle.report(&diag);
        };
    }
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
    const writable_layers = handle.has_image and !handle.image.read_only;
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
        .detached = handle.detached,
        .timed_out = handle.session.timed_out,
        .pid = handle.pid,
        .supervisor = handle.host.own_pid(),
        .tree = if (handle.has_image) handle.image.tree_text() else "",
        .upper = if (writable_layers) handle.image.upper.text() else "",
        .network = handle.network,
        .publish = handle.publish_slice(),
        .env_names = handle.env_names,
        .zbx_version = build_options.version,
        .state = handle.volumes.mount_slice(),
        .mounts = handle.mounts,
        .user = handle.user,
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
    // The bus note, and the note that the host's resolv.conf could not be read.
    assert(handle.notes_count <= 2);
    assert(handle.notes.len >= handle.notes_count + 1); // Room for the scope's.
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
