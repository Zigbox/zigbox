//! `zbx exec` in the library (M6b slice 3): run a command inside a running container, with what
//! the container has and nothing more. The container is found by name from its run record, like
//! `lifecycle.adopt`; the command joins its user, IPC, UTS, network, PID and mount namespaces,
//! is put in its cgroup (its systemd scope, or the cgroupfs child of M4b's driver), and drops to
//! its capability set, `no_new_privs` and its seccomp filter before `execve` (`exec_plan.zig`
//! has the order and why). The command is the caller's child, so `wait` reaps it and its exit
//! code is the command's own; it is inside the container's PID namespace, so it dies with the
//! container.
//!
//! By default the command has the container's environment and working directory (its PID 1's)
//! and user (from the record); `Spec.env`, `Spec.user` and `Spec.workdir` replace them
//! for this command only. A value of `env` is never kept or printed: the history the exec leaves
//! beside the container's log (`exec_history.zig`) has the command and how it ended.
//!
//! Storage belongs to the caller: a `Handle` (about 800 KiB; `constants.exec_handle_bytes_max`)
//! holds the plan, the container's environment and files, and the state of the exec. The
//! thread that calls `start` must call `wait`, and must be the process's only thread when it
//! calls `start` (namespaces are joined in a forked child, as for a run).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const image_user = @import("../image_user.zig");
const diagnose = @import("diagnose.zig");
const exec_child = @import("exec_child.zig");
const exec_diagnose = @import("exec_diagnose.zig");
const exec_history = @import("exec_history.zig");
const exec_plan = @import("exec_plan.zig");
const lifecycle = @import("lifecycle.zig");
const logfile = @import("logfile.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const scope_mod = @import("scope.zig");
const spec_mod = @import("spec.zig");
const sync = @import("sync.zig");

const Host = host_mod.Host;

pub const Error = error{StartFailed};

pub const Label = spec_mod.Label;

/// What to run, in which container.
pub const Spec = struct {
    /// The container's name, as `zbx run --name` gave it.
    name: []const u8,
    /// The program and its arguments; never empty.
    command: []const []const u8,
    /// Variables for this command only, each replacing the container's of the same name. At most
    /// `run_env_count_max`. Never kept or printed.
    env: []const Label = &.{},
    /// `USER[:GROUP]`, names or numbers, looked up in the container's own /etc/passwd and
    /// /etc/group. Null: the container's user.
    user: ?[]const u8 = null,
    /// The directory to start in, absolute; it must exist in the container. Null: the
    /// container's working directory.
    workdir: ?[]const u8 = null,
    /// Give the command a pseudo-terminal of its own, with the size of the caller's terminal,
    /// and make the caller's terminal raw while it runs. False: the command's three streams are
    /// the caller's.
    terminal: bool = false,
};

pub const Options = struct {
    /// Where a warning goes (ZBX-W0207, the history not written).
    warn: ?run.Warn = null,
    /// Note the exec in the container's history.
    keep_history: bool = true,
};

/// How the command ended.
pub const Exit = union(enum) {
    exited: u8,
    signaled: u8,
    /// zbx could not wait for it to the end (`Handle.lost_diag` says why).
    lost,

    /// The process exit code that stands for it, or null when it was lost.
    pub fn code(exit: Exit) ?u8 {
        return switch (exit) {
            .exited => |value| value,
            .signaled => |number| blk: {
                assert(number > 0);
                assert(number < constants.signal_number_max);
                break :blk constants.exit_signal_offset + number;
            },
            .lost => null,
        };
    }
};

pub const Phase = enum { starting, running, stopped };

/// Which ends of the two pipes this process still holds.
const Open = struct {
    ready_write: bool,
    report_read: bool,
};

/// The two files of the container a `--user` name is looked up in.
const UserFiles = struct {
    passwd: [constants.file_bytes_max]u8,
    group: [constants.file_bytes_max]u8,
};

pub const Handle = struct {
    host: Host,
    status: Phase,
    plan: exec_plan.Plan,
    child: exec_child.Context,
    name: text_util.Bounded(constants.container_name_bytes_max),
    /// The container's PID 1, as the host sees it, and its scope's name (empty: none).
    container_pid: u32,
    scope: text_util.Bounded(constants.scope_name_bytes_max),
    /// The container's environment, from `/proc/<pid>/environ`.
    environ: [exec_plan.environ_bytes_max]u8,
    environ_len: u32,
    user_files: UserFiles,
    joiner: ?host_mod.Pid,
    /// The command, once the joiner has forked it; the caller's child.
    pid: ?host_mod.Pid,
    open: Open,
    /// The parent still holds the children's ends of the pipes (before the joiner is forked).
    pipes_child_ends_open: bool,
    /// Why the command could not be put in the container's cgroup.
    cgroup_problem: scope_mod.Problem,
    cgroup_problem_set: bool,
    terminal: ?host_mod.Terminal,
    /// The parent's own copies of the namespace files and of the terminal's peer, open until the
    /// command has its own. (The children's context is never changed after the fork: in the
    /// simulator the children run on the parent's memory.)
    namespaces_open: bool,
    peer_open: bool,
    saved: host_mod.TerminalSaved,
    /// With a terminal: standard input still has bytes to send, the master still has output.
    input_open: bool,
    master_open: bool,
    /// The command was killed with its container (its PID 1 is gone).
    container_ended: bool,
    command: []const []const u8,
    started: u64,
    warn: ?run.Warn,
    keep_history: bool,
    ended: Exit,
    lost_diag: Diag,
    history: exec_history.Scratch,

    pub fn info(handle: *const Handle) exec_diagnose.Info {
        assert(handle.name.len > 0);
        assert(handle.name.len <= constants.container_name_bytes_max);
        return .{ .name = handle.name.slice(), .pid = handle.container_pid };
    }

    fn report_warning(handle: *const Handle, diag: *const Diag) void {
        assert(@intFromPtr(handle) != @intFromPtr(diag));
        assert(diag.code != null);
        if (handle.warn) |warn| warn.call(warn.context, diag);
    }
};

/// Starts the command. On return it runs and `handle` is `running`; on `StartFailed` it did not,
/// nothing it made is left, and `diag` says why. `handle` must not move until `wait` returns.
pub fn start(
    host: Host,
    spec: *const Spec,
    options: Options,
    handle: *Handle,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    init_handle(host, spec, options, handle);
    try check_spec(spec, diag);
    var record: records.Parsed = undefined;
    try find_container(host, spec.name, handle, &record, diag);
    try read_environ(handle, diag);
    const user = try choose_user(handle, spec, &record, diag);
    const term = if (spec.terminal) host.environment("TERM", constants.term_bytes_max) else null;
    const input: exec_plan.Input = .{
        .command = spec.command,
        .environ = handle.environ[0..handle.environ_len],
        .env = spec.env,
        .term = term,
        .workdir = spec.workdir orelse "",
        .user = user,
        .namespaces = all_namespaces,
        .terminal = spec.terminal,
        .cgroup = handle.scope.len > 0,
    };
    if (exec_plan.check_input(&input)) |problem| {
        refuse_input(handle, problem, diag);
        return error.StartFailed;
    }
    handle.plan.build(&input);
    if (builtin.mode == .debug) assert_single_threaded(host);
    handle.started = host.time_now();
    execute(handle, diag) catch {
        handle.status = .stopped;
        return error.StartFailed;
    };
    handle.status = .running;
    assert(handle.pid != null);
}

const all_namespaces: u8 = 0x3f;

fn init_handle(host: Host, spec: *const Spec, options: Options, handle: *Handle) void {
    assert(spec.command.len > 0);
    assert(@intFromPtr(handle) != @intFromPtr(spec));
    handle.host = host;
    handle.status = .starting;
    handle.name = .{};
    handle.container_pid = 0;
    handle.scope = .{};
    handle.environ_len = 0;
    handle.joiner = null;
    handle.pid = null;
    handle.open = .{ .ready_write = false, .report_read = false };
    handle.pipes_child_ends_open = false;
    handle.cgroup_problem_set = false;
    handle.terminal = null;
    handle.namespaces_open = false;
    handle.peer_open = false;
    handle.saved = .{ .bytes = undefined, .valid = false };
    handle.input_open = false;
    handle.master_open = false;
    handle.container_ended = false;
    handle.command = spec.command;
    handle.warn = options.warn;
    handle.keep_history = options.keep_history;
    handle.ended = .lost;
    handle.child = .{
        .host = host,
        .plan = &handle.plan,
        .ready = undefined,
        .report = undefined,
        .namespaces = @splat(null),
        .peer = null,
    };
    assert(handle.status == .starting);
}

/// What needs nothing from the host: the command, the `-e` values and the `--workdir` value.
fn check_spec(spec: *const Spec, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(spec.command.len > 0); // The command line refuses a missing program; so must a caller.
    assert(spec.command[0].len > 0);
    if (spec_mod.command_problem(spec.command)) |problem| {
        diagnose.command_too_big(diag, problem);
        return error.StartFailed;
    }
    if (spec.env.len > constants.run_env_count_max) {
        diagnose.env_too_big(diag, constants.run_env_count_max);
        return error.StartFailed;
    }
    for (spec.env, 0..) |variable, index| {
        const bad = !spec_mod.env_name_valid(variable.key) or
            variable.value.len > constants.env_value_bytes_max or
            std.mem.indexOfScalar(u8, variable.value, 0) != null;
        if (bad) {
            diagnose.env_too_big(diag, @intCast(index));
            return error.StartFailed;
        }
    }
    const workdir = spec.workdir orelse return;
    if (workdir.len <= constants.arg_bytes_max and !spec_mod.workdir_problem(workdir)) return;
    workdir_value_refused(diag, workdir);
    return error.StartFailed;
}

/// ZBX-E0005: `--workdir` is not an absolute path without `..` within the bound.
pub fn workdir_value_refused(diag: *Diag, value: []const u8) void {
    assert(value.len > 0);
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = text_util.sanitise(&storage, value);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("--workdir '{s}' is not an absolute path without '..' of at most {d} bytes", .{
        echo, constants.rootfs_bytes_max,
    });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "give a directory of the container:", .command = "--workdir /srv" });
    diag.mark_last_fix_template();
}

/// The record of the container called `name`, which must be running: its PID 1 alive and, with
/// a scope, in it.
fn find_container(
    host: Host,
    name: []const u8,
    handle: *Handle,
    record: *records.Parsed,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) {
        diagnose.no_such_container(diag, name, .no_state);
        return error.StartFailed;
    }
    records.load(host, &dir, name, record) catch |err| {
        const missing = err == error.NotFound;
        const why: diagnose.NoContainer = if (missing) .no_record else .unreadable_record;
        diagnose.no_such_container(diag, name, why);
        return error.StartFailed;
    };
    const state = lifecycle.state_of(host, record);
    const alive = record.pid > 1 and lifecycle.alive(host, record.pid, record.scope_slice());
    if (state != .running or !alive) {
        exec_diagnose.not_running(diag, name, state == .lost, record);
        return error.StartFailed;
    }
    handle.name.print("{s}", .{record.name_slice()});
    handle.container_pid = record.pid;
    handle.scope.print("{s}", .{record.scope_slice()});
    assert(handle.name.len > 0);
}

/// The container's environment, as its PID 1 was started with it.
fn read_environ(handle: *Handle, diag: *Diag) Error!void {
    assert(handle.container_pid > 1);
    var path: [48]u8 = undefined;
    // Cannot fail: "/proc/" and "/environ" and a pid of at most ten digits.
    const where = std.fmt.bufPrint(&path, "/proc/{d}/environ", .{handle.container_pid}) catch
        unreachable; // Same bound as above.
    const text = handle.host.read_file(where, &handle.environ) catch |err| {
        const failure: exec_diagnose.Failure = .{
            .err = err,
            .errno = handle.host.last_errno(),
        };
        const operation = "reading the environment of the container's first process";
        exec_diagnose.join_failed(diag, handle.info(), operation, failure);
        return error.StartFailed;
    };
    handle.environ_len = @intCast(text.len);
    assert(handle.environ_len <= exec_plan.environ_bytes_max);
}

/// The user the command runs as: `--user` looked up in the container's own files, else the
/// run's (a record older than version 8 says nothing: root). A container with only root mapped
/// has no other user.
fn choose_user(
    handle: *Handle,
    spec: *const Spec,
    record: *const records.Parsed,
    diag: *Diag,
) Error!?spec_mod.User {
    assert(handle.container_pid > 1);
    assert(diag.code == null);
    const user = if (spec.user) |text| try lookup_user(handle, text, diag) else record.user;
    const chosen = user orelse return null;
    const single = if (record.ids) |ids| ids == .single else false;
    if (single and (chosen.uid != 0 or chosen.gid != 0)) {
        exec_diagnose.user_needs_ids(diag, handle.name.slice(), chosen);
        return error.StartFailed;
    }
    return chosen;
}

fn lookup_user(handle: *Handle, text: []const u8, diag: *Diag) Error!spec_mod.User {
    assert(text.len > 0);
    assert(handle.container_pid > 1);
    if (text.len > constants.user_value_bytes_max) {
        workdir_value_refused_user(diag, text);
        return error.StartFailed;
    }
    const passwd = container_file(handle, image_user.passwd, &handle.user_files.passwd);
    const group = container_file(handle, image_user.group, &handle.user_files.group);
    var label: [96]u8 = undefined;
    // Cannot fail: a name of at most 63 bytes and a few words.
    const named = std.fmt.bufPrint(&label, "of the container {s}", .{handle.name.slice()}) catch
        unreachable; // Same bound as above.
    const resolved = image_user.resolve_text_from(text, passwd, group, named, diag) catch
        return error.StartFailed;
    return resolved.user;
}

/// ZBX-E0015: a `--user` value too long to look up.
fn workdir_value_refused_user(diag: *Diag, value: []const u8) void {
    assert(value.len > constants.user_value_bytes_max);
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = text_util.sanitise(&storage, value);
    diag.raise(.E0015);
    diag.while_("reading the command line", .{});
    diag.cause("--user '{s}': the user is longer than 256 bytes", .{echo});
    diag.fix(.{ .sentence = "give a user of the container, by name or number: --user 1000" });
}

/// A file of the container, read through its PID 1's root; null when it is not there or cannot
/// be read (a name is then not found, which the lookup says).
fn container_file(
    handle: *Handle,
    name: []const u8,
    buffer: *[constants.file_bytes_max]u8,
) ?[]const u8 {
    assert(name.len > 0);
    assert(name[0] == '/');
    var path: [64]u8 = undefined;
    // Cannot fail: "/proc/" and "/root" and a pid of ten digits and a short name.
    const pid = handle.container_pid;
    const where = std.fmt.bufPrint(&path, "/proc/{d}/root{s}", .{ pid, name }) catch
        unreachable; // Same bound as above.
    return handle.host.read_file(where, buffer) catch null;
}

fn refuse_input(handle: *const Handle, problem: exec_plan.InputProblem, diag: *Diag) void {
    assert(handle.name.len > 0);
    assert(diag.code == null);
    switch (problem) {
        .environ_too_big, .environ_too_many => {
            const failure: exec_diagnose.Failure = .{ .err = error.FileTooLarge, .errno = 0 };
            const operation = "reading the environment of the container's first process";
            exec_diagnose.join_failed(diag, handle.info(), operation, failure);
        },
        // `check_spec` refused the others before anything was read.
        .command_empty, .command_too_big, .env_too_many, .env_too_big, .workdir => {
            // A workdir from the record that `render` could not have written: damaged.
            diagnose.no_such_container(diag, handle.name.slice(), .unreadable_record);
        },
    }
}

/// Debug builds only: the process has exactly one thread before the joiner is forked.
fn assert_single_threaded(host: Host) void {
    var buffer: [constants.status_bytes_max]u8 = undefined;
    const status = host.read_file("/proc/self/status", &buffer) catch return;
    const threads = run.threads_in_status(status) orelse return;
    assert(threads > 0);
    assert(threads == 1);
}

// ---- The parent's steps --------------------------------------------------------------------

/// Runs the parent's steps until the command has started: everything but `reap`, which `wait`
/// does. A step that fails ends the exec: what was made is undone and the diagnostic names the
/// step; a failure a child reported is diagnosed the same way.
fn execute(handle: *Handle, diag: *Diag) Error!void {
    assert(handle.status == .starting);
    assert(handle.plan.count == handle.plan.steps_expected());
    const host = handle.host;
    const plan = &handle.plan;
    assert(diag.code == null);
    var failed_at: ?u8 = null;
    var failure: exec_diagnose.Failure = .{ .err = error.IoFailed, .errno = 0 };
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (exec_plan.side_of(step.kind) != .parent) continue;
        if (step.kind == .reap) continue;
        host.begin_step(@intCast(index));
        parent_step(handle, step, &failed_at, &failure) catch |err| {
            if (failed_at == null) {
                failed_at = @intCast(index);
                failure = .{ .err = err, .errno = host.last_errno() };
            }
            break;
        };
    }
    host.begin_step(host_mod.step_none);
    const index = failed_at orelse return;
    abandon(handle);
    if (plan.steps[index].kind == .join_cgroup and handle.cgroup_problem_set) {
        cgroup_diag(handle, diag);
    } else {
        exec_diagnose.step_failed(diag, handle.info(), plan, index, failure);
    }
    return error.StartFailed;
}

fn parent_step(
    handle: *Handle,
    step: exec_plan.Step,
    failed_at: *?u8,
    failure: *exec_diagnose.Failure,
) host_mod.Error!void {
    assert(step.kind != .reap);
    const host = handle.host;
    assert(exec_plan.side_of(step.kind) == .parent);
    switch (step.kind) {
        .make_pipes => try make_pipes(handle),
        .open_namespace => {
            const opened = try host.open_namespace(handle.container_pid, step.namespace);
            // Only the network can be the host's (`--net host`); any other is the container's.
            if (opened == null and step.namespace != .net) return error.IoFailed;
            handle.child.namespaces[@backingInt(step.namespace)] = opened;
            handle.namespaces_open = true;
        },
        .open_terminal => try open_terminal(handle),
        .spawn_joiner => try spawn_joiner(handle),
        .await_forked => try await_forked(handle, failed_at, failure),
        .reap_joiner => try reap_joiner(handle),
        .join_cgroup => try join_cgroup(handle),
        .release_command => {
            const byte = [1]u8{exec_child.go_ahead};
            try host.write_handle_all(handle.child.ready.write, &byte);
            host.close(handle.child.ready.write);
            handle.open.ready_write = false;
        },
        .await_report => try await_report(handle, failed_at, failure),
        .reap => unreachable, // `wait` does it.
        else => unreachable, // The children's steps.
    }
}

fn make_pipes(handle: *Handle) host_mod.Error!void {
    assert(!handle.pipes_child_ends_open);
    const host = handle.host;
    assert(!handle.open.ready_write);
    const ready = try host.pipe();
    const report = host.pipe() catch |err| {
        host.close(ready.read);
        host.close(ready.write);
        return err;
    };
    handle.child.ready = ready;
    handle.child.report = report;
    handle.open = .{ .ready_write = true, .report_read = true };
    handle.pipes_child_ends_open = true;
}

/// The pseudo-terminal, sized as zbx's own, and zbx's terminal raw: every key goes to the
/// command's terminal, which echoes, edits lines and sends ^C as SIGINT itself.
fn open_terminal(handle: *Handle) host_mod.Error!void {
    const host = handle.host;
    assert(handle.terminal == null);
    const terminal = try open_container_terminal(handle);
    handle.terminal = terminal;
    handle.child.peer = terminal.peer;
    handle.peer_open = true;
    handle.master_open = true;
    try host.copy_window_size(terminal.master);
    try host.input_raw(true, &handle.saved);
    handle.input_open = true;
    assert(handle.saved.valid);
}

/// A pseudo-terminal of the container's own devpts, reached through its PID 1's root, so that
/// the command finds its terminal under its /dev/pts (`tty` names it); a container without one
/// (the devpts mount is allowed to fail) gets one of the host's, which works as a terminal but
/// has no name inside.
fn open_container_terminal(handle: *Handle) host_mod.Error!host_mod.Terminal {
    const host = handle.host;
    assert(handle.container_pid > 1);
    var path: [64]u8 = undefined;
    // Cannot fail: "/proc/" and "/root/dev/pts/ptmx" and a pid of ten digits.
    const own = std.fmt.bufPrintSentinel(&path, "/proc/{d}/root/dev/pts/ptmx", .{
        handle.container_pid,
    }, 0) catch unreachable; // Same bound as above.
    const terminal = host.open_terminal(own) catch |err| {
        if (err != error.NotFound) return err;
        return host.open_terminal("/dev/ptmx");
    };
    assert(terminal.master != terminal.peer);
    return terminal;
}

fn spawn_joiner(handle: *Handle) host_mod.Error!void {
    assert(handle.pipes_child_ends_open);
    const host = handle.host;
    assert(handle.joiner == null);
    handle.joiner = try host.fork_child(false, exec_child.joiner_entry, &handle.child);
    // From here a write to the ready pipe may find no reader; that is an error to report.
    host.ignore_broken_pipe(true);
    // The children have their own copies: ours would keep the ends from ever closing.
    host.close(handle.child.ready.read);
    host.close(handle.child.report.write);
    handle.pipes_child_ends_open = false;
}

/// Reads the joiner's first record: the command's pid, or the failed step. An end with neither
/// is a joiner that died: IoFailed on this step.
fn await_forked(
    handle: *Handle,
    failed_at: *?u8,
    failure: *exec_diagnose.Failure,
) host_mod.Error!void {
    assert(handle.open.report_read);
    assert(handle.pid == null);
    var bytes: [constants.sync_record_bytes]u8 = undefined;
    const complete = try read_exact(handle.host, handle.child.report.read, &bytes);
    if (!complete) return error.IoFailed;
    if (sync.decode_forked(&bytes)) |pid| {
        handle.pid = pid;
        return;
    }
    const record = sync.Record.decode(&bytes).?; // Only our own joiner writes here.
    assert(record.kind == .failure);
    failed_at.* = record.step;
    failure.* = .{ .err = host_mod.error_for_errno(record.errno), .errno = record.errno };
    return error.IoFailed;
}

fn read_exact(host: Host, handle: host_mod.Handle, into: []u8) host_mod.Error!bool {
    assert(into.len <= constants.sync_record_bytes);
    assert(into.len > 0);
    var length: usize = 0;
    for (0..into.len + constants.eintr_retries_max) |_| {
        if (length == into.len) return true;
        const count = try host.read_some(handle, into[length..]);
        if (count == 0) return false;
        length += count;
    }
    return length == into.len;
}

/// The joiner has forked the command and has nothing more to do: it is reaped, and the
/// namespace files and the terminal's peer, which the command has its own copies of, closed.
fn reap_joiner(handle: *Handle) host_mod.Error!void {
    assert(handle.joiner != null);
    const host = handle.host;
    // Forgotten only once reaped: a wait that fails leaves it to `abandon`, which kills and
    // reaps it.
    _ = try host.wait_for(handle.joiner.?);
    handle.joiner = null;
    close_namespaces(handle);
    close_peer(handle);
    assert(handle.pid != null);
}

fn close_namespaces(handle: *Handle) void {
    assert(handle.child.namespaces.len == 6);
    if (handle.joiner != null) assert(handle.status == .starting);
    if (!handle.namespaces_open) return;
    handle.namespaces_open = false;
    for (handle.child.namespaces) |slot| {
        if (slot) |opened| handle.host.close(opened);
    }
}

fn close_peer(handle: *Handle) void {
    if (handle.peer_open) assert(handle.child.peer != null);
    if (!handle.peer_open) return;
    handle.peer_open = false;
    handle.host.close(handle.child.peer.?);
}

/// Puts the command in the container's cgroup while it waits for its go-ahead, so that nothing
/// it does happens outside the container's limits (`scope.attach`).
fn join_cgroup(handle: *Handle) host_mod.Error!void {
    assert(handle.pid != null);
    assert(handle.scope.len > 0);
    const pid = handle.pid.?;
    const name = handle.scope.slice();
    if (scope_mod.attach(handle.host, name, handle.container_pid, pid, &handle.cgroup_problem)) {
        return;
    }
    handle.cgroup_problem_set = true;
    return error.IoFailed;
}

fn cgroup_diag(handle: *const Handle, diag: *Diag) void {
    assert(diag.code == null);
    assert(handle.cgroup_problem_set);
    exec_diagnose.cgroup_failed(diag, handle.info(), handle.scope.slice(), &handle.cgroup_problem);
}

/// Reads the report pipe to its end: the command's exec closes it, or the command ends after a
/// failure record. The command that failed is reaped here.
fn await_report(
    handle: *Handle,
    failed_at: *?u8,
    failure: *exec_diagnose.Failure,
) host_mod.Error!void {
    const host = handle.host;
    assert(handle.open.report_read);
    var bytes: [constants.sync_record_bytes]u8 = undefined;
    const complete = try read_exact(host, handle.child.report.read, &bytes);
    host.close(handle.child.report.read);
    handle.open.report_read = false;
    if (!complete) return; // The end of file: the command started.
    const record = sync.Record.decode(&bytes).?; // Only our own command writes here.
    assert(record.kind == .failure);
    failed_at.* = record.step;
    failure.* = .{ .err = host_mod.error_for_errno(record.errno), .errno = record.errno };
    return error.IoFailed;
}

/// After a failed step: the children are killed and reaped, every descriptor closed, zbx's
/// terminal put back. Errors here are not reported: the step's own failure is what matters.
fn abandon(handle: *Handle) void {
    const host = handle.host;
    if (handle.pid) |pid| {
        host.signal(pid, constants.signal_kill) catch {};
        _ = host.wait_for(pid) catch {};
        handle.pid = null;
    }
    if (handle.joiner) |joiner| {
        host.signal(joiner, constants.signal_kill) catch {};
        _ = host.wait_for(joiner) catch {};
        handle.joiner = null;
    }
    if (handle.pipes_child_ends_open) {
        host.close(handle.child.ready.read);
        host.close(handle.child.report.write);
        handle.pipes_child_ends_open = false;
    }
    if (handle.open.ready_write) host.close(handle.child.ready.write);
    if (handle.open.report_read) host.close(handle.child.report.read);
    handle.open = .{ .ready_write = false, .report_read = false };
    close_namespaces(handle);
    close_peer(handle);
    close_terminal(handle);
    host.ignore_broken_pipe(false);
    assert(handle.pid == null);
    assert(handle.joiner == null);
}

/// zbx's terminal as it was, and the master closed.
fn close_terminal(handle: *Handle) void {
    if (handle.master_open) assert(handle.terminal != null);
    if (handle.input_open) assert(handle.terminal != null);
    if (handle.saved.valid) handle.host.input_raw(false, &handle.saved) catch {};
    handle.saved.valid = false;
    const terminal = handle.terminal orelse return;
    handle.host.close(terminal.master);
    handle.terminal = null;
    handle.master_open = false;
    handle.input_open = false;
}

// ---- Waiting -------------------------------------------------------------------------------

/// Waits for the command to end, forwarding the signals zbx receives and, with a terminal,
/// passing the keys to it and its output to zbx's, and a new window size on. Call it once.
pub fn wait(handle: *Handle) Exit {
    const host = handle.host;
    assert(handle.status == .running);
    assert(!handle.open.ready_write);
    host.begin_step(handle.plan.count - 1); // The `reap` step.
    const result = wait_loop(handle);
    host.begin_step(host_mod.step_none);
    handle.status = .stopped;
    const status = result catch |err| {
        const failure: exec_diagnose.Failure = .{ .err = err, .errno = host.last_errno() };
        abandon(handle);
        handle.lost_diag.reset();
        const index: u8 = @intCast(handle.plan.count - 1);
        exec_diagnose.step_failed(&handle.lost_diag, handle.info(), &handle.plan, index, failure);
        handle.ended = .lost;
        note_history(handle);
        return .lost;
    };
    handle.pid = null;
    drain_terminal(handle);
    close_terminal(handle);
    host.ignore_broken_pipe(false);
    handle.ended = switch (status) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
    };
    // A command killed by SIGKILL while its container's PID 1 is gone died with the container.
    if (handle.ended == .signaled and handle.ended.signaled == constants.signal_kill) {
        handle.container_ended = container_gone(handle);
    }
    note_history(handle);
    return handle.ended;
}

/// Whether the container's PID 1 is gone or on its way out. The kernel kills the other processes
/// of a PID namespace from PID 1's `do_exit` (`exit_notify`, `forget_original_parent`,
/// `find_child_reaper`, `zap_pid_ns_processes`), after `exit_signals` has set PF_EXITING in its
/// flags, and PID 1 is no zombie until every one of them is reaped, by parents that may be slow.
/// So a PID 1 that still looks alive died with the command if PF_EXITING shows in field 9 of its
/// `/proc/<pid>/stat`: that is decided once, with no wait. No retry backs it up: zbx signals only
/// PID 1, so every path on which the kernel kills the command for the namespace passes through
/// PF_EXITING first; a command that got SIGKILL before that (a kill of the whole cgroup from
/// outside zbx) was killed by someone else, which is what the exec then says.
fn container_gone(handle: *const Handle) bool {
    assert(handle.ended == .signaled);
    assert(handle.container_pid != 0);
    const host = handle.host;
    const pid = handle.container_pid;
    if (!lifecycle.alive(host, pid, handle.scope.slice())) return true;
    var buffer: [constants.status_bytes_max]u8 = undefined;
    var path: [48]u8 = undefined;
    // Cannot fail: "/proc/" and "/stat" are 11 bytes and a pid at most ten digits.
    const stat_path = std.fmt.bufPrint(&path, "/proc/{d}/stat", .{pid}) catch unreachable;
    // A stat that cannot be read went with its process between the two reads, or not: ask again.
    const stat = host.read_file(stat_path, &buffer) catch {
        return !lifecycle.alive(host, pid, handle.scope.slice());
    };
    return lifecycle.is_exiting(stat);
}

fn wait_loop(handle: *Handle) host_mod.Error!host_mod.ExitStatus {
    assert(handle.pid != null);
    assert(handle.status == .running);
    const host = handle.host;
    try host.block_signals(true);
    defer host.block_signals(false) catch {};
    var received: u32 = 0;
    for (0..constants.wait_timeout_ms_max) |_| {
        const event = try next_event(handle);
        switch (event) {
            .exited => |status| return status,
            .signal => |number| {
                if (number == constants.signal_winch) {
                    if (handle.master_open) {
                        host.copy_window_size(handle.terminal.?.master) catch {};
                    }
                    continue;
                }
                received += 1;
                // The command is not a PID 1: a signal it has no handler for acts on it, as it
                // would outside. A flood is cut off by killing it.
                const flood = received > constants.forwarded_signals_max;
                const sent = if (flood) constants.signal_kill else number;
                host.signal(handle.pid.?, sent) catch {};
            },
            .timeout => {},
            .output => |mask| pump(handle, mask),
        }
    }
    unreachable; // Every pass is an event of the command, a signal or its output.
}

/// The next event: with a terminal, also the keys on standard input and the command's output.
fn next_event(handle: *Handle) host_mod.Error!host_mod.Event {
    assert(handle.pid != null);
    if (handle.input_open) assert(handle.terminal != null);
    const host = handle.host;
    const pid = handle.pid.?;
    var watch: [2]host_mod.Handle = undefined;
    var count: u32 = 0;
    if (handle.input_open) {
        watch[count] = host.standard_input();
        count += 1;
    }
    if (handle.master_open) {
        watch[count] = handle.terminal.?.master;
        count += 1;
    }
    if (count == 0) return host.wait_event(pid, 0);
    const event = try host.wait_event_watching(pid, 0, watch[0..count]);
    if (event != .output) return event;
    // Bit 0 is the input when it is watched; the master is the last.
    var mask: u32 = 0;
    var at: u32 = 0;
    if (handle.input_open) {
        if (event.output & 1 != 0) mask |= input_bit;
        at = 1;
    }
    if (handle.master_open and event.output >> @intCast(at) & 1 != 0) mask |= master_bit;
    return .{ .output = mask };
}

const input_bit: u32 = 1;
const master_bit: u32 = 2;

/// One read from each ready side: the keys to the command's terminal, its output to zbx's.
fn pump(handle: *Handle, mask: u32) void {
    const host = handle.host;
    assert(mask != 0);
    assert(handle.terminal != null);
    const master = handle.terminal.?.master;
    var buffer: [constants.log_pump_bytes]u8 = undefined;
    if (mask & input_bit != 0) {
        const count = host.read_some(host.standard_input(), &buffer) catch 0;
        if (count == 0) {
            handle.input_open = false; // The keys end; the command's terminal stays.
        } else {
            host.write_handle_all(master, buffer[0..count]) catch {
                handle.input_open = false;
            };
        }
    }
    if (mask & master_bit != 0) {
        // EIO: every holder of the peer has closed it (the command and its children ended).
        const count = host.read_some(master, &buffer) catch 0;
        if (count == 0) {
            handle.master_open = false;
        } else {
            host.write_all(.stdout, buffer[0..count]) catch {};
        }
    }
}

/// What the command wrote to its terminal and zbx has not shown yet, within a bound of reads
/// and of time for a terminal that something else in the container still holds open.
fn drain_terminal(handle: *Handle) void {
    assert(handle.pid == null);
    if (handle.master_open) assert(handle.terminal != null);
    const host = handle.host;
    if (!handle.master_open) return;
    const master = handle.terminal.?.master;
    for (0..constants.log_drain_reads_max) |_| {
        var buffer: [constants.log_pump_bytes]u8 = undefined;
        const count = host.read_timeout(master, &buffer, constants.log_drain_ms) catch 0;
        if (count == 0) break;
        host.write_all(.stdout, buffer[0..count]) catch break;
    }
    handle.master_open = false;
}

/// Sends a signal to the command (another thread than `wait`'s may call this).
pub fn signal(handle: *const Handle, number: u8) host_mod.Error!void {
    assert(handle.status == .running);
    assert(number > 0);
    try handle.host.signal(handle.pid.?, number);
}

/// Notes the exec in the container's history; a failure is a warning (ZBX-W0207).
fn note_history(handle: *Handle) void {
    assert(handle.status == .stopped);
    assert(handle.command.len > 0);
    const host = handle.host;
    if (!handle.keep_history) return;
    var runs: records.Dir = undefined;
    if (!records.locate(host, &runs)) return;
    const logs = logfile.dir_of(&runs) orelse return;
    var entry: exec_history.Entry = undefined;
    entry.started = @min(handle.started, (1 << 40) - 1);
    entry.ended = @min(@max(host.time_now(), entry.started), (1 << 40) - 1);
    entry.exit = switch (handle.ended) {
        .exited => |code| .{ .exited = code },
        .signaled => |number| .{ .signaled = number },
        .lost => .lost,
    };
    entry.set_command(handle.command);
    const fs = host.log_files();
    fs.make_directory(logs.text(), true) catch {};
    exec_history.append(host, &logs, handle.name.slice(), &entry, &handle.history) catch |err| {
        var warning: Diag = undefined;
        warning.reset();
        const failure: exec_diagnose.Failure = .{ .err = err, .errno = fs.last_errno() };
        exec_diagnose.history_not_kept(&warning, handle.name.slice(), logs.text(), failure);
        handle.report_warning(&warning);
    };
}
