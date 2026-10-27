//! The simulator's model of a machine that runs containers: a small file tree, mount tables and
//! mount namespaces, processes with pipes, and the rules of the kernel that a container setup
//! must respect (`host_sim.zig` wraps these operations as `Host` calls and adds fault
//! injection; this file has no randomness and no faults).
//!
//! What is modelled, because a wrong plan breaks exactly these rules:
//!   - A mount needs its target to exist; a bind of a file needs a file; `pivot_root` needs the
//!     new root to be a mount point of a tree made private; the old root is detached after it.
//!   - A child created with a new mount namespace works on a copy of the mount table; one
//!     created without it would change the host's table. Same for the UTS (hostname) namespace.
//!   - An id map is written once, `gid_map` only after `setgroups` is denied, and an unprivileged
//!     writer may map only its own id to 0.
//!   - A pipe read waits for the child to run; end of file needs every writer to have closed or
//!     exec'd (the ends are close-on-exec). A read that could never complete is `Stalled`,
//!     which is how the simulator finds a deadlock in the code under test.
//!   - A child that is created runs its entry function when the parent first blocks on it
//!     (a pipe read or a wait), to completion, with its own process context.
//!
//! What is not: users, permissions, symlink resolution, `..` in paths, signals other than
//! kill, and the time a command takes. A command ends with `command_exit`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host = @import("host.zig");
const bpf = @import("runtime/bpf.zig");
const seccomp = @import("runtime/seccomp.zig");
const sim_bus = @import("sim_bus.zig");

pub const errno_perm: u16 = 1;
pub const errno_acces: u16 = 13;
pub const errno_noent: u16 = 2;
pub const errno_srch: u16 = 3;
pub const errno_child: u16 = 10;
pub const errno_nomem: u16 = 12;
pub const errno_exist: u16 = 17;
pub const errno_notdir: u16 = 20;
pub const errno_inval: u16 = 22;
pub const errno_pipe: u16 = 32;
pub const errno_nametoolong: u16 = 36;
pub const errno_noexec: u16 = 8;
pub const errno_nospc: u16 = 28;

/// A path of the simulated machine. Fixed-size, so the model never allocates.
pub const SimPath = struct {
    bytes: [constants.sim_path_bytes_max]u8 = undefined,
    len: u16 = 0,

    pub fn slice(path: *const SimPath) []const u8 {
        assert(path.len <= constants.sim_path_bytes_max);
        return path.bytes[0..path.len];
    }

    /// False if `text` does not fit; the path is then unchanged.
    pub fn set(path: *SimPath, text: []const u8) bool {
        if (text.len > constants.sim_path_bytes_max) return false;
        @memcpy(path.bytes[0..text.len], text);
        path.len = @intCast(text.len);
        return true;
    }

    pub fn eql(path: *const SimPath, text: []const u8) bool {
        return std.mem.eql(u8, path.slice(), text);
    }

    /// True if `path` is `prefix` or lies below it.
    pub fn under(path: *const SimPath, prefix: []const u8) bool {
        assert(prefix.len > 0);
        const text = path.slice();
        if (std.mem.eql(u8, prefix, "/")) return text.len > 0 and text[0] == '/';
        if (!std.mem.startsWith(u8, text, prefix)) return false;
        return text.len == prefix.len or text[prefix.len] == '/';
    }
};

/// The ids of the writer of a map: the only ones an unprivileged writer may map to 0.
pub const Ids = struct {
    uid: u32,
    gid: u32,
};

pub const NodeKind = enum { dir, file, symlink };

const Node = struct {
    path: SimPath,
    kind: NodeKind,
};

/// One mount. `kind` is null for a mount the host had before any container ran.
pub const Mount = struct {
    target: SimPath,
    kind: ?host.MountKind,
    /// Set for a procfs: whether it was mounted by a process in its own new PID namespace. A
    /// procfs of the host's namespace would show the host's processes.
    own_pid_namespace: bool,
    /// Remounted read-only (`MountKind.remount_readonly`).
    read_only: bool = false,
};

pub const MountTable = struct {
    mounts: [constants.sim_mounts_max]Mount,
    count: u32,
    /// Set by `make_private` on "/".
    private: bool,

    pub fn slice(table: *const MountTable) []const Mount {
        assert(table.count <= constants.sim_mounts_max);
        return table.mounts[0..table.count];
    }

    pub fn find(table: *const MountTable, target: []const u8) ?u32 {
        for (table.slice(), 0..) |*mount, index| {
            if (mount.target.eql(target)) return @intCast(index);
        }
        return null;
    }

    pub fn has(table: *const MountTable, kind: host.MountKind, target: []const u8) bool {
        for (table.slice()) |*mount| {
            if (mount.kind == kind and mount.target.eql(target)) return true;
        }
        return false;
    }

    fn add(table: *MountTable, mount: Mount) bool {
        if (table.count == constants.sim_mounts_max) return false;
        table.mounts[table.count] = mount;
        table.count += 1;
        return true;
    }

    fn remove_at(table: *MountTable, index: u32) void {
        assert(index < table.count);
        table.mounts[index] = table.mounts[table.count - 1];
        table.count -= 1;
    }

    /// Removes every mount that is not `target` or below it.
    fn keep_only_under(table: *MountTable, target: []const u8) void {
        var index: u32 = 0;
        while (index < table.count) {
            if (table.mounts[index].target.under(target)) {
                index += 1;
            } else {
                table.remove_at(index);
            }
        }
    }
};

pub const ProcessState = enum {
    unused,
    pending,
    running,
    /// The command started and has not ended: it ends when the scripted signals are all in.
    command,
    zombie,
    reaped,
};

/// The id-map files of a user namespace, as the kernel's write-once rules see them.
pub const IdMaps = struct {
    setgroups_denied: bool = false,
    gid_map: bool = false,
    uid_map: bool = false,
};

pub const text_bytes_max: u32 = 512;

pub const Process = struct {
    state: ProcessState,
    pid: u32,
    entry: ?host.ChildEntry,
    entry_context: ?*anyopaque,
    exit: ?host.ExitStatus,
    /// Index of the mount table this process sees: 0 is the host's.
    table: u8,
    /// Index of the hostname this process sees: 0 is the host's.
    uts: u8,
    new_user: bool,
    new_pid: bool,
    new_ipc: bool,
    maps: IdMaps,
    /// The process's current directory, as a path of the machine (not of its root).
    cwd: SimPath,
    /// The process's root directory once `pivot_root` ran; null before.
    root: ?SimPath,
    /// After `pivot_root` the old root is still mounted on the new one until it is detached.
    old_root_attached: bool,
    die_with_parent: bool,
    /// The capability mask the process was restricted to (`restrict_capabilities`), if it was.
    capabilities: ?u64,
    ambient_cleared: bool,
    no_new_privs: bool,
    /// A seccomp filter is installed (`install_seccomp`), and it answered ALLOW for the calls the
    /// process still has to make: write, close and exit_group (to report a failure), and execve.
    seccomp: bool,
    sealed: bool,
    /// When a command that started ends by itself, on the world's clock.
    ends_at_ms: u64,
    execd: bool,
    exec_path: SimPath,
    /// The argv and envp the command got, one string per line, for tests to compare.
    exec_argv: [text_bytes_max]u8,
    exec_argv_len: u16,
    exec_envp: [text_bytes_max]u8,
    exec_envp_len: u16,
    holds: [constants.sim_pipe_ends_max]bool,
    /// A scope's keeper (`World.start_keeper`): alive in the `command` state until the pipe it
    /// holds has no writer left, or it is killed.
    keeper: bool,

    pub fn argv(process: *const Process) []const u8 {
        return process.exec_argv[0..process.exec_argv_len];
    }

    pub fn envp(process: *const Process) []const u8 {
        return process.exec_envp[0..process.exec_envp_len];
    }
};

/// Room for the sync records of a start and for the frames a detached run's supervisor sends.
const pipe_bytes_max: u32 =
    @max(
        constants.sync_record_bytes * constants.sync_records_max + 4,
        constants.diag_carry_bytes_max + 16,
    );

const SimPipe = struct {
    used: bool,
    data: [pipe_bytes_max]u8,
    written: u32,
    consumed: u32,
};

/// Pipe ends are numbered from here, so a pipe handle is never mistaken for a file handle.
pub const pipe_handle_base: u32 = 1000;

/// Bus connections are numbered from here.
pub const bus_handle_base: u32 = 2000;

pub const pipes_max: u32 = constants.sim_pipe_ends_max / 2;

pub const Written = struct {
    path: SimPath,
    content: [constants.sim_written_bytes_max]u8,
    len: u32,
};

pub const script_max: u32 = 8;

/// What a simulated helper did: how it ended and how many bytes of output it wrote.
pub const HelperRun = struct {
    status: host.ExitStatus,
    len: u32,
};

pub const World = struct {
    nodes: [constants.sim_nodes_max]Node,
    nodes_count: u32,
    tables: [2]MountTable,
    processes: [constants.sim_processes_max]Process,
    /// The process whose context host calls run in.
    current: u8,
    pipes: [pipes_max]SimPipe,
    hostnames: [2]host.Text,
    /// What a command that started ends with.
    command_exit: host.ExitStatus,
    /// Mounting `/dev/pts` is refused (an environment without devpts for users).
    devpts_refused: bool,
    /// The kernel refuses overlay mounts (no module, a policy).
    overlay_refused: bool,
    broken_pipe_ignored: bool,
    next_pid: u32,
    /// The plan step the calls that follow belong to (`Host.begin_step`).
    step: u32,
    /// Files written through the host (run records), and whether the disk takes more.
    written: [constants.sim_written_files_max]Written,
    written_count: u32,
    disk_full: bool,
    now: u64,
    /// Signals that reach the container's parent while the command runs, in order. When any
    /// are scripted the command lives until they have all arrived.
    script: [script_max]u8,
    script_len: u32,
    script_at: u32,
    /// The signals the command's PID 1 has handlers for or ignores (`SignalState`).
    command_caught: u64,
    command_ignored: u64,
    /// The signals the command received, in order.
    received: [script_max * 2]u8,
    received_count: u32,
    signals_blocked: bool,
    /// The ids the helpers may map: a range of subordinate ids.
    subid_start: u32,
    subid_count: u32,
    helper_runs: u32,
    /// Makes the helpers fail with this exit code (null: they behave).
    helper_fails_with: ?u8,
    /// When the manager started a scope, the container's process had not run yet: it was waiting
    /// for the go-ahead, so nothing it does happens outside the scope.
    scope_started_before_child_ran: bool,
    /// The user's D-Bus socket and the systemd manager behind it (sim_bus.zig).
    bus: sim_bus.Bus,
    /// A clock for waits, in milliseconds: only sleeps and timed waits advance it.
    now_ms: u64,
    /// How long a command that started runs, in milliseconds of that clock, before it ends by
    /// itself. Zero: it ends the moment it is waited for (what every earlier test assumes).
    command_runs_ms: u32,
    /// A SIGTERM that the command catches ends it (with `term_exit_code`), as a daemon's does.
    term_exits: bool,
    term_exit_code: u8,
    /// What `fork_supervisor` answers, and the code the last `exit_now` was given.
    fork_role: host.Role,
    exited_with: ?u8,
    /// Faults for the lifecycle tests: `fork_supervisor` fails with this errno; a signal (but
    /// not the existence check, number 0) is refused with it; SIGKILL has no effect on the
    /// command (a process the kernel cannot kill).
    fork_errno: ?u16,
    kill_errno: ?u16,
    immortal: bool,
    /// What the kernel counted in the container's cgroup by the time it ended: processes the
    /// OOM killer killed (`memory.events`), and forks refused at the limit (`pids.events`).
    oom_kills: u32,
    pids_max_hits: u32,
    /// A scope's cgroup directory stays after the manager is done with its unit (a cgroup that
    /// something still holds).
    cgroup_stays: bool,
    /// What `memory.max` held in the last scope's cgroup when the cgroup went (the fallback
    /// write for an old systemd), since the file goes with it.
    ended_memory_max: ?host.Text,
    /// Faults for the keeper: forking it fails with this errno; it ends by itself (as if
    /// something killed it) the moment its scope has started.
    keeper_fork_errno: ?u16,
    keeper_dies_early: bool,
    /// Keepers started so far.
    keepers_started: u32,

    pub fn init(world: *World) void {
        world.nodes_count = 0;
        world.tables = undefined;
        for (&world.tables) |*table| {
            table.count = 0;
            table.private = false;
        }
        for (&world.processes) |*process| process.* = unused_process();
        world.current = 0;
        for (&world.pipes) |*pipe| pipe.used = false;
        world.hostnames = .{ host.Text.from_slice("simhost"), host.Text.from_slice("simhost") };
        world.command_exit = .{ .exited = 0 };
        world.devpts_refused = false;
        world.overlay_refused = false;
        world.broken_pipe_ignored = false;
        world.next_pid = 500;
        world.step = host.step_none;
        world.written_count = 0;
        world.disk_full = false;
        world.now = 1_760_000_000;
        world.script_len = 0;
        world.script_at = 0;
        world.command_caught = 0;
        world.command_ignored = 0;
        world.received_count = 0;
        world.signals_blocked = false;
        world.subid_start = 100000;
        world.subid_count = 65536;
        world.helper_runs = 0;
        world.helper_fails_with = null;
        world.scope_started_before_child_ran = false;
        world.bus.init();
        world.now_ms = 1_000_000;
        world.command_runs_ms = 0;
        world.term_exits = false;
        world.term_exit_code = 0;
        world.fork_role = .parent;
        world.exited_with = null;
        world.fork_errno = null;
        world.kill_errno = null;
        world.immortal = false;
        world.oom_kills = 0;
        world.pids_max_hits = 0;
        world.cgroup_stays = false;
        world.ended_memory_max = null;
        world.keeper_fork_errno = null;
        world.keeper_dies_early = false;
        world.keepers_started = 0;
        // The host's own process is alive from the start, in the host's namespaces.
        const first = &world.processes[0];
        first.state = .running;
        first.pid = world.take_pid();
        _ = first.cwd.set("/");
        assert(world.tables[0].count == 0);
        assert(world.processes[1].state == .unused);
    }

    fn take_pid(world: *World) u32 {
        world.next_pid += 1;
        return world.next_pid;
    }

    // ---- Setup for tests ----

    /// Adds `path` and every directory above it. A node that exists is left alone.
    pub fn add_node(world: *World, path: []const u8, kind: NodeKind) void {
        assert(path.len > 0);
        assert(path[0] == '/');
        var end: usize = 1;
        while (end < path.len) {
            const slash = std.mem.indexOfScalarPos(u8, path, end, '/');
            const stop = slash orelse path.len;
            const is_last = stop == path.len;
            world.add_one(path[0..stop], if (is_last) kind else .dir);
            end = stop + 1;
        }
    }

    fn add_one(world: *World, path: []const u8, kind: NodeKind) void {
        if (world.find_node(path) != null) return;
        assert(world.nodes_count < constants.sim_nodes_max);
        const node = &world.nodes[world.nodes_count];
        const fits = node.path.set(path);
        assert(fits); // Test setup uses short paths.
        node.kind = kind;
        world.nodes_count += 1;
    }

    /// A host with the devices a container binds, the host's usual mounts, and a root file
    /// system for the container with a shell in it.
    pub fn seed_container_host(world: *World, rootfs: []const u8) void {
        assert(rootfs.len > 0);
        assert(rootfs[0] == '/');
        const devices = [_][]const u8{ "null", "zero", "full", "random", "urandom", "tty" };
        for (devices) |name| {
            var path: [32]u8 = undefined;
            const text = std.fmt.bufPrint(&path, "/dev/{s}", .{name}) catch unreachable; // Short.
            world.add_node(text, .file);
        }
        world.add_node(rootfs, .dir);
        var buffer: [constants.sim_path_bytes_max]u8 = undefined;
        for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
            world.add_node(join(&buffer, rootfs, suffix), .dir);
        }
        world.add_node(join(&buffer, rootfs, "/bin/sh"), .file);
        world.add_node(join(&buffer, rootfs, "/bin/sleep"), .file);
        const table = &world.tables[0];
        for ([_][]const u8{ "/", "/proc", "/dev" }) |target| {
            var existing: Mount = .{
                .target = .{},
                .kind = null,
                .own_pid_namespace = false,
            };
            _ = existing.target.set(target);
            const added = table.add(existing);
            assert(added);
        }
        assert(table.count == 3);
    }

    // ---- Paths and nodes ----

    pub fn find_node(world: *const World, path: []const u8) ?u32 {
        for (world.nodes[0..world.nodes_count], 0..) |*node, index| {
            if (node.path.eql(path)) return @intCast(index);
        }
        return null;
    }

    pub fn node_kind(world: *const World, path: []const u8) ?NodeKind {
        if (std.mem.eql(u8, path, "/")) return .dir;
        const index = world.find_node(path) orelse return null;
        return world.nodes[index].kind;
    }

    /// Where `path`, as the current process names it, is on the machine. Null with an errno if
    /// it cannot be named: too long, or using `..`, which the model does not follow.
    fn resolve(world: *const World, path: []const u8, out: *SimPath) ?u16 {
        assert(path.len > 0);
        const process = &world.processes[world.current];
        if (path.len > constants.sim_path_bytes_max) return errno_nametoolong;
        if (std.mem.indexOf(u8, path, "..") != null) return errno_inval;
        var buffer: [constants.sim_path_bytes_max * 2 + 2]u8 = undefined;
        const absolute = path[0] == '/';
        const base: []const u8 = if (absolute)
            (if (process.root) |*root| root.slice() else "")
        else
            process.cwd.slice();
        const relative: []const u8 = if (std.mem.eql(u8, path, "."))
            ""
        else if (std.mem.startsWith(u8, path, "./"))
            path[2..]
        else
            path;
        const joined = if (relative.len == 0 or std.mem.eql(u8, relative, "/"))
            (if (base.len == 0) "/" else base)
        else if (absolute)
            join(&buffer, base, relative)
        else
            join_slash(&buffer, base, relative);
        if (!out.set(joined)) return errno_nametoolong;
        return null;
    }

    /// The parent directory of `path` must exist as a directory.
    fn parent_is_dir(world: *const World, path: *const SimPath) bool {
        const text = path.slice();
        const slash = std.mem.lastIndexOfScalar(u8, text, '/') orelse return false;
        if (slash == 0) return true;
        return world.node_kind(text[0..slash]) == .dir;
    }

    // ---- Processes and pipes ----

    pub fn find_process(world: *World, pid: u32) ?*Process {
        const index = world.find_index(pid) orelse return null;
        return &world.processes[index];
    }

    fn find_index(world: *const World, pid: u32) ?u8 {
        for (&world.processes, 0..) |*process, index| {
            if (process.pid == pid and process.state != .unused) return @intCast(index);
        }
        return null;
    }

    pub fn unreaped_children(world: *const World) u32 {
        var count: u32 = 0;
        for (world.processes[1..]) |*process| {
            switch (process.state) {
                .pending, .running, .command, .zombie => count += 1,
                .unused, .reaped => {},
            }
        }
        return count;
    }

    /// Pipe ends the host's own process still holds.
    pub fn open_pipe_ends(world: *const World) u32 {
        var count: u32 = 0;
        for (world.processes[0].holds) |held| {
            if (held) count += 1;
        }
        return count;
    }

    pub fn make_pipe(world: *World) ?host.Pipe {
        for (&world.pipes, 0..) |*pipe, index| {
            if (pipe.used) continue;
            pipe.* = .{ .used = true, .data = undefined, .written = 0, .consumed = 0 };
            const read_end: u32 = @intCast(2 * index);
            world.processes[world.current].holds[read_end] = true;
            world.processes[world.current].holds[read_end + 1] = true;
            return .{
                .read = pipe_handle_base + read_end,
                .write = pipe_handle_base + read_end + 1,
            };
        }
        return null;
    }

    fn end_index(handle: host.Handle) u32 {
        assert(handle >= pipe_handle_base);
        const index = handle - pipe_handle_base;
        assert(index < constants.sim_pipe_ends_max);
        return index;
    }

    fn writer_exists(world: *const World, pipe_index: u32) bool {
        for (&world.processes) |*process| {
            if (process.state == .unused or process.state == .reaped) continue;
            if (process.holds[2 * pipe_index + 1]) return true;
        }
        return false;
    }

    fn reader_exists(world: *const World, pipe_index: u32) bool {
        for (&world.processes) |*process| {
            if (process.state == .unused or process.state == .reaped) continue;
            if (process.holds[2 * pipe_index]) return true;
        }
        return false;
    }

    pub fn close_end(world: *World, handle: host.Handle) void {
        const index = end_index(handle);
        const held = &world.processes[world.current].holds[index];
        assert(held.*); // Closing an end the process does not hold is a programmer error.
        held.* = false;
        // A pipe nobody holds either end of is gone, as in the kernel; its slot can be reused.
        const pipe_index = index / 2;
        if (!world.reader_exists(pipe_index)) {
            if (!world.writer_exists(pipe_index)) world.pipes[pipe_index].used = false;
        }
        if (!world.writer_exists(pipe_index)) world.end_keepers_reading(pipe_index);
    }

    /// A keeper blocked reading a pipe that has lost its last writer sees the end of file and
    /// ends, which may leave its scope empty.
    fn end_keepers_reading(world: *World, pipe_index: u32) void {
        for (&world.processes) |*process| {
            if (!process.keeper or process.state != .command) continue;
            if (!process.holds[2 * pipe_index]) continue;
            world.keeper_ends(process, .{ .exited = 0 });
        }
    }

    fn keeper_ends(world: *World, process: *Process, status: host.ExitStatus) void {
        assert(process.keeper);
        assert(process.state == .command);
        process.exit = status;
        process.state = .zombie;
        process.holds = @splat(false);
        world.process_died(process.pid);
        world.scope_lost_process(process.pid);
    }

    /// Forks a keeper that holds the read end `hold`, outside every namespace. Null if no
    /// process is free or the fault says the fork fails (the errno is `keeper_fork_errno`).
    pub fn start_keeper(world: *World, hold: host.Handle) ?u32 {
        const slot = for (world.processes[1..], 1..) |*process, index| {
            if (process.state == .unused or process.state == .reaped) break index;
        } else return null;
        const read_end = end_index(hold);
        assert(read_end % 2 == 0); // The read end.
        assert(world.processes[world.current].holds[read_end]);
        const keeper = &world.processes[slot];
        keeper.* = unused_process();
        keeper.state = .command;
        keeper.keeper = true;
        keeper.pid = world.take_pid();
        keeper.cwd = world.processes[world.current].cwd;
        keeper.holds[read_end] = true; // It closes everything else.
        world.keepers_started += 1;
        return keeper.pid;
    }

    /// The scope the process was in has one process fewer; with none left, the manager removes
    /// it at once if the model says it does.
    fn scope_lost_process(world: *World, pid: u32) void {
        const slot = world.bus.process_ended(pid) orelse return;
        if (world.bus.model.scope_removal == .promptly) world.end_scope(slot);
    }

    /// Reads from a pipe end the current process holds. 0 means end of file. A read that waits
    /// for a child runs it first. Null with an errno when it would never return.
    pub fn read_pipe(world: *World, handle: host.Handle, buffer: []u8) union(enum) {
        count: u32,
        errno: u16,
    } {
        const index = end_index(handle);
        assert(index % 2 == 0); // The read end.
        assert(world.processes[world.current].holds[index]);
        const pipe_index = index / 2;
        const pipe = &world.pipes[pipe_index];
        while (pipe.consumed == pipe.written) {
            if (!world.writer_exists(pipe_index)) return .{ .count = 0 };
            if (!world.run_next_pending()) return .{ .errno = errno_inval }; // Deadlock.
        }
        const available = pipe.written - pipe.consumed;
        const count: u32 = @min(available, @as(u32, @intCast(buffer.len)));
        @memcpy(buffer[0..count], pipe.data[pipe.consumed..][0..count]);
        pipe.consumed += count;
        return .{ .count = count };
    }

    pub fn write_pipe(world: *World, handle: host.Handle, bytes: []const u8) ?u16 {
        const index = end_index(handle);
        assert(index % 2 == 1); // The write end.
        assert(world.processes[world.current].holds[index]);
        const pipe_index = index / 2;
        if (!world.reader_exists(pipe_index)) return errno_pipe;
        const pipe = &world.pipes[pipe_index];
        if (pipe.written + bytes.len > pipe.data.len) return errno_nomem;
        @memcpy(pipe.data[pipe.written..][0..bytes.len], bytes);
        pipe.written += @intCast(bytes.len);
        return null;
    }

    // ---- Spawn, run, wait ----

    pub fn spawn(
        world: *World,
        flags: host.SpawnFlags,
        entry: host.ChildEntry,
        entry_context: *anyopaque,
    ) ?u32 {
        const slot = for (world.processes[1..], 1..) |*process, index| {
            if (process.state == .unused or process.state == .reaped) break index;
        } else return null;
        const parent = world.processes[world.current];
        const child = &world.processes[slot];
        child.* = unused_process();
        child.state = .pending;
        child.pid = world.take_pid();
        child.entry = entry;
        child.entry_context = entry_context;
        child.new_user = flags.user;
        child.new_pid = flags.pid;
        child.new_ipc = flags.ipc;
        child.cwd = parent.cwd;
        child.root = parent.root;
        child.old_root_attached = parent.old_root_attached;
        child.holds = parent.holds;
        child.table = parent.table;
        child.uts = parent.uts;
        if (flags.mount) {
            const copy = @as(u8, @intCast(world.tables.len - 1));
            world.tables[copy] = world.tables[parent.table];
            child.table = copy;
        }
        if (flags.uts) {
            world.hostnames[1] = world.hostnames[parent.uts];
            child.uts = 1;
        }
        return child.pid;
    }

    /// Runs one child that has not run yet, to completion. False if there is none.
    fn run_next_pending(world: *World) bool {
        for (world.processes[1..], 1..) |*process, index| {
            if (process.state != .pending) continue;
            world.run_child(@intCast(index));
            return true;
        }
        return false;
    }

    /// The child runs inside the parent's blocking call, so the parent's step marker is saved
    /// and restored around it: the child's own steps mark themselves.
    fn run_child(world: *World, index: u8) void {
        const child = &world.processes[index];
        assert(child.state == .pending);
        child.state = .running;
        const previous = world.current;
        const previous_step = world.step;
        world.current = index;
        const code = child.entry.?(child.entry_context.?);
        world.current = previous;
        world.step = previous_step;
        assert(child.state == .running);
        child.holds = @splat(false);
        if (child.execd and (world.script_len > 0 or world.command_runs_ms > 0)) {
            // Still running: the scripted signals and the clock decide how it ends.
            child.state = .command;
            return;
        }
        child.exit = if (child.execd) world.command_exit else .{ .exited = code };
        child.state = .zombie;
    }

    /// Ends a child that has not run: it never gets to. Returns false if it is not pending.
    pub fn kill(world: *World, pid: u32, number: u8) ?u16 {
        const process = world.find_process(pid) orelse return errno_srch;
        if (number == 0) {
            const gone = process.state == .reaped or process.state == .unused;
            return if (gone) errno_srch else null;
        }
        if (world.kill_errno) |errno| return errno;
        if (process.keeper) {
            // A keeper has no handlers and is not PID 1 of anything: SIGKILL ends it and the
            // other signals end it too, but only SIGKILL is ever sent to it.
            if (process.state == .command) world.keeper_ends(process, .{ .signaled = number });
            return null;
        }
        switch (process.state) {
            .command => {
                assert(world.received_count < world.received.len);
                world.received[world.received_count] = number;
                world.received_count += 1;
                // PID 1 of a namespace ignores a signal it has no handler for, from outside it;
                // only SIGKILL (and SIGSTOP) cannot be ignored.
                if (number == constants.signal_kill and !world.immortal) {
                    process.exit = .{ .signaled = number };
                    process.state = .zombie;
                    world.process_died(process.pid);
                }
                const handled = host.SignalState.has(world.command_caught, number);
                if (number == constants.signal_term and handled and world.term_exits) {
                    process.exit = .{ .exited = world.term_exit_code };
                    process.state = .zombie;
                    world.process_died(process.pid);
                }
            },
            .pending => {
                process.exit = .{ .signaled = number };
                process.state = .zombie;
                process.holds = @splat(false);
            },
            .zombie => {},
            .unused, .reaped, .running => return errno_srch,
        }
        return null;
    }

    pub fn wait(world: *World, pid: u32) union(enum) { status: host.ExitStatus, errno: u16 } {
        const index = world.find_index(pid) orelse return .{ .errno = errno_child };
        if (world.processes[index].state == .pending) world.run_child(index);
        const process = &world.processes[index];
        // A keeper never ends by itself: waiting for one that is alive would never return.
        if (process.state == .command and !process.keeper) world.finish_command(process);
        if (process.state != .zombie) return .{ .errno = errno_child };
        world.reap(process);
        return .{ .status = process.exit.? };
    }

    /// The parent collects the child: it is gone, and so is a scope it was the last process of.
    fn reap(world: *World, process: *Process) void {
        assert(process.state == .zombie);
        process.state = .reaped;
        world.drop_proc_files(process.pid);
        world.scope_lost_process(process.pid);
    }

    /// A scope the manager has finished with leaves it, and its cgroup directory goes with it.
    /// The manager gets to it when someone next connects to the bus, unless the model says
    /// otherwise (`Model.scope_removal`).
    pub fn settle_scopes(world: *World) void {
        assert(world.nodes_count <= constants.sim_nodes_max);
        assert(world.written_count <= constants.sim_written_files_max);
        if (world.bus.model.scope_removal == .never) return;
        for (&world.bus.scopes, 0..) |*scope, index| {
            if (scope.active and scope.exited) world.end_scope(@intCast(index));
        }
    }

    /// What `memory.max` holds in the last scope's cgroup, or held when the cgroup went.
    pub fn last_memory_max(world: *const World) ?[]const u8 {
        if (world.ended_memory_max) |*text| return text.slice();
        var relative: [constants.cgroup_path_bytes_max]u8 = undefined;
        const path = scope_cgroup_path(&relative, &world.bus.last_scope);
        var file: [constants.cgroup_path_bytes_max + 48]u8 = undefined;
        // Cannot fail: a bounded path and a short name.
        const where = std.fmt.bufPrint(&file, "/sys/fs/cgroup{s}/memory.max", .{path}) catch
            unreachable; // Same bound as above.
        return world.read_written(where);
    }

    /// The scope is gone from the manager and from the cgroup tree.
    pub fn end_scope(world: *World, slot: u32) void {
        assert(slot < world.bus.scopes.len);
        const scope = &world.bus.scopes[slot];
        assert(scope.active);
        assert(scope.name.len > 0);
        scope.active = false;
        if (world.cgroup_stays) return;
        var path_buffer: [constants.cgroup_path_bytes_max]u8 = undefined;
        const relative = scope_cgroup_path(&path_buffer, scope);
        var directory_buffer: [constants.cgroup_path_bytes_max + 16]u8 = undefined;
        // Cannot fail: a bounded relative path and a short prefix fit the buffer.
        const prefix = "/sys/fs/cgroup{s}";
        const directory = std.fmt.bufPrint(&directory_buffer, prefix, .{relative}) catch
            unreachable; // Same bound as above.
        var limit_path: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
        // Cannot fail: a bounded directory and a short name.
        const memory_path = std.fmt.bufPrint(&limit_path, "{s}/memory.max", .{directory}) catch
            unreachable; // Same bound as above.
        world.ended_memory_max = if (world.read_written(memory_path)) |text|
            host.Text.from_slice(text)
        else
            null;
        var at: u32 = 0;
        while (at < world.written_count) {
            const under = world.written[at].path.under(directory);
            if (under) world.drop_written(at) else at += 1;
        }
        if (world.find_node(directory)) |index| {
            world.nodes[index] = world.nodes[world.nodes_count - 1];
            world.nodes_count -= 1;
        }
        assert(world.find_node(directory) == null);
    }

    /// Gives a scope the manager just started its files: the cgroup directory, and the
    /// `/proc/<pid>/cgroup` line that names it, which is how a client finds the directory.
    pub fn start_scope_files(world: *World, scope: *const sim_bus.Scope) void {
        var path_buffer: [constants.cgroup_path_bytes_max]u8 = undefined;
        const relative = scope_cgroup_path(&path_buffer, scope);
        var directory_buffer: [constants.cgroup_path_bytes_max + 16]u8 = undefined;
        // Cannot fail: a bounded relative path and a short prefix fit the buffer.
        const prefix = "/sys/fs/cgroup";
        const directory = std.fmt.bufPrint(&directory_buffer, prefix ++ "{s}", .{relative}) catch
            unreachable; // Same bound as above.
        world.add_node(directory, .dir);
        var pid_buffer: [32]u8 = undefined;
        // Cannot fail: "/proc/4294967295" fits.
        const proc_directory = std.fmt.bufPrint(&pid_buffer, "/proc/{d}", .{scope.pid}) catch
            unreachable; // Same.
        world.add_node(proc_directory, .dir);
        if (world.find_process(scope.pid)) |process| {
            world.scope_started_before_child_ran = process.state == .pending;
        }
        world.write_event_files(directory);
        if (world.keeper_dies_early and scope.keeper_pid != 0) {
            if (world.find_process(scope.keeper_pid)) |keeper| {
                if (keeper.state == .command) world.keeper_ends(keeper, .{ .signaled = 9 });
            }
        }
        var file_buffer: [48]u8 = undefined;
        // Cannot fail: same.
        const file = std.fmt.bufPrint(&file_buffer, "{s}/cgroup", .{proc_directory}) catch
            unreachable; // Same.
        var line_buffer: [constants.cgroup_path_bytes_max + 8]u8 = undefined;
        // Cannot fail: the relative path is bounded.
        const line = std.fmt.bufPrint(&line_buffer, "0::{s}\n", .{relative}) catch unreachable;
        _ = world.write_file(file, line);
    }

    /// The files the kernel keeps in a cgroup that say what happened to it. They hold the final
    /// counts from the start: the model has no time, and a command ends the way it is told to.
    fn write_event_files(world: *World, directory: []const u8) void {
        assert(directory.len > 0);
        assert(directory[0] == '/');
        var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
        var text_buffer: [128]u8 = undefined;
        const memory = "low 0\nhigh 0\nmax 0\noom {d}\noom_kill {d}\noom_group_kill 0\n";
        // Cannot fail: a short format with two numbers in 128 bytes.
        const counts = .{ world.oom_kills, world.oom_kills };
        const events = std.fmt.bufPrint(&text_buffer, memory, counts) catch
            unreachable; // Same bound as above.
        const memory_path = std.fmt.bufPrint(&path_buffer, "{s}/memory.events", .{directory}) catch
            unreachable; // The directory is bounded and the name short.
        _ = world.write_file(memory_path, events);
        // Cannot fail: same.
        const pids = std.fmt.bufPrint(&text_buffer, "max {d}\n", .{world.pids_max_hits}) catch
            unreachable; // Same.
        const pids_path = std.fmt.bufPrint(&path_buffer, "{s}/pids.events", .{directory}) catch
            unreachable; // Same.
        _ = world.write_file(pids_path, pids);
        const populated = std.fmt.bufPrint(&path_buffer, "{s}/cgroup.events", .{directory}) catch
            unreachable; // Same.
        _ = world.write_file(populated, "populated 1\nfrozen 0\n");
    }

    /// The process exists and is not a zombie: the kernel counts it in its cgroup.
    fn process_alive(world: *World, pid: u32) bool {
        const process = world.find_process(pid) orelse return false;
        return switch (process.state) {
            .pending, .running, .command => true,
            .unused, .zombie, .reaped => false,
        };
    }

    /// The process is gone, and so are its files in /proc.
    fn drop_proc_files(world: *World, pid: u32) void {
        inline for (.{ "status", "cgroup" }) |name| {
            var path: [48]u8 = undefined;
            // Cannot fail: a short path and a pid of at most ten digits.
            const where = std.fmt.bufPrint(&path, "/proc/{d}/" ++ name, .{pid}) catch unreachable;
            if (world.find_written(where)) |index| world.drop_written(index);
        }
    }

    /// `/proc/<pid>/status` of a container's PID 1, as far as a lookup of its identity goes: its
    /// innermost pid is 1 (`NSpid`). Written straight, not through the process's own root.
    fn put_status_file(world: *World, pid: u32, zombie: bool) void {
        var path: [48]u8 = undefined;
        var text: [64]u8 = undefined;
        // Cannot fail: a short path and a short line with a pid of at most ten digits.
        const where = std.fmt.bufPrint(&path, "/proc/{d}/status", .{pid}) catch unreachable;
        const state = if (zombie) "Z (zombie)" else "S (sleeping)";
        const format = "State:\t{s}\nNSpid:\t{d}\t1\n";
        const line = std.fmt.bufPrint(&text, format, .{ state, pid }) catch unreachable; // Same.
        world.put_raw(where, line);
    }

    /// Stores a file by its real path, bypassing the current process's root.
    pub fn put_raw(world: *World, path: []const u8, bytes: []const u8) void {
        var real: SimPath = .{};
        const fits = real.set(path);
        assert(fits);
        const existing = world.find_written(path);
        if (existing == null and world.written_count == constants.sim_written_files_max) return;
        const index = existing orelse world.written_count;
        if (existing == null) world.written_count += 1;
        world.written[index].path = real;
        @memcpy(world.written[index].content[0..bytes.len], bytes);
        world.written[index].len = @intCast(bytes.len);
    }

    /// The command ends by itself, the way the model says it does.
    fn finish_command(world: *World, process: *Process) void {
        assert(process.state == .command);
        process.exit = world.command_exit;
        process.state = .zombie;
        world.process_died(process.pid);
    }

    /// The kernel counts a zombie out of its cgroup: the scope is no longer populated.
    fn process_died(world: *World, pid: u32) void {
        if (world.find_process(pid)) |process| {
            // The status file of a process that ended and is not reaped says so.
            if (process.execd) world.put_status_file(pid, true);
        }
        for (&world.bus.scopes) |*scope| {
            if (!scope.active) continue;
            const mine = scope.pid == pid or (scope.keeper_pid != 0 and scope.keeper_pid == pid);
            if (!mine) continue;
            // The scope is empty only when its container and its keeper are both out of it.
            if (world.process_alive(scope.pid)) continue;
            if (scope.keeper_pid != 0 and world.process_alive(scope.keeper_pid)) continue;
            var relative: [constants.cgroup_path_bytes_max]u8 = undefined;
            const path = scope_cgroup_path(&relative, scope);
            var file: [constants.cgroup_path_bytes_max + 48]u8 = undefined;
            // Cannot fail: a bounded path and a short name.
            const where = std.fmt.bufPrint(&file, "/sys/fs/cgroup{s}/cgroup.events", .{path}) catch
                unreachable; // Same bound as above.
            if (world.find_written(where) != null) world.put_raw(where, "populated 0\nfrozen 0\n");
        }
    }

    /// Waits for the child to end or for a scripted signal to arrive.
    pub fn wait_event(
        world: *World,
        pid: u32,
        timeout_ms: u32,
    ) union(enum) { event: host.Event, errno: u16 } {
        const index = world.find_index(pid) orelse return .{ .errno = errno_child };
        if (world.processes[index].state == .pending) world.run_child(index);
        const process = &world.processes[index];
        assert(world.signals_blocked); // Otherwise a real signal would have acted instead.
        if (process.state == .command) {
            if (world.script_at < world.script_len) {
                defer world.script_at += 1;
                return .{ .event = .{ .signal = world.script[world.script_at] } };
            }
            const left = process.ends_at_ms -| world.now_ms;
            if (timeout_ms > 0 and left > timeout_ms) {
                world.now_ms += timeout_ms;
                return .{ .event = .timeout };
            }
            world.now_ms += left;
            world.finish_command(process);
        }
        if (process.state != .zombie) return .{ .errno = errno_child };
        world.reap(process);
        return .{ .event = .{ .exited = process.exit.? } };
    }

    pub fn signal_state(world: *World, pid: u32) ?host.SignalState {
        const process = world.find_process(pid) orelse return null;
        if (process.state != .command) return .{ .caught = 0, .ignored = 0 };
        return .{ .caught = world.command_caught, .ignored = world.command_ignored };
    }

    // ---- Files written through the host ----

    pub fn find_written(world: *const World, path: []const u8) ?u32 {
        for (world.written[0..world.written_count], 0..) |*file, index| {
            if (file.path.eql(path)) return @intCast(index);
        }
        return null;
    }

    pub fn read_written(world: *const World, path: []const u8) ?[]const u8 {
        const index = world.find_written(path) orelse return null;
        return world.written[index].content[0..world.written[index].len];
    }

    pub fn write_file(world: *World, path: []const u8, bytes: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        if (!world.parent_is_dir(&real)) return errno_noent;
        if (world.node_kind(real.slice()) != null) return errno_notdir;
        // A full disk is the state directory's; cgroup and proc files are not on it.
        const on_disk = !real.under("/sys") and !real.under("/proc");
        if (world.disk_full and on_disk) return errno_nospc;
        if (bytes.len > constants.sim_written_bytes_max) return errno_nospc;
        const existing = world.find_written(real.slice());
        if (existing == null and world.written_count == constants.sim_written_files_max) {
            return errno_nospc;
        }
        const index = existing orelse world.written_count;
        if (existing == null) world.written_count += 1;
        const file = &world.written[index];
        file.path = real;
        @memcpy(file.content[0..bytes.len], bytes);
        file.len = @intCast(bytes.len);
        return null;
    }

    pub fn rename_file(world: *World, from: []const u8, to: []const u8) ?u16 {
        var source: SimPath = .{};
        var target: SimPath = .{};
        if (world.resolve(from, &source)) |errno| return errno;
        if (world.resolve(to, &target)) |errno| return errno;
        const index = world.find_written(source.slice()) orelse return errno_noent;
        if (!world.parent_is_dir(&target)) return errno_noent;
        if (world.find_written(target.slice())) |old| world.drop_written(old);
        const moved = world.find_written(source.slice()).?;
        world.written[moved].path = target;
        assert(index < constants.sim_written_files_max);
        return null;
    }

    pub fn remove_written(world: *World, path: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        const index = world.find_written(real.slice()) orelse return errno_noent;
        world.drop_written(index);
        return null;
    }

    fn drop_written(world: *World, index: u32) void {
        assert(index < world.written_count);
        world.written[index] = world.written[world.written_count - 1];
        world.written_count -= 1;
    }

    pub fn list_written(world: *const World, path: []const u8, listing: *host.DirListing) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        const kind = world.node_kind(real.slice()) orelse return errno_noent;
        if (kind != .dir) return errno_notdir;
        for (world.written[0..world.written_count]) |*file| {
            const text = file.path.slice();
            const slash = std.mem.lastIndexOfScalar(u8, text, '/') orelse continue;
            const directory = if (slash == 0) "/" else text[0..slash];
            if (std.mem.eql(u8, directory, real.slice())) listing.add(text[slash + 1 ..]);
        }
        return null;
    }

    // ---- Helper programs ----

    /// What `newuidmap` and `newgidmap` do for a caller with these ids: map the caller's own id
    /// to 0 and a range of its subordinate ids above it, once. `argv` is the program's name,
    /// the pid and the triples, as numbers in text.
    pub fn run_helper(
        world: *World,
        request: host.ExecRequest,
        ids: Ids,
        output: []u8,
    ) HelperRun {
        world.helper_runs += 1;
        const program = std.fs.path.basename(request.path);
        const is_uid = std.mem.eql(u8, program, "newuidmap");
        if (!is_uid) assert(std.mem.eql(u8, program, "newgidmap"));
        const refused = if (is_uid)
            "newuidmap: write to uid_map failed: Operation not permitted\n"
        else
            "newgidmap: write to gid_map failed: Operation not permitted\n";
        if (world.helper_fails_with) |code| return failed_helper(refused, code, output);
        var words: [constants.helper_words_max][]const u8 = undefined;
        var count: usize = 0;
        while (request.argv[count]) |word| : (count += 1) {
            if (count == words.len) return failed_helper(refused, 1, output);
            words[count] = std.mem.span(word);
        }
        const pid = std.fmt.parseInt(u32, words[1], 10) catch return failed_helper(
            refused,
            1,
            output,
        );
        const target = world.find_process(pid) orelse return failed_helper(refused, 1, output);
        const done = if (is_uid) &target.maps.uid_map else &target.maps.gid_map;
        const own = if (is_uid) ids.uid else ids.gid;
        if (done.* or !target.new_user or !world.map_allowed(words[2..count], own)) {
            return failed_helper(refused, 1, output);
        }
        done.* = true;
        return .{ .status = .{ .exited = 0 }, .len = 0 };
    }

    /// The caller's own id to 0, then ranges inside what it was given, each of three numbers.
    fn map_allowed(world: *const World, numbers: []const []const u8, own: u32) bool {
        if (numbers.len == 0) return false;
        if (numbers.len % 3 != 0) return false;
        var at: usize = 0;
        while (at < numbers.len) : (at += 3) {
            const inside = std.fmt.parseInt(u32, numbers[at], 10) catch return false;
            const outside = std.fmt.parseInt(u32, numbers[at + 1], 10) catch return false;
            const length = std.fmt.parseInt(u32, numbers[at + 2], 10) catch return false;
            if (length == 0) return false;
            if (at == 0) {
                if (inside != 0 or outside != own or length != 1) return false;
                continue;
            }
            const end = @as(u64, outside) + length;
            const allowed_end = @as(u64, world.subid_start) + world.subid_count;
            if (outside < world.subid_start or end > allowed_end) return false;
        }
        return true;
    }

    // ---- Id maps and hostname ----

    /// `ids` are the writer's own user and group id, the only ones an unprivileged writer may map.
    pub fn write_id_map(
        world: *World,
        pid: u32,
        kind: host.IdMapKind,
        bytes: []const u8,
        ids: Ids,
    ) ?u16 {
        const target = world.find_process(pid) orelse return errno_srch;
        if (!target.new_user) return errno_perm; // The host's own maps are not writable.
        switch (kind) {
            .setgroups => {
                if (target.maps.gid_map) return errno_perm; // Too late once gid_map is written.
                if (!std.mem.eql(u8, bytes, "deny")) return errno_inval;
                target.maps.setgroups_denied = true;
            },
            .gid_map => {
                if (target.maps.gid_map) return errno_perm;
                if (!target.maps.setgroups_denied) return errno_perm;
                if (!single_map_line(bytes, ids.gid)) return errno_perm;
                target.maps.gid_map = true;
            },
            .uid_map => {
                if (target.maps.uid_map) return errno_perm;
                if (!single_map_line(bytes, ids.uid)) return errno_perm;
                target.maps.uid_map = true;
            },
        }
        return null;
    }

    pub fn set_hostname(world: *World, name: []const u8) ?u16 {
        const process = &world.processes[world.current];
        if (name.len == 0 or name.len > constants.container_name_bytes_max) return errno_inval;
        world.hostnames[process.uts] = host.Text.from_slice(name);
        return null;
    }

    // ---- Files and mounts ----

    pub fn make_directory(world: *World, path: []const u8, exist_ok: bool) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        if (world.node_kind(real.slice())) |_| return if (exist_ok) null else errno_exist;
        if (!world.parent_is_dir(&real)) return errno_noent;
        return world.add_checked(real.slice(), .dir);
    }

    pub fn create_file(world: *World, path: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        if (world.node_kind(real.slice()) != null) return errno_exist;
        if (!world.parent_is_dir(&real)) return errno_noent;
        return world.add_checked(real.slice(), .file);
    }

    pub fn symlink(world: *World, link: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(link, &real)) |errno| return errno;
        if (world.node_kind(real.slice()) != null) return errno_exist;
        if (!world.parent_is_dir(&real)) return errno_noent;
        return world.add_checked(real.slice(), .symlink);
    }

    fn add_checked(world: *World, real: []const u8, kind: NodeKind) ?u16 {
        if (world.nodes_count == constants.sim_nodes_max) return errno_nomem;
        world.add_one(real, kind);
        return null;
    }

    pub fn change_directory(world: *World, path: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        const kind = world.node_kind(real.slice()) orelse return errno_noent;
        if (kind != .dir) return errno_notdir;
        world.processes[world.current].cwd = real;
        return null;
    }

    pub fn mount(world: *World, request: host.MountRequest) ?u16 {
        const process = &world.processes[world.current];
        const table = &world.tables[process.table];
        var target: SimPath = .{};
        if (world.resolve(request.target, &target)) |errno| return errno;
        if (request.kind == .make_private) {
            if (!target.eql("/")) return errno_inval;
            table.private = true;
            return null;
        }
        if (request.kind == .remount_readonly) {
            // Only a mount point can be remounted; the rootfs bind is one.
            const index = table.find(target.slice()) orelse return errno_inval;
            table.mounts[index].read_only = true;
            return null;
        }
        if (world.mount_target_error(request.kind, &target)) |errno| return errno;
        if (request.kind == .devpts) {
            if (world.devpts_refused) return errno_perm;
        }
        if (request.kind == .overlay) {
            if (world.overlay_refused) return errno_perm;
        } else if (request.source) |source| {
            if (world.bind_source_error(request.kind, source)) |errno| return errno;
        }
        const made: Mount = .{
            .target = target,
            .kind = request.kind,
            .own_pid_namespace = process.new_pid,
        };
        // A mount made while the tree is still shared propagates to the namespace it was
        // copied from. That is the host's: the leak `make_private` exists to prevent.
        if (!table.private and process.table != 0) _ = world.tables[0].add(made);
        const added = table.add(made);
        return if (added) null else errno_nomem;
    }

    fn mount_target_error(world: *const World, kind: host.MountKind, target: *const SimPath) ?u16 {
        const found = world.node_kind(target.slice()) orelse return errno_noent;
        const wants_file = kind == .bind_file;
        if (wants_file and found != .file) return errno_notdir;
        if (!wants_file and found != .dir) return errno_notdir;
        return null;
    }

    fn bind_source_error(world: *const World, kind: host.MountKind, source: []const u8) ?u16 {
        var real: SimPath = .{};
        if (world.resolve(source, &real)) |errno| return errno;
        const found = world.node_kind(real.slice()) orelse return errno_noent;
        if (kind == .bind_file and found != .file) return errno_inval;
        if (kind == .bind_tree and found != .dir) return errno_notdir;
        return null;
    }

    pub fn unmount_detach(world: *World, path: []const u8) ?u16 {
        const process = &world.processes[world.current];
        const table = &world.tables[process.table];
        var real: SimPath = .{};
        if (world.resolve(path, &real)) |errno| return errno;
        if (process.old_root_attached) {
            const root = process.root.?;
            if (!real.eql(root.slice())) return errno_inval;
            table.keep_only_under(root.slice());
            process.old_root_attached = false;
            return null;
        }
        const index = table.find(real.slice()) orelse return errno_inval;
        table.remove_at(index);
        return null;
    }

    pub fn pivot_root(world: *World, new_root: []const u8, put_old: []const u8) ?u16 {
        const process = &world.processes[world.current];
        const table = &world.tables[process.table];
        if (process.root != null) return errno_inval; // Pivoting twice is not what this does.
        var root: SimPath = .{};
        var old: SimPath = .{};
        if (world.resolve(new_root, &root)) |errno| return errno;
        if (world.resolve(put_old, &old)) |errno| return errno;
        // The new root must be a mount point, the tree must not propagate, and the old root goes
        // at or below the new one.
        const index = table.find(root.slice()) orelse return errno_inval;
        const root_kind = table.mounts[index].kind;
        if (root_kind != .bind_tree and root_kind != .overlay) return errno_inval;
        if (!table.private) return errno_inval;
        if (!old.under(root.slice())) return errno_inval;
        process.root = root;
        process.old_root_attached = true;
        return null;
    }

    pub fn begin_step(world: *World, index: u32) void {
        world.step = index;
    }

    pub fn seal(world: *World) void {
        world.processes[world.current].sealed = true;
    }

    /// The capability calls of a container's setup, in the order the child makes them.
    pub fn restrict_capabilities(world: *World, keep: u64) ?u16 {
        assert(keep != 0);
        assert(world.current < world.processes.len);
        const process = &world.processes[world.current];
        if (process.no_new_privs or process.seccomp) return errno_inval; // Out of order.
        process.capabilities = keep;
        return null;
    }

    pub fn clear_ambient(world: *World) void {
        assert(world.current < world.processes.len);
        world.processes[world.current].ambient_cleared = true;
    }

    pub fn no_new_privs(world: *World) void {
        assert(world.current < world.processes.len);
        world.processes[world.current].no_new_privs = true;
    }

    /// The filter is run on the calls the child makes after it: execve, write, close and
    /// exit_group must be allowed on this machine's architecture, or the container could not
    /// start (or report why not).
    pub fn install_seccomp(world: *World, program: []const bpf.Insn) ?u16 {
        assert(program.len > 0);
        assert(world.current < world.processes.len);
        const process = &world.processes[world.current];
        if (!process.no_new_privs) return errno_acces; // The kernel needs it, or CAP_SYS_ADMIN.
        if (bpf.verify(program) != null) return errno_inval;
        if (!seccomp.allows_native(program, "execve")) return errno_perm;
        if (!seccomp.allows_native(program, "write")) return errno_perm;
        if (!seccomp.allows_native(program, "close")) return errno_perm;
        if (!seccomp.allows_native(program, "exit_group")) return errno_perm;
        process.seccomp = true;
        return null;
    }

    pub fn die_with_parent(world: *World) void {
        world.processes[world.current].die_with_parent = true;
    }

    /// Replaces the current process by the program at `path`, which must be a file below its
    /// root. The close-on-exec pipe ends close: every end this model hands out is one.
    pub fn exec(world: *World, request: host.ExecRequest) ?u16 {
        const process = &world.processes[world.current];
        var real: SimPath = .{};
        if (world.resolve(request.path, &real)) |errno| return errno;
        const kind = world.node_kind(real.slice()) orelse return errno_noent;
        if (kind != .file) return errno_noexec;
        process.exec_path = real;
        process.exec_argv_len = copy_lines(&process.exec_argv, request.argv);
        process.exec_envp_len = copy_lines(&process.exec_envp, request.envp);
        process.execd = true;
        process.ends_at_ms = world.now_ms + world.command_runs_ms;
        process.holds = @splat(false);
        world.put_status_file(process.pid, false);
        return null;
    }
};

fn failed_helper(
    message: []const u8,
    code: u8,
    output: []u8,
) HelperRun {
    const length = @min(message.len, output.len);
    @memcpy(output[0..length], message[0..length]);
    return .{ .status = .{ .exited = code }, .len = @intCast(length) };
}

fn unused_process() Process {
    return .{
        .state = .unused,
        .pid = 0,
        .entry = null,
        .entry_context = null,
        .exit = null,
        .table = 0,
        .uts = 0,
        .new_user = false,
        .new_pid = false,
        .new_ipc = false,
        .maps = .{},
        .cwd = .{},
        .root = null,
        .old_root_attached = false,
        .die_with_parent = false,
        .capabilities = null,
        .ambient_cleared = false,
        .no_new_privs = false,
        .seccomp = false,
        .sealed = false,
        .ends_at_ms = 0,
        .execd = false,
        .exec_path = .{},
        .exec_argv = undefined,
        .exec_argv_len = 0,
        .exec_envp = undefined,
        .exec_envp_len = 0,
        .holds = @splat(false),
        .keeper = false,
    };
}

/// Copies a null-terminated array of C strings into `buffer`, one per line, cutting at its end.
fn copy_lines(buffer: *[text_bytes_max]u8, strings: host.CStrings) u16 {
    var length: usize = 0;
    var index: usize = 0;
    while (strings[index]) |text| : (index += 1) {
        assert(index < 4096); // The arrays are bounded by the plan; this guards a missing null.
        const bytes = std.mem.span(text);
        if (length + bytes.len + 1 > buffer.len) break;
        @memcpy(buffer[length..][0..bytes.len], bytes);
        buffer[length + bytes.len] = '\n';
        length += bytes.len + 1;
    }
    return @intCast(length);
}

/// True if `bytes` is exactly one line mapping container id 0 to `id`, with a count of 1.
fn single_map_line(bytes: []const u8, id: u32) bool {
    var expected: [constants.id_map_line_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(&expected, "0 {d} 1\n", .{id}) catch return false;
    return std.mem.eql(u8, bytes, text);
}

fn join(buffer: []u8, first: []const u8, second: []const u8) []const u8 {
    assert(first.len + second.len <= buffer.len);
    @memcpy(buffer[0..first.len], first);
    @memcpy(buffer[first.len..][0..second.len], second);
    return buffer[0 .. first.len + second.len];
}

fn join_slash(buffer: []u8, first: []const u8, second: []const u8) []const u8 {
    assert(first.len + second.len + 1 <= buffer.len);
    if (std.mem.eql(u8, first, "/")) return join(buffer, first, second);
    @memcpy(buffer[0..first.len], first);
    buffer[first.len] = '/';
    @memcpy(buffer[first.len + 1 ..][0..second.len], second);
    return buffer[0 .. first.len + 1 + second.len];
}

const testing = std.testing;

test "paths: set refuses what does not fit, under means below or equal" {
    // Goal: the boundary of a simulated path and the prefix rule the mount code relies on.
    var path: SimPath = .{};
    try testing.expect(path.set("/a/b"));
    try testing.expect(path.under("/a"));
    try testing.expect(path.under("/a/b"));
    try testing.expect(path.under("/"));
    try testing.expect(!path.under("/a/bc"));
    try testing.expect(!path.under("/ab"));
    var long: [constants.sim_path_bytes_max + 1]u8 = undefined;
    @memset(&long, 'x');
    try testing.expect(!path.set(&long));
    try testing.expect(path.set(long[0..constants.sim_path_bytes_max]));
}

test "nodes: add_node adds the directories above, mount targets must exist" {
    // Goal: the file tree rules a plan must satisfy; a mount on a missing directory fails ENOENT
    // and on a file where a directory is wanted fails ENOTDIR.
    var world: World = undefined;
    world.init();
    world.add_node("/r/dev/null", .file);
    try testing.expectEqual(NodeKind.dir, world.node_kind("/r/dev").?);
    try testing.expectEqual(NodeKind.file, world.node_kind("/r/dev/null").?);
    const missing = world.mount(.{ .kind = .proc, .target = "/r/proc", .source = null });
    try testing.expectEqual(@as(?u16, errno_noent), missing);
    const wrong = world.mount(.{ .kind = .proc, .target = "/r/dev/null", .source = null });
    try testing.expectEqual(@as(?u16, errno_notdir), wrong);
    try testing.expectEqual(@as(?u16, null), world.make_directory("/r/proc", false));
    try testing.expectEqual(@as(?u16, errno_exist), world.make_directory("/r/proc", false));
    try testing.expectEqual(@as(?u16, null), world.make_directory("/r/proc", true));
    try testing.expectEqual(@as(?u16, null), world.mount(.{
        .kind = .proc,
        .target = "/r/proc",
        .source = null,
    }));
}

test "id maps: setgroups first, own id only, once" {
    // Goal: the kernel's rules for an unprivileged writer, as the model enforces them.
    var world: World = undefined;
    world.init();
    const entry = struct {
        fn run(_: *anyopaque) u8 {
            return 0;
        }
    }.run;
    var unused: u8 = 0;
    const all: host.SpawnFlags = .{
        .user = true,
        .mount = true,
        .pid = true,
        .uts = true,
        .ipc = true,
    };
    const pid = world.spawn(all, entry, &unused).?;
    const ids: Ids = .{ .uid = 1000, .gid = 1000 };
    const own = "0 1000 1\n";
    const perm: ?u16 = errno_perm;
    try testing.expectEqual(perm, world.write_id_map(pid, .gid_map, own, ids));
    try testing.expectEqual(@as(?u16, null), world.write_id_map(pid, .setgroups, "deny", ids));
    try testing.expectEqual(perm, world.write_id_map(pid, .gid_map, "0 1 1\n", ids));
    try testing.expectEqual(@as(?u16, null), world.write_id_map(pid, .gid_map, own, ids));
    try testing.expectEqual(perm, world.write_id_map(pid, .gid_map, own, ids));
    try testing.expectEqual(@as(?u16, null), world.write_id_map(pid, .uid_map, own, ids));
    try testing.expectEqual(perm, world.write_id_map(pid, .uid_map, own, ids));
}

/// Where the manager puts a scope in the cgroup tree, relative to /sys/fs/cgroup.
pub fn scope_cgroup_path(buffer: []u8, scope: *const sim_bus.Scope) []const u8 {
    const slice_part = if (scope.slice.len > 0) scope.slice.slice() else "";
    const separator = if (scope.slice.len > 0) "/" else "";
    // Cannot fail: a uid, a slice name of 32 bytes and a scope name of 80 fit 256 bytes.
    return std.fmt.bufPrint(
        buffer,
        "/user.slice/user-{d}.slice/user@{d}.service{s}{s}/{s}",
        .{ scope.uid, scope.uid, separator, slice_part, scope.name.slice() },
    ) catch unreachable; // Same bound as above.
}
