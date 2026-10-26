//! The only interface through which Zigbox touches the kernel. Two implementations exist:
//! `host_real.zig` (syscalls) and `host_sim.zig` (an in-memory model with seeded fault
//! injection). Code above this file must not know which one it is using.
//!
//! Design choice: a runtime vtable (`*anyopaque` context plus a table of function pointers)
//! rather than a comptime-selected type. Reasons: (1) the fuzzers and unit tests build real
//! binaries once and swap implementations per iteration without instantiating every caller
//! twice; (2) callers take a plain `Host` value, so no generic parameter spreads through
//! `doctor`, `cli` and the later milestones; (3) the call overhead is irrelevant next to a
//! syscall. The cost is that the compiler cannot see which implementation a call reaches. The
//! vtable struct has no field defaults, so an implementation that omits an entry does not
//! compile.
//!
//! The vtable holds only primitives. Retry and short-read logic is written once, here, in
//! `read_file` and `write_all`, so that the simulator's injected EINTR and short reads exercise
//! the same code that runs in production.

const std = @import("std");
const bpf = @import("runtime/bpf.zig");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const linux = std.os.linux;

/// Operating errors the kernel layer can report. Deliberately coarse: callers choose a message
/// and a fix per error, never per errno.
pub const Error = error{
    NotFound,
    AccessDenied,
    Interrupted,
    WouldBlock,
    NoSpace,
    OutOfMemory,
    PathTooLong,
    InvalidPath,
    /// The file holds more bytes than the caller's buffer, which is its documented limit.
    FileTooLarge,
    /// An operation made no progress within its call bound (a livelock guard).
    Stalled,
    Unsupported,
    /// The file exists but does not have the requested extended attribute.
    NoData,
    /// A wait for a peer's bytes ended with none (`read_timeout`); a bound, not a failure of
    /// the kernel.
    TimedOut,
    IoFailed,
};

/// Maps a raw errno to the coarse operating error callers handle. The one mapping: the real
/// host and the simulator both use it, so a simulated errno means what a real one would.
pub fn error_for_errno(errno: u16) Error {
    assert(errno != 0); // Zero is success, never an error.
    const code: linux.E = @fromBackingInt(errno);
    const mapped: Error = switch (code) {
        .INTR => error.Interrupted,
        .AGAIN => error.WouldBlock,
        .NOENT, .NOTDIR => error.NotFound,
        .ACCES, .PERM => error.AccessDenied,
        .NOSPC => error.NoSpace,
        .NOMEM => error.OutOfMemory,
        .NAMETOOLONG => error.PathTooLong,
        .NOSYS => error.Unsupported,
        .NODATA => error.NoData,
        .TIMEDOUT => error.TimedOut,
        .RANGE => error.FileTooLarge,
        else => error.IoFailed,
    };
    assert(mapped != error.Stalled); // Only host.zig's own loops produce that.
    return mapped;
}

/// An open, read-only file. Small integers so the simulator can hand out table indexes.
pub const Handle = u32;

pub const Stream = enum { stdout, stderr };

pub const Text = struct {
    bytes: [constants.uname_field_bytes]u8,
    len: u8,

    pub fn slice(text: *const Text) []const u8 {
        assert(text.len < constants.uname_field_bytes);
        assert(text.bytes[text.len] == 0); // from_slice zero-fills past the end.
        return text.bytes[0..text.len];
    }

    pub fn from_slice(source: []const u8) Text {
        assert(source.len < constants.uname_field_bytes);
        var text: Text = .{ .bytes = @splat(0), .len = @intCast(source.len) };
        @memcpy(text.bytes[0..source.len], source);
        assert(text.bytes[source.len] == 0);
        return text;
    }
};

pub const Uname = struct {
    release: Text,
    machine: Text,
};

/// File type and permission bits, and the owner, as `stat` reports them.
pub const Stat = struct {
    mode: u32,
    uid: u32,
};

/// Probes run in a forked child so a failed probe cannot damage the caller. The child runs as
/// an unprivileged user even when the caller is root, so the answer is about ordinary users.
pub const ProbeKind = enum { userns, overlay };

pub const ProbeOutcome = enum {
    ok,
    /// The operation under test was refused (EPERM, EACCES, ENOSPC, ENODEV, EINVAL ...).
    denied,
    /// Overlay only: the child could not enter the user and mount namespaces the probe needs.
    setup_denied,
    /// The namespace was created but writing setgroups/uid_map/gid_map was refused.
    map_denied,
    /// The child failed for a reason that says nothing about the feature (no memory, ...).
    failed,
    /// The child was killed by a signal.
    signaled,
    /// The child did not finish within the probe timeout and was killed and reaped.
    timed_out,
};

// ---- Containers --------------------------------------------------------------------------
//
// The primitives a container run is built from. Each is one kernel operation (or one tiny
// fixed sequence of them), so that a plan step maps to one fallible call and the simulator can
// fail exactly that step. `run.zig` owns the order; this file owns what each call means.

/// A process id in the caller's PID namespace.
pub const Pid = u32;

/// The two ends of a pipe. Both are close-on-exec, so a successful `exec` closes them: that EOF
/// is how a parent learns that the child's command started.
pub const Pipe = struct {
    read: Handle,
    write: Handle,
};

/// The namespaces a child is created in.
pub const SpawnFlags = struct {
    user: bool,
    mount: bool,
    pid: bool,
    uts: bool,
    ipc: bool,
};

/// The body of a spawned child. It runs in the child, on a copy of the parent's memory, and its
/// result is the child's exit code unless it replaced itself with `exec`.
pub const ChildEntry = *const fn (entry_context: *anyopaque) u8;

pub const ExitStatus = union(enum) {
    exited: u8,
    /// Killed by this signal number.
    signaled: u8,
};

/// The three files of a user namespace that define its ids, in the order they must be written:
/// `setgroups` ("deny") first, because an unprivileged writer may not map groups otherwise.
pub const IdMapKind = enum { setgroups, gid_map, uid_map };

/// Every mount a container setup makes. The host knows each one's flags and options, so that a
/// plan step is a name, not a pile of kernel constants, and the simulator models what each does.
pub const MountKind = enum {
    /// `target` ("/"): make the whole tree private so nothing propagates to the host.
    make_private,
    /// Bind `source` onto `target`, with everything mounted below it.
    bind_tree,
    /// Bind the single file or device `source` onto the file `target`.
    bind_file,
    /// A fresh procfs for the PID namespace of the caller: nosuid, nodev, noexec.
    proc,
    /// The container's `/dev`: tmpfs, mode 0755, nosuid.
    dev_tmpfs,
    /// `/dev/shm`: tmpfs, mode 1777, nosuid, nodev, noexec.
    shm_tmpfs,
    /// `/dev/pts`: a private devpts instance whose ptmx is mode 0666.
    devpts,
    /// A read-only rootfs gets `/tmp`: tmpfs, mode 1777, nosuid, nodev, sized by
    /// `constants.tmpfs_bytes_max`.
    tmp_tmpfs,
    /// ... and `/run`: tmpfs, mode 0755, nosuid, nodev.
    run_tmpfs,
    /// `target` (a bind mount) becomes read-only. In a user namespace the kernel requires the
    /// flags the mount already has (nosuid, nodev, noexec, atime) to be kept, so the host reads
    /// them first.
    remount_readonly,
};

pub const MountRequest = struct {
    kind: MountKind,
    target: [:0]const u8,
    /// Set exactly for the bind kinds.
    source: ?[:0]const u8,
};

/// A null-terminated array of C strings, as `execve` takes it.
pub const CStrings = [*:null]const ?[*:0]const u8;

pub const ExecRequest = struct {
    path: [:0]const u8,
    argv: CStrings,
    envp: CStrings,
};

/// What a helper program (newuidmap, newgidmap) did: how it ended, and the first bytes it wrote.
pub const HelperResult = struct {
    status: ExitStatus,
    output_len: u32,
};

/// What the parent waiting for its container learns next.
pub const Event = union(enum) {
    /// The child ended.
    exited: ExitStatus,
    /// A signal zbx forwards arrived (INT, TERM, HUP or QUIT).
    signal: u8,
    /// The wait's time ran out with neither (only for a wait given a time).
    timeout,
};

/// Which side of `fork_supervisor` a process is on.
pub const Role = enum {
    /// The caller that asked for a detached run; it goes on, and the supervisor is its child.
    parent,
    /// The new process: its own session, its stdin, stdout and stderr on /dev/null.
    supervisor,
};

/// Which signals a process has handlers for or ignores, as bit masks (bit n-1 is signal n).
pub const SignalState = struct {
    caught: u64,
    ignored: u64,

    pub fn has(mask: u64, number: u8) bool {
        assert(number > 0);
        assert(number <= 64);
        return mask >> @intCast(number - 1) & 1 == 1;
    }
};

/// The names in one directory, NUL-terminated one after another. Fixed size: a directory with
/// more entries, or a longer name, sets `truncated` and the rest is not listed.
pub const DirListing = struct {
    bytes: [constants.dir_listing_bytes_max]u8,
    len: u32,
    count: u32,
    truncated: bool,

    pub fn reset(listing: *DirListing) void {
        listing.len = 0;
        listing.count = 0;
        listing.truncated = false;
    }

    /// Adds a name, or marks the listing truncated if it does not fit.
    pub fn add(listing: *DirListing, entry: []const u8) void {
        assert(entry.len > 0);
        assert(std.mem.indexOfScalar(u8, entry, 0) == null);
        const fits = entry.len <= constants.dir_name_bytes_max;
        if (!fits or listing.count == constants.dir_entries_max) {
            listing.truncated = true;
            return;
        }
        @memcpy(listing.bytes[listing.len..][0..entry.len], entry);
        listing.bytes[listing.len + entry.len] = 0;
        listing.len += @intCast(entry.len + 1);
        listing.count += 1;
        assert(listing.len <= listing.bytes.len);
    }

    /// The name at `index` (in the order added).
    pub fn name(listing: *const DirListing, index: u32) []const u8 {
        assert(index < listing.count);
        var at: u32 = 0;
        var seen: u32 = 0;
        while (seen < index) : (seen += 1) {
            at += @intCast(std.mem.indexOfScalar(u8, listing.bytes[at..listing.len], 0).? + 1);
        }
        const rest = listing.bytes[at..listing.len];
        return rest[0..std.mem.indexOfScalar(u8, rest, 0).?];
    }
};

/// The step index to give `begin_step` when no plan step is running.
pub const step_none: u32 = std.math.maxInt(u32);

pub const VTable = struct {
    open_read: *const fn (context: *anyopaque, path: [:0]const u8) Error!Handle,
    read: *const fn (context: *anyopaque, handle: Handle, buffer: []u8) Error!u32,
    close: *const fn (context: *anyopaque, handle: Handle) void,
    write: *const fn (context: *anyopaque, stream: Stream, bytes: []const u8) Error!u32,
    uname: *const fn (context: *anyopaque) Error!Uname,
    stat: *const fn (context: *anyopaque, path: [:0]const u8) Error!Stat,
    /// Reads the raw `security.capability` xattr. Returns `NoData` if the file has none and
    /// `FileTooLarge` if it does not fit `buffer`.
    read_capability: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        buffer: []u8,
    ) Error!u32,
    /// The mode of the seccomp filter of this process, from `prctl(PR_GET_SECCOMP)`.
    seccomp_mode: *const fn (context: *anyopaque) Error!u32,
    is_terminal: *const fn (context: *anyopaque, stream: Stream) bool,
    /// True if the environment variable NO_COLOR is set to a non-empty value (no-color.org).
    no_color: *const fn (context: *anyopaque) bool,
    /// The real user id of this process.
    uid: *const fn (context: *anyopaque) u32,
    probe: *const fn (context: *anyopaque, kind: ProbeKind) Error!ProbeOutcome,
    /// The raw errno of the most recent call through this vtable: 0 if it succeeded. Lets the
    /// diagnostics name the real errno without widening `Error`.
    last_errno: *const fn (context: *anyopaque) u16,
    // Containers. The step markers and the per-step fault injection are explained at
    // `Host.begin_step`.
    pipe: *const fn (context: *anyopaque) Error!Pipe,
    write_handle: *const fn (context: *anyopaque, handle: Handle, bytes: []const u8) Error!u32,
    /// `clone3` with the namespaces in `flags`. The child runs `entry` and exits with its result.
    spawn: *const fn (
        context: *anyopaque,
        flags: SpawnFlags,
        entry: ChildEntry,
        entry_context: *anyopaque,
    ) Error!Pid,
    /// Blocks until the child ends and reaps it.
    wait: *const fn (context: *anyopaque, pid: Pid) Error!ExitStatus,
    signal: *const fn (context: *anyopaque, pid: Pid, signal: u8) Error!void,
    write_id_map: *const fn (
        context: *anyopaque,
        pid: Pid,
        kind: IdMapKind,
        bytes: []const u8,
    ) Error!void,
    mount: *const fn (context: *anyopaque, request: MountRequest) Error!void,
    unmount_detach: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    pivot_root: *const fn (
        context: *anyopaque,
        new_root: [:0]const u8,
        put_old: [:0]const u8,
    ) Error!void,
    change_directory: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    make_directory: *const fn (context: *anyopaque, path: [:0]const u8, exist_ok: bool) Error!void,
    create_file: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    symlink: *const fn (context: *anyopaque, target: [:0]const u8, link: [:0]const u8) Error!void,
    set_hostname: *const fn (context: *anyopaque, name: []const u8) Error!void,
    /// Marks every descriptor above 2 close-on-exec (`close_range`), so none reaches the command.
    seal_descriptors: *const fn (context: *anyopaque) Error!void,
    /// Asks the kernel to kill this process when its parent dies (`PR_SET_PDEATHSIG`).
    die_with_parent: *const fn (context: *anyopaque) Error!void,
    /// Drops every capability not in `keep` (a mask by capability number) from the bounding set,
    /// then makes it the effective, permitted and inheritable sets (`PR_CAPBSET_DROP`, `capset`).
    restrict_capabilities: *const fn (context: *anyopaque, keep: u64) Error!void,
    /// Empties the ambient capability set (`PR_CAP_AMBIENT_CLEAR_ALL`).
    clear_ambient: *const fn (context: *anyopaque) Error!void,
    /// Sets `no_new_privs` (`PR_SET_NO_NEW_PRIVS`), which stays for the process and its children.
    no_new_privs: *const fn (context: *anyopaque) Error!void,
    /// Installs a seccomp filter (`seccomp(SECCOMP_SET_MODE_FILTER)`). Needs `no_new_privs` first.
    install_seccomp: *const fn (context: *anyopaque, program: []const bpf.Insn) Error!void,
    /// Replaces the process. Returns only on failure in the real host; the simulator returns
    /// success to model a command that started.
    exec: *const fn (context: *anyopaque, request: ExecRequest) Error!void,
    gid: *const fn (context: *anyopaque) u32,
    /// The value of an environment variable of this process, or null if it is not set.
    environment: *const fn (context: *anyopaque, name: []const u8) ?[]const u8,
    /// The `index`th variable of the process environment, in the order the process has them, or
    /// null past the last. Only a bundle lists the environment (with the values redacted).
    environment_at: *const fn (context: *anyopaque, index: u32) ?EnvironmentEntry,
    random_bytes: *const fn (context: *anyopaque, buffer: []u8) Error!void,
    /// Runs a helper program to its end and waits for it. Its output (stdout and stderr, joined)
    /// is kept up to `output.len` bytes. The helper is run with the environment in the request.
    run_helper: *const fn (
        context: *anyopaque,
        request: ExecRequest,
        output: []u8,
    ) Error!HelperResult,
    /// Blocks (or unblocks) INT, TERM, HUP, QUIT and CHLD, so that they wait to be read by
    /// `wait_event` instead of acting.
    block_signals: *const fn (context: *anyopaque, block: bool) Error!void,
    /// Waits for the child to end or for a forwarded signal; the signals must be blocked. With a
    /// `timeout_ms` above zero it also ends, with `.timeout`, when that long has passed.
    wait_event: *const fn (context: *anyopaque, pid: Pid, timeout_ms: u32) Error!Event,
    /// Sleeps at least `ms` milliseconds (the library's polls and graces use it).
    sleep_ms: *const fn (context: *anyopaque, ms: u32) void,
    /// A clock that only goes forward, in milliseconds, for measuring waits.
    monotonic_ms: *const fn (context: *anyopaque) u64,
    /// Forks a supervisor: a new process, detached from the terminal and the caller's session,
    /// with its standard streams on /dev/null, that goes on with the same memory. The caller
    /// must be single-threaded. The real host's supervisor ends with `exit_now`.
    fork_supervisor: *const fn (context: *anyopaque) Error!Role,
    /// Ends the process now with `code`. The real host does not return; the simulator does, so
    /// that a test can look at what the supervisor left behind.
    exit_now: *const fn (context: *anyopaque, code: u8) void,
    signal_state: *const fn (context: *anyopaque, pid: Pid) Error!SignalState,
    /// Seconds since the epoch.
    time_now: *const fn (context: *anyopaque) u64,
    /// Creates the file (mode 0600) or empties it, and writes all of `bytes`.
    write_file: *const fn (context: *anyopaque, path: [:0]const u8, bytes: []const u8) Error!void,
    rename: *const fn (context: *anyopaque, from: [:0]const u8, to: [:0]const u8) Error!void,
    remove_file: *const fn (context: *anyopaque, path: [:0]const u8) Error!void,
    list_directory: *const fn (
        context: *anyopaque,
        path: [:0]const u8,
        listing: *DirListing,
    ) Error!void,
    /// Makes a write to a pipe with no reader fail with `EPIPE` instead of killing the process.
    ignore_broken_pipe: *const fn (context: *anyopaque, ignore: bool) void,
    /// Connects a stream socket to the unix socket at `path` (the user's D-Bus socket). The
    /// handle is close-on-exec and is read and written like a pipe's.
    socket_connect: *const fn (context: *anyopaque, path: [:0]const u8) Error!Handle,
    /// Like `read`, but waits at most `timeout_ms` for the first byte: `TimedOut` if none came.
    read_timeout: *const fn (
        context: *anyopaque,
        handle: Handle,
        buffer: []u8,
        timeout_ms: u32,
    ) Error!u32,
    begin_step: *const fn (context: *anyopaque, index: u32) void,
};

/// What `read_prefix` found.
pub const Prefix = struct {
    bytes: []u8,
    truncated: bool,
};

/// A variable of the process environment.
pub const EnvironmentEntry = struct {
    name: []const u8,
    value: []const u8,
};

pub const Host = struct {
    context: *anyopaque,
    vtable: *const VTable,

    /// Reads the whole file into `buffer` and returns the filled prefix. A file longer than
    /// `buffer` is `FileTooLarge`; it is never silently truncated, because a truncated
    /// /proc or /etc file could turn a failing check into a passing one.
    pub fn read_file(host: Host, path: []const u8, buffer: []u8) Error![]u8 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);

        const handle = try host.open_retrying(path_sentinel);
        defer host.vtable.close(host.context, handle);

        const length = try host.read_all(handle, buffer);
        assert(length <= buffer.len);
        return buffer[0..length];
    }

    /// The first `buffer.len` bytes of the file, and whether there was more. For a bundle, which
    /// keeps what fits and says it cut the rest; never for a check, which must see the whole file.
    pub fn read_prefix(host: Host, path: []const u8, buffer: []u8) Error!Prefix {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);
        const handle = try host.open_retrying(path_sentinel);
        defer host.vtable.close(host.context, handle);
        var truncated = false;
        const length = host.read_all(handle, buffer) catch |err| switch (err) {
            error.FileTooLarge => blk: {
                truncated = true;
                break :blk buffer.len;
            },
            else => return err,
        };
        assert(length <= buffer.len);
        return .{ .bytes = buffer[0..length], .truncated = truncated };
    }

    pub fn write_all(host: Host, stream: Stream, bytes: []const u8) Error!void {
        assert(bytes.len <= constants.output_bytes_max);
        var written: u32 = 0;
        var retries: u32 = 0;
        var calls: u32 = 0;
        // Interrupted calls do not count toward `calls` but are bounded by `retries`, which
        // only a non-interrupted call resets, so the loop terminates.
        while (calls < constants.write_calls_max) {
            if (written == bytes.len) return;
            assert(written < bytes.len);
            const result = host.vtable.write(host.context, stream, bytes[written..]);
            const count = result catch |err| switch (err) {
                error.Interrupted => {
                    retries += 1;
                    if (retries > constants.eintr_retries_max) return error.IoFailed;
                    continue;
                },
                else => return err,
            };
            retries = 0;
            calls += 1;
            assert(count <= bytes.len - written);
            written += count;
        }
        // Each non-EINTR call that returned 0 made no progress; bounded loops end here.
        return error.Stalled;
    }

    pub fn uname(host: Host) Error!Uname {
        const result = try host.vtable.uname(host.context);
        assert(result.release.len < constants.uname_field_bytes);
        assert(result.machine.len < constants.uname_field_bytes);
        return result;
    }

    pub fn stat(host: Host, path: []const u8) Error!Stat {
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);
        assert(path_sentinel.len == path.len);
        const result = try host.vtable.stat(host.context, path_sentinel);
        assert(result.mode <= std.math.maxInt(u16)); // st_mode is 16 bits in the kernel ABI.
        return result;
    }

    /// Returns the filled prefix of `buffer`.
    pub fn read_capability(host: Host, path: []const u8, buffer: []u8) Error![]u8 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.capability_bytes_max);
        var path_z: PathZ = undefined;
        const path_sentinel = try path_z.init(path);
        const length = try host.vtable.read_capability(host.context, path_sentinel, buffer);
        assert(length <= buffer.len);
        return buffer[0..length];
    }

    pub fn seccomp_mode(host: Host) Error!u32 {
        const mode = try host.vtable.seccomp_mode(host.context);
        assert(mode <= 2); // The kernel's modes: disabled, strict, filter.
        return mode;
    }

    pub fn is_terminal(host: Host, stream: Stream) bool {
        return host.vtable.is_terminal(host.context, stream);
    }

    /// Colour only when the stream is a terminal and NO_COLOR is unset. Output must read
    /// correctly without colour, so this is never required for meaning.
    pub fn color_enabled(host: Host, stream: Stream) bool {
        if (!host.is_terminal(stream)) return false;
        return !host.vtable.no_color(host.context);
    }

    pub fn uid(host: Host) u32 {
        const id = host.vtable.uid(host.context);
        assert(id != std.math.maxInt(u32)); // (uid_t)-1 means "no change", never a real id.
        return id;
    }

    /// The errno of the most recent failed host call, or 0 if the last call succeeded. Meaningful
    /// right after a call that returned an error that came from the kernel; errors made inside
    /// this file (`Stalled`, `InvalidPath`, ...) have no errno and callers must not ask.
    pub fn last_errno(host: Host) u16 {
        const errno = host.vtable.last_errno(host.context);
        assert(errno < 4096); // The kernel's errno range.
        return errno;
    }

    pub fn probe(host: Host, kind: ProbeKind) Error!ProbeOutcome {
        return host.vtable.probe(host.context, kind);
    }

    // ---- Containers ----

    /// Creates a pipe whose ends are both close-on-exec.
    pub fn pipe(host: Host) Error!Pipe {
        const result = try host.vtable.pipe(host.context);
        assert(result.read != result.write);
        assert(host.vtable.last_errno(host.context) == 0); // A success leaves no errno behind.
        return result;
    }

    /// Reads at least one byte, or returns 0 at end of file, retrying interrupted calls.
    pub fn read_some(host: Host, handle: Handle, buffer: []u8) Error!u32 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        for (0..constants.eintr_retries_max + 1) |_| {
            const count = host.vtable.read(host.context, handle, buffer) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(count <= buffer.len);
            return count;
        }
        return error.IoFailed;
    }

    /// Connects to the unix socket at `path`. A path longer than a socket address holds is
    /// `PathTooLong`.
    pub fn socket_connect(host: Host, path: []const u8) Error!Handle {
        if (path.len == 0) return error.InvalidPath;
        if (path.len > constants.dbus_socket_path_bytes_max) return error.PathTooLong;
        if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
        var storage: [constants.dbus_socket_path_bytes_max + 1]u8 = undefined;
        @memcpy(storage[0..path.len], path);
        storage[path.len] = 0;
        const path_z: [:0]const u8 = storage[0..path.len :0];
        const handle = try host.vtable.socket_connect(host.context, path_z);
        assert(host.vtable.last_errno(host.context) == 0);
        return handle;
    }

    /// Waits up to `timeout_ms` for bytes, then reads at least one, or returns 0 at end of file.
    /// Interrupted waits are retried, so the wait can be a little longer than asked.
    pub fn read_timeout(host: Host, handle: Handle, buffer: []u8, timeout_ms: u32) Error!u32 {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        assert(timeout_ms <= constants.dbus_job_timeout_ms);
        for (0..constants.eintr_retries_max + 1) |_| {
            const count = host.vtable.read_timeout(
                host.context,
                handle,
                buffer,
                timeout_ms,
            ) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            assert(count <= buffer.len);
            return count;
        }
        return error.IoFailed;
    }

    /// Writes every byte to a pipe, like `write_all` does for the standard streams.
    pub fn write_handle_all(host: Host, handle: Handle, bytes: []const u8) Error!void {
        assert(bytes.len > 0);
        assert(bytes.len <= constants.output_bytes_max);
        var written: u32 = 0;
        var retries: u32 = 0;
        var calls: u32 = 0;
        // Bounded like `write_all`: interrupted calls by `retries`, the rest by `calls`.
        while (calls < constants.write_calls_max) {
            if (written == bytes.len) return;
            const result = host.vtable.write_handle(host.context, handle, bytes[written..]);
            const count = result catch |err| switch (err) {
                error.Interrupted => {
                    retries += 1;
                    if (retries > constants.eintr_retries_max) return error.IoFailed;
                    continue;
                },
                else => return err,
            };
            retries = 0;
            calls += 1;
            assert(count <= bytes.len - written);
            written += count;
        }
        return error.Stalled;
    }

    pub fn close(host: Host, handle: Handle) void {
        assert(handle < std.math.maxInt(i32));
        assert(@intFromPtr(host.vtable) != 0);
        host.vtable.close(host.context, handle);
    }

    pub fn spawn(
        host: Host,
        flags: SpawnFlags,
        entry: ChildEntry,
        entry_context: *anyopaque,
    ) Error!Pid {
        assert(flags.user); // Every other namespace is created owned by a new user namespace.
        const pid = try host.vtable.spawn(host.context, flags, entry, entry_context);
        assert(pid > 0);
        return pid;
    }

    /// Waits for the child to end, retrying interrupted waits. Returns once, with its status.
    pub fn wait_for(host: Host, pid: Pid) Error!ExitStatus {
        assert(pid > 0);
        for (0..constants.wait_interrupts_max + 1) |_| {
            const status = host.vtable.wait(host.context, pid) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            switch (status) {
                .exited => {},
                .signaled => |number| assert(number > 0),
            }
            return status;
        }
        return error.IoFailed;
    }

    /// Sends a signal. Number 0 sends nothing and asks whether the process exists (and may be
    /// signalled by this user): an error `NotFound` says it does not.
    pub fn signal(host: Host, pid: Pid, number: u8) Error!void {
        assert(pid > 0);
        assert(number < constants.signal_number_max);
        try host.vtable.signal(host.context, pid, number);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn write_id_map(host: Host, pid: Pid, kind: IdMapKind, bytes: []const u8) Error!void {
        assert(pid > 0);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.id_map_line_bytes_max);
        if (kind == .setgroups) assert(std.mem.eql(u8, bytes, "deny")); // Never "allow".
        try host.vtable.write_id_map(host.context, pid, kind, bytes);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn mount(host: Host, request: MountRequest) Error!void {
        assert(request.target.len > 0);
        assert(request.target[request.target.len] == 0);
        switch (request.kind) {
            .bind_tree, .bind_file => assert(request.source != null),
            else => assert(request.source == null),
        }
        try host.vtable.mount(host.context, request);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn unmount_detach(host: Host, path: [:0]const u8) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try host.vtable.unmount_detach(host.context, path);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn pivot_root(host: Host, new_root: [:0]const u8, put_old: [:0]const u8) Error!void {
        assert(new_root.len > 0);
        assert(put_old.len > 0);
        assert(new_root[new_root.len] == 0);
        assert(put_old[put_old.len] == 0);
        try host.vtable.pivot_root(host.context, new_root, put_old);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn change_directory(host: Host, path: [:0]const u8) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try host.vtable.change_directory(host.context, path);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    /// Makes a directory. With `exist_ok`, a directory (or anything) that is already there is
    /// success, and a later use of it reports whatever is wrong with it.
    pub fn make_directory(host: Host, path: [:0]const u8, exist_ok: bool) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try host.vtable.make_directory(host.context, path, exist_ok);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    /// Creates an empty file, failing if it exists: it is a mount point on a fresh tmpfs.
    pub fn create_file(host: Host, path: [:0]const u8) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try host.vtable.create_file(host.context, path);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn symlink(host: Host, target: [:0]const u8, link: [:0]const u8) Error!void {
        assert(target.len > 0);
        assert(link.len > 0);
        assert(link[link.len] == 0);
        try host.vtable.symlink(host.context, target, link);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn set_hostname(host: Host, name: []const u8) Error!void {
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        try host.vtable.set_hostname(host.context, name);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn seal_descriptors(host: Host) Error!void {
        assert(@intFromPtr(host.vtable) != 0);
        try host.vtable.seal_descriptors(host.context);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn die_with_parent(host: Host) Error!void {
        assert(@intFromPtr(host.vtable) != 0);
        try host.vtable.die_with_parent(host.context);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn restrict_capabilities(host: Host, keep: u64) Error!void {
        assert(keep != 0); // A container keeps something, and the mask is never empty by policy.
        try host.vtable.restrict_capabilities(host.context, keep);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn clear_ambient(host: Host) Error!void {
        assert(@intFromPtr(host.vtable) != 0);
        assert(@intFromPtr(host.context) != 0);
        try host.vtable.clear_ambient(host.context);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn no_new_privs(host: Host) Error!void {
        assert(@intFromPtr(host.vtable) != 0);
        assert(@intFromPtr(host.context) != 0);
        try host.vtable.no_new_privs(host.context);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn install_seccomp(host: Host, program: []const bpf.Insn) Error!void {
        assert(program.len > 0);
        assert(program.len <= bpf.insns_max);
        try host.vtable.install_seccomp(host.context, program);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn exec(host: Host, request: ExecRequest) Error!void {
        assert(request.path.len > 0);
        assert(request.path[request.path.len] == 0);
        assert(request.argv[0] != null);
        try host.vtable.exec(host.context, request);
        // Only the simulator gets here: a real exec that succeeds does not return.
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn gid(host: Host) u32 {
        const id = host.vtable.gid(host.context);
        assert(id != std.math.maxInt(u32)); // (gid_t)-1 means "no change", never a real id.
        return id;
    }

    /// The value of an environment variable, or null if unset or longer than `limit_bytes`.
    pub fn environment(host: Host, name: []const u8, limit_bytes: u32) ?[]const u8 {
        assert(name.len > 0);
        assert(limit_bytes > 0);
        const value = host.vtable.environment(host.context, name) orelse return null;
        if (value.len > limit_bytes) return null;
        return value;
    }

    /// The `index`th environment variable, or null past the end. Asserts a bounded walk.
    pub fn environment_at(host: Host, index: u32) ?EnvironmentEntry {
        assert(index <= constants.environment_entries_max);
        const entry = host.vtable.environment_at(host.context, index) orelse return null;
        assert(entry.name.len > 0);
        return entry;
    }

    pub fn random_bytes(host: Host, buffer: []u8) Error!void {
        assert(buffer.len > 0);
        assert(buffer.len <= 256); // getrandom never returns short up to 256 bytes.
        try host.vtable.random_bytes(host.context, buffer);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn run_helper(host: Host, request: ExecRequest, output: []u8) Error!HelperResult {
        assert(request.path.len > 0);
        assert(request.argv[0] != null);
        assert(output.len > 0);
        assert(output.len <= constants.helper_output_bytes_max);
        const result = try host.vtable.run_helper(host.context, request, output);
        assert(result.output_len <= output.len);
        return result;
    }

    pub fn block_signals(host: Host, block: bool) Error!void {
        try host.vtable.block_signals(host.context, block);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    /// Waits for the child or a forwarded signal, retrying interrupted waits.
    pub fn wait_event(host: Host, pid: Pid, timeout_ms: u32) Error!Event {
        assert(pid > 0);
        assert(timeout_ms <= constants.wait_timeout_ms_max);
        for (0..constants.wait_interrupts_max + 1) |_| {
            const event = host.vtable.wait_event(host.context, pid, timeout_ms) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
            switch (event) {
                .exited, .timeout => {},
                .signal => |number| assert(number > 0),
            }
            return event;
        }
        return error.IoFailed;
    }

    pub fn signal_state(host: Host, pid: Pid) Error!SignalState {
        assert(pid > 0);
        const state = try host.vtable.signal_state(host.context, pid);
        assert(host.vtable.last_errno(host.context) == 0);
        return state;
    }

    pub fn sleep_ms(host: Host, ms: u32) void {
        assert(ms > 0);
        assert(ms <= constants.sleep_ms_max);
        host.vtable.sleep_ms(host.context, ms);
    }

    pub fn monotonic_ms(host: Host) u64 {
        const now = host.vtable.monotonic_ms(host.context);
        assert(now < 1 << 50);
        return now;
    }

    pub fn fork_supervisor(host: Host) Error!Role {
        const role = try host.vtable.fork_supervisor(host.context);
        assert(host.vtable.last_errno(host.context) == 0);
        return role;
    }

    pub fn exit_now(host: Host, code: u8) void {
        host.vtable.exit_now(host.context, code);
    }

    pub fn time_now(host: Host) u64 {
        const seconds = host.vtable.time_now(host.context);
        assert(seconds < 1 << 40); // Until the year 36812.
        return seconds;
    }

    pub fn write_file(host: Host, path: [:0]const u8, bytes: []const u8) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        assert(bytes.len <= constants.write_bytes_max);
        try host.vtable.write_file(host.context, path, bytes);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn rename(host: Host, from: [:0]const u8, to: [:0]const u8) Error!void {
        assert(from.len > 0);
        assert(to.len > 0);
        assert(!std.mem.eql(u8, from, to));
        try host.vtable.rename(host.context, from, to);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn remove_file(host: Host, path: [:0]const u8) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        try host.vtable.remove_file(host.context, path);
        assert(host.vtable.last_errno(host.context) == 0);
    }

    pub fn list_directory(host: Host, path: [:0]const u8, listing: *DirListing) Error!void {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        listing.reset();
        try host.vtable.list_directory(host.context, path, listing);
        assert(listing.len <= listing.bytes.len);
        assert(listing.count <= constants.dir_entries_max);
    }

    /// The parent writes one byte to a pipe whose reader may already be gone; that must be an
    /// error it can report, not a signal that ends it. Set after `spawn`, so a child (which
    /// inherits dispositions) never starts with the signal ignored.
    pub fn ignore_broken_pipe(host: Host, ignore: bool) void {
        assert(@intFromPtr(host.vtable) != 0);
        host.vtable.ignore_broken_pipe(host.context, ignore);
        assert(host.vtable.last_errno(host.context) < 4096);
    }

    /// Tells the host which plan step the calls that follow belong to (`step_none` when none
    /// does). The real host ignores it: the kernel needs no hint. The simulator uses it to fail
    /// exactly the first call of a chosen step, which is how the run fuzzer walks one injected
    /// failure across every step of a plan and checks that the diagnostic names that step.
    pub fn begin_step(host: Host, index: u32) void {
        if (index != step_none) assert(index < constants.plan_steps_max);
        host.vtable.begin_step(host.context, index);
        assert(host.vtable.last_errno(host.context) < 4096);
    }

    fn open_retrying(host: Host, path: [:0]const u8) Error!Handle {
        assert(path.len > 0);
        assert(path[path.len] == 0);
        for (0..constants.eintr_retries_max + 1) |_| {
            return host.vtable.open_read(host.context, path) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return err,
            };
        }
        return error.IoFailed;
    }

    fn read_all(host: Host, handle: Handle, buffer: []u8) Error!u32 {
        assert(buffer.len > 0);
        assert(handle < std.math.maxInt(i32)); // Descriptors are non-negative i32.
        var filled: u32 = 0;
        var retries: u32 = 0;
        var calls: u32 = 0;
        // See `write_all` for why interrupted calls are bounded separately from `calls`.
        while (calls < constants.read_calls_max) {
            // When the buffer is full, one more byte decides between "exactly full" and
            // "too large". The probe byte is read into scratch and discarded.
            var scratch: [1]u8 = undefined;
            const full = filled == buffer.len;
            const target: []u8 = if (full) scratch[0..] else buffer[filled..];
            const result = host.vtable.read(host.context, handle, target);
            const count = result catch |err| switch (err) {
                error.Interrupted => {
                    retries += 1;
                    if (retries > constants.eintr_retries_max) return error.IoFailed;
                    continue;
                },
                else => return err,
            };
            retries = 0;
            calls += 1;
            assert(count <= target.len);
            if (count == 0) return filled;
            if (full) return error.FileTooLarge;
            filled += count;
        }
        return error.Stalled;
    }
};

/// A NUL-terminated copy of a caller path, on the caller's stack, so the vtable can pass
/// sentinel-terminated slices to syscalls without allocating.
const PathZ = struct {
    storage: [constants.path_bytes_max + 1]u8,

    fn init(path_z: *PathZ, path: []const u8) Error![:0]const u8 {
        if (path.len == 0) return error.InvalidPath;
        if (path.len > constants.path_bytes_max) return error.PathTooLong;
        // An embedded NUL would silently shorten the path the kernel sees.
        if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
        @memcpy(path_z.storage[0..path.len], path);
        path_z.storage[path.len] = 0;
        const result: [:0]const u8 = path_z.storage[0..path.len :0];
        assert(result.len == path.len);
        assert(result[result.len] == 0);
        return result;
    }
};

const repeat = @import("test_util.zig").repeat;

test "Text round-trips and bounds its length" {
    // Goal: Text keeps exactly the bytes given, up to the field size minus the NUL.
    const text = Text.from_slice("6.18.44");
    try std.testing.expectEqualStrings("6.18.44", text.slice());
    const empty = Text.from_slice("");
    try std.testing.expectEqual(@as(usize, 0), empty.slice().len);
    const longest = Text.from_slice(repeat('a', constants.uname_field_bytes - 1));
    try std.testing.expectEqual(@as(usize, constants.uname_field_bytes - 1), longest.slice().len);
}

test "PathZ refuses empty, over-long and NUL-containing paths" {
    // Goal: the boundary where a path becomes invalid is exact, and refusals are errors.
    var path_z: PathZ = undefined;
    try std.testing.expectError(error.InvalidPath, path_z.init(""));
    try std.testing.expectError(error.InvalidPath, path_z.init("/proc/self\x00/status"));
    const longest = repeat('/', constants.path_bytes_max);
    const accepted = try path_z.init(longest);
    try std.testing.expectEqual(@as(usize, constants.path_bytes_max), accepted.len);
    const too_long = repeat('/', constants.path_bytes_max + 1);
    try std.testing.expectError(error.PathTooLong, path_z.init(too_long));
}
