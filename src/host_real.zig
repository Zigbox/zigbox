//! The production `Host`: raw Linux syscalls through `std.os.linux`, no libc. This file,
//! `host_real_fs.zig` (the store's file system), `host_real_net.zig` (sockets) and `host.zig` are
//! the only places that may name syscalls, or paths under /proc and /sys.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const bpf = @import("runtime/bpf.zig");
const capabilities = @import("runtime/capabilities.zig");
const constants = @import("constants.zig");
const host = @import("host.zig");
const host_real_fs = @import("host_real_fs.zig");
const host_real_net = @import("host_real_net.zig");
const registry_net = @import("registry/net.zig");
const store_fs = @import("store/fs.zig");

/// Writes to stderr with no state, no vtable and no error path, for the panic handler: when an
/// invariant has broken, nothing else can be trusted. Short writes and errors are ignored
/// because there is nowhere left to report them.
pub fn write_stderr_best_effort(bytes: []const u8) void {
    assert(bytes.len <= constants.output_bytes_max);
    var written: usize = 0;
    var calls: u32 = 0;
    while (written < bytes.len and calls < constants.write_calls_max) : (calls += 1) {
        const result = linux.write(linux.STDERR_FILENO, bytes[written..].ptr, bytes.len - written);
        if (linux.errno(result) != .SUCCESS) return;
        written += result;
    }
    assert(written <= bytes.len);
}

/// Ends the process at once, without unwinding, flushing or running anything else.
pub fn exit_now(code: u8) noreturn {
    assert(code != 0);
    linux.exit_group(code);
}

fn timespec_of(ms: u64) linux.timespec {
    assert(ms <= std.math.maxInt(u32));
    return .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
}

fn monotonic_now_ms() u64 {
    var now: linux.timespec = undefined;
    const result = linux.clock_gettime(.MONOTONIC, &now);
    assert(linux.errno(result) == .SUCCESS); // A valid clock and a valid pointer.
    assert(now.sec >= 0);
    return @as(u64, @intCast(now.sec)) * 1000 + @as(u64, @intCast(now.nsec)) / 1_000_000;
}

/// The errno of the most recent call checked by `check`, 0 after a success. One per thread,
/// because `check` is a free function used by the probe code too and the library is called from
/// several threads (each caller's host reads the errno of its own last call); a forked child has
/// its own copy.
//
// The alignment is a workaround for a std defect, not decoration. The binary's TLS segment is
// already 256 KiB: std's default `signal_stack_size` (1 << 18) is a `threadlocal` alternate
// signal stack that `std.Thread.maybeAttachSignalStack` installs for every thread. A static
// binary without libc lays out its own thread area at startup (`std.os.linux.tls.initStatic`),
// and with this two-byte variable added to the segment it put the thread control block at a
// misaligned offset and panicked (`incorrectAlignment`) before `main`, in ReleaseSafe only. That
// is a defect in `std.os.linux.tls`: minimal programs with a `u16` threadlocal do not reproduce
// it, so it depends on the layout of the whole segment. `align(16)` made the layout work here.
// The guard is the `zig build release` smoke run, which starts the binary: a later change to
// the thread-locals, or a new Zig, can break this again and only that run would show it.
pub threadlocal var errno_last: u16 align(16) = 0;

pub const HostReal = struct {
    /// Files opened and not yet closed. Pair assertion for the simulator's handle table: a
    /// close without a matching open is a programmer error.
    open_count: u32 = 0,
    /// Directory under which the overlay probe makes its scratch directory.
    scratch_parent: [:0]const u8 = "/tmp",
    probe_timeout_ms: u32 = constants.probe_timeout_ms,
    /// Test hook: replaces the body of the probe child, to exercise timeout, signal and
    /// exit-code handling without depending on what the host kernel allows.
    child_hook: ?*const fn () noreturn = null,
    /// The process environment, for NO_COLOR. Empty unless `main` provides it.
    environ: std.process.Environ = .empty,

    pub fn interface(self: *HostReal) host.Host {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: host.VTable = .{
        .open_read = open_read,
        .read = read,
        .close = close,
        .write = write,
        .uname = uname,
        .stat = stat,
        .read_capability = read_capability,
        .seccomp_mode = seccomp_mode,
        .is_terminal = is_terminal,
        .no_color = no_color,
        .last_errno = last_errno,
        .uid = uid,
        .probe = probe,
        .pipe = pipe,
        .write_handle = write_handle,
        .spawn = spawn,
        .start_keeper = start_keeper,
        .start_program = start_program,
        .wait = wait,
        .signal = signal,
        .write_id_map = write_id_map,
        .mount = mount,
        .unmount_detach = unmount_detach,
        .pivot_root = pivot_root,
        .change_directory = change_directory,
        .make_directory = make_directory,
        .remove_directory = remove_directory,
        .create_file = create_file,
        .bring_up_loopback = bring_up_loopback,
        .symlink = symlink,
        .set_hostname = set_hostname,
        .seal_descriptors = seal_descriptors,
        .die_with_parent = die_with_parent,
        .restrict_capabilities = restrict_capabilities,
        .clear_ambient = clear_ambient,
        .no_new_privs = no_new_privs,
        .set_user = set_user,
        .install_seccomp = install_seccomp,
        .exec = exec,
        .gid = gid,
        .environment = environment,
        .environment_at = environment_at,
        .random_bytes = random_bytes,
        .run_helper = run_helper,
        .block_signals = block_signals,
        .wait_event = wait_event,
        .own_pid = own_pid,
        .working_directory = working_directory,
        .sleep_ms = sleep_ms,
        .monotonic_ms = monotonic_ms,
        .fork_supervisor = fork_supervisor,
        .exit_now = exit_process,
        .signal_state = signal_state,
        .time_now = time_now,
        .write_file = write_file,
        .rename = rename,
        .remove_file = remove_file,
        .list_directory = list_directory,
        .ignore_broken_pipe = ignore_broken_pipe,
        .socket_connect = socket_connect,
        .read_timeout = read_timeout,
        .begin_step = begin_step,
        .filesystem = filesystem,
        .network = network,
    };

    fn from_context(context: *anyopaque) *HostReal {
        return @ptrCast(@alignCast(context));
    }

    fn open_read(context: *anyopaque, path: [:0]const u8) host.Error!host.Handle {
        const self = from_context(context);
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true };
        const result = linux.open(path.ptr, flags, 0);
        try check(result);
        assert(result <= std.math.maxInt(i32)); // A descriptor, not an errno-shaped value.
        self.open_count += 1;
        const descriptor: i32 = @intCast(result);
        return @intCast(descriptor);
    }

    fn read(context: *anyopaque, handle: host.Handle, buffer: []u8) host.Error!u32 {
        const self = from_context(context);
        assert(self.open_count > 0);
        assert(buffer.len > 0);
        assert(buffer.len <= constants.file_bytes_max);
        const descriptor: i32 = @intCast(handle);
        const result = linux.read(descriptor, buffer.ptr, buffer.len);
        try check(result);
        assert(result <= buffer.len);
        return @intCast(result);
    }

    fn close(context: *anyopaque, handle: host.Handle) void {
        const self = from_context(context);
        assert(self.open_count > 0);
        self.open_count -= 1;
        assert(handle <= std.math.maxInt(i32)); // A descriptor, as open_read produced it.
        const descriptor: i32 = @intCast(handle);
        // A close error on a read-only descriptor loses no data and cannot be acted on.
        _ = linux.close(descriptor);
    }

    fn write(context: *anyopaque, stream: host.Stream, bytes: []const u8) host.Error!u32 {
        _ = from_context(context);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.output_bytes_max);
        const descriptor: i32 = switch (stream) {
            .stdout => linux.STDOUT_FILENO,
            .stderr => linux.STDERR_FILENO,
        };
        const result = linux.write(descriptor, bytes.ptr, bytes.len);
        try check(result);
        assert(result <= bytes.len);
        return @intCast(result);
    }

    fn uname(context: *anyopaque) host.Error!host.Uname {
        _ = from_context(context);
        var raw: linux.utsname = undefined;
        try check(linux.uname(&raw));
        const release = std.mem.sliceTo(&raw.release, 0);
        const machine = std.mem.sliceTo(&raw.machine, 0);
        assert(release.len < constants.uname_field_bytes);
        assert(machine.len < constants.uname_field_bytes);
        return .{
            .release = host.Text.from_slice(release),
            .machine = host.Text.from_slice(machine),
        };
    }

    fn stat(context: *anyopaque, path: [:0]const u8) host.Error!host.Stat {
        _ = from_context(context);
        assert(path.len > 0);
        const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true };
        var buffer: linux.Statx = undefined;
        try check(linux.statx(linux.AT.FDCWD, path.ptr, 0, mask, &buffer));
        // The kernel must honour the mask for these fields; a clear bit would mean garbage.
        assert(buffer.mask.TYPE);
        assert(buffer.mask.MODE);
        assert(buffer.mask.UID);
        return .{ .mode = buffer.mode, .uid = buffer.uid };
    }

    fn read_capability(
        context: *anyopaque,
        path: [:0]const u8,
        buffer: []u8,
    ) host.Error!u32 {
        _ = from_context(context);
        assert(path.len > 0);
        assert(buffer.len > 0);
        const result = linux.getxattr(path.ptr, "security.capability", buffer.ptr, buffer.len);
        if (linux.errno(result) == .OPNOTSUPP) return error.NoData; // Filesystem without xattrs.
        try check(result);
        assert(result <= buffer.len);
        return @intCast(result);
    }

    fn seccomp_mode(context: *anyopaque) host.Error!u32 {
        _ = from_context(context);
        const result = linux.prctl(@backingInt(linux.PR.GET_SECCOMP), 0, 0, 0, 0);
        try check(result);
        assert(result <= std.math.maxInt(u32));
        assert(result <= 2);
        return @intCast(result);
    }

    fn is_terminal(context: *anyopaque, stream: host.Stream) bool {
        _ = from_context(context);
        const descriptor: i32 = switch (stream) {
            .stdout => linux.STDOUT_FILENO,
            .stderr => linux.STDERR_FILENO,
        };
        var attributes: linux.termios = undefined;
        return linux.errno(linux.tcgetattr(descriptor, &attributes)) == .SUCCESS;
    }

    fn last_errno(context: *anyopaque) u16 {
        _ = from_context(context);
        assert(errno_last < 4096);
        return errno_last;
    }

    fn no_color(context: *anyopaque) bool {
        return from_context(context).environ.containsUnemptyConstant("NO_COLOR");
    }

    fn uid(context: *anyopaque) u32 {
        _ = from_context(context);
        return linux.getuid();
    }

    fn probe(context: *anyopaque, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
        const self = from_context(context);
        assert(self.probe_timeout_ms >= constants.probe_poll_ms);
        assert(self.scratch_parent.len > 0);
        return probe_run(self, kind);
    }

    // ---- Containers ----

    fn pipe(context: *anyopaque) host.Error!host.Pipe {
        const self = from_context(context);
        var descriptors: [2]i32 = undefined;
        try check(linux.pipe2(&descriptors, .{ .CLOEXEC = true }));
        self.open_count += 2;
        assert(descriptors[0] >= 0);
        assert(descriptors[1] >= 0);
        return .{ .read = @intCast(descriptors[0]), .write = @intCast(descriptors[1]) };
    }

    fn socket_connect(context: *anyopaque, path: [:0]const u8) host.Error!host.Handle {
        const self = from_context(context);
        assert(path.len > 0);
        assert(path.len <= constants.dbus_socket_path_bytes_max);
        const kind = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
        const created = linux.socket(linux.AF.UNIX, kind, 0);
        try check(created);
        const descriptor: i32 = @intCast(created);
        var address: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(address.path[0..path.len], path);
        const length: u32 = @intCast(@sizeOf(linux.sa_family_t) + path.len + 1);
        check(linux.connect(descriptor, &address, length)) catch |err| {
            const errno_connect = errno_last;
            _ = linux.close(descriptor);
            errno_last = errno_connect; // The close must not hide why the connect failed.
            return err;
        };
        self.open_count += 1;
        return @intCast(descriptor);
    }

    /// Waits for the first byte with poll(2), then reads. A hang-up with nothing to read is end
    /// of file (the read returns 0), which the caller treats as the peer closing.
    fn read_timeout(
        context: *anyopaque,
        handle: host.Handle,
        buffer: []u8,
        timeout_ms: u32,
    ) host.Error!u32 {
        const self = from_context(context);
        assert(self.open_count > 0);
        assert(buffer.len > 0);
        const descriptor: i32 = @intCast(handle);
        var poll_set = [1]linux.pollfd{.{ .fd = descriptor, .events = linux.POLL.IN }};
        const waited = linux.poll(&poll_set, 1, @intCast(timeout_ms));
        try check(waited);
        if (waited == 0) {
            errno_last = 0;
            return error.TimedOut;
        }
        const result = linux.read(descriptor, buffer.ptr, buffer.len);
        try check(result);
        assert(result <= buffer.len);
        return @intCast(result);
    }

    fn write_handle(context: *anyopaque, handle: host.Handle, bytes: []const u8) host.Error!u32 {
        _ = from_context(context);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.output_bytes_max);
        const descriptor: i32 = @intCast(handle);
        const result = linux.write(descriptor, bytes.ptr, bytes.len);
        try check(result);
        assert(result <= bytes.len);
        return @intCast(result);
    }

    fn spawn(
        context: *anyopaque,
        flags: host.SpawnFlags,
        entry: host.ChildEntry,
        entry_context: *anyopaque,
    ) host.Error!host.Pid {
        _ = from_context(context);
        var arguments: CloneArgs = std.mem.zeroes(CloneArgs);
        arguments.flags = clone_flags(flags);
        arguments.exit_signal = @backingInt(linux.SIG.CHLD);
        const result = linux.syscall2(.clone3, @intFromPtr(&arguments), @sizeOf(CloneArgs));
        // clone3 returns twice. In the child (result 0) nothing below this line runs: the entry
        // function does the setup and the child ends here, never returning into the caller.
        if (result == 0) linux.exit_group(entry(entry_context));
        try check(result);
        assert(result > 0);
        assert(result <= std.math.maxInt(i32));
        return @intCast(result);
    }

    fn start_keeper(context: *anyopaque, hold: host.Handle) host.Error!host.Pid {
        _ = from_context(context);
        const parent: i32 = linux.getpid();
        const forked = linux.fork();
        // In the child (result 0) only raw system calls run, and it never returns into the
        // caller: `keeper_main` ends it.
        if (forked == 0) keeper_main(parent, @intCast(hold));
        try check(forked);
        assert(forked > 1);
        assert(forked <= std.math.maxInt(i32));
        return @intCast(forked);
    }

    /// Opens the child's stdin and stderr here, where a failure can be reported, then forks;
    /// the child (`program_child`) makes only raw system calls before `execve`.
    fn start_program(
        context: *anyopaque,
        request: host.ExecRequest,
        stdout: host.Handle,
        log: [:0]const u8,
    ) host.Error!host.Pid {
        _ = from_context(context);
        assert(request.path.len > 0);
        assert(stdout > 2); // A pipe's end, never one of our own standard streams.
        const input = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        try check(input);
        const stdin_fd: i32 = @intCast(input);
        const log_flags: linux.O = .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        };
        const null_flags: linux.O = .{ .ACCMODE = .WRONLY, .CLOEXEC = true };
        // A log that cannot be made (a full disk, a directory gone) is not a reason to refuse the
        // run: pasta's stderr then goes to /dev/null, as for a run with no state directory.
        var output: usize = if (log.len > 0) linux.open(log.ptr, log_flags, 0o600) else 0;
        if (log.len == 0 or linux.errno(output) != .SUCCESS) {
            output = linux.open("/dev/null", null_flags, 0);
        }
        check(output) catch |err| {
            const errno_open = errno_last;
            _ = linux.close(stdin_fd);
            errno_last = errno_open; // The close must not hide why the open failed.
            return err;
        };
        const stderr_fd: i32 = @intCast(output);
        const parent: i32 = linux.getpid();
        const forked = linux.fork();
        // In the child (result 0) only raw system calls run, and it never returns.
        if (forked == 0) program_child(request, parent, stdin_fd, @intCast(stdout), stderr_fd);
        const errno_fork = linux.errno(forked);
        _ = linux.close(stdin_fd); // The child has its copies; ours would only leak.
        _ = linux.close(stderr_fd);
        if (errno_fork != .SUCCESS) {
            errno_last = @backingInt(errno_fork);
            return host.error_for_errno(errno_last);
        }
        errno_last = 0;
        assert(forked > 1);
        assert(forked <= std.math.maxInt(i32));
        return @intCast(forked);
    }

    fn wait(context: *anyopaque, pid: host.Pid) host.Error!host.ExitStatus {
        _ = from_context(context);
        assert(pid > 0);
        var status: i32 = 0;
        const result = linux.wait4(@intCast(pid), &status, 0, null);
        try check(result);
        assert(result == pid);
        const bits: u32 = @bitCast(status);
        if (linux.W.IFEXITED(bits)) return .{ .exited = linux.W.EXITSTATUS(bits) };
        if (linux.W.IFSIGNALED(bits)) {
            const number: u32 = @backingInt(linux.W.TERMSIG(bits));
            assert(number > 0);
            assert(number < constants.signal_number_max);
            return .{ .signaled = @intCast(number) };
        }
        return error.IoFailed; // Stopped or continued: wait4 was not asked for those.
    }

    fn signal(context: *anyopaque, pid: host.Pid, number: u8) host.Error!void {
        _ = from_context(context);
        assert(pid > 0);
        // Raw, so that number 0 (does the process exist?) is expressible.
        try check(linux.syscall2(.kill, pid, number));
    }

    fn write_id_map(
        context: *anyopaque,
        pid: host.Pid,
        kind: host.IdMapKind,
        bytes: []const u8,
    ) host.Error!void {
        _ = from_context(context);
        assert(pid > 0);
        assert(bytes.len > 0);
        var path: [64:0]u8 = undefined;
        const format = "/proc/{d}/{s}";
        // Cannot fail: a pid has at most ten digits and the names are at most eight bytes.
        const text = std.fmt.bufPrintSentinel(&path, format, .{ pid, @tagName(kind) }, 0) catch
            unreachable; // Same bound as above.
        const opened = linux.open(text.ptr, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        try check(opened);
        const descriptor: i32 = @intCast(opened);
        const written = linux.write(descriptor, bytes.ptr, bytes.len);
        const result = check(written);
        _ = linux.close(descriptor); // Nothing buffered: the write above was the operation.
        try result;
        if (written != bytes.len) return error.IoFailed; // A map is written whole or not at all.
    }

    fn mount(context: *anyopaque, request: host.MountRequest) host.Error!void {
        _ = from_context(context);
        assert(request.target.len > 0);
        const target = request.target.ptr;
        const bind_source: ?[*:0]const u8 = if (request.source) |source| source.ptr else null;
        const result = switch (request.kind) {
            .make_private => linux.mount(null, target, null, linux.MS.REC | linux.MS.PRIVATE, 0),
            .bind_tree => linux.mount(bind_source, target, null, linux.MS.BIND | linux.MS.REC, 0),
            .bind_file => linux.mount(bind_source, target, null, linux.MS.BIND, 0),
            .move => linux.mount(bind_source, target, null, linux.MS.MOVE, 0),
            .remount_readonly => return remount_readonly(request.target),
            .remount_readonly_tree => return remount_readonly_tree(request.target),
            .user_tmpfs => linux.mount(
                "tmpfs",
                target,
                "tmpfs",
                linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
                @intFromPtr(bind_source.?), // The mount data; `Host.mount` asserted it is set.
            ),
            .overlay => linux.mount(
                "overlay",
                target,
                "overlay",
                0,
                @intFromPtr(bind_source.?), // The mount data; `Host.mount` asserted it is set.
            ),
            .proc, .sysfs, .dev_tmpfs, .shm_tmpfs, .devpts, .tmp_tmpfs, .run_tmpfs => blk: {
                const fresh = fresh_filesystem(request.kind);
                const data = @intFromPtr(fresh.data.ptr);
                break :blk linux.mount(fresh.source, target, fresh.type, fresh.flags, data);
            },
        };
        try check(result);
    }

    fn unmount_detach(context: *anyopaque, path: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        try check(linux.umount2(path.ptr, linux.MNT.DETACH));
    }

    fn pivot_root(
        context: *anyopaque,
        new_root: [:0]const u8,
        put_old: [:0]const u8,
    ) host.Error!void {
        _ = from_context(context);
        assert(new_root.len > 0);
        assert(put_old.len > 0);
        try check(linux.pivot_root(new_root.ptr, put_old.ptr));
    }

    fn change_directory(context: *anyopaque, path: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        try check(linux.chdir(path.ptr));
    }

    fn make_directory(context: *anyopaque, path: [:0]const u8, exist_ok: bool) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        const result = linux.mkdir(path.ptr, 0o755);
        if (exist_ok) {
            if (linux.errno(result) == .EXIST) {
                errno_last = 0;
                return;
            }
        }
        try check(result);
    }

    fn remove_directory(context: *anyopaque, path: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        try check(linux.rmdir(path.ptr));
    }

    fn create_file(context: *anyopaque, path: [:0]const u8, exist_ok: bool) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        // Without O_EXCL, creating a file that is there opens it and leaves it as it is: no
        // O_TRUNC, and read-only, so a file the user may read but not write is fine.
        const flags: linux.O = .{
            .ACCMODE = .RDONLY,
            .CREAT = true,
            .EXCL = !exist_ok,
            .CLOEXEC = true,
        };
        const opened = linux.open(path.ptr, flags, 0o644);
        try check(opened);
        _ = linux.close(@intCast(opened)); // An empty file: nothing was written to lose.
    }

    /// `lo` up: `SIOCGIFFLAGS`, then `SIOCSIFFLAGS` with `IFF_UP` added, on a datagram socket
    /// that is closed again. A new network namespace has `lo`, down; the kernel then brings up
    /// `127.0.0.1` and `::1` with it. The socket needs no privilege, the flag change needs
    /// `CAP_NET_ADMIN` in the user namespace that owns the network namespace, which the
    /// container's root has until the capabilities are restricted.
    fn bring_up_loopback(context: *anyopaque) host.Error!void {
        _ = from_context(context);
        assert(@sizeOf(linux.ifreq) == 40); // The kernel's struct ifreq.
        const opened = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        try check(opened);
        const descriptor: i32 = @intCast(opened);
        const result = set_interface_up(descriptor, "lo");
        _ = linux.close(descriptor); // Nothing buffered: the ioctls were the operation.
        try result;
    }

    fn symlink(context: *anyopaque, target: [:0]const u8, link: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(target.len > 0);
        assert(link.len > 0);
        try check(linux.symlink(target.ptr, link.ptr));
    }

    fn set_hostname(context: *anyopaque, name: []const u8) host.Error!void {
        _ = from_context(context);
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        try check(linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len));
    }

    fn seal_descriptors(context: *anyopaque) host.Error!void {
        _ = from_context(context);
        // Everything above stderr closes at exec; this keeps the failure pipe open until then,
        // which a plain close would not.
        const flags: linux.CLOSE_RANGE = .{ .UNSHARE = false, .CLOEXEC = true };
        try check(linux.close_range(3, -1, flags));
    }

    fn die_with_parent(context: *anyopaque) host.Error!void {
        _ = from_context(context);
        const kill: usize = @backingInt(linux.SIG.KILL);
        try check(linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), kill, 0, 0, 0));
    }

    /// Capabilities are dropped from the bounding set one by one (`PR_CAPBSET_DROP`, which needs
    /// CAP_SETPCAP, still held at this point), then the three sets are set to `keep` in one
    /// `capset` (version 3 data: two words each).
    fn restrict_capabilities(context: *anyopaque, keep: u64) host.Error!void {
        _ = from_context(context);
        assert(keep != 0);
        assert(keep >> (capabilities.last_known + 1) == 0);
        var capability: u32 = 0;
        while (capability <= capabilities.last_known) : (capability += 1) {
            if (keep & (@as(u64, 1) << @intCast(capability)) != 0) continue;
            const result = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), capability, 0, 0, 0);
            // A kernel older than this build knows has fewer capabilities: EINVAL, nothing to drop.
            if (linux.errno(result) == .INVAL) continue;
            try check(result);
        }
        const header: CapHeader = .{ .version = cap_version_3, .pid = 0 };
        const low: u32 = @truncate(keep);
        const high: u32 = @truncate(keep >> 32);
        const data = [2]CapData{
            .{ .effective = low, .permitted = low, .inheritable = low },
            .{ .effective = high, .permitted = high, .inheritable = high },
        };
        try check(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    }

    fn clear_ambient(context: *anyopaque) host.Error!void {
        _ = from_context(context);
        assert(linux.PR.CAP_AMBIENT_CLEAR_ALL == 4);
        const operation = linux.PR.CAP_AMBIENT_CLEAR_ALL;
        try check(linux.prctl(@backingInt(linux.PR.CAP_AMBIENT), operation, 0, 0, 0));
    }

    fn no_new_privs(context: *anyopaque) host.Error!void {
        _ = from_context(context);
        assert(@backingInt(linux.PR.SET_NO_NEW_PRIVS) == 38);
        try check(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    }

    fn set_user(context: *anyopaque, user_id: u32, group_id: u32) host.Error!void {
        assert(user_id != std.math.maxInt(u32));
        assert(group_id != std.math.maxInt(u32));
        _ = from_context(context);
        // No supplementary groups, then the group before the user: a process that has become
        // the user may no longer set its group.
        try check(linux.syscall2(.setgroups, 0, 0));
        try check(linux.setresgid(group_id, group_id, group_id));
        try check(linux.setresuid(user_id, user_id, user_id));
    }

    fn install_seccomp(context: *anyopaque, program: []const bpf.Insn) host.Error!void {
        _ = from_context(context);
        assert(program.len > 0);
        assert(program.len <= bpf.insns_max);
        const filter: SockFprog = .{ .len = @intCast(program.len), .filter = program.ptr };
        const operation = linux.SECCOMP.SET_MODE_FILTER;
        try check(linux.seccomp(operation, 0, &filter));
    }

    fn exec(context: *anyopaque, request: host.ExecRequest) host.Error!void {
        _ = from_context(context);
        assert(request.path.len > 0);
        assert(request.argv[0] != null);
        const result = linux.execve(request.path.ptr, request.argv, request.envp);
        // execve returns only when it failed.
        try check(result);
        unreachable; // A success never returns, and check turns every failure into an error.
    }

    fn gid(context: *anyopaque) u32 {
        _ = from_context(context);
        return linux.getgid();
    }

    fn environment(context: *anyopaque, name: []const u8) ?[]const u8 {
        const self = from_context(context);
        assert(name.len > 0);
        return self.environ.getPosix(name);
    }

    fn environment_at(context: *anyopaque, index: u32) ?host.EnvironmentEntry {
        const self = from_context(context);
        const entries = self.environ.block.slice;
        assert(index <= constants.environment_entries_max);
        if (index >= entries.len) return null;
        const text = std.mem.span(entries[index].?);
        // An entry without "=" has no value; it is listed with an empty one.
        const equals = std.mem.indexOfScalar(u8, text, '=') orelse text.len;
        if (equals == 0) return .{ .name = "?", .value = text };
        const value = if (equals < text.len) text[equals + 1 ..] else text[0..0];
        return .{ .name = text[0..equals], .value = value };
    }

    fn random_bytes(context: *anyopaque, buffer: []u8) host.Error!void {
        _ = from_context(context);
        assert(buffer.len > 0);
        assert(buffer.len <= 256);
        const result = linux.getrandom(buffer.ptr, buffer.len, 0);
        try check(result);
        if (result != buffer.len) return error.IoFailed; // Not short for 256 bytes or fewer.
    }

    // ---- Helpers, signals and files (slice 2) ----

    fn run_helper(
        context: *anyopaque,
        request: host.ExecRequest,
        output: []u8,
    ) host.Error!host.HelperResult {
        _ = from_context(context);
        assert(request.path.len > 0);
        assert(output.len > 0);
        var ends: [2]i32 = undefined;
        try check(linux.pipe2(&ends, .{ .CLOEXEC = true }));
        const forked = linux.fork();
        check(forked) catch |err| {
            _ = linux.close(ends[0]);
            _ = linux.close(ends[1]);
            return err;
        };
        if (forked == 0) helper_child(request, ends[1]);
        _ = linux.close(ends[1]);
        const length = drain_helper(ends[0], output);
        _ = linux.close(ends[0]);
        const status = try wait_child(@intCast(forked));
        assert(length <= output.len);
        return .{ .status = status, .output_len = length };
    }

    fn block_signals(context: *anyopaque, block: bool) host.Error!void {
        _ = from_context(context);
        const set = forwarded_set();
        assert(constants.forwarded_signals_count == 4);
        const how: u32 = if (block) linux.SIG.BLOCK else linux.SIG.UNBLOCK;
        try check(linux.sigprocmask(how, &set, null));
    }

    fn wait_event(context: *anyopaque, pid: host.Pid, timeout_ms: u32) host.Error!host.Event {
        _ = from_context(context);
        assert(pid > 0);
        const set = forwarded_set();
        var info: linux.siginfo_t = undefined;
        var early_status: i32 = 0;
        // Zero waits for ever; a time is a limit on each wait for a signal, and a signal that is
        // not the child's end (a stop, say) is not a reason to start the time again: the
        // deadline is fixed once.
        var limit = timespec_of(timeout_ms);
        const started = monotonic_now_ms();
        // A child that ended before the caller blocked the signals has had its SIGCHLD dropped
        // (the default action ignores it, and a signal that is not blocked is not queued), so
        // looking only at the queue would wait for ever for a child that is already a zombie. A
        // child that ends after this look raises a SIGCHLD that waits in the queue: the caller
        // has the signals blocked.
        const early = linux.wait4(@intCast(pid), &early_status, linux.W.NOHANG, null);
        try check(early);
        if (early != 0) {
            assert(early == pid);
            return .{ .exited = try decode_status(early_status) };
        }
        // Each pass takes one signal off the queue, so the loop ends when the child does; a
        // SIGCHLD for a child that is still running (a stop, say) is skipped.
        for (0..constants.forwarded_signals_max + constants.wait_interrupts_max) |_| {
            const size = linux.NSIG / 8;
            if (timeout_ms > 0) {
                const spent = monotonic_now_ms() -| started;
                if (spent >= timeout_ms) return .timeout;
                const left: u64 = timeout_ms - spent;
                limit = timespec_of(left);
            }
            const wait_for: usize = if (timeout_ms > 0) @intFromPtr(&limit) else 0;
            const taken = linux.syscall4(
                .rt_sigtimedwait,
                @intFromPtr(&set),
                @intFromPtr(&info),
                wait_for,
                size,
            );
            if (timeout_ms > 0 and linux.errno(taken) == .AGAIN) return .timeout;
            try check(taken);
            assert(taken > 0);
            assert(taken < constants.signal_number_max);
            if (taken != @backingInt(linux.SIG.CHLD)) return .{ .signal = @intCast(taken) };
            var status: i32 = 0;
            const result = linux.wait4(@intCast(pid), &status, linux.W.NOHANG, null);
            try check(result);
            if (result == 0) continue;
            assert(result == pid);
            return .{ .exited = try decode_status(status) };
        }
        return error.Stalled;
    }

    fn own_pid(context: *anyopaque) host.Pid {
        _ = from_context(context);
        return @intCast(linux.getpid());
    }

    fn working_directory(context: *anyopaque, buffer: []u8) host.Error![]const u8 {
        _ = from_context(context);
        assert(buffer.len > 1);
        const result = linux.getcwd(buffer.ptr, buffer.len);
        try check(result);
        // The kernel writes the path and its NUL; the result is the length with the NUL.
        const nul = std.mem.indexOfScalar(u8, buffer, 0);
        const length = nul orelse return error.IoFailed;
        // A directory that was removed under us has a path that does not start with a slash.
        if (length == 0 or buffer[0] != '/') return error.NotFound;
        return buffer[0..length];
    }

    fn sleep_ms(context: *anyopaque, ms: u32) void {
        _ = from_context(context);
        assert(ms > 0);
        var left = timespec_of(ms);
        // An interrupted sleep ends early: the callers poll, so a short sleep costs one more look.
        _ = linux.nanosleep(&left, &left);
    }

    fn monotonic_ms(context: *anyopaque) u64 {
        _ = from_context(context);
        return monotonic_now_ms();
    }

    /// Forks. The supervisor leaves the caller's session and process group (so a hang-up of the
    /// terminal does not reach it) and has /dev/null for its standard streams. Zbx has one thread
    /// when this is called, so the child is a faithful copy.
    fn fork_supervisor(context: *anyopaque) host.Error!host.Role {
        _ = from_context(context);
        const forked = linux.fork();
        try check(forked);
        if (forked != 0) return .parent;
        try check(linux.setsid());
        const opened = linux.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
        try check(opened);
        const null_fd: i32 = @intCast(opened);
        for ([_]i32{ 0, 1, 2 }) |target| try check(linux.dup2(null_fd, target));
        if (null_fd > 2) _ = linux.close(null_fd);
        return .supervisor;
    }

    fn exit_process(context: *anyopaque, code: u8) void {
        _ = from_context(context);
        linux.exit_group(code);
    }

    fn signal_state(context: *anyopaque, pid: host.Pid) host.Error!host.SignalState {
        _ = from_context(context);
        assert(pid > 0);
        var path: [48:0]u8 = undefined;
        // Cannot fail: "/proc/" and "/status" are 13 bytes and a pid at most ten digits.
        const text = std.fmt.bufPrintSentinel(&path, "/proc/{d}/status", .{pid}, 0) catch
            unreachable; // Same bound as above.
        const opened = linux.open(text.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        try check(opened);
        const descriptor: i32 = @intCast(opened);
        var buffer: [constants.status_bytes_max]u8 = undefined;
        const count = linux.read(descriptor, &buffer, buffer.len);
        const result = check(count);
        _ = linux.close(descriptor);
        try result;
        return parse_signal_masks(buffer[0..count]) orelse error.IoFailed;
    }

    fn time_now(context: *anyopaque) u64 {
        _ = from_context(context);
        var now: linux.timespec = undefined;
        const result = linux.clock_gettime(.REALTIME, &now);
        assert(linux.errno(result) == .SUCCESS); // A valid clock and a valid pointer.
        assert(now.sec >= 0);
        return @intCast(now.sec);
    }

    fn write_file(
        context: *anyopaque,
        path: [:0]const u8,
        bytes: []const u8,
        mode: u16,
    ) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        assert(mode <= 0o777);
        assert(bytes.len <= constants.write_bytes_max);
        const flags: linux.O = .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        };
        const opened = linux.open(path.ptr, flags, mode);
        try check(opened);
        const descriptor: i32 = @intCast(opened);
        // The process umask has cut the mode the file was made with, and a file that was there
        // kept its own: the mode asked for is set on the descriptor.
        check(linux.fchmod(descriptor, mode)) catch |err| {
            _ = linux.close(descriptor);
            return err;
        };
        var written: usize = 0;
        var calls: u32 = 0;
        const result: host.Error!void = while (written < bytes.len) {
            calls += 1;
            if (calls > constants.write_calls_max) break error.Stalled;
            const count = linux.write(descriptor, bytes[written..].ptr, bytes.len - written);
            check(count) catch |err| break err;
            written += count;
        } else {};
        _ = linux.close(descriptor); // The data is in the page cache; rename publishes it.
        try result;
        assert(written == bytes.len);
    }

    fn rename(context: *anyopaque, from: [:0]const u8, to: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(from.len > 0);
        assert(to.len > 0);
        try check(linux.rename(from.ptr, to.ptr));
    }

    fn remove_file(context: *anyopaque, path: [:0]const u8) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        try check(linux.unlink(path.ptr));
    }

    fn list_directory(
        context: *anyopaque,
        path: [:0]const u8,
        listing: *host.DirListing,
    ) host.Error!void {
        _ = from_context(context);
        assert(path.len > 0);
        assert(listing.count == 0);
        const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
        const opened = linux.open(path.ptr, flags, 0);
        try check(opened);
        const descriptor: i32 = @intCast(opened);
        const result = read_entries(descriptor, listing);
        _ = linux.close(descriptor);
        try result;
    }

    fn ignore_broken_pipe(context: *anyopaque, ignore: bool) void {
        _ = from_context(context);
        const handler = if (ignore) linux.SIG.IGN else linux.SIG.DFL;
        const action: linux.Sigaction = .{
            .handler = .{ .handler = handler },
            .mask = linux.sigemptyset(),
            .flags = 0,
        };
        const result = linux.sigaction(.PIPE, &action, null);
        assert(linux.errno(result) == .SUCCESS); // A valid signal and a valid handler.
    }

    fn filesystem(context: *anyopaque) store_fs.Fs {
        return host_real_fs.interface(from_context(context));
    }

    fn network(context: *anyopaque) registry_net.Net {
        return host_real_net.interface(from_context(context));
    }

    fn begin_step(context: *anyopaque, index: u32) void {
        _ = from_context(context);
        _ = index; // The kernel needs no hint; see Host.begin_step.
    }

    /// Converts a raw syscall return value into an error, or passes success through.
    pub fn check(result: usize) host.Error!void {
        const code = linux.errno(result);
        errno_last = @backingInt(code);
        if (code == .SUCCESS) return;
        assert(@backingInt(code) != 0);
        assert(errno_last < 4096);
        return host.error_for_errno(@backingInt(code));
    }
};

// ---- Container constants ----------------------------------------------------------------

/// The arguments of `clone3` up to and including `tls`: `CLONE_ARGS_SIZE_VER0`, 64 bytes. The
/// later fields (`set_tid`, `cgroup`) are not used, and the kernel accepts the short size.
/// The keeper's whole life, in the forked child: raw system calls only, no allocation. It asks
/// to be killed with its parent, checks the parent is still the one that forked it (it may have
/// ended before the request took effect), leaves the terminal's process group so that a ^C meant
/// for the container does not reach it, closes every descriptor but `hold`, and reads `hold`
/// until the end of file. Any failure ends it, which at worst makes the scope empty early; that
/// is the state before the keeper existed, and zbx copes with it.
fn keeper_main(parent: i32, hold: i32) noreturn {
    assert(parent > 1);
    assert(hold >= 0);
    const kill: usize = @backingInt(linux.SIG.KILL);
    if (linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), kill, 0, 0, 0) != 0) linux.exit_group(1);
    if (linux.getppid() != parent) linux.exit_group(1);
    _ = linux.setpgid(0, 0); // Best effort: the keeper still ends with its parent without it.
    const flags: linux.CLOSE_RANGE = .{ .UNSHARE = false, .CLOEXEC = false };
    if (hold > 0) {
        if (linux.close_range(0, hold - 1, flags) != 0) linux.exit_group(1);
    }
    if (linux.close_range(hold + 1, -1, flags) != 0) linux.exit_group(1);
    var byte: [1]u8 = undefined;
    for (0..constants.keeper_reads_max) |_| {
        const result = linux.read(hold, &byte, byte.len);
        switch (linux.errno(result)) {
            .SUCCESS => if (result == 0) linux.exit_group(0), // The writers are gone.
            .INTR => {},
            else => linux.exit_group(1),
        }
    }
    linux.exit_group(1);
}

const CloneArgs = extern struct {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
};

comptime {
    assert(@sizeOf(CloneArgs) == 64);
}

fn clone_flags(flags: host.SpawnFlags) u64 {
    var bits: u64 = 0;
    if (flags.user) bits |= linux.CLONE.NEWUSER;
    if (flags.mount) bits |= linux.CLONE.NEWNS;
    if (flags.pid) bits |= linux.CLONE.NEWPID;
    if (flags.uts) bits |= linux.CLONE.NEWUTS;
    if (flags.ipc) bits |= linux.CLONE.NEWIPC;
    if (flags.net) bits |= linux.CLONE.NEWNET;
    assert(bits & linux.CLONE.VM == 0); // The child gets its own memory, as after fork.
    assert(bits & linux.CSIGNAL == 0); // The exit signal is its own field.
    return bits;
}

/// The arguments of `mount` for a filesystem made new for the container. Fixed text, so the
/// child formats nothing. `newinstance` gives the container its own devpts, so it cannot see the
/// host's terminals.
/// `struct __user_cap_header_struct` and `__user_cap_data_struct` of capset(2), version 3.
const CapHeader = extern struct { version: u32, pid: i32 };
const CapData = extern struct { effective: u32, permitted: u32, inheritable: u32 };
const cap_version_3: u32 = 0x20080522;

/// `struct sock_fprog`.
const SockFprog = extern struct { len: u16, filter: [*]const bpf.Insn };

/// `struct statfs` of the 64-bit architectures; only `f_flags` is read.
const StatFs = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

const Fresh = struct {
    source: [:0]const u8,
    type: [:0]const u8,
    flags: u32,
    data: [:0]const u8,
};

/// Adds `IFF_UP` to the flags of the interface `name` through the socket `descriptor`. The two
/// ioctls are the whole of what `ip link set lo up` does for an interface that exists.
fn set_interface_up(descriptor: i32, name: []const u8) host.Error!void {
    assert(name.len > 0);
    assert(name.len < linux.IFNAMESIZE);
    var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..name.len], name);
    const get = linux.ioctl(descriptor, linux.SIOCGIFFLAGS, @intFromPtr(&request));
    try HostReal.check(get);
    request.ifru.flags.UP = true;
    const set = linux.ioctl(descriptor, linux.SIOCSIFFLAGS, @intFromPtr(&request));
    try HostReal.check(set);
    assert(request.ifru.flags.UP);
}

/// Makes a bind mount read-only. A bind remount that does not repeat the mount's own flags
/// (nosuid, nodev, noexec, noatime, nodiratime, relatime) is refused in a user namespace, where
/// those flags are locked: they are read from the mount first.
fn remount_readonly(target: [:0]const u8) host.Error!void {
    assert(target.len > 0);
    var found: StatFs = undefined;
    try HostReal.check(linux.syscall2(.statfs, @intFromPtr(target.ptr), @intFromPtr(&found)));
    const ms = linux.MS;
    const locked = ms.NOSUID | ms.NODEV | ms.NOEXEC | ms.NOATIME | ms.NODIRATIME | ms.RELATIME;
    const current: u32 = @intCast(found.f_flags);
    const flags = ms.REMOUNT | ms.BIND | ms.RDONLY | (current & locked);
    try HostReal.check(linux.mount(null, target.ptr, null, flags, 0));
}

/// `mount_setattr` (kernel 5.12): the attributes of a whole mount tree at once.
const MountAttr = extern struct {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
};

/// Makes `target` and every mount below it read-only. Where the call is missing (an older
/// kernel) only the mount itself is, which is all the kernel then offers.
fn remount_readonly_tree(target: [:0]const u8) host.Error!void {
    assert(target.len > 0);
    const mount_setattr_number = 442; // The same on x86_64 and aarch64.
    const attr_rdonly: u64 = 0x1; // MOUNT_ATTR_RDONLY
    const at_recursive: usize = 0x8000; // AT_RECURSIVE
    const attributes: MountAttr = .{
        .attr_set = attr_rdonly,
        .attr_clr = 0,
        .propagation = 0,
        .userns_fd = 0,
    };
    const result = linux.syscall5(
        @fromBackingInt(@intCast(mount_setattr_number)),
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(target.ptr),
        at_recursive,
        @intFromPtr(&attributes),
        @sizeOf(MountAttr),
    );
    if (linux.errno(result) == .NOSYS) return remount_readonly(target);
    try HostReal.check(result);
}

fn fresh_filesystem(kind: host.MountKind) Fresh {
    const ms = linux.MS;
    const fresh: Fresh = switch (kind) {
        .proc => .{
            .source = "proc",
            .type = "proc",
            .flags = ms.NOSUID | ms.NODEV | ms.NOEXEC,
            .data = "",
        },
        .sysfs => .{
            .source = "sysfs",
            .type = "sysfs",
            .flags = ms.RDONLY | ms.NOSUID | ms.NODEV | ms.NOEXEC,
            .data = "",
        },
        .dev_tmpfs => .{
            .source = "tmpfs",
            .type = "tmpfs",
            .flags = ms.NOSUID | ms.STRICTATIME,
            .data = "mode=755,size=65536k",
        },
        .shm_tmpfs => .{
            .source = "tmpfs",
            .type = "tmpfs",
            .flags = ms.NOSUID | ms.NODEV | ms.NOEXEC,
            .data = "mode=1777,size=65536k",
        },
        .tmp_tmpfs => .{
            .source = "tmpfs",
            .type = "tmpfs",
            .flags = ms.NOSUID | ms.NODEV,
            .data = std.fmt.comptimePrint("mode=1777,size={d}", .{constants.tmpfs_bytes_max}),
        },
        .run_tmpfs => .{
            .source = "tmpfs",
            .type = "tmpfs",
            .flags = ms.NOSUID | ms.NODEV,
            .data = std.fmt.comptimePrint("mode=755,size={d}", .{constants.tmpfs_bytes_max}),
        },
        .devpts => .{
            .source = "devpts",
            .type = "devpts",
            .flags = ms.NOSUID | ms.NOEXEC,
            .data = "newinstance,ptmxmode=0666",
        },
        else => unreachable, // The other kinds mount nothing new.
    };
    assert(fresh.source.len > 0);
    assert(fresh.flags & ms.BIND == 0);
    return fresh;
}

test "real host reads a file, reports a missing one, and closes every handle" {
    // Goal: the production implementation honours the interface contract on the machine running
    // the tests. Method: read /proc/self/stat (always present on Linux), then a path that cannot
    // exist, and check that no handle leaked on either path.
    var real: HostReal = .{};
    const subject = real.interface();
    var buffer: [constants.file_bytes_max]u8 = undefined;

    const content = try subject.read_file("/proc/self/stat", &buffer);
    try std.testing.expect(content.len > 0);
    try std.testing.expectEqual(@as(u32, 0), real.open_count);

    try std.testing.expectError(
        error.NotFound,
        subject.read_file("/proc/zigbox-does-not-exist", &buffer),
    );
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

test "real host refuses a file larger than the buffer instead of truncating" {
    // Goal: FileTooLarge, not a short success. Method: /proc/self/stat is over 8 bytes.
    var real: HostReal = .{};
    var small: [8]u8 = undefined;
    try std.testing.expectError(
        error.FileTooLarge,
        real.interface().read_file("/proc/self/stat", &small),
    );
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

// ---- Helper programs, signals and directories ---------------------------------------------

/// The signals zbx forwards to a container, and SIGCHLD, which says the container ended.
fn forwarded_set() linux.sigset_t {
    var set = linux.sigemptyset();
    for ([_]linux.SIG{ .INT, .TERM, .HUP, .QUIT, .CHLD }) |number| linux.sigaddset(&set, number);
    return set;
}

fn decode_status(status: i32) host.Error!host.ExitStatus {
    const bits: u32 = @bitCast(status);
    if (linux.W.IFEXITED(bits)) return .{ .exited = linux.W.EXITSTATUS(bits) };
    if (linux.W.IFSIGNALED(bits)) {
        const number: u32 = @backingInt(linux.W.TERMSIG(bits));
        assert(number > 0);
        assert(number < constants.signal_number_max);
        return .{ .signaled = @intCast(number) };
    }
    return error.IoFailed; // Stopped or continued: nothing here asks for those.
}

fn wait_child(pid: i32) host.Error!host.ExitStatus {
    assert(pid > 0);
    for (0..constants.wait_interrupts_max + 1) |_| {
        var status: i32 = 0;
        const result = linux.wait4(pid, &status, 0, null);
        if (linux.errno(result) == .INTR) continue;
        try HostReal.check(result);
        assert(result == pid);
        return decode_status(status);
    }
    return error.IoFailed;
}

/// The forked helper: its output goes to the pipe, then it becomes the program. It never
/// returns; a failed exec ends it with the conventional "command not found" code.
/// The child of `start_program`: its own session, killed with its parent, the signals zbx may
/// have blocked unblocked, its three streams, then the program. Exit code 127 is "could not run
/// it", as a shell says, and a parent that died before the death signal was set ends it too.
fn program_child(
    request: host.ExecRequest,
    parent: i32,
    stdin_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
) noreturn {
    _ = linux.setsid();
    const kill: usize = @backingInt(linux.SIG.KILL);
    const death = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), kill, 0, 0, 0);
    if (death != 0) linux.exit_group(127);
    if (linux.getppid() != parent) linux.exit_group(127);
    const none: linux.sigset_t = linux.sigemptyset();
    _ = linux.sigprocmask(linux.SIG.SETMASK, &none, null);
    if (linux.errno(linux.dup2(stdin_fd, linux.STDIN_FILENO)) != .SUCCESS) linux.exit_group(127);
    if (linux.errno(linux.dup2(stdout_fd, linux.STDOUT_FILENO)) != .SUCCESS) linux.exit_group(127);
    if (linux.errno(linux.dup2(stderr_fd, linux.STDERR_FILENO)) != .SUCCESS) linux.exit_group(127);
    _ = linux.execve(request.path.ptr, request.argv, request.envp);
    linux.exit_group(127);
}

fn helper_child(request: host.ExecRequest, output: i32) noreturn {
    _ = linux.dup2(output, linux.STDOUT_FILENO);
    _ = linux.dup2(output, linux.STDERR_FILENO);
    _ = linux.execve(request.path.ptr, request.argv, request.envp);
    linux.exit_group(127);
}

/// Reads the helper's output to the end: the first bytes are kept, the rest dropped.
fn drain_helper(descriptor: i32, output: []u8) u32 {
    var kept: usize = 0;
    var scratch: [64]u8 = undefined;
    for (0..constants.helper_read_calls_max) |_| {
        const room: []u8 = if (kept < output.len) output[kept..] else &scratch;
        const count = linux.read(descriptor, room.ptr, room.len);
        if (linux.errno(count) == .INTR) continue;
        if (linux.errno(count) != .SUCCESS) break;
        if (count == 0) break;
        if (kept < output.len) kept += count;
    }
    return @intCast(kept);
}

/// The `SigIgn:` and `SigCgt:` lines of /proc/<pid>/status, as masks.
fn parse_signal_masks(status: []const u8) ?host.SignalState {
    var caught: ?u64 = null;
    var ignored: ?u64 = null;
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        const key_end = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = line[0..key_end];
        const value = std.mem.trim(u8, line[key_end + 1 ..], " \t");
        const mask = std.fmt.parseInt(u64, value, 16) catch continue;
        if (std.mem.eql(u8, key, "SigCgt")) caught = mask;
        if (std.mem.eql(u8, key, "SigIgn")) ignored = mask;
    }
    return .{ .caught = caught orelse return null, .ignored = ignored orelse return null };
}

/// Appends every regular-file name of an open directory.
fn read_entries(descriptor: i32, listing: *host.DirListing) host.Error!void {
    var buffer: [4096]u8 align(8) = undefined;
    for (0..constants.dir_entries_max + constants.eintr_retries_max + 8) |_| {
        const count = linux.getdents64(descriptor, &buffer, buffer.len);
        try HostReal.check(count);
        if (count == 0) return;
        var at: usize = 0;
        while (at < count) {
            // linux_dirent64: ino u64, off i64, reclen u16, type u8, then the NUL-terminated name.
            const reclen = std.mem.readInt(u16, buffer[at + 16 ..][0..2], .little);
            assert(reclen >= 19);
            assert(at + reclen <= count);
            const kind = buffer[at + 18];
            const name = std.mem.sliceTo(buffer[at + 19 .. at + reclen], 0);
            const wanted = kind == dirent_regular or kind == dirent_unknown;
            if (wanted and name.len > 0) listing.add(name);
            at += reclen;
        }
    }
    listing.truncated = true; // More batches than a bounded listing can use.
}

const dirent_unknown: u8 = 0;
const dirent_regular: u8 = 8;

test "signal masks are read from the status lines, and only when both are there" {
    // Goal: SigCgt and SigIgn parse as hex masks; a status without either is not guessed at.
    const text = "Name:\tsh\nSigIgn:\t0000000000000004\nSigCgt:\t0000000000004002\n";
    const state = parse_signal_masks(text).?;
    try std.testing.expect(host.SignalState.has(state.caught, 2)); // SIGINT.
    try std.testing.expect(host.SignalState.has(state.caught, 15)); // SIGTERM.
    try std.testing.expect(!host.SignalState.has(state.caught, 1));
    try std.testing.expect(host.SignalState.has(state.ignored, 3)); // SIGQUIT.
    try std.testing.expect(parse_signal_masks("SigCgt:\t0\n") == null);
    try std.testing.expect(parse_signal_masks("SigIgn:\t0\nSigCgt:\tzz\n") == null);
    try std.testing.expect(parse_signal_masks("") == null);
}

test "a real helper's status and output are captured, and the rest dropped" {
    // Goal: run_helper on this machine: /bin/sh -c prints more than the buffer and exits 3.
    var real: HostReal = .{};
    const argv = [_:null]?[*:0]const u8{ "sh", "-c", "echo hello; echo oops >&2; exit 3", null };
    const envp = [_:null]?[*:0]const u8{null};
    var output: [8]u8 = undefined;
    const result = try real.interface().run_helper(
        .{ .path = "/bin/sh", .argv = &argv, .envp = &envp },
        &output,
    );
    try std.testing.expectEqual(host.ExitStatus{ .exited = 3 }, result.status);
    try std.testing.expectEqualStrings("hello\noo", output[0..result.output_len]);
    const missing = try real.interface().run_helper(
        .{ .path = "/zigbox/nope", .argv = &argv, .envp = &envp },
        &output,
    );
    try std.testing.expectEqual(host.ExitStatus{ .exited = 127 }, missing.status);
}

test "a directory listing keeps regular files and marks what does not fit" {
    // Goal: the real listing of a scratch directory: files by name, subdirectories left out.
    var name_buffer: [64]u8 = undefined;
    const format = "/tmp/zbx-list-{d}";
    const directory = try std.fmt.bufPrintSentinel(&name_buffer, format, .{linux.getpid()}, 0);
    try HostReal.check(linux.mkdir(directory.ptr, 0o755));
    defer _ = linux.rmdir(directory.ptr);
    var real: HostReal = .{};
    const subject = real.interface();
    var one: [80:0]u8 = undefined;
    const first = try std.fmt.bufPrintSentinel(&one, "{s}/a.zon", .{directory}, 0);
    try subject.write_file(first, "x");
    defer _ = linux.unlink(first.ptr);
    var two: [80:0]u8 = undefined;
    const sub = try std.fmt.bufPrintSentinel(&two, "{s}/subdir", .{directory}, 0);
    try HostReal.check(linux.mkdir(sub.ptr, 0o755));
    defer _ = linux.rmdir(sub.ptr);
    var listing: host.DirListing = undefined;
    try subject.list_directory(directory, &listing);
    try std.testing.expectEqual(@as(u32, 1), listing.count);
    try std.testing.expectEqualStrings("a.zon", listing.name(0));
    try std.testing.expect(!listing.truncated);
}

// ---- Probes ----------------------------------------------------------------------------------
//
// A probe forks a child that tries the operation and reports through its exit code, so a crash,
// hang or kernel oddity cannot touch the caller. The child never returns into the caller's
// code: it ends with exit_group, so no deferred cleanup of the parent runs in it. The parent
// bounds the wait, kills and reaps on timeout, and removes the scratch directory on every path.

/// The unprivileged identity probes run as when the caller is root. Root can create user
/// namespaces even where ordinary users cannot, so probing as root would wrongly pass.
const nobody_id: u32 = 65534;

const child_exit_ok: u8 = 0;
const child_exit_refused_namespace: u8 = 10;
const child_exit_refused_mount: u8 = 11;
/// The namespace exists, but writing setgroups/uid_map/gid_map was refused.
const child_exit_refused_map: u8 = 13;
const child_exit_failed: u8 = 12;

const scratch_names = [_][:0]const u8{ "work/work", "work", "upper", "lower", "merged" };

/// A scratch directory for the overlay probe: `root` plus fixed subdirectories made by the child.
const Scratch = struct {
    root: [constants.probe_scratch_bytes_max + 1]u8,
    root_len: u32,
    created: bool,

    /// `give_to` is set only when the caller is root: the unprivileged child then needs to own the
    /// directory. An ordinary caller already owns what it creates (and may not chown to a group
    /// it is not in).
    fn create(scratch: *Scratch, parent: []const u8, give_to: ?u32) host.Error!void {
        scratch.created = false;
        scratch.root_len = 0;
        if (parent.len == 0) return error.InvalidPath;
        if (parent.len > constants.probe_scratch_parent_bytes_max) return error.PathTooLong;
        const process: u32 = @intCast(linux.getpid());
        for (0..constants.probe_dir_attempts_max) |attempt| {
            const formatted = std.fmt.bufPrintSentinel(&scratch.root, "{s}/zbx-doctor-{d}-{d}", .{
                parent, process, attempt,
            }, 0) catch return error.PathTooLong;
            const result = linux.mkdir(formatted.ptr, 0o700);
            if (linux.errno(result) == .EXIST) continue;
            try HostReal.check(result);
            scratch.root_len = @intCast(formatted.len);
            scratch.created = true;
            if (give_to) |owner| try HostReal.check(linux.chown(formatted.ptr, owner, owner));
            assert(scratch.root_len > parent.len);
            assert(scratch.root[scratch.root_len] == 0);
            return;
        }
        return error.IoFailed;
    }

    fn join(scratch: *const Scratch, buffer: []u8, name: []const u8) [:0]const u8 {
        assert(scratch.created);
        assert(name.len > 0);
        const root = scratch.root[0..scratch.root_len];
        // Cannot fail: root is at most probe_scratch_bytes_max and buffers are sized for it.
        const joined = std.fmt.bufPrintSentinel(buffer, "{s}/{s}", .{ root, name }, 0);
        // Cannot fail: same bound as above.
        const result = joined catch unreachable;
        assert(result.len > root.len);
        return result;
    }

    /// Removes everything the child may have made, then the root. Missing entries are fine.
    fn remove(scratch: *const Scratch) void {
        if (!scratch.created) return;
        assert(scratch.root_len > 0);
        var buffer: [constants.probe_scratch_bytes_max + 16]u8 = undefined;
        for (scratch_names) |name| {
            _ = linux.rmdir(scratch.join(&buffer, name).ptr);
        }
        _ = linux.rmdir(scratch.root[0..scratch.root_len :0].ptr);
    }
};

fn probe_run(self: *HostReal, kind: host.ProbeKind) host.Error!host.ProbeOutcome {
    const caller = linux.getuid();
    const give_to: ?u32 = if (caller == 0) nobody_id else null;
    var scratch: Scratch = undefined;
    scratch.created = false;
    // Registered before create(): a failure after the directory exists (chown) must still
    // remove it.
    defer scratch.remove();
    if (kind == .overlay) try scratch.create(self.scratch_parent, give_to);

    var options: [3 * constants.probe_scratch_bytes_max + 64]u8 = undefined;
    const options_text = overlay_options(&options, &scratch);

    const forked = linux.fork();
    try HostReal.check(forked);
    if (forked == 0) child_main(self, kind, &scratch, options_text, caller == 0);
    const child: i32 = @intCast(forked);
    assert(child > 0);
    assert(scratch.created == (kind == .overlay));
    return wait_for_child(child, kind, self.probe_timeout_ms);
}

/// The overlay mount data, built in the parent so the child allocates and formats nothing.
fn overlay_options(buffer: []u8, scratch: *const Scratch) [:0]const u8 {
    if (!scratch.created) return "";
    const root = scratch.root[0..scratch.root_len];
    // userxattr: a mount made from a user namespace must keep its metadata in user.* xattrs.
    const format = "userxattr,lowerdir={s}/lower,upperdir={s}/upper,workdir={s}/work";
    // Cannot fail: the buffer holds three roots plus the fixed text, by construction above.
    const formatted = std.fmt.bufPrintSentinel(buffer, format, .{ root, root, root }, 0);
    // Cannot fail: same bound as above.
    const result = formatted catch unreachable;
    assert(std.mem.startsWith(u8, result, "userxattr,"));
    assert(result.len > 3 * root.len);
    return result;
}

/// Runs in the forked child and never returns.
fn child_main(
    self: *const HostReal,
    kind: host.ProbeKind,
    scratch: *const Scratch,
    options: [:0]const u8,
    drop_privileges: bool,
) noreturn {
    if (drop_privileges) {
        if (!drop_to_nobody()) linux.exit_group(child_exit_failed);
    }
    if (self.child_hook) |hook| hook();
    assert(scratch.created == (kind == .overlay));
    if (kind == .overlay) assert(options.len > 0);

    // The ids to map are read here, before the namespace exists: inside an unmapped user
    // namespace getuid() and getgid() return the overflow id (65534), not the caller's.
    const uid = linux.getuid();
    const gid = linux.getgid();
    assert(uid != 0); // Root was dropped to an unprivileged id above, or never was root.
    // A caller that changed its ids is not dumpable, which makes /proc/self/*_map root-owned.
    const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
    if (linux.errno(dumpable) != .SUCCESS) linux.exit_group(child_exit_failed);

    const flags: usize = switch (kind) {
        .userns => linux.CLONE.NEWUSER,
        .overlay => linux.CLONE.NEWUSER | linux.CLONE.NEWNS,
    };
    const unshared = linux.errno(linux.unshare(flags));
    if (unshared != .SUCCESS) {
        linux.exit_group(refusal_exit(unshared, child_exit_refused_namespace));
    }
    // Map the caller's single id to root inside, as zbx itself will. A process with no mapping
    // can create the namespace but not do anything useful in it (overlay mounts are refused).
    if (!map_single_ids(uid, gid)) linux.exit_group(child_exit_refused_map);
    if (kind == .userns) linux.exit_group(child_exit_ok);

    // Keep the mount from propagating back to the caller's namespace.
    const private = linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0);
    if (linux.errno(private) != .SUCCESS) linux.exit_group(child_exit_refused_mount);
    linux.exit_group(overlay_mount(scratch, options));
}

/// Writes `/proc/self/{setgroups,gid_map,uid_map}` so that `uid` and `gid` (the ids the process
/// had before it entered the namespace) map to 0 inside. A map may only name ids the caller owns.
fn map_single_ids(uid: u32, gid: u32) bool {
    var line: [32]u8 = undefined;
    if (!write_proc("/proc/self/setgroups", "deny")) return false;
    const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{gid}) catch return false;
    if (!write_proc("/proc/self/gid_map", gid_line)) return false;
    const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{uid}) catch return false;
    return write_proc("/proc/self/uid_map", uid_line);
}

fn write_proc(path: [:0]const u8, bytes: []const u8) bool {
    assert(bytes.len > 0);
    assert(std.mem.startsWith(u8, path, "/proc/self/")); // Only our own process's files.
    const opened = linux.open(path.ptr, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const descriptor: i32 = @intCast(opened);
    const written = linux.write(descriptor, bytes.ptr, bytes.len);
    _ = linux.close(descriptor);
    return linux.errno(written) == .SUCCESS and written == bytes.len;
}

/// Creates the overlay directories and mounts. Returns the child's exit code.
fn overlay_mount(scratch: *const Scratch, options: [:0]const u8) u8 {
    assert(scratch.created);
    assert(options.len > 0);
    var buffer: [constants.probe_scratch_bytes_max + 16]u8 = undefined;
    const directories = [_][:0]const u8{ "lower", "upper", "work", "merged" };
    for (directories) |name| {
        const made = linux.errno(linux.mkdir(scratch.join(&buffer, name).ptr, 0o700));
        if (made != .SUCCESS) return child_exit_failed;
    }
    const target = scratch.join(&buffer, "merged");
    const data = @intFromPtr(options.ptr);
    const mounted = linux.errno(linux.mount("overlay", target.ptr, "overlay", 0, data));
    if (mounted == .SUCCESS) return child_exit_ok;
    return refusal_exit(mounted, child_exit_refused_mount);
}

/// Errors that mean "this system says no" map to `refusal`; anything else is a probe failure.
fn refusal_exit(code: linux.E, refusal: u8) u8 {
    assert(code != .SUCCESS);
    const result: u8 = switch (code) {
        .PERM, .ACCES, .NOSPC, .INVAL, .NODEV, .NOSYS, .OPNOTSUPP => refusal,
        else => child_exit_failed,
    };
    assert(result != child_exit_ok); // A refusal is never reported as success.
    return result;
}

fn drop_to_nobody() bool {
    const no_groups = [_]linux.gid_t{};
    if (linux.errno(linux.setgroups(0, &no_groups)) != .SUCCESS) return false;
    if (linux.errno(linux.setresgid(nobody_id, nobody_id, nobody_id)) != .SUCCESS) return false;
    if (linux.errno(linux.setresuid(nobody_id, nobody_id, nobody_id)) != .SUCCESS) return false;
    // Changing ids made the process undumpable, which makes its /proc/self files root-owned
    // and unwritable for the uid_map step; make it dumpable again.
    const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
    if (linux.errno(dumpable) != .SUCCESS) return false;
    // Dropping the user id must also have dropped every capability; check, do not assume.
    return linux.getuid() == nobody_id and linux.geteuid() == nobody_id;
}

fn sleep_poll_interval() void {
    const interval: linux.timespec = .{
        .sec = 0,
        .nsec = @intCast(constants.probe_poll_ms * std.time.ns_per_ms),
    };
    _ = linux.nanosleep(&interval, null);
}

/// Polls for the child with a bounded number of steps; on timeout kills and reaps it.
fn wait_for_child(child: i32, kind: host.ProbeKind, timeout_ms: u32) host.ProbeOutcome {
    assert(child > 0);
    assert(timeout_ms >= constants.probe_poll_ms);
    const polls = @divExact(timeout_ms, constants.probe_poll_ms);
    var status: i32 = 0;
    for (0..polls + 1) |_| {
        const result = linux.wait4(child, &status, linux.W.NOHANG, null);
        if (result == child) return classify_status(@bitCast(status), kind);
        if (linux.errno(result) == .CHILD) return .failed; // Reaped elsewhere: cannot happen.
        sleep_poll_interval();
    }
    _ = linux.kill(child, .KILL);
    for (0..constants.probe_reap_polls_max) |_| {
        if (linux.wait4(child, &status, linux.W.NOHANG, null) == child) return .timed_out;
        sleep_poll_interval();
    }
    return .timed_out; // Unreapable (uninterruptible sleep): reported, and the zombie is harmless.
}

fn classify_status(status: u32, kind: host.ProbeKind) host.ProbeOutcome {
    if (linux.W.IFSIGNALED(status)) return .signaled;
    if (!linux.W.IFEXITED(status)) return .failed;
    return switch (linux.W.EXITSTATUS(status)) {
        child_exit_ok => .ok,
        child_exit_refused_namespace => if (kind == .userns) .denied else .setup_denied,
        child_exit_refused_map => .map_denied,
        child_exit_refused_mount => .denied,
        else => .failed,
    };
}

// ---- Probe tests -----------------------------------------------------------------------------

fn hook_sleep_forever() noreturn {
    const interval: linux.timespec = .{ .sec = 1, .nsec = 0 };
    while (true) _ = linux.nanosleep(&interval, null);
}

fn hook_kill_self() noreturn {
    _ = linux.kill(linux.getpid(), .KILL);
    linux.exit_group(0);
}

fn hook_exit_ok() noreturn {
    linux.exit_group(child_exit_ok);
}

fn hook_exit_namespace() noreturn {
    linux.exit_group(child_exit_refused_namespace);
}

fn hook_exit_map() noreturn {
    linux.exit_group(child_exit_refused_map);
}

fn hook_exit_mount() noreturn {
    linux.exit_group(child_exit_refused_mount);
}

/// Exits 0 only if the child is not root: proves privileges were dropped before the hook ran.
fn hook_exit_ok_if_unprivileged() noreturn {
    linux.exit_group(if (linux.getuid() == 0) 1 else child_exit_ok);
}

fn hook_exit_other() noreturn {
    linux.exit_group(77);
}

/// True if no child of this process remains, reaped or not (wait4 says ECHILD).
fn no_children_left() bool {
    var status: i32 = 0;
    const result = linux.wait4(-1, &status, linux.W.NOHANG, null);
    return linux.errno(result) == .CHILD;
}

test "probe child outcomes map from exit status, signal and timeout, and are all reaped" {
    // Goal: every way a probe child can end becomes the right outcome and leaves no zombie.
    // Method: replace the child body with hooks (so the answer does not depend on this
    // kernel), use a short timeout for the hanging child.
    const Case = struct {
        hook: *const fn () noreturn,
        kind: host.ProbeKind,
        expected: host.ProbeOutcome,
    };
    const cases = [_]Case{
        .{ .hook = hook_exit_ok, .kind = .userns, .expected = .ok },
        .{ .hook = hook_exit_namespace, .kind = .userns, .expected = .denied },
        .{ .hook = hook_exit_namespace, .kind = .overlay, .expected = .setup_denied },
        .{ .hook = hook_exit_mount, .kind = .overlay, .expected = .denied },
        .{ .hook = hook_exit_map, .kind = .userns, .expected = .map_denied },
        .{ .hook = hook_exit_map, .kind = .overlay, .expected = .map_denied },
        .{ .hook = hook_exit_other, .kind = .userns, .expected = .failed },
        .{ .hook = hook_kill_self, .kind = .userns, .expected = .signaled },
        .{ .hook = hook_sleep_forever, .kind = .userns, .expected = .timed_out },
    };
    for (cases) |case| {
        var real: HostReal = .{ .child_hook = case.hook, .probe_timeout_ms = 50 };
        const outcome = try real.interface().probe(case.kind);
        try std.testing.expectEqual(case.expected, outcome);
        try std.testing.expect(no_children_left());
    }
}

test "the probe child runs unprivileged even when the caller is root" {
    // Goal: root can create user namespaces where ordinary users cannot, so a probe run as root
    // would pass wrongly. Method: the hook runs after the privilege drop and reports whether the
    // child is still uid 0. When this test runs as an ordinary user the child never was root.
    var real: HostReal = .{ .child_hook = hook_exit_ok_if_unprivileged, .probe_timeout_ms = 1000 };
    try std.testing.expectEqual(host.ProbeOutcome.ok, try real.interface().probe(.userns));
    try std.testing.expect(no_children_left());
}

/// Forks a process that becomes `uid`:`gid` (dumpable, as a normal login is), runs the real
/// probe there, and returns its outcome. Null if it could not be run. Needs root to drop ids.
fn probe_as(uid: u32, gid: u32, kind: host.ProbeKind) ?host.ProbeOutcome {
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return null;
    if (forked == 0) {
        const no_groups = [_]linux.gid_t{};
        var ok = linux.errno(linux.setgroups(0, &no_groups)) == .SUCCESS;
        ok = ok and linux.errno(linux.setresgid(gid, gid, gid)) == .SUCCESS;
        ok = ok and linux.errno(linux.setresuid(uid, uid, uid)) == .SUCCESS;
        const dumpable = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 1, 0, 0, 0);
        if (!ok or linux.errno(dumpable) != .SUCCESS) linux.exit_group(99);
        var real: HostReal = .{ .probe_timeout_ms = 2000 };
        const outcome = real.interface().probe(kind) catch linux.exit_group(98);
        linux.exit_group(@intCast(@backingInt(outcome)));
    }
    var status: i32 = 0;
    if (linux.wait4(@intCast(forked), &status, 0, null) != forked) return null;
    const bits: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(bits)) return null;
    const code = linux.W.EXITSTATUS(bits);
    if (code >= std.meta.fieldNames(host.ProbeOutcome).len) return null;
    return @fromBackingInt(@intCast(code));
}

test "the real probe works for an ordinary user whose ids are neither root nor 65534" {
    // Goal: regression for reading getuid()/getgid() after unshare, which returns the overflow
    // id 65534 and maps an id the caller does not own (EPERM). The old tests ran as root, which
    // is dropped to 65534, the one id for which that bug is invisible. Method: run the real
    // probe as uid 4242 and gid 4343 (different from each other, root and 65534). It must agree
    // with the probe run as nobody; if this kernel refuses the probe for nobody too, skip.
    if (linux.getuid() != 0) return error.SkipZigTest; // Dropping ids needs root.
    const kinds = [_]host.ProbeKind{ .userns, .overlay };
    for (kinds) |kind| {
        const baseline = probe_as(65534, 65534, kind) orelse return error.SkipZigTest;
        if (baseline != .ok) return error.SkipZigTest;
        const other = probe_as(4242, 4343, kind) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(host.ProbeOutcome.ok, other);
    }
    try std.testing.expect(no_children_left());
}

test "the overlay probe leaves its scratch directory empty and removable" {
    // Goal: cleanup on every path. Method: point the scratch parent at a fresh directory, run
    // the overlay probe for real (whatever this kernel answers) and with each hook, then rmdir
    // the parent: it only succeeds if nothing was left behind.
    var name_buffer: [64]u8 = undefined;
    const format = "/tmp/zbx-test-{d}";
    const parent = try std.fmt.bufPrintSentinel(&name_buffer, format, .{linux.getpid()}, 0);
    try HostReal.check(linux.mkdir(parent.ptr, 0o755));
    defer _ = linux.rmdir(parent.ptr);

    var real: HostReal = .{ .scratch_parent = parent, .probe_timeout_ms = 2000 };
    _ = try real.interface().probe(.overlay);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rmdir(parent.ptr)));
    try HostReal.check(linux.mkdir(parent.ptr, 0o755));

    const hooks = [_]*const fn () noreturn{ hook_exit_ok, hook_kill_self, hook_sleep_forever };
    for (hooks) |hook| {
        real = .{ .scratch_parent = parent, .probe_timeout_ms = 50, .child_hook = hook };
        _ = try real.interface().probe(.overlay);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rmdir(parent.ptr)));
        try HostReal.check(linux.mkdir(parent.ptr, 0o755));
    }
    try std.testing.expect(no_children_left());
}

test "the real userns probe answers with a defined outcome" {
    // Goal: the unhooked probe runs end to end on this machine. The answer depends on the
    // kernel, so only its shape is asserted: not a hang, not a leak.
    var real: HostReal = .{ .probe_timeout_ms = 2000 };
    const outcome = try real.interface().probe(.userns);
    try std.testing.expect(outcome != .timed_out);
    try std.testing.expect(no_children_left());
}

test "real stat reports owner and type, capability read reports absence" {
    // Goal: stat returns the mode and owner of a root-owned directory; a file without the
    // xattr gives NoData rather than success; seccomp and uid answer.
    var real: HostReal = .{};
    const subject = real.interface();
    const result = try subject.stat("/proc");
    try std.testing.expectEqual(@as(u32, std.posix.S.IFDIR), result.mode & std.posix.S.IFMT);
    try std.testing.expectEqual(@as(u32, 0), result.uid);
    try std.testing.expectError(error.NotFound, subject.stat("/zigbox-does-not-exist"));

    var buffer: [constants.capability_bytes_max]u8 = undefined;
    try std.testing.expectError(error.NoData, subject.read_capability("/proc/self/stat", &buffer));
    try std.testing.expectError(error.NotFound, subject.read_capability("/zigbox-nope", &buffer));
    try std.testing.expectEqual(linux.getuid(), subject.uid());
    const mode = try subject.seccomp_mode();
    try std.testing.expect(mode <= 2);
}

const repeat = @import("test_util.zig").repeat;

test "real read_timeout waits for bytes, times out when there are none, and sees the end" {
    // Goal: the poll-then-read that the D-Bus client's waits are built on. Method: a real pipe
    // with nothing in it times out (the call returns after about the time asked, not a hang);
    // with a byte in it the read returns it; with the writer closed the read returns 0.
    var real: HostReal = .{};
    const subject = real.interface();
    const pipe = try subject.pipe();
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.TimedOut, subject.read_timeout(pipe.read, &buffer, 10));
    try std.testing.expectEqual(@as(u16, 0), subject.last_errno());
    try subject.write_handle_all(pipe.write, "x");
    try std.testing.expectEqual(@as(u32, 1), try subject.read_timeout(pipe.read, &buffer, 10));
    try std.testing.expectEqual(@as(u8, 'x'), buffer[0]);
    subject.close(pipe.write);
    try std.testing.expectEqual(@as(u32, 0), try subject.read_timeout(pipe.read, &buffer, 10));
    subject.close(pipe.read);
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

test "real socket_connect names why a bus cannot be reached" {
    // Goal: a path that does not exist is NotFound (ENOENT), and one that is not a socket is
    // refused with the errno the diagnostic names (ECONNREFUSED); neither leaves a descriptor.
    var real: HostReal = .{};
    const subject = real.interface();
    try std.testing.expectError(error.NotFound, subject.socket_connect("/zigbox-no-such-bus"));
    try std.testing.expectEqual(@as(u16, 2), subject.last_errno());
    try std.testing.expectError(error.IoFailed, subject.socket_connect("/dev/null"));
    try std.testing.expectEqual(@as(u16, 111), subject.last_errno());
    try std.testing.expectError(error.PathTooLong, subject.socket_connect(repeat('/', 108)));
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}

/// The number of open descriptors of a process, from `/proc/<pid>/fd`; null if it cannot be read.
fn descriptor_count(pid: host.Pid) ?u32 {
    var path: [32:0]u8 = undefined;
    // Cannot fail: "/proc/4294967295/fd" is 19 bytes.
    const text = std.fmt.bufPrintSentinel(&path, "/proc/{d}/fd", .{pid}, 0) catch unreachable;
    const opened = linux.open(text.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return null;
    const directory: i32 = @intCast(opened);
    defer _ = linux.close(directory);
    var buffer: [4096]u8 align(8) = undefined;
    var count: u32 = 0;
    while (true) {
        const read = linux.getdents64(directory, &buffer, buffer.len);
        if (linux.errno(read) != .SUCCESS) return null;
        if (read == 0) return count;
        var at: usize = 0;
        while (at < read) {
            const length = std.mem.readInt(u16, buffer[at + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(buffer[at + 19 ..], 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) count += 1;
            at += length;
        }
    }
}

test "real wait_event sees a child that ended before the signals were blocked" {
    // Goal: the hang of `zbx run ... -- true` that showed once in a few dozen runs in the VM: the
    // container ended between the start of its command and the block of SIGCHLD, so the signal
    // was dropped and the wait looked at an empty queue for ever. Method: a child that exits at
    // once, a pause long enough for it to be a zombie and its SIGCHLD to be gone, then the
    // block and the wait, which must answer with the child's status and not run out its time.
    var real: HostReal = .{};
    const subject = real.interface();
    const forked = linux.fork();
    try std.testing.expect(linux.errno(forked) == .SUCCESS);
    if (forked == 0) linux.exit_group(7);
    const pid: host.Pid = @intCast(forked);
    subject.sleep_ms(200);
    try subject.block_signals(true);
    defer subject.block_signals(false) catch {};
    const event = try subject.wait_event(pid, 5000);
    try std.testing.expectEqual(host.Event{ .exited = .{ .exited = 7 } }, event);
}

test "real keeper holds one descriptor, lives until its pipe's writers are gone, and ends 0" {
    // Goal: Host.start_keeper on a real kernel. Method: open a second pipe first so there is
    // something to inherit, start the keeper on the first pipe's read end, and wait until it has
    // closed everything else (it holds exactly one descriptor, the pipe). It is alive while the
    // write end is open and, with that closed, ends with status 0 and is reaped. The death
    // signal and the parent check are the kernel's; the VM demo kills a zbx and looks.
    var real: HostReal = .{};
    const subject = real.interface();
    const hold = try subject.pipe();
    const other = try subject.pipe();
    const pid = try subject.start_keeper(hold.read);
    subject.close(hold.read);
    subject.close(other.read);
    subject.close(other.write);
    var settled = false;
    for (0..400) |_| {
        if (descriptor_count(pid) == 1) {
            settled = true;
            break;
        }
        subject.sleep_ms(5);
    }
    try std.testing.expect(settled);
    try subject.signal(pid, 0); // Alive: it is blocked reading.
    subject.close(hold.write);
    const status = try subject.wait_for(pid);
    try std.testing.expectEqual(host.ExitStatus{ .exited = 0 }, status);
    try std.testing.expectEqual(@as(u32, 0), real.open_count);
}
