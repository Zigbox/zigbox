//! The VM's PID 1: a static Linux program, no libc. It makes a root that `pivot_root` works on,
//! mounts what a Linux userland expects, and answers the macOS `zbx` on a vsock port:
//!
//!   hello     the image version
//!   setup     once: the clock, the network (DHCP), the Mac user as a user of the guest, the
//!             delegated cgroup subtree, and `zbx guest serve` started as that user
//!   busy      how many of the user's processes run (the host stops an idle VM)
//!   shutdown  sync and power off
//!
//! PID 1 must never return: the kernel panics if it does. Every failure here is written to the
//! console (the host keeps it in console.log) and ends in a power-off, which the host sees as a
//! stopped machine. Setup failures are different: they are answered, so the host can say why.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const dhcp = @import("vm_dhcp.zig");
const protocol = @import("vm_protocol.zig");
const ports_agent = @import("guest_ports.zig");
const storage = @import("vm_guest_storage.zig");

pub const panic = std.debug.FullPanic(panic_handler);

fn panic_handler(message: []const u8, first_trace_addr: ?usize) noreturn {
    assert(message.len < constants.output_bytes_max);
    _ = first_trace_addr;
    log("zbx-init: panic: ", message);
    power_off();
}

const version_path = "/etc/zbx-image-version";
const accepts_max: u32 = 1 << 20;
const backlog: u32 = 4;
const address_any: u32 = 0xffff_ffff;

const Mount = struct {
    source: [:0]const u8,
    target: [:0]const u8,
    kind: [:0]const u8,
    flags: u32 = 0,
};

/// In order: /proc and /sys first, because the cgroup tree is below /sys.
const mounts = [_]Mount{
    .{ .source = "proc", .target = "/proc", .kind = "proc" },
    .{ .source = "sysfs", .target = "/sys", .kind = "sysfs" },
    .{ .source = "devtmpfs", .target = "/dev", .kind = "devtmpfs" },
    .{ .source = "devpts", .target = "/dev/pts", .kind = "devpts" },
    .{ .source = "tmpfs", .target = "/run", .kind = "tmpfs" },
    .{ .source = "tmpfs", .target = "/tmp", .kind = "tmpfs" },
    .{ .source = "cgroup2", .target = "/sys/fs/cgroup", .kind = "cgroup2" },
};

/// What the initramfs carries that the new root needs. Everything else is made on the way.
const copied = [_][:0]const u8{ "bin", "etc", "lib", "usr" };
const made = [_][:0]const u8{ "proc", "sys", "dev", "run", "tmp", "mnt", "sbin" };

pub fn main() void {
    assert(mounts.len > 0);
    assert(constants.vm_guest_port > 0);
    log("zbx-init: starting", "");
    reap_orphans();
    switch_root();
    for (mounts) |mount| mount_one(&mount);
    make_tun_device();
    open_low_ports();
    var version_buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const version = read_version(&version_buffer);
    log("zbx-init: image ", version);
    const listener = listen_on_vsock();
    log("zbx-init: listening on vsock", "");
    serve(listener, version);
    power_off();
}

/// The Mac decides which ports a user may publish, and a port under 1024 is published by pasta
/// from the guest's side: the guest has no reason to keep them for root.
fn open_low_ports() void {
    assert(mounts.len > 0);
    const path = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
    if (!write_text(path, "0\n", 0o644)) log("zbx-init: cannot open the low ports", "");
}

/// pasta makes its tap device through /dev/net/tun, and the user it runs as must be able to open
/// it: the kernel's own node is root-only unless it is made again with a mode.
fn make_tun_device() void {
    assert(mounts.len > 0);
    _ = linux.mkdir("/dev/net", 0o755);
    const device: u32 = (10 << 8) | 200; // The misc device `tun` has minor 200.
    assert(device != 0);
    _ = linux.unlink("/dev/net/tun");
    const node = linux.mknodat(linux.AT.FDCWD, "/dev/net/tun", linux.S.IFCHR | 0o666, device);
    if (failed(node)) log("zbx-init: cannot make /dev/net/tun", "");
    // The umask took the write bits away from the mode given to mknod.
    _ = linux.chmod("/dev/net/tun", 0o666);
}

/// A process whose parent ended is adopted by PID 1 (a detached container's supervisor is such
/// a process), and a zombie that nobody waits for is a process for ever. PID 1 does not wait for
/// anything itself, so the kernel is told to reap every child of its own that ends.
fn reap_orphans() void {
    const action: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = linux.SA.NOCLDWAIT,
    };
    assert(!failed(linux.sigaction(.CHLD, &action, null)));
}

fn log(prefix: []const u8, detail: []const u8) void {
    assert(prefix.len < 256);
    assert(detail.len <= constants.vm_home_bytes_max); // A path, a word or a version.
    const newline = "\n";
    _ = linux.write(2, prefix.ptr, prefix.len);
    if (detail.len > 0) _ = linux.write(2, detail.ptr, detail.len);
    _ = linux.write(2, newline, newline.len);
}

fn power_off() noreturn {
    assert(version_path.len > 0);
    storage.quiesce_disk();
    linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    // The kernel did not power off; PID 1 may not return, so wait for the host to stop us.
    while (true) _ = linux.pause();
}

fn failed(result: usize) bool {
    return linux.errno(result) != .SUCCESS;
}

fn mount_one(mount: *const Mount) void {
    assert(mount.source.len > 0);
    assert(mount.kind.len > 0);
    assert(mount.target.len > 1);
    assert(mount.target[0] == '/');
    // The directory may exist already; EEXIST is the normal answer.
    _ = linux.mkdir(mount.target, 0o755);
    const result = linux.mount(mount.source, mount.target, mount.kind, mount.flags, 0);
    if (failed(result)) log("zbx-init: could not mount ", mount.target);
}

// ---- The root --------------------------------------------------------------------------------
//
// The initramfs is the kernel's `rootfs`, and `pivot_root` (which zbx uses to enter a
// container's root) refuses to run when the current root is that. So, as `switch_root` does,
// init copies what it needs into a tmpfs, moves the tmpfs over `/` and enters it.

fn switch_root() void {
    assert(copied.len > 0);
    assert(made.len > 0);
    _ = linux.mkdir("/newroot", 0o755);
    if (failed(linux.mount("tmpfs", "/newroot", "tmpfs", 0, 0))) fatal("cannot mount a tmpfs");
    for (copied) |name| copy_directory(name);
    for (made) |name| {
        var path: [32:0]u8 = @splat(0);
        _ = std.fmt.bufPrint(&path, "/newroot/{s}", .{name}) catch unreachable; // Short names.
        _ = linux.mkdir(&path, 0o755);
    }
    _ = linux.chmod("/newroot/tmp", 0o1777);
    if (failed(linux.chdir("/newroot"))) fatal("cannot enter the new root");
    if (failed(linux.mount(".", "/", null, linux.MS.MOVE, 0))) fatal("cannot move the new root");
    if (failed(linux.chroot("."))) fatal("cannot chroot");
    _ = linux.chdir("/");
}

fn fatal(message: []const u8) noreturn {
    log("zbx-init: ", message);
    power_off();
}

const queue_max: u32 = 64;
const path_max: usize = 200;
const Queue = struct {
    paths: [queue_max][path_max]u8 = undefined,
    lengths: [queue_max]u8 = undefined,
    count: u32 = 0,
    next: u32 = 0,
};

var copy_queue: Queue = .{};
var copy_buffer: [64 * 1024]u8 = undefined;
var directory_buffer: [8192]u8 align(8) = undefined;

/// Copies `/<name>` into `/newroot/<name>`: directories, files with their modes (setuid bits
/// too) and symlinks, breadth first with a queue of directories, so there is no recursion.
fn copy_directory(name: [:0]const u8) void {
    assert(name.len > 0);
    assert(name[0] != '/');
    const queue = &copy_queue;
    queue.count = 0;
    queue.next = 0;
    push(queue, "/", name);
    make_in_new_root(name);
    while (queue.next < queue.count) {
        var directory: [path_max + 1:0]u8 = @splat(0);
        const length = queue.lengths[queue.next];
        @memcpy(directory[0..length], queue.paths[queue.next][0..length]);
        queue.next += 1;
        copy_entries(queue, directory[0..length :0]);
    }
    assert(queue.next == queue.count); // Every directory that was found was copied.
}

fn push(queue: *Queue, parent: []const u8, name: []const u8) void {
    assert(queue.count < queue_max);
    assert(name.len > 0);
    const separator = if (std.mem.eql(u8, parent, "/")) "" else "/";
    const target = &queue.paths[queue.count];
    const text = std.fmt.bufPrint(target, "{s}{s}{s}", .{ parent, separator, name }) catch {
        fatal("a path is too long");
    };
    queue.lengths[queue.count] = @intCast(text.len);
    assert(queue.lengths[queue.count] > 0); // A path, never nothing.
    queue.count += 1;
    assert(queue.count <= queue_max);
}

fn make_in_new_root(source: []const u8) void {
    assert(source.len > 0);
    var path: [path_max + 16:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&path, "/newroot/{s}", .{source}) catch fatal("a path is too long");
    _ = linux.mkdir(&path, 0o755);
}

fn destination_of(buffer: *[path_max + 16:0]u8, source: []const u8) [*:0]const u8 {
    buffer.* = @splat(0);
    _ = std.fmt.bufPrint(buffer, "/newroot{s}", .{source}) catch fatal("a path is too long");
    return buffer;
}

fn copy_entries(queue: *Queue, directory: [:0]const u8) void {
    assert(queue.next <= queue.count);
    assert(directory.len > 0);
    const opened = linux.open(directory, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (failed(opened)) fatal("cannot read a directory");
    const handle: i32 = @intCast(opened);
    defer _ = linux.close(handle);
    while (true) {
        const count = linux.getdents64(handle, &directory_buffer, directory_buffer.len);
        if (failed(count) or count == 0) return;
        var at: usize = 0;
        while (at < count) {
            const reclen = std.mem.readInt(u16, directory_buffer[at + 16 ..][0..2], .little);
            const kind = directory_buffer[at + 18];
            const name_start = at + 19;
            const name = std.mem.sliceTo(directory_buffer[name_start .. at + reclen], 0);
            at += reclen;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            copy_entry(queue, directory, name, kind);
        }
    }
}

const dt_dir: u8 = 4;
const dt_reg: u8 = 8;
const dt_lnk: u8 = 10;

fn copy_entry(queue: *Queue, directory: []const u8, name: []const u8, kind: u8) void {
    assert(queue.count <= queue_max);
    assert(name.len > 0);
    var source: [path_max + 1:0]u8 = @splat(0);
    const separator = if (std.mem.eql(u8, directory, "/")) "" else "/";
    _ = std.fmt.bufPrint(&source, "{s}{s}{s}", .{ directory, separator, name }) catch {
        fatal("a path is too long");
    };
    const source_path = std.mem.sliceTo(&source, 0);
    var destination_buffer: [path_max + 16:0]u8 = undefined;
    const destination = destination_of(&destination_buffer, source_path);
    switch (kind) {
        dt_dir => {
            _ = linux.mkdir(destination, 0o755);
            push(queue, directory, name);
        },
        dt_reg => copy_file(@ptrCast(&source), destination),
        dt_lnk => copy_link(@ptrCast(&source), destination),
        else => {},
    }
}

fn copy_file(source: [*:0]const u8, destination: [*:0]const u8) void {
    assert(source[0] == '/');
    assert(destination[0] == '/');
    const input = linux.open(source, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(input)) fatal("cannot read a file");
    const from: i32 = @intCast(input);
    defer _ = linux.close(from);
    var info: linux.Statx = undefined;
    const wanted: linux.STATX = .{ .MODE = true, .SIZE = true };
    if (failed(linux.statx(from, "", linux.AT.EMPTY_PATH, wanted, &info))) {
        fatal("cannot stat a file");
    }
    var copied_bytes: u64 = 0;
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true };
    const output = linux.open(destination, flags, 0o600);
    if (failed(output)) fatal("cannot make a file");
    const to: i32 = @intCast(output);
    defer _ = linux.close(to);
    while (true) {
        const count = linux.read(from, &copy_buffer, copy_buffer.len);
        if (failed(count)) fatal("cannot read a file");
        if (count == 0) break;
        var done: usize = 0;
        while (done < count) {
            const written = linux.write(to, copy_buffer[done..].ptr, count - done);
            if (failed(written)) fatal("cannot write a file");
            done += written;
        }
        copied_bytes += count;
    }
    assert(copied_bytes == info.size); // The copy is the whole file.
    _ = linux.fchmod(to, info.mode & 0o7777);
}

fn copy_link(source: [*:0]const u8, destination: [*:0]const u8) void {
    assert(source[0] == '/');
    assert(destination[0] == '/');
    var target: [path_max + 1:0]u8 = @splat(0);
    const count = linux.readlink(source, &target, path_max);
    if (failed(count)) fatal("cannot read a link");
    assert(count >= 1); // A link to nothing is not a link.
    assert(count <= path_max);
    _ = linux.symlink(&target, destination);
}

fn read_version(buffer: *[constants.vm_line_bytes_max]u8) []const u8 {
    assert(buffer.len == constants.vm_line_bytes_max);
    assert(version_path.len > 0);
    const opened = linux.open(version_path, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(opened)) fatal("no image version file");
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    const count = linux.read(descriptor, buffer, buffer.len);
    if (failed(count)) power_off();
    const text = std.mem.trimEnd(u8, buffer[0..count], "\n");
    if (!protocol.is_version(text)) fatal("bad image version file");
    return text;
}

fn listen_on_vsock() i32 {
    assert(backlog > 0);
    assert(address_any == 0xffff_ffff);
    const opened = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM, 0);
    if (failed(opened)) fatal("no vsock (is the kernel built with it?)");
    const listener: i32 = @intCast(opened);
    const address: linux.sockaddr.vm = .{
        .port = constants.vm_guest_port,
        .cid = address_any,
        .flags = 0,
    };
    const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.vm));
    if (failed(bound)) power_off();
    if (failed(linux.listen(listener, backlog))) power_off();
    return listener;
}

// ---- Answering the host ------------------------------------------------------------------------

/// What setup made, for the answers that follow it.
const World = struct {
    done: bool = false,
    network_up: bool = false,
    uid: u32 = 0,
    gid: u32 = 0,
    serve_pid: i32 = 0,
};

var world: World = .{};

/// Answers one connection at a time, for as long as the machine lives. The bound is a count of
/// connections no real host reaches; it only keeps the loop finite on paper.
fn serve(listener: i32, version: []const u8) void {
    assert(listener >= 0);
    assert(accepts_max > 0);
    var accepted: u32 = 0;
    while (accepted < accepts_max) : (accepted += 1) {
        var peer: linux.sockaddr.vm = undefined;
        var peer_length: u32 = @sizeOf(linux.sockaddr.vm);
        const result = linux.accept(listener, @ptrCast(&peer), &peer_length);
        if (failed(result)) continue;
        const connection: i32 = @intCast(result);
        if (!protocol.from_host(peer.cid)) {
            log("zbx-init: refused a connection that is not from the host", "");
            _ = linux.close(connection);
            continue;
        }
        defer _ = linux.close(connection);
        if (answer(connection, version) == .shutdown) return;
    }
}

const Outcome = enum { go_on, shutdown };

fn answer(connection: i32, version: []const u8) Outcome {
    assert(connection >= 0);
    assert(version.len == constants.vm_image_version_bytes);
    var line: [constants.vm_line_bytes_max]u8 = undefined;
    const length = read_line(connection, &line) orelse return .go_on;
    const request = line[0..length];
    var reply: [constants.vm_line_bytes_max]u8 = undefined;
    if (std.mem.eql(u8, request, protocol.hello_request)) {
        reply_with(connection, protocol.render_hello_reply(&reply, version));
    } else if (std.mem.eql(u8, request, protocol.busy_request)) {
        reply_with(connection, protocol.render_busy_reply(&reply, count_user_processes()));
    } else if (protocol.parse_setup(request)) |setup| {
        reply_with(connection, do_setup(&setup));
    } else if (std.mem.eql(u8, request, protocol.shutdown_request)) {
        reply_with(connection, protocol.shutdown_reply);
        log("zbx-init: shutting down", "");
        return .shutdown;
    }
    return .go_on;
}

fn reply_with(connection: i32, text: []const u8) void {
    assert(text.len > 0);
    assert(text[text.len - 1] == '\n');
    _ = linux.write(connection, text.ptr, text.len);
}

/// Reads up to and including the first newline; null if the line is too long or the peer left.
fn read_line(connection: i32, buffer: *[constants.vm_line_bytes_max]u8) ?usize {
    assert(connection >= 0);
    assert(buffer.len == constants.vm_line_bytes_max);
    var length: usize = 0;
    while (length < buffer.len) {
        const count = linux.read(connection, buffer[length..].ptr, 1);
        if (failed(count)) return null;
        if (count == 0) return null;
        length += 1;
        if (buffer[length - 1] == '\n') return length;
    }
    return null;
}

// ---- Setup ---------------------------------------------------------------------------------

fn fail_reply(word: []const u8) []const u8 {
    assert(word.len < 16);
    assert(word.len > 0);
    log("zbx-init: setup failed: ", word);
    if (std.mem.eql(u8, word, "clock")) return "fail clock\n";
    if (std.mem.eql(u8, word, "user")) return "fail user\n";
    if (std.mem.eql(u8, word, "cgroup")) return "fail cgroup\n";
    if (std.mem.eql(u8, word, "disk")) return "fail disk\n";
    if (std.mem.eql(u8, word, "home")) return "fail home\n";
    if (std.mem.eql(u8, word, "serve")) return "fail serve\n";
    return "fail setup\n";
}

fn do_setup(setup: *const protocol.Setup) []const u8 {
    assert(setup.uid > 0);
    assert(protocol.home_ok(setup.home)); // The request parser refused any other.
    if (world.done) {
        // The host asks again after a restart of its own; the guest is set up for its user.
        if (world.uid != setup.uid) return fail_reply("user");
        return if (world.network_up) protocol.setup_ok_up else protocol.setup_ok_down;
    }
    // The Mac's uid must not sit in the range the containers' ids are mapped to, or one id would
    // mean two users.
    const subid_end = constants.vm_subid_start + constants.vm_subid_count;
    if (setup.uid >= constants.vm_subid_start and setup.uid < subid_end) return fail_reply("user");
    if (setup.uid >= constants.vm_subid_start) assert(setup.uid >= subid_end);
    const time: linux.timeval = .{ .sec = @intCast(setup.seconds), .usec = 0 };
    if (failed(linux.settimeofday(&time, &.{ .minuteswest = 0, .dsttime = 0 }))) {
        return fail_reply("clock");
    }
    world.network_up = bring_up_network(setup.dns);
    if (!make_user(setup)) return fail_reply("user");
    if (!storage.mount_disk(setup.uid, setup.gid)) return fail_reply("disk");
    var home: [constants.vm_home_bytes_max + 1:0]u8 = @splat(0);
    @memcpy(home[0..setup.home.len], setup.home);
    if (!storage.mount_home(home[0..setup.home.len :0])) return fail_reply("home");
    // Rosetta is optional: without it only linux/amd64 images cannot run.
    if (!storage.mount_rosetta()) log("zbx-init: no Rosetta in this machine", "");
    if (!make_cgroups(setup)) return fail_reply("cgroup");
    world.serve_pid = start_serve(setup) orelse return fail_reply("serve");
    assert(world.serve_pid > 1);
    world.uid = setup.uid;
    world.gid = setup.gid;
    world.done = true;
    assert(world.uid == setup.uid);
    return if (world.network_up) protocol.setup_ok_up else protocol.setup_ok_down;
}

fn write_text(path: [:0]const u8, text: []const u8, mode: u32) bool {
    assert(path[0] == '/');
    assert(path.len > 0);
    const opened = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, mode);
    if (failed(opened)) return false;
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    return !failed(linux.write(descriptor, text.ptr, text.len));
}

fn make_user(setup: *const protocol.Setup) bool {
    assert(protocol.name_ok(setup.name));
    assert(protocol.home_ok(setup.home));
    var text: [1024]u8 = undefined;
    const passwd = std.fmt.bufPrint(
        &text,
        "root:x:0:0:root:/root:/bin/sh\n{s}:x:{d}:{d}::{s}:/bin/sh\n",
        .{ setup.name, setup.uid, setup.gid, setup.home },
    ) catch return false;
    if (!write_text("/etc/passwd", passwd, 0o644)) return false;
    const group_line = "root:x:0:\n{s}:x:{d}:\n";
    const group = std.fmt.bufPrint(&text, group_line, .{ setup.name, setup.gid }) catch {
        return false;
    };
    if (!write_text("/etc/group", group, 0o644)) return false;
    const range = std.fmt.bufPrint(&text, "{s}:{d}:{d}\n", .{
        setup.name, constants.vm_subid_start, constants.vm_subid_count,
    }) catch return false;
    if (!write_text("/etc/subuid", range, 0o644)) return false;
    if (!write_text("/etc/subgid", range, 0o644)) return false;
    return make_home(setup);
}

/// The home directory, and its parents, made by root and given to the user.
fn make_home(setup: *const protocol.Setup) bool {
    assert(protocol.home_ok(setup.home));
    assert(setup.uid > 0);
    var path: [constants.vm_home_bytes_max + 1:0]u8 = @splat(0);
    var end: usize = 1;
    while (end <= setup.home.len) : (end += 1) {
        if (end < setup.home.len and setup.home[end] != '/') continue;
        assert(end <= setup.home.len); // A prefix of the home, never past it.
        @memcpy(path[0..end], setup.home[0..end]);
        path[end] = 0;
        _ = linux.mkdir(&path, 0o755);
    }
    @memcpy(path[0..setup.home.len], setup.home);
    path[setup.home.len] = 0;
    return !failed(linux.chown(&path, setup.uid, setup.gid));
}

/// Gives the user a cgroup subtree to make one cgroup per container in, as systemd's `Delegate=`
/// does: the controllers are enabled down to it, it and its control files belong to the user,
/// and the processes of the guest's own service live in a leaf beside the containers' cgroups
/// (a cgroup that has controllers enabled for its children may hold no process itself).
fn make_cgroups(setup: *const protocol.Setup) bool {
    assert(setup.uid > 0);
    const controllers = "+cpu +memory +pids";
    const root = constants.vm_cgroup_root;
    if (!write_text("/sys/fs/cgroup/cgroup.subtree_control", controllers, 0o644)) return false;
    _ = linux.mkdir(root, 0o755);
    _ = linux.mkdir(root ++ "/main", 0o755);
    const owned = [_][:0]const u8{
        root,
        root ++ "/main",
        root ++ "/cgroup.procs",
        root ++ "/cgroup.subtree_control",
        root ++ "/cgroup.threads",
        root ++ "/main/cgroup.procs",
    };
    for (owned) |path| {
        if (failed(linux.chown(path, setup.uid, setup.gid))) return false;
    }
    return write_text(root ++ "/cgroup.subtree_control", controllers, 0o644);
}

/// Forks `zbx guest serve` as the user, in the leaf cgroup, and waits for it to listen.
fn start_serve(setup: *const protocol.Setup) ?i32 {
    assert(protocol.name_ok(setup.name));
    assert(setup.uid > 0);
    var pipe: [2]i32 = undefined;
    if (failed(linux.pipe2(&pipe, .{ .CLOEXEC = false }))) return null;
    const forked = linux.fork();
    if (failed(forked)) return null;
    if (forked == 0) exec_serve(setup, pipe[1]);
    assert(forked > 1); // The child, which is neither this process nor init's idle task.
    _ = linux.close(pipe[1]);
    defer _ = linux.close(pipe[0]);
    var entry = [1]linux.pollfd{.{ .fd = pipe[0], .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&entry, 1, 5000) == 0) return null;
    var byte: [1]u8 = undefined;
    const got = linux.read(pipe[0], &byte, 1);
    if (failed(got)) return null;
    if (got != 1) return null;
    return @intCast(forked);
}

fn exec_serve(setup: *const protocol.Setup, ready_fd: i32) noreturn {
    assert(ready_fd >= 0);
    assert(setup.uid > 0);
    var pid_text: [16:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&pid_text, "{d}", .{linux.getpid()}) catch unreachable; // A pid is short.
    const procs = constants.vm_cgroup_root ++ "/main/cgroup.procs";
    _ = write_text(procs, std.mem.sliceTo(&pid_text, 0), 0o644);
    const groups = [_]u32{setup.gid};
    _ = linux.setgroups(1, &groups);
    if (failed(linux.setgid(setup.gid)) or failed(linux.setuid(setup.uid))) linux.exit_group(126);
    var descriptor: [16:0]u8 = @splat(0);
    // Cannot fail: a descriptor number is a few digits.
    _ = std.fmt.bufPrint(&descriptor, "{d}", .{ready_fd}) catch unreachable;
    var home: [constants.vm_home_bytes_max + 8:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&home, "HOME={s}", .{setup.home}) catch linux.exit_group(126);
    var user: [constants.vm_user_name_bytes_max + 8:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&user, "USER={s}", .{setup.name}) catch linux.exit_group(126);
    const argv = [_:null]?[*:0]const u8{ "zbx", "guest", "serve", "--ready-fd", &descriptor };
    const envp = [_:null]?[*:0]const u8{ "PATH=/usr/bin:/bin", &home, &user };
    _ = linux.execve("/usr/bin/zbx", &argv, &envp);
    linux.exit_group(127);
}

// ---- Counting what the user runs --------------------------------------------------------------

/// The processes owned by the user or by an id of the range its containers map to, not counting
/// the guest's service. The host stops the machine when this has been zero for the idle time.
fn count_user_processes() u32 {
    if (!world.done) return 0;
    const opened = linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (failed(opened)) return 0;
    const handle: i32 = @intCast(opened);
    defer _ = linux.close(handle);
    var count: u32 = 0;
    while (true) {
        const bytes = linux.getdents64(handle, &directory_buffer, directory_buffer.len);
        if (failed(bytes) or bytes == 0) return count;
        var at: usize = 0;
        while (at < bytes) {
            const reclen = std.mem.readInt(u16, directory_buffer[at + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(directory_buffer[at + 19 .. at + reclen], 0);
            at += reclen;
            const pid = std.fmt.parseInt(i32, name, 10) catch continue;
            if (pid == world.serve_pid) continue;
            if (is_port_agent(name)) continue;
            if (owned_by_user(name)) count += 1;
        }
    }
}

/// The guest's port agent and the connections it carries: not the user's work, and a published
/// port alone does not keep the machine up (the container behind it does).
fn is_port_agent(pid_name: []const u8) bool {
    assert(pid_name.len > 0);
    var path: [32:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&path, "/proc/{s}/comm", .{pid_name}) catch return false;
    const opened = linux.open(&path, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(opened)) return false;
    const handle: i32 = @intCast(opened);
    defer _ = linux.close(handle);
    var comm: [16]u8 = undefined;
    const got = linux.read(handle, &comm, comm.len);
    if (failed(got)) return false;
    assert(got <= comm.len);
    return std.mem.startsWith(u8, comm[0..got], ports_agent.process_name);
}

fn owned_by_user(pid_name: []const u8) bool {
    assert(pid_name.len > 0);
    var path: [32:0]u8 = @splat(0);
    _ = std.fmt.bufPrint(&path, "/proc/{s}", .{pid_name}) catch return false;
    var info: linux.Statx = undefined;
    if (failed(linux.statx(linux.AT.FDCWD, &path, 0, .{ .UID = true }, &info))) return false;
    if (info.uid == world.uid) return true;
    const range_end = constants.vm_subid_start + constants.vm_subid_count;
    return info.uid >= constants.vm_subid_start and info.uid < range_end;
}

// ---- Network -------------------------------------------------------------------------------

const Ifreq = extern struct {
    name: [16]u8,
    data: [24]u8,
};

const siocgifflags: u32 = 0x8913;
const siocsifflags: u32 = 0x8914;
const siocsifaddr: u32 = 0x8916;
const siocsifnetmask: u32 = 0x891c;
const siocaddrt: u32 = 0x890b;
const iff_up: u16 = 1;
const interface_name = "eth0";

const Route = extern struct {
    pad1: u64 = 0,
    destination: [16]u8 = @splat(0),
    gateway: [16]u8 = @splat(0),
    mask: [16]u8 = @splat(0),
    flags: u16 = 0,
    pad2: i16 = 0,
    pad3: u64 = 0,
    pad4: u64 = 0,
    metric: i16 = 0,
    device: u64 = 0,
    mtu: u64 = 0,
    window: u64 = 0,
    irtt: u16 = 0,
};

fn ifreq_for(name: []const u8) Ifreq {
    assert(name.len > 0);
    assert(name.len < 16);
    var request: Ifreq = .{ .name = @splat(0), .data = @splat(0) };
    @memcpy(request.name[0..name.len], name);
    return request;
}

fn sockaddr_in(bytes: dhcp.Address) [16]u8 {
    var result: [16]u8 = @splat(0);
    std.mem.writeInt(u16, result[0..2], 2, .little); // AF_INET
    @memcpy(result[4..8], &bytes);
    return result;
}

fn set_up(control: i32, name: []const u8) bool {
    assert(control >= 0);
    assert(name.len > 0);
    var request = ifreq_for(name);
    if (failed(linux.ioctl(control, siocgifflags, @intFromPtr(&request)))) return false;
    const flags = std.mem.readInt(u16, request.data[0..2], .little) | iff_up;
    std.mem.writeInt(u16, request.data[0..2], flags, .little);
    return !failed(linux.ioctl(control, siocsifflags, @intFromPtr(&request)));
}

/// Loopback up, then DHCP on the first virtio NIC. True if the machine has an address, a route
/// and a resolver when this returns.
fn bring_up_network(mac_dns: []const u8) bool {
    assert(mac_dns.len > 0);
    const opened = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (failed(opened)) return false;
    const control: i32 = @intCast(opened);
    defer _ = linux.close(control);
    _ = set_up(control, "lo");
    if (!set_up(control, interface_name)) {
        log("zbx-init: no network interface ", interface_name);
        return false;
    }
    const lease = ask_for_lease() orelse {
        log("zbx-init: no DHCP answer", "");
        return false;
    };
    return configure(control, &lease, mac_dns);
}

fn configure(control: i32, lease: *const dhcp.Lease, mac_dns: []const u8) bool {
    assert(control >= 0);
    assert(mac_dns.len > 0);
    var note: [32]u8 = undefined;
    const a = lease.address;
    const quad = "{d}.{d}.{d}.{d}";
    const summary = std.fmt.bufPrint(&note, quad, .{ a[0], a[1], a[2], a[3] }) catch "";
    log("zbx-init: address ", summary);
    var request = ifreq_for(interface_name);
    request.data[0..16].* = sockaddr_in(lease.address);
    if (failed(linux.ioctl(control, siocsifaddr, @intFromPtr(&request)))) return false;
    request.data[0..16].* = sockaddr_in(lease.mask);
    if (failed(linux.ioctl(control, siocsifnetmask, @intFromPtr(&request)))) return false;
    if (lease.router) |router| {
        var route: Route = .{ .flags = 0x0003 }; // RTF_UP | RTF_GATEWAY
        route.gateway = sockaddr_in(router);
        route.destination = sockaddr_in(.{ 0, 0, 0, 0 });
        route.mask = sockaddr_in(.{ 0, 0, 0, 0 });
        _ = linux.ioctl(control, siocaddrt, @intFromPtr(&route));
    }
    write_resolv_conf(lease, mac_dns);
    return true;
}

/// The Mac's resolvers first, then the one the DHCP server named; with none from the Mac, the
/// DHCP one and then the public fallback (see `protocol.resolv_conf`). The NAT's gateway does not
/// always answer DNS, and the Mac's resolvers are reachable through the NAT.
fn write_resolv_conf(lease: *const dhcp.Lease, mac_dns: []const u8) void {
    assert(mac_dns.len > 0);
    var text: [protocol.resolv_conf_bytes_max]u8 = undefined;
    const content = protocol.resolv_conf(&text, mac_dns, lease.dns orelse lease.router);
    assert(content.len > 0); // The fallback is always there.
    _ = write_text("/etc/resolv.conf", content, 0o644);
}

fn read_mac() ?[6]u8 {
    const address_path = "/sys/class/net/" ++ interface_name ++ "/address";
    const opened = linux.open(address_path, .{ .ACCMODE = .RDONLY }, 0);
    if (failed(opened)) return null;
    const descriptor: i32 = @intCast(opened);
    defer _ = linux.close(descriptor);
    var text: [32]u8 = undefined;
    const count = linux.read(descriptor, &text, text.len);
    if (failed(count) or count < 17) return null;
    var mac: [6]u8 = undefined;
    for (&mac, 0..) |*byte, index| {
        byte.* = std.fmt.parseInt(u8, text[index * 3 ..][0..2], 16) catch return null;
    }
    return mac;
}

fn udp_socket() ?i32 {
    const opened = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (failed(opened)) return null;
    const handle: i32 = @intCast(opened);
    assert(handle >= 0);
    const one = std.mem.toBytes(@as(i32, 1));
    _ = linux.setsockopt(handle, linux.SOL.SOCKET, linux.SO.BROADCAST, &one, one.len);
    _ = linux.setsockopt(handle, linux.SOL.SOCKET, linux.SO.REUSEADDR, &one, one.len);
    const device = interface_name;
    _ = linux.setsockopt(handle, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, device.ptr, device.len);
    const client: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, 68), .addr = 0 };
    if (failed(linux.bind(handle, @ptrCast(&client), @sizeOf(linux.sockaddr.in)))) {
        _ = linux.close(handle);
        return null;
    }
    return handle;
}

fn send_broadcast(handle: i32, packet: []const u8) void {
    assert(handle >= 0);
    assert(packet.len >= 300);
    const port = std.mem.nativeToBig(u16, 67);
    const server: linux.sockaddr.in = .{ .port = port, .addr = 0xffff_ffff };
    const size = @sizeOf(linux.sockaddr.in);
    _ = linux.sendto(handle, packet.ptr, packet.len, 0, @ptrCast(&server), size);
}

/// Waits up to `vm_dhcp_wait_ms` for a reply of `wanted` kind to this client.
fn wait_for(handle: i32, mac: [6]u8, transaction: u32, wanted: dhcp.MessageType) ?dhcp.Lease {
    assert(handle >= 0);
    var packet: [constants.vm_dhcp_packet_bytes_max]u8 = undefined;
    var entry = [1]linux.pollfd{.{ .fd = handle, .events = linux.POLL.IN, .revents = 0 }};
    var waited: u32 = 0;
    while (waited < constants.vm_dhcp_wait_ms) : (waited += 100) {
        entry[0].revents = 0;
        _ = linux.poll(&entry, 1, 100);
        if (entry[0].revents == 0) continue;
        const count = linux.recvfrom(handle, &packet, packet.len, 0, null, null);
        if (failed(count)) continue;
        const lease = dhcp.parse_reply(packet[0..count], mac, transaction) orelse continue;
        if (lease.kind == wanted) return lease;
    }
    return null;
}

fn ask_for_lease() ?dhcp.Lease {
    const mac = read_mac() orelse return null;
    const handle = udp_socket() orelse return null;
    defer _ = linux.close(handle);
    var packet: [constants.vm_dhcp_packet_bytes_max]u8 = undefined;
    var transaction: u32 = std.mem.readInt(u32, mac[2..6], .little) | 1;
    var tries: u32 = 0;
    while (tries < constants.vm_dhcp_tries_max) : (tries += 1) {
        transaction +%= 1;
        send_broadcast(handle, dhcp.render_discover(&packet, mac, transaction));
        const offer = wait_for(handle, mac, transaction, .offer) orelse continue;
        assert(offer.kind == .offer);
        const request = dhcp.render_request(&packet, mac, transaction, offer.address, offer.server);
        send_broadcast(handle, request);
        const ack = wait_for(handle, mac, transaction, .ack) orelse continue;
        assert(ack.kind == .ack);
        assert(tries < constants.vm_dhcp_tries_max);
        return ack;
    }
    return null;
}
