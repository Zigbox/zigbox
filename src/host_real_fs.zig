//! The production file system for the store (`store/fs.zig`): raw Linux syscalls through
//! `std.os.linux`, no libc. Like `host_real.zig`, whose errno and `check` it shares, this is a
//! place that may name syscalls. It is its own file because it is a second, larger vtable.
//!
//! The store runs its calls inside the user's user namespace (`store/namespace.zig`), so every
//! id here is the container's view of it; nothing in this file knows about the mapping.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");
const host = @import("host.zig");
const host_real = @import("host_real.zig");
const fs = @import("store/fs.zig");

const HostReal = host_real.HostReal;
const check = HostReal.check;

pub fn interface(context: *HostReal) fs.Fs {
    assert(context.open_count < 1 << 20);
    assert(@intFromPtr(&vtable) != 0);
    return .{ .context = context, .vtable = &vtable };
}

const vtable: fs.VTable = .{
    .lstat = lstat,
    .read_dir = read_dir,
    .read_link = read_link,
    .list_xattrs = list_xattrs,
    .get_xattr = get_xattr,
    .open_read = open_read,
    .read = read,
    .read_at = read_at,
    .create = create,
    .open_append = open_append,
    .write = write,
    .fsync = fsync,
    .close = close,
    .set_owner = set_owner,
    .set_mode = set_mode,
    .set_xattr = set_xattr,
    .set_mtime = set_mtime,
    .rename = rename,
    .unlink = unlink,
    .make_directory = make_directory,
    .remove_directory = remove_directory,
    .sync_directory = sync_directory,
    .link = link,
    .symlink = symlink,
    .set_path_attributes = set_path_attributes,
    .set_path_xattr = set_path_xattr,
    .lock = lock,
    .last_errno = last_errno,
    .open_directory = open_directory,
    .open_beneath = open_beneath,
    .fstat = fstat,
    .read_dir_fd = read_dir_fd,
    .read_link_fd = read_link_fd,
};

fn from_context(context: *anyopaque) *HostReal {
    assert(@intFromPtr(context) != 0);
    assert(@alignOf(HostReal) <= 8);
    return @ptrCast(@alignCast(context));
}

fn last_errno(context: *anyopaque) u16 {
    assert(@intFromPtr(context) != 0);
    assert(host_real.errno_last < 4096);
    _ = from_context(context);
    return host_real.errno_last;
}

fn kind_of(mode: u32) fs.FileKind {
    assert(mode <= 0o177777);
    assert(linux.S.IFMT == 0o170000);
    return switch (mode & linux.S.IFMT) {
        linux.S.IFREG => .file,
        linux.S.IFDIR => .dir,
        linux.S.IFLNK => .symlink,
        linux.S.IFCHR => .char_device,
        linux.S.IFBLK => .block_device,
        linux.S.IFIFO => .fifo,
        else => .socket,
    };
}

fn lstat(context: *anyopaque, path: [:0]const u8) host.Error!fs.Stat {
    _ = from_context(context);
    assert(path.len > 0);
    return stat_at(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW);
}

fn fstat(context: *anyopaque, fd: fs.Fd) host.Error!fs.Stat {
    const self = from_context(context);
    assert(self.open_count > 0);
    return stat_at(@intCast(fd), "", linux.AT.SYMLINK_NOFOLLOW | linux.AT.EMPTY_PATH);
}

fn stat_at(dir: i32, path: [:0]const u8, flags: u32) host.Error!fs.Stat {
    assert(flags & linux.AT.SYMLINK_NOFOLLOW != 0);
    if (path.len == 0) assert(flags & linux.AT.EMPTY_PATH != 0);
    const mask: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
        .INO = true,
        .SIZE = true,
        .MTIME = true,
        .CTIME = true,
        .BLOCKS = true,
    };
    var buffer: linux.Statx = undefined;
    try check(linux.statx(dir, path.ptr, flags, mask, &buffer));
    // The kernel must honour the mask for these fields; a clear bit would mean garbage.
    assert(buffer.mask.TYPE);
    assert(buffer.mask.MODE);
    assert(buffer.mask.SIZE);
    return .{
        .kind = kind_of(buffer.mode),
        .mode = @intCast(buffer.mode & 0o7777),
        .uid = buffer.uid,
        .gid = buffer.gid,
        .size = buffer.size,
        .inode = buffer.ino,
        .links = buffer.nlink,
        .rdev_major = buffer.rdev_major,
        .rdev_minor = buffer.rdev_minor,
        .mtime = if (buffer.mask.MTIME and buffer.mtime.sec > 0) @intCast(buffer.mtime.sec) else 0,
        .ctime_ns = ctime_ns_of(&buffer),
        .blocks = if (buffer.mask.BLOCKS) buffer.blocks else 0,
    };
}

/// The inode change time in nanoseconds, or zero when the kernel did not give it.
fn ctime_ns_of(buffer: *const linux.Statx) u64 {
    if (!buffer.mask.CTIME or buffer.ctime.sec <= 0) return 0;
    assert(buffer.ctime.nsec < 1_000_000_000);
    const seconds: u64 = @intCast(buffer.ctime.sec);
    return seconds *% 1_000_000_000 +% buffer.ctime.nsec;
}

fn read_dir(context: *anyopaque, path: [:0]const u8, visitor: fs.Visitor) host.Error!void {
    const self = from_context(context);
    assert(path.len > 0);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const opened = linux.open(path.ptr, flags, 0);
    try check(opened);
    self.open_count += 1;
    const descriptor: i32 = @intCast(opened);
    defer {
        _ = linux.close(descriptor);
        self.open_count -= 1;
    }
    return list_entries(descriptor, visitor);
}

fn read_dir_fd(context: *anyopaque, fd: fs.Fd, visitor: fs.Visitor) host.Error!void {
    const self = from_context(context);
    assert(self.open_count > 0);
    // A directory descriptor is read once, from its start: the importer opens one per listing.
    return list_entries(@intCast(fd), visitor);
}

fn list_entries(descriptor: i32, visitor: fs.Visitor) host.Error!void {
    assert(descriptor >= 0);
    assert(@intFromPtr(visitor.call) != 0);
    var buffer: [32 * 1024]u8 align(8) = undefined;
    // Every call that does not end the listing returns at least one entry, and a directory
    // holds at most as many entries as the store accepts plus what the caller refuses to read:
    // the bound is generous and exists so that the loop cannot be endless.
    for (0..constants.store_walk_entries_max) |_| {
        const count = linux.getdents64(descriptor, &buffer, buffer.len);
        try check(count);
        if (count == 0) return;
        var at: usize = 0;
        while (at < count) {
            // linux_dirent64: ino u64, off i64, reclen u16, type u8, then the NUL-terminated name.
            const reclen = std.mem.readInt(u16, buffer[at + 16 ..][0..2], .little);
            assert(reclen >= 19);
            assert(at + reclen <= count);
            const name = std.mem.sliceTo(buffer[at + 19 .. at + reclen], 0);
            const dots = std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..");
            if (!dots and name.len > 0) visitor.call(visitor.context, name);
            at += reclen;
        }
    }
    return error.Stalled;
}

fn read_link(context: *anyopaque, path: [:0]const u8, buffer: []u8) host.Error!u32 {
    _ = from_context(context);
    assert(path.len > 0);
    assert(buffer.len > 0);
    const result = linux.readlink(path.ptr, buffer.ptr, buffer.len);
    try check(result);
    // A target that fills the buffer may have been cut: say so rather than store a wrong one.
    if (result == buffer.len) return error.FileTooLarge;
    return @intCast(result);
}

fn read_link_fd(context: *anyopaque, fd: fs.Fd, buffer: []u8) host.Error!u32 {
    const self = from_context(context);
    assert(self.open_count > 0);
    assert(buffer.len > 0);
    // An empty path reads the link the `O_PATH | O_NOFOLLOW` descriptor itself names.
    const result = linux.readlinkat(@intCast(fd), "", buffer.ptr, buffer.len);
    try check(result);
    if (result == buffer.len) return error.FileTooLarge;
    return @intCast(result);
}

fn open_directory(context: *anyopaque, path: [:0]const u8) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const result = linux.open(path.ptr, flags, 0);
    try check(result);
    assert(result <= std.math.maxInt(i32));
    self.open_count += 1;
    return @intCast(result);
}

/// `struct open_how` (openat2(2)); std.os.linux has no wrapper for the call.
const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
const resolve_no_magiclinks: u64 = 0x02;
const resolve_beneath: u64 = 0x08;

fn open_beneath(
    context: *anyopaque,
    dir: fs.Fd,
    path: [:0]const u8,
    how: fs.Beneath,
) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    assert(path[0] != '/');
    const flags: linux.O = switch (how) {
        .path_follow => .{ .PATH = true, .CLOEXEC = true },
        .path_entry => .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true },
        .read => .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
        .directory => .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
    };
    const open_how: OpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .mode = 0,
        .resolve = resolve_beneath | resolve_no_magiclinks,
    };
    const result = linux.syscall4(
        .openat2,
        @as(usize, @intCast(dir)),
        @intFromPtr(path.ptr),
        @intFromPtr(&open_how),
        @sizeOf(OpenHow),
    );
    try check(result);
    assert(result <= std.math.maxInt(i32));
    self.open_count += 1;
    return @intCast(result);
}

fn list_xattrs(context: *anyopaque, path: [:0]const u8, buffer: []u8) host.Error!u32 {
    _ = from_context(context);
    assert(path.len > 0);
    assert(buffer.len > 0);
    const result = linux.llistxattr(path.ptr, buffer.ptr, buffer.len);
    // A file system without attributes lists none.
    if (linux.errno(result) == .OPNOTSUPP) return 0;
    try check(result);
    assert(result <= buffer.len);
    return @intCast(result);
}

fn get_xattr(
    context: *anyopaque,
    path: [:0]const u8,
    name: [:0]const u8,
    buffer: []u8,
) host.Error!u32 {
    _ = from_context(context);
    assert(path.len > 0);
    assert(name.len > 0);
    const result = linux.lgetxattr(path.ptr, name.ptr, buffer.ptr, buffer.len);
    if (linux.errno(result) == .OPNOTSUPP) return error.NoData;
    try check(result);
    assert(result <= buffer.len);
    return @intCast(result);
}

fn open_read(context: *anyopaque, path: [:0]const u8) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true };
    const result = linux.open(path.ptr, flags, 0);
    try check(result);
    assert(result <= std.math.maxInt(i32));
    self.open_count += 1;
    return @intCast(result);
}

fn read(context: *anyopaque, fd: fs.Fd, buffer: []u8) host.Error!u32 {
    const self = from_context(context);
    assert(self.open_count > 0);
    assert(buffer.len > 0);
    const result = linux.read(@intCast(fd), buffer.ptr, buffer.len);
    try check(result);
    assert(result <= buffer.len);
    return @intCast(result);
}

fn read_at(context: *anyopaque, fd: fs.Fd, offset: u64, buffer: []u8) host.Error!u32 {
    const self = from_context(context);
    assert(self.open_count > 0);
    assert(buffer.len > 0);
    const result = linux.pread(@intCast(fd), buffer.ptr, buffer.len, @intCast(offset));
    try check(result);
    assert(result <= buffer.len);
    return @intCast(result);
}

fn open_append(context: *anyopaque, path: [:0]const u8) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const result = linux.open(path.ptr, flags, 0);
    try check(result);
    assert(result <= std.math.maxInt(i32));
    self.open_count += 1;
    return @intCast(result);
}

fn create(context: *anyopaque, path: [:0]const u8, mode: u16) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    assert(mode <= 0o7777);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const result = linux.open(path.ptr, flags, mode);
    try check(result);
    assert(result <= std.math.maxInt(i32));
    self.open_count += 1;
    return @intCast(result);
}

fn lock(
    context: *anyopaque,
    path: [:0]const u8,
    exclusive: bool,
    holder: []const u8,
) host.Error!fs.Fd {
    const self = from_context(context);
    assert(path.len > 0);
    assert(holder.len <= constants.store_lock_holder_bytes);
    const flags: linux.O = .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true };
    const opened = linux.open(path.ptr, flags, 0o600);
    try check(opened);
    assert(opened <= std.math.maxInt(i32));
    self.open_count += 1;
    const descriptor: i32 = @intCast(opened);
    // flock(2): LOCK_SH 1, LOCK_EX 2, LOCK_NB 4.
    const operation: i32 = (if (exclusive) @as(i32, 2) else @as(i32, 1)) | 4;
    check(linux.flock(descriptor, operation)) catch |err| {
        const errno = host_real.errno_last;
        close(context, @intCast(descriptor));
        host_real.errno_last = errno;
        return err;
    };
    if (exclusive) {
        var record: [constants.store_lock_holder_bytes]u8 = @splat(0);
        @memcpy(record[0..holder.len], holder);
        check(linux.pwrite(descriptor, &record, record.len, 0)) catch |err| {
            const errno = host_real.errno_last;
            close(context, @intCast(descriptor));
            host_real.errno_last = errno;
            return err;
        };
    }
    return @intCast(descriptor);
}

fn write(context: *anyopaque, fd: fs.Fd, bytes: []const u8) host.Error!u32 {
    const self = from_context(context);
    assert(self.open_count > 0);
    assert(bytes.len > 0);
    const result = linux.write(@intCast(fd), bytes.ptr, bytes.len);
    try check(result);
    assert(result <= bytes.len);
    return @intCast(result);
}

fn fsync(context: *anyopaque, fd: fs.Fd) host.Error!void {
    assert(fd < std.math.maxInt(i32));
    const self = from_context(context);
    assert(self.open_count > 0);
    try check(linux.fsync(@intCast(fd)));
}

fn close(context: *anyopaque, fd: fs.Fd) void {
    assert(fd < std.math.maxInt(i32));
    const self = from_context(context);
    assert(self.open_count > 0);
    self.open_count -= 1;
    // A close error on a descriptor that was fsynced loses nothing and cannot be acted on.
    _ = linux.close(@intCast(fd));
}

fn set_owner(context: *anyopaque, fd: fs.Fd, uid: u32, gid: u32) host.Error!void {
    assert(uid != std.math.maxInt(u32));
    assert(fd < std.math.maxInt(i32));
    _ = from_context(context);
    try check(linux.fchown(@intCast(fd), uid, gid));
}

fn set_mode(context: *anyopaque, fd: fs.Fd, mode: u16) host.Error!void {
    assert(fd < std.math.maxInt(i32));
    _ = from_context(context);
    assert(mode <= 0o7777);
    try check(linux.fchmod(@intCast(fd), mode));
}

fn set_xattr(
    context: *anyopaque,
    fd: fs.Fd,
    name: [:0]const u8,
    value: []const u8,
) host.Error!void {
    assert(value.len <= constants.store_xattr_value_bytes_max);
    _ = from_context(context);
    assert(name.len > 0);
    try check(linux.fsetxattr(@intCast(fd), name.ptr, value.ptr, value.len, 0));
}

fn set_mtime(context: *anyopaque, fd: fs.Fd, seconds: u64) host.Error!void {
    assert(fd < std.math.maxInt(i32));
    _ = from_context(context);
    assert(seconds < 1 << 40);
    const stamp: linux.timespec = .{ .sec = @intCast(seconds), .nsec = 0 };
    const times = [2]linux.timespec{ stamp, stamp };
    try check(linux.futimens(@intCast(fd), &times));
}

fn rename(context: *anyopaque, from: [:0]const u8, to: [:0]const u8) host.Error!void {
    _ = from_context(context);
    assert(from.len > 0);
    assert(to.len > 0);
    try check(linux.rename(from.ptr, to.ptr));
}

fn unlink(context: *anyopaque, path: [:0]const u8) host.Error!void {
    assert(path.len <= constants.path_bytes_max);
    _ = from_context(context);
    assert(path.len > 0);
    try check(linux.unlink(path.ptr));
}

fn make_directory(context: *anyopaque, path: [:0]const u8, exist_ok: bool) host.Error!void {
    assert(path.len <= constants.path_bytes_max);
    _ = from_context(context);
    assert(path.len > 0);
    const result = linux.mkdir(path.ptr, 0o755);
    if (exist_ok and linux.errno(result) == .EXIST) {
        host_real.errno_last = 0;
        return;
    }
    try check(result);
}

fn remove_directory(context: *anyopaque, path: [:0]const u8) host.Error!void {
    assert(path.len <= constants.path_bytes_max);
    _ = from_context(context);
    assert(path.len > 0);
    try check(linux.rmdir(path.ptr));
}

fn link(context: *anyopaque, from: [:0]const u8, to: [:0]const u8) host.Error!void {
    _ = from_context(context);
    assert(from.len > 0);
    assert(to.len > 0);
    try check(linux.link(from.ptr, to.ptr));
}

fn symlink(context: *anyopaque, target: [:0]const u8, path: [:0]const u8) host.Error!void {
    _ = from_context(context);
    assert(target.len > 0);
    assert(path.len > 0);
    try check(linux.symlink(target.ptr, path.ptr));
}

fn set_path_attributes(
    context: *anyopaque,
    path: [:0]const u8,
    attributes: fs.PathAttributes,
) host.Error!void {
    _ = from_context(context);
    assert(path.len > 0);
    assert(attributes.mtime < 1 << 40);
    if (attributes.set_owner) try check(linux.lchown(path.ptr, attributes.uid, attributes.gid));
    // A change of owner clears the setuid and setgid bits, so the mode is set after it.
    if (attributes.mode) |mode| {
        assert(mode <= 0o7777);
        try check(linux.chmod(path.ptr, mode));
    }
    const stamp: linux.timespec = .{ .sec = @intCast(attributes.mtime), .nsec = 0 };
    const times = [2]linux.timespec{ stamp, stamp };
    try check(linux.utimensat(linux.AT.FDCWD, path.ptr, &times, linux.AT.SYMLINK_NOFOLLOW));
}

fn set_path_xattr(
    context: *anyopaque,
    path: [:0]const u8,
    name: [:0]const u8,
    value: []const u8,
) host.Error!void {
    _ = from_context(context);
    assert(path.len > 0);
    assert(name.len > 0);
    assert(value.len <= constants.store_xattr_value_bytes_max);
    try check(linux.lsetxattr(path.ptr, name.ptr, value.ptr, value.len, 0));
}

fn sync_directory(context: *anyopaque, path: [:0]const u8) host.Error!void {
    assert(path.len <= constants.path_bytes_max);
    const self = from_context(context);
    assert(path.len > 0);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const opened = linux.open(path.ptr, flags, 0);
    try check(opened);
    self.open_count += 1;
    const descriptor: i32 = @intCast(opened);
    const result = check(linux.fsync(descriptor));
    _ = linux.close(descriptor);
    self.open_count -= 1;
    try result;
}

test "real kernel: open_beneath stays below the directory and reads links as links" {
    // Goal: the openat2 flags are right. Method: in a directory in /tmp, a file, a link to it,
    // a link out by `..` and one by an absolute path; open each beneath the directory.
    const testing = std.testing;
    var real: HostReal = .{};
    const files = interface(&real);
    var storage: [64]u8 = undefined;
    const written = try std.fmt.bufPrint(&storage, "/tmp/zbx-beneath-{d}", .{linux.getpid()});
    storage[written.len] = 0;
    const directory: [:0]const u8 = storage[0..written.len :0];
    try files.make_directory(directory, true);
    const names = [_][:0]const u8{ "file", "in", "up", "abs" };
    defer {
        for (names) |name| {
            var path: [96:0]u8 = @splat(0);
            const text = std.fmt.bufPrint(&path, "{s}/{s}", .{ directory, name }) catch "";
            if (text.len > 0) files.unlink(path[0..text.len :0]) catch {};
        }
        files.remove_directory(directory) catch {};
    }
    var path: [96:0]u8 = @splat(0);
    const file_path = try std.fmt.bufPrint(&path, "{s}/file", .{directory});
    const fd = try files.create(path[0..file_path.len :0], 0o644);
    try files.write_all(fd, "hello");
    files.close(fd);
    const targets = [_][:0]const u8{ "file", "../etc", "/etc" };
    for (names[1..], targets) |name, target| {
        const link_path = try std.fmt.bufPrint(&path, "{s}/{s}", .{ directory, name });
        path[link_path.len] = 0;
        try files.symlink(target, path[0..link_path.len :0]);
    }
    const dir = try files.open_directory(directory);
    defer files.close(dir);
    const entry = try files.open_beneath(dir, "in", .path_entry);
    try testing.expectEqual(fs.FileKind.symlink, (try files.fstat(entry)).kind);
    var target: [64]u8 = undefined;
    try testing.expectEqualStrings("file", try files.read_link_fd(entry, &target));
    files.close(entry);
    const followed = try files.open_beneath(dir, "in", .read);
    try testing.expectEqual(@as(u64, 5), (try files.fstat(followed)).size);
    files.close(followed);
    for ([_][:0]const u8{ "up", "abs" }) |name| {
        try testing.expectError(error.IoFailed, files.open_beneath(dir, name, .path_follow));
        try testing.expectEqual(@as(u16, 18), files.last_errno()); // EXDEV
    }
    try testing.expectEqual(@as(u32, 1), real.open_count);
}
