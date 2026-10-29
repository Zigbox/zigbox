//! The macOS host's small system layer: files, directories, locks, Unix sockets and the clock,
//! through libSystem. It reports a failure as `error.Failed` with the errno kept in `last_errno`
//! for `reason`, which turns it into words; nothing here knows about diagnostics.
//!
//! Descriptors are `i32`. Every read and wait is bounded by a timeout or a size.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const constants = @import("../constants.zig");

pub const Error = error{ Failed, Timeout, TooLong };

extern "c" fn flock(descriptor: i32, operation: i32) i32;

var errno_value: c.E = .SUCCESS;

fn fail() Error {
    assert(@sizeOf(c.E) > 0);
    errno_value = @fromBackingInt(@intCast(c._errno().*));
    return error.Failed;
}

/// The errno of the last `Failed`, in words a person can act on.
pub fn reason() []const u8 {
    assert(@tagName(errno_value).len > 0);
    return switch (errno_value) {
        .NOENT => "no such file or directory",
        .ACCES, .PERM => "permission denied",
        .NOSPC => "no space left on device",
        .ROFS => "read-only file system",
        .NAMETOOLONG => "path too long",
        .EXIST => "already exists",
        .NOTDIR => "not a directory",
        .CONNREFUSED => "connection refused",
        .NOTCONN => "not connected",
        .PIPE => "connection closed",
        else => @tagName(errno_value),
    };
}

/// `text` copied into `buffer` with a terminating NUL, for a call that takes a C string.
pub fn terminate(
    buffer: *[constants.vm_path_bytes_max:0]u8,
    text: []const u8,
) error{TooLong}![:0]const u8 {
    assert(text.len <= buffer.len);
    if (text.len >= buffer.len) return error.TooLong;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

fn terminate_suffixed(
    buffer: *[constants.vm_path_bytes_max:0]u8,
    text: []const u8,
    suffix: []const u8,
) error{TooLong}![:0]const u8 {
    assert(suffix.len > 0);
    if (text.len + suffix.len >= buffer.len) return error.TooLong;
    @memcpy(buffer[0..text.len], text);
    @memcpy(buffer[text.len..][0..suffix.len], suffix);
    buffer[text.len + suffix.len] = 0;
    return buffer[0 .. text.len + suffix.len :0];
}

pub fn now_ms() u64 {
    assert(@sizeOf(c.timespec) > 0);
    var spec: c.timespec = undefined;
    const result = c.clock_gettime(.MONOTONIC, &spec);
    assert(result == 0);
    assert(spec.sec >= 0);
    const seconds: u64 = @intCast(spec.sec);
    const nanoseconds: u64 = @intCast(spec.nsec);
    return seconds * 1000 + @divFloor(nanoseconds, 1_000_000);
}

pub fn sleep_ms(milliseconds: u32) void {
    assert(milliseconds <= 1000);
    assert(milliseconds > 0);
    assert(milliseconds <= 1000);
    var request: c.timespec = .{ .sec = 0, .nsec = @as(isize, milliseconds) * 1_000_000 };
    _ = c.nanosleep(&request, null);
}

pub fn close(descriptor: i32) void {
    assert(descriptor >= 0);
    _ = c.close(descriptor);
}

/// `path` and every parent directory, mode 0700 (the VM's files are the user's alone).
pub fn make_directories(path: []const u8) Error!void {
    assert(path.len < constants.vm_path_bytes_max);
    assert(path.len > 0);
    assert(path[0] == '/');
    var buffer: [constants.vm_path_bytes_max:0]u8 = undefined;
    if (path.len >= buffer.len) return error.TooLong;
    var end: usize = 1;
    while (end <= path.len) : (end += 1) {
        if (end < path.len and path[end] != '/') continue;
        @memcpy(buffer[0..end], path[0..end]);
        buffer[end] = 0;
        const result = c.mkdir(@ptrCast(&buffer), 0o700);
        if (result != 0 and c.errno(result) != .EXIST) return fail();
    }
}

pub fn exists(path: [:0]const u8) bool {
    assert(path.len > 0);
    var status: c.Stat = undefined;
    return c.stat(path.ptr, &status) == 0;
}

/// Writes `bytes` to `path` through a temporary file in the same directory and a rename, so a
/// reader sees the old file or the whole new one.
pub fn write_file_atomically(path: []const u8, bytes: []const u8, mode: u32) Error!void {
    assert(path.len > 0);
    assert(mode <= 0o777);
    var final: [constants.vm_path_bytes_max:0]u8 = undefined;
    var partial: [constants.vm_path_bytes_max:0]u8 = undefined;
    const partial_text = terminate_suffixed(&partial, path, ".part") catch return error.TooLong;
    const final_text = terminate(&final, path) catch return error.TooLong;
    const flags: c.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
    const descriptor = c.open(partial_text.ptr, flags, @as(c.mode_t, @intCast(mode)));
    if (descriptor < 0) return fail();
    defer close(descriptor);
    try write_all(descriptor, bytes);
    if (c.fsync(descriptor) != 0) return fail();
    if (c.rename(partial_text.ptr, final_text.ptr) != 0) return fail();
}

pub fn write_all(descriptor: i32, bytes: []const u8) Error!void {
    assert(bytes.len < 1 << 30);
    assert(descriptor >= 0);
    var done: usize = 0;
    while (done < bytes.len) {
        const count = c.write(descriptor, bytes[done..].ptr, bytes.len - done);
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return fail();
        }
        done += @intCast(count);
    }
    assert(done == bytes.len);
}

/// The whole file into `buffer`; `error.TooLong` if it does not fit with room to spare (the
/// read must reach the end of the file, so the buffer is at least one byte bigger than it).
pub fn read_file(path: []const u8, buffer: []u8) Error![]u8 {
    assert(path.len > 0);
    assert(buffer.len > 0);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return error.TooLong;
    const descriptor = c.open(text.ptr, .{ .ACCMODE = .RDONLY });
    if (descriptor < 0) return fail();
    defer close(descriptor);
    var length: usize = 0;
    while (true) {
        if (length == buffer.len) return error.TooLong;
        const count = c.read(descriptor, buffer[length..].ptr, buffer.len - length);
        if (count < 0) return fail();
        if (count == 0) return buffer[0..length];
        length += @intCast(count);
    }
}

/// Opens (making it if needed) and locks `path` exclusively without waiting. Null if another
/// process holds the lock. The lock lasts as long as the descriptor, and the kernel drops it when
/// the process dies, by any means: a lock file left behind by a killed host is not stale.
pub fn lock_exclusive(path: []const u8) Error!?i32 {
    assert(path[0] == '/');
    assert(path.len > 0);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return error.TooLong;
    const flags: c.O = .{ .ACCMODE = .RDWR, .CREAT = true };
    const descriptor = c.open(text.ptr, flags, @as(c.mode_t, 0o600));
    if (descriptor < 0) return fail();
    const lock_exclusive_nonblocking = c.LOCK.EX | c.LOCK.NB;
    if (flock(descriptor, lock_exclusive_nonblocking) == 0) return descriptor;
    const held = c.errno(@as(c_int, -1)) == .AGAIN;
    if (!held) {
        const failure = fail();
        close(descriptor);
        return failure;
    }
    close(descriptor);
    return null;
}

pub fn socket_address(path: []const u8) Error!c.sockaddr.un {
    assert(path.len > 0);
    if (path.len > constants.vm_socket_path_bytes_max) return error.TooLong;
    var address: c.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..path.len], path);
    return address;
}

/// A listening Unix socket at `path`, made fresh: a file left by a dead host is removed first.
pub fn listen_unix(path: []const u8) Error!i32 {
    assert(path[0] == '/');
    assert(path.len > 0);
    const address = try socket_address(path);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return error.TooLong;
    _ = c.unlink(text.ptr);
    const descriptor = c.socket(c.AF.UNIX, c.SOCK.STREAM, 0);
    if (descriptor < 0) return fail();
    const bound = c.bind(descriptor, @ptrCast(&address), @sizeOf(c.sockaddr.un));
    if (bound != 0 or c.listen(descriptor, 8) != 0) {
        const failure = fail();
        close(descriptor);
        return failure;
    }
    return descriptor;
}

pub fn connect_unix(path: []const u8) Error!i32 {
    assert(path[0] == '/');
    assert(path.len > 0);
    const address = try socket_address(path);
    const descriptor = c.socket(c.AF.UNIX, c.SOCK.STREAM, 0);
    if (descriptor < 0) return fail();
    if (c.connect(descriptor, @ptrCast(&address), @sizeOf(c.sockaddr.un)) != 0) {
        const failure = fail();
        close(descriptor);
        return failure;
    }
    return descriptor;
}

/// True if `descriptor` is readable within `timeout_ms`.
pub fn wait_readable(descriptor: i32, timeout_ms: u32) Error!bool {
    assert(descriptor >= 0);
    assert(timeout_ms <= constants.vm_boot_timeout_ms);
    assert(descriptor >= 0);
    var entry: [1]c.pollfd = .{.{ .fd = descriptor, .events = c.POLL.IN, .revents = 0 }};
    const count = c.poll(&entry, 1, @intCast(timeout_ms));
    if (count < 0) {
        if (c.errno(count) == .INTR) return false;
        return fail();
    }
    return count > 0;
}

/// One line, newline included, within `timeout_ms` in all. `error.Timeout` if the peer says
/// nothing in time, `error.TooLong` if no newline comes within the buffer.
pub fn read_line(descriptor: i32, buffer: []u8, timeout_ms: u32) Error![]u8 {
    assert(descriptor >= 0);
    assert(timeout_ms > 0);
    assert(buffer.len > 1);
    const deadline = now_ms() + timeout_ms;
    var length: usize = 0;
    while (length < buffer.len) {
        const now = now_ms();
        if (now >= deadline) return error.Timeout;
        const step: u32 = @intCast(@min(deadline - now, constants.vm_control_timeout_ms));
        if (!try wait_readable(descriptor, step)) continue;
        const count = c.read(descriptor, buffer[length..].ptr, 1);
        if (count < 0) return fail();
        if (count == 0) return error.Failed;
        length += 1;
        if (buffer[length - 1] == '\n') return buffer[0..length];
    }
    return error.TooLong;
}

pub fn host_cpus() u32 {
    assert(@sizeOf(i32) == 4);
    var count: i32 = 0;
    var size: usize = @sizeOf(i32);
    const result = c.sysctlbyname("hw.ncpu", &count, &size, null, 0);
    if (result != 0 or count < 1) return 1;
    return @intCast(count);
}

/// The head of macOS's `struct statfs` (64-bit inodes, the default), then room for the rest of
/// it (two path buffers of 1024 bytes and reserved words): 2168 bytes in all.
const Statfs = extern struct {
    bsize: u32,
    iosize: i32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    rest: [2168 - 48]u8,
};

extern "c" fn statfs(path: [*:0]const u8, buffer: *Statfs) c_int;

/// What an ordinary user may still write on the volume that holds `path`; 0 if it cannot be told.
pub fn free_bytes(path: []const u8) u64 {
    assert(@sizeOf(Statfs) == 2168);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return 0;
    var buffer: Statfs = undefined;
    if (statfs(text.ptr, &buffer) != 0) return 0;
    return buffer.bavail * buffer.bsize;
}

/// The size in bytes of the file at `path`; 0 when there is none.
pub fn file_size(path: []const u8) u64 {
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return 0;
    var status: c.Stat = undefined;
    if (c.stat(text.ptr, &status) != 0) return 0;
    assert(status.size >= 0);
    return @intCast(status.size);
}

/// Makes the file at `path` exist and be at least `bytes` long, sparse: the blocks are not
/// allocated until the guest writes them. A longer file is left as it is.
pub fn ensure_sparse_file(path: []const u8, bytes: u64) Error!void {
    assert(bytes > 0);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = terminate(&terminated, path) catch return error.TooLong;
    const flags: c.O = .{ .ACCMODE = .RDWR, .CREAT = true };
    const descriptor = c.open(text.ptr, flags, @as(c.mode_t, 0o600));
    if (descriptor < 0) return fail();
    defer close(descriptor);
    var status: c.Stat = undefined;
    if (c.fstat(descriptor, &status) != 0) return fail();
    assert(status.size >= 0);
    if (@as(u64, @intCast(status.size)) >= bytes) return;
    if (c.ftruncate(descriptor, @intCast(bytes)) != 0) return fail();
}

pub fn host_memory_bytes() u64 {
    assert(@sizeOf(u64) == 8);
    var bytes: u64 = 0;
    var size: usize = @sizeOf(u64);
    const result = c.sysctlbyname("hw.memsize", &bytes, &size, null, 0);
    if (result != 0 or bytes == 0) return constants.vm_memory_bytes_default;
    return bytes;
}

test "a sparse file is made, grown and never shortened" {
    // Goal: the disk file takes no room until written and is never cut. Method: a file in the
    // system temp directory, made, grown, then asked for less.
    var name: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&name, "/tmp/zbx-sparse-test-{d}", .{now_ms()});
    try std.testing.expectEqual(@as(u64, 0), file_size(path));
    try ensure_sparse_file(path, 1 << 30);
    try std.testing.expectEqual(@as(u64, 1 << 30), file_size(path));
    try ensure_sparse_file(path, 2 << 30);
    try std.testing.expectEqual(@as(u64, 2 << 30), file_size(path));
    try ensure_sparse_file(path, 1 << 30);
    try std.testing.expectEqual(@as(u64, 2 << 30), file_size(path));
    try std.testing.expect(free_bytes("/tmp") > 0);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    _ = c.unlink((try terminate(&terminated, path)).ptr);
}

test "make_directories makes a chain and is the same twice" {
    // Goal: mkdir -p. Method: a chain under a unique directory in the system temp directory.
    var name: [96]u8 = undefined;
    const base = try std.fmt.bufPrint(&name, "/tmp/zbx-files-test-{d}/a/b", .{now_ms()});
    try make_directories(base);
    try make_directories(base);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = try terminate(&terminated, base);
    try std.testing.expect(exists(text));
}

test "a lock is exclusive and a file written atomically reads back" {
    // Goal: the two promises the host relies on. Method: lock a file twice (the second gets
    // null, not an error), write a file and read it, and read a file bigger than the buffer.
    var base: [96]u8 = undefined;
    const directory = try std.fmt.bufPrint(&base, "/tmp/zbx-lock-test-{d}", .{now_ms()});
    try make_directories(directory);
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/lock", .{directory});
    const first = (try lock_exclusive(path)).?;
    try std.testing.expect((try lock_exclusive(path)) == null);
    close(first);
    const again = (try lock_exclusive(path)).?;
    close(again);
    const file = try std.fmt.bufPrint(&path_buffer, "{s}/file", .{directory});
    try write_file_atomically(file, "twelve bytes", 0o600);
    var buffer: [13]u8 = @splat(0xaa); // One more than the file: the read must see its end.
    try std.testing.expectEqualStrings("twelve bytes", try read_file(file, &buffer));
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.TooLong, read_file(file, &small));
    try std.testing.expectError(error.Failed, read_file("/nonexistent/zbx", &small));
    try std.testing.expectEqualStrings("no such file or directory", reason());
}

test "a socket path at the limit works and one past it is refused" {
    // Goal: the sun_path bound. Method: addresses of 103 and 104 bytes.
    const repeat = @import("../test_util.zig").repeat;
    const at_limit = "/" ++ repeat('a', constants.vm_socket_path_bytes_max - 1);
    _ = try socket_address(at_limit);
    try std.testing.expectError(error.TooLong, socket_address(at_limit ++ "a"));
}

// ---- Passing descriptors over a Unix socket ----------------------------------------------------

const Iovec = extern struct { base: ?*anyopaque, length: usize };
const MessageHeader = extern struct {
    name: ?*anyopaque = null,
    name_length: u32 = 0,
    vectors: ?*Iovec,
    vector_count: i32,
    control: ?*anyopaque,
    control_length: u32,
    flags: i32 = 0,
};
const ControlHeader = extern struct { length: u32, level: i32, kind: i32 };
const socket_level: i32 = 0xffff;
const rights_kind: i32 = 1;
/// The most descriptors one message carries here.
pub const descriptors_max: u32 = 2;
const control_header_bytes: u32 = 12;

extern "c" fn sendmsg(socket: i32, message: *const MessageHeader, flags: i32) isize;
extern "c" fn recvmsg(socket: i32, message: *MessageHeader, flags: i32) isize;

/// A control message: its header and up to two descriptors.
const Control = extern struct {
    header: ControlHeader,
    descriptors: [descriptors_max]i32,
};

fn control_length(count: u32) u32 {
    assert(count >= 1);
    assert(count <= descriptors_max);
    return control_header_bytes + count * @sizeOf(i32);
}

/// Sends `bytes` and, with them, open descriptors (one or two). The receiver gets its own copies.
pub fn send_with_descriptors(socket: i32, bytes: []const u8, descriptors: []const i32) Error!void {
    assert(socket >= 0);
    assert(bytes.len > 0);
    assert(descriptors.len >= 1);
    assert(descriptors.len <= descriptors_max);
    var vector: Iovec = .{ .base = @constCast(bytes.ptr), .length = bytes.len };
    const length = control_length(@intCast(descriptors.len));
    var control: Control = .{
        .header = .{ .length = length, .level = socket_level, .kind = rights_kind },
        .descriptors = @splat(-1),
    };
    for (descriptors, 0..) |descriptor, index| {
        assert(descriptor >= 0);
        control.descriptors[index] = descriptor;
    }
    const message: MessageHeader = .{
        .vectors = &vector,
        .vector_count = 1,
        .control = &control,
        .control_length = length,
    };
    if (sendmsg(socket, &message, 0) < 0) return fail();
}

pub const Received = struct {
    length: u32,
    descriptors: [descriptors_max]i32,
    descriptor_count: u32,
};

/// Reads what the peer sent in one message, and the descriptors that came with it.
pub fn receive_with_descriptors(socket: i32, buffer: []u8) Error!Received {
    assert(socket >= 0);
    assert(buffer.len > 0);
    var vector: Iovec = .{ .base = buffer.ptr, .length = buffer.len };
    var control: Control = undefined;
    var message: MessageHeader = .{
        .vectors = &vector,
        .vector_count = 1,
        .control = &control,
        .control_length = control_length(descriptors_max),
    };
    const count = recvmsg(socket, &message, 0);
    if (count < 0) return fail();
    var result: Received = .{
        .length = @intCast(count),
        .descriptors = @splat(-1),
        .descriptor_count = 0,
    };
    const has_control = message.control_length >= control_header_bytes and
        control.header.level == socket_level and control.header.kind == rights_kind;
    if (!has_control) return result;
    const present = (control.header.length - control_header_bytes) / @sizeOf(i32);
    result.descriptor_count = @min(present, descriptors_max);
    for (0..result.descriptor_count) |index| result.descriptors[index] = control.descriptors[index];
    return result;
}

test "descriptors passed over a Unix socket are working copies" {
    // Goal: the hand-off the client relies on. Method: a socket pair; send a pipe's read end and a
    // second pipe's write end with a line; use both received descriptors; and a message without
    // descriptors says so.
    var pair: [2]i32 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &pair));
    defer close(pair[0]);
    defer close(pair[1]);
    var first: [2]i32 = undefined;
    var second: [2]i32 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.pipe(&first));
    try std.testing.expectEqual(@as(c_int, 0), c.pipe(&second));
    defer close(first[1]);
    defer close(second[0]);
    try send_with_descriptors(pair[0], "ok\n", &.{ first[0], second[1] });
    close(first[0]);
    close(second[1]);
    var line: [16]u8 = undefined;
    const received = try receive_with_descriptors(pair[1], &line);
    try std.testing.expectEqualStrings("ok\n", line[0..received.length]);
    try std.testing.expectEqual(@as(u32, 2), received.descriptor_count);
    const reader = received.descriptors[0];
    const writer = received.descriptors[1];
    defer close(reader);
    try write_all(first[1], "data");
    var data: [8]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 4), c.read(reader, &data, data.len));
    try std.testing.expectEqualStrings("data", data[0..4]);
    // The writer received is a working end of the second pipe: when it closes, the read end
    // sees the end of file (the peer's death, as the host watches it).
    try write_all(writer, "x");
    close(writer);
    try std.testing.expectEqual(@as(isize, 1), c.read(second[0], &data, data.len));
    try std.testing.expectEqual(@as(isize, 0), c.read(second[0], &data, data.len));
    try write_all(pair[0], "no\n");
    const plain = try receive_with_descriptors(pair[1], &line);
    try std.testing.expectEqual(@as(u32, 0), plain.descriptor_count);
    try std.testing.expectEqual(@as(i32, -1), plain.descriptors[0]);
}
