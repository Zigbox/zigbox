//! The server against a real kernel: a child process makes a user and mount namespace, mounts
//! `/dev/fuse` there (`host_real_fuse.mount`, as the setup child does), and sends the descriptor
//! to this process over a channel; this process answers `INIT` and serves on its threads, and
//! the child reads the tree through the mount and checks every byte. Skipped where `/dev/fuse`
//! cannot be opened or a namespace cannot be made (a container without them).

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;
const constants = @import("../constants.zig");
const xattrs = @import("../store/xattrs.zig");
const host_real = @import("../host_real.zig");
const host_real_fuse = @import("../host_real_fuse.zig");
const abi = @import("abi.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");
const cache_mod = @import("cache.zig");
const serve = @import("serve.zig");
const fixture_mod = @import("fixture.zig");

var kernel_fixture: fixture_mod.Fixture = undefined;
const chunk_bytes = 64 * 1024;
const file_bytes = fixture_mod.content_bytes - 1000; // 48 chunks, the last one short.
/// The child's exit status when this host cannot run the test.
const status_skip = 77;
/// The child gives up (SIGALRM) after this long, so a hung mount fails the test, never hangs it.
const child_seconds = 60;
/// The child's direct read: 1 MiB at 512 KiB, which the kernel sends as one `READ` of that size
/// at that offset, spanning chunks.
const direct_offset = 512 * 1024;
const direct_bytes = 1024 * 1024;
/// A small pread at an offset aligned to nothing: one 4 KiB `READ` there.
const small_offset = 12345;
const small_bytes = 4096;
var direct_buffer: [direct_bytes]u8 align(4096) = undefined;
var sequential_buffer: [256 * 1024]u8 = undefined;

test "a real kernel mount serves a tree: reads through it match, byte for byte" {
    const fixture = &kernel_fixture;
    fixture.init(chunk_bytes);
    const content = try testing.allocator.alloc(u8, file_bytes);
    defer testing.allocator.free(content);
    for (content, 0..) |*byte, index| byte.* = @truncate(index *% 13 +% index / 997);
    _ = fixture.begin();
    _ = try fixture.file("a", content, 0o644, &xattrs.empty);
    _ = try fixture.symlink("l", "a");
    const root = try fixture.finish_root(
        .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty },
    );
    const held = try fixture_mod.table_memory(testing.allocator, 8, 4096);
    defer testing.allocator.free(held.region);
    var table: nodes.Table = undefined;
    table.init(held.memory);
    try table.build(fixture.source(), root);

    var target_buffer: [64]u8 = undefined;
    const pid = linux.getpid();
    const target = try std.mem.printSentinel(&target_buffer, "/tmp/zbx-fuse-test-{d}", .{pid}, 0);
    _ = linux.mkdir(target, 0o700);
    defer _ = linux.rmdir(target);

    var real: host_real.HostReal = .{};
    const host = real.interface();
    const channel = try host.channel();
    const forked = linux.fork();
    assert(linux.errno(forked) == .SUCCESS);
    if (forked == 0) {
        host.close(channel.read);
        linux.exit_group(child(channel.write, target, content));
    }
    host.close(channel.write);
    const received = host.receive_handle(channel.read);
    host.close(channel.read);
    const fd: linux.fd_t = @intCast(received catch {
        try testing.expectEqual(@as(u32, status_skip), reap(@intCast(forked)));
        return error.SkipZigTest;
    });
    defer _ = linux.close(fd);

    const cache_bytes: usize = @intCast(cache_mod.memory_bytes(chunk_bytes));
    const cache_memory = try testing.allocator.alloc(u8, cache_bytes);
    defer testing.allocator.free(cache_memory);
    var cache: cache_mod.Cache = undefined;
    cache.init(testing.io, cache_memory, chunk_bytes);
    const server: ops.Server = .{ .table = &table, .cache = &cache, .chunk_bytes = chunk_bytes };
    const memory = try testing.allocator.alignedAlloc(
        u8,
        .@"8",
        @as(usize, constants.lazy_fuse_threads) * serve.thread_memory_bytes,
    );
    defer testing.allocator.free(memory);
    var serving = serve.Serving.init(&server, host_real_fuse.device(&fd), fixture.chunks(), memory);
    try serving.handshake();
    try serving.start();
    const status = reap(@intCast(forked));
    // The child's namespace is gone with it, and with it the mount: the connection ends.
    serving.wait();
    try testing.expectEqual(@as(u32, 0), status);
}

/// Waits for the child: its exit status, or 128 plus its signal.
fn reap(pid: linux.pid_t) u32 {
    var raw: i32 = 0;
    while (true) {
        const got = linux.wait4(pid, &raw, 0, null);
        if (linux.errno(got) == .INTR) continue;
        assert(linux.errno(got) == .SUCCESS);
        break;
    }
    const status: u32 = @bitCast(raw);
    if (linux.W.IFEXITED(status)) return linux.W.EXITSTATUS(status);
    return 128 + @as(u32, @backingInt(linux.W.TERMSIG(status)));
}

/// The child: namespaces, the mount, the handoff, then the reads. Its exit status says what
/// failed: 0 none, `status_skip` the host cannot run it, else the step's number.
fn child(channel: u32, target: [:0]const u8, content: []const u8) u8 {
    const timer: linux.itimerspec = .{
        .it_interval = .{ .sec = 0, .nsec = 0 },
        .it_value = .{ .sec = child_seconds, .nsec = 0 },
    };
    _ = linux.setitimer(@backingInt(linux.ITIMER.REAL), &timer, null);
    const uid = linux.getuid();
    const gid = linux.getgid();
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS)) != .SUCCESS) {
        return status_skip;
    }
    var line: [32]u8 = undefined;
    if (!write_file("/proc/self/setgroups", "deny")) return status_skip;
    const uid_map = std.fmt.bufPrint(&line, "0 {d} 1", .{uid}) catch unreachable; // 32 bytes.
    if (!write_file("/proc/self/uid_map", uid_map)) return status_skip;
    const gid_map = std.fmt.bufPrint(&line, "0 {d} 1", .{gid}) catch unreachable; // 32 bytes.
    if (!write_file("/proc/self/gid_map", gid_map)) return status_skip;
    const private: u32 = linux.MS.REC | linux.MS.PRIVATE;
    if (linux.errno(linux.mount(null, "/", null, private, 0)) != .SUCCESS) return status_skip;
    const fd = host_real_fuse.open_device() catch return status_skip;
    if (host_real_fuse.mount(fd, target) != .SUCCESS) return status_skip;
    var real: host_real.HostReal = .{};
    real.interface().send_handle(channel, @intCast(fd)) catch return 2;
    _ = linux.close(fd);
    var path: [96]u8 = undefined;
    const file = std.mem.printSentinel(&path, "{s}/a", .{target}, 0) catch unreachable; // 96 bytes.
    const buffered: linux.O = .{ .ACCMODE = .RDONLY };
    const buffer = &direct_buffer;
    if (!pread_matches(file, buffered, buffer, small_offset, small_bytes, content)) return 6;
    const direct: linux.O = .{ .ACCMODE = .RDONLY, .DIRECT = true };
    if (!pread_matches(file, direct, buffer, direct_offset, direct_bytes, content)) return 7;
    if (!read_matches(file, content)) return 3;
    const link = std.mem.printSentinel(&path, "{s}/l", .{target}, 0) catch unreachable; // 96 bytes.
    if (!read_matches(link, content)) return 4;
    // 96 bytes hold the target and the name.
    const missing = std.mem.printSentinel(&path, "{s}/nope", .{target}, 0) catch unreachable;
    const opened = linux.open(missing, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(opened) != .NOENT) return 5;
    return 0;
}

fn write_file(path: [:0]const u8, text: []const u8) bool {
    const opened = linux.open(path, .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    return linux.write(fd, text.ptr, text.len) == text.len;
}

/// One pread of `length` bytes at `offset` into `buffer`, opened with `flags`; compares.
fn pread_matches(
    path: [:0]const u8,
    flags: linux.O,
    buffer: []u8,
    offset: u32,
    length: u32,
    expected: []const u8,
) bool {
    assert(length <= buffer.len);
    assert(offset + length <= expected.len);
    const opened = linux.open(path, flags, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    const got = linux.pread(fd, buffer.ptr, length, offset);
    if (linux.errno(got) != .SUCCESS) return false;
    if (got != length) return false;
    return std.mem.eql(u8, buffer[0..length], expected[offset..][0..length]);
}

/// Reads `path` front to back in 256 KiB reads after posix_fadvise(SEQUENTIAL), as a reader
/// that asks for the kernel's larger readahead would, and compares.
fn read_matches(path: [:0]const u8, expected: []const u8) bool {
    const opened = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    const advised = linux.fadvise(fd, 0, 0, linux.POSIX_FADV.SEQUENTIAL);
    if (linux.errno(advised) != .SUCCESS) return false;
    const buffer = &sequential_buffer;
    var at: usize = 0;
    while (true) {
        const got = linux.read(fd, buffer, buffer.len);
        if (linux.errno(got) != .SUCCESS) return false;
        if (got == 0) break;
        if (at + got > expected.len) return false;
        if (!std.mem.eql(u8, buffer[0..got], expected[at..][0..got])) return false;
        at += got;
    }
    return at == expected.len;
}

comptime {
    assert(file_bytes > 47 * chunk_bytes);
    assert(file_bytes > direct_offset + direct_bytes);
    assert(file_bytes <= fixture_mod.content_bytes);
    assert(@sizeOf(abi.InHeader) == 40);
}
