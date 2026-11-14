//! The server against a real kernel: a child process makes a user and mount namespace, mounts
//! `/dev/fuse` there (`host_real_fuse.mount`, as the setup child does), and sends the descriptor
//! to this process over a channel; this process answers `INIT` and serves on its threads, and
//! the child reads the tree through the mount and checks every byte, the attributes, the
//! listing, the extended attributes and the error of a chunk that cannot be read. Skipped where
//! `/dev/fuse` cannot be opened or a namespace cannot be made (a container without them). The VM
//! demo `demo-s2-lazy` runs it as root in the guest, where it must pass, not skip.

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
const Digest = @import("../store/digest.zig").Digest;

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
/// "b" carries one user xattr and one `user.overlay.*` one, which the server never shows.
const b_section = "\x02" ++ "\x06\x00user.a" ++ "\x03\x00one" ++
    "\x13\x00user.overlay.opaque" ++ "\x01\x00y";
const b_content = "the file with attributes\n";
/// "c"'s one chunk cannot be read (`fixture.failing`): a read of it gets EIO.
const c_content = "the file whose chunk is lost\n";
/// Every name the root lists, "." and ".." included.
const root_names = [_][]const u8{ ".", "..", "a", "b", "c", "l" };
var direct_buffer: [direct_bytes]u8 align(4096) = undefined;
var sequential_buffer: [256 * 1024]u8 = undefined;

test "a real kernel mount serves a tree: reads, attributes, listing, xattrs and EIO" {
    // Goal: the server answers a real kernel the way the unit tests say it answers the fake
    // device. Method: a mount in a child's namespaces, served here; the child reads a 48-chunk
    // file buffered, direct and sequentially, follows a link, stats, lists the root, reads the
    // xattrs and reads a file whose chunk fails, and exits with the number of the failed step.
    const fixture = &kernel_fixture;
    fixture.init(chunk_bytes);
    const content = try testing.allocator.alloc(u8, file_bytes);
    defer testing.allocator.free(content);
    for (content, 0..) |*byte, index| byte.* = @truncate(index *% 13 +% index / 997);
    const root = try fill(fixture, content);
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
    // The fixture's chunks are safe from every thread: one source in every slot.
    const chunks: [constants.lazy_fuse_threads]ops.Chunks = @splat(fixture.chunks());
    const device = try host_real_fuse.device(&fd);
    var serving = serve.Serving.init(&server, device, &chunks, memory);
    try serving.handshake();
    try serving.start();
    const status = reap(@intCast(forked));
    // The child's namespace is gone with it, and with it the mount: the connection ends.
    serving.wait();
    try testing.expectEqual(@as(u32, 0), status);
}

/// The root: "a" (`content`), "b" (xattrs), "c" (its chunk lost: `fixture.failing`), "l" -> a.
fn fill(fixture: *fixture_mod.Fixture, content: []const u8) !Digest {
    assert(content.len == file_bytes);
    _ = fixture.begin();
    _ = try fixture.file("a", content, 0o644, &xattrs.empty);
    _ = try fixture.file("b", b_content, 0o600, b_section);
    const lost = try fixture.file("c", c_content, 0o644, &xattrs.empty);
    _ = try fixture.symlink("l", "a");
    fixture.failing = lost;
    assert(fixture.failing != null);
    return fixture.finish_root(.{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty });
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
    return metadata(target);
}

/// The steps after the reads: attributes (8), the listing (9), xattrs (10, 11), EIO (12).
fn metadata(target: [:0]const u8) u8 {
    assert(target.len > 0);
    assert(target.len < 64);
    var path: [96]u8 = undefined;
    const a = std.mem.printSentinel(&path, "{s}/a", .{target}, 0) catch unreachable; // 96 bytes.
    if (!attributes_match(a)) return 8;
    if (!listing_matches(target)) return 9;
    var other: [96]u8 = undefined;
    const b = std.mem.printSentinel(&other, "{s}/b", .{target}, 0) catch unreachable; // 96 bytes.
    if (!xattrs_match(b)) return 10;
    var names: [64]u8 = undefined;
    if (linux.listxattr(a, &names, names.len) != 0) return 11;
    const c = std.mem.printSentinel(&path, "{s}/c", .{target}, 0) catch unreachable; // 96 bytes.
    if (!read_fails(c)) return 12;
    return 0;
}

/// "a": a regular file of mode 0644, `file_bytes` long, one link, owned by root.
fn attributes_match(path: [:0]const u8) bool {
    assert(path.len > 0);
    var got: linux.Statx = undefined;
    var mask: linux.STATX = .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true };
    mask.GID = true;
    mask.SIZE = true;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, mask, &got)) != .SUCCESS) return false;
    assert(got.mask.TYPE);
    if (got.mode != linux.S.IFREG | 0o644) return false;
    if (got.size != file_bytes) return false;
    if (got.nlink != 1) return false;
    return got.uid == 0 and got.gid == 0;
}

/// The root lists exactly `root_names`, each once.
fn listing_matches(target: [:0]const u8) bool {
    const opened = linux.open(target, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    var buffer: [4096]u8 align(8) = undefined;
    var seen: [root_names.len]bool = @splat(false);
    var count: u32 = 0;
    while (true) {
        const got = linux.getdents64(fd, &buffer, buffer.len);
        if (linux.errno(got) != .SUCCESS) return false;
        if (got == 0) break;
        assert(got <= buffer.len);
        var at: usize = 0;
        while (at < got) {
            const length = std.mem.readInt(u16, buffer[at + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(buffer[at + 19 ..], 0);
            at += length;
            count += 1;
            const index = for (root_names, 0..) |known, index| {
                if (std.mem.eql(u8, known, name)) break index;
            } else return false;
            if (seen[index]) return false;
            seen[index] = true;
        }
    }
    return count == root_names.len;
}

/// "b": `user.a` is "one", the list names only it, and the overlay xattr is not there.
fn xattrs_match(path: [:0]const u8) bool {
    assert(path.len > 0);
    var value: [16]u8 = undefined;
    const got = linux.getxattr(path, "user.a", &value, value.len);
    if (linux.errno(got) != .SUCCESS) return false;
    if (!std.mem.eql(u8, value[0..got], "one")) return false;
    const hidden = linux.getxattr(path, "user.overlay.opaque", &value, value.len);
    if (linux.errno(hidden) != .NODATA) return false;
    var names: [64]u8 = undefined;
    const listed = linux.listxattr(path, &names, names.len);
    if (linux.errno(listed) != .SUCCESS) return false;
    assert(listed <= names.len);
    return std.mem.eql(u8, names[0..listed], "user.a\x00");
}

/// A read of `path` (its one chunk lost) fails with EIO and returns no data.
fn read_fails(path: [:0]const u8) bool {
    assert(path.len > 0);
    const opened = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(opened) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    var buffer: [64]u8 = undefined;
    const got = linux.read(fd, &buffer, buffer.len);
    return linux.errno(got) == .IO;
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
    assert(file_bytes + b_content.len + c_content.len <= fixture_mod.content_bytes);
    assert(@sizeOf(abi.InHeader) == 40);
}
