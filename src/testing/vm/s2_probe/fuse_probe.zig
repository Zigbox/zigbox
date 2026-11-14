//! S2 slice 1's probe: a throwaway read-only FUSE server in Zig, with no libc, that answers
//! INIT, LOOKUP, GETATTR, OPEN, READ and READDIRPLUS from a fixed tree in memory, and EIO for
//! the one file that cannot be read. `demo-s2-probe` runs it in the test VM to find out whether
//! Ubuntu 24.04's kernel serves a rootless FUSE mount under a `userxattr` overlay (the brief,
//! decision 1). It is not `zbx`'s server: slice 4 writes that, with bounds and a fuzzer.
//!
//!   fuse_probe mount <dir>   open /dev/fuse, mount it on <dir>, fork the server, and return once
//!                            the server has answered FUSE_INIT; prints the server's pid.
//!   fuse_probe read <file>   read <file> in 1 MiB reads, check every byte against the pattern,
//!                            and print the first read's latency and the mean per MiB.

const std = @import("std");
const abi = @import("fuse_abi.zig");
const linux = std.os.linux;
const assert = std.debug.assert;

const mib: u32 = 1024 * 1024;
/// One READ reply holds at most this much data: 256 pages, the `max_pages` the probe asks for.
const read_bytes_max: u32 = mib;
/// The kernel's requests are small for a read-only server; the buffer must be at least 8 KiB.
const request_bytes_max: usize = 64 * 1024;
/// The probe serves no writes, but the kernel refuses a read of /dev/fuse into a buffer smaller
/// than a WRITE request of `max_write` bytes would be (its header and `fuse_write_in`, 40 each).
const write_bytes_max: u32 = 16 * 1024;
const reply_bytes_max: usize = @sizeOf(abi.OutHeader) + read_bytes_max;
/// The kernel caches entries and attributes this long: the tree never changes.
const valid_s: u64 = 3600;
const big_size_bytes: u64 = 16 * mib;

comptime {
    assert(read_bytes_max % std.heap.page_size_min == 0);
    assert(request_bytes_max >= 8192);
    assert(request_bytes_max >= @sizeOf(abi.InHeader) + 40 + write_bytes_max);
    assert(big_size_bytes % read_bytes_max == 0);
}

const Kind = enum { directory, file };

const Node = struct {
    parent: u64,
    name: []const u8,
    kind: Kind,
    size: u64,
    /// Every READ of this node fails with EIO: the probe's stand-in for a chunk that no source
    /// could deliver.
    broken: bool = false,
};

const hello_text = "hello from the zig fuse probe\n";
const nested_text = "nested file, read only after the server is gone\n";

/// The tree. A node's id is its index plus one; the root is id 1, as FUSE requires.
const nodes = [_]Node{
    .{ .parent = 1, .name = "/", .kind = .directory, .size = 0 },
    .{ .parent = 1, .name = "hello.txt", .kind = .file, .size = hello_text.len },
    .{ .parent = 1, .name = "big.bin", .kind = .file, .size = big_size_bytes },
    .{ .parent = 1, .name = "broken.bin", .kind = .file, .size = 4096, .broken = true },
    .{ .parent = 1, .name = "sub", .kind = .directory, .size = 0 },
    .{ .parent = 5, .name = "nested.txt", .kind = .file, .size = nested_text.len },
    .{ .parent = 1, .name = "other.bin", .kind = .file, .size = 4 * mib },
};

var request_buffer: [request_bytes_max]u8 align(8) = undefined;
var reply_buffer: [reply_bytes_max]u8 align(8) = undefined;

pub fn main(init: std.process.Init.Minimal) u8 {
    var args = init.args.iterate();
    _ = args.next();
    const command = args.next() orelse return usage();
    const path = args.next() orelse return usage();
    if (args.next() != null) return usage();
    if (std.mem.eql(u8, command, "mount")) return mount_and_serve(path);
    if (std.mem.eql(u8, command, "read")) return read_file(path);
    return usage();
}

fn usage() u8 {
    say("usage: fuse_probe mount <dir> | fuse_probe read <file>\n", .{});
    return 2;
}

/// Writes one line to stderr; the probe's only output besides `mount`'s pid line.
fn say(comptime format: []const u8, arguments: anytype) void {
    var buffer: [512]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, format, arguments) catch return;
    assert(text.len <= buffer.len);
    _ = linux.write(2, text.ptr, text.len);
}

/// The byte at `offset` of `big.bin`: position-dependent, so a page at the wrong offset shows.
fn pattern_byte(offset: u64) u8 {
    const mixed = (offset >> 12) *% 31 +% offset *% 7;
    return @truncate(mixed);
}

fn node_of(id: u64) ?*const Node {
    if (id == 0) return null;
    if (id > nodes.len) return null;
    const node = &nodes[@intCast(id - 1)];
    assert(node.parent >= 1);
    return node;
}

fn mount_and_serve(path: [:0]const u8) u8 {
    const opened = linux.open("/dev/fuse", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) {
        say("fuse_probe: refused: cannot open /dev/fuse ({t})\n", .{linux.errno(opened)});
        return 1;
    }
    const fd: linux.fd_t = @intCast(opened);
    var data_buffer: [160]u8 = undefined;
    const options = "fd={d},rootmode=40000,user_id={d},group_id={d},allow_other," ++
        "default_permissions";
    const ids = .{ fd, linux.getuid(), linux.getgid() };
    // 160 bytes hold the fixed text and three numbers of at most ten digits each.
    const data = std.mem.printSentinel(&data_buffer, options, ids, 0) catch unreachable;
    const flags: u32 = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV;
    const mounted = linux.mount("zbxprobe", path, "fuse", flags, @intFromPtr(data.ptr));
    if (linux.errno(mounted) != .SUCCESS) {
        say("fuse_probe: refused: mount fuse on {s} ({t})\n", .{ path, linux.errno(mounted) });
        return 1;
    }
    say("fuse_probe: mounted fuse on {s} with {s}\n", .{ path, data });
    var pipe: [2]linux.fd_t = undefined;
    assert(linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) == .SUCCESS);
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) {
        say("fuse_probe: refused: fork ({t})\n", .{linux.errno(forked)});
        return 1;
    }
    if (forked == 0) {
        _ = linux.close(pipe[0]);
        _ = linux.close(0);
        _ = linux.close(1);
        _ = linux.setsid();
        serve(fd, pipe[1]);
        linux.exit_group(0);
    }
    _ = linux.close(pipe[1]);
    var byte: [1]u8 = undefined;
    const got = linux.read(pipe[0], &byte, 1);
    if (got != 1) {
        say("fuse_probe: refused: the server ended without accepting FUSE_INIT\n", .{});
        return 1;
    }
    var line: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "fuse_probe: server pid {d}\n", .{forked}) catch
        unreachable; // 64 bytes hold the text and a pid.
    _ = linux.write(1, text.ptr, text.len);
    return 0;
}

/// The serving loop: one request at a time until the kernel ends the connection (`ENODEV`).
/// `ready` gets one byte once FUSE_INIT is accepted, and is closed then. A refused FUSE_INIT ends
/// the server, which closes `ready` without a byte, so `mount` reports the refusal.
fn serve(fd: linux.fd_t, ready: linux.fd_t) void {
    var ready_open = true;
    var requests: u64 = 0;
    defer flush_read_log();
    while (true) {
        const got = linux.read(fd, &request_buffer, request_buffer.len);
        switch (linux.errno(got)) {
            .SUCCESS => {},
            .INTR, .AGAIN, .NOENT => continue,
            .NODEV => break,
            else => |err| {
                say("fuse_probe: server: read /dev/fuse ({t})\n", .{err});
                break;
            },
        }
        requests += 1;
        const request = request_buffer[0..got];
        if (ready_open) {
            if (!accept_init(fd, request)) return;
            _ = linux.write(ready, "y", 1);
            _ = linux.close(ready);
            ready_open = false;
        } else {
            handle(fd, request);
        }
    }
    say("fuse_probe: server: connection ended after {d} requests\n", .{requests});
}

/// Answers the first request, which the kernel always makes FUSE_INIT, and returns whether the
/// server accepted it.
fn accept_init(fd: linux.fd_t, request: []const u8) bool {
    assert(request.len >= @sizeOf(abi.InHeader));
    const header = std.mem.bytesToValue(abi.InHeader, request[0..@sizeOf(abi.InHeader)]);
    assert(header.len == request.len);
    const opcode: abi.Opcode = @fromBackingInt(@intCast(header.opcode));
    if (opcode != .init) {
        say("fuse_probe: refused: the kernel's first request was {d}, not INIT\n", .{
            header.opcode,
        });
        reply_error(fd, &header, .PROTO);
        return false;
    }
    return reply_init(fd, &header, request[@sizeOf(abi.InHeader)..]);
}

/// Answers one request after FUSE_INIT.
fn handle(fd: linux.fd_t, request: []const u8) void {
    assert(request.len >= @sizeOf(abi.InHeader));
    const header = std.mem.bytesToValue(abi.InHeader, request[0..@sizeOf(abi.InHeader)]);
    assert(header.len == request.len);
    const body = request[@sizeOf(abi.InHeader)..];
    const opcode: abi.Opcode = @fromBackingInt(@intCast(header.opcode));
    switch (opcode) {
        // The connection is set up once; a second INIT is a kernel bug.
        .init => reply_error(fd, &header, .PROTO),
        .lookup => reply_lookup(fd, &header, body),
        .getattr => reply_getattr(fd, &header),
        .open, .opendir => reply_open(fd, &header, opcode),
        .read => reply_read(fd, &header, body),
        .readdirplus => reply_readdirplus(fd, &header, body),
        .statfs => reply_statfs(fd, &header),
        .getxattr => reply_error(fd, &header, .NODATA),
        .listxattr => reply_listxattr(fd, &header, body),
        .release, .releasedir, .flush => reply_bytes(fd, &header, &.{}),
        .destroy => reply_bytes(fd, &header, &.{}),
        // No reply: the kernel expects none for these.
        .forget, .batch_forget, .interrupt => {},
        .readlink => reply_error(fd, &header, .INVAL),
        else => reply_error(fd, &header, .NOSYS),
    }
}

fn reply_error(fd: linux.fd_t, header: *const abi.InHeader, err: linux.E) void {
    assert(err != .SUCCESS);
    const out: abi.OutHeader = .{
        .len = @sizeOf(abi.OutHeader),
        .@"error" = -@as(i32, @intCast(@backingInt(err))),
        .unique = header.unique,
    };
    assert(out.@"error" < 0);
    write_reply(fd, std.mem.asBytes(&out));
}

/// Sends a successful reply whose body is `body`, copied after the header.
fn reply_bytes(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) void {
    assert(body.len + @sizeOf(abi.OutHeader) <= reply_buffer.len);
    const total = @sizeOf(abi.OutHeader) + body.len;
    const out: abi.OutHeader = .{ .len = @intCast(total), .@"error" = 0, .unique = header.unique };
    @memcpy(reply_buffer[0..@sizeOf(abi.OutHeader)], std.mem.asBytes(&out));
    @memcpy(reply_buffer[@sizeOf(abi.OutHeader)..total], body);
    write_reply(fd, reply_buffer[0..total]);
}

fn write_reply(fd: linux.fd_t, bytes: []const u8) void {
    assert(bytes.len >= @sizeOf(abi.OutHeader));
    const written = linux.write(fd, bytes.ptr, bytes.len);
    switch (linux.errno(written)) {
        .SUCCESS => assert(written == bytes.len),
        // The request was interrupted and is gone; nothing waits for this reply.
        .NOENT => {},
        else => |err| say("fuse_probe: server: write reply ({t})\n", .{err}),
    }
}

/// Answers FUSE_INIT and returns whether the server accepted the kernel's protocol. A refusal is
/// one line on stderr and an EPROTO reply.
fn reply_init(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) bool {
    if (body.len < @sizeOf(abi.InitIn)) {
        say("fuse_probe: refused: INIT of {d} bytes is too short\n", .{body.len});
        reply_error(fd, header, .PROTO);
        return false;
    }
    const in = std.mem.bytesToValue(abi.InitIn, body[0..@sizeOf(abi.InitIn)]);
    say("fuse_probe: server: INIT from kernel {d}.{d}, max_readahead {d}, flags 0x{x}\n", .{
        in.major, in.minor, in.max_readahead, in.flags,
    });
    if (init_refusal(&in)) |reason| {
        say("fuse_probe: refused: kernel FUSE {d}.{d} {s}\n", .{ in.major, in.minor, reason });
        reply_error(fd, header, .PROTO);
        return false;
    }
    const wanted = abi.init_async_read | abi.init_do_readdirplus | abi.init_parallel_dirops |
        abi.init_max_pages;
    const out: abi.InitOut = .{
        .major = abi.kernel_version_major,
        .minor = abi.kernel_minor_version_min,
        .max_readahead = @min(in.max_readahead, read_bytes_max),
        .flags = in.flags & wanted,
        .max_background = 16,
        .congestion_threshold = 12,
        .max_write = write_bytes_max,
        .time_gran = 1,
        .max_pages = @intCast(read_bytes_max / std.heap.page_size_min),
        .map_alignment = 0,
        .flags2 = 0,
        .unused = @splat(0),
    };
    assert(out.flags & abi.init_max_pages != 0);
    say("fuse_probe: server: INIT answered {d}.{d}, max_pages {d}, flags 0x{x}\n", .{
        out.major, out.minor, out.max_pages, out.flags,
    });
    reply_bytes(fd, header, std.mem.asBytes(&out));
    return true;
}

/// Why the server cannot speak the kernel's protocol, or null when it can.
fn init_refusal(in: *const abi.InitIn) ?[]const u8 {
    if (in.major != abi.kernel_version_major) return "is not major version 7";
    if (in.minor < abi.kernel_minor_version_min) return "is older than 7.31";
    if (in.flags & abi.init_max_pages == 0) return "lacks max_pages";
    assert(in.minor >= abi.kernel_minor_version_min);
    return null;
}

fn attr_of(id: u64) abi.Attr {
    const node = node_of(id).?;
    const is_directory = node.kind == .directory;
    const attr: abi.Attr = .{
        .ino = id,
        .size = node.size,
        .blocks = std.math.divCeil(u64, node.size, 512) catch unreachable, // 512 is not zero.
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
        .atimensec = 0,
        .mtimensec = 0,
        .ctimensec = 0,
        .mode = if (is_directory) linux.S.IFDIR | 0o755 else linux.S.IFREG | 0o644,
        .nlink = if (is_directory) 2 + subdirectory_count(id) else 1,
        .uid = 0,
        .gid = 0,
        .rdev = 0,
        .blksize = 4096,
        .flags = 0,
    };
    assert(attr.ino == id);
    return attr;
}

/// A directory's subdirectories, each of which adds one link (its `..`) to the directory.
fn subdirectory_count(id: u64) u32 {
    assert(node_of(id).?.kind == .directory);
    var count: u32 = 0;
    for (nodes[1..]) |node| {
        if (node.parent != id) continue;
        if (node.kind == .directory) count += 1;
    }
    assert(count < nodes.len);
    return count;
}

fn entry_of(id: u64) abi.EntryOut {
    assert(node_of(id) != null);
    return .{
        .nodeid = id,
        .generation = 1,
        .entry_valid = valid_s,
        .attr_valid = valid_s,
        .entry_valid_nsec = 0,
        .attr_valid_nsec = 0,
        .attr = attr_of(id),
    };
}

fn reply_lookup(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) void {
    const parent = node_of(header.nodeid) orelse return reply_error(fd, header, .NOENT);
    if (parent.kind != .directory) return reply_error(fd, header, .NOTDIR);
    const name = std.mem.sliceTo(body, 0);
    if (name.len == body.len) return reply_error(fd, header, .INVAL);
    for (nodes[1..], 2..) |node, id| {
        if (node.parent != header.nodeid) continue;
        if (!std.mem.eql(u8, node.name, name)) continue;
        const entry = entry_of(id);
        return reply_bytes(fd, header, std.mem.asBytes(&entry));
    }
    reply_error(fd, header, .NOENT);
}

fn reply_getattr(fd: linux.fd_t, header: *const abi.InHeader) void {
    if (node_of(header.nodeid) == null) return reply_error(fd, header, .NOENT);
    const out: abi.AttrOut = .{
        .attr_valid = valid_s,
        .attr_valid_nsec = 0,
        .dummy = 0,
        .attr = attr_of(header.nodeid),
    };
    assert(out.attr.ino == header.nodeid);
    reply_bytes(fd, header, std.mem.asBytes(&out));
}

fn reply_open(fd: linux.fd_t, header: *const abi.InHeader, opcode: abi.Opcode) void {
    const node = node_of(header.nodeid) orelse return reply_error(fd, header, .NOENT);
    const wants_directory = opcode == .opendir;
    if (wants_directory != (node.kind == .directory)) {
        return reply_error(fd, header, if (wants_directory) .NOTDIR else .ISDIR);
    }
    // The tree is immutable, so the kernel's page cache (and its directory cache) stays valid.
    const directory_flags: u32 = if (wants_directory) abi.open_cache_dir else 0;
    const flags = abi.open_keep_cache | directory_flags;
    const out: abi.OpenOut = .{ .fh = header.nodeid, .open_flags = flags, .padding = 0 };
    assert(out.open_flags & abi.open_keep_cache != 0);
    reply_bytes(fd, header, std.mem.asBytes(&out));
}

fn reply_read(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) void {
    if (body.len < @sizeOf(abi.ReadIn)) return reply_error(fd, header, .INVAL);
    const in = std.mem.bytesToValue(abi.ReadIn, body[0..@sizeOf(abi.ReadIn)]);
    const node = node_of(header.nodeid) orelse return reply_error(fd, header, .NOENT);
    if (node.kind != .file) return reply_error(fd, header, .ISDIR);
    log_read(node.name, in.offset, in.size);
    if (node.broken) return reply_error(fd, header, .IO);
    const start = @min(in.offset, node.size);
    const count: usize = @intCast(@min(node.size - start, in.size, read_bytes_max));
    const data = reply_buffer[@sizeOf(abi.OutHeader)..][0..count];
    fill(node, start, data);
    const total = @sizeOf(abi.OutHeader) + count;
    const out: abi.OutHeader = .{ .len = @intCast(total), .@"error" = 0, .unique = header.unique };
    @memcpy(reply_buffer[0..@sizeOf(abi.OutHeader)], std.mem.asBytes(&out));
    write_reply(fd, reply_buffer[0..total]);
}

/// Fills `data` with the bytes of `node` from `start`.
fn fill(node: *const Node, start: u64, data: []u8) void {
    assert(start + data.len <= node.size);
    assert(!node.broken);
    if (std.mem.eql(u8, node.name, "hello.txt")) {
        @memcpy(data, hello_text[@intCast(start)..][0..data.len]);
    } else if (std.mem.eql(u8, node.name, "nested.txt")) {
        @memcpy(data, nested_text[@intCast(start)..][0..data.len]);
    } else {
        for (data, 0..) |*byte, index| byte.* = pattern_byte(start + index);
    }
}

fn reply_readdirplus(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) void {
    if (body.len < @sizeOf(abi.ReadIn)) return reply_error(fd, header, .INVAL);
    const in = std.mem.bytesToValue(abi.ReadIn, body[0..@sizeOf(abi.ReadIn)]);
    const directory = node_of(header.nodeid) orelse return reply_error(fd, header, .NOENT);
    if (directory.kind != .directory) return reply_error(fd, header, .NOTDIR);
    const room = @min(in.size, read_bytes_max);
    const data = reply_buffer[@sizeOf(abi.OutHeader)..];
    var used: usize = 0;
    var position: u64 = 0;
    for (nodes[1..], 2..) |node, id| {
        if (node.parent != header.nodeid) continue;
        position += 1;
        if (position <= in.offset) continue;
        const size = abi.direntplus_size(node.name.len);
        if (used + size > room) {
            // Zero bytes would read as the end of the directory, so a buffer too small for even
            // one remaining entry is an error.
            if (used == 0) return reply_error(fd, header, .INVAL);
            break;
        }
        write_direntplus(data[used..][0..size], id, position, node);
        used += size;
    }
    assert(used <= room);
    const total = @sizeOf(abi.OutHeader) + used;
    const out: abi.OutHeader = .{ .len = @intCast(total), .@"error" = 0, .unique = header.unique };
    @memcpy(reply_buffer[0..@sizeOf(abi.OutHeader)], std.mem.asBytes(&out));
    write_reply(fd, reply_buffer[0..total]);
}

fn write_direntplus(slot: []u8, id: u64, position: u64, node: Node) void {
    assert(slot.len == abi.direntplus_size(node.name.len));
    @memset(slot, 0);
    const entry = entry_of(id);
    const dirent: abi.Dirent = .{
        .ino = id,
        .off = position,
        .namelen = @intCast(node.name.len),
        .type = if (node.kind == .directory) linux.DT.DIR else linux.DT.REG,
    };
    const entry_end = @sizeOf(abi.EntryOut);
    const dirent_end = entry_end + @sizeOf(abi.Dirent);
    @memcpy(slot[0..entry_end], std.mem.asBytes(&entry));
    @memcpy(slot[entry_end..dirent_end], std.mem.asBytes(&dirent));
    @memcpy(slot[dirent_end..][0..node.name.len], node.name);
}

fn reply_statfs(fd: linux.fd_t, header: *const abi.InHeader) void {
    // The probe script asks for STATFS before it reads the log, so the log is written here,
    // outside any timed read.
    flush_read_log();
    var out = std.mem.zeroes(abi.Kstatfs);
    out.files = nodes.len;
    out.bsize = 4096;
    out.frsize = 4096;
    out.namelen = 255;
    assert(out.ffree == 0);
    reply_bytes(fd, header, std.mem.asBytes(&out));
}

/// No node has extended attributes: a size query gets 0, a read gets no bytes.
fn reply_listxattr(fd: linux.fd_t, header: *const abi.InHeader, body: []const u8) void {
    if (body.len < @sizeOf(abi.GetxattrIn)) return reply_error(fd, header, .INVAL);
    const in = std.mem.bytesToValue(abi.GetxattrIn, body[0..@sizeOf(abi.GetxattrIn)]);
    if (in.size != 0) return reply_bytes(fd, header, &.{});
    const out: abi.GetxattrOut = .{ .size = 0, .padding = 0 };
    reply_bytes(fd, header, std.mem.asBytes(&out));
}

/// The READ log: one line per READ, kept in memory and written to stderr only on STATFS, when it
/// is full, and when the connection ends, so a write to the log is never inside a timed read.
var read_log: [64 * 1024]u8 = undefined;
var read_log_used: usize = 0;

fn log_read(name: []const u8, offset: u64, size: u32) void {
    var line_buffer: [128]u8 = undefined;
    const format = "fuse_probe: server: READ {s} offset {d} size {d}\n";
    // 128 bytes hold the fixed text, a name of at most 16 bytes and two numbers of 20 digits.
    const line = std.fmt.bufPrint(&line_buffer, format, .{ name, offset, size }) catch
        unreachable;
    if (read_log_used + line.len > read_log.len) flush_read_log();
    assert(read_log_used + line.len <= read_log.len);
    @memcpy(read_log[read_log_used..][0..line.len], line);
    read_log_used += line.len;
}

fn flush_read_log() void {
    assert(read_log_used <= read_log.len);
    _ = linux.write(2, &read_log, read_log_used);
    read_log_used = 0;
}

fn now_ns() u64 {
    var time: linux.timespec = undefined;
    assert(linux.errno(linux.clock_gettime(.MONOTONIC, &time)) == .SUCCESS);
    assert(time.sec >= 0);
    return @as(u64, @intCast(time.sec)) * std.time.ns_per_s + @as(u64, @intCast(time.nsec));
}

var read_buffer: [read_bytes_max]u8 = undefined;

/// Reads `path` in 1 MiB reads, checks each byte against the pattern `fill` serves, and prints the
/// latency of the first read (no page of the file is cached yet) and the mean of all of them.
fn read_file(path: [:0]const u8) u8 {
    const opened = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) {
        say("fuse_probe: refused: open {s} ({t})\n", .{ path, linux.errno(opened) });
        return 1;
    }
    const fd: linux.fd_t = @intCast(opened);
    var offset: u64 = 0;
    var first_ns: u64 = 0;
    var total_ns: u64 = 0;
    var reads: u64 = 0;
    while (true) {
        const started = now_ns();
        const got = linux.read(fd, &read_buffer, read_buffer.len);
        const took = now_ns() - started;
        if (linux.errno(got) != .SUCCESS) {
            say("fuse_probe: read {s} at {d} ({t})\n", .{ path, offset, linux.errno(got) });
            return 1;
        }
        if (got == 0) break;
        for (read_buffer[0..got], 0..) |byte, index| {
            if (byte != pattern_byte(offset + index)) {
                say("fuse_probe: wrong byte at {d} of {s}\n", .{ offset + index, path });
                return 1;
            }
        }
        if (reads == 0) first_ns = took;
        reads += 1;
        total_ns += took;
        offset += got;
    }
    if (reads == 0) return 1;
    const mean_us = @divFloor(total_ns, reads) / std.time.ns_per_us;
    say("fuse_probe: read {s}: {d} bytes in {d} reads, every byte right; first 1 MiB read " ++
        "{d} us, mean {d} us\n", .{ path, offset, reads, first_ns / std.time.ns_per_us, mean_us });
    return 0;
}

test "the pattern differs between pages and within a page" {
    // Goal: a page served at the wrong offset is caught by `read`. Method: compare neighbours.
    try std.testing.expect(pattern_byte(0) != pattern_byte(1));
    try std.testing.expect(pattern_byte(5) != pattern_byte(4096 + 5));
}

test "the tree's ids and parents are consistent" {
    // Goal: every parent is a directory with a smaller id, and the root is its own parent.
    try std.testing.expectEqual(@as(u64, 1), nodes[0].parent);
    for (nodes[1..], 2..) |node, id| {
        try std.testing.expect(node.parent < id);
        try std.testing.expectEqual(Kind.directory, node_of(node.parent).?.kind);
    }
}

test "a directory counts its subdirectories as links" {
    // Goal: `st_nlink` of a directory is 2 plus its subdirectories. Method: the root holds `sub`,
    // which holds only a file.
    try std.testing.expectEqual(@as(u32, 3), attr_of(1).nlink);
    try std.testing.expectEqual(@as(u32, 2), attr_of(5).nlink);
    try std.testing.expectEqual(@as(u32, 1), attr_of(2).nlink);
}

test "INIT is refused without max_pages, before 7.31 and for another major version" {
    // Goal: each refusal names its reason and an acceptable kernel has none. Method: change one
    // field of an acceptable INIT at a time.
    var in = std.mem.zeroes(abi.InitIn);
    in.major = 7;
    in.minor = 39;
    in.flags = abi.init_max_pages;
    try std.testing.expectEqual(@as(?[]const u8, null), init_refusal(&in));
    in.flags = 0;
    try std.testing.expectEqualStrings("lacks max_pages", init_refusal(&in).?);
    in.flags = abi.init_max_pages;
    in.minor = 30;
    try std.testing.expectEqualStrings("is older than 7.31", init_refusal(&in).?);
    in.minor = 39;
    in.major = 8;
    try std.testing.expectEqualStrings("is not major version 7", init_refusal(&in).?);
}

test "every name fits a READ log line" {
    // Goal: `log_read`'s 128-byte line holds every node's name. Method: check the longest.
    for (nodes) |node| try std.testing.expect(node.name.len <= 16);
}

test {
    _ = @import("fuse_abi.zig");
}
