//! The lazy server's requests: one request's bytes in, its reply's bytes out, with no I/O of its
//! own. The serving threads read `/dev/fuse` and write back what `handle` returns; the fuzzer
//! calls `handle` directly.
//!
//! The file system is read-only and never changes, so every answer may be cached for as long as
//! the kernel likes (`fuse_valid_seconds`), names the tree lacks included (a lookup that finds
//! nothing returns node id 0 with a lifetime, which the kernel keeps as a negative entry). A write
//! is refused with `EROFS`; the overlay above takes them. Anything the server does not do answers
//! `ENOSYS`, which the kernel remembers and stops sending.
//!
//! Every field of a request is checked before it is used: a request that does not hold what its
//! opcode needs answers `EINVAL`, never a crash. A `READ` copies only bytes that `Chunks` returned
//! as verified, and only after every chunk it needs arrived whole: any failure answers `EIO` with
//! no data, so a reader sees an error, never wrong or partial bytes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const xattrs = @import("../store/xattrs.zig");
const abi = @import("abi.zig");
const nodes = @import("nodes.zig");

const Digest = digest_mod.Digest;
const Node = nodes.Node;

pub const ChunkError = error{Unavailable};

/// Where a `READ` gets its bytes: chunk `index` of object `id`, verified against its hash, into
/// `out` (which holds a chunk); the length. One per serving thread, so it may keep scratch space.
pub const Chunks = struct {
    context: *anyopaque,
    read: *const fn (context: *anyopaque, id: Digest, index: u32, out: []u8) ChunkError!usize,
};

/// The oldest kernel protocol the server serves: the one it speaks. Kernels older than that
/// (before 5.4) cannot stack the overlay on a FUSE mount in a user namespace anyway.
pub const kernel_minor_min: u32 = abi.minor_version;

/// What the server asks for at `INIT`.
pub const init_flags: u32 = abi.init_async_read | abi.init_do_readdirplus |
    abi.init_parallel_dirops | abi.init_max_pages | abi.init_cache_symlinks;

const Refused = error{ NoEnt, Io, NotDir, IsDir, Inval, Rofs, Range, NoSys, NoData, Proto };

/// What every serving thread shares: the table, never changed while it is served.
pub const Server = struct {
    table: *const nodes.Table,
    chunk_bytes: u32,

    fn node(server: *const Server, nodeid: u64) Refused!*const Node {
        assert(server.chunk_bytes > 0);
        return server.table.node(nodeid) orelse error.NoEnt;
    }

    fn directory(server: *const Server, nodeid: u64) Refused!*const Node {
        const found = try server.node(nodeid);
        if (found.kind != .dir) return error.NotDir;
        return found;
    }
};

/// One serving thread's memory.
pub const Worker = struct {
    chunks: Chunks,
    /// The last chunk read, kept for the next read of the same chunk.
    chunk: []u8,
    held: ?struct { id: Digest, index: u32, len: u32 },
    reply: []align(8) u8,
    reply_len: u32,

    pub fn init(chunks: Chunks, chunk: []u8, reply: []align(8) u8) Worker {
        assert(chunk.len > 0);
        assert(reply.len >= constants.fuse_reply_bytes);
        return .{ .chunks = chunks, .chunk = chunk, .held = null, .reply = reply, .reply_len = 0 };
    }

    fn put(worker: *Worker, bytes: []const u8) void {
        assert(worker.reply_len >= @sizeOf(abi.OutHeader));
        assert(worker.reply_len + bytes.len <= worker.reply.len);
        @memcpy(worker.reply[worker.reply_len..][0..bytes.len], bytes);
        worker.reply_len += @intCast(bytes.len);
    }

    fn put_value(worker: *Worker, value: anytype) void {
        worker.put(std.mem.asBytes(&value));
    }

    fn room(worker: *const Worker) u32 {
        assert(worker.reply_len <= worker.reply.len);
        return @intCast(worker.reply.len - worker.reply_len);
    }
};

/// Answers one request: the reply to write to `/dev/fuse`, or an empty slice when none is due
/// (`FORGET`, `BATCH_FORGET` and `INTERRUPT` take none, and a request too short to hold a
/// header has no `unique` to answer to).
pub fn handle(server: *const Server, worker: *Worker, request: []const u8) []const u8 {
    assert(worker.chunk.len >= server.chunk_bytes);
    if (request.len < @sizeOf(abi.InHeader)) return &.{};
    const header = std.mem.bytesToValue(abi.InHeader, request[0..@sizeOf(abi.InHeader)]);
    const opcode: abi.Opcode = @enumFromInt(header.opcode);
    switch (opcode) {
        // A forget has nothing to free (the table never changes), and an interrupt has nothing
        // to stop: no request waits on anything the server could give up early.
        .forget, .batch_forget, .interrupt => return &.{},
        else => {},
    }
    worker.reply_len = @sizeOf(abi.OutHeader);
    var errno: i32 = 0;
    dispatch(server, worker, &header, request) catch |err| {
        worker.reply_len = @sizeOf(abi.OutHeader); // An error carries no data.
        errno = -@intFromEnum(errno_of(err));
    };
    const out: abi.OutHeader = .{ .len = worker.reply_len, .@"error" = errno, .unique = header.unique };
    @memcpy(worker.reply[0..@sizeOf(abi.OutHeader)], std.mem.asBytes(&out));
    assert(errno == 0 or worker.reply_len == @sizeOf(abi.OutHeader));
    return worker.reply[0..worker.reply_len];
}

fn dispatch(
    server: *const Server,
    worker: *Worker,
    header: *const abi.InHeader,
    request: []const u8,
) Refused!void {
    assert(request.len >= @sizeOf(abi.InHeader));
    if (header.len != request.len) return error.Inval;
    if (header.total_extlen != 0) return error.Inval;
    const body = request[@sizeOf(abi.InHeader)..];
    const id = header.nodeid;
    switch (@as(abi.Opcode, @enumFromInt(header.opcode))) {
        .init => try init(worker, body),
        .lookup => try lookup(server, worker, id, body),
        .getattr => worker.put_value(attr_out(try server.node(id), id)),
        .readlink => try readlink(server, worker, id),
        .open => try open(server, worker, id, body, .file),
        .opendir => try open(server, worker, id, body, .dir),
        .read => try read(server, worker, id, body),
        .readdirplus => try readdirplus(server, worker, id, body),
        .getxattr => try getxattr(server, worker, id, body),
        .listxattr => try listxattr(server, worker, id, body),
        .statfs => worker.put_value(statfs(server)),
        // Nothing is held open, so a close has nothing to do.
        .release, .releasedir, .flush => _ = try server.node(id),
        .setattr, .symlink, .mknod, .mkdir, .unlink, .rmdir, .rename, .link, .write => {
            return error.Rofs;
        },
        .setxattr, .removexattr, .create, .fallocate, .rename2, .tmpfile => return error.Rofs,
        .copy_file_range => return error.Rofs,
        else => return error.NoSys,
    }
}

fn errno_of(err: Refused) abi.Errno {
    return switch (err) {
        error.NoEnt => .noent,
        error.Io => .io,
        error.NotDir => .notdir,
        error.IsDir => .isdir,
        error.Inval => .inval,
        error.Rofs => .rofs,
        error.Range => .range,
        error.NoSys => .nosys,
        error.NoData => .nodata,
        error.Proto => .proto,
    };
}

fn take(comptime T: type, body: []const u8) Refused!T {
    if (body.len < @sizeOf(T)) return error.Inval;
    return std.mem.bytesToValue(T, body[0..@sizeOf(T)]);
}

/// A NUL-terminated name at the start of `bytes`.
fn name_in(bytes: []const u8) Refused![]const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse return error.Inval;
    if (end == 0) return error.Inval;
    if (end > abi.name_bytes_max) return error.Inval;
    return bytes[0..end];
}

fn init(worker: *Worker, body: []const u8) Refused!void {
    const in = try take(abi.InitIn, body);
    if (in.major < abi.major_version) return error.Proto;
    var out = std.mem.zeroes(abi.InitOut);
    out.major = abi.major_version;
    out.minor = abi.minor_version;
    if (in.major > abi.major_version) {
        // A newer kernel reads our major and asks again in it.
        worker.put_value(out);
        return;
    }
    if (in.minor < kernel_minor_min) return error.Proto;
    out.flags = in.flags & init_flags;
    out.max_readahead = in.max_readahead;
    out.max_background = constants.fuse_max_background;
    out.congestion_threshold = constants.fuse_congestion_threshold;
    out.max_write = constants.fuse_max_write;
    out.time_gran = 1;
    out.max_pages = constants.fuse_max_pages;
    worker.put_value(out);
}

const mode_dir: u32 = 0o040000;
const mode_file: u32 = 0o100000;
const mode_symlink: u32 = 0o120000;
const block_bytes: u32 = 4096;

fn attr_of(found: *const Node, nodeid: u64) abi.Attr {
    assert(nodeid > 0);
    assert(found.nlink > 0);
    const size: u64 = if (found.kind == .dir) block_bytes else found.size;
    const kind_bits: u32 = switch (found.kind) {
        .dir => mode_dir,
        .file => mode_file,
        .symlink => mode_symlink,
    };
    const time = constants.store_mtime_seconds;
    return .{
        .ino = nodeid,
        .size = size,
        .blocks = std.math.divCeil(u64, size, 512) catch unreachable, // 512 is not zero.
        .atime = time,
        .mtime = time,
        .ctime = time,
        .atimensec = 0,
        .mtimensec = 0,
        .ctimensec = 0,
        .mode = kind_bits | found.mode,
        .nlink = found.nlink,
        .uid = found.uid,
        .gid = found.gid,
        .rdev = 0,
        .blksize = block_bytes,
        .flags = 0,
    };
}

fn attr_out(found: *const Node, nodeid: u64) abi.AttrOut {
    return .{
        .attr_valid = constants.fuse_valid_seconds,
        .attr_valid_nsec = 0,
        .dummy = 0,
        .attr = attr_of(found, nodeid),
    };
}

fn entry_out(found: *const Node, nodeid: u64) abi.EntryOut {
    return .{
        .nodeid = nodeid,
        .generation = 0,
        .entry_valid = constants.fuse_valid_seconds,
        .attr_valid = constants.fuse_valid_seconds,
        .entry_valid_nsec = 0,
        .attr_valid_nsec = 0,
        .attr = attr_of(found, nodeid),
    };
}

fn lookup(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const directory = try server.directory(nodeid);
    const wanted = try name_in(body);
    if (server.table.lookup(directory, wanted)) |child| {
        const found = server.table.node(child.node + 1).?;
        worker.put_value(entry_out(found, child.node + 1));
    } else {
        // Absent, and absent for good: node id 0 with a lifetime is a negative entry.
        var absent = std.mem.zeroes(abi.EntryOut);
        absent.entry_valid = constants.fuse_valid_seconds;
        worker.put_value(absent);
    }
}

fn readlink(server: *const Server, worker: *Worker, nodeid: u64) Refused!void {
    const found = try server.node(nodeid);
    if (found.kind != .symlink) return error.Inval;
    worker.put(server.table.target(found));
}

fn open(
    server: *const Server,
    worker: *Worker,
    nodeid: u64,
    body: []const u8,
    wanted: nodes.Kind,
) Refused!void {
    const found = try server.node(nodeid);
    const in = try take(abi.OpenIn, body);
    if (wanted == .dir and found.kind != .dir) return error.NotDir;
    if (wanted == .file and found.kind == .dir) return error.IsDir;
    if (wanted == .file and found.kind != .file) return error.Inval;
    const access_mode: u32 = 3; // O_ACCMODE; O_RDONLY is 0.
    const truncate: u32 = 0o1000; // O_TRUNC.
    if (in.flags & access_mode != 0) return error.Rofs;
    if (in.flags & truncate != 0) return error.Rofs;
    var flags: u32 = abi.open_keep_cache;
    if (wanted == .dir) flags |= abi.open_cache_dir;
    worker.put_value(abi.OpenOut{ .fh = 0, .open_flags = flags, .padding = 0 });
}

fn read(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const found = try server.node(nodeid);
    if (found.kind == .dir) return error.IsDir;
    if (found.kind != .file) return error.Inval;
    const in = try take(abi.ReadIn, body);
    if (in.offset >= found.size) return; // At or past the end: no bytes.
    const length: u64 = @min(in.size, constants.fuse_read_bytes_max, found.size - in.offset);
    assert(length <= worker.room());
    var at: u64 = in.offset;
    const end = in.offset + length;
    while (at < end) {
        const index: u32 = @intCast(at / server.chunk_bytes);
        const bytes = try chunk_of(server, worker, found, index);
        const within: usize = @intCast(at - @as(u64, index) * server.chunk_bytes);
        assert(within < bytes.len);
        const part: usize = @intCast(@min(end - at, bytes.len - within));
        worker.put(bytes[within..][0..part]);
        at += part;
    }
    assert(at == end);
}

/// Chunk `index` of a file, verified: the one this thread holds, or a fresh read.
fn chunk_of(server: *const Server, worker: *Worker, found: *const Node, index: u32) Refused![]const u8 {
    assert(found.kind == .file);
    const start = @as(u64, index) * server.chunk_bytes;
    assert(start < found.size);
    const expected: u32 = @intCast(@min(server.chunk_bytes, found.size - start));
    if (worker.held) |held| {
        if (held.index == index and held.id.eql(found.digest)) {
            assert(held.len == expected);
            return worker.chunk[0..held.len];
        }
    }
    worker.held = null;
    const out = worker.chunk[0..server.chunk_bytes];
    const got = worker.chunks.read(worker.chunks.context, found.digest, index, out) catch {
        return error.Io;
    };
    // A length the object's size does not give is a source that lied.
    if (got != expected) return error.Io;
    worker.held = .{ .id = found.digest, .index = index, .len = expected };
    return worker.chunk[0..expected];
}

fn readdirplus(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const directory = try server.directory(nodeid);
    const in = try take(abi.ReadIn, body);
    const list = server.table.children(directory);
    // Entry `k` is ".", "..", then the children; a record's `off` is the next entry's.
    const total: u64 = @as(u64, list.len) + 2;
    const room: u32 = @min(in.size, worker.room());
    var used: u32 = 0;
    var entry: u64 = in.offset;
    while (entry < total) : (entry += 1) {
        const name: []const u8, const id: u64 = switch (entry) {
            0 => .{ ".", nodeid },
            1 => .{ "..", @as(u64, directory.parent) + 1 },
            else => .{
                server.table.name(list[@intCast(entry - 2)]),
                @as(u64, list[@intCast(entry - 2)].node) + 1,
            },
        };
        const bytes = abi.direntplus_bytes(@intCast(name.len));
        if (used + bytes > room) break;
        put_direntplus(server, worker, name, id, entry + 1, entry >= 2);
        used += bytes;
    }
}

fn put_direntplus(
    server: *const Server,
    worker: *Worker,
    name: []const u8,
    nodeid: u64,
    next: u64,
    linked: bool,
) void {
    const found = server.table.node(nodeid).?;
    var record = std.mem.zeroes(abi.Direntplus);
    // "." and ".." carry node id 0: the kernel links neither, and needs no attributes for them.
    if (linked) record.entry_out = entry_out(found, nodeid);
    record.dirent = .{
        .ino = nodeid,
        .off = next,
        .namelen = @intCast(name.len),
        .type = switch (found.kind) {
            .dir => abi.dt_dir,
            .file => abi.dt_reg,
            .symlink => abi.dt_lnk,
        },
    };
    const start = worker.reply_len;
    worker.put_value(record);
    worker.put(name);
    const padded = abi.direntplus_bytes(@intCast(name.len));
    const zeros: [8]u8 = @splat(0);
    worker.put(zeros[0 .. padded - (worker.reply_len - start)]);
    assert(worker.reply_len - start == padded);
}

/// Overlay's own attributes on a lower layer would steer the overlay (an opaque directory, a
/// redirect); the store never keeps them, and the server never shows one.
fn is_overlay(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "user.overlay.") or
        std.mem.startsWith(u8, name, "trusted.overlay.");
}

fn getxattr(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const found = try server.node(nodeid);
    const in = try take(abi.GetxattrIn, body);
    const wanted = try name_in(body[@sizeOf(abi.GetxattrIn)..]);
    if (is_overlay(wanted)) return error.NoData;
    var iterator = xattrs.Iterator.init(server.table.attributes(found));
    const value = while (iterator.next()) |attribute| {
        if (std.mem.eql(u8, attribute.name, wanted)) break attribute.value;
    } else return error.NoData;
    assert(!iterator.broken);
    try put_sized(worker, in.size, value);
}

fn listxattr(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const found = try server.node(nodeid);
    const in = try take(abi.GetxattrIn, body);
    var total: u32 = 0;
    var iterator = xattrs.Iterator.init(server.table.attributes(found));
    while (iterator.next()) |attribute| {
        if (!is_overlay(attribute.name)) total += @intCast(attribute.name.len + 1);
    }
    assert(!iterator.broken);
    if (in.size == 0) return worker.put_value(abi.GetxattrOut{ .size = total, .padding = 0 });
    if (total > in.size) return error.Range;
    iterator = xattrs.Iterator.init(server.table.attributes(found));
    while (iterator.next()) |attribute| {
        if (is_overlay(attribute.name)) continue;
        worker.put(attribute.name);
        worker.put(&.{0});
    }
}

/// A size of zero asks for the length; a buffer too small for the value is `ERANGE`.
fn put_sized(worker: *Worker, size: u32, value: []const u8) Refused!void {
    assert(value.len <= constants.store_xattr_value_bytes_max);
    if (size == 0) {
        return worker.put_value(abi.GetxattrOut{ .size = @intCast(value.len), .padding = 0 });
    }
    if (value.len > size) return error.Range;
    worker.put(value);
}

fn statfs(server: *const Server) abi.StatfsOut {
    var st = std.mem.zeroes(abi.Kstatfs);
    st.files = server.table.node_count;
    st.bsize = block_bytes;
    st.frsize = block_bytes;
    st.namelen = constants.store_name_bytes_max;
    return .{ .st = st };
}
