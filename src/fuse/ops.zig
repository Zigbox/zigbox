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
const cache_mod = @import("cache.zig");

const Digest = digest_mod.Digest;
const Node = nodes.Node;

pub const ChunkError = error{Unavailable};

/// Which object a `READ` wants: its id, and its ordinal (its place in the index's object list,
/// `nodes.Table.ordinal`), by which the chunk resolver finds it.
pub const Object = struct { id: Digest, ordinal: u32 };

/// Where a `READ` gets its bytes: chunk `index` of `object`, verified against its hash, into
/// `out` (which holds a chunk); the length. One per serving thread, so it may keep scratch space;
/// the chunks it reads go into the cache the threads share (`cache.zig`).
pub const Chunks = struct {
    context: *anyopaque,
    read: *const fn (context: *anyopaque, object: Object, index: u32, out: []u8) ChunkError!u32,
};

/// The oldest kernel protocol the server serves: the one it speaks. Kernels older than that
/// (before 5.4) cannot stack the overlay on a FUSE mount in a user namespace anyway.
pub const kernel_minor_min: u32 = abi.minor_version;

/// What the server asks for at `INIT`.
pub const init_flags: u32 = abi.init_async_read | abi.init_do_readdirplus |
    abi.init_parallel_dirops | abi.init_max_pages | abi.init_cache_symlinks;

const Refused = error{ NoEnt, Io, NotDir, IsDir, Inval, Rofs, Range, NoSys, NoData, Proto };

/// What every serving thread shares: the table, never changed while it is served, and the chunks
/// read so far.
pub const Server = struct {
    table: *const nodes.Table,
    cache: *cache_mod.Cache,
    chunk_bytes: u32,

    fn node(server: *const Server, nodeid: u64) Refused!*const Node {
        assert(server.chunk_bytes > 0);
        const found = server.table.node(nodeid) orelse return error.NoEnt;
        assert(nodeid <= server.table.node_count); // A node the table holds has an id in range.
        return found;
    }

    fn directory(server: *const Server, nodeid: u64) Refused!*const Node {
        const found = try server.node(nodeid);
        if (found.kind != .dir) return error.NotDir;
        assert(found.children_first + found.children_count <= server.table.child_count);
        return found;
    }
};

/// One serving thread's memory.
pub const Worker = struct {
    chunks: Chunks,
    reply: []align(8) u8,
    reply_len: u32,

    pub fn init(chunks: Chunks, reply: []align(8) u8) Worker {
        assert(reply.len >= constants.fuse_reply_bytes);
        return .{ .chunks = chunks, .reply = reply, .reply_len = 0 };
    }

    fn put(worker: *Worker, bytes: []const u8) void {
        assert(worker.reply_len >= @sizeOf(abi.OutHeader));
        assert(worker.reply_len + bytes.len <= worker.reply.len);
        @memcpy(worker.reply[worker.reply_len..][0..bytes.len], bytes);
        worker.reply_len += @intCast(bytes.len);
    }

    fn put_value(worker: *Worker, value: anytype) void {
        const before = worker.reply_len;
        worker.put(std.mem.asBytes(&value));
        assert(worker.reply_len - before == @sizeOf(@TypeOf(value))); // Whole, never a part.
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
    assert(server.cache.chunk_bytes == server.chunk_bytes);
    assert(worker.reply.len >= constants.fuse_reply_bytes);
    if (request.len < @sizeOf(abi.InHeader)) return &.{};
    const header = std.mem.bytesToValue(abi.InHeader, request[0..@sizeOf(abi.InHeader)]);
    const opcode: abi.Opcode = @fromBackingInt(@intCast(header.opcode));
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
        errno = -@backingInt(errno_of(err));
    };
    const out: abi.OutHeader = .{
        .len = worker.reply_len,
        .@"error" = errno,
        .unique = header.unique,
    };
    @memcpy(worker.reply[0..@sizeOf(abi.OutHeader)], std.mem.asBytes(&out));
    assert(worker.reply_len >= @sizeOf(abi.OutHeader));
    assert(worker.reply_len <= worker.reply.len);
    if (errno != 0) assert(worker.reply_len == @sizeOf(abi.OutHeader));
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
    assert(header.len >= @sizeOf(abi.InHeader));
    assert(body.len == header.len - @sizeOf(abi.InHeader));
    const id = header.nodeid;
    switch (@as(abi.Opcode, @fromBackingInt(@intCast(header.opcode)))) {
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
    const errno: abi.Errno = switch (err) {
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
    assert(@backingInt(errno) > 0); // A reply's error is the negation of this, never zero.
    return errno;
}

fn take(comptime T: type, body: []const u8) Refused!T {
    assert(@sizeOf(T) <= constants.fuse_request_bytes);
    if (body.len < @sizeOf(T)) return error.Inval;
    return std.mem.bytesToValue(T, body[0..@sizeOf(T)]);
}

/// A NUL-terminated name at the start of `bytes`.
fn name_in(bytes: []const u8) Refused![]const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse return error.Inval;
    if (end == 0) return error.Inval;
    if (end > abi.name_bytes_max) return error.Inval;
    assert(bytes[end] == 0); // The name stops at its terminator,
    assert(std.mem.indexOfScalar(u8, bytes[0..end], 0) == null); // and holds none.
    return bytes[0..end];
}

fn init(worker: *Worker, body: []const u8) Refused!void {
    assert(worker.reply_len == @sizeOf(abi.OutHeader)); // Nothing is written before the answer.
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
    assert(out.flags & ~init_flags == 0); // Only flags the server asked for.
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
    if (found.kind == .dir) assert(size == block_bytes);
    if (found.kind == .file) assert(size == found.size);
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
    assert(nodeid > 0); // A node id of 0 is the negative entry, built apart in `lookup`.
    assert(found.nlink > 0);
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
        assert(child.node < server.table.node_count);
        assert(child.name_len == wanted.len);
        const found = server.table.node(child.node + 1).?;
        worker.put_value(entry_out(found, child.node + 1));
    } else {
        // Absent, and absent for good: node id 0 with a lifetime is a negative entry.
        var absent = std.mem.zeroes(abi.EntryOut);
        absent.entry_valid = constants.fuse_valid_seconds;
        assert(absent.nodeid == 0);
        worker.put_value(absent);
    }
}

fn readlink(server: *const Server, worker: *Worker, nodeid: u64) Refused!void {
    const found = try server.node(nodeid);
    if (found.kind != .symlink) return error.Inval;
    const target = server.table.target(found);
    assert(target.len == found.size);
    assert(target.len <= worker.room());
    worker.put(target);
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
    assert(found.kind == wanted); // The three refusals above leave only the kind asked for.
    var flags: u32 = abi.open_keep_cache;
    if (wanted == .dir) flags |= abi.open_cache_dir;
    if (wanted == .file) assert(flags & abi.open_cache_dir == 0);
    assert(flags & abi.open_keep_cache != 0);
    worker.put_value(abi.OpenOut{ .fh = 0, .open_flags = flags, .padding = 0 });
}

fn read(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const found = try server.node(nodeid);
    if (found.kind == .dir) return error.IsDir;
    if (found.kind != .file) return error.Inval;
    const in = try take(abi.ReadIn, body);
    if (in.offset >= found.size) return; // At or past the end: no bytes.
    const length: u64 = @min(in.size, constants.fuse_read_bytes_max, found.size - in.offset);
    assert(length <= in.size); // Never more than the kernel asked for,
    assert(length <= found.size - in.offset); // nor than the file holds past the offset,
    assert(length <= worker.room());
    var at: u64 = in.offset;
    const end = in.offset + length;
    while (at < end) {
        const index: u32 = @intCast(at / server.chunk_bytes);
        const pinned = try chunk_of(server, worker, found, index);
        defer server.cache.unpin(pinned);
        const within: usize = @intCast(at - @as(u64, index) * server.chunk_bytes);
        assert(within < pinned.bytes.len);
        const part: usize = @intCast(@min(end - at, pinned.bytes.len - within));
        worker.put(pinned.bytes[within..][0..part]);
        at += part;
    }
    assert(at == end);
    assert(worker.reply_len == @sizeOf(abi.OutHeader) + length); // Exactly the bytes counted.
}

/// Chunk `index` of a file, verified, from the shared cache: held there already, or read now.
/// The caller unpins it once copied.
fn chunk_of(
    server: *const Server,
    worker: *Worker,
    found: *const Node,
    index: u32,
) Refused!cache_mod.Pin {
    assert(found.kind == .file);
    const start = @as(u64, index) * server.chunk_bytes;
    assert(start < found.size);
    const expected: u32 = @intCast(@min(server.chunk_bytes, found.size - start));
    const wanted: Object = .{ .id = found.digest, .ordinal = server.table.ordinal(found) };
    const pinned = server.cache.pin(worker.chunks, wanted, index, expected) catch {
        return error.Io;
    };
    assert(pinned.bytes.len == expected);
    assert(expected > 0);
    assert(expected <= server.chunk_bytes);
    return pinned;
}

fn readdirplus(server: *const Server, worker: *Worker, nodeid: u64, body: []const u8) Refused!void {
    const directory = try server.directory(nodeid);
    const in = try take(abi.ReadIn, body);
    const list = server.table.children(directory);
    // Entry `k` is ".", "..", then the children; a record's `off` is the next entry's.
    const total: u64 = @as(u64, list.len) + 2;
    assert(total >= 2);
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
        assert(id > 0);
        const bytes = abi.direntplus_bytes(@intCast(name.len));
        if (used + bytes > room) {
            // An empty reply is the end of the directory to the kernel: refuse instead when
            // entries remain and not even the first fits.
            if (used == 0) return error.Inval;
            break;
        }
        put_direntplus(server, worker, name, id, entry + 1, entry >= 2);
        used += bytes;
    }
    assert(used <= room);
    assert(worker.reply_len == @sizeOf(abi.OutHeader) + used);
}

fn put_direntplus(
    server: *const Server,
    worker: *Worker,
    name: []const u8,
    nodeid: u64,
    next: u64,
    linked: bool,
) void {
    assert(next > 0); // The offset of the entry after this one.
    assert(name.len > 0);
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
    assert(name.len > 0);
    assert(name.len <= constants.store_xattr_name_bytes_max);
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
    assert(value.len <= constants.store_xattr_value_bytes_max);
    assert(!is_overlay(wanted)); // The server never shows one.
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
    assert(total <= constants.store_xattr_names_bytes_max);
    if (in.size == 0) return worker.put_value(abi.GetxattrOut{ .size = total, .padding = 0 });
    if (total > in.size) return error.Range;
    iterator = xattrs.Iterator.init(server.table.attributes(found));
    while (iterator.next()) |attribute| {
        if (is_overlay(attribute.name)) continue;
        worker.put(attribute.name);
        worker.put(&.{0});
    }
    assert(worker.reply_len == @sizeOf(abi.OutHeader) + total); // The names counted, no more.
}

/// A size of zero asks for the length; a buffer too small for the value is `ERANGE`.
fn put_sized(worker: *Worker, size: u32, value: []const u8) Refused!void {
    assert(value.len <= constants.store_xattr_value_bytes_max);
    assert(worker.reply_len == @sizeOf(abi.OutHeader)); // Nothing is written before the value.
    if (size == 0) {
        return worker.put_value(abi.GetxattrOut{ .size = @intCast(value.len), .padding = 0 });
    }
    if (value.len > size) return error.Range;
    worker.put(value);
}

fn statfs(server: *const Server) abi.StatfsOut {
    var st = std.mem.zeroes(abi.Kstatfs);
    assert(server.table.node_count >= 1); // The root.
    st.files = server.table.node_count;
    st.bsize = block_bytes;
    st.frsize = block_bytes;
    st.namelen = constants.store_name_bytes_max;
    return .{ .st = st };
}

const testing = std.testing;
const fixture_mod = @import("fixture.zig");

var test_fixture: fixture_mod.Fixture = undefined;
var test_reply: [constants.fuse_reply_bytes]u8 align(8) = undefined;
const test_chunk_bytes = 64;
var test_cache_memory: [cache_mod.memory_bytes(test_chunk_bytes)]u8 = undefined;
var test_request: [constants.fuse_request_bytes]u8 = undefined;

/// "user.a" = "one", "user.b" = "".
const test_section = "\x02" ++ "\x06\x00user.a" ++ "\x03\x00one" ++ "\x06\x00user.b" ++ "\x00\x00";

const Harness = struct {
    region: []align(8) u8,
    table: nodes.Table,
    cache: cache_mod.Cache,
    server: Server,
    worker: Worker,

    /// A root holding `a` (300 bytes over five chunks of 64, with two attributes), `d/` (with
    /// `x`, empty), and `l` (a symlink to `a`).
    fn init(harness: *Harness) !void {
        const fixture = &test_fixture;
        fixture.init(test_chunk_bytes);
        _ = fixture.begin();
        _ = try fixture.file("x", "", 0o644, &xattrs.empty);
        const sub = fixture.finish();
        var big: [300]u8 = undefined;
        for (&big, 0..) |*byte, index| byte.* = @truncate(index * 7);
        _ = fixture.begin();
        _ = try fixture.file("a", &big, 0o644, test_section);
        try fixture.dir("d", sub);
        try fixture.symlink("l", "a");
        const root = try fixture.finish_root(.{
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .xattrs = &xattrs.empty,
        });
        const held = try fixture_mod.table_memory(testing.allocator, 16, 4096);
        harness.region = held.region;
        harness.table.init(held.memory);
        try harness.table.build(fixture.source(), root);
        harness.cache.init(testing.io, &test_cache_memory, test_chunk_bytes);
        harness.server = .{
            .table = &harness.table,
            .cache = &harness.cache,
            .chunk_bytes = test_chunk_bytes,
        };
        harness.worker = Worker.init(fixture.chunks(), &test_reply);
    }

    fn deinit(harness: *Harness) void {
        testing.allocator.free(harness.region);
    }

    fn ask(
        harness: *Harness,
        opcode: abi.Opcode,
        nodeid: u64,
        parts: []const []const u8,
    ) []const u8 {
        const bytes = fixture_mod.request(&test_request, opcode, nodeid, 99, parts);
        const reply = handle(&harness.server, &harness.worker, bytes);
        if (reply.len > 0) {
            const header = fixture_mod.reply_header(reply);
            assert(header.unique == 99);
            assert(header.len == reply.len);
        }
        return reply;
    }

    fn errno(harness: *Harness, opcode: abi.Opcode, nodeid: u64, parts: []const []const u8) i32 {
        return fixture_mod.reply_header(harness.ask(opcode, nodeid, parts)).@"error";
    }

    fn id_of(harness: *Harness, name: []const u8) u64 {
        const top = harness.table.node(abi.root_id).?;
        return harness.table.lookup(top, name).?.node + 1;
    }
};

fn negated(errno: abi.Errno) i32 {
    return -@backingInt(errno);
}

fn read_in(offset: u64, size: u32) abi.ReadIn {
    return .{
        .fh = 0,
        .offset = offset,
        .size = size,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
}

test "INIT takes the kernel's flags that the server wants, and refuses an old protocol" {
    // Goal: the handshake gives the kernel the server's limits. Method: an INIT offering every
    // flag; one from a newer major; one from a minor older than the server's; one cut short.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var in: abi.InitIn = .{
        .major = 7,
        .minor = 39,
        .max_readahead = 131072,
        .flags = 0xffff_ffff,
    };
    const reply = harness.ask(.init, 0, &.{std.mem.asBytes(&in)});
    const out = std.mem.bytesToValue(abi.InitOut, reply[16..][0..@sizeOf(abi.InitOut)]);
    try testing.expectEqual(@as(u32, 31), out.minor);
    try testing.expectEqual(init_flags, out.flags);
    try testing.expectEqual(constants.fuse_max_pages, out.max_pages);
    try testing.expectEqual(@as(u32, 131072), out.max_readahead);
    in.major = 8;
    const newer = harness.ask(.init, 0, &.{std.mem.asBytes(&in)});
    try testing.expectEqual(@as(u32, 7), std.mem.bytesToValue(u32, newer[16..20]));
    in.major = 7;
    in.minor = 30;
    try testing.expectEqual(negated(.proto), harness.errno(.init, 0, &.{std.mem.asBytes(&in)}));
    try testing.expectEqual(negated(.inval), harness.errno(.init, 0, &.{"short"}));
}

test "LOOKUP finds a child, caches a miss, and refuses a file as a directory" {
    // Goal: lookups answer from the table. Method: a hit (its attributes), a miss (node id 0
    // with a lifetime), a lookup under a file, a name with no NUL, and an unknown node.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const hit = harness.ask(.lookup, abi.root_id, &.{"a\x00"});
    const entry = std.mem.bytesToValue(abi.EntryOut, hit[16..][0..@sizeOf(abi.EntryOut)]);
    try testing.expectEqual(harness.id_of("a"), entry.nodeid);
    try testing.expectEqual(@as(u64, 300), entry.attr.size);
    try testing.expectEqual(@as(u32, 0o100644), entry.attr.mode);
    const miss = harness.ask(.lookup, abi.root_id, &.{"b\x00"});
    const absent = std.mem.bytesToValue(abi.EntryOut, miss[16..][0..@sizeOf(abi.EntryOut)]);
    try testing.expectEqual(@as(u64, 0), absent.nodeid);
    try testing.expectEqual(constants.fuse_valid_seconds, absent.entry_valid);
    const file = harness.id_of("a");
    try testing.expectEqual(negated(.notdir), harness.errno(.lookup, file, &.{"x\x00"}));
    try testing.expectEqual(negated(.inval), harness.errno(.lookup, abi.root_id, &.{"a"}));
    try testing.expectEqual(negated(.noent), harness.errno(.lookup, 77, &.{"a\x00"}));
}

test "READ returns verified bytes across chunks, and EIO with no data when a chunk fails" {
    // Goal: a read is the file's bytes or an error, never a part. Method: a read across three
    // chunks, a read past the end, a read of the end's tail, a second read of a held chunk (no
    // new chunk read), then the object's chunks failing.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const file = harness.id_of("a");
    const content = test_fixture.content_of(harness.table.node(file).?.digest).?;
    var in = read_in(50, 100);
    const reply = harness.ask(.read, file, &.{std.mem.asBytes(&in)});
    try testing.expectEqualSlices(u8, content[50..150], reply[16..]);
    in = read_in(300, 10);
    try testing.expectEqual(@as(usize, 16), harness.ask(.read, file, &.{std.mem.asBytes(&in)}).len);
    in = read_in(290, 4096);
    try testing.expectEqualSlices(
        u8,
        content[290..],
        harness.ask(.read, file, &.{std.mem.asBytes(&in)})[16..],
    );
    const reads = test_fixture.chunk_reads;
    in = read_in(280, 4);
    try testing.expectEqualSlices(
        u8,
        content[280..284],
        harness.ask(.read, file, &.{std.mem.asBytes(&in)})[16..],
    );
    try testing.expectEqual(reads, test_fixture.chunk_reads);
    test_fixture.failing = harness.table.node(file).?.digest;
    in = read_in(0, 300);
    try testing.expectEqual(negated(.io), harness.errno(.read, file, &.{std.mem.asBytes(&in)}));
    try testing.expectEqual(
        negated(.isdir),
        harness.errno(.read, abi.root_id, &.{std.mem.asBytes(&in)}),
    );
}

/// The names in a READDIRPLUS reply, joined by spaces, and the last record's `off`.
fn listing(reply: []const u8, out: []u8) struct { names: []const u8, next: u64 } {
    var at: usize = 16;
    var length: usize = 0;
    var next: u64 = 0;
    while (at < reply.len) {
        const record = std.mem.bytesToValue(
            abi.Direntplus,
            reply[at..][0..@sizeOf(abi.Direntplus)],
        );
        const name = reply[at + @sizeOf(abi.Direntplus) ..][0..record.dirent.namelen];
        @memcpy(out[length..][0..name.len], name);
        out[length + name.len] = ' ';
        length += name.len + 1;
        next = record.dirent.off;
        at += abi.direntplus_bytes(record.dirent.namelen);
    }
    assert(at == reply.len);
    return .{ .names = out[0..length], .next = next };
}

test "READDIRPLUS lists . .. and the children, and resumes from an offset" {
    // Goal: a directory reads whole however the kernel splits it. Method: one read with room
    // for everything; then reads with room for two records each, resumed from the last `off`;
    // then room for less than one record, before the end and at it.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var names: [256]u8 = undefined;
    var in = read_in(0, 4096);
    const whole = listing(harness.ask(.readdirplus, abi.root_id, &.{std.mem.asBytes(&in)}), &names);
    try testing.expectEqualStrings(". .. a d l ", whole.names);
    try testing.expectEqual(@as(u64, 5), whole.next);
    var joined: [256]u8 = undefined;
    var joined_len: usize = 0;
    in = read_in(0, 2 * abi.direntplus_bytes(2));
    while (true) {
        const part = listing(
            harness.ask(.readdirplus, abi.root_id, &.{std.mem.asBytes(&in)}),
            &names,
        );
        if (part.names.len == 0) break;
        @memcpy(joined[joined_len..][0..part.names.len], part.names);
        joined_len += part.names.len;
        in.offset = part.next;
    }
    try testing.expectEqualStrings(". .. a d l ", joined[0..joined_len]);
    // Room for less than one record: an empty reply would read as the end, so EINVAL; at the
    // end itself, the empty reply is right.
    in = read_in(2, abi.direntplus_bytes(1) - 1);
    try testing.expectEqual(
        negated(.inval),
        harness.errno(.readdirplus, abi.root_id, &.{std.mem.asBytes(&in)}),
    );
    in = read_in(5, abi.direntplus_bytes(1) - 1);
    const end = harness.ask(.readdirplus, abi.root_id, &.{std.mem.asBytes(&in)});
    try testing.expectEqual(@as(usize, 16), end.len);
    try testing.expectEqual(@as(i32, 0), fixture_mod.reply_header(end).@"error");
    try testing.expectEqual(
        negated(.notdir),
        harness.errno(.readdirplus, harness.id_of("a"), &.{std.mem.asBytes(&in)}),
    );
}

test "GETXATTR and LISTXATTR answer sizes, values, ERANGE and ENODATA" {
    // Goal: the attribute calls follow getxattr(2)'s size rules. Method: a size query, a read,
    // a buffer one byte short, a missing name, overlay's name, and the list with its sizes.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const file = harness.id_of("a");
    var in: abi.GetxattrIn = .{ .size = 0, .padding = 0 };
    const sized = harness.ask(.getxattr, file, &.{ std.mem.asBytes(&in), "user.a\x00" });
    try testing.expectEqual(@as(u32, 3), std.mem.bytesToValue(u32, sized[16..20]));
    in.size = 3;
    try testing.expectEqualStrings(
        "one",
        harness.ask(.getxattr, file, &.{ std.mem.asBytes(&in), "user.a\x00" })[16..],
    );
    in.size = 2;
    try testing.expectEqual(
        negated(.range),
        harness.errno(.getxattr, file, &.{ std.mem.asBytes(&in), "user.a\x00" }),
    );
    try testing.expectEqual(
        negated(.nodata),
        harness.errno(.getxattr, file, &.{ std.mem.asBytes(&in), "user.c\x00" }),
    );
    try testing.expectEqual(
        negated(.nodata),
        harness.errno(.getxattr, file, &.{ std.mem.asBytes(&in), "user.overlay.opaque\x00" }),
    );
    in.size = 0;
    const list_size = harness.ask(.listxattr, file, &.{std.mem.asBytes(&in)});
    try testing.expectEqual(@as(u32, 14), std.mem.bytesToValue(u32, list_size[16..20]));
    in.size = 13;
    try testing.expectEqual(
        negated(.range),
        harness.errno(.listxattr, file, &.{std.mem.asBytes(&in)}),
    );
    in.size = 14;
    try testing.expectEqualStrings(
        "user.a\x00user.b\x00",
        harness.ask(.listxattr, file, &.{std.mem.asBytes(&in)})[16..],
    );
}

test "writes are EROFS, unknown calls ENOSYS, and forgets get no reply" {
    // Goal: the server is read-only and answers everything it is sent. Method: an open for
    // writing, a mkdir, an unknown opcode, opens of the wrong kind, a forget, a header with a
    // wrong length, and a request shorter than a header.
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const file = harness.id_of("a");
    var open_in: abi.OpenIn = .{ .flags = 2, .open_flags = 0 }; // O_RDWR.
    try testing.expectEqual(
        negated(.rofs),
        harness.errno(.open, file, &.{std.mem.asBytes(&open_in)}),
    );
    open_in.flags = 0;
    try testing.expectEqual(@as(i32, 0), harness.errno(.open, file, &.{std.mem.asBytes(&open_in)}));
    try testing.expectEqual(
        negated(.isdir),
        harness.errno(.open, abi.root_id, &.{std.mem.asBytes(&open_in)}),
    );
    try testing.expectEqual(
        negated(.notdir),
        harness.errno(.opendir, file, &.{std.mem.asBytes(&open_in)}),
    );
    try testing.expectEqual(negated(.rofs), harness.errno(.mkdir, abi.root_id, &.{"x\x00"}));
    try testing.expectEqual(
        negated(.nosys),
        harness.errno(@fromBackingInt(@intCast(4000)), abi.root_id, &.{}),
    );
    try testing.expectEqual(@as(usize, 0), harness.ask(.forget, file, &.{"12345678"}).len);
    try testing.expectEqualStrings("a", harness.ask(.readlink, harness.id_of("l"), &.{})[16..]);
    const bytes = fixture_mod.request(&test_request, .getattr, file, 5, &.{});
    test_request[0] += 1;
    try testing.expectEqual(
        negated(.inval),
        fixture_mod.reply_header(handle(&harness.server, &harness.worker, bytes)).@"error",
    );
    try testing.expectEqual(
        @as(usize, 0),
        handle(&harness.server, &harness.worker, bytes[0..39]).len,
    );
}

/// The kernel's buffered read: 128 KiB `READ`s (docs/decisions/2026-11-14-s2-probe-findings.md).
const kernel_read_bytes = 128 * 1024;

/// A table over one file, `f`, of `size` bytes in chunks of `store_chunk_bytes`, served from a
/// cache in `cache_memory`.
const ChunkHarness = struct {
    region: []align(8) u8,
    cache_memory: []u8,
    table: nodes.Table,
    cache: cache_mod.Cache,
    server: Server,
    file: u64,

    fn init(harness: *ChunkHarness, size: u32) !void {
        const chunk_bytes = constants.store_chunk_bytes;
        assert(size > 0);
        assert(size <= fixture_mod.content_bytes);
        const fixture = &test_fixture;
        fixture.init(chunk_bytes);
        const content = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(content);
        for (content, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% index / 4096);
        _ = fixture.begin();
        _ = try fixture.file("f", content, 0o644, &xattrs.empty);
        const root = try fixture.finish_root(.{
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .xattrs = &xattrs.empty,
        });
        const held = try fixture_mod.table_memory(testing.allocator, 4, 4096);
        errdefer testing.allocator.free(held.region);
        harness.region = held.region;
        harness.table.init(held.memory);
        try harness.table.build(fixture.source(), root);
        const cache_bytes: usize = @intCast(cache_mod.memory_bytes(chunk_bytes));
        harness.cache_memory = try testing.allocator.alloc(u8, cache_bytes);
        harness.cache.init(testing.io, harness.cache_memory, chunk_bytes);
        harness.server = .{
            .table = &harness.table,
            .cache = &harness.cache,
            .chunk_bytes = chunk_bytes,
        };
        const top = harness.table.node(abi.root_id).?;
        harness.file = harness.table.lookup(top, "f").?.node + 1;
    }

    fn deinit(harness: *ChunkHarness) void {
        testing.allocator.free(harness.cache_memory);
        testing.allocator.free(harness.region);
    }

    /// One `READ` of `size` bytes at `offset` on `worker`; checks that its bytes are the file's.
    fn read_at(
        harness: *ChunkHarness,
        worker: *Worker,
        request: []u8,
        offset: u64,
        size: u32,
    ) !void {
        var in = read_in(offset, size);
        const body = std.mem.asBytes(&in);
        const bytes = fixture_mod.request(request, .read, harness.file, offset, &.{body});
        const reply = handle(&harness.server, worker, bytes);
        const header = fixture_mod.reply_header(reply);
        try testing.expectEqual(@as(i32, 0), header.@"error");
        const content = test_fixture.content_of(harness.table.node(harness.file).?.digest).?;
        const start: usize = @intCast(@min(offset, content.len));
        const end: usize = @intCast(@min(offset + size, content.len));
        try testing.expectEqualSlices(u8, content[start..end], reply[16..]);
    }

    /// Reads piece `piece` (128 KiB) of the first chunk on `worker` and checks its bytes.
    fn read_piece(harness: *ChunkHarness, worker: *Worker, request: []u8, piece: u32) !void {
        const offset = @as(u64, piece) * kernel_read_bytes;
        try harness.read_at(worker, request, offset, kernel_read_bytes);
    }
};

test "the kernel's eight 128 KiB READs of one chunk read it once" {
    var harness: ChunkHarness = undefined;
    try harness.init(constants.store_chunk_bytes);
    defer harness.deinit();
    var worker = Worker.init(test_fixture.chunks(), &test_reply);
    const pieces = constants.store_chunk_bytes / kernel_read_bytes;
    comptime assert(pieces == 8);
    for (0..pieces) |piece| try harness.read_piece(&worker, &test_request, @intCast(piece));
    try testing.expectEqual(@as(u32, 1), test_fixture.chunk_reads);
}

test "serving threads share a chunk: one read for READs spread over them" {
    var harness: ChunkHarness = undefined;
    try harness.init(constants.store_chunk_bytes);
    defer harness.deinit();
    const threads = constants.lazy_fuse_threads;
    const pieces = constants.store_chunk_bytes / kernel_read_bytes;
    comptime assert(pieces % threads == 0);
    const replies_bytes = threads * constants.fuse_reply_bytes;
    const replies = try testing.allocator.alignedAlloc(u8, .@"8", replies_bytes);
    defer testing.allocator.free(replies);
    var requests: [threads][constants.fuse_request_bytes]u8 = undefined;
    var failures = std.atomic.Value(u32).init(0);
    const Serve = struct {
        fn run(
            chunk: *ChunkHarness,
            reply: []align(8) u8,
            request: []u8,
            first: u32,
            failed: *std.atomic.Value(u32),
        ) void {
            var worker = Worker.init(test_fixture.chunks(), reply);
            var piece = first;
            while (piece < pieces) : (piece += threads) {
                chunk.read_piece(&worker, request, piece) catch {
                    _ = failed.fetchAdd(1, .monotonic);
                };
            }
        }
    };
    var spawned: [threads]std.Thread = undefined;
    for (&spawned, 0..) |*thread, at| {
        const reply_bytes = constants.fuse_reply_bytes;
        const reply: []align(8) u8 = @alignCast(replies[at * reply_bytes ..][0..reply_bytes]);
        const index: u32 = @intCast(at);
        const arguments = .{ &harness, reply, &requests[at], index, &failures };
        thread.* = try std.Thread.spawn(.{}, Serve.run, arguments);
    }
    for (spawned) |thread| thread.join();
    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), test_fixture.chunk_reads);
}

/// Two and a half chunks: the last one short.
const two_chunks_and_a_half = constants.store_chunk_bytes * 5 / 2;

test "a direct 1 MiB READ at 512 KiB spans two chunks: their bytes, from one read of each" {
    // Goal: a READ is the reader's size at the reader's offset, and may span two chunks
    // (O_DIRECT sends 1 MiB at any offset). Method: one 1 MiB READ at 512 KiB, then a READ
    // that runs past the end of the file.
    var harness: ChunkHarness = undefined;
    try harness.init(two_chunks_and_a_half);
    defer harness.deinit();
    var worker = Worker.init(test_fixture.chunks(), &test_reply);
    const half = constants.store_chunk_bytes / 2;
    try harness.read_at(&worker, &test_request, half, constants.fuse_read_bytes_max);
    try testing.expectEqual(@as(u32, 2), test_fixture.chunk_reads);
    const tail = two_chunks_and_a_half - half;
    try harness.read_at(&worker, &test_request, tail, constants.fuse_read_bytes_max);
    try testing.expectEqual(@as(u32, 3), test_fixture.chunk_reads);
}

test "a 4 KiB READ at an unaligned offset, and one across a chunk boundary" {
    // Goal: a small pread reaches the server as 4 KiB at the reader's offset, aligned to
    // nothing. Method: one inside a chunk at an odd offset, one straddling the first boundary.
    var harness: ChunkHarness = undefined;
    try harness.init(two_chunks_and_a_half);
    defer harness.deinit();
    var worker = Worker.init(test_fixture.chunks(), &test_reply);
    try harness.read_at(&worker, &test_request, 12345, 4096);
    try testing.expectEqual(@as(u32, 1), test_fixture.chunk_reads);
    const boundary: u64 = constants.store_chunk_bytes;
    try harness.read_at(&worker, &test_request, boundary - 1000, 4096);
    try testing.expectEqual(@as(u32, 2), test_fixture.chunk_reads);
}

test "a sequential run of 256 KiB READs reads each chunk once" {
    // Goal: with posix_fadvise(SEQUENTIAL) the kernel asks 256 KiB at a time; the cache turns
    // the run into one read per chunk. Method: the whole file front to back in 256 KiB READs.
    var harness: ChunkHarness = undefined;
    try harness.init(two_chunks_and_a_half);
    defer harness.deinit();
    var worker = Worker.init(test_fixture.chunks(), &test_reply);
    const step: u32 = 256 * 1024;
    var offset: u64 = 0;
    while (offset < two_chunks_and_a_half) : (offset += step) {
        try harness.read_at(&worker, &test_request, offset, step);
    }
    try testing.expectEqual(@as(u32, 3), test_fixture.chunk_reads);
}
