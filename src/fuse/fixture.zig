//! An image held in memory for the FUSE server's tests and its fuzzer: directory objects keyed by
//! digest (a `nodes.TreeSource`) and file contents keyed by object id (an `ops.Chunks`), with a
//! switch that makes one object's chunks fail, as a lying or absent source would.
//!
//! A directory is built bottom up, as a store import builds one: write the children's trees
//! first, then begin the parent with `begin`, add its entries, and `finish` it for its digest.

const std = @import("std");
const assert = std.debug.assert;
const digest_mod = @import("../store/digest.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const xattrs = @import("../store/xattrs.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");
const abi = @import("abi.zig");

const Digest = digest_mod.Digest;

pub const trees_max = 512;
pub const files_max = 1024;
pub const tree_bytes = 512 * 1024;
pub const content_bytes = 3 * 1024 * 1024;
pub const writer_bytes = 64 * 1024;

const Stored = struct { digest: Digest, at: u32, len: u32 };
const File = struct { id: Digest, at: u32, len: u32 };

pub const Fixture = struct {
    tree_store: [tree_bytes]u8,
    tree_len: u32,
    trees: [trees_max]Stored,
    tree_count: u32,
    content_store: [content_bytes]u8,
    content_len: u32,
    files: [files_max]File,
    file_count: u32,
    writer_buffer: [writer_bytes]u8,
    writer: tree.Writer,
    /// The chunk size the fixture serves in.
    chunk_bytes: u32,
    /// An object whose every chunk read fails.
    failing: ?Digest,
    /// Chunk reads served, failed ones included.
    chunk_reads: u32,

    pub fn init(fixture: *Fixture, chunk_bytes: u32) void {
        assert(chunk_bytes > 0);
        assert(chunk_bytes <= content_bytes);
        fixture.tree_len = 0;
        fixture.tree_count = 0;
        fixture.content_len = 0;
        fixture.file_count = 0;
        fixture.chunk_bytes = chunk_bytes;
        fixture.failing = null;
        fixture.chunk_reads = 0;
    }

    /// Starts a directory: the entries that follow go into it, in name order.
    pub fn begin(fixture: *Fixture) *tree.Writer {
        fixture.writer = tree.Writer.init(&fixture.writer_buffer);
        return &fixture.writer;
    }

    /// Adds a file entry with this content and metadata, and keeps the content.
    pub fn file(
        fixture: *Fixture,
        name: []const u8,
        content: []const u8,
        mode: u16,
        section: []const u8,
    ) !Digest {
        assert(fixture.file_count < files_max);
        assert(fixture.content_len + content.len <= content_bytes);
        const content_digest = Digest.of(content);
        const attrs: object.Attrs = .{ .mode = mode, .uid = 0, .gid = 0, .xattrs = section };
        const id = object.object_id(content_digest, attrs);
        try fixture.writer.begin(name, .file, mode, 0, 0, section);
        try fixture.writer.end_file(content.len, content_digest, id);
        @memcpy(fixture.content_store[fixture.content_len..][0..content.len], content);
        fixture.files[fixture.file_count] = .{
            .id = id,
            .at = fixture.content_len,
            .len = @intCast(content.len),
        };
        fixture.file_count += 1;
        fixture.content_len += @intCast(content.len);
        return id;
    }

    pub fn symlink(fixture: *Fixture, name: []const u8, target: []const u8) !void {
        try fixture.writer.begin(name, .symlink, 0o777, 0, 0, &xattrs.empty);
        try fixture.writer.end_symlink(target);
    }

    pub fn dir(fixture: *Fixture, name: []const u8, subtree: Digest) !void {
        try fixture.writer.begin(name, .dir, 0o755, 0, 0, &xattrs.empty);
        try fixture.writer.end_dir(subtree);
    }

    /// Ends the directory begun last and keeps its tree; its digest.
    pub fn finish(fixture: *Fixture) Digest {
        return fixture.keep(fixture.writer.finish());
    }

    /// Ends the directory begun last as a root with its own metadata.
    pub fn finish_root(fixture: *Fixture, own: tree.Own) !Digest {
        return fixture.keep(try fixture.writer.finish_with(own));
    }

    /// Keeps raw bytes as a tree under their digest, valid or not (the fuzzer forges some).
    pub fn keep(fixture: *Fixture, bytes: []const u8) Digest {
        assert(fixture.tree_count < trees_max);
        assert(fixture.tree_len + bytes.len <= tree_bytes);
        const digest = Digest.of(bytes);
        @memcpy(fixture.tree_store[fixture.tree_len..][0..bytes.len], bytes);
        fixture.trees[fixture.tree_count] = .{
            .digest = digest,
            .at = fixture.tree_len,
            .len = @intCast(bytes.len),
        };
        fixture.tree_count += 1;
        fixture.tree_len += @intCast(bytes.len);
        return digest;
    }

    /// The content of the object `id`, or null for one the fixture does not hold.
    pub fn content_of(fixture: *const Fixture, id: Digest) ?[]const u8 {
        assert(fixture.file_count <= files_max);
        for (fixture.files[0..fixture.file_count]) |held| {
            if (held.id.eql(id)) return fixture.content_store[held.at..][0..held.len];
        }
        return null;
    }

    /// The bytes kept under `digest`, or null for a tree the fixture does not hold.
    pub fn tree_held(fixture: *const Fixture, digest: Digest) ?[]const u8 {
        assert(fixture.tree_count <= trees_max);
        for (fixture.trees[0..fixture.tree_count]) |held| {
            if (held.digest.eql(digest)) return fixture.tree_store[held.at..][0..held.len];
        }
        return null;
    }

    pub fn source(fixture: *Fixture) nodes.TreeSource {
        return .{ .context = fixture, .load = load };
    }

    pub fn chunks(fixture: *Fixture) ops.Chunks {
        return .{ .context = fixture, .read = read };
    }

    fn load(context: *anyopaque, digest: Digest, out: []u8) nodes.LoadError![]const u8 {
        const fixture: *Fixture = @ptrCast(@alignCast(context));
        assert(fixture.tree_count <= trees_max);
        for (fixture.trees[0..fixture.tree_count]) |held| {
            if (!held.digest.eql(digest)) continue;
            if (held.len > out.len) return error.Damaged;
            @memcpy(out[0..held.len], fixture.tree_store[held.at..][0..held.len]);
            return out[0..held.len];
        }
        return error.NotFound;
    }

    fn read(context: *anyopaque, wanted: ops.Object, index: u32, out: []u8) ops.ChunkError!u32 {
        const fixture: *Fixture = @ptrCast(@alignCast(context));
        const id = wanted.id;
        assert(out.len >= fixture.chunk_bytes);
        fixture.chunk_reads += 1;
        if (fixture.failing) |failing| {
            if (failing.eql(id)) return error.Unavailable;
        }
        const bytes = fixture.content_of(id) orelse return error.Unavailable;
        const start = @as(u64, index) * fixture.chunk_bytes;
        if (start >= bytes.len) return error.Unavailable;
        const length: u32 = @intCast(@min(bytes.len - start, fixture.chunk_bytes));
        @memcpy(out[0..length], bytes[@intCast(start)..][0..length]);
        return length;
    }
};

/// A table's memory for tests: `nodes_room` nodes and `arena_limit` bytes of directories.
pub fn table_memory(
    allocator: std.mem.Allocator,
    nodes_room: u32,
    arena_limit: u32,
) !struct { region: []align(8) u8, memory: nodes.Memory } {
    const bytes: usize = @intCast(nodes.memory_bytes(nodes_room, arena_limit));
    const region = try allocator.alignedAlloc(u8, .@"8", bytes);
    return .{ .region = region, .memory = nodes.carve(region, nodes_room, arena_limit) };
}

/// A request of `opcode` for `nodeid`, its body the concatenation of `parts`, written into `out`.
pub fn request(
    out: []u8,
    opcode: abi.Opcode,
    nodeid: u64,
    unique: u64,
    parts: []const []const u8,
) []u8 {
    assert(out.len >= @sizeOf(abi.InHeader));
    var length: u32 = @sizeOf(abi.InHeader);
    for (parts) |part| {
        assert(length + part.len <= out.len);
        @memcpy(out[length..][0..part.len], part);
        length += @intCast(part.len);
    }
    const header: abi.InHeader = .{
        .len = length,
        .opcode = @backingInt(opcode),
        .unique = unique,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 1,
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(out[0..@sizeOf(abi.InHeader)], std.mem.asBytes(&header));
    return out[0..length];
}

/// The out-header of a reply.
pub fn reply_header(reply: []const u8) abi.OutHeader {
    assert(reply.len >= @sizeOf(abi.OutHeader));
    return std.mem.bytesToValue(abi.OutHeader, reply[0..@sizeOf(abi.OutHeader)]);
}
