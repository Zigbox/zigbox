//! Where the FUSE server gets trees and chunks: the one file that meets the store. Slice 4 serves
//! an image whose objects are all in the local store, so a chunk is `chunk_read.read_chunk` (which
//! verifies it) and a tree is `trees.load` (which hashes it). Slice 3's chunk resolver, which
//! fetches what is not local, replaces the chunk half here and nothing else changes: the server
//! sees only `ops.Chunks` and `nodes.TreeSource`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chunk_read = @import("../store/chunk_read.zig");
const digest_mod = @import("../store/digest.zig");
const layout = @import("../store/layout.zig");
const trees = @import("../store/trees.zig");
const xattrs = @import("../store/xattrs.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// The trees of an image, read from the store and hashed.
pub const StoreTrees = struct {
    store: *const Store,
    /// The errno of the last refused read, for the caller's error line.
    errno: u16,

    pub fn source(trees_source: *StoreTrees) nodes.TreeSource {
        return .{ .context = trees_source, .load = load };
    }

    fn load(context: *anyopaque, digest: Digest, out: []u8) nodes.LoadError![]const u8 {
        const trees_source: *StoreTrees = @ptrCast(@alignCast(context));
        assert(out.len >= constants.store_tree_bytes_max);
        return trees.load(
            trees_source.store,
            digest,
            out[0..constants.store_tree_bytes_max],
            &trees_source.errno,
        );
    }
};

/// One serving thread's chunk reads from the store, with that thread's scratch space.
pub const StoreChunks = struct {
    store: *const Store,
    io: []u8,
    scratch: *xattrs.Scratch,
    /// The last refusal, for the caller's error line.
    last: ?chunk_read.Error,

    pub fn init(store: *const Store, io: []u8, scratch: *xattrs.Scratch) StoreChunks {
        assert(io.len >= constants.store_chunks_max * constants.store_digest_bytes);
        return .{ .store = store, .io = io, .scratch = scratch, .last = null };
    }

    pub fn chunks(store_chunks: *StoreChunks) ops.Chunks {
        return .{ .context = store_chunks, .read = read };
    }

    fn read(context: *anyopaque, wanted: ops.Object, index: u32, out: []u8) ops.ChunkError!u32 {
        const store_chunks: *StoreChunks = @ptrCast(@alignCast(context));
        assert(out.len >= store_chunks.store.chunk_bytes);
        const s = store_chunks;
        const id = wanted.id;
        const length = chunk_read.read_chunk(s.store, s.io, s.scratch, id, index, out) catch |err| {
            s.last = err;
            return error.Unavailable;
        };
        assert(length <= out.len);
        return @intCast(length); // At most a chunk, and a chunk's size is a u32.
    }
};

/// Checks the index's object list against the table before any read: one object per file node,
/// at the node's ordinal, with the node's id and size. An index whose object order disagrees with
/// its own trees is refused as malformed, with the malformed-index code, since a read by ordinal
/// would otherwise serve one file's bytes as another's
/// (docs/decisions/2026-11-14-s2-fuse-server.md).
/// `objects` is a slice whose items carry `wanted.id` and `wanted.size`, as `lazy.Catalog`'s do.
pub fn check_objects(table: *const nodes.Table, objects: anytype) error{Malformed}!void {
    if (objects.len != table.object_count) return error.Malformed;
    var nodeid: u64 = 1;
    while (nodeid <= table.node_count) : (nodeid += 1) {
        const found = table.node(nodeid).?;
        if (found.kind != .file) continue;
        const wanted = &objects[table.ordinal(found)].wanted;
        if (!wanted.id.eql(found.digest)) return error.Malformed;
        if (wanted.size != found.size) return error.Malformed;
    }
}

const testing = std.testing;
const host_sim = @import("../host_sim.zig");
const chunks_mod = @import("../store/chunks.zig");
const fs_sim = @import("../store/fs_sim.zig");
const object = @import("../store/object.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const abi = @import("abi.zig");
const fixture_mod = @import("fixture.zig");

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var test_store: Store = undefined;
var test_io: [constants.store_io_buffer_bytes]u8 = undefined;
var test_hashes: [16]Digest = undefined;
var test_scratch: xattrs.Scratch = undefined;
var test_chunk: [8]u8 = undefined;
var test_reply: [constants.fuse_reply_bytes]u8 align(8) = undefined;
var test_request: [256]u8 = undefined;
var test_tree: [4096]u8 = undefined;

fn put_object(content: []const u8, attrs: object.Attrs) !Digest {
    var reader = object.Reader.init(test_store.chunk_bytes);
    _ = reader.update(content, &test_hashes);
    const whole = reader.finish(&test_hashes);
    const wanted: chunks_mod.Wanted = .{
        .id = object.object_id(whole, attrs),
        .attrs = attrs,
        .size = content.len,
        .content = whole,
        .hashes = test_hashes[0..reader.count],
    };
    var failure: chunks_mod.Failure = undefined;
    for (0..wanted.hashes.len) |index| {
        const at = index * test_store.chunk_bytes;
        const piece = content[at..@min(at + test_store.chunk_bytes, content.len)];
        _ = try chunks_mod.put_chunk(
            &test_store,
            &test_io,
            &wanted,
            @intCast(index),
            piece,
            &failure,
        );
    }
    return wanted.id;
}

test "the store adapter serves a stored image: its tree from trees, its bytes verified" {
    // Goal: the server reads an image from the store's own objects. Method: a simulated store
    // with chunks of eight bytes holds one file of five chunks and a root tree naming it; the
    // table builds from the store and a READ across chunks returns the content; a damaged chunk
    // then reads as EIO.
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, "/data/store");
    test_store.at(sim.interface(), "/data/store");
    test_store.chunk_bytes = 8;
    const content = "0123456789abcdefghijklmnopqrstuvwxyz";
    const attrs: object.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    const id = try put_object(content, attrs);
    var reader = object.Reader.init(8);
    _ = reader.update(content, &test_hashes);
    var writer = tree.Writer.init(&test_tree);
    try writer.begin("f", .file, 0o644, 0, 0, &xattrs.empty);
    try writer.end_file(content.len, reader.finish(&test_hashes), id);
    const empty = &xattrs.empty;
    const bytes = try writer.finish_with(.{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = empty });
    var failure: object.Failure = undefined;
    _ = try trees.put(&test_store, Digest.of(bytes), bytes, &failure);

    var trees_source: StoreTrees = .{ .store = &test_store, .errno = 0 };
    const held = try fixture_mod.table_memory(testing.allocator, 4, 4096);
    defer testing.allocator.free(held.region);
    var table: nodes.Table = undefined;
    table.init(held.memory);
    try table.build(trees_source.source(), Digest.of(bytes));
    var store_chunks = StoreChunks.init(&test_store, &test_io, &test_scratch);
    const server: ops.Server = .{ .table = &table, .chunk_bytes = 8 };
    var worker = ops.Worker.init(store_chunks.chunks(), &test_chunk, &test_reply);
    const in: abi.ReadIn = .{
        .fh = 0,
        .offset = 3,
        .size = 30,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    const request = fixture_mod.request(&test_request, .read, 2, 1, &.{std.mem.asBytes(&in)});
    try testing.expectEqualStrings(content[3..33], ops.handle(&server, &worker, request)[16..]);
    try testing.expect(store_chunks.last == null);
    var path: [128]u8 = undefined;
    const hex = id.hex();
    const shard = .{ hex[0..2], hex[2..] };
    const object_path = try std.fmt.bufPrint(&path, "/data/store/objects/{s}/{s}", shard);
    @constCast(files.content_of(object_path).?)[1] ^= 1; // The simulator's bytes are the test's.
    const first: abi.ReadIn = .{
        .fh = 0,
        .offset = 0,
        .size = 4,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    const again = fixture_mod.request(&test_request, .read, 2, 2, &.{std.mem.asBytes(&first)});
    const reply = ops.handle(&server, &worker, again);
    try testing.expectEqual(@as(usize, 16), reply.len);
    try testing.expectEqual(@as(i32, -5), fixture_mod.reply_header(reply).@"error");
    try testing.expectEqual(chunk_read.Error.Damaged, store_chunks.last.?);
}

test "an index whose object order disagrees with its trees is refused before any read" {
    // Goal: the server trusts an ordinal only after the index's object list matches the walk.
    // Method: a root with files `a` then `b`; the list in walk order passes; swapped, one short,
    // or with a size the tree does not give, it is refused as malformed.
    const fixture = &adapter_fixture;
    fixture.init(64);
    _ = fixture.begin();
    const a = try fixture.file("a", "alpha", 0o644, &xattrs.empty);
    const b = try fixture.file("b", "bravo!", 0o644, &xattrs.empty);
    const own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    const root = try fixture.finish_root(own);
    const held = try fixture_mod.table_memory(testing.allocator, 4, 4096);
    defer testing.allocator.free(held.region);
    var table: nodes.Table = undefined;
    table.init(held.memory);
    try table.build(fixture.source(), root);

    const Listed = struct { wanted: struct { id: Digest, size: u64 } };
    const in_order = [_]Listed{
        .{ .wanted = .{ .id = a, .size = 5 } },
        .{ .wanted = .{ .id = b, .size = 6 } },
    };
    try check_objects(&table, @as([]const Listed, &in_order));
    const swapped = [_]Listed{ in_order[1], in_order[0] };
    const short: []const Listed = in_order[0..1];
    var resized = in_order;
    resized[1].wanted.size = 7;
    const refused = [_][]const Listed{ &swapped, short, &resized };
    for (refused) |objects| {
        try testing.expectError(error.Malformed, check_objects(&table, objects));
    }
}

var adapter_fixture: fixture_mod.Fixture = undefined;
