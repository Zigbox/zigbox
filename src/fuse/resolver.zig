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
const cache_mod = @import("cache.zig");
const lazy = @import("../lazy/lazy.zig");
const index_mod = @import("../lazy/index.zig");
const chaining = @import("../lazy/chaining.zig");
const object_mod = @import("../store/object.zig");

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
        const bytes = try trees.load(
            trees_source.store,
            digest,
            out[0..constants.store_tree_bytes_max],
            &trees_source.errno,
        );
        assert(bytes.len > 0); // A tree holds at least its own header.
        assert(bytes.len <= constants.store_tree_bytes_max);
        return bytes;
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
        assert(store.chunk_bytes > 0);
        return .{ .store = store, .io = io, .scratch = scratch, .last = null };
    }

    pub fn chunks(store_chunks: *StoreChunks) ops.Chunks {
        assert(store_chunks.io.len >= constants.store_chunks_max * constants.store_digest_bytes);
        return .{ .context = store_chunks, .read = read };
    }

    fn read(context: *anyopaque, wanted: ops.Object, index: u32, out: []u8) ops.ChunkError!u32 {
        const store_chunks: *StoreChunks = @ptrCast(@alignCast(context));
        assert(out.len >= store_chunks.store.chunk_bytes);
        assert(index < constants.store_chunks_max); // An object has at most this many chunks.
        const s = store_chunks;
        const id = wanted.id;
        const length = chunk_read.read_chunk(s.store, s.io, s.scratch, id, index, out) catch |err| {
            s.last = err;
            return error.Unavailable;
        };
        assert(length > 0); // A chunk of a file is never empty.
        assert(length <= s.store.chunk_bytes);
        assert(length <= out.len);
        return @intCast(length); // At most a chunk, and a chunk's size is a u32.
    }
};

/// The chunks of an image that is not all local: every read goes through the chunk resolver
/// (`lazy.Resolver.read`), which serves from the store or fetches, verifies and lands the chunk
/// first. The resolver is shared by every serving thread (it takes its own lock); this adapter
/// keeps only the thread's last refusal, for its tests.
pub const ResolverChunks = struct {
    resolver: *lazy.Resolver,
    chunk_bytes: u32,
    /// The last refusal, for the caller's tests (the resolver logged the coded event itself).
    last: ?lazy.ReadError,

    pub fn init(resolver: *lazy.Resolver, chunk_bytes: u32) ResolverChunks {
        assert(chunk_bytes > 0);
        assert(chunk_bytes <= constants.store_chunk_bytes);
        return .{ .resolver = resolver, .chunk_bytes = chunk_bytes, .last = null };
    }

    pub fn chunks(resolver_chunks: *ResolverChunks) ops.Chunks {
        assert(resolver_chunks.chunk_bytes > 0);
        return .{ .context = resolver_chunks, .read = read };
    }

    fn read(context: *anyopaque, wanted: ops.Object, index: u32, out: []u8) ops.ChunkError!u32 {
        const s: *ResolverChunks = @ptrCast(@alignCast(context));
        assert(out.len >= s.chunk_bytes);
        assert(index < constants.store_chunks_max);
        const objects = s.resolver.options.catalog.objects;
        // `check_objects` matched every file node's ordinal to the catalog before serving.
        assert(wanted.ordinal < objects.len);
        assert(objects[wanted.ordinal].wanted.id.eql(wanted.id));
        const length = s.resolver.read(wanted.ordinal, index, out) catch |err| {
            s.last = err;
            return error.Unavailable;
        };
        assert(length > 0); // A chunk of a file is never empty.
        assert(length <= s.chunk_bytes);
        assert(length <= out.len);
        return @intCast(length); // At most a chunk, and a chunk's size is a u32.
    }
};

/// Where `catalog_of` builds the catalog: one object per index object, one hash, one chaining
/// value and one location per index chunk. The caller's, sized from the verified index's header.
pub const CatalogMemory = struct {
    objects: []lazy.Object,
    hashes: []Digest,
    chaining: []Digest,
    locations: []lazy.Location,
};

/// The resolver's catalog of a verified index (`verify.verify`), in the index's object order,
/// with each object's attributes taken from its file node in `table` (built from the same
/// trees). An object id that the attributes and content do not give is refused as malformed:
/// the index and the trees disagree, and no read may trust an ordinal of either.
pub fn catalog_of(
    table: *const nodes.Table,
    index: *const index_mod.Index,
    memory: CatalogMemory,
) error{Malformed}!lazy.Catalog {
    const header = index.header;
    assert(memory.objects.len == header.objects);
    assert(memory.hashes.len == header.chunks);
    assert(memory.chaining.len == header.chunks);
    assert(memory.locations.len == header.chunks);
    if (table.object_count != header.objects) return error.Malformed;
    for (0..header.chunks) |at| {
        const record = index.chunk(@intCast(at));
        memory.hashes[at] = record.hash;
        memory.chaining[at] = record.chaining;
        memory.locations[at] = .{ .offset = record.offset, .length = record.length };
    }
    var filled: u32 = 0;
    var nodeid: u64 = 1;
    while (nodeid <= table.node_count) : (nodeid += 1) {
        const found = table.node(nodeid).?;
        if (found.kind != .file) continue;
        const ordinal = table.ordinal(found);
        assert(ordinal < header.objects);
        const record = index.object(ordinal);
        if (!record.id.eql(found.digest)) return error.Malformed;
        if (record.size != found.size) return error.Malformed;
        const first = record.first_chunk;
        assert(@as(u64, first) + record.chunk_count <= header.chunks); // `parse` checked it.
        const attrs: object_mod.Attrs = .{
            .mode = found.mode & 0o7777,
            .uid = found.uid,
            .gid = found.gid,
            .xattrs = table.attributes(found),
        };
        const content = content_of(index, &record);
        if (!object_mod.object_id(content, attrs).eql(record.id)) return error.Malformed;
        memory.objects[ordinal] = .{
            .wanted = .{
                .id = record.id,
                .attrs = attrs,
                .size = record.size,
                .content = content,
                .hashes = memory.hashes[first..][0..record.chunk_count],
            },
            .locations = memory.locations[first..][0..record.chunk_count],
            // A one-chunk object's chunk hash is its content; a longer one's chunks are tied to
            // its content only through these (`land.anchored`), which `content_of` joined.
            .chaining = if (record.chunk_count < 2)
                &.{}
            else
                memory.chaining[first..][0..record.chunk_count],
        };
        filled += 1;
    }
    // One file node per object: hard links share a node.
    if (filled != header.objects) return error.Malformed;
    return .{ .objects = memory.objects };
}

/// An object's content hash from its chunks, as `verify` anchored them: the empty hash, the one
/// chunk's hash, or the chunks' chaining values joined.
fn content_of(index: *const index_mod.Index, record: *const index_mod.Object) Digest {
    if (record.chunk_count == 0) return Digest.of("");
    if (record.chunk_count == 1) return index.chunk(record.first_chunk).hash;
    var joiner = chaining.Joiner.init();
    const last = record.first_chunk + record.chunk_count - 1;
    for (record.first_chunk..last) |ordinal| joiner.add(&index.chunk(@intCast(ordinal)).chaining);
    return joiner.root(&index.chunk(last).chaining);
}

/// Checks the index's object list against the table before any read: one object per file node,
/// at the node's ordinal, with the node's id and size. An index whose object order disagrees with
/// its own trees is refused as malformed, with the malformed-index code, since a read by ordinal
/// would otherwise serve one file's bytes as another's
/// (docs/decisions/2026-11-14-s2-fuse-server.md).
/// `objects` is a slice whose items carry `wanted.id` and `wanted.size`, as `lazy.Catalog`'s do.
pub fn check_objects(table: *const nodes.Table, objects: anytype) error{Malformed}!void {
    if (objects.len != table.object_count) return error.Malformed;
    assert(table.node_count >= 1); // The root.
    var nodeid: u64 = 1;
    while (nodeid <= table.node_count) : (nodeid += 1) {
        const found = table.node(nodeid).?;
        if (found.kind != .file) continue;
        assert(table.ordinal(found) < objects.len);
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
var test_cache_memory: [cache_mod.memory_bytes(8)]u8 = undefined;
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
    var cache: cache_mod.Cache = undefined;
    cache.init(testing.io, &test_cache_memory, 8);
    const server: ops.Server = .{ .table = &table, .cache = &cache, .chunk_bytes = 8 };
    var worker = ops.Worker.init(store_chunks.chunks(), &test_reply);
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
    cache.init(testing.io, &test_cache_memory, 8); // Empty again: the chunk is read anew.
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
