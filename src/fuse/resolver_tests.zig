//! Tests of `resolver.zig`'s lazy half: `catalog_of` against a table and an index built from the
//! same trees (agreeing, and disagreeing by mode and by content), and `ResolverChunks` serving
//! FUSE reads through `ops` and the chunk resolver over the simulated store, from the store and
//! from a registry range, with a lying range ending in `EIO`.
//!
//! The indexes are written here by hand from the fixture's files (header, the root tree, one
//! object and its chunk records per file), in the table's ordinal order, so the tests do not
//! depend on the pack's writer. Their ranges are stored deflate blocks in a blob of their own,
//! which `inflate_range` reads as any full-flush segment.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const fs_sim = @import("../store/fs_sim.zig");
const layout = @import("../store/layout.zig");
const chunks_mod = @import("../store/chunks.zig");
const object_mod = @import("../store/object.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const xattrs = @import("../store/xattrs.zig");
const Digest = @import("../store/digest.zig").Digest;
const lazy = @import("../lazy/lazy.zig");
const index_mod = @import("../lazy/index.zig");
const chaining = @import("../lazy/chaining.zig");
const abi = @import("abi.zig");
const cache_mod = @import("cache.zig");
const fixture_mod = @import("fixture.zig");
const nodes = @import("nodes.zig");
const ops = @import("ops.zig");
const resolver = @import("resolver.zig");
const land = @import("../lazy/land.zig");

const testing = std.testing;
const gpa = testing.allocator;
const chunk_bytes = constants.store_chunk_bytes;
/// A stored deflate block holds at most this many bytes after its five-byte header.
const stored_block_bytes_max = 65535;
const own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };

/// An index and the blob its ranges point into; the caller frees both.
const Built = struct {
    bytes: []u8,
    blob: []u8,

    fn deinit(built: *Built) void {
        gpa.free(built.bytes);
        gpa.free(built.blob);
    }
};

/// How a test makes the index lie about one file's chunks.
const Lie = union(enum) {
    none,
    /// The chunk hash of this ordinal's first chunk is of other bytes.
    hash: u32,
    /// The chaining value of this ordinal's first chunk is of other bytes.
    chaining: u32,
    /// This ordinal's second chunk is other bytes in the blob, and the index lists their plain
    /// hash; its chaining value stays the true one, so the index still joins into the tree.
    forged: u32,
};

/// The forged second chunk's bytes (`Lie.forged`).
var forged_piece: [chunk_bytes]u8 = undefined;

/// The bytes the blob holds for chunk `at` of `ordinal`: `piece`, or other bytes of its length
/// whose hash `record` then lists.
fn served_piece(
    piece: []const u8,
    lie: Lie,
    ordinal: u32,
    at: u32,
    record: *index_mod.Chunk,
) []const u8 {
    const wanted = switch (lie) {
        .forged => |wanted| wanted,
        else => return piece,
    };
    if (wanted != ordinal) return piece;
    if (at != 1) return piece;
    const forged = forged_piece[0..piece.len];
    @memcpy(forged, piece);
    forged[0] ^= 0x5a;
    record.hash = Digest.of(forged);
    return forged;
}

/// The index of the flat root `root`, whose files (in name order, which is the table's ordinal
/// order) hold `contents`.
fn build_index(root: Digest, ids: []const Digest, contents: []const []const u8, lie: Lie) !Built {
    assert(ids.len == contents.len);
    const root_bytes = fixture.tree_held(root).?;
    var objects: std.ArrayList(u8) = .empty;
    defer objects.deinit(gpa);
    var records: std.ArrayList(u8) = .empty;
    defer records.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    errdefer blob.deinit(gpa);
    try blob.appendNTimes(gpa, 0, index_mod.gzip_header_bytes);
    var chunk_total: u32 = 0;
    for (ids, contents, 0..) |id, content, ordinal| {
        const count = index_mod.chunk_count(content.len);
        var object: [index_mod.object_record_bytes]u8 = undefined;
        index_mod.encode_object(.{
            .id = id,
            .size = content.len,
            .first_chunk = chunk_total,
            .chunk_count = count,
        }, &object);
        try objects.appendSlice(gpa, &object);
        for (0..count) |at| {
            const start = at * chunk_bytes;
            const piece = content[start..@min(content.len, start + chunk_bytes)];
            var record = chunk_record(piece, @intCast(at), count);
            if (at == 0) lie_about(&record, lie, @intCast(ordinal));
            const served = served_piece(piece, lie, @intCast(ordinal), @intCast(at), &record);
            record.offset = blob.items.len;
            record.length = @intCast(try append_stored(&blob, served));
            var encoded: [index_mod.chunk_record_bytes]u8 = undefined;
            index_mod.encode_chunk(record, &encoded);
            try records.appendSlice(gpa, &encoded);
        }
        chunk_total += count;
    }
    const header: index_mod.Header = .{
        .complete = true,
        .tree = root,
        .names = @intCast(ids.len),
        .trees = 1,
        .objects = @intCast(ids.len),
        .chunks = chunk_total,
        .order = 0,
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var head: [index_mod.header_bytes]u8 = undefined;
    header.encode(&head);
    try out.appendSlice(gpa, &head);
    var tree_head: [index_mod.tree_head_bytes]u8 = undefined;
    index_mod.encode_tree_head(root, @intCast(root_bytes.len), &tree_head);
    try out.appendSlice(gpa, &tree_head);
    try out.appendSlice(gpa, root_bytes);
    try out.appendSlice(gpa, objects.items);
    try out.appendSlice(gpa, records.items);
    return .{ .bytes = try out.toOwnedSlice(gpa), .blob = try blob.toOwnedSlice(gpa) };
}

fn chunk_record(piece: []const u8, at: u32, count: u32) index_mod.Chunk {
    const zero: Digest = .{ .bytes = @splat(0) };
    return .{
        .hash = Digest.of(piece),
        .chaining = if (count < 2) zero else chaining.run_value(piece, at, chunk_bytes),
        .offset = 0,
        .length = 0,
    };
}

fn lie_about(record: *index_mod.Chunk, lie: Lie, ordinal: u32) void {
    switch (lie) {
        .none => {},
        .hash => |wanted| if (wanted == ordinal) {
            record.hash = Digest.of("other bytes");
        },
        .chaining => |wanted| if (wanted == ordinal) {
            record.chaining = Digest.of("other bytes");
        },
        .forged => {},
    }
}

/// Appends `piece` as stored deflate blocks (none of them final) and returns their length.
fn append_stored(blob: *std.ArrayList(u8), piece: []const u8) !u64 {
    const start = blob.items.len;
    var rest = piece;
    while (rest.len > 0) {
        const length: u16 = @intCast(@min(rest.len, stored_block_bytes_max));
        var head: [5]u8 = undefined;
        head[0] = 0;
        std.mem.writeInt(u16, head[1..3], length, .little);
        std.mem.writeInt(u16, head[3..5], ~length, .little);
        try blob.appendSlice(gpa, &head);
        try blob.appendSlice(gpa, rest[0..length]);
        rest = rest[length..];
    }
    return blob.items.len - start;
}

/// The table of `root`, in memory the caller frees.
fn table_of(root: Digest, table: *nodes.Table) ![]align(8) u8 {
    const held = try fixture_mod.table_memory(gpa, 16, 64 * 1024);
    errdefer gpa.free(held.region);
    table.init(held.memory);
    try table.build(fixture.source(), root);
    return held.region;
}

fn catalog_memory(index: *const index_mod.Index) !resolver.CatalogMemory {
    return .{
        .objects = try gpa.alloc(lazy.Object, index.header.objects),
        .hashes = try gpa.alloc(Digest, index.header.chunks),
        .chaining = try gpa.alloc(Digest, index.header.chunks),
        .locations = try gpa.alloc(lazy.Location, index.header.chunks),
    };
}

fn catalog_free(memory: resolver.CatalogMemory) void {
    gpa.free(memory.objects);
    gpa.free(memory.hashes);
    gpa.free(memory.chaining);
    gpa.free(memory.locations);
}

/// A root of `big` (two chunks), `empty` and `small`, each file's id made from `modes`.
fn three_files(contents: *const [3][]const u8, modes: [3]u16, ids: *[3]Digest) !Digest {
    fixture.init(chunk_bytes);
    _ = fixture.begin();
    const names = [3][]const u8{ "big", "empty", "small" };
    for (names, contents, modes, ids) |name, content, mode, *id| {
        id.* = try fixture.file(name, content, mode, &xattrs.empty);
    }
    return fixture.finish_root(own);
}

var fixture: fixture_mod.Fixture = undefined;
var big_content: [chunk_bytes + 5]u8 = undefined;

fn contents_three() [3][]const u8 {
    for (&big_content, 0..) |*byte, at| byte.* = @truncate(at *% 7);
    return .{ &big_content, "", "small" };
}

test "catalog_of: an index from the same trees gives each object its node's attributes" {
    // Goal: the catalog agrees with the index and the table. Method: a root of a two-chunk
    // file, an empty file and a one-chunk file; its index built here; each catalog object has
    // the index's id, size, chunk hashes and locations, the node's mode, and the content hash
    // of the file's bytes (joined from the chaining values for the two-chunk file).
    const contents = contents_three();
    var ids: [3]Digest = undefined;
    const root = try three_files(&contents, .{ 0o644, 0o600, 0o755 }, &ids);
    var built = try build_index(root, &ids, &contents, .none);
    defer built.deinit();
    const index = try index_mod.parse(built.bytes);
    var table: nodes.Table = undefined;
    const region = try table_of(root, &table);
    defer gpa.free(region);
    const memory = try catalog_memory(&index);
    defer catalog_free(memory);

    const catalog = try resolver.catalog_of(&table, &index, memory);
    try testing.expectEqual(@as(usize, 3), catalog.objects.len);
    const modes = [3]u16{ 0o644, 0o600, 0o755 };
    for (catalog.objects, ids, contents, modes, 0..) |object, id, content, mode, ordinal| {
        const record = index.object(@intCast(ordinal));
        try testing.expect(object.wanted.id.eql(id));
        try testing.expectEqual(@as(u64, content.len), object.wanted.size);
        try testing.expectEqual(mode, object.wanted.attrs.mode);
        try testing.expect(object.wanted.content.eql(Digest.of(content)));
        try testing.expectEqual(record.chunk_count, object.wanted.hashes.len);
        try testing.expectEqual(record.chunk_count, object.locations.len);
        for (object.wanted.hashes, object.locations, 0..) |hash, location, at| {
            const chunk = index.chunk(record.first_chunk + @as(u32, @intCast(at)));
            try testing.expect(hash.eql(chunk.hash));
            try testing.expectEqual(chunk.offset, location.offset);
            try testing.expectEqual(chunk.length, location.length);
        }
    }
    // The objects the table and the catalog agree on are the ones `check_objects` accepts.
    try resolver.check_objects(&table, catalog.objects);
}

test "catalog_of: an index object made with another mode is refused as malformed" {
    // Goal: the attributes come from the node, and an index id they do not give is refused.
    // Method: the tree names `small` with mode 0o755 (the table refuses a node that disagrees
    // with its own id), but the index lists for it an id made with mode 0o644.
    const contents = contents_three();
    var ids: [3]Digest = undefined;
    const root = try three_files(&contents, .{ 0o644, 0o600, 0o755 }, &ids);
    const small_attrs: object_mod.Attrs = .{
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .xattrs = &xattrs.empty,
    };
    const honest = ids[2];
    ids[2] = object_mod.object_id(Digest.of(contents[2]), small_attrs);
    try testing.expect(!ids[2].eql(honest));
    try expect_malformed(root, &ids, &contents, .none);
}

test "catalog_of: an index whose chunks do not join into the content is refused" {
    // Goal: the content hash comes from the index's chunks, and one that does not make the id
    // is refused. Method: the same three files; the index lists another hash for the one-chunk
    // file's chunk, and then another chaining value for the two-chunk file's first chunk.
    const contents = contents_three();
    var ids: [3]Digest = undefined;
    const root = try three_files(&contents, .{ 0o644, 0o600, 0o755 }, &ids);
    try expect_malformed(root, &ids, &contents, .{ .hash = 2 });
    try expect_malformed(root, &ids, &contents, .{ .chaining = 0 });
}

fn expect_malformed(
    root: Digest,
    ids: []const Digest,
    contents: []const []const u8,
    lie: Lie,
) !void {
    var built = try build_index(root, ids, contents, lie);
    defer built.deinit();
    const index = try index_mod.parse(built.bytes);
    var table: nodes.Table = undefined;
    const region = try table_of(root, &table);
    defer gpa.free(region);
    const memory = try catalog_memory(&index);
    defer catalog_free(memory);
    try testing.expectError(error.Malformed, resolver.catalog_of(&table, &index, memory));
}

// `ResolverChunks` through `ops`: the server's reads served by the chunk resolver.

const Remote = struct {
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: layout.Store,
    io: [constants.store_io_buffer_bytes]u8,
    blob: []u8,
    range_calls: std.atomic.Value(u32),
    events: [8]lazy.Event,
    events_count: std.atomic.Value(u32),
    resolver: lazy.Resolver,
    request: [256]u8,
    reply: [constants.fuse_reply_bytes]u8 align(8),
};

var remote: Remote = undefined;

fn range_fetch(
    context: *anyopaque,
    offset: u64,
    out: []u8,
    timeout_ms: u32,
) lazy.FetchError!usize {
    assert(context == @as(*anyopaque, &remote));
    assert(timeout_ms > 0);
    _ = remote.range_calls.fetchAdd(1, .monotonic);
    if (offset >= remote.blob.len) return error.Failed;
    const length: usize = @min(out.len, remote.blob.len - offset);
    @memcpy(out[0..length], remote.blob[@intCast(offset)..][0..length]);
    return length;
}

fn log_event(context: *anyopaque, event: *const lazy.Event) void {
    assert(context == @as(*anyopaque, &remote));
    const at = remote.events_count.fetchAdd(1, .monotonic);
    assert(at < remote.events.len);
    remote.events[at] = event.*;
}

fn free_query(context: *anyopaque) u64 {
    assert(context == @as(*anyopaque, &remote));
    return 1 << 40;
}

/// Keeps `content` whole in the store, as an earlier pull would have.
fn store_whole(wanted: *const lazy.Wanted, content: []const u8) !void {
    assert(wanted.hashes.len == 1);
    var failure: chunks_mod.Failure = undefined;
    _ = try chunks_mod.put_chunk(&remote.store, &remote.io, wanted, 0, content, &failure);
}

fn read_file(
    server: *const ops.Server,
    worker: *ops.Worker,
    table: *const nodes.Table,
    name: []const u8,
) []const u8 {
    return read_file_at(server, worker, table, name, 0);
}

fn read_file_at(
    server: *const ops.Server,
    worker: *ops.Worker,
    table: *const nodes.Table,
    name: []const u8,
    offset: u64,
) []const u8 {
    const child = table.lookup(table.node(1).?, name).?;
    const in: abi.ReadIn = .{
        .fh = 0,
        .offset = offset,
        .size = 64,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    const nodeid = @as(u64, child.node) + 1;
    const body = std.mem.asBytes(&in);
    const request = fixture_mod.request(&remote.request, .read, nodeid, 1, &.{body});
    return ops.handle(server, worker, request);
}

test "ResolverChunks: reads through ops come from the store, then the registry, verified" {
    // Goal: a FUSE read of an image that is not all local is served by the resolver. Method:
    // three one-chunk files; `local` is whole in the simulated store, `remote` and `corrupt`
    // only in the registry blob, where one byte of `corrupt`'s range is flipped. The read of
    // `local` asks the registry nothing; `remote` comes from one range and lands in the store;
    // `corrupt` is EIO, with a W1202 event naming the registry and E1203, and nothing landed.
    fixture.init(chunk_bytes);
    _ = fixture.begin();
    const contents = [3][]const u8{ "bytes of a fetched file", "bytes kept locally", "remote!" };
    var ids: [3]Digest = undefined;
    for ([3][]const u8{ "corrupt", "local", "remote" }, contents, &ids) |name, content, *id| {
        id.* = try fixture.file(name, content, 0o644, &xattrs.empty);
    }
    const root = try fixture.finish_root(own);
    var built = try build_index(root, &ids, &contents, .none);
    defer built.deinit();
    const index = try index_mod.parse(built.bytes);
    var table: nodes.Table = undefined;
    const region = try table_of(root, &table);
    defer gpa.free(region);
    const memory = try catalog_memory(&index);
    defer catalog_free(memory);
    const catalog = try resolver.catalog_of(&table, &index, memory);

    open_store();
    try store_whole(&catalog.objects[1].wanted, contents[1]);
    remote.blob = built.blob;
    remote.blob[@intCast(catalog.objects[0].locations[0].offset + 6)] ^= 1;
    try open_resolver(catalog);
    defer remote.resolver.deinit(gpa);
    try remote.resolver.start(testing.io);
    defer remote.resolver.stop();
    try serve_three(&table, &contents);
}

/// The simulated store the resolver lands chunks in, empty.
fn open_store() void {
    remote.host.init(1, &.{});
    remote.files.init(1);
    remote.host.store_fs = &remote.files;
    remote.files.put_dir("/data", 0o755);
    support.make_store_directories(&remote.files, "/data/store");
    remote.store.at(remote.host.interface(), "/data/store");
    remote.store.chunk_bytes = chunk_bytes;
}

/// The resolver over `remote`'s store and blob, with no peers and no fill.
fn open_resolver(catalog: lazy.Catalog) !void {
    remote.range_calls = .init(0);
    remote.events_count = .init(0);
    try remote.resolver.init(gpa, .{
        .store = &remote.store,
        .catalog = catalog,
        .peers = &.{},
        .registry = .{ .context = &remote, .name = "registry", .fetch = range_fetch },
        .log = .{ .context = &remote, .event = log_event },
        .free = .{ .context = &remote, .query = free_query },
        .fill = false,
    });
}

test "ResolverChunks: a chunk whose plain hash the index forged is EIO, and nothing lands" {
    // Goal: a registry cannot serve bytes the signed tree does not cover by listing their plain
    // hash in the index; the chunk's chaining value refuses them. Method: `big` has two
    // chunks; the index lists, for its second, the hash of other bytes, which the blob holds,
    // and the true chaining value, so `catalog_of` accepts it (the chaining values still join
    // into the content). A read of the second chunk is EIO, with W1202 naming the registry and
    // E1203, and the store holds no chunk of `big`. Without the chaining check, the read
    // returns the forged bytes and `partial/<id>/1` keeps them.
    const contents = contents_three();
    var ids: [3]Digest = undefined;
    const root = try three_files(&contents, .{ 0o644, 0o644, 0o644 }, &ids);
    var built = try build_index(root, &ids, &contents, .{ .forged = 0 });
    defer built.deinit();
    const index = try index_mod.parse(built.bytes);
    var table: nodes.Table = undefined;
    const region = try table_of(root, &table);
    defer gpa.free(region);
    const memory = try catalog_memory(&index);
    defer catalog_free(memory);
    const catalog = try resolver.catalog_of(&table, &index, memory);
    try testing.expectEqual(@as(usize, 2), catalog.objects[0].chaining.len);

    open_store();
    remote.blob = built.blob;
    try open_resolver(catalog);
    defer remote.resolver.deinit(gpa);
    try remote.resolver.start(testing.io);
    defer remote.resolver.stop();

    const cache_bytes: usize = @intCast(cache_mod.memory_bytes(chunk_bytes));
    const cache_memory = try gpa.alignedAlloc(u8, .@"8", cache_bytes);
    defer gpa.free(cache_memory);
    var cache: cache_mod.Cache = undefined;
    cache.init(testing.io, cache_memory, chunk_bytes);
    const server: ops.Server = .{ .table = &table, .cache = &cache, .chunk_bytes = chunk_bytes };
    var chunks = resolver.ResolverChunks.init(&remote.resolver, chunk_bytes);
    var worker = ops.Worker.init(chunks.chunks(), &remote.reply);
    const refused = read_file_at(&server, &worker, &table, "big", chunk_bytes);
    try testing.expectEqual(@as(usize, @sizeOf(abi.OutHeader)), refused.len);
    try testing.expectEqual(@as(i32, -5), fixture_mod.reply_header(refused).@"error");
    try testing.expectEqual(lazy.ReadError.Unavailable, chunks.last.?);
    try expect_events(&.{ .lied, .unavailable });
    const report = remote.resolver.report();
    try testing.expectEqual(@as(u64, 0), report.fetched_on_demand_bytes);
    var out: [chunk_bytes]u8 = undefined;
    const wanted = &catalog.objects[0].wanted;
    for (0..2) |chunk| {
        const read = land.read_local(&remote.store, wanted, &.{}, @intCast(chunk), &out, null);
        try testing.expectError(error.NotLocal, read);
    }
}

fn serve_three(table: *const nodes.Table, contents: *const [3][]const u8) !void {
    const cache_bytes: usize = @intCast(cache_mod.memory_bytes(chunk_bytes));
    const cache_memory = try gpa.alignedAlloc(u8, .@"8", cache_bytes);
    defer gpa.free(cache_memory);
    var cache: cache_mod.Cache = undefined;
    cache.init(testing.io, cache_memory, chunk_bytes);
    const server: ops.Server = .{ .table = table, .cache = &cache, .chunk_bytes = chunk_bytes };
    var chunks = resolver.ResolverChunks.init(&remote.resolver, chunk_bytes);
    var worker = ops.Worker.init(chunks.chunks(), &remote.reply);
    const header_bytes = @sizeOf(abi.OutHeader);

    const local = read_file(&server, &worker, table, "local");
    try testing.expectEqualStrings(contents[1], local[header_bytes..]);
    try testing.expectEqual(@as(u32, 0), remote.range_calls.load(.monotonic));
    try testing.expect(chunks.last == null);

    const fetched = read_file(&server, &worker, table, "remote");
    try testing.expectEqualStrings(contents[2], fetched[header_bytes..]);
    try testing.expectEqual(@as(u32, 1), remote.range_calls.load(.monotonic));
    try testing.expect(chunks.last == null);

    const refused = read_file(&server, &worker, table, "corrupt");
    try testing.expectEqual(@as(usize, header_bytes), refused.len);
    try testing.expectEqual(@as(i32, -5), fixture_mod.reply_header(refused).@"error");
    try testing.expectEqual(lazy.ReadError.Unavailable, chunks.last.?);
    const report = remote.resolver.report();
    try testing.expectEqual(@as(u64, 1), report.errors);
    try testing.expectEqual(@as(u64, contents[2].len), report.fetched_on_demand_bytes);
    try testing.expectEqual(@as(u32, 2), report.objects_local);
    try expect_events(&.{ .lied, .unavailable });
}

fn expect_events(kinds: []const lazy.Event.Kind) !void {
    // A worker that drained the queue logs its batch outside the lock, so the read can return
    // before the events reach the log: wait for them, in a bound.
    var waited: u32 = 0;
    while (remote.events_count.load(.acquire) < kinds.len and waited < 5_000) : (waited += 1) {
        std.Io.sleep(testing.io, .fromMilliseconds(1), .awake) catch {};
    }
    const count = remote.events_count.load(.monotonic);
    try testing.expectEqual(kinds.len, count);
    for (kinds, remote.events[0..count]) |kind, event| {
        try testing.expectEqual(kind, event.kind);
        try testing.expectEqual(@as(lazy.ObjectIndex, 0), event.object);
    }
    try testing.expectEqualStrings("registry", remote.events[0].source);
}
