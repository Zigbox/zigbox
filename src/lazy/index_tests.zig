//! Tests of the lazy index's format, parser, annotation, checking walk and range inflate. Indexes
//! here come from `Builder`, a plain recursive writer kept apart from the pack's, so the two
//! agree only if both follow the decision (`docs/decisions/2026-11-14-s2-index-format.md`).

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const constants = @import("../constants.zig");
const chaining = @import("chaining.zig");
const index_mod = @import("index.zig");
const verify_mod = @import("verify.zig");
const tree_mod = @import("../store/tree.zig");
const xattrs = @import("../store/xattrs.zig");
const Digest = @import("../store/digest.zig").Digest;

const testing = std.testing;
const gpa = testing.allocator;
const Anchor = index_mod.Anchor;

/// Trees by digest, as a test's store.
const Trees = std.AutoHashMap([32]u8, []u8);

/// The fill byte of each file of two chunks or more, by content hash: such a file's content and
/// chunks are real, so its chaining values join into its content.
const Fills = std.AutoHashMap([32]u8, u8);

/// Writes an index for the tree at `root`: trees and objects at first appearance, in the pack
/// walk's order, each chunk given a 100-byte range after the one before.
pub const Builder = struct {
    fills: *const Fills,
    trees: std.ArrayList(u8) = .empty,
    objects: std.ArrayList(u8) = .empty,
    chunks: std.ArrayList(u8) = .empty,
    seen: std.AutoHashMap([32]u8, void),
    store: *const Trees,
    names: u32 = 0,
    tree_count: u32 = 0,
    object_count: u32 = 0,
    chunk_count: u32 = 0,
    offset: u64 = index_mod.gzip_header_bytes,

    pub fn deinit(builder: *Builder) void {
        builder.trees.deinit(gpa);
        builder.objects.deinit(gpa);
        builder.chunks.deinit(gpa);
        builder.seen.deinit();
    }

    fn visit(builder: *Builder, digest: Digest, record: bool) !void {
        const bytes = builder.store.get(digest.bytes).?;
        if (record) {
            try builder.seen.put(digest.bytes, {});
            var head: [index_mod.tree_head_bytes]u8 = undefined;
            index_mod.encode_tree_head(digest, @intCast(bytes.len), &head);
            try builder.trees.appendSlice(gpa, &head);
            try builder.trees.appendSlice(gpa, bytes);
            builder.tree_count += 1;
        }
        var decoder: tree_mod.Decoder = undefined;
        try decoder.init(bytes);
        var entry: tree_mod.Entry = undefined;
        while (try decoder.next(&entry)) {
            builder.names += 1;
            switch (entry.kind) {
                .symlink => {},
                .file => try builder.file(&entry),
                .dir => {
                    const first = !builder.seen.contains(entry.subtree.bytes);
                    try builder.visit(entry.subtree, first);
                },
            }
        }
    }

    fn file(builder: *Builder, entry: *const tree_mod.Entry) !void {
        if (builder.seen.contains(entry.object.bytes)) return;
        try builder.seen.put(entry.object.bytes, {});
        const count = index_mod.chunk_count(entry.size);
        var record: [index_mod.object_record_bytes]u8 = undefined;
        index_mod.encode_object(.{
            .id = entry.object,
            .size = entry.size,
            .first_chunk = builder.chunk_count,
            .chunk_count = count,
        }, &record);
        try builder.objects.appendSlice(gpa, &record);
        builder.object_count += 1;
        if (count == 1) try builder.chunk(.{ .hash = entry.content, .chaining = zero });
        if (count < 2) return;
        const fill = builder.fills.get(entry.content.bytes).?;
        const bytes = try gpa.alloc(u8, constants.store_chunk_bytes);
        defer gpa.free(bytes);
        @memset(bytes, fill);
        for (0..count) |ordinal| {
            const start = ordinal * constants.store_chunk_bytes;
            const length = @min(entry.size - start, constants.store_chunk_bytes);
            const run = bytes[0..@intCast(length)];
            try builder.chunk(.{
                .hash = Digest.of(run),
                .chaining = chaining.run_value(run, ordinal, constants.store_chunk_bytes),
            });
        }
    }

    fn chunk(builder: *Builder, hashes: struct { hash: Digest, chaining: Digest }) !void {
        var record: [index_mod.chunk_record_bytes]u8 = undefined;
        index_mod.encode_chunk(.{
            .hash = hashes.hash,
            .chaining = hashes.chaining,
            .offset = builder.offset,
            .length = 100,
        }, &record);
        try builder.chunks.appendSlice(gpa, &record);
        builder.offset += 100;
        builder.chunk_count += 1;
    }

    /// The index bytes; the caller frees them.
    pub fn build(store: *const Trees, fills: *const Fills, root: Digest) ![]u8 {
        var builder: Builder = .{ .seen = .init(gpa), .store = store, .fills = fills };
        defer builder.deinit();
        try builder.visit(root, true);
        const header: index_mod.Header = .{
            .complete = true,
            .tree = root,
            .names = builder.names,
            .trees = builder.tree_count,
            .objects = builder.object_count,
            .chunks = builder.chunk_count,
            .order = 0,
        };
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        var head: [index_mod.header_bytes]u8 = undefined;
        header.encode(&head);
        try out.appendSlice(gpa, &head);
        try out.appendSlice(gpa, builder.trees.items);
        try out.appendSlice(gpa, builder.objects.items);
        try out.appendSlice(gpa, builder.chunks.items);
        return out.toOwnedSlice(gpa);
    }
};

const zero: Digest = .{ .bytes = @splat(0) };

/// A file entry: the content hash stands for `fill` repeated `size` times, and the object id
/// is made from it (the walk checks only that ids repeat as objects do). It is the real hash for
/// an empty file and a file of two chunks or more, whose chunks are anchored to it.
const FileSpec = struct { name: []const u8, size: u64, fill: u8 };

fn content_of(size: u64, fill: u8) !Digest {
    if (size == 0) return Digest.of("");
    if (size > constants.store_chunk_bytes) {
        const bytes = try gpa.alloc(u8, @intCast(size));
        defer gpa.free(bytes);
        @memset(bytes, fill);
        return Digest.of(bytes);
    }
    var name: [9]u8 = undefined;
    std.mem.writeInt(u64, name[0..8], size, .little);
    name[8] = fill;
    return Digest.of(&name);
}

const Fixture = struct {
    store: Trees,
    fills: Fills,
    root: Digest,
    bytes: []u8,
    anchor: Anchor,

    fn deinit(fixture: *Fixture) void {
        var values = fixture.store.valueIterator();
        while (values.next()) |value| gpa.free(value.*);
        fixture.store.deinit();
        fixture.fills.deinit();
        gpa.free(fixture.bytes);
    }

    fn put(fixture: *Fixture, bytes: []const u8) !Digest {
        const digest = Digest.of(bytes);
        const owned = try gpa.dupe(u8, bytes);
        const old = try fixture.store.fetchPut(digest.bytes, owned);
        if (old) |entry| gpa.free(entry.value);
        return digest;
    }

    fn anchor_for(fixture: *Fixture) void {
        fixture.anchor = .{
            .offset = 1 << 20,
            .length = 400,
            .size = fixture.bytes.len,
            .digest = Digest.of(fixture.bytes),
        };
    }

    fn add_file(fixture: *Fixture, writer: *tree_mod.Writer, spec: FileSpec) !void {
        try writer.begin(spec.name, .file, 0o644, 0, 0, &xattrs.empty);
        const content = try content_of(spec.size, spec.fill);
        if (spec.size > constants.store_chunk_bytes) {
            try fixture.fills.put(content.bytes, spec.fill);
        }
        try writer.end_file(spec.size, content, Digest.of(&content.bytes));
    }
};

/// A root with a shared subtree (`a/` and `b/` are the same tree), a file whose object repeats,
/// an empty file, a three-chunk file and a symlink.
fn fixture_make() !Fixture {
    var fixture: Fixture = .{
        .store = .init(gpa),
        .fills = .init(gpa),
        .root = undefined,
        .bytes = &.{},
        .anchor = undefined,
    };
    errdefer fixture.deinit();
    var buffer: [4096]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    try fixture.add_file(&writer, .{ .name = "one", .size = 5, .fill = 'x' });
    try fixture.add_file(&writer, .{ .name = "two", .size = 5, .fill = 'x' });
    const leaf = try fixture.put(writer.finish());
    writer = tree_mod.Writer.init(&buffer);
    try writer.begin("a", .dir, 0o755, 0, 0, &xattrs.empty);
    try writer.end_dir(leaf);
    try writer.begin("b", .dir, 0o755, 0, 0, &xattrs.empty);
    try writer.end_dir(leaf);
    const big_size = 3 * constants.store_chunk_bytes - 1;
    try fixture.add_file(&writer, .{ .name = "big", .size = big_size, .fill = 'y' });
    try fixture.add_file(&writer, .{ .name = "empty", .size = 0, .fill = 0 });
    try fixture.add_file(&writer, .{ .name = "same", .size = 5, .fill = 'x' });
    try writer.begin("z", .symlink, 0o777, 0, 0, &xattrs.empty);
    try writer.end_symlink("one");
    fixture.root = try fixture.put(writer.finish());
    fixture.bytes = try Builder.build(&fixture.store, &fixture.fills, fixture.root);
    fixture.anchor_for();
    return fixture;
}

fn verify_bytes(fixture: *Fixture) index_mod.Refusal!index_mod.Index {
    const ws = gpa.create(verify_mod.Workspace) catch @panic("out of memory");
    ws.key = @splat(5);
    defer gpa.destroy(ws);
    return verify_mod.verify(ws, fixture.bytes, &fixture.anchor, fixture.root);
}

test "a built index verifies, and lists each tree and object once" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    const index = try verify_bytes(&fixture);
    // Names: root (a, b, big, empty, same, z) and two in each of a and b.
    try testing.expectEqual(10, index.header.names);
    try testing.expectEqual(2, index.header.trees);
    try testing.expectEqual(3, index.header.objects);
    try testing.expectEqual(1 + 3 + 0, index.header.chunks);
    try testing.expectEqual(3, index.object(1).chunk_count);
    try testing.expectEqual(0, index.object(2).chunk_count);
}

/// Re-hashes the fixture's bytes after a change, so the change reaches the structural checks.
fn expect_refused(fixture: *Fixture, refusal: index_mod.Refusal) !void {
    fixture.anchor_for();
    try testing.expectError(refusal, verify_bytes(fixture));
}

fn put_u32(bytes: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .little);
}

test "verify refuses wrong bytes, a wrong tree and a wrong count" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    fixture.bytes[100] ^= 1;
    try testing.expectError(error.Malformed, verify_bytes(&fixture));
    fixture.bytes[100] ^= 1;
    fixture.anchor.size += 1;
    try testing.expectError(error.Malformed, verify_bytes(&fixture));
    fixture.anchor_for();
    const root = fixture.root;
    fixture.root = Digest.of("another");
    try testing.expectError(error.Malformed, verify_bytes(&fixture));
    fixture.root = root;
    put_u32(fixture.bytes, 52, 9);
    try expect_refused(&fixture, error.Malformed);
    put_u32(fixture.bytes, 52, 11);
    try expect_refused(&fixture, error.Malformed);
    put_u32(fixture.bytes, 52, 10);
    fixture.anchor_for();
    fixture.anchor.offset = fixture.anchor.offset - (1 << 20) + 10 + 4 * 100 - 1;
    try testing.expectError(error.Malformed, verify_bytes(&fixture));
    fixture.anchor.offset += 1;
    _ = try verify_bytes(&fixture);
}

test "verify refuses objects out of the walk's order and a tree listed twice" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    const objects_at = fixture.bytes.len - 4 * index_mod.chunk_record_bytes -
        3 * index_mod.object_record_bytes;
    // Swap the ids of the first two objects.
    const first: [32]u8 = fixture.bytes[objects_at..][0..32].*;
    const second_at = objects_at + index_mod.object_record_bytes;
    @memcpy(fixture.bytes[objects_at..][0..32], fixture.bytes[second_at..][0..32]);
    @memcpy(fixture.bytes[second_at..][0..32], &first);
    try expect_refused(&fixture, error.Malformed);
    @memcpy(fixture.bytes[second_at..][0..32], fixture.bytes[objects_at..][0..32]);
    @memcpy(fixture.bytes[objects_at..][0..32], &first);
    fixture.anchor_for();
    _ = try verify_bytes(&fixture);
    // A one-chunk file's chunk hash is its content.
    const chunks_at = fixture.bytes.len - 4 * index_mod.chunk_record_bytes;
    fixture.bytes[chunks_at] ^= 1;
    try expect_refused(&fixture, error.Malformed);
}

test "verify anchors a longer file's chunks to its content" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    const chunks_at = fixture.bytes.len - 4 * index_mod.chunk_record_bytes;
    const record = index_mod.chunk_record_bytes;
    // A forged chaining value of the three-chunk file, in its first, middle and last chunk.
    for (1..4) |chunk| {
        const at = chunks_at + chunk * record + 32;
        fixture.bytes[at + 5] ^= 1;
        try expect_refused(&fixture, error.Malformed);
        fixture.bytes[at + 5] ^= 1;
    }
    // Two chunks swapped: each value is right for some place, but not for this one.
    const first = chunks_at + 1 * record + 32;
    const second = chunks_at + 2 * record + 32;
    var held: [32]u8 = fixture.bytes[first..][0..32].*;
    @memcpy(fixture.bytes[first..][0..32], fixture.bytes[second..][0..32]);
    @memcpy(fixture.bytes[second..][0..32], &held);
    try expect_refused(&fixture, error.Malformed);
    @memcpy(fixture.bytes[second..][0..32], fixture.bytes[first..][0..32]);
    @memcpy(fixture.bytes[first..][0..32], &held);
    // A one-chunk file's chaining field is zero.
    fixture.bytes[chunks_at + 32] = 1;
    try expect_refused(&fixture, error.Malformed);
    fixture.bytes[chunks_at + 32] = 0;
    fixture.anchor_for();
    _ = try verify_bytes(&fixture);
}

/// The fixture's bytes with `extra` inserted at `at`, and the header's count at `count_at` one
/// more; the caller frees them.
fn with_record(bytes: []const u8, at: usize, extra: []const u8, count_at: usize) ![]u8 {
    const out = try gpa.alloc(u8, bytes.len + extra.len);
    @memcpy(out[0..at], bytes[0..at]);
    @memcpy(out[at..][0..extra.len], extra);
    @memcpy(out[at + extra.len ..], bytes[at..]);
    const count = std.mem.readInt(u32, out[count_at..][0..4], .little);
    put_u32(out, count_at, count + 1);
    return out;
}

test "verify refuses a trailing tree record and a trailing object record" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    const objects_at = fixture.bytes.len - 4 * index_mod.chunk_record_bytes -
        3 * index_mod.object_record_bytes;
    var buffer: [64]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    const tree = writer.finish();
    var tree_record: [index_mod.tree_head_bytes + 64]u8 = undefined;
    const head = tree_record[0..index_mod.tree_head_bytes];
    index_mod.encode_tree_head(Digest.of(tree), @intCast(tree.len), head);
    @memcpy(tree_record[index_mod.tree_head_bytes..][0..tree.len], tree);
    const tree_bytes = tree_record[0 .. index_mod.tree_head_bytes + tree.len];
    const original = fixture.bytes;
    defer fixture.bytes = original;
    fixture.bytes = try with_record(original, objects_at, tree_bytes, 56);
    _ = try index_mod.parse(fixture.bytes);
    try expect_refused(&fixture, error.Malformed);
    gpa.free(fixture.bytes);
    // An empty object after the last, its first chunk the running count.
    var object: [index_mod.object_record_bytes]u8 = undefined;
    index_mod.encode_object(.{
        .id = Digest.of("never named"),
        .size = 0,
        .first_chunk = 4,
        .chunk_count = 0,
    }, &object);
    const chunks_at = original.len - 4 * index_mod.chunk_record_bytes;
    fixture.bytes = try with_record(original, chunks_at, &object, 60);
    defer gpa.free(fixture.bytes);
    _ = try index_mod.parse(fixture.bytes);
    try expect_refused(&fixture, error.Malformed);
}

test "verify refuses an empty file whose content is not the empty hash" {
    var fixture = try fixture_make();
    defer fixture.deinit();
    var buffer: [256]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    try writer.begin("empty", .file, 0o644, 0, 0, &xattrs.empty);
    const content = Digest.of("not empty");
    try writer.end_file(0, content, Digest.of(&content.bytes));
    fixture.root = try fixture.put(writer.finish());
    gpa.free(fixture.bytes);
    fixture.bytes = try Builder.build(&fixture.store, &fixture.fills, fixture.root);
    try expect_refused(&fixture, error.Malformed);
}

/// A header and `trees` copies of the empty tree's record, with `names` names.
fn trees_only(names: u32, trees: u32) ![]u8 {
    var buffer: [64]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    const tree = writer.finish();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var head: [index_mod.header_bytes]u8 = undefined;
    const header: index_mod.Header = .{
        .complete = true,
        .tree = Digest.of(tree),
        .names = names,
        .trees = trees,
        .objects = 0,
        .chunks = 0,
        .order = 0,
    };
    header.encode(&head);
    try out.appendSlice(gpa, &head);
    for (0..trees) |_| {
        var tree_head: [index_mod.tree_head_bytes]u8 = undefined;
        index_mod.encode_tree_head(Digest.of(tree), @intCast(tree.len), &tree_head);
        try out.appendSlice(gpa, &tree_head);
        try out.appendSlice(gpa, tree);
    }
    return out.toOwnedSlice(gpa);
}

test "parse: trees at most one more than names, and the order section empty in version 1" {
    for ([_][3]u32{ .{ 0, 1, 1 }, .{ 0, 2, 0 }, .{ 1, 2, 1 }, .{ 1, 3, 0 } }) |case| {
        const bytes = try trees_only(case[0], case[1]);
        defer gpa.free(bytes);
        if (case[2] == 1) {
            _ = try index_mod.parse(bytes);
        } else {
            try testing.expectError(error.Malformed, index_mod.parse(bytes));
        }
    }
    const bytes = try trees_only(0, 1);
    defer gpa.free(bytes);
    put_u32(bytes, 68, 1);
    const longer = try gpa.alloc(u8, bytes.len + index_mod.order_record_bytes);
    defer gpa.free(longer);
    @memcpy(longer[0..bytes.len], bytes);
    @memset(longer[bytes.len..], 0);
    try testing.expectError(error.Malformed, index_mod.parse(longer));
}

test "parse: a stub is too large, a malformed stub is malformed" {
    var bytes: [index_mod.header_bytes]u8 = undefined;
    const stub: index_mod.Header = .{
        .complete = false,
        .tree = Digest.of("t"),
        .names = constants.lazy_nodes_max + 1,
        .trees = 0,
        .objects = 0,
        .chunks = 0,
        .order = 0,
    };
    stub.encode(&bytes);
    try testing.expectError(error.TooLarge, index_mod.parse(&bytes));
    put_u32(&bytes, 56, 1);
    try testing.expectError(error.Malformed, index_mod.parse(&bytes));
    put_u32(&bytes, 56, 0);
    put_u32(&bytes, 12, 2);
    try testing.expectError(error.Malformed, index_mod.parse(&bytes));
    put_u32(&bytes, 12, 0);
    put_u32(&bytes, 48, constants.store_chunk_bytes / 2);
    try testing.expectError(error.Malformed, index_mod.parse(&bytes));
    put_u32(&bytes, 48, constants.store_chunk_bytes);
    bytes[0] = 'Z';
    try testing.expectError(error.Malformed, index_mod.parse(&bytes));
    try testing.expectError(error.Malformed, index_mod.parse(bytes[0 .. bytes.len - 1]));
}

/// A one-tree index whose root lists no files, with `chunks` chunk records in an object of the
/// right size; the caller edits it.
fn small_index(names: u32, ranges: []const [2]u64) ![]u8 {
    var buffer: [64]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    const tree = writer.finish();
    const count: u32 = @intCast(ranges.len);
    const size: u64 = if (count == 0) 0 else @as(u64, count) * constants.store_chunk_bytes;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var head: [index_mod.header_bytes]u8 = undefined;
    const header: index_mod.Header = .{
        .complete = true,
        .tree = Digest.of(tree),
        .names = 0,
        .trees = 1,
        .objects = 1,
        .chunks = count,
        .order = 0,
    };
    header.encode(&head);
    put_u32(&head, 52, names); // Past the bound too, which `encode` never writes.
    try out.appendSlice(gpa, &head);
    var tree_head: [index_mod.tree_head_bytes]u8 = undefined;
    index_mod.encode_tree_head(Digest.of(tree), @intCast(tree.len), &tree_head);
    try out.appendSlice(gpa, &tree_head);
    try out.appendSlice(gpa, tree);
    var record: [index_mod.object_record_bytes]u8 = undefined;
    const object: index_mod.Object = .{
        .id = Digest.of("o"),
        .size = size,
        .first_chunk = 0,
        .chunk_count = count,
    };
    index_mod.encode_object(object, &record);
    try out.appendSlice(gpa, &record);
    for (ranges) |range| {
        var chunk: [index_mod.chunk_record_bytes]u8 = @splat(0);
        std.mem.writeInt(u64, chunk[64..72], range[0], .little);
        std.mem.writeInt(u32, chunk[72..76], @intCast(range[1]), .little);
        try out.appendSlice(gpa, &chunk);
    }
    return out.toOwnedSlice(gpa);
}

fn expect_parse(names: u32, ranges: []const [2]u64, expected: ?index_mod.Refusal) !void {
    const bytes = try small_index(names, ranges);
    defer gpa.free(bytes);
    if (expected) |refusal| {
        try testing.expectError(refusal, index_mod.parse(bytes));
    } else {
        _ = try index_mod.parse(bytes);
    }
}

test "parse: names, range lengths and offsets at their bounds and one past" {
    const max = constants.lazy_range_bytes_max;
    try expect_parse(constants.lazy_nodes_max, &.{.{ 10, 1 }}, null);
    try expect_parse(constants.lazy_nodes_max + 1, &.{.{ 10, 1 }}, error.TooLarge);
    try expect_parse(1, &.{.{ 10, max }}, null);
    try expect_parse(1, &.{.{ 10, max + 1 }}, error.Malformed);
    try expect_parse(1, &.{.{ 10, 0 }}, error.Malformed);
    try expect_parse(1, &.{.{ 9, 1 }}, error.Malformed);
    try expect_parse(1, &.{ .{ 10, 5 }, .{ 15, 5 } }, null);
    try expect_parse(1, &.{ .{ 10, 5 }, .{ 14, 5 } }, error.Malformed);
    try expect_parse(1, &.{ .{ 10, 5 }, .{ std.math.maxInt(u64) - 4, 5 } }, error.Malformed);
    try expect_parse(0, &.{.{ 10, 1 }}, error.Malformed); // One object, no names.
}

test "parse: an index one byte past its bound is too large" {
    const bytes = try gpa.alloc(u8, constants.lazy_index_bytes_max + 1);
    defer gpa.free(bytes);
    @memset(bytes, 0);
    try testing.expectError(error.TooLarge, index_mod.parse(bytes));
    const most = bytes[0..constants.lazy_index_bytes_max];
    try testing.expectError(error.Malformed, index_mod.parse(most));
}

test "parse: chunk counts must fit sizes and run without gaps; trailing bytes are refused" {
    const bytes = try small_index(1, &.{ .{ 10, 5 }, .{ 15, 5 } });
    defer gpa.free(bytes);
    const object_at = bytes.len - 2 * index_mod.chunk_record_bytes - index_mod.object_record_bytes;
    put_u32(bytes, object_at + 44, 1);
    try testing.expectError(error.Malformed, index_mod.parse(bytes));
    put_u32(bytes, object_at + 44, 2);
    put_u32(bytes, object_at + 40, 1);
    try testing.expectError(error.Malformed, index_mod.parse(bytes));
    put_u32(bytes, object_at + 40, 0);
    put_u32(bytes, bytes.len - 4, 1); // A chunk's zero field.
    try testing.expectError(error.Malformed, index_mod.parse(bytes));
    put_u32(bytes, bytes.len - 4, 0);
    _ = try index_mod.parse(bytes);
    const longer = try gpa.alloc(u8, bytes.len + 1);
    defer gpa.free(longer);
    @memcpy(longer[0..bytes.len], bytes);
    longer[bytes.len] = 0;
    try testing.expectError(error.Malformed, index_mod.parse(longer));
}

test "anchor: renders and parses back, and refuses every other spelling" {
    const anchor: Anchor = .{ .offset = 10, .length = 1, .size = 72, .digest = Digest.of("i") };
    var out: [index_mod.anchor_text_bytes_max]u8 = undefined;
    const text = anchor.render(&out);
    const back = Anchor.parse(text).?;
    try testing.expectEqual(anchor.offset, back.offset);
    try testing.expect(back.digest.eql(anchor.digest));
    const hex = anchor.digest.text();
    const wrong = [_][]const u8{
        "offset=010 length=1 size=72 digest=",
        "offset=10  length=1 size=72 digest=",
        "length=1 offset=10 size=72 digest=",
        "offset=10 length=1 size=72 digest=b3:",
        "offset=10 length=1 size=99999999999999999999 digest=",
        "offset=10 length=-1 size=72 digest=",
        "offset=10 length=1 size=72 digest= ",
    };
    for (wrong) |prefix| {
        var line: [256]u8 = undefined;
        const value = try std.fmt.bufPrint(&line, "{s}{s}", .{ prefix, &hex });
        try testing.expectEqual(null, Anchor.parse(value));
    }
    var upper = out;
    upper[text.len - 1] = std.ascii.toUpper(upper[text.len - 1]);
    if (upper[text.len - 1] != out[text.len - 1]) {
        try testing.expectEqual(null, Anchor.parse(upper[0..text.len]));
    }
    const largest: Anchor = .{
        .offset = std.math.maxInt(u64),
        .length = std.math.maxInt(u64),
        .size = std.math.maxInt(u64),
        .digest = anchor.digest,
    };
    try testing.expectEqual(index_mod.anchor_text_bytes_max, largest.render(&out).len);
}

test "anchor: bounds at their limit and one past" {
    var anchor: Anchor = .{ .offset = 10, .length = 1, .size = 72, .digest = Digest.of("i") };
    try anchor.check();
    anchor.offset = 9;
    try testing.expectError(error.Malformed, anchor.check());
    anchor.offset = 10;
    anchor.size = 71;
    try testing.expectError(error.Malformed, anchor.check());
    anchor.size = constants.lazy_index_bytes_max;
    try anchor.check();
    anchor.size += 1;
    try testing.expectError(error.TooLarge, anchor.check());
    anchor.size = 72;
    anchor.length = index_mod.compressed_bytes_max;
    try anchor.check();
    anchor.length += 1;
    try testing.expectError(error.TooLarge, anchor.check());
    anchor.length = 0;
    try testing.expectError(error.Malformed, anchor.check());
}

const repeated: [3000]u8 = @splat('x');

test "inflate_range: each segment written by a fresh compressor inflates alone" {
    var window: [flate.max_window_len]u8 = undefined;
    var inflate_window: [flate.max_window_len]u8 = undefined;
    var compressed: [64 * 1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&compressed);
    const texts = [_][]const u8{
        "the first segment, the first segment",
        "a second one",
        &repeated,
    };
    var ends: [texts.len + 1]usize = undefined;
    ends[0] = 0;
    for (texts, 1..) |text, at| {
        var compressor = try flate.Compress.init(&sink, &window, .raw, .default);
        try compressor.writer.writeAll(text);
        try compressor.writer.flush();
        ends[at] = sink.end;
    }
    for (texts, 0..) |text, at| {
        var range: [8192]u8 = undefined;
        const length = ends[at + 1] - ends[at];
        @memcpy(range[0..length], compressed[ends[at]..ends[at + 1]]);
        var out: [4096]u8 = undefined;
        try index_mod.inflate_range(&range, length, out[0..text.len], &inflate_window);
        try testing.expectEqualStrings(text, out[0..text.len]);
        // One byte too few or too many is refused.
        const fewer = out[0 .. text.len - 1];
        const more = out[0 .. text.len + 1];
        const inflate = index_mod.inflate_range;
        try testing.expectError(error.Malformed, inflate(&range, length, fewer, &inflate_window));
        try testing.expectError(error.Malformed, inflate(&range, length, more, &inflate_window));
    }
}
