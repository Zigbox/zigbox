//! Tests of the lazy index's format, parser, annotation, checking walk and range inflate. Indexes
//! here come from `Builder`, a plain recursive writer kept apart from the pack's, so the two
//! agree only if both follow the decision (`docs/decisions/2026-11-14-s2-index-format.md`).

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const constants = @import("../constants.zig");
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

/// Writes an index for the tree at `root`: trees and objects at first appearance, in the pack
/// walk's order, each chunk given a 100-byte range after the one before.
pub const Builder = struct {
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
                .dir => try builder.visit(entry.subtree, !builder.seen.contains(entry.subtree.bytes)),
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
        for (0..count) |ordinal| {
            var name: [8]u8 = undefined;
            std.mem.writeInt(u64, &name, ordinal, .little);
            const hash = if (count == 1) entry.content else Digest.of(&name);
            var chunk: [index_mod.chunk_record_bytes]u8 = undefined;
            index_mod.encode_chunk(.{ .hash = hash, .offset = builder.offset, .length = 100 }, &chunk);
            try builder.chunks.appendSlice(gpa, &chunk);
            builder.offset += 100;
            builder.chunk_count += 1;
        }
    }

    /// The index bytes; the caller frees them.
    pub fn build(store: *const Trees, root: Digest) ![]u8 {
        var builder: Builder = .{ .seen = .init(gpa), .store = store };
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

/// A file entry: the content hash is the hash of `fill` repeated `size` times, and the object id
/// is made from it (the walk checks only that ids repeat as objects do).
const FileSpec = struct { name: []const u8, size: u64, fill: u8 };

fn content_of(size: u64, fill: u8) Digest {
    if (size == 0) return Digest.of("");
    var name: [9]u8 = undefined;
    std.mem.writeInt(u64, name[0..8], size, .little);
    name[8] = fill;
    return Digest.of(&name);
}

const Fixture = struct {
    store: Trees,
    root: Digest,
    bytes: []u8,
    anchor: Anchor,

    fn deinit(fixture: *Fixture) void {
        var values = fixture.store.valueIterator();
        while (values.next()) |value| gpa.free(value.*);
        fixture.store.deinit();
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
};

fn add_file(writer: *tree_mod.Writer, spec: FileSpec) !void {
    try writer.begin(spec.name, .file, 0o644, 0, 0, &xattrs.empty);
    const content = content_of(spec.size, spec.fill);
    try writer.end_file(spec.size, content, Digest.of(&content.bytes));
}

/// A root with a shared subtree (`a/` and `b/` are the same tree), a file whose object repeats,
/// an empty file, a three-chunk file and a symlink.
fn fixture_make() !Fixture {
    var fixture: Fixture = .{ .store = .init(gpa), .root = undefined, .bytes = &.{}, .anchor = undefined };
    errdefer fixture.deinit();
    var buffer: [4096]u8 = undefined;
    var writer = tree_mod.Writer.init(&buffer);
    try add_file(&writer, .{ .name = "one", .size = 5, .fill = 'x' });
    try add_file(&writer, .{ .name = "two", .size = 5, .fill = 'x' });
    const leaf = try fixture.put(writer.finish());
    writer = tree_mod.Writer.init(&buffer);
    try writer.begin("a", .dir, 0o755, 0, 0, &xattrs.empty);
    try writer.end_dir(leaf);
    try writer.begin("b", .dir, 0o755, 0, 0, &xattrs.empty);
    try writer.end_dir(leaf);
    try add_file(&writer, .{ .name = "big", .size = 3 * constants.store_chunk_bytes - 1, .fill = 'y' });
    try add_file(&writer, .{ .name = "empty", .size = 0, .fill = 0 });
    try add_file(&writer, .{ .name = "same", .size = 5, .fill = 'x' });
    try writer.begin("z", .symlink, 0o777, 0, 0, &xattrs.empty);
    try writer.end_symlink("one");
    fixture.root = try fixture.put(writer.finish());
    fixture.bytes = try Builder.build(&fixture.store, fixture.root);
    fixture.anchor_for();
    return fixture;
}

fn verify_bytes(fixture: *Fixture) index_mod.Refusal!index_mod.Index {
    const ws = gpa.create(verify_mod.Workspace) catch @panic("out of memory");
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
    index_mod.encode_object(.{ .id = Digest.of("o"), .size = size, .first_chunk = 0, .chunk_count = count }, &record);
    try out.appendSlice(gpa, &record);
    for (ranges) |range| {
        var chunk: [index_mod.chunk_record_bytes]u8 = @splat(0);
        std.mem.writeInt(u64, chunk[32..40], range[0], .little);
        std.mem.writeInt(u32, chunk[40..44], @intCast(range[1]), .little);
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
    try testing.expectError(error.Malformed, index_mod.parse(bytes[0..constants.lazy_index_bytes_max]));
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
    const texts = [_][]const u8{ "the first segment, the first segment", "a second one", &repeated };
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
        try testing.expectError(error.Malformed, index_mod.inflate_range(&range, length, out[0 .. text.len - 1], &inflate_window));
        try testing.expectError(error.Malformed, index_mod.inflate_range(&range, length, out[0 .. text.len + 1], &inflate_window));
    }
}
