//! demo-s2's reader of a lazy index (docs/decisions/2026-11-14-s2-index-format.md), independent
//! of zbx's: from a pushed manifest, where the index lies in the layer blob, and from the index,
//! where one chunk lies, so the registry can corrupt exactly that chunk in transit (step 6) and
//! count the index's range apart from chunks (step 2). It reads only what the demo needs: the
//! anchor annotation, the header's counts, and the object and chunk records.

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;

pub const annotation = "org.zigbox.lazy-index";
pub const header_bytes = 72;
pub const tree_head_bytes = 36;
pub const object_record_bytes = 48;
pub const chunk_record_bytes = 80;
/// The index's own bound (`constants.lazy_index_bytes_max`).
pub const index_bytes_max = 64 * 1024 * 1024;
/// The empty final fixed block zbx appends to a compressed range, so the stream ends.
pub const range_trailer = [2]u8{ 0x03, 0x00 };

/// Where the index is: its compressed range in the layer blob, and its inflated size.
pub const Anchor = struct {
    blob: [64]u8,
    offset: u64,
    length: u64,
    size: u64,
};

/// The anchor of the first layer that has one; null when the manifest has none.
pub fn anchor_of(arena: std.mem.Allocator, manifest: []const u8) !?Anchor {
    assert(manifest.len > 0);
    const Layer = struct {
        digest: []const u8,
        annotations: ?std.json.ArrayHashMap([]const u8) = null,
    };
    const Manifest = struct { layers: []const Layer };
    const parsed = try std.json.parseFromSliceLeaky(Manifest, arena, manifest, .{
        .ignore_unknown_fields = true,
    });
    for (parsed.layers) |layer| {
        const annotations = layer.annotations orelse continue;
        const text = annotations.map.get(annotation) orelse continue;
        if (layer.digest.len != 71 or !std.mem.startsWith(u8, layer.digest, "sha256:")) {
            return error.BadManifest;
        }
        var anchor: Anchor = .{
            .blob = layer.digest[7..71].*,
            .offset = 0,
            .length = 0,
            .size = 0,
        };
        var fields = std.mem.splitScalar(u8, text, ' ');
        anchor.offset = try field(fields.next(), "offset=");
        anchor.length = try field(fields.next(), "length=");
        anchor.size = try field(fields.next(), "size=");
        if (anchor.length == 0 or anchor.size < header_bytes) return error.BadAnchor;
        if (anchor.size > index_bytes_max) return error.BadAnchor;
        return anchor;
    }
    return null;
}

fn field(text: ?[]const u8, name: []const u8) !u64 {
    assert(name.len > 1);
    const value = text orelse return error.BadAnchor;
    if (!std.mem.startsWith(u8, value, name)) return error.BadAnchor;
    return std.fmt.parseInt(u64, value[name.len..], 10) catch error.BadAnchor;
}

/// Inflates the index from its compressed range; `range` has the `length` bytes and two of room.
pub fn inflate(arena: std.mem.Allocator, range: []u8, size: u64) ![]u8 {
    assert(range.len >= range_trailer.len + 1);
    assert(size <= index_bytes_max);
    const length = range.len - range_trailer.len;
    range[length..][0..range_trailer.len].* = range_trailer;
    const out = try arena.alloc(u8, @intCast(size));
    const window = try arena.create([flate.max_window_len]u8);
    var input: std.Io.Reader = .fixed(range);
    var decompress: flate.Decompress = .init(&input, .raw, window);
    decompress.reader.readSliceAll(out) catch return error.BadIndex;
    return out;
}

/// One chunk of the image as the index places it.
pub const Located = struct {
    /// Its compressed range in the layer blob.
    offset: u64,
    length: u32,
    /// The object it belongs to (`b3:` hex in zbx's lines) and its ordinal there.
    object: [32]u8,
    ordinal: u32,
};

/// The chunk whose BLAKE3 is `hash`; null when the index lists none.
pub fn locate(index: []const u8, hash: *const [32]u8) !?Located {
    if (index.len < header_bytes) return error.BadIndex;
    if (!std.mem.eql(u8, index[0..8], "zbx-lazy")) return error.BadIndex;
    const trees = read_u32(index, 56);
    const objects = read_u32(index, 60);
    const chunks = read_u32(index, 64);
    var at: usize = header_bytes;
    var tree: u32 = 0;
    while (tree < trees) : (tree += 1) {
        if (at + tree_head_bytes > index.len) return error.BadIndex;
        at += tree_head_bytes + read_u32(index, at + 32);
    }
    const objects_at = at;
    const chunks_at = objects_at + @as(usize, objects) * object_record_bytes;
    if (chunks_at + @as(usize, chunks) * chunk_record_bytes > index.len) return error.BadIndex;
    var chunk: u32 = 0;
    while (chunk < chunks) : (chunk += 1) {
        const record_at = chunks_at + @as(usize, chunk) * chunk_record_bytes;
        const record = index[record_at..][0..chunk_record_bytes];
        if (!std.mem.eql(u8, record[0..32], hash)) continue;
        const owner = owner_of(index[objects_at..chunks_at], chunk) orelse return error.BadIndex;
        return .{
            .offset = std.mem.readInt(u64, record[64..72], .little),
            .length = std.mem.readInt(u32, record[72..76], .little),
            .object = owner.id,
            .ordinal = chunk - owner.first,
        };
    }
    return null;
}

const Owner = struct { id: [32]u8, first: u32 };

fn owner_of(objects: []const u8, chunk: u32) ?Owner {
    assert(objects.len % object_record_bytes == 0);
    var at: usize = 0;
    while (at < objects.len) : (at += object_record_bytes) {
        const record = objects[at..][0..object_record_bytes];
        const first = std.mem.readInt(u32, record[40..44], .little);
        const count = std.mem.readInt(u32, record[44..48], .little);
        if (chunk >= first and chunk - first < count) {
            return .{ .id = record[0..32].*, .first = first };
        }
    }
    return null;
}

fn read_u32(bytes: []const u8, at: usize) u32 {
    assert(at + 4 <= bytes.len);
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}

/// A tiny index: one tree, two objects of 1 and 2 chunks, three chunks; for the tests.
fn sample_index(out: []u8) []u8 {
    assert(out.len >= 512);
    @memset(out, 0);
    @memcpy(out[0..8], "zbx-lazy");
    std.mem.writeInt(u32, out[8..12], 1, .little);
    std.mem.writeInt(u32, out[56..60], 1, .little);
    std.mem.writeInt(u32, out[60..64], 2, .little);
    std.mem.writeInt(u32, out[64..68], 3, .little);
    var at: usize = header_bytes;
    std.mem.writeInt(u32, out[at + 32 ..][0..4], 5, .little);
    at += tree_head_bytes + 5;
    for ([_][2]u32{ .{ 0, 1 }, .{ 1, 2 } }, 0..) |span, ordinal| {
        out[at] = @intCast(0xa0 + ordinal);
        std.mem.writeInt(u32, out[at + 40 ..][0..4], span[0], .little);
        std.mem.writeInt(u32, out[at + 44 ..][0..4], span[1], .little);
        at += object_record_bytes;
    }
    for (0..3) |ordinal| {
        out[at] = @intCast(0xc0 + ordinal);
        std.mem.writeInt(u64, out[at + 64 ..][0..8], 1000 * (ordinal + 1), .little);
        std.mem.writeInt(u32, out[at + 72 ..][0..4], @intCast(100 + ordinal), .little);
        at += chunk_record_bytes;
    }
    return out[0..at];
}

test "index_s2: the anchor, the inflate and a chunk's place" {
    // Goal: the harness finds a chunk's compressed range and object from a manifest and the
    // index alone, as zbx writes them.
    // Method: a manifest with the annotation; an index wrapped in a stored deflate block and
    // inflated as zbx does (appending the empty final block); then each chunk by hash.
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const hex = "abababababababababababababababababababababababababababababababab";
    const manifest = "{\"schemaVersion\":2,\"layers\":[{\"digest\":\"sha256:" ++ hex ++ "\"," ++
        "\"annotations\":{\"" ++ annotation ++
        "\":\"offset=10 length=30 size=99 digest=b3:00\"}}]}";
    const anchor = (try anchor_of(arena, manifest)).?;
    try std.testing.expectEqualStrings(hex, &anchor.blob);
    try std.testing.expectEqual(@as(u64, 10), anchor.offset);
    try std.testing.expectEqual(@as(u64, 30), anchor.length);
    try std.testing.expectEqual(@as(u64, 99), anchor.size);
    try std.testing.expect(try anchor_of(arena, "{\"layers\":[{\"digest\":\"x\"}]}") == null);
    var plain: [512]u8 = undefined;
    const index = sample_index(&plain);
    // A stored, non-final block: header byte, LEN, NLEN, the bytes; then room for the trailer.
    var range: [512 + 7]u8 = undefined;
    range[0] = 0;
    std.mem.writeInt(u16, range[1..3], @intCast(index.len), .little);
    std.mem.writeInt(u16, range[3..5], ~@as(u16, @intCast(index.len)), .little);
    @memcpy(range[5..][0..index.len], index);
    const inflated = try inflate(arena, range[0 .. 5 + index.len + 2], index.len);
    try std.testing.expectEqualSlices(u8, index, inflated);
    var hash: [32]u8 = @splat(0);
    hash[0] = 0xc2;
    const found = (try locate(inflated, &hash)).?;
    try std.testing.expectEqual(@as(u64, 3000), found.offset);
    try std.testing.expectEqual(@as(u32, 102), found.length);
    try std.testing.expectEqual(@as(u8, 0xa1), found.object[0]);
    try std.testing.expectEqual(@as(u32, 1), found.ordinal);
    hash[0] = 0xc9;
    try std.testing.expect(try locate(inflated, &hash) == null);
}
