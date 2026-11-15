//! The lazy index: what layer writer 2 appends after the tar's end-of-archive, inside the layer's
//! one gzip stream, so that a reader can fetch a tree's directories and any file's chunks without
//! the rest of the layer. The format, byte for byte, is
//! `docs/decisions/2026-11-14-s2-index-format.md`; this file is its encoder pieces, its strict
//! parser, the annotation that points at it and the inflate of one compressed range. The walk
//! that checks an index against its tree is `verify.zig`.
//!
//! Pure: no store, no I/O, no clock. The parser refuses everything the writer cannot write, and
//! sorts what it refuses into too large (`E1207`: the image is fine, lazy start is not for it)
//! and malformed (`E1202`: the registry sent something no `zbx` writes).

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");

const Digest = digest_mod.Digest;

pub const magic = "zbx-lazy";
pub const format_version: u32 = 1;
pub const header_bytes: u32 = 72;
/// A tree record's fixed part: digest and length; the tree's bytes follow.
pub const tree_head_bytes: u32 = 36;
pub const object_record_bytes: u32 = 48;
pub const chunk_record_bytes: u32 = 80;
pub const order_record_bytes: u32 = 4;
/// The gzip header std writes; no compressed range can start inside it.
pub const gzip_header_bytes: u32 = 10;
/// The largest file an index lists: the store's own bound.
pub const file_bytes_max: u64 = constants.store_file_bytes_max;
/// The compressed length an index can have: deflate's fixed codes spend at most nine bits on a
/// byte, so no block std writes is longer than that, plus block headers and the flush.
pub const compressed_bytes_max: u64 =
    constants.lazy_index_bytes_max + constants.lazy_index_bytes_max / 8 + 4096;
/// The longest annotation value `Anchor.render` writes.
pub const anchor_text_bytes_max: u32 = "offset= length= size= digest=".len + 3 * 20 +
    constants.store_digest_text_bytes;
/// The bytes `inflate_range` appends: an empty final fixed block, so the stream ends.
pub const range_trailer = [2]u8{ 0x03, 0x00 };
pub const range_trailer_bytes: u32 = range_trailer.len;

comptime {
    assert(header_bytes == magic.len + 4 * 2 + constants.store_digest_bytes + 4 * 6);
    assert(tree_head_bytes == constants.store_digest_bytes + 4);
    assert(object_record_bytes == constants.store_digest_bytes + 8 + 4 + 4);
    assert(chunk_record_bytes == 2 * constants.store_digest_bytes + 8 + 4 + 4);
    assert(constants.store_chunk_bytes <= constants.lazy_range_bytes_max);
    assert(compressed_bytes_max < std.math.maxInt(u32));
}

/// Why an index is refused: it is past a bound (the image is pulled whole), or it is not what
/// any writer writes.
pub const Refusal = error{ Malformed, TooLarge };

pub const Header = struct {
    /// False for a stub: the writer's tree was past a bound, and only `tree` and `names` count.
    complete: bool,
    tree: Digest,
    names: u32,
    trees: u32,
    objects: u32,
    chunks: u32,
    order: u32,

    pub fn encode(header: *const Header, out: *[header_bytes]u8) void {
        if (header.complete) {
            assert(header.names <= constants.lazy_nodes_max);
        } else {
            assert(header.trees + header.objects + header.chunks == 0);
        }
        @memcpy(out[0..8], magic);
        std.mem.writeInt(u32, out[8..12], format_version, .little);
        std.mem.writeInt(u32, out[12..16], @intFromBool(header.complete), .little);
        @memcpy(out[16..48], &header.tree.bytes);
        std.mem.writeInt(u32, out[48..52], constants.store_chunk_bytes, .little);
        std.mem.writeInt(u32, out[52..56], header.names, .little);
        std.mem.writeInt(u32, out[56..60], header.trees, .little);
        std.mem.writeInt(u32, out[60..64], header.objects, .little);
        std.mem.writeInt(u32, out[64..68], header.chunks, .little);
        std.mem.writeInt(u32, out[68..72], header.order, .little);
    }

    /// Reads the fixed fields; the caller checks the counts against the bytes.
    fn decode(bytes: *const [header_bytes]u8) Refusal!Header {
        assert(bytes.len == header_bytes);
        assert(magic.len == 8);
        if (!std.mem.eql(u8, bytes[0..8], magic)) return error.Malformed;
        if (read_u32(bytes, 8) != format_version) return error.Malformed;
        const complete = read_u32(bytes, 12);
        if (complete > 1) return error.Malformed;
        if (read_u32(bytes, 48) != constants.store_chunk_bytes) return error.Malformed;
        return .{
            .complete = complete == 1,
            .tree = .{ .bytes = bytes[16..48].* },
            .names = read_u32(bytes, 52),
            .trees = read_u32(bytes, 56),
            .objects = read_u32(bytes, 60),
            .chunks = read_u32(bytes, 64),
            .order = read_u32(bytes, 68),
        };
    }
};

pub const TreeRecord = struct {
    digest: Digest,
    bytes: []const u8,
};

pub const Object = struct {
    id: Digest,
    size: u64,
    first_chunk: u32,
    chunk_count: u32,
};

pub const Chunk = struct {
    /// The chunk's BLAKE3, as the store's chunk list holds it.
    hash: Digest,
    /// The chunk's BLAKE3 chaining value at its place in the file (`chaining.zig`) for a file
    /// of two chunks or more, which joins into the content hash; all zero for a one-chunk file,
    /// whose hash is its content.
    chaining: Digest,
    /// The compressed range in the layer blob.
    offset: u64,
    length: u32,
};

fn read_u32(bytes: []const u8, at: usize) u32 {
    assert(at + 4 <= bytes.len);
    assert(at <= std.math.maxInt(u32));
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}

fn read_u64(bytes: []const u8, at: usize) u64 {
    assert(at + 8 <= bytes.len);
    assert(at <= std.math.maxInt(u32));
    return std.mem.readInt(u64, bytes[at..][0..8], .little);
}

fn read_digest(bytes: []const u8, at: usize) Digest {
    assert(at + constants.store_digest_bytes <= bytes.len);
    assert(at <= std.math.maxInt(u32));
    return .{ .bytes = bytes[at..][0..constants.store_digest_bytes].* };
}

pub fn encode_tree_head(digest: Digest, length: u32, out: *[tree_head_bytes]u8) void {
    assert(length >= 1);
    assert(length <= constants.store_tree_bytes_max);
    @memcpy(out[0..32], &digest.bytes);
    std.mem.writeInt(u32, out[32..36], length, .little);
}

pub fn encode_object(record: Object, out: *[object_record_bytes]u8) void {
    assert(record.size <= file_bytes_max);
    assert(record.chunk_count == chunk_count(record.size));
    @memcpy(out[0..32], &record.id.bytes);
    std.mem.writeInt(u64, out[32..40], record.size, .little);
    std.mem.writeInt(u32, out[40..44], record.first_chunk, .little);
    std.mem.writeInt(u32, out[44..48], record.chunk_count, .little);
}

pub fn encode_chunk(record: Chunk, out: *[chunk_record_bytes]u8) void {
    assert(record.length >= 1);
    assert(record.length <= constants.lazy_range_bytes_max);
    assert(record.offset >= gzip_header_bytes);
    @memcpy(out[0..32], &record.hash.bytes);
    @memcpy(out[32..64], &record.chaining.bytes);
    std.mem.writeInt(u64, out[64..72], record.offset, .little);
    std.mem.writeInt(u32, out[72..76], record.length, .little);
    std.mem.writeInt(u32, out[76..80], 0, .little);
}

/// How many chunks a file of `size` bytes has (the store's `object.chunk_count`, kept here so
/// this file needs nothing but the format).
pub fn chunk_count(size: u64) u32 {
    assert(size <= file_bytes_max);
    assert(constants.store_chunk_bytes > 0);
    const count = (size + constants.store_chunk_bytes - 1) / constants.store_chunk_bytes;
    assert(count <= constants.store_chunks_max);
    return @intCast(count);
}

/// A parsed index: its header and its sections, each checked for shape (lengths, bounds, the
/// running chunk count, the order of the ranges). That the trees are the tree, and the objects
/// its files, is `verify.zig`'s.
pub const Index = struct {
    header: Header,
    trees: []const u8,
    objects: []const u8,
    chunks: []const u8,
    order: []const u8,

    pub fn object(index: *const Index, ordinal: u32) Object {
        assert(ordinal < index.header.objects);
        assert(index.objects.len == @as(u64, index.header.objects) * object_record_bytes);
        const at = @as(usize, ordinal) * object_record_bytes;
        return .{
            .id = read_digest(index.objects, at),
            .size = read_u64(index.objects, at + 32),
            .first_chunk = read_u32(index.objects, at + 40),
            .chunk_count = read_u32(index.objects, at + 44),
        };
    }

    pub fn chunk(index: *const Index, ordinal: u32) Chunk {
        assert(ordinal < index.header.chunks);
        assert(index.chunks.len == @as(u64, index.header.chunks) * chunk_record_bytes);
        const at = @as(usize, ordinal) * chunk_record_bytes;
        return .{
            .hash = read_digest(index.chunks, at),
            .chaining = read_digest(index.chunks, at + 32),
            .offset = read_u64(index.chunks, at + 64),
            .length = read_u32(index.chunks, at + 72),
        };
    }

    pub fn order_at(index: *const Index, position: u32) u32 {
        assert(position < index.header.order);
        assert(index.order.len == @as(u64, index.header.order) * order_record_bytes);
        return read_u32(index.order, @as(usize, position) * order_record_bytes);
    }

    pub fn tree_records(index: *const Index) Trees {
        assert(index.header.complete);
        assert(index.header.trees >= 1);
        return .{ .rest = index.trees, .left = index.header.trees };
    }

    /// Where the last chunk's range ends in the blob (the gzip header's end if there is none).
    pub fn chunks_end(index: *const Index) u64 {
        assert(index.header.complete);
        if (index.header.chunks == 0) return gzip_header_bytes;
        const last = index.chunk(index.header.chunks - 1);
        assert(last.length >= 1);
        return last.offset + last.length;
    }
};

/// The trees section, record by record (its shape was checked by `parse`).
pub const Trees = struct {
    rest: []const u8,
    left: u32,

    pub fn next(trees: *Trees) ?TreeRecord {
        assert(trees.rest.len <= constants.lazy_index_bytes_max);
        if (trees.left == 0) {
            assert(trees.rest.len == 0);
            return null;
        }
        const length = read_u32(trees.rest, 32);
        assert(tree_head_bytes + length <= trees.rest.len);
        const record: TreeRecord = .{
            .digest = read_digest(trees.rest, 0),
            .bytes = trees.rest[tree_head_bytes..][0..length],
        };
        trees.rest = trees.rest[tree_head_bytes + length ..];
        trees.left -= 1;
        return record;
    }
};

/// Parses `bytes` as an index. A stub, however well formed, is `TooLarge`.
pub fn parse(bytes: []const u8) Refusal!Index {
    if (bytes.len > constants.lazy_index_bytes_max) return error.TooLarge;
    if (bytes.len < header_bytes) return error.Malformed;
    const header = try Header.decode(bytes[0..header_bytes]);
    if (!header.complete) {
        const counts = @as(u64, header.trees) + header.objects + header.chunks + header.order;
        if (counts != 0 or bytes.len != header_bytes) return error.Malformed;
        return error.TooLarge;
    }
    if (header.names > constants.lazy_nodes_max) return error.TooLarge;
    // The order section is reserved in version 1: the writer leaves it empty.
    if (header.order != 0) return error.Malformed;
    // The root is a tree; every other tree and every object has a name in the tree.
    if (header.trees == 0 or header.trees > @as(u64, header.names) + 1) return error.Malformed;
    if (header.objects > header.names) return error.Malformed;
    var index: Index = .{
        .header = header,
        .trees = undefined,
        .objects = undefined,
        .chunks = undefined,
        .order = undefined,
    };
    var rest = bytes[header_bytes..];
    index.trees = try take_trees(&rest, header.trees);
    index.objects = try take_records(&rest, header.objects, object_record_bytes);
    index.chunks = try take_records(&rest, header.chunks, chunk_record_bytes);
    index.order = try take_records(&rest, header.order, order_record_bytes);
    if (rest.len != 0) return error.Malformed;
    if (!read_digest(index.trees, 0).eql(header.tree)) return error.Malformed;
    try check_objects(&index);
    try check_chunks(&index);
    assert(index.order.len == 0);
    return index;
}

fn take_trees(rest: *[]const u8, count: u32) Refusal![]const u8 {
    assert(count >= 1);
    assert(rest.len <= constants.lazy_index_bytes_max);
    const start = rest.*;
    var at: usize = 0;
    for (0..count) |_| {
        if (start.len - at < tree_head_bytes) return error.Malformed;
        const length = read_u32(start, at + 32);
        if (length == 0 or length > constants.store_tree_bytes_max) return error.Malformed;
        if (start.len - at - tree_head_bytes < length) return error.Malformed;
        at += tree_head_bytes + length;
    }
    rest.* = start[at..];
    return start[0..at];
}

fn take_records(rest: *[]const u8, count: u32, record_bytes: u32) Refusal![]const u8 {
    assert(record_bytes >= order_record_bytes);
    assert(rest.len <= constants.lazy_index_bytes_max);
    const length = @as(u64, count) * record_bytes;
    if (length > rest.len) return error.Malformed;
    const section = rest.*[0..@intCast(length)];
    rest.* = rest.*[@intCast(length)..];
    return section;
}

/// Each object's chunk count fits its size, and the counts run without gaps over the chunks.
fn check_objects(index: *const Index) Refusal!void {
    assert(index.header.complete);
    assert(index.objects.len == @as(u64, index.header.objects) * object_record_bytes);
    var first: u64 = 0;
    for (0..index.header.objects) |ordinal| {
        const record = index.object(@intCast(ordinal));
        if (record.size > file_bytes_max) return error.Malformed;
        if (record.chunk_count != chunk_count(record.size)) return error.Malformed;
        if (record.first_chunk != first) return error.Malformed;
        first += record.chunk_count;
    }
    if (first != index.header.chunks) return error.Malformed;
}

/// Each range is in bounds, after the gzip header and after the one before it.
fn check_chunks(index: *const Index) Refusal!void {
    assert(index.header.complete);
    assert(index.chunks.len == @as(u64, index.header.chunks) * chunk_record_bytes);
    var end: u64 = gzip_header_bytes;
    for (0..index.header.chunks) |ordinal| {
        const at = ordinal * chunk_record_bytes;
        if (read_u32(index.chunks, at + 76) != 0) return error.Malformed;
        const record = index.chunk(@intCast(ordinal));
        if (record.length == 0) return error.Malformed;
        if (record.length > constants.lazy_range_bytes_max) return error.Malformed;
        if (record.offset < end) return error.Malformed;
        if (record.offset > @as(u64, std.math.maxInt(u64)) - record.length) return error.Malformed;
        end = record.offset + record.length;
    }
}

/// The annotation `org.zigbox.lazy-index` on the layer descriptor: where the index is and what
/// it hashes to.
pub const Anchor = struct {
    /// The index's compressed range in the layer blob.
    offset: u64,
    length: u64,
    /// Its uncompressed length and BLAKE3.
    size: u64,
    digest: Digest,

    pub fn render(anchor: *const Anchor, out: *[anchor_text_bytes_max]u8) []const u8 {
        assert(anchor.length >= 1);
        assert(anchor.size >= header_bytes);
        const text = anchor.digest.text();
        return std.fmt.bufPrint(out, "offset={d} length={d} size={d} digest={s}", .{
            anchor.offset,
            anchor.length,
            anchor.size,
            &text,
        }) catch unreachable; // Three u64s and a digest fit `anchor_text_bytes_max`.
    }

    /// The anchor `text` names, or null when it is not exactly what `render` writes.
    pub fn parse(text: []const u8) ?Anchor {
        if (text.len > anchor_text_bytes_max) return null;
        var rest = text;
        const offset = take_field(&rest, "offset=", ' ') orelse return null;
        const length = take_field(&rest, "length=", ' ') orelse return null;
        const size = take_field(&rest, "size=", ' ') orelse return null;
        if (!std.mem.startsWith(u8, rest, "digest=")) return null;
        const hex = rest["digest=".len..];
        const digest = Digest.parse(hex) orelse return null;
        return .{ .offset = offset, .length = length, .size = size, .digest = digest };
    }

    /// The anchor's bounds: a range after the gzip header, an index no shorter than its header,
    /// and no longer than lazy start takes.
    pub fn check(anchor: *const Anchor) Refusal!void {
        assert(anchor_text_bytes_max > 0);
        assert(compressed_bytes_max > constants.lazy_index_bytes_max);
        if (anchor.size > constants.lazy_index_bytes_max) return error.TooLarge;
        if (anchor.length > compressed_bytes_max) return error.TooLarge;
        if (anchor.size < header_bytes or anchor.length == 0) return error.Malformed;
        if (anchor.offset < gzip_header_bytes) return error.Malformed;
        if (anchor.offset > std.math.maxInt(u64) - anchor.length) return error.Malformed;
    }
};

/// Reads `<name><decimal><end>` from the front of `rest`: decimal digits, no leading zero but
/// `0` itself, no overflow.
fn take_field(rest: *[]const u8, name: []const u8, end: u8) ?u64 {
    assert(name.len > 0);
    assert(name[name.len - 1] == '=');
    if (!std.mem.startsWith(u8, rest.*, name)) return null;
    const digits_start = rest.*[name.len..];
    const stop = std.mem.indexOfScalar(u8, digits_start, end) orelse return null;
    const digits = digits_start[0..stop];
    if (digits.len == 0 or digits.len > 20) return null;
    if (digits[0] == '0' and digits.len > 1) return null;
    var value: u64 = 0;
    for (digits) |digit| {
        if (digit < '0' or digit > '9') return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, digit - '0') catch return null;
    }
    rest.* = digits_start[stop + 1 ..];
    return value;
}

/// Inflates one compressed range (a run of whole deflate blocks that starts with an empty
/// history) to exactly `out.len` bytes. `range` holds the `length` compressed bytes and
/// `range_trailer_bytes` of room after them, which this overwrites with an empty final block.
/// Fewer or more bytes than `out.len`, or anything std's decompressor refuses, is `Malformed`.
pub fn inflate_range(
    range: []u8,
    length: usize,
    out: []u8,
    window: *[flate.max_window_len]u8,
) error{Malformed}!void {
    assert(length >= 1);
    assert(range.len >= length + range_trailer_bytes);
    range[length..][0..range_trailer_bytes].* = range_trailer;
    var input: std.Io.Reader = .fixed(range[0 .. length + range_trailer_bytes]);
    var inflate: flate.Decompress = .init(&input, .raw, window);
    inflate.reader.readSliceAll(out) catch return error.Malformed;
    if (inflate.reader.takeByte()) |_| {
        return error.Malformed;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.Malformed,
    }
}
