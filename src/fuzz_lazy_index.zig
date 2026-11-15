//! The `lazy_index` fuzzer: `zig build fuzz -- lazy_index`. Each iteration builds a random source
//! tree (the `store` fuzzer's generator, with files from empty to a few chunks long), imports it,
//! packs it with layer writer 2, and checks:
//!
//!   1. The layer carries an index exactly when the tree is within `names_max` names (a bound
//!      the iteration lowers at random): the bound is the only reason for no index.
//!   2. An independent reader finds it: the whole blob inflates as one gzip member (its CRC and
//!      size checked) to the config's diff_id, the anchor's range inflates alone to the anchor's
//!      size and hash, `verify` accepts it against the tree the pack started from, and each chunk
//!      of each object inflates alone from its own offset to its own hash and, in a file of two
//!      chunks or more, to its own chaining value, the chunks together being the object's size
//!      and every range lying before the index.
//!   3. Random bytes into the reader never crash it and never pass for an index: the index with
//!      bytes changed, cut short or grown, its anchor made to match, is refused or (when the
//!      change left it a well-formed index of the same tree) accepted as one; any accepted
//!      index's ranges stay in their bounds. Random text into the anchor parser is refused or
//!      renders back to itself. A range's compressed bytes changed or cut short never crash the
//!      range inflate.
//!
//! `check_layer` is the reader of property 2; the `pack` fuzzer uses it as well.

const std = @import("std");
const assert = std.debug.assert;
const flate = std.compress.flate;
const constants = @import("constants.zig");
const Diag = @import("diag/diag.zig").Diag;
const host_sim = @import("host_sim.zig");
const fuzz_store = @import("fuzz_store.zig");
const blobs_mod = @import("registry/blobs.zig");
const digest_mod = @import("store/digest.zig");
const fs_mod = @import("store/fs.zig");
const fs_sim = @import("store/fs_sim.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");
const index_mod = @import("lazy/index.zig");
const verify_mod = @import("lazy/verify.zig");
const chaining = @import("lazy/chaining.zig");
const oci = @import("registry/digest.zig");
const pack = @import("push/pack.zig");

const Digest = digest_mod.Digest;
const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var files_pool: [constants.sim_fs_pool_lazy_fuzz_bytes_max]u8 = undefined;
var store: layout.Store = undefined;
var imports: import.Workspace = undefined;
var packing: pack.Workspace = undefined;
var diag: Diag = undefined;
var settings: images.Settings = undefined;

/// The reader's room: the whole blob, one range and what it inflates to, and the index.
const Reader = struct {
    blob: [blob_bytes_max]u8,
    range: [constants.lazy_range_bytes_max + index_mod.range_trailer_bytes]u8,
    plain: [constants.lazy_range_bytes_max]u8,
    index: [index_bytes_max]u8,
    window: [flate.max_window_len]u8,
    checking: verify_mod.Workspace,
};

const blob_bytes_max = 16 * 1024 * 1024;
const index_bytes_max = 4 * 1024 * 1024;
var reader: Reader = undefined;

/// What `check_layer` read: the index, in `reader.index`, and the blob.
pub const Read = struct {
    index: index_mod.Index,
    bytes: []u8,
    blob: []const u8,
};

/// Reads the layer blob of `made` and checks its index against `tree` (property 2); panics on
/// any failure, naming it.
pub fn check_layer(on: *layout.Store, made: *const pack.Packed, tree: Digest) Read {
    const anchor = made.index orelse @panic("check_layer needs an indexed layer");
    const blob = read_blob(on, made);
    check_member(blob, made.diff_id);
    if (anchor.offset + anchor.length >= blob.len) @panic("the index must end before the footer");
    const plain = inflate_at(blob, anchor.offset, anchor.length, anchor.size) catch
        @panic("the index range must inflate alone");
    if (plain.len > reader.index.len) @panic("the fuzzer's index room is too small");
    const bytes = reader.index[0..plain.len];
    @memcpy(bytes, plain);
    reader.checking.key = tree.bytes[0..verify_mod.key_bytes].*; // Any key; one per tree here.
    const index = verify_mod.verify(&reader.checking, bytes, &anchor, tree) catch
        @panic("a written index must verify");
    for (0..index.header.objects) |ordinal| {
        const object = index.object(@intCast(ordinal));
        var covered: u64 = 0;
        for (0..object.chunk_count) |step| {
            const record = index.chunk(object.first_chunk + @as(u32, @intCast(step)));
            if (record.offset + record.length > anchor.offset) @panic("a chunk after the index");
            const want = @min(object.size - covered, constants.store_chunk_bytes);
            const chunk = inflate_at(blob, record.offset, record.length, want) catch
                @panic("a chunk range must inflate alone");
            if (!Digest.of(chunk).eql(record.hash)) @panic("a chunk does not hash to its record");
            const value = if (object.chunk_count == 1) zero else chaining.run_value(
                chunk,
                step,
                constants.store_chunk_bytes,
            );
            if (!value.eql(record.chaining)) @panic("a chunk is not its chaining value");
            covered += want;
        }
        if (covered != object.size) @panic("an object's chunks are not its size");
    }
    return .{ .index = index, .bytes = bytes, .blob = blob };
}

const zero: Digest = .{ .bytes = @splat(0) };

/// The blob as one gzip member, inflated by std's reader: its footer's CRC and size are the
/// plain bytes', nothing follows it, and the plain bytes hash to `diff_id`.
fn check_member(blob: []const u8, diff_id: oci.Sha256) void {
    var input: std.Io.Reader = .fixed(blob);
    var inflate: flate.Decompress = .init(&input, .gzip, &reader.window);
    var hasher = oci.Hasher.init();
    var crc = std.hash.Crc32.init();
    var total: u64 = 0;
    while (true) {
        const count = inflate.reader.readSliceShort(&reader.plain) catch
            @panic("the layer must inflate as one gzip member");
        if (count == 0) break;
        hasher.update(reader.plain[0..count]);
        crc.update(reader.plain[0..count]);
        total += count;
    }
    const footer = inflate.container_metadata.gzip;
    if (footer.crc != crc.final()) @panic("the gzip footer's CRC is not the plain bytes'");
    if (footer.count != @as(u32, @truncate(total))) @panic("the gzip footer's size is wrong");
    if (input.seek != blob.len) @panic("bytes follow the gzip member");
    if (!hasher.final().eql(diff_id)) @panic("the layer does not inflate to its diff_id");
}

fn read_blob(on: *layout.Store, made: *const pack.Packed) []const u8 {
    var path: fs_mod.PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = on.fs, .root = on.root_text() };
    const fd = on.fs.open_read(blobs.final_path(&path, made.layer)) catch
        @panic("the layer blob must open");
    defer on.fs.close(fd);
    var used: usize = 0;
    while (true) {
        if (used == reader.blob.len) @panic("the fuzzer's blob room is too small");
        const room = @min(reader.blob.len - used, constants.store_io_buffer_bytes);
        const count = on.fs.read(fd, reader.blob[used..][0..room]) catch
            @panic("the layer blob must read");
        if (count == 0) break;
        used += count;
    }
    if (used != made.layer_size) @panic("the layer blob is not its size");
    return reader.blob[0..used];
}

fn inflate_at(blob: []const u8, offset: u64, length: u64, size: u64) error{Malformed}![]u8 {
    assert(length >= 1);
    assert(length <= constants.lazy_range_bytes_max);
    assert(size <= reader.plain.len);
    assert(offset + length <= blob.len);
    const span: usize = @intCast(length);
    @memcpy(reader.range[0..span], blob[@intCast(offset)..][0..span]);
    const out = reader.plain[0..@intCast(size)];
    try index_mod.inflate_range(&reader.range, span, out, &reader.window);
    return out;
}

/// Adds one file the plain generator never makes: empty, one byte short of a chunk, a chunk or
/// one byte over, whose bytes repeat a random 4 KiB block; or a chunk and one byte to 64 KiB
/// of random bytes, which no compressor shrinks. That last file still spans two chunks, so its
/// chaining values, stored blocks and compressed length above plain are exercised; it is kept
/// near one chunk because its cost is linear in size and it dominated the fuzzer's run time.
fn add_sized_file(random: std.Random, target: *fs_sim.SimFs) void {
    const chunk = constants.store_chunk_bytes;
    const sizes = [_]u32{ 0, 1, chunk - 1, chunk, chunk + 1 };
    const choice = random.uintLessThan(usize, sizes.len + 1);
    if (choice == sizes.len) {
        const size = random.intRangeAtMost(u32, chunk + 1, chunk + 64 * 1024);
        assert(size > chunk);
        assert(size <= reader.blob.len);
        const content = reader.blob[0..size];
        random.bytes(content);
        target.put_file("/src/sized", 0o644, content);
        return;
    }
    const content = reader.blob[0..sizes[choice]];
    var block: [4096]u8 = undefined;
    random.bytes(&block);
    for (content, 0..) |*byte, at| byte.* = block[at % block.len];
    target.put_file("/src/sized", 0o644, content);
}

/// Property 3: a chunk's compressed bytes, changed or cut short, into the range inflate; it
/// returns or refuses, and never crashes.
fn mutate_ranges(random: std.Random, read: *const Read) void {
    const index = &read.index;
    if (index.header.chunks == 0) return;
    for (0..4) |_| {
        const object = index.object(random.uintLessThan(u32, index.header.objects));
        if (object.chunk_count == 0) continue;
        const step = random.uintLessThan(u32, object.chunk_count);
        const record = index.chunk(object.first_chunk + step);
        const before = @as(u64, step) * constants.store_chunk_bytes;
        const want: usize = @intCast(@min(object.size - before, constants.store_chunk_bytes));
        var span: usize = record.length;
        @memcpy(reader.range[0..span], read.blob[@intCast(record.offset)..][0..span]);
        if (random.boolean()) {
            reader.range[random.uintLessThan(usize, span)] ^= @as(u8, 1) << random.int(u3);
        } else {
            span = random.uintLessThan(usize, span) + 1;
            reader.range[span - 1] = random.int(u8);
        }
        const out = reader.plain[0..want];
        index_mod.inflate_range(&reader.range, span, out, &reader.window) catch {};
    }
}

/// Property 3: changed, cut and grown copies of `read.bytes`, each with an anchor that matches
/// it, into `verify`.
fn mutate_index(
    random: std.Random,
    read: *const Read,
    anchor: index_mod.Anchor,
    tree: Digest,
) void {
    const room = reader.plain[0..];
    for (0..8) |_| {
        var length = read.bytes.len;
        @memcpy(room[0..length], read.bytes);
        switch (random.uintLessThan(u8, 4)) {
            0 => {
                const at = random.uintLessThan(usize, length);
                room[at] ^= @as(u8, 1) << random.int(u3);
            },
            1 => length = random.uintLessThan(usize, length),
            2 => {
                const extra = random.uintLessThan(usize, 64) + 1;
                random.bytes(room[length..][0..extra]);
                length += extra;
            },
            else => {
                const at = random.uintLessThan(usize, length);
                room[at] = random.int(u8);
                room[random.uintLessThan(usize, length)] = random.int(u8);
            },
        }
        const bytes = room[0..length];
        var changed = anchor;
        changed.size = length;
        changed.digest = Digest.of(bytes);
        if (verify_mod.verify(&reader.checking, bytes, &changed, tree)) |index| {
            // Well formed and of this tree: every range still in bounds and before the index.
            for (0..index.header.chunks) |ordinal| {
                const record = index.chunk(@intCast(ordinal));
                assert(record.length >= 1);
                assert(record.length <= constants.lazy_range_bytes_max);
                assert(record.offset >= index_mod.gzip_header_bytes);
                assert(record.offset + record.length <= changed.offset);
            }
        } else |_| {}
        _ = index_mod.parse(bytes) catch {};
    }
}

/// Property 3: random anchor texts are refused or render back to themselves.
fn fuzz_anchor_text(random: std.Random, anchor: index_mod.Anchor) void {
    var rendered: [index_mod.anchor_text_bytes_max]u8 = undefined;
    const good = anchor.render(&rendered);
    var text: [index_mod.anchor_text_bytes_max + 8]u8 = undefined;
    for (0..8) |_| {
        var length = good.len;
        @memcpy(text[0..length], good);
        if (random.boolean()) {
            text[random.uintLessThan(usize, length)] = random.intRangeAtMost(u8, ' ', '~');
        } else {
            length = random.uintLessThan(usize, text.len + 1);
            random.bytes(text[0..length]);
        }
        const parsed = index_mod.Anchor.parse(text[0..length]) orelse continue;
        var back: [index_mod.anchor_text_bytes_max]u8 = undefined;
        if (parsed.length == 0 or parsed.size < index_mod.header_bytes) continue;
        assert(std.mem.eql(u8, parsed.render(&back), text[0..length]));
    }
}

pub fn fuzz_lazy_index(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    sim.init(seed, &.{});
    files.init(seed);
    files.use_pool(&files_pool);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    fuzz_store.build_tree(seed, &files, "/src");
    if (random.boolean()) add_sized_file(random, &files);
    diag.reset();
    settings.clear();

    var imported: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = random.boolean(), .warn = null };
    import.import(&store, &imports, "/src", options, &imported, &diag) catch
        @panic("a generated tree must import");

    // Count the names with the bound at its maximum, then pack again at a bound around it.
    const full = pack_with(imported.digest, constants.lazy_nodes_max);
    const anchor = full.index orelse @panic("a small tree must have an index");
    const read = check_layer(&store, &full, imported.digest);
    const names = read.index.header.names;
    const blob_end = read.blob.len;
    assert(anchor.offset + anchor.length < blob_end);
    mutate_index(random, &read, anchor, imported.digest);
    mutate_ranges(random, &read);
    fuzz_anchor_text(random, anchor);

    if (names >= 1) {
        const bound = random.intRangeAtMost(u32, @max(names, 2) - 1, names + 1);
        pack.forget(&store, imported.digest, 2);
        const bounded = pack_with(imported.digest, bound);
        const indexed = bounded.index != null;
        if (indexed != (names <= bound)) @panic("the names bound decides the index");
        if (bounded.index != null) {
            _ = check_layer(&store, &bounded, imported.digest);
            assert(bounded.layer.eql(full.layer));
        }
    }
}

fn pack_with(tree: Digest, names_max: u32) pack.Packed {
    var made: pack.Packed = undefined;
    var failure: pack.Failure = undefined;
    const input: pack.Input = .{
        .tree = tree,
        .settings = &settings,
        .labels = null,
        .writer_version = 2,
    };
    packing.piece = constants.pack_io_bytes;
    packing.names_max = names_max;
    packing.index_bytes_max = constants.lazy_index_bytes_max;
    pack.pack_pieces(&store, &packing, input, &made, &failure) catch
        @panic("a whole tree must pack");
    return made;
}

test "the lazy_index fuzzer runs a few seeds without a failed property" {
    // Goal: the properties hold on a spread of trees; `zig build fuzz -- lazy_index` runs more.
    for (1..12) |seed| fuzz_lazy_index(seed);
}
