//! Tests of `pack.zig` against the simulated file system: that one tree gives one image on every
//! pack and at every buffer size, that a second pack finds the first one's layer, and that a tree
//! with a missing object is refused.

const std = @import("std");
const builtin = @import("builtin");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const images = @import("../store/images.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const support = @import("../store/test_support.zig");
const apply = @import("../layer/apply.zig");
const blobs_mod = @import("../registry/blobs.zig");
const reader_mod = @import("../layer/reader.zig");
const trees = @import("../store/trees.zig");
const tree_mod = @import("../store/tree.zig");
const export_mod = @import("export.zig");
const tar_mod = @import("../layer/tar.zig");
const pack = @import("pack.zig");
const index_mod = @import("../lazy/index.zig");
const verify_mod = @import("../lazy/verify.zig");
const chaining = @import("../lazy/chaining.zig");
const flate = std.compress.flate;
const PathBuf = @import("../store/fs.zig").PathBuf;

const testing = std.testing;
const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const Store = layout.Store;

const root_path = "/data/store";

var sim: HostSim = undefined;
var files: SimFs = undefined;
var store: Store = undefined;
var imports: import.Workspace = undefined;
var packing: pack.Workspace = undefined;
var diag: Diag = undefined;
var settings: images.Settings = undefined;

fn start(seed: u64, order: u32) void {
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    support.make_source(&files, order);
    diag.reset();
    settings.clear();
}

fn import_source(squash_owner: bool) !import.Result {
    var result: import.Result = undefined;
    diag.reset();
    try import.import(
        &store,
        &imports,
        "/src",
        .{ .squash_owner = squash_owner, .warn = null },
        &result,
        &diag,
    );
    return result;
}

fn pack_tree(tree: digest_mod.Digest, piece: u32) !pack.Packed {
    return pack_tree_as(tree, piece, constants.layer_writer_version, constants.lazy_nodes_max);
}

fn pack_tree_as(
    tree: digest_mod.Digest,
    piece: u32,
    version: u32,
    names_max: u32,
) !pack.Packed {
    var made: pack.Packed = undefined;
    var failure: pack.Failure = undefined;
    const input: pack.Input = .{
        .tree = tree,
        .settings = &settings,
        .labels = null,
        .writer_version = version,
    };
    packing.piece = piece;
    packing.names_max = names_max;
    packing.index_bytes_max = constants.lazy_index_bytes_max;
    try pack.pack_pieces(&store, &packing, input, &made, &failure);
    try testing.expectEqual(version, made.writer_version);
    return made;
}

test "one tree packs to one image, on every pack and at every buffer size" {
    // Goal: the determinism promise, for both writers. Method: pack the sample tree in two
    // stores, imported in different directory orders, and again at other piece sizes; compare
    // all digests and the index anchor.
    for ([_]u32{ 1, 2 }) |version| {
        start(1, 0);
        const first_import = try import_source(false);
        const first = try pack_version(first_import.digest, constants.pack_io_bytes, version);
        try testing.expect(!first.cached);
        try testing.expect(first.layer_size > 0);
        try testing.expectEqual(version == 2, first.index != null);

        const again = try pack_version(first_import.digest, constants.pack_io_bytes, version);
        try testing.expect(again.cached);
        try testing.expectEqualSlices(u8, &first.manifest.bytes, &again.manifest.bytes);
        try testing.expectEqualSlices(u8, &first.layer.bytes, &again.layer.bytes);
        try expect_same_anchor(first.index, again.index);

        start(2, 1);
        const second_import = try import_source(false);
        try testing.expect(first_import.digest.eql(second_import.digest));
        for ([_]u32{ 1024, 4099, 65536 }) |piece| {
            // Without the record the pack walks and compresses again: a cached one proves
            // nothing.
            pack.forget(&store, second_import.digest, version);
            const other = try pack_version(second_import.digest, piece, version);
            try testing.expect(!other.cached);
            try testing.expectEqualSlices(u8, &first.manifest.bytes, &other.manifest.bytes);
            try testing.expectEqualSlices(u8, &first.config.bytes, &other.config.bytes);
            try testing.expectEqualSlices(u8, &first.layer.bytes, &other.layer.bytes);
            try testing.expectEqualSlices(u8, &first.diff_id.bytes, &other.diff_id.bytes);
            try testing.expectEqual(first.layer_size, other.layer_size);
            try expect_same_anchor(first.index, other.index);
        }
    }
}

fn pack_version(tree: digest_mod.Digest, piece: u32, version: u32) !pack.Packed {
    return pack_tree_as(tree, piece, version, constants.lazy_nodes_max);
}

fn expect_same_anchor(expected: ?index_mod.Anchor, actual: ?index_mod.Anchor) !void {
    try testing.expectEqual(expected == null, actual == null);
    const left = expected orelse return;
    const right = actual.?;
    try testing.expectEqual(left.offset, right.offset);
    try testing.expectEqual(left.length, right.length);
    try testing.expectEqual(left.size, right.size);
    try testing.expect(left.digest.eql(right.digest));
}

var applier: apply.Applier = undefined;
var layer: reader_mod.Layer = undefined;

/// Unpacks the layer of `made` into a fresh `/out` and imports it: the tree digest it gives.
fn round_trip(made: pack.Packed, squash_owner: bool) !digest_mod.Digest {
    files.put_dir("/out", 0o755);
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    const layer_path = blobs.final_path(&path, made.layer);
    applier.start(store.fs, "/out", squash_owner);
    try layer.start(store.fs, layer_path);
    defer layer.close();
    try applier.apply_layer(&layer);
    const diff = try layer.finish();
    try testing.expectEqualSlices(u8, &made.layer.bytes, &diff.bytes);
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = squash_owner, .warn = null };
    try import.import(&store, &imports, "/out", options, &result, &diag);
    return result.digest;
}

test "a packed layer applied again gives the tree it was packed from, in both id modes" {
    // Goal: the round trip, for both writers: M4's applier reads a writer 2 layer, index and
    // all, to the same tree. Method: import /src, pack, apply the layer to a new directory and
    // import that; the digests agree, with owners kept and with owners squashed to 0.
    for ([_]u32{ 1, 2 }) |version| {
        for ([_]bool{ false, true }) |squash| {
            start(3, 0);
            const imported = try import_source(squash);
            const made = try pack_version(imported.digest, constants.pack_io_bytes, version);
            const again = try round_trip(made, squash);
            try testing.expect(imported.digest.eql(again));
        }
    }
}

var blob_bytes: [4 * 1024 * 1024]u8 = undefined;
var range_bytes: [constants.lazy_range_bytes_max + index_mod.range_trailer_bytes]u8 = undefined;
var plain_bytes: [constants.lazy_range_bytes_max]u8 = undefined;
var inflate_window: [flate.max_window_len]u8 = undefined;
var index_bytes: [1024 * 1024]u8 = undefined;
var big_bytes: [constants.store_chunk_bytes + 12345]u8 = undefined;
var checking: verify_mod.Workspace = undefined;

/// The whole layer blob of `made`.
fn read_layer(made: pack.Packed) ![]const u8 {
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    const fd = try store.fs.open_read(blobs.final_path(&path, made.layer));
    defer store.fs.close(fd);
    var used: usize = 0;
    while (true) {
        const room = @min(blob_bytes.len - used, constants.store_io_buffer_bytes);
        const count = try store.fs.read(fd, blob_bytes[used..][0..room]);
        if (count == 0) break;
        used += count;
        if (used == blob_bytes.len) return error.TestBlobTooLarge;
    }
    try testing.expectEqual(made.layer_size, used);
    return blob_bytes[0..used];
}

/// Inflates `length` bytes at `offset` of `blob`, alone, to `size` bytes.
fn inflate_at(blob: []const u8, offset: u64, length: u64, size: u64) ![]const u8 {
    try testing.expect(length <= constants.lazy_range_bytes_max);
    try testing.expect(size <= plain_bytes.len);
    try testing.expect(offset + length <= blob.len);
    const at: usize = @intCast(offset);
    const span: usize = @intCast(length);
    @memcpy(range_bytes[0..span], blob[at..][0..span]);
    const out = plain_bytes[0..@intCast(size)];
    try index_mod.inflate_range(&range_bytes, span, out, &inflate_window);
    return out;
}

/// The index of a writer 2 layer: read from its anchor, verified against `tree`, and every
/// chunk of every object inflated from its own offset to its own hash; the chunks of an
/// object together are its size.
fn check_index(made: pack.Packed, tree: digest_mod.Digest) !index_mod.Index {
    const anchor = made.index orelse return error.TestNoIndex;
    const blob = try read_layer(made);
    try testing.expect(anchor.offset + anchor.length < blob.len); // The gzip footer follows.
    const bytes = try inflate_at(blob, anchor.offset, anchor.length, anchor.size);
    try testing.expect(bytes.len <= index_bytes.len);
    const kept = index_bytes[0..bytes.len];
    @memcpy(kept, bytes); // The chunks are inflated through `plain_bytes` next.
    checking.key = @splat(1);
    const index = try verify_mod.verify(&checking, kept, &anchor, tree);
    for (0..index.header.objects) |ordinal| {
        const object = index.object(@intCast(ordinal));
        var covered: u64 = 0;
        for (0..object.chunk_count) |step| {
            const record = index.chunk(object.first_chunk + @as(u32, @intCast(step)));
            const want = @min(object.size - covered, constants.store_chunk_bytes);
            const chunk = try inflate_at(blob, record.offset, record.length, want);
            try testing.expect(digest_mod.Digest.of(chunk).eql(record.hash));
            const value = if (object.chunk_count == 1) zero else chaining.run_value(
                chunk,
                step,
                constants.store_chunk_bytes,
            );
            try testing.expect(value.eql(record.chaining));
            covered += want;
        }
        try testing.expectEqual(object.size, covered);
    }
    return index;
}

test "every chunk of a writer 2 layer inflates alone from its offset to its hash" {
    // Goal: the index is what lazy start reads: each recorded range is a self-contained raw
    // deflate run. Method: the sample tree, plus a file of a chunk and a tail (its bytes repeat
    // a random block, so the sim's pool holds the source, the object and the layer), packed at
    // two piece sizes; read the index from its anchor, verify it, inflate every chunk alone and
    // hash it. The round trip of a writer 2 layer is the round-trip test's.
    const big = &big_bytes;
    var block: [4096]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(91);
    prng.random().bytes(&block);
    for (big, 0..) |*byte, at| byte.* = block[at % block.len];
    for ([_]u32{ 1024, constants.pack_io_bytes }) |piece| {
        start(4, 0);
        files.put_file("/src/big", 0o644, big);
        const imported = try import_source(false);
        const made = try pack_tree_as(imported.digest, piece, 2, constants.lazy_nodes_max);
        const index = try check_index(made, imported.digest);
        try testing.expectEqual(@as(u32, 11), index.header.names);
        // Six small files (ls's note makes it another object than sh) and big.
        try testing.expectEqual(@as(u32, 7), index.header.objects);
        // One chunk for each small file but the empty one; two for big.
        try testing.expectEqual(@as(u32, 5 + 2), index.header.chunks);
    }
}

test "a tree over the names bound packs with no index and no annotation, and still pulls" {
    // Goal: the owner's answer: a tree past `lazy_nodes_max` names gets neither index nor
    // annotation (W1201 on the read side) and is otherwise a good layer. Method: the sample
    // tree has 10 names; pack it with the bound at 10 (indexed) and at 9 (not).
    start(5, 0);
    const imported = try import_source(false);
    const at_bound = try pack_tree_as(imported.digest, constants.pack_io_bytes, 2, 10);
    _ = try check_index(at_bound, imported.digest);
    try testing.expect(try manifest_names_index(at_bound));

    pack.forget(&store, imported.digest, 2);
    const over = try pack_tree_as(imported.digest, constants.pack_io_bytes, 2, 9);
    try testing.expect(!over.cached);
    try testing.expect(over.index == null);
    try testing.expect(!try manifest_names_index(over));
    try testing.expect(imported.digest.eql(try round_trip(over, false)));
    // The record keeps the answer: a cached pack has no index either.
    const cached = try pack_tree_as(imported.digest, constants.pack_io_bytes, 2, 9);
    try testing.expect(cached.cached);
    try testing.expect(cached.index == null);
    try testing.expectEqualSlices(u8, &over.manifest.bytes, &cached.manifest.bytes);
}

const zero: digest_mod.Digest = .{ .bytes = @splat(0) };

/// Packs `tree` with writer 2 and the index bound at `index_bytes_max` bytes.
fn pack_bytes_bound(tree: digest_mod.Digest, index_bytes_max: u64) !pack.Packed {
    var made: pack.Packed = undefined;
    var failure: pack.Failure = undefined;
    const input: pack.Input = .{
        .tree = tree,
        .settings = &settings,
        .labels = null,
        .writer_version = 2,
    };
    packing.piece = constants.pack_io_bytes;
    packing.names_max = constants.lazy_nodes_max;
    packing.index_bytes_max = index_bytes_max;
    defer packing.index_bytes_max = constants.lazy_index_bytes_max;
    try pack.pack_pieces(&store, &packing, input, &made, &failure);
    return made;
}

/// The names in the store's `tmp/`.
fn tmp_entries() !u32 {
    var counter: struct {
        names: u32 = 0,
        fn call(context: *anyopaque, name: []const u8) void {
            _ = name;
            const self: *@This() = @ptrCast(@alignCast(context));
            self.names += 1;
        }
    } = .{};
    try store.fs.read_dir(root_path ++ "/tmp", .{
        .context = &counter,
        .call = @TypeOf(counter).call,
    });
    return counter.names;
}

test "an index exactly at its byte bound is written, and one byte over gets none" {
    // Goal: `lazy_index_bytes_max` is the writer's bound to the byte, and a tree past it gets
    // neither index nor annotation, nothing half written. Method: pack once to learn the
    // index's size, then again with the bound at that size and one byte under it.
    start(7, 0);
    const imported = try import_source(false);
    const full = try pack_bytes_bound(imported.digest, constants.lazy_index_bytes_max);
    const size = (full.index orelse return error.TestNoIndex).size;
    try testing.expectEqual(0, try tmp_entries());

    pack.forget(&store, imported.digest, 2);
    const at_bound = try pack_bytes_bound(imported.digest, size);
    try testing.expect(!at_bound.cached);
    _ = try check_index(at_bound, imported.digest);
    try testing.expect(try manifest_names_index(at_bound));
    try testing.expect(at_bound.layer.eql(full.layer));
    try testing.expectEqual(0, try tmp_entries());

    pack.forget(&store, imported.digest, 2);
    const over = try pack_bytes_bound(imported.digest, size - 1);
    try testing.expect(!over.cached);
    try testing.expect(over.index == null);
    try testing.expect(!try manifest_names_index(over));
    try testing.expect(imported.digest.eql(try round_trip(over, false)));
    try testing.expectEqual(0, try tmp_entries());
}

test "a writer 2 pack that fails at any write point leaves the store's tmp/ empty" {
    // Goal: the spill files and the blob being written never outlive a failed pack. Method:
    // count a clean pack's write points, then fail each in turn on a fresh store. A failed
    // removal of a spill is swallowed (gc sweeps `tmp/`), so only failed packs are checked.
    start(8, 0);
    const clean_import = try import_source(false);
    const before = files.mutations;
    _ = try pack_bytes_bound(clean_import.digest, constants.lazy_index_bytes_max);
    const points = files.mutations - before;
    try testing.expectEqual(0, try tmp_entries());
    try testing.expect(points > 3);
    var failed: u32 = 0;
    for (0..points) |point| {
        start(8, 0);
        const imported = try import_source(false);
        files.faults.fail_mutation = files.mutations + @as(u32, @intCast(point));
        const made = pack_bytes_bound(imported.digest, constants.lazy_index_bytes_max);
        files.faults.fail_mutation = null;
        if (made) |_| continue else |_| {}
        failed += 1;
        try testing.expectEqual(0, try tmp_entries());
    }
    try testing.expect(failed >= points - 3);
}

/// Whether the manifest blob of `made` carries the lazy-index annotation.
fn manifest_names_index(made: pack.Packed) !bool {
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    var text: [constants.pack_config_bytes_max]u8 = undefined;
    const body = try read_back(blobs.final_path(&path, made.manifest), &text);
    return std.mem.indexOf(u8, body, constants.pack_annotation_lazy_index) != null;
}

/// The path of the first file object found in `tree` or the directories below it.
fn first_object_path(tree: digest_mod.Digest, buffer: *PathBuf) !?[:0]const u8 {
    var bytes: [constants.store_tree_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    const loaded = try trees.load(&store, tree, &bytes, &errno);
    var decoder: tree_mod.Decoder = undefined;
    try decoder.init(loaded);
    var entry: tree_mod.Entry = undefined;
    var below: ?digest_mod.Digest = null;
    while (try decoder.next(&entry)) {
        if (entry.kind == .file) return store.object_path(buffer, entry.object);
        if (entry.kind == .dir and below == null) below = entry.subtree;
    }
    if (below) |subtree| return try first_object_path(subtree, buffer);
    return null;
}

test "a tree with a file missing or changed is refused, naming what stopped the pack" {
    // Goal: E0550's cases. Method: remove a file object, then flip a byte of another pack.
    start(4, 0);
    const imported = try import_source(false);
    var path: PathBuf = undefined;
    const object_path = (try first_object_path(imported.digest, &path)).?;
    var failure: pack.Failure = undefined;
    var made: pack.Packed = undefined;
    const input: pack.Input = .{
        .tree = imported.digest,
        .settings = &settings,
        .labels = null,
        .writer_version = constants.layer_writer_version,
    };
    packing.piece = constants.pack_io_bytes;
    packing.names_max = constants.lazy_nodes_max;
    packing.index_bytes_max = constants.lazy_index_bytes_max;

    files.flip_byte(object_path, 0);
    try testing.expectError(
        error.Stopped,
        pack.pack_pieces(&store, &packing, input, &made, &failure),
    );
    try testing.expectEqual(pack.Stop.object_changed, failure.stop);

    files.remove_path(object_path);
    try testing.expectError(
        error.Stopped,
        pack.pack_pieces(&store, &packing, input, &made, &failure),
    );
    try testing.expectEqual(pack.Stop.object_missing, failure.stop);
}

fn read_back(path: [:0]const u8, buffer: []u8) ![]const u8 {
    return try store.fs.read_whole(path, buffer);
}

test "an export writes the layout, and refuses a directory that holds something" {
    // Goal: the layout and E0557's cases. Method: export to a new directory and to an empty one;
    // the blobs hash to their names; a second export to either, or to a file, is refused.
    start(5, 0);
    const imported = try import_source(false);
    const made = try pack_tree(imported.digest, constants.pack_io_bytes);
    var failure: export_mod.Failure = undefined;
    var out: export_mod.Exported = undefined;
    var buffer: [4096]u8 = undefined;
    @memset(&buffer, 0xAA);
    try export_mod.export_layout(&store, &made, "/export", &buffer, &out, &failure);
    try testing.expectEqualSlices(u8, &made.manifest.bytes, &out.manifest.bytes);
    try testing.expectEqual(
        made.layer_size + made.config_size + made.manifest_size,
        out.total_size,
    );

    var path: PathBuf = undefined;
    var text: [constants.pack_manifest_bytes_max]u8 = undefined;
    try path.set(&.{ "/export/blobs/sha256/", &made.manifest.hex() });
    const manifest = try read_back(path.text(), &text);
    try testing.expectEqualSlices(
        u8,
        &made.manifest.bytes,
        &@import("../registry/digest.zig").Sha256.of(manifest).bytes,
    );
    try path.set(&.{"/export/oci-layout"});
    try testing.expectEqualStrings(
        "{\"imageLayoutVersion\":\"1.0.0\"}",
        try read_back(path.text(), &text),
    );
    try path.set(&.{"/export/index.json"});
    const index = try read_back(path.text(), &text);
    try testing.expect(std.mem.indexOf(u8, index, &made.manifest.text()) != null);

    try testing.expectError(
        error.Stopped,
        export_mod.export_layout(&store, &made, "/export", &buffer, &out, &failure),
    );
    try testing.expectEqual(export_mod.Stop.not_empty, failure.stop);
    files.put_file("/plain", 0o644, "x");
    try testing.expectError(
        error.Stopped,
        export_mod.export_layout(&store, &made, "/plain", &buffer, &out, &failure),
    );
    try testing.expectEqual(export_mod.Stop.not_directory, failure.stop);
    files.put_dir("/empty", 0o755);
    try export_mod.export_layout(&store, &made, "/empty", &buffer, &out, &failure);
}

test "an export to a name with trailing slashes builds beside it, never inside it" {
    // Goal: `store export --oci img out/` (tab completion adds the slash) works like `out`.
    // Method: export to an empty directory and to an absent one, both spelled with slashes;
    // the layout lands in the name, and nothing else is left in the parent.
    start(9, 0);
    const imported = try import_source(false);
    const made = try pack_tree(imported.digest, constants.pack_io_bytes);
    var failure: export_mod.Failure = undefined;
    var out: export_mod.Exported = undefined;
    var buffer: [4096]u8 = undefined;
    files.put_dir("/slash", 0o755);
    try export_mod.export_layout(&store, &made, "/slash/", &buffer, &out, &failure);
    try export_mod.export_layout(&store, &made, "/fresh//", &buffer, &out, &failure);
    var text: [constants.pack_manifest_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(
        "{\"imageLayoutVersion\":\"1.0.0\"}",
        try read_back("/slash/oci-layout", &text),
    );
    try testing.expectEqualStrings(
        "{\"imageLayoutVersion\":\"1.0.0\"}",
        try read_back("/fresh/oci-layout", &text),
    );
    var counter: struct {
        names: u32 = 0,
        fn call(context: *anyopaque, name: []const u8) void {
            _ = name;
            const self: *@This() = @ptrCast(@alignCast(context));
            self.names += 1;
        }
    } = .{};
    try store.fs.read_dir("/slash", .{ .context = &counter, .call = @TypeOf(counter).call });
    try testing.expectEqual(@as(u32, 3), counter.names); // oci-layout, index.json, blobs.
}

test "a failed export leaves nothing under the name, and a damaged blob is dropped" {
    // Goal: the export is all or nothing, and never copies bytes that are not their digest.
    // Method: export below a missing parent (a write failure naming ENOENT), then overwrite the
    // layer blob with other bytes of its length, which must be refused as damaged with nothing
    // left at the target; the next pack rebuilds the blob and the export then succeeds.
    start(6, 0);
    const imported = try import_source(false);
    const made = try pack_tree(imported.digest, constants.pack_io_bytes);
    var failure: export_mod.Failure = undefined;
    var out: export_mod.Exported = undefined;
    var buffer: [4096]u8 = undefined;
    try testing.expectError(
        error.Stopped,
        export_mod.export_layout(&store, &made, "/missing/x", &buffer, &out, &failure),
    );
    try testing.expectEqual(export_mod.Stop.write, failure.stop);
    try testing.expectEqual(error.NotFound, failure.err);
    try testing.expectEqual(@as(u16, 2), failure.errno);

    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    const damaged_path = blobs.final_path(&path, made.layer);
    try store.fs.unlink(damaged_path); // `create` is exclusive: replace the blob by name.
    const fd = try store.fs.create(damaged_path, 0o644);
    var junk: [256]u8 = undefined;
    @memset(&junk, 0x5A);
    var left: u64 = made.layer_size;
    while (left > 0) {
        const piece: usize = @intCast(@min(left, junk.len));
        try store.fs.write_all(fd, junk[0..piece]);
        left -= piece;
    }
    store.fs.close(fd);
    try testing.expect(blobs.has(made.layer, made.layer_size)); // The size check is fooled.
    try testing.expectError(
        error.Stopped,
        export_mod.export_layout(&store, &made, "/export", &buffer, &out, &failure),
    );
    try testing.expectEqual(export_mod.Stop.damaged, failure.stop);
    try testing.expect(failure.digest.eql(made.layer));
    try testing.expectError(error.NotFound, store.fs.lstat("/export"));
    try testing.expect(!blobs.has(made.layer, made.layer_size));

    const again = try pack_tree(imported.digest, constants.pack_io_bytes);
    try testing.expect(!again.cached);
    try testing.expect(again.layer.eql(made.layer));
    try export_mod.export_layout(&store, &again, "/export", &buffer, &out, &failure);
}

/// A fixed root with every kind of entry: directories, files, a symlink, two files that are one
/// object (a hard link), a path longer than the ustar name field, and a kept attribute.
fn make_golden_source() void {
    files.put_dir("/src", 0o755);
    files.put_dir("/src/etc", 0o755);
    files.put_dir("/src/bin", 0o755);
    files.put_file("/src/etc/hostname", 0o644, "zbx\n");
    files.put_file("/src/etc/hostname.copy", 0o644, "zbx\n");
    files.put_symlink("/src/etc/localtime", "../usr/zone");
    files.put_file("/src/bin/tool", 0o755, "#!tool\n");
    files.put_xattr("/src/bin/tool", "user.note", "kept");
    var long_path: [128]u8 = undefined;
    @memcpy(long_path[0..5], "/src/");
    @memset(long_path[5..115], 'l');
    files.put_file(long_path[0..115], 0o600, "long\n");
}

/// The entries of the layer's tar, one line each: type byte, name, link name.
fn listing(made: pack.Packed, out: []u8) ![]const u8 {
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    try layer.start(store.fs, blobs.final_path(&path, made.layer));
    defer layer.close();
    const holder = struct {
        var tar: tar_mod.Reader = undefined;
    };
    holder.tar.init(layer.tar_reader(), 1 << 20);
    var writer: std.Io.Writer = .fixed(out);
    while (try holder.tar.next()) |item| {
        const mode = item.mode;
        if (item.name.len > 60) {
            const kind = @tagName(item.kind);
            try writer.print("{s} long({d}) {s} {o}", .{ kind, item.name.len, item.link, mode });
        } else {
            const kind = @tagName(item.kind);
            try writer.print("{s} {s} {s} {o}", .{ kind, item.name, item.link, mode });
        }
        for (item.xattrs) |attribute| {
            try writer.print(" {s}={s}", .{ attribute.name, attribute.value });
        }
        try writer.writeAll("\n");
    }
    return writer.buffered();
}

/// Packs the golden tree with writer `version` in a fresh store.
fn pack_golden(version: u32) !pack.Packed {
    sim.init(6, &.{});
    files.init(6);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    diag.reset();
    settings.clear();
    make_golden_source();
    const imported = try import_source(false);
    return pack_version(imported.digest, constants.pack_io_bytes, version);
}

test "the golden tree packs to fixed bytes, and its tar lists every entry kind in order" {
    // Goal: the digests are a promise (`layer_writer_version` 1). Method: pack a fixed tree of
    // every entry kind and compare the layer, diff id, config and manifest digests, the tar's
    // entries and the object count against literals taken from a reviewed run. A change that
    // moves one is a new writer version, or a bug.
    const made = try pack_golden(1);
    try testing.expect(made.index == null);
    var text: [1024]u8 = undefined;
    const lines = try listing(made, &text);
    try testing.expectEqualStrings(golden_listing, lines);
    try testing.expectEqualStrings(golden_layer, &made.layer.text());
    try testing.expectEqualStrings(golden_diff_id, &made.diff_id.text());
    // The config names the host's architecture, so its digest and the manifest's are per
    // architecture; the layer's are not.
    if (builtin.cpu.arch == .x86_64) {
        try testing.expectEqualStrings(golden_config_x86_64, &made.config.text());
        try testing.expectEqualStrings(golden_manifest_x86_64, &made.manifest.text());
    }
}

test "the golden tree packs to fixed bytes with writer 2, its index anchored at a fixed place" {
    // Goal: writer 2's digests and anchor are the same promise. Method: as for writer 1; the
    // tar lists the same entries, and the index is the bytes after them.
    const made = try pack_golden(2);
    var text: [1024]u8 = undefined;
    const lines = try listing(made, &text);
    try testing.expectEqualStrings(golden_listing, lines);
    var anchor_text: [index_mod.anchor_text_bytes_max]u8 = undefined;
    const anchor = made.index orelse return error.TestNoIndex;
    try testing.expectEqualStrings(golden_v2_anchor, anchor.render(&anchor_text));
    try testing.expectEqualStrings(golden_v2_layer, &made.layer.text());
    try testing.expectEqualStrings(golden_v2_diff_id, &made.diff_id.text());
    if (builtin.cpu.arch == .x86_64) {
        try testing.expectEqualStrings(golden_v2_config_x86_64, &made.config.text());
        try testing.expectEqualStrings(golden_v2_manifest_x86_64, &made.manifest.text());
    }
}

const golden_listing =
    \\directory ./  755
    \\directory bin/  755
    \\file bin/tool  755 user.note=kept
    \\directory etc/  755
    \\file etc/hostname  644
    \\hardlink etc/hostname.copy etc/hostname 644
    \\symlink etc/localtime ../usr/zone 777
    \\file long(110)  600
    \\
;
const golden_layer = "sha256:819a2bfa252009bd10c789437fd136d5d5cef6e59baa1ed609cb360e3e673499";
const golden_diff_id = "sha256:85a301655cac0027f21e3dd075696ac830ece2bfd6a248fddadb1a3a99a47583";
const golden_config_x86_64 =
    "sha256:df64ce2fc2b1e6ed71f1c4f88673b16d968b3130a3a2c51e549ed7739dafa287";
const golden_manifest_x86_64 =
    "sha256:9fb72b7ef67ab49164f62a0c208083bea73a9c06c40ca8742c6cc5620201d59d";

// Writer 2's goldens: taken from a reviewed run of the test above.
const golden_v2_anchor = "offset=553 length=529 size=1235 digest=b3:" ++
    "583a5ac82933d0cf9a9dcfb61f6240b5e539e994736d81098f77d4efe4bde2b8";
const golden_v2_layer =
    "sha256:5455021fdeb5104679205221c5f42e4cefb616cb2fb18ff5f624c87b670884d1";
const golden_v2_diff_id =
    "sha256:cee1c36b026692889d7e069f9a1e5503045479d58191395125a2762438bc7a0f";
const golden_v2_config_x86_64 =
    "sha256:4d8222c3e3b685e8d3c5d3caf9b406fe77222bfae1fa526222c3ec58191d7983";
const golden_v2_manifest_x86_64 =
    "sha256:ab6d038d21aa9233456f4ba008f25f4a989d166f8b7b709183a07f5f1c0284c6";

const config_mod = @import("../registry/config.zig");
const result_mod = @import("../build/result.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

var derive_record: result_mod.Record = undefined;
var derive_settings: images.Settings = undefined;
var derive_labels: images.Labels = undefined;
var derive_json: [constants.registry_manifest_bytes_max]u8 = undefined;
var derive_arena: [64 * 1024]u8 = undefined;

/// What a pull of the config this record's push writes would derive.
fn pushed_then_pulled(record: *const result_mod.Record) !?digest_mod.Digest {
    const input: pack.Input = .{
        .tree = record.tree,
        .settings = &record.config.settings,
        .labels = &record.config,
        .writer_version = constants.layer_writer_version,
    };
    const body = try pack.render_config(input, Sha256.of("diff"), &derive_json);
    try config_mod.parse(&derive_arena, body, &derive_settings, &derive_labels);
    return result_mod.derive(record.tree, &derive_settings, &derive_labels);
}

fn digest_of_record(record: *const result_mod.Record) !digest_mod.Digest {
    var bytes: [constants.build_result_bytes_max]u8 = undefined;
    return result_mod.result_digest(try result_mod.encode(record, &bytes));
}

const pool = [_][]const u8{
    "a", "", "sh -c", "quote\"d", "back\\slash", "tab\there", "/usr/bin/x",
};

fn random_record(random: std.Random, record: *result_mod.Record) void {
    record.config.clear();
    var name: [8]u8 = undefined;
    record.tree = digest_mod.Digest.of(std.mem.asBytes(&random.int(u64)));
    const cs = &record.config.settings;
    for (0..random.uintAtMost(u32, 3)) |_| {
        _ = cs.add(.entrypoint, pool[random.uintLessThan(usize, pool.len)]);
    }
    for (0..random.uintAtMost(u32, 3)) |_| {
        _ = cs.add(.cmd, pool[random.uintLessThan(usize, pool.len)]);
    }
    for (0..random.uintAtMost(u32, 3)) |index| {
        const text = std.fmt.bufPrint(&name, "K{d}", .{index}) catch {
            unreachable; // Eight bytes hold K and one digit.
        };
        var variable: [24]u8 = undefined;
        const word = pool[random.uintLessThan(usize, pool.len)];
        const full = std.fmt.bufPrint(&variable, "{s}={s}", .{ text, word }) catch {
            unreachable; // Twenty-four bytes hold a short name and a short word.
        };
        _ = cs.add(.env, full);
    }
    _ = cs.set(.workdir, pool[random.uintLessThan(usize, pool.len)]);
    _ = cs.set(.user, if (random.boolean()) "" else "1000:1000");
    for (0..random.uintAtMost(u32, 5)) |_| {
        const key = pool[random.uintLessThan(usize, pool.len)];
        _ = record.config.add_label(key, pool[random.uintLessThan(usize, pool.len)]);
    }
}

test "a pushed-then-pulled image derives the result it was made from, for random configs" {
    // Goal: the derived result equals the original (slice 14). Method: 300 seeded configs, each
    // through the push's config writer and the pull's reader.
    var prng = std.Random.Xoshiro256.init(14);
    const random = prng.random();
    for (0..300) |_| {
        random_record(random, &derive_record);
        const derived = (try pushed_then_pulled(&derive_record)).?;
        try testing.expect(derived.eql(try digest_of_record(&derive_record)));
    }
}

test "any changed field of the config changes the derived result, and an old record derives none" {
    // Goal: nothing of the config is left out of the digest. Method: change each field of one
    // record in turn; each result differs from the original and from every other.
    derive_record.config.clear();
    derive_record.tree = digest_mod.Digest.of("tree");
    const cs = &derive_record.config.settings;
    _ = cs.add(.entrypoint, "/entry");
    _ = cs.add(.cmd, "run");
    _ = cs.add(.env, "A=1");
    _ = cs.set(.workdir, "/w");
    _ = cs.set(.user, "5");
    _ = derive_record.config.add_label("k", "v");
    const original = (try pushed_then_pulled(&derive_record)).?;
    var seen: [11]digest_mod.Digest = undefined;
    var count: usize = 0;
    seen[count] = original;
    count += 1;
    const Change = enum {
        tree,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
        label_key,
        label_value,
        label_added,
        label_gone,
    };
    for (std.enums.values(Change)) |change| {
        var changed = derive_record;
        const edit = &changed.config;
        switch (change) {
            .tree => changed.tree = digest_mod.Digest.of("other"),
            .entrypoint => _ = edit.settings.add(.entrypoint, "x"),
            .cmd => edit.settings.cmd_count = 0,
            .env => _ = edit.settings.add(.env, "B=2"),
            .workdir => _ = edit.settings.set(.workdir, "/v"),
            .user => _ = edit.settings.set(.user, "6"),
            .label_key => {
                edit.clear_labels();
                _ = edit.add_label("j", "v");
            },
            .label_value => {
                edit.clear_labels();
                _ = edit.add_label("k", "w");
            },
            .label_added => _ = edit.add_label("l", "v"),
            .label_gone => edit.clear_labels(),
        }
        const derived = (try pushed_then_pulled(&changed)).?;
        for (seen[0..count]) |before| try testing.expect(!before.eql(derived));
        seen[count] = derived;
        count += 1;
    }
    derive_labels.forget();
    const settings_of = &derive_record.config.settings;
    try testing.expect(result_mod.derive(derive_record.tree, settings_of, &derive_labels) == null);
}
