//! Tests of `pack.zig` against the simulated file system: that one tree gives one image on every
//! pack and at every buffer size, that a second pack finds the first one's layer, and that a tree
//! with a missing object is refused.

const std = @import("std");
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
const pack = @import("pack.zig");
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
    var made: pack.Packed = undefined;
    var failure: pack.Failure = undefined;
    const input: pack.Input = .{ .tree = tree, .settings = &settings, .labels = null };
    packing.piece = piece;
    try pack.pack_pieces(&store, &packing, input, &made, &failure);
    return made;
}

test "one tree packs to one image, on every pack and at every buffer size" {
    // Goal: the determinism promise. Method: pack the sample tree in two stores, imported in
    // different directory orders, and again at other piece sizes; compare all digests.
    start(1, 0);
    const first_import = try import_source(false);
    const first = try pack_tree(first_import.digest, constants.pack_io_bytes);
    try testing.expect(!first.cached);
    try testing.expect(first.layer_size > 0);

    const again = try pack_tree(first_import.digest, constants.pack_io_bytes);
    try testing.expect(again.cached);
    try testing.expectEqualSlices(u8, &first.manifest.bytes, &again.manifest.bytes);
    try testing.expectEqualSlices(u8, &first.layer.bytes, &again.layer.bytes);

    start(2, 1);
    const second_import = try import_source(false);
    try testing.expect(first_import.digest.eql(second_import.digest));
    for ([_]u32{ 1024, 4099, 65536 }) |piece| {
        const other = try pack_tree(second_import.digest, piece);
        try testing.expectEqualSlices(u8, &first.manifest.bytes, &other.manifest.bytes);
        try testing.expectEqualSlices(u8, &first.config.bytes, &other.config.bytes);
        try testing.expectEqualSlices(u8, &first.layer.bytes, &other.layer.bytes);
        try testing.expectEqualSlices(u8, &first.diff_id.bytes, &other.diff_id.bytes);
        try testing.expectEqual(first.layer_size, other.layer_size);
    }
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
    // Goal: the round trip. Method: import /src, pack, apply the layer to a new directory and
    // import that; the digests agree, with owners kept and with owners squashed to 0.
    for ([_]bool{ false, true }) |squash| {
        start(3, 0);
        const imported = try import_source(squash);
        const made = try pack_tree(imported.digest, constants.pack_io_bytes);
        const again = try round_trip(made, squash);
        try testing.expect(imported.digest.eql(again));
    }
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
    const input: pack.Input = .{ .tree = imported.digest, .settings = &settings, .labels = null };
    packing.piece = constants.pack_io_bytes;

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
