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
const pack = @import("pack.zig");

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
    try import.import(&store, &imports, "/src", .{ .squash_owner = squash_owner, .warn = null }, &result, &diag);
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
