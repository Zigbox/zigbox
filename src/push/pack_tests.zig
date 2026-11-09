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
        // Without the record the pack walks and compresses again: a cached one proves nothing.
        pack.forget(&store, second_import.digest);
        const other = try pack_tree(second_import.digest, piece);
        try testing.expect(!other.cached);
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

test "the golden tree packs to fixed bytes, and its tar lists every entry kind in order" {
    // Goal: the digests are a promise (`layer_writer_version` 1). Method: pack a fixed tree of
    // every entry kind and compare the layer, diff id, config and manifest digests, the tar's
    // entries and the object count against literals taken from a reviewed run. A change that
    // moves one is a new writer version, or a bug.
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
    const made = try pack_tree(imported.digest, constants.pack_io_bytes);
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
