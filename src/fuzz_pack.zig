//! The `pack` fuzzer: `zig build fuzz -- pack`. Each iteration builds a random source tree (the
//! `store` fuzzer's generator: directories, files that share contents so that objects repeat and
//! become hard links, attributes, symlinks, owners), imports it in a random id mode, packs it at
//! a random buffer size, and checks:
//!
//!   1. Packing never fails on a whole tree, and a second pack at another buffer size gives the
//!      same layer, config and manifest digests: the bytes do not depend on chunking. The pack
//!      record is dropped between the two, so the second one really packs.
//!   2. Applying the layer to a fresh directory and importing it gives the tree digest the pack
//!      started from, and the layer file's hash is the digest the pack reported.
//!   3. The tar writer never writes past its header bounds: the layer file is a multiple of the
//!      block size once decompressed, which the applier's success shows, and every header
//!      assertion in `tar_write.zig` stays on in this build.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Diag = @import("diag/diag.zig").Diag;
const host_sim = @import("host_sim.zig");
const fuzz_store = @import("fuzz_store.zig");
const apply = @import("layer/apply.zig");
const reader_mod = @import("layer/reader.zig");
const blobs_mod = @import("registry/blobs.zig");
const fs_sim = @import("store/fs_sim.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");
const PathBuf = @import("store/fs.zig").PathBuf;
const pack = @import("push/pack.zig");

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var imports: import.Workspace = undefined;
var packing: pack.Workspace = undefined;
var diag: Diag = undefined;
var settings: images.Settings = undefined;
var applier: apply.Applier = undefined;
var layer: reader_mod.Layer = undefined;

const pieces = [_]u32{ 1024, 1500, 4099, 65536, constants.pack_io_bytes };

fn pack_at(tree: @import("store/digest.zig").Digest, piece: u32) pack.Packed {
    var made: pack.Packed = undefined;
    var failure: pack.Failure = undefined;
    const input: pack.Input = .{ .tree = tree, .settings = &settings, .labels = null };
    packing.piece = piece;
    pack.pack_pieces(&store, &packing, input, &made, &failure) catch
        @panic("a whole tree must pack");
    return made;
}

/// A name of `length` bytes drawn from letters, or (when `raw`) from any byte but '/' and NUL.
fn make_name(random: std.Random, out: []u8, raw: bool) void {
    for (out) |*byte| {
        if (raw) {
            byte.* = random.intRangeAtMost(u8, 1, 255);
            if (byte.* == '/') byte.* = 0xC3;
        } else {
            byte.* = 'a' + random.uintLessThan(u8, 26);
        }
    }
}

/// Adds what the plain generator never makes, which is what the tar writer's long-field branches
/// are for: names around the 100-byte field, a deep path of long names, symlink targets past 100
/// bytes, ids past seven octal digits and bytes that are not UTF-8.
fn add_long_entries(random: std.Random, target: *fs_sim.SimFs) void {
    var name: [256]u8 = undefined;
    var path: [constants.path_bytes_max]u8 = undefined;
    @memcpy(path[0..5], "/src/");
    const lengths = [_]u32{ 94, 95, 99, 100, 101, 105, 110 };
    for (0..1 + random.uintLessThan(u32, 4)) |_| {
        const length = lengths[random.uintLessThan(usize, lengths.len)];
        const raw = random.boolean();
        make_name(random, name[0..length], raw);
        const text = path[0 .. 5 + length];
        @memcpy(text[5..], name[0..length]);
        const owner: [2]u32 = .{ random.int(u32), random.int(u32) };
        target.put(text, .file, 0o644, owner, "long");
    }
    var link: [constants.path_bytes_max]u8 = undefined;
    for (0..random.uintLessThan(u32, 3)) |index| {
        const length = random.intRangeAtMost(u32, 99, 300);
        make_name(random, link[0..length], false);
        const at = std.fmt.bufPrint(path[5..], "link{d}", .{index}) catch unreachable; // Short.
        target.put_symlink(path[0 .. 5 + at.len], link[0..length]);
    }
    deep_chain(random, target, &path);
}

/// A chain of directories with long names, ending in a file: a path past 100 bytes up to the
/// sim's 192-byte limit
/// (the file system model holds no longer path).
fn deep_chain(
    random: std.Random,
    target: *fs_sim.SimFs,
    path: *[constants.path_bytes_max]u8,
) void {
    if (random.boolean()) return;
    var name: [256]u8 = undefined;
    var length: usize = 5;
    const depth = random.intRangeAtMost(u32, 1, 3);
    for (0..depth) |_| {
        const part = random.intRangeAtMost(u32, 12, 30);
        make_name(random, name[0..part], false);
        @memcpy(path[length..][0..part], name[0..part]);
        length += part;
        target.put_dir(path[0..length], 0o755);
        path[length] = '/';
        length += 1;
    }
    const room: u32 = constants.sim_fs_path_bytes_max - 2 - @as(u32, @intCast(length));
    const part = random.intRangeAtMost(u32, 60, room);
    make_name(random, name[0..part], false);
    @memcpy(path[length..][0..part], name[0..part]);
    target.put(path[0 .. length + part], .file, 0o644, .{ 0, 0 }, "deep");
}

pub fn fuzz_pack(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    fuzz_store.build_tree(seed, &files, "/src");
    add_long_entries(random, &files);
    diag.reset();
    settings.clear();

    const squash = random.boolean();
    var imported: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = squash, .warn = null };
    import.import(&store, &imports, "/src", options, &imported, &diag) catch
        @panic("a generated tree must import");

    const first = pack_at(imported.digest, pieces[random.uintLessThan(usize, pieces.len)]);
    // Drop the record, or the second pack would recall the first and compare it with itself.
    pack.forget(&store, imported.digest);
    const other = pack_at(imported.digest, pieces[random.uintLessThan(usize, pieces.len)]);
    assert(!first.cached);
    assert(!other.cached);
    assert(first.layer_size == other.layer_size);
    assert(first.layer.eql(other.layer));
    assert(first.config.eql(other.config));
    assert(first.manifest.eql(other.manifest));
    assert(first.diff_id.eql(other.diff_id));

    files.put_dir("/out", 0o755);
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    applier.start(store.fs, "/out", squash);
    layer.start(store.fs, blobs.final_path(&path, first.layer)) catch
        @panic("the layer blob must open");
    defer layer.close();
    applier.apply_layer(&layer) catch @panic("a packed layer must apply");
    const diff = layer.finish() catch @panic("a packed layer must finish");
    assert(diff.eql(first.layer));
    var again: import.Result = undefined;
    diag.reset();
    import.import(&store, &imports, "/out", options, &again, &diag) catch
        @panic("an applied layer must import");
    assert(again.digest.eql(imported.digest));
}

test "the pack fuzzer runs a few seeds without a failed property" {
    // Goal: the properties hold on a spread of trees; `zig build fuzz -- pack` runs more.
    for (1..40) |seed| fuzz_pack(seed);
}
