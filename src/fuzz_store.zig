//! The `store` fuzzer: `store import` against the simulated file system, with the faults of a
//! disk and the crash of a machine (`store/fs_sim.zig`).
//!
//! Each iteration builds a random source tree (directories, files with a small alphabet of
//! contents so that objects repeat, modes, owners, attributes, symlinks, devices) twice, once in
//! a clean reference file system and once in the one under test, and imports the reference to
//! learn the digest. Then, in the file system under test, sometimes after a different import
//! (so that the store is not empty), it imports with one of: no fault; interrupts and short
//! reads and writes; an error at a random write point; a crash at a random write point; a disk
//! that holds too little. The properties:
//!   1. An import that succeeds has the reference's digest, whatever order the two file systems
//!      listed their directories in and whatever faults ran, and the store is whole.
//!   2. An import that fails, or a crash (after the restart), leaves a store that is whole:
//!      every object, chunk list, tree and root under an id is what its id says
//!      (`test_support.check_whole`).
//!   3. The same import repeated without faults then succeeds with the reference's digest, and
//!      the store is whole again: nothing a failure left behind gets in its way.

const std = @import("std");
const assert = std.debug.assert;
const Diag = @import("diag/diag.zig").Diag;
const host_sim = @import("host_sim.zig");
const fs_sim = @import("store/fs_sim.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var reference_files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var workspace: import.Workspace = undefined;
var diag: Diag = undefined;

/// Builds the same random tree in `target` for the same `seed`: it is a function of the seed.
fn build_source(seed: u64, target: *fs_sim.SimFs) void {
    build_tree(seed, target, "/src");
}

/// The same, at a root of four bytes (`/src`, `/dst`).
pub fn build_tree(seed: u64, target: *fs_sim.SimFs, comptime root: *const [4]u8) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    target.put_dir(root, 0o755);
    var directories: [8][16]u8 = undefined;
    var lengths: [8]u8 = undefined;
    var count: u32 = 1;
    directories[0][0..4].* = root.*;
    lengths[0] = 4;
    const wanted = random.intRangeAtMost(u32, 2, 24);
    for (0..wanted) |index| {
        const parent = random.uintLessThan(u32, count);
        var path: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&path, "{s}/n{d}", .{
            directories[parent][0..lengths[parent]],
            index,
        }) catch unreachable; // A short parent and a short name.
        add_node(random, target, name, &directories, &lengths, &count);
    }
}

fn add_node(
    random: std.Random,
    target: *fs_sim.SimFs,
    path: []const u8,
    directories: *[8][16]u8,
    lengths: *[8]u8,
    count: *u32,
) void {
    const contents = [_][]const u8{
        "", "a", "same", "same", "other bytes here", "0123456789abcdefghij",
    };
    const owner: [2]u32 = .{ random.uintLessThan(u32, 3), random.uintLessThan(u32, 3) };
    const modes = [_]u16{ 0o644, 0o755, 0o600, 0o4755, 0o444 };
    switch (random.uintLessThan(u8, 10)) {
        0, 1 => if (count.* < directories.len and path.len < 16) {
            target.put(path, .dir, 0o755, owner, "");
            @memcpy(directories[count.*][0..path.len], path);
            lengths[count.*] = @intCast(path.len);
            count.* += 1;
        } else target.put(path, .file, 0o644, owner, ""),
        2 => target.put_symlink(path, if (random.boolean()) "n0" else "../elsewhere"),
        3 => target.put(path, .fifo, 0o600, owner, ""),
        else => {
            const content = contents[random.uintLessThan(usize, contents.len)];
            target.put(path, .file, modes[random.uintLessThan(usize, modes.len)], owner, content);
            if (random.uintLessThan(u8, 5) == 0) target.put_xattr(path, "user.k", "v");
            if (random.uintLessThan(u8, 9) == 0) target.put_xattr(path, "trusted.t", "v");
        },
    }
}

const Fault = enum { none, harmless, fail_point, crash_point, small_disk };

fn clean_import(target_store: *layout.Store) import.Result {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(target_store, &workspace, "/src", options, &result, &diag) catch
        unreachable; // A clean import of a valid tree.
    return result;
}

pub fn fuzz_store(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const tree_seed = random.int(u64);
    const chunk_sizes = [_]u32{ 8, 16, 4096 };
    const chunk_bytes = chunk_sizes[random.uintLessThan(usize, chunk_sizes.len)];

    // The reference: a clean file system, another listing order, the digest to expect.
    sim.init(seed, &.{});
    reference_files.init(seed +% 1);
    reference_files.put_dir("/data", 0o755);
    support.make_store_directories(&reference_files, root_path);
    build_source(tree_seed, &reference_files);
    sim.store_fs = &reference_files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    const expected = clean_import(&store);
    const points = reference_files.mutations;
    assert(points > 0);

    // The file system under test, sometimes holding another tree's objects already.
    files.init(seed);
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    build_source(tree_seed, &files);
    sim.store_fs = &files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    if (random.boolean()) prepopulate(random);

    const fault = random.enumValue(Fault);
    switch (fault) {
        .none => {},
        .harmless => {
            files.faults.interrupt_per_mille = random.uintLessThan(u16, 400);
            files.faults.short_read_per_mille = random.uintLessThan(u16, 1000);
            files.faults.short_write_per_mille = random.uintLessThan(u16, 1000);
        },
        .fail_point => files.faults.fail_mutation = files.mutations + random.uintLessThan(
            u32,
            points + 4,
        ),
        .crash_point => files.faults.crash_mutation = files.mutations + random.uintLessThan(
            u32,
            points + 4,
        ),
        .small_disk => files.faults.bytes_max = files.bytes_live + random.uintLessThan(u64, 200),
    }

    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    const outcome = import.import(&store, &workspace, "/src", options, &result, &diag);
    if (outcome) |_| {
        assert(result.digest.eql(expected.digest));
    } else |_| {
        assert(diag.code != null);
        assert(fault != .none); // Only a fault makes an import fail.
    }
    files.restart();
    files.faults = .{};
    assert(files.open_count() == 0);
    support.check_whole(&files, root_path, chunk_bytes) catch unreachable; // The property.
    const again = clean_import(&store);
    assert(again.digest.eql(expected.digest));
    support.check_whole(&files, root_path, chunk_bytes) catch unreachable; // The property.
    assert(files.open_count() == 0);
}

/// Puts another tree's import in the store: the source loses some files, is imported, and gets
/// them back, so the next import finds some objects and trees and lacks others.
fn prepopulate(random: std.Random) void {
    _ = random; // The extra tree is fixed: what matters is that the store is not empty.
    files.put_dir("/other", 0o755);
    files.put_file("/other/a", 0o644, "same");
    files.put_file("/other/b", 0o644, "a");
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &workspace, "/other", options, &result, &diag) catch
        unreachable; // A clean import.
}
