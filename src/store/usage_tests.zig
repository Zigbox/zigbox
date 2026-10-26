//! Tests of `usage.zig`: the totals of the store, and what one tree costs and shares.

const std = @import("std");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const roots = @import("roots.zig");
const support = @import("test_support.zig");
const usage = @import("usage.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var workspace: import.Workspace = undefined;
var diag: Diag = undefined;
var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;
var root_list: [constants.store_roots_max]roots.Root = undefined;

fn start() void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, "/data/store");
    store.at(sim.interface(), "/data/store");
    support.make_source(&files, 0);
    diag.reset();
}

fn import_source() !Digest {
    var result: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &workspace, "/src", options, &result, &diag);
    return result.digest;
}

fn memory() usage.Memory {
    const arena = &workspace.arena;
    const half = arena.len / 2;
    const quarter = arena.len / 4;
    return .{
        .tree_buffer = &tree_buffer,
        .objects = @alignCast(arena[0..half]),
        .visited = @alignCast(arena[half .. half + quarter]),
        .stack = std.mem.bytesAsSlice(Digest, arena[half + quarter ..]),
        .root_list = &root_list,
        .names = &workspace.io,
    };
}

test "the store's totals count objects and trees, and the bytes of both" {
    // Goal: `du` without a digest. Method: import the sample, compare with the simulator's own
    // count of the files under the store.
    start();
    _ = try import_source();
    var total: usage.Total = undefined;
    var failure: usage.Failure = undefined;
    try usage.store_total(&store, &workspace.arena, &total, &failure);
    try testing.expectEqual(@as(u64, 6), total.objects);
    try testing.expectEqual(@as(u64, 4), total.trees);
    const held = support.bytes_under(&files, "/data/store/objects") +
        support.bytes_under(&files, "/data/store/trees");
    try testing.expectEqual(held, total.bytes);
}

test "a tree's cost is its distinct objects, and it shares what another root also has" {
    // Goal: logical, stored and shared sizes. Method: import, add a file, import again: the
    // second tree shares everything the first has; the first shares all it has with the second.
    start();
    const first = try import_source();
    var mem = memory();
    var result: usage.TreeUsage = undefined;
    var failure: usage.Failure = undefined;
    try usage.tree_usage(&store, &mem, first, &result, &failure);
    try testing.expectEqual(@as(u64, 6), result.files);
    try testing.expectEqual(@as(u64, 41), result.logical_bytes);
    try testing.expectEqual(@as(u64, 6), result.objects);
    try testing.expectEqual(@as(u64, 41), result.stored_bytes);
    try testing.expectEqual(@as(u64, 0), result.shared_bytes);
    files.put_file("/src/etc/new", 0o644, "0123456789");
    const second = try import_source();
    mem = memory();
    try usage.tree_usage(&store, &mem, second, &result, &failure);
    try testing.expectEqual(@as(u64, 51), result.stored_bytes);
    try testing.expectEqual(@as(u64, 41), result.shared_bytes);
    try usage.tree_usage(&store, &mem, first, &result, &failure);
    try testing.expectEqual(@as(u64, 41), result.shared_bytes);
}

test "a tree that is not in the store is reported as missing" {
    // Goal: the walk names what it could not find. Method: a digest nothing wrote.
    start();
    _ = try import_source();
    var mem = memory();
    var result: usage.TreeUsage = undefined;
    var failure: usage.Failure = undefined;
    try testing.expectError(
        error.Failed,
        usage.tree_usage(&store, &mem, Digest.of("none"), &result, &failure),
    );
    try testing.expect(failure.tree.kind == .missing);
}
