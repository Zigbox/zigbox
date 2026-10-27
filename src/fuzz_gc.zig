//! The `gc` fuzzer: `gc` (plan, apply, trash, restore) and `verify` against the simulated file
//! system, with the faults of the `store` fuzzer.
//!
//! Each iteration builds two to four random trees that share a base and differ by a few files
//! of random size (so some objects have chunk lists), imports them all, then drops the roots of
//! some and marks some of the dropped as used by a running container. The oracle is a second,
//! clean file system in which only the kept and live trees were ever imported. Properties:
//!   1. A plan is the same twice; after any write to the store it is not.
//!   2. An apply, under any fault that lets it succeed, leaves exactly the oracle's objects and
//!      trees in the store (the rest is in the trash, none of it deleted).
//!   3. An apply that fails or is crashed (after the restart) leaves a store that is whole and
//!      verifies clean, and applying again ends with the oracle's files.
//!   4. Restoring every trash, under a fault at a random write point and then again without one,
//!      gives back exactly the files the store had before the gc, and verify is clean.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Diag = @import("diag/diag.zig").Diag;
const digest_mod = @import("store/digest.zig");
const fs_sim = @import("store/fs_sim.zig");
const fuzz_store = @import("fuzz_store.zig");
const gc = @import("store/gc.zig");
const generation = @import("store/generation.zig");
const host_sim = @import("host_sim.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const roots = @import("store/roots.zig");
const support = @import("store/test_support.zig");
const verify = @import("store/verify.zig");

const Digest = digest_mod.Digest;

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var reference_files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var workspace: import.Workspace = undefined;
var gc_workspace: gc.Workspace = undefined;
var verify_workspace: verify.Workspace = undefined;
var diag: Diag = undefined;

const versions_max = 4;

/// Builds version `number` of the tree at `/v0N`: the shared base and a few files of its own.
fn build_version(target: *fs_sim.SimFs, tree_seed: u64, number: u32) void {
    switch (number) {
        0 => fuzz_store.build_tree(tree_seed, target, "/va0"),
        1 => fuzz_store.build_tree(tree_seed, target, "/va1"),
        2 => fuzz_store.build_tree(tree_seed, target, "/va2"),
        else => fuzz_store.build_tree(tree_seed, target, "/va3"),
    }
    var prng = std.Random.Xoshiro256.init(tree_seed +% number +% 1);
    const random = prng.random();
    const own = random.intRangeAtMost(u32, 1, 3);
    for (0..own) |index| {
        var path: [32]u8 = undefined;
        // Cannot fail: a few short parts.
        const name = std.fmt.bufPrint(&path, "/va{d}/own{d}", .{ number, index }) catch unreachable;
        var content: [40]u8 = undefined;
        const length = random.uintLessThan(usize, content.len);
        for (content[0..length]) |*byte| byte.* = 'a' + random.uintLessThan(u8, 26);
        target.put_file(name, 0o644, content[0..length]);
    }
}

fn version_path(number: u32) []const u8 {
    return switch (number) {
        0 => "/va0",
        1 => "/va1",
        2 => "/va2",
        else => "/va3",
    };
}

fn import_version(target: *layout.Store, number: u32) Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(target, &workspace, version_path(number), options, &result, &diag) catch {
        unreachable; // A clean import of a valid tree.
    };
    return result.digest;
}

/// What the store holds: how many files under objects/ and trees/, and a hash of their paths
/// that does not depend on the order they are listed in.
const Fingerprint = struct {
    count: u32,
    mix: u64,

    fn of(fs: *const fs_sim.SimFs) Fingerprint {
        var print: Fingerprint = .{ .count = 0, .mix = 0 };
        var index: u32 = 0;
        while (index < fs.count) : (index += 1) {
            const path = fs.alive_path(index) orelse continue;
            if (fs.kind_of(path).? != .file) continue;
            const kept = std.mem.startsWith(u8, path, root_path ++ "/objects/") or
                std.mem.startsWith(u8, path, root_path ++ "/trees/");
            if (!kept) continue;
            print.count += 1;
            print.mix +%= std.mem.readInt(u64, Digest.of(path).bytes[0..8], .little);
        }
        return print;
    }

    fn eql(first: Fingerprint, second: Fingerprint) bool {
        return first.count == second.count and first.mix == second.mix;
    }
};

fn plan(live: []const Digest) ?gc.Plan {
    var result: gc.Plan = undefined;
    var failure: gc.Failure = undefined;
    gc.plan(&store, &gc_workspace, &workspace.arena, live, &result, &failure) catch return null;
    return result;
}

fn apply(live: []const Digest, hash: Digest) bool {
    var result: gc.Applied = undefined;
    var failure: gc.Failure = undefined;
    gc.apply(&store, &gc_workspace, &workspace.arena, live, hash, &result, &failure) catch |err| {
        if (files.faults.crash_mutation == null and files.faults.fail_mutation == null) {
            std.debug.print("apply {s}: {any}\n", .{ @errorName(err), failure });
        }
        return false;
    };
    return true;
}

fn verify_clean(chunk_bytes: u32) void {
    var totals: verify.Totals = undefined;
    var failure: verify.Failure = undefined;
    verify.verify(&store, &verify_workspace, &workspace.arena, &totals, &failure) catch {
        unreachable; // The simulated store lists.
    };
    if (totals.damaged != 0) {
        const first = verify_workspace.damage[0];
        std.debug.panic(
            "damaged {d}: {s} {s} {s}",
            .{ totals.damaged, @tagName(first.class), @tagName(first.kind), first.id.text() },
        );
    }
    support.check_whole(&files, root_path, chunk_bytes) catch std.debug.panic("not whole", .{});
}

const Fault = enum { none, harmless, fail_point, crash_point };

fn set_fault(random: std.Random, fault: Fault) void {
    files.mutations = 0;
    switch (fault) {
        .none => {},
        .harmless => {
            files.faults.interrupt_per_mille = random.uintLessThan(u16, 400);
            files.faults.short_read_per_mille = random.uintLessThan(u16, 1000);
            files.faults.short_write_per_mille = random.uintLessThan(u16, 1000);
        },
        .fail_point => files.faults.fail_mutation = random.uintLessThan(u32, 90),
        .crash_point => files.faults.crash_mutation = random.uintLessThan(u32, 90),
    }
}

fn end_fault(fault: Fault) void {
    files.faults = .{};
    if (fault == .crash_point) files.restart();
    assert(files.open_count() == 0);
}

pub fn fuzz_gc(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const tree_seed = random.int(u64);
    const chunk_sizes = [_]u32{ 8, 16, 4096 };
    const chunk_bytes = chunk_sizes[random.uintLessThan(usize, chunk_sizes.len)];
    const versions = random.intRangeAtMost(u32, 2, versions_max);
    // Which versions stay roots, and which of the others a container uses.
    const kept_mask = random.uintLessThan(u32, @as(u32, 1) << @intCast(versions));
    const live_mask = random.int(u32) & ~kept_mask;
    const keep_all = (@as(u32, 1) << @intCast(versions)) - 1;
    const wanted = kept_mask | live_mask;
    _ = keep_all;

    const oracle = oracle_fingerprint(tree_seed, chunk_bytes, versions, wanted);
    sim.init(seed, &.{});
    files.init(seed);
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    sim.store_fs = &files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    sim.world.now = 1_800_000_000;
    var digests: [versions_max]Digest = undefined;
    var live: [versions_max]Digest = undefined;
    var live_count: usize = 0;
    for (0..versions) |number| {
        build_version(&files, tree_seed, @intCast(number));
        digests[number] = import_version(&store, @intCast(number));
    }
    for (0..versions) |number| {
        const bit = @as(u32, 1) << @intCast(number);
        // Two versions can come out identical, and then they are one root.
        var same_as_kept = false;
        for (0..versions) |other| {
            const kept = kept_mask & (@as(u32, 1) << @intCast(other)) != 0;
            if (kept and digests[other].eql(digests[number])) same_as_kept = true;
        }
        if (kept_mask & bit == 0 and !same_as_kept) {
            // A second version with the same tree has no second root to remove.
            roots.remove(&store, digests[number]) catch {};
        }
        if (live_mask & bit != 0) {
            live[live_count] = digests[number];
            live_count += 1;
        }
    }
    const before = Fingerprint.of(&files);
    run_gc(random, live[0..live_count], chunk_bytes, oracle);
    run_restore(random, chunk_bytes, before);
}

/// The files of a clean store into which only the `wanted` versions were imported.
fn oracle_fingerprint(tree_seed: u64, chunk_bytes: u32, versions: u32, wanted: u32) Fingerprint {
    sim.init(1, &.{});
    reference_files.init(1);
    reference_files.put_dir("/data", 0o755);
    support.make_store_directories(&reference_files, root_path);
    sim.store_fs = &reference_files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    for (0..versions) |number| {
        build_version(&reference_files, tree_seed, @intCast(number));
        if (wanted & (@as(
            u32,
            1,
        ) << @intCast(number)) != 0) _ = import_version(&store, @intCast(number));
    }
    return Fingerprint.of(&reference_files);
}

fn run_gc(random: std.Random, live: []const Digest, chunk_bytes: u32, oracle: Fingerprint) void {
    const first = plan(live).?;
    assert(plan(live).?.hash.eql(first.hash)); // Property 1.
    var failure: @import("store/fs.zig").Failure = undefined;
    generation.bump(&store, &failure) catch unreachable; // Writes are on.
    const raised = plan(live).?;
    assert(!raised.hash.eql(first.hash));
    const fault = random.enumValue(Fault);
    set_fault(random, fault);
    var finished = false;
    if (plan(live)) |planned| finished = apply(live, planned.hash);
    end_fault(fault);
    if (!finished) assert(fault != .none);
    verify_clean(chunk_bytes);
    // Whatever happened, applying again ends with the oracle's files.
    var rounds: u32 = 0;
    while (rounds < 4) : (rounds += 1) {
        const planned = plan(live).?;
        if (planned.counts.total() == 0) break;
        assert(apply(live, planned.hash));
    }
    assert(plan(live).?.counts.total() == 0);
    const now = Fingerprint.of(&files);
    if (!now.eql(oracle)) {
        var index: u32 = 0;
        while (index < reference_files.count) : (index += 1) {
            const path = reference_files.alive_path(index) orelse continue;
            if (!std.mem.startsWith(
                u8,
                path,
                root_path ++ "/objects/",
            ) and !std.mem.startsWith(u8, path, root_path ++ "/trees/")) continue;
            if (files.kind_of(path) == null) std.debug.print(
                "missing {s} {d}\n",
                .{ path, reference_files.content_of(path).?.len },
            );
        }
        std.debug.panic("gc: {d} files, expected {d}", .{ now.count, oracle.count });
    }
    verify_clean(chunk_bytes);
}

fn run_restore(random: std.Random, chunk_bytes: u32, before: Fingerprint) void {
    var entries: [constants.store_trash_entries_max]gc.TrashEntry = undefined;
    var listing: gc.Trash = undefined;
    var failure: gc.Failure = undefined;
    var names: [8192]u8 = undefined;
    var offsets: [64]u32 = undefined;
    gc.list_trash(&store, &names, &offsets, &entries, &listing, &failure) catch {
        std.debug.panic("list_trash {any}", .{failure});
    };
    const fault = random.enumValue(Fault);
    for (entries[0..listing.count], 0..) |entry, at| {
        if (at == 0) set_fault(random, fault);
        _ = restore_one(entry.id);
        if (at == 0) end_fault(fault);
        verify_clean(chunk_bytes);
        _ = restore_one(entry.id); // Again: finishes it, or finds it gone.
    }
    const now = Fingerprint.of(&files);
    if (!now.eql(before)) std.debug.panic(
        "restore: {d} files, expected {d}",
        .{ now.count, before.count },
    );
    verify_clean(chunk_bytes);
}

fn restore_one(id: gc.Id) bool {
    var result: gc.Restored = undefined;
    var failure: gc.Failure = undefined;
    gc.restore(&store, &gc_workspace, &workspace.arena, id, &result, &failure) catch return false;
    return true;
}
