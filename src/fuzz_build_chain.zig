//! The `build_chain` fuzzer: random chains of root and copy steps over the simulated store, with
//! a crash at a random write (docs/briefs/M9-dockerfile-import.md, slice 2).
//!
//! Each iteration makes a base tree and a source tree from the seed, then a chain of two to five
//! steps: a root step commits a random upper layer onto the current tree (`import.commit`, as
//! `step.zig` does), a copy step selects random top-level names of the source tree under a
//! destination and lays them over the current tree with the replace merge (`copy.select`,
//! `assemble.merge`, as `compose.zig` does). The chain runs in a clean file system for the
//! digests it must have, and again in a second one with a crash at a random write. Properties:
//!   1. A crash leaves a store that is whole (`test_support.check_whole`).
//!   2. The chain run again, after the restart, gives the clean run's digest at every step: a
//!      step's output is a function of its base and its sources, whatever a crash left.
//!   3. A copy is a pure function of what its patterns take: a file the patterns do not name,
//!      added to the source, gives the same selection.
//!   4. A cache never changes a key: the same spec with and without cache mounts has one key.
//!   5. A copy step's `.chown` and `.chmod` (`copy_owner.restamp`, drawn on some copy steps) is
//!      idempotent, changes nothing outside `.to`, and leaves each directory the base already
//!      has on the way to `.to` with its own mode and owner.

const std = @import("std");
const assert = std.debug.assert;
const assemble = @import("build/assemble.zig");
const constants = @import("constants.zig");
const copy = @import("build/copy.zig");
const copy_owner = @import("build/copy_owner.zig");
const Diag = @import("diag/diag.zig").Diag;
const digest_mod = @import("store/digest.zig");
const fs_sim = @import("store/fs_sim.zig");
const fuzz_store = @import("fuzz_store.zig");
const host_sim = @import("host_sim.zig");
const import = @import("store/import.zig");
const key_mod = @import("build/key.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");
const tree = @import("store/tree.zig");
const trees = @import("store/trees.zig");

const Digest = digest_mod.Digest;

const root_path = "/data/store";
const steps_max = 5;
const names_max = 16;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var reference_files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_ws: import.Workspace = undefined;
var copy_ws: copy.Workspace = undefined;
var owner_ws: copy_owner.Workspace = undefined;
var failure: assemble.Failure = undefined;
var diag: Diag = undefined;

const Error = error{StepFailed};

/// One step of the chain; every field is drawn once, from the seed.
const Step = struct {
    root: bool,
    /// A root step's layer: which of `/u0`..`/u4` it is, and its seed.
    layer_seed: u64,
    /// A copy step: the subset of the source's top-level names it takes, and where they go.
    mask: u16,
    to: u8,
    replace_names: bool,
    /// A copy step's `.chown` and `.chmod`; most change nothing.
    stamp: copy_owner.Stamp,
};

const destinations = [_][]const u8{ "/", "/opt/", "/a/b/" };

const Plan = struct {
    steps: [steps_max]Step,
    count: u32,
    tree_seed: u64,
    chunk_bytes: u32,
};

fn draw(random: std.Random) Plan {
    var plan: Plan = undefined;
    plan.count = random.intRangeAtMost(u32, 2, steps_max);
    plan.tree_seed = random.int(u64);
    const sizes = [_]u32{ 8, 16, 4096 };
    plan.chunk_bytes = sizes[random.uintLessThan(usize, sizes.len)];
    for (plan.steps[0..plan.count]) |*step| {
        step.* = .{
            .root = random.boolean(),
            .layer_seed = random.int(u64),
            .mask = random.int(u16) | 1,
            .to = random.uintLessThan(u8, destinations.len),
            .replace_names = random.boolean(),
            .stamp = draw_stamp(random),
        };
    }
    return plan;
}

fn draw_stamp(random: std.Random) copy_owner.Stamp {
    const owners = [_]?copy_owner.Owner{
        null, .{ .uid = 0, .gid = 0 }, .{ .uid = 1000, .gid = 1000 }, .{ .uid = 7, .gid = 65536 },
    };
    const modes = [_]?u16{ null, 0o600, 0o755, 0o4711 };
    if (random.boolean()) return .{};
    const stamp: copy_owner.Stamp = .{
        .owner = owners[random.uintLessThan(usize, owners.len)],
        .mode = modes[random.uintLessThan(usize, modes.len)],
    };
    if (stamp.mode) |mode| assert(mode <= 0o7777);
    if (stamp.owner) |owner| assert(owner.uid != copy_owner.id_unowned);
    return stamp;
}

/// A layer at `/uK` for step `at`: files, some with names the base and source already use (a
/// replacement of a file, or of a directory when the name is one there).
fn make_layer(target: *fs_sim.SimFs, at: u32, seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var path: [16]u8 = undefined;
    const root = std.fmt.bufPrint(&path, "/u{d}", .{at}) catch unreachable; // Short.
    target.put_dir(root, 0o755);
    const contents = [_][]const u8{ "", "a", "same", "layer bytes" };
    // Names `n0`..`n3` are the base's and the source's own (a replacement); `m0`.. are new.
    var used: u8 = 0;
    for (0..random.intRangeAtMost(u32, 1, 4)) |_| {
        const pick = random.uintLessThan(u3, 6);
        if (used & (@as(u8, 1) << pick) != 0) continue;
        used |= @as(u8, 1) << pick;
        var name: [32]u8 = undefined;
        const letter: u8 = if (pick < 4) 'n' else 'm';
        const text = std.fmt.bufPrint(&name, "{s}/{c}{d}", .{ root, letter, pick }) catch
            unreachable; // Short.
        target.put_file(text, 0o644, contents[random.uintLessThan(usize, contents.len)]);
    }
}

/// Top-level names of `digest`, up to `names_max`.
fn top_names(
    digest: Digest,
    storage: *[names_max][constants.store_name_bytes_max]u8,
    lens: *[names_max]u8,
) u32 {
    var buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    const bytes = trees.load(&store, digest, &buffer, &errno) catch return 0;
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return 0;
    var entry: tree.Entry = undefined;
    var count: u32 = 0;
    while (decoder.next(&entry) catch return count) {
        if (count == names_max) break;
        @memcpy(storage[count][0..entry.name.len], entry.name);
        lens[count] = @intCast(entry.name.len);
        count += 1;
    }
    return count;
}

fn import_tree(path: []const u8) Error!Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &import_ws, path, options, &result, &diag) catch return error.StepFailed;
    return result.digest;
}

fn context(replace: bool) assemble.Context {
    return .{ .store = &store, .ws = &copy_ws.assemble, .failure = &failure, .replace = replace };
}

/// Selects the names of `mask` from `source`, under `to`. Null when nothing matched.
fn select(source: Digest, mask: u16, to: []const u8) Error!?Digest {
    var storage: [names_max][constants.store_name_bytes_max]u8 = undefined;
    var lens: [names_max]u8 = undefined;
    const count = top_names(source, &storage, &lens);
    var patterns: [names_max][]const u8 = undefined;
    var taken: usize = 0;
    for (0..count) |at| {
        if (mask & (@as(u16, 1) << @intCast(at)) == 0) continue;
        patterns[taken] = storage[at][0..lens[at]];
        taken += 1;
    }
    if (taken == 0) return null;
    const selected = copy.select(
        context(false),
        &copy_ws,
        source,
        patterns[0..taken],
        to,
    ) catch |err| {
        if (err == error.NoMatch) return null;
        return error.StepFailed;
    };
    return selected;
}

/// The selection `selected`, laid at `to`, with `stamp`; itself when the stamp changes nothing.
fn restamp(selected: Digest, to: []const u8, stamp: copy_owner.Stamp) Error!Digest {
    if (!stamp.changes()) return selected;
    const owner_context: copy_owner.Context = .{ .store = &store, .failure = &failure };
    return copy_owner.restamp(owner_context, &owner_ws, selected, to, stamp) catch
        error.StepFailed;
}

/// Runs the whole chain: the base and source imports, then each step. `digests` gets the tree
/// after each; the count of steps done is returned (all of them when it does not fail).
fn run_chain(plan: *const Plan, digests: *[steps_max + 2]Digest) Error!u32 {
    const base = try import_tree("/src");
    const source = try import_tree("/dst");
    digests[0] = base;
    digests[1] = source;
    var current = base;
    for (plan.steps[0..plan.count], 0..) |step, at| {
        if (step.root) {
            var path: [16]u8 = undefined;
            const layer = std.fmt.bufPrint(&path, "/u{d}", .{at}) catch unreachable; // Short.
            var result: import.Result = undefined;
            diag.reset();
            const options: import.Options = .{
                .squash_owner = false,
                .warn = null,
                .parent = current,
                .save_root = true,
                .keep_existing_root = true,
                .label = "build:chain",
            };
            import.commit(&store, &import_ws, layer, options, &result, &diag) catch
                return error.StepFailed;
            current = result.digest;
        } else if (try select(source, step.mask, destinations[step.to])) |selected| {
            const laid = try restamp(selected, destinations[step.to], step.stamp);
            current = assemble.merge(context(true), current, laid) catch {
                return error.StepFailed;
            };
        }
        digests[2 + at] = current;
    }
    return plan.count;
}

fn fresh(target: *fs_sim.SimFs, seed: u64, plan: *const Plan) void {
    target.init(seed);
    target.put_dir("/data", 0o755);
    support.make_store_directories(target, root_path);
    fuzz_store.build_tree(plan.tree_seed, target, "/src");
    fuzz_store.build_tree(plan.tree_seed +% 1, target, "/dst");
    for (plan.steps[0..plan.count], 0..) |step, at| {
        if (step.root) make_layer(target, @intCast(at), step.layer_seed);
    }
}

fn attach(target: *fs_sim.SimFs, plan: *const Plan) void {
    sim.store_fs = target;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = plan.chunk_bytes;
}

pub fn fuzz_build_chain(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const plan = draw(random);
    sim.init(seed, &.{});

    // The clean run: the digests the chain must have.
    fresh(&reference_files, seed +% 1, &plan);
    attach(&reference_files, &plan);
    const started = reference_files.mutations;
    var expected: [steps_max + 2]Digest = undefined;
    _ = run_chain(&plan, &expected) catch unreachable; // A clean chain of valid steps.
    const points = reference_files.mutations - started;
    assert(points > 0);
    check_purity(&plan, &expected);
    check_stamps(&plan, &expected);

    // The run that crashes, and the run after it.
    fresh(&files, seed, &plan);
    attach(&files, &plan);
    files.faults.crash_mutation = files.mutations + random.uintLessThan(u32, points + 4);
    var scratch: [steps_max + 2]Digest = undefined;
    _ = run_chain(&plan, &scratch) catch {};
    files.restart();
    files.faults = .{};
    assert(files.open_count() == 0);
    support.check_whole(&files, root_path, plan.chunk_bytes) catch unreachable; // Property 1.
    var again: [steps_max + 2]Digest = undefined;
    const done = run_chain(&plan, &again) catch unreachable; // A clean run after the restart.
    assert(done == plan.count);
    for (expected[0 .. 2 + plan.count], again[0 .. 2 + plan.count]) |want, got| {
        assert(want.eql(got)); // Property 2.
    }
    support.check_whole(&files, root_path, plan.chunk_bytes) catch unreachable; // Property 1.
    check_key(random);
}

/// Property 3 on the clean file system: a file no pattern names does not change a selection.
fn check_purity(plan: *const Plan, expected: *const [steps_max + 2]Digest) void {
    const source = expected[1];
    for (plan.steps[0..plan.count]) |step| {
        if (step.root) continue;
        const to = destinations[step.to];
        const before = (select(source, step.mask, to) catch unreachable) orelse continue; // Clean.
        const twice = (select(source, step.mask, to) catch unreachable).?; // Clean.
        assert(before.eql(twice));
        // Names the patterns do not take are not changed by a file with a name of their own.
        reference_files.put_file("/dst/zz-unrelated", 0o644, "not named by any pattern");
        defer reference_files.remove_path("/dst/zz-unrelated"); // Every copy step is checked.
        const grown = import_tree("/dst") catch unreachable; // A clean import.
        assert(!grown.eql(source));
        var storage: [names_max][constants.store_name_bytes_max]u8 = undefined;
        var lens: [names_max]u8 = undefined;
        const count = top_names(grown, &storage, &lens);
        // The mask indexes the sorted names; `zz-unrelated` sorts after `n*`, so the indexes of
        // the others are the same unless the mask reaches past them.
        const reach: u16 = @intCast((@as(u32, 1) << @intCast(@min(count - 1, 15))) - 1);
        const masked = step.mask & reach;
        const kept = (select(source, masked, to) catch unreachable) orelse continue; // Clean.
        const after = (select(grown, masked, to) catch unreachable).?; // Clean.
        assert(kept.eql(after));
    }
}

/// Property 4: cache mounts are not in the key.
fn check_key(random: std.Random) void {
    const base: key_mod.Spec = .{
        .platform = "linux/amd64",
        .base_tree = Digest.of("base"),
        .base_env = &.{},
        .input_tree = Digest.of("input"),
        .needs = &.{},
        .argv = &.{"true"},
        .env = &.{},
        .network = false,
        .name = "chain",
        .root_output = random.boolean(),
    };
    var with = base;
    const mounts = [_]key_mod.CacheMount{
        .{ .id = "a", .path = "/c/a" },
        .{ .id = "b", .path = "/c/b" },
    };
    with.caches = mounts[0..random.intRangeAtMost(usize, 1, mounts.len)];
    var plain: key_mod.Key = undefined;
    var cached: key_mod.Key = undefined;
    key_mod.compute(&base, &plain) catch unreachable; // A small spec.
    key_mod.compute(&with, &cached) catch unreachable; // A small spec.
    assert(std.mem.eql(u8, plain.preimage(), cached.preimage()));
    assert(plain.digest.eql(cached.digest));
}

/// Property 5 on the clean file system, for each copy step whose stamp changes something.
fn check_stamps(plan: *const Plan, expected: *const [steps_max + 2]Digest) void {
    const source = expected[1];
    for (plan.steps[0..plan.count], 0..) |step, at| {
        if (step.root) continue;
        if (!step.stamp.changes()) continue;
        const to = destinations[step.to];
        const taken = select(source, step.mask, to) catch unreachable; // A clean file system.
        const selected = taken orelse continue;
        const once = restamp(selected, to, step.stamp) catch unreachable; // Clean.
        const twice = restamp(once, to, step.stamp) catch unreachable; // Clean.
        assert(once.eql(twice));
        const before = if (at == 0) expected[0] else expected[2 + at - 1];
        const plain = assemble.merge(context(true), before, selected) catch unreachable; // Clean.
        const laid = assemble.merge(context(true), before, once) catch unreachable; // Clean.
        assert(laid.eql(expected[2 + at]));
        check_outside(plain, laid, before, to);
    }
}

var plain_bytes: [constants.store_tree_bytes_max]u8 = undefined;
var laid_bytes: [constants.store_tree_bytes_max]u8 = undefined;
var base_bytes: [constants.store_tree_bytes_max]u8 = undefined;

fn decoder_of(digest: Digest, buffer: []u8) tree.Decoder {
    var errno: u16 = 0;
    const bytes = trees.load(&store, digest, buffer, &errno) catch unreachable; // Clean.
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch unreachable; // Written by the store.
    return decoder;
}

/// Down the names of `to`, the stamped merge `laid` differs from the unstamped `plain` only on
/// the way: every other entry is the same, and a directory on the way that `base` has keeps
/// its mode and owner. Below `to` the stamp may change anything.
fn check_outside(plain: Digest, laid: Digest, base: Digest, to: []const u8) void {
    var plain_at = plain;
    var laid_at = laid;
    var base_at: ?Digest = base;
    var names = std.mem.tokenizeScalar(u8, to, '/');
    while (names.next()) |name| {
        var plain_decoder = decoder_of(plain_at, &plain_bytes);
        var laid_decoder = decoder_of(laid_at, &laid_bytes);
        const base_entry = if (base_at) |digest| entry_named(digest, name) else null;
        var plain_entry: tree.Entry = undefined;
        var laid_entry: tree.Entry = undefined;
        var next: ?[2]Digest = null;
        while (plain_decoder.next(&plain_entry) catch unreachable) { // Written by the store.
            assert(laid_decoder.next(&laid_entry) catch unreachable); // Same names.
            assert(std.mem.eql(u8, plain_entry.name, laid_entry.name));
            assert(plain_entry.kind == laid_entry.kind);
            if (!std.mem.eql(u8, plain_entry.name, name)) {
                assert(same(&plain_entry, &laid_entry));
                continue;
            }
            assert(laid_entry.kind == .dir);
            if (base_entry) |kept| {
                if (kept.kind == .dir) {
                    assert(kept.mode == laid_entry.mode);
                    assert(kept.uid == laid_entry.uid);
                    assert(kept.gid == laid_entry.gid);
                }
            }
            next = .{ plain_entry.subtree, laid_entry.subtree };
        }
        assert(!(laid_decoder.next(&laid_entry) catch unreachable)); // Same names.
        plain_at = next.?[0];
        laid_at = next.?[1];
        base_at = if (base_entry) |kept| (if (kept.kind == .dir) kept.subtree else null) else null;
    }
}

const Kept = struct { kind: tree.Kind, mode: u16, uid: u32, gid: u32, subtree: Digest };

/// The entry `name` of `digest`, or null.
fn entry_named(digest: Digest, name: []const u8) ?Kept {
    var decoder = decoder_of(digest, &base_bytes);
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch unreachable) { // Written by the store.
        if (!std.mem.eql(u8, entry.name, name)) continue;
        return .{
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .subtree = entry.subtree,
        };
    }
    return null;
}

fn same(a: *const tree.Entry, b: *const tree.Entry) bool {
    assert(a.kind == b.kind);
    assert(std.mem.eql(u8, a.name, b.name));
    if (a.mode != b.mode or a.uid != b.uid or a.gid != b.gid) return false;
    if (!std.mem.eql(u8, a.xattrs, b.xattrs)) return false;
    return switch (a.kind) {
        .file => a.object.eql(b.object),
        .dir => a.subtree.eql(b.subtree),
        .symlink => std.mem.eql(u8, a.target, b.target),
    };
}
