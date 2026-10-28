//! Tests of `verify.zig` and `gc.zig` (plan, apply, trash, restore) against the simulated file
//! system. The oracle of a gc is a second store: the files left after removing a root must be
//! exactly the files of a store that never had it, and a restore must give back exactly the
//! files of the store before. Every write of an apply and of a restore is crashed and failed in
//! turn, and the store must be whole, verify clean, and the work finish when it is run again.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const gc = @import("gc.zig");
const generation = @import("generation.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const roots = @import("roots.zig");
const support = @import("test_support.zig");
const verify = @import("verify.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const Store = layout.Store;

const root_path = "/data/store";

var sim: HostSim = undefined;
var files: SimFs = undefined;
var store: Store = undefined;
var workspace: import.Workspace = undefined;
var verify_workspace: verify.Workspace = undefined;
var gc_workspace: gc.Workspace = undefined;
var gc_tables: [16 * 1024 * 1024]u8 align(8) = @splat(0);
var diag: Diag = undefined;

fn start() void {
    gc_workspace.tables = &gc_tables;
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    store.chunk_bytes = 8;
    sim.world.now = 1_800_000_000;
    diag.reset();
}

fn import_source() Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &workspace, "/src", options, &result, &diag) catch {
        unreachable; // The sample trees import.
    };
    return result.digest;
}

/// The first tree, and a second one that is the first plus some files: the second's own
/// objects and trees are what removing its root frees.
fn two_trees() [2]Digest {
    start();
    support.make_source(&files, 0);
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghij");
    const first = import_source();
    files.put_file("/src/etc/extra", 0o644, "extra bytes\n");
    files.put_file("/src/bin/tool", 0o755, "#!tool\n");
    files.put_file("/src/etc/long2", 0o644, "0123456789abcdefghijklmnopqrstuvwxyz");
    return .{ first, import_source() };
}

/// The files under objects/ and trees/ and cache/, as paths.
const Snapshot = struct {
    text: [1 << 16]u8,
    used: u32,
    count: u32,

    fn take(snapshot: *Snapshot) void {
        snapshot.used = 0;
        snapshot.count = 0;
        var index: u32 = 0;
        while (index < files.count) : (index += 1) {
            const path = files.alive_path(index) orelse continue;
            if (files.kind_of(path).? != .file) continue;
            const parts = [_][]const u8{ "/objects/", "/trees/", "/cache/" };
            inline for (parts) |part| {
                if (std.mem.indexOf(u8, path, root_path ++ part) != null) snapshot.add(path);
            }
        }
    }

    fn add(snapshot: *Snapshot, path: []const u8) void {
        snapshot.text[snapshot.used] = @intCast(path.len);
        @memcpy(snapshot.text[snapshot.used + 1 ..][0..path.len], path);
        snapshot.used += @intCast(1 + path.len);
        snapshot.count += 1;
    }

    fn has(snapshot: *const Snapshot, path: []const u8) bool {
        var at: u32 = 0;
        while (at < snapshot.used) {
            const length = snapshot.text[at];
            if (std.mem.eql(u8, snapshot.text[at + 1 ..][0..length], path)) return true;
            at += 1 + length;
        }
        return false;
    }

    fn expect_same(snapshot: *const Snapshot, other: *const Snapshot) !void {
        try testing.expectEqual(snapshot.count, other.count);
        var at: u32 = 0;
        while (at < snapshot.used) {
            const length = snapshot.text[at];
            const path = snapshot.text[at + 1 ..][0..length];
            if (!other.has(path)) {
                std.debug.print("missing from the other: {s}\n", .{path});
                return error.TestUnexpectedResult;
            }
            at += 1 + length;
        }
    }
};

var before: Snapshot = undefined;
var after: Snapshot = undefined;
var reference: Snapshot = undefined;

fn run_verify() verify.Totals {
    var totals: verify.Totals = undefined;
    var failure: verify.Failure = undefined;
    verify.verify(&store, &verify_workspace, &workspace.arena, &totals, &failure) catch {
        unreachable; // The simulated store lists.
    };
    return totals;
}

fn make_plan(live: []const Digest) !gc.Plan {
    var result: gc.Plan = undefined;
    var failure: gc.Failure = undefined;
    gc.plan(&store, &gc_workspace, &workspace.arena, live, &result, &failure) catch {
        return error.PlanFailed;
    };
    return result;
}

fn drop_root(digest: Digest) void {
    roots.remove(&store, digest) catch unreachable; // The root is there.
}

// ---- verify --------------------------------------------------------------------------------

test "a whole store verifies clean, and counts what it holds" {
    // Goal: no false alarms. Method: two trees, one with a multi-chunk file.
    _ = two_trees();
    const totals = run_verify();
    try testing.expectEqual(@as(u64, 0), totals.damaged);
    try testing.expectEqual(@as(u64, 2), totals.roots);
    try testing.expect(totals.objects >= 8);
    try testing.expect(totals.trees >= 5);
    try testing.expectEqual(@as(u64, 4), totals.chunk_lists); // 11, 20, 12 and 36 bytes.
    try testing.expectEqual(@as(u64, 0), totals.orphan_lists);
    try support.check_whole(&files, root_path, store.chunk_bytes);
}

fn object_path(path: []const u8, buffer: *[constants.sim_fs_path_bytes_max]u8) []const u8 {
    // The object a source file became: found by its content and mode.
    const content = files.content_of(path).?;
    const stat = files.stat_of(path).?;
    const object = @import("object.zig");
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = files.xattrs_of(path) orelse &@import("xattrs.zig").empty,
    };
    const id = object.object_id(Digest.of(content), attrs);
    const hex = id.hex();
    return std.fmt.bufPrint(buffer, root_path ++ "/objects/{s}/{s}", .{ hex[0..2], hex[2..] }) catch
        unreachable; // Short.
}

fn only_damage() verify.Damage {
    const totals = run_verify();
    testing.expectEqual(@as(u64, 1), totals.damaged) catch unreachable; // A test's invariant.
    return verify_workspace.damage_slice()[0];
}

test "a changed byte in an object names the object and every path that reaches it" {
    // Goal: the demo's step 4. Method: two paths with the same bytes and metadata share one
    // object; flip a byte; both paths in the tree, and none other, are listed.
    _ = two_trees();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = object_path("/src/etc/passwd", &buffer);
    files.flip_byte(path, 0);
    const found = only_damage();
    try testing.expectEqual(verify.Kind.content, found.kind);
    try testing.expectEqual(verify.Class.object, found.class);
    try testing.expectEqual(@as(u32, 2), found.reached); // Once in each root's tree.
    const refs = verify.refs_of(&verify_workspace, 0);
    try testing.expectEqual(@as(usize, 2), refs.len);
    for (refs) |*ref| {
        try testing.expectEqualStrings("/etc/passwd", verify_workspace.ref_path(ref));
    }
    try testing.expect(!refs[0].root.eql(refs[1].root));
}

test "two paths to one object are both listed, and a metadata change is damage too" {
    _ = two_trees();
    files.put_file("/src/etc/twin", 0o644, "root:x:0:0\n");
    const digest = import_source();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = object_path("/src/etc/twin", &buffer);
    files.set_mode_of(path, 0o600); // The bytes are right; the mode is not what the id says.
    const found = only_damage();
    try testing.expectEqual(verify.Kind.content, found.kind);
    var listed: u32 = 0;
    for (verify.refs_of(&verify_workspace, 0)) |*ref| {
        if (!ref.root.eql(digest)) continue;
        listed += 1;
        const text = verify_workspace.ref_path(ref);
        try testing.expect(std.mem.eql(
            u8,
            text,
            "/etc/twin",
        ) or std.mem.eql(u8, text, "/etc/passwd"));
    }
    try testing.expectEqual(@as(u32, 2), listed);
}

test "a damaged tree, a missing tree, a missing object and a damaged root record are found" {
    const trees_ = two_trees();
    const hex = trees_[1].hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const second = std.fmt.bufPrint(
        &path,
        root_path ++ "/trees/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch
        unreachable; // Short.
    files.flip_byte(second, 6);
    var found = only_damage();
    try testing.expectEqual(verify.Kind.tree_damaged, found.kind);
    try testing.expectEqual(verify.Class.tree, found.class);
    try testing.expect(found.id.eql(trees_[1]));
    const ref = verify.refs_of(&verify_workspace, 0)[0];
    try testing.expectEqualStrings("/", verify_workspace.ref_path(&ref));
    files.remove_path(second);
    found = only_damage();
    try testing.expectEqual(verify.Kind.tree_missing, found.kind);
}

test "a missing object is named with its paths" {
    _ = two_trees();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.remove_path(object_path("/src/bin/tool", &buffer));
    const found = only_damage();
    try testing.expectEqual(verify.Kind.object_missing, found.kind);
    const refs = verify.refs_of(&verify_workspace, 0);
    try testing.expectEqual(@as(usize, 1), refs.len);
    try testing.expectEqualStrings("/bin/tool", verify_workspace.ref_path(&refs[0]));
}

test "chunk lists: a changed hash, a missing list and a stray list are damage; an orphan is not" {
    // Goal: every disagreement between an object and its list. Method: four edits in turn.
    _ = two_trees();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const object_file = object_path("/src/etc/long", &buffer);
    var list_buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const list = std.fmt.bufPrint(
        &list_buffer,
        "{s}.chunks",
        .{object_file},
    ) catch unreachable; // Short.
    files.flip_byte(list, 3);
    try testing.expectEqual(verify.Kind.chunk_list, only_damage().kind);
    files.flip_byte(list, 3);
    try testing.expectEqual(@as(u64, 0), run_verify().damaged);
    const saved = files.content_of(list).?;
    var copy: [96]u8 = undefined;
    @memcpy(copy[0..saved.len], saved);
    files.remove_path(list);
    try testing.expectEqual(verify.Kind.chunk_list, only_damage().kind);
    files.put_file(list, 0o644, copy[0..saved.len]);
    var small: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const small_file = object_path("/src/etc/shadow", &small);
    var small_list: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const stray = std.fmt.bufPrint(
        &small_list,
        "{s}.chunks",
        .{small_file},
    ) catch unreachable; // Short.
    files.put_file(stray, 0o644, "");
    try testing.expectEqual(verify.Kind.chunk_list, only_damage().kind);
    files.remove_path(stray);
    files.remove_path(object_file);
    const totals = run_verify();
    try testing.expectEqual(@as(u64, 1), totals.orphan_lists);
    try testing.expectEqual(@as(u64, 1), totals.damaged); // The tree names the missing object.
}

test "an unreadable object is damage with its errno, not a stop" {
    _ = two_trees();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.set_unreadable(object_path("/src/bin/tool", &buffer));
    const found = only_damage();
    try testing.expectEqual(verify.Kind.unreadable, found.kind);
    try testing.expectEqual(fs_sim.errno_acces, found.errno);
}

test "the paths listed for one object are capped, and the rest are counted" {
    // Goal: a report stays short. Method: more links to one object than the cap.
    start();
    support.make_source(&files, 0);
    var name: [48]u8 = undefined;
    for (0..constants.store_verify_paths_max + 5) |index| {
        const path = std.fmt.bufPrint(
            &name,
            "/src/etc/copy{d}",
            .{index},
        ) catch unreachable; // Short.
        files.put_file(path, 0o644, "same bytes\n");
    }
    _ = import_source();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.flip_byte(object_path("/src/etc/copy0", &buffer), 1);
    const found = only_damage();
    try testing.expectEqual(@as(u32, constants.store_verify_paths_max + 5), found.reached);
    try testing.expectEqual(@as(u32, constants.store_verify_paths_max), found.listed);
    const refs = verify.refs_of(&verify_workspace, 0);
    try testing.expectEqual(@as(usize, constants.store_verify_paths_max), refs.len);
    for (refs[1..], refs[0 .. refs.len - 1]) |next, previous| {
        try testing.expect(std.mem.lessThan(
            u8,
            verify_workspace.ref_path(&previous),
            verify_workspace.ref_path(&next),
        ));
    }
}

// ---- gc: plan ------------------------------------------------------------------------------

test "with every tree a root, nothing is unreachable, and the plan hash is stable" {
    _ = two_trees();
    const first = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 0), first.counts.total());
    const again = try make_plan(&.{});
    try testing.expect(first.hash.eql(again.hash));
    try testing.expectEqual(@as(u64, 0), first.generation -| first.generation);
}

test "removing a root plans exactly the files a store without it lacks" {
    // Goal: the oracle. Method: the files of a store that only ever had the first tree.
    const trees_ = two_trees();
    before.take();
    start();
    support.make_source(&files, 0);
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghij");
    _ = import_source();
    reference.take();
    _ = two_trees();
    drop_root(trees_[1]);
    const planned = try make_plan(&.{});
    try testing.expect(planned.counts.total() > 0);
    try testing.expectEqual(@as(u64, before.count - reference.count), planned.counts.total());
    try testing.expect(planned.counts.lists >= 1); // long2's list goes too.
    try testing.expect(planned.counts.bytes > 0);
    const kept = try make_plan(&.{trees_[1]}); // A running container keeps it.
    try testing.expectEqual(@as(u64, 0), kept.counts.total());
}

test "any write to the store changes the plan hash" {
    // Goal: the generation is in the hash. Method: the plan of an unchanged store before and
    // after a write that changes no id the plan holds.
    const trees_ = two_trees();
    const first = try make_plan(&.{});
    var failure: @import("fs.zig").Failure = undefined;
    try generation.bump(&store, &failure);
    const second = try make_plan(&.{});
    try testing.expect(!first.hash.eql(second.hash));
    drop_root(trees_[1]);
    const third = try make_plan(&.{});
    try testing.expect(!second.hash.eql(third.hash));
}

// ---- gc: apply, trash and restore ----------------------------------------------------------

fn do_apply(expected: Digest) gc.ApplyError!gc.Applied {
    var result: gc.Applied = undefined;
    var failure: gc.Failure = undefined;
    try gc.apply(&store, &gc_workspace, &workspace.arena, &.{}, expected, &result, &failure);
    return result;
}

fn do_restore(id: gc.Id) gc.RestoreError!gc.Restored {
    var result: gc.Restored = undefined;
    var failure: gc.Failure = undefined;
    try gc.restore(&store, &gc_workspace, &workspace.arena, id, &result, &failure);
    return result;
}

/// Two trees, the second's root dropped, and what the store held before and without it.
fn prepare_gc() ![2]Digest {
    const trees_ = two_trees();
    before.take();
    drop_root(trees_[1]);
    start();
    support.make_source(&files, 0);
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghij");
    _ = import_source();
    reference.take();
    _ = two_trees();
    drop_root(trees_[1]);
    return trees_;
}

test "an apply moves what the plan named to the trash, and a restore moves it all back" {
    // Goal: the whole cycle against the oracle, with verify clean at each stage.
    _ = try prepare_gc();
    const planned = try make_plan(&.{});
    const applied = try do_apply(planned.hash);
    try testing.expectEqual(planned.counts.total(), applied.counts.total());
    after.take();
    try reference.expect_same(&after);
    try testing.expectEqual(reference.count, after.count);
    try testing.expectEqual(@as(u64, 0), run_verify().damaged);
    try support.check_whole(&files, root_path, store.chunk_bytes);
    try testing.expectEqual(@as(u64, 0), (try make_plan(&.{})).counts.total());
    const restored = try do_restore(applied.gc);
    try testing.expectEqual(applied.counts.objects, restored.counts.objects);
    try testing.expectEqual(applied.counts.trees, restored.counts.trees);
    after.take();
    try before.expect_same(&after);
    try testing.expectEqual(before.count, after.count);
    try testing.expectEqual(@as(u64, 0), run_verify().damaged);
    try testing.expectError(error.NoSuchTrash, do_restore(applied.gc));
    // The restored trees are unreachable again, and the same plan comes back (new generation).
    try testing.expectEqual(planned.counts.total(), (try make_plan(&.{})).counts.total());
}

test "a stale hash changes nothing and brings the new one" {
    _ = try prepare_gc();
    const planned = try make_plan(&.{});
    before.take();
    var wrong = planned.hash;
    wrong.bytes[0] ^= 1;
    var result: gc.Applied = undefined;
    var failure: gc.Failure = undefined;
    const refused = gc.apply(
        &store,
        &gc_workspace,
        &workspace.arena,
        &.{},
        wrong,
        &result,
        &failure,
    );
    try testing.expectError(error.Stale, refused);
    try testing.expect(result.fresh.hash.eql(planned.hash));
    after.take();
    try before.expect_same(&after);
    // A plan made before a write is stale after it.
    var raised: @import("fs.zig").Failure = undefined;
    try generation.bump(&store, &raised);
    try testing.expectError(error.Stale, do_apply(planned.hash));
}

test "dead materialized directories and dead leftovers in tmp are cleaned, live ones kept" {
    const trees_ = try prepare_gc();
    const kept_hex = trees_[0].hex();
    const dead_hex = trees_[1].hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const kept = std.fmt.bufPrint(
        &path,
        root_path ++ "/cache/{s}",
        .{kept_hex},
    ) catch unreachable; // Short.
    files.put_dir(kept, 0o755);
    files.put_file(root_path ++ "/cache/" ++ "x", 0o644, "not a farm");
    var farm: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const dead = std.fmt.bufPrint(
        &farm,
        root_path ++ "/cache/{s}",
        .{dead_hex},
    ) catch unreachable; // Short.
    files.put_dir(dead, 0o755);
    var inside: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.put_file(
        std.fmt.bufPrint(&inside, "{s}/file", .{dead}) catch unreachable, // Short.
        0o644,
        "farm file",
    ); // Short.
    files.put_file(root_path ++ "/tmp/4242-0", 0o644, "left by a killed import");
    files.put_file(root_path ++ "/tmp/4242x", 0o644, "not ours to judge");
    const own = std.fmt.allocPrint(
        testing.allocator,
        root_path ++ "/tmp/{d}-0",
        .{sim.interface().own_pid()},
    ) catch unreachable; // Cannot fail: the buffer holds the longest one.
    defer testing.allocator.free(own);
    files.put_file(own, 0o644, "ours");
    const planned = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 1), planned.counts.farms);
    try testing.expectEqual(@as(u64, 1), planned.counts.tmp);
    const applied = try do_apply(planned.hash);
    try testing.expectEqual(@as(u64, 1), applied.counts.tmp);
    try testing.expect(files.kind_of(dead) == null);
    try testing.expect(files.kind_of(kept) != null);
    try testing.expect(files.kind_of(root_path ++ "/tmp/4242-0") == null);
    try testing.expect(files.kind_of(root_path ++ "/tmp/4242x") != null);
    try testing.expect(files.kind_of(own) != null);
    _ = try do_restore(applied.gc);
    try testing.expect(files.kind_of(dead) != null);
    const farm_file = std.fmt.bufPrint(&inside, "{s}/file", .{dead}) catch unreachable; // Short.
    try testing.expectEqualStrings("farm file", files.content_of(farm_file).?); // Short.
}

test "restore refuses a conflict, a missing trash and a trash with things gone" {
    _ = try prepare_gc();
    const planned = try make_plan(&.{});
    const applied = try do_apply(planned.hash);
    var other = applied.gc;
    other[0] = if (other[0] == 'a') 'b' else 'a';
    try testing.expectError(error.NoSuchTrash, do_restore(other));
    // The second tree is imported again: its objects and trees are in the store once more.
    _ = import_source();
    after.take();
    var restored: gc.Restored = undefined;
    var failure: gc.Failure = undefined;
    const refused = gc.restore(
        &store,
        &gc_workspace,
        &workspace.arena,
        applied.gc,
        &restored,
        &failure,
    );
    try testing.expectError(error.Conflict, refused);
    try testing.expect(restored.conflicts > 0);
    try testing.expect(restored.conflict_class == .object or restored.conflict_class == .tree);
    var again: Snapshot = undefined;
    again.take();
    try after.expect_same(&again);
    // A finished trash that lost a file is not restored either.
    var trashed: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const prefix = root_path ++ "/trash/";
    const victim = first_file_under(&trashed, prefix, "/trees/") orelse unreachable; // Is there.
    files.remove_path(victim);
    try testing.expectError(error.Incomplete, do_restore(applied.gc));
}

fn first_file_under(buffer: []u8, prefix: []const u8, part: []const u8) ?[]const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (files.kind_of(path).? != .file) continue;
        if (!std.mem.startsWith(u8, path, prefix)) continue;
        if (std.mem.indexOf(u8, path, part) == null) continue;
        @memcpy(buffer[0..path.len], path);
        return buffer[0..path.len];
    }
    return null;
}

test "trash lasts store_trash_seconds, is listed, and is emptied by the next gc after that" {
    _ = try prepare_gc();
    const applied = try do_apply((try make_plan(&.{})).hash);
    try testing.expectEqual(sim.world.now + constants.store_trash_seconds, applied.expires);
    var entries: [4]gc.TrashEntry = undefined;
    var listing: gc.Trash = undefined;
    var failure: gc.Failure = undefined;
    var names: [4096]u8 = undefined;
    var offsets: [16]u32 = undefined;
    try gc.list_trash(&store, &names, &offsets, &entries, &listing, &failure);
    try testing.expectEqual(@as(u32, 1), listing.count);
    try testing.expectEqualSlices(u8, &applied.gc, &entries[0].id);
    const meta = entries[0].meta.?;
    try testing.expect(meta.complete);
    try testing.expectEqual(applied.expires, meta.expires);
    try testing.expectEqual(applied.counts.objects, meta.objects);
    // A day later nothing is emptied; after the week the next gc empties it.
    sim.world.now += 24 * 60 * 60;
    var plan_again = try make_plan(&.{});
    var second = try do_apply(plan_again.hash);
    try testing.expectEqual(@as(u32, 0), second.expired);
    var directory: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const trash = std.fmt.bufPrint(
        &directory,
        root_path ++ "/trash/{s}",
        .{applied.gc},
    ) catch unreachable; // Short.
    try testing.expect(files.kind_of(trash) != null);
    sim.world.now += constants.store_trash_seconds;
    plan_again = try make_plan(&.{});
    second = try do_apply(plan_again.hash);
    try testing.expectEqual(@as(u32, 1), second.expired);
    try gc.list_trash(&store, &names, &offsets, &entries, &listing, &failure);
    try testing.expectEqual(@as(u32, 0), listing.count);
    try testing.expect(files.kind_of(trash) == null);
    try testing.expectError(error.NoSuchTrash, do_restore(applied.gc));
    try testing.expectEqual(@as(u64, 0), run_verify().damaged);
}

test "a trash directory with no metadata is removed only when it is empty" {
    _ = try prepare_gc();
    files.put_dir(root_path ++ "/trash/aaaaaaaaaaaa", 0o755);
    files.put_dir(root_path ++ "/trash/bbbbbbbbbbbb", 0o755);
    files.put_file(root_path ++ "/trash/bbbbbbbbbbbb/stray", 0o644, "x");
    _ = try do_apply((try make_plan(&.{})).hash);
    try testing.expect(files.kind_of(root_path ++ "/trash/aaaaaaaaaaaa") == null);
    try testing.expect(files.kind_of(root_path ++ "/trash/bbbbbbbbbbbb") != null);
}

test "metadata round-trips, and anything else is not read as metadata" {
    const meta: gc.Meta = .{
        .time = 5,
        .expires = 9,
        .objects = 1,
        .lists = 2,
        .trees = 3,
        .farms = 4,
        .bytes = 6,
        .complete = true,
    };
    var buffer: [gc.meta_bytes_max]u8 = undefined;
    const text = gc.render_meta(&meta, &buffer);
    try testing.expectEqual(meta, gc.parse_meta(text).?);
    try testing.expect(gc.parse_meta("") == null);
    try testing.expect(gc.parse_meta(".{ .version = 2 }") == null);
    var broken: [gc.meta_bytes_max]u8 = undefined;
    const cut = std.mem.replace(u8, text, "complete = true", "complete = maybe", &broken);
    _ = cut;
    try testing.expect(gc.parse_meta(std.mem.sliceTo(&broken, 0)) == null);
    try testing.expect(gc.is_id("0123456789ab"));
    try testing.expect(!gc.is_id("0123456789aB"));
    try testing.expect(!gc.is_id("0123456789a"));
}

// ---- Interrupted writes --------------------------------------------------------------------

const Step = enum { apply_step, restore_step };

/// Runs the step with the fault at write point `point`; true if the step reached its end
/// without the fault firing (so there are no more write points to try).
fn faulty_step(step: Step, point: u32, crash: bool, id: *gc.Id) bool {
    files.mutations = 0;
    if (crash) files.faults.crash_mutation = point else files.faults.fail_mutation = point;
    defer files.faults = .{};
    switch (step) {
        .apply_step => {
            const planned = make_plan(&.{}) catch unreachable; // Reads only.
            const applied = do_apply(planned.hash) catch return false;
            id.* = applied.gc;
        },
        .restore_step => _ = do_restore(id.*) catch return false,
    }
    return true;
}

fn settle(crashed: bool) !void {
    if (crashed) files.restart();
    try support.check_whole(&files, root_path, store.chunk_bytes);
    const totals = run_verify();
    try testing.expectEqual(@as(u64, 0), totals.damaged);
}

/// Finishes whatever an interrupted gc left: a new gc, then every trash restored.
fn finish_and_restore() !void {
    const planned = try make_plan(&.{});
    _ = try do_apply(planned.hash);
    var entries: [8]gc.TrashEntry = undefined;
    var listing: gc.Trash = undefined;
    var failure: gc.Failure = undefined;
    var names: [4096]u8 = undefined;
    var offsets: [32]u32 = undefined;
    try gc.list_trash(&store, &names, &offsets, &entries, &listing, &failure);
    after.take();
    try reference.expect_same(&after);
    try testing.expectEqual(reference.count, after.count);
    for (entries[0..listing.count]) |entry| _ = try do_restore(entry.id);
    after.take();
    try before.expect_same(&after);
    try testing.expectEqual(before.count, after.count);
    try testing.expectEqual(@as(u64, 0), run_verify().damaged);
}

test "a gc killed or failed at any write leaves the store whole, and the work can be finished" {
    // Goal: the brief's interrupted-writes rule for gc. Method: every write point of an apply
    // is crashed, then failed; after each the store is whole and verify clean, a new gc ends
    // with exactly the oracle's files, and restoring every trash gives the first state back.
    for ([_]bool{ true, false }) |crash| {
        var point: u32 = 0;
        while (true) : (point += 1) {
            _ = try prepare_gc();
            var id: gc.Id = undefined;
            const finished = faulty_step(.apply_step, point, crash, &id);
            try settle(crash and !finished);
            if (finished) break;
            try finish_and_restore();
        }
        try testing.expect(point > 10);
    }
}

test "a restore killed or failed at any write leaves the store whole, and can be run again" {
    for ([_]bool{ true, false }) |crash| {
        var point: u32 = 0;
        while (true) : (point += 1) {
            _ = try prepare_gc();
            const applied = try do_apply((try make_plan(&.{})).hash);
            var id = applied.gc;
            const finished = faulty_step(.restore_step, point, crash, &id);
            try settle(crash and !finished);
            if (finished) break;
            _ = do_restore(id) catch |err| try testing.expectEqual(error.NoSuchTrash, err);
            after.take();
            try before.expect_same(&after);
            try testing.expectEqual(before.count, after.count);
            try testing.expectEqual(@as(u64, 0), run_verify().damaged);
        }
        try testing.expect(point > 10);
    }
}

// ---- gc: downloaded blobs and image records --------------------------------------------------

const images = @import("images.zig");
const KeyType = @import("sets.zig").KeySet.Key;
const Sha256 = @import("../registry/digest.zig").Sha256;

/// A blob of the cache, named by the digest of `text` (gc does not hash blobs).
fn put_blob(text: []const u8) Sha256 {
    const digest = Sha256.of(text);
    if (files.kind_of(root_path ++ "/blobs") == null) {
        files.put_dir(root_path ++ "/blobs", 0o755);
        files.put_dir(root_path ++ "/blobs/sha256", 0o755);
        files.put_dir(root_path ++ "/blobs/partial", 0o755);
    }
    var path: [160]u8 = undefined;
    const format = root_path ++ "/blobs/sha256/{s}";
    const where = std.fmt.bufPrint(&path, format, .{&digest.hex()}) catch unreachable; // Short.
    files.put_file(where, 0o644, text);
    return digest;
}

/// An image record for `tree` that names `config` and `layer`.
fn record_image(tree: Digest, config: Sha256, layer: Sha256) void {
    var image: images.Image = undefined;
    image.tag_count = 0;
    image.add_tag("docker.io/library/fixture:1");
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = config;
    image.tree = tree;
    image.time = 1_800_000_000;
    image.layer_count = 1;
    image.layers[0] = layer;
    image.settings.clear();
    var failure: @import("fs.zig").Failure = undefined;
    images.save(&store, &image, &failure) catch unreachable; // The simulated store writes.
}

test "blobs no image names are planned, trashed and restored; the others and cut downloads stay" {
    // Goal: the blob cache is in gc's live set. Method: one image names two blobs; a third and
    // a cut download are not named; the cycle plan, apply, restore moves exactly the third.
    const trees_ = two_trees();
    const config = put_blob("config bytes");
    const layer = put_blob("layer bytes");
    const orphan = put_blob("an abandoned layer");
    files.put_file(root_path ++ "/blobs/partial/cut", 0o644, "half");
    record_image(trees_[0], config, layer);
    const planned = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 1), planned.counts.blobs);
    try testing.expectEqual(@as(u64, 1), planned.counts.total());
    const applied = try do_apply(planned.hash);
    try testing.expectEqual(@as(u64, 1), applied.counts.blobs);
    var path: [160]u8 = undefined;
    const gone = try std.fmt.bufPrint(&path, root_path ++ "/blobs/sha256/{s}", .{&orphan.hex()});
    try testing.expect(files.kind_of(gone) == null);
    var kept: [160]u8 = undefined;
    const format = root_path ++ "/blobs/sha256/{s}";
    const layer_path = try std.fmt.bufPrint(&kept, format, .{&layer.hex()});
    try testing.expect(files.kind_of(layer_path) != null);
    try testing.expect(files.kind_of(root_path ++ "/blobs/partial/cut") != null);
    const again = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 0), again.counts.total());
    const restored = try do_restore(applied.gc);
    try testing.expectEqual(@as(u64, 1), restored.counts.blobs);
    try testing.expectEqualStrings("an abandoned layer", files.content_of(gone).?);
}

test "an image record keeps its tree and blobs when its root is gone" {
    // Goal: the record is a root of its own. Method: drop the tree's root record; with an image
    // record the plan is empty, without it the tree's own objects are planned.
    const trees_ = two_trees();
    const config = put_blob("config bytes");
    const layer = put_blob("layer bytes");
    drop_root(trees_[1]);
    const without = try make_plan(&.{});
    try testing.expect(without.counts.objects + without.counts.trees > 0);
    try testing.expectEqual(@as(u64, 2), without.counts.blobs);
    record_image(trees_[1], config, layer);
    const with = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 0), with.counts.total());
}

test "the sets are sized to the store, and a store beyond the room is refused with the limit" {
    // Goal: the old limit of about 49,000 objects is gone: tables for 100,000 and a million fit
    // the room; the smallest that does not fit is refused, not cut.
    const room = @as(u64, constants.store_gc_tables_bytes) - (4 * 1024 * 1024 + 7 * 1024 * 1024);
    try testing.expect(gc.plan_tables(100_000, 10_000, room) != null);
    const million = gc.plan_tables(1_000_000, 100_000, room).?;
    const slot = @sizeOf(KeyType);
    try testing.expect(million.objects_bytes * 3 >= 1_000_000 * 4 * slot);
    try testing.expect(gc.plan_tables(100_000_000, 10, room) == null);
    try testing.expectEqual(@as(u64, 16 * @sizeOf(KeyType)), gc.table_bytes(0));
    try testing.expectEqual(@as(u64, 32 * @sizeOf(KeyType)), gc.table_bytes(24));
    try testing.expectEqual(@as(u64, 64 * @sizeOf(KeyType)), gc.table_bytes(25));
}

/// A library user's whole world: a store of its own and a region of its own for gc.
const Caller = struct {
    sim: HostSim,
    files: SimFs,
    store: Store,
    workspace: import.Workspace,
    gc_workspace: gc.Workspace,
    tables: [16 * 1024 * 1024]u8 align(8),
    planned: ?gc.Plan,
    extra: u32,
};

var callers: [2]Caller = undefined;

/// Makes a store with `extra` more files than the smallest, drops its only root, and plans.
fn caller_plan(caller: *Caller) void {
    caller.sim.init(1, &.{});
    caller.files.init(1);
    caller.sim.store_fs = &caller.files;
    caller.files.put_dir("/data", 0o755);
    support.make_store_directories(&caller.files, root_path);
    caller.store.at(caller.sim.interface(), root_path);
    caller.store.chunk_bytes = 8;
    caller.sim.world.now = 1_800_000_000;
    caller.gc_workspace.tables = &caller.tables;
    support.make_source(&caller.files, 0);
    var index: u32 = 0;
    while (index < caller.extra) : (index += 1) {
        var name: [32]u8 = undefined;
        const format = "/src/etc/more-{d}";
        const path = std.fmt.bufPrint(&name, format, .{index}) catch unreachable; // Short.
        var content: [24]u8 = undefined;
        const words = "file number {d} here";
        const text = std.fmt.bufPrint(&content, words, .{index}) catch unreachable; // Short.
        caller.files.put_file(path, 0o644, text);
    }
    var result: import.Result = undefined;
    var local_diag: Diag = undefined;
    local_diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&caller.store, &caller.workspace, "/src", options, &result, &local_diag) catch {
        unreachable; // The sample tree imports.
    };
    roots.remove(&caller.store, result.digest) catch unreachable; // The root is there.
    var plan: gc.Plan = undefined;
    var failure: gc.Failure = undefined;
    const arena = &caller.workspace.arena;
    gc.plan(&caller.store, &caller.gc_workspace, arena, &.{}, &plan, &failure) catch return;
    caller.planned = plan;
}

test "two callers with two regions plan gc independently, also at once" {
    // Goal: the library keeps no module-level state for gc: its sets live in the caller's
    // region. Method: two worlds with different stores, planned one after the other for the
    // expected plans, then planned again on two threads at once, each with its own region; the
    // plans are the same.
    callers[0].extra = 0;
    callers[1].extra = 9;
    // A known fill, so the region's use shows whatever the backend leaves in undefined memory.
    for (&callers) |*caller| @memset(&caller.tables, 0xaa);
    for (&callers) |*caller| {
        caller.planned = null;
        caller_plan(caller);
    }
    const expected = [2]gc.Plan{ callers[0].planned.?, callers[1].planned.? };
    try testing.expect(expected[0].counts.objects != expected[1].counts.objects);
    try testing.expect(!expected[0].hash.eql(expected[1].hash));
    // Each region was used by its own owner: its sets were carved and cleared there.
    for (&callers) |*caller| try testing.expect(!std.mem.allEqual(u8, &caller.tables, 0xaa));
    var threads: [2]std.Thread = undefined;
    for (&callers) |*caller| caller.planned = null;
    for (&threads, 0..) |*thread, at| {
        thread.* = try std.Thread.spawn(.{}, caller_plan, .{&callers[at]});
    }
    for (&threads) |thread| thread.join();
    for (&callers, expected) |*caller, want| {
        const got = caller.planned.?;
        try testing.expect(got.hash.eql(want.hash));
        try testing.expectEqual(want.counts.objects, got.counts.objects);
    }
}

fn put_partial(text: []const u8, mtime: u64, buffer: *[160]u8) []const u8 {
    if (files.kind_of(root_path ++ "/blobs") == null) {
        files.put_dir(root_path ++ "/blobs", 0o755);
        files.put_dir(root_path ++ "/blobs/sha256", 0o755);
        files.put_dir(root_path ++ "/blobs/partial", 0o755);
    }
    const format = root_path ++ "/blobs/partial/{s}";
    const hex = Sha256.of(text).hex();
    const where = std.fmt.bufPrint(buffer, format, .{&hex}) catch unreachable; // Short.
    files.put_file(where, 0o644, text);
    files.set_mtime_of(where, mtime);
    return where;
}

test "abandoned cut downloads are planned, trashed and restored; recent ones stay" {
    // Goal: a cut download nobody has written to for a day is gc's, as its own class; one a pull
    // may be writing is not. Method: two partial files, one touched a minute ago and one two days
    // ago; the cycle plan, apply, restore moves exactly the old one, and a restore refuses when
    // a new download of the same blob has begun.
    _ = two_trees();
    const now = sim.world.now;
    var recent_buffer: [160]u8 = undefined;
    var old_buffer: [160]u8 = undefined;
    const recent = put_partial("a pull writes this", now - 60, &recent_buffer);
    const two_days = 2 * constants.store_partial_seconds;
    const old = put_partial("a pull gave this up", now - two_days, &old_buffer);
    const planned = try make_plan(&.{});
    try testing.expectEqual(@as(u64, 1), planned.counts.partials);
    try testing.expectEqual(@as(u64, 0), planned.counts.blobs);
    try testing.expectEqual(@as(u64, "a pull gave this up".len), planned.counts.bytes);
    const applied = try do_apply(planned.hash);
    try testing.expectEqual(@as(u64, 1), applied.counts.partials);
    try testing.expect(files.kind_of(old) == null);
    try testing.expect(files.kind_of(recent) != null);
    try testing.expectEqual(@as(u64, 0), (try make_plan(&.{})).counts.total());
    // The same blob is being downloaded again: the restore would overwrite it, so it refuses.
    var again_buffer: [160]u8 = undefined;
    _ = put_partial("a pull gave this up", now, &again_buffer);
    try testing.expectError(error.Conflict, do_restore(applied.gc));
    files.remove_path(old);
    const restored = try do_restore(applied.gc);
    try testing.expectEqual(@as(u64, 1), restored.counts.partials);
    try testing.expectEqualStrings("a pull gave this up", files.content_of(old).?);
    // It is old again, so it is planned again.
    try testing.expectEqual(@as(u64, 1), (try make_plan(&.{})).counts.partials);
    try support.check_whole(&files, root_path, store.chunk_bytes);
}
