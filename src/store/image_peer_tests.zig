//! Tests of `image_peer.zig` (Zigcube C2's Z4) against the simulated file system: an image
//! record is exported for a tree and imported on a store that holds the tree but no record. The
//! store is a user's (`~/.local/share/zbx/store`), so `run_image.prepare` finds it as `zbx run`
//! does. Each refusal is checked to have written nothing.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const fs_sim = @import("fs_sim.zig");
const gc = @import("gc.zig");
const image_find = @import("image_find.zig");
const image_peer = @import("image_peer.zig");
const images = @import("images.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const lock = @import("lock.zig");
const roots = @import("roots.zig");
const run_image = @import("../run_image.zig");
const support = @import("test_support.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const testing = std.testing;
const Digest = digest_mod.Digest;

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};
const root_path = support.user_store;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_workspace: import.Workspace = undefined;
var memory: image_peer.Memory = undefined;
var gc_workspace: gc.Workspace = undefined;
var gc_tables: [16 * 1024 * 1024]u8 align(8) = @splat(0);
var run_workspace: run_image.Workspace = undefined;
var text_buffer: [constants.image_record_bytes_max]u8 = undefined;
var diag: Diag = undefined;

const options: image_peer.Options = .{ .tags = .drop, .entries_max = 100 };

/// A store that has a tree (imported from a source, then its root dropped, as a tree fetched
/// from a peer has none) and no image record. Returns the tree.
fn start() Digest {
    gc_workspace.tables = &gc_tables;
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    sim.environment_variables = &home;
    sim.world.now = 1_800_000_000;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    store.at(sim.interface(), root_path);
    store.chunk_bytes = 8;
    support.make_source(&files, 0);
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghijklmnopqrstuvwxyz");
    var result: import.Result = undefined;
    diag.reset();
    const import_options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &import_workspace, "/src", import_options, &result, &diag) catch {
        unreachable; // The sample tree imports.
    };
    roots.remove(&store, result.digest) catch unreachable; // The import wrote it.
    return result.digest;
}

fn record_for(tree: Digest, manifest: []const u8, tag: ?[]const u8) []const u8 {
    var image: images.Image = undefined;
    image.tag_count = 0;
    if (tag) |name| image.add_tag(name);
    image.manifest = Sha256.of(manifest);
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = tree;
    image.time = 5; // The peer's clock; the import must not keep it.
    image.layer_count = 1;
    image.layers[0] = Sha256.of("layer");
    image.settings.clear();
    _ = image.settings.add(.entrypoint, "/bin/hello");
    _ = image.settings.add(.env, "GREETING=hi");
    _ = image.settings.set(.workdir, "/srv");
    return images.render(&image, &text_buffer);
}

fn take(text: []const u8, tree: Digest, tags: image_peer.TagPolicy) image_peer.Error!void {
    var failure: image_peer.Failure = undefined;
    _ = try import_with(text, tree, tags, &failure);
}

fn import_with(
    text: []const u8,
    tree: Digest,
    tags: image_peer.TagPolicy,
    failure: *image_peer.Failure,
) image_peer.Error!image_peer.Imported {
    const these: image_peer.Options = .{ .tags = tags, .entries_max = options.entries_max };
    return image_peer.import_record(&store, &memory, text, tree, these, failure);
}

fn refused(text: []const u8, tree: Digest) !image_peer.Failure {
    var failure: image_peer.Failure = undefined;
    const attempt = import_with(text, tree, .keep, &failure);
    try testing.expectError(error.Failed, attempt);
    return failure;
}

fn written() u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (std.mem.indexOf(u8, path, "/images/") != null) count += 1;
        if (std.mem.indexOf(u8, path, "/roots/") != null) count += 1;
    }
    return count;
}

fn plan_total() !u64 {
    var result: gc.Plan = undefined;
    var failure: gc.Failure = undefined;
    var arena: [gc.arena_bytes]u8 align(8) = undefined;
    try gc.plan(&store, &gc_workspace, &arena, &.{}, &result, &failure);
    return result.counts.total();
}

test "an imported record roots the tree, keeps it for gc, and runs like a pulled image" {
    // Goal: Z4's main promise. Method: a tree with no root and no record is all garbage to gc;
    // after the import of a peer's record it is not, even with the root dropped again; the
    // image is then found by its manifest, and `run_image.prepare` gives the record's settings.
    const tree = start();
    try testing.expect((try plan_total()) > 0);
    const text = record_for(tree, "manifest", "alpine:3.20");
    var failure: image_peer.Failure = undefined;
    const taken = try import_with(text, tree, .keep, &failure);
    try testing.expect(taken.created);
    try testing.expect(taken.files > 0);
    roots.remove(&store, tree) catch unreachable; // The import wrote one: the record keeps it.
    try testing.expectEqual(@as(u64, 0), try plan_total());

    var back: images.Image = undefined;
    var errno: u16 = 0;
    try images.load(&store, Sha256.of("manifest"), &back, &errno);
    try testing.expect(back.tree.eql(tree));
    try testing.expectEqual(@as(u64, 1_800_000_000), back.time);
    try testing.expect(back.has_tag("alpine:3.20"));
    const services: run_image.Services = .{
        .host = sim.interface(),
        .facts = undefined,
        .pull = undefined,
        .import_workspace = &import_workspace,
        .output = undefined,
        .warn = null,
    };
    var prepared: run_image.Prepared = undefined;
    var operand: [128]u8 = undefined;
    const name = try std.fmt.bufPrint(&operand, "alpine@{s}", .{&Sha256.of("manifest").text()});
    diag.reset();
    try run_image.prepare(&services, &run_workspace, name, &.{}, null, &prepared, &diag);
    try testing.expectEqualStrings(&tree.text(), prepared.tree);
    try testing.expectEqualStrings("/bin/hello", prepared.command[0]);
    try testing.expectEqualStrings("/srv", prepared.workdir);
}

test "the same record twice is the same store, and tags join the local ones" {
    // Goal: idempotence and the tag and time rules. Method: import twice, compare the files;
    // then a local record with a tag and an older time takes a second import's tag but not its
    // time; with `.drop` the imported tag is not taken.
    const tree = start();
    const text = record_for(tree, "manifest", "peer:1");
    try take(text, tree, .drop);
    var back: images.Image = undefined;
    var errno: u16 = 0;
    try images.load(&store, Sha256.of("manifest"), &back, &errno);
    try testing.expectEqual(@as(u32, 0), back.tag_count);
    const count = written();
    sim.world.now += 100;
    try take(text, tree, .drop);
    try testing.expectEqual(count, written());
    try images.load(&store, Sha256.of("manifest"), &back, &errno);
    try testing.expectEqual(@as(u64, 1_800_000_000), back.time); // The first import's.
    try take(text, tree, .keep);
    try take(text, tree, .keep);
    try images.load(&store, Sha256.of("manifest"), &back, &errno);
    try testing.expectEqual(@as(u32, 1), back.tag_count);
    try testing.expect(back.has_tag("peer:1"));
    const other = record_for(tree, "manifest", "peer:2");
    try take(other, tree, .keep);
    try images.load(&store, Sha256.of("manifest"), &back, &errno);
    try testing.expectEqual(@as(u32, 2), back.tag_count);
    try testing.expectEqual(@as(u64, 1_800_000_000), back.time);
}

test "a record is refused for size, text, version and tree, and nothing is written" {
    // Goal: every check before the walk. Method: one case each; the files under images/ and
    // roots/ are counted before and after. The size case is exactly one byte over the bound,
    // and a text of exactly the bound is read (and found malformed), not too large.
    const tree = start();
    const good = record_for(tree, "manifest", null);
    const before = written();
    var big: [constants.image_record_bytes_max + 1]u8 = @splat('x');
    var failure = try refused(&big, tree);
    try testing.expectEqual(image_peer.Refusal.too_large, failure.refusal);
    try testing.expectEqual(@as(u64, big.len), failure.size);
    failure = try refused(big[0..constants.image_record_bytes_max], tree);
    try testing.expectEqual(image_peer.Refusal.malformed, failure.refusal);
    failure = try refused("", tree);
    try testing.expectEqual(image_peer.Refusal.malformed, failure.refusal);
    failure = try refused(good[0 .. good.len / 2], tree);
    try testing.expectEqual(image_peer.Refusal.malformed, failure.refusal);
    const newer = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        good,
        "version = 2",
        "version = 3",
    );
    defer testing.allocator.free(newer);
    failure = try refused(newer, tree);
    try testing.expectEqual(image_peer.Refusal.newer, failure.refusal);
    failure = try refused(good, Digest.of("another tree"));
    try testing.expectEqual(image_peer.Refusal.wrong_tree, failure.refusal);
    try testing.expect(failure.digest.eql(tree));
    try testing.expectEqual(before, written());
}

fn object_of_tree(tree: Digest) []const u8 {
    // The path of any one object under objects/.
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (files.kind_of(path).? == .file) {
            if (!std.mem.endsWith(u8, path, ".chunks")) return path;
        }
    }
    _ = tree;
    unreachable; // The sample tree has objects.
}

test "a tree that is not whole is refused: an object gone, a tree gone or damaged, too big" {
    // Goal: the completeness check. Method: break the tree one way at a time on fresh stores.
    var tree = start();
    const text = record_for(tree, "manifest", null);
    const before = written();
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = object_of_tree(tree);
    @memcpy(buffer[0..path.len], path);
    files.remove_path(buffer[0..path.len]);
    var failure = try refused(text, tree);
    try testing.expectEqual(image_peer.Refusal.incomplete, failure.refusal);
    try testing.expectEqual(before, written());

    tree = start();
    const hex = tree.hex();
    const tree_path = try std.fmt.bufPrint(&buffer, root_path ++ "/trees/{s}/{s}", .{
        hex[0..2], hex[2..],
    });
    const again = record_for(tree, "manifest", null);
    files.flip_byte(tree_path, 3);
    failure = try refused(again, tree);
    try testing.expectEqual(image_peer.Refusal.tree_damaged, failure.refusal);
    files.remove_path(tree_path);
    failure = try refused(again, tree);
    try testing.expectEqual(image_peer.Refusal.incomplete, failure.refusal);
    try testing.expect(failure.digest.eql(tree));

    tree = start();
    const small = record_for(tree, "manifest", null);
    var limited: image_peer.Failure = undefined;
    const tight: image_peer.Options = .{ .tags = .keep, .entries_max = 1 };
    const attempt = image_peer.import_record(&store, &memory, small, tree, tight, &limited);
    try testing.expectError(error.Failed, attempt);
    try testing.expectEqual(image_peer.Refusal.tree_too_big, limited.refusal);
    try testing.expectEqual(@as(u32, 0), written());
}

test "a record of the same manifest for another tree is a conflict, and is left as it is" {
    // Goal: a peer cannot move a local image to another tree. Method: the local record names
    // a tree; an import of the same manifest for the fetched tree is refused, record unchanged.
    const tree = start();
    const local = record_for(Digest.of("local tree"), "manifest", "alpine:3.20");
    var parsed: images.Image = undefined;
    try testing.expectEqual(images.ParseResult.ok, images.parse(local, &parsed));
    var failure: fs_mod.Failure = undefined;
    try images.save(&store, &parsed, &failure);
    const path = try std.fmt.allocPrint(testing.allocator, root_path ++ "/images/{s}", .{
        &Sha256.of("manifest").hex(),
    });
    defer testing.allocator.free(path);
    const kept = try testing.allocator.dupe(u8, files.content_of(path).?);
    defer testing.allocator.free(kept);
    const refusal = try refused(record_for(tree, "manifest", "peer:1"), tree);
    try testing.expectEqual(image_peer.Refusal.conflict, refusal.refusal);
    try testing.expect(refusal.digest.eql(Digest.of("local tree")));
    try testing.expectEqualStrings(kept, files.content_of(path).?);
    // A record that is damaged is not replaced either.
    files.flip_byte(path, 2);
    const damaged = try refused(record_for(tree, "manifest", null), tree);
    try testing.expectEqual(image_peer.Refusal.local_unusable, damaged.refusal);
}

test "export gives the newest record of a tree, and the import of it is the same record" {
    // Goal: the two calls fit. Method: nothing to export; two records for one tree, the newer
    // one is exported; it imports on a store that has the tree and renders back unchanged.
    const tree = start();
    var out: [constants.image_record_bytes_max]u8 = undefined;
    var failure: image_peer.Failure = undefined;
    const exported = image_peer.export_record(&store, &memory, tree, &out, &failure);
    try testing.expectError(error.Failed, exported);
    try testing.expectEqual(image_peer.Refusal.no_record, failure.refusal);
    var parsed: images.Image = undefined;
    for ([_][]const u8{ "older", "newer" }, [_]u64{ 10, 20 }) |name, time| {
        const result = images.parse(record_for(tree, name, null), &parsed);
        try testing.expectEqual(images.ParseResult.ok, result);
        parsed.time = time;
        var save_failure: fs_mod.Failure = undefined;
        try images.save(&store, &parsed, &save_failure);
    }
    const text = try image_peer.export_record(&store, &memory, tree, &out, &failure);
    try testing.expectEqual(images.ParseResult.ok, images.parse(text, &parsed));
    try testing.expect(parsed.manifest.eql(Sha256.of("newer")));
    const copy = try testing.allocator.dupe(u8, text);
    defer testing.allocator.free(copy);
    const taken = try import_with(copy, tree, .keep, &failure);
    try testing.expect(!taken.created); // The record was there: it is updated in place.
    try testing.expect(taken.manifest.eql(Sha256.of("newer")));
}

test "a store busy with a gc refuses the import, and a failing disk is a store failure" {
    // Goal: the lock and write failures are refusals, not crashes. Method: another descriptor
    // holds the lock exclusive; then a write is made to fail.
    const tree = start();
    const text = record_for(tree, "manifest", null);
    var other: layout.Store = undefined;
    other.at(sim.interface(), root_path);
    try lock.hold(&other, .exclusive, "gc");
    store.lock_wait_ms = 0;
    var failure = try refused(text, tree);
    try testing.expectEqual(image_peer.Refusal.busy, failure.refusal);
    lock.release(&other);
    try testing.expectEqual(@as(u32, 0), written());
    files.faults.fail_mutation = files.mutations;
    files.faults.fail_errno = 28; // ENOSPC
    failure = try refused(text, tree);
    try testing.expectEqual(image_peer.Refusal.store_failed, failure.refusal);
}

comptime {
    _ = image_find;
}
