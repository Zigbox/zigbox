//! Tests of the build cache entry (`cache.zig`) against the simulated file system: the format,
//! lookup and record, a tree an older gc collected, a crash at every write of an entry, and gc
//! treating the cache directory as a root. The entry bound of gc is tested on a real file
//! system in `cache_bounds_tests.zig`, because the simulator holds too few files.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const cache = @import("cache.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const gc = @import("../store/gc.zig");
const import = @import("../store/import.zig");
const key_mod = @import("key.zig");
const layout = @import("../store/layout.zig");
const lock = @import("../store/lock.zig");
const roots = @import("../store/roots.zig");
const support = @import("../store/test_support.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_workspace: import.Workspace = undefined;
var cache_workspace: cache.Workspace = undefined;
var gc_workspace: gc.Workspace = undefined;
var gc_tables: [16 * 1024 * 1024]u8 align(8) = @splat(0);
var diag: Diag = undefined;
var key: key_mod.Key = undefined;
var other_key: key_mod.Key = undefined;
var failure: cache.Failure = undefined;

fn filled(byte: u8) Digest {
    var digest: Digest = undefined;
    @memset(&digest.bytes, byte);
    return digest;
}

/// The key of a step whose input tree is `tag`: different tags give different keys.
fn make_key(target: *key_mod.Key, tag: u8) void {
    const spec: key_mod.Spec = .{
        .platform = "linux/amd64",
        .base_tree = filled(1),
        .base_env = &.{},
        .input_tree = filled(tag),
        .needs = &.{},
        .argv = &.{"true"},
        .env = &.{},
        .network = false,
        .name = "step",
    };
    key_mod.compute(&spec, target) catch unreachable; // A small spec.
}

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
    lock.hold(&store, .shared, "test") catch unreachable; // The simulated lock file is free.
    make_key(&key, 1);
    make_key(&other_key, 2);
}

/// Imports `/src` and returns the tree's digest; its root record is the only thing keeping it.
fn import_source() Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &import_workspace, "/src", options, &result, &diag) catch {
        unreachable; // The sample trees import.
    };
    return result.digest;
}

fn source_tree(extra: []const u8) Digest {
    support.make_source(&files, 0);
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghij");
    files.put_file("/src/etc/extra", 0o644, extra);
    return import_source();
}

fn do_lookup(target: *const key_mod.Key) cache.Lookup {
    return cache.lookup(&store, &cache_workspace, target, &failure) catch {
        unreachable; // The simulated store reads.
    };
}

fn do_record(target: *const key_mod.Key, output: Digest) Digest {
    return cache.record(&store, &cache_workspace, target, output, &failure) catch {
        unreachable; // No fault is armed.
    };
}

fn expect_miss(want: cache.Miss, got: cache.Lookup) !void {
    switch (got) {
        .hit => return error.TestUnexpectedResult,
        .miss => |why| try testing.expectEqual(want, why),
    }
}

fn expect_hit(want: Digest, got: cache.Lookup) !void {
    switch (got) {
        .hit => |output| try testing.expect(output.eql(want)),
        .miss => |why| {
            std.debug.print("expected a hit, got a miss: {s}\n", .{@tagName(why)});
            return error.TestUnexpectedResult;
        },
    }
}

fn entry_path(target: *const key_mod.Key, buffer: *[constants.sim_fs_path_bytes_max]u8) []const u8 {
    const hex = target.digest.hex();
    return std.fmt.bufPrint(buffer, root_path ++ "/build/cache/{s}", .{&hex}) catch
        unreachable; // Short.
}

fn tree_object_path(digest: Digest, buffer: *[constants.sim_fs_path_bytes_max]u8) []const u8 {
    const hex = digest.hex();
    return std.fmt.bufPrint(buffer, root_path ++ "/trees/{s}/{s}", .{ hex[0..2], hex[2..] }) catch
        unreachable; // Short.
}

// ---- The format ------------------------------------------------------------------------------

var render_buffer: [constants.build_cache_entry_bytes_max]u8 = undefined;

test "an entry reads back what was written" {
    // Goal: render and parse are a pair. Method: one key's entry, parsed under its name; the
    // same bytes under another name are not an entry.
    make_key(&key, 1);
    make_key(&other_key, 2);
    const output = filled(7);
    const text = cache.render(&render_buffer, output, key.preimage());
    var entry: cache.Entry = undefined;
    try testing.expectEqual(cache.ParseResult.ok, cache.parse(text, key.digest, &entry));
    try testing.expect(entry.tree.eql(output));
    try testing.expectEqualSlices(u8, key.preimage(), entry.preimage);
    const wrong_name = cache.parse(text, other_key.digest, &entry);
    try testing.expectEqual(cache.ParseResult.malformed, wrong_name);
    try testing.expectEqual(cache.ParseResult.malformed, cache.parse(text, filled(0), &entry));
}

test "an entry cut at any byte, or with a byte more, is malformed" {
    // Goal: parse accepts only what render writes. Method: every prefix, and the entry with one
    // more byte after it.
    make_key(&key, 1);
    const text = cache.render(&render_buffer, filled(7), key.preimage());
    var entry: cache.Entry = undefined;
    for (0..text.len) |length| {
        const got = cache.parse(text[0..length], key.digest, &entry);
        try testing.expectEqual(cache.ParseResult.malformed, got);
    }
    var longer: [constants.build_cache_entry_bytes_max]u8 = undefined;
    @memcpy(longer[0..text.len], text);
    longer[text.len] = 0;
    try testing.expectEqual(
        cache.ParseResult.malformed,
        cache.parse(longer[0 .. text.len + 1], key.digest, &entry),
    );
}

test "a changed byte makes an entry malformed, except in the tree digest, which is data" {
    // Goal: every byte of the entry is covered by a check. Method: flip each byte in turn; the
    // version reads as newer or malformed, the preimage no longer hashes to the name, and the
    // tree's own 32 bytes are the one place a flip is a different, valid entry.
    make_key(&key, 1);
    const text = cache.render(&render_buffer, filled(7), key.preimage());
    var copy: [constants.build_cache_entry_bytes_max]u8 = undefined;
    const tree_from = cache.magic.len + 4;
    for (0..text.len) |at| {
        @memcpy(copy[0..text.len], text);
        copy[at] ^= 0xff;
        var entry: cache.Entry = undefined;
        const got = cache.parse(copy[0..text.len], key.digest, &entry);
        if (at >= tree_from and at < tree_from + constants.store_digest_bytes) {
            try testing.expectEqual(cache.ParseResult.ok, got);
            try testing.expect(!entry.tree.eql(filled(7)));
        } else {
            try testing.expect(got != .ok);
        }
    }
}

test "a newer version is newer, version 0 is malformed" {
    // Goal: the reader skips what it does not know and refuses what no release wrote.
    make_key(&key, 1);
    const text = cache.render(&render_buffer, filled(7), key.preimage());
    var copy: [constants.build_cache_entry_bytes_max]u8 = undefined;
    @memcpy(copy[0..text.len], text);
    var entry: cache.Entry = undefined;
    std.mem.writeInt(u32, copy[cache.magic.len..][0..4], cache.entry_version + 1, .little);
    const parsed = cache.parse(copy[0..text.len], key.digest, &entry);
    try testing.expectEqual(cache.ParseResult.newer, parsed);
    std.mem.writeInt(u32, copy[cache.magic.len..][0..4], 0, .little);
    try testing.expectEqual(
        cache.ParseResult.malformed,
        cache.parse(copy[0..text.len], key.digest, &entry),
    );
}

/// An entry whose preimage is the key's magic and `length - magic.len` filler bytes, under its
/// own hash, with `declared` as the length field.
fn long_entry(
    length: u32,
    declared: u32,
    out: *[constants.build_cache_entry_bytes_max]u8,
) []const u8 {
    const header: u32 = cache.magic.len + 4 + constants.store_digest_bytes + 4;
    assert(header + length <= out.len);
    @memcpy(out[0..cache.magic.len], cache.magic);
    std.mem.writeInt(u32, out[cache.magic.len..][0..4], cache.entry_version, .little);
    @memset(out[cache.magic.len + 4 ..][0..constants.store_digest_bytes], 9);
    std.mem.writeInt(u32, out[header - 4 ..][0..4], declared, .little);
    @memcpy(out[header..][0..key_mod.magic.len], key_mod.magic);
    @memset(out[header + key_mod.magic.len ..][0 .. length - key_mod.magic.len], 'x');
    return out[0 .. header + length];
}

test "a preimage of the largest length is an entry, one byte more is not" {
    // Goal: the bound `render` asserts is checked by `parse`. Method: the longest preimage, then
    // one byte past it with a hash that matches (so only the length can refuse it), and a length
    // field that disagrees with the bytes.
    const most = constants.build_key_preimage_bytes_max;
    var out: [constants.build_cache_entry_bytes_max]u8 = undefined;
    var entry: cache.Entry = undefined;
    var text = long_entry(most, most, &out);
    const name = Digest.of(text[text.len - most ..]);
    try testing.expectEqual(cache.ParseResult.ok, cache.parse(text, name, &entry));
    try testing.expectEqual(@as(usize, most), entry.preimage.len);
    text = long_entry(most + 1, most + 1, &out);
    const past = Digest.of(text[text.len - most - 1 ..]);
    try testing.expectEqual(cache.ParseResult.malformed, cache.parse(text, past, &entry));
    text = long_entry(most, most - 1, &out);
    const same = Digest.of(text[text.len - most ..]);
    try testing.expectEqual(cache.ParseResult.malformed, cache.parse(text, same, &entry));
    text = long_entry(key_mod.magic.len + 3, key_mod.magic.len + 3, &out);
    const short = Digest.of(text[text.len - key_mod.magic.len - 3 ..]);
    try testing.expectEqual(cache.ParseResult.malformed, cache.parse(text, short, &entry));
}

// ---- Lookup and record -----------------------------------------------------------------------

test "an unbuilt step is a miss; a recorded one is a hit; the first entry stays" {
    // Goal: the cycle, and the race rule. Method: look up, record, look up; record the same key
    // for another output and get the first back.
    start();
    const first = source_tree("one");
    try expect_miss(.absent, do_lookup(&key));
    try testing.expect(first.eql(do_record(&key, first)));
    try expect_hit(first, do_lookup(&key));
    try expect_miss(.absent, do_lookup(&other_key));
    files.remove_path("/src/etc/extra");
    files.put_file("/src/etc/extra", 0o644, "two");
    const second = import_source();
    try testing.expect(!first.eql(second));
    try testing.expect(first.eql(do_record(&key, second)));
    try expect_hit(first, do_lookup(&key));
    try support.check_whole(&files, root_path, store.chunk_bytes);
}

test "a tree an older gc took reads as a miss, and a rebuild is recorded and hits" {
    // Goal: the accepted cost of an older gc. Method: drop the root and move the tree's objects
    // away as that gc would (a tree object, then a file object), check a miss each time, then
    // import the rebuilt tree and record: the entry hits.
    start();
    const output = source_tree("one");
    _ = do_record(&key, output);
    try expect_hit(output, do_lookup(&key));
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const tree_file = tree_object_path(output, &buffer);
    const tree_bytes = files.content_of(tree_file).?;
    var saved: [constants.store_tree_bytes_max / 64]u8 = undefined;
    @memcpy(saved[0..tree_bytes.len], tree_bytes);
    files.remove_path(tree_file);
    try expect_miss(.tree_incomplete, do_lookup(&key));
    files.put_file(tree_file, 0o644, saved[0..tree_bytes.len]);
    try expect_hit(output, do_lookup(&key));
    var object_buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const object_file = object_path_of("/src/etc/passwd", &object_buffer);
    files.remove_path(object_file);
    try expect_miss(.tree_incomplete, do_lookup(&key));
    // The old gc took the whole tree: remove it, build again (a different output this time) and
    // record over the stale entry.
    files.remove_path(tree_file);
    files.remove_path("/src/etc/extra");
    files.put_file("/src/etc/extra", 0o644, "rebuilt");
    const rebuilt = import_source();
    try expect_miss(.tree_incomplete, do_lookup(&key));
    try testing.expect(rebuilt.eql(do_record(&key, rebuilt)));
    try expect_hit(rebuilt, do_lookup(&key));
}

fn object_path_of(path: []const u8, buffer: *[constants.sim_fs_path_bytes_max]u8) []const u8 {
    const object = @import("../store/object.zig");
    const content = files.content_of(path).?;
    const stat = files.stat_of(path).?;
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = files.xattrs_of(path) orelse &@import("../store/xattrs.zig").empty,
    };
    const id = object.object_id(Digest.of(content), attrs);
    const hex = id.hex();
    return std.fmt.bufPrint(buffer, root_path ++ "/objects/{s}/{s}", .{ hex[0..2], hex[2..] }) catch
        unreachable; // Short.
}

test "a damaged entry is a miss that says so, and record replaces it" {
    // Goal: malformed is a miss, not an error. Method: garbage, an empty file, an entry from a
    // newer release and an entry of another key under this key's name; each is a miss, and the
    // record after it hits.
    start();
    const output = source_tree("one");
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = entry_path(&key, &buffer);
    files.put_dir(root_path ++ "/build", 0o755);
    files.put_dir(root_path ++ "/build/cache", 0o755);
    files.put_file(path, 0o644, "not an entry");
    try expect_miss(.malformed, do_lookup(&key));
    files.remove_path(path);
    files.put_file(path, 0o644, "");
    try expect_miss(.malformed, do_lookup(&key));
    const other = cache.render(&render_buffer, output, other_key.preimage());
    files.remove_path(path);
    files.put_file(path, 0o644, other);
    try expect_miss(.malformed, do_lookup(&key));
    var newer: [constants.build_cache_entry_bytes_max]u8 = undefined;
    const text = cache.render(&render_buffer, output, key.preimage());
    @memcpy(newer[0..text.len], text);
    std.mem.writeInt(u32, newer[cache.magic.len..][0..4], cache.entry_version + 1, .little);
    files.remove_path(path);
    files.put_file(path, 0o644, newer[0..text.len]);
    try expect_miss(.newer, do_lookup(&key));
    try testing.expect(output.eql(do_record(&key, output)));
    try expect_hit(output, do_lookup(&key));
}

test "an entry that is not a file, or cannot be read, is a failure, not a miss" {
    // Goal: only "not there" and "not an entry" are misses; an unreadable cache is reported.
    start();
    const output = source_tree("one");
    _ = do_record(&key, output);
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.set_unreadable(entry_path(&key, &buffer));
    try testing.expectError(
        error.Failed,
        cache.lookup(&store, &cache_workspace, &key, &failure),
    );
    switch (failure) {
        .io => |io| try testing.expectEqual(@as(u16, fs_sim.errno_acces), io.errno),
        .tree => return error.TestUnexpectedResult,
    }
}

// ---- A crash at every write ------------------------------------------------------------------

/// Records with the fault at write point `point`; true if the record ran to its end without
/// the fault firing, so there are no more points to try.
fn faulty_record(point: u32, crash: bool, output: Digest) bool {
    files.mutations = 0;
    if (crash) files.faults.crash_mutation = point else files.faults.fail_mutation = point;
    defer files.faults = .{};
    _ = cache.record(&store, &cache_workspace, &key, output, &failure) catch return false;
    return true;
}

/// The store is whole, and the key's entry is either absent (a miss) or the new one (a hit): a
/// partial entry is never a hit. `old` is what the key hit before, if anything.
fn expect_unchanged_or_updated(output: Digest, old: ?Digest) !void {
    try support.check_whole(&files, root_path, store.chunk_bytes);
    const got = do_lookup(&key);
    switch (got) {
        .hit => |found| {
            const updated = found.eql(output);
            const unchanged = if (old) |before| found.eql(before) else false;
            try testing.expect(updated or unchanged);
        },
        .miss => |why| {
            try testing.expect(old == null or why == .tree_incomplete);
            try testing.expect(why == .absent or why == .tree_incomplete);
        },
    }
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    if (files.content_of(entry_path(&key, &buffer))) |bytes| {
        var entry: cache.Entry = undefined;
        try testing.expectEqual(cache.ParseResult.ok, cache.parse(bytes, key.digest, &entry));
    }
}

test "a crash or failure at any write of an entry leaves it absent or whole" {
    // Goal: the brief's interrupted-writes rule for the cache. Method: record with the fault at
    // each write point in turn, once as a crash (the machine dies, unsynced bytes torn) and once
    // as a failed call. Afterwards the store is whole, and the entry is either not there or the
    // complete new one; a second record after the fault finishes the job. With a stale entry
    // (its tree gone) in place, the old entry or the new one is there, never half of one.
    for ([_]bool{ false, true }) |stale| {
        for ([_]bool{ true, false }) |crash| {
            var point: u32 = 0;
            while (true) : (point += 1) {
                start();
                const output = source_tree("one");
                var old: ?Digest = null;
                if (stale) {
                    const gone = filled(5);
                    files.put_dir(root_path ++ "/build", 0o755);
                    files.put_dir(root_path ++ "/build/cache", 0o755);
                    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
                    files.put_file(
                        entry_path(&key, &buffer),
                        0o644,
                        cache.render(&render_buffer, gone, key.preimage()),
                    );
                    old = null;
                }
                const finished = faulty_record(point, crash, output);
                if (crash and !finished) files.restart();
                try expect_unchanged_or_updated(output, old);
                if (finished) break;
                try testing.expect(output.eql(do_record(&key, output)));
                try expect_hit(output, do_lookup(&key));
            }
            try testing.expect(point >= 4);
        }
    }
}

// ---- gc --------------------------------------------------------------------------------------

fn plan_total() !u64 {
    var result: gc.Plan = undefined;
    var gc_failure: gc.Failure = undefined;
    gc.plan(&store, &gc_workspace, &import_workspace.arena, &.{}, &result, &gc_failure) catch {
        return error.PlanFailed;
    };
    return result.counts.total();
}

test "gc keeps a tree only a cache entry names, and collects it when the entry is gone" {
    // Goal: the cache directory is a root. Method: import a tree and drop its root record, so
    // that gc would take it; record an entry and the plan is empty; remove the entry and the
    // plan takes the tree again.
    start();
    const output = source_tree("one");
    roots.remove(&store, output) catch unreachable; // The import made the root.
    const unrooted = try plan_total();
    try testing.expect(unrooted > 0);
    _ = do_record(&key, output);
    try testing.expectEqual(@as(u64, 0), try plan_total());
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.remove_path(entry_path(&key, &buffer));
    try testing.expectEqual(unrooted, try plan_total());
}

test "gc: entries that parse not, or name a tree that is gone, root nothing and do not stop it" {
    // Goal: a bad entry is a miss for a lookup and nothing for gc. Method: with a dropped root,
    // add a stray name, garbage under a key's name, an entry for a tree that is not in the
    // store, one whose tree has lost a subtree, and one for another name than its preimage's:
    // the plan is the same as with no entries at all.
    start();
    const output = source_tree("one");
    roots.remove(&store, output) catch unreachable; // The import made the root.
    const unrooted = try plan_total();
    files.put_dir(root_path ++ "/build", 0o755);
    files.put_dir(root_path ++ "/build/cache", 0o755);
    files.put_file(root_path ++ "/build/cache/stray", 0o644, "x");
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.put_file(entry_path(&key, &buffer), 0o644, "garbage");
    make_key(&other_key, 3);
    files.put_file(
        entry_path(&other_key, &buffer),
        0o644,
        cache.render(&render_buffer, filled(5), other_key.preimage()),
    );
    var third: key_mod.Key = undefined;
    make_key(&third, 4);
    const wrong = cache.render(&render_buffer, output, third.preimage());
    files.put_file(entry_path(&key_two(), &buffer), 0o644, wrong);
    try testing.expectEqual(unrooted, try plan_total());
}

fn key_two() key_mod.Key {
    var made: key_mod.Key = undefined;
    make_key(&made, 5);
    return made;
}

test "gc refuses when a tree an entry names is damaged, and says which" {
    // Goal: only a missing tree is tolerated; guessing about a damaged one could free what is
    // wanted. Method: flip a byte of the tree object an entry names.
    start();
    const output = source_tree("one");
    roots.remove(&store, output) catch unreachable; // The import made the root.
    _ = do_record(&key, output);
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    files.flip_byte(tree_object_path(output, &buffer), 6);
    var result: gc.Plan = undefined;
    var gc_failure: gc.Failure = undefined;
    try testing.expectError(
        error.Failed,
        gc.plan(&store, &gc_workspace, &import_workspace.arena, &.{}, &result, &gc_failure),
    );
    switch (gc_failure) {
        .tree => |walked| try testing.expect(walked.where.eql(output)),
        else => return error.TestUnexpectedResult,
    }
}
