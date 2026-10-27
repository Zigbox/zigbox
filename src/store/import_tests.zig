//! Tests of `import.zig` against the simulated file system: what an import records, that two
//! imports of one directory agree, that it survives every fault and every crash, and that the
//! limits and the failures are the diagnostics they are meant to be.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const fs_sim = @import("fs_sim.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const roots = @import("roots.zig");
const support = @import("test_support.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");
const xattrs = @import("xattrs.zig");

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
var diag: Diag = undefined;

/// The warnings an import handed over, by code.
const Warnings = struct {
    codes: [64]codes.Code = undefined,
    count: u32 = 0,

    fn call(context: *anyopaque, warning: *const Diag) void {
        const self: *Warnings = @ptrCast(@alignCast(context));
        self.codes[self.count] = warning.code.?;
        self.count += 1;
    }

    fn options(self: *Warnings, squash_owner: bool) import.Options {
        return .{ .squash_owner = squash_owner, .warn = .{ .context = self, .call = call } };
    }

    fn has(self: *const Warnings, code: codes.Code) bool {
        for (self.codes[0..self.count]) |seen| {
            if (seen == code) return true;
        }
        return false;
    }
};

fn start(seed: u64, order: u32) void {
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    support.make_source(&files, order);
    diag.reset();
}

fn run_import(source: []const u8, warnings: *Warnings) import.Error!import.Result {
    var result: import.Result = undefined;
    diag.reset();
    try import.import(&store, &workspace, source, warnings.options(false), &result, &diag);
    return result;
}

test "an import records files, directories and symlinks, and stores each file once" {
    // Goal: the basic accounting. Method: the sample tree has 6 files (two with equal bytes and
    // modes, but one has an attribute, so six objects), 1 symlink, 4 directories with the root.
    start(1, 0);
    var warnings: Warnings = .{};
    const result = try run_import("/src", &warnings);
    try testing.expectEqual(@as(u64, 6), result.files);
    try testing.expectEqual(@as(u64, 1), result.symlinks);
    try testing.expectEqual(@as(u64, 4), result.directories);
    try testing.expectEqual(@as(u64, 0), result.skipped);
    try testing.expectEqual(@as(u64, 0), warnings.count);
    try testing.expectEqual(@as(u64, 6), result.objects_new);
    try testing.expectEqual(@as(u64, 0), result.objects_reused);
    try testing.expectEqual(@as(u64, 4), result.trees_new);
    try testing.expectEqual(@as(u64, 8 + 8 + 7 + 11 + 7 + 0), result.bytes);
    try support.check_whole(&files, root_path, store.chunk_bytes);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "importing twice gives one digest and stores nothing new" {
    // Goal: acceptance criterion 1 and idempotence. Method: import, import again.
    start(1, 0);
    var warnings: Warnings = .{};
    const first = try run_import("/src", &warnings);
    const objects_before = support.count_files(&files, root_path ++ "/objects");
    const second = try run_import("/src", &warnings);
    try testing.expect(first.digest.eql(second.digest));
    try testing.expectEqual(@as(u64, 0), second.objects_new);
    try testing.expectEqual(@as(u64, 0), second.trees_new);
    try testing.expectEqual(objects_before, support.count_files(&files, root_path ++ "/objects"));
    try support.check_whole(&files, root_path, store.chunk_bytes);
}

test "the digest does not depend on directory order, creation order or times" {
    // Goal: acceptance criterion 1 (independent of mtime and import order). Method: eleven
    // sample trees built in different creation orders, listed in different random orders (the
    // simulator shuffles every listing), with different times: one digest.
    var first: ?Digest = null;
    for (0..11) |order| {
        start(100 + order, @intCast(order));
        files.set_mtime_of("/src/bin/sh", 1000 * order);
        files.set_mtime_of("/src/etc", 77 + order);
        var warnings: Warnings = .{};
        const result = try run_import("/src", &warnings);
        if (first) |digest| {
            try testing.expect(digest.eql(result.digest));
        } else {
            first = result.digest;
        }
    }
}

test "everything that is content changes the digest" {
    // Goal: the digest means something. Method: one change at a time to the sample tree: bytes,
    // mode, owner, an attribute, a symlink target, a name, an added file, a removed file.
    start(1, 0);
    var warnings: Warnings = .{};
    const base = (try run_import("/src", &warnings)).digest;
    const Change = enum {
        bytes,
        mode,
        owner,
        xattr,
        target,
        added,
        empty_dir,
        root_mode,
        root_owner,
        root_group,
        root_xattr,
    };
    for (std.enums.values(Change)) |change| {
        start(1, 0);
        switch (change) {
            .bytes => @constCast(files.content_of("/src/etc/passwd").?)[0] = 'R',
            .mode => files.set_mode_of("/src/etc/passwd", 0o640),
            .owner => files.set_owner_of("/src/etc/passwd", 1, 1),
            .xattr => files.put_xattr("/src/etc/passwd", "user.x", "1"),
            .target => @constCast(files.content_of("/src/bin/busybox").?)[0] = 'x',
            .added => files.put_file("/src/etc/new", 0o644, ""),
            .empty_dir => files.put_dir("/src/etc/newdir", 0o755),
            .root_mode => files.set_mode_of("/src", 0o700),
            .root_owner => files.set_owner_of("/src", 3, 0),
            .root_group => files.set_owner_of("/src", 0, 3),
            .root_xattr => files.put_xattr("/src", "user.x", "1"),
        }
        const changed = (try run_import("/src", &warnings)).digest;
        try testing.expect(!changed.eql(base));
    }
}

/// The sample tree's path of a file in `/src/bin`.
fn sample_path(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "su")) return "/src/bin/su";
    if (std.mem.eql(u8, name, "ls")) return "/src/bin/ls";
    return "/src/bin/sh";
}

test "modes, owners, attributes and symlinks round-trip through the objects and the trees" {
    // Goal: acceptance criterion 2 for the import half. Method: for every file of the source,
    // the object the tree names has the same bytes, mode, owner, attributes and the store's fixed
    // mtime; the symlink and the directory entries carry theirs.
    start(1, 3);
    var warnings: Warnings = .{};
    const result = try run_import("/src", &warnings);
    var path: fs_mod.PathBuf = undefined;
    var buffer: [4096]u8 = undefined;
    var errno: u16 = 0;
    const root_bytes = try trees.load(&store, result.digest, &buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(root_bytes);
    var entry: tree.Entry = undefined;
    var seen: u32 = 0;
    while (try decoder.next(&entry)) {
        seen += 1;
        if (std.mem.eql(u8, entry.name, "bin")) {
            try testing.expectEqual(tree.Kind.dir, entry.kind);
            try testing.expectEqual(@as(u16, 0o755), entry.mode);
        }
        if (std.mem.eql(u8, entry.name, "empty")) {
            try testing.expectEqual(@as(u16, 0o700), entry.mode);
        }
    }
    try testing.expectEqual(@as(u32, 3), seen);
    // The setuid file with a capability: find its object by walking the bin tree.
    var bin_id: ?Digest = null;
    try decoder.init(root_bytes);
    while (try decoder.next(&entry)) {
        if (std.mem.eql(u8, entry.name, "bin")) bin_id = entry.subtree;
    }
    const bin_bytes = try trees.load(&store, bin_id.?, &buffer, &errno);
    try decoder.init(bin_bytes);
    var checked: u32 = 0;
    while (try decoder.next(&entry)) {
        if (entry.kind == .symlink) {
            try testing.expectEqualStrings("busybox", entry.name);
            try testing.expectEqualStrings("sh", entry.target);
            checked += 1;
            continue;
        }
        const stored = store.object_path(&path, entry.object);
        const source_path = sample_path(entry.name);
        const original = files.stat_of(source_path).?;
        const stat = files.stat_of(stored).?;
        try testing.expectEqual(original.mode, stat.mode);
        try testing.expectEqual(original.uid, stat.uid);
        try testing.expectEqualSlices(
            u8,
            files.content_of(source_path).?,
            files.content_of(stored).?,
        );
        try testing.expectEqual(@as(?u64, constants.store_mtime_seconds), files.mtime_of(stored));
        const want = files.xattrs_of(source_path) orelse &xattrs.empty;
        try testing.expectEqualSlices(u8, want, files.xattrs_of(stored) orelse &xattrs.empty);
        try testing.expectEqualSlices(u8, want, entry.xattrs);
        checked += 1;
    }
    try testing.expectEqual(@as(u32, 4), checked);
}

test "the root directory's mode, owner and attributes are in the digest and come back" {
    // Goal: the imported directory becomes the container's `/`, so its own metadata round-trips.
    // Method: import with mode 0700, owner 3, group 4 and an attribute; the root tree's own
    // section says so; setting the mode back gives the first digest again.
    start(1, 0);
    var warnings: Warnings = .{};
    const original = (try run_import("/src", &warnings)).digest;
    files.set_mode_of("/src", 0o700);
    files.set_owner_of("/src", 3, 4);
    files.put_xattr("/src", "user.root", "yes");
    const changed = try run_import("/src", &warnings);
    try testing.expect(!changed.digest.eql(original));
    var buffer: [4096]u8 = undefined;
    var errno: u16 = 0;
    const bytes = try trees.load(&store, changed.digest, &buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    var entry: tree.Entry = undefined;
    while (try decoder.next(&entry)) {}
    try testing.expectEqual(@as(u16, 0o700), decoder.own.mode);
    try testing.expectEqual(@as(u32, 3), decoder.own.uid);
    try testing.expectEqual(@as(u32, 4), decoder.own.gid);
    try testing.expectEqualSlices(u8, files.xattrs_of("/src").?, decoder.own.xattrs);
    // A subdirectory's tree carries no own metadata: it is in the entry in its parent.
    try decoder.init(bytes);
    while (try decoder.next(&entry)) {
        if (!std.mem.eql(u8, entry.name, "bin")) continue;
        // Its own buffer: `bytes` points into `buffer`, which the decoder is still reading.
        var sub_buffer: [4096]u8 = undefined;
        const sub_bytes = try trees.load(&store, entry.subtree, &sub_buffer, &errno);
        var sub: tree.Decoder = undefined;
        try sub.init(sub_bytes);
        var inner: tree.Entry = undefined;
        while (try sub.next(&inner)) {}
        try testing.expectEqual(@as(u16, 0), sub.own.mode);
        try testing.expectEqual(@as(usize, 1), sub.own.xattrs.len);
    }
    // Back to what it was: the first digest, though it was written in between.
    files.set_mode_of("/src", 0o755);
    files.set_owner_of("/src", 0, 0);
    files.remove_xattrs_of("/src");
    try testing.expect((try run_import("/src", &warnings)).digest.eql(original));
}

test "an owner or group the namespace cannot map is counted, recorded as 65534, and warned once" {
    // Goal: no silent loss. Method: three entries show the overflow id (a file's owner, another
    // file's owner and group, the root's group); one warning for the import, with the counts and
    // the first path; the digest holds 65534; a squashing import counts nothing.
    start(1, 0);
    const overflow = constants.store_overflow_id;
    files.set_owner_of("/src/etc/passwd", overflow, 0);
    files.set_owner_of("/src/etc/shadow", overflow, overflow);
    files.set_owner_of("/src", 0, overflow);
    var warnings: Warnings = .{};
    const result = try run_import("/src", &warnings);
    try testing.expectEqual(@as(u64, 2), result.unmapped_uids);
    try testing.expectEqual(@as(u64, 2), result.unmapped_gids);
    try testing.expectEqual(@as(u32, 1), warnings.count);
    try testing.expect(warnings.has(.W0412));
    start(1, 0);
    files.set_owner_of("/src/etc/passwd", overflow, 0);
    files.set_owner_of("/src/etc/shadow", overflow, overflow);
    files.set_owner_of("/src", 0, overflow);
    var squashed: Warnings = .{};
    var again: import.Result = undefined;
    try import.import(&store, &workspace, "/src", squashed.options(true), &again, &diag);
    try testing.expectEqual(@as(u64, 0), again.unmapped_uids + again.unmapped_gids);
    try testing.expectEqual(@as(u32, 0), squashed.count);
    // An ordinary tree has none, and says nothing.
    start(1, 0);
    var clean: Warnings = .{};
    const plain = try run_import("/src", &clean);
    try testing.expectEqual(@as(u64, 0), plain.unmapped_uids + plain.unmapped_gids);
    try testing.expectEqual(@as(u32, 0), clean.count);
}

test "a copy with one more file adds only that file's object" {
    // Goal: the dedupe claim of the demo (step 2). Method: import, add one big file, import:
    // exactly one new object, and its bytes are the store's growth.
    start(1, 0);
    var warnings: Warnings = .{};
    const first = try run_import("/src", &warnings);
    files.put_file("/src/etc/big", 0o644, "x");
    const bytes_before = support.bytes_under(&files, root_path ++ "/objects");
    const second = try run_import("/src", &warnings);
    try testing.expect(!first.digest.eql(second.digest));
    try testing.expectEqual(@as(u64, 1), second.objects_new);
    try testing.expectEqual(@as(u64, 6), second.objects_reused);
    try testing.expectEqual(bytes_before + 1, support.bytes_under(&files, root_path ++ "/objects"));
}

test "the same bytes with another mode are another object, with the same bytes stored again" {
    // Goal: "one object per (content, metadata) pair". Method: two files, equal bytes, modes 644
    // and 600.
    start(1, 0);
    var warnings: Warnings = .{};
    _ = try run_import("/src", &warnings);
    const before = support.count_files(&files, root_path ++ "/objects");
    files.put_file("/src/etc/passwd2", 0o600, "root:x:0:0\n");
    _ = try run_import("/src", &warnings);
    try testing.expectEqual(before + 1, support.count_files(&files, root_path ++ "/objects"));
}

test "devices are skipped with a warning, overlay attributes silently, others with a warning" {
    // Goal: the brief's rules for what is not kept. Method: a character device, a FIFO, a
    // socket, an overlay attribute, a trusted one and a user one.
    start(1, 0);
    files.put("/src/dev0", .char_device, 0o600, .{ 0, 0 }, "");
    files.put("/src/fifo", .fifo, 0o600, .{ 0, 0 }, "");
    files.put("/src/sock", .socket, 0o600, .{ 0, 0 }, "");
    files.put_xattr("/src/etc/passwd", "user.overlay.opaque", "y");
    files.put_xattr("/src/etc/passwd", "trusted.thing", "1");
    files.put_xattr("/src/etc/passwd", "user.keep", "1");
    var warnings: Warnings = .{};
    const result = try run_import("/src", &warnings);
    try testing.expectEqual(@as(u64, 3), result.skipped);
    try testing.expectEqual(@as(u64, 1), result.xattrs_skipped);
    try testing.expect(warnings.has(.W0410));
    try testing.expect(warnings.has(.W0411));
    try testing.expectEqual(@as(u32, 4), warnings.count);
    // Without them the digest is the plain tree's, except for the user attribute.
    start(1, 0);
    files.put_xattr("/src/etc/passwd", "user.keep", "1");
    var quiet: Warnings = .{};
    try testing.expect((try run_import("/src", &quiet)).digest.eql(result.digest));
}

test "past the first few warnings they are counted, and the last one says how many" {
    // Goal: a tree full of devices does not flood stderr. Method: twelve FIFOs.
    start(1, 0);
    for (0..12) |index| {
        var name: [16]u8 = undefined;
        files.put(
            try std.fmt.bufPrint(&name, "/src/f{d:0>2}", .{index}),
            .fifo,
            0o600,
            .{ 0, 0 },
            "",
        );
    }
    var warnings: Warnings = .{};
    const result = try run_import("/src", &warnings);
    try testing.expectEqual(@as(u64, 12), result.skipped);
    try testing.expectEqual(@as(u32, constants.store_warnings_shown_max + 1), warnings.count);
}

test "a host that maps only its own id records every owner as 0" {
    // Goal: W0201's rule. Method: the shadow file is owned by 5; squashing makes the tree the
    // same as one built with every owner 0.
    start(1, 0);
    var warnings: Warnings = .{};
    var result: import.Result = undefined;
    try import.import(&store, &workspace, "/src", warnings.options(true), &result, &diag);
    const squashed = result.digest;
    const plain = (try run_import("/src", &warnings)).digest;
    try testing.expect(!squashed.eql(plain));
    start(1, 0);
    files.set_owner_of("/src/etc/shadow", 0, 0);
    try import.import(&store, &workspace, "/src", warnings.options(true), &result, &diag);
    try testing.expect(result.digest.eql(squashed));
}

fn expect_code(code: codes.Code) !void {
    try testing.expectEqual(@as(?codes.Code, code), diag.code);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a source that is missing, a file, a link or unreadable is refused with E0414" {
    // Goal: the failures naming the path. Method: each case once.
    start(1, 0);
    var warnings: Warnings = .{};
    try testing.expectError(error.Failed, run_import("/nowhere", &warnings));
    try expect_code(.E0414);
    try testing.expectError(error.Failed, run_import("/src/etc/passwd", &warnings));
    try expect_code(.E0414);
    files.put_symlink("/link", "/src");
    try testing.expectError(error.Failed, run_import("/link", &warnings));
    try expect_code(.E0414);
    files.set_unreadable("/src/etc");
    try testing.expectError(error.Failed, run_import("/src", &warnings));
    try expect_code(.E0414);
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/roots"));
}

test "a file that grows while it is imported is E0418" {
    // Goal: the second read is checked against the first. Method: the simulator appends a byte
    // to a file the moment it is opened, after its size was read.
    start(1, 0);
    files.faults.grow_on_open = true;
    var warnings: Warnings = .{};
    try testing.expectError(error.Failed, run_import("/src", &warnings));
    try expect_code(.E0418);
}

test "a tree nested too deep is E0415, and one at the limit is not" {
    // Goal: the depth limit is exact. Method: a chain of 64 directories below the root imports;
    // 65 does not.
    start(1, 0);
    support.make_chain(&files, constants.store_depth_max);
    var warnings: Warnings = .{};
    _ = try run_import("/deep", &warnings);
    start(1, 0);
    support.make_chain(&files, constants.store_depth_max + 1);
    try testing.expectError(error.Failed, run_import("/deep", &warnings));
    try expect_code(.E0415);
}

test "the disk filling is E0416, says what was kept, and the same import finishes later" {
    // Goal: the disk-full path of the brief. Method: room for part of the objects; the import
    // fails with E0416; with room again the same command completes with the same digest.
    start(1, 0);
    var warnings: Warnings = .{};
    const clean = (try run_import("/src", &warnings)).digest;
    start(1, 0);
    files.faults.bytes_max = support.bytes_under(&files, "/src") + 20;
    try testing.expectError(error.Failed, run_import("/src", &warnings));
    try expect_code(.E0416);
    try support.check_whole(&files, root_path, store.chunk_bytes);
    files.faults.bytes_max = null;
    const later = try run_import("/src", &warnings);
    try testing.expect(later.digest.eql(clean));
    try testing.expect(later.objects_reused > 0);
}

test "a failure or a crash at any write point leaves the store whole and repeatable" {
    // Goal: the brief's crash rule, this milestone's equivalent of the VOPR. Method: first run
    // an import to count its write points; then for every point, once as an error and once as a
    // crash (torn files included): the store holds only whole objects, trees and roots, and a
    // second import gives the digest of the clean run.
    start(1, 0);
    var warnings: Warnings = .{};
    const clean = try run_import("/src", &warnings);
    const points = files.mutations;
    try testing.expect(points > 20);
    var point: u32 = 0;
    while (point < points) : (point += 1) {
        for ([_]bool{ false, true }) |crash| {
            start(1000 + point, 0);
            if (crash) files.faults.crash_mutation = point else files.faults.fail_mutation = point;
            const result = run_import("/src", &warnings);
            try testing.expectError(error.Failed, result);
            if (crash) files.restart();
            files.faults.fail_mutation = null;
            try support.check_whole(&files, root_path, store.chunk_bytes);
            const again = try run_import("/src", &warnings);
            try testing.expect(again.digest.eql(clean.digest));
            try support.check_whole(&files, root_path, store.chunk_bytes);
            try testing.expectEqual(@as(u32, 0), sim.open_count());
        }
    }
}

test "interrupted calls, short reads and short writes do not change the result" {
    // Goal: the retry loops are the production ones. Method: heavy faults of the harmless kinds
    // over several seeds: the digest is always the clean one.
    start(1, 0);
    var warnings: Warnings = .{};
    const clean = (try run_import("/src", &warnings)).digest;
    for (0..20) |seed| {
        start(seed, @intCast(seed));
        files.faults.interrupt_per_mille = 300;
        files.faults.short_read_per_mille = 500;
        files.faults.short_write_per_mille = 500;
        const result = try run_import("/src", &warnings);
        try testing.expect(result.digest.eql(clean));
        try support.check_whole(&files, root_path, store.chunk_bytes);
    }
}

test "a file of several chunks gets a chunk list that matches, and a file of one does not" {
    // Goal: the chunk lists. Method: a chunk of 8 bytes; a file of 20 bytes has three hashes and
    // one of 8 has none stored; of the sample's own files only passwd (11 bytes) is longer.
    start(1, 0);
    store.chunk_bytes = 8;
    files.put_file("/src/etc/long", 0o644, "0123456789abcdefghij");
    files.put_file("/src/etc/short", 0o644, "01234567");
    var warnings: Warnings = .{};
    _ = try run_import("/src", &warnings);
    try support.check_whole(&files, root_path, 8);
    try testing.expectEqual(@as(u32, 2), count_chunk_lists());
}

fn count_chunk_lists() u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (std.mem.endsWith(u8, path, ".chunks")) count += 1;
    }
    return count;
}

test "the root record has the source, the time and the totals" {
    // Goal: `ls` can answer from the record alone. Method: import and read it back.
    start(1, 0);
    sim.world.now = 1_792_873_384;
    var warnings: Warnings = .{};
    const result = try run_import("/src/", &warnings);
    var record: roots.Root = undefined;
    var errno: u16 = 0;
    try roots.load(&store, result.digest, &record, &errno);
    try testing.expectEqualStrings("/src/", record.source_text());
    try testing.expectEqual(@as(u64, 1_792_873_384), record.time);
    try testing.expectEqual(result.files, record.files);
    try testing.expectEqual(result.bytes, record.bytes);
}

test "the chunk hashes of an object are its stored list, or the one hash that is implied" {
    // Goal: `chunk_hashes` (the library's `chunks(object_id)`) agrees with the bytes. Method: a
    // chunk of 8 bytes; a file of 20 bytes (stored list of three), one of 8 (implied, one hash)
    // and an empty one (none).
    start(1, 0);
    store.chunk_bytes = 8;
    const content = "0123456789abcdefghij";
    files.put_file("/src/etc/long", 0o644, content);
    files.put_file("/src/etc/short", 0o644, "01234567");
    var warnings: Warnings = .{};
    _ = try run_import("/src", &warnings);
    const none = &xattrs.empty;
    const cases = [_]struct { bytes: []const u8, count: u32 }{
        .{ .bytes = content, .count = 3 },
        .{ .bytes = "01234567", .count = 1 },
        .{ .bytes = "", .count = 0 },
    };
    for (cases) |case| {
        const attrs: object.Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = none };
        const id = object.object_id(Digest.of(case.bytes), attrs);
        const found = try object.chunk_hashes(&store, id, &workspace.io, &workspace.chunks);
        try testing.expectEqual(case.count, found.len);
        for (found, 0..) |hash, at| {
            const start_at = at * 8;
            const end_at = @min(start_at + 8, case.bytes.len);
            try testing.expect(hash.eql(Digest.of(case.bytes[start_at..end_at])));
        }
    }
}
