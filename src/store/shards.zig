//! Reading one shard directory of `objects/` or `trees/` (or the whole of `roots/` and
//! `cache/`) as a sorted list of names, in memory the caller owns. `verify` and `gc` walk the
//! store shard by shard in this order, so a list built from them is in the order of the full
//! 64-digit ids: shard first, then the 62 digits, which is what a plan hash needs.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const names_mod = @import("names.zig");

const Digest = digest_mod.Digest;
const NameList = names_mod.NameList;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

/// The names of a directory and their order.
pub const Names = struct {
    list: NameList,
    order: []const u32,

    pub fn count(names: *const Names) u32 {
        assert(names.order.len <= constants.store_roots_max * 1024);
        assert(names.order.len == names.list.count);
        return names.list.count;
    }

    pub fn name(names: *const Names, index: u32) []const u8 {
        assert(names.list.count == names.order.len);
        assert(index < names.order.len);
        return names.list.at(names.order[index]);
    }
};

/// Lists `<store>/<directory>` (or its shard `shard`, if given), sorted by name bytes. A
/// directory that does not exist is empty. `FileTooLarge` if `bytes` or `offsets` are too small.
pub fn read(
    store: *const Store,
    bytes: []u8,
    offsets: []u32,
    directory: []const u8,
    shard: ?u32,
) host_mod.Error!Names {
    assert(bytes.len > 0);
    assert(directory.len > 0);
    assert(offsets.len > 0);
    var path: PathBuf = undefined;
    var list = NameList.init(bytes, @intCast(offsets.len));
    var listed: [:0]const u8 = undefined;
    if (shard) |index| {
        assert(index < constants.store_shards_count);
        var hex: [2]u8 = undefined;
        // Cannot fail: two digits.
        _ = std.fmt.bufPrint(&hex, "{x:0>2}", .{index}) catch unreachable;
        listed = store.path(&path, &.{ "/", directory, "/", &hex });
    } else {
        listed = store.path(&path, &.{ "/", directory });
    }
    store.fs.read_dir(listed, list.visitor()) catch |err| {
        if (err == error.NotFound) return .{ .list = list, .order = offsets[0..0] };
        return err;
    };
    if (!list.complete()) return error.FileTooLarge;
    return .{ .list = list, .order = list.sorted(offsets) };
}

/// The 64-digit id of the file `name` in shard `shard`: 62 digits after the two of the shard.
/// Null for any other name (a temporary file, a stray, a chunk list).
pub fn id_of(shard: u32, name: []const u8) ?Digest {
    assert(name.len <= constants.store_name_bytes_max);
    assert(shard < constants.store_shards_count);
    if (name.len != constants.store_digest_hex_bytes - 2) return null;
    var hex: [constants.store_digest_hex_bytes]u8 = undefined;
    // Cannot fail: two digits.
    _ = std.fmt.bufPrint(hex[0..2], "{x:0>2}", .{shard}) catch unreachable;
    @memcpy(hex[2..], name);
    return Digest.from_hex(&hex);
}

/// The name `<62 digits>.chunks` is the chunk list of the object `<62 digits>`.
pub fn list_base(name: []const u8) ?[]const u8 {
    assert(name.len <= constants.store_name_bytes_max);
    assert(layout.chunks_suffix.len == 7);
    const suffix = layout.chunks_suffix;
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    return name[0 .. name.len - suffix.len];
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;
const host_sim = @import("../host_sim.zig");
const fs_sim = @import("fs_sim.zig");

var test_host: host_sim.HostSim = undefined;
var test_files: fs_sim.SimFs = undefined;

test "a shard lists in byte order, a missing one is empty, and names map to ids" {
    // Goal: the order a plan hash relies on. Method: names in an arbitrary creation order.
    test_host.init(1, &.{});
    test_files.init(1);
    test_host.store_fs = &test_files;
    test_files.put_dir("/s", 0o755);
    test_files.put_dir("/s/objects", 0o755);
    test_files.put_dir("/s/objects/0a", 0o755);
    const base = repeat('b', 62);
    const first = repeat('a', 62);
    const bad = repeat('g', 62);
    test_files.put_file("/s/objects/0a/" ++ base ++ ".chunks", 0o644, "");
    test_files.put_file("/s/objects/0a/" ++ base, 0o644, "");
    test_files.put_file("/s/objects/0a/" ++ first, 0o644, "");
    var store: Store = undefined;
    store.at(test_host.interface(), "/s");
    var bytes: [1024]u8 = undefined;
    var offsets: [8]u32 = undefined;
    const found = try read(&store, &bytes, &offsets, "objects", 0x0a);
    try testing.expectEqual(@as(u32, 3), found.count());
    try testing.expectEqualStrings(first, found.name(0));
    try testing.expectEqualStrings(base, found.name(1));
    try testing.expectEqualStrings(base ++ ".chunks", found.name(2));
    const none = try read(&store, &bytes, &offsets, "objects", 0x0b);
    try testing.expectEqual(@as(u32, 0), none.count());
    const id = id_of(0x0a, base).?;
    try testing.expectEqualStrings("0a" ++ base, &id.hex());
    try testing.expect(id_of(0x0a, base ++ ".chunks") == null);
    try testing.expect(id_of(0x0a, bad) == null);
    try testing.expectEqualStrings(base, list_base(base ++ ".chunks").?);
    try testing.expect(list_base(base) == null);
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.FileTooLarge, read(&store, &tiny, &offsets, "objects", 0x0a));
}
