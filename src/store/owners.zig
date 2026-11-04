//! Which ids the store's files show to the process that reads them, and how to get back from
//! those to the ids a container sees, which are the ids an object id commits to.
//!
//! Every store write runs in the namespace child (`namespace.zig`), so the store records the
//! container's ids. A reader in that same namespace sees them as they are (`inside`). A reader
//! outside it, such as Zigcube's peer server, which has threads and so cannot enter the
//! namespace, sees the host ids the kernel mapped them to (`outside`) and must map each one back
//! through the store's id map before it can check an object's id. The map is the one `run`
//! writes: the container's root to the user's own id, and, with the full map, ids 1 to
//! `subid_range_min` to the user's subordinate range. A host id the map does not reach has no
//! container id; it is refused, never guessed.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Owners = union(enum) {
    /// The reader is in the store's namespace: `lstat` gives the container's ids.
    inside,
    /// The reader is outside it: `lstat` gives host ids, mapped back through this map.
    outside: Map,
};

/// The store's id map as `namespace.run` writes it, seen from the host.
pub const Map = struct {
    /// The host ids the container's root (0) maps to: the user's own.
    uid: u32,
    gid: u32,
    /// The subordinate ranges that ids 1 to `subid_range_min` map to; null for the one-id map.
    range: ?Range,
};

/// The first host id of each subordinate range; each is `subid_range_min` ids long.
pub const Range = struct {
    uid_start: u32,
    gid_start: u32,
};

pub const Kind = enum { uid, gid };

/// The container id that the host id `host_id` of the kind `kind` stands for, or null if the
/// map does not reach it.
pub fn container_id(map: *const Map, kind: Kind, host_id: u32) ?u32 {
    const own = switch (kind) {
        .uid => map.uid,
        .gid => map.gid,
    };
    // The kernel refuses a map whose host ranges overlap, so the user's own id is never also in
    // the range, and the order of these checks cannot change an answer.
    if (host_id == own) return 0;
    const range = map.range orelse return null;
    const start: u64 = switch (kind) {
        .uid => range.uid_start,
        .gid => range.gid_start,
    };
    if (host_id < start) return null;
    const offset = @as(u64, host_id) - start;
    if (offset >= constants.subid_range_min) return null;
    const id: u32 = @intCast(offset + 1);
    assert(id >= 1);
    assert(id <= constants.subid_range_min);
    return id;
}

/// The container's ids of a file whose `lstat` gave `uid` and `gid`, as `owners` says to read
/// them; null if either is outside the map.
pub fn container_ids(owners: *const Owners, uid: u32, gid: u32) ?[2]u32 {
    switch (owners.*) {
        .inside => return .{ uid, gid },
        .outside => |*map| {
            const container_uid = container_id(map, .uid, uid) orelse return null;
            const container_gid = container_id(map, .gid, gid) orelse return null;
            assert(container_uid <= constants.subid_range_min);
            assert(container_gid <= constants.subid_range_min);
            return .{ container_uid, container_gid };
        },
    }
}

const testing = std.testing;

test "the one-id map reaches only the user's own ids, as the container's root" {
    // Goal: rootless with no subordinate range. Method: the user's ids map to 0; the id one
    // below and one above, root and a typical container id do not map at all.
    const map: Map = .{ .uid = 1000, .gid = 1001, .range = null };
    try testing.expectEqual(@as(?u32, 0), container_id(&map, .uid, 1000));
    try testing.expectEqual(@as(?u32, 0), container_id(&map, .gid, 1001));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .gid, 1000));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 999));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 1001));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 0));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .gid, 42));
}

test "the full map reaches the range, from its first id to its last, and nothing past it" {
    // Goal: the range's edges. Method: the stock Ubuntu range (100000, 65536 ids long) for a
    // user, then for root, whose own id is 0: the first id is 1, the last is 65536, and one
    // below and one past are refused, as is an id in the other kind's range.
    const range: Range = .{ .uid_start = 100000, .gid_start = 300000 };
    for ([_]u32{ 1000, 0 }) |own| {
        const map: Map = .{ .uid = own, .gid = own, .range = range };
        try testing.expectEqual(@as(?u32, 0), container_id(&map, .uid, own));
        try testing.expectEqual(@as(?u32, 1), container_id(&map, .uid, 100000));
        try testing.expectEqual(@as(?u32, 42), container_id(&map, .gid, 300041));
        try testing.expectEqual(@as(?u32, 65536), container_id(&map, .uid, 165535));
        try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 165536));
        try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 99999));
        try testing.expectEqual(@as(?u32, null), container_id(&map, .gid, 100000));
        try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, 42));
    }
}

test "a range at the top of the id space does not wrap" {
    // Goal: no overflow in the arithmetic. Method: a range that starts near 2^32; the last host
    // id is container id 65536 and an id below the start is refused.
    const start: u32 = std.math.maxInt(u32) - constants.subid_range_min + 1;
    const map: Map = .{ .uid = 1000, .gid = 1000, .range = .{
        .uid_start = start,
        .gid_start = start,
    } };
    try testing.expectEqual(@as(?u32, 1), container_id(&map, .uid, start));
    try testing.expectEqual(@as(?u32, 65536), container_id(&map, .uid, std.math.maxInt(u32)));
    try testing.expectEqual(@as(?u32, null), container_id(&map, .uid, start - 1));
}

test "inside the namespace the ids are the container's already" {
    // Goal: `inside` changes nothing; `outside` needs both ids mapped. Method: one file's ids
    // through each.
    const inside: Owners = .inside;
    try testing.expectEqual([2]u32{ 7, 42 }, container_ids(&inside, 7, 42).?);
    const outside: Owners = .{ .outside = .{ .uid = 1000, .gid = 1000, .range = .{
        .uid_start = 100000,
        .gid_start = 100000,
    } } };
    try testing.expectEqual([2]u32{ 0, 42 }, container_ids(&outside, 1000, 100041).?);
    try testing.expectEqual(@as(?[2]u32, null), container_ids(&outside, 1000, 41));
    try testing.expectEqual(@as(?[2]u32, null), container_ids(&outside, 41, 1000));
}
