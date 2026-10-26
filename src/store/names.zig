//! The names in a directory, collected into memory the caller owns: each is a length byte and
//! the bytes, one after another, so a directory of any size costs only its names. A visitor
//! (`fs.Visitor`) fills it; the caller then sorts a list of offsets and walks them in name order.
//!
//! Limits are flags, not errors, because the visitor cannot return one: `full` (the memory ran
//! out), `too_many` (more than the limit asked for) and `too_long` (a name over 255 bytes). The
//! caller checks them after the listing and refuses with a message that names the directory.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const fs_mod = @import("fs.zig");

pub const NameList = struct {
    bytes: []u8,
    used: u32,
    count: u32,
    limit: u32,
    full: bool,
    too_many: bool,
    too_long: bool,

    pub fn init(bytes: []u8, limit: u32) NameList {
        assert(bytes.len < std.math.maxInt(u32));
        assert(limit > 0);
        return .{
            .bytes = bytes,
            .used = 0,
            .count = 0,
            .limit = limit,
            .full = false,
            .too_many = false,
            .too_long = false,
        };
    }

    pub fn visitor(list: *NameList) fs_mod.Visitor {
        assert(list.count <= list.limit);
        assert(list.used <= list.bytes.len);
        return .{ .context = list, .call = visit };
    }

    fn visit(context: *anyopaque, name: []const u8) void {
        assert(name.len > 0);
        assert(@intFromPtr(context) != 0);
        const list: *NameList = @ptrCast(@alignCast(context));
        list.add(name);
    }

    pub fn add(list: *NameList, name: []const u8) void {
        assert(list.used <= list.bytes.len);
        assert(name.len > 0);
        if (name.len > constants.store_name_bytes_max) {
            list.too_long = true;
            return;
        }
        if (list.count == list.limit) {
            list.too_many = true;
            return;
        }
        if (list.used + 1 + name.len > list.bytes.len) {
            list.full = true;
            return;
        }
        list.bytes[list.used] = @intCast(name.len);
        @memcpy(list.bytes[list.used + 1 ..][0..name.len], name);
        list.used += @intCast(1 + name.len);
        list.count += 1;
    }

    /// True if nothing was refused.
    pub fn complete(list: *const NameList) bool {
        assert(list.count <= list.limit);
        assert(list.used <= list.bytes.len);
        return !list.full and !list.too_many and !list.too_long;
    }

    /// The name stored at `offset` (an offset from `sorted`).
    pub fn at(list: *const NameList, offset: u32) []const u8 {
        assert(offset < list.used);
        const length = list.bytes[offset];
        assert(offset + 1 + length <= list.used);
        return list.bytes[offset + 1 ..][0..length];
    }

    /// Fills `offsets` (at least `count` of them) with the offsets of the names in byte order.
    pub fn sorted(list: *const NameList, offsets: []u32) []const u32 {
        assert(offsets.len >= list.count);
        var at_offset: u32 = 0;
        for (0..list.count) |index| {
            offsets[index] = at_offset;
            at_offset += 1 + list.bytes[at_offset];
        }
        assert(at_offset == list.used);
        std.mem.sortUnstable(u32, offsets[0..list.count], list, offset_less);
        return offsets[0..list.count];
    }

    fn offset_less(list: *const NameList, first: u32, second: u32) bool {
        assert(first < list.used);
        assert(second < list.used);
        return std.mem.lessThan(u8, list.at(first), list.at(second));
    }
};

const testing = std.testing;

test "names are kept whole, sorted by bytes, and the limits are flags" {
    // Goal: the collector's contract. Method: names in a shuffled order, then each limit.
    var storage: [64]u8 = undefined;
    var list = NameList.init(&storage, 4);
    for ([_][]const u8{ "b", "a", "ab", "B" }) |name| list.add(name);
    try testing.expect(list.complete());
    var offsets: [4]u32 = undefined;
    const order = list.sorted(&offsets);
    try testing.expectEqualStrings("B", list.at(order[0]));
    try testing.expectEqualStrings("a", list.at(order[1]));
    try testing.expectEqualStrings("ab", list.at(order[2]));
    try testing.expectEqualStrings("b", list.at(order[3]));
    list.add("e");
    try testing.expect(list.too_many);
    var small: [4]u8 = undefined;
    var tight = NameList.init(&small, 10);
    tight.add("abc");
    try testing.expect(tight.complete());
    tight.add("d");
    try testing.expect(tight.full);
    var wide: [1024]u8 = undefined;
    var long = NameList.init(&wide, 10);
    long.add(@import("../test_util.zig").repeat('x', constants.store_name_bytes_max + 1));
    try testing.expect(long.too_long);
    try testing.expectEqual(@as(u32, 0), long.count);
}
