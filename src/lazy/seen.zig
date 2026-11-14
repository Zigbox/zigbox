//! The set of trees and objects a walk has already met, with a number kept for each: the index's
//! writer and its checker both list a tree or an object at its first appearance only, and skip it
//! after. Fixed size, sized for `lazy_nodes_max`: every tree but the root and every object has a
//! name in the tree, so a tree within the bound has at most `lazy_nodes_max + 1` of them, and the
//! table is never more than about half full.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Digest = @import("../store/digest.zig").Digest;

pub const entries_max: u32 = constants.lazy_nodes_max + 1;
pub const slots_count: u32 = 1 << 19;

comptime {
    assert(std.math.isPowerOfTwo(slots_count));
    // At most half full, but for the root's one extra entry.
    assert(slots_count >= 2 * entries_max - 2);
}

pub const Kind = enum(u8) { empty = 0, tree = 1, object = 2 };

const Slot = struct {
    digest: Digest,
    value: u32,
    kind: Kind,
};

/// About 20 MiB; kept by the caller and reset before each walk.
pub const Seen = struct {
    slots: [slots_count]Slot,
    count: u32,

    pub fn reset(seen: *Seen) void {
        assert(seen.slots.len == slots_count);
        for (&seen.slots) |*slot| slot.kind = .empty;
        seen.count = 0;
        assert(seen.count == 0);
    }

    fn home(digest: Digest) u32 {
        assert(slots_count > entries_max);
        assert(digest.bytes.len >= 4);
        return std.mem.readInt(u32, digest.bytes[0..4], .little) & (slots_count - 1);
    }

    /// The slot holding (`kind`, `digest`), or the empty slot where it would go.
    fn find(seen: *Seen, kind: Kind, digest: Digest) *Slot {
        assert(kind != .empty);
        assert(seen.count < slots_count);
        var index = home(digest);
        while (true) : (index = (index + 1) & (slots_count - 1)) {
            const slot = &seen.slots[index];
            if (slot.kind == .empty) return slot;
            if (slot.kind == kind and slot.digest.eql(digest)) return slot;
        }
    }

    pub fn get(seen: *Seen, kind: Kind, digest: Digest) ?u32 {
        assert(kind != .empty);
        const slot = seen.find(kind, digest);
        if (slot.kind == .empty) return null;
        assert(slot.kind == kind);
        return slot.value;
    }

    /// Adds a new entry; false when the set holds `entries_max` already.
    pub fn add(seen: *Seen, kind: Kind, digest: Digest, value: u32) bool {
        assert(kind != .empty);
        assert(seen.count <= entries_max);
        if (seen.count == entries_max) return false;
        const slot = seen.find(kind, digest);
        assert(slot.kind == .empty);
        slot.* = .{ .digest = digest, .value = value, .kind = kind };
        seen.count += 1;
        return true;
    }

    /// Changes the value of an entry that is there.
    pub fn set(seen: *Seen, kind: Kind, digest: Digest, value: u32) void {
        assert(kind != .empty);
        const slot = seen.find(kind, digest);
        assert(slot.kind == kind);
        slot.value = value;
    }
};

test "the set holds entries_max entries and refuses one more" {
    const seen = try std.testing.allocator.create(Seen);
    defer std.testing.allocator.destroy(seen);
    seen.reset();
    var digest: Digest = .{ .bytes = @splat(0) };
    for (0..entries_max) |number| {
        std.mem.writeInt(u64, digest.bytes[0..8], number, .little);
        try std.testing.expect(seen.add(.object, digest, @intCast(number)));
    }
    std.mem.writeInt(u64, digest.bytes[0..8], entries_max, .little);
    try std.testing.expect(!seen.add(.object, digest, 0));
    try std.testing.expectEqual(null, seen.get(.object, digest));
    std.mem.writeInt(u64, digest.bytes[0..8], 7, .little);
    try std.testing.expectEqual(7, seen.get(.object, digest).?);
    try std.testing.expectEqual(null, seen.get(.tree, digest));
    seen.set(.object, digest, 9);
    try std.testing.expectEqual(9, seen.get(.object, digest).?);
}
