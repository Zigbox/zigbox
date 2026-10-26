//! A set of digests with a number each, in memory the caller owns: open addressing with linear
//! probing over a power-of-two table, never growing. A digest is already a hash, so its first
//! eight bytes are the slot. `put` says when the table is full (three quarters), and the caller
//! refuses with a message that names the limit; nothing is allocated and nothing is cut.

const std = @import("std");
const assert = std.debug.assert;
const digest_mod = @import("digest.zig");

const Digest = digest_mod.Digest;

pub const Slot = struct {
    digest: Digest,
    value: u64,
    used: bool,
    /// Free for the caller: `du` marks the objects other roots share.
    mark: bool,
};

pub const Put = enum { inserted, present, full };

pub const DigestMap = struct {
    slots: []Slot,
    count: u32,

    /// Carves the table out of `memory`: the largest power of two of slots that fits.
    pub fn init(memory: []align(8) u8) DigestMap {
        assert(@alignOf(Slot) <= 8);
        assert(memory.len >= @sizeOf(Slot) * 4);
        var capacity: usize = 4;
        while (capacity * 2 * @sizeOf(Slot) <= memory.len) capacity *= 2;
        const slots: []Slot = @alignCast(
            std.mem.bytesAsSlice(Slot, memory[0 .. capacity * @sizeOf(Slot)]),
        );
        for (slots) |*slot| slot.used = false;
        return .{ .slots = slots, .count = 0 };
    }

    fn start(map: *const DigestMap, digest: Digest) usize {
        assert(std.math.isPowerOfTwo(map.slots.len));
        assert(map.slots.len > map.count);
        const hash = std.mem.readInt(u64, digest.bytes[0..8], .little);
        return @intCast(hash & (map.slots.len - 1));
    }

    /// Adds `digest` with `value` unless it is there (then the value is not changed).
    pub fn put(map: *DigestMap, digest: Digest, value: u64) Put {
        assert(map.count < map.slots.len);
        assert(std.math.isPowerOfTwo(map.slots.len));
        if (map.get(digest) != null) return .present;
        if ((map.count + 1) * 4 > map.slots.len * 3) return .full;
        var at = map.start(digest);
        while (map.slots[at].used) at = (at + 1) & (map.slots.len - 1);
        map.slots[at] = .{ .digest = digest, .value = value, .used = true, .mark = false };
        map.count += 1;
        return .inserted;
    }

    pub fn get(map: *const DigestMap, digest: Digest) ?*Slot {
        assert(map.count < map.slots.len);
        assert(std.math.isPowerOfTwo(map.slots.len));
        var at = map.start(digest);
        var probes: usize = 0;
        // The table is never full (`put` stops at three quarters), so an empty slot ends the run.
        while (probes < map.slots.len) : (probes += 1) {
            const slot = &map.slots[at];
            if (!slot.used) return null;
            if (slot.digest.eql(digest)) return slot;
            at = (at + 1) & (map.slots.len - 1);
        }
        unreachable; // A table with an empty slot always ends the probe.
    }
};

const testing = std.testing;

test "a map keeps what it is given, refuses a repeat, and says when it is full" {
    // Goal: the table's contract. Method: fill a small table to its limit with digests of
    // numbers, look each up, add a repeat, and add one more.
    var memory: [@sizeOf(Slot) * 16]u8 align(8) = undefined;
    var map = DigestMap.init(&memory);
    try testing.expectEqual(@as(usize, 16), map.slots.len);
    var index: u8 = 0;
    while (map.count * 4 < 12 - 3) : (index += 1) {
        const digest = Digest.of(&.{index});
        try testing.expectEqual(Put.inserted, map.put(digest, index));
    }
    for (0..index) |at| {
        const digest = Digest.of(&.{@as(u8, @intCast(at))});
        try testing.expectEqual(@as(u64, at), map.get(digest).?.value);
        try testing.expectEqual(Put.present, map.put(digest, 99));
        try testing.expectEqual(@as(u64, at), map.get(digest).?.value);
    }
    try testing.expect(map.get(Digest.of("absent")) == null);
    var more: u8 = 100;
    while (map.put(Digest.of(&.{more}), 0) == .inserted) more += 1;
    try testing.expectEqual(Put.full, map.put(Digest.of("one more"), 0));
    try testing.expectEqual(@as(u32, 12), map.count);
}
