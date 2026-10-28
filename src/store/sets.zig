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

/// A set of digests in sixteen bytes a slot: the first 128 bits of each digest, zero meaning an
/// empty slot. Two digests that agree in 128 bits are taken for one, which for a set that only
/// answers "keep it?" can only keep something that could have gone; the chance is 2^-128 per
/// pair, and the digests are hashes. It is `DigestMap` for what a gc needs, in a third of the
/// memory, which is what lets the sets of a big store fit.
pub const KeySet = struct {
    pub const Key = [2]u64;

    slots: []Key,
    count: u32,

    /// Carves the table out of `memory`: the largest power of two of slots that fits, cleared.
    pub fn init(memory: []align(8) u8) KeySet {
        assert(@alignOf(Key) <= 8);
        assert(memory.len >= @sizeOf(Key) * 4);
        var capacity: usize = 4;
        while (capacity * 2 * @sizeOf(Key) <= memory.len) capacity *= 2;
        const slots: []Key = @alignCast(
            std.mem.bytesAsSlice(Key, memory[0 .. capacity * @sizeOf(Key)]),
        );
        @memset(slots, .{ 0, 0 });
        return .{ .slots = slots, .count = 0 };
    }

    fn key_of(digest: Digest) Key {
        const high = std.mem.readInt(u64, digest.bytes[8..16], .little);
        const low = std.mem.readInt(u64, digest.bytes[0..8], .little);
        // The all-zero key is the empty slot; a digest that would be it is another key.
        if (low == 0 and high == 0) return .{ 0, 1 };
        return .{ low, high };
    }

    fn start(set: *const KeySet, key: Key) usize {
        assert(std.math.isPowerOfTwo(set.slots.len));
        assert(set.slots.len > set.count);
        return @intCast(key[0] & (set.slots.len - 1));
    }

    /// Adds `digest` unless it is there. `value` is ignored (the call matches `DigestMap.put`,
    /// so a walk takes either).
    pub fn put(set: *KeySet, digest: Digest, value: u64) Put {
        assert(set.count < set.slots.len);
        _ = value;
        const key = key_of(digest);
        if (set.get(digest) != null) return .present;
        if ((set.count + 1) * 4 > set.slots.len * 3) return .full;
        var at = set.start(key);
        while (set.slots[at][0] != 0 or set.slots[at][1] != 0) at = (at + 1) & (set.slots.len - 1);
        set.slots[at] = key;
        set.count += 1;
        return .inserted;
    }

    pub fn get(set: *const KeySet, digest: Digest) ?void {
        assert(set.count < set.slots.len);
        const key = key_of(digest);
        var at = set.start(key);
        var probes: usize = 0;
        // The table is never full (`put` stops at three quarters), so an empty slot ends the run.
        while (probes < set.slots.len) : (probes += 1) {
            const slot = set.slots[at];
            if (slot[0] == 0 and slot[1] == 0) return null;
            if (slot[0] == key[0] and slot[1] == key[1]) return {};
            at = (at + 1) & (set.slots.len - 1);
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

test "a key set keeps what it is given, says when it is full, and starts clear" {
    // Goal: the contract of the gc's set: membership, no duplicates, the three-quarter limit, a
    // table cleared on init whatever the memory held, and the all-zero digest as a key.
    var memory: [@sizeOf(KeySet.Key) * 16]u8 align(8) = undefined;
    @memset(&memory, 0xff);
    var set = KeySet.init(&memory);
    try testing.expectEqual(@as(usize, 16), set.slots.len);
    try testing.expect(set.get(Digest.of("x")) == null);
    var index: u8 = 0;
    while (set.put(Digest.of(&.{index}), 0) == .inserted) index += 1;
    try testing.expectEqual(@as(u32, 12), set.count);
    for (0..index) |at| try testing.expect(set.get(Digest.of(&.{@as(u8, @intCast(at))})) != null);
    try testing.expectEqual(Put.present, set.put(Digest.of(&.{0}), 0));
    var other = KeySet.init(&memory);
    const zero: Digest = .{ .bytes = @splat(0) };
    try testing.expectEqual(Put.inserted, other.put(zero, 0));
    try testing.expect(other.get(zero) != null);
    try testing.expect(other.get(Digest.of("y")) == null);
}
