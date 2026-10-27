//! The `tree` fuzzer: the canonical tree encoding and its decoder (`store/tree.zig`), and the
//! attribute section (`store/xattrs.zig`).
//!
//! Properties, each checked every iteration:
//!   1. A tree built from random entries (sorted, unique names; every kind; attributes) decodes
//!      to exactly those entries, and `round_trips` holds for its bytes.
//!   2. Canonicality: for any bytes at all (random, or a valid tree with a byte changed, cut,
//!      inserted or swapped), either the decoder refuses them, or encoding what it decoded gives
//!      the same bytes back. So there is one encoding of a directory and the digest means it.
//!   3. The decoder never reads outside its input: the only evidence is that it does not crash,
//!      which this runner (ReleaseSafe, bounds checks on) turns into a failure.
//!   4. An attribute section from the builder always validates, whatever order it was given
//!      in, and `section_length` accepts a prefix exactly when `validate` accepts it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Digest = @import("store/digest.zig").Digest;
const tree = @import("store/tree.zig");
const xattrs = @import("store/xattrs.zig");

const buffer_bytes: u32 = 16 * 1024;
const entries_max: u32 = 12;

const Planned = struct {
    name: [8]u8,
    name_len: u8,
    kind: tree.Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    target_len: u8,
    blob: [constants.store_xattr_blob_bytes_max]u8,
    blob_len: u32,
};

var builder: xattrs.Builder = undefined;
var planned: [entries_max]Planned = undefined;
var bytes: [buffer_bytes]u8 = undefined;
var other: [buffer_bytes]u8 = undefined;
var mutated: [buffer_bytes]u8 = undefined;
var own: tree.Own = undefined;
var own_blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
var own_attrs_len: u32 = 0;

/// Names come from a small alphabet so that duplicates and order matter; they are sorted and
/// made unique here, as the importer's sort does.
fn plan_entries(random: std.Random) u32 {
    var names: [entries_max][8]u8 = undefined;
    var lengths: [entries_max]u8 = undefined;
    var count: u32 = 0;
    const wanted = random.uintAtMost(u32, entries_max);
    var tries: u32 = 0;
    while (count < wanted and tries < 64) : (tries += 1) {
        const length = random.intRangeAtMost(u8, 1, 3);
        var name: [8]u8 = @splat(0);
        for (name[0..length]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'd');
        var seen = false;
        for (0..count) |at| {
            const same = lengths[at] == length and std.mem.eql(
                u8,
                names[at][0..length],
                name[0..length],
            );
            if (same) seen = true;
        }
        if (seen) continue;
        names[count] = name;
        lengths[count] = length;
        count += 1;
    }
    // Sorted by bytes, as a tree requires: insertion sort on the small array.
    for (1..@max(count, 1)) |at| {
        var back = at;
        while (back > 0 and std.mem.lessThan(
            u8,
            names[back][0..lengths[back]],
            names[back - 1][0..lengths[back - 1]],
        )) : (back -= 1) {
            std.mem.swap([8]u8, &names[back], &names[back - 1]);
            std.mem.swap(u8, &lengths[back], &lengths[back - 1]);
        }
    }
    for (0..count) |at| {
        const item = &planned[at];
        item.name = names[at];
        item.name_len = lengths[at];
        item.kind = switch (random.uintLessThan(u8, 3)) {
            0 => .file,
            1 => .dir,
            else => .symlink,
        };
        item.mode = random.uintAtMost(u16, 0o7777);
        item.uid = random.uintLessThan(u32, std.math.maxInt(u32));
        item.gid = random.uintLessThan(u32, std.math.maxInt(u32));
        item.size = random.uintAtMost(u64, constants.store_file_bytes_max);
        item.target_len = random.intRangeAtMost(u8, 1, 40);
        item.blob_len = plan_attributes(random, &item.blob);
    }
    return count;
}

fn plan_attributes(random: std.Random, out: *[constants.store_xattr_blob_bytes_max]u8) u32 {
    builder.reset();
    const wanted = random.uintAtMost(u32, 4);
    for (0..wanted) |_| {
        var name: [8]u8 = undefined;
        const length = random.intRangeAtMost(usize, 1, 6);
        for (name[0..length]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'c');
        var value: [16]u8 = undefined;
        random.bytes(&value);
        // A repeated name is the file system's impossibility: skip it as the importer would not
        // see it.
        var repeated = false;
        for (0..builder.count) |at| {
            const item = builder.items[at];
            if (std.mem.eql(u8, builder.names[item.name_at..][0..item.name_len], name[0..length])) {
                repeated = true;
            }
        }
        if (repeated) continue;
        builder.add(name[0..length], value[0..random.uintAtMost(usize, value.len)]) catch
            unreachable; // Few.
    }
    const section = builder.finish(out);
    assert(xattrs.validate(section) == .none);
    return @intCast(section.len);
}

fn encode(count: u32, random: std.Random, out: []u8) []const u8 {
    own = tree.Own.none;
    var writer = tree.Writer.init(out);
    for (planned[0..count]) |*item| {
        const attributes = item.blob[0..item.blob_len];
        writer.begin(
            item.name[0..item.name_len],
            item.kind,
            item.mode,
            item.uid,
            item.gid,
            attributes,
        ) catch
            unreachable; // Small.
        switch (item.kind) {
            .file => writer.end_file(
                item.size,
                Digest.of(item.name[0..item.name_len]),
                Digest.of(&.{item.name_len}),
            ) catch
                unreachable, // Small.
            .dir => writer.end_dir(Digest.of(&.{random.int(u8)})) catch unreachable, // Small.
            .symlink => {
                var target: [40]u8 = @splat('t');
                writer.end_symlink(target[0..item.target_len]) catch unreachable; // Small.
            },
        }
    }
    // The root's own section is random too; the subtree case (none) is `finish`.
    if (random.boolean()) return writer.finish();
    own_attrs_len = plan_attributes(random, &own_blob);
    own = .{
        .mode = random.uintAtMost(u16, 0o7777),
        .uid = random.int(u32) -| 1,
        .gid = random.int(u32) -| 1,
        .xattrs = own_blob[0..own_attrs_len],
    };
    return writer.finish_with(own) catch unreachable; // Small.
}

/// Property 1.
fn check_planned(count: u32, encoded: []const u8) void {
    var decoder: tree.Decoder = undefined;
    decoder.init(encoded) catch unreachable; // A tree the writer made.
    var entry: tree.Entry = undefined;
    for (planned[0..count]) |*item| {
        const more = decoder.next(&entry) catch unreachable; // Same.
        assert(more);
        assert(std.mem.eql(u8, entry.name, item.name[0..item.name_len]));
        assert(entry.kind == item.kind);
        assert(entry.mode == item.mode);
        assert(entry.uid == item.uid);
        assert(entry.gid == item.gid);
        assert(std.mem.eql(u8, entry.xattrs, item.blob[0..item.blob_len]));
        if (item.kind == .file) assert(entry.size == item.size);
        if (item.kind == .symlink) assert(entry.target.len == item.target_len);
    }
    assert(!(decoder.next(&entry) catch unreachable)); // Same.
    assert(decoder.own.mode == own.mode);
    assert(decoder.own.uid == own.uid);
    assert(decoder.own.gid == own.gid);
    assert(std.mem.eql(u8, decoder.own.xattrs, own.xattrs));
    assert(tree.round_trips(encoded, &other));
}

/// Property 2, on a copy of `encoded` with one random change.
fn mutate(random: std.Random, encoded: []const u8) []const u8 {
    @memcpy(mutated[0..encoded.len], encoded);
    var length = encoded.len;
    switch (random.uintLessThan(u8, 5)) {
        0 => if (length > 0) {
            mutated[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
        },
        1 => if (length > 0) {
            mutated[random.uintLessThan(usize, length)] = random.int(u8);
        },
        2 => length = random.uintAtMost(usize, length),
        3 => if (length + 1 < mutated.len) {
            const at = random.uintAtMost(usize, length);
            std.mem.copyBackwards(u8, mutated[at + 1 .. length + 1], mutated[at..length]);
            mutated[at] = random.int(u8);
            length += 1;
        },
        else => if (length > 1) {
            const first = random.uintLessThan(usize, length);
            const second = random.uintLessThan(usize, length);
            std.mem.swap(u8, &mutated[first], &mutated[second]);
        },
    }
    return mutated[0..length];
}

fn check_attributes(random: std.Random) void {
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    const length = plan_attributes(random, &blob);
    var shuffled: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    // The same attributes added in the opposite order give the same section.
    var iterator = xattrs.Iterator.init(blob[0..length]);
    var items: [8]xattrs.Xattr = undefined;
    var count: u32 = 0;
    while (iterator.next()) |item| {
        items[count] = item;
        count += 1;
    }
    builder.reset();
    var at = count;
    while (at > 0) : (at -= 1) builder.add(items[at - 1].name, items[at - 1].value) catch
        unreachable; // Few.
    assert(std.mem.eql(u8, builder.finish(&shuffled), blob[0..length]));
    // A damaged section: `section_length` accepts the prefix exactly when `validate` does.
    var damaged: [64]u8 = undefined;
    random.bytes(&damaged);
    damaged[0] &= 0x03;
    const prefix = random.uintAtMost(usize, damaged.len);
    if (prefix == 0) return;
    const found = xattrs.section_length(damaged[0..prefix]);
    if (found) |whole| assert(xattrs.validate(damaged[0..whole]) == .none);
}

pub fn fuzz_tree(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const count = plan_entries(random);
    const encoded = encode(count, random, &bytes);
    check_planned(count, encoded);
    for (0..8) |_| {
        const changed = mutate(random, encoded);
        assert(tree.round_trips(changed, &other));
    }
    // Garbage with the right first byte gets past the version check, which is where the
    // interesting parsing starts.
    const garbage_len = random.uintAtMost(usize, 200);
    random.bytes(mutated[0..garbage_len]);
    if (garbage_len > 0 and random.boolean()) mutated[0] = constants.store_tree_version;
    assert(tree.round_trips(mutated[0..garbage_len], &other));
    check_attributes(random);
}
