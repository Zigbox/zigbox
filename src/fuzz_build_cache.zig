//! The `build_cache` fuzzer: `zig build fuzz -- build_cache`. A build cache entry is read from
//! disk that anything may have written. Each iteration renders an entry for a random key and
//! tree, parses it, then damages the bytes (flip, truncate, extend, splice, noise) and parses
//! those.
//!
//! Properties, every iteration:
//!   1. What `render` wrote parses, under the key's digest as the name, to the same tree and
//!      preimage, and rendering that again gives the same bytes.
//!   2. Damaged bytes never crash the reader. Whatever it still accepts (`ok`) renders back to
//!      exactly the damaged bytes: it accepts only what `render` writes.
//!   3. The same bytes under another name never parse `ok`: the name is the preimage's hash.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const cache = @import("build/cache.zig");
const key_mod = @import("build/key.zig");
const Digest = @import("store/digest.zig").Digest;

var key: key_mod.Key = undefined;
var rendered: [constants.build_cache_entry_bytes_max]u8 = undefined;
var again: [constants.build_cache_entry_bytes_max]u8 = undefined;
var damaged: [constants.build_cache_entry_bytes_max]u8 = undefined;

fn random_digest(random: std.Random) Digest {
    var digest: Digest = undefined;
    random.bytes(&digest.bytes);
    assert(digest.bytes.len == constants.store_digest_bytes);
    assert(@intFromPtr(&digest) != 0);
    return digest;
}

const names = [_][]const u8{ "a", "build", "step-2", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" };
const argvs = [_][]const []const u8{ &.{"true"}, &.{ "sh", "-c", "echo hi" }, &.{ "go", "build" } };

fn make_key(random: std.Random) void {
    const spec: key_mod.Spec = .{
        .platform = if (random.boolean()) "linux/amd64" else "linux/arm64",
        .base_tree = random_digest(random),
        .base_env = &.{"PATH=/bin"},
        .input_tree = random_digest(random),
        .needs = &.{},
        .argv = argvs[random.uintLessThan(usize, argvs.len)],
        .env = if (random.boolean()) &.{"A=1"} else &.{},
        .network = random.boolean(),
        .name = names[random.uintLessThan(usize, names.len)],
    };
    key_mod.compute(&spec, &key) catch unreachable; // A small spec.
    assert(key.len <= constants.build_key_preimage_bytes_max);
    assert(key.len > key_mod.magic.len);
}

/// Damages a copy of `bytes` in `damaged` and returns the result.
fn damage(random: std.Random, bytes: []const u8) []const u8 {
    assert(bytes.len <= damaged.len);
    assert(bytes.len > 0);
    @memcpy(damaged[0..bytes.len], bytes);
    var length = bytes.len;
    const rounds = random.intRangeAtMost(u32, 1, 4);
    for (0..rounds) |_| {
        if (length == 0) break;
        switch (random.uintLessThan(u8, 5)) {
            0 => damaged[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
            1 => length = random.uintLessThan(usize, length + 1),
            2 => {
                if (length < damaged.len) {
                    damaged[length] = random.int(u8);
                    length += 1;
                }
            },
            3 => damaged[random.uintLessThan(usize, length)] = random.int(u8),
            else => {
                const at = random.uintLessThan(usize, length);
                const count = @min(length - at, random.intRangeAtMost(usize, 1, 8));
                for (at..at + count) |index| damaged[index] = random.int(u8);
            },
        }
    }
    return damaged[0..length];
}

fn check_damaged(random: std.Random, bytes: []const u8) void {
    var entry: cache.Entry = undefined;
    switch (cache.parse(bytes, key.digest, &entry)) {
        .ok => {
            const text = cache.render(&again, entry.tree, entry.preimage);
            assert(std.mem.eql(u8, text, bytes));
            assert(std.mem.eql(u8, entry.preimage, key.preimage()));
            var other = key.digest;
            other.bytes[random.uintLessThan(usize, other.bytes.len)] ^= 1;
            assert(cache.parse(bytes, other, &entry) != .ok);
        },
        .malformed, .newer => {},
    }
}

pub fn fuzz_build_cache(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    make_key(random);
    const tree = random_digest(random);
    const text = cache.render(&rendered, tree, key.preimage());
    var entry: cache.Entry = undefined;
    assert(cache.parse(text, key.digest, &entry) == .ok);
    assert(entry.tree.eql(tree));
    assert(std.mem.eql(u8, entry.preimage, key.preimage()));
    assert(std.mem.eql(u8, cache.render(&again, entry.tree, entry.preimage), text));
    for (0..64) |_| check_damaged(random, damage(random, text));
    var noise: [96]u8 = undefined;
    random.bytes(&noise);
    check_damaged(random, noise[0..random.uintLessThan(usize, noise.len + 1)]);
}
