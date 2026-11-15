//! The `chaining` fuzzer: `zig build fuzz -- chaining`. Each iteration takes random bytes of a
//! random length and a random run size (a power of two from one BLAKE3 piece to 64 pieces), cuts
//! the bytes into runs at multiples of the run size, hashes each run to its chaining value with
//! `Subtree` fed in random slices, and checks:
//!
//!   1. The runs' values joined by `Joiner` (or a lone run's root) are std's BLAKE3 of the whole.
//!   2. `run_value` gives each run the same value as the sliced `Subtree`.
//!   3. A run value with one bit flipped, or two runs' differing values swapped, joins to another
//!      hash: what lets `verify` refuse a forged chunk value (`E1202`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const chaining = @import("lazy/chaining.zig");
const Digest = @import("store/digest.zig").Digest;

const runs_max: u32 = constants.fuzz_chaining_bytes_max / chaining.piece_bytes;
const run_shift_max: u32 = 6;

var input: [constants.fuzz_chaining_bytes_max]u8 = undefined;
var values: [runs_max]Digest = undefined;

comptime {
    assert(constants.fuzz_chaining_bytes_max % chaining.piece_bytes == 0);
    assert(runs_max >= 2);
}

pub fn fuzz_chaining(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const run_bytes = chaining.piece_bytes << @intCast(random.uintAtMost(u32, run_shift_max));
    const length_max: u32 = if (random.uintLessThan(u32, 8) == 0)
        constants.fuzz_chaining_bytes_max
    else
        @min(constants.fuzz_chaining_bytes_max, 8 * run_bytes);
    const length = random.intRangeAtMost(u32, 1, length_max);
    const bytes = input[0..length];
    fill(random, bytes);
    const count = std.math.divCeil(u32, length, run_bytes) catch unreachable; // Not zero.
    assert(count >= 1);
    assert(count <= runs_max);
    const whole = Digest.of(bytes);
    if (count == 1) {
        var subtree: chaining.Subtree = undefined;
        subtree.init(0, run_bytes);
        feed(random, &subtree, bytes);
        assert(subtree.final(true).eql(whole));
        return;
    }
    for (0..count) |ordinal| {
        const run = bytes[ordinal * run_bytes .. @min(length, (ordinal + 1) * run_bytes)];
        var subtree: chaining.Subtree = undefined;
        subtree.init(ordinal, run_bytes);
        feed(random, &subtree, run);
        values[ordinal] = subtree.final(false);
        assert(values[ordinal].eql(chaining.run_value(run, ordinal, run_bytes)));
    }
    assert(join(values[0..count]).eql(whole));
    forge(random, values[0..count], whole);
}

/// Random bytes, sometimes runs of one byte, so equal pieces (and equal run values) happen.
fn fill(random: std.Random, bytes: []u8) void {
    assert(bytes.len >= 1);
    assert(bytes.len <= constants.fuzz_chaining_bytes_max);
    switch (random.uintLessThan(u32, 3)) {
        0 => random.bytes(bytes),
        1 => @memset(bytes, random.int(u8)),
        else => for (bytes, 0..) |*byte, at| {
            byte.* = @truncate(at / chaining.piece_bytes);
        },
    }
}

/// Feeds `bytes` to `subtree` in slices of random lengths, some across block and piece edges.
fn feed(random: std.Random, subtree: *chaining.Subtree, bytes: []const u8) void {
    assert(bytes.len >= 1);
    assert(subtree.total == 0);
    var at: usize = 0;
    while (at < bytes.len) {
        const slice = random.intRangeAtMost(usize, 1, 3 * chaining.piece_bytes);
        const take = @min(bytes.len - at, slice);
        subtree.update(bytes[at..][0..take]);
        at += take;
    }
    assert(subtree.total == bytes.len);
}

fn join(runs: []const Digest) Digest {
    assert(runs.len >= 2);
    assert(runs.len <= runs_max);
    var joiner = chaining.Joiner.init();
    for (runs[0 .. runs.len - 1]) |*value| joiner.add(value);
    return joiner.root(&runs[runs.len - 1]);
}

/// A flipped bit in one run's value, and a swap of two differing values, join to another hash.
fn forge(random: std.Random, runs: []Digest, whole: Digest) void {
    assert(runs.len >= 2);
    assert(join(runs).eql(whole));
    const victim = random.uintLessThan(usize, runs.len);
    const bit = random.uintLessThan(u32, 256);
    runs[victim].bytes[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    assert(!join(runs).eql(whole));
    runs[victim].bytes[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    const left = random.uintLessThan(usize, runs.len);
    const right = random.uintLessThan(usize, runs.len);
    if (runs[left].eql(runs[right])) return;
    std.mem.swap(Digest, &runs[left], &runs[right]);
    assert(!join(runs).eql(whole));
    std.mem.swap(Digest, &runs[left], &runs[right]);
}
