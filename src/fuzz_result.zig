//! The build-result fuzzer: `zig build fuzz -- result`. Each iteration makes a random record
//! (words, an env, a workdir and user, labels), encodes it, and checks that `parse` gives back
//! a record that re-encodes to the same bytes and so the same result digest. It then damages
//! the bytes (flips, a cut, a tail of garbage) and checks that `parse` never crashes, and that
//! whatever it accepts re-encodes to exactly the damaged bytes (nothing is accepted loosely).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const result = @import("build/result.zig");
const digest_mod = @import("store/digest.zig");
const images = @import("store/images.zig");

const text_bytes_max: u32 = 24;

var record: result.Record = undefined;
var parsed: result.Record = undefined;
var encoded: [constants.build_result_bytes_max]u8 = undefined;
var again: [constants.build_result_bytes_max]u8 = undefined;
var damaged: [constants.build_result_bytes_max + 16]u8 = undefined;

fn random_text(random: std.Random, out: *[text_bytes_max]u8) []const u8 {
    const length = random.uintAtMost(u32, text_bytes_max);
    random.bytes(out[0..length]);
    return out[0..length];
}

fn random_record(random: std.Random) void {
    record.config.clear();
    record.tree = digest_mod.Digest.of(std.mem.asBytes(&random.int(u64)));
    var text: [text_bytes_max]u8 = undefined;
    const lists = [_]images.Settings.List{ .entrypoint, .cmd, .env };
    for (lists) |list| {
        const count = random.uintAtMost(u32, 6);
        for (0..count) |_| _ = record.config.settings.add(list, random_text(random, &text));
    }
    _ = record.config.settings.set(.workdir, random_text(random, &text));
    _ = record.config.settings.set(.user, random_text(random, &text));
    const labels = random.uintAtMost(u32, 6);
    var value: [text_bytes_max]u8 = undefined;
    for (0..labels) |_| {
        const key = random_text(random, &text);
        _ = record.config.add_label(key, random_text(random, &value));
    }
}

/// `parse` of `bytes`, and when it accepts them, the check that `encode` gives them back.
fn check_parse(bytes: []const u8, must_accept: bool) void {
    const outcome = result.parse(bytes, &parsed);
    if (outcome != .ok) {
        assert(!must_accept);
        return;
    }
    const back = result.encode(&parsed, &again) catch unreachable; // It fit when it was parsed.
    assert(std.mem.eql(u8, back, bytes));
    assert(result.result_digest(back).eql(result.result_digest(bytes)));
}

fn damage(random: std.Random, length: usize) usize {
    @memcpy(damaged[0..length], encoded[0..length]);
    var size = length;
    switch (random.uintLessThan(u32, 3)) {
        0 => for (0..1 + random.uintLessThan(u32, 4)) |_| {
            damaged[random.uintLessThan(usize, size)] ^= @as(u8, 1) << random.int(u3);
        },
        1 => size = random.uintLessThan(usize, size),
        else => {
            const extra = 1 + random.uintLessThan(usize, 16);
            random.bytes(damaged[size..][0..extra]);
            size += extra;
        },
    }
    return size;
}

pub fn fuzz_result(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    random_record(random);
    const bytes = result.encode(&record, &encoded) catch return;
    check_parse(bytes, true);
    for (0..8) |_| {
        const size = damage(random, bytes.len);
        check_parse(damaged[0..size], false);
    }
}
