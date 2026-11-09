//! The `provenance` fuzzer: `zig build fuzz -- provenance`. A provenance record is read from
//! the store, where anyone with the store could have written the bytes. Each iteration builds
//! a random valid record, renders it, damages the text and parses the damage, and parses
//! random bytes too.
//!
//! Properties, every iteration:
//!   1. Round trip: a rendered record parses, and re-renders to the same bytes.
//!   2. Canonical: damaged or random bytes never crash `provenance.parse`. They are accepted
//!      only if they re-render to exactly themselves.
//!   3. Bounds: a record one byte past `statement_bytes_max` is refused.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const provenance = @import("trust/provenance.zig");

const Record = provenance.Record;

var record: Record = undefined;
var parsed: Record = undefined;
var out: [constants.statement_bytes_max + 1]u8 = undefined;
var again: [constants.statement_bytes_max + 1]u8 = undefined;
var second: [constants.statement_bytes_max + 1]u8 = undefined;
var damaged: [constants.statement_bytes_max + 16]u8 = undefined;
var name: [@max(constants.path_bytes_max, constants.reference_bytes_max)]u8 = undefined;

const alphabet = "{}[]\":,\\ 0123456789-+.eEtrufalsn\n\t\x00\x1f\x7f=AZaz/\xc3\xa9\xff";

fn digest(random: std.Random) provenance.Digest {
    var bytes: provenance.Digest = undefined;
    random.bytes(&bytes);
    return bytes;
}

/// A name of up to `limit` bytes, of letters and a few characters JSON escapes.
fn random_name(random: std.Random, limit: usize) []const u8 {
    assert(limit >= 1);
    assert(limit <= name.len);
    const length = 1 + random.uintLessThan(usize, limit);
    for (name[0..length]) |*byte| {
        byte.* = switch (random.uintLessThan(u32, 12)) {
            0 => '"',
            1 => '\\',
            2 => '/',
            else => 'a' + random.uintLessThan(u8, 26),
        };
    }
    return name[0..length];
}

fn random_record(random: std.Random) void {
    record.clear();
    record.tree = digest(random);
    record.result = digest(random);
    record.set_build_file(random_name(random, constants.path_bytes_max));
    record.build_file_digest = digest(random);
    record.lock = if (random.boolean()) digest(random) else null;
    const bases = 1 + random.uintLessThan(u32, constants.provenance_bases_max);
    for (0..bases) |_| {
        const reference = random_name(random, constants.reference_bytes_max);
        _ = record.add_base(reference, digest(random), digest(random));
    }
    const steps = random.uintLessThan(u32, constants.provenance_steps_max + 1);
    for (0..steps) |_| {
        const step = record.add_step(random_name(random, constants.build_step_name_bytes_max));
        step.base = if (bases > 0) random.uintLessThan(u32, bases) else 0;
        step.key = digest(random);
        step.input = digest(random);
        step.output = digest(random);
        step.network = random.boolean();
        const needs = random.uintLessThan(u32, constants.build_step_needs_max + 1);
        for (0..needs) |_| {
            const need = random_name(random, constants.build_step_name_bytes_max);
            Record.add_need(step, need, digest(random));
        }
    }
    record.image_key = digest(random);
    record.image_base = if (random.boolean()) random.uintLessThan(u32, bases) else null;
    record.set_version(random_name(random, constants.provenance_version_bytes_max), "linux/arm64");
    record.zbx = digest(random);
    record.started = random.uintLessThan(u64, constants.signed_at_seconds_max);
    record.finished = record.started;
}

fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len > 0);
    @memcpy(damaged[0..text.len], text);
    var length = text.len;
    switch (random.uintLessThan(u32, 4)) {
        0 => length = random.uintLessThan(usize, length),
        1 => damaged[random.uintLessThan(usize, length)] ^=
            @as(u8, 1) << @as(u3, @intCast(random.uintLessThan(u8, 8))),
        2 => damaged[random.uintLessThan(usize, length)] =
            alphabet[random.uintLessThan(usize, alphabet.len)],
        else => {
            damaged[length] = '\n';
            length += 1;
        },
    }
    return damaged[0..length];
}

fn accepted_is_canonical(bytes: []const u8) void {
    provenance.parse(bytes, &parsed, &again) catch return;
    assert(std.mem.eql(u8, bytes, provenance.render(&second, &parsed)));
}

pub fn fuzz_provenance(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    random_record(random);
    const text = provenance.render(out[0..constants.statement_bytes_max], &record);
    provenance.parse(text, &parsed, &again) catch |err|
        std.debug.panic("a written record was refused: {s}", .{@errorName(err)});
    assert(std.mem.eql(u8, text, provenance.render(&second, &parsed)));
    var round: u32 = 0;
    while (round < 8) : (round += 1) accepted_is_canonical(damage(random, text));
    const length = random.uintLessThan(usize, 256);
    random.bytes(damaged[0..length]);
    accepted_is_canonical(damaged[0..length]);
    // One byte past the bound is refused, whatever else is right.
    @memcpy(damaged[0..text.len], text);
    @memset(damaged[text.len..][0 .. constants.statement_bytes_max + 1 - text.len], ' ');
    assert(std.meta.isError(provenance.parse(
        damaged[0 .. constants.statement_bytes_max + 1],
        &parsed,
        again[0..constants.statement_bytes_max],
    )));
}

test "the fuzzer's properties hold on fixed seeds" {
    // Goal: the fuzzer runs under `zig build test`. Method: a few seeds.
    var seed: u64 = 1;
    while (seed <= 24) : (seed += 1) fuzz_provenance(seed);
}
