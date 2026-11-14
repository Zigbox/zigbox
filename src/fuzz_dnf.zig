//! The `dnf` fuzzer: `zig build fuzz -- dnf`. `dnf.write` takes its rpms from the caller (Zigcube
//! passes its own through `zigbox.package`), reads them with `rpm.split` and `rpm.build_host_of`,
//! and refuses any it did not make for the package beside them (`ForeignRpm`).
//!
//! Each iteration writes the sample package's rpm, damages it (a cut, flipped bytes, a header
//! length pushed to an extreme, random bytes, a byte appended) and writes a dnf tree of it.
//! Properties:
//!   1. No input panics or reads out of bounds: the answer is a tree or `ForeignRpm`.
//!   2. The undamaged rpm is accepted, and its tree is the same bytes twice.
//!   3. Damage that touches the main header, or cuts into it, is always `ForeignRpm`.
//!   4. Damage confined to the payload or the signature header's data is accepted: those bytes
//!      are the caller's to place (a header signature) and dnf describes them as they are.

const std = @import("std");
const assert = std.debug.assert;
const model = @import("package/model.zig");
const rpm = @import("package/rpm.zig");
const dnf = @import("package/dnf.zig");
const sample = &@import("package/deb.zig").sample;

var scratch: [1024 * 1024]u8 = undefined;
var damaged: [16 * 1024]u8 = undefined;

const Damage = enum { cut, flip, length, random, append };

const Damaged = struct {
    bytes: []const u8,
    /// The first byte offset changed, or the cut's offset.
    first: usize,
    kind: Damage,
};

fn damage(random: std.Random, original: []const u8) Damaged {
    assert(original.len > 0);
    assert(original.len + 1 <= damaged.len);
    @memcpy(damaged[0..original.len], original);
    var length = original.len;
    const kind = random.enumValue(Damage);
    var first: usize = length;
    switch (kind) {
        .cut => {
            length = random.uintLessThan(usize, length);
            first = length;
        },
        .flip => for (0..1 + random.uintLessThan(u8, 4)) |_| {
            const at = random.uintLessThan(usize, length);
            damaged[at] ^= @as(u8, 1) << random.int(u3);
            first = @min(first, at);
        },
        .length => {
            // A header's entry or data count (bytes 8 to 15 of either header) set to an extreme.
            const parts = rpm.split(original).?;
            const start: usize = if (random.boolean()) 96 else parts.header_start;
            const at = start + 8 + random.uintLessThan(usize, 8);
            damaged[at] = random.int(u8) | 0x80;
            first = at;
        },
        .random => {
            random.bytes(damaged[0..length]);
            first = 0;
        },
        .append => {
            damaged[length] = random.int(u8);
            first = length;
            length += 1;
        },
    }
    assert(first <= length);
    return .{ .bytes = damaged[0..length], .first = first, .kind = kind };
}

fn tree(bytes: []const u8) model.Error![]model.TreeFile {
    var arena: std.heap.FixedBufferAllocator = .init(&scratch);
    const built = [_]model.Built{.{ .package = sample, .bytes = bytes }};
    return dnf.write(arena.allocator(), .x86_64, &built);
}

pub fn fuzz_dnf(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var write_buffer: [256 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&write_buffer);
    const good = rpm.write(arena.allocator(), sample, .{ .build_host = "fuzz-build" }) catch
        unreachable; // The sample is valid and small; 256 KiB holds its rpm.
    const parts = rpm.split(good).?;
    // Property 2.
    const once = tree(good) catch unreachable; // The rpm `rpm.write` just made is dnf's own.
    const repomd = once[once.len - 1].bytes;
    var repomd_copy: [4096]u8 = undefined;
    assert(repomd.len <= repomd_copy.len);
    @memcpy(repomd_copy[0..repomd.len], repomd);
    const twice = tree(good) catch unreachable; // As above.
    assert(std.mem.eql(u8, repomd_copy[0..repomd.len], twice[twice.len - 1].bytes));

    const broken = damage(random, good);
    const result = tree(broken.bytes);
    // Property 1: a tree or ForeignRpm, nothing else.
    if (result) |_| {} else |err| assert(err == error.ForeignRpm);
    // Property 3.
    if (broken.bytes.len < parts.header_end) {
        assert(result == error.ForeignRpm); // Cut into the main header.
    } else {
        const main = good[parts.header_start..parts.header_end];
        const changed = !std.mem.eql(u8, main, broken.bytes[parts.header_start..parts.header_end]);
        if (changed) assert(result == error.ForeignRpm);
    }
    // Property 4: a few flipped bits only in the payload are accepted.
    if (broken.kind == .flip and broken.first >= parts.header_end) {
        _ = result catch unreachable; // The main header is untouched, so the rpm is dnf's own.
    }
}

test "the undamaged rpm is accepted, and damaged ones are refused, never a crash" {
    // Goal: the fuzzer's body runs under `zig build test` for a couple of hundred seeds.
    for (0..200) |seed| fuzz_dnf(seed);
}
