//! The `dnf` fuzzer: `zig build fuzz -- dnf`. `dnf.write` takes its rpms from the caller (Zigcube
//! passes its own through `zigbox.package`), reads them with `rpm.split`, `rpm.build_host_of` and
//! `rpm.binary_tag`, and refuses any that is not, byte for byte, the rpm `rpm.write` makes for the
//! package beside it (`ForeignRpm`).
//!
//! Each iteration writes the sample package's rpm, unsigned or with a random header signature,
//! damages it (a cut, flipped bytes, a header length pushed to an extreme, random bytes, a byte
//! appended) and writes a dnf tree of it. Properties:
//!   1. No input panics or reads out of bounds: the answer is a tree or `ForeignRpm`.
//!   2. The undamaged rpm, signed or not, is accepted, and its tree is the same bytes twice.
//!   3. Damaged bytes that differ from the rpm anywhere (the lead, either header, the build host,
//!      the payload) are always `ForeignRpm`; damage only inside the header signature's own
//!      bytes (opaque here: `check_tree` reads them), or flips that cancel out, is accepted.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const model = @import("package/model.zig");
const rpm = @import("package/rpm.zig");
const dnf = @import("package/dnf.zig");
const sample = &@import("package/deb.zig").sample;

var scratch: [1024 * 1024]u8 = undefined;
var damaged: [16 * 1024]u8 = undefined;

const Damage = enum { cut, flip, length, random, append };

fn damage(random: std.Random, original: []const u8) []const u8 {
    assert(original.len > 0);
    assert(original.len + 1 <= damaged.len);
    @memcpy(damaged[0..original.len], original);
    var length = original.len;
    switch (random.enumValue(Damage)) {
        .cut => length = random.uintLessThan(usize, length),
        .flip => for (0..1 + random.uintLessThan(u8, 4)) |_| {
            damaged[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
        },
        .length => {
            // A header's entry or data count (bytes 8 to 15 of either header) set to an extreme.
            const parts = rpm.split(original).?;
            const start: usize = if (random.boolean()) 96 else parts.header_start;
            damaged[start + 8 + random.uintLessThan(usize, 8)] = random.int(u8) | 0x80;
        },
        .random => random.bytes(damaged[0..length]),
        .append => {
            damaged[length] = random.int(u8);
            length += 1;
        },
    }
    return damaged[0..length];
}

fn tree(bytes: []const u8) model.Error![]model.TreeFile {
    var arena: std.heap.FixedBufferAllocator = .init(&scratch);
    const built = [_]model.Built{.{ .package = sample, .bytes = bytes }};
    return dnf.write(arena.allocator(), .x86_64, &built);
}

/// Whether `broken` is `good` but for bytes in `start..end`.
fn same_outside(broken: []const u8, good: []const u8, start: usize, end: usize) bool {
    assert(start <= end);
    assert(end <= good.len);
    if (broken.len != good.len) return false;
    if (!std.mem.eql(u8, broken[0..start], good[0..start])) return false;
    return std.mem.eql(u8, broken[end..], good[end..]);
}

pub fn fuzz_dnf(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var write_buffer: [256 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&write_buffer);
    var signature: [constants.openpgp_signature_bytes_max]u8 = undefined;
    const signature_bytes = 1 + random.uintLessThan(usize, signature.len);
    random.bytes(signature[0..signature_bytes]);
    const options: rpm.Options = .{
        .build_host = "fuzz-build",
        .header_signature = if (random.boolean()) signature[0..signature_bytes] else null,
    };
    const good = rpm.write(arena.allocator(), sample, options) catch
        unreachable; // The sample is valid and small; 256 KiB holds its rpm.
    // Property 2.
    const once = tree(good) catch unreachable; // The rpm `rpm.write` just made is dnf's own.
    const repomd = once[once.len - 1].bytes;
    var repomd_copy: [4096]u8 = undefined;
    assert(repomd.len <= repomd_copy.len);
    @memcpy(repomd_copy[0..repomd.len], repomd);
    const twice = tree(good) catch unreachable; // As above.
    assert(std.mem.eql(u8, repomd_copy[0..repomd.len], twice[twice.len - 1].bytes));

    const broken = damage(random, good);
    const result = tree(broken);
    // Property 1: a tree or ForeignRpm, nothing else.
    if (result) |_| {} else |err| assert(err == error.ForeignRpm);
    // Property 3. The header signature's own bytes are opaque here (`check_tree` reads them), so
    // damage inside them alone gives another signature, which is accepted.
    const parts = rpm.split(good).?;
    const placed = rpm.binary_tag(parts.signature_header, rpm.sig_tag.rsa) orelse good[0..0];
    const placed_start = placed.ptr - good.ptr;
    const placed_end = placed_start + placed.len;
    if (same_outside(broken, good, placed_start, placed_end)) {
        _ = result catch unreachable; // Outside the signature, these are the rpm's bytes.
    } else {
        assert(result == error.ForeignRpm);
    }
}

test "the undamaged rpm is accepted, and damaged ones are refused, never a crash" {
    // Goal: the fuzzer's body runs under `zig build test` for a couple of hundred seeds.
    for (0..200) |seed| fuzz_dnf(seed);
}
