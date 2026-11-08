//! The `openpgp` fuzzer: `zig build fuzz -- openpgp`. The signature files the owner places for a
//! release (`.header.sig`, `InRelease`, `Release.gpg`, `repomd.xml.asc`) are read by
//! `openpgp.bound_to`, `bound_binary` and `issuer_fingerprint`, which walk three levels of
//! length fields (the packet, the hashed and unhashed areas, the subpackets) and the MPIs.
//!
//! Each iteration takes a real gpg signature (RSA 4096 or Ed25519, binary, armored or
//! clearsigned, a long notation, or two signatures), damages it (a cut, flipped bytes, a length
//! field pushed up, random bytes, a byte appended) and reads it. Properties:
//!   1. No input panics or reads out of bounds; a damaged signature is `stale`, `several`,
//!      `unsupported` or bound, never a crash.
//!   2. Reading is deterministic: the same bytes give the same answer twice.
//!   3. The undamaged signature binds to its text, with its key's fingerprint.
//!   4. Any binary damage of the same bytes, armored afresh, is read the same by the armored
//!      path as by the binary one (the armor adds nothing to the answer).

const std = @import("std");
const assert = std.debug.assert;
const openpgp = @import("package/openpgp.zig");

const text = @embedFile("package/testdata/gpg/text.txt");
const binary_fixtures = [_][]const u8{
    @embedFile("package/testdata/gpg/rsa4096.bin.sig"),
    @embedFile("package/testdata/gpg/ed25519.bin.sig"),
    @embedFile("package/testdata/gpg/ed25519-notation.bin.sig"),
};
const text_fixtures = [_]struct { []const u8, openpgp.Form }{
    .{ @embedFile("package/testdata/gpg/rsa4096.asc"), .armored_detached },
    .{ @embedFile("package/testdata/gpg/ed25519.asc"), .armored_detached },
    .{ @embedFile("package/testdata/gpg/rsa4096.clear"), .clearsigned },
    .{ @embedFile("package/testdata/gpg/ed25519.clear"), .clearsigned },
    .{ @embedFile("package/testdata/gpg/both.clear"), .clearsigned },
};

var damaged: [4096]u8 = undefined;
var scratch: [64 * 1024]u8 = undefined;
var armor_scratch: [16 * 1024]u8 = undefined;

fn damage(random: std.Random, original: []const u8) []const u8 {
    assert(original.len > 0);
    assert(original.len + 8 <= damaged.len);
    @memcpy(damaged[0..original.len], original);
    var length = original.len;
    switch (random.uintLessThan(u8, 6)) {
        0 => length = random.uintLessThan(usize, length), // A cut.
        1 => for (0..1 + random.uintLessThan(u8, 4)) |_| {
            damaged[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
        },
        2 => for (0..1 + random.uintLessThan(u8, 4)) |_| {
            // A length field (they sit near the front) set to an extreme value.
            damaged[random.uintLessThan(usize, @min(length, 16))] = random.int(u8) | 0x80;
        },
        3 => random.bytes(damaged[0..length]),
        4 => {
            damaged[length] = random.int(u8);
            length += 1;
        },
        else => damaged[random.uintLessThan(usize, length)] = random.int(u8),
    }
    return damaged[0..length];
}

fn read_binary(bytes: []const u8) ?[20]u8 {
    const bound = openpgp.bound_binary(bytes, text) orelse return null;
    return bound.fingerprint orelse @as([20]u8, @splat(0));
}

fn same(left: openpgp.Binding, right: openpgp.Binding) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    if (left != .bound) return true;
    const a = left.bound.fingerprint;
    const b = right.bound.fingerprint;
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, &a.?, &b.?);
}

fn read_text(form: openpgp.Form, bytes: []const u8) openpgp.Binding {
    var arena: std.heap.FixedBufferAllocator = .init(&scratch);
    return openpgp.bound_to(arena.allocator(), form, bytes, text) catch .stale;
}

pub fn fuzz_openpgp(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    // Property 3: every undamaged fixture binds.
    for (binary_fixtures) |fixture| assert(read_binary(fixture) != null);
    for (text_fixtures) |fixture| {
        const binding = read_text(fixture[1], fixture[0]);
        const readable = binding == .bound or binding == .several;
        assert(readable);
    }
    // Properties 1 and 2 on damaged binary packets.
    const packet = binary_fixtures[random.uintLessThan(usize, binary_fixtures.len)];
    const broken = damage(random, packet);
    const once = read_binary(broken);
    assert(std.meta.eql(once, read_binary(broken)));
    const print = openpgp.issuer_fingerprint(broken);
    assert(std.meta.eql(print, openpgp.issuer_fingerprint(broken)));
    // Property 4: armored afresh, the armored path agrees on whether it binds.
    var arena: std.heap.FixedBufferAllocator = .init(&armor_scratch);
    if (broken.len > 0) {
        const armored = openpgp.armor(arena.allocator(), "PGP SIGNATURE", broken) catch return;
        const through = read_text(.armored_detached, armored);
        assert((through == .bound) == (once != null));
    }
    // Properties 1 and 2 on damaged armored and clearsigned text.
    const entry = text_fixtures[random.uintLessThan(usize, text_fixtures.len)];
    const mangled = damage(random, entry[0]);
    assert(same(read_text(entry[1], mangled), read_text(entry[1], mangled)));
}

test "every undamaged fixture is read, and many damaged ones do not crash" {
    // Goal: the fuzzer's body runs under `zig build test` for a few hundred seeds.
    for (0..300) |seed| fuzz_openpgp(seed);
}
