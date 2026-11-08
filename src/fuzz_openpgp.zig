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

/// A v4 algorithm 27 (native Ed25519) signature over `text`, with `size` bytes of raw signature
/// data (64 is the only valid size); the digest bits are right, so only the material can fail.
fn native_packet(random: std.Random, size: usize) []const u8 {
    const prefix = [_]u8{ 4, 0, 27, 8, 0, 0 };
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(text);
    hash.update(&prefix);
    hash.update(&.{ 0x04, 0xff, 0, 0, 0, prefix.len });
    const digest = hash.finalResult();
    native[0] = 0xc2;
    native[1] = @intCast(prefix.len + 2 + 2 + size);
    @memcpy(native[2..8], &prefix);
    native[8] = 0;
    native[9] = 0;
    @memcpy(native[10..12], digest[0..2]);
    random.bytes(native[12..][0..size]);
    return native[0 .. 12 + size];
}

var native: [128]u8 = undefined;

fn read_binary(bytes: []const u8) openpgp.Binding {
    return openpgp.bound_binary(bytes, text);
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
    for (binary_fixtures) |fixture| assert(read_binary(fixture) == .bound);
    assert(read_binary(native_packet(random, 64)) == .bound);
    assert(read_binary(native_packet(random, 63)) == .stale);
    assert(read_binary(native_packet(random, 65)) == .stale);
    for (text_fixtures) |fixture| {
        const binding = read_text(fixture[1], fixture[0]);
        const readable = binding == .bound or binding == .several;
        assert(readable);
    }
    // Properties 1 and 2 on damaged binary packets.
    // One iteration in four starts from an algorithm 27 packet, whose material is raw bytes of
    // 63 to 65 bytes: only 64 binds.
    const packet = if (random.uintLessThan(u8, 4) == 0)
        native_packet(random, 63 + random.uintLessThan(usize, 3))
    else
        binary_fixtures[random.uintLessThan(usize, binary_fixtures.len)];
    const broken = if (random.boolean()) damage(random, packet) else packet;
    const once = read_binary(broken);
    assert(same(once, read_binary(broken)));
    const print = openpgp.issuer_fingerprint(broken);
    assert(std.meta.eql(print, openpgp.issuer_fingerprint(broken)));
    // Property 4: armored afresh, the armored path gives the same answer as the binary one,
    // whatever it is (a stale one only when both are stale, by the `same` of the tags).
    var arena: std.heap.FixedBufferAllocator = .init(&armor_scratch);
    if (broken.len > 0) {
        const armored = openpgp.armor(arena.allocator(), "PGP SIGNATURE", broken) catch return;
        const through = read_text(.armored_detached, armored);
        assert(same(through, once));
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
