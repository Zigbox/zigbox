//! Tests of the key file (M8 slice 1): sealing, opening, the golden file, damaged files and the
//! bounds. The cheap parameters keep each test fast; the default cost is measured in the demo
//! document, not here.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const key = @import("key.zig");

const fixed_seed: [32]u8 = @splat(0x11);
const fixed_salt: [16]u8 = @splat(0x22);
const fixed_nonce: [24]u8 = @splat(0x33);
const cheap: key.Kdf = .{ .t = 1, .m_kib = 8, .p = 1, .salt = fixed_salt };

fn sealed_record(passphrase: []const u8) !key.Record {
    const public = key.public_of_seed(fixed_seed);
    const sealed = try key.seal(
        testing.allocator,
        passphrase,
        fixed_seed,
        public,
        cheap,
        fixed_nonce,
    );
    return .{ .public = public, .body = .{ .passphrase = sealed } };
}

test "a sealed key opens with its passphrase and with nothing else" {
    const record = try sealed_record("correct horse");
    const seed = try key.open(testing.allocator, &record, "correct horse");
    try testing.expectEqualSlices(u8, &fixed_seed, &seed);
    try testing.expectError(error.WrongPassphrase, key.open(testing.allocator, &record, "wrong"));
    try testing.expectError(error.WrongPassphrase, key.open(testing.allocator, &record, null));
    try testing.expectError(error.WrongPassphrase, key.open(testing.allocator, &record, ""));
}

test "a flipped byte of the salt, nonce, sealed seed or public text fails to open" {
    const record = try sealed_record("pw");
    var salt = record;
    salt.body.passphrase.kdf.salt[0] ^= 1;
    var nonce = record;
    nonce.body.passphrase.nonce[0] ^= 1;
    var sealed = record;
    sealed.body.passphrase.sealed[40] ^= 1;
    var public = record;
    public.public[0] ^= 1;
    for ([_]key.Record{ salt, nonce, sealed, public }) |damaged| {
        const result = key.open(testing.allocator, &damaged, "pw");
        try testing.expect(std.meta.isError(result));
    }
}

test "render and parse agree, and the golden file opens to the golden public text" {
    const record = try sealed_record("golden");
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(&record, &buffer);
    const parsed = try key.parse(text);
    try testing.expectEqualDeep(record, parsed);
    const public = key.public_text(key.public_of_seed(fixed_seed));
    try testing.expectEqualSlices(u8, &public, &key.public_text(parsed.public));
    const seed = try key.open(testing.allocator, &parsed, "golden");
    try testing.expectEqualSlices(u8, &fixed_seed, &seed);
    try testing.expect(std.mem.startsWith(u8, &public, key.public_prefix));
}

test "a none key renders its secret and parses back" {
    const record: key.Record = .{
        .public = key.public_of_seed(fixed_seed),
        .body = .{ .none = fixed_seed },
    };
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(&record, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "\"none\"") != null);
    const parsed = try key.parse(text);
    try testing.expectEqualDeep(record, parsed);
    const seed = try key.open(testing.allocator, &parsed, null);
    try testing.expectEqualSlices(u8, &fixed_seed, &seed);
}

test "parse refuses a file that render would not write" {
    const record = try sealed_record("x");
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(&record, &buffer);
    try testing.expectError(error.Malformed, key.parse(""));
    try testing.expectError(error.Malformed, key.parse(text[0 .. text.len - 1]));
    var extra: [constants.key_file_bytes_max + 1]u8 = undefined;
    @memcpy(extra[0..text.len], text);
    extra[text.len] = ' ';
    try testing.expectError(error.Malformed, key.parse(extra[0 .. text.len + 1]));
    var upper: [constants.key_file_bytes_max]u8 = undefined;
    @memcpy(upper[0..text.len], text);
    const at = std.mem.indexOf(u8, text, "nonce").? + 12;
    upper[at] = std.ascii.toUpper(upper[at]);
    if (upper[at] != text[at]) {
        try testing.expectError(error.Malformed, key.parse(upper[0..text.len]));
    }
}

test "a newer version is reported as newer" {
    const record = try sealed_record("x");
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(&record, &buffer);
    var copy: [constants.key_file_bytes_max]u8 = undefined;
    @memcpy(copy[0..text.len], text);
    const at = std.mem.indexOf(u8, text, ".version = 1").? + 11;
    copy[at] = '2';
    try testing.expectError(error.Newer, key.parse(copy[0..text.len]));
}

test "kdf parameters are bounded at and past the limit" {
    var kdf = cheap;
    kdf.t = constants.key_kdf_t_max;
    kdf.m_kib = constants.key_kdf_m_kib_max;
    try testing.expect(key.kdf_valid(kdf));
    kdf.t += 1;
    try testing.expect(!key.kdf_valid(kdf));
    kdf.t = 1;
    kdf.m_kib += 1;
    try testing.expect(!key.kdf_valid(kdf));
    kdf.m_kib = 0;
    try testing.expect(!key.kdf_valid(kdf));
    kdf = cheap;
    kdf.p = constants.key_kdf_p_max + 1;
    try testing.expect(!key.kdf_valid(kdf));
}

test "parse refuses parameters above the bounds without running argon2id" {
    var record = try sealed_record("x");
    record.body.passphrase.kdf.m_kib = constants.key_kdf_m_kib_max;
    var buffer: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(&record, &buffer);
    const needle = "262144";
    const at = std.mem.indexOf(u8, text, needle).?;
    var copy: [constants.key_file_bytes_max]u8 = undefined;
    @memcpy(copy[0..text.len], text);
    copy[at + 5] = '5'; // 262145
    try testing.expectError(error.Malformed, key.parse(copy[0..text.len]));
}

test "names are lowercase letters, digits and hyphens, at most 32 bytes" {
    const name_max: [constants.key_name_bytes_max]u8 = @splat('a');
    const name_over: [constants.key_name_bytes_max + 1]u8 = @splat('a');
    try testing.expect(key.name_valid("release-2"));
    try testing.expect(key.name_valid(&name_max));
    try testing.expect(!key.name_valid(&name_over));
    try testing.expect(!key.name_valid(""));
    try testing.expect(!key.name_valid("Upper"));
    try testing.expect(!key.name_valid("a/b"));
    try testing.expect(!key.name_valid(".."));
}

test "the id is the full BLAKE3 hash over the context and the public key" {
    const public = key.public_of_seed(fixed_seed);
    var expected: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zbx-key\x00");
    hasher.update(&public);
    hasher.final(&expected);
    const id = key.key_id(public);
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(expected, .lower), &id);
    try testing.expectEqual(@as(usize, 64), id.len);
}

test "the pub file round trips and a mode with group or other bits is too open" {
    const public = key.public_of_seed(fixed_seed);
    var buffer: [key.pub_file_bytes_max]u8 = undefined;
    for ([_]key.Encryption{ .passphrase, .none }) |encryption| {
        const bytes = key.render_pub(.{ .public = public, .encryption = encryption }, &buffer);
        const parsed = key.parse_pub(bytes).?;
        try testing.expectEqualSlices(u8, &public, &parsed.public);
        try testing.expectEqual(encryption, parsed.encryption);
        try testing.expect(key.parse_pub(bytes[0 .. bytes.len - 1]) == null);
        try testing.expect(key.parse_pub(bytes[0 .. key.pub_file_bytes_max - 12]) == null);
    }
    try testing.expect(key.parse_pub(&@as([key.pub_file_bytes_max]u8, @splat('x'))) == null);
    try testing.expect(!key.mode_too_open(0o600));
    try testing.expect(!key.mode_too_open(0o700));
    try testing.expect(key.mode_too_open(0o640));
    try testing.expect(key.mode_too_open(0o604));
}
