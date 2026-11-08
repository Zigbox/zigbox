//! The `key` fuzzer: `zig build fuzz -- key`. A key file and its `.pub` are read from a
//! directory anyone could have written to, and a parameter in them decides how much memory
//! argon2id takes. Each iteration renders a random valid record (sealed or not, parameters
//! anywhere inside their bounds, random bytes where the secrets are), then damages the text (a
//! cut, flipped bytes, a byte appended, noise, a number pushed past its bound) and parses that.
//!
//! Properties, every iteration:
//!   1. A record `render` wrote parses back to itself, and renders to the same bytes.
//!   2. Damaged or random bytes never crash `parse` or `parse_pub`. They are accepted only if
//!      they re-render to exactly themselves.
//!   3. An accepted sealed record has parameters inside the bounds (`kdf_valid`): argon2id is
//!      never run above them, because nothing above them is accepted.
//!   4. A KDF parameter written past its bound is refused, whatever else is right.
//!   5. A name is valid only if it is `[a-z0-9-]`, 1 to 32 bytes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const key = @import("trust/key.zig");

var text_buffer: [constants.key_file_bytes_max]u8 = undefined;
var damaged: [constants.key_file_bytes_max + 8]u8 = undefined;
var pub_buffer: [key.pub_file_bytes_max]u8 = undefined;

const kdf_format = ".kdf = .{{ .t = {d}, .m_kib = {d}, .p = {d}, .salt = \"{s}\" }}";

fn random_record(random: std.Random) key.Record {
    var record: key.Record = undefined;
    random.bytes(&record.public);
    if (random.boolean()) {
        var seed: [constants.key_seed_bytes]u8 = undefined;
        random.bytes(&seed);
        record.body = .{ .none = seed };
        return record;
    }
    var sealed: key.Sealed = undefined;
    sealed.kdf.t = random.intRangeAtMost(u32, 1, constants.key_kdf_t_max);
    sealed.kdf.p = constants.key_kdf_p_max;
    sealed.kdf.m_kib = random.intRangeAtMost(u32, 8, constants.key_kdf_m_kib_max);
    random.bytes(&sealed.kdf.salt);
    random.bytes(&sealed.nonce);
    random.bytes(&sealed.sealed);
    assert(key.kdf_valid(sealed.kdf));
    record.body = .{ .passphrase = sealed };
    return record;
}

/// Parses `bytes`; whatever is accepted must be exactly what render writes for it.
fn check_parse(bytes: []const u8) bool {
    const record = key.parse(bytes) catch return false;
    if (record.body == .passphrase) assert(key.kdf_valid(record.body.passphrase.kdf));
    var again: [constants.key_file_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, bytes, key.render(&record, &again)));
    return true;
}

fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len > 0);
    assert(text.len <= constants.key_file_bytes_max);
    @memcpy(damaged[0..text.len], text);
    var length = text.len;
    switch (random.uintLessThan(u8, 5)) {
        0 => length = random.uintLessThan(usize, text.len),
        1 => {
            for (0..random.intRangeAtMost(u32, 1, 4)) |_| {
                damaged[random.uintLessThan(usize, length)] ^= random.intRangeAtMost(u8, 1, 255);
            }
        },
        2 => {
            damaged[length] = random.int(u8);
            length += 1;
        },
        3 => {
            length = random.uintLessThan(usize, damaged.len);
            random.bytes(damaged[0..length]);
        },
        else => {
            const at = random.uintLessThan(usize, length);
            damaged[at] = random.intRangeAtMost(u8, 0x20, 0x7e);
        },
    }
    return damaged[0..length];
}

/// The sealed text with `t`, `m_kib` or `p` replaced by `value`, which is past its bound.
fn with_parameter(
    random: std.Random,
    record: *const key.Record,
    value: u32,
) ?[]const u8 {
    const sealed = record.body.passphrase;
    var good: [constants.key_file_bytes_max]u8 = undefined;
    const text = key.render(record, &good);
    const which = random.uintLessThan(u8, 3);
    var edited = sealed;
    const salt = std.fmt.bytesToHex(sealed.kdf.salt, .lower);
    var line: [160]u8 = undefined;
    const old = std.fmt.bufPrint(&line, kdf_format, .{
        sealed.kdf.t, sealed.kdf.m_kib, sealed.kdf.p, &salt,
    }) catch unreachable; // Short numbers and a salt.
    switch (which) {
        0 => edited.kdf.t = value,
        1 => edited.kdf.m_kib = value,
        else => edited.kdf.p = value,
    }
    var new_line: [160]u8 = undefined;
    const new = std.fmt.bufPrint(&new_line, kdf_format, .{
        edited.kdf.t, edited.kdf.m_kib, edited.kdf.p, &salt,
    }) catch unreachable; // Short numbers and a salt.
    if (std.mem.indexOf(u8, text, old) == null) return null;
    const size = std.mem.replacementSize(u8, text, old, new);
    if (size > damaged.len) return null;
    _ = std.mem.replace(u8, text, old, new, damaged[0..size]);
    return damaged[0..size];
}

fn check_names(random: std.Random) void {
    var name: [40]u8 = undefined;
    const length = random.uintLessThan(usize, name.len + 1);
    for (name[0..length]) |*byte| {
        const noise = random.uintLessThan(u8, 4) == 0;
        byte.* = if (noise) random.int(u8) else random.intRangeAtMost(u8, 'a', 'z');
    }
    if (!key.name_valid(name[0..length])) return;
    assert(length >= 1);
    assert(length <= constants.key_name_bytes_max);
    for (name[0..length]) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-';
        assert(allowed);
    }
}

fn check_pub(random: std.Random, record: *const key.Record) void {
    const file: key.PubFile = .{
        .public = record.public,
        .encryption = std.meta.activeTag(record.body),
    };
    const text = key.render_pub(file, &pub_buffer);
    const back = key.parse_pub(text).?;
    assert(std.mem.eql(u8, &back.public, &file.public));
    assert(back.encryption == file.encryption);
    var copy: [key.pub_file_bytes_max + 4]u8 = undefined;
    @memcpy(copy[0..text.len], text);
    var length = text.len;
    if (random.boolean()) {
        copy[random.uintLessThan(usize, length)] ^= random.intRangeAtMost(u8, 1, 255);
    } else {
        length = random.uintLessThan(usize, length);
    }
    const parsed = key.parse_pub(copy[0..length]) orelse return;
    var again: [key.pub_file_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, copy[0..length], key.render_pub(parsed, &again)));
}

pub fn fuzz_key(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const record = random_record(random);
    const text = key.render(&record, &text_buffer);
    assert(check_parse(text));
    const back = key.parse(text) catch unreachable; // Just accepted.
    assert(std.meta.activeTag(back.body) == std.meta.activeTag(record.body));
    assert(std.mem.eql(u8, &back.public, &record.public));
    _ = check_parse(damage(random, text));
    if (record.body == .passphrase) {
        const past: [3]u32 = .{ 0, constants.key_kdf_m_kib_max + 1, std.math.maxInt(u32) };
        const value = past[random.uintLessThan(usize, past.len)];
        if (with_parameter(random, &record, value)) |edited| {
            // Zero is below every floor, the others above every bound.
            assert(!check_parse(edited));
        }
    }
    check_pub(random, &record);
    check_names(random);
}

test "an unbounded parameter is refused" {
    // Goal: property 4 on a fixed case. Method: a valid sealed record with p = 2 is refused.
    var prng = std.Random.Xoshiro256.init(1);
    var record = random_record(prng.random());
    while (record.body != .passphrase) record = random_record(prng.random());
    const edited = with_parameter(prng.random(), &record, 2) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!check_parse(edited));
}
