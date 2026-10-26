//! Digests: BLAKE3 (unkeyed, from std), shown as `b3:` and 64 lowercase hex digits. The store
//! names everything by one: a tree by the hash of its encoding, a file object by the hash of its
//! header.
//!
//! Input is the full form or a prefix of at least `store_prefix_hex_min` hex digits, with or
//! without the `b3:`. A prefix is only ever a question to ask the store ("which tree starts
//! like this?"); `Prefix.matches` is the one test, and the store refuses a prefix that matches
//! none or more than one tree (zbx never guesses; spec, "Agent operability").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const Blake3 = std.crypto.hash.Blake3;

pub const text_prefix = "b3:";

pub const Digest = struct {
    bytes: [constants.store_digest_bytes]u8,

    /// The digest of `data`, in one call.
    pub fn of(data: []const u8) Digest {
        assert(data.len <= std.math.maxInt(u32));
        assert(@sizeOf(Digest) == constants.store_digest_bytes);
        var digest: Digest = undefined;
        Blake3.hash(data, &digest.bytes, .{});
        return digest;
    }

    pub fn eql(first: Digest, second: Digest) bool {
        assert(first.bytes.len == constants.store_digest_bytes);
        assert(second.bytes.len == constants.store_digest_bytes);
        return std.mem.eql(u8, &first.bytes, &second.bytes);
    }

    /// Byte order: the order a sorted list of digests, and the shard directories, follow.
    pub fn less_than(first: Digest, second: Digest) bool {
        assert(first.bytes.len == constants.store_digest_bytes);
        assert(second.bytes.len == constants.store_digest_bytes);
        return std.mem.lessThan(u8, &first.bytes, &second.bytes);
    }

    /// Lowercase hex, 64 digits.
    pub fn hex(digest: Digest) [constants.store_digest_hex_bytes]u8 {
        assert(digest.bytes.len == constants.store_digest_bytes);
        const lower = std.fmt.bytesToHex(digest.bytes, .lower);
        assert(lower.len == constants.store_digest_hex_bytes);
        return lower;
    }

    /// "b3:" and the hex, 67 bytes.
    pub fn text(digest: Digest) [constants.store_digest_text_bytes]u8 {
        assert(text_prefix.len + constants.store_digest_hex_bytes ==
            constants.store_digest_text_bytes);
        var out: [constants.store_digest_text_bytes]u8 = undefined;
        @memcpy(out[0..text_prefix.len], text_prefix);
        out[text_prefix.len..][0..constants.store_digest_hex_bytes].* = digest.hex();
        assert(std.mem.startsWith(u8, &out, text_prefix));
        return out;
    }

    /// The full text form; null for anything else (wrong length, uppercase, not hex).
    pub fn parse(source: []const u8) ?Digest {
        assert(source.len <= constants.file_bytes_max);
        assert(text_prefix.len == 3);
        if (source.len != constants.store_digest_text_bytes) return null;
        if (!std.mem.startsWith(u8, source, text_prefix)) return null;
        return from_hex(source[text_prefix.len..]);
    }

    /// 64 lowercase hex digits; null for anything else.
    pub fn from_hex(source: []const u8) ?Digest {
        assert(source.len <= constants.file_bytes_max);
        if (source.len != constants.store_digest_hex_bytes) return null;
        var digest: Digest = undefined;
        for (0..constants.store_digest_bytes) |index| {
            const high = hex_value(source[index * 2]) orelse return null;
            const low = hex_value(source[index * 2 + 1]) orelse return null;
            digest.bytes[index] = high << 4 | low;
        }
        assert(std.mem.eql(u8, &digest.hex(), source));
        return digest;
    }
};

/// The value of a lowercase hex digit; uppercase is refused so that a digest has one spelling.
fn hex_value(byte: u8) ?u8 {
    const value: ?u8 = switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
    if (value) |digit| assert(digit < 16);
    if (value == null) {
        if (std.ascii.isLower(byte)) assert(byte > 'f'); // Of the letters only a to f are digits.
    }
    return value;
}

/// A digest's first `len` hex digits.
pub const Prefix = struct {
    hex: [constants.store_digest_hex_bytes]u8,
    len: u8,

    /// `source` is "b3:" and 12 to 64 hex digits, or the digits alone. Null for anything else
    /// (too short, too long, uppercase, not hex).
    pub fn parse(source: []const u8) ?Prefix {
        assert(source.len <= constants.file_bytes_max);
        assert(constants.store_prefix_hex_min >= 2); // The shard is two digits.
        var rest = source;
        if (std.mem.startsWith(u8, rest, text_prefix)) rest = rest[text_prefix.len..];
        if (rest.len < constants.store_prefix_hex_min) return null;
        if (rest.len > constants.store_digest_hex_bytes) return null;
        var prefix: Prefix = .{ .hex = @splat('0'), .len = @intCast(rest.len) };
        for (rest, 0..) |byte, index| {
            if (hex_value(byte) == null) return null;
            prefix.hex[index] = byte;
        }
        assert(prefix.len >= constants.store_prefix_hex_min);
        return prefix;
    }

    pub fn digits(prefix: *const Prefix) []const u8 {
        assert(prefix.len >= constants.store_prefix_hex_min);
        assert(prefix.len <= constants.store_digest_hex_bytes);
        return prefix.hex[0..prefix.len];
    }

    /// True if the digest's hex starts with the prefix. Whole digests compare equal.
    pub fn matches(prefix: *const Prefix, digest: Digest) bool {
        assert(prefix.len >= constants.store_prefix_hex_min);
        assert(prefix.len <= constants.store_digest_hex_bytes);
        const full = digest.hex();
        return std.mem.startsWith(u8, &full, prefix.digits());
    }

    /// The prefix is a whole digest.
    pub fn complete(prefix: *const Prefix) ?Digest {
        assert(prefix.len >= constants.store_prefix_hex_min);
        assert(prefix.len <= constants.store_digest_hex_bytes);
        if (prefix.len != constants.store_digest_hex_bytes) return null;
        return Digest.from_hex(prefix.digits());
    }
};

/// A streaming hash, for content that does not fit in memory.
pub const Hasher = struct {
    state: Blake3,

    pub fn init() Hasher {
        assert(@sizeOf(Blake3) > 0);
        assert(Blake3.digest_length == constants.store_digest_bytes);
        return .{ .state = Blake3.init(.{}) };
    }

    pub fn update(hasher: *Hasher, data: []const u8) void {
        assert(data.len <= std.math.maxInt(u32));
        assert(@intFromPtr(hasher) != 0);
        hasher.state.update(data);
    }

    pub fn final(hasher: *Hasher) Digest {
        assert(@intFromPtr(hasher) != 0);
        assert(Blake3.digest_length == constants.store_digest_bytes);
        var digest: Digest = undefined;
        hasher.state.final(&digest.bytes);
        return digest;
    }
};

const testing = std.testing;

test "a digest round-trips through its text and hex forms" {
    // Goal: text and parse are inverse, and the empty input has BLAKE3's well-known hash.
    // Method: the published BLAKE3 digest of the empty string, then a changed byte.
    const empty = Digest.of("");
    const known = "b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    try testing.expectEqualStrings(known, &empty.text());
    try testing.expect(Digest.parse(known).?.eql(empty));
    try testing.expect(Digest.from_hex(known[3..]).?.eql(empty));
    try testing.expect(!Digest.of("a").eql(empty));
    try testing.expect(empty.less_than(Digest.of("a")) != Digest.of("a").less_than(empty));
}

test "parse refuses every near miss" {
    // Goal: the boundary where text stops being a digest. Method: wrong prefix, case, length,
    // a non-hex byte, a trailing byte.
    const good = "b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    try testing.expect(Digest.parse(good) != null);
    try testing.expect(Digest.parse(good[0 .. good.len - 1]) == null);
    try testing.expect(Digest.parse(good ++ "0") == null);
    try testing.expect(Digest.parse("b4" ++ good[2..]) == null);
    try testing.expect(Digest.parse(good[3..]) == null);
    var upper: [good.len]u8 = good.*;
    upper[5] = 'A';
    try testing.expect(Digest.parse(&upper) == null);
    var bad: [good.len]u8 = good.*;
    bad[10] = 'g';
    try testing.expect(Digest.parse(&bad) == null);
    try testing.expect(Digest.parse("") == null);
}

test "a prefix needs twelve hex digits and matches only digests that start with it" {
    // Goal: the prefix rules of the brief. Method: eleven, twelve and sixty-four digits, with
    // and without "b3:", and one digit changed.
    const digest = Digest.of("");
    const full = digest.hex();
    try testing.expect(Prefix.parse(full[0..11]) == null);
    const twelve = Prefix.parse(full[0..12]).?;
    try testing.expect(twelve.matches(digest));
    try testing.expect(twelve.complete() == null);
    const with_scheme = Prefix.parse(&digest.text()).?;
    try testing.expect(with_scheme.complete().?.eql(digest));
    var other: [12]u8 = full[0..12].*;
    other[11] = if (other[11] == '0') '1' else '0';
    try testing.expect(!Prefix.parse(&other).?.matches(digest));
    try testing.expect(Prefix.parse(full ++ "0") == null);
    try testing.expect(Prefix.parse("b3:") == null);
    try testing.expect(Prefix.parse("ABCDEF012345") == null);
}

test "a streamed hash equals the one-call hash for any split" {
    // Goal: the hasher the importer uses agrees with `of`. Method: every split of a short text.
    const data = "the quick brown fox jumps over the lazy dog";
    const whole = Digest.of(data);
    for (0..data.len + 1) |cut| {
        var hasher = Hasher.init();
        hasher.update(data[0..cut]);
        hasher.update(data[cut..]);
        try testing.expect(hasher.final().eql(whole));
    }
}
