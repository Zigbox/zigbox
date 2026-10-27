//! The digests of an image: SHA-256, written `sha256:` and 64 lowercase hex digits, as the OCI
//! image and distribution specifications name every manifest and blob. They are not the store's
//! digests (`store/digest.zig`, BLAKE3 with a `b3:` prefix): these identify what a registry
//! serves, and are checked against the bytes that came, before anything is used.
//!
//! There is one spelling of a digest. Uppercase hex and other algorithms are refused, so that two
//! texts never name one digest and a lock file compares by bytes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const Sha256Hash = std.crypto.hash.sha2.Sha256;

pub const text_prefix = "sha256:";

pub const Sha256 = struct {
    bytes: [constants.oci_digest_bytes]u8,

    /// The digest of `data`, in one call.
    pub fn of(data: []const u8) Sha256 {
        assert(@sizeOf(Sha256) == constants.oci_digest_bytes);
        var digest: Sha256 = undefined;
        Sha256Hash.hash(data, &digest.bytes, .{});
        return digest;
    }

    pub fn eql(first: Sha256, second: Sha256) bool {
        assert(first.bytes.len == constants.oci_digest_bytes);
        assert(second.bytes.len == constants.oci_digest_bytes);
        return std.mem.eql(u8, &first.bytes, &second.bytes);
    }

    /// Lowercase hex, 64 digits.
    pub fn hex(digest: Sha256) [constants.oci_digest_hex_bytes]u8 {
        assert(digest.bytes.len == constants.oci_digest_bytes);
        const lower = std.fmt.bytesToHex(digest.bytes, .lower);
        assert(lower.len == constants.oci_digest_hex_bytes);
        return lower;
    }

    /// "sha256:" and the hex, 71 bytes.
    pub fn text(digest: Sha256) [constants.oci_digest_text_bytes]u8 {
        assert(text_prefix.len + constants.oci_digest_hex_bytes == constants.oci_digest_text_bytes);
        var out: [constants.oci_digest_text_bytes]u8 = undefined;
        @memcpy(out[0..text_prefix.len], text_prefix);
        out[text_prefix.len..][0..constants.oci_digest_hex_bytes].* = digest.hex();
        assert(std.mem.startsWith(u8, &out, text_prefix));
        return out;
    }

    /// The full text form; null for anything else (another algorithm, wrong length, uppercase).
    pub fn parse(source: []const u8) ?Sha256 {
        assert(source.len <= constants.arg_bytes_max * 4);
        assert(text_prefix.len == 7);
        if (source.len != constants.oci_digest_text_bytes) return null;
        if (!std.mem.startsWith(u8, source, text_prefix)) return null;
        return from_hex(source[text_prefix.len..]);
    }

    /// 64 lowercase hex digits; null for anything else.
    pub fn from_hex(source: []const u8) ?Sha256 {
        assert(source.len <= constants.arg_bytes_max * 4);
        if (source.len != constants.oci_digest_hex_bytes) return null;
        var digest: Sha256 = undefined;
        for (0..constants.oci_digest_bytes) |index| {
            const high = hex_value(source[index * 2]) orelse return null;
            const low = hex_value(source[index * 2 + 1]) orelse return null;
            digest.bytes[index] = high << 4 | low;
        }
        assert(std.mem.eql(u8, &digest.hex(), source));
        return digest;
    }
};

/// Hashes bytes as they arrive, so a blob is checked without being held in memory.
pub const Hasher = struct {
    state: Sha256Hash,
    length: u64,

    pub fn init() Hasher {
        assert(Sha256Hash.digest_length == constants.oci_digest_bytes);
        return .{ .state = Sha256Hash.init(.{}), .length = 0 };
    }

    pub fn update(hasher: *Hasher, bytes: []const u8) void {
        assert(hasher.length <= std.math.maxInt(u64) - bytes.len);
        hasher.state.update(bytes);
        hasher.length += bytes.len;
    }

    pub fn final(hasher: *Hasher) Sha256 {
        assert(hasher.length < std.math.maxInt(u64));
        var digest: Sha256 = undefined;
        hasher.state.final(&digest.bytes);
        assert(digest.bytes.len == constants.oci_digest_bytes);
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
    if (value) |found| assert(found < 16);
    return value;
}

test "a digest round-trips through its text, and has one spelling" {
    // Goal: parse and text are inverse; uppercase, other algorithms, short and long are refused.
    const empty = Sha256.of("");
    const known = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    try std.testing.expectEqualStrings(known, &empty.text());
    try std.testing.expect(Sha256.parse(known).?.eql(empty));
    const upper = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    try std.testing.expect(Sha256.parse(upper) == null);
    try std.testing.expect(Sha256.parse(known[0 .. known.len - 1]) == null);
    try std.testing.expect(Sha256.parse(known ++ "0") == null);
    try std.testing.expect(Sha256.parse("sha512:" ++ known[7..]) == null);
    try std.testing.expect(Sha256.parse(known[7..]) == null);
    try std.testing.expect(Sha256.parse("") == null);
    var bad = known.*;
    bad[20] = 'g';
    try std.testing.expect(Sha256.parse(&bad) == null);
}

test "the streaming hasher agrees with the one-call digest for any split" {
    // Goal: a blob hashed in pieces has the digest of the whole. Method: every split point of a
    // short text, plus the empty input.
    const data = "the quick brown fox jumps over the lazy dog";
    const whole = Sha256.of(data);
    for (0..data.len + 1) |split| {
        var hasher = Hasher.init();
        hasher.update(data[0..split]);
        hasher.update(data[split..]);
        try std.testing.expectEqual(@as(u64, data.len), hasher.length);
        try std.testing.expect(hasher.final().eql(whole));
    }
    var empty = Hasher.init();
    try std.testing.expect(empty.final().eql(Sha256.of("")));
}
