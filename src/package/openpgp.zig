//! OpenPGP (RFC 4880, v4 packets) for the checked-in package test key: Ed25519 signatures in the
//! legacy EdDSA form (algorithm 22) that gpg, apt's sqv and rpm all read, and ASCII armor.
//!
//! This is the test key only. It signs what the unit tests and the VM check serve, so that the
//! signature code is exercised end to end. It vouches for nothing: a release is signed by the
//! owner's gpg key, in the two-round flow of `docs/releases/packaging.md`, and this module never
//! sees that key.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha1 = std.crypto.hash.Sha1;
const Output = std.Io.Writer.Allocating;

pub const Error = error{ OutOfMemory, WriteFailed, BadSignature };

/// The seed of the test key. It is public: anyone can sign as this key, which is why nothing
/// trusts it outside the tests and the VM check.
pub const test_seed = [32]u8{
    0xa0, 0x29, 0xd9, 0x0e, 0x65, 0xcf, 0x37, 0x50, 0x38, 0x7b, 0xcc, 0x76, 0xb9, 0x92, 0x5d, 0x5c,
    0x8e, 0xf9, 0x1d, 0x01, 0x88, 0x1f, 0xe5, 0x75, 0x3e, 0x34, 0xc4, 0x0a, 0x8d, 0xe1, 0x15, 0x7e,
};

const algorithm_eddsa: u8 = 22;
const hash_sha256: u8 = 8;
/// The curve OID of Ed25519 in OpenPGP, 1.3.6.1.4.1.11591.15.1, as stored (length, then bytes).
const ed25519_oid = [_]u8{ 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };

const packet_signature: u8 = 2;
const packet_public_key: u8 = 6;
const packet_user_id: u8 = 13;

pub const SignatureKind = enum(u8) {
    binary = 0x00,
    text = 0x01,
    positive_certification = 0x13,
};

pub fn test_key() Ed25519.KeyPair {
    // Fixed seed: a valid key, checked by the tests.
    return Ed25519.KeyPair.generateDeterministic(test_seed) catch unreachable;
}

fn put(writer: *std.Io.Writer, bytes: []const u8) Error!void {
    writer.writeAll(bytes) catch return error.WriteFailed;
}

fn put_int(writer: *std.Io.Writer, comptime T: type, value: T) Error!void {
    writer.writeInt(T, value, .big) catch return error.WriteFailed;
}

/// An OpenPGP multiprecision integer: bit count, then the value without leading zero bytes.
fn put_mpi(writer: *std.Io.Writer, value: []const u8) Error!void {
    var start: usize = 0;
    while (start < value.len and value[start] == 0) start += 1;
    const significant = value[start..];
    assert(significant.len > 0);
    const top_bits: u32 = 8 - @clz(significant[0]);
    try put_int(writer, u16, @intCast((significant.len - 1) * 8 + top_bits));
    try put(writer, significant);
}

/// The body of the public-key packet: version, creation time, algorithm, OID and the point.
fn public_key_body(public: [32]u8) [1 + 4 + 1 + ed25519_oid.len + 2 + 33]u8 {
    var body: [1 + 4 + 1 + ed25519_oid.len + 2 + 33]u8 = undefined;
    var at: usize = 0;
    body[at] = 4;
    at += 1;
    std.mem.writeInt(u32, body[at..][0..4], @intCast(constants.package_source_date_epoch), .big);
    at += 4;
    body[at] = algorithm_eddsa;
    at += 1;
    @memcpy(body[at..][0..ed25519_oid.len], &ed25519_oid);
    at += ed25519_oid.len;
    std.mem.writeInt(u16, body[at..][0..2], 263, .big); // 0x40 prefix + 32 bytes: 263 bits.
    at += 2;
    body[at] = 0x40; // Native point format marker.
    @memcpy(body[at + 1 ..][0..32], &public);
    at += 33;
    assert(at == body.len);
    return body;
}

/// The v4 fingerprint: SHA-1 of 0x99, the two-byte length and the public-key body.
pub fn fingerprint(public: [32]u8) [20]u8 {
    const body = public_key_body(public);
    var hash = Sha1.init(.{});
    hash.update(&[_]u8{ 0x99, 0, body.len });
    hash.update(&body);
    return hash.finalResult();
}

pub fn key_id(public: [32]u8) [8]u8 {
    return fingerprint(public)[12..20].*;
}

/// A new-format packet header: the tag and a one- or two-octet length (all ours are short).
fn put_packet(writer: *std.Io.Writer, tag_number: u8, body: []const u8) Error!void {
    assert(body.len < 8384);
    try put(writer, &.{0xc0 | tag_number});
    if (body.len < 192) {
        try put(writer, &.{@intCast(body.len)});
    } else {
        const adjusted = body.len - 192;
        const high: u8 = @intCast(adjusted >> 8);
        try put(writer, &.{ high + 192, @intCast(adjusted & 0xff) });
    }
    try put(writer, body);
}

/// The hashed part of a signature, from the version through the hashed subpackets.
fn signature_prefix(memory: Allocator, kind: SignatureKind, public: [32]u8) Error![]u8 {
    var out = Output.init(memory);
    const writer = &out.writer;
    try put(writer, &.{ 4, @backingInt(kind), algorithm_eddsa, hash_sha256 });
    const print = fingerprint(public);
    // Creation time (type 2) and issuer fingerprint (type 33), both hashed; a certification
    // also says what the key may do (key flags, type 27: certify and sign).
    const flags_bytes: u16 = if (kind == .positive_certification) 3 else 0;
    try put_int(writer, u16, 6 + 23 + flags_bytes);
    try put(writer, &.{ 5, 2 });
    try put_int(writer, u32, @intCast(constants.package_source_date_epoch));
    try put(writer, &.{ 22, 33, 4 });
    try put(writer, &print);
    if (kind == .positive_certification) try put(writer, &.{ 2, 27, 0x03 });
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// SHA-256 over the signed material, the signature prefix and the v4 trailer.
fn signature_digest(material: []const []const u8, prefix: []const u8) [32]u8 {
    var hash = Sha256.init(.{});
    for (material) |part| hash.update(part);
    hash.update(prefix);
    hash.update(&.{ 0x04, 0xff });
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, @intCast(prefix.len), .big);
    hash.update(&length);
    return hash.finalResult();
}

/// One signature packet over `material`, signed by `pair`.
fn signature_packet(
    memory: Allocator,
    pair: Ed25519.KeyPair,
    kind: SignatureKind,
    material: []const []const u8,
) Error![]u8 {
    const public = pair.public_key.toBytes();
    const prefix = try signature_prefix(memory, kind, public);
    const digest = signature_digest(material, prefix);
    // EdDSA in OpenPGP signs the hash digest itself as the message.
    const signature = (pair.sign(&digest, null) catch return error.BadSignature).toBytes();
    var body = Output.init(memory);
    const writer = &body.writer;
    try put(writer, prefix);
    try put_int(writer, u16, 10); // Unhashed: the issuer key id (type 16).
    try put(writer, &.{ 9, 16 });
    try put(writer, &key_id(public));
    try put(writer, digest[0..2]);
    try put_mpi(writer, signature[0..32]);
    try put_mpi(writer, signature[32..64]);
    var out = Output.init(memory);
    try put_packet(&out.writer, packet_signature, body.written());
    assert(out.written().len <= constants.openpgp_signature_bytes_max);
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// A binary detached signature (what `gpg --detach-sign` writes) over `data`.
pub fn sign_detached(memory: Allocator, pair: Ed25519.KeyPair, data: []const u8) Error![]u8 {
    return signature_packet(memory, pair, .binary, &.{data});
}

/// The public key as a transferable key: key packet, user id, self-certification.
pub fn public_key_packets(memory: Allocator, pair: Ed25519.KeyPair) Error![]u8 {
    const public = pair.public_key.toBytes();
    const body = public_key_body(public);
    const user = constants.package_test_key_user_id;
    var out = Output.init(memory);
    try put_packet(&out.writer, packet_public_key, &body);
    try put_packet(&out.writer, packet_user_id, user);
    var key_head: [3]u8 = .{ 0x99, 0, body.len };
    var user_head: [5]u8 = undefined;
    user_head[0] = 0xb4;
    std.mem.writeInt(u32, user_head[1..5], user.len, .big);
    const certification = try signature_packet(memory, pair, .positive_certification, &.{
        &key_head, &body, &user_head, user,
    });
    try put(&out.writer, certification);
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

const crc24_init: u32 = 0xb704ce;
const crc24_poly: u32 = 0x1864cfb;

fn crc24(bytes: []const u8) u32 {
    var crc: u32 = crc24_init;
    for (bytes) |byte| {
        crc ^= @as(u32, byte) << 16;
        for (0..8) |_| {
            crc <<= 1;
            if (crc & 0x1000000 != 0) crc ^= crc24_poly;
        }
    }
    return crc & 0xffffff;
}

/// ASCII armor with the given label (`PGP SIGNATURE`, `PGP PUBLIC KEY BLOCK`).
pub fn armor(memory: Allocator, label: []const u8, bytes: []const u8) Error![]u8 {
    assert(bytes.len <= constants.repo_metadata_bytes_max);
    var out = Output.init(memory);
    const writer = &out.writer;
    writer.print("-----BEGIN {s}-----\n\n", .{label}) catch return error.WriteFailed;
    const raw_per_line = constants.armor_line_bytes / 4 * 3;
    var at: usize = 0;
    while (at < bytes.len) : (at += raw_per_line) {
        const chunk = bytes[at..@min(bytes.len, at + raw_per_line)];
        var line: [constants.armor_line_bytes]u8 = undefined;
        writer.print("{s}\n", .{std.base64.standard.Encoder.encode(&line, chunk)}) catch
            return error.WriteFailed;
    }
    const crc = crc24(bytes);
    const crc_bytes = [3]u8{
        @intCast(crc >> 16),
        @intCast((crc >> 8) & 0xff),
        @intCast(crc & 0xff),
    };
    var crc_line: [4]u8 = undefined;
    writer.print("={s}\n-----END {s}-----\n", .{
        std.base64.standard.Encoder.encode(&crc_line, &crc_bytes), label,
    }) catch return error.WriteFailed;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// `gpg --clearsign`: the text, dash-escaped, then a text signature over its canonical form
/// (lines end CRLF with trailing blanks stripped; the last line ending is not signed).
pub fn clearsign(memory: Allocator, pair: Ed25519.KeyPair, text: []const u8) Error![]u8 {
    var canonical = Output.init(memory);
    var shown = Output.init(memory);
    try put(&shown.writer, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n");
    var body = text;
    if (std.mem.endsWith(u8, body, "\n")) body = body[0 .. body.len - 1];
    var lines = std.mem.splitScalar(u8, body, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try put(&canonical.writer, "\r\n");
        first = false;
        try put(&canonical.writer, std.mem.trimEnd(u8, line, " \t\r"));
        if (line.len > 0 and line[0] == '-') try put(&shown.writer, "- ");
        try put(&shown.writer, line);
        try put(&shown.writer, "\n");
    }
    const packet = try signature_packet(memory, pair, .text, &.{canonical.written()});
    try put(&shown.writer, try armor(memory, "PGP SIGNATURE", packet));
    return shown.toOwnedSlice() catch return error.OutOfMemory;
}

/// The fields of a signature packet this module wrote, for verification in tests.
const Parsed = struct { prefix: []const u8, r: [32]u8, s: [32]u8 };

fn read_mpi32(bytes: []const u8, at: *usize) ?[32]u8 {
    if (at.* + 2 > bytes.len) return null;
    const bits = std.mem.readInt(u16, bytes[at.*..][0..2], .big);
    const length = (@as(usize, bits) + 7) / 8;
    at.* += 2;
    if (length > 32 or at.* + length > bytes.len) return null;
    var value: [32]u8 = @splat(0);
    @memcpy(value[32 - length ..], bytes[at.*..][0..length]);
    at.* += length;
    return value;
}

fn parse(packet: []const u8) ?Parsed {
    if (packet.len < 2 or packet[0] != (0xc0 | packet_signature)) return null;
    var at: usize = 2;
    if (packet[1] >= 192) at = 3;
    if (at + 6 > packet.len) return null;
    const hashed_length = std.mem.readInt(u16, packet[at + 4 ..][0..2], .big);
    const prefix_end = at + 6 + hashed_length;
    if (prefix_end + 2 > packet.len) return null;
    const unhashed_length = std.mem.readInt(u16, packet[prefix_end..][0..2], .big);
    var cursor = prefix_end + 2 + unhashed_length + 2; // Skip the 16 bits of the digest.
    const r = read_mpi32(packet, &cursor) orelse return null;
    const s = read_mpi32(packet, &cursor) orelse return null;
    return .{ .prefix = packet[at..prefix_end], .r = r, .s = s };
}

/// Whether `packet` is a valid signature by `public` over `data` (binary kind) or over the
/// canonical text (`text` kind); checks with `std.crypto.sign.Ed25519`.
pub fn verify(packet: []const u8, material: []const []const u8, public: [32]u8) bool {
    const parsed = parse(packet) orelse return false;
    const digest = signature_digest(material, parsed.prefix);
    const key = Ed25519.PublicKey.fromBytes(public) catch return false;
    const signature = Ed25519.Signature.fromBytes(parsed.r ++ parsed.s);
    signature.verify(&digest, key) catch return false;
    return true;
}

test "the test key signs and std's Ed25519 verifies over the OpenPGP hash input" {
    // Goal: the signature is what RFC 4880 hashes: data, the signature prefix and the trailer.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const pair = test_key();
    const public = pair.public_key.toBytes();
    const data = "Release file bytes\n";
    const packet = try sign_detached(memory, pair, data);
    try std.testing.expect(verify(packet, &.{data}, public));
    try std.testing.expect(!verify(packet, &.{"Release file bytez\n"}, public));
    var damaged = try memory.dupe(u8, packet);
    damaged[damaged.len - 3] ^= 1;
    try std.testing.expect(!verify(damaged, &.{data}, public));
    try std.testing.expectEqualSlices(u8, try sign_detached(memory, pair, data), packet);
}

test "armor ends in the CRC-24 of RFC 4880 and wraps at the line width" {
    // Goal: the one published CRC-24 check value, and a block that gpg can dearmor.
    try std.testing.expectEqual(@as(u32, 0x21cf02), crc24("123456789"));
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const long: [100]u8 = @splat(0x5a);
    const text = try armor(arena.allocator(), "PGP SIGNATURE", &long);
    var lines = std.mem.splitScalar(u8, text, '\n');
    try std.testing.expectEqualStrings("-----BEGIN PGP SIGNATURE-----", lines.next().?);
    try std.testing.expectEqualStrings("", lines.next().?);
    try std.testing.expectEqual(@as(usize, constants.armor_line_bytes), lines.next().?.len);
    try std.testing.expectEqual(@as(usize, constants.armor_line_bytes), lines.next().?.len);
    try std.testing.expectEqual(@as(usize, 8), lines.next().?.len); // 100 bytes: 48 + 48 + 4.
    try std.testing.expect(lines.next().?[0] == '=');
    try std.testing.expectEqualStrings("-----END PGP SIGNATURE-----", lines.next().?);
}
