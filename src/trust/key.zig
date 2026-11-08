//! The key file (M8): an Ed25519 signing key, kept in one small text record in either of two
//! forms, and the public key's text and id. Pure: no file system, no host, no terminal. The
//! caller supplies the passphrase, the random bytes and the memory argon2id needs.
//!
//! The record is a fixed layout, written by `render` and read by `parse` only when it is
//! exactly what `render` writes (REVIEW.md, "Parse accepts only what render can write"):
//!
//!     .{
//!         .version = 1,
//!         .algorithm = "ed25519",
//!         .public = "zbx-ed25519:<64 hex>",
//!         .encryption = "argon2id-xchacha20poly1305",
//!         .kdf = .{ .t = 3, .m_kib = 65536, .p = 1, .salt = "<32 hex>" },
//!         .nonce = "<48 hex>",
//!         .sealed = "<96 hex>",
//!     }
//!
//! or, for a key made with `--no-passphrase`, `.encryption = "none"` and `.secret = "<64 hex>"`
//! in place of the last three lines. The 32-byte seed is sealed with XChaCha20-Poly1305 under a
//! key argon2id derives from the passphrase and the salt, with the public key's text as the
//! associated data, so a sealed seed moved under another public key does not open.
//!
//! The secret never leaves a function that needs it, and every buffer that held a seed, a
//! derived key or a passphrase is zeroed with `std.crypto.secureZero` before the function ends.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const argon2 = std.crypto.pwhash.argon2;
const Ed25519 = std.crypto.sign.Ed25519;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const version: u32 = 1;
pub const public_prefix = "zbx-ed25519:";
pub const encryption_passphrase_name = "argon2id-xchacha20poly1305";
/// What the id hashes before the public key: the context, then a NUL.
const id_context = "zbx-key\x00";

pub const Encryption = enum { passphrase, none };

pub const Kdf = struct {
    t: u32,
    m_kib: u32,
    p: u32,
    salt: [constants.key_salt_bytes]u8,
};

pub const Sealed = struct {
    kdf: Kdf,
    nonce: [constants.key_nonce_bytes]u8,
    /// The seed and its tag.
    sealed: [constants.key_sealed_bytes]u8,
};

pub const Body = union(Encryption) {
    passphrase: Sealed,
    none: [constants.key_seed_bytes]u8,
};

/// A key file, read or about to be written.
pub const Record = struct {
    public: [constants.key_public_bytes]u8,
    body: Body,
};

pub const ParseError = error{
    /// Not what `render` writes.
    Malformed,
    /// A `.version` above ours: a newer zbx wrote it.
    Newer,
};

pub const OpenError = error{
    /// The passphrase does not open the key, or the record was changed after it was sealed.
    WrongPassphrase,
    /// The seed opened but is not the key the record names.
    Mismatch,
    OutOfMemory,
};

pub const PublicText = [constants.key_public_text_bytes]u8;
pub const IdText = [constants.key_id_text_bytes]u8;
/// The `.pub` file: the public text and a newline.
pub const pub_file_bytes: u32 = constants.key_public_text_bytes + 1;

comptime {
    // The longest rendering (a sealed key with every number at its widest) fits the bound.
    const widest = 160 + 3 * 10 + 2 * constants.key_salt_bytes + 2 * constants.key_nonce_bytes +
        2 * constants.key_sealed_bytes + constants.key_public_text_bytes + 128;
    assert(widest <= constants.key_file_bytes_max);
}

// ---- Names ----

/// `[a-z0-9-]`, one to `key_name_bytes_max` bytes, and not starting with `-` (it would read as
/// an option).
pub fn name_valid(name: []const u8) bool {
    assert(constants.key_name_bytes_max > 0);
    if (name.len == 0) return false;
    if (name.len > constants.key_name_bytes_max) return false;
    if (name[0] == '-') return false;
    for (name) |byte| {
        const lower = byte >= 'a' and byte <= 'z';
        const digit = byte >= '0' and byte <= '9';
        if (!lower and !digit and byte != '-') return false;
    }
    return true;
}

// ---- The public key's text and id ----

pub fn public_text(public: [constants.key_public_bytes]u8) PublicText {
    assert(public_prefix.len == 12);
    var text: PublicText = undefined;
    @memcpy(text[0..public_prefix.len], public_prefix);
    text[public_prefix.len..].* = std.fmt.bytesToHex(public, .lower);
    return text;
}

/// The 32 bytes of `zbx-ed25519:<64 lowercase hex>`, or null for anything else.
pub fn parse_public_text(text: []const u8) ?[constants.key_public_bytes]u8 {
    assert(text.len <= constants.arg_bytes_max * 4);
    if (text.len != constants.key_public_text_bytes) return null;
    if (!std.mem.startsWith(u8, text, public_prefix)) return null;
    return hex_array(constants.key_public_bytes, text[public_prefix.len..]);
}

/// BLAKE3 over `"zbx-key\x00"` and the public key, as 64 hex digits. Compared in full, always.
pub fn key_id(public: [constants.key_public_bytes]u8) IdText {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(id_context);
    hasher.update(&public);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const text = std.fmt.bytesToHex(digest, .lower);
    assert(text.len == constants.key_id_text_bytes);
    return text;
}

/// The `.pub` file's bytes.
pub fn render_pub(public: [constants.key_public_bytes]u8) [pub_file_bytes]u8 {
    var bytes: [pub_file_bytes]u8 = undefined;
    bytes[0..constants.key_public_text_bytes].* = public_text(public);
    bytes[constants.key_public_text_bytes] = '\n';
    assert(bytes[bytes.len - 1] == '\n');
    return bytes;
}

/// The public key of a `.pub` file, only when it is exactly what `render_pub` writes.
pub fn parse_pub(bytes: []const u8) ?[constants.key_public_bytes]u8 {
    assert(bytes.len <= constants.key_file_bytes_max + 1);
    if (bytes.len != pub_file_bytes) return null;
    if (bytes[bytes.len - 1] != '\n') return null;
    return parse_public_text(bytes[0 .. bytes.len - 1]);
}

/// The public key a seed makes.
pub fn public_of_seed(seed: [constants.key_seed_bytes]u8) [constants.key_public_bytes]u8 {
    const pair = Ed25519.KeyPair.generateDeterministic(seed) catch {
        // A seed whose public key is the identity element: one in 2^250, never from the OS.
        return @as([constants.key_public_bytes]u8, @splat(0));
    };
    return pair.public_key.toBytes();
}

// ---- Hex ----

fn hex_array(comptime count: usize, text: []const u8) ?[count]u8 {
    assert(count > 0);
    if (text.len != count * 2) return null;
    for (text) |byte| {
        const digit = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!digit) return null;
    }
    var bytes: [count]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch return null;
    return bytes;
}

// ---- Render ----

/// The key file's text. `out` is `key_file_bytes_max` long; the text is a prefix of it.
pub fn render(record: *const Record, out: *[constants.key_file_bytes_max]u8) []const u8 {
    assert(record.body != .passphrase or kdf_valid(record.body.passphrase.kdf));
    var writer = std.Io.Writer.fixed(out);
    const public = public_text(record.public);
    writer.print(".{{\n    .version = {d},\n    .algorithm = \"ed25519\",\n", .{version}) catch
        unreachable; // The bound is checked at comptime above.
    writer.print("    .public = \"{s}\",\n", .{&public}) catch unreachable; // Same bound.
    switch (record.body) {
        .none => |seed| {
            const hex = std.fmt.bytesToHex(seed, .lower);
            writer.print("    .encryption = \"none\",\n    .secret = \"{s}\",\n}}\n", .{
                &hex,
            }) catch unreachable; // Same bound.
        },
        .passphrase => |sealed| render_sealed(&writer, &sealed),
    }
    const text = writer.buffered();
    assert(text.len <= constants.key_file_bytes_max);
    assert(text[text.len - 1] == '\n');
    return text;
}

fn render_sealed(writer: *std.Io.Writer, sealed: *const Sealed) void {
    const salt = std.fmt.bytesToHex(sealed.kdf.salt, .lower);
    const nonce = std.fmt.bytesToHex(sealed.nonce, .lower);
    const body = std.fmt.bytesToHex(sealed.sealed, .lower);
    writer.print("    .encryption = \"" ++ encryption_passphrase_name ++ "\",\n", .{}) catch
        unreachable; // The bound is checked at comptime above.
    writer.print(
        "    .kdf = .{{ .t = {d}, .m_kib = {d}, .p = {d}, .salt = \"{s}\" }},\n",
        .{ sealed.kdf.t, sealed.kdf.m_kib, sealed.kdf.p, &salt },
    ) catch unreachable; // Same bound.
    writer.print("    .nonce = \"{s}\",\n    .sealed = \"{s}\",\n}}\n", .{ &nonce, &body }) catch
        unreachable; // Same bound.
}

// ---- Parse ----

/// Reads the text front to back against the layout; nothing is skipped or guessed.
const Scanner = struct {
    text: []const u8,
    at: usize,

    fn literal(scanner: *Scanner, expected: []const u8) bool {
        assert(scanner.at <= scanner.text.len);
        const rest = scanner.text[scanner.at..];
        if (!std.mem.startsWith(u8, rest, expected)) return false;
        scanner.at += expected.len;
        return true;
    }

    /// A decimal number as `render` writes it: digits, no sign, no leading zero, at most ten
    /// digits and below 2^32.
    fn number(scanner: *Scanner) ?u32 {
        assert(scanner.at <= scanner.text.len);
        const start = scanner.at;
        while (scanner.at < scanner.text.len and std.ascii.isDigit(scanner.text[scanner.at])) {
            scanner.at += 1;
            if (scanner.at - start > 10) return null;
        }
        const digits = scanner.text[start..scanner.at];
        if (digits.len == 0) return null;
        if (digits.len > 1 and digits[0] == '0') return null;
        const value = std.fmt.parseInt(u32, digits, 10) catch return null;
        assert(value < (1 << 32));
        return value;
    }

    fn hex(scanner: *Scanner, comptime count: usize) ?[count]u8 {
        assert(scanner.at <= scanner.text.len);
        if (scanner.text.len - scanner.at < count * 2) return null;
        const bytes = hex_array(count, scanner.text[scanner.at..][0 .. count * 2]) orelse
            return null;
        scanner.at += count * 2;
        return bytes;
    }

    fn done(scanner: *const Scanner) bool {
        assert(scanner.at <= scanner.text.len);
        return scanner.at == scanner.text.len;
    }
};

/// Whether argon2id may run with these: every bound `parse` enforces.
pub fn kdf_valid(kdf: Kdf) bool {
    assert(constants.key_kdf_p_max == 1);
    if (kdf.t < 1 or kdf.t > constants.key_kdf_t_max) return false;
    if (kdf.p < 1 or kdf.p > constants.key_kdf_p_max) return false;
    if (kdf.m_kib < 8 * kdf.p or kdf.m_kib > constants.key_kdf_m_kib_max) return false;
    return true;
}

/// The key file at `text`, only when it is exactly what `render` writes, with parameters inside
/// their bounds. A `.version` above ours is `Newer`, whatever follows it.
pub fn parse(text: []const u8) ParseError!Record {
    if (text.len > constants.key_file_bytes_max) return error.Malformed;
    assert(text.len <= constants.key_file_bytes_max);
    var scanner: Scanner = .{ .text = text, .at = 0 };
    if (!scanner.literal(".{\n    .version = ")) return error.Malformed;
    const found = scanner.number() orelse return error.Malformed;
    if (found > version) return error.Newer;
    if (found != version) return error.Malformed;
    if (!scanner.literal(",\n    .algorithm = \"ed25519\",\n    .public = \"")) {
        return error.Malformed;
    }
    if (!scanner.literal(public_prefix)) return error.Malformed;
    const public = scanner.hex(constants.key_public_bytes) orelse return error.Malformed;
    if (!scanner.literal("\",\n    .encryption = \"")) return error.Malformed;
    if (scanner.literal("none\",\n    .secret = \"")) {
        const seed = scanner.hex(constants.key_seed_bytes) orelse return error.Malformed;
        if (!scanner.literal("\",\n}\n")) return error.Malformed;
        if (!scanner.done()) return error.Malformed;
        return .{ .public = public, .body = .{ .none = seed } };
    }
    const sealed = try parse_sealed(&scanner);
    return .{ .public = public, .body = .{ .passphrase = sealed } };
}

fn parse_sealed(scanner: *Scanner) ParseError!Sealed {
    assert(scanner.at <= scanner.text.len);
    if (!scanner.literal(encryption_passphrase_name ++ "\",\n    .kdf = .{ .t = ")) {
        return error.Malformed;
    }
    const t = scanner.number() orelse return error.Malformed;
    if (!scanner.literal(", .m_kib = ")) return error.Malformed;
    const m_kib = scanner.number() orelse return error.Malformed;
    if (!scanner.literal(", .p = ")) return error.Malformed;
    const p = scanner.number() orelse return error.Malformed;
    if (!scanner.literal(", .salt = \"")) return error.Malformed;
    const salt = scanner.hex(constants.key_salt_bytes) orelse return error.Malformed;
    if (!scanner.literal("\" },\n    .nonce = \"")) return error.Malformed;
    const nonce = scanner.hex(constants.key_nonce_bytes) orelse return error.Malformed;
    if (!scanner.literal("\",\n    .sealed = \"")) return error.Malformed;
    const body = scanner.hex(constants.key_sealed_bytes) orelse return error.Malformed;
    if (!scanner.literal("\",\n}\n")) return error.Malformed;
    if (!scanner.done()) return error.Malformed;
    const kdf: Kdf = .{ .t = t, .m_kib = m_kib, .p = p, .salt = salt };
    if (!kdf_valid(kdf)) return error.Malformed;
    return .{ .kdf = kdf, .nonce = nonce, .sealed = body };
}

// ---- Sealing and opening ----

/// argon2id over the passphrase and salt: the 32-byte key that seals or opens the seed. Runs in
/// full whatever the passphrase, so a wrong one costs what a right one does.
fn derive(
    allocator: std.mem.Allocator,
    passphrase: []const u8,
    kdf: Kdf,
) error{OutOfMemory}![32]u8 {
    assert(kdf_valid(kdf));
    assert(passphrase.len <= constants.passphrase_bytes_max);
    var derived: [32]u8 = undefined;
    const params: argon2.Params = .{ .t = kdf.t, .m = kdf.m_kib, .p = @intCast(kdf.p) };
    // One lane (`key_kdf_p_max`), so the `Io` is never used: no threads are started.
    argon2.kdf(allocator, &derived, passphrase, &kdf.salt, params, .argon2id, std.Io.failing) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // The parameters were checked above; the output is 32 bytes; one lane never waits.
            else => unreachable,
        }
    };
    return derived;
}

/// Seals `seed` for `public` under `passphrase`. `kdf` carries the salt, `nonce` is fresh from
/// the OS's random source (a fixed one only in a test).
pub fn seal(
    allocator: std.mem.Allocator,
    passphrase: []const u8,
    seed: [constants.key_seed_bytes]u8,
    public: [constants.key_public_bytes]u8,
    kdf: Kdf,
    nonce: [constants.key_nonce_bytes]u8,
) error{OutOfMemory}!Sealed {
    assert(passphrase.len > 0);
    assert(kdf_valid(kdf));
    var derived = try derive(allocator, passphrase, kdf);
    defer std.crypto.secureZero(u8, &derived);
    const associated = public_text(public);
    var sealed: Sealed = .{ .kdf = kdf, .nonce = nonce, .sealed = undefined };
    var tag: [constants.key_tag_bytes]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        sealed.sealed[0..constants.key_seed_bytes],
        &tag,
        &seed,
        &associated,
        nonce,
        derived,
    );
    sealed.sealed[constants.key_seed_bytes..].* = tag;
    return sealed;
}

/// The seed of `record`. A passphrase key needs `passphrase`; a `none` key ignores it. The
/// caller zeroes the seed after use.
pub fn open(
    allocator: std.mem.Allocator,
    record: *const Record,
    passphrase: ?[]const u8,
) OpenError![constants.key_seed_bytes]u8 {
    assert(record.body != .passphrase or kdf_valid(record.body.passphrase.kdf));
    var seed: [constants.key_seed_bytes]u8 = undefined;
    switch (record.body) {
        .none => |secret| seed = secret,
        .passphrase => |sealed| {
            const given = passphrase orelse return error.WrongPassphrase;
            seed = try open_sealed(allocator, given, record.public, &sealed);
        },
    }
    if (!std.mem.eql(u8, &public_of_seed(seed), &record.public)) {
        std.crypto.secureZero(u8, &seed);
        return error.Mismatch;
    }
    return seed;
}

fn open_sealed(
    allocator: std.mem.Allocator,
    passphrase: []const u8,
    public: [constants.key_public_bytes]u8,
    sealed: *const Sealed,
) OpenError![constants.key_seed_bytes]u8 {
    if (passphrase.len == 0) return error.WrongPassphrase;
    if (passphrase.len > constants.passphrase_bytes_max) return error.WrongPassphrase;
    var derived = try derive(allocator, passphrase, sealed.kdf);
    defer std.crypto.secureZero(u8, &derived);
    const associated = public_text(public);
    var seed: [constants.key_seed_bytes]u8 = undefined;
    const tag = sealed.sealed[constants.key_seed_bytes..][0..constants.key_tag_bytes].*;
    XChaCha20Poly1305.decrypt(
        &seed,
        sealed.sealed[0..constants.key_seed_bytes],
        tag,
        &associated,
        sealed.nonce,
        derived,
    ) catch {
        std.crypto.secureZero(u8, &seed);
        return error.WrongPassphrase;
    };
    return seed;
}

// ---- Permissions ----

/// Whether a mode is too open for a secret key, its directory or a passphrase file: any bit for
/// group or others.
pub fn mode_too_open(mode: u16) bool {
    assert(mode <= 0o7777);
    return mode & 0o077 != 0;
}
