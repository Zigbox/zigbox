//! DSSE envelopes (docs/briefs/M8-trust.md, "What is signed"): the payload type, the payload's
//! base64, and one signature over DSSE's PAE, in the canonical JSON form of `json.zig`.
//!
//!   {"payloadType":"application/vnd.in-toto+json","payload":"<base64>",
//!    "signatures":[{"keyid":"zbx-ed25519:<64 hex>","sig":"<base64>"}]}
//!
//! (Shown with whitespace; the envelope has none.) One envelope holds one signature; a second
//! key makes a second envelope. `keyid` is DSSE's unauthenticated hint, and we set it to the
//! full public text. Base64 is `std.base64.standard`, with padding, and nothing else is
//! accepted: parse decodes, re-encodes and compares, so a non-canonical spelling (stray bits in
//! the last character, say) is refused. Verification checks the signature over the PAE of the
//! payload bytes as stored, and nothing is re-serialized before the check. Whoever parses the
//! payload does so after `verify`, never before.
//!
//! Parse accepts only what `render` writes (REVIEW.md): the members are read in the writer's
//! order, each key token is compared to the expected name, and the root is followed by `.end`.

const std = @import("std");
const assert = std.debug.assert;
const Ed25519 = std.crypto.sign.Ed25519;
const constants = @import("../constants.zig");
const json = @import("json.zig");
const key = @import("key.zig");

pub const payload_type = "application/vnd.in-toto+json";
pub const signature_bytes = Ed25519.Signature.encoded_length;
/// `"DSSEv1 " LEN " " type " " LEN " "` around the body: the type, two numbers of at most 20
/// digits, and the spaces.
pub const pae_overhead_bytes: u32 = 6 + 1 + 20 + 1 + payload_type.len + 1 + 20 + 1;
pub const pae_bytes_max: u32 = pae_overhead_bytes + constants.statement_bytes_max;
const signature_base64_bytes: u32 = ((signature_bytes + 2) / 3) * 4;

pub const ParseError = error{
    /// The text is not an envelope in the form `render` writes, is too long, carries a payload
    /// over `statement_bytes_max`, or has another payload type or more than one signature.
    Malformed,
};

pub const SignError = error{
    /// The payload is over `statement_bytes_max`.
    PayloadTooLarge,
    /// The seed's key cannot sign (an identity-element public key: never from the OS).
    KeyUnusable,
};

pub const VerifyError = error{BadSignature};

/// A parsed envelope. `payload` points into the `Work` it was parsed with.
pub const Envelope = struct {
    payload: []const u8,
    public: [constants.key_public_bytes]u8,
    signature: [signature_bytes]u8,
};

/// The buffers parse, sign, render and verify need, so no call allocates. About 0.5 MiB: the
/// caller makes one (heap or static) and reuses it.
pub const Work = struct {
    /// Strings the reader decodes: the largest is the payload's base64.
    scratch: [constants.payload_base64_bytes_max]u8,
    /// The decoded payload of a parsed envelope.
    payload: [constants.statement_bytes_max]u8,
    pae: [pae_bytes_max]u8,
};

comptime {
    // The longest envelope: every member name, the type, a full payload, one key id, one sig.
    const framing = "{\"payloadType\":\"\",\"payload\":\"\",\"signatures\":[{\"keyid\":\"\"," ++
        "\"sig\":\"\"}]}";
    const longest = framing.len + payload_type.len + constants.payload_base64_bytes_max +
        constants.key_public_text_bytes + signature_base64_bytes;
    assert(longest <= constants.envelope_bytes_max);
    assert(constants.envelope_bytes_max >= longest);
    assert(signature_bytes == 64);
    assert(pae_bytes_max >= constants.statement_bytes_max);
}

/// DSSE's PAE: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, lengths in ASCII decimal
/// with no leading zero. The bytes that are signed.
pub fn pae(buffer: []u8, kind: []const u8, body: []const u8) []const u8 {
    assert(body.len <= constants.statement_bytes_max);
    assert(buffer.len >= pae_overhead_bytes - payload_type.len + kind.len + body.len);
    const text = std.fmt.bufPrint(
        buffer,
        "DSSEv1 {d} {s} {d} ",
        .{ kind.len, kind, body.len },
    ) catch unreachable; // The assertion above sized the buffer for the header and the body.
    @memcpy(buffer[text.len..][0..body.len], body);
    return buffer[0 .. text.len + body.len];
}

/// Signs `payload` with the key of `seed` and returns the envelope's bytes, rendered into
/// `out` (at least `envelope_bytes_max`). Ed25519 is deterministic, so the same key and payload
/// give the same bytes.
pub fn sign(
    work: *Work,
    out: []u8,
    seed: [constants.key_seed_bytes]u8,
    payload: []const u8,
) SignError![]const u8 {
    assert(out.len >= constants.envelope_bytes_max);
    if (payload.len > constants.statement_bytes_max) return error.PayloadTooLarge;
    const pair = Ed25519.KeyPair.generateDeterministic(seed) catch return error.KeyUnusable;
    const signed_bytes = pae(&work.pae, payload_type, payload);
    const signature = pair.sign(signed_bytes, null) catch return error.KeyUnusable;
    const envelope: Envelope = .{
        .payload = payload,
        .public = pair.public_key.toBytes(),
        .signature = signature.toBytes(),
    };
    const text = render(work, out, &envelope);
    verify(work, &envelope) catch unreachable; // We just made this signature with the key.
    return text;
}

/// The bytes of `envelope` in canonical form. `out` is at least `envelope_bytes_max`.
pub fn render(work: *Work, out: []u8, envelope: *const Envelope) []const u8 {
    assert(out.len >= constants.envelope_bytes_max);
    assert(envelope.payload.len <= constants.statement_bytes_max);
    const encoded = std.base64.standard.Encoder.encode(&work.scratch, envelope.payload);
    var signature_text: [signature_base64_bytes]u8 = undefined;
    const signature_encoded = std.base64.standard.Encoder.encode(
        &signature_text,
        &envelope.signature,
    );
    assert(signature_encoded.len == signature_base64_bytes);
    const public = key.public_text(envelope.public);
    var writer = json.Writer.init(out[0..constants.envelope_bytes_max]);
    // Every step fits: `envelope_bytes_max` is the comptime-checked longest envelope.
    write_envelope(&writer, encoded, &public, signature_encoded) catch unreachable;
    const text = writer.finish();
    assert(text.len <= constants.envelope_bytes_max);
    return text;
}

fn write_envelope(
    writer: *json.Writer,
    payload_text: []const u8,
    public_text: []const u8,
    signature_text: []const u8,
) json.WriteError!void {
    try writer.begin_object();
    try writer.member_string("payloadType", payload_type);
    try writer.member_string("payload", payload_text);
    try writer.member_array("signatures");
    try writer.begin_object();
    try writer.member_string("keyid", public_text);
    try writer.member_string("sig", signature_text);
    try writer.end_object();
    try writer.end_array();
    try writer.end_object();
}

/// Checks the signature over the PAE of the payload bytes as stored. Parse the payload only
/// after this returns.
pub fn verify(work: *Work, envelope: *const Envelope) VerifyError!void {
    assert(envelope.payload.len <= constants.statement_bytes_max);
    const signed_bytes = pae(&work.pae, payload_type, envelope.payload);
    const public = Ed25519.PublicKey.fromBytes(envelope.public) catch return error.BadSignature;
    const signature = Ed25519.Signature.fromBytes(envelope.signature);
    signature.verify(signed_bytes, public) catch return error.BadSignature;
}

// ---- Parse ----

/// Reads one envelope. The signature is not checked: call `verify`.
pub fn parse(work: *Work, text: []const u8) ParseError!Envelope {
    if (text.len > constants.envelope_bytes_max) return error.Malformed;
    var reader = json.Reader.init(text);
    const scratch: []u8 = &work.scratch;
    try expect(&reader, scratch, .object_begin);
    try expect_key(&reader, scratch, "payloadType");
    const kind = try read_string(&reader, scratch);
    if (!std.mem.eql(u8, kind, payload_type)) return error.Malformed;
    try expect_key(&reader, scratch, "payload");
    const payload = try decode_payload(work, try read_string(&reader, scratch));
    try expect_key(&reader, scratch, "signatures");
    try expect(&reader, scratch, .array_begin);
    try expect(&reader, scratch, .object_begin);
    try expect_key(&reader, scratch, "keyid");
    const public = key.parse_public_text(try read_string(&reader, scratch)) orelse
        return error.Malformed;
    try expect_key(&reader, scratch, "sig");
    const signature = try decode_signature(try read_string(&reader, scratch));
    try expect(&reader, scratch, .object_end);
    try expect(&reader, scratch, .array_end); // A second signature would be a second object.
    try expect(&reader, scratch, .object_end);
    try expect(&reader, scratch, .end);
    return .{ .payload = payload, .public = public, .signature = signature };
}

fn decode_payload(work: *Work, encoded: []const u8) ParseError![]const u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return error.Malformed;
    if (size > constants.statement_bytes_max) return error.Malformed;
    decoder.decode(work.payload[0..size], encoded) catch return error.Malformed;
    // Canonical base64 only: re-encode into the space after the decoded bytes' own text.
    if (!base64_canonical(work.payload[0..size], encoded)) return error.Malformed;
    return work.payload[0..size];
}

fn decode_signature(encoded: []const u8) ParseError![signature_bytes]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return error.Malformed;
    if (size != signature_bytes) return error.Malformed;
    var signature: [signature_bytes]u8 = undefined;
    decoder.decode(&signature, encoded) catch return error.Malformed;
    if (!base64_canonical(&signature, encoded)) return error.Malformed;
    return signature;
}

/// Whether `encoded` is exactly what the encoder writes for `decoded`, compared in pieces so
/// no second buffer is needed.
fn base64_canonical(decoded: []const u8, encoded: []const u8) bool {
    const encoder = std.base64.standard.Encoder;
    assert(decoded.len <= constants.statement_bytes_max);
    if (encoder.calcSize(decoded.len) != encoded.len) return false;
    var chunk: [192]u8 = undefined; // 144 bytes of input encode to 192 characters.
    var at: usize = 0;
    while (at < decoded.len) {
        const take = @min(decoded.len - at, 144);
        const part = encoder.encode(&chunk, decoded[at..][0..take]);
        const offset = @divExact(at, 3) * 4;
        if (!std.mem.eql(u8, part, encoded[offset..][0..part.len])) return false;
        at += take;
    }
    return true;
}

// ---- Schema helpers (shared with statement.zig) ----

pub fn expect(reader: *json.Reader, scratch: []u8, want: std.meta.Tag(json.Token)) ParseError!void {
    const token = reader.next(scratch) catch return error.Malformed;
    if (std.meta.activeTag(token) != want) return error.Malformed;
}

/// The next token must be the member name `name`: the schema's order, and no other.
pub fn expect_key(reader: *json.Reader, scratch: []u8, name: []const u8) ParseError!void {
    const token = reader.next(scratch) catch return error.Malformed;
    switch (token) {
        .key => |found| if (!std.mem.eql(u8, found, name)) return error.Malformed,
        else => return error.Malformed,
    }
}

pub fn read_string(reader: *json.Reader, scratch: []u8) ParseError![]const u8 {
    const token = reader.next(scratch) catch return error.Malformed;
    switch (token) {
        .string => |value| return value,
        else => return error.Malformed,
    }
}
