//! Tests for `dsse.zig`: PAE against DSSE's published vector, an envelope against a reference
//! implementation's output, signatures that fail on any flipped byte, every spelling parse
//! refuses, and the payload bound at the bound and one past.

const std = @import("std");
const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const constants = @import("../constants.zig");
const dsse = @import("dsse.zig");

/// The seed of the reference output below: bytes 1 to 32.
fn reference_seed() [constants.key_seed_bytes]u8 {
    var seed: [constants.key_seed_bytes]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @intCast(index + 1);
    return seed;
}

/// Captured once with securesystemslib 1.6.0 (`securesystemslib.dsse.Envelope` signing with
/// `CryptoSigner` over `cryptography`'s Ed25519 key, from the same seed), in this container
/// on 2026-11-08: the payload below, and the `payload` and `sig` members of its envelope.
const reference_payload =
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"tree\"," ++
    "\"digest\":{\"zbxTree\":\"030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc" ++
    "\"}},{\"name\":\"result\",\"digest\":{\"zbxResult\":" ++
    "\"05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a\"}}]," ++
    "\"predicateType\":\"https://zigbox.org/attestation/sign/v1\"," ++
    "\"predicate\":{\"signedAt\":\"2026-11-08T10:00:00Z\"}}";
const reference_public = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
const reference_payload_base64 =
    "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJq" ++
    "ZWN0IjpbeyJuYW1lIjoidHJlZSIs" ++
    "ImRpZ2VzdCI6eyJ6YnhUcmVlIjoiMDMwYTExMTgxZjI2MmQzNDNiNDI0OTUwNTc1" ++
    "ZTY1NmM3MzdhODE4ODhmOTY5ZGE0" ++
    "YWJiMmI5YzBjN2NlZDVkYyJ9fSx7Im5hbWUiOiJyZXN1bHQiLCJkaWdlc3QiOnsi" ++
    "emJ4UmVzdWx0IjoiMDUxMDFiMjYz" ++
    "MTNjNDc1MjVkNjg3MzdlODk5NDlmYWFiNWMwY2JkNmUxZWNmNzAyMGQxODIzMmUz" ++
    "OTQ0NGY1YSJ9fV0sInByZWRpY2F0" ++
    "ZVR5cGUiOiJodHRwczovL3ppZ2JveC5vcmcvYXR0ZXN0YXRpb24vc2lnbi92MSIs" ++
    "InByZWRpY2F0ZSI6eyJzaWduZWRB" ++
    "dCI6IjIwMjYtMTEtMDhUMTA6MDA6MDBaIn19";
const reference_signature =
    "lypgEFAW0Qf8Eg33pI1pYYkbREkBaKlPY0ojgd5VzV2cprnXjqqoApz0U0gruZ5W9bDfM7aojzsnploVL7zXBw==";

/// The envelope `reference_*` make, in our canonical form (the key id is ours: the full public
/// text).
pub const reference_envelope =
    "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"" ++
    reference_payload_base64 ++ "\",\"signatures\":[{\"keyid\":\"zbx-ed25519:" ++
    reference_public ++ "\",\"sig\":\"" ++ reference_signature ++ "\"}]}";

const Fixture = struct {
    work: *dsse.Work,
    out: []u8,

    fn init() !Fixture {
        const work = try testing.allocator.create(dsse.Work);
        errdefer testing.allocator.destroy(work);
        const out = try testing.allocator.alloc(u8, constants.envelope_bytes_max);
        return .{ .work = work, .out = out };
    }

    fn deinit(self: *Fixture) void {
        testing.allocator.destroy(self.work);
        testing.allocator.free(self.out);
    }
};

test "PAE matches DSSE's published test vector" {
    // Goal: the signed bytes are DSSE's. Method: the specification's example, byte for byte,
    // and a body with a multi-digit length.
    var buffer: [dsse.pae_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(
        "DSSEv1 29 http://example.com/HelloWorld 11 hello world",
        dsse.pae(&buffer, "http://example.com/HelloWorld", "hello world"),
    );
    try testing.expectEqualStrings("DSSEv1 3 abc 0 ", dsse.pae(&buffer, "abc", ""));
    const body: [123]u8 = @splat('x');
    try testing.expectEqualStrings(
        "DSSEv1 28 application/vnd.in-toto+json 123 " ++ body,
        dsse.pae(&buffer, dsse.payload_type, &body),
    );
}

test "an envelope we sign equals the reference implementation's output" {
    // Goal: REVIEW.md's "checked against real output". Method: sign the reference payload
    // with the reference seed; the result must be the reference's `payload` and `sig`.
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const text = try dsse.sign(fixture.work, fixture.out, reference_seed(), reference_payload);
    try testing.expectEqualStrings(reference_envelope, text);

    const envelope = try dsse.parse(fixture.work, text);
    try testing.expectEqualStrings(reference_payload, envelope.payload);
    try dsse.verify(fixture.work, &envelope);
    try testing.expectEqualStrings(text, dsse.render(fixture.work, fixture.out, &envelope));
}

test "signing the same payload twice gives the same bytes" {
    // Goal: Ed25519 is deterministic, so a record can tell "same line" from "new line".
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const first = try dsse.sign(fixture.work, fixture.out, reference_seed(), "{}");
    var copy: [1024]u8 = undefined;
    @memcpy(copy[0..first.len], first);
    const second = try dsse.sign(fixture.work, fixture.out, reference_seed(), "{}");
    try testing.expectEqualStrings(copy[0..first.len], second);
}

test "a signature fails on any flipped byte of the payload, type, key or signature" {
    // Goal: every input the signature covers matters. Method: flip each byte of each of them
    // in turn and verify; also verify against another payload type's PAE.
    var fixture = try Fixture.init();
    defer fixture.deinit();
    _ = try dsse.sign(fixture.work, fixture.out, reference_seed(), "payload bytes");
    var envelope = try dsse.parse(fixture.work, try dsse.sign(
        fixture.work,
        fixture.out,
        reference_seed(),
        "payload bytes",
    ));
    try dsse.verify(fixture.work, &envelope);

    var payload: [13]u8 = undefined;
    @memcpy(&payload, envelope.payload);
    for (0..payload.len) |index| {
        var changed = payload;
        changed[index] ^= 0x01;
        envelope.payload = &changed;
        try testing.expectError(error.BadSignature, dsse.verify(fixture.work, &envelope));
    }
    envelope.payload = &payload;
    try dsse.verify(fixture.work, &envelope);

    const public = envelope.public;
    for (0..public.len) |index| {
        envelope.public[index] ^= 0x01;
        try testing.expectError(error.BadSignature, dsse.verify(fixture.work, &envelope));
        envelope.public = public;
    }
    const signature = envelope.signature;
    for (0..signature.len) |index| {
        envelope.signature[index] ^= 0x01;
        try testing.expectError(error.BadSignature, dsse.verify(fixture.work, &envelope));
        envelope.signature = signature;
    }

    // The payload type is covered: a signature made over another type's PAE does not verify.
    const pair = try Ed25519.KeyPair.generateDeterministic(reference_seed());
    var buffer: [dsse.pae_bytes_max]u8 = undefined;
    const other = dsse.pae(&buffer, "application/other", &payload);
    envelope.signature = (try pair.sign(other, null)).toBytes();
    try testing.expectError(error.BadSignature, dsse.verify(fixture.work, &envelope));
}

test "parse refuses every spelling render does not write" {
    // Goal: parse accepts only what render writes. Method: damage the reference envelope one
    // way at a time and expect `Malformed` for each.
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const keyid_text = "\"zbx-ed25519:" ++ reference_public ++ "\"";
    const damaged = [_][]const u8{
        "",
        "{}",
        "[]",
        "null",
        reference_envelope ++ " ",
        reference_envelope ++ "{}",
        " " ++ reference_envelope,
        // Another payload type.
        "{\"payloadType\":\"text/plain\",\"payload\":\"" ++ reference_payload_base64 ++
            "\",\"signatures\":[]}",
        // Members swapped, repeated, missing and extra.
        "{\"payload\":\"\",\"payloadType\":\"application/vnd.in-toto+json\",\"signatures\":[]}",
        "{\"payloadType\":\"application/vnd.in-toto+json\",\"payloadType\":\"x\"}",
        "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\"}",
        "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":[]}",
        reference_envelope[0 .. reference_envelope.len - 1] ++ ",\"extra\":1}",
        // Two signatures, a repeated key id, a missing sig.
        reference_envelope[0 .. reference_envelope.len - 2] ++ ",{\"keyid\":" ++ keyid_text ++
            ",\"sig\":\"" ++ reference_signature ++ "\"}]}",
        "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":" ++
            "[{\"keyid\":" ++ keyid_text ++ ",\"keyid\":" ++ keyid_text ++ "}]}",
        "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":" ++
            "[{\"keyid\":" ++ keyid_text ++ "}]}",
    };
    for (damaged) |text| {
        try testing.expectError(error.Malformed, dsse.parse(fixture.work, text));
    }
}

fn envelope_with(
    allocator: std.mem.Allocator,
    payload_text: []const u8,
    keyid: []const u8,
    signature_text: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"{s}\"," ++
            "\"signatures\":[{{\"keyid\":\"{s}\",\"sig\":\"{s}\"}}]}}",
        .{ payload_text, keyid, signature_text },
    );
}

test "parse refuses a key id, base64 or signature that is not canonical" {
    // Goal: base64 is `standard` with padding and nothing else; the key id is the full public
    // text in lowercase. Method: change one thing at a time.
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const good_keyid = "zbx-ed25519:" ++ reference_public;
    const good = try envelope_with(testing.allocator, "aGk=", good_keyid, reference_signature);
    defer testing.allocator.free(good);
    _ = try dsse.parse(fixture.work, good);

    const upper_keyid = "zbx-ed25519:" ++
        "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664";
    const cases = [_]struct { payload: []const u8, keyid: []const u8, sig: []const u8 }{
        .{ .payload = "aGk", .keyid = good_keyid, .sig = reference_signature }, // No padding.
        .{ .payload = "aGl=", .keyid = good_keyid, .sig = reference_signature }, // Stray bits.
        .{ .payload = "aG k=", .keyid = good_keyid, .sig = reference_signature },
        .{ .payload = "aGk=\n", .keyid = good_keyid, .sig = reference_signature },
        .{ .payload = "a-k=", .keyid = good_keyid, .sig = reference_signature }, // URL alphabet.
        .{ .payload = "aGk=", .keyid = upper_keyid, .sig = reference_signature },
        .{ .payload = "aGk=", .keyid = "zbx-ed25519:00", .sig = reference_signature },
        .{ .payload = "aGk=", .keyid = good_keyid[1..], .sig = reference_signature },
        .{ .payload = "aGk=", .keyid = good_keyid, .sig = reference_signature[4..] },
        .{ .payload = "aGk=", .keyid = good_keyid, .sig = reference_signature[0..86] },
        // The last character of a 64-byte signature's base64 carries two stray bits.
        .{ .payload = "aGk=", .keyid = good_keyid, .sig = reference_signature[0..85] ++ "x==" },
    };
    for (cases) |case| {
        const text = try envelope_with(testing.allocator, case.payload, case.keyid, case.sig);
        defer testing.allocator.free(text);
        try testing.expectError(error.Malformed, dsse.parse(fixture.work, text));
    }
}

test "the payload bound: at statement_bytes_max it signs and parses, one past it does not" {
    // Goal: `statement_bytes_max` and `envelope_bytes_max` hold at the edge. Method: a payload
    // of exactly the bound makes the longest envelope; one byte more is refused by `sign`, and
    // by `parse` of an envelope written by hand; so is text one byte over the envelope bound.
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const payload = try testing.allocator.alloc(u8, constants.statement_bytes_max + 1);
    defer testing.allocator.free(payload);
    @memset(payload, 'a');

    const at = payload[0..constants.statement_bytes_max];
    const text = try dsse.sign(fixture.work, fixture.out, reference_seed(), at);
    try testing.expect(text.len <= constants.envelope_bytes_max);
    const envelope = try dsse.parse(fixture.work, text);
    try testing.expectEqualSlices(u8, at, envelope.payload);
    try dsse.verify(fixture.work, &envelope);

    try testing.expectError(
        error.PayloadTooLarge,
        dsse.sign(fixture.work, fixture.out, reference_seed(), payload),
    );

    // By hand: the base64 of one byte more, under a valid-looking key id and signature.
    const encoded = try testing.allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(payload.len),
    );
    defer testing.allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, payload);
    const over = try envelope_with(
        testing.allocator,
        encoded,
        "zbx-ed25519:" ++ reference_public,
        reference_signature,
    );
    defer testing.allocator.free(over);
    try testing.expectError(error.Malformed, dsse.parse(fixture.work, over));

    const long = try testing.allocator.alloc(u8, constants.envelope_bytes_max + 1);
    defer testing.allocator.free(long);
    @memset(long, ' ');
    try testing.expectError(error.Malformed, dsse.parse(fixture.work, long));
}
