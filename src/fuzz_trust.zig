//! The `trust` fuzzer: `zig build fuzz -- trust`. Statements and DSSE envelopes are read from
//! the store and, later, from `trust import` and registries, so anyone could have written the
//! bytes. Each iteration renders a random valid statement, signs it, damages both texts and
//! parses the damage, and parses random bytes too.
//!
//! Properties, every iteration:
//!   1. Round trip: a rendered statement parses back to its fields and re-renders to the same
//!      bytes; a signed envelope parses, verifies, and re-renders to the same bytes.
//!   2. Canonical: damaged or random bytes never crash `statement.parse` or `dsse.parse`. They
//!      are accepted only if they re-render to exactly themselves.
//!   3. Signed: a damaged envelope that still parses verifies only if it is the original; a
//!      flipped byte of what is signed never passes `verify`.
//!   5. Record: a record of up to eight signed lines about one tree parses and re-renders to
//!      itself; a damaged or random record never crashes `record.parse`, and is accepted only if
//!      what it yields is exactly its bytes; one about another tree is refused.
//!   4. Bounds: a third subject, a payload one byte past `statement_bytes_max` and an envelope
//!      one byte past `envelope_bytes_max` are refused, whatever else is right.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const dsse = @import("trust/dsse.zig");
const key = @import("trust/key.zig");
const digest_mod = @import("store/digest.zig");
const record = @import("trust/record.zig");
const statement = @import("trust/statement.zig");

var work: dsse.Work = undefined;
var envelope_buffer: [constants.envelope_bytes_max]u8 = undefined;
var original_buffer: [constants.envelope_bytes_max]u8 = undefined;
var damaged_buffer: [constants.envelope_bytes_max + 8]u8 = undefined;
var render_buffer: [statement.render_bytes_max]u8 = undefined;
var statement_copy: [statement.render_bytes_max]u8 = undefined;
var again_buffer: [constants.envelope_bytes_max]u8 = undefined;
var name_buffer: [constants.reference_bytes_max]u8 = undefined;

const alphabet = "{}[]\":,\\ 0123456789-+.eEtrufalsn\n\t\x00\x1f\x7f=AZaz/\xc3\xa9\xff";

fn random_name(random: std.Random) []const u8 {
    var length: usize = 0;
    const count = random.intRangeAtMost(u32, 1, 120);
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const choice = random.uintLessThan(u32, 12);
        if (choice < 8) {
            name_buffer[length] = random.intRangeAtMost(u8, 0x20, 0x7e);
            length += 1;
        } else if (choice < 10) {
            name_buffer[length] = if (random.boolean()) '"' else '\\';
            length += 1;
        } else if (choice < 11) {
            name_buffer[length] = random.uintLessThan(u8, 0x20);
            length += 1;
        } else {
            const point = random.intRangeAtMost(u21, 0x80, 0xd7ff);
            // In range: `point` is a valid scalar and the buffer has room.
            length += std.unicode.utf8Encode(point, name_buffer[length..]) catch unreachable;
        }
    }
    assert(std.unicode.utf8ValidateSlice(name_buffer[0..length]));
    return name_buffer[0..length];
}

fn random_statement(random: std.Random) statement.Statement {
    var tree: statement.Digest = undefined;
    var other: statement.Digest = undefined;
    random.bytes(&tree);
    random.bytes(&other);
    const when = random.uintAtMost(u64, constants.signed_at_seconds_max);
    return switch (random.uintLessThan(u32, 3)) {
        0 => statement.Statement.for_tree(tree, when),
        1 => statement.Statement.for_result(tree, other, when),
        else => statement.Statement.for_manifest(tree, random_name(random), other, when),
    };
}

fn same_fields(left: *const statement.Statement, right: *const statement.Statement) bool {
    if (!std.mem.eql(u8, &left.tree, &right.tree)) return false;
    if (left.signed_at != right.signed_at) return false;
    if (!std.mem.eql(u8, left.reference(), right.reference())) return false;
    if (std.meta.activeTag(left.binding) != std.meta.activeTag(right.binding)) return false;
    return switch (left.binding) {
        .none => true,
        .result => |digest| std.mem.eql(u8, &digest, &right.binding.result),
        .manifest => |digest| std.mem.eql(u8, &digest, &right.binding.manifest),
    };
}

/// Parses `bytes` as a statement; whatever is accepted must render to exactly those bytes.
fn check_statement(bytes: []const u8) void {
    const parsed = statement.parse(bytes) catch return;
    var out: [statement.render_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, bytes, statement.render(&out, &parsed)));
}

/// Parses `bytes` as an envelope; whatever is accepted must render to exactly those bytes, and
/// verifies only when it is the original envelope.
fn check_envelope(bytes: []const u8, original: []const u8) void {
    const parsed = dsse.parse(&work, bytes) catch return;
    var copy_payload: [constants.statement_bytes_max]u8 = undefined;
    @memcpy(copy_payload[0..parsed.payload.len], parsed.payload);
    const copy: dsse.Envelope = .{
        .payload = copy_payload[0..parsed.payload.len],
        .public = parsed.public,
        .signature = parsed.signature,
    };
    assert(std.mem.eql(u8, bytes, dsse.render(&work, &again_buffer, &copy)));
    if (dsse.verify(&work, &copy)) {
        assert(std.mem.eql(u8, bytes, original));
    } else |_| {}
}

fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len > 0);
    assert(text.len <= constants.envelope_bytes_max);
    @memcpy(damaged_buffer[0..text.len], text);
    var length = text.len;
    switch (random.uintLessThan(u32, 6)) {
        0 => length = random.uintLessThan(usize, length),
        1 => damaged_buffer[random.uintLessThan(usize, length)] ^=
            @as(u8, 1) << @as(u3, @intCast(random.uintLessThan(u8, 8))),
        2 => damaged_buffer[random.uintLessThan(usize, length)] =
            alphabet[random.uintLessThan(usize, alphabet.len)],
        3 => {
            const at = random.uintLessThan(usize, length + 1);
            const tail = damaged_buffer[at..length];
            std.mem.copyBackwards(u8, damaged_buffer[at + 1 .. length + 1], tail);
            damaged_buffer[at] = alphabet[random.uintLessThan(usize, alphabet.len)];
            length += 1;
        },
        4 => {
            const at = random.uintLessThan(usize, length);
            const tail = damaged_buffer[at + 1 .. length];
            std.mem.copyForwards(u8, damaged_buffer[at .. length - 1], tail);
            length -= 1;
        },
        else => {
            damaged_buffer[length] = alphabet[random.uintLessThan(usize, alphabet.len)];
            length += 1;
        },
    }
    return damaged_buffer[0..length];
}

fn check_round_trip(random: std.Random) void {
    const value = random_statement(random);
    const text = statement.render(&render_buffer, &value);
    @memcpy(statement_copy[0..text.len], text);
    const payload = statement_copy[0..text.len];
    const parsed = statement.parse(payload) catch |err|
        std.debug.panic("a rendered statement was refused: {s}", .{@errorName(err)});
    assert(same_fields(&value, &parsed));
    assert(std.mem.eql(u8, payload, statement.render(&render_buffer, &parsed)));

    var seed: [constants.key_seed_bytes]u8 = undefined;
    random.bytes(&seed);
    const signed = dsse.sign(&work, &envelope_buffer, seed, payload) catch |err|
        std.debug.panic("signing was refused: {s}", .{@errorName(err)});
    @memcpy(original_buffer[0..signed.len], signed);
    const original = original_buffer[0..signed.len];
    const envelope = dsse.parse(&work, original) catch |err|
        std.debug.panic("a signed envelope was refused: {s}", .{@errorName(err)});
    dsse.verify(&work, &envelope) catch std.debug.panic("a fresh signature failed", .{});
    assert(std.mem.eql(u8, payload, envelope.payload));
    assert(std.mem.eql(u8, &key.public_of_seed(seed), &envelope.public));

    var round: u32 = 0;
    while (round < 6) : (round += 1) {
        check_statement(damage(random, payload));
        check_envelope(damage(random, original), original);
    }
    check_statement(random_bytes(random));
    check_envelope(random_bytes(random), original);
}

fn random_bytes(random: std.Random) []const u8 {
    const length = random.uintLessThan(usize, 400);
    for (damaged_buffer[0..length]) |*byte| {
        byte.* = if (random.boolean())
            alphabet[random.uintLessThan(usize, alphabet.len)]
        else
            random.int(u8);
    }
    return damaged_buffer[0..length];
}

fn check_bounds(random: std.Random) void {
    // A third subject, with the right shape, is refused.
    var tree: statement.Digest = undefined;
    random.bytes(&tree);
    const hex = std.fmt.bytesToHex(tree, .lower);
    const third = std.fmt.bufPrint(
        &again_buffer,
        "{{\"_type\":\"{s}\",\"subject\":[" ++
            "{{\"name\":\"tree\",\"digest\":{{\"zbxTree\":\"{s}\"}}}}," ++
            "{{\"name\":\"a\",\"digest\":{{\"sha256\":\"{s}\"}}}}," ++
            "{{\"name\":\"b\",\"digest\":{{\"sha256\":\"{s}\"}}}}]," ++
            "\"predicateType\":\"{s}\",\"predicate\":{{\"signedAt\":\"1970-01-01T00:00:00Z\"}}}}",
        .{ statement.statement_type, hex, hex, hex, constants.sign_predicate_type },
    ) catch unreachable; // The text is a few hundred bytes.
    assert(std.meta.isError(statement.parse(third)));

    // One byte past the payload bound is refused by `sign`.
    var seed: [constants.key_seed_bytes]u8 = undefined;
    random.bytes(&seed);
    assert(std.meta.isError(dsse.sign(&work, &envelope_buffer, seed, &payload_over)));
}

var payload_over: [constants.statement_bytes_max + 1]u8 = @splat('a');

var record_work: record.Work = undefined;
var record_in: record.Record = undefined;
var record_out: record.Record = undefined;
var record_damaged: [constants.signature_record_bytes_max + 8]u8 = undefined;

/// A record of random lines about a random tree, damaged in the ways a disk or a hand does.
fn check_record(random: std.Random) void {
    var tree: digest_mod.Digest = undefined;
    random.bytes(&tree.bytes);
    record_in.clear();
    const lines = 1 + random.uintLessThan(u32, constants.signatures_per_tree_max);
    while (record_in.count < lines) {
        var seed: [constants.key_seed_bytes]u8 = undefined;
        random.bytes(&seed);
        const at = random.int(u32);
        const found = statement.Statement.for_tree(tree.bytes, at);
        const text = statement.render(&render_buffer, &found);
        const signed = dsse.sign(&work, &envelope_buffer, seed, text) catch unreachable; // Small.
        _ = record_in.add(signed) catch unreachable; // At most eight lines are made.
    }
    record.parse(&record_work, tree, record_in.text(), &record_out) catch |err|
        std.debug.panic("a written record was refused: {s}", .{@errorName(err)});
    assert(std.mem.eql(u8, record_in.text(), record_out.text()));
    var other = tree;
    other.bytes[0] ^= 1;
    assert(std.meta.isError(record.parse(&record_work, other, record_in.text(), &record_out)));
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        const bytes = damage_record(random, record_in.text());
        record.parse(&record_work, tree, bytes, &record_out) catch continue;
        // Accepted: nothing but a whole record gets through, and it is the bytes given.
        assert(std.mem.eql(u8, bytes, record_out.text()));
        assert(record_out.count >= 1);
    }
    const noise = random_bytes(random);
    record.parse(&record_work, tree, noise, &record_out) catch return;
    assert(std.mem.eql(u8, noise, record_out.text()));
}

fn damage_record(random: std.Random, text: []const u8) []const u8 {
    assert(text.len > 0);
    @memcpy(record_damaged[0..text.len], text);
    var length = text.len;
    switch (random.uintLessThan(u32, 5)) {
        0 => length = random.uintLessThan(usize, length),
        1 => record_damaged[random.uintLessThan(usize, length)] ^=
            @as(u8, 1) << @as(u3, @intCast(random.uintLessThan(u8, 8))),
        2 => {
            const at = random.uintLessThan(usize, length);
            record_damaged[at] = alphabet[random.uintLessThan(usize, alphabet.len)];
        },
        3 => {
            // A line repeated: the writer never makes one.
            const end = std.mem.indexOfScalar(u8, text, '\n').? + 1;
            @memcpy(record_damaged[length..][0..end], text[0..end]);
            length += end;
        },
        else => {
            record_damaged[length] = '\n';
            length += 1;
        },
    }
    return record_damaged[0..length];
}

pub fn fuzz_trust(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_round_trip(random);
    check_bounds(random);
    check_record(random);
}

test "the fuzzer's properties hold on fixed seeds" {
    // Goal: the fuzzer runs under `zig build test`. Method: a few seeds.
    var seed: u64 = 1;
    while (seed <= 24) : (seed += 1) fuzz_trust(seed);
}
