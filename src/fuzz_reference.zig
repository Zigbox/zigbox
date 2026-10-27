//! The `reference` fuzzer: `zig build fuzz -- reference`. Each iteration builds a reference text
//! (a valid one from random parts, a valid one with edits, or noise), parses it, and compares the
//! answer with an independent reading of the grammar written here in another style (splitting on
//! `/` and counting, where the parser scans from the ends).
//!
//! Properties, every iteration:
//!   1. The parser accepts exactly the texts the oracle accepts, with the same registry,
//!      repository, tag and digest.
//!   2. An accepted reference formats to a canonical text, and parsing that gives the same
//!      fields: the canonical form is a fixed point.
//!   3. Its endpoint has a host and a nonzero port, and its manifest name is the digest when
//!      there is one and the tag otherwise.
//!   4. Nothing crashes on any bytes: NULs, high bytes, over-long and empty text.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const reference_mod = @import("registry/reference.zig");

const Reference = reference_mod.Reference;

const text_bytes_max = 1400;

/// What the oracle expects of an accepted text.
const Expected = struct {
    registry: [constants.reference_registry_bytes_max]u8 = undefined,
    registry_len: u32 = 0,
    repository: [400]u8 = undefined,
    repository_len: u32 = 0,
    tag: [200]u8 = undefined,
    tag_len: u32 = 0,
    digest_hex: ?[64]u8 = null,
};

fn lower(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9');
}

/// `[a-z0-9]+(sep [a-z0-9]+)*` with sep one of `.`, `_`, `__`, `-+`, checked by cutting the
/// component at every separator byte and looking at the pieces.
fn oracle_component(component: []const u8) bool {
    if (component.len == 0) return false;
    var at: usize = 0;
    var previous_was_separator = true; // The start counts: a component begins with a letter.
    while (at < component.len) {
        if (lower(component[at])) {
            previous_was_separator = false;
            at += 1;
            continue;
        }
        if (previous_was_separator) return false;
        const rest = component[at..];
        var run: usize = 1;
        while (run < rest.len and rest[run] == rest[0]) run += 1;
        if (rest[0] == '.' and run != 1) return false;
        if (rest[0] == '_' and run > 2) return false;
        if (rest[0] != '.' and rest[0] != '_' and rest[0] != '-') return false;
        previous_was_separator = true;
        at += run;
    }
    return !previous_was_separator;
}

fn oracle_registry_host(host: []const u8, port: ?[]const u8) bool {
    if (port) |digits| {
        if (digits.len == 0 or digits.len > 5 or digits[0] == '0') return false;
        var value: u32 = 0;
        for (digits) |byte| {
            if (byte < '0' or byte > '9') return false;
            value = value * 10 + (byte - '0');
        }
        if (value > 65535) return false;
    }
    if (host.len == 0 or host.len > 253) return false;
    var start: usize = 0;
    for (host, 0..) |byte, index| {
        if (byte != '.') continue;
        if (!oracle_label(host[start..index])) return false;
        start = index + 1;
    }
    return oracle_label(host[start..]);
}

fn oracle_label(label: []const u8) bool {
    if (label.len == 0 or label.len > 63) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;
    for (label) |byte| {
        const ok = lower(byte) or byte == '-';
        if (!ok) return false;
    }
    return true;
}

fn oracle_tag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128) return false;
    for (tag, 0..) |byte, index| {
        const word = lower(byte) or (byte >= 'A' and byte <= 'Z') or byte == '_';
        if (index == 0) {
            if (!word) return false;
        } else if (!word and byte != '.' and byte != '-') return false;
    }
    return true;
}

/// Reads `text` by the grammar. Null means refused.
fn oracle(text: []const u8, expected: *Expected) bool {
    if (text.len == 0 or text.len > 1024) return false;
    for (text) |byte| {
        if (byte < 0x21 or byte > 0x7e) return false;
    }
    if (std.mem.indexOf(u8, text, "://") != null) return false;
    var name = text;
    expected.digest_hex = null;
    if (std.mem.count(u8, text, "@") > 1) return false;
    if (std.mem.indexOfScalar(u8, text, '@')) |at| {
        const digest = text[at + 1 ..];
        if (digest.len != 71 or !std.mem.eql(u8, digest[0..7], "sha256:")) return false;
        for (digest[7..]) |byte| {
            const digit = byte >= '0' and byte <= '9';
            const letter = byte >= 'a' and byte <= 'f';
            if (!digit and !letter) return false;
        }
        expected.digest_hex = digest[7..][0..64].*;
        name = text[0..at];
    }
    return oracle_name(name, expected);
}

fn oracle_name(name: []const u8, expected: *Expected) bool {
    if (name.len == 0) return false;
    var parts_buffer: [64][]const u8 = undefined;
    var count: usize = 0;
    var pieces = std.mem.splitScalar(u8, name, '/');
    while (pieces.next()) |piece| {
        if (count == parts_buffer.len) return false;
        parts_buffer[count] = piece;
        count += 1;
    }
    var parts = parts_buffer[0..count];
    // The tag lives in the last part, after its only colon (a registry's colon is never last).
    const last = parts[count - 1];
    var last_name = last;
    expected.tag_len = 0;
    if (std.mem.indexOfScalar(u8, last, ':')) |colon| {
        const tag = last[colon + 1 ..];
        if (!oracle_tag(tag)) return false;
        @memcpy(expected.tag[0..tag.len], tag);
        expected.tag_len = @intCast(tag.len);
        last_name = last[0..colon];
    }
    var registry: []const u8 = "docker.io";
    if (count >= 2 and registry_shaped(parts[0])) {
        registry = parts[0];
        parts = parts[1..];
    }
    // `parts` ends in the last part, which lost its tag above.
    return oracle_finish(registry, parts, last_name, expected);
}

fn registry_shaped(first: []const u8) bool {
    if (std.mem.eql(u8, first, "localhost")) return true;
    for (first) |byte| {
        if (byte == '.' or byte == ':') return true;
    }
    return false;
}

fn oracle_finish(
    registry: []const u8,
    parts: []const []const u8,
    last_name: []const u8,
    expected: *Expected,
) bool {
    var lowered: [constants.reference_registry_bytes_max + 1]u8 = undefined;
    if (registry.len > constants.reference_registry_bytes_max) return false;
    const host_text = std.ascii.lowerString(&lowered, registry);
    var host = host_text;
    var port: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, host_text, ':')) |colon| {
        host = host_text[0..colon];
        port = host_text[colon + 1 ..];
    }
    if (!oracle_registry_host(host, port)) return false;
    const hub = std.mem.eql(u8, host_text, "docker.io") or
        std.mem.eql(u8, host_text, "index.docker.io");
    var length: usize = 0;
    if (hub and parts.len == 1) {
        @memcpy(expected.repository[0..8], "library/");
        length = 8;
    }
    for (parts, 0..) |part, index| {
        const piece = if (index == parts.len - 1) last_name else part;
        for (piece) |byte| {
            if (byte >= 'A' and byte <= 'Z') return false;
        }
        if (!oracle_component(piece)) return false;
        if (index > 0) {
            expected.repository[length] = '/';
            length += 1;
        }
        if (length + piece.len > 255) return false;
        @memcpy(expected.repository[length..][0..piece.len], piece);
        length += piece.len;
    }
    if (length > 255) return false;
    expected.repository_len = @intCast(length);
    const shown: []const u8 = if (hub) "docker.io" else host_text;
    @memcpy(expected.registry[0..shown.len], shown);
    expected.registry_len = @intCast(shown.len);
    if (expected.tag_len == 0 and expected.digest_hex == null) {
        @memcpy(expected.tag[0..6], "latest");
        expected.tag_len = 6;
    }
    return true;
}

// ---- Generation ----------------------------------------------------------------------------

const interesting = "/:@.-_ABz09\x00\xff\x1b ";

const Builder = struct {
    bytes: [text_bytes_max]u8 = undefined,
    len: u32 = 0,

    fn put(builder: *Builder, text: []const u8) void {
        const room = text_bytes_max - builder.len;
        const count: u32 = @intCast(@min(room, text.len));
        @memcpy(builder.bytes[builder.len..][0..count], text[0..count]);
        builder.len += count;
    }

    fn put_run(builder: *Builder, random: std.Random, alphabet: []const u8, max: usize) void {
        const count = random.intRangeAtMost(usize, 1, max);
        for (0..count) |_| builder.put(&.{alphabet[random.uintLessThan(usize, alphabet.len)]});
    }
};

const component_alphabet = "abcxyz019.-_";
const host_alphabet = "abcxyz019-";

fn generate_registry(random: std.Random, builder: *Builder) void {
    switch (random.uintLessThan(u8, 6)) {
        0 => builder.put("ghcr.io"),
        1 => builder.put("localhost"),
        2 => builder.put("docker.io"),
        3 => builder.put("index.docker.io"),
        else => {
            builder.put_run(random, host_alphabet, 8);
            builder.put(".");
            builder.put_run(random, host_alphabet, 5);
        },
    }
    if (random.uintLessThan(u8, 3) == 0) {
        var port: [8]u8 = undefined;
        const text = std.fmt.bufPrint(&port, ":{d}", .{random.intRangeAtMost(u32, 1, 70000)});
        builder.put(text catch unreachable); // At most 6 bytes.
    }
    builder.put("/");
}

fn generate(random: std.Random, builder: *Builder) void {
    if (random.boolean()) generate_registry(random, builder);
    const parts = random.intRangeAtMost(u8, 1, 3);
    for (0..parts) |index| {
        if (index > 0) builder.put("/");
        builder.put_run(random, component_alphabet, 12);
    }
    if (random.boolean()) {
        builder.put(":");
        builder.put_run(random, "abcXYZ019._-", 20);
    }
    if (random.uintLessThan(u8, 4) == 0) {
        builder.put("@sha256:");
        for (0..64) |_| builder.put(&.{"0123456789abcdef"[random.uintLessThan(usize, 16)]});
    }
}

fn mutate(random: std.Random, builder: *Builder) void {
    const edits = random.intRangeAtMost(u8, 1, 3);
    for (0..edits) |_| {
        if (builder.len == 0) return;
        const at = random.uintLessThan(u32, builder.len);
        switch (random.uintLessThan(u8, 4)) {
            0 => builder.bytes[at] = interesting[random.uintLessThan(usize, interesting.len)],
            1 => builder.bytes[at] = random.int(u8),
            2 => {
                const tail = builder.bytes[at + 1 .. builder.len];
                @memmove(builder.bytes[at .. builder.len - 1], tail);
                builder.len -= 1;
            },
            else => builder.len = at,
        }
    }
}

fn make_text(random: std.Random, builder: *Builder) []const u8 {
    switch (random.uintLessThan(u8, 8)) {
        0 => {
            const count = random.uintAtMost(usize, 80);
            for (0..count) |_| {
                const pick = random.uintLessThan(usize, interesting.len);
                const byte = if (random.boolean()) random.int(u8) else interesting[pick];
                builder.put(&.{byte});
            }
        },
        1 => {
            builder.put_run(random, "ab/", text_bytes_max - 8);
        },
        2, 3 => {
            generate(random, builder);
            mutate(random, builder);
        },
        else => generate(random, builder),
    }
    return builder.bytes[0..builder.len];
}

// ---- The property --------------------------------------------------------------------------

fn same_fields(reference: *const Reference, expected: *const Expected) bool {
    if (!std.mem.eql(u8, reference.registry(), expected.registry[0..expected.registry_len])) {
        return false;
    }
    const repository = expected.repository[0..expected.repository_len];
    if (!std.mem.eql(u8, reference.repository(), repository)) return false;
    const tag = reference.tag();
    if (expected.tag_len == 0) {
        if (tag != null) return false;
    } else if (tag == null or !std.mem.eql(u8, tag.?, expected.tag[0..expected.tag_len])) {
        return false;
    }
    if (expected.digest_hex) |hex| {
        const digest = reference.digest orelse return false;
        return std.mem.eql(u8, &digest.hex(), &hex);
    }
    return reference.digest == null;
}

fn check_accepted(reference: *const Reference) void {
    var formatted: reference_mod.Formatted = undefined;
    const canonical = reference.format(&formatted);
    var again: Reference = undefined;
    reference_mod.parse(canonical, &again) catch unreachable; // The canonical form parses.
    var second: reference_mod.Formatted = undefined;
    assert(std.mem.eql(u8, canonical, again.format(&second)));
    assert(std.mem.eql(u8, reference.registry(), again.registry()));
    assert(std.mem.eql(u8, reference.repository(), again.repository()));
    const endpoint = reference.endpoint();
    assert(endpoint.host.len > 0);
    assert(endpoint.port != 0);
    var name: reference_mod.ManifestName = undefined;
    const manifest = reference.manifest_name(&name);
    if (reference.digest) |digest| {
        assert(std.mem.eql(u8, manifest, &digest.text()));
    } else {
        assert(std.mem.eql(u8, manifest, reference.tag().?));
    }
}

pub fn fuzz_reference(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    var builder: Builder = .{};
    const text = make_text(random, &builder);
    var expected: Expected = .{};
    const accepted = oracle(text, &expected);
    var reference: Reference = undefined;
    if (reference_mod.parse(text, &reference)) {
        assert(accepted);
        assert(same_fields(&reference, &expected));
        check_accepted(&reference);
    } else |_| {
        assert(!accepted);
    }
}
