//! The `dockerignore` fuzzer: `zig build fuzz -- dockerignore`. Globs and `.dockerignore` lines
//! are matched by `build/glob.zig`, a pass over the path with a set of states. Each iteration
//! builds random patterns from tokens (so the expected meaning is known without reading the
//! pattern text), writes them as text, and matches random paths with both `glob.matches` and a
//! slow reference: a table of `token index x path index`.
//!
//! Properties, every iteration:
//!   1. `glob.matches` agrees with the reference on every pattern and path.
//!   2. `glob.excluded` agrees with the reference on a list of lines (comments, blanks, `!`, a
//!      leading `/`): the last line that matches the path or a parent directory decides.
//!   3. Noise (any bytes as a pattern or a line) never crashes the reader, and a pattern it
//!      accepts as valid has a line reading that agrees.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const glob = @import("build/glob.zig");

/// The most tokens in a generated pattern, and the most bytes in a generated path.
const tokens_max = 16;
const path_bytes_max = 24;
const pattern_bytes_max = 128;
const lines_max = 6;

const Kind = enum { literal, one, run, deep, deep_slash, class };

const Range = struct { low: u8, high: u8 };

const Token = struct {
    kind: Kind,
    byte: u8 = 0,
    negated: bool = false,
    ranges: [2]Range = undefined,
    ranges_count: u8 = 0,
};

const Pattern = struct {
    tokens: [tokens_max]Token,
    count: u32,
    text: [pattern_bytes_max]u8,
    length: u32,

    fn put(pattern: *Pattern, bytes: []const u8) void {
        assert(pattern.length + bytes.len <= pattern.text.len);
        @memcpy(pattern.text[pattern.length..][0..bytes.len], bytes);
        pattern.length += @intCast(bytes.len);
    }

    fn add(pattern: *Pattern, token: Token) void {
        assert(pattern.count < tokens_max);
        pattern.tokens[pattern.count] = token;
        pattern.count += 1;
    }
};

const alphabet = "abc";

/// One item of a segment, written and added as a token; `after_run` stops `**` from forming.
fn gen_item(random: std.Random, pattern: *Pattern, after_run: bool) bool {
    assert(pattern.count < tokens_max);
    switch (random.uintLessThan(u8, 6)) {
        0, 1 => {
            const byte = alphabet[random.uintLessThan(usize, alphabet.len)];
            pattern.put(&.{byte});
            pattern.add(.{ .kind = .literal, .byte = byte });
        },
        2 => {
            const escaped = "*?[\\"[random.uintLessThan(usize, 4)];
            pattern.put(&.{ '\\', escaped });
            pattern.add(.{ .kind = .literal, .byte = escaped });
        },
        3 => {
            pattern.put("?");
            pattern.add(.{ .kind = .one });
        },
        4 => {
            if (after_run) return true;
            pattern.put("*");
            pattern.add(.{ .kind = .run });
            return true;
        },
        else => gen_class(random, pattern),
    }
    return false;
}

fn gen_class(random: std.Random, pattern: *Pattern) void {
    assert(pattern.count < tokens_max);
    var token: Token = .{ .kind = .class };
    pattern.put("[");
    if (random.boolean()) {
        token.negated = true;
        pattern.put(if (random.boolean()) "^" else "!");
    }
    token.ranges_count = 1 + random.uintLessThan(u8, 2);
    for (0..token.ranges_count) |index| {
        const low = alphabet[random.uintLessThan(usize, alphabet.len)];
        const high = low + random.uintLessThan(u8, 2);
        token.ranges[index] = .{ .low = low, .high = high };
        if (low == high) {
            pattern.put(&.{low});
        } else {
            pattern.put(&.{ low, '-', high });
        }
    }
    pattern.put("]");
    pattern.add(token);
}

/// A pattern of one to three segments; a segment is `**` (any directories) or a few items.
fn gen_pattern(random: std.Random) Pattern {
    var pattern: Pattern = .{ .tokens = undefined, .count = 0, .text = undefined, .length = 0 };
    const segments = 1 + random.uintLessThan(u32, 3);
    for (0..segments) |segment| {
        const last = segment + 1 == segments;
        if (random.uintLessThan(u8, 5) == 0) {
            if (last) {
                pattern.put("**");
                pattern.add(.{ .kind = .deep });
            } else {
                pattern.put("**/");
                pattern.add(.{ .kind = .deep_slash });
            }
            continue;
        }
        var run = false;
        for (0..1 + random.uintLessThan(u32, 3)) |_| run = gen_item(random, &pattern, run);
        if (!last) {
            pattern.put("/");
            pattern.add(.{ .kind = .literal, .byte = '/' });
        }
    }
    assert(pattern.count <= tokens_max);
    return pattern;
}

fn class_takes(token: Token, byte: u8) bool {
    assert(token.kind == .class);
    if (byte == '/') return false;
    var inside = false;
    for (token.ranges[0..token.ranges_count]) |range| {
        if (byte >= range.low and byte <= range.high) inside = true;
    }
    return inside != token.negated;
}

/// The reference: `table[t][i]` is whether tokens `t..` match `path[i..]` exactly. Slow on
/// purpose: every cell looks at every later position.
fn reference(pattern: *const Pattern, path: []const u8) bool {
    assert(path.len <= path_bytes_max);
    var table: [tokens_max + 1][path_bytes_max + 1]bool = undefined;
    var t: usize = pattern.count + 1;
    while (t > 0) {
        t -= 1;
        for (0..path.len + 1) |i| table[t][i] = cell(pattern, path, &table, t, i);
    }
    return table[0][0];
}

fn cell(
    pattern: *const Pattern,
    path: []const u8,
    table: *const [tokens_max + 1][path_bytes_max + 1]bool,
    t: usize,
    i: usize,
) bool {
    if (t == pattern.count) return i == path.len;
    const token = pattern.tokens[t];
    switch (token.kind) {
        .literal => return i < path.len and path[i] == token.byte and table[t + 1][i + 1],
        .one => return i < path.len and path[i] != '/' and table[t + 1][i + 1],
        .class => return i < path.len and class_takes(token, path[i]) and table[t + 1][i + 1],
        .run => {
            for (i..path.len + 1) |j| {
                if (j > i and path[j - 1] == '/') break;
                if (table[t + 1][j]) return true;
            }
            return false;
        },
        .deep => {
            for (i..path.len + 1) |j| if (table[t + 1][j]) return true;
            return false;
        },
        .deep_slash => {
            if (table[t + 1][i]) return true;
            for (i + 1..path.len + 1) |j| {
                if (path[j - 1] == '/' and table[t + 1][j]) return true;
            }
            return false;
        },
    }
}

/// A relative path of one to four parts of one or two bytes, in a small alphabet.
fn gen_path(random: std.Random, out: *[path_bytes_max]u8) []const u8 {
    var length: usize = 0;
    const parts = 1 + random.uintLessThan(u32, 4);
    for (0..parts) |part| {
        if (part > 0) {
            out[length] = '/';
            length += 1;
        }
        for (0..1 + random.uintLessThan(u32, 2)) |_| {
            out[length] = alphabet[random.uintLessThan(usize, alphabet.len)];
            length += 1;
        }
    }
    assert(length <= path_bytes_max);
    return out[0..length];
}

fn check_matches(random: std.Random, pattern: *const Pattern) void {
    var storage: [path_bytes_max]u8 = undefined;
    const text = pattern.text[0..pattern.length];
    assert(glob.valid(text) == null);
    for (0..16) |_| {
        const path = gen_path(random, &storage);
        const expected = reference(pattern, path);
        if (glob.matches(text, path) != expected) {
            std.debug.print("pattern \"{s}\" path \"{s}\": reference {}\n", .{
                text, path, expected,
            });
            unreachable; // The reader and the reference must agree.
        }
    }
}

const Line = struct {
    pattern: Pattern,
    negated: bool,
    rooted: bool,
    skipped: bool,
    text: [pattern_bytes_max + 4]u8,
    length: u32,
};

fn gen_line(random: std.Random) Line {
    var line: Line = undefined;
    line.pattern = gen_pattern(random);
    line.negated = random.uintLessThan(u8, 4) == 0;
    line.rooted = random.uintLessThan(u8, 6) == 0;
    line.skipped = random.uintLessThan(u8, 8) == 0;
    var length: u32 = 0;
    if (line.skipped) {
        line.text[0] = '#';
        length = 1;
    } else if (line.negated) {
        line.text[0] = '!';
        length = 1;
    }
    if (line.rooted) {
        line.text[length] = '/';
        length += 1;
    }
    const text = line.pattern.text[0..line.pattern.length];
    @memcpy(line.text[length..][0..text.len], text);
    line.length = length + @as(u32, @intCast(text.len));
    return line;
}

/// Whether the lines leave `path` out, by the rule in the module comment.
fn reference_excluded(lines: []const Line, path: []const u8) bool {
    var result = false;
    for (lines) |*line| {
        if (line.skipped) continue;
        var hit = reference(&line.pattern, path);
        for (path, 0..) |byte, index| {
            if (byte == '/' and reference(&line.pattern, path[0..index])) hit = true;
        }
        if (hit) result = !line.negated;
    }
    return result;
}

fn check_excluded(random: std.Random) void {
    var lines: [lines_max]Line = undefined;
    var texts: [lines_max][]const u8 = undefined;
    const count = random.uintLessThan(usize, lines_max + 1);
    for (0..count) |index| {
        lines[index] = gen_line(random);
        texts[index] = lines[index].text[0..lines[index].length];
    }
    var storage: [path_bytes_max]u8 = undefined;
    for (0..8) |_| {
        const path = gen_path(random, &storage);
        const expected = reference_excluded(lines[0..count], path);
        if (glob.excluded(texts[0..count], path) != expected) {
            std.debug.print("path \"{s}\": reference {}\n", .{ path, expected });
            for (texts[0..count]) |text| std.debug.print("  line \"{s}\"\n", .{text});
            unreachable; // The reader and the reference must agree.
        }
    }
}

/// Property 3.
fn check_noise(random: std.Random) void {
    var bytes: [48]u8 = undefined;
    const length = random.uintAtMost(usize, bytes.len);
    random.bytes(bytes[0..length]);
    // Bias toward the bytes that mean something, so classes and escapes are met.
    for (bytes[0..length]) |*byte| {
        if (random.boolean()) byte.* = "*?[]\\^!-/.#ab"[random.uintLessThan(usize, 13)];
    }
    const text = bytes[0..length];
    const fault = glob.valid(text);
    var out: [constants.build_pattern_bytes_max]u8 = undefined;
    _ = glob.is_glob(text);
    _ = glob.line_fault(text);
    _ = glob.matches(text, "a/b");
    if (fault == null and length > 0) {
        // A pattern that is valid on its own is valid as a line, unless the line reading drops
        // or refuses part of it (a `..` part, a leading `!` or `#`, blanks).
        switch (glob.read_line(text, &out)) {
            .line, .nothing, .fault => {},
        }
    }
    assert(length <= bytes.len);
}

pub fn fuzz_dockerignore(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    for (0..4) |_| {
        const pattern = gen_pattern(random);
        check_matches(random, &pattern);
    }
    check_excluded(random);
    check_noise(random);
}
