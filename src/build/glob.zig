//! Globs and `.dockerignore` lines as pure functions (docs/briefs/M9-dockerfile-import.md,
//! "Input globs and excludes"). No I/O and no allocation: a pattern is read into a fixed token
//! table and matched against a path with a set of states, one pass over the path.
//!
//! The language is the part of Docker's (moby's `patternmatcher`) that zbx and Docker agree on:
//! `*` is any run of bytes but `/`, `?` is one byte but `/`, `[a-z]` is a class that never takes
//! `/`, `\x` is the byte `x`, `**/` is any number of leading directories (including none), and
//! a `**` that ends the pattern is any run of bytes, `/` too. A path is relative, written with
//! `/`, with no `.` or `..` part and no trailing `/`.
//!
//! Two forms mean something else in Docker than they would here, so they are refused
//! (`bad_deep`, `bad_class`) rather than read: a `**` that is not a whole segment (`a**b`,
//! `**.log`), and a negated class (`[!a]`, `[^a]`). Write `**/*.log` and list the bytes.
//!
//! An exclude list is `.dockerignore`'s: a line is a pattern, a `#` line or a blank one is
//! skipped, `!` re-includes, and the last line that matches a path or one of its parent
//! directories decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const Kind = enum(u8) { literal, one, run, deep, deep_slash, class };

const Token = struct {
    kind: Kind,
    /// The byte for `literal`; for `class`, whether it is negated (1) or not (0).
    byte: u8,
    /// For `class`: where its body is in the pattern.
    begin: u16,
    end: u16,
};

const Tokens = struct {
    items: [constants.build_pattern_bytes_max]Token,
    count: u32,
};

/// Why a pattern is not one.
pub const Fault = enum { empty, too_long, bad_class, bad_deep, bad_escape, parent_part };

/// Reads `pattern` into `tokens`, or says what is wrong with it.
fn tokenise(pattern: []const u8, tokens: *Tokens) ?Fault {
    if (pattern.len == 0) return .empty;
    if (pattern.len > constants.build_pattern_bytes_max) return .too_long;
    tokens.count = 0;
    var index: u32 = 0;
    while (index < pattern.len) {
        const byte = pattern[index];
        var token: Token = .{ .kind = .literal, .byte = byte, .begin = 0, .end = 0 };
        index += 1;
        switch (byte) {
            '?' => token.kind = .one,
            '*' => {
                token.kind = .run;
                if (index < pattern.len and pattern[index] == '*') {
                    // A `**` is a whole segment: after a `/` or the start, before a `/` or the end.
                    const first = index - 1;
                    if (first > 0 and pattern[first - 1] != '/') return .bad_deep;
                    index += 1;
                    const at_end = index == pattern.len;
                    if (!at_end and pattern[index] != '/') return .bad_deep;
                    token.kind = .deep;
                    if (index < pattern.len and pattern[index] == '/') {
                        index += 1;
                        token.kind = .deep_slash;
                    }
                }
            },
            '\\' => {
                if (index == pattern.len) return .bad_escape;
                token.byte = pattern[index];
                index += 1;
            },
            '[' => {
                const fault = read_class(pattern, &index, &token);
                if (fault != null) return fault;
            },
            else => {},
        }
        tokens.items[tokens.count] = token;
        tokens.count += 1;
    }
    assert(tokens.count >= 1);
    assert(tokens.count <= pattern.len);
    return null;
}

/// A class after its `[`: `index` ends just past its `]`.
fn read_class(pattern: []const u8, index: *u32, token: *Token) ?Fault {
    assert(index.* >= 1);
    assert(pattern[index.* - 1] == '[');
    token.kind = .class;
    token.byte = 0;
    // Docker reads `[!a]` as a set holding `!`, and `[^a]` as a set that takes `/`: refused.
    if (index.* < pattern.len and (pattern[index.*] == '^' or pattern[index.*] == '!')) {
        return .bad_class;
    }
    token.begin = @intCast(index.*);
    while (index.* < pattern.len) {
        const byte = pattern[index.*];
        if (byte == ']') {
            if (index.* == token.begin) return .bad_class; // `[]` takes nothing.
            token.end = @intCast(index.*);
            index.* += 1;
            return null;
        }
        if (byte == '\\') index.* += 1;
        index.* += 1;
    }
    return .bad_class;
}

/// Whether the class `body` (the bytes between `[` and `]`, negation aside) takes `byte`.
fn class_takes(body: []const u8, negated: bool, byte: u8) bool {
    assert(body.len >= 1);
    if (byte == '/') return false; // No class takes a separator.
    var taken = false;
    var index: usize = 0;
    while (index < body.len) {
        var low = body[index];
        index += 1;
        if (low == '\\' and index < body.len) {
            low = body[index];
            index += 1;
        }
        var high = low;
        if (index + 1 < body.len and body[index] == '-') {
            high = body[index + 1];
            index += 2;
            if (high == '\\' and index < body.len) {
                high = body[index];
                index += 1;
            }
        }
        if (byte >= low and byte <= high) taken = true;
    }
    return taken != negated;
}

/// The states are the token positions `0..count`, and `count` is the end of the pattern. A
/// state set holds each position the pattern can be at after the bytes read so far.
const States = struct {
    at: [constants.build_pattern_bytes_max + 1]bool,
};

fn clear(states: *States, count: u32) void {
    assert(count <= constants.build_pattern_bytes_max);
    @memset(states.at[0 .. count + 1], false);
}

/// Adds `position` and what the pattern can pass without reading a byte: a `**` that takes
/// nothing, and `**/`'s leading directories that take none.
fn enter(states: *States, tokens: *const Tokens, position: u32) void {
    var current = position;
    while (true) {
        states.at[current] = true;
        if (current == tokens.count) return;
        const kind = tokens.items[current].kind;
        if (kind != .run and kind != .deep and kind != .deep_slash) return;
        current += 1;
    }
}

/// Whether `pattern` matches the whole of `path`.
pub fn matches(pattern: []const u8, path: []const u8) bool {
    var tokens: Tokens = undefined;
    if (tokenise(pattern, &tokens) != null) return false;
    return matches_tokens(&tokens, pattern, path);
}

fn matches_tokens(tokens: *const Tokens, pattern: []const u8, path: []const u8) bool {
    assert(tokens.count >= 1);
    var now: States = undefined;
    var next: States = undefined;
    clear(&now, tokens.count);
    enter(&now, tokens, 0);
    for (path) |byte| {
        clear(&next, tokens.count);
        var any = false;
        for (tokens.items[0..tokens.count], 0..) |token, position| {
            if (!now.at[position]) continue;
            if (step(token, pattern, byte, &next, tokens, @intCast(position))) any = true;
        }
        if (!any) return false;
        now = next;
    }
    return now.at[tokens.count];
}

/// Moves one state over `byte`; whether it moved anywhere.
fn step(
    token: Token,
    pattern: []const u8,
    byte: u8,
    next: *States,
    tokens: *const Tokens,
    position: u32,
) bool {
    const separator = byte == '/';
    switch (token.kind) {
        .literal => {
            if (token.byte != byte) return false;
            enter(next, tokens, position + 1);
        },
        .one => {
            if (separator) return false;
            enter(next, tokens, position + 1);
        },
        .class => {
            const body = pattern[token.begin..token.end];
            if (!class_takes(body, token.byte == 1, byte)) return false;
            enter(next, tokens, position + 1);
        },
        .run => {
            if (separator) return false;
            enter(next, tokens, position);
        },
        .deep => enter(next, tokens, position),
        .deep_slash => {
            // Leading directories: any bytes, until one `/` ends them.
            if (separator) enter(next, tokens, position + 1);
            next.at[position] = true;
        },
    }
    return true;
}

/// A parsed exclude line: its pattern (cleaned) and whether it re-includes.
pub const Line = struct {
    negated: bool,
    pattern: []const u8,
};

/// What a line is: nothing (blank, a comment, or only `/`), a `Line` whose pattern is written
/// into `out`, or a fault.
pub const Reading = union(enum) {
    nothing,
    line: Line,
    fault: Fault,
};

/// Reads one `.dockerignore` line into `out`: trimmed, `!` taken off, a leading `/` dropped, and
/// `.`, empty and trailing parts cleaned away, as Docker's `filepath.Clean` does. A `..` part
/// is a fault: an exclude names things inside the context only.
pub fn read_line(text: []const u8, out: *[constants.build_pattern_bytes_max]u8) Reading {
    const trimmed = std.mem.trim(u8, text, " \t\r");
    if (trimmed.len == 0) return .nothing;
    if (trimmed[0] == '#') return .nothing;
    var rest = trimmed;
    var negated = false;
    if (rest[0] == '!') {
        negated = true;
        rest = std.mem.trim(u8, rest[1..], " \t");
    }
    var length: u32 = 0;
    var parts = std.mem.tokenizeScalar(u8, rest, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return .{ .fault = .parent_part };
        if (length > 0) {
            if (length == out.len) return .{ .fault = .too_long };
            out[length] = '/';
            length += 1;
        }
        if (length + part.len > out.len) return .{ .fault = .too_long };
        @memcpy(out[length..][0..part.len], part);
        length += @intCast(part.len);
    }
    if (length == 0) return .nothing;
    var tokens: Tokens = undefined;
    if (tokenise(out[0..length], &tokens)) |fault| return .{ .fault = fault };
    return .{ .line = .{ .negated = negated, .pattern = out[0..length] } };
}

/// The fault of the exclude line `text`, or null if it is a fine pattern or nothing.
pub fn line_fault(text: []const u8) ?Fault {
    var out: [constants.build_pattern_bytes_max]u8 = undefined;
    return switch (read_line(text, &out)) {
        .fault => |fault| fault,
        .nothing, .line => null,
    };
}

/// Whether the exclude `lines` leave `path` out: the last line that matches `path` or one of
/// its parent directories decides, and a path no line matches is in.
pub fn excluded(lines: []const []const u8, path: []const u8) bool {
    assert(lines.len <= constants.build_exclude_lines_max);
    assert(path.len > 0);
    var result = false;
    for (lines) |text| {
        var out: [constants.build_pattern_bytes_max]u8 = undefined;
        switch (read_line(text, &out)) {
            .nothing, .fault => continue,
            .line => |line| {
                if (matches_or_parent(line.pattern, path)) result = !line.negated;
            },
        }
    }
    return result;
}

/// Whether `pattern` matches `path` or a directory `path` is in.
fn matches_or_parent(pattern: []const u8, path: []const u8) bool {
    var tokens: Tokens = undefined;
    if (tokenise(pattern, &tokens) != null) return false;
    if (matches_tokens(&tokens, pattern, path)) return true;
    for (path, 0..) |byte, index| {
        if (byte != '/') continue;
        if (matches_tokens(&tokens, pattern, path[0..index])) return true;
    }
    return false;
}

/// Whether `pattern` is a glob this module reads (for a copy's `.src` and an input).
pub fn valid(pattern: []const u8) ?Fault {
    var tokens: Tokens = undefined;
    return tokenise(pattern, &tokens);
}

/// Whether `pattern` has a byte that makes it more than one path (`*`, `?`, `[`, or `\`).
pub fn is_glob(pattern: []const u8) bool {
    return std.mem.indexOfAny(u8, pattern, "*?[\\") != null;
}

comptime {
    assert(constants.build_pattern_bytes_max <= std.math.maxInt(u16));
    assert(constants.build_exclude_lines_max >= 1);
}

const testing = std.testing;

fn expect_match(pattern: []const u8, path: []const u8, want: bool) !void {
    try testing.expectEqual(want, matches(pattern, path));
}

test "star, question mark and class stay within a component" {
    // Goal: the single-component operators never cross a `/`; method: paired hit and miss.
    try expect_match("*.go", "main.go", true);
    try expect_match("*.go", "cmd/main.go", false);
    try expect_match("a?c", "abc", true);
    try expect_match("a?c", "a/c", false);
    try expect_match("[a-c]x", "bx", true);
    try expect_match("[a-c]x", "/x", false);
    try expect_match("a\\*b", "a*b", true);
    try expect_match("a\\*b", "axb", false);
}

test "double star takes directories" {
    // Goal: `**/` is any leading directories, none included; a bare `**` crosses `/`.
    try expect_match("**/a.go", "a.go", true);
    try expect_match("**/a.go", "x/y/a.go", true);
    try expect_match("**/a.go", "x/ya.go", false);
    try expect_match("src/**/a.go", "src/a.go", true);
    try expect_match("src/**/a.go", "src/p/q/a.go", true);
    try expect_match("src/**", "src/p/q", true);
    try expect_match("src/**", "src", false);
    try expect_match("**", "any/thing", true);
}

test "a bad pattern matches nothing and is named" {
    // Goal: the faults of `valid`, and that `matches` never takes a bad pattern.
    try testing.expectEqual(Fault.bad_class, valid("[a").?);
    try testing.expectEqual(Fault.bad_class, valid("[]").?);
    try testing.expectEqual(Fault.bad_escape, valid("a\\").?);
    try testing.expectEqual(Fault.empty, valid("").?);
    try testing.expect(valid("a/[b-d]*/**/e") == null);
    // Forms Docker reads another way are refused, not guessed.
    try testing.expectEqual(Fault.bad_deep, valid("**.log").?);
    try testing.expectEqual(Fault.bad_deep, valid("a**b").?);
    try testing.expectEqual(Fault.bad_deep, valid("a/**b").?);
    try testing.expectEqual(Fault.bad_deep, valid("***").?);
    try testing.expectEqual(Fault.bad_class, valid("[!a]").?);
    try testing.expectEqual(Fault.bad_class, valid("[^a-c]x").?);
    try testing.expect(valid("**") == null);
    try testing.expect(valid("a/**") == null);
    try testing.expect(valid("**/a") == null);
    try expect_match("[a", "[a", false);
}

test "dockerignore lines: the last match wins and parents carry" {
    // Goal: the `.dockerignore` rules of the brief: `!` re-includes, later lines win, a
    // directory match takes what is under it, comments and blanks are skipped.
    const lines = [_][]const u8{ "# comment", "", "node_modules", "*.md", "!README.md", "/build/" };
    try testing.expect(excluded(&lines, "node_modules/x/y.js"));
    try testing.expect(excluded(&lines, "a.md")); // Docker: `*.md` is the root only.
    try testing.expect(!excluded(&lines, "docs/a.md"));
    try testing.expect(!excluded(&lines, "README.md"));
    try testing.expect(excluded(&lines, "build/out.o"));
    try testing.expect(!excluded(&lines, "src/main.go"));
    const reversed = [_][]const u8{ "!README.md", "*.md" };
    try testing.expect(excluded(&reversed, "README.md"));
}

test "read_line cleans and faults" {
    // Goal: the cleaning of a line and its two faults.
    var out: [constants.build_pattern_bytes_max]u8 = undefined;
    const cleaned = read_line("  !/a/./b//c/  ", &out).line;
    try testing.expect(cleaned.negated);
    try testing.expectEqualStrings("a/b/c", cleaned.pattern);
    try testing.expectEqual(Fault.parent_part, read_line("../x", &out).fault);
    try testing.expectEqual(Fault.bad_class, read_line("[x", &out).fault);
    try testing.expect(read_line("/", &out) == .nothing);
}
