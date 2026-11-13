//! The words of an instruction: JSON exec arrays, leading `--name=value` flags, and Docker's
//! shell-like word rules with variable substitution.
//!
//! Substitution follows Docker's: `$X`, `${X}`, `${X:-w}`, `${X-w}`, `${X:+w}`, `${X+w}`,
//! `${X?m}` and `${X:?m}`. The word of an operator may itself name variables (`$Y`, `${Y}`),
//! but not a further operator: that is the one level of nesting Docker files use, and keeping
//! to it keeps this code free of recursion. The pattern forms (`${X#p}`, `${X%p}`, `${X/p/r}`)
//! are pre-release Docker syntax and refused (E0811). Quotes and the escape character are read
//! as Docker's shell lexer reads them: single quotes are literal, double quotes allow `$` and
//! escape only `"`, `$` and the escape character, and outside quotes the escape character makes
//! the next byte literal. Expanded text is never split again.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const refusal_mod = @import("refusal.zig");

const Refusal = refusal_mod.Refusal;
const Refused = refusal_mod.Refused;
const refuse = refusal_mod.refuse;

/// A variable's state where a word names it.
pub const Value = union(enum) {
    /// Not declared: expands to nothing, as Docker's does.
    unset,
    /// An `ARG` declared with no default and no `--build-arg`: naming it is E0812.
    missing,
    set: []const u8,
};

pub const Lookup = struct {
    context: *const anyopaque,
    get: *const fn (context: *const anyopaque, name: []const u8) Value,
};

/// Where expanded and decoded text goes: a slice of the import's scratch memory.
pub const Out = struct {
    bytes: []u8,
    len: u32 = 0,

    pub fn mark(out: *const Out) u32 {
        return out.len;
    }

    pub fn since(out: *const Out, at: u32) []const u8 {
        assert(at <= out.len);
        return out.bytes[at..out.len];
    }

    pub fn push(out: *Out, refusal: *Refusal, line: u32, bytes: []const u8) Refused!void {
        if (bytes.len > out.bytes.len - out.len) {
            return refuse(refusal, .E0815, line, "the import's working text is more than {d} " ++
                "bytes", .{out.bytes.len}, "split the Dockerfile, or shorten its longest " ++
                "values", .{});
        }
        @memcpy(out.bytes[out.len..][0..bytes.len], bytes);
        out.len += @intCast(bytes.len);
    }
};

pub const Context = struct {
    escape: u8,
    line: u32,
    lookup: Lookup,
};

pub const WordList = struct {
    items: [constants.import_words_max][]const u8,
    count: u32,

    pub fn slice(list: *const WordList) []const []const u8 {
        assert(list.count <= constants.import_words_max);
        return list.items[0..list.count];
    }

    fn add(list: *WordList, refusal: *Refusal, line: u32, word: []const u8) Refused!void {
        if (list.count == constants.import_words_max) {
            return refuse(refusal, .E0815, line, "Dockerfile:{d} has more than {d} words", .{
                line, constants.import_words_max,
            }, "split the instruction in two", .{});
        }
        list.items[list.count] = word;
        list.count += 1;
    }
};

pub const Flag = struct {
    name: []const u8,
    /// Null for `--name` written with no `=`.
    value: ?[]const u8,
};

pub const flags_max = 16;

pub const Flags = struct {
    items: [flags_max]Flag,
    count: u32,
    /// The text after the flags, trimmed.
    rest: []const u8,

    pub fn slice(flags: *const Flags) []const Flag {
        assert(flags.count <= flags_max);
        return flags.items[0..flags.count];
    }
};

const blanks = " \t";

/// Splits the leading `--name[=value]` words off `text`. Values are as written: the caller
/// substitutes in the ones Docker substitutes in.
pub fn flags_of(text: []const u8, line: u32, flags: *Flags, refusal: *Refusal) Refused!void {
    flags.count = 0;
    var rest = std.mem.trimStart(u8, text, blanks);
    while (std.mem.startsWith(u8, rest, "--")) {
        const end = std.mem.indexOfAny(u8, rest, blanks) orelse rest.len;
        const word = rest[2..end];
        if (word.len == 0) break; // `--` alone ends the flags, as for most commands.
        if (flags.count == flags_max) {
            return refuse(refusal, .E0815, line, "Dockerfile:{d} has more than {d} flags", .{
                line, flags_max,
            }, "remove the flags the instruction does not need", .{});
        }
        const equals = std.mem.indexOfScalar(u8, word, '=');
        flags.items[flags.count] = if (equals) |at|
            .{ .name = word[0..at], .value = word[at + 1 ..] }
        else
            .{ .name = word, .value = null };
        flags.count += 1;
        rest = std.mem.trimStart(u8, rest[end..], blanks);
    }
    flags.rest = rest;
    assert(flags.count <= flags_max);
}

/// Reads `text` as a JSON array of strings into `list`; false when it is not one (Docker then
/// reads the instruction in shell form).
pub fn exec_form(
    text: []const u8,
    line: u32,
    out: *Out,
    list: *WordList,
    refusal: *Refusal,
) Refused!bool {
    list.count = 0;
    var json: Json = .{ .text = std.mem.trim(u8, text, blanks ++ "\r\n") };
    if (!json.eat('[')) return false;
    if (json.eat(']')) return json.at_end();
    while (true) {
        const start = out.mark();
        if (!try json.string(out, refusal, line)) return false;
        try list.add(refusal, line, out.since(start));
        if (json.eat(']')) return json.at_end();
        if (!json.eat(',')) return false;
    }
}

const Json = struct {
    text: []const u8,
    at: u32 = 0,

    fn skip(json: *Json) void {
        while (json.at < json.text.len) : (json.at += 1) {
            if (std.mem.indexOfScalar(u8, " \t\r\n", json.text[json.at]) == null) return;
        }
    }

    fn eat(json: *Json, byte: u8) bool {
        json.skip();
        if (json.at < json.text.len and json.text[json.at] == byte) {
            json.at += 1;
            return true;
        }
        return false;
    }

    fn at_end(json: *Json) bool {
        json.skip();
        return json.at == json.text.len;
    }

    fn string(json: *Json, out: *Out, refusal: *Refusal, line: u32) Refused!bool {
        if (!json.eat('"')) return false;
        while (json.at < json.text.len) {
            const byte = json.text[json.at];
            json.at += 1;
            if (byte == '"') return true;
            if (byte < 0x20) return false;
            if (byte != '\\') {
                try out.push(refusal, line, &.{byte});
                continue;
            }
            if (json.at >= json.text.len) return false;
            const escaped = json.text[json.at];
            json.at += 1;
            const decoded: u8 = switch (escaped) {
                '"', '\\', '/' => escaped,
                'b' => 0x08,
                'f' => 0x0c,
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => {
                    if (!try json.unicode(out, refusal, line)) return false;
                    continue;
                },
                else => return false,
            };
            try out.push(refusal, line, &.{decoded});
        }
        return false;
    }

    /// `\uXXXX` outside the surrogates and not NUL, as UTF-8; false if it is not one.
    fn unicode(json: *Json, out: *Out, refusal: *Refusal, line: u32) Refused!bool {
        if (json.at + 4 > json.text.len) return false;
        const code = std.fmt.parseInt(u21, json.text[json.at..][0..4], 16) catch return false;
        json.at += 4;
        if (code >= 0xd800 and code <= 0xdfff) return false;
        if (code == 0) return false;
        var buffer: [4]u8 = undefined;
        const length = std.unicode.utf8Encode(code, &buffer) catch return false;
        assert(length > 0);
        try out.push(refusal, line, buffer[0..length]);
        return true;
    }
};

/// The whole of `text` as one word: quotes removed, escapes read, variables substituted, and
/// whitespace kept (`WORKDIR`, `USER`, the legacy `ENV key value`).
pub fn word_of(
    text: []const u8,
    context: *const Context,
    out: *Out,
    refusal: *Refusal,
) ![]const u8 {
    var list: WordList = undefined;
    list.count = 0;
    const start = out.mark();
    try lex(text, context, out, &list, refusal, .whole);
    assert(list.count <= 1);
    return out.since(start);
}

/// `text` split into words at unquoted blanks, each word's quotes removed, escapes read and
/// variables substituted.
pub fn words_of(
    text: []const u8,
    context: *const Context,
    out: *Out,
    list: *WordList,
    refusal: *Refusal,
) Refused!void {
    list.count = 0;
    try lex(text, context, out, list, refusal, .split);
}

const Mode = enum { split, whole };

fn lex(
    text: []const u8,
    context: *const Context,
    out: *Out,
    list: *WordList,
    refusal: *Refusal,
    mode: Mode,
) Refused!void {
    var index: usize = 0;
    var started = false;
    var word_start = out.mark();
    while (index < text.len) {
        const byte = text[index];
        if (mode == .split and (byte == ' ' or byte == '\t')) {
            if (started) try list.add(refusal, context.line, out.since(word_start));
            started = false;
            word_start = out.mark();
            index += 1;
            continue;
        }
        started = true;
        index = try lex_one(text, index, context, out, refusal);
    }
    if (started) try list.add(refusal, context.line, out.since(word_start));
}

/// Reads the token at `index` (a quoted run, an escape, a substitution or one byte) into `out`;
/// returns the index after it.
fn lex_one(
    text: []const u8,
    index: usize,
    context: *const Context,
    out: *Out,
    refusal: *Refusal,
) Refused!usize {
    assert(index < text.len);
    const byte = text[index];
    const line = context.line;
    if (byte == '\'') {
        const end = std.mem.indexOfScalarPos(u8, text, index + 1, '\'') orelse
            return refuse_quote(refusal, line, '\'');
        try out.push(refusal, line, text[index + 1 .. end]);
        return end + 1;
    }
    if (byte == '"') return lex_double(text, index + 1, context, out, refusal);
    if (byte == context.escape) {
        if (index + 1 == text.len) {
            try out.push(refusal, line, text[index..]);
            return text.len;
        }
        try out.push(refusal, line, text[index + 1 ..][0..1]);
        return index + 2;
    }
    if (byte == '$') return dollar(text, index, context, out, refusal);
    try out.push(refusal, line, text[index..][0..1]);
    return index + 1;
}

fn lex_double(
    text: []const u8,
    start: usize,
    context: *const Context,
    out: *Out,
    refusal: *Refusal,
) Refused!usize {
    var index = start;
    const line = context.line;
    while (index < text.len) {
        const byte = text[index];
        if (byte == '"') return index + 1;
        if (byte == '$') {
            index = try dollar(text, index, context, out, refusal);
            continue;
        }
        if (byte == context.escape and index + 1 < text.len) {
            const next = text[index + 1];
            if (next == '"' or next == '$' or next == context.escape) {
                try out.push(refusal, line, &.{next});
                index += 2;
                continue;
            }
        }
        try out.push(refusal, line, &.{byte});
        index += 1;
    }
    return refuse_quote(refusal, line, '"');
}

fn refuse_quote(refusal: *Refusal, line: u32, quote: u8) Refused {
    return refuse(refusal, .E0810, line, "Dockerfile:{d} opens a `{c}` quote and does not " ++
        "close it", .{ line, quote }, "close the quote, or escape it", .{});
}

fn is_name_start(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn is_name_byte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

/// A `$` at `index`: `$NAME`, `${...}`, or a literal `$`.
fn dollar(
    text: []const u8,
    index: usize,
    context: *const Context,
    out: *Out,
    refusal: *Refusal,
) Refused!usize {
    assert(text[index] == '$');
    const line = context.line;
    if (index + 1 < text.len and text[index + 1] == '{') {
        return braced(text, index + 2, context, out, refusal);
    }
    var end = index + 1;
    if (end < text.len and is_name_start(text[end])) {
        while (end < text.len and is_name_byte(text[end])) end += 1;
        try put_plain(text[index + 1 .. end], context, out, refusal);
        return end;
    }
    try out.push(refusal, line, "$");
    return index + 1;
}

fn put_plain(name: []const u8, context: *const Context, out: *Out, refusal: *Refusal) !void {
    assert(name.len > 0);
    switch (context.lookup.get(context.lookup.context, name)) {
        .unset => {},
        .missing => return refuse_missing(refusal, context.line, name),
        .set => |value| try out.push(refusal, context.line, value),
    }
}

pub fn refuse_missing(refusal: *Refusal, line: u32, name: []const u8) Refused {
    return refuse(refusal, .E0812, line, "Dockerfile:{d} uses `{s}`, an ARG with no " ++
        "default and no value given", .{ line, name }, "pass `--build-arg {s}=...`, or give " ++
        "the ARG a default", .{name});
}

const Operator = enum {
    plain,
    default_empty,
    default_unset,
    alt_empty,
    alt_unset,
    error_empty,
    error_unset,
};

/// `${` at `start - 2`: reads the name, the operator and its word up to the matching `}`.
fn braced(
    text: []const u8,
    start: usize,
    context: *const Context,
    out: *Out,
    refusal: *Refusal,
) Refused!usize {
    const line = context.line;
    var index = start;
    while (index < text.len and is_name_byte(text[index])) index += 1;
    const name = text[start..index];
    if (name.len == 0 or index >= text.len) return refuse_substitution(refusal, line, text, start);
    const operator = try operator_at(text, &index, refusal, line);
    const word_start = index;
    const end = closing_brace(text, index) orelse
        return refuse_substitution(refusal, line, text, start);
    const word = text[word_start..end];
    if (operator == .plain) {
        if (word.len > 0) return refuse_substitution(refusal, line, text, start);
        try put_plain(name, context, out, refusal);
        return end + 1;
    }
    const value = context.lookup.get(context.lookup.context, name);
    const is_set = value == .set;
    const non_empty = is_set and value.set.len > 0;
    switch (operator) {
        .plain => unreachable, // Handled above.
        .default_empty, .default_unset => {
            const use_value = if (operator == .default_empty) non_empty else is_set;
            if (use_value) try out.push(refusal, line, value.set) else {
                try nested(word, context, out, refusal);
            }
        },
        .alt_empty, .alt_unset => {
            const use_word = if (operator == .alt_empty) non_empty else is_set;
            if (use_word) try nested(word, context, out, refusal);
        },
        .error_empty, .error_unset => {
            const fine = if (operator == .error_empty) non_empty else is_set;
            if (!fine) {
                return refuse(refusal, .E0812, line, "Dockerfile:{d} requires `{s}`: {s}", .{
                    line, name, if (word.len > 0) word else "it has no value",
                }, "pass `--build-arg {s}=...`", .{name});
            }
            try out.push(refusal, line, value.set);
        },
    }
    return end + 1;
}

fn operator_at(text: []const u8, index: *usize, refusal: *Refusal, line: u32) Refused!Operator {
    assert(index.* < text.len);
    const byte = text[index.*];
    if (byte == '}') return .plain;
    const colon = byte == ':';
    const at = if (colon) index.* + 1 else index.*;
    if (at >= text.len) return refuse_substitution(refusal, line, text, index.*);
    index.* = at + 1;
    switch (text[at]) {
        '-' => return if (colon) .default_empty else .default_unset,
        '+' => return if (colon) .alt_empty else .alt_unset,
        '?' => return if (colon) .error_empty else .error_unset,
        '#', '%', '/' => if (!colon) {
            const what = "Dockerfile:{d} uses the `${{X{c}...}}` substitution, which is " ++
                "pre-release Dockerfile syntax";
            const fix = "do the edit in a RUN step's shell, or pass the value with --build-arg";
            return refuse(refusal, .E0811, line, what, .{ line, text[at] }, fix, .{});
        },
        else => {},
    }
    return refuse_substitution(refusal, line, text, at);
}

fn closing_brace(text: []const u8, start: usize) ?usize {
    var depth: u32 = 0;
    var index = start;
    while (index < text.len) : (index += 1) {
        if (text[index] == '{') depth += 1;
        if (text[index] == '}') {
            if (depth == 0) return index;
            depth -= 1;
        }
    }
    return null;
}

/// An operator's word: `$Y` and `${Y}` are substituted, escapes read; another operator is E0811.
fn nested(word: []const u8, context: *const Context, out: *Out, refusal: *Refusal) !void {
    const line = context.line;
    var index: usize = 0;
    while (index < word.len) {
        const byte = word[index];
        if (byte == context.escape and index + 1 < word.len) {
            try out.push(refusal, line, word[index + 1 ..][0..1]);
            index += 2;
        } else if (byte == '$' and index + 1 < word.len and word[index + 1] == '{') {
            const end = std.mem.indexOfScalarPos(u8, word, index, '}') orelse word.len;
            const name = word[index + 2 .. end];
            var plain = name.len > 0 and end < word.len;
            for (name) |name_byte| plain = plain and is_name_byte(name_byte);
            if (!plain) {
                return refuse(refusal, .E0811, line, "Dockerfile:{d} nests a substitution " ++
                    "with an operator inside another", .{line}, "set the inner value in its " ++
                    "own ARG or ENV first", .{});
            }
            try put_plain(name, context, out, refusal);
            index = end + 1;
        } else if (byte == '$' and index + 1 < word.len and is_name_start(word[index + 1])) {
            var end = index + 1;
            while (end < word.len and is_name_byte(word[end])) end += 1;
            try put_plain(word[index + 1 .. end], context, out, refusal);
            index = end;
        } else {
            try out.push(refusal, line, word[index..][0..1]);
            index += 1;
        }
    }
}

fn refuse_substitution(refusal: *Refusal, line: u32, text: []const u8, at: usize) Refused {
    const from = if (at >= 2) at - 2 else 0;
    const shown = text[from..@min(text.len, from + 32)];
    return refuse(refusal, .E0810, line, "Dockerfile:{d} has a substitution it cannot read " ++
        "at `{s}`", .{ line, shown }, "write `${{NAME}}`, `${{NAME:-default}}` or " ++
        "`${{NAME:+word}}`, or escape the `$`", .{});
}

const testing = std.testing;

const TestVariables = struct {
    fn get(context: *const anyopaque, name: []const u8) Value {
        _ = context;
        if (std.mem.eql(u8, name, "A")) return .{ .set = "a b" };
        if (std.mem.eql(u8, name, "E")) return .{ .set = "" };
        if (std.mem.eql(u8, name, "M")) return .missing;
        return .unset;
    }
};

const test_context: Context = .{
    .escape = '\\',
    .line = 7,
    .lookup = .{ .context = &test_context, .get = TestVariables.get },
};

fn expect_word(text: []const u8, expected: []const u8) !void {
    var bytes: [256]u8 = undefined;
    @memset(&bytes, 0xaa);
    var out: Out = .{ .bytes = &bytes };
    var refusal: Refusal = undefined;
    const word = try word_of(text, &test_context, &out, &refusal);
    try testing.expectEqualStrings(expected, word);
}

fn expect_refused(text: []const u8, code: refusal_mod.Code) !void {
    var bytes: [256]u8 = undefined;
    var out: Out = .{ .bytes = &bytes };
    var refusal: Refusal = undefined;
    try testing.expectError(error.Refused, word_of(text, &test_context, &out, &refusal));
    try testing.expectEqual(code, refusal.code);
    try testing.expectEqual(@as(u32, 7), refusal.line);
}

test "substitution follows Docker's operators" {
    // Goal: each operator on a set, an empty and an unset variable. Method: one word each.
    try expect_word("$A", "a b");
    try expect_word("${A}x", "a bx");
    try expect_word("$U-$", "-$");
    try expect_word("${E:-d}|${E-d}|${U-d}", "d||d");
    try expect_word("${A:+w}|${E:+w}|${E+w}|${U+w}", "w||w|");
    try expect_word("${U:-$A}${U:-${A}}", "a ba b");
    try expect_word("${A?no}", "a b");
    try expect_word("${M:-ok}", "ok");
    try expect_word("'$A' \"$A\" \\$A", "$A a b $A");
    try expect_word("\"q\\\"\\$\\x\"", "q\"$\\x");
}

test "substitution refusals name their code" {
    // Goal: E0812 for a missing value, E0811 for pattern forms, E0810 for syntax. Method: one
    // word each.
    try expect_refused("$M", .E0812);
    try expect_refused("${M}", .E0812);
    try expect_refused("${U?needed}", .E0812);
    try expect_refused("${E:?needed}", .E0812);
    try expect_refused("${A#x}", .E0811);
    try expect_refused("${A%x}", .E0811);
    try expect_refused("${A/x/y}", .E0811);
    try expect_refused("${U:-${A:-x}}", .E0811);
    try expect_refused("${A", .E0810);
    try expect_refused("${}", .E0810);
    try expect_refused("'open", .E0810);
    try expect_refused("\"open", .E0810);
}

test "words split at unquoted blanks and never after substitution" {
    // Goal: Docker's word splitting. Method: a text with quotes, an empty quoted word and an
    // expansion holding a blank.
    var bytes: [256]u8 = undefined;
    var out: Out = .{ .bytes = &bytes };
    var list: WordList = undefined;
    var refusal: Refusal = undefined;
    try words_of("  a=\"x y\"  '' $A  b\\ c ", &test_context, &out, &list, &refusal);
    try testing.expectEqual(@as(u32, 4), list.count);
    try testing.expectEqualStrings("a=x y", list.items[0]);
    try testing.expectEqualStrings("", list.items[1]);
    try testing.expectEqualStrings("a b", list.items[2]);
    try testing.expectEqualStrings("b c", list.items[3]);
}

test "exec form is a JSON array of strings, and anything else is not" {
    // Goal: the JSON forms Docker reads as exec form. Method: valid arrays and near misses.
    var bytes: [256]u8 = undefined;
    var out: Out = .{ .bytes = &bytes };
    var list: WordList = undefined;
    var refusal: Refusal = undefined;
    try testing.expect(try exec_form(" [ \"a\\n\" , \"\\u00e9\\/\" ] ", 1, &out, &list, &refusal));
    try testing.expectEqual(@as(u32, 2), list.count);
    try testing.expectEqualStrings("a\n", list.items[0]);
    try testing.expectEqualStrings("\xc3\xa9/", list.items[1]);
    try testing.expect(try exec_form("[]", 1, &out, &list, &refusal));
    try testing.expectEqual(@as(u32, 0), list.count);
    const not_exec = [_][]const u8{
        "[a]", "[\"a\",]", "[\"a\"] b", "[\"a\"", "echo [", "[\"\\u0000\"]", "[\"\\ud800\"]",
    };
    for (not_exec) |text| try testing.expect(!try exec_form(text, 1, &out, &list, &refusal));
}

test "flags are split off the front, values as written" {
    // Goal: `--name=value` and `--name`, then the rest. Method: one COPY-like text.
    var flags: Flags = undefined;
    var refusal: Refusal = undefined;
    try flags_of("--from=$X --link  a b", 1, &flags, &refusal);
    try testing.expectEqual(@as(u32, 2), flags.count);
    try testing.expectEqualStrings("$X", flags.items[0].value.?);
    try testing.expect(flags.items[1].value == null);
    try testing.expectEqualStrings("a b", flags.rest);
}

test "the word bound is E0815 one past it" {
    // Goal: `import_words_max` at the bound and one past it. Method: that many one-byte words.
    var text: [(constants.import_words_max + 1) * 2]u8 = @splat(' ');
    for (0..constants.import_words_max + 1) |index| text[index * 2] = 'w';
    var bytes: [1024]u8 = undefined;
    var out: Out = .{ .bytes = &bytes };
    var list: WordList = undefined;
    var refusal: Refusal = undefined;
    try words_of(text[0 .. constants.import_words_max * 2], &test_context, &out, &list, &refusal);
    try testing.expectEqual(constants.import_words_max, list.count);
    out.len = 0;
    try testing.expectError(error.Refused, words_of(&text, &test_context, &out, &list, &refusal));
    try testing.expectEqual(refusal_mod.Code.E0815, refusal.code);
}
