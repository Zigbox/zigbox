//! The bounded JSON readers the cloud credential sources share: what AWS and Google send back is
//! JSON (or, for AWS STS, XML) and is read here without allocating, as slices of a body that is
//! already in memory. What comes out is as secret as the body it came from, so the caller zeroes
//! the body.
//!
//! Two kinds of reader live here:
//!
//! - The flat field readers M6c wrote for AWS (`string_field`, `number_field`): a search for
//!   `"name":` anywhere in the body. They do not understand nesting and refuse a value with a
//!   backslash, which is all an AWS answer needs. Their behaviour is unchanged by the move.
//! - The member reader Google's documents need (`Members`, `member`): a walk over the members of
//!   one object, which knows where each value ends, skips nested values without recursion (to at
//!   most `cloud_json_depth_max` levels), refuses a duplicated or escaped member name and
//!   anything after the object, and hands back each value with its kind. A credentials file has
//!   `type` both at its top level and under `credential_source.format`; a flat search cannot
//!   tell them apart, and must not.
//!
//! Also here: the RFC 3339 timestamp and the seconds-count readers both clouds use.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Error = error{Malformed};

/// A field's text between `"name":"` and the next quote, or null if it is not there. A backslash
/// anywhere in the value makes it null too. A flat search: see the file comment.
pub fn string_field(body: []const u8, comptime name: []const u8) ?[]const u8 {
    const key = "\"" ++ name ++ "\"";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, body, from, key)) |found| {
        from = found + key.len;
        var at = from;
        while (at < body.len and is_blank(body[at])) at += 1;
        if (at == body.len or body[at] != ':') continue;
        at += 1;
        while (at < body.len and is_blank(body[at])) at += 1;
        if (at == body.len or body[at] != '"') continue;
        at += 1;
        const end = std.mem.indexOfScalarPos(u8, body, at, '"') orelse return null;
        const value = body[at..end];
        if (std.mem.indexOfScalar(u8, value, '\\') != null) return null;
        return value;
    }
    return null;
}

/// A field's number text, `"name":1.7E9`, or null. A flat search: see the file comment.
pub fn number_field(body: []const u8, comptime name: []const u8) ?[]const u8 {
    const key = "\"" ++ name ++ "\"";
    const found = std.mem.indexOf(u8, body, key) orelse return null;
    var at = found + key.len;
    while (at < body.len and is_blank(body[at])) at += 1;
    if (at == body.len or body[at] != ':') return null;
    at += 1;
    while (at < body.len and is_blank(body[at])) at += 1;
    const start = at;
    while (at < body.len and is_number_byte(body[at])) at += 1;
    if (at == start) return null;
    return body[start..at];
}

pub fn is_blank(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

fn is_number_byte(byte: u8) bool {
    return std.ascii.isDigit(byte) or byte == '.' or byte == 'E' or byte == 'e' or byte == '+' or
        byte == '-';
}

/// `2026-11-09T12:00:00Z`, with fractional seconds allowed and dropped, as seconds since the
/// epoch; null for anything else, or a date before 1970 or after the year 2200.
pub fn parse_timestamp(text: []const u8) ?u64 {
    if (text.len < 20) return null;
    const separators = [_]struct { at: u32, byte: u8 }{
        .{ .at = 4, .byte = '-' },  .{ .at = 7, .byte = '-' },  .{ .at = 10, .byte = 'T' },
        .{ .at = 13, .byte = ':' }, .{ .at = 16, .byte = ':' },
    };
    for (separators) |separator| {
        if (text[separator.at] != separator.byte) return null;
    }
    const year = digits(text[0..4]) orelse return null;
    const month = digits(text[5..7]) orelse return null;
    const day = digits(text[8..10]) orelse return null;
    const hour = digits(text[11..13]) orelse return null;
    const minute = digits(text[14..16]) orelse return null;
    const second = digits(text[17..19]) orelse return null;
    var at: usize = 19;
    if (text[at] == '.') {
        at += 1;
        const fraction_start = at;
        while (at < text.len and std.ascii.isDigit(text[at])) at += 1;
        if (at == fraction_start) return null;
    }
    if (at + 1 != text.len or text[at] != 'Z') return null;
    if (year < 1970 or year > 2200) return null;
    if (month < 1 or month > 12) return null;
    if (day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    const days = days_from_civil(year, month, day);
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

fn digits(text: []const u8) ?u64 {
    var value: u64 = 0;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        value = value * 10 + (byte - '0');
    }
    return value;
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm), for dates from 1970 on.
fn days_from_civil(year: u64, month: u64, day: u64) u64 {
    assert(year >= 1970);
    assert(month >= 1);
    assert(month <= 12);
    const shifted_year = if (month <= 2) year - 1 else year;
    const era = shifted_year / 400;
    const year_of_era = shifted_year - era * 400;
    const month_index = if (month > 2) month - 3 else month + 9;
    const day_of_year = (153 * month_index + 2) / 5 + day - 1;
    const day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

/// A number of seconds, `1.7E9` or `1700000000` or `1700000000.123`, truncated.
pub fn parse_seconds(text: []const u8) ?u64 {
    const value = std.fmt.parseFloat(f64, text) catch return null;
    if (!(value >= 0)) return null;
    if (value >= 1 << 40) return null;
    return @intFromFloat(value);
}

/// What a member's value is. `literal` is `true`, `false` or `null`.
pub const Kind = enum { string, number, literal, object, array };

pub const Value = struct {
    kind: Kind,
    /// For a string, the text between its quotes, escapes as they were sent; for an object or an
    /// array, the whole value with its brackets (so `Members.init` can read an object again);
    /// otherwise the token.
    text: []const u8,
    /// Whether a string held a backslash. A caller that wants the plain text refuses it.
    escaped: bool = false,

    /// The string's text when the value is a string without escapes, or null.
    pub fn plain(value: Value) ?[]const u8 {
        if (value.kind != .string) return null;
        if (value.escaped) return null;
        return value.text;
    }
};

pub const Member = struct { name: []const u8, value: Value };

/// The members of one JSON object, in order. `init` takes the object's whole text (blanks around
/// it allowed); `next` gives each member, then null once the object is closed and nothing but
/// blanks follows it. Anything else is `Malformed`. `next` does not check names for repeats
/// (`member` does, and so must any caller that reads a member by name).
///
/// A nested object or array is only skipped: its brackets must match and its strings close, but
/// what lies between them is not checked (`[1 2 ,,]` passes). A caller that wants a nested value
/// reads it again with `Members.init` or `first_element`, which check that level; nothing may
/// rely on a skipped value having been validated.
pub const Members = struct {
    text: []const u8,
    at: u32,
    done: bool = false,

    pub fn init(text: []const u8) Error!Members {
        const at = skip_blank(text, 0);
        if (at == text.len or text[at] != '{') return error.Malformed;
        assert(text.len <= std.math.maxInt(u32));
        return .{ .text = text, .at = @intCast(at + 1) };
    }

    pub fn next(members: *Members) Error!?Member {
        if (members.done) return null;
        const text = members.text;
        assert(members.at <= text.len);
        var at = skip_blank(text, members.at);
        if (at == text.len) return error.Malformed;
        if (text[at] == '}') return members.close(at);
        if (text[at] != '"') return error.Malformed;
        const name_end = try scan_string(text, at);
        // A name with an escape could spell a member twice; no document here has one.
        if (name_end.escaped) return error.Malformed;
        const name = text[at + 1 .. name_end.end - 1];
        at = skip_blank(text, name_end.end);
        if (at == text.len or text[at] != ':') return error.Malformed;
        at = skip_blank(text, at + 1);
        const value = try scan_value(text, at);
        at = skip_blank(text, value.end);
        if (at == text.len) return error.Malformed;
        if (text[at] == ',') {
            at = skip_blank(text, at + 1);
            if (at == text.len or text[at] != '"') return error.Malformed;
        } else if (text[at] != '}') {
            return error.Malformed;
        }
        assert(at > members.at);
        members.at = @intCast(at);
        return .{ .name = name, .value = value.value };
    }

    fn close(members: *Members, at: usize) Error!?Member {
        assert(members.text[at] == '}');
        if (skip_blank(members.text, at + 1) != members.text.len) return error.Malformed;
        members.done = true;
        members.at = @intCast(members.text.len);
        return null;
    }
};

/// The value of the member `name` of the object `text`, or null when it has none. The whole
/// object is read, so a malformed object, or one that names the member twice, is `Malformed`
/// wherever the fault is.
pub fn member(text: []const u8, name: []const u8) Error!?Value {
    assert(name.len > 0);
    var members = try Members.init(text);
    var found: ?Value = null;
    var count: u32 = 0;
    while (try members.next()) |each| {
        count += 1;
        assert(count <= text.len);
        if (!std.mem.eql(u8, each.name, name)) continue;
        if (found != null) return error.Malformed;
        found = each.value;
    }
    return found;
}

/// The first element of the array `text`, or null for an empty array. Only the first element is
/// read and checked; the scan of the whole array checked that it closes.
pub fn first_element(text: []const u8) Error!?Value {
    var at = skip_blank(text, 0);
    if (at == text.len or text[at] != '[') return error.Malformed;
    const whole = try scan_value(text, at);
    if (skip_blank(text, whole.end) != text.len) return error.Malformed;
    at = skip_blank(text, at + 1);
    assert(at < text.len);
    if (text[at] == ']') return null;
    const element = try scan_value(text, at);
    return element.value;
}

fn skip_blank(text: []const u8, from: usize) usize {
    assert(from <= text.len);
    var at = from;
    while (at < text.len and is_blank(text[at])) at += 1;
    return at;
}

const StringEnd = struct { end: usize, escaped: bool };

/// The end (one past the closing quote) of the string that starts at `text[at]`. A control byte
/// in it, or no closing quote, is `Malformed`; an escape skips the byte after the backslash.
fn scan_string(text: []const u8, start: usize) Error!StringEnd {
    assert(text[start] == '"');
    var at = start + 1;
    var escaped = false;
    while (at < text.len) : (at += 1) {
        const byte = text[at];
        if (byte < 0x20) return error.Malformed;
        if (byte == '"') return .{ .end = at + 1, .escaped = escaped };
        if (byte == '\\') {
            escaped = true;
            at += 1;
        }
    }
    return error.Malformed;
}

const Scanned = struct { end: usize, value: Value };

fn scan_value(text: []const u8, at: usize) Error!Scanned {
    assert(at <= text.len);
    if (at == text.len) return error.Malformed;
    switch (text[at]) {
        '"' => {
            const string = try scan_string(text, at);
            const value: Value = .{
                .kind = .string,
                .text = text[at + 1 .. string.end - 1],
                .escaped = string.escaped,
            };
            return .{ .end = string.end, .value = value };
        },
        '{', '[' => {
            const end = try scan_nested(text, at);
            const kind: Kind = if (text[at] == '{') .object else .array;
            return .{ .end = end, .value = .{ .kind = kind, .text = text[at..end] } };
        },
        else => {
            var end = at;
            while (end < text.len and is_token_byte(text[end])) end += 1;
            if (end == at) return error.Malformed;
            const token = text[at..end];
            const literal = std.mem.eql(u8, token, "true") or std.mem.eql(u8, token, "false") or
                std.mem.eql(u8, token, "null");
            if (!literal and !number_valid(token)) return error.Malformed;
            const kind: Kind = if (literal) .literal else .number;
            return .{ .end = end, .value = .{ .kind = kind, .text = token } };
        },
    }
}

/// The end of the object or array that opens at `text[start]`, found with a stack of open
/// brackets (no recursion), at most `cloud_json_depth_max` deep. It checks that brackets match
/// and strings close; what lies between them is left to the reader that asks for it.
fn scan_nested(text: []const u8, start: usize) Error!usize {
    const opening = text[start];
    assert(std.mem.indexOfScalar(u8, "{[", opening) != null);
    var stack: [constants.cloud_json_depth_max]u8 = undefined;
    var depth: u32 = 0;
    var at = start;
    while (at < text.len) {
        const byte = text[at];
        switch (byte) {
            '"' => {
                at = (try scan_string(text, at)).end;
                continue;
            },
            '{', '[' => {
                if (depth == stack.len) return error.Malformed;
                stack[depth] = if (byte == '{') '}' else ']';
                depth += 1;
            },
            '}', ']' => {
                if (depth == 0 or stack[depth - 1] != byte) return error.Malformed;
                depth -= 1;
                if (depth == 0) return at + 1;
            },
            else => if (byte < 0x20 and !is_blank(byte)) return error.Malformed,
        }
        at += 1;
    }
    return error.Malformed;
}

fn is_token_byte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '+' or byte == '-';
}

/// A JSON number: an optional minus, digits, an optional fraction and exponent.
fn number_valid(token: []const u8) bool {
    assert(token.len > 0);
    var at: usize = 0;
    if (token[at] == '-') at += 1;
    const integer_start = at;
    while (at < token.len and std.ascii.isDigit(token[at])) at += 1;
    if (at == integer_start) return false;
    // JSON writes no leading zero: `0` and `0.5`, never `01`.
    if (token[integer_start] == '0') {
        if (at - integer_start > 1) return false;
    }
    if (at < token.len and token[at] == '.') {
        at += 1;
        const fraction_start = at;
        while (at < token.len and std.ascii.isDigit(token[at])) at += 1;
        if (at == fraction_start) return false;
    }
    if (at < token.len and (token[at] == 'e' or token[at] == 'E')) {
        at += 1;
        if (at < token.len and (token[at] == '+' or token[at] == '-')) at += 1;
        const exponent_start = at;
        while (at < token.len and std.ascii.isDigit(token[at])) at += 1;
        if (at == exponent_start) return false;
    }
    return at == token.len;
}

/// A whole number of seconds, `3599`, at most `limit`; null for a fraction, a sign, an exponent
/// or anything over the limit.
pub fn whole_seconds(value: Value, limit: u64) ?u64 {
    assert(limit > 0);
    if (value.kind != .number) return null;
    if (value.text.len == 0 or value.text.len > 12) return null;
    const seconds = digits(value.text) orelse return null;
    if (seconds > limit) return null;
    return seconds;
}

const testing = std.testing;

test "the member reader tells a top-level member from a nested one" {
    // Goal: `type` at the top and `type` under `format` are different members; the reader gives
    // the top one, and the nested object can be read again for its own.
    const text =
        \\ {"type": "external_account", "credential_source": {"file": "/t",
        \\   "format": {"type": "json", "subject_token_field_name": "id_token"}},
        \\   "n": -1.5e3, "flag": true, "list": [1, {"a": "]"}], "e": "a\"b"}
    ;
    const top = (try member(text, "type")).?;
    try testing.expectEqualStrings("external_account", top.plain().?);
    const source = (try member(text, "credential_source")).?;
    try testing.expectEqual(Kind.object, source.kind);
    const format = (try member(source.text, "format")).?;
    try testing.expectEqualStrings("json", (try member(format.text, "type")).?.plain().?);
    try testing.expectEqual(Kind.number, (try member(text, "n")).?.kind);
    try testing.expectEqual(Kind.literal, (try member(text, "flag")).?.kind);
    const escaped = (try member(text, "e")).?;
    try testing.expect(escaped.escaped);
    try testing.expect(escaped.plain() == null);
    try testing.expect(try member(text, "missing") == null);
    const list = (try member(text, "list")).?;
    try testing.expectEqualStrings("1", (try first_element(list.text)).?.text);
}

test "the member reader refuses what is not one object" {
    // Goal: a duplicate member, an escaped name, trailing bytes, unbalanced brackets, a bare word,
    // a control byte in a string, a leading zero and nesting past the bound are each `Malformed`.
    const bad = [_][]const u8{
        "",
        "[]",
        "{\"a\":1,\"a\":2}",
        "{\"a\\u0062\":1}",
        "{\"a\":1} x",
        "{\"a\":1,}",
        "{\"a\":[1}",
        "{\"a\":nope}",
        "{\"a\":\"x\ny\"}",
        "{\"a\":01x}",
        "{\"a\":01}",
        "{\"a\":-00.5}",
        "{\"a\" 1}",
        "{\"a\":1",
        "{\"a\":[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}",
    };
    for (bad) |text| {
        try testing.expectError(error.Malformed, member(text, "a"));
    }
    try testing.expect(try member("{}", "a") == null);
    try testing.expect(try first_element("[]") == null);
    // A lone zero, with or without a sign or a fraction, is a number.
    for ([_][]const u8{ "0", "-0", "0.5", "0e1", "10" }) |number| {
        var buffer: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "{{\"a\":{s}}}", .{number});
        try testing.expectEqualStrings(number, (try member(text, "a")).?.text);
    }
}

test "whole seconds are digits within the limit" {
    // Goal: `3599` reads; a fraction, a sign, an exponent or a number past the limit does not.
    const read = struct {
        fn seconds(text: []const u8) ?u64 {
            return whole_seconds(.{ .kind = .number, .text = text }, 43200);
        }
    };
    try testing.expectEqual(@as(?u64, 3599), read.seconds("3599"));
    try testing.expectEqual(@as(?u64, null), read.seconds("3599.5"));
    try testing.expectEqual(@as(?u64, null), read.seconds("-1"));
    try testing.expectEqual(@as(?u64, null), read.seconds("1e3"));
    try testing.expectEqual(@as(?u64, null), read.seconds("43201"));
}
