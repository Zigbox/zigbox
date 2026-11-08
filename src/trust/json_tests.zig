//! Unit and golden tests for `json.zig`: the canonical form byte for byte, the bounds at and
//! past their limit, and every non-canonical spelling the reader must refuse.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const json = @import("json.zig");

/// The golden: members in the caller's order (not sorted), no whitespace, every escape the form
/// has, an array of mixed scalars, an empty object and an empty array.
const golden =
    "{\"zeta\":\"a\\\"b\\\\c\\n\\t\\u0001\\u001f\\u0000 /\x7f" ++
    "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\"," ++
    "\"alpha\":[0,1,18446744073709551615,-1,-9223372036854775808,true,false,{},[]]," ++
    "\"nest\":{\"k\":{\"v\":\"\"}}}";

fn write_golden(writer: *json.Writer) !void {
    try writer.begin_object();
    try writer.member_string(
        "zeta",
        "a\"b\\c\n\t\x01\x1f\x00 /\x7f\u{e9}\u{20ac}\u{1f600}",
    );
    try writer.member_array("alpha");
    try writer.unsigned(0);
    try writer.unsigned(1);
    try writer.unsigned(std.math.maxInt(u64));
    try writer.integer(-1);
    try writer.integer(std.math.minInt(i64));
    try writer.boolean(true);
    try writer.boolean(false);
    try writer.begin_object();
    try writer.end_object();
    try writer.begin_array();
    try writer.end_array();
    try writer.end_array();
    try writer.member_object("nest");
    try writer.member_object("k");
    try writer.member_string("v", "");
    try writer.end_object();
    try writer.end_object();
    try writer.end_object();
}

test "the writer's canonical form is the golden" {
    // Goal: pin the bytes. Method: write the golden value and compare, then read it back token
    // by token and check each decoded value.
    var buffer: [256]u8 = undefined;
    var writer = json.Writer.init(&buffer);
    try write_golden(&writer);
    try testing.expectEqualStrings(golden, writer.finish());

    var scratch: [64]u8 = undefined;
    var reader = json.Reader.init(golden);
    try testing.expectEqual(json.Token.object_begin, try reader.next(&scratch));
    try testing.expectEqualStrings("zeta", (try reader.next(&scratch)).key);
    const text = (try reader.next(&scratch)).string;
    try testing.expectEqualStrings("a\"b\\c\n\t\x01\x1f\x00 /\x7f\u{e9}\u{20ac}\u{1f600}", text);
    try testing.expectEqualStrings("alpha", (try reader.next(&scratch)).key);
    try testing.expectEqual(json.Token.array_begin, try reader.next(&scratch));
    try testing.expectEqual(@as(u64, 0), (try reader.next(&scratch)).unsigned);
    try testing.expectEqual(@as(u64, 1), (try reader.next(&scratch)).unsigned);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), (try reader.next(&scratch)).unsigned);
    try testing.expectEqual(@as(i64, -1), (try reader.next(&scratch)).negative);
    try testing.expectEqual(@as(i64, std.math.minInt(i64)), (try reader.next(&scratch)).negative);
    try testing.expect((try reader.next(&scratch)).boolean);
    try testing.expect(!(try reader.next(&scratch)).boolean);
}

test "a scalar is a whole value, and only one value is allowed" {
    // Goal: root handling. Method: each scalar alone reads to `.end`; two values do not.
    var scratch: [8]u8 = undefined;
    for ([_][]const u8{ "1", "\"a\"", "true", "false", "-7", "{}", "[]" }) |text| {
        var reader = json.Reader.init(text);
        var tokens: u32 = 0;
        while (true) {
            const token = try reader.next(&scratch);
            if (token == .end) break;
            tokens += 1;
        }
        try testing.expect(tokens >= 1);
        try testing.expectEqual(json.Token.end, try reader.next(&scratch));
    }
    for ([_][]const u8{ "1 ", "1 1", "{}{}", "[]]", "\"a\"\"b\"", "truetrue", "" }) |text| {
        try testing.expectError(error.Malformed, read_all(text, &scratch));
    }
}

/// Reads `text` to its end, discarding tokens.
fn read_all(text: []const u8, scratch: []u8) json.ReadError!void {
    var reader = json.Reader.init(text);
    while (true) {
        const token = try reader.next(scratch);
        if (token == .end) return;
    }
}

/// Valid JSON, or nearly, but not what the writer writes.
const refused = [_][]const u8{
    // Layout, separators and structure; numbers; escapes; raw bytes; other literals.
    " {}",
    "{} ",
    "{ }",
    "[ ]",
    "[1, 2]",
    "{\"a\": 1}",
    "{\"a\":1 }",
    "{\"a\":1,}",
    "[1,]",
    "[,1]",
    "{,\"a\":1}",
    "{\"a\"1}",
    "{\"a\":}",
    "{1:2}",
    "{'a':1}",
    "[1 2]",
    "{\"a\":1\"b\":2}",
    "01",
    "00",
    "-0",
    "-01",
    "+1",
    "1.0",
    "1e2",
    "1E2",
    "0x1",
    "-",
    "-a",
    ".5",
    "1.",
    "18446744073709551616",
    "-9223372036854775809",
    "[1,01]",
    "\"\\u000A\"",
    "\"\\u000a\"",
    "\"\\u0009\"",
    "\"\\u001F\"",
    "\"\\u0020\"",
    "\"\\u0041\"",
    "\"\\u00e9\"",
    "\"\\u0100\"",
    "\"\\ud83d\\ude00\"",
    "\"\\/\"",
    "\"\\r\"",
    "\"\\b\"",
    "\"\\f\"",
    "\"\\x41\"",
    "\"\\",
    "\"\\u00\"",
    "\"\\u00g0\"",
    "\"a\nb\"",
    "\"a\tb\"",
    "\"a\x01\"",
    "\"abc",
    "\"\xff\"",
    "\"\xc3\"",
    "\"\xc0\x80\"",
    "\"\xed\xa0\x80\"",
    "\"\xf4\x90\x80\x80\"",
    "{\"a\xff\":1}",
    "null",
    "tru",
    "True",
    "nan",
    "Infinity",
    "[null]",
};

test "the reader refuses every non-canonical spelling" {
    // Goal: "parse accepts only what render can write". Method: each text is valid JSON, or
    // nearly, but not what the writer writes; every one is refused as malformed.
    var scratch: [16]u8 = undefined;
    for (refused) |text| {
        const result = read_all(text, &scratch);
        testing.expectError(error.Malformed, result) catch |err| {
            std.debug.print("accepted or wrong error: {s}\n", .{text});
            return err;
        };
    }
}

test "the writer refuses invalid UTF-8 and writes nothing for it" {
    // Goal: the writer's UTF-8 check. Method: bad strings, as values and as member names,
    // leave the buffer as it was.
    var buffer: [32]u8 = undefined;
    var writer = json.Writer.init(&buffer);
    try writer.begin_object();
    const before = writer.length;
    for ([_][]const u8{ "\xff", "\xc3", "\xc0\x80", "\xed\xa0\x80", "ok\xf4\x90\x80\x80" }) |bad| {
        try testing.expectError(error.InvalidUtf8, writer.key(bad));
        try testing.expectEqual(before, writer.length);
    }
    try writer.key("a");
    try testing.expectError(error.InvalidUtf8, writer.string("\xff"));
    try writer.string("v");
    try writer.end_object();
    try testing.expectEqualStrings("{\"a\":\"v\"}", writer.finish());
}

test "the writer escapes every byte below 0x20 and nothing else" {
    // Goal: the escape table, exhaustively. Method: write each ASCII byte alone, and check the
    // spelling and that the reader decodes it back.
    var buffer: [16]u8 = undefined;
    var scratch: [4]u8 = undefined;
    var byte: u8 = 0;
    while (byte < 0x80) : (byte += 1) {
        var writer = json.Writer.init(&buffer);
        try writer.string(&.{byte});
        const text = writer.finish();
        var expected: [8]u8 = undefined;
        const want: []const u8 = switch (byte) {
            '"' => "\"\\\"\"",
            '\\' => "\"\\\\\"",
            '\n' => "\"\\n\"",
            '\t' => "\"\\t\"",
            0...8, 11...31 => std.fmt.bufPrint(&expected, "\"\\u00{x:0>2}\"", .{byte}) catch
                return error.TestUnexpectedResult,
            else => std.fmt.bufPrint(&expected, "\"{c}\"", .{byte}) catch
                return error.TestUnexpectedResult,
        };
        try testing.expectEqualStrings(want, text);
        var reader = json.Reader.init(text);
        try testing.expectEqualSlices(u8, &.{byte}, (try reader.next(&scratch)).string);
    }
}

test "depth stops at json_depth_max, for the writer and the reader" {
    // Goal: the nesting bound at the limit and one past it. Method: nest arrays and objects.
    var buffer: [128]u8 = undefined;
    var writer = json.Writer.init(&buffer);
    var level: u32 = 0;
    while (level < constants.json_depth_max) : (level += 1) try writer.begin_array();
    try testing.expectError(error.TooDeep, writer.begin_array());
    try testing.expectError(error.TooDeep, writer.begin_object());
    while (level > 0) : (level -= 1) try writer.end_array();
    try testing.expectEqual(@as(usize, 2 * constants.json_depth_max), writer.finish().len);

    var text: [64]u8 = undefined;
    @memset(&text, '[');
    var scratch: [4]u8 = undefined;
    var reader = json.Reader.init(text[0 .. constants.json_depth_max + 1]);
    level = 0;
    while (level < constants.json_depth_max) : (level += 1) {
        try testing.expectEqual(json.Token.array_begin, try reader.next(&scratch));
    }
    try testing.expectError(error.TooDeep, reader.next(&scratch));
    // At the limit a whole value reads.
    var whole: [2 * constants.json_depth_max]u8 = undefined;
    @memset(whole[0..constants.json_depth_max], '[');
    @memset(whole[constants.json_depth_max..], ']');
    try read_all(&whole, &scratch);
}

test "a full buffer is an overflow, at every length" {
    // Goal: the buffer bound. Method: write the golden into every shorter buffer; each refuses
    // with Overflow and never writes past it (the canary byte after the buffer is intact).
    var big: [256]u8 = undefined;
    var reference = json.Writer.init(&big);
    try write_golden(&reference);
    const length = reference.finish().len;
    var small: [257]u8 = undefined;
    var size: usize = 0;
    while (size < length) : (size += 1) {
        @memset(&small, 0xa5);
        var writer = json.Writer.init(small[0..size]);
        try testing.expectError(error.Overflow, write_golden(&writer));
        for (small[size..]) |canary| try testing.expectEqual(@as(u8, 0xa5), canary);
    }
    var exact = json.Writer.init(small[0..length]);
    try write_golden(&exact);
}

test "a string longer than the scratch buffer is refused, one that fits is read" {
    // Goal: the reader's string bound, counted in decoded bytes. Method: scratch of 3 holds
    // "a\n" plus one byte, and not four.
    var scratch: [3]u8 = undefined;
    var reader = json.Reader.init("\"a\\nb\"");
    try testing.expectEqualStrings("a\nb", (try reader.next(&scratch)).string);
    var too_long = json.Reader.init("\"abcd\"");
    try testing.expectError(error.TooLong, too_long.next(&scratch));
    var key_long = json.Reader.init("{\"abcd\":1}");
    _ = try key_long.next(&scratch);
    try testing.expectError(error.TooLong, key_long.next(&scratch));
}

test "the reader reads a number at the edges of its range" {
    // Goal: the integer bounds. Method: u64 max and i64 min read; one past each is refused.
    var scratch: [4]u8 = undefined;
    var top = json.Reader.init("18446744073709551615");
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), (try top.next(&scratch)).unsigned);
    var bottom = json.Reader.init("-9223372036854775808");
    try testing.expectEqual(@as(i64, std.math.minInt(i64)), (try bottom.next(&scratch)).negative);
    try testing.expectError(error.Malformed, read_all("18446744073709551616", &scratch));
    try testing.expectError(error.Malformed, read_all("-9223372036854775809", &scratch));
    try testing.expectError(error.Malformed, read_all("99999999999999999999999", &scratch));
}
