//! The tokens of a build file (`zbx.build.zon`, docs/briefs/M7-build.md): the restricted ZON
//! subset the parser in `file.zig` reads. A token is one of `.{`, a field name (`.steps`), `=`,
//! `,`, `}`, a string, a decimal integer, `true` or `false`. Spaces, tabs, line ends and `//`
//! comments (to the end of the line) separate tokens and are never data. Anything else is an
//! `invalid` token, which the parser refuses with its line and column.
//!
//! The lexer only finds where a token ends; a string's escapes are decoded by the parser, into
//! its pool, so that a bad escape is reported where it is. Every position is a byte offset into
//! the text, which is at most `build_render_bytes_max` long, so a `u32` holds it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Tag = enum {
    /// `.{`: a struct or a list begins.
    open,
    /// `.name`: a field, the name without its dot.
    field,
    equals,
    comma,
    /// `}`: a struct or a list ends.
    close,
    /// `"..."`, with its quotes; the escapes are not decoded yet.
    string,
    integer,
    true_word,
    false_word,
    /// The end of the text.
    end,
    /// Anything else: a stray byte, a string without its closing quote on its line, a word.
    invalid,
};

pub const Token = struct {
    tag: Tag,
    /// The token's bytes are `text[start..end]`.
    start: u32,
    end: u32,
    /// Where it starts, counting from 1; the column counts bytes.
    line: u32,
    column: u32,
};

pub const Lexer = struct {
    text: []const u8,
    index: u32,
    line: u32,
    line_start: u32,

    pub fn init(text: []const u8) Lexer {
        assert(text.len <= constants.build_render_bytes_max);
        return .{ .text = text, .index = 0, .line = 1, .line_start = 0 };
    }

    /// The next token. After `end` it keeps returning `end`.
    pub fn next(lexer: *Lexer) Token {
        assert(lexer.index <= lexer.text.len);
        assert(lexer.line_start <= lexer.index);
        lexer.skip_space();
        const start = lexer.index;
        var token: Token = .{
            .tag = .end,
            .start = start,
            .end = start,
            .line = lexer.line,
            .column = start - lexer.line_start + 1,
        };
        if (start == lexer.text.len) return token;
        token.tag = lexer.scan();
        token.end = lexer.index;
        assert(token.end > token.start);
        assert(token.end <= lexer.text.len);
        return token;
    }

    /// Steps over spaces, line ends and comments, keeping the line count.
    fn skip_space(lexer: *Lexer) void {
        const text = lexer.text;
        while (lexer.index < text.len) {
            const byte = text[lexer.index];
            if (byte == '\n') {
                lexer.index += 1;
                lexer.line += 1;
                lexer.line_start = lexer.index;
            } else if (byte == ' ' or byte == '\t' or byte == '\r') {
                lexer.index += 1;
            } else if (is_comment(text, lexer.index)) {
                const end = std.mem.indexOfScalarPos(u8, text, lexer.index, '\n') orelse text.len;
                lexer.index = @intCast(end);
            } else {
                break;
            }
        }
        assert(lexer.index <= text.len);
    }

    /// Reads one token from `index` on, which is not a space; returns its tag.
    fn scan(lexer: *Lexer) Tag {
        const text = lexer.text;
        const start = lexer.index;
        assert(start < text.len);
        lexer.index += 1;
        switch (text[start]) {
            '=' => return .equals,
            ',' => return .comma,
            '}' => return .close,
            '"' => return lexer.scan_string(),
            '0'...'9' => {
                while (lexer.index < text.len and std.ascii.isDigit(text[lexer.index])) {
                    lexer.index += 1;
                }
                return if (lexer.at_word_end()) .integer else lexer.scan_word();
            },
            '.' => {
                if (lexer.index == text.len) return .invalid;
                if (text[lexer.index] == '{') {
                    lexer.index += 1;
                    return .open;
                }
                if (!is_name_start(text[lexer.index])) return .invalid;
                while (lexer.index < text.len and is_name_byte(text[lexer.index])) {
                    lexer.index += 1;
                }
                return .field;
            },
            'a'...'z', 'A'...'Z', '_' => {
                const tag = lexer.scan_word();
                const word = text[start..lexer.index];
                if (std.mem.eql(u8, word, "true")) return .true_word;
                if (std.mem.eql(u8, word, "false")) return .false_word;
                assert(tag == .invalid);
                return tag;
            },
            else => return .invalid,
        }
    }

    /// A word that is not a value (`null`, `12ab`): the rest of its name bytes, as one token.
    fn scan_word(lexer: *Lexer) Tag {
        assert(lexer.index > 0);
        while (lexer.index < lexer.text.len and is_name_byte(lexer.text[lexer.index])) {
            lexer.index += 1;
        }
        assert(lexer.index <= lexer.text.len);
        return .invalid;
    }

    /// A string ends at the first `"` not escaped by a `\`, on the same line.
    fn scan_string(lexer: *Lexer) Tag {
        const text = lexer.text;
        assert(text[lexer.index - 1] == '"');
        while (lexer.index < text.len) {
            const byte = text[lexer.index];
            if (byte == '\n') return .invalid;
            lexer.index += 1;
            if (byte == '"') return .string;
            if (byte == '\\') {
                if (lexer.index == text.len) return .invalid;
                if (text[lexer.index] == '\n') return .invalid;
                lexer.index += 1;
            }
        }
        assert(lexer.index == text.len);
        return .invalid;
    }

    fn at_word_end(lexer: *const Lexer) bool {
        assert(lexer.index <= lexer.text.len);
        if (lexer.index == lexer.text.len) return true;
        return !is_name_byte(lexer.text[lexer.index]);
    }
};

fn is_comment(text: []const u8, index: u32) bool {
    assert(index < text.len);
    if (text[index] != '/') return false;
    if (index + 1 == text.len) return false;
    return text[index + 1] == '/';
}

fn is_name_start(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn is_name_byte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

const testing = std.testing;

fn expect_tags(text: []const u8, expected: []const Tag) !void {
    var lexer = Lexer.init(text);
    for (expected) |tag| try testing.expectEqual(tag, lexer.next().tag);
    try testing.expectEqual(Tag.end, lexer.next().tag);
    try testing.expectEqual(Tag.end, lexer.next().tag);
}

test "the lexer finds every kind of token and skips comments" {
    // Goal: each token of the subset, and that comments and line ends are not data. Method: a
    // small file with one of each, then its positions.
    try expect_tags(
        ".{ .a = \"x\\\"y\", // a comment, with \"quotes\"\n .b = 12, .c = true, .d = false }",
        &.{
            .open,    .field,      .equals, .string, .comma,     .field, .equals,
            .integer, .comma,      .field,  .equals, .true_word, .comma, .field,
            .equals,  .false_word, .close,
        },
    );
    var lexer = Lexer.init("// head\n  .{\n\t.name");
    const open = lexer.next();
    try testing.expectEqual(@as(u32, 2), open.line);
    try testing.expectEqual(@as(u32, 3), open.column);
    const field = lexer.next();
    try testing.expectEqual(Tag.field, field.tag);
    try testing.expectEqualStrings(".name", lexer.text[field.start..field.end]);
    try testing.expectEqual(@as(u32, 3), field.line);
    try testing.expectEqual(@as(u32, 2), field.column);
}

test "what is not a token of the subset is one invalid token" {
    // Goal: the negative space. Method: a string cut by its line end or the end of the text, a
    // lone dot, a word, a number run into letters, a stray byte, and `.@"name"`.
    try expect_tags("\"abc\n\"", &.{ .invalid, .invalid });
    try expect_tags("\"abc\\", &.{.invalid});
    try expect_tags(". {", &.{ .invalid, .invalid });
    try expect_tags("null", &.{.invalid});
    try expect_tags("12ab", &.{.invalid});
    try expect_tags("\x00", &.{.invalid});
    try expect_tags(".@\"x\"", &.{ .invalid, .invalid, .string });
    try expect_tags("/", &.{.invalid});
    try expect_tags("", &.{});
}
