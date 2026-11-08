//! The canonical JSON writer and the bounded reader (docs/briefs/M8-trust.md, "The canonical JSON
//! writer"). The same statement must be the same bytes on every host, so one form exists and the
//! reader accepts nothing else:
//!
//!   - No whitespace anywhere. Members and elements come in the order the caller gives them
//!     (schema order, not sorted: this is not RFC 8785).
//!   - Strings are valid UTF-8. They escape exactly `"` and `\`, and the bytes below 0x20 as
//!     `\n`, `\t` and `\u00xx` (lowercase hex). Every other byte, `/` and 0x7f included, is raw.
//!   - Integers only, in decimal, with no sign unless negative, no leading zero and no `-0`.
//!     Neither side knows floats, `null` or exponents.
//!   - Containers nest at most `constants.json_depth_max` deep.
//!
//! The writer fills a buffer the caller gives it and never allocates. The reader is a pull
//! parser over bytes already in memory (the caller bounded their length when it read them): it
//! hands out one token per call, decodes strings into a buffer the caller gives it, and keeps
//! its container stack in a fixed array. Because it takes only what the writer writes, text it
//! reads to its end re-renders to itself byte for byte (REVIEW.md, "Parse accepts only what
//! render can write"); `src/fuzz_json.zig` checks that on random and damaged bytes.
//!
//! The reader checks the grammar, not a schema: it does not refuse a repeated member name, and
//! it does not know which members a record needs. The schema layer above reads members in the
//! order its writer writes them and refuses any other.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// What a bound or a bad input refuses, with no partial effect the caller must undo: a writer
/// that returned an error is abandoned, since its buffer holds a prefix.
pub const WriteError = error{
    /// The buffer is full.
    Overflow,
    /// A container would nest past `json_depth_max`.
    TooDeep,
    /// A string (or member name) is not valid UTF-8.
    InvalidUtf8,
};

pub const ReadError = error{
    /// The bytes are not the canonical form: any grammar error, a byte the writer never writes,
    /// a number out of range, invalid UTF-8, truncated or trailing bytes.
    Malformed,
    TooDeep,
    /// A string decodes to more bytes than the caller's buffer holds.
    TooLong,
};

const Kind = enum { object, array };

const Frame = struct {
    kind: Kind,
    /// Members (objects) or elements (arrays) started so far.
    count: u32,
    /// An object's key was written or read and its value is next.
    key_pending: bool,
};

const hex_digits = "0123456789abcdef";

pub const Writer = struct {
    buffer: []u8,
    length: u32,
    depth: u32,
    root_done: bool,
    frames: [constants.json_depth_max]Frame,

    pub fn init(buffer: []u8) Writer {
        assert(buffer.len <= std.math.maxInt(u32));
        return .{
            .buffer = buffer,
            .length = 0,
            .depth = 0,
            .root_done = false,
            .frames = undefined,
        };
    }

    /// The bytes written so far, which are the whole value once `depth` is back at 0 and the
    /// root is done.
    pub fn bytes(self: *const Writer) []const u8 {
        return self.buffer[0..self.length];
    }

    /// The finished value. Asserts that every container was closed and a value was written.
    pub fn finish(self: *const Writer) []const u8 {
        assert(self.depth == 0);
        assert(self.root_done);
        return self.bytes();
    }

    pub fn begin_object(self: *Writer) WriteError!void {
        try self.begin(.object);
    }

    pub fn begin_array(self: *Writer) WriteError!void {
        try self.begin(.array);
    }

    pub fn end_object(self: *Writer) WriteError!void {
        try self.end(.object, '}');
    }

    pub fn end_array(self: *Writer) WriteError!void {
        try self.end(.array, ']');
    }

    /// An object member's name. The next call writes its value.
    pub fn key(self: *Writer, name: []const u8) WriteError!void {
        assert(self.depth > 0);
        const frame = &self.frames[self.depth - 1];
        assert(frame.kind == .object);
        assert(!frame.key_pending);
        try self.put_string(name, if (frame.count > 0) ',' else null, ':');
        frame.count += 1;
        frame.key_pending = true;
    }

    pub fn string(self: *Writer, value: []const u8) WriteError!void {
        const separator = self.value_separator();
        try self.put_string(value, separator, null);
        self.value_done();
    }

    pub fn unsigned(self: *Writer, value: u64) WriteError!void {
        const separator = self.value_separator();
        try self.put_number(false, value, separator);
        self.value_done();
    }

    pub fn integer(self: *Writer, value: i64) WriteError!void {
        const separator = self.value_separator();
        try self.put_number(value < 0, @abs(value), separator);
        self.value_done();
    }

    pub fn boolean(self: *Writer, value: bool) WriteError!void {
        const separator = self.value_separator();
        if (separator) |byte| try self.put(&.{byte});
        try self.put(if (value) "true" else "false");
        self.value_done();
    }

    // Members: a key and its value in one call, for the schema writers that list members in
    // a fixed order.

    pub fn member_string(self: *Writer, name: []const u8, value: []const u8) WriteError!void {
        try self.key(name);
        try self.string(value);
    }

    pub fn member_unsigned(self: *Writer, name: []const u8, value: u64) WriteError!void {
        try self.key(name);
        try self.unsigned(value);
    }

    pub fn member_boolean(self: *Writer, name: []const u8, value: bool) WriteError!void {
        try self.key(name);
        try self.boolean(value);
    }

    pub fn member_object(self: *Writer, name: []const u8) WriteError!void {
        try self.key(name);
        try self.begin_object();
    }

    pub fn member_array(self: *Writer, name: []const u8) WriteError!void {
        try self.key(name);
        try self.begin_array();
    }

    fn begin(self: *Writer, kind: Kind) WriteError!void {
        if (self.depth == constants.json_depth_max) return error.TooDeep;
        const separator = self.value_separator();
        if (separator) |byte| try self.put(&.{byte});
        try self.put(if (kind == .object) "{" else "[");
        self.frames[self.depth] = .{ .kind = kind, .count = 0, .key_pending = false };
        self.depth += 1;
    }

    fn end(self: *Writer, kind: Kind, closer: u8) WriteError!void {
        assert(self.depth > 0);
        const frame = &self.frames[self.depth - 1];
        assert(frame.kind == kind);
        assert(!frame.key_pending);
        try self.put(&.{closer});
        self.depth -= 1;
        self.value_done();
    }

    /// The comma that must precede a value about to be written, if any. Asserts the value is
    /// allowed here: not after the root, and in an object only after a key.
    fn value_separator(self: *Writer) ?u8 {
        if (self.depth == 0) {
            assert(!self.root_done);
            return null;
        }
        const frame = &self.frames[self.depth - 1];
        if (frame.kind == .object) {
            assert(frame.key_pending);
            return null;
        }
        return if (frame.count > 0) ',' else null;
    }

    /// Called after a whole value (a scalar, or a container's closer) was written.
    fn value_done(self: *Writer) void {
        if (self.depth == 0) {
            self.root_done = true;
            return;
        }
        const frame = &self.frames[self.depth - 1];
        if (frame.kind == .object) {
            assert(frame.key_pending);
            frame.key_pending = false;
        } else {
            frame.count += 1;
        }
    }

    fn put(self: *Writer, text: []const u8) WriteError!void {
        const free = self.buffer.len - self.length;
        if (text.len > free) return error.Overflow;
        @memcpy(self.buffer[self.length..][0..text.len], text);
        self.length += @intCast(text.len);
    }

    /// A quoted, escaped string, after an optional leading separator, and before an optional
    /// trailing one (the colon after a key).
    fn put_string(self: *Writer, value: []const u8, before: ?u8, after: ?u8) WriteError!void {
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
        if (before) |byte| try self.put(&.{byte});
        try self.put("\"");
        var start: usize = 0;
        for (value, 0..) |byte, index| {
            const escape = needs_escape(byte);
            if (!escape) continue;
            try self.put(value[start..index]);
            try self.put_escape(byte);
            start = index + 1;
        }
        try self.put(value[start..]);
        try self.put("\"");
        if (after) |byte| try self.put(&.{byte});
    }

    fn put_escape(self: *Writer, byte: u8) WriteError!void {
        assert(needs_escape(byte));
        switch (byte) {
            '"' => try self.put("\\\""),
            '\\' => try self.put("\\\\"),
            '\n' => try self.put("\\n"),
            '\t' => try self.put("\\t"),
            else => {
                assert(byte < 0x20);
                const high = hex_digits[byte >> 4];
                try self.put(&.{ '\\', 'u', '0', '0', high, hex_digits[byte & 15] });
            },
        }
    }

    fn put_number(self: *Writer, negative: bool, magnitude: u64, before: ?u8) WriteError!void {
        var digits: [20]u8 = undefined; // u64 max has 20 digits.
        var start: usize = digits.len;
        var rest = magnitude;
        for (0..digits.len) |_| { // At most 20 digits: the loop ends at `rest == 0`.
            start -= 1;
            digits[start] = '0' + @as(u8, @intCast(rest % 10));
            rest = @divFloor(rest, 10);
            if (rest == 0) break;
        }
        assert(rest == 0);
        if (before) |byte| try self.put(&.{byte});
        if (negative) {
            assert(magnitude > 0); // There is no "-0".
            try self.put("-");
        }
        try self.put(digits[start..]);
    }
};

fn needs_escape(byte: u8) bool {
    if (byte < 0x20) return true;
    if (byte == '"') return true;
    return byte == '\\';
}

pub const Token = union(enum) {
    object_begin,
    object_end,
    array_begin,
    array_end,
    /// An object member's name; valid until the next call to `next`.
    key: []const u8,
    /// A string value; valid until the next call to `next`.
    string: []const u8,
    /// A number with no minus sign.
    unsigned: u64,
    /// A number with a minus sign (never zero).
    negative: i64,
    boolean: bool,
    /// The root value is complete and no byte follows it.
    end,
};

pub const Reader = struct {
    input: []const u8,
    position: u32,
    depth: u32,
    root_done: bool,
    failed: bool,
    frames: [constants.json_depth_max]Frame,

    pub fn init(input: []const u8) Reader {
        assert(input.len <= std.math.maxInt(u32));
        return .{
            .input = input,
            .position = 0,
            .depth = 0,
            .root_done = false,
            .failed = false,
            .frames = undefined,
        };
    }

    /// The next token. Strings and member names are decoded into `scratch`, and the token's
    /// slice stays valid until the next call. After an error the reader is finished: asserts
    /// that nobody calls it again. After `.end` it keeps answering `.end`.
    pub fn next(self: *Reader, scratch: []u8) ReadError!Token {
        assert(!self.failed);
        assert(self.position <= self.input.len);
        const token = self.step(scratch) catch |err| {
            self.failed = true;
            return err;
        };
        assert(self.depth <= constants.json_depth_max);
        return token;
    }

    fn step(self: *Reader, scratch: []u8) ReadError!Token {
        if (self.depth == 0) {
            if (!self.root_done) return self.value(scratch);
            if (self.position < self.input.len) return error.Malformed;
            return .end;
        }
        const frame = &self.frames[self.depth - 1];
        return switch (frame.kind) {
            .object => self.step_object(frame, scratch),
            .array => self.step_array(frame, scratch),
        };
    }

    fn step_object(self: *Reader, frame: *Frame, scratch: []u8) ReadError!Token {
        if (frame.key_pending) {
            frame.key_pending = false;
            return self.value(scratch);
        }
        if (try self.peek() == '}') {
            self.position += 1;
            self.close();
            return .object_end;
        }
        if (frame.count > 0) try self.expect(',');
        try self.expect('"');
        const name = try self.string_body(scratch);
        try self.expect(':');
        frame.count += 1;
        frame.key_pending = true;
        return .{ .key = name };
    }

    fn step_array(self: *Reader, frame: *Frame, scratch: []u8) ReadError!Token {
        if (try self.peek() == ']') {
            self.position += 1;
            self.close();
            return .array_end;
        }
        if (frame.count > 0) try self.expect(',');
        frame.count += 1;
        return self.value(scratch);
    }

    /// Pops a container whose closer was just consumed.
    fn close(self: *Reader) void {
        assert(self.depth > 0);
        self.depth -= 1;
        if (self.depth == 0) self.root_done = true;
    }

    /// A scalar is complete: at the root, nothing may follow it.
    fn scalar_done(self: *Reader) void {
        if (self.depth == 0) self.root_done = true;
    }

    fn peek(self: *const Reader) ReadError!u8 {
        if (self.position >= self.input.len) return error.Malformed;
        return self.input[self.position];
    }

    fn expect(self: *Reader, byte: u8) ReadError!void {
        if (try self.peek() != byte) return error.Malformed;
        self.position += 1;
    }

    fn value(self: *Reader, scratch: []u8) ReadError!Token {
        const byte = try self.peek();
        switch (byte) {
            '{' => return self.open(.object),
            '[' => return self.open(.array),
            '"' => {
                self.position += 1;
                const text = try self.string_body(scratch);
                self.scalar_done();
                return .{ .string = text };
            },
            't' => return self.literal("true", true),
            'f' => return self.literal("false", false),
            '-', '0'...'9' => return self.number(),
            else => return error.Malformed,
        }
    }

    fn open(self: *Reader, kind: Kind) ReadError!Token {
        if (self.depth == constants.json_depth_max) return error.TooDeep;
        self.frames[self.depth] = .{ .kind = kind, .count = 0, .key_pending = false };
        self.depth += 1;
        self.position += 1;
        return if (kind == .object) .object_begin else .array_begin;
    }

    fn literal(self: *Reader, text: []const u8, result: bool) ReadError!Token {
        const rest = self.input[self.position..];
        if (!std.mem.startsWith(u8, rest, text)) return error.Malformed;
        self.position += @intCast(text.len);
        self.scalar_done();
        return .{ .boolean = result };
    }

    fn number(self: *Reader) ReadError!Token {
        const negative = self.input[self.position] == '-';
        if (negative) self.position += 1;
        const first = try self.peek();
        if (!std.ascii.isDigit(first)) return error.Malformed;
        const leading_zero = first == '0';
        var magnitude: u64 = 0;
        var digits: u32 = 0;
        while (self.position < self.input.len) {
            const byte = self.input[self.position];
            if (!std.ascii.isDigit(byte)) break;
            if (leading_zero and digits > 0) return error.Malformed;
            const product = std.math.mul(u64, magnitude, 10) catch return error.Malformed;
            magnitude = std.math.add(u64, product, byte - '0') catch return error.Malformed;
            digits += 1;
            self.position += 1;
        }
        assert(digits > 0);
        self.scalar_done();
        if (!negative) return .{ .unsigned = magnitude };
        if (magnitude == 0) return error.Malformed; // "-0" is not canonical.
        const limit = @as(u64, 1) << 63;
        if (magnitude > limit) return error.Malformed;
        if (magnitude == limit) return .{ .negative = std.math.minInt(i64) };
        return .{ .negative = -@as(i64, @intCast(magnitude)) };
    }

    /// Decodes a string whose opening quote was consumed, through its closing quote, into
    /// `scratch`. Raw bytes below 0x20 are refused, and so is every escape the writer does not
    /// write.
    fn string_body(self: *Reader, scratch: []u8) ReadError![]const u8 {
        var length: usize = 0;
        // Each pass consumes one byte, so the string ends (or `peek` fails) within the input.
        while (self.position <= self.input.len) {
            const byte = try self.peek();
            self.position += 1;
            if (byte == '"') break;
            if (byte < 0x20) return error.Malformed;
            const decoded = if (byte == '\\') try self.escape() else byte;
            if (length == scratch.len) return error.TooLong;
            scratch[length] = decoded;
            length += 1;
        }
        const text = scratch[0..length];
        if (!std.unicode.utf8ValidateSlice(text)) return error.Malformed;
        return text;
    }

    /// The byte an escape stands for, after its backslash.
    fn escape(self: *Reader) ReadError!u8 {
        const letter = try self.peek();
        self.position += 1;
        switch (letter) {
            '"' => return '"',
            '\\' => return '\\',
            'n' => return '\n',
            't' => return '\t',
            'u' => {
                try self.expect('0');
                try self.expect('0');
                const high = try self.hex_digit();
                const low = try self.hex_digit();
                const decoded = high << 4 | low;
                // The writer spells \n and \t short, and escapes nothing at 0x20 or above.
                if (decoded >= 0x20) return error.Malformed;
                if (decoded == '\n' or decoded == '\t') return error.Malformed;
                return decoded;
            },
            else => return error.Malformed,
        }
    }

    fn hex_digit(self: *Reader) ReadError!u8 {
        const byte = try self.peek();
        self.position += 1;
        if (std.ascii.isDigit(byte)) return byte - '0';
        if (byte < 'a') return error.Malformed; // Lowercase only.
        if (byte > 'f') return error.Malformed;
        return byte - 'a' + 10;
    }
};
