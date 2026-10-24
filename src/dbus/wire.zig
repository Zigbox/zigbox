//! The D-Bus wire format, the part zbx needs (https://dbus.freedesktop.org/doc/dbus-specification
//! .html, "Message Format" and "Type System"). A `Writer` marshals little-endian values into a
//! fixed buffer; a `Reader` reads either byte order out of a slice. Both work on the types
//! `y b n q i u x t s o g`, arrays, structs and variants; nothing else exists here (no doubles,
//! no unix fds, no dict entries), because no call zbx makes needs them.
//!
//! Alignment: every value starts at an offset that is a multiple of its alignment, counted from
//! the start of the message. A message body starts at a multiple of eight, so a body marshalled
//! on its own from offset zero has the right alignment inside the message.
//!
//! Nothing here recurses. A `Reader` follows the shape its caller asks for, one call per value,
//! so how deep it goes is how deep the calling code is, never what the peer sends. The one
//! thing a peer controls, a signature string, is checked by `check_signature` with a counter.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const repeat = @import("../test_util.zig").repeat;

pub const Endian = std.builtin.Endian;

/// What a malformed or hostile message can be. A caller turns any of these into one protocol
/// diagnostic; the name is for the cause line.
pub const WireError = error{
    /// The bytes end before the value does.
    Truncated,
    /// Padding that is not zero, or a value not at its alignment.
    BadPadding,
    /// A boolean that is neither 0 nor 1, a string with a NUL inside, a path that is not one.
    BadValue,
    /// Longer than a bound in `constants.zig`.
    TooLong,
    /// A signature that is malformed or nests too deep.
    BadSignature,
    /// A header that breaks the rules of a message.
    BadHeader,
    /// A well-formed message of a kind or shape zbx does not read.
    Unsupported,
};

/// The alignment of the first byte of a value of this single-character type code.
pub fn alignment_of(code: u8) u32 {
    assert(code != 0);
    return switch (code) {
        'y', 'g', 'v' => 1,
        'n', 'q' => 2,
        'b', 'i', 'u', 's', 'o', 'a' => 4,
        'x', 't', '(' => 8,
        else => 0,
    };
}

pub fn pad_to(offset: u32, alignment: u32) u32 {
    assert(alignment >= 1);
    assert(alignment <= 8);
    assert(std.math.isPowerOfTwo(alignment));
    const mask = alignment - 1;
    const result = (offset + mask) & ~mask;
    assert(result >= offset);
    assert(result - offset < alignment);
    return result;
}

// ---- Writer --------------------------------------------------------------------------------

pub const ArrayMark = struct {
    /// Where the 4-byte length sits.
    length_at: u32,
    /// Where the first element starts (after the padding to the element alignment).
    start: u32,
};

pub const Writer = struct {
    buffer: []u8,
    len: u32,
    /// Set by any write that did not fit. A later write is ignored; `finish` reports it.
    failed: bool,

    pub fn init(buffer: []u8) Writer {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.dbus_message_bytes_max);
        return .{ .buffer = buffer, .len = 0, .failed = false };
    }

    /// The marshalled bytes, or `TooLong` if anything did not fit.
    pub fn finish(writer: *const Writer) WireError![]const u8 {
        if (writer.failed) return error.TooLong;
        assert(writer.len <= writer.buffer.len);
        assert(writer.len <= constants.dbus_message_bytes_max);
        return writer.buffer[0..writer.len];
    }

    fn room(writer: *Writer, count: u32) bool {
        assert(writer.len <= writer.buffer.len);
        assert(count <= constants.dbus_message_bytes_max);
        if (writer.failed) return false;
        if (count > writer.buffer.len - writer.len) {
            writer.failed = true;
            return false;
        }
        return true;
    }

    pub fn pad(writer: *Writer, alignment: u32) void {
        const target = pad_to(writer.len, alignment);
        if (!writer.room(target - writer.len)) return;
        @memset(writer.buffer[writer.len..target], 0);
        writer.len = target;
        assert(writer.len % alignment == 0);
    }

    fn put(writer: *Writer, bytes: []const u8) void {
        if (!writer.room(@intCast(bytes.len))) return;
        @memcpy(writer.buffer[writer.len..][0..bytes.len], bytes);
        writer.len += @intCast(bytes.len);
        assert(writer.len <= writer.buffer.len);
    }

    pub fn byte(writer: *Writer, value: u8) void {
        const before = writer.len;
        writer.put(&.{value});
        if (!writer.failed) assert(writer.len == before + 1);
    }

    pub fn boolean(writer: *Writer, value: bool) void {
        assert(@intFromBool(value) <= 1);
        writer.uint32(@intFromBool(value));
        if (!writer.failed) assert(writer.len % 4 == 0);
    }

    pub fn uint16(writer: *Writer, value: u16) void {
        writer.pad(2);
        writer.put(&std.mem.toBytes(std.mem.nativeToLittle(u16, value)));
        if (!writer.failed) assert(writer.len % 2 == 0);
    }

    pub fn uint32(writer: *Writer, value: u32) void {
        writer.pad(4);
        writer.put(&std.mem.toBytes(std.mem.nativeToLittle(u32, value)));
        if (!writer.failed) assert(writer.len % 4 == 0);
    }

    pub fn uint64(writer: *Writer, value: u64) void {
        writer.pad(8);
        writer.put(&std.mem.toBytes(std.mem.nativeToLittle(u64, value)));
        if (!writer.failed) assert(writer.len % 8 == 0);
    }

    /// A string: a 4-byte length, the bytes, a NUL. The text must not hold a NUL.
    pub fn string(writer: *Writer, text: []const u8) void {
        assert(std.mem.indexOfScalar(u8, text, 0) == null);
        if (text.len > constants.dbus_string_bytes_max) {
            writer.failed = true;
            return;
        }
        writer.uint32(@intCast(text.len));
        writer.put(text);
        writer.byte(0);
        if (!writer.failed) assert(writer.buffer[writer.len - 1] == 0);
    }

    /// An object path, which marshals as a string. The caller passes a valid path.
    pub fn object_path(writer: *Writer, text: []const u8) void {
        assert(path_is_valid(text));
        assert(text.len <= constants.dbus_string_bytes_max);
        writer.string(text);
    }

    /// A signature: a 1-byte length, the type codes, a NUL.
    pub fn signature(writer: *Writer, text: []const u8) void {
        assert(text.len <= constants.dbus_signature_bytes_max);
        writer.byte(@intCast(text.len));
        writer.put(text);
        writer.byte(0);
        if (!writer.failed) assert(writer.buffer[writer.len - 1] == 0);
    }

    /// Starts an array whose elements have alignment `element_alignment`. The length is patched
    /// by `array_end`. The padding between the length and the first element is not counted.
    pub fn array_begin(writer: *Writer, element_alignment: u32) ArrayMark {
        writer.pad(4);
        const length_at = writer.len;
        writer.uint32(0);
        writer.pad(element_alignment);
        if (!writer.failed) assert(writer.len >= length_at + 4);
        return .{ .length_at = length_at, .start = writer.len };
    }

    pub fn array_end(writer: *Writer, mark: ArrayMark) void {
        assert(mark.start >= mark.length_at + 4);
        if (writer.failed) return;
        assert(writer.len >= mark.start);
        const length = writer.len - mark.start;
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, length));
        @memcpy(writer.buffer[mark.length_at..][0..4], &bytes);
    }

    /// A struct (or dict entry) starts on an 8-byte boundary.
    pub fn struct_begin(writer: *Writer) void {
        writer.pad(8);
        if (!writer.failed) assert(writer.len % 8 == 0);
    }

    /// A variant: the signature of its one value, then the value, which the caller writes next.
    pub fn variant_begin(writer: *Writer, value_signature: []const u8) void {
        assert(value_signature.len > 0);
        assert(value_signature.len <= constants.dbus_signature_bytes_max);
        writer.signature(value_signature);
    }
};

// ---- Reader --------------------------------------------------------------------------------

pub const Reader = struct {
    bytes: []const u8,
    at: u32,
    endian: Endian,

    /// Reads `bytes`, whose first byte is at an offset that is a multiple of eight in the
    /// message (the message itself, or its body).
    pub fn init(bytes: []const u8, endian: Endian) Reader {
        assert(bytes.len <= constants.dbus_message_bytes_max);
        const reader: Reader = .{ .bytes = bytes, .at = 0, .endian = endian };
        assert(reader.remaining() == bytes.len);
        return reader;
    }

    pub fn remaining(reader: *const Reader) u32 {
        assert(reader.at <= reader.bytes.len);
        assert(reader.bytes.len <= constants.dbus_message_bytes_max);
        return @intCast(reader.bytes.len - reader.at);
    }

    /// Skips the padding up to `alignment`; every padding byte must be zero.
    pub fn align_to(reader: *Reader, alignment: u32) WireError!void {
        const target = pad_to(reader.at, alignment);
        if (target > reader.bytes.len) return error.Truncated;
        for (reader.bytes[reader.at..target]) |padding| {
            if (padding != 0) return error.BadPadding;
        }
        reader.at = target;
        assert(reader.at % alignment == 0);
    }

    fn take(reader: *Reader, count: u32) WireError![]const u8 {
        if (count > reader.remaining()) return error.Truncated;
        const slice = reader.bytes[reader.at..][0..count];
        reader.at += count;
        assert(reader.at <= reader.bytes.len);
        return slice;
    }

    pub fn byte(reader: *Reader) WireError!u8 {
        const taken = try reader.take(1);
        assert(taken.len == 1);
        return taken[0];
    }

    pub fn uint16(reader: *Reader) WireError!u16 {
        try reader.align_to(2);
        const taken = try reader.take(2);
        assert(taken.len == 2);
        return std.mem.readInt(u16, taken[0..2], reader.endian);
    }

    pub fn uint32(reader: *Reader) WireError!u32 {
        try reader.align_to(4);
        const taken = try reader.take(4);
        assert(taken.len == 4);
        return std.mem.readInt(u32, taken[0..4], reader.endian);
    }

    pub fn uint64(reader: *Reader) WireError!u64 {
        try reader.align_to(8);
        const taken = try reader.take(8);
        assert(taken.len == 8);
        return std.mem.readInt(u64, taken[0..8], reader.endian);
    }

    pub fn boolean(reader: *Reader) WireError!bool {
        const value = try reader.uint32();
        assert(reader.at % 4 == 0);
        return switch (value) {
            0 => false,
            1 => true,
            else => error.BadValue,
        };
    }

    /// A string. It must be followed by a NUL, hold none inside and fit the bound.
    pub fn string(reader: *Reader) WireError![]const u8 {
        const length = try reader.uint32();
        if (length > constants.dbus_string_bytes_max) return error.TooLong;
        const text = try reader.take(length);
        if ((try reader.byte()) != 0) return error.BadValue;
        if (std.mem.indexOfScalar(u8, text, 0) != null) return error.BadValue;
        assert(text.len <= constants.dbus_string_bytes_max);
        return text;
    }

    pub fn object_path(reader: *Reader) WireError![]const u8 {
        const text = try reader.string();
        if (!path_is_valid(text)) return error.BadValue;
        assert(text[0] == '/');
        return text;
    }

    /// A signature, checked (`check_signature`).
    pub fn signature(reader: *Reader) WireError![]const u8 {
        const length = try reader.byte();
        const text = try reader.take(length);
        if ((try reader.byte()) != 0) return error.BadValue;
        try check_signature(text);
        assert(text.len <= constants.dbus_signature_bytes_max);
        return text;
    }

    /// The length of an array and where its elements end. The caller reads elements until
    /// `reader.at == end`, at most `dbus_array_elements_max` of them.
    pub fn array_begin(reader: *Reader, element_alignment: u32) WireError!u32 {
        const length = try reader.uint32();
        if (length > constants.dbus_message_bytes_max) return error.TooLong;
        try reader.align_to(element_alignment);
        if (length > reader.remaining()) return error.Truncated;
        assert(reader.at % element_alignment == 0);
        return reader.at + length;
    }
};

/// An object path: "/" or components of [A-Za-z0-9_] separated by single slashes.
pub fn path_is_valid(text: []const u8) bool {
    assert(text.len <= constants.dbus_message_bytes_max);
    if (text.len == 0) return false;
    if (text[0] != '/') return false;
    if (text.len == 1) return true;
    if (text[text.len - 1] == '/') return false;
    var previous_slash = true; // The leading slash.
    for (text[1..]) |character| {
        if (character == '/') {
            if (previous_slash) return false;
            previous_slash = true;
            continue;
        }
        previous_slash = false;
        const word = std.ascii.isAlphanumeric(character) or character == '_';
        if (!word) return false;
    }
    return true;
}

/// Checks a signature against the grammar of the types zbx handles, with a depth counter and no
/// recursion: every code is a known one, parentheses match and are not empty, an array is
/// followed by an element, and nesting stays within `dbus_nesting_depth_max`.
pub fn check_signature(text: []const u8) WireError!void {
    if (text.len > constants.dbus_signature_bytes_max) return error.BadSignature;
    var depth: u32 = 0;
    var pending_arrays: u32 = 0; // Array markers waiting for their element.
    var previous: u8 = 0;
    for (text) |code| {
        switch (code) {
            'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 's', 'o', 'g', 'v' => pending_arrays = 0,
            'a' => {
                pending_arrays += 1;
                if (depth + pending_arrays > constants.dbus_nesting_depth_max) {
                    return error.BadSignature;
                }
            },
            '(' => {
                depth += 1;
                if (depth + pending_arrays > constants.dbus_nesting_depth_max) {
                    return error.BadSignature;
                }
            },
            ')' => {
                if (depth == 0) return error.BadSignature;
                if (pending_arrays > 0) return error.BadSignature;
                if (previous == '(') return error.BadSignature; // An empty struct.
                depth -= 1;
            },
            else => return error.BadSignature,
        }
        if (code == '(') pending_arrays = 0;
        previous = code;
    }
    if (depth != 0) return error.BadSignature;
    if (pending_arrays != 0) return error.BadSignature;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

test "alignment of every code, and padding to it" {
    // Goal: the table the writer and reader share. The spec's alignments, and the boundary
    // where padding is none.
    try testing.expectEqual(@as(u32, 1), alignment_of('y'));
    try testing.expectEqual(@as(u32, 2), alignment_of('q'));
    try testing.expectEqual(@as(u32, 4), alignment_of('s'));
    try testing.expectEqual(@as(u32, 8), alignment_of('t'));
    try testing.expectEqual(@as(u32, 8), alignment_of('('));
    try testing.expectEqual(@as(u32, 0), alignment_of('d')); // Doubles are not handled.
    try testing.expectEqual(@as(u32, 8), pad_to(5, 8));
    try testing.expectEqual(@as(u32, 8), pad_to(8, 8));
    try testing.expectEqual(@as(u32, 12), pad_to(9, 4));
}

test "a writer marshals the way the spec says, byte for byte" {
    // Goal: golden bytes written by hand from the specification: a string pads to four and
    // ends in a NUL, a u64 pads to eight, a boolean is a u32, a signature has a 1-byte length.
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    writer.byte(7);
    writer.string("hi");
    writer.uint64(0x0102030405060708);
    writer.boolean(true);
    writer.signature("au");
    const bytes = try writer.finish();
    const expected = [_]u8{
        7, 0, 0, 0, // The byte and its padding to the string's length.
        2, 0, 0, 0, 'h', 'i', 0, // The string: length, bytes, NUL.
        0, 0, 0, 0, 0, // Padding from 11 to 16.
        8, 7, 6, 5, 4, 3, 2, 1, // The u64, little-endian.
        1, 0, 0, 0, // The boolean.
        2, 'a', 'u', 0, // The signature.
    };
    try testing.expectEqualSlices(u8, &expected, bytes);
}

test "an array's length counts the elements, not the padding before them" {
    // Goal: an array of u64 starts its elements at an 8-byte boundary after the length, and the
    // length is the bytes of the elements only. Method: marshal two, then read them back.
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    const mark = writer.array_begin(8);
    writer.uint64(1);
    writer.uint64(2);
    writer.array_end(mark);
    const bytes = try writer.finish();
    try testing.expectEqual(@as(usize, 24), bytes.len);
    try testing.expectEqual(@as(u8, 16), bytes[0]);
    var reader = Reader.init(bytes, .little);
    const end = try reader.array_begin(8);
    try testing.expectEqual(@as(u32, 1), @as(u32, @intCast(try reader.uint64())));
    try testing.expectEqual(@as(u64, 2), try reader.uint64());
    try testing.expectEqual(end, reader.at);
}

test "a reader reads big-endian and refuses padding that is not zero" {
    // Goal: the byte order is the message's, and strict padding is enforced.
    const big = [_]u8{ 0, 0, 1, 2 };
    var reader = Reader.init(&big, .big);
    try testing.expectEqual(@as(u32, 258), try reader.uint32());
    const dirty = [_]u8{ 1, 0, 9, 0, 5, 0, 0, 0 };
    var second = Reader.init(&dirty, .little);
    _ = try second.byte();
    try testing.expectError(error.BadPadding, second.uint32());
}

test "a reader refuses a truncated, unterminated, oversized or NUL-holding string" {
    // Goal: the negative space of a string, one case for each way it is wrong.
    var reader = Reader.init(&.{ 5, 0, 0, 0, 'a', 'b' }, .little);
    try testing.expectError(error.Truncated, reader.string());
    reader = Reader.init(&.{ 1, 0, 0, 0, 'a', 'x' }, .little);
    try testing.expectError(error.BadValue, reader.string());
    reader = Reader.init(&.{ 2, 0, 0, 0, 'a', 0, 0 }, .little);
    try testing.expectError(error.BadValue, reader.string());
    var huge: [8]u8 = .{ 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0 };
    reader = Reader.init(&huge, .little);
    try testing.expectError(error.TooLong, reader.string());
    reader = Reader.init(&.{ 2, 0, 0, 0, 'a', 'b', 0 }, .little);
    try testing.expectEqualStrings("ab", try reader.string());
}

test "a boolean is 0 or 1" {
    var reader = Reader.init(&.{ 2, 0, 0, 0 }, .little);
    try testing.expectError(error.BadValue, reader.boolean());
    reader = Reader.init(&.{ 1, 0, 0, 0 }, .little);
    try testing.expect(try reader.boolean());
}

test "object paths: the grammar's edges" {
    // Goal: valid and invalid paths on both sides of each rule.
    try testing.expect(path_is_valid("/"));
    try testing.expect(path_is_valid("/org/freedesktop/systemd1"));
    try testing.expect(path_is_valid("/org/freedesktop/systemd1/job/42"));
    try testing.expect(!path_is_valid(""));
    try testing.expect(!path_is_valid("org"));
    try testing.expect(!path_is_valid("/org/"));
    try testing.expect(!path_is_valid("//org"));
    try testing.expect(!path_is_valid("/or-g"));
}

test "signatures: valid shapes, and every way to be wrong" {
    // Goal: the signature check accepts what zbx sends and refuses nesting past the bound, an
    // unbalanced or empty struct, a dangling array, and codes it does not handle.
    const good = [_][]const u8{ "", "s", "a(sv)", "a(sa(sv))", "uoss", "v", "au", "(ii)" };
    for (good) |text| try check_signature(text);
    const bad = [_][]const u8{ "a", "(", ")", "()", "(s", "s)", "d", "a)", "{ss}", "aa", "(a)" };
    for (bad) |text| try testing.expectError(error.BadSignature, check_signature(text));
    const depth = constants.dbus_nesting_depth_max;
    const deep_arrays = repeat('a', depth + 1) ++ "y";
    try testing.expectError(error.BadSignature, check_signature(deep_arrays));
    try check_signature(repeat('a', depth) ++ "y");
    const deep_structs = repeat('(', depth + 1) ++ "y" ++ repeat(')', depth + 1);
    try testing.expectError(error.BadSignature, check_signature(deep_structs));
    const long = repeat('y', constants.dbus_signature_bytes_max + 1);
    try testing.expectError(error.BadSignature, check_signature(long));
}

test "a writer that runs out of room fails once and stays failed" {
    // Goal: an oversized request is an error, never a write past the buffer.
    var buffer: [8]u8 = undefined;
    var writer = Writer.init(&buffer);
    writer.string("abcdefgh");
    try testing.expect(writer.failed);
    writer.byte(1);
    try testing.expectError(error.TooLong, writer.finish());
}
