//! Small text helpers: sanitising untrusted text for display and building bounded strings
//! without allocation.

const std = @import("std");
const assert = std.debug.assert;

pub fn is_printable(byte: u8) bool {
    if (byte < 0x20) return false;
    if (byte >= 0x7f) return false;
    return true;
}

/// Makes untrusted text safe to print: non-printable and non-ASCII bytes (which could carry
/// terminal escape sequences) become '?', and text longer than `storage` ends in "...".
/// Returns a slice of `storage`.
pub fn sanitise(storage: []u8, text: []const u8) []const u8 {
    const marker = "...";
    assert(storage.len >= marker.len);
    const truncated = text.len > storage.len;
    const keep = if (truncated) storage.len - marker.len else text.len;
    for (text[0..keep], storage[0..keep]) |byte, *out| {
        out.* = if (is_printable(byte)) byte else '?';
    }
    var result: []const u8 = storage[0..keep];
    if (truncated) {
        @memcpy(storage[keep..][0..marker.len], marker);
        assert(keep + marker.len == storage.len);
        result = storage[0..];
    }
    // Negative space: nothing printable-unsafe survives.
    for (result) |byte| assert(is_printable(byte));
    return result;
}

/// One part of a plain format, filled at the call site and written by `write_parts`.
pub const Part = union(enum) {
    text: []const u8,
    /// Wide enough for every `u64` and `i64`; `printInt` writes the same digits for either.
    integer: i65,
};

/// One piece of a plain format, known at compile time: literal text, or the index of a `{s}` or
/// `{d}` argument.
pub const Piece = union(enum) {
    literal: []const u8,
    string: u32,
    integer: u32,
};

/// The pieces of `format` if it is plain, else null. A plain format has only literal text (no
/// `{{` or `}}`), `{s}` taking a byte slice or a pointer to a byte array, and `{d}` taking an
/// integer of at most 64 bits, each argument used once in order. For those, the bytes that
/// `std.Io.Writer.print` writes are exactly `writeAll` of each literal and string and `printInt`
/// of each integer in base 10, with no padding, and that is what `write_parts` does. Code size:
/// every `print` call site with its own format otherwise instantiates the formatter.
pub fn plain_template(comptime format: []const u8, comptime Args: type) ?[]const Piece {
    comptime {
        if (@typeInfo(Args) != .@"struct") return null;
        const types = @typeInfo(Args).@"struct".field_types;
        var pieces: []const Piece = &.{};
        var arg: u32 = 0;
        var start: usize = 0;
        var index: usize = 0;
        while (index < format.len) : (index += 1) {
            if (format[index] == '}') return null;
            if (format[index] != '{') continue;
            assert(format[index] == '{');
            assert(start <= index);
            if (index + 2 >= format.len) return null;
            assert(index + 2 < format.len);
            if (format[index + 2] != '}') return null;
            if (arg >= types.len) return null;
            if (index > start) pieces = pieces ++ .{Piece{ .literal = format[start..index] }};
            const piece: Piece = switch (format[index + 1]) {
                's' => if (plain_string(types[arg])) .{ .string = arg } else return null,
                'd' => if (plain_integer(types[arg])) .{ .integer = arg } else return null,
                else => return null,
            };
            pieces = pieces ++ .{piece};
            arg += 1;
            assert(arg <= types.len);
            index += 2;
            start = index + 1;
        }
        if (arg != types.len) return null;
        assert(arg == types.len);
        assert(start <= format.len);
        if (format.len > start) pieces = pieces ++ .{Piece{ .literal = format[start..] }};
        assert(pieces.len <= 2 * types.len + 1);
        const result = pieces[0..pieces.len].*;
        return &result;
    }
}

fn plain_string(comptime T: type) bool {
    const info = switch (@typeInfo(T)) {
        .pointer => |pointer| pointer,
        else => return false,
    };
    if (info.size == .slice) return info.child == u8;
    if (info.size != .one) return false;
    return switch (@typeInfo(info.child)) {
        .array => |array| array.child == u8,
        else => false,
    };
}

fn plain_integer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .int => |int| int.bits <= 64,
        else => false,
    };
}

/// Fills `parts` from `args` by `template`: inlined, so a call site keeps no formatting code.
pub inline fn plain_parts(
    comptime template: []const Piece,
    parts: *[template.len]Part,
    args: anytype,
) void {
    const names = @typeInfo(@TypeOf(args)).@"struct".field_names;
    inline for (template, parts) |piece, *part| {
        part.* = switch (piece) {
            .literal => |literal| .{ .text = literal },
            .string => |arg| .{ .text = @field(args, names[arg]) },
            .integer => |arg| .{ .integer = @field(args, names[arg]) },
        };
    }
}

/// Writes the parts of a plain format, as `std.Io.Writer.print` would write the format.
pub noinline fn write_parts(writer: *std.Io.Writer, parts: []const Part) std.Io.Writer.Error!void {
    // A format has at most 32 arguments (std's bound), so at most 33 literals around them.
    assert(parts.len <= 65);
    assert(writer.end <= writer.buffer.len);
    for (parts) |part| {
        switch (part) {
            .text => |text| try writer.writeAll(text),
            .integer => |value| try writer.printInt(value, 10, .lower, .{}),
        }
    }
    assert(writer.end <= writer.buffer.len);
}

/// A fixed-capacity string. Appending past the capacity truncates and ends the text in "...",
/// so a message is always well formed and never overflows.
pub fn Bounded(comptime capacity: u32) type {
    comptime assert(capacity >= 8);
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        len: u32 = 0,
        truncated: bool = false,

        pub fn slice(self: *const Self) []const u8 {
            assert(self.len <= capacity);
            return self.bytes[0..self.len];
        }

        /// A plain format (see `plain_template`) is run by the shared `print_parts`, so a call
        /// site holds only its parts, not its own copy of the formatting code; any other format
        /// goes through `std.Io.Writer.print`. Both write the same bytes.
        pub fn print(self: *Self, comptime format: []const u8, args: anytype) void {
            if (comptime plain_template(format, @TypeOf(args))) |template| {
                var parts: [template.len]Part = undefined;
                plain_parts(template, &parts, args);
                self.print_parts(&parts);
            } else {
                assert(self.len <= capacity);
                if (self.truncated) return;
                var writer = std.Io.Writer.fixed(self.bytes[self.len..]);
                writer.print(format, args) catch return self.end_print(&writer, true);
                self.end_print(&writer, false);
            }
        }

        noinline fn print_parts(self: *Self, parts: []const Part) void {
            assert(self.len <= capacity);
            if (self.truncated) return;
            const start = self.len;
            var writer = std.Io.Writer.fixed(self.bytes[self.len..]);
            write_parts(&writer, parts) catch return self.end_print(&writer, true);
            self.end_print(&writer, false);
            assert(self.len >= start);
        }

        noinline fn end_print(self: *Self, writer: *std.Io.Writer, full: bool) void {
            assert(!self.truncated);
            assert(writer.buffered().len <= capacity - self.len);
            self.len += @intCast(writer.buffered().len);
            if (full) self.truncate();
            assert(self.len <= capacity);
        }

        /// Appends `text` with unsafe bytes replaced, limited to `limit` bytes of it.
        pub fn append_sanitised(self: *Self, text: []const u8, limit: u32) void {
            assert(limit >= 4);
            var storage: [capacity]u8 = undefined;
            const room = @min(limit, capacity);
            self.print("{s}", .{sanitise(storage[0..room], text)});
        }

        fn truncate(self: *Self) void {
            self.truncated = true;
            self.len = @min(self.len, capacity);
            if (self.len < 3) self.len = 3;
            @memcpy(self.bytes[self.len - 3 .. self.len], "...");
            assert(self.len <= capacity);
        }
    };
}

test "sanitise replaces unsafe bytes and marks truncation" {
    // Goal: escapes and non-ASCII never survive, and over-long text ends in "...".
    var storage: [8]u8 = undefined;
    try std.testing.expectEqualStrings("ab?d", sanitise(&storage, "ab\x1bd"));
    try std.testing.expectEqualStrings("?????", sanitise(&storage, "\xc3\xa9\xff\x00\x7f"));
    try std.testing.expectEqualStrings("abcde...", sanitise(&storage, "abcdefghij"));
    try std.testing.expectEqualStrings("abcdefgh", sanitise(&storage, "abcdefgh"));
    try std.testing.expectEqualStrings("", sanitise(&storage, ""));
}

test "Bounded formats, truncates at the boundary and stays truncated" {
    // Goal: exact fit is not truncated; one byte more is; later appends are ignored.
    var exact: Bounded(8) = .{};
    exact.print("{s}", .{"12345678"});
    try std.testing.expectEqualStrings("12345678", exact.slice());
    try std.testing.expect(!exact.truncated);

    var over: Bounded(8) = .{};
    over.print("{s}", .{"123456789"});
    try std.testing.expectEqualStrings("12345...", over.slice());
    over.print("{s}", .{"more"});
    try std.testing.expectEqualStrings("12345...", over.slice());

    var parts: Bounded(16) = .{};
    parts.print("a{d}", .{12});
    parts.print("-{s}", .{"bc"});
    try std.testing.expectEqualStrings("a12-bc", parts.slice());
    parts.append_sanitised("x\x1by", 16);
    try std.testing.expectEqualStrings("a12-bcx?y", parts.slice());
}

/// Runs `format` both ways into buffers of every size from 0 to 40 bytes and checks that the
/// plain path wrote the same bytes and failed the same way as `std.Io.Writer.print`.
fn expect_plain_matches_std(comptime format: []const u8, args: anytype) !void {
    const template = comptime plain_template(format, @TypeOf(args)).?;
    var parts: [template.len]Part = undefined;
    plain_parts(template, &parts, args);
    for (0..41) |size| {
        var expected_storage: [40]u8 = undefined;
        var actual_storage: [40]u8 = undefined;
        var expected = std.Io.Writer.fixed(expected_storage[0..size]);
        var actual = std.Io.Writer.fixed(actual_storage[0..size]);
        const expected_full = if (expected.print(format, args)) false else |_| true;
        const actual_full = if (write_parts(&actual, &parts)) false else |_| true;
        try std.testing.expectEqual(expected_full, actual_full);
        try std.testing.expectEqualStrings(expected.buffered(), actual.buffered());
    }
}

test "a plain format writes exactly what std.Io.Writer.print writes, at every buffer size" {
    // Goal: the shared plain path is a code-size change only. Method: each kind of piece, alone
    // and mixed, at the integer extremes, run into every buffer size so truncation inside a
    // literal, a string and a number is compared too.
    const slice: []const u8 = "a slice";
    const sentinel: [:0]const u8 = "sentinel";
    var mutable_storage = "mutable".*;
    const mutable: []u8 = &mutable_storage;
    try expect_plain_matches_std("", .{});
    try expect_plain_matches_std("only literal text, longer than some buffers", .{});
    try expect_plain_matches_std("{s}", .{slice});
    try expect_plain_matches_std("{s}{s}", .{ sentinel, mutable });
    try expect_plain_matches_std("<{s}> and {s}!", .{ "array literal", slice });
    try expect_plain_matches_std("{d}", .{@as(u8, 0)});
    const u64_max: u64 = std.math.maxInt(u64);
    const i64_min: i64 = std.math.minInt(i64);
    try expect_plain_matches_std("n={d} m={d}", .{ u64_max, i64_min });
    const i8_min: i8 = -128;
    try expect_plain_matches_std("{d}/{d}/{d}", .{ i8_min, @as(u32, 1234567), @as(i64, -1) });
    try expect_plain_matches_std("{d}{s}{d}", .{ @as(usize, 99), "", @as(u1, 1) });
    const steps = .{ @as(u16, 3), @as(u16, 12), slice };
    try expect_plain_matches_std("step {d} of {d}: {s} failed", steps);
}

test "a format is plain only when every piece is a literal, a byte string or a small integer" {
    // Goal: anything the plain path does not reproduce exactly goes to std. Method: one case per
    // rule, against the positive cases beside them.
    const slice: []const u8 = "x";
    const many: [*:0]const u8 = "x";
    const expect_plain = struct {
        fn check(comptime format: []const u8, comptime Args: type, comptime plain: bool) !void {
            try std.testing.expectEqual(plain, comptime plain_template(format, Args) != null);
        }
    }.check;
    try expect_plain("a{s}b{d}", @TypeOf(.{ slice, @as(u64, 1) }), true);
    try expect_plain("{d}", @TypeOf(.{@as(i64, 1)}), true);
    try expect_plain("{{}}", @TypeOf(.{}), false);
    try expect_plain("{x}", @TypeOf(.{@as(u8, 1)}), false);
    try expect_plain("{s:>4}", @TypeOf(.{slice}), false);
    try expect_plain("{0s}", @TypeOf(.{slice}), false);
    try expect_plain("{s}", @TypeOf(.{many}), false);
    try expect_plain("{d}", @TypeOf(.{@as(u128, 1)}), false);
    try expect_plain("{d}", @TypeOf(.{slice}), false);
    try expect_plain("{s}", @TypeOf(.{@as(u8, 1)}), false);
    try expect_plain("{d}", @TypeOf(.{1}), false);
    try expect_plain("{s}", @TypeOf(.{}), false);
    try expect_plain("", @TypeOf(.{slice}), false);
    try expect_plain("{s", @TypeOf(.{slice}), false);
}
