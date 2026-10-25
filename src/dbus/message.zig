//! A D-Bus message: the 16-byte fixed header, the array of header fields, and the body. `parse`
//! turns the bytes of one whole message into a `Message` whose slices point into those bytes;
//! `encode` writes one little-endian message. `frame_length` tells a reader how many bytes a
//! message will take from its first 16.
//!
//! A message that breaks a rule of the format is `WireError`, never a panic and never a read past
//! the bytes: the input is a peer's, and `src/fuzz_dbus.zig` feeds this file truncated, oversized,
//! misaligned, wrong-endian and hostile messages.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const wire = @import("wire.zig");

const WireError = wire.WireError;

pub const fixed_header_bytes: u32 = 16;
pub const protocol_version: u8 = 1;

pub const Kind = enum(u8) {
    method_call = 1,
    method_return = 2,
    error_reply = 3,
    signal = 4,
};

/// Header field codes (spec, "Header Fields").
const Field = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    reply_serial = 5,
    destination = 6,
    sender = 7,
    signature = 8,
    unix_fds = 9,
};

/// A parsed message. Every slice points into the bytes given to `parse`.
pub const Message = struct {
    kind: Kind,
    flags: u8,
    endian: wire.Endian,
    serial: u32,
    path: ?[]const u8,
    interface: ?[]const u8,
    member: ?[]const u8,
    error_name: ?[]const u8,
    reply_serial: ?u32,
    destination: ?[]const u8,
    sender: ?[]const u8,
    /// The body's signature; empty for no body.
    signature: []const u8,
    body: []const u8,

    /// A reader over the body, in the message's byte order.
    pub fn body_reader(message: *const Message) wire.Reader {
        assert(message.body.len <= constants.dbus_message_bytes_max);
        assert((message.signature.len == 0) == (message.body.len == 0));
        return wire.Reader.init(message.body, message.endian);
    }
};

fn endian_of(code: u8) WireError!wire.Endian {
    const result: wire.Endian = switch (code) {
        'l' => .little,
        'B' => .big,
        else => return error.BadHeader,
    };
    assert((result == .little) == (code == 'l'));
    assert((result == .big) == (code == 'B'));
    return result;
}

/// The length of the whole message, from its first `fixed_header_bytes` bytes. Refuses a
/// message longer than `dbus_message_bytes_max` before any of it is read.
pub fn frame_length(prefix: *const [fixed_header_bytes]u8) WireError!u32 {
    const endian = try endian_of(prefix[0]);
    const body_length = std.mem.readInt(u32, prefix[4..8], endian);
    const fields_length = std.mem.readInt(u32, prefix[12..16], endian);
    const limit = constants.dbus_message_bytes_max;
    if (fields_length > limit) return error.TooLong;
    if (body_length > limit) return error.TooLong;
    const total = wire.pad_to(fixed_header_bytes + fields_length, 8) + body_length;
    if (total > limit) return error.TooLong;
    assert(total >= fixed_header_bytes);
    assert(total <= limit);
    return total;
}

/// Parses exactly one message. `bytes.len` must be the message's length.
pub fn parse(bytes: []const u8) WireError!Message {
    if (bytes.len < fixed_header_bytes) return error.Truncated;
    if (bytes.len > constants.dbus_message_bytes_max) return error.TooLong;
    const total = try frame_length(bytes[0..fixed_header_bytes]);
    if (total != bytes.len) return error.BadHeader;
    const endian = try endian_of(bytes[0]);
    const kind = std.enums.fromInt(Kind, bytes[1]) orelse return error.Unsupported;
    if (bytes[3] != protocol_version) return error.BadHeader;
    var message: Message = .{
        .kind = kind,
        .flags = bytes[2],
        .endian = endian,
        .serial = std.mem.readInt(u32, bytes[8..12], endian),
        .path = null,
        .interface = null,
        .member = null,
        .error_name = null,
        .reply_serial = null,
        .destination = null,
        .sender = null,
        .signature = "",
        .body = "",
    };
    if (message.serial == 0) return error.BadHeader;
    const fields_length = std.mem.readInt(u32, bytes[12..16], endian);
    var reader = wire.Reader.init(bytes, endian);
    reader.at = fixed_header_bytes;
    const fields_end = fixed_header_bytes + fields_length;
    if (fields_end > bytes.len) return error.Truncated;
    try parse_fields(&reader, fields_end, &message);
    if (reader.at != fields_end) return error.BadHeader;
    try reader.align_to(8);
    message.body = bytes[reader.at..];
    try check_required(&message);
    if (message.body.len > 0) {
        if (message.signature.len == 0) return error.BadHeader;
    } else {
        if (message.signature.len != 0) return error.BadHeader;
    }
    assert(message.body.len == bytes.len - reader.at);
    return message;
}

fn parse_fields(reader: *wire.Reader, end: u32, message: *Message) WireError!void {
    assert(reader.at == fixed_header_bytes);
    assert(end >= fixed_header_bytes);
    assert(end <= reader.bytes.len);
    var count: u32 = 0;
    while (reader.at < end) {
        count += 1;
        if (count > constants.dbus_header_fields_max) return error.TooLong;
        try reader.align_to(8);
        const code = try reader.byte();
        const value_signature = try reader.signature();
        try parse_field(reader, code, value_signature, message);
        if (reader.at > end) return error.BadHeader;
    }
    assert(count <= constants.dbus_header_fields_max);
}

/// Reads the value of one header field. A duplicate is malformed; an unknown code with a basic
/// type is skipped (the spec says to ignore them), and one with anything else is not read.
fn parse_field(
    reader: *wire.Reader,
    code: u8,
    value_signature: []const u8,
    message: *Message,
) WireError!void {
    assert(value_signature.len <= constants.dbus_signature_bytes_max);
    const known = std.enums.fromInt(Field, code) orelse {
        return skip_basic(reader, value_signature);
    };
    assert(code == @backingInt(known));
    if (value_signature.len != 1) return error.BadHeader;
    const type_code = value_signature[0];
    switch (known) {
        .path => {
            if (type_code != 'o') return error.BadHeader;
            if (message.path != null) return error.BadHeader;
            message.path = try reader.object_path();
        },
        .interface, .member, .error_name, .destination, .sender => {
            if (type_code != 's') return error.BadHeader;
            const text = try reader.string();
            const slot = switch (known) {
                .interface => &message.interface,
                .member => &message.member,
                .error_name => &message.error_name,
                .destination => &message.destination,
                else => &message.sender,
            };
            if (slot.* != null) return error.BadHeader;
            slot.* = text;
        },
        .reply_serial => {
            if (type_code != 'u') return error.BadHeader;
            if (message.reply_serial != null) return error.BadHeader;
            message.reply_serial = try reader.uint32();
        },
        .signature => {
            if (type_code != 'g') return error.BadHeader;
            if (message.signature.len != 0) return error.BadHeader;
            message.signature = try reader.signature();
        },
        .unix_fds => {
            if (type_code != 'u') return error.BadHeader;
            _ = try reader.uint32();
        },
    }
}

fn skip_basic(reader: *wire.Reader, value_signature: []const u8) WireError!void {
    assert(value_signature.len <= constants.dbus_signature_bytes_max);
    const start = reader.at;
    defer assert(reader.at >= start);
    if (value_signature.len != 1) return error.Unsupported;
    switch (value_signature[0]) {
        'y' => _ = try reader.byte(),
        'n', 'q' => _ = try reader.uint16(),
        'b', 'i', 'u' => _ = try reader.uint32(),
        'x', 't' => _ = try reader.uint64(),
        's' => _ = try reader.string(),
        'o' => _ = try reader.object_path(),
        'g' => _ = try reader.signature(),
        else => return error.Unsupported,
    }
}

fn check_required(message: *const Message) WireError!void {
    assert(message.serial != 0);
    assert(message.body.len <= constants.dbus_message_bytes_max);
    switch (message.kind) {
        .method_call => {
            if (message.path == null) return error.BadHeader;
            if (message.member == null) return error.BadHeader;
        },
        .signal => {
            if (message.path == null) return error.BadHeader;
            if (message.interface == null) return error.BadHeader;
            if (message.member == null) return error.BadHeader;
        },
        .method_return => {
            if (message.reply_serial == null) return error.BadHeader;
        },
        .error_reply => {
            if (message.error_name == null) return error.BadHeader;
            if (message.reply_serial == null) return error.BadHeader;
        },
    }
}

/// A message to send. Which fields a kind needs is `check_required`'s rule, asserted on encode.
pub const Outgoing = struct {
    kind: Kind,
    serial: u32,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    /// The body's signature and its marshalled bytes (from offset zero, see wire.zig).
    signature: []const u8 = "",
    body: []const u8 = "",
};

/// Writes `message` little-endian into `out`. `TooLong` if it does not fit.
pub fn encode(out: []u8, message: Outgoing) WireError![]const u8 {
    assert(message.serial != 0);
    assert((message.signature.len == 0) == (message.body.len == 0));
    var writer = wire.Writer.init(out);
    writer.byte('l');
    writer.byte(@backingInt(message.kind));
    writer.byte(0);
    writer.byte(protocol_version);
    writer.uint32(@intCast(message.body.len));
    writer.uint32(message.serial);
    const mark = writer.array_begin(8);
    assert(mark.start == fixed_header_bytes);
    if (message.path) |text| {
        write_field_header(&writer, .path, "o");
        writer.object_path(text);
    }
    inline for (.{
        .{ Field.destination, "destination" },
        .{ Field.interface, "interface" },
        .{ Field.member, "member" },
        .{ Field.error_name, "error_name" },
        .{ Field.sender, "sender" },
    }) |entry| {
        if (@field(message, entry[1])) |text| {
            write_field_header(&writer, entry[0], "s");
            writer.string(text);
        }
    }
    if (message.reply_serial) |serial| {
        write_field_header(&writer, .reply_serial, "u");
        writer.uint32(serial);
    }
    if (message.signature.len > 0) {
        write_field_header(&writer, .signature, "g");
        writer.signature(message.signature);
    }
    writer.array_end(mark);
    writer.pad(8);
    if (writer.failed) return error.TooLong;
    if (message.body.len > writer.buffer.len - writer.len) return error.TooLong;
    @memcpy(out[writer.len..][0..message.body.len], message.body);
    writer.len += @intCast(message.body.len);
    return writer.finish();
}

fn write_field_header(writer: *wire.Writer, field: Field, value_signature: []const u8) void {
    assert(value_signature.len == 1);
    assert(@backingInt(field) >= 1);
    writer.struct_begin();
    writer.byte(@backingInt(field));
    writer.variant_begin(value_signature);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

fn hello_call(buffer: []u8) ![]const u8 {
    return encode(buffer, .{
        .kind = .method_call,
        .serial = 1,
        .path = "/org/freedesktop/DBus",
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
    });
}

test "Hello encodes to the bytes every client sends" {
    // Goal: golden bytes for the first message of every connection, written by hand from the
    // spec: fixed header, then path, destination, interface and member fields, each padded to 8.
    var buffer: [256]u8 = undefined;
    const bytes = try hello_call(&buffer);
    const expected = [_]u8{ 'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0 } ++
        [_]u8{ 0x6e, 0, 0, 0 } ++ // 110 bytes of fields.
        [_]u8{ 1, 1, 'o', 0, 0x15, 0, 0, 0 } ++ "/org/freedesktop/DBus\x00" ++ [_]u8{ 0, 0 } ++
        [_]u8{ 6, 1, 's', 0, 0x14, 0, 0, 0 } ++ "org.freedesktop.DBus\x00" ++ [_]u8{ 0, 0, 0 } ++
        [_]u8{ 2, 1, 's', 0, 0x14, 0, 0, 0 } ++ "org.freedesktop.DBus\x00" ++ [_]u8{ 0, 0, 0 } ++
        [_]u8{ 3, 1, 's', 0, 5, 0, 0, 0 } ++ "Hello\x00" ++ [_]u8{ 0, 0 };
    try testing.expectEqualSlices(u8, expected, bytes);
}

test "an encoded message parses back to the same fields" {
    // Goal: round trip for each kind, with a body.
    var body_buffer: [64]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    writer.uint32(7);
    writer.string("done");
    const body = try writer.finish();
    var buffer: [512]u8 = undefined;
    const bytes = try encode(&buffer, .{
        .kind = .signal,
        .serial = 9,
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager",
        .member = "JobRemoved",
        .sender = ":1.2",
        .signature = "us",
        .body = body,
    });
    const message = try parse(bytes);
    try testing.expectEqual(Kind.signal, message.kind);
    try testing.expectEqual(@as(u32, 9), message.serial);
    try testing.expectEqualStrings("JobRemoved", message.member.?);
    try testing.expectEqualStrings(":1.2", message.sender.?);
    try testing.expectEqualStrings("us", message.signature);
    var reader = message.body_reader();
    try testing.expectEqual(@as(u32, 7), try reader.uint32());
    try testing.expectEqualStrings("done", try reader.string());
    try testing.expectEqual(@as(u32, 0), reader.remaining());
}

test "a big-endian message from a peer parses" {
    // Goal: byte order is the message's. Method: the smallest valid reply, written big-endian by
    // hand: header, one field (reply serial 1), no body.
    const bytes = [_]u8{ 'B', 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 8 } ++
        [_]u8{ 5, 1, 'u', 0, 0, 0, 0, 1 };
    const message = try parse(&bytes);
    try testing.expectEqual(Kind.method_return, message.kind);
    try testing.expectEqual(@as(u32, 5), message.serial);
    try testing.expectEqual(@as(u32, 1), message.reply_serial.?);
}

test "a message with a wrong length, version, kind or serial is refused" {
    // Goal: the negative space of the fixed header, one flipped field at a time.
    var buffer: [256]u8 = undefined;
    const good = try hello_call(&buffer);
    _ = try parse(good);
    var copy: [256]u8 = undefined;
    const length = good.len;
    const flips = [_]struct { at: usize, value: u8, err: WireError }{
        .{ .at = 0, .value = 'x', .err = error.BadHeader },
        .{ .at = 1, .value = 9, .err = error.Unsupported },
        .{ .at = 3, .value = 2, .err = error.BadHeader },
        .{ .at = 8, .value = 0, .err = error.BadHeader }, // Serial 0.
        .{ .at = 4, .value = 1, .err = error.BadHeader }, // A body length with no body.
    };
    for (flips) |flip| {
        @memcpy(copy[0..length], good);
        copy[flip.at] = flip.value;
        try testing.expectError(flip.err, parse(copy[0..length]));
    }
    try testing.expectError(error.Truncated, parse(good[0..15]));
    try testing.expectError(error.BadHeader, parse(good[0 .. length - 8]));
}

test "a method call without its path or member, and a reply without its serial, are refused" {
    // Goal: check_required for every kind.
    var buffer: [256]u8 = undefined;
    const cases = [_]Outgoing{
        .{ .kind = .method_call, .serial = 1, .member = "X" },
        .{ .kind = .method_call, .serial = 1, .path = "/" },
        .{ .kind = .signal, .serial = 1, .path = "/", .member = "X" },
        .{ .kind = .method_return, .serial = 1 },
        .{ .kind = .error_reply, .serial = 1, .reply_serial = 1 },
    };
    for (cases) |case| {
        const bytes = try encode(&buffer, case);
        try testing.expectError(error.BadHeader, parse(bytes));
    }
}

test "a message past the size bound is refused before it is read" {
    // Goal: frame_length decides from 16 bytes, so a reader never buffers a huge message.
    var header = [_]u8{ 'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, header[4..8], constants.dbus_message_bytes_max + 1, .little);
    try testing.expectError(error.TooLong, frame_length(&header));
    std.mem.writeInt(u32, header[4..8], 0, .little);
    std.mem.writeInt(u32, header[12..16], 0xffffffff, .little);
    try testing.expectError(error.TooLong, frame_length(&header));
    std.mem.writeInt(u32, header[12..16], 0, .little);
    try testing.expectEqual(@as(u32, 16), try frame_length(&header));
}

test "a header field repeated, mistyped, or too many, is refused" {
    // Goal: duplicates and wrong variant types are malformed, and the field count is bounded.
    var buffer: [512]u8 = undefined;
    var fields: [256]u8 = undefined;
    var writer = wire.Writer.init(&fields);
    for (0..2) |_| {
        writer.struct_begin();
        writer.byte(3);
        writer.variant_begin("s");
        writer.string("M");
    }
    const two_members = try writer.finish();
    try testing.expectError(error.BadHeader, with_fields(&buffer, two_members));
    writer = wire.Writer.init(&fields);
    writer.struct_begin();
    writer.byte(1);
    writer.variant_begin("s"); // The path must be 'o'.
    writer.string("/");
    try testing.expectError(error.BadHeader, with_fields(&buffer, try writer.finish()));
    writer = wire.Writer.init(&fields);
    for (0..constants.dbus_header_fields_max + 1) |_| {
        writer.struct_begin();
        writer.byte(200); // Unknown codes are skipped, but they still count.
        writer.variant_begin("y");
        writer.byte(1);
    }
    try testing.expectError(error.TooLong, with_fields(&buffer, try writer.finish()));
}

/// A signal header around the given field bytes, for the tests above.
fn with_fields(buffer: []u8, fields: []const u8) WireError!Message {
    var writer = wire.Writer.init(buffer);
    for ([_]u8{ 'l', 4, 0, 1 }) |value| writer.byte(value);
    writer.uint32(0);
    writer.uint32(1);
    writer.uint32(@intCast(fields.len));
    for (fields) |value| writer.byte(value);
    writer.pad(8);
    return parse(try writer.finish());
}
