//! A reader of tar archives, as the layers of an image are: ustar, with the GNU long name and
//! long link records, and pax records for long names, large numbers, owners and extended
//! attributes (`SCHILY.xattr.*`). It reads from a `std.Io.Reader`, one header at a time, and
//! never holds more than one entry's header and records: the body is read by the caller.
//!
//! What it does not do, it refuses by name rather than guess: sparse files and the vendor
//! extensions of other tars (`Unsupported`). A checksum that is wrong, a number that is not one,
//! a name or a record over its bound, or an archive that ends inside a block is an error; an
//! archive that ends at a block boundary without the zero blocks is accepted (some writers omit
//! them), and the first zero block ends it.
//!
//! The standard library's `std.tar` was read first and is not used: its iterator drops the
//! owner ids and every pax record it does not know, and a layer needs both.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const constants = @import("../constants.zig");

pub const block_bytes = 512;

/// The most bytes of pax records one entry may carry (extended attributes can be large).
pub const pax_bytes_max: u32 = 128 * 1024;
/// The most extended attributes one entry keeps; the rest are counted.
pub const xattrs_max: u32 = 32;

pub const Kind = enum {
    file,
    hardlink,
    symlink,
    directory,
    /// Character and block devices, FIFOs: the store skips them.
    special,
};

pub const Xattr = struct {
    /// The attribute's name, without the `SCHILY.xattr.` prefix.
    name: []const u8,
    value: []const u8,
};

pub const Entry = struct {
    kind: Kind,
    /// The path as the archive spells it (not yet cleaned).
    name: []const u8,
    /// The target of a link, as spelled.
    link: []const u8,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: u64,
    xattrs: []const Xattr,
    /// Attributes past `xattrs_max`.
    xattrs_dropped: u32,
};

pub const Error = error{
    /// The archive ends inside a block or a body.
    Truncated,
    BadChecksum,
    /// A numeric field that is not a number.
    BadNumber,
    /// A name, a link or a pax record over its bound.
    TooLong,
    BadPax,
    /// An entry type zbx will not read (sparse files, vendor extensions).
    Unsupported,
    /// The reader below failed; ask it why.
    ReadFailed,
    /// The archive's entries together hold more than the layer limit.
    TooBig,
};

pub const Reader = struct {
    source: *Io.Reader,
    block: [block_bytes]u8,
    name: [constants.path_bytes_max + 1]u8,
    name_len: u32,
    link: [constants.path_bytes_max + 1]u8,
    link_len: u32,
    long_name: [constants.path_bytes_max + 1]u8,
    long_link: [constants.path_bytes_max + 1]u8,
    pax: [pax_bytes_max]u8,
    xattrs: [xattrs_max]Xattr,
    xattr_count: u32,
    xattrs_dropped: u32,
    /// Bytes of the current entry's body not yet read, and its padding to a block.
    body_left: u64,
    padding_left: u64,
    /// The sum of the sizes of all entries so far, and the most they may reach.
    bytes_total: u64,
    bytes_max: u64,
    ended: bool,

    pub fn init(reader: *Reader, source: *Io.Reader, bytes_max: u64) void {
        assert(bytes_max > 0);
        reader.source = source;
        reader.body_left = 0;
        reader.padding_left = 0;
        reader.bytes_total = 0;
        reader.bytes_max = bytes_max;
        reader.ended = false;
        reader.name_len = 0;
        reader.link_len = 0;
        reader.xattr_count = 0;
        reader.xattrs_dropped = 0;
    }

    /// Reads one header block. False at a clean end (no bytes at all).
    fn take_block(reader: *Reader) Error!bool {
        const count = reader.source.readSliceShort(&reader.block) catch return error.ReadFailed;
        if (count == 0) return false;
        if (count < block_bytes) return error.Truncated;
        return true;
    }

    /// Discards what is left of the current entry: its body and the padding.
    fn finish_entry(reader: *Reader) Error!void {
        const left = reader.body_left + reader.padding_left;
        reader.body_left = 0;
        reader.padding_left = 0;
        if (left == 0) return;
        reader.source.discardAll64(left) catch |err| return map_read(err);
    }

    /// Reads up to `buffer.len` bytes of the current body; zero when it is all read.
    pub fn read_body(reader: *Reader, buffer: []u8) Error!usize {
        assert(buffer.len > 0);
        const want: usize = @intCast(@min(reader.body_left, buffer.len));
        if (want == 0) return 0;
        const count = reader.source.readSliceShort(buffer[0..want]) catch return error.ReadFailed;
        if (count < want) return error.Truncated;
        reader.body_left -= count;
        return count;
    }

    /// The next entry, or null at the end of the archive. What is left of the previous entry's
    /// body is skipped.
    pub fn next(reader: *Reader) Error!?Entry {
        try reader.finish_entry();
        if (reader.ended) return null;
        var pax_len: ?usize = null;
        var has_name = false;
        var has_link = false;
        // Records that modify the next header come first, a bounded number of them.
        for (0..8) |_| {
            if (!try reader.take_block()) return reader.end_archive();
            if (is_zero(&reader.block)) return reader.end_archive();
            try verify_checksum(&reader.block);
            const flag = reader.block[156];
            const size = try number(reader.block[124..136]);
            switch (flag) {
                'x' => pax_len = try reader.read_record(size, reader.pax[0..]),
                'g' => try reader.skip_record(size),
                'L' => {
                    try reader.read_text(size, &reader.long_name);
                    has_name = true;
                },
                'K' => {
                    try reader.read_text(size, &reader.long_link);
                    has_link = true;
                },
                else => {
                    const pax = if (pax_len) |length| reader.pax[0..length] else null;
                    return try reader.entry(flag, size, pax, has_name, has_link);
                },
            }
        }
        return error.Unsupported; // Eight records in a row before an entry.
    }

    fn end_archive(reader: *Reader) ?Entry {
        reader.ended = true;
        return null;
    }

    fn read_record(reader: *Reader, size: u64, into: []u8) Error!usize {
        if (size > into.len) return error.TooLong;
        const length: usize = @intCast(size);
        reader.source.readSliceAll(into[0..length]) catch |err| return map_read(err);
        try reader.skip_record(padding_of(size));
        return length;
    }

    /// A GNU long name or link: its text, NUL-terminated in `into`.
    fn read_text(reader: *Reader, size: u64, into: *[constants.path_bytes_max + 1]u8) Error!void {
        if (size >= into.len) return error.TooLong;
        const length: usize = @intCast(size);
        reader.source.readSliceAll(into[0..length]) catch |err| return map_read(err);
        into[length] = 0;
        try reader.skip_record(padding_of(size));
    }

    fn skip_record(reader: *Reader, count: u64) Error!void {
        reader.source.discardAll64(count) catch |err| return map_read(err);
    }

    fn entry(
        reader: *Reader,
        flag: u8,
        header_size: u64,
        pax: ?[]const u8,
        has_name: bool,
        has_link: bool,
    ) Error!Entry {
        const block = &reader.block;
        const kind: Kind = switch (flag) {
            0, '0', '7' => .file,
            '1' => .hardlink,
            '2' => .symlink,
            '5' => .directory,
            '3', '4', '6' => .special,
            else => return error.Unsupported, // Sparse ('S'), multi-volume, vendor types.
        };
        var size = header_size;
        var uid = try number(block[108..116]);
        var gid = try number(block[116..124]);
        const mode = try number(block[100..108]);
        reader.header_names(has_name, has_link);
        reader.xattr_count = 0;
        reader.xattrs_dropped = 0;
        if (pax) |records| try reader.apply_pax(records, &size, &uid, &gid);
        if (uid > std.math.maxInt(u32) - 1 or gid > std.math.maxInt(u32) - 1) {
            return error.BadNumber;
        }
        if (reader.name_len == 0) return error.BadNumber;
        reader.body_left = size;
        reader.padding_left = padding_of(size);
        if (kind == .file) {
            if (size > reader.bytes_max - reader.bytes_total) return error.TooBig;
            reader.bytes_total += size;
        }
        return .{
            .kind = kind,
            .name = reader.name[0..reader.name_len],
            .link = reader.link[0..reader.link_len],
            .mode = @intCast(mode & 0o7777),
            .uid = @intCast(uid),
            .gid = @intCast(gid),
            .size = size,
            .mtime = number(block[136..148]) catch 0,
            .xattrs = reader.xattrs[0..reader.xattr_count],
            .xattrs_dropped = reader.xattrs_dropped,
        };
    }

    /// The path and link of the header: the long records win over the fields, and a pax
    /// record (applied after) wins over both.
    fn header_names(reader: *Reader, has_name: bool, has_link: bool) void {
        const block = &reader.block;
        const ustar = std.mem.eql(u8, block[257..263], "ustar\x00");
        const field = std.mem.sliceTo(block[0..100], 0);
        const prefix = std.mem.sliceTo(block[345..500], 0);
        if (has_name) {
            reader.name_len = copy_text(&reader.name, std.mem.sliceTo(&reader.long_name, 0));
        } else if (ustar and prefix.len > 0) {
            @memcpy(reader.name[0..prefix.len], prefix);
            reader.name[prefix.len] = '/';
            @memcpy(reader.name[prefix.len + 1 ..][0..field.len], field);
            reader.name_len = @intCast(prefix.len + 1 + field.len);
        } else {
            reader.name_len = copy_text(&reader.name, field);
        }
        if (has_link) {
            reader.link_len = copy_text(&reader.link, std.mem.sliceTo(&reader.long_link, 0));
        } else {
            reader.link_len = copy_text(&reader.link, std.mem.sliceTo(block[157..257], 0));
        }
    }

    fn apply_pax(
        reader: *Reader,
        records: []const u8,
        size: *u64,
        uid: *u64,
        gid: *u64,
    ) Error!void {
        var at: usize = 0;
        var count: u32 = 0;
        while (at < records.len) {
            count += 1;
            if (count > pax_bytes_max) return error.BadPax; // Every record is at least a byte.
            const space = std.mem.indexOfScalarPos(u8, records, at, ' ') orelse return error.BadPax;
            const total = std.fmt.parseInt(usize, records[at..space], 10) catch return error.BadPax;
            if (total < space - at + 4 or at + total > records.len) return error.BadPax;
            const record = records[space + 1 .. at + total];
            if (record[record.len - 1] != '\n') return error.BadPax;
            const equals = std.mem.indexOfScalar(u8, record, '=') orelse return error.BadPax;
            const key = record[0..equals];
            const value = record[equals + 1 .. record.len - 1];
            try reader.one_record(key, value, size, uid, gid);
            at += total;
        }
        assert(at == records.len);
    }

    fn one_record(
        reader: *Reader,
        key: []const u8,
        value: []const u8,
        size: *u64,
        uid: *u64,
        gid: *u64,
    ) Error!void {
        const xattr_prefix = "SCHILY.xattr.";
        if (std.mem.eql(u8, key, "path")) {
            if (value.len == 0 or value.len > constants.path_bytes_max) return error.TooLong;
            reader.name_len = copy_text(&reader.name, value);
        } else if (std.mem.eql(u8, key, "linkpath")) {
            if (value.len > constants.path_bytes_max) return error.TooLong;
            reader.link_len = copy_text(&reader.link, value);
        } else if (std.mem.eql(u8, key, "size")) {
            size.* = std.fmt.parseInt(u64, value, 10) catch return error.BadPax;
        } else if (std.mem.eql(u8, key, "uid")) {
            uid.* = std.fmt.parseInt(u64, value, 10) catch return error.BadPax;
        } else if (std.mem.eql(u8, key, "gid")) {
            gid.* = std.fmt.parseInt(u64, value, 10) catch return error.BadPax;
        } else if (std.mem.startsWith(u8, key, xattr_prefix)) {
            const name = key[xattr_prefix.len..];
            if (name.len == 0) return error.BadPax;
            if (reader.xattr_count == xattrs_max) {
                reader.xattrs_dropped += 1;
                return;
            }
            reader.xattrs[reader.xattr_count] = .{ .name = name, .value = value };
            reader.xattr_count += 1;
        }
    }
};

fn copy_text(into: *[constants.path_bytes_max + 1]u8, text: []const u8) u32 {
    assert(text.len <= constants.path_bytes_max);
    @memcpy(into[0..text.len], text);
    into[text.len] = 0;
    return @intCast(text.len);
}

fn is_zero(block: *const [block_bytes]u8) bool {
    for (block) |byte| if (byte != 0) return false;
    return true;
}

fn padding_of(size: u64) u64 {
    return (block_bytes - size % block_bytes) % block_bytes;
}

fn map_read(err: Io.Reader.Error) Error {
    return switch (err) {
        error.EndOfStream => error.Truncated,
        error.ReadFailed => error.ReadFailed,
    };
}

/// A numeric field: octal text, or (high bit set) big-endian binary as GNU tar writes numbers
/// that do not fit. A field of spaces and NULs is zero.
pub fn number(field: []const u8) Error!u64 {
    assert(field.len >= 8);
    assert(field.len <= 12);
    if (field[0] & 0x80 != 0) {
        if (field[0] == 0xff) return error.BadNumber; // Negative.
        var value: u64 = field[0] & 0x7f;
        for (field[1..]) |byte| {
            if (value > std.math.maxInt(u64) >> 8) return error.BadNumber;
            value = value << 8 | byte;
        }
        return value;
    }
    var value: u64 = 0;
    var seen = false;
    for (field) |byte| {
        switch (byte) {
            ' ' => if (seen) break,
            0 => break,
            '0'...'7' => {
                if (value > std.math.maxInt(u64) >> 3) return error.BadNumber;
                value = value << 3 | (byte - '0');
                seen = true;
            },
            else => return error.BadNumber,
        }
    }
    return value;
}

fn verify_checksum(block: *const [block_bytes]u8) Error!void {
    const stored = number(block[148..156]) catch return error.BadChecksum;
    var unsigned: u64 = 0;
    var signed: i64 = 0;
    for (block, 0..) |byte, at| {
        const counted: u8 = if (at >= 148 and at < 156) ' ' else byte;
        unsigned += counted;
        signed += @as(i8, @bitCast(counted));
    }
    if (stored == unsigned) return;
    if (signed >= 0 and stored == @as(u64, @intCast(signed))) return;
    return error.BadChecksum;
}

const testing = std.testing;
const builder = @import("../testing/vm/layer_fixture.zig");
const test_util = @import("../test_util.zig");

var test_reader: Reader = undefined;
var test_storage: [64 * 1024]u8 = undefined;

fn open_test(bytes: []const u8, source: *Io.Reader) void {
    source.* = Io.Reader.fixed(bytes);
    test_reader.init(source, 1 << 30);
}

test "entries come out with their kind, mode, owner, size and body" {
    // Goal: the common shapes of a layer: a directory, a file with a body, a symlink, a hard
    // link, a device, and the end of the archive.
    var tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "etc/", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    tar.add(.{ .name = "etc/os-release", .data = "NAME=x\n", .mode = 0o640, .uid = 3, .gid = 4 });
    tar.add(.{ .name = "bin/sh", .kind = .symlink, .link = "busybox", .mode = 0o777 });
    tar.add(.{ .name = "bin/ash", .kind = .hardlink, .link = "bin/busybox" });
    tar.add(.{ .name = "dev/null", .kind = .char_device, .mode = 0o666 });
    tar.finish();
    var source: Io.Reader = undefined;
    open_test(tar.bytes(), &source);
    const dir = (try test_reader.next()).?;
    try testing.expectEqual(Kind.directory, dir.kind);
    try testing.expectEqualStrings("etc/", dir.name);
    try testing.expectEqual(@as(u16, 0o755), dir.mode);
    const file = (try test_reader.next()).?;
    try testing.expectEqual(Kind.file, file.kind);
    try testing.expectEqual(@as(u32, 3), file.uid);
    try testing.expectEqual(@as(u32, 4), file.gid);
    try testing.expectEqual(@as(u64, 7), file.size);
    var body: [16]u8 = undefined;
    const count = try test_reader.read_body(&body);
    try testing.expectEqualStrings("NAME=x\n", body[0..count]);
    try testing.expectEqual(@as(usize, 0), try test_reader.read_body(&body));
    const link = (try test_reader.next()).?;
    try testing.expectEqual(Kind.symlink, link.kind);
    try testing.expectEqualStrings("busybox", link.link);
    const hard = (try test_reader.next()).?;
    try testing.expectEqual(Kind.hardlink, hard.kind);
    try testing.expectEqualStrings("bin/busybox", hard.link);
    try testing.expectEqual(Kind.special, (try test_reader.next()).?.kind);
    try testing.expect((try test_reader.next()) == null);
    try testing.expect((try test_reader.next()) == null);
}

test "an unread body is skipped by the next call" {
    // Goal: the caller may ignore a body (a file it will not write) without losing its place.
    var tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "a", .data = test_util.repeat('x', 700) });
    tar.add(.{ .name = "b", .data = "y" });
    tar.finish();
    var source: Io.Reader = undefined;
    open_test(tar.bytes(), &source);
    try testing.expectEqualStrings("a", (try test_reader.next()).?.name);
    try testing.expectEqualStrings("b", (try test_reader.next()).?.name);
}

test "long names come from pax, from GNU records and from the ustar prefix" {
    // Goal: all three ways a path longer than 100 bytes is written, and a pax path wins.
    var tar = builder.Tar.init(&test_storage);
    var long_storage: [200]u8 = undefined;
    for (0..80) |at| @memcpy(long_storage[at * 2 ..][0..2], "d/");
    @memcpy(long_storage[160..164], "file");
    const long = long_storage[0..164];
    tar.add(.{ .name = long });
    tar.add_gnu_long(.{ .name = long });
    tar.finish();
    var source: Io.Reader = undefined;
    open_test(tar.bytes(), &source);
    try testing.expectEqualStrings(long, (try test_reader.next()).?.name);
    try testing.expectEqualStrings(long, (try test_reader.next()).?.name);
    var plain = builder.Tar.init(&test_storage);
    plain.add(.{ .name = "name" });
    var bytes: [1536]u8 = undefined;
    @memcpy(bytes[0..512], plain.bytes()[0..512]);
    @memcpy(bytes[345 .. 345 + 5], "prefx");
    @memset(bytes[148..156], ' ');
    var sum: u64 = 0;
    for (bytes[0..512]) |byte| sum += byte;
    _ = std.fmt.bufPrint(bytes[148..155], "{o:0>6}", .{sum}) catch unreachable; // Sized.
    bytes[154] = 0;
    bytes[155] = ' ';
    @memset(bytes[512..], 0);
    open_test(&bytes, &source);
    try testing.expectEqualStrings("prefx/name", (try test_reader.next()).?.name);
}

test "pax gives extended attributes, large owners, and counts what it cannot keep" {
    // Goal: SCHILY.xattr records reach the entry with raw values; an owner past the octal field
    // is read; attributes past the bound are counted.
    var tar = builder.Tar.init(&test_storage);
    tar.add(.{
        .name = "usr/bin/ping",
        .uid = 100000,
        .xattrs = &.{
            .{ .name = "security.capability", .value = "\x01\x00\x00\x02" },
            .{ .name = "user.note", .value = "hi" },
        },
    });
    tar.finish();
    var source: Io.Reader = undefined;
    open_test(tar.bytes(), &source);
    const found = (try test_reader.next()).?;
    try testing.expectEqual(@as(u32, 100000), found.uid);
    try testing.expectEqual(@as(usize, 2), found.xattrs.len);
    try testing.expectEqualStrings("security.capability", found.xattrs[0].name);
    try testing.expectEqualStrings("\x01\x00\x00\x02", found.xattrs[0].value);
    try testing.expectEqualStrings("user.note", found.xattrs[1].name);
    try testing.expectEqual(@as(u32, 0), found.xattrs_dropped);
}

test "damaged archives are refused with their reason" {
    // Goal: a bad checksum, a cut header, a cut body, a number that is not one, a sparse
    // entry and a layer bigger than its limit each stop the reader with an error.
    var tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "a", .bad_checksum = true });
    var source: Io.Reader = undefined;
    open_test(tar.bytes(), &source);
    try testing.expectError(error.BadChecksum, test_reader.next());

    tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "a", .data = "hello" });
    open_test(tar.bytes()[0..100], &source);
    try testing.expectError(error.Truncated, test_reader.next());
    open_test(tar.bytes()[0..514], &source);
    _ = (try test_reader.next()).?;
    var body: [8]u8 = undefined;
    try testing.expectError(error.Truncated, test_reader.read_body(&body));

    tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "s", .kind = .sparse });
    open_test(tar.bytes(), &source);
    try testing.expectError(error.Unsupported, test_reader.next());

    tar = builder.Tar.init(&test_storage);
    tar.add(.{ .name = "big", .size_override = 1 << 40 });
    open_test(tar.bytes(), &source);
    try testing.expectError(error.TooBig, test_reader.next());
}

test "numbers are octal or big-endian binary, and nothing else" {
    // Goal: the two encodings, spaces, and the refusals.
    try testing.expectEqual(@as(u64, 0o644), try number("0000644\x00"));
    try testing.expectEqual(@as(u64, 0o644), try number(" 000644 "));
    try testing.expectEqual(@as(u64, 0), try number("        "));
    try testing.expectEqual(@as(u64, 0x0123), try number("\x80\x00\x00\x00\x00\x00\x01\x23"));
    try testing.expectError(error.BadNumber, number("\xff\xff\xff\xff\xff\xff\xff\xff"));
    try testing.expectError(error.BadNumber, number("0000889\x00"));
    const huge = "\x80\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    try testing.expectError(error.BadNumber, number(huge));
}
