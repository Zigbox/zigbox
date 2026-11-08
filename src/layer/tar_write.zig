//! The tar a pushed or exported image's layer is made of. Only the entry headers and the ends of
//! the archive are written here; the caller streams a file's bytes between a header and `pad`.
//!
//! The form is fixed, because the layer's digest depends on every byte of it (and a layer-writer
//! version names the form, `constants.layer_writer_version`): ustar headers; a pax extended
//! header before an entry only for what ustar cannot hold (a name or link target over 100 bytes,
//! an owner over seven octal digits, a size over 8 GiB, and each kept extended attribute as
//! `SCHILY.xattr.<name>`); the owner as the tree holds it, with empty user and group names; the
//! mode as stored; one fixed mtime for every entry; and two zero blocks to end, with no padding
//! after them.
//!
//! Standard library only. The header type and its checksum are `std.tar.Writer.Header`'s.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const constants = @import("../constants.zig");
const xattrs_mod = @import("../store/xattrs.zig");

const Header = std.tar.Writer.Header;

pub const block_bytes: u32 = 512;

/// The most a header's name or link field holds before a pax record is needed.
const field_bytes: usize = 100;
/// The largest owner a ustar header holds (seven octal digits).
const owner_field_max: u64 = 0o7777777;
/// The largest size a ustar header holds (eleven octal digits).
pub const size_field_max: u64 = 0o77777777777;

/// One more byte for a record's own length digits and its separators.
const record_overhead: u32 = 32;

/// The most bytes of pax records one entry carries.
pub const pax_bytes_max: u32 = 2 * (constants.path_bytes_max + record_overhead) +
    3 * (24 + record_overhead) +
    constants.store_xattrs_max * (constants.store_xattr_name_bytes_max + 16 +
        constants.store_xattr_value_bytes_max + record_overhead);

pub const Kind = enum { directory, file, symlink, hard_link };

pub const Entry = struct {
    /// The path in the archive; a directory's ends in `/`.
    path: []const u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    /// A file's length (zero for the other kinds).
    size: u64,
    /// A symlink's target, or the first path of a hard link.
    link: []const u8,
    /// The canonical attribute section (`store/xattrs.zig`).
    xattrs: []const u8,
};

pub const Error = error{WriteFailed};

/// The room the pax records of one entry are built in.
pub const Scratch = struct {
    pax: [pax_bytes_max]u8,
};

comptime {
    assert(pax_bytes_max < 128 * 1024); // The reader's bound (`tar.zig`).
    assert(@typeInfo(@TypeOf(@as(Header, .{}).size)).array.len == 11);
}

/// "<length> <key>=<value>\n", the length counting its own digits. Returns the bytes added.
fn record(out: []u8, key: []const u8, value: []const u8) usize {
    assert(key.len > 0);
    const base = 1 + key.len + 1 + value.len + 1;
    var digits: usize = 1;
    while (true) {
        const needed = std.fmt.count("{d}", .{base + digits});
        if (needed == digits) break;
        digits = needed;
    }
    const total = base + digits;
    assert(out.len >= total);
    const head = std.fmt.bufPrint(out, "{d} {s}=", .{ total, key }) catch unreachable; // Sized.
    @memcpy(out[head.len..][0..value.len], value);
    out[head.len + value.len] = '\n';
    assert(head.len + value.len + 1 == total);
    return total;
}

fn record_number(out: []u8, key: []const u8, value: u64) usize {
    var text: [24]u8 = undefined;
    const digits = std.fmt.bufPrint(&text, "{d}", .{value}) catch unreachable; // Sized.
    return record(out, key, digits);
}

/// Fills `field` with `value` in octal, zero-padded on the left. The caller checked it fits.
fn fill_octal(field: []u8, value: u64) void {
    var rest = value;
    var at = field.len;
    @memset(field, '0');
    while (rest > 0) {
        assert(at > 0);
        at -= 1;
        field[at] = '0' + @as(u8, @intCast(rest % 8));
        rest /= 8;
    }
}

/// The pax records an entry needs, in a fixed order: path, linkpath, uid, gid, size, then the
/// attributes in the section's order. Returns the length used in `scratch`.
fn pax_records(scratch: *Scratch, entry: Entry) usize {
    const out = &scratch.pax;
    var used: usize = 0;
    if (entry.path.len > field_bytes) used += record(out[used..], "path", entry.path);
    if (entry.link.len > field_bytes) used += record(out[used..], "linkpath", entry.link);
    if (entry.uid > owner_field_max) used += record_number(out[used..], "uid", entry.uid);
    if (entry.gid > owner_field_max) used += record_number(out[used..], "gid", entry.gid);
    if (entry.size > size_field_max) used += record_number(out[used..], "size", entry.size);
    var iterator = xattrs_mod.Iterator.init(entry.xattrs);
    while (iterator.next()) |attribute| {
        var key: [constants.store_xattr_name_bytes_max + 16]u8 = undefined;
        const name = std.fmt.bufPrint(&key, "SCHILY.xattr.{s}", .{attribute.name}) catch
            unreachable; // The name is at most 255 bytes.
        used += record(out[used..], name, attribute.value);
    }
    assert(!iterator.broken); // The caller took the section from a decoded tree.
    assert(used <= pax_bytes_max);
    return used;
}

fn write_header_block(writer: *Io.Writer, header: *Header) Error!void {
    header.write(writer) catch |err| switch (err) {
        error.WriteFailed => return error.WriteFailed,
        error.OctalOverflow => unreachable, // A checksum is far below 8^7.
    };
}

/// Pads a body of `size` bytes to a whole block.
pub fn pad(writer: *Io.Writer, size: u64) Error!void {
    const rest: usize = @intCast(size % block_bytes);
    if (rest == 0) return;
    writer.splatByteAll(0, block_bytes - rest) catch return error.WriteFailed;
}

/// The two zero blocks that end the archive.
pub fn finish(writer: *Io.Writer) Error!void {
    writer.splatByteAll(0, 2 * block_bytes) catch return error.WriteFailed;
}

/// One entry's header, preceded by its pax record when it needs one. A file's body, then `pad`,
/// follow the call.
pub fn write_header(writer: *Io.Writer, scratch: *Scratch, entry: Entry) Error!void {
    assert(entry.path.len > 0);
    assert((entry.kind == .directory) == (entry.path[entry.path.len - 1] == '/'));
    assert((entry.kind == .symlink or entry.kind == .hard_link) == (entry.link.len > 0));
    assert(entry.kind == .file or entry.size == 0);
    const used = pax_records(scratch, entry);
    if (used > 0) {
        var pax: Header = .init(.regular);
        const record_name = "PaxHeaders/entry";
        @memcpy(pax.name[0..record_name.len], record_name);
        fill_octal(&pax.mode, 0o644);
        pax.setSize(used) catch unreachable; // At most 128 KiB.
        pax.setMtime(constants.store_mtime_seconds) catch unreachable; // Fits eleven digits.
        @as(*[block_bytes]u8, @ptrCast(&pax))[156] = 'x'; // `Header.FileType` has no pax type.
        try write_header_block(writer, &pax);
        writer.writeAll(scratch.pax[0..used]) catch return error.WriteFailed;
        try pad(writer, used);
    }
    var header: Header = .init(switch (entry.kind) {
        .directory => .directory,
        .file, .hard_link => .regular,
        .symlink => .symbolic_link,
    });
    fill_octal(&header.mode, entry.mode);
    fill_octal(&header.uid, @min(entry.uid, owner_field_max));
    fill_octal(&header.gid, @min(entry.gid, owner_field_max));
    header.setSize(@min(entry.size, size_field_max)) catch unreachable; // Clamped above.
    header.setMtime(constants.store_mtime_seconds) catch unreachable; // Fits eleven digits.
    if (entry.kind == .hard_link) {
        const bytes: *[block_bytes]u8 = @ptrCast(&header);
        bytes[156] = '1'; // `Header.FileType` has no hard link; the byte is the format's.
    }
    const name = entry.path[0..@min(entry.path.len, field_bytes)];
    @memcpy(header.name[0..name.len], name);
    const link = entry.link[0..@min(entry.link.len, field_bytes)];
    @memcpy(header.linkname[0..link.len], link);
    try write_header_block(writer, &header);
}

const testing = std.testing;
const tar_reader = @import("tar.zig");

fn test_scratch() *Scratch {
    const holder = struct {
        var scratch: Scratch = undefined;
    };
    @memset(&holder.scratch.pax, 0xAA);
    return &holder.scratch;
}

fn entry_of(path: []const u8, kind: Kind) Entry {
    return .{
        .path = path,
        .kind = kind,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .size = 0,
        .link = "",
        .xattrs = &xattrs_mod.empty,
    };
}

test "a directory header is one block with the fixed fields" {
    // Goal: golden bytes of the fields a layer digest depends on.
    var out: [2048]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var entry = entry_of("etc/", .directory);
    entry.uid = 1000;
    entry.gid = 100;
    try write_header(&writer, test_scratch(), entry);
    const bytes = writer.buffered();
    try testing.expectEqual(@as(usize, 512), bytes.len);
    try testing.expectEqualStrings("etc/", std.mem.sliceTo(bytes[0..100], 0));
    try testing.expectEqualStrings("0000755", bytes[100..107]);
    try testing.expectEqualStrings("0001750", bytes[108..115]);
    try testing.expectEqualStrings("0000144", bytes[116..123]);
    try testing.expectEqualStrings("00000000000", bytes[124..135]);
    try testing.expectEqualStrings("02263523000", bytes[136..147]); // 315532800.
    try testing.expectEqual(@as(u8, '5'), bytes[156]);
    try testing.expectEqualStrings("ustar", bytes[257..262]);
    try testing.expectEqual(@as(u8, 0), bytes[265]); // No user name.
}

test "a symlink and a hard link carry their target and type" {
    // Goal: type bytes 2 and 1, and the target in the link field.
    var out: [2048]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var symlink = entry_of("bin/sh", .symlink);
    symlink.link = "busybox";
    try write_header(&writer, test_scratch(), symlink);
    var hard = entry_of("bin/ash", .hard_link);
    hard.link = "bin/busybox";
    try write_header(&writer, test_scratch(), hard);
    const bytes = writer.buffered();
    try testing.expectEqual(@as(usize, 1024), bytes.len);
    try testing.expectEqual(@as(u8, '2'), bytes[156]);
    try testing.expectEqualStrings("busybox", std.mem.sliceTo(bytes[157..257], 0));
    try testing.expectEqual(@as(u8, '1'), bytes[512 + 156]);
    try testing.expectEqualStrings("bin/busybox", std.mem.sliceTo(bytes[512 + 157 ..][0..100], 0));
}

test "a long path gets a pax record and a cut name" {
    // Goal: the pax record holds the whole path; the header holds its first 100 bytes.
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var path: [150]u8 = undefined;
    @memset(&path, 'p');
    var entry = entry_of(&path, .file);
    entry.size = 3;
    entry.link = "";
    try write_header(&writer, test_scratch(), entry);
    const bytes = writer.buffered();
    try testing.expectEqual(@as(usize, 512 + 512 + 512), bytes.len);
    try testing.expectEqual(@as(u8, 'x'), bytes[156]);
    const used = std.mem.sliceTo(bytes[512..], 0);
    const expected = "160 path=" ++ @as([150]u8, @splat('p')) ++ "\n";
    try testing.expectEqualStrings(expected, used);
    try testing.expectEqual(@as(u8, 'p'), bytes[1024 + 99]);
}

test "a kept attribute and a big owner are pax records, in order" {
    // Goal: uid before the attributes, and the attribute named SCHILY.xattr.<name>.
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var entry = entry_of("f", .file);
    entry.uid = 3_000_000;
    const section = [_]u8{ 1, 6, 0, 'u', 's', 'e', 'r', '.', 'a', 2, 0, 'h', 'i' };
    entry.xattrs = &section;
    try write_header(&writer, test_scratch(), entry);
    const used = std.mem.sliceTo(writer.buffered()[512..], 0);
    try testing.expectEqualStrings("15 uid=3000000\n26 SCHILY.xattr.user.a=hi\n", used);
    try testing.expectEqualStrings("7777777", writer.buffered()[1024 + 108 ..][0..7]);
}

test "the reader reads back what this writer wrote" {
    // Goal: header, pax and padding agree with `tar.zig`; the end is two zero blocks.
    var out: [8192]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var path: [120]u8 = undefined;
    @memset(&path, 'q');
    var entry = entry_of(&path, .file);
    entry.size = 5;
    entry.mode = 0o644;
    try write_header(&writer, test_scratch(), entry);
    try writer.writeAll("hello");
    try pad(&writer, 5);
    try finish(&writer);
    try testing.expectEqual(@as(usize, 512 * 3 + 512 + 1024), writer.buffered().len);
    var source: Io.Reader = .fixed(writer.buffered());
    const holder = struct {
        var tar: tar_reader.Reader = undefined;
    };
    holder.tar.init(&source, 1 << 20);
    const item = (try holder.tar.next()).?;
    try testing.expectEqualStrings(&path, item.name);
    try testing.expectEqual(@as(u64, 5), item.size);
}
