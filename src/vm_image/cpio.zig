//! A "newc" cpio archive writer, which is what the Linux kernel unpacks as an initramfs. The
//! output is deterministic: every owner is 0, every time is 0, inodes count up from 1 in the
//! order entries are added, and the caller adds them sorted. Uncompressed.
//!
//! Build-host tooling: allocates from the arena it is given.

const std = @import("std");
const assert = std.debug.assert;

pub const Kind = enum { directory, file, character_device };

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    /// Permission bits only (0o755); the file type comes from `kind`.
    mode: u32,
    data: []const u8 = &.{},
    major: u32 = 0,
    minor: u32 = 0,
};

pub const header_bytes: usize = 110;
const magic = "070701";
const trailer = "TRAILER!!!";
const type_directory: u32 = 0o040000;
const type_file: u32 = 0o100000;
const type_character: u32 = 0o020000;

fn pad4(length: usize) usize {
    return (4 - length % 4) % 4;
}

/// Appends one entry. A path has no leading slash and no `.` or `..` part.
pub fn append(
    list: *std.ArrayList(u8),
    arena: std.mem.Allocator,
    inode: u32,
    entry: Entry,
) !void {
    assert(entry.path.len > 0);
    assert(entry.path[0] != '/');
    assert(entry.mode <= 0o7777);
    if (entry.kind != .file) assert(entry.data.len == 0);
    const type_bits: u32 = switch (entry.kind) {
        .directory => type_directory,
        .file => type_file,
        .character_device => type_character,
    };
    const links: u32 = if (entry.kind == .directory) 2 else 1;
    const name_size = entry.path.len + 1;
    var header: [header_bytes]u8 = undefined;
    const fields = [_]u32{
        inode,       type_bits | entry.mode,   0, 0, links,
        0,           @intCast(entry.data.len), 0, 0, entry.major,
        entry.minor, @intCast(name_size),      0,
    };
    @memcpy(header[0..6], magic);
    for (fields, 0..) |value, index| {
        const text = std.fmt.bytesToHex(std.mem.toBytes(std.mem.nativeToBig(u32, value)), .upper);
        @memcpy(header[6 + index * 8 ..][0..8], &text);
    }
    try list.appendSlice(arena, &header);
    try list.appendSlice(arena, entry.path);
    try list.append(arena, 0);
    try list.appendNTimes(arena, 0, pad4(header_bytes + name_size));
    try list.appendSlice(arena, entry.data);
    try list.appendNTimes(arena, 0, pad4(entry.data.len));
}

/// The archive of `entries` in the order given, then the trailer.
pub fn build(arena: std.mem.Allocator, entries: []const Entry) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    var inode: u32 = 1;
    for (entries) |entry| {
        try append(&list, arena, inode, entry);
        inode += 1;
    }
    try append(&list, arena, 0, .{ .path = trailer, .kind = .file, .mode = 0 });
    assert(list.items.len % 4 == 0);
    return list.items;
}

const console_node: Entry = .{
    .path = "dev/console",
    .kind = .character_device,
    .mode = 0o600,
    .major = 5,
    .minor = 1,
};

test "an archive is aligned, ends with the trailer and has the fields in place" {
    // Goal: the newc layout the kernel reads. Method: one directory and one file, then read the
    // fixed fields back from the bytes: magic, mode, size, name size, and the 4-byte padding.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bytes = try build(arena, &.{
        .{ .path = "etc", .kind = .directory, .mode = 0o755 },
        .{ .path = "etc/v", .kind = .file, .mode = 0o644, .data = "abc" },
        console_node,
    });
    try std.testing.expect(bytes.len % 4 == 0);
    try std.testing.expectEqualStrings("070701", bytes[0..6]);
    try std.testing.expectEqualStrings("00000001", bytes[6..14]); // inode
    try std.testing.expectEqualStrings("000041ED", bytes[14..22]); // 040755
    const second = header_bytes + 4 + pad4(header_bytes + 4); // "etc\0" padded
    try std.testing.expectEqualStrings("070701", bytes[second .. second + 6]);
    try std.testing.expectEqualStrings("000081A4", bytes[second + 14 .. second + 22]); // 0100644
    try std.testing.expectEqualStrings("00000003", bytes[second + 54 .. second + 62]); // size
    try std.testing.expect(std.mem.indexOf(u8, bytes, "TRAILER!!!") != null);
    try std.testing.expectEqualStrings("0000000500000001", blk: {
        const at = std.mem.indexOf(u8, bytes, "dev/console").?;
        const header_start = at - header_bytes;
        break :blk bytes[header_start + 6 + 9 * 8 ..][0..16];
    });
    // The same entries make the same bytes.
    const again = try build(arena, &.{
        .{ .path = "etc", .kind = .directory, .mode = 0o755 },
        .{ .path = "etc/v", .kind = .file, .mode = 0o644, .data = "abc" },
        console_node,
    });
    try std.testing.expectEqualSlices(u8, bytes, again);
}
