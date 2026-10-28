//! Builders of layer blobs for the tests: a tar writer (ustar with pax records for what ustar
//! cannot hold), and the two containers a layer comes in, written without compression: gzip
//! with stored deflate blocks, and zstd with raw blocks. A decoder reads them like any other
//! stream, which is what the applier's tests need; the compression itself is the standard
//! library's, and is checked by pulling real images.
//!
//! Standard library only, so the VM harness and the registry fixture can use it too.

const std = @import("std");
const assert = std.debug.assert;

pub const Kind = enum(u8) {
    file = '0',
    hardlink = '1',
    symlink = '2',
    char_device = '3',
    block_device = '4',
    directory = '5',
    fifo = '6',
    pax = 'x',
    pax_global = 'g',
    gnu_long_name = 'L',
    gnu_long_link = 'K',
    sparse = 'S',
};

pub const Xattr = struct { name: []const u8, value: []const u8 };

pub const Entry = struct {
    name: []const u8,
    kind: Kind = .file,
    mode: u32 = 0o644,
    uid: u64 = 0,
    gid: u64 = 0,
    link: []const u8 = "",
    data: []const u8 = "",
    xattrs: []const Xattr = &.{},
    /// Declare this size in the header whatever `data` holds (a lying archive).
    size_override: ?u64 = null,
    /// Break the checksum.
    bad_checksum: bool = false,
};

pub const Tar = struct {
    buffer: []u8,
    len: u32 = 0,

    pub fn init(buffer: []u8) Tar {
        assert(buffer.len >= 1024);
        return .{ .buffer = buffer };
    }

    pub fn bytes(tar: *const Tar) []const u8 {
        return tar.buffer[0..tar.len];
    }

    fn room(tar: *Tar, count: usize) []u8 {
        assert(tar.len + count <= tar.buffer.len);
        const out = tar.buffer[tar.len..][0..count];
        tar.len += @intCast(count);
        return out;
    }

    fn octal(field: []u8, value: u64) void {
        if (value >> @intCast(3 * (field.len - 1)) != 0) {
            // Too big for the digits: the binary form GNU tar writes.
            @memset(field, 0);
            var rest = value;
            var at: usize = field.len;
            while (at > 1 and rest != 0) {
                at -= 1;
                field[at] = @truncate(rest);
                rest >>= 8;
            }
            field[0] = 0x80;
            return;
        }
        @memset(field, '0');
        field[field.len - 1] = 0;
        var rest = value;
        var at: usize = field.len - 1;
        while (at > 0) {
            at -= 1;
            field[at] = '0' + @as(u8, @intCast(rest & 7));
            rest >>= 3;
        }
        assert(rest == 0);
    }

    /// Writes one header block for `entry` with the name cut to what ustar holds.
    fn header(tar: *Tar, entry: Entry, name: []const u8, link: []const u8, size: u64) void {
        const block = tar.room(512);
        @memset(block, 0);
        const name_part = name[0..@min(name.len, 100)];
        @memcpy(block[0..name_part.len], name_part);
        octal(block[100..108], entry.mode);
        octal(block[108..116], @min(entry.uid, 0o7777777));
        octal(block[116..124], @min(entry.gid, 0o7777777));
        octal(block[124..136], size);
        octal(block[136..148], 0);
        block[156] = @backingInt(entry.kind);
        const link_part = link[0..@min(link.len, 100)];
        @memcpy(block[157..][0..link_part.len], link_part);
        @memcpy(block[257..263], "ustar\x00");
        @memcpy(block[263..265], "00");
        @memset(block[148..156], ' ');
        var sum: u64 = 0;
        for (block) |byte| sum += byte;
        octal(block[148..155], sum);
        block[154] = 0;
        block[155] = ' ';
        if (entry.bad_checksum) block[148] ^= 1;
    }

    fn body(tar: *Tar, data: []const u8) void {
        @memcpy(tar.room(data.len), data);
        const padding = (512 - data.len % 512) % 512;
        @memset(tar.room(padding), 0);
    }

    /// A pax record: "<length> <key>=<value>\n", the length counting itself.
    fn record(out: []u8, key: []const u8, value: []const u8) usize {
        const base = 1 + key.len + 1 + value.len + 1; // space, key, '=', value, '\n'
        var digits: usize = 1;
        while (true) {
            const total = base + digits;
            const needed = std.fmt.count("{d}", .{total});
            if (needed == digits) break;
            digits = needed;
        }
        const total = base + digits;
        const text = std.fmt.bufPrint(out, "{d} {s}=", .{ total, key }) catch unreachable; // Sized.
        @memcpy(out[text.len..][0..value.len], value);
        out[text.len + value.len] = '\n';
        assert(text.len + value.len + 1 == total);
        return total;
    }

    pub fn add(tar: *Tar, entry: Entry) void {
        var pax: [16 * 1024]u8 = undefined;
        var used: usize = 0;
        const long_name = entry.name.len > 100;
        const long_link = entry.link.len > 100;
        if (long_name) used += record(pax[used..], "path", entry.name);
        if (long_link) used += record(pax[used..], "linkpath", entry.link);
        var key: [300]u8 = undefined;
        for (entry.xattrs) |xattr| {
            const format = "SCHILY.xattr.{s}";
            const text = std.fmt.bufPrint(&key, format, .{xattr.name}) catch unreachable; // Sized.
            used += record(pax[used..], text, xattr.value);
        }
        if (entry.uid > 0o7777777) {
            var number: [24]u8 = undefined;
            const text = std.fmt.bufPrint(&number, "{d}", .{entry.uid}) catch unreachable; // Sized.
            used += record(pax[used..], "uid", text);
        }
        if (used > 0) {
            const pax_entry: Entry = .{ .name = "PaxHeaders/x", .kind = .pax, .mode = 0o644 };
            tar.header(pax_entry, pax_entry.name, "", used);
            tar.body(pax[0..used]);
        }
        const size: u64 = entry.size_override orelse entry.data.len;
        tar.header(entry, entry.name, entry.link, size);
        if (entry.size_override == null) tar.body(entry.data);
    }

    /// A GNU long name record ('L') followed by the entry with the name cut.
    pub fn add_gnu_long(tar: *Tar, entry: Entry) void {
        assert(entry.name.len > 100);
        const long: Entry = .{ .name = "././@LongLink", .kind = .gnu_long_name };
        var name: [4200]u8 = undefined;
        @memcpy(name[0..entry.name.len], entry.name);
        name[entry.name.len] = 0;
        tar.header(long, long.name, "", entry.name.len + 1);
        tar.body(name[0 .. entry.name.len + 1]);
        tar.header(entry, entry.name, entry.link, entry.data.len);
        tar.body(entry.data);
    }

    /// Writes raw bytes where a header should be (a damaged archive).
    pub fn raw(tar: *Tar, data: []const u8) void {
        @memcpy(tar.room(data.len), data);
    }

    /// The two zero blocks that end an archive.
    pub fn finish(tar: *Tar) void {
        @memset(tar.room(1024), 0);
    }
};

/// gzip with stored blocks: the 10-byte header, deflate blocks of at most 65535 bytes, then the
/// CRC-32 and the length.
pub fn gzip(out: []u8, data: []const u8) []u8 {
    assert(out.len >= data.len + data.len / 65535 * 5 + 40);
    const header = [10]u8{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 };
    @memcpy(out[0..10], &header);
    var at: usize = 10;
    var rest = data;
    while (true) {
        const part = rest[0..@min(rest.len, 65535)];
        rest = rest[part.len..];
        out[at] = if (rest.len == 0) 1 else 0;
        std.mem.writeInt(u16, out[at + 1 ..][0..2], @intCast(part.len), .little);
        const inverse: u16 = ~@as(u16, @intCast(part.len));
        std.mem.writeInt(u16, out[at + 3 ..][0..2], inverse, .little);
        @memcpy(out[at + 5 ..][0..part.len], part);
        at += 5 + part.len;
        if (rest.len == 0) break;
    }
    std.mem.writeInt(u32, out[at..][0..4], std.hash.Crc32.hash(data), .little);
    std.mem.writeInt(u32, out[at + 4 ..][0..4], @truncate(data.len), .little);
    return out[0 .. at + 8];
}

/// zstd with raw blocks of at most 128 KiB: the magic, a frame header with a 128 KiB window and
/// no declared size, and the blocks.
pub fn zstd(out: []u8, data: []const u8) []u8 {
    assert(out.len >= data.len + data.len / 131072 * 3 + 16);
    @memcpy(out[0..4], &[4]u8{ 0x28, 0xb5, 0x2f, 0xfd });
    out[4] = 0; // No single segment, no checksum, no dictionary, no content size.
    out[5] = 0x38; // Window descriptor: exponent 7, 128 KiB.
    var at: usize = 6;
    var rest = data;
    while (true) {
        const part = rest[0..@min(rest.len, 131072)];
        rest = rest[part.len..];
        const last: u32 = if (rest.len == 0) 1 else 0;
        const word: u32 = last | (@as(u32, @intCast(part.len)) << 3); // Block type 0: raw.
        out[at] = @truncate(word);
        out[at + 1] = @truncate(word >> 8);
        out[at + 2] = @truncate(word >> 16);
        @memcpy(out[at + 3 ..][0..part.len], part);
        at += 3 + part.len;
        if (rest.len == 0) break;
    }
    return out[0..at];
}

const testing = std.testing;

test "a tar built here has whole blocks and ends in two zero blocks" {
    // Goal: the builder's own shape, so a test failure is not the builder's.
    var storage: [8192]u8 = undefined;
    var tar = Tar.init(&storage);
    tar.add(.{ .name = "etc/", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "etc/os-release", .data = "NAME=x\n" });
    tar.finish();
    try testing.expectEqual(@as(usize, 512 * 2 + 512 + 1024), tar.bytes().len);
    const second = std.mem.sliceTo(tar.bytes()[512..][0..100], 0);
    try testing.expectEqualStrings("etc/os-release", second);
    try testing.expectEqual(@as(usize, 0), tar.bytes().len % 512);
}

test "pax records state their own length" {
    // Goal: the length prefix counts itself, also across a digit boundary.
    var out: [512]u8 = undefined;
    const used = Tar.record(&out, "path", "a/b");
    try testing.expectEqualStrings("12 path=a/b\n", out[0..used]);
    var long: [200]u8 = undefined;
    @memset(&long, 'x');
    const second = Tar.record(&out, "path", &long);
    try testing.expectEqual(@as(usize, 200 + 5 + 3 + 1 + 1), second);
}
