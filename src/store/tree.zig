//! The canonical encoding of one directory, and its decoder. A tree object is this encoding and
//! nothing else; its digest (BLAKE3 of the bytes) is the tree's identity, and the digest of a
//! root directory is the identity of the whole tree below it (a Merkle tree).
//!
//! Layout, all integers little-endian:
//!
//!   tree  = version:u8 (1) count:u32 entry* own
//!   own   = mode:u16 uid:u32 gid:u32 xattrs
//!   entry = kind:u8 mode:u16 uid:u32 gid:u32 name_len:u8 name xattrs payload
//!   xattrs  = the canonical section of `xattrs.zig`
//!   payload = file:    size:u64 content:digest object:digest
//!             symlink: target_len:u16 target
//!             dir:     subtree:digest
//!
//! Entries are sorted by name bytes and names are unique, so there is exactly one encoding of a
//! given directory. The decoder is as strict as the encoder is canonical: it refuses everything
//! the encoder cannot write (an unsorted or duplicate name, a name with a slash, a mode past
//! 07777, a count that disagrees with the bytes, trailing bytes). The fuzzer's property follows:
//! if bytes decode at all, encoding what they decode to gives the same bytes back.
//!
//! mtime, atime and ctime are not recorded: they are the one thing a re-import changes.
//! `mode` holds the permission bits and setuid, setgid and sticky (07777), not the file type;
//! `kind` is the type. A directory's own mode, owner and attributes are in its entry in the
//! parent. The `own` section at the end holds them for the one directory that has no parent
//! entry, the imported root, which becomes the container's `/`; in every other tree it is
//! zeros and no attributes, so a subtree is the same object wherever it sits.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;

pub const Kind = enum(u8) { file = 1, dir = 2, symlink = 3 };

/// Why bytes are not a tree. The decoder keeps the first one it finds.
pub const Reason = enum {
    none,
    too_large,
    truncated,
    version,
    count,
    kind,
    mode,
    owner,
    name,
    order,
    xattrs,
    target,
    trailing,
};

pub const Malformed = error{Malformed};

/// A decoded entry. Strings point into the bytes that were decoded.
pub const Entry = struct {
    name: []const u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    /// The canonical attribute section (`xattrs.zig`).
    xattrs: []const u8,
    /// File only: its length, the hash of its content and its object id.
    size: u64,
    content: Digest,
    object: Digest,
    /// Symlink only.
    target: []const u8,
    /// Directory only.
    subtree: Digest,
};

/// The directory's own mode, owner and attributes: meaningful in the root of an import only.
pub const Own = struct {
    mode: u16,
    uid: u32,
    gid: u32,
    xattrs: []const u8,

    pub const none: Own = .{ .mode = 0, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
};

pub const zero_digest: Digest = .{ .bytes = @splat(0) };

const header_bytes: u32 = 5;

/// What `own` takes when it has no attributes: the room every writer keeps for it.
const own_bytes_min: u32 = 2 + 4 + 4 + xattrs.empty.len;

/// A name the encoder accepts: not empty, at most 255 bytes, no slash, no NUL, not "." or "..".
pub fn name_is_valid(name: []const u8) bool {
    assert(constants.store_name_bytes_max <= 255);
    assert(name.len <= constants.file_bytes_max);
    if (name.len == 0) return false;
    if (name.len > constants.store_name_bytes_max) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false;
    if (std.mem.eql(u8, name, ".")) return false;
    if (std.mem.eql(u8, name, "..")) return false;
    return true;
}

/// Writes a tree into memory the caller owns. The importer builds a directory's entry header
/// before it knows a subdirectory's digest, so an entry is two calls: `begin` (everything up to
/// the payload) and one `end_*`.
pub const Writer = struct {
    buffer: []u8,
    len: u32,
    count: u32,
    /// The previous entry's name, to prove the order; it lives in the buffer.
    previous_at: u32,
    previous_len: u32,
    /// A `begin` has no `end_*` yet.
    open: bool,
    kind: Kind,

    pub const Error = error{TooLarge};

    pub fn init(buffer: []u8) Writer {
        assert(buffer.len >= header_bytes);
        assert(buffer.len <= std.math.maxInt(u32));
        buffer[0] = constants.store_tree_version;
        std.mem.writeInt(u32, buffer[1..5], 0, .little);
        return .{
            .buffer = buffer,
            .len = header_bytes,
            .count = 0,
            .previous_at = 0,
            .previous_len = 0,
            .open = false,
            .kind = .file,
        };
    }

    fn room(writer: *const Writer, bytes: usize) Error!void {
        assert(writer.len >= header_bytes);
        assert(writer.len <= writer.buffer.len);
        const limit = @min(writer.buffer.len, constants.store_tree_bytes_max);
        if (limit < own_bytes_min) return error.TooLarge;
        if (writer.len + bytes > limit - own_bytes_min) return error.TooLarge;
    }

    fn put(writer: *Writer, bytes: []const u8) void {
        assert(bytes.len > 0);
        assert(writer.len + bytes.len <= writer.buffer.len);
        @memcpy(writer.buffer[writer.len..][0..bytes.len], bytes);
        writer.len += @intCast(bytes.len);
    }

    fn put_int(writer: *Writer, comptime Int: type, value: Int) void {
        assert(@sizeOf(Int) <= 8);
        assert(writer.len + @sizeOf(Int) <= writer.buffer.len);
        var bytes: [@sizeOf(Int)]u8 = undefined;
        std.mem.writeInt(Int, &bytes, value, .little);
        writer.put(&bytes);
    }

    /// Starts an entry. `name` must be valid and greater than the previous entry's.
    pub fn begin(
        writer: *Writer,
        name: []const u8,
        kind: Kind,
        mode: u16,
        uid: u32,
        gid: u32,
        attributes: []const u8,
    ) Error!void {
        assert(!writer.open);
        assert(name_is_valid(name));
        assert(mode <= 0o7777);
        assert(uid != std.math.maxInt(u32));
        assert(gid != std.math.maxInt(u32));
        assert(xattrs.validate(attributes) == .none);
        if (writer.count > 0) {
            const before = writer.buffer[writer.previous_at..][0..writer.previous_len];
            assert(std.mem.lessThan(u8, before, name)); // Sorted and unique.
        }
        const payload_bytes: usize = switch (kind) {
            .file => 8 + 32 + 32,
            .dir => 32,
            .symlink => 0, // `end_symlink` checks for the target, which is not known yet.
        };
        try writer.room(1 + 2 + 4 + 4 + 1 + name.len + attributes.len + payload_bytes);
        writer.put(&.{@backingInt(kind)});
        writer.put_int(u16, mode);
        writer.put_int(u32, uid);
        writer.put_int(u32, gid);
        writer.put(&.{@as(u8, @intCast(name.len))});
        writer.previous_at = writer.len;
        writer.previous_len = @intCast(name.len);
        writer.put(name);
        writer.put(attributes);
        writer.open = true;
        writer.kind = kind;
    }

    pub fn end_file(writer: *Writer, size: u64, content: Digest, object: Digest) Error!void {
        assert(writer.open);
        assert(writer.kind == .file);
        assert(size <= constants.store_file_bytes_max);
        writer.put_int(u64, size);
        writer.put(&content.bytes);
        writer.put(&object.bytes);
        writer.close_entry();
    }

    pub fn end_symlink(writer: *Writer, target: []const u8) Error!void {
        assert(writer.open);
        assert(writer.kind == .symlink);
        assert(target.len > 0);
        assert(target.len <= constants.store_symlink_target_bytes_max);
        try writer.room(2 + target.len);
        writer.put_int(u16, @intCast(target.len));
        writer.put(target);
        writer.close_entry();
    }

    pub fn end_dir(writer: *Writer, subtree: Digest) Error!void {
        assert(writer.open);
        assert(writer.kind == .dir);
        writer.put(&subtree.bytes);
        writer.close_entry();
    }

    fn close_entry(writer: *Writer) void {
        assert(writer.open);
        writer.open = false;
        writer.count += 1;
        assert(writer.count <= constants.store_dir_entries_max);
    }

    /// The finished tree of a directory that is not a root: `own` is empty. Fills in the count.
    pub fn finish(writer: *Writer) []const u8 {
        // Every `begin` and `end_*` left room for the empty `own`, so this cannot fail.
        return writer.finish_with(Own.none) catch unreachable;
    }

    /// The finished tree of a root directory, with its own mode, owner and attributes.
    pub fn finish_with(writer: *Writer, own: Own) Error![]const u8 {
        assert(writer.len >= header_bytes);
        assert(!writer.open);
        assert(own.mode <= 0o7777);
        assert(xattrs.validate(own.xattrs) == .none);
        const limit = @min(writer.buffer.len, constants.store_tree_bytes_max);
        if (writer.len + 2 + 4 + 4 + own.xattrs.len > limit) return error.TooLarge;
        writer.put_int(u16, own.mode);
        writer.put_int(u32, own.uid);
        writer.put_int(u32, own.gid);
        writer.put(own.xattrs);
        std.mem.writeInt(u32, writer.buffer[1..5], writer.count, .little);
        return writer.buffer[0..writer.len];
    }
};

/// Reads a tree one entry at a time, without allocating.
pub const Decoder = struct {
    bytes: []const u8,
    at: u32,
    left: u32,
    previous: ?[]const u8,
    reason: Reason,
    /// The directory's own attributes; set once `next` has returned false.
    own: Own,
    own_read: bool,

    pub fn init(decoder: *Decoder, bytes: []const u8) Malformed!void {
        assert(@intFromPtr(decoder) != 0);
        assert(header_bytes == 5);
        decoder.* = .{
            .bytes = bytes,
            .at = header_bytes,
            .left = 0,
            .previous = null,
            .reason = .none,
            .own = Own.none,
            .own_read = false,
        };
        if (bytes.len > constants.store_tree_bytes_max) return decoder.refuse(.too_large);
        if (bytes.len < header_bytes + own_bytes_min) return decoder.refuse(.truncated);
        if (bytes[0] != constants.store_tree_version) return decoder.refuse(.version);
        decoder.left = std.mem.readInt(u32, bytes[1..5], .little);
        if (decoder.left > constants.store_dir_entries_max) return decoder.refuse(.count);
        // Every entry is at least this long, so a count that cannot fit is refused up front.
        const entry_bytes_min: u64 = 1 + 2 + 4 + 4 + 1 + 1 + 1 + 3; // The shortest: a symlink.
        if (decoder.left * entry_bytes_min > bytes.len - header_bytes) {
            return decoder.refuse(.count);
        }
    }

    fn refuse(decoder: *Decoder, reason: Reason) Malformed {
        assert(decoder.at <= decoder.bytes.len + 8);
        assert(reason != .none);
        if (decoder.reason == .none) decoder.reason = reason;
        return error.Malformed;
    }

    fn take(decoder: *Decoder, length: usize) Malformed![]const u8 {
        assert(decoder.at <= decoder.bytes.len);
        assert(length <= constants.store_tree_bytes_max);
        if (decoder.at + length > decoder.bytes.len) return decoder.refuse(.truncated);
        const slice = decoder.bytes[decoder.at..][0..length];
        decoder.at += @intCast(length);
        return slice;
    }

    fn take_int(decoder: *Decoder, comptime Int: type) Malformed!Int {
        assert(@sizeOf(Int) <= 8);
        assert(decoder.at <= decoder.bytes.len);
        const slice = try decoder.take(@sizeOf(Int));
        return std.mem.readInt(Int, slice[0..@sizeOf(Int)], .little);
    }

    fn take_digest(decoder: *Decoder) Malformed!Digest {
        assert(decoder.at <= decoder.bytes.len);
        assert(decoder.left <= constants.store_dir_entries_max);
        const slice = try decoder.take(constants.store_digest_bytes);
        return .{ .bytes = slice[0..constants.store_digest_bytes].* };
    }

    /// The next entry, or false at the end (after checking that nothing follows).
    pub fn next(decoder: *Decoder, entry: *Entry) Malformed!bool {
        assert(decoder.at <= decoder.bytes.len);
        assert(decoder.left <= constants.store_dir_entries_max);
        if (decoder.left == 0) {
            if (!decoder.own_read) try decoder.read_own();
            if (decoder.at != decoder.bytes.len) return decoder.refuse(.trailing);
            return false;
        }
        decoder.left -= 1;
        try decoder.read_header(entry);
        switch (entry.kind) {
            .file => try decoder.read_file_payload(entry),
            .symlink => try decoder.read_symlink_payload(entry),
            .dir => entry.subtree = try decoder.take_digest(),
        }
        decoder.previous = entry.name;
        return true;
    }

    fn read_own(decoder: *Decoder) Malformed!void {
        assert(!decoder.own_read);
        assert(decoder.left == 0);
        const mode = try decoder.take_int(u16);
        if (mode > 0o7777) return decoder.refuse(.mode);
        const uid = try decoder.take_int(u32);
        const gid = try decoder.take_int(u32);
        if (uid == std.math.maxInt(u32)) return decoder.refuse(.owner);
        if (gid == std.math.maxInt(u32)) return decoder.refuse(.owner);
        const section = xattrs.section_length(decoder.bytes[decoder.at..]) orelse
            return decoder.refuse(.xattrs);
        const attributes = try decoder.take(section);
        decoder.own = .{ .mode = mode, .uid = uid, .gid = gid, .xattrs = attributes };
        decoder.own_read = true;
    }

    fn read_header(decoder: *Decoder, entry: *Entry) Malformed!void {
        assert(decoder.at >= header_bytes);
        assert(decoder.at <= decoder.bytes.len);
        entry.* = .{
            .name = "",
            .kind = .file,
            .mode = 0,
            .uid = 0,
            .gid = 0,
            .xattrs = &xattrs.empty,
            .size = 0,
            .content = zero_digest,
            .object = zero_digest,
            .target = "",
            .subtree = zero_digest,
        };
        const kind_byte = (try decoder.take(1))[0];
        entry.kind = std.enums.fromInt(Kind, kind_byte) orelse return decoder.refuse(.kind);
        entry.mode = try decoder.take_int(u16);
        if (entry.mode > 0o7777) return decoder.refuse(.mode);
        entry.uid = try decoder.take_int(u32);
        entry.gid = try decoder.take_int(u32);
        // (uid_t)-1 means "no change" to chown, so it is never an owner.
        if (entry.uid == std.math.maxInt(u32)) return decoder.refuse(.owner);
        if (entry.gid == std.math.maxInt(u32)) return decoder.refuse(.owner);
        const name_len = (try decoder.take(1))[0];
        entry.name = try decoder.take(name_len);
        if (!name_is_valid(entry.name)) return decoder.refuse(.name);
        if (decoder.previous) |before| {
            if (!std.mem.lessThan(u8, before, entry.name)) return decoder.refuse(.order);
        }
        const section = xattrs.section_length(decoder.bytes[decoder.at..]) orelse
            return decoder.refuse(.xattrs);
        entry.xattrs = try decoder.take(section);
    }

    fn read_file_payload(decoder: *Decoder, entry: *Entry) Malformed!void {
        assert(entry.kind == .file);
        assert(decoder.at <= decoder.bytes.len);
        entry.size = try decoder.take_int(u64);
        if (entry.size > constants.store_file_bytes_max) return decoder.refuse(.count);
        entry.content = try decoder.take_digest();
        entry.object = try decoder.take_digest();
    }

    fn read_symlink_payload(decoder: *Decoder, entry: *Entry) Malformed!void {
        assert(entry.kind == .symlink);
        assert(decoder.at <= decoder.bytes.len);
        const length = try decoder.take_int(u16);
        if (length == 0) return decoder.refuse(.target);
        if (length > constants.store_symlink_target_bytes_max) return decoder.refuse(.target);
        entry.target = try decoder.take(length);
        if (std.mem.indexOfScalar(u8, entry.target, 0) != null) return decoder.refuse(.target);
    }
};

/// Decodes `bytes` and encodes the entries again into `out`. True if the result is `bytes`
/// exactly, or if `bytes` is not a tree at all; false is a break of canonicality. This is the
/// property the `tree` fuzzer checks, and a unit test checks it on fixed trees.
pub fn round_trips(bytes: []const u8, out: []u8) bool {
    assert(out.len > 0);
    assert(bytes.len <= std.math.maxInt(u32));
    var decoder: Decoder = undefined;
    decoder.init(bytes) catch return true;
    var writer = Writer.init(out);
    var entry: Entry = undefined;
    while (decoder.next(&entry) catch return true) {
        writer.begin(entry.name, entry.kind, entry.mode, entry.uid, entry.gid, entry.xattrs) catch
            return false;
        switch (entry.kind) {
            .file => writer.end_file(entry.size, entry.content, entry.object) catch return false,
            .symlink => writer.end_symlink(entry.target) catch return false,
            .dir => writer.end_dir(entry.subtree) catch return false,
        }
    }
    const again = writer.finish_with(decoder.own) catch return false;
    return std.mem.eql(u8, again, bytes);
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

/// Three entries of the three kinds, in a buffer the caller gives (4 KiB is plenty).
fn sample(out: []u8) Writer.Error![]const u8 {
    const content = Digest.of("hello");
    const object = Digest.of("object");
    var writer = Writer.init(out);
    const none = &xattrs.empty;
    try writer.begin("a.txt", .file, 0o644, 0, 0, none);
    try writer.end_file(5, content, object);
    try writer.begin("bin", .dir, 0o755, 0, 0, none);
    try writer.end_dir(Digest.of("subtree"));
    try writer.begin("link", .symlink, 0o777, 1, 2, none);
    try writer.end_symlink("a.txt");
    return writer.finish();
}

var test_buffer: [4096]u8 = undefined;
var test_other: [4096]u8 = undefined;

test "a tree decodes to the entries that were written, in order" {
    // Goal: the encoder and decoder are a pair. Method: three entries of the three kinds, read
    // back field by field, then the digest is stable.
    const bytes = try sample(&test_buffer);
    var decoder: Decoder = undefined;
    try decoder.init(bytes);
    var entry: Entry = undefined;
    try testing.expect(try decoder.next(&entry));
    try testing.expectEqualStrings("a.txt", entry.name);
    try testing.expectEqual(Kind.file, entry.kind);
    try testing.expectEqual(@as(u16, 0o644), entry.mode);
    try testing.expectEqual(@as(u64, 5), entry.size);
    try testing.expect(entry.content.eql(Digest.of("hello")));
    try testing.expect(entry.object.eql(Digest.of("object")));
    try testing.expect(try decoder.next(&entry));
    try testing.expectEqual(Kind.dir, entry.kind);
    try testing.expect(entry.subtree.eql(Digest.of("subtree")));
    try testing.expect(try decoder.next(&entry));
    try testing.expectEqualStrings("a.txt", entry.target);
    try testing.expectEqual(@as(u32, 1), entry.uid);
    try testing.expectEqual(@as(u32, 2), entry.gid);
    try testing.expect(!(try decoder.next(&entry)));
    try testing.expect(round_trips(bytes, &test_other));
    const again = try sample(&test_other);
    try testing.expect(Digest.of(bytes).eql(Digest.of(again)));
}

test "an empty directory is a tree of just its header and an empty own section" {
    // Goal: the smallest tree is valid and has the same digest every time.
    var writer = Writer.init(&test_buffer);
    const bytes = writer.finish();
    const zeros: [10]u8 = @splat(0);
    const expected = [_]u8{ 1, 0, 0, 0, 0 } ++ zeros ++ xattrs.empty;
    try testing.expectEqualSlices(u8, &expected, bytes);
    var decoder: Decoder = undefined;
    try decoder.init(bytes);
    var entry: Entry = undefined;
    try testing.expect(!(try decoder.next(&entry)));
}

test "the decoder refuses what the encoder cannot write" {
    // Goal: the negative space, one case per reason. Method: damage a good tree one way at a
    // time and check the reason the decoder gives.
    const good = try sample(&test_buffer);
    const cases = [_]struct { reason: Reason, edit: *const fn ([]u8) []u8 }{
        .{ .reason = .version, .edit = edit_version },
        .{ .reason = .count, .edit = edit_count_high },
        .{ .reason = .kind, .edit = edit_kind },
        .{ .reason = .trailing, .edit = edit_trailing },
        .{ .reason = .truncated, .edit = edit_truncate },
        .{ .reason = .mode, .edit = edit_mode },
        .{ .reason = .name, .edit = edit_name_slash },
        .{ .reason = .order, .edit = edit_name_order },
    };
    for (cases) |case| {
        var copy: [4096]u8 = @splat(0);
        @memcpy(copy[0..good.len], good);
        const damaged = case.edit(copy[0..good.len]);
        var decoder: Decoder = undefined;
        var failed = false;
        decoder.init(damaged) catch {
            failed = true;
        };
        var entry: Entry = undefined;
        while (!failed) {
            const more = decoder.next(&entry) catch {
                failed = true;
                break;
            };
            if (!more) break;
        }
        try testing.expect(failed);
        try testing.expectEqual(case.reason, decoder.reason);
        try testing.expect(round_trips(damaged, &test_other));
    }
}

fn edit_version(bytes: []u8) []u8 {
    bytes[0] = 2;
    return bytes;
}

fn edit_count_high(bytes: []u8) []u8 {
    std.mem.writeInt(u32, bytes[1..5], 100, .little);
    return bytes;
}

fn edit_kind(bytes: []u8) []u8 {
    bytes[header_bytes] = 9;
    return bytes;
}

fn edit_trailing(bytes: []u8) []u8 {
    // The caller's buffer is longer than the tree and zero-filled: one more byte follows.
    return bytes.ptr[0 .. bytes.len + 1];
}

fn edit_truncate(bytes: []u8) []u8 {
    return bytes[0 .. bytes.len - 3];
}

fn edit_mode(bytes: []u8) []u8 {
    std.mem.writeInt(u16, bytes[header_bytes + 1 ..][0..2], 0o10000, .little);
    return bytes;
}

fn edit_name_slash(bytes: []u8) []u8 {
    const at = std.mem.indexOf(u8, bytes, "a.txt").?;
    bytes[at + 1] = '/';
    return bytes;
}

fn edit_name_order(bytes: []u8) []u8 {
    const at = std.mem.indexOf(u8, bytes, "bin").?;
    bytes[at] = '0'; // "0in" sorts before "a.txt".
    return bytes;
}

test "names: the edge of valid" {
    // Goal: the names a directory can hold are exactly these. Method: the longest, one over,
    // slash, NUL, dot names, and a name with a space and non-ASCII bytes (valid: names are bytes).
    try testing.expect(name_is_valid("a"));
    try testing.expect(name_is_valid("a b\xc3\xa9"));
    try testing.expect(name_is_valid(".hidden"));
    try testing.expect(name_is_valid("..."));
    try testing.expect(name_is_valid(repeat('x', constants.store_name_bytes_max)));
    try testing.expect(!name_is_valid(repeat('x', constants.store_name_bytes_max + 1)));
    try testing.expect(!name_is_valid(""));
    try testing.expect(!name_is_valid("a/b"));
    try testing.expect(!name_is_valid("a\x00b"));
    try testing.expect(!name_is_valid("."));
    try testing.expect(!name_is_valid(".."));
}

test "the writer refuses a tree that does not fit its buffer" {
    // Goal: exceeding a bound is an operating error, never a write outside the buffer.
    var small: [64]u8 = undefined;
    var writer = Writer.init(&small);
    try testing.expectError(
        error.TooLarge,
        writer.begin("a", .file, 0o644, 0, 0, &xattrs.empty),
    );
}

test "an attribute changes the encoding, and a changed owner does too" {
    // Goal: everything the brief lists is in the identity. Method: the same file with an
    // xattr, another uid and another mode gives four distinct digests.
    var builder: xattrs.Builder = undefined;
    builder.reset();
    try builder.add("user.k", "v");
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    const with_xattr = builder.finish(&blob);
    const variants = [_]struct { mode: u16, uid: u32, attrs: []const u8 }{
        .{ .mode = 0o644, .uid = 0, .attrs = &xattrs.empty },
        .{ .mode = 0o755, .uid = 0, .attrs = &xattrs.empty },
        .{ .mode = 0o644, .uid = 1, .attrs = &xattrs.empty },
        .{ .mode = 0o644, .uid = 0, .attrs = with_xattr },
    };
    var seen: [4]Digest = undefined;
    for (variants, 0..) |variant, index| {
        var writer = Writer.init(&test_buffer);
        try writer.begin("f", .file, variant.mode, variant.uid, 0, variant.attrs);
        try writer.end_file(0, Digest.of(""), Digest.of("o"));
        seen[index] = Digest.of(writer.finish());
        for (seen[0..index]) |before| try testing.expect(!before.eql(seen[index]));
    }
}

test "the own section of a root is part of the digest, and survives a round trip" {
    // Goal: the root directory's mode, owner and attributes change the identity and come back.
    // Method: the same entries finished with four different own sections.
    var builder: xattrs.Builder = undefined;
    builder.reset();
    try builder.add("user.k", "v");
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    const with_xattr = builder.finish(&blob);
    const variants = [_]Own{
        .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty },
        .{ .mode = 0o700, .uid = 0, .gid = 0, .xattrs = &xattrs.empty },
        .{ .mode = 0o755, .uid = 3, .gid = 0, .xattrs = &xattrs.empty },
        .{ .mode = 0o755, .uid = 0, .gid = 4, .xattrs = &xattrs.empty },
        .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = with_xattr },
    };
    var seen: [variants.len]Digest = undefined;
    for (variants, 0..) |variant, index| {
        var writer = Writer.init(&test_buffer);
        try writer.begin("f", .file, 0o644, 0, 0, &xattrs.empty);
        try writer.end_file(0, Digest.of(""), Digest.of("o"));
        const bytes = try writer.finish_with(variant);
        seen[index] = Digest.of(bytes);
        for (seen[0..index]) |before| try testing.expect(!before.eql(seen[index]));
        var decoder: Decoder = undefined;
        try decoder.init(bytes);
        var entry: Entry = undefined;
        try testing.expect(try decoder.next(&entry));
        try testing.expect(!(try decoder.next(&entry)));
        try testing.expectEqual(variant.mode, decoder.own.mode);
        try testing.expectEqual(variant.uid, decoder.own.uid);
        try testing.expectEqual(variant.gid, decoder.own.gid);
        try testing.expectEqualSlices(u8, variant.xattrs, decoder.own.xattrs);
        try testing.expect(round_trips(bytes, &test_other));
    }
}

test "a bad own section is refused for its reason" {
    // Goal: the own section is as strict as an entry. Method: a mode past 07777, an owner
    // of -1, a group of -1.
    var writer = Writer.init(&test_buffer);
    const good = try writer.finish_with(
        .{ .mode = 0o755, .uid = 1, .gid = 2, .xattrs = &xattrs.empty },
    );
    const at = good.len - 11;
    const cases = [_]struct { reason: Reason, offset: usize, bytes: []const u8 }{
        .{ .reason = .mode, .offset = at, .bytes = &.{ 0xff, 0xff } },
        .{ .reason = .owner, .offset = at + 2, .bytes = &.{ 0xff, 0xff, 0xff, 0xff } },
        .{ .reason = .owner, .offset = at + 6, .bytes = &.{ 0xff, 0xff, 0xff, 0xff } },
    };
    for (cases) |case| {
        var copy: [64]u8 = undefined;
        @memcpy(copy[0..good.len], good);
        @memcpy(copy[case.offset..][0..case.bytes.len], case.bytes);
        var decoder: Decoder = undefined;
        try decoder.init(copy[0..good.len]);
        var entry: Entry = undefined;
        try testing.expectError(error.Malformed, decoder.next(&entry));
        try testing.expectEqual(case.reason, decoder.reason);
    }
}
