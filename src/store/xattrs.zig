//! Extended attributes as the store records them: one canonical byte string, the same in a file
//! object's header and in a tree entry, so that two files with the same attributes always
//! encode to the same bytes whatever order the kernel listed them in.
//!
//! The encoding: a count byte, then for each attribute (sorted by name, bytewise, no duplicates)
//! a 16-bit name length, the name, a 16-bit value length and the value, all little-endian.
//!
//! Which attributes the store keeps is a decision (docs/briefs/M3-store.md): `user.*` and
//! `security.capability` round-trip, `user.overlay.*` is overlayfs's own and is never imported,
//! and every other namespace is skipped with a warning. `Class` is that decision as a function.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// A section with no attributes: just the count byte.
pub const empty = [1]u8{0};

pub const Class = enum {
    /// Recorded and restored.
    keep,
    /// Overlayfs's own attribute (`user.overlay.*`): never imported, no warning, because a rootfs
    /// that was a container's upper layer carries them by design.
    overlay,
    /// Any other namespace (`trusted.*`, `system.*`, `security.selinux`, ...): skipped with a
    /// warning that names the file and the attribute.
    unsupported,
};

pub fn class_of(name: []const u8) Class {
    assert(name.len <= constants.file_bytes_max);
    assert(name.len > 0);
    if (std.mem.startsWith(u8, name, "user.overlay.")) return .overlay;
    if (std.mem.eql(u8, name, "security.capability")) return .keep;
    if (std.mem.startsWith(u8, name, "user.")) return .keep;
    return .unsupported;
}

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const Malformed = enum { none, count, name, order, value, truncated };

/// Checks a whole section: the count, every length, the order. `rest` is how many bytes follow
/// the section when `blob` is a prefix of a longer record; here the section must be all of it.
pub fn validate(blob: []const u8) Malformed {
    assert(blob.len <= constants.file_bytes_max);
    assert(constants.store_xattrs_max <= std.math.maxInt(u8));
    if (blob.len == 0) return .truncated;
    if (blob.len > constants.store_xattr_blob_bytes_max) return .count;
    if (blob[0] > constants.store_xattrs_max) return .count;
    var iterator = Iterator.init(blob);
    var previous: ?[]const u8 = null;
    var seen: u32 = 0;
    while (iterator.next()) |item| {
        if (item.name.len == 0) return .name;
        if (item.name.len > constants.store_xattr_name_bytes_max) return .name;
        if (std.mem.indexOfScalar(u8, item.name, 0) != null) return .name;
        if (item.value.len > constants.store_xattr_value_bytes_max) return .value;
        if (previous) |before| {
            if (!std.mem.lessThan(u8, before, item.name)) return .order;
        }
        previous = item.name;
        seen += 1;
    }
    if (iterator.broken) return .truncated;
    if (seen != blob[0]) return .truncated;
    if (iterator.at != blob.len) return .truncated;
    return .none;
}

/// How long the section at the start of `bytes` is, or null if it is cut short or malformed.
pub fn section_length(bytes: []const u8) ?u32 {
    assert(bytes.len <= constants.file_bytes_max);
    assert(constants.store_xattr_blob_bytes_max > 0);
    if (bytes.len == 0) return null;
    var iterator = Iterator.init(bytes);
    var seen: u32 = 0;
    while (seen < bytes[0]) : (seen += 1) {
        _ = iterator.next() orelse return null;
    }
    if (iterator.broken) return null;
    const length = iterator.at;
    if (validate(bytes[0..length]) != .none) return null;
    return length;
}

pub const Iterator = struct {
    blob: []const u8,
    at: u32,
    left: u32,
    /// A length ran past the end of the blob.
    broken: bool,

    pub fn init(blob: []const u8) Iterator {
        assert(constants.store_xattrs_max < 256);
        assert(blob.len > 0);
        return .{ .blob = blob, .at = 1, .left = blob[0], .broken = false };
    }

    pub fn next(iterator: *Iterator) ?Xattr {
        assert(iterator.at >= 1);
        if (!iterator.broken) assert(iterator.at <= iterator.blob.len);
        if (iterator.left == 0) return null;
        iterator.left -= 1;
        const name = iterator.take_sized() orelse return null;
        const value = iterator.take_sized() orelse return null;
        return .{ .name = name, .value = value };
    }

    fn take_sized(iterator: *Iterator) ?[]const u8 {
        assert(iterator.at >= 1);
        assert(iterator.blob.len > 0);
        const blob = iterator.blob;
        if (iterator.at + 2 > blob.len) {
            iterator.broken = true;
            return null;
        }
        const length: u32 = std.mem.readInt(u16, blob[iterator.at..][0..2], .little);
        const start = iterator.at + 2;
        if (start + length > blob.len) {
            iterator.broken = true;
            return null;
        }
        iterator.at = start + length;
        return blob[start..][0..length];
    }
};

/// What `Builder.add` found wrong, for the warning the importer shows.
pub const AddError = error{ TooMany, NameTooLong, ValueTooLong };

/// Collects attributes in any order and writes the canonical section.
pub const Builder = struct {
    /// Where each attribute is in `names` and `values`, so that sorting moves small records.
    items: [constants.store_xattrs_max]Item,
    count: u32,
    names: [constants.store_xattrs_max * constants.store_xattr_name_bytes_max]u8,
    values: [constants.store_xattrs_max * constants.store_xattr_value_bytes_max]u8,
    names_len: u32,
    values_len: u32,

    const Item = struct { name_at: u32, name_len: u32, value_at: u32, value_len: u32 };

    pub fn reset(builder: *Builder) void {
        builder.count = 0;
        builder.names_len = 0;
        builder.values_len = 0;
        assert(builder.count == 0);
        assert(builder.names_len + builder.values_len == 0);
    }

    pub fn add(builder: *Builder, name: []const u8, value: []const u8) AddError!void {
        assert(name.len > 0);
        assert(builder.count <= constants.store_xattrs_max);
        if (builder.count == constants.store_xattrs_max) return error.TooMany;
        if (name.len > constants.store_xattr_name_bytes_max) return error.NameTooLong;
        if (value.len > constants.store_xattr_value_bytes_max) return error.ValueTooLong;
        const item: Item = .{
            .name_at = builder.names_len,
            .name_len = @intCast(name.len),
            .value_at = builder.values_len,
            .value_len = @intCast(value.len),
        };
        @memcpy(builder.names[item.name_at..][0..name.len], name);
        @memcpy(builder.values[item.value_at..][0..value.len], value);
        builder.names_len += item.name_len;
        builder.values_len += item.value_len;
        builder.items[builder.count] = item;
        builder.count += 1;
    }

    fn name_of(builder: *const Builder, item: Item) []const u8 {
        assert(item.name_len > 0);
        assert(item.name_at + item.name_len <= builder.names_len);
        return builder.names[item.name_at..][0..item.name_len];
    }

    fn item_less(builder: *const Builder, first: Item, second: Item) bool {
        assert(first.name_len > 0);
        assert(second.name_len > 0);
        return std.mem.lessThan(u8, builder.name_of(first), builder.name_of(second));
    }

    /// Writes the canonical section into `out` and returns it. Two attributes with one name
    /// cannot come from a file system, so a duplicate is a programming error.
    pub fn finish(builder: *Builder, out: *[constants.store_xattr_blob_bytes_max]u8) []const u8 {
        assert(builder.count <= constants.store_xattrs_max);
        const items = builder.items[0..builder.count];
        std.mem.sortUnstable(Item, items, builder, item_less);
        out[0] = @intCast(builder.count);
        var at: u32 = 1;
        for (items, 0..) |item, index| {
            if (index > 0) assert(builder.item_less(items[index - 1], item)); // No duplicates.
            std.mem.writeInt(u16, out[at..][0..2], @intCast(item.name_len), .little);
            @memcpy(out[at + 2 ..][0..item.name_len], builder.name_of(item));
            at += 2 + item.name_len;
            std.mem.writeInt(u16, out[at..][0..2], @intCast(item.value_len), .little);
            @memcpy(
                out[at + 2 ..][0..item.value_len],
                builder.values[item.value_at..][0..item.value_len],
            );
            at += 2 + item.value_len;
        }
        assert(validate(out[0..at]) == .none);
        return out[0..at];
    }
};

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "the namespaces: user.* and the capability are kept, overlay's own are not, others warn" {
    // Goal: the brief's decision as a function, at its edges (`user.overlayx` is a user
    // attribute; `user.overlay.` with the dot is overlayfs's).
    try testing.expectEqual(Class.keep, class_of("user.comment"));
    try testing.expectEqual(Class.keep, class_of("security.capability"));
    try testing.expectEqual(Class.keep, class_of("user.overlayx"));
    try testing.expectEqual(Class.overlay, class_of("user.overlay.opaque"));
    try testing.expectEqual(Class.overlay, class_of("user.overlay.whiteout"));
    try testing.expectEqual(Class.unsupported, class_of("security.selinux"));
    try testing.expectEqual(Class.unsupported, class_of("trusted.overlay.opaque"));
    try testing.expectEqual(Class.unsupported, class_of("system.posix_acl_access"));
    try testing.expectEqual(Class.unsupported, class_of("security.capabilityx"));
}

var builder_storage: Builder = undefined;

test "the builder sorts, and the section validates and iterates back" {
    // Goal: the encoding is canonical whatever order attributes arrive in. Method: three
    // attributes in two orders give identical bytes, which iterate in name order.
    var first_out: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    var second_out: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    const builder = &builder_storage;
    builder.reset();
    try builder.add("user.b", "two");
    try builder.add("security.capability", "\x01\x00");
    try builder.add("user.a", "");
    const first = builder.finish(&first_out);
    builder.reset();
    try builder.add("user.a", "");
    try builder.add("user.b", "two");
    try builder.add("security.capability", "\x01\x00");
    const second = builder.finish(&second_out);
    try testing.expectEqualSlices(u8, first, second);
    try testing.expectEqual(Malformed.none, validate(first));
    var iterator = Iterator.init(first);
    try testing.expectEqualStrings("security.capability", iterator.next().?.name);
    try testing.expectEqualStrings("user.a", iterator.next().?.name);
    const last = iterator.next().?;
    try testing.expectEqualStrings("user.b", last.name);
    try testing.expectEqualStrings("two", last.value);
    try testing.expect(iterator.next() == null);
    try testing.expectEqual(@as(?u32, @intCast(first.len)), section_length(first));
}

test "validate refuses every way a section can be wrong, at the boundary" {
    // Goal: the negative space. Method: hand-made sections: unsorted, duplicate, empty name,
    // too many, cut short, extra bytes, an oversized value.
    try testing.expectEqual(Malformed.none, validate(&empty));
    try testing.expectEqual(Malformed.truncated, validate(""));
    try testing.expectEqual(Malformed.truncated, validate(&[_]u8{1}));
    const unsorted = [_]u8{ 2, 1, 0, 'b', 0, 0, 1, 0, 'a', 0, 0 };
    try testing.expectEqual(Malformed.order, validate(&unsorted));
    const duplicate = [_]u8{ 2, 1, 0, 'a', 0, 0, 1, 0, 'a', 0, 0 };
    try testing.expectEqual(Malformed.order, validate(&duplicate));
    const nameless = [_]u8{ 1, 0, 0, 0, 0 };
    try testing.expectEqual(Malformed.name, validate(&nameless));
    try testing.expectEqual(Malformed.count, validate(&[_]u8{constants.store_xattrs_max + 1}));
    const extra = [_]u8{ 1, 1, 0, 'a', 0, 0, 9 };
    try testing.expectEqual(Malformed.truncated, validate(&extra));
    try testing.expect(section_length(&extra) == null or section_length(&extra).? == 6);
    const cut = [_]u8{ 1, 1, 0, 'a', 5, 0, 1 };
    try testing.expectEqual(Malformed.truncated, validate(&cut));
    try testing.expect(section_length(&cut) == null);
}

test "the builder refuses what does not fit" {
    // Goal: the limits are operating errors. Method: too many attributes, a long name, a long
    // value.
    const builder = &builder_storage;
    builder.reset();
    for (0..constants.store_xattrs_max) |index| {
        var name: [8]u8 = undefined;
        const text = try std.fmt.bufPrint(&name, "user.{d:0>2}", .{index});
        try builder.add(text, "v");
    }
    try testing.expectError(error.TooMany, builder.add("user.x", "v"));
    builder.reset();
    const long_name = repeat('u', constants.store_xattr_name_bytes_max + 1);
    try testing.expectError(error.NameTooLong, builder.add(long_name, "v"));
    const long_value = repeat('v', constants.store_xattr_value_bytes_max + 1);
    try testing.expectError(error.ValueTooLong, builder.add("user.a", long_value));
    try builder.add("user.a", long_value[0..constants.store_xattr_value_bytes_max]);
}
