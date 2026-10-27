//! Looking through the image records (`images/<manifest hex>`): by the reference an image was
//! pulled as, by the tree it became, or all of them. The records are read one at a time into the
//! caller's `Image`, so the cost is the names of the directory and one record.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const lock_file = @import("../lock_file.zig");
const shards = @import("shards.zig");
const images = @import("images.zig");
const digest_mod = @import("digest.zig");
const layout = @import("layout.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// The memory a scan lists the directory in.
pub const Memory = struct {
    names: [constants.images_max * 66]u8,
    offsets: [constants.images_max]u32,
};

pub const Error = error{ Unreadable, Damaged, TooMany };

/// Calls `visitor.visit(image)` for each record, in the order of the manifest digests. A record
/// that is damaged or newer is `Damaged`: a scan that skipped it would answer wrongly.
pub fn scan(store: *const Store, memory: *Memory, image: *images.Image, visitor: anytype) Error!void {
    assert(store.root_len > 1);
    const found = shards.read(store, &memory.names, &memory.offsets, images.directory_name, null) catch {
        return error.Unreadable;
    };
    if (found.list.too_many or found.list.too_long) return error.TooMany;
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const manifest = Sha256.from_hex(found.name(index)) orelse continue;
        var errno: u16 = 0;
        images.load(store, manifest, image, &errno) catch |err| {
            return if (err == error.Unreadable) error.Unreadable else error.Damaged;
        };
        visitor.visit(image);
    }
}

/// The newest record whose reference means the same image as `text`.
pub const ByReference = struct {
    text: []const u8,
    time: u64 = 0,
    found: bool = false,
    manifest: Sha256 = undefined,
    tree: Digest = undefined,

    pub fn visit(self: *ByReference, image: *const images.Image) void {
        assert(self.text.len > 0);
        if (!lock_file.same_reference(image.reference_text(), self.text)) return;
        if (self.found and image.time < self.time) return;
        self.found = true;
        self.time = image.time;
        self.manifest = image.manifest;
        self.tree = image.tree;
    }
};

/// Counts the records that became the tree, and keeps the manifest of the last.
pub const ByTree = struct {
    tree: Digest,
    count: u32 = 0,
    manifest: Sha256 = undefined,

    pub fn visit(self: *ByTree, image: *const images.Image) void {
        if (!image.tree.eql(self.tree)) return;
        self.count += 1;
        self.manifest = image.manifest;
    }
};

const testing = std.testing;

test "a visitor sees the records it is meant to" {
    // Goal: the visitors' selection logic, without a store.
    var image: images.Image = undefined;
    const written = "docker.io/library/alpine:3.20";
    @memcpy(image.reference[0..written.len], written);
    image.reference_len = written.len;
    image.manifest = Sha256.of("m1");
    image.tree = Digest.of("t1");
    image.time = 5;
    var by: ByReference = .{ .text = "alpine:3.20" };
    by.visit(&image);
    try testing.expect(by.found);
    image.manifest = Sha256.of("m2");
    image.time = 9;
    by.visit(&image);
    try testing.expect(by.manifest.eql(Sha256.of("m2")));
    image.manifest = Sha256.of("m3");
    image.time = 7;
    by.visit(&image);
    try testing.expect(by.manifest.eql(Sha256.of("m2"))); // The older one does not replace.
    var other: ByReference = .{ .text = "alpine:3.19" };
    other.visit(&image);
    try testing.expect(!other.found);
    var tree: ByTree = .{ .tree = Digest.of("t1") };
    tree.visit(&image);
    try testing.expectEqual(@as(u32, 1), tree.count);
}
