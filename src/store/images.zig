//! Image records: `<store>/images/<manifest digest hex>`, one per pulled image. A record says
//! what was pulled (the reference as written, the manifest, the platform, the config blob and
//! the layer blobs) and which tree it became. It keeps those blobs and that tree alive for gc:
//! a blob is kept while an image record names it.
//!
//! The file is the text of a small ZON-like record, written atomically, one field a line:
//!
//!   .{
//!       .version = 1,
//!       .reference = "alpine:3.20",
//!       .manifest = "sha256:...",
//!       .platform = "linux/amd64",
//!       .config = "sha256:...",
//!       .tree = "b3:...",
//!       .time = 1760000000,
//!       .layers = "sha256:...",     (one line per layer, in order)
//!       .layers = "sha256:...",
//!   }
//!
//! Later slices add the image's configuration; a reader skips keys it does not know, and a
//! record of a newer version is `Newer`, never guessed at.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const roots = @import("roots.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const record_version: u32 = 1;
pub const directory_name = "images";

pub const Image = struct {
    reference: [constants.reference_bytes_max]u8,
    reference_len: u16,
    manifest: Sha256,
    platform: [16]u8,
    platform_len: u8,
    config: Sha256,
    tree: Digest,
    time: u64,
    layer_count: u32,
    layers: [constants.registry_layers_max]Sha256,

    pub fn reference_text(image: *const Image) []const u8 {
        assert(image.reference_len <= constants.reference_bytes_max);
        return image.reference[0..image.reference_len];
    }

    pub fn platform_text(image: *const Image) []const u8 {
        assert(image.platform_len <= image.platform.len);
        return image.platform[0..image.platform_len];
    }
};

pub fn render(image: *const Image, buffer: *[constants.image_record_bytes_max]u8) []const u8 {
    assert(image.layer_count <= constants.registry_layers_max);
    assert(image.time < 1 << 40);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the buffer holds the fixed fields, the reference escaped (four bytes a byte
    // at the worst) and 128 layer lines of 90 bytes.
    const head = ".{{\n    .version = {d},\n    .reference = ";
    writer.print(head, .{record_version}) catch unreachable; // Sized.
    roots.put_string(&writer, image.reference_text());
    writer.print(",\n    .manifest = \"{s}\",\n    .platform = \"{s}\",\n", .{
        &image.manifest.text(), image.platform_text(),
    }) catch unreachable; // Same bound.
    writer.print("    .config = \"{s}\",\n    .tree = \"{s}\",\n    .time = {d},\n", .{
        &image.config.text(), image.tree.text(), image.time,
    }) catch unreachable; // Same bound.
    for (image.layers[0..image.layer_count]) |layer| {
        writer.print("    .layers = \"{s}\",\n", .{&layer.text()}) catch unreachable; // Same.
    }
    writer.writeAll("}\n") catch unreachable; // Same bound.
    assert(writer.end <= buffer.len);
    return writer.buffered();
}

pub const ParseResult = enum { ok, malformed, newer };

fn quoted_digest(value: []const u8) ?Sha256 {
    var word: [constants.oci_digest_text_bytes]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return null;
    return Sha256.parse(word[0..length]);
}

/// Reads a record.
pub fn parse(text: []const u8, image: *Image) ParseResult {
    assert(text.len <= constants.image_record_bytes_max);
    image.reference_len = 0;
    image.platform_len = 0;
    image.layer_count = 0;
    image.time = 0;
    var version: u32 = 0;
    var seen: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " ");
        if (!std.mem.startsWith(u8, line, ".")) continue;
        const equals = std.mem.indexOf(u8, line, " = ") orelse continue;
        const key = line[1..equals];
        var value = line[equals + 3 ..];
        if (value.len > 0 and value[value.len - 1] == ',') value = value[0 .. value.len - 1];
        if (std.mem.eql(u8, key, "version")) {
            version = std.fmt.parseInt(u32, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "reference")) {
            const length = roots.parse_string(value, &image.reference) orelse return .malformed;
            image.reference_len = @intCast(length);
            seen += 1;
        } else if (std.mem.eql(u8, key, "manifest")) {
            image.manifest = quoted_digest(value) orelse return .malformed;
            seen += 1;
        } else if (std.mem.eql(u8, key, "platform")) {
            const length = roots.parse_string(value, &image.platform) orelse return .malformed;
            image.platform_len = @intCast(length);
            seen += 1;
        } else if (std.mem.eql(u8, key, "config")) {
            image.config = quoted_digest(value) orelse return .malformed;
            seen += 1;
        } else if (std.mem.eql(u8, key, "tree")) {
            var word: [constants.store_digest_text_bytes]u8 = undefined;
            const length = roots.parse_string(value, &word) orelse return .malformed;
            image.tree = Digest.parse(word[0..length]) orelse return .malformed;
            seen += 1;
        } else if (std.mem.eql(u8, key, "time")) {
            image.time = std.fmt.parseInt(u64, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "layers")) {
            if (image.layer_count == constants.registry_layers_max) return .malformed;
            image.layers[image.layer_count] = quoted_digest(value) orelse return .malformed;
            image.layer_count += 1;
        }
    }
    if (version == 0) return .malformed;
    if (version > record_version) return .newer;
    if (seen != 5) return .malformed;
    return .ok;
}

fn record_path(store: *const Store, buffer: *PathBuf, manifest: Sha256) [:0]const u8 {
    assert(store.root_len > 1);
    const hex = manifest.hex();
    return store.path(buffer, &.{ "/", directory_name, "/", &hex });
}

/// Writes the image's record atomically; a second pull of the same manifest replaces it.
pub fn save(store: *Store, image: *const Image, failure: *fs_mod.Failure) host_mod.Error!void {
    assert(image.layer_count <= constants.registry_layers_max);
    assert(image.time < 1 << 40);
    var directory: PathBuf = undefined;
    const directory_path = store.directory_path(&directory, directory_name);
    store.fs.make_directory(directory_path, true) catch |err| return store.fs.note(failure, err);
    var bytes: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(image, &bytes);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = record_path(store, &final, image.manifest);
    try store.fs.write_atomic(temporary_path, final_path, directory_path, text, 0o644, failure);
}

pub const LoadError = error{ NotFound, Unreadable, Damaged, Newer };

pub fn load(store: *const Store, manifest: Sha256, image: *Image, errno: *u16) LoadError!void {
    assert(@intFromPtr(image) != 0);
    var path: PathBuf = undefined;
    var bytes: [constants.image_record_bytes_max]u8 = undefined;
    const text = store.fs.read_whole(record_path(store, &path, manifest), &bytes) catch |err| {
        errno.* = store.fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    switch (parse(text, image)) {
        .ok => {},
        .malformed => return error.Damaged,
        .newer => return error.Newer,
    }
    if (!image.manifest.eql(manifest)) return error.Damaged;
}

const testing = std.testing;

fn sample() Image {
    var image: Image = undefined;
    const reference = "docker.io/library/alpine:3.20";
    @memcpy(image.reference[0..reference.len], reference);
    image.reference_len = reference.len;
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = Digest.of("tree");
    image.time = 1760000000;
    image.layer_count = 2;
    image.layers[0] = Sha256.of("one");
    image.layers[1] = Sha256.of("two");
    return image;
}

test "a record round-trips, and the worst case fits the buffer" {
    // Goal: every field comes back; 128 layers and an all-escaped reference still render.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqualStrings(image.reference_text(), back.reference_text());
    try testing.expect(back.manifest.eql(image.manifest));
    try testing.expect(back.config.eql(image.config));
    try testing.expect(back.tree.eql(image.tree));
    try testing.expectEqual(@as(u32, 2), back.layer_count);
    try testing.expect(back.layers[1].eql(image.layers[1]));
    try testing.expectEqualStrings("linux/amd64", back.platform_text());

    image.reference_len = constants.reference_bytes_max;
    @memset(image.reference[0..image.reference_len], '"');
    image.layer_count = constants.registry_layers_max;
    for (&image.layers) |*layer| layer.* = Sha256.of("x");
    const worst = render(&image, &buffer);
    try testing.expectEqual(ParseResult.ok, parse(worst, &back));
    try testing.expectEqual(@as(u32, constants.registry_layers_max), back.layer_count);
}

test "a damaged or newer record is refused" {
    // Goal: no guessing: a missing field, a bad digest, a newer version, no version.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    const alloc = testing.allocator;
    const newer = try std.mem.replaceOwned(u8, alloc, text, "version = 1", "version = 2");
    defer testing.allocator.free(newer);
    try testing.expectEqual(ParseResult.newer, parse(newer, &back));
    const cut = text[0..std.mem.indexOf(u8, text, "    .tree").?];
    try testing.expectEqual(ParseResult.malformed, parse(cut, &back));
    try testing.expectEqual(ParseResult.malformed, parse("", &back));
    const bad = try std.mem.replaceOwned(u8, testing.allocator, text, "sha256:", "sha512:");
    defer testing.allocator.free(bad);
    try testing.expectEqual(ParseResult.malformed, parse(bad, &back));
}
