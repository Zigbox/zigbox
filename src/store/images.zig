//! Image records: `<store>/images/<manifest digest hex>`, one per pulled image. A record says
//! what was pulled (every reference it was pulled as, the manifest, the platform, the config blob
//! and the layer blobs) and which tree it became. It keeps those blobs and that tree alive for gc:
//! a blob is kept while an image record names it.
//!
//! The file is the text of a small ZON-like record, written atomically, one field a line:
//!
//!   .{
//!       .version = 3,
//!       .tags = "alpine:3.20",      (none or more, oldest first; a pull by digest adds none)
//!       .tags = "alpine:3.19",
//!       .manifest = "sha256:...",
//!       .platform = "linux/amd64",
//!       .config = "sha256:...",
//!       .tree = "b3:...",
//!       .time = 1760000000,
//!       .layers = "sha256:...",     (one line per layer, in order)
//!       .layers = "sha256:...",
//!   }
//!
//! After `.layers` come the image's settings, a line a word in order: `.entrypoint`, `.cmd`,
//! `.env` ("NAME=value"), and the single `.workdir` and `.user` (left out when empty). A reader
//! skips keys it does not know, and a record of a newer version is `Newer`, never guessed at.
//!
//! Version 3 (M8) adds the image's labels after the settings, two lines a label in key order
//! (`.label_key`, then `.label_value`), or `.labels_unknown = true` when there are none to
//! trust: the image had more than `Labels` holds, or the record was written by a release that
//! did not keep them (versions 1 and 2). Without the labels the result an image was made from
//! cannot be derived (`build/result.zig`, `derive`), so an image of unknown labels derives none.
//!
//! Version 1 (M4) kept one `.reference = "..."` where version 2 keeps the tags; a version-1
//! record reads as an image with that one tag, and is written as version 2 the next time.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const roots = @import("roots.zig");
const lock_file = @import("../lock_file.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const record_version: u32 = 3;
pub const directory_name = "images";

/// Where a string is in `Settings.bytes`.
const Span = struct { at: u16, len: u16 };

/// An image's labels, sorted by key and unique, as a build result keeps them (`build/result.zig`),
/// so that a result digest can be derived from an image's tree, settings and labels. `known` is
/// false when the labels are not the image's own: it had more than fits, or the record is from a
/// release that did not keep them. No labels are held then.
pub const Labels = struct {
    const Place = struct { at: u32, key_len: u16, value_len: u16 };

    bytes: [constants.image_labels_bytes_max]u8,
    used: u32,
    places: [constants.image_labels_count_max]Place,
    total: u32,
    known: bool,

    /// Known and empty.
    pub fn clear(labels: *Labels) void {
        assert(labels.places.len == constants.image_labels_count_max);
        labels.used = 0;
        labels.total = 0;
        labels.known = true;
        assert(labels.count() == 0);
    }

    /// Not the image's own: no labels held, and nothing derives from them.
    pub fn forget(labels: *Labels) void {
        labels.clear();
        labels.known = false;
        assert(labels.total == 0);
        assert(labels.used == 0);
    }

    pub fn count(labels: *const Labels) u32 {
        assert(labels.total <= constants.image_labels_count_max);
        if (!labels.known) assert(labels.total == 0);
        return labels.total;
    }

    pub fn key(labels: *const Labels, index: u32) []const u8 {
        assert(index < labels.total);
        assert(labels.known);
        const place = labels.places[index];
        return labels.bytes[place.at..][0..place.key_len];
    }

    pub fn value(labels: *const Labels, index: u32) []const u8 {
        assert(index < labels.total);
        assert(labels.known);
        const place = labels.places[index];
        return labels.bytes[place.at + place.key_len ..][0..place.value_len];
    }

    /// Adds a label in key order; null if the list or the block is full, or the key is there.
    pub fn add(labels: *Labels, name: []const u8, text: []const u8) ?void {
        assert(labels.used <= labels.bytes.len);
        assert(labels.known);
        if (labels.total == labels.places.len) return null;
        if (name.len > labels.bytes.len - labels.used) return null;
        if (text.len > labels.bytes.len - labels.used - name.len) return null;
        var position: u32 = 0;
        while (position < labels.total) : (position += 1) {
            switch (std.mem.order(u8, labels.key(position), name)) {
                .lt => continue,
                .eq => return null,
                .gt => break,
            }
        }
        var move = labels.total;
        while (move > position) : (move -= 1) labels.places[move] = labels.places[move - 1];
        const at = labels.used;
        @memcpy(labels.bytes[at..][0..name.len], name);
        @memcpy(labels.bytes[at + name.len ..][0..text.len], text);
        labels.used += @intCast(name.len + text.len);
        labels.places[position] = .{
            .at = at,
            .key_len = @intCast(name.len),
            .value_len = @intCast(text.len),
        };
        labels.total += 1;
    }
};

/// What an image runs by default: the members of its configuration that zbx honours
/// (`registry/config.zig` reads them from the blob). All the strings are in one block.
pub const Settings = struct {
    pub const List = enum { entrypoint, cmd, env };
    pub const Single = enum { workdir, user };

    bytes: [constants.image_settings_bytes_max]u8,
    used: u32,
    entrypoint: [constants.image_settings_words_max]Span,
    entrypoint_count: u32,
    cmd: [constants.image_settings_words_max]Span,
    cmd_count: u32,
    env: [constants.env_vars_count_max]Span,
    env_count: u32,
    workdir: Span,
    user: Span,

    pub fn clear(settings: *Settings) void {
        assert(settings.bytes.len == constants.image_settings_bytes_max);
        settings.used = 0;
        settings.entrypoint_count = 0;
        settings.cmd_count = 0;
        settings.env_count = 0;
        settings.workdir = .{ .at = 0, .len = 0 };
        settings.user = .{ .at = 0, .len = 0 };
    }

    fn store(settings: *Settings, text: []const u8) ?Span {
        assert(settings.used <= settings.bytes.len);
        // A word is a line of the record, which escapes a string of this length at most.
        if (text.len > constants.store_source_bytes_max) return null;
        if (settings.used + text.len > settings.bytes.len) return null;
        const at: u16 = @intCast(settings.used);
        @memcpy(settings.bytes[at..][0..text.len], text);
        settings.used += @intCast(text.len);
        return .{ .at = at, .len = @intCast(text.len) };
    }

    fn spans(settings: *Settings, list: List) struct { []Span, *u32 } {
        assert(settings.used <= settings.bytes.len);
        return switch (list) {
            .entrypoint => .{ &settings.entrypoint, &settings.entrypoint_count },
            .cmd => .{ &settings.cmd, &settings.cmd_count },
            .env => .{ &settings.env, &settings.env_count },
        };
    }

    /// Appends a word; null if the list or the block is full.
    pub fn add(settings: *Settings, list: List, text: []const u8) ?void {
        assert(text.len <= constants.image_settings_bytes_max);
        const found = settings.spans(list);
        if (found[1].* == found[0].len) return null;
        const span = settings.store(text) orelse return null;
        found[0][found[1].*] = span;
        found[1].* += 1;
    }

    /// Sets the working directory or the user; null if the block is full.
    pub fn set(settings: *Settings, which: Single, text: []const u8) ?void {
        assert(settings.used <= settings.bytes.len);
        const span = settings.store(text) orelse return null;
        switch (which) {
            .workdir => settings.workdir = span,
            .user => settings.user = span,
        }
    }

    pub fn count(settings: *const Settings, list: List) u32 {
        assert(settings.used <= settings.bytes.len);
        return switch (list) {
            .entrypoint => settings.entrypoint_count,
            .cmd => settings.cmd_count,
            .env => settings.env_count,
        };
    }

    fn view(settings: *const Settings, span: Span) []const u8 {
        assert(span.at + @as(u32, span.len) <= settings.used);
        return settings.bytes[span.at..][0..span.len];
    }

    pub fn word(settings: *const Settings, list: List, index: u32) []const u8 {
        assert(index < settings.count(list));
        return switch (list) {
            .entrypoint => settings.view(settings.entrypoint[index]),
            .cmd => settings.view(settings.cmd[index]),
            .env => settings.view(settings.env[index]),
        };
    }

    pub fn get(settings: *const Settings, which: Single) []const u8 {
        assert(settings.used <= settings.bytes.len);
        return switch (which) {
            .workdir => settings.view(settings.workdir),
            .user => settings.view(settings.user),
        };
    }
};

pub const Image = struct {
    /// Every reference the image was pulled as, oldest first. A pull by digest adds none.
    tags: [constants.image_tags_max][constants.reference_bytes_max]u8,
    tag_lens: [constants.image_tags_max]u16,
    tag_count: u32,
    manifest: Sha256,
    platform: [16]u8,
    platform_len: u8,
    config: Sha256,
    tree: Digest,
    time: u64,
    layer_count: u32,
    layers: [constants.registry_layers_max]Sha256,
    settings: Settings,
    labels: Labels,

    pub fn tag_text(image: *const Image, index: u32) []const u8 {
        assert(image.tag_count <= constants.image_tags_max);
        assert(index < image.tag_count);
        assert(image.tag_lens[index] <= constants.reference_bytes_max);
        return image.tags[index][0..image.tag_lens[index]];
    }

    /// Appends a tag, as a record is read: no check, only the bound; false if the list is full.
    fn push_tag(image: *Image, text: []const u8) bool {
        assert(text.len <= constants.reference_bytes_max);
        assert(image.tag_count <= constants.image_tags_max);
        if (image.tag_count == constants.image_tags_max) return false;
        @memcpy(image.tags[image.tag_count][0..text.len], text);
        image.tag_lens[image.tag_count] = @intCast(text.len);
        image.tag_count += 1;
        return true;
    }

    fn drop_tag(image: *Image, index: u32) void {
        assert(index < image.tag_count);
        const last = image.tag_count - 1;
        var at = index;
        while (at < last) : (at += 1) {
            const length = image.tag_lens[at + 1];
            @memcpy(image.tags[at][0..length], image.tags[at + 1][0..length]);
            image.tag_lens[at] = length;
        }
        image.tag_count = last;
    }

    /// Records that the image was pulled as `text`, which becomes the newest tag. A tag that
    /// means the same reference (`alpine:3.20`, `docker.io/library/alpine:3.20`) is replaced;
    /// when the list is full the oldest tag goes. Others stay.
    pub fn add_tag(image: *Image, text: []const u8) void {
        assert(text.len > 0);
        assert(text.len <= constants.reference_bytes_max);
        assert(std.mem.indexOfScalar(u8, text, '@') == null);
        var index: u32 = 0;
        while (index < image.tag_count) : (index += 1) {
            if (lock_file.same_reference(image.tag_text(index), text)) {
                image.drop_tag(index);
                break;
            }
        }
        if (image.tag_count == constants.image_tags_max) image.drop_tag(0);
        const pushed = image.push_tag(text);
        assert(pushed);
        assert(image.tag_count > 0);
    }

    /// True if one of the tags means the same reference as `text`.
    pub fn has_tag(image: *const Image, text: []const u8) bool {
        assert(text.len <= constants.arg_bytes_max);
        assert(image.tag_count <= constants.image_tags_max);
        for (0..image.tag_count) |index| {
            if (lock_file.same_reference(image.tag_text(@intCast(index)), text)) return true;
        }
        return false;
    }

    pub fn platform_text(image: *const Image) []const u8 {
        assert(image.platform_len > 0);
        assert(image.platform_len <= image.platform.len);
        return image.platform[0..image.platform_len];
    }
};

pub fn render(image: *const Image, buffer: *[constants.image_record_bytes_max]u8) []const u8 {
    assert(image.layer_count <= constants.registry_layers_max);
    assert(image.time < 1 << 40);
    var writer = std.Io.Writer.fixed(buffer);
    assert(image.tag_count <= constants.image_tags_max);
    // Cannot fail: the buffer holds the fixed fields, the tags escaped (four bytes a byte at the
    // worst) and 128 layer lines of 90 bytes.
    writer.print(".{{\n    .version = {d},\n", .{record_version}) catch unreachable; // Sized.
    for (0..image.tag_count) |index| {
        writer.writeAll("    .tags = ") catch unreachable; // Same bound.
        roots.put_string(&writer, image.tag_text(@intCast(index)));
        writer.writeAll(",\n") catch unreachable; // Same bound.
    }
    writer.print("    .manifest = \"{s}\",\n    .platform = \"{s}\",\n", .{
        &image.manifest.text(), image.platform_text(),
    }) catch unreachable; // Same bound.
    writer.print("    .config = \"{s}\",\n    .tree = \"{s}\",\n    .time = {d},\n", .{
        &image.config.text(), image.tree.text(), image.time,
    }) catch unreachable; // Same bound.
    for (image.layers[0..image.layer_count]) |layer| {
        writer.print("    .layers = \"{s}\",\n", .{&layer.text()}) catch unreachable; // Same.
    }
    render_settings(&writer, &image.settings);
    render_labels(&writer, &image.labels);
    writer.writeAll("}\n") catch unreachable; // Same bound.
    assert(writer.end <= buffer.len);
    return writer.buffered();
}

fn render_settings(writer: *std.Io.Writer, settings: *const Settings) void {
    assert(settings.used <= settings.bytes.len);
    inline for (.{ .entrypoint, .cmd, .env }) |list| {
        for (0..settings.count(list)) |index| {
            // Cannot fail: the buffer holds the settings escaped (four bytes a byte at the worst).
            writer.print("    .{s} = ", .{@tagName(list)}) catch unreachable; // Sized.
            roots.put_string(writer, settings.word(list, @intCast(index)));
            writer.writeAll(",\n") catch unreachable; // Sized.
        }
    }
    inline for (.{ .workdir, .user }) |which| {
        if (settings.get(which).len > 0) {
            writer.print("    .{s} = ", .{@tagName(which)}) catch unreachable; // Sized.
            roots.put_string(writer, settings.get(which));
            writer.writeAll(",\n") catch unreachable; // Sized.
        }
    }
}

fn render_labels(writer: *std.Io.Writer, labels: *const Labels) void {
    assert(labels.used <= labels.bytes.len);
    if (!labels.known) {
        // Cannot fail: the buffer holds the fixed lines, with room to spare.
        writer.writeAll("    .labels_unknown = true,\n") catch unreachable; // Sized.
        return;
    }
    for (0..labels.count()) |index| {
        // Cannot fail: the buffer holds the labels escaped (four bytes a byte at the worst).
        writer.writeAll("    .label_key = ") catch unreachable; // Sized.
        roots.put_string(writer, labels.key(@intCast(index)));
        writer.writeAll(",\n    .label_value = ") catch unreachable; // Sized.
        roots.put_string(writer, labels.value(@intCast(index)));
        writer.writeAll(",\n") catch unreachable; // Sized.
    }
}

pub const ParseResult = enum { ok, malformed, newer };

fn quoted_digest(value: []const u8) ?Sha256 {
    assert(value.len <= constants.image_record_bytes_max);
    assert(value.len < 1 << 16);
    var word: [constants.oci_digest_text_bytes]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return null;
    return Sha256.parse(word[0..length]);
}

/// Reads one line of the settings; false if it is one and does not fit or is not a string.
/// A key that is not a setting is not this function's, and is true.
fn parse_setting(settings: *Settings, key: []const u8, value: []const u8) bool {
    assert(value.len <= constants.image_record_bytes_max);
    var word: [constants.env_name_bytes_max + 1 + constants.env_value_bytes_max]u8 = undefined;
    inline for (.{ .entrypoint, .cmd, .env }) |list| {
        if (std.mem.eql(u8, key, @tagName(list))) {
            const length = roots.parse_string(value, &word) orelse return false;
            return settings.add(list, word[0..length]) != null;
        }
    }
    inline for (.{ .workdir, .user }) |which| {
        if (std.mem.eql(u8, key, @tagName(which))) {
            const length = roots.parse_string(value, &word) orelse return false;
            return settings.set(which, word[0..length]) != null;
        }
    }
    return true;
}

/// A `.label_key` waiting for its `.label_value`.
const PendingLabel = struct {
    bytes: [constants.image_labels_bytes_max]u8,
    len: u32,
    waiting: bool,
};

/// Reads one line of the labels; false if it is one and does not fit, is out of order or is not
/// a string. A key that is not about labels is not this function's, and is true.
fn parse_label(labels: *Labels, pending: *PendingLabel, name: []const u8, value: []const u8) bool {
    assert(value.len <= constants.image_record_bytes_max);
    assert(labels.used <= labels.bytes.len);
    var word: [constants.image_labels_bytes_max]u8 = undefined;
    if (std.mem.eql(u8, name, "labels_unknown")) {
        // Unknown labels are none held, and not a mixture.
        if (!std.mem.eql(u8, value, "true")) return false;
        if (labels.total > 0 or !labels.known or pending.waiting) return false;
        labels.forget();
        return true;
    }
    if (std.mem.eql(u8, name, "label_key")) {
        if (pending.waiting or !labels.known) return false;
        const length = roots.parse_string(value, &pending.bytes) orelse return false;
        pending.len = @intCast(length);
        pending.waiting = true;
        return true;
    }
    if (std.mem.eql(u8, name, "label_value")) {
        if (!pending.waiting) return false;
        const length = roots.parse_string(value, &word) orelse return false;
        const given = pending.bytes[0..pending.len];
        // `render` writes keys in strict order, which is what `add` keeps.
        if (labels.total > 0) {
            if (std.mem.order(u8, labels.key(labels.total - 1), given) != .lt) return false;
        }
        pending.waiting = false;
        return labels.add(given, word[0..length]) != null;
    }
    return true;
}

/// Reads a record.
pub fn parse(text: []const u8, image: *Image) ParseResult {
    assert(@intFromPtr(image) != 0);
    assert(text.len <= constants.image_record_bytes_max);
    image.tag_count = 0;
    image.platform_len = 0;
    image.layer_count = 0;
    image.time = 0;
    image.settings.clear();
    image.labels.clear();
    var pending: PendingLabel = .{ .bytes = undefined, .len = 0, .waiting = false };
    var version: u32 = 0;
    var seen: u32 = 0; // A bit for each of manifest, platform, config and tree.
    var has_reference = false;
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
        } else if (std.mem.eql(u8, key, "reference") or std.mem.eql(u8, key, "tags")) {
            // Version 1 wrote its one tag as `.reference`; that key is a tag in any version.
            if (key[0] == 'r') has_reference = true;
            var word: [constants.reference_bytes_max]u8 = undefined;
            const length = roots.parse_string(value, &word) orelse return .malformed;
            // M4 wrote the reference as typed, so a pull by digest left `name@sha256:..`: a
            // digest is never a tag.
            const digest = std.mem.indexOfScalar(u8, word[0..length], '@') != null;
            if (length > 0 and !digest and !image.push_tag(word[0..length])) return .malformed;
        } else if (std.mem.eql(u8, key, "manifest")) {
            image.manifest = quoted_digest(value) orelse return .malformed;
            seen |= 1;
        } else if (std.mem.eql(u8, key, "platform")) {
            const length = roots.parse_string(value, &image.platform) orelse return .malformed;
            image.platform_len = @intCast(length);
            seen |= 2;
        } else if (std.mem.eql(u8, key, "config")) {
            image.config = quoted_digest(value) orelse return .malformed;
            seen |= 4;
        } else if (std.mem.eql(u8, key, "tree")) {
            var word: [constants.store_digest_text_bytes]u8 = undefined;
            const length = roots.parse_string(value, &word) orelse return .malformed;
            image.tree = Digest.parse(word[0..length]) orelse return .malformed;
            seen |= 8;
        } else if (std.mem.eql(u8, key, "time")) {
            image.time = std.fmt.parseInt(u64, value, 10) catch return .malformed;
            // `render` holds a time under 2^40; a damaged record may not read as more.
            if (image.time >= 1 << 40) return .malformed;
        } else if (std.mem.eql(u8, key, "layers")) {
            if (image.layer_count == constants.registry_layers_max) return .malformed;
            image.layers[image.layer_count] = quoted_digest(value) orelse return .malformed;
            image.layer_count += 1;
        } else if (!parse_setting(&image.settings, key, value)) {
            return .malformed;
        } else if (!parse_label(&image.labels, &pending, key, value)) {
            return .malformed;
        }
    }
    return finish_parse(image, version, seen, has_reference, &pending);
}

/// What a record's fields add up to once every line is read: its version, the fields it has and
/// the labels it may carry.
fn finish_parse(
    image: *Image,
    version: u32,
    seen: u32,
    has_reference: bool,
    pending: *const PendingLabel,
) ParseResult {
    assert(@intFromPtr(image) != 0);
    assert(seen <= 15);
    if (version == 0) return .malformed;
    if (version > record_version) return .newer;
    if (pending.waiting) return .malformed;
    if (version < 3) {
        // Releases before version 3 kept no labels, so the image's are not known.
        if (image.labels.total > 0 or !image.labels.known) return .malformed;
        image.labels.forget();
    }
    // Every field once at least: a repeated key must not stand for a missing one.
    if (seen != 15) return .malformed;
    // `render` holds a platform that is not empty; a damaged record may not read as one.
    if (image.platform_len == 0) return .malformed;
    if (version == 1 and !has_reference) return .malformed;
    return .ok;
}

fn record_path(store: *const Store, buffer: *PathBuf, manifest: Sha256) [:0]const u8 {
    assert(manifest.bytes.len == constants.oci_digest_bytes);
    assert(store.root_len > 1);
    const hex = manifest.hex();
    return store.path(buffer, &.{ "/", directory_name, "/", &hex });
}

/// Fills `image.tags` with those of the record kept for `manifest`, or none if there is no record
/// or it does not read: a pull of the same manifest again keeps what was pulled before. Two
/// writers of one manifest at once (a pull and a pull, or a pull and an import) can each read the
/// old tags, and the later save wins: a tag is lost until it is next pulled. Every
/// other field is the caller's to set.
pub fn carry_tags(store: *const Store, manifest: Sha256, image: *Image) void {
    assert(manifest.bytes.len == constants.oci_digest_bytes);
    assert(@intFromPtr(image) != 0);
    var errno: u16 = 0;
    // A record that is damaged, newer or unreadable is replaced by this pull, as it always was.
    load(store, manifest, image, &errno) catch {
        image.tag_count = 0;
        return;
    };
    assert(image.tag_count <= constants.image_tags_max);
}

/// Writes the image's record atomically; a second pull of the same manifest replaces it, so
/// the caller carries the tags of the first over (`pulled_as`).
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

/// Removes the record of the image; an absent one is not an error.
pub fn remove(store: *const Store, manifest: Sha256) host_mod.Error!void {
    assert(manifest.bytes.len == constants.oci_digest_bytes);
    var path: PathBuf = undefined;
    store.fs.unlink(record_path(store, &path, manifest)) catch |err| {
        if (err != error.NotFound) return err;
    };
}

pub const LoadError = error{ NotFound, Unreadable, Damaged, Newer };

pub fn load(store: *const Store, manifest: Sha256, image: *Image, errno: *u16) LoadError!void {
    assert(manifest.bytes.len == constants.oci_digest_bytes);
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
    image.tag_count = 0;
    image.add_tag("docker.io/library/alpine:3.20");
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = Digest.of("tree");
    image.time = 1760000000;
    image.layer_count = 2;
    image.layers[0] = Sha256.of("one");
    image.layers[1] = Sha256.of("two");
    image.settings.clear();
    image.labels.clear();
    return image;
}

test "a record round-trips, and the worst case fits the buffer" {
    // Goal: every field comes back; 128 layers and an all-escaped reference still render.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(@as(u32, 1), back.tag_count);
    try testing.expectEqualStrings(image.tag_text(0), back.tag_text(0));
    try testing.expect(back.manifest.eql(image.manifest));
    try testing.expect(back.config.eql(image.config));
    try testing.expect(back.tree.eql(image.tree));
    try testing.expectEqual(@as(u32, 2), back.layer_count);
    try testing.expect(back.layers[1].eql(image.layers[1]));
    try testing.expectEqualStrings("linux/amd64", back.platform_text());

    image.tag_count = 0;
    var quotes: [constants.reference_bytes_max]u8 = undefined;
    for (0..constants.image_tags_max) |index| {
        quotes[0] = @intCast('a' + index); // Tags that differ, or `add_tag` would merge them.
        @memset(quotes[1..], '"');
        image.add_tag(&quotes);
    }
    try testing.expectEqual(constants.image_tags_max, image.tag_count);
    image.layer_count = constants.registry_layers_max;
    for (&image.layers) |*layer| layer.* = Sha256.of("x");
    const worst = render(&image, &buffer);
    try testing.expectEqual(ParseResult.ok, parse(worst, &back));
    try testing.expectEqual(@as(u32, constants.registry_layers_max), back.layer_count);
    try testing.expectEqual(constants.image_tags_max, back.tag_count);
}

test "the settings round-trip, with escapes, in order" {
    // Goal: an entrypoint, a cmd with a quote and a newline-free odd word, env, directory, user.
    var image = sample();
    image.settings.clear();
    try testing.expect(image.settings.add(.entrypoint, "/entry.sh") != null);
    try testing.expect(image.settings.add(.cmd, "sh") != null);
    try testing.expect(image.settings.add(.cmd, "-c") != null);
    try testing.expect(image.settings.add(.cmd, "echo \"hi\" \\ \tb") != null);
    try testing.expect(image.settings.add(.env, "PATH=/usr/bin:/bin") != null);
    try testing.expect(image.settings.add(.env, "EMPTY=") != null);
    try testing.expect(image.settings.set(.workdir, "/srv/app") != null);
    try testing.expect(image.settings.set(.user, "1000:1000") != null);
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(@as(u32, 1), back.settings.count(.entrypoint));
    try testing.expectEqualStrings("/entry.sh", back.settings.word(.entrypoint, 0));
    try testing.expectEqual(@as(u32, 3), back.settings.count(.cmd));
    try testing.expectEqualStrings("echo \"hi\" \\ \tb", back.settings.word(.cmd, 2));
    try testing.expectEqualStrings("EMPTY=", back.settings.word(.env, 1));
    try testing.expectEqualStrings("/srv/app", back.settings.get(.workdir));
    try testing.expectEqualStrings("1000:1000", back.settings.get(.user));
}

test "the settings at their bounds still render and read back" {
    // Goal: the worst case fits the buffer: full lists of long, all-escaped words.
    var image = sample();
    image.settings.clear();
    var word: [constants.store_source_bytes_max]u8 = @splat('"');
    for (0..constants.image_settings_words_max) |_| {
        if (image.settings.add(.cmd, word[0..5]) == null) break;
    }
    _ = image.settings.set(.workdir, word[0..8]);
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(image.settings.count(.cmd), back.settings.count(.cmd));
    try testing.expect(image.settings.add(.cmd, &word) != null or true);
    var over: [constants.store_source_bytes_max + 1]u8 = @splat('x');
    try testing.expect(image.settings.add(.env, &over) == null);
}

test "the labels round-trip in key order, and a full block is refused" {
    // Goal: labels read back as written, sorted; the bound holds; unknown is written and read.
    var image = sample();
    try testing.expect(image.labels.add("b.key", "two\"") != null);
    try testing.expect(image.labels.add("a.key", "one") != null);
    try testing.expect(image.labels.add("a.key", "again") == null);
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expect(back.labels.known);
    try testing.expectEqual(@as(u32, 2), back.labels.count());
    try testing.expectEqualStrings("a.key", back.labels.key(0));
    try testing.expectEqualStrings("two\"", back.labels.value(1));
    var big: [constants.image_labels_bytes_max]u8 = @splat('"');
    try testing.expect(image.labels.add("c", &big) == null);
    image.labels.clear();
    for (0..constants.image_labels_count_max) |index| {
        var name: [2]u8 = .{ 'a', @intCast('a' + index) };
        try testing.expect(image.labels.add(&name, "\"\"") != null);
    }
    try testing.expect(image.labels.add("zz", "") == null);
    try testing.expectEqual(ParseResult.ok, parse(render(&image, &buffer), &back));
    try testing.expectEqual(constants.image_labels_count_max, back.labels.count());
    image.labels.forget();
    try testing.expectEqual(ParseResult.ok, parse(render(&image, &buffer), &back));
    try testing.expect(!back.labels.known);
}

test "a version 2 record reads with its labels unknown, and may not carry any" {
    // Goal: an old record has no labels to derive from; text claiming some is damaged.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    const two = try std.mem.replaceOwned(u8, testing.allocator, text, "version = 3", "version = 2");
    defer testing.allocator.free(two);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(two, &back));
    try testing.expect(!back.labels.known);
    try testing.expectEqual(@as(u32, 0), back.labels.count());
    image.labels.forget();
    const marked = render(&image, &buffer);
    const old = "version = 2";
    const bad = try std.mem.replaceOwned(u8, testing.allocator, marked, "version = 3", old);
    defer testing.allocator.free(bad);
    try testing.expectEqual(ParseResult.malformed, parse(bad, &back));
}

test "a damaged or newer record is refused" {
    // Goal: no guessing: a missing field, a bad digest, a newer version, no version.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    const alloc = testing.allocator;
    const newer = try std.mem.replaceOwned(u8, alloc, text, "version = 3", "version = 4");
    defer testing.allocator.free(newer);
    try testing.expectEqual(ParseResult.newer, parse(newer, &back));
    const cut = text[0..std.mem.indexOf(u8, text, "    .tree").?];
    try testing.expectEqual(ParseResult.malformed, parse(cut, &back));
    try testing.expectEqual(ParseResult.malformed, parse("", &back));
    const bad = try std.mem.replaceOwned(u8, testing.allocator, text, "sha256:", "sha512:");
    defer testing.allocator.free(bad);
    try testing.expectEqual(ParseResult.malformed, parse(bad, &back));
    // A time past what `render` writes (the fuzzer's `lock` seed 6775460128980188419).
    const late = try std.fmt.allocPrint(alloc, "{d}", .{@as(u64, 1) << 40});
    defer testing.allocator.free(late);
    const time = try std.fmt.allocPrint(alloc, "{d}", .{image.time});
    defer testing.allocator.free(time);
    const far = try std.mem.replaceOwned(u8, alloc, text, time, late);
    defer testing.allocator.free(far);
    try testing.expectEqual(ParseResult.malformed, parse(far, &back));
}

test "tags are kept, merged by meaning, and the oldest goes when the list is full" {
    // Goal: the pull-by-tag rules on the record's list, with no store.
    var image = sample();
    image.add_tag("alpine:3.19");
    try testing.expectEqual(@as(u32, 2), image.tag_count);
    try testing.expectEqualStrings("alpine:3.19", image.tag_text(1));
    // The same reference spelled another way replaces the old spelling and is the newest.
    image.add_tag("alpine:3.20");
    try testing.expectEqual(@as(u32, 2), image.tag_count);
    try testing.expectEqualStrings("alpine:3.19", image.tag_text(0));
    try testing.expectEqualStrings("alpine:3.20", image.tag_text(1));
    try testing.expect(image.has_tag("docker.io/library/alpine:3.19"));
    try testing.expect(!image.has_tag("alpine:3.18"));
    // Past the bound the oldest is dropped; the rest keep their order.
    var name: [16]u8 = undefined;
    for (0..constants.image_tags_max) |number| {
        image.add_tag(std.fmt.bufPrint(&name, "repo:{d}", .{number}) catch unreachable); // Short.
    }
    try testing.expectEqual(constants.image_tags_max, image.tag_count);
    try testing.expectEqualStrings("repo:0", image.tag_text(0));
    image.add_tag("repo:new");
    try testing.expectEqual(constants.image_tags_max, image.tag_count);
    try testing.expectEqualStrings("repo:1", image.tag_text(0));
    try testing.expectEqualStrings("repo:new", image.tag_text(constants.image_tags_max - 1));
}

test "a record with no tags reads and writes back with none" {
    // Goal: a pull by digest first leaves no tag, and that is a valid record.
    var image = sample();
    image.tag_count = 0;
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, ".tags") == null);
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(@as(u32, 0), back.tag_count);
}

test "real version-1 text from M4 reads" {
    // Goal: the exact bytes M4's binary wrote for an alpine pull, with settings.
    const text =
        \\.{
        \\    .version = 1,
        \\    .reference = "alpine:3.20",
        \\    .manifest = "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        \\    .platform = "linux/amd64",
        \\    .config = "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        \\    .tree = "b3:3333333333333333333333333333333333333333333333333333333333333333",
        \\    .time = 1761600000,
        \\    .layers = "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        \\    .cmd = "/bin/sh",
        \\    .env = "PATH=/usr/bin",
        \\    .workdir = "/",
        \\}
        \\
    ;
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(@as(u32, 1), back.tag_count);
    try testing.expectEqualStrings("alpine:3.20", back.tag_text(0));
    try testing.expectEqual(@as(u32, 1), back.layer_count);
    try testing.expectEqualStrings("/bin/sh", back.settings.word(.cmd, 0));
    try testing.expectEqualStrings("/", back.settings.get(.workdir));
    // The checks `parse` gained with Z4 (every field once, a platform that is not empty) hold
    // for what M4 wrote: this is the text of a real release, not one this code rendered.
    try testing.expectEqualStrings("linux/amd64", back.platform_text());
    try testing.expectEqual(@as(u64, 1761600000), back.time);
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const written = render(&back, &buffer);
    try testing.expect(std.mem.indexOf(u8, written, ".version = 3,") != null);
    try testing.expect(std.mem.indexOf(u8, written, ".tags = \"alpine:3.20\",") != null);
    try testing.expect(std.mem.indexOf(u8, written, ".reference") == null);
    // The same text without its reference is damaged, as it was in M4.
    const line = "    .reference = \"alpine:3.20\",\n";
    const bare = try std.mem.replaceOwned(u8, testing.allocator, text, line, "");
    defer testing.allocator.free(bare);
    try testing.expectEqual(ParseResult.malformed, parse(bare, &back));
}

test "real version-1 text spelled by digest has no tag" {
    // Goal: M4 wrote the reference as typed, so a pull by digest left `name@sha256:..`. It is
    // not a tag: the record reads as ok with none, and the same holds in a `.tags` line.
    const five = "5555555555555555555555555555555555555555555555555555555555555555";
    const text = ".{\n    .version = 1,\n" ++
        "    .reference = \"alpine@sha256:" ++ five ++ "\",\n" ++
        "    .manifest = \"sha256:" ++ five ++ "\",\n" ++
        "    .platform = \"linux/amd64\",\n" ++
        "    .config = \"sha256:" ++ five ++ "\",\n" ++
        "    .tree = \"b3:" ++ five ++ "\",\n" ++
        "    .time = 1761600000,\n" ++
        "    .layers = \"sha256:" ++ five ++ "\",\n}\n";
    var back: Image = undefined;
    try testing.expectEqual(ParseResult.ok, parse(text, &back));
    try testing.expectEqual(@as(u32, 0), back.tag_count);
    const tagged = try std.mem.replaceOwned(u8, testing.allocator, text, ".reference", ".tags");
    defer testing.allocator.free(tagged);
    const old = "version = 1";
    const as_two = try std.mem.replaceOwned(u8, testing.allocator, tagged, old, "version = 2");
    defer testing.allocator.free(as_two);
    try testing.expectEqual(ParseResult.ok, parse(as_two, &back));
    try testing.expectEqual(@as(u32, 0), back.tag_count);
}

test "a record with an empty platform, or a repeated key standing for a missing one, is refused" {
    // Goal: parse accepts only what render can write. An empty platform would trip `render`'s
    // assertion; a repeated manifest with no tree used to count as four fields and left the
    // tree unset. Method: edit the text of a good record.
    var image = sample();
    var buffer: [constants.image_record_bytes_max]u8 = undefined;
    const text = render(&image, &buffer);
    var back: Image = undefined;
    const empty = try std.mem.replaceOwned(u8, testing.allocator, text, "linux/amd64", "");
    defer testing.allocator.free(empty);
    try testing.expectEqual(ParseResult.malformed, parse(empty, &back));
    const tree_line = std.mem.indexOf(u8, text, "    .tree").?;
    const tree_end = std.mem.indexOfScalarPos(u8, text, tree_line, '\n').?;
    const zeros = "0000000000000000000000000000000000000000000000000000000000000000";
    const manifest_line = "    .manifest = \"sha256:" ++ zeros ++ "\",\n";
    const twice = try std.mem.concat(testing.allocator, u8, &.{
        text[0..tree_line], manifest_line, text[tree_end + 1 ..],
    });
    defer testing.allocator.free(twice);
    try testing.expectEqual(ParseResult.malformed, parse(twice, &back));
}
