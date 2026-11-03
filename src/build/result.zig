//! The build record (docs/briefs/M7-build.md, "The result"): the tree a build made and the
//! config it runs with, `build/results/<result digest hex>` in the store. **The result digest**
//! is BLAKE3 over the record's bytes, so the same tree with another entrypoint is another result.
//!
//! The bytes (little-endian; `encode` writes exactly this and `parse` accepts nothing else):
//!
//!   "zbx-build-result\0"  17 bytes, the magic
//!   version               u32, 1
//!   tree                  32 bytes, the image tree's digest
//!   entrypoint, cmd, env  each a u32 count and that many strings
//!   workdir, user         a string each (empty: not set)
//!   labels                a u32 count and that many (key, value) string pairs, sorted by key
//!
//! A string is a u32 length and its bytes. Nothing follows. Nothing from the clock, the host or
//! git is in it (the brief's reproducibility rule).
//!
//! The resolved config is the base image's, field by field, under the build file's `image.config`:
//! `entrypoint` and `cmd` are replaced when given (an empty list given clears the base's),
//! `workdir` and `user` are replaced when given, and `env` is the base's without the names the
//! file sets, then the file's, in order. The base has no labels in zbx's image record, so a
//! result's labels are the file's.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const images = @import("../store/images.zig");
const layout = @import("../store/layout.zig");
const file_mod = @import("file.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;
const Settings = images.Settings;

pub const magic = "zbx-build-result\x00";
pub const record_version: u32 = 1;
pub const directory_name = layout.build_results_directory;

/// Where a label's key and value are in `Config.label_bytes`: the key, then the value.
const LabelSpan = struct { at: u32, key_len: u16, value_len: u16 };

/// A result's config: the settings a container starts from, and the labels.
pub const Config = struct {
    settings: Settings,
    label_bytes: [constants.build_result_label_bytes_max]u8,
    label_used: u32,
    labels: [constants.build_config_labels_max]LabelSpan,
    labels_count: u32,

    pub fn clear(config: *Config) void {
        config.settings.clear();
        config.label_used = 0;
        config.labels_count = 0;
    }

    pub fn label_key(config: *const Config, index: u32) []const u8 {
        assert(index < config.labels_count);
        const span = config.labels[index];
        return config.label_bytes[span.at..][0..span.key_len];
    }

    pub fn label_value(config: *const Config, index: u32) []const u8 {
        assert(index < config.labels_count);
        const span = config.labels[index];
        return config.label_bytes[span.at + span.key_len ..][0..span.value_len];
    }

    /// Adds a label in key order; null if the list or the block is full, or the key is there.
    pub fn add_label(config: *Config, key: []const u8, value: []const u8) ?void {
        assert(config.label_used <= config.label_bytes.len);
        assert(config.labels_count <= config.labels.len);
        if (config.labels_count == config.labels.len) return null;
        if (key.len > std.math.maxInt(u16) or value.len > std.math.maxInt(u16)) return null;
        if (key.len + value.len > config.label_bytes.len - config.label_used) return null;
        var position: u32 = 0;
        while (position < config.labels_count) : (position += 1) {
            switch (std.mem.order(u8, config.label_key(position), key)) {
                .lt => continue,
                .eq => return null,
                .gt => break,
            }
        }
        var move = config.labels_count;
        while (move > position) : (move -= 1) config.labels[move] = config.labels[move - 1];
        const at = config.label_used;
        @memcpy(config.label_bytes[at..][0..key.len], key);
        @memcpy(config.label_bytes[at + key.len ..][0..value.len], value);
        config.label_used += @intCast(key.len + value.len);
        config.labels[position] = .{
            .at = at,
            .key_len = @intCast(key.len),
            .value_len = @intCast(value.len),
        };
        config.labels_count += 1;
    }
};

pub const Record = struct {
    tree: Digest,
    config: Config,
};

/// Why a config cannot be resolved: a field that does not fit its block.
pub const Refusal = enum { entrypoint, cmd, env, workdir, user, labels };

fn env_name_is(entry: []const u8, other: []const u8) bool {
    const left = std.mem.indexOfScalar(u8, entry, '=') orelse entry.len;
    const right = std.mem.indexOfScalar(u8, other, '=') orelse other.len;
    return std.mem.eql(u8, entry[0..left], other[0..right]);
}

fn copy_list(
    out: *Settings,
    list: Settings.List,
    base: *const Settings,
    given: ?[]const file_mod.Text,
    file: *const file_mod.BuildFile,
) ?void {
    assert(list != .env);
    if (given) |texts| {
        for (texts) |text| out.add(list, file.text(text)) orelse return null;
        return;
    }
    for (0..base.count(list)) |at| out.add(list, base.word(list, @intCast(at))) orelse return null;
}

fn merge_env(
    out: *Settings,
    base: *const Settings,
    file: *const file_mod.BuildFile,
) ?void {
    const mine = file.image.config.env.slice();
    for (0..base.count(.env)) |at| {
        const entry = base.word(.env, @intCast(at));
        const replaced = for (mine) |text| {
            if (env_name_is(entry, file.text(text))) break true;
        } else false;
        if (!replaced) out.add(.env, entry) orelse return null;
    }
    for (mine) |text| out.add(.env, file.text(text)) orelse return null;
}

/// Resolves the config of an image from its base's settings and the build file's `image.config`.
/// Null if it resolved; otherwise the field that did not fit.
pub fn resolve(
    base: *const Settings,
    file: *const file_mod.BuildFile,
    out: *Config,
) ?Refusal {
    const config = &file.image.config;
    out.clear();
    const entrypoint = if (config.entrypoint.given) config.entrypoint.slice() else null;
    const cmd = if (config.cmd.given) config.cmd.slice() else null;
    copy_list(&out.settings, .entrypoint, base, entrypoint, file) orelse return .entrypoint;
    copy_list(&out.settings, .cmd, base, cmd, file) orelse return .cmd;
    merge_env(&out.settings, base, file) orelse return .env;
    const workdir = if (config.workdir) |text| file.text(text) else base.get(.workdir);
    const user = if (config.user) |text| file.text(text) else base.get(.user);
    out.settings.set(.workdir, workdir) orelse return .workdir;
    out.settings.set(.user, user) orelse return .user;
    for (file.labels_slice()) |label| {
        out.add_label(file.text(label.key), file.text(label.value)) orelse return .labels;
    }
    return null;
}

// ---- The bytes --------------------------------------------------------------------------------

const Encoder = struct {
    out: []u8,
    len: u32,

    fn bytes(encoder: *Encoder, data: []const u8) error{TooLarge}!void {
        assert(encoder.len <= encoder.out.len);
        if (data.len > encoder.out.len - encoder.len) return error.TooLarge;
        @memcpy(encoder.out[encoder.len..][0..data.len], data);
        encoder.len += @intCast(data.len);
    }

    fn int(encoder: *Encoder, value: u32) error{TooLarge}!void {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, value, .little);
        try encoder.bytes(&word);
    }

    fn string(encoder: *Encoder, text: []const u8) error{TooLarge}!void {
        assert(text.len <= std.math.maxInt(u32));
        try encoder.int(@intCast(text.len));
        try encoder.bytes(text);
    }

    fn list(encoder: *Encoder, settings: *const Settings, which: Settings.List) !void {
        const count = settings.count(which);
        try encoder.int(count);
        for (0..count) |at| try encoder.string(settings.word(which, @intCast(at)));
    }
};

/// The record's bytes in `buffer`; `TooLarge` only for a config past the bounds of the file.
pub fn encode(record: *const Record, buffer: []u8) error{TooLarge}![]const u8 {
    assert(buffer.len >= magic.len + 4 + constants.store_digest_bytes);
    var encoder: Encoder = .{ .out = buffer, .len = 0 };
    try encoder.bytes(magic);
    try encoder.int(record_version);
    try encoder.bytes(&record.tree.bytes);
    const settings = &record.config.settings;
    try encoder.list(settings, .entrypoint);
    try encoder.list(settings, .cmd);
    try encoder.list(settings, .env);
    try encoder.string(settings.get(.workdir));
    try encoder.string(settings.get(.user));
    try encoder.int(record.config.labels_count);
    for (0..record.config.labels_count) |at| {
        try encoder.string(record.config.label_key(@intCast(at)));
        try encoder.string(record.config.label_value(@intCast(at)));
    }
    return buffer[0..encoder.len];
}

/// The result digest of a record: BLAKE3 over its bytes.
pub fn result_digest(bytes: []const u8) Digest {
    assert(bytes.len >= magic.len);
    assert(bytes.len <= constants.build_result_bytes_max);
    return Digest.of(bytes);
}

pub const ParseResult = enum { ok, malformed, newer };

const Reader = struct {
    data: []const u8,
    at: u32,

    fn take(reader: *Reader, length: usize) ?[]const u8 {
        assert(reader.at <= reader.data.len);
        if (length > reader.data.len - reader.at) return null;
        const slice = reader.data[reader.at..][0..length];
        reader.at += @intCast(length);
        return slice;
    }

    fn int(reader: *Reader) ?u32 {
        const slice = reader.take(4) orelse return null;
        return std.mem.readInt(u32, slice[0..4], .little);
    }

    fn string(reader: *Reader) ?[]const u8 {
        const length = reader.int() orelse return null;
        return reader.take(length);
    }

    fn words(reader: *Reader, settings: *Settings, which: Settings.List) ?void {
        const count = reader.int() orelse return null;
        if (count > constants.image_settings_words_max) return null;
        for (0..count) |_| {
            const text = reader.string() orelse return null;
            settings.add(which, text) orelse return null;
        }
    }
};

/// Parses a record; anything but exactly what `encode` writes is `malformed`, and a record of a
/// newer version is `newer`. A parsed record re-encodes to the same bytes.
pub fn parse(bytes: []const u8, record: *Record) ParseResult {
    assert(bytes.len <= std.math.maxInt(u32));
    record.config.clear();
    var reader: Reader = .{ .data = bytes, .at = 0 };
    const head = reader.take(magic.len) orelse return .malformed;
    if (!std.mem.eql(u8, head, magic)) return .malformed;
    const version = reader.int() orelse return .malformed;
    if (version > record_version) return .newer;
    if (version != record_version) return .malformed;
    const tree = reader.take(constants.store_digest_bytes) orelse return .malformed;
    record.tree = .{ .bytes = tree[0..constants.store_digest_bytes].* };
    const settings = &record.config.settings;
    reader.words(settings, .entrypoint) orelse return .malformed;
    reader.words(settings, .cmd) orelse return .malformed;
    reader.words(settings, .env) orelse return .malformed;
    const workdir = reader.string() orelse return .malformed;
    const user = reader.string() orelse return .malformed;
    settings.set(.workdir, workdir) orelse return .malformed;
    settings.set(.user, user) orelse return .malformed;
    const labels = reader.int() orelse return .malformed;
    if (labels > constants.build_config_labels_max) return .malformed;
    for (0..labels) |_| {
        const key = reader.string() orelse return .malformed;
        const value = reader.string() orelse return .malformed;
        // Keys in order and unique: what `add_label` keeps, and what `encode` wrote.
        record.config.add_label(key, value) orelse return .malformed;
        if (record.config.labels_count > 1) {
            const last = record.config.labels_count - 1;
            if (!std.mem.eql(u8, record.config.label_key(last), key)) return .malformed;
        }
    }
    if (reader.at != bytes.len) return .malformed;
    return .ok;
}

// ---- The store --------------------------------------------------------------------------------

pub const Failure = struct { err: host_mod.Error, errno: u16, step: []const u8 };

/// Writes the record (by atomic rename) and returns the result digest. The caller holds the
/// store's lock.
pub fn save(
    store: *Store,
    record: *const Record,
    buffer: []u8,
    failure: *Failure,
) error{Failed}!Digest {
    assert(buffer.len == constants.build_result_bytes_max);
    const bytes = encode(record, buffer) catch unreachable; // `build_result_bytes_max` holds it.
    const digest = result_digest(bytes);
    var parent: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const parent_path = store.directory_path(&parent, layout.build_directory);
    const directory_path = store.directory_path(&directory, directory_name);
    const making = "making the build results directory";
    inline for (.{ parent_path, directory_path }) |made| {
        store.fs.make_directory(made, true) catch |err| {
            failure.* = .{ .err = err, .errno = store.fs.last_errno(), .step = making };
            return error.Failed;
        };
    }
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = store.build_result_path(&final, digest);
    var noted: fs_mod.Failure = undefined;
    store.fs.write_atomic(temporary_path, final_path, directory_path, bytes, 0o644, &noted) catch {
        failure.* = .{ .err = noted.err, .errno = noted.errno, .step = "writing a build result" };
        return error.Failed;
    };
    return digest;
}

pub const LoadError = error{ NotFound, Damaged, Newer, Unreadable };

/// Reads the record named `digest`, and checks that its bytes hash to the name.
pub fn load(
    store: *const Store,
    digest: Digest,
    record: *Record,
    buffer: []u8,
    errno: *u16,
) LoadError!void {
    assert(buffer.len == constants.build_result_bytes_max + 1);
    var path: PathBuf = undefined;
    const bytes = store.fs.read_whole(store.build_result_path(&path, digest), buffer) catch |err| {
        errno.* = store.fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    if (!Digest.of(bytes).eql(digest)) return error.Damaged;
    return switch (parse(bytes, record)) {
        .ok => {},
        .malformed => error.Damaged,
        .newer => error.Newer,
    };
}

comptime {
    assert(magic.len == 17);
    assert(constants.build_result_bytes_max >= constants.image_settings_bytes_max);
}
