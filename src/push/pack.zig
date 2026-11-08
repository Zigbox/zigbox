//! Packs a stored tree into an OCI image: one gzip layer of the whole tree, an image config and
//! a manifest. The same tree and settings give the same three blobs on any host for one layer
//! writer version (`constants.layer_writer_version`).
//!
//! The layer: a walk of the tree (iterative, an explicit stack, names in the tree's order, each
//! directory before what is in it) writes ustar entries (`layer/tar_write.zig`) into std's gzip at
//! its default level (6). Every file's bytes are read from the store's object and hashed on
//! the way; bytes that are not the content the tree names stop the pack, so a layer is never
//! made of a tree that is not whole. The second and later names of one object are hard links
//! (until the table of them is full; then the bytes are repeated, which is the same tree).
//!
//! The pack record `pack/<tree hex>-<version>` remembers the layer's digest, its tar's digest and
//! its length, so a second pack of the same tree writes nothing it already has.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const Io = std.Io;
const constants = @import("../constants.zig");
const blobs_mod = @import("../registry/blobs.zig");
const oci = @import("../registry/digest.zig");
const result_mod = @import("../build/result.zig");
const fs_mod = @import("../store/fs.zig");
const digest_mod = @import("../store/digest.zig");
const images = @import("../store/images.zig");
const layout = @import("../store/layout.zig");
const tree_mod = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const json = @import("../trust/json.zig");
const tar_write = @import("../layer/tar_write.zig");

const flate = std.compress.flate;
const Digest = digest_mod.Digest;
const Fs = fs_mod.Fs;
const PathBuf = fs_mod.PathBuf;
const Sha256 = oci.Sha256;
const Store = layout.Store;

/// Why a tree cannot be packed.
pub const Stop = enum {
    /// A tree the walk needs is not in the store.
    tree_missing,
    /// A tree whose bytes do not hash to its name, or that does not decode.
    tree_damaged,
    /// A file's object is not in the store.
    object_missing,
    /// A file's bytes are not the content its tree names (or not its size).
    object_changed,
    /// A path longer than `constants.path_bytes_max`.
    path_too_long,
    /// Something in the store could not be read.
    unreadable,
    /// The layer or a blob could not be written.
    write,
    /// A setting that JSON cannot carry (text that is not UTF-8).
    config_invalid,

    pub fn sentence(stop: Stop) []const u8 {
        assert(@tagName(stop).len > 0);
        return switch (stop) {
            .tree_missing => "a directory of the tree is not in the store",
            .tree_damaged => "a directory of the tree is damaged",
            .object_missing => "a file of the tree is not in the store",
            .object_changed => "a file of the tree does not have the content the tree names",
            .path_too_long => "a path in the tree is longer than 4095 bytes",
            .unreadable => "the store could not be read",
            .write => "the image could not be written",
            .config_invalid => "a setting of the image is not text a JSON config can hold",
        };
    }
};

pub const Failure = struct {
    stop: Stop,
    errno: u16,
    /// The tree or object the stop concerns (the root when it is not one of them).
    digest: Digest,
};

pub const Error = error{Stopped};

/// What a pack makes: the digests and lengths a manifest, a push and an export name.
pub const Packed = struct {
    tree: Digest,
    manifest: Sha256,
    manifest_size: u32,
    config: Sha256,
    config_size: u32,
    layer: Sha256,
    layer_size: u64,
    diff_id: Sha256,
    /// The layer was already in the blob cache (a pack record and its blob).
    cached: bool,
};

/// What is packed: a tree and what runs it.
pub const Input = struct {
    tree: Digest,
    settings: *const images.Settings,
    /// The labels of a build result; an image's own are not kept.
    labels: ?*const result_mod.Config,
};

const Link = struct {
    object: Digest,
    at: u32,
    len: u32,
    used: bool,
};

const Frame = struct {
    digest: Digest,
    at: u32,
    left: u32,
    path_len: u32,
};

/// A writer that counts and hashes what passes and hands it on: to another writer, or (the last
/// stage) to a file.
const Stage = struct {
    writer: Io.Writer,
    hasher: std.crypto.hash.sha2.Sha256,
    bytes: u64,
    next: ?*Io.Writer,
    fs: Fs,
    fd: fs_mod.Fd,
    failed: bool,
    errno: u16,

    fn init(stage: *Stage, buffer: []u8, next: ?*Io.Writer, fs: Fs, fd: fs_mod.Fd) void {
        stage.* = .{
            .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } },
            .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
            .bytes = 0,
            .next = next,
            .fs = fs,
            .fd = fd,
            .failed = false,
            .errno = 0,
        };
    }

    fn put(stage: *Stage, data: []const u8) Io.Writer.Error!void {
        if (data.len == 0) return;
        if (stage.failed) return error.WriteFailed;
        stage.hasher.update(data);
        stage.bytes += data.len;
        if (stage.next) |next| return next.writeAll(data);
        stage.fs.write_all(stage.fd, data) catch {
            stage.failed = true;
            stage.errno = stage.fs.last_errno();
            return error.WriteFailed;
        };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        assert(data.len > 0);
        const stage: *Stage = @alignCast(@fieldParentPtr("writer", w));
        try stage.put(w.buffer[0..w.end]);
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |piece| {
            try stage.put(piece);
            consumed += piece.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try stage.put(last);
        return consumed + last.len * splat;
    }

    fn digest(stage: *Stage) Sha256 {
        var out: Sha256 = undefined;
        stage.hasher.final(&out.bytes);
        return out;
    }
};

/// The memory a pack works in: about 8 MiB, kept by the caller.
pub const Workspace = struct {
    tree: [constants.store_tree_bytes_max]u8,
    path: [constants.path_bytes_max + 1]u8,
    frames: [constants.store_depth_max + 1]Frame,
    link_paths: [constants.pack_link_paths_bytes]u8,
    link_used: u32,
    links: [constants.pack_links_max * 2]Link,
    links_count: u32,
    io: [constants.pack_io_bytes]u8,
    out: [constants.pack_io_bytes]u8,
    tar_buffer: [16 * 1024]u8,
    window: [flate.max_window_len]u8,
    scratch: tar_write.Scratch,
    file_sink: Stage,
    tar_tee: Stage,
    gzip: flate.Compress,
    json: [constants.pack_config_bytes_max]u8,
    walk: Walk,
    /// The size of the pieces the file reads and the writers' buffers use (tests vary it).
    piece: u32,
};

const Walk = struct {
    fs: Fs,
    store: *Store,
    ws: *Workspace,
    archive: *Io.Writer,
    failure: *Failure,
    current: Digest,
    decoder: tree_mod.Decoder,
    path_len: u32,
    depth: u32,

    fn stop(walk: *Walk, reason: Stop, digest: Digest) Error {
        walk.failure.* = .{ .stop = reason, .errno = walk.fs.last_errno(), .digest = digest };
        return error.Stopped;
    }

    /// Loads the tree `digest` into the buffer and starts a decoder on it.
    fn open_tree(walk: *Walk, digest: Digest) Error!void {
        var errno: u16 = 0;
        const bytes = trees.load(walk.store, digest, &walk.ws.tree, &errno) catch |err| {
            walk.failure.* = .{
                .stop = if (err == error.NotFound) .tree_missing else if (err == error.Damaged)
                    .tree_damaged
                else
                    .unreadable,
                .errno = errno,
                .digest = digest,
            };
            return error.Stopped;
        };
        walk.decoder.init(bytes) catch return walk.stop(.tree_damaged, digest);
        walk.current = digest;
    }

    fn write_failed(walk: *Walk) Error {
        const sink = &walk.ws.file_sink;
        walk.failure.* = .{
            .stop = .write,
            .errno = sink.errno,
            .digest = walk.current,
        };
        return error.Stopped;
    }

    fn write_header(walk: *Walk, entry: tar_write.Entry) Error!void {
        tar_write.write_header(walk.archive, &walk.ws.scratch, entry) catch
            return walk.write_failed();
    }
};

fn host_architecture() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @compileError("zbx packs for x86_64 and aarch64 only"),
    };
}

/// The platform text an image record carries for a pack made here.
pub const platform_text = "linux/" ++ host_architecture();

// ---- The walk ------------------------------------------------------------------------------

fn hash_slot(object: Digest) u32 {
    const word = std.mem.readInt(u32, object.bytes[0..4], .little);
    return word & (constants.pack_links_max * 2 - 1);
}

/// The first path of the object, or null; remembers `path` when the object is new and there is
/// room.
fn link_find_or_add(ws: *Workspace, object: Digest, path: []const u8) ?[]const u8 {
    assert(path.len > 0);
    assert(ws.links_count <= constants.pack_links_max);
    var slot = hash_slot(object);
    while (ws.links[slot].used) : (slot = (slot + 1) & (constants.pack_links_max * 2 - 1)) {
        if (ws.links[slot].object.eql(object)) {
            const link = ws.links[slot];
            return ws.link_paths[link.at..][0..link.len];
        }
    }
    if (ws.links_count == constants.pack_links_max) return null;
    if (ws.link_used + path.len > ws.link_paths.len) return null;
    @memcpy(ws.link_paths[ws.link_used..][0..path.len], path);
    ws.links[slot] = .{
        .object = object,
        .at = ws.link_used,
        .len = @intCast(path.len),
        .used = true,
    };
    ws.link_used += @intCast(path.len);
    ws.links_count += 1;
    return null;
}

/// Writes the bytes of a file's object after its header, checking them against the tree.
fn write_body(walk: *Walk, entry: *const tree_mod.Entry) Error!void {
    const fs = walk.fs;
    var path_storage: PathBuf = undefined;
    const path = walk.store.object_path(&path_storage, entry.object);
    const fd = fs.open_read(path) catch |err| {
        const reason: Stop = if (err == error.NotFound) .object_missing else .unreadable;
        return walk.stop(reason, entry.object);
    };
    defer fs.close(fd);
    var hasher = digest_mod.Hasher.init();
    var total: u64 = 0;
    while (true) {
        const count = fs.read(fd, walk.ws.io[0..walk.ws.piece]) catch return walk.stop(.unreadable, entry.object);
        if (count == 0) break;
        total += count;
        if (total > entry.size) return walk.stop(.object_changed, entry.object);
        hasher.update(walk.ws.io[0..count]);
        walk.archive.writeAll(walk.ws.io[0..count]) catch return walk.write_failed();
    }
    if (total != entry.size) return walk.stop(.object_changed, entry.object);
    if (!hasher.final().eql(entry.content)) return walk.stop(.object_changed, entry.object);
    tar_write.pad(walk.archive, total) catch return walk.write_failed();
}

fn write_entry(walk: *Walk, entry: *const tree_mod.Entry) Error!void {
    const ws = walk.ws;
    const before = walk.path_len;
    const extra: usize = if (entry.kind == .dir) 1 else 0;
    if (before + entry.name.len + extra > constants.path_bytes_max) {
        return walk.stop(.path_too_long, walk.current);
    }
    @memcpy(ws.path[before..][0..entry.name.len], entry.name);
    var length: u32 = before + @as(u32, @intCast(entry.name.len));
    if (entry.kind == .dir) {
        ws.path[length] = '/';
        length += 1;
    }
    const path = ws.path[0..length];
    var item: tar_write.Entry = .{
        .path = path,
        .kind = switch (entry.kind) {
            .dir => .directory,
            .file => .file,
            .symlink => .symlink,
        },
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = if (entry.kind == .file) entry.size else 0,
        .link = if (entry.kind == .symlink) entry.target else "",
        .xattrs = entry.xattrs,
    };
    if (entry.kind == .file) {
        if (link_find_or_add(ws, entry.object, path)) |first| {
            item.kind = .hard_link;
            item.size = 0;
            item.link = first;
        }
    }
    try walk.write_header(item);
    if (item.kind == .file) try write_body(walk, entry);
    if (entry.kind == .dir) {
        assert(walk.depth < constants.store_depth_max);
        ws.frames[walk.depth] = .{
            .digest = walk.current,
            .at = walk.decoder.at,
            .left = walk.decoder.left,
            .path_len = before,
        };
        walk.depth += 1;
        walk.path_len = length;
        try walk.open_tree(entry.subtree);
    }
}

/// Resumes the directory above, after the one that just ended.
fn pop(walk: *Walk) Error!void {
    assert(walk.depth > 0);
    walk.depth -= 1;
    const frame = walk.ws.frames[walk.depth];
    try walk.open_tree(frame.digest);
    walk.decoder.at = frame.at;
    walk.decoder.left = frame.left;
    walk.decoder.previous = null;
    walk.path_len = frame.path_len;
}

fn walk_tree(walk: *Walk, root: Digest) Error!void {
    // The root's own metadata comes last in its tree, and the archive's first entry carries it.
    try walk.open_tree(root);
    var entry: tree_mod.Entry = undefined;
    while (walk.decoder.next(&entry) catch return walk.stop(.tree_damaged, root)) {}
    const own = walk.decoder.own;
    try walk.write_header(.{
        .path = "./",
        .kind = .directory,
        .mode = own.mode,
        .uid = own.uid,
        .gid = own.gid,
        .size = 0,
        .link = "",
        .xattrs = own.xattrs,
    });
    try walk.open_tree(root);
    walk.depth = 0;
    walk.path_len = 0;
    while (true) {
        const more = walk.decoder.next(&entry) catch {
            return walk.stop(.tree_damaged, walk.current);
        };
        if (more) {
            try write_entry(walk, &entry);
        } else if (walk.depth == 0) {
            break;
        } else {
            try pop(walk);
        }
    }
    tar_write.finish(walk.archive) catch return walk.write_failed();
}

// ---- The blobs -----------------------------------------------------------------------------

fn blob_path(store: *const Store, buffer: *PathBuf, digest: Sha256) [:0]const u8 {
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    return blobs.final_path(buffer, digest);
}

/// The layer: tar, gzip, file; returns with the layer in the blob cache.
fn write_layer(store: *Store, ws: *Workspace, tree: Digest, out: *Packed, failure: *Failure) Error!void {
    const fs = store.fs;
    const blobs: blobs_mod.Blobs = .{ .fs = fs, .root = store.root_text() };
    var blob_fail: blobs_mod.Failure = undefined;
    blobs.ensure_directories(&blob_fail) catch return stopped_write(failure, tree, blob_fail.errno);
    var temporary: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const fd = fs.create(temporary_path, 0o644) catch {
        failure.* = .{ .stop = .write, .errno = fs.last_errno(), .digest = tree };
        return error.Stopped;
    };
    ws.file_sink.init(ws.out[0..ws.piece], null, fs, fd);
    ws.gzip = flate.Compress.init(&ws.file_sink.writer, &ws.window, .gzip, .default) catch {
        return abandon(fs, fd, temporary_path, .{ .stop = .write, .errno = 0, .digest = tree }, failure);
    };
    ws.tar_tee.init(ws.tar_buffer[0..@min(ws.piece, ws.tar_buffer.len)], &ws.gzip.writer, fs, fd);
    ws.walk = .{
        .fs = fs,
        .store = store,
        .ws = ws,
        .archive = &ws.tar_tee.writer,
        .failure = failure,
        .current = tree,
        .decoder = undefined,
        .path_len = 0,
        .depth = 0,
    };
    walk_tree(&ws.walk, tree) catch return abandon(fs, fd, temporary_path, failure.*, failure);
    const flushed = ws.tar_tee.writer.flush();
    const finished = ws.gzip.finish();
    const drained = ws.file_sink.writer.flush();
    flushed catch return abandon(fs, fd, temporary_path, wrote(ws, tree), failure);
    finished catch return abandon(fs, fd, temporary_path, wrote(ws, tree), failure);
    drained catch return abandon(fs, fd, temporary_path, wrote(ws, tree), failure);
    fs.fsync(fd) catch return abandon(fs, fd, temporary_path, wrote(ws, tree), failure);
    fs.close(fd);
    out.diff_id = ws.tar_tee.digest();
    out.layer = ws.file_sink.digest();
    out.layer_size = ws.file_sink.bytes;
    var final: PathBuf = undefined;
    fs.rename(temporary_path, blob_path(store, &final, out.layer)) catch {
        fs.unlink(temporary_path) catch {};
        failure.* = .{ .stop = .write, .errno = fs.last_errno(), .digest = tree };
        return error.Stopped;
    };
}

fn wrote(ws: *const Workspace, tree: Digest) Failure {
    const errno = if (ws.file_sink.failed) ws.file_sink.errno else ws.tar_tee.errno;
    return .{ .stop = .write, .errno = errno, .digest = tree };
}

fn abandon(fs: Fs, fd: fs_mod.Fd, path: [:0]const u8, what: Failure, failure: *Failure) Error {
    fs.close(fd);
    fs.unlink(path) catch {}; // The failure being reported is the first one.
    failure.* = what;
    return error.Stopped;
}

/// Puts `bytes` in the blob cache under the digest of them, if it is not there.
fn put_blob(store: *Store, bytes: []const u8, failure: *Failure, tree: Digest) Error!Sha256 {
    assert(bytes.len > 0);
    assert(bytes.len <= constants.pack_config_bytes_max);
    const digest = Sha256.of(bytes);
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    if (blobs.has(digest, bytes.len)) return digest;
    var fail: fs_mod.Failure = undefined;
    var blob_fail: blobs_mod.Failure = undefined;
    blobs.ensure_directories(&blob_fail) catch return stopped_write(failure, tree, blob_fail.errno);
    var final: PathBuf = undefined;
    var temporary: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const final_path = blobs.final_path(&final, digest);
    directory.set(&.{ blobs.root, "/blobs/sha256" }) catch unreachable; // Short.
    store.fs.write_atomic(store.tmp_path(&temporary), final_path, directory.text(), bytes, 0o644, &fail) catch {
        return stopped_write(failure, tree, fail.errno);
    };
    return digest;
}

fn stopped_write(failure: *Failure, tree: Digest, errno: u16) Error {
    failure.* = .{ .stop = .write, .errno = errno, .digest = tree };
    return error.Stopped;
}

// ---- The config and the manifest ------------------------------------------------------------

fn write_words(writer: *json.Writer, name: []const u8, settings: *const images.Settings, list: images.Settings.List) json.WriteError!void {
    if (settings.count(list) == 0) return;
    try writer.member_array(name);
    var index: u32 = 0;
    while (index < settings.count(list)) : (index += 1) {
        try writer.string(settings.word(list, index));
    }
    try writer.end_array();
}

/// The image config: what the image runs with, and the one layer's tar digest.
pub fn render_config(input: Input, diff_id: Sha256, out: []u8) json.WriteError![]const u8 {
    var writer = json.Writer.init(out);
    const settings = input.settings;
    try writer.begin_object();
    try writer.member_string("architecture", host_architecture());
    try writer.member_object("config");
    try write_words(&writer, "Cmd", settings, .cmd);
    try write_words(&writer, "Entrypoint", settings, .entrypoint);
    try write_words(&writer, "Env", settings, .env);
    if (input.labels) |config| if (config.labels_count > 0) {
        try writer.member_object("Labels");
        var index: u32 = 0;
        while (index < config.labels_count) : (index += 1) {
            try writer.member_string(config.label_key(index), config.label_value(index));
        }
        try writer.end_object();
    };
    if (settings.get(.user).len > 0) try writer.member_string("User", settings.get(.user));
    if (settings.get(.workdir).len > 0) try writer.member_string("WorkingDir", settings.get(.workdir));
    try writer.end_object();
    try writer.member_string("os", "linux");
    try writer.member_object("rootfs");
    try writer.member_array("diff_ids");
    try writer.string(&diff_id.text());
    try writer.end_array();
    try writer.member_string("type", "layers");
    try writer.end_object();
    try writer.end_object();
    return writer.finish();
}

fn descriptor(writer: *json.Writer, name: []const u8, media: []const u8, digest: Sha256, size: u64) json.WriteError!void {
    if (name.len > 0) try writer.member_object(name) else try writer.begin_object();
    try writer.member_string("digest", &digest.text());
    try writer.member_string("mediaType", media);
    try writer.member_unsigned("size", size);
    try writer.end_object();
}

/// The manifest of the image: the config, the layer, and the two annotations.
pub fn render_manifest(made: *const Packed, out: []u8) json.WriteError![]const u8 {
    var writer = json.Writer.init(out);
    try writer.begin_object();
    try writer.member_object("annotations");
    try writer.member_string(constants.pack_annotation_writer, version_text());
    try writer.member_string(constants.pack_annotation_tree, &made.tree.text());
    try writer.end_object();
    try descriptor(&writer, "config", constants.oci_config_media_type, made.config, made.config_size);
    try writer.member_array("layers");
    try descriptor(&writer, "", constants.oci_layer_media_type, made.layer, made.layer_size);
    try writer.end_array();
    try writer.member_string("mediaType", constants.oci_manifest_media_type);
    try writer.member_unsigned("schemaVersion", 2);
    try writer.end_object();
    return writer.finish();
}

fn version_text() []const u8 {
    return std.fmt.comptimePrint("{d}", .{constants.layer_writer_version});
}

// ---- The pack record ------------------------------------------------------------------------

fn record_path(store: *const Store, buffer: *PathBuf, tree: Digest) [:0]const u8 {
    const hex = tree.hex();
    var name: [constants.store_digest_hex_bytes + 16]u8 = undefined;
    const text = std.fmt.bufPrint(&name, "/pack/{s}-{d}", .{ &hex, constants.layer_writer_version }) catch unreachable; // Sized.
    return store.path(buffer, &.{text});
}

const Remembered = struct { layer: Sha256, diff_id: Sha256, size: u64 };

fn record_text(made: *const Packed, out: []u8) []const u8 {
    return std.fmt.bufPrint(out, "layer {s}\ndiff {s}\nsize {d}\n", .{
        &made.layer.text(), &made.diff_id.text(), made.layer_size,
    }) catch unreachable; // Sized by the caller.
}

fn parse_record(text: []const u8) ?Remembered {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const layer_line = lines.next() orelse return null;
    const diff_line = lines.next() orelse return null;
    const size_line = lines.next() orelse return null;
    if (!std.mem.startsWith(u8, layer_line, "layer ")) return null;
    if (!std.mem.startsWith(u8, diff_line, "diff ")) return null;
    if (!std.mem.startsWith(u8, size_line, "size ")) return null;
    const layer = Sha256.parse(layer_line["layer ".len..]) orelse return null;
    const diff_id = Sha256.parse(diff_line["diff ".len..]) orelse return null;
    const size = std.fmt.parseInt(u64, size_line["size ".len..], 10) catch return null;
    if (size == 0) return null;
    return .{ .layer = layer, .diff_id = diff_id, .size = size };
}

fn recall(store: *const Store, tree: Digest) ?Remembered {
    var path: PathBuf = undefined;
    var bytes: [256]u8 = undefined;
    const text = store.fs.read_whole(record_path(store, &path, tree), &bytes) catch return null;
    const found = parse_record(text) orelse return null;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    if (!blobs.has(found.layer, found.size)) return null;
    return found;
}

fn remember(store: *Store, made: *const Packed, failure: *Failure) Error!void {
    var directory: PathBuf = undefined;
    store.fs.make_directory(store.directory_path(&directory, "pack"), true) catch {
        return stopped_write(failure, made.tree, store.fs.last_errno());
    };
    var bytes: [256]u8 = undefined;
    const text = record_text(made, &bytes);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    var fail: fs_mod.Failure = undefined;
    store.fs.write_atomic(store.tmp_path(&temporary), record_path(store, &final, made.tree), directory.text(), text, 0o644, &fail) catch {
        return stopped_write(failure, made.tree, fail.errno);
    };
}

// ---- Pack -----------------------------------------------------------------------------------

/// Packs `input` into the blob cache and the pack record, and says what it made.
pub fn pack(store: *Store, ws: *Workspace, input: Input, out: *Packed, failure: *Failure) Error!void {
    ws.piece = constants.pack_io_bytes;
    return pack_pieces(store, ws, input, out, failure);
}

/// `pack` with the pieces `ws.piece` bytes long (at least 1024): the output must not depend
/// on it, which the tests check.
pub fn pack_pieces(store: *Store, ws: *Workspace, input: Input, out: *Packed, failure: *Failure) Error!void {
    assert(store.root_len > 1);
    assert(ws.piece >= 1024 and ws.piece <= constants.pack_io_bytes);
    out.tree = input.tree;
    ws.links_count = 0;
    ws.link_used = 0;
    @memset(&ws.links, .{ .object = undefined, .at = 0, .len = 0, .used = false });
    out.cached = false;
    if (recall(store, input.tree)) |found| {
        out.layer = found.layer;
        out.diff_id = found.diff_id;
        out.layer_size = found.size;
        out.cached = true;
    } else {
        try write_layer(store, ws, input.tree, out, failure);
        try remember(store, out, failure);
    }
    const config = render_config(input, out.diff_id, &ws.json) catch {
        failure.* = .{ .stop = .config_invalid, .errno = 0, .digest = input.tree };
        return error.Stopped;
    };
    out.config_size = @intCast(config.len);
    out.config = try put_blob(store, config, failure, input.tree);
    const manifest = render_manifest(out, &ws.json) catch unreachable; // Bounded and sized.
    out.manifest_size = @intCast(manifest.len);
    out.manifest = try put_blob(store, manifest, failure, input.tree);
}

/// Writes the image record of a packed manifest. `tag` is the destination of a push (empty for
/// none).
pub fn record_image(store: *Store, made: *const Packed, input: Input, tag: []const u8, failure: *fs_mod.Failure) fs_mod.Error!void {
    assert(tag.len <= constants.reference_bytes_max);
    var image: images.Image = undefined;
    images.carry_tags(store, made.manifest, &image);
    if (tag.len > 0) image.add_tag(tag);
    image.manifest = made.manifest;
    image.platform_len = platform_text.len;
    @memcpy(image.platform[0..platform_text.len], platform_text);
    image.config = made.config;
    image.tree = made.tree;
    image.time = store.host.time_now();
    image.layer_count = 1;
    image.layers[0] = made.layer;
    image.settings = input.settings.*;
    try images.save(store, &image, failure);
}
