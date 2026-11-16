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
//! Layer writer 2 (`docs/decisions/2026-11-14-s2-index-format.md`) writes the same tar into one
//! gzip member whose deflate stream is cut into segments: each cut flushes the compressor to a
//! byte boundary and starts a fresh one, so no back-reference crosses it. Cuts sit before every
//! file body, after each `store_chunk_bytes` of it, and before the lazy index, which follows the
//! tar's end-of-archive in the same stream (`pack_index.zig` records it during the walk). The
//! layer descriptor's `org.zigbox.lazy-index` annotation points at the index.
//!
//! The pack record `pack/<tree hex>-<version>` remembers the layer's digest, its tar's digest and
//! its length (and for version 2 the index's anchor), so a second pack of the same tree writes
//! nothing it already has.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const Io = std.Io;
const constants = @import("../constants.zig");

/// The newest layer writer version the packer knows. Release 0.5.2 does not write it by
/// default: see `release_writer_version`.
pub const layer_writer_version = constants.layer_writer_version;

/// The layer writer a pack writes when its caller names none, and the one `zbx push`, `push
/// --dry-run` and `store export --oci` write. 0.5.2 keeps lazy start (S2) dormant, for library
/// callers too: writer 1, 0.5.1's bytes (docs/decisions/2026-11-16-0.5.2-s2-dormant.md). 0.6.0
/// sets this back to `layer_writer_version`.
pub const release_writer_version: u32 = 1;

comptime {
    assert(release_writer_version >= 1);
    assert(release_writer_version <= layer_writer_version);
}
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
const chaining = @import("../lazy/chaining.zig");
const index_mod = @import("../lazy/index.zig");
const pack_index = @import("pack_index.zig");

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
    /// The layer writer version the layer was written with.
    writer_version: u32,
    /// Where the lazy index is (writer 2, a tree within the index's bounds), or null.
    index: ?index_mod.Anchor,
    /// The layer was already in the blob cache (a pack record and its blob).
    cached: bool,
};

/// What is packed: a tree and what runs it.
pub const Input = struct {
    tree: Digest,
    settings: *const images.Settings,
    /// The labels of a build result; an image's own are not kept.
    labels: ?*const result_mod.Config,
    /// The layer writer version to write: 1 (`release_writer_version`, the default in 0.5.2)
    /// or `layer_writer_version`.
    writer_version: u32 = release_writer_version,
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
    /// The gzip footer's CRC-32 and length, kept by the tar stage of writer 2 (whose compressor
    /// is raw deflate, so keeps none).
    crc: flate.Container.Hasher,
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
            .crc = .init(.gzip),
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
        stage.crc.update(data);
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

/// The memory a pack works in: about 30 MiB (most of it the index's seen set), kept by the
/// caller.
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
    recorder: pack_index.Recorder,
    /// The size of the pieces the file reads and the writers' buffers use (tests vary it).
    piece: u32,
    /// The most names a tree with an index has: `lazy_nodes_max` (tests lower it to reach it).
    names_max: u32,
    /// The longest index written: `lazy_index_bytes_max` (tests lower it to reach it).
    index_bytes_max: u64,
};

const Walk = struct {
    fs: Fs,
    store: *Store,
    ws: *Workspace,
    archive: *Io.Writer,
    failure: *Failure,
    current: Digest,
    decoder: tree_mod.Decoder,
    /// The bytes of the tree `current`, in `ws.tree`.
    tree_bytes: []const u8,
    path_len: u32,
    depth: u32,
    /// Writer 2: the stream is cut around file bodies and an index is recorded.
    lazy: bool,

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
        walk.tree_bytes = bytes;
    }

    fn spill_failed(walk: *Walk) Error {
        return walk.stop(.write, walk.current);
    }

    /// Ends a segment of writer 2's stream: everything written so far reaches the file's
    /// buffer as whole deflate blocks ending on a byte, and the next byte starts a compressor
    /// with no history. Returns the blob offset where the next segment starts.
    fn cut(walk: *Walk) Error!u64 {
        const ws = walk.ws;
        assert(walk.lazy);
        ws.tar_tee.writer.flush() catch return walk.write_failed();
        ws.gzip.writer.flush() catch return walk.write_failed();
        ws.gzip = flate.Compress.init(&ws.file_sink.writer, &ws.window, .raw, .default) catch
            return walk.write_failed();
        return ws.file_sink.bytes + ws.file_sink.writer.end;
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
/// room. Every file's object is added, not only those with several names, so a big image fills
/// the table: past it, later names are written as ordinary files.
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

/// Writes the bytes of a file's object after its header, checking them against the tree. For
/// writer 2, the stream is cut before the body and after each chunk of it, and the chunks are
/// recorded when `record` (the object's first appearance).
fn write_body(walk: *Walk, entry: *const tree_mod.Entry, record: bool) Error!void {
    if (record) assert(walk.lazy);
    const fs = walk.fs;
    var path_storage: PathBuf = undefined;
    const path = walk.store.object_path(&path_storage, entry.object);
    const fd = fs.open_read(path) catch |err| {
        const reason: Stop = if (err == error.NotFound) .object_missing else .unreadable;
        return walk.stop(reason, entry.object);
    };
    defer fs.close(fd);
    var hasher = digest_mod.Hasher.init();
    var chunk = digest_mod.Hasher.init();
    // A file of two chunks or more anchors each chunk to its content by its chaining value.
    const anchored = entry.size > constants.store_chunk_bytes;
    var ordinal: u64 = 0;
    var subtree: chaining.Subtree = undefined;
    subtree.init(ordinal, constants.store_chunk_bytes);
    var chunk_left: u64 = constants.store_chunk_bytes;
    var chunk_start: u64 = if (walk.lazy and entry.size > 0) try walk.cut() else 0;
    var total: u64 = 0;
    while (true) {
        var room: u64 = walk.ws.piece;
        if (walk.lazy) room = @min(room, chunk_left);
        const count = fs.read(fd, walk.ws.io[0..@intCast(room)]) catch
            return walk.stop(.unreadable, entry.object);
        if (count == 0) break;
        total += count;
        if (total > entry.size) return walk.stop(.object_changed, entry.object);
        hasher.update(walk.ws.io[0..count]);
        walk.archive.writeAll(walk.ws.io[0..count]) catch return walk.write_failed();
        if (!walk.lazy) continue;
        chunk.update(walk.ws.io[0..count]);
        if (anchored) subtree.update(walk.ws.io[0..count]);
        chunk_left -= count;
        if (chunk_left > 0 and total < entry.size) continue;
        const end = try walk.cut();
        const value = if (anchored) subtree.final(false) else zero_digest;
        if (record) try record_chunk(walk, chunk.final(), value, chunk_start, end);
        ordinal += 1;
        subtree.init(ordinal, constants.store_chunk_bytes);
        chunk = digest_mod.Hasher.init();
        chunk_left = constants.store_chunk_bytes;
        chunk_start = end;
    }
    if (total != entry.size) return walk.stop(.object_changed, entry.object);
    if (!hasher.final().eql(entry.content)) return walk.stop(.object_changed, entry.object);
    tar_write.pad(walk.archive, total) catch return walk.write_failed();
}

const zero_digest: Digest = .{ .bytes = @splat(0) };

fn record_chunk(walk: *Walk, hash: Digest, value: Digest, start: u64, end: u64) Error!void {
    assert(end > start);
    assert(end - start <= constants.lazy_range_bytes_max);
    walk.ws.recorder.chunk(walk.fs, .{
        .hash = hash,
        .chaining = value,
        .offset = start,
        .length = @intCast(end - start),
    }) catch return walk.spill_failed();
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
    var first_appearance = false;
    if (walk.lazy) {
        ws.recorder.name();
        if (entry.kind == .file) {
            first_appearance = ws.recorder.object(walk.fs, entry.object, entry.size) catch
                return walk.spill_failed();
        }
    }
    // The first name of an object always carries its bytes: the link table finds only names
    // after it.
    if (first_appearance) assert(item.kind == .file);
    try walk.write_header(item);
    if (item.kind == .file) try write_body(walk, entry, first_appearance);
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
        if (walk.lazy) ws.recorder.tree(walk.fs, entry.subtree, walk.tree_bytes) catch
            return walk.spill_failed();
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
    if (walk.lazy) walk.ws.recorder.tree(walk.fs, root, walk.tree_bytes) catch
        return walk.spill_failed();
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
fn write_layer(
    store: *Store,
    ws: *Workspace,
    input: Input,
    out: *Packed,
    failure: *Failure,
) Error!void {
    const fs = store.fs;
    const tree = input.tree;
    const blobs: blobs_mod.Blobs = .{ .fs = fs, .root = store.root_text() };
    var blob_fail: blobs_mod.Failure = undefined;
    blobs.ensure_directories(&blob_fail) catch return stopped_write(failure, tree, blob_fail.errno);
    const lazy = input.writer_version >= 2;
    if (lazy) {
        ws.recorder.start(store, ws.names_max, ws.index_bytes_max) catch {
            return stopped_write(failure, tree, fs.last_errno());
        };
    }
    defer if (lazy) ws.recorder.discard(fs);
    var temporary: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const fd = fs.create(temporary_path, 0o644) catch {
        failure.* = .{ .stop = .write, .errno = fs.last_errno(), .digest = tree };
        return error.Stopped;
    };
    write_stream(store, ws, tree, lazy, fd, out, failure) catch
        return abandon(fs, fd, temporary_path, failure.*, failure);
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

/// Walks the tree into the open layer file `fd`: the gzip header, the deflate stream of the
/// tar (and for writer 2 its index), the footer. Sets `out.index`.
fn write_stream(
    store: *Store,
    ws: *Workspace,
    tree: Digest,
    lazy: bool,
    fd: fs_mod.Fd,
    out: *Packed,
    failure: *Failure,
) Error!void {
    const fs = store.fs;
    ws.file_sink.init(ws.out[0..ws.piece], null, fs, fd);
    // Writer 1 lets std write the header and footer; writer 2 writes them around raw deflate,
    // since each cut starts a new compressor.
    if (lazy) ws.file_sink.writer.writeAll(flate.Container.gzip.header()) catch
        return stopped_write(failure, tree, ws.file_sink.errno);
    const container: flate.Container = if (lazy) .raw else .gzip;
    ws.gzip = flate.Compress.init(&ws.file_sink.writer, &ws.window, container, .default) catch
        return stopped_write(failure, tree, ws.file_sink.errno);
    ws.tar_tee.init(ws.tar_buffer[0..@min(ws.piece, ws.tar_buffer.len)], &ws.gzip.writer, fs, fd);
    ws.walk = .{
        .fs = fs,
        .store = store,
        .ws = ws,
        .archive = &ws.tar_tee.writer,
        .failure = failure,
        .current = tree,
        .decoder = undefined,
        .tree_bytes = &.{},
        .path_len = 0,
        .depth = 0,
        .lazy = lazy,
    };
    try walk_tree(&ws.walk, tree);
    out.index = null;
    if (lazy) out.index = try write_index(&ws.walk, tree);
    const flushed = ws.tar_tee.writer.flush();
    const finished = ws.gzip.finish();
    flushed catch return failed(failure, wrote(ws, tree));
    finished catch return failed(failure, wrote(ws, tree));
    if (out.index) |*anchor| {
        anchor.length = ws.file_sink.bytes + ws.file_sink.writer.end - anchor.offset;
        // The recorder kept `size` within `lazy_index_bytes_max`. `length` holds the index's
        // deflated bytes, then at most 1,536 bytes of tar padding and end blocks, the flush and
        // the 8-byte gzip footer. Std's deflate writes each block in the shortest of stored
        // (5 bytes a 64 KiB block), fixed (at most 9 bits a byte) and dynamic codes, so the
        // whole is at most 9/8 of the index plus a few KiB: within `compressed_bytes_max`.
        anchor.check() catch unreachable;
    }
    if (lazy) ws.tar_tee.crc.writeFooter(&ws.file_sink.writer) catch
        return failed(failure, wrote(ws, tree));
    ws.file_sink.writer.flush() catch return failed(failure, wrote(ws, tree));
}

/// Cuts the stream after the tar and, when the tree is within the index's bounds, writes the
/// index through the tar stage (so the config's `diff_id` covers it). The anchor's `length` is
/// set once the stream is finished.
fn write_index(walk: *Walk, tree: Digest) Error!?index_mod.Anchor {
    const ws = walk.ws;
    assert(walk.lazy);
    const offset = try walk.cut();
    if (!ws.recorder.recording) return null;
    assert(ws.recorder.index_bytes() <= constants.lazy_index_bytes_max);
    var hasher = digest_mod.Hasher.init();
    const before = ws.tar_tee.bytes + ws.tar_tee.writer.end;
    ws.recorder.emit(walk.fs, tree, walk.archive, &hasher, ws.io[0..ws.piece]) catch |err| {
        if (err == error.WriteFailed) return walk.write_failed();
        return walk.spill_failed();
    };
    const size = ws.tar_tee.bytes + ws.tar_tee.writer.end - before;
    assert(size == ws.recorder.index_bytes());
    return .{ .offset = offset, .length = 1, .size = size, .digest = hasher.final() };
}

fn failed(failure: *Failure, what: Failure) Error {
    failure.* = what;
    return error.Stopped;
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
    store.fs.write_atomic(
        store.tmp_path(&temporary),
        final_path,
        directory.text(),
        bytes,
        0o644,
        &fail,
    ) catch {
        return stopped_write(failure, tree, fail.errno);
    };
    return digest;
}

fn stopped_write(failure: *Failure, tree: Digest, errno: u16) Error {
    failure.* = .{ .stop = .write, .errno = errno, .digest = tree };
    return error.Stopped;
}

// ---- The config and the manifest ------------------------------------------------------------

fn write_words(
    writer: *json.Writer,
    name: []const u8,
    settings: *const images.Settings,
    list: images.Settings.List,
) json.WriteError!void {
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
    if (settings.get(.workdir).len > 0) try writer.member_string(
        "WorkingDir",
        settings.get(.workdir),
    );
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

fn descriptor(
    writer: *json.Writer,
    name: []const u8,
    media: []const u8,
    digest: Sha256,
    size: u64,
    index: ?*const index_mod.Anchor,
) json.WriteError!void {
    if (name.len > 0) try writer.member_object(name) else try writer.begin_object();
    if (index) |anchor| {
        var text: [index_mod.anchor_text_bytes_max]u8 = undefined;
        try writer.member_object("annotations");
        try writer.member_string(constants.pack_annotation_lazy_index, anchor.render(&text));
        try writer.end_object();
    }
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
    var version: [10]u8 = undefined;
    const version_text = std.fmt.bufPrint(&version, "{d}", .{made.writer_version}) catch
        unreachable; // A u32 has at most ten digits.
    try writer.member_string(constants.pack_annotation_writer, version_text);
    try writer.member_string(constants.pack_annotation_tree, &made.tree.text());
    try writer.end_object();
    try descriptor(
        &writer,
        "config",
        constants.oci_config_media_type,
        made.config,
        made.config_size,
        null,
    );
    try writer.member_array("layers");
    const layer_index: ?*const index_mod.Anchor = if (made.index) |*anchor| anchor else null;
    try descriptor(
        &writer,
        "",
        constants.oci_layer_media_type,
        made.layer,
        made.layer_size,
        layer_index,
    );
    try writer.end_array();
    try writer.member_string("mediaType", constants.oci_manifest_media_type);
    try writer.member_unsigned("schemaVersion", 2);
    try writer.end_object();
    return writer.finish();
}

// ---- The pack record ------------------------------------------------------------------------

fn record_path(store: *const Store, buffer: *PathBuf, tree: Digest, version: u32) [:0]const u8 {
    assert(version >= 1);
    assert(version <= constants.layer_writer_version);
    const hex = tree.hex();
    var name: [constants.store_digest_hex_bytes + 16]u8 = undefined;
    const text = std.fmt.bufPrint(&name, "/pack/{s}-{d}", .{ &hex, version }) catch
        unreachable; // Sized.
    return store.path(buffer, &.{text});
}

const Remembered = struct {
    layer: Sha256,
    diff_id: Sha256,
    size: u64,
    index: ?index_mod.Anchor,
};

/// The longest pack record: three lines of version 1 and the index line of version 2.
const record_bytes_max: u32 = 512;

comptime {
    assert(record_bytes_max >= "layer \ndiff \nsize \nindex \n".len + 2 * 71 + 20 +
        index_mod.anchor_text_bytes_max);
}

fn record_text(made: *const Packed, out: *[record_bytes_max]u8) []const u8 {
    var writer: Io.Writer = .fixed(out);
    writer.print("layer {s}\ndiff {s}\nsize {d}\n", .{
        &made.layer.text(), &made.diff_id.text(), made.layer_size,
    }) catch unreachable; // Sized by `record_bytes_max`.
    if (made.writer_version >= 2) {
        var text: [index_mod.anchor_text_bytes_max]u8 = undefined;
        const index = if (made.index) |*anchor| anchor.render(&text) else "none";
        writer.print("index {s}\n", .{index}) catch unreachable; // Same bound.
    }
    return writer.buffered();
}

fn parse_record(text: []const u8, version: u32) ?Remembered {
    assert(version >= 1);
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
    var found: Remembered = .{ .layer = layer, .diff_id = diff_id, .size = size, .index = null };
    if (version >= 2) {
        const index_line = lines.next() orelse return null;
        if (!std.mem.startsWith(u8, index_line, "index ")) return null;
        const value = index_line["index ".len..];
        if (!std.mem.eql(u8, value, "none")) {
            const anchor = index_mod.Anchor.parse(value) orelse return null;
            anchor.check() catch return null;
            found.index = anchor;
        }
    }
    return found;
}

fn recall(store: *const Store, tree: Digest, version: u32) ?Remembered {
    var path: PathBuf = undefined;
    var bytes: [record_bytes_max]u8 = undefined;
    const text = store.fs.read_whole(record_path(store, &path, tree, version), &bytes) catch
        return null;
    const found = parse_record(text, version) orelse return null;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    if (!blobs.has(found.layer, found.size)) return null;
    return found;
}

/// Drops the pack record of `tree`, so the next pack walks and compresses again (tests and the
/// fuzzer use it to compare two real packs; a missing record is no error).
pub fn forget(store: *const Store, tree: Digest, version: u32) void {
    var path: PathBuf = undefined;
    const record = record_path(store, &path, tree, version);
    store.fs.unlink(record) catch |err| assert(err == error.NotFound);
}

fn remember(store: *Store, made: *const Packed, failure: *Failure) Error!void {
    var directory: PathBuf = undefined;
    store.fs.make_directory(store.directory_path(&directory, "pack"), true) catch {
        return stopped_write(failure, made.tree, store.fs.last_errno());
    };
    var bytes: [record_bytes_max]u8 = undefined;
    const text = record_text(made, &bytes);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    var fail: fs_mod.Failure = undefined;
    store.fs.write_atomic(
        store.tmp_path(&temporary),
        record_path(store, &final, made.tree, made.writer_version),
        directory.text(),
        text,
        0o644,
        &fail,
    ) catch {
        return stopped_write(failure, made.tree, fail.errno);
    };
}

// ---- Pack -----------------------------------------------------------------------------------

/// Packs `input` into the blob cache and the pack record, and says what it made.
pub fn pack(
    store: *Store,
    ws: *Workspace,
    input: Input,
    out: *Packed,
    failure: *Failure,
) Error!void {
    ws.piece = constants.pack_io_bytes;
    ws.names_max = constants.lazy_nodes_max;
    ws.index_bytes_max = constants.lazy_index_bytes_max;
    return pack_pieces(store, ws, input, out, failure);
}

/// `pack` with the pieces `ws.piece` bytes long (at least 1024): the output must not depend
/// on it, which the tests check. `ws.names_max` and `ws.index_bytes_max` are set by the caller
/// as well.
pub fn pack_pieces(
    store: *Store,
    ws: *Workspace,
    input: Input,
    out: *Packed,
    failure: *Failure,
) Error!void {
    assert(store.root_len > 1);
    assert(ws.piece >= 1024);
    assert(ws.piece <= constants.pack_io_bytes);
    assert(ws.names_max >= 1);
    assert(ws.names_max <= constants.lazy_nodes_max);
    assert(ws.index_bytes_max >= index_mod.header_bytes);
    assert(ws.index_bytes_max <= constants.lazy_index_bytes_max);
    assert(input.writer_version >= 1);
    assert(input.writer_version <= constants.layer_writer_version);
    out.tree = input.tree;
    out.writer_version = input.writer_version;
    ws.links_count = 0;
    ws.link_used = 0;
    @memset(&ws.links, .{ .object = undefined, .at = 0, .len = 0, .used = false });
    out.cached = false;
    if (recall(store, input.tree, input.writer_version)) |found| {
        out.layer = found.layer;
        out.diff_id = found.diff_id;
        out.layer_size = found.size;
        out.index = found.index;
        out.cached = true;
    } else {
        try write_layer(store, ws, input, out, failure);
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
pub fn record_image(
    store: *Store,
    made: *const Packed,
    input: Input,
    tag: []const u8,
    failure: *fs_mod.Failure,
) fs_mod.Error!void {
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
    set_labels(&image.labels, input.labels);
    image.partial = false; // The tree was just packed from the store.
    try images.save(store, &image, failure);
}

/// The labels the config blob carries, as the record keeps them (what a pull of it would read):
/// none for an image, a result's own otherwise, and unknown when they do not fit.
fn set_labels(labels: *images.Labels, from: ?*const result_mod.Config) void {
    labels.clear();
    const config = from orelse return;
    assert(config.labels_count <= constants.build_config_labels_max);
    for (0..config.labels_count) |index| {
        const at: u32 = @intCast(index);
        const added = labels.add(config.label_key(at), config.label_value(at));
        if (added == null) return labels.forget();
    }
}

var bound_workspace: Workspace = undefined;

fn reset_links(ws: *Workspace) void {
    ws.links_count = 0;
    ws.link_used = 0;
    @memset(&ws.links, .{ .object = undefined, .at = 0, .len = 0, .used = false });
}

test "the link table stops taking objects at its bound, and later names stay full copies" {
    // Goal: the bound and one past it, which fix the layer's form for a big image. Method: fill
    // the table with distinct objects; the next new object is not remembered, so its later
    // names are not links (null again), while an object kept before still links.
    const ws = &bound_workspace;
    reset_links(ws);
    var name: [16]u8 = undefined;
    for (0..constants.pack_links_max) |index| {
        const path = std.fmt.bufPrint(&name, "p{d}", .{index}) catch unreachable; // Short.
        try std.testing.expect(link_find_or_add(ws, Digest.of(path), path) == null);
    }
    try std.testing.expectEqual(constants.pack_links_max, ws.links_count);
    const extra = Digest.of("one past the bound");
    try std.testing.expect(link_find_or_add(ws, extra, "extra") == null);
    try std.testing.expect(link_find_or_add(ws, extra, "extra-again") == null);
    try std.testing.expectEqual(constants.pack_links_max, ws.links_count);
    const kept = link_find_or_add(ws, Digest.of("p7"), "later").?;
    try std.testing.expectEqualStrings("p7", kept);
}

test "the link table stops taking objects when its path room is full" {
    // Goal: the byte bound and one past it. Method: remember long paths until the room is
    // used; the next object that does not fit is not remembered, an earlier one still links.
    const ws = &bound_workspace;
    reset_links(ws);
    var path: [constants.path_bytes_max]u8 = undefined;
    @memset(&path, 'x');
    var index: u32 = 0;
    while (ws.link_used + path.len <= constants.pack_link_paths_bytes) : (index += 1) {
        var key: [8]u8 = undefined;
        const text = std.fmt.bufPrint(&key, "k{d}", .{index}) catch unreachable; // Short.
        try std.testing.expect(link_find_or_add(ws, Digest.of(text), &path) == null);
    }
    const before = ws.links_count;
    try std.testing.expect(link_find_or_add(ws, Digest.of("late"), &path) == null);
    try std.testing.expectEqual(before, ws.links_count);
    try std.testing.expect(link_find_or_add(ws, Digest.of("k0"), "n") != null);
}
