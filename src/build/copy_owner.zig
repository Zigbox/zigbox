//! A copy entry's `.chown` and `.chmod` (docs/briefs/M9-dockerfile-import.md, `.copy`): the
//! selection tree (`copy.zig`) with every entry in it given the owner and the mode asked for.
//!
//! An owner or a mode is part of a file object's id (`store/object.zig`), so a stamped file is
//! another object, written here with the real owner: a `chown` to a container id is allowed only
//! to the root of the store's user namespace. So `restamp` runs in the namespace child
//! (`copy_job.zig`), never in the build's parent process
//! (decisions/2026-11-12-m9-glob-pool-and-copy-chown.md).
//!
//! What a stamp covers: every entry of the selection below its root, at any depth. The owner goes
//! on all of them, the directories made on the way to `.to` included ("all new files and
//! directories" are the owner's, as Docker has it; one the image has keeps its own, since a merge
//! keeps the image's directory). The mode goes on what the patterns took, not on those
//! directories, which keep 0755: a mode such as 0644 would make them untraversable. A symlink
//! keeps its mode (Linux has none for one).
//!
//! The walk is iterative: one frame per open directory, each holding the directory's tree bytes
//! and the stamped digests of the subdirectories it has finished, in one arena used as a stack
//! (`store_arena_bytes_max`, the bound `materialize` gives the same trees). A directory is
//! written once its subdirectories are: its bytes are decoded a second time into `out`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const assemble = @import("assemble.zig");
const digest_mod = @import("../store/digest.zig");
const host_mod = @import("../host.zig");
const layout = @import("../store/layout.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const fs_mod = @import("../store/fs.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

pub const Error = error{Failed};

pub const Owner = struct { uid: u32, gid: u32 };

/// What a copy entry asks every entry it takes to be: null keeps the source's.
pub const Stamp = struct {
    owner: ?Owner = null,
    mode: ?u16 = null,

    pub fn changes(stamp: Stamp) bool {
        if (stamp.owner != null) return true;
        return stamp.mode != null;
    }
};

/// The ids no file can have: `chown` reads -1 as "leave it". A stamp never holds it.
pub const id_unowned: u32 = std.math.maxInt(u32);

/// The mode a `.chmod` text gives: three or four octal digits (`file.is_mode`).
pub fn mode_of(text: []const u8) u16 {
    assert(text.len >= 3);
    assert(text.len <= 4);
    const mode = std.fmt.parseInt(u16, text, 8) catch unreachable; // `is_mode` checked it.
    assert(mode <= 0o7777);
    return mode;
}

/// `entry` as `stamp` leaves it: the owner on every kind, the mode on a file and a directory, and
/// a file's object id for its new attributes.
pub fn stamped(entry: *const tree.Entry, stamp: Stamp) tree.Entry {
    var result = entry.*;
    if (stamp.owner) |owner| {
        assert(owner.uid != id_unowned);
        assert(owner.gid != id_unowned);
        result.uid = owner.uid;
        result.gid = owner.gid;
    }
    if (stamp.mode) |mode| {
        assert(mode <= 0o7777);
        if (entry.kind != .symlink) result.mode = mode;
    }
    if (entry.kind == .file) {
        result.object = object.object_id(entry.content, .{
            .mode = result.mode,
            .uid = result.uid,
            .gid = result.gid,
            .xattrs = entry.xattrs,
        });
    }
    if (result.mode == entry.mode) {
        // The same attributes are the same object (the id is a function of them).
        if (result.uid == entry.uid) {
            if (result.gid == entry.gid) assert(result.object.eql(entry.object));
        }
    }
    return result;
}

const Frame = struct {
    /// The directory's tree, for a failure to name.
    dir: Digest,
    /// The directory is `/` or on the way to `.to`: its directory entries may be too.
    on_path: bool,
    /// Its bytes: `arena[at..][0..len]`; the finished subdirectories' digests follow them.
    at: u32,
    len: u32,
    decoder: tree.Decoder,
    finished: u32,
};

pub const Workspace = struct {
    arena: [constants.store_arena_bytes_max]u8,
    out: [constants.store_tree_bytes_max]u8,
    frames: [constants.store_depth_max + 1]Frame,
    io: [constants.store_io_buffer_bytes]u8,
    chunks: [constants.store_chunks_max]Digest,
    scratch: [constants.store_chunks_max]Digest,
    /// `.to` split at its slashes: `path[d]` is the name at depth `d + 1`.
    path: [constants.store_depth_max][]const u8,
    path_len: u32,
    /// Objects this restamp wrote (the rest were in the store).
    objects_written: u32,
};

comptime {
    // `object.chunk_hashes` reads a chunk list into `io`.
    assert(constants.store_io_buffer_bytes >= constants.store_chunks_max * 32);
    assert(constants.store_tree_bytes_max <= constants.store_arena_bytes_max);
}

pub const Context = struct {
    store: *Store,
    failure: *assemble.Failure,
};

/// The selection `root`, laid at `to`, with `stamp` on every entry below the root (the mode not
/// on the directories on the way to `to`); the root's own attributes kept. The objects of stamped
/// files are written; `Failed` with `context.failure` set.
pub fn restamp(
    context: Context,
    ws: *Workspace,
    root: Digest,
    to: []const u8,
    stamp: Stamp,
) Error!Digest {
    assert(stamp.changes());
    assert(to.len > 0);
    assert(to[0] == '/');
    ws.objects_written = 0;
    ws.path_len = 0;
    var names = std.mem.tokenizeScalar(u8, to, '/');
    while (names.next()) |name| {
        if (ws.path_len == ws.path.len) {
            context.failure.* = .too_deep;
            return error.Failed;
        }
        ws.path[ws.path_len] = name;
        ws.path_len += 1;
    }
    var depth: u32 = 0;
    try push(context, ws, 0, root, 0, true);
    // Each pass enters a directory or finishes one: a tree has at most `store_walk_entries_max`
    // entries.
    for (0..2 * @as(usize, constants.store_walk_entries_max) + 2) |_| {
        const frame = &ws.frames[depth];
        var child: tree.Entry = undefined;
        if (try next_dir(context, frame, &child)) {
            if (depth + 1 == ws.frames.len) {
                context.failure.* = .too_deep;
                return error.Failed;
            }
            const on_path = on_the_way(ws, frame, depth, &child);
            try push(context, ws, depth + 1, child.subtree, top(frame), on_path);
            depth += 1;
            continue;
        }
        const digest = try finish(context, ws, frame, depth, stamp);
        if (depth == 0) return digest;
        depth -= 1;
        try append(context, ws, &ws.frames[depth], digest);
    }
    unreachable; // The bound above is more than the walk can take.
}

/// Where the frame's region of the arena ends.
fn top(frame: *const Frame) u32 {
    return frame.at + frame.len + frame.finished * constants.store_digest_bytes;
}

/// True if `entry`, in the frame's directory at `depth`, is a directory on the way to `.to` (or
/// `.to` itself).
fn on_the_way(
    ws: *const Workspace,
    frame: *const Frame,
    depth: u32,
    entry: *const tree.Entry,
) bool {
    assert(depth < ws.frames.len);
    assert(ws.path_len <= ws.path.len);
    if (!frame.on_path) return false;
    if (entry.kind != .dir) return false;
    if (depth >= ws.path_len) return false;
    return std.mem.eql(u8, entry.name, ws.path[depth]);
}

fn push(
    context: Context,
    ws: *Workspace,
    depth: u32,
    dir: Digest,
    at: u32,
    on_path: bool,
) Error!void {
    assert(depth < ws.frames.len);
    assert(at <= ws.arena.len);
    // Read into `out`, which is free until a directory is finished, so a tree is checked whole
    // before the arena is asked for its room.
    var errno: u16 = 0;
    const bytes = trees.load(context.store, dir, &ws.out, &errno) catch |err| {
        if (err == error.Damaged) {
            context.failure.* = .{ .damaged = dir };
        } else {
            context.failure.* = .{ .io = .{
                .err = error.IoFailed,
                .errno = errno,
                .step = "reading a tree to copy",
            } };
        }
        return error.Failed;
    };
    if (bytes.len > ws.arena.len - at) {
        context.failure.* = .too_large;
        return error.Failed;
    }
    const kept = ws.arena[at..][0..bytes.len];
    @memcpy(kept, bytes);
    const frame = &ws.frames[depth];
    frame.* = .{
        .dir = dir,
        .on_path = on_path,
        .at = at,
        .len = @intCast(bytes.len),
        .decoder = undefined,
        .finished = 0,
    };
    frame.decoder.init(kept) catch return damaged(context, dir);
}

fn damaged(context: Context, dir: Digest) Error {
    context.failure.* = .{ .damaged = dir };
    return error.Failed;
}

/// The next subdirectory of the frame not yet entered, in `entry`; false when every one is.
fn next_dir(context: Context, frame: *Frame, entry: *tree.Entry) Error!bool {
    assert(frame.len > 0);
    while (frame.decoder.next(entry) catch return damaged(context, frame.dir)) {
        if (entry.kind == .dir) return true;
    }
    return false;
}

/// A finished subdirectory's stamped digest, kept after its parent's bytes.
fn append(context: Context, ws: *Workspace, frame: *Frame, digest: Digest) Error!void {
    const at = top(frame);
    if (constants.store_digest_bytes > ws.arena.len - at) {
        context.failure.* = .too_large;
        return error.Failed;
    }
    @memcpy(ws.arena[at..][0..constants.store_digest_bytes], &digest.bytes);
    frame.finished += 1;
}

/// The frame's directory written with every entry stamped and its subdirectories replaced by
/// their stamped digests, in order.
fn finish(
    context: Context,
    ws: *Workspace,
    frame: *const Frame,
    depth: u32,
    stamp: Stamp,
) Error!Digest {
    const bytes = ws.arena[frame.at..][0..frame.len];
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return damaged(context, frame.dir);
    var writer = tree.Writer.init(&ws.out);
    var entry: tree.Entry = undefined;
    var subdirs: u32 = 0;
    while (decoder.next(&entry) catch return damaged(context, frame.dir)) {
        const owner_only: Stamp = .{ .owner = stamp.owner };
        const kept = on_the_way(ws, frame, depth, &entry);
        var result = stamped(&entry, if (kept) owner_only else stamp);
        const r = &result;
        writer.begin(r.name, r.kind, r.mode, r.uid, r.gid, r.xattrs) catch {
            return too_large(context);
        };
        switch (result.kind) {
            .file => {
                try put_object(context, ws, &entry, &result);
                writer.end_file(result.size, result.content, result.object) catch
                    return too_large(context);
            },
            .symlink => writer.end_symlink(result.target) catch return too_large(context),
            .dir => {
                assert(subdirs < frame.finished);
                const at = frame.at + frame.len + subdirs * constants.store_digest_bytes;
                result.subtree = .{ .bytes = ws.arena[at..][0..constants.store_digest_bytes].* };
                subdirs += 1;
                writer.end_dir(result.subtree) catch return too_large(context);
            },
        }
    }
    assert(subdirs == frame.finished);
    const written = if (depth == 0)
        writer.finish_with(decoder.own) catch return too_large(context)
    else
        writer.finish();
    const digest = Digest.of(written);
    var noted: object.Failure = undefined;
    _ = trees.put(context.store, digest, written, &noted) catch
        return io_failed(context, noted.err, noted.errno, "writing a copied tree with its owner");
    return digest;
}

fn too_large(context: Context) Error {
    context.failure.* = .too_large;
    return error.Failed;
}

/// The object of the stamped file, copied from the source's object with the new attributes,
/// unless the store has it.
fn put_object(
    context: Context,
    ws: *Workspace,
    source: *const tree.Entry,
    result: *const tree.Entry,
) Error!void {
    assert(source.kind == .file);
    assert(result.content.eql(source.content));
    const store = context.store;
    if (result.object.eql(source.object)) return;
    const present = object.has(store, result.object) catch |err| {
        return io_failed(context, err, store.fs.last_errno(), "looking up a copied file's object");
    };
    if (present) return;
    const chunks = object.chunk_hashes(store, source.object, &ws.io, &ws.chunks) catch |err| {
        return io_failed(context, err, store.fs.last_errno(), "reading a copied file's chunks");
    };
    const content: object.Content = .{
        .size = source.size,
        .hash = source.content,
        .chunks = chunks,
    };
    const attrs: object.Attrs = .{
        .mode = result.mode,
        .uid = result.uid,
        .gid = result.gid,
        .xattrs = result.xattrs,
    };
    var path: fs_mod.PathBuf = undefined;
    const from = store.object_path(&path, source.object);
    var failure: object.Failure = undefined;
    const id = result.object;
    object.put(store, &ws.io, &ws.scratch, from, &content, attrs, id, &failure) catch |err| {
        if (err == error.Changed) return damaged(context, source.object);
        const step = "writing a copied file with its owner";
        return io_failed(context, failure.err, failure.errno, step);
    };
    ws.objects_written += 1;
}

fn io_failed(context: Context, err: host_mod.Error, errno: u16, step: []const u8) Error {
    assert(step.len > 0);
    context.failure.* = .{ .io = .{ .err = err, .errno = errno, .step = step } };
    return error.Failed;
}
