//! Image assembly (docs/briefs/M7-build.md, "The cache" and "The result"): the base image's tree
//! with each `add` laid over it, in the file's order. An add places the root of a step's output
//! tree at a path: `compile -> /usr/local/bin` puts the output's entries into that directory,
//! making any directory on the way (mode 0755, owner 0:0). A directory both trees have is
//! merged, the base's mode and owner kept; anything else both trees have is a conflict, refused
//! with its path. Nothing is overwritten and nothing is merged silently.
//!
//! The merge works on trees in the store, never on files: a subtree only one side has is taken
//! by its digest. No recursion: a frame stack of at most `store_depth_max + 1` levels. A frame
//! keeps only digests and the results of its finished child merges; resuming it reloads both
//! trees and decodes them again, so memory stays at three tree buffers whatever the depth.
//! Directories two trees have in common are bounded per level (`build_merge_common_max`).
//!
//! Only the root keeps its own mode and owner; an add's root and every other directory is
//! written without (`tree.zig`), so equal contents are equal digests.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const host_mod = @import("../host.zig");
const layout = @import("../store/layout.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// One add: the source's output tree and where its entries go (`/` or `/a/b`, plain).
pub const Add = struct {
    source: Digest,
    to: []const u8,
};

const frames_max = constants.store_depth_max + 1;
const path_bytes = constants.store_path_bytes_max;

const Frame = struct {
    dst: Digest,
    src: Digest,
    /// Common directories merged so far, and their results in the order the join meets them.
    done: u32,
    results: [constants.build_merge_common_max]Digest,
    /// How much of the path is this frame's directory.
    path_len: u32,
};

pub const Workspace = struct {
    dst: [constants.store_tree_bytes_max]u8,
    src: [constants.store_tree_bytes_max]u8,
    out: [constants.store_tree_bytes_max]u8,
    frames: [frames_max]Frame,
    path: [path_bytes]u8,
    names: [constants.store_depth_max + 1][]const u8,
    /// The add that a failure is about: its index in `adds`. Set by `assemble`.
    failed_add: u32,
};

pub const Conflict = struct {
    /// The path in the image, from the root: clipped to `path_bytes`.
    path: [path_bytes]u8,
    path_len: u32,
    /// What the image has there, and what the add brings.
    present: tree.Kind,
    brought: tree.Kind,
};

pub const Failure = union(enum) {
    io: struct { err: host_mod.Error, errno: u16, step: []const u8 },
    damaged: Digest,
    conflict: Conflict,
    /// An add's path, or a merge, deeper than `store_depth_max`.
    too_deep,
    /// A directory past `store_dir_entries_max`, or a tree past `store_tree_bytes_max`.
    too_large,
    /// More than `build_merge_common_max` directories in common at one level.
    too_common,
    /// A part of the destination is longer than `store_name_bytes_max` (the build file refuses
    /// a NUL, an empty, `.` or `..` part before this).
    bad_name,
};

pub const Error = error{Failed};

pub const Context = struct {
    store: *Store,
    ws: *Workspace,
    failure: *Failure,
    /// A copy step's merge (docs/briefs/M9-dockerfile-import.md, `.copy`): where both trees have
    /// a name and they are not both directories, the added entry replaces the image's instead
    /// of being a conflict. Two directories still merge.
    replace: bool = false,
};

/// The image tree: `base` (or an empty tree) with `adds` laid over it in order.
pub fn assemble(context: Context, base: ?Digest, adds: []const Add) Error!Digest {
    assert(adds.len <= constants.build_image_adds_max);
    context.ws.failed_add = 0;
    var image = base orelse try write_empty(context);
    for (adds, 0..) |add, at| {
        context.ws.failed_add = @intCast(at);
        const leaf = try canonical(context, add.source);
        const top = try wrap(context, leaf, add.to);
        image = try merge(context, image, top);
    }
    return image;
}

/// `leaf` (a tree of entries, its own owner ignored) laid at the directory `to` of `base`, with
/// the context's merge rule. The directories on the way are made, 0755 0:0.
pub fn lay(context: Context, base: Digest, leaf: Digest, to: []const u8) Error!Digest {
    assert(to.len > 0);
    assert(to[0] == '/');
    const top = try wrap(context, try canonical(context, leaf), to);
    return merge(context, base, top);
}

/// A tree holding nothing: the start of a selection.
pub fn empty(context: Context) Error!Digest {
    return write_empty(context);
}

/// Which earlier add put what is at `path` (as a `Conflict` holds it) into the image: the last
/// of `adds[0..failed]` whose destination and tree have that path, or null for the base. Only
/// for the message of a conflict, so it reads trees without being quick; any failure to read
/// answers null.
pub fn earlier_source(context: Context, adds: []const Add, failed: u32, path: []const u8) ?u32 {
    assert(failed < adds.len);
    assert(path.len > 0);
    assert(path[0] == '/');
    var at = failed;
    while (at > 0) {
        at -= 1;
        if (has_path(context, adds[at], path)) return at;
    }
    return null;
}

/// Whether the tree the add makes (its source under its destination) has `path`.
fn has_path(context: Context, add: Add, path: []const u8) bool {
    var wanted = std.mem.tokenizeScalar(u8, path, '/');
    var given = std.mem.tokenizeScalar(u8, add.to, '/');
    while (given.next()) |part| {
        const want = wanted.next() orelse return true; // The path is a directory on the way.
        if (!std.mem.eql(u8, want, part)) return false;
    }
    var current = add.source;
    while (wanted.next()) |name| {
        var errno: u16 = 0;
        const bytes = trees.load(context.store, current, &context.ws.dst, &errno) catch {
            return false;
        };
        var decoder: tree.Decoder = undefined;
        decoder.init(bytes) catch return false;
        var entry: tree.Entry = undefined;
        const found = while (decoder.next(&entry) catch return false) {
            if (std.mem.eql(u8, entry.name, name)) break true;
        } else false;
        if (!found) return false;
        if (wanted.peek() == null) return true;
        if (entry.kind != .dir) return false;
        current = entry.subtree;
    }
    return true; // The path is the add's destination itself.
}

fn io_failed(context: Context, err: host_mod.Error, step: []const u8) Error {
    assert(step.len > 0);
    const errno = context.store.fs.last_errno();
    context.failure.* = .{ .io = .{ .err = err, .errno = errno, .step = step } };
    return error.Failed;
}

pub fn put(context: Context, bytes: []const u8) Error!Digest {
    assert(bytes.len <= constants.store_tree_bytes_max);
    const digest = Digest.of(bytes);
    var noted: object.Failure = undefined;
    _ = trees.put(context.store, digest, bytes, &noted) catch {
        context.failure.* = .{ .io = .{
            .err = noted.err,
            .errno = noted.errno,
            .step = "writing an image tree",
        } };
        return error.Failed;
    };
    return digest;
}

fn load(context: Context, digest: Digest, buffer: []u8) Error![]const u8 {
    assert(buffer.len == constants.store_tree_bytes_max);
    var errno: u16 = 0;
    return trees.load(context.store, digest, buffer, &errno) catch |err| {
        if (err == error.Unreadable or err == error.NotFound) {
            context.failure.* = .{ .io = .{
                .err = error.IoFailed,
                .errno = errno,
                .step = "reading an image tree",
            } };
        } else {
            context.failure.* = .{ .damaged = digest };
        }
        return error.Failed;
    };
}

fn write_empty(context: Context) Error!Digest {
    var writer = tree.Writer.init(&context.ws.out);
    const own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = tree.Own.none.xattrs };
    const bytes = writer.finish_with(own) catch unreachable; // An empty tree fits.
    return put(context, bytes);
}

/// Copies one entry into `writer`; false if the writer has no room.
fn emit(writer: *tree.Writer, entry: *const tree.Entry) bool {
    assert(entry.name.len > 0);
    if (writer.count >= constants.store_dir_entries_max) return false;
    const mode = entry.mode;
    writer.begin(entry.name, entry.kind, mode, entry.uid, entry.gid, entry.xattrs) catch {
        return false;
    };
    switch (entry.kind) {
        .file => writer.end_file(entry.size, entry.content, entry.object) catch return false,
        .symlink => writer.end_symlink(entry.target) catch return false,
        .dir => writer.end_dir(entry.subtree) catch return false,
    }
    return true;
}

/// The same entries as a tree with no `own`: how an add's root becomes a plain directory.
fn canonical(context: Context, source: Digest) Error!Digest {
    const ws = context.ws;
    const bytes = try load(context, source, &ws.src);
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return damaged(context, source);
    var writer = tree.Writer.init(&ws.out);
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch return damaged(context, source)) {
        if (!emit(&writer, &entry)) return too_large(context);
    }
    return put(context, writer.finish());
}

fn damaged(context: Context, digest: Digest) Error {
    context.failure.* = .{ .damaged = digest };
    return error.Failed;
}

fn too_large(context: Context) Error {
    context.failure.* = .too_large;
    return error.Failed;
}

/// `leaf` inside one directory per part of `to`, outermost last: the tree to merge.
fn wrap(context: Context, leaf: Digest, to: []const u8) Error!Digest {
    assert(to.len > 0);
    assert(to[0] == '/');
    const ws = context.ws;
    var count: u32 = 0;
    var parts = std.mem.splitScalar(u8, to[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        if (count == ws.names.len) {
            context.failure.* = .too_deep;
            return error.Failed;
        }
        if (!tree.name_is_valid(part)) {
            context.failure.* = .bad_name;
            return error.Failed;
        }
        ws.names[count] = part;
        count += 1;
    }
    var inner = leaf;
    while (count > 0) {
        count -= 1;
        var writer = tree.Writer.init(&ws.out);
        const none = tree.Own.none.xattrs;
        writer.begin(ws.names[count], .dir, 0o755, 0, 0, none) catch unreachable; // Fits.
        writer.end_dir(inner) catch unreachable; // Fits.
        inner = try put(context, writer.finish());
    }
    return inner;
}

// ---- The merge --------------------------------------------------------------------------------

const Step = union(enum) {
    /// A common directory not yet merged: the frame to push.
    descend: struct { dst: Digest, src: Digest, path_len: u32 },
    finished: Digest,
};

pub fn merge(context: Context, dst: Digest, src: Digest) Error!Digest {
    const ws = context.ws;
    ws.frames[0] = .{ .dst = dst, .src = src, .done = 0, .results = undefined, .path_len = 0 };
    var depth: u32 = 0;
    while (true) {
        const frame = &ws.frames[depth];
        switch (try pass(context, frame, depth == 0)) {
            .descend => |next| {
                if (depth + 1 == frames_max) {
                    context.failure.* = .too_deep;
                    return error.Failed;
                }
                depth += 1;
                ws.frames[depth] = .{
                    .dst = next.dst,
                    .src = next.src,
                    .done = 0,
                    .results = undefined,
                    .path_len = next.path_len,
                };
            },
            .finished => |digest| {
                if (depth == 0) return digest;
                depth -= 1;
                const parent = &ws.frames[depth];
                parent.results[parent.done] = digest;
                parent.done += 1;
            },
        }
    }
}

/// One walk over a frame's two directories: the next common directory to merge, or the merged
/// directory written.
fn pass(context: Context, frame: *Frame, root: bool) Error!Step {
    const ws = context.ws;
    const dst_bytes = try load(context, frame.dst, &ws.dst);
    const src_bytes = try load(context, frame.src, &ws.src);
    var join: Join = .{
        .context = context,
        .frame = frame,
        .writer = tree.Writer.init(&ws.out),
        .common = 0,
    };
    join.dd.init(dst_bytes) catch return damaged(context, frame.dst);
    join.sd.init(src_bytes) catch return damaged(context, frame.src);
    if (try join.run()) |step| return step;
    const bytes = if (root)
        join.writer.finish_with(join.dd.own) catch return too_large(context)
    else
        join.writer.finish();
    return .{ .finished = try put(context, bytes) };
}

const Join = struct {
    context: Context,
    frame: *Frame,
    writer: tree.Writer,
    dd: tree.Decoder = undefined,
    sd: tree.Decoder = undefined,
    de: tree.Entry = undefined,
    se: tree.Entry = undefined,
    common: u32,

    /// Joins the two sorted directories into `writer`. A step if a child must be merged first.
    fn run(join: *Join) Error!?Step {
        const context = join.context;
        var have_d = join.dd.next(&join.de) catch return damaged(context, join.frame.dst);
        var have_s = join.sd.next(&join.se) catch return damaged(context, join.frame.src);
        while (have_d or have_s) {
            const order = if (!have_s)
                std.math.Order.lt
            else if (!have_d)
                std.math.Order.gt
            else
                std.mem.order(u8, join.de.name, join.se.name);
            switch (order) {
                .lt => if (!emit(&join.writer, &join.de)) return too_large(context),
                .gt => if (!emit(&join.writer, &join.se)) return too_large(context),
                .eq => if (try join.both()) |step| return step,
            }
            if (order != .gt) have_d = join.dd.next(&join.de) catch {
                return damaged(context, join.frame.dst);
            };
            if (order != .lt) have_s = join.sd.next(&join.se) catch {
                return damaged(context, join.frame.src);
            };
        }
        return null;
    }

    /// A name both have: two directories merge; anything else is a conflict.
    fn both(join: *Join) Error!?Step {
        const context = join.context;
        const de = &join.de;
        const se = &join.se;
        if (de.kind != .dir or se.kind != .dir) {
            if (!context.replace) return join.conflict();
            if (!emit(&join.writer, se)) return too_large(context);
            return null;
        }
        var merged = de.subtree;
        if (!de.subtree.eql(se.subtree)) {
            if (join.common == constants.build_merge_common_max) {
                context.failure.* = .too_common;
                return error.Failed;
            }
            if (join.common == join.frame.done) {
                return .{ .descend = .{
                    .dst = de.subtree,
                    .src = se.subtree,
                    .path_len = join.extend_path(de.name),
                } };
            }
            merged = join.frame.results[join.common];
            join.common += 1;
        }
        var entry = de.*;
        entry.subtree = merged;
        if (!emit(&join.writer, &entry)) return too_large(context);
        return null;
    }

    fn extend_path(join: *Join, name: []const u8) u32 {
        const ws = join.context.ws;
        const start = join.frame.path_len;
        var length = start;
        for ([_][]const u8{ "/", name }) |part| {
            const room = path_bytes - length;
            const taken = @min(room, part.len);
            @memcpy(ws.path[length..][0..taken], part[0..taken]);
            length += @intCast(taken);
        }
        assert(length >= start);
        return length;
    }

    fn conflict(join: *Join) Error {
        const length = join.extend_path(join.de.name);
        var found: Conflict = undefined;
        @memcpy(found.path[0..length], join.context.ws.path[0..length]);
        found.path_len = length;
        found.present = join.de.kind;
        found.brought = join.se.kind;
        join.context.failure.* = .{ .conflict = found };
        return error.Failed;
    }
};
