//! The selection of a copy entry (docs/briefs/M9-dockerfile-import.md, `.copy`): the paths a
//! source tree's `.src` patterns match, laid out under the entry's `.to` as a tree of their own.
//! That tree is what a copy's key holds (`key.Copy.source`), so a file the patterns do not take
//! never changes the key, and what the step's output is made of (`lay`).
//!
//! Docker's rules, as far as a tree can show them: a matched directory puts its contents into
//! `to`; a matched file or link goes to `to/<name>` when `to` ends in `/`, and to `to` itself
//! when it does not; a later match replaces an earlier one at the same path. Directories on the
//! way are made, 0755 0:0. Owners and modes are kept as the source tree has them.
//!
//! The walk of the source tree has an explicit stack and keeps only digests: a frame is resumed
//! by loading its directory again and skipping what it has seen, so memory is one tree buffer
//! whatever the depth. Everything it matches is held in a pool of `build_glob_matches_max`
//! entries and `build_glob_pool_bytes_max` bytes: more is `PoolFull` (E0818).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const assemble = @import("assemble.zig");
const glob = @import("glob.zig");
const input_tree = @import("input_tree.zig");
const digest_mod = @import("../store/digest.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");

const Digest = digest_mod.Digest;

pub const Error = error{ Failed, PoolFull, NoMatch };

/// One matched entry, its strings in `Workspace.bytes`.
const Item = struct {
    name_at: u32,
    name_len: u16,
    kind: tree.Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    content: Digest,
    object: Digest,
    subtree: Digest,
    target_at: u32,
    target_len: u16,
    xattrs_at: u32,
    xattrs_len: u16,
    /// The whole source tree (`.` or `/`): a directory with no name.
    whole: bool,
};

const Frame = struct {
    dir: Digest,
    /// Entries of the directory already looked at.
    next: u32,
    path_len: u32,
};

pub const Workspace = struct {
    assemble: assemble.Workspace,
    tree: [constants.store_tree_bytes_max]u8,
    out: [constants.store_tree_bytes_max]u8,
    frames: [constants.store_depth_max + 1]Frame,
    path: [constants.path_bytes_max + 1]u8,
    items: [constants.build_glob_matches_max]Item,
    items_count: u32,
    bytes: [constants.build_glob_pool_bytes_max]u8,
    bytes_used: u32,
    /// Set with `PoolFull`: the pattern being matched.
    failed_pattern: u32,
};

/// The pattern as the tree sees it: no leading `/` or `./`, no trailing `/`. Empty is the whole
/// tree.
pub fn normalise(pattern: []const u8) []const u8 {
    var text = pattern;
    while (true) {
        if (std.mem.startsWith(u8, text, "/")) {
            text = text[1..];
        } else if (std.mem.startsWith(u8, text, "./")) {
            text = text[2..];
        } else break;
    }
    while (std.mem.endsWith(u8, text, "/")) text = text[0 .. text.len - 1];
    if (std.mem.eql(u8, text, ".")) return "";
    return text;
}

/// Lays what `patterns` match in `source` under `to`, in a tree of its own (its root is a plain
/// directory). `NoMatch` if nothing matched; `PoolFull` has `ws.failed_pattern`.
pub fn select(
    context: assemble.Context,
    ws: *Workspace,
    source: Digest,
    patterns: []const []const u8,
    to: []const u8,
) Error!Digest {
    assert(patterns.len > 0);
    assert(patterns.len <= constants.build_copy_sources_max);
    assert(to.len > 0);
    assert(to[0] == '/');
    ws.items_count = 0;
    ws.bytes_used = 0;
    try collect(context, ws, source, patterns);
    if (ws.items_count == 0) return error.NoMatch;
    assert(ws.items_count <= ws.items.len);
    const merging: assemble.Context = .{
        .store = context.store,
        .ws = &ws.assemble,
        .failure = context.failure,
        .replace = true,
    };
    var selection = assemble.empty(merging) catch return error.Failed;
    for (ws.items[0..ws.items_count]) |*item| {
        selection = try place(merging, ws, selection, item, to);
    }
    return selection;
}

fn load(context: assemble.Context, ws: *Workspace, digest: Digest) Error![]const u8 {
    var errno: u16 = 0;
    return trees.load(context.store, digest, &ws.tree, &errno) catch |err| {
        if (err == error.Damaged) {
            context.failure.* = .{ .damaged = digest };
        } else {
            context.failure.* = .{ .io = .{
                .err = error.IoFailed,
                .errno = errno,
                .step = "reading a copy source",
            } };
        }
        return error.Failed;
    };
}

fn damaged(context: assemble.Context, digest: Digest) Error {
    context.failure.* = .{ .damaged = digest };
    return error.Failed;
}

fn keep(ws: *Workspace, text: []const u8) ?u32 {
    if (text.len > ws.bytes.len - ws.bytes_used) return null;
    const at = ws.bytes_used;
    @memcpy(ws.bytes[at..][0..text.len], text);
    ws.bytes_used += @intCast(text.len);
    return at;
}

/// Adds `entry` (its name is `name`) to the pool.
fn add(ws: *Workspace, entry: *const tree.Entry, name: []const u8, pattern: u32) Error!void {
    const full = error.PoolFull;
    ws.failed_pattern = pattern;
    if (ws.items_count == ws.items.len) return full;
    const name_at = keep(ws, name) orelse return full;
    const target_at = keep(ws, entry.target) orelse return full;
    const xattrs_at = keep(ws, entry.xattrs) orelse return full;
    ws.items[ws.items_count] = .{
        .name_at = name_at,
        .name_len = @intCast(name.len),
        .kind = entry.kind,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = entry.size,
        .content = entry.content,
        .object = entry.object,
        .subtree = entry.subtree,
        .target_at = target_at,
        .target_len = @intCast(entry.target.len),
        .xattrs_at = xattrs_at,
        .xattrs_len = @intCast(entry.xattrs.len),
        .whole = false,
    };
    ws.items_count += 1;
}

fn collect(
    context: assemble.Context,
    ws: *Workspace,
    source: Digest,
    patterns: []const []const u8,
) Error!void {
    var wanted: [constants.build_copy_sources_max][]const u8 = undefined;
    for (patterns, 0..) |pattern, at| {
        wanted[at] = normalise(pattern);
        if (wanted[at].len == 0) {
            // The whole tree: its contents are the one match.
            ws.failed_pattern = @intCast(at);
            const zero = std.mem.zeroes(Digest);
            ws.items[0] = .{
                .name_at = 0,
                .name_len = 0,
                .kind = .dir,
                .mode = 0,
                .uid = 0,
                .gid = 0,
                .size = 0,
                .content = zero,
                .object = zero,
                .subtree = source,
                .target_at = 0,
                .target_len = 0,
                .xattrs_at = 0,
                .xattrs_len = 0,
                .whole = true,
            };
            ws.items_count = 1;
            return;
        }
    }
    ws.frames[0] = .{ .dir = source, .next = 0, .path_len = 0 };
    var depth: u32 = 0;
    // Each pass enters a directory or ends a frame: a tree has at most `store_walk_entries_max`
    // entries, and each is entered once.
    for (0..2 * @as(usize, constants.store_walk_entries_max)) |_| {
        const entered = try step(context, ws, depth, wanted[0..patterns.len]);
        if (entered) |dir| {
            if (depth + 1 == ws.frames.len) {
                context.failure.* = .too_deep;
                return error.Failed;
            }
            depth += 1;
            ws.frames[depth] = .{ .dir = dir.digest, .next = 0, .path_len = dir.path_len };
        } else {
            if (depth == 0) return;
            depth -= 1;
        }
    }
    unreachable; // The bound above is more than the walk can take.
}

const Entered = struct { digest: Digest, path_len: u32 };

/// Looks at entries of the frame at `depth` until one directory is to be entered (returned) or
/// the frame is done (null).
fn step(
    context: assemble.Context,
    ws: *Workspace,
    depth: u32,
    wanted: []const []const u8,
) Error!?Entered {
    const frame = &ws.frames[depth];
    const bytes = try load(context, ws, frame.dir);
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return damaged(context, frame.dir);
    var entry: tree.Entry = undefined;
    for (0..frame.next) |_| {
        _ = decoder.next(&entry) catch return damaged(context, frame.dir);
    }
    while (decoder.next(&entry) catch return damaged(context, frame.dir)) {
        frame.next += 1;
        const length = join(ws, frame.path_len, entry.name);
        const path = ws.path[0..length];
        var matched: ?u32 = null;
        var below = false;
        for (wanted, 0..) |pattern, at| {
            if (glob.matches(pattern, path)) {
                matched = @intCast(at);
                break;
            }
            if (entry.kind == .dir and input_tree.could_match_below(pattern, path)) below = true;
        }
        if (matched) |at| {
            try add(ws, &entry, entry.name, at);
        } else if (below) {
            return .{ .digest = entry.subtree, .path_len = length };
        }
    }
    return null;
}

/// `ws.path` holding the directory's path and `name` after it; the new length.
fn join(ws: *Workspace, directory_len: u32, name: []const u8) u32 {
    var length = directory_len;
    if (length > 0) {
        ws.path[length] = '/';
        length += 1;
    }
    assert(length + name.len <= ws.path.len);
    @memcpy(ws.path[length..][0..name.len], name);
    return length + @as(u32, @intCast(name.len));
}

/// The tree of one matched entry laid at its place, merged into `selection`.
fn place(
    context: assemble.Context,
    ws: *Workspace,
    selection: Digest,
    item: *const Item,
    to: []const u8,
) Error!Digest {
    assert(context.replace);
    const slashed = to[to.len - 1] == '/';
    const trimmed = std.mem.trimEnd(u8, to, "/");
    if (item.kind == .dir) {
        const at = if (trimmed.len == 0) "/" else trimmed;
        return assemble.lay(context, selection, item.subtree, at) catch error.Failed;
    }
    var name: []const u8 = ws.bytes[item.name_at..][0..item.name_len];
    var parent: []const u8 = if (trimmed.len == 0) "/" else trimmed;
    if (!slashed) {
        const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse 0;
        name = trimmed[slash + 1 ..];
        parent = if (slash == 0) "/" else trimmed[0..slash];
    }
    if (!tree.name_is_valid(name)) {
        context.failure.* = .too_deep;
        return error.Failed;
    }
    var writer = tree.Writer.init(&ws.out);
    const xattrs = ws.bytes[item.xattrs_at..][0..item.xattrs_len];
    writer.begin(name, item.kind, item.mode, item.uid, item.gid, xattrs) catch
        return error.Failed;
    switch (item.kind) {
        .file => writer.end_file(item.size, item.content, item.object) catch return error.Failed,
        .symlink => {
            const target = ws.bytes[item.target_at..][0..item.target_len];
            writer.end_symlink(target) catch return error.Failed;
        },
        .dir => unreachable, // Handled above.
    }
    const leaf = assemble.put(context, writer.finish()) catch return error.Failed;
    return assemble.lay(context, selection, leaf, parent) catch error.Failed;
}
