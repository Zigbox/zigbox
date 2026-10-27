//! `store verify`: rehash everything the store holds against its name, and say what is wrong
//! and where it matters.
//!
//!   - Every **file object** is read, and its id recomputed from the hash of its bytes and its
//!     real mode, owner and attributes (an id is the hash of a header, not of the bytes: a
//!     changed mode is as much damage as a changed byte). Its chunk list is recomputed and
//!     compared with the stored one; a stored list without an object, or beside an object too
//!     short to have one, is damage too.
//!   - Every **tree object** is read and must hash to its name and decode.
//!   - Every **root record** must be readable, and the tree below it must be whole: every
//!     subtree present, every file's object present.
//!
//! A damaged thing is recorded once, with its kind. When anything is damaged a second pass
//! walks every root's tree again, keeping paths, and records for each damaged thing the paths
//! (at most `store_verify_paths_max` of them) of every root tree that reaches it, so the report
//! can say which files of which images a damaged object breaks.
//!
//! All memory is the caller's. Nothing is written. A read that fails is damage of the file it
//! failed on (with its errno), not a reason to stop; only a directory that can not be listed
//! stops the run.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const roots = @import("roots.zig");
const sets = @import("sets.zig");
const shards = @import("shards.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");
const walk = @import("walk.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Class = enum { object, tree, root };

pub const Kind = enum {
    /// The bytes and attributes do not hash to the object's name.
    content,
    /// The chunk list is missing, extra, unreadable or does not match the bytes.
    chunk_list,
    /// The file could not be read; `errno` says why.
    unreadable,
    /// Something that is not a regular file is where an object or tree belongs.
    not_a_file,
    /// A tree object does not hash to its name or does not decode.
    tree_damaged,
    /// A tree a root reaches is not in the store.
    tree_missing,
    /// An object a tree names is not in the store.
    object_missing,
    /// A root record that can not be read or understood.
    root_unusable,

    pub fn words(kind: Kind) []const u8 {
        assert(@tagName(kind).len < 32);
        assert(@tagName(kind).len > 0);
        return switch (kind) {
            .content => "its bytes and attributes do not hash to its name",
            .chunk_list => "its chunk list is missing, extra or does not match its bytes",
            .unreadable => "it can not be read",
            .not_a_file => "it is not a regular file",
            .tree_damaged => "it does not hash to its name or does not decode",
            .tree_missing => "it is missing from the store",
            .object_missing => "it is missing from the store",
            .root_unusable => "the root record can not be read or understood",
        };
    }
};

/// One damaged thing.
pub const Damage = struct {
    id: Digest,
    class: Class,
    kind: Kind,
    /// The errno of a failed read, else 0.
    errno: u16,
    /// How many paths in root trees reach it, and how many of those are in `Workspace.refs`.
    reached: u32,
    listed: u32,
};

/// A path in a root's tree that reaches a damaged thing.
pub const Ref = struct {
    damage: u32,
    root: Digest,
    path_at: u32,
    path_len: u16,
};

pub const Totals = struct {
    objects: u64 = 0,
    object_bytes: u64 = 0,
    chunk_lists: u64 = 0,
    /// Chunk lists with no object beside them: what a killed import or gc leaves. Not damage;
    /// the next gc moves them away.
    orphan_lists: u64 = 0,
    trees: u64 = 0,
    roots: u64 = 0,
    /// Names that are none of the above (left alone).
    strays: u64 = 0,
    /// Damaged things found, including those past `store_verify_damaged_max`.
    damaged: u64 = 0,
    /// The reverse pass ran out of room for paths or entries, so some are not listed.
    paths_truncated: bool = false,
};

/// The caller's memory, about 8 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    io: [constants.store_io_buffer_bytes]u8,
    chunks: [constants.store_chunks_max]Digest,
    list: [constants.store_chunks_max]Digest,
    list_bytes: [constants.store_chunks_max * constants.store_digest_bytes]u8,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    damage: [constants.store_verify_damaged_max]Damage,
    damage_count: u32,
    damage_index: [24 * 1024]u8 align(8),
    refs: [constants.store_verify_damaged_max * constants.store_verify_paths_max]Ref,
    ref_count: u32,
    ref_paths: [1 << 20]u8,
    ref_paths_used: u32,
    frames: [8192]Frame,
    frame_paths: [1 << 20]u8,
    current: [constants.path_bytes_max + 1]u8,
    builder: xattrs.Builder,
    blob: [constants.store_xattr_blob_bytes_max]u8,
    xattr_names: [8192]u8,
    xattr_value: [constants.store_xattr_value_bytes_max + 1]u8,

    pub fn damage_slice(ws: *const Workspace) []const Damage {
        assert(ws.damage_count <= ws.damage.len);
        assert(ws.damage.len == constants.store_verify_damaged_max);
        assert(ws.damage_count <= ws.damage.len);
        return ws.damage[0..ws.damage_count];
    }

    pub fn ref_path(ws: *const Workspace, ref: *const Ref) []const u8 {
        assert(ref.path_at <= ws.ref_paths.len);
        assert(ref.path_len <= constants.path_bytes_max);
        assert(ref.path_at + ref.path_len <= ws.ref_paths.len);
        return ws.ref_paths[ref.path_at..][0..ref.path_len];
    }
};

const Frame = struct { digest: Digest, path_at: u32, path_len: u16 };

/// The caller's working memory for names, tables and the walk: split here as `arena_bytes`.
pub const arena_bytes: u32 = names_bytes + offsets_bytes + seen_bytes + visited_bytes + stack_bytes;
const names_bytes: u32 = 4 * 1024 * 1024;
const offsets_bytes: u32 = 1024 * 1024;
const seen_bytes: u32 = 6 * 1024 * 1024;
const visited_bytes: u32 = 2 * 1024 * 1024;
const stack_bytes: u32 = 1024 * 1024;

/// Why verification could not finish (not damage: a store it could not even list).
pub const Failure = struct {
    err: host_mod.Error,
    errno: u16,
    step: []const u8,
};

pub const Error = error{Failed};

const Run = struct {
    store: *const Store,
    ws: *Workspace,
    totals: *Totals,
    failure: *Failure,
    names: []u8,
    offsets: []u32,
    seen: sets.DigestMap,
    visited: sets.DigestMap,
    stack: []Digest,
    index: sets.DigestMap,

    fn stop(run: *Run, step: []const u8, err: host_mod.Error) Error {
        assert(step.len > 0);
        assert(@intFromPtr(run.failure) != 0);
        run.failure.* = .{ .err = err, .errno = run.store.fs.last_errno(), .step = step };
        return error.Failed;
    }

    /// Records damage, once per id.
    fn damage(run: *Run, id: Digest, class: Class, kind: Kind, errno: u16) void {
        assert(run.totals.damaged < 1 << 40);
        assert(errno < 4096);
        const ws = run.ws;
        if (run.index.get(id) != null) return;
        run.totals.damaged += 1;
        if (ws.damage_count == ws.damage.len) return;
        if (run.index.put(id, ws.damage_count) == .full) return;
        ws.damage[ws.damage_count] = .{
            .id = id,
            .class = class,
            .kind = kind,
            .errno = errno,
            .reached = 0,
            .listed = 0,
        };
        ws.damage_count += 1;
    }
};

/// Verifies the store. `arena` is at least `arena_bytes`. Damage is in `ws`; `totals` counts.
pub fn verify(
    store: *const Store,
    ws: *Workspace,
    arena: []align(8) u8,
    totals: *Totals,
    failure: *Failure,
) Error!void {
    assert(@intFromPtr(ws) != 0);
    assert(@intFromPtr(failure) != 0);
    assert(arena.len >= arena_bytes);
    totals.* = .{};
    ws.damage_count = 0;
    ws.ref_count = 0;
    ws.ref_paths_used = 0;
    var at: usize = names_bytes + offsets_bytes;
    var run: Run = .{
        .store = store,
        .ws = ws,
        .totals = totals,
        .failure = failure,
        .names = arena[0..names_bytes],
        .offsets = @alignCast(std.mem.bytesAsSlice(u32, arena[names_bytes..][0..offsets_bytes])),
        .seen = sets.DigestMap.init(@alignCast(arena[at..][0..seen_bytes])),
        .visited = undefined,
        .stack = undefined,
        .index = sets.DigestMap.init(&ws.damage_index),
    };
    at += seen_bytes;
    run.visited = sets.DigestMap.init(@alignCast(arena[at..][0..visited_bytes]));
    at += visited_bytes;
    run.stack = @alignCast(std.mem.bytesAsSlice(Digest, arena[at..][0..stack_bytes]));
    try verify_objects(&run);
    try verify_trees(&run);
    try verify_roots(&run);
    if (ws.damage_count > 0) try find_paths(&run);
    sort_refs(ws);
}

// ---- Objects -------------------------------------------------------------------------------

fn verify_objects(run: *Run) Error!void {
    assert(run.names.len > 0);
    assert(run.ws.damage_count == 0);
    assert(run.offsets.len > 0);
    for (0..constants.store_shards_count) |shard| {
        const found = shards.read(
            run.store,
            run.names,
            run.offsets,
            "objects",
            @intCast(shard),
        ) catch |err| {
            return run.stop("listing a shard of the objects", err);
        };
        var index: u32 = 0;
        while (index < found.count()) : (index += 1) {
            const name = found.name(index);
            if (shards.list_base(name)) |base| {
                run.totals.chunk_lists += 1;
                const previous = if (index > 0) found.name(index - 1) else "";
                if (std.mem.eql(u8, previous, base)) continue;
                if (shards.id_of(@intCast(shard), base) == null) {
                    run.totals.strays += 1;
                } else {
                    run.totals.orphan_lists += 1;
                }
                continue;
            }
            const id = shards.id_of(@intCast(shard), name) orelse {
                run.totals.strays += 1;
                continue;
            };
            const next = if (index + 1 < found.count()) found.name(index + 1) else "";
            const has_list = next.len == name.len + layout.chunks_suffix.len and
                std.mem.startsWith(u8, next, name) and shards.list_base(next) != null;
            check_object(run, id, has_list);
        }
    }
}

fn check_object(run: *Run, id: Digest, has_list: bool) void {
    assert(run.store.root_len > 1);
    assert(id.bytes.len == constants.store_digest_bytes);
    const store = run.store;
    const fs = store.fs;
    const ws = run.ws;
    run.totals.objects += 1;
    var path_storage: PathBuf = undefined;
    const path = store.object_path(&path_storage, id);
    const stat = fs.lstat(path) catch {
        return run.damage(id, .object, .unreadable, fs.last_errno());
    };
    if (stat.kind != .file) return run.damage(id, .object, .not_a_file, 0);
    run.totals.object_bytes += stat.size;
    const fd = fs.open_read(path) catch {
        return run.damage(id, .object, .unreadable, fs.last_errno());
    };
    defer fs.close(fd);
    var reader = object.Reader.init(store.chunk_bytes);
    while (true) {
        const count = fs.read(fd, &ws.io) catch {
            return run.damage(id, .object, .unreadable, fs.last_errno());
        };
        if (count == 0) break;
        if (!reader.update(ws.io[0..count], &ws.chunks)) {
            return run.damage(id, .object, .content, 0);
        }
    }
    const content = reader.finish(&ws.chunks);
    const blob = gather_xattrs(run, path) orelse {
        return run.damage(id, .object, .unreadable, fs.last_errno());
    };
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = blob,
    };
    if (!object.object_id(content, attrs).eql(id)) return run.damage(id, .object, .content, 0);
    const expects = object.list_is_stored(reader.size, store.chunk_bytes);
    if (expects != has_list) return run.damage(id, .object, .chunk_list, 0);
    if (!expects) return;
    const listed = object.read_chunk_list(store, id, &ws.list_bytes, &ws.list) catch {
        return run.damage(id, .object, .chunk_list, fs.last_errno());
    };
    if (listed.len != reader.count) return run.damage(id, .object, .chunk_list, 0);
    for (listed, ws.chunks[0..reader.count]) |have, want| {
        if (!have.eql(want)) return run.damage(id, .object, .chunk_list, 0);
    }
}

/// The canonical attribute section of a stored object, as the importer would have built it.
fn gather_xattrs(run: *Run, path: [:0]const u8) ?[]const u8 {
    assert(path.len > 0);
    assert(run.ws.xattr_names.len > 0);
    const ws = run.ws;
    const fs = run.store.fs;
    ws.builder.reset();
    const listed = fs.list_xattrs(path, &ws.xattr_names) catch return null;
    var start: usize = 0;
    while (start < listed.len) {
        const end = std.mem.indexOfScalarPos(u8, listed, start, 0) orelse break;
        const name = listed[start..end :0];
        start = end + 1;
        if (name.len == 0 or xattrs.class_of(name) != .keep) continue;
        const value = fs.get_xattr(path, name, &ws.xattr_value) catch return null;
        ws.builder.add(name, value) catch return null;
    }
    return ws.builder.finish(&ws.blob);
}

// ---- Trees and roots -----------------------------------------------------------------------

fn verify_trees(run: *Run) Error!void {
    assert(run.names.len > 0);
    assert(run.offsets.len > 0);
    assert(run.offsets.len > 0);
    for (0..constants.store_shards_count) |shard| {
        const found = shards.read(
            run.store,
            run.names,
            run.offsets,
            "trees",
            @intCast(shard),
        ) catch |err| {
            return run.stop("listing a shard of the trees", err);
        };
        var index: u32 = 0;
        while (index < found.count()) : (index += 1) {
            const id = shards.id_of(@intCast(shard), found.name(index)) orelse {
                run.totals.strays += 1;
                continue;
            };
            run.totals.trees += 1;
            check_tree(run, id);
        }
    }
}

fn check_tree(run: *Run, id: Digest) void {
    assert(run.ws.tree_buffer.len >= constants.store_tree_bytes_max);
    assert(id.bytes.len == constants.store_digest_bytes);
    var errno: u16 = 0;
    const bytes = trees.load(run.store, id, &run.ws.tree_buffer, &errno) catch |err| {
        return switch (err) {
            error.Damaged => run.damage(id, .tree, .tree_damaged, 0),
            error.NotFound => run.damage(id, .tree, .tree_missing, 0),
            error.Unreadable => run.damage(id, .tree, .unreadable, errno),
        };
    };
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return run.damage(id, .tree, .tree_damaged, 0);
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch return run.damage(id, .tree, .tree_damaged, 0)) {}
}

/// The visitor of the reference pass: every file's object must be in the store.
const Present = struct {
    run: *Run,

    pub fn entry(present: *Present, found: *const tree.Entry) void {
        if (found.kind != .file) return;
        const run = present.run;
        if (run.seen.put(found.object, 0) != .inserted) return;
        var path: PathBuf = undefined;
        _ = run.store.fs.lstat(run.store.object_path(&path, found.object)) catch |err| {
            const kind: Kind = if (err == error.NotFound) .object_missing else .unreadable;
            run.damage(found.object, .object, kind, run.store.fs.last_errno());
        };
    }
};

fn verify_roots(run: *Run) Error!void {
    assert(run.names.len > 0);
    assert(run.stack.len > 0);
    assert(run.offsets.len > 0);
    const found = shards.read(run.store, run.names, run.offsets, "roots", null) catch |err| {
        return run.stop("listing the roots", err);
    };
    var present: Present = .{ .run = run };
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const digest = Digest.from_hex(found.name(index)) orelse {
            run.totals.strays += 1;
            continue;
        };
        run.totals.roots += 1;
        var record: roots.Root = undefined;
        var errno: u16 = 0;
        roots.load(run.store, digest, &record, &errno) catch {
            run.damage(digest, .root, .root_unusable, errno);
            continue;
        };
        var failed: walk.Failure = undefined;
        walk.walk(
            run.store,
            &run.ws.tree_buffer,
            run.stack,
            &run.visited,
            digest,
            &present,
            &failed,
        ) catch {
            switch (failed.kind) {
                .missing => run.damage(failed.where, .tree, .tree_missing, 0),
                .damaged => run.damage(failed.where, .tree, .tree_damaged, 0),
                .unreadable => run.damage(failed.where, .tree, .unreadable, failed.errno),
                .too_many_entries, .stack_full => return run.stop(
                    "walking a root's tree",
                    error.FileTooLarge,
                ),
            }
        };
    }
}

// ---- Paths ---------------------------------------------------------------------------------

fn find_paths(run: *Run) Error!void {
    assert(run.ws.damage_count > 0);
    assert(run.names.len > 0);
    const found = shards.read(run.store, run.names, run.offsets, "roots", null) catch |err| {
        return run.stop("listing the roots", err);
    };
    var budget: u64 = constants.store_walk_entries_max;
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const digest = Digest.from_hex(found.name(index)) orelse continue;
        var record: roots.Root = undefined;
        var errno: u16 = 0;
        roots.load(run.store, digest, &record, &errno) catch continue;
        walk_paths(run, digest, &budget);
    }
}

/// Walks one root's tree depth first, with paths, adding a ref for every entry that is damaged.
fn walk_paths(run: *Run, root: Digest, budget: *u64) void {
    assert(run.ws.damage_count > 0);
    assert(budget.* <= constants.store_walk_entries_max);
    const ws = run.ws;
    var top: u32 = 0;
    var used: u32 = 0;
    if (run.index.get(root) == null) {
        ws.frames[0] = .{ .digest = root, .path_at = 0, .path_len = 0 };
        top = 1;
    } else {
        add_ref(run, root, root, "/");
    }
    while (top > 0) {
        top -= 1;
        const frame = ws.frames[top];
        @memcpy(ws.current[0..frame.path_len], ws.frame_paths[frame.path_at..][0..frame.path_len]);
        used = frame.path_at;
        const path_len: u32 = frame.path_len;
        var errno: u16 = 0;
        const bytes = trees.load(run.store, frame.digest, &ws.tree_buffer, &errno) catch continue;
        var decoder: tree.Decoder = undefined;
        decoder.init(bytes) catch continue;
        var entry: tree.Entry = undefined;
        while (decoder.next(&entry) catch false) {
            if (budget.* == 0) {
                run.totals.paths_truncated = true;
                return;
            }
            budget.* -= 1;
            if (path_len + 1 + entry.name.len > constants.path_bytes_max) {
                run.totals.paths_truncated = true;
                continue;
            }
            ws.current[path_len] = '/';
            @memcpy(ws.current[path_len + 1 ..][0..entry.name.len], entry.name);
            const child = ws.current[0 .. path_len + 1 + entry.name.len];
            switch (entry.kind) {
                .symlink => {},
                .file => if (run.index.get(entry.object) != null) add_ref(
                    run,
                    entry.object,
                    root,
                    child,
                ),
                .dir => {
                    if (run.index.get(entry.subtree) != null) add_ref(
                        run,
                        entry.subtree,
                        root,
                        child,
                    );
                    if (top == ws.frames.len or used + child.len > ws.frame_paths.len) {
                        run.totals.paths_truncated = true;
                        continue;
                    }
                    @memcpy(ws.frame_paths[used..][0..child.len], child);
                    ws.frames[top] = .{
                        .digest = entry.subtree,
                        .path_at = used,
                        .path_len = @intCast(child.len),
                    };
                    top += 1;
                    used += @intCast(child.len);
                },
            }
        }
    }
}

fn add_ref(run: *Run, id: Digest, root: Digest, path: []const u8) void {
    assert(path.len > 0);
    assert(path[0] == '/');
    const ws = run.ws;
    const slot = run.index.get(id) orelse return;
    const damage = &ws.damage[@intCast(slot.value)];
    damage.reached += 1;
    if (damage.listed == constants.store_verify_paths_max) return;
    if (ws.ref_paths_used + path.len > ws.ref_paths.len or ws.ref_count == ws.refs.len) {
        run.totals.paths_truncated = true;
        return;
    }
    @memcpy(ws.ref_paths[ws.ref_paths_used..][0..path.len], path);
    ws.refs[ws.ref_count] = .{
        .damage = @intCast(slot.value),
        .root = root,
        .path_at = ws.ref_paths_used,
        .path_len = @intCast(path.len),
    };
    ws.ref_count += 1;
    ws.ref_paths_used += @intCast(path.len);
    damage.listed += 1;
}

fn ref_less(ws: *const Workspace, first: Ref, second: Ref) bool {
    assert(first.damage < constants.store_verify_damaged_max);
    assert(second.damage < constants.store_verify_damaged_max);
    if (first.damage != second.damage) return first.damage < second.damage;
    const order = std.mem.order(u8, &first.root.bytes, &second.root.bytes);
    if (order != .eq) return order == .lt;
    return std.mem.lessThan(u8, ws.ref_path(&first), ws.ref_path(&second));
}

fn sort_refs(ws: *Workspace) void {
    assert(ws.ref_count <= ws.refs.len);
    assert(ws.damage_count <= ws.damage.len);
    std.mem.sortUnstable(Ref, ws.refs[0..ws.ref_count], @as(*const Workspace, ws), ref_less);
}

/// The refs of damage number `index`, in order (a slice of the sorted refs).
pub fn refs_of(ws: *const Workspace, index: u32) []const Ref {
    assert(ws.ref_count <= ws.refs.len);
    assert(index < ws.damage_count);
    var first: u32 = 0;
    while (first < ws.ref_count and ws.refs[first].damage < index) first += 1;
    var end = first;
    while (end < ws.ref_count and ws.refs[end].damage == index) end += 1;
    return ws.refs[first..end];
}
