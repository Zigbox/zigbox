//! `store gc`, in three steps that never prompt: a **plan**, an **apply** that needs the plan's
//! hash, and **restore**, which undoes an apply while its trash lasts.
//!
//! What is kept. A tree is kept if it is below a *root* (a record in `roots/`) or below a tree a
//! *live container* runs (the caller lists those). Everything such a tree names is kept: its
//! subtrees, its file objects, their chunk lists, and a root's or live container's materialized
//! directory in `cache/`. What is not kept is the plan:
//!   - file objects no kept tree names (and their chunk lists), and chunk lists with no object;
//!   - tree objects no kept tree reaches;
//!   - materialized directories (`cache/<digest>`) of a tree that is neither a root nor live;
//!   - leftovers in `tmp/` whose `<pid>-<n>` names a process that is gone (a killed import).
//!
//! The plan hash is the BLAKE3 of `"zbx-gc-plan" 0x01`, the store's generation counter
//! (`generation.zig`, raised by every write) and, in the order of the ids, a tag byte and the id
//! of every object, list, tree and directory the plan would move. `apply` makes the plan again
//! and acts only if it hashes the same; otherwise nothing is touched and the caller gets the new
//! hash. Nothing the hash covers can change without changing the hash.
//!
//! Applying never deletes what it moves. Everything goes by `rename` into
//! `trash/<gc id>/{objects,trees,cache}/...`, where the gc id is the first 12 digits of the plan
//! hash, together with `trash/<gc id>/meta.zon` (when, until when, counts, and whether the move
//! finished). A later gc empties trash whose time is past (`store_trash_seconds` after it was
//! made). `restore` moves a trash back, and refuses if anything in it is already in the store
//! again. A gc that was killed leaves a trash with `.complete = false`; the store is whole at
//! every step because an object is moved before its chunk list (so no object ever lacks its
//! list), and a list moved back before its object. The ordinary rename is the only write.
//!
//! Not safe against another zbx writing at the same time: a plan is a picture of the store, and
//! an import in progress has objects no root reaches yet. Do not run `gc --confirm` while
//! another zbx command that writes to the store is running (docs/demos/m3.md, "Cuts").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const generation = @import("generation.zig");
const layout = @import("layout.zig");
const lock = @import("lock.zig");
const object = @import("object.zig");
const remove = @import("remove.zig");
const roots = @import("roots.zig");
const sets = @import("sets.zig");
const shards = @import("shards.zig");
const tree = @import("tree.zig");
const walk = @import("walk.zig");

const Digest = digest_mod.Digest;
const Hasher = digest_mod.Hasher;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const plan_magic = "zbx-gc-plan\x01";
pub const meta_file = "meta.zon";

/// What a plan (or an apply) moves.
pub const Counts = struct {
    objects: u64 = 0,
    lists: u64 = 0,
    trees: u64 = 0,
    farms: u64 = 0,
    /// Leftovers of dead processes in `tmp/`; deleted, not trashed, and not in the hash.
    tmp: u64 = 0,
    /// Bytes of the objects, lists and trees.
    bytes: u64 = 0,

    pub fn total(counts: *const Counts) u64 {
        assert(counts.objects < 1 << 40);
        assert(counts.trees < 1 << 40);
        return counts.objects + counts.lists + counts.trees + counts.farms;
    }
};

pub const Plan = struct {
    counts: Counts,
    hash: Digest,
    generation: u64,
};

/// An id of 12 hex digits, the name of a trash directory.
pub const Id = [constants.store_gc_id_hex_bytes]u8;

pub fn id_of(hash: Digest) Id {
    assert(hash.bytes.len == constants.store_digest_bytes);
    assert(constants.store_gc_id_hex_bytes < constants.store_digest_hex_bytes);
    const hex = hash.hex();
    return hex[0..constants.store_gc_id_hex_bytes].*;
}

/// True if `text` is a gc id (12 lowercase hex digits).
pub fn is_id(text: []const u8) bool {
    assert(text.len <= constants.arg_bytes_max);
    assert(constants.store_gc_id_hex_bytes == 12);
    if (text.len != constants.store_gc_id_hex_bytes) return false;
    for (text) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// Why a plan or an apply could not be made.
pub const Failure = union(enum) {
    io: struct { err: host_mod.Error, errno: u16, step: []const u8 },
    /// A root's or a live container's tree is missing or damaged: what it reaches is unknown.
    tree: walk.Failure,
    /// A root record that can not be read or understood.
    root: struct { digest: Digest, errno: u16 },
    /// A table or list outgrew its memory.
    too_big: []const u8,
    /// The store changed while the plan was being applied.
    changed,
    /// The trash has no metadata zbx can read.
    damaged_trash,
    /// The store lock is held by someone else; the string says what was being done.
    busy: []const u8,
};

pub const Error = error{Failed};

/// The caller's memory for a plan, an apply, a restore and a listing.
pub const Workspace = struct {
    tree_buffer: [constants.store_tree_bytes_max]u8,
    removal: remove.Workspace,
    /// A restore that has to make a chunk list reads the object into these.
    io: [constants.store_io_buffer_bytes]u8,
    chunks: [constants.store_chunks_max]Digest,
};

pub const meta_bytes_max = 512;

pub const arena_bytes: u32 = names_bytes + offsets_bytes + objects_bytes + trees_bytes +
    tops_bytes + stack_bytes;
const names_bytes: u32 = remove.arena_bytes;
const offsets_bytes: u32 = 1024 * 1024;
const objects_bytes: u32 = 5 * 1024 * 1024 + 512 * 1024;
const trees_bytes: u32 = 3 * 1024 * 1024;
const tops_bytes: u32 = 1024 * 1024;
const stack_bytes: u32 = 1024 * 1024;

comptime {
    assert(arena_bytes <= constants.store_arena_bytes_max);
    assert(objects_bytes + trees_bytes >= remove.arena_bytes);
}

// ---- The metadata of a trash ---------------------------------------------------------------

pub const Meta = struct {
    time: u64,
    expires: u64,
    objects: u64,
    lists: u64,
    trees: u64,
    farms: u64,
    bytes: u64,
    /// False while the move is going on, and for ever if it was killed.
    complete: bool,
};

pub fn render_meta(meta: *const Meta, out: *[meta_bytes_max]u8) []const u8 {
    assert(out.len == meta_bytes_max);
    assert(meta.expires >= meta.time);
    var writer = std.Io.Writer.fixed(out);
    // Cannot fail: eight short fields fit 512 bytes.
    writer.print(".{{\n    .version = 1,\n    .time = {d},\n    .expires = {d},\n" ++
        "    .objects = {d},\n    .lists = {d},\n    .trees = {d},\n    .farms = {d},\n" ++
        "    .bytes = {d},\n    .complete = {},\n}}\n", .{
        meta.time,  meta.expires, meta.objects, meta.lists,
        meta.trees, meta.farms,   meta.bytes,   meta.complete,
    }) catch unreachable; // Cannot fail: the buffer holds the longest one.
    return writer.buffered();
}

/// Reads a trash's metadata; null if it is not one this zbx understands.
pub fn parse_meta(text: []const u8) ?Meta {
    assert(meta_bytes_max >= 256);
    assert(text.len <= meta_bytes_max);
    var meta: Meta = std.mem.zeroes(Meta);
    var version: u64 = 0;
    var seen: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " ");
        if (!std.mem.startsWith(u8, line, ".")) continue;
        const equals = std.mem.indexOf(u8, line, " = ") orelse continue;
        const key = line[1..equals];
        var value = line[equals + 3 ..];
        if (value.len > 0 and value[value.len - 1] == ',') value = value[0 .. value.len - 1];
        if (std.mem.eql(u8, key, "complete")) {
            if (std.mem.eql(
                u8,
                value,
                "true",
            )) meta.complete = true else if (!std.mem.eql(u8, value, "false")) return null;
            seen += 1;
            continue;
        }
        const number = std.fmt.parseInt(u64, value, 10) catch continue;
        inline for (.{
            "version",
            "time",
            "expires",
            "objects",
            "lists",
            "trees",
            "farms",
            "bytes",
        }) |name| {
            if (std.mem.eql(u8, key, name)) {
                if (comptime std.mem.eql(
                    u8,
                    name,
                    "version",
                )) version = number else @field(meta, name) = number;
                seen += 1;
            }
        }
    }
    if (version != 1 or seen != 9) return null;
    if (meta.expires < meta.time) return null;
    return meta;
}

// ---- Paths ---------------------------------------------------------------------------------

pub const Class = enum {
    object,
    list,
    tree,
    farm,

    fn directory(class: Class) []const u8 {
        assert(@tagName(class).len > 0);
        assert(@tagName(class).len < 16);
        return switch (class) {
            .object, .list => "objects",
            .tree => "trees",
            .farm => "cache",
        };
    }

    fn tag(class: Class) u8 {
        assert(@tagName(class).len > 0);
        assert(@tagName(class).len < 16);
        return switch (class) {
            .object => 'o',
            .list => 'l',
            .tree => 't',
            .farm => 'f',
        };
    }
};

const Where = union(enum) { store, trash: Id };

/// Where the thing of `class` with `id` is, in the store or in a trash.
fn locate(
    store: *const Store,
    buffer: *PathBuf,
    where: Where,
    class: Class,
    id: Digest,
) [:0]const u8 {
    assert(store.root_len > 1);
    assert(id.bytes.len == constants.store_digest_bytes);
    const hex = id.hex();
    const suffix: []const u8 = if (class == .list) layout.chunks_suffix else "";
    switch (where) {
        .store => {
            if (class == .farm) return store.path(buffer, &.{ "/cache/", &hex });
            return store.id_path(buffer, class.directory(), id, suffix);
        },
        .trash => |gc| {
            if (class == .farm) return store.path(buffer, &.{ "/trash/", &gc, "/cache/", &hex });
            return store.path(buffer, &.{
                "/trash/", &gc, "/", class.directory(), "/", hex[0..2], "/", hex[2..], suffix,
            });
        },
    }
}

fn trash_directory(store: *const Store, buffer: *PathBuf, gc: Id) [:0]const u8 {
    assert(store.root_len > 1);
    assert(gc.len == constants.store_gc_id_hex_bytes);
    return store.path(buffer, &.{ "/trash/", &gc });
}

fn trash_shard(
    store: *const Store,
    buffer: *PathBuf,
    gc: Id,
    class: Class,
    id: Digest,
) [:0]const u8 {
    assert(store.root_len > 1);
    assert(id.bytes.len == constants.store_digest_bytes);
    const hex = id.hex();
    return store.path(buffer, &.{ "/trash/", &gc, "/", class.directory(), "/", hex[0..2] });
}

// ---- Reachability --------------------------------------------------------------------------

const Run = struct {
    store: *Store,
    ws: *Workspace,
    failure: *Failure,
    names: []u8,
    offsets: []u32,
    objects: sets.DigestMap,
    trees: sets.DigestMap,
    tops: sets.DigestMap,
    stack: []Digest,
    full: bool,
    live: []const Digest,

    fn io(run: *Run, step: []const u8, err: host_mod.Error) Error {
        assert(step.len > 0);
        assert(@intFromPtr(run.failure) != 0);
        if (err == error.FileTooLarge) {
            run.failure.* = .{ .too_big = step };
        } else {
            run.failure.* = .{ .io = .{
                .err = err,
                .errno = run.store.fs.last_errno(),
                .step = step,
            } };
        }
        return error.Failed;
    }

    /// Like `io`, for a call that kept the errno it failed with (`write_atomic` cleans up after
    /// itself, which overwrites the file system's last errno).
    fn io_noted(run: *Run, step: []const u8, noted: *const fs_mod.Failure) Error {
        assert(step.len > 0);
        run.failure.* = .{ .io = .{ .err = noted.err, .errno = noted.errno, .step = step } };
        return error.Failed;
    }

    pub fn entry(run: *Run, found: *const tree.Entry) void {
        assert(@intFromPtr(found) != 0);
        assert(run.objects.slots.len > 0);
        if (found.kind != .file) return;
        if (run.objects.put(found.object, found.size) == .full) run.full = true;
    }
};

fn init_run(
    store: *Store,
    ws: *Workspace,
    arena: []align(8) u8,
    live: []const Digest,
    failure: *Failure,
) Run {
    assert(live.len <= constants.store_roots_max);
    assert(@intFromPtr(failure) != 0);
    assert(arena.len >= arena_bytes);
    var at: usize = 0;
    const names = arena[at..][0..names_bytes];
    at += names_bytes;
    const offsets: []u32 = @alignCast(std.mem.bytesAsSlice(u32, arena[at..][0..offsets_bytes]));
    at += offsets_bytes;
    const objects = sets.DigestMap.init(@alignCast(arena[at..][0..objects_bytes]));
    at += objects_bytes;
    const trees = sets.DigestMap.init(@alignCast(arena[at..][0..trees_bytes]));
    at += trees_bytes;
    const tops = sets.DigestMap.init(@alignCast(arena[at..][0..tops_bytes]));
    at += tops_bytes;
    const stack: []Digest = @alignCast(std.mem.bytesAsSlice(Digest, arena[at..][0..stack_bytes]));
    return .{
        .store = store,
        .ws = ws,
        .failure = failure,
        .names = names,
        .offsets = offsets,
        .objects = objects,
        .trees = trees,
        .tops = tops,
        .stack = stack,
        .full = false,
        .live = live,
    };
}

/// Marks everything the roots and the live containers keep.
fn reach(run: *Run) Error!void {
    assert(run.names.len > 0);
    assert(run.offsets.len > 0);
    const found = shards.read(run.store, run.names, run.offsets, "roots", null) catch |err| {
        return run.io("listing the roots", err);
    };
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const digest = Digest.from_hex(found.name(index)) orelse continue;
        var record: roots.Root = undefined;
        var errno: u16 = 0;
        roots.load(run.store, digest, &record, &errno) catch {
            run.failure.* = .{ .root = .{ .digest = digest, .errno = errno } };
            return error.Failed;
        };
        try mark_tree(run, digest);
    }
    for (run.live) |digest| try mark_tree(run, digest);
}

fn mark_tree(run: *Run, digest: Digest) Error!void {
    assert(run.tops.slots.len > 0);
    assert(digest.bytes.len == constants.store_digest_bytes);
    if (run.tops.put(digest, 0) == .full) {
        run.failure.* = .{ .too_big = "the roots" };
        return error.Failed;
    }
    var failed: walk.Failure = undefined;
    walk.walk(run.store, &run.ws.tree_buffer, run.stack, &run.trees, digest, run, &failed) catch {
        run.failure.* = .{ .tree = failed };
        return error.Failed;
    };
    if (run.full) {
        run.failure.* = .{ .too_big = "the files the trees name" };
        return error.Failed;
    }
}

// ---- Enumerating what is not kept ----------------------------------------------------------

const Mode = enum { plan, apply };

/// The things of one pass: the hash, the counts and, when applying, the trash being filled.
const Pass = struct {
    mode: Mode,
    hasher: Hasher,
    counts: Counts,
    gc: Id,

    fn note(pass: *Pass, class: Class, id: Digest) void {
        assert(pass.counts.total() < 1 << 40);
        assert(id.bytes.len == constants.store_digest_bytes);
        pass.hasher.update(&[1]u8{class.tag()});
        pass.hasher.update(&id.bytes);
        switch (class) {
            .object => pass.counts.objects += 1,
            .list => pass.counts.lists += 1,
            .tree => pass.counts.trees += 1,
            .farm => pass.counts.farms += 1,
        }
    }
};

fn file_size(run: *Run, path: [:0]const u8) Error!u64 {
    assert(path.len > 0);
    assert(path.len <= constants.path_bytes_max);
    const stat = run.store.fs.lstat(path) catch |err| return run.io("sizing a file", err);
    return stat.size;
}

/// Moves what the plan names into the trash: the first step of an apply for one thing.
fn move_to_trash(run: *Run, pass: *const Pass, class: Class, id: Digest) Error!void {
    assert(pass.mode == .apply);
    assert(run.store.root_len > 1);
    const fs = run.store.fs;
    var from_storage: PathBuf = undefined;
    var to_storage: PathBuf = undefined;
    const from = locate(run.store, &from_storage, .store, class, id);
    const to = locate(run.store, &to_storage, .{ .trash = pass.gc }, class, id);
    if (class != .farm) {
        var directory_storage: PathBuf = undefined;
        const directory = trash_shard(run.store, &directory_storage, pass.gc, class, id);
        try ensure_chain(run, pass.gc, class, directory);
    }
    fs.rename(from, to) catch |err| return run.io("moving to the trash", err);
}

/// Makes `trash/<gc>/<objects|trees|cache>` and the shard directory below it.
fn ensure_chain(run: *Run, gc: Id, class: Class, shard_directory: [:0]const u8) Error!void {
    assert(shard_directory.len > 0);
    assert(class != .farm);
    const fs = run.store.fs;
    var class_storage: PathBuf = undefined;
    const class_directory = run.store.path(
        &class_storage,
        &.{ "/trash/", &gc, "/", class.directory() },
    );
    fs.make_directory(
        class_directory,
        true,
    ) catch |err| return run.io("making a trash directory", err);
    fs.make_directory(
        shard_directory,
        true,
    ) catch |err| return run.io("making a trash directory", err);
}

fn enumerate_shards(run: *Run, pass: *Pass, class: Class) Error!void {
    assert(class != .farm);
    assert(class != .list);
    assert(run.offsets.len > 0);
    const directory = class.directory();
    for (0..constants.store_shards_count) |shard| {
        const found = shards.read(
            run.store,
            run.names,
            run.offsets,
            directory,
            @intCast(shard),
        ) catch |err| {
            return run.io("listing a shard", err);
        };
        var index: u32 = 0;
        while (index < found.count()) : (index += 1) {
            try consider(run, pass, class, found, index, @intCast(shard));
        }
    }
}

fn consider(
    run: *Run,
    pass: *Pass,
    class: Class,
    found: shards.Names,
    index: u32,
    shard: u32,
) Error!void {
    assert(index < found.count());
    assert(shard < constants.store_shards_count);
    const name = found.name(index);
    if (shards.list_base(name)) |base| {
        if (class != .object) return;
        const previous = if (index > 0) found.name(index - 1) else "";
        if (std.mem.eql(u8, previous, base)) return; // Moves with its object.
        const id = shards.id_of(shard, base) orelse return;
        var path: PathBuf = undefined;
        pass.counts.bytes += try file_size(run, locate(run.store, &path, .store, .list, id));
        pass.note(.list, id);
        if (pass.mode == .apply) try move_to_trash(run, pass, .list, id);
        return;
    }
    const id = shards.id_of(shard, name) orelse return;
    const kept = if (class == .object) run.objects.get(id) != null else run.trees.get(id) != null;
    if (kept) return;
    var path: PathBuf = undefined;
    pass.counts.bytes += try file_size(run, locate(run.store, &path, .store, class, id));
    pass.note(class, id);
    const next = if (index + 1 < found.count()) found.name(index + 1) else "";
    const has_list = class == .object and next.len == name.len + layout.chunks_suffix.len and
        std.mem.startsWith(u8, next, name) and shards.list_base(next) != null;
    if (has_list) {
        pass.counts.bytes += try file_size(run, locate(run.store, &path, .store, .list, id));
        pass.note(.list, id);
    }
    if (pass.mode == .apply) {
        try move_to_trash(run, pass, class, id);
        if (has_list) try move_to_trash(run, pass, .list, id);
    }
}

fn enumerate_farms(run: *Run, pass: *Pass) Error!void {
    assert(run.names.len > 0);
    assert(pass.counts.farms == 0);
    const found = shards.read(run.store, run.names, run.offsets, "cache", null) catch |err| {
        return run.io("listing the materialized trees", err);
    };
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const id = Digest.from_hex(found.name(index)) orelse continue;
        if (run.tops.get(id) != null) continue;
        pass.note(.farm, id);
        if (pass.mode == .apply) {
            try ensure_trash_cache(run, pass.gc);
            try move_to_trash(run, pass, .farm, id);
        }
    }
}

fn ensure_trash_cache(run: *Run, gc: Id) Error!void {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(run.store.root_len > 1);
    var storage: PathBuf = undefined;
    const path = run.store.path(&storage, &.{ "/trash/", &gc, "/cache" });
    run.store.fs.make_directory(
        path,
        true,
    ) catch |err| return run.io("making a trash directory", err);
}

/// Counts what is left in `tmp/` by processes that are gone. With `remove_them`, deletes it.
fn clean_tmp(run: *Run, counts: *Counts, remove_them: bool) Error!void {
    assert(run.names.len > 0);
    assert(counts.tmp == 0);
    const found = shards.read(run.store, run.names, run.offsets, "tmp", null) catch |err| {
        return run.io("listing tmp", err);
    };
    const own = run.store.host.own_pid();
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const name = found.name(index);
        const dash = std.mem.indexOfScalar(u8, name, '-') orelse continue;
        const pid = std.fmt.parseInt(u32, name[0..dash], 10) catch continue;
        if (pid == 0 or pid == own) continue;
        run.store.host.signal(pid, 0) catch |err| {
            if (err == error.AccessDenied) continue; // It exists, and is not ours.
            counts.tmp += 1;
            if (remove_them) try remove_leftover(run, name);
            continue;
        };
    }
}

fn remove_leftover(run: *Run, name: []const u8) Error!void {
    assert(name.len > 0);
    assert(std.mem.indexOfScalar(u8, name, '/') == null);
    var storage: PathBuf = undefined;
    const path = run.store.path(&storage, &.{ "/tmp/", name });
    var failure: remove.Failure = undefined;
    // The names and offsets are in use; the removal borrows the memory of the tables, which an
    // apply no longer needs when it gets here.
    const memory: []u8 = @as([*]u8, @ptrCast(run.objects.slots.ptr))[0..remove.arena_bytes];
    remove.tree(run.store.fs, &run.ws.removal, memory, path, &failure) catch {
        run.failure.* = .{ .io = .{
            .err = failure.err,
            .errno = failure.errno,
            .step = "removing a leftover in tmp",
        } };
        return error.Failed;
    };
}

fn new_pass(mode: Mode, generation_now: u64) Pass {
    assert(plan_magic.len == 12);
    assert(@sizeOf(Hasher) > 0);
    var hasher = Hasher.init();
    hasher.update(plan_magic);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, generation_now, .little);
    hasher.update(&number);
    return .{ .mode = mode, .hasher = hasher, .counts = .{}, .gc = undefined };
}

fn make_plan(run: *Run, pass: *Pass, generation_now: u64) Error!Plan {
    assert(pass.counts.total() == 0);
    assert(run.objects.slots.len > 0);
    try enumerate_shards(run, pass, .object);
    try enumerate_shards(run, pass, .tree);
    try enumerate_farms(run, pass);
    return .{ .counts = pass.counts, .hash = pass.hasher.final(), .generation = generation_now };
}

/// The plan: what a gc would move now, and the hash that confirms it.
pub fn plan(
    store: *Store,
    ws: *Workspace,
    arena: []align(8) u8,
    live: []const Digest,
    result: *Plan,
    failure: *Failure,
) Error!void {
    assert(arena.len >= arena_bytes);
    assert(live.len <= constants.store_roots_max);
    var run = init_run(store, ws, arena, live, failure);
    const now = generation.read(store) catch |err| return run.io("reading the generation", err);
    try reach(&run);
    var pass = new_pass(.plan, now);
    result.* = try make_plan(&run, &pass, now);
    var leftovers: Counts = .{};
    try clean_tmp(&run, &leftovers, false);
    result.counts.tmp = leftovers.tmp;
}

/// What an apply did.
pub const Applied = struct {
    gc: Id,
    counts: Counts,
    /// Trash directories emptied because they had expired.
    expired: u32,
    /// When the trash made now is emptied.
    expires: u64,
    /// The plan made at confirmation, which did not match (set when `apply` returns `Stale`).
    fresh: Plan,
};

/// The exclusive store lock for an apply or a restore; `Failed` with `failure` set if the lock
/// is held or can not be used.
fn hold_exclusive(store: *Store, failure: *Failure, operation: []const u8) error{Failed}!void {
    assert(store.lock_depth == 0); // Not inside another hold: a shared one can not be raised.
    assert(operation.len > 0);
    const who = if (std.mem.startsWith(u8, operation, "applying")) "gc" else "restore";
    lock.hold(store, .exclusive, who) catch |err| {
        failure.* = switch (err) {
            error.Busy => .{ .busy = operation },
            error.Failed => .{ .io = .{
                .err = store.lock_error,
                .errno = store.lock_errno,
                .step = "taking the store lock",
            } },
        };
        return error.Failed;
    };
}

pub const ApplyError = error{ Failed, Stale };

/// Applies the plan whose hash is `expected`: makes the plan again, and if it hashes the same
/// moves everything into a new trash, empties expired trash and deletes dead leftovers in
/// `tmp/`. `Stale` (with `result.fresh` set) if the store is not the one the hash is of.
pub fn apply(
    store: *Store,
    ws: *Workspace,
    arena: []align(8) u8,
    live: []const Digest,
    expected: Digest,
    result: *Applied,
    failure: *Failure,
) ApplyError!void {
    assert(live.len <= constants.store_roots_max);
    assert(expected.bytes.len == constants.store_digest_bytes);
    result.* = std.mem.zeroes(Applied);
    try hold_exclusive(store, failure, "applying the gc plan");
    defer lock.release(store);
    var run = init_run(store, ws, arena, live, failure);
    const now = generation.read(store) catch |err| return run.io("reading the generation", err);
    try reach(&run);
    var check = new_pass(.plan, now);
    result.fresh = try make_plan(&run, &check, now);
    if (!result.fresh.hash.eql(expected)) return error.Stale;
    result.gc = id_of(expected);
    result.counts = result.fresh.counts;
    const time = store.host.time_now();
    result.expires = time + constants.store_trash_seconds;
    if (result.counts.total() > 0) try move_all(&run, result, time);
    result.expired = try empty_expired(&run, time);
    var leftovers: Counts = .{};
    try clean_tmp(&run, &leftovers, true);
    result.counts.tmp = leftovers.tmp;
}

fn move_all(run: *Run, result: *Applied, time: u64) Error!void {
    assert(result.counts.total() > 0);
    assert(result.expires > time);
    var raised: fs_mod.Failure = undefined;
    generation.bump(run.store, &raised) catch |err| {
        run.failure.* = .{ .io = .{
            .err = err,
            .errno = raised.errno,
            .step = "raising the generation",
        } };
        return error.Failed;
    };
    var meta: Meta = .{
        .time = time,
        .expires = result.expires,
        .objects = result.counts.objects,
        .lists = result.counts.lists,
        .trees = result.counts.trees,
        .farms = result.counts.farms,
        .bytes = result.counts.bytes,
        .complete = false,
    };
    try create_trash(run, result.gc, &meta);
    var pass = new_pass(.apply, result.fresh.generation);
    pass.gc = result.gc;
    const again = try make_plan(run, &pass, result.fresh.generation);
    if (!again.hash.eql(result.fresh.hash)) {
        run.failure.* = .changed;
        return error.Failed;
    }
    // What moved is what the plan said; the counts are of what was moved.
    meta.objects = again.counts.objects;
    meta.lists = again.counts.lists;
    meta.trees = again.counts.trees;
    meta.farms = again.counts.farms;
    meta.bytes = again.counts.bytes;
    meta.complete = true;
    try write_meta(run, result.gc, &meta);
}

/// Makes `trash/<gc>/` holding `meta.zon`, so a directory without metadata is only ever empty.
fn create_trash(run: *Run, gc: Id, meta: *const Meta) Error!void {
    assert(!meta.complete);
    assert(gc.len == constants.store_gc_id_hex_bytes);
    const fs = run.store.fs;
    var text: [meta_bytes_max]u8 = undefined;
    const bytes = render_meta(meta, &text);
    var temporary_storage: PathBuf = undefined;
    const temporary = run.store.tmp_path(&temporary_storage);
    var failure: fs_mod.Failure = undefined;
    var staged_storage: PathBuf = undefined;
    var tmp_storage: PathBuf = undefined;
    // The file is first written in tmp/, where nothing reads it as a trash.
    const staged = run.store.path(&staged_storage, &.{ "/tmp/gc-", &gc });
    const tmp_directory = run.store.directory_path(&tmp_storage, "tmp");
    fs.write_atomic(temporary, staged, tmp_directory, bytes, 0o644, &failure) catch {
        return run.io_noted("writing the trash's metadata", &failure);
    };
    var directory_storage: PathBuf = undefined;
    const directory = trash_directory(run.store, &directory_storage, gc);
    fs.make_directory(
        directory,
        false,
    ) catch |err| return run.io("making the trash directory", err);
    var final_storage: PathBuf = undefined;
    const final = run.store.path(&final_storage, &.{ "/trash/", &gc, "/", meta_file });
    fs.rename(staged, final) catch |err| return run.io("putting the metadata in the trash", err);
    var trash_storage: PathBuf = undefined;
    fs.sync_directory(directory) catch |err| return run.io("flushing the trash", err);
    fs.sync_directory(run.store.directory_path(&trash_storage, "trash")) catch |err| {
        return run.io("flushing the trash", err);
    };
}

fn write_meta(run: *Run, gc: Id, meta: *const Meta) Error!void {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(meta.expires >= meta.time);
    var text: [meta_bytes_max]u8 = undefined;
    const bytes = render_meta(meta, &text);
    var temporary_storage: PathBuf = undefined;
    var final_storage: PathBuf = undefined;
    var directory_storage: PathBuf = undefined;
    const temporary = run.store.tmp_path(&temporary_storage);
    const final = run.store.path(&final_storage, &.{ "/trash/", &gc, "/", meta_file });
    const directory = trash_directory(run.store, &directory_storage, gc);
    var failure: fs_mod.Failure = undefined;
    run.store.fs.write_atomic(temporary, final, directory, bytes, 0o644, &failure) catch {
        return run.io_noted("writing the trash's metadata", &failure);
    };
}

// ---- Trash ---------------------------------------------------------------------------------

/// A trash directory as `gc --trash` lists it.
pub const TrashEntry = struct {
    id: Id,
    /// Null if the metadata is missing or not understood.
    meta: ?Meta,
};

pub const Trash = struct {
    count: u32,
    truncated: bool,
};

fn read_meta(store: *const Store, gc: Id) ?Meta {
    assert(store.root_len > 1);
    assert(gc.len == constants.store_gc_id_hex_bytes);
    var path: PathBuf = undefined;
    var bytes: [meta_bytes_max]u8 = undefined;
    const text = store.fs.read_whole(
        store.path(&path, &.{ "/trash/", &gc, "/", meta_file }),
        &bytes,
    ) catch {
        return null;
    };
    return parse_meta(text);
}

/// Lists the trash, oldest first.
pub fn list_trash(
    store: *const Store,
    names_memory: []u8,
    offsets: []u32,
    out: []TrashEntry,
    result: *Trash,
    failure: *Failure,
) Error!void {
    assert(names_memory.len > 0);
    assert(offsets.len > 0);
    assert(out.len > 0);
    result.* = .{ .count = 0, .truncated = false };
    const found = shards.read(store, names_memory, offsets, "trash", null) catch |err| {
        failure.* = .{ .io = .{
            .err = err,
            .errno = store.fs.last_errno(),
            .step = "listing the trash",
        } };
        return error.Failed;
    };
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const name = found.name(index);
        if (!is_id(name)) continue;
        if (result.count == out.len) {
            result.truncated = true;
            break;
        }
        out[result.count] = .{
            .id = name[0..constants.store_gc_id_hex_bytes].*,
            .meta = read_meta(store, name[0..constants.store_gc_id_hex_bytes].*),
        };
        result.count += 1;
    }
    std.mem.sortUnstable(TrashEntry, out[0..result.count], {}, older_first);
}

fn older_first(context: void, first: TrashEntry, second: TrashEntry) bool {
    assert(first.id.len == second.id.len);
    assert(@TypeOf(context) == void);
    const a = if (first.meta) |meta| meta.time else 0;
    const b = if (second.meta) |meta| meta.time else 0;
    if (a != b) return a < b;
    return std.mem.lessThan(u8, &first.id, &second.id);
}

/// Removes every trash whose time is past. A directory without metadata is removed only if it
/// holds nothing (a gc that died before it moved anything).
fn empty_expired(run: *Run, now: u64) Error!u32 {
    assert(now > 0);
    assert(run.names.len > 0);
    const found = shards.read(run.store, run.names, run.offsets, "trash", null) catch |err| {
        return run.io("listing the trash", err);
    };
    var removed: u32 = 0;
    var index: u32 = 0;
    while (index < found.count()) : (index += 1) {
        const name = found.name(index);
        if (!is_id(name)) continue;
        const gc: Id = name[0..constants.store_gc_id_hex_bytes].*;
        const meta = read_meta(run.store, gc);
        var storage: PathBuf = undefined;
        const path = trash_directory(run.store, &storage, gc);
        if (meta) |known| {
            if (known.expires > now) continue;
        } else if (!(try holds_nothing(run, gc))) {
            continue;
        }
        try remove_trash(run, path);
        removed += 1;
    }
    return removed;
}

/// A trash without metadata that holds nothing but empty directories: nothing to keep.
fn holds_nothing(run: *Run, gc: Id) Error!bool {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(run.store.root_len > 1);
    var storage: PathBuf = undefined;
    return !(try has_file(run, trash_directory(run.store, &storage, gc), 0));
}

/// True if a file (anything but a directory) is at or below `path`, at most four levels deep.
fn has_file(run: *Run, path: [:0]const u8, depth: u32) Error!bool {
    assert(depth <= 5);
    assert(path.len > 0);
    if (depth > 4) return true; // Deeper than a trash goes: not ours to remove.
    var bytes: [8192]u8 = undefined;
    var list = @import("names.zig").NameList.init(&bytes, 128);
    run.store.fs.read_dir(
        path,
        list.visitor(),
    ) catch |err| return run.io("looking in the trash", err);
    if (!list.complete()) return true;
    var at: u32 = 0;
    while (at < list.used) {
        const name = list.at(at);
        at += @intCast(1 + name.len);
        var child_storage: PathBuf = undefined;
        child_storage.set(&.{ path, "/", name }) catch return true;
        const child = child_storage.text();
        const stat = run.store.fs.lstat(child) catch |err| return run.io(
            "looking in the trash",
            err,
        );
        if (stat.kind != .dir) return true;
        if (try has_file(run, child, depth + 1)) return true;
    }
    return false;
}

// ---- Restore -------------------------------------------------------------------------------

/// What a restore moved back.
pub const Restored = struct {
    counts: Counts,
    /// Set when `restore` returns `Conflict`: what is already in the store again, and how many
    /// things are.
    conflict_class: Class,
    conflict_id: Digest,
    conflicts: u64,
    /// Set when it returns `Incomplete`: what the metadata promised and what the trash holds.
    promised: Counts,
    found: Counts,
};

pub const RestoreError = error{ Failed, NoSuchTrash, Incomplete, Conflict };

/// Moves the trash `gc` back into the store. Refuses, changing nothing, when the trash does
/// not exist (`NoSuchTrash`), when a trash that finished holds fewer things than it recorded
/// (`Incomplete`), or when any of its objects, trees or directories is in the store again
/// (`Conflict`). A trash whose gc was killed, or whose restore was, is not checked for counts.
pub fn restore(
    store: *Store,
    ws: *Workspace,
    arena: []align(8) u8,
    gc: Id,
    result: *Restored,
    failure: *Failure,
) RestoreError!void {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(arena.len >= arena_bytes);
    result.* = std.mem.zeroes(Restored);
    try hold_exclusive(store, failure, "restoring a trash");
    defer lock.release(store);
    var run = init_run(store, ws, arena, &.{}, failure);
    var directory_storage: PathBuf = undefined;
    const directory = trash_directory(store, &directory_storage, gc);
    _ = store.fs.lstat(directory) catch |err| {
        if (err == error.NotFound) return error.NoSuchTrash;
        return run.io("looking for the trash", err);
    };
    var found: Counts = .{};
    try restore_pass(&run, gc, .check, &found, result);
    var meta = read_meta(store, gc) orelse {
        // Without metadata a trash is either what a killed removal left (nothing in it, which
        // is cleared away now) or damaged.
        if (try has_file(&run, directory, 0)) {
            failure.* = .damaged_trash;
            return error.Failed;
        }
        try remove_trash(&run, directory);
        return error.NoSuchTrash;
    };
    result.found = found;
    result.promised = .{
        .objects = meta.objects,
        .lists = meta.lists,
        .trees = meta.trees,
        .farms = meta.farms,
    };
    const short = found.objects < meta.objects or found.trees < meta.trees or
        found.farms < meta.farms;
    if (meta.complete and short) {
        return error.Incomplete;
    }
    if (result.conflicts > 0) return error.Conflict;
    var raised: fs_mod.Failure = undefined;
    generation.bump(store, &raised) catch |err| {
        failure.* = .{ .io = .{
            .err = err,
            .errno = raised.errno,
            .step = "raising the generation",
        } };
        return error.Failed;
    };
    if (meta.complete) {
        meta.complete = false;
        try write_meta(&run, gc, &meta);
    }
    result.counts = .{};
    try restore_pass(&run, gc, .move, &result.counts, result);
    try remove_trash(&run, directory);
}

fn remove_trash(run: *Run, directory: [:0]const u8) Error!void {
    assert(directory.len > 0);
    assert(std.mem.indexOf(u8, directory, "/trash/") != null);
    var removal: remove.Failure = undefined;
    const memory: []u8 = @as([*]u8, @ptrCast(run.objects.slots.ptr))[0..remove.arena_bytes];
    remove.tree(run.store.fs, &run.ws.removal, memory, directory, &removal) catch {
        run.failure.* = .{ .io = .{
            .err = removal.err,
            .errno = removal.errno,
            .step = "removing a trash",
        } };
        return error.Failed;
    };
}

const RestoreMode = enum { check, move };

fn restore_pass(
    run: *Run,
    gc: Id,
    mode: RestoreMode,
    counts: *Counts,
    result: *Restored,
) RestoreError!void {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(counts.total() == 0);
    for ([_]Class{ .object, .tree }) |class| {
        for (0..constants.store_shards_count) |shard| {
            var directory: [96]u8 = undefined;
            // Cannot fail: "trash/", twelve digits and a directory name fit 96 bytes.
            const where = std.fmt.bufPrint(
                &directory,
                "trash/{s}/{s}",
                .{ gc, class.directory() },
            ) catch unreachable; // Cannot fail: the buffer holds the longest one.
            const names = shards.read(
                run.store,
                run.names,
                run.offsets,
                where,
                @intCast(shard),
            ) catch |err| {
                return run.io("listing a shard of the trash", err);
            };
            var index: u32 = 0;
            while (index < names.count()) : (index += 1) {
                try restore_name(
                    run,
                    gc,
                    mode,
                    class,
                    names,
                    index,
                    @intCast(shard),
                    counts,
                    result,
                );
            }
        }
    }
    var directory: [96]u8 = undefined;
    // Cannot fail: "trash/", twelve digits and "/cache" fit 96 bytes.
    const where = std.fmt.bufPrint(&directory, "trash/{s}/cache", .{gc}) catch unreachable;
    const names = shards.read(run.store, run.names, run.offsets, where, null) catch |err| {
        return run.io("listing the trash's directories", err);
    };
    var index: u32 = 0;
    while (index < names.count()) : (index += 1) {
        const id = Digest.from_hex(names.name(index)) orelse continue;
        try restore_one(run, gc, mode, .farm, id, counts, result);
    }
}

fn restore_name(
    run: *Run,
    gc: Id,
    mode: RestoreMode,
    class: Class,
    names: shards.Names,
    index: u32,
    shard: u32,
    counts: *Counts,
    result: *Restored,
) RestoreError!void {
    assert(index < names.count());
    assert(shard < constants.store_shards_count);
    const name = names.name(index);
    if (shards.list_base(name)) |base| {
        const previous = if (index > 0) names.name(index - 1) else "";
        if (std.mem.eql(u8, previous, base)) return; // Moves with its object.
        const id = shards.id_of(shard, base) orelse return;
        return restore_one(run, gc, mode, .list, id, counts, result);
    }
    const id = shards.id_of(shard, name) orelse return;
    const next = if (index + 1 < names.count()) names.name(index + 1) else "";
    const has_list = class == .object and next.len == name.len + layout.chunks_suffix.len and
        std.mem.startsWith(u8, next, name) and shards.list_base(next) != null;
    // The list goes back first, so an object in the store never lacks its list.
    if (has_list) try restore_one(run, gc, mode, .list, id, counts, result);
    try restore_one(run, gc, mode, class, id, counts, result);
}

fn restore_one(
    run: *Run,
    gc: Id,
    mode: RestoreMode,
    class: Class,
    id: Digest,
    counts: *Counts,
    result: *Restored,
) RestoreError!void {
    assert(gc.len == constants.store_gc_id_hex_bytes);
    assert(id.bytes.len == constants.store_digest_bytes);
    const fs = run.store.fs;
    var from_storage: PathBuf = undefined;
    var to_storage: PathBuf = undefined;
    const from = locate(run.store, &from_storage, .{ .trash = gc }, class, id);
    const to = locate(run.store, &to_storage, .store, class, id);
    switch (class) {
        .object => counts.objects += 1,
        .list => counts.lists += 1,
        .tree => counts.trees += 1,
        .farm => counts.farms += 1,
    }
    if (mode == .check) {
        if (class == .list) return; // Identical content by name; replaced if it is there.
        if (fs.lstat(to)) |_| {
            if (result.conflicts == 0) {
                result.conflict_class = class;
                result.conflict_id = id;
            }
            result.conflicts += 1;
        } else |err| {
            if (err != error.NotFound) return run.io("looking in the store", err);
        }
        return;
    }
    if (class != .farm) {
        var shard_storage: PathBuf = undefined;
        const shard = run.store.shard_path(&shard_storage, class.directory(), id);
        fs.make_directory(shard, true) catch |err| return run.io("making a shard directory", err);
    }
    if (class == .object) try ensure_list(run, from, id);
    fs.rename(from, to) catch |err| return run.io("moving back from the trash", err);
}

/// An object that is longer than one chunk must not come back without its chunk list, and its
/// list may be in another trash (a gc that was killed between the two moves, then another gc
/// that took the list). If the store has no list for it, one is made from the object's bytes
/// before the object is moved, so no object ever lacks its list.
fn ensure_list(run: *Run, from: [:0]const u8, id: Digest) Error!void {
    assert(from.len > 0);
    assert(id.bytes.len == constants.store_digest_bytes);
    const fs = run.store.fs;
    const stat = fs.lstat(from) catch |err| return run.io("looking in the trash", err);
    if (!object.list_is_stored(stat.size, run.store.chunk_bytes)) return;
    var list_storage: PathBuf = undefined;
    const list_path = run.store.chunks_path(&list_storage, id);
    if (fs.lstat(list_path)) |_| return else |err| {
        if (err != error.NotFound) return run.io("looking in the store", err);
    }
    const ws = run.ws;
    const fd = fs.open_read(from) catch |err| return run.io("reading from the trash", err);
    defer fs.close(fd);
    var reader = object.Reader.init(run.store.chunk_bytes);
    while (true) {
        const count = fs.read(fd, &ws.io) catch |err| return run.io("reading from the trash", err);
        if (count == 0) break;
        if (!reader.update(ws.io[0..count], &ws.chunks)) {
            return run.io("reading from the trash", error.FileTooLarge);
        }
    }
    _ = reader.finish(&ws.chunks);
    const total = reader.count * constants.store_digest_bytes;
    for (ws.chunks[0..reader.count], 0..) |hash, at| @memcpy(ws.io[at * 32 ..][0..32], &hash.bytes);
    var temporary: PathBuf = undefined;
    var directory: PathBuf = undefined;
    var failure: fs_mod.Failure = undefined;
    const shard = run.store.shard_path(&directory, "objects", id);
    const staged = run.store.tmp_path(&temporary);
    fs.write_atomic(staged, list_path, shard, ws.io[0..total], 0o644, &failure) catch {
        return run.io_noted("writing a chunk list", &failure);
    };
}
