//! `store du`: how much the store holds, and how much one tree costs.
//!
//! Without a digest: the bytes of every object, chunk list and tree object in the store, and how
//! many objects and trees there are (a chunk list belongs to its object, and is not counted
//! apart). The bytes are the files' lengths, not the disk blocks they occupy.
//!
//! With a digest, for the tree it names:
//!   - `logical_bytes`: the sum of the lengths of its files, each counted where it occurs;
//!   - `stored_bytes`: the bytes of the distinct objects it references, which is what deleting
//!     it from an otherwise empty store would free;
//!   - `shared_bytes`: how much of that is also referenced by another root's tree, so what a
//!     `rm` of this root could not free.
//! Objects are compared by id, so a file with the same bytes but another mode is another object.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const names_mod = @import("names.zig");
const roots = @import("roots.zig");
const sets = @import("sets.zig");
const tree = @import("tree.zig");
const walk = @import("walk.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Total = struct {
    bytes: u64,
    objects: u64,
    trees: u64,
};

/// Why a count could not be made, with the facts a diagnostic needs.
pub const Failure = union(enum) {
    /// A call on a store path failed.
    io: struct { err: host_mod.Error, errno: u16, step: []const u8 },
    /// A tree object is missing or damaged, or the walk passed a bound.
    tree: walk.Failure,
    /// A shard directory holds more names than the memory given for them.
    too_many_names,
    /// A tree has more distinct files than the table holds.
    table_full,
};

pub const Error = error{Failed};

fn io_failure(fs: fs_mod.Fs, err: host_mod.Error, step: []const u8) Failure {
    assert(step.len > 0);
    assert(fs.last_errno() < 4096);
    return .{ .io = .{ .err = err, .errno = fs.last_errno(), .step = step } };
}

/// Adds up one shard directory of `directory` ("objects" or "trees").
fn add_shard(
    store: *const Store,
    arena: []u8,
    directory: []const u8,
    shard: u8,
    total: *Total,
    failure: *Failure,
) Error!void {
    assert(shard < constants.store_shards_count);
    assert(directory.len > 0);
    const fs = store.fs;
    var hex: [2]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x:0>2}", .{shard}) catch unreachable; // Two digits.
    var path: PathBuf = undefined;
    const shard_path = store.path(&path, &.{ "/", directory, "/", &hex });
    var names = names_mod.NameList.init(arena, std.math.maxInt(u32));
    fs.read_dir(shard_path, names.visitor()) catch |err| {
        if (err == error.NotFound) return;
        failure.* = .{ .io = .{ .err = err, .errno = fs.last_errno(), .step = "reading a shard" } };
        return error.Failed;
    };
    if (!names.complete()) {
        failure.* = .too_many_names;
        return error.Failed;
    }
    var at: u32 = 0;
    while (at < names.used) {
        const name = names.at(at);
        at += @intCast(1 + name.len);
        var file: PathBuf = undefined;
        const stat = fs.lstat(
            store.path(&file, &.{ "/", directory, "/", &hex, "/", name }),
        ) catch |err| {
            failure.* = io_failure(fs, err, "sizing a file");
            return error.Failed;
        };
        total.bytes += stat.size;
        const is_list = std.mem.endsWith(u8, name, layout.chunks_suffix);
        if (is_list) continue;
        if (std.mem.eql(u8, directory, "trees")) total.trees += 1 else total.objects += 1;
    }
}

/// The store as a whole. `arena` holds one shard's names.
pub fn store_total(store: *const Store, arena: []u8, total: *Total, failure: *Failure) Error!void {
    assert(arena.len > 0);
    total.* = .{ .bytes = 0, .objects = 0, .trees = 0 };
    for ([_][]const u8{ "objects", "trees" }) |directory| {
        for (0..constants.store_shards_count) |shard| {
            try add_shard(store, arena, directory, @intCast(shard), total, failure);
        }
    }
    assert(total.trees <= std.math.maxInt(u64) / 2); // A count, not a byte total.
}

pub const TreeUsage = struct {
    files: u64,
    logical_bytes: u64,
    objects: u64,
    stored_bytes: u64,
    shared_bytes: u64,
};

/// The memory a tree's usage is counted in. All of it is the caller's.
pub const Memory = struct {
    tree_buffer: []u8,
    /// The table of distinct objects.
    objects: []align(8) u8,
    /// The table of trees already visited when looking at other roots.
    visited: []align(8) u8,
    stack: []Digest,
    root_list: []roots.Root,
    names: []u8,
};

const Counter = struct {
    usage: *TreeUsage,
    objects: *sets.DigestMap,
    full: bool,

    pub fn entry(counter: *Counter, found: *const tree.Entry) void {
        assert(@intFromPtr(counter.usage) != 0);
        assert(counter.objects.slots.len > 0);
        if (found.kind != .file) return;
        counter.usage.files += 1;
        counter.usage.logical_bytes += found.size;
        if (counter.objects.put(found.object, found.size) == .full) counter.full = true;
    }
};

const Marker = struct {
    objects: *sets.DigestMap,

    pub fn entry(marker: *Marker, found: *const tree.Entry) void {
        assert(marker.objects.slots.len > 0);
        assert(@intFromPtr(found) != 0);
        if (found.kind != .file) return;
        if (marker.objects.get(found.object)) |slot| slot.mark = true;
    }
};

/// Counts the tree `digest` and how much of it other roots share.
pub fn tree_usage(
    store: *const Store,
    memory: *Memory,
    digest: Digest,
    usage: *TreeUsage,
    failure: *Failure,
) Error!void {
    assert(memory.tree_buffer.len >= constants.store_tree_bytes_max);
    usage.* = std.mem.zeroes(TreeUsage);
    var objects = sets.DigestMap.init(memory.objects);
    var counter: Counter = .{ .usage = usage, .objects = &objects, .full = false };
    var walk_failure: walk.Failure = undefined;
    walk.walk(
        store,
        memory.tree_buffer,
        memory.stack,
        null,
        digest,
        &counter,
        &walk_failure,
    ) catch {
        failure.* = .{ .tree = walk_failure };
        return error.Failed;
    };
    if (counter.full) {
        failure.* = .table_full;
        return error.Failed;
    }
    for (objects.slots) |slot| {
        if (!slot.used) continue;
        usage.objects += 1;
        usage.stored_bytes += slot.value;
    }
    try mark_shared(store, memory, digest, &objects, failure);
    for (objects.slots) |slot| {
        if (slot.used and slot.mark) usage.shared_bytes += slot.value;
    }
    assert(usage.shared_bytes <= usage.stored_bytes);
}

/// Marks the objects of `objects` that the trees of the other roots reference.
fn mark_shared(
    store: *const Store,
    memory: *Memory,
    digest: Digest,
    objects: *sets.DigestMap,
    failure: *Failure,
) Error!void {
    assert(memory.root_list.len <= constants.store_roots_max);
    assert(objects.slots.len > 0);
    const listing = roots.list(store, memory.names, memory.root_list) catch |err| {
        failure.* = io_failure(store.fs, err, "listing the roots");
        return error.Failed;
    };
    var visited = sets.DigestMap.init(memory.visited);
    var marker: Marker = .{ .objects = objects };
    for (memory.root_list[0..listing.count]) |*root| {
        if (root.digest.eql(digest)) continue;
        var walk_failure: walk.Failure = undefined;
        const stack = memory.stack;
        walk.walk(
            store,
            memory.tree_buffer,
            stack,
            &visited,
            root.digest,
            &marker,
            &walk_failure,
        ) catch {
            // A root whose tree is damaged cannot be said to share anything; `verify` reports it.
            if (walk_failure.kind == .stack_full) {
                failure.* = .{ .tree = walk_failure };
                return error.Failed;
            }
            continue;
        };
    }
}
