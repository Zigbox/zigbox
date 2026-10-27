//! Walking the trees that are in the store, from a digest down: every tree object below it is
//! read once per visit, checked against its name, and its entries handed to a visitor. This is
//! how `du` counts, and how `verify`, `diff` and `gc` will find what a root reaches.
//!
//! The walk is iterative: a stack of subtree digests the caller gives memory for, and a table of
//! the trees already visited if the caller wants each tree once (a `sets.DigestMap` or
//! `sets.KeySet`, or null). Without the table a tree that
//! occurs in many places is visited in each, which is what a total of logical sizes needs; the
//! number of entries seen is bounded (`store_walk_entries_max`) so that a store built by hand
//! cannot make a walk last for ever.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const layout = @import("layout.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// What stopped a walk. `where` names the tree object it was reading.
pub const Failure = struct {
    where: Digest,
    kind: enum { missing, damaged, unreadable, too_many_entries, stack_full },
    errno: u16,
};

pub const Error = error{Failed};

/// Calls `visitor.entry(&entry)` for every entry of every tree reachable from `root`, a
/// directory's own entry before the entries of its subtree. `buffer` holds one tree object.
pub fn walk(
    store: *const Store,
    buffer: []u8,
    stack: []Digest,
    visited: anytype,
    root: Digest,
    visitor: anytype,
    failure: *Failure,
) Error!void {
    assert(buffer.len >= constants.store_tree_bytes_max);
    assert(stack.len > 0);
    var top: usize = 1;
    stack[0] = root;
    var seen: u64 = 0;
    // Each pass pops a tree; every pass pushes at most the directories in one tree, and the
    // entries bound ends a walk that would otherwise revisit the same trees without end.
    while (top > 0) {
        top -= 1;
        const digest = stack[top];
        if (seen_before(visited, digest)) continue;
        var errno: u16 = 0;
        const bytes = trees.load(store, digest, buffer, &errno) catch |err| {
            const kind: @TypeOf(failure.kind) = switch (err) {
                error.NotFound => .missing,
                error.Damaged => .damaged,
                error.Unreadable => .unreadable,
            };
            failure.* = .{ .where = digest, .kind = kind, .errno = errno };
            return error.Failed;
        };
        var decoder: tree.Decoder = undefined;
        decoder.init(bytes) catch return damaged(failure, digest);
        var entry: tree.Entry = undefined;
        while (decoder.next(&entry) catch return damaged(failure, digest)) {
            seen += 1;
            if (seen > constants.store_walk_entries_max) {
                failure.* = .{ .where = digest, .kind = .too_many_entries, .errno = 0 };
                return error.Failed;
            }
            visitor.entry(&entry);
            if (entry.kind != .dir) continue;
            if (top == stack.len) {
                failure.* = .{ .where = digest, .kind = .stack_full, .errno = 0 };
                return error.Failed;
            }
            stack[top] = entry.subtree;
            top += 1;
        }
    }
}

/// True if the table of visited trees has `digest`; it is added if not.
fn seen_before(visited: anytype, digest: Digest) bool {
    const Type = @TypeOf(visited);
    if (Type == @TypeOf(null)) return false;
    if (@typeInfo(Type) == .optional) {
        const table = visited orelse return false;
        return table.put(digest, 0) == .present;
    }
    return visited.put(digest, 0) == .present;
}

fn damaged(failure: *Failure, digest: Digest) Error {
    assert(@intFromPtr(failure) != 0);
    assert(digest.bytes.len == constants.store_digest_bytes);
    failure.* = .{ .where = digest, .kind = .damaged, .errno = 0 };
    return error.Failed;
}
