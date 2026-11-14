//! The checks an index passes before lazy start uses any of it (`E1202` when one fails): its
//! bytes are the ones the annotation hashed, its root is the manifest's tree, and its trees and
//! objects are exactly the pack walk's first appearances. The walk here is the pack's (names in
//! each tree's order, a directory's entries right after its own entry), over the index's own
//! trees, skipping a subtree it has met before and counting its names from what it counted then.
//!
//! Every chunk is anchored to its file's content hash, so to the tree: a one-chunk file's chunk
//! hash is its content, and a longer file's chunk chaining values join into its content
//! (`chaining.zig`, `docs/decisions/2026-11-14-s2-chunk-anchor.md`). A fetched chunk is checked
//! against its chaining value at its place before any byte of it is used. A longer file's plain
//! chunk hashes (what the store's chunk list holds) cannot be checked without the bytes; the
//! fetch checks them too, and a chunk that matches its chaining value but not its hash means the
//! index lied.
//!
//! Pure, like `index.zig`; it writes nothing. A caller stores the trees with
//! `trees.put_checked`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chaining = @import("chaining.zig");
const index_mod = @import("index.zig");
const seen_mod = @import("seen.zig");
const tree_mod = @import("../store/tree.zig");
const Digest = @import("../store/digest.zig").Digest;

const Index = index_mod.Index;
pub const key_bytes = seen_mod.key_bytes;
const Refusal = index_mod.Refusal;

/// A tree being walked; its name count is not known yet.
const pending: u32 = std.math.maxInt(u32);

comptime {
    assert(constants.lazy_nodes_max < pending);
}

const Frame = struct {
    decoder: tree_mod.Decoder,
    digest: Digest,
    names: u32,
};

/// About 20 MiB; kept by the caller, who sets `key` to fresh random bytes before each walk (the
/// walk is pure, so it cannot draw them itself).
pub const Workspace = struct {
    key: [seen_mod.key_bytes]u8,
    seen: seen_mod.Seen,
    frames: [constants.store_depth_max + 1]Frame,
};

const Walk = struct {
    ws: *Workspace,
    index: *const Index,
    trees: index_mod.Trees,
    objects: u32,
    depth: u32,
    empty: Digest,

    fn top(walk: *Walk) *Frame {
        assert(walk.depth > 0);
        assert(walk.depth <= walk.ws.frames.len);
        return &walk.ws.frames[walk.depth - 1];
    }
};

/// Checks `bytes` against the annotation and the tree, and returns the parsed index.
pub fn verify(
    ws: *Workspace,
    bytes: []const u8,
    anchor: *const index_mod.Anchor,
    tree: Digest,
) Refusal!Index {
    assert(@intFromPtr(ws) != 0);
    assert(bytes.len <= std.math.maxInt(u32));
    try anchor.check();
    if (bytes.len != anchor.size) return error.Malformed;
    if (!Digest.of(bytes).eql(anchor.digest)) return error.Malformed;
    const index = try index_mod.parse(bytes);
    if (!index.header.tree.eql(tree)) return error.Malformed;
    if (index.chunks_end() > anchor.offset) return error.Malformed;
    try walk_index(ws, &index);
    return index;
}

/// The walk over the index's trees (see the file's comment).
pub fn walk_index(ws: *Workspace, index: *const Index) Refusal!void {
    assert(index.header.complete);
    assert(index.header.names <= constants.lazy_nodes_max);
    ws.seen.reset(&ws.key);
    var walk: Walk = .{
        .ws = ws,
        .index = index,
        .trees = index.tree_records(),
        .objects = 0,
        .depth = 0,
        .empty = Digest.of(""),
    };
    try push(&walk, index.header.tree);
    var total: u32 = 0;
    var entry: tree_mod.Entry = undefined;
    while (walk.depth > 0) {
        const frame = walk.top();
        const more = frame.decoder.next(&entry) catch return error.Malformed;
        if (!more) {
            walk.ws.seen.set(.tree, frame.digest, frame.names);
            walk.depth -= 1;
            if (walk.depth == 0) {
                total = frame.names;
            } else {
                try add_names(walk.top(), frame.names);
            }
            continue;
        }
        try add_names(frame, 1);
        switch (entry.kind) {
            .symlink => {},
            .file => try check_file(&walk, &entry),
            .dir => try enter(&walk, entry.subtree),
        }
    }
    if (walk.trees.left != 0) return error.Malformed;
    if (walk.objects != index.header.objects) return error.Malformed;
    if (total != index.header.names) return error.Malformed;
}

/// Adds names to a tree's count. The header's count is within `lazy_nodes_max`, so a tree with
/// more is not the one the header counted.
fn add_names(frame: *Frame, names: u32) Refusal!void {
    assert(frame.names <= constants.lazy_nodes_max);
    assert(names <= constants.lazy_nodes_max);
    frame.names += names;
    if (frame.names > constants.lazy_nodes_max) return error.Malformed;
}

/// A directory entry: counted from before when its tree was met, else the next tree listed.
fn enter(walk: *Walk, subtree: Digest) Refusal!void {
    assert(walk.depth > 0);
    assert(walk.depth <= walk.ws.frames.len);
    if (walk.ws.seen.get(.tree, subtree)) |names| {
        // A tree inside itself: its hash would be part of its own bytes.
        if (names == pending) return error.Malformed;
        return add_names(walk.top(), names);
    }
    try push(walk, subtree);
}

/// Starts walking the next tree listed, which must be `digest`.
fn push(walk: *Walk, digest: Digest) Refusal!void {
    assert(walk.depth <= walk.ws.frames.len);
    assert(walk.trees.left <= walk.index.header.trees);
    if (walk.depth == walk.ws.frames.len) return error.Malformed;
    const record = walk.trees.next() orelse return error.Malformed;
    if (!record.digest.eql(digest)) return error.Malformed;
    if (!Digest.of(record.bytes).eql(digest)) return error.Malformed;
    const frame = &walk.ws.frames[walk.depth];
    frame.decoder.init(record.bytes) catch return error.Malformed;
    frame.digest = digest;
    frame.names = 0;
    if (!walk.ws.seen.add(.tree, digest, pending)) return error.Malformed;
    walk.depth += 1;
}

/// A file entry: its object listed with its size, at its first appearance, by the store's rules
/// for chunks (a one-chunk file's chunk is its content, an empty file's content is empty), and
/// a longer file's chunks anchored to its content.
fn check_file(walk: *Walk, entry: *const tree_mod.Entry) Refusal!void {
    assert(entry.kind == .file);
    assert(walk.objects <= walk.index.header.objects);
    if (walk.ws.seen.get(.object, entry.object)) |ordinal| {
        if (walk.index.object(ordinal).size != entry.size) return error.Malformed;
        return;
    }
    if (walk.objects == walk.index.header.objects) return error.Malformed;
    const record = walk.index.object(walk.objects);
    if (!record.id.eql(entry.object)) return error.Malformed;
    if (record.size != entry.size) return error.Malformed;
    if (!walk.ws.seen.add(.object, entry.object, walk.objects)) return error.Malformed;
    walk.objects += 1;
    if (record.size == 0 and !entry.content.eql(walk.empty)) return error.Malformed;
    if (record.chunk_count == 1) {
        const chunk = walk.index.chunk(record.first_chunk);
        if (!chunk.hash.eql(entry.content)) return error.Malformed;
        if (!chunk.chaining.eql(zero)) return error.Malformed;
    }
    if (record.chunk_count >= 2) try check_anchors(walk.index, &record, entry.content);
}

const zero: Digest = .{ .bytes = @splat(0) };

/// The chaining values of a file of two chunks or more join into its content hash.
fn check_anchors(
    index: *const Index,
    record: *const index_mod.Object,
    content: Digest,
) Refusal!void {
    assert(record.chunk_count >= 2);
    assert(record.first_chunk + record.chunk_count <= index.header.chunks);
    var joiner = chaining.Joiner.init();
    const last = record.first_chunk + record.chunk_count - 1;
    for (record.first_chunk..last) |ordinal| {
        joiner.add(&index.chunk(@intCast(ordinal)).chaining);
    }
    const root = joiner.root(&index.chunk(last).chaining);
    if (!root.eql(content)) return error.Malformed;
}
