//! The lazy server's node table: every directory, symlink and file of one tree, numbered for the
//! kernel, built once before the mount is served and never changed after.
//!
//! The tree is immutable, so the whole table is built up front from the tree's directory objects
//! (which a lazy start has before any file byte: the index carries them) and then only read. The
//! serving threads share it without a lock, and `FORGET` has nothing to free.
//!
//! Identity follows the hardlink farm: one node per file **object**, so a file's hard links (the
//! entries that name one object) share an inode and its `st_nlink` counts them; the object id
//! commits to the content, mode, owner and attributes, so the links agree on all of them. A
//! directory gets one node per place it appears (two identical subtrees are two directories: the
//! kernel refuses a directory with two parents), and so does each symlink.
//!
//! The build is breadth first over the node array itself: node `i` is expanded once every node
//! before it has been, and its children are appended. There is no recursion and no stack; the
//! node bound ends the walk of any tree, even one whose objects were forged to refer to an
//! ancestor. A directory's children are a run of `children`, in the tree's order (sorted by name
//! bytes, which the decoder enforces), so a lookup is a binary search.
//!
//! The directory objects are copied into `arena` and kept: names, symlink targets and attribute
//! sections are slices of it. Each distinct tree is copied once (a subtree named twice is read
//! again from the arena), so the arena needs no more than the index's trees section, which the
//! caller sizes it to (docs/decisions/2026-11-14-s2-fuse-server.md); `lazy_index_bytes_max` bounds
//! that. Node ids are index + 1, so the root (index 0) is `FUSE_ROOT_ID`.
//!
//! After the build, `number_objects` gives each file node its **ordinal**: its position in the
//! index's object list, which is first appearance in the pack's walk (preorder, names in the
//! tree's order). The chunk resolver addresses objects by that position.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const xattrs = @import("../store/xattrs.zig");

const Digest = digest_mod.Digest;
pub const Kind = tree.Kind;

pub const Node = struct {
    /// A file's object id, a directory's tree digest; zero for a symlink.
    digest: Digest,
    /// A file's length in bytes, a symlink's target length, a directory's tree length (the kernel
    /// is shown a block for a directory, never this).
    size: u64,
    uid: u32,
    gid: u32,
    nlink: u32,
    /// A directory's parent (the root is its own); zero otherwise.
    parent: u32,
    /// A directory's children: `children[children_first..][0..children_count]`. A file has none,
    /// and keeps its ordinal here instead (`Table.ordinal`), so a node stays 80 bytes.
    children_first: u32,
    children_count: u32,
    /// The canonical attribute section, as a slice of `arena`; a length of zero is the empty one.
    xattrs_at: u32,
    xattrs_len: u32,
    /// A symlink's target, or a directory's tree, in `arena` (its length is `size`).
    target_at: u32,
    mode: u16,
    kind: Kind,
};

/// A file node's ordinal before `number_objects` gives it one.
const unnumbered: u32 = std.math.maxInt(u32);

pub const Child = struct {
    node: u32,
    name_at: u32,
    name_len: u8,
};

/// The memory a table works in, all of it the caller's.
pub const Memory = struct {
    nodes: []Node,
    children: []Child,
    /// The object map: a node index + 1 per slot, zero when empty. A power of two, at least twice
    /// the node room, so a probe always ends at an empty slot.
    slots: []u32,
    /// The directory objects. Room for one more tree than `arena_limit` allows, so a tree is
    /// always read whole before it is found to be past the bound.
    arena: []u8,
    arena_limit: u32,
};

/// Reads the tree `digest` into `out` and checks that it hashes to `digest`.
pub const TreeSource = struct {
    context: *anyopaque,
    load: *const fn (context: *anyopaque, digest: Digest, out: []u8) LoadError![]const u8,
};

pub const LoadError = error{ NotFound, Damaged, Unreadable };

pub const BuildError = LoadError || error{
    /// More nodes or children than the table has room for (`lazy_nodes_max`).
    TooManyNodes,
    /// The directory objects together are longer than `arena_limit` (`lazy_index_bytes_max`).
    TooLarge,
    /// A directory object does not decode, a file entry's attributes are not its object id's, or
    /// two entries name one object with different sizes.
    Malformed,
};

pub const Table = struct {
    memory: Memory,
    node_count: u32,
    child_count: u32,
    arena_len: u32,
    /// Distinct file objects, numbered by `number_objects`.
    object_count: u32,

    pub fn init(table: *Table, memory: Memory) void {
        assert(memory.nodes.len > 0);
        assert(memory.nodes.len < std.math.maxInt(u32));
        assert(std.math.isPowerOfTwo(memory.slots.len));
        // The map always has a free slot, and is at most about half full: the nodes are the
        // entries plus the root, the slots at least twice the entries (`slots_for`).
        assert(memory.slots.len > memory.nodes.len);
        assert(memory.slots.len >= 2 * (memory.nodes.len - 1));
        assert(memory.children.len == memory.nodes.len - 1);
        // The arena is the trees' room plus one tree, read whole before it is found too large.
        assert(memory.arena.len == @as(u64, memory.arena_limit) + constants.store_tree_bytes_max);
        assert(memory.arena.len < std.math.maxInt(u32));
        table.* = .{
            .memory = memory,
            .node_count = 0,
            .child_count = 0,
            .arena_len = 0,
            .object_count = 0,
        };
        @memset(memory.slots, 0);
    }

    /// The node of a kernel node id, or null for an id the table never gave out.
    pub fn node(table: *const Table, nodeid: u64) ?*const Node {
        assert(table.node_count <= table.memory.nodes.len);
        if (nodeid == 0) return null;
        if (nodeid > table.node_count) return null;
        const found = &table.memory.nodes[@intCast(nodeid - 1)];
        assert(found.nlink > 0);
        return found;
    }

    pub fn index_of(table: *const Table, found: *const Node) u32 {
        const base = @intFromPtr(table.memory.nodes.ptr);
        assert(@intFromPtr(found) >= base);
        const index: u32 = @intCast(@divExact(@intFromPtr(found) - base, @sizeOf(Node)));
        assert(index < table.node_count);
        return index;
    }

    pub fn children(table: *const Table, directory: *const Node) []const Child {
        assert(directory.kind == .dir);
        assert(directory.children_first + directory.children_count <= table.child_count);
        return table.memory.children[directory.children_first..][0..directory.children_count];
    }

    pub fn name(table: *const Table, child: Child) []const u8 {
        assert(child.name_len > 0);
        assert(child.name_at + child.name_len <= table.arena_len);
        return table.memory.arena[child.name_at..][0..child.name_len];
    }

    pub fn attributes(table: *const Table, found: *const Node) []const u8 {
        assert(found.xattrs_at + found.xattrs_len <= table.arena_len);
        if (found.xattrs_len == 0) return &xattrs.empty;
        return table.memory.arena[found.xattrs_at..][0..found.xattrs_len];
    }

    /// A file's position in the index's object list.
    pub fn ordinal(table: *const Table, found: *const Node) u32 {
        assert(found.kind == .file);
        assert(found.children_first < table.object_count);
        return found.children_first;
    }

    pub fn target(table: *const Table, found: *const Node) []const u8 {
        assert(found.kind == .symlink);
        assert(found.size > 0);
        assert(found.target_at + found.size <= table.arena_len);
        return table.memory.arena[found.target_at..][0..@intCast(found.size)];
    }

    /// The child of `directory` called `wanted`, by binary search of the sorted names.
    pub fn lookup(table: *const Table, directory: *const Node, wanted: []const u8) ?Child {
        assert(directory.kind == .dir);
        assert(wanted.len > 0);
        const list = table.children(directory);
        var low: u32 = 0;
        var high: u32 = @intCast(list.len);
        while (low < high) {
            const middle = low + @divFloor(high - low, 2);
            switch (std.mem.order(u8, table.name(list[middle]), wanted)) {
                .eq => return list[middle],
                .lt => low = middle + 1,
                .gt => high = middle,
            }
        }
        assert(low == high);
        return null;
    }

    /// Builds the table of the tree `root`, reading its directory objects from `source`.
    pub fn build(table: *Table, source: TreeSource, root: Digest) BuildError!void {
        assert(table.node_count == 0);
        assert(table.child_count == 0);
        table.memory.nodes[0] = .{
            .digest = root,
            .size = 0,
            .uid = 0,
            .gid = 0,
            .nlink = 2,
            .parent = 0,
            .children_first = 0,
            .children_count = 0,
            .xattrs_at = 0,
            .xattrs_len = 0,
            .target_at = 0,
            .mode = 0o755,
            .kind = .dir,
        };
        table.node_count = 1;
        var index: u32 = 0;
        while (index < table.node_count) : (index += 1) {
            assert(index < table.memory.nodes.len);
            if (table.memory.nodes[index].kind == .dir) try table.expand(source, index);
        }
        assert(table.node_count <= table.memory.nodes.len);
        assert(table.memory.nodes[0].kind == .dir);
        try table.number_objects();
    }

    /// Gives each file node its ordinal: first appearance in a preorder walk, names in the tree's
    /// order, as the pack writes the layer and the index lists objects. A subtree named twice is
    /// walked twice, and its files are already numbered the second time.
    fn number_objects(table: *Table) BuildError!void {
        assert(table.object_count == 0);
        const Frame = struct { node: u32, next: u32 };
        var frames: [constants.store_depth_max + 1]Frame = undefined;
        frames[0] = .{ .node = 0, .next = 0 };
        var depth: u32 = 1;
        while (depth > 0) {
            const frame = &frames[depth - 1];
            const list = table.children(&table.memory.nodes[frame.node]);
            if (frame.next == list.len) {
                depth -= 1;
                continue;
            }
            const child = list[frame.next];
            frame.next += 1;
            const named = &table.memory.nodes[child.node];
            switch (named.kind) {
                .file => if (named.children_first == unnumbered) {
                    named.children_first = table.object_count;
                    table.object_count += 1;
                },
                .dir => {
                    // The store never holds a deeper tree; an index that names one is forged.
                    if (depth == frames.len) return error.Malformed;
                    frames[depth] = .{ .node = child.node, .next = 0 };
                    depth += 1;
                },
                .symlink => {},
            }
        }
        assert(table.object_count <= table.node_count);
    }

    fn expand(table: *Table, source: TreeSource, index: u32) BuildError!void {
        assert(table.memory.nodes[index].kind == .dir);
        assert(table.arena_len <= table.memory.arena_limit);
        const bytes = try table.tree_of(source, index);
        table.memory.nodes[index].target_at = table.offset_of(bytes);
        table.memory.nodes[index].size = bytes.len;
        var decoder: tree.Decoder = undefined;
        decoder.init(bytes) catch return error.Malformed;
        const first = table.child_count;
        var entry: tree.Entry = undefined;
        while (decoder.next(&entry) catch return error.Malformed) {
            try table.add_child(index, &entry);
        }
        const directory = &table.memory.nodes[index];
        directory.children_first = first;
        directory.children_count = table.child_count - first;
        if (index == 0) {
            // The root has no entry in a parent: its own section says what it is.
            directory.mode = decoder.own.mode;
            directory.uid = decoder.own.uid;
            directory.gid = decoder.own.gid;
            table.set_attributes(directory, decoder.own.xattrs);
        }
    }

    /// The directory object of node `index`: read from `source` into the arena the first time its
    /// digest is met, and the arena's copy after that.
    fn tree_of(table: *Table, source: TreeSource, index: u32) BuildError![]const u8 {
        const digest = table.memory.nodes[index].digest;
        const slot = table.slot_of(digest, .dir);
        const held = table.memory.slots[slot];
        if (held != 0) {
            assert(held - 1 < index); // Breadth first: the earlier node was expanded first.
            const earlier = &table.memory.nodes[held - 1];
            assert(earlier.target_at + earlier.size <= table.arena_len);
            return table.memory.arena[earlier.target_at..][0..@intCast(earlier.size)];
        }
        const room = table.memory.arena[table.arena_len..];
        assert(room.len >= constants.store_tree_bytes_max);
        const bytes = try source.load(source.context, digest, room);
        assert(bytes.ptr == room.ptr);
        if (bytes.len > table.memory.arena_limit - table.arena_len) return error.TooLarge;
        table.arena_len += @intCast(bytes.len);
        table.memory.slots[slot] = index + 1;
        return bytes;
    }

    /// The map slot of `digest` among nodes of `kind`: the one that holds it, or the empty one
    /// where it goes. Files are keyed by object id, directories by tree digest.
    fn slot_of(table: *const Table, digest: Digest, kind: Kind) usize {
        assert(kind != .symlink);
        const mask = table.memory.slots.len - 1;
        var slot: usize = std.mem.readInt(u64, digest.bytes[0..8], .little) & mask;
        var probes: usize = 0;
        while (probes < table.memory.slots.len) : (probes += 1) {
            const held = table.memory.slots[slot];
            if (held == 0) return slot;
            const existing = &table.memory.nodes[held - 1];
            if (existing.kind == kind and existing.digest.eql(digest)) return slot;
            slot = (slot + 1) & mask;
        }
        // The map is at least twice the node room and each taken slot holds a distinct node, so
        // it is never full.
        unreachable;
    }

    fn add_child(table: *Table, parent: u32, entry: *const tree.Entry) BuildError!void {
        assert(tree.name_is_valid(entry.name));
        assert(entry.mode <= 0o7777);
        if (table.child_count >= table.memory.children.len) return error.TooManyNodes;
        const node_index = switch (entry.kind) {
            .file => try table.file_node(entry),
            .dir => try table.new_node(entry, parent),
            .symlink => try table.new_node(entry, parent),
        };
        if (entry.kind == .dir) table.memory.nodes[parent].nlink += 1; // Its "..".
        table.memory.children[table.child_count] = .{
            .node = node_index,
            .name_at = table.offset_of(entry.name),
            .name_len = @intCast(entry.name.len),
        };
        table.child_count += 1;
    }

    /// The node of a file entry's object: the one an earlier link made, or a new one.
    fn file_node(table: *Table, entry: *const tree.Entry) BuildError!u32 {
        assert(entry.kind == .file);
        const slot = table.slot_of(entry.object, .file);
        const held = table.memory.slots[slot];
        if (held == 0) {
            const created = try table.new_node(entry, 0);
            table.memory.nodes[created].children_first = unnumbered;
            table.memory.slots[slot] = created + 1;
            return created;
        }
        const existing = &table.memory.nodes[held - 1];
        assert(existing.kind == .file);
        // One object is one content: a tree that gives it two sizes is lying.
        if (existing.size != entry.size) return error.Malformed;
        existing.nlink += 1;
        return held - 1;
    }

    fn new_node(table: *Table, entry: *const tree.Entry, parent: u32) BuildError!u32 {
        assert(parent < table.node_count);
        if (table.node_count >= table.memory.nodes.len) return error.TooManyNodes;
        const created = table.node_count;
        const fresh = &table.memory.nodes[created];
        fresh.* = .{
            .digest = Digest{ .bytes = @splat(0) },
            .size = 0,
            .uid = entry.uid,
            .gid = entry.gid,
            .nlink = 1,
            .parent = 0,
            .children_first = 0,
            .children_count = 0,
            .xattrs_at = 0,
            .xattrs_len = 0,
            .target_at = 0,
            .mode = entry.mode,
            .kind = entry.kind,
        };
        switch (entry.kind) {
            .file => {
                if (entry.size > constants.store_file_bytes_max) return error.Malformed;
                // The entry's mode, owner and attributes are what the node shows, and the object
                // id commits to them: an entry that disagrees with its own id is refused, so every
                // link of one object shows the same attributes.
                const attrs: object.Attrs = .{
                    .mode = entry.mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .xattrs = entry.xattrs,
                };
                if (!object.object_id(entry.content, attrs).eql(entry.object)) {
                    return error.Malformed;
                }
                fresh.digest = entry.object;
                fresh.size = entry.size;
            },
            .dir => {
                fresh.digest = entry.subtree;
                fresh.nlink = 2;
                fresh.parent = parent;
            },
            .symlink => {
                assert(entry.target.len > 0);
                fresh.size = entry.target.len;
                fresh.target_at = table.offset_of(entry.target);
            },
        }
        table.set_attributes(fresh, entry.xattrs);
        table.node_count += 1;
        return created;
    }

    fn set_attributes(table: *const Table, target_node: *Node, section: []const u8) void {
        assert(section.len > 0);
        if (section.len == 1) {
            assert(section[0] == 0); // The empty section: no attributes.
            target_node.xattrs_at = 0;
            target_node.xattrs_len = 0;
        } else {
            target_node.xattrs_at = table.offset_of(section);
            target_node.xattrs_len = @intCast(section.len);
        }
    }

    /// Where a slice of a decoded tree sits in the arena.
    fn offset_of(table: *const Table, slice: []const u8) u32 {
        const base = @intFromPtr(table.memory.arena.ptr);
        assert(@intFromPtr(slice.ptr) >= base);
        const at = @intFromPtr(slice.ptr) - base;
        assert(at + slice.len <= table.arena_len);
        return @intCast(at);
    }
};

/// Map slots for a table of `entries` entries: at least twice them, and four, so the map always
/// keeps a free slot for the root's node too.
fn slots_for(entries: u32) u64 {
    assert(entries > 0);
    const slots = std.math.ceilPowerOfTwoAssert(u64, @max(2 * @as(u64, entries), 4));
    assert(slots > @as(u64, entries) + 1);
    return slots;
}

/// Bytes of memory a table with room for `entries` entries below the root and `arena_limit`
/// bytes of directories takes, laid out by `carve`.
pub fn memory_bytes(entries: u32, arena_limit: u32) u64 {
    assert(entries > 0);
    assert(arena_limit > 0);
    const node_room = @as(u64, entries) + 1;
    return node_room * @sizeOf(Node) + @as(u64, entries) * @sizeOf(Child) +
        slots_for(entries) * @sizeOf(u32) + arena_limit + constants.store_tree_bytes_max;
}

/// Lays a table's memory out in one region of `memory_bytes(entries, arena_limit)` bytes. The
/// bound counts entries below the root: a table has a child per entry and a node per entry at
/// most (hard links share one), plus the root's node.
pub fn carve(region: []align(8) u8, entries: u32, arena_limit: u32) Memory {
    assert(region.len >= memory_bytes(entries, arena_limit));
    assert(entries > 0);
    const slots: usize = @intCast(slots_for(entries));
    var at: usize = 0;
    const node_bytes = (@as(usize, entries) + 1) * @sizeOf(Node);
    const nodes_slice: []Node = @alignCast(std.mem.bytesAsSlice(Node, region[at..][0..node_bytes]));
    at += node_bytes;
    const child_bytes = @as(usize, entries) * @sizeOf(Child);
    const children: []Child = @alignCast(std.mem.bytesAsSlice(Child, region[at..][0..child_bytes]));
    at += child_bytes;
    const slots_slice: []u32 = @alignCast(std.mem.bytesAsSlice(u32, region[at..][0 .. slots * 4]));
    at += slots * 4;
    const arena = region[at..][0 .. arena_limit + constants.store_tree_bytes_max];
    assert(nodes_slice.len == children.len + 1);
    return .{
        .nodes = nodes_slice,
        .children = children,
        .slots = slots_slice,
        .arena = arena,
        .arena_limit = arena_limit,
    };
}

comptime {
    assert(@sizeOf(Node) == 80);
    assert(@sizeOf(Child) <= 12);
    assert(@alignOf(Node) <= 8);
    // The fixed part at its bound is the approved 25 MiB (a node, a child and two map slots per
    // node); the arena is the trees section on top (docs/decisions/2026-11-14-s2-fuse-server.md).
    // The root's node is one more than the entries the bound counts.
    const fixed = memory_bytes(constants.lazy_nodes_max, 1) - 1 - constants.store_tree_bytes_max;
    assert(fixed <= 25 * 1024 * 1024 + @sizeOf(Node));
    assert(@as(u64, constants.lazy_index_bytes_max) + constants.store_tree_bytes_max <
        std.math.maxInt(u32));
}

const testing = std.testing;
const fixture_mod = @import("fixture.zig");

var test_fixture: fixture_mod.Fixture = undefined;

/// A root holding `a` (a file), `d/` (with `x` and `y`, two links of one object), and `l` (a
/// symlink to `a`).
fn sample(fixture: *fixture_mod.Fixture) !Digest {
    fixture.init(64);
    _ = fixture.begin();
    _ = try fixture.file("x", "linked", 0o600, &xattrs.empty);
    _ = try fixture.file("y", "linked", 0o600, &xattrs.empty);
    const sub = fixture.finish();
    _ = fixture.begin();
    _ = try fixture.file("a", "hello", 0o644, &xattrs.empty);
    try fixture.dir("d", sub);
    try fixture.symlink("l", "a");
    return fixture.finish_root(.{ .mode = 0o750, .uid = 7, .gid = 8, .xattrs = &xattrs.empty });
}

fn built(region_out: *[]align(8) u8, nodes_room: u32, limit: u32, root: Digest) !Table {
    const held = try fixture_mod.table_memory(testing.allocator, nodes_room, limit);
    region_out.* = held.region;
    var table: Table = undefined;
    table.init(held.memory);
    try table.build(test_fixture.source(), root);
    return table;
}

test "a tree becomes a table: links share a node, directories count their subdirectories" {
    // Goal: the table shows the tree the farm would. Method: build the sample and check every
    // node: the root's own metadata, `nlink` of the root and of the shared object, the parent of
    // the subdirectory, the symlink's target, and lookups that hit and miss.
    const root = try sample(&test_fixture);
    var region: []align(8) u8 = &.{};
    defer testing.allocator.free(region);
    const table = try built(&region, 16, 4096, root);
    try testing.expectEqual(@as(u32, 5), table.node_count); // root, a, d, l, one for x and y.
    const top = table.node(1).?;
    try testing.expectEqual(@as(u16, 0o750), top.mode);
    try testing.expectEqual(@as(u32, 7), top.uid);
    try testing.expectEqual(@as(u32, 3), top.nlink); // ".", its entry, and d's "..".
    const d = table.lookup(top, "d").?;
    const d_node = table.node(d.node + 1).?;
    try testing.expectEqual(Kind.dir, d_node.kind);
    try testing.expectEqual(@as(u32, 0), d_node.parent);
    const x = table.lookup(d_node, "x").?;
    const y = table.lookup(d_node, "y").?;
    try testing.expectEqual(x.node, y.node);
    try testing.expectEqual(@as(u32, 2), table.node(x.node + 1).?.nlink);
    try testing.expectEqual(@as(u64, 6), table.node(x.node + 1).?.size);
    const l = table.node(table.lookup(top, "l").?.node + 1).?;
    try testing.expectEqualStrings("a", table.target(l));
    try testing.expect(table.lookup(top, "b") == null);
    try testing.expect(table.lookup(top, "e") == null);
    try testing.expect(table.lookup(d_node, "a") == null);
    try testing.expect(table.node(0) == null);
    try testing.expect(table.node(6) == null);
}

test "the node bound: a tree of exactly the room builds, one more node is refused" {
    // Goal: `TooManyNodes` is reached at the bound, not before; the bound counts entries below
    // the root. Method: the sample has five entries (a, d, l, x, y) and five nodes with the
    // root; room for five entries builds, room for four is refused.
    const root = try sample(&test_fixture);
    var region: []align(8) u8 = &.{};
    defer testing.allocator.free(region);
    _ = try built(&region, 5, 4096, root);
    testing.allocator.free(region);
    region = &.{};
    try testing.expectError(error.TooManyNodes, built(&region, 4, 4096, root));
}

test "the directory bound: trees of exactly the limit fit, one byte less is refused" {
    // Goal: `TooLarge` is reached at `arena_limit`, not before. Method: sum the two trees'
    // lengths and build with that limit, then with one byte less.
    const root = try sample(&test_fixture);
    const total = test_fixture.tree_len;
    var region: []align(8) u8 = &.{};
    defer testing.allocator.free(region);
    _ = try built(&region, 16, total, root);
    testing.allocator.free(region);
    region = &.{};
    try testing.expectError(error.TooLarge, built(&region, 16, total - 1, root));
}

test "a tree that lies about a file, or names a missing tree, is refused" {
    // Goal: the table is only ever built from a tree whose entries agree with their object ids.
    // Method: an entry whose object id is not its attributes'; two links of one object with
    // different sizes; a subdirectory whose tree is not held.
    var region: []align(8) u8 = &.{};
    defer testing.allocator.free(region);
    const fixture = &test_fixture;
    fixture.init(64);
    var writer = fixture.begin();
    try writer.begin("a", .file, 0o644, 0, 0, &xattrs.empty);
    try writer.end_file(5, Digest.of("hello"), Digest.of("not its id"));
    const forged = fixture.finish();
    try testing.expectError(error.Malformed, built(&region, 16, 4096, forged));
    testing.allocator.free(region);
    region = &.{};

    const content = Digest.of("hello");
    const id = object.object_id(content, .{
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .xattrs = &xattrs.empty,
    });
    writer = fixture.begin();
    try writer.begin("a", .file, 0o644, 0, 0, &xattrs.empty);
    try writer.end_file(5, content, id);
    try writer.begin("b", .file, 0o644, 0, 0, &xattrs.empty);
    try writer.end_file(6, content, id);
    const sizes = fixture.finish();
    try testing.expectError(error.Malformed, built(&region, 16, 4096, sizes));
    testing.allocator.free(region);
    region = &.{};

    _ = fixture.begin();
    try fixture.dir("d", Digest.of("no such tree"));
    const missing = fixture.finish();
    try testing.expectError(error.NotFound, built(&region, 16, 4096, missing));
}

test "a subtree named twice is copied once, and ordinals follow the pack's walk" {
    // Goal: the arena needs only the distinct trees, and each file's ordinal is its first
    // appearance in a preorder walk. Method: a root names one subtree twice (`d1`, `d2`) and then
    // a file `z`; the arena is sized to exactly the two distinct trees and the build succeeds;
    // the subtree's files take ordinals 0 and 1 under `d1`, keep them under `d2`, and `z` is 2.
    const fixture = &test_fixture;
    fixture.init(64);
    _ = fixture.begin();
    _ = try fixture.file("p", "first", 0o644, &xattrs.empty);
    _ = try fixture.file("q", "second", 0o644, &xattrs.empty);
    const sub = fixture.finish();
    _ = fixture.begin();
    try fixture.dir("d1", sub);
    try fixture.dir("d2", sub);
    _ = try fixture.file("z", "last", 0o644, &xattrs.empty);
    const own: tree.Own = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    const root = try fixture.finish_root(own);
    const distinct = fixture.trees[0].len + fixture.trees[1].len;
    var region: []align(8) u8 = &.{};
    defer testing.allocator.free(region);
    const table = try built(&region, 16, distinct, root);
    try testing.expectEqual(distinct, table.arena_len);
    try testing.expectEqual(@as(u32, 3), table.object_count);
    const want = [_]struct { path: []const u8, ordinal: u32 }{
        .{ .path = "d1/p", .ordinal = 0 },
        .{ .path = "d1/q", .ordinal = 1 },
        .{ .path = "d2/p", .ordinal = 0 },
        .{ .path = "d2/q", .ordinal = 1 },
        .{ .path = "z", .ordinal = 2 },
    };
    for (want) |entry| {
        var at: u64 = 1; // The root.
        var parts = std.mem.splitScalar(u8, entry.path, '/');
        while (parts.next()) |part| at = @as(u64, table.lookup(table.node(at).?, part).?.node) + 1;
        try testing.expectEqual(entry.ordinal, table.ordinal(table.node(at).?));
    }
    // One byte less and the second tree does not fit.
    var short: []align(8) u8 = &.{};
    defer testing.allocator.free(short);
    try testing.expectError(error.TooLarge, built(&short, 16, distinct - 1, root));
}
