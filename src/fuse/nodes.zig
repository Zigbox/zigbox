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
//! sections are slices of it. Their total is bounded by `lazy_index_bytes_max`, the bound on the
//! index that carries them. Node ids are index + 1, so the root (index 0) is `FUSE_ROOT_ID`.

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
    /// A file's length in bytes, a symlink's target length; zero for a directory.
    size: u64,
    uid: u32,
    gid: u32,
    nlink: u32,
    /// A directory's parent (the root is its own); zero otherwise.
    parent: u32,
    /// A directory's children: `children[children_first..][0..children_count]`.
    children_first: u32,
    children_count: u32,
    /// The canonical attribute section, as a slice of `arena`; a length of zero is the empty one.
    xattrs_at: u32,
    xattrs_len: u32,
    /// A symlink's target in `arena` (its length is `size`).
    target_at: u32,
    mode: u16,
    kind: Kind,
};

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

    pub fn init(table: *Table, memory: Memory) void {
        assert(memory.nodes.len > 0);
        assert(memory.nodes.len < std.math.maxInt(u32));
        assert(std.math.isPowerOfTwo(memory.slots.len));
        assert(memory.slots.len >= 2 * memory.nodes.len);
        assert(memory.arena.len >= @as(u64, memory.arena_limit) + constants.store_tree_bytes_max);
        assert(memory.arena.len < std.math.maxInt(u32));
        table.* = .{ .memory = memory, .node_count = 0, .child_count = 0, .arena_len = 0 };
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
    }

    fn expand(table: *Table, source: TreeSource, index: u32) BuildError!void {
        assert(table.memory.nodes[index].kind == .dir);
        assert(table.arena_len <= table.memory.arena_limit);
        const room = table.memory.arena[table.arena_len..];
        assert(room.len >= constants.store_tree_bytes_max);
        const bytes = try source.load(source.context, table.memory.nodes[index].digest, room);
        assert(bytes.ptr == room.ptr);
        if (bytes.len > table.memory.arena_limit - table.arena_len) return error.TooLarge;
        table.arena_len += @intCast(bytes.len);
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
        const mask = table.memory.slots.len - 1;
        var slot: usize = std.mem.readInt(u64, entry.object.bytes[0..8], .little) & mask;
        var probes: usize = 0;
        while (probes < table.memory.slots.len) : (probes += 1) {
            const held = table.memory.slots[slot];
            if (held == 0) {
                const created = try table.new_node(entry, 0);
                table.memory.slots[slot] = created + 1;
                return created;
            }
            const existing = &table.memory.nodes[held - 1];
            assert(existing.kind == .file);
            if (existing.digest.eql(entry.object)) {
                // One object is one content: a tree that gives it two sizes is lying.
                if (existing.size != entry.size) return error.Malformed;
                existing.nlink += 1;
                return held - 1;
            }
            slot = (slot + 1) & mask;
        }
        // The map is at least twice the node room and a node is made before its slot is taken,
        // so a full map would mean more nodes than room.
        unreachable;
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

/// Bytes of memory a table with room for `nodes` nodes and `arena_limit` bytes of directories
/// takes, laid out by `carve`.
pub fn memory_bytes(nodes: u32, arena_limit: u32) u64 {
    assert(nodes > 0);
    assert(arena_limit > 0);
    const slots = std.math.ceilPowerOfTwoAssert(u64, 2 * @as(u64, nodes));
    return @as(u64, nodes) * @sizeOf(Node) + @as(u64, nodes) * @sizeOf(Child) +
        slots * @sizeOf(u32) + arena_limit + constants.store_tree_bytes_max;
}

/// Lays a table's memory out in one region of `memory_bytes(nodes, arena_limit)` bytes. A
/// directory has an entry per child, so a table's children are at most its nodes.
pub fn carve(region: []align(8) u8, nodes: u32, arena_limit: u32) Memory {
    assert(region.len >= memory_bytes(nodes, arena_limit));
    assert(nodes > 0);
    const slots: usize = @intCast(std.math.ceilPowerOfTwoAssert(u64, 2 * @as(u64, nodes)));
    var at: usize = 0;
    const node_bytes = @as(usize, nodes) * @sizeOf(Node);
    const nodes_slice: []Node = @alignCast(std.mem.bytesAsSlice(Node, region[at..][0..node_bytes]));
    at += node_bytes;
    const child_bytes = @as(usize, nodes) * @sizeOf(Child);
    const children: []Child = @alignCast(std.mem.bytesAsSlice(Child, region[at..][0..child_bytes]));
    at += child_bytes;
    const slots_slice: []u32 = @alignCast(std.mem.bytesAsSlice(u32, region[at..][0 .. slots * 4]));
    at += slots * 4;
    const arena = region[at..][0 .. arena_limit + constants.store_tree_bytes_max];
    return .{
        .nodes = nodes_slice,
        .children = children,
        .slots = slots_slice,
        .arena = arena,
        .arena_limit = arena_limit,
    };
}

comptime {
    assert(@sizeOf(Node) <= 80);
    assert(@sizeOf(Child) <= 12);
    assert(@alignOf(Node) <= 8);
    // The node table at its bound stays near the brief's 24 MiB, before the directory objects.
    assert(@as(u64, constants.lazy_nodes_max) * (@sizeOf(Node) + @sizeOf(Child) + 8) <
        32 * 1024 * 1024);
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
    // Goal: `TooManyNodes` is reached at the bound, not before. Method: the sample has five
    // nodes and six children; room for five builds, room for four is refused.
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
