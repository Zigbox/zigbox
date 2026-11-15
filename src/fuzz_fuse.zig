//! The `fuse_request` fuzzer: `zig build fuzz -- fuse_request`. The lazy server's request handler
//! (`fuse/ops.zig`) takes bytes from the kernel, and its node table (`fuse/nodes.zig`) is built
//! from directory objects an index delivered. Each iteration builds a random tree in memory (files
//! of random sizes over a random chunk size, hard links, a subtree named twice, symlinks,
//! attributes), sometimes damages the root's object, builds the table with random room, and sends
//! the handler random requests, well formed and damaged.
//!
//! Properties:
//!   1. A build either fails with a `BuildError` or gives a table whose invariants hold: children
//!      sorted and in range, each subdirectory's parent its directory, a directory's `nlink` two
//!      plus its subdirectories, a file's `nlink` the entries naming it.
//!   2. After every request the table is unchanged, byte for byte, and its invariants still hold.
//!   3. Every reply is due or not as the opcode says; a due reply has the request's `unique`, a
//!      length equal to its bytes, and either no error or one of the server's errors with no data.
//!   4. A `READ` that succeeds returns exactly the file's bytes at that offset (the oracle is the
//!      fixture's content), and one of an object whose chunks fail never succeeds with data.
//!   5. A `READDIRPLUS` that succeeds holds whole records, in order, within the asked size, and
//!      is empty only at or past the directory's end.
//!   6. A built table's file ordinals are first appearance in a preorder walk of the fixture's own
//!      trees (the index's object order), its object count is that walk's distinct objects, and
//!      its arena holds each distinct tree once.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const xattrs = @import("store/xattrs.zig");
const tree = @import("store/tree.zig");
const abi = @import("fuse/abi.zig");
const nodes = @import("fuse/nodes.zig");
const ops = @import("fuse/ops.zig");
const fixture_mod = @import("fuse/fixture.zig");
const cache_mod = @import("fuse/cache.zig");

const Digest = @import("store/digest.zig").Digest;

const nodes_room_max = 256;
const arena_limit_max = 64 * 1024;
const directories_max = 10;
const entries_max = 12;
const requests_per_iteration = 200;
const chunk_bytes_max = 4096;

var fixture: fixture_mod.Fixture = undefined;
var region: [nodes.memory_bytes(nodes_room_max, arena_limit_max)]u8 align(8) = undefined;
var table: nodes.Table = undefined;
var cache_memory: [cache_mod.memory_bytes(chunk_bytes_max)]u8 = undefined;
var cache: cache_mod.Cache = undefined;
var reply_buffer: [constants.fuse_reply_bytes]u8 align(8) = undefined;
var request_buffer: [constants.fuse_request_bytes]u8 = undefined;
var links: [nodes_room_max]u32 = undefined;
var pool: [4 * chunk_bytes_max]u8 = undefined;
var walked: [nodes_room_max]Digest = undefined;

/// What the iterations reached, so the test can see that no property was checked vacuously.
var reached: struct {
    builds_refused: u32 = 0,
    reads_with_data: u32 = 0,
    reads_failed: u32 = 0,
    listings: u32 = 0,
    refused: u32 = 0,
    sizes_forged: u32 = 0,
} = .{};

/// Attribute sections a file may carry, all valid and sorted.
const sections = [_][]const u8{
    &xattrs.empty,
    "\x01" ++ "\x06\x00user.a" ++ "\x03\x00one",
    "\x02" ++ "\x06\x00user.a" ++ "\x00\x00" ++ "\x06\x00user.b" ++ "\x02\x00hi",
};

/// Names a request may ask for: some the trees hold, some they never do.
const asked_names = [_][]const u8{
    "e00", "e01", "e05", "e11", "zz", "user.a", "user.b", "user.overlay.opaque",
};

pub fn fuzz_fuse_request(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const chunk_choices = [_]u32{ 8, 64, chunk_bytes_max };
    const chunk_bytes = chunk_choices[random.uintLessThan(usize, chunk_choices.len)];
    fixture.init(chunk_bytes);
    random.bytes(&pool);
    const root = make_tree(random) catch unreachable; // The fixture has room for the largest.
    const nodes_room = random.intRangeAtMost(u32, 1, nodes_room_max);
    const arena_limit = random.intRangeAtMost(u32, 16, arena_limit_max);
    table.init(nodes.carve(&region, nodes_room, arena_limit));
    table.build(fixture.source(), root) catch |err| {
        switch (err) {
            error.TooManyNodes, error.TooLarge, error.Malformed, error.NotFound => {
                reached.builds_refused += 1;
                return;
            },
            error.Damaged, error.Unreadable => unreachable, // The fixture never says these.
        }
    };
    check_table();
    check_walk(root);
    const before = snapshot();
    if (random.uintLessThan(u32, 4) == 0) fixture.failing = random_file(random);
    // A new cache each iteration: the chunk size changes, and the fixture's objects with it.
    const io = std.Io.Threaded.global_single_threaded.io();
    cache.init(io, cache_memory[0..@intCast(cache_mod.memory_bytes(chunk_bytes))], chunk_bytes);
    const server: ops.Server = .{ .table = &table, .cache = &cache, .chunk_bytes = chunk_bytes };
    var worker = ops.Worker.init(fixture.chunks(), &reply_buffer);
    for (0..requests_per_iteration) |_| {
        const sent = random_request(random, &server);
        const reply = ops.handle(&server, &worker, sent.bytes);
        check_reply(&server, &sent, reply);
        check_table();
        assert(std.mem.eql(u8, &snapshot(), &before));
    }
}

// The tree.

/// A random tree, bottom up: each directory names files, symlinks and earlier directories; the
/// last is the root. With some chance the root's object is damaged before it is kept.
fn make_tree(random: std.Random) !Digest {
    var made: [directories_max]Digest = undefined;
    const count = random.intRangeAtMost(u32, 1, directories_max);
    for (0..count) |index| {
        _ = fixture.begin();
        const entries = random.uintAtMost(u32, entries_max);
        var name: u32 = 0;
        for (0..entries) |_| {
            name += random.intRangeAtMost(u32, 1, 3); // Names rise: the writer wants them sorted.
            if (name >= 100) break;
            var text: [3]u8 = undefined;
            _ = std.fmt.bufPrint(&text, "e{d:0>2}", .{name}) catch unreachable; // Three bytes.
            try add_entry(random, &text, made[0..index]);
        }
        if (index + 1 < count) {
            made[index] = fixture.finish();
        } else {
            const bytes = try fixture.writer.finish_with(.{
                .mode = 0o755,
                .uid = random.uintAtMost(u32, 3),
                .gid = 0,
                .xattrs = &xattrs.empty,
            });
            if (random.uintLessThan(u32, 8) == 0) return damaged(random, bytes);
            return fixture.keep(bytes);
        }
    }
    unreachable; // The last directory returns.
}

fn add_entry(random: std.Random, name: []const u8, earlier: []const Digest) !void {
    switch (random.uintLessThan(u32, 6)) {
        0 => try fixture.symlink(name, if (random.boolean()) "e01" else "../x/y"),
        1 => if (earlier.len > 0) {
            try fixture.dir(name, earlier[random.uintLessThan(usize, earlier.len)]);
        } else {
            try fixture.symlink(name, "e00");
        },
        else => {
            // A few contents and modes, so that entries often name one object: hard links.
            const length = switch (random.uintLessThan(u32, 4)) {
                0 => 0,
                1 => random.uintAtMost(usize, 16),
                else => random.uintAtMost(usize, 3 * fixture.chunk_bytes + 5),
            };
            const start = random.uintAtMost(usize, 2) * 17;
            const mode: u16 = if (random.boolean()) 0o644 else 0o755;
            const section = sections[random.uintLessThan(usize, sections.len)];
            const content = pool[start..][0..@min(length, pool.len - start)];
            _ = try fixture.file(name, content, mode, section);
        },
    }
}

fn damaged(random: std.Random, bytes: []const u8) Digest {
    var copy: [fixture_mod.writer_bytes]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    var length = bytes.len;
    if (random.boolean()) {
        copy[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
    } else {
        length = random.uintLessThan(usize, length);
    }
    return fixture.keep(copy[0..length]);
}

fn random_file(random: std.Random) ?Digest {
    const start = random.uintLessThan(u32, table.node_count);
    for (0..table.node_count) |step| {
        const index: u32 = @intCast((start + step) % table.node_count);
        const found = &table.memory.nodes[index];
        if (found.kind == .file) return found.digest;
    }
    return null;
}

// The table's invariants.

fn check_table() void {
    assert(table.node_count > 0);
    assert(table.node_count <= table.memory.nodes.len);
    @memset(links[0..table.node_count], 0);
    for (table.memory.nodes[0..table.node_count], 0..) |*found, index| {
        if (found.kind != .dir) continue;
        const list = table.children(found);
        var subdirectories: u32 = 0;
        for (list, 0..) |child, at| {
            assert(child.node < table.node_count);
            assert(child.node != 0);
            if (at > 0) assert(std.mem.lessThan(u8, table.name(list[at - 1]), table.name(child)));
            links[child.node] += 1;
            const named = &table.memory.nodes[child.node];
            if (named.kind == .dir) {
                assert(named.parent == index);
                subdirectories += 1;
            }
        }
        assert(found.nlink == 2 + subdirectories);
    }
    assert(links[0] == 0);
    for (table.memory.nodes[1..table.node_count], 1..) |*found, index| {
        switch (found.kind) {
            .file => assert(found.nlink == links[index]),
            .dir, .symlink => assert(links[index] == 1),
        }
    }
}

/// Property 6, by a walk of the fixture's trees that shares nothing with the table's.
fn check_walk(root: Digest) void {
    // Each directory names only earlier ones, so a path holds each at most once.
    var decoders: [directories_max]tree.Decoder = undefined;
    var trees_seen: [directories_max]Digest = undefined;
    var trees_count: u32 = 0;
    var tree_bytes: u64 = 0;
    var objects: u32 = 0;
    var depth: u32 = 0;
    var next: ?Digest = root;
    while (true) {
        if (next) |digest| {
            const bytes = fixture.tree_held(digest).?; // The build found it.
            if (!contains(trees_seen[0..trees_count], digest)) {
                trees_seen[trees_count] = digest;
                trees_count += 1;
                tree_bytes += bytes.len;
            }
            decoders[depth].init(bytes) catch unreachable; // The build decoded it.
            depth += 1;
            next = null;
        }
        if (depth == 0) break;
        var entry: tree.Entry = undefined;
        const more = decoders[depth - 1].next(&entry) catch unreachable; // The build did.
        if (!more) {
            depth -= 1;
            continue;
        }
        switch (entry.kind) {
            .file => if (!contains(walked[0..objects], entry.object)) {
                walked[objects] = entry.object;
                objects += 1;
            },
            .dir => next = entry.subtree,
            .symlink => {},
        }
    }
    assert(objects == table.object_count);
    assert(tree_bytes == table.arena_len);
    for (1..table.node_count + 1) |nodeid| {
        const found = table.node(nodeid).?;
        if (found.kind == .file) assert(walked[table.ordinal(found)].eql(found.digest));
    }
}

fn contains(list: []const Digest, wanted: Digest) bool {
    for (list) |held| {
        if (held.eql(wanted)) return true;
    }
    return false;
}

fn snapshot() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(std.mem.sliceAsBytes(table.memory.nodes[0..table.node_count]));
    hasher.update(std.mem.sliceAsBytes(table.memory.children[0..table.child_count]));
    hasher.update(table.memory.arena[0..table.arena_len]);
    return hasher.finalResult();
}

// Requests.

const Sent = struct { bytes: []const u8, unique: u64 };

const opcodes = [_]abi.Opcode{
    .lookup, .getattr,     .readlink,    .open,     .opendir,      .read,      .read,
    .read,   .readdirplus, .readdirplus, .getxattr, .listxattr,    .statfs,    .release,
    .flush,  .releasedir,  .init,        .forget,   .batch_forget, .interrupt, .write,
    .mkdir,  .setxattr,    .access,      .readdir,
};

fn random_request(random: std.Random, server: *const ops.Server) Sent {
    const opcode: abi.Opcode = if (random.uintLessThan(u32, 16) == 0)
        @fromBackingInt(@intCast(random.int(u32)))
    else
        opcodes[random.uintLessThan(usize, opcodes.len)];
    const nodeid: u64 = switch (random.uintLessThan(u32, 8)) {
        0 => random.int(u64),
        1 => abi.root_id,
        else => random.uintAtMost(u64, server.table.node_count + 1),
    };
    var body: [256]u8 = undefined;
    const body_len = random_body(random, opcode, server, &body);
    const unique = random.int(u64);
    var bytes = fixture_mod.request(&request_buffer, opcode, nodeid, unique, &.{body[0..body_len]});
    if (random.uintLessThan(u32, 8) == 0) bytes = damaged_request(random, bytes);
    return .{ .bytes = bytes, .unique = unique };
}

/// A body of the shape `opcode` wants, with random values: sizes and offsets near the edges.
fn random_body(random: std.Random, opcode: abi.Opcode, server: *const ops.Server, out: []u8) usize {
    assert(out.len >= 128);
    switch (opcode) {
        .read, .readdirplus => {
            const in: abi.ReadIn = .{
                .fh = 0,
                .offset = random_offset(random, server),
                .size = random_size(random),
                .read_flags = 0,
                .lock_owner = 0,
                .flags = 0,
                .padding = 0,
            };
            return put_body(out, std.mem.asBytes(&in), "");
        },
        .lookup => {
            const name = asked_names[random.uintLessThan(usize, asked_names.len)];
            @memcpy(out[0..name.len], name);
            out[name.len] = 0;
            return name.len + @intFromBool(random.uintLessThan(u32, 16) != 0); // Sometimes no NUL.
        },
        .getxattr => {
            const in: abi.GetxattrIn = .{ .size = random_size(random) % 64, .padding = 0 };
            const name = asked_names[random.uintLessThan(usize, asked_names.len)];
            return put_body(out, std.mem.asBytes(&in), name);
        },
        .listxattr => {
            const in: abi.GetxattrIn = .{ .size = random_size(random) % 64, .padding = 0 };
            return put_body(out, std.mem.asBytes(&in), "");
        },
        .open, .opendir => {
            const flags = [_]u32{ 0, 0, 0o1, 0o2, 0o1000, 0o100000 };
            const flag = flags[random.uintLessThan(usize, flags.len)];
            const in: abi.OpenIn = .{ .flags = flag, .open_flags = 0 };
            return put_body(out, std.mem.asBytes(&in), "");
        },
        .init => {
            const in: abi.InitIn = .{
                .major = random.intRangeAtMost(u32, 6, 8),
                .minor = random.intRangeAtMost(u32, 25, 45),
                .max_readahead = random.int(u32),
                .flags = random.int(u32),
            };
            return put_body(out, std.mem.asBytes(&in), "");
        },
        else => {
            const length = random.uintAtMost(usize, 64);
            random.bytes(out[0..length]);
            return length;
        },
    }
}

/// `fixed`, then `name` with its NUL.
fn put_body(out: []u8, fixed: []const u8, name: []const u8) usize {
    assert(fixed.len + name.len + 1 <= out.len);
    @memcpy(out[0..fixed.len], fixed);
    if (name.len == 0) return fixed.len;
    @memcpy(out[fixed.len..][0..name.len], name);
    out[fixed.len + name.len] = 0;
    return fixed.len + name.len + 1;
}

fn random_offset(random: std.Random, server: *const ops.Server) u64 {
    return switch (random.uintLessThan(u32, 6)) {
        0 => random.int(u64),
        1 => random.uintAtMost(u64, 4),
        2 => random.uintAtMost(u64, 3) * server.chunk_bytes,
        else => random.uintAtMost(u64, 4 * server.chunk_bytes),
    };
}

fn random_size(random: std.Random) u32 {
    return switch (random.uintLessThan(u32, 5)) {
        0 => random.int(u32),
        1 => random.uintAtMost(u32, 200),
        2 => constants.fuse_read_bytes_max,
        else => random.uintAtMost(u32, 8192),
    };
}

/// The request with one thing wrong: cut short, a header length that lies, an extension, or a
/// flipped byte.
fn damaged_request(random: std.Random, bytes: []u8) []u8 {
    assert(bytes.len >= @sizeOf(abi.InHeader));
    switch (random.uintLessThan(u32, 4)) {
        0 => return bytes[0..random.uintLessThan(usize, bytes.len)],
        1 => std.mem.writeInt(u32, bytes[0..4], random.int(u32), .little),
        2 => std.mem.writeInt(u16, bytes[36..38], random.int(u16) | 1, .little),
        else => {
            const at = random.uintLessThan(usize, bytes.len - 8) + 8; // The opcode or later.
            bytes[at] ^= @as(u8, 1) << random.int(u3);
        },
    }
    return bytes;
}

// Replies.

fn check_reply(server: *const ops.Server, sent: *const Sent, reply: []const u8) void {
    if (sent.bytes.len < @sizeOf(abi.InHeader)) {
        assert(reply.len == 0);
        return;
    }
    const header = std.mem.bytesToValue(abi.InHeader, sent.bytes[0..@sizeOf(abi.InHeader)]);
    switch (@as(abi.Opcode, @fromBackingInt(@intCast(header.opcode)))) {
        .forget, .batch_forget, .interrupt => {
            assert(reply.len == 0);
            return;
        },
        else => {},
    }
    assert(reply.len >= @sizeOf(abi.OutHeader));
    const out = fixture_mod.reply_header(reply);
    assert(out.len == reply.len);
    assert(out.unique == header.unique);
    if (out.@"error" != 0) {
        assert(reply.len == @sizeOf(abi.OutHeader));
        assert(is_known(-out.@"error"));
        reached.refused += 1;
        if (header.opcode == @backingInt(abi.Opcode.read) and -out.@"error" == 5) {
            reached.reads_failed += 1;
        }
        return;
    }
    // A request the handler accepted was whole and named no extension.
    assert(header.len == sent.bytes.len);
    assert(header.total_extlen == 0);
    const body = sent.bytes[@sizeOf(abi.InHeader)..];
    const data = reply[@sizeOf(abi.OutHeader)..];
    switch (@as(abi.Opcode, @fromBackingInt(@intCast(header.opcode)))) {
        .read => check_read(server, header.nodeid, body, data),
        .readdirplus => check_listing(server, header.nodeid, body, data),
        .getattr => assert(data.len == @sizeOf(abi.AttrOut)),
        .lookup => assert(data.len == @sizeOf(abi.EntryOut)),
        else => {},
    }
}

fn is_known(errno: i32) bool {
    inline for (@typeInfo(abi.Errno).@"enum".field_values) |value| {
        if (value == errno) return true;
    }
    return false;
}

fn check_read(server: *const ops.Server, nodeid: u64, body: []const u8, data: []const u8) void {
    const found = server.table.node(nodeid).?; // A read that succeeded named a node.
    assert(found.kind == .file);
    const in = std.mem.bytesToValue(abi.ReadIn, body[0..@sizeOf(abi.ReadIn)]);
    const content = fixture.content_of(found.digest).?;
    if (content.len != found.size) {
        // A damaged root that still decodes gave the object another size (an index carrying it
        // is refused by `resolver.check_objects`); whatever is served is still the object's own.
        reached.sizes_forged += 1;
        if (data.len == 0) return;
        assert(in.offset + data.len <= content.len);
        assert(std.mem.eql(u8, data, content[@intCast(in.offset)..][0..data.len]));
        return;
    }
    if (in.offset >= content.len) {
        assert(data.len == 0);
        return;
    }
    const length = @min(in.size, constants.fuse_read_bytes_max, content.len - in.offset);
    assert(std.mem.eql(u8, data, content[@intCast(in.offset)..][0..@intCast(length)]));
    // An object whose chunks fail never gives bytes.
    if (data.len > 0) {
        if (fixture.failing) |failing| assert(!failing.eql(found.digest));
    }
    if (data.len > 0) reached.reads_with_data += 1;
}

fn check_listing(server: *const ops.Server, nodeid: u64, body: []const u8, data: []const u8) void {
    const found = server.table.node(nodeid).?; // A listing that succeeded named a directory.
    assert(found.kind == .dir);
    const in = std.mem.bytesToValue(abi.ReadIn, body[0..@sizeOf(abi.ReadIn)]);
    assert(data.len <= in.size);
    var at: usize = 0;
    var next = in.offset +% 1;
    while (at < data.len) : (next += 1) {
        assert(data.len - at >= @sizeOf(abi.Direntplus));
        const record = std.mem.bytesToValue(abi.Direntplus, data[at..][0..@sizeOf(abi.Direntplus)]);
        assert(record.dirent.off == next);
        assert(record.dirent.namelen > 0);
        const bytes = abi.direntplus_bytes(record.dirent.namelen);
        assert(data.len - at >= bytes);
        assert(server.table.node(record.dirent.ino) != null);
        at += bytes;
    }
    assert(at == data.len);
    if (at > 0) reached.listings += 1;
    const total = @as(u64, server.table.children(found).len) + 2;
    if (at > 0) assert(next -% 1 <= total);
    // An empty listing is the end to the kernel: it is answered only at or past the end.
    if (at == 0) assert(in.offset >= total);
}

test "fuse_request fuzzer: a few hundred seeds reach every property" {
    // Goal: the fuzzer runs clean and is not vacuous. Method: three hundred seeds, then counts of
    // refused builds, reads with data, failed reads, listings and refusals, each well above zero.
    errdefer std.debug.print("reached: {any}\n", .{reached});
    reached = .{};
    for (0..300) |seed| fuzz_fuse_request(seed);
    try std.testing.expect(reached.builds_refused > 10);
    try std.testing.expect(reached.reads_with_data > 100);
    try std.testing.expect(reached.reads_failed > 10);
    try std.testing.expect(reached.listings > 100);
    try std.testing.expect(reached.refused > 1000);
}
