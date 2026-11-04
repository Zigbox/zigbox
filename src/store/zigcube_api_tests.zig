//! Tests of the store calls Zigcube's C2 makes with bytes from a peer or for a peer: the verified
//! chunk read (`chunk_read.zig`), the checked tree put (`trees.put_checked`), `has` and the
//! limited object walk (`walk.objects`). The store is the simulated file system with chunks of
//! eight bytes, so a few bytes make a many-chunk object.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const chunk_read = @import("chunk_read.zig");
const chunks = @import("chunks.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const fs_sim = @import("fs_sim.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const support = @import("test_support.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");
const walk = @import("walk.zig");
const xattrs = @import("xattrs.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const Store = layout.Store;

const root_path = "/data/store";
const long = "0123456789abcdefghijklmnopqrstuvwxyz"; // 36 bytes: four full chunks and a short one.

var sim: HostSim = undefined;
var files: SimFs = undefined;
var store: Store = undefined;
var io: [constants.store_io_buffer_bytes]u8 = undefined;
var hashes: [16]Digest = undefined;
var out: [8]u8 = undefined;
var scratch: xattrs.Scratch = undefined;

fn start() void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    store.chunk_bytes = 8;
}

/// Puts `content` in the store the way a fetch does and returns its object id.
fn put_object(content: []const u8, attrs: object.Attrs) !Digest {
    var reader = object.Reader.init(store.chunk_bytes);
    if (content.len > 0) _ = reader.update(content, &hashes);
    const whole = reader.finish(&hashes);
    const wanted: chunks.Wanted = .{
        .id = object.object_id(whole, attrs),
        .attrs = attrs,
        .size = content.len,
        .content = whole,
        .hashes = hashes[0..reader.count],
    };
    var failure: chunks.Failure = undefined;
    if (content.len == 0) _ = try chunks.finish(&store, &io, &wanted, &failure);
    for (0..wanted.hashes.len) |index| {
        const at = index * store.chunk_bytes;
        const piece = content[at..@min(at + store.chunk_bytes, content.len)];
        _ = try chunks.put_chunk(&store, &io, &wanted, @intCast(index), piece, &failure);
    }
    return wanted.id;
}

const plain: object.Attrs = .{ .mode = 0o640, .uid = 5, .gid = 6, .xattrs = &xattrs.empty };

fn object_bytes(id: Digest) []u8 {
    var buffer: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const hex = id.hex();
    const path = std.fmt.bufPrint(
        &buffer,
        root_path ++ "/objects/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch unreachable; // Short.
    return @constCast(files.content_of(path).?); // The simulator's bytes are the test's to damage.
}

fn read(id: Digest, index: u32) chunk_read.Error!usize {
    return chunk_read.read_chunk(&store, &io, &scratch, id, index, &out);
}

test "every chunk of an object reads back as the bytes that were put" {
    // Goal: the contract of `read_chunk`. Method: objects of five chunks, of exactly one chunk,
    // of less than one; each chunk is read and compared with its slice of the content; one past
    // the last is out of range; an id that is not in the store is not found.
    const cases = [_][]const u8{ long, "01234567", "short" };
    for (cases) |content| {
        start();
        const id = try put_object(content, plain);
        const count = object.chunk_count(content.len, 8);
        for (0..count) |index| {
            @memset(&out, 0xAA);
            const length = try read(id, @intCast(index));
            const at = index * 8;
            const want = content[at..@min(at + 8, content.len)];
            try testing.expectEqualSlices(u8, want, out[0..length]);
        }
        try testing.expectError(error.IndexOutOfRange, read(id, count));
        try testing.expectError(error.NotFound, read(Digest.of("absent"), 0));
    }
}

test "an object with no bytes has no chunk to read" {
    // Goal: the empty object's edge. Method: put one; chunk 0 is out of range.
    start();
    const id = try put_object("", plain);
    try testing.expectError(error.IndexOutOfRange, read(id, 0));
}

test "a damaged chunk is refused whole, and its neighbours still read" {
    // Goal: a mismatch is an error, never bytes. Method: flip one bit in each chunk in turn;
    // that chunk is `Damaged` and `out` holds nothing of it, and every other chunk reads right.
    for (0..5) |bad| {
        start();
        const id = try put_object(long, plain);
        object_bytes(id)[bad * 8] ^= 1;
        for (0..5) |index| {
            @memset(&out, 0xAA);
            if (index == bad) {
                try testing.expectError(error.Damaged, read(id, @intCast(index)));
                try testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &out);
            } else {
                const length = try read(id, @intCast(index));
                const at = index * 8;
                try testing.expectEqualSlices(u8, long[at..@min(at + 8, long.len)], out[0..length]);
            }
        }
    }
}

test "a damaged or missing chunk list is refused" {
    // Goal: the list is what a long object is checked against, so a list that cannot be trusted
    // refuses the read. Method: flip a bit of one listed hash; cut the list short; remove it.
    start();
    const id = try put_object(long, plain);
    const hex = id.hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const list_text = try std.fmt.bufPrint(
        &path,
        root_path ++ "/objects/{s}/{s}.chunks",
        .{ hex[0..2], hex[2..] },
    );
    const list_path: [:0]const u8 = path[0..list_text.len :0]; // The buffer is zero-filled.
    const list: []u8 = @constCast(files.content_of(list_path).?);
    list[2 * 32 + 5] ^= 1;
    try testing.expectError(error.Damaged, read(id, 2));
    _ = try read(id, 1); // The other hashes are untouched.
    list[2 * 32 + 5] ^= 1;
    _ = try read(id, 2);
    var kept: [5 * 32 + 1]u8 = @splat(0xEE);
    @memcpy(kept[0 .. 5 * 32], list);
    try store.fs.unlink(list_path);
    files.put_file(list_path, 0o644, kept[0 .. 4 * 32]); // One hash short.
    try testing.expectError(error.Damaged, read(id, 0));
    try store.fs.unlink(list_path);
    files.put_file(list_path, 0o644, &kept); // One byte too many.
    try testing.expectError(error.Damaged, read(id, 0));
    try store.fs.unlink(list_path);
    try testing.expectError(error.Damaged, read(id, 0)); // A long object with no list.
}

test "an object of one chunk is checked against its id, with its metadata" {
    // Goal: with no list, the id is the only anchor. Method: damage the bytes; then change the
    // file's mode, which the id covers.
    start();
    const id = try put_object("short", plain);
    _ = try read(id, 0);
    object_bytes(id)[1] ^= 1;
    try testing.expectError(error.Damaged, read(id, 0));
    object_bytes(id)[1] ^= 1;
    _ = try read(id, 0);
    var buffer: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const hex = id.hex();
    const path = try std.fmt.bufPrint(
        &buffer,
        root_path ++ "/objects/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    );
    files.set_mode_of(path, 0o600);
    try testing.expectError(error.Damaged, read(id, 0));
}

test "an object with attributes is read and checked with them" {
    // Goal: the id covers the attributes, so the check must gather them as the importer did.
    // Method: an object with one attribute reads back (the attribute section is part of what
    // the id was made from, so a wrong gather would be `Damaged`).
    start();
    var builder: xattrs.Builder = undefined;
    builder.reset();
    try builder.add("user.zbx.test", "value");
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    const with_attribute: object.Attrs = .{
        .mode = 0o644,
        .uid = 1,
        .gid = 2,
        .xattrs = builder.finish(&blob),
    };
    const id = try put_object("short", with_attribute);
    _ = try read(id, 0);
}

test "a failing or piecemeal file system gives an error or the right bytes, never wrong ones" {
    // Goal: faults of the file system are errors, not bytes. Method: every read fails; then
    // reads come back in pieces, which must not change the answer.
    start();
    const id = try put_object(long, plain);
    files.faults.read_error_per_mille = 1000;
    try testing.expectError(error.Unreadable, read(id, 3));
    files.faults.read_error_per_mille = 0;
    files.faults.short_read_per_mille = 1000;
    for (0..5) |index| _ = try read(id, @intCast(index));
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a read that fails after part of the chunk was read leaves no bytes in out" {
    // Goal: regression, found by the `peer` fuzzer: an error after a partial read left the
    // unverified part in `out`. Method: pieces of the chunk arrive, and a later piece fails;
    // over many reads, every error leaves `out` zero and every success the right bytes.
    start();
    const id = try put_object(long, plain);
    files.faults.short_read_per_mille = 1000;
    files.faults.read_error_per_mille = 400;
    var failed: u32 = 0;
    for (0..200) |round| {
        @memset(&out, 0xAA);
        const index: u32 = @intCast(round % 4);
        if (read(id, index)) |length| {
            try testing.expectEqualSlices(u8, long[index * 8 ..][0..length], out[0..length]);
        } else |_| {
            failed += 1;
            try testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &out);
        }
    }
    try testing.expect(failed > 0); // The faults did fire.
}

/// The path of the object `id` (or of its chunk list, for the suffix ".chunks") in `buffer`.
fn path_of(
    buffer: *[constants.sim_fs_path_bytes_max]u8,
    id: Digest,
    suffix: []const u8,
) [:0]const u8 {
    @memset(buffer, 0);
    const hex = id.hex();
    const text = std.fmt.bufPrint(
        buffer,
        root_path ++ "/objects/{s}/{s}{s}",
        .{ hex[0..2], hex[2..], suffix },
    ) catch unreachable; // Short.
    return buffer[0..text.len :0]; // The buffer is zero-filled.
}

/// Replaces the object's file by one with `bytes`, as a hand that cut or extended it would.
fn replace_object(id: Digest, bytes: []const u8) void {
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = path_of(&buffer, id, "");
    files.remove_path(path);
    files.put_file(path, plain.mode, bytes);
    files.set_owner_of(path, plain.uid, plain.gid);
}

test "a gc that takes the object and its list away is NotFound, never Damaged" {
    // Goal: regression for a read racing a gc: the list vanishing because the object was
    // removed is `NotFound`, while a list missing from an object that is still there is damage.
    // Method: the sim cannot interleave, so `listed_hash`, the call that reads the list, is made
    // after the files are gone, the way the read would see them after the gc ran between its
    // `lstat` and its list read.
    start();
    const id = try put_object(long, plain);
    var object_buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    var list_buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const object_path = path_of(&object_buffer, id, "");
    const list_path = path_of(&list_buffer, id, ".chunks");
    _ = try chunk_read.listed_hash(&store, &io, id, long.len, 5, 2);
    files.remove_path(list_path);
    try testing.expectError(error.Damaged, chunk_read.listed_hash(&store, &io, id, long.len, 5, 2));
    files.remove_path(object_path);
    const missing = chunk_read.listed_hash(&store, &io, id, long.len, 5, 2);
    try testing.expectError(error.NotFound, missing);
    try testing.expectError(error.NotFound, read(id, 2));
}

test "a list longer than any list is damage, not a failed read" {
    // Goal: a `.chunks` file past the scratch buffer is `Damaged`. Method: a list one hash more
    // than the buffer holds.
    start();
    const id = try put_object(long, plain);
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const list_path = path_of(&buffer, id, ".chunks");
    files.remove_path(list_path);
    const too_long = try testing.allocator.alloc(u8, io.len + 1);
    defer testing.allocator.free(too_long);
    @memset(too_long, 3);
    files.put_file(list_path, 0o644, too_long);
    try testing.expectError(error.Damaged, read(id, 0));
}

test "something that is not a file at the object's path is damage" {
    // Goal: the kind check of the object. Method: a directory where the object should be.
    start();
    const id = try put_object(long, plain);
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const path = path_of(&buffer, id, "");
    files.remove_path(path);
    files.put_dir(path, 0o755);
    for (0..5) |index| try testing.expectError(error.Damaged, read(id, @intCast(index)));
    try testing.expect(!(try object.has(&store, id))); // Nor does the store hold it.
}

test "an object cut or extended after it was put never reads as other bytes" {
    // Goal: the size the file now has is not trusted. Method: many-chunk object cut inside its
    // last chunk (the early chunks still read, the last is refused), cut by whole chunks (the
    // list no longer fits, nothing reads), extended inside the last chunk and past it; then
    // the same for an object of one chunk, which is checked against its id.
    start();
    var id = try put_object(long, plain);
    replace_object(id, long[0..33]);
    for (0..4) |index| _ = try read(id, @intCast(index));
    try testing.expectError(error.Damaged, read(id, 4));
    replace_object(id, long[0..32]);
    for (0..5) |index| try testing.expect(if (read(id, @intCast(index))) |_| false else |_| true);
    replace_object(id, long ++ "!");
    for (0..4) |index| _ = try read(id, @intCast(index));
    try testing.expectError(error.Damaged, read(id, 4));
    replace_object(id, long ++ "01234567");
    for (0..6) |index| try testing.expectError(error.Damaged, read(id, @intCast(index)));

    start();
    id = try put_object("short", plain);
    replace_object(id, "shor");
    try testing.expectError(error.Damaged, read(id, 0));
    replace_object(id, "short!");
    try testing.expectError(error.Damaged, read(id, 0));
    replace_object(id, "short");
    _ = try read(id, 0);
}

test "a file that shrinks between its size and its read is refused, not read short" {
    // Goal: the length check after the read. Method: `out` already holds the bytes the read
    // is expected to give, and the file loses its last byte as it is opened, so the read is
    // one byte short; the hash of `out` would be right, so only the length check refuses it.
    const cases = [_]struct { content: []const u8, index: u32 }{
        .{ .content = long, .index = 4 },
        .{ .content = "short", .index = 0 },
    };
    for (cases) |case| {
        start();
        const id = try put_object(case.content, plain);
        files.faults.shrink_on_open = true;
        const want = case.content[case.index * 8 ..];
        @memset(&out, 0xAA);
        @memcpy(out[0..want.len], want);
        try testing.expectError(
            error.Damaged,
            chunk_read.read_chunk(&store, &io, &scratch, id, case.index, &out),
        );
        try testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &out);
    }
}

// ---- put_checked ---------------------------------------------------------------------------

fn small_tree(buffer: []u8) []const u8 {
    var writer = tree.Writer.init(buffer);
    writer.begin("a", .file, 0o644, 0, 0, &xattrs.empty) catch unreachable; // Room.
    writer.end_file(3, Digest.of("abc"), Digest.of("object")) catch unreachable; // Room.
    return writer.finish();
}

test "a tree from outside is stored only if its size, hash and encoding are right" {
    // Goal: untrusted bytes never reach an assertion. Method: a good tree is stored once and
    // reads back; the same bytes under another digest, one flipped bit, an oversize body and a
    // hash-right body that is not a tree are each refused, and none leaves a tree behind.
    start();
    var buffer: [256]u8 = undefined;
    const bytes = small_tree(&buffer);
    const digest = Digest.of(bytes);
    var failure: object.Failure = undefined;
    try testing.expectError(
        error.DigestMismatch,
        trees.put_checked(&store, Digest.of("other"), bytes, &failure),
    );
    var flipped: [256]u8 = undefined;
    @memcpy(flipped[0..bytes.len], bytes);
    flipped[bytes.len - 1] ^= 1;
    try testing.expectError(
        error.DigestMismatch,
        trees.put_checked(&store, digest, flipped[0..bytes.len], &failure),
    );
    const garbage = "this is not a tree";
    try testing.expectError(
        error.Malformed,
        trees.put_checked(&store, Digest.of(garbage), garbage, &failure),
    );
    try testing.expectError(
        error.Malformed,
        trees.put_checked(&store, Digest.of(""), "", &failure),
    );
    const truncated = bytes[0 .. bytes.len - 3];
    try testing.expectError(
        error.Malformed,
        trees.put_checked(&store, Digest.of(truncated), truncated, &failure),
    );
    try testing.expect(!(try trees.has(&store, digest)));
    try testing.expect(!(try trees.has(&store, Digest.of(garbage))));
    try testing.expect(try trees.put_checked(&store, digest, bytes, &failure));
    try testing.expect(!(try trees.put_checked(&store, digest, bytes, &failure)));
    try testing.expect(try trees.has(&store, digest));
    var read_buffer: [256]u8 = undefined;
    var errno: u16 = 0;
    try testing.expectEqualSlices(u8, bytes, try trees.load(&store, digest, &read_buffer, &errno));
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a tree longer than any tree object is too large, not an assertion" {
    // Goal: the size bound is an error. Method: one byte past the bound, with the right hash.
    start();
    const big = try testing.allocator.alloc(u8, constants.store_tree_bytes_max + 1);
    defer testing.allocator.free(big);
    @memset(big, 7);
    var failure: object.Failure = undefined;
    try testing.expectError(
        error.TooLarge,
        trees.put_checked(&store, Digest.of(big), big, &failure),
    );
}

// ---- has and the object walk ---------------------------------------------------------------

const Collector = struct {
    count: u32 = 0,
    bytes: u64 = 0,
    chunk_total: u32 = 0,

    pub fn object(collector: *Collector, ref: *const walk.ObjectRef) void {
        collector.count += 1;
        collector.bytes += ref.size;
        collector.chunk_total += ref.chunk_count;
    }
};

test "has sees an object once it is whole, and the walk lists the objects below a tree" {
    // Goal: Z2. Method: two files and a subdirectory with one file are put in the store and
    // named by trees; `has_object` is false before and true after; the walk sees three file
    // entries with their sizes and chunk counts; a small entry limit stops it with a failure.
    start();
    const first = object.object_id(Digest.of(long), plain);
    try testing.expect(!(try object.has(&store, first)));
    const id_long = try put_object(long, plain);
    try testing.expect(id_long.eql(first));
    try testing.expect(try object.has(&store, first));
    const id_short = try put_object("short", plain);
    var inner_buffer: [256]u8 = undefined;
    var inner = tree.Writer.init(&inner_buffer);
    try inner.begin("c", .file, 0o640, 5, 6, &xattrs.empty);
    try inner.end_file(5, Digest.of("short"), id_short);
    const inner_bytes = inner.finish();
    var failure: object.Failure = undefined;
    const inner_digest = Digest.of(inner_bytes);
    _ = try trees.put_checked(&store, inner_digest, inner_bytes, &failure);
    var outer_buffer: [512]u8 = undefined;
    var outer = tree.Writer.init(&outer_buffer);
    try outer.begin("a", .file, 0o640, 5, 6, &xattrs.empty);
    try outer.end_file(long.len, Digest.of(long), id_long);
    try outer.begin("b", .file, 0o640, 5, 6, &xattrs.empty);
    try outer.end_file(5, Digest.of("short"), id_short);
    try outer.begin("d", .dir, 0o755, 5, 6, &xattrs.empty);
    try outer.end_dir(inner_digest);
    const outer_bytes = outer.finish();
    const root = Digest.of(outer_bytes);
    _ = try trees.put_checked(&store, root, outer_bytes, &failure);

    var buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var stack: [8]Digest = undefined;
    var collector: Collector = .{};
    var walk_failure: walk.Failure = undefined;
    try walk.objects(&store, &buffer, &stack, null, root, &collector, 100, &walk_failure);
    try testing.expectEqual(@as(u32, 3), collector.count);
    try testing.expectEqual(@as(u64, 36 + 5 + 5), collector.bytes);
    try testing.expectEqual(@as(u32, 5 + 1 + 1), collector.chunk_total);

    collector = .{};
    try testing.expectError(
        error.Failed,
        walk.objects(&store, &buffer, &stack, null, root, &collector, 3, &walk_failure),
    );
    try testing.expectEqual(.too_many_entries, walk_failure.kind);
    const absent = Digest.of("none");
    try testing.expectError(
        error.Failed,
        walk.objects(&store, &buffer, &stack, null, absent, &collector, 3, &walk_failure),
    );
    try testing.expectEqual(.missing, walk_failure.kind);
}

test "the walk passes at its entry limit and stops one entry past it" {
    // Goal: the boundary of `entries_max`. Method: a tree of four files; limit 4 sees all four,
    // limit 3 stops with `too_many_entries` after the visitor saw three.
    start();
    var failure: object.Failure = undefined;
    var buffer: [1024]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    const names = [_][]const u8{ "a", "b", "c", "d" };
    for (names) |name| {
        try writer.begin(name, .file, 0o644, 0, 0, &xattrs.empty);
        try writer.end_file(3, Digest.of("abc"), Digest.of("object"));
    }
    const bytes = writer.finish();
    const root = Digest.of(bytes);
    _ = try trees.put_checked(&store, root, bytes, &failure);
    var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var stack: [4]Digest = undefined;
    var collector: Collector = .{};
    var walk_failure: walk.Failure = undefined;
    try walk.objects(&store, &tree_buffer, &stack, null, root, &collector, 4, &walk_failure);
    try testing.expectEqual(@as(u32, 4), collector.count);
    collector = .{};
    try testing.expectError(
        error.Failed,
        walk.objects(&store, &tree_buffer, &stack, null, root, &collector, 3, &walk_failure),
    );
    try testing.expectEqual(.too_many_entries, walk_failure.kind);
    try testing.expectEqual(@as(u32, 3), collector.count);
}

test "the walk refuses a file entry longer than any object can be" {
    // Goal: a tree a peer sent whose size no object could have is `damaged`, not an assertion in
    // the chunk count. Method: one entry at the longest size (passes), one a byte past it.
    start();
    var failure: object.Failure = undefined;
    var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var stack: [4]Digest = undefined;
    const longest = @as(u64, store.chunk_bytes) * constants.store_chunks_max;
    for ([_]u64{ longest, longest + 1 }) |size| {
        var buffer: [256]u8 = undefined;
        var writer = tree.Writer.init(&buffer);
        try writer.begin("a", .file, 0o644, 0, 0, &xattrs.empty);
        try writer.end_file(size, Digest.of("abc"), Digest.of("object"));
        const bytes = writer.finish();
        const root = Digest.of(bytes);
        _ = try trees.put_checked(&store, root, bytes, &failure);
        var collector: Collector = .{};
        var walk_failure: walk.Failure = undefined;
        const result = walk.objects(
            &store,
            &tree_buffer,
            &stack,
            null,
            root,
            &collector,
            4,
            &walk_failure,
        );
        if (size == longest) {
            try result;
            try testing.expectEqual(@as(u32, 1), collector.count);
        } else {
            try testing.expectError(error.Failed, result);
            try testing.expectEqual(.damaged, walk_failure.kind);
            try testing.expectEqual(@as(u32, 0), collector.count);
        }
    }
}

test "a directory where a tree or an object belongs is not one the store has" {
    // Goal: `has` means a file. Method: a directory at the tree's path.
    start();
    const digest = Digest.of("tree");
    var path_storage: fs_mod.PathBuf = undefined;
    const path = store.tree_path(&path_storage, digest);
    const shard = path[0..std.mem.lastIndexOfScalar(u8, path, '/').?];
    if (files.kind_of(shard) == null) files.put_dir(shard, 0o755);
    files.put_dir(path, 0o755);
    try testing.expect(!(try trees.has(&store, digest)));
}
