//! The `peer` fuzzer: the store calls that take or give bytes to a peer (Z1 and Z3 of Zigcube's
//! contract): `read_chunk` and `trees.put_checked`.
//!
//! Each iteration builds an object of random length in the simulated store, and a random valid
//! tree. Properties:
//!   1. `read_chunk` of an intact object gives, for every chunk, exactly that slice of the
//!      content; a chunk past the last is `IndexOutOfRange`.
//!   2. After one bit of the object, or of its chunk list, is flipped, every read gives either
//!      the original bytes of that chunk or an error, never other bytes; an error leaves `out`
//!      zero; and a flip inside a chunk makes that chunk (and only that one) an error.
//!   3. With short reads and failing reads, a read gives the original bytes or an error.
//!   4. `put_checked` of bytes (a valid tree, then cut, extended, flipped or random) under their
//!      own digest or another one is accepted exactly when the digest is right and the decoder
//!      takes every entry; a refusal stores nothing, an acceptance stores a tree that loads.
//!      No input reaches an assertion.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const chunk_read = @import("store/chunk_read.zig");
const chunks = @import("store/chunks.zig");
const Digest = @import("store/digest.zig").Digest;
const fs_sim = @import("store/fs_sim.zig");
const layout = @import("store/layout.zig");
const object = @import("store/object.zig");
const support = @import("store/test_support.zig");
const tree = @import("store/tree.zig");
const trees = @import("store/trees.zig");
const xattrs = @import("store/xattrs.zig");

const root_path = "/data/store";
const content_bytes_max: u32 = 200;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var io: [constants.store_io_buffer_bytes]u8 = undefined;
var hashes: [64]Digest = undefined;
var content: [content_bytes_max]u8 = undefined;
var out: [16]u8 = undefined;
var tree_bytes: [1024]u8 = undefined;
var offered: [1100]u8 = undefined;

pub fn fuzz_peer(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    sim.init(seed, &.{});
    files.init(seed +% 1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    store.chunk_bytes = if (random.boolean()) 8 else 16;
    fuzz_read(random);
    fuzz_put(random);
    assert(sim.open_count() == 0);
}

fn fuzz_read(random: std.Random) void {
    const length = random.uintAtMost(u32, content_bytes_max);
    for (content[0..length]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'e');
    const attrs: object.Attrs = .{
        .mode = random.uintAtMost(u16, 0o7777),
        .uid = random.uintLessThan(u32, 4),
        .gid = random.uintLessThan(u32, 4),
        .xattrs = &xattrs.empty,
    };
    const id = put_object(content[0..length], attrs);
    const count = object.chunk_count(length, store.chunk_bytes);
    for (0..count) |index| expect_chunk(id, @intCast(index), length, true);
    assert(read(id, count) == error.IndexOutOfRange);
    if (length == 0) return;
    // Damage: one bit of the object, or of its list.
    const hex = id.hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const in_list = count > 1 and random.boolean();
    const suffix: []const u8 = if (in_list) ".chunks" else "";
    const text = std.fmt.bufPrint(&path, root_path ++ "/objects/{s}/{s}{s}", .{
        hex[0..2], hex[2..], suffix,
    }) catch unreachable; // Short.
    const bytes: []u8 = @constCast(files.content_of(text).?); // The simulator's bytes are ours.
    const at = random.uintLessThan(usize, bytes.len);
    const flip = @as(u8, 1) << random.int(u3);
    bytes[at] ^= flip;
    const hit: u32 = if (in_list) @intCast(at / 32) else @intCast(at / store.chunk_bytes);
    for (0..count) |index| {
        const must_fail = index == hit or (!in_list and count == 1);
        expect_chunk(id, @intCast(index), length, !must_fail);
    }
    bytes[at] ^= flip; // Restored: the faults below are on an intact object.
    files.faults.short_read_per_mille = random.uintAtMost(u16, 1000);
    files.faults.read_error_per_mille = random.uintAtMost(u16, 1000);
    const faulty = files.faults.read_error_per_mille == 0;
    for (0..count) |index| expect_chunk(id, @intCast(index), length, faulty);
}

fn put_object(bytes: []const u8, attrs: object.Attrs) Digest {
    var reader = object.Reader.init(store.chunk_bytes);
    if (bytes.len > 0) _ = reader.update(bytes, &hashes);
    const whole = reader.finish(&hashes);
    const wanted: chunks.Wanted = .{
        .id = object.object_id(whole, attrs),
        .attrs = attrs,
        .size = bytes.len,
        .content = whole,
        .hashes = hashes[0..reader.count],
    };
    var failure: chunks.Failure = undefined;
    // A clean file system and right chunks, so none of these puts can fail.
    if (bytes.len == 0) _ = chunks.finish(&store, &io, &wanted, &failure) catch unreachable;
    for (0..wanted.hashes.len) |index| {
        const start = index * store.chunk_bytes;
        const piece = bytes[start..@min(start + store.chunk_bytes, bytes.len)];
        _ = chunks.put_chunk(&store, &io, &wanted, @intCast(index), piece, &failure) catch
            unreachable; // Clean file system, right chunks.
    }
    return wanted.id;
}

fn read(id: Digest, index: u32) chunk_read.Error!usize {
    return chunk_read.read_chunk(&store, &io, id, index, &out);
}

/// A read gives the original slice of the content or an error with `out` zero; `must_work` says
/// that an error is itself the failure.
fn expect_chunk(id: Digest, index: u32, length: u32, must_work: bool) void {
    @memset(&out, 0xAA);
    const start = index * store.chunk_bytes;
    const want = content[start..@min(start + store.chunk_bytes, length)];
    if (read(id, index)) |got| {
        assert(std.mem.eql(u8, want, out[0..got]));
    } else |_| {
        assert(!must_work);
        for (out[0..want.len]) |byte| assert(byte == 0);
    }
}

fn fuzz_put(random: std.Random) void {
    files.faults.short_read_per_mille = 0; // Faults were the reads' business; the puts are clean.
    files.faults.read_error_per_mille = 0;
    var writer = tree.Writer.init(&tree_bytes);
    const names = [_][]const u8{ "a", "b", "c", "d" };
    for (names) |name| {
        if (random.boolean()) continue;
        writer.begin(name, .file, 0o644, 0, 0, &xattrs.empty) catch unreachable; // Room.
        writer.end_file(random.uintLessThan(u64, 100), Digest.of(name), Digest.of("o")) catch
            unreachable; // Room.
    }
    const good = writer.finish();
    var length: usize = good.len;
    @memcpy(offered[0..length], good);
    switch (random.uintLessThan(u8, 5)) {
        0 => {},
        1 => length = random.uintAtMost(usize, length),
        2 => offered[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
        3 => {
            const extra = random.intRangeAtMost(usize, 1, 40);
            random.bytes(offered[length..][0..extra]);
            length += extra;
        },
        else => {
            length = random.uintAtMost(usize, 64);
            random.bytes(offered[0..length]);
        },
    }
    const bytes = offered[0..length];
    const elsewhere = random.uintLessThan(u8, 4) == 0;
    const digest = if (elsewhere) Digest.of("elsewhere") else Digest.of(bytes);
    var decodes = digest.eql(Digest.of(bytes));
    var decoder: tree.Decoder = undefined;
    if (decoder.init(bytes)) |_| {
        var entry: tree.Entry = undefined;
        while (decoder.next(&entry) catch blk: {
            decodes = false;
            break :blk false;
        }) {}
    } else |_| decodes = false;
    var failure: object.Failure = undefined;
    if (trees.put_checked(&store, digest, bytes, &failure)) |_| {
        assert(decodes);
        var buffer: [1100]u8 = undefined;
        var errno: u16 = 0;
        const loaded = trees.load(&store, digest, &buffer, &errno) catch unreachable; // Just put.
        assert(std.mem.eql(u8, loaded, bytes));
    } else |_| {
        assert(!decodes);
        assert(!(trees.has(&store, digest) catch unreachable)); // A refusal stores nothing.
    }
}
