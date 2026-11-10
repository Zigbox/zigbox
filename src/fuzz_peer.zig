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
//!      The same holds when the object file is cut or extended: nothing but the original bytes
//!      of a chunk the list still vouches for. Objects carry random attributes, so a one-chunk
//!      object's id check gathers them. The reader is inside the store's namespace or outside
//!      it, with the one-id map or a full one; outside, the object is owned by the host ids of
//!      its container ids.
//!   3. With short reads and failing reads, a read gives the original bytes or an error.
//!   4. `put_checked` of bytes (a valid tree, then cut, extended, flipped or random) under their
//!      own digest or another one is accepted exactly when the digest is right and the decoder
//!      takes every entry; a refusal stores nothing, an acceptance stores a tree that loads.
//!      No input reaches an assertion. A tree one byte too long is `TooLarge`, and an accepted
//!      tree is canonical and walks as its entries say, with the entry limit as the bound.
//!   5. `image_peer.import_record` of an image record (valid, then cut, extended, flipped or
//!      random) for a whole tree is accepted exactly when the text parses and names that tree;
//!      what parses renders and parses again to the same text; a refusal writes nothing under
//!      images/ or roots/, and an acceptance leaves a record that loads with that tree. No input
//!      reaches an assertion.
//!   7. `trust import` of a signed bundle with one byte flipped (or the bundle cut, or extended)
//!      is refused whole, writing nothing, or re-verifies: what it stored is exactly the bytes
//!      given, and loads as a record of its tree. The unmodified bundle is always taken, and
//!      `export_record` gives its bytes back.
//!   6. Outside the namespace, an owner the map does not reach makes a one-chunk object an
//!      error (with `out` zero), and an object of several chunks reads as before.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const image_peer = @import("store/image_peer.zig");
const reference_mod = @import("registry/reference.zig");
const images = @import("store/images.zig");
const Sha256 = @import("registry/digest.zig").Sha256;
const chunk_read = @import("store/chunk_read.zig");
const chunks = @import("store/chunks.zig");
const Digest = @import("store/digest.zig").Digest;
const fs_sim = @import("store/fs_sim.zig");
const layout = @import("store/layout.zig");
const object = @import("store/object.zig");
const object_mod = object; // `Counter.object` hides `object` inside it.
const owners = @import("store/owners.zig");
const dsse = @import("trust/dsse.zig");
const peer = @import("trust/peer.zig");
const record = @import("trust/record.zig");
const statement = @import("trust/statement.zig");
const support = @import("store/test_support.zig");
const tree = @import("store/tree.zig");
const trees = @import("store/trees.zig");
const walk = @import("store/walk.zig");
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
var scratch: xattrs.Scratch = undefined;
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
    store.owners = .inside;
    fuzz_put(random);
    fuzz_image(random);
    fuzz_bundle(random);
    assert(sim.open_count() == 0);
}

var attribute_count: u32 = 0;
var attribute_values: [2][8]u8 = undefined;
var attribute_blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
var attribute_builder: xattrs.Builder = undefined;
const attribute_names = [2][:0]const u8{ "user.zbx.a", "user.zbx.b" };

/// Zero to two attributes with short random values, so that the check of a one-chunk object
/// gathers them. The section is in `attribute_blob`.
fn random_attributes(random: std.Random) []const u8 {
    attribute_count = random.uintAtMost(u32, 2);
    attribute_builder.reset();
    for (0..attribute_count) |index| {
        random.bytes(&attribute_values[index]);
        attribute_builder.add(attribute_names[index], &attribute_values[index]) catch
            unreachable; // Two short attributes fit.
    }
    return attribute_builder.finish(&attribute_blob);
}

/// The object file was replaced, which loses its attributes: set them again.
fn restore_attributes(path: []const u8) void {
    for (0..attribute_count) |index| {
        files.put_xattr(path, attribute_names[index], &attribute_values[index]);
    }
}

fn fuzz_read(random: std.Random) void {
    const length = random.uintAtMost(u32, content_bytes_max);
    for (content[0..length]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'e');
    random_owners(random);
    // The one-id map has only the container's root, so a store made with it owns nothing else.
    const single = store.owners == .outside and store.owners.outside.range == null;
    const attrs: object.Attrs = .{
        .mode = random.uintAtMost(u16, 0o7777),
        .uid = if (single) 0 else random_owner_id(random),
        .gid = if (single) 0 else random_owner_id(random),
        .xattrs = random_attributes(random),
    };
    const id = put_object(content[0..length], attrs);
    host_owner = .{ host_id(.uid, attrs.uid), host_id(.gid, attrs.gid) };
    set_host_owner(id, host_owner);
    const count = object.chunk_count(length, store.chunk_bytes);
    for (0..count) |index| expect_chunk(id, @intCast(index), length, true);
    assert(read(id, count) == error.IndexOutOfRange);
    if (length == 0) return;
    unmapped_owner(random, id, count, length);
    if (random.boolean()) {
        damage_flip(random, id, count, length);
    } else {
        damage_resize(random, id, attrs, count, length);
    }
    files.faults.short_read_per_mille = random.uintAtMost(u16, 1000);
    files.faults.read_error_per_mille = random.uintAtMost(u16, 1000);
    const faulty = files.faults.read_error_per_mille == 0;
    for (0..count) |index| expect_chunk(id, @intCast(index), length, faulty);
}

/// One bit of the object, or of its list, flipped: that chunk, and only that one, is refused.
fn damage_flip(random: std.Random, id: Digest, count: u32, length: u32) void {
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
    bytes[at] ^= flip; // Restored: the faults after are on an intact object.
}

/// The object file cut or extended: an object of one chunk is refused whole (its id no longer
/// holds); of several, the list no longer fits unless the number of chunks is the same, and
/// then only the last chunk, whose length changed, is refused. Never other bytes.
fn damage_resize(
    random: std.Random,
    id: Digest,
    attrs: object.Attrs,
    count: u32,
    length: u32,
) void {
    var resized: [content_bytes_max + 40]u8 = undefined;
    @memcpy(resized[0..length], content[0..length]);
    var new_length: u32 = undefined;
    if (random.boolean()) {
        new_length = random.uintLessThan(u32, length); // Cut, down to nothing at the least.
    } else {
        const extra = random.intRangeAtMost(u32, 1, 40);
        random.bytes(resized[length..][0..extra]);
        new_length = length + extra;
    }
    assert(new_length != length);
    const hex = id.hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const text = std.fmt.bufPrint(&path, root_path ++ "/objects/{s}/{s}", .{
        hex[0..2], hex[2..],
    }) catch unreachable; // Short.
    replace_object(text, attrs, resized[0..new_length]);
    const same_count = object.chunk_count(new_length, store.chunk_bytes) == count;
    for (0..count) |index| {
        const must_work = count > 1 and same_count and index != count - 1;
        expect_chunk(id, @intCast(index), length, must_work);
    }
    replace_object(text, attrs, content[0..length]); // Restored.
}

fn replace_object(path: []const u8, attrs: object.Attrs, bytes: []const u8) void {
    files.remove_path(path);
    files.put_file(path, attrs.mode, bytes);
    // The owner is the one `lstat` shows this reader, not the container's in `attrs`.
    files.set_owner_of(path, host_owner[0], host_owner[1]);
    restore_attributes(path);
}

/// The owner `lstat` shows for the object being fuzzed: the host's ids of its container ids.
var host_owner: [2]u32 = undefined;

/// A container id: mostly the few that images use, sometimes the edges of the range.
fn random_owner_id(random: std.Random) u32 {
    return switch (random.uintLessThan(u32, 6)) {
        0 => constants.subid_range_min,
        1 => constants.subid_range_min - 1,
        else => random.uintLessThan(u32, 4),
    };
}

/// The reader is inside the store's namespace, or outside it with the one-id map or the full
/// map of a user (or root) with a range.
fn random_owners(random: std.Random) void {
    // The user's gid is its own, not its uid (a mutant that maps one through the other fails).
    const own: u32 = if (random.boolean()) 0 else 1000;
    const own_gid: u32 = own + random.uintAtMost(u32, 1);
    store.owners = switch (random.uintLessThan(u32, 3)) {
        0 => .inside,
        1 => .{ .outside = .{ .uid = own, .gid = own_gid, .range = null } },
        else => .{ .outside = .{ .uid = own, .gid = own_gid, .range = .{
            .uid_start = 100000,
            .gid_start = if (random.boolean()) 100000 else 300000,
        } } },
    };
}

/// The host id the kernel maps container id `id` to: the oracle of `owners.container_id`,
/// written forwards, as the id map reads (`0 own 1 1 start range`).
fn host_id(kind: owners.Kind, id: u32) u32 {
    switch (store.owners) {
        .inside => return id,
        .outside => |map| {
            const own = if (kind == .uid) map.uid else map.gid;
            if (id == 0) return own;
            const range = map.range.?; // The one-id map has only id 0.
            const start = if (kind == .uid) range.uid_start else range.gid_start;
            assert(id <= constants.subid_range_min);
            return start + id - 1;
        },
    }
}

fn set_host_owner(id: Digest, owner: [2]u32) void {
    const hex = id.hex();
    var path: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const text = std.fmt.bufPrint(&path, root_path ++ "/objects/{s}/{s}", .{
        hex[0..2], hex[2..],
    }) catch unreachable; // Short.
    files.set_owner_of(text, owner[0], owner[1]);
}

/// Outside the namespace, an owner the map does not reach (one past the range, or one before
/// it) makes a one-chunk object refused, never mapped by a guess; an object of several chunks,
/// whose list does not hold the owner, still reads.
fn unmapped_owner(random: std.Random, id: Digest, count: u32, length: u32) void {
    if (store.owners == .inside) return;
    const map = store.owners.outside;
    const start = if (map.range) |range| range.uid_start else 100000;
    const stray: u32 = if (random.boolean()) start + constants.subid_range_min else start - 1;
    assert(owners.container_id(&map, .uid, stray) == null);
    const stray_group = if (map.range) |range|
        range.gid_start + constants.subid_range_min
    else
        stray;
    assert(owners.container_id(&map, .gid, stray_group) == null);
    const owner: [2]u32 = if (random.boolean())
        .{ stray, host_owner[1] }
    else
        .{ host_owner[0], stray_group };
    expect_refused(id, count, length, owner);
    wrong_owner(random, id, count, length);
    set_host_owner(id, host_owner);
}

/// With `owner` as the file's owner: a one-chunk object is refused as `Damaged` with `out`
/// zeroed (never mapped by a guess); an object of several chunks still reads.
fn expect_refused(id: Digest, count: u32, length: u32, owner: [2]u32) void {
    set_host_owner(id, owner);
    for (0..count) |index| {
        expect_chunk(id, @intCast(index), length, count > 1);
        if (count == 1) assert(read(id, 0) == error.Damaged);
    }
}

/// The neighbour of the right host id, in the range when there is one (a different container
/// id, or none at the edge): the map must tell it from the right one.
fn wrong_owner(random: std.Random, id: Digest, count: u32, length: u32) void {
    const step: u32 = if (random.boolean()) 1 else std.math.maxInt(u32); // +1 or -1, wrapping.
    var owner = host_owner;
    if (random.boolean()) owner[0] +%= step else owner[1] +%= step;
    assert(!std.mem.eql(u32, &owner, &host_owner));
    expect_refused(id, count, length, owner);
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
    return chunk_read.read_chunk(&store, &io, &scratch, id, index, &out);
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

var oversize: [constants.store_tree_bytes_max + 1]u8 = undefined;
var walk_buffer: [constants.store_tree_bytes_max]u8 = undefined;
var walk_stack: [4]Digest = undefined;

/// Counts what a walk shows the visitor.
const Counter = struct {
    files: u32 = 0,

    pub fn object(counter: *Counter, ref: *const walk.ObjectRef) void {
        assert(ref.chunk_count == object_mod.chunk_count(ref.size, store.chunk_bytes));
        counter.files += 1;
    }
};

/// The walk over an accepted tree with a random entry limit: with no directory below it, it
/// passes exactly when the limit covers every entry, and sees every file; otherwise it stops
/// with `too_many_entries`. A tree with a directory (its subtree is not in the store) only has
/// to end in an answer.
fn fuzz_walk(random: std.Random, root: Digest, bytes: []const u8) void {
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch unreachable; // Accepted, so it decodes.
    var entry: tree.Entry = undefined;
    var entries: u32 = 0;
    var file_entries: u32 = 0;
    var has_directory = false;
    var too_long = false;
    while (decoder.next(&entry) catch unreachable) { // Accepted, so every entry decodes.
        entries += 1;
        if (entry.kind == .file) file_entries += 1;
        if (entry.kind == .dir) has_directory = true;
        const longest = @as(u64, constants.store_chunks_max) * store.chunk_bytes;
        if (entry.kind == .file and entry.size > longest) {
            too_long = true;
        }
    }
    const limit = random.intRangeAtMost(u32, 1, 6);
    var counter: Counter = .{};
    var failure: walk.Failure = undefined;
    const result = walk.objects(
        &store,
        &walk_buffer,
        &walk_stack,
        null,
        root,
        &counter,
        limit,
        &failure,
    );
    if (has_directory) return;
    if (too_long) { // A size no object has: the walk may stop on it, or on the limit first.
        assert(result == error.Failed);
        return;
    }
    if (entries <= limit) {
        result catch unreachable; // The limit covers every entry.
        assert(counter.files == file_entries);
    } else {
        assert(result == error.Failed);
        assert(failure.kind == .too_many_entries);
    }
}

/// A tree one byte past the longest tree object is `TooLarge`, whatever its digest.
fn fuzz_too_large(random: std.Random) void {
    @memset(&oversize, random.int(u8));
    var failure: object.Failure = undefined;
    const right = Digest.of(&oversize);
    const digest = if (random.boolean()) right else Digest.of("elsewhere");
    const result = trees.put_checked(&store, digest, &oversize, &failure);
    assert(result == error.TooLarge);
    assert(!(trees.has(&store, digest) catch unreachable)); // Nothing was stored.
}

fn fuzz_put(random: std.Random) void {
    files.faults.short_read_per_mille = 0; // Faults were the reads' business; the puts are clean.
    files.faults.read_error_per_mille = 0;
    if (random.uintLessThan(u8, 32) == 0) fuzz_too_large(random);
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
        var again: [1100 + 64]u8 = undefined;
        assert(tree.round_trips(bytes, &again)); // What is accepted is canonical.
        fuzz_walk(random, digest, bytes);
    } else |_| {
        assert(!decodes);
        assert(!(trees.has(&store, digest) catch unreachable)); // A refusal stores nothing.
    }
}

var peer_memory: image_peer.Memory = undefined;
var image_text: [constants.image_record_bytes_max]u8 = undefined;
var image_offered: [constants.image_record_bytes_max + 64]u8 = undefined;
var image_again: [constants.image_record_bytes_max]u8 = undefined;

/// Files under images/ and roots/ now: what an import may write.
fn image_files() u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (std.mem.indexOf(u8, path, "/images/") != null) count += 1;
        if (std.mem.indexOf(u8, path, "/roots/") != null) count += 1;
    }
    return count;
}

fn random_image(random: std.Random, whole: Digest) []const u8 {
    var image: images.Image = undefined;
    image.tag_count = 0;
    if (random.boolean()) image.add_tag("alpine:3.20");
    if (random.boolean()) image.add_tag("example.org/app:1");
    image.manifest = Sha256.of(&.{random.uintLessThan(u8, 3)});
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = whole;
    image.time = random.uintLessThan(u64, 1 << 20);
    image.layer_count = random.uintLessThan(u32, 3);
    for (image.layers[0..image.layer_count]) |*layer| layer.* = Sha256.of("layer");
    image.settings.clear();
    image.labels.clear();
    if (random.boolean()) _ = image.settings.add(.entrypoint, "/bin/hello");
    if (random.boolean()) _ = image.settings.add(.env, "A=b");
    if (random.boolean()) _ = image.settings.set(.workdir, "/srv");
    return images.render(&image, &image_text);
}

/// True if every tag of `image` reads as a reference, as `image_peer` requires of kept tags.
fn tags_are_references(image: *const images.Image) bool {
    for (0..image.tag_count) |index| {
        var reference: reference_mod.Reference = undefined;
        reference_mod.parse(image.tag_text(@intCast(index)), &reference) catch return false;
    }
    return true;
}

fn fuzz_image(random: std.Random) void {
    var writer = tree.Writer.init(&tree_bytes);
    const empty = writer.finish(); // A directory with no entries: whole with no objects.
    const whole = Digest.of(empty);
    var failure: object.Failure = undefined;
    _ = trees.put_checked(&store, whole, empty, &failure) catch unreachable; // Valid and clean.
    const good = random_image(random, whole);
    var length: usize = good.len;
    @memcpy(image_offered[0..length], good);
    switch (random.uintLessThan(u8, 5)) {
        0 => {},
        1 => length = random.uintAtMost(usize, length),
        2 => image_offered[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
        3 => {
            const extra = random.intRangeAtMost(usize, 1, 40);
            random.bytes(image_offered[length..][0..extra]);
            length += extra;
        },
        else => {
            length = random.uintAtMost(usize, 128);
            random.bytes(image_offered[0..length]);
        },
    }
    const text = image_offered[0..@min(length, constants.image_record_bytes_max)];
    const asked = if (random.uintLessThan(u8, 4) == 0) Digest.of("elsewhere") else whole;
    var parsed: images.Image = undefined;
    const parse = images.parse(text, &parsed);
    if (parse == .ok) {
        const first = images.render(&parsed, &image_text);
        var again: images.Image = undefined;
        assert(images.parse(first, &again) == .ok);
        assert(std.mem.eql(u8, first, images.render(&again, &image_again)));
    }
    const before = image_files();
    const tags: image_peer.TagPolicy = if (random.boolean()) .keep else .drop;
    // The trusted manifest is usually the one the record names, sometimes another.
    const elsewhere = random.uintLessThan(u8, 4) == 0;
    const trusted = if (elsewhere) Sha256.of("elsewhere") else parsed.manifest;
    const options: image_peer.Options = .{
        .expected_manifest = trusted,
        .tags = tags,
        .entries_max = 16,
    };
    var refusal: image_peer.Failure = undefined;
    if (image_peer.import_record(&store, &peer_memory, text, asked, options, &refusal)) |taken| {
        assert(parse == .ok);
        assert(parsed.tree.eql(asked));
        assert(parsed.manifest.eql(trusted)); // A record for another image is never taken.
        assert(taken.manifest.eql(trusted));
        assert(taken.tree.eql(asked));
        var loaded: images.Image = undefined;
        var errno: u16 = 0;
        images.load(&store, parsed.manifest, &loaded, &errno) catch unreachable; // Just saved.
        assert(loaded.tree.eql(asked));
    } else |_| {
        const named = parse == .ok and parsed.tree.eql(asked) and parsed.manifest.eql(trusted);
        // Only no record, another tree or another image is refused, or, when the tags are kept,
        // a tag that is no reference: a flipped byte can make one.
        const bad_tag = tags == .keep and parse == .ok and !tags_are_references(&parsed);
        if (named) assert(bad_tag); // Only a bad tag refuses a record naming tree and image.
        assert(image_files() == before); // A refusal writes nothing.
    }
}

var bundle_memory: peer.Memory = undefined;
var bundle_work: dsse.Work = undefined;
var bundle_line: [constants.envelope_bytes_max]u8 = undefined;
var bundle_good: record.Record = undefined;
var bundle_check: record.Record = undefined;
var bundle_offered: [constants.signature_record_bytes_max + 64]u8 = undefined;

/// A bundle of one to three signed lines about `whole`, flipped, cut or extended: refused whole
/// or stored exactly (property 7).
fn fuzz_bundle(random: std.Random) void {
    var empty_writer = tree.Writer.init(&tree_bytes);
    const whole = Digest.of(empty_writer.finish()); // The tree of `fuzz_image`: no entries.
    bundle_good.clear();
    const lines = random.intRangeAtMost(u32, 1, 3);
    while (bundle_good.count < lines) {
        var seed: [constants.key_seed_bytes]u8 = undefined;
        random.bytes(&seed);
        const found = statement.Statement.for_tree(whole.bytes, random.int(u32));
        var rendered: [statement.render_bytes_max]u8 = undefined;
        const text = statement.render(&rendered, &found);
        const signed = dsse.sign(&bundle_work, &bundle_line, seed, text) catch
            unreachable; // The statement is small, so it fits.
        _ = bundle_good.add(signed) catch unreachable; // At most three lines.
    }
    const good = bundle_good.text();
    assert(good.len <= constants.signature_record_bytes_max);
    var failure: peer.Failure = undefined;
    var length: usize = good.len;
    @memcpy(bundle_offered[0..length], good);
    const intact = random.uintLessThan(u8, 8) == 0;
    if (!intact) switch (random.uintLessThan(u8, 3)) {
        0, 1 => bundle_offered[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
        else => length = random.uintAtMost(usize, length),
    };
    const offered_text = bundle_offered[0..length];
    const taken = peer.import_record(&store, &bundle_memory, offered_text, whole, &failure);
    var errno: u16 = 0;
    const loaded = record.load(&store, &bundle_memory.work, whole, &bundle_check, &errno);
    if (taken) |imported| {
        // Accepted: it is the bytes given, and they load as a record of the tree.
        assert(imported.total >= 1);
        if (intact) assert(std.mem.eql(u8, offered_text, good));
        loaded catch unreachable; // What was stored loads.
        assert(std.mem.eql(u8, bundle_check.text(), offered_text));
    } else |_| {
        // Refused whole: nothing was written, so there is no record of the tree.
        assert(!intact);
        assert(std.meta.isError(loaded));
        loaded catch |err| assert(err == error.NotFound);
        return;
    }
    // Taken again, the same bundle adds nothing, and the export gives the bytes back.
    const again = peer.import_record(&store, &bundle_memory, offered_text, whole, &failure);
    assert((again catch unreachable).added == 0); // The same lines are all there.
    const back = peer.export_record(&store, &bundle_memory, whole, &failure);
    assert(std.mem.eql(u8, (back catch unreachable), offered_text)); // Stored as given.
}
