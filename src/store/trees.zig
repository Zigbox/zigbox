//! Tree objects in the store: writing one under its digest, reading one back, and finding a tree
//! from a digest prefix. A tree object is the file `trees/ab/<62 hex>` holding the encoding of
//! `tree.zig`; its name is the hash of its bytes, so a reader can check it (and `load` does:
//! the digest is verified when the tree is written and again when it is read, as STYLE.md asks
//! of a pair).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const tree = @import("tree.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Prefix = digest_mod.Prefix;
const Store = layout.Store;

/// Writes the tree `bytes` under `digest` unless it is there. True if it was new. A write
/// that fails leaves nothing under the digest.
pub fn put(
    store: *Store,
    digest: Digest,
    bytes: []const u8,
    failure: *object.Failure,
) object.PutError!bool {
    assert(Digest.of(bytes).eql(digest)); // The digest is the hash of exactly these bytes.
    assert(bytes.len <= constants.store_tree_bytes_max);
    const fs = store.fs;
    var final_storage: PathBuf = undefined;
    const final = store.tree_path(&final_storage, digest);
    if (fs.lstat(final)) |_| {
        return false;
    } else |err| {
        if (err != error.NotFound) return store_failed(failure, fs, err);
    }
    var shard_storage: PathBuf = undefined;
    const shard = store.shard_path(&shard_storage, "trees", digest);
    fs.make_directory(shard, true) catch |err| return store_failed(failure, fs, err);
    var parent_storage: PathBuf = undefined;
    const parent = store.directory_path(&parent_storage, "trees");
    fs.sync_directory(parent) catch |err| return store_failed(failure, fs, err);
    var temporary_storage: PathBuf = undefined;
    const temporary = store.tmp_path(&temporary_storage);
    fs.write_atomic(temporary, final, shard, bytes, 0o644, failure) catch return error.StoreFailed;
    return true;
}

fn store_failed(failure: *object.Failure, fs: fs_mod.Fs, err: host_mod.Error) object.PutError {
    assert(@intFromPtr(failure) != 0);
    assert(@intFromPtr(fs.vtable) != 0);
    failure.* = .{ .err = err, .errno = fs.last_errno() };
    return error.StoreFailed;
}

pub const LoadError = error{ NotFound, Damaged, Unreadable };

/// Reads the tree `digest` into `buffer` and checks that it hashes to its name.
pub fn load(
    store: *const Store,
    digest: Digest,
    buffer: []u8,
    errno: *u16,
) LoadError![]const u8 {
    assert(buffer.len <= std.math.maxInt(u32));
    assert(buffer.len > 0);
    var path: PathBuf = undefined;
    const bytes = store.fs.read_whole(store.tree_path(&path, digest), buffer) catch |err| {
        errno.* = store.fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    if (!Digest.of(bytes).eql(digest)) return error.Damaged;
    return bytes;
}

/// What a prefix names.
pub const Match = union(enum) {
    none,
    one: Digest,
    /// Two of the trees it names (there may be more).
    many: [2]Digest,
};

const Finder = struct {
    wanted: []const u8,
    shard: [2]u8,
    first: ?Digest,
    second: ?Digest,

    fn visit(context: *anyopaque, name: []const u8) void {
        assert(@intFromPtr(context) != 0);
        assert(name.len > 0);
        const finder: *Finder = @ptrCast(@alignCast(context));
        if (name.len != constants.store_digest_hex_bytes - 2) return;
        if (!std.mem.startsWith(u8, name, finder.wanted)) return;
        var hex: [constants.store_digest_hex_bytes]u8 = undefined;
        @memcpy(hex[0..2], &finder.shard);
        @memcpy(hex[2..], name);
        const digest = Digest.from_hex(&hex) orelse return;
        if (finder.first == null) {
            finder.first = digest;
        } else if (finder.second == null) {
            finder.second = digest;
        }
    }
};

/// Finds the tree a prefix names, by looking in its shard directory only.
pub fn find(store: *const Store, prefix: *const Prefix) host_mod.Error!Match {
    assert(prefix.len <= constants.store_digest_hex_bytes);
    assert(prefix.len >= constants.store_prefix_hex_min);
    var shard_storage: PathBuf = undefined;
    const shard_digest = Digest.from_hex(&shard_probe(prefix.digits())) orelse unreachable; // Hex.
    const shard = store.shard_path(&shard_storage, "trees", shard_digest);
    var finder: Finder = .{
        .wanted = prefix.digits()[2..],
        .shard = prefix.hex[0..2].*,
        .first = null,
        .second = null,
    };
    store.fs.read_dir(shard, .{ .context = &finder, .call = Finder.visit }) catch |err| {
        if (err == error.NotFound) return .none;
        return err;
    };
    const first = finder.first orelse return .none;
    const second = finder.second orelse return .{ .one = first };
    return .{ .many = .{ first, second } };
}

/// A full-length hex string that starts with the prefix's first two digits, to name the shard.
fn shard_probe(digits: []const u8) [constants.store_digest_hex_bytes]u8 {
    assert(digits.len <= constants.store_digest_hex_bytes);
    assert(digits.len >= 2);
    var probe: [constants.store_digest_hex_bytes]u8 = @splat('0');
    @memcpy(probe[0..2], digits[0..2]);
    return probe;
}

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const SimFs = @import("fs_sim.zig").SimFs;

var test_sim: HostSim = undefined;
var test_files: SimFs = undefined;
var test_store: Store = undefined;

fn start_test() *Store {
    test_sim.init(1, &.{});
    test_files.init(1);
    test_files.put_dir("/s", 0o755);
    test_files.put_dir("/s/trees", 0o755);
    test_files.put_dir("/s/tmp", 0o755);
    test_sim.store_fs = &test_files;
    test_store.at(test_sim.interface(), "/s");
    return &test_store;
}

test "a tree is written once, read back checked, and found by a prefix" {
    // Goal: put, load and find agree. Method: one tree; a second put is a no-op; a prefix finds
    // it; a prefix of another digest finds nothing; a tree that is not there is `NotFound`.
    const store = start_test();
    var buffer: [64]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    const bytes = writer.finish();
    const digest = Digest.of(bytes);
    var failure: object.Failure = undefined;
    try testing.expect(try put(store, digest, bytes, &failure));
    try testing.expect(!(try put(store, digest, bytes, &failure)));
    var read: [64]u8 = undefined;
    var errno: u16 = 0;
    try testing.expectEqualSlices(u8, bytes, try load(store, digest, &read, &errno));
    const prefix = Prefix.parse(digest.hex()[0..14]).?;
    try testing.expect((try find(store, &prefix)).one.eql(digest));
    const other = Prefix.parse(Digest.of("other").hex()[0..14]).?;
    try testing.expect((try find(store, &other)) == .none);
    try testing.expectEqual(error.NotFound, load(store, Digest.of("absent"), &read, &errno));
    try testing.expectEqual(@as(u32, 0), test_sim.open_count());
}

test "a tree whose bytes were damaged on disk is refused when it is read" {
    // Goal: the digest is checked on the way back in. Method: write a tree, change one byte of
    // the file, load it.
    const store = start_test();
    var buffer: [64]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    const bytes = writer.finish();
    const digest = Digest.of(bytes);
    var failure: object.Failure = undefined;
    _ = try put(store, digest, bytes, &failure);
    var path: PathBuf = undefined;
    const stored = store.tree_path(&path, digest);
    const content = test_files.content_of(stored).?;
    @constCast(content)[2] ^= 1; // The simulator's bytes are the test's to damage.
    var read: [64]u8 = undefined;
    var errno: u16 = 0;
    try testing.expectEqual(error.Damaged, load(store, digest, &read, &errno));
}

test "two trees with one prefix are ambiguous" {
    // Goal: the prefix rule. Method: two files in a shard whose names share 12 digits.
    const store = start_test();
    const hex = Digest.of("x").hex();
    var path: [96]u8 = undefined;
    test_files.put_dir(try std.fmt.bufPrint(&path, "/s/trees/{s}", .{hex[0..2]}), 0o755);
    var other = hex;
    other[63] = if (other[63] == '0') '1' else '0';
    for ([_][64]u8{ hex, other }) |name| {
        const where = try std.fmt.bufPrint(&path, "/s/trees/{s}/{s}", .{ name[0..2], name[2..] });
        test_files.put_file(where, 0o644, "");
    }
    const prefix = Prefix.parse(hex[0..12]).?;
    try testing.expect((try find(store, &prefix)) == .many);
    const longer = Prefix.parse(hex[0..64]).?;
    try testing.expect((try find(store, &longer)) == .one);
}

test "a write that fails at any step leaves the tree absent or whole, never part" {
    // Goal: atomicity at every write point. Method: fail each write point of a put in turn;
    // afterwards the tree is not there, or it loads and hashes right, and the retry succeeds.
    var buffer: [64]u8 = undefined;
    var writer = tree.Writer.init(&buffer);
    const bytes = writer.finish();
    const digest = Digest.of(bytes);
    var point: u32 = 0;
    while (point < 16) : (point += 1) {
        const store = start_test();
        var failure: object.Failure = undefined;
        test_files.faults.fail_mutation = point;
        const result = put(store, digest, bytes, &failure);
        test_files.faults.fail_mutation = null;
        var read: [64]u8 = undefined;
        var errno: u16 = 0;
        if (result) |_| break else |_| {}
        if (load(store, digest, &read, &errno)) |found| {
            try testing.expectEqualSlices(u8, bytes, found);
        } else |err| {
            try testing.expectEqual(error.NotFound, err);
        }
        _ = try put(store, digest, bytes, &failure);
        try testing.expectEqualSlices(u8, bytes, try load(store, digest, &read, &errno));
        try testing.expectEqual(@as(u32, 0), test_sim.open_count());
    }
    try testing.expect(point < 16); // The put finished before the last write point tried.
}
