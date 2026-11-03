//! The verified read of one chunk of a stored object, for Zigcube's C2: what a node serves to a
//! peer that asked for chunk `index` of object `id`.
//!
//! What the chunk is checked against depends on what the store keeps:
//!
//!   - an object of several chunks has its list of chunk hashes (`<id>.chunks`); the bytes read
//!     must hash to the listed hash of that chunk;
//!   - an object of one chunk (or none) has no list, and the chunk's hash is the content hash,
//!     which the object id commits to together with the mode, owner and attributes. So the
//!     object id is recomputed from the bytes and the file's own metadata and must be `id`.
//!
//! A mismatch is `Damaged` and no byte is returned: every error clears `out`, so a caller that
//! ignores the error still holds no bytes of an unverified chunk. The call takes no store lock:
//! it only reads, and a gc that moves the object away after it was opened leaves the open file
//! readable, so the call sees the object whole or `NotFound`, never a part.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chunks = @import("chunks.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Error = error{
    /// The object is not in the store.
    NotFound,
    /// The object has no such chunk.
    IndexOutOfRange,
    /// What the store holds does not hash to what it should: the bytes of the chunk, the chunk
    /// list, or the object itself. Nothing was returned.
    Damaged,
    /// The file system refused a read.
    Unreadable,
};

/// Reads chunk `index` of the object `id` into `out`, which holds `store.chunk_bytes`, checks
/// it, and returns its length. `io` is the scratch buffer (room for a chunk list).
pub fn read_chunk(
    store: *const Store,
    io: []u8,
    id: Digest,
    index: u32,
    out: []u8,
) Error!usize {
    assert(io.len >= constants.store_chunks_max * constants.store_digest_bytes);
    assert(out.len >= store.chunk_bytes);
    if (read_checked(store, io, id, index, out)) |length| {
        assert(length > 0);
        assert(length <= store.chunk_bytes);
        return length;
    } else |err| {
        // Whatever was read before the refusal (a part, or a chunk that did not hash right) is
        // not for the caller: no error leaves a byte of it behind.
        @memset(out[0..store.chunk_bytes], 0);
        return err;
    }
}

fn read_checked(
    store: *const Store,
    io: []u8,
    id: Digest,
    index: u32,
    out: []u8,
) Error!usize {
    const fs = store.fs;
    var path_storage: PathBuf = undefined;
    const path = store.object_path(&path_storage, id);
    const stat = fs.lstat(path) catch |err| return map(err);
    if (stat.kind != .file) return error.Damaged;
    if (stat.size > constants.store_file_bytes_max) return error.Damaged;
    const count = object.chunk_count(stat.size, store.chunk_bytes);
    if (index >= count) return error.IndexOutOfRange;
    const length: usize = @intCast(chunks.chunk_length(store, stat.size, index));
    assert(length > 0);
    assert(length <= store.chunk_bytes);
    const expected = try listed_hash(store, io, id, stat.size, count, index);
    const fd = fs.open_read(path) catch |err| return map(err);
    defer fs.close(fd);
    const offset = @as(u64, index) * store.chunk_bytes;
    const got = fs.read_full_at(fd, offset, out[0..length]) catch |err| return map(err);
    if (got != length) return error.Damaged; // The file is shorter than its stat said.
    const refused = if (expected) |hash|
        !Digest.of(out[0..length]).eql(hash)
    else
        !try id_holds(store, path, stat, id, out[0..length]);
    if (refused) return error.Damaged;
    return length;
}

fn map(err: fs_mod.Error) Error {
    return switch (err) {
        error.NotFound => error.NotFound,
        else => error.Unreadable,
    };
}

/// The hash the list gives chunk `index`, or null for an object that has no list.
fn listed_hash(
    store: *const Store,
    io: []u8,
    id: Digest,
    size: u64,
    count: u32,
    index: u32,
) Error!?Digest {
    assert(index < count);
    if (!object.list_is_stored(size, store.chunk_bytes)) {
        assert(count == 1);
        return null;
    }
    var list_storage: PathBuf = undefined;
    const bytes = store.fs.read_whole(store.chunks_path(&list_storage, id), io) catch |err| {
        if (err == error.NotFound) return error.Damaged; // A long object without its list.
        return error.Unreadable;
    };
    if (bytes.len != @as(usize, count) * constants.store_digest_bytes) return error.Damaged;
    return .{ .bytes = bytes[index * constants.store_digest_bytes ..][0..32].* };
}

/// True if an object with these bytes and the file's own metadata has the id `id`. The
/// buffers for the attributes are large (about 160 KB), so they are this function's, on the
/// stack, and only an object of one chunk pays for them.
fn id_holds(
    store: *const Store,
    path: [:0]const u8,
    stat: fs_mod.Stat,
    id: Digest,
    bytes: []const u8,
) Error!bool {
    assert(bytes.len <= store.chunk_bytes);
    const content = Digest.of(bytes);
    var builder: xattrs.Builder = undefined;
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    var names: [8192]u8 = undefined;
    var value: [constants.store_xattr_value_bytes_max + 1]u8 = undefined;
    const fs = store.fs;
    builder.reset();
    const listed = fs.list_xattrs(path, &names) catch |err| return map(err);
    var start: usize = 0;
    while (start < listed.len) {
        const end = std.mem.indexOfScalarPos(u8, listed, start, 0) orelse break;
        const name = listed[start..end :0];
        start = end + 1;
        if (name.len == 0 or xattrs.class_of(name) != .keep) continue;
        const got = fs.get_xattr(path, name, &value) catch |err| return map(err);
        builder.add(name, got) catch return error.Damaged;
    }
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = builder.finish(&blob),
    };
    return object.object_id(content, attrs).eql(id);
}
