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
//!     The id commits to the container's ids, so a reader outside the store's namespace (whose
//!     `lstat` gives host ids) sets `store.owners` and the owner is mapped back first
//!     (`owners.zig`); an owner the map does not reach is `Damaged`.
//!
//! A mismatch is `Damaged` and no byte is returned: every error clears `out`, so a caller that
//! ignores the error still holds no bytes of an unverified chunk. The call takes no store lock:
//! it only reads. It opens the object first, and a gc that removes the object after that leaves
//! the open file readable; a chunk list that is gone then is told from damage by looking for
//! the object again. So the call sees the object whole or `NotFound`, never a part.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chunks = @import("chunks.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const owners = @import("owners.zig");
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
/// it, and returns its length. `io` is the scratch buffer (room for a chunk list) and
/// `scratch` the room for gathering an object's attributes; both are the caller's, so a server
/// keeps them per thread instead of on a stack.
pub fn read_chunk(
    store: *const Store,
    io: []u8,
    scratch: *xattrs.Scratch,
    id: Digest,
    index: u32,
    out: []u8,
) Error!usize {
    assert(io.len >= constants.store_chunks_max * constants.store_digest_bytes);
    assert(out.len >= store.chunk_bytes);
    if (read_checked(store, io, scratch, id, index, out)) |length| {
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
    scratch: *xattrs.Scratch,
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
    // Opened before the list is read: from here a gc cannot take the object's bytes away.
    const fd = fs.open_read(path) catch |err| return map(err);
    defer fs.close(fd);
    const expected = try listed_hash(store, io, id, stat.size, count, index);
    const offset = @as(u64, index) * store.chunk_bytes;
    const got = fs.read_full_at(fd, offset, out[0..length]) catch |err| return map(err);
    if (got != length) return error.Damaged; // The file is shorter than its stat said.
    const refused = if (expected) |hash|
        !Digest.of(out[0..length]).eql(hash)
    else
        !try id_holds(store, scratch, path, stat, id, out[0..length]);
    if (refused) return error.Damaged;
    return length;
}

fn map(err: fs_mod.Error) Error {
    return switch (err) {
        error.NotFound => error.NotFound,
        else => error.Unreadable,
    };
}

/// The hash the list gives chunk `index`, or null for an object that has no list. Public for the
/// test of a gc that takes the object and its list away between the caller's reads.
pub fn listed_hash(
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
        switch (err) {
            // A list longer than any list there can be is damage, not a read that failed.
            error.FileTooLarge => return error.Damaged,
            error.NotFound => return list_missing(store, id),
            else => return error.Unreadable,
        }
    };
    if (bytes.len != @as(usize, count) * constants.store_digest_bytes) return error.Damaged;
    const at = index * constants.store_digest_bytes;
    return .{ .bytes = bytes[at..][0..constants.store_digest_bytes].* };
}

/// A long object whose list is not there: damage if the object is still in the store, but if a
/// gc took the object (and so its list) the caller asked about something that is gone.
fn list_missing(store: *const Store, id: Digest) Error {
    var path_storage: PathBuf = undefined;
    _ = store.fs.lstat(store.object_path(&path_storage, id)) catch |err| return map(err);
    return error.Damaged;
}

/// True if an object with these bytes and the file's own metadata has the id `id`. Only an
/// object of one chunk gets here; its attributes are gathered in the caller's `scratch`.
fn id_holds(
    store: *const Store,
    scratch: *xattrs.Scratch,
    path: [:0]const u8,
    stat: fs_mod.Stat,
    id: Digest,
    bytes: []const u8,
) Error!bool {
    assert(bytes.len <= store.chunk_bytes);
    const content = Digest.of(bytes);
    const section = scratch.gather(store.fs, path) catch |err| switch (err) {
        error.TooMany, error.NameTooLong, error.ValueTooLong => return error.Damaged,
        else => |fs_err| return map(fs_err),
    };
    // Outside the store's namespace `lstat` gives host ids, and the id commits to the
    // container's: map them back. An owner the map does not reach is no object of this store.
    const owner = owners.container_ids(&store.owners, stat.uid, stat.gid) orelse return false;
    if (store.owners == .inside) assert(owner[0] == stat.uid);
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = owner[0],
        .gid = owner[1],
        .xattrs = section,
    };
    return object.object_id(content, attrs).eql(id);
}
