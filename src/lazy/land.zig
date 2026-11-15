//! The store side of the resolver: a verified read of one chunk from the store, and the landing
//! of fetched bytes in it.
//!
//! Every byte the resolver hands a reader comes out of `read_local`, which hashes what it read
//! against the chunk's listed hash before it returns; a fetched chunk is hashed by `land`
//! before `chunks.put_chunk` (which hashes it again) keeps it. So a chunk is checked when it
//! arrives and again when it is served: the pair assertion of docs/STYLE.md, as in the brief's
//! decision 3. A reader never gets bytes straight from a source.
//!
//! The chunk is found where the store keeps it: the whole object under its id, or, until the
//! object assembles, `partial/<id>/<index>`. An assembly removes the chunk files after the
//! object is renamed into place, so a chunk file that vanished between the two looks is looked
//! for again in the object, once.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chunks = @import("../store/chunks.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const object = @import("../store/object.zig");
const chaining_mod = @import("chaining.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;
const Wanted = chunks.Wanted;

pub const ReadError = error{
    /// Neither the object nor the chunk is in the store.
    NotLocal,
    /// The chunk file (`partial/<id>/<index>`) holds bytes that do not hash right. Nothing is
    /// returned; the chunk is fetched again, and the put replaces the damaged file.
    Damaged,
    /// The whole object is in the store but this chunk of it does not hash right. A put never
    /// replaces a whole object, so the read fails.
    ObjectDamaged,
    /// The file system refused a read.
    Unreadable,
};

/// Serialises the store's file calls between threads (its handle count and last errno are not
/// shared safely). `read_local` holds it for each file's open, read and close only, never for
/// the hash, so a reader hashing a chunk does not hold up the slots' puts.
pub const StoreLock = struct {
    context: *anyopaque,
    lock: *const fn (context: *anyopaque) void,
    unlock: *const fn (context: *anyopaque) void,

    fn hold(store_lock: ?*const StoreLock) void {
        const held = store_lock orelse return;
        held.lock(held.context);
    }

    fn release(store_lock: ?*const StoreLock) void {
        const held = store_lock orelse return;
        held.unlock(held.context);
    }
};

/// Reads chunk `index` of `wanted` into `out` and checks it against `wanted.hashes[index]`, and
/// a chunk file against its chaining value too (`anchored`): a chunk file may have been kept by
/// a run whose index listed forged chunk hashes. A whole object's chunks need no chaining
/// check: `put_chunk` assembled it only after its content hashed to `wanted.content`.
/// Every error leaves `out` cleared, so no byte of an unverified chunk stays behind.
/// `store_lock` is null on one thread.
pub fn read_local(
    store: *const Store,
    wanted: *const Wanted,
    chaining: []const Digest,
    index: u32,
    out: []u8,
    store_lock: ?*const StoreLock,
) ReadError!usize {
    assert(index < wanted.hashes.len);
    const length = chunks.chunk_length(store, wanted.size, index);
    assert(length > 0);
    assert(out.len >= length);
    const chunk = out[0..@intCast(length)];
    const checked = read_checked(store, wanted, chaining, index, chunk, store_lock);
    if (checked) |got| {
        assert(got == length);
        return got;
    } else |err| {
        @memset(chunk, 0);
        return err;
    }
}

fn read_checked(
    store: *const Store,
    wanted: *const Wanted,
    chaining: []const Digest,
    index: u32,
    out: []u8,
    store_lock: ?*const StoreLock,
) ReadError!usize {
    assert(out.len == chunks.chunk_length(store, wanted.size, index));
    assert(out.len > 0);
    // The object first, then the chunk file, then the object again: an assembly may finish
    // (and remove the chunk files) between the first two looks.
    for (0..2) |round| {
        StoreLock.hold(store_lock);
        const from_object = read_from_object(store, wanted, index, out);
        StoreLock.release(store_lock);
        if (try from_object) {
            if (!Digest.of(out).eql(wanted.hashes[index])) return error.ObjectDamaged;
            return out.len;
        }
        if (round == 0) {
            StoreLock.hold(store_lock);
            const partial = read_from_partial(store, wanted, index, out);
            StoreLock.release(store_lock);
            if (try partial) {
                if (!Digest.of(out).eql(wanted.hashes[index])) return error.Damaged;
                if (!anchored(chaining, index, store.chunk_bytes, out)) return error.Damaged;
                return out.len;
            }
        }
    }
    return error.NotLocal;
}

/// True if the whole object is in the store and its chunk `index` was read whole (the caller
/// hashes it, outside the store lock).
fn read_from_object(
    store: *const Store,
    wanted: *const Wanted,
    index: u32,
    out: []u8,
) ReadError!bool {
    assert(out.len > 0);
    assert(index < wanted.hashes.len);
    const fs = store.fs;
    var path_storage: PathBuf = undefined;
    const path = store.object_path(&path_storage, wanted.id);
    const fd = fs.open_read(path) catch |err| switch (err) {
        error.NotFound => return false,
        else => return error.Unreadable,
    };
    defer fs.close(fd);
    const offset = @as(u64, index) * store.chunk_bytes;
    const got = fs.read_full_at(fd, offset, out) catch return error.Unreadable;
    if (got != out.len) return error.ObjectDamaged;
    return true;
}

/// True if `partial/<id>/<index>` holds exactly the chunk's length (the caller hashes it).
fn read_from_partial(
    store: *const Store,
    wanted: *const Wanted,
    index: u32,
    out: []u8,
) ReadError!bool {
    assert(out.len > 0);
    assert(index < wanted.hashes.len);
    const fs = store.fs;
    var path_storage: PathBuf = undefined;
    const path = chunks.partial_chunk(store, &path_storage, wanted.id, index);
    const fd = fs.open_read(path) catch |err| switch (err) {
        error.NotFound => return false,
        else => return error.Unreadable,
    };
    defer fs.close(fd);
    const got = fs.read_full_at(fd, 0, out) catch return error.Unreadable;
    if (got != out.len) return error.Damaged;
    // One byte more would mean the file is longer than the chunk: damage too.
    var extra: [1]u8 = undefined;
    const more = fs.read_full_at(fd, out.len, &extra) catch return error.Unreadable;
    if (more != 0) return error.Damaged;
    return true;
}

/// Whether chunk `index` is in the store, by name only (no hash): what the fill and readahead
/// use to skip what is there. A damaged chunk counts as present here; the read that needs it
/// finds the damage and asks for it again with `refetch`, which skips this look.
pub fn is_local(store: *const Store, wanted: *const Wanted, index: u32) bool {
    assert(index < wanted.hashes.len);
    assert(store.root_len > 1);
    if (object_is_whole(store, wanted)) return true;
    var path_storage: PathBuf = undefined;
    const path = chunks.partial_chunk(store, &path_storage, wanted.id, index);
    _ = store.fs.lstat(path) catch return false;
    return true;
}

pub fn object_is_whole(store: *const Store, wanted: *const Wanted) bool {
    assert(store.root_len > 1);
    assert(wanted.hashes.len <= constants.store_chunks_max);
    var path_storage: PathBuf = undefined;
    _ = store.fs.lstat(store.object_path(&path_storage, wanted.id)) catch return false;
    return true;
}

pub const Landed = enum {
    /// The chunk is in the store (now, or it was already).
    landed,
    /// As `landed`, and the object is whole in the store with it.
    whole,
    /// The bytes are not the chunk: wrong length or wrong hash. Nothing was written.
    lied,
    /// Every chunk was in and they do not make the object: the index's chunk hashes do not add
    /// up to its content. The chunks were discarded.
    content_mismatch,
    /// The disk is full.
    store_full,
    /// The store lock is held by a gc or a restore; try again later.
    busy,
    /// Another failure of the store.
    failed,
};

/// True if `bytes`, chunk `index` of an object, has the chaining value the index gave it at its
/// place, or the object has none to check (`lazy.Object.chaining` is empty). A plain chunk hash
/// can be forged in an index; the chaining values join into the content hash, which the object
/// id and the signed tree name, so a chunk that matches its value is the tree's.
pub fn anchored(chaining: []const Digest, index: u32, chunk_bytes: u32, bytes: []const u8) bool {
    if (chaining.len == 0) return true;
    assert(index < chaining.len);
    assert(chaining.len >= 2);
    assert(bytes.len >= 1);
    assert(bytes.len <= chunk_bytes);
    return chaining_mod.run_value(bytes, index, chunk_bytes).eql(chaining[index]);
}

/// Checks `bytes` against chunk `index` and keeps them with `put_chunk`. `io` is the put's copy
/// buffer. The caller holds no lock of the resolver's but serialises calls on one `store`
/// (its temporary names and counters are not shared safely between threads).
pub fn land(
    store: *Store,
    io: []u8,
    wanted: *const Wanted,
    chaining: []const Digest,
    index: u32,
    bytes: []const u8,
) Landed {
    assert(index < wanted.hashes.len);
    assert(io.len >= 4096);
    if (bytes.len != chunks.chunk_length(store, wanted.size, index)) return .lied;
    if (!Digest.of(bytes).eql(wanted.hashes[index])) return .lied;
    if (!anchored(chaining, index, store.chunk_bytes, bytes)) return .lied;
    var failure: chunks.Failure = undefined;
    const progress = chunks.put_chunk(store, io, wanted, index, bytes, &failure) catch |err| {
        return switch (err) {
            // Checked just above: `put_chunk` agreeing is the pair of that check.
            error.WrongLength, error.HashMismatch, error.IndexOutOfRange => unreachable,
            error.BadWanted => .failed,
            error.ContentMismatch => .content_mismatch,
            error.Busy => .busy,
            error.StoreFailed => if (failure_is_full(&failure)) .store_full else .failed,
        };
    };
    assert(progress.have <= progress.total);
    if (progress.complete) {
        assert(progress.have == progress.total);
        return .whole;
    }
    return .landed;
}

/// Makes an empty object whole: it has no chunk to land.
pub fn land_empty(store: *Store, io: []u8, wanted: *const Wanted) Landed {
    assert(wanted.size == 0);
    assert(wanted.hashes.len == 0);
    var failure: chunks.Failure = undefined;
    const progress = chunks.finish(store, io, wanted, &failure) catch |err| {
        return switch (err) {
            error.Busy => .busy,
            error.ContentMismatch => .content_mismatch,
            error.StoreFailed => if (failure_is_full(&failure)) .store_full else .failed,
            else => .failed,
        };
    };
    assert(progress.complete);
    return .whole;
}

fn failure_is_full(failure: *const chunks.Failure) bool {
    assert(failure.errno < 4096);
    if (failure.err == error.NoSpace) return true;
    return failure.errno == 28; // ENOSPC from a call that reported a generic error.
}

comptime {
    assert(constants.store_chunk_bytes <= constants.lazy_range_bytes_max);
    assert(object.chunk_count(0, constants.store_chunk_bytes) == 0);
}
