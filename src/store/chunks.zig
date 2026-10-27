//! The chunk API for Zigcube (`chunks(object_id)` is `object.chunk_hashes`): a verified write of
//! one object, one chunk at a time, in any order, from any source.
//!
//! A caller that wants the object `id` has what the tree entry and the chunk list give it: the
//! `Wanted` below (the object's attributes, its size, its content hash and the hash of each
//! chunk). It hands chunks to `put_chunk(index, bytes)` as they arrive:
//!
//!   - the bytes are accepted only if their length is the chunk's (a full chunk, or the rest of
//!     the file for the last one) and they hash to the chunk's hash; anything else is refused
//!     and nothing is written;
//!   - an accepted chunk is kept in `partial/<id>/<index>` (written atomically), so chunks may
//!     come in any order, twice, or across runs of the program;
//!   - when the last one is in, the object is assembled: the chunks are read in order into a new
//!     file in `tmp/`, which must hash to the content hash and have the size, is given the
//!     object's attributes, and is renamed under its id, with its chunk list first. The object
//!     appears whole or not at all, and the chunks are then removed.
//!
//! `Wanted` is what the caller already knows from the tree (nothing about an object follows
//! from its id alone: the id is a hash of the content hash and the attributes). It is checked:
//! the id must be that hash, the number of chunk hashes must fit the size, and a file of one
//! chunk has its content hash as its one chunk hash. The chunk hashes themselves are the
//! caller's claim; assembling checks them against the content hash, which is the id's anchor.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const generation = @import("generation.zig");
const layout = @import("layout.zig");
const lock = @import("lock.zig");
const object = @import("object.zig");

const Digest = digest_mod.Digest;
const Hasher = digest_mod.Hasher;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Wanted = struct {
    id: Digest,
    attrs: object.Attrs,
    size: u64,
    content: Digest,
    /// One hash per chunk, `chunk_count(size)` of them (none for an empty file).
    hashes: []const Digest,
};

pub const Progress = struct {
    /// Chunks held now (including this one), and how many the object has.
    have: u32,
    total: u32,
    /// The object is in the store (it was assembled now, or was there already).
    complete: bool,
    /// This chunk was already held, or the object was already in the store.
    duplicate: bool,
};

pub const Error = error{
    /// `Wanted` is inconsistent: the id is not the hash of the content and attributes, or the
    /// hashes do not fit the size.
    BadWanted,
    IndexOutOfRange,
    /// The bytes are not as long as the chunk they claim to be.
    WrongLength,
    /// The bytes do not hash to the chunk's hash.
    HashMismatch,
    /// Every chunk was accepted but together they are not the content (the chunk hashes were a
    /// lie); the chunks are discarded.
    ContentMismatch,
    /// The store lock is held by a gc or a restore (`store.lock_holder` says which) for longer
    /// than `store.lock_wait_ms`. Nothing was changed; try again.
    Busy,
    StoreFailed,
};

pub const Failure = fs_mod.Failure;

fn fail(fs: fs_mod.Fs, failure: *Failure, err: anyerror) Error {
    assert(@intFromPtr(failure) != 0);
    assert(fs.last_errno() < 4096);
    assert(@intFromPtr(failure) != 0);
    failure.* = .{ .err = @errorCast(err), .errno = fs.last_errno() };
    return error.StoreFailed;
}

/// The shared store lock for the length of one call. A caller that records the object in a tree
/// or a root afterwards holds the lock itself (`lock.hold`) from the first chunk to the record,
/// or a gc can move the finished object away in between.
fn hold(store: *Store, failure: *Failure) Error!void {
    lock.hold(store, .shared, "put_chunk") catch |err| switch (err) {
        error.Busy => return error.Busy,
        error.Failed => {
            failure.* = .{ .err = store.lock_error, .errno = store.lock_errno };
            return error.StoreFailed;
        },
    };
}

fn check_wanted(store: *const Store, wanted: *const Wanted) Error!void {
    assert(store.chunk_bytes > 0);
    assert(wanted.hashes.len <= constants.store_chunks_max);
    if (wanted.size > constants.store_file_bytes_max) return error.BadWanted;
    if (!object.object_id(wanted.content, wanted.attrs).eql(wanted.id)) return error.BadWanted;
    const count = object.chunk_count(wanted.size, store.chunk_bytes);
    if (wanted.hashes.len != count) return error.BadWanted;
    if (count == 1 and !wanted.hashes[0].eql(wanted.content)) return error.BadWanted;
    if (count == 0 and !wanted.content.eql(Digest.of(""))) return error.BadWanted;
}

/// How many bytes chunk `index` has.
pub fn chunk_length(store: *const Store, size: u64, index: u32) u64 {
    assert(size <= constants.store_file_bytes_max);
    assert(store.chunk_bytes > 0);
    assert(index < object.chunk_count(size, store.chunk_bytes));
    const start = @as(u64, index) * store.chunk_bytes;
    return @min(@as(u64, store.chunk_bytes), size - start);
}

fn partial_directory(store: *const Store, buffer: *PathBuf, id: Digest) [:0]const u8 {
    assert(store.root_len > 1);
    assert(id.bytes.len == constants.store_digest_bytes);
    const hex = id.hex();
    return store.path(buffer, &.{ "/partial/", &hex });
}

fn partial_chunk(store: *const Store, buffer: *PathBuf, id: Digest, index: u32) [:0]const u8 {
    assert(store.root_len > 1);
    assert(index < constants.store_chunks_max);
    const hex = id.hex();
    var name: [12]u8 = undefined;
    // Cannot fail: four digits at most.
    const text = std.fmt.bufPrint(&name, "{d}", .{index}) catch unreachable;
    return store.path(buffer, &.{ "/partial/", &hex, "/", text });
}

fn exists(store: *const Store, path: [:0]const u8) Error!bool {
    assert(path.len > 0);
    assert(store.root_len > 1);
    _ = store.fs.lstat(path) catch |err| {
        if (err == error.NotFound) return false;
        return error.StoreFailed;
    };
    return true;
}

/// Accepts chunk `index` of the wanted object if `bytes` are right, and assembles the object
/// when it is the last one missing. `io` is the copy buffer (`store_io_buffer_bytes`).
pub fn put_chunk(
    store: *Store,
    io: []u8,
    wanted: *const Wanted,
    index: u32,
    bytes: []const u8,
    failure: *Failure,
) Error!Progress {
    assert(io.len >= 4096);
    assert(@intFromPtr(failure) != 0);
    try check_wanted(store, wanted);
    try hold(store, failure);
    defer lock.release(store);
    if (index >= wanted.hashes.len) return error.IndexOutOfRange;
    if (bytes.len != chunk_length(store, wanted.size, index)) return error.WrongLength;
    if (!Digest.of(bytes).eql(wanted.hashes[index])) return error.HashMismatch;
    var final: PathBuf = undefined;
    if (try exists(store, store.object_path(&final, wanted.id))) {
        return .{
            .have = @intCast(wanted.hashes.len),
            .total = @intCast(wanted.hashes.len),
            .complete = true,
            .duplicate = true,
        };
    }
    var chunk_storage: PathBuf = undefined;
    const chunk_path = partial_chunk(store, &chunk_storage, wanted.id, index);
    const duplicate = try chunk_is_held(store, chunk_path, wanted.hashes[index]);
    if (!duplicate) try write_chunk(store, wanted.id, index, bytes, failure);
    var progress = try assemble_if_whole(store, io, wanted, failure);
    progress.duplicate = duplicate;
    return progress;
}

/// Assembles the object if every chunk is held. For an empty file, which has no chunk to put,
/// this is how the object is made.
pub fn finish(store: *Store, io: []u8, wanted: *const Wanted, failure: *Failure) Error!Progress {
    assert(io.len >= 4096);
    assert(@intFromPtr(failure) != 0);
    try check_wanted(store, wanted);
    try hold(store, failure);
    defer lock.release(store);
    var final: PathBuf = undefined;
    if (try exists(store, store.object_path(&final, wanted.id))) {
        const total: u32 = @intCast(wanted.hashes.len);
        return .{ .have = total, .total = total, .complete = true, .duplicate = true };
    }
    return assemble_if_whole(store, io, wanted, failure);
}

/// A held chunk file counts only if it still hashes right (a torn or damaged one is replaced).
fn chunk_is_held(store: *Store, path: [:0]const u8, hash: Digest) Error!bool {
    assert(path.len > 0);
    assert(hash.bytes.len == constants.store_digest_bytes);
    const fs = store.fs;
    const fd = fs.open_read(path) catch |err| {
        if (err == error.NotFound) return false;
        return error.StoreFailed;
    };
    defer fs.close(fd);
    var hasher = Hasher.init();
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = fs.read(fd, &buffer) catch return error.StoreFailed;
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
    return hasher.final().eql(hash);
}

fn write_chunk(
    store: *Store,
    id: Digest,
    index: u32,
    bytes: []const u8,
    failure: *Failure,
) Error!void {
    assert(index < constants.store_chunks_max);
    assert(bytes.len <= store.chunk_bytes);
    const fs = store.fs;
    var partial_root: PathBuf = undefined;
    fs.make_directory(store.path(&partial_root, &.{"/partial"}), true) catch |err| {
        return fail(fs, failure, err);
    };
    var directory: PathBuf = undefined;
    const directory_path = partial_directory(store, &directory, id);
    fs.make_directory(directory_path, true) catch |err| {
        return fail(fs, failure, err);
    };
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = partial_chunk(store, &final, id, index);
    fs.write_atomic(temporary_path, final_path, directory_path, bytes, 0o644, failure) catch {
        return error.StoreFailed;
    };
}

fn assemble_if_whole(
    store: *Store,
    io: []u8,
    wanted: *const Wanted,
    failure: *Failure,
) Error!Progress {
    assert(wanted.hashes.len <= constants.store_chunks_max);
    assert(io.len >= 4096);
    const total: u32 = @intCast(wanted.hashes.len);
    const have = try held_count(store, io, wanted.id, total);
    if (have < total) return .{
        .have = have,
        .total = total,
        .complete = false,
        .duplicate = false,
    };
    try assemble(store, io, wanted, failure);
    return .{ .have = total, .total = total, .complete = true, .duplicate = false };
}

/// How many chunk files `partial/<id>/` holds, by one listing of the directory.
fn held_count(store: *Store, io: []u8, id: Digest, total: u32) Error!u32 {
    assert(total <= constants.store_chunks_max);
    assert(io.len >= 4096);
    var directory: PathBuf = undefined;
    var names = @import("names.zig").NameList.init(io, constants.store_chunks_max + 8);
    store.fs.read_dir(partial_directory(store, &directory, id), names.visitor()) catch |err| {
        if (err == error.NotFound) return 0;
        return error.StoreFailed;
    };
    var held: u32 = 0;
    var at: u32 = 0;
    while (at < names.used) {
        const name = names.at(at);
        at += @intCast(1 + name.len);
        const index = std.fmt.parseInt(u32, name, 10) catch continue;
        if (index < total) held += 1;
    }
    return held;
}

fn assemble(store: *Store, io: []u8, wanted: *const Wanted, failure: *Failure) Error!void {
    assert(wanted.hashes.len <= constants.store_chunks_max);
    assert(store.root_len > 1);
    assert(io.len >= 4096);
    const fs = store.fs;
    generation.bump(store, failure) catch return error.StoreFailed;
    var shard: PathBuf = undefined;
    const shard_path = store.shard_path(&shard, "objects", wanted.id);
    object.ensure_directory(store, shard_path, failure) catch return error.StoreFailed;
    var temporary_storage: PathBuf = undefined;
    const temporary = store.tmp_path(&temporary_storage);
    build_file(store, io, wanted, temporary, failure) catch |err| {
        fs.unlink(temporary) catch {}; // Best effort: the failure being reported is the build's.
        return err;
    };
    // The list goes under its name before the object does, so an object always has its list.
    if (object.list_is_stored(wanted.size, store.chunk_bytes)) {
        write_list(store, io, shard_path, wanted, failure) catch |err| {
            fs.unlink(temporary) catch {}; // Same.
            return err;
        };
    }
    var final: PathBuf = undefined;
    fs.rename(temporary, store.object_path(&final, wanted.id)) catch |err| {
        fs.unlink(temporary) catch {}; // Same.
        return fail(fs, failure, err);
    };
    fs.sync_directory(shard_path) catch |err| {
        return fail(fs, failure, err);
    };
    store.objects_written += 1;
    store.bytes_written += wanted.size;
    discard(store, wanted);
}

fn write_list(
    store: *Store,
    io: []u8,
    shard_path: [:0]const u8,
    wanted: *const Wanted,
    failure: *Failure,
) Error!void {
    assert(wanted.hashes.len > 1);
    assert(shard_path.len > 0);
    const total = wanted.hashes.len * constants.store_digest_bytes;
    if (total > io.len) return error.BadWanted;
    for (wanted.hashes, 0..) |hash, index| @memcpy(io[index * 32 ..][0..32], &hash.bytes);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const target = store.chunks_path(&final, wanted.id);
    store.fs.write_atomic(temporary_path, target, shard_path, io[0..total], 0o644, failure) catch {
        return error.StoreFailed;
    };
}

/// The chunks in order into a new file, which must be the content; then the attributes.
fn build_file(
    store: *Store,
    io: []u8,
    wanted: *const Wanted,
    temporary: [:0]const u8,
    failure: *Failure,
) Error!void {
    assert(temporary.len > 0);
    assert(wanted.hashes.len <= constants.store_chunks_max);
    const fs = store.fs;
    const output = fs.create(temporary, 0o600) catch |err| {
        return fail(fs, failure, err);
    };
    defer fs.close(output);
    var whole = Hasher.init();
    var written: u64 = 0;
    for (0..wanted.hashes.len) |index| {
        var chunk_storage: PathBuf = undefined;
        const path = partial_chunk(store, &chunk_storage, wanted.id, @intCast(index));
        const input = fs.open_read(path) catch |err| {
            return fail(fs, failure, err);
        };
        defer fs.close(input);
        var chunk_hash = Hasher.init();
        var length: u64 = 0;
        while (true) {
            const count = fs.read(input, io) catch |err| {
                return fail(fs, failure, err);
            };
            if (count == 0) break;
            whole.update(io[0..count]);
            chunk_hash.update(io[0..count]);
            length += count;
            fs.write_all(output, io[0..count]) catch |err| {
                return fail(fs, failure, err);
            };
        }
        // A held chunk was checked when it was written; a damaged file is caught here.
        if (length != chunk_length(
            store,
            wanted.size,
            @intCast(index),
        )) return discard_and_refuse(store, wanted);
        if (!chunk_hash.final().eql(wanted.hashes[index])) return discard_and_refuse(store, wanted);
        written += length;
    }
    if (written != wanted.size or !whole.final().eql(wanted.content)) {
        return discard_and_refuse(store, wanted);
    }
    object.apply(fs, output, wanted.attrs, failure) catch return error.StoreFailed;
}

fn discard_and_refuse(store: *Store, wanted: *const Wanted) Error {
    assert(store.root_len > 1);
    assert(wanted.hashes.len <= constants.store_chunks_max);
    discard(store, wanted);
    return error.ContentMismatch;
}

/// Removes the held chunks of an object, and their directory. Best effort: what stays is only
/// disk space, and the next put of the object replaces it.
pub fn discard(store: *Store, wanted: *const Wanted) void {
    assert(store.root_len > 1);
    assert(wanted.hashes.len <= constants.store_chunks_max);
    const fs = store.fs;
    for (0..wanted.hashes.len) |index| {
        var path: PathBuf = undefined;
        fs.unlink(partial_chunk(store, &path, wanted.id, @intCast(index))) catch {}; // Best effort.
    }
    var directory: PathBuf = undefined;
    fs.remove_directory(partial_directory(store, &directory, wanted.id)) catch {}; // Same.
}
