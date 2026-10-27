//! File objects: one per (content, metadata) pair, stored whole as a regular file whose bytes are
//! the file's content and whose mode, owner and attributes are the real ones, so that a
//! container's lower directory can be a hardlink farm of them.
//!
//! The object's id is the BLAKE3 hash of a canonical header, not of the content:
//!
//!   header = "zbx-file" 0x01  content:digest  mode:u16  uid:u32  gid:u32  xattrs
//!
//! (little-endian; `xattrs` is the canonical section of `xattrs.zig`). Two files with the same
//! bytes and the same metadata are one object; the same bytes with another mode or owner are
//! another. The content hash is the hash of the bytes alone, and it is what a chunk list ends in.
//!
//! Chunk lists: every object has the BLAKE3 hashes of its content in chunks of `chunk_bytes`
//! (the last may be shorter). A file of at most one chunk has the one hash that is its content
//! hash (and an empty file has none), so the list is implied and not stored; a longer file has
//! `<id>.chunks` beside it: the hashes, 32 bytes each, nothing else. The library hands the list
//! to Zigcube (`chunks`), which fetches and checks pieces by hash.
//!
//! Writing is atomic. The bytes go to a new file in `tmp/`, with the attributes, flushed; then
//! one rename puts it under its id. A crash leaves a file in `tmp/` or nothing, never a part of
//! an object under its id. The chunk list is renamed into place before the object, so an object
//! that exists always has its list.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const Hasher = digest_mod.Hasher;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const header_magic = "zbx-file\x01";

/// A file's metadata as the store keeps it.
pub const Attrs = struct {
    mode: u16,
    uid: u32,
    gid: u32,
    /// The canonical attribute section.
    xattrs: []const u8,
};

/// The object id of a file with this content hash and these attributes.
pub fn object_id(content: Digest, attrs: Attrs) Digest {
    assert(attrs.mode <= 0o7777);
    assert(xattrs.validate(attrs.xattrs) == .none);
    var hasher = Hasher.init();
    hasher.update(header_magic);
    hasher.update(&content.bytes);
    var fixed: [10]u8 = undefined;
    std.mem.writeInt(u16, fixed[0..2], attrs.mode, .little);
    std.mem.writeInt(u32, fixed[2..6], attrs.uid, .little);
    std.mem.writeInt(u32, fixed[6..10], attrs.gid, .little);
    hasher.update(&fixed);
    hasher.update(attrs.xattrs);
    return hasher.final();
}

/// How many chunks a file of `size` bytes has.
pub fn chunk_count(size: u64, chunk_bytes: u32) u32 {
    assert(chunk_bytes > 0);
    assert(size <= @as(u64, chunk_bytes) * constants.store_chunks_max);
    const count: u64 = (size + chunk_bytes - 1) / chunk_bytes;
    assert(count <= constants.store_chunks_max);
    return @intCast(count);
}

/// A chunk list is stored only when it is not implied by the content hash.
pub fn list_is_stored(size: u64, chunk_bytes: u32) bool {
    assert(chunk_bytes > 0);
    assert(size <= @as(u64, chunk_bytes) * constants.store_chunks_max);
    return chunk_count(size, chunk_bytes) > 1;
}

/// What the importer learned about a file's bytes in its first pass.
pub const Content = struct {
    size: u64,
    hash: Digest,
    /// The hashes of the chunks, `chunk_count` of them.
    chunks: []const Digest,
};

/// A failure while putting an object, and where it came from: the file being imported, the
/// store, or the file changing between the first read and the copy.
pub const PutError = error{ SourceFailed, StoreFailed, Changed };

pub const Failure = fs_mod.Failure;

/// Splits a stream into chunks and hashes it whole and by chunk, as the importer's first pass
/// and the copy's check both need.
pub const Reader = struct {
    whole: Hasher,
    chunk: Hasher,
    in_chunk: u32,
    chunk_bytes: u32,
    size: u64,
    count: u32,

    pub fn init(chunk_bytes: u32) Reader {
        assert(chunk_bytes <= constants.store_file_bytes_max);
        assert(chunk_bytes > 0);
        return .{
            .whole = Hasher.init(),
            .chunk = Hasher.init(),
            .in_chunk = 0,
            .chunk_bytes = chunk_bytes,
            .size = 0,
            .count = 0,
        };
    }

    /// Takes the next bytes of the file. Stores each finished chunk's hash in `chunks`. False if
    /// the file is longer than the store holds.
    pub fn update(reader: *Reader, bytes: []const u8, chunks: []Digest) bool {
        assert(reader.in_chunk < reader.chunk_bytes);
        assert(bytes.len > 0);
        if (reader.size + bytes.len > @as(u64, reader.chunk_bytes) * constants.store_chunks_max) {
            return false;
        }
        reader.whole.update(bytes);
        reader.size += bytes.len;
        var rest = bytes;
        while (rest.len > 0) {
            const room = reader.chunk_bytes - reader.in_chunk;
            const take = @min(room, rest.len);
            reader.chunk.update(rest[0..take]);
            reader.in_chunk += @intCast(take);
            rest = rest[take..];
            if (reader.in_chunk == reader.chunk_bytes) reader.close_chunk(chunks);
        }
        return true;
    }

    fn close_chunk(reader: *Reader, chunks: []Digest) void {
        assert(reader.count < chunks.len);
        assert(reader.in_chunk > 0);
        chunks[reader.count] = reader.chunk.final();
        reader.count += 1;
        reader.chunk = Hasher.init();
        reader.in_chunk = 0;
    }

    /// The end of the file: closes the last chunk and returns the content hash.
    pub fn finish(reader: *Reader, chunks: []Digest) Digest {
        assert(reader.in_chunk <= reader.chunk_bytes);
        if (reader.in_chunk > 0) reader.close_chunk(chunks);
        assert(reader.count == chunk_count(reader.size, reader.chunk_bytes));
        return reader.whole.final();
    }
};

fn fail(failure: *Failure, fs: fs_mod.Fs, err: host_mod.Error) void {
    assert(@intFromPtr(failure) != 0);
    assert(@intFromPtr(fs.vtable) != 0);
    failure.* = .{ .err = err, .errno = fs.last_errno() };
}

/// Puts the file at `source` into the store under `id`, if it is not there. The source must
/// still be what `content` says; if it changed, `Changed`. `io` is the copy buffer.
pub fn put(
    store: *Store,
    io: []u8,
    scratch: []Digest,
    source: [:0]const u8,
    content: *const Content,
    attrs: Attrs,
    id: Digest,
    failure: *Failure,
) PutError!void {
    assert(content.chunks.len == chunk_count(content.size, store.chunk_bytes));
    assert(object_id(content.hash, attrs).eql(id));
    const fs = store.fs;
    var shard: PathBuf = undefined;
    var final: PathBuf = undefined;
    const shard_path = store.shard_path(&shard, "objects", id);
    ensure_directory(store, shard_path, failure) catch return error.StoreFailed;
    if (list_is_stored(content.size, store.chunk_bytes)) {
        put_chunk_list(store, io, shard_path, content, id, failure) catch
            return error.StoreFailed;
    }
    var temporary_storage: PathBuf = undefined;
    const temporary = store.tmp_path(&temporary_storage);
    copy_to(store, io, scratch, source, temporary, content, attrs, failure) catch |err| {
        fs.unlink(temporary) catch {}; // Best effort: the failure being reported is the copy's.
        return err;
    };
    fs.rename(temporary, store.object_path(&final, id)) catch |err| {
        fail(failure, fs, err);
        fs.unlink(temporary) catch {}; // Same.
        return error.StoreFailed;
    };
    fs.sync_directory(shard_path) catch |err| {
        fail(failure, fs, err);
        return error.StoreFailed;
    };
    store.objects_written += 1;
    store.bytes_written += content.size;
}

/// Makes a shard directory, and flushes the directory above it if it was new.
fn ensure_directory(store: *Store, path: [:0]const u8, failure: *Failure) host_mod.Error!void {
    assert(path.len > 0);
    assert(std.mem.indexOfScalar(u8, path, '/') != null);
    const fs = store.fs;
    if (fs.lstat(path)) |_| return else |err| {
        if (err != error.NotFound) {
            fail(failure, fs, err);
            return err;
        }
    }
    fs.make_directory(path, true) catch |err| {
        fail(failure, fs, err);
        return err;
    };
    const parent = path[0..std.mem.lastIndexOfScalar(u8, path, '/').?];
    var parent_storage: PathBuf = undefined;
    parent_storage.set(&.{parent}) catch unreachable; // A prefix of a path that fit.
    fs.sync_directory(parent_storage.text()) catch |err| {
        fail(failure, fs, err);
        return err;
    };
}

fn put_chunk_list(
    store: *Store,
    io: []u8,
    shard_path: [:0]const u8,
    content: *const Content,
    id: Digest,
    failure: *Failure,
) host_mod.Error!void {
    assert(content.chunks.len > 1);
    const fs = store.fs;
    // The io buffer is free until the copy starts, and holds the longest list.
    const total = content.chunks.len * constants.store_digest_bytes;
    assert(total <= io.len);
    for (content.chunks, 0..) |chunk, index| {
        @memcpy(io[index * 32 ..][0..32], &chunk.bytes);
    }
    var temporary_storage: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary = store.tmp_path(&temporary_storage);
    const target = store.chunks_path(&final, id);
    try fs.write_atomic(temporary, target, shard_path, io[0..total], 0o644, failure);
}

/// Copies the source into a new file with the attributes, flushed. Reads the source a second
/// time and checks it against `content`.
fn copy_to(
    store: *Store,
    io: []u8,
    scratch: []Digest,
    source: [:0]const u8,
    temporary: [:0]const u8,
    content: *const Content,
    attrs: Attrs,
    failure: *Failure,
) PutError!void {
    const fs = store.fs;
    const input = fs.open_read(source) catch |err| {
        fail(failure, fs, err);
        return error.SourceFailed;
    };
    defer fs.close(input);
    const output = fs.create(temporary, 0o600) catch |err| {
        fail(failure, fs, err);
        return error.StoreFailed;
    };
    defer fs.close(output);
    assert(scratch.len >= content.chunks.len);
    var reader = Reader.init(store.chunk_bytes);
    var calls: u64 = 0;
    while (true) {
        calls += 1;
        assert(calls <= content.size / io.len + constants.store_chunks_max + 2);
        const count = fs.read(input, io) catch |err| {
            fail(failure, fs, err);
            return error.SourceFailed;
        };
        if (count == 0) break;
        if (!reader.update(io[0..count], scratch)) return error.Changed;
        if (reader.size > content.size) return error.Changed;
        fs.write_all(output, io[0..count]) catch |err| {
            fail(failure, fs, err);
            return error.StoreFailed;
        };
    }
    if (reader.size != content.size) return error.Changed;
    if (!reader.finish(scratch).eql(content.hash)) return error.Changed;
    apply(fs, output, attrs, failure) catch return error.StoreFailed;
}

/// The attributes, in the order the kernel needs: a change of owner clears setuid and the file
/// capability, so the owner first, then the mode, then the attributes.
fn apply(fs: fs_mod.Fs, fd: fs_mod.Fd, attrs: Attrs, failure: *Failure) host_mod.Error!void {
    assert(attrs.mode <= 0o7777);
    assert(xattrs.validate(attrs.xattrs) == .none);
    fs.set_owner(fd, attrs.uid, attrs.gid) catch |err| {
        fail(failure, fs, err);
        return err;
    };
    fs.set_mode(fd, attrs.mode) catch |err| {
        fail(failure, fs, err);
        return err;
    };
    var iterator = xattrs.Iterator.init(attrs.xattrs);
    while (iterator.next()) |item| {
        var name: [constants.store_xattr_name_bytes_max + 1]u8 = undefined;
        @memcpy(name[0..item.name.len], item.name);
        name[item.name.len] = 0;
        fs.set_xattr(fd, name[0..item.name.len :0], item.value) catch |err| {
            fail(failure, fs, err);
            return err;
        };
    }
    fs.set_mtime(fd, constants.store_mtime_seconds) catch |err| {
        fail(failure, fs, err);
        return err;
    };
    fs.fsync(fd) catch |err| {
        fail(failure, fs, err);
        return err;
    };
}

/// The chunk hashes of an object that has them stored; `Unsupported`-free: an object of one
/// chunk or none has no list (the caller derives it from the tree entry).
pub fn read_chunk_list(
    store: *const Store,
    id: Digest,
    buffer: []u8,
    out: []Digest,
) host_mod.Error![]const Digest {
    assert(out.len <= constants.store_chunks_max);
    assert(buffer.len >= out.len * constants.store_digest_bytes);
    var path: PathBuf = undefined;
    const text = try store.fs.read_whole(store.chunks_path(&path, id), buffer);
    if (text.len % constants.store_digest_bytes != 0) return error.IoFailed;
    const count = text.len / constants.store_digest_bytes;
    if (count > out.len) return error.FileTooLarge;
    for (0..count) |index| out[index] = .{ .bytes = text[index * 32 ..][0..32].* };
    return out[0..count];
}

/// The chunk hashes of the object `id`, whichever way they are kept: the stored list of a long
/// object, or the one hash (or none) of a short one, found by reading it. `io` is the read
/// buffer and `out` has room for `store_chunks_max` hashes.
pub fn chunk_hashes(
    store: *const Store,
    id: Digest,
    io: []u8,
    out: []Digest,
) host_mod.Error![]const Digest {
    assert(io.len >= constants.store_chunks_max * constants.store_digest_bytes);
    assert(out.len >= constants.store_chunks_max);
    const fs = store.fs;
    var list_path: PathBuf = undefined;
    if (fs.lstat(store.chunks_path(&list_path, id))) |_| {
        return read_chunk_list(store, id, io, out);
    } else |err| {
        if (err != error.NotFound) return err;
    }
    var path: PathBuf = undefined;
    const fd = try fs.open_read(store.object_path(&path, id));
    defer fs.close(fd);
    var reader = Reader.init(store.chunk_bytes);
    while (true) {
        const count = try fs.read(fd, io[0..constants.store_io_buffer_bytes]);
        if (count == 0) break;
        // An object past one chunk without its list is damaged: it has more than one hash. (One
        // chunk exactly full has closed its hash and is fine, unless more bytes follow.)
        if (!reader.update(io[0..count], out)) return error.FileTooLarge;
        if (reader.size > reader.chunk_bytes) return error.IoFailed;
    }
    _ = reader.finish(out);
    return out[0..reader.count];
}

const testing = std.testing;

test "the id depends on the content and on every attribute, and on nothing else" {
    // Goal: the brief's identity rule. Method: one file, then each field changed in turn.
    const content = Digest.of("bytes");
    const base: Attrs = .{ .mode = 0o644, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
    const id = object_id(content, base);
    try testing.expect(id.eql(object_id(content, base)));
    try testing.expect(!id.eql(object_id(Digest.of("other"), base)));
    var changed = base;
    changed.mode = 0o755;
    try testing.expect(!id.eql(object_id(content, changed)));
    changed = base;
    changed.uid = 1;
    try testing.expect(!id.eql(object_id(content, changed)));
    changed = base;
    changed.gid = 1;
    try testing.expect(!id.eql(object_id(content, changed)));
    const with_attribute = [_]u8{ 1, 1, 0, 'k', 1, 0, 'v' };
    changed = base;
    changed.xattrs = &with_attribute;
    try testing.expect(!id.eql(object_id(content, changed)));
}

test "chunk counts: none for nothing, one up to a chunk, then one more per chunk" {
    // Goal: the edges of the chunk list. A list is stored only when it is not implied.
    try testing.expectEqual(@as(u32, 0), chunk_count(0, 10));
    try testing.expectEqual(@as(u32, 1), chunk_count(1, 10));
    try testing.expectEqual(@as(u32, 1), chunk_count(10, 10));
    try testing.expectEqual(@as(u32, 2), chunk_count(11, 10));
    try testing.expectEqual(@as(u32, 3), chunk_count(30, 10));
    try testing.expect(!list_is_stored(10, 10));
    try testing.expect(list_is_stored(11, 10));
}

test "the reader hashes chunks the same however the bytes arrive" {
    // Goal: chunk hashes do not depend on read sizes. Method: 25 bytes in chunks of 10, fed in
    // one piece, byte by byte and in uneven pieces; each chunk's hash is the hash of its bytes.
    const data = "abcdefghijklmnopqrstuvwxy";
    const ones: [25]usize = @splat(1);
    const feeds = [_][]const usize{ &.{25}, &ones, &.{ 7, 9, 5, 4 } };
    for (feeds) |feed| {
        var chunks: [3]Digest = undefined;
        var reader = Reader.init(10);
        var at: usize = 0;
        for (feed) |length| {
            try testing.expect(reader.update(data[at..][0..length], &chunks));
            at += length;
        }
        const whole = reader.finish(&chunks);
        try testing.expect(whole.eql(Digest.of(data)));
        try testing.expectEqual(@as(u32, 3), reader.count);
        try testing.expect(chunks[0].eql(Digest.of(data[0..10])));
        try testing.expect(chunks[1].eql(Digest.of(data[10..20])));
        try testing.expect(chunks[2].eql(Digest.of(data[20..25])));
    }
}
