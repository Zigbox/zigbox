//! A build step's cache entry (docs/briefs/M7-build.md, "The cache"): `build/cache/<key hex>` in
//! the store, naming the output tree a step made and keeping the preimage of its key.
//!
//! The file (binary, little-endian; `render` writes exactly this and `parse` accepts nothing
//! else):
//!
//!   "zbx-build-cache\0"   16 bytes, the magic
//!   version               u32, 1
//!   tree                  32 bytes, the output tree's digest
//!   preimage length       u32, at most `build_key_preimage_bytes_max`
//!   preimage              the bytes `key.Key.preimage()` holds, so that M8 can write
//!                         provenance without rebuilding
//!
//! and nothing after. The preimage must hash to the entry's name; an entry under another name
//! than its preimage's hash is damage, not a different entry.
//!
//! **The cache directory is the root** (owner, 2026-11-02): gc keeps the tree of every entry that
//! parses (`gc.zig`), and there is no root record of a new kind. An older gc does not know the
//! directory and may collect those trees; that costs a rebuild, not correctness, because a hit
//! checks that its tree is whole in the store and an entry whose tree is missing or partial is a
//! miss.
//!
//! **A malformed entry is a miss, not an error.** The step then runs and `record` replaces the
//! entry. The result says which kind of miss it was so a report can tell a first build from a
//! damaged cache. An entry written by a newer zbx (`newer`) is a miss too, and is replaced the
//! same way; a newer zbx reads the older entry that results.
//!
//! **Two builds racing on one key** both succeed. `record` first looks the key up and, if a
//! whole entry is there, keeps it and returns its tree (the first writer wins, and the loser's
//! dependents are keyed by the winner's output). Two writers that both find nothing both rename;
//! the rename replaces, each entry is whole, and the later one stays.
//!
//! No state of its own: the caller owns the store and the `Workspace`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const generation = @import("../store/generation.zig");
const host_mod = @import("../host.zig");
const key_mod = @import("key.zig");
const layout = @import("../store/layout.zig");
const sets = @import("../store/sets.zig");
const tree = @import("../store/tree.zig");
const walk = @import("../store/walk.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const directory_name = layout.build_cache_directory;
pub const magic = "zbx-build-cache\x00";
pub const entry_version: u32 = 1;

const header_bytes: u32 = magic.len + 4 + constants.store_digest_bytes + 4;
const tree_at: u32 = magic.len + 4;

/// The stack of a tree walk and the table of trees seen: the same room gc gives a walk.
const stack_digests: u32 = 2 * constants.store_dir_entries_max;
const visited_bytes: u32 = 64 * 1024;

comptime {
    assert(header_bytes + constants.build_key_preimage_bytes_max <=
        constants.build_cache_entry_bytes_max);
    assert(magic.len == 16);
    assert(entry_version > 0);
    assert(constants.build_cache_entry_bytes_max <= constants.store_tree_bytes_max);
    // The name of an entry is a digest in hex, and `Store.path` holds the longest.
    assert(constants.store_digest_hex_bytes + directory_name.len < constants.path_bytes_max);
}

/// What an entry holds.
pub const Entry = struct {
    tree: Digest,
    /// Points into the bytes that were parsed.
    preimage: []const u8,
};

pub const ParseResult = enum { ok, malformed, newer };

/// The entry's bytes, in `buffer`. `preimage` is a key's, so it hashes to the entry's name.
pub fn render(
    buffer: *[constants.build_cache_entry_bytes_max]u8,
    output: Digest,
    preimage: []const u8,
) []const u8 {
    assert(preimage.len >= key_mod.magic.len + 4);
    assert(preimage.len <= constants.build_key_preimage_bytes_max);
    assert(std.mem.startsWith(u8, preimage, key_mod.magic));
    @memcpy(buffer[0..magic.len], magic);
    std.mem.writeInt(u32, buffer[magic.len..][0..4], entry_version, .little);
    @memcpy(buffer[tree_at..][0..constants.store_digest_bytes], &output.bytes);
    const length_at = tree_at + constants.store_digest_bytes;
    std.mem.writeInt(u32, buffer[length_at..][0..4], @intCast(preimage.len), .little);
    @memcpy(buffer[header_bytes..][0..preimage.len], preimage);
    const total = header_bytes + preimage.len;
    assert(total <= buffer.len);
    return buffer[0..total];
}

/// Reads an entry that was found under `name`. Accepts only what `render` writes: the magic, a
/// known version, a preimage of a length `render` allows that starts with a key's magic and
/// hashes to `name`, and no byte after it.
pub fn parse(bytes: []const u8, name: Digest, entry: *Entry) ParseResult {
    assert(bytes.len <= constants.build_cache_entry_bytes_max);
    assert(@intFromPtr(entry) != 0);
    if (bytes.len < magic.len + 4) return .malformed;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return .malformed;
    const version = std.mem.readInt(u32, bytes[magic.len..][0..4], .little);
    if (version > entry_version) return .newer;
    if (version != entry_version) return .malformed;
    if (bytes.len < header_bytes) return .malformed;
    const length_at = tree_at + constants.store_digest_bytes;
    const length = std.mem.readInt(u32, bytes[length_at..][0..4], .little);
    if (length > constants.build_key_preimage_bytes_max) return .malformed;
    if (length < key_mod.magic.len + 4) return .malformed;
    if (bytes.len - header_bytes != length) return .malformed;
    const preimage = bytes[header_bytes..];
    if (!std.mem.startsWith(u8, preimage, key_mod.magic)) return .malformed;
    if (!Digest.of(preimage).eql(name)) return .malformed;
    entry.tree = .{ .bytes = bytes[tree_at..][0..constants.store_digest_bytes].* };
    entry.preimage = preimage;
    return .ok;
}

// ---- In the store ----------------------------------------------------------------------------

/// The caller's memory for `lookup` and `record`.
pub const Workspace = struct {
    entry: [constants.build_cache_entry_bytes_max]u8,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    stack: [stack_digests]Digest,
    visited: [visited_bytes]u8 align(8),
};

/// Why a lookup found nothing.
pub const Miss = enum {
    /// No entry for the key: a step that has not been built.
    absent,
    /// The entry does not parse, or its name is not its preimage's hash.
    malformed,
    /// Written by a newer zbx.
    newer,
    /// The tree the entry names is missing or partial (an older gc collected it).
    tree_incomplete,
};

pub const Lookup = union(enum) {
    /// The output tree, whole in the store.
    hit: Digest,
    miss: Miss,
};

/// What stopped a lookup or a record: a store that cannot be read or written, or a tree that
/// cannot be walked (as opposed to one that is missing, which is a miss).
pub const Failure = union(enum) {
    io: struct { err: host_mod.Error, errno: u16, step: []const u8 },
    tree: walk.Failure,
};

pub const Error = error{Failed};

fn io_failure(store: *const Store, failure: *Failure, step: []const u8, err: host_mod.Error) Error {
    assert(step.len > 0);
    assert(@intFromPtr(failure) != 0);
    failure.* = .{ .io = .{ .err = err, .errno = store.fs.last_errno(), .step = step } };
    return error.Failed;
}

/// The visitor that checks every file a tree names has its object in the store.
const Present = struct {
    store: *const Store,
    missing: bool,
    /// The first read error that was not "not found", if any.
    unreadable: ?struct { err: host_mod.Error, errno: u16 },

    pub fn entry(present: *Present, found: *const tree.Entry) void {
        assert(@intFromPtr(present.store) != 0);
        assert(found.name.len > 0);
        if (found.kind != .file) return;
        if (present.missing) return;
        if (present.unreadable != null) return;
        var path: PathBuf = undefined;
        _ = present.store.fs.lstat(present.store.object_path(&path, found.object)) catch |err| {
            if (err == error.NotFound) {
                present.missing = true;
            } else {
                present.unreadable = .{ .err = err, .errno = present.store.fs.last_errno() };
            }
        };
    }
};

/// True if `output` and every tree and file object below it are in the store. A tree that is
/// missing or does not decode is not whole (false); one that cannot be read at all is a failure.
fn tree_whole(
    store: *const Store,
    ws: *Workspace,
    output: Digest,
    failure: *Failure,
) Error!bool {
    assert(ws.tree_buffer.len >= constants.store_tree_bytes_max);
    assert(ws.stack.len > 0);
    var visited = sets.KeySet.init(&ws.visited);
    var present: Present = .{ .store = store, .missing = false, .unreadable = null };
    var failed: walk.Failure = undefined;
    walk.walk(store, &ws.tree_buffer, &ws.stack, &visited, output, &present, &failed) catch {
        switch (failed.kind) {
            .missing, .damaged => return false,
            .unreadable, .too_many_entries, .stack_full => {
                failure.* = .{ .tree = failed };
                return error.Failed;
            },
        }
    };
    if (present.unreadable) |unreadable| {
        failure.* = .{ .io = .{
            .err = unreadable.err,
            .errno = unreadable.errno,
            .step = "checking the files of a cached tree",
        } };
        return error.Failed;
    }
    return !present.missing;
}

/// The entry for `key`: a hit only if the entry is whole, is this key's, and its tree is whole
/// in the store. Every other state is a miss that says why, never an error.
pub fn lookup(
    store: *const Store,
    ws: *Workspace,
    key: *const key_mod.Key,
    failure: *Failure,
) Error!Lookup {
    assert(@intFromPtr(ws) != 0);
    assert(key.len <= constants.build_key_preimage_bytes_max);
    var path: PathBuf = undefined;
    const where = store.build_cache_path(&path, key.digest);
    const bytes = store.fs.read_whole(where, &ws.entry) catch |err| {
        if (err == error.NotFound) return .{ .miss = .absent };
        if (err == error.FileTooLarge) return .{ .miss = .malformed };
        return io_failure(store, failure, "reading a build cache entry", err);
    };
    var entry: Entry = undefined;
    switch (parse(bytes, key.digest, &entry)) {
        .ok => {},
        .malformed => return .{ .miss = .malformed },
        .newer => return .{ .miss = .newer },
    }
    if (!std.mem.eql(u8, entry.preimage, key.preimage())) return .{ .miss = .malformed };
    const output = entry.tree;
    if (!try tree_whole(store, ws, output, failure)) return .{ .miss = .tree_incomplete };
    return .{ .hit = output };
}

/// Writes the entry saying that the key's step made `output`, and returns the tree the entry
/// names: `output`, unless a whole entry for the key was already there (then that one's tree,
/// which the caller uses from here on). The caller holds the store lock, as every write does.
pub fn record(
    store: *Store,
    ws: *Workspace,
    key: *const key_mod.Key,
    output: Digest,
    failure: *Failure,
) Error!Digest {
    assert(store.lock_depth > 0);
    assert(key.len >= key_mod.magic.len + 4);
    switch (try lookup(store, ws, key, failure)) {
        .hit => |existing| return existing,
        .miss => {},
    }
    var raised: fs_mod.Failure = undefined;
    generation.bump(store, &raised) catch {
        const step = "raising the generation";
        failure.* = .{ .io = .{ .err = raised.err, .errno = raised.errno, .step = step } };
        return error.Failed;
    };
    try write_entry(store, ws, key, output, failure);
    return output;
}

fn write_entry(
    store: *Store,
    ws: *Workspace,
    key: *const key_mod.Key,
    output: Digest,
    failure: *Failure,
) Error!void {
    assert(key.len <= constants.build_key_preimage_bytes_max);
    assert(ws.entry.len == constants.build_cache_entry_bytes_max);
    var parent: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const parent_path = store.directory_path(&parent, layout.build_directory);
    const directory_path = store.directory_path(&directory, layout.build_cache_directory);
    inline for (.{ parent_path, directory_path }) |made| {
        store.fs.make_directory(made, true) catch |err| {
            return io_failure(store, failure, "making the build cache directory", err);
        };
    }
    const text = render(&ws.entry, output, key.preimage());
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = store.build_cache_path(&final, key.digest);
    var noted: fs_mod.Failure = undefined;
    store.fs.write_atomic(temporary_path, final_path, directory_path, text, 0o644, &noted) catch {
        failure.* = .{ .io = .{
            .err = noted.err,
            .errno = noted.errno,
            .step = "writing a build cache entry",
        } };
        return error.Failed;
    };
}
