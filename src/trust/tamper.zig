//! The tamper check (docs/briefs/M8-trust.md, "The tamper check"): before a run under a policy
//! file starts, every file object the tree reaches is hashed again as `zbx store verify` does
//! (`verify.check_object_alone`), so a signature over the tree means something. It runs in the
//! store's child, where the objects owned by container ids can be read.
//!
//! The first checked run of a tree hashes all of it and writes `trust/verified/<tree hex>`: one
//! entry per object, `(object id, inode, size, ctime_ns)`, sorted by id. Later runs `lstat`
//! each object and hash again only one whose four fields are not all equal. The record is a
//! cache and never a trust source: a record that is damaged, newer or unsorted is ignored and
//! rewritten, and `ctime_ns == 0` (the file system gives none) is never trusted. A tree with
//! more objects than `trust_verified_entries_max` is hashed whole and writes no record.
//!
//! A file changed between the check and `execve` is not seen (the brief's accepted limit).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const verify = @import("../store/verify.zig");
const walk = @import("../store/walk.zig");
const diagnose = @import("diagnose.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Error = error{Failed};

const magic = "zbxverif";
const version: u32 = 1;
const header_bytes: u32 = 16;
const entry_bytes = constants.trust_verified_entry_bytes;
const entries_cap = constants.trust_verified_entries_max;

pub const directory_name = "trust/verified";

comptime {
    assert(32 + 3 * 8 == entry_bytes);
    assert(constants.trust_verified_file_bytes_max <= constants.store_tree_bytes_max);
}

const Frame = struct { digest: Digest, path_at: u32, path_len: u16 };

/// The caller's memory, about 10 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    /// The ids of the tree's file objects, then sorted and without repeats.
    ids: [entries_cap]Digest,
    /// The record as read, and the record to write.
    old: [constants.trust_verified_file_bytes_max]u8,
    fresh: [constants.trust_verified_file_bytes_max]u8,
    /// The path search that names a damaged object.
    frames: [4096]Frame,
    frame_paths: [1 << 18]u8,
    current: [constants.path_bytes_max + 1]u8,
};

/// The rest of the memory a check uses, lent by the caller: it is idle during a run.
pub const Lent = struct {
    scratch: *verify.Scratch,
    tree_buffer: []u8,
    stack: []Digest,
};

const Found = struct {
    id: Digest,
    what: diagnose.Tampered,
    errno: u16,
};

fn found_of(id: Digest, damage: verify.ObjectDamage) Found {
    assert(id.bytes.len == constants.store_digest_bytes);
    assert(damage.errno < 4096);
    if (damage.kind == .unreadable) {
        const missing = damage.errno != 0 and
            host_mod.error_for_errno(damage.errno) == error.NotFound;
        if (missing) return .{ .id = id, .what = .missing, .errno = 0 };
        return .{ .id = id, .what = .unreadable, .errno = damage.errno };
    }
    return .{ .id = id, .what = .bytes, .errno = 0 };
}

/// Hashes one object against its id, as `zbx store verify` does.
fn check_one(store: *const Store, scratch: *verify.Scratch, id: Digest) ?Found {
    assert(store.root_len > 1);
    const fs = store.fs;
    var path: PathBuf = undefined;
    var has_list = true;
    _ = fs.lstat(store.chunks_path(&path, id)) catch |err| {
        if (err != error.NotFound) {
            return .{ .id = id, .what = .unreadable, .errno = fs.last_errno() };
        }
        has_list = false;
    };
    var bytes: u64 = 0;
    const damage = verify.check_object_alone(store, scratch, id, has_list, &bytes) orelse {
        return null;
    };
    return found_of(id, damage);
}

fn id_less(_: void, first: Digest, second: Digest) bool {
    assert(first.bytes.len == constants.store_digest_bytes);
    assert(second.bytes.len == constants.store_digest_bytes);
    return std.mem.order(u8, &first.bytes, &second.bytes) == .lt;
}

/// Sorts `ids` and removes repeats; the new length.
fn compact(ids: []Digest) u32 {
    assert(ids.len <= entries_cap);
    std.mem.sortUnstable(Digest, ids, {}, id_less);
    var length: u32 = 0;
    for (ids) |id| {
        if (length > 0 and ids[length - 1].eql(id)) continue;
        ids[length] = id;
        length += 1;
    }
    assert(length <= ids.len);
    return length;
}

const Collector = struct {
    store: *const Store,
    ws: *Workspace,
    scratch: *verify.Scratch,
    count: u32,
    /// Some object was checked without room to record it: no record is written.
    partial: bool,
    found: ?Found,

    pub fn object(collector: *Collector, ref: *const walk.ObjectRef) void {
        assert(collector.count <= entries_cap);
        if (collector.found != null) return;
        if (collector.count == entries_cap) {
            collector.count = compact(collector.ws.ids[0..collector.count]);
        }
        if (collector.count == entries_cap) {
            collector.partial = true;
            collector.found = check_one(collector.store, collector.scratch, ref.id);
            return;
        }
        collector.ws.ids[collector.count] = ref.id;
        collector.count += 1;
    }
};

/// Checks the files of `root`'s tree. With `always` no record is believed. A refusal is E0907
/// in `diag`. The caller has found the tree in the store.
pub fn check(
    store: *Store,
    ws: *Workspace,
    lent: Lent,
    root: Digest,
    always: bool,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(lent.tree_buffer.len >= constants.store_tree_bytes_max);
    var collector: Collector = .{
        .store = store,
        .ws = ws,
        .scratch = lent.scratch,
        .count = 0,
        .partial = false,
        .found = null,
    };
    var failure: walk.Failure = undefined;
    walk.objects(
        store,
        lent.tree_buffer,
        lent.stack,
        null,
        root,
        &collector,
        constants.store_walk_entries_max,
        &failure,
    ) catch return walk_failed(diag, &failure);
    if (collector.found) |found| return refuse(store, ws, lent, root, found, diag);
    const count = compact(ws.ids[0..collector.count]);
    const old = if (always) 0 else load(store, ws, root);
    var fresh_count: u32 = 0;
    var cursor: u32 = 0;
    const fs = store.fs;
    for (ws.ids[0..count]) |id| {
        var path: PathBuf = undefined;
        const stat = fs.lstat(store.object_path(&path, id)) catch {
            const found: Found = if (fs.last_errno() != 0 and
                host_mod.error_for_errno(fs.last_errno()) == error.NotFound)
                .{ .id = id, .what = .missing, .errno = 0 }
            else
                .{ .id = id, .what = .unreadable, .errno = fs.last_errno() };
            return refuse(store, ws, lent, root, found, diag);
        };
        while (cursor < old and std.mem.order(
            u8,
            ws.old[entry_at(cursor)..][0..32],
            &id.bytes,
        ) == .lt) cursor += 1;
        const known = cursor < old and
            std.mem.eql(u8, ws.old[entry_at(cursor)..][0..32], &id.bytes);
        const trusted = known and stat.kind == .file and stat.ctime_ns != 0 and
            same_as_record(ws, cursor, &stat);
        if (!trusted) {
            if (check_one(store, lent.scratch, id)) |found| {
                return refuse(store, ws, lent, root, found, diag);
            }
        }
        // The stat from before the hash: a file changed during it differs at the next run.
        if (!collector.partial) put_entry(ws, fresh_count, id, &stat);
        fresh_count += 1;
    }
    if (collector.partial) return;
    save(store, ws, root, fresh_count, old);
}

fn entry_at(index: u32) usize {
    assert(index < entries_cap);
    return header_bytes + @as(usize, index) * entry_bytes;
}

fn same_as_record(ws: *const Workspace, index: u32, stat: *const fs_mod.Stat) bool {
    assert(index < entries_cap);
    assert(stat.ctime_ns != 0);
    const at = entry_at(index);
    const entry = ws.old[at..][0..entry_bytes];
    const inode = std.mem.readInt(u64, entry[32..40], .little);
    const size = std.mem.readInt(u64, entry[40..48], .little);
    const ctime = std.mem.readInt(u64, entry[48..56], .little);
    return inode == stat.inode and size == stat.size and ctime == stat.ctime_ns;
}

fn put_entry(ws: *Workspace, index: u32, id: Digest, stat: *const fs_mod.Stat) void {
    assert(index < entries_cap);
    assert(id.bytes.len == constants.store_digest_bytes);
    const entry = ws.fresh[entry_at(index)..][0..entry_bytes];
    @memcpy(entry[0..32], &id.bytes);
    std.mem.writeInt(u64, entry[32..40], stat.inode, .little);
    std.mem.writeInt(u64, entry[40..48], stat.size, .little);
    std.mem.writeInt(u64, entry[48..56], stat.ctime_ns, .little);
}

fn record_path(store: *const Store, buffer: *PathBuf, root: Digest) [:0]const u8 {
    assert(store.root_len > 1);
    assert(root.bytes.len == constants.store_digest_bytes);
    const hex = root.hex();
    return store.path(buffer, &.{ "/", directory_name, "/", &hex });
}

/// Reads the record of `root` into `ws.old`; its entry count, zero if there is none or it is
/// not one this release trusts to read (wrong magic or version, wrong length, not sorted).
fn load(store: *const Store, ws: *Workspace, root: Digest) u32 {
    assert(store.root_len > 1);
    assert(root.bytes.len == constants.store_digest_bytes);
    var path: PathBuf = undefined;
    const bytes = store.fs.read_whole(record_path(store, &path, root), &ws.old) catch return 0;
    if (bytes.len < header_bytes) return 0;
    if (!std.mem.eql(u8, bytes[0..8], magic)) return 0;
    if (std.mem.readInt(u32, bytes[8..12], .little) != version) return 0;
    const count = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > entries_cap) return 0;
    if (bytes.len != header_bytes + @as(usize, count) * entry_bytes) return 0;
    var index: u32 = 1;
    while (index < count) : (index += 1) {
        const before = ws.old[entry_at(index - 1)..][0..32];
        const after = ws.old[entry_at(index)..][0..32];
        if (std.mem.order(u8, before, after) != .lt) return 0;
    }
    return count;
}

/// Writes the record unless it is the one already there. A failure is no one's: it is a cache.
fn save(store: *Store, ws: *Workspace, root: Digest, count: u32, old: u32) void {
    assert(count <= entries_cap);
    const length = entry_at_end(count);
    @memcpy(ws.fresh[0..8], magic);
    std.mem.writeInt(u32, ws.fresh[8..12], version, .little);
    std.mem.writeInt(u32, ws.fresh[12..16], count, .little);
    if (old == count and std.mem.eql(u8, ws.old[0..length], ws.fresh[0..length])) return;
    const fs = store.fs;
    var parent: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const parent_path = store.directory_path(&parent, "trust");
    const directory_path = store.directory_path(&directory, directory_name);
    inline for (.{ parent_path, directory_path }) |made| {
        fs.make_directory(made, true) catch return;
    }
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    var failure: fs_mod.Failure = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = record_path(store, &final, root);
    fs.write_atomic(
        temporary_path,
        final_path,
        directory_path,
        ws.fresh[0..length],
        0o644,
        &failure,
    ) catch {};
}

fn entry_at_end(count: u32) usize {
    assert(count <= entries_cap);
    assert(entry_bytes > 0);
    return header_bytes + @as(usize, count) * entry_bytes;
}

fn walk_failed(diag: *Diag, failure: *const walk.Failure) Error {
    assert(diag.code == null);
    assert(failure.errno < 4096);
    const hex = failure.where.hex();
    const what: diagnose.Tampered = switch (failure.kind) {
        .missing => .missing,
        .damaged => .bytes,
        .unreadable => .unreadable,
        .too_many_entries, .stack_full => .too_large,
    };
    diagnose.tampered(diag, "", &hex, what, failure.errno);
    return error.Failed;
}

/// Names the damaged object's path in the image and what differs, and raises E0907.
fn refuse(
    store: *const Store,
    ws: *Workspace,
    lent: Lent,
    root: Digest,
    found: Found,
    diag: *Diag,
) Error {
    var what = found.what;
    const hex = found.id.hex();
    const path_length = locate(store, ws, lent, root, found.id, &what);
    diagnose.tampered(diag, ws.current[0..path_length], &hex, what, found.errno);
    return error.Failed;
}

/// A search of the tree, depth first, for the first file that is `id`: its path is left in
/// `ws.current` (its length returned, zero if not found). A file whose bytes are what its
/// name says but whose mode or owner is not is `mode` or `owner`, not `bytes`.
fn locate(
    store: *const Store,
    ws: *Workspace,
    lent: Lent,
    root: Digest,
    id: Digest,
    what: *diagnose.Tampered,
) usize {
    assert(ws.frames.len > 0);
    var top: u32 = 1;
    var used: u32 = 0;
    ws.frames[0] = .{ .digest = root, .path_at = 0, .path_len = 0 };
    var budget: u64 = constants.store_walk_entries_max;
    while (top > 0) {
        top -= 1;
        const frame = ws.frames[top];
        @memcpy(ws.current[0..frame.path_len], ws.frame_paths[frame.path_at..][0..frame.path_len]);
        used = frame.path_at;
        const path_len: u32 = frame.path_len;
        var errno: u16 = 0;
        const bytes = trees.load(store, frame.digest, lent.tree_buffer, &errno) catch continue;
        var decoder: tree.Decoder = undefined;
        decoder.init(bytes) catch continue;
        var entry: tree.Entry = undefined;
        while (decoder.next(&entry) catch false) {
            if (budget == 0) return 0;
            budget -= 1;
            if (path_len + 1 + entry.name.len > constants.path_bytes_max) continue;
            ws.current[path_len] = '/';
            @memcpy(ws.current[path_len + 1 ..][0..entry.name.len], entry.name);
            const length = path_len + 1 + entry.name.len;
            switch (entry.kind) {
                .symlink => {},
                .file => if (entry.object.eql(id)) {
                    refine(store, &entry, what);
                    return length;
                },
                .dir => {
                    const fits = top < ws.frames.len and used + length <= ws.frame_paths.len;
                    if (!fits) continue;
                    @memcpy(ws.frame_paths[used..][0..length], ws.current[0..length]);
                    ws.frames[top] = .{
                        .digest = entry.subtree,
                        .path_at = used,
                        .path_len = @intCast(length),
                    };
                    top += 1;
                    used += @intCast(length);
                },
            }
        }
    }
    return 0;
}

fn refine(store: *const Store, entry: *const tree.Entry, what: *diagnose.Tampered) void {
    assert(entry.kind == .file);
    assert(store.root_len > 1);
    if (what.* != .bytes) return;
    var path: PathBuf = undefined;
    const stat = store.fs.lstat(store.object_path(&path, entry.object)) catch return;
    if (stat.mode != entry.mode) {
        what.* = .mode;
    } else if (stat.uid != entry.uid or stat.gid != entry.gid) {
        what.* = .owner;
    }
}
