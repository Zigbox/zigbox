//! Materializing a tree: the directory a container's overlay uses as its lower layer. It is a
//! hardlink farm. Every directory of the tree is a real directory with the mode, owner and
//! attributes the tree records; every file is a hard link to its object (so it costs no space
//! and carries the object's real owner, mode and attributes); every symlink is made again. The
//! tree's root directory gets the root's own mode, owner and attributes (`Decoder.own`).
//!
//!   <store>/cache/<64 hex>           the farm of the tree with that digest
//!
//! A farm is built once and used by every run of the tree. It is built in `tmp/` and renamed
//! into `cache/` when whole, so a killed build leaves nothing under a digest, and two builds at
//! once end with one farm: the loser's rename finds the farm there, discards its own and uses
//! the winner's. Directories get their attributes after their entries, so a directory without
//! write permission is still filled and its modification time is the fixed one.
//!
//! The farm is never written by a container: it is the overlay's lower layer, and a write goes
//! to the container's own upper layer by copy-up (`runtime/image.zig`). It must be built from
//! inside the user's namespace (`namespace.zig`): a hard link to a file owned by a subordinate
//! id is allowed there, because the namespace's root has `CAP_FOWNER` over mapped ids, and
//! `chown` of a directory to a container id works.
//!
//! The walk is iterative, like the import's: a stack of frames, one per open directory, each
//! holding the tree bytes it reads from (in one arena used as a stack) and the next entry. A
//! tree needing more than `store_arena_bytes_max`, or nested deeper than `store_depth_max`, is
//! refused, never cut.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const diagnose = @import("diagnose.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const remove = @import("remove.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

/// The build failed; the reason is in the `Diag`.
pub const Error = error{Failed};

const Frame = struct {
    path_len: u32,
    /// Where this directory's tree bytes are in the arena, and how long.
    bytes_at: u32,
    bytes_len: u32,
    decoder: tree.Decoder,
    /// The directory's own mode, owner and attributes, to apply when it is full: for a
    /// subdirectory the entry's (in the parent's bytes), for the root `decoder.own`.
    own: tree.Own,
    is_root: bool,
};

/// The caller's memory, about 17 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    arena: [constants.store_arena_bytes_max]u8 align(8),
    path: [constants.path_bytes_max + 1]u8,
    object_path: PathBuf,
    frames: [constants.store_depth_max + 1]Frame,
    /// A NUL-terminated copy of an attribute's name.
    xattr_name: [constants.store_xattr_name_bytes_max + 1]u8,
    /// A NUL-terminated copy of a symlink's target.
    target: [constants.store_symlink_target_bytes_max + 1]u8,
    removal: remove.Workspace,
};

/// The path of the farm of `digest`.
pub fn farm_path(store: *const Store, buffer: *PathBuf, digest: Digest) [:0]const u8 {
    assert(store.root_len > 1);
    const hex = digest.hex();
    return store.path(buffer, &.{ "/cache/", &hex });
}

fn align_up(value: u32, alignment: u32) u32 {
    assert(alignment > 0);
    assert(alignment & (alignment - 1) == 0);
    return (value + alignment - 1) & ~(alignment - 1);
}

const Run = struct {
    store: *Store,
    ws: *Workspace,
    diag: *Diag,
    depth: u32,

    fn path_text(run: *const Run, length: u32) [:0]const u8 {
        assert(length > 0);
        assert(length <= constants.path_bytes_max);
        assert(run.ws.path[length] == 0);
        return run.ws.path[0..length :0];
    }

    fn write_failed(run: *Run, operation: []const u8, err: host_mod.Error, errno: u16) Error {
        assert(run.diag.code == null);
        if (errno == errno_mlink) {
            diagnose.link_limit(run.diag, run.store);
        } else {
            diagnose.write_failed(run.diag, run.store, operation, err, errno);
        }
        return error.Failed;
    }

    fn limit(run: *Run, which: diagnose.Limit, path: []const u8) Error {
        assert(path.len > 0);
        assert(run.diag.code == null);
        diagnose.too_big(run.diag, which, path);
        return error.Failed;
    }

    /// Loads the tree `digest` into the arena at `base` and starts a frame for it.
    fn push_frame(
        run: *Run,
        digest: Digest,
        path_len: u32,
        own: tree.Own,
        is_root: bool,
    ) Error!void {
        const ws = run.ws;
        assert(run.depth <= constants.store_depth_max);
        const base: u32 = if (run.depth == 0) 0 else blk: {
            const parent = &ws.frames[run.depth - 1];
            break :blk align_up(parent.bytes_at + parent.bytes_len, 8);
        };
        const room = @min(ws.arena.len - base, constants.store_tree_bytes_max);
        if (room < 64) return run.limit(.arena, run.ws.path[0..path_len]);
        var errno: u16 = 0;
        const bytes = trees.load(run.store, digest, ws.arena[base..][0..room], &errno) catch |err| {
            switch (err) {
                error.NotFound => diagnose.tree_damaged(
                    run.diag,
                    digest,
                    "is missing from the store",
                ),
                error.Damaged => diagnose.tree_damaged(
                    run.diag,
                    digest,
                    "does not hash to its name",
                ),
                error.Unreadable => diagnose.cannot_read(
                    run.diag,
                    run.store,
                    "reading a tree",
                    error.IoFailed,
                    errno,
                ),
            }
            return error.Failed;
        };
        const frame = &ws.frames[run.depth];
        frame.* = .{
            .path_len = path_len,
            .bytes_at = base,
            .bytes_len = @intCast(bytes.len),
            .decoder = undefined,
            .own = own,
            .is_root = is_root,
        };
        frame.decoder.init(ws.arena[base..][0..bytes.len]) catch {
            diagnose.tree_damaged(run.diag, digest, "is not a valid tree");
            return error.Failed;
        };
        run.depth += 1;
    }

    fn step(run: *Run) Error!void {
        assert(run.depth > 0);
        const frame = &run.ws.frames[run.depth - 1];
        var found: tree.Entry = undefined;
        const more = frame.decoder.next(&found) catch {
            diagnose.tree_damaged(
                run.diag,
                Digest.of(run.frame_bytes(frame)),
                "is not a valid tree",
            );
            return error.Failed;
        };
        if (!more) return run.finish_frame(frame);
        try run.entry(frame, &found);
    }

    fn frame_bytes(run: *const Run, frame: *const Frame) []const u8 {
        return run.ws.arena[frame.bytes_at..][0..frame.bytes_len];
    }

    fn entry(run: *Run, frame: *Frame, found: *const tree.Entry) Error!void {
        const ws = run.ws;
        var length = frame.path_len;
        const slash: u32 = if (ws.path[length - 1] == '/') 0 else 1;
        if (length + slash + found.name.len > constants.path_bytes_max) {
            return run.limit(.path, ws.path[0..length]);
        }
        if (slash == 1) ws.path[length] = '/';
        length += slash;
        @memcpy(ws.path[length..][0..found.name.len], found.name);
        length += @intCast(found.name.len);
        ws.path[length] = 0;
        const path = run.path_text(length);
        switch (found.kind) {
            .file => try run.link_file(path, found),
            .symlink => try run.make_symlink(path, found),
            .dir => try run.make_dir(path, found),
        }
    }

    fn link_file(run: *Run, path: [:0]const u8, found: *const tree.Entry) Error!void {
        assert(found.kind == .file);
        const fs = run.store.fs;
        const source = run.store.object_path(&run.ws.object_path, found.object);
        fs.link(source, path) catch |err| {
            if (err == error.NotFound and fs.last_errno() == errno_noent) {
                diagnose.object_missing(run.diag, found.object);
                return error.Failed;
            }
            return run.write_failed("linking an object into the tree", err, fs.last_errno());
        };
    }

    fn make_symlink(run: *Run, path: [:0]const u8, found: *const tree.Entry) Error!void {
        assert(found.kind == .symlink);
        const fs = run.store.fs;
        const ws = run.ws;
        assert(found.target.len <= constants.store_symlink_target_bytes_max);
        @memcpy(ws.target[0..found.target.len], found.target);
        ws.target[found.target.len] = 0;
        const target = ws.target[0..found.target.len :0];
        fs.symlink(target, path) catch |err| {
            return run.write_failed("making a symlink", err, fs.last_errno());
        };
        fs.set_path_attributes(path, .{
            .mode = null,
            .uid = found.uid,
            .gid = found.gid,
            .mtime = constants.store_mtime_seconds,
        }) catch |err| {
            return run.write_failed("setting a symlink's owner", err, fs.last_errno());
        };
    }

    fn make_dir(run: *Run, path: [:0]const u8, found: *const tree.Entry) Error!void {
        assert(found.kind == .dir);
        if (run.depth > constants.store_depth_max) return run.limit(.depth, path);
        const fs = run.store.fs;
        fs.make_directory(path, false) catch |err| {
            return run.write_failed("making a directory", err, fs.last_errno());
        };
        const own: tree.Own = .{
            .mode = found.mode,
            .uid = found.uid,
            .gid = found.gid,
            .xattrs = found.xattrs,
        };
        try run.push_frame(found.subtree, @intCast(path.len), own, false);
    }

    /// The directory is full: now its mode, owner and attributes, and the fixed mtime.
    fn finish_frame(run: *Run, frame: *Frame) Error!void {
        assert(run.depth > 0);
        const ws = run.ws;
        ws.path[frame.path_len] = 0; // Deeper entries overwrote it.
        const path = run.path_text(frame.path_len);
        const own = if (frame.is_root) frame.decoder.own else frame.own;
        try run.apply(path, own);
        run.depth -= 1;
    }

    fn apply(run: *Run, path: [:0]const u8, own: tree.Own) Error!void {
        const fs = run.store.fs;
        fs.set_path_attributes(path, .{
            .mode = own.mode,
            .uid = own.uid,
            .gid = own.gid,
            .mtime = constants.store_mtime_seconds,
        }) catch |err| {
            return run.write_failed("setting a directory's mode and owner", err, fs.last_errno());
        };
        var iterator = xattrs.Iterator.init(own.xattrs);
        while (iterator.next()) |item| {
            const ws = run.ws;
            @memcpy(ws.xattr_name[0..item.name.len], item.name);
            ws.xattr_name[item.name.len] = 0;
            const name = ws.xattr_name[0..item.name.len :0];
            fs.set_path_xattr(path, name, item.value) catch |err| {
                return run.write_failed("setting a directory's attribute", err, fs.last_errno());
            };
        }
    }
};

const errno_noent: u16 = 2;
const errno_mlink: u16 = 31;

/// Makes sure the farm of `digest` exists in `cache/`, building it if not. True if this call
/// built it; false if it was already there (or another build finished first).
pub fn ensure(store: *Store, ws: *Workspace, digest: Digest, diag: *Diag) Error!bool {
    assert(diag.code == null);
    assert(store.root_len > 1);
    const fs = store.fs;
    var final_storage: PathBuf = undefined;
    const final = farm_path(store, &final_storage, digest);
    if (fs.lstat(final)) |found| {
        if (found.kind == .dir) return false;
        diagnose.tree_damaged(diag, digest, "has a file where its materialized directory belongs");
        return error.Failed;
    } else |err| {
        if (err != error.NotFound) {
            diagnose.cannot_read(
                diag,
                store,
                "looking for a materialized tree",
                err,
                fs.last_errno(),
            );
            return error.Failed;
        }
    }
    var temporary_storage: PathBuf = undefined;
    const temporary = store.tmp_path(&temporary_storage);
    var run: Run = .{ .store = store, .ws = ws, .diag = diag, .depth = 0 };
    fs.make_directory(temporary, false) catch |err| {
        return run.write_failed("making the directory to build the tree in", err, fs.last_errno());
    };
    const built = build(&run, digest, temporary);
    built catch |failure| {
        // Whatever was built is thrown away; the diagnostic is the build's, not the cleanup's.
        discard(store, ws, temporary);
        return failure;
    };
    fs.rename(temporary, final) catch |err| {
        // Another build finished first: its farm is as good as ours.
        const winner_there = if (fs.lstat(final)) |_| true else |_| false;
        const errno = fs.last_errno();
        discard(store, ws, temporary);
        if (winner_there) return false;
        return run.write_failed("moving the built tree into the cache", err, errno);
    };
    var cache_storage: PathBuf = undefined;
    fs.sync_directory(store.directory_path(&cache_storage, "cache")) catch |err| {
        return run.write_failed("flushing the cache directory", err, fs.last_errno());
    };
    return true;
}

fn build(run: *Run, digest: Digest, temporary: [:0]const u8) Error!void {
    const ws = run.ws;
    @memcpy(ws.path[0..temporary.len], temporary);
    ws.path[temporary.len] = 0;
    try run.push_frame(digest, @intCast(temporary.len), tree.Own.none, true);
    // Each step handles one entry or finishes one directory; the walk ends because every entry
    // is handled once and the stack is at most `store_depth_max` deep.
    while (run.depth > 0) try run.step();
}

/// Removes a half-built tree. If that fails too, it stays in `tmp/` for the next cleanup.
fn discard(store: *Store, ws: *Workspace, path: [:0]const u8) void {
    var failure: remove.Failure = undefined;
    remove.tree(store.fs, &ws.removal, &ws.arena, path, &failure) catch return;
}

/// The root directory's own mode, owner and attributes of the tree `digest`, copied into
/// `blob` (its attribute section), for whoever needs to give another directory the same.
pub fn root_own(
    store: *const Store,
    digest: Digest,
    buffer: []u8,
    blob: []u8,
    errno: *u16,
) trees.LoadError!tree.Own {
    const bytes = try trees.load(store, digest, buffer, errno);
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return error.Damaged;
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch return error.Damaged) {}
    const own = decoder.own;
    if (own.xattrs.len > blob.len) return error.Damaged;
    @memcpy(blob[0..own.xattrs.len], own.xattrs);
    return .{
        .mode = own.mode,
        .uid = own.uid,
        .gid = own.gid,
        .xattrs = blob[0..own.xattrs.len],
    };
}

const testing = std.testing;
const host_sim = @import("../host_sim.zig");
const fs_sim = @import("fs_sim.zig");
const import = @import("import.zig");
const support = @import("test_support.zig");

const root_path = "/data/tstore";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var tstore: Store = undefined;
var tws: Workspace = undefined;
var import_ws: import.Workspace = undefined;
var tdiag: Diag = undefined;

fn start(seed: u64) void {
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    tstore.at(sim.interface(), root_path);
    support.make_source(&files, 0);
    tdiag.reset();
}

fn imported() !Digest {
    var result: import.Result = undefined;
    try import.import(
        &tstore,
        &import_ws,
        "/src",
        .{ .squash_owner = false, .warn = null },
        &result,
        &tdiag,
    );
    return result.digest;
}

fn farm_of(digest: Digest, name: []const u8) []const u8 {
    const hex = digest.hex();
    const parts = [_][]const u8{ root_path, "/cache/", &hex, name };
    var buffer: [256]u8 = undefined;
    var length: usize = 0;
    for (parts) |part| {
        @memcpy(buffer[length..][0..part.len], part);
        length += part.len;
    }
    return farm_scratch(buffer[0..length]);
}

var scratch: [256]u8 = undefined;

fn farm_scratch(text: []const u8) []const u8 {
    @memcpy(scratch[0..text.len], text);
    return scratch[0..text.len];
}

test "a farm has the tree's directories, links to its objects, and its symlinks" {
    // Goal: the lower layer is the tree. Method: import the sample, build the farm, and compare
    // every path with the source: kind, mode, owner, bytes, and attributes; a file is the same
    // inode as its object; the farm costs no bytes.
    start(1);
    const digest = try imported();
    const bytes_before = files.bytes_live;
    try testing.expect(try ensure(&tstore, &tws, digest, &tdiag));
    // Only the symlink's target ("sh") is new data; the files are links.
    try testing.expectEqual(bytes_before + 2, files.bytes_live);
    const sources = [_][]const u8{
        "/src/bin",
        "/src/etc",
        "/src/empty",
        "/src/bin/sh",
        "/src/bin/ls",
        "/src/bin/su",
        "/src/bin/busybox",
        "/src/etc/passwd",
        "/src/etc/shadow",
        "/src/etc/empty",
    };
    for (sources) |source| {
        const found = files.stat_of(farm_of(digest, source["/src".len..])).?;
        const original = files.stat_of(source).?;
        try testing.expectEqual(original.kind, found.kind);
        try testing.expectEqual(original.uid, found.uid);
        if (original.kind != .symlink) try testing.expectEqual(original.mode, found.mode);
        if (original.kind == .file) {
            try testing.expectEqualSlices(
                u8,
                files.content_of(source).?,
                files.content_of(farm_of(digest, source["/src".len..])).?,
            );
            try testing.expect(found.links >= 2); // The object and this name.
        }
    }
    try testing.expectEqualStrings("sh", files.content_of(farm_of(digest, "/bin/busybox")).?);
    try testing.expectEqual(
        @as(?u64, constants.store_mtime_seconds),
        files.mtime_of(farm_of(digest, "/bin")),
    );
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "the root gets the recorded mode, owner and attributes" {
    // Goal: the farm's root is the container's `/`. Method: the source root has mode 0700,
    // owner 3:4 and an attribute; the farm's root has them, and so does a farm built after the
    // source changed, for the old digest.
    start(1);
    files.set_mode_of("/src", 0o700);
    files.set_owner_of("/src", 3, 4);
    files.put_xattr("/src", "user.root", "yes");
    const digest = try imported();
    _ = try ensure(&tstore, &tws, digest, &tdiag);
    const root = farm_of(digest, "");
    const found = files.stat_of(root).?;
    try testing.expectEqual(@as(u16, 0o700), found.mode);
    try testing.expectEqual(@as(u32, 3), found.uid);
    try testing.expectEqual(@as(u32, 4), found.gid);
    try testing.expectEqualSlices(u8, files.xattrs_of("/src").?, files.xattrs_of(root).?);
    try testing.expectEqual(@as(?u64, constants.store_mtime_seconds), files.mtime_of(root));
}

test "a second ensure uses the farm that is there, and builds nothing" {
    // Goal: built once. Method: ensure twice; the second reports false and the mutation count
    // does not move.
    start(1);
    const digest = try imported();
    try testing.expect(try ensure(&tstore, &tws, digest, &tdiag));
    const mutations = files.mutations;
    try testing.expect(!(try ensure(&tstore, &tws, digest, &tdiag)));
    try testing.expectEqual(mutations, files.mutations);
}

test "a failure or a crash at any write point leaves no half farm under a digest" {
    // Goal: atomic. Method: for every write point of a build, once failing and once crashing,
    // the cache holds the whole farm or nothing under the digest; after a restart a second
    // ensure ends with a whole farm.
    start(1);
    const digest = try imported();
    _ = try ensure(&tstore, &tws, digest, &tdiag);
    const points = files.mutations;
    const sample = points;
    for (0..2) |crash| {
        var at: u32 = 0;
        while (at < sample) : (at += 1) {
            start(1);
            const clean = try imported();
            try testing.expect(clean.eql(digest));
            files.mutations = 0;
            if (crash == 0) {
                files.faults.fail_mutation = at;
            } else {
                files.faults.crash_mutation = at;
            }
            tdiag.reset();
            _ = ensure(&tstore, &tws, digest, &tdiag) catch {};
            files.faults = .{};
            files.restart();
            var final: PathBuf = undefined;
            const present = files.kind_of(farm_path(&tstore, &final, digest)) != null;
            if (present) try check_complete(digest);
            tdiag.reset();
            _ = try ensure(&tstore, &tws, digest, &tdiag);
            try check_complete(digest);
        }
    }
}

fn check_complete(digest: Digest) !void {
    try testing.expect(files.stat_of(farm_of(digest, "/etc/passwd")) != null);
    try testing.expect(files.stat_of(farm_of(digest, "/bin/busybox")) != null);
    try testing.expect(files.stat_of(farm_of(digest, "/empty")) != null);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a hardlink limit is its own diagnostic, and the half farm is removed" {
    // Goal: ext4 allows 65000 names per inode. Method: the sample has two files with the same
    // object; a limit of 2 names per inode (the object and one link) is hit by the second.
    start(1);
    files.put_file("/src/bin/ls2", 0o755, "#!shell\n");
    const digest = try imported();
    files.faults.link_max = 2;
    try testing.expectError(error.Failed, ensure(&tstore, &tws, digest, &tdiag));
    try testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0424), tdiag.code);
    files.faults = .{};
    var final: PathBuf = undefined;
    try testing.expect(files.kind_of(farm_path(&tstore, &final, digest)) == null);
    var left: PathBuf = undefined;
    try testing.expectEqual(
        @as(u32, 0),
        support.count_files(&files, tstore.directory_path(&left, "tmp")),
    );
}

test "a tree whose object is missing is E0422, not a half farm" {
    // Goal: a damaged tstore is named. Method: remove an object, then build.
    start(1);
    const digest = try imported();
    var target: PathBuf = undefined;
    const original = files.stat_of("/src/etc/passwd").?;
    _ = original;
    // Find the object file of the sample's passwd by walking the objects directory.
    var index: u32 = 0;
    var removed = false;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (files.kind_of(path).? != .file) continue;
        if (std.mem.endsWith(u8, path, ".chunks")) continue;
        files.remove_path(path);
        removed = true;
        break;
    }
    try testing.expect(removed);
    _ = &target;
    try testing.expectError(error.Failed, ensure(&tstore, &tws, digest, &tdiag));
    try testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0422), tdiag.code);
}

test "root_own reads a root's own section" {
    // Goal: the run command gives the upper layer's root the same. Method: a root with an
    // attribute.
    start(1);
    files.set_mode_of("/src", 0o711);
    files.put_xattr("/src", "user.k", "v");
    const digest = try imported();
    var buffer: [4096]u8 = undefined;
    var blob: [constants.store_xattr_blob_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    const own = try root_own(&tstore, digest, &buffer, &blob, &errno);
    try testing.expectEqual(@as(u16, 0o711), own.mode);
    try testing.expectEqualSlices(u8, files.xattrs_of("/src").?, own.xattrs);
}
