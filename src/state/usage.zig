//! A volume's size, as `zbx state ls` shows it: every file, directory and symlink under its
//! `data` directory, a file with several names counted once. It runs in the store's namespace
//! child, where files of the container's users can be read.
//!
//! The walk is iterative, with an explicit stack of directories (at most `store_depth_max` deep)
//! whose names share one region (`state_walk_arena_bytes`): a directory's names are read whole
//! after its parent's, and given back when it is done. Entries are counted to
//! `state_walk_entries_max`, and the inodes of files with more than one name are remembered in a
//! fixed table (`state_walk_links_max`). Past any bound the walk stops and says which; the size
//! is then unknown, never a guess.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const names_mod = @import("../store/names.zig");

const Fs = fs_mod.Fs;
const NameList = names_mod.NameList;

pub const Size = struct {
    /// The bytes of the files and symlinks (`st_size`), each inode once.
    bytes: u64,
    /// The space on the disk (`st_blocks` times 512), directories included, each inode once.
    disk_bytes: u64,
    files: u64,
};

pub const Stop = enum {
    unreadable,
    too_deep,
    too_many_entries,
    too_many_links,
    names_too_big,

    pub fn sentence(stop: Stop) []const u8 {
        assert(@tagName(stop).len > 0);
        return switch (stop) {
            .unreadable => "a file or directory in it could not be read",
            .too_deep => "it is nested deeper than 64 directories",
            .too_many_entries => "it has more than 4194304 entries",
            .too_many_links => "it has more than 16384 files with several names",
            .names_too_big => "a directory's names do not fit the room the count has",
        };
    }
};

comptime {
    // The sentences above say so.
    assert(constants.store_depth_max == 64);
    assert(constants.state_walk_entries_max == 4194304);
    assert(constants.state_walk_links_max == 16384);
}

pub const Failure = struct {
    stop: Stop,
    err: host_mod.Error,
    errno: u16,
};

const Frame = struct {
    path_len: u32,
    /// Where this directory's names start in the region, and the names.
    base: u32,
    names: NameList,
    /// The offset in `names` of the next name.
    at: u32,
};

pub const Workspace = struct {
    path: [constants.path_bytes_max + 1]u8,
    frames: [constants.store_depth_max + 1]Frame,
    arena: [constants.state_walk_arena_bytes]u8,
    /// Inodes with more than one name seen so far: open addressing, zero is empty (no file has
    /// inode zero).
    links: [table_slots]u64,
    links_count: u32,
};

/// Twice the bound, so that the table is at most half full.
const table_slots: u32 = constants.state_walk_links_max * 2;

pub const Error = error{Stopped};

const Walk = struct {
    fs: Fs,
    ws: *Workspace,
    size: *Size,
    failure: *Failure,
    depth: u32,
    entries: u64,

    fn stop(walk: *Walk, reason: Stop, err: host_mod.Error) Error {
        walk.failure.* = .{ .stop = reason, .err = err, .errno = walk.fs.last_errno() };
        return error.Stopped;
    }

    fn text(walk: *const Walk, length: u32) [:0]const u8 {
        assert(length > 0);
        walk.ws.path[length] = 0;
        return walk.ws.path[0..length :0];
    }

    fn push(walk: *Walk, length: u32) Error!void {
        if (walk.depth > constants.store_depth_max) return walk.stop(.too_deep, error.IoFailed);
        const base: u32 = if (walk.depth == 0) 0 else blk: {
            const parent = &walk.ws.frames[walk.depth - 1];
            break :blk parent.base + parent.names.used;
        };
        const frame = &walk.ws.frames[walk.depth];
        frame.* = .{
            .path_len = length,
            .base = base,
            .names = NameList.init(walk.ws.arena[base..], constants.store_dir_entries_max),
            .at = 0,
        };
        walk.fs.read_dir(walk.text(length), frame.names.visitor()) catch |err| {
            return walk.stop(.unreadable, err);
        };
        if (!frame.names.complete()) return walk.stop(.names_too_big, error.IoFailed);
        walk.depth += 1;
    }

    fn step(walk: *Walk) Error!void {
        assert(walk.depth > 0);
        const frame = &walk.ws.frames[walk.depth - 1];
        if (frame.at == frame.names.used) {
            walk.depth -= 1;
            return;
        }
        const name = frame.names.at(frame.at);
        frame.at += @intCast(1 + name.len);
        if (frame.path_len + 1 + name.len > constants.path_bytes_max) {
            return walk.stop(.too_deep, error.PathTooLong);
        }
        const length: u32 = frame.path_len + 1 + @as(u32, @intCast(name.len));
        walk.ws.path[frame.path_len] = '/';
        @memcpy(walk.ws.path[frame.path_len + 1 ..][0..name.len], name);
        try walk.count(length);
    }

    fn count(walk: *Walk, length: u32) Error!void {
        walk.entries += 1;
        if (walk.entries > constants.state_walk_entries_max) {
            return walk.stop(.too_many_entries, error.IoFailed);
        }
        const found = walk.fs.lstat(walk.text(length)) catch |err| {
            return walk.stop(.unreadable, err);
        };
        if (found.kind == .dir) {
            walk.size.disk_bytes += found.blocks * 512;
            return walk.push(length);
        }
        if (found.links > 1) {
            if (try walk.seen(found.inode)) return;
        }
        walk.size.disk_bytes += found.blocks * 512;
        walk.size.bytes += found.size;
        walk.size.files += 1;
    }

    /// Whether the inode was counted already; it is remembered if not.
    fn seen(walk: *Walk, inode: u64) Error!bool {
        assert(inode != 0);
        const table = &walk.ws.links;
        var slot: u32 = @intCast(std.hash.int(inode) % table_slots);
        // The table is at most half full, so a free slot is found.
        for (0..table_slots) |_| {
            if (table[slot] == inode) return true;
            if (table[slot] == 0) {
                if (walk.ws.links_count == constants.state_walk_links_max) {
                    return walk.stop(.too_many_links, error.IoFailed);
                }
                table[slot] = inode;
                walk.ws.links_count += 1;
                return false;
            }
            slot = (slot + 1) % table_slots;
        }
        unreachable; // At most half the slots are used.
    }
};

/// Counts everything under `root` (a directory; a missing one is size zero).
pub fn measure(
    fs: Fs,
    ws: *Workspace,
    root: [:0]const u8,
    size: *Size,
    failure: *Failure,
) Error!void {
    assert(root.len > 1);
    assert(root.len <= constants.path_bytes_max);
    size.* = .{ .bytes = 0, .disk_bytes = 0, .files = 0 };
    @memset(&ws.links, 0);
    ws.links_count = 0;
    var walk: Walk = .{
        .fs = fs,
        .ws = ws,
        .size = size,
        .failure = failure,
        .depth = 0,
        .entries = 0,
    };
    const found = fs.lstat(root) catch |err| {
        if (err == error.NotFound) return;
        return walk.stop(.unreadable, err);
    };
    if (found.kind != .dir) return walk.stop(.unreadable, error.InvalidPath);
    size.disk_bytes += found.blocks * 512;
    @memcpy(ws.path[0..root.len], root);
    try walk.push(@intCast(root.len));
    // Each step counts one name or ends one directory; every directory is finite and is read
    // once, and the entries bound ends a walk of a tree that changes under it.
    while (walk.depth > 0) try walk.step();
    assert(size.disk_bytes >= found.blocks * 512);
}

comptime {
    // The names of the deepest walk of the longest names fit the region several times over.
    assert(constants.state_walk_arena_bytes >=
        (constants.store_depth_max + 1) * (constants.store_name_bytes_max + 1) * 4);
}

const testing = std.testing;
const SimFs = @import("../store/fs_sim.zig").SimFs;

var test_files: SimFs = undefined;
var test_ws: Workspace = undefined;

test "a size counts files, symlinks and directories, and a file of two names once" {
    // Goal: what `state ls` adds up. Method: a small tree with a hard link, measured.
    test_files.init(1);
    test_files.put_dir("/v", 0o755);
    test_files.put_dir("/v/a", 0o700);
    test_files.put_file("/v/a/f", 0o600, @import("../test_util.zig").repeat('x', 5000));
    test_files.put_file("/v/g", 0o644, "hello");
    test_files.put_symlink("/v/l", "g");
    const fs = test_files.interface();
    try fs.link("/v/a/f", "/v/f2");
    var size: Size = undefined;
    var failure: Failure = undefined;
    try measure(fs, &test_ws, "/v", &size, &failure);
    try testing.expectEqual(@as(u64, 5000 + 5 + 1), size.bytes);
    try testing.expectEqual(@as(u64, 3), size.files);
    // Two directories (4 KiB each), a two-block file, a one-block file and the link's block.
    try testing.expectEqual(@as(u64, (2 + 2 + 1 + 1) * 4096), size.disk_bytes);
    try measure(fs, &test_ws, "/missing", &size, &failure);
    try testing.expectEqual(@as(u64, 0), size.disk_bytes);
}

test "a walk past its depth stops and says so, and an unreadable directory too" {
    // Goal: the bounds are errors, never a wrong size. Method: a chain one past the depth.
    test_files.init(1);
    var path: [512]u8 = undefined;
    var length: usize = 0;
    @memcpy(path[0..2], "/v");
    length = 2;
    test_files.put_dir(path[0..length], 0o755);
    for (0..constants.store_depth_max + 1) |_| {
        @memcpy(path[length..][0..2], "/d");
        length += 2;
        test_files.put_dir(path[0..length], 0o755);
    }
    var size: Size = undefined;
    var failure: Failure = undefined;
    const fs = test_files.interface();
    try testing.expectError(error.Stopped, measure(fs, &test_ws, "/v", &size, &failure));
    try testing.expectEqual(Stop.too_deep, failure.stop);
    test_files.init(1);
    test_files.put_dir("/v", 0o755);
    test_files.put_dir("/v/locked", 0o700);
    test_files.set_unreadable("/v/locked");
    try testing.expectError(error.Stopped, measure(fs, &test_ws, "/v", &size, &failure));
    try testing.expectEqual(Stop.unreadable, failure.stop);
}
