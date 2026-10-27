//! Removing a directory tree: what the store's own cleanups and a container's upper layer need.
//! It runs in the store's child (`namespace.zig`), because an upper layer holds files and
//! directories owned by subordinate ids, which only the user's namespace may remove.
//!
//! The walk is iterative: a stack of frames, one per directory being emptied, each holding a
//! batch of its names. A directory is read in batches of `batch_names`; when a batch is done it
//! is read again, and an empty read means the directory can go. So a directory of any size
//! costs a fixed amount of memory, and nothing is held open across a removal. A tree nested
//! deeper than `store_depth_max` is not removed (the caller says so; it is a leftover, not a
//! loss).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("fs.zig");
const names_mod = @import("names.zig");

const Fs = fs_mod.Fs;
const NameList = names_mod.NameList;

pub const batch_names: u32 = 256;
const region_bytes: u32 = batch_names * (constants.store_name_bytes_max + 1);

/// The memory a removal needs for names: one region per level.
pub const arena_bytes: u32 = (constants.store_depth_max + 1) * region_bytes;

/// Why a removal stopped: the path, the coarse error and the errno.
pub const Failure = struct {
    path: [constants.path_bytes_max]u8,
    path_len: u32,
    err: host_mod.Error,
    errno: u16,
    /// The tree is deeper than the walk's stack.
    too_deep: bool,

    pub fn path_text(failure: *const Failure) []const u8 {
        assert(failure.path_len <= failure.path.len);
        return failure.path[0..failure.path_len];
    }
};

const Frame = struct {
    path_len: u32,
    names: NameList,
    /// The offset in `names` of the next name to remove.
    at: u32,
};

pub const Workspace = struct {
    path: [constants.path_bytes_max + 1]u8,
    frames: [constants.store_depth_max + 1]Frame,
};

pub const Error = error{Failed};

const Run = struct {
    fs: Fs,
    ws: *Workspace,
    arena: []u8,
    failure: *Failure,
    depth: u32,

    fn fail(run: *Run, length: u32, err: host_mod.Error) Error {
        assert(length <= constants.path_bytes_max);
        @memcpy(run.failure.path[0..length], run.ws.path[0..length]);
        run.failure.path_len = length;
        run.failure.err = err;
        run.failure.errno = run.fs.last_errno();
        run.failure.too_deep = false;
        return error.Failed;
    }

    fn path_text(run: *const Run, length: u32) [:0]const u8 {
        assert(length > 0);
        run.ws.path[length] = 0;
        return run.ws.path[0..length :0];
    }

    /// Starts a frame for the directory at the first `length` bytes of the path.
    fn push(run: *Run, length: u32) Error!void {
        assert(run.depth <= constants.store_depth_max);
        const base = run.depth * region_bytes;
        run.ws.frames[run.depth] = .{
            .path_len = length,
            .names = NameList.init(run.arena[base..][0..region_bytes], batch_names),
            .at = 0,
        };
        run.depth += 1;
        try run.read_batch(&run.ws.frames[run.depth - 1]);
    }

    fn read_batch(run: *Run, frame: *Frame) Error!void {
        const base = (run.depth - 1) * region_bytes;
        frame.names = NameList.init(run.arena[base..][0..region_bytes], batch_names);
        frame.at = 0;
        const path = run.path_text(frame.path_len);
        run.fs.read_dir(path, frame.names.visitor()) catch |err| {
            return run.fail(frame.path_len, err);
        };
        // A directory with more than a batch of names reports `too_many`; the rest are read
        // on the next round, after these are gone.
        assert(!frame.names.full);
    }

    fn step(run: *Run) Error!void {
        assert(run.depth > 0);
        const frame = &run.ws.frames[run.depth - 1];
        if (frame.at == frame.names.used) {
            if (frame.names.count > 0) {
                try run.read_batch(frame); // The batch is gone; are there more?
                if (frame.names.count > 0) return;
            }
            const path = run.path_text(frame.path_len);
            run.fs.remove_directory(path) catch |err| return run.fail(frame.path_len, err);
            run.depth -= 1;
            return;
        }
        const length = frame.names.bytes[frame.at];
        const name = frame.names.bytes[frame.at + 1 ..][0..length];
        frame.at += 1 + length;
        var path_len = frame.path_len;
        if (path_len + 1 + name.len > constants.path_bytes_max) {
            return run.fail(path_len, error.PathTooLong);
        }
        run.ws.path[path_len] = '/';
        path_len += 1;
        @memcpy(run.ws.path[path_len..][0..name.len], name);
        path_len += @intCast(name.len);
        const path = run.path_text(path_len);
        const found = run.fs.lstat(path) catch |err| return run.fail(path_len, err);
        if (found.kind != .dir) {
            run.fs.unlink(path) catch |err| return run.fail(path_len, err);
            return;
        }
        if (run.depth > constants.store_depth_max) {
            _ = run.fail(path_len, error.IoFailed) catch {};
            run.failure.too_deep = true;
            return error.Failed;
        }
        try run.push(path_len);
    }
};

/// Removes `root` and everything below it. `arena` is at least `arena_bytes`.
pub fn tree(
    fs: Fs,
    ws: *Workspace,
    arena: []u8,
    root: [:0]const u8,
    failure: *Failure,
) Error!void {
    assert(arena.len >= arena_bytes);
    assert(root.len > 1);
    assert(root.len <= constants.path_bytes_max);
    @memcpy(ws.path[0..root.len], root);
    ws.path[root.len] = 0;
    var run: Run = .{ .fs = fs, .ws = ws, .arena = arena, .failure = failure, .depth = 0 };
    const found = fs.lstat(root) catch |err| {
        if (err == error.NotFound) return; // Nothing to remove.
        return run.fail(@intCast(root.len), err);
    };
    if (found.kind != .dir) {
        fs.unlink(root) catch |err| return run.fail(@intCast(root.len), err);
        return;
    }
    try run.push(@intCast(root.len));
    // Each step removes one name, reads a batch or removes one directory; the tree is finite
    // and every pass over a directory removes what it read.
    while (run.depth > 0) try run.step();
}

comptime {
    assert(arena_bytes <= constants.store_arena_bytes_max);
    assert(batch_names > 0);
}

const testing = std.testing;
const fs_sim = @import("fs_sim.zig");

var test_sim: fs_sim.SimFs = undefined;
var test_ws: Workspace = undefined;
var test_arena: [arena_bytes]u8 align(8) = undefined;
var test_failure: Failure = undefined;

test "a tree goes, and a missing one is no error" {
    // Goal: the basic walk. Method: a small tree with a deep chain, a symlink and a file in
    // every directory, removed; the root is gone, and a second removal does nothing.
    test_sim.init(1);
    test_sim.put_dir("/d", 0o755);
    test_sim.put_dir("/d/a", 0o755);
    test_sim.put_dir("/d/a/b", 0o755);
    test_sim.put_file("/d/f", 0o644, "x");
    test_sim.put_file("/d/a/g", 0o644, "y");
    test_sim.put_file("/d/a/b/h", 0o644, "z");
    const fs = test_sim.interface();
    try tree(fs, &test_ws, &test_arena, "/d", &test_failure);
    try testing.expect(test_sim.kind_of("/d") == null);
    try testing.expectEqual(@as(u32, 0), test_sim.live_count());
    try tree(fs, &test_ws, &test_arena, "/d", &test_failure);
}

test "a directory of more than a batch is emptied in rounds" {
    // Goal: memory does not grow with the directory. Method: three batches of files.
    test_sim.init(1);
    test_sim.put_dir("/big", 0o755);
    var name: [32]u8 = undefined;
    for (0..batch_names * 2 + 5) |index| {
        const path = std.fmt.bufPrint(&name, "/big/f{d}", .{index}) catch unreachable; // Short.
        test_sim.put_file(path, 0o644, "");
    }
    try tree(test_sim.interface(), &test_ws, &test_arena, "/big", &test_failure);
    try testing.expectEqual(@as(u32, 0), test_sim.live_count());
}

test "a failure names the path and the error" {
    // Goal: the caller can say what stayed. Method: the third write point fails.
    test_sim.init(1);
    test_sim.put_dir("/d", 0o755);
    test_sim.put_file("/d/a", 0o644, "");
    test_sim.put_file("/d/b", 0o644, "");
    test_sim.faults.fail_mutation = 1;
    test_sim.faults.fail_errno = 13;
    try testing.expectError(
        error.Failed,
        tree(test_sim.interface(), &test_ws, &test_arena, "/d", &test_failure),
    );
    try testing.expect(std.mem.startsWith(u8, test_failure.path_text(), "/d/"));
    try testing.expectEqual(@as(u16, 13), test_failure.errno);
}
