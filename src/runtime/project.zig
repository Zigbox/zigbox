//! The project directory, and paths resolved against the file system as the kernel would
//! (M6b, docs/briefs/M6b-dev-loop.md, "Writable mounts"). A writable mount is allowed only below
//! the project directory, and "below" has to be judged on the real path: `./site` may be a
//! symbolic link to `/etc`, and `../other` may be a way back in. So a path is resolved here part
//! by part, with every symbolic link followed, and only the result is compared with the project.
//!
//! The project directory is the one that holds the nearest `zbx.lock` up from the working
//! directory (found as `zbx run` finds the lock, `lock_file.locate`), else the working directory.
//!
//! Everything goes through the `Fs` interface (`lstat` and `read_link`), so the simulator can
//! make a link that points out of the project and the real host sees the same walk. No
//! recursion: the rest of the path is one buffer, and a link's target is put in front of it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const lock_file = @import("../lock_file.zig");
const fs_mod = @import("../store/fs.zig");
const volume = @import("../state/volume.zig");

pub const Fs = fs_mod.Fs;
const Host = host_mod.Host;

/// A resolved path: absolute, with no symbolic link and no `.`, `..` or empty part, and a NUL
/// after its last byte. The root is "/".
pub const Path = struct {
    bytes: [constants.path_bytes_max + 1]u8,
    len: u32,

    pub fn text(path: *const Path) [:0]const u8 {
        assert(path.len >= 1);
        assert(path.len <= constants.path_bytes_max);
        assert(path.bytes[path.len] == 0);
        return path.bytes[0..path.len :0];
    }
};

pub const ResolveError = error{
    /// A part of the path is not there (or is not a directory where one is needed).
    NotFound,
    /// A part cannot be looked at (permission, input/output).
    Unreadable,
    /// More than `symlinks_followed_max` links, or links that lead back to themselves.
    Loop,
    /// The path, or what a link makes of it, is longer than `path_bytes_max`.
    TooLong,
};

/// The room for what is still to be read: a link's target goes in front of it, so the whole of
/// it is never longer than this, and anything longer is `TooLong`.
const rest_bytes_max = 2 * constants.path_bytes_max + 1;

comptime {
    // A link's target and the path after it can each be the longest path.
    assert(rest_bytes_max >= constants.path_bytes_max + 1 + constants.path_bytes_max);
    assert(constants.path_resolve_steps_max > constants.symlinks_followed_max);
}

/// Resolves `input` (absolute, or relative to `base`, which is absolute and has no link in it)
/// into `out`. Every symbolic link is followed, in the middle of the path and at its end; the
/// path must exist.
pub fn resolve(fs: Fs, base: []const u8, input: []const u8, out: *Path) ResolveError!void {
    assert(base.len > 0);
    assert(base[0] == '/');
    assert(input.len > 0);
    assert(input.len <= constants.path_bytes_max);
    // `walk` is what is resolved so far (empty is the root); `rest` is what is left to read,
    // kept at the end of its buffer so that a link's target can be put in front of it.
    var walk: [constants.path_bytes_max + 1]u8 = undefined;
    var walk_len: usize = 0;
    var rest: [rest_bytes_max]u8 = undefined;
    var start: usize = rest.len - input.len;
    @memcpy(rest[start..], input);
    if (input[0] != '/') {
        const trimmed = std.mem.trimEnd(u8, base, "/");
        if (trimmed.len > constants.path_bytes_max) return error.TooLong;
        @memcpy(walk[0..trimmed.len], trimmed);
        walk_len = trimmed.len;
    }
    var links: u32 = 0;
    for (0..constants.path_resolve_steps_max) |_| {
        while (start < rest.len and rest[start] == '/') start += 1;
        if (start == rest.len) return finish(&walk, walk_len, out);
        const end = std.mem.indexOfScalarPos(u8, &rest, start, '/') orelse rest.len;
        const name = rest[start..end];
        start = end;
        if (std.mem.eql(u8, name, ".")) continue;
        if (std.mem.eql(u8, name, "..")) {
            walk_len = std.mem.lastIndexOfScalar(u8, walk[0..walk_len], '/') orelse 0;
            continue;
        }
        if (walk_len + 1 + name.len > constants.path_bytes_max) return error.TooLong;
        walk[walk_len] = '/';
        @memcpy(walk[walk_len + 1 ..][0..name.len], name);
        walk_len += 1 + name.len;
        walk[walk_len] = 0;
        const found = fs.lstat(walk[0..walk_len :0]) catch |err| {
            return if (err == error.NotFound) error.NotFound else error.Unreadable;
        };
        if (found.kind != .symlink) continue;
        links += 1;
        if (links > constants.symlinks_followed_max) return error.Loop;
        var target_storage: [constants.path_bytes_max + 1]u8 = undefined;
        const target = fs.read_link(walk[0..walk_len :0], &target_storage) catch |err| {
            return if (err == error.FileTooLarge) error.TooLong else error.Unreadable;
        };
        // Back to the directory that holds the link; an absolute target starts from the root.
        walk_len -= 1 + name.len;
        if (target.len == 0) return error.NotFound;
        if (target[0] == '/') walk_len = 0;
        if (start < target.len + 1) return error.TooLong;
        start -= target.len + 1;
        @memcpy(rest[start..][0..target.len], target);
        rest[start + target.len] = '/';
    }
    return error.Loop;
}

fn finish(walk: *const [constants.path_bytes_max + 1]u8, walk_len: usize, out: *Path) void {
    assert(walk_len <= constants.path_bytes_max);
    if (walk_len == 0) {
        out.bytes[0] = '/';
        out.bytes[1] = 0;
        out.len = 1;
        return;
    }
    assert(walk[0] == '/');
    @memcpy(out.bytes[0..walk_len], walk[0..walk_len]);
    out.bytes[walk_len] = 0;
    out.len = @intCast(walk_len);
}

pub const DirectoryError = error{
    /// The working directory cannot be read.
    NoDirectory,
} || ResolveError;

/// The project directory, resolved: `given` if the caller named one (absolute), else the
/// directory of the nearest `zbx.lock` up from the working directory, else the working
/// directory itself.
pub fn directory(host: Host, fs: Fs, given: []const u8, out: *Path) DirectoryError!void {
    assert(given.len <= constants.path_bytes_max);
    if (given.len > 0) {
        assert(given[0] == '/');
        return resolve(fs, "/", given, out);
    }
    var located: lock_file.Located = undefined;
    located.path[0] = 0;
    located.len = 0;
    lock_file.locate(host, fs, &located) catch |err| {
        return if (err == error.TooLong) error.TooLong else error.NoDirectory;
    };
    const text = if (located.directory_len == 0) "/" else located.directory();
    return resolve(fs, "/", text, out);
}

/// Whether `path` is `project` or below it, part by part (`/home/a/projectile` is not below
/// `/home/a/project`). Both are resolved paths. Everything is below the root.
pub fn is_inside(project: []const u8, path: []const u8) bool {
    assert(project.len > 0);
    assert(project[0] == '/');
    assert(path.len > 0);
    assert(path[0] == '/');
    if (project.len == 1) return true;
    return volume.under(path, project);
}

const testing = std.testing;
const SimFs = @import("../store/fs_sim.zig").SimFs;

var files: SimFs = undefined;

fn tree() void {
    files.init(1);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir("/home/alice/proj", 0o755);
    files.put_dir("/home/alice/proj/site", 0o755);
    files.put_file("/home/alice/proj/site/index.html", 0o644, "hello\n");
    files.put_file("/home/alice/proj/zbx.lock", 0o644, "");
    files.put_dir("/home/alice/other", 0o755);
    files.put_dir("/etc", 0o755);
    files.put_symlink("/home/alice/proj/escape", "/etc");
    files.put_symlink("/home/alice/proj/up", "../other");
    files.put_symlink("/home/alice/proj/in", "site");
    files.put_symlink("/home/alice/proj/self", "self");
    files.put_symlink("/home/alice/proj/dangling", "nowhere");
    files.put_symlink("/home/alice/proj/chain", "in/..");
}

fn resolved(base: []const u8, input: []const u8) (ResolveError || error{OutOfMemory})![]const u8 {
    var path: Path = undefined;
    @memset(&path.bytes, 0xAA); // Not undefined: a stale byte must not pass for a result.
    try resolve(files.interface(), base, input, &path);
    return try testing.allocator.dupe(u8, path.text());
}

fn expect_resolves(base: []const u8, input: []const u8, expected: []const u8) !void {
    const found = try resolved(base, input);
    defer testing.allocator.free(found);
    try testing.expectEqualStrings(expected, found);
}

test "a path is resolved part by part, with every link followed" {
    // Goal: the real path, as the kernel gives it. Method: relative and absolute paths, `.`
    // and `..`, a link in the middle and at the end, a link to a relative target with `..`,
    // and a chain.
    tree();
    const base = "/home/alice/proj";
    try expect_resolves(base, "site", "/home/alice/proj/site");
    try expect_resolves(base, "./site/", "/home/alice/proj/site");
    try expect_resolves(base, ".", "/home/alice/proj");
    try expect_resolves(base, "site/index.html", "/home/alice/proj/site/index.html");
    try expect_resolves(base, "../other", "/home/alice/other");
    try expect_resolves(base, "/home/alice//proj/./site", "/home/alice/proj/site");
    try expect_resolves(base, "in", "/home/alice/proj/site");
    try expect_resolves(base, "in/index.html", "/home/alice/proj/site/index.html");
    try expect_resolves(base, "escape", "/etc");
    try expect_resolves(base, "up", "/home/alice/other");
    try expect_resolves(base, "site/../escape/..", "/");
    try expect_resolves(base, "/", "/");
    try expect_resolves(base, "../../../..", "/");
    // `in/..` is the directory that holds `site`, the link's target, not the link's own parent.
    try expect_resolves(base, "chain", "/home/alice/proj");
}

test "a path that is not there, a loop and a path too long are refused" {
    // Goal: each failure is its own error. Method: a missing part (middle and end), a file
    // used as a directory, a link to itself, a dangling link, and paths past the bound.
    tree();
    const base = "/home/alice/proj";
    try testing.expectError(error.NotFound, resolved(base, "missing"));
    try testing.expectError(error.NotFound, resolved(base, "missing/deeper"));
    try testing.expectError(error.NotFound, resolved(base, "site/index.html/more"));
    try testing.expectError(error.NotFound, resolved(base, "dangling"));
    try testing.expectError(error.Loop, resolved(base, "self"));
    // The base is trusted (it is the working directory), so a long one makes the first part
    // too long before anything is looked at.
    var long: [constants.path_bytes_max - 4]u8 = undefined;
    @memset(&long, 'a');
    long[0] = '/';
    try testing.expectError(error.TooLong, resolved(&long, "bcdefghij"));
    // A chain of links as long as the limit ends in a loop error, one shorter still resolves.
    var name: [16]u8 = undefined;
    for (0..constants.symlinks_followed_max + 1) |index| {
        const from = try std.fmt.bufPrint(&name, "/l{d}", .{index});
        var target: [16]u8 = undefined;
        const to = try std.fmt.bufPrint(&target, "l{d}", .{index + 1});
        files.put_symlink(from, to);
    }
    var last: [16]u8 = undefined;
    const end = try std.fmt.bufPrint(&last, "/l{d}", .{constants.symlinks_followed_max + 1});
    files.put_dir(end, 0o755);
    try testing.expectError(error.Loop, resolved("/", "l0"));
    const from_one = try resolved("/", "l1"); // One link fewer: forty, the limit itself.
    defer testing.allocator.free(from_one);
    try testing.expectEqualStrings(end, from_one);
}

test "a read that fails is unreadable, not missing" {
    // Goal: a fault is not reported as a path that is not there. Method: the simulated disk
    // fails reads with EIO.
    tree();
    files.faults.read_error_per_mille = 0;
    files.crashed = true; // Every call fails with EIO until restart.
    try testing.expectError(error.Unreadable, resolved("/home/alice/proj", "site"));
}

test "inside means the project or below it, by whole parts" {
    // Goal: the comparison the guardrail rests on. Method: the project itself, below it, a
    // sibling that shares a prefix, the parent, and the root as the project.
    const project = "/home/alice/proj";
    try testing.expect(is_inside(project, "/home/alice/proj"));
    try testing.expect(is_inside(project, "/home/alice/proj/site"));
    try testing.expect(!is_inside(project, "/home/alice/projectile"));
    try testing.expect(!is_inside(project, "/home/alice"));
    try testing.expect(!is_inside(project, "/"));
    try testing.expect(is_inside("/", "/anything"));
}

test "the project directory is the one with the nearest zbx.lock, else the working directory" {
    // Goal: found as `zbx run` finds the lock. Method: from the project's subdirectory, from a
    // directory with no lock above it, and from a named directory.
    const HostSim = @import("../host_sim.zig").HostSim;
    tree();
    files.put_dir("/home/alice/proj/site/deep", 0o755);
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim.store_fs = &files;
    var path: Path = undefined;
    _ = sim.world.processes[0].cwd.set("/home/alice/proj/site/deep");
    try directory(sim.interface(), files.interface(), "", &path);
    try testing.expectEqualStrings("/home/alice/proj", path.text());
    _ = sim.world.processes[0].cwd.set("/home/alice/other");
    try directory(sim.interface(), files.interface(), "", &path);
    try testing.expectEqualStrings("/home/alice/other", path.text());
    try directory(sim.interface(), files.interface(), "/home/alice/proj/in", &path);
    try testing.expectEqualStrings("/home/alice/proj/site", path.text());
    try testing.expectError(
        error.NotFound,
        directory(sim.interface(), files.interface(), "/home/alice/none", &path),
    );
}
