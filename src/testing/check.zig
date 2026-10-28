//! `check <zig> <user>`: the last step of `zig build check`, which has already built, tested,
//! tidied, cross-compiled and checked the error pages when this runs (they are its dependencies,
//! so any failure stops the build before here). It adds the one gate a root build container
//! cannot see: CI runs `zig build test` as an ordinary user. When this runs as root and <user> is
//! not "-", the committed tree is checked out into a scratch worktree owned by <user> and tested
//! as that user, with its own cache. Then it prints the line a report quotes:
//!
//!     check: PASS 1a2b3c4d5e6f (build test tidy release errors-site, test as tester)
//!
//! "+dirty" after the commit means the working tree had uncommitted changes, which the first five
//! gates saw and the user test did not. Build-host tool, run by build.zig from the repository root.

const std = @import("std");
const Io = std.Io;

const scratch = ".zig-cache/zbx-check-tree";

/// Runs `argv` (in `cwd` if given) with its output on stderr; fails unless it exits 0.
fn run(io: Io, argv: []const []const u8, cwd: ?[]const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return error.CommandFailed;
}

/// Runs `argv` and returns its standard output, trimmed; fails unless it exits 0.
fn output(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) ![]const u8 {
    const result = try std.process.run(gpa, io, .{ .argv = argv });
    switch (result.term) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
    return std.mem.trim(u8, result.stdout, " \n");
}

pub fn main(init: std.process.Init) !u8 {
    var buffer: [512]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const err = &file_writer.interface;
    defer err.flush() catch {};
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const zig = arguments.next() orelse return usage(err);
    const user = arguments.next() orelse return usage(err);
    const io = init.io;
    const gpa = init.arena.allocator();
    const commit = try output(gpa, io, &.{ "git", "rev-parse", "--short=12", "HEAD" });
    const porcelain = [_][]const u8{ "git", "status", "--porcelain", "--untracked-files=no" };
    const status = try output(gpa, io, &porcelain);
    const dirty: []const u8 = if (status.len > 0) "+dirty" else "";
    const as_user = !std.mem.eql(u8, user, "-") and std.os.linux.geteuid() == 0;
    if (as_user) {
        test_as(gpa, io, zig, user) catch {
            try err.print("check: FAIL {s}{s} (zig build test as {s})\n", .{ commit, dirty, user });
            return 1;
        };
    }
    const tail: []const u8 = if (as_user)
        try std.fmt.allocPrint(gpa, ", test as {s}", .{user})
    else
        "";
    try err.print("check: PASS {s}{s} (build test tidy release errors-site{s})\n", .{
        commit, dirty, tail,
    });
    return 0;
}

/// `zig build test` as `user` in a scratch worktree of HEAD that `user` owns.
fn test_as(gpa: std.mem.Allocator, io: Io, zig: []const u8, user: []const u8) !void {
    try run(io, &.{ "git", "worktree", "prune" }, null);
    if (Io.Dir.cwd().access(io, scratch, .{})) |_| {
        try run(io, &.{ "git", "worktree", "remove", "--force", scratch }, null);
    } else |_| {}
    try run(io, &.{ "git", "worktree", "add", "--quiet", "--detach", scratch, "HEAD" }, null);
    defer run(io, &.{ "git", "worktree", "remove", "--force", scratch }, null) catch {};
    const absolute = try Io.Dir.cwd().realPathFileAlloc(io, scratch, gpa);
    try run(io, &.{ "chown", "-R", user, scratch }, null);
    const cache = try std.fmt.allocPrint(gpa, "ZIG_GLOBAL_CACHE_DIR={s}/.zig-global", .{absolute});
    const home = try std.fmt.allocPrint(gpa, "HOME={s}", .{absolute});
    const argv = [_][]const u8{
        "runuser", "-u", user, "--", "env", cache, home, zig, "build", "test",
    };
    try run(io, &argv, scratch);
}

fn usage(err: *Io.Writer) !u8 {
    try err.print("usage: check <zig> <user|->\n", .{});
    return 2;
}
