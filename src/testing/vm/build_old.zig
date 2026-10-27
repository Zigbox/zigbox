//! `build_old <zig> <commit> <output>`: builds the x86_64 release `zbx` of an older commit, for
//! the upgrade test of `zig build demo-m3`. A git worktree of <commit> under `.zig-cache`,
//! `zig build release` in it (the same pinned Zig), and the stripped binary copied to <output>.
//! Build-host tool, run by build.zig from the repository root.

const std = @import("std");
const Io = std.Io;

const tree = ".zig-cache/zbx-old-tree";

/// Runs `argv` (in `cwd` if given), its output on stderr, and fails unless it exits 0.
fn run(io: Io, argv: []const []const u8, cwd: ?[]const u8, quiet: bool) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .stdout = .ignore,
        .stderr = if (quiet) .ignore else .inherit,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return error.CommandFailed;
}

pub fn main(init: std.process.Init) !u8 {
    var buffer: [512]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const err = &file_writer.interface;
    defer err.flush() catch {};
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const zig = arguments.next() orelse return usage(err);
    const commit = arguments.next() orelse return usage(err);
    const output = arguments.next() orelse return usage(err);
    const io = init.io;
    const exists = [_][]const u8{ "git", "cat-file", "-e", try std.fmt.allocPrint(
        init.arena.allocator(),
        "{s}^{{commit}}",
        .{commit},
    ) };
    run(io, &exists, null, true) catch {
        try err.print("build_old: commit {s} is not in this clone (CI needs fetch-depth: 0)\n", .{
            commit,
        });
        return 1;
    };
    try run(io, &.{ "git", "worktree", "prune" }, null, false);
    if (Io.Dir.cwd().access(io, tree, .{})) |_| {} else |_| {
        const add = [_][]const u8{
            "git",      "worktree", "add",  "--quiet", "--force",
            "--detach", tree,       commit,
        };
        try run(io, &add, null, false);
    }
    try run(io, &.{ "git", "-C", tree, "checkout", "--quiet", "--detach", commit }, null, false);
    try run(io, &.{ zig, "build", "release" }, tree, false);
    const built = tree ++ "/zig-out/release/x86_64-linux/zbx";
    try Io.Dir.cwd().copyFile(built, Io.Dir.cwd(), output, io, .{});
    return 0;
}

fn usage(err: *Io.Writer) !u8 {
    try err.print("usage: build_old <zig> <commit> <output>\n", .{});
    return 2;
}
