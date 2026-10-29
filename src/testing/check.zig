//! `check <zig> <user> <fuzz>`: the last step of `zig build check`, which has already built,
//! tested, tidied, cross-compiled, checked the error pages and compiled every VM demo harness
//! when this runs (they are its dependencies, so any failure stops the build before here). It
//! adds two gates of its own:
//!
//!   - Every fuzzer, each with a fresh seed (`fuzz all`), as CI's fuzz job does: a fixed seed
//!     run by hand found nothing CI's random ones then did. A failure prints the seed above it.
//!   - The one gate a root build container cannot see: CI runs `zig build test` as an ordinary
//!     user. When this runs as root and <user> is not "-", the committed tree is checked out into
//!     a scratch worktree owned by <user> and tested as that user, with its own cache.
//!
//! Then it prints the line a report quotes:
//!
//!     check: PASS 1a2b3c4d5e6f (build test tidy release errors-site harness fuzz, test as tester)
//!
//! It also says when the build cache has grown past `cache_note_bytes`, with the command that
//! empties it, because a full disk costs more than a rebuild.
//!
//! "+dirty" after the commit means the working tree had uncommitted changes, which the first five
//! gates saw and the user test did not. Build-host tool, run by build.zig from the repository root.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const scratch = ".zig-cache/zbx-check-tree";

/// What a Mac's check leaves out or does differently, said in its PASS line.
const mac_note = "linux tests compiled for aarch64-linux, not run; skipped on macOS: " ++
    "linux tests, VM harness run, test as tester";
const cache_note_bytes: u64 = 6 << 30;

/// Runs `argv` (in `cwd` if given) with its errors on stderr; fails unless it exits 0.
fn run(io: Io, argv: []const []const u8, cwd: ?[]const u8) !void {
    return run_shown(io, argv, cwd, .ignore);
}

/// `run`, with the command's standard output shown (`.inherit`) or dropped (`.ignore`).
fn run_shown(
    io: Io,
    argv: []const []const u8,
    cwd: ?[]const u8,
    stdout: std.process.SpawnOptions.StdIo,
) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .stdout = stdout,
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
    const fuzz = arguments.next() orelse return usage(err);
    const io = init.io;
    const gpa = init.arena.allocator();
    const commit = try output(gpa, io, &.{ "git", "rev-parse", "--short=12", "HEAD" });
    const porcelain = [_][]const u8{ "git", "status", "--porcelain", "--untracked-files=no" };
    const status = try output(gpa, io, &porcelain);
    const dirty: []const u8 = if (status.len > 0) "+dirty" else "";
    run_shown(io, &.{ fuzz, "all" }, null, .inherit) catch {
        try err.print("check: FAIL {s}{s} (a fuzzer: its seed is the last line above)\n", .{
            commit, dirty,
        });
        return 1;
    };
    const on_macos = builtin.os.tag == .macos;
    // On a Mac there is no `tester` user and no Linux kernel: the Linux tests are compiled for
    // aarch64-linux (so they cannot break unseen) but run only on Linux CI.
    if (on_macos) {
        run(io, &.{ zig, "build", "test", "-Dtarget=aarch64-linux" }, null) catch {
            const words = "the Linux tests do not compile";
            try err.print("check: FAIL {s}{s} ({s})\n", .{ commit, dirty, words });
            return 1;
        };
    }
    const as_user = !on_macos and !std.mem.eql(u8, user, "-") and std.os.linux.geteuid() == 0;
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
    note_cache(gpa, io, err);
    if (on_macos) {
        const gates = "build test tidy release errors-site harness fuzz";
        try err.print("check: PASS {s}{s} ({s}; {s})\n", .{ commit, dirty, gates, mac_note });
        return 0;
    }
    try err.print("check: PASS {s}{s} (build test tidy release errors-site harness fuzz{s})\n", .{
        commit, dirty, tail,
    });
    return 0;
}

/// Says so when `.zig-cache/o` is past `cache_note_bytes`. Every rebuild of a changed binary
/// adds a copy and nothing removes the old ones; emptying it costs one full rebuild.
fn note_cache(gpa: std.mem.Allocator, io: Io, err: *Io.Writer) void {
    const text = output(gpa, io, &.{ "du", "-sb", ".zig-cache/o" }) catch return;
    const end = std.mem.indexOfAny(u8, text, " \t") orelse return;
    const bytes = std.fmt.parseInt(u64, text[0..end], 10) catch return;
    if (bytes < cache_note_bytes) return;
    err.print("check: note: .zig-cache/o holds {d} MiB; outside a build, rm -rf .zig-cache\n", .{
        bytes >> 20,
    }) catch {};
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
    try err.print("usage: check <zig> <user|-> <fuzz>\n", .{});
    return 2;
}
