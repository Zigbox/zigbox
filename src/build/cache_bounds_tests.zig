//! The build cache's entry bound that the simulator cannot reach (it holds 640 nodes): gc
//! follows exactly `build_cache_entries_max` entries and refuses one more, on a real kernel in
//! /tmp. The entries are empty files named like keys, so each is malformed and roots nothing.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const host_real = @import("../host_real.zig");
const gc = @import("../store/gc.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const remove = @import("../store/remove.zig");

const testing = std.testing;

var real: host_real.HostReal = .{};
var store: layout.Store = undefined;
var gc_workspace: gc.Workspace = undefined;
var gc_tables: [16 * 1024 * 1024]u8 align(8) = @splat(0);
var import_workspace: import.Workspace = undefined;
var remove_workspace: remove.Workspace = undefined;
var remove_arena: [remove.arena_bytes]u8 = undefined;

fn ok(result: usize) bool {
    return linux.errno(result) == .SUCCESS;
}

/// Creates `count` empty entries in `directory`, named by their index in 64 hex digits.
fn make_entries(directory: i32, count: u32) !void {
    var name: [64:0]u8 = undefined;
    for (0..count) |index| {
        // Cannot fail: 64 digits fit.
        _ = std.fmt.bufPrint(&name, "{x:0>64}", .{index}) catch unreachable;
        name[64] = 0;
        const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true };
        const opened = linux.openat(directory, &name, flags, 0o644);
        try testing.expect(ok(opened));
        _ = linux.close(@intCast(opened));
    }
}

fn plan_with(tag: []const u8, count: u32) !?gc.Failure {
    var storage: [96:0]u8 = @splat(0);
    const base = try std.fmt.bufPrint(&storage, "/tmp/zbx-cache-{s}-{d}", .{ tag, linux.getpid() });
    const fs = real.interface().filesystem();
    defer {
        var failed: remove.Failure = undefined;
        const where = storage[0..base.len :0];
        remove.tree(fs, &remove_workspace, &remove_arena, where, &failed) catch {};
    }
    var path: [128:0]u8 = @splat(0);
    try fs.make_directory(storage[0..base.len :0], true);
    const parts = [_][]const u8{
        "", "/objects", "/trees", "/roots", "/cache", "/trash", "/tmp", "/build", "/build/cache",
    };
    for (parts) |name| {
        const made = try std.fmt.bufPrint(&path, "{s}{s}", .{ base, name });
        path[made.len] = 0;
        try fs.make_directory(path[0..made.len :0], true);
    }
    store.at(real.interface(), storage[0..base.len]);
    const made = try std.fmt.bufPrint(&path, "{s}/build/cache", .{base});
    path[made.len] = 0;
    const opened = linux.open(path[0..made.len :0], .{ .DIRECTORY = true, .CLOEXEC = true }, 0);
    try testing.expect(ok(opened));
    defer _ = linux.close(@intCast(opened));
    try make_entries(@intCast(opened), count);
    gc_workspace.tables = &gc_tables;
    var result: gc.Plan = undefined;
    var failed: gc.Failure = undefined;
    const arena = &import_workspace.arena;
    gc.plan(&store, &gc_workspace, arena, &.{}, &result, &failed) catch return failed;
    return null;
}

test "gc follows build_cache_entries_max entries and refuses one more" {
    comptime assert(constants.build_cache_entries_max == 8192);
    const at_bound = try plan_with("at", constants.build_cache_entries_max);
    try testing.expectEqual(@as(?gc.Failure, null), at_bound);
    const past = try plan_with("past", constants.build_cache_entries_max + 1);
    try testing.expect(past != null);
    try testing.expect(past.? == .too_big);
}
