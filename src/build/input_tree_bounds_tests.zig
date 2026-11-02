//! The input tree's bounds that the simulator cannot reach, on a real kernel in /tmp: a path
//! of 4095 bytes below the project, a directory whose tree is exactly 4 MiB, and a chain of
//! directories whose names fill the import's arena. Each is tested at its bound and past it.
//! The depth bound is tested in the simulator (`input_tree_tests.zig`).

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_real = @import("../host_real.zig");
const file_mod = @import("file.zig");
const inputs_mod = @import("inputs.zig");
const input_tree = @import("input_tree.zig");
const digest_mod = @import("../store/digest.zig");
const layout = @import("../store/layout.zig");
const remove = @import("../store/remove.zig");
const tree = @import("../store/tree.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var real: host_real.HostReal = .{};
var store: layout.Store = undefined;
var workspace: input_tree.Workspace = undefined;
var remove_workspace: remove.Workspace = undefined;
var remove_arena: [remove.arena_bytes]u8 = undefined;
var diag: Diag = undefined;
var build_file: file_mod.BuildFile = undefined;
var problem: inputs_mod.Problem = undefined;

/// A scratch directory in /tmp with a store and a project `p`, removed by `finish`.
const Scratch = struct {
    base: [64:0]u8,
    base_len: u32,
    /// The project, open for building its contents with `*at` calls.
    project: i32,

    fn start(scratch: *Scratch, tag: []const u8) !void {
        const fs = real.interface().filesystem();
        scratch.base = @splat(0);
        const text = try std.fmt.bufPrint(&scratch.base, "/tmp/zbx-input-{s}-{d}", .{
            tag,
            linux.getpid(),
        });
        scratch.base_len = @intCast(text.len);
        try fs.make_directory(scratch.path(""), true);
        try fs.make_directory(scratch.path("/store"), true);
        for ([_][]const u8{ "objects", "trees", "roots", "cache", "trash", "tmp" }) |name| {
            var storage: [96:0]u8 = @splat(0);
            const where = try std.fmt.bufPrint(&storage, "{s}/store/{s}", .{ text, name });
            try fs.make_directory(storage[0..where.len :0], true);
        }
        store.at(real.interface(), scratch.path("/store"));
        try fs.make_directory(scratch.path("/p"), true);
        const opened = linux.open(scratch.path("/p"), .{ .DIRECTORY = true, .CLOEXEC = true }, 0);
        try testing.expect(ok(opened));
        scratch.project = @intCast(opened);
    }

    var path_storage: [96:0]u8 = undefined;

    fn path(scratch: *const Scratch, suffix: []const u8) [:0]const u8 {
        assert(scratch.base_len + suffix.len < path_storage.len);
        const base = scratch.base[0..scratch.base_len];
        path_storage = @splat(0);
        @memcpy(path_storage[0..base.len], base);
        @memcpy(path_storage[base.len..][0..suffix.len], suffix);
        return path_storage[0 .. base.len + suffix.len :0];
    }

    fn finish(scratch: *Scratch) void {
        _ = linux.close(scratch.project);
        var failure: remove.Failure = undefined;
        const fs = real.interface().filesystem();
        remove.tree(fs, &remove_workspace, &remove_arena, scratch.path(""), &failure) catch {};
    }
};

fn ok(result: usize) bool {
    return linux.errno(result) == .SUCCESS;
}

fn parse(input: []const u8) void {
    var text: [256]u8 = undefined;
    const written = std.fmt.bufPrint(&text, ".{{ .version = 1, .image = .{{}}, .steps = .{{ " ++
        ".{{ .name = \"s\", .base = \"b\", .run = .{{\"x\"}}, .inputs = .{{\"{s}\"}} }} }} }}", .{
        input,
    }) catch unreachable; // Short.
    var parse_problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(written, &build_file, &parse_problem);
    assert(parsed == .parsed);
}

fn import_inputs(scratch: *const Scratch) input_tree.Error!Digest {
    const fs = store.fs;
    const project = fs.open_directory(scratch.path("/p")) catch unreachable; // `start` made it.
    defer fs.close(project);
    diag.reset();
    const request: input_tree.Request = .{
        .store = &store,
        .project = project,
        .file = &build_file,
        .step = 0,
    };
    return input_tree.import(request, &workspace, &problem, &diag);
}

fn expect_limit(words: []const u8) !void {
    try testing.expectEqual(@as(?@TypeOf(diag.code.?), .E0415), diag.code);
    try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, words) != null);
}

/// A name of `len` bytes that is unique for `index`: the index in six digits, then `x`s.
fn name_of(storage: *[256:0]u8, index: u32, len: u32) [:0]const u8 {
    assert(len >= 6);
    assert(len <= constants.store_name_bytes_max);
    storage.* = @splat(0);
    _ = std.fmt.bufPrint(storage, "{d:0>6}", .{index}) catch unreachable; // Six digits.
    @memset(storage[6..len], 'x');
    return storage[0..len :0];
}

/// `count` links in the directory `directory`, each with the one-byte target `t`; the first
/// `short` names are 254 bytes and the rest `len`.
fn make_links(directory: i32, count: u32, short: u32, len: u32) !void {
    var storage: [256:0]u8 = undefined;
    for (0..count) |index| {
        const name = name_of(&storage, @intCast(index), if (index < short) len - 1 else len);
        try testing.expect(ok(linux.symlinkat("t", directory, name)));
    }
}

fn make_directory_at(directory: i32, name: [:0]const u8) !i32 {
    try testing.expect(ok(linux.mkdirat(directory, name, 0o755)));
    const opened = linux.openat(directory, name, .{ .DIRECTORY = true, .CLOEXEC = true }, 0);
    try testing.expect(ok(opened));
    return @intCast(opened);
}

test "real kernel: a path of 4095 bytes below the project imports, and 4096 is E0415" {
    // Goal: the path bound is exact for an entry found inside a directory input. Method: `d`
    // holds 15 directories of 255-byte names and a last one of 253 bytes, 4095 bytes in all;
    // then the last one is renamed to 254 bytes. The absolute path is longer than the kernel
    // takes, so the chain is made, and taken apart, one directory at a time.
    for ([_]u32{ 253, 254 }) |last| {
        var scratch: Scratch = undefined;
        try scratch.start("path");
        defer scratch.finish();
        parse("d");
        var fds: [17]i32 = undefined;
        var names: [17][256:0]u8 = undefined;
        fds[0] = try make_directory_at(scratch.project, "d");
        names[0] = @splat(0);
        names[0][0] = 'd';
        var length: u32 = 1;
        for (1..17) |level| {
            const len: u32 = if (level == 16) last else constants.store_name_bytes_max;
            const name = name_of(&names[level], @intCast(level), len);
            fds[level] = try make_directory_at(fds[level - 1], name);
            length += 1 + len;
        }
        defer {
            var level: u32 = 16;
            while (level > 0) : (level -= 1) {
                _ = linux.close(fds[level]);
                const name: [*:0]const u8 = &names[level];
                _ = linux.unlinkat(fds[level - 1], name, linux.AT.REMOVEDIR);
            }
            _ = linux.close(fds[0]);
        }
        try testing.expectEqual(@as(u32, constants.path_bytes_max - 253 + last), length);
        if (length <= constants.path_bytes_max) {
            _ = try import_inputs(&scratch);
        } else {
            try testing.expectError(error.Failed, import_inputs(&scratch));
            try expect_limit("longer than 4095 bytes");
        }
        try testing.expectEqual(@as(u32, 0), real.open_count);
    }
}

test "real kernel: a directory whose tree is exactly 4 MiB imports, and one byte more is E0415" {
    // Goal: the tree bound is exact. Method: links with a one-byte target encode to 16 bytes
    // and their name (kind, mode, owner, name length, empty xattrs, target length and target).
    // Enough of them, most named with 255 bytes and some with 254, fill the tree to the byte.
    // Then one 254-byte name becomes 255.
    const entry_bytes = 1 + 2 + 4 + 4 + 1 + 1 + 2 + 1;
    const room = constants.store_tree_bytes_max - tree.header_bytes - tree.own_bytes_min;
    const long = constants.store_name_bytes_max;
    const count: u32 = room / (entry_bytes + long) + 1;
    const short: u32 = count * (entry_bytes + long) - room;
    comptime assert(short < count);
    comptime assert(count < constants.store_dir_entries_max);
    for ([_]u32{ short, short - 1 }) |shorter| {
        var scratch: Scratch = undefined;
        try scratch.start("tree");
        defer scratch.finish();
        parse("t");
        const directory = try make_directory_at(scratch.project, "t");
        try make_links(directory, count, shorter, long);
        _ = linux.close(directory);
        if (shorter == short) {
            _ = try import_inputs(&scratch);
        } else {
            try testing.expectError(error.Failed, import_inputs(&scratch));
            try expect_limit("encode to more than 4 MiB");
        }
        try testing.expectEqual(@as(u32, 0), real.open_count);
    }
}

test "real kernel: names that fill the import's arena are E0415, and a level fewer imports" {
    // Goal: an import that needs more than its 16 MiB of working memory is refused as that,
    // not as a tree too large. Method: a chain of directories, each holding 16000 links with
    // 240-byte names (3.9 MiB of names, a 3.9 MiB tree) and the next directory, `0`, which is
    // read first. Every level holds its names while the levels below it are read, so three
    // levels fit and four do not. The arena is several regions, so its bound is shown a level
    // apart rather than to the byte.
    for ([_]u32{ 3, 4 }) |levels| {
        var scratch: Scratch = undefined;
        try scratch.start("arena");
        defer scratch.finish();
        parse("0");
        var directory = scratch.project;
        for (0..levels) |_| {
            const next = try make_directory_at(directory, "0");
            if (directory != scratch.project) _ = linux.close(directory);
            directory = next;
            try make_links(directory, 16000, 0, 240);
        }
        _ = linux.close(directory);
        if (levels == 3) {
            _ = try import_inputs(&scratch);
        } else {
            try testing.expectError(error.Failed, import_inputs(&scratch));
            try expect_limit("more working memory than the 16 MiB");
        }
        try testing.expectEqual(@as(u32, 0), real.open_count);
    }
}
