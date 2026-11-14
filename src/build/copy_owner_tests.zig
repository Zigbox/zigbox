//! Tests of a copy's `.chown` and `.chmod` on a selection tree (`copy_owner.zig`), against the
//! simulated store.

const std = @import("std");
const assemble = @import("assemble.zig");
const copy_owner = @import("copy_owner.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const layout = @import("../store/layout.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const fs_mod = @import("../store/fs.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var ws: copy_owner.Workspace = undefined;
var failure: assemble.Failure = undefined;
var buffer: [64 * 1024]u8 = undefined;
var io: [1 << 18]u8 = undefined;
var chunks: [4096]Digest = undefined;
var scratch: [4096]Digest = undefined;

const no_xattrs = tree.Own.none.xattrs;

fn start() copy_owner.Context {
    sim.init(1, &.{});
    files.init(1);
    files.put_dir("/s", 0o755);
    files.put_dir("/s/trees", 0o755);
    files.put_dir("/s/objects", 0o755);
    files.put_dir("/s/tmp", 0o755);
    files.put_dir("/src", 0o755);
    sim.store_fs = &files;
    store.at(sim.interface(), "/s");
    store.chunk_bytes = 4; // So a file of a few bytes has a stored chunk list.
    return .{ .store = &store, .failure = &failure };
}

const File = struct { size: u64, content: Digest, object: Digest };

/// A file object owned 0:0 with `mode`, put the way an import puts one.
fn put_file(name: []const u8, content: []const u8, mode: u16) !File {
    var path_buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrintSentinel(&path_buffer, "/src/{s}", .{name}, 0);
    files.put_file(path, mode, content);
    var reader = object.Reader.init(store.chunk_bytes);
    if (content.len > 0) try testing.expect(reader.update(content, &chunks));
    const hash = reader.finish(&chunks);
    const count = object.chunk_count(content.len, store.chunk_bytes);
    const attrs: object.Attrs = .{ .mode = mode, .uid = 0, .gid = 0, .xattrs = no_xattrs };
    const id = object.object_id(hash, attrs);
    const described: object.Content = .{
        .size = content.len,
        .hash = hash,
        .chunks = chunks[0..count],
    };
    var noted: object.Failure = undefined;
    try object.put(&store, &io, &scratch, path, &described, attrs, id, &noted);
    return .{ .size = content.len, .content = hash, .object = id };
}

const Item = union(enum) {
    file: struct { name: []const u8, file: File, mode: u16 = 0o644 },
    dir: struct { name: []const u8, child: Digest },
    symlink: struct { name: []const u8, target: []const u8 },
};

fn directory(items: []const Item, root: bool) !Digest {
    var writer = tree.Writer.init(&buffer);
    for (items) |item| switch (item) {
        .file => |f| {
            try writer.begin(f.name, .file, f.mode, 0, 0, no_xattrs);
            try writer.end_file(f.file.size, f.file.content, f.file.object);
        },
        .dir => |d| {
            try writer.begin(d.name, .dir, 0o755, 0, 0, no_xattrs);
            try writer.end_dir(d.child);
        },
        .symlink => |s| {
            try writer.begin(s.name, .symlink, 0o777, 0, 0, no_xattrs);
            try writer.end_symlink(s.target);
        },
    };
    const own: tree.Own = .{ .mode = 0o700, .uid = 0, .gid = 0, .xattrs = no_xattrs };
    const bytes = if (root) try writer.finish_with(own) else writer.finish();
    const digest = Digest.of(bytes);
    var noted: object.Failure = undefined;
    _ = try trees.put(&store, digest, bytes, &noted);
    return digest;
}

/// The entry `path` names below `root`.
fn entry_at(root: Digest, path: []const []const u8, out: *tree.Entry, own: ?*tree.Own) !void {
    var at = root;
    var read: [64 * 1024]u8 = undefined;
    var errno: u16 = 0;
    for (path, 0..) |part, depth| {
        var decoder: tree.Decoder = undefined;
        try decoder.init(try trees.load(&store, at, &read, &errno));
        var found = false;
        while (try decoder.next(out)) {
            if (!std.mem.eql(u8, out.name, part)) continue;
            found = true;
            break;
        }
        try testing.expect(found);
        if (depth + 1 < path.len) at = out.subtree;
    }
    if (own) |kept| {
        var decoder: tree.Decoder = undefined;
        try decoder.init(try trees.load(&store, root, &read, &errno));
        var entry: tree.Entry = undefined;
        while (try decoder.next(&entry)) {}
        kept.* = decoder.own;
    }
}

/// /app/ holding `a` (three chunks), `sub/b`, and `l` -> a: what `copy.select` makes of a copy
/// of a directory to `/app/`.
fn selection() !Digest {
    const a = try put_file("a", "0123456789", 0o644);
    const b = try put_file("b", "bee", 0o755);
    const sub = try directory(&.{.{ .file = .{ .name = "b", .file = b, .mode = 0o755 } }}, false);
    const app = try directory(&.{
        .{ .file = .{ .name = "a", .file = a } },
        .{ .symlink = .{ .name = "l", .target = "a" } },
        .{ .dir = .{ .name = "sub", .child = sub } },
    }, false);
    return directory(&.{.{ .dir = .{ .name = "app", .child = app } }}, true);
}

test "a stamp sets the owner on every kind and the mode on all but a symlink" {
    _ = start();
    const a = try put_file("a", "abc", 0o644);
    var file: tree.Entry = undefined;
    const root = try directory(&.{.{ .file = .{ .name = "a", .file = a } }}, true);
    try entry_at(root, &.{"a"}, &file, null);
    const stamp: copy_owner.Stamp = .{ .owner = .{ .uid = 1000, .gid = 1001 }, .mode = 0o600 };
    const result = copy_owner.stamped(&file, stamp);
    try testing.expectEqual(@as(u32, 1000), result.uid);
    try testing.expectEqual(@as(u32, 1001), result.gid);
    try testing.expectEqual(@as(u16, 0o600), result.mode);
    try testing.expect(!result.object.eql(file.object));
    try testing.expect(result.content.eql(file.content));
    // No change is the same object.
    const same = copy_owner.stamped(&file, .{ .mode = 0o644 });
    try testing.expect(same.object.eql(file.object));

    var link = file;
    link.kind = .symlink;
    link.mode = 0o777;
    link.target = "a";
    const linked = copy_owner.stamped(&link, stamp);
    try testing.expectEqual(@as(u16, 0o777), linked.mode);
    try testing.expectEqual(@as(u32, 1000), linked.uid);
}

test "a mode text is octal" {
    try testing.expectEqual(@as(u16, 0o755), copy_owner.mode_of("755"));
    try testing.expectEqual(@as(u16, 0o4750), copy_owner.mode_of("4750"));
    try testing.expectEqual(@as(u16, 0), copy_owner.mode_of("000"));
}

test "a restamp reaches every depth, keeps the mode of the way to .to, and writes owned objects" {
    const context = start();
    const root = try selection();
    const stamp: copy_owner.Stamp = .{ .owner = .{ .uid = 1000, .gid = 1000 }, .mode = 0o640 };
    const stamped = try copy_owner.restamp(context, &ws, root, "/app/", stamp);
    try testing.expect(!stamped.eql(root));
    var entry: tree.Entry = undefined;
    var own: tree.Own = undefined;
    // `/app` is the way to `.to`: the owner, but not the mode.
    try entry_at(stamped, &.{"app"}, &entry, &own);
    try testing.expectEqual(@as(u16, 0o755), entry.mode);
    try testing.expectEqual(@as(u32, 1000), entry.uid);
    // The root keeps its own attributes.
    try testing.expectEqual(@as(u16, 0o700), own.mode);
    try testing.expectEqual(@as(u32, 0), own.uid);
    // What the patterns took has both, at any depth.
    try entry_at(stamped, &.{ "app", "sub" }, &entry, null);
    try testing.expectEqual(@as(u16, 0o640), entry.mode);
    try entry_at(stamped, &.{ "app", "l" }, &entry, null);
    try testing.expectEqual(@as(u16, 0o777), entry.mode);
    try testing.expectEqual(@as(u32, 1000), entry.gid);
    const names = [_][]const []const u8{ &.{ "app", "a" }, &.{ "app", "sub", "b" } };
    for (names) |path| {
        try entry_at(stamped, path, &entry, null);
        try testing.expectEqual(@as(u16, 0o640), entry.mode);
        try testing.expectEqual(@as(u32, 1000), entry.uid);
        const attrs: object.Attrs = .{
            .mode = 0o640,
            .uid = 1000,
            .gid = 1000,
            .xattrs = no_xattrs,
        };
        try testing.expect(entry.object.eql(object.object_id(entry.content, attrs)));
        // The object is in the store, with the owner and the mode, and its chunks.
        var path_buffer: fs_mod.PathBuf = undefined;
        const stat = files.stat_of(store.object_path(&path_buffer, entry.object)).?;
        try testing.expectEqual(@as(u32, 1000), stat.uid);
        try testing.expectEqual(@as(u16, 0o640), stat.mode & 0o7777);
        const listed = try object.chunk_hashes(&store, entry.object, &io, &chunks);
        try testing.expectEqual(object.chunk_count(entry.size, store.chunk_bytes), listed.len);
    }
    try testing.expectEqual(@as(u32, 2), ws.objects_written);
    // Again: the same tree, and nothing written.
    try testing.expect((try copy_owner.restamp(context, &ws, root, "/app/", stamp)).eql(stamped));
    try testing.expectEqual(@as(u32, 0), ws.objects_written);
}

test "a mode alone keeps the owners, and a file to a name stamps that file" {
    const context = start();
    const a = try put_file("a", "abc", 0o644);
    const app = try directory(&.{.{ .file = .{ .name = "run", .file = a } }}, false);
    const root = try directory(&.{.{ .dir = .{ .name = "app", .child = app } }}, true);
    const stamped = try copy_owner.restamp(context, &ws, root, "/app/run", .{ .mode = 0o700 });
    var entry: tree.Entry = undefined;
    try entry_at(stamped, &.{ "app", "run" }, &entry, null);
    try testing.expectEqual(@as(u16, 0o700), entry.mode);
    try testing.expectEqual(@as(u32, 0), entry.uid);
    try entry_at(stamped, &.{"app"}, &entry, null);
    try testing.expectEqual(@as(u16, 0o755), entry.mode);
}

test "a source object that no longer matches its content is a damaged tree, not a new object" {
    const context = start();
    const root = try selection();
    var entry: tree.Entry = undefined;
    try entry_at(root, &.{ "app", "a" }, &entry, null);
    var path_buffer: fs_mod.PathBuf = undefined;
    files.flip_byte_quietly(store.object_path(&path_buffer, entry.object), 0);
    const stamp: copy_owner.Stamp = .{ .owner = .{ .uid = 7, .gid = 7 } };
    try testing.expectError(error.Failed, copy_owner.restamp(context, &ws, root, "/app/", stamp));
    try testing.expect(failure == .damaged);
    try testing.expect(failure.damaged.eql(entry.object));
}

test "a tree the store lacks is damaged or unreadable, never a crash" {
    const context = start();
    const missing = Digest.of("no such tree");
    const stamp: copy_owner.Stamp = .{ .mode = 0o600 };
    try testing.expectError(error.Failed, copy_owner.restamp(context, &ws, missing, "/x", stamp));
    try testing.expect(failure == .io or failure == .damaged);
}
