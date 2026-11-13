//! A copy's selection and replace-merge (`copy.zig`, `assemble.zig` with `replace`) on trees in
//! the simulated store: what the patterns take, where it lands, and what a later copy replaces.

const std = @import("std");
const assemble = @import("assemble.zig");
const copy = @import("copy.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const layout = @import("../store/layout.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const object = @import("../store/object.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var ws: copy.Workspace = undefined;
var failure: assemble.Failure = undefined;
var buffer: [64 * 1024]u8 = undefined;

const Item = struct {
    name: []const u8,
    child: ?Digest = null,
    content: []const u8 = "",
};

fn start() assemble.Context {
    sim.init(1, &.{});
    files.init(1);
    files.put_dir("/s", 0o755);
    files.put_dir("/s/trees", 0o755);
    files.put_dir("/s/tmp", 0o755);
    sim.store_fs = &files;
    store.at(sim.interface(), "/s");
    return .{ .store = &store, .ws = &ws.assemble, .failure = &failure };
}

fn directory(items: []const Item, root: bool) !Digest {
    var writer = tree.Writer.init(&buffer);
    for (items) |item| {
        const kind: tree.Kind = if (item.child != null) .dir else .file;
        const mode: u16 = if (item.child != null) 0o755 else 0o644;
        try writer.begin(item.name, kind, mode, 0, 0, tree.Own.none.xattrs);
        if (item.child) |child| {
            try writer.end_dir(child);
        } else {
            const content = Digest.of(item.content);
            try writer.end_file(item.content.len, content, content);
        }
    }
    const own: tree.Own = .{ .mode = 0o700, .uid = 0, .gid = 0, .xattrs = tree.Own.none.xattrs };
    const bytes = if (root) try writer.finish_with(own) else writer.finish();
    const digest = Digest.of(bytes);
    var noted: object.Failure = undefined;
    _ = try trees.put(&store, digest, bytes, &noted);
    return digest;
}

/// The names under `path`, as "name name ...", or "-" when the path is not there.
fn names_at(root: Digest, path: []const []const u8, out: []u8) ![]const u8 {
    var at = root;
    var read: [64 * 1024]u8 = undefined;
    var errno: u16 = 0;
    for (path) |part| {
        var decoder: tree.Decoder = undefined;
        try decoder.init(try trees.load(&store, at, &read, &errno));
        var entry: tree.Entry = undefined;
        var found = false;
        while (try decoder.next(&entry)) {
            if (std.mem.eql(u8, entry.name, part) and entry.kind == .dir) {
                at = entry.subtree;
                found = true;
            }
        }
        if (!found) return "-";
    }
    var decoder: tree.Decoder = undefined;
    try decoder.init(try trees.load(&store, at, &read, &errno));
    var entry: tree.Entry = undefined;
    var length: usize = 0;
    while (try decoder.next(&entry)) {
        const text = try std.fmt.bufPrint(out[length..], "{s} ", .{entry.name});
        length += text.len;
    }
    return std.mem.trimEnd(u8, out[0..length], " ");
}

/// The content of the file at `path`, found by its content hash among `candidates`.
fn is_content(root: Digest, path: []const []const u8, content: []const u8) !bool {
    var at = root;
    var read: [64 * 1024]u8 = undefined;
    var errno: u16 = 0;
    for (path, 0..) |part, index| {
        var decoder: tree.Decoder = undefined;
        try decoder.init(try trees.load(&store, at, &read, &errno));
        var entry: tree.Entry = undefined;
        while (try decoder.next(&entry)) {
            if (!std.mem.eql(u8, entry.name, part)) continue;
            if (index + 1 == path.len) return entry.content.eql(Digest.of(content));
            at = entry.subtree;
            break;
        } else return false;
    }
    return false;
}

fn source_tree() !Digest {
    const sub = try directory(&.{.{ .name = "c.go", .content = "c" }}, false);
    const src = try directory(&.{
        .{ .name = "a.go", .content = "a" },
        .{ .name = "b.go", .content = "b" },
        .{ .name = "notes.txt", .content = "n" },
        .{ .name = "sub", .child = sub },
    }, false);
    return directory(&.{
        .{ .name = "README", .content = "r" },
        .{ .name = "src", .child = src },
    }, true);
}

test "a glob takes the matching files into a destination that ends in a slash" {
    // Goal: file matches go to `to/<name>`. Method: `src/*.go` to `/app/`; the two Go files are
    // there, the notes and the subdirectory are not, and the same selection is the same digest.
    const context = start();
    const source = try source_tree();
    const patterns = [_][]const u8{"src/*.go"};
    const selected = try copy.select(context, &ws, source, &patterns, "/app/");
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("a.go b.go", try names_at(selected, &.{"app"}, &text));
    const again = try copy.select(context, &ws, source, &patterns, "/app/");
    try testing.expect(again.eql(selected));
}

test "a directory source puts its contents, not itself, into the destination" {
    // Goal: Docker's rule for a directory. Method: `src` to `/app`; its four entries are in
    // /app, there is no /app/src.
    const context = start();
    const source = try source_tree();
    const selected = try copy.select(context, &ws, source, &.{"/src/"}, "/app");
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("a.go b.go notes.txt sub", try names_at(selected, &.{"app"}, &text));
}

test "a file to a destination without a slash is renamed, and the whole tree is `.`" {
    // Goal: the two other layouts. Method: README to /etc/readme; `.` to /srv.
    const context = start();
    const source = try source_tree();
    const renamed = try copy.select(context, &ws, source, &.{"README"}, "/etc/readme");
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("readme", try names_at(renamed, &.{"etc"}, &text));
    const whole = try copy.select(context, &ws, source, &.{"."}, "/srv");
    try testing.expectEqualStrings("README src", try names_at(whole, &.{"srv"}, &text));
}

test "nothing matched is NoMatch" {
    // Goal: the empty selection is refused, not an empty copy. Method: a pattern with no match.
    const context = start();
    const source = try source_tree();
    try testing.expectError(error.NoMatch, copy.select(context, &ws, source, &.{"src/*.rs"}, "/x/"));
}

test "a later copy replaces a file and merges a directory; a plain add still conflicts" {
    // Goal: the replace-merge. Method: the base has /app/a.go "old" and /app/keep; a copy brings
    // /app/a.go "a": the file is replaced, `keep` stays; without `replace` it is a conflict.
    var context = start();
    const source = try source_tree();
    const base_app = try directory(&.{
        .{ .name = "a.go", .content = "old" },
        .{ .name = "keep", .content = "k" },
    }, false);
    const base = try directory(&.{.{ .name = "app", .child = base_app }}, true);
    const selected = try copy.select(context, &ws, source, &.{"src/*.go"}, "/app/");
    context.replace = true;
    const adds = [_]assemble.Add{.{ .source = selected, .to = "/" }};
    const image = try assemble.assemble(context, base, &adds);
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("a.go b.go keep", try names_at(image, &.{"app"}, &text));
    try testing.expect(try is_content(image, &.{ "app", "a.go" }, "a"));
    context.replace = false;
    try testing.expectError(error.Failed, assemble.assemble(context, base, &adds));
    try testing.expect(failure == .conflict);
}

test "a file replaces a directory and a directory replaces a file" {
    // Goal: the kinds that differ replace each other under `replace`. Method: /x is a file in
    // the base and a directory in the copy, and /y the other way round.
    var context = start();
    const inner = try directory(&.{.{ .name = "n", .content = "n" }}, false);
    const base = try directory(&.{
        .{ .name = "x", .content = "file" },
        .{ .name = "y", .child = inner },
    }, true);
    const brought = try directory(&.{
        .{ .name = "x", .child = inner },
        .{ .name = "y", .content = "file" },
    }, true);
    context.replace = true;
    const image = try assemble.assemble(context, base, &.{.{ .source = brought, .to = "/" }});
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("n", try names_at(image, &.{"x"}, &text));
    try testing.expectEqualStrings("-", try names_at(image, &.{"y"}, &text));
    try testing.expect(try is_content(image, &.{"y"}, "file"));
}
