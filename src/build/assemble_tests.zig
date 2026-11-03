//! Image assembly (`assemble.zig`) on trees in the simulated store: merges, the directories it
//! makes, conflicts with their paths, and the bounds.

const std = @import("std");
const constants = @import("../constants.zig");
const assemble = @import("assemble.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const layout = @import("../store/layout.zig");
const tree = @import("../store/tree.zig");
const diagnose = @import("diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const trees = @import("../store/trees.zig");
const object = @import("../store/object.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var ws: assemble.Workspace = undefined;
var failure: assemble.Failure = undefined;
var buffer: [64 * 1024]u8 = undefined;

const Item = struct {
    name: []const u8,
    child: ?Digest = null,
    content: []const u8 = "",
    mode: u16 = 0o644,
};

fn start() assemble.Context {
    sim.init(1, &.{});
    files.init(1);
    files.put_dir("/s", 0o755);
    files.put_dir("/s/trees", 0o755);
    files.put_dir("/s/tmp", 0o755);
    sim.store_fs = &files;
    store.at(sim.interface(), "/s");
    return .{ .store = &store, .ws = &ws, .failure = &failure };
}

/// A directory of `items` (a directory when it has a child), written to the store.
fn directory(items: []const Item, root: bool) !Digest {
    var writer = tree.Writer.init(&buffer);
    for (items) |item| {
        const kind: tree.Kind = if (item.child != null) .dir else .file;
        const mode: u16 = if (item.child != null) 0o755 else item.mode;
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

/// The entries of the tree at `path`, as "name name ...".
fn names_at(root: Digest, path: []const []const u8, out: []u8) ![]const u8 {
    var at = root;
    var read: [64 * 1024]u8 = undefined;
    var errno: u16 = 0;
    for (path) |part| {
        var decoder: tree.Decoder = undefined;
        try decoder.init(try trees.load(&store, at, &read, &errno));
        var entry: tree.Entry = undefined;
        while (try decoder.next(&entry)) {
            if (std.mem.eql(u8, entry.name, part)) at = entry.subtree;
        }
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

test "an add merges into a directory the base has and makes the ones it lacks" {
    // Goal: the splice. Method: a base with /usr/bin/sh; add one tree at /usr/local/bin and one
    // at /; the base's file stays, the new file and the made directories are there.
    const context = start();
    const bin = try directory(&.{.{ .name = "sh", .content = "sh" }}, false);
    const usr = try directory(&.{.{ .name = "bin", .child = bin }}, false);
    const base = try directory(&.{.{ .name = "usr", .child = usr }}, true);
    const out = try directory(&.{.{ .name = "hello", .content = "hi", .mode = 0o755 }}, true);
    const notice = try directory(&.{.{ .name = "VERSION", .content = "1" }}, true);
    const adds = [_]assemble.Add{
        .{ .source = out, .to = "/usr/local/bin" },
        .{ .source = notice, .to = "/" },
    };
    const image = try assemble.assemble(context, base, &adds);
    var text: [256]u8 = undefined;
    try testing.expectEqualStrings("VERSION usr", try names_at(image, &.{}, &text));
    try testing.expectEqualStrings("bin local", try names_at(image, &.{"usr"}, &text));
    const deep = try names_at(image, &.{ "usr", "local", "bin" }, &text);
    try testing.expectEqualStrings("hello", deep);
    try testing.expectEqualStrings("sh", try names_at(image, &.{ "usr", "bin" }, &text));
    const again = try assemble.assemble(context, base, &adds);
    try testing.expect(again.eql(image)); // A function of its inputs only.
}

test "an empty base takes an add at the root" {
    // Goal: no base. Method: assemble one add onto nothing; the tree has the add's entries.
    const context = start();
    const out = try directory(&.{.{ .name = "a", .content = "a" }}, true);
    const image = try assemble.assemble(context, null, &.{.{ .source = out, .to = "/" }});
    var text: [64]u8 = undefined;
    try testing.expectEqualStrings("a", try names_at(image, &.{}, &text));
}

test "a file both trees have is a conflict that names its path and kinds" {
    // Goal: E0807's data. Method: /usr/bin/sh in the base and in an add at /usr.
    const context = start();
    const bin = try directory(&.{.{ .name = "sh", .content = "sh" }}, false);
    const usr = try directory(&.{.{ .name = "bin", .child = bin }}, false);
    const base = try directory(&.{.{ .name = "usr", .child = usr }}, true);
    const other = try directory(&.{.{ .name = "bin", .child = bin }}, true);
    const clash = try directory(&.{.{ .name = "bin", .child = other }}, true);
    _ = clash;
    const wrong = try directory(&.{.{ .name = "sh", .content = "different" }}, true);
    const result = assemble.assemble(context, base, &.{.{ .source = wrong, .to = "/usr/bin" }});
    try testing.expectError(error.Failed, result);
    const found = failure.conflict;
    try testing.expectEqualStrings("/usr/bin/sh", found.path[0..found.path_len]);
    try testing.expect(found.present == .file and found.brought == .file);
}

test "a directory where the base has a file is a conflict" {
    // Goal: kinds that differ. Method: /x is a file in the base, a directory in the add.
    const context = start();
    const base = try directory(&.{.{ .name = "x", .content = "x" }}, true);
    const inner = try directory(&.{.{ .name = "y", .content = "y" }}, false);
    const out = try directory(&.{.{ .name = "x", .child = inner }}, true);
    const fine = try directory(&.{.{ .name = "q", .content = "q" }}, true);
    const result = assemble.assemble(context, base, &.{
        .{ .source = fine, .to = "/" },
        .{ .source = out, .to = "/" },
    });
    try testing.expectError(error.Failed, result);
    try testing.expectEqual(1, ws.failed_add); // The second add is the one that clashes.
    try testing.expect(failure.conflict.present == .file);
    try testing.expect(failure.conflict.brought == .dir);
}

test "a path deeper than the store allows is refused" {
    // Goal: the depth bound, at and past it. Method: a path of 64 parts is built; 66 is refused.
    const context = start();
    const out = try directory(&.{.{ .name = "a", .content = "a" }}, true);
    var path: [2 * 70]u8 = undefined;
    var length: usize = 0;
    for (0..66) |_| {
        path[length] = '/';
        path[length + 1] = 'd';
        length += 2;
    }
    const deep = assemble.assemble(context, null, &.{.{ .source = out, .to = path[0..length] }});
    try testing.expectError(error.Failed, deep);
    try testing.expect(failure == .too_deep);
    const shallow: assemble.Add = .{ .source = out, .to = path[0 .. 2 * 60] };
    const ok = try assemble.assemble(context, null, &.{shallow});
    try testing.expect(ok.bytes[0] != 0 or ok.bytes[1] != 0);
}

/// A root with `count` directories `d000`.., each holding the file `name`.
fn many_dirs(count: usize, name: []const u8) !Digest {
    var items: [constants.build_merge_common_max + 1]Item = undefined;
    var names: [constants.build_merge_common_max + 1][4]u8 = undefined;
    const child = try directory(&.{.{ .name = name, .content = name }}, false);
    for (0..count) |at| {
        _ = std.fmt.bufPrint(&names[at], "d{d:0>3}", .{at}) catch unreachable; // Four bytes.
        items[at] = .{ .name = &names[at], .child = child };
    }
    return directory(items[0..count], true);
}

test "directories in common are bounded: at the bound merges, past it is refused" {
    // Goal: `build_merge_common_max`. Method: two roots with that many common differing
    // directories merge; one more is `too_common`.
    const context = start();
    const limit = constants.build_merge_common_max;
    const base = try many_dirs(limit, "a");
    const add = try many_dirs(limit, "b");
    const merged = try assemble.assemble(context, base, &.{.{ .source = add, .to = "/" }});
    var text: [8]u8 = undefined;
    try testing.expectEqualStrings("a b", try names_at(merged, &.{"d000"}, &text));
    const past_base = try many_dirs(limit + 1, "a");
    const past_add = try many_dirs(limit + 1, "b");
    const past = assemble.assemble(context, past_base, &.{.{ .source = past_add, .to = "/" }});
    try testing.expectError(error.Failed, past);
    try testing.expect(failure == .too_common);
}

test "a conflict reads as one E0807 line naming the path, the add and the kinds" {
    // Goal: the user-facing text. Method: raise the diagnostic for the /usr/bin/sh clash.
    const context = start();
    const base = try directory(&.{.{ .name = "sh", .content = "sh" }}, true);
    const wrong = try directory(&.{.{ .name = "sh", .content = "other" }}, true);
    const result = assemble.assemble(context, base, &.{.{ .source = wrong, .to = "/" }});
    try testing.expectError(error.Failed, result);
    var diag: Diag = undefined;
    diag.reset();
    diagnose.assembly_refused(&diag, &failure, ws.failed_add, "compile", "/");
    try testing.expectEqual(.E0807, diag.code.?);
    const cause = diag.last_cause().?;
    const expected = "the image already has a file at /sh; .image.add compile -> / brings a file";
    try testing.expectEqualStrings(expected, cause);
    diag.reset();
    diagnose.config_too_large(&diag, .labels);
    try testing.expectEqual(.E0807, diag.code.?);
}
