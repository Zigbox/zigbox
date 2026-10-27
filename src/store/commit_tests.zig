//! Tests of a commit (`import.commit`) and of `diff.zig` against the simulated file system.
//!
//! The oracle of a commit is an import: applying an upper layer to a parent tree must give the
//! digest of importing the directory that the overlay would show, which the test builds by hand
//! and independently of the merge. The oracle of a diff is the list the test knows it made.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const constants = @import("../constants.zig");
const diff = @import("diff.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const support = @import("test_support.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const Store = layout.Store;

const root_path = "/data/store";

var sim: HostSim = undefined;
var files: SimFs = undefined;
var store: Store = undefined;
var workspace: import.Workspace = undefined;
var diff_workspace: diff.Workspace = undefined;
var diag: Diag = undefined;

fn start() Digest {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    support.make_source(&files, 0);
    return import_directory("/src");
}

fn import_directory(path: []const u8) Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(&store, &workspace, path, options, &result, &diag) catch {
        unreachable; // The sample trees import.
    };
    return result.digest;
}

fn commit_upper(path: []const u8, parent: Digest) import.Error!import.Result {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null, .parent = parent };
    try import.commit(&store, &workspace, path, options, &result, &diag);
    return result;
}

/// An upper layer whose root is the sample's root, as the overlay's would be.
fn make_upper(path: []const u8) void {
    files.put_dir(path, 0o755);
}

fn put_whiteout_device(path: []const u8) void {
    files.put(path, .char_device, 0o000, .{ 0, 0 }, "");
}

test "a commit gives the digest of the tree the overlay shows" {
    // Goal: the merge. Method: an upper layer that modifies, adds, deletes (as a 0/0 device and
    // as a marked file), replaces a directory (opaque), and changes a mode; the expected tree
    // is built by hand as a plain directory and imported. The digests must agree.
    const parent = start();
    make_upper("/upper");
    files.put_dir("/upper/bin", 0o755);
    files.put_file("/upper/bin/sh", 0o755, "#!newer shell\n");
    files.put_file("/upper/bin/new", 0o644, "fresh\n");
    put_whiteout_device("/upper/bin/ls");
    files.put_file("/upper/bin/su", 0o000, "");
    files.put_xattr("/upper/bin/su", "user.overlay.whiteout", "");
    files.put_dir("/upper/etc", 0o755);
    files.put_xattr("/upper/etc", "user.overlay.opaque", "y");
    files.put_file("/upper/etc/hosts", 0o644, "localhost\n");
    files.put_dir("/upper/empty", 0o750);
    // What the container sees.
    build_expected();
    const expected = import_directory("/expect");
    const result = try commit_upper("/upper", parent);
    try testing.expect(result.digest.eql(expected));
    try testing.expect(!result.digest.eql(parent));
    try testing.expectEqual(@as(u64, 2), result.whiteouts);
    // No trace of the overlay's marks in the objects: the tree the commit made has no entry
    // for a whiteout and no attribute named user.overlay.
    try support.check_whole(&files, root_path, store.chunk_bytes);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

/// `/expect`: the sample tree with the changes `make_upper` makes.
fn build_expected() void {
    // The sample's source is `/src`; copy it by hand with the changes.
    files.put_dir("/expect", 0o755);
    files.put_dir("/expect/bin", 0o755);
    files.put_dir("/expect/etc", 0o755);
    files.put_dir("/expect/empty", 0o750);
    files.put_file("/expect/bin/sh", 0o755, "#!newer shell\n");
    files.put_file("/expect/bin/new", 0o644, "fresh\n");
    files.put_symlink("/expect/bin/busybox", "sh");
    files.put_file("/expect/etc/hosts", 0o644, "localhost\n");
}

test "a commit of an empty upper layer is the parent" {
    // Goal: nothing changed, nothing new. Method: commit an empty upper layer; the digest is the
    // parent's and no object or tree was written.
    const parent = start();
    make_upper("/upper");
    const result = try commit_upper("/upper", parent);
    try testing.expect(result.digest.eql(parent));
    try testing.expectEqual(@as(u64, 0), result.objects_new);
    try testing.expectEqual(@as(u64, 0), result.trees_new);
}

test "a whiteout of a name the parent lacks, and a whiteout of a directory" {
    // Goal: deleting something that is not there changes nothing; deleting a directory removes
    // all of it. Method: one of each.
    const parent = start();
    make_upper("/upper");
    put_whiteout_device("/upper/not-there");
    const same = try commit_upper("/upper", parent);
    try testing.expect(same.digest.eql(parent));
    put_whiteout_device("/upper/etc");
    const result = try commit_upper("/upper", parent);
    try testing.expect(!result.digest.eql(parent));
    var summary: diff.Summary = undefined;
    var listing: Listing = .{};
    try run_diff(parent, result.digest, &listing, &summary);
    try listing.expect(&.{
        "D /etc/",
        "D /etc/empty",
        "D /etc/passwd",
        "D /etc/shadow",
    });
}

test "a directory in the upper layer is merged, a file replaces a directory and the reverse" {
    // Goal: the rest of the merge. Method: a directory with only a changed mode keeps the
    // parent's entries; a file over a directory drops the directory; a directory over a file
    // is a directory with the upper's contents only.
    const parent = start();
    make_upper("/upper");
    files.put_dir("/upper/bin", 0o700);
    files.put_file("/upper/etc", 0o644, "was a directory\n");
    files.put_dir("/upper/empty", 0o750);
    const result = try commit_upper("/upper", parent);
    var summary: diff.Summary = undefined;
    var listing: Listing = .{};
    try run_diff(parent, result.digest, &listing, &summary);
    try listing.expect(&.{
        "M /bin/  mode",
        "M /empty/  mode",
        "M /etc  mode, type",
        "D /etc/empty",
        "D /etc/passwd",
        "D /etc/shadow",
    });
}

test "an upper layer with a redirect or a metadata-only copy-up is refused" {
    // Goal: E0428, and nothing written. Method: one of each attribute on a directory and a file.
    const parent = start();
    const names = [_][]const u8{ "user.overlay.redirect", "user.overlay.metacopy" };
    for (names, 0..) |name, index| {
        make_upper("/upper");
        files.put_dir("/upper/bin", 0o755);
        files.put_file("/upper/bin/sh", 0o755, "x");
        files.put_xattr("/upper/bin/sh", name, "/y");
        _ = index;
        const trees_before = support.count_files(&files, root_path ++ "/trees");
        try testing.expectError(error.Failed, commit_upper("/upper", parent));
        try testing.expectEqual(codes.Code.E0428, diag.code.?);
        try testing.expectEqual(trees_before, support.count_files(&files, root_path ++ "/trees"));
        files.remove_path("/upper/bin/sh");
        files.remove_path("/upper/bin");
        files.remove_path("/upper");
    }
}

test "other devices in an upper layer are skipped as in an import" {
    // Goal: only the 0/0 device is a deletion. Method: a device with other numbers is skipped
    // (a warning's case in an import), and does not delete.
    const parent = start();
    make_upper("/upper");
    files.put("/upper/null", .char_device, 0o666, .{ 0, 0 }, "");
    files.set_rdev("/upper/null", 1, 3);
    const result = try commit_upper("/upper", parent);
    try testing.expect(result.digest.eql(parent));
    try testing.expectEqual(@as(u64, 1), result.skipped);
    try testing.expectEqual(@as(u64, 0), result.whiteouts);
}

test "a commit is reproducible and its parent's tree is not changed" {
    // Goal: the store is content addressed. Method: commit twice, the same digest; the parent
    // tree object is still there and still hashes to its name (`trees.load` checks it).
    const parent = start();
    make_upper("/upper");
    files.put_file("/upper/added", 0o644, "x");
    const first = try commit_upper("/upper", parent);
    const second = try commit_upper("/upper", parent);
    try testing.expect(first.digest.eql(second.digest));
    var buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    _ = try trees.load(&store, parent, &buffer, &errno);
}

// ---- diff ----------------------------------------------------------------------------------

/// The lines of a diff in the form the command prints, without the newline.
const Listing = struct {
    lines: [64][160]u8 = undefined,
    lengths: [64]u8 = undefined,
    count: u32 = 0,

    fn call(context: *anyopaque, change: *const diff.Change, _: *Diag) bool {
        const self: *Listing = @ptrCast(@alignCast(context));
        var writer = std.Io.Writer.fixed(&self.lines[self.count]);
        const word: u8 = switch (change.what) {
            .added => 'A',
            .removed => 'D',
            .changed => 'M',
        };
        const slash: []const u8 = if (change.kind == .dir and change.path.len > 1) "/" else "";
        writer.print("{c} {s}{s}", .{ word, change.path, slash }) catch unreachable; // Short.
        var first = true;
        inline for (.{ "content", "mode", "owner", "xattrs", "target", "kind" }) |field| {
            if (@field(change.attrs, field)) {
                const label = if (std.mem.eql(u8, field, "kind")) "type" else field;
                const separator = if (first) "  " else ", ";
                writer.print("{s}{s}", .{ separator, label }) catch unreachable; // Short.
                first = false;
            }
        }
        self.lengths[self.count] = @intCast(writer.buffered().len);
        self.count += 1;
        return true;
    }

    fn expect(self: *const Listing, wanted: []const []const u8) !void {
        errdefer for (0..self.count) |at| {
            std.debug.print("got: {s}\n", .{self.lines[at][0..self.lengths[at]]});
        };
        try testing.expectEqual(wanted.len, self.count);
        for (wanted, 0..) |line, at| {
            try testing.expectEqualStrings(line, self.lines[at][0..self.lengths[at]]);
        }
    }
};

fn run_diff(a: Digest, b: Digest, listing: *Listing, summary: *diff.Summary) !void {
    const sink: diff.Sink = .{ .context = listing, .call = Listing.call };
    diag.reset();
    try diff.diff(&store, &diff_workspace, &workspace.arena, a, b, sink, summary, &diag);
}

test "a diff lists added, removed and changed paths, with what changed" {
    // Goal: the brief's diff. Method: the commit of the first test; the list is the changes the
    // upper layer made, in path order, and the summary counts them.
    const parent = start();
    make_upper("/upper");
    files.put_dir("/upper/bin", 0o755);
    files.put_file("/upper/bin/sh", 0o755, "#!newer shell\n");
    files.put_file("/upper/bin/new", 0o644, "fresh\n");
    put_whiteout_device("/upper/bin/ls");
    files.put_dir("/upper/empty", 0o750);
    const result = try commit_upper("/upper", parent);
    var listing: Listing = .{};
    var summary: diff.Summary = undefined;
    try run_diff(parent, result.digest, &listing, &summary);
    try listing.expect(&.{
        "D /bin/ls",
        "A /bin/new",
        "M /bin/sh  content",
        "M /empty/  mode",
    });
    try testing.expectEqual(@as(u64, 1), summary.added);
    try testing.expectEqual(@as(u64, 1), summary.removed);
    try testing.expectEqual(@as(u64, 2), summary.changed);
    // The same trees the other way round: added and removed swap.
    var back: Listing = .{};
    try run_diff(result.digest, parent, &back, &summary);
    try back.expect(&.{
        "A /bin/ls",
        "D /bin/new",
        "M /bin/sh  content",
        "M /empty/  mode",
    });
}

test "a diff names each attribute that changed" {
    // Goal: per path, which of content, mode, owner, xattrs, link target or type changed.
    // Method: one change of each kind to a copy of the sample tree, and one change of two.
    const a = start();
    build_copy();
    files.set_owner_of("/copy/etc/shadow", 7, 5);
    files.put_xattr("/copy/etc/passwd", "user.k", "v");
    files.remove_path("/copy/bin/sh");
    files.put_file("/copy/bin/sh", 0o700, "#!shell\nmore");
    files.remove_path("/copy/bin/busybox");
    files.put_symlink("/copy/bin/busybox", "ls");
    files.remove_path("/copy/bin/ls");
    files.put_dir("/copy/bin/ls", 0o755);
    const b = import_directory("/copy");
    var listing: Listing = .{};
    var summary: diff.Summary = undefined;
    try run_diff(a, b, &listing, &summary);
    try listing.expect(&.{
        "M /bin/busybox  target",
        "M /bin/ls/  xattrs, type",
        "M /bin/sh  content, mode",
        "M /etc/passwd  xattrs",
        "M /etc/shadow  owner",
    });
}

/// `/copy`: the sample tree as a second directory.
fn build_copy() void {
    files.put_dir("/copy", 0o755);
    files.put_dir("/copy/bin", 0o755);
    files.put_dir("/copy/etc", 0o755);
    files.put_dir("/copy/empty", 0o700);
    files.put_file("/copy/bin/sh", 0o755, "#!shell\n");
    files.put_file("/copy/bin/ls", 0o755, "#!shell\n");
    files.put_xattr("/copy/bin/ls", "user.note", "listing");
    files.put_file("/copy/bin/su", 0o4755, "setuid\n");
    files.put_xattr("/copy/bin/su", "security.capability", "\x01\x00\x00\x02");
    files.put_file("/copy/etc/passwd", 0o644, "root:x:0:0\n");
    files.put("/copy/etc/shadow", .file, 0o600, .{ 5, 5 }, "root:!\n");
    files.put_file("/copy/etc/empty", 0o644, "");
    files.put_symlink("/copy/bin/busybox", "sh");
}

test "equal trees have no diff, and equal subtrees are not read" {
    // Goal: the walk skips identical subtree digests. Method: two imports that differ in one
    // directory; the tree object of a directory they share is deleted from the store, and the
    // diff still succeeds. A tree that really is read and is missing is E0422.
    const a = start();
    build_copy();
    files.put_file("/copy/etc/more", 0o644, "m");
    const b = import_directory("/copy");
    var listing: Listing = .{};
    var summary: diff.Summary = undefined;
    try run_diff(a, a, &listing, &summary);
    try listing.expect(&.{});
    const shared = subtree_of(a, "bin");
    try testing.expect(subtree_of(b, "bin").eql(shared));
    var path: fs_sim_path = undefined;
    try store.fs.unlink(store.tree_path(&path, shared));
    listing = .{};
    try run_diff(a, b, &listing, &summary);
    try listing.expect(&.{"A /etc/more"});
    const changed = subtree_of(b, "etc");
    try store.fs.unlink(store.tree_path(&path, changed));
    try testing.expectError(error.Failed, run_diff(a, b, &listing, &summary));
    try testing.expectEqual(codes.Code.E0422, diag.code.?);
}

const fs_sim_path = @import("fs.zig").PathBuf;

fn subtree_of(root: Digest, name: []const u8) Digest {
    var buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    const bytes = trees.load(&store, root, &buffer, &errno) catch unreachable; // In the store.
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch unreachable; // A tree we wrote.
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch unreachable) { // A tree we wrote.
        if (std.mem.eql(u8, entry.name, name)) return entry.subtree;
    }
    unreachable; // The sample has the name.
}

test "the root directory's own change is listed as /" {
    // Goal: the root's mode is in the digest, so a diff must show it. Method: chmod the copy's
    // root.
    const a = start();
    build_copy();
    files.set_mode_of("/copy", 0o711);
    const b = import_directory("/copy");
    var listing: Listing = .{};
    var summary: diff.Summary = undefined;
    try run_diff(a, b, &listing, &summary);
    try listing.expect(&.{"M /  mode"});
}

// ---- fixtures captured from a real overlayfs -----------------------------------------------

const fixture_lower = @embedFile("fixtures/overlay_lower.txt");
const fixture_upper = @embedFile("fixtures/overlay_upper.txt");
const fixture_diff = @embedFile("fixtures/overlay_diff.txt");

/// Builds the directory a fixture lists under `prefix`. A line is `kind mode uid gid major:minor
/// path data xattr...`: kind d, f, l or c; data is hex (a file's bytes, a link's target) or `-`
/// for none; an attribute is `name=hex`. Parents come before their children.
fn load_listing(text: []const u8, prefix: []const u8) void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = words.next().?;
        const mode = std.fmt.parseInt(u16, words.next().?, 8) catch unreachable; // A fixture.
        const uid = std.fmt.parseInt(u32, words.next().?, 10) catch unreachable; // A fixture.
        const gid = std.fmt.parseInt(u32, words.next().?, 10) catch unreachable; // A fixture.
        const rdev = words.next().?;
        const rel = words.next().?;
        var path_buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
        const shown = if (std.mem.eql(u8, rel, "/")) "" else rel;
        const path = std.fmt.bufPrint(&path_buffer, "{s}{s}", .{ prefix, shown }) catch {
            unreachable; // A fixture path is short.
        };
        put_listed(kind[0], path, mode, .{ uid, gid }, rdev, words.next().?);
        while (words.next()) |attribute| {
            const equals = std.mem.indexOfScalar(u8, attribute, '=').?;
            var value: [256]u8 = undefined;
            const hex = attribute[equals + 1 ..];
            const bytes = if (std.mem.eql(u8, hex, "-")) value[0..0] else decode(&value, hex);
            files.put_xattr(path, attribute[0..equals], bytes);
        }
    }
}

fn decode(buffer: []u8, hex: []const u8) []const u8 {
    if (std.mem.eql(u8, hex, "-")) return buffer[0..0];
    return std.fmt.hexToBytes(buffer, hex) catch unreachable; // A fixture.
}

fn put_listed(
    kind: u8,
    path: []const u8,
    mode: u16,
    owner: [2]u32,
    rdev: []const u8,
    data: []const u8,
) void {
    var content: [4096]u8 = undefined;
    switch (kind) {
        'd' => files.put(path, .dir, mode, owner, ""),
        'f' => files.put(path, .file, mode, owner, decode(&content, data)),
        'l' => files.put_symlink(path, decode(&content, data)),
        'c' => {
            files.put(path, .char_device, mode, owner, "");
            const colon = std.mem.indexOfScalar(u8, rdev, ':').?;
            const major = std.fmt.parseInt(u32, rdev[0..colon], 10) catch unreachable; // A fixture.
            const minor = std.fmt.parseInt(u32, rdev[colon + 1 ..], 10) catch unreachable; // Same.
            files.set_rdev(path, major, minor);
        },
        else => unreachable, // A fixture has no other kind.
    }
}

test "an upper layer captured from a real overlayfs commits to what the real commit listed" {
    // Goal: the simulator's idea of an upper layer is the kernel's. Method: the lower tree and
    // the upper layer of a container that added, rewrote, chmod'ed, deleted (files and a
    // directory), replaced a directory (opaque), renamed a directory (copied, as overlayfs
    // without redirects does), linked and recreated files were captured from a real overlay
    // mounted with `userxattr` (docs/demos/m3.md, "Fixtures"), along with the diff that `zbx
    // store diff` printed for the real commit. The simulator commits the captured layer and must
    // print the same diff, and no `user.overlay` attribute reaches an object or a tree.
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    load_listing(fixture_lower, "/lower");
    const parent = import_directory("/lower");
    load_listing(fixture_upper, "/upper");
    const result = try commit_upper("/upper", parent);
    try testing.expectEqual(@as(u64, 2), result.whiteouts);
    var listing: Listing = .{};
    var summary: diff.Summary = undefined;
    try run_diff(parent, result.digest, &listing, &summary);
    var expected: [64][]const u8 = undefined;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, fixture_diff, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        expected[count] = line;
        count += 1;
    }
    try listing.expect(expected[0..count]);
    try expect_no_overlay_marks(root_path);
}

/// Nothing under the store holds the text `overlay`: not an object's attributes, not a tree.
fn expect_no_overlay_marks(root: []const u8) !void {
    var index: u32 = 0;
    var seen: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (!std.mem.startsWith(u8, path, root)) continue;
        seen += 1;
        if (files.xattrs_of(path)) |blob| {
            try testing.expect(std.mem.indexOf(u8, blob, "overlay") == null);
        }
        if (files.kind_of(path) != .file) continue;
        const content = files.content_of(path).?;
        try testing.expect(std.mem.indexOf(u8, content, "overlay") == null);
    }
    try testing.expect(seen > 10);
}
