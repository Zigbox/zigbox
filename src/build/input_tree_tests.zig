//! The input tree in the simulator (`input_tree.zig`): what goes into it and what does not,
//! links kept as links, kinds refused, and a path that leaves the project refused.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const diagnose = @import("diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const file_mod = @import("file.zig");
const inputs_mod = @import("inputs.zig");
const input_tree = @import("input_tree.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const layout = @import("../store/layout.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

const store_root = "/data/store";
const proj = "/p";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var workspace: input_tree.Workspace = undefined;
var diag: Diag = undefined;
var build_file: file_mod.BuildFile = undefined;
var problem: inputs_mod.Problem = undefined;
var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;

fn start(seed: u64) void {
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, store_root);
    store.at(sim.interface(), store_root);
    files.put_dir(proj, 0o755);
    files.put_file(proj ++ "/README", 0o644, "read me\n");
    files.put_dir(proj ++ "/src", 0o755);
    files.put_file(proj ++ "/src/main.c", 0o600, "int main;\n");
    files.put_file(proj ++ "/src/run.sh", 0o700, "#!/bin/sh\n");
    files.put_symlink(proj ++ "/src/out", "../../etc/passwd");
    files.put_dir(proj ++ "/src/lib", 0o750);
    files.put_file(proj ++ "/src/lib/a.c", 0o664, "a\n");
    files.put_dir(proj ++ "/docs", 0o755);
    files.put_file(proj ++ "/docs/a.txt", 0o644, "docs\n");
    files.put_file(proj ++ "/a-b", 0o644, "dash\n");
    diag.reset();
}

fn parse(comptime inputs: []const u8) void {
    const text = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"s\", .base = \"b\", " ++
        ".run = .{\"x\"}, .inputs = .{" ++ inputs ++ "} } } }";
    var parse_problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &build_file, &parse_problem);
    assert(parsed == .parsed);
}

fn import_inputs() input_tree.Error!Digest {
    const fs = store.fs;
    const project = fs.open_directory(proj) catch unreachable; // The test made it.
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

/// The entry `name` of the tree `digest`, or null.
fn entry_of(digest: Digest, name: []const u8, out: *tree.Entry) !bool {
    var errno: u16 = 0;
    const bytes = try trees.load(&store, digest, &tree_buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    while (try decoder.next(out)) {
        if (std.mem.eql(u8, out.name, name)) return true;
    }
    return false;
}

test "the input tree holds the declared inputs at their paths, and nothing else" {
    // Goal: an undeclared file is not in the tree, made-up parents are 0755 and owner 0, files
    // are 0644 or 0755 by the owner's execute bit, and a link inside a directory input is a
    // link. Method: import `src`, `docs/a.txt` and `a-b`, then look at the tree.
    start(1);
    parse("\"src\", \"docs/a.txt\", \"a-b\"");
    const root = try import_inputs();
    try testing.expectEqual(@as(u32, 0), files.open_count());
    var entry: tree.Entry = undefined;
    try testing.expect(!try entry_of(root, "README", &entry));
    try testing.expect(try entry_of(root, "a-b", &entry));
    try testing.expect(try entry_of(root, "docs", &entry));
    try testing.expectEqual(tree.Kind.dir, entry.kind);
    try testing.expectEqual(@as(u16, 0o755), entry.mode);
    const docs = entry.subtree;
    try testing.expect(try entry_of(docs, "a.txt", &entry));
    try testing.expect(try entry_of(root, "src", &entry));
    const source = entry.subtree;
    try testing.expect(try entry_of(source, "main.c", &entry));
    try testing.expectEqual(@as(u16, 0o644), entry.mode);
    try testing.expect(try entry_of(source, "run.sh", &entry));
    try testing.expectEqual(@as(u16, 0o755), entry.mode);
    try testing.expect(try entry_of(source, "out", &entry));
    try testing.expectEqual(tree.Kind.symlink, entry.kind);
    try testing.expectEqualStrings("../../etc/passwd", entry.target);
    try testing.expect(try entry_of(source, "lib", &entry));
    try testing.expectEqual(@as(u16, 0o755), entry.mode);
    try testing.expectEqual(@as(u32, 0), entry.uid);
}

test "the input tree's digest ignores what a checkout does not fix" {
    // Goal: times, owners, the group and other bits, and undeclared files do not change the
    // digest; content, the owner's execute bit and a link's text do. Method: import, change one
    // thing at a time, import again.
    start(2);
    parse("\"src\", \"docs/a.txt\"");
    const first = try import_inputs();
    files.set_mtime_of(proj ++ "/src/main.c", 12345);
    files.set_owner_of(proj ++ "/src/main.c", 1000, 1000);
    files.set_mode_of(proj ++ "/src/main.c", 0o640);
    files.set_mode_of(proj ++ "/src/lib", 0o700);
    files.remove_path(proj ++ "/README");
    files.remove_path(proj ++ "/docs/a.txt");
    files.put_file(proj ++ "/docs/a.txt", 0o666, "docs\n");
    try testing.expect(first.eql(try import_inputs()));
    files.set_mode_of(proj ++ "/src/main.c", 0o740);
    const executable = try import_inputs();
    try testing.expect(!first.eql(executable));
    files.remove_path(proj ++ "/src/out");
    files.put_symlink(proj ++ "/src/out", "../etc/passwd");
    const relinked = try import_inputs();
    try testing.expect(!executable.eql(relinked));
    files.flip_byte(proj ++ "/src/lib/a.c", 0);
    try testing.expect(!relinked.eql(try import_inputs()));
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "the order the inputs are listed in does not change the tree" {
    start(3);
    parse("\"src\", \"a-b\", \"docs/a.txt\"");
    const first = try import_inputs();
    parse("\"docs/a.txt\", \"a-b\", \"src\"");
    try testing.expect(first.eql(try import_inputs()));
}

test "a device, a FIFO or a socket inside a directory input is refused" {
    // Goal: E0803 names the entry and its kind. Method: a FIFO, then a socket, in `src/lib`.
    start(4);
    parse("\"src\"");
    files.put(proj ++ "/src/lib/pipe", .fifo, 0o644, .{ 0, 0 }, "");
    try testing.expectError(error.Refused, import_inputs());
    try testing.expectEqual(inputs_mod.ProblemKind.holds_bad_kind, problem.kind);
    try testing.expectEqualStrings("src/lib/pipe", problem.resolved.text());
    try testing.expectEqual(@as(u32, 0), files.open_count());
    files.remove_path(proj ++ "/src/lib/pipe");
    files.put(proj ++ "/src/lib/sock", .socket, 0o644, .{ 0, 0 }, "");
    try testing.expectError(error.Refused, import_inputs());
    try testing.expectEqual(fs_mod.FileKind.socket, problem.file_kind);
    diag.reset();
    diagnose.input_problem(&diag, proj, &build_file, &problem);
    try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, "holds 'src/lib/sock'") != null);
}

test "a declared input that leads out of the project is refused, never read" {
    // Goal: the import resolves beneath the project, whatever the disk became after the check.
    // Method: replace `docs` with a link to `/data` (as a race would), and with `..`.
    start(5);
    parse("\"docs/a.txt\"");
    files.remove_path(proj ++ "/docs/a.txt");
    files.remove_path(proj ++ "/docs");
    files.put_symlink(proj ++ "/docs", "/data");
    try testing.expectError(error.Refused, import_inputs());
    try testing.expectEqual(inputs_mod.ProblemKind.changed, problem.kind);
    diag.reset();
    diagnose.input_problem(&diag, proj, &build_file, &problem);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "changed while the build read it") != null);
    files.remove_path(proj ++ "/docs");
    files.put_symlink(proj ++ "/docs", "../data");
    try testing.expectError(error.Refused, import_inputs());
    try testing.expectEqual(inputs_mod.ProblemKind.changed, problem.kind);
    files.remove_path(proj ++ "/docs");
    files.put_symlink(proj ++ "/docs", "src");
    files.put_file(proj ++ "/src/a.txt", 0o644, "docs\n");
    _ = try import_inputs(); // A link that stays inside is followed.
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

/// Directories `/p/<first>/d/d/...` with `levels` directories below `first`.
fn make_chain(first: []const u8, levels: u32) void {
    var buffer: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const base = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ proj, first }) catch
        unreachable; // Short.
    var length: usize = base.len;
    files.put_dir(buffer[0..length], 0o755);
    for (0..levels) |_| {
        @memcpy(buffer[length..][0..2], "/d");
        length += 2;
        files.put_dir(buffer[0..length], 0o755);
    }
}

fn repeat(comptime unit: []const u8, comptime times: u32) *const [unit.len * times]u8 {
    comptime {
        var out: [unit.len * times]u8 = undefined;
        for (0..times) |index| @memcpy(out[index * unit.len ..][0..unit.len], unit);
        const final = out;
        return &final;
    }
}

/// Every directory above `path`, below the project.
fn put_parents(path: []const u8) void {
    var at: usize = proj.len + 1;
    while (std.mem.indexOfScalarPos(u8, path, at, '/')) |slash| : (at = slash + 1) {
        files.put_dir(path[0..slash], 0o755);
    }
}

fn expect_limit(words: []const u8) !void {
    try testing.expectEqual(@as(?@TypeOf(diag.code.?), .E0415), diag.code);
    try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, words) != null);
}

test "a directory input nested to the store's depth imports, and one level more is E0415" {
    // Goal: the depth bound is exact for a directory that is read. Method: `deep` holds a
    // chain of 63 directories, so the tree has 64 below its root; then one more.
    start(6);
    parse("\"deep\"");
    make_chain("deep", constants.store_depth_max - 1);
    _ = try import_inputs();
    start(6);
    make_chain("deep", constants.store_depth_max);
    try testing.expectError(error.Failed, import_inputs());
    try expect_limit("nested more than 64 levels deep");
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "a declared file below 64 made-up directories imports, and below 65 is E0415" {
    // Goal: the depth bound is exact for the directories made up above a declared input.
    // Method: a file `a/a/.../f` with 64 parts above it, then 65.
    const at_bound = comptime repeat("a/", constants.store_depth_max);
    const past = comptime repeat("a/", constants.store_depth_max + 1);
    start(7);
    parse("\"" ++ at_bound ++ "f\"");
    put_parents(proj ++ "/" ++ past ++ "f");
    files.put_file(proj ++ "/" ++ at_bound ++ "f", 0o644, "deep\n");
    files.put_file(proj ++ "/" ++ past ++ "f", 0o644, "deeper\n");
    _ = try import_inputs();
    parse("\"" ++ past ++ "f\"");
    try testing.expectError(error.Failed, import_inputs());
    try expect_limit("nested more than 64 levels deep");
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

fn parse_excluding(
    comptime inputs: []const u8,
    comptime file_ex: []const u8,
    comptime step_ex: []const u8,
) void {
    const text = ".{ .version = 1, .image = .{}, .exclude = .{" ++ file_ex ++ "}, .steps = .{ " ++
        ".{ .name = \"s\", .base = \"b\", .run = .{\"x\"}, .exclude = .{" ++ step_ex ++
        "}, .inputs = .{" ++ inputs ++ "} } } }";
    var parse_problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &build_file, &parse_problem);
    assert(parsed == .parsed);
}

/// Whether the tree `root` holds the path `path` (names joined by `/`).
fn has(root: Digest, path: []const u8) !bool {
    var current = root;
    var names = std.mem.splitScalar(u8, path, '/');
    var entry: tree.Entry = undefined;
    while (names.next()) |name| {
        if (!try entry_of(current, name, &entry)) return false;
        current = entry.subtree;
        if (names.peek() != null and entry.kind != .dir) return false;
    }
    return true;
}

test "a glob input brings in the paths it matches and a matched directory whole" {
    // Goal: `*.c` under src is main.c only, `**/*.c` reaches lib/a.c too, a directory a glob
    // matches is imported whole, and nothing else is in the tree. Method: three imports.
    start(3);
    parse("\"src/*.c\"");
    const shallow = try import_inputs();
    try testing.expect(try has(shallow, "src/main.c"));
    try testing.expect(!try has(shallow, "src/run.sh"));
    try testing.expect(!try has(shallow, "src/lib"));
    try testing.expect(!try has(shallow, "docs"));
    parse("\"**/*.c\"");
    const deep = try import_inputs();
    try testing.expect(!deep.eql(shallow));
    try testing.expect(try has(deep, "src/main.c"));
    try testing.expect(try has(deep, "src/lib/a.c"));
    parse("\"s?c\", \"d*\"");
    const dirs = try import_inputs();
    try testing.expect(try has(dirs, "src/lib/a.c"));
    try testing.expect(try has(dirs, "docs/a.txt"));
    try testing.expect(!try has(dirs, "README"));
}

test "a glob that matches nothing is refused, and an input a glob and a path both name is once" {
    // Goal: an empty glob is an error naming the input; overlap between globs and plain inputs
    // is merged, not refused. Method: `*.zig` matches nothing; `src` plus `src/*.c` equals `src`.
    start(4);
    parse("\"*.zig\"");
    try testing.expectError(error.Refused, import_inputs());
    try testing.expectEqual(inputs_mod.ProblemKind.missing, problem.kind);
    parse("\"src\"");
    const plain = try import_inputs();
    parse("\"src\", \"src/*.c\", \"s*\"");
    try testing.expect(plain.eql(try import_inputs()));
}

test "excludes leave out paths from directory inputs, globs and plain inputs" {
    // Goal: the file's and the step's exclude lines both apply, a `!` line re-includes, and an
    // excluded plain input is dropped. Method: import with lines, look at the tree.
    start(5);
    parse_excluding("\"src\"", "\"src/lib\"", "\"src/*.sh\"");
    const cut = try import_inputs();
    try testing.expect(try has(cut, "src/main.c"));
    try testing.expect(!try has(cut, "src/run.sh"));
    try testing.expect(!try has(cut, "src/lib"));
    parse_excluding("\"src\"", "\"src/lib\"", "\"!src/lib/a.c\"");
    const back = try import_inputs();
    try testing.expect(try has(back, "src/lib/a.c"));
    try testing.expect(try has(back, "src/main.c"));
    parse_excluding("\"src/main.c\", \"README\"", "\"README\"", "");
    const dropped = try import_inputs();
    try testing.expect(!try has(dropped, "README"));
    try testing.expect(try has(dropped, "src/main.c"));
    parse_excluding("\"**/*.c\"", "\"src/lib\"", "");
    const globbed = try import_inputs();
    try testing.expect(try has(globbed, "src/main.c"));
    try testing.expect(!try has(globbed, "src/lib"));
}

test "the matched-path pool holds its bound and no more" {
    // Goal: E0818's bound. Method: add paths to a pool until it is full: the last that fits
    // is number `build_glob_matches_max`, the next is refused.
    const matches = &workspace.matches;
    matches.count = 0;
    matches.used = 0;
    for (0..constants.build_glob_matches_max) |index| {
        var buffer: [16]u8 = undefined;
        // Sixteen bytes hold "p/" and a number below 65,536.
        const path = std.fmt.bufPrint(&buffer, "p/{d}", .{index}) catch unreachable;
        try testing.expect(matches.add(path, 0));
    }
    try testing.expect(!matches.add("one/more", 0));
    try testing.expectEqual(constants.build_glob_matches_max, matches.count);
}
