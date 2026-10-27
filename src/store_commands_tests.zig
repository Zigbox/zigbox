//! Tests of the `zbx store` commands through the command line, against the simulated host:
//! what they print, in text and in JSON (checked against the schemas' required keys), what
//! they leave in the store, and how they refuse. The diagnostics' own text is in the golden
//! tests (`diag_golden.zig`).

const std = @import("std");
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const schemas = @import("schemas.zig");
const sim_run = @import("runtime/sim_run.zig");
const digest_mod = @import("store/digest.zig");
const fs_sim = @import("store/fs_sim.zig");
const support = @import("store/test_support.zig");
const test_util = @import("test_util.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;

const Items = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    pub fn next(iterator: *Items) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

fn start() void {
    sim_run.init(&sim, 1);
    files.init(1);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    sim.store_fs = &files;
    support.make_source(&files, 0);
}

/// Runs `zbx <args>` and returns the exit code; the output is in the simulator.
fn command(args: []const [:0]const u8) !u8 {
    var items: [16][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    var iterator: Items = .{ .items = items[0 .. 1 + args.len] };
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    const code = cli.run_from_iterator(sim.interface(), &iterator);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

fn parse_stdout() !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
}

/// `text` as a C string in `buffer`, for an argument built at run time.
fn term(buffer: *[80]u8, text: []const u8) [:0]const u8 {
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

/// The digest an import printed, without its newline.
fn printed_digest() ![]const u8 {
    const out = sim.stdout();
    try testing.expect(out.len == constants.store_digest_text_bytes + 1);
    try testing.expect(out[out.len - 1] == '\n');
    try testing.expect(Digest.parse(out[0 .. out.len - 1]) != null);
    return out[0 .. out.len - 1];
}

test "import prints the digest alone on stdout, and says nothing on stderr" {
    // Goal: a script can capture the digest. Method: import twice; same digest, empty stderr.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var first: [constants.store_digest_text_bytes]u8 = undefined;
    @memcpy(&first, try printed_digest());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src/" }));
    try testing.expectEqualStrings(&first, try printed_digest());
}

test "import --output json matches the schema's required keys and counts" {
    // Goal: the machine-readable result. Method: parse it and check each required key's type.
    start();
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "import", "/src" }),
    );
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.store.import/1", object.get("schema").?.string);
    try testing.expect(Digest.parse(object.get("digest").?.string) != null);
    try testing.expectEqual(@as(i64, 6), object.get("files").?.integer);
    try testing.expectEqual(@as(i64, 4), object.get("directories").?.integer);
    try testing.expectEqual(@as(i64, 1), object.get("symlinks").?.integer);
    try testing.expectEqual(@as(i64, 41), object.get("bytes").?.integer);
    try testing.expectEqual(@as(i64, 0), object.get("unmapped_owners").?.integer);
    try testing.expectEqual(@as(i64, 0), object.get("unmapped_groups").?.integer);
    try testing.expectEqual(@as(i64, 6), object.get("new_objects").?.integer);
    try testing.expectEqualStrings("full", object.get("ids").?.string);
    const schema = schemas.of("store-import").?;
    const required = [_][]const u8{ "schema", "digest", "source", "files", "directories", "ids" };
    for (required) |key| {
        try testing.expect(std.mem.indexOf(u8, schema, key) != null);
        try testing.expect(object.get(key) != null);
    }
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "import counts owners the namespace cannot map, warns once, and says so in JSON" {
    // Goal: no silent loss of an owner. Method: two files and the root show the overflow id.
    start();
    files.set_owner_of("/src/etc/passwd", constants.store_overflow_id, 0);
    files.set_owner_of("/src/etc/shadow", 0, constants.store_overflow_id);
    files.set_owner_of("/src", constants.store_overflow_id, 0);
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "import", "/src" }),
    );
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0412"));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 2), parsed.value.object.get("unmapped_owners").?.integer);
    try testing.expectEqual(@as(i64, 1), parsed.value.object.get("unmapped_groups").?.integer);
    const schema = schemas.of("store-import").?;
    try testing.expect(std.mem.indexOf(u8, schema, "unmapped_owners") != null);
    try testing.expect(std.mem.indexOf(u8, schema, "unmapped_groups") != null);
}

test "ls lists the roots newest first, in text and in JSON" {
    // Goal: `ls` answers from the root records. Method: two imports at different times.
    start();
    sim.world.now = 1_000;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    files.put_file("/src/etc/new", 0o644, "x");
    sim.world.now = 2_000;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const newest = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(newest);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "ls" }));
    var lines = std.mem.splitScalar(u8, sim.stdout(), '\n');
    try testing.expect(std.mem.startsWith(u8, lines.next().?, "DIGEST"));
    try testing.expect(std.mem.startsWith(u8, lines.next().?, newest));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const roots = parsed.value.object.get("roots").?.array;
    try testing.expectEqual(@as(usize, 2), roots.items.len);
    try testing.expectEqualStrings(newest, roots.items[0].object.get("digest").?.string);
    try testing.expectEqual(@as(i64, 2_000), roots.items[0].object.get("time").?.integer);
    try testing.expectEqualStrings("/src", roots.items[0].object.get("source").?.string);
    try testing.expect(roots.items[1].object.get("parent").? == .null);
}

test "ls of a store that does not exist is an empty list, and creates nothing" {
    // Goal: reading never creates. Method: ls on a host with a home and no store.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 0), parsed.value.object.get("roots").?.array.items.len);
    try testing.expect(files.kind_of(support.user_store) == null);
}

test "du grows by the new file only, and a tree's cost is its distinct objects" {
    // Goal: the demo's step 2 in miniature. Method: du of the store before and after adding a
    // 1000-byte file and importing again.
    start();
    var argument: [80]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const first = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(first);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "du" }));
    var parsed = try parse_stdout();
    const before = parsed.value.object.get("store").?.object.get("bytes").?.integer;
    parsed.deinit();
    files.put_file("/src/etc/big", 0o644, "x");
    var big: [1000]u8 = @splat('b');
    files.put_file("/src/etc/bigger", 0o644, &big);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "du" }));
    parsed = try parse_stdout();
    const after = parsed.value.object.get("store").?.object.get("bytes").?.integer;
    parsed.deinit();
    // The two files, and a handful of tree objects of a few dozen bytes each.
    try testing.expect(after - before >= 1001);
    try testing.expect(after - before < 1001 + 1000);
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "du", term(&argument, first[3..23]) }),
    );
    parsed = try parse_stdout();
    defer parsed.deinit();
    const tree = parsed.value.object.get("tree").?.object;
    try testing.expectEqual(@as(i64, 41), tree.get("logical_bytes").?.integer);
    try testing.expectEqual(@as(i64, 41), tree.get("stored_bytes").?.integer);
    try testing.expectEqual(@as(i64, 41), tree.get("shared_bytes").?.integer);
}

test "rm drops the root, keeps the data, and a second rm is a refusal" {
    // Goal: rm's contract. Method: import, rm by prefix, ls is empty, the objects are still
    // there, rm again is E0420, and a digest that was never there is E0410.
    start();
    var argument: [80]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const digest = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(digest);
    const objects = support.count_files(&files, support.user_store ++ "/objects");
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "rm", term(&argument, digest[0..20]) }),
    );
    const parsed = try parse_stdout();
    defer parsed.deinit();
    try testing.expectEqualStrings(digest, parsed.value.object.get("digest").?.string);
    try testing.expect(parsed.value.object.get("removed").?.bool);
    try testing.expectEqual(objects, support.count_files(&files, support.user_store ++ "/objects"));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const listed = try parse_stdout();
    defer listed.deinit();
    try testing.expectEqual(@as(usize, 0), listed.value.object.get("roots").?.array.items.len);
    try testing.expectEqual(
        @as(u8, 1),
        try command(&.{ "store", "rm", term(&argument, digest[0..20]) }),
    );
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0420") != null);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "store", "rm", "b3:000000000000" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0410") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "the usage errors of store are E0006, E0001 and E0003 with nothing on stdout" {
    // Goal: every wrong command line is refused in one block. Method: each shape.
    start();
    const cases = [_]struct { args: []const [:0]const u8, code: []const u8 }{
        .{ .args = &.{"store"}, .code = "ZBX-E0006" },
        .{ .args = &.{ "store", "frob" }, .code = "ZBX-E0001" },
        .{ .args = &.{ "store", "import" }, .code = "ZBX-E0006" },
        .{ .args = &.{ "store", "rm" }, .code = "ZBX-E0006" },
        .{ .args = &.{ "store", "ls", "x" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "du", "a", "b" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "import", "a", "b" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "rm", "not-a-digest" }, .code = "ZBX-E0412" },
        .{ .args = &.{ "store", "du", "ABCDEF012345" }, .code = "ZBX-E0412" },
    };
    for (cases) |case| {
        try testing.expectEqual(@as(u8, 1), try command(case.args));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.code) != null);
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-"));
    }
}

test "a host that maps only one id warns once and records every owner as 0" {
    // Goal: W0201 reaches an import and changes what it records. Method: the single-id host.
    sim_run.init_single(&sim, 1);
    files.init(1);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    sim.store_fs = &files;
    support.make_source(&files, 0);
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "import", "/src" }),
    );
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-W0201"));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    try testing.expectEqualStrings("single", parsed.value.object.get("ids").?.string);
    // Plain commands do not repeat the warning.
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "ls" }));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "the schemas of the store commands are valid JSON and listed by schema" {
    // Goal: `zbx schema store-*` prints each one, and the store commands have all four.
    start();
    for ([_][:0]const u8{ "store-import", "store-ls", "store-du", "store-rm" }) |name| {
        try testing.expectEqual(@as(u8, 0), try command(&.{ "schema", name }));
        try testing.expect(try test_util.json_is_valid(sim.stdout()));
        try testing.expect(std.mem.indexOf(u8, sim.stdout(), name) != null);
    }
}

test "a host with no data directory is refused first, with one diagnostic and no warning" {
    // Goal: a regression found by the `cli` fuzzer (seed 4): the one-id warning came first and
    // then the refusal, two diagnostics for one command. Method: a host that would warn, with no
    // HOME; the namespace is never made.
    sim_run.init_single(&sim, 1);
    sim.environment_variables = &.{};
    sim.store_fs = &files;
    try testing.expectEqual(@as(u8, 2), try command(&.{ "store", "import", "/src" }));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "ZBX-E0421"));
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, sim.stderr(), "ZBX-W0201"));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "ls shows a source path with no byte a terminal could act on, and JSON keeps it exact" {
    // Goal: an escape sequence in a path cannot reach the terminal through `ls`. Method: import
    // a directory whose name holds ESC and a newline; text has '?', JSON has the escaped bytes.
    start();
    files.put_dir("/src/odd\x1b[2J\nname", 0o755);
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "store", "import", "/src/odd\x1b[2J\nname" }),
    );
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "ls" }));
    try testing.expect(std.mem.indexOfScalar(u8, sim.stdout(), 0x1b) == null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, sim.stdout(), "\n"));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "odd?[2J?name") != null);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const source = parsed.value.object.get("roots").?.array.items[0].object.get("source").?.string;
    try testing.expectEqualStrings("/src/odd\x1b[2J\nname", source);
}

/// A stopped container "web-1" that ran the tree `digest` text; its upper layer is `/upper`.
fn put_container(digest_text: []const u8) void {
    var view = sim_run.sample_view("web-1", 1000);
    view.tree = digest_text;
    view.upper = "/upper";
    sim_run.put_record(&sim, &view);
    files.put_dir("/upper", 0o755);
}

test "commit prints the new digest, records the root, and diff lists what changed" {
    // Goal: the demo's step 3 and 5 in miniature. Method: import, a container that added a
    // file, changed one and deleted one; commit; the root lists its parent and container; diff
    // lists those three paths; a tree without the deleted large file costs less.
    start();
    sim.world.now = 1_000;
    var big: [5000]u8 = @splat('B');
    files.put_file("/src/etc/big", 0o644, &big);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const parent = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(parent);
    put_container(parent);
    files.put_file("/upper/new", 0o644, "added\n");
    files.put_dir("/upper/etc", 0o755);
    files.put("/upper/etc/big", .char_device, 0o000, .{ 0, 0 }, "");
    files.put_file("/upper/etc/passwd", 0o644, "root:x:0:0:changed\n");
    sim.world.now = 5_000;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "commit", "web-1" }));
    const child = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(child);
    try testing.expect(!std.mem.eql(u8, parent, child));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    // The root, with the container and the parent.
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    var parsed = try parse_stdout();
    const listed = parsed.value.object.get("roots").?.array.items[0].object;
    try testing.expectEqualStrings(child, listed.get("digest").?.string);
    try testing.expectEqualStrings("web-1", listed.get("source").?.string);
    try testing.expectEqualStrings(parent, listed.get("parent").?.string);
    parsed.deinit();
    // The diff, in text.
    var first: [80]u8 = undefined;
    var second: [80]u8 = undefined;
    const args = [_][:0]const u8{ "store", "diff", term(&first, parent), term(&second, child) };
    try testing.expectEqual(@as(u8, 0), try command(&args));
    try testing.expectEqualStrings(
        "D /etc/big\nM /etc/passwd  content\nA /new\n",
        sim.stdout(),
    );
    // The diff, in JSON.
    const json_args = [_][:0]const u8{
        "--output", "json", "store", "diff", term(&first, parent), term(&second, child),
    };
    try testing.expectEqual(@as(u8, 0), try command(&json_args));
    parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.store.diff/1", object.get("schema").?.string);
    try testing.expectEqualStrings(parent, object.get("from").?.string);
    const changes = object.get("changes").?.array.items;
    try testing.expectEqual(@as(usize, 3), changes.len);
    try testing.expectEqualStrings("removed", changes[0].object.get("change").?.string);
    try testing.expectEqualStrings("/etc/passwd", changes[1].object.get("path").?.string);
    const attributes = changes[1].object.get("attributes").?.array.items;
    try testing.expectEqualStrings("content", attributes[0].string);
    try testing.expectEqual(@as(i64, 1), object.get("summary").?.object.get("added").?.integer);
    for ([_][]const u8{ "schema", "from", "to", "changes", "summary" }) |key| {
        try testing.expect(std.mem.indexOf(u8, schemas.of("store-diff").?, key) != null);
    }
    // Deleting the large file: the child's stored size is smaller than the parent's by it.
    const du_parent = [_][:0]const u8{
        "--output", "json", "store", "du", term(&first, parent),
    };
    try testing.expectEqual(@as(u8, 0), try command(&du_parent));
    parsed.deinit();
    parsed = try parse_stdout();
    const parent_stored = parsed.value.object.get("tree").?.object.get("stored_bytes").?.integer;
    const du_child = [_][:0]const u8{
        "--output", "json", "store", "du", term(&first, child),
    };
    try testing.expectEqual(@as(u8, 0), try command(&du_child));
    parsed.deinit();
    parsed = try parse_stdout();
    const child_stored = parsed.value.object.get("tree").?.object.get("stored_bytes").?.integer;
    try testing.expect(child_stored < parent_stored);
}

test "commit --output json has the schema's keys, and an unchanged commit writes no root" {
    // Goal: the machine-readable result and idempotence. Method: commit an empty upper layer.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const parent = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(parent);
    put_container(parent);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "commit", "web-1" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    const schema = schemas.of("commit").?;
    const required = [_][]const u8{
        "schema", "digest",      "parent",    "container", "unchanged", "files",
        "bytes",  "new_objects", "new_bytes", "new_trees", "deleted",
    };
    for (required) |key| {
        try testing.expect(std.mem.indexOf(u8, schema, key) != null);
        try testing.expect(object.get(key) != null);
    }
    try testing.expectEqualStrings("zbx.commit/1", object.get("schema").?.string);
    try testing.expect(object.get("unchanged").?.bool);
    try testing.expectEqualStrings(parent, object.get("digest").?.string);
    try testing.expectEqual(@as(i64, 6), object.get("files").?.integer);
    try testing.expectEqual(@as(i64, 0), object.get("new_objects").?.integer);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const roots = try parse_stdout();
    defer roots.deinit();
    try testing.expectEqual(@as(usize, 1), roots.value.object.get("roots").?.array.items.len);
}

test "commit refuses what it can't commit with a coded line and leaves the store alone" {
    // Goal: E0426 (a directory run), E0427 is in the goldens, and an unknown container is the
    // lifecycle commands' own refusal. Method: one of each; stdout stays empty.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    try testing.expectEqual(@as(u8, 1), try command(&.{ "commit", "nobody" }));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "nobody") != null);
    sim_run.put_record(&sim, &sim_run.sample_view("web-1", 1000));
    try testing.expectEqual(@as(u8, 1), try command(&.{ "commit", "web-1" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0426") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    // A record whose upper layer has gone.
    var view = sim_run.sample_view("web-2", 1000);
    const text = "b3:0000000000000000000000000000000000000000000000000000000000000000";
    view.tree = text;
    view.upper = "/not-there";
    sim_run.put_record(&sim, &view);
    try testing.expect(try command(&.{ "commit", "web-2" }) != 0);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E04") != null);
}

test "diff of equal trees prints nothing, and usage errors are E0006" {
    // Goal: no lines, exit 0 for equal trees; a missing operand is a usage error.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var first: [80]u8 = undefined;
    const digest = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(digest);
    const args = [_][:0]const u8{ "store", "diff", term(&first, digest), term(&first, digest) };
    try testing.expectEqual(@as(u8, 0), try command(&args));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "store", "diff", "b3:000000000000" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0006") != null);
    try testing.expectEqual(@as(u8, 1), try command(&.{"commit"}));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0006") != null);
}
