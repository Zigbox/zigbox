//! Tests of the `zbx store` commands through the command line, against the simulated host:
//! what they print, in text and in JSON (checked against the schemas' required keys), what
//! they leave in the store, and how they refuse. The diagnostics' own text is in the golden
//! tests (`diag_golden.zig`).

const std = @import("std");
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const host_sim = @import("host_sim.zig");
const schemas = @import("schemas.zig");
const store_commands = @import("store_commands.zig");
const mounts_mod = @import("runtime/mounts.zig");
const sim_run = @import("runtime/sim_run.zig");
const digest_mod = @import("store/digest.zig");
const fs_sim = @import("store/fs_sim.zig");
const support = @import("store/test_support.zig");
const test_util = @import("test_util.zig");
const aws_sim = @import("aws/aws_sim.zig");
const net_sim = @import("registry/net_sim.zig");
const push_registry = @import("registry/push_registry.zig");

const assert = std.debug.assert;
const net = @import("registry/net.zig");
const testing = std.testing;
const Digest = digest_mod.Digest;
const Sha256 = @import("registry/digest.zig").Sha256;

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
    const code = command_raw(args);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

/// The same, for a test that has a container running (its pipes stay open).
fn command_raw(args: []const [:0]const u8) u8 {
    var items: [16][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    var iterator: Items = .{ .items = items[0 .. 1 + args.len] };
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return cli.run_from_iterator(sim.interface(), &iterator);
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

test "ls counts a file linked under several names once in size_unique, and bytes per name (#112)" {
    // Goal: `bytes` keeps its meaning (a file per name) and `size_unique` counts each file once,
    // in JSON and in the SIZE column of the text. Method: import the sample plus a 10-byte file
    // under three names.
    start();
    files.put_file("/src/etc/one", 0o644, "0123456789");
    try files.interface().link("/src/etc/one", "/src/etc/two");
    try files.interface().link("/src/etc/one", "/src/etc/three");
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "ls" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const root = parsed.value.object.get("roots").?.array.items[0].object;
    const bytes = root.get("bytes").?.integer;
    const unique = root.get("size_unique").?.integer;
    try testing.expectEqual(@as(i64, 20), bytes - unique); // Two names too many, 10 bytes each.
    try testing.expectEqual(@as(i64, 51), unique);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "ls" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "51 B") != null);
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

/// `store du <digest>`'s stored size of a tree.
fn stored_bytes(digest_text: []const u8) !i64 {
    var buffer: [80]u8 = undefined;
    const args = [_][:0]const u8{
        "--output", "json", "store", "du", term(&buffer, digest_text),
    };
    try testing.expectEqual(@as(u8, 0), try command(&args));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    return parsed.value.object.get("tree").?.object.get("stored_bytes").?.integer;
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
    const parent_stored = try stored_bytes(parent);
    const child_stored = try stored_bytes(child);
    try testing.expect(child_stored < parent_stored);
}

test "a commit leaves out a --mount's target and what is below it, and keeps its neighbours" {
    // Goal: M6b's rule that a writable mount point is never in `zbx commit`, as --bind's and
    // --secret's are not. Method: a record that names a `--mount` at /srv (its resolved host path
    // below the project) and a `--bind`; the upper layer holds the mount point, a file written
    // into the mounted directory, a neighbour whose name starts the same (/srvx), and one real
    // change. The diff holds the real change and the neighbour, not /srv.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const parent = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(parent);
    const mounts = [_]mounts_mod.Mount{
        .{ .kind = .mount, .source = "/home/alice/proj/site", .target = "/srv", .size_bytes = 0 },
        .{ .kind = .bind, .source = "/home/alice/ro", .target = "/ro", .size_bytes = 0 },
    };
    var view = sim_run.sample_view("web-1", 1000);
    view.tree = parent;
    view.upper = "/upper";
    view.mounts = &mounts;
    sim_run.put_record(&sim, &view);
    files.put_dir("/upper", 0o755);
    files.put_dir("/upper/srv", 0o755);
    files.put_file("/upper/srv/made-inside.txt", 0o644, "x\n");
    files.put_dir("/upper/srvx", 0o755);
    files.put_file("/upper/srvx/keep", 0o644, "y\n");
    files.put_file("/upper/new.txt", 0o644, "added\n");
    sim.world.now = 5_000;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "commit", "web-1" }));
    const child = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(child);
    var first: [80]u8 = undefined;
    var second: [80]u8 = undefined;
    const args = [_][:0]const u8{ "store", "diff", term(&first, parent), term(&second, child) };
    try testing.expectEqual(@as(u8, 0), try command(&args));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "A /new.txt") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "/srvx") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "/srv/") == null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "made-inside") == null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "A /srv\n") == null);
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

const zero_hash = "b3:" ++ test_util.repeat('0', 64);

// ---- verify, gc and restore ----------------------------------------------------------------

fn stored_object(source_path: []const u8, buffer: *[200]u8) []const u8 {
    const object = @import("store/object.zig");
    const stat = files.stat_of(source_path).?;
    const attrs: object.Attrs = .{
        .mode = stat.mode,
        .uid = stat.uid,
        .gid = stat.gid,
        .xattrs = files.xattrs_of(source_path) orelse &@import("store/xattrs.zig").empty,
    };
    const id = object.object_id(Digest.of(files.content_of(source_path).?), attrs);
    const hex = id.hex();
    return std.fmt.bufPrint(buffer, support.user_store ++ "/objects/{s}/{s}", .{
        hex[0..2], hex[2..],
    }) catch unreachable; // Short.
}

fn json_object_has(object: std.json.ObjectMap, schema: []const u8, keys: []const []const u8) !void {
    for (keys) |key| {
        try testing.expect(std.mem.indexOf(u8, schema, key) != null);
        try testing.expect(object.get(key) != null);
    }
}

test "verify of a whole store says so, in text and in JSON" {
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "0 roots: no damage") != null);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "1 roots: no damage") != null);
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "verify" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.store.verify/1", object.get("schema").?.string);
    try testing.expect(object.get("ok").?.bool);
    const keys = [_][]const u8{
        "schema", "ok",    "objects",         "object_bytes", "chunk_lists",
        "trees",  "roots", "paths_truncated", "things",
    };
    try json_object_has(object, schemas.of("store-verify").?, &keys);
    try testing.expectEqual(@as(usize, 0), object.get("things").?.array.items.len);
}

test "verify names a damaged object, its file and every path that reaches it, and exits 2" {
    // Goal: the demo's step 4. Method: the byte of the object /etc/passwd became is changed.
    start();
    files.put_file("/src/etc/passwd-copy", 0o644, "root:x:0:0\n");
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [200]u8 = undefined;
    const object_path = stored_object("/src/etc/passwd", &buffer);
    files.flip_byte(object_path, 1);
    try testing.expectEqual(@as(u8, 2), try command(&.{ "store", "verify" }));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-E0429]"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-E0430]"));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "1 damaged") != null);
    // The default text names a path and says how many more, not only --verbose.
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "reached by") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "/etc/passwd") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "and 1 more") != null);
    try testing.expectEqual(@as(u8, 2), try command(&.{ "--verbose", "store", "verify" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), object_path) != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "reached by") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "/etc/passwd-copy in root") != null);
    try testing.expectEqual(@as(u8, 2), try command(&.{ "--output", "json", "store", "verify" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expect(!object.get("ok").?.bool);
    try testing.expectEqual(@as(i64, 1), object.get("damaged").?.integer);
    const thing = object.get("things").?.array.items[0].object;
    try testing.expectEqualStrings("content", thing.get("kind").?.string);
    try testing.expectEqual(@as(i64, 2), thing.get("reached").?.integer);
    const paths = thing.get("paths").?.array.items;
    try testing.expectEqualStrings("/etc/passwd", paths[0].object.get("path").?.string);
    try testing.expectEqualStrings("/etc/passwd-copy", paths[1].object.get("path").?.string);
    try testing.expect(Digest.parse(paths[0].object.get("root").?.string) != null);
    try json_object_has(
        thing,
        schemas.of("store-verify").?,
        &.{ "id", "class", "reason", "errno" },
    );
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, sim.stderr(), "\"code\":\"ZBX-E04"));
}

/// The plan hash a `gc --output json` printed.
fn printed_plan(buffer: *[80]u8) ![:0]const u8 {
    const parsed = try parse_stdout();
    defer parsed.deinit();
    return term(buffer, parsed.value.object.get("plan").?.string);
}

/// Two trees imported and the second's root dropped; returns the plan's hash in `buffer`.
fn drop_second_root(buffer: *[80]u8) ![:0]const u8 {
    var argument: [80]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    files.put_file("/src/etc/extra", 0o644, "extra bytes\n");
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const second = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(second);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "gc" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "nothing is unreachable") != null);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "rm", term(&argument, second) }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "gc" }));
    return printed_plan(buffer);
}

fn stored_files() u32 {
    return support.count_files(&files, support.user_store ++ "/objects") +
        support.count_files(&files, support.user_store ++ "/trees");
}

test "gc plans what a dropped root frees, and refuses a hash that is not the plan" {
    // Goal: plan, then confirm by hash. Method: two trees, one root dropped.
    start();
    var hash_storage: [80]u8 = undefined;
    const hash = try drop_second_root(&hash_storage);
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        const plan = parsed.value.object;
        try testing.expect(!plan.get("applied").?.bool);
        try testing.expectEqual(@as(i64, 1), plan.get("objects").?.integer);
        try testing.expectEqual(@as(i64, 2), plan.get("trees").?.integer);
        const keys = [_][]const u8{ "schema", "applied", "plan", "objects", "lists", "trees" };
        try json_object_has(plan, schemas.of("store-gc").?, &keys);
    }
    const before = stored_files();
    try testing.expectEqual(@as(u8, 1), try command(&.{ "store", "gc", "--confirm", zero_hash }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0431]") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), hash) != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expectEqual(before, stored_files());
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "gc" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "would move to the trash") != null);
}

test "gc applies the right hash, lists the trash, and restore puts it back" {
    start();
    var hash_storage: [80]u8 = undefined;
    const hash = try drop_second_root(&hash_storage);
    const before = stored_files();
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "gc", "--confirm", hash }),
    );
    var id_storage: [80]u8 = undefined;
    const id = id: {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        const applied = parsed.value.object;
        try testing.expect(applied.get("applied").?.bool);
        break :id term(&id_storage, applied.get("gc").?.string);
    };
    try testing.expectEqual(before - 3, stored_files());
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "gc", "--trash" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), id) != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "complete") != null);
    const listing = [_][:0]const u8{ "--output", "json", "store", "gc", "--trash" };
    try testing.expectEqual(@as(u8, 0), try command(&listing));
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        const entry = parsed.value.object.get("trash").?.array.items[0].object;
        try testing.expect(entry.get("complete").?.bool);
        try json_object_has(entry, schemas.of("store-trash").?, &.{ "gc", "readable", "expires" });
    }
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "restore", id }),
    );
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        try testing.expectEqual(@as(i64, 2), parsed.value.object.get("trees").?.integer);
        const keys = [_][]const u8{ "schema", "gc", "objects", "trees", "farms" };
        try json_object_has(parsed.value.object, schemas.of("store-restore").?, &keys);
    }
    try testing.expectEqual(before, stored_files());
    try testing.expectEqual(@as(u8, 1), try command(&.{ "store", "restore", id }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0433") != null);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
}

test "the usage errors of verify, gc and restore are coded, with nothing on stdout" {
    start();
    const cases = [_]struct { args: []const [:0]const u8, code: []const u8 }{
        .{ .args = &.{ "store", "verify", "x" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "gc", "x" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "restore" }, .code = "ZBX-E0006" },
        .{ .args = &.{ "store", "restore", "a", "b" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "restore", "not-an-id" }, .code = "ZBX-E0433" },
        .{ .args = &.{ "store", "restore", "0123456789ab" }, .code = "ZBX-E0433" },
        .{ .args = &.{ "store", "gc", "--confirm" }, .code = "ZBX-E0005" },
        .{ .args = &.{ "store", "gc", "--confirm", "abc" }, .code = "ZBX-E0412" },
        .{ .args = &.{ "store", "gc", "--confirm", zero_hash, "--trash" }, .code = "ZBX-E0003" },
        .{ .args = &.{ "store", "ls", "--trash" }, .code = "ZBX-E0004" },
        .{ .args = &.{ "store", "verify", "--confirm", zero_hash }, .code = "ZBX-E0004" },
    };
    for (cases) |case| {
        try testing.expect(try command(case.args) != 0);
        testing.expect(std.mem.indexOf(u8, sim.stderr(), case.code) != null) catch |err| {
            std.debug.print("{s}: {s}\n", .{ case.args[case.args.len - 1], sim.stderr() });
            return err;
        };
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-"));
    }
}

var live_handle: @import("runtime/run.zig").Handle = undefined;
var live_workspace: store_commands.Workspace = undefined;

test "the trees of running containers, and only of those, are what gc is told to keep" {
    // Goal: live containers are roots. Method: a detached run in the simulator, its record
    // made to name a tree (as a run by digest writes it); gc's preparation finds it while the
    // container runs and not after it ends.
    start();
    const run = @import("runtime/run.zig");
    const container: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web-1",
        .command = &.{"/bin/sh"},
    };
    sim.world.command_runs_ms = 3_600_000;
    var diag: @import("diag/diag.zig").Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &container, .{ .detached = true }, &live_handle, &diag);
    const record_path = sim_run.runs_path ++ "/web-1.zon";
    const text = sim.world.read_written(record_path).?;
    var patched: [constants.record_bytes_max]u8 = undefined;
    const marker = ".tree = \"\"";
    const at = std.mem.indexOf(u8, text, marker).?;
    const tree_text = "b3:" ++ test_util.repeat('c', 64);
    const record = try std.fmt.bufPrint(&patched, "{s}.tree = \"{s}\"{s}", .{
        text[0..at], tree_text, text[at + marker.len ..],
    });
    try testing.expect(sim.world.write_file(record_path, record) == null);
    const args: store_commands.Args = .{ .action = .gc, .operand = null };
    _ = try store_commands.prepare_gc(sim.interface(), args, &live_workspace, &diag);
    try testing.expectEqual(@as(u32, 1), live_workspace.live_count);
    try testing.expectEqualStrings(tree_text, &live_workspace.live[0].text());
    // A container that ended without a layer to commit does not hold its tree; one that ended
    // with its layer still on disk does (it can be committed), and one whose layer is gone not.
    const other = "b3:" ++ test_util.repeat('d', 64);
    const kept = "b3:" ++ test_util.repeat('e', 64);
    var done = sim_run.sample_view("done-1", 1000);
    done.tree = other;
    sim_run.put_record(&sim, &done);
    var ended = sim_run.sample_view("done-2", 1001);
    ended.tree = kept;
    ended.upper = "/upper-2";
    files.put_dir("/upper-2", 0o755);
    sim_run.put_record(&sim, &ended);
    var gone = sim_run.sample_view("done-3", 1002);
    gone.tree = "b3:" ++ test_util.repeat('f', 64);
    gone.upper = "/upper-3";
    sim_run.put_record(&sim, &gone);
    _ = try store_commands.prepare_gc(sim.interface(), args, &live_workspace, &diag);
    try testing.expectEqual(@as(u32, 2), live_workspace.live_count);
    var seen_running = false;
    var seen_ended = false;
    for (live_workspace.live[0..2]) |digest| {
        if (std.mem.eql(u8, &digest.text(), tree_text)) seen_running = true;
        if (std.mem.eql(u8, &digest.text(), kept)) seen_ended = true;
    }
    try testing.expect(seen_running and seen_ended);
    // `--trash` does not look at containers at all.
    const trash: store_commands.Args = .{ .action = .gc, .operand = null, .trash = true };
    _ = try store_commands.prepare_gc(sim.interface(), trash, &live_workspace, &diag);
    try testing.expectEqual(@as(u32, 0), live_workspace.live_count);
    live_handle.session.release_keeper();
    sim.world.command_runs_ms = 0;
}

test "a gc confirm and a restore are refused with E0436 while a writer holds the store" {
    // Goal: the lock as the user meets it. Method: another program holds the lock shared (an
    // import in progress); gc --confirm and restore wait their ten seconds and say the store is
    // in use, changing nothing and printing nothing.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var writer: @import("store/layout.zig").Store = undefined;
    writer.at(sim.interface(), support.user_store);
    try @import("store/lock.zig").hold(&writer, .shared, "import");
    defer @import("store/lock.zig").release(&writer);
    const before = stored_files();
    const cases = [_][]const [:0]const u8{
        &.{ "store", "gc", "--confirm", zero_hash },
        &.{ "store", "restore", "aaaaaaaaaaaa" },
    };
    for (cases) |args| {
        const began = sim.world.now_ms;
        try testing.expectEqual(@as(u8, 1), command_raw(args));
        try testing.expect(sim.world.now_ms - began >= constants.store_lock_wait_ms);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "error[ZBX-E0436]") != null);
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), "writing to the store") != null);
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    }
    try testing.expectEqual(before, stored_files());
}

test "an ended container's tree survives gc, and commit still works" {
    // Goal: gc must not strand `zbx commit`. Method: import, a container record with its upper
    // layer, the root dropped. gc plans nothing to move, and commit works after a confirmed
    // gc. With the layer gone (or the record pruned) the tree is a plan item.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const parent = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(parent);
    put_container(parent);
    files.put_file("/upper/new", 0o644, "added\n");
    var argument: [80]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "rm", term(&argument, parent) }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "gc" }));
    {
        const parsed = try parse_stdout();
        defer parsed.deinit();
        try testing.expectEqual(@as(i64, 0), parsed.value.object.get("trees").?.integer);
        try testing.expectEqual(@as(i64, 0), parsed.value.object.get("objects").?.integer);
    }
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "gc" }));
    var hash_storage: [80]u8 = undefined;
    const hash = try printed_plan(&hash_storage);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "gc", "--confirm", hash }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "commit", "web-1" }));
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
    // The commit's root keeps the new tree; the parent is the container's, not a root, and is
    // kept as long as the container's layer is.
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "verify" }));
    // The layer is gone: nothing can be committed, so the parent tree is no longer held.
    files.remove_path("/upper/new");
    files.remove_path("/upper");
    try testing.expectEqual(@as(u8, 0), try command(&.{ "--output", "json", "store", "gc" }));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    try testing.expect(parsed.value.object.get("trees").?.integer > 0);
}

test "store gc never reads, moves or removes anything under state/" {
    // Goal: state volumes are never collected implicitly (docs/briefs/M6-state.md). Method: a
    // store with a dropped root next to a state directory holding a volume (files, a record,
    // a lock), and a trash entry whose time is long past; a gc plan and its confirm with the
    // clock moved past every expiry. Every path under state/ is there afterwards, with its bytes,
    // and the plan counted nothing of it.
    start();
    const state = "/home/alice/.local/share/zbx/state";
    const paths = [_][]const u8{
        state,                         state ++ "/pgdata",
        state ++ "/pgdata/data",       state ++ "/pgdata/data/base",
        state ++ "/.trash",            state ++ "/.trash/old@1",
        state ++ "/.trash/old@1/data",
    };
    var hash_storage: [80]u8 = undefined;
    const hash = try drop_second_root(&hash_storage);
    for (paths) |path| files.put_dir(path, 0o700);
    files.put_file(state ++ "/pgdata/data/base/1", 0o600, "a row\n");
    files.put_file(state ++ "/pgdata/state.zon", 0o644, ".{}\n");
    files.put_file(state ++ "/pgdata/lock", 0o600, "");
    files.put_file(state ++ "/.trash/old@1/data/f", 0o600, "old");
    sim.world.now += 30 * 24 * 60 * 60;
    files.clock += 30 * 24 * 60 * 60;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "gc", "--confirm", hash }));
    for (paths) |path| try testing.expect(files.kind_of(path).? == .dir);
    try testing.expectEqualStrings("a row\n", files.content_of(state ++ "/pgdata/data/base/1").?);
    try testing.expectEqualStrings(".{}\n", files.content_of(state ++ "/pgdata/state.zon").?);
    try testing.expectEqualStrings("old", files.content_of(state ++ "/.trash/old@1/data/f").?);
    try testing.expect(files.kind_of(state ++ "/pgdata/lock") != null);
}

// ---- export (lane U) ------------------------------------------------------------------------

/// The OCI digest an export printed, without its newline.
/// `zbx store export --oci` with the two words after it: the source and the directory.
fn export_to(words: *const [2][:0]const u8) !u8 {
    return command(&.{ "store", "export", "--oci", words[0], words[1] });
}

fn printed_oci_digest() ![]const u8 {
    const out = sim.stdout();
    try testing.expect(out.len == constants.oci_digest_text_bytes + 1);
    try testing.expect(out[out.len - 1] == '\n');
    try testing.expect(Sha256.parse(out[0 .. out.len - 1]) != null);
    return out[0 .. out.len - 1];
}

test "export of an imported tree prints the manifest digest and writes a whole layout" {
    // Goal: `store export --oci <tree>` end to end through the command line, which also runs
    // `source.resolve` on a bare tree digest. Method: import, export twice into two new
    // directories; both print the same manifest digest, whose blob, the layout marker and the
    // index exist, and stderr stays empty.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    const tree = try testing.allocator.dupe(u8, try printed_digest());
    defer testing.allocator.free(tree);
    var first: [constants.oci_digest_text_bytes]u8 = undefined;
    for ([_][:0]const u8{ "/export-a", "/export-b" }, 0..) |dir, index| {
        const args = [_][:0]const u8{ "store", "export", "--oci", "", dir };
        var buffer: [80]u8 = undefined;
        var mine = args;
        mine[3] = term(&buffer, tree);
        try testing.expectEqual(@as(u8, 0), try command(&mine));
        const manifest = try printed_oci_digest();
        if (index == 0) {
            @memcpy(&first, manifest);
        } else {
            try testing.expectEqualStrings(&first, manifest);
        }
        try testing.expectEqual(@as(usize, 0), sim.stderr().len);
        var path: [96]u8 = undefined;
        const marker = try std.fmt.bufPrint(&path, "{s}/oci-layout", .{dir});
        try testing.expect(files.kind_of(marker) != null);
        const index_path = try std.fmt.bufPrint(&path, "{s}/index.json", .{dir});
        const index_text = files.content_of(index_path).?;
        try testing.expect(std.mem.indexOf(u8, index_text, &first) != null);
        const blob = try std.fmt.bufPrint(&path, "{s}/blobs/sha256/{s}", .{ dir, first[7..] });
        try testing.expect(files.kind_of(blob) != null);
    }
}

test "push --dry-run prints the digest an export prints, and refuses without --dry-run" {
    // Goal: the brief's `zbx push --dry-run`: packs, prints the manifest digest, no network.
    // Method: import, export (the reference digest), then push --dry-run the same tree.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [80]u8 = undefined;
    const tree = term(&buffer, try printed_digest());
    try testing.expectEqual(@as(u8, 0), try export_to(&.{ tree, "/export-a" }));
    var expected: [constants.oci_digest_text_bytes]u8 = undefined;
    @memcpy(&expected, try printed_oci_digest());
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", "--dry-run", tree }));
    try testing.expectEqualStrings(&expected, try printed_oci_digest());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", tree }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "needs the destination") != null);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", "--dry-run" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "needs the build result") != null);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", "--dry-run", "nope" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0550") != null);
}

test "push --dry-run takes name@sha256:<digest>, as sign does (#111)" {
    // Goal: a digest reference names one image of the store, so a dry run of it packs that image
    // and prints the same manifest digest; it used to be refused as E0550 because the lookup
    // read `@` references as tags. Method: a dry run records the image, then name it by digest;
    // a digest the store does not hold, and a name with no digest, are still E0550.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [80]u8 = undefined;
    const tree = term(&buffer, try printed_digest());
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", "--dry-run", tree }));
    var expected: [constants.oci_digest_text_bytes]u8 = undefined;
    @memcpy(&expected, try printed_oci_digest());
    var operand: [128]u8 = undefined;
    const named = try std.fmt.bufPrintSentinel(&operand, "alpine@{s}", .{&expected}, 0);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", "--dry-run", named }));
    try testing.expectEqualStrings(&expected, try printed_oci_digest());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    const absent = "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", "--dry-run", absent }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0550") != null);
}

var push_wire: net_sim.SimNet = undefined;
var upload_registry: push_registry.PushRegistry = undefined;

test "push puts the image in the registry, prints the digest, and a repeat sends nothing" {
    // Goal: `zbx push <source> <destination>` end to end in the simulator. Method: import, push
    // to a tag, push again; the digest is the dry run's, the JSON result lists each blob as
    // uploaded and then as existing, and a destination without a tag is E0551.
    start();
    push_wire.init(1, upload_registry.responder());
    upload_registry.init(&push_wire);
    sim.wire = &push_wire;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [80]u8 = undefined;
    const tree = term(&buffer, try printed_digest());
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", "--dry-run", tree }));
    var expected: [constants.oci_digest_text_bytes]u8 = undefined;
    @memcpy(&expected, try printed_oci_digest());
    const target = push_registry.PushRegistry.destination(.ok);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", tree, target }));
    try testing.expectEqualStrings(&expected, try printed_oci_digest());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    const json_push = [_][:0]const u8{ "--output", "json", "push", tree, target };
    try testing.expectEqual(@as(u8, 0), try command(&json_push));
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.push/1", object.get("schema").?.string);
    try testing.expectEqualStrings(&expected, object.get("manifest").?.string);
    for (object.get("blobs").?.array.items) |blob| {
        try testing.expectEqualStrings("exists", blob.object.get("outcome").?.string);
    }
    const bare = push_registry.registry_host ++ "/push/ok";
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", tree, bare }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0551") != null);
}

test "a push whose tag record fails warns W0552 and still succeeds" {
    // Goal: the registry holds the image, so a host failure while the store records the tag is
    // a warning, not a failed push. Method: walk a one-shot failure across every host call of a
    // push; each run either fails with an error, succeeds quietly, or exits 0 with the digest on
    // stdout and W0552 on stderr, and the walk must reach the third kind at least once.
    var writes: u32 = 0;
    var warned: u32 = 0;
    var index: u32 = 0;
    while (index <= writes) : (index += 1) {
        start();
        push_wire.init(1, upload_registry.responder());
        upload_registry.init(&push_wire);
        sim.wire = &push_wire;
        try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
        var buffer: [80]u8 = undefined;
        const tree = term(&buffer, try printed_digest());
        const target = push_registry.PushRegistry.destination(.ok);
        const before = files.mutations;
        if (index > 0) files.faults.fail_mutation = before + index - 1;
        const code = try command(&.{ "push", tree, target });
        if (index == 0) writes = files.mutations - before;
        files.faults.fail_mutation = null;
        if (code != 0) continue;
        if (std.mem.indexOf(u8, sim.stderr(), "ZBX-W0552") == null) continue;
        warned += 1;
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "warning["));
        try testing.expect(std.mem.startsWith(u8, sim.stdout(), "sha256:"));
    }
    try testing.expect(warned > 0);
}

/// Imports the sample tree and starts the registry; returns the tree's term.
fn start_push(buffer: *[80]u8) ![:0]const u8 {
    start();
    push_wire.init(1, upload_registry.responder());
    upload_registry.init(&push_wire);
    sim.wire = &push_wire;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    return term(buffer, try printed_digest());
}

fn seen(needle: []const u8) bool {
    if (std.mem.indexOf(u8, sim.stdout(), needle) != null) return true;
    return std.mem.indexOf(u8, sim.stderr(), needle) != null;
}

test "push logs in with --username and a password on standard input or in a file" {
    // Goal: the credential flags end to end. Method: a registry that asks for Basic and one that
    // asks for a Bearer token; the password arrives on stdin, then from a 0600 file.
    const secret = "Hunter-22-marker";
    inline for (.{ push_registry.Mode.basic, push_registry.Mode.bearer }) |mode| {
        var buffer: [80]u8 = undefined;
        const tree = try start_push(&buffer);
        upload_registry.require(mode, secret);
        const target = push_registry.PushRegistry.destination(.ok);
        const user = push_registry.test_user;
        sim.world.input = secret ++ "\n";
        sim.world.input_handle = null;
        const by_stdin = &.{ "push", tree, target, "--username", user, "--password-stdin" };
        try testing.expectEqual(@as(u8, 0), try command(by_stdin));
        try testing.expect(std.mem.startsWith(u8, sim.stdout(), "sha256:"));
        try testing.expect(!seen(secret));
        files.put_file("/pw", 0o600, secret ++ "\n");
        const by_file = &.{ "push", tree, target, "--username", user, "--password-file=/pw" };
        try testing.expectEqual(@as(u8, 0), try command(by_file));
        try testing.expect(!seen(secret));
    }
}

test "push without credentials to a registry that asks is E0552, and wrong ones E0553" {
    // Goal: the two codes at the command line, with the password nowhere in the output.
    var buffer: [80]u8 = undefined;
    const tree = try start_push(&buffer);
    upload_registry.require(.bearer, "the-right-one");
    const target = push_registry.PushRegistry.destination(.ok);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "push", tree, target }));
    try testing.expect(seen("ZBX-E0552"));
    files.put_file("/pw", 0o600, "the-wrong-one\n");
    const user = push_registry.test_user;
    const wrong = &.{ "push", tree, target, "--username", user, "--password-file", "/pw" };
    try testing.expectEqual(@as(u8, 1), try command(wrong));
    try testing.expect(seen("ZBX-E0553"));
    try testing.expect(!seen("the-wrong-one"));
}

test "the password file's rules: mode, link, missing, empty, long, and a terminal on stdin" {
    // Goal: E0558 for each unsafe or unusable source, before any request is made.
    var buffer: [80]u8 = undefined;
    const tree = try start_push(&buffer);
    upload_registry.require(.basic, "pw");
    const target = push_registry.PushRegistry.destination(.ok);
    const user = push_registry.test_user;
    files.put_file("/open", 0o644, "pw\n");
    files.put_file("/empty", 0o600, "\n");
    files.put_symlink("/link", "/open");
    var long: [push_long]u8 = undefined;
    @memset(&long, 'x');
    files.put_file("/long", 0o600, &long);
    const paths = [_][:0]const u8{ "/open", "/empty", "/link", "/missing", "/long" };
    for (paths) |path| {
        errdefer std.debug.print("path {s}\n", .{path});
        const argv = &.{ "push", tree, target, "--username", user, "--password-file", path };
        const before = push_wire.requests;
        try testing.expectEqual(@as(u8, 1), try command(argv));
        try testing.expect(seen("ZBX-E0558"));
        try testing.expectEqual(before, push_wire.requests);
    }
    sim.terminal = true;
    sim.world.input_terminal = true;
    sim.world.input = "pw\n";
    sim.world.input_handle = null;
    const typed = &.{ "push", tree, target, "--username", user, "--password-stdin" };
    try testing.expectEqual(@as(u8, 1), try command(typed));
    try testing.expect(seen("ZBX-E0558"));
    try testing.expect(sim.world.input_handle == null); // Never read.
}

const push_long = constants.push_credential_bytes_max + 100;

test "the credential options: --password is refused without its value, and misuse is E0003" {
    // Goal: no secret on the command line is accepted, and none is echoed back.
    var buffer: [80]u8 = undefined;
    const tree = try start_push(&buffer);
    const target = push_registry.PushRegistry.destination(.ok);
    const bad = [_][]const [:0]const u8{
        &.{ "push", tree, target, "--password", "s3cret-value" },
        &.{ "push", tree, target, "--password=s3cret-value" },
        &.{ "push", tree, target, "--username", "u" },
        &.{ "push", tree, target, "--password-stdin" },
        &.{ "push", tree, target, "--username", "u", "--password-stdin", "--password-file", "/x" },
        &.{ "push", tree, target, "--username", "u", "--username", "v", "--password-stdin" },
        &.{ "pull", target, "--username", "u" },
    };
    for (bad) |argv| {
        try testing.expectEqual(@as(u8, 1), try command(argv));
        try testing.expect(!seen("s3cret-value"));
        // `pull` has no credential options at all, so it says "unknown option".
        const code = if (std.mem.eql(u8, argv[0], "pull")) "ZBX-E0004" else "ZBX-E0003";
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), code) != null);
    }
}

test "the marker password is in no output, file or log, and only in requests to the registry" {
    // Goal: the brief's marker test at the command line. Method: over random runs (registry
    // mode, fault, failures), the marker and the base64 of user:marker are recorded nowhere the
    // simulator keeps: stdout, stderr, every file, and every request to another host.
    const modes = [_]push_registry.Mode{ .basic, .bearer, .expiring, .far_realm, .pull_only };
    const faults = [_][:0]const u8{
        push_registry.PushRegistry.destination(.ok),
        push_registry.PushRegistry.destination(.farlocation),
        push_registry.PushRegistry.destination(.absolute),
    };
    var seed: u64 = 0;
    while (seed < 60) : (seed += 1) {
        var prng = std.Random.Xoshiro256.init(seed);
        const random = prng.random();
        var buffer: [80]u8 = undefined;
        const tree = try start_push(&buffer);
        var secret: [20]u8 = undefined;
        for (&secret) |*byte| byte.* = "ABCDEFGHJKLMNPQRSTUVWXYZ"[random.uintLessThan(usize, 24)];
        upload_registry.require(modes[random.uintLessThan(usize, modes.len)], &secret);
        upload_registry.expire_after = random.intRangeAtMost(u32, 2, 6);
        push_wire.faults = .{ .fail_per_mille = random.uintLessThan(u16, 30) };
        sim.world.input = &secret;
        sim.world.input_handle = null;
        const target = faults[random.uintLessThan(usize, faults.len)];
        const user = push_registry.test_user;
        const argv = &.{ "push", tree, target, "--username", user, "--password-stdin" };
        _ = try command(argv);
        var plain: [64]u8 = undefined;
        const joined = try std.fmt.bufPrint(&plain, "{s}:{s}", .{ user, &secret });
        var encoded: [96]u8 = undefined;
        const based = std.base64.standard.Encoder.encode(&encoded, joined);
        try testing.expect(!seen(&secret));
        try testing.expect(!seen(based));
        try testing.expect(!files_hold(&secret));
        try testing.expect(!files_hold(based));
        try testing.expectEqual(@as(u32, 0), upload_registry.leaked);
        var index: u32 = 0;
        while (push_wire.logged(index)) |entry| : (index += 1) {
            if (std.mem.eql(u8, entry.host_text(), push_registry.registry_host)) continue;
            try testing.expectEqual(@as(u32, 0), entry.basic_len + entry.bearer_len);
        }
    }
}

fn files_hold(needle: []const u8) bool {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        const content = files.content_of(path) orelse continue;
        if (std.mem.indexOf(u8, content, needle) != null) return true;
    }
    return false;
}

test "export --output json is zbx.export/1, and its keys are the schema's" {
    // Goal: the machine-readable result issue #60 asked for. Method: parse it and check each
    // required key's type against the schema text.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [80]u8 = undefined;
    const tree = term(&buffer, try printed_digest());
    try testing.expectEqual(
        @as(u8, 0),
        try command(&.{ "--output", "json", "store", "export", "--oci", tree, "/export" }),
    );
    const parsed = try parse_stdout();
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.export/1", object.get("schema").?.string);
    try testing.expectEqualStrings("/export", object.get("dir").?.string);
    try testing.expect(object.get("size").?.integer > 0);
    const schema = schemas.of("store-export").?;
    for ([_][]const u8{ "manifest", "config", "layer" }) |key| {
        try testing.expect(std.mem.indexOf(u8, schema, key) != null);
        try testing.expect(Sha256.parse(object.get(key).?.string) != null);
    }
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "export refuses what cannot be packed or written with one coded line" {
    // Goal: E0550 for each way a source fails to resolve, and E0557 for a directory that holds
    // something. Method: an unknown name, a tree digest nothing holds, a manifest digest (not a
    // tree), then a second export into the first's directory; stdout stays empty each time.
    start();
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    var buffer: [80]u8 = undefined;
    const tree = term(&buffer, try printed_digest());
    const nothing = "b3:0000000000000000000000000000000000000000000000000000000000000000";
    try testing.expectEqual(@as(u8, 1), try export_to(&.{ "nope", "/o" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0550") != null);
    try testing.expectEqual(@as(u8, 1), try export_to(&.{ nothing, "/o" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0550") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expectEqual(@as(u8, 0), try export_to(&.{ tree, "/o" }));
    var manifest_buffer: [80]u8 = undefined;
    const manifest = term(&manifest_buffer, try printed_oci_digest());
    try testing.expectEqual(@as(u8, 1), try export_to(&.{ manifest, "/p" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0550") != null);
    try testing.expectEqual(@as(u8, 1), try command(&.{ "store", "export", "--oci", tree, "/o" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0557") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

// ---- Push credentials: which one the command line picks (M8 slice 13) ---------------------

const ecr_host = "123456789012.dkr.ecr.us-east-1.amazonaws.com";
var ecr_aws: aws_sim.AwsSim = .{};

const ecr_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = "/home/alice" },
    .{ .name = "AWS_ACCESS_KEY_ID", .value = aws_sim.issued_key_id },
    .{ .name = "AWS_SECRET_ACCESS_KEY", .value = aws_sim.issued_secret },
    .{ .name = "AWS_SESSION_TOKEN", .value = aws_sim.issued_token },
};

fn ecr_answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    assert(@intFromPtr(context) != 0);
    const is_aws = std.mem.startsWith(u8, request.host, "api.ecr.") or
        std.mem.startsWith(u8, request.host, "sts.") or
        std.mem.eql(u8, request.host, "169.254.169.254");
    const inner = if (is_aws) ecr_aws.responder() else upload_registry.responder();
    inner.answer(inner.context, request, received, served);
}

/// A store with the sample tree, an ECR-named registry that wants `AWS` and the model's password
/// (or, with `user_secret`, the test user and that), and AWS keys in the process environment.
fn start_ecr(buffer: *[80]u8, user_secret: ?[]const u8) ![:0]const u8 {
    start();
    ecr_aws = .{};
    ecr_aws.now_s = sim.world.now;
    var token: u8 = 0;
    push_wire.init(1, .{ .context = &token, .answer = ecr_answer });
    upload_registry.init(&push_wire);
    upload_registry.host = ecr_host;
    upload_registry.fixture.init("https://" ++ ecr_host, "https://" ++ push_registry.other_host);
    if (user_secret) |secret| {
        upload_registry.require(.basic, secret);
    } else {
        upload_registry.require_as("AWS", .basic, aws_sim.ecr_password);
    }
    sim.wire = &push_wire;
    try testing.expectEqual(@as(u8, 0), try command(&.{ "store", "import", "/src" }));
    sim.environment_variables = &ecr_env;
    return term(buffer, try printed_digest());
}

/// How many requests to `host` carried a Basic credential, and that credential's text each time
/// must be `expected`.
fn basic_requests_to(host: []const u8, expected: []const u8) !u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (push_wire.logged(index)) |entry| : (index += 1) {
        if (entry.basic_len == 0) continue;
        try testing.expectEqualStrings(host, entry.host_text());
        try testing.expectEqualStrings(expected, entry.basic_text());
        count += 1;
    }
    return count;
}

fn basic_of(comptime plain: []const u8) []const u8 {
    const length = comptime std.base64.standard.Encoder.calcSize(plain.len);
    const encoded = comptime blk: {
        var out: [length]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&out, plain);
        break :blk out;
    };
    return &encoded;
}

test "push to ECR with no --username resolves AWS credentials and sends the AWS token" {
    // Goal: the command line's AWS step. Method: keys in the environment, no --username; the ECR
    // API is asked once, every registry request that carries a credential carries the AWS token,
    // and neither output stream (JSON included) holds the token, the password or a secret.
    var buffer: [80]u8 = undefined;
    const tree = try start_ecr(&buffer, null);
    const target = ecr_host ++ "/push/ok:v1";
    const json = [_][:0]const u8{ "--output", "json", "push", tree, target };
    try testing.expectEqual(@as(u8, 0), try command(&json));
    try testing.expectEqual(@as(u32, 1), ecr_aws.ecr_ok);
    const token = comptime basic_of("AWS:" ++ aws_sim.ecr_password);
    try testing.expect(try basic_requests_to(ecr_host, token) > 0);
    const secrets = [_][]const u8{
        token,
        aws_sim.ecr_password,
        aws_sim.issued_secret,
        aws_sim.issued_token,
    };
    for (secrets) |secret| {
        try testing.expect(!seen(secret));
    }
}

test "push to ECR with --username beats AWS: AWS is never asked and the user's password is sent" {
    // Goal: "an explicit --username beats AWS credentials". Method: the same environment, plus
    // --username; the model sees no ECR, STS or IMDS call, and the one credential on the wire is
    // the user's.
    const secret = "Hunter-22-marker";
    var buffer: [80]u8 = undefined;
    const tree = try start_ecr(&buffer, secret);
    files.put_file("/pw", 0o600, secret ++ "\n");
    const target = ecr_host ++ "/push/ok:v1";
    const user = push_registry.test_user;
    const argv = &.{ "push", tree, target, "--username", user, "--password-file", "/pw" };
    try testing.expectEqual(@as(u8, 0), try command(argv));
    try testing.expectEqual(@as(u32, 0), ecr_aws.ecr_calls);
    try testing.expectEqual(@as(u32, 0), ecr_aws.sts_calls);
    try testing.expectEqual(@as(u32, 0), ecr_aws.imds_calls);
    const expected = comptime basic_of(push_registry.test_user ++ ":" ++ secret);
    try testing.expect(try basic_requests_to(ecr_host, expected) > 0);
    try testing.expect(!seen(secret));
}

test "push to a registry that is not ECR never asks AWS, whatever the environment holds" {
    // Goal: AWS credentials are resolved for private ECR hosts only. Method: keys in the
    // environment, an open registry that is not ECR; the push works and the model is untouched.
    var buffer: [80]u8 = undefined;
    const tree = try start_push(&buffer);
    ecr_aws = .{};
    sim.environment_variables = &ecr_env;
    const target = push_registry.PushRegistry.destination(.ok);
    try testing.expectEqual(@as(u8, 0), try command(&.{ "push", tree, target }));
    try testing.expectEqual(@as(u32, 0), ecr_aws.ecr_calls);
    var index: u32 = 0;
    while (push_wire.logged(index)) |entry| : (index += 1) {
        try testing.expectEqual(@as(u32, 0), entry.basic_len);
        try testing.expectEqual(@as(u32, 0), entry.authorization_len);
    }
    try testing.expect(push_wire.requests > 0);
}
