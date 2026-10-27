//! Tests of `zbx pull --resolve-only` through the command line, against the simulated host and
//! the test registry on the simulated network: the output in both formats, the usage errors, and
//! that a registry token appears in no output of any mode, on success or on any failure.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const codes = @import("diag/codes.zig");
const host_mod = @import("host.zig");
const host_sim = @import("host_sim.zig");
const net_sim = @import("registry/net_sim.zig");
const schemas = @import("schemas.zig");
const sim_run = @import("runtime/sim_run.zig");
const test_registry = @import("registry/test_registry.zig");
const test_util = @import("test_util.zig");
const client_tests = @import("registry/client_tests.zig");

const testing = std.testing;
const HostSim = host_sim.HostSim;

/// One host, one test registry and the wire between them, set up as the tests need.
const World = struct {
    sim: HostSim,
    registry: test_registry.TestRegistry,
    wire: net_sim.SimNet,

    fn setup(world: *World, seed: u64) void {
        world.sim.init(seed, &.{});
        world.registry.init();
        world.wire.init(seed, world.registry.responder());
        world.sim.wire = &world.wire;
    }

    fn run(world: *World, args: []const [:0]const u8) u8 {
        var iterator: sim_run.SliceIterator = .{ .items = args };
        return cli.run_from_iterator(world.sim.interface(), &iterator);
    }
};

fn parse_json(bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
}

test "text output is the digest of this platform's manifest and nothing else" {
    // Goal: one line, sha256: and 64 hex digits, on stdout; nothing on stderr; exit 0.
    var world: World = undefined;
    world.setup(1);
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "pull", "--resolve-only", reference };
    try testing.expectEqual(@as(u8, 0), world.run(&args));
    const expected = world.registry.fixture.oci.amd64.digest;
    try testing.expectEqualStrings(&expected, std.mem.trimEnd(u8, world.sim.stdout(), "\n"));
    try testing.expectEqual(@as(usize, 0), world.sim.stderr().len);
    try testing.expectEqual(@as(usize, 72), world.sim.stdout().len);
}

test "the platform is the machine's, from its uname" {
    // Goal: an aarch64 host gets the arm64 manifest, in JSON too, and the digest differs.
    var world: World = undefined;
    world.setup(2);
    world.sim.uname_value.machine = host_mod.Text.from_slice("aarch64");
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "--output", "json", "pull", "--resolve-only", reference };
    try testing.expectEqual(@as(u8, 0), world.run(&args));
    const parsed = try parse_json(world.sim.stdout());
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("linux/arm64", object.get("platform").?.string);
    const digest = object.get("manifest_digest").?.string;
    try testing.expectEqualStrings(&world.registry.fixture.oci.arm64.digest, digest);
}

test "the JSON result has every key its schema requires, and its schema is registered" {
    // Goal: a script can rely on the schema: the required keys are all there, with the types.
    var world: World = undefined;
    world.setup(3);
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "pull", "--output=json", "--resolve-only", reference };
    try testing.expectEqual(@as(u8, 0), world.run(&args));
    try testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, world.sim.stdout(), "\n")));
    const parsed = try parse_json(world.sim.stdout());
    defer parsed.deinit();
    const object = parsed.value.object;
    const schema = schemas.of("pull-resolve").?;
    const required = [_][]const u8{
        "schema",        "reference",       "registry",      "repository",
        "index_digest",  "manifest_digest", "manifest_size", "platform",
        "config_digest", "config_size",     "layers",
    };
    for (required) |key| {
        try testing.expect(object.get(key) != null);
        var quoted: [40]u8 = undefined;
        const text = try std.fmt.bufPrint(&quoted, "\"{s}\"", .{key});
        try testing.expect(std.mem.indexOf(u8, schema, text) != null);
    }
    try testing.expectEqualStrings("zbx.pull.resolve/1", object.get("schema").?.string);
    const shown = object.get("reference").?.string;
    try testing.expectEqualStrings("registry.test/fixture/open:3.20", shown);

    try testing.expectEqual(@as(usize, 2), object.get("layers").?.array.items.len);
    const layer = object.get("layers").?.array.items[0].object;
    try testing.expectEqualStrings("tar_gzip", layer.get("kind").?.string);
    try testing.expectEqual(@as(u8, 0), world.run(&.{ "zbx", "schema", "pull-resolve" }));
}

test "usage: the flag and the reference are both needed, and the flag is pull's" {
    // Goal: E0006 without a reference, E0004 for the flag on another command, E0003 for a second
    // reference.
    var world: World = undefined;
    world.setup(4);
    try testing.expectEqual(@as(u8, 1), world.run(&.{ "zbx", "pull" }));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0006]"));
    try testing.expectEqual(@as(u32, 0), world.wire.requests);
    world.setup(5);
    try testing.expectEqual(@as(u8, 1), world.run(&.{ "zbx", "pull", "--resolve-only" }));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0006]"));
    world.setup(6);
    try testing.expectEqual(@as(u8, 1), world.run(&.{ "zbx", "ps", "--resolve-only" }));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0004]"));
    world.setup(7);
    const two = [_][:0]const u8{ "zbx", "pull", "--resolve-only", "a", "b" };
    try testing.expectEqual(@as(u8, 1), world.run(&two));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0003]"));
}

test "a host with no network says it cannot reach the registry" {
    // Goal: no wire at all is the connection failing, exit 2, not a crash or a hang.
    var world: World = undefined;
    world.setup(8);
    world.sim.wire = null;
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "pull", "--resolve-only", reference };
    try testing.expectEqual(@as(u8, 2), world.run(&args));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0503]"));
}

test "a registry token is in no output, in any mode, on success or on any failure" {
    // Goal: DIAGNOSTICS.md's secret rule for the registry. Method: every scenario of the test
    // registry (the ones with tokens included), in text, verbose and JSON mode; the token and the
    // header that carries it appear in neither stdout nor stderr.
    var world: World = undefined;
    const styles = [_][]const [:0]const u8{ &.{}, &.{"-v"}, &.{ "--output", "json" } };
    var found_token_flow: u32 = 0;
    for (client_tests.expectations) |expectation| {
        for (styles) |style| {
            world.setup(9);
            var items: [8][:0]const u8 = undefined;
            items[0] = "zbx";
            var count: usize = 1;
            for (style) |word| {
                items[count] = word;
                count += 1;
            }
            const reference = reference_of(expectation.scenario);
            const tail = [_][:0]const u8{ "pull", "--resolve-only", reference };
            for (tail) |word| {
                items[count] = word;
                count += 1;
            }
            _ = world.run(items[0..count]);
            for ([_][]const u8{ world.sim.stdout(), world.sim.stderr() }) |output| {
                try testing.expect(std.mem.indexOf(u8, output, test_registry.token_text) == null);
                try testing.expect(std.mem.indexOf(u8, output, "FAKEtoken") == null);
                try testing.expect(std.mem.indexOf(u8, output, "Bearer ") == null);
                try testing.expect(std.mem.indexOf(u8, output, "eyJzdWIi") == null);
            }
            for (0..world.wire.requests) |index| {
                const entry = world.wire.logged(@intCast(index)).?;
                if (std.mem.startsWith(u8, entry.target_text(), "/token")) found_token_flow += 1;
            }
        }
    }
    // The check is not vacuous: tokens were really exchanged in the seven scenarios that use
    // them, in each of the three modes.
    try testing.expectEqual(@as(u32, 21), found_token_flow);
}

fn reference_of(scenario: test_registry.Scenario) [:0]const u8 {
    return switch (scenario) {
        inline else => |known| test_registry.TestRegistry.reference(known),
    };
}

// ---- A whole pull ----------------------------------------------------------------------------

const fs_sim = @import("store/fs_sim.zig");
const support = @import("store/test_support.zig");

var store_files: fs_sim.SimFs = undefined;

/// A host that can map a full range of ids, a store disk, and the test registry on the wire.
fn pull_world(world: *World, seed: u64) void {
    sim_run.init(&world.sim, seed);
    world.registry.init();
    world.wire.init(seed, world.registry.responder());
    world.sim.wire = &world.wire;
    store_files.init(seed);
    store_files.put_dir("/home", 0o755);
    store_files.put_dir("/home/alice", 0o755);
    world.sim.store_fs = &store_files;
}

fn run_text(world: *World, args: []const [:0]const u8) u8 {
    world.sim.stdout_len = 0;
    world.sim.stderr_len = 0;
    return world.run(args);
}

/// What the fixture's two layers flatten to, built by hand under `/expected`.
fn build_expected() void {
    const f = &store_files;
    f.put_dir("/expected", 0o755);
    f.put_dir("/expected/etc", 0o755);
    f.put_file("/expected/etc/os-release", 0o644, "NAME=Fixture 2\n");
    f.put_dir("/expected/bin", 0o755);
    f.put_file("/expected/bin/hello", 0o755, "#!/bin/hello\n");
    f.put_file("/expected/bin/hi", 0o755, "#!/bin/hello\n");
    f.put_file("/expected/bin/ping", 0o755, "ping");
    f.put_xattr("/expected/bin/ping", "user.note", "kept");
    f.put_dir("/expected/lib", 0o755);
    f.put_file("/expected/lib/libx.so.1", 0o644, "ELF libx");
    f.put_symlink("/expected/lib/libx.so", "libx.so.1");
    f.put_dir("/expected/tmp", 0o1777);
    f.put_dir("/expected/usr", 0o755);
    f.put_dir("/expected/usr/old", 0o755);
    f.put_file("/expected/usr/old/new", 0o644, "new");
    f.put_dir("/expected/home", 0o755);
    f.put("/expected/home/user", .dir, 0o700, .{ 1000, 1000 }, "");
}

fn json_field(parsed: *const std.json.Parsed(std.json.Value), key: []const u8) []const u8 {
    return parsed.value.object.get(key).?.string;
}

test "a pull makes the tree the layers flatten to, and records the image" {
    // Goal: the whole path in the simulator: resolve, download, unpack in the child, import. The
    // tree is the digest of the hand-built result (so the whiteout, the opaque directory, the
    // replaced file, the hard link, the owner and the capability-less xattr are all right), the
    // trusted.* attribute was left out with a warning, and the store is whole.
    var world: World = undefined;
    pull_world(&world, 1);
    build_expected();
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "--output", "json", "pull", reference };
    try testing.expectEqual(@as(u8, 0), run_text(&world, &args));
    const parsed = try parse_json(world.sim.stdout());
    defer parsed.deinit();
    try testing.expectEqualStrings("zbx.pull/1", json_field(&parsed, "schema"));
    const image = &world.registry.fixture.oci;
    try testing.expectEqualStrings(&image.amd64.digest, json_field(&parsed, "manifest_digest"));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-W0502") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-W0501") == null);
    const layers = parsed.value.object.get("layers").?.array.items;
    try testing.expectEqual(@as(usize, 2), layers.len);
    try testing.expectEqualStrings("downloaded", layers[0].object.get("cache").?.string);
    const tree = try testing.allocator.dupe(u8, json_field(&parsed, "tree"));
    defer testing.allocator.free(tree);
    const import = [_][:0]const u8{ "zbx", "store", "import", "/expected" };
    try testing.expectEqual(@as(u8, 0), run_text(&world, &import));
    try testing.expectEqualStrings(tree, std.mem.trimEnd(u8, world.sim.stdout(), "\n"));
    try support.check_whole(&store_files, "/home/alice/.local/share/zbx/store", 1 << 20);
    // The staging directory is gone, and the blobs are in the cache.
    try testing.expect(store_files.kind_of("/home/alice/.local/share/zbx/store/blobs") != null);
    var count: u32 = 0;
    var index: u32 = 0;
    while (store_files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.indexOf(u8, path, "/store/tmp/") != null) count += 1;
    }
    try testing.expectEqual(@as(u32, 0), count);
}

test "a second pull asks the registry for the manifests only" {
    // Goal: blobs in the cache are not fetched again: the same tree, 'cached' for every blob,
    // and no request for a blob.
    var world: World = undefined;
    pull_world(&world, 2);
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "--output", "json", "pull", reference };
    try testing.expectEqual(@as(u8, 0), run_text(&world, &args));
    const first = try parse_json(world.sim.stdout());
    defer first.deinit();
    const tree = try testing.allocator.dupe(u8, json_field(&first, "tree"));
    defer testing.allocator.free(tree);
    world.wire.requests = 0;
    try testing.expectEqual(@as(u8, 0), run_text(&world, &args));
    const second = try parse_json(world.sim.stdout());
    defer second.deinit();
    try testing.expectEqualStrings(tree, json_field(&second, "tree"));
    try testing.expectEqual(@as(u32, 2), world.wire.requests);
    const layers = second.value.object.get("layers").?.array.items;
    for (layers) |layer| {
        try testing.expectEqualStrings("cached", layer.object.get("cache").?.string);
    }
}

test "text output is the manifest digest, as for --resolve-only" {
    // Goal: step 1 of the demo: the line a script captures.
    var world: World = undefined;
    pull_world(&world, 3);
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", reference }));
    const image = &world.registry.fixture.oci;
    const printed = std.mem.trimEnd(u8, world.sim.stdout(), "\n");
    try testing.expectEqualStrings(&image.amd64.digest, printed);
}

test "a pull cut in the middle resumes, and a hostile layer is refused with nothing kept" {
    // Goal: the acceptance criterion in the small: the second run downloads only the rest; an
    // image whose layer would write outside its root (E0515), one with a damaged tar (E0516),
    // and a layer of device nodes only (a warning, success).
    var world: World = undefined;
    pull_world(&world, 4);
    const open_reference = test_registry.TestRegistry.reference(.open);
    world.wire.faults.cut_per_mille = 1000;
    try testing.expectEqual(@as(u8, 3), run_text(&world, &.{ "zbx", "pull", open_reference }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0513") != null);
    world.wire.faults.cut_per_mille = 0;
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", open_reference }));

    pull_world(&world, 5);
    const unsafe = test_registry.TestRegistry.reference(.unsafe);
    try testing.expectEqual(@as(u8, 3), run_text(&world, &.{ "zbx", "pull", unsafe }));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0515]"));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "/etc/passwd") != null);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "store", "ls" }));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, world.sim.stdout(), "\n")); // Header.
    try testing.expect(store_files.kind_of("/etc") == null);

    pull_world(&world, 6);
    const damaged = test_registry.TestRegistry.reference(.damaged);
    try testing.expectEqual(@as(u8, 3), run_text(&world, &.{ "zbx", "pull", damaged }));
    try testing.expect(std.mem.startsWith(u8, world.sim.stderr(), "error[ZBX-E0516]"));

    pull_world(&world, 7);
    const special = test_registry.TestRegistry.reference(.special);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", special }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-W0501") != null);
}
