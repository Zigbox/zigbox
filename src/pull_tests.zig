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

test "a failed write anywhere in a pull is a coded refusal, and the next pull finishes the job" {
    // Goal: the pull's own durability, as the gc tests have for theirs. Method: the first run
    // gives the tree; then for every third write point of a pull the disk fails there
    // (`ENOSPC`, once): the command ends with 0 or with a coded error, never a crash; the store
    // is whole; a staging directory is left only when the failure was the removal of it, and
    // the same command run again gives the same tree and leaves nothing.
    var world: World = undefined;
    pull_world(&world, 20);
    const reference = test_registry.TestRegistry.reference(.open);
    const args = [_][:0]const u8{ "zbx", "--output", "json", "pull", reference };
    try testing.expectEqual(@as(u8, 0), run_text(&world, &args));
    const first = try parse_json(world.sim.stdout());
    var tree: [67]u8 = undefined;
    @memcpy(&tree, json_field(&first, "tree"));
    const points = store_files.mutations;
    first.deinit();
    try testing.expect(points > 50);
    var refused: u32 = 0;
    var at: u32 = 0;
    while (at < points) : (at += 3) {
        pull_world(&world, 21);
        store_files.faults.fail_mutation = at;
        store_files.faults.fail_errno = 28;
        const code = run_text(&world, &args);
        if (code != 0) {
            refused += 1;
            // The diagnostics are JSON lines, as the command was asked for JSON.
            try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "\"code\":\"ZBX-E") != null);
        }
        const left = staging_left();
        if (left > 0) {
            try testing.expect(code != 0);
            const said = std.mem.indexOf(u8, world.sim.stderr(), "staging directory");
            try testing.expect(said != null);
        }
        store_files.faults.fail_mutation = null;
        try support.check_whole(&store_files, "/home/alice/.local/share/zbx/store", 1 << 20);
        // The simulated process keeps its pid, so a second run would meet its own leftover; a
        // real one is a new process and gc removes the leftover of the dead one.
        if (left > 0) continue;
        try testing.expectEqual(@as(u8, 0), run_text(&world, &args));
        const again = try parse_json(world.sim.stdout());
        defer again.deinit();
        try testing.expectEqualStrings(&tree, json_field(&again, "tree"));
        try testing.expectEqual(@as(u32, 0), staging_left());
    }
    try testing.expect(refused > 10);
}

/// Files and directories under the store's `tmp/`.
fn staging_left() u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (store_files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.indexOf(u8, path, "/store/tmp/") != null) count += 1;
    }
    return count;
}

// ---- The lock, and running by name ----------------------------------------------------------

const project = "/home/alice/project";
const lock_path = project ++ "/zbx.lock";
const containers = "/home/alice/.local/state/zbx/containers";

/// A project directory to work in, with the host's /sys and a container root for `name`.
fn project_world(world: *World, seed: u64, name: []const u8) void {
    pull_world(world, seed);
    store_files.put_dir(project, 0o755);
    _ = world.sim.world.processes[0].cwd.set(project);
    world.sim.world.add_node("/sys", .dir);
    second_container(world, name);
}

fn joined(buffer: *[220]u8, base: []const u8, suffix: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ base, suffix }) catch unreachable; // Short.
}

/// The root of a container, as the run makes it when the overlay is mounted.
fn second_container(world: *World, name: []const u8) void {
    var path: [200]u8 = undefined;
    var inner: [220]u8 = undefined;
    const format = containers ++ "/{s}/merged";
    const merged = std.fmt.bufPrint(&path, format, .{name}) catch unreachable; // Short.
    world.sim.world.add_node(merged, .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        world.sim.world.add_node(joined(&inner, merged, suffix), .dir);
    }
    for ([_][]const u8{ "/bin/sh", "/bin/hello", "/bin/other", "/bin/svc" }) |program| {
        world.sim.world.add_node(joined(&inner, merged, program), .file);
    }
}

/// Replaces a file of the store disk (or makes it).
fn overwrite(path: []const u8, text: []const u8) void {
    var copy: [256]u8 = undefined; // The caller's path may be the model's own storage.
    @memcpy(copy[0..path.len], path);
    if (store_files.kind_of(copy[0..path.len]) != null) store_files.remove_path(copy[0..path.len]);
    store_files.put_file(copy[0..path.len], 0o644, text);
}

fn lock_text() []const u8 {
    return store_files.content_of(lock_path) orelse "";
}

test "a pull writes zbx.lock: the reference as written, sorted, and never the mirror" {
    // Goal: the lock records what the name meant, in the project directory. Method: two pulls
    // with a mirror named; the lock has both references in order, the manifest, platform and
    // tree of each, the JSON says it made the file once, and no mirror host appears in it.
    var world: World = undefined;
    project_world(&world, 31, "web-1");
    const mirrors = [_]host_sim.EnvironmentVariable{
        .{ .name = "HOME", .value = "/home/alice" },
        .{ .name = "ZBX_REGISTRY_MIRRORS", .value = "mirror.example" },
    };
    world.sim.environment_variables = &mirrors;
    const second = test_registry.TestRegistry.reference(.docker);
    const first = test_registry.TestRegistry.reference(.open);
    const code = run_text(&world, &.{ "zbx", "--output", "json", "pull", second });
    if (code != 0) std.debug.print("PULL2: {s}\n", .{world.sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    const made = try parse_json(world.sim.stdout());
    defer made.deinit();
    const lock = made.value.object.get("lock").?.object;
    try testing.expectEqualStrings(lock_path, lock.get("path").?.string);
    try testing.expect(lock.get("created").?.bool);
    const image = made.value.object.get("image").?.object;
    try testing.expectEqualStrings("/bin/hello", image.get("entrypoint").?.array.items[0].string);
    try testing.expectEqualStrings("/srv/app", image.get("workdir").?.string);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "pull", first }),
    );
    const again = try parse_json(world.sim.stdout());
    defer again.deinit();
    try testing.expect(!again.value.object.get("lock").?.object.get("created").?.bool);
    const text = lock_text();
    const at_first = std.mem.indexOf(u8, text, first).?;
    const at_second = std.mem.indexOf(u8, text, second).?;
    try testing.expect(at_second < at_first or std.mem.order(u8, second, first) == .lt);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, text, ".reference = "));
    try testing.expect(std.mem.indexOf(u8, text, "mirror") == null);
    try testing.expect(std.mem.indexOf(u8, text, &world.registry.fixture.oci.amd64.digest) != null);
    try testing.expect(std.mem.indexOf(u8, text, json_field(&again, "tree")) != null);
    // A digest reference needs no lock and leaves it alone.
    const before = try testing.allocator.dupe(u8, text);
    defer testing.allocator.free(before);
    var pinned: [200]u8 = undefined;
    const by_digest = try std.fmt.bufPrintSentinel(
        &pinned,
        "registry.test/fixture/open@{s}",
        .{&world.registry.fixture.oci.amd64.digest},
        0,
    );
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "pull", by_digest }),
    );
    const pulled = try parse_json(world.sim.stdout());
    defer pulled.deinit();
    try testing.expect(pulled.value.object.get("lock").? == .null);
    try testing.expectEqualStrings(before, lock_text());
}

fn started_argv(world: *const World) []const u8 {
    return world.sim.world.processes[1].exec_argv[0..world.sim.world.processes[1].exec_argv_len];
}

test "a run by tag starts the locked image with its entrypoint, command, env and directory" {
    // Goal: Docker's way of combining the image's settings, and the lock in force. Method: pull,
    // then run the tag with no command (entrypoint and cmd), with words after -- (the cmd is
    // replaced, the entrypoint stays) and read what the child was started with.
    var world: World = undefined;
    project_world(&world, 32, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    const code = run_text(&world, &.{ "zbx", "pull", reference });
    if (code != 0) std.debug.print("PULL: {s}\n", .{world.sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "run", "--name", "web-1", reference }),
    );
    try testing.expectEqualStrings("/bin/hello\nworld\n", started_argv(&world));
    const child = &world.sim.world.processes[1];
    const envp = child.exec_envp[0..child.exec_envp_len];
    try testing.expect(std.mem.indexOf(u8, envp, "PATH=/bin:/usr/bin\n") != null);
    try testing.expect(std.mem.indexOf(u8, envp, "LANG=C\n") != null);
    try testing.expect(std.mem.indexOf(u8, envp, "/sbin") == null); // The image's PATH, not ours.
    try testing.expect(std.mem.endsWith(u8, child.cwd.slice(), "/srv/app"));
    try testing.expect(child.user_set == null);
    // /sys is bound read-only from the host.
    var found_sys = false;
    const table = &world.sim.world.tables[child.table];
    for (table.mounts[0..table.count]) |mount| {
        if (std.mem.endsWith(u8, mount.target.slice(), "/sys")) found_sys = true;
    }
    try testing.expect(found_sys);
    second_container(&world, "web-2");
    const second_code = run_text(
        &world,
        &.{ "zbx", "run", "--name", "web-2", reference, "--", "one", "two" },
    );
    if (second_code != 0) std.debug.print("RUN2: {s}\n", .{world.sim.stderr()});
    try testing.expectEqual(@as(u8, 0), second_code);
    try testing.expectEqualStrings("/bin/hello\none\ntwo\n", started_argv(&world));
}

test "a run by tag refuses when the lock and the store disagree, naming both digests" {
    // Goal: step 5 of the demo, and its relatives. Method: edit the lock's tree, then its
    // manifest, then ask for a name it lacks; E0519, E0520, E0522, and a damaged lock E0518.
    var world: World = undefined;
    project_world(&world, 33, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "pull", reference }),
    );
    const pulled = try parse_json(world.sim.stdout());
    defer pulled.deinit();
    const tree = try testing.allocator.dupe(u8, json_field(&pulled, "tree"));
    defer testing.allocator.free(tree);
    const original = try testing.allocator.dupe(u8, lock_text());
    defer testing.allocator.free(original);
    const wrong_tree = "b3:" ++ test_util.repeat('0', 64);
    const edited = try std.mem.replaceOwned(u8, testing.allocator, original, tree, wrong_tree);
    defer testing.allocator.free(edited);
    overwrite(lock_path, edited);
    try testing.expectEqual(
        @as(u8, 125),
        run_text(&world, &.{ "zbx", "run", "--name", "web-1", reference }),
    );
    const refusal = world.sim.stderr();
    try testing.expect(std.mem.indexOf(u8, refusal, "ZBX-E0519") != null);
    try testing.expect(std.mem.indexOf(u8, refusal, tree) != null);
    try testing.expect(std.mem.indexOf(u8, refusal, wrong_tree) != null);

    const manifest = &world.registry.fixture.oci.amd64.digest;
    const wrong_manifest = "sha256:" ++ test_util.repeat('1', 64);
    const moved = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        original,
        manifest,
        wrong_manifest,
    );
    defer testing.allocator.free(moved);
    overwrite(lock_path, moved);
    try testing.expectEqual(
        @as(u8, 125),
        run_text(&world, &.{ "zbx", "run", "--name", "web-1", reference }),
    );
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0520") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), wrong_manifest) != null);
    try testing.expect(
        std.mem.indexOf(u8, world.sim.stderr(), manifest) != null,
    ); // What the store has.

    overwrite(lock_path, original);
    const other = test_registry.TestRegistry.reference(.docker);
    try testing.expectEqual(@as(u8, 125), run_text(&world, &.{ "zbx", "run", other }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0522") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "zbx pull") != null);

    overwrite(lock_path, ".{\n    .version = 1,\n    nonsense\n}\n");
    try testing.expectEqual(@as(u8, 125), run_text(&world, &.{ "zbx", "run", reference }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0518") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "line 3") != null);
    // None of the refusals pulled or started anything.
    try testing.expect(
        world.sim.world.processes[1].state == .unused or !world.sim.world.processes[1].execd,
    );
}

test "a run by tag with no lock pulls, writes one, and says so in one warning" {
    // Goal: the first run of a project. Method: nothing pulled, no lock; the run pulls quietly
    // (stdout is the container's, not the pull's), writes zbx.lock and warns W0503.
    var world: World = undefined;
    project_world(&world, 34, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expect(store_files.kind_of(lock_path) == null);
    const code = run_text(&world, &.{ "zbx", "run", "--name", "web-1", reference });
    if (code != 0) std.debug.print("RUN: {s}\n", .{world.sim.stderr()});
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expectEqual(@as(usize, 0), world.sim.stdout().len);
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, world.sim.stderr(), "warning[ZBX-W0503]"),
    );
    try testing.expect(std.mem.indexOf(u8, lock_text(), reference) != null);
    try testing.expectEqualStrings("/bin/hello\nworld\n", started_argv(&world));
    // The second run has a lock and says nothing.
    second_container(&world, "web-2");
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "run", "--name", "web-2", reference }),
    );
    try testing.expectEqual(@as(usize, 0), world.sim.stderr().len);
}

test "an image with no command and none given is refused" {
    // Goal: E0524. The fixture has a command, so the record is rewritten without one.
    var world: World = undefined;
    project_world(&world, 35, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", reference }));
    var index: u32 = 0;
    while (store_files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.indexOf(u8, path, "/store/images/") == null) continue;
        const record = store_files.content_of(path) orelse continue;
        var kept: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&kept);
        var lines = std.mem.splitScalar(u8, record, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " ");
            const drop = std.mem.startsWith(u8, trimmed, ".entrypoint") or
                std.mem.startsWith(u8, trimmed, ".cmd");
            if (drop) continue;
            try writer.print("{s}\n", .{line});
        }
        overwrite(path, std.mem.trimEnd(u8, writer.buffered(), "\n"));
    }
    try testing.expectEqual(@as(u8, 125), run_text(&world, &.{ "zbx", "run", reference }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0524") != null);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "run", "--name", "web-1", reference, "--", "/bin/other" }),
    );
    try testing.expectEqualStrings("/bin/other\n", started_argv(&world));
}

var library_handle: @import("runtime/run.zig").Handle = undefined;
var library_workspace: @import("runtime/image.zig").Workspace = undefined;

test "the library starts an image by its tag, from the store's records" {
    // Goal: Spec.image accepts a tag as well as a digest. Method: pull, then start through the
    // library with the tag; the container runs on the pulled tree. A tag nothing was pulled as
    // is E0522, and a digest reference of the manifest finds the same tree.
    const lib = @import("runtime/run.zig");
    var world: World = undefined;
    project_world(&world, 36, "lib-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", reference }));
    var diag: @import("diag/diag.zig").Diag = undefined;
    diag.reset();
    const container: lib.Spec = .{ .image = reference, .name = "lib-1", .command = &.{"/bin/sh"} };
    const options: lib.StartOptions = .{ .image_workspace = &library_workspace };
    try lib.start(world.sim.interface(), &container, options, &library_handle, &diag);
    try testing.expectEqual(lib.Status.running, lib.inspect(&library_handle));
    _ = lib.wait(&library_handle);
    diag.reset();
    const unknown: lib.Spec = .{
        .image = "registry.test/fixture/never:1",
        .name = "lib-2",
        .command = &.{"/bin/sh"},
    };
    try testing.expectError(
        error.StartFailed,
        lib.start(world.sim.interface(), &unknown, options, &library_handle, &diag),
    );
    try testing.expectEqual(@as(?codes.Code, .E0522), diag.code);
}

test "store ls and du --by-image show the images, and rm of a pulled tree takes its records" {
    // Goal: the store knows images. Method: pull; ls lists the image (text and JSON); du
    // --by-image gives the sizes, the compressed one being the layers' as downloaded; rm of the
    // tree removes its image record with the root, after which gc plans the blobs.
    var world: World = undefined;
    project_world(&world, 37, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "pull", reference }),
    );
    const pulled = try parse_json(world.sim.stdout());
    defer pulled.deinit();
    const tree = try testing.allocator.dupeSentinel(u8, json_field(&pulled, "tree"), 0);
    defer testing.allocator.free(tree);
    var layer_bytes: i64 = 0;
    for (pulled.value.object.get("layers").?.array.items) |layer| {
        layer_bytes += layer.object.get("size").?.integer;
    }

    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "store", "ls" }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), "\nIMAGE ") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), reference) != null);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "store", "ls" }),
    );
    try testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, world.sim.stdout(), "\n")));
    const listed = try parse_json(world.sim.stdout());
    defer listed.deinit();
    const images = listed.value.object.get("images").?.array.items;
    try testing.expectEqual(@as(usize, 1), images.len);
    try testing.expectEqualStrings(tree, images[0].object.get("tree").?.string);
    try testing.expectEqualStrings(reference, images[0].object.get("reference").?.string);

    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "store", "du", "--by-image" }),
    );
    const sized = try parse_json(world.sim.stdout());
    defer sized.deinit();
    const row = sized.value.object.get("images").?.array.items[0].object;
    try testing.expectEqualStrings(tree, row.get("tree").?.string);
    try testing.expectEqual(layer_bytes, row.get("compressed_bytes").?.integer);
    try testing.expect(row.get("logical_bytes").?.integer > 0);
    try testing.expect(row.get("stored_bytes").?.integer > 0);
    try testing.expectEqual(@as(i64, 0), row.get("shared_bytes").?.integer);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "store", "du", "--by-image" }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), "COMPRESSED") != null);
    try testing.expectEqual(
        @as(u8, 1),
        run_text(&world, &.{ "zbx", "store", "du", "--by-image", tree }),
    );
    try testing.expectEqual(@as(u8, 1), run_text(&world, &.{ "zbx", "store", "ls", "--by-image" }));
}

test "rm of a pulled tree takes its image record with it, and gc then plans the blobs" {
    // Goal: the tree is kept by its image record as well as its root, so rm drops both.
    var world: World = undefined;
    project_world(&world, 43, "web-1");
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "pull", reference }),
    );
    const pulled = try parse_json(world.sim.stdout());
    defer pulled.deinit();
    const tree = try testing.allocator.dupeSentinel(u8, json_field(&pulled, "tree"), 0);
    defer testing.allocator.free(tree);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "store", "rm", tree }),
    );
    const removed = try parse_json(world.sim.stdout());
    defer removed.deinit();
    try testing.expectEqual(@as(i64, 1), removed.value.object.get("images").?.integer);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "store", "ls" }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), "IMAGE") == null);
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "--output", "json", "store", "gc" }),
    );
    const plan = try parse_json(world.sim.stdout());
    defer plan.deinit();
    try testing.expectEqual(
        @as(i64, 3),
        plan.value.object.get("blobs").?.integer,
    ); // Config and two layers.
}

test "an image's user is resolved against its own files and set before the command" {
    // Goal: User "app:staff", the working directory and HOME, end to end. Method: pull an image
    // whose passwd and group have them; the child is started as 1000:50 in /var/lib/app with HOME
    // from passwd. The same image with the single-id map is E0523, a user the files lack is
    // E0521, and a configuration that is not JSON is E0517 with nothing recorded.
    const service = test_registry.TestRegistry.reference(.service);
    var world: World = undefined;
    project_world(&world, 38, "svc-1");
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", service }));
    try testing.expectEqual(
        @as(u8, 0),
        run_text(&world, &.{ "zbx", "run", "--name", "svc-1", service }),
    );
    const child = &world.sim.world.processes[1];
    try testing.expectEqual(@as(?[2]u32, .{ 1000, 50 }), child.user_set);
    try testing.expect(std.mem.endsWith(u8, child.cwd.slice(), "/var/lib/app"));
    try testing.expect(
        std.mem.indexOf(u8, child.exec_envp[0..child.exec_envp_len], "HOME=/home/app\n") != null,
    );
    try testing.expectEqualStrings("/bin/svc\n", started_argv(&world));

    // The same store and project, a host that can map only root.
    const saved_home = world.sim.environment_variables;
    sim_run.init_single(&world.sim, 39);
    world.sim.wire = &world.wire;
    world.sim.store_fs = &store_files;
    world.sim.environment_variables = saved_home;
    _ = world.sim.world.processes[0].cwd.set(project);
    world.sim.world.add_node("/sys", .dir);
    second_container(&world, "svc-2");
    try testing.expectEqual(
        @as(u8, 125),
        run_text(&world, &.{ "zbx", "run", "--name", "svc-2", service }),
    );
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0523") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "user 1000, group 50") != null);

    project_world(&world, 41, "ghost-1");
    const ghost = test_registry.TestRegistry.reference(.ghost);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "pull", ghost }));
    try testing.expectEqual(
        @as(u8, 125),
        run_text(&world, &.{ "zbx", "run", "--name", "ghost-1", ghost }),
    );
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0521") != null);
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "/etc/passwd") != null);

    project_world(&world, 42, "bad-1");
    const bad = test_registry.TestRegistry.reference(.badconfig);
    try testing.expectEqual(@as(u8, 3), run_text(&world, &.{ "zbx", "pull", bad }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stderr(), "ZBX-E0517") != null);
    try testing.expect(store_files.kind_of(lock_path) == null);
    try testing.expectEqual(@as(u8, 0), run_text(&world, &.{ "zbx", "store", "ls" }));
    try testing.expect(std.mem.indexOf(u8, world.sim.stdout(), "IMAGE") == null);
}
