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
        "schema",        "reference", "registry",      "repository",  "index_digest", "manifest_digest",
        "manifest_size", "platform",  "config_digest", "config_size", "layers",
    };
    for (required) |key| {
        try testing.expect(object.get(key) != null);
        var quoted: [40]u8 = undefined;
        const text = try std.fmt.bufPrint(&quoted, "\"{s}\"", .{key});
        try testing.expect(std.mem.indexOf(u8, schema, text) != null);
    }
    try testing.expectEqualStrings("zbx.pull.resolve/1", object.get("schema").?.string);
    try testing.expectEqualStrings(
        "registry.test/fixture/open:3.20",
        std.mem.trimStart(u8, object.get("reference").?.string, "x"),
    );
    try testing.expectEqual(@as(usize, 2), object.get("layers").?.array.items.len);
    const layer = object.get("layers").?.array.items[0].object;
    try testing.expectEqualStrings("tar_gzip", layer.get("kind").?.string);
    try testing.expectEqual(@as(u8, 0), world.run(&.{ "zbx", "schema", "pull-resolve" }));
}

test "usage: the flag and the reference are both needed, and the flag is pull's" {
    // Goal: E0006 without --resolve-only (nothing is fetched yet) and without a reference, E0004
    // for the flag on another command, E0003 for a second reference.
    var world: World = undefined;
    world.setup(4);
    try testing.expectEqual(@as(u8, 1), world.run(&.{ "zbx", "pull", "alpine:3.20" }));
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
            const tail = [_][:0]const u8{ "pull", "--resolve-only", reference_of(expectation.scenario) };
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
    // The check is not vacuous: tokens were really exchanged in the six scenarios that use
    // them, in each of the three modes.
    try testing.expectEqual(@as(u32, 18), found_token_flow);
}

fn reference_of(scenario: test_registry.Scenario) [:0]const u8 {
    return switch (scenario) {
        inline else => |known| test_registry.TestRegistry.reference(known),
    };
}
