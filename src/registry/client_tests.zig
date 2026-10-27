//! Tests of the registry client against the test registry in the simulator's network: the
//! anonymous flow, index and manifest parsing, platform selection, digest checks, and every
//! refusal with its code. Nothing here touches the internet.

const std = @import("std");
const assert = std.debug.assert;
const client_mod = @import("client.zig");
const codes = @import("../diag/codes.zig");
const manifest = @import("manifest.zig");
const net = @import("net.zig");
const net_sim = @import("net_sim.zig");
const reference_mod = @import("reference.zig");
const test_registry = @import("test_registry.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Sha256 = @import("digest.zig").Sha256;

const testing = std.testing;
const Scenario = test_registry.Scenario;

/// The tests run one at a time, so one workspace serves them all (it is 1.6 MiB).
var workspace: client_mod.Workspace = undefined;

const Env = struct {
    registry: test_registry.TestRegistry,
    sim: net_sim.SimNet,
    diag: Diag,
    resolved: manifest.Resolved,

    fn setup(env: *Env, seed: u64) void {
        env.registry.init();
        env.sim.init(seed, env.registry.responder());
        env.diag.reset();
        env.resolved = undefined;
    }

    /// Resolves `text` as `machine`; the result is in `resolved` or the failure in `diag`.
    fn resolve(env: *Env, text: []const u8, machine: []const u8) client_mod.Error!void {
        var reference: reference_mod.Reference = undefined;
        reference_mod.parse(text, &reference) catch unreachable; // The tests pass good text.
        var subject = client_mod.Client.init(env.sim.interface(), &workspace, machine);
        return client_mod.resolve(&subject, &reference, &env.resolved, &env.diag);
    }

    fn resolve_scenario(env: *Env, scenario: Scenario, machine: []const u8) client_mod.Error!void {
        var text: [96]u8 = undefined;
        const name = @tagName(scenario);
        const reference = std.fmt.bufPrint(&text, "registry.test/fixture/{s}:3.20", .{name});
        return env.resolve(reference catch unreachable, machine); // The name is short.
    }

    /// A fresh world in which `scenario` is refused with `code`.
    fn refused(env: *Env, seed: u64, scenario: Scenario, code: codes.Code) !void {
        env.setup(seed);
        try testing.expectError(error.Failed, env.resolve_scenario(scenario, "x86_64"));
        try testing.expectEqual(@as(?codes.Code, code), env.diag.code);
    }

    fn expect_code(env: *const Env, expected: codes.Code) !void {
        try testing.expectEqual(@as(?codes.Code, expected), env.diag.code);
    }

    fn last_cause(env: *const Env) []const u8 {
        return env.diag.last_cause().?;
    }

    /// The manifest the resolve found is the one with this digest text.
    fn expect_manifest(env: *const Env, expected: []const u8) !void {
        const actual = env.resolved.manifest_digest.text();
        try testing.expectEqualStrings(expected, &actual);
    }

    /// The bearer token request `index` carried (empty for none).
    fn bearer_length(env: *const Env, index: u32) u32 {
        return env.sim.logged(index).?.bearer_len;
    }
};

/// What each scenario of the test registry must give, in the simulator and over TCP alike: the
/// image resolves (null) or the refusal has this code.
pub const Expectation = struct { scenario: Scenario, code: ?codes.Code };

pub const expectations = [_]Expectation{
    .{ .scenario = .open, .code = null },
    .{ .scenario = .docker, .code = null },
    .{ .scenario = .single, .code = null },
    .{ .scenario = .bearer, .code = null },
    .{ .scenario = .redirect, .code = null },
    .{ .scenario = .redirectfar, .code = null },
    .{ .scenario = .limited, .code = .E0506 },
    .{ .scenario = .tokenlimited, .code = .E0506 },
    .{ .scenario = .denied, .code = .E0507 },
    .{ .scenario = .private, .code = .E0507 },
    .{ .scenario = .badsum, .code = .E0511 },
    .{ .scenario = .badindex, .code = .E0511 },
    .{ .scenario = .cut, .code = .E0513 },
    .{ .scenario = .media, .code = .E0510 },
    .{ .scenario = .layermedia, .code = .E0510 },
    .{ .scenario = .nomatch, .code = .E0509 },
    .{ .scenario = .missing, .code = .E0508 },
    .{ .scenario = .broken, .code = .E0505 },
    .{ .scenario = .huge, .code = .E0512 },
};

test "every scenario of the test registry gives its result in the simulator" {
    // Goal: the table the real network tests also use; the scenarios are all covered by it.
    var env: Env = undefined;
    for (expectations) |expectation| {
        env.setup(300);
        const result = env.resolve_scenario(expectation.scenario, "x86_64");
        if (expectation.code) |code| {
            try testing.expectError(error.Failed, result);
            try env.expect_code(code);
        } else {
            try result;
            try testing.expectEqual(@as(?codes.Code, null), env.diag.code);
        }
    }
    try testing.expectEqual(std.enums.values(Scenario).len, expectations.len);
}

test "an open registry: an index, this platform's manifest, and nothing else asked" {
    // Goal: tag -> index -> manifest by digest, both checked; amd64 on x86_64; two requests; no
    // token anywhere; the layers and config read.
    var env: Env = undefined;
    env.setup(1);
    try env.resolve(test_registry.TestRegistry.reference(.open), "x86_64");
    const image = &env.registry.fixture.oci;
    const index = env.resolved.index_digest.?.text();
    try testing.expectEqualStrings(&image.index.digest, &index);
    try env.expect_manifest(&image.amd64.digest);
    try testing.expectEqual(@as(u64, image.amd64.len), env.resolved.manifest_size);
    try testing.expectEqual(manifest.Architecture.amd64, env.resolved.architecture);
    const config = env.resolved.config_digest.text();
    try testing.expectEqualStrings(&image.config.digest, &config);
    try testing.expectEqual(@as(u32, 2), env.resolved.layer_count);
    try testing.expectEqual(manifest.LayerKind.tar_gzip, env.resolved.layers[0].kind);
    try testing.expectEqual(manifest.LayerKind.tar_zstd, env.resolved.layers[1].kind);
    try testing.expectEqual(@as(u32, 2), env.sim.requests);
    const first = env.sim.logged(0).?;
    try testing.expectEqualStrings("/v2/fixture/open/manifests/3.20", first.target_text());
    try testing.expectEqual(@as(u32, 0), env.bearer_length(0));
    try testing.expectEqual(@as(u32, 0), env.bearer_length(1));
}

test "the platform follows the machine, and Docker's types read the same" {
    // Goal: aarch64 picks the arm64 v8 entry; the Docker v2 list and manifest resolve alike, and
    // a Docker layer type is a gzip tar.
    var env: Env = undefined;
    env.setup(2);
    try env.resolve(test_registry.TestRegistry.reference(.open), "aarch64");
    try env.expect_manifest(&env.registry.fixture.oci.arm64.digest);
    try testing.expectEqual(manifest.Architecture.arm64, env.resolved.architecture);
    env.setup(3);
    try env.resolve(test_registry.TestRegistry.reference(.docker), "x86_64");
    try env.expect_manifest(&env.registry.fixture.docker.amd64.digest);
    try testing.expectEqual(manifest.LayerKind.tar_gzip, env.resolved.layers[1].kind);
}

test "a tag that names one manifest, and references by digest" {
    // Goal: a single manifest has no index digest; a digest reference needs no tag; the index
    // digest resolves.
    var env: Env = undefined;
    env.setup(4);
    try env.resolve(test_registry.TestRegistry.reference(.single), "x86_64");
    try testing.expect(env.resolved.index_digest == null);
    try env.expect_manifest(&env.registry.fixture.oci.amd64.digest);
    try testing.expectEqual(@as(u32, 1), env.sim.requests);

    var text: [160]u8 = undefined;
    const index = &env.registry.fixture.oci.index.digest;
    const by_index = try std.fmt.bufPrint(&text, "registry.test/fixture/open@{s}", .{index});
    env.setup(5);
    try env.resolve(by_index, "x86_64");
    try env.expect_manifest(&env.registry.fixture.oci.amd64.digest);
    const asked = env.sim.logged(0).?.target_text();
    try testing.expect(std.mem.startsWith(u8, asked, "/v2/fixture/open/manifests/sha256:"));
}

test "the anonymous flow: 401, one token, the repeat, and the token goes nowhere else" {
    // Goal: four requests in this order: manifest without a token, the token request (also
    // without one), the manifest with it, the platform manifest with it. The token service is
    // asked with the challenge's service and scope.
    var env: Env = undefined;
    env.setup(6);
    try env.resolve(test_registry.TestRegistry.reference(.bearer), "x86_64");
    try testing.expectEqual(@as(u32, 4), env.sim.requests);
    try testing.expectEqual(@as(u16, 401), env.sim.logged(0).?.status);
    try testing.expectEqual(@as(u32, 0), env.bearer_length(0));
    const token_request = env.sim.logged(1).?;
    const expected = "/token?service=fixture.registry&scope=repository%3Afixture%2Fbearer%3Apull";
    try testing.expectEqualStrings(expected, token_request.target_text());
    try testing.expectEqual(@as(u32, 0), token_request.bearer_len);
    try testing.expectEqualStrings(test_registry.token_text, env.sim.logged(2).?.bearer_text());
    try testing.expectEqualStrings(test_registry.token_text, env.sim.logged(3).?.bearer_text());
    try env.expect_manifest(&env.registry.fixture.oci.amd64.digest);
}

test "a 429 is one refusal with the wait, never a loop" {
    // Goal: the manifest's 429 and the token service's 429 each stop at once, with the
    // Retry-After in the message and the right count of requests.
    var env: Env = undefined;
    try env.refused(7, .limited, .E0506);
    try testing.expectEqual(@as(u32, 3), env.sim.requests); // 401, token, 429.
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "wait 30") != null);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "?") == null); // No query shown.
    try env.refused(8, .tokenlimited, .E0506);
    try testing.expectEqual(@as(u32, 2), env.sim.requests); // 401, then the token's 429.
}

test "auth refusals: the token service says no, or the registry keeps saying 401" {
    // Goal: E0507 for a refused token (two requests) and for a rejected token (three, one repeat).
    var env: Env = undefined;
    try env.refused(9, .denied, .E0507);
    try testing.expectEqual(@as(u32, 2), env.sim.requests);
    try env.refused(10, .private, .E0507);
    try testing.expectEqual(@as(u32, 3), env.sim.requests);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "still answered 401") != null);
}

test "digests are checked: a changed manifest and a lying header" {
    // Goal: E0511 for a platform manifest that hashes to something else than the index says,
    // and for an index that disagrees with the registry's own Docker-Content-Digest.
    var env: Env = undefined;
    try env.refused(11, .badsum, .E0511);
    const expected = &env.registry.fixture.oci.amd64.digest;
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), expected) != null);
    try env.refused(12, .badindex, .E0511);
    try testing.expectEqual(@as(u32, 1), env.sim.requests); // Nothing after the bad index.
}

test "documents that cannot be used, each with its code" {
    // Goal: an unknown index type and an unknown layer type (E0510), no platform (E0509 with the
    // offer), a missing tag (E0508), a huge manifest and a cut body (E0512, E0513).
    var env: Env = undefined;
    try env.refused(13, .media, .E0510);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "vnd.example.unknown") != null);
    try env.refused(14, .layermedia, .E0510);
    try env.refused(15, .nomatch, .E0509);
    const offer = "no linux/amd64 build: the image offers linux/arm/v7, linux/ppc64le";
    try testing.expectEqualStrings(offer, env.last_cause());
    try env.refused(16, .missing, .E0508);
    try env.refused(17, .huge, .E0512);
    try env.refused(18, .cut, .E0513);
}

test "a machine with no image platform is refused before any request" {
    // Goal: an unknown uname machine is E0509 and makes no request.
    var env: Env = undefined;
    env.setup(19);
    try testing.expectError(error.Failed, env.resolve_scenario(.open, "riscv64"));
    try env.expect_code(.E0509);
    try testing.expectEqual(@as(u32, 0), env.sim.requests);
}

test "redirects: followed, and the token stays with the registry" {
    // Goal: a relative redirect resolves; a redirect to another host is followed without the
    // token (the log shows an empty bearer for it).
    var env: Env = undefined;
    env.setup(20);
    try env.resolve_scenario(.redirect, "x86_64");
    try testing.expectEqual(@as(u16, 307), env.sim.logged(0).?.status);
    env.setup(21);
    try env.resolve_scenario(.redirectfar, "x86_64");
    var far_hops: u32 = 0;
    for (0..env.sim.requests) |index| {
        const entry = env.sim.logged(@intCast(index)).?;
        if (!std.mem.eql(u8, entry.host_text(), test_registry.other_host)) continue;
        far_hops += 1;
        try testing.expectEqual(@as(u32, 0), entry.bearer_len);
    }
    try testing.expect(far_hops > 0);
}

test "an injected network failure at any request is a diagnostic, never a crash" {
    // Goal: for every request index of a full bearer resolve and every error the wire can
    // report, resolve fails with a registered code of the right family, and a failure after the
    // last request changes nothing.
    const errors = [_]net.Error{
        error.UnknownHost, error.ConnectFailed,   error.ProxyFailed, error.TlsUntrusted,
        error.TlsExpired,  error.TlsHostMismatch, error.TlsFailed,   error.NoCertificates,
        error.TimedOut,    error.Truncated,       error.TooLarge,    error.BadResponse,
        error.SinkFailed,  error.Unsupported,     error.IoFailed,
    };
    var env: Env = undefined;
    for (errors) |wire_error| {
        for (0..4) |index| {
            env.setup(100 + index);
            env.sim.faults.fail_request = @intCast(index);
            env.sim.faults.fail_error = wire_error;
            try testing.expectError(error.Failed, env.resolve_scenario(.bearer, "x86_64"));
            try testing.expect(std.mem.startsWith(u8, @tagName(env.diag.code.?), "E05"));
            try testing.expect(env.diag.last_cause() != null);
            try testing.expectEqual(@as(u32, @intCast(index)) + 1, env.sim.requests);
        }
        env.setup(200);
        env.sim.faults.fail_request = 4;
        env.sim.faults.fail_error = wire_error;
        try env.resolve_scenario(.bearer, "x86_64");
    }
}

test "a seeded mix of faults never leaves the client in a state it cannot report" {
    // Goal: 200 seeds of random failures and cut bodies: each resolve either succeeds with the
    // right digest or fails with a registered E05xx code, and never uses more requests than a
    // full flow plus one repeat.
    var env: Env = undefined;
    var good: u32 = 0;
    for (0..200) |seed| {
        env.setup(1000 + seed);
        env.sim.faults.fail_per_mille = 150;
        env.sim.faults.cut_per_mille = 150;
        env.sim.faults.chunk_bytes_max = 1 + @as(u32, @intCast(seed % 97));
        const result = env.resolve_scenario(.bearer, "x86_64");
        try testing.expect(env.sim.requests <= 4);
        if (result) |_| {
            good += 1;
            try env.expect_manifest(&env.registry.fixture.oci.amd64.digest);
        } else |_| {
            try testing.expect(std.mem.startsWith(u8, @tagName(env.diag.code.?), "E05"));
        }
    }
    try testing.expect(good > 20);
    try testing.expect(good < 200);
}

test "a registry elsewhere cannot send the client to a service on this machine" {
    // Goal: a token realm in plain HTTP is only asked for when the registry is itself spoken to
    // in plain HTTP. Here the realm is on loopback and the registry is HTTPS: refused, with no
    // request to the realm.
    var env: Env = undefined;
    env.setup(22);
    env.registry.fixture.init("http://127.0.0.1:9", "https://other.test");
    try testing.expectError(error.Failed, env.resolve_scenario(.bearer, "x86_64"));
    try env.expect_code(.E0507);
    try testing.expectEqual(@as(u32, 1), env.sim.requests); // The 401 only.
}

/// A world with a mirror and Docker Hub in it: the mirror serves `mirror_scenario` where the
/// reference says `open`, Docker Hub serves it as written. Both are the test registry.
const MirrorWorld = struct {
    registry: test_registry.TestRegistry,
    sim: net_sim.SimNet,
    diag: Diag,
    resolved: manifest.Resolved,
    mirror_scenario: Scenario,
    target: [160]u8,

    const mirror_host = "mirror.test";
    const hub_host = "registry-1.docker.io";
    const reference = "docker.io/fixture/open:3.20";

    fn setup(world: *MirrorWorld, seed: u64, mirror_scenario: Scenario) void {
        world.registry.init();
        world.sim.init(seed, .{ .context = world, .answer = answer });
        world.diag.reset();
        world.resolved = undefined;
        world.mirror_scenario = mirror_scenario;
    }

    fn answer(context: *anyopaque, request: *const net.Request, served: *net_sim.Served) void {
        const world: *MirrorWorld = @ptrCast(@alignCast(context));
        const inner = world.registry.responder();
        if (!std.mem.eql(u8, request.host, mirror_host)) {
            return inner.answer(inner.context, request, served);
        }
        const name = "/fixture/open/";
        const at = std.mem.indexOf(u8, request.target, name) orelse
            return inner.answer(inner.context, request, served);
        const swapped = std.fmt.bufPrint(&world.target, "{s}/fixture/{s}/{s}", .{
            request.target[0..at],
            @tagName(world.mirror_scenario),
            request.target[at + name.len ..],
        }) catch unreachable; // The targets of the tests are short.
        var changed = request.*;
        changed.target = swapped;
        inner.answer(inner.context, &changed, served);
    }

    fn resolve(world: *MirrorWorld, mirrors: []const u8) client_mod.Error!client_mod.Client {
        var parsed: reference_mod.Reference = undefined;
        reference_mod.parse(reference, &parsed) catch unreachable; // Good text.
        var subject = client_mod.Client.init(world.sim.interface(), &workspace, "x86_64");
        subject.mirrors = mirrors;
        try client_mod.resolve(&subject, &parsed, &world.resolved, &world.diag);
        return subject;
    }

    /// How many requests went to `host`.
    fn requests_to(world: *const MirrorWorld, host: []const u8) u32 {
        var count: u32 = 0;
        var index: u32 = 0;
        while (world.sim.logged(index)) |entry| : (index += 1) {
            if (std.mem.eql(u8, entry.host_text(), host)) count += 1;
        }
        return count;
    }
};

test "a mirror that answers is the only one asked, and its answer is the image" {
    // Goal: with a mirror listed the registry is never touched; the digest is the fixture's.
    var world: MirrorWorld = undefined;
    world.setup(40, .open);
    const subject = try world.resolve(" mirror.test ,");
    try testing.expectEqual(@as(u32, 0), subject.winner);
    try testing.expectEqual(@as(u32, 2), world.requests_to(MirrorWorld.mirror_host));
    try testing.expectEqual(@as(u32, 0), world.requests_to(MirrorWorld.hub_host));
    const actual = world.resolved.manifest_digest.text();
    try testing.expectEqualStrings(&world.registry.fixture.oci.amd64.digest, &actual);
}

test "a mirror that is down falls back to Docker Hub, and the answer is the same" {
    // Goal: the first request fails on the wire; the second candidate gives the image and the
    // earlier refusal leaves no mark.
    var world: MirrorWorld = undefined;
    world.setup(41, .open);
    world.sim.faults.fail_request = 0;
    const subject = try world.resolve("mirror.test");
    try testing.expectEqual(@as(u32, 1), subject.winner);
    try testing.expectEqual(@as(?codes.Code, null), world.diag.code);
    try testing.expectEqual(@as(u32, 1), world.requests_to(MirrorWorld.mirror_host));
    try testing.expectEqual(@as(u32, 2), world.requests_to(MirrorWorld.hub_host));
    const actual = world.resolved.manifest_digest.text();
    try testing.expectEqualStrings(&world.registry.fixture.oci.amd64.digest, &actual);
}

test "a mirror that serves a wrong digest is refused and Docker Hub is not asked" {
    // Goal: a mirror can make a pull fail, never change what is pulled: E0511, no fall-through.
    var world: MirrorWorld = undefined;
    world.setup(42, .badsum);
    try testing.expectError(error.Failed, world.resolve("mirror.test"));
    try testing.expectEqual(@as(?codes.Code, .E0511), world.diag.code);
    try testing.expectEqual(@as(u32, 0), world.requests_to(MirrorWorld.hub_host));
}

test "a mirror list that is not hosts is refused, and a mirror is for Docker Hub only" {
    // Goal: E0514 names the entry; another registry's pull ignores a good list.
    var world: MirrorWorld = undefined;
    world.setup(43, .open);
    try testing.expectError(error.Failed, world.resolve("mirror.test,bad host"));
    try testing.expectEqual(@as(?codes.Code, .E0514), world.diag.code);
    try testing.expect(std.mem.indexOf(u8, world.diag.last_cause().?, "bad host") != null);
    try testing.expectEqual(@as(u32, 0), world.sim.requests);

    var env: Env = undefined;
    env.setup(44);
    var parsed: reference_mod.Reference = undefined;
    const text = test_registry.TestRegistry.reference(.open);
    reference_mod.parse(text, &parsed) catch unreachable; // Good text.
    var subject = client_mod.Client.init(env.sim.interface(), &workspace, "x86_64");
    subject.mirrors = "mirror.test";
    try client_mod.resolve(&subject, &parsed, &env.resolved, &env.diag);
    try testing.expectEqual(@as(u32, 0), subject.winner);
    try testing.expectEqualStrings("registry.test", env.sim.logged(0).?.host_text());
}
