//! Tests of the registry client against the test registry in the simulator's network: the
//! anonymous flow, index and manifest parsing, platform selection, digest checks, and every
//! refusal with its code. Nothing here touches the internet.

const std = @import("std");
const assert = std.debug.assert;
const client_mod = @import("client.zig");
const constants = @import("../constants.zig");
const manifest = @import("manifest.zig");
const net = @import("net.zig");
const net_sim = @import("net_sim.zig");
const reference_mod = @import("reference.zig");
const test_registry = @import("test_registry.zig");
const Diag = @import("../diag/diag.zig").Diag;
const codes = @import("../diag/codes.zig");

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

    fn client(env: *Env, machine: []const u8) client_mod.Client {
        return client_mod.Client.init(env.sim.interface(), &workspace, machine);
    }

    /// Resolves `text` as `machine`; the result is in `resolved` or the failure in `diag`.
    fn resolve(env: *Env, text: []const u8, machine: []const u8) client_mod.Error!void {
        var reference: reference_mod.Reference = undefined;
        reference_mod.parse(text, &reference) catch unreachable; // The tests pass good text.
        var subject = env.client(machine);
        return client_mod.resolve(&subject, &reference, &env.resolved, &env.diag);
    }

    fn resolve_scenario(env: *Env, scenario: Scenario, machine: []const u8) client_mod.Error!void {
        var text: [96]u8 = undefined;
        const name = @tagName(scenario);
        const reference = std.fmt.bufPrint(&text, "registry.test/fixture/{s}:3.20", .{name});
        return env.resolve(reference catch unreachable, machine); // The name is short.
    }

    fn expect_code(env: *const Env, expected: codes.Code) !void {
        try testing.expectEqual(@as(?codes.Code, expected), env.diag.code);
    }

    fn last_cause(env: *const Env) []const u8 {
        return env.diag.last_cause().?;
    }
};

fn digest_text(digest: anytype) []const u8 {
    return &digest.text();
}

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
    const fixture = &env.registry.fixture;
    try testing.expectEqualStrings(&fixture.oci.index.digest, digest_text(env.resolved.index_digest.?));
    try testing.expectEqualStrings(&fixture.oci.amd64.digest, digest_text(env.resolved.manifest_digest));
    try testing.expectEqual(@as(u64, fixture.oci.amd64.len), env.resolved.manifest_size);
    try testing.expectEqual(manifest.Architecture.amd64, env.resolved.architecture);
    try testing.expectEqualStrings(&fixture.oci.config.digest, digest_text(env.resolved.config_digest));
    try testing.expectEqual(@as(u32, 2), env.resolved.layer_count);
    try testing.expectEqual(manifest.LayerKind.tar_gzip, env.resolved.layers[0].kind);
    try testing.expectEqual(manifest.LayerKind.tar_zstd, env.resolved.layers[1].kind);
    try testing.expectEqual(@as(u32, 2), env.sim.requests);
    try testing.expectEqualStrings(
        "/v2/fixture/open/manifests/3.20",
        env.sim.logged(0).?.target_text(),
    );
    for (0..2) |index| try testing.expectEqual(@as(u32, 0), env.sim.logged(@intCast(index)).?.bearer_len);
}

test "the platform follows the machine, and Docker's types read the same" {
    // Goal: aarch64 picks the arm64 v8 entry; the Docker v2 list and manifest resolve alike, and
    // a Docker layer type is a gzip tar.
    var env: Env = undefined;
    env.setup(2);
    try env.resolve(test_registry.TestRegistry.reference(.open), "aarch64");
    try testing.expectEqualStrings(&env.registry.fixture.oci.arm64.digest, digest_text(env.resolved.manifest_digest));
    try testing.expectEqual(manifest.Architecture.arm64, env.resolved.architecture);
    env.setup(3);
    try env.resolve(test_registry.TestRegistry.reference(.docker), "x86_64");
    try testing.expectEqualStrings(&env.registry.fixture.docker.amd64.digest, digest_text(env.resolved.manifest_digest));
    try testing.expectEqual(manifest.LayerKind.tar_gzip, env.resolved.layers[1].kind);
}

test "a tag that names one manifest, and references by digest" {
    // Goal: a single manifest has no index digest; a digest reference needs no tag; the index
    // digest and the manifest digest both resolve.
    var env: Env = undefined;
    env.setup(4);
    try env.resolve(test_registry.TestRegistry.reference(.single), "x86_64");
    try testing.expect(env.resolved.index_digest == null);
    try testing.expectEqualStrings(&env.registry.fixture.oci.amd64.digest, digest_text(env.resolved.manifest_digest));
    try testing.expectEqual(@as(u32, 1), env.sim.requests);

    var text: [160]u8 = undefined;
    const by_index = try std.fmt.bufPrint(&text, "registry.test/fixture/open@{s}", .{&env.registry.fixture.oci.index.digest});
    env.setup(5);
    try env.resolve(by_index, "x86_64");
    try testing.expectEqualStrings(&env.registry.fixture.oci.amd64.digest, digest_text(env.resolved.manifest_digest));
    try testing.expectEqualStrings(
        "/v2/fixture/open/manifests/sha256",
        env.sim.logged(0).?.target_text()[0..33],
    );
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
    try testing.expectEqual(@as(u32, 0), env.sim.logged(0).?.bearer_len);
    const token_request = env.sim.logged(1).?;
    try testing.expectEqualStrings(
        "/token?service=fixture.registry&scope=repository%3Afixture%2Fbearer%3Apull",
        token_request.target_text(),
    );
    try testing.expectEqual(@as(u32, 0), token_request.bearer_len);
    try testing.expectEqualStrings(test_registry.token_text, env.sim.logged(2).?.bearer_text());
    try testing.expectEqualStrings(test_registry.token_text, env.sim.logged(3).?.bearer_text());
    try testing.expectEqualStrings(&env.registry.fixture.oci.amd64.digest, digest_text(env.resolved.manifest_digest));
}

test "a 429 is one refusal with the wait, never a loop" {
    // Goal: the manifest's 429 and the token service's 429 each stop at once, with the
    // Retry-After in the message and the right count of requests.
    var env: Env = undefined;
    env.setup(7);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.limited), "x86_64"));
    try env.expect_code(.E0506);
    try testing.expectEqual(@as(u32, 3), env.sim.requests); // 401, token, 429.
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "wait 30") != null);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "?") == null); // No query shown.
    env.setup(8);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.tokenlimited), "x86_64"));
    try env.expect_code(.E0506);
    try testing.expectEqual(@as(u32, 2), env.sim.requests); // 401, then the token's 429.
}

test "auth refusals: the token service says no, or the registry keeps saying 401" {
    // Goal: E0507 for a refused token (two requests) and for a rejected token (three, one repeat).
    var env: Env = undefined;
    env.setup(9);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.denied), "x86_64"));
    try env.expect_code(.E0507);
    try testing.expectEqual(@as(u32, 2), env.sim.requests);
    env.setup(10);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.private), "x86_64"));
    try env.expect_code(.E0507);
    try testing.expectEqual(@as(u32, 3), env.sim.requests);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "still answered 401") != null);
}

test "digests are checked: a changed manifest and a lying header" {
    // Goal: E0511 for a platform manifest that hashes to something else than the index says,
    // and for an index that disagrees with the registry's own Docker-Content-Digest.
    var env: Env = undefined;
    env.setup(11);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.badsum), "x86_64"));
    try env.expect_code(.E0511);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), &env.registry.fixture.oci.amd64.digest) != null);
    env.setup(12);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.badindex), "x86_64"));
    try env.expect_code(.E0511);
    try testing.expectEqual(@as(u32, 1), env.sim.requests); // Nothing after the bad index.
}

test "documents that cannot be used, each with its code" {
    // Goal: an unknown index type and an unknown layer type (E0510), no platform (E0509 with the
    // offer), a missing tag (E0508), a huge manifest and a cut body (E0512, E0513).
    var env: Env = undefined;
    env.setup(13);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.media), "x86_64"));
    try env.expect_code(.E0510);
    try testing.expect(std.mem.indexOf(u8, env.last_cause(), "vnd.example.unknown") != null);
    env.setup(14);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.layermedia), "x86_64"));
    try env.expect_code(.E0510);
    env.setup(15);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.nomatch), "x86_64"));
    try env.expect_code(.E0509);
    try testing.expectEqualStrings(
        "no linux/amd64 build: the image offers linux/arm/v7, linux/ppc64le",
        env.last_cause(),
    );
    env.setup(16);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.missing), "x86_64"));
    try env.expect_code(.E0508);
    env.setup(17);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.huge), "x86_64"));
    try env.expect_code(.E0512);
    env.setup(18);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.cut), "x86_64"));
    try env.expect_code(.E0513);
}

test "a machine with no image platform is refused before any request" {
    // Goal: an unknown uname machine is E0509 and makes no request.
    var env: Env = undefined;
    env.setup(19);
    try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.open), "riscv64"));
    try env.expect_code(.E0509);
    try testing.expectEqual(@as(u32, 0), env.sim.requests);
}

test "redirects: followed, and the token stays with the registry" {
    // Goal: a relative redirect resolves; a redirect to another host is followed without the
    // token (the log shows an empty bearer for it).
    var env: Env = undefined;
    env.setup(20);
    try env.resolve(test_registry.TestRegistry.reference(.redirect), "x86_64");
    try testing.expectEqual(@as(u16, 307), env.sim.logged(0).?.status);
    env.setup(21);
    try env.resolve(test_registry.TestRegistry.reference(.redirectfar), "x86_64");
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
            try testing.expectError(error.Failed, env.resolve(test_registry.TestRegistry.reference(.bearer), "x86_64"));
            const code = env.diag.code.?;
            const family = @tagName(code);
            try testing.expect(std.mem.startsWith(u8, family, "E05"));
            try testing.expect(env.diag.last_cause() != null);
            try testing.expectEqual(@as(u32, @intCast(index)) + 1, env.sim.requests);
        }
        env.setup(200);
        env.sim.faults.fail_request = 4;
        env.sim.faults.fail_error = wire_error;
        try env.resolve(test_registry.TestRegistry.reference(.bearer), "x86_64");
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
        const result = env.resolve(test_registry.TestRegistry.reference(.bearer), "x86_64");
        try testing.expect(env.sim.requests <= 4);
        if (result) |_| {
            good += 1;
            try testing.expectEqualStrings(&env.registry.fixture.oci.amd64.digest, digest_text(env.resolved.manifest_digest));
        } else |_| {
            try testing.expect(std.mem.startsWith(u8, @tagName(env.diag.code.?), "E05"));
        }
    }
    try testing.expect(good > 20);
    try testing.expect(good < 200);
}
