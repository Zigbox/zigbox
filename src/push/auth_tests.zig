//! Tests of the push's credentials (`upload.zig`, `credentials.zig`) against the test registry's
//! challenges in the simulator: `Basic`, the `Bearer` exchange, the realm rule, the scope, the
//! origin-only rule, and the marker password that must be nowhere it should not be.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("../diag/codes.zig");
const credentials_mod = @import("credentials.zig");
const net = @import("../registry/net.zig");
const push_registry = @import("../registry/push_registry.zig");
const render = @import("../diag/render.zig");
const tests = @import("upload_tests.zig");
const upload = @import("upload.zig");

const testing = std.testing;
const Rig = tests.Rig;
const marker = "Zq7-marker-pass-4417";

fn options_with(credentials: *const credentials_mod.Credentials) upload.Options {
    return .{ .credentials = credentials };
}

/// Whether any request of the run went to a host other than the registry's with a credential.
fn credential_left_the_registry(rig: *const Rig) bool {
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        if (std.mem.eql(u8, entry.host_text(), push_registry.registry_host)) continue;
        if (entry.basic_len > 0 or entry.bearer_len > 0) return true;
    }
    return false;
}

fn sent_any_credential(rig: *const Rig) bool {
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        if (entry.basic_len > 0 or entry.bearer_len > 0) return true;
    }
    return false;
}

test "Basic: the challenge is answered once and the credentials go to the registry only" {
    // Goal: a registry that asks for Basic gets it. Method: the first request carries nothing,
    // the retry carries the Basic value, and the push ends whole.
    const rig = try Rig.create(21);
    defer rig.destroy();
    rig.registry.require(.basic, marker);
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
    defer credentials.wipe();
    try rig.push("push/ok", options_with(&credentials));
    try testing.expect(rig.holds("push/ok", rig.made.layer));
    try testing.expectEqual(@as(u32, 0), rig.wire.logged(0).?.basic_len);
    try testing.expect(rig.wire.logged(1).?.basic_len > 0);
    try testing.expectEqual(@as(u32, 0), rig.registry.token_requests);
    try testing.expect(!credential_left_the_registry(rig));
}

test "Bearer: Basic at the realm buys a token with the push scope, the challenge's scope ignored" {
    // Goal: the exchange. Method: the token request carries Basic and no bearer and asks for
    // pull and push of the destination; every later request carries the token and no Basic.
    const rig = try Rig.create(22);
    defer rig.destroy();
    rig.registry.require(.bearer, marker);
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
    defer credentials.wipe();
    try rig.push("push/ok", options_with(&credentials));
    try testing.expectEqual(@as(u32, 1), rig.registry.token_requests);
    const scope = rig.registry.scope_asked();
    try testing.expectEqualStrings("repository%3Apush%2Fok%3Apull%2Cpush", scope);
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        const is_token = std.mem.startsWith(u8, entry.target_text(), "/token");
        if (is_token) {
            try testing.expect(entry.basic_len > 0);
            try testing.expectEqual(@as(u32, 0), entry.bearer_len);
        } else {
            try testing.expectEqual(@as(u32, 0), entry.basic_len);
        }
    }
    try testing.expect(rig.holds("push/ok", rig.made.config));
}

test "a token that expires mid-push is bought again once" {
    // Goal: a 401 after the token was accepted re-authenticates and resends the piece. Method:
    // the registry forgets its token on its third served request.
    const rig = try Rig.create(23);
    defer rig.destroy();
    rig.registry.require(.expiring, marker);
    rig.registry.expire_after = 3;
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
    defer credentials.wipe();
    try rig.push("push/ok", options_with(&credentials));
    try testing.expectEqual(@as(u32, 2), rig.registry.token_requests);
    try testing.expect(rig.holds("push/ok", rig.made.layer));
    try testing.expect(rig.registry.fixture.tag_digest("push/ok", "v1") != null);
}

test "a token granted pull only is E0553 naming push" {
    // Goal: the registry says insufficient_scope; the line names the missing scope.
    const rig = try Rig.create(24);
    defer rig.destroy();
    rig.registry.require(.pull_only, marker);
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
    defer credentials.wipe();
    try testing.expectError(error.Failed, rig.push("push/ok", options_with(&credentials)));
    try tests.expect_code(rig, .E0553);
    try testing.expect(std.mem.indexOf(u8, rig.diag.last_cause().?, "push") != null);
    try testing.expect(!rig.holds("push/ok", rig.made.layer));
}

test "a realm on another host is refused before any credential is sent" {
    // Goal: E0554, and not one request carried a credential or reached the other host.
    const rig = try Rig.create(25);
    defer rig.destroy();
    rig.registry.require(.far_realm, marker);
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
    defer credentials.wipe();
    try testing.expectError(error.Failed, rig.push("push/ok", options_with(&credentials)));
    try tests.expect_code(rig, .E0554);
    try testing.expect(!sent_any_credential(rig));
    try testing.expectEqual(@as(u32, 0), rig.registry.token_requests);
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        try testing.expect(!std.mem.eql(u8, entry.host_text(), "evil.test"));
    }
}

test "no credentials: a challenge is E0552 and nothing is sent" {
    // Goal: E0552 after one unauthenticated request, for Basic and for Bearer.
    inline for (.{ push_registry.Mode.basic, push_registry.Mode.bearer }) |mode| {
        const rig = try Rig.create(26);
        defer rig.destroy();
        rig.registry.require(mode, marker);
        try testing.expectError(error.Failed, rig.push("push/ok", .{}));
        try tests.expect_code(rig, .E0552);
        try testing.expect(!sent_any_credential(rig));
        try testing.expectEqual(@as(u32, 0), rig.registry.token_requests);
    }
}

test "a wrong password is E0553 and is not retried" {
    // Goal: the realm refuses; the push stops after one token request.
    const rig = try Rig.create(27);
    defer rig.destroy();
    rig.registry.require(.bearer, marker);
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, "not-the-password");
    defer credentials.wipe();
    try testing.expectError(error.Failed, rig.push("push/ok", options_with(&credentials)));
    try tests.expect_code(rig, .E0553);
    try testing.expectEqual(@as(u32, 1), rig.registry.token_requests);
}

test "a Location on another origin carries no Authorization, for Basic and for Bearer" {
    // Goal: the origin-only rule. Method: uploads that continue on another host, and absolute
    // Locations on the registry's own origin (which still get the credential).
    inline for (.{ push_registry.Mode.basic, push_registry.Mode.bearer }) |mode| {
        const rig = try Rig.create(28);
        defer rig.destroy();
        rig.registry.require(mode, marker);
        var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
        defer credentials.wipe();
        try rig.push("push/farlocation", options_with(&credentials));
        try testing.expect(rig.holds("push/farlocation", rig.made.layer));
        try testing.expectEqual(@as(u32, 0), rig.registry.leaked);
        try testing.expect(!credential_left_the_registry(rig));
        try rig.push("push/absolute", options_with(&credentials));
        try testing.expectEqual(@as(u32, 0), rig.registry.leaked);
    }
}

/// Whether `bytes` holds `needle`, as text or as the base64 of `user:needle`.
fn holds_secret(bytes: []const u8, secret: []const u8) bool {
    if (std.mem.indexOf(u8, bytes, secret) != null) return true;
    var plain: [128]u8 = undefined;
    const text = std.fmt.bufPrint(&plain, "{s}:{s}", .{ push_registry.test_user, secret }) catch
        unreachable;
    var encoded: [192]u8 = undefined;
    const based = std.base64.standard.Encoder.encode(&encoded, text);
    return std.mem.indexOf(u8, bytes, based) != null;
}

test "the marker password is only in requests to the registry, and in no buffer after" {
    // Goal: over random runs, the marker (and the base64 of user:marker) is in no diagnostic,
    // no file, no leftover buffer of the push, and in no request to another host. The token
    // too. Method: each seed picks a registry mode, a fault and network failures.
    const rig = try Rig.create(30);
    defer rig.destroy();
    const modes = [_]push_registry.Mode{ .basic, .bearer, .expiring, .far_realm, .pull_only };
    const faults = [_][]const u8{ "push/ok", "push/farlocation", "push/absolute", "push/nomount" };
    var seed: u64 = 0;
    while (seed < 200) : (seed += 1) {
        var prng = std.Random.Xoshiro256.init(seed);
        const random = prng.random();
        var secret: [24]u8 = undefined;
        for (&secret) |*byte| byte.* = "abcdefghijklmnop"[random.uintLessThan(usize, 16)];
        rig.wire.init(seed, rig.registry.responder());
        rig.registry.init(&rig.wire);
        rig.registry.require(modes[random.uintLessThan(usize, modes.len)], &secret);
        rig.registry.expire_after = random.intRangeAtMost(u32, 2, 6);
        rig.wire.faults = .{ .fail_per_mille = random.uintLessThan(u16, 40) };
        var credentials = credentials_mod.Credentials.of(push_registry.test_user, &secret);
        const repository = faults[random.uintLessThan(usize, faults.len)];
        _ = rig.push(repository, .{ .credentials = &credentials }) catch {};
        credentials.wipe();
        try testing.expect(!credential_left_the_registry(rig));
        try testing.expect(!holds_secret(std.mem.asBytes(&rig.ws), &secret));
        try testing.expect(!holds_secret(std.mem.asBytes(&rig.diag), &secret));
        try testing.expect(!holds_secret(std.mem.asBytes(&rig.files), &secret));
        try testing.expect(std.mem.indexOf(u8, std.mem.asBytes(&rig.ws), "push-token-") == null);
        try testing.expect(!holds_secret(std.mem.asBytes(&credentials), &secret));
    }
}

/// Whether any request of the run carried both an `Authorization: Basic` and a Bearer token.
fn sent_both_credentials(rig: *const Rig) bool {
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        if (entry.basic_len > 0 and entry.bearer_len > 0) return true;
    }
    return false;
}

test "a registry that switches its challenge mid-push is never sent both credentials" {
    // Goal: Basic and Bearer are exclusive, in both directions (the real host asserts it, so a
    // request with both would be a panic there and two Authorization headers here). Method: the
    // registry serves in one mode, then, after some served requests, answers in the other; the
    // push must end whole, with the second scheme's credential alone after the switch, and the
    // wiped one gone from the workspace.
    const pairs = [_][2]push_registry.Mode{
        .{ .basic, .bearer },
        .{ .bearer, .basic },
    };
    for (pairs) |pair| {
        var after: u32 = 1;
        while (after <= 5) : (after += 1) {
            const rig = try Rig.create(31);
            defer rig.destroy();
            rig.registry.require(pair[0], marker);
            rig.registry.switch_after = after;
            rig.registry.switch_to = pair[1];
            var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
            defer credentials.wipe();
            try rig.push("push/ok", options_with(&credentials));
            try testing.expect(rig.holds("push/ok", rig.made.layer));
            try testing.expect(!sent_both_credentials(rig));
            try testing.expect(!credential_left_the_registry(rig));
            // The scheme in use at the end is the second one; the other's bytes are zero.
            if (pair[1] == .bearer) {
                try testing.expect(rig.registry.token_requests > 0);
                try testing.expect(rig.ws.basic[0] == 0);
            } else {
                try testing.expectEqual(@as(u8, 0), rig.ws.token[0]);
            }
        }
    }
}

test "a realm that is not a URL, or is plain http, is refused with its own cause" {
    // Goal: E0554 names the reason (not the host) for a malformed realm and for plain http on a
    // registry that is not on loopback, and no credential is sent in either case.
    const cases = [_]struct { realm: []const u8, cause: []const u8 }{
        .{ .realm = "htp:/x", .cause = "which is not a URL zbx can use" },
        .{ .realm = "http://registry.test/token", .cause = "over plain http" },
    };
    for (cases) |case| {
        const rig = try Rig.create(32);
        defer rig.destroy();
        rig.registry.require(.bearer, marker);
        rig.registry.realm_override = case.realm;
        var credentials = credentials_mod.Credentials.of(push_registry.test_user, marker);
        defer credentials.wipe();
        try testing.expectError(error.Failed, rig.push("push/ok", options_with(&credentials)));
        try tests.expect_code(rig, .E0554);
        try testing.expect(std.mem.indexOf(u8, rig.diag.last_cause().?, case.cause) != null);
        try testing.expect(!sent_any_credential(rig));
    }
}
