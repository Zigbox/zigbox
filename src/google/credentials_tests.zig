//! Tests of `credentials.resolve` against the simulated host and the simulated Google: each source
//! on its own, the order between them, every way a source can fail, and the rules that must hold
//! whatever happens: a set `GOOGLE_APPLICATION_CREDENTIALS` never falls through to the metadata
//! server, a proxy never carries a metadata call, each secret goes only to its own service, every
//! secret call is marked, and every secret buffer is zero afterwards. Every token is a fixed fake.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const google_sim = @import("google_sim.zig");
const host_sim = @import("../host_sim.zig");
const net_sim = @import("../registry/net_sim.zig");
const parse = @import("parse.zig");
const parse_tests = @import("parse_tests.zig");

const Token = credentials_mod.Token;
const Trace = credentials_mod.Trace;
const Workspace = credentials_mod.Workspace;

const credentials_path = "/home/ci/gcp.json";
const subject_path = "/run/zbx/oidc-token";

const wif_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "GOOGLE_APPLICATION_CREDENTIALS", .value = credentials_path },
};

/// Everything one test owns, on the heap: the workspace, the host and the fixture are large.
const Fixture = struct {
    host: host_sim.HostSim,
    wire: net_sim.SimNet,
    google: google_sim.GoogleSim,
    workspace: Workspace,
    token: Token,
    trace: Trace,
    received: [constants.google_request_body_bytes_max]u8,

    fn create(
        seed: u64,
        files: []const host_sim.File,
        env: []const host_sim.EnvironmentVariable,
    ) !*Fixture {
        const fixture = try std.heap.page_allocator.create(Fixture);
        fixture.host.init(seed, files);
        fixture.host.environment_variables = env;
        fixture.google.init();
        fixture.google.now_s = fixture.host.world.now;
        fixture.wire.init(seed, fixture.google.responder());
        fixture.wire.received = &fixture.received;
        fixture.host.wire = &fixture.wire;
        fixture.token = .{};
        // Not zero to start, so a buffer `resolve` forgot to wipe fails `expect_wiped`.
        @memset(std.mem.asBytes(&fixture.workspace), 0xAA);
        @memset(&fixture.token.bytes, 0xAA);
        return fixture;
    }

    fn destroy(fixture: *Fixture) void {
        std.heap.page_allocator.destroy(fixture);
    }

    fn resolve(fixture: *Fixture, sources: credentials_mod.Sources) credentials_mod.Error!void {
        var storage: [credentials_mod.Env.names.len]credentials_mod.Env.Pair = undefined;
        const env = credentials_mod.Env.from_host(fixture.host.interface(), &storage);
        return credentials_mod.resolve(
            fixture.host.interface(),
            env,
            fixture.host.world.now,
            sources,
            &fixture.workspace,
            &fixture.token,
            &fixture.trace,
        );
    }

    /// Every call that carried a credential, or whose body or answer is one, was marked `secret`.
    fn expect_secret_marked(fixture: *const Fixture) !void {
        var index: u32 = 0;
        while (fixture.wire.logged(index)) |entry| : (index += 1) {
            const host = entry.host_text();
            const holds_one = std.mem.eql(u8, host, parse.sts_host) or
                std.mem.eql(u8, host, parse.iam_host) or
                std.mem.eql(u8, host, google_sim.metadata_host) or
                std.mem.eql(u8, host, google_sim.subject_host) or entry.credential_sent();
            if (holds_one) try testing.expect(entry.secret);
        }
    }

    fn expect_wiped(fixture: *const Fixture) !void {
        const buffers = [_][]const u8{
            &fixture.workspace.credentials_file,
            &fixture.workspace.subject_token,
            &fixture.workspace.request_body,
            &fixture.workspace.response,
            &fixture.workspace.federated_token,
        };
        for (buffers) |buffer| {
            for (buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
        }
    }

    /// What must hold after any resolve: no leak, every secret call marked, the workspace zero,
    /// and a token only on success.
    fn expect_rules(fixture: *const Fixture) !void {
        try testing.expectEqual(@as(u32, 0), fixture.google.leaked);
        try testing.expectEqual(@as(u32, 0), fixture.google.stray);
        try fixture.expect_secret_marked();
        try fixture.expect_wiped();
        const used = fixture.trace.workload_identity == .used or fixture.trace.metadata == .used;
        try testing.expectEqual(used, fixture.token.len > 0);
        // Past its length the token holds nothing: no old token's tail survives a shorter one.
        for (fixture.token.bytes[fixture.token.len..]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }
};

const both: credentials_mod.Sources = .{ .workload_identity = true, .metadata = true };

const credentials_file: host_sim.File = .{
    .path = credentials_path,
    .content = parse_tests.file_account,
};
const url_credentials_file: host_sim.File = .{
    .path = credentials_path,
    .content = parse_tests.url_account,
};
const subject_file: host_sim.File = .{
    .path = subject_path,
    .content = google_sim.subject_token ++ "\n",
};

test "a file subject token is exchanged and impersonated" {
    // Goal: the demo's path end to end: the subject token from its file goes to STS only, the
    // federated token to IAM Credentials only, and the impersonated token comes back with its
    // expiry; the metadata server is not asked, though allowed.
    const fixture = try Fixture.create(1, &.{ credentials_file, subject_file }, &wif_env);
    defer fixture.destroy();
    try fixture.resolve(both);
    try testing.expectEqual(credentials_mod.State.used, fixture.trace.workload_identity);
    try testing.expectEqual(credentials_mod.MetadataState.not_asked, fixture.trace.metadata);
    try testing.expectEqual(credentials_mod.Source.workload_identity, fixture.token.source);
    try testing.expectEqualStrings(google_sim.access_token, fixture.token.text());
    const expected_expiry = fixture.host.world.now + fixture.google.lifetime_s;
    try testing.expectEqual(expected_expiry, fixture.token.expiration_s);
    try testing.expectEqualStrings(parse_tests.service_account, fixture.trace.account());
    try testing.expectEqual(@as(u32, 1), fixture.google.sts_calls);
    try testing.expectEqual(@as(u32, 1), fixture.google.iam_calls);
    try testing.expectEqual(@as(u32, 0), fixture.google.metadata_calls);
    try fixture.expect_rules();
    fixture.token.wipe();
    try testing.expectEqual(@as(u32, 0), fixture.token.len);
    for (fixture.token.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "a URL subject token is fetched with its header, and the federated token is used" {
    // Goal: the `google-github-actions/auth` shape: the runner's request token goes to the URL
    // host only, as the whole Authorization value; with no impersonation URL the federated
    // token is the answer, and IAM Credentials is never called.
    const fixture = try Fixture.create(2, &.{url_credentials_file}, &wif_env);
    defer fixture.destroy();
    try fixture.resolve(.{ .workload_identity = true });
    try testing.expectEqual(credentials_mod.State.used, fixture.trace.workload_identity);
    try testing.expectEqualStrings(google_sim.federated_token, fixture.token.text());
    try testing.expectEqual(parse.SourceKind.url, fixture.trace.subject_source);
    try testing.expectEqual(@as(u32, 1), fixture.google.subject_calls);
    try testing.expectEqual(@as(u32, 0), fixture.google.iam_calls);
    const first = fixture.wire.logged(0).?;
    try testing.expectEqualStrings(google_sim.subject_host, first.host_text());
    try testing.expect(first.authorization_len > 0);
    try fixture.expect_rules();
}

const WifCase = struct {
    name: []const u8,
    sts: google_sim.StsMode = .ok,
    iam: google_sim.IamMode = .ok,
    subject: google_sim.SubjectMode = .ok,
    url: bool = false,
    state: credentials_mod.State,
    step: credentials_mod.Step,
    code: []const u8 = "",
    status: u16 = 0,
};

const wif_cases = [_]WifCase{
    .{
        .name = "subject refused",
        .sts = .invalid_grant,
        .state = .refused,
        .step = .exchange,
        .code = "invalid_grant",
        .status = 400,
    },
    .{
        .name = "audience wrong",
        .sts = .invalid_target,
        .state = .refused,
        .step = .exchange,
        .code = "invalid_target",
        .status = 400,
    },
    .{
        .name = "sts down",
        .sts = .unavailable,
        .state = .refused,
        .step = .exchange,
        .code = "server_error",
        .status = 503,
    },
    .{ .name = "sts garbage", .sts = .malformed, .state = .malformed, .step = .exchange },
    .{
        .name = "impersonation denied",
        .iam = .denied,
        .state = .refused,
        .step = .impersonation,
        .code = "PERMISSION_DENIED",
        .status = 403,
    },
    .{
        .name = "iam down",
        .iam = .unavailable,
        .state = .refused,
        .step = .impersonation,
        .code = "UNAVAILABLE",
        .status = 503,
    },
    .{ .name = "iam garbage", .iam = .malformed, .state = .malformed, .step = .impersonation },
    .{
        .name = "url refused",
        .subject = .refused,
        .url = true,
        .state = .refused,
        .step = .subject_token,
        .status = 401,
    },
    .{
        .name = "url down",
        .subject = .unavailable,
        .url = true,
        .state = .refused,
        .step = .subject_token,
        .status = 502,
    },
};

test "every workload identity failure is terminal and named" {
    // Goal: each fault stops at its own step with its own state and Google's code, never
    // repeats a message, and never falls through to the metadata server, which is allowed and
    // would answer.
    for (wif_cases, 0..) |case, index| {
        const files: []const host_sim.File = if (case.url)
            &.{url_credentials_file}
        else
            &.{ credentials_file, subject_file };
        const fixture = try Fixture.create(10 + index, files, &wif_env);
        defer fixture.destroy();
        fixture.google.sts = case.sts;
        fixture.google.iam = case.iam;
        fixture.google.subject = case.subject;
        try testing.expectError(error.NoCredentials, fixture.resolve(both));
        try testing.expectEqual(case.state, fixture.trace.workload_identity);
        try testing.expectEqual(case.step, fixture.trace.step);
        try testing.expectEqualStrings(case.code, fixture.trace.code());
        try testing.expectEqual(case.status, fixture.trace.status);
        try testing.expectEqual(credentials_mod.MetadataState.not_asked, fixture.trace.metadata);
        try testing.expectEqual(@as(u32, 0), fixture.google.metadata_calls);
        try fixture.expect_rules();
    }
}

test "a missing or unusable credentials file is terminal, with no network call" {
    // Goal: a set variable whose file is absent, empty, a key, or a subject file that is
    // missing, stops before any secret leaves; a key file is named as one.
    const key_file: host_sim.File = .{
        .path = credentials_path,
        .content = "{\"type\":\"service_account\",\"private_key\":\"FAKE\"}",
    };
    const Case = struct {
        files: []const host_sim.File,
        state: credentials_mod.State,
        calls: u32,
    };
    const cases = [_]Case{
        .{ .files = &.{}, .state = .unreadable, .calls = 0 },
        .{ .files = &.{key_file}, .state = .unsupported, .calls = 0 },
        .{ .files = &.{credentials_file}, .state = .subject_unreadable, .calls = 0 },
    };
    for (cases, 0..) |case, index| {
        const fixture = try Fixture.create(30 + index, case.files, &wif_env);
        defer fixture.destroy();
        try testing.expectError(error.NoCredentials, fixture.resolve(both));
        try testing.expectEqual(case.state, fixture.trace.workload_identity);
        try testing.expectEqual(case.calls, fixture.wire.requests);
        try fixture.expect_rules();
    }
    const fixture = try Fixture.create(39, &.{key_file}, &wif_env);
    defer fixture.destroy();
    try testing.expectError(error.NoCredentials, fixture.resolve(both));
    try testing.expectEqual(parse.Refusal.service_account_key, fixture.trace.unsupported);
    // The reason names a key file, so the type is not copied as well.
    try testing.expectEqualStrings("", fixture.trace.file_type());
}

const MetadataCase = struct {
    mode: google_sim.MetadataMode,
    state: credentials_mod.MetadataState,
};

const metadata_cases = [_]MetadataCase{
    .{ .mode = .ok, .state = .used },
    .{ .mode = .absent, .state = .absent },
    .{ .mode = .slow, .state = .absent },
    .{ .mode = .no_flavor, .state = .not_gce },
    .{ .mode = .ec2, .state = .not_gce },
    .{ .mode = .no_service_account, .state = .no_service_account },
    .{ .mode = .unavailable, .state = .refused },
    .{ .mode = .malformed, .state = .malformed },
};

test "the metadata server, in each of the ways it answers" {
    // Goal: with no variable set, the metadata server is asked once, with its header, never
    // through a proxy, within its own timeouts; only a Google-flavoured 200 is a token.
    for (metadata_cases, 0..) |case, index| {
        const fixture = try Fixture.create(40 + index, &.{}, &.{});
        defer fixture.destroy();
        fixture.google.metadata = case.mode;
        const result = fixture.resolve(both);
        if (case.state == .used) {
            try result;
        } else {
            try testing.expectError(error.NoCredentials, result);
        }
        try testing.expectEqual(case.state, fixture.trace.metadata);
        const wif_state = fixture.trace.workload_identity;
        try testing.expectEqual(credentials_mod.State.not_configured, wif_state);
        try testing.expectEqual(@as(u32, 1), fixture.wire.requests);
        const entry = fixture.wire.logged(0).?;
        try testing.expectEqual(.never, entry.proxy);
        try testing.expectEqual(@as(u8, 1), entry.extra_headers);
        try testing.expectEqual(constants.google_metadata_timeout_ms, entry.idle_timeout_ms);
        try testing.expectEqual(constants.google_metadata_total_timeout_ms, entry.total_timeout_ms);
        try fixture.expect_rules();
        if (case.state != .used) continue;
        try testing.expectEqualStrings(google_sim.metadata_token, fixture.token.text());
        try testing.expectEqual(credentials_mod.Source.metadata, fixture.token.source);
    }
}

test "a source not named in the mask is not asked" {
    // Goal: the caller decides: no metadata call unless asked for, no file read unless asked for;
    // and a set variable stays terminal when the mask leaves workload identity out, so the
    // metadata server is not asked even when the mask names it.
    const masks = [_]credentials_mod.Sources{ .{ .metadata = false }, .{ .metadata = true } };
    for (masks, 0..) |mask, index| {
        const files = &.{ credentials_file, subject_file };
        const fixture = try Fixture.create(50 + index, files, &wif_env);
        defer fixture.destroy();
        try testing.expectError(error.NoCredentials, fixture.resolve(mask));
        try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
        const wif_state = fixture.trace.workload_identity;
        try testing.expectEqual(credentials_mod.State.not_asked, wif_state);
        try testing.expectEqual(credentials_mod.MetadataState.not_asked, fixture.trace.metadata);
        try testing.expectEqual(@as(u32, 0), fixture.google.metadata_calls);
        try fixture.expect_rules();
    }
    // With no variable, a mask without workload identity goes straight to the metadata server.
    const gce = try Fixture.create(53, &.{}, &.{});
    defer gce.destroy();
    try gce.resolve(.{ .metadata = true });
    try testing.expectEqual(credentials_mod.State.not_configured, gce.trace.workload_identity);
    try testing.expectEqual(credentials_mod.MetadataState.used, gce.trace.metadata);
    try gce.expect_rules();
}

test "a token that is already, or about to be, out of date is refused" {
    // Goal: a lifetime inside the margin gives `expired` and no token, from either source.
    const fixture = try Fixture.create(51, &.{ credentials_file, subject_file }, &wif_env);
    defer fixture.destroy();
    fixture.google.lifetime_s = constants.google_token_margin_s;
    try testing.expectError(error.NoCredentials, fixture.resolve(both));
    try testing.expectEqual(credentials_mod.State.expired, fixture.trace.workload_identity);
    try fixture.expect_rules();
    const gce = try Fixture.create(52, &.{}, &.{});
    defer gce.destroy();
    gce.google.lifetime_s = 1;
    try testing.expectError(error.NoCredentials, gce.resolve(both));
    try testing.expectEqual(credentials_mod.MetadataState.expired, gce.trace.metadata);
    try gce.expect_rules();
}

test "an expireTime past the lifetime bound is malformed" {
    // Goal: IAM Credentials states an absolute time; one more than the bound ahead is refused as
    // the relative `expires_in` is, and one at the bound is used.
    const extras = [_]u64{ 0, 1 };
    for (extras, 0..) |extra, index| {
        const files = &.{ credentials_file, subject_file };
        const fixture = try Fixture.create(54 + index, files, &wif_env);
        defer fixture.destroy();
        fixture.google.lifetime_s = constants.google_token_lifetime_max_s;
        fixture.google.iam_extra_s = extra;
        const result = fixture.resolve(both);
        if (extra == 0) {
            try result;
            try testing.expectEqual(credentials_mod.State.used, fixture.trace.workload_identity);
        } else {
            try testing.expectError(error.NoCredentials, result);
            const state = fixture.trace.workload_identity;
            try testing.expectEqual(credentials_mod.State.malformed, state);
            try testing.expectEqual(credentials_mod.Step.impersonation, fixture.trace.step);
        }
        try fixture.expect_rules();
    }
}

/// `head`, then blanks to `total` bytes, then `tail`.
fn padded_text(head: []const u8, total: usize, tail: []const u8) ![]u8 {
    assert(tail.len > 0);
    assert(head.len + tail.len <= total);
    const text = try testing.allocator.alloc(u8, total);
    @memcpy(text[0..head.len], head);
    @memset(text[head.len .. total - tail.len], ' ');
    @memcpy(text[total - tail.len ..], tail);
    return text;
}

test "the credentials file and the subject token, at their bounds and one past" {
    // Goal: a credentials file of exactly its bound is read and one byte more is unreadable,
    // with no network call; a subject token of exactly its bound reaches STS and one byte more
    // is unreadable, with no network call.
    const file_max = constants.google_credentials_file_bytes_max;
    const account = parse_tests.file_account;
    for ([_]usize{ file_max, file_max + 1 }, 0..) |size, index| {
        const text = try padded_text(account[0 .. account.len - 1], size, "}");
        defer testing.allocator.free(text);
        const file: host_sim.File = .{ .path = credentials_path, .content = text };
        const fixture = try Fixture.create(60 + index, &.{ file, subject_file }, &wif_env);
        defer fixture.destroy();
        const result = fixture.resolve(both);
        if (size == file_max) {
            try result;
        } else {
            try testing.expectError(error.NoCredentials, result);
        }
        const expected: credentials_mod.State = if (size == file_max) .used else .unreadable;
        try testing.expectEqual(expected, fixture.trace.workload_identity);
        if (size > file_max) try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
        try fixture.expect_rules();
    }
    const subject_max = constants.google_subject_token_bytes_max;
    for ([_]usize{ subject_max, subject_max + 1 }, 0..) |size, index| {
        const token = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(token);
        @memset(token, 'j');
        const subject: host_sim.File = .{ .path = subject_path, .content = token };
        const fixture = try Fixture.create(62 + index, &.{ credentials_file, subject }, &wif_env);
        defer fixture.destroy();
        try testing.expectError(error.NoCredentials, fixture.resolve(both));
        if (size == subject_max) {
            // Not the token STS knows, so it is refused there: it was sent whole.
            try testing.expectEqual(credentials_mod.Step.exchange, fixture.trace.step);
            try testing.expectEqual(@as(u32, 1), fixture.google.sts_calls);
        } else {
            const state = fixture.trace.workload_identity;
            try testing.expectEqual(credentials_mod.State.subject_unreadable, state);
            try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
        }
        try fixture.expect_rules();
    }
}

test "an answer and an access token, at their bounds and one past" {
    // Goal: an STS answer of exactly the response bound is read and one byte more is refused
    // before IAM Credentials is called; a metadata token of exactly the token bound is used and
    // one byte more is malformed.
    const answer_max = constants.google_response_bytes_max;
    for ([_]u32{ answer_max, answer_max + 1 }, 0..) |size, index| {
        const files = &.{ credentials_file, subject_file };
        const fixture = try Fixture.create(64 + index, files, &wif_env);
        defer fixture.destroy();
        fixture.google.sts_answer_bytes = size;
        const result = fixture.resolve(both);
        if (size == answer_max) {
            try result;
        } else {
            try testing.expectError(error.NoCredentials, result);
        }
        const expected_calls: u32 = if (size == answer_max) 1 else 0;
        try testing.expectEqual(expected_calls, fixture.google.iam_calls);
        try testing.expectEqual(@as(u32, 1), fixture.google.sts_calls);
        try fixture.expect_rules();
    }
    const token_max = constants.google_access_token_bytes_max;
    for ([_]usize{ token_max, token_max + 1 }, 0..) |size, index| {
        const token = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(token);
        @memcpy(token[0..5], "ya29.");
        @memset(token[5..], 'm');
        const fixture = try Fixture.create(66 + index, &.{}, &.{});
        defer fixture.destroy();
        fixture.google.metadata_token_text = token;
        const result = fixture.resolve(both);
        if (size == token_max) {
            try result;
            try testing.expectEqualStrings(token, fixture.token.text());
        } else {
            try testing.expectError(error.NoCredentials, result);
            const state = fixture.trace.metadata;
            try testing.expectEqual(credentials_mod.MetadataState.malformed, state);
        }
        try fixture.expect_rules();
    }
}

test "seeded network faults never leak a secret or leave one in memory" {
    // Goal: whatever call the network fails, and however the bodies arrive, the rules hold and
    // the outcome is either a token or a named state.
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        const fixture = try Fixture.create(seed, &.{ credentials_file, subject_file }, &wif_env);
        defer fixture.destroy();
        fixture.wire.faults.fail_per_mille = 300;
        fixture.wire.faults.chunk_bytes_max = 7;
        fixture.resolve(both) catch {
            try testing.expect(fixture.trace.workload_identity != .used);
            try testing.expect(fixture.trace.workload_identity != .not_configured);
        };
        try fixture.expect_rules();
    }
}
