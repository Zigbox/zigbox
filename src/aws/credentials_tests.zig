//! Tests of `credentials.resolve` against the simulated host and the simulated AWS: each source
//! on its own, the order between them, every way a source can fail, and the rules that must hold
//! whatever happens: version 1 of the metadata service is never asked, a proxy never carries a
//! metadata call, a configured role never falls through to another identity, and every secret
//! buffer is zero afterwards.

const std = @import("std");
const testing = std.testing;
const aws_sim = @import("aws_sim.zig");
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const host_sim = @import("../host_sim.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const parse = @import("parse.zig");
const sigv4 = @import("sigv4.zig");

const Credentials = credentials_mod.Credentials;
const Trace = credentials_mod.Trace;
const Workspace = credentials_mod.Workspace;

const token_path = "/var/run/secrets/eks/token";
const role_arn = "arn:aws:iam::123456789012:role/zbx-pull";

/// Everything one test owns, on the heap: the workspace and the host are large.
const Fixture = struct {
    host: host_sim.HostSim,
    wire: net_sim.SimNet,
    aws: aws_sim.AwsSim,
    workspace: Workspace,
    credentials: Credentials,
    trace: Trace,
    received: [1024]u8,

    fn create(
        seed: u64,
        files: []const host_sim.File,
        env: []const host_sim.EnvironmentVariable,
    ) !*Fixture {
        const fixture = try std.heap.page_allocator.create(Fixture);
        fixture.host.init(seed, files);
        fixture.host.environment_variables = env;
        fixture.aws = .{};
        fixture.aws.now_s = fixture.host.world.now;
        fixture.wire.init(seed, fixture.aws.responder());
        fixture.wire.received = &fixture.received;
        fixture.host.wire = &fixture.wire;
        return fixture;
    }

    fn destroy(fixture: *Fixture) void {
        std.heap.page_allocator.destroy(fixture);
    }

    /// Resolves with the environment the fixture's host holds, read through `Env.from_host`.
    fn resolve(fixture: *Fixture) credentials_mod.Error!void {
        var storage: [credentials_mod.Env.names.len]credentials_mod.Env.Pair = undefined;
        const env = credentials_mod.Env.from_host(fixture.host.interface(), &storage);
        return fixture.resolve_with(env);
    }

    fn resolve_with(fixture: *Fixture, env: credentials_mod.Env) credentials_mod.Error!void {
        return credentials_mod.resolve(
            fixture.host.interface(),
            env,
            "us-east-1",
            fixture.host.world.now,
            &fixture.workspace,
            &fixture.credentials,
            &fixture.trace,
        );
    }

    fn expect_wiped(fixture: *const Fixture) !void {
        for (fixture.workspace.token_file) |byte| try testing.expectEqual(@as(u8, 0), byte);
        for (fixture.workspace.request_body) |byte| try testing.expectEqual(@as(u8, 0), byte);
        for (fixture.workspace.response) |byte| try testing.expectEqual(@as(u8, 0), byte);
    }
};

const token_file: host_sim.File = .{ .path = token_path, .content = aws_sim.web_token ++ "\n" };
const web_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "AWS_ROLE_ARN", .value = role_arn },
    .{ .name = "AWS_WEB_IDENTITY_TOKEN_FILE", .value = token_path },
};

// Goal: the environment is the first source and costs no network call.
// Method: set both variables and a token; resolve; check the key, the source, no request made.
test "environment credentials are used as given, with no network call" {
    const env = [_]host_sim.EnvironmentVariable{
        .{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIAEXAMPLEEXAMPLE1" },
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = aws_sim.issued_secret },
        .{ .name = "AWS_SESSION_TOKEN", .value = aws_sim.issued_token },
    };
    const fixture = try Fixture.create(1, &.{}, &env);
    defer fixture.destroy();
    try fixture.resolve();
    try testing.expectEqual(credentials_mod.Source.environment, fixture.credentials.source);
    try testing.expectEqualStrings("AKIAEXAMPLEEXAMPLE1", fixture.credentials.key().access_key_id);
    try testing.expectEqualStrings(aws_sim.issued_token, fixture.credentials.key().session_token);
    try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
    try testing.expect(!fixture.credentials.expired(fixture.host.world.now + 1_000_000));
    try fixture.expect_wiped();
    fixture.credentials.wipe();
    try testing.expectEqual(@as(u32, 0), fixture.credentials.access_key_id_len);
    for (fixture.credentials.secret_access_key) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

// Goal: environment credentials that are half set, or not keys, are the answer: reported, never
// used, and never replaced by another identity (web identity or the instance role).
test "an incomplete or malformed environment pair is terminal" {
    const long_token: [constants.aws_session_token_bytes_max + 1]u8 = @splat('t');
    const Pair = credentials_mod.Env.Pair;
    const key = Pair{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIAEXAMPLEEXAMPLE1" };
    const spaced = Pair{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIA EXAMPLE EXAMPLE" };
    const short = Pair{ .name = "AWS_ACCESS_KEY_ID", .value = "SHORT" };
    const dirty = Pair{ .name = "AWS_SECRET_ACCESS_KEY", .value = "wJalrXUtnFEMI/K7MDENG\n" };
    const big = Pair{ .name = "AWS_SESSION_TOKEN", .value = &long_token };
    const secret = credentials_mod.Env.Pair{
        .name = "AWS_SECRET_ACCESS_KEY",
        .value = aws_sim.issued_secret,
    };
    const Case = struct { pairs: []const Pair, state: credentials_mod.State };
    const cases = [_]Case{
        .{ .pairs = &.{key}, .state = .incomplete },
        .{ .pairs = &.{secret}, .state = .incomplete },
        .{
            .pairs = &.{ .{ .name = "AWS_SESSION_TOKEN", .value = aws_sim.issued_token }, key },
            .state = .incomplete,
        },
        .{ .pairs = &.{ spaced, secret }, .state = .malformed },
        .{ .pairs = &.{ short, secret }, .state = .malformed },
        .{ .pairs = &.{ dirty, key }, .state = .malformed },
        // A token over its bound is refused with a reason, not dropped.
        .{ .pairs = &.{ key, secret, big }, .state = .malformed },
    };
    for (cases) |case| {
        // Web identity is configured and the metadata service is there: neither is reached.
        const fixture = try Fixture.create(2, &.{token_file}, &web_env);
        defer fixture.destroy();
        fixture.aws.imds = .v2;
        const env: credentials_mod.Env = .{ .pairs = case.pairs };
        try testing.expectError(error.NoCredentials, fixture.resolve_with(env));
        try testing.expectEqual(case.state, fixture.trace.environment);
        try testing.expectEqual(credentials_mod.State.not_configured, fixture.trace.web_identity);
        try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
        try testing.expectEqual(@as(u32, 0), fixture.credentials.access_key_id_len);
        try fixture.expect_wiped();
    }
}

// Goal: the environment is the caller's: a host whose own process holds other settings (or
// none) changes nothing, and a second caller with its own view gets its own answer.
test "the environment is the caller's view, not the host's" {
    const process_env = [_]host_sim.EnvironmentVariable{
        .{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIAPROCESSPROCESS1" },
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = "processsecretprocesssecret" },
    };
    const fixture = try Fixture.create(21, &.{token_file}, &process_env);
    defer fixture.destroy();
    const workload_a = [_]credentials_mod.Env.Pair{
        .{ .name = "AWS_ACCESS_KEY_ID", .value = "AKIAWORKLOADAAAAA1" },
        .{ .name = "AWS_SECRET_ACCESS_KEY", .value = aws_sim.issued_secret },
    };
    try fixture.resolve_with(.{ .pairs = &workload_a });
    try testing.expectEqualStrings("AKIAWORKLOADAAAAA1", fixture.credentials.key().access_key_id);
    const workload_b = [_]credentials_mod.Env.Pair{
        .{ .name = "AWS_ROLE_ARN", .value = role_arn },
        .{ .name = "AWS_WEB_IDENTITY_TOKEN_FILE", .value = token_path },
    };
    try fixture.resolve_with(.{ .pairs = &workload_b });
    try testing.expectEqual(credentials_mod.Source.web_identity, fixture.credentials.source);
    // No view at all: the process's variables are not consulted, so the metadata service answers.
    fixture.aws.imds = .v2;
    try fixture.resolve_with(.{ .pairs = &.{} });
    try testing.expectEqual(credentials_mod.Source.instance_metadata, fixture.credentials.source);
    fixture.credentials.wipe();
}

// Goal: web identity sends the token file in an unsigned STS call, escaped, and takes the answer.
test "web identity: an unsigned call with the escaped form, credentials with an expiry" {
    const fixture = try Fixture.create(3, &.{token_file}, &web_env);
    defer fixture.destroy();
    try fixture.resolve();
    try testing.expectEqual(credentials_mod.Source.web_identity, fixture.credentials.source);
    try testing.expectEqualStrings(aws_sim.issued_key_id, fixture.credentials.key().access_key_id);
    try testing.expectEqual(fixture.host.world.now + 3600, fixture.credentials.expiration_s);
    try testing.expectEqual(@as(u32, 1), fixture.aws.sts_calls);
    try testing.expectEqual(@as(u32, 0), fixture.aws.imds_calls);
    try testing.expectEqual(@as(u32, 0), fixture.aws.leaked);
    const form = fixture.aws.last_form[0..fixture.aws.last_form_len];
    const want = "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fzbx-pull";
    try testing.expect(std.mem.indexOf(u8, form, want) != null);
    try testing.expect(std.mem.indexOf(u8, form, "RoleSessionName=zbx&") != null);
    const logged = fixture.wire.logged(0).?;
    try testing.expectEqualStrings("sts.us-east-1.amazonaws.com", logged.host_text());
    try testing.expectEqual(net.Scheme.https, logged.scheme);
    try testing.expectEqual(@as(u32, 0), logged.authorization_len);
    try fixture.expect_wiped();
}

// Goal: every way web identity can fail is a named state, a configured role never falls through
// to the metadata service, and a refusal reports STS's code and never its message.
test "web identity failures are terminal and named" {
    const cases = [_]struct { mode: aws_sim.StsMode, state: credentials_mod.State }{
        .{ .mode = .refused, .state = .refused },
        .{ .mode = .malformed, .state = .malformed },
        .{ .mode = .expired, .state = .expired },
        .{ .mode = .unavailable, .state = .refused },
    };
    for (cases) |case| {
        const fixture = try Fixture.create(4, &.{token_file}, &web_env);
        defer fixture.destroy();
        fixture.aws.sts = case.mode;
        try testing.expectError(error.NoCredentials, fixture.resolve());
        try testing.expectEqual(case.state, fixture.trace.web_identity);
        try testing.expectEqual(@as(u32, 0), fixture.aws.imds_calls);
        try testing.expectEqual(@as(u32, 0), fixture.credentials.access_key_id_len);
        if (case.mode == .refused) {
            try testing.expectEqualStrings("InvalidIdentityToken", fixture.trace.code());
            try testing.expectEqual(@as(u16, 400), fixture.trace.status);
            const code = &fixture.trace.error_code;
            try testing.expect(std.mem.indexOf(u8, code, aws_sim.message_marker) == null);
        }
        try fixture.expect_wiped();
    }
    const fixture = try Fixture.create(5, &.{token_file}, &web_env);
    defer fixture.destroy();
    fixture.wire.faults.fail_per_mille = 1000;
    try testing.expectError(error.NoCredentials, fixture.resolve());
    try testing.expectEqual(credentials_mod.State.no_answer, fixture.trace.web_identity);
}

// Goal: a token file that is missing, unreadable, empty or not a token, and a half-set pair, are
// told apart and never reach the network.
test "web identity: unusable token files and half-set variables" {
    const unreadable: host_sim.File = .{ .path = token_path, .content = "x", .readable = false };
    const empty: host_sim.File = .{ .path = token_path, .content = "\n" };
    const garbage: host_sim.File = .{ .path = token_path, .content = "not a token!" };
    const files = [_]?host_sim.File{ null, unreadable, empty, garbage };
    for (files) |file| {
        const list = if (file) |present| &[_]host_sim.File{present} else &[_]host_sim.File{};
        const fixture = try Fixture.create(6, list, &web_env);
        defer fixture.destroy();
        try testing.expectError(error.NoCredentials, fixture.resolve());
        try testing.expectEqual(credentials_mod.State.unreadable, fixture.trace.web_identity);
        try testing.expectEqual(@as(u32, 0), fixture.wire.requests);
    }
    const only_role = [_]host_sim.EnvironmentVariable{
        .{ .name = "AWS_ROLE_ARN", .value = role_arn },
    };
    const fixture = try Fixture.create(7, &.{token_file}, &only_role);
    defer fixture.destroy();
    fixture.wire.faults.fail_per_mille = 1000;
    try testing.expectError(error.NoCredentials, fixture.resolve());
    try testing.expectEqual(credentials_mod.State.incomplete, fixture.trace.web_identity);
}

// Goal: the metadata service is used over version 2, plain HTTP, never through a proxy, with the
// session token as a secret header, and the proxy settings of the environment change nothing.
test "metadata service: version 2 only, never through a proxy" {
    const env = [_]host_sim.EnvironmentVariable{
        .{ .name = "HTTP_PROXY", .value = "http://proxy.example:3128" },
        .{ .name = "HTTPS_PROXY", .value = "http://proxy.example:3128" },
    };
    const fixture = try Fixture.create(8, &.{}, &env);
    defer fixture.destroy();
    try fixture.resolve();
    try testing.expectEqual(credentials_mod.Source.instance_metadata, fixture.credentials.source);
    try testing.expectEqual(@as(u32, 3), fixture.aws.imds_calls);
    try testing.expectEqual(@as(u32, 0), fixture.aws.leaked);
    try testing.expectEqual(@as(u32, 0), fixture.aws.imds_v1_served);
    var index: u32 = 0;
    while (index < 3) : (index += 1) {
        const logged = fixture.wire.logged(index).?;
        try testing.expectEqual(net.ProxyUse.never, logged.proxy);
        try testing.expectEqual(net.Scheme.http, logged.scheme);
        try testing.expectEqualStrings("169.254.169.254", logged.host_text());
        if (index > 0) try testing.expect(logged.secret_headers == 1);
        // The short limits, not the registry's: a laptop off EC2 is not kept waiting.
        try testing.expectEqual(constants.aws_imds_timeout_ms, logged.idle_timeout_ms);
        try testing.expectEqual(constants.aws_imds_total_timeout_ms, logged.total_timeout_ms);
    }
    try testing.expectEqual(net.Method.put, fixture.wire.logged(0).?.method);
    try fixture.expect_wiped();
}

// Goal: a service that does not offer version 2, has no role, answers nonsense, is switched off or
// is simply not there ends in "no credentials" without ever asking for version 1.
test "metadata service failures never fall back to version 1" {
    const modes = [_]struct { mode: aws_sim.ImdsMode, state: credentials_mod.State, calls: u32 }{
        .{ .mode = .v1_only, .state = .v1_only, .calls = 1 },
        .{ .mode = .no_role, .state = .no_role, .calls = 2 },
        .{ .mode = .malformed, .state = .malformed, .calls = 3 },
        .{ .mode = .unavailable, .state = .refused, .calls = 1 },
    };
    for (modes) |case| {
        const fixture = try Fixture.create(9, &.{}, &.{});
        defer fixture.destroy();
        fixture.aws.imds = case.mode;
        try testing.expectError(error.NoCredentials, fixture.resolve());
        try testing.expectEqual(case.state, fixture.trace.instance_metadata);
        try testing.expectEqual(case.calls, fixture.aws.imds_calls);
        try testing.expectEqual(@as(u32, 0), fixture.aws.imds_v1_served);
        try fixture.expect_wiped();
    }
    const absent = try Fixture.create(10, &.{}, &.{});
    defer absent.destroy();
    absent.wire.faults.fail_per_mille = 1000;
    absent.wire.faults.fail_error = error.TimedOut;
    try testing.expectError(error.NoCredentials, absent.resolve());
    try testing.expectEqual(credentials_mod.State.not_configured, absent.trace.instance_metadata);
    try testing.expectEqual(@as(u32, 1), absent.wire.requests);
    const off = [_]host_sim.EnvironmentVariable{
        .{ .name = "AWS_EC2_METADATA_DISABLED", .value = "true" },
    };
    const disabled = try Fixture.create(11, &.{}, &off);
    defer disabled.destroy();
    try testing.expectError(error.NoCredentials, disabled.resolve());
    try testing.expectEqual(credentials_mod.State.disabled, disabled.trace.instance_metadata);
    try testing.expectEqual(@as(u32, 0), disabled.wire.requests);
}

// Goal: credentials that are about to run out are not handed out.
test "credentials inside the expiry margin are refused" {
    const fixture = try Fixture.create(12, &.{}, &.{});
    defer fixture.destroy();
    fixture.aws.lifetime_s = 30;
    try testing.expectError(error.NoCredentials, fixture.resolve());
    try testing.expectEqual(credentials_mod.State.expired, fixture.trace.instance_metadata);
    try testing.expectEqual(@as(u32, 0), fixture.credentials.access_key_id_len);
}

/// Signs the ECR `GetAuthorizationToken` call with `key` at the host's time and makes it.
fn call_ecr(fixture: *Fixture, key: sigv4.Key, now_s: u64) !u16 {
    const host_name = "api.ecr.us-east-1.amazonaws.com";
    const target = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";
    var workspace: sigv4.Workspace = undefined;
    var signed: sigv4.Signed = undefined;
    try sigv4.sign(&.{
        .method = .post,
        .target = "/",
        .headers = &.{
            .{ .name = "content-type", .value = "application/x-amz-json-1.1" },
            .{ .name = "host", .value = host_name },
            .{ .name = "x-amz-target", .value = target },
        },
        .body = "{}",
        .scope = .{ .region = "us-east-1", .service = "ecr" },
        .key = key,
        .now_s = now_s,
    }, &workspace, &signed);
    var source: net.SliceSource = .{ .bytes = "{}" };
    var buffer: [512]u8 = undefined;
    var sink: net.BufferSink = .{ .buffer = &buffer };
    var head: net.Head = .{};
    const headers = [_]net.Header{
        .{ .name = "X-Amz-Target", .value = target },
        .{ .name = "X-Amz-Date", .value = &signed.amz_date },
        .{ .name = "X-Amz-Security-Token", .value = key.session_token, .secret = true },
    };
    try fixture.host.interface().network().call(&.{
        .scheme = .https,
        .host = host_name,
        .port = 443,
        .target = "/",
        .accept = "",
        .bearer = "",
        .body_bytes_max = buffer.len,
        .idle_timeout_ms = 1000,
        .total_timeout_ms = 0,
        .method = .post,
        .body = source.body(),
        .content_type = "application/x-amz-json-1.1",
        .authorization = signed.authorization_text(),
        .extra_headers = headers[0..if (key.session_token.len > 0) 3 else 2],
    }, &head, sink.sink());
    if (head.status == 200) {
        const token = try parse.parse_ecr_token(sink.bytes());
        try testing.expect(token.expiration_s > now_s);
    } else {
        try testing.expect(parse.error_code(sink.bytes()) != null);
    }
    return head.status;
}

// Goal: resolved credentials sign a request the simulated ECR accepts; a wrong secret, a missing
// session token and a clock five minutes off are each refused with a code.
test "resolved credentials sign for the simulated ECR; skew and bad keys are refused" {
    const fixture = try Fixture.create(13, &.{token_file}, &web_env);
    defer fixture.destroy();
    try fixture.resolve();
    const key = fixture.credentials.key();
    const now = fixture.host.world.now;
    try testing.expectEqual(@as(u16, 200), try call_ecr(fixture, key, now));
    try testing.expectEqual(@as(u32, 1), fixture.aws.ecr_ok);
    try testing.expectEqual(@as(u16, 200), try call_ecr(fixture, key, now + 299));
    try testing.expectEqual(@as(u16, 400), try call_ecr(fixture, key, now + 301));
    try testing.expectEqual(@as(u16, 400), try call_ecr(fixture, key, now - 301));
    var wrong = key;
    wrong.secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYWRONGKEY";
    try testing.expectEqual(@as(u16, 400), try call_ecr(fixture, wrong, now));
    var untokened = key;
    untokened.session_token = "";
    try testing.expectEqual(@as(u16, 400), try call_ecr(fixture, untokened, now));
    try testing.expectEqual(@as(u32, 2), fixture.aws.ecr_ok);
}

// Goal: S3 refuses a request that carries an Authorization, which is why the client must strip it
// on the redirect to a blob; the simulation counts what it was sent.
test "the simulated S3 refuses a credential and counts it" {
    const fixture = try Fixture.create(14, &.{}, &.{});
    defer fixture.destroy();
    var buffer: [128]u8 = undefined;
    var sink: net.BufferSink = .{ .buffer = &buffer };
    var head: net.Head = .{};
    const network = fixture.host.interface().network();
    var request: net.Request = .{
        .scheme = .https,
        .host = "layers.s3.us-east-1.amazonaws.com",
        .port = 443,
        .target = "/blob?X-Amz-Signature=abc",
        .accept = "",
        .bearer = "",
        .body_bytes_max = buffer.len,
        .idle_timeout_ms = 1000,
        .total_timeout_ms = 0,
    };
    try network.call(&request, &head, sink.sink());
    try testing.expectEqual(@as(u16, 200), head.status);
    request.basic = "QVdTOnBhc3N3b3Jk";
    sink.len = 0;
    try network.call(&request, &head, sink.sink());
    try testing.expectEqual(@as(u16, 400), head.status);
    try testing.expectEqual(@as(u32, 1), fixture.aws.leaked);
}

// Goal: under seeded faults on every request, resolve either returns the right key or says no
// credentials, never crashes, and leaves every buffer zero.
test "seeded faults: the right key or no credentials, and clean buffers" {
    var seed: u64 = 0;
    while (seed < 200) : (seed += 1) {
        const web = seed % 2 == 0;
        const files: []const host_sim.File = if (web) &.{token_file} else &.{};
        const env: []const host_sim.EnvironmentVariable = if (web) &web_env else &.{};
        const fixture = try Fixture.create(seed, files, env);
        defer fixture.destroy();
        fixture.wire.faults.fail_per_mille = 250;
        fixture.wire.faults.chunk_bytes_max = 1 + @as(u32, @intCast(seed % 40));
        fixture.wire.faults.cut_per_mille = 150;
        if (fixture.resolve()) {
            const key = fixture.credentials.key();
            try testing.expectEqualStrings(aws_sim.issued_key_id, key.access_key_id);
            try testing.expectEqualStrings(aws_sim.issued_secret, key.secret_access_key);
        } else |err| {
            try testing.expectEqual(error.NoCredentials, err);
            try testing.expectEqual(@as(u32, 0), fixture.credentials.access_key_id_len);
        }
        try testing.expectEqual(@as(u32, 0), fixture.aws.imds_v1_served);
        try testing.expectEqual(@as(u32, 0), fixture.aws.leaked);
        try fixture.expect_wiped();
    }
}
