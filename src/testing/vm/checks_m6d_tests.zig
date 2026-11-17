//! Unit tests for checks_m6d.zig: each check fed the output it must accept and the wrong outputs
//! it must refuse, and the setup's pure pieces fed wrong values.

const std = @import("std");
const testing = std.testing;
const m6d = @import("checks_m6d.zig");
const checks_m4 = @import("checks_m4.zig");

fn rep(comptime byte: u8, comptime count: usize) [count]u8 {
    return @splat(byte);
}
fn stdout_only(text: []const u8) m6d.Streams {
    return .{ .stdout = text, .stderr = "" };
}

const hex_a = rep('a', 64);
const hex_b = rep('b', 64);
const hex_c = rep('c', 64);
const hex_d = rep('d', 64);

const good: m6d.Config = .{
    .provider = "projects/123456789/locations/global/workloadIdentityPools/github/providers/zigbox",
    .service_account = "zbx-demo@my-project.iam.gserviceaccount.com",
    .gar_registry = "us-docker.pkg.dev/my-project",
    .gcr_registry = "gcr.io/my-project",
};

test "the repository variables: good values pass, each wrong shape is refused" {
    // Goal: nothing that could break a guest command or a JSON string reaches one. Method: change
    // one value at a time to a wrong shape or a byte outside the alphabet.
    try m6d.check_config(good);
    var direct = good;
    direct.service_account = "";
    try m6d.check_config(direct);
    var eu = good;
    eu.gcr_registry = "eu.gcr.io/my-project";
    try m6d.check_config(eu);

    const providers = [_][]const u8{
        "",
        "projects/x1/locations/global/workloadIdentityPools/github/providers/zigbox",
        "projects/1/locations/us/workloadIdentityPools/github/providers/zigbox",
        "projects/1/locations/global/workloadIdentityPools/github/providers/zig box",
        "projects/1/locations/global/workloadIdentityPools/github/providers/zigbox/x",
        "projects/1/locations/global/workloadIdentityPools/github/providers",
        "projects/1/locations/global/workloadIdentityPools/git\"hub/providers/z",
    };
    for (providers) |provider| {
        var config = good;
        config.provider = provider;
        try testing.expectError(error.ProviderWrong, m6d.check_config(config));
    }
    const accounts = [_][]const u8{
        "zbx-demo@my-project.example.com",
        "@my-project.iam.gserviceaccount.com",
        "zbx-demo.iam.gserviceaccount.com",
        "zbx;demo@my-project.iam.gserviceaccount.com",
    };
    for (accounts) |account| {
        var config = good;
        config.service_account = account;
        try testing.expectError(error.ServiceAccountWrong, m6d.check_config(config));
    }
    const gars = [_][]const u8{ "us-docker.pkg.dev", "gcr.io/my-project", "us-docker.pkg.dev/" };
    for (gars) |registry| {
        var config = good;
        config.gar_registry = registry;
        try testing.expectError(error.RegistryWrong, m6d.check_config(config));
    }
    var gcr = good;
    gcr.gcr_registry = "gcr.io/my project";
    try testing.expectError(error.RegistryWrong, m6d.check_config(gcr));
    var long = good;
    long.gar_registry = "us-docker.pkg.dev/" ++ rep('a', 200);
    try testing.expectError(error.TooLong, m6d.check_config(long));
    try testing.expectEqualStrings("my-project", m6d.project_of(good.gar_registry));
}

test "first_missing names the first absent variable and lets the service account be empty" {
    const all: [6]?[]const u8 = .{ "p", null, "g", "c", "u", "t" };
    try testing.expectEqual(@as(?[]const u8, null), m6d.first_missing(all));
    var no_gar = all;
    no_gar[2] = "";
    try testing.expectEqualStrings("ZBX_GAR_REGISTRY", m6d.first_missing(no_gar).?);
    var fork = all;
    fork[4] = null;
    fork[5] = null;
    try testing.expectEqualStrings("ACTIONS_ID_TOKEN_REQUEST_URL", m6d.first_missing(fork).?);
    const none: [6]?[]const u8 = .{ null, null, null, null, null, null };
    try testing.expectEqualStrings("ZBX_GAR_PROVIDER", m6d.first_missing(none).?);
}

test "the OIDC request asks for the provider's default audience, percent-encoded" {
    var buffer: [512]u8 = undefined;
    const url = try m6d.oidc_request_url(
        &buffer,
        "https://runner.example/token?api-version=2.0",
        "projects/1/locations/global/workloadIdentityPools/p/providers/q",
    );
    try testing.expectEqualStrings(
        "https://runner.example/token?api-version=2.0&audience=https%3A%2F%2F" ++
            "iam.googleapis.com%2Fprojects%2F1%2Flocations%2Fglobal%2F" ++
            "workloadIdentityPools%2Fp%2Fproviders%2Fq",
        url,
    );
    const bare = try m6d.oidc_request_url(&buffer, "https://r.example/t", "projects/1");
    try testing.expect(std.mem.startsWith(u8, bare, "https://r.example/t?audience=https%3A"));
    var small: [16]u8 = undefined;
    try testing.expectError(error.WriteFailed, m6d.oidc_request_url(&small, "https://x", "p"));
}

test "the runner's answer yields the JWT; anything else is refused" {
    const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl";
    const body = "{\"count\":1959,\"value\": \"" ++ jwt ++ "\"}";
    try testing.expectEqualStrings(jwt, try m6d.parse_oidc_response(body));
    const wrong = [_][]const u8{
        "",
        "{\"message\":\"Unable to get ACTIONS_ID_TOKEN_REQUEST_URL\"}",
        "{\"value\":1}",
        "{\"value\":\"abc\"}",
        "{\"value\":\"eyJh.only-one-dot\"}",
        "{\"value\":\"eyJh.b.c\\\"d\"}",
        "{\"value\":\"eyJh.b c.d\"}",
        "{\"value\":\"eyJh.b.c",
    };
    for (wrong) |text| try testing.expectError(error.JsonWrong, m6d.parse_oidc_response(text));
}

test "a token is used for three minutes, and not if the clock went back" {
    try testing.expect(m6d.oidc_fresh(1000, 1000));
    try testing.expect(m6d.oidc_fresh(1000, 1000 + m6d.oidc_fresh_ms - 1));
    try testing.expect(!m6d.oidc_fresh(1000, 1000 + m6d.oidc_fresh_ms));
    try testing.expect(!m6d.oidc_fresh(1000, 999));
}

test "the external_account file is the JSON zbx reads, impersonating only when asked" {
    // Goal: the file the demo writes parses as the fields slice 1's parser reads. Method: render
    // both forms and parse them with std.json.
    var buffer: [2048]u8 = undefined;
    const Source = struct { file: []const u8 };
    const File = struct {
        type: []const u8,
        audience: []const u8,
        subject_token_type: []const u8,
        token_url: []const u8,
        credential_source: Source,
        service_account_impersonation_url: ?[]const u8 = null,
    };
    const text = try m6d.render_external_account(&buffer, good, "/home/demo/s/oidc", true);
    const parsed = try std.json.parseFromSlice(File, testing.allocator, text, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("external_account", parsed.value.type);
    try testing.expectEqualStrings("//iam.googleapis.com/" ++ good.provider, parsed.value.audience);
    try testing.expectEqualStrings("/home/demo/s/oidc", parsed.value.credential_source.file);
    try testing.expectEqualStrings(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" ++
            good.service_account ++ ":generateAccessToken",
        parsed.value.service_account_impersonation_url.?,
    );
    const direct = try m6d.render_external_account(&buffer, good, "/home/demo/s/oidc", false);
    const plain = try std.json.parseFromSlice(File, testing.allocator, direct, .{});
    defer plain.deinit();
    try testing.expectEqual(@as(?[]const u8, null), plain.value.service_account_impersonation_url);
}

test "masking hides every token shape and every named secret, and nothing else" {
    // Goal: no guest output reaches the job log with a token in it. Method: a line with each
    // shape, a named secret, and words that only look close.
    var out: [512]u8 = undefined;
    const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOnppZ2JveCJ9.c2lnbmF0dXJlLXRleHQ";
    const text = "Bearer ya29.a0AfB_x-y token=" ++ jwt ++
        " Basic b2F1dGgyYWNjZXNzdG9rZW46eWEy end opaque-secret-42 ya29 eyJshort.a.b";
    const shown = m6d.mask_secrets(text, &.{"opaque-secret-42"}, &out);
    try testing.expectEqualStrings(
        "Bearer [masked] token=[masked] Basic [masked] end [masked] ya29 eyJshort.a.b",
        shown,
    );
    const clean = "pulled us-docker.pkg.dev/p/zbx-demo/hello:latest sha256:abc";
    try testing.expectEqualStrings(clean, m6d.mask_secrets(clean, &.{"opaque-secret-42"}, &out));
    // Inside a word is not the start of a token.
    try testing.expectEqualStrings("xya29.b", m6d.mask_secrets("xya29.b", &.{}, &out));
    // A named secret is masked wherever it starts.
    const glued = m6d.mask_secrets("key:opaque-secret-42.", &.{"opaque-secret-42"}, &out);
    try testing.expectEqualStrings("key:[masked].", glued);
    // The output never outgrows its bound, even when every run is the shortest shape.
    const dense = "ya29. ya29. ya29. ya29.";
    var tight: [2 * dense.len]u8 = undefined;
    const masked = m6d.mask_secrets(dense, &.{}, &tight);
    try testing.expectEqualStrings("[masked] [masked] [masked] [masked]", masked);
}

const refusal_e0560 =
    \\error[ZBX-E0560]: no Google credentials were found to pull from us-docker.pkg.dev
    \\  fix: point GOOGLE_APPLICATION_CREDENTIALS at a workload identity federation file
    \\  fix: or pull on Google Compute Engine with a service account
;

test "step 1: E0560, exit 2, naming the sources" {
    const streams: m6d.Streams = .{ .stdout = "", .stderr = refusal_e0560 };
    try m6d.check_no_credentials(streams, 2, "us-docker.pkg.dev");
    try testing.expectError(error.ExitCodeWrong, m6d.check_no_credentials(streams, 1, "x"));
    const other: m6d.Streams = .{ .stdout = "", .stderr = "error[ZBX-E0567]: refused" };
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(other, 2, "x"));
    const half: m6d.Streams = .{
        .stdout = "",
        .stderr = "error[ZBX-E0560]: no Google credentials were found to pull from x",
    };
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(half, 2, "x"));
    const printed: m6d.Streams = .{ .stdout = "sha256:", .stderr = refusal_e0560 };
    try testing.expectError(
        error.RefusalWrong,
        m6d.check_no_credentials(printed, 2, "us-docker.pkg.dev"),
    );
    const errno: m6d.Streams = .{ .stdout = "", .stderr = refusal_e0560 ++ "\nerrno 13" };
    try testing.expectError(
        error.RefusalWrong,
        m6d.check_no_credentials(errno, 2, "us-docker.pkg.dev"),
    );
}

test "step 2: hello, and the lock holding the reference and digest" {
    try m6d.check_hello(.{ .stdout = "hello\n", .stderr = "" }, 0);
    try testing.expectError(error.OutputWrong, m6d.check_hello(stdout_only("hi"), 0));
    try testing.expectError(error.ExitCodeWrong, m6d.check_hello(stdout_only(""), 1));
    const digest = "sha256:" ++ hex_a;
    const reference = "us-docker.pkg.dev/p/zbx-demo/hello:latest";
    const lock = "{\"images\":{\"" ++ reference ++ "\":\"" ++ digest ++ "\"}}";
    try m6d.check_lock(lock, reference, digest);
    try testing.expectError(error.DigestWrong, m6d.check_lock("{}", reference, digest));
    try testing.expectError(
        error.DigestWrong,
        m6d.check_lock(lock, reference, "sha256:" ++ hex_b),
    );
}

test "step 4: E0568, exit 1, naming the repository and the permission" {
    const stderr =
        \\error[ZBX-E0568]: us-docker.pkg.dev denied the pull of p/zbx-denied/hello: the identity
        \\ lacks artifactregistry.repositories.downloadArtifacts, or the repository does not exist
    ;
    const streams: m6d.Streams = .{ .stdout = "", .stderr = stderr };
    try m6d.check_denied(streams, 1, "p/zbx-denied/hello");
    try testing.expectError(error.RefusalWrong, m6d.check_denied(streams, 1, "p/zbx-demo/hello"));
    try testing.expectError(error.ExitCodeWrong, m6d.check_denied(streams, 2, "p/zbx-denied"));
    const missing: m6d.Streams = .{
        .stdout = "",
        .stderr = "error[ZBX-E0569]: p/zbx-denied/hello has no tag latest",
    };
    try testing.expectError(error.RefusalWrong, m6d.check_denied(missing, 1, "p/zbx-denied"));
}

test "the agent's JSON matches the command line's pull" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const digest = "sha256:" ++ hex_a;
    const tree = "b3:" ++ hex_c;
    const reference = "us-docker.pkg.dev/p/zbx-demo/hello:latest";
    const cli: checks_m4.PullDoc = .{
        .schema = "zbx.pull/1",
        .reference = reference,
        .manifest_digest = digest,
        .platform = "linux/amd64",
        .tree = tree,
        .config = .{ .digest = digest, .cache = "downloaded" },
        .layers = &.{},
    };
    const json = "{\"schema\":\"zbx-demo.m6d-agent/1\",\"reference\":\"" ++ reference ++
        "\",\"manifest_digest\":\"" ++ digest ++ "\",\"tree\":\"" ++ tree ++
        "\",\"token_source\":\"workload_identity\"}";
    try m6d.check_agent(arena, .{ .stdout = json, .stderr = "" }, 0, reference, cli);
    const prose: m6d.Streams = .{ .stdout = "pulled " ++ digest, .stderr = "" };
    try testing.expectError(error.JsonWrong, m6d.check_agent(arena, prose, 0, reference, cli));
    var other = cli;
    other.tree = "b3:" ++ hex_d;
    try testing.expectError(
        error.DigestWrong,
        m6d.check_agent(arena, .{ .stdout = json, .stderr = "" }, 0, reference, other),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        m6d.check_agent(arena, .{ .stdout = json, .stderr = "" }, 1, reference, cli),
    );
}

test "the shape check says one line per token, and nothing else" {
    const two = "shapes: federated token starts with ya29.\n" ++
        "shapes: access token starts with ya29.\n";
    try m6d.check_shapes(.{ .stdout = two, .stderr = "" }, 0, true);
    try testing.expectError(
        error.OutputWrong,
        m6d.check_shapes(.{ .stdout = two, .stderr = "" }, 0, false),
    );
    const one = "shapes: federated token starts with ya29.\n";
    try m6d.check_shapes(.{ .stdout = one, .stderr = "" }, 0, false);
    const leaked = one ++ "ya29.x";
    try testing.expectError(
        error.OutputWrong,
        m6d.check_shapes(.{ .stdout = leaked, .stderr = "" }, 0, false),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        m6d.check_shapes(.{ .stdout = one, .stderr = "" }, 1, false),
    );
}

test "step 5: clean only with enough needles, some files and no hit" {
    const clean = "needles 6\nfiles 41 bytes 90210 skipped 0\nscan: clean\n";
    try m6d.check_scan(.{ .stdout = clean, .stderr = "" }, 0, 5);
    try testing.expectError(error.SecretFound, m6d.check_scan(stdout_only(clean), 0, 7));
    const empty = "needles 6\nfiles 0 bytes 0 skipped 0\nscan: clean\n";
    try testing.expectError(error.SecretFound, m6d.check_scan(stdout_only(empty), 0, 5));
    const hit = "needles 6\nfiles 41 bytes 9 skipped 0\nHIT /home/demo/x needle=2 offset=7\n" ++
        "scan: FOUND 1\n";
    try testing.expectError(error.SecretFound, m6d.check_scan(stdout_only(hit), 1, 5));
    try testing.expectError(error.SecretFound, m6d.check_scan(stdout_only(clean), 1, 5));
}

test {
    _ = @import("m6d_fixture/scan.zig");
    _ = @import("m6d_fixture/mask.zig");
}
