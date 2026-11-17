//! Unit tests for checks_m6d.zig: each check fed the output it must accept and the wrong outputs
//! it must refuse, and the setup's pure pieces fed wrong values.

const std = @import("std");
const testing = std.testing;
const m6d = @import("checks_m6d.zig");
const checks_m4 = @import("checks_m4.zig");
const scan = @import("m6d_fixture/scan.zig");
const shape = @import("m6d_fixture/shape.zig");

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

/// `good` with the field named `field` set to `value`.
fn good_with(comptime field: []const u8, value: []const u8) m6d.Config {
    var config = good;
    @field(config, field) = value;
    return config;
}

test "the repository variables: each single condition refuses on its own" {
    // Goal: every condition of check_config is needed (a mutant that drops one fails here).
    // Method: rows that differ from `good` in exactly one fact.
    const pool = "projects/1/locations/global/workloadIdentityPools/";
    try m6d.check_config(good_with("provider", pool ++ rep('a', 63) ++ "/providers/z"));
    try testing.expectError(
        error.ProviderWrong,
        m6d.check_config(good_with("provider", pool ++ rep('a', 64) ++ "/providers/z")),
    );
    try testing.expectError(error.ServiceAccountWrong, m6d.check_config(good_with(
        "service_account",
        "zbx-demo@my_project.iam.gserviceaccount.com",
    )));
    const registries = [_]struct { []const u8, []const u8 }{
        .{ "gar_registry", "us-docker.example.com/my-project" }, // The host suffix.
        .{ "gar_registry", "u_s-docker.pkg.dev/my-project" }, // A label.
        .{ "gcr_registry", "eu_x.gcr.io/my-project" }, // A label.
        .{ "gcr_registry", "gcr.example.com/my-project" }, // The host suffix.
    };
    inline for (0..registries.len) |index| {
        const row = registries[index];
        try testing.expectError(error.RegistryWrong, m6d.check_config(good_with(row[0], row[1])));
    }
    // A quote never reaches a guest shell line, in any field.
    try testing.expectError(error.ProviderWrong, m6d.check_config(good_with(
        "provider",
        pool ++ "git'hub/providers/z",
    )));
    try testing.expectError(error.ServiceAccountWrong, m6d.check_config(good_with(
        "service_account",
        "zbx'demo@my-project.iam.gserviceaccount.com",
    )));
    try testing.expectError(
        error.RegistryWrong,
        m6d.check_config(good_with("gar_registry", "us-docker.pkg.dev/my'project")),
    );
    try testing.expectError(
        error.RegistryWrong,
        m6d.check_config(good_with("gcr_registry", "gcr.io/my'project")),
    );
    // The project number: empty is refused, a `0` and a `9` in it are not.
    const tail = "/locations/global/workloadIdentityPools/github/providers/z";
    try testing.expectError(
        error.ProviderWrong,
        m6d.check_config(good_with("provider", "projects/" ++ tail)),
    );
    try m6d.check_config(good_with("provider", "projects/1090" ++ tail));
    // A value of exactly the bound passes; one byte more is too long.
    const at_bound = "projects/" ++ rep('1', m6d.value_bytes_max - 9 - tail.len) ++ tail;
    comptime std.debug.assert(at_bound.len == m6d.value_bytes_max);
    try m6d.check_config(good_with("provider", at_bound));
    try testing.expectError(
        error.TooLong,
        m6d.check_config(good_with("provider", "projects/1" ++ at_bound[9..])),
    );
    // The service account's domain, with every other fact right.
    try testing.expectError(error.ServiceAccountWrong, m6d.check_config(good_with(
        "service_account",
        "zbx-demo@my-project.iam.gserviceaccount.net",
    )));
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

test "masking: a JWT needs exactly two dots, and a Basic value is masked to its end" {
    // Goal: the mask's two finer rules each matter. Method: an `eyJ` run of JWT length with one
    // and with three dots is left alone (the later parts start no `eyJ`, so no suffix of the run
    // is a JWT either); a Basic value with `+`, `/` and `=` is masked whole.
    var out: [512]u8 = undefined;
    const one_dot = "eyJhbGciOiJSUzI1NiJ9eyJzdWIiOiJyZXBvOnppZ2JveCJ9.c2lnbmF0dXJl";
    try testing.expectEqualStrings(one_dot, m6d.mask_secrets(one_dot, &.{}, &out));
    const three_dots = "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZC1wYXJ0LW9uZQ.c2lnbmF0.dXJl";
    try testing.expectEqualStrings(three_dots, m6d.mask_secrets(three_dots, &.{}, &out));
    const basic = "Basic b2F1dGgyYWNjZXNzdG9rZW46eWEy+/a= end";
    try testing.expectEqualStrings("Basic [masked] end", m6d.mask_secrets(basic, &.{}, &out));
}

/// zbx's real refusals, the diagnostic goldens (src/testdata/diag/), handed to the harness by
/// build.zig as data.
const golden_e0560 = @embedFile("m6d_e0560");
const golden_e0568 = @embedFile("m6d_e0568");

/// `text` with every `fact` replaced by `instead`, in `buffer`.
fn without(buffer: []u8, text: []const u8, fact: []const u8, instead: []const u8) []const u8 {
    std.debug.assert(std.mem.indexOf(u8, text, fact) != null);
    const length = std.mem.replace(u8, text, fact, instead, buffer);
    std.debug.assert(length > 0);
    return buffer[0 .. text.len - length * fact.len + length * instead.len];
}

fn refusal(stderr: []const u8) m6d.Streams {
    return .{ .stdout = "", .stderr = stderr };
}

test "step 1: zbx's real E0560 passes; each fact taken out alone is refused" {
    // Goal: the check accepts the golden and needs each fact it names. Method: the golden, then
    // one row per fact with that fact alone replaced.
    const host = "us-docker.pkg.dev";
    try m6d.check_no_credentials(refusal(golden_e0560), 2, host);
    try testing.expectError(
        error.ExitCodeWrong,
        m6d.check_no_credentials(refusal(golden_e0560), 1, host),
    );
    var buffer: [2048]u8 = undefined;
    const facts = [_][]const u8{
        "no Google credentials were found", host, "GOOGLE_APPLICATION_CREDENTIALS",
        "Google Compute Engine",
    };
    for (facts) |fact| {
        const text = without(&buffer, golden_e0560, fact, "X");
        const result = m6d.check_no_credentials(refusal(text), 2, host);
        try testing.expectError(error.RefusalWrong, result);
    }
    // The coded first line: its prefix, and the code within it (not only in `more`).
    const prefix = without(&buffer, golden_e0560, "error[ZBX-", "warning[ZBX-");
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(refusal(prefix), 2, host));
    const late = without(&buffer, golden_e0560, "error[ZBX-E0560]", "error[ZBX-E0567]");
    try testing.expect(std.mem.indexOf(u8, late, "E0560") != null);
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(refusal(late), 2, host));
    const printed: m6d.Streams = .{ .stdout = "sha256:", .stderr = golden_e0560 };
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(printed, 2, host));
    const errno = refusal(golden_e0560 ++ "errno 13\n");
    try testing.expectError(error.RefusalWrong, m6d.check_no_credentials(errno, 2, host));
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
    // The digest alone, without the reference.
    const unnamed = "{\"images\":{\"other\":\"" ++ digest ++ "\"}}";
    try testing.expectError(error.DigestWrong, m6d.check_lock(unnamed, reference, digest));
}

test "step 4: zbx's real E0568 passes; the repository or the permission missing is refused" {
    // Goal: as for step 1, on the golden. Method: the golden, then one fact out per row.
    const repository = "zbx-demo/zbx-denied/hello";
    try m6d.check_denied(refusal(golden_e0568), 1, repository);
    try testing.expectError(
        error.ExitCodeWrong,
        m6d.check_denied(refusal(golden_e0568), 2, repository),
    );
    try testing.expectError(
        error.RefusalWrong,
        m6d.check_denied(refusal(golden_e0568), 1, "zbx-demo/zbx-other/hello"),
    );
    var buffer: [2048]u8 = undefined;
    const permission = "artifactregistry.repositories.downloadArtifacts";
    const no_permission = without(&buffer, golden_e0568, permission, "X");
    try testing.expectError(
        error.RefusalWrong,
        m6d.check_denied(refusal(no_permission), 1, repository),
    );
    const other = without(&buffer, golden_e0568, "error[ZBX-E0568]", "error[ZBX-E0569]");
    try testing.expectError(error.RefusalWrong, m6d.check_denied(refusal(other), 1, repository));
}

const agent_digest = "sha256:" ++ hex_a;
const agent_tree = "b3:" ++ hex_c;
const agent_reference = "us-docker.pkg.dev/p/zbx-demo/hello:latest";
const agent_cli: checks_m4.PullDoc = .{
    .schema = "zbx.pull/1",
    .reference = agent_reference,
    .manifest_digest = agent_digest,
    .platform = "linux/amd64",
    .tree = agent_tree,
    .config = .{ .digest = agent_digest, .cache = "downloaded" },
    .layers = &.{},
};

fn agent_json(
    comptime schema: []const u8,
    comptime reference: []const u8,
    comptime digest: []const u8,
    comptime source: []const u8,
) []const u8 {
    return "{\"schema\":\"" ++ schema ++ "\",\"reference\":\"" ++ reference ++
        "\",\"manifest_digest\":\"" ++ digest ++ "\",\"tree\":\"" ++ agent_tree ++
        "\",\"token_source\":\"" ++ source ++ "\"}";
}

test "the agent's JSON matches the command line's pull; each field wrong alone is refused" {
    // Goal: every field the check reads is needed. Method: the good document, then one row per
    // field with that field alone changed.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const schema = "zbx-demo.m6d-agent/1";
    const source = "workload_identity";
    const json = agent_json(schema, agent_reference, agent_digest, source);
    try m6d.check_agent(arena, stdout_only(json), 0, agent_reference, agent_cli);
    const rows = [_]struct { []const u8, anyerror }{
        .{ "pulled " ++ agent_digest, error.JsonWrong },
        .{
            agent_json("zbx-demo.m6d-agent/2", agent_reference, agent_digest, source),
            error.JsonWrong,
        },
        .{
            agent_json(schema, "us-docker.pkg.dev/p/x:latest", agent_digest, source),
            error.JsonWrong,
        },
        .{ agent_json(schema, agent_reference, "sha256:" ++ hex_b, source), error.DigestWrong },
        .{ agent_json(schema, agent_reference, agent_digest, "metadata_server"), error.JsonWrong },
    };
    for (rows) |row| {
        const result = m6d.check_agent(arena, stdout_only(row[0]), 0, agent_reference, agent_cli);
        try testing.expectError(row[1], result);
    }
    var other = agent_cli;
    other.tree = "b3:" ++ hex_d;
    const result = m6d.check_agent(arena, stdout_only(json), 0, agent_reference, other);
    try testing.expectError(error.DigestWrong, result);
    try testing.expectError(
        error.ExitCodeWrong,
        m6d.check_agent(arena, stdout_only(json), 1, agent_reference, agent_cli),
    );
}

/// Throwaway tokens, one of each shape step 5 and the mask know; none was ever issued.
const throwaway_tokens = [_][]const u8{
    "ya29.throwaway-federated-token-0123456789abcdefghij",
    "ya29.c.throwaway-access-token_ABCDEFGHIJKLMNOP-xyz",
    "eyJ0aHJvd2F3YXkiOiIxIn0.eyJzdWIiOiJ0aHJvd2F3YXkifQ.dGhyb3dhd2F5LXNpZw",
    "b2F1dGgyYWNjZXNzdG9rZW46dGhyb3dhd2F5LXRva2Vu",
};

test "the helper's shape lines carry no token shape and no token byte" {
    // Goal: the helper's report of a token is safe to print: the mask leaves it as it is, step 5's
    // search finds nothing in it, and it holds neither the token nor any shape. Method: render the
    // line for throwaway tokens of every shape, as the helper does, and look.
    var line_buffer: [shape.line_bytes_max]u8 = undefined;
    var out: [2 * shape.line_bytes_max]u8 = undefined;
    const scanner = try testing.allocator.create(scan.Scanner);
    defer testing.allocator.destroy(scanner);
    for (throwaway_tokens) |token| {
        const line = shape.shape_line(&line_buffer, "federated", token);
        try testing.expect(std.mem.indexOf(u8, line, token) == null);
        try testing.expect(std.mem.indexOf(u8, line, token[0..5]) == null);
        for (scan.shapes) |prefix| try testing.expect(std.mem.indexOf(u8, line, prefix) == null);
        try testing.expect(std.mem.indexOf(u8, line, "eyJ") == null);
        try testing.expectEqualStrings(line, m6d.mask_secrets(line, &.{token}, &out));
        scanner.* = .{};
        const needles = [_][]const u8{ token, scan.shapes[0], scan.shapes[1] };
        scanner.init(&needles);
        try testing.expectEqual(@as(?scan.Hit, null), scanner.feed(line));
    }
    try testing.expectEqual(shape.Class.google_access, shape.classify(throwaway_tokens[0]));
    try testing.expectEqual(shape.Class.unknown, shape.classify(throwaway_tokens[2]));
    try testing.expectEqual(shape.Class.unknown, shape.classify("ya29."));
}

test "the shape check accepts the helper's lines as the mask shows them, and nothing else" {
    // Goal: the live check passes on what the harness really reads (the helper's output through
    // the mask), and each wrong line fails. Method: render the lines as the helper does, mask
    // them, check; then one wrong row per condition, including the old line that printed `ya29.`.
    var buffers: [2][shape.line_bytes_max]u8 = undefined;
    const federated = shape.shape_line(&buffers[0], "federated", throwaway_tokens[0]);
    const access = shape.shape_line(&buffers[1], "access", throwaway_tokens[1]);
    var joined: [512]u8 = undefined;
    const raw = try std.fmt.bufPrint(&joined, "{s}\n{s}\n", .{ federated, access });
    var out: [1024]u8 = undefined;
    const two = m6d.mask_secrets(raw, &.{}, &out);
    try m6d.check_shapes(stdout_only(two), 0, true);
    const one = federated;
    try m6d.check_shapes(stdout_only(one), 0, false);
    try testing.expectError(error.OutputWrong, m6d.check_shapes(stdout_only(two), 0, false));
    try testing.expectError(error.OutputWrong, m6d.check_shapes(stdout_only(one), 0, true));
    try testing.expectError(error.ExitCodeWrong, m6d.check_shapes(stdout_only(one), 1, false));
    const errors: m6d.Streams = .{ .stdout = one, .stderr = "warning\n" };
    try testing.expectError(error.OutputWrong, m6d.check_shapes(errors, 0, false));
    var old_out: [256]u8 = undefined;
    const old = "shapes: federated token starts with ya29.\n";
    try testing.expectError(error.SecretFound, m6d.check_shapes(stdout_only(old), 0, false));
    const old_masked = m6d.mask_secrets(old, &.{}, &old_out);
    try testing.expectError(error.SecretFound, m6d.check_shapes(stdout_only(old_masked), 0, false));
    // A JWT's start alone is token-shaped too.
    const jwt = "shapes: federated token: google_access, 52 bytes\neyJhbGciOi\n";
    try testing.expectError(error.SecretFound, m6d.check_shapes(stdout_only(jwt), 0, false));
    const wrong = [_][]const u8{
        "shapes: federated token: unknown, 52 bytes",
        "shapes: federated token: google_access, 5 bytes",
        "shapes: federated token: google_access, many bytes",
        "shapes: access token: google_access, 52 bytes",
        "shapes: federated token: not resolved (exchange at sts)",
        // One byte off in the head, then in the tail, with the rest of the line right.
        "shapes: federated token: google_accesz, 52 bytes",
        "shapes: federated token: google_access, 52 bytez",
    };
    for (wrong) |line| {
        try testing.expectError(error.OutputWrong, m6d.check_shapes(stdout_only(line), 0, false));
    }
}

const scan_roots = [_][]const u8{ "/home/demo", "/run/user/1000", "/tmp", "/var/tmp" };
const scan_nonempty = [_][]const u8{ "/home/demo", "/var/tmp" };

fn check_scan(stdout: []const u8, status: u8, needles_min: u32) m6d.Error!void {
    return m6d.check_scan(stdout_only(stdout), status, needles_min, &scan_roots, &scan_nonempty);
}

test "step 5: clean only with enough needles, every root searched, and no hit" {
    // Goal: each condition of the check is needed. Method: the helper's clean report, then one
    // row per condition with that fact alone wrong.
    const roots = "root /home/demo files 40\nroot /run/user/1000 files 0\nroot /tmp files 0\n";
    const clean = "needles 6\n" ++ roots ++ "root /var/tmp files 1\n" ++
        "files 41 bytes 90210 skipped 0\nscan: clean\n";
    try check_scan(clean, 0, 5);
    try check_scan(clean, 0, 6);
    try testing.expectError(error.SecretFound, check_scan(clean, 0, 7));
    try testing.expectError(error.SecretFound, check_scan(clean, 1, 5));
    const no_journal = "needles 6\n" ++ roots ++ "root /var/tmp files 0\nscan: clean\n";
    try testing.expectError(error.SecretFound, check_scan(no_journal, 0, 5));
    const no_tmp = "needles 6\nroot /home/demo files 40\nroot /run/user/1000 files 0\n" ++
        "root /var/tmp files 1\nscan: clean\n";
    try testing.expectError(error.SecretFound, check_scan(no_tmp, 0, 5));
    const unclean = "needles 6\n" ++ roots ++ "root /var/tmp files 1\n";
    try testing.expectError(error.SecretFound, check_scan(unclean, 0, 5));
    const hit = "needles 6\n" ++ roots ++ "root /var/tmp files 1\n" ++
        "HIT /home/demo/x needle=2 offset=7\nscan: clean\n";
    try testing.expectError(error.SecretFound, check_scan(hit, 0, 5));
}

test {
    _ = @import("m6d_fixture/scan.zig");
    _ = @import("m6d_fixture/mask.zig");
    _ = @import("m6d_fixture/shape.zig");
}
