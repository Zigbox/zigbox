//! Tests of `parse.zig`: the credentials file and each of its refusals, the subject token
//! formats, the three token answers and the three error shapes. Every token here is a fixed fake.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const parse = @import("parse.zig");

pub const audience = "//iam.googleapis.com/projects/123456789012/locations/global/" ++
    "workloadIdentityPools/zbx-pool/providers/github";
pub const service_account = "zbx-pull@zbx-demo.iam.gserviceaccount.com";
pub const impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/" ++
    "serviceAccounts/" ++ service_account ++ ":generateAccessToken";

/// A file-sourced account as the demo writes it, with impersonation.
pub const file_account =
    \\{
    \\  "universe_domain": "googleapis.com",
    \\  "type": "external_account",
    \\  "audience": "
++ audience ++
    \\",
    \\  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    \\  "token_url": "https://sts.googleapis.com/v1/token",
    \\  "service_account_impersonation_url": "
++ impersonation_url ++
    \\",
    \\  "credential_source": {"file": "/run/zbx/oidc-token", "format": {"type": "text"}}
    \\}
;

/// A URL-sourced account as `google-github-actions/auth` writes it, without impersonation.
pub const url_account =
    \\{"type":"external_account","audience":"
++ audience ++
    \\","subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
    \\"token_url":"https://sts.googleapis.com/v1/token",
    \\"credential_source":{"url":"https://tokens.example.com/oidc?audience=x",
    \\"headers":{"Authorization":"Bearer fake-runner-request-token-0001"},
    \\"format":{"type":"json","subject_token_field_name":"value"}}}
;

test "a file-sourced account with impersonation is read whole" {
    // Goal: every field the exchange needs comes out, and the impersonated email is named.
    const parsed = parse.parse_credentials(file_account);
    const account = parsed.account;
    try testing.expectEqualStrings(audience, account.audience);
    const jwt_type = "urn:ietf:params:oauth:token-type:jwt";
    try testing.expectEqualStrings(jwt_type, account.subject_token_type);
    try testing.expectEqual(parse.SourceKind.file, account.source);
    try testing.expectEqualStrings("/run/zbx/oidc-token", account.location);
    try testing.expectEqualStrings("", account.json_field);
    try testing.expectEqualStrings(service_account, account.service_account);
    try testing.expectEqualStrings(impersonation_url, account.impersonation_url);
}

test "a URL-sourced account keeps its headers and JSON field" {
    // Goal: the URL, the header that carries the runner's token and the field name are read.
    const account = parse.parse_credentials(url_account).account;
    try testing.expectEqual(parse.SourceKind.url, account.source);
    try testing.expectEqualStrings("value", account.json_field);
    try testing.expectEqual(@as(usize, 1), account.source_headers().len);
    try testing.expectEqualStrings("Authorization", account.source_headers()[0].name);
    try testing.expectEqualStrings("", account.impersonation_url);
}

fn expect_refused(text: []const u8, reason: parse.Refusal) !void {
    const parsed = parse.parse_credentials(text);
    try testing.expectEqual(reason, parsed.refused.reason);
}

fn swapped(from: []const u8, to: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, testing.allocator, file_account, from, to);
}

const RefusalCase = struct { from: []const u8, to: []const u8, reason: parse.Refusal };

/// Each swap turns the good file into one the brief refuses, for the reason named.
const refusal_cases = [_]RefusalCase{
    .{
        .from = "https://sts.googleapis.com/v1/token",
        .to = "https://sts.example.com/v1/token",
        .reason = .token_url,
    },
    .{ .from = "\"googleapis.com\"", .to = "\"example.com\"", .reason = .universe_domain },
    .{
        .from = "iamcredentials.googleapis.com",
        .to = "iam.example.com",
        .reason = .impersonation_url,
    },
    .{ .from = ":generateAccessToken", .to = ":generateIdToken", .reason = .impersonation_url },
    .{
        .from = "projects/123456789012/locations/global/workloadIdentityPools",
        .to = "locations/global/workforcePools",
        .reason = .workforce_pool,
    },
    .{
        .from = "\"file\": \"/run/zbx/oidc-token\"",
        .to = "\"executable\": {\"command\": \"x\"}",
        .reason = .executable,
    },
    .{
        .from = "\"file\": \"/run/zbx/oidc-token\"",
        .to = "\"environment_id\": \"aws1\"",
        .reason = .aws,
    },
    .{
        .from = "\"file\": \"/run/zbx/oidc-token\"",
        .to = "\"certificate\": {}",
        .reason = .certificate,
    },
    .{
        .from = "\"file\": \"/run/zbx/oidc-token\"",
        .to = "\"url\": \"http://169.254.169.254/metadata/identity\"",
        .reason = .plain_http_url,
    },
    .{ .from = "\"file\": \"/run/zbx/oidc-token\", ", .to = "", .reason = .no_source },
    .{
        .from = "\"file\": \"/run/zbx/oidc-token\"",
        .to = "\"file\": \"/a\", \"url\": \"https://x\"",
        .reason = .no_source,
    },
    .{
        .from = "\"universe_domain\"",
        .to = "\"workforce_pool_user_project\"",
        .reason = .workforce_pool,
    },
    .{ .from = "\"audience\"", .to = "\"audiences\"", .reason = .malformed },
    .{ .from = "\"type\": \"text\"", .to = "\"type\": \"xml\"", .reason = .malformed },
    .{
        .from = "\"type\": \"external_account\",",
        .to = "\"type\": \"external_account\", \"type\": \"x\",",
        .reason = .malformed,
    },
    .{ .from = "/run/zbx/oidc-token", .to = "/run/zbx/oidc\\u002dtoken", .reason = .malformed },
};

test "each unsupported credentials file is refused with its own reason" {
    // Goal: a key file, gcloud's user credentials, another type and every unsupported
    // `external_account` shape the brief lists each give their reason, so the user is told
    // what to change; a type that is not a plain name is not shown back.
    const key_file = "{\"type\":\"service_account\",\"private_key\":\"-----\"}";
    try expect_refused(key_file, .service_account_key);
    try expect_refused("{\"type\":\"authorized_user\",\"refresh_token\":\"x\"}", .authorized_user);
    const other = parse.parse_credentials("{\"type\":\"impersonated_service_account\"}");
    try testing.expectEqualStrings("impersonated_service_account", other.refused.type_name);
    const odd = parse.parse_credentials("{\"type\":\"Odd Type\"}");
    try testing.expectEqualStrings("", odd.refused.type_name);
    try expect_refused("{}", .malformed);
    try expect_refused("not json", .malformed);
    for (refusal_cases) |case| {
        const changed = try swapped(case.from, case.to);
        defer testing.allocator.free(changed);
        try expect_refused(changed, case.reason);
    }
}

test "a URL source's headers are bounded and checked" {
    // Goal: more headers than the bound, a reserved header name or a header on a file source is
    // malformed; a plain-HTTP URL is its own refusal.
    const head = "{\"type\":\"external_account\",\"audience\":\"a\",";
    const many = head ++ "\"subject_token_type\":\"t\"," ++
        "\"credential_source\":{\"url\":\"https://x/t\",\"headers\":{\"a\":\"1\",\"b\":\"2\"," ++
        "\"c\":\"3\",\"d\":\"4\",\"e\":\"5\"}}}";
    comptime std.debug.assert(constants.google_source_headers_max == 4);
    try expect_refused(many, .malformed);
    const reserved = head ++ "\"subject_token_type\":\"t\"," ++
        "\"credential_source\":{\"url\":\"https://x/t\",\"headers\":{\"Host\":\"y\"}}}";
    try expect_refused(reserved, .malformed);
    const on_file = head ++ "\"subject_token_type\":\"t\"," ++
        "\"credential_source\":{\"file\":\"/t\",\"headers\":{\"a\":\"1\"}}}";
    try expect_refused(on_file, .malformed);
}

test "subject tokens in text and JSON" {
    // Goal: a text token loses its trailing line end; a JSON token is its named member; an empty
    // or blank-holding token is refused.
    const text_token = "eyJhbGciOi.fake.sig";
    try testing.expectEqualStrings(text_token, try parse.subject_text(text_token ++ "\n"));
    try testing.expectError(error.Malformed, parse.subject_text("\n"));
    try testing.expectError(error.Malformed, parse.subject_text("a b"));
    const json_token = "{\"count\":1,\"value\":\"eyJ.fake\"}";
    try testing.expectEqualStrings("eyJ.fake", try parse.subject_json(json_token, "value"));
    try testing.expectError(error.Malformed, parse.subject_json("{\"value\":1}", "value"));
    try testing.expectError(error.Malformed, parse.subject_json("{\"other\":\"x\"}", "value"));
}

pub const sts_answer = "{\"access_token\":\"ya29.fake-federated-token-0001\"," ++
    "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"," ++
    "\"token_type\":\"Bearer\",\"expires_in\":3599}";
pub const iam_answer = "{\n  \"accessToken\": \"ya29.fake-impersonated-token-0001\",\n" ++
    "  \"expireTime\": \"2026-11-16T13:00:00Z\"\n}";
pub const metadata_answer = "{\"access_token\":\"ya29.fake-metadata-token-0001\"," ++
    "\"expires_in\":3599,\"token_type\":\"Bearer\"}";

test "the three token answers" {
    // Goal: STS and the metadata server give a token and a lifetime in seconds; IAM Credentials
    // gives a token and an absolute expiry.
    const sts = try parse.parse_token_answer(sts_answer);
    try testing.expectEqualStrings("ya29.fake-federated-token-0001", sts.token);
    try testing.expectEqual(@as(u64, 3599), sts.expires);
    try testing.expect(sts.relative);
    const iam = try parse.parse_impersonation(iam_answer);
    try testing.expectEqualStrings("ya29.fake-impersonated-token-0001", iam.token);
    try testing.expect(!iam.relative);
    try testing.expectEqual(@as(u64, 1_794_834_000), iam.expires);
    _ = try parse.parse_token_answer(metadata_answer);
}

test "a token answer wrong in any one way is refused" {
    // Goal: a missing or zero lifetime, a lifetime past the bound, a token with a blank, an
    // escaped token, and a short token are each `Malformed`.
    const bad = [_][]const u8{
        "{\"access_token\":\"ya29.fake-federated-token-0001\"}",
        "{\"access_token\":\"ya29.fake-federated-token-0001\",\"expires_in\":0}",
        "{\"access_token\":\"ya29.fake-federated-token-0001\",\"expires_in\":99999}",
        "{\"access_token\":\"ya29.fake federated-token\",\"expires_in\":3599}",
        "{\"access_token\":\"ya29.fake\\u002dfederated-token\",\"expires_in\":3599}",
        "{\"access_token\":\"ya29.x\",\"expires_in\":3599}",
        "{\"access_token\":\"ya29.fake-federated-token-0001\",\"expires_in\":\"3599\"}",
    };
    for (bad) |body| {
        try testing.expectError(error.Malformed, parse.parse_token_answer(body));
    }
    try testing.expectError(error.Malformed, parse.parse_impersonation(
        "{\"accessToken\":\"ya29.fake-impersonated-token-0001\",\"expireTime\":\"soon\"}",
    ));
}

test "error codes from each of Google's shapes, and never a message" {
    // Goal: STS's, IAM's and the registry's codes come out; a code with other characters, a
    // message alone or a body that is not JSON gives nothing.
    try testing.expectEqualStrings("invalid_grant", parse.error_code(
        "{\"error\":\"invalid_grant\",\"error_description\":\"secret words\"}",
    ).?);
    try testing.expectEqualStrings("PERMISSION_DENIED", parse.error_code(
        "{\"error\":{\"code\":403,\"message\":\"secret words\",\"status\":\"PERMISSION_DENIED\"}}",
    ).?);
    try testing.expectEqualStrings("DENIED", parse.error_code(
        "{\"errors\":[{\"code\":\"DENIED\",\"message\":\"secret words\"}]}",
    ).?);
    try testing.expect(parse.error_code("{\"error\":\"bad code\"}") == null);
    try testing.expect(parse.error_code("{\"message\":\"secret words\"}") == null);
    try testing.expect(parse.error_code("<html>") == null);
    try testing.expect(parse.error_code("{\"errors\":[]}") == null);
}

test "impersonation URLs and emails" {
    // Goal: only the exact `generateAccessToken` URL names an account, and the email is checked.
    const named = parse.impersonated_account(impersonation_url).?;
    try testing.expectEqualStrings(service_account, named);
    try testing.expect(parse.impersonated_account(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/:generateAccessToken",
    ) == null);
    try testing.expect(parse.impersonated_account(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" ++
            "a/b@c:generateAccessToken",
    ) == null);
    try testing.expect(!parse.email_valid("a@b@c"));
    try testing.expect(!parse.email_valid("@b.c"));
}

test "each parse bound holds at its value and refuses one past it" {
    // Goal: an access token, a subject token and a credentials-file field are each accepted at
    // exactly their bound and refused one byte past it.
    const access_max = constants.google_access_token_bytes_max;
    var access: [access_max + 1]u8 = undefined;
    @memset(&access, 'a');
    try testing.expect(parse.access_token_valid(access[0..access_max]));
    try testing.expect(!parse.access_token_valid(access[0 .. access_max + 1]));
    const subject_max = constants.google_subject_token_bytes_max;
    var subject: [subject_max + 1]u8 = undefined;
    @memset(&subject, 's');
    const at_bound = try parse.subject_text(subject[0..subject_max]);
    try testing.expectEqual(subject_max, at_bound.len);
    try testing.expectError(error.Malformed, parse.subject_text(subject[0 .. subject_max + 1]));
    const field_max = constants.google_field_bytes_max;
    var field: [field_max + 1]u8 = undefined;
    @memset(&field, 'f');
    const long_at = try swapped(audience, field[0..field_max]);
    defer testing.allocator.free(long_at);
    try testing.expectEqual(field_max, parse.parse_credentials(long_at).account.audience.len);
    const long_past = try swapped(audience, field[0 .. field_max + 1]);
    defer testing.allocator.free(long_past);
    try expect_refused(long_past, .malformed);
}

test "a source header named twice, in any case, is refused" {
    // Goal: `Authorization` and `authorization` are one header; sending both would let the
    // server pick one, so the file is malformed.
    const twice = "{\"type\":\"external_account\",\"audience\":\"a\"," ++
        "\"subject_token_type\":\"t\",\"credential_source\":{\"url\":\"https://x/t\"," ++
        "\"headers\":{\"Authorization\":\"Bearer a\",\"authorization\":\"Bearer b\"}}}";
    try expect_refused(twice, .malformed);
    const once = "{\"type\":\"external_account\",\"audience\":\"a\"," ++
        "\"subject_token_type\":\"t\",\"credential_source\":{\"url\":\"https://x/t\"," ++
        "\"headers\":{\"Authorization\":\"Bearer a\",\"X-Other\":\"b\"}}}";
    const account = parse.parse_credentials(once).account;
    try testing.expectEqual(@as(usize, 2), account.source_headers().len);
}
