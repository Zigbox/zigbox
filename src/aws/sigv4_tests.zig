//! Known-answer and boundary tests for `sigv4.zig`. The known answers are the published ones of
//! AWS's SigV4 documentation and its `aws-sig-v4-test-suite` (access key `AKIDEXAMPLE`, secret
//! `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, time `20150830T123600Z`); they come from outside
//! this code, which is why they can show the signer is right.

const std = @import("std");
const testing = std.testing;
const sigv4 = @import("sigv4.zig");
const net = @import("../registry/net.zig");

const example_key: sigv4.Key = .{
    .access_key_id = "AKIDEXAMPLE",
    .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    .session_token = "",
};
const form_charset = "application/x-www-form-urlencoded; charset=utf-8";
const example_time_s: u64 = 1440938160; // 20150830T123600Z

fn expect_signature(
    method: net.Method,
    target: []const u8,
    headers: []const net.Header,
    body: []const u8,
    scope: sigv4.Scope,
    expected_signature: []const u8,
) !void {
    var workspace: sigv4.Workspace = undefined;
    var signed: sigv4.Signed = undefined;
    try sigv4.sign(&.{
        .method = method,
        .target = target,
        .headers = headers,
        .body = body,
        .scope = scope,
        .key = example_key,
        .now_s = example_time_s,
    }, &workspace, &signed);
    const text = signed.authorization_text();
    if (!std.mem.endsWith(u8, text, expected_signature)) {
        std.debug.print("signature mismatch for {s}: got {s}\n", .{ target, text });
        return error.TestExpectedEqual;
    }
    try testing.expect(std.mem.indexOf(u8, text, "Credential=AKIDEXAMPLE/20150830/") != null);
}

// Goal: the date and the signing key match the documentation's values.
// Method: compute both from the example inputs and compare with the published hex.
test "the date text and the signing key are the published ones" {
    try testing.expectEqualStrings("20150830T123600Z", &sigv4.amz_date_of(example_time_s));
    try testing.expectEqualStrings("19700101T000000Z", &sigv4.amz_date_of(0));
    const key = sigv4.signing_key(
        example_key.secret_access_key,
        "20150830",
        .{ .region = "us-east-1", .service = "iam" },
    );
    try testing.expectEqualStrings(
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
        &std.fmt.bytesToHex(key, .lower),
    );
}

// Goal: the IAM ListUsers example of the AWS documentation signs to its published signature.
test "the documentation's iam ListUsers request" {
    try expect_signature(
        .get,
        "/?Action=ListUsers&Version=2010-05-08",
        &.{
            .{ .name = "content-type", .value = form_charset },
            .{ .name = "host", .value = "iam.amazonaws.com" },
        },
        "",
        .{ .region = "us-east-1", .service = "iam" },
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
}

// Goal: the test suite's simplest request, then its query ordering, form post and header ordering.
test "the aws-sig-v4-test-suite requests" {
    const scope: sigv4.Scope = .{ .region = "us-east-1", .service = "service" };
    const host: net.Header = .{ .name = "Host", .value = "example.amazonaws.com" };
    const vanilla = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    try expect_signature(.get, "/", &.{host}, "", scope, vanilla);
    const query_order = "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500";
    try expect_signature(.get, "/?Param2=value2&Param1=value1", &.{host}, "", scope, query_order);
    try expect_signature(
        .post,
        "/",
        &.{
            host,
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
        },
        "Param1=value1",
        scope,
        "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
    );
}

// Goal: a repeated header, a header the signer adds, a path with a dot segment and a target
// with too many query parameters are refused, never signed as given.
test "what the signer refuses" {
    var workspace: sigv4.Workspace = undefined;
    var signed: sigv4.Signed = undefined;
    const host: net.Header = .{ .name = "host", .value = "example.amazonaws.com" };
    const base: sigv4.Input = .{
        .method = .get,
        .target = "/",
        .headers = &.{host},
        .body = "",
        .scope = .{ .region = "us-east-1", .service = "ecr" },
        .key = example_key,
        .now_s = example_time_s,
    };
    var input = base;
    input.headers = &.{ host, .{ .name = "Host", .value = "other" } };
    try testing.expectError(error.BadHeader, sigv4.sign(&input, &workspace, &signed));
    input.headers = &.{ host, .{ .name = "x-amz-date", .value = "x" } };
    try testing.expectError(error.BadHeader, sigv4.sign(&input, &workspace, &signed));
    input = base;
    input.target = "/a/../b";
    try testing.expectError(error.BadTarget, sigv4.sign(&input, &workspace, &signed));
    input.target = "/a//b";
    try testing.expectError(error.BadTarget, sigv4.sign(&input, &workspace, &signed));
    input.target = "a";
    try testing.expectError(error.BadTarget, sigv4.sign(&input, &workspace, &signed));
    input.target = "/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=0&k=1&l=2&m=3&n=4&o=5&p=6&q=7";
    try testing.expectError(error.BadTarget, sigv4.sign(&input, &workspace, &signed));
    input = base;
    try sigv4.sign(&input, &workspace, &signed);
}

// Goal: a temporary key's token is signed and listed, and the workspace is zero afterwards.
test "a session token is covered and the workspace is wiped" {
    var workspace: sigv4.Workspace = undefined;
    var signed: sigv4.Signed = undefined;
    var key = example_key;
    key.session_token = "TOKEN+/=";
    try sigv4.sign(&.{
        .method = .post,
        .target = "/",
        .headers = &.{.{ .name = "host", .value = "api.ecr.us-east-1.amazonaws.com" }},
        .body = "{}",
        .scope = .{ .region = "us-east-1", .service = "ecr" },
        .key = key,
        .now_s = example_time_s,
    }, &workspace, &signed);
    try testing.expect(std.mem.indexOf(
        u8,
        signed.authorization_text(),
        "SignedHeaders=host;x-amz-date;x-amz-security-token,",
    ) != null);
    for (workspace.canonical) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (workspace.query) |byte| try testing.expectEqual(@as(u8, 0), byte);
    signed.wipe();
    try testing.expectEqual(@as(u32, 0), signed.authorization_len);
}

// Goal: the percent-encoding rules: query decoded and re-encoded once, path encoded again.
test "query and path encoding" {
    var workspace: sigv4.Workspace = undefined;
    const canonical = try sigv4.canonical_request(&.{
        .method = .get,
        .target = "/a%20b/c?x=a+b&x=%7e&A=%2f",
        .headers = &.{.{ .name = "host", .value = "h" }},
        .body = "",
        .scope = .{ .region = "r", .service = "s" },
        .key = example_key,
        .now_s = example_time_s,
    }, "20150830T123600Z", &workspace);
    try testing.expect(std.mem.startsWith(
        u8,
        canonical.text,
        "GET\n/a%2520b/c\nA=%2F&x=a%2Bb&x=~\n",
    ));
}
