//! A simulated AWS for the tests: the metadata service, STS, the ECR API and S3, behind one
//! `net_sim.Responder`. It is a model with enough teeth to catch the mistakes that matter, not a
//! copy of AWS:
//!
//! - The ECR API checks the SigV4 signature by recomputing it with the signer, for the key it
//!   accepts, and the clock (a request more than five minutes off is refused, as AWS does). This
//!   uses the signer to judge the signer, which is fair only because the signer's own tests check
//!   it against AWS's published answers.
//! - The metadata service, when it is a version 1 one, answers a request that has no session
//!   token with credentials and counts it: a client that falls back to version 1 shows in
//!   `imds_v1_served`.
//! - STS and S3 count a request that carried a signature or any credential they must not get in
//!   `leaked`.
//!
//! Connection failures and timeouts are the net simulator's own faults, not this model's.

const std = @import("std");
const assert = std.debug.assert;
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const parse = @import("parse.zig");
const sigv4 = @import("sigv4.zig");

pub const ImdsMode = enum {
    /// A version 2 service with a role.
    v2,
    /// No token endpoint (it answers 404) but credentials for a request without a token.
    v1_only,
    /// Version 2, and the role list is empty (404).
    no_role,
    /// Version 2, and the credentials document is not JSON.
    malformed,
    /// The service is failing: every call answers 503.
    unavailable,
};

pub const StsMode = enum {
    ok,
    refused,
    malformed,
    expired,
    /// Throttled or failing: 503.
    unavailable,
};

pub const issued_key_id = "ASIAEXAMPLEEXAMPLE1";
pub const issued_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
pub const issued_token = "AQoDYXdzEJr//////////wEXAMPLETOKEN+/=";
pub const imds_token = "AQAEAexampleimdstoken0123456789==";
pub const role_name = "zbx-test-role";
pub const web_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YngifQ.c2lnbmF0dXJl";
/// What the STS answer's message says, to show that no message text is ever repeated.
pub const message_marker = "MESSAGE-MARKER-DO-NOT-PRINT";
pub const ecr_password = "ecr-password-0123456789";
pub const clock_skew_s_max: u64 = 300;

pub const AwsSim = struct {
    /// The time the model believes it is, seconds since the epoch; tests set it from the host
    /// simulator's clock.
    now_s: u64 = 0,
    region: []const u8 = "us-east-1",
    imds: ImdsMode = .v2,
    sts: StsMode = .ok,
    lifetime_s: u64 = 3600,
    /// The key the ECR API accepts.
    accepted_key_id: []const u8 = issued_key_id,
    accepted_secret: []const u8 = issued_secret,
    accepted_token: []const u8 = issued_token,
    sts_calls: u32 = 0,
    imds_calls: u32 = 0,
    imds_v1_served: u32 = 0,
    ecr_calls: u32 = 0,
    ecr_ok: u32 = 0,
    s3_calls: u32 = 0,
    /// Requests that carried a credential to a service that must not get one.
    leaked: u32 = 0,
    /// The form body STS last received, for tests that check it was escaped.
    last_form: [512]u8 = undefined,
    last_form_len: u32 = 0,
    scratch: [2048]u8 = undefined,

    pub fn responder(sim: *AwsSim) net_sim.Responder {
        return .{ .context = sim, .answer = answer };
    }

    fn credentials_json(sim: *AwsSim) []const u8 {
        return credentials_json_of(sim);
    }

    fn print(sim: *AwsSim, comptime format: []const u8, args: anytype) []const u8 {
        return std.fmt.bufPrint(&sim.scratch, format, args) catch unreachable; // scratch is large.
    }
};

fn header_value(request: *const net.Request, name: []const u8) ?[]const u8 {
    for (request.extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const sim: *AwsSim = @ptrCast(@alignCast(context));
    served.* = .{ .status = 404 };
    if (std.mem.eql(u8, request.host, "169.254.169.254")) return imds(sim, request, served);
    if (std.mem.startsWith(u8, request.host, "sts.")) return sts(sim, request, received, served);
    if (std.mem.startsWith(u8, request.host, "api.ecr.")) return ecr_api(sim, request, served);
    if (std.mem.indexOf(u8, request.host, ".s3.") != null) return s3(sim, request, served);
}

fn imds(sim: *AwsSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.imds_calls += 1;
    if (request.proxy != .never) sim.leaked += 1;
    if (sim.imds == .unavailable) {
        served.status = 503;
        return;
    }
    if (request.method == .put) {
        if (sim.imds == .v1_only) return;
        if (header_value(request, "X-aws-ec2-metadata-token-ttl-seconds") == null) {
            served.status = 400;
            return;
        }
        served.* = .{ .status = 200, .body = imds_token };
        return;
    }
    assert(request.method == .get);
    const presented = header_value(request, "X-aws-ec2-metadata-token");
    if (presented == null) {
        if (sim.imds != .v1_only) {
            served.status = 401;
            return;
        }
        sim.imds_v1_served += 1;
    } else if (!std.mem.eql(u8, presented.?, imds_token)) {
        served.status = 401;
        return;
    }
    if (std.mem.eql(u8, request.target, "/latest/meta-data/iam/security-credentials/")) {
        if (sim.imds == .no_role) return;
        served.* = .{ .status = 200, .body = role_name ++ "\n" };
        return;
    }
    const wanted = "/latest/meta-data/iam/security-credentials/" ++ role_name;
    if (!std.mem.eql(u8, request.target, wanted)) return;
    if (sim.imds == .malformed) {
        served.* = .{ .status = 200, .body = "<html>not json</html>" };
        return;
    }
    served.* = .{ .status = 200, .body = sim.credentials_json() };
}

fn format_time(buffer: *[20]u8, seconds: u64) []const u8 {
    const date = sigv4.amz_date_of(seconds);
    return std.fmt.bufPrint(buffer, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        date[0..4], date[4..6], date[6..8], date[9..11], date[11..13], date[13..15],
    }) catch unreachable; // Twenty bytes hold the extended form.
}

fn credentials_json_of(sim: *AwsSim) []const u8 {
    var stamp: [20]u8 = undefined;
    const expiry = format_time(&stamp, sim.now_s + sim.lifetime_s);
    return sim.print(
        "{{\"Code\":\"Success\",\"Type\":\"AWS-HMAC\",\"AccessKeyId\":\"{s}\"," ++
            "\"SecretAccessKey\":\"{s}\",\"Token\":\"{s}\",\"Expiration\":\"{s}\"}}",
        .{ issued_key_id, issued_secret, issued_token, expiry },
    );
}

fn sts(
    sim: *AwsSim,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    sim.sts_calls += 1;
    if (request.authorization.len > 0) sim.leaked += 1;
    if (request.method != .post) return;
    const kept = @min(received.len, sim.last_form.len);
    @memcpy(sim.last_form[0..kept], received[0..kept]);
    sim.last_form_len = @intCast(kept);
    const form_ok = std.mem.indexOf(u8, received, "Action=AssumeRoleWithWebIdentity") != null;
    const token_ok = std.mem.indexOf(u8, received, "WebIdentityToken=" ++ web_token) != null;
    if (!form_ok or !token_ok) {
        served.* = .{ .status = 400, .body = sts_error("InvalidParameterValue") };
        return;
    }
    switch (sim.sts) {
        .unavailable => served.* = .{ .status = 503, .body = "<Error/>" },
        .refused => served.* = .{ .status = 400, .body = sts_error("InvalidIdentityToken") },
        .malformed => served.* = .{ .status = 200, .body = "<Oops/>" },
        .ok, .expired => {
            const lifetime = if (sim.sts == .expired) 0 else sim.lifetime_s;
            var stamp: [20]u8 = undefined;
            const expiry = format_time(&stamp, sim.now_s + lifetime);
            const body = sim.print(
                "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>" ++
                    "<Credentials><AccessKeyId>{s}</AccessKeyId>" ++
                    "<SecretAccessKey>{s}</SecretAccessKey><SessionToken>{s}</SessionToken>" ++
                    "<Expiration>{s}</Expiration></Credentials>" ++
                    "</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>",
                .{ issued_key_id, issued_secret, issued_token, expiry },
            );
            served.* = .{ .status = 200, .body = body };
        },
    }
}

fn sts_error(comptime code: []const u8) []const u8 {
    return "<ErrorResponse><Error><Type>Sender</Type><Code>" ++ code ++ "</Code><Message>" ++
        message_marker ++ "</Message></Error></ErrorResponse>";
}

const api_error_bad_signature =
    "{\"__type\":\"com.amazon.coral.service#UnrecognizedClientException\"," ++
    "\"message\":\"" ++ message_marker ++ "\"}";
const api_error_skew =
    "{\"__type\":\"com.amazon.coral.service#InvalidSignatureException\"," ++
    "\"message\":\"" ++ message_marker ++ "\"}";

/// The ECR API's `GetAuthorizationToken`, signature and clock checked.
fn ecr_api(sim: *AwsSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.ecr_calls += 1;
    const target = header_value(request, "X-Amz-Target") orelse return;
    const expected = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";
    if (request.method != .post or !std.mem.eql(u8, target, expected)) return;
    const date = header_value(request, "X-Amz-Date") orelse {
        served.* = .{ .status = 400, .body = api_error_bad_signature };
        return;
    };
    const signed_at = amz_date_seconds(date) orelse {
        served.* = .{ .status = 400, .body = api_error_bad_signature };
        return;
    };
    const skew = if (signed_at > sim.now_s) signed_at - sim.now_s else sim.now_s - signed_at;
    if (skew > clock_skew_s_max) {
        served.* = .{ .status = 400, .body = api_error_skew };
        return;
    }
    if (!signature_matches(sim, request, signed_at)) {
        served.* = .{ .status = 400, .body = api_error_bad_signature };
        return;
    }
    sim.ecr_ok += 1;
    var encoded: [64]u8 = undefined;
    const plain = "AWS:" ++ ecr_password;
    const token = std.base64.standard.Encoder.encode(&encoded, plain);
    const body = sim.print(
        "{{\"authorizationData\":[{{\"authorizationToken\":\"{s}\",\"expiresAt\":{d}.0E0," ++
            "\"proxyEndpoint\":\"https://x\"}}]}}",
        .{ token, sim.now_s + 12 * 3600 },
    );
    served.* = .{ .status = 200, .body = body };
}

/// `20150830T123600Z` as seconds since the epoch, or null.
fn amz_date_seconds(date: []const u8) ?u64 {
    if (date.len != 16 or date[8] != 'T' or date[15] != 'Z') return null;
    var text: [20]u8 = undefined;
    const extended = std.fmt.bufPrint(&text, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        date[0..4], date[4..6], date[6..8], date[9..11], date[11..13], date[13..15],
    }) catch return null;
    return parse.parse_timestamp(extended);
}

/// Whether the request's `Authorization` is what the signer makes for the accepted key and the
/// headers the signature says it covers.
fn signature_matches(sim: *AwsSim, request: *const net.Request, signed_at: u64) bool {
    const token = header_value(request, "X-Amz-Security-Token") orelse "";
    if (!std.mem.eql(u8, token, sim.accepted_token)) return false;
    const text = request.authorization;
    const marker = "SignedHeaders=";
    const start = std.mem.indexOf(u8, text, marker) orelse return false;
    const list_start = start + marker.len;
    const list_end = std.mem.indexOfPos(u8, text, list_start, ",") orelse return false;
    var headers: [8]net.Header = undefined;
    var count: u32 = 0;
    var names = std.mem.splitScalar(u8, text[list_start..list_end], ';');
    while (names.next()) |name| {
        if (std.mem.eql(u8, name, "x-amz-date")) continue;
        if (std.mem.eql(u8, name, "x-amz-security-token")) continue;
        if (count == headers.len) return false;
        const value = if (std.mem.eql(u8, name, "host"))
            request.host
        else if (std.mem.eql(u8, name, "content-type"))
            request.content_type
        else
            header_value(request, name) orelse return false;
        headers[count] = .{ .name = name, .value = value };
        count += 1;
    }
    var workspace: sigv4.Workspace = undefined;
    var signed: sigv4.Signed = undefined;
    sigv4.sign(&.{
        .method = request.method,
        .target = request.target,
        .headers = headers[0..count],
        .body = "{}",
        .scope = .{ .region = sim.region, .service = "ecr" },
        .key = .{
            .access_key_id = sim.accepted_key_id,
            .secret_access_key = sim.accepted_secret,
            .session_token = sim.accepted_token,
        },
        .now_s = signed_at,
    }, &workspace, &signed) catch return false;
    return std.mem.eql(u8, signed.authorization_text(), request.authorization);
}

/// S3 takes no `Authorization` on a blob request: a pre-signed URL says everything, and a header
/// on top of it is refused, as S3 does.
fn s3(sim: *AwsSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.s3_calls += 1;
    const sent = request.bearer.len + request.basic.len + request.authorization.len;
    if (sent > 0) {
        sim.leaked += 1;
        served.* = .{
            .status = 400,
            .body = "<Error><Code>InvalidArgument</Code><Message>" ++ message_marker ++
                "</Message></Error>",
        };
        return;
    }
    served.* = .{ .status = 200, .body = "blob" };
}
