//! The ECR `GetAuthorizationToken` call (M6c, slice 2):
//! `POST https://api.ecr.<region>.amazonaws.com/` signed with SigV4 for the service `ecr`. The
//! `authorizationToken` it returns is already the base64 of `AWS:<password>`, so it is sent as it
//! is, as `Authorization: Basic <token>`, to the registry's own origin and to nothing else
//! (`registry/client.zig` holds that rule).
//!
//! Everything secret lives in buffers the caller gave and owns: the answer in `response`, the
//! token in `token_out`. This function zeroes `response` on every path and the caller zeroes
//! `token_out` when the pull ends. A failure carries the status and the AWS error code name and
//! nothing else of the answer: never its message, never its body.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const net = @import("../registry/net.zig");
const parse = @import("parse.zig");
const sigv4 = @import("sigv4.zig");
const ecr = @import("ecr.zig");

/// The ECR API's host is `api.ecr.<region>`; the service the signature is scoped to is `ecr`.
pub const api_service = "api.ecr";
pub const target_name = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";
const content_type = "application/x-amz-json-1.1";

/// What went wrong, in the terms the diagnostics need.
pub const Kind = enum {
    /// The call did not complete: `Failure.net_error` says how.
    network,
    /// The request was signed at a time AWS is too far from: the host clock is likely wrong.
    skew,
    /// AWS does not accept the credentials (expired, unknown key, wrong secret).
    credentials,
    /// The credentials are fine and the identity may not call `ecr:GetAuthorizationToken`.
    denied,
    /// Any other status (throttling, a 5xx): `Failure.status` says which.
    status,
    /// A 200 that is not an authorization token.
    malformed,
};

pub const Failure = struct {
    kind: Kind = .status,
    status: u16 = 0,
    net_error: net.Error = error.IoFailed,
    code_bytes: [constants.aws_error_code_bytes_max]u8 = undefined,
    code_len: u32 = 0,

    /// The AWS error code name (`AccessDeniedException`), empty when the answer had none.
    pub fn code(failure: *const Failure) []const u8 {
        assert(failure.code_len <= failure.code_bytes.len);
        return failure.code_bytes[0..failure.code_len];
    }
};

pub const Error = error{Failed};

/// Whether the host would call the answer a clock problem: AWS says "Signature expired" or
/// "not yet current" in its message when the request's time is off. The message is read for this
/// and nowhere else; it is never kept or shown.
pub fn mentions_skew(body: []const u8) bool {
    assert(body.len <= constants.aws_response_bytes_max);
    const words = [_][]const u8{ "Signature expired", "not yet current", "Request has expired" };
    for (words) |word| {
        if (std.ascii.findIgnoreCase(body, word) != null) return true;
    }
    return false;
}

/// Sorts a refusal by what the user can do about it.
pub fn classify(status: u16, body: []const u8, code: []const u8) Kind {
    assert(status >= 100);
    assert(status <= 599);
    if (mentions_skew(body)) return .skew;
    if (status == 400 or status == 401 or status == 403) {
        if (std.mem.eql(u8, code, "AccessDeniedException")) return .denied;
        if (std.mem.eql(u8, code, "ExpiredTokenException")) return .credentials;
        if (std.mem.eql(u8, code, "UnrecognizedClientException")) return .credentials;
        if (std.mem.eql(u8, code, "InvalidClientTokenId")) return .credentials;
        if (std.mem.eql(u8, code, "InvalidSignatureException")) return .credentials;
        if (std.mem.eql(u8, code, "SignatureDoesNotMatch")) return .credentials;
        if (std.mem.eql(u8, code, "IncompleteSignature")) return .credentials;
        if (std.mem.eql(u8, code, "MissingAuthenticationToken")) return .credentials;
        if (std.mem.eql(u8, code, "InvalidIdentityToken")) return .credentials;
    }
    return .status;
}

/// Asks ECR in `region` for an authorization token with `key`, signed at `now_s`; the base64 text
/// goes to the front of `token_out` and its length is returned. `response` holds the answer and
/// is zeroed before this returns.
pub fn fetch(
    host: host_mod.Host,
    region: []const u8,
    key: sigv4.Key,
    now_s: u64,
    response: []u8,
    token_out: []u8,
    failure: *Failure,
) Error!u32 {
    assert(response.len >= constants.aws_ecr_token_bytes_max * 2);
    assert(token_out.len >= constants.aws_ecr_token_bytes_max);
    defer std.crypto.secureZero(u8, response);
    failure.* = .{};
    var host_buffer: [constants.aws_service_bytes_max + constants.aws_region_bytes_max + 15]u8 =
        undefined;
    const api_host = ecr.service_host(&host_buffer, api_service, region);
    var workspace: sigv4.Workspace = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&workspace));
    var signed: sigv4.Signed = undefined;
    defer signed.wipe();
    sigv4.sign(&.{
        .method = .post,
        .target = "/",
        .headers = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "host", .value = api_host },
            .{ .name = "x-amz-target", .value = target_name },
        },
        .body = "{}",
        .scope = .{ .region = region, .service = "ecr" },
        .key = key,
        .now_s = now_s,
    }, &workspace, &signed) catch {
        // The inputs were checked by the caller; a signer refusal is a bug.
        failure.kind = .malformed;
        return error.Failed;
    };
    return exchange(host, api_host, &signed, key, response, token_out, failure);
}

/// Sends the signed request and reads the token out of the answer.
fn exchange(
    host: host_mod.Host,
    api_host: []const u8,
    signed: *const sigv4.Signed,
    key: sigv4.Key,
    response: []u8,
    token_out: []u8,
    failure: *Failure,
) Error!u32 {
    assert(response.len >= constants.aws_ecr_token_bytes_max * 2);
    assert(token_out.len >= constants.aws_ecr_token_bytes_max);
    var source: net.SliceSource = .{ .bytes = "{}" };
    var sink: net.BufferSink = .{ .buffer = response };
    var head: net.Head = .{};
    const headers = [_]net.Header{
        .{ .name = "X-Amz-Target", .value = target_name },
        .{ .name = "X-Amz-Date", .value = &signed.amz_date },
        .{ .name = "X-Amz-Security-Token", .value = key.session_token, .secret = true },
    };
    const header_count: usize = if (key.session_token.len > 0) 3 else 2;
    const request: net.Request = .{
        .scheme = .https,
        .host = api_host,
        .port = 443,
        .target = "/",
        .accept = "application/json",
        .bearer = "",
        .body_bytes_max = response.len,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = .post,
        .body = source.body(),
        .content_type = content_type,
        .authorization = signed.authorization_text(),
        .secret = true, // The answer is an authorization token.
        .extra_headers = headers[0..header_count],
    };
    host.network().call(&request, &head, sink.sink()) catch |err| {
        failure.kind = .network;
        failure.net_error = err;
        return error.Failed;
    };
    failure.status = head.status;
    if (head.status != 200) {
        const found = parse.error_code(sink.bytes()) orelse "";
        @memcpy(failure.code_bytes[0..found.len], found);
        failure.code_len = @intCast(found.len);
        failure.kind = classify(head.status, sink.bytes(), found);
        return error.Failed;
    }
    const token = parse.parse_ecr_token(sink.bytes()) catch {
        failure.kind = .malformed;
        return error.Failed;
    };
    assert(token.basic.len <= token_out.len);
    @memcpy(token_out[0..token.basic.len], token.basic);
    return @intCast(token.basic.len);
}
