//! The ECR step of a pull's resolve (M6c, slice 2): for a reference on a private Amazon ECR host,
//! ask ECR for an authorization token with the AWS credentials the caller gave, and keep it in the
//! client's workspace to be sent as `Basic` to the registry's own origin. For any other host this
//! does nothing, and public pulls are exactly what they were.
//!
//! Credentials are never looked for here: the caller resolves them (`pull_aws.zig`, or
//! `aws_credentials_resolve` for the library) once per pull, and they are not kept.

const std = @import("std");
const assert = std.debug.assert;
const aws_diagnose = @import("../aws/diagnose.zig");
const client_mod = @import("client.zig");
const constants = @import("../constants.zig");
const credentials_mod = @import("../aws/credentials.zig");
const diagnose = @import("diagnose.zig");
const ecr = @import("../aws/ecr.zig");
const ecr_token = @import("../aws/ecr_token.zig");
const host_mod = @import("../host.zig");
const net = @import("net.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const Error = error{Failed};

/// Gives `client` the ECR authorization token for `registry` when it is a private ECR host.
/// A host that is ECR of a kind zbx does not sign for, or a private one with no credentials given,
/// is a coded refusal; any other host is left alone.
pub fn login(
    host: host_mod.Host,
    aws: ?*const credentials_mod.Credentials,
    registry: []const u8,
    client: *client_mod.Client,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(client.basic_len == 0);
    const private = switch (ecr.classify(registry)) {
        .other, .public => return,
        .unsupported => {
            aws_diagnose.unsupported_host(diag, registry);
            return error.Failed;
        },
        .private => |found| found,
    };
    const given = aws orelse {
        aws_diagnose.none_given(diag, registry);
        return error.Failed;
    };
    try ask(host, given, private.region, client, diag);
    assert(client.basic_len > 0);
}

/// Asks the ECR API of `region`; the token ends in the client's `basic`.
fn ask(
    host: host_mod.Host,
    aws: *const credentials_mod.Credentials,
    region: []const u8,
    client: *client_mod.Client,
    diag: *Diag,
) Error!void {
    assert(region.len > 0);
    assert(constants.aws_response_bytes_max <= constants.registry_token_response_bytes_max);
    var failure: ecr_token.Failure = undefined;
    const response = client.workspace.token_body[0..constants.aws_response_bytes_max];
    const now_s = host.time_now();
    const length = ecr_token.fetch(
        host,
        region,
        aws.key(),
        now_s,
        response,
        &client.workspace.basic,
        &failure,
    ) catch {
        failed(host, aws, region, &failure, diag);
        return error.Failed;
    };
    assert(length > 0);
    client.basic_len = length;
}

fn failed(
    host: host_mod.Host,
    aws: *const credentials_mod.Credentials,
    region: []const u8,
    failure: *const ecr_token.Failure,
    diag: *Diag,
) void {
    assert(diag.code == null);
    var host_buffer: [constants.aws_service_bytes_max + constants.aws_region_bytes_max + 15]u8 =
        undefined;
    const api_host = ecr.service_host(&host_buffer, ecr_token.api_service, region);
    switch (failure.kind) {
        .network => {
            const target: diagnose.Target = .{ .host = api_host, .port = 443, .scheme = .https };
            diagnose.network_failed(diag, failure.net_error, target, host.network().last_errno());
        },
        .skew => aws_diagnose.clock_skew(diag, api_host),
        .credentials => {
            aws_diagnose.refused(diag, aws.source, failure.status, failure.code());
        },
        .denied => aws_diagnose.token_denied(diag, failure.code()),
        .status, .malformed => {
            var url: [constants.registry_url_bytes_max]u8 = undefined;
            const text = std.fmt.bufPrint(&url, "https://{s}/", .{api_host}) catch "https://ecr/";
            const status = if (failure.status >= 100) failure.status else 200;
            const note: ?[]const u8 = if (failure.kind == .malformed)
                "an answer that is not an authorization token"
            else
                null;
            diagnose.http_error(diag, status, text, note);
        },
    }
    assert(diag.code != null);
}
