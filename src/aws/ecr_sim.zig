//! A simulated Amazon ECR for the tests: the AWS model (`aws_sim.zig`: metadata service, STS, the
//! ECR API), a registry on an ECR host that takes only the Basic token the API issued, and an S3
//! host the registry redirects blobs to. Like the real S3, the S3 host refuses a request that
//! carries any credential and counts it in `leaked`, so a client that forwards the token across the
//! redirect shows at once.
//!
//! The registry answers as ECR does: 401 for a missing or wrong token, 403 `DENIED` for a
//! repository the identity may not read, 404 `NAME_UNKNOWN` for one that does not exist.

const std = @import("std");
const assert = std.debug.assert;
const aws_sim = @import("aws_sim.zig");
const fixture_mod = @import("../testing/vm/registry_fixture.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");

pub const ecr_host = "123456789012.dkr.ecr.us-east-1.amazonaws.com";
pub const s3_host = "zbx-layers.s3.us-east-1.amazonaws.com";
/// The repository of the fixture's `cdn` scenario: its blobs are redirected to the S3 host.
pub const reference = ecr_host ++ "/fixture/cdn:3.20";

pub const Fault = enum {
    none,
    /// 403 `DENIED`: the identity may not read the repository.
    denied,
    /// 404 `NAME_UNKNOWN`: there is no such repository.
    missing_repo,
    /// 401 whatever Basic is presented: the token is not accepted.
    bad_token,
};

pub const EcrSim = struct {
    aws: aws_sim.AwsSim = .{},
    fixture: fixture_mod.Fixture,
    fault: Fault = .none,
    registry_calls: u32 = 0,
    /// Registry requests that carried the right Basic token.
    registry_authenticated: u32 = 0,
    /// Requests that reached any host but the AWS ones, the ECR registry and S3.
    stray: u32 = 0,
    /// Blobs S3 served, and requests it refused for carrying a credential.
    s3_served: u32 = 0,
    s3_leaked: u32 = 0,

    pub fn init(sim: *EcrSim) void {
        sim.* = .{ .fixture = undefined };
        sim.fixture.init("https://" ++ ecr_host, "https://" ++ s3_host);
        assert(sim.fixture.oci.index.len > 0);
        assert(sim.aws.leaked == 0);
    }

    pub fn responder(sim: *EcrSim) net_sim.Responder {
        return .{ .context = sim, .answer = answer };
    }

    /// Every credential that reached a host that must not get one.
    pub fn leaked(sim: *const EcrSim) u32 {
        return sim.aws.leaked + sim.s3_leaked;
    }

    /// The Basic token the API issues, as a client must send it.
    pub fn basic_text(storage: *[64]u8) []const u8 {
        return std.base64.standard.Encoder.encode(storage, "AWS:" ++ aws_sim.ecr_password);
    }
};

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const sim: *EcrSim = @ptrCast(@alignCast(context));
    if (std.mem.eql(u8, request.host, ecr_host)) return registry(sim, request, served);
    if (std.mem.eql(u8, request.host, s3_host)) return s3(sim, request, served);
    const aws_host = std.mem.eql(u8, request.host, "169.254.169.254") or
        std.mem.startsWith(u8, request.host, "sts.") or
        std.mem.startsWith(u8, request.host, "api.ecr.");
    if (!aws_host) sim.stray += 1;
    const inner = sim.aws.responder();
    inner.answer(inner.context, request, received, served);
}

fn error_body(comptime code: []const u8) []const u8 {
    return "{\"errors\":[{\"code\":\"" ++ code ++ "\",\"message\":\"" ++
        aws_sim.message_marker ++ "\"}]}";
}

fn registry(sim: *EcrSim, request: *const net.Request, served: *net_sim.Served) void {
    assert(std.mem.eql(u8, request.host, ecr_host));
    assert(request.target.len > 0);
    sim.registry_calls += 1;
    var storage: [64]u8 = undefined;
    const right = EcrSim.basic_text(&storage);
    served.* = .{ .status = 401, .body = error_body("UNAUTHORIZED") };
    if (sim.fault == .bad_token or !std.mem.eql(u8, request.basic, right)) return;
    sim.registry_authenticated += 1;
    if (sim.fault == .denied) {
        served.* = .{ .status = 403, .body = error_body("DENIED") };
        return;
    }
    if (sim.fault == .missing_repo) {
        served.* = .{ .status = 404, .body = error_body("NAME_UNKNOWN") };
        return;
    }
    var out: fixture_mod.Answer = .{};
    sim.fixture.answer(.{
        .host = request.host,
        .target = request.target,
        .bearer = fixture_mod.token_text,
        .range_from = request.range_from,
    }, &out);
    served.* = of_answer(&out);
}

/// The blob host: any credential is refused (and counted); the rest is the fixture's content
/// delivery path.
fn s3(sim: *EcrSim, request: *const net.Request, served: *net_sim.Served) void {
    assert(std.mem.eql(u8, request.host, s3_host));
    assert(request.target.len > 0);
    const sent = request.bearer.len + request.basic.len + request.authorization.len;
    if (sent > 0) {
        sim.s3_leaked += 1;
        served.* = .{ .status = 400, .body = error_body("InvalidArgument") };
        return;
    }
    var out: fixture_mod.Answer = .{};
    sim.fixture.answer(.{
        .host = request.host,
        .target = request.target,
        .bearer = "",
        .range_from = request.range_from,
    }, &out);
    if (out.status == 200 or out.status == 206) sim.s3_served += 1;
    served.* = of_answer(&out);
}

fn of_answer(out: *const fixture_mod.Answer) net_sim.Served {
    assert(out.status >= 100);
    assert(out.status <= 599);
    return .{
        .status = out.status,
        .content_length = out.content_length,
        .www_authenticate = out.www_authenticate,
        .retry_after = out.retry_after,
        .content_type = out.content_type,
        .content_digest = out.content_digest,
        .location = out.location,
        .content_range = out.content_range,
        .range = out.range,
        .body = out.body,
        .deliver = out.deliver,
    };
}
