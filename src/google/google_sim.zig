//! A simulated Google for the tests, behind one `net_sim.Responder`: STS, IAM Credentials, a
//! subject-token URL host, the GCE metadata server, an Artifact Registry host with its realm, and
//! `storage.googleapis.com`. It is a model with enough teeth to catch the mistakes that matter,
//! not a copy of Google:
//!
//! - STS takes only the subject token it issued, for the audience it knows, in a form; IAM
//!   Credentials only the federated token STS issued, for the one service account it knows.
//! - The metadata server answers only a request with `Metadata-Flavor: Google`, and marks its
//!   answers with the same header; in its `ec2` mode it answers as EC2's does, without it.
//! - The registry's realm takes Basic `oauth2accesstoken:<access token>`, as Artifact Registry
//!   does, and answers as it was seen to on 2026-11-16: `403 DENIED` for a repository the caller
//!   may not read (anonymously, a missing one answers the same), `401 UNAUTHORIZED` for a token it
//!   does not accept.
//! - Layer blobs redirect either to a relative path on the registry host, as Artifact Registry
//!   does today, or to the storage host, which fails any request carrying `Authorization`.
//!
//! Every credential that reaches a host that must not get it is counted in `leaked`: a subject
//! token anywhere but STS, a federated token anywhere but IAM Credentials, any `Authorization` at
//! STS, the metadata server or storage, a metadata call that may use a proxy. Connection failures
//! are the net simulator's own faults; the metadata server's absence and slowness are modelled
//! here, since they are what it is (`Served.fail`).

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("../testing/vm/registry_fixture.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const sigv4 = @import("../aws/sigv4.zig");
const parse = @import("parse.zig");

pub const registry_host = "us-docker.pkg.dev";
pub const storage_host = "storage.googleapis.com";
pub const subject_host = "tokens.example.com";
pub const metadata_host = "169.254.169.254";

pub const audience = "//iam.googleapis.com/projects/123456789012/locations/global/" ++
    "workloadIdentityPools/zbx-pool/providers/github";
pub const service_account = "zbx-pull@zbx-demo.iam.gserviceaccount.com";
pub const impersonation_target = "/v1/projects/-/serviceAccounts/" ++ service_account ++
    ":generateAccessToken";
pub const subject_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOnpieCJ9.RkFLRXNpZ25hdHVyZQ";
/// The header value the URL source must send.
pub const runner_authorization = "Bearer fake-runner-request-token-0001";
pub const federated_token = "ya29.FAKEfederated-0123456789abcdefghijklmnop";
pub const access_token = "ya29.FAKEimpersonated-0123456789abcdefghijk";
pub const metadata_token = "ya29.FAKEmetadata-0123456789abcdefghijklmnopq";
/// What every error message says, to show that no message text is ever repeated.
pub const message_marker = "MESSAGE-MARKER-DO-NOT-PRINT";
/// Where the URL source's subject token is served.
pub const subject_target = "/oidc?audience=x";

pub const StsMode = enum {
    ok,
    /// 400 `invalid_grant`: the subject token is refused (expired, or the wrong issuer).
    invalid_grant,
    /// 400 `invalid_target`: the audience names no pool or provider Google knows.
    invalid_target,
    malformed,
    unavailable,
};

pub const IamMode = enum {
    ok,
    /// 403 `PERMISSION_DENIED`: the pool's identity may not act as the service account.
    denied,
    malformed,
    unavailable,
};

pub const MetadataMode = enum {
    ok,
    /// Nothing listens at the address (not on a cloud).
    absent,
    /// Nothing answers in time.
    slow,
    /// Answers 200 without `Metadata-Flavor`.
    no_flavor,
    /// Answers as EC2's does: 404 for a Google path, without `Metadata-Flavor`.
    ec2,
    /// GCE with no service account on the instance: 404 with the header.
    no_service_account,
    malformed,
    unavailable,
};

pub const SubjectMode = enum { ok, refused, unavailable };

pub const RegistryFault = enum {
    none,
    /// The realm answers 403 `DENIED` to every credential.
    denied,
    /// As `denied`: a missing repository looks the same at the realm (checked anonymously).
    missing_repo,
    /// The realm answers 401 `UNAUTHORIZED` to every credential.
    bad_token,
    unavailable,
};

pub const BlobRedirect = enum { same_host, storage };

pub const GoogleSim = struct {
    /// The time the model believes it is, seconds since the epoch.
    now_s: u64 = 0,
    lifetime_s: u64 = 3600,
    sts: StsMode = .ok,
    iam: IamMode = .ok,
    metadata: MetadataMode = .ok,
    subject: SubjectMode = .ok,
    registry_fault: RegistryFault = .none,
    blob_redirect: BlobRedirect = .same_host,
    /// The access token the realm accepts.
    accepted_token: []const u8 = access_token,
    fixture: fixture_mod.Fixture,
    sts_calls: u32 = 0,
    iam_calls: u32 = 0,
    metadata_calls: u32 = 0,
    subject_calls: u32 = 0,
    realm_calls: u32 = 0,
    realm_ok: u32 = 0,
    storage_served: u32 = 0,
    /// Requests to a host the model does not know.
    stray: u32 = 0,
    /// Requests that carried a credential to a host that must not get it.
    leaked: u32 = 0,
    scratch: [512]u8 = undefined,
    location: [256]u8 = undefined,

    pub fn init(sim: *GoogleSim) void {
        sim.* = .{ .fixture = undefined };
        sim.fixture.init("https://" ++ registry_host, "https://" ++ storage_host);
        assert(sim.fixture.oci.index.len > 0);
        assert(sim.leaked == 0);
    }

    pub fn responder(sim: *GoogleSim) net_sim.Responder {
        return .{ .context = sim, .answer = answer };
    }

    /// The Basic value the realm accepts, as a client must send it.
    pub fn basic_text(sim: *const GoogleSim, out: *[128]u8) []const u8 {
        var plain: [96]u8 = undefined;
        const user = "oauth2accesstoken:";
        assert(user.len + sim.accepted_token.len <= plain.len);
        @memcpy(plain[0..user.len], user);
        @memcpy(plain[user.len..][0..sim.accepted_token.len], sim.accepted_token);
        const text = plain[0 .. user.len + sim.accepted_token.len];
        return std.base64.standard.Encoder.encode(out, text);
    }
};

fn header_value(request: *const net.Request, name: []const u8) ?[]const u8 {
    for (request.extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn carries_credential(request: *const net.Request) bool {
    if (request.bearer.len + request.basic.len + request.authorization.len > 0) return true;
    for (request.extra_headers) |header| {
        if (header.secret) return true;
    }
    return false;
}

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const sim: *GoogleSim = @ptrCast(@alignCast(context));
    served.* = .{ .status = 404 };
    // A token the model issued, sent anywhere it was not issued for, is a leak.
    const subject_sent = std.mem.indexOf(u8, received, subject_token) != null;
    if (subject_sent and !std.mem.eql(u8, request.host, parse.sts_host)) sim.leaked += 1;
    const federated_sent = std.mem.eql(u8, request.bearer, federated_token);
    if (federated_sent and !std.mem.eql(u8, request.host, parse.iam_host)) sim.leaked += 1;
    if (std.mem.eql(u8, request.host, metadata_host)) return metadata(sim, request, served);
    if (std.mem.eql(u8, request.host, parse.sts_host)) return sts(sim, request, received, served);
    if (std.mem.eql(u8, request.host, parse.iam_host)) return iam(sim, request, received, served);
    if (std.mem.eql(u8, request.host, subject_host)) return subject(sim, request, served);
    if (std.mem.eql(u8, request.host, registry_host)) return registry(sim, request, served);
    if (std.mem.eql(u8, request.host, storage_host)) return storage(sim, request, served);
    sim.stray += 1;
    if (carries_credential(request)) sim.leaked += 1;
}

fn oauth_error(comptime code: []const u8) []const u8 {
    return "{\"error\":\"" ++ code ++ "\",\"error_description\":\"" ++ message_marker ++ "\"}";
}

fn google_error(comptime status: u16, comptime code: []const u8) []const u8 {
    return std.fmt.comptimePrint("{{\"error\":{{\"code\":{d},\"message\":\"{s}\"," ++
        "\"status\":\"{s}\"}}}}", .{ status, message_marker, code });
}

fn registry_error(comptime code: []const u8) []const u8 {
    return "{\"errors\":[{\"code\":\"" ++ code ++ "\",\"message\":\"" ++ message_marker ++ "\"}]}";
}

fn sts(
    sim: *GoogleSim,
    request: *const net.Request,
    form: []const u8,
    served: *net_sim.Served,
) void {
    sim.sts_calls += 1;
    if (request.bearer.len + request.basic.len + request.authorization.len > 0) sim.leaked += 1;
    const well_formed = request.method == .post and std.mem.eql(u8, request.target, "/v1/token") and
        std.mem.eql(u8, request.content_type, "application/x-www-form-urlencoded");
    if (!well_formed) {
        served.* = .{ .status = 400, .body = oauth_error("invalid_request") };
        return;
    }
    const expected_audience = "audience=%2F%2Fiam.googleapis.com%2Fprojects%2F123456789012";
    const known = std.mem.indexOf(u8, form, expected_audience) != null;
    if (sim.sts == .invalid_target or !known) {
        served.* = .{ .status = 400, .body = oauth_error("invalid_target") };
        return;
    }
    const presented = std.mem.indexOf(u8, form, "subject_token=" ++ subject_token) != null;
    if (sim.sts == .invalid_grant or !presented) {
        served.* = .{ .status = 400, .body = oauth_error("invalid_grant") };
        return;
    }
    switch (sim.sts) {
        .unavailable => served.* = .{ .status = 503, .body = oauth_error("server_error") },
        .malformed => served.* = .{ .status = 200, .body = "{\"access_token\":7}" },
        .ok => served.* = .{ .status = 200, .body = sts_answer(sim) },
        .invalid_grant, .invalid_target => unreachable, // Answered above.
    }
}

fn sts_answer(sim: *GoogleSim) []const u8 {
    return std.fmt.bufPrint(&sim.scratch, "{{\"access_token\":\"{s}\",\"issued_token_type\":" ++
        "\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\"," ++
        "\"expires_in\":{d}}}", .{ federated_token, sim.lifetime_s }) catch unreachable;
}

fn format_time(buffer: *[20]u8, seconds: u64) []const u8 {
    const date = sigv4.amz_date_of(seconds);
    return std.fmt.bufPrint(buffer, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        date[0..4], date[4..6], date[6..8], date[9..11], date[11..13], date[13..15],
    }) catch unreachable; // Twenty bytes hold the extended form.
}

fn iam(
    sim: *GoogleSim,
    request: *const net.Request,
    body: []const u8,
    served: *net_sim.Served,
) void {
    sim.iam_calls += 1;
    if (request.basic.len + request.authorization.len > 0) sim.leaked += 1;
    if (!std.mem.eql(u8, request.bearer, federated_token)) {
        served.* = .{ .status = 401, .body = google_error(401, "UNAUTHENTICATED") };
        return;
    }
    const scoped = std.mem.indexOf(u8, body, "cloud-platform") != null;
    const right = request.method == .post and std.mem.eql(u8, request.target, impersonation_target);
    if (!right or !scoped) {
        served.* = .{ .status = 404, .body = google_error(404, "NOT_FOUND") };
        return;
    }
    switch (sim.iam) {
        .denied => served.* = .{ .status = 403, .body = google_error(403, "PERMISSION_DENIED") },
        .unavailable => served.* = .{ .status = 503, .body = google_error(503, "UNAVAILABLE") },
        .malformed => served.* = .{ .status = 200, .body = "{\"accessToken\":\"" },
        .ok => {
            var stamp: [20]u8 = undefined;
            const expires = format_time(&stamp, sim.now_s + sim.lifetime_s);
            const text = std.fmt.bufPrint(&sim.scratch, "{{\"accessToken\":\"{s}\"," ++
                "\"expireTime\":\"{s}\"}}", .{ access_token, expires }) catch unreachable;
            served.* = .{ .status = 200, .body = text };
        },
    }
}

fn subject(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.subject_calls += 1;
    if (request.bearer.len + request.basic.len > 0) sim.leaked += 1;
    const authorized = std.mem.eql(u8, request.authorization, runner_authorization);
    if (sim.subject == .refused or !authorized) {
        served.* = .{ .status = 401, .body = "{\"message\":\"" ++ message_marker ++ "\"}" };
        return;
    }
    if (sim.subject == .unavailable) {
        served.* = .{ .status = 502, .body = "" };
        return;
    }
    if (!std.mem.eql(u8, request.target, subject_target)) return;
    served.* = .{ .status = 200, .body = "{\"count\":1,\"value\":\"" ++ subject_token ++ "\"}" };
}

fn metadata(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.metadata_calls += 1;
    if (request.proxy != .never) sim.leaked += 1;
    if (request.bearer.len + request.basic.len + request.authorization.len > 0) sim.leaked += 1;
    const unmarked: ?net_sim.Served = switch (sim.metadata) {
        .absent => .{ .fail = error.ConnectFailed },
        .slow => .{ .fail = error.TimedOut },
        .ec2 => .{ .status = 404, .body = "" },
        .no_flavor => .{ .status = 200, .body = metadata_answer(sim) },
        else => null,
    };
    if (unmarked) |value| {
        served.* = value;
        return;
    }
    const flavor = header_value(request, "Metadata-Flavor") orelse "";
    if (!std.mem.eql(u8, flavor, "Google")) {
        served.* = .{ .status = 403, .metadata_flavor = "Google", .body = "Missing header" };
        return;
    }
    const path = "/computeMetadata/v1/instance/service-accounts/default/token";
    if (!std.mem.eql(u8, request.target, path)) {
        served.* = .{ .status = 404, .metadata_flavor = "Google" };
        return;
    }
    served.* = switch (sim.metadata) {
        .no_service_account => .{ .status = 404, .metadata_flavor = "Google", .body = "" },
        .unavailable => .{ .status = 503, .metadata_flavor = "Google", .body = "" },
        .malformed => .{ .status = 200, .metadata_flavor = "Google", .body = "<html>" },
        .ok => .{ .status = 200, .metadata_flavor = "Google", .body = metadata_answer(sim) },
        .absent, .slow, .ec2, .no_flavor => unreachable, // Answered above.
    };
}

fn metadata_answer(sim: *GoogleSim) []const u8 {
    return std.fmt.bufPrint(&sim.scratch, "{{\"access_token\":\"{s}\",\"expires_in\":{d}," ++
        "\"token_type\":\"Bearer\"}}", .{ metadata_token, sim.lifetime_s }) catch unreachable;
}

const downloads_prefix = "/artifacts-downloads/namespaces/fixture/downloads/";

/// The registry host: the realm (`/token`) takes Basic `oauth2accesstoken`, the rest is the
/// fixture's, with its blob redirect pointed where `blob_redirect` says.
fn registry(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    assert(request.target.len > 0);
    if (std.mem.startsWith(u8, request.target, "/token")) return realm(sim, request, served);
    if (std.mem.startsWith(u8, request.target, downloads_prefix)) {
        // Served without auth, as Artifact Registry serves its downloads path.
        if (carries_credential(request)) sim.leaked += 1;
        const digest = request.target[downloads_prefix.len..];
        const target = std.fmt.bufPrint(&sim.scratch, "/cdn/{s}", .{digest}) catch {
            served.* = .{ .status = 404 };
            return;
        };
        return fixture_answer(sim, request, target, "", served);
    }
    if (request.basic.len + request.authorization.len > 0) sim.leaked += 1;
    fixture_answer(sim, request, request.target, request.bearer, served);
    const storage_base = "https://" ++ storage_host ++ "/cdn/";
    const to_storage = std.mem.startsWith(u8, served.location, storage_base);
    const redirected = served.status == 307 and to_storage;
    if (!redirected or sim.blob_redirect == .storage) return;
    const digest = served.location[storage_base.len..];
    served.status = 302;
    served.location = std.fmt.bufPrint(&sim.location, downloads_prefix ++ "{s}", .{digest}) catch
        unreachable; // A digest is 71 bytes.
}

fn realm(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.realm_calls += 1;
    if (request.bearer.len + request.authorization.len > 0) sim.leaked += 1;
    if (sim.registry_fault == .unavailable) {
        served.* = .{ .status = 503, .body = registry_error("UNAVAILABLE") };
        return;
    }
    var storage_buffer: [128]u8 = undefined;
    const right = sim.basic_text(&storage_buffer);
    if (request.basic.len == 0) {
        // Anonymous: a private repository, or a missing one, is denied.
        served.* = .{ .status = 403, .body = registry_error("DENIED") };
        return;
    }
    if (sim.registry_fault == .bad_token or !std.mem.eql(u8, request.basic, right)) {
        served.* = .{ .status = 401, .body = registry_error("UNAUTHORIZED") };
        return;
    }
    if (sim.registry_fault == .denied or sim.registry_fault == .missing_repo) {
        served.* = .{ .status = 403, .body = registry_error("DENIED") };
        return;
    }
    sim.realm_ok += 1;
    fixture_answer(sim, request, request.target, "", served);
}

/// The storage host: any credential is refused (and counted); the rest is the fixture's content
/// delivery path.
fn storage(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    assert(request.target.len > 0);
    if (carries_credential(request)) {
        sim.leaked += 1;
        served.* = .{ .status = 400, .body = "<Error><Code>InvalidArgument</Code></Error>" };
        return;
    }
    fixture_answer(sim, request, request.target, "", served);
    if (served.status == 200 or served.status == 206) sim.storage_served += 1;
}

fn fixture_answer(
    sim: *GoogleSim,
    request: *const net.Request,
    target: []const u8,
    bearer: []const u8,
    served: *net_sim.Served,
) void {
    var out: fixture_mod.Answer = .{};
    sim.fixture.answer(.{
        .host = request.host,
        .target = target,
        .bearer = bearer,
        .range_from = request.range_from,
    }, &out);
    assert(out.status >= 100);
    served.* = .{
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
