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
//!   does, and answers as it was seen to on 2026-11-16: `403 DENIED` anonymously for a private or
//!   a missing repository, `401 UNAUTHORIZED` for a token it does not accept. Where a credentialed
//!   caller is refused a repository it may not read, or one that does not exist, was not checked
//!   (`docs/decisions/2026-11-16-m6d-missing-repo-unverified.md`), so each candidate is a fault:
//!   `403 DENIED` at the realm, or a realm that grants and a manifest that answers `403 DENIED` or
//!   `404 NAME_UNKNOWN`.
//! - Layer blobs redirect either to a relative path on the registry host, as Artifact Registry
//!   does today, or to the storage host, which fails any request carrying `Authorization`.
//!
//! Every credential that reaches a host that must not get it is counted in `leaked`: a subject
//! token anywhere but STS, a federated token anywhere but IAM Credentials, an access token sent
//! anywhere as itself (it only ever travels inside the realm's Basic value), any `Authorization`
//! at STS, the metadata server or storage, a metadata call that may use a proxy. Connection
//! failures are the net simulator's own faults; the metadata server's absence and slowness are
//! modelled here, since they are what it is (`Served.fail`).

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("../testing/vm/registry_fixture.zig");
const net = @import("../registry/net.zig");
const net_sim = @import("../registry/net_sim.zig");
const sigv4 = @import("../aws/sigv4.zig");
const constants = @import("../constants.zig");
const parse = @import("parse.zig");

pub const registry_host = "us-docker.pkg.dev";
pub const storage_host = "storage.googleapis.com";
pub const subject_host = "tokens.example.com";
pub const metadata_host = "169.254.169.254";
/// A token service on another host, which a registry's challenge may name (`RealmAt.elsewhere`).
pub const elsewhere_host = "token.elsewhere.example";

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
    /// As `denied`: anonymously, a missing repository looks the same at the realm. Whether it does
    /// with valid credentials is unverified; `denied_at_manifest` and `missing_at_manifest` are
    /// the other candidates.
    missing_repo,
    /// The realm grants a token; the manifest answers 403 `DENIED` (the permission is missing,
    /// or the repository is: Google's message says "or it may not exist").
    denied_at_manifest,
    /// The realm grants a token; the manifest answers 404 `NAME_UNKNOWN`.
    missing_at_manifest,
    /// The realm answers 401 `UNAUTHORIZED` to every credential.
    bad_token,
    unavailable,
};

/// Where a blob request is sent: the registry's own downloads path, which serves it; storage
/// directly; or the downloads path, which sends it on to storage (a chain of two redirects).
pub const BlobRedirect = enum { same_host, storage, same_host_then_storage };

/// The realm the registry's challenge names: its own `https://<registry>/token`, a token service
/// on another host (`elsewhere_host`, which refuses anonymously), or its own over plain HTTP.
pub const RealmAt = enum { own, elsewhere, plain };

pub const GoogleSim = struct {
    /// The time the model believes it is, seconds since the epoch.
    now_s: u64 = 0,
    lifetime_s: u64 = 3600,
    /// Added to the lifetime IAM Credentials states as its `expireTime` (a test of the cap).
    iam_extra_s: u64 = 0,
    sts: StsMode = .ok,
    iam: IamMode = .ok,
    metadata: MetadataMode = .ok,
    subject: SubjectMode = .ok,
    registry_fault: RegistryFault = .none,
    blob_redirect: BlobRedirect = .same_host,
    realm_at: RealmAt = .own,
    /// The repository is public: the realm grants an anonymous token request, as Artifact Registry
    /// and gcr.io do for a public image.
    public: bool = false,
    /// The access token the realm accepts.
    accepted_token: []const u8 = access_token,
    /// The token the metadata server hands out (a test at the token's bound sets a long one).
    metadata_token_text: []const u8 = metadata_token,
    /// When not zero, STS's answer is padded with blanks to exactly this many bytes (a test at
    /// the response bound).
    sts_answer_bytes: u32 = 0,
    fixture: fixture_mod.Fixture,
    /// The registry's host: Artifact Registry's unless `init_at` names a gcr.io one.
    registry_name: []const u8 = registry_host,
    sts_calls: u32 = 0,
    iam_calls: u32 = 0,
    metadata_calls: u32 = 0,
    subject_calls: u32 = 0,
    realm_calls: u32 = 0,
    realm_ok: u32 = 0,
    storage_served: u32 = 0,
    /// Requests to the registry's downloads path that carried the realm's Bearer.
    downloads_bearer: u32 = 0,
    /// Requests to `elsewhere_host`.
    elsewhere_calls: u32 = 0,
    /// Requests to a host the model does not know.
    stray: u32 = 0,
    /// Requests that carried a credential to a host that must not get it.
    leaked: u32 = 0,
    scratch: [512]u8 = undefined,
    padded: [constants.google_response_bytes_max + 1]u8 = undefined,
    /// The metadata answer, with room for a token one past its bound.
    metadata_scratch: [constants.google_access_token_bytes_max + 128]u8 = undefined,
    location: [256]u8 = undefined,
    challenge: [512]u8 = undefined,

    pub fn init(sim: *GoogleSim) void {
        sim.init_at(registry_host);
    }

    /// As `init`, with the registry at `host` (a gcr.io host, say).
    pub fn init_at(sim: *GoogleSim, comptime host: []const u8) void {
        sim.* = .{ .fixture = undefined, .registry_name = host };
        sim.fixture.init("https://" ++ host, "https://" ++ storage_host);
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
    // An access token travels only inside the realm's Basic value, never as itself.
    if (sends(request, received, access_token)) sim.leaked += 1;
    if (sends(request, received, metadata_token)) sim.leaked += 1;
    // No credential travels in plain HTTP to any of the model's hosts.
    if (request.scheme == .http and carries_credential(request)) sim.leaked += 1;
    if (std.mem.eql(u8, request.host, metadata_host)) return metadata(sim, request, served);
    if (std.mem.eql(u8, request.host, parse.sts_host)) return sts(sim, request, received, served);
    if (std.mem.eql(u8, request.host, parse.iam_host)) return iam(sim, request, received, served);
    if (std.mem.eql(u8, request.host, subject_host)) return subject(sim, request, served);
    if (std.mem.eql(u8, request.host, sim.registry_name)) return registry(sim, request, served);
    if (std.mem.eql(u8, request.host, storage_host)) return storage(sim, request, served);
    if (std.mem.eql(u8, request.host, elsewhere_host)) return elsewhere(sim, request, served);
    sim.stray += 1;
    if (carries_credential(request)) sim.leaked += 1;
}

/// Whether `secret` is anywhere in what the request sent: a credential, a header or the body.
fn sends(request: *const net.Request, received: []const u8, secret: []const u8) bool {
    assert(secret.len > 0);
    if (std.mem.indexOf(u8, received, secret) != null) return true;
    if (std.mem.indexOf(u8, request.bearer, secret) != null) return true;
    if (std.mem.indexOf(u8, request.authorization, secret) != null) return true;
    if (std.mem.indexOf(u8, request.target, secret) != null) return true;
    for (request.extra_headers) |header| {
        if (std.mem.indexOf(u8, header.value, secret) != null) return true;
    }
    return false;
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
        .ok => served.* = .{ .status = 200, .body = padded(sim, sts_answer(sim)) },
        .invalid_grant, .invalid_target => unreachable, // Answered above.
    }
}

fn sts_answer(sim: *GoogleSim) []const u8 {
    return std.fmt.bufPrint(&sim.scratch, "{{\"access_token\":\"{s}\",\"issued_token_type\":" ++
        "\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\"," ++
        // Cannot fail: scratch fits.
        "\"expires_in\":{d}}}", .{ federated_token, sim.lifetime_s }) catch unreachable;
}

/// `body` with blanks before its closing brace, to `sts_answer_bytes` when that is set.
fn padded(sim: *GoogleSim, body: []const u8) []const u8 {
    assert(body.len > 0);
    assert(body[body.len - 1] == '}');
    const total = sim.sts_answer_bytes;
    if (total == 0) return body;
    assert(total > body.len);
    assert(total <= sim.padded.len);
    @memcpy(sim.padded[0 .. body.len - 1], body[0 .. body.len - 1]);
    @memset(sim.padded[body.len - 1 .. total - 1], ' ');
    sim.padded[total - 1] = '}';
    return sim.padded[0..total];
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
            const expires = format_time(&stamp, sim.now_s + sim.lifetime_s + sim.iam_extra_s);
            const text = std.fmt.bufPrint(&sim.scratch, "{{\"accessToken\":\"{s}\"," ++
                // Cannot fail: scratch fits.
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
    assert(sim.metadata_token_text.len <= constants.google_access_token_bytes_max + 1);
    const format = "{{\"access_token\":\"{s}\",\"expires_in\":{d},\"token_type\":\"Bearer\"}}";
    const arguments = .{ sim.metadata_token_text, sim.lifetime_s };
    // Cannot fail: the scratch holds a token one past its bound and the rest.
    return std.fmt.bufPrint(&sim.metadata_scratch, format, arguments) catch unreachable;
}

const downloads_prefix = "/artifacts-downloads/namespaces/fixture/downloads/";

/// The registry host: the realm (`/token`) takes Basic `oauth2accesstoken`, the rest is the
/// fixture's, with its blob redirect pointed where `blob_redirect` says.
fn registry(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    assert(request.target.len > 0);
    if (std.mem.startsWith(u8, request.target, "/token")) return realm(sim, request, served);
    if (std.mem.startsWith(u8, request.target, downloads_prefix)) {
        // Served without auth, as Artifact Registry serves its downloads path. It is the
        // registry's own origin, so the realm's Bearer may follow the redirect (the client's
        // same-origin rule); the realm's Basic or any other `Authorization` may not.
        if (request.basic.len + request.authorization.len > 0) sim.leaked += 1;
        if (request.bearer.len > 0) sim.downloads_bearer += 1;
        const digest = request.target[downloads_prefix.len..];
        if (sim.blob_redirect == .same_host_then_storage) {
            const format = "https://" ++ storage_host ++ "/cdn/{s}";
            served.* = .{ .status = 302 };
            served.location = std.fmt.bufPrint(&sim.location, format, .{digest}) catch {
                served.* = .{ .status = 404 };
                return;
            };
            return;
        }
        const target = std.fmt.bufPrint(&sim.scratch, "/cdn/{s}", .{digest}) catch {
            served.* = .{ .status = 404 };
            return;
        };
        return fixture_answer(sim, request, target, "", served);
    }
    if (request.basic.len + request.authorization.len > 0) sim.leaked += 1;
    if (manifest_refusal(sim, request)) |refusal| {
        served.* = refusal;
        return;
    }
    fixture_answer(sim, request, request.target, request.bearer, served);
    if (served.www_authenticate.len > 0) move_realm(sim, served);
    const storage_base = "https://" ++ storage_host ++ "/cdn/";
    const to_storage = std.mem.startsWith(u8, served.location, storage_base);
    const redirected = served.status == 307 and to_storage;
    if (!redirected or sim.blob_redirect == .storage) return;
    const digest = served.location[storage_base.len..];
    served.status = 302;
    served.location = std.fmt.bufPrint(&sim.location, downloads_prefix ++ "{s}", .{digest}) catch
        unreachable; // A digest is 71 bytes.
}

/// Rewrites the challenge's realm to where `realm_at` says.
fn move_realm(sim: *GoogleSim, served: *net_sim.Served) void {
    assert(served.www_authenticate.len > 0);
    const realm_of: []const u8 = switch (sim.realm_at) {
        .own => return,
        .elsewhere => "https://" ++ elsewhere_host ++ "/token",
        .plain => "http://",
    };
    const prefix = "Bearer realm=\"https://";
    const header = served.www_authenticate;
    assert(std.mem.startsWith(u8, header, prefix));
    // The plain realm keeps the registry's host and path; the other replaces them.
    const rest = if (sim.realm_at == .plain) header[prefix.len..] else after_realm(header);
    served.www_authenticate = std.fmt.bufPrint(
        &sim.challenge,
        "Bearer realm=\"{s}{s}",
        .{ realm_of, rest },
    ) catch unreachable; // The fixture's challenge is short.
}

/// The challenge from the realm's closing quote on.
fn after_realm(header: []const u8) []const u8 {
    const prefix = "Bearer realm=\"";
    assert(std.mem.startsWith(u8, header, prefix));
    const end = std.mem.indexOfScalarPos(u8, header, prefix.len, '"') orelse header.len;
    return header[end..];
}

/// A token service on another host: it refuses anonymously, as a private realm does, and any
/// credential that reaches it is a leak.
fn elsewhere(sim: *GoogleSim, request: *const net.Request, served: *net_sim.Served) void {
    sim.elsewhere_calls += 1;
    if (carries_credential(request)) sim.leaked += 1;
    served.* = .{ .status = 403, .body = registry_error("DENIED") };
}

/// A credentialed manifest request refused at the origin, when the fault says so.
fn manifest_refusal(sim: *const GoogleSim, request: *const net.Request) ?net_sim.Served {
    assert(request.target.len > 0);
    if (request.bearer.len == 0) return null;
    if (std.mem.indexOf(u8, request.target, "/manifests/") == null) return null;
    return switch (sim.registry_fault) {
        .denied_at_manifest => .{ .status = 403, .body = registry_error("DENIED") },
        .missing_at_manifest => .{ .status = 404, .body = registry_error("NAME_UNKNOWN") },
        .none, .denied, .missing_repo, .bad_token, .unavailable => null,
    };
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
    if (request.basic.len == 0 and sim.public) {
        sim.realm_ok += 1;
        fixture_answer(sim, request, request.target, "", served);
        return;
    }
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

/// A GET at the registry host, with `bearer` or `basic` (base64) as its credential.
fn registry_get(target: []const u8, bearer: []const u8, basic: []const u8) net.Request {
    assert(target.len > 0);
    const one_credential = bearer.len == 0 or basic.len == 0;
    assert(one_credential);
    return .{
        .scheme = .https,
        .host = registry_host,
        .port = 443,
        .target = target,
        .accept = "application/json",
        .bearer = bearer,
        .basic = basic,
        .body_bytes_max = 4096,
        .idle_timeout_ms = 1000,
        .total_timeout_ms = 1000,
    };
}

test "a manifest fault grants at the realm and refuses at the manifest" {
    // Goal: the two unverified candidates for a missing repository: the realm grants a token to
    // valid credentials, and only a credentialed manifest request is refused, with Google's code;
    // an anonymous one, and every other fault, reach the registry as before.
    const sim = try std.heap.page_allocator.create(GoogleSim);
    defer std.heap.page_allocator.destroy(sim);
    const Case = struct { fault: RegistryFault, status: u16, code: []const u8 };
    const cases = [_]Case{
        .{ .fault = .denied_at_manifest, .status = 403, .code = "\"DENIED\"" },
        .{ .fault = .missing_at_manifest, .status = 404, .code = "\"NAME_UNKNOWN\"" },
    };
    const manifest = "/v2/fixture/bearer/manifests/latest";
    for (cases) |case| {
        sim.init();
        sim.registry_fault = case.fault;
        var basic_buffer: [128]u8 = undefined;
        const basic = sim.basic_text(&basic_buffer);
        var served: net_sim.Served = .{};
        const scope = "/token?scope=repository:fixture/bearer:pull";
        const token_request = registry_get(scope, "", basic);
        answer(sim, &token_request, "", &served);
        try std.testing.expectEqual(@as(u16, 200), served.status);
        const credentialed = registry_get(manifest, "registry-token", "");
        answer(sim, &credentialed, "", &served);
        try std.testing.expectEqual(case.status, served.status);
        try std.testing.expect(std.mem.indexOf(u8, served.body, case.code) != null);
        const anonymous = registry_get(manifest, "", "");
        answer(sim, &anonymous, "", &served);
        try std.testing.expect(served.status != case.status);
        try std.testing.expectEqual(@as(u32, 0), sim.leaked);
    }
}
