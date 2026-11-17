//! Finding a Google access token: the `google_credentials_resolve` of the library, the twin of
//! `aws_credentials_resolve`. It knows nothing of pulls or registries; Artifact Registry pull
//! calls it (M6d slice 2), and so can Zigcube's agent.
//!
//! Two sources, in this order, each asked only when the caller's `Sources` mask names it:
//!
//! 1. Workload identity federation: `GOOGLE_APPLICATION_CREDENTIALS` names an `external_account`
//!    file (`parse.zig` says which shapes are accepted). The subject token is read from its file
//!    or fetched from its HTTPS URL, exchanged at `sts.googleapis.com` for a federated token, and,
//!    when the file names a service account to impersonate, that token buys the account's access
//!    token at `iamcredentials.googleapis.com`. Once the variable is set this source is the
//!    answer, success or not: a failure is reported and the metadata server is not asked, because
//!    the user said which identity to use.
//! 2. The GCE metadata server: a GET of the default service account's token from the link-local
//!    address with `Metadata-Flavor: Google`, never through a proxy, with a short timeout. The
//!    answer must carry `Metadata-Flavor: Google`, or this is not GCE (an EC2 host answers on the
//!    same address, without it).
//!
//! Each secret goes only where it is for: the subject token to STS, the federated token to IAM
//! Credentials, a URL source's headers to that URL. Nothing is stored. The caller owns the
//! `Token` and the `Workspace` and calls `wipe` on both when it is done; `resolve` zeroes the
//! workspace before it returns. The `Trace` says what each source did, in words that hold no
//! secret, so the caller can tell the user why nothing was found.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const net = @import("../registry/net.zig");
const cloud_env = @import("../cloud/env.zig");
const metadata = @import("../cloud/metadata.zig");
const sigv4 = @import("../aws/sigv4.zig");
const parse = @import("parse.zig");

/// The environment as the caller sees it (`src/cloud/env.zig`): only this name is read.
pub const Env = cloud_env.CredentialEnv(&.{"GOOGLE_APPLICATION_CREDENTIALS"});

pub const credentials_variable = "GOOGLE_APPLICATION_CREDENTIALS";

/// Which sources `resolve` may ask. The CLI asks for workload identity up front and for the
/// metadata server only after an anonymous refusal; a library caller chooses. The mask never
/// overrides the terminal rule: when `GOOGLE_APPLICATION_CREDENTIALS` is set, the metadata server
/// is asked by no mask, and a mask without `workload_identity` finds nothing (`not_asked`).
pub const Sources = struct {
    workload_identity: bool = false,
    metadata: bool = false,
};

pub const Source = enum { none, workload_identity, metadata };

/// What workload identity federation did. `used` is the only success.
pub const State = enum {
    /// `GOOGLE_APPLICATION_CREDENTIALS` is not set.
    not_configured,
    /// `GOOGLE_APPLICATION_CREDENTIALS` is set, but the caller's `Sources` leaves workload
    /// identity out. The metadata server is not asked either: the user named an identity, and
    /// another must not stand in for it unannounced.
    not_asked,
    /// The credentials file could not be read, or is larger than its bound.
    unreadable,
    /// The file is not one zbx uses; `Trace.unsupported` says why.
    unsupported,
    /// The subject token could not be read (file or URL), or is empty or not a token.
    subject_unreadable,
    /// A step's service said no (a status that is not 200); `Trace.step` says which, and
    /// `Trace.code()` has Google's error code when it sent one.
    refused,
    /// A step's service could not be reached or the call failed; `Trace.step` says which.
    no_answer,
    /// A step's answer is not the document it should be.
    malformed,
    /// The token is, or is about to be, out of date.
    expired,
    used,
};

/// What the metadata server did. `used` is the only success.
pub const MetadataState = enum {
    not_asked,
    /// Nothing answered at the link-local address, or not in time: not on a cloud.
    absent,
    /// Something answered without `Metadata-Flavor: Google`: another cloud (EC2), or not GCE.
    not_gce,
    /// GCE, with no service account attached to the instance (404).
    no_service_account,
    /// GCE said no with another status; `Trace.status` has it.
    refused,
    malformed,
    expired,
    used,
};

/// The step of workload identity federation a failure happened at.
pub const Step = enum { none, credentials_file, subject_token, exchange, impersonation };

pub const Trace = struct {
    workload_identity: State = .not_configured,
    metadata: MetadataState = .not_asked,
    step: Step = .none,
    /// Why the credentials file is not used, when `workload_identity` is `unsupported`.
    unsupported: parse.Refusal = .malformed,
    /// Where the subject token comes from, once the file was read.
    subject_source: parse.SourceKind = .file,
    type_name: [constants.google_type_name_bytes_max]u8 = undefined,
    type_name_len: u32 = 0,
    /// The service account the file impersonates (not a secret; named in a fix), else empty.
    service_account: [constants.google_service_account_bytes_max]u8 = undefined,
    service_account_len: u32 = 0,
    /// The error code Google sent with a refusal (`invalid_grant`), empty for none.
    error_code: [constants.google_error_code_bytes_max]u8 = undefined,
    error_code_len: u32 = 0,
    /// The status of the last refusal, zero for none.
    status: u16 = 0,

    pub fn code(trace: *const Trace) []const u8 {
        assert(trace.error_code_len <= trace.error_code.len);
        return trace.error_code[0..trace.error_code_len];
    }

    pub fn file_type(trace: *const Trace) []const u8 {
        assert(trace.type_name_len <= trace.type_name.len);
        return trace.type_name[0..trace.type_name_len];
    }

    pub fn account(trace: *const Trace) []const u8 {
        assert(trace.service_account_len <= trace.service_account.len);
        return trace.service_account[0..trace.service_account_len];
    }

    fn note_refusal(trace: *Trace, status: u16, body: []const u8) void {
        assert(status != 200);
        trace.status = status;
        const found = parse.error_code(body) orelse return;
        assert(found.len <= trace.error_code.len);
        @memcpy(trace.error_code[0..found.len], found);
        trace.error_code_len = @intCast(found.len);
    }

    fn note_unsupported(trace: *Trace, refused: parse.Refused) void {
        assert(refused.type_name.len <= trace.type_name.len);
        trace.workload_identity = .unsupported;
        trace.unsupported = refused.reason;
        @memcpy(trace.type_name[0..refused.type_name.len], refused.type_name);
        trace.type_name_len = @intCast(refused.type_name.len);
    }

    fn note_account(trace: *Trace, email: []const u8) void {
        assert(email.len <= trace.service_account.len);
        @memcpy(trace.service_account[0..email.len], email);
        trace.service_account_len = @intCast(email.len);
    }
};

/// An access token, in memory the caller owns.
pub const Token = struct {
    bytes: [constants.google_access_token_bytes_max]u8 = undefined,
    len: u32 = 0,
    /// Seconds since the epoch.
    expiration_s: u64 = 0,
    source: Source = .none,

    pub fn text(token: *const Token) []const u8 {
        assert(token.len <= token.bytes.len);
        return token.bytes[0..token.len];
    }

    pub fn wipe(token: *Token) void {
        std.crypto.secureZero(u8, &token.bytes);
        token.len = 0;
        token.expiration_s = 0;
        token.source = .none;
    }

    /// Whether it is out of date at `now_s`, or will be within `google_token_margin_s`. An empty
    /// token is expired.
    pub fn expired(token: *const Token, now_s: u64) bool {
        if (token.len == 0) return true;
        return token.expiration_s <= now_s +| constants.google_token_margin_s;
    }

    fn set(token: *Token, source: Source, value: []const u8, expiration_s: u64) void {
        assert(parse.access_token_valid(value));
        assert(source != .none);
        token.wipe();
        @memcpy(token.bytes[0..value.len], value);
        token.len = @intCast(value.len);
        token.expiration_s = expiration_s;
        token.source = source;
    }
};

/// The memory `resolve` works in. Zeroed by `resolve` before it returns, and by `wipe`. The
/// credentials file is here because a URL source's headers in it can hold a secret.
pub const Workspace = struct {
    credentials_file: [constants.google_credentials_file_bytes_max]u8,
    subject_token: [constants.google_subject_token_bytes_max]u8,
    request_body: [constants.google_request_body_bytes_max]u8,
    response: [constants.google_response_bytes_max]u8,
    federated_token: [constants.google_access_token_bytes_max]u8,

    pub fn wipe(workspace: *Workspace) void {
        std.crypto.secureZero(u8, &workspace.credentials_file);
        std.crypto.secureZero(u8, &workspace.subject_token);
        std.crypto.secureZero(u8, &workspace.request_body);
        std.crypto.secureZero(u8, &workspace.response);
        std.crypto.secureZero(u8, &workspace.federated_token);
    }
};

pub const Error = error{
    /// No source gave a token; the trace says what each did.
    NoCredentials,
};

pub const metadata_token_path = "/computeMetadata/v1/instance/service-accounts/default/token";
const cloud_platform_scope = "https://www.googleapis.com/auth/cloud-platform";
const impersonation_body = "{\"scope\":[\"" ++ cloud_platform_scope ++
    "\"],\"lifetime\":\"3600s\"}";

/// Finds an access token at `now_s` (seconds since the epoch; the expiry of what a service hands
/// out is judged against it), from the sources `sources` names. On success `token` holds it and
/// the trace says which source. `env` is the caller's view of the environment; the host gives the
/// file system, the network and nothing else here. Exported as `google_credentials_resolve`.
pub fn resolve(
    host: host_mod.Host,
    env: Env,
    now_s: u64,
    sources: Sources,
    workspace: *Workspace,
    token: *Token,
    trace: *Trace,
) Error!void {
    token.wipe();
    trace.* = .{};
    defer workspace.wipe();
    if (sources.workload_identity) {
        workload_identity(host, env, now_s, workspace, token, trace);
        if (trace.workload_identity == .used) return;
        // Once the variable is set, its answer is the answer.
        if (trace.workload_identity != .not_configured) return error.NoCredentials;
    } else if (env.get(credentials_variable) != null) {
        // The variable names the identity to use, whatever the mask says: never fall through.
        trace.workload_identity = .not_asked;
        return error.NoCredentials;
    }
    assert(trace.workload_identity == .not_configured);
    if (sources.metadata) {
        metadata_server(host, now_s, workspace, token, trace);
        if (trace.metadata == .used) return;
    }
    assert(token.len == 0);
    return error.NoCredentials;
}

fn workload_identity(
    host: host_mod.Host,
    env: Env,
    now_s: u64,
    workspace: *Workspace,
    token: *Token,
    trace: *Trace,
) void {
    const path = env.get(credentials_variable) orelse return;
    trace.step = .credentials_file;
    if (path.len > constants.path_bytes_max) {
        trace.workload_identity = .unreadable;
        return;
    }
    // A file over the bound is `FileTooLarge` here: refused, never cut.
    const text = host.read_file(path, &workspace.credentials_file) catch {
        trace.workload_identity = .unreadable;
        return;
    };
    const account = switch (parse.parse_credentials(text)) {
        .refused => |refused| return trace.note_unsupported(refused),
        .account => |account| account,
    };
    trace.note_account(account.service_account);
    trace.subject_source = account.source;
    trace.step = .subject_token;
    const subject = subject_token(host, &account, workspace, trace) orelse return;
    trace.step = .exchange;
    const federated = exchange(host, &account, subject, workspace, trace) orelse return;
    if (account.impersonation_url.len == 0) {
        accept(now_s, federated, token, &trace.workload_identity);
        return;
    }
    // The federated token is copied out of the response buffer, which the next call reuses.
    assert(federated.token.len <= workspace.federated_token.len);
    @memcpy(workspace.federated_token[0..federated.token.len], federated.token);
    const bearer = workspace.federated_token[0..federated.token.len];
    trace.step = .impersonation;
    const impersonated = impersonate(host, &account, bearer, workspace, trace) orelse return;
    accept(now_s, impersonated, token, &trace.workload_identity);
}

/// Takes a token unless it is out of date, or claims a life past `google_token_lifetime_max_s`
/// from now. An `expireTime` is held to the same bound `parse` holds `expires_in` to, so no
/// answer is trusted for longer than Google issues a token.
fn accept(now_s: u64, answer: parse.AccessToken, token: *Token, state: *State) void {
    assert(parse.access_token_valid(answer.token));
    if (answer.relative) assert(answer.expires <= constants.google_token_lifetime_max_s);
    if (!answer.relative) {
        if (answer.expires > now_s +| constants.google_token_lifetime_max_s) {
            state.* = .malformed;
            return;
        }
    }
    const expiration_s = if (answer.relative) now_s +| answer.expires else answer.expires;
    token.set(.workload_identity, answer.token, expiration_s);
    if (token.expired(now_s)) {
        token.wipe();
        state.* = .expired;
        return;
    }
    state.* = .used;
}

fn subject_token(
    host: host_mod.Host,
    account: *const parse.ExternalAccount,
    workspace: *Workspace,
    trace: *Trace,
) ?[]const u8 {
    assert(trace.step == .subject_token);
    const body = switch (account.source) {
        .file => host.read_file(account.location, &workspace.subject_token) catch {
            trace.workload_identity = .subject_unreadable;
            return null;
        },
        .url => subject_from_url(host, account, workspace, trace) orelse return null,
    };
    const token = if (account.json_field.len == 0)
        parse.subject_text(body)
    else
        parse.subject_json(body, account.json_field);
    return token catch {
        trace.workload_identity = .subject_unreadable;
        return null;
    };
}

/// A GET of the URL source, with its headers: an `Authorization` header is the request's whole
/// `Authorization` value, any other a secret extra header.
fn subject_from_url(
    host: host_mod.Host,
    account: *const parse.ExternalAccount,
    workspace: *Workspace,
    trace: *Trace,
) ?[]const u8 {
    assert(account.source == .url);
    const url = net.parse_url(account.location) catch unreachable; // `parse` checked it.
    assert(url.scheme == .https);
    var extra: [constants.google_source_headers_max]net.Header = undefined;
    var extra_count: u32 = 0;
    var authorization: []const u8 = "";
    for (account.source_headers()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            authorization = header.value;
            continue;
        }
        extra[extra_count] = .{ .name = header.name, .value = header.value, .secret = true };
        assert(extra[extra_count].valid());
        extra_count += 1;
    }
    var sink: net.BufferSink = .{ .buffer = &workspace.subject_token };
    var head: net.Head = .{};
    const request: net.Request = .{
        .scheme = .https,
        .host = url.host,
        .port = url.port,
        .target = url.target,
        .accept = "",
        .bearer = "",
        .authorization = authorization,
        .body_bytes_max = workspace.subject_token.len,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .extra_headers = extra[0..extra_count],
        .secret = true, // The headers may carry the runner's token; the answer is a token.
    };
    host.network().call(&request, &head, sink.sink()) catch {
        trace.workload_identity = .no_answer;
        return null;
    };
    if (head.status != 200) {
        trace.workload_identity = .refused;
        trace.status = head.status; // Not `note_refusal`: this body is not Google's.
        return null;
    }
    return sink.bytes();
}

fn build_form(
    workspace: *Workspace,
    account: *const parse.ExternalAccount,
    subject: []const u8,
) ?[]const u8 {
    var form: sigv4.Writer = .{ .buffer = &workspace.request_body };
    form.put("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&audience=");
    sigv4.put_encoded(&form, account.audience, false, false);
    form.put("&subject_token_type=");
    sigv4.put_encoded(&form, account.subject_token_type, false, false);
    form.put("&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token");
    form.put("&scope=");
    sigv4.put_encoded(&form, cloud_platform_scope, false, false);
    form.put("&subject_token=");
    sigv4.put_encoded(&form, subject, false, false);
    if (form.overflow) return null;
    return form.text();
}

/// The token exchange at STS. The answer, as slices of `workspace.response`, or null with the
/// trace set.
fn exchange(
    host: host_mod.Host,
    account: *const parse.ExternalAccount,
    subject: []const u8,
    workspace: *Workspace,
    trace: *Trace,
) ?parse.AccessToken {
    assert(trace.step == .exchange);
    const body = build_form(workspace, account, subject) orelse {
        trace.workload_identity = .subject_unreadable;
        return null;
    };
    var source: net.SliceSource = .{ .bytes = body };
    const request: net.Request = .{
        .scheme = .https,
        .host = parse.sts_host,
        .port = 443,
        .target = "/v1/token",
        .accept = "application/json",
        .bearer = "",
        .body_bytes_max = workspace.response.len,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = .post,
        .body = source.body(),
        .content_type = "application/x-www-form-urlencoded",
        .secret = true, // The subject token is in the body; the federated token in the answer.
    };
    const answer = call(host, &request, workspace, trace) orelse return null;
    return parse.parse_token_answer(answer) catch {
        trace.workload_identity = .malformed;
        return null;
    };
}

/// `generateAccessToken` at IAM Credentials, with the federated token as Bearer.
fn impersonate(
    host: host_mod.Host,
    account: *const parse.ExternalAccount,
    federated: []const u8,
    workspace: *Workspace,
    trace: *Trace,
) ?parse.AccessToken {
    assert(trace.step == .impersonation);
    const url = net.parse_url(account.impersonation_url) catch unreachable; // Checked exactly.
    assert(std.mem.eql(u8, url.host, parse.iam_host));
    var source: net.SliceSource = .{ .bytes = impersonation_body };
    const request: net.Request = .{
        .scheme = .https,
        .host = parse.iam_host,
        .port = 443,
        .target = url.target,
        .accept = "application/json",
        .bearer = federated,
        .body_bytes_max = workspace.response.len,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = .post,
        .body = source.body(),
        .content_type = "application/json",
        .secret = true, // The access token is in the answer.
    };
    const answer = call(host, &request, workspace, trace) orelse return null;
    return parse.parse_impersonation(answer) catch {
        trace.workload_identity = .malformed;
        return null;
    };
}

/// One call to STS or IAM Credentials: the answer of a 200, or null with the trace set.
fn call(
    host: host_mod.Host,
    request: *const net.Request,
    workspace: *Workspace,
    trace: *Trace,
) ?[]const u8 {
    assert(request.scheme == .https);
    assert(request.secret);
    var sink: net.BufferSink = .{ .buffer = &workspace.response };
    var head: net.Head = .{};
    host.network().call(request, &head, sink.sink()) catch {
        trace.workload_identity = .no_answer;
        return null;
    };
    if (head.status != 200) {
        trace.workload_identity = .refused;
        trace.note_refusal(head.status, sink.bytes());
        return null;
    }
    return sink.bytes();
}

fn metadata_server(
    host: host_mod.Host,
    now_s: u64,
    workspace: *Workspace,
    token: *Token,
    trace: *Trace,
) void {
    assert(trace.metadata == .not_asked);
    const flavor: net.Header = .{ .name = "Metadata-Flavor", .value = "Google" };
    var request = metadata.request(
        metadata_token_path,
        &workspace.response,
        constants.google_metadata_timeout_ms,
        constants.google_metadata_total_timeout_ms,
    );
    request.accept = "application/json";
    request.extra_headers = &.{flavor};
    var sink: net.BufferSink = .{ .buffer = &workspace.response };
    var head: net.Head = .{};
    const status = metadata.call(host, &request, &head, &sink) orelse {
        trace.metadata = .absent;
        return;
    };
    const answered_flavor = head.metadata_flavor.slice() orelse "";
    if (!std.mem.eql(u8, answered_flavor, "Google")) {
        trace.metadata = .not_gce;
        return;
    }
    if (status != 200) {
        trace.metadata = if (status == 404) .no_service_account else .refused;
        trace.note_refusal(status, sink.bytes());
        return;
    }
    const answer = parse.parse_token_answer(sink.bytes()) catch {
        trace.metadata = .malformed;
        return;
    };
    token.set(.metadata, answer.token, now_s +| answer.expires);
    if (token.expired(now_s)) {
        token.wipe();
        trace.metadata = .expired;
        return;
    }
    trace.metadata = .used;
}
