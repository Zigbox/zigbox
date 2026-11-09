//! Finding the AWS credentials a command runs with: the `aws_credentials_resolve` of the library.
//! It knows nothing of pulls or registries; ECR pull calls it, and so will ECR push.
//!
//! Three sources, tried in this order, the first that gives credentials wins:
//!
//! 1. The environment: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`
//!    if the key is temporary. Used as given; never expires here.
//! 2. Web identity, the way Kubernetes service accounts work: `AWS_ROLE_ARN` and
//!    `AWS_WEB_IDENTITY_TOKEN_FILE` (and `AWS_ROLE_SESSION_NAME`, default `zbx`). The token file is
//!    read and sent in an unsigned STS `AssumeRoleWithWebIdentity` call. Once the pair is set, this
//!    source is the answer, success or not: a configured role that fails is reported, and zbx does
//!    not quietly go on to another identity, because the user said which one to use.
//! 3. The instance metadata service, version 2 only: a PUT for a session token, then the role's
//!    credentials. Plain HTTP to the link-local address, never through a proxy (a proxy cannot
//!    reach it, and must not see a credential), with a short timeout, so a machine that is not on
//!    AWS finds out fast. Version 1 is never used: if the token call is refused, the answer is
//!    "no credentials", not a weaker request.
//!
//! Nothing here is stored. The caller owns the `Credentials` and the `Workspace` and calls `wipe`
//! on both when it is done; `resolve` itself zeroes every buffer it used for a secret before it
//! returns. The `Trace` says what each source did, in words that hold no secret, so the caller can
//! tell the user why nothing was found.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const net = @import("../registry/net.zig");
const ecr = @import("ecr.zig");
const parse = @import("parse.zig");
const sigv4 = @import("sigv4.zig");

pub const Source = enum { environment, web_identity, instance_metadata };

/// What one source did. `used` is the only success.
pub const State = enum {
    /// Nothing for it was set (or, for the metadata service, nothing answered).
    not_configured,
    /// Some of what it needs was set, not all.
    incomplete,
    /// Switched off on purpose (`AWS_EC2_METADATA_DISABLED=true`).
    disabled,
    used,
    /// The token file could not be read, or is empty or not a token.
    unreadable,
    /// The service answered and said no (a status that is not 200). `Trace.error_code` has its
    /// code when it sent one.
    refused,
    /// The service could not be reached or the call failed.
    no_answer,
    /// An answer that is not the document it should be.
    malformed,
    /// Credentials that are, or are about to be, out of date.
    expired,
};

pub const Trace = struct {
    environment: State = .not_configured,
    web_identity: State = .not_configured,
    instance_metadata: State = .not_configured,
    /// The error code STS sent when it refused (letters and digits), empty for none.
    error_code: [constants.aws_error_code_bytes_max]u8 = undefined,
    error_code_len: u32 = 0,
    /// The status of the last refusal, zero for none.
    status: u16 = 0,

    pub fn code(trace: *const Trace) []const u8 {
        assert(trace.error_code_len <= trace.error_code.len);
        return trace.error_code[0..trace.error_code_len];
    }

    fn note_refusal(trace: *Trace, status: u16, body: []const u8) void {
        trace.status = status;
        const found = parse.error_code(body) orelse return;
        assert(found.len <= trace.error_code.len);
        @memcpy(trace.error_code[0..found.len], found);
        trace.error_code_len = @intCast(found.len);
    }
};

pub const Error = error{
    /// No source gave credentials; the trace says what each did.
    NoCredentials,
};

/// Credentials in their own storage, so they need no allocation and can be wiped.
pub const Credentials = struct {
    access_key_id: [constants.aws_key_id_bytes_max]u8,
    access_key_id_len: u32,
    secret_access_key: [constants.aws_secret_key_bytes_max]u8,
    secret_access_key_len: u32,
    session_token: [constants.aws_session_token_bytes_max]u8,
    session_token_len: u32,
    /// Seconds since the epoch; zero for credentials that do not expire (the environment's).
    expiration_s: u64,
    source: Source,

    pub fn key(credentials: *const Credentials) sigv4.Key {
        assert(credentials.access_key_id_len > 0);
        assert(credentials.secret_access_key_len > 0);
        const secret_len = credentials.secret_access_key_len;
        return .{
            .access_key_id = credentials.access_key_id[0..credentials.access_key_id_len],
            .secret_access_key = credentials.secret_access_key[0..secret_len],
            .session_token = credentials.session_token[0..credentials.session_token_len],
        };
    }

    pub fn wipe(credentials: *Credentials) void {
        std.crypto.secureZero(u8, &credentials.access_key_id);
        std.crypto.secureZero(u8, &credentials.secret_access_key);
        std.crypto.secureZero(u8, &credentials.session_token);
        credentials.access_key_id_len = 0;
        credentials.secret_access_key_len = 0;
        credentials.session_token_len = 0;
        credentials.expiration_s = 0;
    }

    /// Whether they are out of date at `now_s`, or will be within `aws_credentials_margin_s`.
    pub fn expired(credentials: *const Credentials, now_s: u64) bool {
        if (credentials.expiration_s == 0) return false;
        return credentials.expiration_s <= now_s + constants.aws_credentials_margin_s;
    }

    fn set(
        credentials: *Credentials,
        source: Source,
        key_id: []const u8,
        secret: []const u8,
        token: []const u8,
        expiration_s: u64,
    ) void {
        assert(parse.key_id_valid(key_id));
        assert(parse.secret_valid(secret));
        if (token.len > 0) assert(parse.token_valid(token));
        credentials.wipe();
        @memcpy(credentials.access_key_id[0..key_id.len], key_id);
        credentials.access_key_id_len = @intCast(key_id.len);
        @memcpy(credentials.secret_access_key[0..secret.len], secret);
        credentials.secret_access_key_len = @intCast(secret.len);
        @memcpy(credentials.session_token[0..token.len], token);
        credentials.session_token_len = @intCast(token.len);
        credentials.expiration_s = expiration_s;
        credentials.source = source;
    }
};

/// The memory `resolve` works in. Zeroed by `resolve` before it returns, and by `wipe`.
pub const Workspace = struct {
    token_file: [constants.aws_web_identity_token_bytes_max]u8,
    request_body: [constants.aws_request_body_bytes_max]u8,
    response: [constants.aws_response_bytes_max]u8,

    pub fn wipe(workspace: *Workspace) void {
        std.crypto.secureZero(u8, &workspace.token_file);
        std.crypto.secureZero(u8, &workspace.request_body);
        std.crypto.secureZero(u8, &workspace.response);
    }
};

const sts_service = "sts";
const imds_host = "169.254.169.254";
const role_path = "/latest/meta-data/iam/security-credentials/";

/// Finds credentials for a call in `region` (the STS endpoint is the region's). On success
/// `credentials` holds them and the trace says which source. The one function the library
/// exports; see the module comment for the order and the rules.
pub fn resolve(
    host: host_mod.Host,
    region: []const u8,
    workspace: *Workspace,
    credentials: *Credentials,
    trace: *Trace,
) Error!void {
    assert(ecr.valid_region(region));
    credentials.wipe();
    trace.* = .{};
    defer workspace.wipe();
    if (from_environment(host, credentials, trace)) return;
    // A configured role is the answer, whatever it says: no falling through to another identity.
    web_identity(host, region, workspace, credentials, trace);
    if (trace.web_identity == .used) return;
    if (trace.web_identity != .not_configured) return error.NoCredentials;
    instance_metadata(host, workspace, credentials, trace);
    if (trace.instance_metadata == .used) return;
    return error.NoCredentials;
}

fn from_environment(host: host_mod.Host, credentials: *Credentials, trace: *Trace) bool {
    const key_id = host.environment("AWS_ACCESS_KEY_ID", constants.aws_key_id_bytes_max);
    const secret = host.environment("AWS_SECRET_ACCESS_KEY", constants.aws_secret_key_bytes_max);
    const token = host.environment("AWS_SESSION_TOKEN", constants.aws_session_token_bytes_max);
    if (key_id == null and secret == null) return false;
    if (key_id == null or secret == null) {
        trace.environment = .incomplete;
        return false;
    }
    const token_text = token orelse "";
    if (!parse.key_id_valid(key_id.?) or !parse.secret_valid(secret.?) or
        (token_text.len > 0 and !parse.token_valid(token_text)))
    {
        trace.environment = .malformed;
        return false;
    }
    credentials.set(.environment, key_id.?, secret.?, token_text, 0);
    trace.environment = .used;
    return true;
}

/// Reads a token file into `buffer`, trims trailing blanks, and checks it looks like a JWT: base64
/// url characters and dots. Null for any other file.
fn read_token(host: host_mod.Host, path: []const u8, buffer: []u8) ?[]const u8 {
    const content = host.read_file(path, buffer) catch return null;
    const token = std.mem.trimEnd(u8, content, " \t\r\n");
    if (token.len == 0) return null;
    for (token) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (byte == '-' or byte == '_' or byte == '.' or byte == '=') continue;
        return null;
    }
    return token;
}

fn web_identity(
    host: host_mod.Host,
    region: []const u8,
    workspace: *Workspace,
    credentials: *Credentials,
    trace: *Trace,
) void {
    const role = host.environment("AWS_ROLE_ARN", constants.aws_role_arn_bytes_max);
    const path = host.environment("AWS_WEB_IDENTITY_TOKEN_FILE", constants.path_bytes_max);
    if (role == null and path == null) return;
    if (role == null or path == null or role.?.len == 0 or path.?.len == 0) {
        trace.web_identity = .incomplete;
        return;
    }
    const session_name = host.environment(
        "AWS_ROLE_SESSION_NAME",
        constants.aws_role_session_name_bytes_max,
    ) orelse "zbx";
    const token = read_token(host, path.?, &workspace.token_file) orelse {
        trace.web_identity = .unreadable;
        return;
    };
    var form: sigv4.Writer = .{ .buffer = &workspace.request_body };
    form.put("Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=");
    sigv4.put_encoded(&form, role.?, false, false);
    form.put("&RoleSessionName=");
    sigv4.put_encoded(&form, session_name, false, false);
    form.put("&WebIdentityToken=");
    sigv4.put_encoded(&form, token, false, false);
    if (form.overflow) {
        trace.web_identity = .malformed;
        return;
    }
    var host_buffer: [constants.aws_service_bytes_max + constants.aws_region_bytes_max + 15]u8 =
        undefined;
    const sts_host = ecr.service_host(&host_buffer, sts_service, region);
    var source: net.SliceSource = .{ .bytes = form.text() };
    var sink: net.BufferSink = .{ .buffer = &workspace.response };
    var head: net.Head = .{};
    const request: net.Request = .{
        .scheme = .https,
        .host = sts_host,
        .port = 443,
        .target = "/",
        .accept = "text/xml",
        .bearer = "",
        .body_bytes_max = workspace.response.len,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = .post,
        .body = source.body(),
        .content_type = "application/x-www-form-urlencoded",
    };
    host.network().call(&request, &head, sink.sink()) catch {
        trace.web_identity = .no_answer;
        return;
    };
    if (head.status != 200) {
        trace.web_identity = .refused;
        trace.note_refusal(head.status, sink.bytes());
        return;
    }
    const parsed = parse.parse_sts(sink.bytes()) catch {
        trace.web_identity = .malformed;
        return;
    };
    accept(host, parsed, .web_identity, credentials, &trace.web_identity);
}

/// Takes parsed credentials unless they are out of date.
fn accept(
    host: host_mod.Host,
    parsed: parse.Credentials,
    source: Source,
    credentials: *Credentials,
    state: *State,
) void {
    credentials.set(
        source,
        parsed.access_key_id,
        parsed.secret_access_key,
        parsed.session_token,
        parsed.expiration_s,
    );
    if (credentials.expired(host.time_now())) {
        credentials.wipe();
        state.* = .expired;
        return;
    }
    state.* = .used;
}

/// One call to the metadata service, never through a proxy. The status, or null if the call failed.
fn imds_call(
    host: host_mod.Host,
    request: *const net.Request,
    sink: *net.BufferSink,
) ?u16 {
    assert(request.proxy == .never);
    assert(request.scheme == .http);
    var head: net.Head = .{};
    sink.len = 0;
    host.network().call(request, &head, sink.sink()) catch return null;
    return head.status;
}

fn instance_metadata(
    host: host_mod.Host,
    workspace: *Workspace,
    credentials: *Credentials,
    trace: *Trace,
) void {
    if (host.environment("AWS_EC2_METADATA_DISABLED", 8)) |value| {
        if (std.ascii.eqlIgnoreCase(value, "true")) {
            trace.instance_metadata = .disabled;
            return;
        }
    }
    var sink: net.BufferSink = .{ .buffer = &workspace.response };
    var empty: net.SliceSource = .{ .bytes = "" };
    var ttl_text: [8]u8 = undefined;
    const ttl = std.fmt.bufPrint(&ttl_text, "{d}", .{constants.aws_imds_token_ttl_s}) catch
        unreachable; // A u32 constant below 1000 fits eight bytes.
    const ttl_header: net.Header = .{
        .name = "X-aws-ec2-metadata-token-ttl-seconds",
        .value = ttl,
    };
    var request = imds_request("/latest/api/token", &workspace.response);
    request.method = .put;
    request.body = empty.body();
    request.extra_headers = &.{ttl_header};
    const status = imds_call(host, &request, &sink) orelse return;
    // Anything but a token is the end: version 1 is never asked.
    if (status != 200 or !parse.imds_token_valid(sink.bytes())) {
        trace.instance_metadata = .refused;
        trace.status = status;
        return;
    }
    var session: [constants.aws_imds_token_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &session);
    @memcpy(session[0..sink.len], sink.bytes());
    fetch_role(host, session[0..sink.len], workspace, credentials, trace);
}

fn imds_request(target: []const u8, response: []u8) net.Request {
    return .{
        .scheme = .http,
        .host = imds_host,
        .port = 80,
        .target = target,
        .accept = "",
        .bearer = "",
        .body_bytes_max = response.len,
        .idle_timeout_ms = constants.aws_imds_timeout_ms,
        .total_timeout_ms = constants.aws_imds_total_timeout_ms,
        .proxy = .never,
    };
}

fn fetch_role(
    host: host_mod.Host,
    session: []const u8,
    workspace: *Workspace,
    credentials: *Credentials,
    trace: *Trace,
) void {
    assert(parse.imds_token_valid(session));
    var sink: net.BufferSink = .{ .buffer = &workspace.response };
    const token_header: net.Header = .{
        .name = "X-aws-ec2-metadata-token",
        .value = session,
        .secret = true,
    };
    var request = imds_request(role_path, &workspace.response);
    request.extra_headers = &.{token_header};
    const listed = imds_call(host, &request, &sink) orelse {
        trace.instance_metadata = .no_answer;
        return;
    };
    if (listed != 200) {
        trace.instance_metadata = .refused;
        trace.status = listed;
        return;
    }
    const role = parse.parse_imds_role(sink.bytes()) catch {
        trace.instance_metadata = .malformed;
        return;
    };
    var target_buffer: [role_path.len + constants.aws_role_name_bytes_max]u8 = undefined;
    const target = std.fmt.bufPrint(&target_buffer, "{s}{s}", .{ role_path, role }) catch
        unreachable; // The role name is at most `aws_role_name_bytes_max`, checked by the parser.
    request = imds_request(target, &workspace.response);
    request.extra_headers = &.{token_header};
    // The role name lives in the response buffer, which the next call overwrites; `target` is
    // a copy.
    const status = imds_call(host, &request, &sink) orelse {
        trace.instance_metadata = .no_answer;
        return;
    };
    if (status != 200) {
        trace.instance_metadata = .refused;
        trace.status = status;
        return;
    }
    const parsed = parse.parse_imds(sink.bytes()) catch {
        trace.instance_metadata = .malformed;
        return;
    };
    accept(host, parsed, .instance_metadata, credentials, &trace.instance_metadata);
}
