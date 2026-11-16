//! Reading what Google hands zbx: the `external_account` credentials file that
//! `GOOGLE_APPLICATION_CREDENTIALS` names, a JSON subject token, and the answers of STS, IAM
//! Credentials and the metadata server, and the error code of a refusal. Each reader works over a
//! body already in memory with the bounded member reader of `src/cloud/json.zig`, allocates
//! nothing and returns slices of that body, so what it returns is as secret as the body and the
//! caller zeroes the body.
//!
//! The credentials file is checked whole before anything is sent. Only workload identity
//! federation with a file or an HTTPS URL subject token, exchanged at `sts.googleapis.com` and
//! optionally impersonating a service account at `iamcredentials.googleapis.com`, is accepted;
//! each other shape is refused with its own reason (`Refusal`), so the user is told which field
//! zbx does not support. A value that is escaped is refused: none of the values zbx reads ever
//! needs an escape, and Go's encoder writes `&` as `\u0026`, so a URL with a query that a Go
//! tool wrote is refused rather than half-read (recorded in the slice's handoff).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const json = @import("../cloud/json.zig");
const net = @import("../registry/net.zig");

pub const Error = json.Error;

pub const sts_url = "https://sts.googleapis.com/v1/token";
pub const sts_host = "sts.googleapis.com";
pub const iam_host = "iamcredentials.googleapis.com";
pub const universe_domain = "googleapis.com";
const workforce_prefix = "//iam.googleapis.com/locations/global/workforcePools/";
const impersonation_prefix = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/";
const impersonation_suffix = ":generateAccessToken";

/// Why a credentials file is not used. Each names what the user has and what zbx would need.
pub const Refusal = enum {
    /// Not JSON, not an object, a required field missing or a value out of its bounds.
    malformed,
    /// `"type": "service_account"`: a key file. Workload identity federation is the fix.
    service_account_key,
    /// `"type": "authorized_user"`: gcloud's user credentials.
    authorized_user,
    /// Any other `type`; `Parsed.type_name` holds it when it is a plain name.
    other_type,
    /// A `token_url` other than STS's.
    token_url,
    /// An impersonation URL off `iamcredentials.googleapis.com` or not `generateAccessToken`.
    impersonation_url,
    /// A `universe_domain` other than `googleapis.com`.
    universe_domain,
    /// A workforce pool audience, or `workforce_pool_user_project`.
    workforce_pool,
    /// `credential_source.executable`.
    executable,
    /// `credential_source.environment_id` (`aws1`): an AWS-sourced account.
    aws,
    /// `credential_source.certificate`: an X.509 source.
    certificate,
    /// `credential_source.url` over plain HTTP (Azure's managed identity endpoint among them).
    plain_http_url,
    /// A `credential_source` with neither `file` nor `url`, or with both.
    no_source,
};

pub const SourceKind = enum { file, url };

pub const Header = struct { name: []const u8, value: []const u8 };

/// A usable `external_account` file, as slices of the file's text.
pub const ExternalAccount = struct {
    audience: []const u8,
    subject_token_type: []const u8,
    source: SourceKind,
    /// The file's path, or the URL (HTTPS).
    location: []const u8,
    /// Empty for a text subject token; the field name for a JSON one.
    json_field: []const u8 = "",
    /// For a URL source: its headers (`credential_source.headers`), which may hold a secret.
    headers: [constants.google_source_headers_max]Header = undefined,
    headers_count: u32 = 0,
    /// The impersonation URL whole, or empty for none.
    impersonation_url: []const u8 = "",
    /// The service account the impersonation URL names; empty for none.
    service_account: []const u8 = "",

    pub fn source_headers(account: *const ExternalAccount) []const Header {
        assert(account.headers_count <= account.headers.len);
        return account.headers[0..account.headers_count];
    }
};

pub const Parsed = union(enum) {
    account: ExternalAccount,
    refused: Refused,
};

pub const Refused = struct {
    reason: Refusal,
    /// For `other_type`: the type when it is a plain lower-case name, else empty.
    type_name: []const u8 = "",
};

/// Reads a credentials file. A refusal is an answer, never an error: the caller reports it.
pub fn parse_credentials(text: []const u8) Parsed {
    const top_type = string_member(text, "type") orelse return refuse(.malformed);
    if (!std.mem.eql(u8, top_type, "external_account")) return refuse_type(top_type);
    return parse_external_account(text) catch refuse(.malformed);
}

fn refuse(reason: Refusal) Parsed {
    return .{ .refused = .{ .reason = reason } };
}

fn refuse_type(name: []const u8) Parsed {
    if (std.mem.eql(u8, name, "service_account")) return refuse(.service_account_key);
    if (std.mem.eql(u8, name, "authorized_user")) return refuse(.authorized_user);
    var shown: []const u8 = name;
    if (name.len == 0 or name.len > constants.google_type_name_bytes_max) shown = "";
    for (shown) |byte| {
        if (!std.ascii.isLower(byte) and byte != '_') shown = "";
    }
    assert(shown.len <= constants.google_type_name_bytes_max);
    return .{ .refused = .{ .reason = .other_type, .type_name = shown } };
}

/// A member that is a plain string, or null when it is absent, not a string, escaped or the
/// object is malformed.
fn string_member(object: []const u8, name: []const u8) ?[]const u8 {
    const value = (json.member(object, name) catch return null) orelse return null;
    return value.plain();
}

/// A member that, when present, must be a plain string within `google_field_bytes_max`.
fn optional_field(object: []const u8, name: []const u8) Error!?[]const u8 {
    const value = (try json.member(object, name)) orelse return null;
    const text = value.plain() orelse return error.Malformed;
    if (!field_valid(text)) return error.Malformed;
    return text;
}

fn required_field(object: []const u8, name: []const u8) Error![]const u8 {
    return (try optional_field(object, name)) orelse error.Malformed;
}

/// Printable, without blanks, within the field bound: what an audience, a type, a path or a URL
/// in a credentials file is.
fn field_valid(text: []const u8) bool {
    if (text.len == 0 or text.len > constants.google_field_bytes_max) return false;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    return true;
}

fn parse_external_account(text: []const u8) Error!Parsed {
    if (try optional_field(text, "universe_domain")) |domain| {
        if (!std.mem.eql(u8, domain, universe_domain)) return refuse(.universe_domain);
    }
    if (try optional_field(text, "token_url")) |url| {
        if (!std.mem.eql(u8, url, sts_url)) return refuse(.token_url);
    }
    var account: ExternalAccount = .{
        .audience = try required_field(text, "audience"),
        .subject_token_type = try required_field(text, "subject_token_type"),
        .source = .file,
        .location = "",
    };
    if (std.mem.startsWith(u8, account.audience, workforce_prefix)) {
        return refuse(.workforce_pool);
    }
    if (try json.member(text, "workforce_pool_user_project") != null) {
        return refuse(.workforce_pool);
    }
    if (try optional_field(text, "service_account_impersonation_url")) |url| {
        account.service_account = impersonated_account(url) orelse
            return refuse(.impersonation_url);
        account.impersonation_url = url;
    }
    const source = (try json.member(text, "credential_source")) orelse return refuse(.no_source);
    if (source.kind != .object) return error.Malformed;
    if (try source_refusal(source.text)) |reason| return refuse(reason);
    try read_source(source.text, &account);
    assert(account.location.len > 0);
    return .{ .account = account };
}

/// The service account an impersonation URL names, or null when the URL is not exactly
/// `impersonation_prefix`, the email and `:generateAccessToken`.
pub fn impersonated_account(url: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, url, impersonation_prefix)) return null;
    if (!std.mem.endsWith(u8, url, impersonation_suffix)) return null;
    if (url.len <= impersonation_prefix.len + impersonation_suffix.len) return null;
    const email = url[impersonation_prefix.len .. url.len - impersonation_suffix.len];
    if (!email_valid(email)) return null;
    return email;
}

/// A service account's email: letters, digits and `.-_`, one `@` with text on both sides.
pub fn email_valid(email: []const u8) bool {
    if (email.len < 3 or email.len > constants.google_service_account_bytes_max) return false;
    var at_signs: u32 = 0;
    for (email) |byte| {
        if (byte == '@') {
            at_signs += 1;
            continue;
        }
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '-' and byte != '_') {
            return false;
        }
    }
    if (at_signs != 1) return false;
    return email[0] != '@' and email[email.len - 1] != '@';
}

/// The reason a `credential_source` is of a kind zbx does not support, or null.
fn source_refusal(source: []const u8) Error!?Refusal {
    if (try json.member(source, "executable") != null) return .executable;
    if (try json.member(source, "certificate") != null) return .certificate;
    if (try json.member(source, "environment_id")) |value| {
        const id = value.plain() orelse return error.Malformed;
        if (std.mem.startsWith(u8, id, "aws")) return .aws;
        return .no_source;
    }
    const file = try json.member(source, "file");
    const url = try json.member(source, "url");
    if ((file == null) == (url == null)) return .no_source;
    if (url) |value| {
        const text = value.plain() orelse return error.Malformed;
        if (std.ascii.startsWithIgnoreCase(text, "http://")) return .plain_http_url;
    }
    return null;
}

fn read_source(source: []const u8, account: *ExternalAccount) Error!void {
    if (try optional_field(source, "file")) |path| {
        account.source = .file;
        account.location = path;
        if (try json.member(source, "headers") != null) return error.Malformed;
    } else {
        const url = try required_field(source, "url");
        const parsed = net.parse_url(url) catch return error.Malformed;
        if (parsed.scheme != .https) return error.Malformed;
        account.source = .url;
        account.location = url;
        if (try json.member(source, "headers")) |headers| {
            if (headers.kind != .object) return error.Malformed;
            try read_headers(headers.text, account);
        }
    }
    if (try json.member(source, "format")) |format| {
        if (format.kind != .object) return error.Malformed;
        const kind = try required_field(format.text, "type");
        if (std.mem.eql(u8, kind, "json")) {
            const name = try required_field(format.text, "subject_token_field_name");
            if (name.len > constants.google_field_name_bytes_max) return error.Malformed;
            account.json_field = name;
        } else if (!std.mem.eql(u8, kind, "text")) {
            return error.Malformed;
        }
    }
    assert(account.location.len > 0);
}

fn read_headers(object: []const u8, account: *ExternalAccount) Error!void {
    var members = try json.Members.init(object);
    while (try members.next()) |header| {
        if (account.headers_count == account.headers.len) return error.Malformed;
        if (!header_name_valid(header.name)) return error.Malformed;
        // Two spellings of one header would send it twice, and the server would pick one.
        for (account.source_headers()) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier.name, header.name)) return error.Malformed;
        }
        const value = header.value.plain() orelse return error.Malformed;
        if (value.len == 0 or value.len > constants.net_header_value_bytes_max) {
            return error.Malformed;
        }
        for (value) |byte| {
            if (byte < 0x20 or byte >= 0x7f) return error.Malformed;
        }
        account.headers[account.headers_count] = .{ .name = header.name, .value = value };
        account.headers_count += 1;
    }
    assert(account.headers_count <= constants.google_source_headers_max);
}

/// A header name a URL source may send: an HTTP token, and not one the network sets itself
/// (`Authorization` is allowed: it is how a runner's request token is sent, and the caller
/// carries it as the request's whole `Authorization` value).
fn header_name_valid(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    }
    if (std.ascii.eqlIgnoreCase(name, "authorization")) return true;
    const header: net.Header = .{ .name = name, .value = "x" };
    return header.valid();
}

/// An access token: what STS, IAM Credentials or the metadata server returns, `ya29.` and
/// URL-safe characters, within `google_access_token_bytes_max`.
pub fn access_token_valid(text: []const u8) bool {
    if (text.len < 16 or text.len > constants.google_access_token_bytes_max) return false;
    for (text) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (std.mem.indexOfScalar(u8, "._-~+/=", byte) != null) continue;
        return false;
    }
    return true;
}

/// A subject token: printable without blanks, within `google_subject_token_bytes_max`. An OIDC
/// JWT, or whatever opaque token the provider issues.
pub fn subject_token_valid(text: []const u8) bool {
    if (text.len == 0 or text.len > constants.google_subject_token_bytes_max) return false;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    return true;
}

/// The subject token in a text source: the whole text, without trailing line ends or blanks (a
/// file written by `echo` ends in one).
pub fn subject_text(body: []const u8) Error![]const u8 {
    const token = std.mem.trimEnd(u8, body, " \t\r\n");
    if (!subject_token_valid(token)) return error.Malformed;
    return token;
}

/// The subject token in a JSON source: the string member `field` of the top-level object.
pub fn subject_json(body: []const u8, field: []const u8) Error![]const u8 {
    assert(field.len > 0);
    const value = (try json.member(body, field)) orelse return error.Malformed;
    const token = value.plain() orelse return error.Malformed;
    if (!subject_token_valid(token)) return error.Malformed;
    return token;
}

/// The member `name`, which must be there and be a plain string.
fn plain_member(body: []const u8, name: []const u8) Error![]const u8 {
    const value = (try json.member(body, name)) orelse return error.Malformed;
    return value.plain() orelse error.Malformed;
}

/// An access token and when it stops being valid.
pub const AccessToken = struct {
    token: []const u8,
    /// Seconds since the epoch for an absolute expiry; see `relative`.
    expires: u64,
    /// `expires` is seconds from now (`expires_in`) rather than a time (`expireTime`).
    relative: bool,
};

/// STS's token-exchange answer, or the metadata server's token: `access_token` and
/// `expires_in` (the same two members in both).
pub fn parse_token_answer(body: []const u8) Error!AccessToken {
    const token = try plain_member(body, "access_token");
    if (!access_token_valid(token)) return error.Malformed;
    const lifetime = (try json.member(body, "expires_in")) orelse return error.Malformed;
    const seconds = json.whole_seconds(lifetime, constants.google_token_lifetime_max_s) orelse
        return error.Malformed;
    if (seconds == 0) return error.Malformed;
    return .{ .token = token, .expires = seconds, .relative = true };
}

/// IAM Credentials' `generateAccessToken` answer: `accessToken` and `expireTime` (RFC 3339).
pub fn parse_impersonation(body: []const u8) Error!AccessToken {
    const token = try plain_member(body, "accessToken");
    if (!access_token_valid(token)) return error.Malformed;
    const expiry = try plain_member(body, "expireTime");
    const expiration_s = json.parse_timestamp(expiry) orelse return error.Malformed;
    return .{ .token = token, .expires = expiration_s, .relative = false };
}

/// The error code of a refusal, from any of Google's three shapes: OAuth's
/// `{"error":"invalid_grant"}` (STS), the API's `{"error":{"status":"PERMISSION_DENIED"}}` (IAM
/// Credentials) and the registry's `{"errors":[{"code":"DENIED"}]}`. Only letters, digits and `_`,
/// at most `google_error_code_bytes_max`; anything else is null, because the code is shown to the
/// user and a message never is.
pub fn error_code(body: []const u8) ?[]const u8 {
    const raw = error_code_raw(body) catch return null;
    const code = raw orelse return null;
    if (code.len == 0 or code.len > constants.google_error_code_bytes_max) return null;
    for (code) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return null;
    }
    return code;
}

fn error_code_raw(body: []const u8) Error!?[]const u8 {
    if (try json.member(body, "error")) |value| {
        switch (value.kind) {
            .string => return value.plain(),
            .object => {
                const status = (try json.member(value.text, "status")) orelse return null;
                return status.plain();
            },
            else => return null,
        }
    }
    const errors = (try json.member(body, "errors")) orelse return null;
    if (errors.kind != .array) return null;
    const first = (try json.first_element(errors.text)) orelse return null;
    if (first.kind != .object) return null;
    const code = (try json.member(first.text, "code")) orelse return null;
    return code.plain();
}
