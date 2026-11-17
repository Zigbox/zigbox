//! Reading what AWS sends back: the STS `AssumeRoleWithWebIdentity` answer (XML), the instance
//! metadata service's credentials (JSON), ECR's `GetAuthorizationToken` answer (JSON) and the
//! error code of a refused call. Each parser is a bounded scan over a body that is already in
//! memory, allocates nothing and returns slices of that body, so what it returns is a secret as
//! long as the body is, and the caller zeroes the body.
//!
//! The scans are deliberately small: they find a named field and check its characters, and refuse
//! (`Malformed`) anything else. They do not understand nesting or escapes: a value with a backslash
//! is refused, because no AWS credential has one, and a field that is not where it was expected is
//! not guessed at. Everything that comes out has been checked against the character set and the
//! bound of its kind, so a caller can put it in a header without a second look.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const cloud_json = @import("../cloud/json.zig");

pub const Error = error{Malformed};

/// Temporary credentials, as slices of the body they were read from.
pub const Credentials = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: []const u8,
    /// Seconds since the epoch.
    expiration_s: u64,
};

/// ECR's authorization token: the base64 text AWS sent, which is `AWS:<password>` encoded and is
/// used as is in `Authorization: Basic`, and when it stops being valid.
pub const EcrToken = struct {
    basic: []const u8,
    expiration_s: u64,
};

// The flat JSON field readers and the timestamp reader moved to `src/cloud/json.zig` (M6d), where
// Google's sources share them; these names keep every AWS caller as it was.
const json_string = cloud_json.string_field;
const json_number = cloud_json.number_field;
const parse_seconds = cloud_json.parse_seconds;
pub const parse_timestamp = cloud_json.parse_timestamp;

/// The text of the first `<name>...</name>` in `body`, or null.
fn xml_element(body: []const u8, comptime name: []const u8) ?[]const u8 {
    const open = "<" ++ name ++ ">";
    const close = "</" ++ name ++ ">";
    const start = std.mem.indexOf(u8, body, open) orelse return null;
    const text_start = start + open.len;
    const end = std.mem.indexOfPos(u8, body, text_start, close) orelse return null;
    return body[text_start..end];
}

pub fn key_id_valid(text: []const u8) bool {
    if (text.len < 16 or text.len > constants.aws_key_id_bytes_max) return false;
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return false;
    }
    return true;
}

pub fn secret_valid(text: []const u8) bool {
    if (text.len < 16 or text.len > constants.aws_secret_key_bytes_max) return false;
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '/' and byte != '+' and byte != '=') {
            return false;
        }
    }
    return true;
}

/// A session token is base64, in either alphabet (AWS has used both), and may be long.
pub fn token_valid(text: []const u8) bool {
    if (text.len < 16 or text.len > constants.aws_session_token_bytes_max) return false;
    for (text) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (byte == '/' or byte == '+' or byte == '=' or byte == '-' or byte == '_') continue;
        return false;
    }
    return true;
}

/// The credentials in an STS `AssumeRoleWithWebIdentity` XML answer.
pub fn parse_sts(body: []const u8) Error!Credentials {
    const section = xml_element(body, "Credentials") orelse return error.Malformed;
    const key_id = xml_element(section, "AccessKeyId") orelse return error.Malformed;
    const secret = xml_element(section, "SecretAccessKey") orelse return error.Malformed;
    const token = xml_element(section, "SessionToken") orelse return error.Malformed;
    const expiry = xml_element(section, "Expiration") orelse return error.Malformed;
    return checked(key_id, secret, token, expiry);
}

/// The credentials in the metadata service's role document.
pub fn parse_imds(body: []const u8) Error!Credentials {
    const code = json_string(body, "Code") orelse return error.Malformed;
    if (!std.mem.eql(u8, code, "Success")) return error.Malformed;
    const key_id = json_string(body, "AccessKeyId") orelse return error.Malformed;
    const secret = json_string(body, "SecretAccessKey") orelse return error.Malformed;
    const token = json_string(body, "Token") orelse return error.Malformed;
    const expiry = json_string(body, "Expiration") orelse return error.Malformed;
    return checked(key_id, secret, token, expiry);
}

fn checked(
    key_id: []const u8,
    secret: []const u8,
    token: []const u8,
    expiry: []const u8,
) Error!Credentials {
    if (!key_id_valid(key_id)) return error.Malformed;
    if (!secret_valid(secret)) return error.Malformed;
    if (!token_valid(token)) return error.Malformed;
    const expiration_s = parse_timestamp(expiry) orelse return error.Malformed;
    assert(key_id.len >= 16);
    return .{
        .access_key_id = key_id,
        .secret_access_key = secret,
        .session_token = token,
        .expiration_s = expiration_s,
    };
}

/// The role name the metadata service lists: the first line of its answer, which must be a
/// role name (letters, digits and `+=,.@_-`).
pub fn parse_imds_role(body: []const u8) Error![]const u8 {
    const end = std.mem.indexOfAny(u8, body, "\r\n") orelse body.len;
    const name = body[0..end];
    if (name.len == 0 or name.len > constants.aws_role_name_bytes_max) return error.Malformed;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (std.mem.indexOfScalar(u8, "+=,.@_-", byte) != null) continue;
        return error.Malformed;
    }
    return name;
}

/// The metadata service's session token: printable, without blanks.
pub fn imds_token_valid(text: []const u8) bool {
    if (text.len == 0 or text.len > constants.aws_imds_token_bytes_max) return false;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    return true;
}

/// ECR's `GetAuthorizationToken` answer: the token and its expiry.
pub fn parse_ecr_token(body: []const u8) Error!EcrToken {
    const token = json_string(body, "authorizationToken") orelse return error.Malformed;
    if (token.len < 8 or token.len > constants.aws_ecr_token_bytes_max) return error.Malformed;
    var decoded: [constants.aws_ecr_token_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    const size = std.base64.standard.Decoder.calcSizeForSlice(token) catch return error.Malformed;
    if (size > decoded.len) return error.Malformed;
    std.base64.standard.Decoder.decode(decoded[0..size], token) catch return error.Malformed;
    // The user name is always `AWS`; a token that says otherwise is not ECR's.
    if (!std.mem.startsWith(u8, decoded[0..size], "AWS:")) return error.Malformed;
    if (size == "AWS:".len) return error.Malformed;
    for (decoded[0..size]) |byte| {
        if (byte < 0x21 or byte >= 0x7f) return error.Malformed;
    }
    const seconds = json_number(body, "expiresAt") orelse return error.Malformed;
    const expiration_s = parse_seconds(seconds) orelse return error.Malformed;
    return .{ .basic = token, .expiration_s = expiration_s };
}

/// The error code of a refused call: an STS or IAM XML `<Code>`, or an API JSON `__type` (the
/// part after `#`, when there is one). Only letters and digits, at most `aws_error_code_bytes_max`;
/// anything else is null, because the code is shown to the user and a message never is.
pub fn error_code(body: []const u8) ?[]const u8 {
    const raw = xml_element(body, "Code") orelse json_string(body, "__type") orelse return null;
    const start = if (std.mem.lastIndexOfScalar(u8, raw, '#')) |at| at + 1 else 0;
    const code = raw[start..];
    if (code.len == 0 or code.len > constants.aws_error_code_bytes_max) return null;
    for (code) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return null;
    }
    return code;
}

const testing = std.testing;

const sts_sample =
    "<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">" ++
    "<AssumeRoleWithWebIdentityResult><Credentials>" ++
    "<AccessKeyId>ASIAEXAMPLEEXAMPLE1</AccessKeyId>" ++
    "<SecretAccessKey>wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY</SecretAccessKey>" ++
    "<SessionToken>AQoDYXdzEJr//////////wEXAMPLETOKEN+/=</SessionToken>" ++
    "<Expiration>2015-08-30T12:36:00Z</Expiration></Credentials>" ++
    "</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";

const imds_sample =
    "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2015-08-30T11:36:00Z\",\n" ++
    "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"ASIAEXAMPLEEXAMPLE1\",\n" ++
    "  \"SecretAccessKey\" : \"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\",\n" ++
    "  \"Token\" : \"AQoDYXdzEJr//////////wEXAMPLETOKEN+/=\",\n" ++
    "  \"Expiration\" : \"2015-08-30T12:36:00Z\"\n}";

test "STS and metadata answers parse to the same credentials" {
    // Goal: both documents give the key, secret, token and the expiry as an epoch time.
    const from_sts = try parse_sts(sts_sample);
    const from_imds = try parse_imds(imds_sample);
    try testing.expectEqualStrings("ASIAEXAMPLEEXAMPLE1", from_sts.access_key_id);
    try testing.expectEqualStrings(from_sts.secret_access_key, from_imds.secret_access_key);
    try testing.expectEqualStrings(from_sts.session_token, from_imds.session_token);
    try testing.expectEqual(@as(u64, 1440938160), from_sts.expiration_s);
    try testing.expectEqual(from_sts.expiration_s, from_imds.expiration_s);
}

test "an answer that is wrong in any one field is refused" {
    // Goal: every field is required and checked; one bad field refuses the whole answer.
    const bad = [_][]const u8{
        "",
        "<Credentials></Credentials>",
        "{\"Code\":\"AssumeRoleUnauthorizedAccess\"}",
        "{\"Code\":\"Success\"}",
    };
    for (bad) |body| {
        try testing.expectError(error.Malformed, parse_sts(body));
        try testing.expectError(error.Malformed, parse_imds(body));
    }
    const swaps = [_][2][]const u8{
        .{ "ASIAEXAMPLEEXAMPLE1", "ASIA EXAMPLE" },
        .{ "ASIAEXAMPLEEXAMPLE1", "ASIA" },
        .{ "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "wJalr\\XUtnFEMI/K7MDENG+bPxRfiC" },
        .{ "2015-08-30T12:36:00Z", "2015-13-30T12:36:00Z" },
        .{ "2015-08-30T12:36:00Z", "2015-08-30 12:36:00Z" },
        .{ "2015-08-30T12:36:00Z", "1969-08-30T12:36:00Z" },
        .{ "AQoDYXdzEJr//////////wEXAMPLETOKEN+/=", "AQoDYXdz\nEJr//////////wEXAMPLE" },
    };
    for (swaps) |swap| {
        const changed = try std.mem.replaceOwned(
            u8,
            testing.allocator,
            imds_sample,
            swap[0],
            swap[1],
        );
        defer testing.allocator.free(changed);
        try testing.expectError(error.Malformed, parse_imds(changed));
    }
}

test "timestamps at their edges" {
    // Goal: the epoch, a leap day and the end of the accepted range; fractions are dropped.
    try testing.expectEqual(@as(?u64, 0), parse_timestamp("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?u64, 951782400), parse_timestamp("2000-02-29T00:00:00Z"));
    try testing.expectEqual(@as(?u64, 1440938160), parse_timestamp("2015-08-30T12:36:00.123Z"));
    try testing.expectEqual(@as(?u64, null), parse_timestamp("2015-08-30T12:36:00.Z"));
    try testing.expectEqual(@as(?u64, null), parse_timestamp("2015-08-30T12:36:00+00:00"));
    try testing.expectEqual(@as(?u64, null), parse_timestamp("2201-01-01T00:00:00Z"));
}

test "the role list gives one valid name" {
    // Goal: the first line is the role; blanks, markup and an empty list are refused.
    try testing.expectEqualStrings("my-role_1", try parse_imds_role("my-role_1\nother"));
    try testing.expectError(error.Malformed, parse_imds_role(""));
    try testing.expectError(error.Malformed, parse_imds_role("<html>"));
    try testing.expectError(error.Malformed, parse_imds_role("a b"));
}

test "ECR's token answer" {
    // Goal: a well-formed answer parses; a token that is not `AWS:` plus a password, a bad
    // alphabet or a missing expiry is refused.
    const good = "{\"authorizationData\":[{\"authorizationToken\":\"QVdTOnBhc3N3b3Jk\"," ++
        "\"expiresAt\":1.7E9,\"proxyEndpoint\":\"https://x\"}]}";
    const parsed = try parse_ecr_token(good);
    try testing.expectEqualStrings("QVdTOnBhc3N3b3Jk", parsed.basic);
    try testing.expectEqual(@as(u64, 1_700_000_000), parsed.expiration_s);
    // "Zm9vOmJhcg==" is `foo:bar`.
    const wrong_user = "{\"authorizationToken\":\"Zm9vOmJhcg==\",\"expiresAt\":1}";
    try testing.expectError(error.Malformed, parse_ecr_token(wrong_user));
    const no_expiry = "{\"authorizationToken\":\"QVdTOnBhc3N3b3Jk\"}";
    try testing.expectError(error.Malformed, parse_ecr_token(no_expiry));
    const not_base64 = "{\"authorizationToken\":\"!!!!!!!!!!!!\",\"expiresAt\":1}";
    try testing.expectError(error.Malformed, parse_ecr_token(not_base64));
    const empty_password = "{\"authorizationToken\":\"QVdTOg==\",\"expiresAt\":1}";
    try testing.expectError(error.Malformed, parse_ecr_token(empty_password));
}

test "error codes are names and nothing else" {
    // Goal: a code comes out only as letters and digits; a message never does.
    const xml = "<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code>" ++
        "<Message>secret text</Message></Error></ErrorResponse>";
    try testing.expectEqualStrings("InvalidIdentityToken", error_code(xml).?);
    const json = "{\"__type\":\"com.amazon.coral.service#UnrecognizedClientException\"}";
    try testing.expectEqualStrings("UnrecognizedClientException", error_code(json).?);
    try testing.expect(error_code("<Code>bad code</Code>") == null);
    try testing.expect(error_code("<html>") == null);
    try testing.expect(error_code("") == null);
}
