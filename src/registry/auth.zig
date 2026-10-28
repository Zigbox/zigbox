//! Anonymous bearer authentication, as Docker Hub, GHCR and every registry of the OCI
//! distribution family speak it: a request without a token gets `401` and a
//! `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` challenge; the client asks the
//! realm for a token (no credentials: anonymous) and repeats the request with
//! `Authorization: Bearer <token>`. Nothing here is specific to a registry: the realm is whatever
//! the challenge says, never a hard-coded Docker Hub address.
//!
//! This file only reads and builds text: the challenge, the token request's target, the token
//! response. The requests are made by `client.zig`. A token is copied into the caller's buffer
//! and is never put in a message.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Challenge = struct {
    /// The URL to ask for a token. Slices of the header text.
    realm: []const u8,
    service: ?[]const u8,
    scope: ?[]const u8,
    /// `error="invalid_token"` and the like: why the token that was sent was refused.
    error_code: ?[]const u8,
};

/// What `parse_challenge` found when there is no Bearer challenge to use.
pub const ChallengeError = error{
    /// Only other schemes (Basic: the registry wants credentials), or none.
    NoBearer,
    /// A Bearer challenge without a realm, or with text that is not the grammar.
    Malformed,
};

/// Reads the first Bearer challenge of a `WWW-Authenticate` header value. Other schemes in the
/// same header are skipped. A parameter value with a backslash escape is refused: a realm or a
/// scope never needs one, and unescaping would need a buffer for a case that does not occur.
pub fn parse_challenge(header: []const u8) ChallengeError!Challenge {
    assert(header.len <= constants.registry_challenge_bytes_max);
    var found: Challenge = .{ .realm = "", .service = null, .scope = null, .error_code = null };
    var in_bearer = false;
    var seen_bearer = false;
    var at: usize = 0;
    while (true) {
        at = skip(header, at, " \t,");
        if (at == header.len) break;
        const word_end = word_end_at(header, at);
        if (word_end == at) return error.Malformed;
        const word = header[at..word_end];
        const after = skip(header, word_end, " \t");
        if (after < header.len and header[after] == '=') {
            // An auth-param of the challenge being read.
            const value_start = skip(header, after + 1, " \t");
            const value = try read_value(header, value_start);
            if (in_bearer) store_param(&found, word, value.text);
            at = value.end;
            continue;
        }
        // A scheme name starts a challenge.
        if (seen_bearer) break;
        in_bearer = std.ascii.eqlIgnoreCase(word, "bearer");
        seen_bearer = in_bearer;
        at = word_end;
    }
    if (!seen_bearer) return error.NoBearer;
    if (found.realm.len == 0) return error.Malformed;
    return found;
}

fn skip(text: []const u8, from: usize, set: []const u8) usize {
    assert(from <= text.len);
    var at = from;
    while (at < text.len and std.mem.indexOfScalar(u8, set, text[at]) != null) at += 1;
    assert(at <= text.len);
    return at;
}

/// The end of a token: it stops at a space, a comma or an equals sign.
fn word_end_at(text: []const u8, from: usize) usize {
    assert(from <= text.len);
    var at = from;
    while (at < text.len and std.mem.indexOfScalar(u8, " \t,=\"", text[at]) == null) at += 1;
    return at;
}

const Value = struct { text: []const u8, end: usize };

fn read_value(text: []const u8, from: usize) ChallengeError!Value {
    assert(from <= text.len);
    if (from == text.len) return error.Malformed;
    if (text[from] != '"') {
        const end = word_end_at(text, from);
        if (end == from) return error.Malformed;
        return .{ .text = text[from..end], .end = end };
    }
    var at = from + 1;
    while (at < text.len and text[at] != '"') {
        if (text[at] == '\\') return error.Malformed;
        at += 1;
    }
    if (at == text.len) return error.Malformed;
    return .{ .text = text[from + 1 .. at], .end = at + 1 };
}

fn store_param(found: *Challenge, name: []const u8, value: []const u8) void {
    assert(value.len <= constants.registry_challenge_bytes_max);
    if (std.ascii.eqlIgnoreCase(name, "realm")) {
        found.realm = value;
    } else if (std.ascii.eqlIgnoreCase(name, "service")) {
        found.service = value;
    } else if (std.ascii.eqlIgnoreCase(name, "scope")) {
        found.scope = value;
    } else if (std.ascii.eqlIgnoreCase(name, "error")) {
        found.error_code = value;
    }
}

/// Writes `text` percent-encoded (everything but letters, digits and `-._~`).
fn encode_into(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |byte| {
        const unreserved = std.mem.indexOfScalar(u8, "-._~", byte) != null;
        if (std.ascii.isAlphanumeric(byte) or unreserved) {
            try writer.writeByte(byte);
        } else {
            try writer.print("%{X:0>2}", .{byte});
        }
    }
}

pub const TokenTargetError = error{ TooLong, BadRealm };

/// Where to ask for a token: the realm, then `service` and `scope` as query parameters. The
/// scope is the challenge's own, or pulling `repository` when the challenge names none.
pub fn token_url(
    challenge: *const Challenge,
    repository: []const u8,
    buffer: *[constants.registry_url_bytes_max * 2]u8,
) TokenTargetError![]const u8 {
    assert(repository.len > 0);
    assert(challenge.realm.len > 0);
    if (std.mem.indexOfScalar(u8, challenge.realm, '#') != null) return error.BadRealm;
    var writer = std.Io.Writer.fixed(buffer);
    const joiner: u8 = if (std.mem.indexOfScalar(u8, challenge.realm, '?') == null) '?' else '&';
    writer.writeAll(challenge.realm) catch return error.TooLong;
    var first = true;
    if (challenge.service) |service| {
        writer.print("{c}service=", .{joiner}) catch return error.TooLong;
        encode_into(&writer, service) catch return error.TooLong;
        first = false;
    }
    const separator: u8 = if (first) joiner else '&';
    writer.print("{c}scope=", .{separator}) catch return error.TooLong;
    if (challenge.scope) |scope| {
        encode_into(&writer, scope) catch return error.TooLong;
    } else {
        writer.writeAll("repository%3A") catch return error.TooLong;
        encode_into(&writer, repository) catch return error.TooLong;
        writer.writeAll("%3Apull") catch return error.TooLong;
    }
    const url = writer.buffered();
    assert(url.len > challenge.realm.len);
    return url;
}

const TokenDocument = struct {
    token: ?[]const u8 = null,
    access_token: ?[]const u8 = null,
};

/// Reads the token out of a token response (`token`, or `access_token` when that is all there is)
/// and copies it into `out`. Null for a response without a usable token: not JSON, no token, an
/// empty one, one that does not fit, or one with a byte that cannot go in a header.
pub fn parse_token(body: []const u8, arena: std.mem.Allocator, out: []u8) ?[]const u8 {
    assert(body.len <= constants.registry_token_response_bytes_max);
    assert(out.len <= constants.registry_token_bytes_max);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const document = std.json.parseFromSliceLeaky(TokenDocument, arena, body, options) catch {
        return null;
    };
    const token = document.token orelse document.access_token orelse return null;
    if (token.len == 0) return null;
    if (token.len > out.len) return null;
    for (token) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return null;
    }
    @memcpy(out[0..token.len], token);
    return out[0..token.len];
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

test "the challenges of Docker Hub and GHCR" {
    // Goal: the two real forms parse to their realm, service and scope.
    const hub =
        "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"," ++
        "scope=\"repository:library/alpine:pull\"";
    const found = try parse_challenge(hub);
    try testing.expectEqualStrings("https://auth.docker.io/token", found.realm);
    try testing.expectEqualStrings("registry.docker.io", found.service.?);
    try testing.expectEqualStrings("repository:library/alpine:pull", found.scope.?);
    try testing.expect(found.error_code == null);
    const ghcr = "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\"," ++
        "scope=\"repository:o/i:pull\"";

    const second = try parse_challenge(ghcr);
    try testing.expectEqualStrings("https://ghcr.io/token", second.realm);
}

test "case, spacing, bare tokens, other schemes and error parameters" {
    // Goal: the forms the grammar allows are read the same; Basic alone is NoBearer.
    const odd = "bEaReR   Realm = \"https://a/t\" , SERVICE=reg, error=\"invalid_token\"";
    const found = try parse_challenge(odd);
    try testing.expectEqualStrings("https://a/t", found.realm);
    try testing.expectEqualStrings("reg", found.service.?);
    try testing.expectEqualStrings("invalid_token", found.error_code.?);
    try testing.expect(found.scope == null);
    const mixed = "Basic realm=\"x\", Bearer realm=\"https://a/t\",service=\"s\"";
    const after_basic = try parse_challenge(mixed);
    try testing.expectEqualStrings("https://a/t", after_basic.realm);
    try testing.expectEqualStrings("s", after_basic.service.?);
    const reversed = "Bearer realm=\"https://a/t\", Basic realm=\"other\"";
    try testing.expectEqualStrings("https://a/t", (try parse_challenge(reversed)).realm);
    try testing.expectError(error.NoBearer, parse_challenge("Basic realm=\"x\""));
    try testing.expectError(error.NoBearer, parse_challenge(""));
}

test "malformed challenges are refused, not repaired" {
    // Goal: no realm, an unterminated quote, an escape and a missing value are Malformed.
    try testing.expectError(error.Malformed, parse_challenge("Bearer service=\"s\""));
    try testing.expectError(error.Malformed, parse_challenge("Bearer realm=\"https://a/t"));
    try testing.expectError(error.Malformed, parse_challenge("Bearer realm=\"https://a/\\\"t\""));
    try testing.expectError(error.Malformed, parse_challenge("Bearer realm="));
    try testing.expectError(error.Malformed, parse_challenge("Bearer realm=\"\""));
    try testing.expectError(error.Malformed, parse_challenge("Bearer realm=\"a\" =x"));
}

test "the token URL encodes service and scope, and defaults the scope" {
    // Goal: the query is exact for the challenge's scope, for none, and for a realm with a query.
    var buffer: [constants.registry_url_bytes_max * 2]u8 = undefined;
    var challenge: Challenge = .{
        .realm = "https://auth.docker.io/token",
        .service = "registry.docker.io",
        .scope = "repository:library/alpine:pull",
        .error_code = null,
    };
    const hub = "https://auth.docker.io/token?service=registry.docker.io" ++
        "&scope=repository%3Alibrary%2Falpine%3Apull";
    try testing.expectEqualStrings(hub, try token_url(&challenge, "library/alpine", &buffer));
    challenge.scope = null;
    try testing.expectEqualStrings(hub, try token_url(&challenge, "library/alpine", &buffer));

    challenge.service = null;
    challenge.realm = "https://a/t?x=1";
    try testing.expectEqualStrings(
        "https://a/t?x=1&scope=repository%3Aa%2Fb%3Apull",
        try token_url(&challenge, "a/b", &buffer),
    );
    challenge.realm = "https://a/t#f";
    try testing.expectError(error.BadRealm, token_url(&challenge, "a/b", &buffer));
}

test "a token is read from token or access_token and nothing else" {
    // Goal: both field names work, junk and empty do not, and the token is copied out.
    var storage: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var out: [64]u8 = undefined;
    const both = "{\"token\":\"abc.def\",\"access_token\":\"zzz\",\"expires_in\":300}";
    try testing.expectEqualStrings("abc.def", parse_token(both, fixed.allocator(), &out).?);
    fixed.reset();
    const only = "{\"access_token\":\"zzz\",\"issued_at\":\"x\"}";
    try testing.expectEqualStrings("zzz", parse_token(only, fixed.allocator(), &out).?);
    fixed.reset();
    try testing.expect(parse_token("{\"token\":\"\"}", fixed.allocator(), &out) == null);
    try testing.expect(parse_token("{}", fixed.allocator(), &out) == null);
    try testing.expect(parse_token("not json", fixed.allocator(), &out) == null);
    try testing.expect(parse_token("{\"token\":\"a b\"}", fixed.allocator(), &out) == null);
    try testing.expect(parse_token("{\"token\":5}", fixed.allocator(), &out) == null);
    var tiny: [3]u8 = undefined;
    try testing.expect(parse_token("{\"token\":\"abcd\"}", fixed.allocator(), &tiny) == null);
}
