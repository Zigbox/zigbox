//! Tests of the credential helpers (`credentials.zig`) and of the registries' published
//! challenges: the realm rule, the Docker Hub and GHCR fixtures, and the wipe.

const std = @import("std");
const auth = @import("../registry/auth.zig");
const constants = @import("../constants.zig");
const credentials = @import("credentials.zig");
const net = @import("../registry/net.zig");

const testing = std.testing;

test "the realm rule: the registry's own host, the known pair, loopback for loopback" {
    // Goal: where a password may be sent. Method: each case of the owner's rule and its refusals.
    const own = try net.parse_url("https://ghcr.io/token");
    try testing.expect(credentials.realm_allowed("ghcr.io", .https, own));
    const pair = try net.parse_url("https://auth.docker.io/token");
    try testing.expect(credentials.realm_allowed("registry-1.docker.io", .https, pair));
    try testing.expect(!credentials.realm_allowed("ghcr.io", .https, pair));
    try testing.expect(!credentials.realm_allowed("registry.example.com", .https, pair));
    const far = try net.parse_url("https://evil.test/token");
    try testing.expect(!credentials.realm_allowed("registry.test", .https, far));
    const plain = try net.parse_url("http://ghcr.io/token");
    try testing.expect(!credentials.realm_allowed("ghcr.io", .https, plain));
    const local = try net.parse_url("http://127.0.0.1:5000/token");
    try testing.expect(credentials.realm_allowed("127.0.0.1", .http, local));
    try testing.expect(!credentials.realm_allowed("registry.test", .https, local));
    try testing.expect(!credentials.realm_allowed("ghcr.io", .http, local));
    const suffix = try net.parse_url("https://auth.docker.io.evil.test/token");
    try testing.expect(!credentials.realm_allowed("registry-1.docker.io", .https, suffix));
}

// The challenges and the token responses below are built from the registries' published
// documentation (Docker's token authentication specification and the registry API of each
// service), not captured from the live services: this session's network could not reach them
// with a credential, and a capture needs none of ours. They hold no secret: the token is a
// placeholder.
const hub_challenge = "Bearer realm=\"https://auth.docker.io/token\"," ++
    "service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"";
const hub_token = "{\"token\":\"PLACEHOLDER.hub.token\"," ++
    "\"access_token\":\"PLACEHOLDER.hub.token\"," ++
    "\"expires_in\":300,\"issued_at\":\"2026-11-09T00:00:00Z\"}";
const ghcr_challenge = "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\"," ++
    "scope=\"repository:zigbox/zigbox-demo:pull\"";
const ghcr_token = "{\"token\":\"PLACEHOLDER.ghcr.token\"}";

fn exchange(
    host: []const u8,
    header: []const u8,
    body: []const u8,
    repository: []const u8,
    expect_url: []const u8,
) !void {
    const challenge = try auth.parse_challenge(header);
    var buffer: [constants.registry_url_bytes_max * 2]u8 = undefined;
    const url_text = try auth.push_token_url(&challenge, repository, "", &buffer);
    try testing.expectEqualStrings(expect_url, url_text);
    const realm = try net.parse_url(url_text);
    try testing.expect(credentials.realm_allowed(host, .https, realm));
    var bytes: [constants.registry_token_response_bytes_max * 2]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&bytes);
    var out: [constants.registry_token_bytes_max]u8 = undefined;
    const token = auth.parse_token(body, fixed.allocator(), &out);
    try testing.expect(token != null);
    try testing.expect(std.mem.startsWith(u8, token.?, "PLACEHOLDER."));
}

test "Docker Hub's challenge and token response give a push token request to its own realm" {
    // Goal: the Hub exchange from its published shapes: the realm is the known pair, the scope
    // is ours (pull and push), not the challenge's pull.
    try exchange(
        "registry-1.docker.io",
        hub_challenge,
        hub_token,
        "me/app",
        "https://auth.docker.io/token?service=registry.docker.io" ++
            "&scope=repository%3Ame%2Fapp%3Apull%2Cpush",
    );
}

test "GHCR's challenge and token response give a push token request to its own host" {
    try exchange(
        "ghcr.io",
        ghcr_challenge,
        ghcr_token,
        "zigbox/zigbox-demo",
        "https://ghcr.io/token?service=ghcr.io" ++
            "&scope=repository%3Azigbox%2Fzigbox-demo%3Apull%2Cpush",
    );
}

test "wipe zeroes the whole credential" {
    // Goal: no byte of the password stays after use.
    var held = credentials.Credentials.of("user", "very-secret-password");
    try testing.expect(std.mem.indexOf(u8, &held.bytes, "very-secret") != null);
    held.wipe();
    for (held.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
    try testing.expect(!held.present());
}

test "the Basic value is the base64 of user:password" {
    var held = credentials.Credentials.of("alice", "wonderland");
    defer held.wipe();
    var out: [constants.push_basic_bytes_max]u8 = undefined;
    const encoded = credentials.encode_basic(&held, &out);
    try testing.expectEqualStrings("YWxpY2U6d29uZGVybGFuZA==", encoded);
}
