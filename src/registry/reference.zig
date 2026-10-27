//! Image references: `[registry/][namespace/]name[:tag][@sha256:<hex>]`. The parser is pure: no
//! allocation, no network, no environment. It refuses what is ambiguous or malformed with one
//! named reason each and never guesses a repair (an uppercase repository is refused, not
//! lowercased). What it does fill in is only what the convention fixes:
//!
//!   - no registry means Docker Hub, `docker.io`, which is reached at `registry-1.docker.io`;
//!   - a Docker Hub name of one part gets the `library/` namespace;
//!   - no tag and no digest means the tag `latest`;
//!   - the first part is a registry when it has a dot or a port, or is `localhost`; otherwise it
//!     is a namespace on Docker Hub (`foo/bar` is Hub's `foo/bar`, never a host called `foo`).
//!
//! When both a tag and a digest are given the digest decides what is pulled; the tag is kept for
//! display. A registry on loopback (`localhost`, `127.*`) is spoken to in plain HTTP, as Docker
//! and Podman do; every other registry is HTTPS.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const repeat = @import("../test_util.zig").repeat;

const Sha256 = digest_mod.Sha256;

pub const docker_hub = "docker.io";
pub const docker_hub_endpoint = "registry-1.docker.io";
const docker_hub_alias = "index.docker.io";
const default_tag = "latest";
const library_namespace = "library/";

/// Why a reference was refused. The text of each is in `registry/diagnose.zig`.
pub const Error = error{
    Empty,
    TooLong,
    /// A space, control character or non-ASCII byte.
    BadCharacter,
    /// `https://alpine` and the like: a URL, not a reference.
    LooksLikeUrl,
    /// A registry and nothing after it, or only a digest.
    MissingRepository,
    BadRegistry,
    BadPort,
    BadRepository,
    UppercaseRepository,
    BadTag,
    BadDigest,
    /// `@sha512:...` and other algorithms.
    UnsupportedDigestAlgorithm,
};

pub const Scheme = enum { http, https };

/// Where to connect for a registry.
pub const Endpoint = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
};

pub const Reference = struct {
    registry_bytes: [constants.reference_registry_bytes_max]u8,
    registry_len: u16,
    repository_bytes: [constants.reference_repository_bytes_max]u8,
    repository_len: u16,
    tag_bytes: [constants.reference_tag_bytes_max]u8,
    /// Zero when there is no tag (only a digest was given).
    tag_len: u16,
    digest: ?Sha256,

    /// The registry as the reference names it: "docker.io", "ghcr.io", "localhost:5000".
    pub fn registry(reference: *const Reference) []const u8 {
        assert(reference.registry_len > 0);
        assert(reference.registry_len <= constants.reference_registry_bytes_max);
        return reference.registry_bytes[0..reference.registry_len];
    }

    /// The repository with its namespace: "library/alpine".
    pub fn repository(reference: *const Reference) []const u8 {
        assert(reference.repository_len > 0);
        assert(reference.repository_len <= constants.reference_repository_bytes_max);
        return reference.repository_bytes[0..reference.repository_len];
    }

    pub fn tag(reference: *const Reference) ?[]const u8 {
        assert(reference.tag_len <= constants.reference_tag_bytes_max);
        if (reference.tag_len == 0) assert(reference.digest != null);
        if (reference.tag_len == 0) return null;
        return reference.tag_bytes[0..reference.tag_len];
    }

    /// What names the manifest in a request: the digest when there is one, else the tag. A
    /// parsed reference has at least one of them.
    pub fn manifest_name(reference: *const Reference, buffer: *ManifestName) []const u8 {
        assert(buffer.len == constants.oci_digest_text_bytes);
        assert(reference.registry_len > 0);
        if (reference.digest) |digest| {
            buffer[0..constants.oci_digest_text_bytes].* = digest.text();
            return buffer[0..constants.oci_digest_text_bytes];
        }
        const found = reference.tag().?;
        @memcpy(buffer[0..found.len], found);
        return buffer[0..found.len];
    }

    /// Where to connect: Docker Hub at its API host, a loopback registry in plain HTTP, any
    /// other over HTTPS. The port is the one in the reference, else the scheme's.
    pub fn endpoint(reference: *const Reference) Endpoint {
        const name = reference.registry();
        if (std.mem.eql(u8, name, docker_hub)) {
            return .{ .scheme = .https, .host = docker_hub_endpoint, .port = 443 };
        }
        var host = name;
        var port: ?u16 = null;
        if (std.mem.lastIndexOfScalar(u8, name, ':')) |colon| {
            host = name[0..colon];
            port = std.fmt.parseInt(u16, name[colon + 1 ..], 10) catch unreachable; // Validated.
        }
        const scheme: Scheme = if (is_loopback(host)) .http else .https;
        const default_port: u16 = if (scheme == .http) 80 else 443;
        assert(host.len > 0);
        return .{ .scheme = scheme, .host = host, .port = port orelse default_port };
    }

    /// The canonical text: registry, repository, tag if any, digest if any. Parsing it gives
    /// this reference back.
    pub fn format(reference: *const Reference, buffer: *Formatted) []const u8 {
        var writer = std.Io.Writer.fixed(buffer);
        const first = .{ reference.registry(), reference.repository() };
        // Cannot fail: the buffer holds the longest of each part (the constants assert it).
        writer.print("{s}/{s}", first) catch unreachable;
        if (reference.tag()) |found| {
            writer.print(":{s}", .{found}) catch unreachable; // The same bound.
        }
        if (reference.digest) |digest| {
            writer.print("@{s}", .{&digest.text()}) catch unreachable; // The same bound.
        }
        return writer.buffered();
    }
};

/// The room `manifest_name` needs: a digest is longer than a tag.
pub const ManifestName = [constants.oci_digest_text_bytes]u8;
/// The room `format` needs.
pub const Formatted = [constants.reference_bytes_max]u8;

/// True for the hosts a registry may be spoken to over plain HTTP: `localhost` and 127.x.y.z.
pub fn is_loopback(host: []const u8) bool {
    assert(host.len <= constants.reference_registry_bytes_max);
    if (std.mem.eql(u8, host, "localhost")) return true;
    if (!std.mem.startsWith(u8, host, "127.")) return false;
    for (host) |byte| {
        if (byte != '.' and !std.ascii.isDigit(byte)) return false;
    }
    return true;
}

/// Reads `text` into `reference`, or says why not.
pub fn parse(text: []const u8, reference: *Reference) Error!void {
    assert(text.len <= constants.arg_bytes_max);
    if (text.len == 0) return error.Empty;
    if (text.len > constants.reference_bytes_max) return error.TooLong;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return error.BadCharacter;
    }
    if (std.mem.indexOf(u8, text, "://") != null) return error.LooksLikeUrl;
    var name = text;
    reference.digest = null;
    if (std.mem.indexOfScalar(u8, text, '@')) |at| {
        reference.digest = try parse_digest(text[at + 1 ..]);
        name = text[0..at];
    }
    if (name.len == 0) return error.MissingRepository;
    reference.tag_len = 0;
    name = try split_tag(name, reference);
    if (name.len == 0) return error.MissingRepository; // ":3.20" has a tag and no name.
    try split_registry(name, reference);
    if (reference.tag_len == 0 and reference.digest == null) {
        set_tag(reference, default_tag);
    }
    if (reference.tag_len == 0) assert(reference.digest != null);
    assert(reference.registry_len > 0);
    assert(reference.repository_len > 0);
}

fn parse_digest(text: []const u8) Error!Sha256 {
    assert(text.len <= constants.reference_bytes_max);
    assert(digest_mod.text_prefix.len == "sha256:".len);
    if (Sha256.parse(text)) |digest| return digest;
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.BadDigest;
    const algorithm = text[0..colon];
    if (!std.mem.eql(u8, algorithm, "sha256") and algorithm.len > 0) {
        for (algorithm) |byte| {
            if (!std.ascii.isAlphanumeric(byte)) return error.BadDigest;
        }
        return error.UnsupportedDigestAlgorithm;
    }
    return error.BadDigest;
}

/// Cuts a `:tag` off the end of the name and checks it. The tag's colon is the last one, and
/// only when no `/` follows it (otherwise it is a registry's port).
fn split_tag(name: []const u8, reference: *Reference) Error![]const u8 {
    assert(name.len > 0);
    const slash = std.mem.lastIndexOfScalar(u8, name, '/');
    const colon = std.mem.lastIndexOfScalar(u8, name, ':') orelse return name;
    if (slash) |after| {
        if (colon < after) return name;
    }
    const tag = name[colon + 1 ..];
    if (!tag_valid(tag)) return error.BadTag;
    set_tag(reference, tag);
    assert(reference.tag_len > 0);
    return name[0..colon];
}

fn set_tag(reference: *Reference, tag: []const u8) void {
    assert(tag.len > 0);
    assert(tag.len <= constants.reference_tag_bytes_max);
    @memcpy(reference.tag_bytes[0..tag.len], tag);
    reference.tag_len = @intCast(tag.len);
}

fn tag_valid(tag: []const u8) bool {
    assert(tag.len <= constants.reference_bytes_max);
    if (tag.len == 0) return false;
    if (tag.len > constants.reference_tag_bytes_max) return false;
    for (tag, 0..) |byte, index| {
        const word = std.ascii.isAlphanumeric(byte) or byte == '_';
        if (index == 0 and !word) return false;
        if (!word and byte != '.' and byte != '-') return false;
    }
    return true;
}

/// Finds the registry and the repository in `name` (no tag, no digest) and stores both.
fn split_registry(name: []const u8, reference: *Reference) Error!void {
    assert(name.len > 0);
    const slash = std.mem.indexOfScalar(u8, name, '/');
    var registry: []const u8 = docker_hub;
    var repository = name;
    if (slash) |at| {
        if (names_registry(name[0..at])) {
            registry = name[0..at];
            repository = name[at + 1 ..];
        }
    }
    if (repository.len == 0) return error.MissingRepository;
    var lower: [constants.reference_registry_bytes_max]u8 = undefined;
    if (registry.len > lower.len) return error.BadRegistry;
    const host = std.ascii.lowerString(&lower, registry);
    try registry_valid(host);
    const hub = std.mem.eql(u8, host, docker_hub) or std.mem.eql(u8, host, docker_hub_alias);
    const prefix: []const u8 = if (hub and std.mem.indexOfScalar(u8, repository, '/') == null)
        library_namespace
    else
        "";
    try repository_valid(repository, prefix.len);
    set_registry(reference, if (hub) docker_hub else host);
    const total = prefix.len + repository.len;
    @memcpy(reference.repository_bytes[0..prefix.len], prefix);
    @memcpy(reference.repository_bytes[prefix.len..][0..repository.len], repository);
    reference.repository_len = @intCast(total);
}

fn set_registry(reference: *Reference, registry: []const u8) void {
    assert(registry.len > 0);
    assert(std.mem.indexOfScalar(u8, registry, '/') == null);
    assert(registry.len <= constants.reference_registry_bytes_max);
    @memcpy(reference.registry_bytes[0..registry.len], registry);
    reference.registry_len = @intCast(registry.len);
}

/// The first part of a name is a registry when it has a dot or a colon or is `localhost`.
fn names_registry(first: []const u8) bool {
    assert(std.mem.indexOfScalar(u8, first, '/') == null); // One part of the name.
    assert(first.len <= constants.reference_bytes_max);
    if (std.mem.eql(u8, first, "localhost")) return true;
    return std.mem.indexOfAny(u8, first, ".:") != null;
}

/// `host` or `host:port`, lowercase. A host is dot-separated labels of letters, digits and
/// inner hyphens; IPv6 literals are refused.
fn registry_valid(name: []const u8) Error!void {
    assert(name.len <= constants.reference_registry_bytes_max);
    assert(std.mem.indexOfScalar(u8, name, '/') == null);
    if (name.len == 0) return error.BadRegistry;
    var host = name;
    if (std.mem.lastIndexOfScalar(u8, name, ':')) |colon| {
        host = name[0..colon];
        try port_valid(name[colon + 1 ..]);
    }
    if (host.len == 0 or host.len > 253) return error.BadRegistry;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadRegistry;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.BadRegistry;
        for (label) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.BadRegistry;
        }
    }
}

fn port_valid(text: []const u8) Error!void {
    assert(text.len <= constants.reference_registry_bytes_max);
    if (text.len == 0 or text.len > 5) return error.BadPort;
    if (text[0] == '0') return error.BadPort;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.BadPort;
    }
    const port = std.fmt.parseInt(u32, text, 10) catch return error.BadPort;
    if (port > std.math.maxInt(u16)) return error.BadPort;
}

/// Lowercase components separated by `/`; `prefix_len` is the namespace added to the front,
/// counted in the length bound.
fn repository_valid(path: []const u8, prefix_len: usize) Error!void {
    if (prefix_len > 0) assert(prefix_len == library_namespace.len);
    if (path.len == 0) return error.MissingRepository;
    if (path.len + prefix_len > constants.reference_repository_bytes_max) return error.TooLong;
    for (path) |byte| {
        if (std.ascii.isUpper(byte)) return error.UppercaseRepository;
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (!component_valid(component)) return error.BadRepository;
    }
}

/// `[a-z0-9]+` pieces joined by one separator each: `.`, `_`, `__` or any run of `-`.
fn component_valid(component: []const u8) bool {
    assert(std.mem.indexOfScalar(u8, component, '/') == null);
    assert(component.len <= constants.reference_repository_bytes_max);
    if (component.len == 0) return false;
    if (!is_lower_alnum(component[0])) return false;
    if (!is_lower_alnum(component[component.len - 1])) return false;
    var index: usize = 0;
    while (index < component.len) {
        if (is_lower_alnum(component[index])) {
            index += 1;
            continue;
        }
        const separator = component[index];
        var run: usize = 0;
        while (index + run < component.len and component[index + run] == separator) run += 1;
        const allowed: bool = switch (separator) {
            '.' => run == 1,
            '_' => run <= 2,
            '-' => true,
            else => false,
        };
        if (!allowed) return false;
        index += run;
        // A different separator may not follow directly: the end of the run is a letter.
        if (!is_lower_alnum(component[index])) return false;
    }
    return true;
}

fn is_lower_alnum(byte: u8) bool {
    assert(@sizeOf(@TypeOf(byte)) == 1);
    assert('a' < 'z');
    assert('0' < '9');
    return (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9');
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const zero_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn expect_parsed(
    text: []const u8,
    registry: []const u8,
    repository: []const u8,
    tag: ?[]const u8,
) !void {
    var reference: Reference = undefined;
    try parse(text, &reference);
    try testing.expectEqualStrings(registry, reference.registry());
    try testing.expectEqualStrings(repository, reference.repository());
    if (tag) |expected| {
        try testing.expectEqualStrings(expected, reference.tag().?);
    } else {
        try testing.expect(reference.tag() == null);
    }
}

fn expect_refused(text: []const u8, expected: Error) !void {
    var reference: Reference = undefined;
    try testing.expectError(expected, parse(text, &reference));
}

test "the names the demo and the top 20 use" {
    // Goal: Docker Hub short names get docker.io and library/, other hosts keep theirs.
    try expect_parsed("alpine:3.20", "docker.io", "library/alpine", "3.20");
    try expect_parsed("alpine", "docker.io", "library/alpine", "latest");
    try expect_parsed("python:3.12-slim", "docker.io", "library/python", "3.12-slim");
    try expect_parsed("docker.io/library/alpine:3.20", "docker.io", "library/alpine", "3.20");
    try expect_parsed("index.docker.io/alpine", "docker.io", "library/alpine", "latest");
    try expect_parsed("grafana/grafana:11.0.0", "docker.io", "grafana/grafana", "11.0.0");
    try expect_parsed("ghcr.io/owner/image:v1", "ghcr.io", "owner/image", "v1");
    try expect_parsed("GHCR.IO/owner/image", "ghcr.io", "owner/image", "latest");
    try expect_parsed("localhost:5000/test/a:1", "localhost:5000", "test/a", "1");
    try expect_parsed("localhost/test", "localhost", "test", "latest");
    try expect_parsed("quay.io:443/a/b/c", "quay.io:443", "a/b/c", "latest");
    try expect_parsed("foo/bar", "docker.io", "foo/bar", "latest"); // A namespace, not a host.
    try expect_parsed("a.b-c/e__f--g", "a.b-c", "e__f--g", "latest");
}

test "a digest decides, and a tag may come with it" {
    // Goal: the digest is parsed whole; with no tag there is none; with both, both are kept.
    var reference: Reference = undefined;
    try parse("alpine@" ++ zero_digest, &reference);
    try testing.expect(reference.tag() == null);
    try testing.expectEqualStrings(zero_digest, &reference.digest.?.text());
    var name: ManifestName = undefined;
    try testing.expectEqualStrings(zero_digest, reference.manifest_name(&name));
    try parse("alpine:3.20@" ++ zero_digest, &reference);
    try testing.expectEqualStrings("3.20", reference.tag().?);
    try testing.expect(reference.digest != null);
    try parse("alpine:3.20", &reference);
    try testing.expectEqualStrings("3.20", reference.manifest_name(&name));
}

test "what is refused, each with its reason" {
    // Goal: the boundary where a reference becomes invalid, one case per reason and per edge.
    try expect_refused("", error.Empty);
    try expect_refused("alpine 3.20", error.BadCharacter);
    try expect_refused("alpine\x00", error.BadCharacter);
    try expect_refused("alp\xc3\xafne", error.BadCharacter);
    try expect_refused("https://alpine", error.LooksLikeUrl);
    try expect_refused("docker://alpine", error.LooksLikeUrl);
    try expect_refused("ghcr.io/", error.MissingRepository);
    try expect_refused("@" ++ zero_digest, error.MissingRepository);
    try expect_refused("Alpine", error.UppercaseRepository);
    try expect_refused("foo/Bar", error.UppercaseRepository);
    try expect_refused("alpine:", error.BadTag);
    try expect_refused(":3.20", error.MissingRepository);
    try expect_refused(":3.20@" ++ zero_digest, error.MissingRepository);
    try expect_refused("alpine:-1", error.BadTag);
    try expect_refused("alpine:a:b", error.BadRepository);
    try expect_refused("alpine:a/b", error.BadPort);
    try expect_refused("a//b", error.BadRepository);
    try expect_refused("/a", error.BadRepository);
    try expect_refused("a/", error.BadRepository);
    try expect_refused("a..b", error.BadRepository);
    try expect_refused("a___b", error.BadRepository);
    try expect_refused("a._b", error.BadRepository);
    try expect_refused("-a", error.BadRepository);
    try expect_refused("a-", error.BadRepository);
    try expect_refused("host.io:0/a", error.BadPort);
    try expect_refused("host.io:99999/a", error.BadPort);
    try expect_refused("host.io:80a/a", error.BadPort);
    try expect_refused("[::1]:5000/a", error.BadRegistry);
    try expect_refused("-host.io/a", error.BadRegistry);
    try expect_refused("a..io/a", error.BadRegistry);
    try expect_refused("alpine@sha256:abc", error.BadDigest);
    try expect_refused("alpine@" ++ zero_digest[0..70], error.BadDigest);
    try expect_refused("alpine@sha256:" ++ repeat('A', 64), error.BadDigest);
    try expect_refused("alpine@" ++ zero_digest ++ "@x", error.BadDigest);
    try expect_refused("alpine@sha512:" ++ repeat('0', 128), error.UnsupportedDigestAlgorithm);
    try expect_refused("alpine@", error.BadDigest);
}

test "length bounds are exact" {
    // Goal: the longest accepted tag, repository and reference, and one byte more of each.
    var buffer: [constants.reference_bytes_max + 8]u8 = undefined;
    const tag_ok = try std.fmt.bufPrint(&buffer, "a:{s}", .{repeat('t', 128)});
    try expect_parsed(tag_ok, "docker.io", "library/a", repeat('t', 128));
    const tag_long = try std.fmt.bufPrint(&buffer, "a:{s}", .{repeat('t', 129)});
    try expect_refused(tag_long, error.BadTag);
    // 255 bytes of repository in two parts, so no namespace is added.
    const repo_ok = repeat('a', 127) ++ "/" ++ repeat('b', 127);
    try expect_parsed(repo_ok, "docker.io", repo_ok, "latest");
    try expect_refused(repo_ok ++ "b", error.TooLong);
    // One part of 247 bytes is 255 with "library/"; 248 is not.
    try expect_parsed(repeat('a', 247), "docker.io", "library/" ++ repeat('a', 247), "latest");
    try expect_refused(repeat('a', 248), error.TooLong);
    const over = repeat('a', constants.reference_bytes_max + 1);
    try expect_refused(over, error.TooLong);
}

test "the endpoint: Hub at its API host, loopback in plain HTTP, the rest HTTPS" {
    // Goal: the connection target follows the reference, and the port defaults by scheme.
    var reference: Reference = undefined;
    try parse("alpine", &reference);
    var endpoint = reference.endpoint();
    try testing.expectEqualStrings("registry-1.docker.io", endpoint.host);
    try testing.expectEqual(Scheme.https, endpoint.scheme);
    try testing.expectEqual(@as(u16, 443), endpoint.port);
    try parse("ghcr.io/a/b", &reference);
    endpoint = reference.endpoint();
    try testing.expectEqualStrings("ghcr.io", endpoint.host);
    try testing.expectEqual(@as(u16, 443), endpoint.port);
    try parse("localhost:5000/a", &reference);
    endpoint = reference.endpoint();
    try testing.expectEqual(Scheme.http, endpoint.scheme);
    try testing.expectEqual(@as(u16, 5000), endpoint.port);
    try parse("127.0.0.1:8080/a", &reference);
    try testing.expectEqual(Scheme.http, reference.endpoint().scheme);
    try parse("127.example.com/a", &reference);
    try testing.expectEqual(Scheme.https, reference.endpoint().scheme);
    try parse("localhost/a", &reference);
    try testing.expectEqual(@as(u16, 80), reference.endpoint().port);
}

test "format gives a canonical text that parses back to the same reference" {
    // Goal: the canonical form is a fixed point, which the lock file relies on.
    var buffer: Formatted = undefined;
    const inputs = [_][]const u8{
        "alpine",           "alpine:3.20",            "ghcr.io/o/i:v1",
        "localhost:5000/a", "alpine@" ++ zero_digest, "alpine:3.20@" ++ zero_digest,
    };
    for (inputs) |input| {
        var first: Reference = undefined;
        try parse(input, &first);
        const canonical = first.format(&buffer);
        var second: Reference = undefined;
        try parse(canonical, &second);
        var again: Formatted = undefined;
        try testing.expectEqualStrings(canonical, second.format(&again));
    }
    var reference: Reference = undefined;
    try parse("alpine:3.20", &reference);
    try testing.expectEqualStrings(
        "docker.io/library/alpine:3.20",
        reference.format(&buffer),
    );
}
