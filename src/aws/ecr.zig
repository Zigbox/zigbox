//! Telling an ECR registry host from any other, and what zbx does with each. A private ECR host is
//! `<12-digit account>.dkr.ecr.<region>.amazonaws.com`; its credentials come from AWS, not from
//! the user. `public.ecr.aws` is ECR Public: anonymous pulls work, so it takes the ordinary
//! anonymous path. Hosts in other AWS partitions (China's `.amazonaws.com.cn`), FIPS endpoints and
//! the dual-stack and other variants are recognised as ECR but refused with `unsupported`, so the
//! user is told so and zbx never sends a request that would fail in a confusing way.
//!
//! The parser is pure: it reads the host text and nothing else. It never allocates; the region it
//! returns is a slice of the input.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// What a registry host is, as far as AWS is concerned.
pub const Host = union(enum) {
    /// Not an AWS host (or one this code does not treat specially): the ordinary path.
    other,
    /// `public.ecr.aws`: anonymous, through the ordinary path.
    public,
    /// A private ECR registry zbx can authenticate to.
    private: Private,
    /// An ECR host of a kind zbx does not support yet: a partition other than `aws`, FIPS,
    /// dual-stack. The user is told, with the host; nothing is sent.
    unsupported,
};

pub const Private = struct {
    account: [constants.aws_account_digits]u8,
    /// A slice of the host text, e.g. `us-east-1`.
    region: []const u8,
};

pub const public_host = "public.ecr.aws";

/// Classifies `host` (lower case, no port). A port, an upper-case letter or any other oddity makes
/// it `other`, because a registry the reference parser accepted is already in this form.
pub fn classify(host: []const u8) Host {
    if (std.mem.eql(u8, host, public_host)) return .public;
    assert(public_host.len < constants.aws_ecr_host_bytes_max);
    if (host.len == 0 or host.len > constants.aws_ecr_host_bytes_max) return .other;
    // Only a host that names ECR at all gets past this point: ordinary registries stay `other`.
    if (std.mem.indexOf(u8, host, ".dkr.ecr") == null) {
        if (std.mem.indexOf(u8, host, ".dkr.ecr-fips") == null) return .other;
    }
    const digits = constants.aws_account_digits;
    if (host.len <= digits + 1) return .other;
    for (host[0..digits]) |byte| {
        if (!std.ascii.isDigit(byte)) return .other;
    }
    var rest = host[digits..];
    if (!std.mem.startsWith(u8, rest, ".dkr.ecr.")) return .unsupported;
    rest = rest[".dkr.ecr.".len..];
    const suffix = ".amazonaws.com";
    if (!std.mem.endsWith(u8, rest, suffix)) return .unsupported;
    const region = rest[0 .. rest.len - suffix.len];
    if (!valid_region(region)) return .unsupported;
    var account: [constants.aws_account_digits]u8 = undefined;
    @memcpy(&account, host[0..digits]);
    assert(region.len > 0);
    assert(region.len <= constants.aws_region_bytes_max);
    return .{ .private = .{ .account = account, .region = region } };
}

/// A region name: lower-case letters and digits in dash-separated parts, `us-east-1` or
/// `ap-southeast-2`, and no more than `aws_region_bytes_max` bytes. A name with a dot, a
/// `fips` part or an empty part is not one.
pub fn valid_region(region: []const u8) bool {
    if (region.len < 5 or region.len > constants.aws_region_bytes_max) return false;
    var part_length: u32 = 0;
    var parts: u32 = 0;
    for (region) |byte| {
        if (byte == '-') {
            if (part_length == 0) return false;
            part_length = 0;
            parts += 1;
        } else if (std.ascii.isLower(byte) or std.ascii.isDigit(byte)) {
            part_length += 1;
        } else {
            return false;
        }
    }
    if (part_length == 0) return false;
    parts += 1;
    if (parts < 3) return false;
    return !std.mem.containsAtLeast(u8, region, 1, "fips");
}

/// The host of the AWS endpoint of `service` in `region`, `sts.us-east-1.amazonaws.com`.
pub fn service_host(buffer: []u8, service: []const u8, region: []const u8) []const u8 {
    assert(valid_region(region));
    assert(service.len > 0);
    assert(service.len <= constants.aws_service_bytes_max);
    const text = std.fmt.bufPrint(buffer, "{s}.{s}.amazonaws.com", .{ service, region }) catch
        unreachable; // The caller's buffer holds a region and a service name plus 15 bytes.
    assert(std.mem.endsWith(u8, text, ".amazonaws.com"));
    return text;
}

test "private ECR hosts are recognised with their account and region" {
    // Goal: the one accepted form yields the account digits and the region as a slice.
    const found = classify("123456789012.dkr.ecr.us-east-1.amazonaws.com");
    try std.testing.expectEqualStrings("123456789012", &found.private.account);
    try std.testing.expectEqualStrings("us-east-1", found.private.region);
    const far = classify("000000000001.dkr.ecr.ap-southeast-2.amazonaws.com");
    try std.testing.expectEqualStrings("ap-southeast-2", far.private.region);
}

test "public ECR and ordinary registries stay on the ordinary path" {
    // Goal: only ECR private hosts are special; the rest are not touched.
    try std.testing.expect(classify("public.ecr.aws") == .public);
    try std.testing.expect(classify("registry-1.docker.io") == .other);
    try std.testing.expect(classify("ghcr.io") == .other);
    try std.testing.expect(classify("localhost") == .other);
    try std.testing.expect(classify("") == .other);
    try std.testing.expect(classify("12345678901.dkr.ecr.us-east-1.amazonaws.com") == .other);
    try std.testing.expect(classify("12345678901x.dkr.ecr.us-east-1.amazonaws.com") == .other);
    try std.testing.expect(classify("evil.com.dkr.ecr.us-east-1.amazonaws.com") == .other);
}

test "other partitions, FIPS and malformed regions are unsupported, never guessed at" {
    // Goal: every ECR-looking host that is not the plain `aws` partition says so.
    const unsupported = [_][]const u8{
        "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn",
        "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com",
        "123456789012.dkr.ecr.us-east-1.api.aws",
        "123456789012.dkr.ecr.us-east-1.amazonaws.com.evil.example",
        "123456789012.dkr.ecr..amazonaws.com",
        "123456789012.dkr.ecr.us-east-1.fips.amazonaws.com",
        "123456789012.dkr.ecr.useast1.amazonaws.com",
        "123456789012.dkr.ecr.US-EAST-1.amazonaws.com",
        "123456789012.dkr.ecr.a.b.amazonaws.com",
    };
    for (unsupported) |host| {
        try std.testing.expect(classify(host) == .unsupported);
    }
}

test "service hosts" {
    // Goal: the endpoint names zbx builds are exactly AWS's.
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "sts.eu-west-1.amazonaws.com",
        service_host(&buffer, "sts", "eu-west-1"),
    );
    try std.testing.expectEqualStrings(
        "api.ecr.us-east-1.amazonaws.com",
        service_host(&buffer, "api.ecr", "us-east-1"),
    );
}

test "region validity at its boundaries" {
    // Goal: the length limits and part rules are exact.
    try std.testing.expect(valid_region("us-east-1"));
    try std.testing.expect(valid_region("me-central-1"));
    try std.testing.expect(!valid_region("us-east"));
    try std.testing.expect(!valid_region("us--east-1"));
    try std.testing.expect(!valid_region("-us-east-1"));
    try std.testing.expect(!valid_region("us-east-1-"));
    const long = "aaaaaaaa-bbbbbbbbb-cccccccc-d";
    try std.testing.expect(!valid_region(long));
}
