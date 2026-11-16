//! Telling a Google registry host from any other, and what zbx does with each (M6d):
//!
//! - Artifact Registry, `<region>-docker.pkg.dev`, where the region is a location name (`us`,
//!   `europe-west4`): Google credentials, after an anonymous refusal or up front with workload
//!   identity federation.
//! - The four gcr.io hosts, `gcr.io`, `us.gcr.io`, `eu.gcr.io` and `asia.gcr.io`, which Artifact
//!   Registry serves today: the same.
//! - `mirror.gcr.io`, a public Docker Hub mirror: never credentials, never a change.
//! - Any other Google shape (`*.pkg.dev` that is not `<region>-docker`, any other `*.gcr.io` such
//!   as `k8s.gcr.io`): never credentials; the anonymous path as today, and a refusal there is
//!   reported as an unsupported Google host.
//! - Everything else: not Google.
//!
//! The classifier is pure: it reads the host text and nothing else. The host is what a reference
//! names as its registry, lower case; a port or an upper-case letter makes it `not_google`,
//! because Google's hosts take neither.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Host = enum {
    /// A `<region>-docker.pkg.dev` host.
    artifact_registry,
    /// One of the four gcr.io hosts.
    gcr,
    /// A Google registry shape zbx does not authenticate to.
    other_google,
    /// `mirror.gcr.io`, Docker Hub's public mirror.
    mirror,
    not_google,

    /// Whether Google credentials may ever be sent for this host.
    pub fn credentialed(host: Host) bool {
        return host == .artifact_registry or host == .gcr;
    }
};

pub const mirror_host = "mirror.gcr.io";
pub const gcr_hosts = [_][]const u8{ "gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io" };
const artifact_suffix = "-docker.pkg.dev";

/// Classifies `host` (lower case, no port).
pub fn classify(host: []const u8) Host {
    if (host.len == 0 or host.len > constants.registry_host_bytes_max) return .not_google;
    for (host) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '.' or byte == '-')) {
            return .not_google;
        }
    }
    if (std.mem.eql(u8, host, mirror_host)) return .mirror;
    for (gcr_hosts) |gcr_host| {
        if (std.mem.eql(u8, host, gcr_host)) return .gcr;
    }
    if (std.mem.endsWith(u8, host, ".gcr.io")) return .other_google;
    if (std.mem.eql(u8, host, "pkg.dev")) return .other_google;
    if (!std.mem.endsWith(u8, host, ".pkg.dev")) return .not_google;
    if (!std.mem.endsWith(u8, host, artifact_suffix)) return .other_google;
    const region = host[0 .. host.len - artifact_suffix.len];
    if (!valid_region(region)) return .other_google;
    assert(region.len <= constants.google_region_bytes_max);
    return .artifact_registry;
}

/// A location name: lower-case letters, digits and hyphens, starting with a letter, not ending
/// with a hyphen, without two hyphens together, at most `google_region_bytes_max` bytes.
pub fn valid_region(region: []const u8) bool {
    if (region.len == 0 or region.len > constants.google_region_bytes_max) return false;
    if (!std.ascii.isLower(region[0])) return false;
    if (region[region.len - 1] == '-') return false;
    var previous: u8 = 0;
    for (region) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-';
        if (!allowed) return false;
        if (byte == '-' and previous == '-') return false;
        previous = byte;
    }
    assert(region.len > 0);
    return true;
}

const testing = std.testing;

test "Google hosts are told apart" {
    // Goal: every shape the brief names lands in its class, and near misses fall to the safe
    // side: never credentials for a host that is not exactly one of the supported shapes.
    const cases = [_]struct { host: []const u8, class: Host }{
        .{ .host = "us-docker.pkg.dev", .class = .artifact_registry },
        .{ .host = "europe-west4-docker.pkg.dev", .class = .artifact_registry },
        .{ .host = "northamerica-northeast1-docker.pkg.dev", .class = .artifact_registry },
        .{ .host = "gcr.io", .class = .gcr },
        .{ .host = "us.gcr.io", .class = .gcr },
        .{ .host = "eu.gcr.io", .class = .gcr },
        .{ .host = "asia.gcr.io", .class = .gcr },
        .{ .host = "mirror.gcr.io", .class = .mirror },
        .{ .host = "k8s.gcr.io", .class = .other_google },
        .{ .host = "marketplace.gcr.io", .class = .other_google },
        .{ .host = "us-python.pkg.dev", .class = .other_google },
        .{ .host = "-docker.pkg.dev", .class = .other_google },
        .{ .host = "1us-docker.pkg.dev", .class = .other_google },
        .{ .host = "us--east-docker.pkg.dev", .class = .other_google },
        .{ .host = "a.us-docker.pkg.dev", .class = .other_google },
        .{ .host = "pkg.dev", .class = .other_google },
        .{ .host = "docker.io", .class = .not_google },
        .{ .host = "gcr.io.example.com", .class = .not_google },
        .{ .host = "evilgcr.io", .class = .not_google },
        .{ .host = "US-docker.pkg.dev", .class = .not_google },
        .{ .host = "gcr.io:443", .class = .not_google },
        .{ .host = "", .class = .not_google },
    };
    for (cases) |case| {
        try testing.expectEqual(case.class, classify(case.host));
    }
    try testing.expect(Host.artifact_registry.credentialed());
    try testing.expect(Host.gcr.credentialed());
    try testing.expect(!Host.mirror.credentialed());
    try testing.expect(!Host.other_google.credentialed());
}

test "a region at its bound" {
    // Goal: the longest region is accepted, one byte more is not.
    const longest: [constants.google_region_bytes_max]u8 = @splat('a');
    try testing.expectEqual(Host.artifact_registry, classify(&(longest ++ "-docker.pkg.dev".*)));
    try testing.expectEqual(Host.other_google, classify(&(longest ++ "a-docker.pkg.dev".*)));
}
