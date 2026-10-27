//! The registry's diagnostics, in one place: each function raises one registered code and fills
//! in the causes, context and fixes (DIAGNOSTICS.md). The code under `registry/` reports failures
//! as plain Zig errors plus the facts; nothing in it formats text for a user.
//!
//! A URL is always shown without its query (a redirect to a CDN carries a signature), and a token
//! is never an argument of any function here.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const blobs = @import("blobs.zig");
const errors = @import("../diag/errors.zig");
const net = @import("net.zig");
const reference_mod = @import("reference.zig");
const manifest = @import("manifest.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const Sha256 = @import("digest.zig").Sha256;

const echo_bytes_max = 96;

const fix_again = "run the command again; if it repeats, the registry or a proxy is at fault";

fn echo_of(storage: *[echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max * 4);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0501: the text is not a reference.
pub fn bad_reference(diag: *Diag, text: []const u8, err: reference_mod.Error) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, text);
    diag.raise(.E0501);
    diag.while_("reading an image reference", .{});
    switch (err) {
        error.Empty => diag.cause("the reference is empty", .{}),
        error.TooLong => diag.cause(
            "the reference is longer than {d} bytes, or its repository is longer than {d}",
            .{ constants.reference_bytes_max, constants.reference_repository_bytes_max },
        ),
        error.BadCharacter => diag.cause(
            "'{s}' has a space, a control character or a byte outside ASCII",
            .{echo},
        ),
        error.LooksLikeUrl => diag.cause("'{s}' is a URL, and a reference has no scheme", .{echo}),
        error.MissingRepository => diag.cause("'{s}' names no repository", .{echo}),
        error.BadRegistry => diag.cause(
            "the registry in '{s}' is not a DNS name (IPv6 literals are not supported)",
            .{echo},
        ),
        error.BadPort => diag.cause("the registry's port in '{s}' is not 1 to 65535", .{echo}),
        error.BadRepository => diag.cause(
            "the repository in '{s}' is not lowercase letters and digits joined by '.', '_', " ++
                "'__' or '-' in parts separated by '/'",
            .{echo},
        ),
        error.UppercaseRepository => diag.cause(
            "the repository in '{s}' has an uppercase letter, which a repository never has",
            .{echo},
        ),
        error.BadTag => diag.cause(
            "the tag in '{s}' is not 1 to 128 letters, digits, '_', '.' or '-', not starting " ++
                "with '.' or '-'",
            .{echo},
        ),
        error.BadDigest => diag.cause(
            "the digest in '{s}' is not 'sha256:' and 64 lowercase hex digits",
            .{echo},
        ),
        error.UnsupportedDigestAlgorithm => diag.cause(
            "the digest in '{s}' is not a sha256 digest, the only kind zbx reads",
            .{echo},
        ),
    }
    diag.context("ref", "{s}", .{echo});
    diag.fix(.{ .sentence = "write it as name[:tag]:", .command = "zbx pull alpine:3.20" });
    diag.fix(.{
        .sentence = "or with a registry:",
        .command = "zbx pull ghcr.io/owner/image:v1",
    });
    assert(diag.code.? == .E0501);
}

/// ZBX-E0514: an entry of `ZBX_REGISTRY_MIRRORS` is not a host or host:port.
pub fn bad_mirror(diag: *Diag, entry: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, entry);
    diag.raise(.E0514);
    diag.while_("reading ZBX_REGISTRY_MIRRORS", .{});
    diag.cause(
        "'{s}' is not a registry host (a DNS name, optionally with :port, no scheme or path), " ++
            "or the list has more than {d} entries",
        .{ echo, constants.registry_mirrors_max },
    );
    diag.context("mirror", "{s}", .{echo});
    diag.fix(.{
        .sentence = "write the list as host[:port],host[:port]:",
        .command = "ZBX_REGISTRY_MIRRORS=mirror.gcr.io zbx pull alpine:3.20",
    });
    assert(diag.code.? == .E0514);
}

/// ZBX-E0511: a blob in the cache no longer hashes to its name: the disk changed it.
pub fn blob_damaged(diag: *Diag, root: []const u8, expected: Sha256, actual: Sha256) void {
    assert(diag.code == null);
    assert(!expected.eql(actual));
    diag.raise(.E0511);
    diag.cause("a downloaded layer in the blob cache has changed on the disk", .{});
    diag.cause("expected {s} but got {s}", .{ &expected.text(), &actual.text() });
    diag.context("expect", "{s}", .{&expected.text()});
    diag.context("actual", "{s}", .{&actual.text()});
    diag.context("path", "{s}/blobs/sha256/{s}", .{ root, &expected.hex() });
    diag.fix_with(
        "remove the damaged blob and pull again:",
        "rm '{s}/blobs/sha256/{s}'",
        .{ root, &expected.hex() },
    );
}

/// ZBX-E0416 for a full disk and ZBX-E0417 for any other failure to write the blob cache.
pub fn cache_failed(diag: *Diag, root: []const u8, failure: *const blobs.Failure) void {
    assert(diag.code == null);
    assert(failure.step.len > 0);
    const full = failure.err == error.NoSpace;
    diag.raise(if (full) .E0416 else .E0417);
    diag.while_("writing the blob cache", .{});
    errors.cause_host_error(diag, failure.step, failure.err, failure.errno);
    diag.context("path", "{s}", .{root});
    if (full) {
        diag.fix_with(
            "free space on the disk that holds the store, then run the same command again:",
            "df -h '{s}'",
            .{root},
        );
        diag.fix(.{ .sentence = "the blobs already downloaded are kept, and the pull resumes" });
    } else {
        diag.fix(.{ .sentence = "check that you can write to the store directory, and the disk" });
    }
}

/// What the client was doing, for the causes: the host and port of the failed request.
pub const Target = struct {
    host: []const u8,
    port: u16,
    scheme: net.Scheme,
};

/// ZBX-E0502 to E0504, E0512 and E0513: a request failed on the wire. `errno` is the real
/// system error, shown only in verbose output.
pub fn network_failed(diag: *Diag, err: net.Error, target: Target, errno: u16) void {
    assert(diag.code == null);
    assert(target.host.len > 0);
    var storage: [echo_bytes_max]u8 = undefined;
    const host = echo_of(&storage, target.host);
    switch (err) {
        error.UnknownHost => unknown_host(diag, host),
        error.TlsUntrusted, error.TlsExpired, error.TlsHostMismatch, error.TlsFailed => {
            tls_failed(diag, err, host);
        },
        error.NoCertificates => no_certificates(diag),
        error.Truncated => {
            diag.raise(.E0513);
            diag.cause("{s} closed the connection before the whole answer arrived", .{host});
            diag.fix(.{ .sentence = "run the command again" });
        },
        error.TooLarge, error.BadResponse, error.SinkFailed, error.IoFailed, error.Unsupported => {
            unusable_wire(diag, err, host);
        },
        error.ConnectFailed, error.ProxyFailed, error.TimedOut => {
            cannot_connect(diag, err, host, target.port);
        },
    }
    diag.context("host", "{s}", .{host});
    if (errno != 0) diag.context("errno", "{d}", .{errno});
    assert(diag.code != null);
}

fn unknown_host(diag: *Diag, host: []const u8) void {
    assert(host.len > 0);
    assert(diag.code == null);
    diag.raise(.E0502);
    diag.cause("no address was found for '{s}'", .{host});
    diag.fix(.{ .sentence = "check the registry's name in the reference" });
    diag.fix(.{
        .sentence = "and that this machine resolves names:",
        .command = "getent hosts docker.io",
    });
}

fn cannot_connect(diag: *Diag, err: net.Error, host: []const u8, port: u16) void {
    assert(host.len > 0);
    assert(port != 0);
    diag.raise(.E0503);
    switch (err) {
        error.TimedOut => diag.cause("{s}:{d} did not answer within {d} seconds", .{
            host,
            port,
            constants.net_idle_timeout_ms / 1000,
        }),
        error.ProxyFailed => diag.cause(
            "the proxy refused to open a tunnel to {s}:{d}, or is not a proxy",
            .{ host, port },
        ),
        else => diag.cause("the connection to {s}:{d} failed", .{ host, port }),
    }
    diag.fix(.{ .sentence = "check that the network is up and that HTTPS_PROXY, if set, works" });
    diag.fix(.{ .sentence = "then run the command again" });
}

fn tls_failed(diag: *Diag, err: net.Error, host: []const u8) void {
    assert(host.len > 0);
    assert(diag.code == null);
    diag.raise(.E0504);
    switch (err) {
        error.TlsUntrusted => diag.cause(
            "the certificate of {s} does not lead to a root this machine trusts",
            .{host},
        ),
        error.TlsExpired => diag.cause(
            "the certificate of {s} is expired or not yet valid (is the clock right?)",
            .{host},
        ),
        error.TlsHostMismatch => diag.cause("the certificate is not for the host {s}", .{host}),
        else => diag.cause("the TLS handshake with {s} failed", .{host}),
    }
    diag.fix(.{ .sentence = "behind a proxy that inspects traffic, trust its CA certificate" });
    diag.fix(.{ .sentence = "in the system store, or in a file that SSL_CERT_FILE names" });
}

fn no_certificates(diag: *Diag) void {
    assert(diag.code == null);
    assert(constants.arg_bytes_max > 0);
    diag.raise(.E0504);
    diag.cause("no CA certificates could be loaded, so no HTTPS peer can be verified", .{});
    diag.fix(.{ .sentence = "install the system's CA certificates (the ca-certificates package)" });
    diag.fix(.{ .sentence = "or point SSL_CERT_FILE at a file of certificates to trust" });
}

fn unusable_wire(diag: *Diag, err: net.Error, host: []const u8) void {
    assert(host.len > 0);
    assert(diag.code == null);
    diag.raise(.E0512);
    switch (err) {
        error.TooLarge => diag.cause("{s} sent more than zbx accepts in one answer", .{host}),
        error.BadResponse => diag.cause("{s} did not answer in usable HTTP", .{host}),

        error.Unsupported => diag.cause("the request to {s} is too large to send", .{host}),
        else => diag.cause("reading the answer of {s} failed", .{host}),
    }
    diag.fix(.{ .sentence = fix_again });
}

/// ZBX-E0505: a status zbx has no code for, or a redirect it can't follow.
pub fn http_error(diag: *Diag, status: u16, url: []const u8, detail: ?[]const u8) void {
    assert(diag.code == null);
    assert(status >= 100);
    assert(status <= 599);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, net.without_query(url));
    diag.raise(.E0505);
    if (detail) |text| {
        diag.cause("{s} answered {d}: {s}", .{ shown, status, text });
    } else {
        diag.cause("{s} answered {d}", .{ shown, status });
    }
    diag.context("url", "{s}", .{shown});
    diag.context("status", "{d}", .{status});
    if (status >= 500) {
        diag.fix(.{ .sentence = "this is the registry's failure; run the command again later" });
    } else {
        diag.fix(.{ .sentence = "check the reference and that the registry serves this image" });
    }
}

/// ZBX-E0506: 429. `retry_after` is the registry's Retry-After value, as text.
pub fn rate_limited(diag: *Diag, url: []const u8, retry_after: ?[]const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, net.without_query(url));
    diag.raise(.E0506);
    diag.context("url", "{s}", .{shown});
    if (retry_after) |text| {
        var wait_storage: [32]u8 = undefined;
        const wait = text_util.sanitise(&wait_storage, text);
        diag.cause("{s} answered 429: the pull rate limit is used up; wait {s}", .{ shown, wait });
        diag.context("wait", "{s}", .{wait});
    } else {
        diag.cause("{s} answered 429: the pull rate limit is used up", .{shown});
    }
    diag.fix(.{ .sentence = "wait a few minutes, then run the command again" });
    diag.fix(.{ .sentence = "or pull from another registry or mirror that has the image" });
}

/// Which step of the anonymous flow was refused.
pub const AuthStep = enum {
    /// A 401 with no Bearer challenge (Basic: the registry wants credentials).
    no_bearer,
    /// A Bearer challenge that could not be read.
    bad_challenge,
    /// The token service answered 401 or 403.
    token_refused,
    /// The token service's answer had no usable token.
    token_unusable,
    /// The registry still answered 401 with a token.
    token_rejected,
    /// The realm is not a URL zbx will ask.
    bad_realm,
};

/// ZBX-E0507: anonymous access did not work.
pub fn auth_refused(
    diag: *Diag,
    step: AuthStep,
    registry: []const u8,
    repository: []const u8,
) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, registry);
    diag.raise(.E0507);
    switch (step) {
        .no_bearer => diag.cause("{s} asks for credentials, and zbx pulls anonymously", .{shown}),
        .bad_challenge => diag.cause("{s} sent a challenge zbx can't read", .{shown}),
        .token_refused => diag.cause(
            "the token service of {s} refused an anonymous token for {s}",
            .{ shown, repository },
        ),
        .token_unusable => diag.cause("the token service of {s} sent no usable token", .{shown}),
        .token_rejected => diag.cause("{s} still answered 401 after a token", .{shown}),
        .bad_realm => diag.cause("the token service {s} named is not a URL zbx will ask", .{shown}),
    }
    diag.context("host", "{s}", .{shown});
    diag.context("repo", "{s}", .{repository});
    diag.fix(.{ .sentence = "check that the image is public and its name is right" });
    diag.fix(.{ .sentence = "private registries are not supported yet" });
}

/// ZBX-E0508: 404. `name` is the tag or digest that was asked for.
pub fn not_found(diag: *Diag, registry: []const u8, repository: []const u8, name: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const shown = echo_of(&storage, name);
    diag.raise(.E0508);
    diag.cause("{s} has no '{s}' in the repository {s}", .{ registry, shown, repository });
    diag.context("host", "{s}", .{registry});
    diag.context("repo", "{s}", .{repository});
    diag.context("name", "{s}", .{shown});
    diag.fix(.{ .sentence = "check the spelling of the name and the tag" });
}

/// ZBX-E0509: no entry for this platform; the index offers `offered`.
pub fn no_platform(
    diag: *Diag,
    wanted: ?manifest.Architecture,
    machine: []const u8,
    offered: *const manifest.Offered,
) void {
    assert(diag.code == null);
    assert(offered.total >= offered.listed);
    var list_storage: [160]u8 = undefined;
    var writer = std.Io.Writer.fixed(&list_storage);
    for (0..offered.listed) |index| {
        // A list cut to the storage is only shorter: it is for display.
        if (index > 0) writer.writeAll(", ") catch {};
        writer.writeAll(offered.label(@intCast(index))) catch {};
    }
    const more = offered.total - offered.listed;
    var machine_storage: [48]u8 = undefined;
    const kind = text_util.sanitise(&machine_storage, machine);
    diag.raise(.E0509);
    if (wanted == null) {
        diag.cause("zbx has no image platform for the machine type '{s}'", .{kind});
    }
    const name: []const u8 = if (wanted) |architecture| architecture.name() else "?";
    if (offered.listed == 0) {
        diag.cause("no linux/{s} build: the image offers no platform at all", .{name});
    } else if (more > 0) {
        const list = writer.buffered();
        diag.cause("no linux/{s} build: the image offers {s} and {d} more", .{ name, list, more });
    } else {
        diag.cause("no linux/{s} build: the image offers {s}", .{ name, writer.buffered() });
    }
    diag.context("offer", "{d}", .{offered.total});
    diag.fix(.{ .sentence = "choose a tag or an image built for this platform" });
}

/// What a media type problem was found in.
pub const Where = enum { document, index_entry, config, layer };

/// ZBX-E0510 and E0512: a body that `manifest.zig` refused.
pub fn unusable_document(diag: *Diag, err: manifest.ParseError, detail: []const u8) void {
    assert(diag.code == null);
    assert(detail.len <= 120);
    switch (err) {
        error.UnknownMediaType => {
            diag.raise(.E0510);
            diag.cause("the media type '{s}' is not one zbx reads", .{detail});
            diag.fix(.{ .sentence = "zbx reads OCI and Docker v2 images (tar, gzip, zstd)" });
        },
        error.MediaTypeMismatch => {
            diag.raise(.E0510);
            diag.cause("the document and its Content-Type name different types ({s})", .{detail});
            diag.fix(.{ .sentence = "this is the registry's fault; zbx does not guess" });
        },
        else => {
            diag.raise(.E0512);
            switch (err) {
                error.Malformed => diag.cause("the manifest is not a valid document", .{}),
                error.TooComplex => diag.cause("the manifest is too complex to read", .{}),
                error.TooManyEntries => diag.cause(
                    "the index has more than {d} entries",
                    .{constants.registry_index_entries_max},
                ),
                error.TooManyLayers => diag.cause(
                    "the image has more than {d} layers ({s})",
                    .{ constants.registry_layers_max, detail },
                ),
                error.BadDescriptor => diag.cause(
                    "a descriptor has a digest or a size zbx can't use ({s})",
                    .{detail},
                ),
                else => unreachable, // The two media type errors were handled above.
            }
            diag.fix(.{ .sentence = fix_again });
        },
    }
    assert(diag.code != null);
}

/// ZBX-E0511: bytes that do not hash to the digest that named them. `what` says which (a
/// manifest and where it came from) and goes in an earlier cause; the last cause, the one the
/// default output shows, holds both digests.
pub fn digest_mismatch(diag: *Diag, what: []const u8, expected: Sha256, actual: Sha256) void {
    assert(diag.code == null);
    assert(!expected.eql(actual));
    diag.raise(.E0511);
    diag.cause("{s} failed its check", .{what});
    diag.cause("expected {s} but got {s}", .{ &expected.text(), &actual.text() });
    diag.context("expect", "{s}", .{&expected.text()});
    diag.context("actual", "{s}", .{&actual.text()});
    diag.fix(.{ .sentence = "run the command again; if it repeats, do not trust this source" });
}
