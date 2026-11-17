//! The registry client: from a reference to the image to pull, over `net.zig`. It speaks the
//! OCI distribution API anonymously. For one reference it asks for the manifest; on `401` it reads
//! the `WWW-Authenticate: Bearer` challenge, asks the realm for a token and repeats the request
//! once (a second `401` is a refusal, not another round); when the answer is an index it picks the
//! entry for this host and fetches that manifest by its digest. Every manifest is hashed and
//! checked against the digest that named it before a byte of it is used. A `429` is a refusal with
//! the registry's Retry-After; nothing here retries, loops, or sleeps.
//!
//! The token is kept in the caller's workspace, sent only to the registry's own origin (a
//! redirect to another host does not get it), and is not an argument to any diagnostic.
//!
//! Redirects are followed here, up to `registry_redirects_max`, never from https to http (a
//! loopback registry spoken to in plain HTTP is the exception that stays on http).

const std = @import("std");
const assert = std.debug.assert;
const auth = @import("auth.zig");
const blobs_mod = @import("blobs.zig");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const diagnose = @import("diagnose.zig");
const digest_mod = @import("digest.zig");
const manifest = @import("manifest.zig");
const net = @import("net.zig");
const reference_mod = @import("reference.zig");
const google_diagnose = @import("../google/diagnose.zig");
const google_hosts = @import("../google/hosts.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Sha256 = digest_mod.Sha256;
const Reference = reference_mod.Reference;

/// The memory a resolve works in, owned by the caller: a manifest's bytes, the arena its JSON is
/// read in, the token and the token service's answer. Large, so it lives in the command's
/// storage, not on the stack.
pub const Workspace = struct {
    body: [constants.registry_manifest_bytes_max]u8,
    arena: [constants.registry_json_arena_bytes]u8,
    token: [constants.registry_token_bytes_max]u8,
    token_body: [constants.registry_token_response_bytes_max]u8,
    /// The `Basic` value of `Client.credential`: the ECR authorization token (base64 of
    /// `AWS:<password>`), or the base64 of `user:secret` for a realm. Secret: `Workspace.wipe`
    /// zeroes it.
    basic: [constants.registry_basic_bytes_max]u8,

    /// Zeroes every secret in it: the bearer token, the token service's answer (which also holds
    /// the ECR API's answer) and the ECR authorization token.
    pub fn wipe(workspace: *Workspace) void {
        std.crypto.secureZero(u8, &workspace.token);
        std.crypto.secureZero(u8, &workspace.token_body);
        std.crypto.secureZero(u8, &workspace.basic);
        assert(workspace.basic[0] == 0);
        assert(workspace.token_body[0] == 0);
    }
};

/// The failure is in the `Diag`.
pub const Error = error{Failed};

/// The one credential a pull holds, in `Workspace.basic`, chosen by the registry's host:
/// - `ecr_basic`: ECR's authorization token, `Basic` on the registry origin from the first
///   request (M6c).
/// - `realm_basic`: a user and a secret (Google's `oauth2accesstoken` and an access token),
///   `Basic` to the registry's same-host token realm only, after its challenge; the realm's
///   Bearer token then goes to the registry origin. Never both on one request.
pub const Credential = enum { none, ecr_basic, realm_basic };

/// Asked at most once per pull, when a Google registry's realm refuses an anonymous token
/// request and the pull holds no credential: the access token to send to the realm as
/// `oauth2accesstoken`, in the caller's storage, or null with the refusal in `diag`. The CLI asks
/// the metadata server here, or raises the refusal of a credentials file it deferred so a public
/// image still pulls anonymously (`pull_google.zig`).
pub const RealmFallback = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, registry: []const u8, diag: *Diag) ?[]const u8,
};

/// The longest `user:secret` a realm credential holds: what `Workspace.basic` encodes.
const realm_joined_bytes_max = constants.registry_basic_bytes_max / 4 * 3;

pub const Origin = struct {
    scheme: net.Scheme,
    host: []const u8,
    port: u16,

    pub fn same(first: Origin, second: Origin) bool {
        assert(first.host.len > 0);
        assert(second.host.len > 0);
        if (first.scheme != second.scheme) return false;
        if (first.port != second.port) return false;
        return std.ascii.eqlIgnoreCase(first.host, second.host);
    }
};

pub const Client = struct {
    net: net.Net,
    workspace: *Workspace,
    /// What this machine runs, from its `uname`; null for a machine this build has no images for.
    architecture: ?manifest.Architecture,
    /// A platform the machine runs through a translator (Rosetta in the macOS VM): used for an
    /// image whose index has no entry for `architecture`. Null on a plain Linux machine.
    fallback: ?manifest.Architecture,
    machine: []const u8,
    token_len: u32,
    /// The bytes of `workspace.basic` in use; 0 for `credential` `none`.
    basic_len: u32,
    credential: Credential,
    /// The host's class when it is Google's; `not_google` otherwise. Set by `resolve`.
    google: google_hosts.Host,
    /// For a Google registry with no credential: see `RealmFallback`. Null for none.
    realm_fallback: ?RealmFallback,
    /// The mirrors for docker.io, comma separated (`ZBX_REGISTRY_MIRRORS`); empty for none.
    mirrors: []const u8,
    /// The places the last resolve could ask, for the blobs.
    places: Candidates,
    /// Which candidate (see `Candidates`) answered the last resolve; blobs ask it first.
    winner: u32,

    pub fn init(
        wire: net.Net,
        workspace: *Workspace,
        machine: []const u8,
    ) Client {
        assert(machine.len < constants.uname_field_bytes);
        assert(@intFromPtr(workspace) != 0);
        return .{
            .net = wire,
            .workspace = workspace,
            .architecture = manifest.architecture_of_machine(machine),
            .fallback = null,
            .machine = machine,
            .token_len = 0,
            .basic_len = 0,
            .credential = .none,
            .google = .not_google,
            .realm_fallback = null,
            .mirrors = "",
            .places = undefined,
            .winner = 0,
        };
    }

    fn basic(client: *const Client) []const u8 {
        assert(client.basic_len <= constants.registry_basic_bytes_max);
        assert(client.workspace.basic.len == constants.registry_basic_bytes_max);
        if (client.credential == .none) assert(client.basic_len == 0);
        return client.workspace.basic[0..client.basic_len];
    }

    /// Holds `user:secret` as the realm credential, base64 in `workspace.basic`; the caller's
    /// copy of the secret is the caller's to wipe.
    pub fn use_realm_basic(client: *Client, user: []const u8, secret: []const u8) void {
        assert(user.len > 0);
        assert(secret.len > 0);
        assert(client.credential != .ecr_basic);
        const joined_len = user.len + 1 + secret.len;
        var joined: [realm_joined_bytes_max]u8 = undefined;
        assert(joined_len <= joined.len);
        defer std.crypto.secureZero(u8, &joined);
        @memcpy(joined[0..user.len], user);
        joined[user.len] = ':';
        @memcpy(joined[user.len + 1 .. joined_len], secret);
        const encoded = std.base64.standard.Encoder.encode(
            &client.workspace.basic,
            joined[0..joined_len],
        );
        client.basic_len = @intCast(encoded.len);
        client.credential = .realm_basic;
        assert(client.basic_len > 0);
    }

    fn token(client: *const Client) []const u8 {
        assert(client.token_len <= constants.registry_token_bytes_max);
        assert(client.workspace.token.len == constants.registry_token_bytes_max);
        return client.workspace.token[0..client.token_len];
    }
};

/// The places an image may be asked for, in order: for a docker.io reference the mirrors, then
/// Docker Hub; for any other registry only itself.
pub const Candidates = struct {
    origins: [constants.registry_mirrors_max + 1]Origin,
    count: u32,
    names: [constants.registry_mirrors_max][constants.reference_registry_bytes_max]u8,
};

/// Reads the mirror setting. A mirror that is not `host` or `host:port` is a refusal naming it
/// (`E0514`), also for a reference that would not use it: a wrong setting is found at once.
pub fn candidates(
    client: *const Client,
    reference: *const Reference,
    list: *Candidates,
    diag: *Diag,
) Error!void {
    list.count = 0;
    // The setting is the caller's, so a setting too long is a refusal, not a programming error.
    if (client.mirrors.len > constants.registry_mirrors_bytes_max) {
        const shown = client.mirrors[0..@min(client.mirrors.len, constants.arg_bytes_max)];
        return bad_mirror(diag, shown);
    }
    var mirrors_used: u32 = 0;
    var entries = std.mem.splitScalar(u8, client.mirrors, ',');
    while (entries.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t");
        if (entry.len == 0) continue;
        const usable = entry.len <= list.names[0].len and mirrors_used < list.names.len;
        if (!usable) return bad_mirror(diag, entry);
        const lowered = std.ascii.lowerString(&list.names[mirrors_used], entry);
        reference_mod.registry_valid(lowered) catch return bad_mirror(diag, entry);
        const endpoint = reference_mod.endpoint_of(lowered);
        list.origins[mirrors_used] = .{
            .scheme = endpoint.scheme,
            .host = endpoint.host,
            .port = endpoint.port,
        };
        mirrors_used += 1;
    }
    const own = reference.endpoint();
    const is_hub = std.mem.eql(u8, reference.registry(), reference_mod.docker_hub);
    // Mirrors are for Docker Hub only; Docker Hub itself is always the last candidate.
    const used: u32 = if (is_hub) mirrors_used else 0;
    list.origins[used] = .{ .scheme = own.scheme, .host = own.host, .port = own.port };
    list.count = used + 1;
    assert(list.count >= 1);
    assert(list.count <= list.origins.len);
}

fn bad_mirror(diag: *Diag, entry: []const u8) Error {
    assert(entry.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    diagnose.bad_mirror(diag, entry);
    return error.Failed;
}

/// A refusal that another candidate might not make: the mirror was down, did not have the image,
/// or the like. What a mirror must not be able to do is change the answer, so a wrong digest, a
/// document that cannot be used, and a platform that is missing end the resolve.
fn falls_through(code: codes.Code) bool {
    assert(@tagName(code).len == 5);
    return switch (code) {
        .E0502, .E0503, .E0504, .E0505, .E0506, .E0507, .E0508, .E0513 => true,
        else => false,
    };
}

/// Resolves `reference` to the image manifest for this machine's platform.
pub fn resolve(
    client: *Client,
    reference: *const Reference,
    resolved: *manifest.Resolved,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(client.workspace.body.len == constants.registry_manifest_bytes_max);
    const list = &client.places;
    client.google = google_hosts.classify(reference.registry());
    try candidates(client, reference, list, diag);
    var shown_storage: reference_mod.Formatted = undefined;
    const shown = reference.format(&shown_storage);
    for (list.origins[0..list.count], 0..) |origin, index| {
        client.token_len = 0; // A token is for one repository, one registry.
        if (index > 0) diag.reset(); // The earlier candidate's refusal was not the last word.
        const outcome = resolve_inner(client, reference, origin, resolved, diag);
        if (outcome) |_| {
            client.winner = @intCast(index);
            assert(resolved.layer_count <= constants.registry_layers_max);
            assert(resolved.manifest_size > 0);
            return;
        } else |err| {
            const last = index + 1 == list.count;
            if (!last and falls_through(diag.code.?)) continue;
            diag.while_("resolving {s}", .{shown});
            return err;
        }
    }
    unreachable; // The last candidate returns.
}

fn resolve_inner(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    resolved: *manifest.Resolved,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(client.token_len == 0);
    const architecture = client.architecture orelse {
        const empty: manifest.Offered = .{};
        diagnose.no_platform(diag, null, client.machine, &empty);
        return error.Failed;
    };
    var name_storage: reference_mod.ManifestName = undefined;
    const name = reference.manifest_name(&name_storage);
    var head: net.Head = .{};
    const top = try fetch_manifest(client, reference, origin, name, &head, diag);
    var problem: manifest.Problem = .{};
    var arena = std.heap.FixedBufferAllocator.init(&client.workspace.arena);
    const document = manifest.parse_document(
        arena.allocator(),
        client.workspace.body[0..top.body_len],
        head.content_type.slice(),
        &problem,
    ) catch |err| return unusable(diag, err, &problem);
    resolved.index_digest = null;
    if (!document.media.is_index()) {
        resolved.manifest_digest = top.digest;
        resolved.manifest_size = top.body_len;
        resolved.architecture = architecture;
        manifest.read_manifest(&document, resolved, &problem) catch |err| {
            return unusable(diag, err, &problem);
        };
        return;
    }
    resolved.index_digest = top.digest;
    var offered: manifest.Offered = .{};
    const picked = manifest.select_platform_or(
        &document,
        architecture,
        client.fallback,
        &offered,
        &problem,
    );
    const chosen = picked catch |err| return unusable(diag, err, &problem);
    const found = chosen orelse {
        diagnose.no_platform(diag, architecture, client.machine, &offered);
        return error.Failed;
    };
    const selected = found.selected;
    const architecture_found = found.architecture;
    try fetch_platform_manifest(
        client,
        reference,
        origin,
        selected,
        architecture_found,
        resolved,
        diag,
    );
}

fn unusable(diag: *Diag, err: manifest.ParseError, problem: *const manifest.Problem) Error {
    assert(diag.code == null);
    diagnose.unusable_document(diag, err, problem.text.slice());
    assert(diag.code != null);
    return error.Failed;
}

const Fetched = struct {
    digest: Sha256,
    body_len: u32,
};

/// The manifest of a chosen index entry, by digest, checked against the entry; its layers and
/// config are read into `resolved`.
fn fetch_platform_manifest(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    selected: manifest.Selected,
    architecture: manifest.Architecture,
    resolved: *manifest.Resolved,
    diag: *Diag,
) Error!void {
    assert(selected.size > 0);
    assert(selected.size <= constants.registry_manifest_bytes_max);
    var scratch: net.Head = .{};
    var wanted: Reference = reference.*;
    wanted.digest = selected.digest;
    wanted.tag_len = 0;
    const text = selected.digest.text();
    const fetched = try fetch_manifest(client, &wanted, origin, &text, &scratch, diag);
    if (fetched.body_len != selected.size) {
        var detail: [64]u8 = undefined;
        const format = "{d} bytes, the index says {d}";
        const numbers = .{ fetched.body_len, selected.size };
        // Cannot fail: two numbers and the words are under 64 bytes.
        const sizes = std.fmt.bufPrint(&detail, format, numbers) catch unreachable;
        diagnose.unusable_document(diag, error.BadDescriptor, sizes);
        return error.Failed;
    }
    var problem: manifest.Problem = .{};
    var arena = std.heap.FixedBufferAllocator.init(&client.workspace.arena);
    const document = manifest.parse_document(
        arena.allocator(),
        client.workspace.body[0..fetched.body_len],
        scratch.content_type.slice(),
        &problem,
    ) catch |err| return unusable(diag, err, &problem);
    if (document.media.is_index()) {
        problem.text.print("an index inside an index", .{});
        return unusable(diag, error.UnknownMediaType, &problem);
    }
    resolved.manifest_digest = fetched.digest;
    resolved.manifest_size = fetched.body_len;
    resolved.architecture = architecture;
    manifest.read_manifest(&document, resolved, &problem) catch |err| {
        return unusable(diag, err, &problem);
    };
    assert(resolved.manifest_digest.eql(selected.digest));
}

/// The most the request target of a manifest takes: "/v2/", a repository, "/manifests/", a name.
const manifest_target_bytes_max = 16 + constants.reference_repository_bytes_max +
    reference_mod.manifest_name_bytes_max;

/// Fetches the manifest `name` of `reference` into the workspace body and checks its digest. The
/// anonymous flow lives here: a 401 gets one token and one repeat.
fn fetch_manifest(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    name: []const u8,
    head: *net.Head,
    diag: *Diag,
) Error!Fetched {
    assert(name.len > 0);
    assert(origin.port != 0);
    var target_storage: [manifest_target_bytes_max]u8 = undefined;
    const target = std.fmt.bufPrint(
        &target_storage,
        "/v2/{s}/manifests/{s}",
        .{ reference.repository(), name },
    ) catch unreachable; // The storage holds the longest repository and name.
    var sink: net.BufferSink = .{ .buffer = &client.workspace.body };
    const had_token = client.token_len > 0 or client.credential == .ecr_basic;
    const receiver = Receiver.of_buffer(&sink, constants.net_request_timeout_ms);
    try request_following(client, origin, target, manifest.accept, true, receiver, head, diag);
    if (head.status == 401 and !had_token) {
        // The one repeat: with the token that was just given. A second 401 is a refusal.
        try authenticate(client, reference, origin, head, constants.net_request_timeout_ms, diag);
        try request_following(client, origin, target, manifest.accept, true, receiver, head, diag);
    }
    const seen = Seen.of(client, sink.bytes());
    try check_status(reference, origin, target, head, seen, diag);
    assert(head.status == 200);
    return verify_manifest(reference, name, head, sink.bytes(), diag);
}

fn verify_manifest(
    reference: *const Reference,
    name: []const u8,
    head: *const net.Head,
    body: []const u8,
    diag: *Diag,
) Error!Fetched {
    assert(body.len <= constants.registry_manifest_bytes_max);
    const actual = Sha256.of(body);
    if (reference.digest) |expected| {
        if (!expected.eql(actual)) {
            var what_storage: [constants.diag_field_bytes_max]u8 = undefined;
            // A digest is 71 bytes and the storage holds 200: the fallback is for the compiler.
            const what = std.fmt.bufPrint(&what_storage, "the manifest {s}", .{name}) catch
                "the manifest";
            diagnose.digest_mismatch(diag, what, expected, actual);
            return error.Failed;
        }
    }
    if (head.content_digest.slice()) |text| {
        if (Sha256.parse(text)) |claimed| {
            if (!claimed.eql(actual)) {
                const what = "the manifest, against the registry's own digest header";
                diagnose.digest_mismatch(diag, what, claimed, actual);
                return error.Failed;
            }
        }
    }
    if (reference.digest) |expected| assert(expected.eql(actual));
    return .{ .digest = actual, .body_len = @intCast(body.len) };
}

/// What a refusal's mapping knows of the request: whether it carried the ECR `Basic` credential,
/// and the answer's body (empty where the caller has none), which is read for the registry's
/// error code and never kept.
const Seen = struct {
    basic: bool = false,
    /// The pull held a Google realm credential: a refusal is the identity's.
    google: bool = false,
    gcr: bool = false,
    body: []const u8 = "",

    fn of(client: *const Client, body: []const u8) Seen {
        assert(body.len <= constants.registry_manifest_bytes_max);
        assert(client.basic_len <= constants.registry_basic_bytes_max);
        return .{
            .basic = client.credential == .ecr_basic,
            .google = client.credential == .realm_basic and client.google.credentialed(),
            .gcr = client.google == .gcr,
            .body = body,
        };
    }
};

/// Whether the registry's error body names `NAME_UNKNOWN`: the repository does not exist.
fn names_unknown(body: []const u8) bool {
    assert(body.len <= constants.registry_manifest_bytes_max);
    return std.mem.indexOf(u8, body, "NAME_UNKNOWN") != null;
}

/// Maps the status of the answer to the manifest request. Anything but 200 is a refusal.
fn check_status(
    reference: *const Reference,
    origin: Origin,
    target: []const u8,
    head: *const net.Head,
    seen: Seen,
    diag: *Diag,
) Error!void {
    assert(target.len > 0);
    assert(diag.code == null);
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    const url = url_of(&url_storage, origin, target);
    const registry = reference.registry();
    const repository = reference.repository();
    // The ECR credential is the registry's: an answer from the host a redirect led to (S3 for a
    // layer) says nothing of the AWS identity, so it is never read as the registry's refusal.
    const basic = seen.basic and !head.elsewhere;
    if (head.elsewhere and head.status == 403) {
        diagnose.http_error(diag, head.status, url, "the host it redirects to refused the request");
        return error.Failed;
    }
    if (seen.google and !head.elsewhere) {
        if (google_status(diag, registry, repository, head.status, seen)) return error.Failed;
    }
    switch (head.status) {
        200 => return,
        401 => if (basic) {
            diagnose.ecr_token_rejected(diag, registry);
        } else diagnose.auth_refused(diag, .token_rejected, registry, repository),
        403 => if (basic) {
            const blob = std.mem.indexOf(u8, target, "/blobs/") != null;
            diagnose.ecr_repository_denied(diag, registry, repository, blob);
        } else diagnose.http_error(diag, head.status, url, null),
        404 => {
            const name = target[std.mem.lastIndexOf(u8, target, "/").? + 1 ..];
            if (basic and names_unknown(seen.body)) {
                diagnose.ecr_repository_missing(diag, registry, repository);
            } else diagnose.not_found(diag, registry, repository, name);
        },
        429 => diagnose.rate_limited(diag, url, head.retry_after.slice()),
        else => diagnose.http_error(diag, head.status, url, null),
    }
    return error.Failed;
}

/// A Google registry's answer to a pull that held a realm credential: 401 is the access token
/// refused, 403 the repository denied (or missing: the registry answers both alike), 404
/// `NAME_UNKNOWN` the repository missing. Whether it raised one of them.
fn google_status(
    diag: *Diag,
    registry: []const u8,
    repository: []const u8,
    status: u16,
    seen: Seen,
) bool {
    assert(seen.google);
    assert(diag.code == null);
    switch (status) {
        401 => google_diagnose.token_refused(diag, registry, false),
        403 => google_diagnose.repository_denied(diag, registry, repository),
        404 => if (names_unknown(seen.body)) {
            google_diagnose.repository_missing(diag, registry, repository, seen.gcr);
        } else return false,
        else => return false,
    }
    assert(diag.code != null);
    return true;
}

/// Reads the challenge of a 401 and gets a token for it; `client.token` holds it on success.
fn authenticate(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    head: *const net.Head,
    timeout_ms: u32,
    diag: *Diag,
) Error!void {
    assert(head.status == 401);
    assert(client.token_len == 0);
    assert(timeout_ms > 0);
    const registry = reference.registry();
    const repository = reference.repository();
    const header = head.www_authenticate.slice() orelse {
        diagnose.auth_refused(diag, .no_bearer, registry, repository);
        return error.Failed;
    };
    const challenge = auth.parse_challenge(header) catch |err| {
        const step: diagnose.AuthStep = if (err == error.NoBearer) .no_bearer else .bad_challenge;
        diagnose.auth_refused(diag, step, registry, repository);
        return error.Failed;
    };
    var url_storage: [constants.registry_url_bytes_max * 2]u8 = undefined;
    const url = auth.token_url(&challenge, repository, &url_storage) catch {
        diagnose.auth_refused(diag, .bad_realm, registry, repository);
        return error.Failed;
    };
    const parsed = net.parse_url(url) catch {
        diagnose.auth_refused(diag, .bad_realm, registry, repository);
        return error.Failed;
    };
    // A token is asked for over HTTPS. Plain HTTP only when the registry itself is spoken to in
    // plain HTTP (a loopback registry) and the realm is on loopback too: a registry elsewhere
    // cannot send zbx to a service on this machine.
    const plain_ok = origin.scheme == .http and reference_mod.is_loopback(parsed.host);
    const secure = parsed.scheme == .https or plain_ok;

    if (!secure) {
        diagnose.auth_refused(diag, .bad_realm, registry, repository);
        return error.Failed;
    }
    try fetch_token(client, reference, origin, parsed, timeout_ms, diag);
    assert(client.token_len > 0);
    assert(diag.code == null);
}

fn fetch_token(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    url: net.Url,
    timeout_ms: u32,
    diag: *Diag,
) Error!void {
    assert(url.target[0] == '/');
    assert(client.token_len == 0);
    var head: net.Head = .{};
    var sink: net.BufferSink = .{ .buffer = &client.workspace.token_body };
    try token_request(client, reference, origin, url, timeout_ms, &sink, &head, diag);
    const refused = head.status == 401 or head.status == 403;
    const ask = client.credential == .none and client.google.credentialed();
    if (refused and ask) {
        if (client.realm_fallback) |fallback| {
            if (!auth.realm_allowed(origin.host, origin.scheme, url)) {
                // No token is asked for a realm it would never be sent to.
                const registry = reference.registry();
                diagnose.auth_refused(diag, .bad_realm, registry, reference.repository());
                return error.Failed;
            }
            // The one fallback, once: the anonymous answer was the registry's no.
            const secret = fallback.call(fallback.context, reference.registry(), diag) orelse {
                assert(diag.code != null);
                return error.Failed;
            };
            client.use_realm_basic(constants.google_realm_user, secret);
            try token_request(client, reference, origin, url, timeout_ms, &sink, &head, diag);
        }
    }
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    const token_origin: Origin = .{ .scheme = url.scheme, .host = url.host, .port = url.port };
    const shown = url_of(&url_storage, token_origin, url.target);
    switch (head.status) {
        200 => {},
        401, 403 => return token_refused(client, reference, head.status, diag),
        429 => {
            diagnose.rate_limited(diag, shown, head.retry_after.slice());
            return error.Failed;
        },
        else => {
            diagnose.http_error(diag, head.status, shown, null);
            return error.Failed;
        },
    }
    var arena = std.heap.FixedBufferAllocator.init(&client.workspace.arena);
    const found = auth.parse_token(sink.bytes(), arena.allocator(), &client.workspace.token);
    const usable = found orelse {
        const registry = reference.registry();
        diagnose.auth_refused(diag, .token_unusable, registry, reference.repository());
        return error.Failed;
    };
    client.token_len = @intCast(usable.len);
    assert(client.token_len > 0);
}

/// Asks the realm `url` for a token into `sink`: anonymously (following redirects, as any
/// registry's realm), or with the realm credential, which goes in one request with no redirect
/// and only to a realm `auth.realm_allowed` passes for the registry's origin.
fn token_request(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    url: net.Url,
    timeout_ms: u32,
    sink: *net.BufferSink,
    head: *net.Head,
    diag: *Diag,
) Error!void {
    assert(url.target[0] == '/');
    assert(timeout_ms > 0);
    sink.len = 0;
    if (client.credential != .realm_basic) {
        const at: Origin = .{ .scheme = url.scheme, .host = url.host, .port = url.port };
        const receiver = Receiver.of_buffer(sink, timeout_ms);
        const accept = "application/json";
        return request_following(client, at, url.target, accept, false, receiver, head, diag);
    }
    if (!auth.realm_allowed(origin.host, origin.scheme, url)) {
        // Refused before the credential is sent anywhere.
        diagnose.auth_refused(diag, .bad_realm, reference.registry(), reference.repository());
        return error.Failed;
    }
    const request = auth.realm_request(url, client.basic(), timeout_ms);
    client.net.call(&request, head, sink.sink()) catch |err| {
        const where: diagnose.Target = .{
            .host = url.host,
            .port = url.port,
            .scheme = url.scheme,
        };
        diagnose.network_failed(diag, err, where, client.net.last_errno());
        return error.Failed;
    };
    assert(head.status >= 100);
}

/// The realm said no (401 or 403). For a Google registry the answer is the identity's: the access
/// token refused, the repository denied, no credentials to try, or a host zbx sends none to.
fn token_refused(
    client: *const Client,
    reference: *const Reference,
    status: u16,
    diag: *Diag,
) Error {
    assert(status >= 401);
    assert(status <= 403);
    assert(diag.code == null);
    const registry = reference.registry();
    const repository = reference.repository();
    switch (client.google) {
        .artifact_registry, .gcr => if (client.credential == .realm_basic) {
            if (status == 401) {
                google_diagnose.token_refused(diag, registry, false);
            } else google_diagnose.repository_denied(diag, registry, repository);
        } else google_diagnose.none_given(diag, registry, false),
        .other_google => google_diagnose.unsupported_host(diag, registry),
        .mirror, .not_google => diagnose.auth_refused(diag, .token_refused, registry, repository),
    }
    assert(diag.code != null);
    return error.Failed;
}

/// "https://host:port/path" without the query, for a message.
fn url_of(
    storage: *[constants.registry_url_bytes_max]u8,
    origin: Origin,
    target: []const u8,
) []const u8 {
    assert(origin.host.len > 0);
    assert(target.len > 0);
    const scheme: []const u8 = if (origin.scheme == .https) "https" else "http";
    const default_port: u16 = if (origin.scheme == .https) 443 else 80;
    const path = net.without_query(target);
    const result = if (origin.port == default_port)
        std.fmt.bufPrint(storage, "{s}://{s}{s}", .{ scheme, origin.host, path })
    else
        std.fmt.bufPrint(storage, "{s}://{s}:{d}{s}", .{ scheme, origin.host, origin.port, path });
    const text = result catch storage[0..0];
    assert(text.len <= storage.len);
    return text;
}

pub fn is_redirect(status: u16) bool {
    assert(status >= 100);
    assert(status <= 599);
    return status == 301 or status == 302 or status == 303 or status == 307 or status == 308;
}

/// Where a response body goes and how much of it may come: a buffer that starts empty on every
/// hop, or a sink that knows an answer that is not its blob when it sees one.
const Receiver = struct {
    sink: net.Sink,
    body_bytes_max: u64,
    range_from: u64 = 0,
    range_last: ?u64 = null,
    buffer: ?*net.BufferSink = null,
    total_timeout_ms: u32,

    fn of_buffer(buffer: *net.BufferSink, timeout_ms: u32) Receiver {
        assert(buffer.buffer.len > 0);
        assert(timeout_ms > 0);
        return .{
            .sink = buffer.sink(),
            .body_bytes_max = buffer.buffer.len,
            .buffer = buffer,
            .total_timeout_ms = timeout_ms,
        };
    }
};

/// The request for one hop. The credential goes only to the origin the client started with
/// (`own`): a hop elsewhere (ECR sends blobs to S3, which refuses any Authorization) gets neither.
fn request_of(
    client: *const Client,
    own: bool,
    at: Origin,
    target: []const u8,
    accept: []const u8,
    receiver: Receiver,
) net.Request {
    assert(target.len > 0);
    assert(at.port != 0);
    // Only ECR's credential goes to the registry origin; a realm credential goes to the realm.
    const basic: []const u8 = if (own and client.credential == .ecr_basic) client.basic() else "";
    return .{
        .scheme = at.scheme,
        .host = at.host,
        .port = at.port,
        .target = target,
        .accept = accept,
        .bearer = if (own) client.token() else "",
        .basic = basic,
        .body_bytes_max = receiver.body_bytes_max,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = receiver.total_timeout_ms,
        .range_from = receiver.range_from,
        .range_last = receiver.range_last,
        .secret = basic.len > 0, // An ECR answer is held under the same care as its token.
    };
}

/// One GET that follows redirects. The token goes only to the origin the client started with
/// (`use_token`, and the same origin); a hop to another host drops it.
fn request_following(
    client: *Client,
    origin: Origin,
    target: []const u8,
    accept: []const u8,
    use_token: bool,
    receiver: Receiver,
    head: *net.Head,
    diag: *Diag,
) Error!void {
    assert(target.len > 0);
    assert(target[0] == '/');
    assert(receiver.body_bytes_max > 0);
    assert(origin.port != 0);
    var host_storage: [constants.registry_host_bytes_max]u8 = undefined;
    var target_storage: [constants.registry_url_bytes_max]u8 = undefined;
    var current = origin;
    var current_target = target;
    for (0..constants.registry_redirects_max + 1) |hop| {
        if (receiver.buffer) |buffer| buffer.len = 0;
        const own = use_token and current.same(origin);
        const request = request_of(client, own, current, current_target, accept, receiver);
        client.net.get(&request, head, receiver.sink) catch |err| {
            const target_info: diagnose.Target = .{
                .host = current.host,
                .port = current.port,
                .scheme = current.scheme,
            };

            diagnose.network_failed(diag, err, target_info, client.net.last_errno());
            return error.Failed;
        };
        head.elsewhere = !current.same(origin);
        if (!is_redirect(head.status)) return;
        var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
        const here = url_of(&url_storage, current, current_target);
        if (hop == constants.registry_redirects_max) {
            diagnose.http_error(diag, head.status, here, "too many redirects");
            return error.Failed;
        }
        const location = head.location.slice() orelse {
            diagnose.http_error(diag, head.status, here, "a redirect with no usable Location");
            return error.Failed;
        };
        const next = follow(current, location, &host_storage, &target_storage) orelse {
            diagnose.http_error(diag, head.status, here, "a redirect zbx will not follow");
            return error.Failed;
        };
        assert(next.target.len > 0);
        assert(next.target[0] == '/');
        current = next.origin;
        current_target = next.target;
    }
    unreachable; // The loop returns on the last hop.
}

pub const Next = struct { origin: Origin, target: []const u8 };

/// The place a Location points at, copied into the storage (the head it came from is reused by
/// the next request). Null for one that is not followed: another scheme, a downgrade from https
/// to http, or a malformed URL.
pub fn follow(
    current: Origin,
    location: []const u8,
    host_storage: *[constants.registry_host_bytes_max]u8,
    target_storage: *[constants.registry_url_bytes_max]u8,
) ?Next {
    assert(location.len <= constants.registry_url_bytes_max);
    assert(current.host.len > 0);
    if (location.len > 0 and location[0] == '/') {
        // Not a protocol-relative URL ("//host"): that would name another host.
        if (location.len > 1 and location[1] == '/') return null;
        // The target goes into a request line as it is, so nothing that could end or split it.
        for (location) |byte| {
            if (byte <= 0x20 or byte >= 0x7f or byte == '#') return null;
        }
        @memcpy(target_storage[0..location.len], location);
        const target = target_storage[0..location.len];
        return .{ .origin = current, .target = target };
    }
    const url = net.parse_url(location) catch return null;
    if (url.scheme == .http and current.scheme == .https) return null;
    @memcpy(host_storage[0..url.host.len], url.host);
    @memcpy(target_storage[0..url.target.len], url.target);
    const origin: Origin = .{
        .scheme = url.scheme,
        .host = host_storage[0..url.host.len],
        .port = url.port,
    };
    assert(url.target[0] == '/');
    assert(origin.host.len > 0);
    return .{ .origin = origin, .target = target_storage[0..url.target.len] };
}

test "a redirect target is followed only when it can go into a request line" {
    // Goal: relative targets keep the origin and are checked byte by byte; absolute ones may not
    // downgrade from https; protocol-relative ones are refused.
    var host: [constants.registry_host_bytes_max]u8 = undefined;
    var target: [constants.registry_url_bytes_max]u8 = undefined;
    const secure: Origin = .{ .scheme = .https, .host = "registry.test", .port = 443 };
    const relative = follow(secure, "/v2/x/blobs/sha256:ab?sig=1", &host, &target).?;
    try std.testing.expectEqualStrings("/v2/x/blobs/sha256:ab?sig=1", relative.target);
    try std.testing.expect(relative.origin.same(secure));
    try std.testing.expect(follow(secure, "//evil.test/x", &host, &target) == null);
    try std.testing.expect(follow(secure, "/a b", &host, &target) == null);
    try std.testing.expect(follow(secure, "/a\x7f", &host, &target) == null);
    try std.testing.expect(follow(secure, "/a#fragment", &host, &target) == null);
    try std.testing.expect(follow(secure, "http://cdn.test/x", &host, &target) == null);
    try std.testing.expect(follow(secure, "ftp://cdn.test/x", &host, &target) == null);
    try std.testing.expect(follow(secure, "relative/path", &host, &target) == null);
    const far = follow(secure, "https://cdn.test:8443/x?a=b", &host, &target).?;
    try std.testing.expectEqualStrings("cdn.test", far.origin.host);
    try std.testing.expectEqual(@as(u16, 8443), far.origin.port);
    try std.testing.expect(!far.origin.same(secure));
    const plain: Origin = .{ .scheme = .http, .host = "127.0.0.1", .port = 80 };
    try std.testing.expect(follow(plain, "http://127.0.0.1:81/x", &host, &target) != null);
}

// ---- Blobs ---------------------------------------------------------------------------------

/// What `fetch_blob` did.
pub const BlobOutcome = enum { cached, downloaded, resumed };

/// The blob `digest` of `size` bytes is in the cache when this returns, or the failure is in
/// `diag`. It asks the place that answered the resolve first and then the others, in order; a
/// candidate's refusal that another could answer differently falls through (see
/// `falls_through`), and a blob whose bytes are wrong never does.
pub fn fetch_blob(
    client: *Client,
    reference: *const Reference,
    digest: Sha256,
    size: u64,
    blobs: blobs_mod.Blobs,
    download: *blobs_mod.Download,
    diag: *Diag,
) Error!BlobOutcome {
    assert(diag.code == null);
    assert(size > 0);
    const count = client.places.count;
    assert(count >= 1);
    assert(client.winner < count);
    for (0..count) |attempt| {
        const index: u32 = place_at(client.winner, @intCast(attempt));
        if (attempt > 0) {
            diag.reset(); // The earlier candidate's refusal was not the last word.
            client.token_len = 0; // A token is for one registry.
        }
        const origin = client.places.origins[index];
        const outcome = blob_from(client, reference, origin, digest, size, blobs, download, diag);
        if (outcome) |done| return done else |err| {
            const last = attempt + 1 == count;
            if (!last and falls_through(diag.code.?)) continue;
            return err;
        }
    }
    unreachable; // The last candidate returns.
}

/// The `attempt`th place to ask: the winner first, then the others in their order.
fn place_at(winner: u32, attempt: u32) u32 {
    assert(winner < constants.registry_mirrors_max + 1);
    assert(attempt <= constants.registry_mirrors_max);
    if (attempt == 0) return winner;
    return if (attempt - 1 < winner) attempt - 1 else attempt;
}

fn cache_error(blobs: blobs_mod.Blobs, download: *const blobs_mod.Download, diag: *Diag) Error {
    assert(diag.code == null);
    assert(download.failure.step.len > 0);
    diagnose.cache_failed(diag, blobs.root, &download.failure);
    return error.Failed;
}

fn blob_from(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    digest: Sha256,
    size: u64,
    blobs: blobs_mod.Blobs,
    download: *blobs_mod.Download,
    diag: *Diag,
) Error!BlobOutcome {
    assert(size > 0);
    var head: net.Head = .{};
    for (0..2) |round| {
        const began = download.begin(blobs, digest, size, &head) catch {
            return cache_error(blobs, download, diag);
        };
        if (began == .cached) return .cached;
        const restart = if (download.complete()) false else request_blob(
            client,
            reference,
            origin,
            download,
            &head,
            diag,
        ) catch |err| {
            download.abandon();
            return err;
        };
        if (restart) {
            download.abandon();
            download.discard() catch return cache_error(blobs, download, diag);
            if (round == 1) return unsatisfiable(origin, digest, diag);
            continue;
        }
        const finished = download.finish() catch return cache_error(blobs, download, diag);
        switch (finished) {
            .ok => return if (download.was_resumed()) .resumed else .downloaded,
            .short => {
                const target: diagnose.Target = .{
                    .host = origin.host,
                    .port = origin.port,
                    .scheme = origin.scheme,
                };
                diagnose.network_failed(diag, error.Truncated, target, 0);
                return error.Failed;
            },
            .mismatch => |actual| {
                // Bytes that were kept from an earlier try may be what is wrong: once, fresh.
                if (round == 0 and download.was_resumed()) continue;
                diagnose.digest_mismatch(diag, "a layer or config blob", digest, actual);
                return error.Failed;
            },
        }
    }
    unreachable; // The second round returns in every branch.
}

/// The registry answered 416 to a request for the whole blob.
fn unsatisfiable(origin: Origin, digest: Sha256, diag: *Diag) Error {
    assert(digest.bytes.len == constants.oci_digest_bytes);
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    const url = url_of(&url_storage, origin, "/v2/blobs");
    diagnose.http_error(diag, 416, url, "it would not give the blob from its start");
    return error.Failed;
}

/// Asks for the blob (or the rest of it), with the one re-authentication a 401 gets. True if the
/// registry says the range cannot be satisfied (the partial file is wrong: start again).
fn request_blob(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    download: *blobs_mod.Download,
    head: *net.Head,
    diag: *Diag,
) Error!bool {
    assert(!download.complete());
    var target_storage: [manifest_target_bytes_max]u8 = undefined;
    const digest_text = download.digest.text();
    const target = std.fmt.bufPrint(
        &target_storage,
        "/v2/{s}/blobs/{s}",
        .{ reference.repository(), &digest_text },
    ) catch unreachable; // The storage holds the longest repository and a digest.
    for (0..2) |attempt| {
        const receiver: Receiver = .{
            .sink = download.sink(),
            // A registry may answer a range with the whole blob; the sink keeps the bound.
            .body_bytes_max = download.size,
            .range_from = download.range_from(),
            .total_timeout_ms = 0, // A blob is bounded by progress, not by time.
        };
        request_following(client, origin, target, "", true, receiver, head, diag) catch |err| {
            download.abandon();
            return blob_sink_failed(download, diag, err);
        };
        if (head.status == 401 and attempt == 0 and client.credential != .ecr_basic) {
            // A token lasts minutes and a layer can take longer: ask for a fresh one, once.
            client.token_len = 0;
            const timeout = constants.net_request_timeout_ms;
            try authenticate(client, reference, origin, head, timeout, diag);
            continue;
        }
        break;
    }
    if (head.status == 416) return true;
    const seen = Seen.of(client, "");
    if (head.status != 206) try check_status(reference, origin, target, head, seen, diag);
    return false;
}

const long_blob = "a blob longer than its manifest says";
const wrong_range = "a partial answer for another range";

/// A request that failed: if the sink refused the body, say why instead of the wire's error.
fn blob_sink_failed(download: *const blobs_mod.Download, diag: *Diag, err: Error) Error {
    assert(download.fd == null);
    assert(@errorName(err).len > 0);
    if (download.problem == .none) return err;
    diag.reset();
    switch (download.problem) {
        .io => diagnose.cache_failed(diag, download.blobs.root, &download.failure),
        .too_long => diagnose.unusable_document(diag, error.BadDescriptor, long_blob),
        .bad_range => diagnose.unusable_document(diag, error.BadDescriptor, wrong_range),
        .none => unreachable, // Handled above.
    }
    return error.Failed;
}

// ---- Ranges --------------------------------------------------------------------------------

/// Why `fetch_range` got no bytes; the failure is in the `Diag` too.
pub const RangeError = error{
    /// The registry does not hold the blob (`404`).
    NotFound,
    Failed,
};

/// A monotonic clock in milliseconds, from whatever the caller has (an `Io`, a `Host`).
pub const Clock = struct {
    context: *const anyopaque,
    now_ms: *const fn (context: *const anyopaque) u64,
};

/// When a call must be done: what `fetch_range` is given, so a token it has to fetch again comes
/// out of the same time as the range.
pub const Deadline = struct {
    clock: Clock,
    at_ms: u64,

    /// `timeout_ms` from now.
    pub fn after(clock: Clock, timeout_ms: u32) Deadline {
        assert(timeout_ms > 0);
        const now = clock.now_ms(clock.context);
        assert(now < std.math.maxInt(u64) - @as(u64, timeout_ms));
        return .{ .clock = clock, .at_ms = now + timeout_ms };
    }

    /// The whole milliseconds left, at most `limit_ms`; null when none are.
    pub fn remaining_ms(deadline: Deadline, limit_ms: u32) ?u32 {
        assert(deadline.at_ms > 0);
        assert(limit_ms > 0);
        const now = deadline.clock.now_ms(deadline.clock.context);
        if (now >= deadline.at_ms) return null;
        const left: u32 = @intCast(@min(deadline.at_ms - now, limit_ms));
        assert(left > 0);
        return left;
    }
};

/// Where a range answer's body goes: a `206`'s into the caller's buffer (at most its length),
/// any other status's (a 401's challenge page, a 404's JSON) nowhere, and at most
/// `push_error_body_bytes` of it (of every hop's together), however small the range: the bound is
/// the status's, never `out.len`'s. The head is filled before the first byte of the body comes.
const RangeSink = struct {
    buffer: *net.BufferSink,
    head: *const net.Head,
    other: u32 = 0,

    fn sink(range: *RangeSink) net.Sink {
        return .{ .context = range, .write = write };
    }

    fn write(context: *anyopaque, data: []const u8) error{SinkFull}!void {
        const range: *RangeSink = @ptrCast(@alignCast(context));
        assert(range.head.status >= 100);
        assert(range.other <= constants.push_error_body_bytes);
        if (range.head.status == 206) {
            const into = range.buffer.sink();
            return into.write(into.context, data);
        }
        if (data.len > constants.push_error_body_bytes - range.other) return error.SinkFull;
        range.other += @intCast(data.len);
    }
};

/// The most body bytes a range request takes: the range, or an error answer's bound.
fn range_body_bytes_max(out_len: usize) u64 {
    assert(out_len > 0);
    return @max(out_len, constants.push_error_body_bytes);
}

/// Bytes `offset` to `offset + out.len - 1` of blob `digest` by one closed `Range` request to the
/// place that answered the resolve, all of it (a fresh token after a 401 included) before
/// `deadline`, and no one request longer than `timeout_ms`. Only a `206` whose Content-Range
/// starts at `offset` is an answer; its bytes are unverified, for the caller to check. Returns
/// how many came: fewer than asked when the blob ends sooner.
pub fn fetch_range(
    client: *Client,
    reference: *const Reference,
    digest: Sha256,
    offset: u64,
    out: []u8,
    deadline: Deadline,
    timeout_ms: u32,
    diag: *Diag,
) RangeError!usize {
    assert(out.len > 0);
    assert(timeout_ms > 0);
    assert(diag.code == null);
    assert(client.winner < client.places.count);
    const origin = client.places.origins[client.winner];
    var target_storage: [manifest_target_bytes_max]u8 = undefined;
    const digest_text = digest.text();
    const target = std.fmt.bufPrint(
        &target_storage,
        "/v2/{s}/blobs/{s}",
        .{ reference.repository(), &digest_text },
    ) catch unreachable; // The storage holds the longest repository and a digest.
    var buffer: net.BufferSink = .{ .buffer = out };
    var head: net.Head = .{};
    var range: RangeSink = .{ .buffer = &buffer, .head = &head };
    for (0..2) |attempt| {
        range.other = 0;
        const left = deadline.remaining_ms(timeout_ms) orelse return out_of_time(origin, diag);
        const receiver: Receiver = .{
            .sink = range.sink(),
            .body_bytes_max = range_body_bytes_max(out.len),
            .range_from = offset,
            .range_last = offset + out.len - 1,
            .buffer = &buffer,
            .total_timeout_ms = left,
        };
        try request_following(client, origin, target, "", true, receiver, &head, diag);
        if (head.status == 401 and attempt == 0 and client.credential != .ecr_basic) {
            client.token_len = 0; // The token ran out mid-run: a fresh one, once.
            const auth_left = deadline.remaining_ms(timeout_ms) orelse {
                return out_of_time(origin, diag);
            };
            try authenticate(client, reference, origin, &head, auth_left, diag);
            continue;
        }
        break;
    }
    return range_answer(reference, origin, target, &head, buffer.len, offset, client, diag);
}

/// The deadline passed before a request of `fetch_range` could start.
fn out_of_time(origin: Origin, diag: *Diag) RangeError {
    assert(origin.port != 0);
    assert(diag.code == null);
    const target_info: diagnose.Target = .{
        .host = origin.host,
        .port = origin.port,
        .scheme = origin.scheme,
    };
    // Stalled, not TimedOut: the cause names the whole request's limit, not the idle one.
    diagnose.network_failed(diag, error.Stalled, target_info, 0);
    return error.Failed;
}

/// The bytes a range request got, or why it got none.
fn range_answer(
    reference: *const Reference,
    origin: Origin,
    target: []const u8,
    head: *const net.Head,
    got: u32,
    offset: u64,
    client: *const Client,
    diag: *Diag,
) RangeError!usize {
    assert(target.len > 0);
    assert(diag.code == null);
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    switch (head.status) {
        206 => {
            if (range_starts_at(head.content_range.slice() orelse "", offset)) return got;
            diagnose.unusable_document(diag, error.BadDescriptor, wrong_range);
            return error.Failed;
        },
        200 => {
            const url = url_of(&url_storage, origin, target);
            diagnose.http_error(diag, 200, url, "it answered a range request with the whole blob");
            return error.Failed;
        },
        else => {
            const seen = Seen.of(client, "");
            check_status(reference, origin, target, head, seen, diag) catch {};
            assert(diag.code != null);
            return if (head.status == 404) error.NotFound else error.Failed;
        },
    }
}

/// Whether a Content-Range ("bytes first-last/total") starts at `offset`.
pub fn range_starts_at(text: []const u8, offset: u64) bool {
    assert(text.len <= constants.registry_header_bytes_max);
    const prefix = "bytes ";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    const rest = text[prefix.len..];
    const dash = std.mem.indexOfScalar(u8, rest, '-') orelse return false;
    const first = std.fmt.parseInt(u64, rest[0..dash], 10) catch return false;
    return first == offset;
}

test "a Content-Range is read only when it starts where the request did" {
    // Goal: an answer for another range is never taken as the bytes asked for.
    try std.testing.expect(range_starts_at("bytes 10-19/100", 10));
    try std.testing.expect(!range_starts_at("bytes 0-99/100", 10));
    try std.testing.expect(!range_starts_at("bytes */100", 10));
    try std.testing.expect(!range_starts_at("items 10-19/100", 10));
    try std.testing.expect(!range_starts_at("", 0));
}
