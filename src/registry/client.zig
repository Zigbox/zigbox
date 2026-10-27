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
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const diagnose = @import("diagnose.zig");
const digest_mod = @import("digest.zig");
const manifest = @import("manifest.zig");
const net = @import("net.zig");
const reference_mod = @import("reference.zig");
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
};

/// The failure is in the `Diag`.
pub const Error = error{Failed};

pub const Origin = struct {
    scheme: net.Scheme,
    host: []const u8,
    port: u16,

    fn same(first: Origin, second: Origin) bool {
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
    machine: []const u8,
    token_len: u32,
    /// The mirrors for docker.io, comma separated (`ZBX_REGISTRY_MIRRORS`); empty for none.
    mirrors: []const u8,
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
            .machine = machine,
            .token_len = 0,
            .mirrors = "",
            .winner = 0,
        };
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
    assert(client.mirrors.len <= constants.registry_mirrors_bytes_max);
    list.count = 0;
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
    diagnose.bad_mirror(diag, entry);
    return error.Failed;
}

/// A refusal that another candidate might not make: the mirror was down, did not have the image,
/// or the like. What a mirror must not be able to do is change the answer, so a wrong digest, a
/// document that cannot be used, and a platform that is missing end the resolve.
fn falls_through(code: codes.Code) bool {
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
    var list: Candidates = undefined;
    try candidates(client, reference, &list, diag);
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
    const picked = manifest.select_platform(&document, architecture, &offered, &problem);
    const chosen = picked catch |err| return unusable(diag, err, &problem);
    const selected = chosen orelse {
        diagnose.no_platform(diag, architecture, client.machine, &offered);
        return error.Failed;
    };
    try fetch_platform_manifest(client, reference, origin, selected, architecture, resolved, diag);
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
    constants.oci_digest_text_bytes;

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
    const had_token = client.token_len > 0;
    try request_following(client, origin, target, manifest.accept, true, &sink, head, diag);
    if (head.status == 401 and !had_token) {
        // The one repeat: with the token that was just given. A second 401 is a refusal.
        try authenticate(client, reference, origin, head, diag);
        try request_following(client, origin, target, manifest.accept, true, &sink, head, diag);
    }
    try check_status(reference, origin, target, head, diag);
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

/// Maps the status of the answer to the manifest request. Anything but 200 is a refusal.
fn check_status(
    reference: *const Reference,
    origin: Origin,
    target: []const u8,
    head: *const net.Head,
    diag: *Diag,
) Error!void {
    assert(target.len > 0);
    assert(diag.code == null);
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    const url = url_of(&url_storage, origin, target);
    switch (head.status) {
        200 => return,
        401 => {
            const registry = reference.registry();
            diagnose.auth_refused(diag, .token_rejected, registry, reference.repository());
        },
        404 => {
            const name = target[std.mem.lastIndexOf(u8, target, "/").? + 1 ..];
            diagnose.not_found(diag, reference.registry(), reference.repository(), name);
        },
        429 => diagnose.rate_limited(diag, url, head.retry_after.slice()),
        else => diagnose.http_error(diag, head.status, url, null),
    }
    return error.Failed;
}

/// Reads the challenge of a 401 and gets a token for it; `client.token` holds it on success.
fn authenticate(
    client: *Client,
    reference: *const Reference,
    origin: Origin,
    head: *const net.Head,
    diag: *Diag,
) Error!void {
    assert(head.status == 401);
    assert(client.token_len == 0);
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
    try fetch_token(client, reference, parsed, diag);
    assert(client.token_len > 0);
    assert(diag.code == null);
}

fn fetch_token(client: *Client, reference: *const Reference, url: net.Url, diag: *Diag) Error!void {
    assert(url.target[0] == '/');
    assert(client.token_len == 0);
    const origin: Origin = .{ .scheme = url.scheme, .host = url.host, .port = url.port };
    var head: net.Head = .{};
    var sink: net.BufferSink = .{ .buffer = &client.workspace.token_body };
    const target = url.target;
    try request_following(client, origin, target, "application/json", false, &sink, &head, diag);
    var url_storage: [constants.registry_url_bytes_max]u8 = undefined;
    const shown = url_of(&url_storage, origin, url.target);
    const registry = reference.registry();
    const repository = reference.repository();
    switch (head.status) {
        200 => {},
        401, 403 => {
            diagnose.auth_refused(diag, .token_refused, registry, repository);
            return error.Failed;
        },
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
    const body = sink.bytes();
    const found = auth.parse_token(body, arena.allocator(), &client.workspace.token) orelse {
        diagnose.auth_refused(diag, .token_unusable, registry, repository);
        return error.Failed;
    };
    client.token_len = @intCast(found.len);
    assert(client.token_len > 0);
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

fn is_redirect(status: u16) bool {
    assert(status >= 100);
    assert(status <= 599);
    return status == 301 or status == 302 or status == 303 or status == 307 or status == 308;
}

/// One GET that follows redirects. The token goes only to the origin the client started with
/// (`use_token`, and the same origin); a hop to another host drops it.
fn request_following(
    client: *Client,
    origin: Origin,
    target: []const u8,
    accept: []const u8,
    use_token: bool,
    sink: *net.BufferSink,
    head: *net.Head,
    diag: *Diag,
) Error!void {
    assert(target.len > 0);
    assert(target[0] == '/');
    assert(sink.buffer.len > 0);
    assert(origin.port != 0);
    var host_storage: [256]u8 = undefined;
    var target_storage: [constants.registry_url_bytes_max]u8 = undefined;
    var current = origin;
    var current_target = target;
    for (0..constants.registry_redirects_max + 1) |hop| {
        sink.len = 0;
        const bearer: []const u8 = if (use_token and current.same(origin)) client.token() else "";
        const request: net.Request = .{
            .scheme = current.scheme,
            .host = current.host,
            .port = current.port,
            .target = current_target,
            .accept = accept,
            .bearer = bearer,
            .body_bytes_max = sink.buffer.len,
            .idle_timeout_ms = constants.net_idle_timeout_ms,
            .total_timeout_ms = constants.net_request_timeout_ms,
        };
        client.net.get(&request, head, sink.sink()) catch |err| {
            const target_info: diagnose.Target = .{
                .host = current.host,
                .port = current.port,
                .scheme = current.scheme,
            };

            diagnose.network_failed(diag, err, target_info, client.net.last_errno());
            return error.Failed;
        };
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

const Next = struct { origin: Origin, target: []const u8 };

/// The place a Location points at, copied into the storage (the head it came from is reused by
/// the next request). Null for one that is not followed: another scheme, a downgrade from https
/// to http, or a malformed URL.
fn follow(
    current: Origin,
    location: []const u8,
    host_storage: *[256]u8,
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
    var host: [256]u8 = undefined;
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
