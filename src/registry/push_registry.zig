//! The upload test registry (`src/testing/vm/push_fixture.zig`) behind the simulator's network:
//! the fixture answers, `net_sim.zig` is the wire. Tests of the push code build one of these and
//! hand its `responder` to a `SimNet`.

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("../testing/vm/push_fixture.zig");
const net = @import("net.zig");
const net_sim = @import("net_sim.zig");

pub const PushFixture = fixture_mod.PushFixture;
pub const Fault = fixture_mod.Fault;

/// The registry's own host in the simulator, and the other host a Location may point at.
pub const registry_host = "registry.test";
pub const other_host = "other.test";

/// How the registry asks for credentials. The realm is the registry's own host (`/token`),
/// because that is the realm rule's ordinary case.
pub const Mode = enum {
    /// No challenge: every request is served.
    open,
    /// `Basic` is the challenge; the right user and password at the registry pass.
    basic,
    /// `Bearer`: `Basic` at `/token` buys a token with pull and push.
    bearer,
    /// As `bearer`, but the token endpoint grants `pull` only.
    pull_only,
    /// As `bearer`, but the challenge's realm is on another host.
    far_realm,
    /// As `bearer`, and the registry forgets the token after `expire_after` served requests.
    expiring,
};

/// The user the registry accepts, and the largest password a test gives it.
pub const test_user = "zbx-test";
const password_bytes_max = 64;

pub const PushRegistry = struct {
    fixture: PushFixture,
    /// Where the simulator drains an upload body to.
    drained: [fixture_mod.blob_bytes_max]u8,
    mode: Mode = .open,
    /// The host the registry answers as (`registry_host`; an ECR test names an ECR host), and the
    /// user it accepts.
    host: []const u8 = registry_host,
    user: []const u8 = test_user,
    /// The base64 of `test_user:<password>` the registry accepts; empty accepts none.
    expected: [(test_user.len + 1 + password_bytes_max + 2) / 3 * 4]u8 = undefined,
    expected_len: u8 = 0,
    /// Served requests after which an `expiring` registry forgets its token (once).
    expire_after: u32 = 0,
    served_count: u32 = 0,
    generation: u32 = 1,
    /// Requests to `/token`, and the scope the last one asked for.
    token_requests: u32 = 0,
    token_scope: [160]u8 = undefined,
    token_scope_len: u8 = 0,
    /// Requests to a host other than the registry's that carried any credential.
    leaked: u32 = 0,
    challenge: [256]u8 = undefined,
    token_body: [96]u8 = undefined,
    /// After this many served requests (0 for never) the registry changes its mode to
    /// `switch_to`: a registry whose challenge scheme changes in the middle of a push.
    switch_after: u32 = 0,
    switch_to: Mode = .open,
    /// When not empty, the realm the Bearer challenge names, in place of the two fixed ones.
    realm_override: []const u8 = "",
    /// When not empty, the whole `WWW-Authenticate` value, and the body of the token answer
    /// (fuzzers hand arbitrary bytes here).
    challenge_override: []const u8 = "",
    token_body_override: []const u8 = "",

    /// Starts the registry and gives `sim` the room to drain uploads into.
    pub fn init(registry: *PushRegistry, sim: *net_sim.SimNet) void {
        registry.fixture.init("https://" ++ registry_host, "https://" ++ other_host);
        registry.mode = .open;
        registry.host = registry_host;
        registry.user = test_user;
        registry.switch_after = 0;
        registry.switch_to = .open;
        registry.realm_override = "";
        registry.challenge_override = "";
        registry.token_body_override = "";
        registry.expected_len = 0;
        registry.expire_after = 0;
        registry.served_count = 0;
        registry.generation = 1;
        registry.token_requests = 0;
        registry.token_scope_len = 0;
        registry.leaked = 0;
        sim.received = &registry.drained;
        assert(sim.received.len == fixture_mod.blob_bytes_max);
    }

    pub fn responder(registry: *PushRegistry) net_sim.Responder {
        return .{ .context = registry, .answer = answer };
    }

    /// Makes the registry ask for credentials; `password` is what it will accept.
    pub fn require(registry: *PushRegistry, mode: Mode, password: []const u8) void {
        registry.require_as(test_user, mode, password);
    }

    /// As `require`, for a registry whose user is `user` (Amazon ECR's is `AWS`).
    pub fn require_as(
        registry: *PushRegistry,
        user: []const u8,
        mode: Mode,
        password: []const u8,
    ) void {
        assert(mode != .open);
        assert(user.len > 0);
        assert(user.len <= test_user.len);
        registry.user = user;
        assert(password.len > 0);
        assert(password.len <= password_bytes_max);
        var plain: [test_user.len + 1 + password_bytes_max]u8 = undefined;
        const text = std.fmt.bufPrint(
            &plain,
            "{s}:{s}",
            .{ user, password },
        ) catch unreachable; // plain fits user, colon and password
        const encoded = std.base64.standard.Encoder.encode(&registry.expected, text);
        registry.expected_len = @intCast(encoded.len);
        registry.mode = mode;
        std.crypto.secureZero(u8, &plain);
    }

    /// The scope the last token request asked for.
    pub fn scope_asked(registry: *const PushRegistry) []const u8 {
        return registry.token_scope[0..registry.token_scope_len];
    }

    fn expected_basic(registry: *const PushRegistry) []const u8 {
        return registry.expected[0..registry.expected_len];
    }

    /// The token the registry accepts now.
    fn push_token(registry: *PushRegistry, out: []u8) []const u8 {
        return std.fmt.bufPrint(
            out,
            "push-token-{d}",
            .{registry.generation},
        ) catch unreachable; // callers pass a buffer of 32 bytes or more
    }

    /// The destination text of a fault's repository: `registry.test/push/<fault>:v1`.
    pub fn destination(comptime fault: Fault) [:0]const u8 {
        return registry_host ++ "/push/" ++ @tagName(fault) ++ ":v1";
    }
};

fn method_of(method: net.Method) fixture_mod.Method {
    return switch (method) {
        .get => .get,
        .head => .head,
        .post => .post,
        .patch => .patch,
        .put => .put,
    };
}

fn answer(
    context: *anyopaque,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    const registry: *PushRegistry = @ptrCast(@alignCast(context));
    const has_credential = request.basic.len > 0 or request.bearer.len > 0;
    if (!std.mem.eql(u8, request.host, registry.host)) {
        if (has_credential) registry.leaked += 1;
        return delegate(registry, request, received, served);
    }
    if (registry.switch_after > 0 and registry.served_count >= registry.switch_after) {
        registry.mode = registry.switch_to;
        registry.switch_after = 0;
    }
    if (registry.mode == .open) return delegate(registry, request, received, served);
    if (std.mem.startsWith(u8, request.target, "/token")) {
        return token_endpoint(registry, request, served);
    }
    if (authorized(registry, request)) {
        registry.served_count += 1;
        const forget = registry.mode == .expiring and
            registry.served_count == registry.expire_after;
        if (forget) registry.generation += 1;
        if (!forget) return delegate(registry, request, received, served);
    }
    challenge(registry, request, served);
}

fn authorized(registry: *PushRegistry, request: *const net.Request) bool {
    assert(registry.mode != .open);
    if (registry.mode == .basic) {
        return request.basic.len > 0 and
            std.mem.eql(u8, request.basic, registry.expected_basic());
    }
    var token: [32]u8 = undefined;
    if (request.bearer.len == 0) return false;
    return std.mem.eql(u8, request.bearer, registry.push_token(&token));
}

fn challenge(registry: *PushRegistry, request: *const net.Request, served: *net_sim.Served) void {
    assert(registry.mode != .open);
    var text: []const u8 = "Basic realm=\"fixture\"";
    if (registry.mode != .basic) {
        var realm: []const u8 = if (registry.mode == .far_realm)
            "https://evil.test/token"
        else
            "https://" ++ registry_host ++ "/token";
        if (registry.realm_override.len > 0) realm = registry.realm_override;
        const error_part = if (request.bearer.len > 0) ",error=\"insufficient_scope\"" else "";
        text = std.fmt.bufPrint(
            &registry.challenge,
            "Bearer realm=\"{s}\",service=\"fixture\",scope=\"repository:push/ok:pull\"{s}",
            .{ realm, error_part },
        ) catch unreachable; // the challenge buffer holds the longest form
    }
    if (registry.challenge_override.len > 0) text = registry.challenge_override;
    served.* = .{ .status = 401, .www_authenticate = text };
}

fn token_endpoint(
    registry: *PushRegistry,
    request: *const net.Request,
    served: *net_sim.Served,
) void {
    registry.token_requests += 1;
    const question = std.mem.indexOfScalar(u8, request.target, '?') orelse request.target.len;
    const scope = fixture_mod.query_value(request.target[question..], "scope");
    const kept = @min(scope.len, registry.token_scope.len);
    @memcpy(registry.token_scope[0..kept], scope[0..kept]);
    registry.token_scope_len = @intCast(kept);
    const right = request.basic.len > 0 and
        std.mem.eql(u8, request.basic, registry.expected_basic());
    if (!right or request.bearer.len > 0) {
        served.* = .{ .status = 401 };
        return;
    }
    var token: [32]u8 = undefined;
    const granted = if (registry.mode == .pull_only) "pull-token" else registry.push_token(&token);
    const body = std.fmt.bufPrint(&registry.token_body, "{{\"token\":\"{s}\"}}", .{granted}) catch
        unreachable;
    const answer_body = if (registry.token_body_override.len > 0)
        registry.token_body_override
    else
        body;
    served.* = .{ .status = 200, .content_type = "application/json", .body = answer_body };
}

fn delegate(
    registry: *PushRegistry,
    request: *const net.Request,
    received: []const u8,
    served: *net_sim.Served,
) void {
    var out: fixture_mod.Answer = .{};
    registry.fixture.answer(.{
        .method = method_of(request.method),
        .target = request.target,
        .content_range = request.content_range,
        .body = received,
    }, &out);
    served.* = .{
        .status = out.status,
        .content_length = out.content_length,
        .www_authenticate = out.www_authenticate,
        .retry_after = out.retry_after,
        .content_type = out.content_type,
        .content_digest = out.content_digest,
        .location = out.location,
        .content_range = out.content_range,
        .range = out.range,
        .body = out.body,
        .deliver = out.deliver,
    };
}
