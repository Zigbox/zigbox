//! The upload half of the OCI distribution protocol: a packed image's layer and config go to a
//! registry as blobs, and then the manifest is put under its tag.
//!
//! For each blob: `HEAD` it, and a blob the registry has is not sent (a repeat push sends no blob
//! bytes). Otherwise, with a repository to mount from, `POST ...?mount=&from=` asks the registry to
//! link it (`201`); a declined mount (`202`) is an upload session, as is a plain `POST`. The bytes
//! go in pieces of `chunk_bytes` (`PATCH`, each answer's `Location` followed, its `Range` checked)
//! and the last piece closes the session (`PUT <location>?digest=`). The manifest is put only
//! when both blobs are confirmed, and the `Docker-Content-Digest` it answers with must be ours;
//! an answer with no such header is confirmed by a `HEAD` of the tag, which must say the same.
//!
//! Nothing here retries or sleeps (a `429` fails at once, as in pull): a refusal is a code on the
//! `Diag`, and running the command again skips what the registry already holds. An upload's
//! `Location` may name another origin (an upload host behind the registry): it is followed, and a
//! request there carries no `Authorization` (`bearer_for`). The bytes are read from the store's
//! blob cache as they are sent.

const std = @import("std");
const assert = std.debug.assert;
const auth = @import("../registry/auth.zig");
const blobs_mod = @import("../registry/blobs.zig");
const client_mod = @import("../registry/client.zig");
const constants = @import("../constants.zig");
const credentials_mod = @import("credentials.zig");
const diagnose = @import("../registry/diagnose.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const net = @import("../registry/net.zig");
const oci = @import("../registry/digest.zig");
const pack = @import("pack.zig");
const push_diagnose = @import("diagnose.zig");
const reference_mod = @import("../registry/reference.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Fs = fs_mod.Fs;
const Origin = client_mod.Origin;
const PathBuf = fs_mod.PathBuf;
const Reference = reference_mod.Reference;
const Sha256 = oci.Sha256;
const Store = layout.Store;

/// The failure is in the `Diag`.
pub const Error = error{Failed};

/// What happened to one blob.
pub const Outcome = enum { exists, mounted, uploaded };

pub const Sent = struct {
    digest: Sha256,
    size: u64,
    outcome: Outcome,
};

/// What a push did: the config, then the layer (the order they are pushed in, and the order of
/// `zbx.push/1`'s `blobs`), then the manifest the registry holds now.
pub const Report = struct {
    config: Sent,
    layer: Sent,
    manifest: Sha256,
    manifest_size: u32,
    /// Blob bytes sent in request bodies; zero when the registry had every blob.
    bytes_sent: u64,

    pub fn blobs(report: *const Report) [constants.push_blobs]Sent {
        return .{ report.config, report.layer };
    }
};

/// Where an image goes: the registry's origin, the repository and the tag.
pub const Destination = struct {
    origin: Origin,
    repository: []const u8,
    tag: []const u8,

    /// `reference` must name a tag; the slices point into it.
    pub fn of(reference: *const Reference) Destination {
        const endpoint = reference.endpoint();
        assert(reference.tag() != null);
        return .{
            .origin = .{ .scheme = endpoint.scheme, .host = endpoint.host, .port = endpoint.port },
            .repository = reference.repository(),
            .tag = reference.tag().?,
        };
    }
};

pub const Options = struct {
    /// A repository on the same registry that may hold the blobs, to ask for a mount; empty for
    /// none.
    mount_from: []const u8 = "",
    /// The size of a piece; tests make it small.
    chunk_bytes: u32 = constants.push_chunk_bytes,
    /// The user and password for a registry that asks; null for none (a registry that asks is then
    /// E0552). The caller owns them and wipes them.
    credentials: ?*const credentials_mod.Credentials = null,
};

/// The memory a push works in, owned by the caller (about 140 KiB). What a credential touches in
/// it (`basic`, `token`, `token_body`, `arena`) is zeroed when the push ends, whatever the way.
pub const Workspace = struct {
    head: net.Head,
    error_body: [constants.push_error_body_bytes]u8,
    error_len: u32,
    manifest: [constants.pack_manifest_bytes_max]u8,
    target: [constants.registry_url_bytes_max]u8,
    location_host: [host_bytes]u8,
    location_target: [constants.registry_url_bytes_max]u8,
    close_target: [constants.registry_url_bytes_max + digest_param_bytes]u8,
    range_text: [range_bytes]u8,
    /// The base64 of `user:password`, for `Authorization: Basic`.
    basic: [constants.push_basic_bytes_max]u8,
    /// The token the realm granted.
    token: [constants.registry_token_bytes_max]u8,
    /// The realm's answer, and the memory its JSON is read in.
    token_body: [constants.registry_token_response_bytes_max]u8,
    token_arena: [constants.push_token_arena_bytes]u8,
};

/// What `client.follow` takes for a host name.
const host_bytes = 256;
/// Two numbers of at most 20 digits and the dash between them ("0-18446744073709551615").
const range_bytes = 48;
/// `?digest=` or `&digest=`, and a digest of 71 bytes.
const digest_param_bytes = 96;
/// "it holds bytes up to N, zbx sent up to N": 36 bytes of words and two numbers.
const detail_bytes = 96;
const number_bytes_max = "18446744073709551615".len;

comptime {
    assert(2 * number_bytes_max + 1 <= range_bytes);
    assert("&digest=".len + "sha256:".len + 64 <= digest_param_bytes);
    assert(36 + 2 * number_bytes_max <= detail_bytes);
    assert(host_bytes == 256);
}

const octet_stream = "application/octet-stream";

const Push = struct {
    ws: *Workspace,
    wire: net.Net,
    store: *const Store,
    destination: Destination,
    options: Options,
    bytes_sent: u64,
    /// The token for the destination's origin, in `ws.token`; empty until one is granted.
    bearer: []const u8,
    /// The Basic credential for the destination's origin, in `ws.basic`; empty until one is used.
    basic: []const u8,
};

/// An upload session: where it is, which may be another origin than the registry's.
const Session = struct {
    origin: Origin,
    target: []const u8,
};

/// The credential a request to `origin` carries: the destination's, to the destination's origin
/// only. A `Location` on another origin is followed with none, so a token never leaves for a host
/// the registry named.
fn bearer_for(state: *const Push, origin: Origin) []const u8 {
    assert(origin.host.len > 0);
    if (!origin.same(state.destination.origin)) return "";
    return state.bearer;
}

/// The Basic credential a request to `origin` carries: the registry's own origin only, and then
/// only over TLS or to loopback (a registry on plain HTTP elsewhere is never named by a
/// reference). Never to an upload `Location` on another origin.
fn basic_for(state: *const Push, origin: Origin) []const u8 {
    assert(origin.host.len > 0);
    if (!origin.same(state.destination.origin)) return "";
    if (origin.scheme == .http) assert(reference_mod.is_loopback(origin.host));
    return state.basic;
}

/// The number of requests a blob of `size` bytes takes in pieces of `chunk` bytes.
pub fn pieces_of(size: u64, chunk: u64) u64 {
    assert(chunk > 0);
    return (size + chunk - 1) / chunk;
}

/// A blob that would take more pieces than `push_chunks_max` is refused before any request.
fn check_pieces(state: *const Push, digest: Sha256, size: u64, diag: *Diag) Error!void {
    const pieces = pieces_of(size, state.options.chunk_bytes);
    if (pieces <= constants.push_chunks_max) return;
    push_diagnose.too_many_pieces(diag, state.destination.origin.host, digest, .{
        .pieces = pieces,
        .chunk = state.options.chunk_bytes,
    });
    return error.Failed;
}

/// Pushes the packed image `made` to `destination`; the failure is in `diag`.
pub fn push(
    store: *const Store,
    ws: *Workspace,
    wire: net.Net,
    destination: Destination,
    made: *const pack.Packed,
    options: Options,
    report: *Report,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(options.chunk_bytes > 0);
    assert(options.chunk_bytes <= constants.push_chunk_bytes);
    var state: Push = .{
        .ws = ws,
        .wire = wire,
        .store = store,
        .destination = destination,
        .options = options,
        .bytes_sent = 0,
        .bearer = "",
        .basic = "",
    };
    defer wipe_secrets(ws);
    try check_pieces(&state, made.config, made.config_size, diag);
    try check_pieces(&state, made.layer, made.layer_size, diag);
    // The config, then the layer: the order of the report.
    const config: Sent = .{
        .digest = made.config,
        .size = made.config_size,
        .outcome = try push_blob(&state, made.config, made.config_size, diag),
    };
    const layer: Sent = .{
        .digest = made.layer,
        .size = made.layer_size,
        .outcome = try push_blob(&state, made.layer, made.layer_size, diag),
    };
    // Both blobs are confirmed: the manifest names nothing the registry lacks.
    try push_manifest(&state, made, diag);
    report.* = .{
        .layer = layer,
        .config = config,
        .manifest = made.manifest,
        .manifest_size = made.manifest_size,
        .bytes_sent = state.bytes_sent,
    };
    if (report.layer.outcome == .mounted) assert(options.mount_from.len > 0);
    assert(report.manifest_size > 0);
}

// ---- Requests ------------------------------------------------------------------------------

fn read_nothing(context: *anyopaque, buffer: []u8) net.Read {
    assert(@intFromPtr(context) != 0);
    assert(buffer.len > 0);
    return 0;
}

var nothing: u8 = 0;

/// The body of a request that carries none (opening an upload): zero bytes.
const empty_body: net.Body = .{
    .length = 0,
    .source = .{ .context = &nothing, .read = read_nothing },
};

/// The bytes of a request body, from the blob cache or from memory.
const Piece = struct {
    fs: ?Fs,
    fd: fs_mod.Fd,
    memory: []const u8,
    at: u64,
    end: u64,

    fn read(context: *anyopaque, buffer: []u8) net.Read {
        const piece: *Piece = @ptrCast(@alignCast(context));
        assert(piece.at <= piece.end);
        const want: usize = @intCast(@min(buffer.len, piece.end - piece.at));
        if (want == 0) return 0;
        if (piece.fs) |fs| {
            const room = @min(want, constants.store_io_buffer_bytes);
            const count = fs.read_at(piece.fd, piece.at, buffer[0..room]) catch {
                return error.SourceFailed;
            };
            if (count == 0) return error.SourceFailed; // The file is shorter than its size.
            piece.at += count;
            return count;
        }
        @memcpy(buffer[0..want], piece.memory[@intCast(piece.at)..][0..want]);
        piece.at += want;
        return want;
    }

    fn body(piece: *Piece) net.Body {
        return .{
            .length = piece.end - piece.at,
            .source = .{ .context = piece, .read = read },
        };
    }
};

/// One request.
const Call = struct {
    method: net.Method,
    /// The registry's origin, or the one an upload's `Location` named.
    origin: Origin,
    target: []const u8,
    /// The bytes of the body; rewound to where they started when the call is made again after
    /// authenticating.
    piece: ?*Piece = null,
    content_type: []const u8 = "",
    content_range: []const u8 = "",
    accept: []const u8 = "",
};

/// The call to the registry's own origin.
fn registry_call(state: *const Push, method: net.Method, target: []const u8) Call {
    return .{ .method = method, .origin = state.destination.origin, .target = target };
}

/// Makes `call`; a `401` from the registry's own origin is answered by authenticating and making
/// it once more, with the body from its start. The answer is in `ws.head` and `ws.error_body`.
fn exchange(state: *Push, call: Call, diag: *Diag) Error!void {
    assert(call.target.len > 0);
    const start: u64 = if (call.piece) |piece| piece.at else 0;
    try exchange_once(state, call, diag);
    const status = state.ws.head.status;
    if (status == 403 and state.bearer.len + state.basic.len > 0) {
        if (std.mem.eql(u8, registry_code(state.ws), "DENIED")) {
            return refuse_credentials(state, diag, .no_push_scope);
        }
    }
    if (status != 401) return;
    if (!call.origin.same(state.destination.origin)) return;
    const next = try authenticate(state, diag);
    if (next == .give_up) return refuse_credentials(state, diag, .refused);
    if (call.piece) |piece| piece.at = start;
    try exchange_once(state, call, diag);
    // Credentials went with the repeat, so a 401 or a 403 is the answer to them.
    const again = state.ws.head.status;
    if (again == 401 or again == 403) return refuse_credentials(state, diag, .refused);
}

/// One request, as `exchange` makes it. A refusal (status 400 or more) whose body is over the
/// bound is still an answer: its status is kept and its body dropped.
fn exchange_once(state: *Push, call: Call, diag: *Diag) Error!void {
    assert(call.target.len > 0);
    assert(call.target[0] == '/');
    const origin = call.origin;
    const ws = state.ws;
    ws.head.reset();
    ws.error_len = 0;
    var sink: net.BufferSink = .{ .buffer = &ws.error_body };
    const request: net.Request = .{
        .scheme = origin.scheme,
        .host = origin.host,
        .port = origin.port,
        .target = call.target,
        .accept = call.accept,
        .bearer = bearer_for(state, origin),
        .basic = basic_for(state, origin),
        .body_bytes_max = constants.push_error_body_bytes,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = call.method,
        .body = body_of(call),
        .content_type = call.content_type,
        .content_range = call.content_range,
    };
    state.wire.call(&request, &ws.head, sink.sink()) catch |err| {
        if (err == error.TooLarge and ws.head.status >= 400) return;
        const where: diagnose.Target = .{
            .host = origin.host,
            .port = origin.port,
            .scheme = origin.scheme,
        };
        diagnose.network_failed(diag, err, where, state.wire.last_errno());
        return error.Failed;
    };
    ws.error_len = sink.len;
    assert(ws.head.status >= 200);
}

fn body_of(call: Call) ?net.Body {
    assert(call.target.len > 0);
    if (call.piece) |piece| return piece.body();
    return if (call.method.has_body()) empty_body else null;
}

/// The registry's own code for what it refused ("BLOB_UPLOAD_INVALID"), from the first error of
/// the body's `errors` list; empty when there is none.
fn registry_code(ws: *const Workspace) []const u8 {
    assert(ws.error_len <= ws.error_body.len);
    const body = ws.error_body[0..ws.error_len];
    const key = "\"code\"";
    const found = std.mem.indexOf(u8, body, key) orelse return "";
    var at = found + key.len;
    while (at < body.len and (body[at] == ' ' or body[at] == ':' or body[at] == '"')) at += 1;
    const start = at;
    while (at < body.len and at - start < 40) : (at += 1) {
        if (!std.ascii.isUpper(body[at]) and body[at] != '_') break;
    }
    assert(at >= start);
    return body[start..at];
}

fn refuse_blob(
    state: *const Push,
    diag: *Diag,
    digest: Sha256,
    step: []const u8,
    detail: []const u8,
) Error {
    assert(state.ws.head.status >= 200);
    assert(step.len > 0);
    push_diagnose.blob_refused(diag, state.destination.origin.host, digest, .{
        .step = step,
        .status = state.ws.head.status,
        .code = registry_code(state.ws),
        .detail = detail,
        .retry_after = state.ws.head.retry_after.slice() orelse "",
    });
    return error.Failed;
}

fn blob_target(state: *Push, comptime middle: []const u8, tail: []const u8) []const u8 {
    assert(state.destination.repository.len > 0);
    const destination = state.destination;
    return std.fmt.bufPrint(&state.ws.target, "/v2/{s}" ++ middle ++ "{s}", .{
        destination.repository,
        tail,
    }) catch unreachable; // The repository and a digest fit a target (constants.zig).
}

// ---- Authentication ------------------------------------------------------------------------

const Next = enum { retry, give_up };

/// Answers a `401` from the registry: with the Basic credential when the challenge is Basic, or
/// with a token the realm grants for `pull,push` on the repository. `retry` means the request may
/// be made again; `give_up` that the credentials were already in use and are refused. A failure
/// (no credentials, a realm that may not be sent the password, a token service that refuses) is
/// on `diag`. Nothing is sent to the realm before the realm rule has passed.
fn authenticate(state: *Push, diag: *Diag) Error!Next {
    assert(state.ws.head.status == 401);
    const host = state.destination.origin.host;
    const repository = state.destination.repository;
    const credentials = state.options.credentials orelse {
        push_diagnose.no_credentials(diag, host, repository);
        return error.Failed;
    };
    if (!credentials.present()) {
        push_diagnose.no_credentials(diag, host, repository);
        return error.Failed;
    }
    const header = state.ws.head.www_authenticate.slice() orelse "";
    const challenge = auth.parse_challenge(header) catch |err| {
        if (err == error.NoBearer and auth.offers_basic(header)) {
            return use_basic(state, credentials);
        }
        push_diagnose.credentials_refused(diag, host, repository, .no_challenge);
        return error.Failed;
    };
    var url_storage: [constants.registry_url_bytes_max * 2]u8 = undefined;
    const from = state.options.mount_from;
    const text = auth.push_token_url(&challenge, repository, from, &url_storage) catch {
        push_diagnose.realm_refused(diag, host, challenge.realm, .not_a_url);
        return error.Failed;
    };
    const url = net.parse_url(text) catch {
        push_diagnose.realm_refused(diag, host, challenge.realm, .not_a_url);
        return error.Failed;
    };
    if (!credentials_mod.realm_allowed(host, state.destination.origin.scheme, url)) {
        const plain = url.scheme == .http;
        const why: push_diagnose.RealmProblem = if (plain) .plain_http else .other_host;
        push_diagnose.realm_refused(diag, host, url.host, why);
        return error.Failed;
    }
    // The realm rule has passed: the password may go there, and only there.
    try fetch_token(state, credentials, url, diag);
    return .retry;
}

fn use_basic(state: *Push, credentials: *const credentials_mod.Credentials) Next {
    assert(credentials.present());
    if (state.basic.len > 0) return .give_up; // It was sent, and refused.
    const ws = state.ws;
    // Exclusive: a registry that changes its challenge from Bearer to Basic gets the Basic
    // credential alone, and the token it was granted is wiped.
    drop_bearer(state);
    state.basic = credentials_mod.encode_basic(credentials, &ws.basic);
    assert(state.basic.len > 0);
    assert(state.bearer.len == 0);
    return .retry;
}

/// Asks the realm for a token with `Authorization: Basic`, in one request that follows no
/// redirect, and keeps the token in `ws.token` for the registry's origin.
fn fetch_token(
    state: *Push,
    credentials: *const credentials_mod.Credentials,
    url: net.Url,
    diag: *Diag,
) Error!void {
    assert(url.target[0] == '/');
    const ws = state.ws;
    const host = state.destination.origin.host;
    const repository = state.destination.repository;
    defer std.crypto.secureZero(u8, &ws.token_body);
    defer std.crypto.secureZero(u8, &ws.token_arena);
    const basic = credentials_mod.encode_basic(credentials, &ws.basic);
    var head: net.Head = .{};
    var sink: net.BufferSink = .{ .buffer = &ws.token_body };
    const request: net.Request = .{
        .scheme = url.scheme,
        .host = url.host,
        .port = url.port,
        .target = url.target,
        .accept = "application/json",
        .bearer = "",
        .basic = basic,
        .body_bytes_max = constants.registry_token_response_bytes_max,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
    };
    state.wire.call(&request, &head, sink.sink()) catch |err| {
        const where: diagnose.Target = .{
            .host = url.host,
            .port = url.port,
            .scheme = url.scheme,
        };
        if (err == error.TooLarge) {
            push_diagnose.credentials_refused(diag, host, repository, .token_unusable);
        } else {
            diagnose.network_failed(diag, err, where, state.wire.last_errno());
        }
        return error.Failed;
    };
    switch (head.status) {
        200 => {},
        401, 403 => {
            push_diagnose.credentials_refused(diag, host, repository, .refused);
            return error.Failed;
        },
        else => {
            push_diagnose.credentials_refused(diag, host, repository, .token_unusable);
            return error.Failed;
        },
    }
    var arena = std.heap.FixedBufferAllocator.init(&ws.token_arena);
    const found = auth.parse_token(sink.bytes(), arena.allocator(), &ws.token) orelse {
        push_diagnose.credentials_refused(diag, host, repository, .token_unusable);
        return error.Failed;
    };
    // Exclusive: the token replaces the Basic credential, which is wiped, so no request ever
    // carries both (the real host asserts it).
    drop_basic(state);
    state.bearer = found;
    assert(state.bearer.len > 0);
    assert(state.basic.len == 0);
}

fn drop_basic(state: *Push) void {
    std.crypto.secureZero(u8, &state.ws.basic);
    state.basic = "";
    assert(state.basic.len == 0);
    assert(state.ws.basic[0] == 0);
}

fn drop_bearer(state: *Push) void {
    std.crypto.secureZero(u8, &state.ws.token);
    state.bearer = "";
    assert(state.bearer.len == 0);
    assert(state.ws.token[0] == 0);
}

/// The registry's `401` (or `403 DENIED`) to credentials that were in use. A token that says
/// `insufficient_scope` is one the realm granted without `push`.
fn refuse_credentials(
    state: *const Push,
    diag: *Diag,
    kind: push_diagnose.CredentialsRefusal,
) Error {
    assert(state.ws.head.status >= 401);
    var refusal = kind;
    if (kind == .refused and state.bearer.len > 0 and says_insufficient_scope(&state.ws.head)) {
        refusal = .no_push_scope;
    }
    const host = state.destination.origin.host;
    push_diagnose.credentials_refused(diag, host, state.destination.repository, refusal);
    return error.Failed;
}

fn says_insufficient_scope(head: *const net.Head) bool {
    const header = head.www_authenticate.slice() orelse return false;
    const challenge = auth.parse_challenge(header) catch return false;
    const code = challenge.error_code orelse return false;
    return std.mem.eql(u8, code, "insufficient_scope");
}

/// Zeroes everything of a credential that is in the workspace: the Basic text, the token, the
/// realm's answer and the memory it was read in. Whatever way a push ends.
fn wipe_secrets(ws: *Workspace) void {
    std.crypto.secureZero(u8, &ws.basic);
    std.crypto.secureZero(u8, &ws.token);
    std.crypto.secureZero(u8, &ws.token_body);
    std.crypto.secureZero(u8, &ws.token_arena);
    assert(ws.basic[0] == 0);
    assert(ws.token[0] == 0);
}

// ---- Blobs ---------------------------------------------------------------------------------

/// Makes sure the registry holds blob `digest`; sends it unless it does.
fn push_blob(state: *Push, digest: Sha256, size: u64, diag: *Diag) Error!Outcome {
    assert(size > 0);
    assert(state.destination.tag.len > 0);
    const name = digest.text();
    const target = blob_target(state, "/blobs/", &name);
    try exchange(state, registry_call(state, .head, target), diag);
    switch (state.ws.head.status) {
        200 => return .exists,
        404 => {},
        else => return refuse_blob(state, diag, digest, "checking for the blob", ""),
    }
    var session: Session = undefined;
    if (state.options.mount_from.len > 0) {
        session = (try mount(state, digest, diag)) orelse return .mounted;
    } else {
        session = try open_session(state, digest, diag);
    }
    try send_blob(state, digest, size, session, diag);
    return .uploaded;
}

/// Asks for a mount. Null when the registry linked the blob (`201`); the session when it declined
/// (`202`) and opened an upload session instead.
fn mount(state: *Push, digest: Sha256, diag: *Diag) Error!?Session {
    const name = digest.text();
    const from = state.options.mount_from;
    const format = "/v2/{s}/blobs/uploads/?mount={s}&from={s}";
    const target = std.fmt.bufPrint(&state.ws.target, format, .{
        state.destination.repository,
        &name,
        from,
    }) catch unreachable; // Two repositories and a digest fit a target.
    try exchange(state, registry_call(state, .post, target), diag);
    switch (state.ws.head.status) {
        201 => return null,
        202 => return try session_location(state, digest, "opening the upload", diag),
        else => return refuse_blob(state, diag, digest, "asking for a mount", ""),
    }
}

fn open_session(state: *Push, digest: Sha256, diag: *Diag) Error!Session {
    const target = blob_target(state, "/blobs/uploads/", "");
    try exchange(state, registry_call(state, .post, target), diag);
    if (state.ws.head.status != 202) {
        return refuse_blob(state, diag, digest, "opening the upload", "");
    }
    return session_location(state, digest, "opening the upload", diag);
}

/// The session an answer's `Location` names, copied into `location_host` and `location_target`.
/// It may be on another origin (the brief: each `Location` is followed, relative or absolute).
fn session_location(
    state: *Push,
    digest: Sha256,
    step: []const u8,
    diag: *Diag,
) Error!Session {
    const ws = state.ws;
    const location = ws.head.location.slice() orelse {
        return refuse_blob(state, diag, digest, step, "the answer has no usable Location");
    };
    const next = client_mod.follow(
        state.destination.origin,
        location,
        &ws.location_host,
        &ws.location_target,
    ) orelse return refuse_blob(state, diag, digest, step, "the Location is not one zbx follows");
    assert(next.target.len > 0);
    return .{ .origin = next.origin, .target = next.target };
}

/// Sends the bytes of the blob: whole pieces by `PATCH`, the last piece with the closing `PUT`.
fn send_blob(
    state: *Push,
    digest: Sha256,
    size: u64,
    first_session: Session,
    diag: *Diag,
) Error!void {
    const chunk: u64 = state.options.chunk_bytes;
    assert(pieces_of(size, chunk) <= constants.push_chunks_max); // `check_pieces` refused more.
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = state.store.fs, .root = state.store.root_text() };
    const fs = state.store.fs;
    const fd = fs.open_read(blobs.final_path(&path, digest)) catch {
        return push_diagnose.blob_unreadable(diag, digest);
    };
    defer fs.close(fd);
    var piece: Piece = .{ .fs = fs, .fd = fd, .memory = "", .at = 0, .end = size };
    var session = first_session;
    var at: u64 = 0;
    while (size - at > chunk) {
        piece.at = at;
        piece.end = at + chunk;
        session = try send_piece(state, digest, session, &piece, diag);
        at += chunk;
    }
    piece.at = at;
    piece.end = size;
    try close_session(state, digest, session, &piece, diag);
    state.bytes_sent += size;
}

/// `PATCH`es one piece and returns where the next goes.
fn send_piece(
    state: *Push,
    digest: Sha256,
    session: Session,
    piece: *Piece,
    diag: *Diag,
) Error!Session {
    const first = piece.at;
    const last = piece.end - 1;
    const range = std.fmt.bufPrint(&state.ws.range_text, "{d}-{d}", .{ first, last }) catch {
        unreachable; // Two numbers of at most 20 digits.
    };
    try exchange(state, .{
        .method = .patch,
        .origin = session.origin,
        .target = session.target,
        .piece = piece,
        .content_type = octet_stream,
        .content_range = range,
    }, diag);
    if (state.ws.head.status != 202) {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "");
    }
    if (state.ws.head.range.slice()) |held| try check_range(state, digest, held, last, diag);
    return session_location(state, digest, "sending a piece of the blob", diag);
}

/// The registry says which bytes it holds ("0-N", or "bytes=0-N"); one that does not start at 0,
/// or says fewer than were sent, has lost some, and the upload stops there. One that says nothing
/// is trusted: the closing `PUT` checks the whole blob against its digest.
fn check_range(
    state: *Push,
    digest: Sha256,
    held: []const u8,
    last: u64,
    diag: *Diag,
) Error!void {
    assert(held.len <= constants.registry_header_bytes_max);
    var text = held;
    if (std.mem.startsWith(u8, text, "bytes=")) text = text["bytes=".len..];
    const dash = std.mem.indexOfScalar(u8, text, '-') orelse {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "the Range is odd");
    };
    if (!std.mem.eql(u8, text[0..dash], "0")) {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "the Range is odd");
    }
    const end = std.fmt.parseInt(u64, text[dash + 1 ..], 10) catch {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "the Range is odd");
    };
    if (end == last) return;
    var detail: [detail_bytes]u8 = undefined;
    const said = std.fmt.bufPrint(&detail, "it holds bytes up to {d}, zbx sent up to {d}", .{
        end,
        last,
    }) catch unreachable; // Short text and two numbers.
    return refuse_blob(state, diag, digest, "sending a piece of the blob", said);
}

/// The last piece, and the digest that makes the registry check the whole blob.
fn close_session(
    state: *Push,
    digest: Sha256,
    session: Session,
    piece: *Piece,
    diag: *Diag,
) Error!void {
    assert(piece.end > piece.at);
    const name = digest.text();
    const joiner: u8 = if (std.mem.indexOfScalar(u8, session.target, '?') != null) '&' else '?';
    const target = std.fmt.bufPrint(&state.ws.close_target, "{s}{c}digest={s}", .{
        session.target,
        joiner,
        &name,
    }) catch unreachable; // The session fits `registry_url_bytes_max`; the digest the rest.
    var range_storage: [range_bytes]u8 = undefined;
    var range: []const u8 = "";
    if (piece.at > 0) {
        range = std.fmt.bufPrint(&range_storage, "{d}-{d}", .{ piece.at, piece.end - 1 }) catch {
            unreachable; // Two numbers of at most 20 digits.
        };
    }
    try exchange(state, .{
        .method = .put,
        .origin = session.origin,
        .target = target,
        .piece = piece,
        .content_type = octet_stream,
        .content_range = range,
    }, diag);
    if (state.ws.head.status != 201) {
        return refuse_blob(state, diag, digest, "closing the upload", "");
    }
}

// ---- The manifest --------------------------------------------------------------------------

fn push_manifest(state: *Push, made: *const pack.Packed, diag: *Diag) Error!void {
    assert(made.manifest_size > 0);
    assert(made.manifest_size <= constants.pack_manifest_bytes_max);
    const ws = state.ws;
    var path: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = state.store.fs, .root = state.store.root_text() };
    const from = blobs.final_path(&path, made.manifest);
    const bytes = state.store.fs.read_whole(from, &ws.manifest) catch {
        return push_diagnose.blob_unreadable(diag, made.manifest);
    };
    if (!Sha256.of(bytes).eql(made.manifest)) {
        return push_diagnose.blob_unreadable(diag, made.manifest);
    }
    var piece: Piece = .{
        .fs = null,
        .fd = undefined,
        .memory = bytes,
        .at = 0,
        .end = bytes.len,
    };
    const target = blob_target(state, "/manifests/", state.destination.tag);
    var call = registry_call(state, .put, target);
    call.piece = &piece;
    call.content_type = constants.oci_manifest_media_type;
    try exchange(state, call, diag);
    const status = ws.head.status;
    if (status != 201 and status != 200) return refuse_manifest(state, diag, "");
    const text = made.manifest.text();
    const said = ws.head.content_digest.slice() orelse {
        return confirm_manifest(state, target, &text, diag);
    };
    if (std.mem.eql(u8, said, &text)) return;
    return refuse_manifest(state, diag, "the registry stored it under another digest");
}

/// The registry took the manifest and named no digest for it (the header is optional on this
/// answer): a `HEAD` of the tag says which digest it holds now, which must be ours. A registry
/// that cannot say is refused, since the digest `zbx push` prints would be a guess.
fn confirm_manifest(state: *Push, target: []const u8, ours: []const u8, diag: *Diag) Error!void {
    var call = registry_call(state, .head, target);
    call.accept = constants.oci_manifest_media_type;
    try exchange(state, call, diag);
    if (state.ws.head.status != 200) {
        return refuse_manifest(state, diag, "it did not say which digest it stored the manifest" ++
            " under, and has no manifest under the tag");
    }
    const said = state.ws.head.content_digest.slice() orelse {
        return refuse_manifest(state, diag, "it did not say which digest it stored the manifest" ++
            " under");
    };
    if (std.mem.eql(u8, said, ours)) return;
    return refuse_manifest(state, diag, "the registry stored it under another digest");
}

fn refuse_manifest(state: *const Push, diag: *Diag, detail: []const u8) Error {
    assert(state.ws.head.status >= 200);
    push_diagnose.manifest_refused(diag, state.destination.origin.host, state.destination.tag, .{
        .step = "putting the manifest",
        .status = state.ws.head.status,
        .code = registry_code(state.ws),
        .detail = detail,
        .retry_after = state.ws.head.retry_after.slice() orelse "",
    });
    return error.Failed;
}
