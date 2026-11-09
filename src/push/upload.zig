//! The upload half of the OCI distribution protocol: a packed image's layer and config go to a
//! registry as blobs, and then the manifest is put under its tag.
//!
//! For each blob: `HEAD` it, and a blob the registry has is not sent (a repeat push sends no blob
//! bytes). Otherwise, with a repository to mount from, `POST ...?mount=&from=` asks the registry to
//! link it (`201`); a declined mount (`202`) is an upload session, as is a plain `POST`. The bytes
//! go in pieces of `chunk_bytes` (`PATCH`, each answer's `Location` followed, its `Range` checked)
//! and the last piece closes the session (`PUT <location>?digest=`). The manifest is put only
//! when both blobs are confirmed, and the `Docker-Content-Digest` it answers with must be ours.
//!
//! Nothing here retries or sleeps: a refusal is a code on the `Diag`, and running the command
//! again skips what the registry already holds. A `Location` is followed only to the registry's
//! own origin. The bytes are read from the store's blob cache as they are sent.

const std = @import("std");
const assert = std.debug.assert;
const blobs_mod = @import("../registry/blobs.zig");
const client_mod = @import("../registry/client.zig");
const constants = @import("../constants.zig");
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

/// What a push did: the layer, then the config, then the manifest the registry holds now.
pub const Report = struct {
    layer: Sent,
    config: Sent,
    manifest: Sha256,
    manifest_size: u32,
    /// Blob bytes sent in request bodies; zero when the registry had every blob.
    bytes_sent: u64,

    pub fn blobs(report: *const Report) [constants.push_blobs]Sent {
        return .{ report.layer, report.config };
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
};

/// The memory a push works in, owned by the caller (about 12 KiB).
pub const Workspace = struct {
    head: net.Head,
    error_body: [constants.push_error_body_bytes]u8,
    error_len: u32,
    manifest: [constants.pack_manifest_bytes_max]u8,
    target: [constants.registry_url_bytes_max]u8,
    location_host: [256]u8,
    location_target: [constants.registry_url_bytes_max]u8,
    close_target: [constants.registry_url_bytes_max + 96]u8,
    range_text: [48]u8,
};

const octet_stream = "application/octet-stream";

const Push = struct {
    ws: *Workspace,
    wire: net.Net,
    store: *const Store,
    destination: Destination,
    options: Options,
    bytes_sent: u64,
};

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
    };
    const layer: Sent = .{
        .digest = made.layer,
        .size = made.layer_size,
        .outcome = try push_blob(&state, made.layer, made.layer_size, diag),
    };
    const config: Sent = .{
        .digest = made.config,
        .size = made.config_size,
        .outcome = try push_blob(&state, made.config, made.config_size, diag),
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

/// One request to the registry's origin (or the location's, which is the same origin). The
/// answer is in `ws.head` and `ws.error_body`; a network failure is on `diag`.
fn exchange(
    state: *Push,
    method: net.Method,
    target: []const u8,
    body: ?net.Body,
    content_type: []const u8,
    content_range: []const u8,
    diag: *Diag,
) Error!void {
    assert(target.len > 0);
    assert(target[0] == '/');
    const origin = state.destination.origin;
    const ws = state.ws;
    ws.head.reset();
    var sink: net.BufferSink = .{ .buffer = &ws.error_body };
    const request: net.Request = .{
        .scheme = origin.scheme,
        .host = origin.host,
        .port = origin.port,
        .target = target,
        .accept = "",
        .bearer = "",
        .body_bytes_max = constants.push_error_body_bytes,
        .idle_timeout_ms = constants.net_idle_timeout_ms,
        .total_timeout_ms = constants.net_request_timeout_ms,
        .method = method,
        .body = if (method.has_body() and body == null) empty_body else body,
        .content_type = content_type,
        .content_range = content_range,
    };
    state.wire.call(&request, &ws.head, sink.sink()) catch |err| {
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

// ---- Blobs ---------------------------------------------------------------------------------

/// Makes sure the registry holds blob `digest`; sends it unless it does.
fn push_blob(state: *Push, digest: Sha256, size: u64, diag: *Diag) Error!Outcome {
    assert(size > 0);
    assert(state.destination.tag.len > 0);
    const name = digest.text();
    const target = blob_target(state, "/blobs/", &name);
    try exchange(state, .head, target, null, "", "", diag);
    switch (state.ws.head.status) {
        200 => return .exists,
        404 => {},
        else => return refuse_blob(state, diag, digest, "checking for the blob", ""),
    }
    var session: []const u8 = undefined;
    if (state.options.mount_from.len > 0) {
        session = (try mount(state, digest, diag)) orelse return .mounted;
    } else {
        session = try open_session(state, digest, diag);
    }
    try send_blob(state, digest, size, session, diag);
    return .uploaded;
}

/// Asks for a mount. Null when the registry linked the blob (`201`); the session's target when
/// it declined (`202`) and opened an upload session instead.
fn mount(state: *Push, digest: Sha256, diag: *Diag) Error!?[]const u8 {
    const name = digest.text();
    const from = state.options.mount_from;
    const format = "/v2/{s}/blobs/uploads/?mount={s}&from={s}";
    const target = std.fmt.bufPrint(&state.ws.target, format, .{
        state.destination.repository,
        &name,
        from,
    }) catch unreachable; // Two repositories and a digest fit a target.
    try exchange(state, .post, target, null, "", "", diag);
    switch (state.ws.head.status) {
        201 => return null,
        202 => return try session_location(state, digest, "opening the upload", diag),
        else => return refuse_blob(state, diag, digest, "asking for a mount", ""),
    }
}

fn open_session(state: *Push, digest: Sha256, diag: *Diag) Error![]const u8 {
    const target = blob_target(state, "/blobs/uploads/", "");
    try exchange(state, .post, target, null, "", "", diag);
    if (state.ws.head.status != 202) {
        return refuse_blob(state, diag, digest, "opening the upload", "");
    }
    return session_location(state, digest, "opening the upload", diag);
}

/// The session's target, copied from the answer's `Location` into `location_target`. Only the
/// registry's own origin is followed.
fn session_location(
    state: *Push,
    digest: Sha256,
    step: []const u8,
    diag: *Diag,
) Error![]const u8 {
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
    if (!next.origin.same(state.destination.origin)) {
        return refuse_blob(state, diag, digest, step, "the Location names another host");
    }
    assert(next.target.len > 0);
    return next.target;
}

/// Sends the bytes of the blob: whole pieces by `PATCH`, the last piece with the closing `PUT`.
fn send_blob(
    state: *Push,
    digest: Sha256,
    size: u64,
    first_session: []const u8,
    diag: *Diag,
) Error!void {
    const chunk: u64 = state.options.chunk_bytes;
    assert(size / chunk < constants.push_chunks_max);
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
    session: []const u8,
    piece: *Piece,
    diag: *Diag,
) Error![]const u8 {
    const first = piece.at;
    const last = piece.end - 1;
    const range = std.fmt.bufPrint(&state.ws.range_text, "{d}-{d}", .{ first, last }) catch {
        unreachable; // Two numbers of at most 20 digits.
    };
    try exchange(state, .patch, session, piece.body(), octet_stream, range, diag);
    if (state.ws.head.status != 202) {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "");
    }
    if (state.ws.head.range.slice()) |held| try check_range(state, digest, held, last, diag);
    state.bytes_sent += piece.end - piece.at;
    return session_location(state, digest, "sending a piece of the blob", diag);
}

/// The registry says which bytes it holds ("0-N", or "bytes=0-N"); a registry that says fewer
/// than were sent has lost some, and the upload stops there. One that says nothing is trusted:
/// the closing `PUT` checks the whole blob against its digest.
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
    const end = std.fmt.parseInt(u64, text[dash + 1 ..], 10) catch {
        return refuse_blob(state, diag, digest, "sending a piece of the blob", "the Range is odd");
    };
    if (end == last) return;
    var detail: [96]u8 = undefined;
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
    session: []const u8,
    piece: *Piece,
    diag: *Diag,
) Error!void {
    assert(piece.end > piece.at);
    const name = digest.text();
    const joiner: u8 = if (std.mem.indexOfScalar(u8, session, '?') != null) '&' else '?';
    const target = std.fmt.bufPrint(&state.ws.close_target, "{s}{c}digest={s}", .{
        session,
        joiner,
        &name,
    }) catch unreachable; // The session fits `registry_url_bytes_max`; the rest is 80 bytes.
    var range_storage: [48]u8 = undefined;
    var range: []const u8 = "";
    if (piece.at > 0) {
        range = std.fmt.bufPrint(&range_storage, "{d}-{d}", .{ piece.at, piece.end - 1 }) catch {
            unreachable; // Two numbers of at most 20 digits.
        };
    }
    try exchange(state, .put, target, piece.body(), octet_stream, range, diag);
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
    try exchange(state, .put, target, piece.body(), constants.oci_manifest_media_type, "", diag);
    const status = ws.head.status;
    if (status != 201 and status != 200) return refuse_manifest(state, diag, "");
    const said = ws.head.content_digest.slice() orelse return;
    const text = made.manifest.text();
    if (std.mem.eql(u8, said, &text)) return;
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
