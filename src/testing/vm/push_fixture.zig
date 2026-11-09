//! The upload half of the test registry: a registry in memory that takes blobs and manifests, a
//! pure function from a request to an answer, as `registry_fixture.zig` is for pulls. The
//! simulator serves it through `src/registry/push_registry.zig` and `registry_server.zig` serves
//! it over TCP.
//!
//! Its faults are named by repository, so a test picks one by the destination it pushes to:
//! `push/<fault>` (a `-suffix` makes another repository of the same behaviour, `push/ok-src` for
//! a mount to come from). A registry here is as strict as a real one in the one way that matters
//! to the order of a push: a manifest naming a blob the repository does not hold is refused
//! (`MANIFEST_BLOB_UNKNOWN`) and counted (`unknown_refusals`).

const std = @import("std");
const assert = std.debug.assert;
const fixture_mod = @import("registry_fixture.zig");

pub const Answer = fixture_mod.Answer;

pub const Method = enum { get, head, post, patch, put };

/// What each repository name does wrong, or nothing.
pub const Fault = enum {
    ok,
    /// Every Location is an absolute URL on the registry's own origin.
    absolute,
    /// A `202` for a piece with no `Range`.
    norange,
    /// A `Range` one byte short of what was sent.
    shortrange,
    /// A piece is refused with `416`.
    refusechunk,
    /// The closing `PUT` finds the digest wrong (`DIGEST_INVALID`).
    badclose,
    /// A mount is declined: `202` and an upload session.
    nomount,
    /// The manifest is refused: `MANIFEST_INVALID`.
    invalidmanifest,
    /// The manifest is taken and the `Docker-Content-Digest` is another digest.
    wrongdigest,
    /// Opening an upload is `429` with `Retry-After`.
    throttle,
    /// Every Location is on another origin.
    farlocation,
};

pub const Query = struct {
    method: Method,
    /// Path and query.
    target: []const u8,
    /// The `Content-Range` header of a piece; empty for none.
    content_range: []const u8 = "",
    /// The request's body, already read.
    body: []const u8 = "",
};

pub const blob_bytes_max = 64 * 1024;
const blobs_max = 8;
const sessions_max = 4;
const manifests_max = 4;
const manifest_bytes_max = 4096;
const repo_bytes_max = 48;
const digest_text_bytes = 71;
const media_json = "application/json";

const Blob = struct {
    used: bool = false,
    repo: [repo_bytes_max]u8 = undefined,
    repo_len: u8 = 0,
    digest: [digest_text_bytes]u8 = undefined,
    len: u32 = 0,
    bytes: [blob_bytes_max]u8 = undefined,

    fn repo_text(blob: *const Blob) []const u8 {
        return blob.repo[0..blob.repo_len];
    }
};

const Session = struct {
    active: bool = false,
    id: u32 = 0,
    repo: [repo_bytes_max]u8 = undefined,
    repo_len: u8 = 0,
    len: u32 = 0,
    bytes: [blob_bytes_max]u8 = undefined,
};

const Manifest = struct {
    used: bool = false,
    repo: [repo_bytes_max]u8 = undefined,
    repo_len: u8 = 0,
    tag: [64]u8 = undefined,
    tag_len: u8 = 0,
    len: u32 = 0,
    bytes: [manifest_bytes_max]u8 = undefined,
    digest: [digest_text_bytes]u8 = undefined,
};

/// The registry's own URL and another origin, for the Locations that name one.
pub const PushFixture = struct {
    base: [96]u8,
    base_len: u8,
    other_base: [96]u8,
    other_base_len: u8,
    blobs: [blobs_max]Blob,
    sessions: [sessions_max]Session,
    manifests: [manifests_max]Manifest,
    next_session: u32,
    location: [256]u8,
    error_text: [128]u8,
    digest_text: [digest_text_bytes]u8,
    range_text: [32]u8,
    /// Body bytes taken in pieces and closings.
    received_bytes: u64,
    /// Manifests taken, refused for a missing blob, mounts done.
    manifest_puts: u32,
    unknown_refusals: u32,
    mounts: u32,

    pub fn init(fixture: *PushFixture, base: []const u8, other_base: []const u8) void {
        assert(base.len > 0);
        assert(base.len <= fixture.base.len);
        assert(other_base.len <= fixture.other_base.len);
        for (&fixture.blobs) |*blob| blob.used = false;
        for (&fixture.sessions) |*session| session.active = false;
        for (&fixture.manifests) |*stored| stored.used = false;
        @memcpy(fixture.base[0..base.len], base);
        fixture.base_len = @intCast(base.len);
        @memcpy(fixture.other_base[0..other_base.len], other_base);
        fixture.other_base_len = @intCast(other_base.len);
        fixture.next_session = 1;
        fixture.received_bytes = 0;
        fixture.manifest_puts = 0;
        fixture.unknown_refusals = 0;
        fixture.mounts = 0;
    }

    /// Whether the repository `repo` holds blob `digest`.
    pub fn has_blob(fixture: *const PushFixture, repo: []const u8, digest: []const u8) bool {
        return fixture.find_blob(repo, digest) != null;
    }

    /// The bytes of blob `digest` in `repo`; null for none.
    pub fn blob_bytes(
        fixture: *const PushFixture,
        repo: []const u8,
        digest: []const u8,
    ) ?[]const u8 {
        const blob = fixture.find_blob(repo, digest) orelse return null;
        return blob.bytes[0..blob.len];
    }

    /// The digest the registry holds for `repo:tag`; null for none.
    pub fn tag_digest(fixture: *const PushFixture, repo: []const u8, tag: []const u8) ?[]const u8 {
        for (&fixture.manifests) |*stored| {
            if (!stored.used) continue;
            if (!std.mem.eql(u8, stored.repo[0..stored.repo_len], repo)) continue;
            if (std.mem.eql(u8, stored.tag[0..stored.tag_len], tag)) return &stored.digest;
        }
        return null;
    }

    fn find_blob(fixture: *const PushFixture, repo: []const u8, digest: []const u8) ?*const Blob {
        for (&fixture.blobs) |*blob| {
            if (!blob.used) continue;
            if (!std.mem.eql(u8, blob.repo_text(), repo)) continue;
            if (std.mem.eql(u8, &blob.digest, digest)) return blob;
        }
        return null;
    }

    fn free_blob(fixture: *PushFixture) ?*Blob {
        for (&fixture.blobs) |*blob| {
            if (!blob.used) return blob;
        }
        return null;
    }

    fn find_session(fixture: *PushFixture, id: u32) ?*Session {
        for (&fixture.sessions) |*session| {
            if (session.active and session.id == id) return session;
        }
        return null;
    }

    /// Answers one request; `out` is filled whole.
    pub fn answer(fixture: *PushFixture, query: Query, out: *Answer) void {
        out.* = .{ .status = 404 };
        const parsed = parse(query.target) orelse return fixture.refuse(out, 404, "NAME_UNKNOWN");
        const rest = parsed.rest;
        if (std.mem.startsWith(u8, rest, "/blobs/uploads/")) {
            return fixture.uploads(query, parsed, rest["/blobs/uploads/".len..], out);
        }
        if (std.mem.startsWith(u8, rest, "/blobs/") and query.method == .head) {
            return fixture.blob_head(parsed, rest["/blobs/".len..], out);
        }
        const manifests = "/manifests/";
        if (std.mem.startsWith(u8, rest, manifests) and query.method == .put) {
            return fixture.manifest_put(query, parsed, rest[manifests.len..], out);
        }
        return fixture.refuse(out, 404, "UNSUPPORTED");
    }

    fn refuse(fixture: *PushFixture, out: *Answer, status: u16, code: []const u8) void {
        assert(code.len > 0);
        assert(status >= 400);
        const text = std.fmt.bufPrint(
            &fixture.error_text,
            "{{\"errors\":[{{\"code\":\"{s}\",\"message\":\"test registry\"}}]}}",
            .{code},
        ) catch unreachable; // The code is short.
        out.* = .{ .status = status, .content_type = media_json, .body = text };
    }

    fn blob_head(fixture: *PushFixture, parsed: Parsed, digest: []const u8, out: *Answer) void {
        const blob = fixture.find_blob(parsed.repo, digest) orelse {
            return fixture.refuse(out, 404, "BLOB_UNKNOWN");
        };
        out.* = .{
            .status = 200,
            .content_length = blob.len,
            .content_digest = &blob.digest,
            .content_type = "application/octet-stream",
        };
    }

    fn uploads(
        fixture: *PushFixture,
        query: Query,
        parsed: Parsed,
        tail: []const u8,
        out: *Answer,
    ) void {
        if (tail.len == 0 or tail[0] == '?') {
            if (query.method != .post) return fixture.refuse(out, 405, "UNSUPPORTED");
            return fixture.open(parsed, tail, out);
        }
        const mark = std.mem.indexOfScalar(u8, tail, '?') orelse tail.len;
        const id = std.fmt.parseInt(u32, tail[0..mark], 10) catch {
            return fixture.refuse(out, 404, "BLOB_UPLOAD_UNKNOWN");
        };
        const session = fixture.find_session(id) orelse {
            return fixture.refuse(out, 404, "BLOB_UPLOAD_UNKNOWN");
        };
        switch (query.method) {
            .patch => fixture.piece(query, parsed, session, out),
            .put => fixture.close(query, parsed, session, tail[mark..], out),
            else => fixture.refuse(out, 405, "UNSUPPORTED"),
        }
    }

    /// `POST uploads/`, with or without `?mount=&from=`.
    fn open(fixture: *PushFixture, parsed: Parsed, query_text: []const u8, out: *Answer) void {
        if (parsed.fault == .throttle) {
            fixture.refuse(out, 429, "TOOMANYREQUESTS");
            out.retry_after = "7";
            return;
        }
        if (query_text.len > 0 and parsed.fault != .nomount) {
            const digest = query_value(query_text, "mount");
            const from = query_value(query_text, "from");
            if (fixture.find_blob(from, digest)) |source| {
                return fixture.mount(parsed, source, out);
            }
        }
        const session = for (&fixture.sessions) |*slot| {
            if (!slot.active) break slot;
        } else return fixture.refuse(out, 429, "TOOMANYREQUESTS");
        session.* = .{ .active = true, .id = fixture.next_session, .len = 0 };
        session.repo_len = @intCast(parsed.repo.len);
        @memcpy(session.repo[0..parsed.repo.len], parsed.repo);
        fixture.next_session += 1;
        const location = fixture.location_of(parsed, session.id);
        out.* = .{ .status = 202, .location = location, .range = "0-0" };
    }

    fn mount(fixture: *PushFixture, parsed: Parsed, source: *const Blob, out: *Answer) void {
        const copy = fixture.free_blob() orelse return fixture.refuse(out, 507, "DENIED");
        copy.used = true;
        copy.repo_len = @intCast(parsed.repo.len);
        @memcpy(copy.repo[0..parsed.repo.len], parsed.repo);
        copy.digest = source.digest;
        copy.len = source.len;
        @memcpy(copy.bytes[0..source.len], source.bytes[0..source.len]);
        fixture.mounts += 1;
        out.* = .{ .status = 201, .content_digest = &copy.digest };
    }

    fn location_of(fixture: *PushFixture, parsed: Parsed, id: u32) []const u8 {
        const base: []const u8 = switch (parsed.fault) {
            .absolute => fixture.base[0..fixture.base_len],
            .farlocation => fixture.other_base[0..fixture.other_base_len],
            else => "",
        };
        return std.fmt.bufPrint(&fixture.location, "{s}/v2/{s}/blobs/uploads/{d}", .{
            base,
            parsed.repo,
            id,
        }) catch unreachable; // The base, the repository and a number fit.
    }

    /// `PATCH`: appends a piece at the session's end; `Content-Range` must start there.
    fn piece(
        fixture: *PushFixture,
        query: Query,
        parsed: Parsed,
        session: *Session,
        out: *Answer,
    ) void {
        if (parsed.fault == .refusechunk) return fixture.refuse(out, 416, "BLOB_UPLOAD_INVALID");
        const spanned = query.content_range;
        const dash = std.mem.indexOfScalar(u8, spanned, '-') orelse spanned.len;
        const first = std.fmt.parseInt(u32, query.content_range[0..dash], 10) catch {
            return fixture.refuse(out, 416, "BLOB_UPLOAD_INVALID");
        };
        if (first != session.len) return fixture.refuse(out, 416, "BLOB_UPLOAD_INVALID");
        if (!append(session, query.body)) return fixture.refuse(out, 413, "SIZE_INVALID");
        fixture.received_bytes += query.body.len;
        const kept = if (parsed.fault == .shortrange) session.len - 2 else session.len - 1;
        var range: []const u8 = "";
        if (parsed.fault != .norange) {
            // The buffer holds "0-" and a number.
            range = std.fmt.bufPrint(&fixture.range_text, "0-{d}", .{kept}) catch unreachable;
        }
        const location = fixture.location_of(parsed, session.id);
        out.* = .{ .status = 202, .location = location, .range = range };
    }

    /// `PUT <session>?digest=`: appends the last bytes and checks the whole against the digest.
    fn close(
        fixture: *PushFixture,
        query: Query,
        parsed: Parsed,
        session: *Session,
        query_text: []const u8,
        out: *Answer,
    ) void {
        if (!append(session, query.body)) return fixture.refuse(out, 413, "SIZE_INVALID");
        fixture.received_bytes += query.body.len;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(session.bytes[0..session.len], &hash, .{});
        var computed: [digest_text_bytes]u8 = undefined;
        _ = std.fmt.bufPrint(&computed, "sha256:{x}", .{&hash}) catch unreachable; // 7 + 64.
        const wanted = query_value(query_text, "digest");
        if (parsed.fault == .badclose or !std.mem.eql(u8, wanted, &computed)) {
            session.active = false;
            return fixture.refuse(out, 400, "DIGEST_INVALID");
        }
        const blob = fixture.free_blob() orelse return fixture.refuse(out, 507, "DENIED");
        blob.used = true;
        blob.repo_len = @intCast(parsed.repo.len);
        @memcpy(blob.repo[0..parsed.repo.len], parsed.repo);
        blob.digest = computed;
        blob.len = session.len;
        @memcpy(blob.bytes[0..session.len], session.bytes[0..session.len]);
        session.active = false;
        out.* = .{ .status = 201, .content_digest = &blob.digest };
    }

    fn manifest_put(
        fixture: *PushFixture,
        query: Query,
        parsed: Parsed,
        tag: []const u8,
        out: *Answer,
    ) void {
        if (parsed.fault == .invalidmanifest) return fixture.refuse(out, 400, "MANIFEST_INVALID");
        if (query.body.len > manifest_bytes_max or tag.len > 64) {
            return fixture.refuse(out, 400, "MANIFEST_INVALID");
        }
        if (!fixture.blobs_known(parsed.repo, query.body)) {
            fixture.unknown_refusals += 1;
            return fixture.refuse(out, 404, "MANIFEST_BLOB_UNKNOWN");
        }
        const stored = fixture.manifest_slot(parsed.repo, tag) orelse {
            return fixture.refuse(out, 507, "DENIED");
        };
        stored.used = true;
        stored.repo_len = @intCast(parsed.repo.len);
        @memcpy(stored.repo[0..parsed.repo.len], parsed.repo);
        stored.tag_len = @intCast(tag.len);
        @memcpy(stored.tag[0..tag.len], tag);
        stored.len = @intCast(query.body.len);
        @memcpy(stored.bytes[0..query.body.len], query.body);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(query.body, &hash, .{});
        _ = std.fmt.bufPrint(&stored.digest, "sha256:{x}", .{&hash}) catch unreachable; // 7 + 64.
        fixture.manifest_puts += 1;
        fixture.digest_text = stored.digest;
        if (parsed.fault == .wrongdigest) @memset(fixture.digest_text["sha256:".len..], '0');
        out.* = .{ .status = 201, .content_digest = &fixture.digest_text };
    }

    fn manifest_slot(fixture: *PushFixture, repo: []const u8, tag: []const u8) ?*Manifest {
        for (&fixture.manifests) |*stored| {
            if (!stored.used) continue;
            if (!std.mem.eql(u8, stored.repo[0..stored.repo_len], repo)) continue;
            if (std.mem.eql(u8, stored.tag[0..stored.tag_len], tag)) return stored;
        }
        for (&fixture.manifests) |*stored| {
            if (!stored.used) return stored;
        }
        return null;
    }

    /// Every `sha256:<hex>` the manifest names is a blob of the repository.
    fn blobs_known(fixture: *const PushFixture, repo: []const u8, body: []const u8) bool {
        var at: usize = 0;
        while (std.mem.indexOfPos(u8, body, at, "sha256:")) |found| {
            const end = found + digest_text_bytes;
            if (end > body.len) return false;
            if (fixture.find_blob(repo, body[found..end]) == null) return false;
            at = end;
        }
        return true;
    }
};

fn append(session: *Session, bytes: []const u8) bool {
    if (bytes.len > blob_bytes_max - session.len) return false;
    @memcpy(session.bytes[session.len..][0..bytes.len], bytes);
    session.len += @intCast(bytes.len);
    return true;
}

/// The value of `name` in a query text ("?mount=x&from=y" or "mount=x&from=y"); empty for none.
fn query_value(text: []const u8, name: []const u8) []const u8 {
    var rest = if (text.len > 0 and text[0] == '?') text[1..] else text;
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, '&') orelse rest.len;
        const pair = rest[0..end];
        if (std.mem.indexOfScalar(u8, pair, '=')) |equals| {
            if (std.mem.eql(u8, pair[0..equals], name)) return pair[equals + 1 ..];
        }
        rest = if (end < rest.len) rest[end + 1 ..] else "";
    }
    return "";
}

const Parsed = struct {
    /// "push/<name>".
    repo: []const u8,
    fault: Fault,
    /// What follows the repository: "/blobs/uploads/", "/manifests/v1".
    rest: []const u8,
};

/// `/v2/push/<name>/...`; null for any other path or a name that is no fault.
fn parse(target: []const u8) ?Parsed {
    const prefix = "/v2/push/";
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    const after = target[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, after, '/') orelse return null;
    const name = after[0..slash];
    const dash = std.mem.indexOfScalar(u8, name, '-') orelse name.len;
    const fault = std.meta.stringToEnum(Fault, name[0..dash]) orelse return null;
    const repo = target["/v2/".len .. prefix.len + slash];
    if (repo.len > repo_bytes_max) return null;
    return .{ .repo = repo, .fault = fault, .rest = after[slash..] };
}

test "an upload through the fixture ends with the blob and the manifest stored" {
    // Goal: the fixture is a registry a push can finish against: a blob goes up by a session and
    // is then there, and a manifest naming it is taken under its tag.
    var fixture: PushFixture = undefined;
    fixture.init("https://registry.test", "https://other.test");
    var out: Answer = .{};
    fixture.answer(.{ .method = .post, .target = "/v2/push/ok/blobs/uploads/" }, &out);
    try std.testing.expectEqual(@as(u16, 202), out.status);
    var location: [128]u8 = undefined;
    const target = std.fmt.bufPrint(&location, "{s}", .{out.location}) catch {
        unreachable; // The buffer outsizes a location.
    };
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello", &hash, .{});
    var closing: [200]u8 = undefined;
    const close = std.fmt.bufPrint(&closing, "{s}?digest=sha256:{x}", .{ target, &hash }) catch {
        unreachable; // The buffer outsizes both.
    };
    fixture.answer(.{ .method = .put, .target = close, .body = "hello" }, &out);
    try std.testing.expectEqual(@as(u16, 201), out.status);
    var digest: [digest_text_bytes]u8 = undefined;
    _ = std.fmt.bufPrint(&digest, "sha256:{x}", .{&hash}) catch unreachable; // 7 + 64.
    try std.testing.expect(fixture.has_blob("push/ok", &digest));
    try std.testing.expect(!fixture.has_blob("push/ok-src", &digest));
    var manifest: [128]u8 = undefined;
    const text = "{{\"digest\":\"{s}\"}}";
    const body = std.fmt.bufPrint(&manifest, text, .{&digest}) catch unreachable; // Fits.
    fixture.answer(.{ .method = .put, .target = "/v2/push/ok/manifests/v1", .body = body }, &out);
    try std.testing.expectEqual(@as(u16, 201), out.status);
    try std.testing.expectEqual(@as(u32, 1), fixture.manifest_puts);
    try std.testing.expect(fixture.tag_digest("push/ok", "v1") != null);
    const zeros = "{\"digest\":\"sha256:" ++
        "0000000000000000000000000000000000000000000000000000000000000000" ++ "\"}";
    fixture.answer(.{ .method = .put, .target = "/v2/push/ok/manifests/v2", .body = zeros }, &out);
    try std.testing.expectEqual(@as(u16, 404), out.status);
    try std.testing.expectEqual(@as(u32, 1), fixture.unknown_refusals);
}

test "query_value and parse read what the fixture is addressed by" {
    // Goal: the two little parsers, with the shapes a push sends.
    try std.testing.expectEqualStrings("b", query_value("?a=1&mount=b&from=c", "mount"));
    try std.testing.expectEqualStrings("c", query_value("a=1&mount=b&from=c", "from"));
    try std.testing.expectEqualStrings("", query_value("?a=1", "digest"));
    const parsed = parse("/v2/push/norange-x/blobs/uploads/").?;
    try std.testing.expectEqualStrings("push/norange-x", parsed.repo);
    try std.testing.expectEqual(Fault.norange, parsed.fault);
    try std.testing.expectEqualStrings("/blobs/uploads/", parsed.rest);
    try std.testing.expect(parse("/v2/push/nosuch/blobs/") == null);
    try std.testing.expect(parse("/v2/other/ok/blobs/") == null);
}
