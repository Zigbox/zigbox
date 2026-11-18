//! demo-s2's registry, on the runner (docs/briefs/S2-lazy-start.md, "The demo"): the push
//! registry fixture made disk-backed, for a 3 GiB image the guest pushes and pulls. Blobs live in
//! `<root>/blobs/<hex>`, uploads in `<root>/uploads/<id>`, manifests in memory. It serves pulls
//! with a closed `Range` (206), one global bandwidth limit for every byte of a response body, a
//! counter of the bytes it served by kind, and two faults: one byte flipped in transit at a set
//! blob offset (step 6) and "down", which drops every connection, including transfers in flight
//! (step 7). Uploads are not throttled: the limit models a registry's egress.
//!
//! A fixed pool of worker threads accepts on one listener (127.0.0.1, which the guest reaches as
//! 10.0.2.2), each serving one connection at a time. The guest drives the faults and reads the
//! counter through `/control/<verb>`, which "down" does not drop and the counter does not count:
//! the script can then cut the registry at the moment the step needs, inside one guest command.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const Sha256 = std.crypto.hash.sha2.Sha256;
const http = @import("http_s2.zig");

/// Connections served at once: zbx's on-demand and fill fetches (8 + 2) and the forwarder's
/// slack. More wait in the listen backlog.
pub const workers_max = 16;
pub const uploads_max = 16;
pub const manifests_max = 16;
pub const manifest_bytes_max = 64 * 1024;
pub const index_ranges_max = 4;
/// What the throttle releases at a time, and the size of a read from a blob file.
pub const piece_bytes = 64 * 1024;
/// The largest upload request body: zbx sends 8 MiB pieces.
pub const upload_request_bytes_max: u64 = 64 * 1024 * 1024;
const upload_buffer_bytes = 256 * 1024;
const repo_bytes_max = 64;
const tag_bytes_max = 128;
const media_bytes_max = 96;
const listen_backlog = 64;
const accept_poll_ms = 50;

comptime {
    assert(piece_bytes % 8 == 0);
    assert(upload_buffer_bytes >= piece_bytes);
    assert(manifest_bytes_max <= upload_buffer_bytes);
}

/// What the response bodies carried, by kind. `chunks` is every `Range` request but a
/// registered index range: what zbx's summary line counts.
pub const Snapshot = struct {
    total: u64,
    chunks: u64,
    index: u64,
    whole: u64,
    manifests: u64,
    requests: u64,

    pub fn format_line(snapshot: Snapshot, buffer: []u8) []const u8 {
        assert(snapshot.total == snapshot.chunks + snapshot.index + snapshot.whole +
            snapshot.manifests);
        assert(buffer.len >= 160);
        return std.fmt.bufPrint(buffer, "served {d} chunks {d} index {d} whole {d} " ++
            "manifests {d} requests {d}\n", .{
            snapshot.total, snapshot.chunks,    snapshot.index,
            snapshot.whole, snapshot.manifests, snapshot.requests,
        }) catch unreachable; // Six u64s fit 160 bytes.
    }
};

const Class = enum(u8) { chunks, index, whole, manifests };

const Upload = struct {
    active: bool = false,
    id: u32 = 0,
    length: u64 = 0,
    hash: Sha256 = undefined,
    fd: i32 = -1,
};

const Manifest = struct {
    used: bool = false,
    repo: [repo_bytes_max]u8 = undefined,
    repo_len: u8 = 0,
    tag: [tag_bytes_max]u8 = undefined,
    tag_len: u8 = 0,
    digest: [71]u8 = undefined,
    media: [media_bytes_max]u8 = undefined,
    media_len: u8 = 0,
    bytes: [manifest_bytes_max]u8 = undefined,
    len: u32 = 0,
};

const IndexRange = struct { blob: [64]u8, first: u64, last: u64 };

pub const Registry = struct {
    root: i32 = -1,
    listener: i32 = -1,
    port: u16 = 0,
    bytes_per_second: u64,
    stopping: std.atomic.Value(bool) = .init(false),
    down: std.atomic.Value(bool) = .init(false),
    flipping: std.atomic.Value(bool) = .init(false),
    /// Set while no worker runs (`set_flip`), read by workers.
    flip_blob: [64]u8 = @splat(0),
    flip_offset: u64 = 0,
    counts: [4]std.atomic.Value(u64) = @splat(.init(0)),
    requests: std.atomic.Value(u64) = .init(0),
    /// Guards the throttle, the uploads, the manifests and the index ranges.
    lock: std.atomic.Mutex = .unlocked,
    throttle_next_ns: u64 = 0,
    uploads: [uploads_max]Upload = @splat(.{}),
    upload_next: u32 = 1,
    manifests: [manifests_max]Manifest = @splat(.{}),
    index_ranges: [index_ranges_max]IndexRange = undefined,
    index_count: u32 = 0,
    threads: [workers_max]?std.Thread = @splat(null),

    /// Makes `<root>/blobs` and `<root>/uploads` and listens on 127.0.0.1 with an ephemeral
    /// port; serving starts at `start`. `registry` must not move afterwards.
    pub fn init(registry: *Registry, root: [:0]const u8, bytes_per_second: u64) !void {
        assert(bytes_per_second > 0);
        registry.* = .{ .bytes_per_second = bytes_per_second };
        try make_directory(linux.AT.FDCWD, root);
        const directory: linux.O = .{ .DIRECTORY = true, .CLOEXEC = true };
        const opened = linux.openat(linux.AT.FDCWD, root, directory, 0);
        if (linux.errno(opened) != .SUCCESS) return error.RegistryRootFailed;
        registry.root = @intCast(opened);
        try make_directory(registry.root, "blobs");
        try make_directory(registry.root, "uploads");
        registry.listener = try listen(&registry.port);
        assert(registry.port != 0);
    }

    pub fn start(registry: *Registry) !void {
        assert(registry.listener >= 0);
        for (&registry.threads) |*thread| {
            thread.* = try std.Thread.spawn(.{}, work, .{registry});
        }
    }

    /// Stops the workers (a transfer in flight ends at its next piece) and closes everything.
    pub fn deinit(registry: *Registry) void {
        registry.stopping.store(true, .release);
        for (&registry.threads) |*thread| {
            if (thread.*) |running| running.join();
            thread.* = null;
        }
        for (&registry.uploads) |*upload| {
            if (upload.active) _ = linux.close(upload.fd);
        }
        if (registry.listener >= 0) _ = linux.close(registry.listener);
        if (registry.root >= 0) _ = linux.close(registry.root);
        registry.listener = -1;
        registry.root = -1;
    }

    pub fn snapshot(registry: *Registry) Snapshot {
        const chunks = registry.counts[@backingInt(Class.chunks)].load(.acquire);
        const index = registry.counts[@backingInt(Class.index)].load(.acquire);
        const whole = registry.counts[@backingInt(Class.whole)].load(.acquire);
        const manifests = registry.counts[@backingInt(Class.manifests)].load(.acquire);
        return .{
            .total = chunks + index + whole + manifests,
            .chunks = chunks,
            .index = index,
            .whole = whole,
            .manifests = manifests,
            .requests = registry.requests.load(.acquire),
        };
    }

    pub fn reset(registry: *Registry) void {
        for (&registry.counts) |*count| count.store(0, .release);
        registry.requests.store(0, .release);
        assert(registry.snapshot().total == 0);
    }

    pub fn set_down(registry: *Registry, down: bool) void {
        registry.down.store(down, .release);
        assert(registry.down.load(.acquire) == down);
    }

    /// Arms the flip: the byte at `offset` of blob `blob` goes out XORed with 0xff while
    /// `flipping` is set (`/control/flip-on`).
    pub fn set_flip(registry: *Registry, blob: *const [64]u8, offset: u64) void {
        assert(!registry.flipping.load(.acquire));
        assert(valid_hex(blob));
        registry.acquire();
        defer registry.release();
        registry.flip_blob = blob.*;
        registry.flip_offset = offset;
    }

    /// Counts a `Range` request for exactly `first`..`last` of `blob` as the index's.
    pub fn add_index_range(registry: *Registry, blob: *const [64]u8, first: u64, last: u64) void {
        assert(first <= last);
        assert(valid_hex(blob));
        registry.acquire();
        defer registry.release();
        assert(registry.index_count < index_ranges_max);
        const range: IndexRange = .{ .blob = blob.*, .first = first, .last = last };
        registry.index_ranges[registry.index_count] = range;
        registry.index_count += 1;
    }

    /// The manifest `repo:tag` names, copied into `out`; null when there is none.
    pub fn manifest_of(registry: *Registry, repo: []const u8, tag: []const u8, out: []u8) ?[]u8 {
        assert(out.len >= manifest_bytes_max);
        registry.acquire();
        defer registry.release();
        const found = registry.find_manifest(repo, tag) orelse return null;
        @memcpy(out[0..found.len], found.bytes[0..found.len]);
        return out[0..found.len];
    }

    /// Reads `out.len` bytes of blob `blob` from `offset`.
    pub fn read_blob(registry: *Registry, blob: *const [64]u8, offset: u64, out: []u8) !void {
        assert(valid_hex(blob));
        const fd = try registry.open_blob(blob);
        defer _ = linux.close(fd);
        try pread_all(fd, out, offset);
    }

    fn acquire(registry: *Registry) void {
        while (!registry.lock.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(registry: *Registry) void {
        registry.lock.unlock();
    }

    fn work(registry: *Registry) void {
        while (!registry.stopping.load(.acquire)) {
            var entries = [1]linux.pollfd{
                .{ .fd = registry.listener, .events = linux.POLL.IN, .revents = 0 },
            };
            const ready = linux.poll(&entries, 1, accept_poll_ms);
            if (linux.errno(ready) != .SUCCESS or ready == 0) continue;
            const accepted = linux.accept4(registry.listener, null, null, linux.SOCK.CLOEXEC);
            if (linux.errno(accepted) != .SUCCESS) continue; // Another worker took it.
            const socket: i32 = @intCast(accepted);
            registry.handle(socket);
            _ = linux.close(socket);
        }
    }

    fn handle(registry: *Registry, socket: i32) void {
        var head: [http.head_bytes_max]u8 = undefined;
        var filled: usize = 0;
        const head_len = http.read_head(socket, &head, &filled, &registry.stopping) orelse return;
        const request = http.parse(head[0..filled], head_len) orelse return;
        if (std.mem.startsWith(u8, request.path, "/control/")) {
            return registry.control(socket, request);
        }
        // Down: the connection ends with no answer, as a dropped network looks to a client.
        if (registry.down.load(.acquire)) return;
        _ = registry.requests.fetchAdd(1, .acq_rel);
        if (std.mem.eql(u8, request.path, "/v2/") or std.mem.eql(u8, request.path, "/v2")) {
            return answer_text(socket, 200, "{}");
        }
        const route = parse_route(request.path) orelse return answer_text(socket, 404, not_found);
        switch (route.kind) {
            .blob => registry.serve_blob(socket, request, route),
            .uploads => registry.upload_open(socket, request, route),
            .upload => registry.upload_piece(socket, request, route),
            .manifest => switch (request.method) {
                .put => registry.manifest_put(socket, request, route),
                else => registry.manifest_get(socket, request, route),
            },
        }
    }

    fn control(registry: *Registry, socket: i32, request: http.Request) void {
        const verb = request.path["/control/".len..];
        assert(request.path.len >= "/control/".len);
        if (std.mem.eql(u8, verb, "down")) registry.set_down(true);
        if (std.mem.eql(u8, verb, "up")) registry.set_down(false);
        if (std.mem.eql(u8, verb, "flip-on")) registry.flipping.store(true, .release);
        if (std.mem.eql(u8, verb, "flip-off")) registry.flipping.store(false, .release);
        if (std.mem.eql(u8, verb, "reset")) registry.reset();
        var buffer: [256]u8 = undefined;
        answer_text(socket, 200, registry.snapshot().format_line(&buffer));
    }

    fn serve_blob(registry: *Registry, socket: i32, request: http.Request, route: Route) void {
        const hex = digest_hex(route.rest) orelse return answer_text(socket, 404, not_found);
        if (request.method != .get and request.method != .head) {
            return answer_text(socket, 404, not_found);
        }
        const fd = registry.open_blob(hex) catch return answer_text(socket, 404, not_found);
        defer _ = linux.close(fd);
        const size = linux.lseek(fd, 0, linux.SEEK.END);
        if (@as(i64, @bitCast(size)) < 0) return answer_text(socket, 404, not_found);
        var first: u64 = 0;
        var last: u64 = size -| 1;
        var range_text: [96]u8 = undefined;
        var head: http.Head = .{ .status = 200, .length = size, .digest = route.rest };
        head.content_type = "application/octet-stream";
        if (request.header("Range")) |text| {
            const range = http.parse_range(text, size) orelse return answer_text(socket, 416, "");
            first = range.first;
            last = range.last;
            head.status = 206;
            head.length = last - first + 1;
            head.content_range = std.fmt.bufPrint(&range_text, "bytes {d}-{d}/{d}", .{
                first, last, size,
            }) catch unreachable; // Three u64s fit.
        }
        var rendered: [http.response_head_bytes_max]u8 = undefined;
        if (!http.write_all(socket, http.render_head(head, &rendered))) return;
        if (request.method == .head or size == 0) return;
        const class: Class = if (head.status == 200)
            .whole
        else if (registry.is_index(hex, first, last)) .index else .chunks;
        registry.send_file(socket, fd, hex, first, last - first + 1, class);
    }

    fn send_file(
        registry: *Registry,
        socket: i32,
        fd: i32,
        hex: *const [64]u8,
        first: u64,
        count: u64,
        class: Class,
    ) void {
        assert(count > 0);
        var buffer: [piece_bytes]u8 = undefined;
        var at = first;
        while (at < first + count) {
            const length: usize = @intCast(@min(first + count - at, piece_bytes));
            const piece = buffer[0..length];
            pread_all(fd, piece, at) catch return;
            if (registry.flipping.load(.acquire) and std.mem.eql(u8, hex, &registry.flip_blob)) {
                const flip = registry.flip_offset;
                if (flip >= at and flip < at + length) piece[@intCast(flip - at)] ^= 0xff;
            }
            if (!registry.send_piece(socket, piece, class)) return;
            at += length;
        }
        assert(at == first + count);
    }

    /// Waits for the throttle, sends `piece` and counts it; false when the transfer ends: the
    /// client went away, the registry went down or is stopping.
    fn send_piece(registry: *Registry, socket: i32, piece: []const u8, class: Class) bool {
        assert(piece.len <= piece_bytes);
        if (registry.down.load(.acquire) or registry.stopping.load(.acquire)) return false;
        registry.throttle(piece.len);
        if (registry.down.load(.acquire)) return false;
        if (!http.write_all(socket, piece)) return false;
        _ = registry.counts[@backingInt(class)].fetchAdd(piece.len, .acq_rel);
        return true;
    }

    /// One global schedule for every response body: each piece takes its time slot after the
    /// last one's, and goes out at the slot's end, so no burst ever exceeds the rate.
    fn throttle(registry: *Registry, bytes: usize) void {
        assert(bytes > 0);
        const now = now_ns();
        const duration = @as(u64, bytes) * std.time.ns_per_s / registry.bytes_per_second;
        registry.acquire();
        const slot_start = @max(now, registry.throttle_next_ns);
        registry.throttle_next_ns = slot_start + duration;
        const due = registry.throttle_next_ns;
        registry.release();
        if (duration > 0) assert(due > now);
        sleep_ns(due -| now);
    }

    fn is_index(registry: *Registry, hex: *const [64]u8, first: u64, last: u64) bool {
        registry.acquire();
        defer registry.release();
        for (registry.index_ranges[0..registry.index_count]) |range| {
            if (std.mem.eql(u8, &range.blob, hex) and range.first == first and range.last == last) {
                return true;
            }
        }
        return false;
    }

    fn open_blob(registry: *Registry, hex: *const [64]u8) !i32 {
        assert(valid_hex(hex));
        var path: [80:0]u8 = undefined;
        // The buffer is sized for the longest name.
        const name = std.mem.printSentinel(&path, "blobs/{s}", .{hex}, 0) catch unreachable;
        const opened = linux.openat(registry.root, name, .{ .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) return error.BlobUnknown;
        return @intCast(opened);
    }

    /// `POST <repo>/blobs/uploads/`: a mount of a blob the registry holds, or a new upload.
    fn upload_open(registry: *Registry, socket: i32, request: http.Request, route: Route) void {
        if (request.method != .post) return answer_text(socket, 404, not_found);
        const mount = http.query_value(request.query, "mount");
        if (digest_hex(mount)) |hex| {
            if (registry.open_blob(hex)) |fd| {
                _ = linux.close(fd);
                return answer_blob_created(socket, route.repo, mount);
            } else |_| {}
        }
        const upload = registry.upload_new() orelse return answer_text(socket, 413, "");
        answer_upload(socket, route.repo, upload.id, 0);
    }

    fn upload_new(registry: *Registry) ?*Upload {
        registry.acquire();
        defer registry.release();
        for (&registry.uploads) |*upload| {
            if (upload.active) continue;
            const id = registry.upload_next;
            var path: [32:0]u8 = undefined;
            // The buffer is sized for the longest name.
            const name = std.mem.printSentinel(&path, "uploads/{d}", .{id}, 0) catch unreachable;
            const flags: linux.O = .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
                .CLOEXEC = true,
            };
            const opened = linux.openat(registry.root, name, flags, 0o644);
            if (linux.errno(opened) != .SUCCESS) return null;
            registry.upload_next += 1;
            upload.* = .{ .active = true, .id = id, .hash = .init(.{}), .fd = @intCast(opened) };
            assert(upload.length == 0);
            return upload;
        }
        return null;
    }

    fn find_upload(registry: *Registry, text: []const u8) ?*Upload {
        const id = std.fmt.parseInt(u32, text, 10) catch return null;
        registry.acquire();
        defer registry.release();
        for (&registry.uploads) |*upload| {
            if (upload.active and upload.id == id) return upload;
        }
        return null;
    }

    /// `PATCH` appends a piece; `PUT ?digest=` appends the last one and closes the upload.
    fn upload_piece(registry: *Registry, socket: i32, request: http.Request, route: Route) void {
        const upload = registry.find_upload(route.rest) orelse {
            return answer_text(socket, 404, not_found);
        };
        if (request.method != .patch and request.method != .put) {
            return answer_text(socket, 404, not_found);
        }
        if (request.header("Content-Range")) |spanned| {
            const dash = std.mem.indexOfScalar(u8, spanned, '-') orelse spanned.len;
            const first = std.fmt.parseInt(u64, spanned[0..dash], 10) catch upload.length + 1;
            if (first != upload.length) return answer_text(socket, 416, "");
        }
        const length = request.content_length() orelse return answer_text(socket, 411, "");
        if (length > upload_request_bytes_max) return answer_text(socket, 413, "");
        if (!registry.receive(socket, request, upload, length)) {
            registry.upload_end(upload, null);
            return;
        }
        if (request.method == .patch) {
            return answer_upload(socket, route.repo, upload.id, upload.length);
        }
        const wanted = http.query_value(request.query, "digest");
        const hex = digest_hex(wanted) orelse {
            registry.upload_end(upload, null);
            return answer_text(socket, 400, "{\"errors\":[{\"code\":\"DIGEST_INVALID\"}]}");
        };
        const computed = std.fmt.bytesToHex(upload.hash.finalResult(), .lower);
        if (!std.mem.eql(u8, &computed, hex)) {
            registry.upload_end(upload, null);
            return answer_text(socket, 400, "{\"errors\":[{\"code\":\"DIGEST_INVALID\"}]}");
        }
        registry.upload_end(upload, hex);
        answer_blob_created(socket, route.repo, wanted);
    }

    /// Reads `length` body bytes into the upload's file and hash.
    fn receive(
        registry: *Registry,
        socket: i32,
        request: http.Request,
        upload: *Upload,
        length: u64,
    ) bool {
        assert(upload.active);
        const early = request.early[0..@intCast(@min(length, request.early.len))];
        if (!append(upload, early)) return false;
        var buffer: [upload_buffer_bytes]u8 = undefined;
        var left = length - early.len;
        while (left > 0) {
            const room = buffer[0..@intCast(@min(left, buffer.len))];
            const got = http.read_some(socket, room, &registry.stopping) orelse return false;
            if (!append(upload, room[0..got])) return false;
            left -= got;
        }
        assert(left == 0);
        return true;
    }

    /// Ends an upload: its file becomes blob `hex`, or is removed.
    fn upload_end(registry: *Registry, upload: *Upload, hex: ?*const [64]u8) void {
        assert(upload.active);
        var path: [32:0]u8 = undefined;
        // The buffer is sized for the longest name.
        const name = std.mem.printSentinel(&path, "uploads/{d}", .{upload.id}, 0) catch unreachable;
        _ = linux.close(upload.fd);
        if (hex) |digest| {
            var target_path: [80:0]u8 = undefined;
            // The buffer is sized for the longest name.
            const target = std.mem.printSentinel(&target_path, "blobs/{s}", .{digest}, 0) catch
                unreachable; // The buffer is sized for the longest name.
            _ = linux.renameat(registry.root, name, registry.root, target);
        } else {
            _ = linux.unlinkat(registry.root, name, 0);
        }
        registry.acquire();
        defer registry.release();
        upload.* = .{};
    }

    fn manifest_put(registry: *Registry, socket: i32, request: http.Request, route: Route) void {
        const length = request.content_length() orelse return answer_text(socket, 411, "");
        if (length == 0 or length > manifest_bytes_max) return answer_text(socket, 413, "");
        if (route.repo.len > repo_bytes_max or route.rest.len > tag_bytes_max) {
            return answer_text(socket, 400, "");
        }
        var body: [manifest_bytes_max]u8 = undefined;
        const bytes = body[0..@intCast(length)];
        const early = @min(bytes.len, request.early.len);
        @memcpy(bytes[0..early], request.early[0..early]);
        var at: usize = early;
        while (at < bytes.len) {
            at += http.read_some(socket, bytes[at..], &registry.stopping) orelse return;
        }
        const media = request.header("Content-Type") orelse "";
        if (media.len > media_bytes_max) return answer_text(socket, 400, "");
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        var digest: [71]u8 = undefined;
        const hex = std.fmt.bytesToHex(hash, .lower);
        _ = std.fmt.bufPrint(&digest, "sha256:{s}", .{&hex}) catch unreachable; // 71 bytes exactly.
        if (!registry.store_manifest(route.repo, route.rest, media, bytes, &digest)) {
            return answer_text(socket, 413, "");
        }
        var location: [256]u8 = undefined;
        // A route's repository is at most 64 bytes, so the location fits.
        const where = std.fmt.bufPrint(&location, "/v2/{s}/manifests/{s}", .{
            route.repo, &digest,
        }) catch unreachable; // A short repository and a digest fit.
        var rendered: [http.response_head_bytes_max]u8 = undefined;
        const head: http.Head = .{ .status = 201, .digest = &digest, .location = where };
        _ = http.write_all(socket, http.render_head(head, &rendered));
    }

    fn store_manifest(
        registry: *Registry,
        repo: []const u8,
        tag: []const u8,
        media: []const u8,
        bytes: []const u8,
        digest: *const [71]u8,
    ) bool {
        assert(bytes.len <= manifest_bytes_max);
        registry.acquire();
        defer registry.release();
        const slot = registry.find_manifest(repo, tag) orelse for (&registry.manifests) |*free| {
            if (!free.used) break free;
        } else return false;
        slot.used = true;
        @memcpy(slot.repo[0..repo.len], repo);
        slot.repo_len = @intCast(repo.len);
        @memcpy(slot.tag[0..tag.len], tag);
        slot.tag_len = @intCast(tag.len);
        slot.digest = digest.*;
        @memcpy(slot.media[0..media.len], media);
        slot.media_len = @intCast(media.len);
        @memcpy(slot.bytes[0..bytes.len], bytes);
        slot.len = @intCast(bytes.len);
        return true;
    }

    /// The manifest stored as `repo:reference`, a tag or a digest. Called under the lock.
    fn find_manifest(registry: *Registry, repo: []const u8, reference: []const u8) ?*Manifest {
        assert(registry.lock == .locked);
        for (&registry.manifests) |*slot| {
            if (!slot.used or !std.mem.eql(u8, slot.repo[0..slot.repo_len], repo)) continue;
            if (std.mem.eql(u8, slot.tag[0..slot.tag_len], reference)) return slot;
            if (std.mem.eql(u8, &slot.digest, reference)) return slot;
        }
        return null;
    }

    fn manifest_get(registry: *Registry, socket: i32, request: http.Request, route: Route) void {
        if (request.method != .get and request.method != .head) {
            return answer_text(socket, 404, not_found);
        }
        var body: [manifest_bytes_max]u8 = undefined;
        var media: [media_bytes_max]u8 = undefined;
        var digest: [71]u8 = undefined;
        var head: http.Head = .{ .status = 200 };
        {
            registry.acquire();
            defer registry.release();
            const found = registry.find_manifest(route.repo, route.rest) orelse {
                head.status = 404;
                return answer_text(socket, 404, not_found);
            };
            @memcpy(body[0..found.len], found.bytes[0..found.len]);
            @memcpy(media[0..found.media_len], found.media[0..found.media_len]);
            digest = found.digest;
            head.length = found.len;
            head.content_type = media[0..found.media_len];
        }
        head.digest = &digest;
        var rendered: [http.response_head_bytes_max]u8 = undefined;
        if (!http.write_all(socket, http.render_head(head, &rendered))) return;
        if (request.method == .head) return;
        _ = registry.send_piece(socket, body[0..@intCast(head.length)], .manifests);
    }
};

const not_found = "{\"errors\":[{\"code\":\"NOT_FOUND\"}]}";

fn answer_text(socket: i32, status: u16, body: []const u8) void {
    assert(body.len < 1024);
    var rendered: [http.response_head_bytes_max]u8 = undefined;
    const head: http.Head = .{ .status = status, .length = body.len };
    if (!http.write_all(socket, http.render_head(head, &rendered))) return;
    _ = http.write_all(socket, body);
}

fn answer_upload(socket: i32, repo: []const u8, id: u32, length: u64) void {
    assert(repo.len <= repo_bytes_max);
    var location: [128]u8 = undefined;
    // Each buffer holds its longest text: a short repository and two u64s.
    const where = std.fmt.bufPrint(&location, "/v2/{s}/blobs/uploads/{d}", .{ repo, id }) catch
        unreachable; // A short repository and a u64 fit.
    var range: [32]u8 = undefined;
    const kept = std.fmt.bufPrint(&range, "0-{d}", .{length -| 1}) catch unreachable; // Fits.
    var uuid: [24]u8 = undefined;
    const name = std.fmt.bufPrint(&uuid, "{d}", .{id}) catch unreachable; // Fits.
    var rendered: [http.response_head_bytes_max]u8 = undefined;
    const head: http.Head = .{
        .status = 202,
        .location = where,
        .range = kept,
        .upload_uuid = name,
    };
    _ = http.write_all(socket, http.render_head(head, &rendered));
}

fn answer_blob_created(socket: i32, repo: []const u8, digest: []const u8) void {
    assert(digest.len == 71);
    var location: [192]u8 = undefined;
    // A short repository and a digest fit.
    const where = std.fmt.bufPrint(&location, "/v2/{s}/blobs/{s}", .{ repo, digest }) catch
        unreachable; // A short repository and a digest fit.
    var rendered: [http.response_head_bytes_max]u8 = undefined;
    const head: http.Head = .{ .status = 201, .digest = digest, .location = where };
    _ = http.write_all(socket, http.render_head(head, &rendered));
}

fn append(upload: *Upload, bytes: []const u8) bool {
    assert(upload.active);
    var at: usize = 0;
    while (at < bytes.len) {
        const rest = bytes[at..];
        const offset: i64 = @intCast(upload.length + at);
        const written = linux.pwrite(upload.fd, rest.ptr, rest.len, offset);
        if (linux.errno(written) != .SUCCESS or written == 0) return false;
        at += written;
    }
    upload.hash.update(bytes);
    upload.length += bytes.len;
    return true;
}

const Route = struct {
    kind: enum { blob, uploads, upload, manifest },
    repo: []const u8,
    rest: []const u8,
};

/// `/v2/<repo>/blobs/<digest>`, `/v2/<repo>/blobs/uploads/[<id>]`, `/v2/<repo>/manifests/<ref>`.
fn parse_route(path: []const u8) ?Route {
    if (!std.mem.startsWith(u8, path, "/v2/")) return null;
    const tail = path["/v2/".len..];
    const markers = [_]struct { []const u8, @FieldType(Route, "kind") }{
        .{ "/blobs/uploads/", .upload },
        .{ "/blobs/", .blob },
        .{ "/manifests/", .manifest },
    };
    for (markers) |marker| {
        const at = std.mem.indexOf(u8, tail, marker[0]) orelse continue;
        const repo = tail[0..at];
        const rest = tail[at + marker[0].len ..];
        if (!valid_repo(repo)) return null;
        var kind = marker[1];
        if (kind == .upload and rest.len == 0) kind = .uploads;
        if (kind != .uploads and rest.len == 0) return null;
        assert(repo.len > 0);
        return .{ .kind = kind, .repo = repo, .rest = rest };
    }
    return null;
}

fn valid_repo(repo: []const u8) bool {
    if (repo.len == 0 or repo.len > repo_bytes_max) return false;
    for (repo) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or
            byte == '/' or byte == '.' or byte == '_' or byte == '-';
        if (!allowed) return false;
    }
    return true;
}

/// The hex of `sha256:<64 lowercase hex>`, or null.
fn digest_hex(text: []const u8) ?*const [64]u8 {
    const prefix = "sha256:";
    if (text.len != prefix.len + 64 or !std.mem.startsWith(u8, text, prefix)) return null;
    const hex = text[prefix.len..][0..64];
    if (!valid_hex(hex)) return null;
    return hex;
}

fn valid_hex(hex: *const [64]u8) bool {
    for (hex) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn make_directory(parent: i32, path: [*:0]const u8) !void {
    const made = linux.mkdirat(parent, path, 0o755);
    switch (linux.errno(made)) {
        .SUCCESS, .EXIST => {},
        else => return error.RegistryRootFailed,
    }
}

fn listen(port: *u16) !i32 {
    // Non-blocking: every worker polls the one listener, and those that lose the race to
    // `accept4` must get EAGAIN, not block past a stop.
    const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const created = linux.socket(linux.AF.INET, flags, 0);
    if (linux.errno(created) != .SUCCESS) return error.SocketFailed;
    const listener: i32 = @intCast(created);
    errdefer _ = linux.close(listener);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 0),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(bound) != .SUCCESS) return error.BindFailed;
    if (linux.errno(linux.listen(listener, listen_backlog)) != .SUCCESS) return error.ListenFailed;
    var length: linux.socklen_t = @sizeOf(@TypeOf(address));
    const named = linux.getsockname(listener, @ptrCast(&address), &length);
    if (linux.errno(named) != .SUCCESS) return error.SocketFailed;
    port.* = std.mem.bigToNative(u16, address.port);
    assert(port.* != 0);
    return listener;
}

fn pread_all(fd: i32, out: []u8, offset: u64) !void {
    assert(fd >= 0);
    var at: usize = 0;
    while (at < out.len) {
        const rest = out[at..];
        const got = linux.pread(fd, rest.ptr, rest.len, @intCast(offset + at));
        if (linux.errno(got) != .SUCCESS or got == 0) return error.ReadFailed;
        at += got;
    }
    assert(at == out.len);
}

pub fn now_ns() u64 {
    var time: linux.timespec = undefined;
    const result = linux.clock_gettime(.MONOTONIC, &time);
    assert(linux.errno(result) == .SUCCESS);
    return @as(u64, @intCast(time.sec)) * std.time.ns_per_s + @as(u64, @intCast(time.nsec));
}

fn sleep_ns(duration: u64) void {
    if (duration == 0) return;
    var request: linux.timespec = .{
        .sec = @intCast(duration / std.time.ns_per_s),
        .nsec = @intCast(duration % std.time.ns_per_s),
    };
    var remaining: linux.timespec = undefined;
    while (linux.errno(linux.nanosleep(&request, &remaining)) == .INTR) request = remaining;
}

test {
    _ = @import("registry_disk_s2_tests.zig");
}
