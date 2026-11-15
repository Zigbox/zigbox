//! A pinned fetch: the download of a copy entry's `.fetch` into the store's blob cache, in the
//! parent, before any step runs (M9 slice 3b).
//!
//! The bytes stream to `blobs/partial/<hex>` and are hashed as they arrive. When the SHA-256 is
//! the pinned one the file is flushed and renamed to `blobs/sha256/<hex>`, where the registry's
//! blobs live; when it is not, the partial file is removed. So `blobs/sha256/` never holds a
//! file whose bytes are not its name, and a blob that is there is never downloaded again.
//!
//! The rules (docs/briefs/M9-dockerfile-import.md, *Pinned fetches*): only `https://`, plain
//! `http://` only for a loopback host; a redirect may not go from https to http, nor from a host
//! that is not loopback to one that is; every hop counts against `build_fetch_redirects_max`;
//! a body over `build_fetch_bytes_max` is refused. The download is never resumed: a partial
//! file left by a crash is started again.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const net = @import("../registry/net.zig");
const client = @import("../registry/client.zig");
const reference = @import("../registry/reference.zig");
const digest_mod = @import("../registry/digest.zig");
const blobs_mod = @import("../registry/blobs.zig");
const fs_mod = @import("../store/fs.zig");

const Blobs = blobs_mod.Blobs;
const PathBuf = fs_mod.PathBuf;
const Sha256 = digest_mod.Sha256;

/// Why a redirect was not followed.
pub const Refusal = enum {
    /// To plain `http://` on a host that is not loopback (or from https at all).
    http,
    /// From a host that is not loopback to one that is.
    loopback,
    /// No Location, one too long to keep, or one that is not a URL this client follows.
    malformed,
};

/// Why a fetch failed. `mismatch` is E0821; every other one is E0820.
pub const Reason = union(enum) {
    /// The server's answer: not 200 and not a redirect.
    status: u16,
    network: net.Error,
    /// The body is longer than `build_fetch_bytes_max`.
    too_large,
    /// More than `build_fetch_redirects_max` redirects.
    redirects,
    refused: Refusal,
    io: blobs_mod.Failure,
    /// The SHA-256 of the bytes that came.
    mismatch: Sha256,
};

pub const Outcome = enum { cached, downloaded };

pub const Fetcher = struct {
    blobs: Blobs,
    net: net.Net,
    /// Set when `fetch` fails.
    reason: Reason,
    head: net.Head,
    hasher: digest_mod.Hasher,
    fd: ?fs_mod.Fd,
    written: u64,
    sink_failed: bool,
    host_storage: [256]u8,
    target_storage: [constants.registry_url_bytes_max]u8,

    pub fn init(fetcher: *Fetcher, blobs: Blobs, network: net.Net) void {
        assert(blobs.root[0] == '/');
        assert(blobs.root.len > 1);
        fetcher.blobs = blobs;
        fetcher.net = network;
        fetcher.fd = null;
        fetcher.written = 0;
        fetcher.sink_failed = false;
        fetcher.reason = .redirects;
    }

    /// True if `blobs/sha256/<hex>` is there: no request is made for it.
    pub fn has(fetcher: *const Fetcher, expected: Sha256) bool {
        assert(fetcher.fd == null);
        assert(fetcher.blobs.root.len > 1);
        var path: PathBuf = undefined;
        const text = fetcher.blobs.final_path(&path, expected);
        const found = fetcher.blobs.fs.lstat(text) catch return false;
        return found.kind == .file;
    }

    /// Puts the bytes of `url` in the blob cache as `expected`, or sets `reason` and fails.
    /// `url` passed the load-time check (`file.is_fetch_url`).
    pub fn fetch(fetcher: *Fetcher, url: []const u8, expected: Sha256) error{Failed}!Outcome {
        assert(url.len <= constants.registry_url_bytes_max);
        assert(fetcher.fd == null);
        if (fetcher.has(expected)) return .cached;
        var failure: blobs_mod.Failure = undefined;
        fetcher.blobs.ensure_directories(&failure) catch return fetcher.fail(.{ .io = failure });
        var partial: PathBuf = undefined;
        const partial_text = fetcher.blobs.partial_path(&partial, expected);
        fetcher.start(partial_text) catch return error.Failed;
        fetcher.download(url) catch {
            fetcher.drop(partial_text);
            return error.Failed;
        };
        try fetcher.finish(partial_text, expected);
        assert(fetcher.fd == null);
        return .downloaded;
    }

    fn fail(fetcher: *Fetcher, reason: Reason) error{Failed} {
        assert(fetcher.fd == null);
        fetcher.reason = reason;
        return error.Failed;
    }

    fn io_failure(fetcher: *Fetcher, step: []const u8, err: fs_mod.Error) blobs_mod.Failure {
        assert(step.len > 0);
        assert(@errorName(err).len > 0);
        return .{ .step = step, .err = err, .errno = fetcher.blobs.fs.last_errno() };
    }

    /// A fresh partial file: what an earlier, cut fetch left is removed first.
    fn start(fetcher: *Fetcher, partial_text: [:0]const u8) error{Failed}!void {
        assert(fetcher.fd == null);
        assert(partial_text.len > 0);
        const fs = fetcher.blobs.fs;
        fs.unlink(partial_text) catch |err| switch (err) {
            error.NotFound => {},
            else => {
                return fetcher.fail(.{ .io = fetcher.io_failure("removing a partial fetch", err) });
            },
        };
        fetcher.fd = fs.create(partial_text, 0o644) catch |err| {
            return fetcher.fail(.{ .io = fetcher.io_failure("creating the partial fetch", err) });
        };
        fetcher.hasher = digest_mod.Hasher.init();
        fetcher.written = 0;
        fetcher.sink_failed = false;
    }

    /// Closes and removes the partial file of a fetch that failed (best effort: a partial file
    /// left behind is removed by the next fetch, and is never in `sha256/`).
    fn drop(fetcher: *Fetcher, partial_text: [:0]const u8) void {
        assert(partial_text.len > 0);
        assert(fetcher.blobs.root.len > 1);
        if (fetcher.fd) |fd| fetcher.blobs.fs.close(fd);
        fetcher.fd = null;
        fetcher.blobs.fs.unlink(partial_text) catch {};
    }

    /// Asks `url`, following redirects, until a 200's body is in the partial file.
    fn download(fetcher: *Fetcher, url: []const u8) error{Failed}!void {
        assert(fetcher.fd != null);
        assert(fetcher.written == 0);
        const parsed = net.parse_url(url) catch unreachable; // Checked at load (`is_fetch_url`).
        var origin: client.Origin = .{
            .scheme = parsed.scheme,
            .host = parsed.host,
            .port = parsed.port,
        };
        var target = parsed.target;
        if (origin.scheme == .http and !reference.is_loopback(origin.host)) {
            return fetcher.refuse(.http);
        }
        var hops: u32 = 0;
        while (true) {
            try fetcher.ask(origin, target);
            const status = fetcher.head.status;
            if (status == 200) return;
            if (status < 100 or status > 599 or !client.is_redirect(status)) {
                return fetcher.refuse_status(status);
            }
            if (hops == constants.build_fetch_redirects_max) {
                return fetcher.refuse_reason(.redirects);
            }
            hops += 1;
            const next = try fetcher.next_hop(origin);
            origin = next.origin;
            target = next.target;
        }
    }

    fn refuse(fetcher: *Fetcher, refusal: Refusal) error{Failed} {
        assert(fetcher.fd != null);
        assert(@backingInt(refusal) <= @backingInt(Refusal.malformed));
        fetcher.reason = .{ .refused = refusal };
        return error.Failed;
    }

    fn refuse_status(fetcher: *Fetcher, status: u16) error{Failed} {
        assert(fetcher.fd != null);
        assert(status != 200);
        fetcher.reason = .{ .status = status };
        return error.Failed;
    }

    fn refuse_reason(fetcher: *Fetcher, reason: Reason) error{Failed} {
        assert(fetcher.fd != null);
        assert(reason != .mismatch);
        fetcher.reason = reason;
        return error.Failed;
    }

    /// Where a redirect goes, if the rules let it be followed.
    fn next_hop(fetcher: *Fetcher, origin: client.Origin) error{Failed}!client.Next {
        assert(origin.host.len > 0);
        assert(client.is_redirect(fetcher.head.status));
        const location = fetcher.head.location.slice() orelse return fetcher.refuse(.malformed);
        if (location.len > constants.registry_url_bytes_max) return fetcher.refuse(.malformed);
        // Read before `follow`, which may write the next host over this one.
        const from_loopback = reference.is_loopback(origin.host);
        const from_https = origin.scheme == .https;
        const hosts = &fetcher.host_storage;
        const next = client.follow(origin, location, hosts, &fetcher.target_storage) orelse {
            if (from_https and std.ascii.startsWithIgnoreCase(location, "http://")) {
                return fetcher.refuse(.http);
            }
            return fetcher.refuse(.malformed);
        };
        const to_loopback = reference.is_loopback(next.origin.host);
        if (next.origin.scheme == .http and !to_loopback) return fetcher.refuse(.http);
        if (to_loopback and !from_loopback) return fetcher.refuse(.loopback);
        return next;
    }

    /// One request; the body goes to the partial file only if the answer is a 200.
    fn ask(fetcher: *Fetcher, origin: client.Origin, target: []const u8) error{Failed}!void {
        assert(fetcher.fd != null);
        assert(target.len > 0);
        assert(target[0] == '/');
        fetcher.head = .{};
        const request: net.Request = .{
            .scheme = origin.scheme,
            .host = origin.host,
            .port = origin.port,
            .target = target,
            .accept = "",
            .bearer = "",
            .body_bytes_max = constants.build_fetch_bytes_max,
            .idle_timeout_ms = constants.net_idle_timeout_ms,
            .total_timeout_ms = 0,
        };
        const sink: net.Sink = .{ .context = fetcher, .write = write };
        fetcher.net.get(&request, &fetcher.head, sink) catch |err| {
            if (fetcher.sink_failed) return error.Failed; // The reason is set.
            if (err == error.TooLarge) return fetcher.refuse_reason(.too_large);
            return fetcher.refuse_reason(.{ .network = err });
        };
    }

    fn write(context: *anyopaque, bytes: []const u8) error{SinkFull}!void {
        assert(@intFromPtr(context) != 0);
        const fetcher: *Fetcher = @ptrCast(@alignCast(context));
        assert(fetcher.fd != null);
        // A redirect's or an error's body is not the file.
        if (fetcher.head.status != 200) return;
        assert(fetcher.written + bytes.len <= constants.build_fetch_bytes_max);
        fetcher.blobs.fs.write_all(fetcher.fd.?, bytes) catch |err| {
            fetcher.reason = .{ .io = fetcher.io_failure("writing the partial fetch", err) };
            fetcher.sink_failed = true;
            return error.SinkFull;
        };
        fetcher.hasher.update(bytes);
        fetcher.written += bytes.len;
    }

    /// Checks the hash; a match is flushed and moved into the cache, a mismatch removed.
    fn finish(fetcher: *Fetcher, partial_text: [:0]const u8, expected: Sha256) error{Failed}!void {
        assert(fetcher.fd != null);
        assert(fetcher.written <= constants.build_fetch_bytes_max);
        const fs = fetcher.blobs.fs;
        const fd = fetcher.fd.?;
        const received = fetcher.hasher.final();
        if (!received.eql(expected)) {
            fetcher.drop(partial_text);
            return fetcher.fail(.{ .mismatch = received });
        }
        fs.fsync(fd) catch |err| {
            fetcher.drop(partial_text);
            return fetcher.fail(.{ .io = fetcher.io_failure("flushing the fetched file", err) });
        };
        fs.close(fd);
        fetcher.fd = null;
        var final: PathBuf = undefined;
        const final_text = fetcher.blobs.final_path(&final, expected);
        fs.rename(partial_text, final_text) catch |err| {
            fetcher.drop(partial_text);
            const failure = fetcher.io_failure("moving the fetched file into the cache", err);
            return fetcher.fail(.{ .io = failure });
        };
        var directory: PathBuf = undefined;
        const parts = [_][]const u8{ fetcher.blobs.root, blobs_mod.final_directory };
        directory.set(&parts) catch unreachable; // Short.
        fs.sync_directory(directory.text()) catch |err| {
            return fetcher.fail(.{ .io = fetcher.io_failure("flushing the blob directory", err) });
        };
    }
};
