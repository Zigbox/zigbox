//! A pinned fetch: the download of a copy entry's `.fetch` into the store's blob cache, in the
//! parent, on a miss of its copy step, under the store's shared lock (M9 slice 3b).
//!
//! The bytes stream to a file of the caller's that no other download writes (the store's
//! `tmp/<pid>-<n>`, so two builds fetching one pin at once never share it) and are hashed as
//! they arrive. When the SHA-256 is the pinned one the file is flushed and renamed to
//! `blobs/sha256/<hex>`, where the registry's blobs live; when it is not, the file is removed.
//! So `blobs/sha256/` never holds a file whose bytes are not its name. A blob that is there is
//! hashed again before it counts as cached: one damaged after it landed is downloaded again
//! rather than refused for good.
//!
//! The rules (docs/briefs/M9-dockerfile-import.md, *Pinned fetches*): only `https://`, plain
//! `http://` only for a loopback host; a redirect may not go from https to http, nor from a host
//! that is not loopback to one that is (`names_loopback`, which also knows the numeric
//! spellings); every hop counts against `build_fetch_redirects_max`; a body over
//! `build_fetch_bytes_max` is refused. The download is never resumed. Ctrl-C stops it at the
//! next piece of the body.

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

/// Asks whether the build was asked to stop (`Host.interrupt_signal`): the signal, 0 for none.
pub const Interrupt = struct {
    context: *anyopaque,
    signal: *const fn (context: *anyopaque) u8,
};

/// Why a fetch failed. `mismatch` is E0821, `interrupted` the build's interrupt (E0808); every
/// other one is E0820.
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
    /// The signal that stopped the download.
    interrupted: u8,
};

pub const Outcome = enum { cached, downloaded };

pub const Fetcher = struct {
    blobs: Blobs,
    net: net.Net,
    interrupt: Interrupt,
    /// The most bytes a body may have: `build_fetch_bytes_max`, lower only in tests of the bound.
    bytes_max: u64,
    /// Set when `fetch` fails.
    reason: Reason,
    head: net.Head,
    hasher: digest_mod.Hasher,
    fd: ?fs_mod.Fd,
    written: u64,
    sink_failed: bool,
    host_storage: [constants.registry_host_bytes_max]u8,
    target_storage: [constants.registry_url_bytes_max]u8,
    /// What `has` reads a cached blob through.
    io: [constants.store_io_buffer_bytes]u8,

    pub fn init(fetcher: *Fetcher, blobs: Blobs, network: net.Net, interrupt: Interrupt) void {
        assert(blobs.root[0] == '/');
        assert(blobs.root.len > 1);
        fetcher.blobs = blobs;
        fetcher.net = network;
        fetcher.interrupt = interrupt;
        fetcher.bytes_max = constants.build_fetch_bytes_max;
        fetcher.fd = null;
        fetcher.written = 0;
        fetcher.sink_failed = false;
        fetcher.reason = .redirects;
    }

    /// True if `blobs/sha256/<hex>` is there and its bytes hash to `expected`: no request is
    /// made for it. A file there whose bytes are not its name (a disk fault, another program)
    /// is not cached: the next fetch downloads it again and replaces it.
    pub fn has(fetcher: *Fetcher, expected: Sha256) bool {
        assert(fetcher.fd == null);
        assert(fetcher.blobs.root.len > 1);
        const fs = fetcher.blobs.fs;
        var path: PathBuf = undefined;
        const text = fetcher.blobs.final_path(&path, expected);
        const found = fs.lstat(text) catch return false;
        if (found.kind != .file) return false;
        if (found.size > fetcher.bytes_max) return false;
        const fd = fs.open_read(text) catch return false;
        defer fs.close(fd);
        var hasher = digest_mod.Hasher.init();
        var total: u64 = 0;
        // `read_full` fills the buffer but at the end, so the bound is exact.
        const calls_max = fetcher.bytes_max / fetcher.io.len + 2;
        for (0..calls_max) |_| {
            const count = fs.read_full(fd, &fetcher.io) catch return false;
            if (count == 0) break;
            total += count;
            if (total > fetcher.bytes_max) return false;
            hasher.update(fetcher.io[0..count]);
        } else return false;
        return hasher.final().eql(expected);
    }

    /// Puts the bytes of `url` in the blob cache as `expected`, or sets `reason` and fails.
    /// `url` passed the load-time check (`file.is_fetch_url`). `partial_text` is a path in the
    /// store, on the file system of `blobs/sha256/`, that no other download writes (the store's
    /// `tmp_path`); it holds the bytes until they are checked, and is gone when this returns.
    pub fn fetch(
        fetcher: *Fetcher,
        url: []const u8,
        expected: Sha256,
        partial_text: [:0]const u8,
    ) error{Failed}!Outcome {
        assert(url.len <= constants.registry_url_bytes_max);
        assert(fetcher.fd == null);
        assert(partial_text.len > fetcher.blobs.root.len);
        if (fetcher.has(expected)) return .cached;
        var failure: blobs_mod.Failure = undefined;
        fetcher.blobs.ensure_directories(&failure) catch return fetcher.fail(.{ .io = failure });
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

    /// The download's own file, new: its name is this process's and no other download's.
    fn start(fetcher: *Fetcher, partial_text: [:0]const u8) error{Failed}!void {
        assert(fetcher.fd == null);
        assert(partial_text.len > 0);
        fetcher.fd = fetcher.blobs.fs.create(partial_text, 0o644) catch |err| {
            return fetcher.fail(.{ .io = fetcher.io_failure("creating the partial fetch", err) });
        };
        fetcher.hasher = digest_mod.Hasher.init();
        fetcher.written = 0;
        fetcher.sink_failed = false;
    }

    /// Closes and removes the partial file of a fetch that failed (best effort: a file left by
    /// a process that is gone is removed by `store gc`, and is never in `sha256/`).
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
            const signal = fetcher.interrupt.signal(fetcher.interrupt.context);
            if (signal != 0) return fetcher.refuse_reason(.{ .interrupted = signal });
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
        const from_loopback = names_loopback(origin.host);
        const from_https = origin.scheme == .https;
        const hosts = &fetcher.host_storage;
        const next = client.follow(origin, location, hosts, &fetcher.target_storage) orelse {
            if (from_https and std.ascii.startsWithIgnoreCase(location, "http://")) {
                return fetcher.refuse(.http);
            }
            return fetcher.refuse(.malformed);
        };
        const to_loopback = names_loopback(next.origin.host);
        if (next.origin.scheme == .http and !reference.is_loopback(next.origin.host)) {
            return fetcher.refuse(.http);
        }
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
            .body_bytes_max = fetcher.bytes_max,
            .idle_timeout_ms = constants.net_idle_timeout_ms,
            .total_timeout_ms = 0,
        };
        const sink: net.Sink = .{ .context = fetcher, .write = write };
        fetcher.net.get(&request, &fetcher.head, sink) catch |err| {
            if (fetcher.sink_failed) return error.Failed; // The reason is set.
            if (err == error.TooLarge) {
                // A head over its bound comes before any status: that is not usable HTTP, not
                // a file too large.
                if (fetcher.head.status == 0) {
                    return fetcher.refuse_reason(.{ .network = error.BadResponse });
                }
                return fetcher.refuse_reason(.too_large);
            }
            return fetcher.refuse_reason(.{ .network = err });
        };
    }

    fn write(context: *anyopaque, bytes: []const u8) error{SinkFull}!void {
        assert(@intFromPtr(context) != 0);
        const fetcher: *Fetcher = @ptrCast(@alignCast(context));
        assert(fetcher.fd != null);
        // A redirect's or an error's body is not the file.
        if (fetcher.head.status != 200) return;
        assert(fetcher.written + bytes.len <= fetcher.bytes_max);
        // A large body takes minutes: Ctrl-C stops it here, at the next piece.
        const signal = fetcher.interrupt.signal(fetcher.interrupt.context);
        if (signal != 0) {
            fetcher.reason = .{ .interrupted = signal };
            fetcher.sink_failed = true;
            return error.SinkFull;
        }
        fetcher.blobs.fs.write_all(fetcher.fd.?, bytes) catch |err| {
            fetcher.reason = .{ .io = fetcher.io_failure("writing the partial fetch", err) };
            fetcher.sink_failed = true;
            return error.SinkFull;
        };
        fetcher.hasher.update(bytes);
        fetcher.written += bytes.len;
    }

    /// Checks the hash; a match is flushed and moved into the cache, a mismatch removed. Two
    /// downloads of one pin may both get here: each renames its own whole, checked file, and
    /// the second replaces the first with the same bytes.
    fn finish(fetcher: *Fetcher, partial_text: [:0]const u8, expected: Sha256) error{Failed}!void {
        assert(fetcher.fd != null);
        assert(fetcher.written <= fetcher.bytes_max);
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

/// True for a host that may reach this machine: `localhost` (any case, a trailing dot, or a
/// name below `.localhost`), and an IPv4 address in 127/8 or 0.0.0.0 in any spelling the
/// resolver takes (`127.1`, `0x7f.0.0.1`, `2130706433`, `0177.0.0.1`). A redirect from a host
/// that is not one of these to one that is is refused, so a public server cannot point a
/// build at a service on the build host. `net.parse_url` takes no IPv6 literal, so `[::1]`
/// cannot be a host here. A name that DNS resolves to 127.0.0.1 is not caught: the rule is
/// about what the URL says.
pub fn names_loopback(host: []const u8) bool {
    assert(host.len > 0);
    assert(host.len <= constants.registry_host_bytes_max);
    const name = if (host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
    if (std.ascii.eqlIgnoreCase(name, "localhost")) return true;
    if (std.ascii.endsWithIgnoreCase(name, ".localhost")) return true;
    const address = ipv4_value(name) orelse return false;
    return address >> 24 == 127 or address == 0;
}

/// The IPv4 address `text` spells as `inet_aton` reads it (one to four parts, each decimal,
/// octal with a leading 0, or hex with 0x; the last fills the bytes left), or null.
fn ipv4_value(text: []const u8) ?u32 {
    assert(text.len <= constants.registry_host_bytes_max);
    if (text.len == 0) return null;
    if (!std.ascii.isDigit(text[0])) return null;
    var parts: [4]u64 = undefined;
    var count: u32 = 0;
    var iterator = std.mem.splitScalar(u8, text, '.');
    while (iterator.next()) |part| {
        if (count == parts.len) return null;
        parts[count] = ipv4_part(part) orelse return null;
        count += 1;
    }
    assert(count >= 1);
    assert(count <= 4);
    var value: u64 = 0;
    for (parts[0 .. count - 1], 0..) |part, at| {
        if (part > 255) return null;
        value |= part << @intCast(24 - 8 * at);
    }
    const last_bits: u6 = @intCast(32 - 8 * (count - 1));
    const last = parts[count - 1];
    if (last >> last_bits != 0) return null;
    value |= last;
    return @intCast(value);
}

fn ipv4_part(text: []const u8) ?u64 {
    assert(text.len <= constants.registry_host_bytes_max);
    if (text.len == 0) return null;
    if (text.len > 12) return null; // Past 2^32 in any base.
    var base: u8 = 10;
    var digits = text;
    if (std.ascii.startsWithIgnoreCase(text, "0x")) {
        base = 16;
        digits = text[2..];
    } else if (text[0] == '0') {
        if (text.len > 1) {
            base = 8;
            digits = text[1..];
        }
    }
    assert(digits.len <= text.len);
    return std.fmt.parseUnsigned(u64, digits, base) catch null;
}
