//! The blob cache and one blob's download. Blobs (layers and configs) live in the store as
//!
//!   <store>/blobs/sha256/<64 hex>     a blob whose digest was checked when it arrived
//!   <store>/blobs/partial/<64 hex>    a download that was cut: its bytes so far
//!
//! A blob enters `sha256/` only by a rename from `partial/`, after its length and its SHA-256
//! are right, so a name in `sha256/` is a verified blob. A cut download keeps its bytes; the
//! next try hashes them again (the hash cannot be saved: it is a state, not a file) and asks the
//! registry for the rest with `Range`. A registry that ignores the range and sends the whole
//! blob (200) makes the download start again; one that answers a different range is refused.
//!
//! The network writes through `Download.sink`; nothing here talks to the network. The code is
//! written against `Fs`, so the simulator's file system tests it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("../store/fs.zig");
const net = @import("net.zig");

const Fs = fs_mod.Fs;
const PathBuf = fs_mod.PathBuf;
const Sha256 = digest_mod.Sha256;

pub const blobs_directory = "/blobs";
pub const final_directory = "/blobs/sha256";
pub const partial_directory = "/blobs/partial";

/// What went wrong with a file, for the message: the step, the error and the errno.
pub const Failure = struct {
    step: []const u8,
    err: fs_mod.Error,
    errno: u16,
};

/// Why a body was refused by the sink.
pub const Problem = enum {
    none,
    /// The file system failed (`Download.failure`).
    io,
    /// The registry sent more bytes than the manifest says the blob has.
    too_long,
    /// A 206 whose range does not start where the partial file ends, or has no range.
    bad_range,
};

pub const Blobs = struct {
    fs: Fs,
    /// The store's directory, absolute, without a trailing slash.
    root: []const u8,

    pub fn final_path(blobs: Blobs, buffer: *PathBuf, digest: Sha256) [:0]const u8 {
        assert(blobs.root[0] == '/');
        assert(blobs.root.len > 1);
        const hex = digest.hex();
        buffer.set(&.{ blobs.root, final_directory, "/", &hex }) catch unreachable; // Short.
        return buffer.text();
    }

    pub fn partial_path(blobs: Blobs, buffer: *PathBuf, digest: Sha256) [:0]const u8 {
        assert(blobs.root[0] == '/');
        assert(blobs.root.len > 1);
        const hex = digest.hex();
        buffer.set(&.{ blobs.root, partial_directory, "/", &hex }) catch unreachable; // Short.
        return buffer.text();
    }

    /// Makes `blobs/`, `blobs/sha256/` and `blobs/partial/` (a store made before M4 has none).
    pub fn ensure_directories(blobs: Blobs, failure: *Failure) fs_mod.Error!void {
        assert(blobs.root[0] == '/');
        assert(blobs.root.len > 1);
        const names = [_][]const u8{ blobs_directory, final_directory, partial_directory };
        for (names) |name| {
            var path: PathBuf = undefined;
            path.set(&.{ blobs.root, name }) catch unreachable; // Short.
            blobs.fs.make_directory(path.text(), true) catch |err| {
                failure.* = .{
                    .step = "making the blob directory",
                    .err = err,
                    .errno = blobs.fs.last_errno(),
                };
                return err;
            };
        }
    }

    /// True if the verified blob is in the cache with this length.
    pub fn has(blobs: Blobs, digest: Sha256, size: u64) bool {
        assert(size > 0);
        assert(blobs.root.len > 1);
        var path: PathBuf = undefined;
        const found = blobs.fs.lstat(blobs.final_path(&path, digest)) catch return false;
        return found.kind == .file and found.size == size;
    }
};

pub const Begin = enum { cached, ready };

pub const Finish = union(enum) {
    ok,
    /// The file has fewer bytes than the blob: the partial file stays for a resume.
    short: u64,
    /// The bytes are not the blob; the partial file was removed.
    mismatch: Sha256,
};

pub const Download = struct {
    blobs: Blobs,
    digest: Sha256,
    size: u64,
    head: *const net.Head,
    fd: ?fs_mod.Fd,
    hasher: digest_mod.Hasher,
    /// Bytes in the partial file now (and hashed).
    offset: u64,
    /// The offset the download started at, to tell a resumed one from a fresh one.
    started_at: u64,
    started: bool,
    problem: Problem,
    failure: Failure,
    io: [constants.blob_io_bytes]u8,

    /// Looks at the cache: `cached` if the blob is there; otherwise the partial file is opened
    /// (made, or appended to after its bytes are hashed) and the download is `ready`.
    pub fn begin(
        download: *Download,
        blobs: Blobs,
        digest: Sha256,
        size: u64,
        head: *const net.Head,
    ) fs_mod.Error!Begin {
        assert(size > 0);
        download.* = .{
            .blobs = blobs,
            .digest = digest,
            .size = size,
            .head = head,
            .fd = null,
            .hasher = digest_mod.Hasher.init(),
            .offset = 0,
            .started_at = 0,
            .started = false,
            .problem = .none,
            .failure = undefined,
            .io = undefined,
        };
        if (blobs.has(digest, size)) return .cached;
        errdefer download.abandon();
        try download.drop_wrong_final();
        try download.open_partial();
        download.started_at = download.offset;
        assert(download.fd != null);
        return .ready;
    }

    fn record(download: *Download, step: []const u8, err: fs_mod.Error) void {
        assert(step.len > 0);
        assert(@errorName(err).len > 0);
        download.failure = .{
            .step = step,
            .err = err,
            .errno = download.blobs.fs.last_errno(),
        };
    }

    fn note(download: *Download, step: []const u8, err: fs_mod.Error) fs_mod.Error {
        assert(step.len > 0);
        assert(@errorName(err).len > 0);
        download.record(step, err);
        return err;
    }

    /// A file in `sha256/` of another length is not that blob: it goes.
    fn drop_wrong_final(download: *Download) fs_mod.Error!void {
        assert(download.fd == null);
        assert(download.size > 0);
        var path: PathBuf = undefined;
        const text = download.blobs.final_path(&path, download.digest);
        _ = download.blobs.fs.lstat(text) catch |err| switch (err) {
            error.NotFound => return,
            else => return download.note("looking for the cached blob", err),
        };
        download.blobs.fs.unlink(text) catch |err| {
            return download.note("removing a blob of the wrong length", err);
        };
    }

    fn open_partial(download: *Download) fs_mod.Error!void {
        const fs = download.blobs.fs;
        var path: PathBuf = undefined;
        const text = download.blobs.partial_path(&path, download.digest);
        const found = fs.lstat(text) catch |err| switch (err) {
            error.NotFound => return download.create_partial(text),
            else => return download.note("looking for the partial blob", err),
        };
        if (found.kind != .file or found.size > download.size) {
            // Not a download of this blob (too long, or not a file): start again.
            fs.unlink(text) catch |err| return download.note("removing a partial blob", err);
            return download.create_partial(text);
        }
        try download.hash_existing(text);
        assert(download.offset <= download.size);
        assert(download.offset == found.size);
        download.fd = fs.open_append(text) catch |err| {
            return download.note("opening the partial blob", err);
        };
    }

    fn create_partial(download: *Download, text: [:0]const u8) fs_mod.Error!void {
        assert(text.len > 0);
        assert(download.fd == null);
        download.hasher = digest_mod.Hasher.init();
        download.offset = 0;
        download.fd = download.blobs.fs.create(text, 0o644) catch |err| {
            return download.note("creating the partial blob", err);
        };
    }

    /// Reads the partial file through the hasher.
    fn hash_existing(download: *Download, text: [:0]const u8) fs_mod.Error!void {
        const fs = download.blobs.fs;
        const fd = fs.open_read(text) catch |err| {
            return download.note("reading the partial blob", err);
        };
        defer fs.close(fd);
        download.hasher = digest_mod.Hasher.init();
        download.offset = 0;
        var reads: u64 = 0;
        while (true) {
            reads += 1;
            assert(reads <= download.size / download.io.len + 2);
            const count = fs.read(fd, &download.io) catch |err| {
                return download.note("reading the partial blob", err);
            };
            if (count == 0) break;
            download.hasher.update(download.io[0..count]);
            download.offset += count;
        }
        assert(download.offset <= download.size);
    }

    /// The offset to ask the registry for; the whole blob if zero.
    pub fn range_from(download: *const Download) u64 {
        assert(download.size > 0);
        assert(download.offset <= download.size);
        return download.offset;
    }

    /// True if every byte is already here (a complete partial file): no request is needed.
    pub fn complete(download: *const Download) bool {
        assert(download.size > 0);
        assert(download.offset <= download.size);
        return download.offset == download.size;
    }

    pub fn sink(download: *Download) net.Sink {
        assert(download.fd != null);
        assert(download.offset <= download.size);
        return .{ .context = download, .write = write };
    }

    fn write(context: *anyopaque, bytes: []const u8) error{SinkFull}!void {
        assert(@intFromPtr(context) != 0);
        const download: *Download = @ptrCast(@alignCast(context));
        assert(download.fd != null);
        const status = download.head.status;
        // An answer that is not the blob (a redirect, an error page) is not kept.
        if (status != 200 and status != 206) return;
        if (!download.started) try download.first_bytes(status);
        if (bytes.len > download.size - download.offset) {
            download.problem = .too_long;
            return error.SinkFull;
        }
        download.blobs.fs.write_all(download.fd.?, bytes) catch |err| {
            download.record("writing the partial blob", err);
            download.problem = .io;
            return error.SinkFull;
        };
        download.hasher.update(bytes);
        download.offset += bytes.len;
    }

    /// The first body byte of the answer that is the blob: a 200 starts the file again, a 206
    /// must continue it.
    fn first_bytes(download: *Download, status: u16) error{SinkFull}!void {
        assert(status >= 200);
        assert(status <= 206);
        assert(!download.started);
        download.started = true;
        if (status == 200) {
            if (download.offset == 0) return;
            download.restart() catch {
                download.problem = .io;
                return error.SinkFull;
            };
            return;
        }
        const text = download.head.content_range.slice() orelse {
            download.problem = .bad_range;
            return error.SinkFull;
        };
        if (range_start(text) != download.offset) {
            download.problem = .bad_range;
            return error.SinkFull;
        }
    }

    /// The registry sent the whole blob though a range was asked: drop the old bytes.
    fn restart(download: *Download) fs_mod.Error!void {
        assert(download.fd != null);
        assert(download.offset > 0);
        const fs = download.blobs.fs;
        var path: PathBuf = undefined;
        const text = download.blobs.partial_path(&path, download.digest);
        fs.close(download.fd.?);
        download.fd = null;
        fs.unlink(text) catch |err| return download.note("removing a partial blob", err);
        try download.create_partial(text);
        download.started_at = 0;
    }

    /// Ends the download: close the file, then check what it holds.
    pub fn finish(download: *Download) fs_mod.Error!Finish {
        assert(download.offset <= download.size);
        const fs = download.blobs.fs;
        const fd = download.fd orelse unreachable; // `begin` opened it and `abandon` clears it.
        download.fd = null;
        if (download.offset < download.size) {
            fs.close(fd);
            return .{ .short = download.offset };
        }
        assert(download.offset == download.size);
        const actual = download.hasher.final();
        var partial: PathBuf = undefined;
        const partial_text = download.blobs.partial_path(&partial, download.digest);
        if (!actual.eql(download.digest)) {
            fs.close(fd);
            fs.unlink(partial_text) catch |err| return download.note("removing a bad blob", err);
            return .{ .mismatch = actual };
        }
        fs.fsync(fd) catch |err| {
            fs.close(fd);
            return download.note("flushing the blob", err);
        };
        fs.close(fd);
        var final: PathBuf = undefined;
        const final_text = download.blobs.final_path(&final, download.digest);
        fs.rename(partial_text, final_text) catch |err| {
            return download.note("moving the blob into the cache", err);
        };
        var directory: PathBuf = undefined;
        directory.set(&.{ download.blobs.root, final_directory }) catch unreachable; // Short.
        fs.sync_directory(directory.text()) catch |err| {
            return download.note("flushing the blob directory", err);
        };
        return .ok;
    }

    /// Closes the file of a download that is given up; the partial file stays.
    pub fn abandon(download: *Download) void {
        assert(download.size > 0);
        assert(download.offset <= download.size);
        if (download.fd) |fd| download.blobs.fs.close(fd);
        download.fd = null;
    }

    /// True if the download began from a partial file.
    pub fn was_resumed(download: *const Download) bool {
        assert(download.started_at <= download.size);
        assert(download.started_at <= download.offset);
        return download.started_at > 0;
    }

    /// Removes the partial file (a resumed download whose bytes turned out wrong).
    pub fn discard(download: *Download) fs_mod.Error!void {
        assert(download.fd == null);
        assert(download.size > 0);
        var path: PathBuf = undefined;
        const text = download.blobs.partial_path(&path, download.digest);
        download.blobs.fs.unlink(text) catch |err| switch (err) {
            error.NotFound => return,
            else => return download.note("removing a partial blob", err),
        };
    }
};

/// The first byte of "bytes first-last/total"; maxInt if the text is not that.
pub fn range_start(text: []const u8) u64 {
    assert(text.len < 1 << 16);
    assert(text.len <= constants.registry_header_bytes_max);
    const prefix = "bytes ";
    if (!std.mem.startsWith(u8, text, prefix)) return std.math.maxInt(u64);
    const rest = text[prefix.len..];
    const dash = std.mem.indexOfScalar(u8, rest, '-') orelse return std.math.maxInt(u64);
    return std.fmt.parseInt(u64, rest[0..dash], 10) catch std.math.maxInt(u64);
}

const testing = std.testing;
const fs_sim = @import("../store/fs_sim.zig");

var test_fs: fs_sim.SimFs = undefined;
var test_download: Download = undefined;

fn test_blobs() Blobs {
    test_fs.init(1);
    test_fs.put_dir("/s", 0o755);
    return .{ .fs = test_fs.interface(), .root = "/s" };
}

fn feed(download: *Download, status: u16, bytes: []const u8) !void {
    const head: *net.Head = @constCast(download.head);
    head.status = status;
    try download.sink().write(download.sink().context, bytes);
}

test "a blob is written, verified and moved into the cache" {
    // Goal: the happy path in two writes; the cache holds the blob under its digest and the
    // partial file is gone.
    const blobs = test_blobs();
    var failure: Failure = undefined;
    try blobs.ensure_directories(&failure);
    const digest = Sha256.of("hello blob");
    var head: net.Head = .{};
    try testing.expectEqual(Begin.ready, try test_download.begin(blobs, digest, 10, &head));
    try feed(&test_download, 200, "hello ");
    try feed(&test_download, 200, "blob");
    try testing.expectEqual(Finish.ok, try test_download.finish());
    var path: PathBuf = undefined;
    const final = blobs.final_path(&path, digest);
    try testing.expectEqualStrings("hello blob", test_fs.content_of(final).?);
    try testing.expect(blobs.has(digest, 10));
    var again: PathBuf = undefined;
    try testing.expect(test_fs.kind_of(blobs.partial_path(&again, digest)) == null);
    try testing.expectEqual(Begin.cached, try test_download.begin(blobs, digest, 10, &head));
}

test "a cut download is resumed from its bytes, and a wrong range is refused" {
    // Goal: the partial file is hashed again and appended to; a 206 must start at its end.
    const blobs = test_blobs();
    var failure: Failure = undefined;
    try blobs.ensure_directories(&failure);
    const digest = Sha256.of("hello blob");
    var head: net.Head = .{};
    _ = try test_download.begin(blobs, digest, 10, &head);
    try feed(&test_download, 200, "hello");
    test_download.abandon();
    try testing.expectEqual(Begin.ready, try test_download.begin(blobs, digest, 10, &head));
    try testing.expectEqual(@as(u64, 5), test_download.range_from());
    head.content_range.set("bytes 4-9/10");
    try testing.expectError(error.SinkFull, feed(&test_download, 206, " blob"));
    try testing.expectEqual(Problem.bad_range, test_download.problem);
    test_download.abandon();
    _ = try test_download.begin(blobs, digest, 10, &head);
    head.content_range = .{};
    head.content_range.set("bytes 5-9/10");
    try feed(&test_download, 206, " blob");
    try testing.expect(test_download.was_resumed());
    try testing.expectEqual(Finish.ok, try test_download.finish());
}

test "a registry that ignores the range starts the blob again, and wrong bytes are not kept" {
    // Goal: a 200 to a resume replaces the partial file; a blob that hashes wrong is removed
    // and never reaches the cache; a longer body is refused.
    const blobs = test_blobs();
    var failure: Failure = undefined;
    try blobs.ensure_directories(&failure);
    const digest = Sha256.of("hello blob");
    var head: net.Head = .{};
    _ = try test_download.begin(blobs, digest, 10, &head);
    try feed(&test_download, 200, "hello");
    test_download.abandon();
    _ = try test_download.begin(blobs, digest, 10, &head);
    try feed(&test_download, 200, "hello blob");
    try testing.expectEqual(Finish.ok, try test_download.finish());

    const other = Sha256.of("something else");
    _ = try test_download.begin(blobs, other, 10, &head);
    try feed(&test_download, 200, "0123456789");
    const finished = try test_download.finish();
    try testing.expect(finished == .mismatch);
    try testing.expect(!blobs.has(other, 10));
    var path: PathBuf = undefined;
    try testing.expect(test_fs.kind_of(blobs.partial_path(&path, other)) == null);

    _ = try test_download.begin(blobs, other, 10, &head);
    try testing.expectError(error.SinkFull, feed(&test_download, 200, "0123456789a"));
    try testing.expectEqual(Problem.too_long, test_download.problem);
    test_download.abandon();
}

test "an answer that is not the blob is not kept, and a short file is a short result" {
    // Goal: a redirect or an error body never reaches the file; a download that ends early
    // reports its length and keeps the file.
    const blobs = test_blobs();
    var failure: Failure = undefined;
    try blobs.ensure_directories(&failure);
    const digest = Sha256.of("hello blob");
    var head: net.Head = .{};
    _ = try test_download.begin(blobs, digest, 10, &head);
    try feed(&test_download, 307, "moved elsewhere");
    try feed(&test_download, 503, "Service Unavailable");
    try testing.expectEqual(@as(u64, 0), test_download.offset);
    try feed(&test_download, 200, "hello");
    const finished = try test_download.finish();
    try testing.expectEqual(@as(u64, 5), finished.short);
    var path: PathBuf = undefined;
    const partial = test_fs.content_of(blobs.partial_path(&path, digest)).?;
    try testing.expectEqual(@as(usize, 5), partial.len);
}

test "range_start reads the first byte of a Content-Range" {
    // Goal: the one field the resume needs, and nothing else accepted.
    try testing.expectEqual(@as(u64, 5), range_start("bytes 5-9/10"));
    try testing.expectEqual(@as(u64, 0), range_start("bytes 0-0/*"));
    try testing.expectEqual(std.math.maxInt(u64), range_start("bytes */10"));
    try testing.expectEqual(std.math.maxInt(u64), range_start("items 5-9/10"));
    try testing.expectEqual(std.math.maxInt(u64), range_start(""));
}
