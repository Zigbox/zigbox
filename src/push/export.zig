//! `zbx store export --oci`: a packed image written as an OCI image layout, a directory another
//! tool can push or load: `oci-layout`, `index.json` naming the one manifest, and the manifest,
//! config and layer under `blobs/sha256/`. The blobs are the packer's own, copied byte for byte,
//! so the manifest digest is the one `pack` made on any host (same layer-writer version).
//!
//! The directory must not exist, or be an empty directory: export never mixes into what is
//! there (ZBX-E0557). The layout is written to a sibling directory first, synced, and renamed
//! onto the name, so a failed or killed export leaves nothing under it, and a retry works. Every
//! blob is hashed as it is copied: a cached blob that no longer matches its digest is dropped
//! (ZBX-E0550) rather than exported under a name it does not match.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const blobs_mod = @import("../registry/blobs.zig");
const oci = @import("../registry/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const json = @import("../trust/json.zig");
const pack = @import("pack.zig");

const Fs = fs_mod.Fs;
const PathBuf = fs_mod.PathBuf;
const Sha256 = oci.Sha256;
const Store = layout.Store;

pub const Stop = enum {
    /// The directory exists and holds something.
    not_empty,
    /// The path exists and is not a directory.
    not_directory,
    /// A path is too long, or the directory cannot be read or written.
    write,
    /// A cached blob's bytes do not hash to its digest; it was dropped.
    damaged,
};

pub const Failure = struct {
    stop: Stop,
    errno: u16,
    /// What the file system said, for the cause (`write`).
    err: fs_mod.Error = error.IoFailed,
    /// The blob that failed its hash (`damaged`).
    digest: Sha256 = .{ .bytes = @splat(0) },
};

pub const Error = error{Stopped};

/// What was written: the three digests and the bytes of all three blobs.
pub const Exported = struct {
    manifest: Sha256,
    config: Sha256,
    layer: Sha256,
    total_size: u64,
};

const layout_text = "{\"imageLayoutVersion\":\"1.0.0\"}";

const Counter = struct {
    count: u32 = 0,

    fn call(context: *anyopaque, name: []const u8) void {
        assert(name.len > 0);
        const self: *Counter = @ptrCast(@alignCast(context));
        self.count +|= 1;
    }
};

fn stopped(failure: *Failure, stop: Stop, errno: u16) Error {
    failure.* = .{ .stop = stop, .errno = errno };
    return error.Stopped;
}

/// A failed call of the file system: its error, and the errno the kernel gave (a missing path
/// sets none, so ENOENT is filled in).
fn io_stopped(fs: Fs, failure: *Failure, err: fs_mod.Error) Error {
    var errno = fs.last_errno();
    if (errno == 0 and err == error.NotFound) errno = errno_noent;
    failure.* = .{ .stop = .write, .errno = errno, .err = err };
    return error.Stopped;
}

const errno_noent: u16 = 2;

/// Checks `dir` is absent or an empty directory; writes nothing. A command calls it before the
/// pack too, so a refusal does not wait for minutes of compression.
pub fn check_target(fs: Fs, dir: []const u8, failure: *Failure) Error!void {
    assert(dir.len > 0);
    var path: PathBuf = undefined;
    path.set(&.{dir}) catch return stopped(failure, .write, 0);
    if (fs.lstat(path.text())) |found| {
        if (found.kind != .dir) return stopped(failure, .not_directory, 0);
        var counter: Counter = .{};
        fs.read_dir(path.text(), .{ .context = &counter, .call = Counter.call }) catch |err| {
            return io_stopped(fs, failure, err);
        };
        if (counter.count > 0) return stopped(failure, .not_empty, 0);
    } else |err| {
        if (err != error.NotFound) return io_stopped(fs, failure, err);
    }
}

/// The sibling the layout is built in: `<dir>.zbx-tmp-` and 8 digits of the manifest's.
fn work_path(dir: []const u8, made: *const pack.Packed, path: *PathBuf) Error!void {
    const hex = made.manifest.hex();
    path.set(&.{ dir, ".zbx-tmp-", hex[0..8] }) catch return error.Stopped;
}

fn make_directories(fs: Fs, dir: []const u8, failure: *Failure) Error!void {
    const parts = [_][]const u8{ "", "/blobs", "/blobs/sha256" };
    for (parts) |part| {
        var path: PathBuf = undefined;
        path.set(&.{ dir, part }) catch return stopped(failure, .write, 0);
        fs.make_directory(path.text(), true) catch |err| return io_stopped(fs, failure, err);
    }
}

/// Removes what an export makes in `work` (a failed run's, or a stale one), ignoring what is
/// not there: the layout is fixed, so the names are known.
fn discard(fs: Fs, work: []const u8, made: *const pack.Packed) void {
    var path: PathBuf = undefined;
    const files = [_][]const u8{ "/index.json", "/oci-layout" };
    for (files) |name| {
        path.set(&.{ work, name }) catch return;
        fs.unlink(path.text()) catch {}; // Best effort: a missing file is the usual case.
    }
    for ([_]Sha256{ made.layer, made.config, made.manifest }) |digest| {
        blob_target(work, digest, &path) catch return;
        fs.unlink(path.text()) catch {}; // Best effort, as above.
    }
    for ([_][]const u8{ "/blobs/sha256", "/blobs", "" }) |name| {
        path.set(&.{ work, name }) catch return;
        fs.remove_directory(path.text()) catch {}; // Best effort; a directory with strangers stays.
    }
}

fn put_text(fs: Fs, path: [:0]const u8, text: []const u8, failure: *Failure) Error!void {
    assert(text.len > 0);
    const fd = fs.create(path, constants.export_file_mode) catch |err| {
        return io_stopped(fs, failure, err);
    };
    defer fs.close(fd);
    fs.write_all(fd, text) catch |err| return io_stopped(fs, failure, err);
    fs.fsync(fd) catch |err| return io_stopped(fs, failure, err);
}

/// A cached blob whose bytes are not its digest: drop it and the pack record that names it, so
/// the next run makes it again.
fn blob_damaged(
    store: *const Store,
    made: *const pack.Packed,
    digest: Sha256,
    failure: *Failure,
) Error {
    var from: PathBuf = undefined;
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    store.fs.unlink(blobs.final_path(&from, digest)) catch {}; // Best effort; a gc finds it too.
    pack.forget(store, made.tree);
    failure.* = .{ .stop = .damaged, .errno = 0, .digest = digest };
    return error.Stopped;
}

/// Copies the store's blob `digest` to `to`, through `buffer`, hashing what it copies.
fn copy_blob(
    store: *const Store,
    made: *const pack.Packed,
    digest: Sha256,
    to: [:0]const u8,
    buffer: []u8,
    failure: *Failure,
) Error!void {
    assert(buffer.len > 0);
    const fs = store.fs;
    const blobs: blobs_mod.Blobs = .{ .fs = fs, .root = store.root_text() };
    var from: PathBuf = undefined;
    const source = fs.open_read(blobs.final_path(&from, digest)) catch |err| {
        return io_stopped(fs, failure, err);
    };
    defer fs.close(source);
    const target = fs.create(to, constants.export_file_mode) catch |err| {
        return io_stopped(fs, failure, err);
    };
    defer fs.close(target);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    while (true) {
        const count = fs.read(source, buffer) catch |err| return io_stopped(fs, failure, err);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
        fs.write_all(target, buffer[0..count]) catch |err| return io_stopped(fs, failure, err);
    }
    var found: Sha256 = undefined;
    hasher.final(&found.bytes);
    if (!found.eql(digest)) return blob_damaged(store, made, digest, failure);
    fs.fsync(target) catch |err| return io_stopped(fs, failure, err);
}

fn blob_target(dir: []const u8, digest: Sha256, path: *PathBuf) Error!void {
    const hex = digest.hex();
    path.set(&.{ dir, "/blobs/sha256/", &hex }) catch return error.Stopped;
}

/// `index.json`: one manifest.
pub fn render_index(made: *const pack.Packed, out: []u8) json.WriteError![]const u8 {
    var writer = json.Writer.init(out);
    try writer.begin_object();
    try writer.member_array("manifests");
    try writer.begin_object();
    try writer.member_string("digest", &made.manifest.text());
    try writer.member_string("mediaType", constants.oci_manifest_media_type);
    try writer.member_unsigned("size", made.manifest_size);
    try writer.end_object();
    try writer.end_array();
    try writer.member_string("mediaType", constants.oci_index_media_type);
    try writer.member_unsigned("schemaVersion", 2);
    try writer.end_object();
    return writer.finish();
}

/// Writes the three blobs, `index.json` and `oci-layout` into `work`, and syncs its directories.
fn build(
    store: *const Store,
    made: *const pack.Packed,
    work: []const u8,
    buffer: []u8,
    failure: *Failure,
) Error!void {
    const fs = store.fs;
    try make_directories(fs, work, failure);
    for ([_]Sha256{ made.layer, made.config, made.manifest }) |digest| {
        var target: PathBuf = undefined;
        blob_target(work, digest, &target) catch return stopped(failure, .write, 0);
        try copy_blob(store, made, digest, target.text(), buffer, failure);
    }
    var index: [constants.pack_manifest_bytes_max]u8 = undefined;
    const index_text = render_index(made, &index) catch unreachable; // Sized for one manifest.
    var path: PathBuf = undefined;
    path.set(&.{ work, "/index.json" }) catch return stopped(failure, .write, 0);
    try put_text(fs, path.text(), index_text, failure);
    path.set(&.{ work, "/oci-layout" }) catch return stopped(failure, .write, 0);
    try put_text(fs, path.text(), layout_text, failure);
    for ([_][]const u8{ "/blobs/sha256", "/blobs", "" }) |name| {
        path.set(&.{ work, name }) catch return stopped(failure, .write, 0);
        fs.sync_directory(path.text()) catch |err| return io_stopped(fs, failure, err);
    }
}

/// Moves the finished `work` onto `dir` (absent, or an empty directory, which is removed first:
/// if something arrived there meanwhile, that is E0557) and syncs the parent.
fn install(fs: Fs, work: [:0]const u8, dir: []const u8, failure: *Failure) Error!void {
    var path: PathBuf = undefined;
    path.set(&.{dir}) catch return stopped(failure, .write, 0);
    if (fs.lstat(path.text())) |_| {
        fs.remove_directory(path.text()) catch |err| {
            if (fs.last_errno() == errno_notempty) return stopped(failure, .not_empty, 0);
            return io_stopped(fs, failure, err);
        };
    } else |err| {
        if (err != error.NotFound) return io_stopped(fs, failure, err);
    }
    fs.rename(work, path.text()) catch |err| return io_stopped(fs, failure, err);
    const slash = std.mem.lastIndexOfScalar(u8, dir, '/');
    const parent = if (slash) |at| (if (at == 0) "/" else dir[0..at]) else ".";
    path.set(&.{parent}) catch return stopped(failure, .write, 0);
    fs.sync_directory(path.text()) catch |err| return io_stopped(fs, failure, err);
}

const errno_notempty: u16 = 39;

/// Writes the layout of `made` to `dir`. `buffer` is the copy's piece.
pub fn export_layout(
    store: *const Store,
    made: *const pack.Packed,
    dir: []const u8,
    buffer: []u8,
    out: *Exported,
    failure: *Failure,
) Error!void {
    assert(dir.len > 0);
    assert(buffer.len >= 1024);
    const fs = store.fs;
    try check_target(fs, dir, failure);
    var work: PathBuf = undefined;
    work_path(dir, made, &work) catch return stopped(failure, .write, 0);
    discard(fs, work.text(), made); // A killed run's leftovers.
    build(store, made, work.text(), buffer, failure) catch |err| {
        discard(fs, work.text(), made);
        return err;
    };
    install(fs, work.text(), dir, failure) catch |err| {
        discard(fs, work.text(), made);
        return err;
    };
    out.* = .{
        .manifest = made.manifest,
        .config = made.config,
        .layer = made.layer,
        .total_size = made.layer_size + made.config_size + made.manifest_size,
    };
}
