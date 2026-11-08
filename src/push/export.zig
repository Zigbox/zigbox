//! `zbx store export --oci`: a packed image written as an OCI image layout, a directory another
//! tool can push or load: `oci-layout`, `index.json` naming the one manifest, and the manifest,
//! config and layer under `blobs/sha256/`. The blobs are the packer's own, copied byte for byte,
//! so the manifest digest is the one `pack` made on any host (same layer-writer version).
//!
//! The directory must not exist, or be an empty directory: export never mixes into what is
//! there (ZBX-E0557).

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
};

pub const Failure = struct {
    stop: Stop,
    errno: u16,
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

/// Checks `dir` is absent or empty, and makes it.
fn prepare(fs: Fs, dir: []const u8, failure: *Failure) Error!void {
    assert(dir.len > 0);
    var path: PathBuf = undefined;
    path.set(&.{dir}) catch return stopped(failure, .write, 0);
    if (fs.lstat(path.text())) |found| {
        if (found.kind != .dir) return stopped(failure, .not_directory, 0);
        var counter: Counter = .{};
        fs.read_dir(path.text(), .{ .context = &counter, .call = Counter.call }) catch {
            return stopped(failure, .write, fs.last_errno());
        };
        if (counter.count > 0) return stopped(failure, .not_empty, 0);
    } else |err| {
        if (err != error.NotFound) return stopped(failure, .write, fs.last_errno());
    }
    fs.make_directory(path.text(), true) catch return stopped(failure, .write, fs.last_errno());
}

fn make_directories(fs: Fs, dir: []const u8, failure: *Failure) Error!void {
    const parts = [_][]const u8{ "", "/blobs", "/blobs/sha256" };
    for (parts) |part| {
        var path: PathBuf = undefined;
        path.set(&.{ dir, part }) catch return stopped(failure, .write, 0);
        fs.make_directory(path.text(), true) catch return stopped(failure, .write, fs.last_errno());
    }
}

fn put_text(fs: Fs, path: [:0]const u8, text: []const u8, failure: *Failure) Error!void {
    assert(text.len > 0);
    const fd = fs.create(path, constants.export_file_mode) catch {
        return stopped(failure, .write, fs.last_errno());
    };
    defer fs.close(fd);
    fs.write_all(fd, text) catch return stopped(failure, .write, fs.last_errno());
    fs.fsync(fd) catch return stopped(failure, .write, fs.last_errno());
}

/// Copies the store's blob `digest` to `to`, through `buffer`.
fn copy_blob(store: *const Store, digest: Sha256, to: [:0]const u8, buffer: []u8, failure: *Failure) Error!void {
    assert(buffer.len > 0);
    const fs = store.fs;
    const blobs: blobs_mod.Blobs = .{ .fs = fs, .root = store.root_text() };
    var from: PathBuf = undefined;
    const source = fs.open_read(blobs.final_path(&from, digest)) catch {
        return stopped(failure, .write, fs.last_errno());
    };
    defer fs.close(source);
    const target = fs.create(to, constants.export_file_mode) catch {
        return stopped(failure, .write, fs.last_errno());
    };
    defer fs.close(target);
    while (true) {
        const count = fs.read(source, buffer) catch return stopped(failure, .write, fs.last_errno());
        if (count == 0) break;
        fs.write_all(target, buffer[0..count]) catch return stopped(failure, .write, fs.last_errno());
    }
    fs.fsync(target) catch return stopped(failure, .write, fs.last_errno());
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
    try writer.member_unsigned("schemaVersion", 2);
    try writer.end_object();
    return writer.finish();
}

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
    try prepare(fs, dir, failure);
    try make_directories(fs, dir, failure);
    const digests = [_]Sha256{ made.layer, made.config, made.manifest };
    for (digests) |digest| {
        var target: PathBuf = undefined;
        blob_target(dir, digest, &target) catch return stopped(failure, .write, 0);
        try copy_blob(store, digest, target.text(), buffer, failure);
    }
    var index: [constants.pack_manifest_bytes_max]u8 = undefined;
    const index_text = render_index(made, &index) catch unreachable; // Sized for one manifest.
    var path: PathBuf = undefined;
    path.set(&.{ dir, "/index.json" }) catch return stopped(failure, .write, 0);
    try put_text(fs, path.text(), index_text, failure);
    path.set(&.{ dir, "/oci-layout" }) catch return stopped(failure, .write, 0);
    try put_text(fs, path.text(), layout_text, failure);
    out.* = .{
        .manifest = made.manifest,
        .config = made.config,
        .layer = made.layer,
        .total_size = made.layer_size + made.config_size + made.manifest_size,
    };
}
