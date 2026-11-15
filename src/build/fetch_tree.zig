//! The tree a fetched file is copied from: one regular file, named after the URL, with Docker's
//! remote-`ADD` defaults (mode 0600, owner 0:0, no extended attributes), read from the blob
//! cache (`blobs/sha256/<hex>`). Its SHA-256 is checked again as it is read, so a blob that was
//! damaged after its download never reaches a step.
//!
//! It runs in the store's namespace, in the child `input_job` starts, because writing an object
//! owned by 0:0 is a `chown` only the namespace's root may do.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const digest_mod = @import("../store/digest.zig");
const oci_digest = @import("../registry/digest.zig");
const blobs_mod = @import("../registry/blobs.zig");
const registry_diagnose = @import("../registry/diagnose.zig");
const store_diagnose = @import("../store/diagnose.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const xattrs = @import("../store/xattrs.zig");
const input_tree = @import("input_tree.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Sha256 = oci_digest.Sha256;
const Store = layout.Store;

/// Docker's remote `ADD`: the file is 0600 unless `.chmod` says otherwise.
pub const file_mode: u16 = 0o600;

/// The name of the file in the tree when `.to` names the file itself (the URL's name is used
/// only when `.to` ends in `/`, and the selection puts the one file at `.to`).
pub const name_default = "fetched";

/// Reads blob `sha256` into the store as the tree `{ name: file }` and returns the tree. Null
/// with `diag` raised on a failure; a blob whose bytes are not `sha256` is E0511, as for a pull.
pub fn import(
    store: *Store,
    ws: *input_tree.Workspace,
    sha256: Sha256,
    name: []const u8,
    diag: *Diag,
) ?Digest {
    assert(diag.code == null);
    assert(name.len > 0);
    assert(name.len <= constants.store_name_bytes_max);
    const blobs: blobs_mod.Blobs = .{ .fs = store.fs, .root = store.root_text() };
    var path_storage: PathBuf = undefined;
    const path = blobs.final_path(&path_storage, sha256);
    var content: object.Content = undefined;
    if (!hash_blob(store, ws, path, sha256, &content, diag)) return null;
    const attrs: object.Attrs = .{
        .mode = file_mode,
        .uid = 0,
        .gid = 0,
        .xattrs = &xattrs.empty,
    };
    const id = object.object_id(content.hash, attrs);
    var failure: object.Failure = undefined;
    const source: object.Source = .{ .path = path };
    object.put_from(store, &ws.io, &ws.scratch, source, &content, attrs, id, &failure) catch |err| {
        return switch (err) {
            error.Changed => changed(store, sha256, diag),
            error.SourceFailed => failed(store, "reading a fetched file", &failure, diag),
            error.StoreFailed => failed(store, "writing a fetched file", &failure, diag),
        };
    };
    return one_file_tree(store, ws, name, &content, id, diag);
}

/// The first read: size, store hash and chunks, and the SHA-256 checked against the name.
fn hash_blob(
    store: *Store,
    ws: *input_tree.Workspace,
    path: [:0]const u8,
    sha256: Sha256,
    content: *object.Content,
    diag: *Diag,
) bool {
    assert(path.len > 0);
    assert(diag.code == null);
    const fs = store.fs;
    const fd = fs.open_read(path) catch |err| {
        var failure: object.Failure = .{ .err = err, .errno = fs.last_errno() };
        _ = failed(store, "reading a fetched file", &failure, diag);
        return false;
    };
    defer fs.close(fd);
    var reader = object.Reader.init(store.chunk_bytes);
    var hasher = oci_digest.Hasher.init();
    const calls_max = constants.build_fetch_bytes_max / ws.io.len + constants.store_chunks_max + 2;
    for (0..calls_max) |_| {
        const count = fs.read(fd, &ws.io) catch |err| {
            var failure: object.Failure = .{ .err = err, .errno = fs.last_errno() };
            _ = failed(store, "reading a fetched file", &failure, diag);
            return false;
        };
        if (count == 0) break;
        hasher.update(ws.io[0..count]);
        // A blob over the store's file bound cannot be: build_fetch_bytes_max is below it.
        const fits = reader.update(ws.io[0..count], &ws.chunks);
        if (!fits) return changed(store, sha256, diag) != null;
    } else return changed(store, sha256, diag) != null;
    const actual = hasher.final();
    if (!actual.eql(sha256)) {
        registry_diagnose.blob_damaged(diag, store.root_text(), .fetched, sha256, actual);
        return false;
    }
    const hash = reader.finish(&ws.chunks);
    content.* = .{ .size = reader.size, .hash = hash, .chunks = ws.chunks[0..reader.count] };
    return true;
}

fn one_file_tree(
    store: *Store,
    ws: *input_tree.Workspace,
    name: []const u8,
    content: *const object.Content,
    id: Digest,
    diag: *Diag,
) ?Digest {
    assert(name.len > 0);
    assert(diag.code == null);
    var writer = tree.Writer.init(ws.arena[0..]);
    writer.begin(name, .file, file_mode, 0, 0, &xattrs.empty) catch unreachable; // One entry.
    writer.end_file(content.size, content.hash, id) catch unreachable; // Fits the arena.
    const own: tree.Own = .{
        .mode = input_tree.directory_mode,
        .uid = 0,
        .gid = 0,
        .xattrs = &xattrs.empty,
    };
    const bytes = writer.finish_with(own) catch unreachable; // Fits the arena.
    const digest = Digest.of(bytes);
    var failure: object.Failure = undefined;
    _ = trees.put(store, digest, bytes, &failure) catch {
        return failed(store, "writing the tree of a fetched file", &failure, diag);
    };
    return digest;
}

fn failed(
    store: *Store,
    operation: []const u8,
    failure: *const object.Failure,
    diag: *Diag,
) ?Digest {
    assert(operation.len > 0);
    assert(diag.code == null);
    store_diagnose.write_failed(diag, store, operation, failure.err, failure.errno);
    return null;
}

/// The blob changed while it was read: it grew, or differs between the two reads. Nothing
/// should write `blobs/sha256` but a fetch or a pull, so this is a failure of the disk or of
/// another program, told as a failed read of the store.
fn changed(store: *Store, sha256: Sha256, diag: *Diag) ?Digest {
    assert(diag.code == null);
    assert(store.root_len > 0);
    assert(sha256.hex().len == 64);
    const operation = "reading a fetched file, which changed while it was read";
    store_diagnose.write_failed(diag, store, operation, error.IoFailed, 0);
    return null;
}
