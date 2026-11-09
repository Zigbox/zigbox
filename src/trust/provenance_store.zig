//! The provenance record of a result in the store: `trust/provenance/<result hex>`, the payload
//! bytes of `provenance.zig` and nothing else (no envelope: it is not signed, and a signature
//! is a different file, `record.zig`). Written whole by atomic rename under the store lock, and
//! replaced by a later build of the same result. A record is read only when it parses
//! (`provenance.parse`) and is about the result its name says.
//!
//! The record's own digest is the BLAKE3 of its bytes; `zbx inspect --provenance` shows it and
//! `zbx sign` signs exactly these bytes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const provenance = @import("provenance.zig");
const record = @import("record.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const directory_name = "trust/provenance";

pub const LoadError = error{ NotFound, Unreadable, Damaged };

/// The memory a read needs: the file, and what parse needs beside it.
pub const Work = struct {
    file: [constants.statement_bytes_max + 1]u8,
    again: [constants.statement_bytes_max]u8,
    parsed: provenance.Record,
};

pub fn record_path(store: *const Store, buffer: *PathBuf, result: Digest) [:0]const u8 {
    assert(store.root_len > 1);
    const hex = result.hex();
    return store.path(buffer, &.{ "/", directory_name, "/", &hex });
}

/// The digest of a record's bytes.
pub fn digest_of(payload: []const u8) Digest {
    assert(payload.len <= constants.statement_bytes_max);
    return Digest.of(payload);
}

/// Reads the record of `result` into `work.parsed` and returns its bytes (in `work.file`).
/// `NotFound` is an absent record, which is not damage.
pub fn load(
    store: *const Store,
    work: *Work,
    result: Digest,
    errno: *u16,
) LoadError![]const u8 {
    var path: PathBuf = undefined;
    const fs = store.fs;
    const bytes = fs.read_whole(record_path(store, &path, result), &work.file) catch |err| {
        errno.* = fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    provenance.parse(bytes, &work.parsed, &work.again) catch return error.Damaged;
    if (!std.mem.eql(u8, &work.parsed.result, &result.bytes)) return error.Damaged;
    return bytes;
}

/// Writes the record of `result` whole, by atomic rename. The caller holds the store lock.
pub fn save(
    store: *Store,
    result: Digest,
    payload: []const u8,
    failure: *fs_mod.Failure,
) host_mod.Error!void {
    assert(payload.len > 0);
    assert(payload.len <= constants.statement_bytes_max);
    var parent: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const fs = store.fs;
    const parent_path = store.directory_path(&parent, record.trust_directory);
    const directory_path = store.directory_path(&directory, directory_name);
    inline for (.{ parent_path, directory_path }) |made| {
        fs.make_directory(made, true) catch |err| return fs.note(failure, err);
    }
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = record_path(store, &final, result);
    try fs.write_atomic(temporary_path, final_path, directory_path, payload, 0o644, failure);
}

/// True when a record of `result` is there (readable or not).
pub fn exists(store: *const Store, result: Digest) bool {
    var path: PathBuf = undefined;
    _ = store.fs.lstat(record_path(store, &path, result)) catch return false;
    return true;
}

/// How many provenance records the store holds, for `trust_records_max`.
pub fn count(store: *const Store, errno: *u16) host_mod.Error!u32 {
    return record.count_in(store, directory_name, errno);
}
