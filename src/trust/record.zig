//! The signature record of one tree (docs/briefs/M8-trust.md, "The signature record"):
//! `trust/signatures/<tree hex>` in the store, an in-toto bundle. JSON Lines, one DSSE envelope
//! (`dsse.zig`) per line, each line ending in a newline, at most `signatures_per_tree_max`
//! lines and `signature_record_bytes_max` bytes.
//!
//! The record is keyed by the tree, so a re-pull of the same image, another manifest or a new
//! farm all find it. It is only ever replaced whole, by atomic rename, under the store lock
//! (the caller holds it): a reader and a crash see the old record or the new one. Signing the
//! same statement with the same key again makes the same line (Ed25519 is deterministic), and
//! `add` then changes nothing.
//!
//! Parse accepts only what the writer writes (REVIEW.md): every line must parse as an envelope
//! and re-render to its own bytes, hold a statement of this release's `sign/v1` form about the
//! very tree the record is keyed by, and no line may occur twice. A record whose statement has
//! another predicate type is `Newer` (a release that knows more wrote it); any other defect is
//! `Malformed`. Signatures are not checked here: that is `dsse.verify`'s job, at the gate.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const dsse = @import("dsse.zig");
const statement = @import("statement.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const directory_name = "trust/signatures";
pub const trust_directory = "trust";

pub const ParseError = error{
    /// Not a record in the form this release writes.
    Malformed,
    /// A well-formed envelope whose statement has a predicate type this release does not know.
    Newer,
};

pub const AddError = error{
    /// The record already has `signatures_per_tree_max` distinct lines.
    Full,
};

pub const Added = enum { added, present };

/// The memory parse needs, about 2.9 MiB: the caller makes one (static or heap) and reuses it.
pub const Work = struct {
    envelope: dsse.Work,
    /// One line, re-rendered, to compare with the line read.
    line: [constants.envelope_bytes_max]u8,
    /// The file as read: one byte more than the bound, so a file that is too long is seen.
    file: [constants.signature_record_bytes_max + 1]u8,
};

pub const Record = struct {
    bytes: [constants.signature_record_bytes_max]u8,
    length: u32,
    count: u32,

    pub fn clear(record: *Record) void {
        record.length = 0;
        record.count = 0;
    }

    pub fn text(record: *const Record) []const u8 {
        assert(record.length <= constants.signature_record_bytes_max);
        return record.bytes[0..record.length];
    }

    /// Line `index` (0-based), without its newline.
    pub fn line(record: *const Record, index: u32) []const u8 {
        assert(index < record.count);
        var start: usize = 0;
        var at: u32 = 0;
        const bytes = record.text();
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, bytes, start, '\n').?;
            if (at == index) return bytes[start..end];
            start = end + 1;
            at += 1;
        }
    }

    /// True if `envelope` (one line's bytes, no newline) is already a line.
    pub fn has(record: *const Record, envelope: []const u8) bool {
        for (0..record.count) |index| {
            if (std.mem.eql(u8, record.line(@intCast(index)), envelope)) return true;
        }
        return false;
    }

    /// Appends `envelope` as a line unless it is there already. The caller made the envelope
    /// itself, so it is well formed; this only enforces the bounds.
    pub fn add(record: *Record, envelope: []const u8) AddError!Added {
        assert(envelope.len > 0);
        assert(envelope.len <= constants.envelope_bytes_max);
        assert(std.mem.indexOfScalar(u8, envelope, '\n') == null);
        if (record.has(envelope)) return .present;
        if (record.count == constants.signatures_per_tree_max) return error.Full;
        const need = envelope.len + 1;
        // Eight lines of the longest envelope fit by the constant's definition.
        assert(record.length + need <= constants.signature_record_bytes_max);
        @memcpy(record.bytes[record.length..][0..envelope.len], envelope);
        record.bytes[record.length + envelope.len] = '\n';
        record.length += @intCast(need);
        record.count += 1;
        return .added;
    }
};

comptime {
    assert(constants.signature_record_bytes_max >=
        constants.signatures_per_tree_max * (constants.envelope_bytes_max + 1));
    assert(constants.signatures_per_tree_max >= 1);
}

/// Reads `bytes`, which must be a record of the tree `tree`, into `out`.
pub fn parse(work: *Work, tree: Digest, bytes: []const u8, out: *Record) ParseError!void {
    assert(tree.bytes.len == constants.store_digest_bytes);
    out.clear();
    if (bytes.len == 0) return error.Malformed;
    if (bytes.len > constants.signature_record_bytes_max) return error.Malformed;
    if (bytes[bytes.len - 1] != '\n') return error.Malformed;
    var start: usize = 0;
    var newer = false;
    // Each pass consumes one line, and a record has at most `signatures_per_tree_max` of them.
    while (start < bytes.len) {
        const end = std.mem.indexOfScalarPos(u8, bytes, start, '\n').?; // The last byte is one.
        const text = bytes[start..end];
        start = end + 1;
        if (text.len == 0) return error.Malformed;
        if (out.count == constants.signatures_per_tree_max) return error.Malformed;
        check_line(work, tree, text) catch |err| switch (err) {
            error.Newer => newer = true,
            error.Malformed => return error.Malformed,
        };
        // A duplicate is refused here, as `add` never writes one.
        if (out.has(text)) return error.Malformed;
        const added = out.add(text) catch return error.Malformed;
        assert(added == .added);
    }
    assert(out.count >= 1);
    // A newer line still has to be a whole record of lines we can count, but the record as a
    // whole is one this release must not rewrite, so it is refused after the scan.
    if (newer) return error.Newer;
    assert(std.mem.eql(u8, out.text(), bytes));
}

/// One line: an envelope that re-renders to itself and a statement about `tree`.
fn check_line(work: *Work, tree: Digest, text: []const u8) ParseError!void {
    if (text.len > constants.envelope_bytes_max) return error.Malformed;
    const envelope = dsse.parse(&work.envelope, text) catch return error.Malformed;
    const again = dsse.render(&work.envelope, &work.line, &envelope);
    if (!std.mem.eql(u8, again, text)) return error.Malformed;
    const found = statement.parse(envelope.payload) catch |err| switch (err) {
        error.UnknownPredicate => return error.Newer,
        error.Malformed => return error.Malformed,
    };
    if (!std.mem.eql(u8, &found.tree, &tree.bytes)) return error.Malformed;
}

// ---- The store ----

pub const LoadError = error{ NotFound, Unreadable, Damaged, Newer };

fn record_path(store: *const Store, buffer: *PathBuf, tree: Digest) [:0]const u8 {
    assert(store.root_len > 1);
    const hex = tree.hex();
    return store.path(buffer, &.{ "/", directory_name, "/", &hex });
}

/// Reads the record of `tree`. `NotFound` is an absent record, which is not damage.
pub fn load(
    store: *const Store,
    work: *Work,
    tree: Digest,
    out: *Record,
    errno: *u16,
) LoadError!void {
    out.clear();
    var path: PathBuf = undefined;
    const fs = store.fs;
    const bytes = fs.read_whole(record_path(store, &path, tree), &work.file) catch |err| {
        errno.* = fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    return parse(work, tree, bytes, out) catch |err| switch (err) {
        error.Malformed => error.Damaged,
        error.Newer => error.Newer,
    };
}

/// Writes the record of `tree` whole, by atomic rename. The caller holds the store lock.
pub fn save(
    store: *Store,
    tree: Digest,
    record: *const Record,
    failure: *fs_mod.Failure,
) host_mod.Error!void {
    assert(record.count >= 1);
    assert(record.count <= constants.signatures_per_tree_max);
    var parent: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const fs = store.fs;
    const parent_path = store.directory_path(&parent, trust_directory);
    const directory_path = store.directory_path(&directory, directory_name);
    inline for (.{ parent_path, directory_path }) |made| {
        fs.make_directory(made, true) catch |err| return fs.note(failure, err);
    }
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = record_path(store, &final, tree);
    try fs.write_atomic(temporary_path, final_path, directory_path, record.text(), 0o644, failure);
}

/// How many signature records the store holds, for `trust_records_max`.
pub fn count_records(store: *const Store, errno: *u16) host_mod.Error!u32 {
    var counter: Counter = .{ .count = 0 };
    var directory: PathBuf = undefined;
    const fs = store.fs;
    const visitor: fs_mod.Visitor = .{ .context = &counter, .call = Counter.visit };
    fs.read_dir(store.directory_path(&directory, directory_name), visitor) catch |err| {
        if (err == error.NotFound) return 0;
        errno.* = fs.last_errno();
        return err;
    };
    return counter.count;
}

const Counter = struct {
    count: u32,

    fn visit(context: *anyopaque, name: []const u8) void {
        assert(name.len > 0);
        const counter: *Counter = @ptrCast(@alignCast(context));
        // Saturating: a directory a hand filled cannot wrap the count to a small number.
        counter.count +|= 1;
    }
};
