//! Trust records for a peer and for housekeeping (docs/briefs/M8-trust.md, "Records, gc,
//! export and import"): the library beside Z4's `export_image` and `import_image`, which
//! `zbx trust export|import|prune` and Zigcube's nodes both call.
//!
//! - `export_record` gives the tree's signature record, the bytes of an in-toto bundle.
//! - `import_record` takes such a bundle for one tree: it is parsed and every line verified
//!   (`record.parse`, whole or not at all), and its lines are merged into the tree's record
//!   under the exclusive store lock. A signature by a key nobody trusts is kept: trust is
//!   decided at run time. Whether the tree is in the store is not asked, as a signature may
//!   come before the pull.
//! - `prune_records` removes the orphans: a signature record whose tree is not in the store,
//!   and a provenance record whose result, or the tree it names, is not. One `unlink` each, so
//!   a crash leaves a record present or gone, and a second run finishes. A record whose tree
//!   is present is never removed. `scan` is the same walk without the lock, which gc's orphan
//!   count and the lock holder use.
//!
//! The caller owns the memory; nothing here allocates.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const result_mod = @import("../build/result.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const lock = @import("../store/lock.zig");
const trees = @import("../store/trees.zig");
const dsse = @import("dsse.zig");
const provenance_store = @import("provenance_store.zig");
const record_mod = @import("record.zig");
const statement = @import("statement.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const Refusal = enum {
    /// Export: the store has no signature record for the tree.
    no_record,
    /// Export, import: the record of this store can not be used (newer than this zbx, or it
    /// can not be read for another reason than the disk).
    local_unusable,
    /// Import: the text is longer than any record. `Failure.size` is its length.
    too_large,
    /// Import: the text is not a bundle this zbx reads (a bad line, signature or statement).
    malformed,
    /// Import: a statement of a predicate this zbx does not know.
    newer,
    /// Import: the tree's record would hold more than `signatures_per_tree_max` lines.
    tree_full,
    /// Import: the store holds `trust_records_max` signature records already.
    store_full,
    /// The store lock is held by another process.
    busy,
    /// The store lock file can not be used; `Failure.err` and `errno` say why.
    store_failed,
    /// A read failed; `Failure.errno` says why.
    unreadable,
    /// A write or an unlink failed; `Failure.err` and `errno` say why.
    write_failed,
};

pub const Failure = struct {
    refusal: Refusal,
    size: u64,
    err: host_mod.Error,
    errno: u16,
    /// `local_unusable`: the record is of a newer zbx, not damaged.
    newer: bool = false,

    fn make(refusal: Refusal) Failure {
        return .{ .refusal = refusal, .size = 0, .err = error.IoFailed, .errno = 0 };
    }
};

pub const Error = error{Failed};

/// Export and import work in this: parse's memory (about 6 MiB) and two records.
pub const Memory = struct {
    work: record_mod.Work,
    existing: record_mod.Record,
    incoming: record_mod.Record,
};

pub const Imported = struct {
    /// Lines that were new, and lines the record had already.
    added: u32,
    present: u32,
    /// Lines the tree's record holds now.
    total: u32,
};

fn fail(failure: *Failure, refusal: Refusal) Error {
    failure.* = Failure.make(refusal);
    return error.Failed;
}

fn hold(store: *Store, mode: lock.Mode, who: []const u8, failure: *Failure) Error!void {
    lock.hold(store, mode, who) catch |err| {
        failure.* = Failure.make(if (err == error.Busy) .busy else .store_failed);
        if (err == error.Failed) failure.err = store.lock_error;
        failure.errno = store.lock_errno;
        return error.Failed;
    };
}

/// The tree a bundle is about: its first line's statement's first subject.
pub fn bundle_tree(work: *record_mod.Work, text: []const u8) error{ Malformed, Newer }!Digest {
    const end = std.mem.indexOfScalar(u8, text, '\n') orelse return error.Malformed;
    if (end == 0 or end > constants.envelope_bytes_max) return error.Malformed;
    const envelope = dsse.parse(&work.envelope, text[0..end]) catch return error.Malformed;
    const found = statement.parse(envelope.payload) catch |err| switch (err) {
        error.UnknownPredicate => return error.Newer,
        error.Malformed => return error.Malformed,
    };
    return .{ .bytes = found.tree };
}

/// The record `tree` has here, in `memory.existing` (empty when none), and whether it was
/// there. A damaged record is replaceable by an import and so reads as `damaged`.
const Have = enum { absent, present, damaged };

fn load_existing(store: *const Store, memory: *Memory, tree: Digest, failure: *Failure) Error!Have {
    var errno: u16 = 0;
    record_mod.load(store, &memory.work, tree, &memory.existing, &errno) catch |err| {
        memory.existing.clear();
        switch (err) {
            error.NotFound => return .absent,
            error.Damaged => return .damaged,
            error.Newer => {
                failure.* = Failure.make(.local_unusable);
                failure.newer = true;
                return error.Failed;
            },
            error.Unreadable => {
                failure.* = Failure.make(.unreadable);
                failure.errno = errno;
                return error.Failed;
            },
        }
    };
    return .present;
}

/// The signature record of `tree`, as the bytes of a bundle (they live in `memory`).
pub fn export_record(
    store: *Store,
    memory: *Memory,
    tree: Digest,
    failure: *Failure,
) Error![]const u8 {
    assert(store.root_len > 1);
    try hold(store, .shared, "export_trust", failure);
    defer lock.release(store);
    const have = try load_existing(store, memory, tree, failure);
    if (have == .absent) return fail(failure, .no_record);
    if (have == .damaged) return fail(failure, .local_unusable);
    assert(memory.existing.count >= 1);
    return memory.existing.text();
}

/// Takes the bundle `text` for `tree`. It is refused whole, with nothing written, when any line
/// is not an envelope that verifies and holds a statement about `tree`.
pub fn import_record(
    store: *Store,
    memory: *Memory,
    text: []const u8,
    tree: Digest,
    failure: *Failure,
) Error!Imported {
    assert(store.root_len > 1);
    if (text.len > constants.signature_record_bytes_max) {
        failure.* = Failure.make(.too_large);
        failure.size = text.len;
        return error.Failed;
    }
    record_mod.parse(&memory.work, tree, text, &memory.incoming) catch |err| {
        return fail(failure, if (err == error.Newer) .newer else .malformed);
    };
    try hold(store, .exclusive, "import_trust", failure);
    defer lock.release(store);
    const have = try load_existing(store, memory, tree, failure);
    if (have == .absent) {
        var errno: u16 = 0;
        const count = record_mod.count_records(store, &errno) catch {
            failure.* = Failure.make(.unreadable);
            failure.errno = errno;
            return error.Failed;
        };
        if (count >= constants.trust_records_max) return fail(failure, .store_full);
    }
    var added: u32 = 0;
    for (0..memory.incoming.count) |index| {
        const line = memory.incoming.line(@intCast(index));
        const result = memory.existing.add(line) catch return fail(failure, .tree_full);
        if (result == .added) added += 1;
    }
    if (added > 0 or have == .damaged) {
        var written: fs_mod.Failure = undefined;
        record_mod.save(store, tree, &memory.existing, &written) catch {
            failure.* = Failure.make(.write_failed);
            failure.err = written.err;
            failure.errno = written.errno;
            return error.Failed;
        };
    }
    return .{
        .added = added,
        .present = memory.incoming.count - added,
        .total = memory.existing.count,
    };
}

// ---- Prune ----

pub const Kind = enum { signature, provenance };

pub const Fate = enum {
    /// Its tree (or result) is not in the store: `prune` removes it.
    orphan,
    /// Its tree is in the store but the record is damaged: kept, and `W0902`.
    damaged,
};

pub const Entry = struct {
    kind: Kind,
    fate: Fate,
    /// The tree (signature record) or the result (provenance record).
    digest: Digest,
    envelopes: u32,
    bytes: u32,
};

pub const Report = struct {
    entries: [constants.trust_prune_entries_max]Entry,
    count: u32,
    orphans: u32,
    damaged: u32,
    /// Records whose tree is present and that read: kept, not listed.
    kept: u32,
    /// Orphans `prune` removed.
    removed: u32,
    /// A directory held more than `trust_records_max` names, which were not looked at.
    truncated: bool,

    pub fn clear(report: *Report) void {
        report.count = 0;
        report.orphans = 0;
        report.damaged = 0;
        report.kept = 0;
        report.removed = 0;
        report.truncated = false;
    }

    pub fn list(report: *const Report) []const Entry {
        assert(report.count <= report.entries.len);
        return report.entries[0..report.count];
    }
};

/// What a scan reads with: light, so gc's count needs no more.
pub const ScanMemory = struct {
    result: result_mod.Record,
    result_bytes: [constants.build_result_bytes_max + 1]u8,
    file: [constants.signature_record_bytes_max + 1]u8,
};

/// What a scan that also looks for damage reads with.
pub const Damage = struct {
    work: record_mod.Work,
    record: record_mod.Record,
    provenance: provenance_store.Work,
};

pub const PruneMemory = struct {
    scan: ScanMemory,
    damage: Damage,
};

/// Collects the names of one directory that are digests, up to a cap.
const Collector = struct {
    report: *Report,
    kind: Kind,
    limit: u32,
    taken: u32 = 0,

    fn visit(context: *anyopaque, name: []const u8) void {
        assert(name.len > 0);
        const collector: *Collector = @ptrCast(@alignCast(context));
        const digest = Digest.from_hex(name) orelse return;
        const report = collector.report;
        if (collector.taken == collector.limit) {
            report.truncated = true;
            return;
        }
        assert(report.count < report.entries.len);
        report.entries[report.count] = .{
            .kind = collector.kind,
            .fate = .orphan,
            .digest = digest,
            .envelopes = 0,
            .bytes = 0,
        };
        report.count += 1;
        collector.taken += 1;
    }
};

fn collect(
    store: *const Store,
    report: *Report,
    kind: Kind,
    limit: u32,
    failure: *Failure,
) Error!void {
    var collector: Collector = .{ .report = report, .kind = kind, .limit = limit };
    var path: PathBuf = undefined;
    const name = switch (kind) {
        .signature => record_mod.directory_name,
        .provenance => provenance_store.directory_name,
    };
    const visitor: fs_mod.Visitor = .{ .context = &collector, .call = Collector.visit };
    store.fs.read_dir(store.directory_path(&path, name), visitor) catch |err| {
        if (err == error.NotFound) return;
        failure.* = Failure.make(.unreadable);
        failure.err = err;
        failure.errno = store.fs.last_errno();
        return error.Failed;
    };
}

fn path_of(store: *const Store, buffer: *PathBuf, entry: *const Entry) [:0]const u8 {
    return switch (entry.kind) {
        .signature => record_mod.record_path(store, buffer, entry.digest),
        .provenance => provenance_store.record_path(store, buffer, entry.digest),
    };
}

/// The size and line count of an orphan's file, as far as it reads (an unreadable orphan is
/// still an orphan, listed with zeros).
fn measure(store: *const Store, memory: *ScanMemory, entry: *Entry) void {
    var path: PathBuf = undefined;
    const bytes = store.fs.read_whole(path_of(store, &path, entry), &memory.file) catch return;
    entry.bytes = @intCast(bytes.len);
    const lines: u32 = @intCast(std.mem.count(u8, bytes, "\n"));
    entry.envelopes = if (entry.kind == .provenance) 1 else lines;
}

const Verdict = enum { orphan, present, damaged, gone };

const Committed = union(enum) { absent, unknown, tree: Digest };

fn tree_of_result(
    store: *const Store,
    memory: *ScanMemory,
    entry: *const Entry,
    failure: *Failure,
) Error!Committed {
    var errno: u16 = 0;
    result_mod.load(store, entry.digest, &memory.result, &memory.result_bytes, &errno) catch |err| {
        switch (err) {
            error.NotFound => return .absent,
            // A result record that does not read cannot say which tree it commits to, so its
            // provenance is kept: nothing is removed on a guess.
            error.Damaged, error.Newer => return .unknown,
            error.Unreadable => {
                failure.* = Failure.make(.unreadable);
                failure.errno = errno;
                return error.Failed;
            },
        }
    };
    return .{ .tree = memory.result.tree };
}

fn tree_has(store: *const Store, tree: Digest, failure: *Failure) Error!bool {
    return trees.has(store, tree) catch |err| {
        failure.* = Failure.make(.unreadable);
        failure.err = err;
        failure.errno = store.fs.last_errno();
        return error.Failed;
    };
}

fn judge(
    store: *const Store,
    memory: *ScanMemory,
    damage: ?*Damage,
    entry: *const Entry,
    failure: *Failure,
) Error!Verdict {
    var errno: u16 = 0;
    switch (entry.kind) {
        .signature => {
            if (!try tree_has(store, entry.digest, failure)) return .orphan;
            const found = damage orelse return .present;
            record_mod.load(store, &found.work, entry.digest, &found.record, &errno) catch |err| {
                switch (err) {
                    error.NotFound => return .gone,
                    error.Damaged => return .damaged,
                    // Newer is a record a later zbx wrote, not damage.
                    error.Newer => return .present,
                    error.Unreadable => {
                        failure.* = Failure.make(.unreadable);
                        failure.errno = errno;
                        return error.Failed;
                    },
                }
            };
            return .present;
        },
        .provenance => {
            switch (try tree_of_result(store, memory, entry, failure)) {
                .absent => return .orphan,
                .unknown => return .present,
                .tree => |tree| if (!try tree_has(store, tree, failure)) return .orphan,
            }
            const found = damage orelse return .present;
            _ = provenance_store.load(store, &found.provenance, entry.digest, &errno) catch |err| {
                switch (err) {
                    error.NotFound => return .gone,
                    error.Damaged => return .damaged,
                    error.Unreadable => {
                        failure.* = Failure.make(.unreadable);
                        failure.errno = errno;
                        return error.Failed;
                    },
                }
            };
            return .present;
        },
    }
}

/// Reads both directories and fills `report` with the orphans and, when `damage` is given, the
/// damaged records whose trees are present. The caller holds the store lock.
pub fn scan(
    store: *const Store,
    memory: *ScanMemory,
    damage: ?*Damage,
    report: *Report,
    failure: *Failure,
) Error!void {
    return scan_limited(store, memory, damage, report, constants.trust_records_max, failure);
}

/// `scan` reading at most `limit` names per directory, which a test lowers to reach the bound
/// without a store of `trust_records_max` files.
pub fn scan_limited(
    store: *const Store,
    memory: *ScanMemory,
    damage: ?*Damage,
    report: *Report,
    limit: u32,
    failure: *Failure,
) Error!void {
    assert(store.root_len > 1);
    assert(limit >= 1);
    assert(limit <= constants.trust_records_max);
    report.clear();
    try collect(store, report, .signature, limit, failure);
    try collect(store, report, .provenance, limit, failure);
    const listed = report.count;
    report.count = 0;
    for (0..listed) |index| {
        var entry = report.entries[index];
        const verdict = try judge(store, memory, damage, &entry, failure);
        switch (verdict) {
            .gone => continue,
            .present => {
                report.kept += 1;
                continue;
            },
            .orphan => {
                entry.fate = .orphan;
                report.orphans += 1;
            },
            .damaged => {
                entry.fate = .damaged;
                report.damaged += 1;
            },
        }
        measure(store, memory, &entry);
        // Compacting in place: the write index never passes the read index.
        assert(report.count <= index);
        report.entries[report.count] = entry;
        report.count += 1;
    }
    assert(report.orphans + report.damaged == report.count);
}

/// Removes the orphans `scan` found, one `unlink` each.
fn remove_orphans(store: *Store, report: *Report, failure: *Failure) Error!void {
    for (report.entries[0..report.count]) |*entry| {
        if (entry.fate != .orphan) continue;
        var path: PathBuf = undefined;
        store.fs.unlink(path_of(store, &path, entry)) catch |err| {
            if (err == error.NotFound) continue;
            failure.* = Failure.make(.write_failed);
            failure.err = err;
            failure.errno = store.fs.last_errno();
            return error.Failed;
        };
        report.removed += 1;
    }
}

/// `zbx trust prune`: the orphans in `report`, removed when `apply`. The lock is held from the
/// presence checks to the last unlink (exclusive to remove, shared to list).
pub fn prune_records(
    store: *Store,
    memory: *PruneMemory,
    apply: bool,
    report: *Report,
    failure: *Failure,
) Error!void {
    assert(store.root_len > 1);
    try hold(store, if (apply) .exclusive else .shared, "trust prune", failure);
    defer lock.release(store);
    try scan(store, &memory.scan, &memory.damage, report, failure);
    if (apply) try remove_orphans(store, report, failure);
    assert(report.removed <= report.orphans);
}

/// How many orphans there are, for gc's report. Takes the shared lock itself.
pub fn count_orphans(
    store: *Store,
    memory: *ScanMemory,
    report: *Report,
    failure: *Failure,
) Error!u32 {
    assert(store.root_len > 1);
    try hold(store, .shared, "gc", failure);
    defer lock.release(store);
    try scan(store, memory, null, report, failure);
    return report.orphans;
}

comptime {
    assert(constants.trust_prune_entries_max == 2 * constants.trust_records_max);
}
