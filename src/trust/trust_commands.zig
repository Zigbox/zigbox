//! `zbx trust export`, `import` and `prune` (M8): a tree's signatures leave the store as a
//! bundle (its signature record, as it is stored), come in from a bundle, and records whose trees
//! are gone are listed and removed (docs/briefs/M8-trust.md, "Trust peers").
//!
//!   zbx trust export <tree>     the tree's bundle on stdout
//!   zbx trust import <file>     verifies every line, then adds what the store does not have
//!   zbx trust prune [--apply]   lists the orphans; removes them with `--apply`
//!
//! The work is in `peer.zig`; this module reads the file, takes the output apart and says what
//! happened. None of it needs the tree itself, so none of it needs the store's user namespace.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const render = @import("../diag/render.zig");
const errors = @import("../diag/errors.zig");
const open = @import("../store/open.zig");
const store_diagnose = @import("../store/diagnose.zig");
const lock = @import("../store/lock.zig");
const diagnose = @import("diagnose.zig");
const peer = @import("peer.zig");
const provenance_store = @import("provenance_store.zig");
const record_mod = @import("record.zig");

const Digest = @import("../store/digest.zig").Digest;
const PathBuf = @import("../store/fs.zig").PathBuf;
const Host = host_mod.Host;
const Store = @import("../store/layout.zig").Store;

pub const Error = error{Failed};

pub const Action = enum { @"export", import, prune };

pub const Args = struct {
    action: Action,
    /// `export`'s tree, `import`'s file; null for `prune`.
    operand: ?[]const u8 = null,
    /// `prune` removes what it lists.
    apply: bool = false,
};

pub const Output = struct {
    json: bool,
    mode: render.Mode = .text,
    color: bool = false,
};

/// The caller's memory, tens of MiB: keep it off the stack.
pub const Workspace = struct {
    /// Export and import.
    memory: peer.Memory,
    /// The bundle `import` reads.
    file: [constants.signature_record_bytes_max + 1]u8,
    /// Prune.
    prune: peer.PruneMemory,
    report: peer.Report,
};

const Job = struct {
    host: Host,
    ws: *Workspace,
    args: Args,
    output: Output,
    store: Store,
    diag: *Diag,
};

pub fn run(host: Host, ws: *Workspace, args: Args, output: Output, diag: *Diag) Error!u8 {
    assert(diag.code == null);
    assert((args.operand != null) == (args.action != .prune));
    if (args.apply) assert(args.action == .prune);
    if (args.action != .prune) assert(!args.apply);
    var job: Job = .{
        .host = host,
        .ws = ws,
        .args = args,
        .output = output,
        .store = undefined,
        .diag = diag,
    };
    if (!job.store.locate(host)) {
        store_diagnose.no_data_directory(diag);
        return error.Failed;
    }
    // An import into a store that is not there yet makes it; the others only read what exists.
    const mode: open.Mode = if (args.action == .import) .create else .existing;
    const present = open.check(&job.store, mode, diag) catch return error.Failed;
    switch (args.action) {
        .@"export" => try run_export(&job, present),
        .import => try run_import(&job),
        .prune => try run_prune(&job, present),
    }
    return 0;
}

// ---- What went wrong ----

/// Raises the diagnostic for a refused peer operation.
fn refused(job: *Job, failure: *const peer.Failure, what: []const u8, tree: ?Digest) Error {
    assert(what.len > 0);
    const diag = job.diag;
    switch (failure.refusal) {
        .no_record, .too_large, .malformed, .newer, .tree_full, .store_full => {
            diagnose.trust_refused(diag, failure, what);
        },
        .busy => store_diagnose.store_busy(diag, what, lock.holder(&job.store)),
        .store_failed => store_diagnose.write_failed(
            diag,
            &job.store,
            "taking the store lock",
            failure.err,
            failure.errno,
        ),
        .write_failed => store_diagnose.write_failed(
            diag,
            &job.store,
            what,
            failure.err,
            failure.errno,
        ),
        .unreadable => store_diagnose.cannot_read(
            diag,
            &job.store,
            what,
            error.IoFailed,
            failure.errno,
        ),
        .local_unusable => {
            var path: PathBuf = undefined;
            const text = record_mod.record_path(&job.store, &path, tree.?);
            diagnose.record_unusable(diag, text, if (failure.newer) .newer else .damaged);
        },
    }
    return error.Failed;
}

fn put(job: *const Job, text: []const u8) Error!void {
    assert(text.len <= constants.output_bytes_max);
    assert(job.diag.code == null);
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(job.diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

/// A warning, on stderr; it does not end the command.
fn warn(job: *Job, diag: *const Diag) Error!void {
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, job.output.mode, job.output.color, &buffer);
    job.host.write_all(.stderr, text) catch |err| {
        errors.output_failed(job.diag, .stderr, err, job.host.last_errno());
        return error.Failed;
    };
}

// ---- export ----

fn run_export(job: *Job, present: bool) Error!void {
    const operand = job.args.operand.?;
    const tree = Digest.parse(operand) orelse {
        store_diagnose.bad_digest(job.diag, operand);
        return error.Failed;
    };
    var failure: peer.Failure = undefined;
    if (!present) {
        failure = .{ .refusal = .no_record, .size = 0, .err = error.IoFailed, .errno = 0 };
        return refused(job, &failure, "exporting the signatures of a tree", tree);
    }
    const bundle = peer.export_record(&job.store, &job.ws.memory, tree, &failure) catch {
        return refused(job, &failure, "exporting the signatures of a tree", tree);
    };
    assert(bundle.len > 0);
    assert(bundle[bundle.len - 1] == '\n');
    // The bundle is the output in both modes: it is already lines of JSON.
    try put(job, bundle);
}

// ---- import ----

fn run_import(job: *Job) Error!void {
    const operand = job.args.operand.?;
    const ws = job.ws;
    var failure: peer.Failure = undefined;
    const text = try read_bundle(job, operand);
    const tree = peer.bundle_tree(&ws.memory.work, text) catch |err| {
        failure = .{
            .refusal = if (err == error.Newer) .newer else .malformed,
            .size = 0,
            .err = error.IoFailed,
            .errno = 0,
        };
        return refused(job, &failure, "importing a bundle of signatures", null);
    };
    const imported = peer.import_record(&job.store, &ws.memory, text, tree, &failure) catch {
        return refused(job, &failure, "importing a bundle of signatures", tree);
    };
    try put_imported(job, tree, imported);
}

/// The bundle file's bytes, in the workspace. A name that is not absolute is the working
/// directory's.
fn read_bundle(job: *Job, operand: []const u8) Error![]const u8 {
    assert(operand.len > 0);
    var cwd: [constants.store_path_bytes_max]u8 = undefined;
    var path: PathBuf = undefined;
    const set = if (operand[0] == '/') path.set(&.{operand}) else blk: {
        const base = job.host.working_directory(&cwd) catch |err| {
            return source_unreadable(job, operand, err, job.host.last_errno());
        };
        break :blk path.set(&.{ base, "/", operand });
    };
    set catch return source_unreadable(job, operand, error.PathTooLong, 0);
    const bytes = job.store.fs.read_whole(path.text(), &job.ws.file) catch |err| {
        if (err == error.FileTooLarge) {
            var failure: peer.Failure = .{
                .refusal = .too_large,
                .size = constants.signature_record_bytes_max + 1,
                .err = error.IoFailed,
                .errno = 0,
            };
            return refused(job, &failure, "importing a bundle of signatures", null);
        }
        return source_unreadable(job, operand, err, job.store.fs.last_errno());
    };
    return bytes;
}

fn source_unreadable(job: *Job, operand: []const u8, err: host_mod.Error, errno: u16) Error {
    diagnose.bundle_unreadable(job.diag, operand, err, errno);
    return error.Failed;
}

fn put_imported(job: *const Job, tree: Digest, imported: peer.Imported) Error!void {
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const text = tree.text();
    // Cannot fail: a few short lines fit the buffer.
    if (job.output.json) {
        writer.print(
            "{{\"schema\":\"zbx.trust/1\",\"action\":\"import\",\"tree\":\"{s}\"," ++
                "\"added\":{d},\"present\":{d},\"total\":{d}}}\n",
            .{ &text, imported.added, imported.present, imported.total },
        ) catch unreachable; // The line is far shorter than the buffer.
    } else {
        writer.print(
            "imported {s}: {d} new signature(s), {d} already there; the tree has {d}\n",
            .{ &text, imported.added, imported.present, imported.total },
        ) catch unreachable; // Same bound.
    }
    try put(job, writer.buffered());
}

// ---- prune ----

fn run_prune(job: *Job, present: bool) Error!void {
    const ws = job.ws;
    ws.report.clear();
    var failure: peer.Failure = undefined;
    if (present) {
        peer.prune_records(&job.store, &ws.prune, job.args.apply, &ws.report, &failure) catch {
            return refused(job, &failure, "pruning the trust records", null);
        };
    }
    try warn_damaged(job);
    try put_pruned(job);
}

/// W0902 for every damaged record that was kept, up to a few; a count says the rest.
fn warn_damaged(job: *Job) Error!void {
    var shown: u32 = 0;
    for (job.ws.report.list()) |entry| {
        if (entry.fate != .damaged) continue;
        if (shown == damaged_shown_max) break;
        var path: PathBuf = undefined;
        const text = switch (entry.kind) {
            .signature => record_mod.record_path(&job.store, &path, entry.digest),
            .provenance => provenance_store.record_path(&job.store, &path, entry.digest),
        };
        var diag: Diag = undefined;
        diag.reset();
        diagnose.prune_kept_damaged(&diag, text);
        try warn(job, &diag);
        shown += 1;
    }
    assert(shown <= damaged_shown_max);
}

const damaged_shown_max: u32 = 8;

fn kind_word(kind: peer.Kind) []const u8 {
    assert(@tagName(kind).len > 0);
    assert(@backingInt(kind) <= 1);
    return switch (kind) {
        .signature => "signature",
        .provenance => "provenance",
    };
}

fn fate_word(fate: peer.Fate) []const u8 {
    assert(@tagName(fate).len > 0);
    assert(@backingInt(fate) <= 1);
    return switch (fate) {
        .orphan => "orphan",
        .damaged => "damaged",
    };
}

fn put_pruned(job: *const Job) Error!void {
    const report = &job.ws.report;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const wrote = if (job.output.json)
        write_pruned_json(report, job.args.apply, &writer)
    else
        write_pruned_text(report, job.args.apply, &writer);
    wrote catch {
        // The entries are more than one buffer holds: say how many and stop there.
        return put_pruned_short(job);
    };
    try put(job, writer.buffered());
}

/// The summary alone, when the entries do not fit one output buffer.
fn put_pruned_short(job: *const Job) Error!void {
    const report = &job.ws.report;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    write_summary(report, job.args.apply, job.output.json, &writer) catch unreachable; // Short.
    try put(job, writer.buffered());
}

fn write_summary(
    report: *const peer.Report,
    apply: bool,
    as_json: bool,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    if (as_json) {
        try writer.print(
            "{{\"schema\":\"zbx.trust-prune/1\",\"dry_run\":{},\"orphans\":{d},\"damaged\":{d}," ++
                "\"removed\":{d},\"truncated\":{},\"entries\":[]}}\n",
            .{ !apply, report.orphans, report.damaged, report.removed, report.truncated },
        );
        return;
    }
    try writer.print(
        "{d} orphan record(s), {d} damaged and kept",
        .{ report.orphans, report.damaged },
    );
    if (apply) try writer.print("; removed {d}", .{report.removed});
    try writer.writeAll("\n");
    if (!apply and report.orphans > 0) {
        try writer.writeAll("run 'zbx trust prune --apply' to remove them; to keep a record " ++
            "outside the store first, run 'zbx trust export <tree>'\n");
    }
}

fn write_pruned_text(
    report: *const peer.Report,
    apply: bool,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    for (report.list()) |entry| {
        const text = entry.digest.text();
        try writer.print("{s} {s} {s} ({d} line(s), {d} bytes)\n", .{
            fate_word(entry.fate), kind_word(entry.kind), &text, entry.envelopes, entry.bytes,
        });
    }
    if (report.truncated) try writer.writeAll("more records than listed here; run it again\n");
    try write_summary(report, apply, false, writer);
}

fn write_pruned_json(
    report: *const peer.Report,
    apply: bool,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    try writer.print(
        "{{\"schema\":\"zbx.trust-prune/1\",\"dry_run\":{},\"orphans\":{d},\"damaged\":{d}," ++
            "\"removed\":{d},\"truncated\":{},\"entries\":[",
        .{ !apply, report.orphans, report.damaged, report.removed, report.truncated },
    );
    for (report.list(), 0..) |entry, at| {
        const text = entry.digest.text();
        try writer.print(
            "{s}{{\"kind\":\"{s}\",\"fate\":\"{s}\",\"digest\":\"{s}\"," ++
                "\"lines\":{d},\"bytes\":{d}}}",
            .{
                if (at == 0) "" else ",", kind_word(entry.kind), fate_word(entry.fate),
                &text,                    entry.envelopes,       entry.bytes,
            },
        );
    }
    try writer.writeAll("]}\n");
}
