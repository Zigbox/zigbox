//! The `zbx store` commands: `import`, `ls`, `du` and `rm`. Each parses its digest in the parent
//! (a usage error needs no namespace), then runs in the store's child (`store/namespace.zig`):
//! the child opens the store, does the work, writes the result to stdout (text, or one JSON
//! object with `--output json`; the schemas are `schemas.zig`) and any diagnostic to stderr, and
//! its exit code is the command's. Nothing prompts.
//!
//! Warnings (a device node left out, an attribute left out, the one-id map) are written to
//! stderr as they happen, in the format the command line asked for.

const std = @import("std");
const assert = std.debug.assert;
const commands = @import("commands.zig");
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const host_mod = @import("host.zig");
const Diag = @import("diag/diag.zig").Diag;
const errors = @import("diag/errors.zig");
const render = @import("diag/render.zig");
const text_util = @import("text.zig");
const diagnose = @import("store/diagnose.zig");
const digest_mod = @import("store/digest.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const namespace = @import("store/namespace.zig");
const open = @import("store/open.zig");
const roots = @import("store/roots.zig");
const trees = @import("store/trees.zig");
const usage = @import("store/usage.zig");

const Digest = digest_mod.Digest;
const Host = host_mod.Host;
const Store = layout.Store;

pub const Error = error{Failed};

pub const Action = enum { import, ls, du, rm };

pub const Args = struct {
    action: Action,
    /// The directory (`import`), or a digest or prefix (`du`, `rm`).
    operand: ?[]const u8,
};

/// How results and diagnostics are written.
pub const Output = struct {
    mode: render.Mode,
    color: bool,
    json: bool,
};

/// The caller's memory, about 21 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    import: import.Workspace,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    root_list: [constants.store_roots_max]roots.Root,
};

const Job = struct {
    host: Host,
    args: Args,
    output: Output,
    workspace: *Workspace,
};

/// Runs a store command. The result is the exit code; `diag` holds a failure of the parent's
/// own (a usage error, or a worker that could not start). The child's failures are already on
/// stderr, and are its exit code.
pub fn run(
    host: Host,
    args: Args,
    output: Output,
    facts: *doctor.Facts,
    workspace: *Workspace,
    diag: *Diag,
) Error!u8 {
    assert(diag.code == null);
    switch (args.action) {
        .import, .rm => assert(args.operand != null),
        .ls => assert(args.operand == null),
        .du => {},
    }
    if (args.action == .du or args.action == .rm) {
        if (args.operand) |text| {
            if (digest_mod.Prefix.parse(text) == null) {
                diagnose.bad_digest(diag, text);
                return error.Failed;
            }
        }
    }
    // Without a data directory there is nothing to do, and no reason to make a namespace first.
    var probe: Store = undefined;
    if (!probe.locate(host)) {
        diagnose.no_data_directory(diag);
        return error.Failed;
    }
    var job: Job = .{ .host = host, .args = args, .output = output, .workspace = workspace };
    var reporter: Reporter = .{ .host = host, .output = output };
    const work: namespace.Work = .{ .context = &job, .call = work_call };
    // The id map decides what an import records; the other commands only read, so a one-id map
    // is no news to them.
    const warn: namespace.Warn = .{ .context = &reporter, .call = report_warning };
    const sink: ?namespace.Warn = if (args.action == .import) warn else null;
    return namespace.run(host, facts, work, sink, diag) catch return error.Failed;
}

const Reporter = struct {
    host: Host,
    output: Output,
};

fn report_warning(context: *anyopaque, diag: *const Diag) void {
    assert(@intFromPtr(context) != 0);
    const reporter: *const Reporter = @ptrCast(@alignCast(context));
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, reporter.output.mode, reporter.output.color, &buffer);
    // A warning that cannot be written is lost, and the command goes on: it is only a warning.
    reporter.host.write_all(.stderr, text) catch return;
}

// ---- In the child --------------------------------------------------------------------------

fn work_call(context: *anyopaque, squash_owner: bool) u8 {
    assert(@intFromPtr(context) != 0);
    const job: *Job = @ptrCast(@alignCast(context));
    assert(@intFromPtr(job.workspace) != 0);
    var diag: Diag = undefined;
    diag.reset();
    execute(job, squash_owner, &diag) catch {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a store command failed with no diagnostic", .{});
        }
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&diag, job.output.mode, job.output.color, &buffer);
        job.host.write_all(.stderr, text) catch return constants.exit_environment;
        return diag.exit_code();
    };
    return constants.exit_ok;
}

fn execute(job: *Job, squash_owner: bool, diag: *Diag) Error!void {
    if (job.args.action == .ls) assert(job.args.operand == null);
    assert(diag.code == null);
    switch (job.args.action) {
        .import => try do_import(job, squash_owner, diag),
        .ls => try do_ls(job, diag),
        .du => try do_du(job, diag),
        .rm => try do_rm(job, diag),
    }
}

/// Writes to stdout; a failure is ZBX-E0009.
fn put(job: *const Job, text: []const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(text.len <= constants.output_bytes_max);
    if (text.len == 0) return;
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn json_string(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    assert(text.len <= constants.file_bytes_max);
    assert(writer.buffer.len > 0);
    return @import("bundle.zig").write_json_string(writer, text);
}

fn open_store(job: *const Job, store: *Store, mode: open.Mode, diag: *Diag) Error!bool {
    assert(diag.code == null);
    assert(@intFromPtr(store) != 0);
    return open.open(job.host, store, mode, diag) catch error.Failed;
}

// ---- import --------------------------------------------------------------------------------

fn do_import(job: *Job, squash_owner: bool, diag: *Diag) Error!void {
    assert(job.args.action == .import);
    assert(job.args.operand != null);
    var store: Store = undefined;
    _ = try open_store(job, &store, .create, diag);
    var reporter: Reporter = .{ .host = job.host, .output = job.output };
    const options: import.Options = .{
        .squash_owner = squash_owner,
        .warn = .{ .context = &reporter, .call = report_warning },
    };
    var result: import.Result = undefined;
    const source = job.args.operand.?;
    import.import(&store, &job.workspace.import, source, options, &result, diag) catch {
        return error.Failed;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try put(job, import_text(job, source, squash_owner, &result, &buffer), diag);
}

fn import_text(
    job: *const Job,
    source: []const u8,
    squash_owner: bool,
    result: *const import.Result,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    assert(source.len > 0);
    assert(result.directories > 0);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: a digest line, or a JSON object of a few hundred bytes plus the source cut
    // to its bound, fits the 16 KiB buffer.
    if (!job.output.json) {
        writer.print("{s}\n", .{result.digest.text()}) catch unreachable; // Same bound.
        return writer.buffered();
    }
    writer.print("{{\"schema\":\"zbx.store.import/1\",\"digest\":\"{s}\",\"source\":", .{
        result.digest.text(),
    }) catch unreachable; // Same bound.
    json_string(&writer, source[0..@min(source.len, constants.store_source_bytes_max)]) catch
        unreachable; // Same bound.
    writer.print(",\"files\":{d},\"directories\":{d},\"symlinks\":{d},\"skipped\":{d}," ++
        "\"xattrs_skipped\":{d},\"bytes\":{d},\"new_objects\":{d},\"reused_objects\":{d}," ++
        "\"new_bytes\":{d},\"new_trees\":{d},\"reused_trees\":{d},\"ids\":\"{s}\"}}\n", .{
        result.files,
        result.directories,
        result.symlinks,
        result.skipped,
        result.xattrs_skipped,
        result.bytes,
        result.objects_new,
        result.objects_reused,
        result.bytes_new,
        result.trees_new,
        result.trees_reused,
        if (squash_owner) "single" else "full",
    }) catch unreachable; // Same bound.
    return writer.buffered();
}

// ---- ls ------------------------------------------------------------------------------------

fn do_ls(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .ls);
    assert(diag.code == null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    const ws = &job.workspace.import;
    var listing: roots.Listing = .{ .count = 0, .skipped = 0, .truncated = false };
    if (exists) {
        listing = roots.list(&store, &ws.arena, &job.workspace.root_list) catch |err| {
            diagnose.cannot_read(diag, &store, "listing the roots", err, store.fs.last_errno());
            return error.Failed;
        };
    }
    const found = job.workspace.root_list[0..listing.count];
    if (job.output.json) return ls_json(job, found, diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const head = std.fmt.bufPrint(&buffer, "{s: <67} {s: <9} {s: >7} {s: >11}  {s: <19}  {s}\n", .{
        "DIGEST", "KIND", "FILES", "SIZE", "TIME", "SOURCE",
    }) catch unreachable; // A short fixed line.
    try put(job, head, diag);
    for (found) |*root| try put(job, ls_row(root, &buffer), diag);
}

fn ls_row(root: *const roots.Root, buffer: *[constants.output_bytes_max]u8) []const u8 {
    assert(root.source_len <= constants.store_source_bytes_max);
    assert(buffer.len == constants.output_bytes_max);
    var size: [32]u8 = undefined;
    var when: [19]u8 = undefined;
    // The source is the user's own text, but a path can hold anything: no byte reaches the
    // terminal that is not printable.
    var safe: [constants.store_source_bytes_max]u8 = undefined;
    const source = text_util.sanitise(&safe, root.source_text());
    // Cannot fail: the fixed columns are under 200 bytes and the source is at most 1024.
    return std.fmt.bufPrint(buffer, "{s} {s: <9} {d: >7} {s: >11}  {s}  {s}\n", .{
        root.digest.text(),
        root.kind.word(),
        root.files,
        size_words(&size, root.bytes),
        commands.clock_text(root.time, &when),
        source,
    }) catch unreachable; // Same bound.
}

fn ls_json(job: *const Job, found: []const roots.Root, diag: *Diag) Error!void {
    assert(found.len <= constants.store_roots_max);
    assert(diag.code == null);
    try put(job, "{\"schema\":\"zbx.store.ls/1\",\"roots\":[", diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    for (found, 0..) |*root, index| {
        var writer = std.Io.Writer.fixed(&buffer);
        // Cannot fail: one root's object is under 5 KiB (the source escaped is the bulk).
        if (index > 0) writer.writeByte(',') catch unreachable; // Same bound.
        writer.print("{{\"digest\":\"{s}\",\"kind\":\"{s}\",\"time\":{d},\"files\":{d}," ++
            "\"bytes\":{d},\"source\":", .{
            root.digest.text(), root.kind.word(), root.time, root.files, root.bytes,
        }) catch unreachable; // Same bound.
        json_string(&writer, root.source_text()) catch unreachable; // Same bound.
        if (root.parent) |parent| {
            writer.print(",\"parent\":\"{s}\"}}", .{parent.text()}) catch unreachable; // Same.
        } else {
            writer.writeAll(",\"parent\":null}") catch unreachable; // Same bound.
        }
        try put(job, writer.buffered(), diag);
    }
    try put(job, "]}\n", diag);
}

/// "7.8 MiB" for a byte count; bytes below 1 KiB are shown as they are.
pub fn size_words(buffer: *[32]u8, bytes: u64) []const u8 {
    assert(buffer.len == 32);
    assert(bytes < 1 << 63);
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var scaled: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    while (scaled >= 1024 and unit + 1 < units.len) : (unit += 1) scaled /= 1024;
    // Cannot fail: a number of at most 20 digits and a unit fit 32 bytes.
    if (unit == 0) return std.fmt.bufPrint(buffer, "{d} B", .{bytes}) catch unreachable; // Same.
    return std.fmt.bufPrint(buffer, "{d:.1} {s}", .{ scaled, units[unit] }) catch
        unreachable; // Same.
}

// ---- du ------------------------------------------------------------------------------------

fn do_du(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .du);
    assert(diag.code == null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    if (job.args.operand) |text| {
        const digest = try resolve(&store, exists, text, diag);
        return du_tree(job, &store, digest, diag);
    }
    var total: usage.Total = .{ .bytes = 0, .objects = 0, .trees = 0 };
    var failure: usage.Failure = undefined;
    if (exists) {
        usage.store_total(&store, &job.workspace.import.arena, &total, &failure) catch {
            return usage_failed(&store, &failure, diag);
        };
    }
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var size: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: two short lines or one short object.
    if (job.output.json) {
        writer.print("{{\"schema\":\"zbx.store.du/1\",\"store\":{{\"bytes\":{d},\"objects\":{d}," ++
            "\"trees\":{d}}}}}\n", .{ total.bytes, total.objects, total.trees }) catch
            unreachable; // Same.
    } else {
        writer.print("{s}  {d} objects, {d} trees\n", .{
            size_words(&size, total.bytes), total.objects, total.trees,
        }) catch unreachable; // Same bound.
    }
    try put(job, writer.buffered(), diag);
}

fn du_tree(job: *Job, store: *const Store, digest: Digest, diag: *Diag) Error!void {
    assert(job.args.action == .du);
    assert(job.workspace.tree_buffer.len >= constants.store_tree_bytes_max);
    const ws = &job.workspace.import;
    const half = ws.arena.len / 2;
    const quarter = ws.arena.len / 4;
    var memory: usage.Memory = .{
        .tree_buffer = &job.workspace.tree_buffer,
        .objects = @alignCast(ws.arena[0..half]),
        .visited = @alignCast(ws.arena[half .. half + quarter]),
        .stack = std.mem.bytesAsSlice(Digest, ws.arena[half + quarter ..]),
        .root_list = &job.workspace.root_list,
        .names = &ws.io,
    };
    var result: usage.TreeUsage = undefined;
    var failure: usage.Failure = undefined;
    usage.tree_usage(store, &memory, digest, &result, &failure) catch {
        return usage_failed(store, &failure, diag);
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var sizes: [3][32]u8 = undefined;
    // Cannot fail: a few short lines or one short object.
    if (job.output.json) {
        const format = "{{\"schema\":\"zbx.store.du/1\",\"tree\":{{\"digest\":\"{s}\"," ++
            "\"files\":{d},\"logical_bytes\":{d},\"objects\":{d},\"stored_bytes\":{d}," ++
            "\"shared_bytes\":{d}}}}}\n";
        writer.print(format, .{
            digest.text(),
            result.files,
            result.logical_bytes,
            result.objects,
            result.stored_bytes,
            result.shared_bytes,
        }) catch unreachable; // Same bound.
    } else {
        writer.print("{s}\n  files          {d}\n  logical size   {s}\n  stored size    {s}\n" ++
            "  shared         {s} (also in other roots)\n", .{
            digest.text(),
            result.files,
            size_words(&sizes[0], result.logical_bytes),
            size_words(&sizes[1], result.stored_bytes),
            size_words(&sizes[2], result.shared_bytes),
        }) catch unreachable; // Same bound.
    }
    try put(job, writer.buffered(), diag);
}

fn usage_failed(store: *const Store, failure: *const usage.Failure, diag: *Diag) Error {
    assert(diag.code == null);
    assert(store.root_len > 1);
    switch (failure.*) {
        .io => |io| diagnose.cannot_read(diag, store, io.step, io.err, io.errno),
        .too_many_names => diagnose.cannot_read(
            diag,
            store,
            "listing a shard",
            error.FileTooLarge,
            0,
        ),
        .table_full => diagnose.too_big(diag, .arena, store.root_text()),
        .tree => |walked| {
            const kind: []const u8 = switch (walked.kind) {
                .missing => "is missing from the store",
                .damaged => "does not hash to its name or does not decode",
                .unreadable => "cannot be read",
                .too_many_entries => "is part of a tree with more entries than a walk follows",
                .stack_full => "is below more directories than a walk keeps",
            };
            diagnose.tree_damaged(diag, walked.where, kind);
        },
    }
    return error.Failed;
}

// ---- rm ------------------------------------------------------------------------------------

/// The tree a digest or prefix names. A store that does not exist has none.
fn resolve(store: *const Store, exists: bool, text: []const u8, diag: *Diag) Error!Digest {
    assert(text.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const prefix = digest_mod.Prefix.parse(text) orelse {
        diagnose.bad_digest(diag, text);
        return error.Failed;
    };
    if (!exists) {
        diagnose.unknown_digest(diag, text);
        return error.Failed;
    }
    const found = trees.find(store, &prefix) catch |err| {
        diagnose.cannot_read(diag, store, "looking for a tree", err, store.fs.last_errno());
        return error.Failed;
    };
    switch (found) {
        .one => |digest| return digest,
        .none => diagnose.unknown_digest(diag, text),
        .many => |two| diagnose.ambiguous_digest(diag, text, two[0], two[1]),
    }
    return error.Failed;
}

fn do_rm(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .rm);
    assert(job.args.operand != null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    const digest = try resolve(&store, exists, job.args.operand.?, diag);
    var root: roots.Root = undefined;
    var errno: u16 = 0;
    roots.load(&store, digest, &root, &errno) catch |err| switch (err) {
        error.NotFound => {
            diagnose.not_a_root(diag, digest);
            return error.Failed;
        },
        else => {
            const damaged = err != error.Unreadable;
            const kind: host_mod.Error = if (damaged) error.FileTooLarge else error.IoFailed;
            diagnose.cannot_read(diag, &store, "reading the root record", kind, errno);
            return error.Failed;
        },
    };
    roots.remove(&store, digest) catch |err| {
        diagnose.write_failed(diag, &store, "removing the root record", err, store.fs.last_errno());
        return error.Failed;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = if (job.output.json)
        std.fmt.bufPrint(
            &buffer,
            "{{\"schema\":\"zbx.store.rm/1\",\"digest\":\"{s}\",\"removed\":true}}\n",
            .{digest.text()},
        )
    else
        std.fmt.bufPrint(&buffer, "removed {s}\n", .{digest.text()});
    // Cannot fail: one short line.
    try put(job, text catch unreachable, diag); // Same bound.
}
