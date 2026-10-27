//! The `zbx store` commands: `import`, `ls`, `du`, `rm` and `diff`, and `zbx commit`, which is
//! store work too. Each parses its digest in the parent
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
const diff = @import("store/diff.zig");
const generation = @import("store/generation.zig");
const import = @import("store/import.zig");
const lifecycle = @import("runtime/lifecycle.zig");
const records = @import("runtime/records.zig");
const runtime_diagnose = @import("runtime/diagnose.zig");
const spec = @import("runtime/spec.zig");
const layout = @import("store/layout.zig");
const namespace = @import("store/namespace.zig");
const open = @import("store/open.zig");
const roots = @import("store/roots.zig");
const tree = @import("store/tree.zig");
const trees = @import("store/trees.zig");
const usage = @import("store/usage.zig");
const verify = @import("store/verify.zig");
const gc = @import("store/gc.zig");

const Digest = digest_mod.Digest;
const Host = host_mod.Host;
const Store = layout.Store;

pub const Error = error{Failed};

pub const Action = enum { import, ls, du, rm, diff, commit, verify, gc, restore };

pub const Args = struct {
    action: Action,
    /// The directory (`import`), a digest or prefix (`du`, `rm`, `diff`), or the container's
    /// name (`commit`).
    operand: ?[]const u8,
    /// `diff`: the second digest or prefix.
    second: ?[]const u8 = null,
    /// `gc --confirm`: the plan hash to act on. Without it `gc` only plans.
    confirm: ?[]const u8 = null,
    /// `gc --trash`: list the trash instead of planning.
    trash: bool = false,
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
    diff: diff.Workspace,
    /// `commit`: the container's record, read before the child starts.
    record: records.Parsed,
    verify: verify.Workspace,
    gc: gc.Workspace,
    /// `gc`: the trees the running containers use, read before the child starts.
    live: [constants.store_roots_max]Digest,
    live_count: u32,
    trash: [constants.store_trash_entries_max]gc.TrashEntry,
};

const Job = struct {
    host: Host,
    args: Args,
    output: Output,
    workspace: *Workspace,
    /// `commit`: the tree the container started from.
    parent: Digest,
    /// `gc --confirm`: the plan hash.
    confirm: Digest,
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
        .import, .rm, .commit, .restore => assert(args.operand != null),
        .ls, .verify, .gc => assert(args.operand == null),
        .diff => {
            assert(args.operand != null);
            assert(args.second != null);
        },
        .du => {},
    }
    assert((args.second != null) == (args.action == .diff));
    const digests = [2]?[]const u8{ args.operand, args.second };
    if (args.action == .du or args.action == .rm or args.action == .diff) {
        for (digests) |maybe| {
            const text = maybe orelse continue;
            if (digest_mod.Prefix.parse(text) == null) {
                diagnose.bad_digest(diag, text);
                return error.Failed;
            }
        }
    }
    var parent = tree.zero_digest;
    if (args.action == .commit) parent = try prepare_commit(host, args.operand.?, workspace, diag);
    var confirm = tree.zero_digest;
    if (args.action == .gc) confirm = try prepare_gc(host, args, workspace, diag);
    if (args.action == .restore and !gc.is_id(args.operand.?)) {
        diagnose.no_such_trash(diag, args.operand.?);
        return error.Failed;
    }
    // Without a data directory there is nothing to do, and no reason to make a namespace first.
    var probe: Store = undefined;
    if (!probe.locate(host)) {
        diagnose.no_data_directory(diag);
        return error.Failed;
    }
    var job: Job = .{
        .host = host,
        .args = args,
        .output = output,
        .workspace = workspace,
        .parent = parent,
        .confirm = confirm,
    };
    var reporter: Reporter = .{ .host = host, .output = output };
    const work: namespace.Work = .{ .context = &job, .call = work_call };
    // The id map decides what an import records; the other commands only read, so a one-id map
    // is no news to them.
    const warn: namespace.Warn = .{ .context = &reporter, .call = report_warning };
    const shows_warnings = args.action == .import or args.action == .commit;
    const sink: ?namespace.Warn = if (shows_warnings) warn else null;
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
        .diff => try do_diff(job, diag),
        .commit => try do_commit(job, squash_owner, diag),
        .verify => try do_verify(job, diag),
        .gc => try do_gc(job, diag),
        .restore => try do_restore(job, diag),
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
        "\"xattrs_skipped\":{d},\"unmapped_owners\":{d},\"unmapped_groups\":{d}," ++
        "\"bytes\":{d},\"new_objects\":{d},\"reused_objects\":{d}," ++
        "\"new_bytes\":{d},\"new_trees\":{d},\"reused_trees\":{d},\"ids\":\"{s}\"}}\n", .{
        result.files,
        result.directories,
        result.symlinks,
        result.skipped,
        result.xattrs_skipped,
        result.unmapped_uids,
        result.unmapped_gids,
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

/// The memory a tree's usage is counted in: the import workspace's arena, which no other
/// command is using at the time.
fn usage_memory(job: *Job) usage.Memory {
    assert(job.workspace.tree_buffer.len >= constants.store_tree_bytes_max);
    const ws = &job.workspace.import;
    const half = ws.arena.len / 2;
    const quarter = ws.arena.len / 4;
    return .{
        .tree_buffer = &job.workspace.tree_buffer,
        .objects = @alignCast(ws.arena[0..half]),
        .visited = @alignCast(ws.arena[half .. half + quarter]),
        .stack = std.mem.bytesAsSlice(Digest, ws.arena[half + quarter ..]),
        .root_list = &job.workspace.root_list,
        .names = &ws.io,
    };
}

fn du_tree(job: *Job, store: *const Store, digest: Digest, diag: *Diag) Error!void {
    assert(job.args.action == .du);
    assert(job.workspace.tree_buffer.len >= constants.store_tree_bytes_max);
    var memory = usage_memory(job);
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
    var raised: object_failure = undefined;
    generation.bump(&store, &raised) catch {
        diagnose.write_failed(diag, &store, "raising the generation", raised.err, raised.errno);
        return error.Failed;
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

// ---- commit --------------------------------------------------------------------------------

/// In the parent, before the namespace: the container's record says what it started from, and
/// whether it is still running. Returns the tree it started from; the record is in the workspace.
fn prepare_commit(host: Host, name: []const u8, ws: *Workspace, diag: *Diag) Error!Digest {
    assert(diag.code == null);
    assert(name.len <= constants.arg_bytes_max);
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) {
        runtime_diagnose.no_such_container(diag, name, .no_state);
        return error.Failed;
    }
    const record = &ws.record;
    records.load(host, &dir, name, record) catch |err| {
        const why: runtime_diagnose.NoContainer = switch (err) {
            error.NotFound => .no_record,
            else => .unreadable_record,
        };
        runtime_diagnose.no_such_container(diag, name, why);
        return error.Failed;
    };
    if (lifecycle.state_of(host, record) == .running) {
        diagnose.container_running(diag, name);
        return error.Failed;
    }
    if (record.tree_len == 0) {
        diagnose.no_layer(diag, name, .directory);
        return error.Failed;
    }
    if (record.upper_len == 0) {
        diagnose.no_layer(diag, name, .read_only);
        return error.Failed;
    }
    return Digest.parse(record.tree_slice()) orelse {
        runtime_diagnose.no_such_container(diag, name, .unreadable_record);
        return error.Failed;
    };
}

fn do_commit(job: *Job, squash_owner: bool, diag: *Diag) Error!void {
    assert(job.args.action == .commit);
    assert(diag.code == null);
    const name = job.args.operand.?;
    const record = &job.workspace.record;
    var upper: [constants.containers_path_bytes_max + 1]u8 = undefined;
    @memcpy(upper[0..record.upper_len], record.upper_slice());
    upper[record.upper_len] = 0;
    const upper_path = upper[0..record.upper_len :0];
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    if (!exists) {
        const text = job.parent.text();
        diagnose.unknown_digest(diag, &text);
        return error.Failed;
    }
    _ = store.fs.lstat(upper_path) catch |err| {
        if (err != error.NotFound) {
            const errno = store.fs.last_errno();
            diagnose.cannot_read(diag, &store, "looking for the upper layer", err, errno);
        } else {
            diagnose.no_layer(diag, name, .gone);
        }
        return error.Failed;
    };
    var reporter: Reporter = .{ .host = job.host, .output = job.output };
    const options: import.Options = .{
        .squash_owner = squash_owner,
        .warn = .{ .context = &reporter, .call = report_warning },
        .parent = job.parent,
    };
    var result: import.Result = undefined;
    import.commit(&store, &job.workspace.import, upper_path, options, &result, diag) catch {
        return error.Failed;
    };
    const unchanged = result.digest.eql(job.parent);
    var totals: usage.TreeUsage = undefined;
    var failure: usage.Failure = undefined;
    var memory = usage_memory(job);
    usage.tree_usage(&store, &memory, result.digest, &totals, &failure) catch {
        return usage_failed(&store, &failure, diag);
    };
    if (!unchanged) try save_commit_root(&store, name, &result, &totals, job.parent, diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try put(job, commit_text(job, name, &result, &totals, unchanged, &buffer), diag);
}

/// The new tree is a root, recording the container and the parent.
fn save_commit_root(
    store: *Store,
    name: []const u8,
    result: *const import.Result,
    totals: *const usage.TreeUsage,
    parent: Digest,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    var root: roots.Root = undefined;
    root.digest = result.digest;
    root.kind = .commit;
    root.time = store.host.time_now();
    root.files = totals.files;
    root.bytes = totals.logical_bytes;
    root.set_source(name);
    root.parent = parent;
    var failure: object_failure = undefined;
    roots.save(store, &root, &failure) catch {
        diagnose.write_failed(diag, store, "writing the root record", failure.err, failure.errno);
        return error.Failed;
    };
}

const object_failure = @import("store/object.zig").Failure;

fn commit_text(
    job: *const Job,
    name: []const u8,
    result: *const import.Result,
    totals: *const usage.TreeUsage,
    unchanged: bool,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    assert(name.len > 0);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: a digest line, or a JSON object of a few hundred bytes, fits the buffer.
    if (!job.output.json) {
        writer.print("{s}\n", .{result.digest.text()}) catch unreachable; // Same bound.
        return writer.buffered();
    }
    writer.print("{{\"schema\":\"zbx.commit/1\",\"digest\":\"{s}\",\"parent\":\"{s}\"," ++
        "\"container\":", .{ result.digest.text(), job.parent.text() }) catch {
        unreachable; // The object's head is a few hundred bytes at most.
    };
    json_string(&writer, name) catch unreachable; // Same bound.
    writer.print(",\"unchanged\":{},\"files\":{d},\"bytes\":{d},\"new_objects\":{d}," ++
        "\"new_bytes\":{d},\"new_trees\":{d},\"deleted\":{d}}}\n", .{
        unchanged,
        totals.files,
        totals.logical_bytes,
        result.objects_new,
        result.bytes_new,
        result.trees_new,
        result.whiteouts,
    }) catch unreachable; // Same bound.
    return writer.buffered();
}

// ---- diff ----------------------------------------------------------------------------------

/// The room one line needs at most: a path of `path_bytes_max` bytes with every byte escaped as
/// six, and the fixed words around it.
const diff_line_bytes_max: u32 = constants.path_bytes_max * 6 + 512;

/// Collects diff lines and writes them out in large pieces.
const DiffOut = struct {
    job: *const Job,
    buffer: [diff_line_bytes_max * 2]u8,
    len: u32,
    count: u64,

    fn call(context: *anyopaque, change: *const diff.Change, diag: *Diag) bool {
        const out: *DiffOut = @ptrCast(@alignCast(context));
        out.line(change, diag) catch return false;
        return true;
    }

    fn line(out: *DiffOut, change: *const diff.Change, diag: *Diag) Error!void {
        assert(out.len <= diff_line_bytes_max);
        var writer = std.Io.Writer.fixed(out.buffer[out.len..][0..diff_line_bytes_max]);
        // Cannot fail: the room is the longest line.
        if (out.job.output.json) {
            diff_json(&writer, change, out.count);
        } else {
            diff_text(&writer, change);
        }
        out.len += @intCast(writer.buffered().len);
        out.count += 1;
        if (out.len > diff_line_bytes_max) try out.flush(diag);
    }

    fn flush(out: *DiffOut, diag: *Diag) Error!void {
        try put_big(out.job, out.buffer[0..out.len], diag);
        out.len = 0;
    }
};

/// Like `put`, for text that may be longer than a command's usual output.
fn put_big(job: *const Job, text: []const u8, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (text.len == 0) return;
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn diff_text(writer: *std.Io.Writer, change: *const diff.Change) void {
    const word: u8 = switch (change.what) {
        .added => 'A',
        .removed => 'D',
        .changed => 'M',
    };
    var safe: [constants.path_bytes_max]u8 = undefined;
    const path = text_util.sanitise(&safe, change.path);
    const slash: []const u8 = if (change.kind == .dir and path.len > 1) "/" else "";
    // The room is the longest line.
    writer.print("{c} {s}{s}", .{ word, path, slash }) catch unreachable;
    if (change.what == .changed) {
        const attrs = change.attrs;
        var first = true;
        inline for (.{ "content", "mode", "owner", "xattrs", "target", "kind" }) |field| {
            if (@field(attrs, field)) {
                const word_ = if (std.mem.eql(u8, field, "kind")) "type" else field;
                const separator = if (first) "  " else ", ";
                // The room is the longest line.
                writer.print("{s}{s}", .{ separator, word_ }) catch unreachable;
                first = false;
            }
        }
    }
    writer.writeByte('\n') catch unreachable; // The room is the longest.
}

fn diff_json(writer: *std.Io.Writer, change: *const diff.Change, index: u64) void {
    if (index > 0) writer.writeByte(',') catch unreachable; // The room is the longest.
    writer.print("{{\"change\":\"{s}\",\"kind\":\"{s}\",\"path\":", .{
        @tagName(change.what),
        switch (change.kind) {
            .file => "file",
            .dir => "dir",
            .symlink => "symlink",
        },
    }) catch unreachable; // The room is the longest.
    json_string(writer, change.path) catch unreachable; // The room is the longest.
    if (change.what == .changed) {
        writer.writeAll(",\"attributes\":[") catch unreachable; // The room is the longest.
        var first = true;
        inline for (.{ "content", "mode", "owner", "xattrs", "target", "kind" }) |field| {
            if (@field(change.attrs, field)) {
                const word = if (std.mem.eql(u8, field, "kind")) "type" else field;
                const separator = if (first) "" else ",";
                // The room is the longest line.
                writer.print("{s}\"{s}\"", .{ separator, word }) catch unreachable;
                first = false;
            }
        }
        writer.writeByte(']') catch unreachable; // The room is the longest.
    }
    writer.writeByte('}') catch unreachable; // The room is the longest.
}

fn do_diff(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .diff);
    assert(diag.code == null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    const a = try resolve(&store, exists, job.args.operand.?, diag);
    const b = try resolve(&store, exists, job.args.second.?, diag);
    var out: DiffOut = .{ .job = job, .buffer = undefined, .len = 0, .count = 0 };
    if (job.output.json) {
        var head: [256]u8 = undefined;
        const text = std.fmt.bufPrint(
            &head,
            "{{\"schema\":\"zbx.store.diff/1\",\"from\":\"{s}\",\"to\":\"{s}\",\"changes\":[",
            .{ a.text(), b.text() },
        ) catch unreachable; // A short fixed line.
        try put(job, text, diag);
    }
    var summary: diff.Summary = .{};
    const sink: diff.Sink = .{ .context = &out, .call = DiffOut.call };
    const arena: []align(8) u8 = &job.workspace.import.arena;
    diff.diff(&store, &job.workspace.diff, arena, a, b, sink, &summary, diag) catch {
        return error.Failed;
    };
    try out.flush(diag);
    if (!job.output.json) return;
    var tail: [160]u8 = undefined;
    const text = std.fmt.bufPrint(
        &tail,
        "],\"summary\":{{\"added\":{d},\"removed\":{d},\"changed\":{d}}}}}\n",
        .{ summary.added, summary.removed, summary.changed },
    ) catch unreachable; // A short fixed line.
    try put(job, text, diag);
}

// ---- verify --------------------------------------------------------------------------------

fn write_diag(job: *const Job, diag: *const Diag) void {
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, job.output.mode, job.output.color, &buffer);
    // A diagnostic that can not be written is lost; the exit code still says it failed.
    job.host.write_all(.stderr, text) catch return;
}

fn class_word(damage: *const verify.Damage) []const u8 {
    assert(@tagName(damage.class).len > 0);
    assert(damage.reached >= damage.listed);
    return switch (damage.class) {
        .object => "object",
        .tree => "tree",
        .root => "root record",
    };
}

fn damage_file(
    store: *const Store,
    buffer: *fs_path_buffer,
    damage: *const verify.Damage,
) [:0]const u8 {
    assert(store.root_len > 1);
    assert(damage.errno < 4096);
    return switch (damage.class) {
        .object => store.object_path(buffer, damage.id),
        .tree => store.tree_path(buffer, damage.id),
        .root => store.root_record_path(buffer, damage.id),
    };
}

const fs_path_buffer = @import("store/fs.zig").PathBuf;

/// "b3:<12 digits of the root>:/path" for a diagnostic, the path made printable.
fn ref_text(ws: *const verify.Workspace, ref: *const verify.Ref, out: *[200]u8) []const u8 {
    assert(ref.path_len <= constants.path_bytes_max);
    assert(out.len == 200);
    var safe: [constants.path_bytes_max]u8 = undefined;
    const path = text_util.sanitise(&safe, ws.ref_path(ref));
    const hex = ref.root.hex();
    return std.fmt.bufPrint(out, "{s} in root {s}", .{ path, hex[0..12] }) catch out[0..];
}

fn report_damage(job: *const Job, store: *const Store, index: u32) void {
    assert(index < job.workspace.verify.damage_count);
    assert(store.root_len > 1);
    const ws = &job.workspace.verify;
    const damage = &ws.damage[index];
    var file_storage: fs_path_buffer = undefined;
    const file = damage_file(store, &file_storage, damage);
    var texts: [3][200]u8 = undefined;
    var refs: [3][]const u8 = undefined;
    const listed = verify.refs_of(ws, index);
    const shown = @min(listed.len, 3);
    for (listed[0..shown], 0..) |*ref, at| refs[at] = ref_text(ws, ref, &texts[at]);
    var report: Diag = undefined;
    report.reset();
    diagnose.damaged_thing(
        &report,
        class_word(damage),
        damage.id,
        damage.kind.words(),
        damage.errno,
        file,
        refs[0..shown],
        damage.reached,
    );
    write_diag(job, &report);
}

fn do_verify(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .verify);
    assert(diag.code == null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    const ws = &job.workspace.verify;
    var totals: verify.Totals = .{};
    ws.damage_count = 0;
    ws.ref_count = 0;
    if (exists) {
        var failure: verify.Failure = undefined;
        verify.verify(&store, ws, &job.workspace.import.arena, &totals, &failure) catch {
            diagnose.cannot_read(diag, &store, failure.step, failure.err, failure.errno);
            return error.Failed;
        };
    }
    for (0..ws.damage_count) |index| report_damage(job, &store, @intCast(index));
    if (job.output.json) try verify_json(
        job,
        &totals,
        diag,
    ) else try verify_text(job, &totals, diag);
    if (totals.damaged == 0) return;
    const checked = totals.objects + totals.trees + totals.roots;
    diagnose.verify_failed(diag, totals.damaged, ws.damage_count, checked);
    return error.Failed;
}

fn verify_text(job: *const Job, totals: *const verify.Totals, diag: *Diag) Error!void {
    assert(totals.orphan_lists <= totals.chunk_lists);
    assert(diag.code == null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var size: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: two short lines.
    writer.print("checked {d} objects ({s}), {d} trees, {d} roots: ", .{
        totals.objects,
        size_words(&size, totals.object_bytes),
        totals.trees,
        totals.roots,
    }) catch unreachable; // Same bound.
    if (totals.damaged == 0) {
        writer.writeAll("no damage\n") catch unreachable; // Same bound.
    } else {
        writer.print("{d} damaged\n", .{totals.damaged}) catch unreachable; // Same bound.
    }
    if (totals.orphan_lists > 0) {
        writer.print("{d} chunk lists have no object (an interrupted import or gc left them; " ++
            "the next gc moves them away)\n", .{totals.orphan_lists}) catch unreachable; // Same.
    }
    try put(job, writer.buffered(), diag);
}

fn verify_json(job: *const Job, totals: *const verify.Totals, diag: *Diag) Error!void {
    assert(job.output.json);
    assert(diag.code == null);
    const ws = &job.workspace.verify;
    var buffer: [diff_line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: the room is the longest piece.
    writer.print("{{\"schema\":\"zbx.store.verify/1\",\"ok\":{},\"objects\":{d}," ++
        "\"object_bytes\":{d}," ++
        "\"chunk_lists\":{d},\"orphan_lists\":{d},\"trees\":{d},\"roots\":{d},\"damaged\":{d}," ++
        "\"paths_truncated\":{},\"things\":[", .{
        totals.damaged == 0,
        totals.objects,
        totals.object_bytes,
        totals.chunk_lists,
        totals.orphan_lists,
        totals.trees,
        totals.roots,
        totals.damaged,
        totals.paths_truncated,
    }) catch unreachable; // Same bound.
    try put_big(job, writer.buffered(), diag);
    for (0..ws.damage_count) |index| try damage_json(job, @intCast(index), diag);
    try put(job, "]}\n", diag);
}

fn damage_json(job: *const Job, index: u32, diag: *Diag) Error!void {
    assert(index < job.workspace.verify.damage_count);
    assert(diag.code == null);
    const ws = &job.workspace.verify;
    const damage = &ws.damage[index];
    var buffer: [diff_line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: the room is the longest piece.
    if (index > 0) writer.writeByte(',') catch unreachable; // Same bound.
    writer.print("{{\"id\":\"{s}\",\"class\":\"{s}\",\"kind\":\"{s}\",\"reason\":\"{s}\"," ++
        "\"errno\":{d},\"reached\":{d},\"paths\":[", .{
        damage.id.text(),
        @tagName(damage.class),
        @tagName(damage.kind),
        damage.kind.words(),
        damage.errno,
        damage.reached,
    }) catch unreachable; // Same bound.
    try put_big(job, writer.buffered(), diag);
    for (verify.refs_of(ws, index), 0..) |*ref, at| {
        var piece = std.Io.Writer.fixed(&buffer);
        if (at > 0) piece.writeByte(',') catch unreachable; // Same bound.
        piece.print("{{\"root\":\"{s}\",\"path\":", .{ref.root.text()}) catch unreachable; // Same.
        json_string(&piece, ws.ref_path(ref)) catch unreachable; // Same bound.
        piece.writeByte('}') catch unreachable; // Same bound.
        try put_big(job, piece.buffered(), diag);
    }
    try put(job, "]}", diag);
}

// ---- gc and restore ------------------------------------------------------------------------

/// In the parent: the trees the running containers use are kept by gc. A listing that does not
/// fit is a refusal, never a shorter list.
pub fn prepare_gc(host: Host, args: Args, ws: *Workspace, diag: *Diag) Error!Digest {
    assert(args.action == .gc);
    assert(diag.code == null);
    ws.live_count = 0;
    var confirm = tree.zero_digest;
    if (args.confirm) |text| {
        confirm = Digest.parse(text) orelse Digest.from_hex(text) orelse {
            diagnose.bad_plan_hash(diag, text);
            return error.Failed;
        };
    }
    if (args.trash) return confirm;
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return confirm; // No state directory: no containers.
    var listing: host_mod.DirListing = undefined;
    listing.reset();
    records.names(host, &dir, &listing) catch |err| {
        if (err == error.NotFound) return confirm;
        runtime_diagnose.no_such_container(diag, "(any)", .unreadable_record);
        return error.Failed;
    };
    if (listing.truncated) {
        runtime_diagnose.no_such_container(diag, "(any)", .unreadable_record);
        return error.Failed;
    }
    for (0..listing.count) |at| {
        const stem = records.name_of(listing.name(@intCast(at))) orelse continue;
        records.load(host, &dir, stem, &ws.record) catch continue;
        if (ws.record.tree_len == 0) continue;
        if (lifecycle.state_of(host, &ws.record) != .running) continue;
        const digest = Digest.parse(ws.record.tree_slice()) orelse continue;
        if (ws.live_count == ws.live.len) continue;
        ws.live[ws.live_count] = digest;
        ws.live_count += 1;
    }
    return confirm;
}

fn do_gc(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .gc);
    assert(diag.code == null);
    var store: Store = undefined;
    _ = try open_store(job, &store, .existing, diag);
    if (job.args.trash) return do_trash(job, &store, diag);
    const ws = job.workspace;
    const live = ws.live[0..ws.live_count];
    var failure: gc.Failure = undefined;
    if (job.args.confirm == null) {
        var planned: gc.Plan = undefined;
        gc.plan(&store, &ws.gc, &ws.import.arena, live, &planned, &failure) catch {
            diagnose.gc_failed(diag, &store, &failure);
            return error.Failed;
        };
        return put_plan(job, &planned, diag);
    }
    var applied: gc.Applied = undefined;
    gc.apply(&store, &ws.gc, &ws.import.arena, live, job.confirm, &applied, &failure) catch |err| {
        if (err == error.Stale) {
            diagnose.plan_stale(diag, job.confirm, applied.fresh.hash);
        } else {
            diagnose.gc_failed(diag, &store, &failure);
        }
        return error.Failed;
    };
    try put_applied(job, &applied, diag);
}

fn counts_words(counts: *const gc.Counts, buffer: *[constants.output_bytes_max]u8) []const u8 {
    assert(counts.total() < 1 << 40);
    assert(buffer.len == constants.output_bytes_max);
    var size: [32]u8 = undefined;
    // Cannot fail: one short line.
    return std.fmt.bufPrint(buffer, "{d} objects, {d} chunk lists, {d} trees, {d} materialized " ++
        "directories, {s}", .{
        counts.objects, counts.lists, counts.trees, counts.farms, size_words(&size, counts.bytes),
    }) catch unreachable; // Same bound.
}

fn put_plan(job: *const Job, planned: *const gc.Plan, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(planned.counts.total() < 1 << 40);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const counts = &planned.counts;
    if (job.output.json) {
        const text = std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.store.gc/1\"," ++
            "\"applied\":false," ++
            "\"plan\":\"{s}\",\"generation\":{d},\"objects\":{d},\"lists\":{d},\"trees\":{d}," ++
            "\"farms\":{d},\"tmp\":{d},\"bytes\":{d}}}\n", .{
            planned.hash.text(),
            planned.generation,
            counts.objects,
            counts.lists,
            counts.trees,
            counts.farms,
            counts.tmp,
            counts.bytes,
        }) catch unreachable; // One short object.
        return put(job, text, diag);
    }
    var words: [constants.output_bytes_max]u8 = undefined;
    const moved = counts_words(counts, &words);
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: a few short lines.
    writer.print("plan {s}\n", .{planned.hash.text()}) catch unreachable; // Same bound.
    if (counts.total() == 0) {
        writer.writeAll("  nothing is unreachable\n") catch unreachable; // Same bound.
    } else {
        writer.print("  would move to the trash: {s}\n", .{moved}) catch unreachable; // Same.
    }
    if (counts.tmp > 0) {
        writer.print(
            "  would delete {d} leftovers of dead processes in tmp/\n",
            .{counts.tmp},
        ) catch unreachable; // Same.
    }
    writer.print(
        "confirm with: zbx store gc --confirm {s}\n",
        .{planned.hash.text()},
    ) catch unreachable; // Same.
    try put(job, writer.buffered(), diag);
}

fn put_applied(job: *const Job, applied: *const gc.Applied, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(applied.expires > 0);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const counts = &applied.counts;
    if (job.output.json) {
        const text = std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.store.gc/1\"," ++
            "\"applied\":true," ++
            "\"plan\":\"{s}\",\"gc\":\"{s}\",\"expires\":{d},\"objects\":{d},\"lists\":{d}," ++
            "\"trees\":{d},\"farms\":{d},\"tmp\":{d},\"bytes\":{d},\"expired\":{d}}}\n", .{
            job.confirm.text(),
            applied.gc,
            applied.expires,
            counts.objects,
            counts.lists,
            counts.trees,
            counts.farms,
            counts.tmp,
            counts.bytes,
            applied.expired,
        }) catch unreachable; // One short object.
        return put(job, text, diag);
    }
    var words: [constants.output_bytes_max]u8 = undefined;
    var when: [19]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: a few short lines.
    if (counts.total() == 0) {
        writer.writeAll("nothing was unreachable; nothing moved\n") catch unreachable; // Short.
    } else {
        writer.print("moved to the trash {s}: {s}\n  kept until {s} UTC; undo with: zbx store " ++
            "restore {s}\n", .{
            applied.gc,
            counts_words(counts, &words),
            commands.clock_text(applied.expires, &when),
            applied.gc,
        }) catch unreachable; // Same bound.
    }
    if (counts.tmp > 0) writer.print(
        "deleted {d} leftovers in tmp/\n",
        .{counts.tmp},
    ) catch unreachable; // Same.
    if (applied.expired > 0) writer.print(
        "emptied {d} expired trash\n",
        .{applied.expired},
    ) catch unreachable; // Same.
    try put(job, writer.buffered(), diag);
}

fn do_trash(job: *Job, store: *const Store, diag: *Diag) Error!void {
    assert(job.args.trash);
    assert(diag.code == null);
    const ws = job.workspace;
    var listing: gc.Trash = undefined;
    var failure: gc.Failure = undefined;
    const arena = &ws.import.arena;
    const offsets: []u32 = @alignCast(std.mem.bytesAsSlice(
        u32,
        arena[ws.import.arena.len / 2 ..][0..4096],
    ));
    gc.list_trash(
        store,
        arena[0 .. ws.import.arena.len / 2],
        offsets,
        &ws.trash,
        &listing,
        &failure,
    ) catch {
        diagnose.gc_failed(diag, store, &failure);
        return error.Failed;
    };
    const found = ws.trash[0..listing.count];
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (job.output.json) {
        try put(job, "{\"schema\":\"zbx.store.trash/1\",\"trash\":[", diag);
        for (found, 0..) |entry, index| try put(job, trash_json(&entry, index, &buffer), diag);
        return put(job, "]}\n", diag);
    }
    try put(job, trash_head(&buffer), diag);
    for (found) |entry| try put(job, trash_row(&entry, &buffer), diag);
}

fn trash_head(buffer: *[constants.output_bytes_max]u8) []const u8 {
    assert(buffer.len == constants.output_bytes_max);
    // Cannot fail: a short fixed line.
    return std.fmt.bufPrint(buffer, "{s: <12} {s: <19} {s: <19} {s: >8} {s: >7} {s: >6} {s: " ++
        ">11}  {s}\n", .{
        "GC", "MADE", "EXPIRES", "OBJECTS", "TREES", "DIRS", "SIZE", "STATE",
    }) catch unreachable; // Cannot fail: the buffer holds the longest one.
}

fn trash_row(entry: *const gc.TrashEntry, buffer: *[constants.output_bytes_max]u8) []const u8 {
    assert(buffer.len == constants.output_bytes_max);
    assert(entry.id.len == constants.store_gc_id_hex_bytes);
    var made: [19]u8 = undefined;
    var expires: [19]u8 = undefined;
    var size: [32]u8 = undefined;
    const meta = entry.meta orelse {
        // Cannot fail: a short fixed line.
        return std.fmt.bufPrint(
            buffer,
            "{s: <12} (its metadata is missing or unreadable)\n",
            .{entry.id},
        ) catch unreachable; // Cannot fail: the buffer holds the longest one.
    };
    const state: []const u8 = if (meta.complete) "complete" else "incomplete (a gc or " ++
        "restore was interrupted)";
    // Cannot fail: a short fixed line.
    return std.fmt.bufPrint(buffer, "{s: <12} {s: <19} {s: <19} {d: >8} {d: >7} {d: >6} {s: " ++
        ">11}  {s}\n", .{
        entry.id,
        commands.clock_text(meta.time, &made),
        commands.clock_text(meta.expires, &expires),
        meta.objects,
        meta.trees,
        meta.farms,
        size_words(&size, meta.bytes),
        state,
    }) catch unreachable; // Cannot fail: the buffer holds the longest one.
}

fn trash_json(
    entry: *const gc.TrashEntry,
    index: usize,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    assert(buffer.len == constants.output_bytes_max);
    assert(entry.id.len == constants.store_gc_id_hex_bytes);
    const comma: []const u8 = if (index > 0) "," else "";
    const meta = entry.meta orelse {
        // Cannot fail: a short fixed object.
        return std.fmt.bufPrint(
            buffer,
            "{s}{{\"gc\":\"{s}\",\"readable\":false}}",
            .{ comma, entry.id },
        ) catch unreachable; // Cannot fail: the buffer holds the longest one.
    };
    // Cannot fail: a short fixed object.
    return std.fmt.bufPrint(buffer, "{s}{{\"gc\":\"{s}\",\"readable\":true,\"time\":{d}," ++
        "\"expires\":{d}," ++
        "\"objects\":{d},\"lists\":{d},\"trees\":{d},\"farms\":{d},\"bytes\":{d}," ++
        "\"complete\":{}}}", .{
        comma,      entry.id,   meta.time,  meta.expires, meta.objects,
        meta.lists, meta.trees, meta.farms, meta.bytes,   meta.complete,
    }) catch unreachable; // Cannot fail: the buffer holds the longest one.
}

fn do_restore(job: *Job, diag: *Diag) Error!void {
    assert(job.args.action == .restore);
    assert(diag.code == null);
    var store: Store = undefined;
    const exists = try open_store(job, &store, .existing, diag);
    const text = job.args.operand.?;
    if (!exists) {
        diagnose.no_such_trash(diag, text);
        return error.Failed;
    }
    const id: gc.Id = text[0..constants.store_gc_id_hex_bytes].*;
    const ws = job.workspace;
    var restored: gc.Restored = undefined;
    var failure: gc.Failure = undefined;
    gc.restore(&store, &ws.gc, &ws.import.arena, id, &restored, &failure) catch |err| {
        switch (err) {
            error.NoSuchTrash => diagnose.no_such_trash(diag, text),
            error.Conflict => diagnose.restore_conflict(
                diag,
                text,
                @tagName(restored.conflict_class),
                restored.conflict_id,
                restored.conflicts,
            ),
            error.Incomplete => diagnose.trash_incomplete(
                diag,
                text,
                restored.promised.objects + restored.promised.trees + restored.promised.farms,
                restored.found.objects + restored.found.trees + restored.found.farms,
            ),
            error.Failed => diagnose.gc_failed(diag, &store, &failure),
        }
        return error.Failed;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const counts = &restored.counts;
    const out = if (job.output.json)
        std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.store.restore/1\",\"gc\":\"{s}\"," ++
            "\"objects\":{d}," ++
            "\"lists\":{d},\"trees\":{d},\"farms\":{d}}}\n", .{
            id, counts.objects, counts.lists, counts.trees, counts.farms,
        })
    else
        std.fmt.bufPrint(&buffer, "restored {d} objects, {d} chunk lists, {d} trees and {d} " ++
            "materialized directories from the trash {s}\n", .{
            counts.objects, counts.lists, counts.trees, counts.farms, id,
        });
    try put(job, out catch unreachable, diag); // One short line.
}
