//! The `zbx state` commands: `ls`, `rm NAME` and `restore NAME` (docs/briefs/M6-state.md).
//!
//! The parent reads what is the user's own (the state directory's listing, each volume's record
//! and lock, the run records), decides, and refuses with a coded diagnostic; the file work on a
//! volume's files, which belong to the container's ids (sizing, moving to and from the trash,
//! emptying expired trash), runs in the store's namespace child (`store/namespace.zig`), which
//! also writes the result: text, or one JSON object with `--output json` (`schemas.zig`).
//!
//! `rm` holds the volume's lock exclusive from before the child starts until it ends, so a run
//! that starts meanwhile is refused (it waits `state_lock_wait_ms` first), and `rm` is refused
//! while any run holds it. `restore` takes nothing: the trash is no run's, and a volume made
//! again under the name meanwhile is refused (E0708).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const host_mod = @import("host.zig");
const Diag = @import("diag/diag.zig").Diag;
const errors = @import("diag/errors.zig");
const render = @import("diag/render.zig");
const commands = @import("commands.zig");
const json = @import("bundle.zig");
const records = @import("runtime/records.zig");
const fs_mod = @import("store/fs.zig");
const names_mod = @import("store/names.zig");
const namespace = @import("store/namespace.zig");
const remove = @import("store/remove.zig");
const size_words = @import("store_commands.zig").size_words;
const volume = @import("state/volume.zig");
const record_mod = @import("state/record.zig");
const lock = @import("state/lock.zig");
const holders = @import("state/holders.zig");
const usage = @import("state/usage.zig");
const diagnose = @import("state/diagnose.zig");

const Host = host_mod.Host;
const NameList = names_mod.NameList;

pub const Error = error{Failed};

pub const Action = enum { ls, rm, restore };

pub const Args = struct {
    action: Action,
    /// The volume's name, for `rm` and `restore`.
    operand: ?[]const u8,
};

pub const Output = struct {
    mode: render.Mode,
    color: bool,
    json: bool,
};

/// One volume as `ls` shows it.
pub const Volume = struct {
    name: [constants.state_name_bytes_max]u8,
    name_len: u8,
    /// The record, when it reads; `record_state` says why not otherwise.
    record: record_mod.Record,
    record_state: enum { ok, missing, unreadable },
    /// The running containers that mount it.
    users: [constants.state_holders_max][constants.container_name_bytes_max]u8,
    user_lens: [constants.state_holders_max]u8,
    user_read_only: [constants.state_holders_max]bool,
    users_count: u32,
    /// Counted in the child; `size_known` false when the count stopped (W0702).
    size: usage.Size,
    size_known: bool,

    pub fn name_slice(entry: *const Volume) []const u8 {
        assert(entry.name_len > 0);
        return entry.name[0..entry.name_len];
    }

    pub fn user(entry: *const Volume, index: u32) []const u8 {
        assert(index < entry.users_count);
        return entry.users[index][0..entry.user_lens[index]];
    }
};

/// One trash entry.
pub const Trashed = struct {
    entry: volume.TrashName,
    name_len: u8,
    removed: u64,

    pub fn name_slice(trashed: *const Trashed) []const u8 {
        assert(trashed.name_len > 0);
        return trashed.entry.bytes[0..trashed.name_len];
    }
};

const listing_names_max = constants.state_volumes_listed_max + constants.state_trash_listed_max;
const listing_bytes = listing_names_max * (constants.store_name_bytes_max + 1);

/// The caller's memory, about 5 MiB (the size walk's region is most of it): keep it in static
/// or heap storage.
pub const Workspace = struct {
    volumes: [constants.state_volumes_listed_max]Volume,
    volumes_count: u32,
    trash: [constants.state_trash_listed_max]Trashed,
    trash_count: u32,
    /// More of either than are kept were found: the listing says so.
    truncated: bool,
    listing: [listing_bytes]u8,
    offsets: [listing_names_max]u32,
    /// The listing `list_names` filled last; the offsets it returned point into it.
    names: NameList,
    scratch: records.Parsed,
    found: holders.Found,
    usage: usage.Workspace,
    remove: remove.Workspace,
    remove_arena: [remove.arena_bytes]u8,
};

const Job = struct {
    host: Host,
    args: Args,
    output: Output,
    workspace: *Workspace,
    root: volume.Root,
    /// `rm`: when it is moved, and the entry's name. `restore`: the entry brought back.
    now: u64,
    entry: volume.TrashName,
    removed: u64,
};

/// Runs a state command and returns its exit code. `diag` holds a failure of the parent's own;
/// the child's failures are on stderr already, and are its exit code.
pub fn run(
    host: Host,
    args: Args,
    output: Output,
    facts: *doctor.Facts,
    workspace: *Workspace,
    diag: *Diag,
) Error!u8 {
    assert(diag.code == null);
    assert((args.operand != null) == (args.action != .ls));
    if (args.operand) |name| {
        if (volume.name_problem(name)) |problem| {
            diagnose.bad_name(diag, name, problem);
            return error.Failed;
        }
    }
    var job: Job = .{
        .host = host,
        .args = args,
        .output = output,
        .workspace = workspace,
        .root = undefined,
        .now = @min(host.time_now(), constants.state_time_max - 1),
        .entry = undefined,
        .removed = 0,
    };
    if (!job.root.locate(host)) {
        diagnose.directory_failed(diag, null);
        return error.Failed;
    }
    return switch (args.action) {
        .ls => run_ls(&job, facts, diag),
        .rm => run_rm(&job, facts, diag),
        .restore => run_restore(&job, facts, diag),
    };
}

fn in_child(job: *Job, facts: *doctor.Facts, diag: *Diag) Error!u8 {
    const work: namespace.Work = .{ .context = job, .call = work_call };
    return namespace.run(job.host, facts, work, null, diag) catch error.Failed;
}

fn work_call(context: *anyopaque, squash_owner: bool) u8 {
    _ = squash_owner; // Nothing here records an owner.
    const job: *Job = @ptrCast(@alignCast(context));
    var diag: Diag = undefined;
    diag.reset();
    const result = switch (job.args.action) {
        .ls => child_ls(job, &diag),
        .rm => child_rm(job, &diag),
        .restore => child_restore(job, &diag),
    };
    result catch {
        if (diag.code == null) {
            diag.raise(.B0001);
            diag.cause("a state command failed with no diagnostic", .{});
        }
        report(job, &diag);
        return diag.exit_code();
    };
    return constants.exit_ok;
}

fn report(job: *const Job, diag: *const Diag) void {
    assert(diag.code != null);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(diag, job.output.mode, job.output.color, &buffer);
    job.host.write_all(.stderr, text) catch return; // Nowhere else to say it.
}

/// Writes to stdout; a failure is ZBX-E0009.
fn put(job: *const Job, text: []const u8, diag: *Diag) Error!void {
    assert(text.len <= constants.output_bytes_max);
    if (text.len == 0) return;
    job.host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, job.host.last_errno());
        return error.Failed;
    };
}

fn fail_path(job: *const Job, diag: *Diag, operation: []const u8, path: []const u8) Error {
    const fs = job.host.filesystem();
    diagnose.directory_failed(diag, .{
        .operation = operation,
        .path = path,
        .err = host_mod.error_for_errno(fs.last_errno()),
        .errno = fs.last_errno(),
    });
    return error.Failed;
}

/// The names in `path`, sorted, in the workspace's listing region; a missing directory is none.
fn list_names(job: *Job, path: [:0]const u8, diag: *Diag) Error![]const u32 {
    const ws = job.workspace;
    var names = NameList.init(&ws.listing, listing_names_max);
    ws.names = names;
    job.host.filesystem().read_dir(path, names.visitor()) catch |err| {
        if (err == error.NotFound) return &.{};
        return fail_path(job, diag, "listing", path);
    };
    if (!names.complete()) ws.truncated = true;
    ws.names = names;
    return ws.names.sorted(&ws.offsets);
}

// ---- ls ---------------------------------------------------------------------------------------

fn run_ls(job: *Job, facts: *doctor.Facts, diag: *Diag) Error!u8 {
    const ws = job.workspace;
    ws.volumes_count = 0;
    ws.trash_count = 0;
    ws.truncated = false;
    for (try list_names(job, job.root.text(), diag)) |offset| {
        const name = job.workspace.names.at(offset);
        if (volume.name_problem(name) != null) continue; // `.trash`, or nothing of ours.
        if (ws.volumes_count == ws.volumes.len) {
            ws.truncated = true;
            break;
        }
        read_volume(job, name, &ws.volumes[ws.volumes_count]);
        ws.volumes_count += 1;
    }
    var trash: volume.Path = undefined;
    job.root.trash(&trash, null);
    for (try list_names(job, trash.text(), diag)) |offset| {
        const entry = volume.parse_trash_name(job.workspace.names.at(offset)) orelse continue;
        if (ws.trash_count == ws.trash.len) {
            ws.truncated = true;
            break;
        }
        const item = &ws.trash[ws.trash_count];
        volume.trash_name_of(entry.name, entry.removed, &item.entry);
        item.name_len = @intCast(entry.name.len);
        item.removed = entry.removed;
        ws.trash_count += 1;
    }
    return in_child(job, facts, diag);
}

/// What the parent knows of a volume: its record and who uses it now.
fn read_volume(job: *Job, name: []const u8, entry: *Volume) void {
    assert(volume.name_problem(name) == null);
    @memcpy(entry.name[0..name.len], name);
    entry.name_len = @intCast(name.len);
    var path: volume.Path = undefined;
    job.root.volume(&path, name, volume.record_name);
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    entry.record_state = .ok;
    if (job.host.filesystem().read_whole(path.text(), &buffer)) |text| {
        record_mod.parse(text, &entry.record) catch {
            entry.record_state = .unreadable;
        };
    } else |err| {
        entry.record_state = if (err == error.NotFound) .missing else .unreadable;
    }
    const ws = job.workspace;
    holders.find(job.host, name, &ws.scratch, &ws.found);
    entry.users_count = ws.found.count;
    for (0..ws.found.count) |index| {
        const user = ws.found.name(@intCast(index));
        @memcpy(entry.users[index][0..user.len], user);
        entry.user_lens[index] = @intCast(user.len);
        entry.user_read_only[index] = ws.found.read_only[index];
    }
    entry.size_known = false;
}

fn child_ls(job: *Job, diag: *Diag) Error!void {
    const ws = job.workspace;
    for (ws.volumes[0..ws.volumes_count]) |*entry| measure(job, entry);
    if (job.output.json) return ls_json(job, diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const format = "{s: <24} {s: >10}  {s: <19}  {s: <19}  {s: <20} {s}\n";
    const head = std.fmt.bufPrint(&buffer, format, .{
        "NAME", "SIZE", "CREATED", "LAST USED", "LAST CONTAINER", "IN USE BY",
    }) catch unreachable; // A short fixed line.
    try put(job, head, diag);
    for (ws.volumes[0..ws.volumes_count]) |*entry| try put(job, ls_row(entry, &buffer), diag);
    for (ws.trash[0..ws.trash_count]) |*item| try put(job, trash_row(job, item, &buffer), diag);
    if (ws.truncated) try put(job, "(more volumes or trash than are listed)\n", diag);
}

/// The volume's size, counted here in the namespace; a count that stops is a warning.
fn measure(job: *Job, entry: *Volume) void {
    var path: volume.Path = undefined;
    job.root.volume(&path, entry.name_slice(), volume.data_name);
    var failure: usage.Failure = undefined;
    const fs = job.host.filesystem();
    usage.measure(fs, &job.workspace.usage, path.text(), &entry.size, &failure) catch {
        entry.size_known = false;
        var warning: Diag = undefined;
        warning.reset();
        diagnose.size_unknown(&warning, entry.name_slice(), failure.stop.sentence());
        report(job, &warning);
        return;
    };
    entry.size_known = true;
}

fn ls_row(entry: *const Volume, buffer: *[constants.output_bytes_max]u8) []const u8 {
    var size: [32]u8 = undefined;
    const size_text = if (entry.size_known) size_words(&size, entry.size.disk_bytes) else "?";
    var created: [19]u8 = undefined;
    var used: [19]u8 = undefined;
    const has = entry.record_state == .ok;
    const created_text = if (has) commands.clock_text(entry.record.created, &created) else "-";
    const used_text = if (has) commands.clock_text(entry.record.last_used, &used) else "-";
    const last = if (has and entry.record.last_container_len > 0)
        entry.record.container_slice()
    else
        "-";
    var users: [constants.state_holders_max * (constants.container_name_bytes_max + 6)]u8 =
        undefined;
    var writer = std.Io.Writer.fixed(&users);
    for (0..entry.users_count) |index| {
        // Cannot fail: the buffer holds every name with its separator and mark.
        if (index > 0) writer.writeAll(", ") catch unreachable; // Same bound.
        writer.writeAll(entry.user(@intCast(index))) catch unreachable; // Same bound.
        if (entry.user_read_only[index]) writer.writeAll(" (ro)") catch unreachable; // Same.
    }
    const in_use = if (entry.users_count == 0) "-" else writer.buffered();
    const format = "{s: <24} {s: >10}  {s: <19}  {s: <19}  {s: <20} {s}\n";
    return std.fmt.bufPrint(buffer, format, .{
        entry.name_slice(), size_text, created_text, used_text, last, in_use,
    }) catch unreachable; // Bounded names, times and sizes fit the output buffer.
}

fn trash_row(
    job: *const Job,
    item: *const Trashed,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    var removed: [19]u8 = undefined;
    var until: [19]u8 = undefined;
    const expires = item.removed + constants.store_trash_seconds;
    const state = if (volume.expired(item.removed, job.now)) "expired" else "restorable";
    // Cannot fail: a name, two times and fixed words fit the output buffer.
    return std.fmt.bufPrint(buffer, "trash: {s} removed {s}, kept until {s} ({s})\n", .{
        item.name_slice(),
        commands.clock_text(item.removed, &removed),
        commands.clock_text(@min(expires, constants.state_time_max - 1), &until),
        state,
    }) catch unreachable; // Same bound.
}

fn ls_json(job: *Job, diag: *Diag) Error!void {
    const ws = job.workspace;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail, any of these: a bounded path and fixed words fit the buffer.
    writer.writeAll("{\"schema\":\"zbx.state.ls/1\",\"directory\":") catch unreachable; // Same.
    json.write_json_string(&writer, job.root.text()) catch unreachable; // Same bound.
    writer.writeAll(",\"volumes\":[") catch unreachable; // Same bound.
    try put(job, writer.buffered(), diag);
    for (ws.volumes[0..ws.volumes_count], 0..) |*entry, index| {
        try put(job, volume_json(entry, index > 0, &buffer), diag);
    }
    try put(job, "],\"trash\":[", diag);
    for (ws.trash[0..ws.trash_count], 0..) |*item, index| {
        try put(job, trash_json(job, item, index > 0, &buffer), diag);
    }
    const tail = if (ws.truncated) "],\"truncated\":true}\n" else "],\"truncated\":false}\n";
    try put(job, tail, diag);
}

fn volume_json(
    entry: *const Volume,
    comma: bool,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail, any of these: one volume's bounded fields fit the output buffer.
    if (comma) writer.writeAll(",") catch unreachable; // Same bound.
    writer.writeAll("{\"name\":") catch unreachable; // Same bound.
    json.write_json_string(&writer, entry.name_slice()) catch unreachable; // Same bound.
    if (entry.size_known) {
        writer.print(",\"bytes\":{d},\"disk_bytes\":{d},\"files\":{d}", .{
            entry.size.bytes, entry.size.disk_bytes, entry.size.files,
        }) catch unreachable; // Same bound.
    } else {
        writer.writeAll(",\"bytes\":null,\"disk_bytes\":null,\"files\":null") catch
            unreachable; // Same bound.
    }
    writer.print(",\"record\":\"{s}\"", .{@tagName(entry.record_state)}) catch
        unreachable; // Same bound.
    record_json(&writer, entry);
    writer.print(",\"in_use\":{s},\"used_by\":[", .{
        if (entry.users_count > 0) "true" else "false",
    }) catch unreachable; // Same bound.
    for (0..entry.users_count) |index| {
        if (index > 0) writer.writeAll(",") catch unreachable; // Same bound.
        writer.writeAll("{\"container\":") catch unreachable; // Same bound.
        json.write_json_string(&writer, entry.user(@intCast(index))) catch unreachable; // Same.
        writer.print(",\"read_only\":{s}}}", .{
            if (entry.user_read_only[index]) "true" else "false",
        }) catch unreachable; // Same bound.
    }
    writer.writeAll("]}") catch unreachable; // Same bound.
    return writer.buffered();
}

fn record_json(writer: *std.Io.Writer, entry: *const Volume) void {
    // Cannot fail, any of these: the caller's buffer holds one volume's bounded fields.
    if (entry.record_state != .ok) {
        writer.writeAll(",\"created\":null,\"last_used\":null,\"last_container\":null," ++
            "\"last_path\":null,\"last_read_only\":null") catch unreachable; // Same bound.
        return;
    }
    const record = &entry.record;
    writer.print(",\"created\":{d},\"last_used\":{d},\"last_container\":", .{
        record.created, record.last_used,
    }) catch unreachable; // Same bound.
    if (record.last_container_len == 0) {
        writer.writeAll("null,\"last_path\":null,\"last_read_only\":null") catch
            unreachable; // Same bound.
        return;
    }
    json.write_json_string(writer, record.container_slice()) catch unreachable; // Same bound.
    writer.writeAll(",\"last_path\":") catch unreachable; // Same bound.
    json.write_json_string(writer, record.target_slice()) catch unreachable; // Same bound.
    writer.print(",\"last_read_only\":{s}", .{
        if (record.last_read_only) "true" else "false",
    }) catch unreachable; // Same bound.
}

fn trash_json(
    job: *const Job,
    item: *const Trashed,
    comma: bool,
    buffer: *[constants.output_bytes_max]u8,
) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail, any of these: a trash entry's bounded fields fit the output buffer.
    if (comma) writer.writeAll(",") catch unreachable; // Same bound.
    writer.writeAll("{\"name\":") catch unreachable; // Same bound.
    json.write_json_string(&writer, item.name_slice()) catch unreachable; // Same bound.
    writer.writeAll(",\"entry\":") catch unreachable; // Same bound.
    json.write_json_string(&writer, item.entry.text()) catch unreachable; // Same bound.
    writer.print(",\"removed\":{d},\"expires\":{d},\"expired\":{s}}}", .{
        item.removed,
        item.removed + constants.store_trash_seconds,
        if (volume.expired(item.removed, job.now)) "true" else "false",
    }) catch unreachable; // Same bound.
    return writer.buffered();
}

// ---- rm ---------------------------------------------------------------------------------------

fn run_rm(job: *Job, facts: *doctor.Facts, diag: *Diag) Error!u8 {
    const name = job.args.operand.?;
    const fs = job.host.filesystem();
    var path: volume.Path = undefined;
    job.root.volume(&path, name, null);
    const found = fs.lstat(path.text()) catch |err| {
        if (err == error.NotFound) {
            diagnose.no_such_volume(diag, name);
            return error.Failed;
        }
        return fail_path(job, diag, "reading", path.text());
    };
    if (found.kind != .dir) {
        diagnose.no_such_volume(diag, name);
        return error.Failed;
    }
    var lock_path: volume.Path = undefined;
    job.root.volume(&lock_path, name, volume.lock_name);
    var text: lock.HolderText = undefined;
    lock.holder_text(job.host.own_pid(), "zbx state rm", &text);
    const fd = lock.take(job.host, lock_path.text(), .exclusive, &text, 0) catch |err| {
        switch (err) {
            error.Busy => refuse_in_use(job, lock_path.text(), name, diag),
            error.Failed => return fail_path(job, diag, "locking", lock_path.text()),
        }
        return error.Failed;
    };
    // The child inherits the descriptor; the lock is the parent's until the move is done.
    defer lock.release(job.host, fd);
    volume.trash_name_of(name, job.now, &job.entry);
    return in_child(job, facts, diag);
}

fn refuse_in_use(job: *Job, path: [:0]const u8, name: []const u8, diag: *Diag) void {
    var buffer: [constants.store_lock_holder_bytes]u8 = undefined;
    const holder = lock.holder_of(job.host, path, .exclusive, &buffer);
    const ws = job.workspace;
    holders.find(job.host, name, &ws.scratch, &ws.found);
    var named: diagnose.Holders = undefined;
    holders.describe(holder, &ws.found, &named);
    diagnose.in_use(diag, name, false, &named);
}

fn child_rm(job: *Job, diag: *Diag) Error!void {
    const fs = job.host.filesystem();
    const name = job.args.operand.?;
    var trash: volume.Path = undefined;
    job.root.trash(&trash, null);
    fs.make_directory(trash.text(), true) catch {
        return fail_path(job, diag, "making the directory", trash.text());
    };
    var from: volume.Path = undefined;
    job.root.volume(&from, name, null);
    var to: volume.Path = undefined;
    job.root.trash(&to, job.entry.text());
    fs.rename(from.text(), to.text()) catch return fail_path(job, diag, "moving", from.text());
    fs.sync_directory(job.root.text()) catch {}; // The rename is done; durability is best effort.
    const emptied = empty_expired(job);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var until: [19]u8 = undefined;
    const expires = job.now + constants.store_trash_seconds;
    const text = if (job.output.json)
        std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.state.rm/1\",\"name\":\"{s}\"," ++
            "\"entry\":\"{s}\",\"removed\":{d},\"expires\":{d},\"emptied\":{d}}}\n", .{
            name, job.entry.text(), job.now, expires, emptied,
        })
    else
        std.fmt.bufPrint(&buffer, "{s}: moved to the trash, kept until {s}; " ++
            "zbx state restore {s} brings it back\n", .{
            name, commands.clock_text(@min(expires, constants.state_time_max - 1), &until), name,
        });
    // A volume's name needs no JSON escape (its bytes are letters, digits and `.-_`).
    try put(job, text catch unreachable, diag); // A name and numbers fit the buffer.
}

/// Empties every trash entry whose time is past, now that the user has removed something: the
/// store's rule for gc's trash. One that cannot be emptied stays for the next `rm`.
fn empty_expired(job: *Job) u32 {
    const ws = job.workspace;
    const fs = job.host.filesystem();
    var trash: volume.Path = undefined;
    job.root.trash(&trash, null);
    var diag: Diag = undefined;
    diag.reset();
    const offsets = list_names(job, trash.text(), &diag) catch return 0;
    var emptied: u32 = 0;
    for (offsets) |offset| {
        const text = job.workspace.names.at(offset);
        const entry = volume.parse_trash_name(text) orelse continue;
        if (!volume.expired(entry.removed, job.now)) continue;
        var path: volume.Path = undefined;
        job.root.trash(&path, text);
        var failure: remove.Failure = undefined;
        remove.tree(fs, &ws.remove, &ws.remove_arena, path.text(), &failure) catch continue;
        emptied += 1;
    }
    return emptied;
}

// ---- restore ----------------------------------------------------------------------------------

fn run_restore(job: *Job, facts: *doctor.Facts, diag: *Diag) Error!u8 {
    const name = job.args.operand.?;
    var trash: volume.Path = undefined;
    job.root.trash(&trash, null);
    var newest: ?u64 = null;
    for (try list_names(job, trash.text(), diag)) |offset| {
        const entry = volume.parse_trash_name(job.workspace.names.at(offset)) orelse continue;
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (newest == null or entry.removed > newest.?) newest = entry.removed;
    }
    const removed = newest orelse {
        diagnose.not_in_trash(diag, name);
        return error.Failed;
    };
    volume.trash_name_of(name, removed, &job.entry);
    job.removed = removed;
    if (volume.expired(removed, job.now)) {
        diagnose.trash_expired(diag, name, job.entry.text(), removed);
        return error.Failed;
    }
    var path: volume.Path = undefined;
    job.root.volume(&path, name, null);
    if (job.host.filesystem().lstat(path.text())) |_| {
        diagnose.restore_over(diag, name, job.entry.text());
        return error.Failed;
    } else |err| {
        if (err != error.NotFound) return fail_path(job, diag, "reading", path.text());
    }
    return in_child(job, facts, diag);
}

fn child_restore(job: *Job, diag: *Diag) Error!void {
    const fs = job.host.filesystem();
    const name = job.args.operand.?;
    var from: volume.Path = undefined;
    job.root.trash(&from, job.entry.text());
    var to: volume.Path = undefined;
    job.root.volume(&to, name, null);
    // Checked once more here: a run may have made the name since the parent looked.
    if (fs.lstat(to.text())) |_| {
        diagnose.restore_over(diag, name, job.entry.text());
        return error.Failed;
    } else |_| {}
    fs.rename(from.text(), to.text()) catch return fail_path(job, diag, "moving", from.text());
    fs.sync_directory(job.root.text()) catch {}; // The rename is done; durability is best effort.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = if (job.output.json)
        std.fmt.bufPrint(&buffer, "{{\"schema\":\"zbx.state.restore/1\",\"name\":\"{s}\"," ++
            "\"entry\":\"{s}\",\"removed\":{d}}}\n", .{ name, job.entry.text(), job.removed })
    else
        std.fmt.bufPrint(&buffer, "{s}: restored\n", .{name});
    try put(job, text catch unreachable, diag); // A name and a number fit the buffer.
}
