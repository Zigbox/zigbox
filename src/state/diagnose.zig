//! The state volumes' diagnostics, `ZBX-E0705` to `E0713` and `W0702`: one function per
//! failure, each with its cause and a fix (DIAGNOSTICS.md). Nothing here decides; the callers
//! say what happened.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const volume = @import("volume.zig");

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0705: a name that cannot name a volume, in `--state` or as an operand.
pub fn bad_name(diag: *Diag, name: []const u8, problem: volume.NameProblem) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, name);
    diag.raise(.E0705);
    diag.while_("reading the command line", .{});
    diag.cause("the volume name '{s}' {s}", .{ echo, problem.sentence() });
    diag.context("name", "{s}", .{echo});
    diag.fix(.{
        .sentence = "name it in lowercase letters and digits, for example:",
        .command = "zbx run --state pgdata:/var/lib/postgresql/data postgres:16",
    });
}

/// ZBX-E0005: a `--state` value whose target, or whose place among the others, is wrong.
pub fn bad_value(diag: *Diag, value: []const u8, reason: []const u8) void {
    assert(diag.code == null);
    assert(reason.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("--state '{s}': {s}", .{ echo, reason });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give a volume's name and an absolute path in the container, :ro to share it:",
        .command = "zbx run --state pgdata:/var/lib/postgresql/data postgres:16",
    });
}

pub fn list_sentence(problem: volume.ListProblem) []const u8 {
    comptime assert(constants.state_volumes_max == 8); // The sentence says so.
    return switch (problem) {
        .too_many => "--state is given more than 8 times",
        .same_name => "that volume is already mounted by this run",
        .same_target => "that path is, or is inside, or holds, another volume's path",
    };
}

/// Who holds a volume, as a refusal says it: the containers (read-only ones, or the writer), or
/// another command.
pub const Holders = struct {
    names: [constants.state_holders_max][]const u8,
    count: u32,
    /// The lock is held exclusive: by `names[0]` if known, else by `writer_text`.
    writer: bool,
    /// What the writer wrote in the lock file (`<pid> <who>` cut to its size), when no running
    /// container's record names it: `zbx state rm`, or a run whose record is not written yet.
    writer_text: []const u8,
    writer_pid: u32,
};

/// ZBX-E0706: the volume is held in a mode that excludes this one.
pub fn in_use(diag: *Diag, name: []const u8, wanted_read_only: bool, holders: *const Holders) void {
    assert(diag.code == null);
    assert(holders.count <= constants.state_holders_max);
    diag.raise(.E0706);
    diag.while_("taking the state volume {s}", .{name});
    const how = if (wanted_read_only) "to read" else "to write";
    if (holders.writer) {
        if (holders.count > 0) {
            diag.cause("the container {s} is writing to the volume {s}, so it is not free {s}", .{
                holders.names[0], name, how,
            });
        } else if (holders.writer_text.len > 0) {
            diag.cause("{s} (process {d}) holds the volume {s} for writing", .{
                holders.writer_text, holders.writer_pid, name,
            });
        } else {
            diag.cause("another process holds the volume {s} for writing", .{name});
        }
    } else {
        var list: [constants.state_holders_max * (constants.container_name_bytes_max + 2)]u8 =
            undefined;
        const names = join_names(&list, holders.names[0..holders.count]);
        if (names.len > 0) {
            diag.cause("the volume {s} is mounted read-only by {s}, and a writer must be " ++
                "alone", .{ name, names });
        } else {
            diag.cause("the volume {s} is mounted read-only by other containers, and a " ++
                "writer must be alone", .{name});
        }
    }
    diag.context("volume", "{s}", .{name});
    if (holders.count > 0) diag.context("holder", "{s}", .{holders.names[0]});
    var command: [constants.container_name_bytes_max + 16]u8 = undefined;
    // A writer whose record is not there yet is named by its lock's text: a container's name,
    // or a command (which has a space, and is not a container to stop).
    const text = holders.writer_text;
    const named = text.len > 0 and std.mem.indexOfScalar(u8, text, ' ') == null;
    const first = if (holders.count > 0) holders.names[0] else if (named) text else "<name>";
    // Cannot fail: a container name and "zbx stop " fit the buffer.
    const stop = std.fmt.bufPrint(&command, "zbx stop {s}", .{first}) catch unreachable;
    diag.fix(.{ .sentence = "stop the container that holds it, then run again:", .command = stop });
    if (!wanted_read_only) {
        diag.fix(.{ .sentence = "or, if this run only reads it, mount it with NAME:PATH:ro" });
    }
}

fn join_names(buffer: []u8, names: []const []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    for (names, 0..) |item, index| {
        if (index > 0) writer.writeAll(", ") catch break;
        writer.writeAll(item) catch break;
    }
    return writer.buffered();
}

/// ZBX-E0707: `state rm` or `state export` of a volume that is not there.
pub fn no_such_volume(diag: *Diag, name: []const u8, doing: []const u8) void {
    assert(diag.code == null);
    assert(volume.name_problem(name) == null);
    diag.raise(.E0707);
    diag.while_("{s} the state volume {s}", .{ doing, name });
    diag.cause("there is no state volume called {s}", .{name});
    diag.context("volume", "{s}", .{name});
    diag.fix(.{ .sentence = "list the volumes and the trash:", .command = "zbx state ls" });
}

/// ZBX-E0708: a restore whose name was made again meanwhile.
pub fn restore_over(diag: *Diag, name: []const u8, entry: []const u8) void {
    assert(diag.code == null);
    assert(entry.len > name.len);
    diag.raise(.E0708);
    diag.while_("restoring the state volume {s}", .{name});
    diag.cause("a volume called {s} was made again after {s} went to the trash; restoring " ++
        "would replace it", .{ name, entry });
    diag.context("volume", "{s}", .{name});
    diag.context("trash", "{s}", .{entry});
    var command: [constants.state_name_bytes_max + 16]u8 = undefined;
    // Cannot fail: a volume name and "zbx state rm " fit the buffer.
    const remove = std.fmt.bufPrint(&command, "zbx state rm {s}", .{name}) catch unreachable;
    diag.fix(.{
        .sentence = "move the new one to the trash first, if it is not needed:",
        .command = remove,
    });
}

/// ZBX-E0709: nothing of that name in the trash.
pub fn not_in_trash(diag: *Diag, name: []const u8) void {
    assert(diag.code == null);
    assert(volume.name_problem(name) == null);
    diag.raise(.E0709);
    diag.while_("restoring the state volume {s}", .{name});
    diag.cause("the trash holds no volume called {s}", .{name});
    diag.context("volume", "{s}", .{name});
    diag.fix(.{ .sentence = "list the volumes and the trash:", .command = "zbx state ls" });
}

/// ZBX-E0710: the newest trash entry of that name is past its time.
pub fn trash_expired(diag: *Diag, name: []const u8, entry: []const u8, removed: u64) void {
    assert(diag.code == null);
    assert(removed < constants.state_time_max);
    diag.raise(.E0710);
    diag.while_("restoring the state volume {s}", .{name});
    diag.cause("{s} went to the trash more than 7 days ago, and its trash has expired", .{name});
    diag.context("volume", "{s}", .{name});
    diag.context("trash", "{s}", .{entry});
    diag.fix(.{ .sentence = "copy its files out by hand first (zbx explain E0710)" });
}

comptime {
    assert(constants.store_trash_seconds == 7 * 24 * 60 * 60); // "7 days" above.
}

/// What could not be done to which path, for E0711.
pub const Failure = struct {
    operation: []const u8,
    path: []const u8,
    err: host_mod.Error,
    errno: u16,
};

/// ZBX-E0711: no state directory, or a directory or file of it could not be made or read.
pub fn directory_failed(diag: *Diag, failure: ?Failure) void {
    assert(diag.code == null);
    diag.raise(.E0711);
    const found = failure orelse {
        diag.while_("finding the state directory", .{});
        diag.cause("neither XDG_DATA_HOME nor HOME names an absolute directory", .{});
        diag.fix(.{ .sentence = "set HOME, or point XDG_DATA_HOME at a directory you own" });
        return;
    };
    assert(found.operation.len > 0);
    diag.while_("using the state directory", .{});
    var operation: [constants.state_volume_path_bytes_max + 64]u8 = undefined;
    const text = std.fmt.bufPrint(&operation, "{s} {s}", .{ found.operation, found.path }) catch
        found.operation;
    errors.cause_host_error(diag, text, found.err, found.errno);
    diag.context("path", "{s}", .{found.path});
    diag.fix(.{
        .sentence = "free space, or point XDG_DATA_HOME at a directory you own with room",
    });
}

/// ZBX-E0712: a volume's record is damaged or newer.
pub fn record_unreadable(diag: *Diag, path: []const u8, newer: bool) void {
    assert(diag.code == null);
    assert(path.len > 0);
    diag.raise(.E0712);
    diag.while_("reading the record of a state volume", .{});
    if (newer) {
        diag.cause("{s} was written by a newer zbx", .{path});
    } else {
        diag.cause("{s} is not a state volume record this zbx can read", .{path});
    }
    diag.context("path", "{s}", .{path});
    diag.fix(.{
        .sentence = "use the zbx that wrote it, or move the record aside (the data is not in it)",
    });
}

/// ZBX-E0713: a step that mounts a volume in the container failed.
pub fn mount_failed(
    diag: *Diag,
    operation: []const u8,
    name: []const u8,
    target: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    diag.raise(.E0713);
    diag.while_("mounting the state volume {s} at {s}", .{ name, target });
    errors.cause_host_error(diag, operation, err, errno);
    if (errno == errno_read_only) {
        diag.cause("the container's root is read-only and has no {s} to mount on", .{target});
        diag.fix(.{ .sentence = "mount the volume at a path the image has, or drop --read-only" });
    }
    diag.context("volume", "{s}", .{name});
    diag.context("target", "{s}", .{target});
    diag.fix(.{ .sentence = "see what this host allows:", .command = "zbx doctor" });
}

const errno_read_only: u16 = 30; // EROFS

/// ZBX-W0702: a volume's size could not be counted; `state ls` shows it as unknown.
pub fn size_unknown(diag: *Diag, name: []const u8, why: []const u8) void {
    assert(diag.code == null);
    assert(why.len > 0);
    diag.raise(.W0702);
    diag.while_("counting the size of the state volume {s}", .{name});
    diag.cause("{s}", .{why});
    diag.context("volume", "{s}", .{name});
    diag.fix(.{ .sentence = "count it by hand from the user's namespace (zbx explain W0702)" });
}

/// ZBX-E0714: `state export` with standard output on a terminal.
pub fn export_to_terminal(diag: *Diag, name: []const u8) void {
    assert(diag.code == null);
    assert(volume.name_problem(name) == null);
    diag.raise(.E0714);
    diag.while_("exporting the state volume {s}", .{name});
    diag.cause("standard output is a terminal, and the archive is binary data", .{});
    diag.context("volume", "{s}", .{name});
    var command: [constants.state_name_bytes_max + 48]u8 = undefined;
    // Cannot fail: a volume name and the fixed words fit the buffer.
    const format = "zbx state export {s} -o {s}.tar.gz";
    const text = std.fmt.bufPrint(&command, format, .{ name, name }) catch unreachable; // Same.
    diag.fix(.{ .sentence = "name a file:", .command = text, .template = true });
    diag.fix(.{ .sentence = "or redirect the output: zbx state export <name> > <name>.tar.gz" });
}

/// ZBX-E0715: the archive could not be written to its file or its output.
pub fn export_write_failed(
    diag: *Diag,
    name: []const u8,
    destination: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(destination.len > 0);
    diag.raise(.E0715);
    diag.while_("exporting the state volume {s}", .{name});
    var operation: [constants.state_volume_path_bytes_max + 64]u8 = undefined;
    const text = std.fmt.bufPrint(&operation, "writing the archive to {s}", .{destination}) catch
        "writing the archive";
    errors.cause_host_error(diag, text, err, errno);
    diag.context("volume", "{s}", .{name});
    diag.context("file", "{s}", .{destination});
    diag.fix(.{ .sentence = "free space, or write somewhere else with -o <file>" });
}

/// ZBX-E0716: the volume's files could not be read into the archive.
pub fn export_read_failed(
    diag: *Diag,
    name: []const u8,
    why: []const u8,
    path: []const u8,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(why.len > 0);
    diag.raise(.E0716);
    diag.while_("exporting the state volume {s}", .{name});
    diag.cause("{s}", .{why});
    var operation: [constants.path_bytes_max + 32]u8 = undefined;
    if (path.len > 0 and err != error.IoFailed) {
        const text = std.fmt.bufPrint(&operation, "reading {s}", .{path}) catch "reading a file";
        errors.cause_host_error(diag, text, err, errno);
    }
    diag.context("volume", "{s}", .{name});
    if (path.len > 0) diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "stop what changes the volume, then export again" });
}

/// ZBX-W0703: a device, socket or fifo left out of the archive; or, with `more`, the count of
/// the others not shown.
pub fn export_skipped(diag: *Diag, path: []const u8, kind: []const u8, more: u64) void {
    assert(diag.code == null);
    diag.raise(.W0703);
    diag.while_("exporting a state volume", .{});
    if (more > 0) {
        diag.cause("{d} more devices, sockets and fifos were left out", .{more});
    } else {
        diag.cause("{s} is a {s}, which the archive does not keep", .{ path, kind });
        diag.context("path", "{s}", .{path});
    }
    diag.fix(.{ .sentence = "nothing to do: the archive holds every other file" });
}
