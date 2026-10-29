//! The diagnostics of images, locks and running by name (05xx): each function raises one
//! registered code and fills in the causes, context and fixes (DIAGNOSTICS.md). The code that
//! decides things reports the facts; nothing in it formats text for a user.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const errors = @import("diag/errors.zig");
const fs_mod = @import("store/fs.zig");
const lock_file = @import("lock_file.zig");
const text_util = @import("text.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;
const Sha256 = @import("registry/digest.zig").Sha256;

const echo_bytes_max = 96;

fn echo_of(storage: *[echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max * 4);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0517: the image's configuration blob is not usable.
pub fn config_refused(diag: *Diag, config: Sha256, problem: []const u8) void {
    assert(diag.code == null);
    assert(problem.len > 0);
    diag.raise(.E0517);
    diag.while_("reading the image's configuration", .{});
    diag.cause("the configuration {s} {s}", .{ &config.text(), problem });
    diag.context("config", "{s}", .{&config.text()});
    diag.fix(.{ .sentence = "try another tag of the image, or tell its publisher" });
}

/// ZBX-E0518: `zbx.lock` can't be read. `problem` null: the file could not be read at all.
pub fn lock_unreadable(diag: *Diag, path: []const u8, problem: ?lock_file.Problem) void {
    assert(diag.code == null);
    assert(path.len > 0);
    diag.raise(.E0518);
    diag.while_("reading the lock file", .{});
    if (problem) |found| {
        const what = switch (found.kind) {
            .unknown_line => "is not a line of a lock file",
            .bad_value => "has a value that is not what that field holds",
            .incomplete_entry => "begins an entry that lacks a field (or repeats one)",
            .no_version => "the file has no .version",
            .newer => "has a newer version than this zbx reads",
            .duplicate => "repeats an image that an earlier entry has",
            .too_big => "is past the entries a lock holds",
        };
        if (found.line > 0) {
            diag.cause("'{s}' line {d} {s}", .{ path, found.line, what });
        } else {
            diag.cause("'{s}': {s}", .{ path, what });
        }
        diag.context("line", "{d}", .{found.line});
    } else {
        diag.cause("'{s}' could not be read, or is longer than {d} bytes", .{
            path, constants.lock_file_bytes_max,
        });
    }
    diag.context("path", "{s}", .{path});
    diag.fix_with("remove the lock and pull again to write a new one:", "rm '{s}'", .{path});
}

/// The diagnostic for a lock that could not be opened or saved.
pub fn lock_failure(diag: *Diag, path: []const u8, failure: lock_file.Failure) void {
    assert(diag.code == null);
    switch (failure) {
        .no_directory => lock_not_written(diag, lock_file.file_name, &.{
            .err = error.NotFound,
            .errno = 0,
        }),
        .unreadable => lock_unreadable(diag, path, null),
        .problem => |problem| lock_unreadable(diag, path, problem),
        .full => lock_unreadable(diag, path, .{ .kind = .too_big, .line = 0 }),
        .write => |written| lock_not_written(diag, path, &written),
    }
    assert(diag.code != null);
}

/// ZBX-E0519: the lock's tree and the store's record of the locked manifest differ.
pub fn lock_mismatch(
    diag: *Diag,
    reference: []const u8,
    path: []const u8,
    expected: Digest,
    actual: Digest,
) void {
    assert(diag.code == null);
    assert(!expected.eql(actual));
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, reference);
    diag.raise(.E0519);
    diag.while_("checking {s} against the lock", .{echo});
    diag.cause("zbx.lock has tree {s}; the store has tree {s}", .{
        expected.text(), actual.text(),
    });
    diag.context("ref", "{s}", .{echo});
    diag.context("expect", "{s}", .{expected.text()});
    diag.context("actual", "{s}", .{actual.text()});
    diag.context("path", "{s}", .{path});
    diag.fix_with(
        "to take the store's image, pull again and let the lock follow:",
        "zbx pull '{s}'",
        .{echo},
    );
    diag.fix(.{ .sentence = "or put the tree the lock names back, from version control" });
}

/// ZBX-E0520: the manifest the lock names has no image in the store. `found` is the manifest of
/// another image the store has under the reference, if any.
pub fn locked_absent(
    diag: *Diag,
    reference: []const u8,
    path: []const u8,
    expected: Sha256,
    found: ?Sha256,
    pull_by_digest: []const u8,
) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, reference);
    diag.raise(.E0520);
    diag.while_("checking {s} against the lock", .{echo});
    if (found) |actual| {
        diag.cause("zbx.lock wants manifest {s}; the store has {s}", .{
            &expected.text(), &actual.text(),
        });
        diag.context("actual", "{s}", .{&actual.text()});
    } else {
        diag.cause("zbx.lock wants manifest {s}, which the store does not have", .{
            &expected.text(),
        });
        diag.context("actual", "none", .{});
    }
    diag.context("ref", "{s}", .{echo});
    diag.context("expect", "{s}", .{&expected.text()});
    diag.context("path", "{s}", .{path});
    diag.fix_with("fetch the locked image:", "zbx pull '{s}'", .{pull_by_digest});
}

/// ZBX-E0521: a user or group name the image's files do not have.
pub fn unknown_user(diag: *Diag, name: []const u8, file: []const u8, is_group: bool) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, name);
    diag.raise(.E0521);
    diag.while_("choosing the user the image runs as", .{});
    const kind = if (is_group) "group" else "user";
    diag.cause("the image runs as {s} '{s}', which {s} in the image has no entry for", .{
        kind, echo, file,
    });
    if (is_group) diag.context("group", "{s}", .{echo}) else diag.context("user", "{s}", .{echo});
    diag.context("file", "{s}", .{file});
    diag.fix(.{ .sentence = "the image's configuration is wrong; try another tag of it" });
}

/// ZBX-E0522: nothing by that name is locked or in the store. `lock_path` is null when there is
/// no lock file to look in.
pub fn not_locked(diag: *Diag, name: []const u8, lock_path: ?[]const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, name);
    diag.raise(.E0522);
    diag.while_("finding the image '{s}'", .{echo});
    if (lock_path) |path| {
        diag.cause("'{s}' has no entry for '{s}'", .{ path, echo });
        diag.context("path", "{s}", .{path});
    } else {
        diag.cause("no image in the store was pulled as '{s}'", .{echo});
    }
    diag.context("ref", "{s}", .{echo});
    diag.fix_with("pull it (this also records it in zbx.lock):", "zbx pull '{s}'", .{echo});
}

/// ZBX-E0523: the image's user needs the full id map and the run has the single one.
pub fn needs_id_map(diag: *Diag, uid: u32, gid: u32) void {
    assert(diag.code == null);
    diag.raise(.E0523);
    diag.while_("setting the user the image runs as", .{});
    diag.cause("the image runs as user {d}, group {d}, and this run maps only root", .{
        uid, gid,
    });
    diag.context("uid", "{d}", .{uid});
    diag.context("gid", "{d}", .{gid});
    diag.fix(.{
        .sentence = "give your account id ranges and the helpers; the doctor shows how:",
        .command = "zbx doctor",
    });
}

/// ZBX-E0524: no entrypoint, no command, none given.
pub fn no_command(diag: *Diag, name: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, name);
    diag.raise(.E0524);
    diag.while_("choosing what '{s}' runs", .{echo});
    diag.cause("the image sets no entrypoint and no command, and none was given", .{});
    diag.context("image", "{s}", .{echo});
    diag.fix_with("say what to run:", "zbx run '{s}' -- <command> [arguments]", .{echo});
    diag.mark_last_fix_template();
}

/// ZBX-E0526: `zbx lock show` found no `zbx.lock`. `directory` is where one would be made.
pub fn no_lock(diag: *Diag, directory: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, directory);
    diag.raise(.E0526);
    diag.while_("reading zbx.lock", .{});
    diag.cause("there is no zbx.lock in '{s}' or any directory above it", .{echo});
    diag.context("dir", "{s}", .{echo});
    diag.fix(.{
        .sentence = "pull an image from the project directory; that makes the lock:",
        .command = "zbx pull alpine:3.20",
        .template = true,
    });
}

/// ZBX-E0525: `zbx.lock` could not be written.
pub fn lock_not_written(diag: *Diag, path: []const u8, failure: *const fs_mod.Failure) void {
    assert(diag.code == null);
    assert(path.len > 0);
    diag.raise(.E0525);
    diag.while_("writing the lock file", .{});
    var operation: [echo_bytes_max + 16]u8 = undefined;
    var shown: [echo_bytes_max]u8 = undefined;
    const words = std.fmt.bufPrint(&operation, "writing '{s}'", .{echo_of(&shown, path)}) catch
        "writing the lock file"; // The path is cut to fit.
    errors.cause_host_error(diag, words, failure.err, failure.errno);
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "make the directory writable, then run the command again" });
}

/// ZBX-W0503: a run found no lock and made one.
pub fn lock_created(diag: *Diag, reference: []const u8, path: []const u8) void {
    assert(diag.code == null);
    var storage: [echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, reference);
    diag.raise(.W0503);
    diag.while_("finding the project's lock file", .{});
    diag.cause("no zbx.lock in the working directory or above; pulled '{s}' and wrote '{s}'", .{
        echo, path,
    });
    diag.context("path", "{s}", .{path});
    diag.fix(.{ .sentence = "commit it, so every machine runs the same image" });
}
