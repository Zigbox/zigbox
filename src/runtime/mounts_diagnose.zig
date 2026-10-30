//! The diagnostics of the other mounts, `ZBX-E0012`, `E0013`, `E0210` and `E0211`, and of
//! `--mount` (M6b): `E0014`, `E0212` to `E0215`. One function per failure, each with its cause
//! and a fix (DIAGNOSTICS.md). Nothing here decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const mounts = @import("mounts.zig");
const spec_mod = @import("spec.zig");
const plan_mod = @import("plan.zig");

const example =
    "zbx run --tmpfs /scratch:128m --bind /srv/site:/srv nginx";
const example_mount = "zbx run --mount ./site:/srv python:3.12-slim";

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0012: a flag's value that is not a mount zbx can make.
pub fn bad_value(diag: *Diag, kind: mounts.Kind, value: []const u8, reason: []const u8) void {
    assert(diag.code == null);
    assert(reason.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(if (kind == .mount) .E0014 else .E0012);
    diag.while_("reading the command line", .{});
    diag.cause("{s} '{s}': {s}", .{ kind.flag(), echo, reason });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "mounts look like this:",
        .command = if (kind == .mount) example_mount else example,
        .template = true,
    });
}

/// ZBX-E0013: a mount whose path meets another's, or one too many.
pub fn conflict(diag: *Diag, flag: []const u8, value: []const u8, reason: []const u8) void {
    assert(diag.code == null);
    assert(reason.len > 0);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0013);
    diag.while_("reading the command line", .{});
    diag.cause("{s} '{s}': {s}", .{ flag, echo, reason });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "give each mount a path of its own, or drop one" });
}

/// ZBX-E0210: the host path of a bind or a secret is not there, or is not the right kind.
pub fn bad_source(
    diag: *Diag,
    kind: mounts.Kind,
    source: []const u8,
    problem: mounts.SourceProblem,
) void {
    assert(diag.code == null);
    assert(kind != .tmpfs);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, source);
    diag.raise(.E0210);
    diag.while_("looking at the source of {s}", .{kind.flag()});
    diag.cause("{s} {s}: {s}", .{ kind.flag(), echo, problem.sentence() });
    diag.context("path", "{s}", .{echo});
    switch (problem) {
        .missing => diag.fix(.{
            .sentence = "zbx never makes a source: make it, or check the spelling",
        }),
        .unreadable => diag.fix(.{ .sentence = "check that you may look at it" }),
        .not_a_file_or_directory => diag.fix(.{ .sentence = "bind a directory or a file" }),
        .not_a_file => diag.fix(.{ .sentence = "give --secret one file (--bind: a directory)" }),
        .loop, .too_long, .unusable_path, .no_project => unreachable, // A --mount's.
    }
}

/// ZBX-E0214: the source of a `--mount` is not there, or is not the right kind, or the project
/// directory cannot be found. `typed` is the source as given (empty for the project).
pub fn writable_source(
    diag: *Diag,
    typed: []const u8,
    problem: mounts.SourceProblem,
) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, typed);
    diag.raise(.E0214);
    if (problem == .no_project) {
        diag.while_("finding the project directory for --mount", .{});
        diag.cause("--mount: {s}", .{problem.sentence()});
        diag.fix(.{ .sentence = "run zbx from the project's directory" });
        return;
    }
    diag.while_("looking at the source of --mount", .{});
    diag.cause("--mount {s}: {s}", .{ echo, problem.sentence() });
    diag.context("path", "{s}", .{echo});
    switch (problem) {
        .missing => diag.fix(.{
            .sentence = "zbx never makes a source: make it, or check the spelling",
        }),
        .unreadable => diag.fix(.{ .sentence = "check that you may look at it" }),
        .not_a_file_or_directory => diag.fix(.{ .sentence = "mount a directory or a file" }),
        .loop => diag.fix(.{ .sentence = "fix the symbolic links on the way to it" }),
        .too_long, .unusable_path => diag.fix(.{
            .sentence = "move the project to a path without those, or mount a shorter one",
        }),
        .not_a_file, .no_project => unreachable, // Not a --mount's problems / handled above.
    }
}

/// ZBX-E0212: a `--mount` source that, with its links followed, is not the project directory or
/// inside it. `resolved` is where it really is.
pub fn outside_project(
    diag: *Diag,
    typed: []const u8,
    resolved: []const u8,
    project: []const u8,
) void {
    assert(diag.code == null);
    assert(resolved.len > 0);
    assert(project.len > 0);
    var typed_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var resolved_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var project_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const typed_echo = echo_of(&typed_storage, typed);
    const resolved_echo = text_util.sanitise(&resolved_storage, resolved);
    const project_echo = text_util.sanitise(&project_storage, project);
    diag.raise(.E0212);
    diag.while_("checking that --mount {s} is inside the project", .{typed_echo});
    if (project.len == 1) {
        diag.cause("the project directory is /, the whole file system: no --mount is allowed", .{});
        diag.fix(.{ .sentence = "run zbx from the project's directory (the one with zbx.lock)" });
    } else {
        const format = "--mount {s} is {s}, outside the project {s}; " ++
            "a writable mount stays inside it";
        diag.cause(format, .{ typed_echo, resolved_echo, project_echo });
        diag.fix(.{ .sentence = "run zbx from the project's directory" });
        diag.fix(.{
            .sentence = "or give a directory elsewhere read-only:",
            .command = "zbx run --bind /path/to/dir:/dir <image>",
            .template = true,
        });
    }
    diag.context("within", "{s}", .{project_echo});
    diag.context("real", "{s}", .{resolved_echo});
}

/// ZBX-E0213: a `--mount` with a user that is not the container's root. `user_text` may be empty.
pub fn needs_root(diag: *Diag, user_text: []const u8, user: spec_mod.User) void {
    assert(diag.code == null);
    const user_is_root = user.uid == 0 and user.gid == 0;
    assert(!user_is_root);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, user_text);
    diag.raise(.E0213);
    diag.while_("checking the user of a run with --mount", .{});
    if (echo.len > 0) {
        const format = "the container would run as {s} (uid {d}, gid {d}), and what it writes " ++
            "through --mount would belong to an id that is not yours";
        diag.cause(format, .{ echo, user.uid, user.gid });
    } else {
        const format = "the container would run as uid {d}, gid {d}, and what it writes " ++
            "through --mount would belong to an id that is not yours";
        diag.cause(format, .{ user.uid, user.gid });
    }
    diag.context("uid", "{d}", .{user.uid});
    diag.context("gid", "{d}", .{user.gid});
    diag.fix(.{
        .sentence = "run it as root, which is you inside the container:",
        .command = "zbx run --user 0 --mount ./site:/srv <image>",
        .template = true,
    });
    diag.fix(.{
        .sentence = "or give the directory read-only:",
        .command = "zbx run --bind ./site:/srv <image>",
        .template = true,
    });
}

/// ZBX-E0211 (or E0215 for a `--mount`): a step that makes a mount in the container failed.
pub fn mount_failed(
    diag: *Diag,
    operation: []const u8,
    names: plan_mod.MountNames,
    err: host_mod.Error,
    errno: u16,
) void {
    assert(diag.code == null);
    assert(operation.len > 0);
    const flag: []const u8 = switch (names.shape) {
        .tmpfs => "--tmpfs",
        .bind_dir, .bind_file => "--bind",
        .mount_dir, .mount_file => "--mount",
        .secret => "--secret",
    };
    diag.raise(if (names.shape == .mount_dir or names.shape == .mount_file) .E0215 else .E0211);
    diag.while_("mounting {s} at {s}", .{ flag, names.target });
    errors.cause_host_error(diag, operation, err, errno);
    if (errno == errno_read_only) {
        diag.cause("the container's root is read-only and has no {s} to mount on", .{names.target});
        diag.fix(.{ .sentence = "mount at a path the image has, or drop --read-only" });
    }
    if (err == error.FileTooLarge) {
        diag.cause("a secret is copied whole, and this one is longer than {d} bytes", .{
            constants.secret_bytes_max,
        });
        diag.fix(.{ .sentence = "mount it with --bind instead, if the container may read it" });
    }
    if (names.source.len > 0) diag.context("source", "{s}", .{names.source});
    diag.context("target", "{s}", .{names.target});
    diag.fix(.{ .sentence = "see what this host allows:", .command = "zbx doctor" });
}

const errno_read_only: u16 = 30; // EROFS
