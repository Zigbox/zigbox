//! The diagnostics of the other mounts, `ZBX-E0012`, `E0013`, `E0210` and `E0211`: one function
//! per failure, each with its cause and a fix (DIAGNOSTICS.md). Nothing here decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const errors = @import("../diag/errors.zig");
const mounts = @import("mounts.zig");
const plan_mod = @import("plan.zig");

const example =
    "zbx run --tmpfs /scratch:128m --bind /srv/site:/srv nginx";

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
    diag.raise(.E0012);
    diag.while_("reading the command line", .{});
    diag.cause("{s} '{s}': {s}", .{ kind.flag(), echo, reason });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "mounts look like this:",
        .command = example,
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
    }
}

/// ZBX-E0211: a step that makes a mount in the container failed.
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
        .secret => "--secret",
    };
    diag.raise(.E0211);
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
