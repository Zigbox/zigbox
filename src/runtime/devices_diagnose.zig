//! The diagnostics of `--device` (M10 slice 1): `ZBX-E0225` for a device that is refused, and
//! `ZBX-W0209` for the note that the groups carry over. One function per failure, each with its
//! cause and a fix (DIAGNOSTICS.md). Nothing here decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const devices = @import("devices.zig");

const example = "zbx run --device /dev/dri/renderD128 <image>";

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max);
    return text_util.sanitise(storage, text);
}

/// ZBX-E0225: a `--device` whose value is not a path zbx takes (read from the command line).
pub fn bad_path(diag: *Diag, value: []const u8, problem: devices.ListProblem) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0225);
    diag.while_("reading the command line", .{});
    diag.cause("--device '{s}': {s}", .{ echo, problem.sentence() });
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give the path of a device node below /dev, once each:",
        .command = example,
        .template = true,
    });
    assert(diag.code.? == .E0225);
}

/// ZBX-E0225: a device node the host shows that cannot be bound, with what the host said.
pub fn refused(diag: *Diag, path: []const u8, problem: devices.NodeProblem) void {
    assert(diag.code == null);
    assert(devices.path_problem(path) == null);
    diag.raise(.E0225);
    diag.while_("looking at the device {s}", .{path});
    switch (problem) {
        .missing => diag.cause("{s} is not on this host", .{path}),
        .unreadable => diag.cause("{s} could not be looked at", .{path}),
        .not_character => |node| diag.cause(
            "{s} is a {s}, not a character device",
            .{ path, if (node.kind() == .block) "block device" else "file of another kind" },
        ),
        .cannot_open => |node| diag.cause(
            "you cannot open {s} for reading and writing: mode {o:0>4}, owner {d}, group {d}{s}",
            .{
                path,
                node.mode & 0o7777,
                node.uid,
                node.gid,
                if (node.member) " (you are in that group)" else " (you are not in that group)",
            },
        ),
    }
    diag.context("device", "{s}", .{path});
    switch (problem) {
        .cannot_open => |node| {
            diag.context("mode", "{o:0>4}", .{node.mode & 0o7777});
            diag.context("group", "{d}", .{node.gid});
            diag.fix(.{
                .sentence = "ask whoever runs this host to put you in the node's group, or to " ++
                    "change its mode; zbx never changes either",
            });
        },
        else => diag.fix(.{
            .sentence = "list the nodes the host has, and give one of them:",
            .command = "ls -l /dev/dri",
        }),
    }
    assert(diag.code.? == .E0225);
}

/// ZBX-W0209: the groups carry over and show as `nogroup` inside the container.
pub fn groups_note(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.W0209);
    diag.while_("starting the container", .{});
    diag.cause("a run with devices keeps your groups; inside the container they show as " ++
        "'nogroup', and the host's file permissions still decide who may open each device", .{});
    diag.fix(.{ .sentence = "nothing to do; the groups work, only their names are not shown" });
    assert(diag.code.? == .W0209);
}
