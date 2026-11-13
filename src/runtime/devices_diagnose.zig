//! The diagnostics of `--device` (M10 slice 1): `ZBX-E0225` for a device that is refused, and
//! `ZBX-W0209` for the note that the groups carry over. One function per failure, each with its
//! cause and a fix (DIAGNOSTICS.md). Nothing here decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const devices = @import("devices.zig");
const gpu = @import("gpu.zig");

const example = "zbx run --device /dev/dri/renderD128 <image>";

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(text.len <= constants.arg_bytes_max);
    assert(storage.len == constants.arg_echo_bytes_max);
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

/// ZBX-E0225: the devices asked and the nodes `--gpu dri` found are more than a run takes. The
/// cause is the host's node count, not a `--device` the user gave, so it says so and names the
/// way out: ask for the nodes one by one.
pub fn too_many_gpu_nodes(diag: *Diag, count: u32) void {
    assert(diag.code == null);
    assert(count <= constants.run_devices_max + 1);
    diag.raise(.E0225);
    diag.while_("giving the GPUs to the container", .{});
    diag.cause("--gpu dri found render nodes that, with the other devices asked for, are more " ++
        "than the {d} devices a run takes", .{constants.run_devices_max});
    diag.context("limit", "{d}", .{constants.run_devices_max});
    diag.fix(.{
        .sentence = "name the nodes you want, instead of --gpu dri (zbx doctor lists them):",
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

/// ZBX-E0228: `--gpu` found nothing to give. Names what was looked for, what was there and not
/// usable, and sends the user to `zbx doctor` for each gap.
pub fn no_gpu(diag: *Diag, nothing: gpu.Nothing) void {
    assert(diag.code == null);
    const word = nothing.ask.word();
    diag.raise(.E0228);
    diag.while_("looking for a GPU for --gpu {s}", .{word});
    const looked = switch (nothing.ask) {
        .all => "no nvidia.com/gpu device in the CDI specs ($XDG_CONFIG_HOME/cdi, " ++
            "/var/run/cdi, /etc/cdi), and no render node (/dev/dri/renderD*) or /dev/kfd " ++
            "that you can open",
        .dri => "no render node (/dev/dri/renderD*) or /dev/kfd that you can open",
    };
    diag.cause("{s}", .{looked});
    if (nothing.unopenable > 0) {
        diag.cause("{d} found, none openable by you: you are not in their group", .{
            nothing.unopenable,
        });
    }
    if (nothing.spec_trouble) {
        diag.cause("a CDI spec could not be used, and it may be the one with the GPU", .{});
    }
    diag.context("gpu", "{s}", .{word});
    diag.fix(.{
        .sentence = "see what this host has, and the fix for each gap:",
        .command = "zbx doctor",
    });
    assert(diag.code.? == .E0228);
}

/// ZBX-E0225: a `--gpu` value that is not `all` or `dri` (read from the command line).
pub fn bad_gpu(diag: *Diag, value: []const u8) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, value);
    diag.raise(.E0225);
    diag.while_("reading the command line", .{});
    diag.cause("--gpu '{s}': it is 'all' (every NVIDIA GPU, else the render nodes) or 'dri' " ++
        "(the render nodes)", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give all or dri:",
        .command = "zbx run --gpu all <image>",
        .template = true,
    });
    assert(diag.code.? == .E0225);
}
