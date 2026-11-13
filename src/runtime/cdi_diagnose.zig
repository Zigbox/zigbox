//! The diagnostics of CDI devices (M10 slice 2): `ZBX-E0226` for a spec that cannot be used,
//! `ZBX-E0227` for an edit Zigbox does not apply, `ZBX-E0230` for a name no spec has, and
//! `ZBX-W0208` for the libraries put on `LD_LIBRARY_PATH`. One function per failure, each with
//! its cause and a fix (DIAGNOSTICS.md). Nothing here decides.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const text_util = @import("../text.zig");
const Diag = @import("../diag/diag.zig").Diag;
const cdi = @import("cdi.zig");

const generate = "nvidia-ctk cdi generate --format=json --output=/etc/cdi/nvidia.json";
const directories = "/etc/cdi, /var/run/cdi and $XDG_CONFIG_HOME/cdi";

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    assert(storage.len == constants.arg_echo_bytes_max);
    return text_util.sanitise(storage, text[0..@min(text.len, constants.arg_bytes_max)]);
}

/// ZBX-E0226: a spec file that cannot be used, or a mount or node of one that the host lacks.
pub fn spec_unusable(diag: *Diag, found: *const cdi.FileProblem) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const file = echo_of(&storage, found.file());
    diag.raise(.E0226);
    diag.while_("reading the CDI specs in {s}", .{directories});
    diag.cause("{s}: {s} (at {s})", .{ file, found.problem.sentence(), found.field.text() });
    diag.context("file", "{s}", .{file});
    diag.context("field", "{s}", .{found.field.text()});
    if (found.problem == .yaml) {
        diag.fix(.{ .sentence = "write the spec as JSON:", .command = generate });
    } else if (found.problem == .stale or found.problem == .node) {
        diag.fix(.{ .sentence = "write the spec again for this host:", .command = generate });
    } else {
        diag.fix(.{ .sentence = "correct the file, or move it out of the CDI directories" });
    }
    assert(diag.code.? == .E0226);
}

/// ZBX-E0226 for what a spec names and the host lacks: the thing, and the spec's device.
pub fn host_lacks(diag: *Diag, problem: cdi.Problem, what: []const u8, device: []const u8) void {
    assert(diag.code == null);
    assert(switch (problem) {
        .stale, .node => true,
        else => false,
    });
    var what_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var device_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&what_storage, what);
    const named = echo_of(&device_storage, device);
    diag.raise(.E0226);
    diag.while_("looking at what the CDI device {s} needs", .{named});
    diag.cause("{s}: {s}", .{ echo, problem.sentence() });
    diag.context("device", "{s}", .{named});
    diag.context("path", "{s}", .{echo});
    diag.fix(.{ .sentence = "write the spec again for this host:", .command = generate });
    assert(diag.code.? == .E0226);
}

/// ZBX-E0226 for devices whose edits together are more than a run holds (`Resolved`).
pub fn too_big(diag: *Diag, device: []const u8) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const named = echo_of(&storage, device);
    diag.raise(.E0226);
    diag.while_("resolving the CDI device {s}", .{named});
    diag.cause("the devices ask for more nodes, mounts or variables than one run takes", .{});
    diag.context("device", "{s}", .{named});
    diag.fix(.{ .sentence = "ask for fewer devices, or trim the spec of the ones asked for" });
    assert(diag.code.? == .E0226);
}

/// ZBX-E0227: an asked device whose spec has an edit Zigbox does not apply.
pub fn unsupported(diag: *Diag, device: []const u8, edit: cdi.Unsupported, name: []const u8) void {
    assert(diag.code == null);
    assert(edit != .none);
    var device_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    var name_storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const named = echo_of(&device_storage, device);
    const echo = echo_of(&name_storage, name);
    diag.raise(.E0227);
    diag.while_("applying the CDI device {s}", .{named});
    if (echo.len > 0) {
        diag.cause("its spec has {s}: {s}", .{ edit.sentence(), echo });
    } else {
        diag.cause("its spec has {s}", .{edit.sentence()});
    }
    diag.context("device", "{s}", .{named});
    diag.context("edit", "{s}", .{edit.sentence()});
    if (edit == .read_only_mounts) {
        diag.fix(.{
            .sentence = "run without --read-only, or pass the node as a path:",
            .command = "zbx run --device /dev/nvidia0 <image>",
            .template = true,
        });
        assert(diag.code.? == .E0227);
        return;
    }
    diag.fix(.{
        .sentence = "ask a device that needs only device nodes, mounts, environment " ++
            "variables and nvidia-cdi-hook update-ldcache, or pass the node as a path:",
        .command = "zbx run --device /dev/nvidia0 <image>",
        .template = true,
    });
    assert(diag.code.? == .E0227);
}

/// ZBX-E0230: a name no spec has, with the names the specs do have (up to the bound).
pub fn unknown(diag: *Diag, device: []const u8, resolver: *const cdi.Resolver) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const named = echo_of(&storage, device);
    diag.raise(.E0230);
    diag.while_("looking for the CDI device {s}", .{named});
    diag.context("device", "{s}", .{named});
    var list: [400]u8 = undefined;
    var at: usize = 0;
    var index: u32 = 0;
    while (index < resolver.known_count) : (index += 1) {
        const known = resolver.known_name(index);
        const room = list.len - at;
        if (known.len + 2 > room) break;
        if (at > 0) {
            list[at] = ' ';
            at += 1;
        }
        @memcpy(list[at..][0..known.len], known);
        at += known.len;
    }
    if (at > 0) {
        diag.cause("no spec in {s} has it; the specs have: {s}", .{ directories, list[0..at] });
        diag.context("known", "{s}", .{list[0..at]});
        diag.fix(.{ .sentence = "give one of the devices the specs have" });
    } else {
        diag.cause("no spec in {s} has it", .{directories});
        diag.fix(.{ .sentence = "write the host's CDI spec first:", .command = generate });
    }
    assert(diag.code.? == .E0230);
}

/// ZBX-W0208: the image cannot build the library cache, so the directories are on the path.
pub fn no_ldconfig(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.W0208);
    diag.while_("starting the container", .{});
    diag.cause("the image has no usable ldconfig (or its root is read-only), so the driver " ++
        "libraries are found through LD_LIBRARY_PATH instead of the library cache", .{});
    diag.fix(.{ .sentence = "nothing to do for an image that finds them; a musl image such " ++
        "as Alpine cannot load glibc driver libraries, use a glibc image" });
    assert(diag.code.? == .W0208);
}

/// ZBX-E0226 for CDI directories that hold more spec files than a run reads.
pub fn too_many_files(diag: *Diag, directory: []const u8) void {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const named = echo_of(&storage, directory);
    diag.raise(.E0226);
    diag.while_("reading the CDI specs in {s}", .{directories});
    diag.cause("{s} brings the CDI spec files past {d}, the most a run reads", .{
        named,
        constants.cdi_dir_entries_max,
    });
    diag.context("dir", "{s}", .{named});
    diag.fix(.{ .sentence = "move the specs this host does not use out of the CDI directories" });
    assert(diag.code.? == .E0226);
}

/// ZBX-E0227: `--read-only` with a CDI device whose spec has mounts.
pub fn read_only_mounts(diag: *Diag, device: []const u8) void {
    unsupported(diag, device, .read_only_mounts, "");
}
