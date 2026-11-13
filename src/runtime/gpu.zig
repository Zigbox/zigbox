//! `--gpu all|dri` (M10 slice 3, docs/briefs/M10-gpu.md): what a run that asks for "a GPU" gets.
//!
//! The ask is kept as a keyword in the run's device list (`gpu=all`, `gpu=dri`), so the run
//! record keeps what was asked and a start after a reboot resolves again. At a start the
//! keyword becomes devices:
//!
//! - `dri`: every `/dev/dri/renderD*` the user can open, and `/dev/kfd` (AMD ROCm) when there.
//!   No libraries are mounted: Mesa and ROCm userspace come from the image.
//! - `all`: every `nvidia.com/gpu` CDI device when a spec offers them, else `dri`.
//!
//! The looking is split from the deciding so that Zigcube's agent can do it on its own host and
//! pass the result in: `look_dri` reads the host, `expand` is a pure function of what it found.
//! A node the user cannot open is not given (it would only fail in the workload), and is counted,
//! so that "found nothing" (E0228) can say that nodes were there.

const std = @import("std");
const assert = std.debug.assert;
const cdi = @import("cdi.zig");
const cdi_discover = @import("cdi_discover.zig");
const constants = @import("../constants.zig");
const devices = @import("devices.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Host = host_mod.Host;
const Device = devices.Device;

/// What `--gpu` was given.
pub const Ask = enum {
    all,
    dri,

    /// The keyword as the device list and the run record keep it.
    pub fn text(ask: Ask) []const u8 {
        return switch (ask) {
            .all => "gpu=all",
            .dri => "gpu=dri",
        };
    }

    /// The word the command line takes.
    pub fn word(ask: Ask) []const u8 {
        return switch (ask) {
            .all => "all",
            .dri => "dri",
        };
    }
};

/// The keyword of an asked device, or null when it is a path or a CDI name.
pub fn ask_of(asked: []const u8) ?Ask {
    assert(asked.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, asked, "gpu=all")) return .all;
    if (std.mem.eql(u8, asked, "gpu=dri")) return .dri;
    return null;
}

/// The CDI device `--gpu all` asks for: every device of the `nvidia.com/gpu` kind.
pub const nvidia_all = "nvidia.com/gpu=all";
pub const dri_directory: [:0]const u8 = "/dev/dri";
pub const render_prefix = "renderD";
pub const kfd_path = "/dev/kfd";

/// The render nodes and `/dev/kfd` of the host the user can open, in name order, kfd last.
pub const Dri = struct {
    text: [constants.run_devices_max][constants.device_path_bytes_max]u8,
    lengths: [constants.run_devices_max]u8,
    count: u32,
    /// More openable nodes than a run takes: the ones past the bound are not kept.
    over: bool,
    /// Nodes that are there and that the user cannot open (a group they are not in).
    unopenable: u32,

    pub fn path(dri: *const Dri, index: u32) []const u8 {
        assert(index < dri.count);
        return dri.text[index][0..dri.lengths[index]];
    }

    fn add(dri: *Dri, node: []const u8) void {
        assert(node.len <= constants.device_path_bytes_max);
        assert(devices.path_problem(node) == null);
        if (dri.count == constants.run_devices_max) {
            dri.over = true;
            return;
        }
        @memcpy(dri.text[dri.count][0..node.len], node);
        dri.lengths[dri.count] = @intCast(node.len);
        dri.count += 1;
    }
};

fn name_less(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

/// Looks at the host: `/dev/dri/renderD*` (listed, sorted, each opened-for-real by the kernel's
/// own answer) and `/dev/kfd`. A directory that is not there is a host with no render nodes.
pub fn look_dri(host: Host, out: *Dri) void {
    out.count = 0;
    out.over = false;
    out.unopenable = 0;
    var listing: host_mod.DirListing = undefined;
    var names: [constants.dir_entries_max][]const u8 = undefined;
    var count: usize = 0;
    if (host.list_directory(dri_directory, &listing)) {
        var index: u32 = 0;
        while (index < listing.count) : (index += 1) {
            const name = listing.name(index);
            if (!std.mem.startsWith(u8, name, render_prefix)) continue;
            if (name.len == render_prefix.len) continue;
            names[count] = name;
            count += 1;
        }
    } else |_| {}
    std.mem.sort([]const u8, names[0..count], {}, name_less);
    for (names[0..count]) |name| look_node(host, name, out);
    look_path(host, kfd_path, out);
    assert(out.count <= constants.run_devices_max);
}

fn look_node(host: Host, name: []const u8, out: *Dri) void {
    var path: [constants.device_path_bytes_max + 1]u8 = undefined;
    const prefix = dri_directory ++ "/";
    if (prefix.len + name.len > constants.device_path_bytes_max) return; // Not a path --device takes.
    @memcpy(path[0..prefix.len], prefix);
    @memcpy(path[prefix.len..][0..name.len], name);
    const node = path[0 .. prefix.len + name.len];
    if (devices.path_problem(node) != null) return;
    look_path(host, node, out);
}

fn look_path(host: Host, path: []const u8, out: *Dri) void {
    assert(path.len <= constants.device_path_bytes_max);
    if (devices.look_path(host, path)) |problem| {
        // A node of another kind, or one that is not there, is not a GPU's; one the user cannot
        // open is, and is the usual gap (not in `render`), so it is counted.
        if (std.meta.activeTag(problem) == .cannot_open) out.unopenable += 1;
        return;
    }
    out.add(path);
}

/// What an expansion gave.
pub const Outcome = union(enum) {
    /// `Expanded.slice()` is the run's devices.
    given,
    /// The ask that found nothing, and what was there but not usable.
    nothing: Nothing,
    /// The asked devices and what the keywords gave are more than a run takes.
    too_many,
};

pub const Nothing = struct {
    ask: Ask,
    /// Render nodes and `/dev/kfd` that are there and that the user cannot open.
    unopenable: u32,
    /// A CDI spec could not be read, so an NVIDIA spec may be hidden by it.
    spec_trouble: bool,
};

/// The devices a run takes once its keywords are expanded: the explicit ones as given and the
/// nodes `gpu=dri` gave (their text is kept here).
pub const Expanded = struct {
    items: [constants.run_devices_max]Device,
    count: u32,
    nodes: [constants.run_devices_max][constants.device_path_bytes_max]u8,
    nodes_count: u32,

    pub fn slice(expanded: *const Expanded) []const Device {
        assert(expanded.count <= constants.run_devices_max);
        return expanded.items[0..expanded.count];
    }

    fn has(expanded: *const Expanded, path: []const u8) bool {
        for (expanded.slice()) |item| {
            if (std.mem.eql(u8, item.path, path)) return true;
        }
        return false;
    }

    /// Adds `path` unless the list has it (`--gpu dri --device /dev/dri/renderD128` is one bind).
    /// False when the list is full.
    fn add(expanded: *Expanded, path: []const u8) bool {
        if (expanded.has(path)) return true;
        if (expanded.count == constants.run_devices_max) return false;
        expanded.items[expanded.count] = .{ .path = path };
        expanded.count += 1;
        return true;
    }

    /// Adds a node the expansion made up: its text is copied into the list's own.
    fn add_node(expanded: *Expanded, path: []const u8) bool {
        assert(path.len <= constants.device_path_bytes_max);
        if (expanded.has(path)) return true;
        if (expanded.count == constants.run_devices_max) return false;
        const slot = &expanded.nodes[expanded.nodes_count];
        @memcpy(slot[0..path.len], path);
        expanded.nodes_count += 1;
        return expanded.add(slot[0..path.len]);
    }
};

/// Turns the asked devices into the run's: a path or a CDI name stays, a keyword becomes what it
/// stands for. `nvidia` says a spec offers `nvidia.com/gpu` devices (`probe_nvidia`), `dri` what
/// the host has (`look_dri`); `spec_trouble` that a spec could not be read. Pure: nothing here
/// looks at the host, so a caller that resolved those on another host can give them in.
pub fn expand(
    asked: []const Device,
    nvidia: bool,
    dri: *const Dri,
    spec_trouble: bool,
    out: *Expanded,
) Outcome {
    assert(asked.len <= constants.run_devices_max);
    assert(dri.count <= constants.run_devices_max);
    out.count = 0;
    out.nodes_count = 0;
    for (asked) |device| {
        const ask = ask_of(device.path) orelse {
            if (!out.add(device.path)) return .too_many;
            continue;
        };
        const given: bool = if (ask == .all and nvidia) true else dri.count > 0;
        if (!given) return .{ .nothing = .{
            .ask = ask,
            .unopenable = dri.unopenable,
            .spec_trouble = spec_trouble,
        } };
        if (ask == .all and nvidia) {
            if (!out.add(nvidia_all)) return .too_many;
            continue;
        }
        if (dri.over) return .too_many;
        var index: u32 = 0;
        while (index < dri.count) : (index += 1) {
            if (!out.add_node(dri.path(index))) return .too_many;
        }
    }
    assert(out.count > 0 or asked.len == 0);
    return .given;
}

/// What looking for NVIDIA devices in the CDI specs found.
pub const Probe = enum {
    /// A spec offers `nvidia.com/gpu` devices and the host has what they name.
    offered,
    /// No spec has any.
    absent,
    /// None, and a spec file could not be used (it may have been the NVIDIA one).
    trouble,
    /// A spec offers them and they cannot be used: `diag` says why (E0225, E0227, ...).
    refused,
};

/// Resolves `nvidia.com/gpu=all` against the host's specs only to learn whether it works. The
/// run resolves again with its real list; the cost is reading the specs twice. A refusal that
/// says "there are none" is not one: the answer is `absent` or `trouble` and `diag` is left
/// clean. Any other refusal is the answer the user needs and stays raised.
pub fn probe_nvidia(host: Host, diag: *Diag) Probe {
    assert(diag.code == null);
    var scratch: cdi_discover.Scratch = undefined;
    var found: cdi.Resolved = undefined;
    const asked = [_][]const u8{nvidia_all};
    if (cdi_discover.resolve(host, &asked, &scratch, &found, diag)) return .offered;
    const code = diag.code.?;
    if (code == .E0230) {
        diag.reset();
        return .absent;
    }
    if (code == .E0226) {
        diag.reset();
        return .trouble;
    }
    return .refused;
}

const testing = std.testing;

fn dri_of(paths: []const []const u8, unopenable: u32) Dri {
    var dri: Dri = undefined;
    dri.count = 0;
    dri.over = false;
    dri.unopenable = unopenable;
    for (paths) |path| dri.add(path);
    return dri;
}

test "expand: a path and a CDI name stay, dri gives the nodes, repeats are one bind" {
    // Goal: keywords become devices, everything else passes, and a node asked twice (once as
    // itself, once by `gpu=dri`) is bound once. Method: pure inputs, no host.
    const dri = dri_of(&.{ "/dev/dri/renderD128", "/dev/dri/renderD129", "/dev/kfd" }, 0);
    var out: Expanded = undefined;
    const asked = [_]Device{
        .{ .path = "/dev/dri/renderD129" },
        .{ .path = "vendor.com/gpu=0" },
        .{ .path = "gpu=dri" },
    };
    try testing.expectEqual(Outcome.given, expand(&asked, false, &dri, false, &out));
    try testing.expectEqual(@as(u32, 4), out.count);
    try testing.expectEqualStrings("/dev/dri/renderD129", out.slice()[0].path);
    try testing.expectEqualStrings("vendor.com/gpu=0", out.slice()[1].path);
    try testing.expectEqualStrings("/dev/dri/renderD128", out.slice()[2].path);
    try testing.expectEqualStrings("/dev/kfd", out.slice()[3].path);
}

test "expand: all is NVIDIA when a spec offers it, else dri, else nothing" {
    // Goal: the rule of the brief. Method: each of the three situations.
    const dri = dri_of(&.{"/dev/dri/renderD128"}, 0);
    const empty = dri_of(&.{}, 2);
    var out: Expanded = undefined;
    const asked = [_]Device{.{ .path = "gpu=all" }};
    try testing.expectEqual(Outcome.given, expand(&asked, true, &dri, false, &out));
    try testing.expectEqual(@as(u32, 1), out.count);
    try testing.expectEqualStrings(nvidia_all, out.slice()[0].path);
    try testing.expectEqual(Outcome.given, expand(&asked, false, &dri, false, &out));
    try testing.expectEqualStrings("/dev/dri/renderD128", out.slice()[0].path);
    const none = expand(&asked, false, &empty, true, &out);
    try testing.expectEqual(Ask.all, none.nothing.ask);
    try testing.expectEqual(@as(u32, 2), none.nothing.unopenable);
    try testing.expect(none.nothing.spec_trouble);
    const only_dri = [_]Device{.{ .path = "gpu=dri" }};
    try testing.expectEqual(Ask.dri, expand(&only_dri, true, &empty, false, &out).nothing.ask);
}

test "expand: the bound is the run's device limit, at it and one past" {
    // Goal: a host with many nodes cannot push a run past `run_devices_max`. Method: fill the
    // list to the bound with explicit devices and a dri list that fits exactly, then one more.
    var texts: [constants.run_devices_max + 1][constants.device_path_bytes_max]u8 = undefined;
    var paths: [constants.run_devices_max + 1][]const u8 = undefined;
    for (&texts, &paths, 0..) |*text, *path, at| {
        const made = std.fmt.bufPrint(text, "/dev/dri/renderD{d}", .{128 + at}) catch unreachable;
        path.* = made; // "/dev/dri/renderD144" fits 48 bytes.
    }
    const exact = dri_of(paths[0..constants.run_devices_max], 0);
    var out: Expanded = undefined;
    const asked = [_]Device{.{ .path = "gpu=dri" }};
    try testing.expectEqual(Outcome.given, expand(&asked, false, &exact, false, &out));
    try testing.expectEqual(constants.run_devices_max, out.count);
    var over = exact;
    over.add(paths[constants.run_devices_max]);
    try testing.expect(over.over);
    try testing.expectEqual(Outcome.too_many, expand(&asked, false, &over, false, &out));
    // One explicit device and a full dri list: 17.
    const explicit = [_]Device{ .{ .path = "vendor.com/gpu=0" }, .{ .path = "gpu=dri" } };
    try testing.expectEqual(Outcome.too_many, expand(&explicit, false, &exact, false, &out));
}

test "ask_of reads only the two keywords" {
    // Goal: a path or a CDI name is never taken for a keyword.
    try testing.expectEqual(@as(?Ask, .all), ask_of("gpu=all"));
    try testing.expectEqual(@as(?Ask, .dri), ask_of("gpu=dri"));
    try testing.expectEqual(@as(?Ask, null), ask_of("gpu=0"));
    try testing.expectEqual(@as(?Ask, null), ask_of("nvidia.com/gpu=all"));
    try testing.expectEqual(@as(?Ask, null), ask_of("/dev/dri/gpu=all"));
    try testing.expectEqual(@as(?Ask, null), ask_of(""));
}
