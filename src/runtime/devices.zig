//! Host devices of a run (M10 slice 1, docs/briefs/M10-gpu.md): `--device /dev/<path>`. A
//! character device the user can open, bound into the container's `/dev` at the same path. This
//! file holds what is true of them without a kernel (how a path is read, the text the run record
//! keeps) and how a node on the host is looked at before a container is made. The steps that
//! bind them are the plan's (`plan.zig`, `create_user_device` and `bind_user_device`).
//!
//! Access is the host's file permissions: a rootless container has no device cgroup, so a node
//! is reachable exactly when the user could open it on the host. That is why a run with devices
//! keeps the user's supplementary groups (ZBX-W0209), and why a node the user cannot open is
//! refused here, with its mode and group, instead of failing in the workload.
//!
//! A path holds no ':', quote, backslash, space, control or non-ASCII byte and no '..': every
//! part is a name, so that the run record keeps the paths in one string separated by spaces, with
//! nothing to escape.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const plan_mod = @import("plan.zig");
const cdi = @import("cdi.zig");

const Host = host_mod.Host;

/// One device as given: its path on the host, which is its path in the container.
pub const Device = struct {
    path: []const u8,
};

/// Why a path is not one `--device` takes.
pub const Problem = enum {
    not_under_dev,
    too_long,
    unusable_byte,
    dot_dot,
    /// One of M1's six, or a name the container's `/dev` has for another purpose.
    reserved,
    /// Not a path and not a CDI name `vendor/class=name` either.
    bad_name,

    pub fn sentence(problem: Problem) []const u8 {
        assert(@tagName(problem).len > 0);
        return switch (problem) {
            .not_under_dev => "only a device node below /dev can be given",
            .too_long => "the path is longer than 48 bytes",
            .unusable_byte => "the path has a quote, a backslash, a ':', a space, or a byte " ++
                "that is not printable ASCII",
            .dot_dot => "the path has a '..' part",
            .reserved => "every container has that one already",
            .bad_name => "it is neither a path below /dev nor a CDI name like vendor.com/class=name",
        };
    }
};

/// Whether `path` is a path `--device` takes, by its text alone.
pub fn path_problem(path: []const u8) ?Problem {
    const prefix = "/dev/";
    if (path.len > constants.device_path_bytes_max) return .too_long;
    if (!std.mem.startsWith(u8, path, prefix)) return .not_under_dev;
    if (path.len == prefix.len) return .not_under_dev;
    for (path) |byte| {
        const escaped = byte == '"' or byte == '\\';
        if (escaped or byte == ':' or byte <= ' ' or byte >= 0x7f) return .unusable_byte;
    }
    var parts = std.mem.splitScalar(u8, path[prefix.len..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) return .not_under_dev;
        if (std.mem.eql(u8, part, "..")) return .dot_dot;
    }
    return if (is_reserved(path)) .reserved else null;
}

/// M1's six devices, the container's own `/dev/shm`, `/dev/pts` and links, and the hidden names
/// the runtime stages mounts at. A `--device` there would be bound over or under them.
fn is_reserved(path: []const u8) bool {
    assert(path.len > "/dev/".len);
    assert(std.mem.startsWith(u8, path, "/dev/"));
    const first = path["/dev/".len..];
    const head = first[0 .. std.mem.indexOfScalar(u8, first, '/') orelse first.len];
    for (plan_mod.devices) |name| {
        if (std.mem.eql(u8, head, name)) return true;
    }
    for (plan_mod.links) |link| {
        if (std.mem.eql(u8, head, link.name)) return true;
    }
    if (std.mem.eql(u8, head, "shm") or std.mem.eql(u8, head, "pts")) return true;
    return head.len > 0 and head[0] == '.'; // The stages: `.zbx-mount-0`, `.zbx-state-0`, ...
}

/// What is wrong with the devices of a run as a list, or null: at most `run_devices_max`, each
/// path fit, and none given twice. The text does not see a path inside another (`/dev/dri` and
/// `/dev/dri/card0`): `resolve` refuses it, since a directory is not a character device.
pub const ListProblem = union(enum) {
    path: struct { index: u32, problem: Problem },
    too_many,
    repeated: u32,
    /// All the devices together are longer than the run record keeps.
    too_long,

    /// The device at fault, or null when the list as a whole is.
    pub fn index(problem: ListProblem) ?u32 {
        return switch (problem) {
            .path => |found| found.index,
            .repeated => |at| at,
            .too_many, .too_long => null,
        };
    }

    pub fn sentence(problem: ListProblem) []const u8 {
        assert(@backingInt(std.meta.activeTag(problem)) <= 3);
        assert(constants.run_devices_max == 16); // The text below says 16.
        return switch (problem) {
            .path => |found| found.problem.sentence(),
            .too_many => "a run takes at most 16 devices",
            .repeated => "it was given twice",
            .too_long => "the devices together are longer than 896 bytes",
        };
    }
};

/// Whether a device is a host path (`/dev/...`), as against a CDI name (`vendor/class=name`).
pub fn is_path(asked: []const u8) bool {
    assert(asked.len <= constants.cdi_name_bytes_max or asked.len > 0);
    return std.mem.startsWith(u8, asked, "/dev/");
}

/// What is wrong with one device as asked, by its text alone.
pub fn asked_problem(asked: []const u8) ?Problem {
    if (is_path(asked)) return path_problem(asked);
    if (std.mem.indexOfScalar(u8, asked, '=') == null) return path_problem(asked);
    return if (cdi.split_qualified(asked) == null) .bad_name else null;
}

pub fn list_problem(devices: []const Device) ?ListProblem {
    if (devices.len > constants.run_devices_max) return .too_many;
    var total: usize = 0;
    for (devices, 0..) |device, index| {
        total += device.path.len + 1;
        if (total > text_bytes_max + 1) return .too_long;
        if (asked_problem(device.path)) |problem| {
            return .{ .path = .{ .index = @intCast(index), .problem = problem } };
        }
        for (devices[0..index]) |before| {
            if (std.mem.eql(u8, before.path, device.path)) return .{ .repeated = @intCast(index) };
        }
    }
    assert(devices.len <= constants.run_devices_max);
    return null;
}

/// The longest text `text` writes: every path and a space after each.
/// A CDI name is longer than a path, so the whole list is bounded as text, not by the product.
pub const text_bytes_max = constants.run_devices_text_bytes_max;

/// The paths as the run record keeps them: `/dev/a /dev/b`, one string.
pub fn text(devices: []const Device, buffer: *[text_bytes_max]u8) []const u8 {
    assert(list_problem(devices) == null);
    var at: usize = 0;
    for (devices, 0..) |device, index| {
        if (index > 0) {
            buffer[at] = ' ';
            at += 1;
        }
        @memcpy(buffer[at..][0..device.path.len], device.path);
        at += device.path.len;
    }
    assert(at <= text_bytes_max);
    return buffer[0..at];
}

// ---- Looking at the host --------------------------------------------------------------------

/// Why a node on the host cannot be bound.
pub const NodeProblem = union(enum) {
    missing,
    /// `stat` failed for another reason (a permission on the way, a loop).
    unreadable,
    /// Not a character device: its kind and mode.
    not_character: host_mod.DeviceNode,
    /// A character device the user cannot open for reading and writing.
    cannot_open: host_mod.DeviceNode,
};

/// Looks at a device node with the kernel's own answer (`Host.device_node`). Nothing is made.
pub fn look(host: Host, device: *const Device) ?NodeProblem {
    return look_path(host, device.path);
}

/// `look` for a path as text, which is what a node of a CDI spec is.
pub fn look_path(host: Host, path: []const u8) ?NodeProblem {
    assert(path.len <= constants.cdi_path_bytes_max);
    assert(path.len > 0);
    const node = host.device_node(path) catch |err| {
        return if (err == error.NotFound) .missing else .unreadable;
    };
    if (node.kind() != .character) return .{ .not_character = node };
    if (!node.can_open) return .{ .cannot_open = node };
    return null;
}

/// The first device of the list that cannot be bound, with why.
pub const Refusal = struct { index: u32, problem: NodeProblem };

pub fn resolve(host: Host, devices: []const Device) ?Refusal {
    assert(list_problem(devices) == null);
    assert(devices.len <= constants.run_devices_max);
    for (devices, 0..) |*device, index| {
        if (!is_path(device.path)) continue; // A CDI name: its nodes are looked at with the spec.
        if (look(host, device)) |problem| return .{ .index = @intCast(index), .problem = problem };
    }
    return null;
}

/// The plan's input for the devices: the paths.
pub fn plan_input(
    devices: []const Device,
    out: *[constants.run_devices_max][]const u8,
) []const []const u8 {
    assert(list_problem(devices) == null);
    var count: usize = 0;
    for (devices) |device| {
        if (!is_path(device.path)) continue; // A CDI name becomes nodes with its spec.
        out[count] = device.path;
        count += 1;
    }
    return out[0..count];
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "paths: the rules" {
    // Goal: the text of a path alone decides whether `--device` takes it, and why not.
    try testing.expectEqual(@as(?Problem, null), path_problem("/dev/dri/renderD128"));
    try testing.expectEqual(@as(?Problem, null), path_problem("/dev/nvidiactl"));
    try testing.expectEqual(Problem.not_under_dev, path_problem("/dev"));
    try testing.expectEqual(Problem.not_under_dev, path_problem("/dev/"));
    try testing.expectEqual(Problem.not_under_dev, path_problem("/etc/passwd"));
    try testing.expectEqual(Problem.not_under_dev, path_problem("dev/null"));
    try testing.expectEqual(Problem.not_under_dev, path_problem("/dev/dri//x"));
    try testing.expectEqual(Problem.dot_dot, path_problem("/dev/../etc/passwd"));
    try testing.expectEqual(Problem.unusable_byte, path_problem("/dev/a b"));
    try testing.expectEqual(Problem.unusable_byte, path_problem("/dev/a:b"));
    try testing.expectEqual(Problem.unusable_byte, path_problem("/dev/a\"b"));
    try testing.expectEqual(Problem.unusable_byte, path_problem("/dev/a\\b"));
    try testing.expectEqual(Problem.unusable_byte, path_problem("/dev/\xc3\xa9"));
    try testing.expectEqual(Problem.reserved, path_problem("/dev/null"));
    try testing.expectEqual(Problem.reserved, path_problem("/dev/shm/x"));
    try testing.expectEqual(Problem.reserved, path_problem("/dev/pts"));
    try testing.expectEqual(Problem.reserved, path_problem("/dev/stdout"));
    try testing.expectEqual(Problem.reserved, path_problem("/dev/.zbx-mount-0"));
    const long = "/dev/" ++ repeat('x', constants.device_path_bytes_max);
    try testing.expectEqual(Problem.too_long, path_problem(long));
    // At the bound: exactly `device_path_bytes_max` bytes is taken, one more is not.
    const exact = "/dev/" ++ repeat('x', constants.device_path_bytes_max - "/dev/".len);
    try testing.expectEqual(constants.device_path_bytes_max, exact.len);
    try testing.expectEqual(@as(?Problem, null), path_problem(exact));
    try testing.expectEqual(Problem.too_long, path_problem(exact ++ "x"));
}

test "list: bound, repeats, and the record text" {
    // Goal: a list is refused when too long or repeating, and its text reads back as the paths.
    const one: Device = .{ .path = "/dev/dri/card0" };
    const two: Device = .{ .path = "/dev/dri/renderD128" };
    try testing.expectEqual(@as(?ListProblem, null), list_problem(&.{ one, two }));
    try testing.expectEqual(ListProblem{ .repeated = 1 }, list_problem(&.{ one, one }).?);
    var many: [constants.run_devices_max + 1]Device = undefined;
    for (&many) |*device| device.* = one;
    try testing.expectEqual(ListProblem.too_many, list_problem(&many).?);
    var buffer: [text_bytes_max]u8 = undefined;
    const both = text(&.{ one, two }, &buffer);
    try testing.expectEqualStrings("/dev/dri/card0 /dev/dri/renderD128", both);
    try testing.expectEqualStrings("", text(&.{}, &buffer));
}

test "list: CDI names are taken, the total text is bounded" {
    // Goal: a qualified name passes by its text, a bad one is named, and the sum is bounded.
    const gpu: Device = .{ .path = "vendor.com/gpu=0" };
    try testing.expectEqual(@as(?ListProblem, null), list_problem(&.{gpu}));
    const bad: Device = .{ .path = "vendor.com/gpu=" };
    try testing.expectEqual(Problem.bad_name, list_problem(&.{bad}).?.path.problem);
    const odd: Device = .{ .path = "not-a-device" };
    try testing.expectEqual(Problem.not_under_dev, list_problem(&.{odd}).?.path.problem);
    try testing.expect(!is_path(gpu.path));
    var out: [constants.run_devices_max][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), plan_input(&.{gpu}, &out).len);
    // A list that fills the text exactly is taken; one byte more is not.
    var names: [14][64]u8 = undefined;
    var many: [14]Device = undefined;
    for (&many, &names, 0..) |*device, *buf, at| {
        const head = "vendor.com/gpu=";
        @memcpy(buf[0..head.len], head);
        @memset(buf[head.len..], 'a');
        buf[62] = @as(u8, 'a') + @as(u8, @intCast(at)); // 63 bytes each, all different.
        device.* = .{ .path = buf[0..63] };
    }
    try testing.expectEqual(@as(?ListProblem, null), list_problem(&many)); // 14 * 64 = 896.
    var buffer: [text_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 14 * 64 - 1), text(&many, &buffer).len);
}
