//! The VM's size: how many virtual CPUs and how much memory it boots with. `zbx vm config` writes
//! it, every boot reads it. The record is a small versioned text file in the user's Library:
//!
//!     zbx-vm-settings/2
//!     cpus=4
//!     memory_bytes=2147483648
//!     disk_bytes=68719476736
//!
//! Version 1, which this release reads, has no `disk_bytes`: it means the default disk.
//!
//! `parse` accepts only what `render` writes (same bounds, same order, nothing after), so a
//! damaged file is refused, never half-read. A newer version is refused too: this release does
//! not guess at a format it does not know.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Settings = struct {
    cpus: u32,
    memory_bytes: u64,
    disk_bytes: u64 = constants.vm_disk_bytes_default,
};

pub const header = "zbx-vm-settings/2\n";
/// The header of the first version, read and never written.
pub const header_v1 = "zbx-vm-settings/1\n";

/// The size used when nothing is set: the default CPU count, or half the Mac's if fewer.
pub fn defaults(host_cpus: u32) Settings {
    assert(host_cpus >= 1);
    const half = @max(@divFloor(host_cpus, 2), 1);
    const cpus = @min(constants.vm_cpus_default, half);
    assert(cpus >= constants.vm_cpus_min);
    return .{
        .cpus = cpus,
        .memory_bytes = constants.vm_memory_bytes_default,
        .disk_bytes = constants.vm_disk_bytes_default,
    };
}

/// Why a size is refused.
pub const Problem = enum {
    cpus_below,
    cpus_above,
    memory_below,
    memory_above,
    memory_unaligned,
    disk_below,
    disk_above,
    disk_unaligned,
    /// Not a number, or not a size: nothing to compare with the bounds.
    not_a_size,
};

/// The sizes this Mac allows: the named constants, the framework's, and the Mac's own.
pub const Bounds = struct {
    cpus_min: u32,
    cpus_max: u32,
    memory_bytes_min: u64,
    memory_bytes_max: u64,
    /// The disk is a sparse file: only the constants limit it, not the framework or the Mac.
    disk_bytes_min: u64 = constants.vm_disk_bytes_min,
    disk_bytes_max: u64 = constants.vm_disk_bytes_max,
};

/// Memory is at most this share of the Mac's, in sixteenths, so the Mac keeps room to work.
pub const host_memory_sixteenths: u64 = 12;

/// The tightest of the three sources of limits. `framework_*` are what Virtualization.framework
/// reports; the host's are its CPU count and its memory in bytes.
pub fn bounds_of(framework: Bounds, host_cpus: u32, host_memory_bytes: u64) Bounds {
    assert(host_cpus >= 1);
    assert(host_memory_bytes > 0);
    const host_share = @divFloor(host_memory_bytes, 16) * host_memory_sixteenths;
    const result: Bounds = .{
        .cpus_min = @max(constants.vm_cpus_min, framework.cpus_min),
        .cpus_max = @min(@min(constants.vm_cpus_max, framework.cpus_max), host_cpus),
        .memory_bytes_min = @max(constants.vm_memory_bytes_min, framework.memory_bytes_min),
        .memory_bytes_max = @min(
            @min(constants.vm_memory_bytes_max, framework.memory_bytes_max),
            host_share,
        ),
    };
    assert(result.cpus_min >= 1);
    return result;
}

pub fn check(settings: Settings, bounds: Bounds) ?Problem {
    if (settings.cpus < bounds.cpus_min) return .cpus_below;
    if (settings.cpus > bounds.cpus_max) return .cpus_above;
    if (settings.memory_bytes % (1 << 20) != 0) return .memory_unaligned;
    if (settings.memory_bytes < bounds.memory_bytes_min) return .memory_below;
    if (settings.memory_bytes > bounds.memory_bytes_max) return .memory_above;
    if (settings.disk_bytes % (1 << 20) != 0) return .disk_unaligned;
    if (settings.disk_bytes < bounds.disk_bytes_min) return .disk_below;
    if (settings.disk_bytes > bounds.disk_bytes_max) return .disk_above;
    return null;
}

pub const record_bytes_max: u32 = 160;

pub fn render(buffer: []u8, settings: Settings) []const u8 {
    assert(buffer.len >= record_bytes_max);
    assert(settings.cpus >= constants.vm_cpus_min);
    assert(settings.cpus <= constants.vm_cpus_max);
    assert(settings.memory_bytes >= constants.vm_memory_bytes_min);
    assert(settings.memory_bytes <= constants.vm_memory_bytes_max);
    assert(settings.disk_bytes >= constants.vm_disk_bytes_min);
    assert(settings.disk_bytes <= constants.vm_disk_bytes_max);
    // Cannot fail: the header and three numbers of at most twenty digits fit.
    return std.fmt.bufPrint(buffer, "{s}cpus={d}\nmemory_bytes={d}\ndisk_bytes={d}\n", .{
        header, settings.cpus, settings.memory_bytes, settings.disk_bytes,
    }) catch unreachable; // Cannot fail: the buffer is asserted to hold the longest record.
}

pub const ParseError = error{ Malformed, NewerVersion };

/// A record in the form `render` writes, with sizes in the constants' range (the machine's own
/// limits are checked when the VM boots, because they can change: another Mac, other memory).
pub fn parse(text: []const u8) ParseError!Settings {
    assert(header.len == header_v1.len); // Both versions' first lines are skipped the same way.
    if (text.len > record_bytes_max) return error.Malformed;
    if (is_other_version(text)) return error.NewerVersion;
    const version_one = std.mem.startsWith(u8, text, header_v1);
    if (!version_one and !std.mem.startsWith(u8, text, header)) return error.Malformed;
    var lines = std.mem.splitScalar(u8, text[header.len..], '\n');
    const cpus_text = value_of(lines.next() orelse return error.Malformed, "cpus=") orelse
        return error.Malformed;
    const memory_text = value_of(lines.next() orelse return error.Malformed, "memory_bytes=") orelse
        return error.Malformed;
    var disk_bytes: u64 = constants.vm_disk_bytes_default;
    if (!version_one) {
        const disk_line = lines.next() orelse return error.Malformed;
        const disk_text = value_of(disk_line, "disk_bytes=") orelse return error.Malformed;
        disk_bytes = number(u64, disk_text) orelse return error.Malformed;
    }
    const last = lines.next() orelse return error.Malformed;
    if (last.len != 0) return error.Malformed;
    if (lines.next() != null) return error.Malformed;
    const cpus = number(u32, cpus_text) orelse return error.Malformed;
    const memory = number(u64, memory_text) orelse return error.Malformed;
    if (cpus < constants.vm_cpus_min or cpus > constants.vm_cpus_max) return error.Malformed;
    if (memory < constants.vm_memory_bytes_min) return error.Malformed;
    if (memory > constants.vm_memory_bytes_max) return error.Malformed;
    if (memory % (1 << 20) != 0) return error.Malformed;
    if (disk_bytes < constants.vm_disk_bytes_min) return error.Malformed;
    if (disk_bytes > constants.vm_disk_bytes_max) return error.Malformed;
    if (disk_bytes % (1 << 20) != 0) return error.Malformed;
    return .{ .cpus = cpus, .memory_bytes = memory, .disk_bytes = disk_bytes };
}

/// True if the first line is `zbx-vm-settings/` and a version number that is not 1 or 2.
fn is_other_version(text: []const u8) bool {
    const name = "zbx-vm-settings/";
    if (!std.mem.startsWith(u8, text, name)) return false;
    const line_end = std.mem.indexOfScalar(u8, text, '\n') orelse return false;
    const version = text[name.len..line_end];
    if (number(u32, version) == null) return false;
    return !std.mem.eql(u8, version, "1") and !std.mem.eql(u8, version, "2");
}

fn value_of(line: []const u8, key: []const u8) ?[]const u8 {
    assert(key.len > 0);
    if (!std.mem.startsWith(u8, line, key)) return null;
    return line[key.len..];
}

/// A decimal number as `render` writes it: digits only, no sign, no leading zero.
fn number(comptime T: type, text: []const u8) ?T {
    if (text.len == 0) return null;
    if (text.len > 1 and text[0] == '0') return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(T, text, 10) catch null;
}

const wide: Bounds = .{
    .cpus_min = 1,
    .cpus_max = 64,
    .memory_bytes_min = 128 << 20,
    .memory_bytes_max = 1 << 40,
};

test "defaults are four CPUs, or half the Mac's if fewer" {
    // Goal: the documented default. Method: the host sizes around the boundary.
    try std.testing.expectEqual(@as(u32, 4), defaults(8).cpus);
    try std.testing.expectEqual(@as(u32, 4), defaults(16).cpus);
    try std.testing.expectEqual(@as(u32, 3), defaults(6).cpus);
    try std.testing.expectEqual(@as(u32, 1), defaults(2).cpus);
    try std.testing.expectEqual(@as(u32, 1), defaults(1).cpus);
    try std.testing.expectEqual(@as(u64, 2 << 30), defaults(8).memory_bytes);
}

test "bounds take the tightest of the constants, the framework and the Mac" {
    // Goal: no source of limits is ignored. Method: each source in turn is the tightest.
    const host_memory: u64 = 24 << 30;
    const base = bounds_of(wide, 8, host_memory);
    try std.testing.expectEqual(@as(u32, 8), base.cpus_max); // The Mac's CPUs.
    try std.testing.expectEqual(@as(u64, 18 << 30), base.memory_bytes_max); // Three quarters.
    try std.testing.expectEqual(constants.vm_memory_bytes_min, base.memory_bytes_min);
    var framework = wide;
    framework.cpus_max = 6;
    framework.memory_bytes_max = 8 << 30;
    framework.memory_bytes_min = 1 << 30;
    const tight = bounds_of(framework, 8, host_memory);
    try std.testing.expectEqual(@as(u32, 6), tight.cpus_max);
    try std.testing.expectEqual(@as(u64, 8 << 30), tight.memory_bytes_max);
    try std.testing.expectEqual(@as(u64, 1 << 30), tight.memory_bytes_min);
    try std.testing.expectEqual(@as(u32, 64), bounds_of(wide, 128, 1 << 50).cpus_max);
}

test "a size is checked at each bound and one past it" {
    // Goal: the boundary where a size becomes invalid. Method: every edge of both numbers.
    const bounds = bounds_of(wide, 8, 24 << 30);
    const ok: Settings = .{ .cpus = 4, .memory_bytes = 2 << 30 };
    try std.testing.expect(check(ok, bounds) == null);
    try std.testing.expect(check(.{ .cpus = 1, .memory_bytes = ok.memory_bytes }, bounds) == null);
    try std.testing.expect(check(.{ .cpus = 8, .memory_bytes = ok.memory_bytes }, bounds) == null);
    const memory = ok.memory_bytes;
    const none: Settings = .{ .cpus = 0, .memory_bytes = memory };
    try std.testing.expectEqual(Problem.cpus_below, check(none, bounds).?);
    const many: Settings = .{ .cpus = 9, .memory_bytes = memory };
    try std.testing.expectEqual(Problem.cpus_above, check(many, bounds).?);
    const low = constants.vm_memory_bytes_min;
    try std.testing.expect(check(.{ .cpus = 4, .memory_bytes = low }, bounds) == null);
    const below: Settings = .{ .cpus = 4, .memory_bytes = low - (1 << 20) };
    try std.testing.expectEqual(Problem.memory_below, check(below, bounds).?);
    const high = bounds.memory_bytes_max;
    try std.testing.expect(check(.{ .cpus = 4, .memory_bytes = high }, bounds) == null);
    const above: Settings = .{ .cpus = 4, .memory_bytes = high + (1 << 20) };
    try std.testing.expectEqual(Problem.memory_above, check(above, bounds).?);
    const odd: Settings = .{ .cpus = 4, .memory_bytes = low + 1 };
    try std.testing.expectEqual(Problem.memory_unaligned, check(odd, bounds).?);
    const disk_low = constants.vm_disk_bytes_min;
    const disk_high = constants.vm_disk_bytes_max;
    const at_low: Settings = .{ .cpus = 4, .memory_bytes = memory, .disk_bytes = disk_low };
    const at_high: Settings = .{ .cpus = 4, .memory_bytes = memory, .disk_bytes = disk_high };
    try std.testing.expect(check(at_low, bounds) == null);
    try std.testing.expect(check(at_high, bounds) == null);
    const disk_small: Settings = .{
        .cpus = 4,
        .memory_bytes = memory,
        .disk_bytes = disk_low - (1 << 20),
    };
    try std.testing.expectEqual(Problem.disk_below, check(disk_small, bounds).?);
    const disk_big: Settings = .{
        .cpus = 4,
        .memory_bytes = memory,
        .disk_bytes = disk_high + (1 << 20),
    };
    try std.testing.expectEqual(Problem.disk_above, check(disk_big, bounds).?);
    const disk_odd: Settings = .{ .cpus = 4, .memory_bytes = memory, .disk_bytes = disk_low + 1 };
    try std.testing.expectEqual(Problem.disk_unaligned, check(disk_odd, bounds).?);
}

test "the record round-trips and parse refuses everything render does not write" {
    // Goal: parse accepts only what render writes. Method: a round trip over the corners of the
    // range, then text damaged in each way (header, order, sign, leading zero, range, tail).
    var buffer: [record_bytes_max]u8 = @splat(0xaa);
    const corners = [_]Settings{
        .{ .cpus = constants.vm_cpus_min, .memory_bytes = constants.vm_memory_bytes_min },
        .{ .cpus = constants.vm_cpus_max, .memory_bytes = constants.vm_memory_bytes_max },
        .{ .cpus = 4, .memory_bytes = 2 << 30 },
        .{ .cpus = 4, .memory_bytes = 2 << 30, .disk_bytes = constants.vm_disk_bytes_min },
        .{ .cpus = 4, .memory_bytes = 2 << 30, .disk_bytes = constants.vm_disk_bytes_max },
    };
    for (corners) |settings| {
        const text = render(&buffer, settings);
        try std.testing.expectEqual(settings, try parse(text));
    }
    const bad = [_][]const u8{
        "",
        "zbx-vm-settings/1\n",
        "zbx-vm-settings/1\ncpus=4\n",
        "zbx-vm-settings/1\nmemory_bytes=2147483648\ncpus=4\n",
        "zbx-vm-settings/1\ncpus=04\nmemory_bytes=2147483648\n",
        "zbx-vm-settings/1\ncpus=+4\nmemory_bytes=2147483648\n",
        "zbx-vm-settings/1\ncpus=0\nmemory_bytes=2147483648\n",
        "zbx-vm-settings/1\ncpus=65\nmemory_bytes=2147483648\n",
        "zbx-vm-settings/1\ncpus=4\nmemory_bytes=2147483649\n",
        "zbx-vm-settings/1\ncpus=4\nmemory_bytes=1048576\n",
        "zbx-vm-settings/1\ncpus=4\nmemory_bytes=2147483648",
        "zbx-vm-settings/1\ncpus=4\nmemory_bytes=2147483648\nx\n",
        "zbx-vm-settings/1\r\ncpus=4\nmemory_bytes=2147483648\n",
    };
    for (bad) |text| try std.testing.expectError(error.Malformed, parse(text));
    const bad_two = [_][]const u8{
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\n",
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=1073741823\n",
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=536870912\n",
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=9223372036854775808\n",
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=01073741824\n",
        "zbx-vm-settings/2\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=1073741824\nx\n",
    };
    for (bad_two) |text| try std.testing.expectError(error.Malformed, parse(text));
    const newer = "zbx-vm-settings/3\ncpus=4\nmemory_bytes=2147483648\ndisk_bytes=1073741824\n";
    try std.testing.expectError(error.NewerVersion, parse(newer));
}

test "a settings record written by a real zbx reads back" {
    // Goal: the fixture is real output (REVIEW.md). Method: the text below is the file
    // `zbx vm config --cpus 2 --memory 1536M` wrote on 2026-10-29 (version 1 of the record).
    const written = "zbx-vm-settings/1\ncpus=2\nmemory_bytes=1610612736\n";
    const values = try parse(written);
    const expected: Settings = .{ .cpus = 2, .memory_bytes = 1536 << 20 };
    try std.testing.expectEqual(expected, values);
    // Version 1 is only read: what is written back is version 2, with the default disk.
    var buffer: [record_bytes_max]u8 = undefined;
    const upgraded = "zbx-vm-settings/2\ncpus=2\nmemory_bytes=1610612736\ndisk_bytes=68719476736\n";
    try std.testing.expectEqualStrings(upgraded, render(&buffer, values));
    try std.testing.expectEqual(values, try parse(upgraded));
}
