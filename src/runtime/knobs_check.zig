//! The parent's check of a run's workload knobs, before anything is created: a library caller's
//! values against the bounds the flags are held to, each `--ulimit` against the invoking user's
//! own hard limit, `--shm-size` against `--memory` or the host's `MemTotal`, and the sysctls
//! against the allowlist and the run's network (docs/briefs/M2b-workload-knobs.md).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const knobs = @import("knobs.zig");
const knobs_diagnose = @import("knobs_diagnose.zig");

const Host = host_mod.Host;

pub const Error = error{StartFailed};

/// The parts of a run's spec the knobs depend on.
pub const Input = struct {
    rlimits: knobs.Rlimits,
    sysctls: []const knobs.Sysctl,
    shm_bytes: ?u64,
    memory_bytes: ?u64,
    /// Whether the run has a network namespace of its own.
    isolated: bool,
};

pub fn check(host: Host, input: Input, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(input.sysctls.len <= std.math.maxInt(u32));
    try check_rlimits(host, input.rlimits, diag);
    if (input.shm_bytes) |shm_bytes| try check_shm(host, shm_bytes, input.memory_bytes, diag);
    if (input.sysctls.len > 0) {
        if (knobs.list_problem(input.sysctls, input.isolated)) |problem| {
            knobs_diagnose.sysctl_invalid(diag, input.sysctls, problem);
            return error.StartFailed;
        }
    }
    assert(diag.code == null);
}

/// Each limit asked for: soft at most hard, and hard at most the caller's own. The caller's are
/// read here, before anything starts, as `prlimit64` gives them.
fn check_rlimits(host: Host, rlimits: knobs.Rlimits, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (rlimits.problem()) |resource| {
        var buffer: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&buffer, "{s}=", .{@tagName(resource)}) catch
            unreachable; // The longest name is 7 bytes.
        knobs_diagnose.ulimit_invalid(diag, name, .soft_above_hard);
        return error.StartFailed;
    }
    if (rlimits.nofile) |nofile| {
        // A library caller's `unlimited` nofile, which the flag's parser already refuses.
        if (nofile.hard == knobs.unlimited) {
            knobs_diagnose.ulimit_invalid(diag, "nofile=", .nofile_unlimited);
            return error.StartFailed;
        }
    }
    for (std.enums.values(knobs.Resource)) |resource| {
        const asked = rlimits.get(resource) orelse continue;
        // A limit that can't be read can't be checked, and the child's set would then fail
        // late with less to say, so the run is refused here, before anything is created.
        const own = host.get_rlimit(resource) catch |err| {
            var buffer: [48]u8 = undefined;
            const operation = std.fmt.bufPrint(&buffer, "reading your {s} limit (prlimit64)", .{
                @tagName(resource),
            }) catch unreachable; // The longest name is 7 bytes.
            const errno = host.last_errno();
            knobs_diagnose.rlimit_failed(diag, operation, .read, resource, err, errno);
            return error.StartFailed;
        };
        assert(own.soft <= own.hard);
        if (asked.hard > own.hard) {
            knobs_diagnose.ulimit_above_hard(diag, resource, asked.hard, own.hard, host.uid());
            return error.StartFailed;
        }
    }
}

fn check_shm(host: Host, shm_bytes: u64, memory_bytes: ?u64, diag: *Diag) Error!void {
    assert(diag.code == null);
    var buffer: [24]u8 = undefined;
    // Cannot fail: a u64 has at most 20 digits and the buffer holds 24.
    const text = std.fmt.bufPrint(&buffer, "{d}", .{shm_bytes}) catch unreachable;
    if (shm_bytes < constants.shm_bytes_min) {
        knobs_diagnose.shm_invalid(diag, text, .below_page, constants.shm_bytes_min);
        return error.StartFailed;
    }
    // Without `--memory`, the bound is the host's memory, and a host whose `MemTotal` can't be
    // read is refused (docs/decisions/2026-11-16-m2b-knob-bounds.md). With it, unused.
    const host_bytes = if (memory_bytes != null) 1 else mem_total(host) orelse {
        knobs_diagnose.shm_invalid(diag, text, .host_unknown, 0);
        return error.StartFailed;
    };
    const found = knobs.shm_problem(shm_bytes, memory_bytes, host_bytes) orelse return;
    const bound = memory_bytes orelse host_bytes;
    const issue: knobs_diagnose.ShmIssue = switch (found) {
        .above_memory => .above_memory,
        .above_host => .above_host,
    };
    knobs_diagnose.shm_invalid(diag, text, issue, bound);
    return error.StartFailed;
}

/// The host's memory in bytes, from `MemTotal` in `/proc/meminfo`; null if it can't be read.
pub fn mem_total(host: Host) ?u64 {
    var buffer: [constants.meminfo_bytes_max]u8 = undefined;
    const text = host.read_file("/proc/meminfo", &buffer) catch return null;
    return parse_mem_total(text);
}

/// `MemTotal:       16303372 kB` among the lines of `/proc/meminfo`, in bytes.
pub fn parse_mem_total(text: []const u8) ?u64 {
    assert(text.len <= constants.meminfo_bytes_max);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var words = std.mem.tokenizeScalar(u8, line["MemTotal:".len..], ' ');
        const number = words.next() orelse return null;
        const unit = words.next() orelse return null;
        if (!std.mem.eql(u8, unit, "kB")) return null;
        const kibibytes = std.fmt.parseUnsigned(u64, number, 10) catch return null;
        const bytes = std.math.mul(u64, kibibytes, 1024) catch return null;
        if (bytes == 0) return null;
        return bytes;
    }
    return null;
}

const testing = std.testing;

test "parse_mem_total: the line, in bytes, and every malformed form refused" {
    // Goal: the kernel's form reads exactly; anything else is unreadable, never a guess.
    const good = "MemFree:  100 kB\nMemTotal:       16303372 kB\nMemAvailable: 1 kB\n";
    try testing.expectEqual(@as(?u64, 16303372 * 1024), parse_mem_total(good));
    try testing.expectEqual(@as(?u64, null), parse_mem_total(""));
    try testing.expectEqual(@as(?u64, null), parse_mem_total("MemTotal: 12\n"));
    try testing.expectEqual(@as(?u64, null), parse_mem_total("MemTotal: 12 MB\n"));
    try testing.expectEqual(@as(?u64, null), parse_mem_total("MemTotal: x kB\n"));
    try testing.expectEqual(@as(?u64, null), parse_mem_total("MemTotal: 0 kB\n"));
    const huge = "MemTotal: 99999999999999999999 kB\n";
    try testing.expectEqual(@as(?u64, null), parse_mem_total(huge));
}
