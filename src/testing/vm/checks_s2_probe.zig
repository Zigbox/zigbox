//! The S2 probe's assertions (docs/briefs/S2-lazy-start.md, slice 1) as pure functions over what
//! the guest script printed, each with a unit test fed wrong text. The script and the commands
//! are in main_s2_probe.zig; the server is s2_probe/fuse_probe.zig.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// A check the brief asks for printed no `ok` line, or printed `FAIL`.
    CheckFailed,
    /// A fact the brief asks the probe to report is missing.
    ReportMissing,
};

/// Every check the brief's slice 1 names, as the script names them.
pub const checks_required = [_][]const u8{
    "fuse mount",
    "overlay mount",
    "read as uid 0 through the overlay",
    "16 MiB read through the overlay",
    "read as uid 1000 through the overlay",
    "read as uid 1000 on the FUSE mount",
    "copy-up",
    "lower unchanged",
    "new file in the upper",
    "lower is read-only",
    "EIO reaches cat",
    "ENOTCONN after kill",
};

/// The facts the report must carry: the kernel, /dev/fuse's mode, AppArmor's userns setting and
/// the latency of a first 1 MiB read.
pub const reports_required = [_][]const u8{
    "probe: kernel: ",
    "probe: /dev/fuse: ",
    "probe: apparmor_restrict_unprivileged_userns: ",
    "probe: latency uncached: ",
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    assert(wanted.len > 0);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

fn has_line_starting(text: []const u8, prefix: []const u8) bool {
    assert(prefix.len > 0);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, raw, " \r\t"), prefix)) return true;
    }
    return false;
}

/// The probe passed: exit 0, every required check printed `ok`, none printed `FAIL`, the
/// closing line is there, and every fact the brief asks for was reported.
pub fn check_probe(output: []const u8, status: u8) Error!void {
    if (status != 0) return error.CheckFailed;
    if (std.mem.indexOf(u8, output, ": FAIL") != null) return error.CheckFailed;
    var line_buffer: [128]u8 = undefined;
    for (checks_required) |name| {
        const line = std.fmt.bufPrint(&line_buffer, "probe: {s}: ok", .{name}) catch
            unreachable; // Every name is under 100 bytes; the buffer holds it and the frame.
        if (!has_line(output, line)) return error.CheckFailed;
    }
    if (!has_line(output, "probe: all ok")) return error.CheckFailed;
    for (reports_required) |prefix| {
        if (!has_line_starting(output, prefix)) return error.ReportMissing;
    }
}

fn passing_output(buffer: []u8) []const u8 {
    assert(buffer.len >= 4096); // The whole passing output is under 1 KiB.
    var writer: std.Io.Writer = .fixed(buffer);
    for (reports_required) |prefix| {
        writer.print("{s}x\n", .{prefix}) catch unreachable; // The buffer holds it all.
    }
    for (checks_required) |name| {
        writer.print("probe: {s}: ok\n", .{name}) catch unreachable; // The buffer holds it all.
    }
    writer.writeAll("probe: all ok\n") catch unreachable; // The buffer holds it all.
    return writer.buffered();
}

test "a full probe output passes" {
    // Goal: the check accepts what a passing script prints. Method: build that text from the
    // lists the check reads, so the test and the check cannot disagree on a name.
    var buffer: [4096]u8 = undefined;
    try check_probe(passing_output(&buffer), 0);
}

test "a missing check, a FAIL, a missing report or a non-zero exit is refused" {
    // Goal: each way the probe can fail is caught. Method: damage a passing output one way at
    // a time.
    var buffer: [4096]u8 = undefined;
    const good = passing_output(&buffer);
    try std.testing.expectError(error.CheckFailed, check_probe(good, 1));
    var damaged: [4096]u8 = undefined;
    const eio = "probe: EIO reaches cat: ok\n";
    const at = std.mem.indexOf(u8, good, eio).?;
    @memcpy(damaged[0..at], good[0..at]);
    const rest = good[at + eio.len ..];
    @memcpy(damaged[at..][0..rest.len], rest);
    try std.testing.expectError(error.CheckFailed, check_probe(damaged[0 .. at + rest.len], 0));
    var with_fail: [4200]u8 = undefined;
    const failed = try std.fmt.bufPrint(&with_fail, "{s}probe: copy-up: FAIL (x)\n", .{good});
    try std.testing.expectError(error.CheckFailed, check_probe(failed, 0));
    // The latency line is the last report and comes first after the others: drop the reports.
    const latency_line = "probe: latency uncached: x\n";
    const latency = std.mem.indexOf(u8, good, latency_line).?;
    const no_reports = good[latency + latency_line.len ..];
    try std.testing.expectError(error.ReportMissing, check_probe(no_reports, 0));
}
