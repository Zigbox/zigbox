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

/// What the probe printed in the VM run after the review fixes
/// (https://github.com/Zigbox/zigbox/actions/runs/43636460487), with the `ls` lines dropped and
/// each line cut to 92 bytes and its trailing spaces dropped, for the line rules.
const recorded_output =
    \\probe: kernel: 6.8.0-147-generic
    \\probe: /dev/fuse: 666 root:root
    \\probe: apparmor_restrict_unprivileged_userns: 0
    \\probe: user: 1000 demo
    \\probe: subordinate ids: uid 100000 gid 100000, 65536 each
    \\probe: uid_map:  0 1000 1; 1 100000 65536;
    \\probe: gid_map:  0 1000 1; 1 100000 65536;
    \\probe: fuse mount: ok
    \\probe: mountinfo: 409 260 0:47 / /tmp/s2probe/lower ro,nosuid,nodev,relatime - fuse zbxprobe
    \\probe: overlay mount: ok
    \\probe: mountinfo: 412 260 0:48 / /tmp/s2probe/merged rw,relatime - overlay overlay rw,lowerd
    \\probe: read as uid 0 through the overlay: ok
    \\probe: 16 MiB read through the overlay: ok
    \\probe: latency uncached: fuse_probe: read /tmp/s2probe/merged/big.bin: 16777216 bytes in 16
    \\probe: latency cached: fuse_probe: read /tmp/s2probe/merged/big.bin: 16777216 bytes in 16 re
    \\probe: READ requests for big.bin (count size):  128 131072
    \\probe: read as uid 1000 through the overlay: ok
    \\probe: read as uid 1000 on the FUSE mount: ok
    \\probe: id as 1000: uid=1000(demo) gid=1000(demo) groups=1000(demo)
    \\probe: O_DIRECT 1 MiB reads on the FUSE mount: 2097152 bytes (2.1 MB, 2.0 MiB) copied, 0.002
    \\probe: READ requests for other.bin (count size):  32 131072 2 1048576
    \\probe: copy-up: ok
    \\probe: lower unchanged: ok
    \\probe: new file in the upper: ok
    \\probe: touch on the FUSE mount: touch: cannot touch '/tmp/s2probe/lower/x': Read-only file s
    \\probe: lower is read-only: ok
    \\probe: cat broken.bin: cat: /tmp/s2probe/merged/broken.bin: Input/output error
    \\probe: EIO reaches cat: ok
    \\probe: cat after kill: cat: /tmp/s2probe/merged/sub/nested.txt: Transport endpoint is not co
    \\probe: ENOTCONN after kill: ok
    \\probe: ls on the FUSE mount after kill: ls: cannot open directory '/tmp/s2probe/lower': Tran
    \\probe: new open of cached big.bin: cat: /tmp/s2probe/merged/big.bin: Transport endpoint is n
    \\probe: fd opened before the kill: 16777216 bytes of big.bin cat: closing standard input: Tra
    \\probe: server log: fuse_probe: mounted fuse on /tmp/s2probe/lower with fd=3,rootmode=40000,u
    \\probe: server log: fuse_probe: server: INIT from kernel 7.39, max_readahead 131072, flags 0x
    \\probe: server log: fuse_probe: server: INIT answered 7.31, max_pages 256, flags 0x442001
    \\probe: all ok
    \\
;

test "the output recorded in a real VM run passes, and fails once a check is gone" {
    // Goal: the check reads the text the guest script really prints, not text written from what
    // it is believed to print. Method: the recorded run passes; the same run without its last
    // line, `probe: all ok`, does not.
    try check_probe(recorded_output, 0);
    const last = std.mem.lastIndexOf(u8, recorded_output, "probe: all ok").?;
    try std.testing.expectError(error.CheckFailed, check_probe(recorded_output[0..last], 0));
}
