//! What the M9 demo's step 7 asserts (docs/briefs/M9-dockerfile-import.md, "Demo"), a pinned
//! `ADD` of `m9_fetch/`, as pure functions of the commands' output, each with a unit test.
//! fetch_m9.zig runs the commands in the guest and calls these.

const std = @import("std");
const assert = std.debug.assert;
const m7 = @import("checks_m7.zig");
const m9 = @import("checks_m9.zig");

pub const Error = m9.Error;
pub const Report = m7.Report;

/// The payload's SHA-256 (`m9_fetch/hello.txt`), as the Dockerfile pins it.
pub const hello_sha256 = "5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62";
/// A hash nothing has: the wrong pin of the mismatch.
pub const wrong_sha256 = "1111111111111111111111111111111111111111111111111111111111111111";
pub const url = "http://127.0.0.1:8080/hello.txt";
/// The fetch entry as `zbx import` prints it.
pub const entry = ".{ .fetch = .{ .url = \"" ++ url ++ "\", .sha256 = \"" ++ hello_sha256 ++
    "\" }, .to = \"/opt/hello.txt\" },";
/// The two steps of the import: the fetch, then the `RUN`.
pub const step_names = [_][]const u8{ "stage0-1", "stage0-2" };
/// The build report's rows: the two steps, then the image.
pub const row_names = step_names ++ [_][]const u8{"image"};

/// `zbx import` of the fetch project: exit 0, nothing flagged, no warning, no error. The report
/// is on stderr; stdout is empty.
pub fn check_import(stdout: []const u8, stderr: []const u8, status: u8) Error!void {
    if (status != 0) return error.ImportWrong;
    if (stdout.len != 0) return error.ImportWrong;
    // The harness may drop the stream's last newline: the report's last line ends it.
    const trimmed = std.mem.trimEnd(u8, stderr, "\n");
    if (!std.mem.endsWith(u8, trimmed, "; 0 flagged")) return error.ImportWrong;
    if (std.mem.indexOf(u8, stderr, "warning[") != null) return error.ImportWrong;
    if (std.mem.indexOf(u8, stderr, "error[") != null) return error.ImportWrong;
}

/// The written build file holds the fetch entry, with the URL and the hash.
pub fn check_entry(build_file: []const u8) Error!void {
    assert(entry.len > url.len);
    if (std.mem.indexOf(u8, build_file, entry) == null) return error.ImportWrong;
}

/// The server's log holds `want` requests, one `GET /` line each. The harness may drop the
/// stream's last newline, so lines are counted, not newlines.
pub fn check_requests(log: []const u8, want: u32) Error!void {
    var lines: u32 = 0;
    var split = std.mem.tokenizeScalar(u8, log, '\n');
    while (split.next()) |line| {
        if (!std.mem.startsWith(u8, line, "GET /")) return error.ReportWrong;
        lines += 1;
    }
    if (lines != want) return error.ReportWrong;
}

/// Both steps and the image row of the build: `hit` says whether each was a hit.
pub fn check_rows(report: *const Report, hit: bool) Error!void {
    assert(report.count <= m7.rows_max);
    if (report.count != row_names.len) return error.ReportWrong;
    for (row_names) |name| {
        const row = report.row(name) orelse return error.ReportWrong;
        if (row.hit != hit) return error.CacheWrong;
    }
    if (report.hits != (if (hit) row_names.len else 0)) return error.CacheWrong;
}

/// `stat -c '%u:%g %a'` of /opt/hello.txt: Docker's defaults for a remote `ADD`.
pub fn check_owner(stdout: []const u8) Error!void {
    return m7.check_stdout_is(stdout, "0:0 600");
}

/// A wrong pin: exit 3, stderr starts `error[ZBX-E0821]: ` and names the URL, the expected hash
/// and the received one; no step ran, so the report has no row.
pub fn check_mismatch(stdout: []const u8, stderr: []const u8, status: u8) Error!void {
    if (status != 3) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, stderr, "error[ZBX-E0821]: ")) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    const wants = [_][]const u8{ "127.0.0.1:8080", wrong_sha256, hello_sha256 };
    if (!m9.contains_all(stderr, &wants)) return error.RefusalWrong;
    for (step_names) |name| {
        if (std.mem.indexOf(u8, stdout, name) != null) return error.RefusalWrong;
    }
}

const testing = std.testing;

test "the import: nothing flagged, no warning" {
    const report = "imported 2 steps from 1 stage (target stage0) to zbx.build.zon; 0 flagged\n";
    try check_import("", report, 0);
    try testing.expectError(error.ImportWrong, check_import("", report, 1));
    try testing.expectError(error.ImportWrong, check_import(report, "", 0));
    const flagged = "imported 2 steps from 1 stage (target stage0) to zbx.build.zon; 1 flagged\n";
    try testing.expectError(error.ImportWrong, check_import("", flagged, 0));
    try check_import("", report[0 .. report.len - 1], 0);
    const warned = "warning[ZBX-W0811]: EXPOSE\n" ++ report;
    try testing.expectError(error.ImportWrong, check_import("", warned, 0));
}

test "the entry names the URL and the hash" {
    try check_entry("        .copy = .{\n            " ++ entry ++ "\n        },\n");
    const other = ".{ .fetch = .{ .url = \"" ++ url ++ "\", .sha256 = \"" ++ wrong_sha256 ++
        "\" }, .to = \"/opt/hello.txt\" },";
    try testing.expectError(error.ImportWrong, check_entry(other));
}

test "requests are counted by lines" {
    try check_requests("", 0);
    try check_requests("GET /hello.txt HTTP/1.1\n", 1);
    try check_requests("GET /hello.txt HTTP/1.1", 1);
    try testing.expectError(error.ReportWrong, check_requests("GET /hello.txt HTTP/1.1\n", 0));
    try testing.expectError(error.ReportWrong, check_requests("GET /a\nGET /b", 1));
    try testing.expectError(error.ReportWrong, check_requests("HEAD /hello.txt HTTP/1.1", 1));
}

fn report_of(first: bool, second: bool) Report {
    var report: Report = undefined;
    report.count = 3;
    report.digest = "";
    report.elapsed_ms = 0;
    report.hits = @as(u32, @intFromBool(first)) * 2 + @intFromBool(second);
    report.misses = 3 - report.hits;
    for (row_names, [_]bool{ first, second, first }, 0..) |name, hit, index| {
        report.rows[index] = .{
            .name = name,
            .hit = hit,
            .network = false,
            .start_ms = 0,
            .end_ms = 0,
            .key = "",
            .output = "",
        };
    }
    return report;
}

test "rows: all hits, all misses, never a mix" {
    try check_rows(&report_of(true, true), true);
    try check_rows(&report_of(false, false), false);
    try testing.expectError(error.CacheWrong, check_rows(&report_of(true, false), true));
    try testing.expectError(error.CacheWrong, check_rows(&report_of(true, false), false));
    var two = report_of(true, true);
    two.count = 2;
    try testing.expectError(error.ReportWrong, check_rows(&two, true));
}

test "the owner and mode of a remote ADD" {
    try check_owner("0:0 600\n");
    try testing.expectError(error.ReportWrong, check_owner("0:0 644\n"));
}

test "the mismatch names the URL and both hashes, and ran no step" {
    const stderr = "error[ZBX-E0821]: http://127.0.0.1:8080/r/hello.txt sent other bytes\n" ++
        "  expected sha256:" ++ wrong_sha256 ++ "\n  received sha256:" ++ hello_sha256 ++ "\n";
    try check_mismatch("", stderr, 3);
    try testing.expectError(error.RefusalWrong, check_mismatch("", stderr, 1));
    try testing.expectError(error.RefusalWrong, check_mismatch("stage0-1 miss\n", stderr, 3));
    const short = "error[ZBX-E0821]: http://127.0.0.1:8080/hello.txt sent other bytes\n";
    try testing.expectError(error.RefusalWrong, check_mismatch("", short, 3));
}
