//! The assertions of demo-m6b's ACCEPT part (accept_m6b.zig) as pure functions over the text the
//! guest printed, each unit-tested with right and wrong input. The part checks the one acceptance
//! criterion the other parts do not: a container's log is removed with its run record. (The
//! owner of what a mount receives, the refusal of a user that is not root, the bound of a log,
//! the log after its `zbx` was killed and what `exec` gains are the parts WRITABLE, LOGS and
//! EXEC, with checks_writable_m6b.zig, checks_logs_m6b.zig and checks_exec_m6b.zig.)

const std = @import("std");

pub const Error = error{
    ExitCodeWrong,
    /// The summary lacks a line, or a line says other than it must.
    SummaryWrong,
    /// The log (or the record) was not there when the container had just run, or is still there
    /// after the record was pruned.
    RemovalWrong,
};

fn value_of(summary: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, summary, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len <= key.len + 1) continue;
        if (!std.mem.startsWith(u8, line, key)) continue;
        if (line[key.len] != '=') continue;
        return line[key.len + 1 ..];
    }
    return null;
}

fn expect_value(summary: []const u8, key: []const u8, wanted: []const u8) Error!void {
    const found = value_of(summary, key) orelse return error.SummaryWrong;
    if (!std.mem.eql(u8, found, wanted)) return error.RemovalWrong;
}

/// The guest's summary (one `key=value` per line) of a container that ran first and then had
/// more than `constants.runs_max` newer ones after it: right after its run its log, rotated once
/// (both files), and its record were there and `zbx logs` ended with `marker`; once the record
/// was pruned neither file was left, a newer container's log was, and `zbx logs` of the old name
/// is ZBX-E0402 with its summary, exit 1 (DIAGNOSTICS.md, "Exit codes": 125 is only for a
/// command that runs or waits on a workload).
pub fn check_removal(summary: []const u8, status: u8, marker: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    try expect_value(summary, "before_log", "1");
    try expect_value(summary, "before_older", "1");
    try expect_value(summary, "before_record", "1");
    try expect_value(summary, "before_text", marker);
    try expect_value(summary, "after_log", "0");
    try expect_value(summary, "after_older", "0");
    try expect_value(summary, "after_record", "0");
    try expect_value(summary, "newest_log", "1");
    try expect_value(summary, "gone_status", "1");
    try expect_value(summary, "gone_line", "error[ZBX-E0402]: no container with that name");
}

const testing = std.testing;
const marker_text = "gone-with-the-record";

/// The summary of run 41079428757 (vm/m6b-slice5d), with the two lines that run did not print
/// yet (`before_older`, `gone_line`, from E0402 as the agent's JSON gave it in that run).
const good = "before_log=1\nbefore_older=1\nbefore_record=1\nbefore_text=gone-with-the-record\n" ++
    "after_log=0\nafter_older=0\nafter_record=0\nnewest_log=1\ngone_status=1\n" ++
    "gone_line=error[ZBX-E0402]: no container with that name\n";

test "a log removed with its record passes, and each way to fail is caught" {
    // Goal: the check passes on the summary of a correct run and fails on each lie in it: a log
    // or its older half left, the record left, the log never there or never rotated, the newest
    // missing, the wrong refusal (another code, another summary), and a command that failed.
    // Method: the summary the guest printed (`good`), each line changed in turn.
    try check_removal(good, 0, "gone-with-the-record");
    try testing.expectError(error.ExitCodeWrong, check_removal(good, 1, "gone-with-the-record"));
    const keys = [_][]const u8{
        "before_log",  "before_older", "before_record", "after_log",
        "after_older", "after_record", "newest_log",
    };
    var buffer: [512]u8 = undefined;
    for (keys) |key| {
        // Flip the digit of the line: a 0 becomes 1 and the other way.
        const at = std.mem.indexOf(u8, good, key).? + key.len + 1;
        @memcpy(buffer[0..good.len], good);
        buffer[at] = if (good[at] == '1') '0' else '1';
        const bad = check_removal(buffer[0..good.len], 0, "gone-with-the-record");
        try testing.expectError(error.RemovalWrong, bad);
    }
    const wrong_text = check_removal(good, 0, "another-marker");
    try testing.expectError(error.RemovalWrong, wrong_text);
    const unix = try std.mem.replaceOwned(u8, testing.allocator, good, "1", "125");
    defer testing.allocator.free(unix);
    try testing.expectError(error.RemovalWrong, check_removal(unix, 0, "gone-with-the-record"));
    try testing.expectError(error.SummaryWrong, check_removal("", 0, "x"));
    const other_code = try std.mem.replaceOwned(u8, testing.allocator, good, "E0402", "E0217");
    defer testing.allocator.free(other_code);
    try testing.expectError(error.RemovalWrong, check_removal(other_code, 0, marker_text));
    const summary = "no container with that name";
    const other_summary = try std.mem.replaceOwned(u8, testing.allocator, good, summary, "no");
    defer testing.allocator.free(other_summary);
    try testing.expectError(error.RemovalWrong, check_removal(other_summary, 0, marker_text));
    const cut = good[0..std.mem.indexOf(u8, good, "gone_line=").?];
    try testing.expectError(error.SummaryWrong, check_removal(cut, 0, "gone-with-the-record"));
}
