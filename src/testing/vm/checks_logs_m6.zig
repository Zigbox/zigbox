//! The assertions of M6b slice 2's `zbx logs` as pure functions over the text the guest printed,
//! each unit-tested with right and wrong input. The commands that print it are in logs_m6.zig,
//! a part of demo-m6 until slice 4 moves it to demo-m6b.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// The requests a server logged are not all there, or are not what was asked.
    RequestsWrong,
    /// A JSON line is not a `zbx.logs/1` record.
    JsonWrong,
    /// The container's output is not on the terminal, or not in the log, or in the wrong stream.
    OutputWrong,
    /// `--follow` did not show everything the container wrote.
    FollowWrong,
    /// The capped log is not a whole suffix of what the container wrote.
    CapWrong,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

fn count_lines_with(text: []const u8, part: []const u8) u32 {
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (contains(line, part)) count += 1;
    }
    return count;
}

/// What python's `http.server` logged for a request for `/` (answered 200, a directory listing)
/// and for a path it does not have (404): one line each, in that order, however many other lines
/// there are.
pub fn check_requests(log: []const u8, ok_path: []const u8, missing_path: []const u8) Error!void {
    var wanted_ok: [64]u8 = undefined;
    var wanted_missing: [64]u8 = undefined;
    const ok = std.fmt.bufPrint(&wanted_ok, "\"GET {s} HTTP/1.1\" 200", .{ok_path}) catch
        return error.RequestsWrong;
    const format = "\"GET {s} HTTP/1.1\" 404";
    const missing = std.fmt.bufPrint(&wanted_missing, format, .{missing_path}) catch
        return error.RequestsWrong;
    if (count_lines_with(log, ok) != 1) return error.RequestsWrong;
    if (count_lines_with(log, missing) != 1) return error.RequestsWrong;
    const first = std.mem.indexOf(u8, log, ok).?;
    if (first > std.mem.indexOf(u8, log, missing).?) return error.RequestsWrong;
}

/// `zbx logs --output json`: every line is one `zbx.logs/1` record of the stream `only` (null:
/// either), and there are at least `min` of them.
pub fn check_json(output: []const u8, only: ?[]const u8, min: u32) Error!void {
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, output, "\n"), '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const head = "{\"schema\":\"zbx.logs/1\",\"stream\":\"";
        if (!std.mem.startsWith(u8, line, head)) return error.JsonWrong;
        if (!contains(line, "\",\"time\":")) return error.JsonWrong;
        if (!contains(line, ",\"text\":\"")) return error.JsonWrong;
        if (!std.mem.endsWith(u8, line, "}")) return error.JsonWrong;
        if (only) |stream| {
            if (!std.mem.startsWith(u8, line[head.len..], stream)) return error.JsonWrong;
        }
        count += 1;
    }
    if (count < min) return error.JsonWrong;
}

/// A foreground run: its output on the terminal, the two streams as the command wrote them.
pub fn check_terminal(terminal: Streams) Error!void {
    if (!std.mem.eql(u8, std.mem.trim(u8, terminal.stdout, " \r\n"), "to-stdout")) {
        return error.OutputWrong;
    }
    if (!std.mem.eql(u8, std.mem.trim(u8, terminal.stderr, " \r\n"), "to-stderr")) {
        return error.OutputWrong;
    }
}

/// The same two lines, in order, in the log.
pub fn check_log(log: []const u8) Error!void {
    const out = std.mem.indexOf(u8, log, "to-stdout") orelse return error.OutputWrong;
    const err = std.mem.indexOf(u8, log, "to-stderr") orelse return error.OutputWrong;
    if (out > err) return error.OutputWrong;
}

/// `--stream`: the output holds `wanted` and not `other`.
pub fn check_stream(output: []const u8, wanted: []const u8, other: []const u8) Error!void {
    if (!contains(output, wanted)) return error.OutputWrong;
    if (contains(output, other)) return error.OutputWrong;
}

/// `zbx logs` of a run that had the terminal: nothing on stdout, and the notice (W0206) on stderr
/// that says why, with exit 0.
pub fn check_terminal_notice(streams: Streams) Error!void {
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.OutputWrong;
    if (!contains(streams.stderr, "warning[ZBX-W0206]")) return error.OutputWrong;
    if (!contains(streams.stderr, "standard output and error")) return error.OutputWrong;
}

/// A run under a pseudo-terminal: the command printed `tty` because `test -t 1` held inside.
pub fn check_tty(output: []const u8) Error!void {
    if (!contains(output, "tty-yes")) return error.OutputWrong;
    if (contains(output, "tty-no")) return error.OutputWrong;
}

/// `--follow` of a container that printed tick-1 to tick-3 a second apart: all three, in order,
/// and nothing after.
pub fn check_follow(output: []const u8) Error!void {
    const expected = [_][]const u8{ "tick-1", "tick-2", "tick-3" };
    var lines = std.mem.tokenizeAny(u8, output, "\r\n");
    for (expected) |want| {
        const line = lines.next() orelse return error.FollowWrong;
        if (!std.mem.eql(u8, line, want)) return error.FollowWrong;
    }
    if (lines.next() != null) return error.FollowWrong;
}

/// The capped log, as the guest's summary script prints it (one `key=value` per line): the
/// container wrote `total` bytes, the cap is `cap`. What `zbx logs` shows is the end of that
/// output, from a whole record on: dropped plus shown is everything written, the end is the last
/// line, the first JSON record carries the dropped count and no other does, the warning names
/// the same count, and the two files on the disk are each under half the cap.
pub fn check_cap(summary: []const u8, total: u64, cap: u64, last_line: []const u8) Error!void {
    const dropped = number_of(summary, "dropped=") orelse return error.CapWrong;
    const shown = number_of(summary, "bytes=") orelse return error.CapWrong;
    if (dropped == 0) return error.CapWrong;
    if (dropped + shown != total) return error.CapWrong;
    if (shown > cap) return error.CapWrong;
    if (shown < cap / 2 -| 4200) return error.CapWrong;
    const last = text_of(summary, "last=") orelse return error.CapWrong;
    if (!std.mem.eql(u8, last, last_line)) return error.CapWrong;
    const warned = number_of(summary, "warned=") orelse return error.CapWrong;
    if (warned != dropped) return error.CapWrong;
    if (!contains(summary, "code=ZBX-W0205")) return error.CapWrong;
    const later = number_of(summary, "later=") orelse return error.CapWrong;
    if (later != 0) return error.CapWrong;
    const records = number_of(summary, "records=") orelse return error.CapWrong;
    if (records < 2) return error.CapWrong;
    const current = number_of(summary, "current=") orelse return error.CapWrong;
    const older = number_of(summary, "older=") orelse return error.CapWrong;
    if (current > cap / 2) return error.CapWrong;
    if (older > cap / 2) return error.CapWrong;
    if (older == 0) return error.CapWrong;
}

fn text_of(summary: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, summary, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (std.mem.startsWith(u8, trimmed, key)) return trimmed[key.len..];
    }
    return null;
}

fn number_of(summary: []const u8, key: []const u8) ?u64 {
    const text = text_of(summary, key) orelse return null;
    return std.fmt.parseInt(u64, text, 10) catch null;
}

const testing = std.testing;

const server_log =
    "127.0.0.1 - - [30/Oct/2026 10:00:00] \"GET / HTTP/1.1\" 200 -\n" ++
    "127.0.0.1 - - [30/Oct/2026 10:00:01] code 404, message File not found\n" ++
    "127.0.0.1 - - [30/Oct/2026 10:00:01] \"GET /nothing-lg HTTP/1.1\" 404 -\n";

test "check_requests wants both requests, once each, in order" {
    // Goal: the log of the server shows the two requests. A missing, repeated or reversed one
    // fails.
    try check_requests(server_log, "/", "/nothing-lg");
    try testing.expectError(error.RequestsWrong, check_requests("", "/", "/nothing-lg"));
    const only_ok = "\"GET / HTTP/1.1\" 200 -\n";
    try testing.expectError(error.RequestsWrong, check_requests(only_ok, "/", "/nothing-lg"));
    const twice = server_log ++ "\"GET / HTTP/1.1\" 200 -\n";
    try testing.expectError(error.RequestsWrong, check_requests(twice, "/", "/nothing-lg"));
    const reversed = "\"GET /nothing-lg HTTP/1.1\" 404 -\n\"GET / HTTP/1.1\" 200 -\n";
    try testing.expectError(error.RequestsWrong, check_requests(reversed, "/", "/nothing-lg"));
}

test "check_json wants zbx.logs/1 records of the stream asked for" {
    const line = "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":5,\"text\":\"x\\n\"}\n";
    try check_json(line ++ line, "stderr", 2);
    try check_json(line, null, 1);
    try testing.expectError(error.JsonWrong, check_json(line, "stdout", 1));
    try testing.expectError(error.JsonWrong, check_json(line, "stderr", 2));
    try testing.expectError(error.JsonWrong, check_json("plain text\n", null, 1));
    try testing.expectError(error.JsonWrong, check_json("", null, 1));
}

test "check_foreground wants the output on the terminal and in the log" {
    const good: Streams = .{ .stdout = "to-stdout\r\n", .stderr = "to-stderr\r\n" };
    try check_terminal(good);
    try check_log("to-stdout\nto-stderr\n");
    try testing.expectError(error.OutputWrong, check_log("to-stderr\nto-stdout\n"));
    try testing.expectError(error.OutputWrong, check_log("to-stdout\n"));
    const silent: Streams = .{ .stdout = "", .stderr = "to-stderr\n" };
    try testing.expectError(error.OutputWrong, check_terminal(silent));
}

test "check_stream and check_follow" {
    try check_stream("to-stderr\n", "to-stderr", "to-stdout");
    const crossed = check_stream("to-stdout\n", "to-stderr", "to-stdout");
    try testing.expectError(error.OutputWrong, crossed);
    try check_follow("tick-1\ntick-2\ntick-3\n");
    try testing.expectError(error.FollowWrong, check_follow("tick-1\ntick-2\n"));
    try testing.expectError(error.FollowWrong, check_follow(""));
}

test "check_tty and check_terminal_notice" {
    try check_tty("tty-yes\r\n");
    try testing.expectError(error.OutputWrong, check_tty("tty-no\n"));
    try testing.expectError(error.OutputWrong, check_tty(""));
    const notice = "warning[ZBX-W0206]: the terminal was not logged\n  cause  this run's " ++
        "standard output and error went to a terminal\n";
    try check_terminal_notice(.{ .stdout = "", .stderr = notice });
    const noisy = check_terminal_notice(.{ .stdout = "x\n", .stderr = notice });
    try testing.expectError(error.OutputWrong, noisy);
    const silent = check_terminal_notice(.{ .stdout = "", .stderr = "" });
    try testing.expectError(error.OutputWrong, silent);
}

const good_summary =
    "dropped=700000\nbytes=5140000\nlast=line-079999 xx\nwarned=700000\ncode=ZBX-W0205\n" ++
    "later=0\nrecords=1300\ncurrent=2000000\nolder=2600000\n";

test "check_cap wants dropped plus shown to be everything, and the rest to agree" {
    // Goal: every clause of the cap check can fail. Method: the good summary passes; each line
    // altered in turn does not.
    try check_cap(good_summary, 5_840_000, 5_242_880, "line-079999 xx");
    const wrong_total = check_cap(good_summary, 5_840_001, 5_242_880, "line-079999 xx");
    try testing.expectError(error.CapWrong, wrong_total);
    const wrong_last = check_cap(good_summary, 5_840_000, 5_242_880, "line-079998 xx");
    try testing.expectError(error.CapWrong, wrong_last);
    const edits = [_][2][]const u8{
        .{ "dropped=700000", "dropped=0" },
        .{ "warned=700000", "warned=1" },
        .{ "code=ZBX-W0205", "code=none" },
        .{ "later=0", "later=1" },
        .{ "records=1300", "records=1" },
        .{ "older=2600000", "older=0" },
        .{ "older=2600000", "older=2700000" },
        .{ "current=2000000", "current=2700000" },
        .{ "bytes=5140000", "bytes=5300000" },
    };
    for (edits) |edit| {
        var buffer: [512]u8 = undefined;
        const size = std.mem.replacementSize(u8, good_summary, edit[0], edit[1]);
        _ = std.mem.replace(u8, good_summary, edit[0], edit[1], &buffer);
        const edited = check_cap(buffer[0..size], 5_840_000, 5_242_880, "line-079999 xx");
        try testing.expectError(error.CapWrong, edited);
    }
    try testing.expectError(error.CapWrong, check_cap("", 5_840_000, 5_242_880, ""));
}
