//! The top-20 run's judgement as pure functions over the text the guest printed, each
//! unit-tested with right and wrong input. The commands that print the text are in
//! main_top20.zig. One image gives one `Result`, and a `Result` gives one line.

const std = @import("std");
const assert = std.debug.assert;

pub const Verdict = enum {
    /// The default command ended with 0, or was still running when `--timeout` stopped it.
    pass,
    /// It did not, and the list gives the reason an image like this cannot run rootless.
    known,
    /// It did not, and nothing explains it: the run fails.
    fail,
};

/// What the guest showed for one image.
pub const Observed = struct {
    pulled: bool,
    /// zbx's exit code for the run; 0 when the pull failed and no run was tried.
    status: u8,
    /// The run's stderr (or the pull's, when it failed).
    stderr: []const u8,
};

pub const Result = struct {
    ref: []const u8,
    pulled: bool,
    ran: bool,
    status: u8,
    verdict: Verdict,
    /// Syscall names that returned EPERM and are not on the seccomp allowlist; empty if none
    /// or not looked for.
    seccomp: []const u8,
    /// One line: why it failed, or why it is known not to run, or "-" for a pass.
    reason: []const u8,
};

/// `zbx run --timeout` ended the container: exit 143 and the report says so.
pub fn stopped_by_timeout(status: u8, stderr: []const u8) bool {
    if (status != 143) return false;
    return std.mem.indexOf(u8, stderr, "timed out after") != null;
}

/// zbx failed before the command started (125) or could not start it (126, 127 from zbx).
pub fn command_started(status: u8) bool {
    return status < 125 or status > 127;
}

pub fn judge(observed: Observed, known: []const u8) Verdict {
    if (!observed.pulled) return if (known.len > 0) .known else .fail;
    if (observed.status == 0) return .pass;
    if (stopped_by_timeout(observed.status, observed.stderr)) return .pass;
    return if (known.len > 0) .known else .fail;
}

/// The last non-empty line of `text`, trimmed; "-" if there is none. A failed container's last
/// word is usually its reason; zbx's own refusals are one line.
pub fn last_line(text: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, text, " \r\n\t");
    if (trimmed.len == 0) return "-";
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    return std.mem.trim(u8, trimmed[start..], " \r\t");
}

/// The first line of `text` that starts with `prefix`, or null.
pub fn first_line_with(text: []const u8, prefix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (std.mem.startsWith(u8, trimmed, prefix)) return trimmed;
    }
    return null;
}

/// Splits the guest's one line of EPERM syscall names (space separated) into those that are not
/// in `allowed`: the filter's own refusals. The others (a name the allowlist has) were refused
/// by something else, such as a missing capability. Writes the names, space separated, into
/// `out` and returns them.
pub fn seccomp_suspects(names: []const u8, allowed: []const []const u8, out: []u8) []const u8 {
    assert(out.len >= 2);
    var length: usize = 0;
    var words = std.mem.tokenizeAny(u8, names, " \r\n\t");
    while (words.next()) |word| {
        if (is_allowed(word, allowed)) continue;
        const room = out.len - length;
        if (word.len + 1 > room) break;
        if (length > 0) {
            out[length] = ' ';
            length += 1;
        }
        @memcpy(out[length..][0..word.len], word);
        length += word.len;
    }
    assert(length <= out.len);
    return out[0..length];
}

fn is_allowed(name: []const u8, allowed: []const []const u8) bool {
    for (allowed) |entry| {
        if (std.mem.eql(u8, entry, name)) return true;
    }
    return false;
}

/// The result line: fixed fields first, so a script can cut it at " | ".
pub fn format_line(buffer: []u8, result: Result) std.fmt.BufPrintError![]const u8 {
    assert(result.ref.len > 0);
    const seccomp = if (result.seccomp.len > 0) result.seccomp else "none";
    var exit_buffer: [8]u8 = undefined;
    const exit = if (result.pulled)
        try std.fmt.bufPrint(&exit_buffer, "{d}", .{result.status})
    else
        "-";
    return std.fmt.bufPrint(
        buffer,
        "{s} | pulled={s} | ran={s} | exit={s} | {s} | seccomp={s} | {s}",
        .{
            result.ref,
            yes_no(result.pulled),
            yes_no(result.ran),
            exit,
            @tagName(result.verdict),
            seccomp,
            result.reason,
        },
    );
}

fn yes_no(flag: bool) []const u8 {
    return if (flag) "yes" else "no";
}

const testing = std.testing;

test "a run passes on exit 0 or on the harness's own timeout, and on nothing else" {
    // Goal: the verdict of one image. Method: each way a run can end.
    const ok: Observed = .{ .pulled = true, .status = 0, .stderr = "" };
    try testing.expectEqual(Verdict.pass, judge(ok, ""));
    const timed: Observed = .{
        .pulled = true,
        .status = 143,
        .stderr = "zbx: stopped: timed out after 20000 ms\n",
    };
    try testing.expectEqual(Verdict.pass, judge(timed, ""));
    // 143 without the report is the container's own SIGTERM exit, not our timeout.
    const termed: Observed = .{ .pulled = true, .status = 143, .stderr = "" };
    try testing.expectEqual(Verdict.fail, judge(termed, ""));
    const failed: Observed = .{ .pulled = true, .status = 1, .stderr = "boom\n" };
    try testing.expectEqual(Verdict.fail, judge(failed, ""));
    try testing.expectEqual(Verdict.known, judge(failed, "needs a password"));
    // A reason does not hide a pass.
    try testing.expectEqual(Verdict.pass, judge(ok, "needs a password"));
    const unpulled: Observed = .{ .pulled = false, .status = 0, .stderr = "error[ZBX-E0505]" };
    try testing.expectEqual(Verdict.fail, judge(unpulled, ""));
}

test "the command started unless zbx itself failed" {
    // Goal: `ran` in the result line. Method: the edges of the 125 to 127 range.
    try testing.expect(command_started(0));
    try testing.expect(command_started(124));
    try testing.expect(!command_started(125));
    try testing.expect(!command_started(127));
    try testing.expect(command_started(128));
    try testing.expect(command_started(255));
}

test "the last line of the stderr is the reason" {
    // Goal: the reason column. Method: empty, one line, several lines and trailing blanks.
    try testing.expectEqualStrings("-", last_line(""));
    try testing.expectEqualStrings("-", last_line("\n \n"));
    try testing.expectEqualStrings("one", last_line("one\n"));
    try testing.expectEqualStrings("two", last_line("one\ntwo\n\n"));
    try testing.expectEqualStrings("error[ZBX-E0501]: x", first_line_with(
        "warning: y\n  error[ZBX-E0501]: x\nmore\n",
        "error[",
    ).?);
    try testing.expect(first_line_with("nothing\n", "error[") == null);
}

test "only a syscall the allowlist lacks is the filter's refusal" {
    // Goal: tell a seccomp EPERM from any other. Method: one name of each kind, and a buffer
    // too small for all of them.
    const allowed = [_][]const u8{ "setgroups", "openat", "read" };
    var out: [64]u8 = undefined;
    const got = seccomp_suspects("setgroups fchmodat2 openat cachestat\n", &allowed, &out);
    try testing.expectEqualStrings("fchmodat2 cachestat", got);
    try testing.expectEqualStrings("", seccomp_suspects("", &allowed, &out));
    try testing.expectEqualStrings("", seccomp_suspects("openat read", &allowed, &out));
    var small: [10]u8 = undefined;
    const cut = seccomp_suspects("fchmodat2 cachestat", &allowed, &small);
    try testing.expectEqualStrings("fchmodat2", cut);
}

test "a result is one line with the fields in a fixed order" {
    // Goal: the line a script cuts at " | ". Method: a pass, a seccomp failure, an unpulled image.
    var buffer: [256]u8 = undefined;
    const pass: Result = .{
        .ref = "alpine:latest",
        .pulled = true,
        .ran = true,
        .status = 0,
        .verdict = .pass,
        .seccomp = "",
        .reason = "-",
    };
    try testing.expectEqualStrings(
        "alpine:latest | pulled=yes | ran=yes | exit=0 | pass | seccomp=none | -",
        try format_line(&buffer, pass),
    );
    var seccomp = pass;
    seccomp.status = 1;
    seccomp.verdict = .fail;
    seccomp.seccomp = "fchmodat2";
    seccomp.reason = "Operation not permitted";
    try testing.expectEqualStrings(
        "alpine:latest | pulled=yes | ran=yes | exit=1 | fail | seccomp=fchmodat2 | " ++
            "Operation not permitted",
        try format_line(&buffer, seccomp),
    );
    var unpulled = pass;
    unpulled.pulled = false;
    unpulled.ran = false;
    unpulled.verdict = .fail;
    try testing.expectEqualStrings(
        "alpine:latest | pulled=no | ran=no | exit=- | fail | seccomp=none | -",
        try format_line(&buffer, unpulled),
    );
}
