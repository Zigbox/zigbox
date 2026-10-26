//! The M2 demo's assertions as pure functions over the text the guest printed, each unit-tested
//! with right and wrong input (a check that cannot fail proves nothing). The commands that print
//! this text are in main_m2.zig; the markers (`BOMB-EXIT:`, `SCOPE-lim1:`, ...) are theirs.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    StderrNotEmpty,
    StdoutNotEmpty,
    ExitCodeWrong,
    /// A line the step must print is missing or wrong.
    LineMissing,
    /// The last line of stderr is not the report the step needs.
    ReportWrong,
    JsonWrong,
    LimitsWrong,
    ScopeLeft,
    HostUnresponsive,
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

/// Formats into `buffer`.
fn print(buffer: []u8, comptime format: []const u8, args: anytype) []const u8 {
    // Cannot fail: every caller's buffer holds its longest line.
    return std.fmt.bufPrint(buffer, format, args) catch unreachable;
}

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// The last non-empty line of `text`, trimmed.
pub fn last_line(text: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, text, " \r\n\t");
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    return std.mem.trim(u8, trimmed[start..], " \r\t");
}

fn status_of(output: []const u8, marker: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, marker)) continue;
        return std.fmt.parseInt(u32, line[marker.len..], 10) catch return null;
    }
    return null;
}

// ---- Demo step 1: the fork bomb --------------------------------------------------------------

/// The host side prints `PROBES:<n>` (n answers from the host while the bomb ran, each one
/// separated by a second), `BOMB-EXIT:<zbx's status>` and `BOMB-LAST:<last line of stderr>`.
/// zbx must not have been cut off by `timeout` (124) or have failed to run (125), and its last
/// words must be the process-limit report.
pub fn check_fork_bomb(output: []const u8, limit: u32, probes_wanted: u32) Error!void {
    const probes = status_of(output, "PROBES:") orelse return error.LineMissing;
    if (probes < probes_wanted) return error.HostUnresponsive;
    const code = status_of(output, "BOMB-EXIT:") orelse return error.LineMissing;
    if (code == 124 or code == 125) return error.ExitCodeWrong;
    var expected: [96]u8 = undefined;
    const line = print(
        &expected,
        "BOMB-LAST:zbx: stopped: process limit reached (limit {d})",
        .{limit},
    ); // A short fixed line.
    if (!has_line(output, line)) return error.ReportWrong;
}

// ---- Demo step 2: the memory limit -----------------------------------------------------------

/// `stress-ng --vm 1 --vm-bytes 512m` under `--memory 128m`: the exit code is 128+9 whatever
/// the process did, and the report is the last thing on stderr.
pub fn check_oom_report(streams: Streams, status: u8, limit_mib: u32) Error!void {
    if (status != 137) return error.ExitCodeWrong;
    var expected: [80]u8 = undefined;
    const line = print(
        &expected,
        "zbx: killed: out of memory (limit {d} MiB)",
        .{limit_mib},
    ); // A short fixed line.
    if (!std.mem.eql(u8, last_line(streams.stderr), line)) return error.ReportWrong;
}

// ---- Demo step 3 and 4: the refusals ---------------------------------------------------------

/// The part of a refused `mount` that is stable: busybox says "permission denied (are you
/// root?)" and glibc's mount says "Operation not permitted" for the same EPERM.
pub fn is_eperm_text(text: []const u8) bool {
    var lower: [512]u8 = undefined;
    const length = @min(text.len, lower.len);
    for (text[0..length], lower[0..length]) |byte, *target| target.* = std.ascii.toLower(byte);
    const seen = lower[0..length];
    return contains(seen, "permission denied") or contains(seen, "operation not permitted");
}

pub fn check_mount_refused(streams: Streams, status: u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    if (status == 125 or status == 70) return error.ExitCodeWrong; // zbx's own, not mount's.
    if (!is_eperm_text(streams.stderr)) return error.LineMissing;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.StdoutNotEmpty;
}

pub fn check_read_only_refused(streams: Streams, status: u8) Error!void {
    if (status == 0 or status == 125 or status == 70) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "touch: /x: Read-only file system")) return error.LineMissing;
}

pub fn check_tmp_writable(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(streams.stdout, "tmp-ok")) return error.LineMissing;
    if (std.mem.trim(u8, streams.stderr, " \r\n").len != 0) return error.StderrNotEmpty;
}

/// The capability sets, `no_new_privs` and the seccomp mode of the container's PID 1.
pub fn check_hardening_status(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const set = "00000000a00405fb";
    const wanted = [_][]const u8{
        "CapInh:\t" ++ set,          "CapPrm:\t" ++ set, "CapEff:\t" ++ set, "CapBnd:\t" ++ set,
        "CapAmb:\t0000000000000000", "NoNewPrivs:\t1",   "Seccomp:\t2",
    };
    for (wanted) |line| {
        if (!has_line(streams.stdout, line)) return error.LineMissing;
    }
}

// ---- Acceptance: limits visible while running, gone after ------------------------------------

/// `look` prints the limit files of a running container; both blocks are in `output`.
pub fn check_limits_visible(output: []const u8) Error!void {
    const wanted = [_][]const u8{
        "SCOPE-lim1:1", "memory.max=67108864",  "memory.swap.max=0",
        "pids.max=20",  "cpu.max=50000 100000",
    };
    for (wanted) |line| {
        if (!has_line(output, line)) return error.LimitsWrong;
    }
}

/// `scope_of` and the `after` probe of the demo: no scope in the cgroup tree, none in the manager.
pub fn check_scope_gone(output: []const u8, name: []const u8) Error!void {
    var expected: [64]u8 = undefined;
    const line = print(&expected, "SCOPE-{s}:0", .{name});
    if (!has_line(output, line)) return error.ScopeLeft;
    if (!has_line(output, "AFTER-CGROUP:0")) return error.ScopeLeft;
    if (!has_line(output, "AFTER-MANAGER:0")) return error.ScopeLeft;
}

// ---- Acceptance: the exit reasons are distinguished ------------------------------------------

/// The `container_exit` line of `--output json` on stderr, with this reason and exit code.
pub fn check_exit_json(stderr: []const u8, reason: []const u8, code: u8) Error!void {
    const line = last_line(stderr);
    var buffer: [64]u8 = undefined;
    const reason_text = print(&buffer, "\"container_exit\":{{\"reason\":\"{s}\"", .{reason});
    if (!contains(line, reason_text)) return error.JsonWrong;
    // The code ends where the next character is not a digit: `code":1` is not `code":137`.
    const code_text = print(&buffer, "\"code\":{d}", .{code});
    const at = std.mem.indexOf(u8, line, code_text) orelse return error.JsonWrong;
    const next = line[at + code_text.len ..];
    if (next.len == 0 or (next[0] != ',' and next[0] != '}')) return error.JsonWrong;
}

// ---- The lifecycle (slice 4) -----------------------------------------------------------------

/// `run -d` prints the name and returns: nothing on stderr, exit 0.
pub fn check_detached_start(streams: Streams, status: u8, name: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, streams.stdout, " \r\n"), name)) return error.LineMissing;
    if (std.mem.trim(u8, streams.stderr, " \r\n").len != 0) return error.StderrNotEmpty;
}

/// `ps` text: a row with the name, the state and the command.
pub fn check_ps_text(streams: Streams, status: u8, name: []const u8, state: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, "NAME")) return error.LineMissing;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |raw| {
        var fields = std.mem.tokenizeAny(u8, raw, " \r\t");
        const first = fields.next() orelse continue;
        if (!std.mem.eql(u8, first, name)) continue;
        const second = fields.next() orelse continue;
        return if (std.mem.eql(u8, second, state)) {} else error.LineMissing;
    }
    return error.LineMissing;
}

/// `ps --output json`: the schema tag, and the container's object with these fields.
pub fn check_ps_json(
    streams: Streams,
    status: u8,
    name: []const u8,
    state: []const u8,
    timed_out: bool,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.startsWith(u8, streams.stdout, "{\"schema\":\"zbx.ps/1\",\"containers\":["))
        return error.JsonWrong;
    var head: [160]u8 = undefined;
    const object = print(
        &head,
        "{{\"name\":\"{s}\",\"state\":\"{s}\",\"pid\":",
        .{ name, state },
    );
    const at = std.mem.indexOf(u8, streams.stdout, object) orelse return error.JsonWrong;
    const rest = streams.stdout[at..];
    const end = std.mem.indexOf(u8, rest, "\"limits\"") orelse return error.JsonWrong;
    const body = rest[0..end];
    if (!contains(body, "\"detached\":true")) return error.JsonWrong;
    const flag = if (timed_out) "\"timed_out\":true" else "\"timed_out\":false";
    if (!contains(body, flag)) return error.JsonWrong;
    if (!contains(body, "\"command\":[\"sleep\",\"1000\"]")) return error.JsonWrong;
}

/// `stop --output json`: how it stopped and with what code.
pub fn check_stop_json(
    streams: Streams,
    status: u8,
    name: []const u8,
    result: []const u8,
    code: u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var expected: [160]u8 = undefined;
    const line = print(
        &expected,
        "{{\"schema\":\"zbx.stop/1\",\"name\":\"{s}\",\"result\":\"{s}\",",
        .{ name, result },
    );
    if (!std.mem.startsWith(u8, streams.stdout, line)) return error.JsonWrong;
    var tail: [32]u8 = undefined;
    const code_text = print(&tail, "\"exit_code\":{d}}}", .{code});
    if (!contains(streams.stdout, code_text)) return error.JsonWrong;
}

/// A second `stop`, or `stop` of a container that already ended.
pub fn check_stop_again(streams: Streams, status: u8, name: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var expected: [64]u8 = undefined;
    const line = print(&expected, "{s} was not running", .{name});
    if (!contains(streams.stdout, line)) return error.LineMissing;
}

/// `run --timeout` in the foreground: the signal's code and the timeout line.
pub fn check_timeout_report(streams: Streams, status: u8, ms: u32) Error!void {
    if (status != 143 and status != 137) return error.ExitCodeWrong;
    var expected: [64]u8 = undefined;
    const line = print(&expected, "zbx: stopped: timed out after {d} ms", .{ms});
    if (!has_line(streams.stderr, line)) return error.ReportWrong;
}

/// A refusal with a registered code: `error[ZBX-Exxxx]` first on stderr, nothing on stdout.
pub fn check_refused(streams: Streams, status: u8, code: []const u8, exit: u8) Error!void {
    if (status != exit) return error.ExitCodeWrong;
    var expected: [32]u8 = undefined;
    const header = print(&expected, "error[ZBX-{s}]: ", .{code});
    if (!std.mem.startsWith(u8, streams.stderr, header)) return error.LineMissing;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.StdoutNotEmpty;
}

/// `zbx schema ps`: a JSON Schema with its id.
pub fn check_schema(streams: Streams, status: u8, command: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var expected: [96]u8 = undefined;
    const id = print(
        &expected,
        "\"$id\":\"https://zigbox.github.io/zigbox/schema/{s}/1\"",
        .{command},
    );
    if (!contains(streams.stdout, id)) return error.JsonWrong;
    if (!contains(streams.stdout, "json-schema.org/draft/2020-12")) return error.JsonWrong;
}

// ---- Tests -----------------------------------------------------------------------------------

const testing = std.testing;

fn only_out(text: []const u8) Streams {
    return .{ .stdout = text, .stderr = "" };
}

fn only_err(text: []const u8) Streams {
    return .{ .stdout = "", .stderr = text };
}

fn replaced(original: []const u8, from: []const u8, to: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, testing.allocator, original, from, to);
}

test "fork bomb: probes answered, not cut off, and the report is the last word" {
    const report = "BOMB-LAST:zbx: stopped: process limit reached (limit 64)\n";
    const good = "PROBES:5\nBOMB-EXIT:0\n" ++ report;
    try check_fork_bomb(good, 64, 5);
    const slow = "PROBES:2\nBOMB-EXIT:0\n" ++ report;
    try testing.expectError(error.HostUnresponsive, check_fork_bomb(slow, 64, 5));
    const cut = "PROBES:5\nBOMB-EXIT:124\n" ++ report;
    try testing.expectError(error.ExitCodeWrong, check_fork_bomb(cut, 64, 5));
    const noise = "PROBES:5\nBOMB-EXIT:0\nBOMB-LAST:sh: can't fork\n";
    try testing.expectError(error.ReportWrong, check_fork_bomb(noise, 64, 5));
    try testing.expectError(error.ReportWrong, check_fork_bomb(good, 16, 5));
    try testing.expectError(error.LineMissing, check_fork_bomb("BOMB-EXIT:0\n", 64, 5));
}

test "oom: 137, and the report is the last line of stderr" {
    const report = "zbx: killed: out of memory (limit 128 MiB)\n";
    const noisy = only_err("stress-ng: info: dispatching\n" ++ report);
    try check_oom_report(noisy, 137, 128);
    try testing.expectError(error.ExitCodeWrong, check_oom_report(noisy, 1, 128));
    try testing.expectError(error.ReportWrong, check_oom_report(noisy, 137, 64));
    const later = only_err(report ++ "something after\n");
    try testing.expectError(error.ReportWrong, check_oom_report(later, 137, 128));
}

test "mount refusal: either spelling of EPERM, never zbx's own failure" {
    const busybox = only_err("mount: permission denied (are you root?)\n");
    const glibc = only_err("mount: /mnt: Operation not permitted.\n");
    try check_mount_refused(busybox, 1);
    try check_mount_refused(glibc, 32);
    try testing.expectError(error.ExitCodeWrong, check_mount_refused(busybox, 0));
    try testing.expectError(error.ExitCodeWrong, check_mount_refused(busybox, 125));
    const other = only_err("mount: no such device\n");
    try testing.expectError(error.LineMissing, check_mount_refused(other, 1));
}

test "read-only: /x refused, /tmp written" {
    const refused = only_err("touch: /x: Read-only file system\n");
    try check_read_only_refused(refused, 1);
    try testing.expectError(error.ExitCodeWrong, check_read_only_refused(only_err(""), 0));
    const denied = only_err("touch: /x: Permission denied\n");
    try testing.expectError(error.LineMissing, check_read_only_refused(denied, 1));
    try check_tmp_writable(only_out("tmp-ok\n"), 0);
    try testing.expectError(error.LineMissing, check_tmp_writable(only_out(""), 0));
    try testing.expectError(error.ExitCodeWrong, check_tmp_writable(only_out("tmp-ok\n"), 1));
}

test "hardening status: the allowlist mask, no_new_privs, seccomp filter mode" {
    const set = "00000000a00405fb";
    const good = "CapInh:\t" ++ set ++ "\nCapPrm:\t" ++ set ++ "\nCapEff:\t" ++ set ++
        "\nCapBnd:\t" ++ set ++ "\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
    try check_hardening_status(only_out(good), 0);
    const bad = try replaced(good, "Seccomp:\t2", "Seccomp:\t0");
    defer testing.allocator.free(bad);
    try testing.expectError(error.LineMissing, check_hardening_status(only_out(bad), 0));
}

test "limits and cleanup" {
    const running = "SCOPE-lim1:1\nmemory.max=67108864\nmemory.swap.max=0\n" ++
        "pids.max=20\ncpu.max=50000 100000\n";
    try check_limits_visible(running);
    try testing.expectError(error.LimitsWrong, check_limits_visible("SCOPE-lim1:1\n"));
    const gone = "SCOPE-lim1:0\nAFTER-CGROUP:0\nAFTER-MANAGER:0\n";
    try check_scope_gone(gone, "lim1");
    const left = try replaced(gone, "SCOPE-lim1:0", "SCOPE-lim1:1");
    defer testing.allocator.free(left);
    try testing.expectError(error.ScopeLeft, check_scope_gone(left, "lim1"));
    const cgroup = try replaced(gone, "AFTER-CGROUP:0", "AFTER-CGROUP:1");
    defer testing.allocator.free(cgroup);
    try testing.expectError(error.ScopeLeft, check_scope_gone(cgroup, "lim1"));
}

test "exit reasons: the JSON line names the reason and the code" {
    const oom = "noise\n{\"container_exit\":{\"reason\":\"oom\",\"limit_bytes\":3,\"code\":137}}\n";
    try check_exit_json(oom, "oom", 137);
    try testing.expectError(error.JsonWrong, check_exit_json(oom, "signal", 137));
    try testing.expectError(error.JsonWrong, check_exit_json(oom, "oom", 1));
    const plain = "{\"container_exit\":{\"reason\":\"exited\",\"code\":42}}\n";
    try check_exit_json(plain, "exited", 42);
}

const ps_json_good = "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"det1\"," ++
    "\"state\":\"running\",\"pid\":7,\"supervisor\":6,\"scope\":\"zbx-det1.scope\"," ++
    "\"detached\":true,\"timed_out\":false,\"started\":1,\"ended\":null,\"reason\":\"none\"," ++
    "\"exit_code\":null,\"command\":[\"sleep\",\"1000\"],\"labels\":[],\"limits\":{}}]}\n";

test "lifecycle: detached start and ps" {
    try check_detached_start(only_out("det1\n"), 0, "det1");
    try testing.expectError(error.LineMissing, check_detached_start(only_out("det2\n"), 0, "det1"));
    const noisy: Streams = .{ .stdout = "det1\n", .stderr = "x" };
    try testing.expectError(error.StderrNotEmpty, check_detached_start(noisy, 0, "det1"));
    const table = "NAME  STATE  PID  STARTED  COMMAND\ndet1  running  7  2026-01-01  sleep 1000\n";
    try check_ps_text(only_out(table), 0, "det1", "running");
    try testing.expectError(error.LineMissing, check_ps_text(only_out(table), 0, "det1", "lost"));
    try check_ps_json(only_out(ps_json_good), 0, "det1", "running", false);
    const timed = only_out(ps_json_good);
    try testing.expectError(error.JsonWrong, check_ps_json(timed, 0, "det1", "running", true));
    try testing.expectError(error.JsonWrong, check_ps_json(timed, 0, "det1", "stopped", false));
}

test "lifecycle: stop, timeout, refusals, schema" {
    const stopped = only_out("{\"schema\":\"zbx.stop/1\",\"name\":\"det1\"," ++
        "\"result\":\"killed\"," ++
        "\"reason\":\"signal\",\"exit_code\":137}\n");
    try check_stop_json(stopped, 0, "det1", "killed", 137);
    try testing.expectError(error.JsonWrong, check_stop_json(stopped, 0, "det1", "graceful", 137));
    try testing.expectError(error.JsonWrong, check_stop_json(stopped, 0, "det1", "killed", 7));
    try check_stop_again(only_out("det1 was not running, exit code 137\n"), 0, "det1");
    const timeout = only_err("zbx: stopped: timed out after 3000 ms\n");
    try check_timeout_report(timeout, 143, 3000);
    try testing.expectError(error.ReportWrong, check_timeout_report(only_err(""), 143, 3000));
    const refusal = only_err("error[ZBX-E0402]: no container with that name\n");
    try check_refused(refusal, 1, "E0402", 1);
    try testing.expectError(error.ExitCodeWrong, check_refused(refusal, 125, "E0402", 1));
    try testing.expectError(error.LineMissing, check_refused(refusal, 1, "E0401", 1));
    const schema = only_out("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\n" ++
        "\"$id\":\"https://zigbox.github.io/zigbox/schema/ps/1\"}");
    try check_schema(schema, 0, "ps");
    try testing.expectError(error.JsonWrong, check_schema(only_out("{}"), 0, "ps"));
    try testing.expectError(error.JsonWrong, check_schema(schema, 0, "stop"));
}
