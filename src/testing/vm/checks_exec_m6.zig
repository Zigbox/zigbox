//! The assertions of M6b slice 3's `zbx exec` as pure functions over the text the guest printed,
//! each unit-tested with right and wrong input. The commands that print it are in exec_m6.zig,
//! a part of demo-m6 until slice 4 moves it to demo-m6b.

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// The exec and the run of the same command did not fail the same way.
    NotLikeTheContainer,
    /// The command is not in the container's cgroup, or was not held to its process limit.
    LimitWrong,
    /// A refusal lacks its code, or its state.
    RefusalWrong,
    /// The command did not die with its container, or zbx did not say so.
    LifetimeWrong,
    /// The command had no terminal.
    TerminalWrong,
    /// The bundle lacks the exec, or holds the value of its `-e`.
    BundleWrong,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// Something the container may not do, tried by `zbx run` of a new container and by `zbx exec`
/// into a running one: both exit with the command's own failure (not 0, not zbx's 125 to 127),
/// and both say `refusal` (case aside) on stderr, as the kernel's EPERM reads.
pub fn check_same_refusal(
    run: Streams,
    run_status: u8,
    exec: Streams,
    exec_status: u8,
    refusal: []const u8,
) Error!void {
    for ([_]u8{ run_status, exec_status }) |status| {
        if (status == 0) return error.NotLikeTheContainer;
        if (status >= 125 and status <= 127) return error.ExitCodeWrong;
    }
    if (run_status != exec_status) return error.NotLikeTheContainer;
    for ([_][]const u8{ run.stderr, exec.stderr }) |text| {
        var lower: [4096]u8 = undefined;
        const length = @min(text.len, lower.len);
        const folded = std.ascii.lowerString(lower[0..length], text[0..length]);
        if (!contains(folded, refusal)) return error.NotLikeTheContainer;
    }
}

/// `cat /proc/self/cgroup` in the exec'd command: its unified line names the container's scope.
pub fn check_cgroup(output: []const u8, scope: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r");
        if (!std.mem.startsWith(u8, trimmed, "0::")) continue;
        if (std.mem.endsWith(u8, trimmed, scope)) return;
        return error.LimitWrong;
    }
    return error.LimitWrong;
}

/// A shell exec'd into a container at its process limit could not fork: busybox says so, and the
/// command failed.
pub fn check_fork_refused(streams: Streams, status: u8) Error!void {
    if (status == 0) return error.LimitWrong;
    if (status >= 125 and status <= 127) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "can't fork")) return error.LimitWrong;
}

/// An exec into a stopped container: ZBX-E0220, exit 125, naming the state.
pub fn check_stopped(streams: Streams, status: u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (!std.mem.startsWith(u8, streams.stderr, "error[ZBX-E0220]")) return error.RefusalWrong;
    if (!contains(streams.stderr, "is stopped")) return error.RefusalWrong;
    if (streams.stdout.len != 0) return error.RefusalWrong;
}

/// What the guest printed after a container was stopped under a running exec: `code=<n>` (the
/// exec's exit code, written when it ended) and its stderr. The command was killed with the
/// container (137), and zbx said the container ended.
pub fn check_died(output: []const u8) Error!void {
    if (!contains(output, "code=137")) return error.LifetimeWrong;
    if (!contains(output, "the container ex4 ended, and the command with it")) {
        return error.LifetimeWrong;
    }
}

/// A command whose `zbx` was killed: it was running (`started`), and a second later it was not
/// (`gone`).
pub fn check_gone(output: []const u8) Error!void {
    if (!contains(output, "started")) return error.LifetimeWrong;
    if (contains(output, "still-there")) return error.LifetimeWrong;
    if (!contains(output, "gone")) return error.LifetimeWrong;
}

/// `script` ran an exec whose command tested its standard input and output for a terminal.
pub fn check_terminal(output: []const u8) Error!void {
    if (!contains(output, "TTY-OK")) return error.TerminalWrong;
    if (contains(output, "TTY-NO")) return error.TerminalWrong;
}

/// The `execs.txt` of a bundle of the container: the exec that exited 42 is there, and the value
/// of the `-e` it was given is not.
pub fn check_bundle(execs: []const u8, value: []const u8) Error!void {
    if (!contains(execs, "exited 42")) return error.BundleWrong;
    if (!contains(execs, "\"exit 42\"")) return error.BundleWrong;
    if (contains(execs, value)) return error.BundleWrong;
}

const testing = std.testing;

fn two(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "check_same_refusal: the same failure, the kernel's words, never zbx's codes" {
    const said = two("", "unshare: unshare(0x10000000): Operation not permitted\n");
    try check_same_refusal(said, 1, said, 1, "not permitted");
    const busybox = two("", "mount: permission denied (are you root?)\n");
    try check_same_refusal(busybox, 255, busybox, 255, "permission denied");
    try testing.expectError(error.NotLikeTheContainer, check_same_refusal(said, 0, said, 0, "x"));
    try testing.expectError(error.ExitCodeWrong, check_same_refusal(said, 1, said, 125, "not"));
    const fine = two("", "");
    try testing.expectError(
        error.NotLikeTheContainer,
        check_same_refusal(said, 1, fine, 1, "not permitted"),
    );
    try testing.expectError(
        error.NotLikeTheContainer,
        check_same_refusal(said, 1, said, 2, "not permitted"),
    );
}

test "check_cgroup and check_fork_refused" {
    const scope = "zbx-ex2.scope";
    const line = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/zbx-ex2.scope\n";
    try check_cgroup(line, scope);
    const elsewhere = "0::/user.slice/session-3.scope\n";
    try testing.expectError(error.LimitWrong, check_cgroup(elsewhere, scope));
    try testing.expectError(error.LimitWrong, check_cgroup("", scope));
    const refused = two("", "sh: can't fork: Resource temporarily unavailable\n");
    try check_fork_refused(refused, 2);
    try testing.expectError(error.LimitWrong, check_fork_refused(refused, 0));
    try testing.expectError(error.LimitWrong, check_fork_refused(two("", ""), 1));
    try testing.expectError(error.ExitCodeWrong, check_fork_refused(refused, 125));
}

test "check_stopped, check_died, check_terminal and check_bundle" {
    const stopped = two("", "error[ZBX-E0220]: the container is not running\n  cause  " ++
        "the container ex1 is stopped: it was killed by signal 9\n");
    try check_stopped(stopped, 125);
    try testing.expectError(error.ExitCodeWrong, check_stopped(stopped, 1));
    try testing.expectError(error.RefusalWrong, check_stopped(two("", "error[ZBX-E0402]"), 125));
    const died = "code=137\nzbx: exec: the container ex4 ended, and the command with it\n";
    try check_died(died);
    try testing.expectError(error.LifetimeWrong, check_died("code=0\n"));
    try testing.expectError(error.LifetimeWrong, check_died("code=137\n"));
    try check_gone("started\ngone\n");
    try testing.expectError(error.LifetimeWrong, check_gone("started\nstill-there\n"));
    try testing.expectError(error.LifetimeWrong, check_gone("gone\n"));
    try check_terminal("TTY-OK\r\n");
    try testing.expectError(error.TerminalWrong, check_terminal("TTY-NO\r\n"));
    const execs = "1 recent execs of ex1\n2026-10-30T00-00-00Z  0s  exited 42  \"sh\" \"-c\" " ++
        "\"exit 42\"\n";
    try check_bundle(execs, "VALUE-PSI");
    try testing.expectError(error.BundleWrong, check_bundle(execs, "exit"));
    try testing.expectError(error.BundleWrong, check_bundle("1 recent execs\n", "VALUE-PSI"));
}
