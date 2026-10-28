//! The assertions of demo-m5's own parts (spec_m5.zig: the spec's four steps; accept_net_m5.zig:
//! the acceptance checks of a missing pasta), as pure functions over the text the guest printed,
//! each unit-tested with right and wrong input. The slice 2 and 3 assertions (the hint, the
//! generated files, the listener, the rules) are in checks_m5.zig; the spec's steps reuse them.

const std = @import("std");
const checks = @import("checks.zig");
const checks_m5 = @import("checks_m5.zig");

const Streams = checks.Streams;
const Error = checks_m5.Error;

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// Spec step 2: `wget -qO- https://example.com` with `--net user` printed example.com's page and
/// exited 0, and the no-network note is nowhere (the container had a network).
pub fn check_example_page(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, "Example Domain")) return error.PageWrong;
    if (contains(streams.stderr, "grant with --net")) return error.HintWrong;
}

/// Spec step 4, `ss -tlnp` run as the demo user: a socket listens on `port`. The process column
/// stays empty even though the socket is the demo user's: pasta drops its privileges and makes
/// itself undumpable once it is ready, so its `/proc/PID/fd` is closed to the user (the root
/// listing, `checks_m5.check_listener`, does name it). The peer address column ("0.0.0.0:*")
/// never ends in ":PORT ".
pub fn check_listener_listed(text: []const u8, port: u16) Error!void {
    var needle: [16]u8 = undefined;
    const local = std.fmt.bufPrint(&needle, ":{d} ", .{port}) catch return error.ListenerWrong;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "LISTEN")) continue;
        if (contains(line, local)) return;
    }
    return error.ListenerWrong;
}

/// The same with `-e`, as the demo user: the listener on `port` is owned by uid 1000. The owner
/// comes from the socket, so it shows without the process.
pub fn check_listener_owned(text: []const u8, port: u16) Error!void {
    var needle: [16]u8 = undefined;
    const local = std.fmt.bufPrint(&needle, ":{d} ", .{port}) catch return error.ListenerWrong;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "LISTEN")) continue;
        if (!contains(line, local)) continue;
        if (contains(line, " uid:1000 ")) return;
    }
    return error.ListenerWrong;
}

/// The rules read before were real rules: `iptables -S` and `ip6tables -S` print their built-in
/// chains' policies (`-P INPUT ...`) even when there is no rule. A guest without `iptables`
/// prints "command not found" both times, and two such texts are equal, so equality alone shows
/// nothing.
pub fn check_rules_read(text: []const u8) Error!void {
    var chains: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "-P INPUT ")) chains += 1;
        if (std.mem.startsWith(u8, line, "-P FORWARD ")) chains += 1;
        if (std.mem.startsWith(u8, line, "-P OUTPUT ")) chains += 1;
    }
    // Both programs, three chains each.
    if (chains != 6) return error.RulesChanged;
}

/// `zbx doctor` on a host without pasta (a PATH that lacks it): a warning on the `net` line that
/// says how to install it, and exit 0, because `--net none` and `--net host` work without it.
pub fn check_doctor_without_pasta(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "warn net ")) continue;
        if (!contains(line, "pasta not found")) return error.FileWrong;
        if (!contains(line, "apt install passt")) return error.FileWrong;
        return;
    }
    return error.FileWrong;
}

/// `zbx doctor` with pasta on PATH: the `net` line is `ok` and names pasta.
pub fn check_doctor_with_pasta(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "ok   net ")) continue;
        if (!contains(line, "pasta")) return error.FileWrong;
        return;
    }
    return error.FileWrong;
}

/// `zbx run --net user alpine -- true` without pasta: refused before the container exists
/// (exit 125, nothing on stdout), as ZBX-E0601 with its install command, and not as a hint.
pub fn check_run_without_pasta(streams: Streams, status: u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.PageWrong;
    if (!contains(streams.stderr, "error[ZBX-E0601]: pasta is not installed\n")) {
        return error.FileWrong;
    }
    if (!contains(streams.stderr, "sudo apt install passt")) return error.FileWrong;
    if (contains(streams.stderr, "grant with --net")) return error.HintWrong;
}

const testing = std.testing;

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "example.com's page came through --net user" {
    // Goal: spec step 2. Method: right; no page; a failed run; the note where none belongs.
    try check_example_page(captured("<title>Example Domain</title>\n", ""), 0);
    try testing.expectError(error.PageWrong, check_example_page(captured("", ""), 0));
    const failed = captured("", "wget: bad address 'example.com'\n");
    try testing.expectError(error.ExitCodeWrong, check_example_page(failed, 1));
    const noted = captured("Example Domain\n", checks_m5.hint ++ "\n");
    try testing.expectError(error.HintWrong, check_example_page(noted, 0));
}

test "the listener ss shows the demo user is on the port, and owns it" {
    // Goal: spec step 4's `ss` as the demo user. Method: the line the guest printed in run
    // 40746904215 (no process column); the same with the -e columns of run 40738142463; a
    // listener of another uid; the port free; a port that is a prefix.
    const listed = "State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n" ++
        "LISTEN 0      128          0.0.0.0:8080      0.0.0.0:*          \n" ++
        "LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*          \n";
    try check_listener_listed(listed, 8080);
    try testing.expectError(error.ListenerWrong, check_listener_listed(listed, 808));
    try testing.expectError(error.ListenerWrong, check_listener_listed(listed, 9090));
    try testing.expectError(error.ListenerWrong, check_listener_listed("", 8080));
    const owned = "LISTEN 0      128          0.0.0.0:8080      0.0.0.0:*    " ++
        "uid:1000 ino:16798 sk:1001 cgroup:/user.slice/user-0.slice/session-2.scope <->\n";
    try check_listener_owned(owned, 8080);
    try testing.expectError(error.ListenerWrong, check_listener_owned(listed, 8080));
    try testing.expectError(error.ListenerWrong, check_listener_owned(owned, 808));
    const root = "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* uid:0 ino:1 sk:2 <->\n";
    try testing.expectError(error.ListenerWrong, check_listener_owned(root, 8080));
}

test "the rules that were read are rules" {
    // Goal: an empty comparison proves nothing. Method: both programs' output; one program
    // missing; a guest without either.
    const both = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n" ++
        "---\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
    try check_rules_read(both);
    const one = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n---\nip6tables: not found\n";
    try testing.expectError(error.RulesChanged, check_rules_read(one));
    const missing = "sh: 1: iptables: not found\n---\nsh: 1: ip6tables: not found\n";
    try testing.expectError(error.RulesChanged, check_rules_read(missing));
}

test "doctor warns about a missing pasta and still passes" {
    // Goal: the acceptance check of doctor. Method: the line from src/testdata/doctor/
    // pasta_missing.txt; an ok line; a failing doctor; no net line.
    const warned = "ok   seccomp  s\nwarn net  pasta not found: --net user and --publish " ++
        "need it " ++
        "(apt install passt)\n";
    try check_doctor_without_pasta(captured(warned, ""), 0);
    const failed = check_doctor_without_pasta(captured(warned, ""), 2);
    try testing.expectError(error.ExitCodeWrong, failed);
    const found = "ok   net  pasta unknown version at /usr/bin/pasta\n";
    try testing.expectError(error.FileWrong, check_doctor_without_pasta(captured(found, ""), 0));
    const bare = "warn net  pasta not found\n";
    try testing.expectError(error.FileWrong, check_doctor_without_pasta(captured(bare, ""), 0));
    try testing.expectError(error.FileWrong, check_doctor_without_pasta(captured("", ""), 0));
    try check_doctor_with_pasta(captured(found, ""), 0);
    try testing.expectError(error.FileWrong, check_doctor_with_pasta(captured(warned, ""), 0));
}

test "a run without pasta is refused as E0601 before it starts" {
    // Goal: the acceptance check of the run. Method: src/testdata/diag/E0601.txt; a run that
    // started (exit 1); the hint instead of the diagnostic; output on stdout.
    const refused = "error[ZBX-E0601]: pasta is not installed\n" ++
        "  cause  no executable named pasta in the directories of PATH\n" ++
        "  fix    install pasta (Debian, Ubuntu):   sudo apt install passt\n";
    try check_run_without_pasta(captured("", refused), 125);
    try testing.expectError(error.ExitCodeWrong, check_run_without_pasta(captured("", refused), 1));
    try testing.expectError(error.PageWrong, check_run_without_pasta(captured("x", refused), 125));
    const hint = captured("", checks_m5.hint ++ "\n");
    try testing.expectError(error.FileWrong, check_run_without_pasta(hint, 125));
    const other = "error[ZBX-E0603]: pasta failed to start\n  fix  sudo apt install passt\n";
    try testing.expectError(error.FileWrong, check_run_without_pasta(captured("", other), 125));
}
