//! M6b slice 2's `zbx logs` in the VM, a temporary part of demo-m6 (`LOGS`); slice 4 moves it to
//! demo-m6b. As the user `demo`, in the net project (`zn`):
//!
//!   1. A detached `python -m http.server` is asked for `/` and for a path it lacks; its requests
//!      are in `zbx logs` (and in `--stream stderr`, and as `zbx.logs/1` lines).
//!   2. A foreground run's `zbx` is killed (SIGKILL) while its command runs: the log is still
//!      readable and has what the command wrote before.
//!   3. A foreground run shows its two streams on the terminal and keeps both in its log.
//!   4. `--follow` of a detached container that prints for three seconds shows it all, and ends
//!      with exit 0 when the container does.
//!   5. The cap: a container that writes 5,840,000 bytes (more than 5 MiB). Its log holds the end
//!      of that output from a whole record on, `dropped_bytes` and the bytes shown add up to
//!      what was written, and the two files on the disk are each at most half the cap.
//!
//! Every assertion is a function of checks_logs_m6.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_logs_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "LOGS";

const python = "python:3.12-slim";
const port = "18089";

const serve = zn ++ " run -d --name lg1 --publish " ++ port ++ ":8000 " ++ python ++
    " -- python -m http.server 8000";
const ask = "for i in $(seq 60); do curl -fsS -o /dev/null http://127.0.0.1:" ++ port ++
    "/ && break; sleep 1; done; curl -sS -o /dev/null http://127.0.0.1:" ++ port ++
    "/nothing-lg; sleep 1";

const written_total: u64 = 5_840_000;
const cap: u64 = 5 * 1024 * 1024;
const last_line = "line-079999 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const writer_loop = "i=0; while [ $i -lt 80000 ]; do printf \"line-%06d " ++
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n\" $i; i=$((i+1)); done";
const flood = zn ++ " run -d --name lg5 alpine -- sh -c '" ++ writer_loop ++ "'";

/// The guest's summary of the capped log, one `key=value` per line (a script, so that the
/// quoting of the command line stays simple).
const summary_script =
    "#!/bin/sh\n" ++
    "Z=/home/demo/zn\n" ++
    "L=" ++ common.state_dir ++ "/logs\n" ++
    "$Z logs lg5 > /tmp/lg5.txt 2> /tmp/lg5.err\n" ++
    "$Z --output json logs lg5 > /tmp/lg5.json 2> /dev/null\n" ++
    "echo bytes=$(wc -c < /tmp/lg5.txt)\n" ++
    "echo last=$(tail -n 1 /tmp/lg5.txt)\n" ++
    "echo code=$(grep -o 'ZBX-W0205' /tmp/lg5.err | head -n 1)\n" ++
    "echo warned=$(grep -o '[0-9]* bytes of older output' /tmp/lg5.err | grep -o '^[0-9]*')\n" ++
    "echo dropped=$(head -n 1 /tmp/lg5.json | grep -o '\"dropped_bytes\":[0-9]*' | " ++
    "grep -o '[0-9]*$')\n" ++
    "echo later=$(tail -n +2 /tmp/lg5.json | grep -c dropped_bytes)\n" ++
    "echo records=$(wc -l < /tmp/lg5.json)\n" ++
    "echo current=$(stat -c %s $L/lg5.log)\n" ++
    "echo older=$(stat -c %s $L/lg5.log.1)\n";
const summary_path = "/home/demo/lg5-summary.sh";

pub fn step_logs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: LOGS: zbx logs (M6b slice 2)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try ok(session, out, zn ++ " pull alpine");
    _ = try ok(session, out, zn ++ " pull " ++ python);
    try server_requests(session, out);
    try killed_zbx(session, out);
    try foreground(session, out);
    try follow(session, out);
    try the_cap(session, out);
    try timer.lap(out, "logs");
}

/// Runs `command` and fails the step unless it exits 0.
fn ok(session: *Session, out: *Io.Writer, command: []const u8) !H.SplitResult {
    return common.expect_exit(session, out, step_name, command, 0);
}

fn server_requests(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: LOGS 1: a detached server's requests are in its log\n", .{H.demo_name});
    _ = try ok(session, out, serve);
    _ = try ok(session, out, ask);
    const log = try ok(session, out, zn ++ " logs lg1");
    checks.check_requests(log.streams.stdout, "/", "/nothing-lg") catch |err| {
        return fail_step(out, step_name, "expected the two requests in the log", err);
    };
    const errors = try ok(session, out, zn ++ " logs lg1 --stream stderr");
    checks.check_requests(errors.streams.stdout, "/", "/nothing-lg") catch |err| {
        return fail_step(out, step_name, "expected the requests on the error stream", err);
    };
    const json = try ok(session, out, zn ++ " --output json logs lg1");
    checks.check_json(json.streams.stdout, null, 2) catch |err| {
        return fail_step(out, step_name, "expected zbx.logs/1 lines", err);
    };
    const quiet = try ok(session, out, zn ++ " logs lg1 --tail 1");
    if (std.mem.count(u8, quiet.streams.stdout, "\n") != 1) {
        return fail_step(out, step_name, "expected one line of --tail 1", error.OutputWrong);
    }
    _ = try ok(session, out, zn ++ " stop lg1");
}

fn killed_zbx(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: LOGS 2: the log after the zbx that started it was killed\n";
    try out.print(title, .{H.demo_name});
    const start = H.as_demo_setsid ++ "/home/demo/zn run --name lg2 alpine -- sh -c " ++
        "\"echo before-the-kill; sleep 600\" </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 100); do pgrep -u demo -fx 'sleep 600' >/dev/null && break; " ++
        "sleep 0.2; done; sleep 1; pkill -KILL -u demo -f -- '--name lg2 ' && echo killed";
    _ = try ok(session, out, start);
    const log = try ok(session, out, zn ++ " logs lg2");
    if (!std.mem.eql(u8, std.mem.trim(u8, log.streams.stdout, " \r\n"), "before-the-kill")) {
        const what = "expected the log to hold what was written";
        return fail_step(out, step_name, what, error.OutputWrong);
    }
}

fn foreground(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: LOGS 3: a foreground run's output, on the terminal and in the log\n", .{
        H.demo_name,
    });
    const run = zn ++ " run --name lg3 alpine -- sh -c 'echo to-stdout; echo to-stderr >&2'";
    const shown = try ok(session, out, run);
    const terminal = shown.streams;
    const log = try ok(session, out, zn ++ " logs lg3");
    checks.check_foreground(terminal, log.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the output on the terminal and in the log", err);
    };
    const only = try ok(session, out, zn ++ " logs lg3 --stream stderr");
    checks.check_stream(only.streams.stdout, "to-stderr", "to-stdout") catch |err| {
        return fail_step(out, step_name, "expected only the error stream", err);
    };
}

fn follow(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: LOGS 4: --follow ends, exit 0, when the container ends\n";
    try out.print(title, .{H.demo_name});
    const start = zn ++ " run -d --name lg4 alpine -- sh -c " ++
        "'for i in 1 2 3; do echo tick-$i; sleep 1; done'";
    _ = try ok(session, out, start);
    const followed = try ok(session, out, "timeout 50 " ++ zn ++ " logs --follow lg4");
    checks.check_follow(followed.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the three ticks, then the end", err);
    };
}

fn the_cap(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: LOGS 5: a container that writes more than 5 MiB\n", .{H.demo_name});
    _ = try ok(session, out, flood);
    // The last line, then the end of the container: --follow waits for it.
    const wait = "timeout 55 " ++ zn ++ " logs --follow --tail 1 lg5";
    const ended = try ok(session, out, wait);
    if (std.mem.indexOf(u8, ended.streams.stdout, last_line) == null) {
        return fail_step(out, step_name, "expected the last line", error.CapWrong);
    }
    try H.put_file(session, summary_path, summary_script);
    const chown = "chown demo:demo " ++ summary_path ++ " && chmod 755 " ++ summary_path;
    _ = try ok(session, out, chown);
    const summary = try ok(session, out, H.as_demo ++ summary_path);
    checks.check_cap(summary.streams.stdout, written_total, cap, last_line) catch |err| {
        const what = "expected the end of the output, from a whole record";
        return fail_step(out, step_name, what, err);
    };
}

test {
    _ = @import("checks_logs_m6.zig");
    _ = limits;
}
