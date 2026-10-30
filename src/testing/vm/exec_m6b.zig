//! M6b slice 3's `zbx exec` in the VM, a part of demo-m6b (`EXEC`). As the user `demo`, in the
//! net project (`zn`), with a running alpine container that mounts the project's `site`:
//!
//!   1. `exec` writes a file into the writable mount; on the host it is the user's.
//!   2. A syscall the container's filter refuses (`unshare -U`) and a capability it lacks
//!      (`mount`) fail in an exec exactly as in a run of the same image.
//!   3. The exec'd command is in the container's cgroup (its scope) and held to its `--pids`.
//!   4. The command's exit code is zbx's; a value of `-e` is in no byte of the bundle, which
//!      notes the exec.
//!   5. Under `script` (a terminal on zbx's input and output), the command has a terminal.
//!   6. An exec'd command dies with its container, and zbx says so instead of hanging.
//!   7. `exec` into the stopped container is refused, naming its state.
//!   8. A foreground `run` of an image whose user is not root (memcached:alpine), and an `exec`
//!      with `--user`: their `zbx` killed with SIGKILL, the command is gone within a second (the
//!      change of user clears the death signal; the child asks for it again).
//!
//! Every assertion is a function of checks_exec_m6b.zig with a unit test. Each command but the
//! one under `script` reads /dev/null: the guest's console is a terminal, and an exec with a
//! terminal on both ends gets a pseudo-terminal, which part 5 is for.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_exec_m6b.zig");
const writable = @import("checks_writable_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "EXEC";

const project = net_user.net_project;
const by_exec_owns = H.as_demo ++
    writable.owners_command(project ++ "/site/by-exec.txt", project ++ "/site");
const no_input = " </dev/null";
const secret_value = "VALUE-PSI-77";

pub fn step_exec(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: EXEC: zbx exec (M6b slice 3)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try ok(session, out, zn ++ " pull alpine");
    _ = try ok(session, out, H.as_demo ++ "mkdir -p " ++ project ++ "/site");
    _ = try ok(session, out, zn ++ " run -d --name ex1 --mount site:/srv alpine -- sleep 1000");
    try writes_a_file(session, out);
    try refused_alike(session, out);
    try in_the_cgroup(session, out);
    try code_and_bundle(session, out);
    try terminal(session, out);
    try dies_with_container(session, out);
    try stopped(session, out);
    try killed_zbx(session, out);
    try timer.lap(out, "exec");
}

fn ok(session: *Session, out: *Io.Writer, command: []const u8) !H.SplitResult {
    return common.expect_exit(session, out, step_name, command, 0);
}

fn writes_a_file(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: EXEC 1: a file written by exec is the host user's\n", .{H.demo_name});
    const write = zn ++ " exec ex1 -- sh -c 'echo made-by-exec > /srv/by-exec.txt'" ++ no_input;
    _ = try ok(session, out, write);
    const owners = try ok(session, out, by_exec_owns);
    writable.check_owner(owners.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the host user to own the file", err);
    };
}

/// The same command in a new container and in an exec: both fail the same way.
fn alike(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    name: []const u8,
    refusal: []const u8,
) !void {
    const run_line = try common.format(session, "{s} run --name {s} alpine -- {s}", .{
        zn, name, command,
    });
    const ran = try common.run_shown(session, out, run_line);
    // The streams live in the session's buffer: kept before the next command.
    const run_streams = H.SplitResult{
        .streams = .{
            .stdout = try session.scratch_allocator().dupe(u8, ran.streams.stdout),
            .stderr = try session.scratch_allocator().dupe(u8, ran.streams.stderr),
        },
        .status = ran.status,
    };
    const exec_line = try common.format(session, "{s} exec ex1 -- {s}{s}", .{
        zn, command, no_input,
    });
    const execd = try common.run_shown(session, out, exec_line);
    checks.check_same_refusal(
        run_streams.streams,
        run_streams.status,
        execd.streams,
        execd.status,
        refusal,
    ) catch |err| {
        return fail_step(out, step_name, "expected the exec to fail as the run does", err);
    };
}

fn refused_alike(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: EXEC 2: a refused syscall and a missing capability, as in a run\n";
    try out.print(title, .{H.demo_name});
    try alike(session, out, "unshare -U true", "ex-r1", "not permitted");
    try alike(session, out, "mount -t tmpfs none /mnt", "ex-r2", "permission denied");
}

fn in_the_cgroup(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: EXEC 3: the command is in the container's cgroup and under its --pids\n";
    try out.print(title, .{H.demo_name});
    _ = try ok(session, out, zn ++ " run -d --name ex2 --pids 2 alpine -- sleep 1000");
    const cgroup = try ok(session, out, zn ++ " exec ex2 -- cat /proc/self/cgroup" ++ no_input);
    checks.check_cgroup(cgroup.streams.stdout, "zbx-ex2.scope") catch |err| {
        return fail_step(out, step_name, "expected the command in the container's scope", err);
    };
    const fork = zn ++ " exec ex2 -- sh -c 'sleep 1 & wait'" ++ no_input;
    const forked = try common.run_shown(session, out, fork);
    checks.check_fork_refused(forked.streams, forked.status) catch |err| {
        return fail_step(out, step_name, "expected the container's process limit to hold", err);
    };
    _ = try ok(session, out, zn ++ " stop ex2");
}

fn code_and_bundle(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: EXEC 4: the command's exit code; the bundle notes it, never -e\n";
    try out.print(title, .{H.demo_name});
    const exit = zn ++ " exec ex1 -e SECRET=" ++ secret_value ++ " -- sh -c 'exit 42'" ++
        no_input;
    _ = try common.expect_exit(session, out, step_name, exit, 42);
    _ = try ok(session, out, zn ++ " bundle ex1 --no-redact");
    const read = H.as_demo ++ "sh -c 'tar -xzOf \"$(ls -t " ++ common.state_dir ++
        "/bundles/*.tar.gz | head -n 1)\" --wildcards \"*/execs.txt\"'";
    const execs = try ok(session, out, read);
    checks.check_bundle(execs.streams.stdout, secret_value) catch |err| {
        return fail_step(out, step_name, "expected the exec in the bundle, without -e", err);
    };
}

fn terminal(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: EXEC 5: with a terminal, the command has one\n", .{H.demo_name});
    const inner = zn ++ " exec ex1 -- sh -c " ++
        "\"test -t 0 && test -t 1 && echo TTY-OK || echo TTY-NO\"";
    const shown = try ok(session, out, "script -qec '" ++ inner ++ "' /dev/null");
    checks.check_terminal(shown.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected a terminal for the command", err);
    };
}

fn dies_with_container(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: EXEC 6: an exec'd command dies with its container\n";
    try out.print(title, .{H.demo_name});
    _ = try ok(session, out, "rm -f /tmp/ex4.code /tmp/ex4.err");
    _ = try ok(session, out, zn ++ " run -d --name ex4 alpine -- sleep 1000");
    const start = H.as_demo_setsid ++ "sh -c \"/home/demo/zn exec ex4 -- sleep 600 </dev/null " ++
        "2>/tmp/ex4.err; echo code=\\$? >/tmp/ex4.code\" </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 100); do pgrep -u demo -fx 'sleep 600' >/dev/null && break; " ++
        "sleep 0.2; done; sleep 1; pgrep -u demo -fx 'sleep 600' >/dev/null && echo exec-runs";
    const started = try ok(session, out, start);
    if (std.mem.indexOf(u8, started.streams.stdout, "exec-runs") == null) {
        return fail_step(out, step_name, "expected the exec to run", error.LifetimeWrong);
    }
    _ = try ok(session, out, zn ++ " stop ex4");
    const ended = "for i in $(seq 30); do test -f /tmp/ex4.code && break; sleep 1; done; " ++
        "cat /tmp/ex4.code /tmp/ex4.err";
    const shown = try ok(session, out, ended);
    checks.check_died(shown.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the exec to end with its container", err);
    };
}

fn stopped(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: EXEC 7: exec into a stopped container\n", .{H.demo_name});
    _ = try ok(session, out, zn ++ " stop ex1");
    const result = try common.run_shown(session, out, zn ++ " exec ex1 -- true" ++ no_input);
    checks.check_stopped(result.streams, result.status) catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0220 naming the state", err);
    };
}

/// Starts `command` (a `zn` line whose command is `sleep <marker>`) in its own session, waits
/// for the sleep, kills the `zbx` whose arguments hold `zbx_marker` with SIGKILL, and a second
/// later says whether the sleep is still there.
fn kill_and_look(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    sleep: []const u8,
    zbx_marker: []const u8,
) !void {
    const line = try common.format(session, "{s}{s} </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 100); do pgrep -fx '{s}' >/dev/null && break; sleep 0.2; done; " ++
        "pgrep -fx '{s}' >/dev/null && echo started; pkill -KILL -u demo -f -- '{s}'; " ++
        "sleep 1; pgrep -fx '{s}' >/dev/null && echo still-there || echo gone", .{
        H.as_demo_setsid, command, sleep, sleep, zbx_marker, sleep,
    });
    const shown = try ok(session, out, line);
    checks.check_gone(shown.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the command gone with its zbx", err);
    };
}

fn killed_zbx(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: EXEC 8: a command that runs as a user dies with a killed zbx\n";
    try out.print(title, .{H.demo_name});
    _ = try ok(session, out, zn ++ " pull memcached:alpine");
    const run = "/home/demo/zn run --name pd1 memcached:alpine -- sleep 611";
    try kill_and_look(session, out, run, "sleep 611", "--name pd1 ");
    _ = try ok(session, out, zn ++ " run -d --name ex6 alpine -- sleep 1000");
    const exec = "/home/demo/zn exec --user 1000 ex6 -- sleep 612";
    try kill_and_look(session, out, exec, "sleep 612", "exec --user 1000 ex6");
    _ = try ok(session, out, zn ++ " stop ex6");
}

test {
    _ = @import("checks_exec_m6b.zig");
    _ = limits;
}
