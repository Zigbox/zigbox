//! M6 slice 2's state volumes in the VM, a part of demo-m5 (`STATE`) until demo-m6 exists in
//! slice 4. As the user `demo`, in the net project (`zn`), with `postgres:16`:
//!
//!   1. postgres runs detached with `--state pgdata:/var/lib/postgresql/data --publish
//!      5432:5432`; `psql` from the guest creates a table and writes a row.
//!   2. A second writer of `pgdata` is refused (E0706) naming `pg`; `state ls` says it is in use
//!      by `pg`.
//!   3. The container's PID 1 is killed with SIGKILL; the lock is free; the same command again,
//!      and the row is there.
//!   4. `state ls` shows the volume, its size and its last container.
//!   5. `zbx stop`; the data directory inside a `:ro` run is owned by 999, mode 700: postgres's
//!      entrypoint `chown`ed it through the id map, with no `chmod 777`.
//!   6. The lock is free after each exit path: a clean exit, `--timeout`, SIGKILL of zbx in the
//!      foreground, and SIGKILL of a detached run's supervisor (SIGKILL of the container and
//!      `zbx stop` are steps 3 and 5).
//!   7. `state rm` moves it to the trash and `state restore` brings it back.
//!
//! postgres needs its password variable, and `-e` arrives in slice 1 in parallel. Until then the
//! words after `--` (which replace the image's command, not its entrypoint) start the entrypoint
//! a second time under `env POSTGRES_HOST_AUTH_METHOD=trust`: the first entrypoint sees `env` and
//! only `exec`s it. Slice 4's demo-m6 uses `-e`.
//!
//! Every assertion is a function of checks_state_m6.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_state_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "STATE";

const image = "postgres:16";
const volume_flag = " --state pgdata:/var/lib/postgresql/data";
const trust = " -- env POSTGRES_HOST_AUTH_METHOD=trust docker-entrypoint.sh postgres";
const start_pg = zn ++ " run -d --name pg" ++ volume_flag ++ " --publish 5432:5432 " ++ image ++
    trust;
const psql = H.as_demo ++ "psql -h 127.0.0.1 -U postgres -v ON_ERROR_STOP=1 ";
const row = "kept-across-sigkill";
const lock_file = "/home/demo/.local/share/zbx/state/pgdata/lock";
const pg_ready = H.as_demo ++ "sh -c 'for i in $(seq 120); do " ++
    "pg_isready -q -h 127.0.0.1 && psql -h 127.0.0.1 -U postgres -tAc \"select 1\" " ++
    ">/dev/null 2>&1 && break; sleep 1; done; pg_isready -h 127.0.0.1'";
/// `flock(1)` tries the volume's lock without waiting, for up to ten seconds (a supervisor
/// finishes its record a moment after its container is gone).
const lock_free = H.as_demo ++ "sh -c 'for i in $(seq 50); do " ++
    "flock -n -x " ++ lock_file ++ " true && break; sleep 0.2; done; " ++
    "flock -n -x " ++ lock_file ++ " echo free || echo held'";
/// The pid of a container's PID 1, from `ps --output json` (one object per line first).
fn pid_of(comptime name: []const u8) []const u8 {
    return zn ++ " ps --output json | tr '{' '\\n' | grep '\"name\":\"" ++ name ++ "\"' | " ++
        "sed -n 's/.*\"pid\":\\([0-9]*\\),\"supervisor\".*/\\1/p'";
}

pub fn step_state(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: STATE: state volumes with postgres (M6 slice 2)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    for ([_][]const u8{ image, "alpine" }) |reference| {
        const command = try common.format(session, "{s} pull {s}", .{ zn, reference });
        _ = try expect_long(session, out, command, 0, 600);
    }
    try write_row(session, out);
    try second_writer(session, out);
    try kill_and_rerun(session, out);
    try stop_and_owner(session, out);
    try exit_paths(session, out);
    try trash_round_trip(session, out);
    try timer.lap(out, "state");
}

fn expect_long(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    want: u8,
    timeout_s: u32,
) !Session.Result {
    const result = try session.run(command, timeout_s);
    try H.show(out, command, result);
    if (result.status != want) return fail_step(out, step_name, command, error.ExitCodeWrong);
    return result;
}

fn wait_ready(session: *Session, out: *Io.Writer) !void {
    _ = try expect_long(session, out, pg_ready, 0, 180);
}

fn expect_free(session: *Session, out: *Io.Writer, why: []const u8) !void {
    const result = try session.run(lock_free, limits.command_timeout_kvm_s);
    const title = try common.format(session, "the lock of pgdata {s}", .{why});
    try H.show(out, title, result);
    checks.check_free(result.output) catch |err| {
        return fail_step(out, step_name, "expected the volume's lock free", err);
    };
}

fn listing(session: *Session, out: *Io.Writer, expect: checks.Expect, what: []const u8) !void {
    const result = try common.run_shown(session, out, zn ++ " --output json state ls");
    const allocator = session.scratch_allocator();
    checks.check_listing(allocator, result.streams.stdout, expect) catch |err| {
        return fail_step(out, step_name, what, err);
    };
}

fn write_row(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 1: postgres with --state, a row written with psql\n", .{
        H.demo_name,
    });
    _ = try expect_long(session, out, start_pg, 0, 300);
    try wait_ready(session, out);
    const write = psql ++ "-c \"create table t (v text); insert into t values ('" ++ row ++ "')\"";
    _ = try expect_long(session, out, write, 0, limits.command_timeout_kvm_s);
}

fn second_writer(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 2: a second writer is refused, and ls names the holder\n", .{
        H.demo_name,
    });
    const second = zn ++ " run --name pg2 --state pgdata:/data alpine -- true";
    const result = try common.run_shown(session, out, second);
    checks.check_in_use(result.streams, result.status, "pg") catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0706 naming pg", err);
    };
    try listing(session, out, .{
        .name = "pgdata",
        .last_container = "pg",
        .in_use = true,
        .user = "pg",
        .disk_bytes_min = 1 << 20,
    }, "expected pgdata in use by pg");
}

fn kill_and_rerun(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 3: SIGKILL of postgres, the same command again, the row\n", .{
        H.demo_name,
    });
    const kill = "kill -KILL $(" ++ pid_of("pg") ++ ") && echo killed";
    _ = try expect_long(session, out, kill, 0, limits.command_timeout_kvm_s);
    try expect_free(session, out, "after SIGKILL of the container");
    _ = try expect_long(session, out, start_pg, 0, 300);
    try wait_ready(session, out);
    const read = psql ++ "-tAc \"select v from t\"";
    const result = try expect_long(session, out, read, 0, limits.command_timeout_kvm_s);
    checks.check_row(result.output, result.status, row) catch |err| {
        return fail_step(out, step_name, "expected the row written before the kill", err);
    };
    try out.print("\n{s}: STATE 4: state ls shows pgdata, its size and its last container\n", .{
        H.demo_name,
    });
    _ = try common.run_shown(session, out, zn ++ " state ls");
    try listing(session, out, .{
        .name = "pgdata",
        .last_container = "pg",
        .in_use = true,
        .user = "pg",
        .disk_bytes_min = 1 << 20,
    }, "expected pgdata with its size and last container pg");
}

fn stop_and_owner(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 5: zbx stop, then the owner inside a read-only run\n", .{
        H.demo_name,
    });
    _ = try expect_long(session, out, zn ++ " stop pg", 0, limits.command_timeout_kvm_s);
    try expect_free(session, out, "after zbx stop");
    const host_view = "stat -c '%u %g %a' /home/demo/.local/share/zbx/state/pgdata/data";
    _ = try expect_long(session, out, host_view, 0, limits.command_timeout_kvm_s);
    const inside = zn ++ " run --name pgro --state pgdata:/d:ro " ++ image ++
        " -- stat -c '%u %g %a' /d";
    const result = try common.run_shown(session, out, inside);
    checks.check_owner(result.streams.stdout, result.status) catch |err| {
        return fail_step(out, step_name, "expected /d owned by 999, mode 700, inside", err);
    };
    const touch = zn ++ " run --name pgro2 --state pgdata:/d:ro alpine -- touch /d/x";
    const refused = try common.run_shown(session, out, touch);
    if (refused.status == 0) return fail_step(out, step_name, touch, error.ExitCodeWrong);
    try expect_free(session, out, "after the read-only runs");
}

fn exit_paths(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 6: the lock is free after each exit path\n", .{H.demo_name});
    const clean = zn ++ " run --name st1 --state pgdata:/d alpine -- true";
    _ = try expect_long(session, out, clean, 0, limits.command_timeout_kvm_s);
    try expect_free(session, out, "after a clean exit");
    const timed = zn ++ " run --name st2 --timeout 2000 --state pgdata:/d alpine -- sleep 60";
    const result = try session.run(timed, limits.command_timeout_kvm_s);
    try H.show(out, timed, result);
    try expect_free(session, out, "after --timeout");
    const foreground = H.as_demo_setsid ++ "/home/demo/zn run --name st3 --state pgdata:/d " ++
        "alpine -- sleep 600 </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 100); do pgrep -u demo -fx 'sleep 600' >/dev/null && break; " ++
        "sleep 0.2; done; pkill -KILL -u demo -f -- '--name st3 ' && echo killed";
    _ = try expect_long(session, out, foreground, 0, limits.command_timeout_kvm_s);
    try expect_free(session, out, "after SIGKILL of zbx");
    const detached = zn ++ " run -d --name st4 --state pgdata:/d alpine -- sleep 600";
    _ = try expect_long(session, out, detached, 0, limits.command_timeout_kvm_s);
    const kill = "pkill -KILL -u demo -f -- '--name st4 ' && echo killed";
    _ = try expect_long(session, out, kill, 0, limits.command_timeout_kvm_s);
    try expect_free(session, out, "after SIGKILL of a detached run's supervisor");
}

fn trash_round_trip(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: STATE 7: state rm to the trash, state restore back\n", .{H.demo_name});
    _ = try expect_long(session, out, zn ++ " state rm pgdata", 0, limits.command_timeout_kvm_s);
    _ = try common.run_shown(session, out, zn ++ " state ls");
    const restore = zn ++ " state restore pgdata";
    _ = try expect_long(session, out, restore, 0, limits.command_timeout_kvm_s);
    try listing(session, out, .{
        .name = "pgdata",
        .last_container = "st4",
        .in_use = false,
        .disk_bytes_min = 1 << 20,
    }, "expected pgdata back, whole");
}

test {
    _ = @import("checks_state_m6.zig");
}
