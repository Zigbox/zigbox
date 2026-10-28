//! The spec's five steps of M6, as the spec types them, run as the user `demo` in the guest
//! (docs/SPEC.md, M6; docs/briefs/M6-state.md), with `postgres:16`:
//!
//!   1. `zbx run --state pgdata:/var/lib/postgresql/data --publish 5432:5432
//!      -e POSTGRES_PASSWORD=demo postgres:16`. It is run detached (`-d`, as demo-m5 ran nginx),
//!      so that the next steps can use the shell; nothing else differs from the spec's line
//!      except `--name pg`, which names the container the later steps kill and `state ls` shows.
//!   2. `psql` from the guest creates a table and inserts a row. (The spec says "from the host";
//!      the guest is the host of the containers.)
//!   3. SIGKILL of the container's PID 1, which takes every process of its PID namespace with
//!      it: none is left, the record says stopped by a signal. The same command again, and the
//!      row is still there.
//!   4. `zbx state ls` (text, and JSON for the numbers) shows `pgdata`, its size and the last
//!      container that used it.
//!   5. Without `--state`, the same postgres writes a table and a row, is stopped and started
//!      again: the table is gone. `pgdata` is unchanged (its last container is still `pg`).
//!
//! The part ends by removing `pgdata` (`state rm`), so that the acceptance part (state_m6.zig),
//! which runs next and needs a new volume, finds none.
//!
//! Every assertion is a function of checks_spec_m6.zig or checks_state_m6.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_spec_m6.zig");
const checks_state = @import("checks_state_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "SPEC";

const image = "postgres:16";
const volume_flag = " --state pgdata:/var/lib/postgresql/data";
const publish_flag = " --publish 5432:5432 -e POSTGRES_PASSWORD=demo ";
const start_spec = zn ++ " run -d --name pg" ++ volume_flag ++ publish_flag ++ image;
const start_tmp = zn ++ " run -d --name pgtmp" ++ publish_flag ++ image;
const psql = state.psql_on(5432);
const ready = state.pg_ready_on(5432);
const row = "kept-across-sigkill";
const ephemeral = "ephemeral-row";
const long_s: u32 = 300;

pub fn step_spec(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: SPEC: the five steps of the spec (M6)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    const command = try common.format(session, "{s} pull {s}", .{ zn, image });
    _ = try state.expect_long(session, out, command, 0, 600);
    try step_one_two(session, out);
    try step_three(session, out);
    try step_four(session, out);
    try step_five(session, out);
    try remove_volume(session, out);
    try timer.lap(out, "spec");
}

fn step_one_two(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 1: zbx run --state pgdata:... --publish 5432:5432 postgres:16\n", .{
        H.demo_name,
    });
    _ = try state.expect_long(session, out, start_spec, 0, long_s);
    try state.wait_ready_on(session, out, ready);
    try out.print("\n{s}: SPEC 2: psql: create a table, insert a row\n", .{H.demo_name});
    const write = psql ++ "-c \"create table t (v text)\" -c \"insert into t values ('" ++
        row ++ "')\"";
    const wrote = try state.expect_long_split(session, out, write, 0, limits.command_timeout_kvm_s);
    checks.check_write(wrote.streams.stdout, wrote.status) catch |err| {
        return fail_step(out, "SPEC 2", "expected CREATE TABLE and INSERT 0 1", err);
    };
}

/// A command that prints how many processes named postgres the guest has, after waiting up to
/// ten seconds for the count to reach zero (the kernel reaps a PID namespace a moment late).
const count_postgres = "for i in $(seq 50); do [ \"$(pgrep -cx postgres)\" = 0 ] && break; " ++
    "sleep 0.2; done; pgrep -cx postgres; true";

/// The record of `pg`, after waiting up to ten seconds for the supervisor to write the end.
const record_of_pg = "for i in $(seq 50); do " ++ zn ++ " ps --all --output json | " ++
    "tr '{' '\\n' | grep '\"name\":\"pg\"' | grep -q '\"state\":\"stopped\"' && break; " ++
    "sleep 0.2; done; " ++ zn ++ " ps --all --output json";

fn step_three(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 3: SIGKILL of the container, the same command, the row\n", .{
        H.demo_name,
    });
    const kill = "kill -KILL $(" ++ comptime state.pid_of("pg") ++ ") && echo killed";
    _ = try state.expect_long(session, out, kill, 0, limits.command_timeout_kvm_s);
    const left = try session.run(count_postgres, limits.command_timeout_kvm_s);
    try H.show(out, count_postgres, left);
    checks.check_none_left(left.output) catch |err| {
        return fail_step(out, "SPEC 3", "expected no postgres process left", err);
    };
    const record = try state.expect_long_split(session, out, record_of_pg, 0, 60);
    const arena = session.scratch_allocator();
    checks.check_killed_record(arena, record.streams.stdout, record.status, "pg") catch |err| {
        return fail_step(out, "SPEC 3", "expected pg stopped by a signal", err);
    };
    try state.expect_volume_free(session, out, "pgdata", "after the container was killed");
    _ = try state.expect_long(session, out, start_spec, 0, long_s);
    try state.wait_ready_on(session, out, ready);
    const read = psql ++ "-tAc \"select v from t\"";
    const result = try state.expect_long_split(session, out, read, 0, limits.command_timeout_kvm_s);
    checks_state.check_row(result.streams.stdout, result.status, row) catch |err| {
        return fail_step(out, "SPEC 3", "expected the row written before the kill", err);
    };
}

fn step_four(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 4: zbx state ls: pgdata, its size, its last container\n", .{
        H.demo_name,
    });
    const text = try common.run_shown(session, out, zn ++ " state ls");
    checks.check_ls_text(text.streams.stdout, text.status, "pgdata", "pg", 1 << 20) catch |err| {
        return fail_step(out, "SPEC 4", "expected pgdata, at least 1 MiB, last container pg", err);
    };
    try state.listing(session, out, .{
        .name = "pgdata",
        .last_container = "pg",
        .in_use = true,
        .user = "pg",
        .disk_bytes_min = 1 << 20,
    }, "expected pgdata in JSON, in use by pg");
}

fn step_five(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 5: without --state the data is gone after exit\n", .{H.demo_name});
    _ = try state.expect_long(session, out, zn ++ " stop pg", 0, limits.command_timeout_kvm_s);
    try net_user.expect_free(session, out, 5432, "after pg was stopped");
    _ = try state.expect_long(session, out, start_tmp, 0, long_s);
    try state.wait_ready_on(session, out, ready);
    const write = psql ++ "-c \"create table t (v text)\" -c \"insert into t values ('" ++
        ephemeral ++ "')\"";
    _ = try state.expect_long(session, out, write, 0, limits.command_timeout_kvm_s);
    const read = psql ++ "-tAc \"select v from t\"";
    const there = try state.expect_long_split(session, out, read, 0, limits.command_timeout_kvm_s);
    checks.check_data_there(there.streams.stdout, there.status, ephemeral) catch |err| {
        return fail_step(out, "SPEC 5", "expected the row in the run without --state", err);
    };
    _ = try state.expect_long(session, out, zn ++ " stop pgtmp", 0, limits.command_timeout_kvm_s);
    try net_user.expect_free(session, out, 5432, "after pgtmp was stopped");
    _ = try state.expect_long(session, out, start_tmp, 0, long_s);
    try state.wait_ready_on(session, out, ready);
    const again = try common.run_shown(session, out, read);
    checks.check_data_gone(again.streams, again.status, ephemeral) catch |err| {
        return fail_step(out, "SPEC 5", "expected the table gone after the exit", err);
    };
    _ = try state.expect_long(session, out, zn ++ " stop pgtmp", 0, limits.command_timeout_kvm_s);
    try net_user.expect_free(session, out, 5432, "after pgtmp was stopped again");
    try state.listing(session, out, .{
        .name = "pgdata",
        .last_container = "pg",
        .in_use = false,
        .disk_bytes_min = 1 << 20,
    }, "expected pgdata untouched by the runs without --state");
}

fn remove_volume(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC: pgdata removed, for the acceptance part that follows\n", .{
        H.demo_name,
    });
    _ = try state.expect_long(session, out, zn ++ " state rm pgdata", 0, 60);
    const listed = try common.run_shown(session, out, zn ++ " --output json state ls");
    const arena = session.scratch_allocator();
    checks.check_volume_absent(arena, listed.streams.stdout, "pgdata") catch |err| {
        return fail_step(out, step_name, "expected pgdata gone from state ls", err);
    };
}

test {
    _ = @import("checks_spec_m6.zig");
}
