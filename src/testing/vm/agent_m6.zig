//! The agent test of M6 (docs/SPEC.md, "Production readiness"): a scripted agent drives the spec's
//! five steps, and the state commands around them, using only `--output json`, `zbx schema
//! <command>` and `zbx explain --output json`. Every decision is made on a member of a JSON
//! document, and each document is checked against the schema `zbx schema` printed. What the
//! agent has to learn some other way, or cannot learn, is a finding (docs/demos/m6.md, "The
//! agent test"), printed as a `FINDING` line and not worked around. It runs in the agent's own
//! project directory (the `za` wrapper), with its own `zbx.lock`, on its own volumes.
//!
//!   1. The schemas of run, ps, stop and the four state documents, none with a `$ref`.
//!   2. Step 1 and 2 of the spec: postgres with `--state agentdb:...`, `--publish` and `-e`
//!      (the document says the network, the forward and the name, never the password), `psql`
//!      writes a row.
//!   3. A second writer is refused as ZBX-E0706 (exit 125, the volume in its context); `explain`
//!      agrees; `state ls` names the holder from `used_by`.
//!   4. Step 3: the pid from `ps` is killed with SIGKILL; `ps --all` says stopped by a signal;
//!      the volume is free; the same command again, and the row is there.
//!   5. Step 4: `state ls` gives the volume, its size, its last container and its holder.
//!   6. Step 5: stop, and a run without `--state` keeps nothing.
//!   7. `state rm` of a volume in use is refused; `rm` and `restore` are read as JSON, the trash
//!      in `state ls`; a trash past its expiry is `expired` and `restore` refuses it as E0710;
//!      a name with no trash is E0709.
//!   8. `state export -o` is read as JSON; a fifo is left out with a W0703 whose path is the one
//!      inside the volume.
//!
//! Every assertion is a function of agent_json_m6.zig, agent_json.zig or checks_*.zig with a
//! unit test.

const std = @import("std");
const Io = std.Io;
const checks_spec = @import("checks_spec_m6.zig");
const checks_state = @import("checks_state_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const json = @import("agent_json.zig");
const json_m5 = @import("agent_json_m5.zig");
const json_m6 = @import("agent_json_m6.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const za = common.za;
const fail_step = common.fail_step;
const step = "AGENT6";
const volume = "agentdb";
const container = "agentpg";
const port: u16 = 5433;
/// The password given with `-e`: it reaches postgres and no document the agent reads.
const password = "agent-pg-pass";
const row = "agent-kept-row";
const ephemeral = "agent-ephemeral-row";
const image = "postgres:16";
const alpine = "alpine:3.20";
const long_s: u32 = 300;
const short_s: u32 = 60;
const export_file = "/home/demo/agent-export.tar.gz";
const lk_file = "/home/demo/agent-lk.tar.gz";
const trash_dir = "/home/demo/.local/share/zbx/state/.trash/";
const expired_seconds = "1000000000";

const run_flags = " --output json run -d --name ";
const publish_flags = " --publish 5433:5432 -e POSTGRES_PASSWORD=" ++ password ++ " " ++ image;
const start_pg = za ++ run_flags ++ container ++ " --state " ++ volume ++
    ":/var/lib/postgresql/data" ++ publish_flags;
const start_tmp = za ++ run_flags ++ "agentpgtmp" ++ publish_flags;
const psql = H.as_demo ++ "PGPASSWORD=" ++ password ++ " psql -h 127.0.0.1 -p 5433 -U postgres " ++
    "-v ON_ERROR_STOP=1 ";
const ready = H.as_demo ++ "PGPASSWORD=" ++ password ++ " sh -c 'for i in $(seq 120); do " ++
    "pg_isready -q -h 127.0.0.1 -p 5433 && psql -h 127.0.0.1 -p 5433 -U postgres " ++
    "-tAc \"select 1\" >/dev/null 2>&1 && break; sleep 1; done; " ++
    "pg_isready -h 127.0.0.1 -p 5433'";

/// The schemas the agent read first, kept for the steps that check a document against them.
var run_schema: []const u8 = "";
var ps_schema: []const u8 = "";
var ls_schema: []const u8 = "";
var rm_schema: []const u8 = "";
var restore_schema: []const u8 = "";
var export_schema: []const u8 = "";

/// How many findings the run has printed: each is something the agent could not read from JSON.
var findings_count: u32 = 0;

fn finding(out: *Io.Writer, text: []const u8) !void {
    findings_count += 1;
    try out.print("{s}: AGENT6: FINDING: {s}\n", .{ H.demo_name, text });
}

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT6: M6's steps, by JSON only\n", .{H.demo_name});
    findings_count = 0;
    try step_schemas(session, out);
    try step_pulls(session, out);
    try step_start_and_write(session, out);
    try step_second_writer(session, out);
    try step_kill_and_rerun(session, out);
    try step_listing(session, out);
    try step_without_state(session, out);
    try step_trash(session, out);
    try step_expired(session, out);
    try step_export(session, out);
    try out.print("{s}: AGENT6: {d} findings\n", .{ H.demo_name, findings_count });
    try timer.lap(out, "agent6");
}

fn json_run(session: *Session, out: *Io.Writer, command: []const u8, want: u8) !H.SplitResult {
    return state.expect_long_split(session, out, command, want, short_s);
}

fn fetch_schema(session: *Session, out: *Io.Writer, name: []const u8, id: []const u8) ![]const u8 {
    const arena = session.scratch_allocator();
    const command = try common.format(session, "{s} schema {s}", .{ za, name });
    const result = try json_run(session, out, command, 0);
    json.schema_names(arena, result.streams.stdout, id) catch |err| {
        return fail_step(out, step, "expected a schema that names its document", err);
    };
    json_m6.check_flat(result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected a schema without $ref", err);
    };
    return arena.dupe(u8, result.streams.stdout);
}

fn step_schemas(session: *Session, out: *Io.Writer) !void {
    run_schema = try fetch_schema(session, out, "run", "zbx.run/1");
    ps_schema = try fetch_schema(session, out, "ps", "zbx.ps/1");
    _ = try fetch_schema(session, out, "stop", "zbx.stop/1");
    ls_schema = try fetch_schema(session, out, "state-ls", "zbx.state.ls/1");
    rm_schema = try fetch_schema(session, out, "state-rm", "zbx.state.rm/1");
    restore_schema = try fetch_schema(session, out, "state-restore", "zbx.state.restore/1");
    export_schema = try fetch_schema(session, out, "state-export", "zbx.state.export/1");
}

/// The document `text` follows `schema`, which the agent reads as it is: no `$ref` to resolve.
fn expect_follows(
    arena: std.mem.Allocator,
    out: *Io.Writer,
    schema: []const u8,
    text: []const u8,
    what: []const u8,
) !void {
    const reason = json.violation(arena, schema, text) catch |err| {
        return fail_step(out, step, what, err);
    };
    if (reason) |why| {
        try out.print("{s}: AGENT6: {s} breaks its schema: {s}\n", .{ H.demo_name, what, why });
        return fail_step(out, step, what, error.SchemaViolated);
    }
}

fn step_pulls(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const pull = try fetch_schema(session, out, "pull", "zbx.pull/1");
    for ([_][]const u8{ image, alpine }) |reference| {
        const pattern = "{s} --output json pull {s}";
        const command = try common.format(session, pattern, .{ za, reference });
        const result = try state.expect_long_split(session, out, command, 0, long_s);
        try expect_follows(arena, out, pull, result.streams.stdout, "the pull document");
    }
}

/// Waits for postgres on the published port: no document says when it is ready (a finding).
fn wait_ready(session: *Session, out: *Io.Writer) !void {
    _ = try state.expect_long(session, out, ready, 0, 180);
}

/// `za run -d` of postgres with the volume: the document says the network, the forward and the
/// name of the variable, and not the password.
fn start_postgres(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const started = try state.expect_long_split(session, out, start_pg, 0, long_s);
    const detached = json_m5.check_detached(arena, started.streams, started.status) catch |err| {
        return fail_step(out, step, "expected the detached document with the name", err);
    };
    if (!std.mem.eql(u8, detached.name, container)) {
        return fail_step(out, step, "expected the name asked for", error.JsonWrong);
    }
    const forwards = [_]json_m5.Published{.{ .host = port, .container = 5432 }};
    json_m5.check_reach(detached.reach, "user", &forwards, &.{"POSTGRES_PASSWORD"}) catch |err| {
        return fail_step(out, step, "expected network user, the forward and the -e name", err);
    };
    try expect_follows(arena, out, run_schema, started.streams.stdout, "the run -d document");
    const shown = [_][]const u8{ started.streams.stdout, started.streams.stderr };
    json_m6.check_absent(&shown, password) catch |err| {
        return fail_step(out, step, "the password is in a document", err);
    };
    try wait_ready(session, out);
}

fn step_start_and_write(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 1: run postgres with --state, write a row\n", .{H.demo_name});
    try start_postgres(session, out);
    try finding(out, "no document says when a container is ready: the agent polls the " ++
        "published port with pg_isready and psql");
    const write = psql ++ "-c \"create table t (v text)\" -c \"insert into t values ('" ++
        row ++ "')\"";
    const wrote = try state.expect_long_split(session, out, write, 0, short_s);
    checks_spec.check_write(wrote.streams.stdout, wrote.status) catch |err| {
        return fail_step(out, step, "expected CREATE TABLE and INSERT 0 1", err);
    };
}

/// `state ls --output json`, checked against the schema, and the volume read from it.
fn read_listing(session: *Session, out: *Io.Writer, name: []const u8) !json_m6.Volume {
    const arena = session.scratch_allocator();
    const listed = try json_run(session, out, za ++ " --output json state ls", 0);
    try expect_follows(arena, out, ls_schema, listed.streams.stdout, "the state ls document");
    return json_m6.read_volume(arena, listed.streams, listed.status, name) catch |err| {
        return fail_step(out, step, "expected the volume in state ls", err);
    };
}

/// A refusal the agent reads by its code: exit `exit`, the volume `named` in its context.
fn expect_refusal(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    exit: u8,
    code: []const u8,
    named: []const u8,
) !json.Diagnostic {
    const arena = session.scratch_allocator();
    const refused = try common.run_shown(session, out, command);
    const found = json_m6.check_refusal(arena, refused.streams, refused.status, exit, code, named);
    const diagnostic = found catch |err| {
        return fail_step(out, step, "expected the refusal with its code and volume", err);
    };
    const line = std.mem.trim(u8, refused.streams.stderr, " \r\n\t");
    try expect_follows(arena, out, run_schema, line, "the refusal");
    return diagnostic;
}

fn explain(session: *Session, out: *Io.Writer, found: json.Diagnostic) !void {
    const arena = session.scratch_allocator();
    const pattern = "{s} --output json explain {s}";
    const command = try common.format(session, pattern, .{ za, found.code[4..] });
    const explained = try json_run(session, out, command, 0);
    json.check_explain(arena, explained.streams, explained.status, found) catch |err| {
        return fail_step(out, step, "expected explain to carry the diagnostic's members", err);
    };
}

fn step_second_writer(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 2: a second writer is refused\n", .{H.demo_name});
    const second = za ++ " --output json run --name agentpg2 --state " ++ volume ++ ":/d " ++
        alpine ++ " -- true";
    const found = try expect_refusal(session, out, second, 125, "ZBX-E0706", volume);
    try explain(session, out, found);
    const listed = try read_listing(session, out, volume);
    if (!listed.in_use or listed.holder == null) {
        return fail_step(out, step, "expected the volume in use, with a holder", error.StateWrong);
    }
    if (!std.mem.eql(u8, listed.holder.?, container)) {
        return fail_step(out, step, "expected state ls to name the holder", error.StateWrong);
    }
    if (json_m6.holder_in_context(found) == null) {
        try finding(out, "ZBX-E0706's context names the volume and not the holder: the holder " ++
            "is in the cause text and the fix's command, so the agent reads it from state ls");
    }
}

/// The record of `agentpg`, after waiting up to ten seconds for the supervisor to write the end.
const record_of_pg = "for i in $(seq 50); do " ++ za ++ " --output json ps --all | " ++
    "tr '{' '\\n' | grep '\"name\":\"" ++ container ++ "\"' | grep -q '\"state\":\"stopped\"' " ++
    "&& break; sleep 0.2; done; " ++ za ++ " --output json ps --all";

fn step_kill_and_rerun(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 3: SIGKILL of the pid ps names, the same command, the row\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const listed = try json_run(session, out, za ++ " --output json ps", 0);
    try expect_follows(arena, out, ps_schema, listed.streams.stdout, "the ps document");
    const pid = json_m6.ps_pid(arena, listed.streams.stdout, container) catch |err| {
        return fail_step(out, step, "expected ps to give the pid of the container", err);
    };
    const keys = [_][]const u8{ "volumes", "mounts", "state_volumes", "binds" };
    if (!(try json_m6.entry_has_any(arena, listed.streams.stdout, container, &keys))) {
        try finding(out, "ps and run -d do not say which volumes a container mounts: only " ++
            "state ls says who holds a volume");
    }
    const kill = try common.format(session, "kill -KILL {d} && echo killed", .{pid});
    _ = try state.expect_long(session, out, kill, 0, short_s);
    const record = try state.expect_long_split(session, out, record_of_pg, 0, short_s);
    const killed = record.streams.stdout;
    checks_spec.check_killed_record(arena, killed, record.status, container) catch |err| {
        return fail_step(out, step, "expected the container stopped by a signal", err);
    };
    try expect_follows(arena, out, ps_schema, record.streams.stdout, "the ps --all document");
    try state.expect_volume_free(session, out, volume, "after the agent killed postgres");
    const after = try read_listing(session, out, volume);
    if (after.in_use or after.holder != null) {
        return fail_step(out, step, "expected the volume free", error.StateWrong);
    }
    try start_postgres(session, out);
    const read = psql ++ "-tAc \"select v from t\"";
    const result = try state.expect_long_split(session, out, read, 0, short_s);
    checks_state.check_row(result.streams.stdout, result.status, row) catch |err| {
        return fail_step(out, step, "expected the row written before the kill", err);
    };
}

fn step_listing(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 4: state ls: the volume, its size, its last container\n", .{
        H.demo_name,
    });
    const found = try read_listing(session, out, volume);
    const size = found.disk_bytes orelse return fail_step(out, step, "no size", error.StateWrong);
    const last = found.last_container orelse "";
    if (size < 1 << 20 or !std.mem.eql(u8, last, container) or !found.in_use) {
        return fail_step(out, step, "expected 1 MiB, the last container", error.StateWrong);
    }
    const files = found.files orelse 0;
    if (files < 1 or !std.mem.eql(u8, found.holder.?, container)) {
        return fail_step(out, step, "expected files, and pg as the holder", error.StateWrong);
    }
}

fn stop(session: *Session, out: *Io.Writer, name: []const u8) !void {
    const arena = session.scratch_allocator();
    const command = try common.format(session, "{s} --output json stop {s}", .{ za, name });
    const stopped = try json_run(session, out, command, 0);
    json_m5.check_stopped(arena, stopped.streams, stopped.status, name) catch |err| {
        return fail_step(out, step, "expected zbx.stop/1 for the container", err);
    };
}

fn step_without_state(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 5: without --state the data is gone\n", .{H.demo_name});
    const arena = session.scratch_allocator();
    try stop(session, out, container);
    try net_user.expect_free(session, out, port, "after the agent stopped postgres");
    for ([_]bool{ true, false }) |first| {
        const started = try state.expect_long_split(session, out, start_tmp, 0, long_s);
        const checked = json_m5.check_detached(arena, started.streams, started.status);
        const detached = checked catch |err| {
            return fail_step(out, step, "expected the detached document", err);
        };
        try wait_ready(session, out);
        if (first) try write_ephemeral(session, out);
        const read = psql ++ "-tAc \"select v from t\"";
        const result = try common.run_shown(session, out, read);
        if (first) {
            const there = result.streams.stdout;
            checks_spec.check_data_there(there, result.status, ephemeral) catch |err| {
                return fail_step(out, step, "expected the row in the first run", err);
            };
        } else {
            checks_spec.check_data_gone(result.streams, result.status, ephemeral) catch |err| {
                return fail_step(out, step, "expected the table gone", err);
            };
        }
        try stop(session, out, detached.name);
        try net_user.expect_free(session, out, port, "after the run without --state");
    }
    const after = try read_listing(session, out, volume);
    const last = after.last_container orelse "";
    if (!std.mem.eql(u8, last, container) or after.in_use) {
        return fail_step(out, step, "expected the volume untouched", error.StateWrong);
    }
}

fn write_ephemeral(session: *Session, out: *Io.Writer) !void {
    const write = psql ++ "-c \"create table t (v text)\" -c \"insert into t values ('" ++
        ephemeral ++ "')\"";
    _ = try state.expect_long_split(session, out, write, 0, short_s);
}

/// Renames the trash entry `entry` to one removed long ago, on the host: the test of an expired
/// trash needs a removal from the past, and a test cannot wait a week.
fn age_trash(session: *Session, out: *Io.Writer, entry: []const u8) !void {
    const command = try common.format(
        session,
        H.as_demo ++ "mv {s}{s} {s}agentold@{s}",
        .{ trash_dir, entry, trash_dir, expired_seconds },
    );
    _ = try state.expect_long(session, out, command, 0, short_s);
}

fn step_trash(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 6: state rm and restore, by JSON\n", .{H.demo_name});
    const arena = session.scratch_allocator();
    const hold = za ++ " --output json run -d --name agenthold --state " ++ volume ++ ":/d " ++
        alpine ++ " -- sleep 600";
    _ = try json_run(session, out, hold, 0);
    const rm_busy = za ++ " --output json state rm " ++ volume;
    const found = try expect_refusal(session, out, rm_busy, 1, "ZBX-E0706", volume);
    try explain(session, out, found);
    try stop(session, out, "agenthold");
    try state.expect_volume_free(session, out, volume, "after the agent stopped agenthold");
    const rm = try json_run(session, out, za ++ " --output json state rm " ++ volume, 0);
    const removed = json_m6.check_rm(arena, rm.streams, rm.status, volume) catch |err| {
        return fail_step(out, step, "expected zbx.state.rm/1 for the volume", err);
    };
    try expect_follows(arena, out, rm_schema, rm.streams.stdout, "the state rm document");
    const entry = try arena.dupe(u8, removed.entry);
    const listed = try json_run(session, out, za ++ " --output json state ls", 0);
    json_m6.check_unlisted(arena, listed.streams, listed.status, volume) catch |err| {
        return fail_step(out, step, "expected the volume gone from state ls", err);
    };
    const trash = json_m6.read_trash(arena, listed.streams, listed.status, volume) catch |err| {
        return fail_step(out, step, "expected the trash entry in state ls", err);
    };
    if (!std.mem.eql(u8, trash.entry, entry) or trash.expired or trash.expires != removed.expires) {
        return fail_step(out, step, "expected the entry rm named, not expired", error.StateWrong);
    }
    const restore = try json_run(session, out, za ++ " --output json state restore " ++ volume, 0);
    json_m6.check_restore(arena, restore.streams, restore.status, volume, entry) catch |err| {
        return fail_step(out, step, "expected zbx.state.restore/1 for the entry", err);
    };
    try expect_follows(arena, out, restore_schema, restore.streams.stdout, "the restore document");
    const back = try read_listing(session, out, volume);
    const last = back.last_container orelse "";
    if (!std.mem.eql(u8, last, "agenthold") or back.in_use) {
        return fail_step(out, step, "expected the volume back, whole", error.StateWrong);
    }
}

fn step_expired(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 6b: a restore after the trash expired, and with no trash\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const make = za ++ " --output json run --name agentold1 --state agentold:/d " ++ alpine ++
        " -- true";
    _ = try json_run(session, out, make, 0);
    const rm = try json_run(session, out, za ++ " --output json state rm agentold", 0);
    const removed = json_m6.check_rm(arena, rm.streams, rm.status, "agentold") catch |err| {
        return fail_step(out, step, "expected zbx.state.rm/1 for agentold", err);
    };
    try age_trash(session, out, try arena.dupe(u8, removed.entry));
    const listed = try json_run(session, out, za ++ " --output json state ls", 0);
    const trash = json_m6.read_trash(arena, listed.streams, listed.status, "agentold") catch |err| {
        return fail_step(out, step, "expected the aged entry in state ls", err);
    };
    if (!trash.expired) return fail_step(out, step, "expected expired: true", error.StateWrong);
    const late = za ++ " --output json state restore agentold";
    const found = try expect_refusal(session, out, late, 1, "ZBX-E0710", "agentold");
    const named = json_m6.trash_in_context(found) orelse "";
    if (!std.mem.eql(u8, named, trash.entry)) {
        return fail_step(out, step, "expected the context to name the entry", error.RefusalWrong);
    }
    try explain(session, out, found);
    const none = za ++ " --output json state restore agentnone";
    const missing = try expect_refusal(session, out, none, 1, "ZBX-E0709", "agentnone");
    try explain(session, out, missing);
}

fn step_export(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6 7: state export, read as JSON\n", .{H.demo_name});
    const arena = session.scratch_allocator();
    const export_pg = za ++ " --output json state export " ++ volume ++ " -o " ++ export_file;
    const done = try state.expect_long_split(session, out, export_pg, 0, long_s);
    const checked = json_m6.check_export(arena, done.streams, done.status, volume, export_file, 0);
    const sent = checked catch |err| {
        return fail_step(out, step, "expected zbx.state.export/1 with the file", err);
    };
    try expect_follows(arena, out, export_schema, done.streams.stdout, "the export document");
    if (sent.files < 100 or done.streams.stderr.len != 0) {
        return fail_step(out, step, "expected postgres's files and no note", error.StateWrong);
    }
    const gzip = "gzip -t " ++ export_file ++ " && echo gzip-ok";
    _ = try common.expect_exit(session, out, step, gzip, 0);
    const make = za ++ " --output json run --name agentlk1 --state agentlk:/data " ++ alpine ++
        " -- sh -c 'echo x > /data/f; mkfifo /data/p'";
    _ = try json_run(session, out, make, 0);
    const lk = za ++ " --output json state export agentlk -o " ++ lk_file;
    const skipped = try json_run(session, out, lk, 0);
    const one = json_m6.check_export(arena, skipped.streams, skipped.status, "agentlk", lk_file, 1);
    _ = one catch |err| {
        return fail_step(out, step, "expected the export to count one file left out", err);
    };
    try expect_follows(arena, out, export_schema, skipped.streams.stdout, "the export document");
    json_m6.check_skip_warning(arena, skipped.streams.stderr, "/p") catch |err| {
        return fail_step(out, step, "expected one W0703 naming /p", err);
    };
}

test {
    _ = @import("agent_json_m6.zig");
}
