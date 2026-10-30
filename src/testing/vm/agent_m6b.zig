//! The agent test of M6b (docs/SPEC.md, "Production readiness"): a scripted agent drives the dev
//! loop using only `--output json`, `zbx schema <command>` and `zbx explain --output json`. Every
//! decision is made on a member of a JSON document, and each document is checked against the
//! schema `zbx schema` printed. What the agent has to learn some other way, or cannot learn, is
//! a finding (docs/demos/m6b.md, "The agent test"), printed as a `FINDING` line and not worked
//! around. It runs in the agent's own project directory (the `za` wrapper), with its own
//! `zbx.lock`.
//!
//!   1. The schemas of run, ps, logs and exec, none with a `$ref`.
//!   2. `run -d --mount agentsite:/srv --publish`: the document gives the resolved host path,
//!      the target and the user; the agent checks that the path is inside its project and the
//!      user is root; `ps` says the same.
//!   3. The page is served, edited on the host and served again. `logs --output json` gives the
//!      two requests, found by their stream and text.
//!   4. `exec --output json -e TOKEN=...`: the process status and `exec_exit` agree, the value
//!      of `-e` is in no document, and the file it wrote is the host user's.
//!   5. The refusals: a mount outside the project is E0212 (the project in `within`), a mount
//!      with a user that is not root is E0213 (a template, so the agent adapts it by the flag
//!      the fix names, `--user 0`, and the run works); `explain` agrees with each.
//!   6. After `stop`, `exec` is E0220 with the state `stopped`, the fix (a command, not a
//!      template) is run and `ps` agrees; `logs` of the stopped container still gives its
//!      records; a name with no record is E0402 (exit 1 for `logs`).
//!
//! Every assertion is a function of agent_json_m6b.zig, agent_json.zig or checks_*.zig with a
//! unit test.

const std = @import("std");
const Io = std.Io;
const checks_writable = @import("checks_writable_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const json = @import("agent_json.zig");
const json_m5 = @import("agent_json_m5.zig");
const json_m6 = @import("agent_json_m6.zig");
const json_m6b = @import("agent_json_m6b.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const spec = @import("spec_m6b.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const za = common.za;
const fail_step = common.fail_step;
const step = "AGENT6B";
const project = common.agent_project;
const site = project ++ "/agentsite";
const outside = "/home/demo/outside-agent";
const container = "agentweb";
const python = "python:3.12-slim";
const non_root = "memcached:alpine";
const alpine = "alpine:3.20";
const port = "18090";
const token = "agent-token-VALUE-9";
const long_s: u32 = 300;
const short_s: u32 = 60;
const no_input = " </dev/null";

const setup = H.as_demo ++ "sh -c 'mkdir -p " ++ site ++ " " ++ outside ++ " && echo " ++
    "agent-first-TAU > " ++ site ++ "/index.html'";
const edit = H.as_demo ++ "sh -c 'echo agent-second-TAU > " ++ site ++ "/index.html'";
const start_web = za ++ " --output json run -d --name " ++ container ++ " --publish " ++ port ++
    ":8000 --mount agentsite:/srv " ++ python ++ " -- python -m http.server -d /srv 8000";
const wait_path = "/home/demo/wait-agentweb.sh";
const fetch = "curl -fsS http://127.0.0.1:" ++ port ++ "/index.html; sleep 1";
const run_exec = za ++ " --output json exec " ++ container ++ " -e TOKEN=" ++ token ++
    " -- sh -c 'echo agent-inside > /srv/agent.txt; test -n \"$TOKEN\"; exit 3'" ++ no_input;
const owners = H.as_demo ++ checks_writable.owners_command(site ++ "/agent.txt", site);

/// The schemas the agent read first, kept for the steps that check a document against them.
var run_schema: []const u8 = "";
var ps_schema: []const u8 = "";
var logs_schema: []const u8 = "";
var exec_schema: []const u8 = "";

/// How many findings the run has printed: each is something the agent could not read from JSON.
var findings_count: u32 = 0;

fn finding(out: *Io.Writer, text: []const u8) !void {
    findings_count += 1;
    try out.print("{s}: AGENT6B: FINDING: {s}\n", .{ H.demo_name, text });
}

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT6B: M6b's dev loop, by JSON only\n", .{H.demo_name});
    findings_count = 0;
    try step_schemas(session, out);
    try step_pulls(session, out);
    try step_start(session, out);
    try step_loop(session, out);
    try step_exec(session, out);
    try step_refusals(session, out);
    try step_stopped(session, out);
    try out.print("{s}: AGENT6B: {d} findings\n", .{ H.demo_name, findings_count });
    try timer.lap(out, "agent6b");
}

fn json_run(session: *Session, out: *Io.Writer, command: []const u8, want: u8) !H.SplitResult {
    return state.expect_long_split(session, out, command, want, short_s);
}

fn fetch_schema(session: *Session, out: *Io.Writer, name: []const u8) ![]const u8 {
    const arena = session.scratch_allocator();
    const command = try common.format(session, "{s} schema {s}", .{ za, name });
    const result = try json_run(session, out, command, 0);
    json_m6.check_flat(result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected a schema without $ref", err);
    };
    return arena.dupe(u8, result.streams.stdout);
}

fn step_schemas(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    run_schema = try fetch_schema(session, out, "run");
    ps_schema = try fetch_schema(session, out, "ps");
    logs_schema = try fetch_schema(session, out, "logs");
    exec_schema = try fetch_schema(session, out, "exec");
    json.schema_names(arena, logs_schema, "zbx.logs/1") catch |err| {
        return fail_step(out, step, "expected the logs schema to name its document", err);
    };
    // The exec schema has no `schema` member: its document is a line, `exec_exit`.
    json_m6b.check_describes(arena, exec_schema, "exec_exit") catch |err| {
        return fail_step(out, step, "expected the exec schema to describe exec_exit", err);
    };
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
        try out.print("{s}: AGENT6B: {s} breaks its schema: {s}\n", .{ H.demo_name, what, why });
        return fail_step(out, step, what, error.SchemaViolated);
    }
}

fn step_pulls(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const pull = try fetch_schema(session, out, "pull");
    for ([_][]const u8{ python, non_root, alpine }) |reference| {
        const pattern = "{s} --output json pull {s}";
        const command = try common.format(session, pattern, .{ za, reference });
        const result = try state.expect_long_split(session, out, command, 0, long_s);
        try expect_follows(arena, out, pull, result.streams.stdout, "the pull document");
    }
    _ = try state.expect_long(session, out, setup, 0, short_s);
}

fn step_start(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6B 1: run -d with --mount: the document gives the mount\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const started = try state.expect_long_split(session, out, start_web, 0, long_s);
    const mount = json_m6b.detached_mount(arena, started.streams, started.status, container);
    const found = mount catch |err| {
        return fail_step(out, step, "expected the mount and the user in the run -d document", err);
    };
    json_m6b.check_mount(found, project, "/srv") catch |err| {
        return fail_step(out, step, "expected the mount inside the project, run as root", err);
    };
    json_m6b.check_resolved(found, site) catch |err| {
        return fail_step(out, step, "expected the resolved path of agentsite", err);
    };
    try expect_follows(arena, out, run_schema, started.streams.stdout, "the run -d document");
    try spec.run_waiter(session, out, wait_path, spec.wait_script("/home/demo/za", container));
    try finding(out, "no document says when a container is ready: the agent polls the " ++
        "server by connecting to it from inside the container");
    const listed = try json_run(session, out, za ++ " --output json ps", 0);
    try expect_follows(arena, out, ps_schema, listed.streams.stdout, "the ps document");
    const in_ps = json_m6b.ps_mount(arena, listed.streams.stdout, container) catch |err| {
        return fail_step(out, step, "expected ps to list the mount and the user", err);
    };
    json_m6b.check_mount(in_ps, project, "/srv") catch |err| {
        return fail_step(out, step, "expected ps to agree with run -d", err);
    };
}

fn step_loop(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6B 2: edit on the host; logs as JSON give the two requests\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const first = try state.expect_long_split(session, out, fetch, 0, short_s);
    const page = checks_writable.check_page;
    page(first.streams.stdout, "agent-first-TAU", "agent-second-TAU") catch |err| {
        return fail_step(out, step, "expected the page from the mounted directory", err);
    };
    _ = try state.expect_long(session, out, edit, 0, short_s);
    const second = try state.expect_long_split(session, out, fetch, 0, short_s);
    page(second.streams.stdout, "agent-second-TAU", "agent-first-TAU") catch |err| {
        return fail_step(out, step, "expected the edit to be served", err);
    };
    const command = try common.format(session, "{s} --output json logs {s}", .{ za, container });
    const logged = try json_run(session, out, command, 0);
    json_m6b.check_log_records(
        arena,
        logs_schema,
        logged.streams,
        logged.status,
        "stderr",
        "GET /index.html",
        2,
    ) catch |err| {
        return fail_step(out, step, "expected two requests in zbx.logs/1 lines", err);
    };
}

fn step_exec(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6B 3: exec as JSON: exec_exit, no -e value, the host user owns\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const ran = try state.expect_long_split(session, out, run_exec, 3, short_s);
    json_m6b.check_exec_exit(arena, ran.streams, ran.status, container, 3) catch |err| {
        return fail_step(out, step, "expected exec_exit to agree with the exit status", err);
    };
    const lines = std.mem.trim(u8, ran.streams.stderr, " \r\n");
    try expect_follows(arena, out, exec_schema, lines, "the exec_exit line");
    const shown = [_][]const u8{ ran.streams.stdout, ran.streams.stderr };
    json_m6.check_absent(&shown, token) catch |err| {
        return fail_step(out, step, "the value of -e is in a document", err);
    };
    // The owner is read from stdout; `find` runs from the site, so it has nothing to say on stderr.
    const who = try state.expect_long_split(session, out, owners, 0, short_s);
    checks_writable.check_owner(who.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the host user to own the file", err);
    };
}

/// A refusal read by its members, checked against the schema of the command that refused (null
/// for a command whose schema describes no refusal: a finding), and `explain` of its code agrees
/// with it.
fn refusal(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    schema: ?[]const u8,
    want: json_m6b.Want,
) !json.Diagnostic {
    const arena = session.scratch_allocator();
    const refused = try common.run_shown(session, out, command);
    const found = json_m6b.check_refusal(arena, refused.streams, refused.status, want) catch |err| {
        return fail_step(out, step, "expected the refusal with its code, context and fix", err);
    };
    const line = std.mem.trim(u8, refused.streams.stderr, " \r\n\t");
    if (schema) |text| try expect_follows(arena, out, text, line, "the refusal");
    const pattern = "{s} --output json explain {s}";
    const explain = try common.format(session, pattern, .{ za, found.code[4..] });
    const explained = try json_run(session, out, explain, 0);
    json.check_explain(arena, explained.streams, explained.status, found) catch |err| {
        return fail_step(out, step, "expected explain to carry the diagnostic's members", err);
    };
    return found;
}

fn step_refusals(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: AGENT6B 4: a mount outside the project; a user that is not root\n", .{
        H.demo_name,
    });
    const arena = session.scratch_allocator();
    const outside_run = za ++ " --output json run --mount ../outside-agent:/x " ++ alpine ++
        " -- true";
    const found = try refusal(session, out, outside_run, run_schema, .{
        .code = "ZBX-E0212",
        .exit = 125,
        .key = "within",
        .value = project,
        .fix_template = true,
        .fix_has = "--bind",
    });
    json_m6b.check_context(found, "real", outside) catch |err| {
        return fail_step(out, step, "expected the real path in the context", err);
    };
    const user_run = za ++ " --output json run --mount agentsite:/srv " ++ non_root ++ " -- id -u";
    const root = try refusal(session, out, user_run, run_schema, .{
        .code = "ZBX-E0213",
        .exit = 125,
        .key = "uid",
        .not_value = "0",
        .fix_template = true,
        .fix_has = "--user 0",
    });
    try finding(out, "the fix of ZBX-E0213 is a template (<image>, ./site): the agent adapts " ++
        "it by the flag it names, --user 0, and keeps its own directory and image");
    // The agent never runs a template as written: it takes the flag (and its value) from it and
    // adds that to its own command.
    const fix = json_m6b.fix_command(root) orelse "";
    const flag = json_m6b.flag_from_fix(fix, "--user") orelse {
        const what = "expected the fix to name --user and its value";
        return fail_step(out, step, what, error.FixWrong);
    };
    const pattern = "{s} --output json run {s} --mount agentsite:/srv {s} -- id -u";
    const adapted = try common.format(session, pattern, .{ za, flag, non_root });
    const ran = try state.expect_long_split(session, out, adapted, 0, long_s);
    json.check_exited(arena, ran.streams, ran.status, 0) catch |err| {
        return fail_step(out, step, "expected the adapted run to end with 0", err);
    };
    checks_writable.check_json(ran.streams.stderr, site, "/srv") catch |err| {
        return fail_step(out, step, "expected the mount and user 0 in container_exit", err);
    };
}

fn step_stopped(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: AGENT6B 5: stopped: exec is E0220, logs remain, a missing name E0402\n";
    try out.print(title, .{H.demo_name});
    const arena = session.scratch_allocator();
    const stop = try common.format(session, "{s} --output json stop {s}", .{ za, container });
    const stopped = try json_run(session, out, stop, 0);
    json_m5.check_stopped(arena, stopped.streams, stopped.status, container) catch |err| {
        return fail_step(out, step, "expected zbx.stop/1 for the container", err);
    };
    try net_user.expect_free(session, out, 18090, "after the agent stopped the server");
    const exec = za ++ " --output json exec " ++ container ++ " -- true" ++ no_input;
    const found = try refusal(session, out, exec, exec_schema, .{
        .code = "ZBX-E0220",
        .exit = 125,
        .key = "state",
        .value = "stopped",
        .fix_template = false,
        .fix_has = "ps --all",
    });
    // The fix is a command, not a template: the agent runs it and reads the state from ps.
    var buffer: [256]u8 = undefined;
    const fix = json_m6b.fix_command(found) orelse "";
    const typed = json.fix_command(&buffer, za, fix) catch |err| {
        return fail_step(out, step, "expected a fix that is a zbx command", err);
    };
    const listed = try json_run(session, out, typed, 0);
    try expect_follows(arena, out, ps_schema, listed.streams.stdout, "the ps --all document");
    json_m6b.check_ps_state(arena, listed.streams.stdout, container, "stopped") catch |err| {
        return fail_step(out, step, "expected ps --all to say the container is stopped", err);
    };
    const command = try common.format(session, "{s} --output json logs {s}", .{ za, container });
    const logged = try json_run(session, out, command, 0);
    json_m6b.check_log_records(
        arena,
        logs_schema,
        logged.streams,
        logged.status,
        "stderr",
        "GET /index.html",
        2,
    ) catch |err| {
        return fail_step(out, step, "expected the stopped container's log, the same two", err);
    };
    const missing = za ++ " --output json logs no-such-container";
    _ = try refusal(session, out, missing, null, .{
        .code = "ZBX-E0402",
        .exit = 1,
        .key = "name",
        .value = "no-such-container",
        .fix_template = false,
        .fix_has = "ps --all",
    });
    try finding(out, "the logs schema describes only its stdout records: a refusal on stderr " ++
        "is in no schema logs serves, so the agent checks it by its members alone");
}

test {
    _ = @import("agent_json_m6b.zig");
}
