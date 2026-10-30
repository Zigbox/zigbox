//! The agent test of M5 (docs/SPEC.md, "Production readiness"), as M6 slice 1 left it: a scripted
//! agent drives M5's steps using only `--output json`, `zbx schema <command>` and `zbx explain
//! --output json`. It never reads the hint, the `ss` output or a diagnostic's text: every
//! decision is made on a member of a JSON document, and each document is checked against the
//! schema `zbx schema` printed, with no `$ref` to follow. M5's run of this test printed six
//! findings (docs/demos/m5.md); each is a check here now and fails the demo if it regresses.
//! It runs in the agent's own project directory (the `za` wrapper), with its own `zbx.lock`.
//!
//!   1. `schema run` and `schema doctor` have no `$ref`; `schema run` names the network members.
//!   2. `run alpine:3.20 -- wget -qO- https://example.com` fails; the exit line says the network
//!      was `none` and carries `"hint":"network_none"`. An explicit `--net none` carries none.
//!      The agent grants `--net user` and the page comes; the exit line says `user`.
//!   3. `run --publish 18091:80` ends with the forward in `published`.
//!   4. `run -d --publish 18092:80 -e AGENT_NOTE=... nginx:alpine`: the document and `ps` say the
//!      network, the forward and the name AGENT_NOTE, and never its value; the agent reaches the
//!      server on the port it asked for; `stop` ends it and the port is free.
//!   5. `-e NAME=VALUE` and `-e NAME` reach the container and no value reaches a JSON document or
//!      the run records; an unset `-e NAME` is refused as ZBX-E0011 with template fixes.
//!   6. With a `PATH` that has no pasta, `run --net user` is refused as ZBX-E0601: the agent reads
//!      the code, the blame and the fixes, which say that the first needs root and the second is
//!      a template; it applies the template's flag to its own command and gets the page.
//!      `explain --output json` agrees with the diagnostic. `doctor --output json` carries the net
//!      warning with its code (ZBX-W0102) and the fix that needs root.
//!   7. The firewall rules are what they were before the demo's first step.
//!
//! Every assertion is a function of agent_json_m5.zig, agent_json.zig or checks_*.zig with a
//! unit test.

const std = @import("std");
const Io = std.Io;
const accept = @import("accept_net_m5.zig");
const checks_m4 = @import("checks_m4.zig");
const checks_m5 = @import("checks_m5.zig");
const checks_spec = @import("checks_spec_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const json = @import("agent_json.zig");
const json_m5 = @import("agent_json_m5.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const spec = @import("spec_m5.zig");

const Session = session_mod.Session;
const H = harness;
const za = common.za;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const step = "AGENT";
const fetch = " alpine:3.20 -- wget -qO- https://example.com";
const server_port: u16 = 18092;
const server_name = "agent-web";
/// The agent's `za` with a `PATH` that lacks pasta (accept_net_m5.zig makes the directory).
const za_without = H.as_demo ++ "PATH=/tmp/nopasta /home/demo/za";

/// The schemas the agent read first, kept for the steps that check a document against them.
var run_schema: []const u8 = "";
var ps_schema: []const u8 = "";
var doctor_schema: []const u8 = "";
/// A value given with `-e`: it must reach the container and no document the agent reads.
const marker_value = "agent-secret-value-7";
const copied_value = "agent-copied-value-9";

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT: M5's steps, by JSON only\n", .{H.demo_name});
    try step_schemas(session, out);
    try step_pulls(session, out);
    try step_no_network(session, out);
    try step_published(session, out);
    try step_detached(session, out);
    try step_env(session, out);
    try step_pasta_missing(session, out);
    try spec.expect_rules_unchanged(session, out);
    try out.print("{s}: AGENT: no finding left open\n", .{H.demo_name});
    try timer.lap(out, "agent");
}

fn fetch_schema(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    id: ?[]const u8,
) ![]const u8 {
    const arena = session.scratch_allocator();
    const line = try common.format(session, "{s} schema {s}", .{ za, command });
    const result = try expect_exit(session, out, step, line, 0);
    if (id) |wanted| {
        json.schema_names(arena, result.streams.stdout, wanted) catch |err| {
            return fail_step(out, step, "expected a schema that names its document", err);
        };
    }
    return arena.dupe(u8, result.streams.stdout);
}

fn step_schemas(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    run_schema = try fetch_schema(session, out, "run", null);
    json_m5.schema_describes_network(arena, run_schema) catch |err| {
        return fail_step(out, step, "expected the run schema to name network and hint", err);
    };
    _ = try fetch_schema(session, out, "stop", "zbx.stop/1");
    ps_schema = try fetch_schema(session, out, "ps", "zbx.ps/1");
    doctor_schema = try fetch_schema(session, out, "doctor", "zbx.doctor/1");
    if (std.mem.indexOf(u8, doctor_schema, "\"$ref\"") != null) {
        return fail_step(out, step, "expected a doctor schema without $ref", error.JsonWrong);
    }
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
        try out.print("{s}: AGENT: {s} breaks its schema: {s}\n", .{ H.demo_name, what, why });
        return fail_step(out, step, what, error.SchemaViolated);
    }
}

fn step_pulls(session: *Session, out: *Io.Writer) !void {
    const pull = try fetch_schema(session, out, "pull", "zbx.pull/1");
    const references = [_][]const u8{ "alpine:3.20", "nginx:alpine" };
    for (references) |reference| {
        const pattern = "{s} --output json pull {s}";
        const command = try common.format(session, pattern, .{ za, reference });
        const result = try expect_exit(session, out, step, command, 0);
        const reason = json.violation(session.scratch_allocator(), pull, result.streams.stdout);
        if (try reason) |text| {
            try out.print("{s}: AGENT: the pull breaks its schema: {s}\n", .{ H.demo_name, text });
            return fail_step(out, step, reference, error.SchemaViolated);
        }
    }
}

/// Step 2: the refusal and the grant, from the exit line.
fn step_no_network(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const refused = try common.run_shown(session, out, za ++ " --output json run" ++ fetch);
    json_m5.check_failed_without_network(arena, refused.streams, refused.status) catch |err| {
        return fail_step(out, step, "expected the exit line to say none, with the hint", err);
    };
    const line = try json_m5.exit_line(refused.streams.stderr);
    try expect_follows(arena, out, run_schema, line, "the exit line of the refused run");
    // Asked for, the network is not the likely cause: the same failure carries no hint.
    const explicit = za ++ " --output json run --net none" ++ fetch;
    const asked = try common.run_shown(session, out, explicit);
    json_m5.check_failed_with_explicit_none(arena, asked.streams, asked.status) catch |err| {
        return fail_step(out, step, "expected no hint after an explicit --net none", err);
    };
    const grant = za ++ " --output json run --net user" ++ fetch;
    const granted = try common.run_shown(session, out, grant);
    json_m5.check_granted(arena, granted.streams, granted.status, "user", &.{}) catch |err| {
        return fail_step(out, step, "expected the exit line to say network user", err);
    };
    checks_spec.check_example_page(granted.streams, granted.status) catch |err| {
        return fail_step(out, step, "expected example.com's page", err);
    };
}

fn step_published(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const command = za ++ " --output json run --publish 18091:80 alpine:3.20 -- true";
    const result = try common.run_shown(session, out, command);
    const wanted = [_]json_m5.Published{.{ .host = 18091, .container = 80 }};
    json_m5.check_granted(arena, result.streams, result.status, "user", &wanted) catch |err| {
        return fail_step(out, step, "expected network user and the forward in JSON", err);
    };
    try net_user.expect_free(session, out, 18091, "after the run the agent made");
}

/// Step 4: a server in the background, reached on the port the agent asked for. The documents
/// say what it can reach, and the name of its variable, never the value.
fn step_detached(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const start = za ++ " --output json run -d --name " ++ server_name ++
        " --publish 18092:80 -e AGENT_NOTE=" ++ marker_value ++ " nginx:alpine";
    const started = try expect_exit(session, out, step, start, 0);
    const detached = json_m5.check_detached(arena, started.streams, started.status) catch |err| {
        return fail_step(out, step, "expected the detached document with the name", err);
    };
    const name = try arena.dupe(u8, detached.name);
    const wanted = [_]json_m5.Published{.{ .host = 18092, .container = 80 }};
    json_m5.check_reach(detached.reach, "user", &wanted, &.{"AGENT_NOTE"}) catch |err| {
        return fail_step(out, step, "expected run -d to say the network, port and -e name", err);
    };
    try expect_follows(arena, out, run_schema, started.streams.stdout, "the run -d document");
    const listed = try expect_exit(session, out, step, za ++ " --output json ps", 0);
    const entry = json_m5.ps_reach(arena, listed.streams.stdout, name) catch |err| {
        return fail_step(out, step, "expected ps to list the running container", err);
    };
    json_m5.check_reach(entry, "user", &wanted, &.{"AGENT_NOTE"}) catch |err| {
        return fail_step(out, step, "expected ps to say the network, port and -e name", err);
    };
    try expect_follows(arena, out, ps_schema, listed.streams.stdout, "the ps document");
    // The value is in neither document.
    const shown = [_][]const u8{
        started.streams.stdout, started.streams.stderr, listed.streams.stdout,
    };
    for (shown) |text| {
        if (std.mem.indexOf(u8, text, marker_value) != null) {
            return fail_step(out, step, "a -e value is in a JSON document", error.ReachWrong);
        }
    }
    try reach_server(session, out);
    const stop = try common.format(session, "{s} --output json stop {s}", .{ za, name });
    const stopped = try expect_exit(session, out, step, stop, 0);
    json_m5.check_stopped(arena, stopped.streams, stopped.status, name) catch |err| {
        return fail_step(out, step, "expected zbx.stop/1 for the container", err);
    };
    try net_user.expect_free(session, out, server_port, "after the agent stopped its server");
}

fn reach_server(session: *Session, out: *Io.Writer) !void {
    const curl = "for i in $(seq 30); do curl -fsS http://localhost:18092/ && break; " ++
        "sleep 1; done";
    const page = try session.run(curl, limits.command_timeout_kvm_s);
    try H.show(out, curl, page);
    checks_m5.check_nginx_page(page.output, page.status) catch |err| {
        return fail_step(out, step, "expected nginx's page on the port asked for", err);
    };
}

/// Step 5: `-e` by JSON. A value given with `-e NAME=VALUE`, and one copied with `-e NAME`,
/// reach the container (its own output shows them); the exit line, the records on disk and
/// `ps` hold the names and no value; an unset `-e NAME` is a refusal with the code the agent
/// reads, ZBX-E0011, whose fixes are templates.
fn step_env(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const copy = H.as_demo ++ "AGENT_COPY=" ++ copied_value ++ " /home/demo/za";
    const command = copy ++ " --output json run -e AGENT_NOTE=" ++ marker_value ++
        " -e AGENT_COPY alpine:3.20 -- sh -c 'echo $AGENT_NOTE $AGENT_COPY'";
    const ran = try common.run_shown(session, out, command);
    json_m5.check_env_reached(ran.streams, ran.status, marker_value, copied_value) catch |err| {
        return fail_step(out, step, "expected -e values in the container and not in the JSON", err);
    };
    const line = try json_m5.exit_line(ran.streams.stderr);
    try expect_follows(arena, out, run_schema, line, "the exit line of the run with -e");
    // The logs directory keeps what the container wrote (M6b): this command prints the values,
    // so its log has them. What zbx itself stores (records, bundles) must not.
    const grep = try common.format(
        session,
        "grep -rlE --exclude-dir=logs '{s}|{s}' {s}",
        .{ marker_value, copied_value, common.state_dir },
    );
    const found = try session.run(grep, limits.command_timeout_kvm_s);
    try H.show(out, grep, found);
    if (found.status != 1) { // grep: 1 is "no file matches".
        return fail_step(out, step, "a -e value is in the state directory", error.ReachWrong);
    }
    const unset = za ++ " --output json run -e AGENT_NOT_SET alpine:3.20 -- true";
    const refused = try common.run_shown(session, out, unset);
    const diagnostic = json_m5.check_env_unset(arena, refused.streams, refused.status) catch |err| {
        return fail_step(out, step, "expected ZBX-E0011 with template fixes", err);
    };
    const pattern = "{s} --output json explain {s}";
    const explain = try common.format(session, pattern, .{ za, diagnostic.code[4..] });
    const explained = try expect_exit(session, out, step, explain, 0);
    json.check_explain(arena, explained.streams, explained.status, diagnostic) catch |err| {
        return fail_step(out, step, "expected explain to carry the diagnostic's members", err);
    };
}

/// Step 5: E0601 read from the diagnostic, and the alternative its fixes name applied.
fn step_pasta_missing(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    try accept.make_path_without_pasta(session, out);
    const command = za_without ++ " --output json run --net user alpine:3.20 -- true";
    const refused = try common.run_shown(session, out, command);
    const found = json_m5.check_pasta_missing(arena, refused.streams, refused.status) catch |err| {
        return fail_step(out, step, "expected ZBX-E0601 with its fixes", err);
    };
    const pattern = "{s} --output json explain {s}";
    const explain = try common.format(session, pattern, .{ za, found.code[4..] });
    const explained = try expect_exit(session, out, step, explain, 0);
    json.check_explain(arena, explained.streams, explained.status, found) catch |err| {
        return fail_step(out, step, "expected explain to carry the diagnostic's members", err);
    };
    const mode = json_m5.fix_net_mode(found) catch |err| {
        return fail_step(out, step, "expected a fix that runs with the host's network", err);
    };
    const own_pattern = "{s} --output json run --net {s}{s}";
    const own = try common.format(session, own_pattern, .{ za_without, mode, fetch });
    const ran = try common.run_shown(session, out, own);
    json_m5.check_granted(arena, ran.streams, ran.status, mode, &.{}) catch |err| {
        return fail_step(out, step, "expected the fix's network to run the command", err);
    };
    checks_spec.check_example_page(ran.streams, ran.status) catch |err| {
        return fail_step(out, step, "expected example.com's page on the host's network", err);
    };
    const doctor_command = za_without ++ " --output json doctor";
    const doctor = try expect_exit(session, out, step, doctor_command, 0);
    const checked = json_m5.check_doctor_net(arena, doctor.streams, doctor.status, doctor_schema);
    const net = checked catch |err| {
        return fail_step(out, step, "expected the doctor's JSON with the net warning", err);
    };
    const install = net.diagnostic.fixes[0];
    if (!install.needs_root or install.template) {
        return fail_step(out, step, "expected the net fix to need root", error.FlagsWrong);
    }
    const warning_explain = try common.format(session, pattern, .{ za, net.code[4..] });
    const warned = try expect_exit(session, out, step, warning_explain, 0);
    json_m5.check_explain_of_net(arena, warned.streams, warned.status, net) catch |err| {
        return fail_step(out, step, "expected explain to carry the net warning's members", err);
    };
}

test {
    _ = @import("agent_json_m5.zig");
    _ = checks_m4;
}
