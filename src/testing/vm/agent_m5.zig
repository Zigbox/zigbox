//! The agent test of M5 (docs/SPEC.md, "Production readiness"): a scripted agent drives M5's
//! steps using only `--output json`, `zbx schema <command>` and `zbx explain --output json`. It
//! never reads the hint, the `ss` output or a diagnostic's text: every decision is made on a
//! member of a JSON document. What it has to guess is a finding (docs/demos/m5.md, "The agent
//! test"), printed as a `FINDING` line and not worked around. It runs in the agent's own project
//! directory (the `za` wrapper), with its own `zbx.lock`.
//!
//!   1. `schema run` names the network members; the agent relies on them only after that.
//!   2. `run alpine:3.20 -- wget -qO- https://example.com` fails; the exit line says the network
//!      was `none`. The agent grants `--net user` and the page comes; the exit line says `user`.
//!   3. `run --publish 18091:80` ends with the forward in `published`.
//!   4. `run -d --publish 18092:80 nginx:alpine`: the agent reads the name from the document and
//!      reaches the server on the port it asked for; `stop` ends it and the port is free.
//!   5. With a `PATH` that has no pasta, `run --net user` is refused as ZBX-E0601: the agent reads
//!      the code, the blame and the fixes, finds the host-network alternative in them, applies
//!      its flag to its own command and gets the page. `explain --output json` agrees with the
//!      diagnostic. `doctor --output json` is run too.
//!   6. The firewall rules are what they were before the demo's first step.
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

/// How many findings the run has printed: each is something the agent could not read from JSON.
var findings_count: u32 = 0;

fn finding(out: *Io.Writer, text: []const u8) !void {
    findings_count += 1;
    try out.print("{s}: AGENT: FINDING: {s}\n", .{ H.demo_name, text });
}

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT: M5's steps, by JSON only\n", .{H.demo_name});
    findings_count = 0;
    try step_schemas(session, out);
    try step_pulls(session, out);
    try step_no_network(session, out);
    try step_published(session, out);
    try step_detached(session, out);
    try step_pasta_missing(session, out);
    try spec.expect_rules_unchanged(session, out);
    try out.print("{s}: AGENT: {d} findings\n", .{ H.demo_name, findings_count });
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
    const run = try fetch_schema(session, out, "run", null);
    json_m5.schema_describes_network(arena, run) catch |err| {
        return fail_step(out, step, "expected the run schema to name network and published", err);
    };
    _ = try fetch_schema(session, out, "stop", "zbx.stop/1");
    _ = try fetch_schema(session, out, "ps", "zbx.ps/1");
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
        return fail_step(out, step, "expected the exit line to say network none", err);
    };
    try finding(out, "nothing in the exit line says the network was the cause, only that the " ++
        "program failed on network none; an explicit --net none looks the same");
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

/// Step 4: a server in the background, reached on the port the agent asked for.
fn step_detached(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const start = za ++ " --output json run -d --name " ++ server_name ++
        " --publish 18092:80 nginx:alpine";
    const started = try expect_exit(session, out, step, start, 0);
    const detached = json_m5.check_detached(arena, started.streams, started.status) catch |err| {
        return fail_step(out, step, "expected the detached document with the name", err);
    };
    const name = try arena.dupe(u8, detached.name);
    if (!detached.network_in_json) {
        try finding(out, "run -d --output json does not say the network or the published ports");
    }
    const listed = try expect_exit(session, out, step, za ++ " --output json ps", 0);
    if (!try json_m5.ps_network_in_json(arena, listed.streams.stdout, name)) {
        try finding(out, "ps --output json does not say a running container's network or ports");
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
    try finding(out, "the fixes of ZBX-E0601 are a sentence and a command each, with nothing to " ++
        "say that the first needs root and the second is a template ('alpine -- sh')");
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
    const doctor = try expect_exit(session, out, step, za_without ++ " --output json doctor", 0);
    if (!try json_m5.doctor_net_in_json(arena, doctor.streams, doctor.status)) {
        try finding(out, "doctor --output json prints the text report: the net warning (pasta " ++
            "missing) has no JSON form and no code");
    }
}

test {
    _ = @import("agent_json_m5.zig");
    _ = checks_m4;
}
