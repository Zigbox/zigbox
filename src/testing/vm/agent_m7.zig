//! The agent test of M7 (docs/briefs/M7-build.md, "The agent test"): a scripted agent builds
//! using only `--output json`, `zbx schema <command>` and `zbx explain --output json`. Every
//! decision is made on a member of a JSON document, and each document is checked against the
//! schema `zbx schema` printed. What the agent has to learn some other way is a `FINDING`
//! (docs/demos/m7.md, "The agent test"), printed and not worked around. It runs in its own copy
//! of the project (`~/agent-hello`, the `zha` wrapper).
//!
//!   1. The schemas of build, build-graph and inspect, none with a `$ref`.
//!   2. `build --output json` follows the build schema, line by line, and is three rows and
//!      a result.
//!   3. `build --graph --output json` follows the graph schema: three nodes, two edges.
//!   4. A `fetch` step with no network: stderr is an E0805 diagnostic naming the step and the
//!      file, and its fix names `.network = true` (a sentence, not a command: a FINDING);
//!      `explain ZBX-E0805` agrees with the diagnostic.
//!   5. The agent adds the grant the fix named: the build works, the `fetch` row says
//!      `network: true`, and a W0801 diagnostic says the step is not reproducible.
//!
//! Every assertion is a function of checks_m7.zig or agent_json.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m7.zig");
const json = @import("agent_json.zig");
const json_m6 = @import("agent_json_m6.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const step = "AGENT7";
const directory = "/home/demo/agent-hello";
const zha = H.as_demo ++ "/home/demo/zha";
const short_s: u32 = 120;
const build_timeout_s: u32 = 900;
const lines_max: u32 = 16;

const setup = H.as_demo ++ "sh -c 'rm -rf " ++ directory ++ " && cp -a " ++ hello.project_dir ++
    " " ++ directory ++ "'";

/// How many findings the run has printed: each is something the agent could not read from JSON.
var findings_count: u32 = 0;

fn finding(out: *Io.Writer, text: []const u8) !void {
    findings_count += 1;
    try out.print("{s}: AGENT7: FINDING: {s}\n", .{ H.demo_name, text });
}

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT7: zbx build, by JSON only\n", .{H.demo_name});
    findings_count = 0;
    _ = try common.expect_exit(session, out, step, setup, 0);
    try hello.make_wrapper(session, directory, "/home/demo/zha");
    const schemas = try step_schemas(session, out);
    try step_build(session, out, schemas);
    try step_graph(session, out, schemas);
    try step_refused(session, out);
    try step_granted(session, out, schemas);
    try out.print("{s}: AGENT7: {d} findings\n", .{ H.demo_name, findings_count });
    try timer.lap(out, "agent7");
}

const Schemas = struct { build: []const u8, graph: []const u8, inspect: []const u8 };

fn fetch_schema(session: *Session, out: *Io.Writer, name: []const u8) ![]const u8 {
    const command = try common.format(session, "{s} schema {s}", .{ zha, name });
    const result = try state.expect_long_split(session, out, command, 0, short_s);
    json_m6.check_flat(result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected a schema without $ref", err);
    };
    return session.scratch_allocator().dupe(u8, result.streams.stdout);
}

fn step_schemas(session: *Session, out: *Io.Writer) !Schemas {
    const schemas: Schemas = .{
        .build = try fetch_schema(session, out, "build"),
        .graph = try fetch_schema(session, out, "build-graph"),
        .inspect = try fetch_schema(session, out, "inspect"),
    };
    const arena = session.scratch_allocator();
    json.schema_names(arena, schemas.graph, "zbx.build_graph/1") catch |err| {
        return fail_step(out, step, "expected the graph schema to name its document", err);
    };
    return schemas;
}

/// Every non-empty line of `text` follows `schema`.
fn expect_lines_follow(
    arena: std.mem.Allocator,
    out: *Io.Writer,
    schema: []const u8,
    text: []const u8,
    what: []const u8,
) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var count: u32 = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (count > lines_max) return fail_step(out, step, what, error.TooManyLines);
        const reason = json.violation(arena, schema, line) catch |err| {
            return fail_step(out, step, what, err);
        };
        if (reason) |why| {
            try out.print("{s}: AGENT7: {s} breaks its schema: {s}\n", .{ H.demo_name, what, why });
            return fail_step(out, step, what, error.SchemaViolated);
        }
    }
    if (count == 0) return fail_step(out, step, what, error.NoOutput);
}

fn step_build(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const command = zha ++ " build --output json";
    const done = try state.expect_long_split(session, out, command, 0, build_timeout_s);
    const stdout = done.streams.stdout;
    try expect_lines_follow(arena, out, schemas.build, stdout, "the build report");
    const report = checks.parse_json(arena, stdout) catch |err| {
        return fail_step(out, step, "expected a report of three steps and a result", err);
    };
    checks.check_all_hits(&report) catch |err| {
        return fail_step(out, step, "expected the copy to hit what ~/hello built", err);
    };
    const same = try common.expect_exit(session, out, step, hello.zh ++ " build --output json", 0);
    const before = checks.parse_json(arena, same.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the reference report", err);
    };
    checks.check_digest_equal(report.digest, before.digest) catch |err| {
        return fail_step(out, step, "expected the copy to build the same digest", err);
    };
}

fn step_graph(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const command = zha ++ " build --graph --output json";
    const done = try state.expect_long_split(session, out, command, 0, short_s);
    const stdout = done.streams.stdout;
    try expect_lines_follow(arena, out, schemas.graph, stdout, "the build graph");
    checks.check_graph_json(arena, stdout) catch |err| {
        return fail_step(out, step, "expected three nodes and two edges to image", err);
    };
}

fn write_variant(session: *Session, out: *Io.Writer, extra: []const u8) !void {
    var buffer: [2048]u8 = undefined;
    const text = checks.with_step(&buffer, hello.build_file_text, extra) orelse {
        return fail_step(out, step, "the build file cannot take a step", error.PrepareFailed);
    };
    try hello.put_text(session, directory ++ "/zbx.build.zon", text);
}

fn step_refused(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    try write_variant(session, out, checks.fetch_step);
    const failed = try common.run_shown(session, out, zha ++ " build --output json");
    const failure = checks.check_failure_json(
        arena,
        failed.streams.stderr,
        failed.status,
    ) catch |err| {
        return fail_step(out, step, "expected E0805 as a JSON diagnostic", err);
    };
    if (!std.mem.eql(u8, failure.step, "fetch")) {
        return fail_step(
            out,
            step,
            "expected the diagnostic to name the fetch step",
            error.RefusalWrong,
        );
    }
    if (failure.fix_is_prose) {
        try finding(out, "the fix that names `.network = true` is a sentence with no command: " ++
            "the agent infers the edit to zbx.build.zon");
    }
    const all = try json.diagnostics(arena, failed.streams.stderr);
    const explain = try common.format(session, "{s} explain ZBX-E0805 --output json", .{zha});
    const said = try state.expect_long_split(session, out, explain, 0, short_s);
    checks.check_explain_entry(arena, said.streams.stdout, all[0]) catch |err| {
        return fail_step(out, step, "expected explain to agree with the diagnostic", err);
    };
}

fn step_granted(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    try write_variant(session, out, checks.fetch_network_step);
    const command = zha ++ " build --output json";
    const done = try state.expect_long_split(session, out, command, 0, build_timeout_s);
    try expect_lines_follow(arena, out, schemas.build, done.streams.stdout, "the granted build");
    const report = checks.parse_json(arena, done.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the report of the granted build", err);
    };
    const fetched = report.row("fetch") orelse {
        return fail_step(out, step, "expected a fetch row", error.ReportWrong);
    };
    if (!fetched.network) return fail_step(out, step, "expected network: true", error.ReportWrong);
    checks.check_has_code(arena, done.streams.stderr, "ZBX-W0801") catch |err| {
        return fail_step(out, step, "expected W0801 for a step with network", err);
    };
}

test {
    // Goal: the setup fits the guest's limit and the agent's wrapper is its own.
    // Method: length and names.
    try std.testing.expect(setup.len <= 1024);
    try std.testing.expect(!std.mem.eql(u8, directory, hello.project_dir));
}
