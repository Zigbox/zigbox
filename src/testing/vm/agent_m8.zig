//! The agent test of M8 (docs/briefs/M8-trust.md, "The agent test"): a scripted agent signs and
//! verifies using only `--output json` and `zbx schema <command>`. The passphrase is given by
//! file, never on a command line. Every document is checked against the schema `zbx schema`
//! printed, and a refusal is read from its diagnostic's `code`. What the agent has to learn some
//! other way is a `FINDING`, printed and not worked around. It runs after `trust_m8.zig`, on
//! the key `demo` and the passphrase file that part made.
//!
//!   1. The schemas of sign, verify, trust-prune and inspect, none with a `$ref`.
//!   2. `sign --output json` follows the sign schema (the signature is found, as it was made).
//!   3. `verify --output json` follows the verify schema: six links, all ok.
//!   4. `trust prune --output json` follows its schema: a dry run, no orphans.
//!   5. `sign` with no passphrase and no terminal: a JSON diagnostic with ZBX-E0911.
//!
//! Every assertion is a function of checks_m8.zig or agent_json.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m8.zig");
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
const zh = hello.zh;
const step = "AGENT8";
const short_s: u32 = 120;
const pass_file = "/home/demo/pass";
const nobody = " </dev/null";
const lines_max: u32 = 4;

var findings_count: u32 = 0;

fn finding(out: *Io.Writer, text: []const u8) !void {
    findings_count += 1;
    try out.print("{s}: AGENT8: FINDING: {s}\n", .{ H.demo_name, text });
}

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: AGENT8: sign and verify, by JSON only\n", .{H.demo_name});
    findings_count = 0;
    const sign_schema = try fetch_schema(session, out, "sign", "zbx.sign/1");
    const verify_schema = try fetch_schema(session, out, "verify", "zbx.verify/1");
    const prune_schema = try fetch_schema(session, out, "trust-prune", "zbx.trust-prune/1");
    _ = try fetch_schema(session, out, "inspect", "zbx.inspect/1");
    const report = try hello.json_report(session, out, step);
    try step_sign(session, out, sign_schema, report.digest);
    try step_verify(session, out, verify_schema, report.digest);
    try step_prune(session, out, prune_schema);
    try step_refused(session, out, report.digest);
    try out.print("{s}: AGENT8: {d} findings\n", .{ H.demo_name, findings_count });
    try timer.lap(out, "agent8");
}

fn fetch_schema(
    session: *Session,
    out: *Io.Writer,
    name: []const u8,
    id: []const u8,
) ![]const u8 {
    const command = try common.format(session, "{s} schema {s}", .{ zh, name });
    const result = try state.expect_long_split(session, out, command, 0, short_s);
    json_m6.check_flat(result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected a schema without $ref", err);
    };
    const arena = session.scratch_allocator();
    json.schema_names(arena, result.streams.stdout, id) catch |err| {
        return fail_step(out, step, "expected the schema to name its document", err);
    };
    return arena.dupe(u8, result.streams.stdout);
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
            try out.print("{s}: AGENT8: {s} breaks its schema: {s}\n", .{ H.demo_name, what, why });
            return fail_step(out, step, what, error.SchemaViolated);
        }
    }
    if (count == 0) return fail_step(out, step, what, error.NoOutput);
}

fn step_sign(session: *Session, out: *Io.Writer, schema: []const u8, digest: []const u8) !void {
    const command = try common.format(
        session,
        "{s} sign {s} --passphrase-file {s} --output json",
        .{ zh, digest, pass_file },
    );
    const done = try state.expect_long_split(session, out, command, 0, short_s);
    const arena = session.scratch_allocator();
    try expect_lines_follow(arena, out, schema, done.streams.stdout, "the sign document");
}

fn step_verify(session: *Session, out: *Io.Writer, schema: []const u8, digest: []const u8) !void {
    const command = try common.format(session, "{s} verify {s} --output json", .{ zh, digest });
    const done = try state.expect_long_split(session, out, command, 0, short_s);
    const arena = session.scratch_allocator();
    try expect_lines_follow(arena, out, schema, done.streams.stdout, "the verify document");
    checks.check_verify_ok(arena, done.streams.stdout, done.status) catch |err| {
        return fail_step(out, step, "expected six links ok", err);
    };
}

fn step_prune(session: *Session, out: *Io.Writer, schema: []const u8) !void {
    const command = zh ++ " trust prune --output json";
    const done = try state.expect_long_split(session, out, command, 0, short_s);
    const arena = session.scratch_allocator();
    try expect_lines_follow(arena, out, schema, done.streams.stdout, "the prune document");
    checks.check_prune_dry(arena, done.streams.stdout, 0) catch |err| {
        return fail_step(out, step, "expected a dry run with no orphans", err);
    };
}

fn step_refused(session: *Session, out: *Io.Writer, digest: []const u8) !void {
    const command = try common.format(
        session,
        "{s} sign {s} --output json" ++ nobody,
        .{ zh, digest },
    );
    const failed = try state.expect_long_split(session, out, command, 1, short_s);
    const arena = session.scratch_allocator();
    const all = json.diagnostics(arena, failed.streams.stderr) catch |err| {
        return fail_step(out, step, "expected E0911 as a JSON diagnostic", err);
    };
    if (all.len == 0 or !std.mem.eql(u8, all[0].code, "ZBX-E0911")) {
        return fail_step(out, step, "expected the code ZBX-E0911", error.RefusalWrong);
    }
    if (all[0].fixes.len == 0 or all[0].fixes[0].command == null) {
        try finding(out, "the fix for a missing passphrase is a sentence with no command");
    }
}
