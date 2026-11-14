//! The agent test of M9 (docs/briefs/M9-dockerfile-import.md, "The demo", AGENT): a scripted
//! agent imports and builds the demo project using only `--output json`, `zbx schema <command>`
//! and `zbx explain --output json`. Each document is checked against the schema `zbx schema`
//! printed. It runs in its own copy of the project (`~/agent-hello`, the `zha` wrapper), with
//! the build file removed.
//!
//!   1. The schemas of import and build, neither with a `$ref`; the import schema names
//!      `zbx.import/1`.
//!   2. `import --output json` follows the import schema: target `stage2`, the six steps with
//!      their lines, none flagged; stderr carries W0811 as a JSON diagnostic.
//!   3. `build --output json` follows the build schema: every step a hit, the digest of
//!      `~/hello`.
//!   4. An `ONBUILD` added to the Dockerfile: `import --output json` is refused with an E0811
//!      JSON diagnostic and writes nothing; `explain ZBX-E0811 --output json` agrees with it.
//!
//! Every assertion is a function of checks_m9.zig, checks_m7.zig or agent_json.zig with a unit
//! test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m9.zig");
const m7 = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m9.zig");
const hello_m7 = @import("hello_m7.zig");
const json = @import("agent_json.zig");
const json_m6 = @import("agent_json_m6.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const step = "AGENT9";
const directory = "/home/demo/agent-hello";
const zha = H.as_demo ++ "/home/demo/zha";
const short_s: u32 = 120;
const lines_max: u32 = 16;

const setup = H.as_demo ++ "sh -c 'rm -rf " ++ directory ++ " && cp -a " ++ hello.project_dir ++
    " " ++ directory ++ " && rm " ++ directory ++ "/zbx.build.zon'";
const build_file_absent = "test ! -e " ++ directory ++ "/zbx.build.zon";
const clear_build_file = H.as_demo ++ "rm " ++ directory ++ "/zbx.build.zon";
/// The demo Dockerfile with an instruction import refuses, on line 22.
const onbuild_dockerfile = hello.dockerfile ++ "ONBUILD RUN true\n";
/// The catalog's summaries (src/diag/codes.zig): the harness cannot import the catalog.
const summary_e0811 = "a Dockerfile instruction or flag is not supported";

pub fn run_agent(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: zbx import and build, by JSON only\n", .{ H.demo_name, step });
    _ = try common.expect_exit(session, out, step, setup, 0);
    try hello_m7.make_wrapper(session, directory, "/home/demo/zha");
    const schemas = try step_schemas(session, out);
    try step_import(session, out, schemas);
    try step_build(session, out, schemas);
    try step_refused(session, out);
    try timer.lap(out, "agent9");
}

const Schemas = struct { import: []const u8, build: []const u8 };

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
        .import = try fetch_schema(session, out, "import"),
        .build = try fetch_schema(session, out, "build"),
    };
    json.schema_names(session.scratch_allocator(), schemas.import, "zbx.import/1") catch |err| {
        return fail_step(out, step, "expected the import schema to name its document", err);
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
            try out.print("{s}: {s}: {s} breaks its schema: {s}\n", .{
                H.demo_name, step, what, why,
            });
            return fail_step(out, step, what, error.SchemaViolated);
        }
    }
    if (count == 0) return fail_step(out, step, what, error.NoOutput);
}

/// The diagnostic of `code` among stderr's JSON lines.
fn find_diagnostic(
    arena: std.mem.Allocator,
    stderr: []const u8,
    code: []const u8,
) ?json.Diagnostic {
    const all = json.diagnostics(arena, stderr) catch return null;
    for (all) |diagnostic| {
        if (std.mem.eql(u8, diagnostic.code, code)) return diagnostic;
    }
    return null;
}

fn step_import(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const command = zha ++ " import --output json";
    const done = try state.expect_long_split(session, out, command, 0, short_s);
    try expect_lines_follow(arena, out, schemas.import, done.streams.stdout, "the import report");
    checks.check_import_json(arena, done.streams.stdout) catch |err| {
        return fail_step(out, step, "expected target stage2 and its six steps", err);
    };
    _ = find_diagnostic(arena, done.streams.stderr, "ZBX-W0811") orelse {
        return fail_step(out, step, "expected W0811 as a JSON diagnostic", error.RefusalWrong);
    };
}

fn step_build(session: *Session, out: *Io.Writer, schemas: Schemas) !void {
    const arena = session.scratch_allocator();
    const command = zha ++ " build --output json";
    const done = try state.expect_long_split(session, out, command, 0, hello.build_timeout_s);
    try expect_lines_follow(arena, out, schemas.build, done.streams.stdout, "the build report");
    const report = m7.parse_json(arena, done.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the rows and a result", err);
    };
    checks.check_all_hits(&report) catch |err| {
        return fail_step(out, step, "expected the copy to hit what ~/hello built", err);
    };
    m7.check_digest_equal(hello.first_digest(), report.digest) catch |err| {
        return fail_step(out, step, "expected the digest of ~/hello", err);
    };
}

fn step_refused(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    try hello_m7.put_text(session, directory ++ "/Dockerfile", onbuild_dockerfile);
    _ = try common.expect_exit(session, out, step, clear_build_file, 0);
    const refused = try common.run_shown(session, out, zha ++ " import --output json");
    if (refused.status != 1) return fail_step(out, step, "expected exit 1", error.ExitCodeWrong);
    const diagnostic = find_diagnostic(arena, refused.streams.stderr, "ZBX-E0811") orelse {
        return fail_step(out, step, "expected E0811 as a JSON diagnostic", error.RefusalWrong);
    };
    _ = try common.expect_exit(session, out, step, build_file_absent, 0);
    const explain = zha ++ " explain ZBX-E0811 --output json";
    const said = try state.expect_long_split(session, out, explain, 0, short_s);
    m7.check_explain_entry(arena, said.streams.stdout, diagnostic, summary_e0811) catch |err| {
        return fail_step(out, step, "expected explain to agree with the diagnostic", err);
    };
}

test {
    // Goal: the variant Dockerfile and the commands fit the guest. Method: lengths, and the
    // variant ends with the refused instruction.
    try std.testing.expect(onbuild_dockerfile.len <= 1536);
    try std.testing.expect(std.mem.endsWith(u8, onbuild_dockerfile, "ONBUILD RUN true\n"));
    try std.testing.expect(setup.len <= 1024);
}
