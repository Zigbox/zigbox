//! The M7 acceptance checks (docs/briefs/M7-build.md, "Acceptance"), run in the first VM after
//! the six steps, in a copy of the project (`~/hello2`, wrapper `zh2`) so that `~/hello` stays
//! what step 1 built:
//!
//!   - `--graph` as text is the golden, and as JSON has the nodes and edges of the schema;
//!   - reordering the steps in the file gives the same keys and the same digest;
//!   - `touch` on every input is three hits;
//!   - a cycle is E0802 and names it, an input outside the project is E0803, a base that
//!     `zbx.lock` does not name is E0804 with the pull as the fix;
//!   - every file the builds put in the store is the user's; and after every build above no
//!     work directory is left, and no step's run record.
//!
//! The 0.0 ownership inside the tree (`0:0`) is BUILD7's (spec_m7.zig). Every assertion is a
//! function of checks_m7.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const step = "ACCEPT7";
const copy_dir = "/home/demo/hello2";
const zh2 = H.as_demo ++ "/home/demo/zh2";
const short_s: u32 = 120;
const build_timeout_s: u32 = 900;

const setup = H.as_demo ++ "sh -c 'rm -rf " ++ copy_dir ++ " /home/demo/secret && " ++
    "cp -a " ++ hello.project_dir ++ " " ++ copy_dir ++ " && echo secret > /home/demo/secret && " ++
    "ln -s /home/demo/secret " ++ copy_dir ++ "/escape'";
const touch_inputs = H.as_demo ++ "sh -c 'cd " ++ copy_dir ++ " && " ++
    "touch go.mod main.go VERSION LICENSE'";
const count_work = "ls -A " ++ common.store_dir ++ "/build/work 2>/dev/null | wc -l";
const count_records = H.as_demo ++ "sh -c '/home/demo/zh2 ps --all | grep -c build-; true'";
const count_foreign = "find " ++ common.store_dir ++ "/objects -type f ! -uid 1000 | wc -l";
const count_all = "find " ++ common.store_dir ++ "/objects -type f | wc -l";

const cycle_file =
    ".{\n    .version = 1,\n    .steps = .{\n" ++
    "        .{ .name = \"a\", .base = \"alpine:3.20\", .run = .{\"true\"}," ++
    " .needs = .{\"b\"} },\n" ++
    "        .{ .name = \"b\", .base = \"alpine:3.20\", .run = .{\"true\"}," ++
    " .needs = .{\"a\"} },\n" ++
    "    },\n    .image = .{ .base = \"alpine:3.20\" },\n}\n";
const outside_file =
    ".{\n    .version = 1,\n    .steps = .{\n" ++
    "        .{ .name = \"a\", .base = \"alpine:3.20\", .run = .{\"true\"}, " ++
    ".inputs = .{\"escape\"} },\n" ++
    "    },\n    .image = .{ .base = \"alpine:3.20\" },\n}\n";
const unlocked_file =
    ".{\n    .version = 1,\n    .steps = .{\n" ++
    "        .{ .name = \"a\", .base = \"busybox:1.36\", .run = .{\"true\"} },\n" ++
    "    },\n    .image = .{ .base = \"alpine:3.20\" },\n}\n";

const Refusal = struct {
    file: []const u8,
    code: []const u8,
    wants: []const []const u8,
};

const refusals = [_]Refusal{
    .{ .file = cycle_file, .code = "ZBX-E0802", .wants = &.{ "need each other", "a -> b -> a" } },
    .{ .file = outside_file, .code = "ZBX-E0803", .wants = &.{ "\"escape\"", "outside" } },
    .{
        .file = unlocked_file,
        .code = "ZBX-E0804",
        .wants = &.{ "busybox:1.36", "not in zbx.lock", "zbx pull docker.io/library/busybox:1.36" },
    },
};

pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: ACCEPT7: graph, order, touch, refusals, a clean store\n", .{H.demo_name});
    _ = try common.expect_exit(session, out, step, setup, 0);
    try hello.make_wrapper(session, copy_dir, "/home/demo/zh2");
    try graph(session, out);
    try reorder_and_touch(session, out);
    try refuse(session, out);
    try clean(session, out);
    try timer.lap(out, "accept7");
}

fn graph(session: *Session, out: *Io.Writer) !void {
    const text = try common.expect_exit(session, out, step, hello.zh ++ " build --graph", 0);
    checks.check_graph_text(text.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the graph text of the brief", err);
    };
    const command = hello.zh ++ " build --graph --output json";
    const json = try common.expect_exit(session, out, step, command, 0);
    checks.check_graph_json(session.scratch_allocator(), json.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the graph as JSON", err);
    };
}

fn reorder_and_touch(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const json = zh2 ++ " build --output json";
    const first = try state.expect_long_split(session, out, json, 0, build_timeout_s);
    const base = checks.parse_json(arena, first.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the report of the copy", err);
    };
    checks.check_all_hits(&base) catch |err| {
        return fail_step(out, step, "expected the copy to hit what ~/hello built", err);
    };
    var buffer: [2048]u8 = undefined;
    const swapped = checks.swap_steps(&buffer, hello.build_file_text) orelse {
        return fail_step(out, step, "the build file cannot be reordered", error.PrepareFailed);
    };
    try hello.put_text(session, copy_dir ++ "/zbx.build.zon", swapped);
    const again = try state.expect_long_split(session, out, json, 0, build_timeout_s);
    const second = checks.parse_json(arena, again.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the report of the reordered file", err);
    };
    checks.check_reorder(&base, &second) catch |err| {
        return fail_step(out, step, "expected the same keys and digest after a reorder", err);
    };
    try hello.put_text(session, copy_dir ++ "/zbx.build.zon", hello.build_file_text);
    _ = try common.expect_exit(session, out, step, touch_inputs, 0);
    const touched = try state.expect_long_split(session, out, zh2 ++ " build", 0, build_timeout_s);
    const report = checks.parse_text(touched.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the text report after touch", err);
    };
    checks.check_all_hits(&report) catch |err| {
        return fail_step(out, step, "expected three hits after touching every input", err);
    };
}

fn refuse(session: *Session, out: *Io.Writer) !void {
    inline for (refusals) |case| {
        try hello.put_text(session, copy_dir ++ "/zbx.build.zon", case.file);
        const refused = try common.run_shown(session, out, zh2 ++ " build");
        const stdout = refused.streams.stdout;
        checks.check_refusal(
            stdout,
            refused.streams.stderr,
            refused.status,
            case.code,
            case.wants,
        ) catch |err| {
            return fail_step(out, step, "expected " ++ case.code ++ " as the brief words it", err);
        };
    }
    try hello.put_text(session, copy_dir ++ "/zbx.build.zon", hello.build_file_text);
}

fn clean(session: *Session, out: *Io.Writer) !void {
    const work = try common.expect_exit(session, out, step, count_work, 0);
    checks.check_zero(work.streams.stdout) catch |err| {
        return fail_step(out, step, "expected no build/work directory left", err);
    };
    const records = try common.expect_exit(session, out, step, count_records, 0);
    checks.check_zero(records.streams.stdout) catch |err| {
        return fail_step(out, step, "expected no step run record left", err);
    };
    const all = try common.expect_exit(session, out, step, count_all, 0);
    checks.check_some(all.streams.stdout) catch |err| {
        return fail_step(out, step, "expected files in the store", err);
    };
    const foreign = try common.expect_exit(session, out, step, count_foreign, 0);
    checks.check_zero(foreign.streams.stdout) catch |err| {
        return fail_step(out, step, "expected every file in the store to be the user's", err);
    };
}

test {
    // Goal: the commands fit the guest's limit and the variants are what the refusals need.
    // Method: lengths, and the refusal table's words against the goldens' own.
    try std.testing.expect(setup.len <= 1024);
    try std.testing.expect(count_foreign.len <= 1024);
    try std.testing.expect(std.mem.indexOf(u8, cycle_file, ".needs = .{\"a\"}") != null);
    try std.testing.expectEqual(@as(usize, 3), refusals.len);
}
