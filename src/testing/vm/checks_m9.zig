//! What the M9 demo asserts (docs/briefs/M9-dockerfile-import.md, "Demo"), as pure functions of
//! the commands' output, each with a unit test. hello_m9.zig, accept_m9.zig and agent_m9.zig run
//! the commands in the guest and call these. The build report's parsers are M7's
//! (checks_m7.zig): `zbx build` prints the same report for an imported file.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const m7 = @import("checks_m7.zig");

pub const Error = m7.Error || error{
    /// `zbx import`'s report, build file or JSON is not what the brief shows.
    ImportWrong,
};

pub const Report = m7.Report;

/// A step of the demo's import: its name, the Dockerfile line it came from and its kind.
pub const Step = struct { name: []const u8, line: u32, kind: []const u8 };

/// The steps `zbx import` makes of the demo Dockerfile, in the report's order.
pub const steps = [_]Step{
    .{ .name = "build-1", .line = 5, .kind = "copy" },
    .{ .name = "build-2", .line = 6, .kind = "copy" },
    .{ .name = "build-3", .line = 8, .kind = "run" },
    .{ .name = "stage2-1", .line = 14, .kind = "run" },
    .{ .name = "stage2-2", .line = 15, .kind = "copy" },
    .{ .name = "stage2-3", .line = 16, .kind = "copy" },
};

/// The build's rows: the six steps and the image.
pub const rows_count: u32 = steps.len + 1;

const footer = "imported 6 steps from 2 stages (target stage2) to zbx.build.zon; 0 flagged";

fn has_line(text: []const u8, want: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trimEnd(u8, line, " \r"), want)) return true;
    }
    return false;
}

/// The report's lines that name a step: they start with a step name, not with a space.
fn count_step_lines(text: []const u8) u32 {
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == ' ') continue;
        if (std.mem.indexOf(u8, line, "  Dockerfile:") != null) count += 1;
    }
    return count;
}

const normalized_bytes_max = 8192;

/// `text` holds every one of `wants` once white space is folded (a cause wraps at a word).
pub fn contains_all(text: []const u8, wants: []const []const u8) bool {
    var buffer: [normalized_bytes_max]u8 = undefined;
    var want_buffer: [normalized_bytes_max]u8 = undefined;
    const flat = m7.normalize(&buffer, text);
    assert(flat.len <= buffer.len);
    for (wants) |want| {
        const folded = m7.normalize(&want_buffer, want);
        if (std.mem.indexOf(u8, flat, folded) == null) return false;
    }
    return true;
}

/// The text report and the warnings after it: `zbx import` prints both to stderr, the report
/// first, and nothing to stdout (only `--output json` writes stdout). Null when the report is
/// empty or a warning comes first.
const Split = struct { report: []const u8, warnings: []const u8 };

fn split_report(stdout: []const u8, stderr: []const u8) ?Split {
    if (stdout.len != 0) return null;
    const at = if (std.mem.indexOf(u8, stderr, "\nwarning[")) |index| index + 1 else stderr.len;
    assert(at <= stderr.len);
    if (at == 0 or std.mem.startsWith(u8, stderr, "warning[")) return null;
    const split: Split = .{ .report = stderr[0..at], .warnings = stderr[at..] };
    assert(split.report.len + split.warnings.len == stderr.len);
    return split;
}

/// Step 1: `zbx import` exited 0; the report has each step with its line and kind and nothing
/// after (no `net`, no `cache`: the `tools` stage is not reached), the footer, `EXPOSE` and
/// `HEALTHCHECK` as labels, and W0811 follows it.
pub fn check_import(stdout: []const u8, stderr: []const u8, status: u8) Error!void {
    if (status != 0) return error.ImportWrong;
    const split = split_report(stdout, stderr) orelse return error.ImportWrong;
    const report = split.report;
    var buffer: [64]u8 = undefined;
    for (steps) |one| {
        const want = std.fmt.bufPrint(&buffer, "{s}  Dockerfile:{d}  {s}", .{
            one.name, one.line, one.kind,
        }) catch unreachable; // 64 holds the longest name.
        if (!has_line(report, want)) return error.ImportWrong;
    }
    if (count_step_lines(report) != steps.len) return error.ImportWrong;
    if (!has_line(report, footer)) return error.ImportWrong;
    if (!std.mem.startsWith(u8, split.warnings, "warning[ZBX-W0811]: ")) return error.ImportWrong;
    if (std.mem.indexOf(u8, stderr, "error[") != null) return error.ImportWrong;
    // W0811's cause is cut after a few entries, so the labels are read from the report's list
    // of what did not carry over, which W0811 summarizes.
    const labels = [_][]const u8{
        "  Dockerfile:19  EXPOSE: label org.zigbox.import.expose",
        "  Dockerfile:20  HEALTHCHECK: label org.zigbox.import.healthcheck",
    };
    for (labels) |label| {
        if (!has_line(report, label)) return error.ImportWrong;
    }
}

/// A file the guest wrote is the golden, byte for byte.
pub fn check_same_bytes(got: []const u8, golden: []const u8) Error!void {
    assert(golden.len > 0);
    if (!std.mem.eql(u8, got, golden)) return error.ImportWrong;
}

/// The first build on a store: every row a miss.
pub fn check_first_build(report: *const Report) Error!void {
    assert(report.count <= m7.rows_max);
    if (report.count != rows_count) return error.ReportWrong;
    if (report.misses != rows_count) return error.CacheWrong;
    for (steps) |one| {
        if (report.row(one.name) == null) return error.ReportWrong;
    }
}

/// Every row a hit.
pub fn check_all_hits(report: *const Report) Error!void {
    assert(report.count <= m7.rows_max);
    if (report.count != rows_count) return error.ReportWrong;
    if (report.hits != rows_count) return error.CacheWrong;
    if (report.misses != 0) return error.CacheWrong;
}

fn expect_row(report: *const Report, name: []const u8, hit: bool) Error!void {
    const one = report.row(name) orelse return error.ReportWrong;
    if (one.hit != hit) return error.CacheWrong;
}

/// Step 4, with `extra.go`: the `build` stage's copy of `*.go` and its compile miss, the copy
/// of `go.mod` and the final stage's `adduser` hit; what follows the compile misses.
pub fn check_extra(report: *const Report) Error!void {
    assert(report.count <= m7.rows_max);
    if (report.count != rows_count) return error.ReportWrong;
    try expect_row(report, "build-1", true);
    try expect_row(report, "build-2", false);
    try expect_row(report, "build-3", false);
    try expect_row(report, "stage2-1", true);
    try expect_row(report, "stage2-2", false);
    try expect_row(report, "stage2-3", false);
    try expect_row(report, "image", false);
    if (report.hits != 2) return error.CacheWrong;
}

/// Step 2: `zbx inspect <digest> --output json` shows the digest, the user as `uid:gid`, the
/// workdir and the two labels the import made.
pub fn check_inspect(stdout: []const u8, digest: []const u8) Error!void {
    assert(digest.len > 0);
    var buffer: [96]u8 = undefined;
    const named = std.fmt.bufPrint(&buffer, "\"digest\":\"{s}\"", .{digest}) catch {
        return error.InspectWrong;
    };
    const wants = [_][]const u8{
        "\"schema\":\"zbx.build_result/1\"",
        named,
        "\"workdir\":\"/home/app\"",
        "\"user\":\"10001:10001\"",
        "\"org.zigbox.import.expose\":\"8080\"",
        "\"org.zigbox.import.healthcheck\":\"CMD [",
    };
    for (wants) |want| {
        if (std.mem.indexOf(u8, stdout, want) == null) return error.InspectWrong;
    }
}

/// The tree digest of a `zbx.build_result/1` document, to run the tree with no config.
pub fn inspect_tree(stdout: []const u8) ?[]const u8 {
    const marker = "\"tree\":\"";
    const at = std.mem.indexOf(u8, stdout, marker) orelse return null;
    const start = at + marker.len;
    if (stdout.len < start + 67) return null;
    const tree = stdout[start .. start + 67];
    if (!m7.is_digest(tree)) return null;
    return tree;
}

/// `stat -c '%u:%g %a' /etc/hello/VERSION` in the tree: the owner and mode the COPY set.
pub fn check_owner(stdout: []const u8) Error!void {
    const got = std.mem.trim(u8, stdout, " \r\n");
    assert(got.len <= stdout.len);
    if (!std.mem.eql(u8, got, "10001:10001 644")) return error.InspectWrong;
}

/// Step 6: the `tools` stage's report flags its one step with the match and the cache, and
/// stderr carries W0810 and then W0811 (the brief has W0810 last; the dropped parts follow it).
pub fn check_tools(stdout: []const u8, stderr: []const u8, status: u8) Error!void {
    if (status != 0) return error.ImportWrong;
    const split = split_report(stdout, stderr) orelse return error.ImportWrong;
    const line = "tools-1  Dockerfile:11  run  net (matched \"apk add\")  cache";
    if (!has_line(split.report, line)) return error.ImportWrong;
    if (count_step_lines(split.report) != 1) return error.ImportWrong;
    if (std.mem.indexOf(u8, split.report, "; 1 flagged") == null) return error.ImportWrong;
    if (!std.mem.startsWith(u8, split.warnings, "warning[ZBX-W0810]: ")) return error.ImportWrong;
    if (std.mem.indexOf(u8, split.warnings, "\nwarning[ZBX-W0811]: ") == null) {
        return error.ImportWrong;
    }
    if (std.mem.indexOf(u8, stderr, "error[") != null) return error.ImportWrong;
}

/// A refusal: exit 1, stderr starts `error[<code>]: `, no `errno`, and holds every one of
/// `wants`.
pub fn check_refused(
    stderr: []const u8,
    status: u8,
    code: []const u8,
    wants: []const []const u8,
) Error!void {
    assert(code.len > 0);
    if (status != 1) return error.RefusalWrong;
    var buffer: [32]u8 = undefined;
    const head = std.fmt.bufPrint(&buffer, "error[{s}]: ", .{code}) catch {
        return error.RefusalWrong; // A code longer than any registered one.
    };
    if (!std.mem.startsWith(u8, stderr, head)) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    if (!contains_all(stderr, wants)) return error.RefusalWrong;
}

/// The pull's own refusal with the network down: a first line `error[ZBX-E05..]` and the exit
/// code of a failure the user did not cause: 2 (environment, as a name that does not resolve) or
/// 3 (external, a registry that fails), never 1 (user) or 70 (internal).
pub fn check_pull_refused(stderr: []const u8, status: u8) Error!void {
    if (status != 2 and status != 3) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, stderr, "error[ZBX-E05")) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
}

/// stderr names each of `codes` as a warning.
pub fn check_warnings(stderr: []const u8, codes: []const []const u8) Error!void {
    assert(codes.len > 0);
    var buffer: [32]u8 = undefined;
    for (codes) |code| {
        const head = std.fmt.bufPrint(&buffer, "warning[{s}]: ", .{code}) catch {
            return error.ReportWrong; // A code longer than any registered one.
        };
        if (std.mem.indexOf(u8, stderr, head) == null) return error.ReportWrong;
    }
}

/// A fixture's refusal golden: `<code> Dockerfile:<line>`, the what, the fix.
pub const Golden = struct {
    code: []const u8,
    location: []const u8,
    what: []const u8,
    fix: []const u8,
};

pub fn parse_golden(text: []const u8) ?Golden {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const head = lines.next() orelse return null;
    const what = lines.next() orelse return null;
    const fix = lines.next() orelse return null;
    const space = std.mem.indexOfScalar(u8, head, ' ') orelse return null;
    if (!std.mem.startsWith(u8, head[space + 1 ..], "Dockerfile:")) return null;
    if (what.len == 0 or fix.len == 0) return null;
    return .{ .code = head[0..space], .location = head[space + 1 ..], .what = what, .fix = fix };
}

/// A fixture the binary refused as its golden says: the code, the line, the what and the fix,
/// (the caller checks that no build file was written).
pub fn check_fixture_refused(stderr: []const u8, status: u8, golden: []const u8) Error!void {
    const expected = parse_golden(golden) orelse return error.RefusalWrong;
    var buffer: [16]u8 = undefined;
    const code = std.fmt.bufPrint(&buffer, "ZBX-{s}", .{expected.code}) catch {
        return error.RefusalWrong;
    };
    try check_refused(stderr, status, code, &.{ expected.location, expected.what, expected.fix });
}

/// The demo Dockerfile with its two blank lines (9 and 12, between the stages) turned into
/// comments, `first` on line 9 and `second` on line 12: the lines keep their numbers.
pub fn with_comments(
    buffer: []u8,
    dockerfile: []const u8,
    first: []const u8,
    second: []const u8,
) ?[]const u8 {
    assert(first.len > 0);
    assert(second.len > 0);
    var writer: std.Io.Writer = .fixed(buffer);
    var lines = std.mem.splitScalar(u8, dockerfile, '\n');
    var number: u32 = 0;
    while (lines.next()) |line| {
        number += 1;
        if (lines.index == null and line.len == 0) break;
        const comment = switch (number) {
            9 => first,
            12 => second,
            else => {
                writer.print("{s}\n", .{line}) catch return null;
                continue;
            },
        };
        if (line.len != 0) return null;
        writer.print("# {s}\n", .{comment}) catch return null;
    }
    if (number < 12) return null;
    return writer.buffered();
}

/// The `zbx.import/1` document of the demo import: target `stage2`, two stages, the six steps
/// with their lines, none flagged.
pub fn check_import_json(arena: Allocator, stdout: []const u8) !void {
    const Json = struct {
        schema: []const u8,
        target: []const u8,
        stages: u32,
        steps: []const struct { name: []const u8, line: u32, kind: []const u8, cache: bool },
        flagged: u32,
    };
    const options: std.json.ParseOptions = .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    const trimmed = std.mem.trim(u8, stdout, " \r\n");
    const doc = std.json.parseFromSliceLeaky(Json, arena, trimmed, options) catch {
        return error.ImportWrong;
    };
    if (!std.mem.eql(u8, doc.schema, "zbx.import/1")) return error.ImportWrong;
    if (!std.mem.eql(u8, doc.target, "stage2")) return error.ImportWrong;
    if (doc.stages != 2 or doc.flagged != 0) return error.ImportWrong;
    if (doc.steps.len != steps.len) return error.ImportWrong;
    for (doc.steps, steps) |got, want| {
        if (!std.mem.eql(u8, got.name, want.name)) return error.ImportWrong;
        if (!std.mem.eql(u8, got.kind, want.kind)) return error.ImportWrong;
        if (got.line != want.line or got.cache) return error.ImportWrong;
    }
}

// ---- Tests --------------------------------------------------------------------------------

const testing = std.testing;
const digest_a = "b3:" ++ @as([64]u8, @splat('a'));
const digest_b = "b3:" ++ @as([64]u8, @splat('b'));

/// Recorded from the binary on 2026-11-14 (chown built, so no copy notes): stderr is
/// the report, then W0811; stdout is empty.
const import_report =
    "build-1  Dockerfile:5  copy\n" ++
    "build-2  Dockerfile:6  copy\n" ++
    "build-3  Dockerfile:8  run\n" ++
    "stage2-1  Dockerfile:14  run\n" ++
    "stage2-2  Dockerfile:15  copy\n" ++
    "stage2-3  Dockerfile:16  copy\n" ++
    "not carried over as instructions:\n" ++
    "  Dockerfile:1  # syntax: ignored: zbx reads the file\n" ++
    "  Dockerfile:19  EXPOSE: label org.zigbox.import.expose\n" ++
    "  Dockerfile:20  HEALTHCHECK: label org.zigbox.import.healthcheck\n" ++
    footer ++ "\n";

const import_warning =
    "warning[ZBX-W0811]: parts of the Dockerfile did not carry over\n" ++
    "  cause  not carried over: # syntax:1 (ignored: zbx reads the file), EXPOSE:19\n" ++
    "         (label org.zigbox.import.expose), HEALTHCHECK:20 (label\n" ++
    "         org.zigbox.import.healthcheck)\n" ++
    "  fix    nothing to do unless one matters; the report says what became of each\n";
const import_stderr = import_report ++ import_warning;

test "the import report: each step with its line, the footer, W0811 naming the labels" {
    // Goal: step 1's check accepts what the binary printed and refuses a flag, a lost step, a
    // missing warning, a report on stdout or a warning before it. Method: the recorded output,
    // then each edited.
    try check_import("", import_stderr, 0);
    try testing.expectError(error.ImportWrong, check_import("", import_stderr, 1));
    try testing.expectError(error.ImportWrong, check_import(import_report, import_warning, 0));
    try testing.expectError(error.ImportWrong, check_import("", import_report, 0));
    try testing.expectError(error.ImportWrong, check_import("", import_warning, 0));
    const first = import_warning ++ import_report;
    try testing.expectError(error.ImportWrong, check_import("", first, 0));
    var buffer: [2048]u8 = undefined;
    const net_size = std.mem.replacementSize(u8, import_stderr, "8  run", "8  run  net");
    const netted = buffer[0..net_size];
    _ = std.mem.replace(u8, import_stderr, "8  run", "8  run  net", netted);
    try testing.expectError(error.ImportWrong, check_import("", netted, 0));
    const lost = import_stderr["build-1  Dockerfile:5  copy\n".len..];
    try testing.expectError(error.ImportWrong, check_import("", lost, 0));
    const health = comptime std.mem.indexOf(u8, import_report, "  Dockerfile:20").?;
    const no_health = import_report[0..health] ++ footer ++ "\n" ++ import_warning;
    try testing.expectError(error.ImportWrong, check_import("", no_health, 0));
}

const row_names = [_][]const u8{
    "build-1", "build-2", "build-3", "stage2-1", "stage2-2", "stage2-3", "image",
};

fn report_of(names_hit: []const []const u8, digest: []const u8) Report {
    var report: Report = .{
        .rows = undefined,
        .count = 0,
        .digest = digest,
        .hits = 0,
        .misses = 0,
        .elapsed_ms = 0,
    };
    for (row_names) |name| {
        var hit = false;
        for (names_hit) |one| hit = hit or std.mem.eql(u8, one, name);
        report.rows[report.count] = .{
            .name = name,
            .hit = hit,
            .network = false,
            .start_ms = 0,
            .end_ms = 0,
            .key = "",
            .output = "",
        };
        report.count += 1;
        if (hit) report.hits += 1 else report.misses += 1;
    }
    return report;
}

test "the cache verdicts of steps 1, 3 and 4" {
    // Goal: each step's verdict check takes its own pattern and no other. Method: reports of
    // all misses, all hits, and step 4's pattern, each against the three checks.
    const misses = report_of(&.{}, digest_a);
    const hits = report_of(&row_names, digest_a);
    const extra = report_of(&.{ "build-1", "stage2-1" }, digest_b);
    try check_first_build(&misses);
    try check_all_hits(&hits);
    try check_extra(&extra);
    try testing.expectError(error.CacheWrong, check_first_build(&hits));
    try testing.expectError(error.CacheWrong, check_all_hits(&misses));
    try testing.expectError(error.CacheWrong, check_extra(&misses));
    try testing.expectError(error.CacheWrong, check_extra(&report_of(&.{"build-1"}, digest_b)));
    var short = hits;
    short.count = 6;
    try testing.expectError(error.ReportWrong, check_all_hits(&short));
}

const inspect_json = "{\"schema\":\"zbx.build_result/1\",\"digest\":\"" ++ digest_a ++ "\"," ++
    "\"tree\":\"" ++ digest_b ++ "\",\"config\":{\"entrypoint\":[\"/usr/local/bin/hello\"]," ++
    "\"cmd\":[],\"env\":[],\"workdir\":\"/home/app\",\"user\":\"10001:10001\",\"labels\":" ++
    "{\"org.zigbox.import.expose\":\"8080\",\"org.zigbox.import.healthcheck\":" ++
    "\"CMD [\\\"/usr/local/bin/hello\\\", \\\"--whoami\\\"]\"}}}\n";

test "inspect shows the user, the workdir and the labels; its tree runs the stat" {
    // Goal: step 2's inspect and owner checks. Method: the document render_json writes, then
    // with the user still a name; the stat line, then a root-owned one.
    try check_inspect(inspect_json, digest_a);
    try testing.expectEqualStrings(digest_b, inspect_tree(inspect_json).?);
    var buffer: [1024]u8 = undefined;
    const named_size = std.mem.replacementSize(u8, inspect_json, "10001:10001", "app");
    const named = buffer[0..named_size];
    _ = std.mem.replace(u8, inspect_json, "10001:10001", "app", named);
    try testing.expectError(error.InspectWrong, check_inspect(named, digest_a));
    try testing.expectError(error.InspectWrong, check_inspect(inspect_json, digest_b));
    try testing.expectEqual(null, inspect_tree("{\"tree\":\"b3:short\"}"));
    try check_owner("10001:10001 644\n");
    try testing.expectError(error.InspectWrong, check_owner("0:0 644\n"));
    try testing.expectError(error.InspectWrong, check_owner("10001:10001 755\n"));
}

test "the tools stage: flagged with its match and cache, W0810 then W0811" {
    // Goal: step 6's import check. Method: the recorded stderr (the report, then the warnings),
    // then without the flag, without either warning, with the two swapped, and on stdout.
    const report = "tools-1  Dockerfile:11  run  net (matched \"apk add\")  cache\n" ++
        "imported 1 step from 1 stage (target tools) to tools.build.zon; 1 flagged\n";
    const w0810 = "warning[ZBX-W0810]: the import has steps that are not hermetic\n";
    const w0811 = "warning[ZBX-W0811]: parts of the Dockerfile did not carry over\n";
    try check_tools("", report ++ w0810 ++ w0811, 0);
    try testing.expectError(error.ImportWrong, check_tools(report, w0810 ++ w0811, 0));
    const bare = "tools-1  Dockerfile:11  run\nimported 1 step; 0 flagged\n";
    try testing.expectError(error.ImportWrong, check_tools("", bare ++ w0810 ++ w0811, 0));
    try testing.expectError(error.ImportWrong, check_tools("", report ++ w0811, 0));
    try testing.expectError(error.ImportWrong, check_tools("", report ++ w0810, 0));
    try testing.expectError(error.ImportWrong, check_tools("", report ++ w0811 ++ w0810, 0));
    const both = "warning[ZBX-W0801]: a\nwarning[ZBX-W0802]: b\n";
    try check_warnings(both, &.{ "ZBX-W0801", "ZBX-W0802" });
    const one = "warning[ZBX-W0801]: a\n";
    try testing.expectError(error.ReportWrong, check_warnings(one, &.{"ZBX-W0802"}));
}

test "refusals: the code first, the words anywhere once wrapped, never errno" {
    // Goal: the hermetic, E0816 and network-down checks. Method: recorded first lines, then a
    // wrong code, an errno and a wrong status.
    const hermetic = "error[ZBX-E0814]: --hermetic refused a step\n" ++
        "  cause  Dockerfile:11 has a step that is not\n         hermetic\n";
    try check_refused(hermetic, 1, "ZBX-E0814", &.{ "Dockerfile:11", "step that is not hermetic" });
    try testing.expectError(error.RefusalWrong, check_refused(hermetic, 1, "ZBX-E0816", &.{}));
    try testing.expectError(error.RefusalWrong, check_refused(hermetic, 0, "ZBX-E0814", &.{}));
    const elsewhere = check_refused(hermetic, 1, "ZBX-E0814", &.{"Dockerfile:12"});
    try testing.expectError(error.RefusalWrong, elsewhere);
    const resolve = "error[ZBX-E0502]: the registry's name does not resolve\n";
    try check_pull_refused(resolve, 2);
    try check_pull_refused(resolve, 3);
    try testing.expectError(error.RefusalWrong, check_pull_refused(resolve, 1));
    try testing.expectError(error.RefusalWrong, check_pull_refused(resolve, 70));
    try testing.expectError(error.RefusalWrong, check_pull_refused("error[ZBX-E0814]: x\n", 2));
    const errno = "error[ZBX-E0501]: errno 101\n";
    try testing.expectError(error.RefusalWrong, check_pull_refused(errno, 2));
}

test "a fixture's refusal golden is read and matched against the binary's stderr" {
    // Goal: the ACCEPT fixture check. Method: a golden of the translator's format against
    // a rendered diagnostic that wraps, then one that truncates the what.
    const golden = "E0811 Dockerfile:3\n" ++
        "Dockerfile:3 has the label key `Has Space`, and a label key is only [a-z0-9._/-]\n" ++
        "rename the label, or remove it\n";
    const parsed = parse_golden(golden).?;
    try testing.expectEqualStrings("E0811", parsed.code);
    try testing.expectEqualStrings("Dockerfile:3", parsed.location);
    const stderr = "error[ZBX-E0811]: a Dockerfile instruction or flag is not supported\n" ++
        "  cause  Dockerfile:3 has the label key `Has Space`, and a label key is\n" ++
        "         only [a-z0-9._/-]\n" ++
        "  fix    rename the label, or remove it\n";
    try check_fixture_refused(stderr, 1, golden);
    const cut = "error[ZBX-E0811]: a Dockerfile instruction or flag is not supported\n" ++
        "  cause  Dockerfile:3: Dockerfile:3 has the label key `Has Space`, and a label\n" ++
        "         key i...\n  fix    rename the label, or remove it\n";
    try testing.expectError(error.RefusalWrong, check_fixture_refused(cut, 1, golden));
    try testing.expectEqual(null, parse_golden("E0811\n"));
}

const demo_dockerfile = @embedFile("m9_project/Dockerfile");

test "the comment variants keep every line where it was" {
    // Goal: ACCEPT's comment reorder changes only comments. Method: both orders of the two
    // comments; each has the same line count and the same instruction lines as the original.
    var first_buffer: [2048]u8 = undefined;
    var second_buffer: [2048]u8 = undefined;
    const one = with_comments(&first_buffer, demo_dockerfile, "one", "two").?;
    const two = with_comments(&second_buffer, demo_dockerfile, "two", "one").?;
    try testing.expectEqual(one.len, two.len);
    try testing.expectEqual(demo_dockerfile.len + 2 * "# one".len, one.len);
    var a = std.mem.splitScalar(u8, demo_dockerfile, '\n');
    var b = std.mem.splitScalar(u8, one, '\n');
    var number: u32 = 0;
    while (a.next()) |line| {
        number += 1;
        const other = b.next().?;
        if (number == 9 or number == 12) {
            try testing.expect(other.len > 0 and other[0] == '#');
        } else try testing.expectEqualStrings(line, other);
    }
    try testing.expectEqual(null, with_comments(&first_buffer, "FROM a\n", "x", "y"));
}

test "the import JSON: the target, the stages and each step's line" {
    // Goal: AGENT's reading of `zbx import --output json`. Method: the recorded document, then
    // one with a step's line moved.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const json_doc = @embedFile("m9_fixtures/import.json.txt");
    try check_import_json(arena, json_doc);
    const moved = try std.mem.replaceOwned(u8, arena, json_doc, "\"line\":14", "\"line\":13");
    try testing.expectError(error.ImportWrong, check_import_json(arena, moved));
    try testing.expectError(error.ImportWrong, check_import_json(arena, "{}"));
}
