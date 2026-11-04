//! The assertions of the M7 demo (docs/briefs/M7-build.md, slice 4), as pure functions over the
//! text a command printed, each with unit tests: the build report as text and as JSON, the
//! steps' overlap, the result digest against the golden, the refusals (E0802 to E0805), the
//! graph, and the reorder, ownership and cleanliness checks of ACCEPT. The scripts that run in
//! the guest print `key=value` lines or whole outputs; nothing here touches a VM.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("agent_json.zig");

pub const Error = error{
    /// The report is not in the format `zbx build` documents.
    ReportWrong,
    /// A step is a hit where a miss was expected, or the reverse.
    CacheWrong,
    /// The result digest is not the one expected.
    DigestWrong,
    /// Two steps that must overlap in time do not.
    NoOverlap,
    /// The build took longer than the brief allows for an all-hit build.
    TooSlow,
    /// A refusal is missing, or does not say what the brief requires.
    RefusalWrong,
    /// The graph differs from its golden or from its schema.
    GraphWrong,
    /// `inspect` does not show the tree and the config.
    InspectWrong,
    OutOfMemory,
};

pub const rows_max: u32 = 8;

pub const Row = struct {
    name: []const u8,
    hit: bool,
    network: bool,
    start_ms: u64,
    end_ms: u64,
    key: []const u8,
    output: []const u8,
};

pub const Report = struct {
    rows: [rows_max]Row,
    count: u32,
    digest: []const u8,
    hits: u32,
    misses: u32,
    /// Only a JSON report has the times.
    elapsed_ms: u64,

    pub fn row(report: *const Report, name: []const u8) ?Row {
        for (report.rows[0..report.count]) |one| {
            if (std.mem.eql(u8, one.name, name)) return one;
        }
        return null;
    }
};

pub fn is_digest(text: []const u8) bool {
    if (text.len != 67) return false;
    if (!std.mem.startsWith(u8, text, "b3:")) return false;
    for (text[3..]) |byte| {
        if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}

// ---- The text report ----------------------------------------------------------------------

/// `built b3:<64 hex>  (H hit(s), M miss(es), S.d s)` -> the digest and the counts.
fn parse_footer(line: []const u8, report: *Report) Error!void {
    const prefix = "built ";
    if (!std.mem.startsWith(u8, line, prefix)) return error.ReportWrong;
    const rest = line[prefix.len..];
    if (rest.len < 67) return error.ReportWrong;
    report.digest = rest[0..67];
    if (!is_digest(report.digest)) return error.ReportWrong;
    var words = std.mem.tokenizeAny(u8, rest[67..], " (),");
    const hits = words.next() orelse return error.ReportWrong;
    const hits_word = words.next() orelse return error.ReportWrong;
    const misses = words.next() orelse return error.ReportWrong;
    const misses_word = words.next() orelse return error.ReportWrong;
    report.hits = std.fmt.parseInt(u32, hits, 10) catch return error.ReportWrong;
    report.misses = std.fmt.parseInt(u32, misses, 10) catch return error.ReportWrong;
    // The plural is part of the text the brief shows: `1 hit`, `2 hits`, `1 miss`, `2 misses`.
    const hits_plural = if (report.hits == 1) "hit" else "hits";
    const misses_plural = if (report.misses == 1) "miss" else "misses";
    if (!std.mem.eql(u8, hits_word, hits_plural)) return error.ReportWrong;
    if (!std.mem.eql(u8, misses_word, misses_plural)) return error.ReportWrong;
}

/// `  compile   miss   0.42 s` (and `net` after the time for a network step).
fn parse_row(line: []const u8) ?Row {
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    const name = words.next() orelse return null;
    const verdict = words.next() orelse return null;
    const hit = std.mem.eql(u8, verdict, "hit");
    if (!hit and !std.mem.eql(u8, verdict, "miss")) return null;
    var network = false;
    while (words.next()) |word| {
        if (std.mem.eql(u8, word, "net")) network = true;
    }
    return .{
        .name = name,
        .hit = hit,
        .network = network,
        .start_ms = 0,
        .end_ms = 0,
        .key = "",
        .output = "",
    };
}

/// The text report of a build that succeeded: a header, a row per step, the footer.
pub fn parse_text(stdout: []const u8) Error!Report {
    var report: Report = .{
        .rows = undefined,
        .count = 0,
        .digest = "",
        .hits = 0,
        .misses = 0,
        .elapsed_ms = 0,
    };
    var header = false;
    var footer = false;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "pulling ")) continue;
        if (std.mem.startsWith(u8, line, "build: ")) {
            header = true;
        } else if (std.mem.startsWith(u8, line, "built ")) {
            try parse_footer(line, &report);
            footer = true;
        } else if (parse_row(line)) |one| {
            if (report.count == rows_max) return error.ReportWrong;
            report.rows[report.count] = one;
            report.count += 1;
        } else return error.ReportWrong;
    }
    if (!header or !footer) return error.ReportWrong;
    var hits: u32 = 0;
    for (report.rows[0..report.count]) |one| hits += @intFromBool(one.hit);
    if (hits != report.hits) return error.ReportWrong;
    if (report.count != report.hits + report.misses) return error.ReportWrong;
    return report;
}

// ---- The JSON report ----------------------------------------------------------------------

const JsonStep = struct {
    schema: []const u8,
    step: []const u8,
    cache: []const u8,
    key: []const u8,
    output: []const u8,
    start_ms: u64,
    end_ms: u64,
    network: bool,
};

const JsonResult = struct {
    digest: []const u8,
    hits: u32,
    misses: u32,
    elapsed_ms: u64,
};

const JsonFinal = struct { schema: []const u8, build_result: JsonResult };

fn parse_json_line(arena: Allocator, comptime T: type, line: []const u8) Error!T {
    const options: std.json.ParseOptions = .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    return std.json.parseFromSliceLeaky(T, arena, line, options) catch error.ReportWrong;
}

/// The JSON lines of `zbx build --output json`: a line per step, in end order, then the result.
pub fn parse_json(arena: Allocator, stdout: []const u8) Error!Report {
    var report: Report = .{
        .rows = undefined,
        .count = 0,
        .digest = "",
        .hits = 0,
        .misses = 0,
        .elapsed_ms = 0,
    };
    var final = false;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (line.len == 0) continue;
        if (final) return error.ReportWrong;
        if (std.mem.indexOf(u8, line, "\"build_result\"") != null) {
            const one = try parse_json_line(arena, JsonFinal, line);
            if (!std.mem.eql(u8, one.schema, "zbx.build/1")) return error.ReportWrong;
            report.digest = one.build_result.digest;
            report.hits = one.build_result.hits;
            report.misses = one.build_result.misses;
            report.elapsed_ms = one.build_result.elapsed_ms;
            final = true;
            continue;
        }
        const one = try parse_json_line(arena, JsonStep, line);
        if (!std.mem.eql(u8, one.schema, "zbx.build/1")) return error.ReportWrong;
        if (report.count == rows_max) return error.ReportWrong;
        const hit = std.mem.eql(u8, one.cache, "hit");
        if (!hit and !std.mem.eql(u8, one.cache, "miss")) return error.ReportWrong;
        if (one.end_ms < one.start_ms) return error.ReportWrong;
        if (!is_digest(one.key)) return error.ReportWrong;
        if (!is_digest(one.output)) return error.ReportWrong;
        report.rows[report.count] = .{
            .name = one.step,
            .hit = hit,
            .network = one.network,
            .start_ms = one.start_ms,
            .end_ms = one.end_ms,
            .key = one.key,
            .output = one.output,
        };
        report.count += 1;
    }
    if (!final) return error.ReportWrong;
    if (!is_digest(report.digest)) return error.ReportWrong;
    if (report.count != report.hits + report.misses) return error.ReportWrong;
    return report;
}

// ---- What a report must say ---------------------------------------------------------------

/// Step 1: the three steps are all misses, and `compile` and `notice` ran at the same time.
pub fn check_first_build(report: *const Report) Error!void {
    if (report.count != 3) return error.ReportWrong;
    if (report.misses != 3) return error.CacheWrong;
    try check_overlap(report, "compile", "notice");
}

/// The intervals `[start_ms, end_ms]` of `a` and `b` share a moment: they were not run one
/// after the other.
pub fn check_overlap(report: *const Report, a: []const u8, b: []const u8) Error!void {
    const first = report.row(a) orelse return error.ReportWrong;
    const second = report.row(b) orelse return error.ReportWrong;
    if (first.end_ms <= first.start_ms) return error.ReportWrong;
    if (second.end_ms <= second.start_ms) return error.ReportWrong;
    if (first.start_ms >= second.end_ms) return error.NoOverlap;
    if (second.start_ms >= first.end_ms) return error.NoOverlap;
}

/// Every step of the build was a hit. (That it was fast is `check_fast`'s.)
pub fn check_all_hits(report: *const Report) Error!void {
    if (report.count != 3) return error.ReportWrong;
    if (report.misses != 0) return error.CacheWrong;
    if (report.hits != 3) return error.CacheWrong;
}

pub fn check_fast(report: *const Report) Error!void {
    if (report.elapsed_ms == 0) return error.ReportWrong;
    if (report.elapsed_ms >= 1000) return error.TooSlow;
}

/// Step 4: only `compile` and `image` were built again.
pub fn check_one_changed(report: *const Report) Error!void {
    if (report.count != 3) return error.ReportWrong;
    const compile = report.row("compile") orelse return error.ReportWrong;
    const notice = report.row("notice") orelse return error.ReportWrong;
    const image = report.row("image") orelse return error.ReportWrong;
    if (compile.hit) return error.CacheWrong;
    if (!notice.hit) return error.CacheWrong;
    if (image.hit) return error.CacheWrong;
    if (report.hits != 1) return error.CacheWrong;
    if (report.misses != 2) return error.CacheWrong;
}

pub fn check_digest_equal(first: []const u8, second: []const u8) Error!void {
    if (!is_digest(first)) return error.DigestWrong;
    if (!std.mem.eql(u8, first, second)) return error.DigestWrong;
}

pub fn check_digest_differs(first: []const u8, second: []const u8) Error!void {
    if (!is_digest(first)) return error.DigestWrong;
    if (!is_digest(second)) return error.DigestWrong;
    if (std.mem.eql(u8, first, second)) return error.DigestWrong;
}

/// The golden file `m7_expected.zon` holds `.digest = "b3:..."`. An empty golden is how a first
/// run learns the digest: the part prints it and fails, and the value is copied from the log of
/// a green run of the same commit.
pub fn golden_digest(golden: []const u8) ?[]const u8 {
    const marker = ".digest = \"";
    const at = std.mem.indexOf(u8, golden, marker) orelse return null;
    const rest = golden[at + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    if (!is_digest(rest[0..end])) return null;
    return rest[0..end];
}

pub fn check_golden(golden: []const u8, digest: []const u8) Error!void {
    const expected = golden_digest(golden) orelse return error.DigestWrong;
    return check_digest_equal(expected, digest);
}

/// `zbx inspect <digest> --output json` shows the digest, a tree, and the config the image set.
pub fn check_inspect(stdout: []const u8, digest: []const u8) Error!void {
    const wants = [_][]const u8{
        "\"schema\":\"zbx.build_result/1\"",
        digest,
        "\"tree\":\"b3:",
        "/usr/local/bin/hello",
        "GREETING_STYLE=plain",
        "org.opencontainers.image.source",
    };
    for (wants) |want| {
        if (std.mem.indexOf(u8, stdout, want) == null) return error.InspectWrong;
    }
}

// ---- Refusals -----------------------------------------------------------------------------

/// `text` with every run of white space as one space: a long cause wraps at a word.
pub fn normalize(buffer: []u8, text: []const u8) []const u8 {
    var length: usize = 0;
    var space = true;
    for (text) |byte| {
        if (std.ascii.isWhitespace(byte)) {
            if (space) continue;
            space = true;
            if (length == buffer.len) break;
            buffer[length] = ' ';
            length += 1;
            continue;
        }
        space = false;
        if (length == buffer.len) break;
        buffer[length] = byte;
        length += 1;
    }
    return std.mem.trimEnd(u8, buffer[0..length], " ");
}

const normalized_bytes_max = 8192;

fn contains_all(stderr: []const u8, wants: []const []const u8) bool {
    var buffer: [normalized_bytes_max]u8 = undefined;
    const flat = normalize(&buffer, stderr);
    for (wants) |want| {
        if (std.mem.indexOf(u8, flat, want) == null) return false;
    }
    return true;
}

/// A refusal of the build file: exit 1, nothing built (stdout holds no report), the first line
/// of stderr is `error[ZBX-E080x]: ...`, no `errno`, and the words in `wants` are in it.
pub fn check_refusal(
    stdout: []const u8,
    stderr: []const u8,
    status: u8,
    code: []const u8,
    wants: []const []const u8,
) Error!void {
    if (status != 1) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stdout, "built b3:") != null) return error.RefusalWrong;
    var head_buffer: [32]u8 = undefined;
    const head = std.fmt.bufPrint(
        &head_buffer,
        "error[{s}]: ",
        .{code},
    ) catch unreachable; // 32 holds the longest code.
    if (!std.mem.startsWith(u8, stderr, head)) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    if (!contains_all(stderr, wants)) return error.RefusalWrong;
}

/// Step 6: the `fetch` step has no network. The brief's words, the other steps' hits are checked
/// from the text report of the same build (it is not printed on a failure, so by `ps` and cache).
pub fn check_no_network(stderr: []const u8, status: u8) Error!void {
    if (status != 1) return error.RefusalWrong;
    const head = "error[ZBX-E0805]: build step \"fetch\" failed: exit";
    if (!std.mem.startsWith(u8, stderr, head)) return error.RefusalWrong;
    const wants = [_][]const u8{
        "the step has no network",
        "add .network = true to step \"fetch\" in zbx.build.zon",
    };
    if (!contains_all(stderr, &wants)) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
}

/// The rows a failed build printed before the failure: `compile` and `notice` hit.
pub fn check_others_hit(stdout: []const u8) Error!void {
    var seen: u32 = 0;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        const one = parse_row(line) orelse continue;
        if (std.mem.eql(u8, one.name, "fetch")) continue;
        if (!one.hit) return error.CacheWrong;
        seen += 1;
    }
    if (seen != 2) return error.ReportWrong;
}

/// A program's whole output is `want` and a newline (`zbx run <digest>` of the demo image).
pub fn check_stdout_is(stdout: []const u8, want: []const u8) Error!void {
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, stdout, "\r\n"), want)) return error.ReportWrong;
    if (stdout.len == 0) return error.ReportWrong;
}

// ---- The graph ----------------------------------------------------------------------------

/// The text of `zbx build --graph` for the demo project (src/testdata/build_graph.stdout.txt,
/// which the harness module cannot embed from here).
pub const graph_golden =
    "compile   base golang:1.23-alpine   inputs go.mod main.go\n" ++
    "notice    base alpine:3.20          inputs VERSION LICENSE\n" ++
    "image     base alpine:3.20          adds compile -> /usr/local/bin, notice -> /\n";

pub fn check_graph_text(stdout: []const u8) Error!void {
    if (!std.mem.eql(u8, stdout, graph_golden)) return error.GraphWrong;
}

/// `--graph --output json` has the schema's name, the three nodes (two steps and the image) and
/// the edges from each step to the image. The `path` is the machine's own.
pub fn check_graph_json(arena: Allocator, stdout: []const u8) Error!void {
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const doc = std.json.parseFromSliceLeaky(Value, arena, stdout, options) catch {
        return error.GraphWrong;
    };
    if (doc != .object) return error.GraphWrong;
    const schema = doc.object.get("schema") orelse return error.GraphWrong;
    if (schema != .string) return error.GraphWrong;
    if (!std.mem.eql(u8, schema.string, "zbx.build_graph/1")) return error.GraphWrong;
    const nodes = doc.object.get("nodes") orelse return error.GraphWrong;
    const edges = doc.object.get("edges") orelse return error.GraphWrong;
    if (nodes != .array) return error.GraphWrong;
    if (edges != .array) return error.GraphWrong;
    if (nodes.array.items.len != 3) return error.GraphWrong;
    if (edges.array.items.len != 2) return error.GraphWrong;
    for (edges.array.items) |edge| {
        if (edge != .object) return error.GraphWrong;
        const to = edge.object.get("to") orelse return error.GraphWrong;
        if (to != .string) return error.GraphWrong;
        if (!std.mem.eql(u8, to.string, "image")) return error.GraphWrong;
    }
}

// ---- The agent's reading of the refusal ---------------------------------------------------

/// What the agent read from a failed step's JSON diagnostic: the step, and whether the fix that
/// names the grant is a sentence only (`command` null), so that the agent infers the edit.
pub const Failure = struct { step: []const u8, fix_is_prose: bool };

/// stderr of a failed JSON build is an E0805 diagnostic: exit 1, the code, the step and the
/// file in the context, and a fix that names `.network = true`.
pub fn check_failure_json(arena: Allocator, stderr: []const u8, status: u8) !Failure {
    if (status != 1) return error.RefusalWrong;
    const all = try json.diagnostics(arena, stderr);
    if (all.len == 0) return error.RefusalWrong;
    const first = all[0];
    if (!std.mem.eql(u8, first.code, "ZBX-E0805")) return error.RefusalWrong;
    if (first.context != .object) return error.RefusalWrong;
    const step = first.context.object.get("step") orelse return error.RefusalWrong;
    const file = first.context.object.get("file") orelse return error.RefusalWrong;
    if (step != .string) return error.RefusalWrong;
    if (file != .string) return error.RefusalWrong;
    if (!std.mem.eql(u8, file.string, "zbx.build.zon")) return error.RefusalWrong;
    for (first.fixes) |fix| {
        if (std.mem.indexOf(u8, fix.sentence, ".network = true") == null) continue;
        return .{ .step = step.string, .fix_is_prose = fix.command == null };
    }
    return error.RefusalWrong;
}

/// Some diagnostic among stderr's JSON lines has `code`.
pub fn check_has_code(arena: Allocator, stderr: []const u8, code: []const u8) !void {
    for (try json.diagnostics(arena, stderr)) |one| {
        if (std.mem.eql(u8, one.code, code)) return;
    }
    return error.RefusalWrong;
}

/// The `fetch` step with the grant the fix named.
pub const fetch_network_step =
    "        .{\n" ++
    "            .name = \"fetch\",\n" ++
    "            .base = \"alpine:3.20\",\n" ++
    "            .network = true,\n" ++
    "            .run = .{ \"wget\", \"-q\", \"-O\", \"/out/page\", \"https://example.com\" },\n" ++
    "        },\n";

// ---- ACCEPT: order, ownership, cleanliness ------------------------------------------------

/// Reordering the steps in the file gives the same keys and the same digest.
pub fn check_reorder(first: *const Report, second: *const Report) Error!void {
    try check_digest_equal(first.digest, second.digest);
    for (first.rows[0..first.count]) |one| {
        const other = second.row(one.name) orelse return error.ReportWrong;
        if (!std.mem.eql(u8, one.key, other.key)) return error.DigestWrong;
        if (!std.mem.eql(u8, one.output, other.output)) return error.DigestWrong;
    }
}

/// A count printed by a command (`wc -l`): `0` is a clean directory or no record.
pub fn check_zero(stdout: []const u8) Error!void {
    if (!std.mem.eql(u8, std.mem.trim(u8, stdout, " \r\n"), "0")) return error.ReportWrong;
}

/// A count above zero: the store holds files, so a count of those that are not the user's means
/// something.
pub fn check_some(stdout: []const u8) Error!void {
    const count = std.fmt.parseInt(u32, std.mem.trim(u8, stdout, " \r\n"), 10) catch {
        return error.ReportWrong;
    };
    if (count == 0) return error.ReportWrong;
}

// ---- Variants of the build file -----------------------------------------------------------

/// Appends the `fetch` step of the brief's step 6 before the end of `.steps`.
pub const fetch_step =
    "        .{\n" ++
    "            .name = \"fetch\",\n" ++
    "            .base = \"alpine:3.20\",\n" ++
    "            .run = .{ \"wget\", \"-q\", \"-O\", \"/out/page\", \"https://example.com\" },\n" ++
    "        },\n";

const steps_end = "    },\n    .image = .{";

/// `file` with `extra` (step text) as the last of its steps.
pub fn with_step(buffer: []u8, file: []const u8, extra: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, file, steps_end) orelse return null;
    const total = file.len + extra.len;
    if (total > buffer.len) return null;
    @memcpy(buffer[0..at], file[0..at]);
    @memcpy(buffer[at..][0..extra.len], extra);
    @memcpy(buffer[at + extra.len ..][0 .. file.len - at], file[at..]);
    return buffer[0..total];
}

const compile_marker = "        .{\n            .name = \"compile\"";
const notice_marker = "        .{\n            .name = \"notice\"";

/// `file` with its `compile` and `notice` steps swapped (in either order they stand).
pub fn swap_steps(buffer: []u8, file: []const u8) ?[]const u8 {
    const one = std.mem.indexOf(u8, file, compile_marker) orelse return null;
    const other = std.mem.indexOf(u8, file, notice_marker) orelse return null;
    const end = std.mem.indexOf(u8, file, steps_end) orelse return null;
    const first = @min(one, other);
    const second = @max(one, other);
    if (second >= end) return null;
    if (file.len > buffer.len) return null;
    var at: usize = 0;
    const pieces = [_][]const u8{
        file[0..first], file[second..end], file[first..second], file[end..],
    };
    for (pieces) |piece| {
        @memcpy(buffer[at..][0..piece.len], piece);
        at += piece.len;
    }
    std.debug.assert(at == file.len);
    return buffer[0..at];
}

// ---- Tests --------------------------------------------------------------------------------

fn repeat(comptime byte: u8) [64]u8 {
    return @splat(byte);
}

const digest_a = "b3:" ++ repeat('a');
const digest_b = "b3:" ++ repeat('b');
const digest_c = "b3:" ++ repeat('c');

const text_first =
    "build: zbx.build.zon, 3 steps\n" ++
    "  compile   miss   3.42 s\n" ++
    "  notice    miss   0.42 s\n" ++
    "  image     miss   0.10 s\n" ++
    "built " ++ digest_a ++ "  (0 hits, 3 misses, 3.9 s)\n";

const text_hits =
    "build: zbx.build.zon, 3 steps\n" ++
    "  compile   hit    0.00 s\n" ++
    "  notice    hit    0.00 s\n" ++
    "  image     hit    0.00 s\n" ++
    "built " ++ digest_a ++ "  (3 hits, 0 misses, 0.0 s)\n";

const text_one =
    "build: zbx.build.zon, 3 steps\n" ++
    "  compile   miss   2.00 s\n" ++
    "  notice    hit    0.00 s\n" ++
    "  image     miss   0.10 s\n" ++
    "built " ++ digest_b ++ "  (1 hit, 2 misses, 2.1 s)\n";

const json_first =
    "{\"schema\":\"zbx.build/1\",\"step\":\"notice\",\"cache\":\"miss\",\"key\":\"" ++ digest_b ++
    "\",\"output\":\"" ++ digest_c ++ "\",\"start_ms\":10,\"end_ms\":900,\"network\":false}\n" ++
    "{\"schema\":\"zbx.build/1\",\"step\":\"compile\",\"cache\":\"miss\",\"key\":\"" ++ digest_a ++
    "\",\"output\":\"" ++ digest_c ++ "\",\"start_ms\":5,\"end_ms\":3000,\"network\":false}\n" ++
    "{\"schema\":\"zbx.build/1\",\"step\":\"image\",\"cache\":\"miss\",\"key\":\"" ++ digest_a ++
    "\",\"output\":\"" ++ digest_c ++ "\",\"start_ms\":3001,\"end_ms\":3100,\"network\":false}\n" ++
    "{\"schema\":\"zbx.build/1\",\"build_result\":{\"digest\":\"" ++ digest_a ++
    "\",\"hits\":0,\"misses\":3,\"elapsed_ms\":3200}}\n";

test "a text report parses; hits, misses and rows must agree" {
    // Goal: the footer's plural, the counts and the rows are read as the brief shows them.
    const first = try parse_text(text_first);
    try check_digest_equal(digest_a, first.digest);
    try std.testing.expectEqual(@as(u32, 3), first.misses);
    try check_all_hits(&(try parse_text(text_hits)));
    try check_one_changed(&(try parse_text(text_one)));
    try std.testing.expectError(error.CacheWrong, check_all_hits(&first));
    // A footer that disagrees with its rows, a wrong plural and a missing header are refused.
    const lying = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        text_hits,
        "(3 hits, 0 misses",
        "(2 hits, 1 miss",
    );
    defer std.testing.allocator.free(lying);
    try std.testing.expectError(error.ReportWrong, parse_text(lying));
    const plural = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        text_one,
        "1 hit,",
        "1 hits,",
    );
    defer std.testing.allocator.free(plural);
    try std.testing.expectError(error.ReportWrong, parse_text(plural));
    try std.testing.expectError(error.ReportWrong, parse_text(text_hits[30..]));
    try std.testing.expectError(error.ReportWrong, parse_text(""));
}

test "a text row with net marks a network step" {
    // Goal: the `net` suffix is read, and a step line without a verdict is not a row.
    const row = parse_row(
        "  fetch     miss   0.40 s  net",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(row.network);
    try std.testing.expect(!row.hit);
    try std.testing.expect(parse_row("  fetch     maybe  0.40 s") == null);
    try std.testing.expect(parse_row("") == null);
}

test "a JSON report parses, and the overlap of two steps is decided on their intervals" {
    // Goal: compile [5,3000] and notice [10,900] overlap; back to back they do not.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const report = try parse_json(arena, json_first);
    try check_first_build(&report);
    try std.testing.expectEqual(@as(u64, 3200), report.elapsed_ms);
    try std.testing.expectError(error.TooSlow, check_fast(&report));
    const apart = try std.mem.replaceOwned(
        u8,
        arena,
        json_first,
        "\"start_ms\":10,\"end_ms\":900",
        "\"start_ms\":3000,\"end_ms\":3900",
    );
    const later = try parse_json(arena, apart);
    try std.testing.expectError(error.NoOverlap, check_first_build(&later));
    try std.testing.expectError(
        error.ReportWrong,
        parse_json(arena, json_first[0 .. json_first.len - 60]),
    );
    try std.testing.expectError(
        error.ReportWrong,
        parse_json(arena, "{\"schema\":\"zbx.build/2\"}\n"),
    );
    try std.testing.expectError(error.ReportWrong, parse_json(arena, ""));
}

test "an all-hit report is fast only under a second" {
    // Goal: the boundary of `elapsed_ms < 1000`.
    var report = try parse_text(text_hits);
    report.elapsed_ms = 999;
    try check_fast(&report);
    report.elapsed_ms = 1000;
    try std.testing.expectError(error.TooSlow, check_fast(&report));
    report.elapsed_ms = 0;
    try std.testing.expectError(error.ReportWrong, check_fast(&report));
}

test "digests are equal, different, or the golden" {
    // Goal: the golden is read from the zon text; an empty or damaged golden fails.
    try check_digest_equal(digest_a, digest_a);
    try std.testing.expectError(error.DigestWrong, check_digest_equal(digest_a, digest_b));
    try std.testing.expectError(error.DigestWrong, check_digest_equal("b3:12", "b3:12"));
    try check_digest_differs(digest_a, digest_b);
    try std.testing.expectError(error.DigestWrong, check_digest_differs(digest_a, digest_a));
    const golden = ".{\n    .digest = \"" ++ digest_a ++ "\",\n}\n";
    try check_golden(golden, digest_a);
    try std.testing.expectError(error.DigestWrong, check_golden(golden, digest_b));
    try std.testing.expectError(
        error.DigestWrong,
        check_golden(".{\n    .digest = \"\",\n}\n", digest_a),
    );
    try std.testing.expectError(error.DigestWrong, check_golden("", digest_a));
}

test "inspect must show the digest, a tree and the config" {
    // Goal: each of the five facts is needed.
    const good = "{\"schema\":\"zbx.build_result/1\",\"digest\":\"" ++ digest_a ++
        "\",\"tree\":\"b3:abc\",\"config\":{\"entrypoint\":[\"/usr/local/bin/hello\"]," ++
        "\"env\":[\"GREETING_STYLE=plain\"]," ++
        "\"labels\":{\"org.opencontainers.image.source\":\"x\"}}}";
    try check_inspect(good, digest_a);
    try std.testing.expectError(error.InspectWrong, check_inspect(good, digest_b));
    const no_tree = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        good,
        "\"tree\"",
        "\"leaf\"",
    );
    defer std.testing.allocator.free(no_tree);
    try std.testing.expectError(error.InspectWrong, check_inspect(no_tree, digest_a));
}

test "a refusal is exit 1, its code first, and the words the brief names" {
    // Goal: the E0802 fixture (src/testdata/diag/E0802.txt) passes; each defect fails.
    const cycle =
        "error[ZBX-E0802]: the build graph is invalid\n" ++
        "  cause  'zbx.build.zon' line 4, column 77: the steps need each other round: a\n" ++
        "         -> b -> a\n" ++
        "  fix    remove a need that closes the round\n";
    const wants = [_][]const u8{ "need each other", "a -> b -> a" };
    try check_refusal("", cycle, 1, "ZBX-E0802", &wants);
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", cycle, 125, "ZBX-E0802", &wants),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", cycle, 1, "ZBX-E0803", &wants),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", cycle, 0, "ZBX-E0802", &wants),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", " " ++ cycle, 1, "ZBX-E0802", &wants),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", cycle ++ "errno 2\n", 1, "ZBX-E0802", &wants),
    );
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("built " ++ digest_a, cycle, 1, "ZBX-E0802", &wants),
    );
    const missing = [_][]const u8{"a -> c -> a"};
    try std.testing.expectError(
        error.RefusalWrong,
        check_refusal("", cycle, 1, "ZBX-E0802", &missing),
    );
}

test "the no-network refusal is read across a wrapped line" {
    // Goal: the E0805 fixture (src/testdata/diag/E0805.txt), where the cause wraps and the fix
    // has two spaces around the edit.
    const fixture =
        "error[ZBX-E0805]: build step \"fetch\" failed: exit 6\n" ++
        "  cause  curl: (6) Could not resolve host: example.org; the step has no network:\n" ++
        "         build steps run with network none unless they ask\n" ++
        "  fix    if the step needs the network, add  .network = true  to step \"fetch\" " ++
        "in zbx.build.zon\n";
    try check_no_network(fixture, 1);
    const wrapped = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        fixture,
        "the step has no network",
        "the step has\n         no network",
    );
    defer std.testing.allocator.free(wrapped);
    try check_no_network(wrapped, 1);
    try std.testing.expectError(error.RefusalWrong, check_no_network(fixture, 0));
    const other = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        fixture,
        "\"fetch\" failed",
        "\"other\" failed",
    );
    defer std.testing.allocator.free(other);
    try std.testing.expectError(error.RefusalWrong, check_no_network(other, 1));
    const no_fix = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        fixture,
        ".network = true",
        ".net = true",
    );
    defer std.testing.allocator.free(no_fix);
    try std.testing.expectError(error.RefusalWrong, check_no_network(no_fix, 1));
}

test "the failed build's rows: the others are hits" {
    // Goal: two hit rows pass; a miss, or a missing row, fails.
    try check_others_hit("  compile   hit    0.00 s\n  notice    hit    0.00 s\n");
    try std.testing.expectError(
        error.CacheWrong,
        check_others_hit("  compile   miss   1.00 s\n  notice    hit    0.00 s\n"),
    );
    try std.testing.expectError(error.ReportWrong, check_others_hit("  compile   hit    0.00 s\n"));
}

test "the graph text is the golden; the graph JSON has three nodes and two edges" {
    // Goal: the golden text is exact; the JSON fixture has the shape of the build_graph golden.
    try check_graph_text(graph_golden);
    try std.testing.expectError(error.GraphWrong, check_graph_text(graph_golden ++ "\n"));
    try std.testing.expectError(error.GraphWrong, check_graph_text(""));
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const good = "{\"schema\":\"zbx.build_graph/1\",\"path\":\"/x\"," ++
        "\"nodes\":[{\"name\":\"compile\"},{\"name\":\"notice\"},{\"name\":\"image\"}]," ++
        "\"edges\":[{\"from\":\"compile\",\"to\":\"image\"}," ++
        "{\"from\":\"notice\",\"to\":\"image\"}]}";
    try check_graph_json(arena, good);
    try std.testing.expectError(error.GraphWrong, check_graph_json(arena, "{}"));
    try std.testing.expectError(error.GraphWrong, check_graph_json(arena, "nope"));
    const one_edge = try std.mem.replaceOwned(
        u8,
        arena,
        good,
        ",{\"from\":\"notice\",\"to\":\"image\"}",
        "",
    );
    try std.testing.expectError(error.GraphWrong, check_graph_json(arena, one_edge));
}

test "reordering must keep every key and the digest" {
    // Goal: equal reports pass; a changed key or digest fails.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const first = try parse_json(arena, json_first);
    try check_reorder(&first, &first);
    var second = first;
    second.rows[0].key = digest_c;
    try std.testing.expectError(error.DigestWrong, check_reorder(&first, &second));
    second = first;
    second.digest = digest_b;
    try std.testing.expectError(error.DigestWrong, check_reorder(&first, &second));
}

test "a program's output is exactly the greeting" {
    // Goal: the greeting with its newline passes; another greeting, a prefix and nothing fail.
    try check_stdout_is("hello from zigbox\n", "hello from zigbox");
    try std.testing.expectError(
        error.ReportWrong,
        check_stdout_is("hello again from zigbox\n", "hello from zigbox"),
    );
    try std.testing.expectError(error.ReportWrong, check_stdout_is("", "hello from zigbox"));
    try std.testing.expectError(
        error.ReportWrong,
        check_stdout_is("x hello from zigbox\n", "hello from zigbox"),
    );
}

const e0805_json = @embedFile("m7_fixtures/E0805.json.txt");
const w0801_json = @embedFile("m7_fixtures/W0801.json.txt");

test "an agent reads the failed step and the grant from the diagnostic" {
    // Goal: the E0805 fixture (the golden of the diagnostics) gives the step, and its fix is
    // prose; a wrong exit, another code or a fix without the grant fail.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const failure = try check_failure_json(arena, e0805_json, 1);
    try std.testing.expectEqualStrings("fetch", failure.step);
    try std.testing.expect(failure.fix_is_prose);
    try std.testing.expectError(error.RefusalWrong, check_failure_json(arena, e0805_json, 0));
    try std.testing.expectError(error.RefusalWrong, check_failure_json(arena, "", 1));
    try std.testing.expectError(error.RefusalWrong, check_failure_json(arena, w0801_json, 1));
    const no_grant = try std.mem.replaceOwned(
        u8,
        arena,
        e0805_json,
        ".network = true",
        ".net = true",
    );
    try std.testing.expectError(error.RefusalWrong, check_failure_json(arena, no_grant, 1));
}

test "the warning about network steps is found by its code" {
    // Goal: W0801 is found among the lines; E0805 alone does not hold it.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try check_has_code(arena, w0801_json, "ZBX-W0801");
    try std.testing.expectError(error.RefusalWrong, check_has_code(arena, e0805_json, "ZBX-W0801"));
    try std.testing.expectError(error.RefusalWrong, check_has_code(arena, "", "ZBX-W0801"));
}

test "counts: zero is clean, some is not zero" {
    // Goal: `0` passes check_zero only; check_some wants a positive number.
    try check_zero("0\n");
    try std.testing.expectError(error.ReportWrong, check_zero("1\n"));
    try std.testing.expectError(error.ReportWrong, check_zero(""));
    try check_some("12\n");
    try std.testing.expectError(error.ReportWrong, check_some("0\n"));
    try std.testing.expectError(error.ReportWrong, check_some("many"));
}

const project_file = @embedFile("m7_project/zbx.build.zon");

test "variants of the project file: a step added, the steps swapped" {
    // Goal: the variants the ACCEPT and step 6 scripts write are the project file with one
    // edit; swapping twice gives the file back.
    var buffer: [4096]u8 = undefined;
    const added = with_step(
        &buffer,
        project_file,
        fetch_step,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(project_file.len + fetch_step.len, added.len);
    try std.testing.expect(std.mem.indexOf(u8, added, "\"fetch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, added, steps_end) != null);
    var small: [64]u8 = undefined;
    try std.testing.expect(with_step(&small, project_file, fetch_step) == null);
    var swapped_buffer: [4096]u8 = undefined;
    const swapped = swap_steps(
        &swapped_buffer,
        project_file,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(project_file.len, swapped.len);
    try std.testing.expect(!std.mem.eql(u8, swapped, project_file));
    try std.testing.expect(
        std.mem.indexOf(u8, swapped, "\"notice\"").? <
            std.mem.indexOf(u8, swapped, "\"compile\"").?,
    );
    var again_buffer: [4096]u8 = undefined;
    // The swapped file has the same markers, so swapping it again restores the original.
    const again = swap_steps(&again_buffer, swapped) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(project_file, again);
}

const ExplainEntry = struct {
    schema: []const u8,
    code: []const u8,
    severity: []const u8,
    blame: []const u8,
    summary: []const u8,
    explanation: []const u8,
    docs: []const u8,
};

/// `zbx explain <code> --output json` agrees with a diagnostic of that code in everything the
/// code fixes: the schema, code, severity, blame and docs. Its summary is the code's own
/// (`summary_catalog`, "a build step failed"), not the instance's (`build step "fetch" failed:
/// exit 1`). The harness is a module of its own and cannot import the catalog, so the caller
/// states the catalog's summary; a drift in the catalog fails the demo here.
pub fn check_explain_entry(
    arena: Allocator,
    stdout: []const u8,
    diagnostic: json.Diagnostic,
    summary_catalog: []const u8,
) !void {
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const doc = std.json.parseFromSliceLeaky(ExplainEntry, arena, stdout, options) catch {
        return error.JsonWrong;
    };
    if (!std.mem.eql(u8, doc.schema, "zbx.explain/1")) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.code, diagnostic.code)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.severity, diagnostic.severity)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.blame, diagnostic.blame)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.docs, diagnostic.docs)) return error.ExplainWrong;
    if (!std.mem.eql(u8, doc.summary, summary_catalog)) return error.ExplainWrong;
    if (doc.explanation.len == 0) return error.ExplainWrong;
}

test "explain agrees with the diagnostic except for the instance's summary" {
    // Goal: the agent's explain check accepts what the VM run printed (the code's generic
    // summary against the instance's) and refuses another code or a missing explanation.
    // Method: the run's explain line against a diagnostic built from the run's own fields.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = "https://zigbox.github.io/zigbox/errors/E0805.html";
    const diagnostic: json.Diagnostic = .{
        .code = "ZBX-E0805",
        .severity = "error",
        .blame = "user",
        .summary = "build step \"fetch\" failed: exit 1",
        .context = .null,
        .fixes = &.{},
        .docs = docs,
    };
    const line = "{\"schema\":\"zbx.explain/1\",\"code\":\"ZBX-E0805\",\"severity\":\"error\"," ++
        "\"blame\":\"user\",\"summary\":\"a build step failed\",\"explanation\":\"A step.\"," ++
        "\"docs\":\"" ++ docs ++ "\"}\n";
    const summary = "a build step failed";
    try check_explain_entry(arena, line, diagnostic, summary);
    const other = try std.mem.replaceOwned(u8, arena, line, "E0805\",\"sev", "E0806\",\"sev");
    const wrong = check_explain_entry(arena, other, diagnostic, summary);
    try std.testing.expectError(error.ExplainWrong, wrong);
    const bare = try std.mem.replaceOwned(u8, arena, line, "A step.", "");
    const empty = check_explain_entry(arena, bare, diagnostic, summary);
    try std.testing.expectError(error.ExplainWrong, empty);
    const instance = check_explain_entry(arena, line, diagnostic, diagnostic.summary);
    try std.testing.expectError(error.ExplainWrong, instance);
}
