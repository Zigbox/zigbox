//! The release evidence table: what the release commit's CI runs did, rendered from the GitHub
//! Actions API's own answers, never typed (docs/releases/automation.md, "The evidence table").
//! Build-host tool, run by the release workflow's `draft` job with `zig run`:
//!
//!   release_evidence --product <owner/repo>@<sha> [--dependency <owner/repo>@<sha>]
//!       --gate <workflow> <runs.json> <jobs.json> [--gate ...]
//!       [--current <workflow> <run.json> <jobs.json> <job,job...>]
//!
//! `runs.json` is `GET /repos/{repo}/actions/workflows/{workflow}.yml/runs?head_sha=&event=push`
//! and `jobs.json` is `GET /repos/{repo}/actions/runs/{id}/jobs?per_page=100` for the newest of
//! those runs; the workflow fetches both with `gh api`, its token in the environment. This file
//! never touches the network, so a test feeds it recorded responses (`release_evidence/`).
//!
//! Every job gets one of three labels, and anything else refuses the table (exit 1, one line):
//!
//! - **passed**: the job succeeded and every one of its steps succeeded.
//! - **expected failure observed**: the job succeeded, a step failed, and the workflow accepted
//!   that (`continue-on-error`), so GitHub still counts the job as a success.
//! - **skipped**: the job was skipped, or it succeeded with a step that did not run. 0.5.3's
//!   demo-m6d was green with its demo step skipped (no Google setup); that is "skipped", never
//!   "passed". A skipped step outranks a failed one: the gate did not run in full.
//!
//! A run that is not a completed success, a job that failed or was cancelled, a step that was
//! cancelled, or a job listing that is not the newest run's, or not the product's commit, refuses.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Label = enum {
    passed,
    expected_failure_observed,
    skipped,

    pub fn text(label: Label) []const u8 {
        return switch (label) {
            .passed => "passed",
            .expected_failure_observed => "expected failure observed",
            .skipped => "skipped",
        };
    }
};

pub const Counts = struct {
    passed: u32 = 0,
    expected_failure_observed: u32 = 0,
    skipped: u32 = 0,

    fn add(counts: *Counts, label: Label) void {
        const before = counts.total();
        switch (label) {
            .passed => counts.passed += 1,
            .expected_failure_observed => counts.expected_failure_observed += 1,
            .skipped => counts.skipped += 1,
        }
        assert(counts.total() == before + 1);
    }

    pub fn total(counts: *const Counts) u32 {
        return counts.passed + counts.expected_failure_observed + counts.skipped;
    }
};

/// The one line a refusal prints, after `release-evidence: refused: `.
pub const Diagnostic = struct {
    buffer: [512]u8 = undefined,
    text: []const u8 = "",

    fn set(
        diagnostic: *Diagnostic,
        comptime format: []const u8,
        arguments: anytype,
    ) error{Refused} {
        diagnostic.text = std.fmt.bufPrint(&diagnostic.buffer, format, arguments) catch
            diagnostic.buffer[0..]; // A name too long to fit is cut, not lost: the start is there.
        assert(diagnostic.text.len > 0);
        assert(diagnostic.text.len <= diagnostic.buffer.len);
        return error.Refused;
    }
};

pub const Error = error{ Refused, WriteFailed };

// The API's JSON, reduced to the members this table reads. Unknown members are ignored, so the
// full responses and the trimmed fixtures parse alike.
const Step = struct { name: []const u8, conclusion: ?[]const u8 = null };
const Job = struct {
    name: []const u8,
    status: []const u8,
    conclusion: ?[]const u8 = null,
    html_url: []const u8,
    head_sha: []const u8,
    run_id: u64,
    steps: []const Step = &.{},
};
const Jobs = struct { total_count: u32, jobs: []const Job };
const Run = struct {
    id: u64,
    head_sha: []const u8,
    status: []const u8,
    conclusion: ?[]const u8 = null,
    html_url: []const u8,
    created_at: []const u8,
    run_attempt: u32 = 1,
};
const Runs = struct { total_count: u32, workflow_runs: []const Run };

const json_options: std.json.ParseOptions = .{
    .ignore_unknown_fields = true,
    .max_value_len = constants.release_evidence_input_bytes_max,
};

/// The parsed responses of one gate live here, and are dropped before the next gate's.
var parse_buffer: [constants.release_evidence_parse_bytes_max]u8 = undefined;

pub fn write_header(out: *std.Io.Writer, product: []const u8, dependency: ?[]const u8) Error!void {
    assert(product.len > 0);
    if (dependency) |name| assert(name.len > 0);
    try out.writeAll("## CI evidence\n\n");
    try out.writeAll("Rendered by the release workflow from the GitHub Actions API: the " ++
        "conclusion of every job, and of every step in it, of the release commit's runs. " ++
        "Nothing here is typed (docs/releases/automation.md).\n\n");
    try out.print("- Product: `{s}`\n", .{product});
    try out.print("- Dependency: {s}{s}{s}\n\n", .{
        if (dependency == null) "none" else "`",
        dependency orelse "",
        if (dependency == null) "" else "`",
    });
    try out.writeAll("| Workflow | Job | Result | Steps not run, or failed as expected |\n");
    try out.writeAll("| --- | --- | --- | --- |\n");
}

pub fn write_footer(out: *std.Io.Writer, counts: *const Counts) Error!void {
    assert(counts.total() > 0);
    assert(counts.total() <= constants.release_evidence_gates_max *
        constants.release_evidence_jobs_max);
    try out.print("\n{d} jobs: {d} passed, {d} expected failure observed, {d} skipped.\n", .{
        counts.total(), counts.passed, counts.expected_failure_observed, counts.skipped,
    });
}

/// One gate: the newest run of `workflow` at `product_sha`, and every job of it, as table rows.
pub fn render_gate(
    out: *std.Io.Writer,
    gate: *const Gate,
    counts: *Counts,
    diagnostic: *Diagnostic,
) Error!void {
    assert(gate.workflow.len > 0);
    assert(gate.product_sha.len > 0);
    var fixed: std.heap.FixedBufferAllocator = .init(&parse_buffer);
    const allocator = fixed.allocator();
    const run: Run = if (gate.jobs_named == null) newest: {
        const text = gate.runs_text;
        const runs = std.json.parseFromSliceLeaky(Runs, allocator, text, json_options) catch
            return diagnostic.set("{s}: the runs listing is not the API's JSON", .{gate.workflow});
        break :newest try newest_run(&runs, gate, diagnostic);
    } else std.json.parseFromSliceLeaky(Run, allocator, gate.runs_text, json_options) catch
        return diagnostic.set("{s}: the run is not the API's JSON", .{gate.workflow});
    const jobs = std.json.parseFromSliceLeaky(Jobs, allocator, gate.jobs_text, json_options) catch
        return diagnostic.set("{s}: the job listing is not the API's JSON", .{gate.workflow});
    try check_jobs(&jobs, &run, gate, diagnostic);
    try write_rows(out, gate, &run, &jobs, counts, diagnostic);
}

/// Every job, or with `jobs_named` those jobs alone, by name, so the table reads the same however
/// the API orders them.
fn write_rows(
    out: *std.Io.Writer,
    gate: *const Gate,
    run: *const Run,
    jobs: *const Jobs,
    counts: *Counts,
    diagnostic: *Diagnostic,
) Error!void {
    assert(jobs.jobs.len <= constants.release_evidence_jobs_max);
    var order: [constants.release_evidence_jobs_max]u32 = undefined;
    for (order[0..jobs.jobs.len], 0..) |*slot, index| slot.* = @intCast(index);
    std.mem.sort(u32, order[0..jobs.jobs.len], jobs.jobs, job_before);
    const before = counts.total();
    var written: u32 = 0;
    for (order[0..jobs.jobs.len]) |index| {
        const job = &jobs.jobs[index];
        if (gate.jobs_named) |names| {
            if (!named(names, job.name)) continue;
            if (!std.mem.eql(u8, job.status, "completed")) {
                return diagnostic.set("{s}: job '{s}' is {s}, not completed", .{
                    gate.workflow, job.name, job.status,
                });
            }
        }
        const label = try classify(job, gate.workflow, diagnostic);
        counts.add(label);
        try write_row(out, gate.workflow, run, job, label);
        written += 1;
    }
    if (gate.jobs_named) |names| {
        const wanted: u32 = @intCast(std.mem.count(u8, names, ",") + 1);
        if (written != wanted) {
            return diagnostic.set("{s}: {d} of the {d} named jobs are in run {d}", .{
                gate.workflow, written, wanted, run.id,
            });
        }
    }
    assert(counts.total() == before + written);
}

fn named(names: []const u8, name: []const u8) bool {
    assert(names.len > 0);
    var iterator = std.mem.splitScalar(u8, names, ',');
    while (iterator.next()) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

pub const Gate = struct {
    workflow: []const u8,
    product_sha: []const u8,
    runs_text: []const u8,
    jobs_text: []const u8,
    /// Null: the gate is every job of the newest run of `workflow` at the product, which must be
    /// a completed success (`ci`). Otherwise the gate is the release run itself, still running
    /// when the table is drawn: `runs_text` is that one run (`GET .../runs/{id}`), and only these
    /// jobs, by name and comma-separated, each completed, are its evidence (the jobs `draft`
    /// needs). Its commit is the workflow's, so it is not compared with the product's.
    jobs_named: ?[]const u8 = null,
};

fn job_before(jobs: []const Job, left: u32, right: u32) bool {
    assert(left < jobs.len);
    assert(right < jobs.len);
    return std.mem.order(u8, jobs[left].name, jobs[right].name) == .lt;
}

/// The run the release gate reads, as `plan` does: the newest by creation time. It must be the
/// product's commit and a completed success.
fn newest_run(runs: *const Runs, gate: *const Gate, diagnostic: *Diagnostic) Error!Run {
    if (runs.workflow_runs.len == 0) {
        return diagnostic.set("{s}: no run at {s}", .{ gate.workflow, gate.product_sha });
    }
    if (runs.total_count != runs.workflow_runs.len) {
        return diagnostic.set("{s}: the runs listing holds {d} of {d} runs", .{
            gate.workflow, runs.workflow_runs.len, runs.total_count,
        });
    }
    var newest = &runs.workflow_runs[0];
    for (runs.workflow_runs[1..]) |*run| {
        if (std.mem.order(u8, run.created_at, newest.created_at) == .gt) newest = run;
    }
    if (!std.mem.eql(u8, newest.head_sha, gate.product_sha)) {
        return diagnostic.set("{s}: run {d} is of {s}, not the product {s}", .{
            gate.workflow, newest.id, newest.head_sha, gate.product_sha,
        });
    }
    if (!std.mem.eql(u8, newest.status, "completed")) {
        return diagnostic.set("{s}: run {d} is {s}, not completed", .{
            gate.workflow, newest.id, newest.status,
        });
    }
    if (!std.mem.eql(u8, newest.conclusion orelse "none", "success")) {
        return diagnostic.set("{s}: run {d} ended {s}, not success", .{
            gate.workflow, newest.id, newest.conclusion orelse "none",
        });
    }
    assert(newest.id > 0);
    return newest.*;
}

/// The job listing is the whole of the run's, at the run's commit (for `ci`, the product's: the
/// pair of `newest_run`'s check).
fn check_jobs(
    jobs: *const Jobs,
    run: *const Run,
    gate: *const Gate,
    diagnostic: *Diagnostic,
) Error!void {
    assert(run.id > 0);
    if (jobs.jobs.len == 0) {
        return diagnostic.set("{s}: run {d} has no jobs", .{ gate.workflow, run.id });
    }
    if (jobs.jobs.len > constants.release_evidence_jobs_max) {
        return diagnostic.set("{s}: run {d} has {d} jobs, above {d}", .{
            gate.workflow, run.id, jobs.jobs.len, constants.release_evidence_jobs_max,
        });
    }
    if (jobs.total_count != jobs.jobs.len) {
        return diagnostic.set("{s}: the job listing holds {d} of {d} jobs", .{
            gate.workflow, jobs.jobs.len, jobs.total_count,
        });
    }
    for (jobs.jobs) |*job| {
        if (job.run_id != run.id) {
            return diagnostic.set("{s}: job '{s}' is of run {d}, not {d}", .{
                gate.workflow, job.name, job.run_id, run.id,
            });
        }
        if (!std.mem.eql(u8, job.head_sha, run.head_sha)) {
            return diagnostic.set("{s}: job '{s}' is of {s}, not the run's {s}", .{
                gate.workflow, job.name, job.head_sha, run.head_sha,
            });
        }
    }
    assert(jobs.jobs.len <= constants.release_evidence_jobs_max);
}

/// A job's own housekeeping, not a gate: the runner's set-up and tear-down, and the clean-up an
/// action registers (`Post <step>`), which is skipped whenever its step is.
fn housekeeping(step: *const Step) bool {
    if (std.mem.eql(u8, step.name, "Set up job")) return true;
    if (std.mem.eql(u8, step.name, "Complete job")) return true;
    return std.mem.startsWith(u8, step.name, "Post ");
}

pub fn classify(job: *const Job, workflow: []const u8, diagnostic: *Diagnostic) Error!Label {
    assert(workflow.len > 0);
    const conclusion = job.conclusion orelse "none";
    if (std.mem.eql(u8, conclusion, "skipped")) return .skipped;
    if (!std.mem.eql(u8, conclusion, "success")) {
        return diagnostic.set("{s}: job '{s}' ended {s}", .{ workflow, job.name, conclusion });
    }
    if (job.steps.len > constants.release_evidence_steps_max) {
        return diagnostic.set("{s}: job '{s}' has {d} steps, above {d}", .{
            workflow, job.name, job.steps.len, constants.release_evidence_steps_max,
        });
    }
    var skipped: u32 = 0;
    var failed: u32 = 0;
    for (job.steps) |*step| {
        if (housekeeping(step)) continue;
        const outcome = step.conclusion orelse "none";
        if (std.mem.eql(u8, outcome, "success")) continue;
        if (std.mem.eql(u8, outcome, "skipped")) {
            skipped += 1;
        } else if (std.mem.eql(u8, outcome, "failure")) {
            failed += 1;
        } else {
            return diagnostic.set("{s}: job '{s}', step '{s}' ended {s}", .{
                workflow, job.name, step.name, outcome,
            });
        }
    }
    assert(skipped + failed <= job.steps.len);
    if (skipped > 0) return .skipped;
    if (failed > 0) return .expected_failure_observed;
    return .passed;
}

fn write_row(
    out: *std.Io.Writer,
    workflow: []const u8,
    run: *const Run,
    job: *const Job,
    label: Label,
) Error!void {
    assert(workflow.len > 0);
    assert(job.html_url.len > 0);
    try out.writeAll("| [");
    try write_cell(out, workflow);
    try out.print("]({s}) attempt {d} | [", .{ run.html_url, run.run_attempt });
    try write_cell(out, job.name);
    try out.print("]({s}) | {s} | ", .{ job.html_url, label.text() });
    var listed: u32 = 0;
    for (job.steps) |*step| {
        if (housekeeping(step)) continue;
        const outcome = step.conclusion orelse "none";
        if (std.mem.eql(u8, outcome, "success")) continue;
        if (listed > 0) try out.writeAll("; ");
        try write_cell(out, step.name);
        try out.print(" ({s})", .{outcome});
        listed += 1;
    }
    if (label == .passed) assert(listed == 0);
    try out.writeAll(" |\n");
}

/// A table cell holds no line break and no unescaped `|`.
fn write_cell(out: *std.Io.Writer, cell: []const u8) Error!void {
    for (cell) |byte| {
        switch (byte) {
            '|' => try out.writeAll("\\|"),
            '\n', '\r' => try out.writeByte(' '),
            else => try out.writeByte(byte),
        }
    }
}

// The command line.

const Arguments = struct {
    product: []const u8 = "",
    dependency: ?[]const u8 = null,
    gates: [constants.release_evidence_gates_max]GatePaths = undefined,
    gates_count: u32 = 0,
};

const GatePaths = struct {
    workflow: []const u8,
    runs_path: []const u8,
    jobs_path: []const u8,
    jobs_named: ?[]const u8 = null,
};

var runs_buffer: [constants.release_evidence_input_bytes_max]u8 = undefined;
var jobs_buffer: [constants.release_evidence_input_bytes_max]u8 = undefined;
var output_buffer: [constants.release_evidence_output_bytes_max]u8 = undefined;

pub fn main(init: std.process.Init) !u8 {
    var error_buffer: [1024]u8 = undefined;
    var error_writer: std.Io.File.Writer = .init(.stderr(), init.io, &error_buffer);
    const errors = &error_writer.interface;
    var arguments: Arguments = .{};
    parse_arguments(init, &arguments) catch {
        try errors.writeAll("usage: release_evidence --product <repo>@<sha> " ++
            "[--dependency <repo>@<sha>] --gate <workflow> <runs.json> <jobs.json>... " ++
            "[--current <workflow> <run.json> <jobs.json> <job,job...>]\n");
        try errors.flush();
        return constants.tool_exit_usage;
    };
    assert(arguments.gates_count > 0);
    var out: std.Io.Writer = .fixed(&output_buffer);
    var diagnostic: Diagnostic = .{};
    render_all(init.io, &out, &arguments, &diagnostic) catch |err| switch (err) {
        error.Refused => {
            try errors.print("release-evidence: refused: {s}\n", .{diagnostic.text});
            try errors.flush();
            return constants.tool_exit_failed;
        },
        error.WriteFailed => {
            try errors.writeAll("release-evidence: refused: the table is larger than its " ++
                "buffer (release_evidence_output_bytes_max)\n");
            try errors.flush();
            return constants.tool_exit_failed;
        },
    };
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), init.io, &.{});
    try stdout_writer.interface.writeAll(out.buffered());
    try stdout_writer.interface.flush();
    return constants.tool_exit_ok;
}

fn render_all(
    io: std.Io,
    out: *std.Io.Writer,
    arguments: *const Arguments,
    diagnostic: *Diagnostic,
) Error!void {
    assert(arguments.gates_count > 0);
    const product_sha = commit_of(arguments.product);
    try write_header(out, arguments.product, arguments.dependency);
    var counts: Counts = .{};
    for (arguments.gates[0..arguments.gates_count]) |*paths| {
        const runs_text = read(io, paths.runs_path, &runs_buffer, diagnostic) catch
            return error.Refused;
        const jobs_text = read(io, paths.jobs_path, &jobs_buffer, diagnostic) catch
            return error.Refused;
        const gate: Gate = .{
            .workflow = paths.workflow,
            .product_sha = product_sha,
            .runs_text = runs_text,
            .jobs_text = jobs_text,
            .jobs_named = paths.jobs_named,
        };
        try render_gate(out, &gate, &counts, diagnostic);
    }
    try write_footer(out, &counts);
    assert(counts.total() > 0);
}

/// `owner/repo@sha` names a commit; the runs are checked against the part after the `@`.
fn commit_of(name: []const u8) []const u8 {
    const at = std.mem.lastIndexOfScalar(u8, name, '@').?; // parse_arguments checked it is there.
    assert(at + 1 < name.len);
    return name[at + 1 ..];
}

fn read(io: std.Io, path: []const u8, buffer: []u8, diagnostic: *Diagnostic) error{Refused}![]u8 {
    assert(path.len > 0);
    const text = std.Io.Dir.cwd().readFile(io, path, buffer) catch |err|
        return diagnostic.set("cannot read {s} ({s})", .{ path, @errorName(err) });
    if (text.len == buffer.len) {
        return diagnostic.set("{s} is larger than {d} bytes", .{ path, buffer.len });
    }
    return text;
}

fn parse_arguments(init: std.process.Init, arguments: *Arguments) error{Usage}!void {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |argument| {
        if (std.mem.eql(u8, argument, "--product")) {
            arguments.product = try commit_name(iterator.next());
        } else if (std.mem.eql(u8, argument, "--dependency")) {
            arguments.dependency = try commit_name(iterator.next());
        } else if (std.mem.eql(u8, argument, "--gate")) {
            if (arguments.gates_count == arguments.gates.len) return error.Usage;
            arguments.gates[arguments.gates_count] = .{
                .workflow = iterator.next() orelse return error.Usage,
                .runs_path = iterator.next() orelse return error.Usage,
                .jobs_path = iterator.next() orelse return error.Usage,
            };
            arguments.gates_count += 1;
        } else if (std.mem.eql(u8, argument, "--current")) {
            if (arguments.gates_count == arguments.gates.len) return error.Usage;
            arguments.gates[arguments.gates_count] = .{
                .workflow = iterator.next() orelse return error.Usage,
                .runs_path = iterator.next() orelse return error.Usage,
                .jobs_path = iterator.next() orelse return error.Usage,
                .jobs_named = iterator.next() orelse return error.Usage,
            };
            if (arguments.gates[arguments.gates_count].jobs_named.?.len == 0) return error.Usage;
            arguments.gates_count += 1;
        } else {
            return error.Usage;
        }
    }
    if (arguments.product.len == 0) return error.Usage;
    if (arguments.gates_count == 0) return error.Usage;
    assert(arguments.gates_count <= arguments.gates.len);
}

fn commit_name(argument: ?[]const u8) error{Usage}![]const u8 {
    const name = argument orelse return error.Usage;
    const at = std.mem.lastIndexOfScalar(u8, name, '@') orelse return error.Usage;
    if (at == 0) return error.Usage;
    if (at + 1 == name.len) return error.Usage;
    assert(name.len > 2);
    return name;
}

// Tests.

const testing = std.testing;
const fixture_ci_runs = @embedFile("release_evidence/0.5.3-ci-runs.json");
const fixture_ci_jobs = @embedFile("release_evidence/0.5.3-ci-jobs.json");
const fixture_release_run = @embedFile("release_evidence/0.5.3-release-run.json");
const fixture_release_jobs = @embedFile("release_evidence/0.5.3-release-jobs.json");
const release_jobs_named = "plan the release,macOS gates (hosted)," ++
    "the tap and the site are reachable";
const fixture_table = @embedFile("release_evidence/0.5.3-table.md");
const sha_0_5_3 = "87498d04ea854cfbe7114699556a43866a0fcbc4";

fn render_test(out: *std.Io.Writer, gates: []const Gate, diagnostic: *Diagnostic) Error!void {
    try write_header(out, "Zigbox/zigbox@" ++ sha_0_5_3, null);
    var counts: Counts = .{};
    for (gates) |*gate| try render_gate(out, gate, &counts, diagnostic);
    try write_footer(out, &counts);
}

test "0.5.3's recorded runs render the checked-in table, demo-m6d skipped" {
    // Goal: the API's recorded answers for 0.5.3's release commit (ci, and the release run's own
    // jobs `draft` needs; fetched once with `gh api` and trimmed) render exactly the checked-in
    // table, and demo-m6d, green with its demo step skipped, reads "skipped", not "passed".
    // Method: render and compare bytes.
    var buffer: [64 * 1024]u8 = undefined;
    @memset(&buffer, 0xaa);
    var out: std.Io.Writer = .fixed(&buffer);
    var diagnostic: Diagnostic = .{};
    try render_test(&out, &.{
        gate_of("ci", sha_0_5_3, fixture_ci_runs, fixture_ci_jobs),
        release_gate(release_jobs_named),
    }, &diagnostic);
    try testing.expectEqualStrings(fixture_table, out.buffered());
    const m6d_row = "| [ci](https://github.com/Zigbox/zigbox/actions/runs/44198012387) " ++
        "attempt 2 | " ++
        "[demo-m6d (Ubuntu 24.04 VM, KVM, Artifact Registry and gcr.io through WIF)]" ++
        "(https://github.com/Zigbox/zigbox/actions/runs/44198012387/job/134468367728) | skipped |";
    try testing.expect(std.mem.indexOf(u8, out.buffered(), m6d_row) != null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "| demo-m6d") == null);
}

test "a run of another commit, a failed run and a short job listing refuse" {
    // Goal: the table is refused, never rendered, when the evidence is not the product's or not
    // whole. Method: the recorded 0.5.3 responses against another commit, and edited copies.
    var buffer: [64 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var diagnostic: Diagnostic = .{};
    const other = "f8209996e8c96121fa1f9b91d94ed4d6344a3dea";
    var counts: Counts = .{};
    const wrong_commit = gate_of("ci", other, fixture_ci_runs, fixture_ci_jobs);
    try testing.expectError(error.Refused, render_gate(&out, &wrong_commit, &counts, &diagnostic));
    try testing.expect(std.mem.indexOf(u8, diagnostic.text, "not the product") != null);

    const failed_runs = try replace_once(fixture_ci_runs, "\"success\"", "\"failure\"");
    defer testing.allocator.free(failed_runs);
    const failed_run = gate_of("ci", sha_0_5_3, failed_runs, fixture_ci_jobs);
    try testing.expectError(error.Refused, render_gate(&out, &failed_run, &counts, &diagnostic));
    const failed_text = "ci: run 44198012387 ended failure, not success";
    try testing.expectEqualStrings(failed_text, diagnostic.text);

    const count_27 = "\"total_count\": 27";
    const short_jobs = try replace_once(fixture_ci_jobs, "\"total_count\": 26", count_27);
    defer testing.allocator.free(short_jobs);
    const short = gate_of("ci", sha_0_5_3, fixture_ci_runs, short_jobs);
    try testing.expectError(error.Refused, render_gate(&out, &short, &counts, &diagnostic));
    try testing.expectEqualStrings("ci: the job listing holds 26 of 27 jobs", diagnostic.text);
    try testing.expectEqual(@as(u32, 0), counts.total());
}

fn replace_once(text: []const u8, old: []const u8, new: []const u8) ![]u8 {
    const at = std.mem.indexOf(u8, text, old).?; // The fixture holds it; a test that misses fails.
    return std.mem.concat(testing.allocator, u8, &.{ text[0..at], new, text[at + old.len ..] });
}

fn release_gate(names: []const u8) Gate {
    var gate = gate_of("release", sha_0_5_3, fixture_release_run, fixture_release_jobs);
    gate.jobs_named = names;
    return gate;
}

test "the release run's named jobs: each must be there and completed" {
    // Goal: a named job missing from the release run, or still running, refuses. Method: the
    // recorded release run with a name it lacks, and with a named job edited to in_progress.
    var buffer: [16 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var diagnostic: Diagnostic = .{};
    var counts: Counts = .{};
    const missing = release_gate("plan the release,no such job");
    try testing.expectError(error.Refused, render_gate(&out, &missing, &counts, &diagnostic));
    try testing.expectEqualStrings(
        "release: 1 of the 2 named jobs are in run 44205899240",
        diagnostic.text,
    );
    const running_jobs = try replace_once(
        fixture_release_jobs,
        "\"status\": \"completed\"",
        "\"status\": \"in_progress\"",
    );
    defer testing.allocator.free(running_jobs);
    var running = release_gate("plan the release");
    running.jobs_text = running_jobs;
    try testing.expectError(error.Refused, render_gate(&out, &running, &counts, &diagnostic));
    const running_text = "release: job 'plan the release' is in_progress, not completed";
    try testing.expectEqualStrings(running_text, diagnostic.text);
}

fn gate_of(workflow: []const u8, sha: []const u8, runs: []const u8, jobs: []const u8) Gate {
    return .{ .workflow = workflow, .product_sha = sha, .runs_text = runs, .jobs_text = jobs };
}

test "each label at its boundary, and the outcomes that refuse" {
    // Goal: the three labels and the refusals, one case each, including a skipped step beating a
    // failed one and housekeeping steps not counting. Method: classify hand-built jobs; these
    // are synthetic (no recorded run had a continue-on-error failure), and say so.
    var diagnostic: Diagnostic = .{};
    const ok: Step = .{ .name = "Run the demo", .conclusion = "success" };
    const skip: Step = .{ .name = "Run the demo", .conclusion = "skipped" };
    const fail: Step = .{ .name = "Probe", .conclusion = "failure" };
    const post_skipped: Step = .{ .name = "Post Cache the VM base image", .conclusion = "skipped" };
    const cancelled: Step = .{ .name = "Run the demo", .conclusion = "cancelled" };
    const base: Job = .{
        .name = "j",
        .status = "completed",
        .conclusion = "success",
        .html_url = "u",
        .head_sha = "s",
        .run_id = 1,
    };
    const cases = [_]struct { steps: []const Step, conclusion: []const u8, label: ?Label }{
        .{ .steps = &.{ ok, post_skipped }, .conclusion = "success", .label = .passed },
        .{ .steps = &.{ ok, fail }, .conclusion = "success", .label = .expected_failure_observed },
        .{ .steps = &.{ fail, skip }, .conclusion = "success", .label = .skipped },
        .{ .steps = &.{}, .conclusion = "skipped", .label = .skipped },
        .{ .steps = &.{ ok, fail }, .conclusion = "failure", .label = null },
        .{ .steps = &.{ok}, .conclusion = "cancelled", .label = null },
        .{ .steps = &.{ ok, cancelled }, .conclusion = "success", .label = null },
    };
    for (cases) |case| {
        var job = base;
        job.steps = case.steps;
        job.conclusion = case.conclusion;
        if (case.label) |label| {
            try testing.expectEqual(label, try classify(&job, "ci", &diagnostic));
        } else {
            try testing.expectError(error.Refused, classify(&job, "ci", &diagnostic));
        }
    }
}

test "a cell escapes the table's separator" {
    // Goal: a job name with `|` or a newline cannot break the row. Method: render one cell.
    var buffer: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try write_cell(&out, "a|b\nc");
    try testing.expectEqualStrings("a\\|b c", out.buffered());
}
