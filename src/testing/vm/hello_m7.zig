//! The six steps of the M7 demo (docs/briefs/M7-build.md, "Demo"), on the Go hello-world in
//! `m7_project/`. Steps 1 to 4 run in the first VM (`step_first`), steps 5 and 6 in a second,
//! clean one (`step_second`), where the store holds nothing the first built.
//!
//!   1. The first build: three misses, `compile` and `notice` overlapping, `zbx run` prints
//!      the greeting, `zbx inspect` shows the tree and the config.
//!   2. The second build: three hits, the same digest, under a second.
//!   3. An edit of README.md (no input of any step): three hits, the same digest.
//!   4. The greeting changed: `compile` and `image` miss, `notice` hits, a new digest that
//!      prints the new greeting; restored, the first digest again, three hits.
//!   5. (Second VM) the same build gives step 1's digest, and the golden of `m7_expected.zon`.
//!   6. (Second VM) a `fetch` step without network: exit 1, E0805, the grant named.
//!
//! Every assertion is a function of checks_m7.zig with a unit test; this file runs the commands.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;

pub const project_dir = "/home/demo/hello";
/// `zbx` as the demo user in the hello project directory.
pub const zh = H.as_demo ++ "/home/demo/zh";
pub const build_file_text = @embedFile("m7_project/zbx.build.zon");
const golden = @embedFile("m7_expected.zon");
const greeting = "hello from zigbox";
const greeting_again = "hello again from zigbox";
/// A first build pulls two images (golang is large) and compiles; a long timeout, in seconds.
const build_timeout_s: u32 = 1800;
const short_s: u32 = 120;

const project_files = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "zbx.build.zon", .text = build_file_text },
    .{ .name = "zbx.lock", .text = @embedFile("m7_project/zbx.lock") },
    .{ .name = "go.mod", .text = @embedFile("m7_project/go.mod") },
    .{ .name = "main.go", .text = @embedFile("m7_project/main.go") },
    .{ .name = "VERSION", .text = @embedFile("m7_project/VERSION") },
    .{ .name = "LICENSE", .text = @embedFile("m7_project/LICENSE") },
    .{ .name = "README.md", .text = @embedFile("m7_project/README.md") },
};

/// The result digest of step 1, kept for the second VM. A fixed buffer: no allocation.
var first_storage: [67]u8 = undefined;
var first_length: usize = 0;

pub fn first_digest() []const u8 {
    return first_storage[0..first_length];
}

fn remember_first(digest: []const u8) void {
    std.debug.assert(checks.is_digest(digest));
    @memcpy(first_storage[0..digest.len], digest);
    first_length = digest.len;
}

/// Writes `text` to `path` in the guest, as a file of the demo user (mode 644).
pub fn put_text(session: *Session, path: []const u8, text: []const u8) !void {
    try H.put_file(session, path, text);
    const fix = try common.format(session, "chown demo:demo {s} && chmod 644 {s}", .{ path, path });
    const done = try session.run(fix, short_s);
    if (done.status != 0) return error.PrepareFailed;
}

/// The wrapper `name` (a path in the guest) that runs `zbx` in `directory`: `z` with its `cd`
/// changed, so it keeps the mirror and the CA that `common.write_wrappers` gave `z`.
pub fn make_wrapper(session: *Session, directory: []const u8, name: []const u8) !void {
    const command = try common.format(
        session,
        "sed 's#cd {s} #cd {s} #' /home/demo/z > {s} && chown demo:demo {s} && chmod 755 {s} " ++
            "&& grep -c 'cd {s} ' {s}",
        .{ common.project, directory, name, name, name, directory, name },
    );
    const done = try session.run(command, short_s);
    if (done.status != 0) return error.PrepareFailed;
}

/// Makes the project directory with its files and the `zh` wrapper.
pub fn install_project(session: *Session, out: *Io.Writer) !void {
    const made = "mkdir -p " ++ project_dir ++ " && chown demo:demo " ++ project_dir;
    _ = try common.expect_exit(session, out, "HELLO7", made, 0);
    inline for (project_files) |file| {
        try put_text(session, project_dir ++ "/" ++ file.name, file.text);
    }
    try make_wrapper(session, project_dir, "/home/demo/zh");
    _ = try common.expect_exit(session, out, "HELLO7", "ls -l " ++ project_dir, 0);
}

const build_json = zh ++ " build --output json";
const build_text = zh ++ " build";

fn run_text(session: *Session, out: *Io.Writer, command: []const u8) !H.SplitResult {
    return state.expect_long_split(session, out, command, 0, build_timeout_s);
}

/// A JSON build that succeeded, as the report the brief describes.
pub fn json_report(session: *Session, out: *Io.Writer, step: []const u8) !checks.Report {
    const result = try run_text(session, out, build_json);
    return checks.parse_json(session.scratch_allocator(), result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the JSON build report", err);
    };
}

/// A text build that succeeded.
pub fn text_report(session: *Session, out: *Io.Writer, step: []const u8) !checks.Report {
    const result = try run_text(session, out, build_text);
    return checks.parse_text(result.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the text build report", err);
    };
}

/// `zbx run <digest>` prints `want`.
pub fn expect_greeting(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    digest: []const u8,
    want: []const u8,
) !void {
    const command = try common.format(session, "{s} run {s}", .{ zh, digest });
    const ran = try state.expect_long_split(session, out, command, 0, short_s);
    checks.check_stdout_is(ran.streams.stdout, want) catch |err| {
        return fail_step(out, step, "expected the image to print its greeting", err);
    };
}

const step1 = "HELLO7 1";
const step2 = "HELLO7 2";
const step3 = "HELLO7 3";
const step4 = "HELLO7 4";

const debug_command = "sh -c 'apt-get install -y strace >/dev/null 2>&1; " ++
    "strace -f -o /tmp/s.log " ++ zh ++ " pull " ++
    "docker.io/library/golang@sha256:a7ecaac5efda22510d8c903bdc6b19026543f1eac3317d47363680df22161bd8" ++
    " 2>&1 | tail -3; grep -B3 EPERM /tmp/s.log | cut -c1-200 | head -20; which strace'";

fn debug_pull(session: *Session, out: *Io.Writer) !void {
    _ = try common.run_shown(session, out, debug_command);
}

pub fn step_first(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print(
        "\n{s}: HELLO7: the brief's steps 1 to 4, on the Go hello-world\n",
        .{H.demo_name},
    );
    try install_project(session, out);
    try debug_pull(session, out);
    try first_build(session, out);
    try second_build(session, out);
    try readme_edit(session, out);
    try greeting_change(session, out);
    try timer.lap(out, "hello7");
}

fn first_build(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: the first build: three misses, two steps in parallel\n", .{
        H.demo_name, step1,
    });
    const report = try json_report(session, out, step1);
    checks.check_first_build(&report) catch |err| {
        return fail_step(out, step1, "expected three misses and overlapping steps", err);
    };
    remember_first(report.digest);
    try expect_greeting(session, out, step1, report.digest, greeting);
    const inspect = try common.format(
        session,
        "{s} inspect {s} --output json",
        .{ zh, report.digest },
    );
    const shown = try state.expect_long_split(session, out, inspect, 0, short_s);
    checks.check_inspect(shown.streams.stdout, report.digest) catch |err| {
        return fail_step(out, step1, "expected inspect to show the tree and the config", err);
    };
}

fn second_build(session: *Session, out: *Io.Writer) !void {
    try out.print(
        "\n{s}: {s}: the second build: all hits, under a second\n",
        .{ H.demo_name, step2 },
    );
    const report = try json_report(session, out, step2);
    checks.check_all_hits(&report) catch |err| {
        return fail_step(out, step2, "expected three hits", err);
    };
    checks.check_fast(&report) catch |err| {
        return fail_step(out, step2, "expected a build under a second", err);
    };
    checks.check_digest_equal(first_digest(), report.digest) catch |err| {
        return fail_step(out, step2, "expected the digest of the first build", err);
    };
    const text = try text_report(session, out, step2);
    checks.check_all_hits(&text) catch |err| {
        return fail_step(out, step2, "expected the text to say 3 hits, 0 misses", err);
    };
}

fn readme_edit(session: *Session, out: *Io.Writer) !void {
    try out.print(
        "\n{s}: {s}: README.md is no step's input: still all hits\n",
        .{ H.demo_name, step3 },
    );
    const edit = H.as_demo ++ "sh -c 'echo more words >> " ++ project_dir ++ "/README.md'";
    _ = try common.expect_exit(session, out, step3, edit, 0);
    const report = try text_report(session, out, step3);
    checks.check_all_hits(&report) catch |err| {
        return fail_step(out, step3, "expected three hits after the README edit", err);
    };
    checks.check_digest_equal(first_digest(), report.digest) catch |err| {
        return fail_step(out, step3, "expected the digest of the first build", err);
    };
}

const main_go = project_dir ++ "/main.go";
const to_again = H.as_demo ++ "sed -i 's/" ++ greeting ++ "/" ++ greeting_again ++ "/' " ++ main_go;
const to_first = H.as_demo ++ "sed -i 's/" ++ greeting_again ++ "/" ++ greeting ++ "/' " ++ main_go;

fn greeting_change(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: the greeting changed: only compile and image are built\n", .{
        H.demo_name, step4,
    });
    _ = try common.expect_exit(session, out, step4, to_again, 0);
    const changed = try text_report(session, out, step4);
    checks.check_one_changed(&changed) catch |err| {
        return fail_step(out, step4, "expected compile and image to miss, notice to hit", err);
    };
    checks.check_digest_differs(first_digest(), changed.digest) catch |err| {
        return fail_step(out, step4, "expected a new digest", err);
    };
    try expect_greeting(session, out, step4, changed.digest, greeting_again);
    _ = try common.expect_exit(session, out, step4, to_first, 0);
    const restored = try text_report(session, out, step4);
    checks.check_all_hits(&restored) catch |err| {
        return fail_step(out, step4, "expected three hits for the restored file", err);
    };
    checks.check_digest_equal(first_digest(), restored.digest) catch |err| {
        return fail_step(out, step4, "expected the first digest again", err);
    };
}

const step5 = "HELLO7 5";
const step6 = "HELLO7 6";

/// Steps 5 and 6, in the second VM: a project installed afresh, an empty store.
pub fn step_second(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print(
        "\n{s}: HELLO7: the brief's steps 5 and 6, in a second clean VM\n",
        .{H.demo_name},
    );
    if (first_digest().len == 0) {
        return fail_step(out, step5, "no digest from step 1", error.DigestWrong);
    }
    try install_project(session, out);
    try same_digest(session, out);
    try no_network(session, out);
    try timer.lap(out, "hello7b");
}

fn same_digest(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: a clean machine builds the same bytes\n", .{ H.demo_name, step5 });
    const report = try json_report(session, out, step5);
    checks.check_first_build(&report) catch |err| {
        return fail_step(out, step5, "expected three misses on a clean store", err);
    };
    checks.check_digest_equal(first_digest(), report.digest) catch |err| {
        return fail_step(out, step5, "expected the digest of the first VM", err);
    };
    try out.print("{s}: m7 result digest: {s}\n", .{ H.demo_name, report.digest });
    checks.check_golden(golden, report.digest) catch |err| {
        try out.print("{s}: put .digest = \"{s}\" in src/testing/vm/m7_expected.zon\n", .{
            H.demo_name, report.digest,
        });
        return fail_step(out, step5, "expected the golden digest of m7_expected.zon", err);
    };
}

fn no_network(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: a step with no network fails, and says how to grant it\n", .{
        H.demo_name, step6,
    });
    var buffer: [2048]u8 = undefined;
    const added = checks.with_step(&buffer, build_file_text, checks.fetch_step) orelse {
        return fail_step(out, step6, "the build file has no place for a step", error.PrepareFailed);
    };
    try put_text(session, project_dir ++ "/zbx.build.zon", added);
    const failed = try common.run_shown(session, out, build_text);
    checks.check_no_network(failed.streams.stderr, failed.status) catch |err| {
        return fail_step(out, step6, "expected E0805 with the grant named", err);
    };
    checks.check_others_hit(failed.streams.stdout) catch |err| {
        return fail_step(out, step6, "expected the other steps to report hit", err);
    };
}

test {
    // Goal: the files this part embeds fit what the guest accepts, and the project has what the
    // steps edit. Method: sizes against `put_file`'s limit, and the strings the sed commands use.
    inline for (project_files) |file| try std.testing.expect(file.text.len <= 1536);
    try std.testing.expect(std.mem.indexOf(u8, @embedFile("m7_project/main.go"), greeting) != null);
    try std.testing.expect(to_again.len <= 1024);
    try std.testing.expect(std.mem.indexOf(u8, golden, ".digest = \"") != null);
}
