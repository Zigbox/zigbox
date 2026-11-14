//! The M9 acceptance checks (docs/briefs/M9-dockerfile-import.md, "The demo", ACCEPT), run in
//! the first VM after HELLO9, in a copy of the project (`~/hello2`, wrapper `zh2`) and a fixture
//! directory (`~/fx`, wrapper `zf`), so that `~/hello` stays what step 1 imported:
//!
//!   - the fixtures that need only the demo lock's images, through the binary: each writes its
//!     golden translation, or is refused as its golden says and writes nothing;
//!   - `zbx build --graph` on the imported file is the golden `m9_expected.graph.txt`;
//!   - changing nothing in the Dockerfile but its comments gives the same build file;
//!   - an unlocked `FROM` with the network down is the pull's own `05xx` refusal;
//!   - `zbx import` over an existing build file is E0816, and the file is unchanged;
//!   - after every build, no step's run record and no `build/work/` entry is left.
//!
//! Every assertion is a function of checks_m9.zig or checks_m7.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m9.zig");
const m7 = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m9.zig");
const hello_m7 = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");
const vm_cases = @import("m9_vm_cases");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const step = "ACCEPT9";
const copy_dir = "/home/demo/hello2";
const zh2 = H.as_demo ++ "/home/demo/zh2";
const fixture_dir = "/home/demo/fx";
const zf = H.as_demo ++ "/home/demo/zf";
const short_s: u32 = 120;
const graph_golden = @embedFile("m9_expected.graph.txt");

const setup = H.as_demo ++ "sh -c 'rm -rf " ++ copy_dir ++ " " ++ fixture_dir ++ " && " ++
    "cp -a " ++ hello.project_dir ++ " " ++ copy_dir ++ " && mkdir " ++ fixture_dir ++ " && " ++
    "cp " ++ hello.project_dir ++ "/zbx.lock " ++ fixture_dir ++ "/'";
/// Clears what the last fixture left: its Dockerfile, its ignore file, its build file.
const fixture_clear = H.as_demo ++ "rm -f " ++ fixture_dir ++ "/Dockerfile " ++
    fixture_dir ++ "/.dockerignore " ++ fixture_dir ++ "/zbx.build.zon";
const fixture_absent = "test ! -e " ++ fixture_dir ++ "/zbx.build.zon";
const copy_build_file = copy_dir ++ "/zbx.build.zon";
const copy_clear = H.as_demo ++ "rm -f " ++ copy_build_file;
const copy_absent = "test ! -e " ++ copy_build_file;
/// A base `zbx.lock` does not pin: the import must pull it, and the network is down.
const unlocked_dockerfile = "FROM busybox:1.36\nRUN true\n";
const zh2_offline = "unshare -n " ++ zh2;
// Each count runs the listing alone first (`&&`), so the command's own failure is the exit code
// the harness asserts; `grep -c` exits 1 for a count of zero, which is the answer wanted here.
const count_work = "sh -c 'if [ -d " ++ common.store_dir ++ "/build/work ]; then ls -A " ++
    common.store_dir ++ "/build/work > /tmp/work.out && wc -l < /tmp/work.out; else echo 0; fi'";
const count_records = H.as_demo ++ "sh -c '/home/demo/zh2 ps --all > /home/demo/ps.out && " ++
    "{ grep -c build- /home/demo/ps.out || test $? -eq 1; }'";

pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: fixtures, graph, comments, refusals, a clean store\n", .{
        H.demo_name, step,
    });
    _ = try common.expect_exit(session, out, step, setup, 0);
    try hello_m7.make_wrapper(session, copy_dir, "/home/demo/zh2");
    try hello_m7.make_wrapper(session, fixture_dir, "/home/demo/zf");
    try fixtures(session, out);
    try graph(session, out);
    try comments(session, out);
    try refuse(session, out);
    try clean(session, out);
    try timer.lap(out, "accept9");
}

fn fixtures(session: *Session, out: *Io.Writer) !void {
    inline for (vm_cases.cases) |case| {
        try out.print("{s}: {s}: fixture {s}\n", .{ H.demo_name, step, case.name });
        _ = try common.expect_exit(session, out, step, fixture_clear, 0);
        try hello_m7.put_text(session, fixture_dir ++ "/Dockerfile", case.dockerfile);
        if (case.dockerignore.len > 0) {
            try hello_m7.put_text(session, fixture_dir ++ "/.dockerignore", case.dockerignore);
        }
        const command = zf ++ " import " ++ case.arguments;
        const done = try common.run_shown(session, out, command);
        if (case.refused) {
            const stderr = done.streams.stderr;
            checks.check_fixture_refused(stderr, done.status, case.golden) catch |err| {
                return fail_step(out, step, "expected fixture " ++ case.name ++ "'s refusal", err);
            };
            _ = try common.expect_exit(session, out, step, fixture_absent, 0);
        } else {
            if (done.status != 0) {
                const what = "fixture " ++ case.name ++ " refused";
                return fail_step(out, step, what, error.ImportWrong);
            }
            const path = fixture_dir ++ "/zbx.build.zon";
            const written = try hello.read_file(session, out, step, path);
            checks.check_same_bytes(written, case.golden) catch |err| {
                return fail_step(out, step, "expected fixture " ++ case.name ++ "'s golden", err);
            };
        }
    }
}

fn graph(session: *Session, out: *Io.Writer) !void {
    const shown = try common.expect_exit(session, out, step, hello.zh ++ " build --graph", 0);
    checks.check_same_bytes(shown.streams.stdout, graph_golden) catch |err| {
        return fail_step(out, step, "expected the graph of m9_expected.graph.txt", err);
    };
}

fn comments(session: *Session, out: *Io.Writer) !void {
    var buffer: [2048]u8 = undefined;
    const dockerfile = hello.dockerfile;
    const commented = checks.with_comments(&buffer, dockerfile, "the tools", "the image") orelse {
        const what = "the Dockerfile has no blank lines 9 and 12";
        return fail_step(out, step, what, error.PrepareFailed);
    };
    try hello_m7.put_text(session, copy_dir ++ "/Dockerfile", commented);
    _ = try common.expect_exit(session, out, step, copy_clear, 0);
    _ = try state.expect_long_split(session, out, zh2 ++ " import", 0, short_s);
    const written = try hello.read_file(session, out, step, copy_build_file);
    checks.check_same_bytes(written, hello.golden_build) catch |err| {
        return fail_step(out, step, "expected the same build file with other comments", err);
    };
}

fn refuse(session: *Session, out: *Io.Writer) !void {
    // Over the build file the comments' import wrote: refused, and the file as it was.
    const over = try common.run_shown(session, out, zh2 ++ " import");
    checks.check_refused(over.streams.stderr, over.status, "ZBX-E0816", &.{}) catch |err| {
        return fail_step(out, step, "expected E0816 over an existing build file", err);
    };
    const kept = try hello.read_file(session, out, step, copy_build_file);
    checks.check_same_bytes(kept, hello.golden_build) catch |err| {
        return fail_step(out, step, "expected the existing build file unchanged", err);
    };
    try hello_m7.put_text(session, copy_dir ++ "/Dockerfile", unlocked_dockerfile);
    _ = try common.expect_exit(session, out, step, copy_clear, 0);
    const offline = try common.run_shown(session, out, zh2_offline ++ " import");
    checks.check_pull_refused(offline.streams.stderr, offline.status) catch |err| {
        return fail_step(out, step, "expected the pull's own refusal, the network down", err);
    };
    _ = try common.expect_exit(session, out, step, copy_absent, 0);
    try hello_m7.put_text(session, copy_dir ++ "/Dockerfile", hello.dockerfile);
}

fn clean(session: *Session, out: *Io.Writer) !void {
    const work = try common.expect_exit(session, out, step, count_work, 0);
    m7.check_zero(work.streams.stdout) catch |err| {
        return fail_step(out, step, "expected no build/work entry left", err);
    };
    const records = try common.expect_exit(session, out, step, count_records, 0);
    m7.check_zero(records.streams.stdout) catch |err| {
        return fail_step(out, step, "expected no step run record left", err);
    };
}

test {
    // Goal: what this part puts in the guest fits what the guest accepts. Method: every fixture
    // against `put_file`'s bound, the commands against the command line's, and the comment
    // variant of the demo Dockerfile against the same bound.
    inline for (vm_cases.cases) |case| {
        try std.testing.expect(case.dockerfile.len <= 1536);
        try std.testing.expect(case.dockerignore.len <= 1536);
    }
    try std.testing.expect(setup.len <= 1024);
    try std.testing.expect(count_records.len <= 1024);
    var buffer: [2048]u8 = undefined;
    const commented = checks.with_comments(&buffer, hello.dockerfile, "the tools", "the image");
    try std.testing.expect(commented.?.len <= 1536);
}
