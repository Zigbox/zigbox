//! The steps of the M9 demo (docs/briefs/M9-dockerfile-import.md, "Demo"), on the Go
//! hello-world of `m9_project/`, which has a Dockerfile and no build file. Steps 1 to 4 and 6 run
//! in the first VM (`step_first`), step 5 in a second, clean one (`step_second`).
//!
//!   1. `zbx import`: the golden build file, the lock unchanged, every step with its line,
//!      W0811 naming EXPOSE and HEALTHCHECK.
//!   2. `zbx build`: all misses, a digest; the image prints the greeting, `--whoami` is 10001;
//!      inspect shows the user, workdir and labels; /etc/hello/VERSION is 10001:10001 0644.
//!   3. Again, as JSON: all hits, the same digest.
//!   4. README.md (excluded) edited: all hits. `extra.go` added: the build stage's `*.go` copy
//!      and compile miss, `adduser` hits, a new digest; removed, the first digest, all hits.
//!   6. The `tools` stage: flagged `net` and `cache`, W0810 then W0811; `--hermetic` refuses
//!      it (E0814, Dockerfile:11, nothing written); built with W0801 and W0802, curl runs.
//!   5. (Second VM) the same import bytes and step 2's digest, the golden of `m9_expected.zon`.
//!
//! Every assertion is a function of checks_m9.zig with a unit test; this file runs the commands.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m9.zig");
const m7 = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello_m7 = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;

pub const project_dir = "/home/demo/hello";
/// `zbx` as the demo user in the hello project directory.
pub const zh = H.as_demo ++ "/home/demo/zh";
pub const dockerfile = @embedFile("m9_project/Dockerfile");
pub const lock_text = @embedFile("m9_project/zbx.lock");
pub const golden_build = @embedFile("m9_expected.build.zon");
const golden = @embedFile("m9_expected.zon");
const greeting = "hello from zigbox";
/// A first build pulls two images (golang is large) and compiles; a long timeout, in seconds.
pub const build_timeout_s: u32 = 1800;
pub const short_s: u32 = 120;

pub const project_files = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "Dockerfile", .text = dockerfile },
    .{ .name = ".dockerignore", .text = @embedFile("m9_project/.dockerignore") },
    .{ .name = "zbx.lock", .text = lock_text },
    .{ .name = "go.mod", .text = @embedFile("m9_project/go.mod") },
    .{ .name = "main.go", .text = @embedFile("m9_project/main.go") },
    .{ .name = "VERSION", .text = @embedFile("m9_project/VERSION") },
    .{ .name = "LICENSE", .text = @embedFile("m9_project/LICENSE") },
    .{ .name = "README.md", .text = @embedFile("m9_project/README.md") },
};

/// The result digest of step 2, kept for step 4 and the second VM. A fixed buffer.
var first_storage: [67]u8 = undefined;
var first_length: usize = 0;

pub fn first_digest() []const u8 {
    return first_storage[0..first_length];
}

fn remember_first(digest: []const u8) void {
    std.debug.assert(m7.is_digest(digest));
    @memcpy(first_storage[0..digest.len], digest);
    first_length = digest.len;
}

/// Makes `directory` with the project's files (no build file) and the wrapper `wrapper`.
pub fn install_project(
    session: *Session,
    out: *Io.Writer,
    directory: []const u8,
    wrapper: []const u8,
) !void {
    const made = try common.format(session, "rm -rf {s} && mkdir -p {s} && chown demo:demo {s}", .{
        directory, directory, directory,
    });
    _ = try common.expect_exit(session, out, "HELLO9", made, 0);
    inline for (project_files) |file| {
        const path = try common.format(session, "{s}/{s}", .{ directory, file.name });
        try hello_m7.put_text(session, path, file.text);
    }
    try hello_m7.make_wrapper(session, directory, wrapper);
}

/// The text of a file of the guest, as the demo user reads it.
pub fn read_file(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    path: []const u8,
) ![]const u8 {
    const command = try common.format(session, H.as_demo ++ "cat {s}", .{path});
    const shown = try common.expect_exit(session, out, step, command, 0);
    return shown.streams.stdout;
}

/// Step 1's import, and its checks: the report, the golden build file, the lock unchanged.
pub fn expect_import(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    directory: []const u8,
    wrapper: []const u8,
) !void {
    const command = try common.format(session, "{s} import", .{wrapper});
    const done = try state.expect_long_split(session, out, command, 0, build_timeout_s);
    checks.check_import(done.streams.stdout, done.streams.stderr, done.status) catch |err| {
        return fail_step(out, step, "expected every step with its line, and W0811", err);
    };
    const build_path = try common.format(session, "{s}/zbx.build.zon", .{directory});
    const written = try read_file(session, out, step, build_path);
    checks.check_same_bytes(written, golden_build) catch |err| {
        return fail_step(out, step, "expected the golden m9_expected.build.zon", err);
    };
    const lock_path = try common.format(session, "{s}/zbx.lock", .{directory});
    const lock = try read_file(session, out, step, lock_path);
    checks.check_same_bytes(lock, lock_text) catch |err| {
        return fail_step(out, step, "expected zbx.lock unchanged", err);
    };
}

fn build_text(session: *Session, out: *Io.Writer, step: []const u8) !checks.Report {
    const done = try state.expect_long_split(session, out, zh ++ " build", 0, build_timeout_s);
    return m7.parse_text(done.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the text build report", err);
    };
}

pub fn build_json(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    wrapper: []const u8,
) !checks.Report {
    const command = try common.format(session, "{s} build --output json", .{wrapper});
    const done = try state.expect_long_split(session, out, command, 0, build_timeout_s);
    return m7.parse_json(session.scratch_allocator(), done.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the JSON build report", err);
    };
}

/// `zbx run <what> <rest>` exits 0; its stdout.
fn run_image(session: *Session, out: *Io.Writer, what: []const u8, rest: []const u8) ![]const u8 {
    const command = try common.format(session, "{s} run {s}{s}", .{ zh, what, rest });
    const ran = try state.expect_long_split(session, out, command, 0, short_s);
    return ran.streams.stdout;
}

const step1 = "HELLO9 1";
const step2 = "HELLO9 2";
const step3 = "HELLO9 3";
const step4 = "HELLO9 4";
const step5 = "HELLO9 5";
const step6 = "HELLO9 6";

pub fn step_first(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: HELLO9: the brief's steps 1 to 4 and 6\n", .{H.demo_name});
    try install_project(session, out, project_dir, "/home/demo/zh");
    try out.print("\n{s}: {s}: zbx import writes the golden build file\n", .{ H.demo_name, step1 });
    try expect_import(session, out, step1, project_dir, zh);
    try first_build(session, out);
    try out.print("\n{s}: {s}: again: all hits, the same digest\n", .{ H.demo_name, step3 });
    const again = try build_json(session, out, step3, zh);
    try expect_hits(out, step3, &again);
    try globs_and_excludes(session, out);
    try not_hermetic(session, out);
    try timer.lap(out, "hello9");
}

fn expect_hits(out: *Io.Writer, step: []const u8, report: *const checks.Report) !void {
    checks.check_all_hits(report) catch |err| {
        return fail_step(out, step, "expected every step a hit", err);
    };
    m7.check_digest_equal(first_digest(), report.digest) catch |err| {
        return fail_step(out, step, "expected the digest of step 2", err);
    };
}

fn first_build(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: zbx build, run, inspect\n", .{ H.demo_name, step2 });
    const report = try build_text(session, out, step2);
    checks.check_first_build(&report) catch |err| {
        return fail_step(out, step2, "expected every step a miss", err);
    };
    remember_first(report.digest);
    // The report's slices point into the session's output buffer, which the next command's
    // output overwrites: keep to the copy.
    const digest = first_digest();
    const said = try run_image(session, out, digest, "");
    m7.check_stdout_is(said, greeting) catch |err| {
        return fail_step(out, step2, "expected the image to print its greeting", err);
    };
    // The brief's command: `--` replaces the image's cmd and keeps its entrypoint, so the path
    // is hello's first argument; main.go reads `--whoami` from its last.
    const whoami = try run_image(session, out, digest, " -- /usr/local/bin/hello --whoami");
    m7.check_stdout_is(whoami, "10001") catch |err| {
        return fail_step(out, step2, "expected the image to run as uid 10001", err);
    };
    const pattern = "{s} inspect {s} --output json";
    const inspect = try common.format(session, pattern, .{ zh, digest });
    const shown = try state.expect_long_split(session, out, inspect, 0, short_s);
    checks.check_inspect(shown.streams.stdout, digest) catch |err| {
        return fail_step(out, step2, "expected the user, workdir and labels in inspect", err);
    };
    const tree = checks.inspect_tree(shown.streams.stdout) orelse {
        return fail_step(out, step2, "expected a tree digest in inspect", error.InspectWrong);
    };
    // The bare tree runs with no config: as root, the command as given.
    const stat = " -- /bin/stat -c '%u:%g %a' /etc/hello/VERSION";
    const owner = try run_image(session, out, tree, stat);
    checks.check_owner(owner) catch |err| {
        return fail_step(out, step2, "expected /etc/hello/VERSION owned 10001:10001, 0644", err);
    };
}

const readme_edit = H.as_demo ++ "sh -c 'echo more >> " ++ project_dir ++ "/README.md'";
/// A second Go file that compiles beside main.go: its `main` renamed `init`, which the program
/// runs, so the binary (and the digest) must change. A renamed function nothing calls could be
/// dropped by the linker and leave the binary as it was.
const add_extra = H.as_demo ++ "sh -c 'sed s/func\\ main/func\\ init/ " ++ project_dir ++
    "/main.go > " ++ project_dir ++ "/extra.go'";
const remove_extra = H.as_demo ++ "rm " ++ project_dir ++ "/extra.go";

fn globs_and_excludes(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: an excluded file changes nothing; a new *.go does\n", .{
        H.demo_name, step4,
    });
    _ = try common.expect_exit(session, out, step4, readme_edit, 0);
    const edited = try build_text(session, out, step4);
    try expect_hits(out, step4, &edited);
    _ = try common.expect_exit(session, out, step4, add_extra, 0);
    const extra = try build_text(session, out, step4);
    checks.check_extra(&extra) catch |err| {
        return fail_step(out, step4, "expected build-2, build-3 to miss, adduser to hit", err);
    };
    m7.check_digest_differs(first_digest(), extra.digest) catch |err| {
        return fail_step(out, step4, "expected a new digest with extra.go", err);
    };
    _ = try common.expect_exit(session, out, step4, remove_extra, 0);
    const restored = try build_text(session, out, step4);
    try expect_hits(out, step4, &restored);
}

const tools_import = zh ++ " import --target tools -o tools.build.zon";
const hermetic_import = zh ++ " import --target tools --hermetic -o t2.build.zon";
const t2_absent = "test ! -e " ++ project_dir ++ "/t2.build.zon";
const tools_build = zh ++ " build -f tools.build.zon";

fn not_hermetic(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: a stage that fetches is flagged, and --hermetic refuses it\n", .{
        H.demo_name, step6,
    });
    const tools = try state.expect_long_split(session, out, tools_import, 0, short_s);
    checks.check_tools(tools.streams.stdout, tools.streams.stderr, tools.status) catch |err| {
        return fail_step(out, step6, "expected tools-1 flagged net and cache, and W0810", err);
    };
    const refused = try common.run_shown(session, out, hermetic_import);
    const wants = [_][]const u8{"Dockerfile:11"};
    checks.check_refused(refused.streams.stderr, refused.status, "ZBX-E0814", &wants) catch |err| {
        return fail_step(out, step6, "expected E0814 naming Dockerfile:11", err);
    };
    _ = try common.expect_exit(session, out, step6, t2_absent, 0);
    const built = try state.expect_long_split(session, out, tools_build, 0, build_timeout_s);
    checks.check_warnings(built.streams.stderr, &.{ "ZBX-W0801", "ZBX-W0802" }) catch |err| {
        return fail_step(out, step6, "expected W0801 and W0802", err);
    };
    const report = m7.parse_text(built.streams.stdout) catch |err| {
        return fail_step(out, step6, "expected the text build report", err);
    };
    _ = try run_image(session, out, report.digest, " -- curl --version");
}

/// Step 5, in the second VM: a project installed afresh, an empty store.
pub fn step_second(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: a clean machine imports and builds the same bytes\n", .{
        H.demo_name, step5,
    });
    if (first_digest().len == 0) {
        return fail_step(out, step5, "no digest from step 2", error.DigestWrong);
    }
    try install_project(session, out, project_dir, "/home/demo/zh");
    try expect_import(session, out, step5, project_dir, zh);
    const report = try build_json(session, out, step5, zh);
    checks.check_first_build(&report) catch |err| {
        return fail_step(out, step5, "expected every step a miss on a clean store", err);
    };
    m7.check_digest_equal(first_digest(), report.digest) catch |err| {
        return fail_step(out, step5, "expected the digest of the first VM", err);
    };
    try out.print("{s}: m9 result digest: {s}\n", .{ H.demo_name, report.digest });
    m7.check_golden(golden, report.digest) catch |err| {
        try out.print("{s}: put .digest = \"{s}\" in src/testing/vm/m9_expected.zon\n", .{
            H.demo_name, report.digest,
        });
        return fail_step(out, step5, "expected the golden digest of m9_expected.zon", err);
    };
    try timer.lap(out, "hello9b");
}

test {
    // Goal: the files this part puts in the guest fit what the guest accepts, and the commands
    // fit a command line. Method: sizes against `put_file`'s and the command limit.
    inline for (project_files) |file| try std.testing.expect(file.text.len <= 1536);
    try std.testing.expect(add_extra.len <= 1024);
    const main_go = @embedFile("m9_project/main.go");
    try std.testing.expect(std.mem.indexOf(u8, main_go, "func main()") != null);
    try std.testing.expect(std.mem.indexOf(u8, golden, ".digest = ") != null);
    try std.testing.expect(std.mem.indexOf(u8, golden_build, ".chown = \"app:app\"") != null);
}
