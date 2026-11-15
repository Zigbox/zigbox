//! The M9 demo's step 7 (docs/briefs/M9-dockerfile-import.md, "Demo"): a pinned `ADD` of the
//! project `m9_fetch/`, served in the guest by `fixture_http.zig` on 127.0.0.1:8080. Nothing in
//! it reaches the internet but the pull of `alpine:3.20` through the mirror.
//!
//!   7. `zbx import` flags nothing and writes the fetch entry; `--hermetic` imports it too.
//!      `zbx build`: one request; /opt/hello.txt is 0:0 0600 with hello.txt's bytes. Again: all
//!      hits, the same digest, no request. The URL through `/r/`: all hits, no request.
//!      `.chmod = "0644"`: both steps miss, no request. A wrong `.sha256` in a fresh store:
//!      exit 3, E0821 with the URL and both hashes, no step ran.
//!
//! Every assertion is a function of checks_fetch_m9.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_fetch_m9.zig");
const m7 = @import("checks_m7.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m9.zig");
const hello_m7 = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");
const vm = @import("zigbox_vm");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;

pub const project_dir = "/home/demo/fetch";
const wrapper = "/home/demo/zf";
const zf = H.as_demo ++ wrapper;
const server_path = "/home/demo/fixture-http";
const log_path = "/home/demo/http.log";
const build_path = project_dir ++ "/zbx.build.zon";
const step7 = "FETCH9 7";
const local_url = "http://127.0.0.1:8080/hello.txt";
const fresh_data = "/home/demo/fresh-data";

/// The server the harness serves to the guest, beside zbx.
pub const routes = [_]vm.Route{
    .{ .path = "/m9/fixture-http", .body = @embedFile("fixture_http") },
};

const project_files = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "Dockerfile", .text = @embedFile("m9_fetch/Dockerfile") },
    .{ .name = "zbx.lock", .text = @embedFile("m9_fetch/zbx.lock") },
    .{ .name = "hello.txt", .text = @embedFile("m9_fetch/hello.txt") },
};

/// The digest of the first build, kept for the second. A fixed buffer.
var first_storage: [67]u8 = undefined;
var first_length: usize = 0;

pub fn step_fetch(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: a pinned ADD, fetched once\n", .{ H.demo_name, step7 });
    try install(session, out);
    try start_server(session, out);
    try expect_import(session, out);
    try first_build(session, out);
    try out.print("\n{s}: {s}: again, then through a redirect: all hits\n", .{
        H.demo_name, step7,
    });
    try expect_hits(session, out);
    const redirect = "sed -i 's#8080/hello.txt#8080/r/hello.txt#' " ++ build_path;
    _ = try common.expect_exit(session, out, step7, H.as_demo ++ redirect, 0);
    try expect_hits(session, out);
    try out.print("\n{s}: {s}: a new mode misses, with no request\n", .{ H.demo_name, step7 });
    const chmod = "sed -i 's#.to = \"/opt/hello.txt\"#.to = \"/opt/hello.txt\", " ++
        ".chmod = \"0644\"#' " ++ build_path;
    _ = try common.expect_exit(session, out, step7, H.as_demo ++ chmod, 0);
    const changed = try build(session, out);
    checks.check_rows(&changed, false) catch |err| {
        return fail_step(out, step7, "expected the copy and the RUN to miss", err);
    };
    try expect_requests(session, out, 1);
    try mismatch(session, out);
    try timer.lap(out, "fetch9");
}

fn install(session: *Session, out: *Io.Writer) !void {
    const made = try common.format(session, "rm -rf {s} && mkdir -p {s} && chown demo:demo {s}", .{
        project_dir, project_dir, project_dir,
    });
    _ = try common.expect_exit(session, out, step7, made, 0);
    inline for (project_files) |file| {
        try hello_m7.put_text(session, project_dir ++ "/" ++ file.name, file.text);
    }
    try hello_m7.make_wrapper(session, project_dir, wrapper);
    const fetched = try common.format(
        session,
        "curl -fsS -o {s} http://10.0.2.2:{d}/m9/fixture-http && chown demo:demo {s} && " ++
            "chmod 755 {s}",
        .{ server_path, session.server.port, server_path, server_path },
    );
    _ = try common.expect_exit(session, out, step7, fetched, 0);
}

/// Starts the server in the project directory, its log appended to `log_path`; waits until it
/// answers, then empties the log, so that it counts the build's requests only.
fn start_server(session: *Session, out: *Io.Writer) !void {
    const start = H.as_demo_setsid ++ "sh -c \"cd " ++ project_dir ++ " && exec " ++
        server_path ++ " >>" ++ log_path ++ " 2>&1\" </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 50); do curl -fsS --noproxy '*' -o /dev/null " ++ local_url ++
        " && break; sleep 0.2; done; curl -fsS --noproxy '*' " ++ local_url ++ " && : > " ++
        log_path;
    const started = try common.expect_exit(session, out, step7, start, 0);
    m7.check_stdout_is(started.streams.stdout, "hello, fetch") catch |err| {
        return fail_step(out, step7, "expected the server to serve hello.txt", err);
    };
}

fn expect_import(session: *Session, out: *Io.Writer) !void {
    const imported = try common.run_shown(session, out, zf ++ " import");
    const streams = imported.streams;
    checks.check_import(streams.stdout, streams.stderr, imported.status) catch |err| {
        return fail_step(out, step7, "expected an import with nothing flagged", err);
    };
    const written = try hello.read_file(session, out, step7, build_path);
    checks.check_entry(written) catch |err| {
        return fail_step(out, step7, "expected the entry's .fetch with the URL and hash", err);
    };
    const hermetic = zf ++ " import --hermetic -o h.build.zon";
    _ = try common.expect_exit(session, out, step7, hermetic, 0);
    const sealed = try hello.read_file(session, out, step7, project_dir ++ "/h.build.zon");
    checks.check_entry(sealed) catch |err| {
        return fail_step(out, step7, "expected --hermetic to write the same .fetch entry", err);
    };
}

fn build(session: *Session, out: *Io.Writer) !checks.Report {
    const command = zf ++ " build";
    const done = try state.expect_long_split(session, out, command, 0, hello.build_timeout_s);
    return m7.parse_text(done.streams.stdout) catch |err| {
        return fail_step(out, step7, "expected the text build report", err);
    };
}

fn expect_requests(session: *Session, out: *Io.Writer, want: u32) !void {
    const log = try hello.read_file(session, out, step7, log_path);
    checks.check_requests(log, want) catch |err| {
        return fail_step(out, step7, "expected the server's log to hold one request", err);
    };
}

fn first_build(session: *Session, out: *Io.Writer) !void {
    const report = try build(session, out);
    checks.check_rows(&report, false) catch |err| {
        return fail_step(out, step7, "expected every step a miss", err);
    };
    std.debug.assert(m7.is_digest(report.digest));
    @memcpy(first_storage[0..report.digest.len], report.digest);
    first_length = report.digest.len;
    try expect_requests(session, out, 1);
    const digest = first_storage[0..first_length];
    const stat_pattern = "{s} run {s} -- /bin/stat -c '%u:%g %a' /opt/hello.txt";
    const stat = try common.format(session, stat_pattern, .{ zf, digest });
    const owner = try state.expect_long_split(session, out, stat, 0, hello.short_s);
    checks.check_owner(owner.streams.stdout) catch |err| {
        return fail_step(out, step7, "expected /opt/hello.txt owned 0:0, mode 0600", err);
    };
    const cat_pattern = "{s} run {s} -- /bin/cat /opt/hello.txt";
    const cat = try common.format(session, cat_pattern, .{ zf, digest });
    const bytes = try state.expect_long_split(session, out, cat, 0, hello.short_s);
    m7.check_stdout_is(bytes.streams.stdout, "hello, fetch") catch |err| {
        return fail_step(out, step7, "expected hello.txt's bytes", err);
    };
}

fn expect_hits(session: *Session, out: *Io.Writer) !void {
    const report = try build(session, out);
    checks.check_rows(&report, true) catch |err| {
        return fail_step(out, step7, "expected every step a hit", err);
    };
    m7.check_digest_equal(first_storage[0..first_length], report.digest) catch |err| {
        return fail_step(out, step7, "expected the first build's digest", err);
    };
    try expect_requests(session, out, 1);
}

/// A wrong pin, in a fresh store (a second XDG_DATA_HOME), so the blob is not there.
fn mismatch(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: {s}: a wrong pin in a fresh store is E0821\n", .{ H.demo_name, step7 });
    const wrong = "sed 's#" ++ checks.hello_sha256 ++ "#" ++ checks.wrong_sha256 ++ "#' " ++
        build_path ++ " > " ++ project_dir ++ "/bad.build.zon";
    _ = try common.expect_exit(session, out, step7, H.as_demo ++ "sh -c '" ++ wrong ++ "'", 0);
    // XDG_DATA_HOME must exist, as for every command: the store is made below it.
    const data_home = H.as_demo ++ "mkdir -p " ++ fresh_data;
    _ = try common.expect_exit(session, out, step7, data_home, 0);
    const fresh = H.as_demo ++ "XDG_DATA_HOME=" ++ fresh_data ++ " " ++ wrapper ++
        " build -f bad.build.zon";
    const refused = try state.expect_long_split(session, out, fresh, 3, hello.build_timeout_s);
    const streams = refused.streams;
    checks.check_mismatch(streams.stdout, streams.stderr, refused.status) catch |err| {
        return fail_step(out, step7, "expected E0821 naming the URL and both hashes", err);
    };
}

test {
    _ = @import("checks_fetch_m9.zig");
}
