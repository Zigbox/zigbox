//! The spec's five steps of M6b, as the spec types them, run as the user `demo` in the net
//! project (`zn`), with `python:3.12-slim` (docs/SPEC.md, M6b; docs/briefs/M6b-dev-loop.md):
//!
//!   1. `zbx run -d --name web --publish 8000:8000 --mount ./site:/srv python:3.12-slim --
//!      python -m http.server -d /srv 8000`.
//!   2. `curl localhost:8000/index.html` returns the page. The page is edited on the host; the
//!      next `curl` returns the edit.
//!   3. `zbx exec web -- sh -c 'echo made-inside > /srv/new.txt'`; on the host, `ls -l
//!      site/new.txt` shows the presenter's user (`demo`) as its owner.
//!   4. `zbx logs web` shows the two requests, and no others.
//!   5. A writable mount outside the guardrails (`--mount ../outside-spec:/x`, a directory next
//!      to the project) is refused, naming the rule: ZBX-E0212, the project directory, "outside
//!      the project".
//!
//! Nothing differs from the spec's lines but what the guest needs: the port is waited for with a
//! connection that sends no request, made from inside the container (so the log holds only the
//! steps' requests), and `-d` is the spec's own. The part ends by stopping `web`, which frees
//! port 8000 (checked).
//!
//! Every assertion is a function of checks_spec_m6b.zig or checks_writable_m6b.zig with a unit
//! test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_spec_m6b.zig");
const writable = @import("checks_writable_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "SPEC6B";

const project = net_user.net_project;
const outside = "/home/demo/outside-spec";
const python = "python:3.12-slim";

const setup = H.as_demo ++ "sh -c 'cd " ++ project ++ " && rm -rf site && mkdir site && " ++
    "echo first-SIGMA > site/index.html && mkdir -p " ++ outside ++ "'";
const start = zn ++ " run -d --name web --publish 8000:8000 --mount ./site:/srv " ++ python ++
    " -- python -m http.server -d /srv 8000";
const wait_path = "/home/demo/wait-web.sh";
const fetch = "curl -fsS http://localhost:8000/index.html";
const edit = H.as_demo ++ "sh -c 'echo second-SIGMA > " ++ project ++ "/site/index.html'";
const exec = zn ++ " exec web -- sh -c 'echo made-inside > /srv/new.txt' </dev/null";
const look = H.as_demo ++ "sh -c 'cd " ++ project ++ " && ls -l site/new.txt && cat site/new.txt'";
/// From inside the project: `find` run where the user cannot read (`/root`, runuser's start)
/// fails on its way out, and its status is what tells a failed search from an empty one.
const strangers = H.as_demo ++ "sh -c 'cd " ++ project ++ " && find site ! -user demo -print'";

/// The text of a script that waits (ninety seconds) until the server in the container `name`
/// (`wrapper` is the `zbx` of its project) takes a connection, asked from inside the container
/// with `exec`. A connection from the host would not do: the forward accepts it before the
/// server is up, and resets it. The connection sends no request, so the log has none for it.
pub fn wait_script(comptime wrapper: []const u8, comptime name: []const u8) []const u8 {
    return "#!/bin/sh\n" ++
        "for i in $(seq 90); do\n" ++
        "  " ++ wrapper ++ " exec " ++ name ++ " -- python -c " ++
        "\"import socket; socket.create_connection(('127.0.0.1', 8000)).close()\" " ++
        "</dev/null >/dev/null 2>&1 && exit 0\n" ++
        "  sleep 1\n" ++
        "done\n" ++
        "exit 1\n";
}

/// Writes `script` to `path` as the demo user's executable and runs it as the demo user.
pub fn run_waiter(session: *Session, out: *Io.Writer, path: []const u8, script: []const u8) !void {
    try H.put_file(session, path, script);
    const pattern = "chown demo:demo {s} && chmod 755 {s}";
    const command = try common.format(session, pattern, .{ path, path });
    _ = try common.expect_exit(session, out, step_name, command, 0);
    const run = try common.format(session, "{s}{s}", .{ H.as_demo, path });
    _ = try common.expect_exit(session, out, step_name, run, 0);
}

pub fn step_spec(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: SPEC6B: the five steps of the spec (M6b)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull " ++ python, 0);
    _ = try common.expect_exit(session, out, step_name, setup, 0);
    try step_one_two(session, out);
    try step_three(session, out);
    try step_four(session, out);
    try step_five(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " stop web", 0);
    try net_user.expect_free(session, out, 8000, "after web was stopped");
    try timer.lap(out, "spec6b");
}

fn step_one_two(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC6B 1 and 2: serve ./site, curl, edit, curl\n", .{H.demo_name});
    _ = try common.expect_exit(session, out, step_name, start, 0);
    try run_waiter(session, out, wait_path, wait_script("/home/demo/zn", "web"));
    const first = try common.expect_exit(session, out, step_name, fetch, 0);
    writable.check_page(first.streams.stdout, "first-SIGMA", "second-SIGMA") catch |err| {
        return fail_step(out, step_name, "expected the page from ./site", err);
    };
    _ = try common.expect_exit(session, out, step_name, edit, 0);
    const second = try common.expect_exit(session, out, step_name, fetch, 0);
    writable.check_page(second.streams.stdout, "second-SIGMA", "first-SIGMA") catch |err| {
        return fail_step(out, step_name, "expected the next curl to return the edit", err);
    };
}

fn step_three(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC6B 3: exec writes into the mount; the host user owns it\n", .{
        H.demo_name,
    });
    _ = try common.expect_exit(session, out, step_name, exec, 0);
    const listed = try common.run_shown(session, out, look);
    checks.check_owner_listing(
        listed.streams.stdout,
        listed.status,
        "demo",
        "site/new.txt",
        "made-inside",
    ) catch |err| {
        return fail_step(out, step_name, "expected ls -l to show demo as the owner", err);
    };
    // Nothing in the project belongs to anyone else, the file the page came from included.
    const others = try common.run_shown(session, out, strangers);
    const streams = others.streams;
    checks.check_no_strangers(streams.stdout, streams.stderr, others.status) catch |err| {
        return fail_step(out, step_name, "expected no file of another owner", err);
    };
}

fn step_four(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC6B 4: zbx logs web shows the two requests\n", .{H.demo_name});
    const log = try common.run_shown(session, out, zn ++ " logs web");
    checks.check_two_requests(log.streams.stdout, log.status, "/index.html") catch |err| {
        return fail_step(out, step_name, "expected the two requests of step 2", err);
    };
}

fn step_five(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC6B 5: a writable mount outside the guardrails is refused\n", .{
        H.demo_name,
    });
    const command = zn ++ " run --mount ../outside-spec:/x alpine -- true";
    const refused = try common.run_shown(session, out, command);
    const parts = [_][]const u8{ project, "outside the project", outside };
    writable.check_refusal(refused.streams, refused.status, "E0212", &parts) catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0212 naming the rule", err);
    };
}

test {
    _ = @import("checks_spec_m6b.zig");
    _ = @import("checks_writable_m6b.zig");
}
