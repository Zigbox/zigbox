//! M6b slice 1's writable mounts and `--user` in the VM, a part of demo-m6b
//! (`WRITABLE`). As the user `demo`, in the net project (`zn`),
//! which holds a `site` directory, a link to a directory outside the project and a link to /etc:
//!
//!   1. python's `http.server` serves the mounted `site` (`--publish`), and `curl` gets its page.
//!   2. An edit of the page on the host is what the next `curl` returns.
//!   3. A file written inside by a run as root is owned by the host user, and the run's JSON and
//!      `ps` list the mount by its host path and target, and the user.
//!   4. The refusals: `../outside`, a link that points out, a link to /etc, `/` (E0212, naming
//!      the project directory), a source that is not there (E0214), and an image whose user is
//!      not root (E0213, naming the user and both fixes); nothing was made.
//!   5. That same image with `--user 0` runs, and its file is the host user's.
//!
//! Every assertion is a function of checks_writable_m6b.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_writable_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "WRITABLE";

const project = net_user.net_project;
const by_memcached_owns = H.as_demo ++
    checks.owners_command(project ++ "/site/by-memcached.txt", project ++ "/site");
const outside = "/home/demo/outside-wr";
const python = "python:3.12-slim";
const non_root = "memcached:alpine";
const port = "18088";

const setup = H.as_demo ++ "sh -c 'cd " ++ project ++ " && mkdir -p site " ++ outside ++
    " && echo first-OMEGA > site/index.html && ln -sfn " ++ outside ++ " leak && " ++
    "ln -sfn /etc etcdir'";

const serve = zn ++ " run -d --name wr1 --publish " ++ port ++ ":8000 --mount site:/srv " ++
    python ++ " -- python -m http.server -d /srv 8000";
const fetch = "for i in $(seq 60); do curl -fsS http://127.0.0.1:" ++ port ++
    "/index.html && break; sleep 1; done";
const edit = H.as_demo ++ "sh -c 'echo second-OMEGA > " ++ project ++ "/site/index.html'";

const write_inside = zn ++ " --output json run --name wr2 --mount site:/srv alpine -- sh -c " ++
    "'echo made-inside > /srv/new.txt; id -u'";
const who_owns = H.as_demo ++
    checks.owners_command(project ++ "/site/new.txt", project ++ "/site");

pub fn step_writable(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: WRITABLE: --mount and --user (M6b slice 1)\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull alpine", 0);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull " ++ python, 0);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull " ++ non_root, 0);
    _ = try common.expect_exit(session, out, step_name, setup, 0);
    try serve_and_edit(session, out);
    try owned_by_the_user(session, out);
    try refusals(session, out);
    try root_flag(session, out);
    try timer.lap(out, "writable");
}

fn serve_and_edit(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: WRITABLE 1: python serves the mounted directory; an edit is seen\n", .{
        H.demo_name,
    });
    _ = try common.expect_exit(session, out, step_name, serve, 0);
    const first = try common.expect_exit(session, out, step_name, fetch, 0);
    checks.check_page(first.streams.stdout, "first-OMEGA", "second-OMEGA") catch |err| {
        return fail_step(out, step_name, "expected the page from the mounted directory", err);
    };
    _ = try common.expect_exit(session, out, step_name, edit, 0);
    const second = try common.expect_exit(session, out, step_name, fetch, 0);
    checks.check_page(second.streams.stdout, "second-OMEGA", "first-OMEGA") catch |err| {
        return fail_step(out, step_name, "expected the edit made on the host", err);
    };
    _ = try common.expect_exit(session, out, step_name, zn ++ " stop wr1", 0);
}

fn owned_by_the_user(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: WRITABLE 3: a file written inside is the host user's\n", .{H.demo_name});
    // Each result is read before the next command: the streams live in the session's buffer.
    const inside = try common.expect_exit(session, out, step_name, write_inside, 0);
    checks.check_root_run(inside.streams.stdout, inside.status) catch |err| {
        return fail_step(out, step_name, "expected the run to be root", err);
    };
    const site = project ++ "/site";
    checks.check_json(inside.streams.stderr, site, "/srv") catch |err| {
        return fail_step(out, step_name, "expected the mount and the user in run's JSON", err);
    };
    const owners = try common.expect_exit(session, out, step_name, who_owns, 0);
    checks.check_owner(owners.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the host user to own the file", err);
    };
    const ps = zn ++ " --output json ps --all";
    const listed = try common.expect_exit(session, out, step_name, ps, 0);
    checks.check_json(listed.streams.stdout, site, "/srv") catch |err| {
        return fail_step(out, step_name, "expected the mount and the user in ps's JSON", err);
    };
}

fn refused(
    session: *Session,
    out: *Io.Writer,
    flag: []const u8,
    code: []const u8,
    parts: []const []const u8,
) !void {
    const command = try common.format(session, "{s} run {s} alpine -- true", .{ zn, flag });
    const result = try common.run_shown(session, out, command);
    checks.check_refusal(result.streams, result.status, code, parts) catch |err| {
        return fail_step(out, step_name, command, err);
    };
}

fn refusals(session: *Session, out: *Io.Writer) !void {
    const title = "\n{s}: WRITABLE 4: outside the project, a link out, a missing source, a user\n";
    try out.print(title, .{H.demo_name});
    const outside_parts = [_][]const u8{ project, "outside the project", outside };
    try refused(session, out, "--mount ../outside-wr:/x", "E0212", &outside_parts);
    try refused(session, out, "--mount leak:/x", "E0212", &outside_parts);
    const etc_parts = [_][]const u8{ project, "outside the project", " is /etc," };
    try refused(session, out, "--mount etcdir:/x", "E0212", &etc_parts);
    const root_parts = [_][]const u8{ project, "outside the project", " is /," };
    try refused(session, out, "--mount /:/x", "E0212", &root_parts);
    const listed = try common.run_shown(session, out, "ls -A " ++ outside);
    checks.check_nothing_made(listed.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected nothing made outside the project", err);
    };
    const missing_parts = [_][]const u8{ "does not exist", "--mount nowhere" };
    try refused(session, out, "--mount nowhere:/x", "E0214", &missing_parts);
    const absent = H.as_demo ++ "sh -c 'test ! -e " ++ project ++ "/nowhere && echo not-made'";
    _ = try common.expect_exit(session, out, step_name, absent, 0);
    const user = zn ++ " run --name wr3 --mount site:/srv " ++ non_root ++ " -- id -u";
    const result = try common.run_shown(session, out, user);
    const user_parts = [_][]const u8{ "memcache", "--user 0", "--bind", "not yours" };
    checks.check_refusal(result.streams, result.status, "E0213", &user_parts) catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0213 naming the user and the fixes", err);
    };
}

fn root_flag(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: WRITABLE 5: the same image with --user 0\n", .{H.demo_name});
    const run = zn ++ " run --name wr4 --user 0 --mount site:/srv " ++ non_root ++ " -- sh -c " ++
        "'id -u; echo by-memcached > /srv/by-memcached.txt'";
    const inside = try common.run_shown(session, out, run);
    checks.check_root_run(inside.streams.stdout, inside.status) catch |err| {
        return fail_step(out, step_name, "expected the image to run as root", err);
    };
    const owners = try common.expect_exit(session, out, step_name, by_memcached_owns, 0);
    checks.check_owner(owners.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the host user to own the file", err);
    };
}

test {
    _ = @import("checks_writable_m6b.zig");
    _ = limits;
}
