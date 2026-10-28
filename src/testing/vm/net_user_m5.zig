//! M5 slice 3's checks in the guest, the last part of demo-m4's NET step (net_m5.zig): user-mode
//! networking through pasta, which the VM installs (`passt`, cloud_init.zig).
//!
//!   `--net user`: the container's resolv.conf names pasta's DNS address, and `wget` of
//!   https://example.com works, DNS included, on a host whose own resolver is systemd-resolved's
//!   stub. `run --output json` says user and lists the forward.
//!   `--publish 8080:80` with nginx: `curl localhost:8080` on the guest gets nginx's page, and
//!   `ss -tlnpe` shows pasta listening, as the demo user.
//!   A port is free again after each exit path: a clean exit, `zbx stop`, `--timeout`, SIGKILL
//!   of the container, and SIGKILL of zbx itself (its supervisor, with the port published).
//!   `iptables -S` and `ip6tables -S` are the same before and after.
//!
//! nginx runs from a project directory of its own (`/home/demo/net-project`, its own zbx.lock),
//! so the steps after this one see the project's lock as they did. Every assertion is a function
//! of checks_m5.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks_m5 = @import("checks_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;

const step_name = "NET";
/// `zbx` as the demo user in the net project: the `z` wrapper with another directory.
const zn = H.as_demo ++ "/home/demo/zn";
const net_project = "/home/demo/net-project";
const nginx = "nginx:alpine";

const make_wrapper = "runuser -u demo -- mkdir -p " ++ net_project ++
    " && sed 's#" ++ common.project ++ "#" ++ net_project ++ "#' /home/demo/z > /home/demo/zn" ++
    " && chown demo:demo /home/demo/zn && chmod 755 /home/demo/zn && grep cd /home/demo/zn";

const rules = "(iptables -S; echo ---; ip6tables -S) 2>&1";

pub fn step_user(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m4: NET: --net user and --publish through pasta (M5 slice 3)\n", .{});
    const version = try session.run(H.as_demo ++ "pasta --version | head -1", 30);
    try H.show(out, "pasta --version", version);
    if (version.status != 0) {
        return fail_step(out, step_name, "pasta is not installed", error.NoPasta);
    }
    const made = try session.run(make_wrapper, limits.command_timeout_kvm_s);
    try H.show(out, "a wrapper for the net project", made);
    if (made.status != 0) return error.PrepareFailed;
    var before_storage: [8192]u8 = undefined;
    const before = try read_rules(session, out, &before_storage);
    try step_fetch(session, out);
    try step_publish(session, out);
    try step_exits(session, out);
    var after_storage: [8192]u8 = undefined;
    const after = try read_rules(session, out, &after_storage);
    checks_m5.check_rules_same(before, after) catch |err| {
        return fail_step(out, step_name, "expected the host's rules unchanged", err);
    };
}

fn read_rules(session: *Session, out: *Io.Writer, storage: []u8) ![]const u8 {
    const result = try session.run(rules, limits.command_timeout_kvm_s);
    try H.show(out, "the host's firewall rules", result);
    if (result.output.len > storage.len) return error.RulesTooLong;
    @memcpy(storage[0..result.output.len], result.output);
    return storage[0..result.output.len];
}

/// DNS and a connection out, through pasta; and the JSON line of a run with a forward, which
/// is also the clean exit: the port is free when it returns.
fn step_fetch(session: *Session, out: *Io.Writer) !void {
    const fetch = z ++ " run --net user alpine:3.20 -- sh -c " ++
        "'cat /etc/resolv.conf; wget -qO- https://example.com'";
    const fetched = try common.run_shown(session, out, fetch);
    checks_m5.check_user_fetch(fetched.streams, fetched.status) catch |err| {
        return fail_step(out, step_name, "expected pasta's DNS and example.com's page", err);
    };
    const json = z ++ " --output json run --publish 18081:80 alpine:3.20 -- true";
    const ran = try common.run_shown(session, out, json);
    checks_m5.check_json_published(ran.streams, ran.status, 18081, 80) catch |err| {
        return fail_step(out, step_name, "expected network user and the forward in JSON", err);
    };
    try expect_free(session, out, 18081, "after a clean exit");
}

/// nginx with `--publish 8080:80`, reached from the guest; pasta listens as the user.
fn step_publish(session: *Session, out: *Io.Writer) !void {
    const pulled = try common.run_shown(session, out, zn ++ " pull " ++ nginx);
    if (pulled.status != 0) return fail_step(out, step_name, "pull " ++ nginx, error.PullFailed);
    try start_nginx(session, out, "web8080", 8080);
    try expect_listening(session, out, 8080);
}

/// Starts nginx detached with a forward and waits for it to answer through the port.
fn start_nginx(session: *Session, out: *Io.Writer, name: []const u8, port: u16) !void {
    const command = try common.format(session, "{s} run -d --name {s} --publish {d}:80 {s}", .{
        zn, name, port, nginx,
    });
    _ = try common.expect_exit(session, out, step_name, command, 0);
    const curl = try common.format(session, "for i in $(seq 30); do " ++
        "curl -fsS http://localhost:{d}/ && break; sleep 1; done", .{port});
    const page = try session.run(curl, limits.command_timeout_kvm_s);
    try H.show(out, curl, page);
    checks_m5.check_nginx_page(page.output, page.status) catch |err| {
        return fail_step(out, step_name, "expected nginx's page through the published port", err);
    };
}

/// The four exit paths that remain: SIGKILL of zbx (web8080's supervisor), `zbx stop`,
/// `--timeout` and SIGKILL of the container. The port is free after each.
fn step_exits(session: *Session, out: *Io.Writer) !void {
    const kill_zbx = "pkill -KILL -u demo -f -- '--name web8080 '; sleep 1; " ++
        "pgrep -u demo -fa -- 'web8080' || echo 'no supervisor left'";
    const killed = try session.run(kill_zbx, limits.command_timeout_kvm_s);
    try H.show(out, "SIGKILL of zbx, the supervisor of web8080", killed);
    try expect_free(session, out, 8080, "after SIGKILL of zbx");
    // Not `-x pasta`: on amd64 the process is `pasta.avx2`.
    const left = try session.run("pgrep -u demo pasta | wc -l", limits.command_timeout_kvm_s);
    try H.show(out, "pasta processes left", left);
    if (!std.mem.eql(u8, std.mem.trim(u8, left.output, " \r\n"), "0")) {
        return fail_step(out, step_name, "expected no pasta left", error.PastaLeft);
    }

    try start_nginx(session, out, "web8081", 8081);
    _ = try common.expect_exit(session, out, step_name, zn ++ " stop web8081", 0);
    try expect_free(session, out, 8081, "after zbx stop");

    const timed = zn ++ " run --timeout 3000 --publish 8082:80 " ++ nginx ++ " >/dev/null";
    const result = try session.run(timed, limits.command_timeout_kvm_s);
    try H.show(out, timed, result);
    try expect_free(session, out, 8082, "after --timeout");

    try start_nginx(session, out, "web8083", 8083);
    // `ps` prints one document, every container on its one line: one object per line first.
    const pid_of = zn ++ " ps --output json | tr '{' '\\n' | grep '\"name\":\"web8083\"' | " ++
        "sed -n 's/.*\"pid\":\\([0-9]*\\),\"supervisor\".*/\\1/p'";
    const kill_container = "kill -KILL $(" ++ pid_of ++ ") && echo killed";
    const killed_container = try session.run(kill_container, limits.command_timeout_kvm_s);
    try H.show(out, "SIGKILL of web8083's PID 1", killed_container);
    if (killed_container.status != 0) return error.KillFailed;
    try expect_free(session, out, 8083, "after SIGKILL of the container");
}

/// `ss -tlnpe` as root shows pasta, as uid 1000, listening on `port`.
fn expect_listening(session: *Session, out: *Io.Writer, port: u16) !void {
    const command = try common.format(session, "ss -tlnpe | grep -E '^State|:{d} '", .{port});
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, command, result);
    checks_m5.check_listener(result.output, port, true) catch |err| {
        return fail_step(out, step_name, "expected pasta listening as the user", err);
    };
}

/// Waits up to five seconds for `port` to be free (pasta's own check of its namespace takes up
/// to a second), then checks it with `ss -tlnpe`.
fn expect_free(session: *Session, out: *Io.Writer, port: u16, why: []const u8) !void {
    const command = try common.format(session, "for i in $(seq 25); do " ++
        "ss -tln | grep -q ':{d} ' || break; sleep 0.2; done; " ++
        "ss -tlnpe | grep -E '^State|:{d} '", .{ port, port });
    const result = try session.run(command, limits.command_timeout_kvm_s);
    const title = try common.format(session, "port {d} {s}", .{ port, why });
    try H.show(out, title, result);
    checks_m5.check_listener(result.output, port, false) catch |err| {
        return fail_step(out, step_name, "expected the published port free again", err);
    };
}

test {
    _ = @import("checks_m5.zig");
}
