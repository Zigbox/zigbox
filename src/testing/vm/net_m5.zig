//! M5 slice 2's acceptance checks, in the guest, run by demo-m4 after its own steps (the network
//! namespace is what slice 2 adds, and `demo-m5` is slice 4's):
//!
//!   A container has a network namespace of its own: `ls /sys/class/net` lists `lo` alone and
//!   `ip link` says it is up. A web server on the guest's loopback is out of its reach, so
//!   `wget` fails, and zbx adds `zbx: network: none (grant with --net)` after wget's own line.
//!   `--net none` given explicitly fails the same way with no hint. `--net host` reaches the
//!   server and sees the host's interfaces.
//!   /etc/hosts and /etc/resolv.conf are generated and read-only; `run --output json` names the
//!   network; a commit of a container does not hold either file.
//!
//! Every assertion is a function of checks_m5.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks_m5 = @import("checks_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const checks_m3 = @import("checks_m3.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;

const port = "8099";
const url = "http://127.0.0.1:" ++ port ++ "/";
const page = "zbx-net-ok";
const step_name = "NET";

/// A web server on the guest's loopback, as the user: it answers with `page`.
const serve = "runuser -u demo -- sh -c 'mkdir -p /tmp/www && echo " ++ page ++
    " > /tmp/www/index.html && cd /tmp/www && " ++
    "(setsid python3 -m http.server " ++ port ++
    " --bind 127.0.0.1 </dev/null >/dev/null 2>&1 &)'; sleep 2; curl -fsS " ++ url;

pub fn step_network(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: NET: a network namespace of its own (M5 slice 2)\n", .{});
    const started = try session.run(serve, limits.command_timeout_kvm_s);
    try H.show(out, "a web server on the guest's loopback", started);
    if (started.status != 0 or std.mem.indexOf(u8, started.output, page) == null) {
        return fail_step(out, step_name, "the web server did not start", error.ServeFailed);
    }
    try step_interfaces(session, out);
    try step_reach(session, out);
    try step_files(session, out);
    try step_json(session, out);
    try step_commit(session, out);
    try timer.lap(out, "network");
}

fn step_interfaces(session: *Session, out: *Io.Writer) !void {
    const own = z ++ " run alpine:3.20 -- sh -c 'ls /sys/class/net; echo ---; ip -o link'";
    const result = try common.run_shown(session, out, own);
    checks_m5.check_only_loopback(result.streams, result.status) catch |err| {
        return fail_step(out, step_name, "expected lo alone, and up", err);
    };
    const host = z ++ " run --net host alpine:3.20 -- ls /sys/class/net";
    const shared = try common.run_shown(session, out, host);
    checks_m5.check_host_interfaces(shared.streams, shared.status) catch |err| {
        return fail_step(out, step_name, "expected the host's interfaces with --net host", err);
    };
}

fn step_reach(session: *Session, out: *Io.Writer) !void {
    const fetch = " alpine:3.20 -- wget -qO- " ++ url;
    const default = try common.run_shown(session, out, z ++ " run" ++ fetch);
    checks_m5.check_hint(default.streams, default.status, page) catch |err| {
        return fail_step(out, step_name, "expected wget to fail, then the hint last", err);
    };
    const none = try common.run_shown(session, out, z ++ " run --net none" ++ fetch);
    checks_m5.check_no_hint(none.streams, none.status, page) catch |err| {
        return fail_step(out, step_name, "expected wget to fail, and no hint", err);
    };
    const host = try common.run_shown(session, out, z ++ " run --net host" ++ fetch);
    checks_m5.check_page(host.streams, host.status, page) catch |err| {
        return fail_step(out, step_name, "expected --net host to fetch the page", err);
    };
}

fn step_files(session: *Session, out: *Io.Writer) !void {
    const script = " alpine:3.20 -- sh -c 'cat /etc/hosts; echo ---; cat /etc/resolv.conf; " ++
        "echo ---; (echo x >> /etc/hosts) 2>&1'";
    const own = try common.run_shown(session, out, z ++ " run --name gen2" ++ script);
    checks_m5.check_generated_files(own.streams, own.status, "gen2", false) catch |err| {
        return fail_step(out, step_name, "expected hosts, no nameserver, read-only", err);
    };
    const host = try common.run_shown(session, out, z ++ " run --net host --name gen4" ++ script);
    checks_m5.check_generated_files(host.streams, host.status, "gen4", true) catch |err| {
        return fail_step(out, step_name, "expected the host's nameserver with --net host", err);
    };
}

fn step_json(session: *Session, out: *Io.Writer) !void {
    const none = try common.run_shown(session, out, z ++ " --output json run alpine:3.20 -- true");
    checks_m5.check_json_network(none.streams, none.status, "none") catch |err| {
        return fail_step(out, step_name, "expected network none in the JSON line", err);
    };
    const host_command = z ++ " --output json run --net host alpine:3.20 -- true";
    const host = try common.run_shown(session, out, host_command);
    checks_m5.check_json_network(host.streams, host.status, "host") catch |err| {
        return fail_step(out, step_name, "expected network host in the JSON line", err);
    };
}

/// A container writes one file and is committed; the diff against the image's tree lists that
/// file and neither generated one.
fn step_commit(session: *Session, out: *Io.Writer) !void {
    const read = try session.run(
        "grep -A4 'alpine:3.20' " ++ common.project ++ "/zbx.lock | grep -o 'b3:[0-9a-f]*'",
        limits.command_timeout_kvm_s,
    );
    const found = std.mem.trim(u8, read.output, " \r\n");
    if (found.len != 67) return error.LockTreeNotFound;
    var tree_storage: [67]u8 = undefined;
    @memcpy(&tree_storage, found);
    const tree: []const u8 = &tree_storage;
    const run = z ++ " run --name gen3 alpine:3.20 -- sh -c 'echo hi > /root/note'";
    _ = try common.expect_exit(session, out, step_name, run, 0);
    const committed = try common.run_shown(session, out, z ++ " commit gen3");
    const digest = checks_m3.check_changed(committed.streams, committed.status, tree) catch |err| {
        return fail_step(out, step_name, "expected a new tree from the commit", err);
    };
    const command = try common.format(session, "{s} store diff {s} {s}", .{ z, tree, digest });
    const listed = try common.run_shown(session, out, command);
    checks_m5.check_commit_diff(listed.streams, listed.status, "/root/note") catch |err| {
        return fail_step(out, step_name, "expected /root/note, and neither /etc file", err);
    };
}

test {
    _ = @import("checks_m5.zig");
}
