//! The spec's four steps of M5, exactly as the spec types them, run as the user `demo` in the
//! guest (docs/SPEC.md, M5; docs/briefs/M5-network.md):
//!
//!   1. `zbx run alpine -- wget -qO- https://example.com` fails, and the last line of stderr is
//!      `zbx: network: none (grant with --net)`.
//!   2. `zbx run --net user alpine -- wget -qO- https://example.com` prints the page.
//!   3. `zbx run --publish 8080:80 nginx`, in the background (`-d`), and `curl localhost:8080`
//!      on the guest returns the nginx welcome page.
//!   4. `ss -tlnp` as the demo user shows the listener on 8080 and `ss -tlnpe` that its owner is
//!      the demo user (the process column is empty for the user: pasta is undumpable), and
//!      as root `ss -tlnpe` names pasta; `iptables -S` as root is the same before step 1 and
//!      after step 3.
//!
//! The image names are the spec's: `alpine` and `nginx`, which are `alpine:latest` and
//! `nginx:latest`. A name needs an entry in `zbx.lock` (a run without one is ZBX-E0522), so
//! `zbx pull alpine` and `zbx pull nginx` come first, as they would for a person; they are in the
//! net project's own lock (`/home/demo/net-project`), so the demo project's lock is unchanged.
//! The pulls go through the registry mirror the wrapper names.
//!
//! Every assertion is a function of checks_m5.zig or checks_spec_m5.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks_m5 = @import("checks_m5.zig");
const checks_spec = @import("checks_spec_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "SPEC";
const port: u16 = 8080;
const container = "spec-nginx";
const fetch = " alpine -- wget -qO- https://example.com";

/// The firewall rules before step 1, kept for the comparison after step 3 and the one at the
/// end of the demo (`expect_rules_unchanged`): "no rule added, ever".
var rules_storage: [8192]u8 = undefined;
var rules_len: usize = 0;

pub fn step_spec(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: SPEC: the four steps of the spec\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    const before = try net_user.read_rules(session, out, &rules_storage);
    checks_spec.check_rules_read(before) catch |err| {
        return fail_step(out, step_name, "expected iptables to print the built-in chains", err);
    };
    rules_len = before.len;
    try pull_images(session, out);
    try step_one(session, out);
    try step_two(session, out);
    try step_three(session, out);
    try step_four(session, out);
    try stop_server(session, out);
    try timer.lap(out, "spec");
}

fn pull_images(session: *Session, out: *Io.Writer) !void {
    const names = [_][]const u8{ "alpine", "nginx" };
    for (names) |name| {
        const command = try common.format(session, "{s} pull {s}", .{ zn, name });
        _ = try common.expect_exit(session, out, step_name, command, 0);
    }
}

fn step_one(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 1: zbx run alpine, no network granted\n", .{H.demo_name});
    const result = try common.run_shown(session, out, zn ++ " run" ++ fetch);
    checks_m5.check_hint(result.streams, result.status, "Example Domain") catch |err| {
        return fail_step(out, "SPEC 1", "expected wget to fail, the hint last", err);
    };
}

fn step_two(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 2: zbx run --net user alpine\n", .{H.demo_name});
    const result = try common.run_shown(session, out, zn ++ " run --net user" ++ fetch);
    checks_spec.check_example_page(result.streams, result.status) catch |err| {
        return fail_step(out, "SPEC 2", "expected example.com's page", err);
    };
}

fn step_three(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 3: zbx run --publish 8080:80 nginx, in the background\n", .{
        H.demo_name,
    });
    // The helper runs `zbx run -d --name <name> --publish 8080:80 <image>` and curls the port.
    net_user.start_nginx(session, out, container, port, "nginx") catch |err| {
        return fail_step(out, "SPEC 3", "expected nginx's page on localhost:8080", err);
    };
}

fn step_four(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: SPEC 4: ss -tlnp as the demo user, and the firewall rules\n", .{
        H.demo_name,
    });
    const listing = try session.run(H.as_demo ++ "ss -tlnp", limits.command_timeout_kvm_s);
    try H.show(out, "ss -tlnp, as the demo user", listing);
    checks_spec.check_listener_listed(listing.output, port) catch |err| {
        return fail_step(out, "SPEC 4", "expected a listener on 8080", err);
    };
    // The process column is empty for the user (pasta is undumpable), so the owner is read from
    // the socket with -e, and the process from the root listing below.
    const command = H.as_demo ++ "ss -tlnpe";
    const owned = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "ss -tlnpe, as the demo user", owned);
    checks_spec.check_listener_owned(owned.output, port) catch |err| {
        return fail_step(out, "SPEC 4", "expected the listener to be the demo user's", err);
    };
    try net_user.expect_listening(session, out, port);
    try expect_rules_unchanged(session, out);
}

/// The rules now are the rules before step 1.
pub fn expect_rules_unchanged(session: *Session, out: *Io.Writer) !void {
    var after_storage: [8192]u8 = undefined;
    const after = try net_user.read_rules(session, out, &after_storage);
    checks_m5.check_rules_same(rules_storage[0..rules_len], after) catch |err| {
        return fail_step(out, step_name, "expected the host's rules unchanged", err);
    };
}

fn stop_server(session: *Session, out: *Io.Writer) !void {
    const command = try common.format(session, "{s} stop {s}", .{ zn, container });
    _ = try common.expect_exit(session, out, step_name, command, 0);
    try net_user.expect_free(session, out, port, "after the spec's server stopped");
}

test {
    _ = @import("checks_spec_m5.zig");
}
