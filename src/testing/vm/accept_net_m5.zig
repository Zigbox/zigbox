//! The acceptance checks of M5 (docs/briefs/M5-network.md), the ACCEPT part of demo-m5:
//!
//!   - The network checks of slices 2 and 3 (net_m5.zig, net_user_m5.zig): the namespace of its
//!     own, the generated files, `--net user` and `--publish`, a published port released after
//!     each exit path (a clean exit, `zbx stop`, `--timeout`, SIGKILL of the container and of
//!     zbx), and the host's rules unchanged across them. They were demo-m4's NET step until
//!     slice 4 moved them here.
//!   - A missing pasta, made with a `PATH` that lacks it (a directory of links to everything in
//!     /usr/bin but pasta and passt): `zbx doctor` warns on its `net` line and still exits 0,
//!     `zbx run --net user` and `--publish` are refused as ZBX-E0601 before a container exists,
//!     and `--net none` still runs.
//!
//! Every assertion is a function of checks_m5.zig or checks_spec_m5.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks_spec = @import("checks_spec_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net = @import("net_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;

const step_name = "ACCEPT";
const farm = "/tmp/nopasta";
/// `zbx` as the demo user with a `PATH` that has no pasta.
const z_without = H.as_demo ++ "PATH=" ++ farm ++ " /home/demo/z";

const make_farm = "rm -rf " ++ farm ++ " && mkdir " ++ farm ++ " && " ++
    "for f in /usr/bin/*; do case \"${f##*/}\" in pasta|pasta.avx2|passt|passt.avx2|" ++
    "passt.repair) ;; *) ln -sf \"$f\" " ++ farm ++ "/ ;; esac; done; chmod 755 " ++ farm ++
    "; ls " ++ farm ++ " | grep -c pasta; ls " ++ farm ++ " | wc -l";

pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try net.step_network(session, out, timer);
    try out.print("\n{s}: ACCEPT: a missing pasta\n", .{H.demo_name});
    try step_doctor_with(session, out);
    try make_path_without_pasta(session, out);
    try step_doctor_without(session, out);
    try step_run_without(session, out);
    try timer.lap(out, "no pasta");
}

fn step_doctor_with(session: *Session, out: *Io.Writer) !void {
    const result = try common.run_shown(session, out, z ++ " doctor");
    checks_spec.check_doctor_with_pasta(result.streams, result.status) catch |err| {
        return fail_step(out, step_name, "expected doctor's net line to be ok", err);
    };
}

pub fn make_path_without_pasta(session: *Session, out: *Io.Writer) !void {
    const result = try session.run(make_farm, limits.command_timeout_kvm_s);
    try H.show(out, "a PATH without pasta", result);
    // `grep -c` prints 0 and exits 1 when nothing matches; the farm must hold no pasta.
    if (!std.mem.startsWith(u8, result.output, "0\n")) {
        return fail_step(out, step_name, "the PATH still has pasta", error.PastaOnPath);
    }
}

fn step_doctor_without(session: *Session, out: *Io.Writer) !void {
    const result = try common.run_shown(session, out, z_without ++ " doctor");
    checks_spec.check_doctor_without_pasta(result.streams, result.status) catch |err| {
        return fail_step(out, step_name, "expected doctor to warn about pasta, exit 0", err);
    };
}

fn step_run_without(session: *Session, out: *Io.Writer) !void {
    const command = z_without ++ " run --net user alpine:3.20 -- true";
    const user = try common.run_shown(session, out, command);
    checks_spec.check_run_without_pasta(user.streams, user.status) catch |err| {
        return fail_step(out, step_name, "expected E0601 for --net user", err);
    };
    const publish = z_without ++ " run --publish 18090:80 alpine:3.20 -- true";
    const published = try common.run_shown(session, out, publish);
    checks_spec.check_run_without_pasta(published.streams, published.status) catch |err| {
        return fail_step(out, step_name, "expected E0601 for --publish", err);
    };
    // Without pasta, a container with no network or the host's still runs.
    _ = try common.expect_exit(session, out, step_name, z_without ++ " run alpine:3.20 -- true", 0);
    const host = z_without ++ " run --net host alpine:3.20 -- true";
    _ = try common.expect_exit(session, out, step_name, host, 0);
}

test {
    _ = @import("checks_spec_m5.zig");
    _ = @import("net_m5.zig");
}
