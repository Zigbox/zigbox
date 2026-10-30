//! The M6b upgrade test, in the guest: the merged M6 `zbx` (the commit `m6b_commit` in
//! `old_release.zon`) pulls `alpine:3.20` in the project directory (which writes `zbx.lock`) and
//! starts a detached container with a new `--state` volume that writes a file into it. This
//! `zbx` then reads and uses what it left, while the container still runs:
//!
//!   - `store ls`, `store verify` and `lock show` read M6's store, version-2 image record and
//!     lock;
//!   - `ps --output json` lists the container as running, from a version-7 run record (this
//!     `zbx` writes 8), with its pid and scope; `state ls` shows the volume in use by it;
//!   - `exec` into that container, which this `zbx` did not start, reads the file the old one
//!     wrote through the volume, as root, and fails nothing for want of a field the record lacks;
//!   - `logs` of it is ZBX-E0217 (a record and no log: M6 kept none), a coded error, not a crash;
//!   - `zbx stop` ends it, the volume's lock is free, `exec` is now ZBX-E0220, and the record is
//!     listed stopped beside the one this `zbx` writes (version 8);
//!   - this `zbx` runs the image with the same volume and reads the file: M6's volume is whole.
//!
//! Every assertion is a function of checks_upgrade_m6b.zig, checks_upgrade_m5.zig,
//! checks_writable_m6b.zig, checks_exec_m6b.zig, checks_state_m6.zig or checks_m4.zig with a unit
//! test.

const std = @import("std");
const Io = std.Io;
const agent_json = @import("agent_json.zig");
const checks_exec = @import("checks_exec_m6b.zig");
const checks_up5 = @import("checks_upgrade_m5.zig");
const checks_up6 = @import("checks_upgrade_m6.zig");
const checks = @import("checks_upgrade_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const m4 = @import("checks_m4.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");
const up5 = @import("upgrade_m5.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const step = "UPGRADE6B";
const alpine = "alpine:3.20";
const volume = "oldvol";
const container = "m6bold";
const marker = "from-m6";
const no_input = " </dev/null";

/// The M6 `zbx` as the demo user, in the project directory, with the registry mirror named.
const zbx_old = up5.zbx_old;

const start_old = zbx_old ++ " run -d --name " ++ container ++ " --state " ++ volume ++
    ":/data " ++ alpine ++ " -- sh -c 'echo " ++ marker ++ " > /data/marker; sleep 1000'";
/// `exec` reads the marker, waiting up to thirty seconds for the old container to have written it.
const read_marker = "for i in $(seq 30); do " ++ z ++ " exec " ++ container ++
    " -- cat /data/marker" ++ no_input ++ " && break; sleep 1; done";

pub fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const title = "\n{s}: UPGRADE6B: the M6 binary leaves a store, a lock, a container\n";
    try out.print(title, .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    const pull = try old_makes(session, out);
    try read_store(session, out, pull);
    try read_running(session, out);
    try exec_and_logs(session, out);
    try stop_and_reuse(session, out);
    try timer.lap(out, "upgrade6b");
}

/// The M6 binary pulls alpine and starts the detached container with a new volume.
fn old_makes(session: *Session, out: *Io.Writer) !m4.PullDoc {
    const arena = session.scratch_allocator();
    const pulled = try expect_exit(session, out, step, zbx_old ++ " --output json pull " ++
        alpine, 0);
    const pull = m4.check_pull_json(arena, pulled.streams, pulled.status, alpine) catch |err| {
        return fail_step(out, step, "expected the M6 pull as JSON", err);
    };
    try up5.expect_record_version(session, out, pull, checks.image_record_version);
    _ = try expect_exit(session, out, step, start_old, 0);
    return pull;
}

/// `store ls`, `store verify` and `lock show` read what the M6 binary left.
fn read_store(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    const arena = session.scratch_allocator();
    const ls = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const roots = [_][]const u8{pull.tree};
    const check = checks_up5.check_image_listed;
    check(arena, ls.streams, ls.status, pull, &.{alpine}, &roots) catch |err| {
        return fail_step(out, step, "expected store ls to list M6's alpine with its tag", err);
    };
    const shown = try expect_exit(session, out, step, z ++ " --output json lock show", 0);
    const read = agent_json.check_lock_show(arena, shown.streams, shown.status, alpine);
    const entry = read catch |err| {
        return fail_step(out, step, "expected lock show to read M6's lock", err);
    };
    checks_up5.check_lock_entry(entry, common.project ++ "/zbx.lock", pull) catch |err| {
        return fail_step(out, step, "expected M6's lock entry to be what the pull said", err);
    };
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 1) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
}

/// The old container's record (version 7) and volume, read by this binary while it runs.
fn read_running(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const ps = try expect_exit(session, out, step, z ++ " --output json ps", 0);
    const found = checks.check_old_running(arena, ps.streams.stdout, ps.status, container);
    _ = found catch |err| {
        return fail_step(out, step, "expected ps to list the M6 container running", err);
    };
    const version = try common.format(session, "grep -h version {s}/runs/{s}.zon", .{
        common.state_dir, container,
    });
    const record = try session.run(version, limits.command_timeout_kvm_s);
    try H.show(out, version, record);
    checks_up5.check_record_version(record.output, checks.run_record_version_m6) catch |err| {
        return fail_step(out, step, "expected the run record to be version 7", err);
    };
    try state.listing(session, out, .{
        .name = volume,
        .last_container = container,
        .in_use = true,
        .user = container,
        .disk_bytes_min = 1,
    }, "expected oldvol in use by the M6 container");
}

/// `exec` into a container this binary did not start; `logs` of one that has none.
fn exec_and_logs(session: *Session, out: *Io.Writer) !void {
    const read = try expect_exit(session, out, step, read_marker, 0);
    m4.check_output_is(read.streams, read.status, marker) catch |err| {
        return fail_step(out, step, "expected exec to read what M6 wrote to the volume", err);
    };
    const who = z ++ " exec " ++ container ++ " -- id -u" ++ no_input;
    const id = try expect_exit(session, out, step, who, 0);
    m4.check_output_is(id.streams, id.status, "0") catch |err| {
        return fail_step(out, step, "expected the exec to be root, as the container is", err);
    };
    const logs = try common.run_shown(session, out, z ++ " logs " ++ container);
    checks.check_no_log(logs.streams, logs.status, container) catch |err| {
        return fail_step(out, step, "expected ZBX-E0217 for a container M6 started", err);
    };
}

/// `stop` ends the old container; this binary uses the volume M6 made.
fn stop_and_reuse(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    _ = try state.expect_long(session, out, z ++ " stop " ++ container, 0, 60);
    try state.expect_volume_free(session, out, volume, "after zbx stopped the M6 container");
    const exec = try common.run_shown(session, out, z ++ " exec " ++ container ++ " -- true" ++
        no_input);
    checks_exec.check_stopped(exec.streams, exec.status) catch |err| {
        return fail_step(out, step, "expected ZBX-E0220 for the stopped M6 container", err);
    };
    const run = z ++ " run --name m6bnew --state " ++ volume ++ ":/data " ++ alpine ++
        " -- cat /data/marker";
    const used = try expect_exit(session, out, step, run, 0);
    m4.check_output_is(used.streams, used.status, marker) catch |err| {
        return fail_step(out, step, "expected M6's volume to hold the file", err);
    };
    const listed = try expect_exit(session, out, step, z ++ " --output json ps --all", 0);
    const wants = [_]checks_up6.Want{
        .{ .name = container, .network = "none" },
        .{ .name = "m6bnew", .network = "none" },
    };
    checks_up6.check_ps_records(arena, listed.streams.stdout, listed.status, &wants) catch |err| {
        return fail_step(out, step, "expected ps --all to list M6's record and the new one", err);
    };
    const names = [_][]const u8{ container, "m6bnew" };
    const versions = [_]u32{ checks.run_record_version_m6, checks.run_record_version };
    for (names, versions) |name, version| {
        const command = try common.format(session, "grep -h version {s}/runs/{s}.zon", .{
            common.state_dir, name,
        });
        const record = try session.run(command, limits.command_timeout_kvm_s);
        try H.show(out, command, record);
        checks_up5.check_record_version(record.output, version) catch |err| {
            return fail_step(out, step, "expected the run record of its own version", err);
        };
    }
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 1) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
}

test {
    _ = @import("checks_upgrade_m6b.zig");
}
