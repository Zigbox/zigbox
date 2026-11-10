//! The M8 upgrade test, in the guest: the merged v0.3.1 `zbx` (the commit `m8_tag` in
//! `old_release.zon`) pulls `alpine:3.20` in the project directory (which writes `zbx.lock`) and
//! starts a detached container with a `--state` volume that writes a file into it and a line
//! to its log. This `zbx` then reads and uses what it left, while the container still runs:
//!
//!   - `store ls`, `store verify` and `lock show` read v0.3.1's store, version-2 image record
//!     and lock;
//!   - `ps --output json` lists the container as running, from a version-8 run record (what
//!     this `zbx` writes too), and `state ls` shows the volume in use by it;
//!   - `exec` into that container, which this `zbx` did not start, reads the file the old one
//!     wrote through the volume, as root; `logs` of it shows the line (v0.3.1 keeps logs);
//!   - `zbx stop` ends it, the volume's lock is free, `exec` is now ZBX-E0220, and the record is
//!     listed stopped beside the one this `zbx` writes;
//!   - this `zbx` runs the image with the same volume and reads the file.
//!
//! Two more things come from the old binary, in the same project directory:
//!
//!   - a build with the old binary (one step on alpine) fills the build cache; this `zbx` builds
//!     the same file and finds the step in that cache (`hit`), and its provenance record is
//!     complete (the step and its base) though the old binary wrote none;
//!   - a policy that requires a signature refuses the image the old binary pulled (E0905).
//!
//! Every assertion is a function of checks_m8.zig, checks_upgrade_m6b.zig, checks_upgrade_m5.zig,
//! checks_writable_m6b.zig, checks_exec_m6b.zig, checks_state_m6.zig or checks_m4.zig with a
//! unit test.

const std = @import("std");
const Io = std.Io;
const agent_json = @import("agent_json.zig");
const checks_exec = @import("checks_exec_m6b.zig");
const checks_up5 = @import("checks_upgrade_m5.zig");
const checks_up6 = @import("checks_upgrade_m6.zig");
const checks = @import("checks_upgrade_m6b.zig");

/// The run record version v0.3.1 wrote; this binary reads it as it is and writes its own.
// v0.3.1 writes run record version 8 (constants.zig at the tag).
const run_record_version_old: u32 = 8;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const m4 = @import("checks_m4.zig");
const m8 = @import("checks_m8.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");
const up5 = @import("upgrade_m5.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const step = "UPGRADE8";
const alpine = "alpine:3.20";
const volume = "oldvol";
const container = "m8old";
const marker = "from-m8";
const log_line = "m8-old-log-line";
const no_input = " </dev/null";

/// The v0.3.1 `zbx` as the demo user, in the project directory, with the registry mirror named.
const zbx_old = up5.zbx_old;

const start_old = zbx_old ++ " run -d --name " ++ container ++ " --state " ++ volume ++
    ":/data " ++ alpine ++ " -- sh -c 'echo " ++ log_line ++ "; echo " ++ marker ++
    " > /data/marker; sleep 1000'";
/// `exec` reads the marker, waiting up to thirty seconds for the old container to have written it.
const read_marker = "for i in $(seq 30); do " ++ z ++ " exec " ++ container ++
    " -- cat /data/marker" ++ no_input ++ " && break; sleep 1; done";

pub fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const title = "\n{s}: UPGRADE8: the v0.3.1 binary leaves a store, a lock, a container\n";
    try out.print(title, .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    const pull = try old_makes(session, out);
    try read_store(session, out, pull);
    try read_running(session, out);
    try exec_and_logs(session, out);
    try stop_and_reuse(session, out);
    try old_cache_reused(session, out);
    try old_image_under_policy(session, out);
    try timer.lap(out, "upgrade8");
}

/// The v0.3.1 binary pulls alpine and starts the detached container with a new volume.
fn old_makes(session: *Session, out: *Io.Writer) !m4.PullDoc {
    const arena = session.scratch_allocator();
    const pulled = try expect_exit(session, out, step, zbx_old ++ " --output json pull " ++
        alpine, 0);
    const pull = m4.check_pull_json(arena, pulled.streams, pulled.status, alpine) catch |err| {
        return fail_step(out, step, "expected the v0.3.1 pull as JSON", err);
    };
    try up5.expect_record_version(session, out, pull, checks.image_record_version);
    _ = try expect_exit(session, out, step, start_old, 0);
    return pull;
}

/// `store ls`, `store verify` and `lock show` read what the v0.3.1 binary left.
fn read_store(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    const arena = session.scratch_allocator();
    const ls = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const roots = [_][]const u8{pull.tree};
    const check = checks_up5.check_image_listed;
    check(arena, ls.streams, ls.status, pull, &.{alpine}, &roots) catch |err| {
        return fail_step(out, step, "expected store ls to list v0.3.1's alpine with its tag", err);
    };
    const shown = try expect_exit(session, out, step, z ++ " --output json lock show", 0);
    const read = agent_json.check_lock_show(arena, shown.streams, shown.status, alpine);
    const entry = read catch |err| {
        return fail_step(out, step, "expected lock show to read v0.3.1's lock", err);
    };
    checks_up5.check_lock_entry(entry, common.project ++ "/zbx.lock", pull) catch |err| {
        return fail_step(out, step, "expected v0.3.1's lock entry to be what the pull said", err);
    };
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 1) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
}

/// The old container's record (v0.3.1's version) and volume, read by this binary while it runs.
fn read_running(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const ps = try expect_exit(session, out, step, z ++ " --output json ps", 0);
    const found = checks.check_old_running(arena, ps.streams.stdout, ps.status, container);
    _ = found catch |err| {
        return fail_step(out, step, "expected ps to list the v0.3.1 container running", err);
    };
    const version = try common.format(session, "grep -h version {s}/runs/{s}.zon", .{
        common.state_dir, container,
    });
    const record = try session.run(version, limits.command_timeout_kvm_s);
    try H.show(out, version, record);
    checks_up5.check_record_version(record.output, run_record_version_old) catch |err| {
        return fail_step(out, step, "expected the run record to be v0.3.1's version", err);
    };
    try state.listing(session, out, .{
        .name = volume,
        .last_container = container,
        .in_use = true,
        .user = container,
        .disk_bytes_min = 1,
    }, "expected oldvol in use by the v0.3.1 container");
}

/// `exec` into a container this binary did not start; `logs` of one that has none.
fn exec_and_logs(session: *Session, out: *Io.Writer) !void {
    const read = try expect_exit(session, out, step, read_marker, 0);
    m4.check_output_is(read.streams, read.status, marker) catch |err| {
        return fail_step(out, step, "expected exec to read what v0.3.1 wrote to the volume", err);
    };
    const who = z ++ " exec " ++ container ++ " -- id -u" ++ no_input;
    const id = try expect_exit(session, out, step, who, 0);
    m4.check_output_is(id.streams, id.status, "0") catch |err| {
        return fail_step(out, step, "expected the exec to be root, as the container is", err);
    };
    const logs = try expect_exit(session, out, step, z ++ " logs " ++ container, 0);
    if (!log_has_line(logs.streams.stdout)) {
        return fail_step(
            out,
            step,
            "expected logs to show what v0.3.1's container printed",
            error.LogWrong,
        );
    }
}

/// `stop` ends the old container; this binary uses the volume v0.3.1 made.
fn stop_and_reuse(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    _ = try state.expect_long(session, out, z ++ " stop " ++ container, 0, 60);
    try state.expect_volume_free(session, out, volume, "after zbx stopped the v0.3.1 container");
    const exec = try common.run_shown(session, out, z ++ " exec " ++ container ++ " -- true" ++
        no_input);
    checks_exec.check_stopped(exec.streams, exec.status) catch |err| {
        return fail_step(out, step, "expected ZBX-E0220 for the stopped v0.3.1 container", err);
    };
    const run = z ++ " run --name m8new --state " ++ volume ++ ":/data " ++ alpine ++
        " -- cat /data/marker";
    const used = try expect_exit(session, out, step, run, 0);
    m4.check_output_is(used.streams, used.status, marker) catch |err| {
        return fail_step(out, step, "expected v0.3.1's volume to hold the file", err);
    };
    const listed = try expect_exit(session, out, step, z ++ " --output json ps --all", 0);
    const wants = [_]checks_up6.Want{
        .{ .name = container, .network = "none" },
        .{ .name = "m8new", .network = "none" },
    };
    checks_up6.check_ps_records(arena, listed.streams.stdout, listed.status, &wants) catch |err| {
        return fail_step(
            out,
            step,
            "expected ps --all to list v0.3.1's record and the new one",
            err,
        );
    };
    const names = [_][]const u8{ container, "m8new" };
    const versions = [_]u32{ run_record_version_old, checks.run_record_version };
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

const build_file =
    \\.{ .version = 1,
    \\  .steps = .{ .{ .name = "probe", .base = "alpine:3.20", .inputs = .{"in.txt"},
    \\    .run = .{ "sh", "-c", "cp in.txt /out/" } } },
    \\  .image = .{ .base = "alpine:3.20", .add = .{ .{ .from = "probe", .to = "/" } } } }
    \\
;

/// The old binary builds a one-step file; this binary builds it again from the old cache and
/// writes complete provenance.
fn old_cache_reused(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    try H.put_file(session, common.project ++ "/in.txt", "from the old build\n");
    try H.put_file(session, common.project ++ "/zbx.build.zon", build_file);
    _ = try expect_exit(session, out, step, zbx_old ++ " build", 0);
    const built = try expect_exit(session, out, step, z ++ " --output json build", 0);
    m8.check_old_cache_hit(built.streams.stdout, "probe") catch |err| {
        return fail_step(out, step, "expected this build to find the old binary's cache", err);
    };
    const printed = m8.build_result(built.streams.stdout) catch |err| {
        return fail_step(out, step, "expected the build to print its result", err);
    };
    // The next command reuses the output buffer `printed` points into.
    const result = try arena.dupe(u8, printed);
    const command = try common.format(session, z ++ " inspect --provenance {s} --output json", .{
        result,
    });
    const shown = try expect_exit(session, out, step, command, 0);
    const checked = m8.check_cached_provenance(arena, shown.streams.stdout, result, "probe", 1);
    checked catch |err| {
        return fail_step(out, step, "expected complete provenance for the cached build", err);
    };
}

/// A config directory of its own: the key made here must not be one more key for TRUST8's `sign`.
const config_dir = "/home/demo/upc";
const zc = H.as_demo ++ "XDG_CONFIG_HOME=" ++ config_dir ++ " /home/demo/z";
const policy_path = config_dir ++ "/zbx/policy.zon";

/// A policy that requires a signature refuses what the old binary pulled, in one line.
fn old_image_under_policy(session: *Session, out: *Io.Writer) !void {
    _ = try expect_exit(session, out, step, zc ++ " key new m8up --no-passphrase", 0);
    const shown = try expect_exit(session, out, step, zc ++ " --output json key show m8up", 0);
    const public = m8.public_of_key_show(shown.streams.stdout) orelse {
        return fail_step(out, step, "expected key show to name the key", error.KeyWrong);
    };
    const text = try common.format(session, ".{{ .version = 1, .keys = .{{ .{{ .name = " ++
        "\"up\", .public = \"{s}\" }} }},\n  .require_signature = true," ++
        " .require_provenance = false }}\n", .{public});
    const mkdir = "mkdir -p " ++ config_dir ++ "/zbx && chown -R demo " ++ config_dir;
    _ = try session.run(mkdir, limits.command_timeout_kvm_s);
    try H.put_file(session, policy_path, text);
    const refused = try common.run_shown(session, out, zc ++ " run " ++ alpine ++ " -- true");
    _ = try session.run("rm -f " ++ policy_path, limits.command_timeout_kvm_s);
    m8.check_old_image_refused(refused.streams.stderr, refused.status, policy_path) catch |err| {
        return fail_step(out, step, "expected the policy to refuse the old image", err);
    };
}

/// Whether the log text of the old container holds the line it printed.
pub fn log_has_line(log: []const u8) bool {
    return std.mem.indexOf(u8, log, log_line) != null;
}

test "the old container's log is read for its line" {
    // Goal: the line is found among others, and an empty or other log is not.
    try std.testing.expect(log_has_line("t 1 stdout " ++ log_line ++ "\n"));
    try std.testing.expect(!log_has_line(""));
    try std.testing.expect(!log_has_line("other\n"));
}
