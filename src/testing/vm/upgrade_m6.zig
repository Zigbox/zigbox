//! The M6 upgrade test, in the guest: the merged M5 `zbx` (the commit `m6_commit` in
//! `old_release.zon`) pulls `alpine:3.20` in the project directory (which writes `zbx.lock`),
//! runs it with `--net user`, commits a change, and pulls `postgres:16`. This `zbx` then reads
//! what it left:
//!
//!   - `store ls` lists both version-2 image records with their tags, and the trees; `store
//!     verify` finds no damage; `lock show` reads M5's `zbx.lock` with both entries;
//!   - the images run by tag, by manifest digest and (the commit) by tree digest, alpine with
//!     the default `--net none`;
//!   - M5's run record (version 4, no network) is listed beside this binary's own (version 6) by
//!     `ps --all`, in text and as JSON;
//!   - postgres runs with a new `--state` volume on M5's store, published on port 15432 (the spec
//!     part uses 5432); `psql` writes a row; `state ls` shows the volume in use; `zbx stop`
//!     ends it, the lock is free and `store verify` is still clean.
//!
//! Every assertion is a function of checks_upgrade_m6.zig, checks_upgrade_m5.zig,
//! checks_state_m6.zig, checks_spec_m6.zig, checks_m5.zig or checks_m4.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const agent_json = @import("agent_json.zig");
const checks_m5 = @import("checks_m5.zig");
const checks_spec = @import("checks_spec_m6.zig");
const checks_state = @import("checks_state_m6.zig");
const checks_up5 = @import("checks_upgrade_m5.zig");
const checks = @import("checks_upgrade_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const m3 = @import("checks_m3.zig");
const m4 = @import("checks_m4.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");
const up5 = @import("upgrade_m5.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const step = "UPGRADE";
const alpine = "alpine:3.20";
const postgres = "postgres:16";
const port: u16 = 15432;
const volume = "upstate";
const start_pg = z ++ " run -d --name m6pg --state upstate:/var/lib/postgresql/data" ++
    " --publish 15432:5432 -e POSTGRES_PASSWORD=demo " ++ postgres;

/// The M5 `zbx` as the demo user, in the project directory, with the registry mirror named.
pub const zbx_old = up5.zbx_old;

const Made = struct { alpine: m4.PullDoc, postgres: m4.PullDoc, child: []const u8 };

pub fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: UPGRADE: the M5 binary leaves a store, records and a lock\n", .{
        H.demo_name,
    });
    const made = try old_makes(session, out);
    try read_store(session, out, made);
    try run_images(session, out, made);
    try read_run_records(session, out);
    try postgres_state(session, out);
    try verify(session, out);
    try timer.lap(out, "upgrade");
}

/// The M5 binary pulls, runs with `--net user`, commits, and pulls postgres.
fn old_makes(session: *Session, out: *Io.Writer) !Made {
    const arena = session.scratch_allocator();
    const pulled = try expect_exit(session, out, step, zbx_old ++ " --output json pull " ++
        alpine, 0);
    const pull = m4.check_pull_json(arena, pulled.streams, pulled.status, alpine) catch |err| {
        return fail_step(out, step, "expected the M5 pull as JSON", err);
    };
    const run = zbx_old ++ " run --net user --name m5up1 " ++ alpine ++
        " -- sh -c 'wget -qO /dev/null https://example.com && echo upgraded > /marker'";
    _ = try expect_exit(session, out, step, run, 0);
    const committed = try expect_exit(session, out, step, zbx_old ++ " commit m5up1", 0);
    const changed = m3.check_changed(committed.streams, committed.status, pull.tree);
    const child_text = changed catch |err| {
        return fail_step(out, step, "expected a new tree from the M5 commit", err);
    };
    const child = try arena.dupe(u8, child_text);
    try up5.expect_record_version(session, out, pull, checks.image_record_version);
    const pg_command = zbx_old ++ " --output json pull " ++ postgres;
    const pg_pulled = try state.expect_long_split(session, out, pg_command, 0, 900);
    const pg_streams = pg_pulled.streams;
    const pg = m4.check_pull_json(arena, pg_streams, pg_pulled.status, postgres) catch |err| {
        return fail_step(out, step, "expected the M5 pull of postgres as JSON", err);
    };
    return .{ .alpine = pull, .postgres = pg, .child = child };
}

/// `store ls`, `store verify` and `lock show` read what the M5 binary left.
fn read_store(session: *Session, out: *Io.Writer, made: Made) !void {
    const arena = session.scratch_allocator();
    const ls = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const roots = [_][]const u8{ made.alpine.tree, made.child, made.postgres.tree };
    const check = checks_up5.check_image_listed;
    const listed = check(arena, ls.streams, ls.status, made.alpine, &.{alpine}, &roots);
    listed catch |err| {
        return fail_step(out, step, "expected store ls to list M5's alpine with its tag", err);
    };
    const pg_listed = check(arena, ls.streams, ls.status, made.postgres, &.{postgres}, &roots);
    pg_listed catch |err| {
        return fail_step(out, step, "expected store ls to list M5's postgres with its tag", err);
    };
    try read_lock(session, out, made.alpine);
    try read_lock(session, out, made.postgres);
    try verify(session, out);
}

fn read_lock(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    const arena = session.scratch_allocator();
    const shown = try expect_exit(session, out, step, z ++ " --output json lock show", 0);
    const read = agent_json.check_lock_show(arena, shown.streams, shown.status, pull.reference);
    const entry = read catch |err| {
        return fail_step(out, step, "expected lock show to read M5's lock", err);
    };
    const path = common.project ++ "/zbx.lock";
    checks_up5.check_lock_entry(entry, path, pull) catch |err| {
        return fail_step(out, step, "expected M5's lock entry to be what the pull said", err);
    };
}

/// The images run by tag and by manifest digest; the commit by tree digest.
fn run_images(session: *Session, out: *Io.Writer, made: Made) !void {
    const by_tag = z ++ " run " ++ alpine ++ " -- sh -c 'ls /sys/class/net; echo ---; ip -o link'";
    const tagged = try common.run_shown(session, out, by_tag);
    checks_m5.check_only_loopback(tagged.streams, tagged.status) catch |err| {
        return fail_step(out, step, "expected the run by tag to have lo alone", err);
    };
    var buffer: [128]u8 = undefined;
    const manifest = made.alpine.manifest_digest;
    const spelled = checks_up5.digest_reference(&buffer, "alpine", manifest) catch |err| {
        return fail_step(out, step, "the digest reference", err);
    };
    const pattern = "{s} --output json run {s} -- cat /etc/os-release";
    const by_digest = try common.format(session, pattern, .{ z, spelled });
    const digested = try common.run_shown(session, out, by_digest);
    m4.check_output_has(digested.streams, digested.status, "ID=alpine") catch |err| {
        return fail_step(out, step, "expected the run by digest to print Alpine's os-release", err);
    };
    checks_m5.check_json_network(digested.streams, digested.status, "none") catch |err| {
        return fail_step(out, step, "expected the run by digest to say network none", err);
    };
    const marker = try common.format(session, "{s} run {s} -- cat /marker", .{ z, made.child });
    const committed = try common.run_shown(session, out, marker);
    m4.check_output_is(committed.streams, committed.status, "upgraded") catch |err| {
        return fail_step(out, step, "expected the M5 commit to hold the marker", err);
    };
    try run_postgres_image(session, out, made.postgres);
}

/// postgres runs by tag and by digest (`--version`: the entrypoint passes it through).
fn run_postgres_image(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    var buffer: [128]u8 = undefined;
    const manifest = pull.manifest_digest;
    const spelled = checks_up5.digest_reference(&buffer, "postgres", manifest) catch |err| {
        return fail_step(out, step, "the digest reference", err);
    };
    const names = [_][]const u8{ postgres, spelled };
    for (names) |name| {
        const pattern = "{s} run {s} -- postgres --version";
        const command = try common.format(session, pattern, .{ z, name });
        const result = try state.expect_long_split(session, out, command, 0, 300);
        m4.check_output_has(result.streams, result.status, "postgres (PostgreSQL) 16") catch |err| {
            return fail_step(out, step, "expected postgres 16 from M5's image", err);
        };
    }
}

/// M5's run record (version 4) is listed beside this binary's own (version 6).
fn read_run_records(session: *Session, out: *Io.Writer) !void {
    const run = z ++ " run --name m6up2 " ++ alpine ++ " -- true";
    _ = try expect_exit(session, out, step, run, 0);
    const arena = session.scratch_allocator();
    const listed = try expect_exit(session, out, step, z ++ " --output json ps --all", 0);
    const wants = [_]checks.Want{
        .{ .name = "m5up1", .network = null },
        .{ .name = "m6up2", .network = "none" },
    };
    checks.check_ps_records(arena, listed.streams.stdout, listed.status, &wants) catch |err| {
        return fail_step(out, step, "expected ps --all to list M5's record and the new one", err);
    };
    const text = try expect_exit(session, out, step, z ++ " ps --all", 0);
    m4.check_table_lists(text.streams, text.status, &.{ "m5up1", "m6up2" }) catch |err| {
        return fail_step(out, step, "expected ps --all in text to list both", err);
    };
    const names = [_][]const u8{ "m5up1", "m6up2" };
    const versions = [_]u32{ checks.run_record_version_m5, checks.run_record_version };
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
}

/// postgres with a new `--state` volume, on M5's store.
fn postgres_state(session: *Session, out: *Io.Writer) !void {
    _ = try state.expect_long(session, out, start_pg, 0, 300);
    const ready = comptime state.pg_ready_on(port);
    try state.wait_ready_on(session, out, ready);
    const write = comptime state.psql_on(port) ++ "-c \"create table t (v text)\" -c " ++
        "\"insert into t values ('from-m5-store')\"";
    const wrote = try state.expect_long_split(session, out, write, 0, limits.command_timeout_kvm_s);
    checks_spec.check_write(wrote.streams.stdout, wrote.status) catch |err| {
        return fail_step(out, step, "expected CREATE TABLE and INSERT 0 1", err);
    };
    try state.listing(session, out, .{
        .name = volume,
        .last_container = "m6pg",
        .in_use = true,
        .user = "m6pg",
        .disk_bytes_min = 1 << 20,
    }, "expected upstate in use by m6pg");
    _ = try state.expect_long(session, out, z ++ " stop m6pg", 0, limits.command_timeout_kvm_s);
    try state.expect_volume_free(session, out, volume, "after zbx stop");
}

fn verify(session: *Session, out: *Io.Writer) !void {
    const arena = session.scratch_allocator();
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 3) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
}

test {
    _ = @import("checks_upgrade_m6.zig");
    _ = checks_state;
}
