//! The M5 upgrade test, in the guest: the merged M4 `zbx` (the commit in `old_release.zon`) pulls
//! `alpine:3.20` in the project directory (which writes `zbx.lock`), runs it and commits a
//! change. This `zbx` then reads what it left:
//!
//!   - `store ls` lists the M4 image record (version 1 on disk) with its tag, and both trees;
//!     `store verify` finds no damage; `lock show` reads M4's `zbx.lock`;
//!   - the image runs by tag, by manifest digest and (the commit) by tree digest, with the
//!     default `--net none`, and its output is right;
//!   - M4's run record is listed beside this binary's own, both version 4;
//!   - M4 pulls by digest, which replaces its record's tag by the digest (a digest is no tag);
//!     this binary pulls by tag, so the record lists the tag again (version 2 now), and a pull by
//!     digest after that keeps it.
//!
//! Every assertion is a function of checks_upgrade_m5.zig, checks_m5.zig, checks_m4.zig or
//! checks_m3.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const agent_json = @import("agent_json.zig");
const checks_m5 = @import("checks_m5.zig");
const checks = @import("checks_upgrade_m5.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const m3 = @import("checks_m3.zig");
const m4 = @import("checks_m4.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const step = "UPGRADE";
const reference = "alpine:3.20";

/// The M4 `zbx` as the demo user, in the project directory, with the registry mirror named.
pub const zbx_old = H.as_demo ++ "/home/demo/zo";

/// Writes the wrapper of the older binary, beside the others (common.write_wrappers).
pub fn write_old_wrapper(session: *Session, out: *Io.Writer, with_ca: bool) !void {
    const plain = common.wrapper_for(common.project, false, "/home/demo/zbx-old");
    const with = common.wrapper_for(common.project, true, "/home/demo/zbx-old");
    try H.put_file(session, "/home/demo/zo", if (with_ca) with else plain);
    const command = "chown demo:demo /home/demo/zo && chmod 755 /home/demo/zo";
    const owned = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "the wrapper that runs the M4 zbx in the project directory", owned);
    if (owned.status != 0) return error.PrepareFailed;
}

pub fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: UPGRADE: the M4 binary leaves a store, records and a lock\n", .{
        H.demo_name,
    });
    const made = try old_makes(session, out);
    try read_store(session, out, made);
    try run_image(session, out, made);
    try read_run_records(session, out);
    try tags(session, out, made.pull);
    try timer.lap(out, "upgrade");
}

const Made = struct { pull: m4.PullDoc, child: []const u8 };

/// The M4 binary pulls, runs and commits.
fn old_makes(session: *Session, out: *Io.Writer) !Made {
    const arena = session.scratch_allocator();
    const pulled = try expect_exit(session, out, step, zbx_old ++ " --output json pull " ++
        reference, 0);
    const pull = m4.check_pull_json(arena, pulled.streams, pulled.status, reference) catch |err| {
        return fail_step(out, step, "expected the M4 pull as JSON", err);
    };
    const run = zbx_old ++ " run " ++ reference ++ " --name up1 -- sh -c 'echo upgraded > /marker'";
    _ = try expect_exit(session, out, step, run, 0);
    const committed = try expect_exit(session, out, step, zbx_old ++ " commit up1", 0);
    const changed = m3.check_changed(committed.streams, committed.status, pull.tree);
    const child_text = changed catch |err| {
        return fail_step(out, step, "expected a new tree from the M4 commit", err);
    };
    const child = try arena.dupe(u8, child_text);
    try expect_record_version(session, out, pull, checks.image_record_version_m4);
    return .{ .pull = pull, .child = child };
}

/// The image's record file has `.version = <version>,`.
fn expect_record_version(
    session: *Session,
    out: *Io.Writer,
    pull: m4.PullDoc,
    version: u32,
) !void {
    var buffer: [256]u8 = undefined;
    const path = checks.record_path(&buffer, common.store_dir, pull.manifest_digest) catch |err| {
        return fail_step(out, step, "the record's path", err);
    };
    const command = try common.format(session, "grep -h '\\.version' {s}", .{path});
    const record = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, command, record);
    checks.check_record_version(record.output, version) catch |err| {
        return fail_step(out, step, "expected the image record's version", err);
    };
}

/// `store ls`, `store verify` and `lock show` read what the M4 binary left.
fn read_store(session: *Session, out: *Io.Writer, made: Made) !void {
    const arena = session.scratch_allocator();
    const roots = [_][]const u8{ made.pull.tree, made.child };
    const ls = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const tags_wanted = [_][]const u8{reference};
    const listed = checks.check_image_listed(
        arena,
        ls.streams,
        ls.status,
        made.pull,
        &tags_wanted,
        &roots,
    );
    listed catch |err| {
        return fail_step(out, step, "expected store ls to list the M4 image with its tag", err);
    };
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 2) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
    try read_lock(session, out, made.pull);
}

fn read_lock(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    const arena = session.scratch_allocator();
    const shown = try expect_exit(session, out, step, z ++ " --output json lock show", 0);
    const read = agent_json.check_lock_show(arena, shown.streams, shown.status, reference);
    const entry = read catch |err| {
        return fail_step(out, step, "expected lock show to read M4's lock", err);
    };
    const path = common.project ++ "/zbx.lock";
    checks.check_lock_entry(entry, path, pull) catch |err| {
        return fail_step(out, step, "expected M4's lock entry to be what the pull said", err);
    };
}

/// The M4 image runs by tag, by manifest digest and by the tree digest of the commit, with the
/// default network, which is none.
fn run_image(session: *Session, out: *Io.Writer, made: Made) !void {
    const by_tag = z ++ " run " ++ reference ++
        " -- sh -c 'ls /sys/class/net; echo ---; ip -o link'";
    const tagged = try common.run_shown(session, out, by_tag);
    checks_m5.check_only_loopback(tagged.streams, tagged.status) catch |err| {
        return fail_step(out, step, "expected the run by tag to have lo alone", err);
    };
    var buffer: [128]u8 = undefined;
    const manifest = made.pull.manifest_digest;
    const spelled = checks.digest_reference(&buffer, "alpine", manifest) catch |err| {
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
        return fail_step(out, step, "expected the M4 commit to hold the marker", err);
    };
}

/// M4's run record (version 4) is listed beside this binary's own (version 5).
fn read_run_records(session: *Session, out: *Io.Writer) !void {
    _ = try expect_exit(session, out, step, z ++ " run " ++ reference ++ " --name up2 -- true", 0);
    const listed = try expect_exit(session, out, step, z ++ " --output json ps --all", 0);
    m3.check_ps_lists(listed.streams, listed.status, &.{ "up1", "up2" }) catch |err| {
        return fail_step(out, step, "expected ps --all to list M4's record and the new one", err);
    };
    const names = [_][]const u8{ "up1", "up2" };
    const versions = [_]u32{ checks.run_record_version_old, checks.run_record_version };
    for (names, versions) |name, version| {
        const command = try common.format(session, "grep -h version {s}/runs/{s}.zon", .{
            common.state_dir, name,
        });
        const record = try session.run(command, limits.command_timeout_kvm_s);
        try H.show(out, command, record);
        checks.check_record_version(record.output, version) catch |err| {
            return fail_step(out, step, "expected the run record of its own version", err);
        };
    }
}

/// M4 pulls by digest (its record loses the tag), this binary pulls by tag (the record has it
/// again, as version 2) and then by digest (the record keeps it).
fn tags(session: *Session, out: *Io.Writer, pull: m4.PullDoc) !void {
    const arena = session.scratch_allocator();
    var buffer: [128]u8 = undefined;
    const spelled = checks.digest_reference(&buffer, "alpine", pull.manifest_digest) catch |err| {
        return fail_step(out, step, "the digest reference", err);
    };
    const by_digest = try pull_json(session, out, zbx_old, spelled);
    checks.check_same_image(pull, by_digest) catch |err| {
        return fail_step(out, step, "expected M4's pull by digest to be the same image", err);
    };
    try expect_record_version(session, out, pull, checks.image_record_version_m4);
    try expect_tags(session, out, pull, &.{});
    const by_tag = try pull_json(session, out, z, reference);
    checks.check_same_image(pull, by_tag) catch |err| {
        return fail_step(out, step, "expected this pull by tag to find M4's blobs", err);
    };
    try expect_record_version(session, out, pull, checks.image_record_version_m5);
    try expect_tags(session, out, pull, &.{reference});
    _ = try pull_json(session, out, z, spelled);
    try expect_tags(session, out, pull, &.{reference});
    try read_lock(session, out, pull);
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 2) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
}

fn expect_tags(
    session: *Session,
    out: *Io.Writer,
    pull: m4.PullDoc,
    wanted: []const []const u8,
) !void {
    const arena = session.scratch_allocator();
    const ls = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const roots = [_][]const u8{pull.tree};
    const listed = checks.check_image_listed(arena, ls.streams, ls.status, pull, wanted, &roots);
    listed catch |err| {
        return fail_step(out, step, "expected the record to list exactly these tags", err);
    };
}

fn pull_json(
    session: *Session,
    out: *Io.Writer,
    program: []const u8,
    spelled: []const u8,
) !m4.PullDoc {
    const command = try common.format(session, "{s} --output json pull {s}", .{ program, spelled });
    const result = try expect_exit(session, out, step, command, 0);
    const arena = session.scratch_allocator();
    return m4.check_pull_json(arena, result.streams, result.status, spelled) catch |err| {
        return fail_step(out, step, "expected the pull as JSON", err);
    };
}
