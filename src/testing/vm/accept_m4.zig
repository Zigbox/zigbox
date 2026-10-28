//! The M4 demo's acceptance criteria and its upgrade test, in the guest:
//!
//! UPGRADE. The merged M3 `zbx` (the commit in `old_release.zon`) imports a tree, runs it by
//!   digest and commits it. This `zbx` then lists that store (`store ls`), verifies it clean,
//!   runs both trees by digest, imports the same directory to the same digest, and lists the old
//!   run record next to its own.
//! IDENTITY. Every image is its tree digest: the pull, `store ls` and `zbx.lock` name one tree
//!   for an image, a tag and a digest reference of the same image give the same tree, and the
//!   tree digest runs it.
//! RESUME. An image is pulled again with its own blobs deleted; the pull is killed halfway
//!   (SIGKILL, once bytes are in `blobs/partial/`); the next pull downloads none of the blobs that
//!   were complete, resumes the cut one, and yields the same tree.
//! BLOBS. The pulled blobs are kept between runs on a second disk (`--blob-cache`, which CI
//!   caches), so that a pull in CI is mostly a read from disk.
//!
//! Every assertion is a function of m4.zig or m3.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const m3 = @import("checks_m3.zig");
const m4 = @import("checks_m4.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const fail_step = common.fail_step;
const expect_exit = common.expect_exit;
const run_shown = common.run_shown;

/// Unpacks the pinned Alpine minirootfs as user `demo`: the tree the older zbx imports.
pub fn unpack_rootfs(session: *Session, out: *Io.Writer) !void {
    const command = try common.format(
        session,
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "runuser -u demo -- sh -c 'mkdir -p {s} && tar -xzf /tmp/rootfs.tar.gz -C {s}' && " ++
            "stat -c '%U %n' {s}/bin/busybox",
        .{ session.server.port, common.rootfs_dir, common.rootfs_dir, common.rootfs_dir },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "unpack the pinned Alpine minirootfs as user demo", result);
    if (result.status != 0) return error.UnpackFailed;
    const owner = "demo " ++ common.rootfs_dir ++ "/bin/busybox";
    if (std.mem.indexOf(u8, result.output, owner) == null) return error.RootfsNotOwnedByDemo;
}

pub fn install_old(session: *Session, out: *Io.Writer) !void {
    const command = try common.format(
        session,
        "curl -fsS -o /home/demo/zbx-old http://10.0.2.2:{d}/zbx-old && " ++
            "chown demo:demo /home/demo/zbx-old && chmod 755 /home/demo/zbx-old && " ++
            "runuser -u demo -- /home/demo/zbx-old --version",
        .{session.server.port},
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "install the M3 zbx", result);
    if (result.status != 0) return error.InstallFailed;
}

// ---- The upgrade test ---------------------------------------------------------------------

/// What the older zbx leaves: two trees, found again by this one.
pub fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "UPGRADE";
    try out.print("\ndemo-m4: UPGRADE: the M3 binary leaves a store, this one reads it\n", .{});
    const old = common.zbx_old;
    const imported = try expect_exit(session, out, step, old ++ " store import " ++
        common.rootfs_dir, 0);
    const first_tree = m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, step, "expected the older zbx to print a tree digest", err);
    };
    const parent = try session.scratch_allocator().dupe(u8, first_tree);
    const run = try common.format(
        session,
        "{s} run {s} --name up1 -- sh -c 'echo upgraded > /marker'",
        .{ old, parent },
    );
    _ = try expect_exit(session, out, step, run, 0);
    const committed = try expect_exit(session, out, step, old ++ " commit up1", 0);
    const child_text = m3.check_changed(committed.streams, committed.status, parent) catch |err| {
        return fail_step(out, step, "expected a new tree from the older zbx's commit", err);
    };
    const child = try session.scratch_allocator().dupe(u8, child_text);
    _ = try expect_exit(session, out, step, old ++ " store verify", 0);
    try read_old_store(session, out, parent, child);
    try timer.lap(out, "upgrade");
}

/// This zbx reads the store the older one left.
fn read_old_store(session: *Session, out: *Io.Writer, parent: []const u8, child: []const u8) !void {
    const step = "UPGRADE";
    const arena = session.scratch_allocator();
    const listed = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    m4.check_old_roots(arena, listed.streams, listed.status, &.{ parent, child }) catch |err| {
        return fail_step(out, step, "expected store ls to list both trees of the older zbx", err);
    };
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 2) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
    const marker = try common.format(session, "{s} run {s} -- cat /marker", .{ z, child });
    const read = try run_shown(session, out, marker);
    m4.check_output_is(read.streams, read.status, "upgraded") catch |err| {
        return fail_step(out, step, "expected the committed tree to hold the marker", err);
    };
    const bare = try common.format(session, "{s} run {s} -- true", .{ z, parent });
    _ = try expect_exit(session, out, step, bare, 0);
    // The same directory imported by this zbx is the same tree: the digest did not change with
    // the version.
    const again = try expect_exit(session, out, step, z ++ " store import " ++
        common.rootfs_dir, 0);
    m3.check_same_digest(parent, std.mem.trim(u8, again.streams.stdout, " \r\n")) catch |err| {
        return fail_step(out, step, "expected the same directory to give the same tree", err);
    };
    try read_run_records(session, out);
}

/// The older zbx's run record is listed and read, and this zbx's own is the same version.
fn read_run_records(session: *Session, out: *Io.Writer) !void {
    const step = "UPGRADE";
    _ = try expect_exit(session, out, step, z ++ " run --rootfs " ++ common.rootfs_dir ++
        " --name up2 -- true", 0);
    const listed = try expect_exit(session, out, step, z ++ " --output json ps --all", 0);
    m3.check_ps_lists(listed.streams, listed.status, &.{ "up1", "up2" }) catch |err| {
        return fail_step(out, step, "expected ps --all to list the old record and the new", err);
    };
    const names = [_][]const u8{ "up1", "up2" };
    for (names) |name| {
        const command = try common.format(session, "grep -h version {s}/runs/{s}.zon", .{
            common.state_dir, name,
        });
        const record = try session.run(command, limits.command_timeout_kvm_s);
        try H.show(out, command, record);
        m3.check_record_version(record.output, 4) catch |err| {
            return fail_step(out, step, "expected a version 4 record", err);
        };
    }
}

// ---- The blobs, kept between runs -----------------------------------------------------------

const cache_mount = "/mnt/blobs";
const blobs_dir = common.store_dir ++ "/blobs/sha256";

/// Mounts the cache disk (formatting it the first time) and copies its blobs into the store.
/// The older zbx has made the store by now; the blob directories are made here as zbx would.
pub fn cache_restore(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: BLOBS: the cache disk into the store\n", .{});
    const mount = "mkdir -p " ++ cache_mount ++ " && (blkid /dev/vdb > /dev/null || " ++
        "mkfs.ext4 -q -L zbxblobs /dev/vdb) && mount /dev/vdb " ++ cache_mount;
    const mounted = try session.run(mount, limits.boot_timeout_kvm_s);
    try H.show(out, "mount the blob cache disk", mounted);
    if (mounted.status != 0) return error.CacheDiskFailed;
    const prepare = "runuser -u demo -- mkdir -p " ++ blobs_dir ++ " " ++ common.store_dir ++
        "/blobs/partial";
    const made = try session.run(prepare, limits.command_timeout_kvm_s);
    if (made.status != 0) return error.CacheDiskFailed;
    const copy = "find " ++ cache_mount ++ " -maxdepth 1 -type f -name '[0-9a-f]*' " ++
        "-exec cp {} " ++ blobs_dir ++ "/ \\; && chown -R demo:demo " ++ common.store_dir ++
        "/blobs && echo \"restored $(ls " ++ blobs_dir ++ " | wc -l) blobs\"";
    const restored = try session.run(copy, limits.boot_timeout_kvm_s);
    try H.show(out, "the cached blobs into the store", restored);
    if (restored.status != 0) return error.CacheDiskFailed;
    try timer.lap(out, "blob cache restore");
}

/// Mirrors the store's blobs onto the cache disk, so it holds exactly what this run used, and
/// unmounts it cleanly.
pub fn cache_save(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const save = "find " ++ cache_mount ++ " -maxdepth 1 -type f -name '[0-9a-f]*' -delete; " ++
        "cp " ++ blobs_dir ++ "/* " ++ cache_mount ++ "/ && sync && " ++
        "echo \"saved $(ls " ++ cache_mount ++ " | grep -c .) files, " ++
        "$(du -sh " ++ cache_mount ++ " | cut -f1)\" && umount " ++ cache_mount;
    const saved = try session.run(save, limits.boot_timeout_kvm_s);
    try H.show(out, "the store's blobs onto the cache disk", saved);
    if (saved.status != 0) return error.CacheDiskFailed;
    try timer.lap(out, "blob cache save");
}

// ---- Identity: the tree digest is the image --------------------------------------------------

pub fn step_identity(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "IDENTITY";
    try out.print("\ndemo-m4: IDENTITY: an image is its tree digest, a tag is an alias\n", .{});
    const arena = session.scratch_allocator();
    const by_tag = try pull_json(session, out, step, "alpine:3.20");
    const spelled = try common.format(session, "alpine@sha256:{s}", .{by_tag.manifest_digest[7..]});
    const by_digest = try pull_json(session, out, step, spelled);
    m4.check_alias(by_tag, by_digest) catch |err| {
        return fail_step(out, step, "expected a tag and its digest to be one tree", err);
    };
    const cat = "cat " ++ common.project ++ "/zbx.lock";
    const lock = try session.run(cat, limits.command_timeout_kvm_s);
    const lock_text = try arena.dupe(u8, lock.output);
    const listed = try expect_exit(session, out, step, z ++ " --output json store ls", 0);
    const tag = by_tag.reference;
    m4.check_identity(arena, listed.streams, listed.status, by_tag, tag, lock_text) catch |err| {
        return fail_step(out, step, "expected pull, store ls and zbx.lock to name one tree", err);
    };
    const os_release = "{s} run {s} -- cat /etc/os-release";
    const run = try common.format(session, os_release, .{ z, by_tag.tree });
    const ran = try run_shown(session, out, run);
    m4.check_output_has(ran.streams, ran.status, "ID=alpine") catch |err| {
        return fail_step(out, step, "expected the tree digest to run the image", err);
    };
    try timer.lap(out, "identity");
}

// ---- Resume: a pull killed halfway ----------------------------------------------------------

/// Starts `z pull <ref>`, waits until a file in `blobs/partial/` has bytes, and kills the process
/// with SIGKILL: a pull cut halfway.
const kill_script =
    "#!/bin/sh\n" ++
    "partial=$HOME/.local/share/zbx/store/blobs/partial\n" ++
    "/home/demo/z pull \"$1\" > /dev/null 2>&1 &\n" ++
    "pid=$!\n" ++
    "n=0\n" ++
    "while [ $n -lt 6000 ]; do\n" ++
    "  kill -0 $pid 2> /dev/null || { echo finished-before-kill; exit 3; }\n" ++
    "  for f in \"$partial\"/*; do\n" ++
    "    if [ -s \"$f\" ]; then kill -9 $pid; wait $pid 2> /dev/null; echo killed; exit 0; fi\n" ++
    "  done\n" ++
    "  n=$((n+1))\n" ++
    "  sleep 0.01\n" ++
    "done\n" ++
    "kill -9 $pid; echo no-partial; exit 4\n";

/// What `blobs/` holds, as `m4.parse_blob_listing` reads it.
const listing_command = "cd " ++ common.store_dir ++ "/blobs && " ++
    "for f in sha256/*; do [ -f \"$f\" ] && echo \"complete $(basename $f)\"; done; " ++
    "for f in partial/*; do [ -f \"$f\" ] && echo \"partial $(basename $f) $(stat -c %s $f)\"; " ++
    "done; true";

pub fn step_resume(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "RESUME";
    try out.print("\ndemo-m4: RESUME: a pull killed halfway, then pulled again\n", .{});
    const arena = session.scratch_allocator();
    const reference = "python:3.13-slim";
    const later = try pull_json(session, out, step, reference);
    const earlier = try pull_json(session, out, step, "python:3.12-slim");
    var own_buffer: [8][]const u8 = undefined;
    const own = m4.layers_only_in(earlier, later, &own_buffer) catch |err| {
        return fail_step(out, step, "expected the 3.13 image to have layers of its own", err);
    };
    // The image is taken out and its own blobs deleted, so that the next pull has to download.
    const remove = try common.format(session, "{s} store rm {s}", .{ z, later.tree });
    _ = try expect_exit(session, out, step, remove, 0);
    for (own) |digest| {
        const hex = digest[7..];
        const command = try common.format(session, "rm -f {s}/{s}", .{ blobs_dir, hex });
        const removed = try session.run(command, limits.command_timeout_kvm_s);
        if (removed.status != 0) return fail_step(out, step, command, error.PrepareFailed);
    }
    try H.put_file(session, "/home/demo/killpull.sh", kill_script);
    const kill = H.as_demo ++ "sh /home/demo/killpull.sh " ++ reference;
    const killed = try session.run(kill, limits.command_timeout_kvm_s);
    try H.show(out, kill, killed);
    m4.check_killed(killed.output, killed.status) catch |err| {
        return fail_step(out, step, "expected the pull to be killed while downloading", err);
    };
    const left = try session.run(listing_command, limits.command_timeout_kvm_s);
    try H.show(out, "what the kill left in blobs/", left);
    const states = m4.parse_blob_listing(arena, left.output) catch |err| {
        return fail_step(out, step, "expected a listing of the blobs", err);
    };
    const again = try expect_exit(session, out, step, z ++ " --output json pull " ++ reference, 0);
    const resumed = m4.check_resume(arena, again.streams, again.status, reference, states);
    const facts = resumed catch |err| {
        return fail_step(out, step, "expected the cut blob resumed, the rest cached", err);
    };
    try out.print("demo-m4: RESUME: {d} resumed, {d} cached, {d} downloaded\n", .{
        facts.resumed, facts.cached, facts.downloaded,
    });
    const doc = try m4.check_pull_json(arena, again.streams, again.status, reference);
    if (!std.mem.eql(u8, doc.tree, later.tree)) {
        const what = "expected the resumed pull to give the same tree";
        return fail_step(out, step, what, error.IdentityWrong);
    }
    const verified = try expect_exit(session, out, step, z ++ " --output json store verify", 0);
    m4.check_verify_ok(arena, verified.streams, verified.status, 1) catch |err| {
        return fail_step(out, step, "expected store verify to find no damage", err);
    };
    try timer.lap(out, "resume");
}

fn pull_json(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    reference: []const u8,
) !m4.PullDoc {
    const command = try common.format(session, "{s} --output json pull {s}", .{ z, reference });
    const result = try expect_exit(session, out, step, command, 0);
    const arena = session.scratch_allocator();
    return m4.check_pull_json(arena, result.streams, result.status, reference) catch |err| {
        return fail_step(out, step, "expected the pull as JSON", err);
    };
}
