//! M6 slice 3's other mounts and `state export` in the VM, a part of demo-m6 (`MOUNTS`). As the
//! user `demo`, in the net project (`zn`), with `alpine` and the `pgdata` volume that the STATE
//! part leaves (restored, owned by postgres's 999):
//!
//!   1. A secret is readable inside, mode 0400, owned by the container's root, and cannot be
//!      written.
//!   2. A run with a secret, two binds and a tmpfs is committed: the diff holds the container's
//!      change and no mount point; the bundle of the run, with and without redaction, holds no
//!      byte of the secret.
//!   3. A `--bind` cannot be written, nor its file, nor a name removed from it; the host's
//!      directory is as it was. A bind of a path that is not there is refused and not made.
//!   4. A `--tmpfs` has the size, mode and flags asked for, is full at its size, is gone with its
//!      run, and with `--memory` the memory it fills is the container's.
//!   5. `state export pgdata` is a gzip tar that `tar -tzvf` lists with owner 999 and none of the
//!      host's subordinate ids; a volume a container writes is refused (E0706); a volume with a
//!      symlink, a hard link, a mode and a time keeps them, and its fifo is left out with a note.
//!
//! Every assertion is a function of checks_mounts_m6.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_mounts_m6.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("limits.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "MOUNTS";

const marker = "marker-OMEGA-4417";
const home = "/home/demo/";
const secret_flag = " --secret " ++ home ++ "secret.txt:/run/key";
const setup = H.as_demo ++ "sh -c 'mkdir -p " ++ home ++ "hostdir && echo seen > " ++ home ++
    "hostdir/seen && echo " ++ marker ++ " > " ++ home ++ "secret.txt && chmod 644 " ++ home ++
    "secret.txt && echo hello > " ++ home ++ "note.txt'";

pub fn step_mounts(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: MOUNTS: --tmpfs, --bind, --secret and state export (M6 slice 3)\n", .{
        H.demo_name,
    });
    try net_user.make_net_wrapper(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull alpine", 0);
    _ = try common.expect_exit(session, out, step_name, setup, 0);
    try secret(session, out);
    try commit_and_bundle(session, out);
    try bind(session, out);
    try tmpfs(session, out);
    try export_pgdata(session, out);
    try export_links(session, out);
    try timer.lap(out, "mounts");
}

fn secret(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 1: a secret, read inside\n", .{H.demo_name});
    const command = zn ++ " run --name sec0" ++ secret_flag ++ " alpine -- sh -c " ++
        "'cat /run/key; stat -c \"%a %u %g\" /run/key; " ++
        "(echo x > /run/key) 2>/dev/null && echo writable || echo readonly; id -u'";
    const result = try common.run_shown(session, out, command);
    checks.check_secret(result.streams.stdout, result.status, marker) catch |err| {
        return fail_step(out, step_name, "expected the secret, 400 0 0, read-only", err);
    };
}

fn commit_and_bundle(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 2: no mount point in a commit, no secret in a bundle\n", .{
        H.demo_name,
    });
    const run = zn ++ " run --name sec1" ++ secret_flag ++ " --bind " ++ home ++
        "note.txt:/mnt/note --bind " ++ home ++ "hostdir:/media/hostdir --tmpfs /scratch alpine " ++
        "-- sh -c 'echo changed > /changed; cat /run/key /mnt/note /media/hostdir/seen >/dev/null'";
    _ = try common.expect_exit(session, out, step_name, run, 0);
    const diff = "out=$(" ++ zn ++ " --output json commit sec1) && " ++
        "parent=$(echo \"$out\" | sed -n 's/.*\"parent\":\"\\([^\"]*\\)\".*/\\1/p') && " ++
        "digest=$(echo \"$out\" | sed -n 's/.*\"digest\":\"\\([^\"]*\\)\".*/\\1/p') && " ++
        zn ++ " store diff \"$parent\" \"$digest\"";
    const listed = try common.run_shown(session, out, diff);
    if (listed.status != 0) return fail_step(out, step_name, diff, error.ExitCodeWrong);
    checks.check_commit_diff(listed.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected only /changed in the commit", err);
    };
    const bundles = "for f in \"$(" ++ zn ++ " bundle sec1)\" \"$(" ++ zn ++
        " bundle --no-redact sec1)\"; do tar -xzOf \"$f\" | grep -c " ++ marker ++ "; done; true";
    const counted = try common.run_shown(session, out, bundles);
    checks.check_bundles_clean(counted.streams.stdout, 2) catch |err| {
        return fail_step(out, step_name, "expected no secret byte in either bundle", err);
    };
}

fn bind(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 3: a bind that cannot be written; a source never made\n", .{
        H.demo_name,
    });
    const run = zn ++ " run --name bnd1 --bind " ++ home ++ "hostdir:/mnt/h --bind " ++ home ++
        "note.txt:/mnt/n alpine -- sh -c 'cat /mnt/h/seen; touch /mnt/h/new 2>&1; " ++
        "(echo x >> /mnt/n) 2>/dev/null && echo n-writable || echo n-readonly; " ++
        "(rm /mnt/h/seen) 2>/dev/null && echo rm-ok || echo rm-refused; true'";
    const result = try common.run_shown(session, out, run);
    checks.check_bind(result.streams.stdout, result.status) catch |err| {
        return fail_step(out, step_name, "expected a bind nothing can write", err);
    };
    const host = H.as_demo ++ "ls " ++ home ++ "hostdir";
    const listed = try common.run_shown(session, out, host);
    checks.check_host_dir(listed.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the host's directory as it was", err);
    };
    const missing = zn ++ " run --bind " ++ home ++ "nowhere:/mnt/x alpine -- true";
    const refused = try common.run_shown(session, out, missing);
    checks.check_missing_source(refused.streams, refused.status) catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0210 for a missing source", err);
    };
    const made = H.as_demo ++ "sh -c 'test ! -e " ++ home ++ "nowhere && echo not-made'";
    _ = try common.expect_exit(session, out, step_name, made, 0);
}

fn tmpfs(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 4: a tmpfs: its size, gone with the run, in --memory\n", .{
        H.demo_name,
    });
    const run = zn ++ " run --name tmp1 --tmpfs /scratch:8m alpine -- sh -c " ++
        "'df -k /scratch | tail -1; stat -c %a /scratch; mount | grep \" /scratch \"; " ++
        "echo hi > /scratch/f; cat /scratch/f; " ++
        "dd if=/dev/zero of=/scratch/big bs=1M count=9 2>&1 | tail -1'";
    const result = try common.run_shown(session, out, run);
    checks.check_tmpfs(result.streams.stdout, result.status, "8192") catch |err| {
        return fail_step(out, step_name, "expected an 8 MiB tmpfs, mode 1777, noexec", err);
    };
    const after = zn ++ " run --name tmp2 alpine -- sh -c " ++
        "'test -e /scratch && echo present || echo gone'";
    const gone = try common.run_shown(session, out, after);
    checks.check_gone(gone.streams.stdout, gone.status) catch |err| {
        return fail_step(out, step_name, "expected no tmpfs in the next run", err);
    };
    const charged = zn ++ " run --name tmp3 --memory 64m --tmpfs /scratch:256m alpine -- " ++
        "dd if=/dev/zero of=/scratch/big bs=1M count=200";
    const filled = try common.run_shown(session, out, charged);
    checks.check_memory_charged(filled.status) catch |err| {
        return fail_step(out, step_name, "expected the tmpfs to count against --memory (137)", err);
    };
}

fn export_pgdata(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 5: state export of the postgres volume\n", .{H.demo_name});
    const hold = zn ++ " run -d --name pgw --state pgdata:/d alpine -- sleep 600";
    _ = try common.expect_exit(session, out, step_name, hold, 0);
    const busy = zn ++ " state export pgdata -o " ++ home ++ "busy.tar.gz";
    const refused = try common.run_shown(session, out, busy);
    checks.check_export_in_use(refused.streams, refused.status, "pgw") catch |err| {
        return fail_step(out, step_name, "expected ZBX-E0706 naming pgw", err);
    };
    _ = try common.expect_exit(session, out, step_name, zn ++ " stop pgw", 0);
    const file = home ++ "pgdata.tar.gz";
    const export_pg = zn ++ " state export pgdata -o " ++ file;
    _ = try common.expect_exit(session, out, step_name, export_pg, 0);
    const listing = "tar -tzvf " ++ file ++ " | head -3";
    _ = try common.expect_exit(session, out, step_name, listing, 0);
    const owners = "tar -tzvf " ++ file ++ " | awk '{print $2}' | sort | uniq -c";
    const counted = try common.run_shown(session, out, owners);
    checks.check_owners(counted.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected owner 999 and no host ids in the archive", err);
    };
    const content = "gzip -t " ++ file ++ " && echo gzip-ok; tar -xzOf " ++ file ++ " ./PG_VERSION";
    const read = try common.run_shown(session, out, content);
    checks.check_archive_content(read.streams.stdout, "16") catch |err| {
        return fail_step(out, step_name, "expected a whole archive with PG_VERSION 16", err);
    };
}

fn export_links(session: *Session, out: *Io.Writer) !void {
    try out.print("\n{s}: MOUNTS 5b: links, modes, times kept; a fifo left out\n", .{H.demo_name});
    const make = zn ++ " run --name lk1 --state lk:/data alpine -- sh -c " ++
        "'cd /data && echo one > a " ++
        "&& ln a b && ln -s a c && mkfifo p && mkdir -p d/e && chmod 750 d && " ++
        "touch -d @1700000000 a'";
    _ = try common.expect_exit(session, out, step_name, make, 0);
    const file = home ++ "lk.tar.gz";
    const exported = try common.run_shown(session, out, zn ++ " state export lk -o " ++ file);
    checks.check_skip_note(exported.streams, exported.status) catch |err| {
        return fail_step(out, step_name, "expected one note for the fifo", err);
    };
    const listing = try common.run_shown(session, out, "tar -tzvf " ++ file);
    checks.check_links(listing.streams.stdout) catch |err| {
        return fail_step(out, step_name, "expected the links, mode and time kept", err);
    };
}

test {
    _ = @import("checks_mounts_m6.zig");
    _ = limits;
}
