//! The M3 demo, run in a real Ubuntu 24.04 VM (the M0/M1/M2 harness: same image, same
//! provisioning, the pinned Alpine minirootfs unpacked as user `demo`). It grows slice by slice;
//! this is slice 3, "Commit and diff" (steps 6 to 8) on top of slice 2, "Materialize and run":
//!   1. Import the rootfs; its digest is printed.
//!   2. `zbx run <digest prefix>` runs on an overlay: a container that writes, changes modes,
//!      changes owners and deletes across the tree leaves the store byte for byte as it was
//!      (a listing with modes, owners and link counts, and the sums of every file, before and
//!      after, compared in the guest). Its writes are in its own upper layer, and the run record
//!      names the tree and the upper.
//!   3. `--read-only` with a digest: touching `/x` is refused by the file system.
//!   4. A tree imported with a root directory of mode 711 is that in the container.
//!   5. An unknown digest is ZBX-E0410 and exit 125. A second run with a name starts from a
//!      fresh upper layer.
//!   6. A copy of the rootfs with an 8 MB file is imported and run; the container adds a file,
//!      rewrites one, changes a mode, deletes two (the large file and a small one) and exits.
//!      `zbx commit` prints a new digest, `zbx store diff old new` lists exactly those five
//!      paths (text and JSON), and the new tree's stored size is smaller by the large file.
//!   7. A commit of a running container is ZBX-E0427; of a run on a directory ZBX-E0426; of a
//!      container that changed nothing it prints the parent's digest. (There is no network in
//!      the guest's containers yet, so `apk add` is not part of the demo: file operations are.)
//!   8. Corrupt the object of `/etc/passwd` by hand: `zbx store verify` exits 2 and names the
//!      object, its file and the paths (`/etc/passwd`) in the root trees that reach it, in text
//!      and in JSON; deleting the file and importing again makes it clean.
//!   9. gc: drop two roots; a plan (with a dead leftover in `tmp/`) names what they free; a
//!      wrong hash, and then the right hash after a write to the store, are refused with the
//!      new hash; the fresh hash is applied and the store shrinks by the big file; the trash is
//!      listed and verify is clean; restore puts it back (the store is as large as before and
//!      the materialized directory is back) and a second restore is refused.
//! `zig build demo-m3` (KVM) or `zig build demo-m3 -Daccel=tcg`. See docs/demos/m3.md.

const std = @import("std");
const Io = std.Io;
const checks_m3 = @import("checks_m3.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m3";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m3: bad arguments ({s}); see docs/demos/m3.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m3: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m3: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m3: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const rootfs_path = try image.ensure_pin(init, options.cache_dir, out, .{
        .url = alpine.url,
        .sha256 = alpine.sha256,
        .file_name = alpine.file_name,
    });
    const limit: Io.Limit = .limited(limits.http_body_bytes_max);
    const rootfs = try Io.Dir.cwd().readFileAlloc(io, rootfs_path, arena, limit);
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay = try std.fmt.allocPrint(
        arena,
        "{s}/overlay-demo-m3.qcow2",
        .{options.cache_dir},
    );
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = @import("cloud_init.zig").user_data,
        .binary = binary,
        .rootfs = rootfs,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out, &timer);
    try write_scripts(&session, out);
    const digest = try step_import(&session, out, &timer);
    try step_store_untouched(&session, out, &timer, digest);
    try step_read_only(&session, out, &timer, digest);
    try step_root_mode(&session, out, &timer);
    try step_refusals(&session, out, &timer, digest);
    const big = try step_commit(&session, out, &timer);
    try step_commit_refusals(&session, out, &timer, digest);
    try step_verify(&session, out, &timer);
    try step_gc(&session, out, &timer, big);
    try session.shutdown();
    return 0;
}

// The commands, as the user `demo` runs them, through `H.as_demo`.
const zbx = H.as_demo ++ "/home/demo/zbx";
const rootfs_dir = "/home/demo/alpine";
const store_dir = "/home/demo/.local/share/zbx/store";
const state_dir = "/home/demo/.local/state/zbx";

fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("demo-m3: {s} FAILED: {s} ({s})\n", .{ step, what, @errorName(err) });
    return err;
}

fn unpack_rootfs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: unpacking the pinned Alpine minirootfs as user demo\n", .{});
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "runuser -u demo -- sh -c 'mkdir -p {s} && tar -xzf /tmp/rootfs.tar.gz -C {s}' && " ++
            "stat -c '%U %n' {s}/bin/busybox",
        .{ session.server.port, rootfs_dir, rootfs_dir, rootfs_dir },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "unpack the rootfs", result);
    if (result.status != 0) return error.UnpackFailed;
    if (std.mem.indexOf(u8, result.output, "demo " ++ rootfs_dir ++ "/bin/busybox") == null) {
        return error.RootfsNotOwnedByDemo;
    }
    try timer.lap(out, "unpack");
}

/// Writes `text` to `path` in the guest through base64 in short pieces (a typed line is at most
/// 1 KiB, and the text has quotes in it).
fn put(session: *Session, path: []const u8, text: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    var encoded: [2048]u8 = undefined;
    if (encoder.calcSize(text.len) > encoded.len) return error.ScriptTooBig;
    const whole = encoder.encode(&encoded, text);
    const piece = 600;
    var at: usize = 0;
    var command_buffer: [900]u8 = undefined;
    _ = try session.run("rm -f /tmp/put.b64", limits.command_timeout_kvm_s);
    while (at < whole.len) : (at += piece) {
        const end = @min(at + piece, whole.len);
        const command = try std.fmt.bufPrint(
            &command_buffer,
            "printf %s {s} >> /tmp/put.b64",
            .{whole[at..end]},
        );
        const result = try session.run(command, limits.command_timeout_kvm_s);
        if (result.status != 0) return error.ScriptNotWritten;
    }
    const decode = try std.fmt.bufPrint(
        &command_buffer,
        "base64 -d /tmp/put.b64 > {s} && chmod 755 {s}",
        .{ path, path },
    );
    const result = try session.run(decode, limits.command_timeout_kvm_s);
    if (result.status != 0) return error.ScriptNotWritten;
}

/// What the container does to the tree: writes, modes, owners and deletions across it.
const scribble_script =
    "set -e\n" ++
    "echo hi > /etc/motd\n" ++
    "chmod -R go+w /etc /bin /lib /usr\n" ++
    "chmod 4755 /bin/busybox\n" ++
    "chown -R 7:7 /etc /usr/share\n" ++
    "chown 5:5 /bin/busybox\n" ++
    "rm -rf /usr/share /lib/apk /var\n" ++
    "mkdir -p /newdir/deep\n" ++
    "touch /newdir/deep/f /left\n" ++
    "ln -s x /newlink\n" ++
    "echo scribbled\n";

/// The store as a listing (type, mode, owner, size, link count, path) and the sum of every file,
/// read as root, which can read what belongs to subordinate ids.
const snapshot_script =
    "cd " ++ store_dir ++ "\n" ++
    "find . -path ./tmp -prune -o -printf '%y %m %U:%G %s %n %p\\n' | sort\n" ++
    "find . -path ./tmp -prune -o -type f -print0 | sort -z | xargs -0 sha256sum\n";

fn write_scripts(session: *Session, out: *Io.Writer) !void {
    try put(session, rootfs_dir ++ "/scribble.sh", scribble_script);
    try put(session, "/tmp/snapshot.sh", snapshot_script);
    const check = try session.run("chown demo:demo " ++ rootfs_dir ++ "/scribble.sh; " ++
        "ls -l " ++ rootfs_dir ++ "/scribble.sh /tmp/snapshot.sh", limits.command_timeout_kvm_s);
    try H.show(out, "the test scripts", check);
}

fn step_import(session: *Session, out: *Io.Writer, timer: *H.Timer) ![]const u8 {
    try out.print("\ndemo-m3: STEP 1: import the rootfs\n", .{});
    const command = zbx ++ " store import " ++ rootfs_dir;
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const digest = checks_m3.check_import(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 1", "expected the digest alone on stdout, exit 0", err);
    };
    try timer.lap(out, "import");
    return try session.scratch_allocator().dupe(u8, digest);
}

fn step_store_untouched(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 2: a container that writes everywhere leaves the store " ++
        "as it was\n", .{});
    const arena = session.scratch_allocator();
    const prefix = digest[3..15];
    // The first run builds the farm (the store grows by it); the sums are taken after it.
    const prime = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name prime1 -- true",
        .{ zbx, prefix },
    );
    const primed = try H.run_split(session, prime);
    try H.show_split(out, prime, primed);
    if (primed.status != 0) {
        return fail_step(out, "STEP 2", "the first run by digest", error.RunFailed);
    }
    const before = try session.run(
        "sh /tmp/snapshot.sh > /tmp/store.before; wc -l < /tmp/store.before",
        120,
    );
    try H.show(out, "the store before: listing and sums", before);
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name scribble1 -- sh /scribble.sh",
        .{ zbx, prefix },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    checks_m3.check_scribbled(ran.streams, ran.status) catch |err| {
        return fail_step(out, "STEP 2", "expected the script to run to its end", err);
    };
    const compare = "sh /tmp/snapshot.sh > /tmp/store.after; " ++
        "if cmp -s /tmp/store.before /tmp/store.after; then echo STORE-SAME; " ++
        "else echo STORE-DIFFERS; diff /tmp/store.before /tmp/store.after | head -20; fi; " ++
        "echo UPPER-ENTRIES:$(find " ++ state_dir ++ "/containers/scribble1/upper | wc -l); " ++
        "echo FARMS:$(ls " ++ store_dir ++ "/cache | wc -l)";
    const after = try session.run(compare, 120);
    try H.show(out, "the store after, compared", after);
    checks_m3.check_store_same(after.output) catch |err| {
        return fail_step(out, "STEP 2", "expected the store byte for byte as it was", err);
    };
    checks_m3.check_upper_written(after.output, 20) catch |err| {
        return fail_step(out, "STEP 2", "expected the writes in the container's upper layer", err);
    };
    const record = try session.run(
        "cat " ++ state_dir ++ "/runs/scribble1.zon",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the run record", record);
    checks_m3.check_record(record.output, digest) catch |err| {
        return fail_step(out, "STEP 2", "expected the record to name the tree and the upper", err);
    };
    try timer.lap(out, "store untouched");
}

fn step_read_only(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 3: --read-only with a digest\n", .{});
    const arena = session.scratch_allocator();
    const refused = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --read-only --name ro1 -- touch /x",
        .{ zbx, digest[3..15] },
    );
    const first = try H.run_split(session, refused);
    try H.show_split(out, refused, first);
    const allowed = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --read-only --name ro2 -- sh -c 'touch /tmp/x && echo tmp-ok'",
        .{ zbx, digest[3..15] },
    );
    const second = try H.run_split(session, allowed);
    try H.show_split(out, allowed, second);
    const checked = checks_m3.check_read_only(
        first.streams,
        first.status,
        second.streams,
        second.status,
    );
    checked catch |err| {
        return fail_step(out, "STEP 3", "expected touch /x refused, touch /tmp/x allowed", err);
    };
    try timer.lap(out, "read-only");
}

fn step_root_mode(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: STEP 4: the root directory's mode is the tree's\n", .{});
    const arena = session.scratch_allocator();
    const prepare = "runuser -u demo -- chmod 711 " ++ rootfs_dir;
    _ = try session.run(prepare, limits.command_timeout_kvm_s);
    const import = zbx ++ " store import " ++ rootfs_dir;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const digest = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "STEP 4", "expected a digest", err);
    };
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name root1 -- sh -c 'echo ROOT:$(stat -c \"%a %u %g\" /)'",
        .{ zbx, digest[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    checks_m3.check_root(ran.streams.stdout, "711 0 0") catch |err| {
        return fail_step(out, "STEP 4", "expected the root to be 711, owned by root", err);
    };
    try timer.lap(out, "root mode");
}

fn step_refusals(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 5: an unknown digest, and a name used twice\n", .{});
    const arena = session.scratch_allocator();
    const unknown = zbx ++ " run ffffffffffff -- true";
    const result = try H.run_split(session, unknown);
    try H.show_split(out, unknown, result);
    checks_m3.check_unknown_digest(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 5", "expected ZBX-E0410 and exit 125", err);
    };
    // The first run of `scribble1` left /left in its upper layer; the same name starts afresh.
    const again = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name scribble1 -- sh -c 'ls /left 2>&1; echo END'",
        .{ zbx, digest[3..15] },
    );
    const second = try H.run_split(session, again);
    try H.show_split(out, again, second);
    if (second.status != 0 or std.mem.indexOf(u8, second.streams.stdout, "No such file") == null) {
        const wanted = "expected /left gone in a run of the same name";
        return fail_step(out, "STEP 5", wanted, error.NotFresh);
    }
    try timer.lap(out, "refusals");
}

/// What the container does in step 6: an addition, a rewrite, a mode change and two deletions,
/// one of them the large file.
const ops_script =
    "set -e\n" ++
    "echo added > /added.txt\n" ++
    "echo changed >> /etc/hostname\n" ++
    "chmod 600 /etc/passwd\n" ++
    "rm /etc/shadow /big.bin\n" ++
    "echo ops-done\n";

/// The lines `store diff` must print for those operations, in path order.
const ops_diff =
    "A /added.txt\n" ++
    "D /big.bin\n" ++
    "M /etc/hostname  content\n" ++
    "M /etc/passwd  mode\n" ++
    "D /etc/shadow\n";

/// The two trees step 6 made: the one with the 8 MB file, and the commit without it.
const BigTrees = struct { parent: []const u8, child: []const u8 };

fn step_commit(session: *Session, out: *Io.Writer, timer: *H.Timer) !BigTrees {
    try out.print("\ndemo-m3: STEP 6: commit what a container changed, and diff\n", .{});
    const arena = session.scratch_allocator();
    const big_dir = "/home/demo/alpine-big";
    const prepare = "runuser -u demo -- sh -c 'cp -a " ++ rootfs_dir ++ " " ++ big_dir ++
        " && head -c 8000000 /dev/urandom > " ++ big_dir ++ "/big.bin'";
    const prepared = try session.run(prepare, limits.command_timeout_kvm_s);
    try H.show(out, "a copy with an 8 MB file", prepared);
    if (prepared.status != 0) return error.PrepareFailed;
    try put(session, big_dir ++ "/ops.sh", ops_script);
    _ = try session.run("chown demo:demo " ++ big_dir ++ "/ops.sh", limits.command_timeout_kvm_s);
    const import = zbx ++ " store import " ++ big_dir;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const parent = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "STEP 6", "expected a digest", err);
    };
    const parent_copy = try arena.dupe(u8, parent);
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name ops1 -- sh /ops.sh",
        .{ zbx, parent_copy[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    if (ran.status != 0 or std.mem.indexOf(u8, ran.streams.stdout, "ops-done") == null) {
        return fail_step(out, "STEP 6", "expected the operations to run", error.RunFailed);
    }
    const commit = zbx ++ " commit ops1";
    const committed = try H.run_split(session, commit);
    try H.show_split(out, commit, committed);
    const changed = checks_m3.check_changed(committed.streams, committed.status, parent_copy);
    const child = changed catch |err| {
        return fail_step(out, "STEP 6", "expected a new digest from the commit", err);
    };
    const child_copy = try arena.dupe(u8, child);
    try step_diff(session, out, parent_copy, child_copy);
    try timer.lap(out, "commit and diff");
    return .{ .parent = parent_copy, .child = child_copy };
}

fn step_diff(session: *Session, out: *Io.Writer, parent: []const u8, child: []const u8) !void {
    const arena = session.scratch_allocator();
    const text_command = try std.fmt.allocPrint(
        arena,
        "{s} store diff {s} {s}",
        .{ zbx, parent[3..15], child[3..15] },
    );
    const listed = try H.run_split(session, text_command);
    try H.show_split(out, text_command, listed);
    checks_m3.check_diff(listed.streams, listed.status, ops_diff) catch |err| {
        return fail_step(out, "STEP 6", "expected exactly the five changed paths", err);
    };
    const json_command = try std.fmt.allocPrint(
        arena,
        "{s} --output json store diff {s} {s}",
        .{ zbx, parent[3..15], child[3..15] },
    );
    const json = try H.run_split(session, json_command);
    try H.show_split(out, json_command, json);
    checks_m3.check_diff_summary(json.streams.stdout, 1, 2, 2) catch |err| {
        return fail_step(out, "STEP 6", "expected 1 added, 2 removed, 2 changed", err);
    };
    const parent_du = try std.fmt.allocPrint(
        arena,
        "{s} --output json store du {s}",
        .{ zbx, parent[3..15] },
    );
    const child_du = try std.fmt.allocPrint(
        arena,
        "{s} --output json store du {s}",
        .{ zbx, child[3..15] },
    );
    const before = try H.run_split(session, parent_du);
    try H.show_split(out, parent_du, before);
    // The next command reuses the buffer the output is in.
    const before_stdout = try arena.dupe(u8, before.streams.stdout);
    const after = try H.run_split(session, child_du);
    try H.show_split(out, child_du, after);
    const dropped = checks_m3.check_stored_drop(
        before_stdout,
        after.streams.stdout,
        8_000_000,
    );
    dropped catch |err| {
        const wanted = "expected the deleted 8 MB file out of the stored size";
        return fail_step(out, "STEP 6", wanted, err);
    };
}

fn step_commit_refusals(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 7: what a commit refuses, and a commit of nothing\n", .{});
    const arena = session.scratch_allocator();
    const start = try std.fmt.allocPrint(
        arena,
        "{s} run {s} -d --name live1 -- sleep 600",
        .{ zbx, digest[3..15] },
    );
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    if (started.status != 0) return fail_step(out, "STEP 7", "the detached run", error.RunFailed);
    const running = zbx ++ " commit live1";
    const refused = try H.run_split(session, running);
    try H.show_split(out, running, refused);
    checks_m3.check_commit_running(refused.streams, refused.status) catch |err| {
        return fail_step(out, "STEP 7", "expected ZBX-E0427 and exit 1", err);
    };
    const stop = zbx ++ " stop live1";
    _ = try H.run_split(session, stop);
    const directory = zbx ++ " run --rootfs " ++ rootfs_dir ++ " --name dir1 -- true";
    _ = try H.run_split(session, directory);
    const no_layer = zbx ++ " commit dir1";
    const none = try H.run_split(session, no_layer);
    try H.show_split(out, no_layer, none);
    checks_m3.check_no_layer(none.streams, none.status) catch |err| {
        return fail_step(out, "STEP 7", "expected ZBX-E0426 and exit 1", err);
    };
    // `prime1` ran `true` on the first tree and changed nothing.
    const nothing = zbx ++ " commit prime1";
    const same = try H.run_split(session, nothing);
    try H.show_split(out, nothing, same);
    checks_m3.check_unchanged(same.streams, same.status, digest) catch |err| {
        return fail_step(out, "STEP 7", "expected the parent's digest back", err);
    };
    try timer.lap(out, "commit refusals");
}

/// Finds the object `/etc/passwd` became, changes its first byte, and prints where it was.
const corrupt_script =
    "set -e\n" ++
    "cd " ++ store_dir ++ "\n" ++
    "for f in $(find objects -type f ! -name '*.chunks'); do\n" ++
    "  if cmp -s $f " ++ rootfs_dir ++ "/etc/passwd; then\n" ++
    "    printf X | dd of=$f bs=1 seek=0 conv=notrunc 2>/dev/null\n" ++
    "    echo CORRUPTED:$f\n" ++
    "    break\n" ++
    "  fi\n" ++
    "done\n";

fn step_verify(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: STEP 8: verify names a damaged object and where it matters\n", .{});
    const arena = session.scratch_allocator();
    try put(session, "/tmp/corrupt.sh", corrupt_script);
    const clean = zbx ++ " store verify";
    const before = try H.run_split(session, clean);
    try H.show_split(out, clean, before);
    checks_m3.check_verify_clean(before.streams, before.status) catch |err| {
        return fail_step(out, "STEP 8", "expected a clean store before the damage", err);
    };
    const corrupt = H.as_demo ++ "sh /tmp/corrupt.sh";
    const done = try H.run_split(session, corrupt);
    try H.show_split(out, corrupt, done);
    var id_buffer: [67]u8 = undefined;
    const found = checks_m3.corrupted_id(done.streams.stdout, &id_buffer) catch |err| {
        return fail_step(out, "STEP 8", "expected the script to damage an object", err);
    };
    const id = try arena.dupe(u8, found);
    const damaged = try H.run_split(session, clean);
    try H.show_split(out, clean, damaged);
    checks_m3.check_verify_damaged(damaged.streams, damaged.status, id) catch |err| {
        return fail_step(out, "STEP 8", "expected exit 2 and the object, file and path named", err);
    };
    const json_command = zbx ++ " --output json store verify";
    const json = try H.run_split(session, json_command);
    try H.show_split(out, json_command, json);
    checks_m3.check_verify_json(json.streams, json.status, id, 3) catch |err| {
        return fail_step(out, "STEP 8", "expected /etc/passwd under at least three roots", err);
    };
    const remove = try std.fmt.allocPrint(
        arena,
        "{s}rm -f {s}/objects/{s}/{s}",
        .{ H.as_demo, store_dir, id[3..5], id[5..] },
    );
    const removed = try H.run_split(session, remove);
    try H.show_split(out, remove, removed);
    if (removed.status != 0) return fail_step(out, "STEP 8", "the repair", error.RunFailed);
    const import = zbx ++ " store import " ++ rootfs_dir;
    const repaired = try H.run_split(session, import);
    try H.show_split(out, import, repaired);
    if (repaired.status != 0) return fail_step(out, "STEP 8", "the repair", error.RunFailed);
    const again = try H.run_split(session, clean);
    try H.show_split(out, clean, again);
    checks_m3.check_verify_clean(again.streams, again.status) catch |err| {
        return fail_step(out, "STEP 8", "expected a clean store after the repair", err);
    };
    try timer.lap(out, "verify");
}

/// `zbx --output json store du`, the store's total bytes.
fn store_bytes(session: *Session, out: *Io.Writer) !u64 {
    const command = zbx ++ " --output json store du";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    if (result.status != 0) return error.RunFailed;
    return try checks_m3.store_total_bytes(result.streams.stdout);
}

fn step_gc(session: *Session, out: *Io.Writer, timer: *H.Timer, big: BigTrees) !void {
    try out.print(
        "\ndemo-m3: STEP 9: gc plans, refuses a stale hash, applies, and restores\n",
        .{},
    );
    const arena = session.scratch_allocator();
    const total_before = try store_bytes(session, out);
    const leftover = H.as_demo ++ "touch " ++ store_dir ++ "/tmp/99999-0";
    _ = try H.run_split(session, leftover);
    for ([_][]const u8{ big.parent, big.child }) |digest| {
        const command = try std.fmt.allocPrint(arena, "{s} store rm {s}", .{ zbx, digest[3..15] });
        const dropped = try H.run_split(session, command);
        try H.show_split(out, command, dropped);
        if (dropped.status != 0) return fail_step(
            out,
            "STEP 9",
            "dropping a root",
            error.RunFailed,
        );
    }
    const plan_command = zbx ++ " --output json store gc";
    const planned = try H.run_split(session, plan_command);
    try H.show_split(out, plan_command, planned);
    const first = checks_m3.check_plan(planned.streams, planned.status, 8_000_000, 1) catch |err| {
        return fail_step(out, "STEP 9", "expected a plan of at least 8 MB and one leftover", err);
    };
    const hash = try arena.dupe(u8, first);
    try step_gc_stale(session, out, hash);
    const fresh = try step_gc_fresh(session, out, hash);
    const apply = try std.fmt.allocPrint(
        arena,
        "{s} --output json store gc --confirm {s}",
        .{ zbx, fresh },
    );
    const applied = try H.run_split(session, apply);
    try H.show_split(out, apply, applied);
    const found = checks_m3.check_applied(
        applied.streams,
        applied.status,
        fresh,
        8_000_000,
        1,
    ) catch |err| {
        return fail_step(out, "STEP 9", "expected the fresh plan applied", err);
    };
    const id = try arena.dupe(u8, found);
    try step_gc_after(session, out, big, id, total_before);
    try timer.lap(out, "gc");
}

/// A hash that is not the plan, and then the plan's own hash after a write to the store, are
/// refused. Returns nothing: the fresh hash is read again by the caller from a new plan.
fn step_gc_stale(session: *Session, out: *Io.Writer, hash: []const u8) !void {
    const arena = session.scratch_allocator();
    const zeros = "0000000000000000000000000000000000000000000000000000000000000000";
    const wrong = zbx ++ " store gc --confirm b3:" ++ zeros;
    const refused = try H.run_split(session, wrong);
    try H.show_split(out, wrong, refused);
    checks_m3.check_stale(refused.streams, refused.status, hash) catch |err| {
        return fail_step(out, "STEP 9", "expected E0431 for a wrong hash", err);
    };
    // A write to the store: importing the rootfs again raises the generation.
    const write = zbx ++ " store import " ++ rootfs_dir;
    const wrote = try H.run_split(session, write);
    try H.show_split(out, write, wrote);
    const late = try std.fmt.allocPrint(arena, "{s} store gc --confirm {s}", .{ zbx, hash });
    const stale = try H.run_split(session, late);
    try H.show_split(out, late, stale);
    checks_m3.check_stale(stale.streams, stale.status, null) catch |err| {
        return fail_step(out, "STEP 9", "expected the old hash refused after a write", err);
    };
}

/// The plan as the store is now: its hash differs from the old one and is what the refusal said.
fn step_gc_fresh(session: *Session, out: *Io.Writer, old: []const u8) ![]const u8 {
    const arena = session.scratch_allocator();
    const late = try std.fmt.allocPrint(arena, "{s} store gc --confirm {s}", .{ zbx, old });
    const stale = try H.run_split(session, late);
    const said = try arena.dupe(u8, try checks_m3.stale_hash(stale.streams.stderr));
    const plan_command = zbx ++ " --output json store gc";
    const planned = try H.run_split(session, plan_command);
    try H.show_split(out, plan_command, planned);
    const again = checks_m3.check_plan(planned.streams, planned.status, 8_000_000, 1) catch |err| {
        return fail_step(out, "STEP 9", "expected a plan again", err);
    };
    if (std.mem.eql(u8, again, old) or !std.mem.eql(u8, again, said)) {
        return fail_step(
            out,
            "STEP 9",
            "expected the refusal's hash to be the new plan",
            error.DigestWrong,
        );
    }
    return said;
}

fn step_gc_after(
    session: *Session,
    out: *Io.Writer,
    big: BigTrees,
    id: []const u8,
    total_before: u64,
) !void {
    const arena = session.scratch_allocator();
    const farm = try std.fmt.allocPrint(
        arena,
        "test -e {s}/cache/{s} && echo FARM-THERE || echo FARM-GONE",
        .{ store_dir, big.parent[3..] },
    );
    const gone = try session.run(farm, limits.command_timeout_kvm_s);
    try H.show(out, "the materialized directory of the dropped tree", gone);
    if (std.mem.indexOf(u8, gone.output, "FARM-GONE") == null) {
        return fail_step(
            out,
            "STEP 9",
            "expected the dead materialized directory moved",
            error.NotFresh,
        );
    }
    const total_after = try store_bytes(session, out);
    checks_m3.check_shrank(total_before, total_after, 8_000_000) catch |err| {
        return fail_step(out, "STEP 9", "expected the store to shrink by the big file", err);
    };
    const trash = zbx ++ " store gc --trash";
    const listed = try H.run_split(session, trash);
    try H.show_split(out, trash, listed);
    checks_m3.check_trash_listed(listed.streams, listed.status, id) catch |err| {
        return fail_step(out, "STEP 9", "expected the trash listed as complete", err);
    };
    const clean = zbx ++ " store verify";
    const verified = try H.run_split(session, clean);
    try H.show_split(out, clean, verified);
    checks_m3.check_verify_clean(verified.streams, verified.status) catch |err| {
        return fail_step(out, "STEP 9", "expected a clean store after the gc", err);
    };
    const restore = try std.fmt.allocPrint(arena, "{s} store restore {s}", .{ zbx, id });
    const restored = try H.run_split(session, restore);
    try H.show_split(out, restore, restored);
    checks_m3.check_restored(restored.streams, restored.status, id) catch |err| {
        return fail_step(out, "STEP 9", "expected the trash restored", err);
    };
    const back = try session.run(farm, limits.command_timeout_kvm_s);
    if (std.mem.indexOf(u8, back.output, "FARM-THERE") == null) {
        return fail_step(out, "STEP 9", "expected the materialized directory back", error.NotFresh);
    }
    if (try store_bytes(session, out) != total_before) {
        return fail_step(
            out,
            "STEP 9",
            "expected the store as large as before",
            error.StoreChanged,
        );
    }
    const final = try H.run_split(session, clean);
    checks_m3.check_verify_clean(final.streams, final.status) catch |err| {
        return fail_step(out, "STEP 9", "expected a clean store after the restore", err);
    };
    const again = try H.run_split(session, restore);
    try H.show_split(out, restore, again);
    checks_m3.check_no_trash(again.streams, again.status) catch |err| {
        return fail_step(out, "STEP 9", "expected E0433 for the restored trash", err);
    };
}

test {
    _ = @import("checks_m3.zig");
    _ = @import("harness.zig");
}
