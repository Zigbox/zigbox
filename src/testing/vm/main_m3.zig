//! The M3 demo, run in a real Ubuntu 24.04 VM (the M0/M1/M2 harness: same image, same
//! provisioning, the pinned Alpine minirootfs unpacked as user `demo`, with an http repository
//! and a resolver so that `apk` works in a container). First the upgrade test, then the five
//! steps of the spec's M3 demo, then the acceptance criteria and the checks of each slice.
//!
//! UPGRADE. The M2 `zbx` (built from the commit in `old_release.zon`) runs, runs detached and
//!   stops containers and leaves version 3 run records; the new `zbx` lists every one with
//!   `ps --all`, and its own run writes a version 4 record beside them.
//! SPEC 1. Import the rootfs: a digest, and `store du`'s total.
//! SPEC 2. A copy with a 10 MB file is imported: the total grows by about 10 MB, not by a second
//!   rootfs.
//! SPEC 3. `printf 'apk add tree\nexit\n' | zbx run <digest> -- sh`, then `zbx commit`: a new
//!   digest, and `zbx store diff` lists additions and apk's own database files and nothing else.
//! SPEC 4. Corrupt the object of `/etc/passwd` by hand: `zbx store verify` exits 2 and names the
//!   object, its file and the paths in the root trees that reach it, in text and JSON; deleting
//!   the file and importing again makes it clean.
//! SPEC 5. The container on the copy deletes the large file (and adds, rewrites, `chmod`s,
//!   deletes another); `zbx commit`, `store diff` lists those five paths, and the new tree's
//!   stored size is smaller by the large file.
//! ACCEPTANCE. The same digest for an import of a copy with other mtimes; modes (setuid, 0600,
//!   0444), a directory, symlinks (one dangling), an extended attribute, and owners a container
//!   gave, all seen again in a container; a running container never writes the store.
//! CHECKS of the slices. A container that writes everywhere leaves the store as it was;
//!   `--read-only`; the root directory's mode; refusals; what a commit refuses; gc's plan,
//!   a stale hash, the store lock held by a writer, the apply, the trash, restore.
//! `zig build demo-m3` (KVM) or `zig build demo-m3 -Daccel=tcg`. See docs/demos/m3.md.

const std = @import("std");
const Io = std.Io;
const checks_m3 = @import("checks_m3.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");
const old_release = @import("old_release.zon");

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
    if (options.old_zbx.len == 0) {
        try out.print("demo-m3: --old-zbx is missing: the upgrade test needs the M2 binary\n", .{});
        return error.MissingBinary;
    }
    const old_binary = try Io.Dir.cwd().readFileAlloc(
        io,
        options.old_zbx,
        init.arena.allocator(),
        .limited(limits.elf_bytes_max),
    );
    try out.print("demo-m3: upgrade test from {s}: {s}, {d} bytes\n", .{
        old_release.commit, options.old_zbx, old_binary.len,
    });
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
        .old_binary = old_binary,
        .rootfs = rootfs,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out, &timer);
    try write_scripts(&session, out);
    try install_old(&session, out);
    try run_steps(init, out, &session, &timer);
    try session.shutdown();
    return 0;
}

fn run_steps(
    init: std.process.Init,
    out: *Io.Writer,
    session_ptr: *Session,
    timer_ptr: *H.Timer,
) !void {
    try step_upgrade(session_ptr, out, timer_ptr);
    const digest = try step_import(session_ptr, out, timer_ptr);
    if (init.environ_map.get("ZBX_DEMO_LOOP_STEP7")) |count| {
        return loop_step7(session_ptr, out, digest, try std.fmt.parseInt(u32, count, 10));
    }
    try step_same_digest(session_ptr, out, timer_ptr, digest);
    const big_parent = try step_copy_big(session_ptr, out, timer_ptr);
    try step_apk(session_ptr, out, timer_ptr, digest);
    try step_verify(session_ptr, out, timer_ptr);
    const big = try step_commit(session_ptr, out, timer_ptr, big_parent);
    try step_round_trip(session_ptr, out, timer_ptr);
    try step_store_untouched(session_ptr, out, timer_ptr, digest);
    try step_running_untouched(session_ptr, out, timer_ptr, digest);
    try step_read_only(session_ptr, out, timer_ptr, digest);
    try step_root_mode(session_ptr, out, timer_ptr);
    try step_refusals(session_ptr, out, timer_ptr, digest);
    try step_commit_refusals(session_ptr, out, timer_ptr, digest);
    try step_gc(session_ptr, out, timer_ptr, big);
}

/// A debugging aid, not a step: `ZBX_DEMO_LOOP_STEP7=<n> zig build demo-m3 ...` imports the
/// rootfs and then runs the commands of step 7 `n` times in the foreground, as the demo does.
/// A heartbeat started in the guest prints to the console every ten seconds (load, free memory,
/// and what the `zbx` and `runuser` processes are waiting for), so that a command which never
/// returns, or a console that goes quiet, shows what the guest was doing. It exists to look for
/// a hang (docs/demos/m3.md, "The step 7 hang").
fn loop_step7(session: *Session, out: *Io.Writer, digest: []const u8, count: u32) !void {
    const arena = session.scratch_allocator();
    try put(session, "/tmp/hb.sh", heartbeat_script);
    _ = try session.run("nohup sh /tmp/hb.sh > /dev/null 2>&1 &", limits.command_timeout_kvm_s);
    for (1..count + 1) |round| {
        try out.print("\ndemo-m3: loop round {d}/{d}\n", .{ round, count });
        const commands = [_][]const u8{
            try std.fmt.allocPrint(arena, "{s} run {s} -d --name live{d} -- sleep 600", .{
                zbx, digest[3..15], round,
            }),
            try std.fmt.allocPrint(arena, "{s} commit live{d}", .{ zbx, round }),
            try std.fmt.allocPrint(arena, "{s} stop live{d}", .{ zbx, round }),
            try std.fmt.allocPrint(arena, "{s} run --rootfs {s} --name dir{d} -- true", .{
                zbx, rootfs_dir, round,
            }),
            try std.fmt.allocPrint(arena, "{s} commit dir{d}", .{ zbx, round }),
        };
        for (commands) |command| {
            const began = session_mod.now_ms();
            const result = try H.run_split(session, command);
            try out.print("demo-m3: {d} ms, exit {d}: {s}\n", .{
                session_mod.now_ms() - began,
                result.status,
                command[(std.mem.indexOf(u8, command, "/home/demo/zbx") orelse 0)..],
            });
        }
    }
}

const heartbeat_script =
    "while :; do\n" ++
    "  sleep 10\n" ++
    "  { echo \"HB $(cut -d' ' -f1-3 /proc/loadavg) avail=$(grep MemAvailable /proc/meminfo " ++
    "| tr -s ' ' | cut -d' ' -f2)\"\n" ++
    "    ps -eo pid,stat,wchan:18,etime,args | grep -E '/home/demo/zbx|runuser|systemd-run' " ++
    "| grep -v grep | cut -c1-150\n" ++
    "    ps -eo stat,pid,wchan:18,comm | grep '^D'\n" ++
    "  } > /dev/console 2>&1\n" ++
    "done\n";

const apk_main = "http://dl-cdn.alpinelinux.org/alpine/v3.20/main";
const apk_community = "http://dl-cdn.alpinelinux.org/alpine/v3.20/community";

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
    // /etc/hosts and /etc/resolv.conf are zbx's own, bound read-only (M5): they are left alone.
    "skip='! ( -path /etc/hosts -o -path /etc/resolv.conf )'\n" ++
    "find /etc $skip -exec chmod go+w {} \\;\n" ++
    "chmod -R go+w /bin /lib /usr\n" ++
    "chmod 4755 /bin/busybox\n" ++
    "find /etc $skip -exec chown 7:7 {} \\;\n" ++
    "chown -R 7:7 /usr/share\n" ++
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
    // The minirootfs has no CA certificates, so apk fetches over http (it checks the signatures
    // itself); the emulated resolver is 10.0.2.3. As in demo-m2, `--net host` shares the network.
    const network = H.as_demo ++ "sh -c 'printf \"%s\\n\" " ++ apk_main ++ " " ++ apk_community ++
        " > " ++ rootfs_dir ++ "/etc/apk/repositories && echo nameserver 10.0.2.3 > " ++
        rootfs_dir ++ "/etc/resolv.conf'";
    const prepared = try session.run(network, limits.command_timeout_kvm_s);
    try H.show(out, "an http repository and a resolver in the rootfs", prepared);
    if (prepared.status != 0) return error.PrepareFailed;
    const check = try session.run("chown demo:demo " ++ rootfs_dir ++ "/scribble.sh; " ++
        "ls -l " ++ rootfs_dir ++ "/scribble.sh /tmp/snapshot.sh", limits.command_timeout_kvm_s);
    try H.show(out, "the test scripts", check);
}

fn step_import(session: *Session, out: *Io.Writer, timer: *H.Timer) ![]const u8 {
    try out.print("\ndemo-m3: SPEC 1: import the rootfs\n", .{});
    const command = zbx ++ " store import " ++ rootfs_dir;
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const digest = checks_m3.check_import(result.streams, result.status) catch |err| {
        return fail_step(out, "SPEC 1", "expected the digest alone on stdout, exit 0", err);
    };
    const kept = try session.scratch_allocator().dupe(u8, digest);
    spec1_total = try store_bytes(session, out);
    try timer.lap(out, "import");
    return kept;
}

/// `store du`'s total after spec step 1, which spec step 2 compares with.
var spec1_total: u64 = 0;

// ---- The upgrade test ---------------------------------------------------------------------

const old_zbx = H.as_demo ++ "/home/demo/zbx-old";

fn install_old(session: *Session, out: *Io.Writer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /home/demo/zbx-old http://10.0.2.2:{d}/zbx-old && " ++
            "chown demo:demo /home/demo/zbx-old && chmod 755 /home/demo/zbx-old && " ++
            "runuser -u demo -- /home/demo/zbx-old --version",
        .{session.server.port},
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "install the M2 zbx", result);
    if (result.status != 0) return error.InstallFailed;
}

/// Runs `command`, shows it, and fails the step unless it ended with `want`.
fn expect_exit(
    session: *Session,
    out: *Io.Writer,
    step: []const u8,
    command: []const u8,
    want: u8,
) !H.SplitResult {
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    if (result.status != want) return fail_step(out, step, command, error.ExitCodeWrong);
    return result;
}

fn record_version(
    session: *Session,
    out: *Io.Writer,
    name: []const u8,
    version: u32,
) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "grep -h version {s}/runs/{s}.zon",
        .{ state_dir, name },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, command, result);
    checks_m3.check_record_version(result.output, version) catch |err| {
        const what = try std.fmt.allocPrint(
            session.scratch_allocator(),
            "expected the record of {s} to be version {d}",
            .{ name, version },
        );
        return fail_step(out, "UPGRADE", what, err);
    };
}

fn step_upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: UPGRADE: the M2 binary leaves state, the new one reads it\n", .{});
    const step = "UPGRADE";
    const dir = " run --rootfs " ++ rootfs_dir;
    _ = try expect_exit(session, out, step, old_zbx ++ dir ++ " --name old1 -- true", 0);
    _ = try expect_exit(session, out, step, old_zbx ++ dir ++ " -d --name old2 -- sleep 600", 0);
    _ = try expect_exit(session, out, step, old_zbx ++ dir ++ " --name old3 -- sh -c 'exit 3'", 3);
    _ = try expect_exit(session, out, step, old_zbx ++ " stop old2", 0);
    const names = [_][]const u8{ "old1", "old2", "old3" };
    for (names) |name| try record_version(session, out, name, 3);
    const listing = zbx ++ " --output json ps --all";
    const listed = try expect_exit(session, out, step, listing, 0);
    checks_m3.check_ps_lists(listed.streams, listed.status, &names) catch |err| {
        return fail_step(out, step, "expected ps --all to list every old container", err);
    };
    _ = try expect_exit(session, out, step, zbx ++ " ps --all", 0);
    _ = try expect_exit(session, out, step, zbx ++ dir ++ " --name new1 -- true", 0);
    try record_version(session, out, "new1", 4);
    try record_version(session, out, "old1", 3);
    const again = try expect_exit(session, out, step, listing, 0);
    const all = [_][]const u8{ "old1", "old2", "old3", "new1" };
    checks_m3.check_ps_lists(again.streams, again.status, &all) catch |err| {
        return fail_step(out, step, "expected the old and the new record side by side", err);
    };
    try timer.lap(out, "upgrade");
}

// ---- The spec's steps 2 and 3, and the acceptance criteria --------------------------------

fn step_same_digest(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print(
        "\ndemo-m3: ACCEPTANCE: the same tree with other mtimes is the same digest\n",
        .{},
    );
    const copy = "/home/demo/alpine-b";
    const prepare = H.as_demo ++ "sh -c 'cd /home/demo && cp -a " ++ rootfs_dir ++ " " ++ copy ++
        " && find " ++ copy ++ " -exec touch -h -d @1000000000 {} +'";
    const prepared = try session.run(prepare, limits.command_timeout_kvm_s);
    try H.show(out, "a copy with every mtime changed", prepared);
    if (prepared.status != 0) return error.PrepareFailed;
    const import = zbx ++ " store import " ++ copy;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const second = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected a digest", err);
    };
    checks_m3.check_same_digest(digest, second) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected the first import's digest", err);
    };
    const total = try store_bytes(session, out);
    checks_m3.check_growth(spec1_total, total, 0, 50_000) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected the store not to grow", err);
    };
    try timer.lap(out, "same digest");
}

fn step_copy_big(session: *Session, out: *Io.Writer, timer: *H.Timer) ![]const u8 {
    try out.print(
        "\ndemo-m3: SPEC 2: a copy with one 10 MB file grows the store by that file\n",
        .{},
    );
    const big_dir = "/home/demo/alpine-big";
    const prepare = H.as_demo ++ "sh -c 'cp -a " ++ rootfs_dir ++ " " ++ big_dir ++
        " && head -c 10000000 /dev/urandom > " ++ big_dir ++ "/big.bin'";
    const prepared = try session.run(prepare, limits.command_timeout_kvm_s);
    try H.show(out, "a copy with a 10 MB file", prepared);
    if (prepared.status != 0) return error.PrepareFailed;
    try put(session, big_dir ++ "/ops.sh", ops_script);
    _ = try session.run("chown demo:demo " ++ big_dir ++ "/ops.sh", limits.command_timeout_kvm_s);
    const import = zbx ++ " store import " ++ big_dir;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const digest = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "SPEC 2", "expected a digest", err);
    };
    const kept = try session.scratch_allocator().dupe(u8, digest);
    const total = try store_bytes(session, out);
    // The file and the few tree objects that changed; a second rootfs would be 7 MB more.
    checks_m3.check_growth(spec1_total, total, 10_000_000, 10_300_000) catch |err| {
        return fail_step(out, "SPEC 2", "expected the store to grow by about 10 MB", err);
    };
    try timer.lap(out, "copy with a large file");
    return kept;
}

fn step_apk(session: *Session, out: *Io.Writer, timer: *H.Timer, digest: []const u8) !void {
    try out.print("\ndemo-m3: SPEC 3: apk add in a container, commit, diff\n", .{});
    const arena = session.scratch_allocator();
    const package = "dtach";
    const run = try std.fmt.allocPrint(
        arena,
        "printf 'apk add --no-cache {s}\\nexit\\n' | {s} run --net host {s} --name apk1 -- sh",
        .{ package, zbx, digest[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    checks_m3.check_apk_run(ran.streams, ran.status, package) catch |err| {
        return fail_step(out, "SPEC 3", "expected apk to install the package", err);
    };
    const commit = zbx ++ " commit apk1";
    const committed = try H.run_split(session, commit);
    try H.show_split(out, commit, committed);
    const changed = checks_m3.check_changed(committed.streams, committed.status, digest);
    const child = changed catch |err| {
        return fail_step(out, "SPEC 3", "expected a new digest from the commit", err);
    };
    const diff = try std.fmt.allocPrint(
        arena,
        "{s} store diff {s} {s}",
        .{ zbx, digest[3..15], child[3..15] },
    );
    const listed = try H.run_split(session, diff);
    try H.show_split(out, diff, listed);
    checks_m3.check_apk_diff(listed.streams, listed.status, "/usr/bin/dtach") catch |err| {
        const wanted = "expected only additions and apk's own database files";
        return fail_step(out, "SPEC 3", wanted, err);
    };
    try timer.lap(out, "apk add and commit");
}

// ---- Modes, owners, xattrs and links round-trip ---------------------------------------------

/// Lists what a container sees of /rt: the lines `check_lines` looks for.
const rt_script =
    "for f in suid private readonly dir700 link dangling owned olink; do\n" ++
    "  stat -c 'RT:%n %a %u:%g %F' /rt/$f 2>/dev/null\n" ++
    "done\n" ++
    "for f in link dangling olink; do\n" ++
    "  [ -L /rt/$f ] && echo LINK:/rt/$f $(readlink /rt/$f)\n" ++
    "done\n" ++
    "true\n";

/// What a container gives a new file: an owner, a mode with setgid, a link of that owner.
const own_script =
    "set -e\n" ++
    "touch /rt/owned\n" ++
    "chown 5:6 /rt/owned\n" ++
    "chmod 2750 /rt/owned\n" ++
    "ln -s owned /rt/olink\n" ++
    "chown -h 5:6 /rt/olink\n" ++
    "echo own-done\n";

/// The tree the guest makes before the import: a setuid file, 0600, 0444, a 0700 directory, two
/// symlinks (one dangling) and a file with an extended attribute.
const rt_prepare =
    "set -e\n" ++
    "rm -rf /home/demo/rt-root\n" ++
    "cp -a " ++ rootfs_dir ++ " /home/demo/rt-root\n" ++
    "cd /home/demo/rt-root\n" ++
    "mkdir rt\n" ++
    "cd rt\n" ++
    "echo suid > suid; chmod 4755 suid\n" ++
    "echo private > private; chmod 600 private\n" ++
    "echo ro > readonly; chmod 444 readonly\n" ++
    "mkdir dir700; chmod 700 dir700\n" ++
    "echo x > xfile\n" ++
    "ln -s suid link\n" ++
    "ln -s /nowhere dangling\n" ++
    "python3 -c 'import os; os.setxattr(\"xfile\", \"user.zbx\", b\"hello\")'\n" ++
    "cd ..\n" ++
    "cp /tmp/rt.sh /tmp/own.sh .\n";

/// Reads the attribute from the file the container's lower directory is made of (as root,
/// which can read what belongs to subordinate ids).
const xattr_script =
    "import glob, os\n" ++
    "for p in glob.glob('" ++ store_dir ++ "/cache/*/rt/xfile'):\n" ++
    "    print('XATTR:user.zbx=' + os.getxattr(p, 'user.zbx').decode())\n";

fn step_round_trip(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: ACCEPTANCE: modes, owners, xattrs and links round-trip\n", .{});
    const arena = session.scratch_allocator();
    try put(session, "/tmp/rt.sh", rt_script);
    try put(session, "/tmp/own.sh", own_script);
    try put(session, "/tmp/rt_prepare.sh", rt_prepare);
    try put(session, "/tmp/xattr.py", xattr_script);
    const prepare = H.as_demo ++ "sh /tmp/rt_prepare.sh";
    const prepared = try session.run(prepare, limits.command_timeout_kvm_s);
    try H.show(out, "the tree to round-trip", prepared);
    if (prepared.status != 0) return error.PrepareFailed;
    const import = zbx ++ " store import /home/demo/rt-root";
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const tree = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected a digest", err);
    };
    const tree_copy = try arena.dupe(u8, tree);
    const first = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name rt1 -- sh /rt.sh",
        .{ zbx, tree_copy[3..15] },
    );
    const seen = try H.run_split(session, first);
    try H.show_split(out, first, seen);
    checks_m3.check_lines(seen.streams.stdout, &checks_m3.round_trip_lines) catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected the modes, kinds and links as made", err);
    };
    const attribute = try session.run("python3 /tmp/xattr.py", limits.command_timeout_kvm_s);
    try H.show(out, "the extended attribute on the lower file", attribute);
    checks_m3.check_xattr(attribute.output, "user.zbx", "hello") catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected the attribute on the lower file", err);
    };
    // Owners a container gives, committed, and seen again in a run of the new tree.
    const give = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name rt2 -- sh /own.sh",
        .{ zbx, tree_copy[3..15] },
    );
    const gave = try H.run_split(session, give);
    try H.show_split(out, give, gave);
    if (gave.status != 0) return fail_step(out, "ROUND-TRIP", "the owner script", error.RunFailed);
    const commit = zbx ++ " commit rt2";
    const committed = try H.run_split(session, commit);
    try H.show_split(out, commit, committed);
    const changed = checks_m3.check_changed(committed.streams, committed.status, tree_copy);
    const child = changed catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected a new digest", err);
    };
    const child_copy = try arena.dupe(u8, child);
    const second = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name rt3 -- sh /rt.sh",
        .{ zbx, child_copy[3..15] },
    );
    const again = try H.run_split(session, second);
    try H.show_split(out, second, again);
    checks_m3.check_lines(again.streams.stdout, &checks_m3.round_trip_lines) catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected the first lines again after a commit", err);
    };
    checks_m3.check_lines(again.streams.stdout, &checks_m3.owner_lines) catch |err| {
        return fail_step(out, "ROUND-TRIP", "expected the owners the container gave", err);
    };
    try timer.lap(out, "round trip");
}

/// A container that is still running has not written the store either: the listing and sums
/// before it started and while it runs are the same, and its writes are in its upper layer.
fn step_running_untouched(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: ACCEPTANCE: a running container never writes the store\n", .{});
    const arena = session.scratch_allocator();
    const before = try session.run(
        "sh /tmp/snapshot.sh > /tmp/store.before; wc -l < /tmp/store.before",
        120,
    );
    try H.show(out, "the store before", before);
    const upper = state_dir ++ "/containers/busy1/upper";
    const start = try std.fmt.allocPrint(
        arena,
        "{s} run {s} -d --name busy1 -- sh -c 'sh /scribble.sh; sleep 600'",
        .{ zbx, digest[3..15] },
    );
    _ = try expect_exit(session, out, "ACCEPTANCE", start, 0);
    const wait = "for i in $(seq 90); do [ -e " ++ upper ++ "/left ] && break; sleep 1; done; " ++
        "[ -e " ++ upper ++ "/left ] && echo UPPER-READY";
    const waited = try session.run(wait, 200);
    try H.show(out, "wait for the container's writes", waited);
    if (std.mem.indexOf(u8, waited.output, "UPPER-READY") == null) {
        return fail_step(out, "ACCEPTANCE", "the container never wrote", error.RunFailed);
    }
    const listing = zbx ++ " --output json ps";
    const running = try expect_exit(session, out, "ACCEPTANCE", listing, 0);
    checks_m3.check_ps_lists(running.streams, running.status, &.{"busy1"}) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected the container to be running", err);
    };
    const compare = "sh /tmp/snapshot.sh > /tmp/store.after; " ++
        "if cmp -s /tmp/store.before /tmp/store.after; then echo STORE-SAME; " ++
        "else echo STORE-DIFFERS; diff /tmp/store.before /tmp/store.after | head -20; fi; " ++
        "echo UPPER-ENTRIES:$(find " ++ upper ++ " | wc -l)";
    const after = try session.run(compare, 120);
    try H.show(out, "the store while the container runs, compared", after);
    checks_m3.check_store_same(after.output) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected the store as it was", err);
    };
    checks_m3.check_upper_written(after.output, 20) catch |err| {
        return fail_step(out, "ACCEPTANCE", "expected the writes in the upper layer", err);
    };
    _ = try expect_exit(session, out, "ACCEPTANCE", zbx ++ " stop busy1", 0);
    try timer.lap(out, "running container");
}

fn step_store_untouched(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: CHECK untouched: a container that writes leaves the store\n", .{});
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
        return fail_step(out, "CHECK untouched", "the first run by digest", error.RunFailed);
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
        return fail_step(out, "CHECK untouched", "expected the script to run to its end", err);
    };
    const compare = "sh /tmp/snapshot.sh > /tmp/store.after; " ++
        "if cmp -s /tmp/store.before /tmp/store.after; then echo STORE-SAME; " ++
        "else echo STORE-DIFFERS; diff /tmp/store.before /tmp/store.after | head -20; fi; " ++
        "echo UPPER-ENTRIES:$(find " ++ state_dir ++ "/containers/scribble1/upper | wc -l); " ++
        "echo FARMS:$(ls " ++ store_dir ++ "/cache | wc -l)";
    const after = try session.run(compare, 120);
    try H.show(out, "the store after, compared", after);
    checks_m3.check_store_same(after.output) catch |err| {
        return fail_step(out, "CHECK untouched", "expected the store byte for byte as it was", err);
    };
    checks_m3.check_upper_written(after.output, 20) catch |err| {
        return fail_step(
            out,
            "CHECK untouched",
            "expected the writes in the container's upper layer",
            err,
        );
    };
    const record = try session.run(
        "cat " ++ state_dir ++ "/runs/scribble1.zon",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the run record", record);
    checks_m3.check_record(record.output, digest) catch |err| {
        return fail_step(
            out,
            "CHECK untouched",
            "expected the record to name the tree and the upper",
            err,
        );
    };
    try timer.lap(out, "store untouched");
}

fn step_read_only(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: CHECK read-only: --read-only with a digest\n", .{});
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
        return fail_step(
            out,
            "CHECK read-only",
            "expected touch /x refused, touch /tmp/x allowed",
            err,
        );
    };
    try timer.lap(out, "read-only");
}

fn step_root_mode(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: CHECK root mode: the root directory's mode is the tree's\n", .{});
    const arena = session.scratch_allocator();
    const prepare = "runuser -u demo -- chmod 711 " ++ rootfs_dir;
    _ = try session.run(prepare, limits.command_timeout_kvm_s);
    const import = zbx ++ " store import " ++ rootfs_dir;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const digest = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "CHECK root mode", "expected a digest", err);
    };
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name root1 -- sh -c 'echo ROOT:$(stat -c \"%a %u %g\" /)'",
        .{ zbx, digest[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    checks_m3.check_root(ran.streams.stdout, "711 0 0") catch |err| {
        return fail_step(out, "CHECK root mode", "expected the root to be 711, owned by root", err);
    };
    try timer.lap(out, "root mode");
}

fn step_refusals(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: CHECK refusals: an unknown digest, and a name used twice\n", .{});
    const arena = session.scratch_allocator();
    const unknown = zbx ++ " run ffffffffffff -- true";
    const result = try H.run_split(session, unknown);
    try H.show_split(out, unknown, result);
    checks_m3.check_unknown_digest(result.streams, result.status) catch |err| {
        return fail_step(out, "CHECK refusals", "expected ZBX-E0410 and exit 125", err);
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
        return fail_step(out, "CHECK refusals", wanted, error.NotFresh);
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

/// The two trees spec step 5 made: the one with the 10 MB file, and the commit without it.
const BigTrees = struct { parent: []const u8, child: []const u8 };

fn step_commit(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    parent_copy: []const u8,
) !BigTrees {
    try out.print("\ndemo-m3: SPEC 5: commit what a container changed, and diff\n", .{});
    const arena = session.scratch_allocator();
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name ops1 -- sh /ops.sh",
        .{ zbx, parent_copy[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    if (ran.status != 0 or std.mem.indexOf(u8, ran.streams.stdout, "ops-done") == null) {
        return fail_step(out, "SPEC 5", "expected the operations to run", error.RunFailed);
    }
    const commit = zbx ++ " commit ops1";
    const committed = try H.run_split(session, commit);
    try H.show_split(out, commit, committed);
    const changed = checks_m3.check_changed(committed.streams, committed.status, parent_copy);
    const child = changed catch |err| {
        return fail_step(out, "SPEC 5", "expected a new digest from the commit", err);
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
        return fail_step(out, "SPEC 5", "expected exactly the five changed paths", err);
    };
    const json_command = try std.fmt.allocPrint(
        arena,
        "{s} --output json store diff {s} {s}",
        .{ zbx, parent[3..15], child[3..15] },
    );
    const json = try H.run_split(session, json_command);
    try H.show_split(out, json_command, json);
    checks_m3.check_diff_summary(json.streams.stdout, 1, 2, 2) catch |err| {
        return fail_step(out, "SPEC 5", "expected 1 added, 2 removed, 2 changed", err);
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
        10_000_000,
    );
    dropped catch |err| {
        const wanted = "expected the deleted 10 MB file out of the stored size";
        return fail_step(out, "SPEC 5", wanted, err);
    };
}

fn step_commit_refusals(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print(
        "\ndemo-m3: CHECK commit refusals: what a commit refuses, and a commit of nothing\n",
        .{},
    );
    const arena = session.scratch_allocator();
    const start = try std.fmt.allocPrint(
        arena,
        "{s} run {s} -d --name live1 -- sleep 600",
        .{ zbx, digest[3..15] },
    );
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    if (started.status != 0) return fail_step(
        out,
        "CHECK commit refusals",
        "the detached run",
        error.RunFailed,
    );
    const running = zbx ++ " commit live1";
    const refused = try H.run_split(session, running);
    try H.show_split(out, running, refused);
    checks_m3.check_commit_running(refused.streams, refused.status) catch |err| {
        return fail_step(out, "CHECK commit refusals", "expected ZBX-E0427 and exit 1", err);
    };
    const stop = zbx ++ " stop live1";
    _ = try H.run_split(session, stop);
    const directory = zbx ++ " run --rootfs " ++ rootfs_dir ++ " --name dir1 -- true";
    _ = try H.run_split(session, directory);
    const no_layer = zbx ++ " commit dir1";
    const none = try H.run_split(session, no_layer);
    try H.show_split(out, no_layer, none);
    checks_m3.check_no_layer(none.streams, none.status) catch |err| {
        return fail_step(out, "CHECK commit refusals", "expected ZBX-E0426 and exit 1", err);
    };
    // `prime1` ran `true` on the first tree and changed nothing.
    const nothing = zbx ++ " commit prime1";
    const same = try H.run_split(session, nothing);
    try H.show_split(out, nothing, same);
    checks_m3.check_unchanged(same.streams, same.status, digest) catch |err| {
        return fail_step(out, "CHECK commit refusals", "expected the parent's digest back", err);
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
    try out.print("\ndemo-m3: SPEC 4: verify names a damaged object and where it matters\n", .{});
    const arena = session.scratch_allocator();
    try put(session, "/tmp/corrupt.sh", corrupt_script);
    const clean = zbx ++ " store verify";
    const before = try H.run_split(session, clean);
    try H.show_split(out, clean, before);
    checks_m3.check_verify_clean(before.streams, before.status) catch |err| {
        return fail_step(out, "SPEC 4", "expected a clean store before the damage", err);
    };
    const corrupt = H.as_demo ++ "sh /tmp/corrupt.sh";
    const done = try H.run_split(session, corrupt);
    try H.show_split(out, corrupt, done);
    var id_buffer: [67]u8 = undefined;
    const found = checks_m3.corrupted_id(done.streams.stdout, &id_buffer) catch |err| {
        return fail_step(out, "SPEC 4", "expected the script to damage an object", err);
    };
    const id = try arena.dupe(u8, found);
    const damaged = try H.run_split(session, clean);
    try H.show_split(out, clean, damaged);
    checks_m3.check_verify_damaged(damaged.streams, damaged.status, id) catch |err| {
        return fail_step(out, "SPEC 4", "expected exit 2 and the object, file and path named", err);
    };
    const json_command = zbx ++ " --output json store verify";
    const json = try H.run_split(session, json_command);
    try H.show_split(out, json_command, json);
    checks_m3.check_verify_json(json.streams, json.status, id, 3) catch |err| {
        return fail_step(out, "SPEC 4", "expected /etc/passwd under at least three roots", err);
    };
    const remove = try std.fmt.allocPrint(
        arena,
        "{s}rm -f {s}/objects/{s}/{s}",
        .{ H.as_demo, store_dir, id[3..5], id[5..] },
    );
    const removed = try H.run_split(session, remove);
    try H.show_split(out, remove, removed);
    if (removed.status != 0) return fail_step(out, "SPEC 4", "the repair", error.RunFailed);
    const import = zbx ++ " store import " ++ rootfs_dir;
    const repaired = try H.run_split(session, import);
    try H.show_split(out, import, repaired);
    if (repaired.status != 0) return fail_step(out, "SPEC 4", "the repair", error.RunFailed);
    const again = try H.run_split(session, clean);
    try H.show_split(out, clean, again);
    checks_m3.check_verify_clean(again.streams, again.status) catch |err| {
        return fail_step(out, "SPEC 4", "expected a clean store after the repair", err);
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
        "\ndemo-m3: CHECK gc: gc plans, refuses a stale hash, applies, and restores\n",
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
            "CHECK gc",
            "dropping a root",
            error.RunFailed,
        );
    }
    const plan_command = zbx ++ " --output json store gc";
    // The container `ops1` ended with its layer kept, so it can still be committed and holds its
    // parent tree, which is the one with the big file: the plan leaves that tree alone.
    const held = try H.run_split(session, plan_command);
    try H.show_split(out, plan_command, held);
    checks_m3.check_plan_holds(held.streams, held.status, 1_000_000) catch |err| {
        return fail_step(out, "CHECK gc", "expected the committable container's tree kept", err);
    };
    // Its layer deleted (as root: the files belong to subordinate ids), nothing can be committed
    // onto that tree, and it is a plan item.
    const forget = "rm -rf " ++ state_dir ++ "/containers/ops1";
    const forgotten = try session.run(forget, limits.command_timeout_kvm_s);
    try H.show(out, forget, forgotten);
    if (forgotten.status != 0) return fail_step(out, "CHECK gc", "the layer", error.RunFailed);
    const planned = try H.run_split(session, plan_command);
    try H.show_split(out, plan_command, planned);
    const first = checks_m3.check_plan(planned.streams, planned.status, 8_000_000, 1) catch |err| {
        return fail_step(out, "CHECK gc", "expected a plan of at least 8 MB and one leftover", err);
    };
    const hash = try arena.dupe(u8, first);
    try step_gc_stale(session, out, hash);
    const fresh = try step_gc_fresh(session, out, hash);
    try step_gc_busy(session, out, fresh);
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
        return fail_step(out, "CHECK gc", "expected the fresh plan applied", err);
    };
    const id = try arena.dupe(u8, found);
    try step_gc_after(session, out, big, id, total_before);
    try timer.lap(out, "gc");
}

/// A writer (`flock -s` on the store's lock file, as an importer would hold it) keeps the
/// confirmed gc out: it waits its ten seconds and says so, changing nothing.
fn step_gc_busy(session: *Session, out: *Io.Writer, fresh: []const u8) !void {
    const arena = session.scratch_allocator();
    const flock = "sh -c 'flock -s " ++ store_dir ++ "/lock sleep 41 >/dev/null 2>&1 &'";
    const hold = H.as_demo ++ flock;
    const started = try H.run_split(session, hold);
    try H.show_split(out, "a writer holds the store lock (flock -s)", started);
    if (started.status != 0) return fail_step(out, "CHECK gc", "the writer", error.RunFailed);
    const confirm = try std.fmt.allocPrint(arena, "{s} store gc --confirm {s}", .{ zbx, fresh });
    const busy = try H.run_split(session, confirm);
    try H.show_split(out, confirm, busy);
    checks_m3.check_busy(busy.streams, busy.status, "are writing to the store") catch |err| {
        return fail_step(out, "CHECK gc", "expected E0436 while a writer holds the lock", err);
    };
    const release = "pkill -f 'sleep 41'; pkill -f 'flock -s'; true";
    _ = try session.run(release, limits.command_timeout_kvm_s);
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
        return fail_step(out, "CHECK gc", "expected E0431 for a wrong hash", err);
    };
    // A write to the store: importing the rootfs again raises the generation.
    const write = zbx ++ " store import " ++ rootfs_dir;
    const wrote = try H.run_split(session, write);
    try H.show_split(out, write, wrote);
    const late = try std.fmt.allocPrint(arena, "{s} store gc --confirm {s}", .{ zbx, hash });
    const stale = try H.run_split(session, late);
    try H.show_split(out, late, stale);
    checks_m3.check_stale(stale.streams, stale.status, null) catch |err| {
        return fail_step(out, "CHECK gc", "expected the old hash refused after a write", err);
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
        return fail_step(out, "CHECK gc", "expected a plan again", err);
    };
    if (std.mem.eql(u8, again, old) or !std.mem.eql(u8, again, said)) {
        return fail_step(
            out,
            "CHECK gc",
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
            "CHECK gc",
            "expected the dead materialized directory moved",
            error.NotFresh,
        );
    }
    const total_after = try store_bytes(session, out);
    checks_m3.check_shrank(total_before, total_after, 8_000_000) catch |err| {
        return fail_step(out, "CHECK gc", "expected the store to shrink by the big file", err);
    };
    const trash = zbx ++ " store gc --trash";
    const listed = try H.run_split(session, trash);
    try H.show_split(out, trash, listed);
    checks_m3.check_trash_listed(listed.streams, listed.status, id) catch |err| {
        return fail_step(out, "CHECK gc", "expected the trash listed as complete", err);
    };
    const clean = zbx ++ " store verify";
    const verified = try H.run_split(session, clean);
    try H.show_split(out, clean, verified);
    checks_m3.check_verify_clean(verified.streams, verified.status) catch |err| {
        return fail_step(out, "CHECK gc", "expected a clean store after the gc", err);
    };
    try step_gc_restore(session, out, id, total_before, farm);
}

fn step_gc_restore(
    session: *Session,
    out: *Io.Writer,
    id: []const u8,
    total_before: u64,
    farm: []const u8,
) !void {
    const arena = session.scratch_allocator();
    const clean = zbx ++ " store verify";
    const restore = try std.fmt.allocPrint(arena, "{s} store restore {s}", .{ zbx, id });
    const restored = try H.run_split(session, restore);
    try H.show_split(out, restore, restored);
    checks_m3.check_restored(restored.streams, restored.status, id) catch |err| {
        return fail_step(out, "CHECK gc", "expected the trash restored", err);
    };
    const back = try session.run(farm, limits.command_timeout_kvm_s);
    if (std.mem.indexOf(u8, back.output, "FARM-THERE") == null) {
        return fail_step(
            out,
            "CHECK gc",
            "expected the materialized directory back",
            error.NotFresh,
        );
    }
    if (try store_bytes(session, out) != total_before) {
        return fail_step(
            out,
            "CHECK gc",
            "expected the store as large as before",
            error.StoreChanged,
        );
    }
    const final = try H.run_split(session, clean);
    checks_m3.check_verify_clean(final.streams, final.status) catch |err| {
        return fail_step(out, "CHECK gc", "expected a clean store after the restore", err);
    };
    const again = try H.run_split(session, restore);
    try H.show_split(out, restore, again);
    checks_m3.check_no_trash(again.streams, again.status) catch |err| {
        return fail_step(out, "CHECK gc", "expected E0433 for the restored trash", err);
    };
}

test {
    _ = @import("checks_m3.zig");
    _ = @import("harness.zig");
}
