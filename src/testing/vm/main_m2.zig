//! The M2 demo, run in a real Ubuntu 24.04 VM (the M0/M1 harness: same image, same provisioning,
//! the pinned Alpine minirootfs unpacked as user `demo`). The four steps of the spec:
//!   1. `--pids 64` with the fork bomb `sh -c 'b(){ b|b& }; b; wait; sleep 3'`: the host keeps
//!      answering, and zbx ends with `stopped: process limit reached (limit 64)`.
//!   2. `--memory 128m` with `stress-ng --vm 1 --vm-bytes 512m --oomable` (stress-ng is
//!      installed with `apk` inside a zbx run, into a copy of the rootfs): exit 137 and a last
//!      line of `killed: out of memory (limit 128 MiB)`.
//!   3. `mount -t tmpfs none /mnt` fails (EPERM, whichever way the program words it).
//!   4. `--read-only`: `touch /x` fails, `touch /tmp/x` works.
//! The acceptance criteria: the limits are files under the user's slice while a container runs
//! and the scope is gone after it; oom, process limit, signal and timeout are told apart in the
//! JSON report; the capability sets, `no_new_privs` and the seccomp filter are in force.
//! And the lifecycle: `run -d`, `ps` (text and JSON), `stop` (killed, graceful, again), a
//! container found again by new zbx processes, `--timeout`, `schema`, and the refusals.
//! `zig build demo-m2` (KVM) or `zig build demo-m2 -Daccel=tcg`. See docs/demos/m2.md.

const std = @import("std");
const Io = std.Io;
const checks_m2 = @import("checks_m2.zig");
const cloud_init = @import("cloud_init.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m2";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m2: bad arguments ({s}); see docs/demos/m2.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m2: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m2: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m2: /dev/kvm is not usable here; for software emulation " ++
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
        "{s}/overlay-demo-m2.qcow2",
        .{options.cache_dir},
    );
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = cloud_init.user_data,
        .binary = binary,
        .rootfs = rootfs,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out, &timer);
    try write_scripts(&session, out);
    try install_stress_ng(&session, out, &timer);
    try step_fork_bomb(&session, out, &timer);
    try step_memory(&session, out, &timer);
    try step_mount(&session, out, &timer);
    try step_read_only(&session, out, &timer);
    try accept_hardening(&session, out, &timer);
    try accept_limits_visible(&session, out, &timer);
    try accept_reasons(&session, out, &timer);
    try lifecycle_detached(&session, out, &timer);
    try lifecycle_stop_grace(&session, out, &timer);
    try lifecycle_timeout(&session, out, &timer);
    try lifecycle_refusals(&session, out, &timer);
    try extra_read_only_without_tmp(&session, out, &timer);
    try extra_bus_fallback(&session, out, &timer);
    try session.shutdown();
    return 0;
}

// The commands, as the user `demo` runs them, through `H.as_demo` (the session variables a login
// would set: HOME for the run records, the runtime directory and the user's bus).
const zbx = H.as_demo ++ "/home/demo/zbx";
const rootfs_dir = "/home/demo/alpine";
const stress_dir = "/home/demo/alpine-stress";
const run_prefix = zbx ++ " run --rootfs " ++ rootfs_dir;
const app_slice = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice";

fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("demo-m2: {s} FAILED: {s} ({s})\n", .{ step, what, @errorName(err) });
    return err;
}

fn show(session: *Session, out: *Io.Writer, title: []const u8, command: []const u8) !void {
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, title, result);
}

/// What is left of the container's scope, in the cgroup tree and in the manager.
const after = "echo AFTER-CGROUP:$(ls " ++ app_slice ++ " | grep -c zbx-); " ++
    "echo AFTER-MANAGER:$(runuser -u demo -- env XDG_RUNTIME_DIR=/run/user/1000 " ++
    "systemctl --user list-units --all --no-legend 'zbx-*' | wc -l)";

fn scope_of(comptime name: []const u8) []const u8 {
    return "echo SCOPE-" ++ name ++ ":$(ls " ++ app_slice ++ " | grep -c zbx-" ++ name ++
        ".scope); ";
}

/// The scope of `name` is gone from the cgroup tree and from the manager, after a settling second.
fn expect_scope_gone(
    session: *Session,
    out: *Io.Writer,
    comptime name: []const u8,
    step: []const u8,
) !void {
    const result = try session.run("sleep 2; " ++ comptime scope_of(name) ++ after, 60);
    try H.show(out, "what is left of " ++ name, result);
    checks_m2.check_scope_gone(result.output, name) catch |err| {
        return fail_step(out, step, "expected no scope of " ++ name ++ " anywhere", err);
    };
}

fn unpack_rootfs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: unpacking the pinned Alpine minirootfs as user demo\n", .{});
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

/// Writes `text` to `path` in the guest, through base64 in short pieces (a typed line is at
/// most 1 KiB, and the text has quotes in it).
fn put(session: *Session, path: []const u8, text: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    var encoded: [2048]u8 = undefined;
    const length = encoder.calcSize(text.len);
    if (length > encoded.len) return error.ScriptTooBig;
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

const hog_script = "x=$(head -c 80000000 /dev/zero | tr \"\\0\" a); echo done-${#x}\n";
const loop_script =
    "i=0; while [ $i -lt 40 ]; do sleep 100 & i=$((i+1)); done; echo spawned-$i\n";
const harden_script =
    "grep -E \"NoNewPrivs|Seccomp:|CapInh|CapPrm|CapEff|CapBnd|CapAmb\" /proc/self/status\n";

/// The host side of step 1. The spec's line is `b(){ b|b& }; b; wait`; in the VM, PID 1's `wait`
/// returns as soon as its own jobs have forked and exited (their children are not its jobs), so
/// PID 1 ends the container before the limit is reached (exit 0, nothing reported; measured, TCG).
/// `sleep 3` after the `wait` keeps PID 1 alive while the bomb runs. See docs/demos/m2.md.
/// the bomb runs in the background while the host answers a probe each
/// second; zbx's status and the last line it wrote are printed after.
const bomb_script =
    "( timeout 150 " ++ run_prefix ++ " --pids 64 --name bomb1 -- " ++
    "sh -c 'b(){ b|b& }; b; wait; sleep 3' >/tmp/bomb.out 2>/tmp/bomb.err; " ++
    "echo $? >/tmp/bomb.status ) &\n" ++
    "n=0; for i in 1 2 3 4 5; do sleep 1; " ++
    "timeout 10 cat /proc/loadavg >/dev/null && n=$((n+1)); done\n" ++
    "echo PROBES:$n; wait\n" ++
    "echo BOMB-EXIT:$(cat /tmp/bomb.status)\n" ++
    "echo BOMB-LAST:$(tail -n 1 /tmp/bomb.err | sed 's/.*\\(zbx: stopped:\\)/\\1/')\n" ++
    "echo BOMB-FORK-ERRORS:$(grep -c \"can't fork\" /tmp/bomb.err)\n" ++
    "echo BOMB-ERR-BYTES:$(wc -c </tmp/bomb.err)\n";

fn write_scripts(session: *Session, out: *Io.Writer) !void {
    try put(session, rootfs_dir ++ "/hog.sh", hog_script);
    try put(session, rootfs_dir ++ "/loop.sh", loop_script);
    try put(session, rootfs_dir ++ "/harden.sh", harden_script);
    try put(session, "/tmp/bomb.sh", bomb_script);
    // The kernel prints a report to the console for every OOM kill, and stress-ng is killed over
    // and over; the console is where the harness reads the command's output.
    try show(session, out, "quiet the kernel's console", "dmesg -n 1");
    try show(session, out, "the test scripts", "ls -l " ++ rootfs_dir ++ "/*.sh /tmp/bomb.sh");
}

// The minirootfs has no CA certificates, so apk fetches over http; it checks the signatures of
// the index and of each package against the keys in the rootfs.
const apk_main = "http://dl-cdn.alpinelinux.org/alpine/v3.20/main";
const apk_community = "http://dl-cdn.alpinelinux.org/alpine/v3.20/community";

/// stress-ng goes into a copy of the rootfs, by `apk` run inside a zbx container (the VM has a
/// network, and the container shares it with --net host; 10.0.2.3 is the emulated resolver).
fn install_stress_ng(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: provisioning: stress-ng into a copy of the rootfs\n", .{});
    const copy = "runuser -u demo -- sh -c 'cp -a " ++ rootfs_dir ++ " " ++ stress_dir ++
        " && echo nameserver 10.0.2.3 > " ++ stress_dir ++ "/etc/resolv.conf" ++
        " && printf \"%s\\n\" " ++ apk_main ++ " " ++ apk_community ++ " > " ++ stress_dir ++
        "/etc/apk/repositories'";
    const copied = try session.run(copy, limits.command_timeout_kvm_s);
    if (copied.status != 0) return fail_step(out, "provisioning", "copy", error.ProvisionFailed);
    // The container has no network unless granted (M5): apk needs the host's.
    const apk = zbx ++ " run --net host --rootfs " ++ stress_dir ++
        " --name apk1 -- apk add --no-cache stress-ng";
    const result = try session.run(apk, 300);
    try H.show(out, "apk add stress-ng, inside zbx run", result);
    if (result.status != 0) return fail_step(out, "provisioning", "apk add", error.ProvisionFailed);
    const version = zbx ++ " run --rootfs " ++ stress_dir ++ " --name sv1 -- stress-ng --version";
    const checked = try session.run(version, limits.command_timeout_kvm_s);
    try H.show(out, "stress-ng --version, inside zbx run", checked);
    if (checked.status != 0 or std.mem.indexOf(u8, checked.output, "stress-ng") == null) {
        return fail_step(out, "provisioning", "stress-ng does not run", error.ProvisionFailed);
    }
    try timer.lap(out, "stress-ng");
}

// ---- The four steps of the spec --------------------------------------------------------------

fn step_fork_bomb(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: STEP 1: a fork bomb with --pids 64; the host keeps answering\n", .{});
    const result = try session.run("sh /tmp/bomb.sh", 240);
    try H.show(out, "sh /tmp/bomb.sh (the bomb in the background, host probes)", result);
    checks_m2.check_fork_bomb(result.output, 64, 5) catch |err| {
        return fail_step(out, "STEP 1", "expected 5 host probes answered, zbx not cut off by " ++
            "timeout, and `zbx: stopped: process limit reached (limit 64)` last", err);
    };
    try expect_scope_gone(session, out, "bomb1", "STEP 1");
    try timer.lap(out, "step 1");
}

fn step_memory(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    // The spec's command has no --oomable: stress-ng then starts a new worker each time the kernel
    // kills one, for a day by default, and the demo never reaches the report (measured: over seven
    // minutes under TCG, with 128 MiB touched per restart). --oomable is its own switch for
    // "the OOM killer's victim is the answer".
    try out.print("\ndemo-m2: STEP 2: --memory 128m, stress-ng --vm 1 --vm-bytes 512m\n", .{});
    const command = "timeout 300 " ++ zbx ++ " run --rootfs " ++ stress_dir ++
        " --memory 128m --name oom1 -- stress-ng --vm 1 --vm-bytes 512m --oomable";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m2.check_oom_report(result.streams, result.status, 128) catch |err| {
        return fail_step(out, "STEP 2", "expected exit 137 and `zbx: killed: out of memory " ++
            "(limit 128 MiB)` as the last line of stderr", err);
    };
    try expect_scope_gone(session, out, "oom1", "STEP 2");
    try timer.lap(out, "step 2");
}

fn step_mount(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: STEP 3: mount -t tmpfs none /mnt is refused\n", .{});
    const command = run_prefix ++ " --name mount1 -- mount -t tmpfs none /mnt";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m2.check_mount_refused(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 3", "expected a non-zero exit from mount and " ++
            "`permission denied` or `Operation not permitted` on stderr", err);
    };
    try timer.lap(out, "step 3");
}

fn step_read_only(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: STEP 4: --read-only: touch /x fails, touch /tmp/x works\n", .{});
    const refused = run_prefix ++ " --read-only --name ro1 -- touch /x";
    const first = try H.run_split(session, refused);
    try H.show_split(out, refused, first);
    checks_m2.check_read_only_refused(first.streams, first.status) catch |err| {
        return fail_step(out, "STEP 4", "expected touch /x to fail: Read-only file system", err);
    };
    const allowed = run_prefix ++ " --read-only --name ro2 -- sh -c 'touch /tmp/x && echo tmp-ok'";
    const second = try H.run_split(session, allowed);
    try H.show_split(out, allowed, second);
    checks_m2.check_tmp_writable(second.streams, second.status) catch |err| {
        return fail_step(out, "STEP 4", "expected touch /tmp/x to work (tmpfs)", err);
    };
    try timer.lap(out, "step 4");
}

// ---- The acceptance criteria -----------------------------------------------------------------

fn accept_hardening(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: ACCEPT: capabilities, no_new_privs and seccomp in force\n", .{});
    const command = run_prefix ++ " --name hard1 -- sh /harden.sh";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m2.check_hardening_status(result.streams, result.status) catch |err| {
        return fail_step(out, "ACCEPT hardening", "expected the allowlist mask " ++
            "00000000a00405fb in four sets, CapAmb 0, NoNewPrivs 1, Seccomp 2", err);
    };
    try timer.lap(out, "hardening");
}

fn accept_limits_visible(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: ACCEPT: the limits are files in the user's slice, then gone\n", .{});
    const start = run_prefix ++ " -d --memory 64m --pids 20 --cpus 0.5 --name lim1 -- sleep 1000";
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    checks_m2.check_detached_start(started.streams, started.status, "lim1") catch |err| {
        return fail_step(out, "ACCEPT limits", "expected `lim1` on stdout, exit 0", err);
    };
    const scope = app_slice ++ "/zbx-lim1.scope";
    const look = "sleep 2; " ++ comptime scope_of("lim1") ++ "d=" ++ scope ++
        "; for f in memory.max memory.swap.max pids.max cpu.max; do echo $f=$(cat $d/$f); done" ++
        "; echo PROCS:$(wc -l < $d/cgroup.procs)";
    const result = try session.run(look, limits.command_timeout_kvm_s);
    try H.show(out, "lim1 while it runs: the scope's files", result);
    checks_m2.check_limits_visible(result.output) catch |err| {
        return fail_step(out, "ACCEPT limits", "expected memory.max=67108864, " ++
            "memory.swap.max=0, pids.max=21 (20 and the keeper), cpu.max=50000 100000", err);
    };
    const hidden = run_prefix ++
        " --name lim2 -- sh -c 'cat /proc/[0-9]*/comm | grep -c zbx; true'";
    const unseen = try H.run_split(session, hidden);
    try H.show_split(out, "the keeper is not inside the container: no process named zbx", unseen);
    if (!std.mem.eql(u8, std.mem.trim(u8, unseen.streams.stdout, " \r\n"), "0")) {
        return fail_step(out, "ACCEPT limits", "the scope's keeper is visible inside the " ++
            "container", error.KeeperVisible);
    }
    const stop = zbx ++ " stop lim1";
    _ = try session.run(stop, limits.command_timeout_kvm_s);
    try expect_scope_gone(session, out, "lim1", "ACCEPT limits");
    try timer.lap(out, "limits visible");
}

/// The same exit code (137) is an OOM kill, a stop and a timeout: the JSON report tells them apart.
fn accept_reasons(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: ACCEPT: oom, process limit, signal and exit are told apart\n", .{});
    const Case = struct { title: []const u8, command: []const u8, reason: []const u8, code: u8 };
    const cases = [_]Case{
        .{
            .title = "memory: a hog under --memory 32m",
            .command = run_prefix ++ " --output json --memory 32m --name rs1 -- sh /hog.sh",
            .reason = "oom",
            .code = 137,
        },
        .{
            .title = "process limit: 40 sleeps under --pids 16",
            .command = run_prefix ++ " --output json --pids 16 --name rs2 -- sh /loop.sh",
            .reason = "pid_limit",
            .code = 2,
        },
        .{
            .title = "signal: --timeout stops a sleep PID 1",
            .command = run_prefix ++ " --output json --timeout 2000 --name rs3 -- sleep 1000",
            .reason = "signal",
            .code = 143,
        },
        .{
            .title = "exit: exit 42",
            .command = run_prefix ++ " --output json --name rs4 -- sh -c 'exit 42'",
            .reason = "exited",
            .code = 42,
        },
    };
    inline for (cases) |case| {
        const result = try H.run_split(session, case.command);
        try H.show_split(out, case.title ++ ": " ++ case.command, result);
        checks_m2.check_exit_json(result.streams.stderr, case.reason, case.code) catch |err| {
            return fail_step(out, "ACCEPT reasons", case.title, err);
        };
    }
    try timer.lap(out, "reasons");
}

// ---- The lifecycle ---------------------------------------------------------------------------

fn lifecycle_detached(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: LIFECYCLE: run -d, ps, stop, found again by new processes\n", .{});
    const start = run_prefix ++ " -d --name det1 -- sleep 1000";
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    checks_m2.check_detached_start(started.streams, started.status, "det1") catch |err| {
        return fail_step(out, "LIFECYCLE", "run -d prints the name and returns", err);
    };
    // Each zbx below is a new process: none of them started det1.
    const text = try H.run_split(session, zbx ++ " ps");
    try H.show_split(out, "ps", text);
    checks_m2.check_ps_text(text.streams, text.status, "det1", "running") catch |err| {
        return fail_step(out, "LIFECYCLE", "ps lists det1 as running", err);
    };
    const listing = try H.run_split(session, zbx ++ " ps --output json");
    try H.show_split(out, "ps --output json", listing);
    checks_m2.check_ps_json(listing.streams, listing.status, "det1", "running", false) catch |err| {
        return fail_step(out, "LIFECYCLE", "ps JSON: det1 running, detached, its command", err);
    };
    const supervisor = "runuser -u demo -- sh -c 'p=$(grep -o \"supervisor = [0-9]*\" " ++
        "/home/demo/.local/state/zbx/runs/det1.zon | cut -d\" \" -f3); " ++
        "ps -o pid=,ppid=,sid=,tty= -p $p; test -d /proc/$p && echo SUPERVISOR-ALIVE'";
    const alive = try session.run(supervisor, limits.command_timeout_kvm_s);
    try H.show(out, "the supervisor of det1, from its record", alive);
    if (std.mem.indexOf(u8, alive.output, "SUPERVISOR-ALIVE") == null) {
        return fail_step(out, "LIFECYCLE", "the supervisor is not running", error.LineMissing);
    }
    const stop = try H.run_split(session, zbx ++ " stop det1 --output json");
    try H.show_split(out, "stop det1 --output json", stop);
    checks_m2.check_stop_json(stop.streams, stop.status, "det1", "killed", 137) catch |err| {
        return fail_step(out, "LIFECYCLE", "stop: killed (a sleep has no SIGTERM handler)", err);
    };
    try expect_scope_gone(session, out, "det1", "LIFECYCLE");
    const again = try H.run_split(session, zbx ++ " stop det1");
    try H.show_split(out, "stop det1 (again)", again);
    checks_m2.check_stop_again(again.streams, again.status, "det1") catch |err| {
        return fail_step(out, "LIFECYCLE", "a second stop says it was not running", err);
    };
    const gone = try H.run_split(session, zbx ++ " ps --output json");
    try H.show_split(out, "ps --output json (det1 ended: not listed without --all)", gone);
    if (std.mem.indexOf(u8, gone.streams.stdout, "\"name\":\"det1\"") != null) {
        return fail_step(out, "LIFECYCLE", "ps lists a stopped container", error.JsonWrong);
    }
    const every = try H.run_split(session, zbx ++ " ps --all");
    try H.show_split(out, "ps --all", every);
    checks_m2.check_ps_text(every.streams, every.status, "det1", "signal:9") catch |err| {
        return fail_step(out, "LIFECYCLE", "ps --all lists det1 as signal:9", err);
    };
    try timer.lap(out, "detached");
}

fn lifecycle_stop_grace(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: LIFECYCLE: stop gives a SIGTERM handler its grace period\n", .{});
    const start = run_prefix ++
        " -d --name det3 -- sh -c 'trap \"exit 7\" TERM; sleep 1000 & wait'";
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    checks_m2.check_detached_start(started.streams, started.status, "det3") catch |err| {
        return fail_step(out, "LIFECYCLE grace", "run -d prints the name", err);
    };
    const stop = try H.run_split(session, zbx ++ " stop det3 --grace 3000 --output json");
    try H.show_split(out, "stop det3 --grace 3000 --output json", stop);
    checks_m2.check_stop_json(stop.streams, stop.status, "det3", "graceful", 7) catch |err| {
        return fail_step(out, "LIFECYCLE grace", "graceful, with the handler's exit code 7", err);
    };
    try expect_scope_gone(session, out, "det3", "LIFECYCLE grace");
    try timer.lap(out, "grace");
}

fn lifecycle_timeout(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: LIFECYCLE: --timeout on a detached and a foreground run\n", .{});
    const start = run_prefix ++ " -d --timeout 3000 --name det4 -- sleep 1000";
    const started = try H.run_split(session, start);
    try H.show_split(out, start, started);
    checks_m2.check_detached_start(started.streams, started.status, "det4") catch |err| {
        return fail_step(out, "LIFECYCLE timeout", "run -d prints the name", err);
    };
    _ = try session.run("sleep 8", limits.command_timeout_kvm_s);
    const every = try H.run_split(session, zbx ++ " ps --all --output json");
    try H.show_split(out, "ps --all --output json, 8 s later", every);
    const object = "\"name\":\"det4\",\"state\":\"stopped\"";
    const listed = every.streams.stdout;
    const at = std.mem.indexOf(u8, listed, object);
    const flag = "\"timed_out\":true";
    if (at == null or std.mem.indexOf(u8, listed[at.?..], flag) == null) {
        return fail_step(out, "LIFECYCLE timeout", "det4 stopped, timed_out true", error.JsonWrong);
    }
    try expect_scope_gone(session, out, "det4", "LIFECYCLE timeout");
    const foreground = run_prefix ++ " --timeout 3000 --name fg1 -- sleep 1000";
    const result = try H.run_split(session, foreground);
    try H.show_split(out, foreground, result);
    checks_m2.check_timeout_report(result.streams, result.status, 3000) catch |err| {
        return fail_step(out, "LIFECYCLE timeout", "exit 143 and `timed out after 3000 ms`", err);
    };
    try timer.lap(out, "timeout");
}

fn lifecycle_refusals(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: LIFECYCLE: one-line refusals, and the schemas\n", .{});
    const cases = [_]struct { command: []const u8, code: []const u8 }{
        .{ .command = zbx ++ " stop nobody", .code = "E0402" },
        .{ .command = zbx ++ " stop det4 --grace soon", .code = "E0401" },
        .{ .command = zbx ++ " schema logs", .code = "E0406" },
    };
    inline for (cases) |case| {
        const result = try H.run_split(session, case.command);
        try H.show_split(out, case.command, result);
        checks_m2.check_refused(result.streams, result.status, case.code, 1) catch |err| {
            return fail_step(out, "LIFECYCLE refusals", case.command, err);
        };
    }
    inline for (.{ "run", "bundle", "ps", "stop", "doctor" }) |name| {
        const result = try H.run_split(session, zbx ++ " schema " ++ name);
        checks_m2.check_schema(result.streams, result.status, name) catch |err| {
            return fail_step(out, "LIFECYCLE schema", name, err);
        };
    }
    try out.print("demo-m2: schema run, bundle, ps, stop, doctor: each has its $id\n", .{});
    try timer.lap(out, "refusals");
}

// ---- Failure modes ---------------------------------------------------------------------------

fn extra_read_only_without_tmp(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: FAILURE MODE: --read-only, no /tmp, rootfs not writable\n", .{});
    const make = "rm -rf /home/demo/bare && mkdir /home/demo/bare && " ++
        "cp -a " ++ rootfs_dir ++ "/bin " ++ rootfs_dir ++ "/lib /home/demo/bare/ && " ++
        "mkdir /home/demo/bare/proc /home/demo/bare/dev && " ++
        "chown -R demo:demo /home/demo/bare && chown root:root /home/demo/bare";
    const made = try session.run(make, limits.command_timeout_kvm_s);
    if (made.status != 0) return error.ProvisionFailed;
    const command = zbx ++ " run --rootfs /home/demo/bare --read-only --name ro3 -- " ++
        "/bin/sh -c true";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m2.check_refused(result.streams, result.status, "E0209", 125) catch |err| {
        return fail_step(out, "FAILURE MODE", "expected ZBX-E0209, exit 125", err);
    };
    try timer.lap(out, "read-only without /tmp");
}

fn extra_bus_fallback(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2: FAILURE MODE: an inherited bus address that names root's bus\n", .{});
    // no-bus-env: this is the point, root's address is inherited as `su` would leave it.
    const command = "runuser -u demo -- env HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000 " ++
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus " ++
        "/home/demo/zbx -v run --rootfs " ++ rootfs_dir ++
        " --name fb1 -- sh -c 'echo fallback-ran'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const wrote = std.mem.indexOf(u8, result.streams.stdout, "fallback-ran") != null;
    const said = "connected to /run/user/1000/bus";
    const noted = std.mem.indexOf(u8, result.streams.stderr, said) != null;
    if (result.status != 0 or !wrote or !noted) {
        return fail_step(out, "FAILURE MODE", "the run must go on, on the user's own bus, " ++
            "and say so", error.LineMissing);
    }
    try timer.lap(out, "bus fallback");
}

test {
    _ = @import("checks_m2.zig");
    _ = @import("harness.zig");
}
