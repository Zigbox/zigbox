//! The M1 demo, run in a real Ubuntu 24.04 VM (the M0 harness: same image, same provisioning):
//! the pinned Alpine minirootfs is unpacked as user `demo`, and `zbx run` runs in it.
//!   1. The shell is fed `id`, `ps`, `hostname` and `cat /etc/os-release` on stdin: root inside,
//!      only PID 1 and `ps`, the container's name as hostname, Alpine.
//!   2. `sleep 1000` in the background: the host `ps` shows it with the demo user's uid.
//!   3. `touch /etc/hacked` lands in the rootfs, owned by demo, and not on the host.
//!   4. `exit 42` makes zbx exit 42.
//!   5. A real Ctrl-C (byte 0x03 on the serial console) stops a foreground `sleep 1000` in the
//!      container within 2 s, with exit 130.
//! And: the full id map inside, a host mount and process invisible, a missing rootfs is
//! ZBX-E0201 with exit 1, and a bundle made after a run with secrets planted holds none.
//! `zig build demo-m1` (KVM) or `zig build demo-m1 -Daccel=tcg`. See docs/demos/m1.md.

const std = @import("std");
const Io = std.Io;
const checks_m1 = @import("checks_m1.zig");
const cloud_init = @import("cloud_init.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m1";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m1: bad arguments ({s}); see docs/demos/m1.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m1: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m1: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn kvm_message(out: *Io.Writer) !void {
    try out.print("demo-m1: /dev/kvm is not usable here; for software emulation " ++
        "(slow) add -Daccel=tcg\n", .{});
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try kvm_message(out);
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
        "{s}/overlay-demo-m1.qcow2",
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
    try step_shell(&session, out, &timer);
    try step_host_sees_process(&session, out, &timer);
    try step_write_lands(&session, out, &timer);
    try step_exit_code(&session, out, &timer);
    try step_ctrl_c(&session, out, &timer);
    try extra_id_maps(&session, out, &timer);
    try extra_host_invisible(&session, out, &timer);
    try extra_missing_rootfs(&session, out, &timer);
    try extra_bundle(&session, out, &timer);
    try session.shutdown();
    return 0;
}

// The commands, as the user `demo` runs them. HOME is set because `runuser -u` keeps root's, and
// the run records and bundles go under the home of the user who runs zbx.
const run_prefix = "runuser -u demo -- env HOME=/home/demo /home/demo/zbx run " ++
    "--rootfs /home/demo/alpine";
const rootfs_dir = "/home/demo/alpine";

fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("demo-m1: {s} FAILED: {s} ({s})\n", .{ step, what, @errorName(err) });
    return err;
}

fn unpack_rootfs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: unpacking the pinned Alpine minirootfs as user demo\n", .{});
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "runuser -u demo -- sh -c 'mkdir -p {s} && tar -xzf /tmp/rootfs.tar.gz -C {s}' && " ++
            "ls {s} | head -20 && stat -c '%U %n' {s}/bin/busybox",
        .{ session.server.port, rootfs_dir, rootfs_dir, rootfs_dir, rootfs_dir },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "unpack the rootfs", result);
    if (result.status != 0) return error.UnpackFailed;
    if (std.mem.indexOf(u8, result.output, "demo " ++ rootfs_dir ++ "/bin/busybox") == null) {
        return error.RootfsNotOwnedByDemo;
    }
    try timer.lap(out, "unpack");
}

fn step_shell(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: STEP 1: the shell, fed commands on stdin\n", .{});
    const command = "printf 'id\\nps\\nhostname\\ncat /etc/os-release\\n' | " ++
        run_prefix ++ " --name demo1 -- /bin/sh";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m1.check_shell_session(result.streams, result.status, "demo1") catch |err| {
        return fail_step(out, "STEP 1", "expected uid=0(root), only PID 1 and ps, " ++
            "hostname demo1, Alpine, empty stderr, exit 0", err);
    };
    try timer.lap(out, "step 1");
}

fn step_host_sees_process(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: STEP 2: sleep 1000 in the background, seen by the host's ps\n", .{});
    const command = "runuser -u demo -- sh -c 'setsid env HOME=/home/demo /home/demo/zbx run " ++
        "--rootfs " ++ rootfs_dir ++ " --name bg1 -- sleep 1000 </dev/null >/dev/null 2>&1 &'; " ++
        "for i in $(seq 60); do pgrep -u demo -fx 'sleep 1000' >/dev/null && break; " ++
        "sleep 0.5; done; " ++
        "ps -eo uid=,args= | grep -E '^ *[0-9]+ sleep 1000$' | sed 's/^ *//'; " ++
        "pkill -TERM -u demo -f 'zbx run .*bg1'; " ++
        "for i in $(seq 60); do pgrep -u demo -fx 'sleep 1000' >/dev/null || break; " ++
        "sleep 0.5; done; " ++
        "echo GONE:$(pgrep -c -u demo -fx 'sleep 1000')";
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "sleep 1000 in a container, then ps on the host", result);
    checks_m1.check_host_sees_user_process(result.output, 1000) catch |err| {
        return fail_step(out, "STEP 2", "expected one `1000 sleep 1000` row on the host, and " ++
            "none after stopping zbx", err);
    };
    try timer.lap(out, "step 2");
}

fn step_write_lands(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: STEP 3: touch /etc/hacked lands in the rootfs\n", .{});
    const container = run_prefix ++ " --name hack1 -- sh -c 'touch /etc/hacked'";
    const first = try H.run_split(session, container);
    try H.show_split(out, container, first);
    if (first.status != 0) return fail_step(out, "STEP 3", "touch failed", error.ExitCodeWrong);
    const look = "stat -c '%U %n' " ++ rootfs_dir ++ "/etc/hacked; " ++
        "test ! -e /etc/hacked && echo host-etc-clean";
    const result = try session.run(look, limits.command_timeout_kvm_s);
    try H.show(out, look, result);
    checks_m1.check_write_lands_in_rootfs(
        result.output,
        "demo",
        rootfs_dir ++ "/etc/hacked",
    ) catch |err| {
        return fail_step(out, "STEP 3", "expected the file in the rootfs, owned by demo, " ++
            "and none on the host", err);
    };
    try timer.lap(out, "step 3");
}

fn step_exit_code(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: STEP 4: exit 42 makes zbx exit 42\n", .{});
    const command = run_prefix ++ " --name exit1 -- sh -c 'exit 42'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m1.check_exit_passes_through(result.streams, result.status, 42) catch |err| {
        return fail_step(out, "STEP 4", "expected exit 42 and nothing on either stream", err);
    };
    try timer.lap(out, "step 4");
}

/// The real thing: a script is run from the console's own shell, so it is the foreground job of
/// the console tty, and the byte 0x03 goes through the tty line discipline as a SIGINT, exactly as
/// a person's Ctrl-C does. The script's shell catches SIGINT (`trap : INT`, a handler, so zbx does
/// not inherit an ignored SIGINT) and goes on to print zbx's exit status; without it bash would
/// abandon the rest of the line. `setpriv` execs, so nothing sits between the tty and zbx.
fn step_ctrl_c(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: STEP 5: a real Ctrl-C (byte 0x03) on a foreground run\n", .{});
    const write_script = "printf '%s\\n' 'trap : INT' " ++
        "'setpriv --reuid=1000 --regid=1000 --init-groups env HOME=/home/demo " ++
        "/home/demo/zbx run --rootfs " ++ rootfs_dir ++ " --name ctrlc1 -- " ++
        "sh -c \"echo CTRLC-READY; exec sleep 1000\" 2>/tmp/zbx-ctrlc-err' " ++
        "'echo CTRLC-EXIT:$?' 'cat /tmp/zbx-ctrlc-err' > /tmp/ctrlc.sh";
    const wrote = try session.run(write_script, limits.command_timeout_kvm_s);
    if (wrote.status != 0) return error.ScriptNotWritten;
    const line = "sh /tmp/ctrlc.sh\n";
    const mark = session.console_len;
    try session.send(line);
    const ready = try session.wait_for("CTRLC-READY", mark, limits.command_timeout_kvm_s);
    // Let the container get into its sleep, then press Ctrl-C.
    const settle_until = session_mod.now_ms() + 500 * session.scale;
    while (session_mod.now_ms() < settle_until) try session.pump(limits.poll_step_ms);
    const pressed = session_mod.now_ms();
    try session.send("\x03");
    const budget_s: u32 = 2;
    const after = try session.wait_for("CTRLC-EXIT:", ready, budget_s * 4 + 30);
    const elapsed = session_mod.now_ms() - pressed;
    const end = try session.wait_for("\n", after, limits.command_timeout_kvm_s);
    const code_text = std.mem.trim(u8, session.console[after..end], " \r\n");
    const status = std.fmt.parseInt(u8, code_text, 10) catch return error.BadStatus;
    // The note on stderr follows the status line; it names the signal.
    const noted = try session.wait_for("(SIGINT)", end, limits.command_timeout_kvm_s);
    var note_buffer: [512]u8 = undefined;
    const tail = session.console[end..noted];
    const length = try session_mod.clean_output(
        tail[0..@min(tail.len, note_buffer.len)],
        &note_buffer,
    );
    const note = note_buffer[0..length];
    // 2 s on KVM; the TCG guest is slower and its clock budget is scaled the same way.
    const limit_ms: u64 = @as(u64, budget_s) * 1000 * session.scale;
    try out.print("\ndemo-m1: Ctrl-C sent; zbx exited {d} after {d} ms (limit {d} ms)\n", .{
        status, elapsed, limit_ms,
    });
    checks_m1.check_ctrl_c(status, elapsed, limit_ms, note) catch |err| {
        return fail_step(out, "STEP 5", "expected exit 130 within 2 s and the SIGINT note", err);
    };
    _ = try session.run("true", limits.command_timeout_kvm_s); // Back at a clean prompt.
    try timer.lap(out, "step 5");
}

fn extra_id_maps(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: EXTRA: /proc/self/uid_map inside shows the full range\n", .{});
    const command = run_prefix ++ " --name idmap1 -- sh -c " ++
        "'cat /proc/self/uid_map; echo ---; cat /proc/self/gid_map'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m1.check_full_id_maps(result.streams, result.status, 1000, 1000) catch |err| {
        return fail_step(out, "EXTRA id maps", "expected `0 1000 1` and `1 100000 65536` for " ++
            "uid and gid, and no warning", err);
    };
    try timer.lap(out, "id maps");
}

fn extra_host_invisible(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: EXTRA: a host mount and a host process are invisible inside\n", .{});
    const host_side = "mkdir -p /mnt/hostmount-demo && mount -t tmpfs tmpfs " ++
        "/mnt/hostmount-demo && " ++
        "(setsid sleep 4321 </dev/null >/dev/null 2>&1 &); sleep 1; " ++
        "grep -q hostmount-demo /proc/mounts && echo HOST-MOUNT:yes; " ++
        "pgrep -fx 'sleep 4321' >/dev/null && echo HOST-PROC:yes; ";
    const inside = run_prefix ++ " --name hidden1 -- sh -c " ++
        "'if grep -q hostmount-demo /proc/mounts; then echo MOUNT-LEAK; else echo " ++
        "mount-hidden; fi; " ++
        "if ps | grep -q \"[4]321\"; then echo PROCESS-LEAK; else echo process-hidden; fi'";
    const cleanup = "; umount /mnt/hostmount-demo; pkill -fx 'sleep 4321'; true";
    const command = host_side ++ inside ++ cleanup;
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "mount and process on the host, then look from inside", result);
    checks_m1.check_host_is_invisible(result.output) catch |err| {
        return fail_step(out, "EXTRA host invisible", "expected the host mount and process to " ++
            "exist, and neither to be visible in the container", err);
    };
    try timer.lap(out, "host invisible");
}

fn extra_missing_rootfs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: EXTRA: a missing rootfs is ZBX-E0201, exit 1\n", .{});
    const command = "runuser -u demo -- env HOME=/home/demo /home/demo/zbx run " ++
        "--rootfs /home/demo/nothere -- /bin/sh";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m1.check_missing_rootfs(result.streams, result.status) catch |err| {
        return fail_step(out, "EXTRA missing rootfs", "expected error[ZBX-E0201] on stderr, " ++
            "nothing on stdout, exit 1", err);
    };
    try timer.lap(out, "missing rootfs");
}

fn extra_bundle(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m1: EXTRA: a bundle after a run with secrets planted holds none\n", .{});
    const script = "z=/home/demo/zbx; " ++
        "$z run --rootfs " ++ rootfs_dir ++ " --name secret1 -- sh -c \"echo ran\" x " ++
        "--password=hunter2cmd; " ++
        "P=$($z bundle --last); echo BUNDLE:$P; tar -tzf $P; echo LISTED-END; " ++
        "echo LEAKS:$(tar -xzOf $P | grep -c -e hunter2 -e ghp_FAKEdemo); " ++
        "echo REDACTED:$(tar -xzOf $P | grep -c redacted:)";
    const command = "runuser -u demo -- env HOME=/home/demo " ++
        "GITHUB_TOKEN=ghp_FAKEdemo0123456789abcdefghij " ++
        "DB_PASSWORD=hunter2demo sh -c '" ++ script ++ "'";
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "run, bundle --last, tar -tzf, grep for the secrets", result);
    checks_m1.check_bundle_has_no_secret(result.output) catch |err| {
        return fail_step(out, "EXTRA bundle", "expected a listed bundle with no trace of the " ++
            "planted secrets and at least one [redacted:...] marker", err);
    };
    try timer.lap(out, "bundle");
}

test {
    _ = @import("checks_m1.zig");
    _ = @import("harness.zig");
}
