//! A first look at M2 in the real VM (the M1 harness: same image, same provisioning), run by
//! `zig build vm-m2-experiment` (KVM) or `-Daccel=tcg`. It is not the M2 demo (that is slice 5):
//! it runs the limits and the exit reports against the guest's real systemd user manager and
//! kernel and prints what happened, so that the report can say exactly what ran.
//!   - `--pids 16` with a fork loop, and the brief's fork bomb with `--pids 64`;
//!   - `--memory 32m` with a memory hog that is PID 1, and with one that is a child of PID 1;
//!   - the limit files of a running container, read from the host, and gone after it ends;
//!   - whether the scope is gone from the cgroup tree and from the manager after each run;
//!   - an inherited root bus address, which the fallback to the user's own bus has to survive;
//!   - slice 4: `run -d`, `ps` (text and JSON), `stop` (graceful, killed, unknown), `--timeout`,
//!     the scope gone afterwards, and re-adoption by a new zbx process.

const std = @import("std");
const Io = std.Io;
const cloud_init = @import("cloud_init.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "vm-m2";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("vm-m2: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = experiment(init, out, options) catch |err| {
        try out.print("\nvm-m2: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\nvm-m2: finished in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

const rootfs_dir = "/home/demo/alpine";
const run_prefix = H.as_demo ++ "/home/demo/zbx -v run --rootfs " ++ rootfs_dir;
const app_slice = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice";

fn experiment(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = try harness.choose_accel(options.accel, H.kvm_usable(io));
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
    const overlay = try std.fmt.allocPrint(arena, "{s}/overlay-vm-m2.qcow2", .{options.cache_dir});
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
    try unpack_and_scripts(&session, out);
    try show(&session, out, "the guest", "uname -r; systemctl --version | head -1; " ++
        "stat -fc %T /sys/fs/cgroup; ls -ld /run/user/0 /run/user/0/bus /run/user/1000/bus");
    try hardening(&session, out);
    try pids_limit(&session, out);
    try memory_limit(&session, out);
    try limits_visible(&session, out);
    try inherited_bus(&session, out);
    try lifecycle(&session, out);
    const names = "pid1 bomb1 oom1 oom2 oom3 oomchild det1 det3";
    try show(&session, out, "records", "for f in " ++ names ++ "; do " ++
        "echo == $f; cat /home/demo/.local/state/zbx/runs/$f.zon 2>&1 | " ++
        "grep -E 'version|exit|reason|detached|scope|limit'; done");
    try session.shutdown();
    return 0;
}

fn show(session: *Session, out: *Io.Writer, title: []const u8, command: []const u8) !void {
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, title, result);
}

fn unpack_and_scripts(session: *Session, out: *Io.Writer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "runuser -u demo -- sh -c 'mkdir -p {s} && tar -xzf /tmp/rootfs.tar.gz -C {s}' && " ++
            "printf '%s\\n' 'x=$(head -c 80000000 /dev/zero | tr \"\\0\" a); echo done-${{#x}}' " ++
            "> {s}/hog.sh && " ++
            "printf '%s\\n' 'i=0; while [ $i -lt 40 ]; do sleep 100 & i=$((i+1)); done; " ++
            "echo spawned-$i' > {s}/loop.sh && ls {s}/*.sh",
        .{ session.server.port, rootfs_dir, rootfs_dir, rootfs_dir, rootfs_dir, rootfs_dir },
    );
    try show(session, out, "unpack the rootfs and write the test scripts", command);
}

/// What is left of the container's scope, in the cgroup tree and in the manager.
const after = "echo AFTER-CGROUP:$(ls " ++ app_slice ++ " | grep -c zbx-); " ++
    "echo AFTER-MANAGER:$(runuser -u demo -- env XDG_RUNTIME_DIR=/run/user/1000 " ++
    "systemctl --user list-units --all --no-legend 'zbx-*' | wc -l)";

fn split(session: *Session, out: *Io.Writer, command: []const u8) !void {
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    try show(session, out, "what is left", after);
}

/// The scripts the hardening checks run inside the container, written into the rootfs as root.
const hardening_scripts = [_][]const u8{
    "printf '%s\\n' 'echo == status' " ++
        "'grep -E \"NoNewPrivs|Seccomp:|CapInh|CapPrm|CapEff|CapBnd|CapAmb\" /proc/self/status' " ++
        "'echo == mount' 'mount -t tmpfs none /mnt; echo status:$?' " ++
        "'echo == hostname' 'hostname changed; echo status:$?' " ++
        "'echo == unshare' 'unshare -U true; echo status:$?' " ++
        "> /home/demo/alpine/hard1.sh",
    "printf '%s\\n' 'echo == chown' 'touch /tmp/c; chown 5:5 /tmp/c; echo status:$?' " ++
        "'echo == applets' " ++
        "'busybox --list | grep -E \"^(unshare|nsenter|mount|chroot)$\" | tr \"\\n\" \" \"' " ++
        "'echo' 'echo == fork and pipes' 'sh -c \"echo child\" | cat; ps | wc -l' " ++
        "> /home/demo/alpine/hard2.sh",
    "printf '%s\\n' 'echo == write /x' 'touch /x; echo status:$?' " ++
        "'echo == write /tmp/x' 'touch /tmp/x; echo status:$?' " ++
        "'echo == write /run/y' 'touch /run/y; echo status:$?' " ++
        "'echo == write /etc/f' 'echo hi > /etc/f; echo status:$?' " ++
        "'echo == mounts' " ++
        "'grep -E \" (/|/tmp|/run) \" /proc/self/mountinfo | cut -d\" \" -f5-7' " ++
        "> /home/demo/alpine/ro.sh",
};

fn hardening(session: *Session, out: *Io.Writer) !void {
    for (hardening_scripts) |script| try show(session, out, "write a test script", script);
    try out.print("\nvm-m2: hardening, a normal run\n", .{});
    try split(session, out, run_prefix ++ " --name hard1 -- sh /hard1.sh");
    try split(session, out, run_prefix ++ " --name hard2 -- sh /hard2.sh");
    try out.print("\nvm-m2: --read-only\n", .{});
    try split(session, out, run_prefix ++ " --read-only --name ro1 -- sh /ro.sh");
    // The container's root can write any directory its user owns, so "not writable" means owned
    // by an id the container does not map.
    try out.print("\nvm-m2: --read-only, no /tmp, rootfs directory owned by root\n", .{});
    const bare = "rm -rf /home/demo/bare && mkdir /home/demo/bare && " ++
        "cp -a /home/demo/alpine/bin /home/demo/alpine/lib /home/demo/bare/ && " ++
        "mkdir /home/demo/bare/proc /home/demo/bare/dev && " ++
        "chown -R demo:demo /home/demo/bare && chown root:root /home/demo/bare && " ++
        "ls /home/demo/bare";
    try show(session, out, "a rootfs without /tmp, owned by root", bare);
    try split(session, out, H.as_demo ++ "/home/demo/zbx -v run --rootfs /home/demo/bare " ++
        "--read-only --name ro2 -- /bin/sh -c true");
}

fn pids_limit(session: *Session, out: *Io.Writer) !void {
    try out.print("\nvm-m2: --pids 16 with a loop that starts 40 sleeps\n", .{});
    try split(session, out, run_prefix ++ " --pids 16 --name pid1 -- sh /loop.sh");
    // busybox sh refuses `:` as a function name, so the bomb is `b`; PID 1 stays alive 3 s, or
    // it would end the container before the bomb had forked 64 times.
    try out.print("\nvm-m2: a fork bomb with --pids 64\n", .{});
    const bomb = "timeout 120 " ++ run_prefix ++
        " --pids 64 --name bomb1 -- sh -c 'b(){ b|b& }; b; sleep 3'";
    try split(session, out, bomb);
}

fn memory_limit(session: *Session, out: *Io.Writer) !void {
    // Three times: the manager removes the cgroup when PID 1 dies, so this is the race.
    try out.print("\nvm-m2: --memory 32m, a hog that is PID 1\n", .{});
    inline for (.{ "oom1", "oom2", "oom3" }) |name| {
        try split(session, out, run_prefix ++ " --memory 32m --name " ++ name ++ " -- sh /hog.sh");
    }
    try out.print("\nvm-m2: --memory 32m, a hog that is a child of PID 1\n", .{});
    const child = " --memory 32m --name oomchild -- sh -c 'sh /hog.sh; echo child-status:$?'";
    try split(session, out, run_prefix ++ child);
}

fn limits_visible(session: *Session, out: *Io.Writer) !void {
    try out.print("\nvm-m2: the limits of a running container, read from the host\n", .{});
    const start = H.as_demo_setsid ++ "/home/demo/zbx run --rootfs " ++ rootfs_dir ++
        " --memory 64m --pids 20 --cpus 0.5 --name lim1 -- sleep 1000 " ++
        "</dev/null >/dev/null 2>&1 &'; sleep 1; echo started";
    try show(session, out, "start lim1 in the background", start);
    const scope = app_slice ++ "/zbx-lim1.scope";
    const look = "for i in $(seq 120); do pgrep -u demo -fx 'sleep 1000' >/dev/null && " ++
        "break; sleep 0.5; done; d=" ++ scope ++ "; " ++
        "for f in memory.max memory.swap.max pids.max cpu.max cgroup.type; do " ++
        "echo $f=$(cat $d/$f); done; echo PROCS:$(cat $d/cgroup.procs | wc -l)";
    try show(session, out, "lim1 while it runs", look);
    const stop = "pkill -TERM -u demo -f 'zbx run .*lim1'; " ++
        "for i in $(seq 60); do pgrep -u demo -fx 'sleep 1000' >/dev/null || break; " ++
        "sleep 0.5; done; sleep 2; " ++ after;
    try show(session, out, "lim1 after it is stopped", stop);
}

fn inherited_bus(session: *Session, out: *Io.Writer) !void {
    try out.print("\nvm-m2: an inherited bus address that names root's bus\n", .{});
    // no-bus-env: this is the point, root's address is inherited as `su` would leave it.
    const command = "runuser -u demo -- env HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000 " ++
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus " ++
        "/home/demo/zbx -v run --rootfs " ++ rootfs_dir ++
        " --name fb1 -- sh -c 'echo fallback-ran'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
}

const zbx = H.as_demo ++ "/home/demo/zbx";
const detached = zbx ++ " run -d --rootfs " ++ rootfs_dir;

/// The scope of `name` in the cgroup tree and the manager, and who is still running as demo.
fn scope_of(comptime name: []const u8) []const u8 {
    return "echo SCOPE-" ++ name ++ ":$(ls " ++ app_slice ++ " | grep -c zbx-" ++ name ++
        ".scope); echo PROCS:$(pgrep -u demo -fa 'sleep 1000|zbx run' | grep -vc pgrep)";
}

fn lifecycle(session: *Session, out: *Io.Writer) !void {
    try out.print("\nvm-m2: slice 4, a detached run: start, list, stop\n", .{});
    try split(session, out, detached ++ " --name det1 -- sleep 1000");
    try show(session, out, "det1 is running", "sleep 2; " ++ comptime scope_of("det1"));
    const record = "/home/demo/.local/state/zbx/runs/det1.zon";
    const fields = "grep -E 'pid|supervisor|detached|scope' ";
    try show(session, out, "the record names the pids", fields ++
        record ++ "; ps -o pid,ppid,sid,tty,args -p $(grep -o 'supervisor = [0-9]*' " ++ record ++
        " | cut -d' ' -f3)");
    // Each zbx below is a new process: none of them started det1.
    try split(session, out, zbx ++ " ps");
    try split(session, out, zbx ++ " ps --output json");
    try split(session, out, zbx ++ " stop det1 --output json");
    try show(session, out, "det1 after stop", "sleep 2; " ++ comptime scope_of("det1") ++ after);
    try split(session, out, zbx ++ " ps --all");
    try split(session, out, zbx ++ " stop det1");

    try out.print("\nvm-m2: slice 4, stop gives a handler of SIGTERM its grace period\n", .{});
    try split(session, out, detached ++ " --name det3 -- sh -c 'trap \"exit 7\" TERM; " ++
        "sleep 1000 & wait'");
    try show(session, out, "det3 is running", "sleep 2; " ++ comptime scope_of("det3"));
    try split(session, out, zbx ++ " stop det3 --grace 3000 --output json");
    try show(session, out, "det3 after stop", "sleep 2; " ++ comptime scope_of("det3") ++ after);

    try out.print("\nvm-m2: slice 4, --timeout on a detached and a foreground run\n", .{});
    try split(session, out, detached ++ " --timeout 3000 --name det4 -- sleep 1000");
    try show(session, out, "det4, 8 s later", "sleep 8; " ++ comptime scope_of("det4") ++ after);
    try split(session, out, zbx ++ " ps --all --output json");
    try split(session, out, run_prefix ++ " --timeout 3000 --name fg1 -- sleep 1000");
    try split(session, out, zbx ++ " stop nobody");
    try split(session, out, zbx ++ " stop det4 --grace soon");
    try show(session, out, "schema ps", zbx ++ " schema ps | head -c 300");
}
