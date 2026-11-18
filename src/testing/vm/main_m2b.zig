//! The M2b demo, run in a real Ubuntu 24.04 VM (the M2 harness: same image, same provisioning,
//! the pinned Alpine minirootfs unpacked as user `demo`, with `numactl` added by `apk` inside a
//! `zbx run` and `numa-probe` copied in). The six steps of the spec, as the user `demo`:
//!   1. `--ulimit nofile=4096:8192` reads back 4096 and 8192; one above the user's own hard
//!      limit is refused (E0311), naming the limit and both fixes, the user manager's with the
//!      `LimitNOFILE=` line to add.
//!   2. `--shm-size 256m` gives a /dev/shm of 262144 1K-blocks; `--memory 128m --shm-size 256m`
//!      is refused (E0314), saying /dev/shm counts against --memory.
//!   3. `--sysctl net.core.somaxconn=8192` reads back 8192 (the VM kernel's default is 4096, so
//!      the brief's 4096 would prove nothing; decision 2026-11-16-m2b-sysctl-keys); a host key is
//!      refused (E0316), and a net.* key with --net host (E0317).
//!   4. With `vm.max_map_count` set to 65530, `--require-host 'vm.max_map_count>=262144'` is
//!      refused (E0319) with the host value and the fix; `zbx doctor` shows 65530; the fix is
//!      applied and the same run exits 0.
//!   5. The cgroup view: `0::/`, 268435456, `150000 100000`; a write to it fails, read-only.
//!   6. `numactl --interleave=all true` exits 0 (v0.5.2 fails it: recorded), and numa-probe
//!      prints the four policy calls ok and the two page movers EPERM.
//! Then: /dev/shm filling --memory is an OOM kill with the M2 report; under --net host, --net
//! none and --net user the host's cgroup tree is not reachable at /sys/fs/cgroup (and under
//! --net user a net.* sysctl survives pasta); the scripted agent runs steps 1 to 5 with
//! `--output json` and `zbx explain` only; and the upgrade test: v0.5.2 starts three detached
//! containers (plain and `--publish`, record version 9; `--device`, version 10), this zbx lists
//! them from their records, stops them, and `ps --all` shows none running.
//! Every assertion is a function of checks_m2b.zig or checks_m2.zig with a unit test.
//! `zig build demo-m2b` (KVM) or `zig build demo-m2b -Daccel=tcg`. See docs/demos/m2b.md.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const agent_json = @import("agent_json.zig");
const checks = @import("checks_m2b.zig");
const checks_m2 = @import("checks_m2.zig");
const checks_up5 = @import("checks_upgrade_m5.zig");
const checks_up6b = @import("checks_upgrade_m6b.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const old_release = @import("old_release.zon");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

/// numa-probe, built for the guest by build.zig (`add_numa_probe`).
const numa_probe = @embedFile("numa_probe");

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m2b";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m2b: bad arguments ({s}); see docs/demos/m2b.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m2b: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m2b: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const accel = harness.choose_accel(options.accel, H.kvm_usable(init.io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-m2b: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
        }
        return err;
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        try out.print("demo-m2b: --old-zbx is missing: the upgrade test needs {s}\n", .{
            old_release.m2b_tag,
        });
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const elf_limit: Io.Limit = .limited(limits.elf_bytes_max);
    const old_binary = try Io.Dir.cwd().readFileAlloc(init.io, options.old_zbx, arena, elf_limit);
    const rootfs_path = try image.ensure_pin(init, options.cache_dir, out, .{
        .url = alpine.url,
        .sha256 = alpine.sha256,
        .file_name = alpine.file_name,
    });
    const limit: Io.Limit = .limited(limits.http_body_bytes_max);
    const rootfs = try Io.Dir.cwd().readFileAlloc(init.io, rootfs_path, arena, limit);
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_name = "{s}/overlay-demo-m2b.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_name, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(init.io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = "/m2b/numa-probe", .body = numa_probe },
    };
    const vm_limits = @import("zigbox_vm").limits;
    comptime assert(vm_limits.seed_routes + 3 + extra.len <= vm_limits.http_routes_max);
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .rootfs = rootfs,
        .old_binary = old_binary,
        .extra = &extra,
    });
    defer session.deinit();
    try run_all(&session, out, options.reuse_overlay);
    try session.shutdown();
    return 0;
}

fn run_all(session: *Session, out: *Io.Writer, reuse: bool) !void {
    var timer = H.Timer.start();
    try H.provision(session, out, &timer, reuse);
    try H.install_binary(session, out, &timer);
    try install_old(session, out);
    try unpack_rootfs(session, out, &timer);
    try install_numactl(session, out, &timer);
    try step_ulimit(session, out, &timer);
    try step_shm(session, out, &timer);
    try step_sysctl(session, out, &timer);
    try step_require_host(session, out, &timer);
    try step_cgroup_view(session, out, &timer);
    try step_numa(session, out, &timer);
    try extra_shm_oom(session, out, &timer);
    try extra_host_tree(session, out, &timer);
    try agent_steps(session, out, &timer);
    try upgrade(session, out, &timer);
}

// The commands, as the user `demo` runs them, through `H.as_demo` (the session variables a login
// would set: HOME for the run records, the runtime directory and the user's bus).
const zbx = H.as_demo ++ "/home/demo/zbx";
const zbx_old = H.as_demo ++ "/home/demo/zbx-old";
const zbx_json = zbx ++ " --output json";
const rootfs_dir = "/home/demo/alpine";
const state_dir = "/home/demo/.local/state/zbx";
// `--net none` is the default; saying it keeps zbx's note about the network out of the lines
// the steps compare.
const run_prefix = zbx ++ " run --net none --rootfs " ++ rootfs_dir;
const json_prefix = zbx_json ++ " run --net none --rootfs " ++ rootfs_dir;
/// The kernel's default, which Ubuntu 24.04 raises to 1048576 (that would hide the refusal).
const map_count_low = "65530";
const map_count_needed = "262144";
const require_map_count = " --require-host 'vm.max_map_count>=" ++ map_count_needed ++ "'";

fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("demo-m2b: {s} FAILED: {s} ({s})\n", .{ step, what, @errorName(err) });
    return err;
}

fn show(session: *Session, out: *Io.Writer, title: []const u8, command: []const u8) !void {
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, title, result);
}

/// Runs `command` with its streams apart and shows them.
fn split(session: *Session, out: *Io.Writer, command: []const u8) !H.SplitResult {
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    return result;
}

fn format(session: *Session, comptime pattern: []const u8, args: anytype) ![]const u8 {
    return std.fmt.allocPrint(session.scratch_allocator(), pattern, args);
}

/// Sets `vm.max_map_count` as root: the VM's privileged setup, never the demo user.
fn set_map_count(session: *Session, out: *Io.Writer, value: []const u8) !void {
    const command = try format(session, "sysctl -w vm.max_map_count={s}", .{value});
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, command, result);
    checks.check_ran(result.status) catch |err| {
        return fail_step(out, "provisioning", "expected the sysctl to be set", err);
    };
}

fn install_old(session: *Session, out: *Io.Writer) !void {
    const command = try format(
        session,
        "curl -fsS -o /home/demo/zbx-old http://10.0.2.2:{d}/zbx-old && " ++
            "chown demo:demo /home/demo/zbx-old && chmod 755 /home/demo/zbx-old && " ++
            "runuser -u demo -- /home/demo/zbx-old --version",
        .{session.server.port},
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "install " ++ old_release.m2b_tag, result);
    checks.check_ran(result.status) catch |err| {
        return fail_step(out, "provisioning", "expected " ++ old_release.m2b_tag ++ " to run", err);
    };
}

fn unpack_rootfs(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: unpacking the pinned Alpine minirootfs as user demo\n", .{});
    const command = try format(
        session,
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "runuser -u demo -- sh -c 'mkdir -p {s} && tar -xzf /tmp/rootfs.tar.gz -C {s}' && " ++
            "stat -c '%U %n' {s}/bin/busybox",
        .{ session.server.port, rootfs_dir, rootfs_dir, rootfs_dir },
    );
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "unpack the rootfs", result);
    checks.check_ran(result.status) catch |err| {
        return fail_step(out, "provisioning", "expected the rootfs unpacked", err);
    };
    // The kernel prints a report to the console for every OOM kill; the console is where the
    // harness reads the command's output.
    try show(session, out, "quiet the kernel's console", "dmesg -n 1");
    try timer.lap(out, "unpack");
}

// The minirootfs has no CA certificates, so apk fetches over http; it checks the signatures of
// the index and of each package against the keys in the rootfs.
const apk_main = "http://dl-cdn.alpinelinux.org/alpine/v3.20/main";
const apk_community = "http://dl-cdn.alpinelinux.org/alpine/v3.20/community";

/// numactl goes into the rootfs by `apk` inside a zbx container (--net host: the VM has a
/// network; 10.0.2.3 is the emulated resolver), and numa-probe is copied in as /numa-probe.
fn install_numactl(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: provisioning: numactl and numa-probe into the rootfs\n", .{});
    const configure = "runuser -u demo -- sh -c 'echo nameserver 10.0.2.3 > " ++ rootfs_dir ++
        "/etc/resolv.conf && printf \"%s\\n\" " ++ apk_main ++ " " ++ apk_community ++ " > " ++
        rootfs_dir ++ "/etc/apk/repositories'";
    const configured = try session.run(configure, limits.command_timeout_kvm_s);
    try H.show(out, "configure apk", configured);
    checks.check_ran(configured.status) catch |err| {
        return fail_step(out, "provisioning", "apk configuration", err);
    };
    const apk = zbx ++ " run --net host --rootfs " ++ rootfs_dir ++
        " --name apk1 -- apk add --no-cache numactl-tools";
    const result = try session.run(apk, 300);
    try H.show(out, "apk add numactl-tools, inside zbx run", result);
    checks.check_ran(result.status) catch |err| {
        return fail_step(out, "provisioning", "apk add", err);
    };
    const copied = try session.copy_in(.{
        .route = "/m2b/numa-probe",
        .guest_path = rootfs_dir ++ "/numa-probe",
        .owner = "demo:demo",
        .mode = "755",
    });
    try H.show(out, "copy numa-probe into the rootfs", copied);
    checks.check_ran(copied.status) catch |err| {
        return fail_step(out, "provisioning", "copy", err);
    };
    try set_map_count(session, out, map_count_low);
    try timer.lap(out, "numactl");
}

// ---- The six steps of the spec ---------------------------------------------------------------

/// The demo user's own hard limit on open files, as the zbx it starts inherits it.
fn hard_nofile(session: *Session, out: *Io.Writer, step: []const u8) !u64 {
    const command = H.as_demo ++ "sh -c 'ulimit -Hn'";
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "the demo user's hard limit: ulimit -Hn", result);
    return checks.parse_hard_limit(result.output) catch |err| {
        return fail_step(out, step, "expected a finite number from ulimit -Hn", err);
    };
}

fn step_ulimit(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 1";
    try out.print("\ndemo-m2b: STEP 1: --ulimit nofile=4096:8192, then one above your own\n", .{});
    const command = run_prefix ++ " --ulimit nofile=4096:8192 -- sh -c 'ulimit -n; ulimit -Hn'";
    const read = try split(session, out, command);
    checks.check_lines(read.streams, read.status, &.{ "4096", "8192" }) catch |err| {
        return fail_step(out, step, "expected 4096 and 8192", err);
    };
    const hard = try hard_nofile(session, out, step);
    const above = try format(session, run_prefix ++ " --ulimit nofile={d} -- true", .{hard + 1});
    const refused = try split(session, out, above);
    var hard_text: [24]u8 = undefined;
    var unit_text: [40]u8 = undefined;
    const needles = [_][]const u8{
        try std.fmt.bufPrint(&hard_text, "{d}", .{hard}),
        "/etc/security/limits.conf",
        "user@1000.service",
        try std.fmt.bufPrint(&unit_text, "LimitNOFILE={d} under [Service]", .{hard + 1}),
    };
    checks.check_text_refusal(refused.streams, refused.status, "ZBX-E0311", &needles) catch |err| {
        return fail_step(out, step, "expected E0311 naming the hard limit, limits.conf and " ++
            "the user manager's LimitNOFILE=", err);
    };
    try timer.lap(out, "step 1");
}

fn step_shm(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 2";
    try out.print("\ndemo-m2b: STEP 2: --shm-size 256m; larger than --memory is refused\n", .{});
    const sized = try split(session, out, run_prefix ++ " --shm-size 256m -- df -k /dev/shm");
    checks.check_df_blocks(sized.streams, sized.status, 262144) catch |err| {
        return fail_step(out, step, "expected /dev/shm of 262144 1K-blocks", err);
    };
    const command = run_prefix ++ " --memory 128m --shm-size 256m -- true";
    const refused = try split(session, out, command);
    const needles = [_][]const u8{ "/dev/shm", "memory limit" };
    checks.check_text_refusal(refused.streams, refused.status, "ZBX-E0314", &needles) catch |err| {
        return fail_step(out, step, "expected E0314: /dev/shm counts against --memory", err);
    };
    try timer.lap(out, "step 2");
}

fn step_sysctl(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 3";
    try out.print("\ndemo-m2b: STEP 3: --sysctl, a host key, a net.* key with --net host\n", .{});
    const command = run_prefix ++ " --sysctl net.core.somaxconn=8192 -- " ++
        "cat /proc/sys/net/core/somaxconn";
    const read = try split(session, out, command);
    checks.check_lines(read.streams, read.status, &.{"8192"}) catch |err| {
        return fail_step(out, step, "expected 8192", err);
    };
    const host_key = run_prefix ++ " --sysctl vm.max_map_count=262144 -- true";
    const host = try split(session, out, host_key);
    const pointing = [_][]const u8{ "host setting", "--require-host" };
    checks.check_text_refusal(host.streams, host.status, "ZBX-E0316", &pointing) catch |err| {
        return fail_step(out, step, "expected E0316 pointing at --require-host", err);
    };
    const shared = zbx ++ " run --net host --rootfs " ++ rootfs_dir ++
        " --sysctl net.core.somaxconn=8192 -- true";
    const net = try split(session, out, shared);
    const own_network = [_][]const u8{ "--net host", "network of its own" };
    checks.check_text_refusal(net.streams, net.status, "ZBX-E0317", &own_network) catch |err| {
        return fail_step(out, step, "expected E0317: net.* needs the container's network", err);
    };
    try timer.lap(out, "step 3");
}

fn step_require_host(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 4";
    try out.print("\ndemo-m2b: STEP 4: --require-host on a host at the kernel's default\n", .{});
    const command = run_prefix ++ require_map_count ++ " -- true";
    const refused = try split(session, out, command);
    const needles = [_][]const u8{
        "vm.max_map_count",
        map_count_low,
        ">=" ++ map_count_needed,
        "sudo sysctl -w vm.max_map_count=" ++ map_count_needed,
    };
    checks.check_text_refusal(refused.streams, refused.status, "ZBX-E0319", &needles) catch |err| {
        return fail_step(out, step, "expected E0319 with the host value and the fix", err);
    };
    const doctor = try session.run(zbx ++ " doctor 2>&1", limits.command_timeout_kvm_s);
    try H.show(out, "zbx doctor", doctor);
    checks.check_doctor_value(doctor.output, "vm.max_map_count", map_count_low) catch |err| {
        return fail_step(out, step, "expected the host-settings line to show 65530", err);
    };
    try set_map_count(session, out, map_count_needed);
    const again = try split(session, out, command);
    checks.check_quiet(again.streams, again.status) catch |err| {
        return fail_step(out, step, "expected exit 0 and nothing said", err);
    };
    try timer.lap(out, "step 4");
}

fn step_cgroup_view(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 5";
    try out.print("\ndemo-m2b: STEP 5: the container's own cgroup, read-only\n", .{});
    const command = run_prefix ++ " --memory 256m --cpus 1.5 -- sh -c 'cat /proc/self/cgroup " ++
        "/sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max'";
    const read = try split(session, out, command);
    const lines = [_][]const u8{ "0::/", "268435456", "150000 100000" };
    checks.check_lines(read.streams, read.status, &lines) catch |err| {
        return fail_step(out, step, "expected 0::/, 268435456 and 150000 100000", err);
    };
    const write = run_prefix ++ " --memory 256m -- sh -c 'echo 1 > /sys/fs/cgroup/memory.max'";
    const refused = try split(session, out, write);
    checks.check_failed_with(refused.streams, refused.status, "Read-only file system") catch |e| {
        return fail_step(out, step, "expected the write to fail: Read-only file system", e);
    };
    try timer.lap(out, "step 5");
}

fn step_numa(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const step = "STEP 6";
    try out.print("\ndemo-m2b: STEP 6: NUMA memory policy\n", .{});
    const interleave = run_prefix ++ " -- numactl --interleave=all true";
    const ran = try split(session, out, interleave);
    checks.check_quiet(ran.streams, ran.status) catch |err| {
        return fail_step(out, step, "expected numactl to exit 0, quiet", err);
    };
    // The same command under v0.5.2, whose filter had none of the policy calls: recorded in
    // docs/demos/m2b.md as the before.
    const before = zbx_old ++ " run --net none --rootfs " ++ rootfs_dir ++
        " -- numactl --interleave=all true";
    const old = try split(session, out, before);
    checks.check_failed_with(old.streams, old.status, "Operation not permitted") catch |err| {
        return fail_step(out, step, "expected " ++ old_release.m2b_tag ++ " to fail it", err);
    };
    const probe = try split(session, out, run_prefix ++ " -- /numa-probe");
    checks.check_lines(probe.streams, probe.status, &checks.probe_lines) catch |err| {
        return fail_step(out, step, "expected the four policy calls ok, the movers EPERM", err);
    };
    try timer.lap(out, "step 6");
}

// ---- The extra checks ------------------------------------------------------------------------

/// /dev/shm's pages are charged to the container's memory cgroup: filling a /dev/shm as large
/// as --memory is an OOM kill, with M2's report.
fn extra_shm_oom(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: EXTRA: filling /dev/shm is an OOM kill under --memory\n", .{});
    const command = "timeout 120 " ++ run_prefix ++ " --memory 64m --shm-size 64m -- " ++
        "dd if=/dev/zero of=/dev/shm/fill bs=1M count=100";
    const result = try split(session, out, command);
    checks_m2.check_oom_report(result.streams, result.status, 64) catch |err| {
        return fail_step(out, "EXTRA shm", "expected exit 137 and `zbx: killed: out of " ++
            "memory (limit 64 MiB)` last", err);
    };
    try timer.lap(out, "shm oom");
}

/// What the container finds at /sys/fs/cgroup: each entry, the memory limit, its own cgroup.
/// The script is left open: each caller closes its quote, after adding to it.
const view_probe = " -- sh -c 'for e in /sys/fs/cgroup/*; do echo LS:${e##*/}; done; " ++
    "echo MEMORY:$(cat /sys/fs/cgroup/memory.max); echo CGROUP:$(cat /proc/self/cgroup)";

/// The host's cgroup tree is not reachable at /sys/fs/cgroup under --net host (the host's /sys
/// is bound there), the default, or --net user (pasta's namespace). Mountinfo still lists the
/// host's cgroup2 under --net host: a recorded cut, not asserted.
fn extra_host_tree(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: EXTRA: the host's cgroup tree is not reachable\n", .{});
    const modes = [_][]const u8{ "host", "none" };
    inline for (modes) |mode| {
        const command = zbx ++ " run --net " ++ mode ++ " --rootfs " ++ rootfs_dir ++
            " --memory 256m" ++ view_probe ++ "'";
        const result = try split(session, out, command);
        checks.check_view(result.streams, result.status, "268435456") catch |err| {
            return fail_step(out, "EXTRA --net " ++ mode, "expected the scope's own files " ++
                "and no host slice at /sys/fs/cgroup", err);
        };
    }
    // Under --net user, pasta sets the network up after zbx has written the sysctls: the value
    // read back inside is the one the run set (pasta resets no net.* key).
    const user = zbx ++ " run --net user --rootfs " ++ rootfs_dir ++ " --memory 256m" ++
        " --sysctl net.core.somaxconn=8192" ++ view_probe ++
        "; echo SYSCTL:$(cat /proc/sys/net/core/somaxconn)'";
    const result = try split(session, out, user);
    checks.check_view_sysctl(result.streams, result.status, "268435456", "8192") catch |err| {
        return fail_step(out, "EXTRA --net user", "expected the scope's own files, no host " ++
            "slice, and somaxconn 8192 after pasta", err);
    };
    try timer.lap(out, "host tree");
}

// ---- The scripted agent ----------------------------------------------------------------------

/// `zbx explain <code> --output json` agrees with the diagnostic the agent got, except for the
/// summary of a code whose instance sets a headline (`checks.explain_summary`).
fn explain(session: *Session, out: *Io.Writer, diagnostic: agent_json.Diagnostic) !void {
    const command = try format(session, zbx ++ " explain {s} --output json", .{diagnostic.code});
    const result = try split(session, out, command);
    const arena = session.scratch_allocator();
    var expected = diagnostic;
    expected.summary = checks.explain_summary(diagnostic);
    agent_json.check_explain(arena, result.streams, result.status, expected) catch |err| {
        return fail_step(out, "AGENT", "expected explain to agree", err);
    };
}

/// Runs a refused command and returns its diagnostic, explained.
fn refusal_of(
    session: *Session,
    out: *Io.Writer,
    command: []const u8,
    code: []const u8,
) !agent_json.Diagnostic {
    const result = try split(session, out, command);
    const arena = session.scratch_allocator();
    const found = checks.refusal(arena, result.streams, result.status, code) catch |err| {
        return fail_step(out, "AGENT", "expected the refusal's diagnostic", err);
    };
    try explain(session, out, found);
    return found;
}

/// Runs an accepted command and returns its `container_exit` object.
fn accepted(session: *Session, out: *Io.Writer, command: []const u8) !std.json.ObjectMap {
    const result = try split(session, out, command);
    const arena = session.scratch_allocator();
    return checks.exit_object(arena, result.streams, result.status) catch |err| {
        return fail_step(out, "AGENT", "expected exit 0 and a container_exit line", err);
    };
}

fn agent_steps(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: AGENT: steps 1 to 5 with --output json and explain only\n", .{});
    try set_map_count(session, out, map_count_low);
    try agent_ulimit(session, out);
    try agent_shm_and_sysctl(session, out);
    try agent_require_host(session, out);
    try agent_view(session, out);
    try timer.lap(out, "agent");
}

fn agent_ulimit(session: *Session, out: *Io.Writer) !void {
    const exit = try accepted(session, out, json_prefix ++ " --ulimit nofile=4096:8192 -- true");
    checks.check_exit_ulimit(exit, "nofile", 4096, 8192) catch |err| {
        return fail_step(out, "AGENT 1", "expected ulimits.nofile 4096/8192", err);
    };
    const hard = try hard_nofile(session, out, "AGENT 1");
    const above = try format(session, json_prefix ++ " --ulimit nofile={d} -- true", .{hard + 1});
    const found = try refusal_of(session, out, above, "ZBX-E0311");
    checks.check_e0311(found, hard, demo_uid) catch |err| {
        return fail_step(out, "AGENT 1", "expected asked, hard, the unit line and the fixes " ++
            "in the diagnostic's fields", err);
    };
}

/// The uid of the user `demo` the harness provisions.
const demo_uid: u32 = 1000;

fn agent_shm_and_sysctl(session: *Session, out: *Io.Writer) !void {
    const shm = try accepted(session, out, json_prefix ++ " --shm-size 256m -- true");
    checks.check_exit_shm(shm, 268435456) catch |err| {
        return fail_step(out, "AGENT 2", "expected shm_bytes 268435456", err);
    };
    const larger = json_prefix ++ " --memory 128m --shm-size 256m -- true";
    const e0314 = try refusal_of(session, out, larger, "ZBX-E0314");
    checks.expect_context(e0314, "size", "268435456") catch |err| {
        return fail_step(out, "AGENT 2", "expected context.size 268435456", err);
    };
    const sysctl = json_prefix ++ " --sysctl net.core.somaxconn=8192 -- true";
    const set = try accepted(session, out, sysctl);
    checks.check_exit_sysctl(set, "net.core.somaxconn", "8192") catch |err| {
        return fail_step(out, "AGENT 3", "expected sysctls net.core.somaxconn 8192", err);
    };
    const host_key = json_prefix ++ " --sysctl vm.max_map_count=262144 -- true";
    const e0316 = try refusal_of(session, out, host_key, "ZBX-E0316");
    checks.expect_context(e0316, "sysctl", "vm.max_map_count") catch |err| {
        return fail_step(out, "AGENT 3", "expected context.sysctl vm.max_map_count", err);
    };
    checks.check_require_host_pointer(e0316, "vm.max_map_count") catch |err| {
        return fail_step(out, "AGENT 3", "expected the template fix --require-host", err);
    };
    const shared = zbx_json ++ " run --net host --rootfs " ++ rootfs_dir ++
        " --sysctl net.core.somaxconn=8192 -- true";
    const e0317 = try refusal_of(session, out, shared, "ZBX-E0317");
    checks.expect_context(e0317, "sysctl", "net.core.somaxconn") catch |err| {
        return fail_step(out, "AGENT 3", "expected context.sysctl net.core.somaxconn", err);
    };
}

/// The agent reads the host value and the fix from E0319's fields, has the fix applied as root
/// (the harness stands in for the person with sudo), checks it with the doctor fix, and reruns.
fn agent_require_host(session: *Session, out: *Io.Writer) !void {
    const step = "AGENT 4";
    const command = json_prefix ++ require_map_count ++ " -- true";
    const found = try refusal_of(session, out, command, "ZBX-E0319");
    checks.expect_context(found, "key", "vm.max_map_count") catch |err| {
        return fail_step(out, step, "expected context.key", err);
    };
    checks.expect_context(found, "host", map_count_low) catch |err| {
        return fail_step(out, step, "expected context.host 65530", err);
    };
    checks.expect_context(found, "needed", ">=" ++ map_count_needed) catch |err| {
        return fail_step(out, step, "expected context.needed >=262144", err);
    };
    const as_root = checks.root_command(found, 0) catch |err| {
        return fail_step(out, step, "expected a root fix that is no template", err);
    };
    const fix = try session.scratch_allocator().dupe(u8, as_root);
    const doctor_fix = try session.scratch_allocator().dupe(u8, try checks.fix_at(found, 1));
    const applied = try session.run(fix, limits.command_timeout_kvm_s);
    try H.show(out, fix, applied);
    checks.check_ran(applied.status) catch |err| {
        return fail_step(out, step, "expected the root fix to run", err);
    };
    var buffer: [256]u8 = undefined;
    const doctor = agent_json.fix_command(&buffer, zbx, doctor_fix) catch |err| {
        return fail_step(out, step, "expected the second fix to be a zbx command", err);
    };
    const report = try split(session, out, doctor);
    const arena = session.scratch_allocator();
    const doc = report.streams.stdout;
    checks.check_doctor_reads(arena, doc, "vm.max_map_count", 262144) catch |err| {
        return fail_step(out, step, "expected the doctor to read 262144", err);
    };
    _ = try accepted(session, out, command);
}

fn agent_view(session: *Session, out: *Io.Writer) !void {
    const step = "AGENT 5";
    const command = json_prefix ++ " --memory 256m --cpus 1.5 -- sh -c 'cat /proc/self/cgroup " ++
        "/sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max'";
    const read = try split(session, out, command);
    const lines = [_][]const u8{ "0::/", "268435456", "150000 100000" };
    checks.check_lines(read.streams, read.status, &lines) catch |err| {
        return fail_step(out, step, "expected 0::/, 268435456 and 150000 100000", err);
    };
    _ = checks.exit_object(session.scratch_allocator(), read.streams, read.status) catch |err| {
        return fail_step(out, step, "expected container_exit with code 0", err);
    };
    const write = json_prefix ++ " --memory 256m -- sh -c 'echo 1 > /sys/fs/cgroup/memory.max'";
    const failed = try split(session, out, write);
    const arena = session.scratch_allocator();
    checks.check_read_only_write(arena, failed.streams, failed.status) catch |err| {
        return fail_step(out, step, "expected the write to fail: Read-only file system", err);
    };
}

// ---- The upgrade test ------------------------------------------------------------------------

/// v0.5.2 writes run record version 9 for a detached run, with the forward in `.publish` when it
/// has `--publish`, and version 10 when it has `--device` (constants.zig and run_record.zig at
/// the tag).
const record_plain: u32 = 9;
const record_device: u32 = 10;
const old_plain = "m2bold";
const old_published = "m2bpub";
const old_device = "m2bdev";
const old_names = [_][]const u8{ old_plain, old_published, old_device };
/// /dev/fuse: a device v0.5.2 does not bind on its own (it reserves /dev/null and the rest).
const old_starts = [_][]const u8{
    "--net none",
    "--net user --publish 18080:80",
    "--net none --device /dev/fuse",
};

fn upgrade(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m2b: UPGRADE: " ++ old_release.m2b_tag ++ " starts three containers, " ++
        "this zbx reads their records and stops them\n", .{});
    inline for (old_names, old_starts) |name, flags| {
        const start = zbx_old ++ " run -d " ++ flags ++ " --rootfs " ++ rootfs_dir ++
            " --name " ++ name ++ " -- sleep 300";
        const started = try split(session, out, start);
        checks.check_detached(started.streams, started.status, name) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected the old zbx to start it", err);
        };
    }
    const ps = try split(session, out, zbx_json ++ " ps");
    const arena = session.scratch_allocator();
    const listed = ps.streams.stdout;
    inline for (.{ old_plain, old_device }) |name| {
        _ = checks_up6b.check_old_running(arena, listed, ps.status, name) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected ps to list it running", err);
        };
    }
    checks.check_old_published(arena, listed, ps.status, old_published, .{ 18080, 80 }) catch |e| {
        return fail_step(out, "UPGRADE " ++ old_published, "expected ps to list it running " ++
            "under --net user with 18080:80", e);
    };
    try upgrade_records(session, out);
    try upgrade_stop(session, out);
    try timer.lap(out, "upgrade");
}

/// Each record is the version v0.5.2 wrote, with the line its flag added.
fn upgrade_records(session: *Session, out: *Io.Writer) !void {
    const versions = [_]u32{ record_plain, record_plain, record_device };
    const lines = [_][]const u8{
        ".detached = true,",
        ".publish = .{ \"18080:80\" },",
        ".devices = \"/dev/fuse\",",
    };
    inline for (old_names, versions, lines) |name, version, line| {
        const command = "cat " ++ state_dir ++ "/runs/" ++ name ++ ".zon";
        const record = try session.run(command, limits.command_timeout_kvm_s);
        try H.show(out, command, record);
        checks.check_ran(record.status) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected its run record", err);
        };
        checks_up5.check_record_version(record.output, version) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected the record's version", err);
        };
        checks.check_record_line(record.output, line) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected the record line " ++ line, err);
        };
    }
}

/// This zbx stops each, and `ps` then lists none of them running.
fn upgrade_stop(session: *Session, out: *Io.Writer) !void {
    inline for (old_names) |name| {
        const stop = try split(session, out, zbx ++ " stop " ++ name);
        checks.check_stopped(stop.streams, stop.status, name) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected zbx stop to stop it", err);
        };
    }
    const ps = try split(session, out, zbx_json ++ " ps --all");
    const arena = session.scratch_allocator();
    inline for (old_names) |name| {
        checks.check_not_running(arena, ps.streams.stdout, ps.status, name) catch |err| {
            return fail_step(out, "UPGRADE " ++ name, "expected the stop to take effect", err);
        };
    }
}

test {
    _ = @import("checks_m2b.zig");
    _ = @import("checks_m2.zig");
    _ = @import("harness.zig");
}
