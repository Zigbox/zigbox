//! The M10 demo, run in a real Ubuntu 24.04 VM (the M0 harness: same image, same provisioning):
//! `--device` and `--gpu` with a fake vendor, `zigbox.test/gpu`, whose spec is in /etc/cdi and
//! whose device is a 0660 root:render node (the character device 1:5, `/dev/zero`'s numbers),
//! and whose driver library `libzbxgpu.so.1` is a real shared object (m10_fixture/).
//!   1. doctor lists the spec and its device, and none of it is a gap.
//!   2. `--device zigbox.test/gpu=0` in a glibc rootfs: the node reads as four zero bytes, the
//!      spec's variable is set, the image's `ldconfig` cached the library, and a program that
//!      needs it starts with no LD_LIBRARY_PATH.
//!   3. `--gpu all` with no NVIDIA spec: E0228 when the guest has no render node; `--gpu dri`
//!      when it has one (the runner's QEMU gives none: recorded as NOT RUN in the output).
//!   4. A user removed from `render` is refused with E0225 naming the node and the group.
//!   5. A YAML spec beside the JSON one: doctor shows the refusal and the fix, the JSON device
//!      still runs, and a name only the YAML could have is E0226 naming the file.
//!   6. An image copy with no `ldconfig` runs with W0208 and the library on LD_LIBRARY_PATH.
//!   7. A run with no devices is as before: no demo node, no note, exit 0.
//! The real vendors (NVIDIA, AMD, Intel) are by hand: docs/demos/m10.md. Every assertion is a
//! function of checks_m10.zig with a unit test. `zig build demo-m10` (KVM) or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m10.zig");
const checks_m1 = @import("checks_m1.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

const rootfs_dir = "/home/demo/alpine";
/// A glibc rootfs the guest makes from its own Ubuntu files (`glibc_rootfs_script`), so that the
/// image's `ldconfig` is glibc's, as in `debian:12`; the fake driver's probe is in it.
const glibc_dir = "/home/demo/glibc";
const zbx = H.as_demo ++ "/home/demo/zbx";
const run_prefix = zbx ++ " run --rootfs " ++ rootfs_dir;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m10";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m10: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m10: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m10: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m10: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
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
    const format = "{s}/overlay-demo-m10.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = "/m10/libzbxgpu.so.1", .body = @embedFile("zbxgpu_library") },
        .{ .path = "/m10/zbxgpu-probe", .body = @embedFile("zbxgpu_probe") },
        .{ .path = "/m10/glibc-rootfs.sh", .body = glibc_rootfs_script },
    };
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .rootfs = rootfs,
        .extra = &extra,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out);
    try prepare_host(&session, out);
    try step_doctor(&session, out);
    try step_device(&session, out);
    try step_gpu(&session, out);
    try step_not_in_group(&session, out);
    try step_yaml(&session, out);
    try step_no_ldconfig(&session, out);
    try step_baseline(&session, out);
    try session.shutdown();
}

fn fail_step(out: *Io.Writer, step: []const u8, err: anyerror) anyerror {
    try out.print("demo-m10: {s} FAILED ({s})\n", .{ step, @errorName(err) });
    return err;
}

fn unpack_rootfs(session: *Session, out: *Io.Writer) !void {
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
}

/// Makes a glibc rootfs at `$1` from the guest's own Ubuntu 24.04 files: the shell, the tools
/// step 2 runs, glibc's `ldconfig` (Ubuntu's is a script that execs `ldconfig.real`) and the
/// libraries `ldd` names, with Ubuntu's merged-/usr links. `$2` is the probe, put in `/usr/bin`.
const glibc_rootfs_script =
    \\set -e
    \\R=$1
    \\mkdir -p $R/usr/bin $R/usr/sbin $R/usr/lib $R/usr/lib64 $R/etc $R/var/cache/ldconfig
    \\mkdir -p $R/tmp $R/dev $R/proc $R/sys $R/opt $R/root
    \\ln -s usr/bin $R/bin; ln -s usr/sbin $R/sbin; ln -s usr/lib $R/lib; ln -s usr/lib64 $R/lib64
    \\for f in /usr/bin/dash /usr/bin/head /usr/bin/od /usr/bin/grep /usr/bin/ls /usr/bin/id \
    \\    /usr/sbin/ldconfig /usr/sbin/ldconfig.real; do
    \\  cp $f $R$f
    \\  for l in $(ldd $f 2>/dev/null | grep -o '/[^ ]*' || true); do
    \\    mkdir -p $(dirname $R$l); cp -L $l $R$l
    \\  done
    \\done
    \\ln -s dash $R/usr/bin/sh
    \\: > $R/etc/ld.so.conf
    \\install -m 0755 $2 $R/usr/bin/zbxgpu-probe
    \\test -x $R/lib64/ld-linux-x86-64.so.2
    \\
;

/// The fake vendor: a node 0660 root:render that `demo` can open (it is put in `render`), the
/// driver library in its own directory, a glibc rootfs with a program that needs that library,
/// and a spec with the node, a mount, a variable and the NVIDIA-style library cache hook.
fn prepare_host(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: the fake vendor zigbox.test/gpu: node, library, spec\n", .{});
    const spec = "{\"cdiVersion\":\"0.6.0\",\"kind\":\"zigbox.test/gpu\",\"devices\":[" ++
        "{\"name\":\"0\",\"containerEdits\":{\"deviceNodes\":[{\"path\":\"/dev/zbx-gpu\"}]," ++
        "\"mounts\":[{\"hostPath\":\"/opt/zbx-gpu-lib\",\"containerPath\":\"/opt/zbx-gpu-lib\"," ++
        "\"options\":[\"ro\",\"bind\"]}]}}],\"containerEdits\":{\"env\":[\"ZBXGPU=on\"]," ++
        "\"hooks\":[{\"hookName\":\"createContainer\",\"path\":\"/usr/bin/nvidia-cdi-hook\"," ++
        "\"args\":[\"nvidia-cdi-hook\",\"update-ldcache\",\"--folder\",\"/opt/zbx-gpu-lib\"]}]}}";
    const setup = "groupadd -f render && usermod -aG render demo && " ++
        "mknod /dev/zbx-gpu c 1 5 && chgrp render /dev/zbx-gpu && chmod 0660 /dev/zbx-gpu && " ++
        "mkdir -p /etc/cdi && printf '%s' '" ++ spec ++ "' > /etc/cdi/zbx-gpu.json";
    const prepared = try session.run(setup, limits.command_timeout_kvm_s);
    try H.show(out, "write the spec, make the node, put demo in render", prepared);
    if (prepared.status != 0) return error.DeviceSetupFailed;
    const library = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "mkdir -p /opt/zbx-gpu-lib && cd /tmp && U=http://10.0.2.2:{d}/m10 && " ++
            "curl -fsS -o /opt/zbx-gpu-lib/libzbxgpu.so.1 $U/libzbxgpu.so.1 && " ++
            "curl -fsS -o zbxgpu-probe $U/zbxgpu-probe && " ++
            "curl -fsS -o glibc-rootfs.sh $U/glibc-rootfs.sh && " ++
            "sh glibc-rootfs.sh {s} /tmp/zbxgpu-probe && chown -R demo:demo {s} && " ++
            "du -sh {s} && ls -l /opt/zbx-gpu-lib",
        .{ session.server.port, glibc_dir, glibc_dir, glibc_dir },
    );
    const made = try session.run(library, limits.command_timeout_kvm_s);
    try H.show(out, "fetch the driver library and the probe, make the glibc rootfs", made);
    if (made.status != 0) return error.DeviceSetupFailed;
}

fn step_doctor(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 1: doctor lists the spec and the device\n", .{});
    const command = zbx ++ " doctor";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks.check_doctor(result.streams) catch |err| return fail_step(out, "STEP 1", err);
}

fn step_device(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 2: --device zigbox.test/gpu=0: node, variable, library\n", .{});
    // The node must read as /dev/zero (a failed bind leaves an empty file), and the probe must
    // start with LD_LIBRARY_PATH empty, so only the cache `ldconfig` wrote can find the library.
    const inside = "'head -c 4 /dev/zbx-gpu | od -An -tx1; echo ZBXGPU=$ZBXGPU; " ++
        "echo LDP=$LD_LIBRARY_PATH; ldconfig -p | grep libzbxgpu; zbxgpu-probe'";
    const command = zbx ++ " run --rootfs " ++ glibc_dir ++
        " --name gpu-dev --device zigbox.test/gpu=0 -- sh -c " ++ inside;
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks.check_device_run(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 2", err);
    };
}

fn step_gpu(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 3: --gpu all and --gpu dri on this guest\n", .{});
    const count = "ls /dev/dri 2>/dev/null | grep -c renderD; true";
    const probe = try session.run(count, limits.command_timeout_kvm_s);
    const has_render = !std.mem.eql(u8, std.mem.trim(u8, probe.output, " \r\n"), "0");
    try out.print("demo-m10: the guest has a render node: {}\n", .{has_render});
    if (has_render) {
        const dri = run_prefix ++ " --name gpu-dri --gpu dri -- ls /dev/dri";
        const shown = try H.run_split(session, dri);
        try H.show_split(out, dri, shown);
        checks_m1.check_gpu_dri(shown.streams, shown.status) catch |err| {
            return fail_step(out, "STEP 3", err);
        };
        return;
    }
    const all = run_prefix ++ " --name gpu-all --gpu all -- sh -c 'echo ran'";
    const refused = try H.run_split(session, all);
    try H.show_split(out, all, refused);
    checks_m1.check_gpu_none(refused.streams, refused.status) catch |err| {
        return fail_step(out, "STEP 3", err);
    };
    try out.print("demo-m10: NOT RUN: --gpu dri (the guest has no render node)\n", .{});
}

fn step_not_in_group(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 4: a user outside the node's group is refused\n", .{});
    const gid = try session.run("getent group render | cut -d: -f3", limits.command_timeout_kvm_s);
    if (gid.status != 0) return error.DeviceSetupFailed;
    // A result's output is the session's scratch, which the next command overwrites.
    const trimmed = std.mem.trim(u8, gid.output, " \r\n");
    const render_gid = try session.scratch_allocator().dupe(u8, trimmed);
    const removed = try session.run("gpasswd -d demo render", limits.command_timeout_kvm_s);
    try H.show(out, "take demo out of render", removed);
    const command = run_prefix ++ " --name gpu-out --device zigbox.test/gpu=0 -- sh -c 'echo ran'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const back = try session.run("usermod -aG render demo", limits.command_timeout_kvm_s);
    if (back.status != 0) return error.DeviceSetupFailed;
    checks.check_not_in_group(result.streams, result.status, render_gid) catch |err| {
        return fail_step(out, "STEP 4", err);
    };
}

fn step_yaml(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 5: a YAML spec beside the JSON one\n", .{});
    const put = "printf 'cdiVersion: 0.6.0\\n' > /etc/cdi/zbx-yaml.yaml";
    const wrote = try session.run(put, limits.command_timeout_kvm_s);
    if (wrote.status != 0) return error.DeviceSetupFailed;
    defer _ = session.run("rm -f /etc/cdi/zbx-yaml.yaml", limits.command_timeout_kvm_s) catch {};
    const doctor = zbx ++ " doctor";
    const listed = try H.run_split(session, doctor);
    try H.show_split(out, doctor, listed);
    checks.check_yaml_doctor(listed.streams) catch |err| return fail_step(out, "STEP 5", err);
    const works = run_prefix ++ " --name gpu-yaml1 --device zigbox.test/gpu=0 -- sh -c 'echo ran'";
    const worked = try H.run_split(session, works);
    try H.show_split(out, works, worked);
    if (worked.status != 0 or std.mem.indexOf(u8, worked.streams.stderr, "ZBX-E") != null) {
        return fail_step(out, "STEP 5", error.JsonDeviceDidNotRun);
    }
    const lacks = run_prefix ++ " --name gpu-yaml2 --device zigbox.test/gpu=9 -- sh -c 'echo ran'";
    const refused = try H.run_split(session, lacks);
    try H.show_split(out, lacks, refused);
    checks.check_yaml_run(refused.streams, refused.status) catch |err| {
        return fail_step(out, "STEP 5", err);
    };
}

fn step_no_ldconfig(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 6: an image with no ldconfig\n", .{});
    const copy = "runuser -u demo -- sh -c 'cp -a /home/demo/alpine /home/demo/alpine-nold && " ++
        "rm -f /home/demo/alpine-nold/sbin/ldconfig /home/demo/alpine-nold/usr/sbin/ldconfig " ++
        "/home/demo/alpine-nold/bin/ldconfig /home/demo/alpine-nold/usr/bin/ldconfig'";
    const copied = try session.run(copy, limits.command_timeout_kvm_s);
    try H.show(out, "copy the rootfs without ldconfig", copied);
    if (copied.status != 0) return error.UnpackFailed;
    const command = zbx ++ " run --rootfs /home/demo/alpine-nold --name gpu-nold " ++
        "--device zigbox.test/gpu=0 -- sh -c 'echo LDP=$LD_LIBRARY_PATH'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks.check_no_ldconfig(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 6", err);
    };
}

fn step_baseline(session: *Session, out: *Io.Writer) !void {
    try out.print("\ndemo-m10: STEP 7: a run without devices is as before\n", .{});
    const command = run_prefix ++ " --name gpu-base -- sh -c 'ls /dev; echo UID=$(id -u)'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks.check_baseline(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 7", err);
    };
}

test {
    _ = @import("checks_m10.zig");
}
