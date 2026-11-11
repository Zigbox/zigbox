//! The M8b demo, run in a real Ubuntu 24.04 VM (the M0 harness: same image, same provisioning):
//! `zbx run --net none --listen 127.0.0.1:8080 --listen-send FD` makes a listener inside the
//! container's network namespace and hands it to the harness over a Unix socket.
//!   1. hello: the harness receives the listener, accepts the container's own `wget`, answers
//!      `hello from outside`, and the container prints it.
//!   2. hostile: inside, the port is taken; no socket is in the workload's descriptor table; a
//!      host listener on 127.0.0.1:9999 is unreachable; the host shows nothing on :8080.
//!   3. refusals: `--net host`, `--publish`, no `--listen-send`, a `--listen-send` that is not a
//!      Unix socket, and a non-loopback address are each refused with one coded line.
//!   4. closed: when the harness closes the listener, a new `wget` is refused and the container
//!      goes on.
//! The harness side runs as the guest's Python (`m8b/*.py`: `socket.recv_fds` is the receiving
//! half of SCM_RIGHTS); every assertion is a function of checks_m8b.zig with a unit test.
//! `zig build demo-m8b` (KVM) or `zig build demo-m8b -Daccel=tcg`. See docs/demos/m8b.md.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_m8b.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

const rootfs_dir = "/home/demo/alpine";

const Script = struct {
    title: []const u8,
    path: []const u8,
    text: []const u8,
    check: *const fn ([]const u8) checks.Error!void,
};

const scripts = [_]Script{
    .{
        .title = "STEP 1: the listener arrives and the container is answered",
        .path = "/home/demo/m8b_hello.py",
        .text = @embedFile("m8b/hello.py"),
        .check = checks.check_hello,
    },
    .{
        .title = "STEP 2: the hostile checks",
        .path = "/home/demo/m8b_hostile.py",
        .text = @embedFile("m8b/hostile.py"),
        .check = checks.check_hostile,
    },
    .{
        .title = "STEP 3: the refusals",
        .path = "/home/demo/m8b_refuse.py",
        .text = @embedFile("m8b/refuse.py"),
        .check = checks.check_refusals,
    },
    .{
        .title = "STEP 4: the harness closes its end",
        .path = "/home/demo/m8b_closed.py",
        .text = @embedFile("m8b/closed.py"),
        .check = checks.check_closed,
    },
};

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m8b";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m8b: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m8b: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m8b: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-m8b: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
        }
        return err;
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
    const format = "{s}/overlay-demo-m8b.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .rootfs = rootfs,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out);
    for (scripts) |script| try run_script(&session, out, script);
    try session.shutdown();
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

fn run_script(session: *Session, out: *Io.Writer, script: Script) !void {
    try out.print("\ndemo-m8b: {s}\n", .{script.title});
    try session.put_file(script.path, script.text);
    const chown = "chown demo:demo " ++ "/home/demo/m8b_*.py";
    const put = try session.run(chown, limits.command_timeout_kvm_s);
    if (put.status != 0) return error.InstallFailed;
    const allocator = session.scratch_allocator();
    const format = "{s}python3 {s} 2>&1";
    const command = try std.fmt.allocPrint(allocator, format, .{ H.as_demo, script.path });
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, script.path, result);
    script.check(result.output) catch |err| {
        try out.print("demo-m8b: {s} FAILED ({s})\n", .{ script.title, @errorName(err) });
        return err;
    };
}

test "every guest script fits a put_file" {
    for (scripts) |script| {
        try std.testing.expect(script.text.len <= @import("zigbox_vm").limits.put_file_bytes_max);
    }
}

test "the scripts print the markers the checks look for" {
    const markers = [_][]const u8{ "HELLO-RC:", "HOSTILE-RC:", "REFUSED", "CLOSED-RC:" };
    for (scripts, markers) |script, marker| {
        try std.testing.expect(std.mem.indexOf(u8, script.text, marker) != null);
    }
}

test {
    _ = @import("checks_m8b.zig");
}
