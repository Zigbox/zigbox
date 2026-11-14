//! The C4 demo (Zigbox 0.5.2: ZB-5 to ZB-8, docs/demos/c4.md), run in a real Ubuntu 24.04 VM (the
//! M0 harness: same image, same provisioning). A small multi-threaded program, `c4_fixture/
//! supervisor.zig`, plays Zigcube's per-replica supervisor: it did not start the container, and
//! makes sockets in its network namespace with `zigbox.container_socket`. Python scripts
//! (`c4/*.py`) drive it and `zbx`; every assertion is a function of checks_c4.zig with a unit
//! test.
//!   1. start: `zbx run -d --net none` holds one link, `lo`.
//!   2. listen (ZB-5): listeners on 127.77.0.2 and .3 made and closed live, answered from inside.
//!   3. connect (ZB-5, ZB-8): a socket held before an adoption connects to a server inside.
//!   4. net (ZB-7): a second `zbx exec` reaches the first one's listener on 127.0.0.1.
//!   5. hostile: the workload cannot see, signal or write what it must not.
//!   6. refusals: one coded line each.
//! `zig build demo-c4` (KVM) or `zig build demo-c4 -Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_c4.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

const rootfs_dir = "/home/demo/alpine";
const supervisor_route = "/c4/supervisor";
const supervisor_path = "/home/demo/c4-supervisor";

const Script = struct {
    title: []const u8,
    name: []const u8,
    text: []const u8,
    check: *const fn ([]const u8) checks.Error!void,
};

const lib_py = @embedFile("c4/lib.py");

const scripts = [_]Script{
    .{
        .title = "STEP 1: the container, --net none, only lo",
        .name = "start",
        .text = @embedFile("c4/start.py"),
        .check = checks.check_start,
    },
    .{
        .title = "STEP 2: listeners on 127.77.x.y made and closed live (ZB-5)",
        .name = "listen",
        .text = @embedFile("c4/listen.py"),
        .check = checks.check_listen,
    },
    .{
        .title = "STEP 3: a socket held across an adoption connects inside (ZB-5, ZB-8)",
        .name = "connect",
        .text = @embedFile("c4/connect.py"),
        .check = checks.check_connect,
    },
    .{
        .title = "STEP 4: exec joins the container's network (ZB-7)",
        .name = "net",
        .text = @embedFile("c4/net.py"),
        .check = checks.check_net,
    },
    .{
        .title = "STEP 5: the hostile checks",
        .name = "hostile",
        .text = @embedFile("c4/hostile.py"),
        .check = checks.check_hostile,
    },
    .{
        .title = "STEP 6: the refusals",
        .name = "refuse",
        .text = @embedFile("c4/refuse.py"),
        .check = checks.check_refusals,
    },
    .{
        .title = "STEP 7: a given hosts file at /etc/hosts, read-only (ZB-6)",
        .name = "hosts",
        .text = @embedFile("c4/hosts.py"),
        .check = checks.check_hosts,
    },
};

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-c4";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-c4: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-c4: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-c4: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-c4: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
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
    const format = "{s}/overlay-demo-c4.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = supervisor_route, .body = @embedFile("c4_supervisor") },
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
    try install_fixtures(&session, out);
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

/// The supervisor program (served, it is larger than a typed file) and the Python helper module
/// the scripts import.
fn install_fixtures(session: *Session, out: *Io.Writer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o {s} http://10.0.2.2:{d}{s} && chown demo:demo {s} && chmod 755 {s}",
        .{
            supervisor_path,
            session.server.port,
            supervisor_route,
            supervisor_path,
            supervisor_path,
        },
    );
    const copied = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "install the supervisor", copied);
    if (copied.status != 0) return error.InstallFailed;
    try session.put_file("/home/demo/lib.py", lib_py);
}

fn run_script(session: *Session, out: *Io.Writer, script: Script) !void {
    try out.print("\ndemo-c4: {s}\n", .{script.title});
    var path_buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "/home/demo/c4_{s}.py", .{script.name});
    try session.put_file(path, script.text);
    const timeout = limits.command_timeout_kvm_s;
    const chown = try session.run("chown demo:demo /home/demo/c4_*.py", timeout);
    if (chown.status != 0) return error.InstallFailed;
    const format = "{s}sh -c 'cd /home/demo && python3 {s} 2>&1'";
    const allocator = session.scratch_allocator();
    const command = try std.fmt.allocPrint(allocator, format, .{ H.as_demo, path });
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, path, result);
    script.check(result.output) catch |err| {
        try out.print("demo-c4: {s} FAILED ({s})\n", .{ script.title, @errorName(err) });
        return err;
    };
}

test "every guest script fits a put_file" {
    const max = @import("zigbox_vm").limits.put_file_bytes_max;
    try std.testing.expect(lib_py.len <= max);
    for (scripts) |script| try std.testing.expect(script.text.len <= max);
}

test "the scripts print the markers the checks look for" {
    const markers = [_][]const u8{
        "START-RC", "LISTEN-A", "DIAL", "OTHER-EXEC", "KILL-ALL", "REFUSED", "HOSTS-RC",
    };
    for (scripts, markers) |script, marker| {
        try std.testing.expect(std.mem.indexOf(u8, script.text, marker) != null);
    }
}

test {
    _ = @import("checks_c4.zig");
}
