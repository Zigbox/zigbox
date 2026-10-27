//! The M4 demo, run in a real Ubuntu 24.04 VM (the M0 to M3 harness: same image, same
//! provisioning). This is the part slice 3 builds: pull and run real images by name, through
//! `ZBX_REGISTRY_MIRRORS=mirror.gcr.io` when the guest cannot reach Docker Hub unthrottled.
//!
//! SPEC 1. `zbx pull alpine:3.20` prints the manifest digest and writes `zbx.lock`.
//! SPEC 2. `zbx run alpine:3.20 -- cat /etc/os-release` prints Alpine's.
//! SPEC 4. `zbx run python:3.12-slim -- python -c 'print(2**100)'` prints the number.
//! SPEC 5. The lock's tree for alpine:3.20 is changed to a wrong digest: `zbx run` refuses with
//!   exit 125 and names the digest the lock expects and the store's.
//! CONFIG. `memcached:alpine` runs as the user its configuration names (the full id map is on
//!   in the guest, so the image's /etc/passwd is used); `/sys` is read-only in a container.
//! Slice 5 adds step 3 (`store du --by-image`), the interrupted pull, the agent test, the
//! upgrade test and the CI job. `zig build demo-m4 -Daccel=tcg` for software emulation.

const std = @import("std");
const Io = std.Io;
const checks_m4 = @import("checks_m4.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m4";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m4: bad arguments ({s}); see docs/demos/m4.md\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    const code = demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m4: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m4: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return code;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !u8 {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-m4: /dev/kvm is not usable here; for software emulation " ++
                "(slow) add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay = try std.fmt.allocPrint(
        arena,
        "{s}/overlay-demo-m4.qcow2",
        .{options.cache_dir},
    );
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    const ca_file: []const u8 = if (options.ca_file.len == 0) "" else try Io.Dir.cwd().readFileAlloc(
        io,
        options.ca_file,
        arena,
        .limited(limits.http_body_bytes_max),
    );
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = @import("cloud_init.zig").user_data,
        .binary = binary,
        .ca_file = ca_file,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try write_wrapper(&session, out, ca_file.len > 0);
    try step_pull(&session, out, &timer);
    try step_run_alpine(&session, out, &timer);
    try step_run_python(&session, out, &timer);
    try step_lock_refusal(&session, out, &timer);
    try step_config(&session, out, &timer);
    try session.shutdown();
    return 0;
}

/// `zbx` as the demo user, in the project directory, with the mirror named: the images come from
/// `mirror.gcr.io` first, as in CI, so the anonymous Docker Hub allowance is not what the demo
/// depends on.
const z = H.as_demo ++ "/home/demo/z";
const project = "/home/demo/project";

const wrapper =
    "#!/bin/sh\n" ++
    "cd " ++ project ++ " || exit 125\n" ++
    "export ZBX_REGISTRY_MIRRORS=mirror.gcr.io\n" ++
    "exec /home/demo/zbx \"$@\"\n";

const wrapper_with_ca =
    "#!/bin/sh\n" ++
    "cd " ++ project ++ " || exit 125\n" ++
    "export ZBX_REGISTRY_MIRRORS=mirror.gcr.io SSL_CERT_FILE=/home/demo/ca.crt\n" ++
    "exec /home/demo/zbx \"$@\"\n";

fn fail_step(out: *Io.Writer, step: []const u8, what: []const u8, err: anyerror) anyerror {
    try out.print("demo-m4: {s} FAILED: {s} ({s})\n", .{ step, what, @errorName(err) });
    return err;
}

fn write_wrapper(session: *Session, out: *Io.Writer, with_ca: bool) !void {
    const made = try session.run(
        "runuser -u demo -- mkdir -p " ++ project,
        limits.command_timeout_kvm_s,
    );
    if (made.status != 0) return error.PrepareFailed;
    try H.put_file(session, "/home/demo/z", if (with_ca) wrapper_with_ca else wrapper);
    if (with_ca) {
        const fetch = try std.fmt.allocPrint(
            session.scratch_allocator(),
            "curl -fsS -o /home/demo/ca.crt http://10.0.2.2:{d}/ca.crt",
            .{session.server.port},
        );
        const fetched = try session.run(fetch, limits.command_timeout_kvm_s);
        if (fetched.status != 0) return error.PrepareFailed;
    }
    const owned = try session.run(
        "chown demo:demo /home/demo/z && ls -l /home/demo/z",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the wrapper that runs zbx in the project directory", owned);
    if (owned.status != 0) return error.PrepareFailed;
}

var alpine_manifest: [71]u8 = undefined;

fn step_pull(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 1: zbx pull alpine:3.20\n", .{});
    const command = z ++ " pull alpine:3.20";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const digest = checks_m4.check_pull(result.streams, result.status) catch |err| {
        return fail_step(
            out,
            "SPEC 1",
            "expected the manifest digest alone on stdout, exit 0",
            err,
        );
    };
    @memcpy(&alpine_manifest, digest);
    const lock = try session.run("cat " ++ project ++ "/zbx.lock", limits.command_timeout_kvm_s);
    try H.show(out, "cat zbx.lock", lock);
    if (std.mem.indexOf(u8, lock.output, &alpine_manifest) == null) return error.LockMissingDigest;
    try timer.lap(out, "pull alpine");
}

fn step_run_alpine(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 2: zbx run alpine:3.20 -- cat /etc/os-release\n", .{});
    const command = z ++ " run alpine:3.20 -- cat /etc/os-release";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m4.check_output_has(result.streams, result.status, "ID=alpine") catch |err| {
        return fail_step(out, "SPEC 2", "expected Alpine's os-release, exit 0", err);
    };
    try timer.lap(out, "run alpine");
}

fn step_run_python(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 4: pull python:3.12-slim and run python\n", .{});
    const pulled = try H.run_split(session, z ++ " pull python:3.12-slim");
    try H.show_split(out, "zbx pull python:3.12-slim", pulled);
    _ = checks_m4.check_pull(pulled.streams, pulled.status) catch |err| {
        return fail_step(out, "SPEC 4", "the pull of python:3.12-slim", err);
    };
    try timer.lap(out, "pull python");
    const command = z ++ " run python:3.12-slim -- python -c 'print(2**100)'";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    checks_m4.check_output_is(
        result.streams,
        result.status,
        "1267650600228229401496703205376",
    ) catch |err| {
        return fail_step(out, "SPEC 4", "expected 2**100, exit 0", err);
    };
    try timer.lap(out, "run python");
}

fn step_lock_refusal(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 5: a wrong tree in zbx.lock\n", .{});
    // The tree the lock has for alpine:3.20, then the same lock with its first digits changed.
    const read = try session.run(
        "grep -A4 'alpine:3.20' " ++ project ++ "/zbx.lock | grep -o 'b3:[0-9a-f]*'",
        limits.command_timeout_kvm_s,
    );
    const found = std.mem.trim(u8, read.output, " \r\n");
    if (found.len != 67) return error.LockTreeNotFound;
    // The session's buffer is reused by the next command: keep the digests here.
    var tree_storage: [67]u8 = undefined;
    @memcpy(&tree_storage, found);
    const tree: []const u8 = &tree_storage;
    const wrong = "b3:00000000";
    const edit = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "runuser -u demo -- cp {s}/zbx.lock /tmp/zbx.lock.good && " ++
            "runuser -u demo -- sed -i 's/{s}/{s}{s}/' {s}/zbx.lock",
        .{ project, tree, wrong, tree[wrong.len..], project },
    );
    const edited = try session.run(edit, limits.command_timeout_kvm_s);
    if (edited.status != 0) return error.LockNotEdited;
    const command = z ++ " run alpine:3.20 -- true";
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    var wrong_storage: [67]u8 = undefined;
    const wrong_tree = try std.fmt.bufPrint(&wrong_storage, "{s}{s}", .{ wrong, tree[wrong.len..] });
    const digests = [_][]const u8{ tree, wrong_tree };
    checks_m4.check_refusal(result.streams, result.status, "ZBX-E0519", &digests) catch |err| {
        return fail_step(out, "SPEC 5", "expected E0519 naming both trees, exit 125", err);
    };
    const restored = try session.run(
        "runuser -u demo -- cp /tmp/zbx.lock.good " ++ project ++ "/zbx.lock",
        limits.command_timeout_kvm_s,
    );
    if (restored.status != 0) return error.LockNotRestored;
    try timer.lap(out, "lock refusal");
}

fn step_config(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: CONFIG: the user of the image, and /sys\n", .{});
    const pulled = try H.run_split(session, z ++ " pull memcached:alpine");
    try H.show_split(out, "zbx pull memcached:alpine", pulled);
    _ = checks_m4.check_pull(pulled.streams, pulled.status) catch |err| {
        return fail_step(out, "CONFIG", "the pull of memcached:alpine", err);
    };
    const user_command = z ++ " run memcached:alpine -- sh -c 'id -un; id -u; echo $HOME'";
    const user = try H.run_split(session, user_command);
    try H.show_split(out, user_command, user);
    checks_m4.check_output_has(
        user.streams,
        user.status,
        "memcache\n11211\n/home/memcache",
    ) catch |err| {
        return fail_step(out, "CONFIG", "expected the image's user memcache (11211)", err);
    };
    const sys_command = z ++ " run alpine:3.20 -- sh -c " ++
        "'touch /sys/x 2>&1; grep \" /sys \" /proc/mounts'";
    const sys = try H.run_split(session, sys_command);
    try H.show_split(out, sys_command, sys);
    checks_m4.check_output_has(sys.streams, 0, "Read-only file system") catch |err| {
        return fail_step(out, "CONFIG", "expected /sys to be read-only", err);
    };
    try timer.lap(out, "config");
}
