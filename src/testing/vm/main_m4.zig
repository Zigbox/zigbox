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
//! SPEC 3. `zbx pull python:3.12-slim` and then `python:3.13-slim`; `zbx store du --by-image`
//!   shows the second costs a share of its compressed size (a ratio, never exact bytes).
//! UPGRADE, IDENTITY, RESUME, BLOBS (accept_m4.zig): the merged M3 `zbx` leaves a store this one
//!   reads; an image is its tree digest; a pull killed halfway resumes; the blobs are kept
//!   between runs on a second disk.
//! AGENT (agent_m4.zig): the demo again, driven by JSON only.
//! `zig build demo-m4 -Daccel=tcg` for software emulation. See docs/demos/m4.md.

const std = @import("std");
const Io = std.Io;
const accept = @import("accept_m4.zig");
const agent = @import("agent_m4.zig");
const checks_m4 = @import("checks_m4.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const alpine_pin = @import("alpine.zon");
const old_release = @import("old_release.zon");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const z = common.z;
const project = common.project;
const fail_step = common.fail_step;

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
    if (options.old_zbx.len == 0) {
        try out.print("demo-m4: --old-zbx is missing: the upgrade test needs the M3 binary\n", .{});
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const old_binary = try Io.Dir.cwd().readFileAlloc(
        io,
        options.old_zbx,
        arena,
        .limited(limits.elf_bytes_max),
    );
    try out.print("demo-m4: upgrade test from {s}: {s}, {d} bytes\n", .{
        old_release.m4_commit, options.old_zbx, old_binary.len,
    });
    const rootfs_path = try image.ensure_pin(init, options.cache_dir, out, .{
        .url = alpine_pin.url,
        .sha256 = alpine_pin.sha256,
        .file_name = alpine_pin.file_name,
    });
    const rootfs_limit: Io.Limit = .limited(limits.http_body_bytes_max);
    const rootfs = try Io.Dir.cwd().readFileAlloc(io, rootfs_path, arena, rootfs_limit);
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay = try std.fmt.allocPrint(
        arena,
        "{s}/overlay-demo-m4.qcow2",
        .{options.cache_dir},
    );
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};
    if (options.blob_cache.len > 0) {
        try image.ensure_cache_disk(init, options.blob_cache, limits.blob_cache_size_text);
    }

    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(io, options.ca_file, arena, limit);
    }
    var session: Session = undefined;
    try session.start(init, out, overlay, accel, .{
        .user_data = @import("cloud_init.zig").user_data,
        .binary = binary,
        .old_binary = old_binary,
        .rootfs = rootfs,
        .ca_file = ca_file,
        .cache_disk = options.blob_cache,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try steps(&session, out, &timer, ca_file.len > 0, options.blob_cache.len > 0);
    try session.shutdown();
    return 0;
}

fn steps(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    with_ca: bool,
    with_cache: bool,
) !void {
    try accept.unpack_rootfs(session, out);
    try accept.install_old(session, out);
    try common.write_wrappers(session, out, with_ca);
    try accept.step_upgrade(session, out, timer);
    if (with_cache) try accept.cache_restore(session, out, timer);
    try step_pull(session, out, timer);
    try step_run_alpine(session, out, timer);
    try step_dedup(session, out, timer);
    try step_run_python(session, out, timer);
    try step_lock_refusal(session, out, timer);
    try step_config(session, out, timer);
    try accept.step_identity(session, out, timer);
    try accept.step_resume(session, out, timer);
    try agent.run_agent(session, out, timer);
    if (with_cache) try accept.cache_save(session, out, timer);
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

fn step_dedup(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 3: pull python:3.12-slim and python:3.13-slim, then du\n", .{});
    const references = [_][]const u8{ "python:3.12-slim", "python:3.13-slim" };
    for (references) |reference| {
        const command = try common.format(session, "{s} pull {s}", .{ z, reference });
        const pulled = try H.run_split(session, command);
        try H.show_split(out, command, pulled);
        _ = checks_m4.check_pull(pulled.streams, pulled.status) catch |err| {
            return fail_step(out, "SPEC 3", "the pull of the digest", err);
        };
        try timer.lap(out, reference);
    }
    const table = try H.run_split(session, z ++ " store du --by-image");
    try H.show_split(out, "zbx store du --by-image", table);
    const rows = [_][]const u8{ "python:3.12-slim", "python:3.13-slim" };
    checks_m4.check_table_lists(table.streams, table.status, &rows) catch |err| {
        return fail_step(out, "SPEC 3", "expected a row for each image", err);
    };
    const json = try H.run_split(session, z ++ " --output json store du --by-image");
    const arena = session.scratch_allocator();
    const checked = checks_m4.check_dedup(arena, json.streams, json.status, rows[0], rows[1]);
    const facts = checked catch |err| {
        return fail_step(out, "SPEC 3", "expected the second image to cost far less", err);
    };
    try out.print(
        "demo-m4: SPEC 3: python:3.13-slim costs {d} bytes of its {d} compressed " ++
            "({d} of its {d} stored bytes are shared)\n",
        .{ facts.unique_bytes, facts.compressed_bytes, facts.shared_bytes, facts.stored_bytes },
    );
    try timer.lap(out, "du");
}

fn step_run_python(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m4: SPEC 4: zbx run python:3.12-slim, 2**100 in Python\n", .{});
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
    const rest = tree[wrong.len..];
    const wrong_tree = try std.fmt.bufPrint(&wrong_storage, "{s}{s}", .{ wrong, rest });
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

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("accept_m4.zig");
    _ = @import("agent_json.zig");
    _ = @import("agent_m4.zig");
    _ = @import("checks_m4.zig");
    _ = @import("common_m4.zig");
    _ = @import("harness.zig");
    _ = @import("session.zig");
    _ = @import("image.zig");
}
