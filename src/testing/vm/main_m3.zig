//! The M3 demo, run in a real Ubuntu 24.04 VM (the M0/M1/M2 harness: same image, same
//! provisioning, the pinned Alpine minirootfs unpacked as user `demo`). It grows slice by slice;
//! this is slice 2, "Materialize and run":
//!   1. Import the rootfs; its digest is printed.
//!   2. `zbx run <digest prefix>` runs on an overlay: a container that writes, changes modes,
//!      changes owners and deletes across the tree leaves the store byte for byte as it was
//!      (a listing with modes, owners and link counts, and the sums of every file, before and
//!      after, compared in the guest). Its writes are in its own upper layer, and the run record
//!      names the tree and the upper.
//!   3. `--read-only` with a digest: touching `/x` is refused by the file system.
//!   4. A tree imported with a root directory of mode 711 is that in the container.
//!   5. An unknown digest is ZBX-E0410 and exit 125. A second run with a name starts from a
//!      fresh upper layer.
//! `zig build demo-m3` (KVM) or `zig build demo-m3 -Daccel=tcg`. See docs/demos/m3.md.

const std = @import("std");
const Io = std.Io;
const checks_m3 = @import("checks_m3.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

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
        .rootfs = rootfs,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try unpack_rootfs(&session, out, &timer);
    try write_scripts(&session, out);
    const digest = try step_import(&session, out, &timer);
    try step_store_untouched(&session, out, &timer, digest);
    try step_read_only(&session, out, &timer, digest);
    try step_root_mode(&session, out, &timer);
    try step_refusals(&session, out, &timer, digest);
    try session.shutdown();
    return 0;
}

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
    "chmod -R go+w /etc /bin /lib /usr\n" ++
    "chmod 4755 /bin/busybox\n" ++
    "chown -R 7:7 /etc /usr/share\n" ++
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
    const check = try session.run("chown demo:demo " ++ rootfs_dir ++ "/scribble.sh; " ++
        "ls -l " ++ rootfs_dir ++ "/scribble.sh /tmp/snapshot.sh", limits.command_timeout_kvm_s);
    try H.show(out, "the test scripts", check);
}

fn step_import(session: *Session, out: *Io.Writer, timer: *H.Timer) ![]const u8 {
    try out.print("\ndemo-m3: STEP 1: import the rootfs\n", .{});
    const command = zbx ++ " store import " ++ rootfs_dir;
    const result = try H.run_split(session, command);
    try H.show_split(out, command, result);
    const digest = checks_m3.check_import(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 1", "expected the digest alone on stdout, exit 0", err);
    };
    try timer.lap(out, "import");
    return try session.scratch_allocator().dupe(u8, digest);
}

fn step_store_untouched(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 2: a container that writes everywhere leaves the store " ++
        "as it was\n", .{});
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
        return fail_step(out, "STEP 2", "the first run by digest", error.RunFailed);
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
        return fail_step(out, "STEP 2", "expected the script to run to its end", err);
    };
    const compare = "sh /tmp/snapshot.sh > /tmp/store.after; " ++
        "if cmp -s /tmp/store.before /tmp/store.after; then echo STORE-SAME; " ++
        "else echo STORE-DIFFERS; diff /tmp/store.before /tmp/store.after | head -20; fi; " ++
        "echo UPPER-ENTRIES:$(find " ++ state_dir ++ "/containers/scribble1/upper | wc -l); " ++
        "echo FARMS:$(ls " ++ store_dir ++ "/cache | wc -l)";
    const after = try session.run(compare, 120);
    try H.show(out, "the store after, compared", after);
    checks_m3.check_store_same(after.output) catch |err| {
        return fail_step(out, "STEP 2", "expected the store byte for byte as it was", err);
    };
    checks_m3.check_upper_written(after.output, 20) catch |err| {
        return fail_step(out, "STEP 2", "expected the writes in the container's upper layer", err);
    };
    const record = try session.run(
        "cat " ++ state_dir ++ "/runs/scribble1.zon",
        limits.command_timeout_kvm_s,
    );
    try H.show(out, "the run record", record);
    checks_m3.check_record(record.output, digest) catch |err| {
        return fail_step(out, "STEP 2", "expected the record to name the tree and the upper", err);
    };
    try timer.lap(out, "store untouched");
}

fn step_read_only(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 3: --read-only with a digest\n", .{});
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
        return fail_step(out, "STEP 3", "expected touch /x refused, touch /tmp/x allowed", err);
    };
    try timer.lap(out, "read-only");
}

fn step_root_mode(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\ndemo-m3: STEP 4: the root directory's mode is the tree's\n", .{});
    const arena = session.scratch_allocator();
    const prepare = "runuser -u demo -- chmod 711 " ++ rootfs_dir;
    _ = try session.run(prepare, limits.command_timeout_kvm_s);
    const import = zbx ++ " store import " ++ rootfs_dir;
    const imported = try H.run_split(session, import);
    try H.show_split(out, import, imported);
    const digest = checks_m3.check_import(imported.streams, imported.status) catch |err| {
        return fail_step(out, "STEP 4", "expected a digest", err);
    };
    const run = try std.fmt.allocPrint(
        arena,
        "{s} run {s} --name root1 -- sh -c 'echo ROOT:$(stat -c \"%a %u %g\" /)'",
        .{ zbx, digest[3..15] },
    );
    const ran = try H.run_split(session, run);
    try H.show_split(out, run, ran);
    checks_m3.check_root(ran.streams.stdout, "711 0 0") catch |err| {
        return fail_step(out, "STEP 4", "expected the root to be 711, owned by root", err);
    };
    try timer.lap(out, "root mode");
}

fn step_refusals(
    session: *Session,
    out: *Io.Writer,
    timer: *H.Timer,
    digest: []const u8,
) !void {
    try out.print("\ndemo-m3: STEP 5: an unknown digest, and a name used twice\n", .{});
    const arena = session.scratch_allocator();
    const unknown = zbx ++ " run ffffffffffff -- true";
    const result = try H.run_split(session, unknown);
    try H.show_split(out, unknown, result);
    checks_m3.check_unknown_digest(result.streams, result.status) catch |err| {
        return fail_step(out, "STEP 5", "expected ZBX-E0410 and exit 125", err);
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
        return fail_step(out, "STEP 5", wanted, error.NotFresh);
    }
    try timer.lap(out, "refusals");
}
