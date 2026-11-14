//! The S2 slice 4 check (docs/briefs/S2-lazy-start.md), run in the M0 harness's Ubuntu 24.04 VM:
//! the ordinary user `demo` imports the pinned Alpine minirootfs into the store and runs it with
//! `zbx run --lazy`, so the image's tree is served over FUSE from the store's own objects (no
//! registry). The same commands run eagerly and lazily must print the same thing; a write lands
//! in the upper; nothing of the server is left after the run. The guest script (`lazy_script`)
//! prints one `lazy: <check>: ok` line per check. Slice 6's `demo-s2` replaces it.
//! `zig build demo-s2-lazy` (KVM) or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-s2-lazy";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-s2-lazy: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-s2-lazy: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    const elapsed_s = @divFloor(session_mod.now_ms() - started, 1000);
    try out.print("\ndemo-s2-lazy: PASSED in {d} s\n", .{elapsed_s});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-s2-lazy: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
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
    const format = "{s}/overlay-demo-s2-lazy.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = "/s2/lazy.sh", .body = lazy_script },
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
    try step_lazy(&session, out);
    try timer.lap(out, "lazy");
    try session.shutdown();
}

fn step_lazy(session: *Session, out: *Io.Writer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "curl -fsS -o /tmp/lazy.sh http://10.0.2.2:{d}/s2/lazy.sh && " ++
            "chmod 644 /tmp/rootfs.tar.gz /tmp/lazy.sh && " ++
            H.as_demo ++ "sh /tmp/lazy.sh 2>&1",
        .{ session.server.port, session.server.port },
    );
    assert(command.len < limits.command_bytes_max);
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "zbx run --lazy from the store, as demo", result);
    if (result.status != 0 or std.mem.indexOf(u8, result.output, "lazy: all ok") == null) {
        try out.print("demo-s2-lazy: the lazy run FAILED\n", .{});
        return error.LazyFailed;
    }
}

/// Run as `demo`: unpacks the rootfs, imports it, runs one command eagerly and lazily and
/// compares, then checks a write and what is left after the lazy run.
const lazy_script =
    \\set -u
    \\Z=/home/demo/zbx
    \\R=/home/demo/alpine
    \\ok() { echo "lazy: $1: ok"; }
    \\fail() { echo "lazy: $1: FAIL ($2)"; FAILED=1; }
    \\FAILED=0
    \\echo "lazy: kernel: $(uname -r); /dev/fuse: $(stat -c '%a' /dev/fuse 2>&1)"
    \\rm -rf $R; mkdir -p $R && tar -xzf /tmp/rootfs.tar.gz -C $R ||
    \\  { echo "lazy: unpack FAILED"; exit 1; }
    \\D=$($Z store import $R) || { echo "lazy: import FAILED"; exit 1; }
    \\echo "lazy: imported $D"
    \\C='cat /etc/alpine-release; md5sum /bin/busybox /lib/ld-musl-*'
    \\# Not the link counts or block totals: an eager tree is hard links into the store.
    \\A='$1 != "total" {print $1, $3, $4, $5, $NF}'
    \\C="$C; ls -lan /etc /usr/bin /lib | awk '$A' | md5sum"
    \\E=$($Z run $D -- sh -c "$C" 2>&1); S=$?
    \\[ $S = 0 ] && ok "eager run" || fail "eager run" "exit $S: $E"
    \\L=$($Z run --lazy $D -- sh -c "$C" 2>&1); S=$?
    \\echo "$L" | sed 's/^/lazy: lazy output: /'
    \\[ $S = 0 ] && ok "lazy run" || fail "lazy run" "exit $S: $L"
    \\[ "$E" = "$L" ] && ok "same output eager and lazy" ||
    \\  fail "same output eager and lazy" "eager: $E"
    \\W='echo w > /etc/w && cat /etc/w; grep -c " fuse" /proc/self/mountinfo'
    \\W="$W; head -c 1048576 /bin/busybox | wc -c"
    \\T=$($Z run --lazy $D -- sh -c "$W" 2>&1); S=$?
    \\echo "$T" | sed 's/^/lazy: write run: /'
    \\[ $S = 0 ] && [ "$(echo "$T" | head -1)" = w ] && ok "write in a lazy run" ||
    \\  fail "write in a lazy run" "exit $S"
    \\T=$($Z run --lazy $D -- false 2>&1); S=$?
    \\[ $S = 1 ] && ok "a lazy run's exit status" || fail "a lazy run's exit status" "exit $S: $T"
    \\T=$($Z run --lazy -d $D -- true 2>&1); S=$?
    \\echo "lazy: detached: exit $S: $T"
    \\[ $S != 0 ] && ok "a detached lazy run is refused" ||
    \\  fail "a detached lazy run is refused" "ran"
    \\P=$(pgrep -u demo -f "$Z run" | tr '\n' ' ')
    \\[ -z "$P" ] && ok "no zbx left running" || fail "no zbx left running" "$P"
    \\[ $FAILED = 0 ] && echo "lazy: all ok" || { echo "lazy: some checks FAILED"; exit 1; }
    \\
;
