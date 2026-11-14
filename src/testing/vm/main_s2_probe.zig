//! The S2 probe (docs/briefs/S2-lazy-start.md, slice 1), run in the M0 harness's Ubuntu 24.04
//! VM: a throwaway no-libc FUSE server (s2_probe/fuse_probe.zig) mounted by the ordinary user
//! `demo` inside a user and mount namespace with the full subordinate id map, a `userxattr`
//! overlay stacked on it, and the facts slice 4 depends on: the kernel, /dev/fuse's mode,
//! AppArmor's userns setting, 1 MiB read latency, reads as uid 0 and uid 1000, copy-up, EIO
//! reaching `cat`, ENOTCONN once the server is killed, and what a cached file gives then. The
//! guest script (`probe_script`) prints one `probe: <check>: ok` line per check;
//! checks_s2_probe.zig judges it. Throwaway: the real server is slice 2's.
//! `zig build demo-s2-probe` (KVM) or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const checks = @import("checks_s2_probe.zig");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-s2-probe";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-s2-probe: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-s2-probe: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    const elapsed_s = @divFloor(session_mod.now_ms() - started, 1000);
    try out.print("\ndemo-s2-probe: PASSED in {d} s\n", .{elapsed_s});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-s2-probe: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    const arena = init.arena.allocator();
    const base = try image.ensure(init, options.cache_dir, out);
    const format = "{s}/overlay-demo-s2-probe.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    var session: Session = undefined;
    const extra = [_]@import("zigbox_vm").Route{
        .{ .path = "/s2/fuse_probe", .body = @embedFile("fuse_probe") },
        .{ .path = "/s2/probe.sh", .body = probe_script },
    };
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .extra = &extra,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    try step_probe(&session, out);
    try timer.lap(out, "probe");
    try session.shutdown();
}

fn step_probe(session: *Session, out: *Io.Writer) !void {
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/fuse_probe http://10.0.2.2:{d}/s2/fuse_probe && " ++
            "curl -fsS -o /tmp/probe.sh http://10.0.2.2:{d}/s2/probe.sh && " ++
            "chmod 755 /tmp/fuse_probe /tmp/probe.sh && " ++
            "runuser -u demo -- sh /tmp/probe.sh /tmp/fuse_probe 2>&1",
        .{ session.server.port, session.server.port },
    );
    assert(command.len < limits.command_bytes_max);
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "the FUSE probe, as demo", result);
    checks.check_probe(result.output, result.status) catch |err| {
        try out.print("demo-s2-probe: the probe FAILED ({s})\n", .{@errorName(err)});
        return err;
    };
}

/// Run as the ordinary user with the server's path as `$1`; it re-runs itself as `$0 $1 inner`
/// inside `unshare --user --map-root-user --map-users --map-groups --mount`, mounts the server
/// on `lower` and an overlay over it on `merged`, and prints one line per fact and per check.
const probe_script =
    \\set -u
    \\# $1: the fuse_probe binary. Run as the ordinary user; re-runs itself inside the namespaces.
    \\P=$1
    \\D=/tmp/s2probe
    \\if [ "${2:-}" != inner ]; then
    \\  echo "probe: kernel: $(uname -r)"
    \\  echo "probe: /dev/fuse: $(stat -c '%a %U:%G' /dev/fuse 2>&1)"
    \\  A=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>&1)
    \\  echo "probe: apparmor_restrict_unprivileged_userns: $A"
    \\  echo "probe: user: $(id -u) $(id -un)"
    \\  rm -rf $D; mkdir -p $D/lower $D/upper $D/work $D/merged
    \\  chmod 755 $D $D/upper $D/merged
    \\  S=$(awk -F: -v u="$(id -un)" '$1==u {print $2; exit}' /etc/subuid)
    \\  G=$(awk -F: -v u="$(id -un)" '$1==u {print $2; exit}' /etc/subgid)
    \\  echo "probe: subordinate ids: uid $S gid $G, 65536 each"
    \\  exec unshare --user --map-root-user --map-users=1:$S:65536 \
    \\    --map-groups=1:$G:65536 --setgroups=allow --mount sh "$0" "$P" inner
    \\fi
    \\ok() { echo "probe: $1: ok"; }
    \\fail() { echo "probe: $1: FAIL ($2)"; FAILED=1; }
    \\FAILED=0
    \\U1="setpriv --reuid=1000 --regid=1000 --clear-groups"
    \\HELLO="hello from the zig fuse probe"
    \\echo "probe: uid_map: $(tr -s ' ' < /proc/self/uid_map | tr '\n' ';')"
    \\echo "probe: gid_map: $(tr -s ' ' < /proc/self/gid_map | tr '\n' ';')"
    \\if $P mount $D/lower > $D/pid 2> $D/server.log; then ok "fuse mount"; else
    \\  cat $D/server.log; fail "fuse mount" "see above"; exit 1; fi
    \\SERVER=$(sed -n 's/.*server pid //p' $D/pid)
    \\echo "probe: mountinfo: $(grep zbxprobe /proc/self/mountinfo)"
    \\O=lowerdir=$D/lower,upperdir=$D/upper,workdir=$D/work,userxattr
    \\if mount -t overlay overlay -o $O $D/merged 2> $D/err; then ok "overlay mount"
    \\else fail "overlay mount" "$(cat $D/err)"; exit 1; fi
    \\echo "probe: mountinfo: $(grep ' overlay ' /proc/self/mountinfo | grep s2probe)"
    \\ls -ln $D/merged | sed 's/^/probe: ls: /'
    \\T=$(cat $D/merged/hello.txt 2>&1)
    \\[ "$T" = "$HELLO" ] && ok "read as uid 0 through the overlay" ||
    \\  fail "read as uid 0 through the overlay" "$T"
    \\R=$($P read $D/merged/big.bin 2>&1) && ok "16 MiB read through the overlay" ||
    \\  fail "16 MiB read through the overlay" "$R"
    \\echo "probe: latency uncached: $R"
    \\R=$($P read $D/merged/big.bin 2>&1)
    \\echo "probe: latency cached: $R"
    \\# STATFS makes the server write its READ log, which it keeps out of the timed reads.
    \\sizes() { stat -f $D/lower > /dev/null
    \\  sed -n "s/.*READ $1 offset [0-9]* size //p" $D/server.log | sort -n | uniq -c |
    \\  tr -s ' \n' ' '; }
    \\echo "probe: READ requests for big.bin (count size): $(sizes big.bin)"
    \\R=$($U1 $P read $D/merged/other.bin 2>&1) && ok "read as uid 1000 through the overlay" ||
    \\  fail "read as uid 1000 through the overlay" "$R"
    \\T=$($U1 cat $D/lower/hello.txt 2>&1)
    \\[ "$T" = "$HELLO" ] && ok "read as uid 1000 on the FUSE mount" ||
    \\  fail "read as uid 1000 on the FUSE mount" "$T"
    \\echo "probe: id as 1000: $($U1 id)"
    \\T=$(dd if=$D/lower/other.bin of=/dev/null bs=1M count=2 iflag=direct 2>&1 | tail -1)
    \\echo "probe: O_DIRECT 1 MiB reads on the FUSE mount: $T"
    \\echo "probe: READ requests for other.bin (count size): $(sizes other.bin)"
    \\echo appended >> $D/merged/hello.txt 2> $D/err || fail "copy-up" "$(cat $D/err)"
    \\[ "$(cat $D/upper/hello.txt)" = "$(printf '%s\nappended' "$HELLO")" ] &&
    \\  ok "copy-up" || fail "copy-up" "upper: $(cat $D/upper/hello.txt 2>&1)"
    \\[ "$(cat $D/lower/hello.txt)" = "$HELLO" ] && ok "lower unchanged" ||
    \\  fail "lower unchanged" "$(cat $D/lower/hello.txt 2>&1)"
    \\echo new > $D/merged/new.txt && [ -f $D/upper/new.txt ] && ok "new file in the upper" ||
    \\  fail "new file in the upper" "missing"
    \\T=$(touch $D/lower/x 2>&1); echo "probe: touch on the FUSE mount: $T"
    \\case "$T" in *"Read-only file system"*) ok "lower is read-only" ;;
    \\  *) fail "lower is read-only" "$T" ;; esac
    \\T=$(cat $D/merged/broken.bin 2>&1 >/dev/null); echo "probe: cat broken.bin: $T"
    \\case "$T" in *"Input/output error"*) ok "EIO reaches cat" ;;
    \\  *) fail "EIO reaches cat" "$T" ;; esac
    \\exec 3< $D/merged/big.bin
    \\kill -9 "$SERVER"; sleep 1
    \\T=$(cat $D/merged/sub/nested.txt 2>&1 >/dev/null); echo "probe: cat after kill: $T"
    \\case "$T" in *"not connected"*) ok "ENOTCONN after kill" ;;
    \\  *) fail "ENOTCONN after kill" "$T" ;; esac
    \\T=$(ls $D/lower 2>&1); echo "probe: ls on the FUSE mount after kill: $T"
    \\T=$(cat $D/merged/big.bin 2>&1 >/dev/null); echo "probe: new open of cached big.bin: $T"
    \\N=$(cat <&3 2> $D/err | wc -c)
    \\echo "probe: fd opened before the kill: $N bytes of big.bin $(cat $D/err)"
    \\exec 3<&-
    \\grep -v ' READ ' $D/server.log | sed 's/^/probe: server log: /' | head -40
    \\[ $FAILED = 0 ] && echo "probe: all ok" || { echo "probe: some checks FAILED"; exit 1; }
    \\
;

test {
    _ = @import("checks_s2_probe.zig");
    _ = @import("s2_probe/fuse_probe.zig");
}
