//! The S2 slice 4 check (docs/briefs/S2-lazy-start.md), run in the M0 harness's Ubuntu 24.04 VM:
//! the ordinary user `demo` imports the pinned Alpine minirootfs (plus a 3 MiB file, a hard-link
//! pair and a user xattr) into a fresh store and runs it with `zbx run --lazy`, so the image's
//! tree is served over FUSE from the store's own objects (no registry). From outside, as root,
//! the script checks that FUSE served it: `zbx` holds `/dev/fuse`, a FUSE connection exists, and
//! no materialized tree does. A recursive listing of the whole tree is the same eager and lazy; a
//! write lands in the upper; the container killed mid-read and `zbx` killed both leave nothing
//! behind. The guest script (`lazy_script`) prints one `lazy: <check>: ok` line per check.
//! Slice 6's `demo-s2` replaces it.
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
        .{ .path = "/s2/fuse-kernel-test", .body = @embedFile("fuse_kernel_test") },
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
    try step_kernel_test(&session, out);
    try timer.lap(out, "kernel test");
    try session.shutdown();
}

fn step_lazy(session: *Session, out: *Io.Writer) !void {
    // As root: the checks look at the run from outside (`/proc`, fusectl); the script runs
    // `zbx` as `demo` itself.
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "curl -fsS -o /tmp/lazy.sh http://10.0.2.2:{d}/s2/lazy.sh && " ++
            "chmod 644 /tmp/rootfs.tar.gz /tmp/lazy.sh && " ++
            "U='" ++ H.as_demo ++ "' sh /tmp/lazy.sh 2>&1",
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

fn step_kernel_test(session: *Session, out: *Io.Writer) !void {
    // As `demo`, as zbx serves: the test makes its own user namespace, mounts `/dev/fuse` there
    // and serves it (src/fuse/kernel_tests.zig). It skips where it cannot mount; here it must not.
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/fuse-kernel-test http://10.0.2.2:{d}/s2/fuse-kernel-test && " ++
            "chmod 755 /tmp/fuse-kernel-test && cd /tmp && " ++
            H.as_demo ++ "/tmp/fuse-kernel-test 2>&1",
        .{session.server.port},
    );
    assert(command.len < limits.command_bytes_max);
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "the FUSE server against the guest's kernel, as demo", result);
    // The runner prints the test's name and then OK, SKIP or FAIL.
    const passed = std.mem.indexOf(u8, result.output, "xattrs and EIO...OK") != null;
    if (result.status != 0 or !passed) {
        try out.print("demo-s2-lazy: the FUSE kernel test FAILED or skipped\n", .{});
        return error.KernelTestFailed;
    }
}

/// Run as root with `U` the prefix that runs a command as `demo`: unpacks and extends the rootfs,
/// imports it into a fresh store, then runs the checks in order (the first lazy run comes before
/// any eager run, so nothing is materialized yet).
const lazy_script = lazy_setup ++ lazy_served ++ lazy_compare ++ lazy_exits;

const lazy_setup =
    \\set -u
    \\Z=/home/demo/zbx
    \\R=/home/demo/alpine
    \\X=/home/demo/s2-data
    \\U="$U XDG_DATA_HOME=$X"
    \\CACHE=$X/zbx/store/cache
    \\FC=/sys/fs/fuse/connections
    \\ok() { echo "lazy: $1: ok"; }
    \\fail() { echo "lazy: $1: FAIL ($2)"; FAILED=1; }
    \\FAILED=0
    \\echo "lazy: kernel: $(uname -r); /dev/fuse: $(stat -c '%a' /dev/fuse 2>&1)"
    \\mountpoint -q $FC || mount -t fusectl none $FC || { echo "lazy: no fusectl"; exit 1; }
    \\conns() { ls $FC | wc -l; }
    \\BASE=$(conns)
    \\rm -rf $R $X; install -d -o demo -g demo $R $X
    \\$U tar -xzf /tmp/rootfs.tar.gz -C $R || { echo "lazy: unpack FAILED"; exit 1; }
    \\# Over 1 MiB so reads cross chunks; a hard-link pair; a user xattr.
    \\$U sh -c "head -c 3158093 /dev/urandom > $R/big && ln $R/big $R/big.link &&
    \\  head -c 65536 /dev/urandom > $R/cold &&
    \\  python3 -c 'import os; os.setxattr(\"$R/cold\", \"user.zbx.demo\", b\"lazy\")'" ||
    \\  { echo "lazy: extending the rootfs FAILED"; exit 1; }
    \\cat > /tmp/s2-list.sh <<'LIST'
    \\# Every entry of / that is not a mount point: type and mode, owner, size and checksum of a
    \\# file, target of a link, link count of a directory (a file's differs: an eager tree is hard
    \\# links into the store). Directory sizes are the file system's own and differ too.
    \\M=$(awk '{print $2}' /proc/mounts)
    \\find / -xdev | sort | while IFS= read -r p; do
    \\  echo "$M" | grep -qxF "$p" && continue
    \\  if [ -L "$p" ]; then echo "$(stat -c '%n %f %u %g' "$p") -> $(readlink "$p")"
    \\  elif [ -d "$p" ]; then stat -c '%n %f %u %g links %h' "$p"
    \\  elif [ -f "$p" ]; then echo "$(stat -c '%n %f %u %g %s' "$p") $(md5sum < "$p")"
    \\  else stat -c '%n %f %u %g' "$p"; fi
    \\done
    \\LIST
    \\$U cp /tmp/s2-list.sh $R/s2-list.sh
    \\D=$($U $Z store import $R) || { echo "lazy: import FAILED"; exit 1; }
    \\echo "lazy: imported $D"
    \\[ -d $CACHE ] && [ -z "$(ls -A $CACHE)" ] && ok "fresh store, nothing materialized" ||
    \\  fail "fresh store, nothing materialized" "$(ls -A $CACHE 2>&1)"
    \\
;

/// The first lazy run: while it sleeps, everything that shows FUSE serves the tree.
const lazy_served =
    \\$U $Z run --lazy $D -- sh -c 'exec sleep 41' > /tmp/lazy1.out 2>&1 &
    \\RUN=$!
    \\SP=; for i in $(seq 100); do SP=$(pgrep -f '^sleep 41$') && break; sleep 0.1; done
    \\ZP=$(pgrep -o -f "^$Z run --lazy")
    \\echo "lazy: zbx pid ${ZP:-none}, container pid ${SP:-none}"
    \\if [ -n "$SP" ] && [ -n "$ZP" ]; then
    \\  # By device number (misc 10:229): the setup child opened it in the container's mount
    \\  # namespace, so the link's path is the one seen from there.
    \\  FD=""; for f in /proc/$ZP/fd/*; do
    \\    [ "$(stat -L -c '%F %t:%T' "$f" 2>/dev/null)" = "character special file a:e5" ] && FD=$f
    \\  done
    \\  [ -n "$FD" ] && ok "zbx holds /dev/fuse ($FD)" ||
    \\    fail "zbx holds /dev/fuse" "$(ls -l /proc/$ZP/fd)"
    \\  N=$(conns); [ $N -gt $BASE ] && ok "a FUSE connection ($BASE -> $N)" ||
    \\    fail "a FUSE connection" "$BASE -> $N"
    \\  grep -q ' / overlay ' /proc/$SP/mounts && ok "the container's root is an overlay" ||
    \\    fail "the container's root is an overlay" "$(cat /proc/$SP/mounts)"
    \\  [ -z "$(ls -A $CACHE)" ] && ok "no materialized tree while lazy" ||
    \\    fail "no materialized tree while lazy" "$(ls -A $CACHE)"
    \\  python3 - /proc/$SP/root $R <<'PY'
    \\import hashlib, os, sys
    \\root, host = sys.argv[1], sys.argv[2]
    \\def check(name, good, detail):
    \\    print("lazy: %s: %s" % (name, "ok" if good else "FAIL (%s)" % detail))
    \\with open(root + "/big", "rb") as f, open(host + "/big", "rb") as g:
    \\    got, want = os.pread(f.fileno(), 3000, 1048000), os.pread(g.fileno(), 3000, 1048000)
    \\check("3000 bytes at offset 1048000, across a chunk", got == want, len(got))
    \\digest = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    \\check("all of the 3 MiB file", digest(root + "/big") == digest(host + "/big"), "differs")
    \\a, b = os.stat(root + "/big"), os.stat(root + "/big.link")
    \\check("hard links share an inode", a.st_ino == b.st_ino, (a.st_ino, b.st_ino))
    \\check("a hard link counts 2", a.st_nlink == 2, a.st_nlink)
    \\value = os.getxattr(root + "/cold", "user.zbx.demo")
    \\check("the user xattr", value == b"lazy", value)
    \\names = os.listxattr(root + "/cold")
    \\check("the file's xattr names", names == ["user.zbx.demo"], names)
    \\leaked = [n for n in os.listxattr(root + "/") if "overlay" in n]
    \\check("no overlay xattr shows", leaked == [], leaked)
    \\PY
    \\  kill -9 $SP
    \\else
    \\  fail "the lazy run started" "$(cat /tmp/lazy1.out)"
    \\fi
    \\wait $RUN; S=$?
    \\[ $S = 137 ] && ok "the lazy run ended with its container (137)" ||
    \\  fail "the lazy run ended with its container" "exit $S: $(cat /tmp/lazy1.out)"
    \\[ -z "$(ls -A $CACHE)" ] && ok "still nothing materialized" ||
    \\  fail "still nothing materialized" "$(ls -A $CACHE)"
    \\T=$($U $Z run --lazy -d $D -- true 2>&1); S=$?
    \\echo "lazy: detached: exit $S: $T"
    \\[ $S = 0 ] && ok "a detached lazy run starts (S2 slice 6)" ||
    \\  fail "a detached lazy run starts" "exit $S"
    \\
;

/// The whole tree eager and lazy, then a write, an exit status.
const lazy_compare =
    \\$U $Z run $D -- sh /s2-list.sh > /tmp/eager.list 2>&1; S=$?
    \\[ $S = 0 ] && ok "eager listing" || fail "eager listing" "exit $S: $(tail -3 /tmp/eager.list)"
    \\[ -n "$(ls -A $CACHE)" ] && ok "the eager run materialized" ||
    \\  fail "the eager run materialized" "nothing in $CACHE"
    \\$U $Z run --lazy $D -- sh /s2-list.sh > /tmp/lazy.list 2>&1; S=$?
    \\[ $S = 0 ] && ok "lazy listing" || fail "lazy listing" "exit $S: $(tail -3 /tmp/lazy.list)"
    \\echo "lazy: listing: $(wc -l < /tmp/lazy.list) entries" \
    \\  "$(grep -c ' -> ' /tmp/lazy.list) links"
    \\grep '^/big\|^/cold\|^/etc/alpine-release' /tmp/lazy.list | sed 's/^/lazy: lazy: /'
    \\cmp -s /tmp/eager.list /tmp/lazy.list && ok "the whole tree is the same eager and lazy" || {
    \\  diff /tmp/eager.list /tmp/lazy.list | head -20 | sed 's/^/lazy: diff: /'
    \\  fail "the whole tree is the same eager and lazy" "see diff"; }
    \\W='echo w > /etc/w && cat /etc/w; head -c 1048576 /big | wc -c'
    \\T=$($U $Z run --lazy $D -- sh -c "$W" 2>&1); S=$?
    \\echo "$T" | sed 's/^/lazy: write run: /'
    \\[ $S = 0 ] && [ "$T" = "$(printf 'w\n1048576')" ] && ok "write in a lazy run" ||
    \\  fail "write in a lazy run" "exit $S"
    \\T=$($U $Z run --lazy $D -- false 2>&1); S=$?
    \\[ $S = 1 ] && ok "a lazy run's exit status" || fail "a lazy run's exit status" "exit $S: $T"
    \\
;

/// The exits that do not go through the container ending on its own, then what is left.
const lazy_exits =
    \\$U $Z run --lazy $D -- sh -c 'while :; do cat /big /cold > /dev/null; done' \
    \\  > /tmp/lazy2.out 2>&1 &
    \\RUN=$!
    \\CP=; for i in $(seq 100); do CP=$(pgrep -f '^sh -c while') && break; sleep 0.1; done
    \\sleep 1; kill -9 $CP
    \\( sleep 15; kill -9 $RUN 2>/dev/null ) & GUARD=$!
    \\wait $RUN; S=$?; kill $GUARD 2>/dev/null
    \\[ $S = 137 ] && ok "container killed mid-read: zbx returns (137)" ||
    \\  fail "container killed mid-read: zbx returns" "exit $S: $(cat /tmp/lazy2.out)"
    \\$U $Z run --lazy $D -- sh -c 'exec sleep 42' > /tmp/lazy3.out 2>&1 &
    \\RUN=$!
    \\SP=; for i in $(seq 100); do SP=$(pgrep -f '^sleep 42$') && break; sleep 0.1; done
    \\ZP=$(pgrep -o -f "^$Z run --lazy")
    \\kill -9 $ZP; wait $RUN
    \\for i in $(seq 100); do kill -0 $SP 2>/dev/null || break; sleep 0.1; done
    \\if kill -0 $SP 2>/dev/null; then
    \\  E=$(cat /proc/$SP/root/cold 2>&1 > /dev/null); S=$?
    \\  [ $S != 0 ] && ok "zbx killed: a reader gets an error ($E)" ||
    \\    fail "zbx killed: a reader gets an error" "read worked"
    \\  kill -9 $SP
    \\else
    \\  ok "zbx killed: its container ended with it"
    \\fi
    \\for i in $(seq 100); do [ "$(conns)" -le $BASE ] && break; sleep 0.1; done
    \\N=$(conns); [ $N -le $BASE ] && ok "no FUSE connection left ($N)" ||
    \\  fail "no FUSE connection left" "$BASE -> $N"
    \\F=$(awk '$3 ~ /^fuse(\.|$)/' /proc/mounts)
    \\[ -z "$F" ] && ok "no FUSE mount left" || fail "no FUSE mount left" "$F"
    \\P=$(pgrep -u demo -f "$Z run" | tr '\n' ' ')
    \\[ -z "$P" ] && ok "no zbx left running" || fail "no zbx left running" "$P"
    \\[ $FAILED = 0 ] && echo "lazy: all ok" || { echo "lazy: some checks FAILED"; exit 1; }
    \\
;
