//! `zig build demo-s2` (docs/briefs/S2-lazy-start.md, "The demo"), in the M0 harness's Ubuntu
//! 24.04 VM, as the ordinary user `demo`. The registry runs on the runner (`registry_disk_s2.zig`,
//! throttled to 40 MiB/s, with a byte counter and two faults) and the guest reaches it through a
//! loopback relay (`tool_s2.zig forward`), since zbx speaks plain HTTP only to a loopback registry.
//! The guest generates the fixture image `lazy:3g` and its `-v2` (`fixture_s2.zig`) and pushes
//! both with its own `zbx push`; the runner computes the hashes the steps expect from the same
//! generator, reads the pushed index to find chunk 3 of `/data/c.bin`, and arms the flip there.
//! Then the brief's nine steps run, one guest command each (`s2_script`). Each prints one
//! `s2: <step>: <check>: ok` or `FAIL (...)` line per check and `s2: recorded <key> <value>` per
//! measured number; the harness checks every number's bound again (`checks_s2.zig`) and prints
//! them all as `demo-s2: RECORDED` lines. A failed step does not stop the later ones, so one run
//! shows every step; the demo fails if any did.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const vm = @import("zigbox_vm");
const harness = @import("harness.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const session_mod = @import("session.zig");
const alpine = @import("alpine.zon");
const old_release = @import("old_release.zon");
const checks = @import("checks_s2.zig");
const fixture = @import("fixture_s2.zig");
const index = @import("index_s2.zig");
const registry_mod = @import("registry_disk_s2.zig");

const Session = session_mod.Session;
const Registry = registry_mod.Registry;
const H = harness;

/// The guest's disk holds the generated tree, a scratch store, and the stores of steps 2 to 9
/// (two of them whole, 3 GiB each); the default overlay is too small.
const overlay_size = "40G";
const registry_directory = "s2-registry";

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-s2";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-s2: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-s2: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    const elapsed_s = @divFloor(session_mod.now_ms() - started, 1000);
    try out.print("\ndemo-s2: PASSED in {d} s\n", .{elapsed_s});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const io = init.io;
    const accel = harness.choose_accel(options.accel, H.kvm_usable(io)) catch |err| switch (err) {
        error.NoKvm => {
            try out.print("demo-s2: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
            return error.NoKvm;
        },
        error.BadAccel => return error.BadAccel,
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        try out.print("demo-s2: --old-zbx is missing: step 9 needs {s}\n", .{old_release.s2_tag});
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const elf_limit: Io.Limit = .limited(limits.elf_bytes_max);
    const old_binary = try Io.Dir.cwd().readFileAlloc(io, options.old_zbx, arena, elf_limit);
    const rootfs_path = try image.ensure_pin(init, options.cache_dir, out, .{
        .url = alpine.url,
        .sha256 = alpine.sha256,
        .file_name = alpine.file_name,
    });
    const limit: Io.Limit = .limited(limits.http_body_bytes_max);
    const rootfs = try Io.Dir.cwd().readFileAlloc(io, rootfs_path, arena, limit);
    const base = try image.ensure(init, options.cache_dir, out);
    const overlay_name = "{s}/overlay-demo-s2.qcow2";
    const overlay = try std.fmt.allocPrint(arena, overlay_name, .{options.cache_dir});
    if (!options.reuse_overlay) try vm.image.make_overlay_sized(init, base, overlay, overlay_size);
    defer if (!options.keep_overlay) Io.Dir.cwd().deleteFile(io, overlay) catch {};

    // About 6 GiB of pushed blobs: on the runner's disk, gone when the demo ends either way.
    const root = try std.fmt.allocPrintSentinel(arena, "{s}/" ++ registry_directory, .{
        options.cache_dir,
    }, 0);
    Io.Dir.cwd().deleteTree(io, root) catch {};
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const registry = try arena.create(Registry); // About 1 MiB: its manifests are inline.
    try registry.init(root, fixture.throttle_bytes_per_second);
    defer registry.deinit();
    try registry.start();
    try out.print("demo-s2: registry on 127.0.0.1:{d} at {d} MiB/s, blobs in {s}\n", .{
        registry.port, fixture.throttle_bytes_per_second >> 20, root,
    });

    var session: Session = undefined;
    const extra = [_]vm.Route{
        .{ .path = "/s2/tool", .body = @embedFile("tool_s2") },
        .{ .path = "/s2/s2.sh", .body = s2_script },
    };
    comptime assert(vm.limits.seed_routes + 3 + extra.len <= vm.limits.http_routes_max);
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .rootfs = rootfs,
        .old_binary = old_binary,
        .extra = &extra,
    });
    defer session.deinit();
    try run_all(&session, out, registry, options.reuse_overlay);
    try session.shutdown();
}

fn run_all(session: *Session, out: *Io.Writer, registry: *Registry, reuse: bool) !void {
    var timer = H.Timer.start();
    try H.provision(session, out, &timer, reuse);
    try H.install_binary(session, out, &timer);
    try fetch(session, out);
    try write_env(session, out, registry.port);
    try timer.lap(out, "the guest's files and the expected hashes");
    try run_step(session, out, prep, null);
    try timer.lap(out, "prep");
    try arm_flip(session, out, registry);
    var recorded: checks.Recorded = .{};
    var failed: u32 = 0;
    for (steps) |step| {
        run_step(session, out, step, &recorded) catch |err| {
            try out.print("demo-s2: step {s} FAILED ({s})\n", .{ step.name, @errorName(err) });
            failed += 1;
        };
        try timer.lap(out, step.name);
    }
    try out.print("\n", .{});
    for (0..checks.key_count) |at| {
        const key: checks.Key = @fromBackingInt(@intCast(at));
        const value = recorded.get(key) orelse continue;
        try out.print("demo-s2: RECORDED {s} {d}\n", .{ @tagName(key), value });
    }
    var buffer: [256]u8 = undefined;
    if (checks.verdict(&recorded, &buffer)) |failure| {
        try out.print("demo-s2: the recorded numbers FAILED: {s}\n", .{failure});
        failed += 1;
    }
    if (failed > 0) return error.StepsFailed;
}

/// The rootfs, the script, the tool and the old release's `zbx`, onto the guest.
fn fetch(session: *Session, out: *Io.Writer) !void {
    const port = session.server.port;
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "curl -fsS -o /tmp/rootfs.tar.gz http://10.0.2.2:{d}/rootfs.tar.gz && " ++
            "curl -fsS -o /tmp/s2.sh http://10.0.2.2:{d}/s2/s2.sh && " ++
            "curl -fsS -o /usr/local/bin/s2tool http://10.0.2.2:{d}/s2/tool && " ++
            "curl -fsS -o /home/demo/zbx-old http://10.0.2.2:{d}/zbx-old && " ++
            "chmod 644 /tmp/rootfs.tar.gz /tmp/s2.sh && chmod 755 /usr/local/bin/s2tool && " ++
            "chown demo:demo /home/demo/zbx-old && chmod 755 /home/demo/zbx-old && " ++
            "runuser -u demo -- /home/demo/zbx-old --version",
        .{ port, port, port, port },
    );
    assert(command.len < limits.command_bytes_max);
    const result = try session.run(command, limits.command_timeout_kvm_s);
    try H.show(out, "the rootfs, the script, the tool and the old zbx", result);
    if (result.status != 0) return error.FetchFailed;
}

/// The registry's port and every hash the steps compare against, from the generator alone.
fn write_env(session: *Session, out: *Io.Writer, registry_port: u16) !void {
    const v1 = fixture.expected(.v1);
    const v2 = fixture.expected(.v2);
    assert(!std.mem.eql(u8, &v1.ready, &v2.ready));
    assert(std.mem.eql(u8, &v1.data_c, &v2.data_c));
    const text = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "S2_PORT={d}\nREADY1={s}\nREADY2={s}\nHC={s}\nHE={s}\n",
        .{ registry_port, &v1.ready, &v2.ready, &v1.data_c, &v1.data_e },
    );
    try H.put_file(session, "/tmp/s2.env", text);
    try out.print("demo-s2: expected: ready {s} (v1), ready {s} (v2), c.bin {s}, e.bin {s}\n", .{
        &v1.ready, &v2.ready, &v1.data_c, &v1.data_e,
    });
}

/// From the pushed `lazy:3g`'s index, where chunk `corrupt_chunk` of `/data/c.bin` lies: the
/// registry flips a byte in the middle of its compressed range when step 6 turns the flip on,
/// and counts both images' index ranges apart from chunks.
fn arm_flip(session: *Session, out: *Io.Writer, registry: *Registry) !void {
    const arena = session.scratch_allocator();
    var anchors: [2]index.Anchor = undefined;
    for ([_][]const u8{ "3g", "3g-v2" }, &anchors) |tag, *anchor| {
        const manifest = try arena.alloc(u8, registry_mod.manifest_bytes_max);
        const text = registry.manifest_of("lazy", tag, manifest) orelse return error.NoManifest;
        anchor.* = try index.anchor_of(arena, text) orelse {
            try out.print("demo-s2: lazy:{s} was pushed without a lazy index\n", .{tag});
            return error.NoLazyIndex;
        };
        registry.add_index_range(&anchor.blob, anchor.offset, anchor.offset + anchor.length - 1);
    }
    const anchor = anchors[0];
    const range = try arena.alloc(u8, @intCast(anchor.length + index.range_trailer.len));
    try registry.read_blob(&anchor.blob, anchor.offset, range[0..@intCast(anchor.length)]);
    const inflated = try index.inflate(arena, range, anchor.size);
    const hash = fixture.expected(.v1).corrupt_chunk_hash;
    const chunk = try index.locate(inflated, &hash) orelse {
        try out.print("demo-s2: lazy:3g's index has no chunk of /data/c.bin's hash\n", .{});
        return error.ChunkNotIndexed;
    };
    assert(chunk.length > 0);
    const offset = chunk.offset + chunk.length / 2;
    registry.set_flip(&anchor.blob, offset);
    const object = std.fmt.bytesToHex(chunk.object, .lower);
    const text = try std.fmt.allocPrint(arena, "OBJ={s}\nORD={d}\n", .{ &object, chunk.ordinal });
    try H.put_file(session, "/tmp/s2.flip", text);
    try out.print("demo-s2: the flip is armed in chunk {d} of {s}, at blob offset {d}\n", .{
        chunk.ordinal, &object, offset,
    });
}

const Step = struct {
    name: []const u8,
    title: []const u8,
    timeout_s: u32,
};

/// Generating, importing and pushing two 3 GiB images: minutes; the bound is generous.
const prep: Step = .{
    .name = "prep",
    .title = "generate, push lazy:3g and -v2",
    .timeout_s = 1500,
};

const steps = [_]Step{
    .{ .name = "doctor", .title = "1. zbx doctor: FUSE usable", .timeout_s = 120 },
    .{ .name = "lazy", .title = "2. lazy start of lazy:3g", .timeout_s = 300 },
    .{ .name = "pull", .title = "3. the full pull, for comparison", .timeout_s = 600 },
    .{ .name = "fill", .title = "4. background fill and gc", .timeout_s = 600 },
    .{ .name = "reuse", .title = "5. the local store as a source", .timeout_s = 300 },
    .{ .name = "corrupt", .title = "6. a corrupt chunk", .timeout_s = 300 },
    .{ .name = "netcut", .title = "7. the network cut mid-run", .timeout_s = 300 },
    .{ .name = "refusals", .title = "8. refusals and fallbacks", .timeout_s = 300 },
    .{ .name = "upgrade", .title = "9. upgrade: the release before S2", .timeout_s = 300 },
};

/// One step: the script's function of that name, as root (it runs `zbx` as `demo` itself). It
/// passes when the script says the step is done and no check failed.
fn run_step(session: *Session, out: *Io.Writer, step: Step, recorded: ?*checks.Recorded) !void {
    assert(step.timeout_s > 0);
    const command = try std.fmt.allocPrint(
        session.scratch_allocator(),
        "sh /tmp/s2.sh {s} 2>&1",
        .{step.name},
    );
    assert(command.len < limits.command_bytes_max);
    const result = try session.run(command, step.timeout_s);
    try H.show(out, step.title, result);
    if (recorded) |into| try checks.collect(into, result.output);
    var done_buffer: [64]u8 = undefined;
    const done = try std.fmt.bufPrint(&done_buffer, "s2: {s}: done", .{step.name});
    const finished = std.mem.indexOf(u8, result.output, done) != null;
    const failed = std.mem.indexOf(u8, result.output, ": FAIL (") != null;
    if (result.status != 0 or !finished or failed) return error.StepFailed;
}

/// Run as root, `sh /tmp/s2.sh <step>`: the common part, one function per step, and a dispatch
/// on the argument. `/tmp/s2.env` holds the registry's port and the expected hashes,
/// `/tmp/s2.flip` the object and ordinal of the flipped chunk (both written by the harness).
const s2_script = script_common ++ script_prep ++ script_lazy ++ script_fill ++
    script_corrupt ++ script_netcut ++ script_refusals ++ script_upgrade ++ script_dispatch;

const script_common = "set -u\nU='" ++ H.as_demo ++ "'\n" ++
    \\. /tmp/s2.env
    \\[ -f /tmp/s2.flip ] && . /tmp/s2.flip
    \\Z=/home/demo/zbx
    \\O=/home/demo/zbx-old
    \\T=/usr/local/bin/s2tool
    \\R=localhost:5000
    \\IMG=$R/lazy:3g
    \\IMG2=$R/lazy:3g-v2
    \\H=/home/demo/s2
    \\STEP=$1
    \\FAILED=0
    \\ok() { echo "s2: $STEP: $1: ok"; }
    \\fail() { echo "s2: $STEP: $1: FAIL ($2)"; FAILED=1; }
    \\rec() { echo "s2: recorded $1 $2"; }
    \\ctl() { curl -fsS "http://127.0.0.1:5000/control/$1"; }
    \\now() { date +%s%3N; }
    \\# `with <store> <command...>`: the command as demo, its store under $H/<store>, run from
    \\# that directory: zbx writes zbx.lock in the working directory, which must be demo's.
    \\with() { s=$1; shift; ( cd "$H/$s" && $U XDG_DATA_HOME=$H/$s "$@" ); }
    \\fresh() { rm -rf "$H/$1"; install -d -o demo -g demo "$H/$1"; }
    \\# The word after word $2 in the line $1: `word "$(ctl counter)" served`.
    \\word() { echo "$1" | tr ' ' '\n' | grep -A1 -x "$2" | sed -n 2p; }
    \\# The last diagnostic of file $1 without its `more` and `docs` lines (its code, cause and
    \\# fix), else its last $2 lines (3), on one line.
    \\last() {
    \\  awk -v n="${2:-3}" '{ l[NR] = $0 } /(error|warning)\[ZBX-/ { e = NR }
    \\    END { s = e ? e : NR - n + 1; if (s < 1) s = 1
    \\      for (i = s; i <= NR; i++) if (!e || l[i] !~ /^  (more|docs) /) print l[i] }' "$1" |
    \\    tr '\n' '|' | cut -c1-400
    \\}
    \\show() { sed -n "1,${2:-12}p" "$1" | sed "s/^/s2: $STEP: | /"; }
    \\eio() { grep -Eq 'Input/output error|I/O error' "$1"; }
    \\finish() { [ $FAILED = 0 ] && echo "s2: $STEP: done"; exit $FAILED; }
    \\
;

/// The relay, then each image: Alpine's rootfs plus the fixture, imported into a scratch store
/// and pushed with the guest's own `zbx push`. Then step 1.
const script_prep =
    \\prep() {
    \\  if ! ctl counter >/dev/null 2>&1; then
    \\    setsid $T forward 5000 $S2_PORT </dev/null >/dev/null 2>&1 &
    \\    for i in $(seq 50); do ctl counter >/dev/null 2>&1 && break; sleep 0.2; done
    \\  fi
    \\  ctl counter >/dev/null || { fail "the relay to the registry" "no answer"; finish; }
    \\  rm -rf $H; install -d -o demo -g demo $H $H/tmp
    \\  for v in v1 v2; do
    \\    tag=3g; [ $v = v2 ] && tag=3g-v2
    \\    t0=$(now); fresh src
    \\    with tmp tar -xzf /tmp/rootfs.tar.gz -C $H/src || { fail "unpack" "tar"; finish; }
    \\    with tmp $T gen $H/src $v || { fail "generate $v" "s2tool gen"; finish; }
    \\    D=$(with tmp $Z store import $H/src 2>/tmp/s2-import.err) ||
    \\      { fail "import $v" "$(last /tmp/s2-import.err)"; finish; }
    \\    with tmp $Z push "$D" $R/lazy:$tag > /tmp/s2-push.out 2>&1 ||
    \\      { fail "push lazy:$tag" "$(last /tmp/s2-push.out)"; finish; }
    \\    echo "s2: prep: lazy:$tag ($D) pushed in $(( ($(now) - t0) / 1000 )) s"
    \\  done
    \\  rm -rf $H/src $H/tmp
    \\  echo "s2: prep: registry: $(ctl counter)"; df -h /home | tail -n 1
    \\  finish
    \\}
    \\doctor() {
    \\  $U $Z doctor > /tmp/s2-doctor.out 2>&1
    \\  line=$(grep 'FUSE mounts inside a user namespace' /tmp/s2-doctor.out)
    \\  echo "s2: doctor: $line"
    \\  echo "$line" | grep -qw ok && ok "zbx doctor shows FUSE usable" ||
    \\    fail "zbx doctor shows FUSE usable" "$(last /tmp/s2-doctor.out 6)"
    \\  finish
    \\}
    \\
;

/// Steps 2 and 3. The `ready` line is timed as it arrives, and the registry's counter read at
/// that moment; zbx's exit status travels down the pipe as a last line.
const script_lazy =
    \\lazy() {
    \\  fresh lazy; rm -f /tmp/s2-ready /tmp/s2-at-ready; ctl reset >/dev/null
    \\  t0=$(now)
    \\  { with lazy $Z run --lazy $IMG -- /app/start; echo "exit $?"; } 2>&1 |
    \\  while IFS= read -r l; do
    \\    case "$l" in
    \\      "ready "*) echo "$(now) $l" > /tmp/s2-ready; ctl counter > /tmp/s2-at-ready;;
    \\    esac
    \\    echo "$l"
    \\  done > /tmp/s2-lazy.out
    \\  end=$(ctl counter); show /tmp/s2-lazy.out
    \\  ctl trace | sed 's/^/s2: lazy: trace: /'
    \\  [ -s /tmp/s2-ready ] || { fail "a ready line" "$(last /tmp/s2-lazy.out 5)"; finish; }
    \\  ms=$(( $(cut -d' ' -f1 /tmp/s2-ready) - t0 )); line=$(cut -d' ' -f2- /tmp/s2-ready)
    \\  at=$(word "$(cat /tmp/s2-at-ready)" served)
    \\  rec lazy_ms $ms; rec lazy_bytes_at_ready $at; echo $ms > /tmp/s2-lazy-ms
    \\  [ "$line" = "ready $READY1" ] && ok "the expected ready line" || fail "ready line" "$line"
    \\  grep -qx 'exit 0' /tmp/s2-lazy.out && ok "zbx exits 0" || fail "zbx exits 0" "not 0"
    \\  [ $ms -lt 10000 ] && ok "ready in $ms ms, under 10 s" || fail "under 10 s" "$ms ms"
    \\  [ $at -lt 67108864 ] && ok "$at bytes served by then, under 64 MiB" ||
    \\    fail "under 64 MiB by the ready line" "$at bytes"
    \\  summary=$(grep 'fetched on first read' /tmp/s2-lazy.out | tail -n 1)
    \\  sent=$(echo "$summary" | grep -o 'sent [0-9]* bytes' | awk '{n += $2} END {print n + 0}')
    \\  chunks=$(word "$end" chunks)
    \\  echo "s2: lazy: summary: $summary"; echo "s2: lazy: registry: $end"
    \\  rec lazy_sent_bytes $sent; rec registry_chunk_bytes $chunks
    \\  [ -n "$summary" ] && [ "$sent" = "$chunks" ] && ok "summary and counter agree: $sent" ||
    \\    fail "summary and counter agree" "summary $sent, counter $chunks"
    \\  finish
    \\}
    \\pull() {
    \\  fresh pull; ctl reset >/dev/null
    \\  t0=$(now); with pull $Z pull $IMG > /tmp/s2-pull.out 2>&1; st=$?; ms=$(( $(now) - t0 ))
    \\  echo "s2: pull: registry: $(ctl counter)"; rec pull_ms $ms
    \\  [ $st = 0 ] && ok "zbx pull exits 0" || fail "zbx pull" "$(last /tmp/s2-pull.out)"
    \\  [ $ms -gt 75000 ] && ok "the pull took $ms ms, over 75 s" || fail "over 75 s" "$ms ms"
    \\  l=$(cat /tmp/s2-lazy-ms 2>/dev/null || echo 999999)
    \\  [ $((l * 4)) -lt $ms ] && ok "the lazy start ($l ms) under a quarter of it" ||
    \\    fail "the lazy start under a quarter of the pull" "$l ms against $ms ms"
    \\  finish
    \\}
    \\
;

/// Steps 4 and 5. Step 5's store is step 3's, which holds `lazy:3g` whole.
const script_fill =
    \\pct() {
    \\  with fill $Z --output json ps 2>/dev/null | grep -o '"local_percent":[0-9]*' |
    \\    head -n 1 | cut -d: -f2
    \\}
    \\fill() {
    \\  fresh fill; ctl reset >/dev/null; t0=$(now)
    \\  with fill $Z run -d --lazy --name fill $IMG -- sleep 600 > /tmp/s2-fill.out 2>&1 ||
    \\    { fail "zbx run -d --lazy" "$(last /tmp/s2-fill.out)"; finish; }
    \\  p=$(pct)
    \\  [ -n "$p" ] && [ "$p" -lt 100 ] && ok "ps shows local_percent $p, below 100" ||
    \\    fail "local_percent below 100" "${p:-none}"
    \\  with fill $Z --output json store gc > /tmp/s2-gc.out 2>&1
    \\  echo "s2: fill: gc plan: $(head -c 400 /tmp/s2-gc.out)"
    \\  grep -q '"objects":0,' /tmp/s2-gc.out && grep -q '"partials":0,' /tmp/s2-gc.out &&
    \\    ok "gc plans no removal of objects or chunks" || fail "gc plans nothing" "see above"
    \\  i=0
    \\  while :; do
    \\    p=$(pct); [ "$p" = 100 ] && break
    \\    [ $(( $(now) - t0 )) -gt 300000 ] && break; sleep 2; i=$(( i + 1 ))
    \\    [ $(( i % 15 )) = 0 ] && echo "s2: fill: at $(( $(now) - t0 )) ms: $p%, $(ctl counter)"
    \\  done
    \\  ctl trace > /tmp/s2-tf; { head -n 40 /tmp/s2-tf; echo ...; tail -n 5 /tmp/s2-tf; } |
    \\    sed 's/^/s2: fill: trace: /'
    \\  ms=$(( $(now) - t0 )); rec fill_ms $ms
    \\  [ "$p" = 100 ] && ok "local_percent 100 after $ms ms" || fail "100 in 300 s" "${p:-none}"
    \\  with fill $Z stop fill > /tmp/s2-stop.out 2>&1 || fail "stop" "$(last /tmp/s2-stop.out)"
    \\  with fill $Z store verify > /tmp/s2-verify.out 2>&1 && ok "zbx store verify is clean" ||
    \\    fail "zbx store verify" "$(last /tmp/s2-verify.out)"
    \\  with fill $Z run $IMG -- cat /proc/self/mountinfo > /tmp/s2-mi.out 2>&1; st=$?
    \\  [ $st = 0 ] && grep -q ' / / ' /tmp/s2-mi.out && ! grep -q fuse /tmp/s2-mi.out &&
    \\    ok "a run without --lazy has no FUSE mount" || fail "no FUSE" "$(last /tmp/s2-mi.out)"
    \\  finish
    \\}
    \\reuse() {
    \\  ctl reset >/dev/null
    \\  # The pull store, from a directory of its own: the pull's zbx.lock has no entry for v2
    \\  # (E0522), and a directory without one resolves the name at the registry.
    \\  fresh reuse
    \\  ( cd "$H/reuse" && $U XDG_DATA_HOME=$H/pull $Z run --lazy $IMG2 -- /app/start ) \
    \\    > /tmp/s2-reuse.out 2>&1; st=$?
    \\  c=$(ctl counter); served=$(word "$c" served); show /tmp/s2-reuse.out
    \\  echo "s2: reuse: registry: $c"; rec source_bytes $served
    \\  [ $st = 0 ] && grep -qx "ready $READY2" /tmp/s2-reuse.out &&
    \\    ok "lazy:3g-v2 prints its ready line" || fail "the v2 ready line" "exit $st"
    \\  [ $served -lt 20971520 ] && ok "$served bytes from the registry, under 20 MiB" ||
    \\    fail "under 20 MiB" "$served bytes"
    \\  finish
    \\}
    \\
;

/// Step 6: the flip on for the first read, off for the second. Alpine's `sha256sum` (musl)
/// says `I/O error` where glibc says `Input/output error`; either is EIO.
const script_corrupt =
    \\corrupt() {
    \\  [ -n "${OBJ:-}" ] || { fail "the flip" "not armed"; finish; }
    \\  fresh c; ctl flip-on >/dev/null
    \\  with c $Z run --lazy $IMG -- sha256sum /data/c.bin > /tmp/s2-c1.out 2>&1; st=$?
    \\  ctl flip-off >/dev/null; show /tmp/s2-c1.out 30
    \\  [ $st != 0 ] && ok "exits $st" || fail "exits non-zero" "0"
    \\  eio /tmp/s2-c1.out && ok "sha256sum sees EIO" || fail "EIO" "$(last /tmp/s2-c1.out)"
    \\  w=$(grep -n W1202 /tmp/s2-c1.out | head -n 1 | cut -d: -f1)
    \\  e=$(grep -n E1203 /tmp/s2-c1.out | head -n 1 | cut -d: -f1)
    \\  [ -n "$w" ] && [ -n "$e" ] && [ "$w" -lt "$e" ] && ok "W1202, then E1203" ||
    \\    fail "W1202, then E1203" "lines ${w:-none} and ${e:-none}"
    \\  grep -A8 W1202 /tmp/s2-c1.out | grep -q "$OBJ" &&
    \\    grep -A8 W1202 /tmp/s2-c1.out | grep -q "match chunk $ORD's hash" &&
    \\    ok "W1202 names chunk $ORD of the object" || fail "W1202 names the chunk" "see above"
    \\  [ ! -e $H/c/zbx/store/partial/$OBJ/$ORD ] && ok "no partial chunk $ORD in the store" ||
    \\    fail "no partial chunk" "$H/c/zbx/store/partial/$OBJ/$ORD exists"
    \\  with c $Z run --lazy $IMG -- sha256sum /data/c.bin > /tmp/s2-c2.out 2>&1
    \\  grep -q "^$HC " /tmp/s2-c2.out && ok "honest again: the expected hash" ||
    \\    fail "the expected hash" "$(last /tmp/s2-c2.out)"
    \\  finish
    \\}
    \\
;

/// Step 7. The registry goes down right after the first read, before the fill (in the index's
/// order) reaches `/data/e.bin`; the weights' tail is filled last.
const script_netcut =
    \\netcut() {
    \\  fresh n; ctl up >/dev/null; ctl reset >/dev/null
    \\  with n $Z run -d --lazy --name cut $IMG -- sleep 600 > /tmp/s2-n.out 2>&1 ||
    \\    { fail "zbx run -d --lazy" "$(last /tmp/s2-n.out)"; finish; }
    \\  with n $Z exec cut -- cat /app/config | grep -qx 'name=lazy-3g' &&
    \\    ok "cat /app/config works" || fail "cat /app/config" "no config"
    \\  ctl down >/dev/null; echo "s2: netcut: down after $(ctl counter)"
    \\  t0=$(now); with n $Z exec cut -- sha256sum /data/e.bin > /tmp/s2-e1.out 2>&1; st=$?
    \\  ms=$(( $(now) - t0 )); rec cut_first_ms $ms
    \\  [ $st != 0 ] && eio /tmp/s2-e1.out && [ $ms -lt 35000 ] &&
    \\    ok "/data/e.bin fails with EIO in $ms ms" || fail "EIO in 35 s" "$ms ms, exit $st"
    \\  with n $Z logs cut > /tmp/s2-logs.out 2>&1
    \\  grep -q E1203 /tmp/s2-logs.out && ok "zbx logs shows E1203" || fail "E1203 in logs" "none"
    \\  t0=$(now); with n $Z exec cut -- sha256sum /models/weights.bin > /tmp/s2-e3.out 2>&1
    \\  st=$?; ms=$(( $(now) - t0 )); rec cut_second_ms $ms
    \\  [ $st != 0 ] && eio /tmp/s2-e3.out && [ $ms -lt 7000 ] &&
    \\    ok "a second missing file fails with EIO in $ms ms" ||
    \\    fail "the second read fails in 7 s" "$ms ms, exit $st"
    \\  with n $Z exec cut -- cat /app/config | grep -qx 'name=lazy-3g' &&
    \\    ok "cat /app/config still works" || fail "cat /app/config while down" "no config"
    \\  with n $Z exec cut -- true && ok "the container still runs" || fail "still runs" "exec"
    \\  ctl up >/dev/null
    \\  t0=$(now); with n $Z exec cut -- sha256sum /data/e.bin > /tmp/s2-e2.out 2>&1
    \\  ms=$(( $(now) - t0 )); rec cut_recover_ms $ms
    \\  grep -q "^$HE " /tmp/s2-e2.out && [ $ms -lt 10000 ] &&
    \\    ok "back up: the expected hash in $ms ms" ||
    \\    fail "the hash in 10 s" "$ms ms: $(last /tmp/s2-e2.out)"
    \\  with n $Z stop cut > /dev/null 2>&1
    \\  finish
    \\}
    \\
;

/// Step 8. The second user's `/dev/fuse` is denied by a group change (demo's own access stays),
/// put back as it was found.
const script_refusals =
    \\refusals() {
    \\  fresh r; install -d -o demo -g demo $H/r/root
    \\  with r ZBX_REGISTRY_MIRRORS=mirror.gcr.io $Z run --lazy alpine:3.20 -- true \
    \\    > /tmp/s2-r1.out 2>&1; st=$?; grep -m 1 W1201 /tmp/s2-r1.out
    \\  [ $st = 0 ] && grep -q W1201 /tmp/s2-r1.out && ok "no index: W1201, then it runs" ||
    \\    fail "W1201 and a run" "exit $st: $(last /tmp/s2-r1.out)"
    \\  with r $Z run --lazy --rootfs $H/r/root -- true > /tmp/s2-r2.out 2>&1; st=$?
    \\  grep -m 1 E1208 /tmp/s2-r2.out
    \\  [ $st = 125 ] && grep -q E1208 /tmp/s2-r2.out && ok "--lazy --rootfs: E1208" ||
    \\    fail "E1208" "exit $st: $(last /tmp/s2-r2.out)"
    \\  id s2other >/dev/null 2>&1 || useradd -m -s /bin/sh s2other
    \\  loginctl enable-linger s2other; ou=$(id -u s2other)
    \\  for i in $(seq 50); do [ -d /run/user/$ou ] && break; sleep 0.2; done
    \\  install -m 755 $Z /usr/local/bin/zbx-s2
    \\  mode=$(stat -c %a /dev/fuse); group=$(stat -c %G /dev/fuse)
    \\  chgrp demo /dev/fuse; chmod 660 /dev/fuse
    \\  # zbx makes the store under XDG_DATA_HOME, which must exist; it runs from there.
    \\  rm -rf /home/s2other/d; install -d -o s2other -g s2other /home/s2other/d
    \\  ( cd /home/s2other/d && runuser -u s2other -- env HOME=/home/s2other \
    \\    XDG_RUNTIME_DIR=/run/user/$ou XDG_DATA_HOME=/home/s2other/d \
    \\    /usr/local/bin/zbx-s2 run --lazy $IMG -- true ) > /tmp/s2-r3.out 2>&1; st=$?
    \\  chgrp "$group" /dev/fuse; chmod "$mode" /dev/fuse; grep -m 1 E1201 /tmp/s2-r3.out
    \\  [ $st != 0 ] && grep -q E1201 /tmp/s2-r3.out && ok "/dev/fuse denied: E1201" ||
    \\    fail "E1201" "exit $st: $(last /tmp/s2-r3.out)"
    \\  finish
    \\}
    \\
;

/// Step 9, in one store: the old release's run is listed and stopped by this `zbx`. This `zbx`'s
/// lazy run writes a record of a version the old release does not know (11): the old `zbx ps`
/// leaves it out without a word (v0.5.1 warns W0203 only when it prunes), and the old `zbx stop`
/// refuses it with E0402, "from a newer zbx", the old release's newer-version refusal.
const script_upgrade =
    \\upgrade() {
    \\  fresh u; install -d -o demo -g demo $H/u/root
    \\  $U tar -xzf /tmp/rootfs.tar.gz -C $H/u/root || { fail "unpack" "tar"; finish; }
    \\  echo "s2: upgrade: the old zbx is $($U $O --version 2>&1 | head -n 1)"
    \\  D=$(with u $O store import $H/u/root 2>/tmp/s2-u.err) ||
    \\    { fail "the old zbx imports" "$(last /tmp/s2-u.err)"; finish; }
    \\  with u $O run -d --name old1 $D -- sleep 600 > /tmp/s2-u1.out 2>&1 ||
    \\    { fail "the old zbx runs -d" "$(last /tmp/s2-u1.out)"; finish; }
    \\  with u $Z ps > /tmp/s2-u2.out 2>&1
    \\  grep -qw old1 /tmp/s2-u2.out && ok "this zbx lists the old release's run" ||
    \\    fail "ps lists old1" "$(last /tmp/s2-u2.out)"
    \\  with u $Z stop old1 > /tmp/s2-u3.out 2>&1 && ok "this zbx stops it" ||
    \\    fail "stop old1" "$(last /tmp/s2-u3.out)"
    \\  with u $Z run -d --lazy --name lz $IMG -- sleep 600 > /tmp/s2-u4.out 2>&1 ||
    \\    { fail "a lazy run in the same store" "$(last /tmp/s2-u4.out)"; finish; }
    \\  with u $Z ps > /tmp/s2-u5.out 2>&1
    \\  grep -w lz /tmp/s2-u5.out | grep -qw running && ok "this zbx ps shows lz running" ||
    \\    fail "lz runs" "$(last /tmp/s2-u5.out 4)"
    \\  with u $O ps --all > /tmp/s2-u6.out 2>&1; st=$?
    \\  [ $st = 0 ] && grep -q '^NAME' /tmp/s2-u6.out && ! grep -qw lz /tmp/s2-u6.out &&
    \\    ok "the old zbx ps --all leaves the lazy record out" ||
    \\    fail "the old ps leaves lz out" "exit $st: $(last /tmp/s2-u6.out 4)"
    \\  with u $O stop lz > /tmp/s2-u7.out 2>&1; st=$?; grep -m 1 E0402 /tmp/s2-u7.out
    \\  [ $st != 0 ] && grep -q E0402 /tmp/s2-u7.out && grep -q 'newer zbx' /tmp/s2-u7.out &&
    \\    ok "the old zbx stop lz: E0402, a record from a newer zbx" ||
    \\    fail "E0402 from a newer zbx" "exit $st: $(last /tmp/s2-u7.out)"
    \\  with u $Z stop lz > /tmp/s2-u8.out 2>&1 && ok "this zbx stops lz" ||
    \\    fail "stop lz" "$(last /tmp/s2-u8.out)"
    \\  finish
    \\}
    \\
;

const script_dispatch =
    \\case "$STEP" in
    \\  prep|doctor|lazy|pull|fill|reuse|corrupt|netcut|refusals|upgrade) $STEP;;
    \\  *) echo "s2: no step $STEP"; exit 2;;
    \\esac
    \\
;

comptime {
    @setEvalBranchQuota(1_000_000);
    for (steps ++ [_]Step{prep}) |step| {
        assert(std.mem.indexOf(u8, s2_script, step.name ++ "() {") != null);
        assert(std.mem.indexOf(u8, script_dispatch, step.name) != null);
    }
}

test {
    _ = @import("checks_s2.zig");
    _ = @import("fixture_s2.zig");
    _ = @import("http_s2.zig");
    _ = @import("index_s2.zig");
    _ = @import("registry_disk_s2.zig");
    _ = @import("tool_s2.zig");
}
