//! The M8 slice 10 and 11 checks and the SIGN part (slice 3), run in a real Ubuntu 24.04 VM.
//!
//! Slice 10 (`zbx store export --oci`): one tree is imported and exported as two different users,
//! and the two layouts must be byte-identical. Every blob must also hash to its own file name,
//! and the layer must read back with the guest's own `tar` and `gzip`, which are not ours.
//!
//! Slice 11 (`zbx push`, no credentials): a real registry (the distribution registry, from the
//! guest's `docker-registry` package, on `localhost:5000`, so not our test registry) takes the
//! tree as `localhost:5000/m8/tree:1`; the digest `push` prints is the export's manifest digest
//! and the registry's own `Docker-Content-Digest`; a second push says `exists` for every blob and
//! sends nothing; a second user pulls it and gets the same tree. The brief names the `registry:2`
//! image run by `zbx run`; the guest has no container runtime to pull it with before this check
//! trusts `zbx run`, so the package stands in (docs/demos/m8.md).
//!
//! The SIGN part (slice 3): as `demo`, with a store and a config directory of its own, a key
//! sealed by a passphrase file signs a pulled `alpine`; under `require_signature` the signed
//! tree runs, an unsigned one is refused (E0905), and a changed object of the signed tree is
//! refused (E0907) until it is put back.
//!
//! This is not the M8 demo, which needs slices 12 to 14. `zig build demo-m8`, or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const harness = @import("harness.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

const script_path = "/root/m8-export.sh";
const push_path = "/root/m8-push.sh";
const marker = "m8-export: identical";
const push_marker = "m8-push: ok";
const timeout_s: u32 = 300;
const sign_script_path = "/tmp/m8-sign.sh";
const sign_marker = "m8-sign: refused, then run again";
const sign_timeout_s: u32 = 900;

/// The whole check, as one script: it prints `marker` as its last line when every step held.
const script = body ++ "\necho '" ++ marker ++ "'\n";

/// Slice 11: the real registry, a push, a push again, and a pull by a second user.
const push_script = push_body ++ "\necho '" ++ push_marker ++ "'\n";

const push_body =
    \\set -eu
    \\trap 'cat /tmp/err-* 2>/dev/null' EXIT
    \\d=$(cat /tmp/tree)
    \\m=$(cat /tmp/manifest)
    \\export DEBIAN_FRONTEND=noninteractive
    \\apt-get update -qq >/tmp/err-apt 2>&1
    \\apt-get install -y -qq docker-registry >>/tmp/err-apt 2>&1
    \\{ echo 'version: 0.1'; echo 'storage: {filesystem: {rootdirectory: /var/lib/docker-registry}}'
    \\  echo 'http: {addr: ":5000"}'; } >/etc/docker/registry/config.yml
    \\systemctl restart docker-registry >/tmp/err-start 2>&1
    \\i=0
    \\until curl -fs http://localhost:5000/v2/ >/dev/null; do
    \\  i=$((i + 1))
    \\  [ "$i" -lt 30 ] || { echo 'the registry did not start'
    \\    systemctl status docker-registry --no-pager | tail -5; exit 1; }
    \\  sleep 1
    \\done
    \\zd() { u=$1; shift; runuser -u "$u" -- env HOME=/home/$u /usr/local/bin/zbx "$@"; }
    \\ref=localhost:5000/m8/tree:1
    \\p1=$(zd demo push "$d" $ref 2>/tmp/err-p1)
    \\[ "$p1" = "$m" ] || { echo "push printed $p1"; exit 1; }
    \\j=$(zd demo --output json push "$d" $ref 2>/tmp/err-p2)
    \\n=$(echo "$j" | grep -o '"outcome":"exists"' | wc -l)
    \\[ "$n" = 2 ] || { echo 'not all exist'; exit 1; }
    \\c=$(curl -fsI -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    \\  http://localhost:5000/v2/m8/tree/manifests/1 | tr -d '\r' |
    \\  sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
    \\[ "$c" = "$m" ] || { echo "the registry has $c"; exit 1; }
    \\mkdir /tmp/p2
    \\chown demo2 /tmp/p2
    \\cd /tmp/p2
    \\zd demo2 --output json pull $ref >/tmp/pull-demo2 2>/tmp/err-pull
    \\grep -q "\"tree\":\"$d\"" /tmp/pull-demo2 || { echo "pulled another tree"; exit 1; }
    \\true
;

const body =
    \\set -eu
    \\trap 'cat /tmp/err-* 2>/dev/null' EXIT
    \\useradd -m -s /bin/sh demo2
    \\mkdir -p /srv/m8/tree/sub /srv/m8/tree/empty
    \\printf 'hello\n' > /srv/m8/tree/sub/a.txt
    \\printf '#!/bin/sh\n' > /srv/m8/tree/run.sh
    \\chmod 755 /srv/m8/tree/run.sh
    \\ln -s sub/a.txt /srv/m8/tree/link
    \\chmod -R a+rX /srv/m8
    \\for u in demo demo2; do
    \\  z="runuser -u $u -- env HOME=/home/$u /usr/local/bin/zbx"
    \\  d=$($z store import /srv/m8/tree 2>/tmp/err-i$u)
    \\  m=$($z store export --oci "$d" /tmp/out-$u 2>/tmp/err-e$u)
    \\  echo "$u: tree $d manifest $m"
    \\  echo "$m" > /tmp/manifest-$u
    \\done
    \\diff -r /tmp/out-demo /tmp/out-demo2
    \\cmp /tmp/manifest-demo /tmp/manifest-demo2
    \\cd /tmp/out-demo
    \\for f in blobs/sha256/*; do
    \\  h=$(sha256sum "$f" | cut -d' ' -f1)
    \\  [ "$h" = "$(basename "$f")" ] || { echo "bad blob $f"; exit 1; }
    \\done
    \\grep -q imageLayoutVersion oci-layout
    \\for f in blobs/sha256/*; do
    \\  if gzip -t "$f" 2>/dev/null; then tar -tvzf "$f"; fi
    \\done
    \\echo "$d" > /tmp/tree
    \\echo "$m" > /tmp/manifest
    \\true
;

/// The SIGN part's script, run as `demo` with `XDG_DATA_HOME` and `XDG_CONFIG_HOME` of its own,
/// so that the other parts' store and policy are not touched. It prints `sign_marker` last.
const sign_script = sign_body ++ "\necho '" ++ sign_marker ++ "'\n";

const sign_body =
    \\export ZBX_REGISTRY_MIRRORS=mirror.gcr.io XDG_DATA_HOME=$HOME/d XDG_CONFIG_HOME=$HOME/c
    \\Z=/usr/local/bin/zbx
    \\cd
    \\f() { echo "FAIL: $*"; exit 1; }
    \\rm -rf $XDG_DATA_HOME $XDG_CONFIG_HOME; mkdir -p $XDG_DATA_HOME $XDG_CONFIG_HOME/zbx
    \\echo 'correct horse' > ~/pw; chmod 600 ~/pw
    \\$Z key new demo --passphrase-file ~/pw || f key
    \\T=$($Z --output json pull alpine:3.20 | sed -n 's/.*"tree":"\(b3:[0-9a-f]*\)".*/\1/p')
    \\P=$($Z --output json key show demo | sed -n 's/.*"public":"\([^"]*\)".*/\1/p')
    \\[ -n "$T" ] && [ -n "$P" ] || f "tree or key"
    \\Q=$XDG_CONFIG_HOME/zbx/policy.zon
    \\echo ".{ .version = 1, .keys = .{ .{ .name = \"demo\", .public = \"$P\" } }," > $Q
    \\echo ".require_signature = true }" >> $Q
    \\$Z run $T -- true 2> /tmp/e1; [ $? = 125 ] || f "unsigned ran"
    \\grep -m1 'E0905' /tmp/e1 || f "no E0905"
    \\$Z sign $T --passphrase-file ~/pw || f sign
    \\$Z run $T -- true || f "signed did not run"
    \\O=$(find $XDG_DATA_HOME -path '*/objects/*' -type f ! -name '*.chunks' -size +2k | head -n 1)
    \\M=$(stat -c %a $O); chmod u+w $O; printf x >> $O
    \\$Z run $T -- true 2> /tmp/e2; [ $? = 125 ] || f "changed ran"
    \\grep -m1 'E0907' /tmp/e2 || f "no E0907"
    \\truncate -s -1 $O; chmod $M $O; $Z run $T -- true || f "put back"
    \\rm -rf $XDG_CONFIG_HOME
    \\true
;

pub fn main(init: std.process.Init) !u8 {
    harness.demo_name = "demo-m8";
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);
    const out = &file_writer.interface;
    defer out.flush() catch {};
    const options = H.parse_options(init) catch |err| {
        try out.print("demo-m8: bad arguments ({s})\n", .{@errorName(err)});
        return 2;
    };
    const started = session_mod.now_ms();
    demo(init, out, options) catch |err| {
        if (err == error.NoKvm) return 1;
        try out.print("\ndemo-m8: FAILED ({s})\n", .{@errorName(err)});
        return 1;
    };
    try out.print("\ndemo-m8: PASSED in {d} s\n", .{(session_mod.now_ms() - started) / 1000});
    return 0;
}

fn demo(init: std.process.Init, out: *Io.Writer, options: H.Options) !void {
    const image = @import("image.zig");
    const accel = harness.choose_accel(options.accel, H.kvm_usable(init.io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-m8: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
        }
        return err;
    };
    const binary = try H.check_binaries(init, out, options);
    const base = try image.ensure(init, options.cache_dir, out);
    const arena = init.arena.allocator();
    const format = "{s}/overlay-demo-m8.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    var session: Session = undefined;
    try session_mod.start(&session, init, out, overlay, accel, .{ .binary = binary });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try export_check(&session, out);
    try sign_check(&session, out);
    try session.shutdown();
}

fn export_check(session: *Session, out: *Io.Writer) !void {
    const copied = try session.copy_in(.{
        .route = "/zbx",
        .guest_path = "/usr/local/bin/zbx",
        .mode = "755",
    });
    try H.show(out, "install zbx", copied);
    if (copied.status != 0) return error.InstallFailed;
    try session.put_file(push_path, push_script);
    try session.put_file(script_path, script);
    const result = try session.run("sh " ++ script_path ++ " 2>&1", timeout_s);
    try H.show(out, "export as two users", result);
    if (result.status != 0) return error.CheckFailed;
    if (std.mem.indexOf(u8, result.output, marker) == null) return error.CheckFailed;
    const pushed = try session.run("sh " ++ push_path ++ " 2>&1", timeout_s);
    try H.show(out, "push to a real registry, push again, pull", pushed);
    if (pushed.status != 0) return error.CheckFailed;
    if (std.mem.indexOf(u8, pushed.output, push_marker) == null) return error.CheckFailed;
}

fn sign_check(session: *Session, out: *Io.Writer) !void {
    try session.put_file(sign_script_path, sign_script);
    const command = H.as_demo ++ "sh " ++ sign_script_path ++ " 2>&1";
    const result = try session.run(command, sign_timeout_s);
    try H.show(out, "sign, run under a policy, change an object", result);
    if (result.status != 0) return error.SignCheckFailed;
    if (std.mem.indexOf(u8, result.output, sign_marker) == null) return error.SignCheckFailed;
}

test "the sign script ends with its marker and fits a put_file" {
    try std.testing.expect(std.mem.endsWith(u8, sign_script, sign_marker ++ "'\n"));
    try std.testing.expect(sign_script.len <= @import("zigbox_vm").limits.put_file_bytes_max);
}

test "the scripts end with the markers the check looks for" {
    try std.testing.expect(std.mem.endsWith(u8, script, marker ++ "'\n"));
    try std.testing.expect(std.mem.endsWith(u8, push_script, push_marker ++ "'\n"));
}

test "the scripts fit a put_file" {
    const limit = @import("zigbox_vm").limits.put_file_bytes_max;
    try std.testing.expect(script.len <= limit);
    try std.testing.expect(push_script.len <= limit);
}
