//! The M8 slice 10 check (`zbx store export --oci`), run in a real Ubuntu 24.04 VM: one tree is
//! imported and exported as two different users, and the two layouts must be byte-identical.
//! Every blob must also hash to its own file name, and the layer must read back with the guest's
//! own `tar` and `gzip`, which are not ours. This is the slice's check, not the M8 demo, which
//! needs the registry upload (slice 11). `zig build demo-m8`, or `-Daccel=tcg`.
//!
//! The SIGN part (slice 3): as `demo`, with a store and a config directory of its own, a key
//! sealed by a passphrase file signs a pulled `alpine`; under `require_signature` the signed
//! tree runs, an unsigned one is refused (E0905), and a changed object of the signed tree is
//! refused (E0907) until it is put back.

const std = @import("std");
const Io = std.Io;
const harness = @import("harness.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;

const script_path = "/root/m8-export.sh";
const marker = "m8-export: identical";
const timeout_s: u32 = 300;
const sign_script_path = "/tmp/m8-sign.sh";
const sign_marker = "m8-sign: refused, then run again";
const sign_timeout_s: u32 = 900;

/// The whole check, as one script: it prints `marker` as its last line when every step held.
const script = body ++ "\necho '" ++ marker ++ "'\n";

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
    \\true
;

/// The SIGN part's script, run as `demo` with `XDG_DATA_HOME` and `XDG_CONFIG_HOME` of its own,
/// so that the other parts' store and policy are not touched. It prints `sign_marker` last.
const sign_script = sign_body ++ "\necho '" ++ sign_marker ++ "'\n";

const sign_body =
    \\set -u
    \\export ZBX_REGISTRY_MIRRORS=mirror.gcr.io
    \\export XDG_DATA_HOME=/home/demo/m8-data XDG_CONFIG_HOME=/home/demo/m8-config
    \\Z=/usr/local/bin/zbx
    \\fail() { echo "FAIL: $*"; exit 1; }
    \\rm -rf "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"
    \\mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"
    \\printf 'correct horse battery\n' > /home/demo/m8-pass
    \\chmod 600 /home/demo/m8-pass
    \\$Z key new demo --passphrase-file /home/demo/m8-pass || fail "key new"
    \\T=$($Z --output json pull alpine:3.20 | sed -n 's/.*"tree":"\(b3:[0-9a-f]*\)".*/\1/p' | head -n 1)
    \\[ -n "$T" ] || fail "no tree digest from pull"
    \\echo "tree $T"
    \\P=$($Z --output json key show demo | sed -n 's/.*"public":"\([^"]*\)".*/\1/p')
    \\[ -n "$P" ] || fail "no public key"
    \\printf '.{ .version = 1, .keys = .{ .{ .name = "demo", .public = "%s" } }, .require_signature = true }\n' "$P" \
    \\  > "$XDG_CONFIG_HOME/zbx/policy.zon"
    \\$Z run "$T" -- true 2> /tmp/m8-unsigned.err
    \\[ $? -eq 125 ] || fail "an unsigned tree ran under require_signature"
    \\head -n 1 /tmp/m8-unsigned.err
    \\grep -q '^error\[ZBX-E0905\]' /tmp/m8-unsigned.err || fail "no E0905 for the unsigned tree"
    \\$Z sign "$T" --key demo --passphrase-file /home/demo/m8-pass || fail "sign"
    \\$Z run "$T" -- true || fail "the signed tree did not run"
    \\O=$(find "$XDG_DATA_HOME/zbx/store/objects" -type f ! -name '*.chunks' -size +2k | head -n 1)
    \\[ -n "$O" ] || fail "no object to change"
    \\M=$(stat -c %a "$O")
    \\chmod u+w "$O" && printf x >> "$O" || fail "could not change $O"
    \\$Z run "$T" -- true 2> /tmp/m8-tampered.err
    \\[ $? -eq 125 ] || fail "a changed object still ran"
    \\head -n 1 /tmp/m8-tampered.err
    \\grep -q '^error\[ZBX-E0907\]' /tmp/m8-tampered.err || fail "no E0907 for the changed object"
    \\truncate -s -1 "$O" && chmod "$M" "$O" || fail "could not put the object back"
    \\$Z run "$T" -- true || fail "the object was put back and still did not run"
    \\rm -rf "$XDG_CONFIG_HOME"
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
    try session.put_file(script_path, script);
    const result = try session.run("sh " ++ script_path ++ " 2>&1", timeout_s);
    try H.show(out, "export as two users", result);
    if (result.status != 0) return error.ExportCheckFailed;
    if (std.mem.indexOf(u8, result.output, marker) == null) return error.ExportCheckFailed;
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

test "the script ends with the marker the check looks for" {
    try std.testing.expect(std.mem.endsWith(u8, script, marker ++ "'\n"));
}

test "the script fits a put_file" {
    try std.testing.expect(script.len <= @import("zigbox_vm").limits.put_file_bytes_max);
}
