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
//! The VERIFY part (slice 5): a tree is signed, then `zbx verify` runs with no network at all (a
//! network namespace with nothing in it), passes; with the record deleted it is refused (E0908);
//! the exported bundle is imported again and it passes.
//!
//! This is not the M8 demo, which needs slices 12 to 14. `zig build demo-m8`, or `-Daccel=tcg`.

const std = @import("std");
const Io = std.Io;
const accept = @import("accept_m4.zig");
const agent = @import("agent_m8.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m7.zig");
const image = @import("image.zig");
const limits = @import("limits.zig");
const old_release = @import("old_release.zon");
const old_wrapper = @import("upgrade_m5.zig");
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const spec_m6b = @import("spec_m6b.zig");
const trust = @import("trust_m8.zig");
const upgrade = @import("upgrade_m8.zig");

const script_path = "/root/m8-export.sh";
const push_path = "/root/m8-push.sh";
const marker = "m8-export: identical";
const push_marker = "m8-push: ok";
const timeout_s: u32 = 300;

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

/// The VERIFY part's script, run as root, which drops to `demo` (and, for `verify`, into a
/// network namespace with no link) with a store and config directory of their own.
const verify_script = verify_body ++ "\necho '" ++ verify_marker ++ "'\n";
const verify_script_path = "/tmp/m8-verify.sh";
const verify_marker = "m8-verify: offline, refused, imported";

const verify_body =
    \\set -eu
    \\trap 'cat /tmp/err-v* 2>/dev/null' EXIT
    \\f() { echo "FAIL: $*"; exit 1; }
    \\E="env HOME=/home/demo XDG_DATA_HOME=/home/demo/v XDG_CONFIG_HOME=/home/demo/vc"
    \\Z=/usr/local/bin/zbx
    \\z() { runuser -u demo -- $E $Z "$@"; }
    \\n() { unshare -n runuser -u demo -- $E $Z "$@"; }
    \\rm -rf /home/demo/v /home/demo/vc
    \\mkdir -p /home/demo/v /home/demo/vc/zbx
    \\chown -R demo /home/demo/v /home/demo/vc
    \\d=$(z store import /srv/m8/tree 2>/tmp/err-v1)
    \\z key new ci --no-passphrase 2>>/tmp/err-v1 || f key
    \\z sign "$d" 2>>/tmp/err-v1 || f sign
    \\n verify "$d" --key ci >/tmp/v-out 2>/tmp/err-v2 || f "verify with no link"
    \\grep -q '3 tree: ok' /tmp/v-out || f "the tree link"
    \\z trust export "$d" >/tmp/v-bundle 2>/tmp/err-v3 || f export
    \\find /home/demo/v -path '*/trust/signatures/*' -type f -delete
    \\if n verify "$d" --key ci >/dev/null 2>/tmp/err-v4; then f "verified without a record"; fi
    \\grep -q E0908 /tmp/err-v4 || f "no E0908"
    \\z trust import /tmp/v-bundle >/dev/null 2>/tmp/err-v5 || f import
    \\n verify "$d" --key ci >/dev/null 2>/tmp/err-v6 || f "verify after the import"
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
    const accel = harness.choose_accel(options.accel, H.kvm_usable(init.io)) catch |err| {
        if (err == error.NoKvm) {
            try out.print("demo-m8: /dev/kvm is not usable here; add -Daccel=tcg\n", .{});
        }
        return err;
    };
    const binary = try H.check_binaries(init, out, options);
    if (options.old_zbx.len == 0) {
        try out.print("demo-m8: --old-zbx is missing: the upgrade test needs {s}\n", .{
            old_release.m8_tag,
        });
        return error.MissingBinary;
    }
    const arena = init.arena.allocator();
    const limit: Io.Limit = .limited(limits.elf_bytes_max);
    const old_binary = try Io.Dir.cwd().readFileAlloc(init.io, options.old_zbx, arena, limit);
    const base = try image.ensure(init, options.cache_dir, out);
    var ca_file: []const u8 = "";
    if (options.ca_file.len > 0) {
        const body_limit: Io.Limit = .limited(limits.http_body_bytes_max);
        ca_file = try Io.Dir.cwd().readFileAlloc(init.io, options.ca_file, arena, body_limit);
    }
    const format = "{s}/overlay-demo-m8.qcow2";
    const overlay = try std.fmt.allocPrint(arena, format, .{options.cache_dir});
    if (!options.reuse_overlay) try image.make_overlay(init, base, overlay);
    var session: Session = undefined;
    try session_mod.start(&session, init, out, overlay, accel, .{
        .binary = binary,
        .old_binary = old_binary,
        .ca_file = ca_file,
    });
    defer session.deinit();
    var timer = H.Timer.start();
    try H.provision(&session, out, &timer, options.reuse_overlay);
    try H.install_binary(&session, out, &timer);
    const with_ca = ca_file.len > 0;
    try accept.install_old(&session, out);
    try common.write_wrappers(&session, out, with_ca);
    try old_wrapper.write_old_wrapper(&session, out, with_ca);
    inline for (parts) |part| try part(&session, out, &timer);
    try export_check(&session, out);
    try verify_check(&session, out);
    try session.shutdown();
}

/// The parts, in order. A part is `fn (*Session, *Io.Writer, *H.Timer) !void`.
const parts = [_]*const fn (*Session, *Io.Writer, *H.Timer) anyerror!void{
    upgrade.step_upgrade,
    spec_m6b.step_spec,
    hello.step_first,
    trust.step_trust,
    agent.run_agent,
};

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

fn verify_check(session: *Session, out: *Io.Writer) !void {
    try session.put_file(verify_script_path, verify_script);
    const result = try session.run("sh " ++ verify_script_path ++ " 2>&1", timeout_s);
    try H.show(out, "verify offline, with the link down", result);
    if (result.status != 0) return error.VerifyCheckFailed;
    if (std.mem.indexOf(u8, result.output, verify_marker) == null) return error.VerifyCheckFailed;
}

test "the verify script ends with its marker and fits a put_file" {
    try std.testing.expect(std.mem.endsWith(u8, verify_script, verify_marker ++ "'\n"));
    try std.testing.expect(verify_script.len <= @import("zigbox_vm").limits.put_file_bytes_max);
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

test {
    // The files this demo is made of carry their own unit tests; a test root reaches them here.
    _ = @import("checks_m8.zig");
    _ = @import("trust_m8.zig");
    _ = @import("upgrade_m8.zig");
    _ = @import("agent_m8.zig");
}
