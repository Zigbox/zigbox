//! The ACCEPT checks of the M8 demo that the single-command TRUST8 steps do not make
//! (docs/briefs/M8-trust.md, "ACCEPT also checks"), run as shell scripts in the guest, as root,
//! each command as the ordinary user:
//!
//!   - A1/A2, in a store and config directory of their own (`~/a`, `~/ac`): a signature survives
//!     `store rm`, `store gc` and a re-pull; `require_provenance` refuses a tree-only signature
//!     (E0906); `policy check` agrees with `run`; a malformed policy is E0904 with its line and
//!     column; `trust prune` lists a real orphan and `--apply` removes it, after which the
//!     image is refused again (E0905).
//!   - B1/B2, in the demo user's own store, on the signed hello result TRUST8 left: `registry:2`
//!     is run by `zbx run`, the result is pushed, a second user imports the exported trust,
//!     pulls the image and runs it under `require_signature` and `require_provenance`, which
//!     holds only through the derived binding.
//!
//! A script prints its marker as its last line; the part fails unless it did and exited 0.

const std = @import("std");
const Io = std.Io;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const limits = @import("zigbox_vm").limits;
const session_mod = @import("session.zig");

const Session = session_mod.Session;
const H = harness;
const step = "ACCEPT8";
const timeout_s: u32 = 600;
pub const digest_file = "/tmp/m8-digest";

const lib_path = "/tmp/m8a-lib.sh";
const scripts = [_]Script{
    script("1", a1),
    script("2", a2),
    script("3", b1),
    script("4", b2),
};

const Script = struct { path: []const u8, body: []const u8, marker: []const u8 };

fn script(comptime name: []const u8, comptime body: []const u8) Script {
    const marker = "m8-accept-" ++ name ++ ": ok";
    return .{
        .path = "/tmp/m8a-" ++ name ++ ".sh",
        .body = body ++ "\necho '" ++ marker ++ "'\n",
        .marker = marker,
    };
}

/// Shared by every script: `z` is zbx as demo in the private store, `m` in the demo's own store,
/// `w` as the second user; `policy` writes the demo's policy file for the store it names.
const lib =
    \\set -eu
    \\trap 'cat /tmp/err-a* 2>/dev/null' EXIT
    \\f() { echo "FAIL: $*"; exit 1; }
    \\B="HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000"
    \\B="$B DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
    \\B="$B ZBX_REGISTRY_MIRRORS=mirror.gcr.io"
    \\[ ! -f /home/demo/ca.crt ] || B="$B SSL_CERT_FILE=/home/demo/ca.crt"
    \\Z=/usr/local/bin/zbx
    \\cd /home/demo
    \\X="XDG_DATA_HOME=/home/demo/a XDG_CONFIG_HOME=/home/demo/ac"
    \\z() { runuser -u demo -- env $B $X $Z "$@"; }
    \\m() { runuser -u demo -- env $B $Z "$@"; }
    \\w() { runuser -u demo2 -- env $B HOME=/home/demo2 XDG_RUNTIME_DIR=/run/user/1001 $Z "$@"; }
    \\code() { grep -q "ZBX-$1" "$2" || { cat "$2"; f "expected $1"; }; }
    \\policy() { printf '.{ .version = 1, .keys = .{ .{ .name = "ci", .public = "%s" } },\n' \
    \\  "$1" >"$2"
    \\  printf '  .require_signature = true, .require_provenance = %s }\n' "$3" >>"$2"
    \\  chown demo "$2"; }
;

const a1 =
    \\. /tmp/m8a-lib.sh
    \\install -m 755 /home/demo/zbx $Z
    \\rm -rf /home/demo/a /home/demo/ac
    \\mkdir -p /home/demo/a /home/demo/ac/zbx
    \\chown -R demo /home/demo/a /home/demo/ac
    \\P=/home/demo/ac/zbx/policy.zon
    \\z key new ci --no-passphrase 2>/tmp/err-a1 || f key
    \\pub=$(z --output json key show ci | sed -n 's/.*"public":"\([^"]*\)".*/\1/p')
    \\echo "$pub" >/tmp/m8-pub
    \\z --output json pull alpine:3.20 >/tmp/a-pull 2>/tmp/err-a2 || f pull
    \\t=$(sed -n 's/.*"tree":"\(b3:[0-9a-f]*\)".*/\1/p' /tmp/a-pull)
    \\[ -n "$t" ] || f "no tree for alpine"
    \\echo "$t" >/tmp/m8-alpine
    \\z sign "$t" 2>>/tmp/err-a2 || f sign
    \\policy "$pub" $P false
    \\z run alpine:3.20 -- true 2>/tmp/err-a3 || f "the signed image did not run"
    \\policy "$pub" $P true
    \\z run alpine:3.20 -- true 2>/tmp/err-a4 && f "ran with a tree-only signature"
    \\code E0906 /tmp/err-a4
    \\z policy check alpine:3.20 --output json >/tmp/a-check 2>&1 || true
    \\grep -q '"allowed":false' /tmp/a-check || { head -c 1400 /tmp/a-check | tail -c 800; f "policy check"; }
    \\policy "$pub" $P false
    \\z store rm "$t" 2>/tmp/err-a5 || f "store rm"
    \\z store gc 2>>/tmp/err-a5 || f "store gc"
    \\z pull alpine:3.20 >/dev/null 2>>/tmp/err-a5 || f "re-pull"
    \\z run alpine:3.20 -- true 2>/tmp/err-a6 || f "the signature did not survive the re-pull"
;

const a2 =
    \\. /tmp/m8a-lib.sh
    \\P=/home/demo/ac/zbx/policy.zon
    \\t=$(cat /tmp/m8-alpine)
    \\pub=$(cat /tmp/m8-pub)
    \\mkdir -p /home/demo/a-src && echo kept >/home/demo/a-src/f
    \\chown -R demo /home/demo/a-src
    \\k=$(z store import /home/demo/a-src 2>/tmp/err-a7)
    \\z sign "$k" 2>>/tmp/err-a7 || f "sign the second tree"
    \\n() { find /home/demo/a -path '*/trust/signatures/*' -type f | wc -l; }
    \\[ "$(n)" = 2 ] || f "expected two records, have $(n)"
    \\z store rm "$t" 2>>/tmp/err-a7 || f "store rm"
    \\z store gc 2>>/tmp/err-a7 || f "store gc"
    \\z trust prune --output json >/tmp/a-dry 2>>/tmp/err-a7 || f "prune"
    \\grep -q '"dry_run":true' /tmp/a-dry || f "prune is not a dry run"
    \\grep -q '"orphans":1' /tmp/a-dry || { cat /tmp/a-dry; f "expected one orphan"; }
    \\[ "$(n)" = 2 ] || f "the dry run removed a record"
    \\z trust prune --apply --output json >/tmp/a-app 2>>/tmp/err-a7 || f "prune --apply"
    \\grep -q '"removed":1' /tmp/a-app || { cat /tmp/a-app; f "expected one removed"; }
    \\[ "$(n)" = 1 ] || f "expected the other record kept"
    \\z pull alpine:3.20 >/dev/null 2>>/tmp/err-a7 || f "re-pull"
    \\z run alpine:3.20 -- true 2>/tmp/err-a8 && f "ran after the prune"
    \\code E0905 /tmp/err-a8
    \\printf '.{ .version = 1,\n  .bogus = 1 }\n' >$P
    \\z run alpine:3.20 -- true 2>/tmp/err-a9 && f "ran under a malformed policy"
    \\code E0904 /tmp/err-a9
    \\grep -q 'line 2, column' /tmp/err-a9 || { cat /tmp/err-a9; f "no line and column"; }
    \\rm -f $P
;

const b1 =
    \\. /tmp/m8a-lib.sh
    \\d=$(cat /tmp/m8-digest)
    \\cd /home/demo/hello
    \\m run -d --name m8reg --publish 5000:5000 registry:2 >/tmp/err-a1 2>&1 || f "registry:2"
    \\i=0
    \\until curl -fs http://localhost:5000/v2/ >/dev/null; do
    \\  i=$((i + 1)); [ "$i" -lt 60 ] || f "the registry did not start"; sleep 1
    \\done
    \\p=$(m push "$d" localhost:5000/m8/hello:demo 2>/tmp/err-a2) || f push
    \\echo "$p" | grep -q '^sha256:' || f "push printed $p"
    \\m push "$d" localhost:5000/m8/hello:demo >/dev/null 2>/tmp/err-a3 || f "second push"
    \\q=$(m inspect --provenance "$d" --output json)
    \\e='s/^{"schema":"[^"]*","result":"[^"]*","tree":"\\(b3:[0-9a-f]*\\)".*/\\1/p'
    \\t=$(echo "$q" | sed -n "$e")
    \\[ -n "$t" ] || f "no tree in the provenance"
    \\m trust export "$t" >/tmp/m8-bundle 2>/tmp/err-a4 || f export
    \\chmod 644 /tmp/m8-bundle
    \\id demo2 >/dev/null 2>&1 || useradd -m -s /bin/sh demo2
    \\true
;

const b2 =
    \\. /tmp/m8a-lib.sh
    \\pub=$(m --output json key show demo | sed -n 's/.*"public":"\\([^"]*\\)".*/\\1/p')
    \\d=$(cat /tmp/m8-digest)
    \\r=localhost:5000/m8/hello:demo
    \\mkdir -p /home/demo2/.config/zbx /home/demo2/p && chown -R demo2 /home/demo2
    \\cd /home/demo2/p
    \\w pull $r >/dev/null 2>/tmp/err-a1 || f "second user pull"
    \\policy "$pub" /home/demo2/.config/zbx/policy.zon true
    \\chown demo2 /home/demo2/.config/zbx/policy.zon
    \\w run $r 2>/tmp/err-a2 && f "ran before the trust import"
    \\code E0905 /tmp/err-a2
    \\w trust import /tmp/m8-bundle >/dev/null 2>/tmp/err-a3 || f import
    \\out=$(w run $r 2>/tmp/err-a4) || f "the imported image did not run"
    \\[ "$out" = "hello from zigbox" ] || f "it printed $out"
    \\m stop m8reg >/dev/null 2>&1 || true
    \\rm -f /home/demo2/.config/zbx/policy.zon
;

/// The part: writes the library and the scripts, runs each, checks each marker.
pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: survive, E0906, prune, E0904, push, two users\n", .{
        H.demo_name, step,
    });
    try H.put_file(session, lib_path, lib);
    inline for (scripts) |one| try H.put_file(session, one.path, one.body);
    inline for (scripts) |one| {
        const result = try session.run("sh " ++ one.path ++ " 2>&1", timeout_s);
        try H.show(out, one.path, result);
        const ok = result.status == 0 and std.mem.indexOf(u8, result.output, one.marker) != null;
        if (!ok) {
            return common.fail_step(out, step, "a script failed: " ++ one.path, error.CheckFailed);
        }
    }
    try timer.lap(out, "accept8");
}

test "every script fits a put_file and ends with its marker" {
    try std.testing.expect(lib.len <= limits.put_file_bytes_max);
    inline for (scripts) |one| try std.testing.expect(one.body.len <= limits.put_file_bytes_max);
}
