//! The ACCEPT checks of the M8 demo that the single-command TRUST8 steps do not make
//! (docs/briefs/M8-trust.md, "ACCEPT also checks"). Seven small shell scripts run in the guest,
//! as root, each command as the ordinary user. A script only orchestrates: for each command it
//! prints an evidence block (`@@ev NAME RC`, stdout, `@@err`, stderr, `@@end`), and every
//! assertion is made on the host by a pure function of `checks_m8.zig` (`check_a1` to
//! `check_b3`), each with unit tests, including the cases it must refuse.
//!
//!   - A1 to A4, in a store and config directory of their own (`~/a`, `~/ac`): a signature
//!     survives `store rm`, `store gc` (the tree is gone before the re-pull, and the same
//!     after it); `require_provenance` refuses a tree-only signature (E0906); `policy check`
//!     is run beside every `run` verdict and must agree; `trust prune` lists exactly one real
//!     orphan, `--apply` removes exactly it, gc then counts no orphans, and the image is refused
//!     again (E0905); a step whose base is unsigned is refused naming the step; a malformed
//!     policy is E0904 with its line and column.
//!   - B1 to B3, in the demo user's own store, on the signed hello result TRUST8 left:
//!     `registry:2` is run by `zbx run`, the result is pushed twice (the second finds every blob),
//!     a second result with the same tree and another entrypoint is built and pushed, a second
//!     user imports the exported trust and pulls both: the first runs under `require_signature`
//!     and `require_provenance` (the derived binding), the second is refused, and a `-- <cmd>`
//!     override on the first stays allowed.
//!
//! A script prints its marker as its last line; the part fails unless it did and exited 0.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const checks = @import("checks_m8.zig");
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
const Check = *const fn (Allocator, []const u8) checks.Error!void;
const Script = struct { path: []const u8, body: []const u8, marker: []const u8, check: Check };
const scripts = [_]Script{
    script("1", a1, checks.check_a1),
    script("2", a2, checks.check_a2),
    script("3", a3, checks.check_a3),
    script("4", a4, checks.check_a4),
    script("5", b1, checks.check_b1),
    script("6", b2, checks.check_b2),
    script("7", b3, checks.check_b3),
};

fn script(comptime name: []const u8, comptime body: []const u8, check: Check) Script {
    const marker = "m8-accept-" ++ name ++ ": ok";
    return .{
        .path = "/tmp/m8a-" ++ name ++ ".sh",
        .body = body ++ "\necho '" ++ marker ++ "'\n",
        .marker = marker,
        .check = check,
    };
}

/// Shared by every script: `z` is zbx as demo in the private store, `m` in the demo's own store,
/// `w` as the second user; `x NAME cmd...` runs a command and prints its evidence block;
/// `policy` writes the demo's policy file; `g` plans and confirms a gc; `drop` forgets the
/// ended containers (their layers keep a tree alive; there is no command to remove them).
const lib =
    \\set -eu
    \\trap 'cat /tmp/xe 2>/dev/null' EXIT
    \\f() { echo "FAIL: $*"; exit 1; }
    \\B="HOME=/home/demo XDG_RUNTIME_DIR=/run/user/1000"
    \\B="$B DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
    \\B="$B ZBX_REGISTRY_MIRRORS=mirror.gcr.io"
    \\[ ! -f /home/demo/ca.crt ] || B="$B SSL_CERT_FILE=/home/demo/ca.crt"
    \\Z=/usr/local/bin/zbx
    \\cd /home/demo
    \\X="XDG_DATA_HOME=/home/demo/a XDG_CONFIG_HOME=/home/demo/ac XDG_STATE_HOME=/home/demo/as"
    \\z() { runuser -u demo -- env $B $X $Z "$@"; }
    \\m() { runuser -u demo -- env $B $Z "$@"; }
    \\w() { runuser -u demo2 -- env $B HOME=/home/demo2 XDG_RUNTIME_DIR=/run/user/1001 $Z "$@"; }
    \\x() { xn=$1; shift; "$@" >/tmp/xo 2>/tmp/xe && xr=0 || xr=$?
    \\  printf '@@ev %s %s\n' "$xn" "$xr"; cat /tmp/xo; printf '\n@@err\n'
    \\  cat /tmp/xe; printf '\n@@end\n'; }
    \\g() { z store gc >/tmp/a-plan 2>&1
    \\  h=$(sed -n 's/^confirm with: zbx store gc --confirm //p' /tmp/a-plan)
    \\  [ -n "$h" ] || f "no gc plan"
    \\  z store gc --confirm "$h" >/dev/null 2>&1 || f "gc confirm"; }
    \\drop() { rm -rf /home/demo/as/zbx/containers /home/demo/as/zbx/runs /home/demo/as/zbx/logs; }
    \\policy() { printf '.{ .version = 1, .keys = .{ .{ .name = "ci", .public = "%s" } },\n' \
    \\  "$1" >"$2"
    \\  printf '  .require_signature = true, .require_provenance = %s }\n' "$3" >>"$2"
    \\  chown demo "$2"; }
;

const a1 =
    \\. /tmp/m8a-lib.sh
    \\install -m 755 /home/demo/zbx $Z
    \\rm -rf /home/demo/a /home/demo/ac /home/demo/as
    \\mkdir -p /home/demo/a /home/demo/ac/zbx /home/demo/as
    \\chown -R demo /home/demo/a /home/demo/ac /home/demo/as
    \\P=/home/demo/ac/zbx/policy.zon
    \\z key new ci --no-passphrase >/dev/null 2>&1 || f key
    \\pub=$(z --output json key show ci | sed -n 's/.*"public":"\([^"]*\)".*/\1/p')
    \\echo "$pub" >/tmp/m8-pub
    \\x pull1 z --output json pull alpine:3.20
    \\t=$(sed -n 's/.*"tree":"\(b3:[0-9a-f]*\)".*/\1/p' /tmp/xo)
    \\[ -n "$t" ] || f "no tree for alpine"
    \\echo "$t" >/tmp/m8-alpine
    \\z sign "$t" >/dev/null 2>&1 || f sign
    \\x ls0 z --output json store ls
    \\policy "$pub" $P false
    \\x run1 z run alpine:3.20 -- true
    \\x chk1 z policy check alpine:3.20 --output json
    \\policy "$pub" $P true
    \\x run2 z run alpine:3.20 -- true
    \\x chk2 z policy check alpine:3.20 --output json
;

const a2 =
    \\. /tmp/m8a-lib.sh
    \\P=/home/demo/ac/zbx/policy.zon
    \\t=$(cat /tmp/m8-alpine)
    \\policy "$(cat /tmp/m8-pub)" $P false
    \\x tree cat /tmp/m8-alpine
    \\x rm1 z store rm "$t"
    \\drop
    \\g
    \\x ls1 z --output json store ls
    \\x pull2 z --output json pull alpine:3.20
    \\x run3 z run alpine:3.20 -- true
    \\x chk3 z policy check alpine:3.20 --output json
;

const a3 =
    \\. /tmp/m8a-lib.sh
    \\t=$(cat /tmp/m8-alpine)
    \\x tree cat /tmp/m8-alpine
    \\mkdir -p /home/demo/a-src && echo kept >/home/demo/a-src/f
    \\chown -R demo /home/demo/a-src
    \\k=$(z store import /home/demo/a-src 2>/dev/null)
    \\x sign2 z sign "$k"
    \\n() { find /home/demo/a -path '*/trust/signatures/*' -type f | wc -l; }
    \\x n0 n
    \\x rm2 z store rm "$t"
    \\drop
    \\g
    \\x orph0 z --output json store gc
    \\x dry z trust prune --output json
    \\x n1 n
    \\x app z trust prune --apply --output json
    \\x n2 n
    \\x orph1 z --output json store gc
    \\x pull3 z pull alpine:3.20
    \\x run4 z run alpine:3.20 -- true
    \\x chk4 z policy check alpine:3.20 --output json
;

const a4 =
    \\. /tmp/m8a-lib.sh
    \\P=/home/demo/ac/zbx/policy.zon
    \\mkdir -p /tmp/m8a-proj && cd /tmp/m8a-proj && echo in >in.txt
    \\cat >zbx.build.zon <<'EOF'
    \\.{ .version = 1, .steps = .{ .{ .name = "probe", .base = "alpine:3.20",
    \\  .inputs = .{"in.txt"}, .run = .{ "sh", "-c", "cp in.txt /out/" } } },
    \\  .image = .{ .base = "alpine:3.20", .add = .{ .{ .from = "probe", .to = "/" } } } }
    \\EOF
    \\chown -R demo /tmp/m8a-proj
    \\z pull alpine:3.20 >/dev/null 2>&1 || f "pull in the project"
    \\x bld z build
    \\printf '.{ .version = 1,\n  .bogus = 1 }\n' >$P
    \\x run5 z run alpine:3.20 -- true
    \\rm -f $P
;

const b1 =
    \\. /tmp/m8a-lib.sh
    \\d=$(cat /tmp/m8-digest)
    \\mkdir -p /home/demo/reg && chown demo /home/demo/reg && cd /home/demo/reg
    \\m pull registry:2 >/dev/null 2>&1 || f "pull registry:2"
    \\m run -d --name m8reg --publish 5000:5000 registry:2 >/dev/null 2>&1 || f registry
    \\i=0
    \\until curl -fs http://localhost:5000/v2/ >/dev/null; do
    \\  i=$((i + 1)); [ "$i" -lt 60 ] || f "the registry did not start"; sleep 1
    \\done
    \\cd /home/demo/hello
    \\x push1 m --output json push "$d" localhost:5000/m8/hello:demo
    \\[ "$xr" = 0 ] || {
    \\  x reglog m logs m8reg
    \\  x push1r m --output json push "$d" localhost:5000/m8/hello:demo
    \\}
    \\x push2 m --output json push "$d" localhost:5000/m8/hello:demo
;

const b2 =
    \\. /tmp/m8a-lib.sh
    \\d=$(cat /tmp/m8-digest)
    \\rm -rf /home/demo/hello2 && cp -r /home/demo/hello /home/demo/hello2
    \\cd /home/demo/hello2
    \\h=/usr/local/bin/hello
    \\e="s#\.entrypoint = \.{\"$h\"}#.entrypoint = .{ \"$h\", \"--x\" }#"
    \\sed -i "$e" zbx.build.zon
    \\grep -q -- '"--x"' zbx.build.zon || f "the entrypoint was not changed"
    \\chown -R demo /home/demo/hello2
    \\x bld2 m --output json build
    \\d2=$(sed -n 's/.*"digest":"\(b3:[0-9a-f]*\)".*/\1/p' /tmp/xo | tail -1)
    \\[ -n "$d2" ] && [ "$d2" != "$d" ] || f "no second result"
    \\x ins2 m inspect --provenance "$d2" --output json
    \\x ins1 m inspect --provenance "$d" --output json
    \\t=$(grep -o '"tree":"b3:[0-9a-f]*' /tmp/xo | head -1 | cut -d'"' -f4)
    \\[ -n "$t" ] || f "no tree in the provenance"
    \\x push3 m --output json push "$d2" localhost:5000/m8/hello:other
    \\x exp m trust export "$t"
    \\cp /tmp/xo /tmp/m8-bundle && chmod 644 /tmp/m8-bundle
;

const b3 =
    \\. /tmp/m8a-lib.sh
    \\pub=$(m --output json key show demo | grep -o '"public":"[^"]*' | cut -d'"' -f4)
    \\r=localhost:5000/m8/hello:demo; o=localhost:5000/m8/hello:other
    \\id demo2 >/dev/null 2>&1 || useradd -m -s /bin/sh demo2
    \\Q=/home/demo2/.config/zbx/policy.zon
    \\mkdir -p /home/demo2/.config/zbx /home/demo2/p && chown -R demo2 /home/demo2
    \\cd /home/demo2/p
    \\w pull $r >/dev/null 2>&1 || f "second user pull"
    \\w pull $o >/dev/null 2>&1 || f "second user pull of the other result"
    \\policy "$pub" $Q true && chown demo2 $Q
    \\x run_before w run $r
    \\x chk_before w policy check $r --output json
    \\x import w trust import /tmp/m8-bundle
    \\x run_after w run $r
    \\x chk_after w policy check $r --output json
    \\x run_other w run $o
    \\x chk_other w policy check $o --output json
    \\x run_override w run $r -- extra
    \\m stop m8reg >/dev/null 2>&1 || true
    \\rm -f $Q
;

/// The part: writes the library and the scripts, runs each, checks each marker and its evidence.
pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: survive, E0906, prune, E0904, push, derived binding\n", .{
        H.demo_name, step,
    });
    try H.put_file(session, lib_path, lib);
    inline for (scripts) |one| try H.put_file(session, one.path, one.body);
    inline for (scripts) |one| {
        const result = try session.run("sh " ++ one.path ++ " 2>&1", timeout_s);
        try H.show(out, one.path, result);
        const ran = result.status == 0 and std.mem.indexOf(u8, result.output, one.marker) != null;
        if (!ran) {
            return common.fail_step(out, step, "a script failed: " ++ one.path, error.CheckFailed);
        }
        one.check(session.scratch_allocator(), result.output) catch |err| {
            return common.fail_step(out, step, "a check failed for " ++ one.path, err);
        };
    }
    try timer.lap(out, "accept8");
}

test "every script fits a put_file and ends with its marker" {
    try std.testing.expect(lib.len <= limits.put_file_bytes_max);
    inline for (scripts) |one| {
        try std.testing.expect(one.body.len <= limits.put_file_bytes_max);
        try std.testing.expect(std.mem.endsWith(u8, one.body, one.marker ++ "'\n"));
    }
}
