//! The M7 demo's build part (`BUILD7`; slice 2 of docs/briefs/M7-build.md): `zbx build` on a
//! one-step build file, as the user `demo`, in the net project (`zn`), with `alpine:3.20`.
//!
//!   1. The first `zbx build` exits 0 and prints `compile  built  <digest>`.
//!   2. The digest is the step's output tree: `/hello` is in it, owned 0:0 (read by running
//!      the tree with the busybox the step copied into it), and no `build-*` run record and no
//!      work directory is left.
//!   3. The second `zbx build` prints `compile  hit  <same digest>`, starts no container (the
//!      list of run records and the step's log file are unchanged) and leaves nothing behind.
//!   4. SIGKILL of `zbx build` in the middle of a step (the step sleeps) leaves its work
//!      directory; the next build, with another command, succeeds and sweeps it away.
//!
//! The script prints `key=value` lines and the assertions are one pure function over them
//! (`check_build`), with unit tests. The store's output tree has no `zbx` command of its own to
//! list it yet, so its owner is what a container sees.

const std = @import("std");
const Io = std.Io;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "BUILD7";

const base = "alpine:3.20";

/// Writes `/hello` and, so that a container can run the tree, a busybox and its loader.
const quick_run = "mkdir -p /out/bin /out/lib && cp /bin/busybox /out/bin/ && " ++
    "cp /lib/ld-musl-* /out/lib/ && echo hello > /out/hello";
const slow_run = "sleep 300; echo late > /out/late";

fn build_file(comptime command: []const u8) []const u8 {
    return "cat > $P/zbx.build.zon <<'EOF'\n" ++
        ".{\n" ++
        "    .version = 1,\n" ++
        "    .image = .{ .base = \"" ++ base ++ "\" },\n" ++
        "    .steps = .{\n" ++
        "        .{\n" ++
        "            .name = \"compile\",\n" ++
        "            .base = \"" ++ base ++ "\",\n" ++
        "            .run = .{ \"sh\", \"-c\", \"" ++ command ++ "\" },\n" ++
        "        },\n" ++
        "    },\n" ++
        "}\n" ++
        "EOF\n";
}

/// Each script is at most `script_bytes_max` (a typed file is base64 in 2 KiB); they append their
/// `key=value` lines to `results_path`, which the part prints at the end.
const results_path = "/tmp/m7.out";
const script_bytes_max = 1400;
const prelude =
    "#!/bin/sh\n" ++
    "Z=/home/demo/zn\n" ++
    "P=/home/demo/net-project\n" ++
    "B=" ++ common.store_dir ++ "/build\n" ++
    "exec >> " ++ results_path ++ "\n" ++
    "ndir() { ls -A \"$1\" 2>/dev/null | wc -l; }\n";
const script_miss =
    prelude ++
    build_file(quick_run) ++
    "$Z build > /tmp/b1.out 2> /tmp/b1.err\n" ++
    "echo first_status=$?\n" ++
    "echo first_row=$(awk '$1 == \"compile\" { print $1 \":\" $2 }' /tmp/b1.out)\n" ++
    "D=$(awk '$1 == \"built\" { print $2 }' /tmp/b1.out)\n" ++
    "echo first_digest=$D\n" ++
    "echo work_first=$(ndir $B/work)\n" ++
    "$Z ps --all > /tmp/ps1.txt 2>&1\n" ++
    "echo records_first=$(grep -c 'build-' /tmp/ps1.txt)\n" ++
    "L=$(ls $B/logs/*/compile.log)\n" ++
    "echo log_first=$(stat -c '%y %s' $L)\n" ++
    "echo tree_owner=$($Z run $D -- /bin/busybox stat -c '%u:%g' /hello | tail -n 1)\n" ++
    "echo tree_text=$($Z run $D -- /bin/busybox cat /hello | tail -n 1)\n" ++
    "$Z ps --all > /tmp/ps1.txt 2>&1\n" ++
    "echo ps_lines_first=$(wc -l < /tmp/ps1.txt)\n";
const script_hit =
    prelude ++
    "L=$(ls $B/logs/*/compile.log)\n" ++
    "$Z build > /tmp/b2.out 2> /tmp/b2.err\n" ++
    "echo second_status=$?\n" ++
    "echo second_row=$(awk '$1 == \"compile\" { print $1 \":\" $2 }' /tmp/b2.out)\n" ++
    "echo second_digest=$(awk '$1 == \"built\" { print $2 }' /tmp/b2.out)\n" ++
    "echo work_second=$(ndir $B/work)\n" ++
    "$Z ps --all > /tmp/ps2.txt 2>&1\n" ++
    "echo records_second=$(grep -c 'build-' /tmp/ps2.txt)\n" ++
    "echo ps_lines_second=$(wc -l < /tmp/ps2.txt)\n" ++
    "echo log_second=$(stat -c '%y %s' $L)\n";
const script_kill =
    prelude ++
    build_file(slow_run) ++
    "$Z build > /dev/null 2>&1 &\n" ++
    "PID=$!\n" ++
    "i=0\n" ++
    "while [ $i -lt 120 ] && [ \"$(ndir $B/work)\" = 0 ]; do sleep 1; i=$((i+1)); done\n" ++
    "echo work_killed=$(ndir $B/work)\n" ++
    "kill -9 $PID; wait $PID 2> /dev/null\n" ++
    "sleep 2\n" ++
    build_file(quick_run ++ "; echo again > /out/again") ++
    "$Z build > /tmp/b3.out 2> /tmp/b3.err\n" ++
    "echo third_status=$?\n" ++
    "echo work_third=$(ndir $B/work)\n" ++
    "rm -f $P/zbx.build.zon\n";

comptime {
    std.debug.assert(script_miss.len <= script_bytes_max);
    std.debug.assert(script_hit.len <= script_bytes_max);
    std.debug.assert(script_kill.len <= script_bytes_max);
}

/// What the part's script printed, as `key=value` lines. Returns the text after `key=` on the
/// line that starts with it, or null.
pub fn value_of(output: []const u8, key: []const u8) ?[]const u8 {
    std.debug.assert(key.len > 0);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (!std.mem.startsWith(u8, line, key)) continue;
        if (line.len == key.len) continue;
        if (line[key.len] == '=') return line[key.len + 1 ..];
    }
    return null;
}

pub fn expect_value(output: []const u8, key: []const u8, want: []const u8) !void {
    const found = value_of(output, key) orelse return error.KeyMissing;
    if (!std.mem.eql(u8, found, want)) return error.ValueWrong;
}

/// Whether `text` is `b3:` and 64 hex digits.
pub fn is_digest(text: []const u8) bool {
    if (text.len != 67) return false;
    if (!std.mem.startsWith(u8, text, "b3:")) return false;
    for (text[3..]) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

/// The assertions of the part, over the script's output.
pub fn check_build(output: []const u8) !void {
    try expect_value(output, "first_status", "0");
    try expect_value(output, "second_status", "0");
    try expect_value(output, "first_row", "compile:miss");
    try expect_value(output, "second_row", "compile:hit");
    const built = value_of(output, "first_digest") orelse return error.KeyMissing;
    const again = value_of(output, "second_digest") orelse return error.KeyMissing;
    if (!is_digest(built)) return error.RowWrong;
    if (!std.mem.eql(u8, built, again)) return error.DigestChanged;
    try expect_value(output, "tree_owner", "0:0");
    try expect_value(output, "tree_text", "hello");
    try check_clean(output);
    try check_no_container(output);
    try check_killed(output);
}

/// No work directory and no `build-*` run record is left after either build.
fn check_clean(output: []const u8) !void {
    try expect_value(output, "work_first", "0");
    try expect_value(output, "work_second", "0");
    try expect_value(output, "records_first", "0");
    try expect_value(output, "records_second", "0");
}

/// A hit starts no container: no run record was added, and the step's log was not rewritten.
fn check_no_container(output: []const u8) !void {
    const lines_first = value_of(output, "ps_lines_first") orelse return error.KeyMissing;
    try expect_value(output, "ps_lines_second", lines_first);
    const log_first = value_of(output, "log_first") orelse return error.KeyMissing;
    if (log_first.len == 0) return error.KeyMissing;
    try expect_value(output, "log_second", log_first);
}

/// The build killed mid-step left a work directory, and the next build swept it.
fn check_killed(output: []const u8) !void {
    const during = value_of(output, "work_killed") orelse return error.KeyMissing;
    if (std.mem.eql(u8, during, "0")) return error.StepNeverStarted;
    try expect_value(output, "third_status", "0");
    try expect_value(output, "work_third", "0");
}

pub fn step_build(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: BUILD7: zbx build, one step: miss, hit, SIGKILL\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull " ++ base, 0);
    const chown = "chown demo:demo /home/demo/build-m7-*.sh && chmod 755 /home/demo/build-m7-*.sh";
    _ = try common.expect_exit(session, out, step_name, "rm -f " ++ results_path, 0);
    const scripts = [_][]const u8{ script_miss, script_hit, script_kill };
    inline for (scripts, 0..) |text, at| {
        const path = std.fmt.comptimePrint("/home/demo/build-m7-{d}.sh", .{at});
        try H.put_file(session, path, text);
        _ = try common.expect_exit(session, out, step_name, chown, 0);
        _ = try state.expect_long(session, out, H.as_demo ++ path, 0, 900);
    }
    const ran = try state.expect_long(session, out, "cat " ++ results_path, 0, 60);
    check_build(ran.output) catch |err| {
        return fail_step(out, step_name, "expected a miss, a hit and a swept work dir", err);
    };
    try timer.lap(out, "build7");
}

const sample_digest = "b3:abababababababababababababababababababababababababababababababab";
const good =
    "first_status=0\nfirst_row=compile:miss\nfirst_digest=" ++ sample_digest ++ "\n" ++
    "work_first=0\nrecords_first=0\nps_lines_first=3\nlog_first=t 10\n" ++
    "tree_owner=0:0\ntree_text=hello\n" ++
    "second_status=0\nsecond_row=compile:hit\nsecond_digest=" ++ sample_digest ++ "\n" ++
    "work_second=0\nrecords_second=0\nps_lines_second=3\nlog_second=t 10\n" ++
    "work_killed=1\nthird_status=0\nwork_third=0\n";

test "check_build accepts the output of a miss, a hit and a swept kill" {
    // Goal: the assertions pass on a transcript that has every property of the part.
    try check_build(good);
}

fn replaced(comptime from: []const u8, comptime to: []const u8) []const u8 {
    return comptime blk: {
        const at = std.mem.indexOf(u8, good, from).?;
        break :blk good[0..at] ++ to ++ good[at + from.len ..];
    };
}

test "check_build refuses each property that is broken" {
    // Goal: every assertion is needed; a transcript with one property broken is refused, with
    // the error that names it.
    const wrong = error.ValueWrong;
    const changed = error.DigestChanged;
    const cases = [_]struct { text: []const u8, err: anyerror }{
        .{ .text = replaced("tree_owner=0:0", "tree_owner=1000:1000"), .err = wrong },
        .{ .text = replaced("work_first=0", "work_first=1"), .err = wrong },
        .{ .text = replaced("records_second=0", "records_second=1"), .err = wrong },
        .{ .text = replaced("ps_lines_second=3", "ps_lines_second=4"), .err = wrong },
        .{ .text = replaced("log_second=t 10", "log_second=t 11"), .err = wrong },
        .{ .text = replaced("work_third=0", "work_third=2"), .err = wrong },
        .{ .text = replaced("work_killed=1", "work_killed=0"), .err = error.StepNeverStarted },
        .{ .text = replaced("compile:hit", "compile:miss"), .err = wrong },
        .{ .text = replaced("second_digest=b3:ab", "second_digest=b3:cd"), .err = changed },
        .{ .text = replaced("first_digest=b3:", "first_digest=b4:"), .err = error.RowWrong },
    };
    for (cases) |case| try std.testing.expectError(case.err, check_build(case.text));
}

test "value_of finds a key only at the start of a line" {
    // Goal: `work_first` must not be found inside `xwork_first`, and a key without `=` is none.
    try std.testing.expectEqualStrings("1", value_of("a=2\nwork=1\n", "work").?);
    try std.testing.expect(value_of("xwork=1\n", "work") == null);
    try std.testing.expect(value_of("work\n", "work") == null);
}
