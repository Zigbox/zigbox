//! The M7 demo's result part (`RESULT7`; slice 3b-ii of docs/briefs/M7-build.md): the full
//! project, `compile` and `notice` into an image with a config, as the user `demo` in the net
//! project (`zn`), with `alpine:3.20`.
//!
//!   1. `zbx build --output json` exits 0; `compile`, `notice` and `image` are all `miss`, and
//!      the `[start_ms, end_ms]` intervals of `compile` and `notice` overlap (each sleeps).
//!   2. `zbx run <result digest>` runs the config's entrypoint and prints `hello from zigbox`.
//!   3. `zbx inspect <result digest> --output json` shows the digest, a tree and the config.
//!   4. The same build again, in text, reports `(3 hits, 0 misses` and the same digest.
//!
//! As in `spec_m7.zig`, the script prints `key=value` lines and the assertions are one pure
//! function over them (`check_result`), with unit tests.

const std = @import("std");
const Io = std.Io;
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const spec = @import("spec_m7.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "RESULT7";

const results_path = "/tmp/m7r.out";
const script_bytes_max = 1400;
const prelude =
    "#!/bin/sh\n" ++
    "Z=/home/demo/zn\n" ++
    "P=/home/demo/net-project\n" ++
    "exec >> " ++ results_path ++ "\n";

/// A step that sleeps, so that two of them in one build must overlap to finish together.
fn step(comptime name: []const u8, comptime command: []const u8) []const u8 {
    return "        .{ .name = \"" ++ name ++ "\", .base = \"alpine:3.20\",\n" ++
        "          .run = .{ \"sh\", \"-c\", \"sleep 3; " ++ command ++ "\" } },\n";
}

const build_file =
    "cat > $P/zbx.build.zon <<'EOF'\n" ++
    ".{\n    .version = 1,\n    .steps = .{\n" ++
    step("compile", "mkdir -p /out && echo hello from zigbox > /out/hello; chmod 755 /out/hello") ++
    step("notice", "mkdir -p /out/etc && echo 1 > /out/etc/notice") ++
    "    },\n    .image = .{\n        .base = \"alpine:3.20\",\n" ++
    "        .add = .{ .{ .from = \"compile\", .to = \"/usr/local/bin\" },\n" ++
    "                  .{ .from = \"notice\", .to = \"/\" } },\n" ++
    "        .config = .{ .entrypoint = .{ \"/usr/local/bin/hello\" },\n" ++
    "                     .env = .{ \"GREETING_STYLE=plain\" } },\n    },\n}\nEOF\n";

const script_build =
    prelude ++ build_file ++
    "$Z build --output json > /tmp/r1.out 2> /tmp/r1.err\n" ++
    "echo result_status=$?\n" ++
    "echo result_rows=$(grep -o '\"step\":\"[a-z]*\",\"cache\":\"[a-z]*\"' /tmp/r1.out |" ++
    " tr -d '\"' | sed 's/step://;s/,cache:/:/' | sort | tr '\\n' ' ')\n" ++
    "echo result_digest=$(sed -n 's/.*\"build_result\":{\"digest\":\"\\([^\"]*\\)\".*/\\1/p'" ++
    " /tmp/r1.out)\n" ++
    "for N in compile notice; do\n" ++
    "  echo span_$N=$(grep \"\\\"step\\\":\\\"$N\\\"\" /tmp/r1.out | sed " ++
    "'s/.*\"start_ms\":\\([0-9]*\\),\"end_ms\":\\([0-9]*\\).*/\\1 \\2/')\n" ++
    "done\n";
const script_use =
    prelude ++
    "D=$(sed -n 's/.*\"build_result\":{\"digest\":\"\\([^\"]*\\)\".*/\\1/p' /tmp/r1.out)\n" ++
    "echo result_run=$($Z run $D 2>&1 | tail -n 1)\n" ++
    "echo result_inspect=$($Z inspect $D --output json 2>&1)\n" ++
    "$Z build > /tmp/r2.out 2> /tmp/r2.err\n" ++
    "echo again_status=$?\n" ++
    "echo \"again_footer=$(grep '^built ' /tmp/r2.out)\"\n" ++
    "rm -f $P/zbx.build.zon\n";

comptime {
    std.debug.assert(script_build.len <= script_bytes_max);
    std.debug.assert(script_use.len <= script_bytes_max);
}

/// The two numbers of a `span_*` value, `start end`.
fn span(output: []const u8, key: []const u8) ![2]u64 {
    const text = spec.value_of(output, key) orelse return error.KeyMissing;
    var parts = std.mem.splitScalar(u8, text, ' ');
    const start = std.fmt.parseInt(u64, parts.next() orelse "", 10) catch return error.SpanWrong;
    const end = std.fmt.parseInt(u64, parts.next() orelse "", 10) catch return error.SpanWrong;
    if (parts.next() != null) return error.SpanWrong;
    if (end < start) return error.SpanWrong;
    return .{ start, end };
}

/// The assertions of the part, over the script's output.
pub fn check_result(output: []const u8) !void {
    try spec.expect_value(output, "result_status", "0");
    try spec.expect_value(output, "result_rows", "compile:miss image:miss notice:miss");
    const digest = spec.value_of(output, "result_digest") orelse return error.KeyMissing;
    if (!spec.is_digest(digest)) return error.DigestWrong;
    const compile = try span(output, "span_compile");
    const notice = try span(output, "span_notice");
    if (compile[0] >= notice[1] or notice[0] >= compile[1]) return error.NoOverlap;
    try spec.expect_value(output, "result_run", "hello from zigbox");
    const inspect = spec.value_of(output, "result_inspect") orelse return error.KeyMissing;
    if (std.mem.indexOf(u8, inspect, digest) == null) return error.InspectWrong;
    if (std.mem.indexOf(u8, inspect, "\"tree\":\"b3:") == null) return error.InspectWrong;
    const entry = "\"entrypoint\":[\"/usr/local/bin/hello\"]";
    if (std.mem.indexOf(u8, inspect, entry) == null) return error.InspectWrong;
    if (std.mem.indexOf(u8, inspect, "\"GREETING_STYLE=plain\"") == null) return error.InspectWrong;
    try spec.expect_value(output, "again_status", "0");
    const footer = spec.value_of(output, "again_footer") orelse return error.KeyMissing;
    var want: [96]u8 = undefined;
    const format = "built {s}  (3 hits, 0 misses,";
    const head = std.fmt.bufPrint(&want, format, .{digest}) catch unreachable; // 96 holds it.
    if (!std.mem.startsWith(u8, footer, head)) return error.AgainWrong;
}

pub fn step_result(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    const title = "{s}: RESULT7: the full project: overlap, run, inspect, hits\n";
    try out.print("\n" ++ title, .{H.demo_name});
    const chown = "chown demo:demo /home/demo/build-m7r-*.sh && " ++
        "chmod 755 /home/demo/build-m7r-*.sh";
    _ = try common.expect_exit(session, out, step_name, "rm -f " ++ results_path, 0);
    const scripts = [_][]const u8{ script_build, script_use };
    inline for (scripts, 0..) |text, at| {
        const path = std.fmt.comptimePrint("/home/demo/build-m7r-{d}.sh", .{at});
        try H.put_file(session, path, text);
        _ = try common.expect_exit(session, out, step_name, chown, 0);
        _ = try state.expect_long(session, out, H.as_demo ++ path, 0, 900);
    }
    const ran = try state.expect_long(session, out, "cat " ++ results_path, 0, 60);
    check_result(ran.output) catch |err| {
        return fail_step(out, step_name, "expected miss rows, overlap, a run, inspect, hits", err);
    };
    try timer.lap(out, "result7");
}

const sample = "b3:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const good =
    "result_status=0\nresult_rows=compile:miss image:miss notice:miss\n" ++
    "result_digest=" ++ sample ++ "\nspan_compile=10 3400\nspan_notice=12 3300\n" ++
    "result_run=hello from zigbox\n" ++
    "result_inspect={\"schema\":\"zbx.build_result/1\",\"digest\":\"" ++ sample ++
    "\",\"tree\":\"b3:ab\",\"config\":{\"entrypoint\":[\"/usr/local/bin/hello\"],\"cmd\":[]," ++
    "\"env\":[\"PATH=/bin\",\"GREETING_STYLE=plain\"]}}\n" ++
    "again_status=0\nagain_footer=built " ++ sample ++ "  (3 hits, 0 misses, 0.1 s)\n";

fn replaced(comptime from: []const u8, comptime to: []const u8) []const u8 {
    return comptime blk: {
        const at = std.mem.indexOf(u8, good, from).?;
        break :blk good[0..at] ++ to ++ good[at + from.len ..];
    };
}

test "check_result accepts a build whose steps overlapped, ran, inspected and hit" {
    // Goal: the assertions pass on a transcript that has every property of the part.
    try check_result(good);
}

test "check_result refuses each property that is broken" {
    // Goal: every assertion is needed; one broken property is refused with the error naming it.
    const wrong = error.ValueWrong;
    const no_overlap = error.NoOverlap;
    const cases = [_]struct { text: []const u8, err: anyerror }{
        .{ .text = replaced("result_status=0", "result_status=1"), .err = wrong },
        .{ .text = replaced("image:miss", "image:hit"), .err = wrong },
        .{ .text = replaced("span_notice=12 3300", "span_notice=3400 6000"), .err = no_overlap },
        .{ .text = replaced("span_compile=10 3400", "span_compile=x"), .err = error.SpanWrong },
        .{ .text = replaced("result_run=hello from zigbox", "result_run=hi"), .err = wrong },
        .{ .text = replaced("\"tree\":\"b3:ab\"", "\"tree\":\"none\""), .err = error.InspectWrong },
        .{ .text = replaced("GREETING_STYLE=plain", "GREETING=1"), .err = error.InspectWrong },
        .{ .text = replaced("(3 hits", "(2 hits"), .err = error.AgainWrong },
        .{ .text = replaced("result_digest=b3:", "result_digest=b4:"), .err = error.DigestWrong },
    };
    for (cases) |case| try std.testing.expectError(case.err, check_result(case.text));
}
