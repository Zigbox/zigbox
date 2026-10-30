//! demo-m6b's ACCEPT part: the acceptance criterion of M6b that the parts WRITABLE, LOGS and EXEC
//! do not show. As the user `demo`, in the net project (`zn`):
//!
//!   A container (`lrm00`) writes a marker and ends; its log and its run record are on the disk
//!   and `zbx logs` shows the marker. Forty more containers run after it, so that the record
//!   (the newest `runs_max` are kept) is pruned. The log goes with it: neither of its two files
//!   is left, the newest container's log is, and `zbx logs lrm00` is ZBX-E0402.
//!
//! It runs last, because pruning removes the oldest records of the demo's state directory, which
//! must not be one a part still needs.
//!
//! Every assertion is a function of checks_accept_m6b.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_accept_m6b.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const net_user = @import("net_user_m5.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;
const zn = net_user.zn;
const step_name = "ACCEPT6B";

const marker = "gone-with-the-record";

const script_path = "/home/demo/log-removal.sh";
const script =
    "#!/bin/sh\n" ++
    "Z=/home/demo/zn\n" ++
    "L=" ++ common.state_dir ++ "/logs\n" ++
    "R=" ++ common.state_dir ++ "/runs\n" ++
    "$Z run --name lrm00 alpine -- echo " ++ marker ++ " > /dev/null || exit 1\n" ++
    "echo before_log=$(ls $L | grep -c '^lrm00\\.log$')\n" ++
    "echo before_record=$(ls $R | grep -c '^lrm00\\.')\n" ++
    "echo before_text=$($Z logs lrm00)\n" ++
    "i=1\n" ++
    "while [ $i -le 40 ]; do\n" ++
    "  $Z run --name lrm$(printf %02d $i) alpine -- true > /dev/null 2>&1 || exit 2\n" ++
    "  i=$((i+1))\n" ++
    "done\n" ++
    "echo after_log=$(ls $L | grep -c '^lrm00\\.log$')\n" ++
    "echo after_older=$(ls $L | grep -c '^lrm00\\.log\\.1$')\n" ++
    "echo after_record=$(ls $R | grep -c '^lrm00\\.')\n" ++
    "echo newest_log=$(ls $L | grep -c '^lrm40\\.log$')\n" ++
    "$Z logs lrm00 > /dev/null 2> /tmp/lrm00.err\n" ++
    "echo gone_status=$?\n" ++
    "echo gone_code=$(grep -o 'ZBX-E0402' /tmp/lrm00.err | head -n 1)\n";

pub fn step_accept(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: ACCEPT6B: a log is removed with its run record\n", .{H.demo_name});
    try net_user.make_net_wrapper(session, out);
    _ = try common.expect_exit(session, out, step_name, zn ++ " pull alpine", 0);
    try H.put_file(session, script_path, script);
    const chown = "chown demo:demo " ++ script_path ++ " && chmod 755 " ++ script_path;
    _ = try common.expect_exit(session, out, step_name, chown, 0);
    const ran = try state.expect_long(session, out, H.as_demo ++ script_path, 0, 600);
    checks.check_removal(ran.output, ran.status, marker) catch |err| {
        return fail_step(out, step_name, "expected the log to go with its record", err);
    };
    try timer.lap(out, "accept6b");
}

test {
    _ = @import("checks_accept_m6b.zig");
}
