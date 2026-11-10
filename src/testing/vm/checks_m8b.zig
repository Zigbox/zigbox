//! The assertions of the M8b demo (docs/briefs/M8b-listen.md), as pure functions over the lines
//! the guest scripts in `m8b/` print. Each takes the whole output of one script and says which
//! claim failed. Nothing here touches a VM; every check has a unit test with wrong input.

const std = @import("std");

pub const Error = error{
    /// The listener did not arrive, or the workload did not get the harness's answer.
    HelloWrong,
    /// A hostile check held where it had to refuse: the port was free, a socket was in the
    /// workload's table, the host's own listener was reachable, or the host showed the port.
    HostileWrong,
    /// The container did not survive its listener going away, or it still answered.
    ClosedWrong,
    /// A refusal is missing, not coded, or not one line.
    RefusalWrong,
};

/// The value after `key` on the first line that starts with it, or null.
fn value_of(output: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, "\r ");
        if (std.mem.startsWith(u8, trimmed, key)) {
            return std.mem.trimStart(u8, trimmed[key.len..], " ");
        }
    }
    return null;
}

fn expect_value(output: []const u8, key: []const u8, want: []const u8) bool {
    const got = value_of(output, key) orelse return false;
    return std.mem.eql(u8, got, want);
}

/// The container's `wget` printed what the harness answered, with the one descriptor the
/// harness received, and zbx exited 0.
pub fn check_hello(output: []const u8) Error!void {
    if (!expect_value(output, "HELLO-DESCRIPTORS:", "1")) return error.HelloWrong;
    if (!expect_value(output, "HELLO-RC:", "0")) return error.HelloWrong;
    if (!expect_value(output, "HELLO-OUT:", "hello from outside")) return error.HelloWrong;
    if (!expect_value(output, "HELLO-ERR:", "")) return error.HelloWrong;
}

/// Inside, the port is taken (`nc` exits 1 and says so); no socket is in the workload's table;
/// the host's own `127.0.0.1:9999` is unreachable; the host shows nothing on `:8080`; zbx is 0.
pub fn check_hostile(output: []const u8) Error!void {
    if (!expect_value(output, "NC-EXIT:", "1")) return error.HostileWrong;
    if (std.mem.indexOf(u8, output, "in use") == null) return error.HostileWrong;
    if (!expect_value(output, "SOCKETS:", "0")) return error.HostileWrong;
    const wget = value_of(output, "W9999:") orelse return error.HostileWrong;
    if (std.mem.eql(u8, wget, "0")) return error.HostileWrong;
    if (!expect_value(output, "HOST-9999-ACCEPTED:", "0")) return error.HostileWrong;
    if (!expect_value(output, "HOST-SS-8080:", "0")) return error.HostileWrong;
    if (!expect_value(output, "HOSTILE-RC:", "0")) return error.HostileWrong;
}

/// After the harness closed its listener: `wget` was refused, the shell went on (`ALIVE`), and
/// zbx exited 0.
pub fn check_closed(output: []const u8) Error!void {
    if (std.mem.indexOf(u8, output, "CLOSED-HARNESS-END") == null) return error.ClosedWrong;
    const after = value_of(output, "AFTER:") orelse return error.ClosedWrong;
    if (std.mem.eql(u8, after, "0")) return error.ClosedWrong;
    if (std.mem.indexOf(u8, output, "refused") == null) return error.ClosedWrong;
    if (std.mem.indexOf(u8, output, "ALIVE") == null) return error.ClosedWrong;
    if (!expect_value(output, "CLOSED-RC:", "0")) return error.ClosedWrong;
}

const Refusal = struct { label: []const u8, code: []const u8 };

const refusals = [_]Refusal{
    .{ .label = "host", .code = "ZBX-E0606" },
    .{ .label = "publish", .code = "ZBX-E0606" },
    .{ .label = "nosend", .code = "ZBX-E0606" },
    .{ .label = "notsocket", .code = "ZBX-E0606" },
    .{ .label = "badfd", .code = "ZBX-E0606" },
    .{ .label = "gone", .code = "ZBX-E0609" },
    .{ .label = "remote", .code = "ZBX-E0607" },
};

/// Every refusal printed one `REFUSED <label> rc=125 error[<code>]: ...` line with its code.
pub fn check_refusals(output: []const u8) Error!void {
    var seen: u32 = 0;
    for (refusals) |refusal| {
        var key_buffer: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buffer, "REFUSED {s} ", .{refusal.label}) catch {
            return error.RefusalWrong;
        };
        const rest = value_of(output, key) orelse return error.RefusalWrong;
        if (!std.mem.startsWith(u8, rest, "rc=125 error[")) return error.RefusalWrong;
        if (std.mem.indexOf(u8, rest, refusal.code) == null) return error.RefusalWrong;
        if (std.mem.indexOf(u8, rest, "errno") != null) return error.RefusalWrong;
        seen += 1;
    }
    if (seen != refusals.len) return error.RefusalWrong;
    // The send to a gone peer stopped the container: zbx came back long before the 30 s sleep
    // would have ended, and no sleep is left.
    const seconds = value_of(output, "GONE-SECS:") orelse return error.RefusalWrong;
    const took = std.fmt.parseInt(u32, seconds, 10) catch return error.RefusalWrong;
    if (took >= 20) return error.RefusalWrong;
    if (!expect_value(output, "GONE-LEFT:", "0")) return error.RefusalWrong;
}

const hello_good =
    \\HELLO-DESCRIPTORS: 1
    \\HELLO-RC: 0
    \\HELLO-OUT: hello from outside
    \\HELLO-ERR:
    \\
;

test "hello holds on the right output" {
    try check_hello(hello_good);
}

test "hello fails on a wrong answer, a failed run, two descriptors or stderr" {
    const bad = [_][]const u8{
        "",
        "HELLO-DESCRIPTORS: 1\nHELLO-RC: 0\nHELLO-OUT: \nHELLO-ERR:\n",
        "HELLO-DESCRIPTORS: 1\nHELLO-RC: 1\nHELLO-OUT: hello from outside\nHELLO-ERR:\n",
        "HELLO-DESCRIPTORS: 2\nHELLO-RC: 0\nHELLO-OUT: hello from outside\nHELLO-ERR:\n",
        "HELLO-DESCRIPTORS: 1\nHELLO-RC: 0\nHELLO-OUT: hello from outside\nHELLO-ERR: x\n",
    };
    for (bad) |text| try std.testing.expectError(error.HelloWrong, check_hello(text));
}

const hostile_good =
    \\nc: bind: Address in use
    \\NC-EXIT:1
    \\SOCKETS:0
    \\W9999:1
    \\READY
    \\HOST-SS-8080: 0
    \\HOST-9999-ACCEPTED: 0
    \\DONE
    \\HOSTILE-RC: 0
    \\HOSTILE-ERR:
    \\
;

test "hostile holds on the right output" {
    try check_hostile(hostile_good);
}

test "hostile fails on each broken claim" {
    const swaps = [_][2][]const u8{
        .{ "NC-EXIT:1", "NC-EXIT:0" },
        .{ "Address in use", "Address ok" },
        .{ "SOCKETS:0", "SOCKETS:1" },
        .{ "W9999:1", "W9999:0" },
        .{ "HOST-9999-ACCEPTED: 0", "HOST-9999-ACCEPTED: 1" },
        .{ "HOST-SS-8080: 0", "HOST-SS-8080: 1" },
        .{ "HOSTILE-RC: 0", "HOSTILE-RC: 125" },
    };
    var buffer: [512]u8 = undefined;
    for (swaps) |swap| {
        const count = std.mem.replacementSize(u8, hostile_good, swap[0], swap[1]);
        try std.testing.expect(count <= buffer.len);
        _ = std.mem.replace(u8, hostile_good, swap[0], swap[1], &buffer);
        try std.testing.expectError(error.HostileWrong, check_hostile(buffer[0..count]));
    }
}

const closed_good =
    \\CLOSED-HARNESS-END
    \\wget: can't connect to remote host (127.0.0.1): Connection refused
    \\AFTER:1
    \\ALIVE
    \\CLOSED-RC: 0
    \\CLOSED-ERR:
    \\
;

test "closed holds on the right output" {
    try check_closed(closed_good);
}

test "closed fails when the connection worked or the container died" {
    const bad = [_][]const u8{
        "",
        "CLOSED-HARNESS-END\nAFTER:0\nALIVE\nCLOSED-RC: 0\n",
        "CLOSED-HARNESS-END\nConnection refused\nAFTER:1\nCLOSED-RC: 0\n",
        "CLOSED-HARNESS-END\nConnection refused\nAFTER:1\nALIVE\nCLOSED-RC: 137\n",
        "Connection refused\nAFTER:1\nALIVE\nCLOSED-RC: 0\n",
    };
    for (bad) |text| try std.testing.expectError(error.ClosedWrong, check_closed(text));
}

const refusals_good =
    \\REFUSED host rc=125 error[ZBX-E0606]: --listen is refused with these options
    \\REFUSED publish rc=125 error[ZBX-E0606]: --listen is refused with these options
    \\REFUSED nosend rc=125 error[ZBX-E0606]: --listen is refused with these options
    \\REFUSED notsocket rc=125 error[ZBX-E0606]: --listen is refused with these options
    \\REFUSED badfd rc=125 error[ZBX-E0606]: --listen is refused with these options
    \\REFUSED remote rc=125 error[ZBX-E0607]: --listen takes 127.0.0.1 and a port
    \\REFUSED gone rc=125 error[ZBX-E0609]: the listener could not be handed on
    \\GONE-SECS:1
    \\GONE-LEFT:0
    \\
;

test "refusals hold on the right output" {
    try check_refusals(refusals_good);
}

test "refusals fail on a missing line, a wrong code, an exit code or an errno dump" {
    const swaps = [_][2][]const u8{
        .{ "REFUSED remote", "REFUSED other" },
        .{ "ZBX-E0607", "ZBX-E0606" },
        .{ "rc=125 error[ZBX-E0609]", "rc=1 error[ZBX-E0609]" },
        .{ "handed on", "handed on (errno 88)" },
        .{ "GONE-SECS:1", "GONE-SECS:30" },
        .{ "GONE-LEFT:0", "GONE-LEFT:1" },
        .{ "REFUSED gone ", "REFUSED gon " },
    };
    var buffer: [1024]u8 = undefined;
    for (swaps) |swap| {
        const count = std.mem.replacementSize(u8, refusals_good, swap[0], swap[1]);
        try std.testing.expect(count <= buffer.len);
        _ = std.mem.replace(u8, refusals_good, swap[0], swap[1], &buffer);
        try std.testing.expectError(error.RefusalWrong, check_refusals(buffer[0..count]));
    }
}
