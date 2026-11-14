//! The assertions of the C4 demo (docs/briefs/zb-c4.md), as pure functions over the lines the
//! guest scripts in `c4/` print. Each takes the whole output of one script and says which claim
//! failed. Nothing here touches a VM; every check has a unit test with wrong input.

const std = @import("std");

pub const Error = error{
    /// The container did not start, or it has more than a loopback.
    StartWrong,
    /// A listener made with `container_socket` was not reached from inside, or was reached
    /// from the host, or outlived its close.
    ListenWrong,
    /// The caller's socket did not reach the server inside, or did not survive the adoption.
    ConnectWrong,
    /// A command from `zbx exec` did not see the container's own loopback.
    NetWrong,
    /// The workload reached the supervisor, or could write the hosts file.
    HostileWrong,
    /// A hosts file given with `--hosts-file` was not read, followed in place, or refused.
    HostsWrong,
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

/// A value that is a number other than 0 (a refused connection, a failed command).
fn is_failure(output: []const u8, key: []const u8) bool {
    const got = value_of(output, key) orelse return false;
    const number = std.fmt.parseInt(i32, got, 10) catch return false;
    return number != 0;
}

/// The container started with `zbx run -d --net none`, and holds one link, `lo`.
pub fn check_start(output: []const u8) Error!void {
    if (!expect_value(output, "START-RC:", "0")) return error.StartWrong;
    if (!expect_value(output, "START-ERR:", "")) return error.StartWrong;
    if (!expect_value(output, "LINKS:", "1")) return error.StartWrong;
    if (!expect_value(output, "LINK-LO:", "1")) return error.StartWrong;
}

/// A listener on 127.77.0.2:8080 made by the supervisor is answered inside; closed, it refuses
/// and a second on 127.77.0.3 answers; the host reaches neither.
pub fn check_listen(output: []const u8) Error!void {
    const wrong = error.ListenWrong;
    if (!expect_value(output, "LISTEN-A:", "LISTENING 0")) return wrong;
    if (!expect_value(output, "A-RC:", "0")) return wrong;
    if (!expect_value(output, "A-OUT:", "hello from supervisor")) return wrong;
    if (!expect_value(output, "CLOSE-A:", "CLOSED 0")) return wrong;
    if (!expect_value(output, "LISTEN-B:", "LISTENING 1")) return wrong;
    if (!expect_value(output, "B-OUT:", "hello from supervisor")) return wrong;
    if (!is_failure(output, "A-AFTER-RC:")) return wrong;
    if (!is_failure(output, "HOST-A:")) return wrong;
    if (!is_failure(output, "HOST-B:")) return wrong;
    if (!expect_value(output, "CLOSE-B:", "CLOSED 1")) return wrong;
}

/// A socket held before the adoption (ZB-8) connected to the server inside and exchanged a line.
pub fn check_connect(output: []const u8) Error!void {
    const wrong = error.ConnectWrong;
    if (!expect_value(output, "HOLD:", "HELD 3")) return wrong;
    if (!expect_value(output, "ADOPT:", "ADOPTED c4 running")) return wrong;
    if (!expect_value(output, "SERVER-UP:", "1")) return wrong;
    if (!expect_value(output, "DIAL:", "DIAL-REPLY 3 pong-from-inside")) return wrong;
    if (!expect_value(output, "SERVER-GOT:", "ping-from-supervisor")) return wrong;
    if (!expect_value(output, "SOCKET-AFTER:", "HELD 3")) return wrong;
}

/// ZB-7: a second `exec` connected to the first one's listener on 127.0.0.1, which the host
/// cannot reach, and the container has no address but its loopback's.
pub fn check_net(output: []const u8) Error!void {
    if (!expect_value(output, "SERVER-UP:", "1")) return error.NetWrong;
    if (!expect_value(output, "OTHER-EXEC:", "inside")) return error.NetWrong;
    if (!is_failure(output, "HOST-9100:")) return error.NetWrong;
    if (!expect_value(output, "ADDRS:", "1")) return error.NetWrong;
}

/// From inside: the supervisor's pid is not there and cannot be signalled, `kill -1` leaves the
/// supervisor and the container alive, and `/etc/hosts` is not writable.
pub fn check_hostile(output: []const u8) Error!void {
    const wrong = error.HostileWrong;
    const kill = value_of(output, "KILL-SUPERVISOR:") orelse return wrong;
    if (std.mem.indexOf(u8, kill, "No such process") == null) return wrong;
    if (std.mem.indexOf(u8, kill, "kill-rc=1") == null) return wrong;
    if (std.mem.indexOf(u8, kill, "No such file") == null) return wrong;
    const procs = value_of(output, "PROCS:") orelse return wrong;
    const count = std.fmt.parseInt(u32, procs, 10) catch return wrong;
    if (count == 0 or count > 5) return wrong;
    if (!expect_value(output, "KILL-ALL:", "ran")) return wrong;
    if (!expect_value(output, "SUPERVISOR:", "PONG")) return wrong;
    if (!expect_value(output, "CONTAINER:", "1")) return wrong;
    if (!is_failure(output, "WRITE-ETC-HOSTS:")) return wrong;
}

/// `--hosts-file` (ZB-6): bound read-only, an in-place rewrite is seen inside, a rename over the
/// path is not (the bind holds the old file), and three bad paths are refused with E0612.
pub fn check_hosts(output: []const u8) Error!void {
    const wrong = error.HostsWrong;
    if (!expect_value(output, "HOSTS-RC:", "0")) return wrong;
    if (!expect_value(output, "HOSTS-ERR:", "")) return wrong;
    const cat = value_of(output, "HOSTS-CAT:") orelse return wrong;
    if (!std.mem.eql(u8, cat, "127.0.0.1 localhost|10.9.9.9 svc.mesh|")) return wrong;
    if (!expect_value(output, "HOSTS-GETENT:", "['10.9.9.9']")) return wrong;
    if (!expect_value(output, "HOSTS-INPLACE:", "['10.9.9.10']")) return wrong;
    if (!expect_value(output, "HOSTS-RENAMED:", "['10.9.9.10']")) return wrong;
    if (!is_failure(output, "HOSTS-WRITE:")) return wrong;
    const keys = [_][]const u8{
        "HOSTS-REFUSED-NET:", "HOSTS-REFUSED-MISSING:", "HOSTS-REFUSED-DIR:",
    };
    for (keys) |key| {
        const rest = value_of(output, key) orelse return wrong;
        if (std.mem.indexOf(u8, rest, "error[ZBX-E0612]") == null) return wrong;
        if (std.mem.indexOf(u8, rest, "errno") != null) return wrong;
    }
}

const Refusal = struct { label: []const u8, code: []const u8 };

const refusals = [_]Refusal{
    .{ .label = "host", .code = "ZBX-E0610" },
    .{ .label = "unknown", .code = "ZBX-E0402" },
    .{ .label = "stopped", .code = "ZBX-E0220" },
};

/// Every refusal printed one `REFUSED <label>: <PREFIX> error[<code>]: ...` line, no `errno`.
pub fn check_refusals(output: []const u8) Error!void {
    for (refusals) |refusal| {
        var key_buffer: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buffer, "REFUSED {s}:", .{refusal.label}) catch {
            return error.RefusalWrong;
        };
        const rest = value_of(output, key) orelse return error.RefusalWrong;
        if (std.mem.indexOf(u8, rest, "error[") == null) return error.RefusalWrong;
        if (std.mem.indexOf(u8, rest, refusal.code) == null) return error.RefusalWrong;
        if (std.mem.indexOf(u8, rest, "errno") != null) return error.RefusalWrong;
    }
}

/// `text` with its first `swap[0]` replaced by `swap[1]`, for a test to free.
fn swapped(text: []const u8, swap: [2][]const u8) ![]u8 {
    std.debug.assert(std.mem.indexOf(u8, text, swap[0]) != null);
    return std.mem.replaceOwned(u8, std.testing.allocator, text, swap[0], swap[1]);
}

const start_good = "START-RC: 0\nSTART-ERR:\nLINKS: 1\nLINK-LO: 1\n";

test "start holds on the right output" {
    try check_start(start_good);
}

test "start fails on a failed run, stderr, or a second link" {
    const bad = [_][]const u8{
        "",
        "START-RC: 125\nSTART-ERR:\nLINKS: 1\nLINK-LO: 1\n",
        "START-RC: 0\nSTART-ERR: x\nLINKS: 1\nLINK-LO: 1\n",
        "START-RC: 0\nSTART-ERR:\nLINKS: 2\nLINK-LO: 1\n",
        "START-RC: 0\nSTART-ERR:\nLINKS: 1\nLINK-LO: 0\n",
    };
    for (bad) |text| try std.testing.expectError(error.StartWrong, check_start(text));
}

const listen_good =
    \\LISTEN-A: LISTENING 0
    \\A-RC: 0
    \\A-OUT: hello from supervisor
    \\CLOSE-A: CLOSED 0
    \\LISTEN-B: LISTENING 1
    \\B-OUT: hello from supervisor
    \\A-AFTER-RC: 1
    \\HOST-A: 111
    \\HOST-B: 111
    \\CLOSE-B: CLOSED 1
    \\
;

test "listen holds on the right output" {
    try check_listen(listen_good);
}

test "listen fails when a listener is missing, answered after close, or reached from the host" {
    const bad = [_][]const u8{
        "",
        "LISTEN-A: BIND-FAILED 0 ADDRNOTAVAIL\n",
        "LISTEN-A: LISTENING 0\nA-RC: 1\nA-OUT:\n",
        "LISTEN-A: LISTENING 0\nA-RC: 0\nA-OUT: hello from supervisor\nCLOSE-A: CLOSED 0\n" ++
            "LISTEN-B: LISTENING 1\nB-OUT: hello from supervisor\nA-AFTER-RC: 0\n",
    };
    for (bad) |text| try std.testing.expectError(error.ListenWrong, check_listen(text));
    const swaps = [_][2][]const u8{
        .{ "HOST-A: 111", "HOST-A: 0" },
        .{ "A-AFTER-RC: 1", "A-AFTER-RC: 0" },
    };
    for (swaps) |swap| {
        const text = try swapped(listen_good, swap);
        defer std.testing.allocator.free(text);
        try std.testing.expectError(error.ListenWrong, check_listen(text));
    }
}

const connect_good =
    \\HOLD: HELD 3
    \\ADOPT: ADOPTED c4 running
    \\SERVER-UP: 1
    \\DIAL: DIAL-REPLY 3 pong-from-inside
    \\SERVER-GOT: ping-from-supervisor
    \\SOCKET-AFTER: HELD 3
    \\
;

test "connect holds on the right output" {
    try check_connect(connect_good);
}

test "connect fails on a failed dial, adoption or a server that heard nothing" {
    const bad = [_][]const u8{
        "",
        "HOLD: HOLD-FAILED error[ZBX-E0611]: x\n",
        "HOLD: HELD 3\nADOPT: ADOPT-FAILED NoSuchContainer\n",
        "HOLD: HELD 3\nADOPT: ADOPTED c4 running\nSERVER-UP: 1\nDIAL: DIAL-FAILED 3 CONNREFUSED\n",
        "HOLD: HELD 3\nADOPT: ADOPTED c4 running\nSERVER-UP: 1\n" ++
            "DIAL: DIAL-REPLY 3 pong-from-inside\nSERVER-GOT:\n",
    };
    for (bad) |text| try std.testing.expectError(error.ConnectWrong, check_connect(text));
}

test "net holds on the right output and fails on the host's reach or a second address" {
    const good = "SERVER-UP: 1\nOTHER-EXEC: inside\nHOST-9100: 111\nADDRS: 1\n";
    try check_net(good);
    const bad = [_][]const u8{
        "",
        "SERVER-UP: 1\nOTHER-EXEC:\nHOST-9100: 111\nADDRS: 1\n",
        "SERVER-UP: 1\nOTHER-EXEC: inside\nHOST-9100: 0\nADDRS: 1\n",
        "SERVER-UP: 1\nOTHER-EXEC: inside\nHOST-9100: 111\nADDRS: 2\n",
    };
    for (bad) |text| try std.testing.expectError(error.NetWrong, check_net(text));
}

const hostile_good =
    \\PROCS: 2
    \\KILL-SUPERVISOR: kill: (4242) - No such process | kill-rc=1 | ls: /proc/4242: No such file
    \\KILL-ALL: ran
    \\SUPERVISOR: PONG
    \\CONTAINER: 1
    \\WRITE-ETC-HOSTS: 1
    \\
;

test "hostile holds on the right output" {
    try check_hostile(hostile_good);
}

test "hostile fails when the supervisor is visible, killed, or the hosts file is writable" {
    const swaps = [_][2][]const u8{
        .{ "No such process", "Operation not permitted" },
        .{ "kill-rc=1", "kill-rc=0" },
        .{ "SUPERVISOR: PONG", "SUPERVISOR:" },
        .{ "CONTAINER: 1", "CONTAINER: 0" },
        .{ "WRITE-ETC-HOSTS: 1", "WRITE-ETC-HOSTS: 0" },
        .{ "PROCS: 2", "PROCS: 40" },
    };
    for (swaps) |swap| {
        const text = try swapped(hostile_good, swap);
        defer std.testing.allocator.free(text);
        try std.testing.expectError(error.HostileWrong, check_hostile(text));
    }
}

const refusals_good =
    \\REFUSED host: HOLD-FAILED error[ZBX-E0610]: container 'c4h' shares the host's network
    \\REFUSED unknown: HOLD-FAILED error[ZBX-E0402]: no container named 'nope'
    \\REFUSED stopped: HOLD-FAILED error[ZBX-E0220]: container 'c4h' is not running
    \\
;

test "refusals hold on one coded line each and fail on a wrong code or an errno" {
    try check_refusals(refusals_good);
    const swaps = [_][2][]const u8{
        .{ "E0610", "E0611" },
        .{ "REFUSED stopped", "REFUSED stop" },
        .{ "is not running", "errno 3" },
    };
    for (swaps) |swap| {
        const text = try swapped(refusals_good, swap);
        defer std.testing.allocator.free(text);
        try std.testing.expectError(error.RefusalWrong, check_refusals(text));
    }
}
