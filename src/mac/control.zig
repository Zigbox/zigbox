//! What `zbx vm status` and `zbx vm stop` say to the process that owns the VM, over a Unix
//! socket in the VM directory: one request line, one answer line.
//!
//!     client: status\n   host: zbx-vm-host/2 state=running pid=412 cpus=4 \
//!                               memory_bytes=2147483648 version=<16 hex> net=up uptime_ms=1530\n
//!     client: stop\n     host: zbx-vm-host/2 stopping\n   (then it stops the VM and exits)
//!     client: connect\n  host: ok\n, with a connected vsock descriptor to the guest's command
//!                               service attached (SCM_RIGHTS); or fail <word>\n
//!
//! `parse_reply` accepts only what `render_status` and `render_stopping` write.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const protocol = @import("../vm_protocol.zig");

pub const status_request = "status\n";
pub const stop_request = "stop\n";
pub const connect_request = "connect\n";
pub const connect_ok = "ok\n";
pub const connect_failed_prefix = "fail ";

pub const Request = enum { status, stop, connect };

pub fn parse_request(line: []const u8) ?Request {
    if (line.len > constants.vm_line_bytes_max) return null;
    assert(line.len <= constants.vm_line_bytes_max);
    if (std.mem.eql(u8, line, status_request)) return .status;
    if (std.mem.eql(u8, line, stop_request)) return .stop;
    if (std.mem.eql(u8, line, connect_request)) return .connect;
    return null;
}

pub const State = enum { starting, running, stopping };

pub const Status = struct {
    state: State,
    pid: u32,
    cpus: u32,
    memory_bytes: u64,
    version: [constants.vm_image_version_bytes]u8,
    /// Whether the guest got an address by DHCP.
    network_up: bool,
    /// Time since the guest answered; zero before it has.
    uptime_ms: u64,
};

pub const Reply = union(enum) {
    status: Status,
    stopping,
    /// A host of another release answers in a format this one does not read. It is replaced
    /// like a machine of another image, by `stop`, which every release understands.
    other_format,
};

const family = "zbx-vm-host/";
const prefix = family ++ "2 ";
/// A time past this is a clock gone wrong, not an uptime.
const uptime_ms_max: u64 = 1 << 40;
const stopping_line = prefix ++ "stopping\n";

pub fn render_status(buffer: []u8, status: *const Status) []const u8 {
    assert(buffer.len >= constants.vm_line_bytes_max);
    assert(protocol.is_version(&status.version));
    assert(status.uptime_ms < uptime_ms_max);
    assert(status.pid > 0);
    // Cannot fail: a prefix and six short fields fit the line.
    return std.fmt.bufPrint(
        buffer,
        "{s}state={s} pid={d} cpus={d} memory_bytes={d} version={s} net={s} uptime_ms={d}\n",
        .{
            prefix,                                  @tagName(status.state), status.pid,
            status.cpus,                             status.memory_bytes,    &status.version,
            if (status.network_up) "up" else "down", status.uptime_ms,
        },
    ) catch unreachable; // Cannot fail: a prefix and six short fields fit the line.
}

pub fn render_stopping() []const u8 {
    assert(stopping_line.len < constants.vm_line_bytes_max);
    return stopping_line;
}

pub fn parse_reply(line: []const u8) ?Reply {
    if (line.len > constants.vm_line_bytes_max) return null;
    assert(line.len <= constants.vm_line_bytes_max);
    if (std.mem.eql(u8, line, stopping_line)) return .stopping;
    if (!std.mem.startsWith(u8, line, prefix)) {
        const other = std.mem.startsWith(u8, line, family) and line[line.len - 1] == '\n';
        return if (other) .other_format else null;
    }
    if (line[line.len - 1] != '\n') return null;
    var words = std.mem.splitScalar(u8, line[prefix.len .. line.len - 1], ' ');
    const state_word = field(&words, "state") orelse return null;
    const state = std.meta.stringToEnum(State, state_word) orelse return null;
    var status: Status = undefined;
    status.state = state;
    status.pid = number(u32, field(&words, "pid") orelse return null) orelse return null;
    status.cpus = number(u32, field(&words, "cpus") orelse return null) orelse return null;
    const memory_text = field(&words, "memory_bytes") orelse return null;
    status.memory_bytes = number(u64, memory_text) orelse return null;
    const version = field(&words, "version") orelse return null;
    if (!protocol.is_version(version)) return null;
    @memcpy(&status.version, version);
    const net = field(&words, "net") orelse return null;
    if (!std.mem.eql(u8, net, "up") and !std.mem.eql(u8, net, "down")) return null;
    status.network_up = std.mem.eql(u8, net, "up");
    const uptime_text = field(&words, "uptime_ms") orelse return null;
    status.uptime_ms = number(u64, uptime_text) orelse return null;
    if (words.next() != null) return null;
    if (status.pid == 0 or status.uptime_ms >= uptime_ms_max) return null;
    return .{ .status = status };
}

fn field(words: *std.mem.SplitIterator(u8, .scalar), key: []const u8) ?[]const u8 {
    assert(key.len > 0);
    const word = words.next() orelse return null;
    if (word.len <= key.len + 1) return null;
    if (!std.mem.startsWith(u8, word, key)) return null;
    if (word[key.len] != '=') return null;
    return word[key.len + 1 ..];
}

fn number(comptime T: type, text: []const u8) ?T {
    if (text.len > 20) return null; // More digits than a u64 has.
    assert(text.len <= 20);
    if (text.len == 0) return null;
    if (text.len > 1 and text[0] == '0') return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(T, text, 10) catch null;
}

test "requests parse only as written" {
    // Goal: the request line is exact. Method: each request, then near misses.
    try std.testing.expectEqual(Request.status, parse_request("status\n").?);
    try std.testing.expectEqual(Request.stop, parse_request("stop\n").?);
    try std.testing.expect(parse_request("status") == null);
    try std.testing.expect(parse_request("STATUS\n") == null);
    try std.testing.expect(parse_request("status\nstop\n") == null);
    try std.testing.expect(parse_request("") == null);
}

test "a status reply round-trips and damaged ones are refused" {
    // Goal: parse accepts only what render writes. Method: a round trip for each state and each
    // network answer, then damage: a missing field, a swapped order, a bad version, a leading
    // zero, a bad network word, a tail.
    var buffer: [constants.vm_line_bytes_max]u8 = @splat(0xaa);
    for (std.enums.values(State)) |state| {
        for ([_]bool{ true, false }) |network_up| {
            const status: Status = .{
                .state = state,
                .pid = 4121,
                .cpus = 4,
                .memory_bytes = 2 << 30,
                .version = "0123456789abcdef".*,
                .network_up = network_up,
                .uptime_ms = 1530,
            };
            const line = render_status(&buffer, &status);
            try std.testing.expectEqual(status, parse_reply(line).?.status);
        }
    }
    try std.testing.expectEqual(Reply.stopping, parse_reply(render_stopping()).?);
    const head = "zbx-vm-host/2 state=running pid=4 cpus=4 memory_bytes=1 ";
    const tail = "version=0123456789abcdef net=up uptime_ms=1";
    try std.testing.expect(parse_reply(head ++ tail ++ "\n") != null);
    const bad = [_][]const u8{
        "",
        "zbx-vm-host/2 state=running\n",
        "zbx-vm-host/2 state=sleeping pid=4 cpus=4 memory_bytes=1 " ++ tail ++ "\n",
        "zbx-vm-host/2 state=running cpus=4 pid=4 memory_bytes=1 " ++ tail ++ "\n",
        "zbx-vm-host/2 state=running pid=0 cpus=4 memory_bytes=1 " ++ tail ++ "\n",
        "zbx-vm-host/2 state=running pid=04 cpus=4 memory_bytes=1 " ++ tail ++ "\n",
        head ++ "version=0123456789ABCDEF net=up uptime_ms=1\n",
        head ++ "version=0123456789abcdef net=maybe uptime_ms=1\n",
        head ++ "version=0123456789abcdef uptime_ms=1\n",
        head ++ tail ++ " x=1\n",
        head ++ tail,
        head ++ "version=0123456789abcdef net=up uptime_ms=1099511627776\n",
        "zbx-vm-host/2 stopping",
    };
    for (bad) |line| try std.testing.expect(parse_reply(line) == null);
}

test "a line captured from a real slice 1 host is another format, not garbage" {
    // Goal: a newer zbx meets a host of the release before it (REVIEW.md: older records stay
    // readable). The line below was read from the control socket of a running slice 1 host
    // (2 CPUs, 1536 MiB) on 2026-10-29; the new reader cannot parse it, and says so, so that
    // the machine is stopped and replaced like one of another image.
    const captured = "zbx-vm-host/1 state=running pid=75610 cpus=2 memory_bytes=1610612736 " ++
        "version=8faf0982c2757619 uptime_ms=38\n";
    try std.testing.expectEqual(Reply.other_format, parse_reply(captured).?);
    try std.testing.expect(parse_reply("zbx-vm-host/1 state=running") == null);
}

test "the connect request parses as written" {
    // Goal: the third request. Method: exact text only.
    try std.testing.expectEqual(Request.connect, parse_request("connect\n").?);
    try std.testing.expect(parse_request("connect") == null);
}
