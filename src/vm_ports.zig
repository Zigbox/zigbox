//! How published ports travel between the Mac and the guest (milestone M4b, slice 4). Pure text
//! and number handling, shared by the host process and the guest's port agent.
//!
//! The host keeps one connection to the guest's port agent (vsock `vm_ports_port`) and says
//! `watch\n` on it; the agent answers, and later whenever the set changes, with the guest ports
//! the user's `pasta` processes forward:
//!
//!     host: watch\n      agent: ports 8080 8081\n      (an empty set is `ports\n`)
//!     host: scan\n       agent: ports 8080 8081\n      (a look right now, always answered)
//!
//! Each connection the Mac accepts for a published port is one more vsock connection to the same
//! agent, which connects to that port inside the guest:
//!
//!     host: connect 8080\n      agent: ok\n and then the bytes both ways; or fail\n and a close
//!
//! The ports are found in the command line of `pasta`, as zbx starts it
//! (`pasta ... --tcp-ports HOST:CONTAINER ... PID`): the host port is the port in the guest.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const watch_request = "watch\n";
pub const scan_request = "scan\n";
pub const connect_ok = "ok\n";
pub const connect_failed = "fail\n";
const ports_prefix = "ports";
const scanned_prefix = "scanned";
const connect_prefix = "connect ";

pub const PortSet = struct {
    ports: [constants.vm_ports_max]u16 = undefined,
    count: u32 = 0,

    pub fn slice(set: *const PortSet) []const u16 {
        assert(set.count <= constants.vm_ports_max);
        return set.ports[0..set.count];
    }

    pub fn contains(set: *const PortSet, port: u16) bool {
        assert(set.count <= constants.vm_ports_max);
        for (set.slice()) |member| {
            if (member == port) return true;
        }
        return false;
    }

    /// Adds a port the set lacks; false when it is full.
    pub fn add(set: *PortSet, port: u16) bool {
        assert(port > 0);
        if (set.contains(port)) return true;
        if (set.count == constants.vm_ports_max) return false;
        set.ports[set.count] = port;
        set.count += 1;
        assert(set.count <= constants.vm_ports_max);
        return true;
    }
};

/// `ports 8080 8081\n`, ports in the order of the set: the news that the set changed.
pub fn render_ports(buffer: []u8, set: *const PortSet) []const u8 {
    assert(set.count <= constants.vm_ports_max);
    const text = render_with(buffer, ports_prefix, set);
    assert(text[text.len - 1] == '\n');
    return text;
}

/// `scanned 8080 8081\n`: the answer to `scan`, so that the host can tell it from news.
pub fn render_scanned(buffer: []u8, set: *const PortSet) []const u8 {
    assert(set.count <= constants.vm_ports_max);
    const text = render_with(buffer, scanned_prefix, set);
    assert(text[text.len - 1] == '\n');
    return text;
}

fn render_with(buffer: []u8, word: []const u8, set: *const PortSet) []const u8 {
    assert(buffer.len >= constants.vm_line_bytes_max);
    assert(set.count <= constants.vm_ports_max);
    var writer: std.Io.Writer = .fixed(buffer);
    // Cannot fail: 64 ports of at most six characters fit the line buffer of 512 bytes.
    writer.writeAll(word) catch unreachable;
    for (set.slice()) |port| writer.print(" {d}", .{port}) catch unreachable; // Same.
    writer.writeAll("\n") catch unreachable; // Same.
    return writer.buffered();
}

/// The set a `ports` line names; null for a line `render_ports` does not write.
pub fn parse_ports(line: []const u8) ?PortSet {
    const result = parse_with(line, ports_prefix);
    if (result) |set| assert(set.count <= constants.vm_ports_max);
    return result;
}

/// The set a `scanned` line names.
pub fn parse_scanned(line: []const u8) ?PortSet {
    const result = parse_with(line, scanned_prefix);
    if (result) |set| assert(set.count <= constants.vm_ports_max);
    return result;
}

fn parse_with(line: []const u8, name: []const u8) ?PortSet {
    assert(name.len > 0);
    if (line.len > constants.vm_line_bytes_max) return null;
    if (line.len == 0) return null;
    if (line[line.len - 1] != '\n') return null;
    const body = line[0 .. line.len - 1];
    if (!std.mem.startsWith(u8, body, name)) return null;
    var set: PortSet = .{};
    var words = std.mem.splitScalar(u8, body[name.len..], ' ');
    const first = words.next().?; // A split always has a first part; it is empty when none follows.
    if (first.len != 0) return null; // After "ports" comes a space or the end.
    while (words.next()) |word| {
        const port = port_of(word) orelse return null;
        if (set.contains(port)) return null; // A set names a port once, as render writes it.
        if (!set.add(port)) return null;
    }
    assert(set.count <= constants.vm_ports_max);
    return set;
}

/// A decimal port, 1 to 65535, no sign and no leading zero.
pub fn port_of(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > 5) return null;
    if (text[0] == '0') return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    const value = std.fmt.parseInt(u16, text, 10) catch return null;
    assert(value > 0);
    return value;
}

pub fn render_connect(buffer: []u8, port: u16) []const u8 {
    assert(buffer.len >= 16);
    assert(port > 0);
    // Cannot fail: a prefix, five digits and a newline fit sixteen bytes.
    return std.fmt.bufPrint(buffer, connect_prefix ++ "{d}\n", .{port}) catch unreachable;
}

pub fn parse_connect(line: []const u8) ?u16 {
    if (line.len > 16) return null;
    if (!std.mem.startsWith(u8, line, connect_prefix)) return null;
    if (line[line.len - 1] != '\n') return null;
    const port = port_of(line[connect_prefix.len .. line.len - 1]) orelse return null;
    assert(port > 0);
    return port;
}

/// The guest ports in the command line of a `pasta` process (`cmdline` is /proc/PID/cmdline:
/// arguments each ended by a NUL). Adds to `set`; false if the set filled up.
pub fn published_ports(cmdline: []const u8, set: *PortSet) bool {
    assert(set.count <= constants.vm_ports_max);
    assert(cmdline.len <= 64 * 1024);
    var arguments = std.mem.splitScalar(u8, cmdline, 0);
    while (arguments.next()) |argument| {
        if (!std.mem.eql(u8, argument, "--tcp-ports")) continue;
        const value = arguments.next() orelse return true;
        const colon = std.mem.indexOfScalar(u8, value, ':') orelse continue;
        const port = port_of(value[0..colon]) orelse continue; // "none" and the like.
        if (!set.add(port)) return false;
    }
    return true;
}

test "a ports line round-trips, the empty set included, and nothing else is read" {
    // Goal: parse_ports reads exactly what render_ports writes. Method: three sets, then lines
    // damaged in each way.
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    var set: PortSet = .{};
    try std.testing.expectEqualStrings("ports\n", render_ports(&buffer, &set));
    try std.testing.expectEqual(@as(u32, 0), parse_ports("ports\n").?.count);
    try std.testing.expect(set.add(8080));
    try std.testing.expect(set.add(65535));
    try std.testing.expect(set.add(8080)); // Twice is once.
    const text = render_ports(&buffer, &set);
    try std.testing.expectEqualStrings("ports 8080 65535\n", text);
    const back = parse_ports(text).?;
    try std.testing.expectEqualSlices(u16, set.slice(), back.slice());
    const bad = [_][]const u8{
        "",              "ports",            "ports 80",      "ports  80\n", "ports 0\n",
        "ports 65536\n", "ports 080\n",      "ports -1\n",    "portsx 80\n", "port 80\n",
        "ports 80 \n",   "ports 80\nmore\n", "ports 80,81\n",
    };
    for (bad) |line| try std.testing.expect(parse_ports(line) == null);
    const scanned = render_scanned(&buffer, &set);
    try std.testing.expectEqualStrings("scanned 8080 65535\n", scanned);
    try std.testing.expect(parse_ports(scanned) == null);
    try std.testing.expectEqual(@as(u32, 2), parse_scanned(scanned).?.count);
    var many: PortSet = .{};
    for (1..constants.vm_ports_max + 1) |port| try std.testing.expect(many.add(@intCast(port)));
    try std.testing.expect(!many.add(9000));
}

test "a connect request round-trips and refuses the rest" {
    // Goal: the one request a Mac connection makes. Method: the bounds of a port and bad text.
    var buffer: [16]u8 = undefined;
    for ([_]u16{ 1, 80, 8080, 65535 }) |port| {
        try std.testing.expectEqual(port, parse_connect(render_connect(&buffer, port)).?);
    }
    const bad = [_][]const u8{
        "connect 0\n",   "connect 65536\n", "connect 80",    "connect \n",
        "connect 8 0\n", "Connect 80\n",    "connect +80\n",
    };
    for (bad) |line| try std.testing.expect(parse_connect(line) == null);
}

test "the ports pasta forwards are found in its command line" {
    // Goal: the guest ports come from `--tcp-ports HOST:CONTAINER`, as zbx writes it (the line
    // below is the form in docs/demos/m5.md). Method: that line, one with two ports, one with
    // `--tcp-ports none`, and a cut one.
    const two = "pasta\x00--config-net\x00--tcp-ports\x008080:80\x00" ++
        "--tcp-ports\x009090:90\x00--udp-ports\x00none\x0042\x00";
    var set: PortSet = .{};
    try std.testing.expect(published_ports(two, &set));
    try std.testing.expectEqualSlices(u16, &.{ 8080, 9090 }, set.slice());
    var none: PortSet = .{};
    try std.testing.expect(published_ports("pasta\x00--tcp-ports\x00none\x0042\x00", &none));
    try std.testing.expectEqual(@as(u32, 0), none.count);
    var cut: PortSet = .{};
    try std.testing.expect(published_ports("pasta\x00--tcp-ports", &cut));
    try std.testing.expectEqual(@as(u32, 0), cut.count);
}
