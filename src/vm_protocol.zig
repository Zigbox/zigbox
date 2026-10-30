//! What the macOS `zbx` and the guest's init say to each other over vsock, one line at a time.
//! Shared by both sides (and so free of anything but `std`): the guest is a Linux program, the
//! host a macOS one. The version in the answer is the VM image's, so the host can tell that the
//! guest it reached is the one it shipped.
//!
//!     host:  hello\n                     guest: zbx-vm/1 <image version>\n
//!     host:  shutdown\n                  guest: bye\n   (then it syncs and powers off)
//!     host:  setup <seconds> <uid> <gid> <name> <home> <dns>\n
//!                                        guest: ok net=up\n | ok net=down\n | fail <word>\n
//!     host:  busy\n                      guest: busy <count>\n   (0: nothing runs for the user)

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const hello_request = "hello\n";
pub const shutdown_request = "shutdown\n";
pub const shutdown_reply = "bye\n";
pub const reply_prefix = "zbx-vm/1 ";

comptime {
    assert(hello_request.len < constants.vm_line_bytes_max);
    assert(reply_prefix.len + constants.vm_image_version_bytes + 1 <= constants.vm_line_bytes_max);
}

/// True for exactly the text an image version is: lowercase hex digits, no more, no fewer.
pub fn is_version(text: []const u8) bool {
    if (text.len != constants.vm_image_version_bytes) return false;
    for (text) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// The guest's answer to `hello`: the prefix, the version and a newline.
pub fn render_hello_reply(buffer: []u8, version: []const u8) []const u8 {
    assert(is_version(version));
    assert(buffer.len >= reply_prefix.len + version.len + 1);
    const fmt = "{s}{s}\n";
    const arguments = .{ reply_prefix, version };
    // Cannot fail: the buffer was asserted to hold the prefix, the version and a newline.
    const written = std.fmt.bufPrint(buffer, fmt, arguments) catch unreachable;
    assert(written.len == reply_prefix.len + constants.vm_image_version_bytes + 1);
    return written;
}

/// The version in a guest's answer; null for anything `render_hello_reply` does not write.
pub fn parse_hello_reply(line: []const u8) ?[]const u8 {
    if (line.len != reply_prefix.len + constants.vm_image_version_bytes + 1) return null;
    if (!std.mem.startsWith(u8, line, reply_prefix)) return null;
    if (line[line.len - 1] != '\n') return null;
    const version = line[reply_prefix.len .. line.len - 1];
    if (!is_version(version)) return null;
    return version;
}

test "the guest's answer round-trips and nothing else parses" {
    // Goal: parse accepts only what render writes. Method: a good reply, then each way to
    // damage it (prefix, length, case, newline, junk after).
    var buffer: [64]u8 = @splat(0xaa);
    const reply = render_hello_reply(&buffer, "0123456789abcdef");
    try std.testing.expectEqualStrings("zbx-vm/1 0123456789abcdef\n", reply);
    try std.testing.expectEqualStrings("0123456789abcdef", parse_hello_reply(reply).?);
    try std.testing.expect(parse_hello_reply("zbx-vm/2 0123456789abcdef\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcde\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdeF\n") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdef") == null);
    try std.testing.expect(parse_hello_reply("zbx-vm/1 0123456789abcdef\n\n") == null);
    try std.testing.expect(parse_hello_reply("") == null);
}

pub const busy_request = "busy\n";

/// Whether a connection's peer is the host. The guest answers nobody else.
pub fn from_host(peer_cid: u32) bool {
    return peer_cid == constants.vm_host_cid;
}

test "only the host's address is the host" {
    // Goal: the one comparison both guest listeners make. Method: the host, the guest's own
    // address, the wildcard, the hypervisor's reserved address and the largest.
    try std.testing.expect(from_host(2));
    try std.testing.expect(!from_host(3));
    try std.testing.expect(!from_host(0));
    try std.testing.expect(!from_host(1));
    try std.testing.expect(!from_host(0xffff_ffff));
}

/// What the host tells the guest once it is up: the Mac's wall clock (the guest has no RTC, and
/// TLS needs the time) and the user the commands run as, with the Mac user's own name, ids and
/// home path, so that paths and ownership read the same on both sides.
pub const Setup = struct {
    seconds: u64,
    uid: u32,
    gid: u32,
    name: []const u8,
    home: []const u8,
    /// The Mac's own resolvers (IPv4), "a.b.c.d,e.f.g.h", or "-" for none. The NAT's gateway is
    /// not always a resolver, so the guest asks the ones the Mac asks.
    dns: []const u8,
};

pub const dns_count_max: u32 = 3;

/// The addresses in a `dns` field: "-" is none; otherwise up to three dotted quads, comma
/// separated, none with a leading zero. Null for anything else.
pub fn parse_dns(text: []const u8, out: *[dns_count_max][4]u8) ?u32 {
    if (std.mem.eql(u8, text, "-")) return 0;
    var count: u32 = 0;
    var entries = std.mem.splitScalar(u8, text, ',');
    while (entries.next()) |entry| {
        if (count == dns_count_max) return null;
        var parts = std.mem.splitScalar(u8, entry, '.');
        for (0..4) |index| {
            const part = parts.next() orelse return null;
            const value = parse_number(u8, part) orelse return null;
            out[count][index] = value;
        }
        if (parts.next() != null) return null;
        count += 1;
    }
    assert(count >= 1); // A text that is not "-" has at least one address.
    assert(count <= dns_count_max);
    return count;
}

/// The resolvers the guest falls back to when the Mac gives it none (the `dns` field is "-"):
/// Cloudflare's and Google's public ones. A Mac whose only resolver is an IPv6 router (a router
/// advertising only an fe80:: address) leaves the guest with the NAT gateway, which does not
/// answer DNS; without these, every name fails to resolve. They follow the gateway, and are used
/// only in that case: a Mac with an IPv4 resolver never sends a query to a public resolver.
pub const dns_fallback = [_][4]u8{ .{ 1, 1, 1, 1 }, .{ 8, 8, 8, 8 } };

/// "nameserver 255.255.255.255\n", the longest line `resolv_conf` writes.
const nameserver_line_bytes_max: usize = 27;

/// The most nameservers in the file: the Mac's, or the fallback, and the DHCP one.
const nameservers_max: usize = @as(usize, @max(dns_count_max, dns_fallback.len)) + 1;

pub const resolv_conf_bytes_max: usize = nameservers_max * nameserver_line_bytes_max;

/// The guest's `/etc/resolv.conf`. With the Mac's resolvers (`mac_dns` a list): theirs first, then
/// the DHCP one (`gateway`, if the lease named one). With "-": the DHCP one first, then
/// `dns_fallback`. `mac_dns` has passed `parse_dns`. The text is written into `out`.
pub fn resolv_conf(
    out: *[resolv_conf_bytes_max]u8,
    mac_dns: []const u8,
    gateway: ?[4]u8,
) []const u8 {
    var addresses: [dns_count_max][4]u8 = undefined;
    const count = parse_dns(mac_dns, &addresses) orelse 0;
    var lines: u32 = 0;
    var length: usize = 0;
    if (count == 0) {
        if (gateway) |address| length += nameserver_line(out[length..], address, &lines);
        for (dns_fallback) |address| length += nameserver_line(out[length..], address, &lines);
    } else {
        for (addresses[0..count]) |address| {
            length += nameserver_line(out[length..], address, &lines);
        }
        if (gateway) |address| length += nameserver_line(out[length..], address, &lines);
    }
    assert(lines <= nameservers_max); // Every line is a nameserver, and the buffer fits them all.
    assert(length <= lines * nameserver_line_bytes_max);
    return out[0..length];
}

fn nameserver_line(out: []u8, address: [4]u8, lines: *u32) usize {
    const text = std.fmt.bufPrint(out, "nameserver {d}.{d}.{d}.{d}\n", .{
        address[0], address[1], address[2], address[3],
    }) catch unreachable; // Cannot fail: `resolv_conf_bytes_max` holds every line that is written.
    lines.* += 1;
    return text.len;
}

/// A name that is safe as a /etc/passwd field and as an argument: letters, digits, `_`, `.`, `-`,
/// not starting with `-`.
pub fn name_ok(name: []const u8) bool {
    if (name.len == 0 or name.len > constants.vm_user_name_bytes_max) return false;
    if (name[0] == '-') return false;
    for (name) |byte| {
        const plain = std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '.' or byte == '-';
        if (!plain) return false;
    }
    return true;
}

/// An absolute path with no byte that would break a passwd line or a protocol line.
pub fn home_ok(home: []const u8) bool {
    if (home.len < 2 or home.len > constants.vm_home_bytes_max) return false;
    if (home[0] != '/') return false;
    for (home) |byte| {
        if (byte <= ' ' or byte == ':' or byte == 0x7f) return false;
    }
    return true;
}

pub fn render_setup(buffer: []u8, setup: *const Setup) []const u8 {
    assert(name_ok(setup.name));
    assert(home_ok(setup.home));
    assert(setup.uid > 0);
    assert(buffer.len >= constants.vm_line_bytes_max);
    // Cannot fail: the name and the home are bounded so that the line fits (constants.zig).
    var addresses: [dns_count_max][4]u8 = undefined;
    assert(parse_dns(setup.dns, &addresses) != null);
    return std.fmt.bufPrint(buffer, "setup {d} {d} {d} {s} {s} {s}\n", .{
        setup.seconds, setup.uid, setup.gid, setup.name, setup.home, setup.dns,
    }) catch unreachable; // Cannot fail: the bounds above keep the line within the buffer.
}

pub fn parse_setup(line: []const u8) ?Setup {
    if (line.len == 0 or line.len > constants.vm_line_bytes_max) return null;
    if (line[line.len - 1] != '\n') return null;
    var words = std.mem.splitScalar(u8, line[0 .. line.len - 1], ' ');
    if (!std.mem.eql(u8, words.next() orelse return null, "setup")) return null;
    const seconds = parse_number(u64, words.next() orelse return null) orelse return null;
    const uid = parse_number(u32, words.next() orelse return null) orelse return null;
    const gid = parse_number(u32, words.next() orelse return null) orelse return null;
    const name = words.next() orelse return null;
    const home = words.next() orelse return null;
    const dns = words.next() orelse return null;
    if (words.next() != null) return null;
    var addresses: [dns_count_max][4]u8 = undefined;
    if (parse_dns(dns, &addresses) == null) return null;
    if (uid == 0 or !name_ok(name) or !home_ok(home)) return null;
    return .{ .seconds = seconds, .uid = uid, .gid = gid, .name = name, .home = home, .dns = dns };
}

fn parse_number(comptime T: type, text: []const u8) ?T {
    if (text.len == 0 or text.len > 20) return null;
    if (text.len > 1 and text[0] == '0') return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(T, text, 10) catch null;
}

/// The guest's answer to `setup`.
pub const SetupReply = union(enum) {
    ok: struct { network_up: bool },
    failed,
};

pub const setup_ok_up = "ok net=up\n";
pub const setup_ok_down = "ok net=down\n";
pub const setup_failed_prefix = "fail ";

pub fn parse_setup_reply(line: []const u8) ?SetupReply {
    if (std.mem.eql(u8, line, setup_ok_up)) return .{ .ok = .{ .network_up = true } };
    if (std.mem.eql(u8, line, setup_ok_down)) return .{ .ok = .{ .network_up = false } };
    if (!std.mem.startsWith(u8, line, setup_failed_prefix)) return null;
    if (line.len <= setup_failed_prefix.len + 1 or line[line.len - 1] != '\n') return null;
    if (line.len > constants.vm_line_bytes_max) return null;
    return .failed;
}

pub fn render_busy_reply(buffer: []u8, count: u32) []const u8 {
    assert(buffer.len >= 32);
    // Cannot fail: a u32 has at most ten digits.
    return std.fmt.bufPrint(buffer, "busy {d}\n", .{count}) catch unreachable;
}

/// The number of the user's processes the guest counts, or null for anything but its reply.
pub fn parse_busy_reply(line: []const u8) ?u32 {
    const prefix = "busy ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    if (line.len <= prefix.len + 1 or line[line.len - 1] != '\n') return null;
    return parse_number(u32, line[prefix.len .. line.len - 1]);
}

test "a setup line round-trips and a bad name, home, id or shape is refused" {
    // Goal: parse accepts only what render writes. Method: a good line, then each field wrong.
    var buffer: [constants.vm_line_bytes_max]u8 = undefined;
    const setup: Setup = .{
        .seconds = 1761700000,
        .uid = 501,
        .gid = 20,
        .name = "ada",
        .home = "/Users/ada",
        .dns = "192.168.1.1,10.0.0.2",
    };
    const line = render_setup(&buffer, &setup);
    const expected = "setup 1761700000 501 20 ada /Users/ada 192.168.1.1,10.0.0.2\n";
    try std.testing.expectEqualStrings(expected, line);
    const parsed = parse_setup(line).?;
    try std.testing.expectEqual(setup.seconds, parsed.seconds);
    try std.testing.expectEqual(setup.uid, parsed.uid);
    try std.testing.expectEqualStrings(setup.name, parsed.name);
    try std.testing.expectEqualStrings(setup.home, parsed.home);
    const bad = [_][]const u8{
        "",
        "setup 1 501 20 ada /Users/ada -",
        "setup 1 0 20 ada /Users/ada -\n",
        "setup 01 501 20 ada /Users/ada -\n",
        "setup 1 501 20 -ada /Users/ada -\n",
        "setup 1 501 20 a:da /Users/ada -\n",
        "setup 1 501 20 ada Users/ada -\n",
        "setup 1 501 20 ada /Users/a:da -\n",
        "setup 1 501 20 ada /Users/ada - extra\n",
        "setup 1 501 20 ada /Users/ada\n",
        "setup 1 501 20 ada\n",
        "setup x 501 20 ada /Users/ada -\n",
        "setup 1 501 20 ada /Users/ada 1.2.3\n",
        "setup 1 501 20 ada /Users/ada 1.2.3.256\n",
        "setup 1 501 20 ada /Users/ada 01.2.3.4\n",
        "setup 1 501 20 ada /Users/ada 1.2.3.4,1.2.3.4,1.2.3.4,1.2.3.4\n",
        "setup 1 501 20 ada /Users/ada 1.2.3.4,\n",
    };
    for (bad) |text| try std.testing.expect(parse_setup(text) == null);
}

test "the setup and busy answers parse only as written" {
    // Goal: the two answers the host reads. Method: each good form, then near misses.
    try std.testing.expectEqual(true, parse_setup_reply(setup_ok_up).?.ok.network_up);
    try std.testing.expectEqual(false, parse_setup_reply(setup_ok_down).?.ok.network_up);
    try std.testing.expectEqual(SetupReply.failed, parse_setup_reply("fail clock\n").?);
    try std.testing.expect(parse_setup_reply("fail \n") == null);
    try std.testing.expect(parse_setup_reply("ok net=maybe\n") == null);
    var buffer: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 3), parse_busy_reply(render_busy_reply(&buffer, 3)).?);
    try std.testing.expectEqual(@as(u32, 0), parse_busy_reply("busy 0\n").?);
    try std.testing.expect(parse_busy_reply("busy 03\n") == null);
    try std.testing.expect(parse_busy_reply("busy \n") == null);
    try std.testing.expect(parse_busy_reply("idle\n") == null);
}

test "resolv.conf: the Mac leads, or the fallback follows the gateway" {
    var out: [resolv_conf_bytes_max]u8 = undefined;
    const gateway: [4]u8 = .{ 192, 168, 64, 1 };
    try std.testing.expectEqualStrings(
        "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 192.168.64.1\n",
        resolv_conf(&out, "10.0.0.1,10.0.0.2", gateway),
    );
    try std.testing.expectEqualStrings(
        "nameserver 192.168.64.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n",
        resolv_conf(&out, "-", gateway),
    );
    try std.testing.expectEqualStrings(
        "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
        resolv_conf(&out, "-", null),
    );
    // The longest case: three Mac resolvers and a gateway, all of the widest lines.
    const widest = "255.255.255.255,255.255.255.255,255.255.255.255";
    const text = resolv_conf(&out, widest, .{ 255, 255, 255, 255 });
    try std.testing.expectEqual(resolv_conf_bytes_max, text.len);
}
