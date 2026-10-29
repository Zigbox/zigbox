//! The DHCP packets of the guest's network setup (RFC 2131), as pure functions on bytes: the
//! DISCOVER and REQUEST the guest sends, and the parse of the OFFER and ACK it gets back. The
//! guest's init does the sockets; this file knows nothing of them, so the packets are tested
//! here, on any host.
//!
//! `parse_reply` accepts only a reply to this client's transaction, from a server, of the kind
//! asked for, with the options it needs; anything else (another client's, a short packet, a bad
//! cookie, an option that runs past the end) is null.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

const op_request: u8 = 1;
const op_reply: u8 = 2;
const hardware_ethernet: u8 = 1;
const flag_broadcast: u16 = 0x8000;
const cookie = [4]u8{ 0x63, 0x82, 0x53, 0x63 };
const fixed_bytes: usize = 236; // The BOOTP part before the cookie.
const options_at: usize = fixed_bytes + cookie.len;
/// Servers drop packets shorter than the BOOTP minimum.
const packet_bytes_min: usize = 300;

const option_subnet_mask: u8 = 1;
const option_router: u8 = 3;
const option_dns: u8 = 6;
const option_requested_address: u8 = 50;
const option_lease_time: u8 = 51;
const option_message_type: u8 = 53;
const option_server_identifier: u8 = 54;
const option_parameter_request: u8 = 55;
const option_end: u8 = 255;
const option_pad: u8 = 0;

pub const MessageType = enum(u8) { discover = 1, offer = 2, request = 3, ack = 5, nak = 6 };

pub const Address = [4]u8;

/// What the server's reply says.
pub const Lease = struct {
    kind: MessageType,
    address: Address,
    server: Address,
    mask: Address,
    router: ?Address,
    dns: ?Address,
    seconds: u32,
};

fn put_option(out: []u8, at: usize, code: u8, value: []const u8) usize {
    assert(at + 2 + value.len <= out.len);
    assert(value.len <= 255);
    out[at] = code;
    out[at + 1] = @intCast(value.len);
    @memcpy(out[at + 2 ..][0..value.len], value);
    return at + 2 + value.len;
}

fn begin(out: []u8, mac: [6]u8, transaction: u32) void {
    assert(out.len >= packet_bytes_min);
    assert(out.len >= constants.vm_dhcp_packet_bytes_max);
    @memset(out[0..packet_bytes_min], 0);
    out[0] = op_request;
    out[1] = hardware_ethernet;
    out[2] = 6;
    std.mem.writeInt(u32, out[4..8], transaction, .big);
    std.mem.writeInt(u16, out[10..12], flag_broadcast, .big);
    @memcpy(out[28..34], &mac);
    @memcpy(out[fixed_bytes..][0..4], &cookie);
}

fn finish(out: []u8, at: usize) []const u8 {
    assert(at < out.len);
    assert(out.len >= packet_bytes_min);
    out[at] = option_end;
    return out[0..@max(at + 1, packet_bytes_min)];
}

const wanted = [_]u8{ option_subnet_mask, option_router, option_dns, option_lease_time };

/// The DISCOVER packet.
pub fn render_discover(out: []u8, mac: [6]u8, transaction: u32) []const u8 {
    begin(out, mac, transaction);
    const kind = [1]u8{@backingInt(MessageType.discover)};
    var at = put_option(out, options_at, option_message_type, &kind);
    at = put_option(out, at, option_parameter_request, &wanted);
    return finish(out, at);
}

/// The REQUEST packet for the address the server offered.
pub fn render_request(
    out: []u8,
    mac: [6]u8,
    transaction: u32,
    address: Address,
    server: Address,
) []const u8 {
    begin(out, mac, transaction);
    var at = put_option(out, options_at, option_message_type, &.{@backingInt(MessageType.request)});
    at = put_option(out, at, option_requested_address, &address);
    at = put_option(out, at, option_server_identifier, &server);
    at = put_option(out, at, option_parameter_request, &wanted);
    return finish(out, at);
}

/// A reply to `transaction` from a server, or null.
pub fn parse_reply(packet: []const u8, mac: [6]u8, transaction: u32) ?Lease {
    if (packet.len < options_at + 1 or packet.len > constants.vm_dhcp_packet_bytes_max) return null;
    if (packet[0] != op_reply) return null;
    if (std.mem.readInt(u32, packet[4..8], .big) != transaction) return null;
    if (!std.mem.eql(u8, packet[28..34], &mac)) return null;
    if (!std.mem.eql(u8, packet[fixed_bytes..][0..4], &cookie)) return null;
    var lease: Lease = .{
        .kind = undefined,
        .address = packet[16..20].*,
        .server = undefined,
        .mask = .{ 255, 255, 255, 0 },
        .router = null,
        .dns = null,
        .seconds = 0,
    };
    var kind: ?MessageType = null;
    var server: ?Address = null;
    var at: usize = options_at;
    while (at < packet.len) {
        const code = packet[at];
        if (code == option_end) break;
        if (code == option_pad) {
            at += 1;
            continue;
        }
        if (at + 2 > packet.len) return null;
        const length: usize = packet[at + 1];
        if (at + 2 + length > packet.len) return null;
        const value = packet[at + 2 ..][0..length];
        at += 2 + length;
        switch (code) {
            option_message_type => {
                if (length != 1) return null;
                kind = std.enums.fromInt(MessageType, value[0]);
            },
            option_server_identifier => {
                if (length != 4) return null;
                server = value[0..4].*;
            },
            option_subnet_mask => {
                if (length != 4) return null;
                lease.mask = value[0..4].*;
            },
            option_router => {
                if (length >= 4) lease.router = value[0..4].*;
            },
            option_dns => {
                if (length >= 4) lease.dns = value[0..4].*;
            },
            option_lease_time => {
                if (length != 4) return null;
                lease.seconds = std.mem.readInt(u32, value[0..4], .big);
            },
            else => {},
        }
    }
    if (at >= packet.len) return null; // No end option: the packet is cut.
    lease.kind = kind orelse return null;
    lease.server = server orelse return null;
    if (lease.kind != .offer and lease.kind != .ack and lease.kind != .nak) return null;
    return lease;
}

/// The packet a server would send, for tests and the fuzzer.
pub fn render_reply(out: []u8, mac: [6]u8, transaction: u32, lease: *const Lease) []const u8 {
    begin(out, mac, transaction);
    out[0] = op_reply;
    @memcpy(out[16..20], &lease.address);
    var at = put_option(out, options_at, option_message_type, &.{@backingInt(lease.kind)});
    at = put_option(out, at, option_server_identifier, &lease.server);
    at = put_option(out, at, option_subnet_mask, &lease.mask);
    if (lease.router) |router| at = put_option(out, at, option_router, &router);
    if (lease.dns) |dns| at = put_option(out, at, option_dns, &dns);
    var seconds: [4]u8 = undefined;
    std.mem.writeInt(u32, &seconds, lease.seconds, .big);
    at = put_option(out, at, option_lease_time, &seconds);
    return finish(out, at);
}

const test_mac = [6]u8{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
const test_lease: Lease = .{
    .kind = .offer,
    .address = .{ 192, 168, 64, 7 },
    .server = .{ 192, 168, 64, 1 },
    .mask = .{ 255, 255, 255, 0 },
    .router = .{ 192, 168, 64, 1 },
    .dns = .{ 192, 168, 64, 1 },
    .seconds = 86400,
};

test "discover and request are well-formed BOOTP packets of at least 300 bytes" {
    // Goal: what a server needs to answer. Method: render both and read the fields back.
    var out: [constants.vm_dhcp_packet_bytes_max]u8 = @splat(0xaa);
    const discover = render_discover(&out, test_mac, 0xdeadbeef);
    try std.testing.expect(discover.len >= packet_bytes_min);
    try std.testing.expectEqual(@as(u8, 1), discover[0]);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), std.mem.readInt(u32, discover[4..8], .big));
    try std.testing.expectEqualSlices(u8, &test_mac, discover[28..34]);
    try std.testing.expectEqualSlices(u8, &cookie, discover[236..240]);
    try std.testing.expectEqual(option_message_type, discover[240]);
    try std.testing.expectEqual(@as(u8, 1), discover[242]);
    var again: [constants.vm_dhcp_packet_bytes_max]u8 = @splat(0x55);
    const request = render_request(&again, test_mac, 7, .{ 10, 0, 0, 5 }, .{ 10, 0, 0, 1 });
    try std.testing.expectEqual(@as(u8, 3), request[242]);
    try std.testing.expect(std.mem.indexOf(u8, request, &.{ 50, 4, 10, 0, 0, 5 }) != null);
}

test "an offer round-trips and every wrong reply is refused" {
    // Goal: parse accepts only a reply to this transaction. Method: a good reply, then another
    // transaction, another MAC, a request instead of a reply, a short packet, a cut option and a
    // missing server identifier.
    var out: [constants.vm_dhcp_packet_bytes_max]u8 = undefined;
    const packet = render_reply(&out, test_mac, 42, &test_lease);
    try std.testing.expectEqual(test_lease, parse_reply(packet, test_mac, 42).?);
    try std.testing.expect(parse_reply(packet, test_mac, 43) == null);
    try std.testing.expect(parse_reply(packet, .{ 1, 2, 3, 4, 5, 6 }, 42) == null);
    var copy: [constants.vm_dhcp_packet_bytes_max]u8 = undefined;
    @memcpy(copy[0..packet.len], packet);
    copy[0] = 1;
    try std.testing.expect(parse_reply(copy[0..packet.len], test_mac, 42) == null);
    @memcpy(copy[0..packet.len], packet);
    copy[236] = 0;
    try std.testing.expect(parse_reply(copy[0..packet.len], test_mac, 42) == null);
    try std.testing.expect(parse_reply(packet[0..200], test_mac, 42) == null);
    var cut = test_lease;
    cut.router = null;
    cut.dns = null;
    const small = render_reply(&out, test_mac, 42, &cut);
    try std.testing.expect(parse_reply(small, test_mac, 42) != null);
    @memcpy(copy[0..small.len], small);
    copy[241] = 200; // The message type option now claims more bytes than the packet has.
    try std.testing.expect(parse_reply(copy[0..small.len], test_mac, 42) == null);
}
