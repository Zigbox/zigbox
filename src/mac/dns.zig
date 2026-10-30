//! The Mac's own DNS resolvers, from the system configuration (the same source `scutil --dns`
//! reads), for the guest to use. The NAT gateway the guest is given by DHCP does not always
//! answer DNS queries; the resolvers the Mac asks (the router, a VPN's) are reachable through the
//! NAT. Only IPv4 addresses are kept: the guest's NAT network is IPv4. A Mac with none (its only
//! resolver is an IPv6 router) gives the field "-", and the guest then also asks the public
//! resolvers of `vm_protocol.dns_fallback`; `none()` says so, for the warning W1003.

const std = @import("std");
const assert = std.debug.assert;
const objc = @import("objc.zig");
const protocol = @import("../vm_protocol.zig");

extern "c" fn SCDynamicStoreCreate(
    allocator: ?*anyopaque,
    name: objc.Id,
    callout: ?*anyopaque,
    context: ?*anyopaque,
) ?*anyopaque;
extern "c" fn SCDynamicStoreCopyValue(store: ?*anyopaque, key: objc.Id) objc.Id;
extern "c" fn CFRelease(object: ?*anyopaque) void;

/// The resolvers as the `dns` field of the setup line: "a.b.c.d,e.f.g.h", or "-" if there are
/// none. Written into `buffer`.
pub fn resolvers(buffer: []u8) []const u8 {
    assert(buffer.len >= 64);
    const pool = objc.Pool.push();
    defer pool.pop();
    const store = SCDynamicStoreCreate(null, objc.string("zbx"), null, null) orelse {
        return "-";
    };
    defer CFRelease(store);
    const value = SCDynamicStoreCopyValue(store, objc.string("State:/Network/Global/DNS"));
    if (value == null) return "-";
    defer CFRelease(value);
    const list = objc.send(objc.Id, value, "objectForKey:", .{objc.string("ServerAddresses")});
    if (list == null) return "-";
    return join(buffer, list);
}

/// Whether the Mac gives the guest no IPv4 resolver, so that the guest falls back to public ones.
pub fn none() bool {
    var buffer: [64]u8 = undefined;
    return std.mem.eql(u8, resolvers(&buffer), "-");
}

fn join(buffer: []u8, list: objc.Id) []const u8 {
    const count = objc.send(u64, list, "count", .{});
    var length: usize = 0;
    var kept: u32 = 0;
    var index: u64 = 0;
    while (index < count and kept < protocol.dns_count_max) : (index += 1) {
        const item = objc.send(objc.Id, list, "objectAtIndex:", .{index});
        var text: [64]u8 = undefined;
        const address = objc.copy_text(item, &text);
        var parsed: [protocol.dns_count_max][4]u8 = undefined;
        const valid = protocol.parse_dns(address, &parsed) orelse continue;
        if (valid != 1) continue; // An IPv6 address, or a list.
        const separator: usize = if (kept > 0) 1 else 0;
        if (length + separator + address.len > buffer.len) break;
        if (separator == 1) buffer[length] = ',';
        @memcpy(buffer[length + separator ..][0..address.len], address);
        length += separator + address.len;
        kept += 1;
        assert(kept <= protocol.dns_count_max);
        assert(length <= buffer.len);
    }
    if (kept == 0) return "-";
    return buffer[0..length];
}

test "the Mac's resolvers come out as a field the guest accepts" {
    // Goal: whatever the system says, the result passes the guest's parser. Method: ask this Mac.
    var buffer: [128]u8 = undefined;
    const field = resolvers(&buffer);
    var parsed: [protocol.dns_count_max][4]u8 = undefined;
    try std.testing.expect(protocol.parse_dns(field, &parsed) != null);
}
