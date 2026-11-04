//! TCP forwards from the host into a guest: QEMU's user-mode network `hostfwd=` option. Zigcube's
//! demo-c2 runs several guests and sends peer traffic guest -> host -> guest, so each guest
//! publishes the ports its peers dial on the host's loopback address.
//!
//! Host port 0 (let QEMU pick) is refused: QEMU runs with `-monitor none`, so the harness has no
//! channel to learn which port it chose. Callers name every host port. See
//! docs/decisions/2026-11-04-z7-hostfwd-explicit-ports.md.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");

pub const Forward = struct {
    /// The host address QEMU listens on. Loopback by default: a forward is for the harness and its
    /// sibling guests, never for the network.
    host_address: [4]u8 = .{ 127, 0, 0, 1 },
    host_port: u16,
    guest_port: u16,
};

pub const Refusal = struct {
    pub const Kind = enum { too_many, host_port_zero, guest_port_zero, host_port_duplicate };

    kind: Kind,
    /// The forward it is about; for `too_many`, the first one past the bound.
    index: u32,

    pub fn code(refusal: Refusal) []const u8 {
        return switch (refusal.kind) {
            .too_many => "VM-F001",
            .host_port_zero => "VM-F002",
            .guest_port_zero => "VM-F003",
            .host_port_duplicate => "VM-F004",
        };
    }
};

/// The first reason `forwards` cannot be rendered, or null. Pure: it touches nothing.
pub fn validate(forwards: []const Forward) ?Refusal {
    if (forwards.len > limits.forwards_max) {
        return .{ .kind = .too_many, .index = limits.forwards_max };
    }
    for (forwards, 0..) |forward, index| {
        const at: u32 = @intCast(index);
        if (forward.host_port == 0) return .{ .kind = .host_port_zero, .index = at };
        if (forward.guest_port == 0) return .{ .kind = .guest_port_zero, .index = at };
        for (forwards[0..index]) |earlier| {
            // Two forwards on one port clash even on different addresses: 0.0.0.0 covers all.
            if (earlier.host_port == forward.host_port) {
                return .{ .kind = .host_port_duplicate, .index = at };
            }
        }
    }
    return null;
}

/// One line saying what was refused and why, led by the code.
pub fn describe(refusal: Refusal, forwards: []const Forward, buffer: []u8) []const u8 {
    assert(buffer.len >= limits.forward_message_bytes_max);
    const code = refusal.code();
    const port: u16 = if (refusal.index < forwards.len) forwards[refusal.index].host_port else 0;
    const text = switch (refusal.kind) {
        .too_many => std.fmt.bufPrint(buffer, "{s}: {d} port forwards asked for, " ++
            "at most {d} are allowed per guest", .{ code, forwards.len, limits.forwards_max }),
        .host_port_zero => std.fmt.bufPrint(buffer, "{s}: forward {d} has host port 0; name an " ++
            "explicit port, the harness cannot learn the one QEMU would pick", .{
            code, refusal.index,
        }),
        .guest_port_zero => std.fmt.bufPrint(buffer, "{s}: forward {d} has guest port 0; " ++
            "name the port the guest listens on", .{ code, refusal.index }),
        .host_port_duplicate => std.fmt.bufPrint(buffer, "{s}: forward {d} reuses host port " ++
            "{d}; each host port can lead to one guest port only", .{
            code, refusal.index, port,
        }),
    };
    // The longest line is under the buffer's bound; the test below fills each one.
    return text catch unreachable; // The buffer holds `forward_message_bytes_max` bytes.
}

/// The `-netdev` value: `user,id=net0`, then one `,hostfwd=tcp:A.B.C.D:H-:G` per forward. With no
/// forwards it is the text the harness always used. `forwards` must already be valid.
pub fn netdev_argument(arena: std.mem.Allocator, forwards: []const Forward) ![]const u8 {
    assert(validate(forwards) == null);
    const base = "user,id=net0";
    var buffer: [base.len + limits.forwards_max * limits.forward_argument_bytes_max]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    writer.writeAll(base) catch unreachable; // The buffer starts with room for `base`.
    for (forwards) |forward| {
        const address = forward.host_address;
        writer.print(",hostfwd=tcp:{d}.{d}.{d}.{d}:{d}-:{d}", .{
            address[0],        address[1],
            address[2],        address[3],
            forward.host_port, forward.guest_port,
        }) catch unreachable; // Room for `forwards_max` longest arguments (limits.zig asserts it).
    }
    return arena.dupe(u8, writer.buffered());
}

test "netdev argument: no forwards is the text the harness always used" {
    // Goal: an empty list changes nothing, byte for byte.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const text = try netdev_argument(arena_state.allocator(), &.{});
    try std.testing.expectEqualStrings("user,id=net0", text);
}

test "netdev argument snapshot: one, several, and another address" {
    // Goal: the rendered text is exactly QEMU's hostfwd syntax, in the order given.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings(
        "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
        try netdev_argument(arena, &.{.{ .host_port = 2222, .guest_port = 22 }}),
    );
    try std.testing.expectEqualStrings(
        "user,id=net0,hostfwd=tcp:127.0.0.1:18080-:8080,hostfwd=tcp:0.0.0.0:65535-:1",
        try netdev_argument(arena, &.{
            .{ .host_port = 18080, .guest_port = 8080 },
            .{ .host_address = .{ 0, 0, 0, 0 }, .host_port = 65535, .guest_port = 1 },
        }),
    );
}

test "netdev argument fits its buffer at the bound with the longest numbers" {
    // Goal: `forwards_max` forwards of 255.255.255.255:65535-:65535 render without overflow.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var forwards: [limits.forwards_max]Forward = undefined;
    for (&forwards, 0..) |*forward, index| {
        forward.* = .{
            .host_address = .{ 255, 255, 255, 255 },
            .host_port = @intCast(65535 - index),
            .guest_port = 65535,
        };
    }
    const text = try netdev_argument(arena_state.allocator(), &forwards);
    try std.testing.expect(std.mem.endsWith(u8, text, "hostfwd=tcp:255.255.255.255:65528-:65535"));
}

test "validate accepts the bound and refuses one past it" {
    // Goal: the count bound, the port range ends and duplicates, each with its code and index.
    var full: [limits.forwards_max + 1]Forward = undefined;
    for (&full, 0..) |*forward, index| {
        forward.* = .{ .host_port = @intCast(1000 + index), .guest_port = 80 };
    }
    try std.testing.expectEqual(@as(?Refusal, null), validate(full[0..limits.forwards_max]));
    const over = validate(&full).?;
    try std.testing.expectEqual(Refusal.Kind.too_many, over.kind);
    try std.testing.expectEqualStrings("VM-F001", over.code());
    const high: Forward = .{ .host_port = 65535, .guest_port = 65535 };
    const low: Forward = .{ .host_port = 1, .guest_port = 1 };
    try std.testing.expectEqual(@as(?Refusal, null), validate(&.{high}));
    try std.testing.expectEqual(@as(?Refusal, null), validate(&.{low}));
    const first: Forward = .{ .host_port = 5, .guest_port = 5 };
    const zero_host = validate(&.{ first, .{ .host_port = 0, .guest_port = 5 } }).?;
    try std.testing.expectEqual(Refusal{ .kind = .host_port_zero, .index = 1 }, zero_host);
    const zero_guest = validate(&.{.{ .host_port = 5, .guest_port = 0 }}).?;
    try std.testing.expectEqual(Refusal{ .kind = .guest_port_zero, .index = 0 }, zero_guest);
    const twin = validate(&.{
        .{ .host_port = 7, .guest_port = 1 },
        .{ .host_address = .{ 0, 0, 0, 0 }, .host_port = 7, .guest_port = 2 },
    }).?;
    try std.testing.expectEqual(Refusal{ .kind = .host_port_duplicate, .index = 1 }, twin);
}

test "refusals read as one coded line and fit their buffer" {
    // Goal: every refusal is a single line, led by its code, even with the longest numbers.
    var forwards: [limits.forwards_max + 1]Forward = undefined;
    for (&forwards, 0..) |*forward, index| {
        forward.* = .{ .host_port = @intCast(65535 - index), .guest_port = 65535 };
    }
    var buffer: [limits.forward_message_bytes_max]u8 = undefined;
    @memset(&buffer, 0xAA);
    const kinds = std.enums.values(Refusal.Kind);
    for (kinds) |kind| {
        const refusal: Refusal = .{ .kind = kind, .index = limits.forwards_max - 1 };
        const line = describe(refusal, &forwards, &buffer);
        try std.testing.expect(std.mem.startsWith(u8, line, refusal.code()));
        try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
    }
    const line = describe(.{ .kind = .host_port_duplicate, .index = 1 }, &.{
        .{ .host_port = 9, .guest_port = 1 }, .{ .host_port = 9, .guest_port = 2 },
    }, &buffer);
    try std.testing.expectEqualStrings(
        "VM-F004: forward 1 reuses host port 9; each host port can lead to one guest port only",
        line,
    );
}
