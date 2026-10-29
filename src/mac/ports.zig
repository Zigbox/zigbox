//! Published ports on the Mac (milestone M4b, slice 4). The host process listens on the Mac for
//! every port a container publishes in the guest, and carries each connection it accepts to the
//! guest over vsock, to the guest's port agent (`guest_ports.zig`, protocol in `vm_ports.zig`).
//! The client is not in the data path: `zbx run -d` can end and the port stays.
//!
//! A port's life:
//!   1. The client says `publish <address> <port>` before it runs the command. The host binds the
//!      Mac port at once: a port that is taken is refused before anything runs (`taken`), and a
//!      port that is free cannot be taken by another process between the check and the command.
//!   2. The guest's agent reports the ports `pasta` publishes. A reserved port that is reported is
//!      `seen`; from then on, when the agent stops reporting it, the Mac listener is closed. That
//!      is the event of the container's end: after `zbx stop`, a crash or a kill alike.
//!   3. A reserved port that is not reported is closed when the client says `sync` (its command
//!      ended without publishing), or after `vm_reserve_ttl_ms` (the client is gone).
//! The machine stopping ends the process, and with it every listener.
//!
//! Every Mac connection is one vsock connection and one thread that copies bytes both ways.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const constants = @import("../constants.zig");
const control = @import("control.zig");
const files = @import("files.zig");
const objc = @import("objc.zig");
const ports = @import("../vm_ports.zig");
const vz = @import("vz.zig");

// The values of macOS's <sys/socket.h> and <netinet/in.h> for what is used here.
const af_inet: u8 = 2;
const af_inet6: u8 = 30;
const sol_socket: c_int = 0xffff;
const so_reuseaddr: c_int = 0x0004;
const so_nosigpipe: c_int = 0x1022;
const so_error: c_int = 0x1007;
const ipproto_ipv6: c_int = 41;
const ipv6_v6only: c_int = 27;

const SockaddrIn = extern struct {
    length: u8 = @sizeOf(SockaddrIn),
    family: u8 = af_inet,
    port: u16,
    address: u32,
    zero: [8]u8 = @splat(0),
};

const SockaddrIn6 = extern struct {
    length: u8 = @sizeOf(SockaddrIn6),
    family: u8 = af_inet6,
    port: u16,
    flow: u32 = 0,
    address: [16]u8,
    scope: u32 = 0,
};

extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) c_int;
extern "c" fn setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: *const c_int,
    length: u32,
) c_int;
extern "c" fn bind(fd: c_int, address: *const anyopaque, length: u32) c_int;
extern "c" fn connect(fd: c_int, address: *const anyopaque, length: u32) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *c_int, length: *u32) c_int;
extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
extern "c" fn accept(fd: c_int, address: ?*anyopaque, length: ?*u32) c_int;

/// One published port: its Mac listeners (two for loopback, IPv4 and IPv6; one otherwise).
const Entry = struct {
    port: u16 = 0,
    listeners: [2]i32 = .{ -1, -1 },
    /// The guest has reported the port: its end is now an event.
    seen: bool = false,
    reserved_ms: u64 = 0,
};

var entries: [constants.vm_ports_max]Entry = @splat(.{});

/// The connection to the guest's agent, and the framework object that must outlive it.
var agent_fd: i32 = -1;
var agent_object: objc.Id = null;
var agent_line: [constants.vm_line_bytes_max]u8 = undefined;
var agent_length: usize = 0;

var relays_active: std.atomic.Value(u32) = .init(0);

/// Called once. SIGPIPE is the host's to ignore already; a closed peer is an error return.
pub fn open_agent(machine: *vz.Machine) bool {
    assert(agent_fd < 0);
    assert(relays_active.load(.monotonic) == 0);
    var failure: vz.Failure = .{};
    const connection = machine.connect(constants.vm_ports_port, &failure) catch return false;
    files.write_all(connection.descriptor, ports.watch_request) catch {
        vz.finish_connection(connection);
        return false;
    };
    assert(connection.object != null);
    agent_fd = connection.descriptor;
    agent_object = connection.object;
    agent_length = 0;
    return true;
}

/// Why the last `listening` failed.
var last_error: c.E = .SUCCESS;

fn listening(kind: c_int, address: *const anyopaque, length: u32, v6_only: ?c_int) ?i32 {
    assert(length > 0);
    if (v6_only != null) assert(kind == af_inet6); // Only an IPv6 socket has the option.
    const handle = socket(kind, 1, 0);
    if (handle < 0) {
        last_error = @fromBackingInt(@intCast(c._errno().*));
        return null;
    }
    const one: c_int = 1;
    _ = setsockopt(handle, sol_socket, so_reuseaddr, &one, @sizeOf(c_int));
    _ = setsockopt(handle, sol_socket, so_nosigpipe, &one, @sizeOf(c_int));
    if (v6_only) |value| _ = setsockopt(handle, ipproto_ipv6, ipv6_v6only, &value, @sizeOf(c_int));
    if (bind(handle, address, length) != 0 or listen(handle, 128) != 0) {
        last_error = @fromBackingInt(@intCast(c._errno().*));
        files.close(handle);
        return null;
    }
    return handle;
}

const loopback_v6: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

/// Opens the Mac listeners for `address` and `port`; null if any of them cannot be bound.
fn open_listeners(address: control.Address, port: u16) ?[2]i32 {
    assert(port > 0);
    if (address.kind == .v4) assert(address.v4 != 0); // Zero is the "any" address, its own kind.
    const wire_port = std.mem.nativeToBig(u16, port);
    switch (address.kind) {
        .loopback => {
            const loopback = std.mem.nativeToBig(u32, 0x7f000001);
            const v4: SockaddrIn = .{ .port = wire_port, .address = loopback };
            const first = listening(af_inet, &v4, @sizeOf(SockaddrIn), null) orelse return null;
            const v6: SockaddrIn6 = .{ .port = wire_port, .address = loopback_v6 };
            // A Mac without IPv6 loopback still serves IPv4.
            const second = listening(af_inet6, &v6, @sizeOf(SockaddrIn6), 1) orelse -1;
            return .{ first, second };
        },
        .any => {
            const v6: SockaddrIn6 = .{ .port = wire_port, .address = @splat(0) };
            const dual = listening(af_inet6, &v6, @sizeOf(SockaddrIn6), 0) orelse return null;
            return .{ dual, -1 };
        },
        .v4 => {
            const bound = std.mem.nativeToBig(u32, address.v4);
            const v4: SockaddrIn = .{ .port = wire_port, .address = bound };
            const only = listening(af_inet, &v4, @sizeOf(SockaddrIn), null) orelse return null;
            return .{ only, -1 };
        },
    }
}

fn find(port: u16) ?*Entry {
    assert(port > 0);
    assert(entries.len == constants.vm_ports_max);
    for (&entries) |*entry| {
        if (entry.port == port) return entry;
    }
    return null;
}

/// True if something accepts connections on `port` on this Mac's loopback, whatever address it
/// listens on. A listener of another program that shares its port (SO_REUSEADDR on both) would
/// let a bind succeed beside it and take the connections that name our address, so the port is
/// asked before it is bound: one connection, made and ended at once.
fn in_use(port: u16) bool {
    assert(port > 0);
    assert(@sizeOf(SockaddrIn) == 16); // The sizes macOS gives struct sockaddr_in and _in6.
    assert(@sizeOf(SockaddrIn6) == 28);
    const wire_port = std.mem.nativeToBig(u16, port);
    const v4: SockaddrIn = .{ .port = wire_port, .address = std.mem.nativeToBig(u32, 0x7f000001) };
    const v6: SockaddrIn6 = .{ .port = wire_port, .address = loopback_v6 };
    return answers(af_inet, &v4, @sizeOf(SockaddrIn)) or
        answers(af_inet6, &v6, @sizeOf(SockaddrIn6));
}

/// True if a connection to the address is accepted, or is neither refused nor answered within a
/// moment (a listener whose queue is full drops the attempt).
fn answers(kind: u8, address: *const anyopaque, length: u32) bool {
    assert(length > 0);
    const handle = socket(kind, 1, 0);
    if (handle < 0) return false;
    defer files.close(handle);
    const flags = c.fcntl(handle, c.F.GETFL);
    assert(flags >= 0);
    _ = c.fcntl(handle, c.F.SETFL, flags | @as(c_int, @bitCast(c.O{ .NONBLOCK = true })));
    if (connect(handle, address, length) == 0) return true;
    if (c.errno(@as(c_int, -1)) != .INPROGRESS) return false;
    var entry = [1]c.pollfd{.{ .fd = handle, .events = c.POLL.OUT, .revents = 0 }};
    if (c.poll(&entry, 1, 200) == 0) return true;
    var failure: c_int = 0;
    var size: u32 = @sizeOf(c_int);
    _ = getsockopt(handle, sol_socket, so_error, &failure, &size);
    return failure == 0;
}

pub const Reserve = union(enum) {
    ok,
    /// Another program listens on the port.
    taken,
    full,
    /// The port cannot be listened on for another reason; the errno's name.
    failed: []const u8,
};

/// A reservation made twice (a second command that publishes the same port) is a port that
/// is taken: by the first.
pub fn reserve(request: control.Publish) Reserve {
    assert(request.port > 0);
    if (find(request.port) != null) return .taken;
    var free: ?*Entry = null;
    for (&entries) |*entry| {
        if (entry.port == 0) {
            free = entry;
            break;
        }
    }
    const slot = free orelse return .full;
    if (in_use(request.port)) return .taken;
    const bound = open_listeners(request.address, request.port) orelse {
        if (last_error == .ADDRINUSE) return .taken;
        return .{ .failed = @tagName(last_error) };
    };
    slot.* = .{ .port = request.port, .listeners = bound, .reserved_ms = files.now_ms() };
    assert(slot.listeners[0] >= 0);
    return .ok;
}

fn release(entry: *Entry) void {
    assert(entry.listeners[0] >= 0); // A reserved port always has its first listener.
    assert(entry.port > 0);
    for (entry.listeners) |handle| {
        if (handle >= 0) files.close(handle);
    }
    entry.* = .{};
}

/// The guest reported `set` as its published ports.
fn apply(set: *const ports.PortSet) void {
    assert(set.count <= constants.vm_ports_max);
    for (&entries) |*entry| {
        if (entry.port == 0) continue;
        if (set.contains(entry.port)) {
            entry.seen = true;
        } else if (entry.seen) {
            release(entry);
        }
    }
    assert(open_count() <= constants.vm_ports_max);
}

/// Releases the ports a command reserved and the guest never reported.
pub fn forget_unseen(wanted: *const ports.PortSet) void {
    assert(wanted.count <= constants.vm_ports_max);
    for (wanted.slice()) |port| {
        const entry = find(port) orelse continue;
        if (!entry.seen) release(entry);
    }
    assert(open_count() <= constants.vm_ports_max);
}

fn sweep(now_ms: u64) void {
    assert(now_ms > 0);
    assert(constants.vm_reserve_ttl_ms > 0);
    for (&entries) |*entry| {
        if (entry.port == 0 or entry.seen) continue;
        if (now_ms - entry.reserved_ms > constants.vm_reserve_ttl_ms) release(entry);
    }
}

/// How many ports are listened on (the status and the tests).
pub fn open_count() u32 {
    assert(entries.len == constants.vm_ports_max);
    var count: u32 = 0;
    for (entries) |entry| {
        if (entry.port != 0) count += 1;
    }
    assert(count <= entries.len);
    return count;
}

/// Asks the agent to look now and waits for its answer, which `apply` takes. False if the agent
/// does not answer.
pub fn scan(wait_ms: u32) bool {
    assert(wait_ms > 0);
    assert(wait_ms <= 60_000);
    if (agent_fd < 0) return false;
    files.write_all(agent_fd, ports.scan_request) catch return false;
    const deadline = files.now_ms() + wait_ms;
    while (files.now_ms() < deadline) {
        const ready = files.wait_readable(agent_fd, 50) catch return false;
        if (!ready) continue;
        if (read_agent()) return true;
    }
    return false;
}

/// Takes what the agent sent; true once the answer to a `scan` was applied.
fn read_agent() bool {
    assert(agent_length <= agent_line.len);
    assert(agent_fd >= 0);
    var applied = false;
    var byte: [1]u8 = undefined;
    // The agent writes whole lines; they are read a byte at a time, so that a line is never cut.
    var guard: u32 = 0;
    while (guard < agent_line.len * 4) : (guard += 1) {
        var entry = [1]c.pollfd{.{ .fd = agent_fd, .events = c.POLL.IN, .revents = 0 }};
        if (c.poll(&entry, 1, 0) <= 0) return applied;
        const got = c.read(agent_fd, &byte, 1);
        if (got <= 0) {
            drop_agent();
            return applied;
        }
        if (agent_length == agent_line.len) {
            agent_length = 0;
            continue;
        }
        agent_line[agent_length] = byte[0];
        agent_length += 1;
        if (byte[0] != '\n') continue;
        if (ports.parse_ports(agent_line[0..agent_length])) |set| apply(&set);
        if (ports.parse_scanned(agent_line[0..agent_length])) |set| {
            apply(&set);
            applied = true;
        }
        agent_length = 0;
    }
    return applied;
}

fn drop_agent() void {
    assert(agent_object != null); // The connection and its object come together.
    assert(agent_fd >= 0);
    files.close(agent_fd);
    objc.release(agent_object);
    agent_fd = -1;
    agent_object = null;
}

/// Waits up to `timeout_ms` for the control socket, a Mac connection to a published port, or news
/// from the guest. Connections are taken here; true if the control socket is readable.
pub fn wait(machine: *vz.Machine, control_fd: i32, timeout_ms: u32) bool {
    assert(timeout_ms > 0);
    assert(control_fd >= 0);
    var list: [1 + 1 + 2 * constants.vm_ports_max]c.pollfd = undefined;
    var owner: [list.len]?*Entry = @splat(null);
    list[0] = .{ .fd = control_fd, .events = c.POLL.IN, .revents = 0 };
    list[1] = .{ .fd = agent_fd, .events = c.POLL.IN, .revents = 0 };
    var count: usize = 2;
    for (&entries) |*entry| {
        if (entry.port == 0) continue;
        for (entry.listeners) |handle| {
            if (handle < 0) continue;
            list[count] = .{ .fd = handle, .events = c.POLL.IN, .revents = 0 };
            owner[count] = entry;
            count += 1;
        }
    }
    assert(count >= 2); // The control socket and the agent are always polled.
    assert(count <= list.len);
    const ready = c.poll(&list, @intCast(count), @intCast(timeout_ms));
    sweep(files.now_ms());
    if (ready <= 0) return false;
    if (list[1].revents != 0 and agent_fd >= 0) _ = read_agent();
    for (list[2..count], owner[2..count]) |polled, entry| {
        if (polled.revents == 0) continue;
        // The entry may have been released by the news just read; its listener is closed then.
        if (entry.?.port == 0) continue;
        carry(machine, polled.fd, entry.?.port);
    }
    return list[0].revents != 0;
}

// ---- Carrying a connection --------------------------------------------------------------------

const Relay = struct {
    mac: i32,
    guest: i32,
    object: objc.Id,
};

/// Accepts one Mac connection and starts carrying it to `port` in the guest.
fn carry(machine: *vz.Machine, listener: i32, port: u16) void {
    assert(listener >= 0);
    assert(port > 0);
    const accepted = accept(listener, null, null);
    if (accepted < 0) return;
    assert(relays_active.load(.monotonic) <= constants.vm_relays_max);
    if (relays_active.load(.monotonic) >= constants.vm_relays_max) return files.close(accepted);
    const one: c_int = 1;
    _ = setsockopt(accepted, sol_socket, so_nosigpipe, &one, @sizeOf(c_int));
    var failure: vz.Failure = .{};
    const guest = machine.connect(constants.vm_ports_port, &failure) catch {
        return files.close(accepted);
    };
    _ = setsockopt(guest.descriptor, sol_socket, so_nosigpipe, &one, @sizeOf(c_int));
    var line: [16]u8 = undefined;
    files.write_all(guest.descriptor, ports.render_connect(&line, port)) catch {
        vz.finish_connection(guest);
        return files.close(accepted);
    };
    _ = relays_active.fetchAdd(1, .monotonic);
    const relay: Relay = .{ .mac = accepted, .guest = guest.descriptor, .object = guest.object };
    const thread = std.Thread.spawn(.{}, relay_main, .{relay}) catch {
        _ = relays_active.fetchSub(1, .monotonic);
        vz.finish_connection(guest);
        return files.close(accepted);
    };
    thread.detach();
}

fn relay_main(relay: Relay) void {
    assert(relay.mac >= 0);
    assert(relay.guest >= 0);
    defer {
        files.close(relay.mac);
        files.close(relay.guest);
        objc.release(relay.object);
        _ = relays_active.fetchSub(1, .monotonic);
    }
    var answer: [ports.connect_ok.len]u8 = undefined;
    var have: usize = 0;
    const deadline = files.now_ms() + constants.vm_relay_connect_ms;
    while (have < answer.len) {
        if (files.now_ms() >= deadline) return;
        const ready = files.wait_readable(relay.guest, 100) catch return;
        if (!ready) continue;
        const got = c.read(relay.guest, answer[have..].ptr, answer.len - have);
        if (got <= 0) return;
        have += @intCast(got);
    }
    assert(have == answer.len);
    if (!std.mem.eql(u8, &answer, ports.connect_ok)) return;
    pump(relay.mac, relay.guest);
}

/// Copies both ways until each side has ended; an end on one side is passed on as a half close.
fn pump(first: i32, second: i32) void {
    assert(first >= 0);
    assert(first != second);
    var buffer: [constants.vm_relay_buffer_bytes]u8 = undefined;
    const sides = [2]i32{ first, second };
    var open = [2]bool{ true, true };
    var turns: u64 = 0;
    const turns_max: u64 = 1 << 50; // A transfer that lasts still makes progress.
    while ((open[0] or open[1]) and turns < turns_max) : (turns += 1) {
        var entries_poll: [2]c.pollfd = undefined;
        for (0..2) |side| {
            entries_poll[side] = .{
                .fd = if (open[side]) sides[side] else -1,
                .events = c.POLL.IN,
                .revents = 0,
            };
        }
        const ready = c.poll(&entries_poll, 2, -1);
        if (ready < 0 and c.errno(ready) == .INTR) continue;
        if (ready < 0) return;
        for (0..2) |side| {
            if (entries_poll[side].revents == 0) continue;
            const got = c.read(sides[side], &buffer, buffer.len);
            if (got < 0 and c.errno(got) == .INTR) continue;
            if (got <= 0) {
                open[side] = false;
                _ = c.shutdown(sides[1 - side], c.SHUT.WR);
                continue;
            }
            files.write_all(sides[1 - side], buffer[0..@intCast(got)]) catch return;
        }
    }
}

test "a reserved port is bound at once, a second reservation is refused, and a release frees it" {
    // Goal: the Mac port is taken before the command runs, and given back. Method: a high
    // port on loopback, the same port twice, then released and bound again.
    const request: control.Publish = .{ .address = .{ .kind = .loopback }, .port = 48731 };
    try std.testing.expectEqual(Reserve.ok, reserve(request));
    try std.testing.expectEqual(@as(u32, 1), open_count());
    try std.testing.expectEqual(Reserve.taken, reserve(request));
    var wanted: ports.PortSet = .{};
    try std.testing.expect(wanted.add(48731));
    forget_unseen(&wanted);
    try std.testing.expectEqual(@as(u32, 0), open_count());
    try std.testing.expectEqual(Reserve.ok, reserve(request));
    var reported: ports.PortSet = .{};
    try std.testing.expect(reported.add(48731));
    apply(&reported); // Seen: it now lives as long as the guest reports it.
    forget_unseen(&wanted);
    try std.testing.expectEqual(@as(u32, 1), open_count());
    const none: ports.PortSet = .{};
    apply(&none);
    try std.testing.expectEqual(@as(u32, 0), open_count());
}

test "a port that something else listens on is taken" {
    // Goal: the refusal for a Mac port in use. Method: hold a port with a plain listener, as
    // another program would (no SO_REUSEADDR), and reserve the same one.
    const wire = std.mem.nativeToBig(u16, 48732);
    const holder = socket(af_inet, 1, 0);
    try std.testing.expect(holder >= 0);
    defer files.close(holder);
    const address: SockaddrIn = .{ .port = wire, .address = std.mem.nativeToBig(u32, 0x7f000001) };
    try std.testing.expectEqual(@as(c_int, 0), bind(holder, &address, @sizeOf(SockaddrIn)));
    try std.testing.expectEqual(@as(c_int, 0), listen(holder, 1));
    const request: control.Publish = .{ .address = .{ .kind = .loopback }, .port = 48732 };
    try std.testing.expectEqual(Reserve.taken, reserve(request));
    try std.testing.expectEqual(@as(u32, 0), open_count());
}

test "a port another program listens on is seen even when it shares the port" {
    // Goal: the case of a listener that sets SO_REUSEADDR and listens on every address (a Java
    // server), beside which a bind to 127.0.0.1 would succeed. Method: such a listener, then
    // the reservation.
    const holder = socket(af_inet6, 1, 0);
    try std.testing.expect(holder >= 0);
    defer files.close(holder);
    const one: c_int = 1;
    _ = setsockopt(holder, sol_socket, so_reuseaddr, &one, @sizeOf(c_int));
    const wire = std.mem.nativeToBig(u16, 48733);
    const wildcard: SockaddrIn6 = .{ .port = wire, .address = @splat(0) };
    try std.testing.expectEqual(@as(c_int, 0), bind(holder, &wildcard, @sizeOf(SockaddrIn6)));
    try std.testing.expectEqual(@as(c_int, 0), listen(holder, 1));
    try std.testing.expect(in_use(48733));
    try std.testing.expect(!in_use(48734));
    const request: control.Publish = .{ .address = .{ .kind = .loopback }, .port = 48733 };
    try std.testing.expectEqual(Reserve.taken, reserve(request));
}
