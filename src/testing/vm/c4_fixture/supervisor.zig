//! demo-c4's stand-in for Zigcube's per-replica supervisor: a multi-threaded process that did not
//! start the container and makes sockets in its network namespace with `zigbox.container_socket`.
//! The demo's guest script drives it over stdin and stdout, one line each way:
//!   listen ID NAME IP PORT   a thread makes a socket in NAME, binds IP:PORT, listens, and
//!                            answers each HTTP request `hello from supervisor` until closed
//!   close ID                 stops that listener and closes its socket
//!   hold ID NAME             makes a socket in NAME and keeps it, unconnected
//!   dial ID IP PORT TEXT     connects the held socket ID, sends TEXT and a newline, prints the
//!                            reply line, and closes it
//!   adopt NAME               finds NAME as a restarted agent does (`zigbox.adopt`)
//!   ping                     prints PONG (the process is alive)
//! Every thread uses a `HostReal` of its own: the real host counts its open files in it.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const zigbox = @import("zigbox");

const HostReal = zigbox.host_real.HostReal;
const Diag = zigbox.diag.Diag;

const slots_max = 8;
const line_bytes_max = 256;
/// `render` needs `constants.output_bytes_max` (16 KiB) of room.
const render_bytes = 16 * 1024;
const reply_text = "HTTP/1.0 200 OK\r\n\r\nhello from supervisor\n";
const free_fd: i32 = -1;

/// One listener or held socket: its descriptor and, for a listener, its accept thread.
const Slot = struct {
    fd: std.atomic.Value(i32) = .init(free_fd),
    thread: ?std.Thread = null,
};

var slots: [slots_max]Slot = @splat(.{});
var output_lock: std.atomic.Mutex = .unlocked;

/// Prints one line to stdout; the threads share it, so each line is one `write`.
fn say(comptime format: []const u8, args: anytype) void {
    var buffer: [line_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, format ++ "\n", args) catch return;
    while (!output_lock.tryLock()) std.atomic.spinLoopHint();
    defer output_lock.unlock();
    _ = linux.write(1, text.ptr, text.len);
}

/// The rendered one-line diagnostic, as `zbx` would print it.
fn say_diag(label: []const u8, diag: *const Diag) void {
    assert(label.len > 0);
    var buffer: [render_bytes]u8 = undefined;
    const text = zigbox.render.render(diag, .text, false, &buffer);
    // The first line is the diagnostic; the rest is its cause, fix and links.
    const first = std.mem.sliceTo(text, '\n');
    say("{s} {s}", .{ label, first });
}

fn make_socket(name: []const u8, label: []const u8) ?i32 {
    assert(name.len > 0);
    var real: HostReal = .{};
    var diag: Diag = undefined;
    diag.reset();
    const handle = zigbox.container_socket(real.interface(), name, .tcp4, &diag) catch {
        say_diag(label, &diag);
        return null;
    };
    // The real host's handle is the descriptor itself; the call counted it in `real`, which
    // this function ends with: the descriptor is the caller's from here.
    return @intCast(handle);
}

fn address_of(ip: []const u8, port: u16) ?linux.sockaddr.in {
    var parts: [4]u8 = undefined;
    var iterator = std.mem.splitScalar(u8, ip, '.');
    for (&parts) |*part| {
        const text = iterator.next() orelse return null;
        part.* = std.fmt.parseInt(u8, text, 10) catch return null;
    }
    if (iterator.next() != null) return null;
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(parts) };
}

const Listen = struct { id: usize, name: []const u8, address: linux.sockaddr.in };
var listens: [slots_max]Listen = undefined;
var name_storage: [slots_max][64]u8 = undefined;

fn serve(listen: *const Listen) void {
    const id = listen.id;
    const fd = make_socket(listen.name, "LISTEN-FAILED") orelse return;
    const address = &listen.address;
    const bound = linux.bind(fd, @ptrCast(address), @sizeOf(linux.sockaddr.in));
    if (linux.errno(bound) != .SUCCESS) {
        say("BIND-FAILED {d} {s}", .{ id, @tagName(linux.errno(bound)) });
        _ = linux.close(fd);
        return;
    }
    assert(linux.errno(linux.listen(fd, 8)) == .SUCCESS);
    slots[id].fd.store(fd, .release);
    say("LISTENING {d}", .{id});
    while (true) {
        const rc = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) break;
        const peer: i32 = @intCast(rc);
        var request: [512]u8 = undefined;
        _ = linux.read(peer, &request, request.len);
        _ = linux.write(peer, reply_text, reply_text.len);
        _ = linux.close(peer);
    }
}

fn start_listen(id: usize, name: []const u8, ip: []const u8, port: u16) void {
    assert(id < slots_max);
    assert(slots[id].thread == null);
    const address = address_of(ip, port) orelse return say("BAD address {s}", .{ip});
    if (name.len > name_storage[id].len) return say("BAD name", .{});
    @memcpy(name_storage[id][0..name.len], name);
    listens[id] = .{ .id = id, .name = name_storage[id][0..name.len], .address = address };
    slots[id].thread = std.Thread.spawn(.{}, serve, .{&listens[id]}) catch {
        return say("BAD spawn", .{});
    };
}

fn close_listen(id: usize) void {
    assert(id < slots_max);
    const fd = slots[id].fd.swap(free_fd, .acq_rel);
    if (fd == free_fd) return say("BAD no listener {d}", .{id});
    // A shutdown wakes the accept; the thread then ends and the descriptor can be closed.
    _ = linux.shutdown(fd, 2);
    if (slots[id].thread) |thread| thread.join();
    slots[id].thread = null;
    _ = linux.close(fd);
    say("CLOSED {d}", .{id});
}

fn dial(id: usize, ip: []const u8, port: u16, text: []const u8) void {
    assert(id < slots_max);
    const fd = slots[id].fd.swap(free_fd, .acq_rel);
    if (fd == free_fd) return say("BAD nothing held {d}", .{id});
    defer _ = linux.close(fd);
    const address = address_of(ip, port) orelse return say("BAD address {s}", .{ip});
    const rc = linux.connect(fd, &address, @sizeOf(linux.sockaddr.in));
    if (linux.errno(rc) != .SUCCESS) {
        return say("DIAL-FAILED {d} {s}", .{ id, @tagName(linux.errno(rc)) });
    }
    var line: [line_bytes_max]u8 = undefined;
    const sent = std.fmt.bufPrint(&line, "{s}\n", .{text}) catch return;
    _ = linux.write(fd, sent.ptr, sent.len);
    const count = linux.read(fd, &line, line.len);
    if (linux.errno(count) != .SUCCESS) return say("DIAL-FAILED {d} read", .{id});
    say("DIAL-REPLY {d} {s}", .{ id, std.mem.trimEnd(u8, line[0..count], "\r\n") });
}

fn adopt(name: []const u8) void {
    assert(name.len > 0);
    var real: HostReal = .{};
    var ref: zigbox.Ref = undefined;
    var state: zigbox.lifecycle.State = undefined;
    zigbox.adopt(real.interface(), name, &ref, &state) catch |err| {
        return say("ADOPT-FAILED {s}", .{@errorName(err)});
    };
    say("ADOPTED {s} {s}", .{ name, @tagName(state) });
}

/// One input line. False ends the program.
fn command(line: []const u8) bool {
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    const verb = words.next() orelse return true;
    const first = words.next() orelse "";
    if (std.mem.eql(u8, verb, "quit")) return false;
    if (std.mem.eql(u8, verb, "ping")) {
        say("PONG", .{});
    } else if (std.mem.eql(u8, verb, "adopt")) {
        adopt(first);
    } else {
        const id = std.fmt.parseInt(usize, first, 10) catch slots_max;
        if (id >= slots_max) return bad_slot();
        slot_command(verb, id, &words);
    }
    return true;
}

fn bad_slot() bool {
    say("BAD slot", .{});
    return true;
}

fn port_of(word: ?[]const u8) u16 {
    return std.fmt.parseInt(u16, word orelse "", 10) catch 0;
}

fn slot_command(verb: []const u8, id: usize, words: *std.mem.TokenIterator(u8, .scalar)) void {
    assert(id < slots_max);
    const second = words.next() orelse "";
    if (std.mem.eql(u8, verb, "close")) {
        close_listen(id);
    } else if (std.mem.eql(u8, verb, "hold")) {
        hold(id, second);
    } else if (std.mem.eql(u8, verb, "listen")) {
        const ip = words.next() orelse "";
        start_listen(id, second, ip, port_of(words.next()));
    } else if (std.mem.eql(u8, verb, "dial")) {
        const port = port_of(words.next());
        dial(id, second, port, std.mem.trimStart(u8, words.rest(), " "));
    } else say("BAD verb", .{});
}

fn hold(id: usize, name: []const u8) void {
    assert(id < slots_max);
    const fd = make_socket(name, "HOLD-FAILED") orelse return;
    slots[id].fd.store(fd, .release);
    say("HELD {d}", .{id});
}

pub fn main() u8 {
    say("SUPERVISOR-PID {d}", .{linux.getpid()});
    var line: [line_bytes_max]u8 = undefined;
    var length: usize = 0;
    while (true) {
        var byte: [1]u8 = undefined;
        if (linux.read(0, &byte, 1) != 1) return 0;
        if (byte[0] != '\n') {
            if (length < line.len) {
                line[length] = byte[0];
                length += 1;
            }
            continue;
        }
        const keep_going = command(line[0..length]);
        length = 0;
        if (!keep_going) return 0;
    }
}
