//! The production network for the registry client (`registry/net.zig`): sockets through raw Linux
//! syscalls, no libc, with a deadline on every wait. Like `host_real.zig` this is a place that may
//! name syscalls. What it takes from `std` is what `std` does well and needs no clock of its own:
//! the TLS 1.2 and 1.3 client with certificate verification (`std.crypto.tls`), the CA bundle
//! parser, name resolution (`std.Io.net.HostName`, through the single-threaded `Io`), and the HTTP
//! head parser and chunked decoder (`std.http`).
//!
//! `std.http.Client` is not used. It has no timeout on connect, handshake or read (a connect with a
//! timeout panics with a TODO in the pinned std), so a registry that stops answering would hang
//! the command for ever, and a bound on everything is a rule here (docs/STYLE.md). This file opens
//! its own sockets, polls with a deadline, and hands the TLS client and the HTTP reader a
//! `std.Io.Reader` and `Writer` over the socket.
//!
//! One request, one connection (`Connection: close`). The proxy is `HTTPS_PROXY` (an HTTP CONNECT
//! tunnel), bypassed by `NO_PROXY`; plain-HTTP requests, which only a loopback registry makes, go
//! direct. All buffers are static and the call is not reentrant: the registry client is the
//! parent process's, single-threaded (a second call at once is a bug and asserts).

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const linux = std.os.linux;
const constants = @import("constants.zig");
const host_real = @import("host_real.zig");
const net = @import("registry/net.zig");
const proxy_mod = @import("registry/proxy.zig");

const Io = std.Io;
const tls = std.crypto.tls;
const http = std.http;

const HostReal = host_real.HostReal;
const Host = @import("host.zig").Host;

pub fn interface(context: *HostReal) net.Net {
    assert(@intFromPtr(&vtable) != 0);
    assert(@intFromPtr(context) != 0);
    return .{ .context = context, .vtable = &vtable };
}

const vtable: net.VTable = .{ .get = get, .last_errno = last_errno };

fn last_errno(context: *anyopaque) u16 {
    assert(@intFromPtr(context) != 0);
    assert(state.errno_last < 4096);
    return state.errno_last;
}

const request_head_bytes_max = constants.registry_request_head_bytes_max;

/// The buffers of the socket and of TLS, the request head, and the memory the CA certificates are
/// kept in (parsed once per process, on the first HTTPS call). Static and never initialised, so
/// they take no room in the binary.
const Buffers = struct {
    socket_read: [tls.Client.min_buffer_len]u8,
    socket_write: [tls.Client.min_buffer_len]u8,
    tls_read: [tls.Client.min_buffer_len + constants.registry_head_bytes_max]u8,
    tls_write: [tls.Client.min_buffer_len]u8,
    request_head: [request_head_bytes_max]u8,
    ca_arena: [constants.net_ca_arena_bytes]u8,
};

var buffers: Buffers = undefined;

/// What one call and the process keep between calls.
const State = struct {
    busy: bool,
    errno_last: u16,
    ca_allocator: std.heap.FixedBufferAllocator,
    ca_bundle: std.crypto.Certificate.Bundle,
    ca_lock: Io.RwLock,
    ca_ready: bool,
};

var state: State = .{
    .busy = false,
    .errno_last = 0,
    .ca_allocator = undefined,
    .ca_bundle = .empty,
    .ca_lock = .init,
    .ca_ready = false,
};

fn global_io() Io {
    const io = Io.Threaded.global_single_threaded.io();
    assert(io.userdata != null);
    assert(@intFromPtr(io.vtable) != 0);
    return io;
}

// ---- Time and sockets ----------------------------------------------------------------------

fn monotonic_ms() u64 {
    var now: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &now);
    assert(linux.errno(rc) == .SUCCESS); // CLOCK_MONOTONIC always exists.
    assert(now.sec >= 0);
    const seconds: u64 = @intCast(now.sec);
    const nanoseconds: u64 = @intCast(now.nsec);
    assert(nanoseconds < 1_000_000_000);
    return seconds * 1000 + @divFloor(nanoseconds, 1_000_000);
}

const Failure = enum { none, eof, timed_out, io };

/// A connected socket with the deadlines of the call, and a `Reader` and `Writer` over it for the
/// layers above. Every wait ends at the idle timeout or the call's deadline, whichever is first.
const Socket = struct {
    fd: i32,
    idle_ms: u32,
    /// Absolute monotonic time the whole call must end by; zero for no limit.
    deadline_ms: u64,
    failure: Failure,
    reader: Io.Reader,
    writer: Io.Writer,

    fn remaining_ms(socket: *const Socket) ?u32 {
        assert(socket.idle_ms > 0);
        assert(socket.idle_ms <= constants.net_request_timeout_ms);
        if (socket.deadline_ms == 0) return socket.idle_ms;
        const now = monotonic_ms();
        if (now >= socket.deadline_ms) return null;
        const left = socket.deadline_ms - now;
        const wait_ms: u32 = @intCast(@min(left, socket.idle_ms));
        assert(wait_ms > 0);
        return wait_ms;
    }

    /// Waits until the socket is ready for `events`.
    fn wait(socket: *Socket, events: i16) error{ TimedOut, Io }!void {
        assert(socket.fd >= 0);
        assert((events & (linux.POLL.IN | linux.POLL.OUT)) != 0);
        for (0..constants.eintr_retries_max + 1) |_| {
            const timeout = socket.remaining_ms() orelse return error.TimedOut;
            var entries = [1]linux.pollfd{.{ .fd = socket.fd, .events = events, .revents = 0 }};
            const rc = linux.poll(&entries, 1, @intCast(timeout));
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.TimedOut;
                    return;
                },
                .INTR => continue,
                else => |code| {
                    state.errno_last = @backingInt(code);
                    return error.Io;
                },
            }
        }
        return error.Io;
    }

    fn fail(socket: *Socket, kind: Failure) void {
        assert(kind != .none);
        assert(socket.idle_ms > 0);
        socket.failure = kind;
        assert(socket.failure == kind);
    }

    /// Reads at least one byte, or zero at the end of the stream.
    fn read_some(socket: *Socket, buffer: []u8) error{Failed}!u32 {
        assert(buffer.len > 0);
        assert(socket.fd >= 0);
        for (0..constants.net_io_calls_max) |_| {
            const rc = linux.recvfrom(socket.fd, buffer.ptr, buffer.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    assert(rc <= buffer.len);
                    return @intCast(rc);
                },
                .AGAIN => socket.wait(linux.POLL.IN) catch |err| return socket.failed(err),
                .INTR => continue,
                else => |code| {
                    state.errno_last = @backingInt(code);
                    socket.fail(.io);
                    return error.Failed;
                },
            }
        }
        socket.fail(.io);
        return error.Failed;
    }

    fn failed(socket: *Socket, err: error{ TimedOut, Io }) error{Failed} {
        const kind: Failure = if (err == error.TimedOut) .timed_out else .io;
        socket.fail(kind);
        assert(socket.failure != .none);
        assert(socket.failure == kind);
        return error.Failed;
    }

    fn write_all(socket: *Socket, bytes: []const u8) error{Failed}!void {
        assert(socket.fd >= 0);
        assert(bytes.len <= constants.write_bytes_max * 4);
        var at: usize = 0;
        for (0..constants.write_calls_max) |_| {
            if (at == bytes.len) return;
            const rest = bytes[at..];
            const rc = linux.sendto(socket.fd, rest.ptr, rest.len, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    at += rc;
                    assert(at <= bytes.len);
                },
                .AGAIN => socket.wait(linux.POLL.OUT) catch |err| return socket.failed(err),
                .INTR => continue,
                else => |code| {
                    state.errno_last = @backingInt(code);
                    socket.fail(.io);
                    return error.Failed;
                },
            }
        }
        socket.fail(.io);
        return error.Failed;
    }

    fn close(socket: *Socket) void {
        if (socket.fd < 0) return;
        assert(socket.idle_ms > 0);
        _ = linux.shutdown(socket.fd, linux.SHUT.RDWR);
        _ = linux.close(socket.fd);
        socket.fd = -1;
        assert(socket.fd < 0);
    }
};

fn socket_from_reader(reader: *Io.Reader) *Socket {
    const socket: *Socket = @alignCast(@fieldParentPtr("reader", reader));
    assert(socket.fd >= -1);
    assert(&socket.reader == reader);
    return socket;
}

fn socket_from_writer(writer: *Io.Writer) *Socket {
    const socket: *Socket = @alignCast(@fieldParentPtr("writer", writer));
    assert(socket.fd >= -1);
    assert(&socket.writer == writer);
    return socket;
}

fn reader_stream(
    reader: *Io.Reader,
    writer: *Io.Writer,
    limit: Io.Limit,
) Io.Reader.StreamError!usize {
    const socket = socket_from_reader(reader);
    const room = limit.slice(try writer.writableSliceGreedy(1));
    assert(room.len > 0);
    const count = socket.read_some(room) catch return error.ReadFailed;
    assert(count <= room.len);
    if (count == 0) {
        socket.fail(.eof);
        return error.EndOfStream;
    }
    writer.advance(count);
    return count;
}

fn writer_drain(writer: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    assert(data.len > 0); // The contract of a drain: there is always a last slice to repeat.
    const socket = socket_from_writer(writer);
    socket.write_all(writer.buffered()) catch return error.WriteFailed;
    writer.end = 0;
    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |piece| {
        socket.write_all(piece) catch return error.WriteFailed;
        consumed += piece.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| socket.write_all(last) catch return error.WriteFailed;
    assert(writer.end == 0);
    return consumed + last.len * splat;
}

fn init_socket(socket: *Socket, fd: i32, idle_ms: u32, deadline_ms: u64) void {
    assert(fd >= 0);
    assert(idle_ms > 0);
    socket.* = .{
        .fd = fd,
        .idle_ms = idle_ms,
        .deadline_ms = deadline_ms,
        .failure = .none,
        .reader = .{
            .vtable = &.{ .stream = reader_stream },
            .buffer = &buffers.socket_read,
            .seek = 0,
            .end = 0,
        },
        .writer = .{
            .vtable = &.{ .drain = writer_drain },
            .buffer = &buffers.socket_write,
        },
    };
}

// ---- Connecting ----------------------------------------------------------------------------

const Address = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,
};

/// The addresses of `host`: the literal itself, or what the system's resolver finds.
fn resolve(host: []const u8, addresses: *[constants.net_addresses_max]Address) net.Error!u32 {
    assert(host.len > 0);
    assert(host.len <= 253);
    if (Io.net.Ip4Address.parse(host, 0)) |literal| {
        addresses[0] = .{ .ip4 = literal.bytes };
        return 1;
    } else |_| {}
    const name = Io.net.HostName.init(host) catch return error.UnknownHost;
    const io = global_io();
    var storage: [32]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&storage);
    var canonical: [Io.net.HostName.max_len]u8 = undefined;
    const options: Io.net.HostName.LookupOptions = .{
        .port = 0,
        .canonical_name_buffer = &canonical,
    };
    name.lookup(io, &queue, options) catch |err| switch (err) {
        error.SystemResources => return error.IoFailed,
        else => return error.UnknownHost,
    };
    var count: u32 = 0;
    while (queue.getOne(io)) |found| {
        switch (found) {
            .address => |address| {
                if (count == addresses.len) continue;
                addresses[count] = switch (address) {
                    .ip4 => |ip4| .{ .ip4 = ip4.bytes },
                    .ip6 => |ip6| .{ .ip6 = ip6.bytes },
                };
                count += 1;
            },
            .canonical_name => {},
        }
    } else |_| {}
    if (count == 0) return error.UnknownHost;
    assert(count <= addresses.len);
    return count;
}

/// A non-blocking stream socket connecting to `address:port`; its descriptor, once connected.
fn connect_one(address: Address, port: u16, idle_ms: u32, deadline_ms: u64) error{Connect}!i32 {
    assert(port != 0);
    assert(idle_ms > 0);
    const family: u32 = switch (address) {
        .ip4 => linux.AF.INET,
        .ip6 => linux.AF.INET6,
    };
    const kind = linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
    const created = linux.socket(family, kind, 0);
    if (linux.errno(created) != .SUCCESS) {
        state.errno_last = @backingInt(linux.errno(created));
        return error.Connect;
    }
    const fd: i32 = @intCast(created);
    errdefer _ = linux.close(fd);
    var storage: linux.sockaddr.storage = undefined;
    const length = fill_address(&storage, address, port);
    const rc = linux.connect(fd, @ptrCast(&storage), length);
    switch (linux.errno(rc)) {
        .SUCCESS => {
            assert(fd >= 0);
            return fd;
        },
        .INPROGRESS, .INTR => {},
        else => |code| {
            state.errno_last = @backingInt(code);
            return error.Connect;
        },
    }
    var waiter: Socket = undefined;
    init_socket(&waiter, fd, idle_ms, deadline_ms);
    waiter.wait(linux.POLL.OUT) catch |err| {
        if (err == error.TimedOut) state.errno_last = @backingInt(linux.E.TIMEDOUT);
        return error.Connect;
    };
    var pending: i32 = 0;
    var size: linux.socklen_t = @sizeOf(i32);
    const got = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&pending), &size);
    if (linux.errno(got) != .SUCCESS) return error.Connect;
    if (pending != 0) {
        state.errno_last = @intCast(pending);
        return error.Connect;
    }
    assert(fd >= 0);
    assert(size == @sizeOf(i32));
    return fd;
}

fn fill_address(storage: *linux.sockaddr.storage, address: Address, port: u16) linux.socklen_t {
    assert(port != 0);
    assert(@sizeOf(linux.sockaddr.storage) >= @sizeOf(linux.sockaddr.in6));
    switch (address) {
        .ip4 => |bytes| {
            const target: *linux.sockaddr.in = @ptrCast(storage);
            target.* = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bytes) };
            return @sizeOf(linux.sockaddr.in);
        },
        .ip6 => |bytes| {
            const target: *linux.sockaddr.in6 = @ptrCast(storage);
            target.* = .{
                .port = std.mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = bytes,
                .scope_id = 0,
            };
            return @sizeOf(linux.sockaddr.in6);
        },
    }
}

/// Connects to the first address of `host` that answers.
fn connect_host(host: []const u8, port: u16, idle_ms: u32, deadline_ms: u64) net.Error!i32 {
    assert(host.len > 0);
    assert(port != 0);
    var addresses: [constants.net_addresses_max]Address = undefined;
    const count = try resolve(host, &addresses);
    assert(count >= 1);
    assert(count <= addresses.len);
    for (addresses[0..count]) |address| {
        if (connect_one(address, port, idle_ms, deadline_ms)) |fd| return fd else |_| {}
    }
    if (state.errno_last == @backingInt(linux.E.TIMEDOUT)) return error.TimedOut;
    return error.ConnectFailed;
}

// ---- The proxy -----------------------------------------------------------------------------

/// The proxy the request goes through, from the environment; null when it goes direct.
fn proxy_for(
    host: Host,
    request: *const net.Request,
    storage: *[constants.net_proxy_url_bytes_max]u8,
) net.Error!?proxy_mod.Proxy {
    assert(request.host.len > 0);
    assert(request.port != 0);
    if (request.scheme == .http) return null;
    const url = host.environment("HTTPS_PROXY", constants.net_proxy_url_bytes_max) orelse
        host.environment("https_proxy", constants.net_proxy_url_bytes_max) orelse return null;
    if (url.len == 0) return null;
    const list = host.environment("NO_PROXY", constants.net_no_proxy_bytes_max) orelse
        host.environment("no_proxy", constants.net_no_proxy_bytes_max) orelse "";
    if (proxy_mod.bypasses(list, request.host, request.port)) return null;
    assert(url.len <= storage.len);
    @memcpy(storage[0..url.len], url);
    return proxy_mod.parse_proxy(storage[0..url.len]) catch return error.ProxyFailed;
}

/// Opens the tunnel: `CONNECT host:port`, and a 2xx answer with nothing after it.
fn open_tunnel(
    socket: *Socket,
    proxy: proxy_mod.Proxy,
    request: *const net.Request,
) net.Error!void {
    assert(proxy.host.len > 0);
    assert(request.port != 0);
    var writer = Io.Writer.fixed(&buffers.request_head);
    const target = .{ request.host, request.port, request.host, request.port };
    // Cannot fail: the head buffer holds a host name, a port and a base64 userinfo of 255 bytes.
    writer.print("CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n", target) catch unreachable;
    if (proxy.userinfo.len > 0) {
        var encoded: [512]u8 = undefined;
        if (std.base64.standard.Encoder.calcSize(proxy.userinfo.len) > encoded.len) {
            return error.ProxyFailed;
        }
        const text = std.base64.standard.Encoder.encode(&encoded, proxy.userinfo);
        // Same bound.
        writer.print("Proxy-Authorization: Basic {s}\r\n", .{text}) catch unreachable;
    }
    writer.writeAll("\r\n") catch unreachable; // Same bound.
    socket.write_all(writer.buffered()) catch return socket_error(socket);
    var answer: [1024]u8 = undefined;
    var length: usize = 0;
    while (std.mem.indexOf(u8, answer[0..length], "\r\n\r\n") == null) {
        if (length == answer.len) return error.ProxyFailed;
        const count = socket.read_some(answer[length..]) catch return socket_error(socket);
        if (count == 0) return error.ProxyFailed;
        length += count;
    }
    const end = std.mem.indexOf(u8, answer[0..length], "\r\n\r\n").? + 4;
    if (end != length) return error.ProxyFailed; // A proxy says nothing before the handshake.
    const line = answer[0..end];
    if (!std.mem.startsWith(u8, line, "HTTP/1.")) return error.ProxyFailed;
    if (line.len < 12) return error.ProxyFailed;
    if (line[9] != '2') return error.ProxyFailed;
    assert(end == length);
    assert(end >= 12);
}

fn socket_error(socket: *const Socket) net.Error {
    assert(@backingInt(socket.failure) <= @backingInt(Failure.io));
    assert(socket.idle_ms > 0);
    return switch (socket.failure) {
        .timed_out => error.TimedOut,
        .eof => error.Truncated,
        .io, .none => error.IoFailed,
    };
}

// ---- TLS -----------------------------------------------------------------------------------

/// Loads the CA certificates once: the file `SSL_CERT_FILE` names, else the system's.
fn load_certificates(real: *HostReal) net.Error!void {
    assert(buffers.ca_arena.len == constants.net_ca_arena_bytes);
    if (state.ca_ready) return;
    state.ca_allocator = std.heap.FixedBufferAllocator.init(&buffers.ca_arena);
    const gpa = state.ca_allocator.allocator();
    const io = global_io();
    const now = Io.Clock.real.now(io);
    const host = real.interface();
    var loaded = false;
    if (host.environment("SSL_CERT_FILE", constants.path_bytes_max)) |path| {
        if (path.len > 0 and path[0] == '/') {
            const added = state.ca_bundle.addCertsFromFilePathAbsolute(gpa, io, now, path);
            loaded = if (added) |_| true else |_| false;
        }
    }
    if (!loaded) state.ca_bundle.rescan(gpa, io, now) catch return error.NoCertificates;
    if (state.ca_bundle.map.count() == 0) return error.NoCertificates;
    state.ca_ready = true;
    assert(state.ca_bundle.map.count() > 0);
    assert(state.ca_ready);
}

fn tls_error(err: tls.Client.InitError, socket: *const Socket) net.Error {
    assert(@errorName(err).len > 0);
    assert(socket.idle_ms > 0);
    return switch (err) {
        error.ReadFailed, error.WriteFailed => switch (socket.failure) {
            .timed_out => error.TimedOut,
            .eof => error.TlsFailed,
            .io, .none => error.ConnectFailed,
        },
        error.CertificateHostMismatch => error.TlsHostMismatch,
        error.CertificateExpired, error.CertificateNotYetValid, error.CertificateTimeInvalid => {
            return error.TlsExpired;
        },
        error.TlsCertificateNotVerified, error.CertificateIssuerMismatch => error.TlsUntrusted,
        else => error.TlsFailed,
    };
}

fn start_tls(real: *HostReal, socket: *Socket, host: []const u8) net.Error!tls.Client {
    assert(host.len > 0);
    assert(socket.fd >= 0);
    try load_certificates(real);
    const io = global_io();
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    const options: tls.Client.Options = .{
        .host = .{ .explicit = host },
        .ca = .{ .bundle = .{
            .gpa = state.ca_allocator.allocator(),
            .io = io,
            .lock = &state.ca_lock,
            .bundle = &state.ca_bundle,
        } },
        .write_buffer = &buffers.tls_write,
        .read_buffer = &buffers.tls_read,
        .entropy = &entropy,
        .realtime_now = Io.Clock.real.now(io),
        // Truncation is caught by the HTTP layer: a body shorter than its declared length is an
        // error here (`Truncated`), and a chunked body must end in its terminating chunk.
        .allow_truncation_attacks = true,
    };
    return tls.Client.init(&socket.reader, &socket.writer, options) catch |err| {
        return tls_error(err, socket);
    };
}

// ---- The request ---------------------------------------------------------------------------

fn write_request(writer: *Io.Writer, request: *const net.Request) Io.Writer.Error!void {
    assert(request.target[0] == '/');
    assert(request.host.len > 0);
    const default_port: u16 = if (request.scheme == .https) 443 else 80;
    try writer.print("GET {s} HTTP/1.1\r\nHost: {s}", .{ request.target, request.host });
    if (request.port != default_port) try writer.print(":{d}", .{request.port});
    try writer.print("\r\nUser-Agent: zbx/{s}\r\n", .{build_options.version});
    try writer.writeAll("Accept-Encoding: identity\r\nConnection: close\r\n");
    if (request.accept.len > 0) try writer.print("Accept: {s}\r\n", .{request.accept});
    if (request.range_from > 0) try writer.print("Range: bytes={d}-\r\n", .{request.range_from});
    if (request.bearer.len > 0) {
        try writer.print("Authorization: Bearer {s}\r\n", .{request.bearer});
    }
    try writer.writeAll("\r\n");
}

fn fill_head(head: *net.Head, parsed: http.Client.Response.Head) net.Error!void {
    assert(head.body_len == 0);
    assert(head.status == 0);
    head.status = @backingInt(parsed.status);
    head.content_length = parsed.content_length;
    if (head.status < 200) return error.BadResponse; // We never ask for 100-continue.
    if (parsed.content_encoding != .identity) return error.BadResponse;
    var headers = parsed.iterateHeaders();
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) {
            if (!head.www_authenticate.present) head.www_authenticate.set(header.value);
        } else if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) {
            if (!head.retry_after.present) head.retry_after.set(header.value);
        } else if (std.ascii.eqlIgnoreCase(header.name, "docker-content-digest")) {
            if (!head.content_digest.present) head.content_digest.set(header.value);
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-range")) {
            if (!head.content_range.present) head.content_range.set(header.value);
        }
    }
    if (parsed.content_type) |text| head.content_type.set(text);
    if (parsed.location) |text| head.location.set(text);
    assert(head.status >= 200);
    assert(head.status <= 599);
}

/// The reader positioned after the head, and how the body is framed.
const Response = struct {
    reader: http.Reader,
    transfer_encoding: http.TransferEncoding,
};

fn read_head(
    in: *Io.Reader,
    socket: *const Socket,
    head: *net.Head,
    response: *Response,
) net.Error!void {
    assert(in.buffer.len >= constants.registry_head_bytes_max);
    assert(head.status == 0);
    response.reader = .{
        .in = in,
        .interface = undefined,
        .state = .ready,
        .max_head_len = constants.registry_head_bytes_max,
    };
    const bytes = response.reader.receiveHead() catch |err| switch (err) {
        error.HttpHeadersOversize => return error.TooLarge,
        error.ReadFailed => return socket_error(socket),
        else => return error.Truncated,
    };
    if (bytes.len > constants.registry_head_bytes_max) return error.TooLarge;
    const parsed = http.Client.Response.Head.parse(bytes) catch return error.BadResponse;
    try fill_head(head, parsed);
    response.transfer_encoding = parsed.transfer_encoding;
    assert(head.status >= 200);
    assert(bytes.len <= constants.registry_head_bytes_max);
}

fn read_body(
    response: *Response,
    request: *const net.Request,
    socket: *const Socket,
    head: *net.Head,
    sink: net.Sink,
) net.Error!void {
    assert(head.status >= 200);
    assert(head.body_len == 0);
    if (head.content_length) |declared| {
        if (declared > request.body_bytes_max) return error.TooLarge;
    }
    const reader = &response.reader;
    var transfer: [64]u8 = undefined;
    const body = reader.bodyReader(&transfer, response.transfer_encoding, head.content_length);
    var chunk: [8192]u8 = undefined;
    while (true) {
        const count = body.readSliceShort(&chunk) catch {
            if (reader.body_err != null) return error.Truncated;
            return socket_error(socket);
        };
        if (count > request.body_bytes_max - head.body_len) return error.TooLarge;
        sink.write(sink.context, chunk[0..count]) catch return error.SinkFailed;
        head.body_len += count;
        if (count < chunk.len) break;
    }
    assert(head.body_len <= request.body_bytes_max);
    if (head.content_length) |declared| {
        if (head.body_len < declared) return error.Truncated;
    }
}

fn get(
    context: *anyopaque,
    request: *const net.Request,
    head: *net.Head,
    sink: net.Sink,
) net.Error!void {
    const real: *HostReal = @ptrCast(@alignCast(context));
    assert(request.port != 0);
    assert(request.host.len > 0);
    assert(!state.busy); // Not reentrant: one call at a time, from the parent process.
    state.busy = true;
    defer state.busy = false;
    state.errno_last = 0;
    var socket: Socket = undefined;
    const started = monotonic_ms();
    const deadline = if (request.total_timeout_ms == 0) 0 else started + request.total_timeout_ms;
    var proxy_storage: [constants.net_proxy_url_bytes_max]u8 = undefined;
    const proxy = try proxy_for(real.interface(), request, &proxy_storage);
    const via_host = if (proxy) |found| found.host else request.host;
    const via_port = if (proxy) |found| found.port else request.port;
    const fd = try connect_host(via_host, via_port, request.idle_timeout_ms, deadline);
    init_socket(&socket, fd, request.idle_timeout_ms, deadline);
    defer socket.close();
    if (proxy) |found| try open_tunnel(&socket, found, request);
    if (request.scheme == .https) {
        var client = try start_tls(real, &socket, request.host);
        return exchange(request, head, sink, &socket, &client.reader, &client.writer);
    }
    socket.reader.buffer = &buffers.tls_read;
    return exchange(request, head, sink, &socket, &socket.reader, &socket.writer);
}

fn exchange(
    request: *const net.Request,
    head: *net.Head,
    sink: net.Sink,
    socket: *Socket,
    in: *Io.Reader,
    out: *Io.Writer,
) net.Error!void {
    assert(socket.fd >= 0);
    assert(state.busy);
    var writer = Io.Writer.fixed(&buffers.request_head);
    write_request(&writer, request) catch return error.Unsupported;

    out.writeAll(writer.buffered()) catch return socket_error(socket);
    out.flush() catch return socket_error(socket);
    // TLS wrote its records into the socket's own buffer: that one is sent too.
    socket.writer.flush() catch return socket_error(socket);
    var response: Response = undefined;
    try read_head(in, socket, head, &response);
    try read_body(&response, request, socket, head, sink);
}

// ---- Tests ---------------------------------------------------------------------------------
//
// The real network against the test registry on loopback (src/testing/vm/registry_server.zig):
// sockets, the head parser, chunked bodies, deadlines, tunnels. TLS against a real peer is not
// testable without a TLS server and is done by hand (docs/demos/m4.md).

const testing = std.testing;
const client_mod = @import("registry/client.zig");
const client_tests = @import("registry/client_tests.zig");
const fixture_mod = @import("testing/vm/registry_fixture.zig");
const manifest = @import("registry/manifest.zig");
const reference_mod = @import("registry/reference.zig");
const registry_server = @import("testing/vm/registry_server.zig");
const Diag = @import("diag/diag.zig").Diag;
const HostSim = @import("host_sim.zig").HostSim;

var test_workspace: client_mod.Workspace = undefined;

const Loopback = struct {
    server: registry_server.Server,
    fixture: fixture_mod.Fixture,

    fn start(loopback: *Loopback, mode: registry_server.Mode) !void {
        loopback.server = .{ .mode = mode };
        try loopback.server.bind();
        var base: [48]u8 = undefined;
        var other: [48]u8 = undefined;
        const port = loopback.server.port;
        const here = try std.fmt.bufPrint(&base, "http://127.0.0.1:{d}", .{port});
        const there = try std.fmt.bufPrint(&other, "http://localhost:{d}", .{port});
        loopback.fixture.init(here, there);
        try loopback.server.serve(&loopback.fixture);
    }

    fn stop(loopback: *Loopback) void {
        loopback.server.stop();
    }

    fn resolve(
        loopback: *Loopback,
        scenario: fixture_mod.Scenario,
        diag: *Diag,
    ) !manifest.Resolved {
        var text: [96]u8 = undefined;
        const name = @tagName(scenario);
        const port = loopback.server.port;
        const format = "127.0.0.1:{d}/fixture/{s}:3.20";
        const written = try std.fmt.bufPrint(&text, format, .{ port, name });
        var reference: reference_mod.Reference = undefined;
        try reference_mod.parse(written, &reference);
        var real: HostReal = .{};
        var client = client_mod.Client.init(interface(&real), &test_workspace, "x86_64");
        var resolved: manifest.Resolved = undefined;
        diag.reset();
        try client_mod.resolve(&client, &reference, &resolved, diag);
        return resolved;
    }
};

test "over TCP every scenario gives the result it gives in the simulator" {
    // Goal: the real sockets, the head parser and the client agree with the simulator on all
    // every scenario, in normal and in chunked framing.
    var loopback: Loopback = undefined;
    var diag: Diag = undefined;
    for ([_]registry_server.Mode{ .normal, .chunked }) |mode| {
        try loopback.start(mode);
        defer loopback.stop();
        for (client_tests.expectations) |expectation| {
            const result = loopback.resolve(expectation.scenario, &diag);
            if (expectation.code) |code| {
                try testing.expectError(error.Failed, result);
                try testing.expectEqual(@as(?@TypeOf(code), code), diag.code);
            } else {
                const resolved = try result;
                const item = loopback.fixture.manifest_of(expectation.scenario);
                const digest = resolved.manifest_digest.text();
                try testing.expectEqualStrings(&item.digest, &digest);
                const layers = loopback.fixture.layers_of(expectation.scenario);
                try testing.expectEqual(layers, resolved.layer_count);
            }
        }
    }
}

test "the token goes to the registry's origin and not to another host over TCP" {
    // Goal: the bearer flow on a real wire: the log shows the 401, the token request without a
    // token, the repeat with one, and for a redirect to another host name, no token at all.
    var loopback: Loopback = undefined;
    var diag: Diag = undefined;
    try loopback.start(.normal);
    _ = try loopback.resolve(.redirectfar, &diag);
    loopback.stop();
    const log = &loopback.server.log;
    try testing.expect(std.mem.indexOf(u8, log[0].text(), "/manifests/3.20") != null);
    try testing.expectEqual(@as(u32, 0), log[0].bearer_len);
    try testing.expect(std.mem.indexOf(u8, log[1].text(), "GET /token?") != null);
    try testing.expectEqual(@as(u32, 0), log[1].bearer_len);
    try testing.expect(log[2].bearer_len > 0); // The repeat.
    try testing.expect(log[3].bearer_len == 0); // After the redirect to localhost.
    try testing.expect(std.mem.indexOf(u8, log[3].text(), "fixture/open") != null);
}

fn probe_request(port: u16, idle_ms: u32, total_ms: u32) net.Request {
    return .{
        .scheme = .http,
        .host = "127.0.0.1",
        .port = port,
        .target = "/v2/fixture/open/manifests/3.20",
        .accept = "",
        .bearer = "",
        .body_bytes_max = 1 << 20,
        .idle_timeout_ms = idle_ms,
        .total_timeout_ms = total_ms,
    };
}

const Probed = struct { status: u16, content_length: ?u64 };

/// One GET straight through the real network; only the error set, so a failed `expectError`
/// does not print a whole head.
fn probe(loopback: *Loopback, request: *const net.Request, storage: []u8) net.Error!Probed {
    var real: HostReal = .{};
    var sink: net.BufferSink = .{ .buffer = storage };
    var head: net.Head = .{};
    try interface(&real).get(request, &head, sink.sink());
    _ = loopback;
    return .{ .status = head.status, .content_length = head.content_length };
}

test "a peer that never answers is a timeout, idle or total, and quickly" {
    // Goal: both deadlines end a stalled call within a fraction of the default, with TimedOut.
    var loopback: Loopback = undefined;
    try loopback.start(.stall);
    defer loopback.stop();
    var storage: [4096]u8 = undefined;
    const started = monotonic_ms();
    const idle = probe_request(loopback.server.port, 200, 0);
    try testing.expectError(error.TimedOut, probe(&loopback, &idle, &storage));
    const total = probe_request(loopback.server.port, 10_000, 300);
    try testing.expectError(error.TimedOut, probe(&loopback, &total, &storage));
    try testing.expect(monotonic_ms() - started < 3000);
}

test "a closed port is a refused connection, with the errno" {
    // Goal: ConnectFailed, and the real errno (ECONNREFUSED) is there for the verbose cause.
    var loopback: Loopback = undefined;
    try loopback.start(.normal);
    loopback.stop();
    loopback.server.unbind();
    var storage: [64]u8 = undefined;
    const request = probe_request(loopback.server.port, 1000, 0);
    try testing.expectError(error.ConnectFailed, probe(&loopback, &request, &storage));
    try testing.expectEqual(@as(u16, @backingInt(linux.E.CONNREFUSED)), state.errno_last);
}

test "answers that are not usable: garbage, a fat head, a body over the bound" {
    // Goal: BadResponse, TooLarge for the head and for the body, SinkFailed for a full sink.
    var loopback: Loopback = undefined;
    var storage: [4096]u8 = undefined;
    try loopback.start(.garbage);
    var request = probe_request(loopback.server.port, 1000, 0);
    try testing.expectError(error.BadResponse, probe(&loopback, &request, &storage));
    loopback.stop();
    try loopback.start(.fat_head);
    request = probe_request(loopback.server.port, 1000, 0);
    try testing.expectError(error.TooLarge, probe(&loopback, &request, &storage));
    loopback.stop();
    try loopback.start(.chunked);
    defer loopback.stop();
    request = probe_request(loopback.server.port, 1000, 0);
    request.body_bytes_max = 10;
    try testing.expectError(error.TooLarge, probe(&loopback, &request, &storage));
    request.body_bytes_max = 1 << 20;
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.SinkFailed, probe(&loopback, &request, &tiny));
    const answered = try probe(&loopback, &request, &storage);
    try testing.expectEqual(@as(u16, 200), answered.status);
    try testing.expectEqual(@as(?u64, null), answered.content_length);
}

test "a tunnel: CONNECT with the proxy's credentials, a refusal, and no TLS behind it" {
    // Goal: open_tunnel sends the right request and reads a 2xx; a 407 is ProxyFailed; and a
    // tunnel to a peer that does not speak TLS ends the handshake as TlsFailed.
    var loopback: Loopback = undefined;
    var real: HostReal = .{};
    try loopback.start(.normal);
    var socket: Socket = undefined;
    var request = probe_request(loopback.server.port, 1000, 0);
    request.scheme = .https;
    request.host = "registry.test";
    request.port = 443;
    const fd = try connect_host("127.0.0.1", loopback.server.port, 1000, 0);
    init_socket(&socket, fd, 1000, 0);
    const proxy: proxy_mod.Proxy = .{
        .host = "127.0.0.1",
        .port = loopback.server.port,
        .userinfo = "user:pw",
    };
    try open_tunnel(&socket, proxy, &request);
    // The handshake reads a closed peer: TlsFailed. On a machine with no CA file at all the
    // certificates are the first thing missing, which is a different, also honest, answer.
    const handshake = start_tls(&real, &socket, "registry.test");
    if (handshake) |_| return error.TestUnexpectedResult else |err| {
        try testing.expect(err == error.TlsFailed or err == error.NoCertificates);
    }

    socket.close();
    loopback.stop();
    const line = loopback.server.log[0].text();
    try testing.expectEqualStrings("CONNECT registry.test:443 HTTP/1.1", line);

    try testing.expect(loopback.server.log[0].proxy_authorization);

    try loopback.start(.refuse_tunnel);
    defer loopback.stop();
    const again = try connect_host("127.0.0.1", loopback.server.port, 1000, 0);
    init_socket(&socket, again, 1000, 0);
    defer socket.close();
    try testing.expectError(error.ProxyFailed, open_tunnel(&socket, proxy, &request));
}

test "the proxy comes from the environment and NO_PROXY bypasses it" {
    // Goal: HTTPS_PROXY (either case) is used for https, never for plain http, and NO_PROXY wins.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    var storage: [constants.net_proxy_url_bytes_max]u8 = undefined;
    var request = probe_request(443, 1000, 0);
    request.scheme = .https;
    request.host = "registry-1.docker.io";
    request.port = 443;
    try testing.expect((try proxy_for(sim.interface(), &request, &storage)) == null);
    sim.environment_variables = &.{.{ .name = "https_proxy", .value = "http://proxy.corp:3128" }};
    const found = (try proxy_for(sim.interface(), &request, &storage)).?;
    try testing.expectEqualStrings("proxy.corp", found.host);
    try testing.expectEqual(@as(u16, 3128), found.port);
    request.scheme = .http;
    try testing.expect((try proxy_for(sim.interface(), &request, &storage)) == null);
    request.scheme = .https;
    sim.environment_variables = &.{
        .{ .name = "HTTPS_PROXY", .value = "http://proxy.corp:3128" },
        .{ .name = "NO_PROXY", .value = "docker.io,.docker.io" },
    };
    try testing.expect((try proxy_for(sim.interface(), &request, &storage)) == null);
    sim.environment_variables = &.{.{ .name = "HTTPS_PROXY", .value = "socks5://proxy:1080" }};
    try testing.expectError(error.ProxyFailed, proxy_for(sim.interface(), &request, &storage));
}
