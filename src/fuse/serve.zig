//! The serving threads, in the parent: each reads a request from `/dev/fuse`, answers it with
//! `ops.handle`, and writes the reply back, until the kernel ends the connection. The mount itself
//! is made in the container's single-threaded setup child (`host_real_fuse.mount`), which hands
//! the descriptor to the parent over a channel (`SCM_RIGHTS`).
//!
//! The first request on a new connection is `INIT`; `handshake` answers it on the calling thread
//! before any serving thread starts, so a kernel the server cannot serve is refused before the
//! run goes on. The kernel holds every other request until `INIT` is answered.
//!
//! Teardown: once the container has exited, `stop` sets a flag each thread looks at between
//! requests and at least every `fuse_poll_ms` (the device's wait), and `wait` joins them. A thread
//! also returns when the kernel ends the connection (`ENODEV`: the mount's last user is gone).
//! Nothing outside the run can keep the threads, so a holder of the mount outside (a descriptor
//! passed out of the container) cannot hang `zbx`: once the server closes its descriptor, the
//! kernel ends the connection and that holder gets `ENOTCONN`
//! (docs/decisions/2026-11-14-s2-lazy-teardown.md).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const abi = @import("abi.zig");
const ops = @import("ops.zig");

/// The kernel refuses (`EINVAL`) a read of `/dev/fuse` into a buffer shorter than a `WRITE` of
/// `max_write` would be: its header and `fuse_write_in`, 40 bytes each. A refused read makes
/// the serving thread spin and the mount hang, so the request buffer is held to it here.
const write_in_bytes = 40;
comptime {
    assert(@sizeOf(abi.InHeader) == 40);
    assert(constants.fuse_request_bytes >= @sizeOf(abi.InHeader) + write_in_bytes +
        constants.fuse_max_write);
    assert(constants.fuse_request_bytes >= 8192); // The kernel's `FUSE_MIN_READ_BUFFER`.
}

/// What a read of the device gives.
pub const ReceiveError = error{
    /// Nothing this time: no request within `fuse_poll_ms`, or `EINTR`, `EAGAIN`, or `ENOENT`
    /// for a request the kernel took back.
    Again,
    /// The connection is over (`ENODEV`, or anything else the device says).
    Ended,
};

/// `/dev/fuse` as the server uses it: one request per read, one reply per write. A read waits
/// at most `fuse_poll_ms` for a request. A reply the
/// kernel refuses (`ENOENT`, its request was interrupted) is dropped: nobody waits for it.
pub const Device = struct {
    context: *anyopaque,
    receive: *const fn (context: *anyopaque, buffer: []u8) ReceiveError!u32,
    send: *const fn (context: *anyopaque, bytes: []const u8) void,
};

pub const HandshakeError = error{
    /// The connection ended before `INIT` was answered.
    Ended,
    /// The first request was not `INIT`, or `INIT` was refused (a kernel older than 7.31).
    Refused,
    /// No request came within `fuse_init_timeout_ms`.
    TimedOut,
};

/// The device reads `handshake` makes before giving up: each waits at most `fuse_poll_ms`.
pub const handshake_polls_max: u32 = constants.fuse_init_timeout_ms / constants.fuse_poll_ms;

/// One serving thread's buffers: a request and a reply.
pub const thread_memory_bytes: u32 = constants.fuse_request_bytes + constants.fuse_reply_bytes;

pub const Serving = struct {
    server: *const ops.Server,
    device: Device,
    /// One chunk source per serving thread; the handshake uses the first.
    chunks: *const [constants.lazy_fuse_threads]ops.Chunks,
    memory: []align(8) u8,
    threads: [constants.lazy_fuse_threads]std.Thread,
    started: u32,
    /// Set by `stop`: each thread returns at its next look.
    stopping: std.atomic.Value(bool),

    /// `memory` holds `lazy_fuse_threads` threads' buffers (`thread_memory_bytes` each).
    /// Thread `i` reads chunks only through `chunks[i]`, so a source may keep its scratch space
    /// for one thread; one source may stand in every slot if it is safe from every thread.
    pub fn init(
        server: *const ops.Server,
        device: Device,
        chunks: *const [constants.lazy_fuse_threads]ops.Chunks,
        memory: []align(8) u8,
    ) Serving {
        assert(memory.len == @as(usize, constants.lazy_fuse_threads) * thread_memory_bytes);
        comptime assert(thread_memory_bytes % 8 == 0);
        return .{
            .server = server,
            .device = device,
            .chunks = chunks,
            .memory = memory,
            .threads = undefined,
            .started = 0,
            .stopping = .init(false),
        };
    }

    /// Answers the connection's `INIT` (more than one if the kernel asks again in our major).
    pub fn handshake(serving: *Serving) HandshakeError!void {
        assert(serving.started == 0);
        assert(!serving.stopping.load(.acquire));
        var thread_worker = serving.worker(0);
        const request = serving.request_buffer(0);
        var polls: u32 = 0;
        while (true) {
            if (polls == handshake_polls_max) return error.TimedOut;
            polls += 1;
            const got = serving.device.receive(serving.device.context, request) catch |err| {
                switch (err) {
                    error.Again => continue,
                    error.Ended => return error.Ended,
                }
            };
            const bytes = request[0..got];
            if (got < @sizeOf(abi.InHeader)) return error.Refused;
            const header = std.mem.bytesToValue(abi.InHeader, bytes[0..@sizeOf(abi.InHeader)]);
            if (header.opcode != @backingInt(abi.Opcode.init)) return error.Refused;
            const reply = ops.handle(serving.server, &thread_worker, bytes);
            assert(reply.len >= @sizeOf(abi.OutHeader));
            serving.device.send(serving.device.context, reply);
            const out = std.mem.bytesToValue(abi.OutHeader, reply[0..@sizeOf(abi.OutHeader)]);
            if (out.@"error" != 0) return error.Refused;
            const body = bytes[@sizeOf(abi.InHeader)..];
            const in = std.mem.bytesToValue(abi.InitIn, body[0..@sizeOf(abi.InitIn)]);
            // A newer major got ours back and asks again in it.
            if (in.major == abi.major_version) return;
        }
    }

    /// Starts the serving threads. On a failure, the threads already started go on serving and
    /// `wait` still joins them.
    pub fn start(serving: *Serving) std.Thread.SpawnError!void {
        assert(serving.started == 0);
        while (serving.started < constants.lazy_fuse_threads) {
            const index = serving.started;
            serving.threads[index] = try std.Thread.spawn(.{}, run, .{ serving, index });
            serving.started += 1;
        }
        assert(serving.started == constants.lazy_fuse_threads);
    }

    /// Tells every thread to return at its next look (within `fuse_poll_ms` and its request in
    /// hand). The connection itself ends when the descriptor is closed after `wait`.
    pub fn stop(serving: *Serving) void {
        assert(serving.started <= constants.lazy_fuse_threads);
        serving.stopping.store(true, .release);
        assert(serving.stopping.load(.acquire));
    }

    /// Returns once every started thread has returned: after `stop`, or once the connection ends.
    pub fn wait(serving: *Serving) void {
        assert(serving.started <= constants.lazy_fuse_threads);
        for (serving.threads[0..serving.started]) |thread| thread.join();
        serving.started = 0;
        assert(serving.started == 0);
    }

    fn run(serving: *Serving, index: u32) void {
        // Not `started`: the spawning thread counts this one only after the spawn returns.
        assert(index < constants.lazy_fuse_threads);
        var thread_worker = serving.worker(index);
        const request = serving.request_buffer(index);
        while (!serving.stopping.load(.acquire)) {
            const got = serving.device.receive(serving.device.context, request) catch |err| {
                switch (err) {
                    error.Again => continue,
                    error.Ended => return,
                }
            };
            assert(got <= request.len);
            const reply = ops.handle(serving.server, &thread_worker, request[0..got]);
            if (reply.len > 0) serving.device.send(serving.device.context, reply);
        }
    }

    fn worker(serving: *const Serving, index: u32) ops.Worker {
        assert(index < constants.lazy_fuse_threads);
        const at = @as(usize, index) * thread_memory_bytes;
        const bytes = serving.memory[at..][0..constants.fuse_reply_bytes];
        const reply: []align(8) u8 = @alignCast(bytes);
        return ops.Worker.init(serving.chunks[index], reply);
    }

    fn request_buffer(serving: *const Serving, index: u32) []u8 {
        assert(index < constants.lazy_fuse_threads);
        const at = @as(usize, index) * thread_memory_bytes + constants.fuse_reply_bytes;
        return serving.memory[at..][0..constants.fuse_request_bytes];
    }
};

/// A device that never has a request: every receive is `Again`, counted.
const Idle = struct {
    receives: std.atomic.Value(u32) = .init(0),

    fn device(idle: *Idle) Device {
        return .{ .context = idle, .receive = receive, .send = send };
    }

    fn receive(context: *anyopaque, buffer: []u8) ReceiveError!u32 {
        const idle: *Idle = @ptrCast(@alignCast(context));
        assert(buffer.len == constants.fuse_request_bytes);
        _ = idle.receives.fetchAdd(1, .monotonic);
        std.Thread.yield() catch {};
        return error.Again;
    }

    fn send(context: *anyopaque, bytes: []const u8) void {
        _ = context;
        _ = bytes;
        unreachable; // Nothing was received, so nothing is answered.
    }
};

const test_threads_partial = 2;
var test_memory: [constants.lazy_fuse_threads * thread_memory_bytes]u8 align(8) = undefined;

fn test_serving(idle: *Idle, chunks: *const [constants.lazy_fuse_threads]ops.Chunks) Serving {
    // No request reaches the server, so its table, cache and chunk sources are never read.
    const server: *const ops.Server = undefined;
    return Serving.init(server, idle.device(), chunks, &test_memory);
}

test "handshake: no INIT within the deadline is TimedOut after exactly the polls allowed" {
    // Goal: the INIT wait is bounded by `fuse_init_timeout_ms`, counted in device waits.
    // Method: a device that is never ready (it returns at once, as a poll timeout would); the
    // handshake gives up with `TimedOut` after `handshake_polls_max` receives, no more.
    var idle: Idle = .{};
    const chunks: [constants.lazy_fuse_threads]ops.Chunks = undefined;
    var serving = test_serving(&idle, &chunks);
    try std.testing.expectError(error.TimedOut, serving.handshake());
    try std.testing.expectEqual(handshake_polls_max, idle.receives.load(.monotonic));
    try std.testing.expectEqual(0, serving.started);
}

test "stop and wait join threads whose connection never ends, a partial start included" {
    // Goal: teardown does not depend on the kernel: threads that only ever see `Again` return
    // after `stop`, also when `start` failed partway (fewer threads started than wanted).
    // Method: start two of the threads as `start` would before a failed spawn, let them poll,
    // then `stop` and `wait`; every one is joined and none is left counted.
    var idle: Idle = .{};
    const chunks: [constants.lazy_fuse_threads]ops.Chunks = undefined;
    var serving = test_serving(&idle, &chunks);
    comptime assert(test_threads_partial < constants.lazy_fuse_threads);
    while (serving.started < test_threads_partial) {
        const index = serving.started;
        serving.threads[index] = try std.Thread.spawn(.{}, Serving.run, .{ &serving, index });
        serving.started += 1;
    }
    while (idle.receives.load(.monotonic) < 2 * test_threads_partial) std.Thread.yield() catch {};
    serving.stop();
    serving.wait();
    try std.testing.expectEqual(0, serving.started);
    const after = idle.receives.load(.monotonic);
    try std.testing.expect(after >= 2 * test_threads_partial);
}
