//! The serving threads, in the parent: each reads a request from `/dev/fuse`, answers it with
//! `ops.handle`, and writes the reply back, until the kernel ends the connection. The mount itself
//! is made in the container's single-threaded setup child (`host_real_fuse.mount`), which hands
//! the descriptor to the parent over a channel (`SCM_RIGHTS`).
//!
//! The first request on a new connection is `INIT`; `handshake` answers it on the calling thread
//! before any serving thread starts, so a kernel the server cannot serve is refused before the
//! run goes on. The kernel holds every other request until `INIT` is answered.
//!
//! Teardown: the connection ends when the mount's last user is gone, that is, when the container's
//! mount namespace ends with its last process. The kernel then answers every read with `ENODEV`,
//! each thread returns, and `wait` joins them. After a server dies with the mount still there,
//! a read the page cache cannot answer gets `ENOTCONN` (the probe, 2026-11-14).

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
    /// Nothing this time (`EINTR`, `EAGAIN`, or `ENOENT` for a request the kernel took back).
    Again,
    /// The connection is over (`ENODEV`, or anything else the device says).
    Ended,
};

/// `/dev/fuse` as the server uses it: one request per read, one reply per write. A reply the
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
};

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
        };
    }

    /// Answers the connection's `INIT` (more than one if the kernel asks again in our major).
    pub fn handshake(serving: *Serving) HandshakeError!void {
        assert(serving.started == 0);
        var thread_worker = serving.worker(0);
        const request = serving.request_buffer(0);
        while (true) {
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
            const in = std.mem.bytesToValue(abi.InitIn, bytes[@sizeOf(abi.InHeader)..][0..8]);
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
    }

    /// Returns once every started thread has seen the connection end.
    pub fn wait(serving: *Serving) void {
        assert(serving.started <= constants.lazy_fuse_threads);
        for (serving.threads[0..serving.started]) |thread| thread.join();
        serving.started = 0;
    }

    fn run(serving: *Serving, index: u32) void {
        var thread_worker = serving.worker(index);
        const request = serving.request_buffer(index);
        while (true) {
            const got = serving.device.receive(serving.device.context, request) catch |err| {
                switch (err) {
                    error.Again => continue,
                    error.Ended => return,
                }
            };
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
