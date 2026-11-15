//! The chunks the serving threads share. The kernel sends a buffered read of a lazy file as
//! 128 KiB `READ`s (`max_readahead`; docs/decisions/2026-11-14-s2-probe-findings.md), eight to a
//! 1 MiB chunk, and with several serving threads those eight may land on different threads. The
//! cache makes them one chunk read: the first thread to want a chunk reads it into a slot, the
//! others wait on that slot and copy from it. Each chunk read is then one `Chunks.read`, so the
//! resolver sees one read per chunk, in order, and counts a file read front to back as sequential
//! (`lazy_readahead_chunks`).
//!
//! The cache is fixed at start: `slots` chunks, the least recently used one given up for a new
//! chunk. A slot in use (being read, or being copied from) is never given up. A serving thread
//! holds at most one slot at a time and there are at most `lazy_fuse_threads` of them, so with
//! more slots than threads a free one always exists. A failed read is not kept: the threads that
//! waited on it answer `EIO`, and the next request asks again.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const ops = @import("ops.zig");

const Digest = digest_mod.Digest;

/// Chunks held: twice the serving threads, so each may have one in use and one kept.
pub const slots: u32 = 2 * constants.lazy_fuse_threads;

comptime {
    assert(slots > constants.lazy_fuse_threads);
    assert(slots <= 64);
}

/// The cache's chunk memory for a chunk size.
pub fn memory_bytes(chunk_bytes: u32) u64 {
    assert(chunk_bytes > 0);
    return @as(u64, slots) * chunk_bytes;
}

const State = enum(u8) { empty, reading, ready, failed };

const Slot = struct {
    state: State,
    id: Digest,
    index: u32,
    len: u32,
    /// Threads reading, waiting on or copying from the slot. Never given up while above zero.
    users: u32,
    /// When it was last wanted, in `Cache.clock` ticks.
    used: u64,
};

/// A slot taken by `pin`: its verified bytes, valid until `unpin`.
pub const Pin = struct { slot: u32, bytes: []const u8 };

pub const Cache = struct {
    io: std.Io,
    mutex: std.Io.Mutex,
    read_done: std.Io.Condition,
    chunk_bytes: u32,
    memory: []u8,
    table: [slots]Slot,
    clock: u64,

    /// An empty cache over `memory` (`memory_bytes(chunk_bytes)` long).
    pub fn init(cache: *Cache, io: std.Io, memory: []u8, chunk_bytes: u32) void {
        assert(memory.len == memory_bytes(chunk_bytes));
        cache.* = .{
            .io = io,
            .mutex = .init,
            .read_done = .init,
            .chunk_bytes = chunk_bytes,
            .memory = memory,
            .table = undefined,
            .clock = 0,
        };
        for (&cache.table) |*slot| slot.* = .{
            .state = .empty,
            .id = undefined,
            .index = 0,
            .len = 0,
            .users = 0,
            .used = 0,
        };
    }

    /// Chunk `index` of `object`, `expected` bytes long: held already, read by another thread
    /// (waited for), or read now through `chunks`. A read that fails or returns another length
    /// is `error.Unavailable`, and nothing is kept.
    pub fn pin(
        cache: *Cache,
        chunks: ops.Chunks,
        object: ops.Object,
        index: u32,
        expected: u32,
    ) ops.ChunkError!Pin {
        assert(expected > 0);
        assert(expected <= cache.chunk_bytes);
        cache.mutex.lockUncancelable(cache.io);
        defer cache.mutex.unlock(cache.io);
        cache.clock += 1;
        if (cache.find(object.id, index)) |found| {
            const slot = &cache.table[found];
            slot.users += 1;
            slot.used = cache.clock;
            while (slot.state == .reading) cache.read_done.waitUncancelable(cache.io, &cache.mutex);
            // Held by `users`: never given up meanwhile.
            assert(slot.id.eql(object.id));
            assert(slot.index == index);
            if (slot.state == .failed) {
                cache.release(found);
                return error.Unavailable;
            }
            assert(slot.state == .ready);
            assert(slot.len == expected);
            return .{ .slot = found, .bytes = cache.bytes(found)[0..slot.len] };
        }
        const taken = cache.victim();
        const slot = &cache.table[taken];
        slot.* = .{
            .state = .reading,
            .id = object.id,
            .index = index,
            .len = 0,
            .users = 1,
            .used = cache.clock,
        };
        // The read runs unlocked: other chunks are served meanwhile, and threads wanting this
        // one wait on the slot.
        cache.mutex.unlock(cache.io);
        const got = chunks.read(chunks.context, object, index, cache.bytes(taken));
        cache.mutex.lockUncancelable(cache.io);
        assert(slot.state == .reading);
        assert(slot.users >= 1);
        cache.read_done.broadcast(cache.io);
        // A length the object's size does not give is a source that lied.
        const length = got catch 0;
        if (length != expected) {
            slot.state = .failed;
            cache.release(taken);
            return error.Unavailable;
        }
        slot.state = .ready;
        slot.len = length;
        return .{ .slot = taken, .bytes = cache.bytes(taken)[0..length] };
    }

    /// Gives back a slot `pin` returned: its bytes may be replaced from now on.
    pub fn unpin(cache: *Cache, pinned: Pin) void {
        assert(pinned.slot < slots);
        cache.mutex.lockUncancelable(cache.io);
        defer cache.mutex.unlock(cache.io);
        assert(cache.table[pinned.slot].state == .ready);
        cache.release(pinned.slot);
    }

    fn release(cache: *Cache, index: u32) void {
        const slot = &cache.table[index];
        assert(slot.users > 0);
        assert(slot.state != .empty);
        assert(slot.state != .reading);
        slot.users -= 1;
        if (slot.state == .failed and slot.users == 0) slot.state = .empty;
    }

    fn find(cache: *const Cache, id: Digest, index: u32) ?u32 {
        for (&cache.table, 0..) |*slot, at| {
            if (slot.state == .empty) continue;
            if (slot.state == .failed) continue; // Being given up: a new read is due.
            if (slot.index == index and slot.id.eql(id)) return @intCast(at);
        }
        return null;
    }

    /// An empty slot, or else the least recently used one no thread is using.
    fn victim(cache: *const Cache) u32 {
        var best: ?u32 = null;
        for (&cache.table, 0..) |*slot, at| {
            if (slot.state == .empty) return @intCast(at);
            if (slot.users > 0) continue;
            assert(slot.state == .ready);
            if (best == null or slot.used < cache.table[best.?].used) best = @intCast(at);
        }
        // At most `lazy_fuse_threads` slots are in use, and there are more slots than that.
        return best.?;
    }

    fn bytes(cache: *const Cache, index: u32) []u8 {
        assert(index < slots);
        return cache.memory[index * cache.chunk_bytes ..][0..cache.chunk_bytes];
    }
};
