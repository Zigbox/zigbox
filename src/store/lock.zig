//! The store lock: one file, `<root>/lock`, and `flock` on it.
//!
//! Why: an import that finds an object already in the store reuses it instead of writing it, and
//! a gc that is moving that object to the trash at the same moment leaves a tree that names a
//! missing object. So every operation that may reuse what is in the store, or put something in
//! that nothing reaches yet, holds the lock **shared** (many at once) for the whole operation:
//! an import with its root record, a commit, the build of a materialized directory, the chunk
//! writes. A gc apply and a restore, which move things out of the way of readers, hold it
//! **exclusive**: they wait for the writers to finish and keep new ones out. A gc plan and a
//! verify read only and take nothing; the plan is made again under the exclusive lock, so a
//! confirmed plan is compared with a store that nothing is writing.
//!
//! The wait is bounded (`Store.lock_wait_ms`, 10 s by default, tried every 20 ms without
//! blocking): past it `hold` returns `Busy`, and the caller says who holds the lock. An
//! exclusive holder writes `<pid> <command>` into the file; a shared holder writes nothing, so
//! a gc that is kept waiting by importers says only that writers are active. The lock goes when
//! the descriptor is closed, so a killed process never leaves one behind.
//!
//! Holds nest within one `Store` value: a caller that needs the lock across several library
//! calls (a commit and the recording of its root) takes it first, and the calls inside only
//! count. A shared hold may not be raised to an exclusive one (that could deadlock); asking is
//! a programming error.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");

const Store = layout.Store;
const PathBuf = fs_mod.PathBuf;

pub const Mode = enum { shared, exclusive };

/// `Busy`: the lock is held, `store.lock_holder` says by whom if known. `Failed`: the lock file
/// can not be used; `store.lock_error` and `store.lock_errno` say why.
pub const Error = error{ Busy, Failed };

pub const file_name = "/lock";

/// Takes the lock in `mode`, or counts one more hold if this store value has it already.
/// `who` names the operation for whoever has to wait for it ("gc", "restore").
pub fn hold(store: *Store, mode: Mode, who: []const u8) Error!void {
    assert(who.len > 0);
    assert(who.len + 12 <= constants.store_lock_holder_bytes);
    if (store.lock_depth > 0) {
        const upgrade = mode == .exclusive and !store.lock_exclusive;
        assert(!upgrade); // A shared hold is never raised to an exclusive one.
        store.lock_depth += 1;
        return;
    }
    const exclusive = mode == .exclusive;
    var storage: PathBuf = undefined;
    const path = store.path(&storage, &.{file_name});
    var record: [constants.store_lock_holder_bytes]u8 = undefined;
    const text: []const u8 = if (exclusive) std.fmt.bufPrint(&record, "{d} {s}", .{
        store.host.own_pid(),
        who,
    }) catch unreachable else ""; // Cannot fail: 10 digits, a space and `who` fit 64 bytes.
    const attempts = store.lock_wait_ms / constants.store_lock_retry_ms + 1;
    for (0..attempts) |attempt| {
        if (store.fs.lock(path, exclusive, text)) |fd| {
            store.lock_fd = fd;
            store.lock_depth = 1;
            store.lock_exclusive = exclusive;
            return;
        } else |err| {
            if (err != error.WouldBlock) {
                store.lock_error = err;
                store.lock_errno = store.fs.last_errno();
                return error.Failed;
            }
        }
        if (attempt + 1 < attempts) store.host.sleep_ms(constants.store_lock_retry_ms);
    }
    note_holder(store, path, exclusive);
    return error.Busy;
}

/// Ends one hold; the last one closes the descriptor and so frees the lock.
pub fn release(store: *Store) void {
    assert(store.lock_depth > 0);
    store.lock_depth -= 1;
    if (store.lock_depth == 0) {
        store.fs.close(store.lock_fd);
        store.lock_exclusive = false;
    }
}

/// Fills `store.lock_holder` after a wait that ran out. Only an exclusive holder leaves a
/// record, and a record is old if the blockers are shared holders, so for a caller that wanted
/// the exclusive lock one non-blocking shared try tells which: if that works, nobody holds it
/// exclusive and the record means nothing.
fn note_holder(store: *Store, path: [:0]const u8, wanted_exclusive: bool) void {
    assert(store.lock_depth == 0);
    store.lock_holder_len = 0;
    if (wanted_exclusive) {
        if (store.fs.lock(path, false, "")) |probe| {
            store.fs.close(probe);
            return;
        } else |_| {}
    }
    var buffer: [constants.store_lock_holder_bytes]u8 = undefined;
    const bytes = store.fs.read_whole(path, &buffer) catch return;
    const text = std.mem.trimEnd(u8, bytes, "\x00 \n");
    @memcpy(store.lock_holder[0..text.len], text);
    store.lock_holder_len = @intCast(text.len);
}

/// The holder's record, `<pid> <command>`, or empty when it is not known.
pub fn holder(store: *const Store) []const u8 {
    assert(store.lock_holder_len <= store.lock_holder.len);
    return store.lock_holder[0..store.lock_holder_len];
}
