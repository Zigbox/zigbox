//! The registry as the resolver's last source: a `lazy.Range` over one layer blob, by closed
//! `Range` requests through the registry client (`client.fetch_range`), after the run's resolve.
//!
//! The client is one connection's state (its token, the wire's buffers), so one fetch runs at a
//! time. A resolver thread waits for its turn for at most its `timeout_ms`, and what it waited
//! comes off the time its fetch is given: `fetch` returns within `timeout_ms` plus the wire's
//! own slack. The resolver coalesces neighbouring chunks into one request, so a turn is one
//! range of up to `lazy_range_bytes_max`.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const client_mod = @import("../registry/client.zig");
const digest_mod = @import("../registry/digest.zig");
const lazy = @import("lazy.zig");
const reference_mod = @import("../registry/reference.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;

pub const RegistryRange = struct {
    client: *client_mod.Client,
    reference: *const reference_mod.Reference,
    blob: digest_mod.Sha256,
    io: Io,
    mutex: Io.Mutex,
    turn: Io.Condition,
    /// A fetch holds the client. Guarded by `mutex`.
    busy: bool,
    /// The failure of the last fetch, for a test or a verbose log; used only by the fetch that
    /// holds the turn.
    diag: Diag,
    /// Fetches that ended in a failure, of any kind.
    failures: std.atomic.Value(u64),

    /// `client` has resolved `reference`: its token and the place that answered are set.
    pub fn init(
        range: *RegistryRange,
        client: *client_mod.Client,
        reference: *const reference_mod.Reference,
        blob: digest_mod.Sha256,
        io: Io,
    ) void {
        assert(client.places.count >= 1);
        assert(client.winner < client.places.count);
        range.client = client;
        range.reference = reference;
        range.blob = blob;
        range.io = io;
        range.mutex = .init;
        range.turn = .init;
        range.busy = false;
        range.diag.reset();
        range.failures = .init(0);
    }

    pub fn source(range: *RegistryRange) lazy.Range {
        assert(range.client.places.count >= 1);
        assert(range.client.winner < range.client.places.count);
        return .{ .context = range, .name = "registry", .fetch = fetch };
    }

    fn take_turn(range: *RegistryRange, deadline: Io.Clock.Timestamp) error{TimedOut}!void {
        assert(deadline.clock == .awake);
        range.mutex.lockUncancelable(range.io);
        defer range.mutex.unlock(range.io);
        while (range.busy) {
            const timeout: Io.Timeout = .{ .deadline = deadline };
            range.turn.waitTimeout(range.io, &range.mutex, timeout) catch return error.TimedOut;
        }
        range.busy = true;
        assert(range.busy);
    }

    fn give_turn(range: *RegistryRange) void {
        range.mutex.lockUncancelable(range.io);
        assert(range.busy);
        range.busy = false;
        range.mutex.unlock(range.io);
        range.turn.signal(range.io);
    }
};

fn fetch(context: *anyopaque, offset: u64, out: []u8, timeout_ms: u32) lazy.FetchError!usize {
    const range: *RegistryRange = @ptrCast(@alignCast(context));
    assert(out.len > 0);
    assert(timeout_ms > 0);
    const started = Io.Clock.Timestamp.now(range.io, .awake);
    const allowed: Io.Clock.Duration = .{
        .raw = .fromMilliseconds(timeout_ms),
        .clock = .awake,
    };
    const clock: client_mod.Clock = .{ .context = &range.io, .now_ms = io_now_ms };
    const deadline = client_mod.Deadline.after(clock, timeout_ms);
    range.take_turn(started.addDuration(allowed)) catch {
        _ = range.failures.fetchAdd(1, .monotonic);
        return error.TimedOut;
    };
    defer range.give_turn();
    if (deadline.remaining_ms(timeout_ms) == null) {
        _ = range.failures.fetchAdd(1, .monotonic);
        return error.TimedOut;
    }
    range.diag.reset();
    const got = client_mod.fetch_range(
        range.client,
        range.reference,
        range.blob,
        offset,
        out,
        deadline,
        timeout_ms,
        &range.diag,
    );
    return got catch |err| {
        _ = range.failures.fetchAdd(1, .monotonic);
        if (err == error.NotFound) return error.NotFound;
        // The wire says why it failed in the `Diag`; a call that used up its time timed out.
        if (deadline.remaining_ms(timeout_ms) == null) return error.TimedOut;
        return error.Failed;
    };
}

/// The awake clock of the `Io` at `context`, in milliseconds.
fn io_now_ms(context: *const anyopaque) u64 {
    const io: *const Io = @ptrCast(@alignCast(context));
    const now = Io.Clock.Timestamp.now(io.*, .awake);
    assert(now.clock == .awake);
    const ms = now.raw.toMilliseconds();
    assert(ms >= 0);
    return @intCast(ms);
}

pub const WholeError = error{
    /// The registry, or the time, failed; the `Diag` says which.
    Failed,
    /// The blob ended before `out` was full: the caller's offsets are not this blob's.
    Short,
};

/// All of `out`, from `offset` of blob `digest`, before lazy start uses any of it (the index):
/// as many range requests as the registry's answers take, all of them within
/// `net_request_timeout_ms` (a registry that drips a byte per answer is cut off), no one longer
/// than `lazy_read_deadline_ms`.
pub fn fetch_whole(
    client: *client_mod.Client,
    reference: *const reference_mod.Reference,
    digest: digest_mod.Sha256,
    offset: u64,
    out: []u8,
    clock: client_mod.Clock,
    diag: *Diag,
) WholeError!void {
    assert(out.len > 0);
    assert(diag.code == null);
    const deadline = client_mod.Deadline.after(clock, constants.net_request_timeout_ms);
    const each_ms = constants.lazy_read_deadline_ms;
    var done: usize = 0;
    while (done < out.len) {
        const at = offset + done;
        const rest = out[done..];
        const count = client_mod.fetch_range(
            client,
            reference,
            digest,
            at,
            rest,
            deadline,
            each_ms,
            diag,
        ) catch return error.Failed;
        assert(count <= rest.len);
        if (count == 0) return error.Short;
        done += count;
    }
    assert(done == out.len);
}
