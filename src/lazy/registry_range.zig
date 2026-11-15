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
    const deadline = started.addDuration(allowed);
    range.take_turn(deadline) catch {
        _ = range.failures.fetchAdd(1, .monotonic);
        return error.TimedOut;
    };
    defer range.give_turn();
    const left = remaining_ms(range.io, deadline) orelse {
        _ = range.failures.fetchAdd(1, .monotonic);
        return error.TimedOut;
    };
    range.diag.reset();
    const got = client_mod.fetch_range(
        range.client,
        range.reference,
        range.blob,
        offset,
        out,
        left,
        &range.diag,
    );
    return got catch |err| {
        _ = range.failures.fetchAdd(1, .monotonic);
        if (err == error.NotFound) return error.NotFound;
        // The wire says why it failed in the `Diag`; a call that used up its time timed out.
        if (remaining_ms(range.io, deadline) == null) return error.TimedOut;
        return error.Failed;
    };
}

/// The whole milliseconds left before `deadline`; null when none are.
fn remaining_ms(io: Io, deadline: Io.Clock.Timestamp) ?u32 {
    assert(deadline.clock == .awake);
    const now = Io.Clock.Timestamp.now(io, .awake);
    const left = now.durationTo(deadline).raw.toMilliseconds();
    if (left <= 0) return null;
    const bounded: u32 = @intCast(@min(left, std.math.maxInt(u32)));
    assert(bounded > 0);
    return bounded;
}
