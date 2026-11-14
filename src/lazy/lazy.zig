//! `zigbox.lazy`: the chunk resolver's public interface (S2, docs/briefs/S2-lazy-start.md).
//!
//! The resolver answers one question: give me chunk `index` of object `object`, verified. It
//! looks in the local store first (the object whole, or the chunk held in
//! `partial/<id>/<index>`), then asks the sources in order (the peers a library caller supplies,
//! then the registry by `Range` on a layer writer 2 blob), hashes every chunk it is given against
//! the chunk's listed hash, keeps it in the store with `chunks.put_chunk`, and only then reads
//! it back (checked again) into the caller's buffer. It owns the deadlines, the concurrency
//! limit, readahead, range coalescing, the background fill and each source's health. It knows
//! nothing of FUSE: the FUSE server (slice 4) calls `Resolver.read`, and a later VM front end
//! reuses it unchanged.
//!
//! What this file fixes, for the FUSE server, the run integration and Zigcube's agent:
//!
//!   - `Source`: what a peer source (Zigcube's swarm) implements. Its bytes are never trusted.
//!   - `Range`: the registry's blob, by `Range` request (`registry_range.zig` over the client).
//!   - `Catalog` and `Object`: what the lazy index gives the resolver, one entry per object of
//!     the tree, in the order the fill fetches them. The FUSE server addresses an object by its
//!     position here (`ObjectIndex`).
//!   - `Resolver`: `init`, `start`, `read`, `stop`, `report` (in `resolver.zig`).
//!   - `Event` and `Log`: the coded lines the resolver asks its caller to show (W1202, E1203,
//!     E1206); the caller limits them (`lazy_errors_shown_max`) and renders them.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chunks = @import("../store/chunks.zig");
const digest_mod = @import("../store/digest.zig");

pub const Digest = digest_mod.Digest;
/// What the index says about one object: its id, attributes, size, content hash and the hash
/// of each chunk. `chunks.put_chunk` checks it against the id before it keeps a byte.
pub const Wanted = chunks.Wanted;

/// The position of an object in `Catalog.objects`.
pub const ObjectIndex = u32;

pub const FetchError = error{
    /// The source does not hold this chunk (a peer that never had it). The next source is
    /// asked at once, and this one is not counted as failing.
    NotFound,
    /// The source did not answer within the `deadline_ms` it was given.
    TimedOut,
    /// Anything else: the connection failed, the source refused, it is shutting down.
    Failed,
};

/// A source of chunks that is not the store or the registry: Zigcube's agent passes its swarm's
/// peer fetch as one (`StartOptions.lazy_sources`). Zigbox never imports Zigcube and never talks
/// a peer protocol. Verification is never the source's job: the resolver checks whatever it
/// gets.
pub const Source = struct {
    context: *anyopaque,
    name: []const u8, // for messages: "registry", "peer 10.0.0.3"
    /// Fills `out` with chunk `index` of object `id` (unverified), or fails. Must return
    /// within `deadline_ms`; may be called from several resolver threads at once.
    fetch: *const fn (
        context: *anyopaque,
        id: Digest,
        index: u32,
        out: []u8,
        deadline_ms: u32,
    ) FetchError!usize,
    /// Told when bytes from this source failed their hash (C2 reports the peer).
    lied: *const fn (context: *anyopaque, id: Digest, index: u32) void,
};

/// The registry's side of a fetch: `length` bytes of the layer blob from `offset`, by an HTTP
/// `Range` request (`bytes=offset-(offset+length-1)`). The resolver asks for neighbouring chunks
/// in one call (coalescing) and inflates each chunk from its location itself, so the bytes are
/// compressed and unverified. The registry is always the last source.
pub const Range = struct {
    context: *anyopaque,
    name: []const u8, // "registry"
    /// Fills `out` (`out.len` is the length asked for, at most `lazy_range_bytes_max`) or fails;
    /// a short answer returns how much came. Must return within `deadline_ms`; called from
    /// several resolver threads at once.
    fetch: *const fn (
        context: *anyopaque,
        offset: u64,
        out: []u8,
        deadline_ms: u32,
    ) FetchError!usize,
};

/// Where chunk `index` of an object is in the layer blob (layer writer 2): inflating raw
/// deflate from `offset` (a full-flush point) gives the chunk's bytes first. A hint, never
/// trusted: a wrong offset gives bytes that fail the chunk's hash.
pub const Location = struct {
    /// The compressed range's first byte in the blob.
    offset: u64,
    /// The compressed range's length; at most `constants.lazy_range_bytes_max`.
    length: u32,
};

/// One object of the tree, from the lazy index.
pub const Object = struct {
    wanted: Wanted,
    /// One per chunk (`wanted.hashes.len` of them), or empty when no registry holds the object
    /// (a test, or a catalog made from the store alone).
    locations: []const Location,
};

/// Every object the tree names, each once (a file's hard links share one), in the order the
/// background fill fetches them: tree order, which is the blob's order.
pub const Catalog = struct {
    objects: []const Object,
};

pub const ReadError = error{
    /// No source gave verified bytes before the read's deadline (`lazy_read_deadline_ms`, or
    /// `lazy_down_fail_ms` when every source it needs is down). An `E1203` event was logged.
    /// The FUSE reply is `EIO`.
    Unavailable,
    /// The store's disk is too full to keep the chunk (`lazy_store_free_bytes_min`). An `E1206`
    /// event was logged. `EIO`.
    StoreFull,
    /// The resolver is stopping: the run is ending. `EIO`.
    Stopped,
};

/// One line for the caller to show. Strings point into the catalog and the sources; they live
/// as long as the resolver.
pub const Event = struct {
    pub const Kind = enum {
        /// W1202: `source` sent bytes that do not match the chunk's hash (or its length);
        /// another source is asked, and this one is not asked for this object again.
        lied,
        /// E1203: a read gave up: `reason` says what each source did.
        unavailable,
        /// E1206: the store's disk is too full.
        store_full,
    };
    kind: Kind,
    object: ObjectIndex,
    chunk: u32,
    /// The source the event is about (`lied`), else "".
    source: []const u8,
    /// For `unavailable`: what each source did on its last try, indexed as in
    /// `Resolver.source_name` (peers in order, then the registry). The caller renders it as
    /// "registry: timed out; peer 10.0.0.3: not found".
    outcomes: [constants.lazy_sources_max]Outcome,
    sources_count: u8,
};

/// What one source did for a chunk, for the `unavailable` event's reason.
pub const Outcome = enum(u8) {
    not_tried,
    not_found,
    timed_out,
    failed,
    lied,
    /// Down and not due for a probe: not asked.
    down,

    pub fn text(outcome: Outcome) []const u8 {
        return switch (outcome) {
            .not_tried => "not asked",
            .not_found => "not found",
            .timed_out => "timed out",
            .failed => "failed",
            .lied => "sent wrong bytes",
            .down => "down",
        };
    }
};

/// Where the resolver sends its events. Called from resolver threads, never with the
/// resolver's lock held, so it may block briefly (write a line to stderr or the run's log).
pub const Log = struct {
    context: *anyopaque,
    event: *const fn (context: *anyopaque, event: *const Event) void,
};

/// The store's free bytes now (`statfs` of its file system); the caller supplies it so the
/// resolver does no system call of its own and the simulation can model a filling disk.
pub const FreeBytes = struct {
    context: *anyopaque,
    query: *const fn (context: *anyopaque) u64,
};

/// What the run's summary line and record show.
pub const Report = struct {
    /// Chunk bytes landed in the store because a reader waited for them (or their readahead).
    fetched_on_demand_bytes: u64,
    /// Chunk bytes landed by the background fill.
    fetched_fill_bytes: u64,
    /// Bytes each source sent (compressed bytes for the registry), indexed as in
    /// `Resolver.source_name`.
    source_bytes: [constants.lazy_sources_max]u64,
    /// Reads that ended in `ReadError`.
    errors: u64,
    /// Objects of the catalog that are whole in the store, as last counted.
    objects_local: u32,
    objects_total: u32,
};

pub const Resolver = @import("resolver.zig").Resolver;
pub const Options = @import("resolver.zig").Options;

comptime {
    assert(constants.lazy_sources_max >= 2); // The store's peers and the registry at least.
    assert(constants.lazy_range_bytes_max >= constants.store_chunk_bytes);
}

test {
    _ = @import("land.zig");
    _ = @import("schedule.zig");
    _ = @import("resolver.zig");
    _ = @import("sim.zig");
}
