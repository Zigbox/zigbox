//! `zigbox.lazy`: the chunk resolver's public interface (S2, docs/briefs/S2-lazy-start.md).
//!
//! The resolver answers one question: give me chunk `index` of object `object`, verified. It
//! looks in the local store first (the object whole, or the chunk held in
//! `partial/<id>/<index>`), then asks the sources in order (the peers a library caller supplies,
//! then the registry by `Range` on a layer writer 2 blob), hashes every chunk it is given against
//! the chunk's listed hash and its chaining value, keeps it in the store with `chunks.put_chunk`,
//! and only then reads it back (checked again) into the caller's buffer. It owns the deadlines,
//! the concurrency limit, readahead, range coalescing, the background fill and each source's
//! health. It knows nothing of FUSE: the FUSE server (slice 4) calls `Resolver.read`, and a
//! later VM front end reuses it unchanged.
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
    /// The source did not answer within the `timeout_ms` it was given. A source that limits
    /// its bandwidth waits for its turn inside that time and then says this, never `NotFound`.
    TimedOut,
    /// Anything else: the connection failed, the source refused, it is shutting down.
    Failed,
};

/// What a source is asked for: one chunk, by its digest and length, which is all a source
/// needs to serve it. The object and the chunk's index in it are hints (for a source that keeps
/// objects whole); a source that serves by chunk digest ignores them.
pub const Request = struct {
    chunk: Digest,
    /// The chunk's length: `out` is exactly this long.
    length: u32,
    object: Digest,
    index: u32,
    /// The source answers (or says `TimedOut`) within this many milliseconds.
    timeout_ms: u32,
};

/// Which peer of a source answered, in the source's own terms: the resolver never looks inside
/// it and passes it back to `Source.lied`.
pub const PeerToken = u64;

pub const Fetched = struct {
    /// The bytes written to `out`. Fewer than `out.len` is a failed fetch (as `Failed`), never
    /// a lie: only bytes that do not hash right are a lie.
    length: u32,
    peer: PeerToken,
};

/// A source of chunks that is not the store or the registry: Zigcube's agent passes its swarm's
/// peer fetch as one (`StartOptions.lazy_sources`). Zigbox never imports Zigcube and never talks
/// a peer protocol. Verification is never the source's job: the resolver checks whatever it
/// gets.
///
/// A swarm is one `Source`, however many peers it has (it may have more than
/// `lazy_sources_max`): it picks the peer, keeps its own view of which peers are down, and fails
/// (`TimedOut` or `Failed`) only when no peer of it serves. The resolver's down state is about
/// the whole source (docs/decisions/2026-11-14-lazy-source-interface.md).
pub const Source = struct {
    context: *anyopaque,
    name: []const u8, // for messages: "registry", "peer 10.0.0.3", "swarm"
    /// Fills `out` (`request.length` bytes) with the chunk (unverified), or fails. Must return
    /// within `request.timeout_ms`; may be called from several resolver threads at once.
    fetch: *const fn (context: *anyopaque, request: *const Request, out: []u8) FetchError!Fetched,
    /// Told when the bytes `peer` sent for `request` failed the chunk's hash (C2 reports the
    /// peer). Called from a resolver thread, without the resolver's lock.
    lied: *const fn (context: *anyopaque, request: *const Request, peer: PeerToken) void,
};

/// The registry's side of a fetch: `length` bytes of the layer blob from `offset`, by an HTTP
/// `Range` request (`bytes=offset-(offset+length-1)`). The resolver asks for neighbouring chunks
/// in one call (coalescing) and inflates each chunk from its location itself, so the bytes are
/// compressed and unverified. The registry is always the last source.
pub const Range = struct {
    context: *anyopaque,
    name: []const u8, // "registry"
    /// Fills `out` (`out.len` is the length asked for, at most `lazy_range_bytes_max`) or fails;
    /// a short answer returns how much came. The chunks whose bytes did not all come count as
    /// a failed fetch, never a lie; the ones that did are inflated and checked. Must return
    /// within `timeout_ms`; called from several resolver threads at once.
    fetch: *const fn (
        context: *anyopaque,
        offset: u64,
        out: []u8,
        timeout_ms: u32,
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
    /// Each chunk's BLAKE3 chaining value at its place (`chaining.run_value`), one per chunk,
    /// for an object of two chunks or more: what ties a chunk's bytes to the content hash, so
    /// to the signed tree. A plain chunk hash alone is not tied to it (an index can list any),
    /// so every chunk of such an object is checked against this too before it is kept or
    /// served. Empty for an object of fewer than two chunks (its one chunk's hash is its
    /// content), and in a catalog that anchors nothing (a test's, whose sources are trusted).
    chaining: []const Digest,
};

/// Every object the tree names, each once (a file's hard links share one), in the order the
/// background fill fetches them: tree order, which is the blob's order.
pub const Catalog = struct {
    objects: []const Object,
};

pub const ReadError = error{
    /// No source gave verified bytes before the read's deadline (`lazy_read_deadline_ms`, or
    /// `lazy_down_fail_ms` when every source it needs is down), or, at once, every source sent
    /// wrong bytes for the object (`Outcome.lied`, `lied_before`). An `E1203` event was logged.
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
        /// W1202: `source` sent bytes that do not match the chunk's hash;
        /// another source is asked, and this one is not asked for this object again.
        lied,
        /// E1203: a read gave up: `reason` says what each source did.
        unavailable,
        /// E1206: the store's disk is too full.
        store_full,
    };
    kind: Kind,
    object: ObjectIndex,
    /// The object's id (`Catalog.objects[object].wanted.id`): the line names it, as the catalog
    /// has no path.
    id: Digest,
    chunk: u32,
    /// The source the event is about (`lied`), else "".
    source: []const u8,
    /// For `unavailable`: what each source did on its last try, indexed as in
    /// `Resolver.source_name` (peers in order, then the registry). The caller renders it as
    /// "registry: timed out; peer 10.0.0.3: not found".
    outcomes: [constants.lazy_sources_max]Outcome,
    sources_count: u8,
    /// The sources' names, indexed as `outcomes`: `sources_count` of them are set.
    names: *const [constants.lazy_sources_max][]const u8,
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
    /// Sent wrong bytes for this object before (here or for another reader), so not asked
    /// again: the reason it was not asked, which `not_tried` would hide.
    lied_before,

    pub fn text(outcome: Outcome) []const u8 {
        return switch (outcome) {
            .not_tried => "not asked",
            .not_found => "not found",
            .timed_out => "timed out",
            .failed => "failed",
            .lied => "sent wrong bytes",
            .down => "down",
            .lied_before => "sent wrong bytes for this file before, not asked again",
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
    /// Objects of the catalog seen whole in the store since `init` (at `init`, landed whole, or
    /// found whole by the fill). Never goes down: a gc that removes one later is not seen.
    objects_local: u32,
    objects_total: u32,
    /// The sizes of the objects counted in `objects_local`, and of every object of the catalog
    /// (an object with a hard link counts once): "image 38% local" and "3.0 GiB not yet local".
    bytes_local: u64,
    bytes_total: u64,
    /// Events the resolver had no room for (its ring holds `lazy_pending_max`): the caller
    /// shows the count, so a dropped line is never silent.
    events_dropped: u64,
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
    _ = @import("resolver_test.zig");
    _ = @import("registry_range.zig");
    _ = @import("registry_range_test.zig");
}
