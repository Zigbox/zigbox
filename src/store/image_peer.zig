//! An image record, sent to a peer and taken from one (Zigcube C2's Z4). A pull writes an image
//! record beside the tree it unpacked, and the record is what lets `zbx run <reference or
//! digest>` find the tree, start it with the image's settings, and what keeps the tree for gc. A
//! tree fetched from a peer through `put_chunk`, `put_tree` and the rest has none of that, so:
//!
//!   - `export_record` gives the text of the newest record whose tree is `tree`, for the node
//!     that has the image to send;
//!   - `import_record` takes that text, from a peer nobody vouches for, and, only if the tree
//!     named is whole in this store, writes the same record (and a root record, as a pull does).
//!
//! The peer must not decide which image a tree is. The caller passes `Options.expected_manifest`
//! from a source it trusts (for Zigcube, the digest-pinned image reference of the assignment),
//! never from the peer's text; a record for another manifest is refused. Otherwise a peer could
//! name a well-known digest for its own tree, and `zbx run name@sha256:<digest>` would run it, or
//! name the one tree under many invented manifests until the image records fill up.
//!
//! What is checked, in this order, each refusal a `Refusal` and nothing written:
//!   1. the text is no longer than any record (`image_record_bytes_max`);
//!   2. it reads as a record of this version or an older one, with every bound `render` keeps;
//!   3. its tree is the one the caller fetched, so a record cannot root a different tree;
//!   4. its manifest is the one the caller expects (`Options.expected_manifest`);
//!   5. under `.keep`, every tag reads as an image reference;
//!   6. the tree and every object below it are in the store, whole (`walk.objects` with
//!      `entries_max`, which also catches a tree that is damaged);
//!   7. no record of the same manifest names another tree, and none is unreadable or newer.
//!
//! The store lock is held shared from the walk to the last write, so a gc cannot take what was
//! just checked. The import is idempotent: the second time, the record is rewritten to the same
//! text, nothing grows. A refusal writes nothing. A store failure (a full disk) can stop between
//! the two writes: the image record is written first, and it alone keeps the tree for gc, so the
//! worst left behind is a record without its root; the same import again writes the root.
//! One race is left, the one a pull has with another pull of the same manifest: the record is
//! read, merged and written under a shared lock, so a pull and an import of one manifest at
//! once can each start from the old tags and the later write wins; a tag of the other is lost
//! until it is pulled or imported again. Nothing but a tag is lost, and the tree stays rooted.
//! Three things the peer's text does not decide:
//!   - the time is this node's own (a peer's clock must not make its record the newest);
//!   - tags are dropped unless the caller says `.keep`: a tag names a thing on this node, and a
//!     peer that sends `alpine:3.20` must not take the name from the image pulled here;
//!   - an existing record keeps its own tags and time, and the imported tags (if kept) join them.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const image_find = @import("image_find.zig");
const images = @import("images.zig");
const layout = @import("layout.zig");
const lock = @import("lock.zig");
const object_mod = @import("object.zig");
const reference_mod = @import("../registry/reference.zig");
const roots = @import("roots.zig");
const walk = @import("walk.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// Why a call was refused. `Failure.digest` and the other facts say what.
pub const Refusal = enum {
    /// Export: no image record names the tree.
    no_record,
    /// A record of this store (the one exported, or the one the import would replace) can not
    /// be used: it is damaged, newer than this zbx, or there are more than any scan lists.
    local_unusable,
    /// Import: the text is longer than any record. `Failure.size` is its length.
    too_large,
    /// Import: the text is not a record this zbx reads.
    malformed,
    /// Import: the record is from a newer zbx.
    newer,
    /// Import: the record names another tree. `Failure.digest` is that tree.
    wrong_tree,
    /// Import: the record names another image. `Failure.manifest` is that manifest.
    wrong_manifest,
    /// Import: the tree or an object below it is not in the store. `Failure.digest` names it.
    incomplete,
    /// Import: a tree below is damaged. `Failure.digest` names it.
    tree_damaged,
    /// Import: the tree has more entries than `Options.entries_max`, which is `Failure.size`.
    too_many_entries,
    /// Import: the tree has more directories pending at once than the walk keeps
    /// (`constants.image_import_stack_max`, which is `Failure.size`).
    stack_full,
    /// Import: a record of the same manifest already names another tree.
    conflict,
    /// The store lock is held by a gc or a restore for longer than the wait.
    busy,
    /// A read or a write of the store failed: `Failure.err` and `Failure.errno`.
    store_failed,
};

pub const Failure = struct {
    refusal: Refusal,
    digest: Digest,
    manifest: Sha256,
    size: u64,
    err: host_mod.Error,
    errno: u16,

    fn make(refusal: Refusal) Failure {
        return .{
            .refusal = refusal,
            .digest = .{ .bytes = @splat(0) },
            .manifest = .{ .bytes = @splat(0) },
            .size = 0,
            .err = error.IoFailed,
            .errno = 0,
        };
    }
};

pub const Error = error{Failed};

/// What the two calls work in. It is big (a tree object and the scan of the records), so a
/// caller keeps one for its life. Nothing in it needs to be set before a call.
pub const Memory = struct {
    scan: image_find.Memory,
    image: images.Image,
    existing: images.Image,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    stack: [constants.image_import_stack_max]Digest,
};

pub const TagPolicy = enum {
    /// The imported record's tags join those the local record has.
    keep,
    /// The imported record has no tags of its own; a local record keeps its.
    drop,
};

pub const Options = struct {
    /// The manifest the image is meant to have, from a source the caller trusts (never from
    /// the peer's record): a record for another manifest is refused (`wrong_manifest`).
    expected_manifest: Sha256,
    tags: TagPolicy,
    /// The most entries of the tree (all kinds) the completeness check looks at.
    entries_max: u32,
};

pub const Imported = struct {
    manifest: Sha256,
    tree: Digest,
    /// File entries below the tree and their bytes, as the root record shows them.
    files: u64,
    bytes: u64,
    /// False when a record of this manifest was there already (it is updated, not made).
    created: bool,
};

fn fail(failure: *Failure, refusal: Refusal) Error {
    assert(@intFromPtr(failure) != 0);
    failure.* = Failure.make(refusal);
    return error.Failed;
}

/// The newest record whose tree is `tree`.
const Newest = struct {
    tree: Digest,
    found: bool = false,
    time: u64 = 0,
    manifest: Sha256 = undefined,

    pub fn visit(self: *Newest, image: *const images.Image) void {
        assert(self.tree.bytes.len == constants.store_digest_bytes);
        if (!image.tree.eql(self.tree)) return;
        if (self.found and image.time < self.time) return;
        self.found = true;
        self.time = image.time;
        self.manifest = image.manifest;
    }
};

/// The text of the record of the newest image that became `tree`, for a peer to import. It is
/// in `out`; the result is the used part. Needs no lock: a record is written whole.
pub fn export_record(
    store: *const Store,
    memory: *Memory,
    tree: Digest,
    out: *[constants.image_record_bytes_max]u8,
    failure: *Failure,
) Error![]const u8 {
    assert(store.root_len > 1);
    assert(out.len == constants.image_record_bytes_max);
    var newest: Newest = .{ .tree = tree };
    image_find.scan(store, &memory.scan, &memory.image, &newest) catch |err| {
        const unreadable = err == error.Unreadable;
        failure.* = Failure.make(if (unreadable) .store_failed else .local_unusable);
        return error.Failed;
    };
    if (!newest.found) return fail(failure, .no_record);
    var errno: u16 = 0;
    images.load(store, newest.manifest, &memory.image, &errno) catch |err| {
        failure.* = Failure.make(if (err == error.Unreadable) .store_failed else .local_unusable);
        failure.errno = errno;
        return error.Failed;
    };
    assert(memory.image.tree.eql(tree));
    return images.render(&memory.image, out);
}

/// Counts the files below a tree and finds the first object the store does not have.
const Completeness = struct {
    store: *const Store,
    files: u64 = 0,
    bytes: u64 = 0,
    missing: ?Digest = null,
    io: ?host_mod.Error = null,

    pub fn object(self: *Completeness, ref: *const walk.ObjectRef) void {
        assert(self.files < std.math.maxInt(u64));
        self.files += 1;
        self.bytes +|= ref.size;
        if (self.missing != null) return;
        if (self.io != null) return;
        const present = object_mod.has(self.store, ref.id) catch |err| {
            self.io = err;
            return;
        };
        if (!present) self.missing = ref.id;
    }
};

fn check_complete(
    store: *const Store,
    memory: *Memory,
    tree: Digest,
    entries_max: u32,
    counted: *Completeness,
    failure: *Failure,
) Error!void {
    assert(entries_max > 0);
    assert(entries_max <= constants.store_walk_entries_max);
    var walk_failure: walk.Failure = undefined;
    counted.* = .{ .store = store };
    walk.objects(
        store,
        &memory.tree_buffer,
        &memory.stack,
        null,
        tree,
        counted,
        entries_max,
        &walk_failure,
    ) catch {
        failure.* = Failure.make(switch (walk_failure.kind) {
            .missing => .incomplete,
            .damaged => .tree_damaged,
            .unreadable => .store_failed,
            .too_many_entries => .too_many_entries,
            .stack_full => .stack_full,
        });
        failure.digest = walk_failure.where;
        failure.errno = walk_failure.errno;
        switch (failure.refusal) {
            .too_many_entries => failure.size = entries_max,
            .stack_full => failure.size = constants.image_import_stack_max,
            else => {},
        }
        return error.Failed;
    };
    if (counted.io) |err| {
        failure.* = Failure.make(.store_failed);
        failure.err = err;
        return error.Failed;
    }
    if (counted.missing) |id| {
        failure.* = Failure.make(.incomplete);
        failure.digest = id;
        return error.Failed;
    }
}

/// Reads the text as a record for `tree` and `options.expected_manifest` into `memory.image`, or
/// refuses it.
fn read_record(
    memory: *Memory,
    text: []const u8,
    tree: Digest,
    options: Options,
    failure: *Failure,
) Error!void {
    assert(@intFromPtr(memory) != 0);
    if (text.len > constants.image_record_bytes_max) {
        failure.* = Failure.make(.too_large);
        failure.size = text.len;
        return error.Failed;
    }
    switch (images.parse(text, &memory.image)) {
        .ok => {},
        .malformed => return fail(failure, .malformed),
        .newer => return fail(failure, .newer),
    }
    if (!memory.image.tree.eql(tree)) {
        failure.* = Failure.make(.wrong_tree);
        failure.digest = memory.image.tree;
        return error.Failed;
    }
    if (!memory.image.manifest.eql(options.expected_manifest)) {
        failure.* = Failure.make(.wrong_manifest);
        failure.manifest = memory.image.manifest;
        return error.Failed;
    }
    if (options.tags == .keep) try check_tags(&memory.image, failure);
}

/// Refuses a record whose tag is not an image reference: a peer's tag becomes a name on this
/// node, so it must be one `zbx run` can resolve.
fn check_tags(image: *const images.Image, failure: *Failure) Error!void {
    assert(image.tag_count <= constants.image_tags_max);
    for (0..image.tag_count) |index| {
        const text = image.tag_text(@intCast(index));
        assert(text.len > 0); // `parse` drops an empty tag.
        var reference: reference_mod.Reference = undefined;
        reference_mod.parse(text, &reference) catch return fail(failure, .malformed);
        // A digest is never a tag (REVIEW.md); `parse` drops one, so none can be here.
        assert(reference.digest == null);
    }
}

/// Puts the tags and the time the new record keeps into `memory.image`: those of the record
/// already here (`memory.existing`, when `exists`), then the imported ones if they are kept.
fn merge(memory: *Memory, exists: bool, now: u64, policy: TagPolicy) void {
    assert(now < 1 << 40);
    const image = &memory.image;
    const base = &memory.existing;
    if (!exists) base.tag_count = 0;
    if (policy == .keep) {
        for (0..image.tag_count) |index| base.add_tag(image.tag_text(@intCast(index)));
    }
    image.tags = base.tags;
    image.tag_lens = base.tag_lens;
    image.tag_count = base.tag_count;
    image.time = if (exists) base.time else now;
    assert(image.time < 1 << 40);
}

/// Looks for the record of the same manifest: true if there is one (in `memory.existing`).
fn load_existing(store: *const Store, memory: *Memory, failure: *Failure) Error!bool {
    assert(@intFromPtr(memory) != 0);
    var errno: u16 = 0;
    images.load(store, memory.image.manifest, &memory.existing, &errno) catch |err| switch (err) {
        error.NotFound => return false,
        error.Unreadable => {
            failure.* = Failure.make(.store_failed);
            failure.errno = errno;
            return error.Failed;
        },
        error.Damaged, error.Newer => return fail(failure, .local_unusable),
    };
    if (!memory.existing.tree.eql(memory.image.tree)) {
        failure.* = Failure.make(.conflict);
        failure.digest = memory.existing.tree;
        return error.Failed;
    }
    return true;
}

fn save_root(
    store: *Store,
    tree: Digest,
    counted: *const Completeness,
    failure: *Failure,
) Error!void {
    var root: roots.Root = undefined;
    var errno: u16 = 0;
    // A record that is there and damaged or newer is left alone: the image record roots the
    // tree anyway. One that can not be read at all is a failing store.
    roots.load(store, tree, &root, &errno) catch |err| {
        if (err == error.Unreadable) {
            failure.* = Failure.make(.store_failed);
            failure.errno = errno;
            return error.Failed;
        }
        if (err != error.NotFound) return;
        root.digest = tree;
        root.kind = .import;
        root.time = store.host.time_now();
        root.files = counted.files;
        root.bytes = counted.bytes;
        root.set_source("peer");
        root.parent = null;
        var written: fs_mod.Failure = undefined;
        roots.save(store, &root, &written) catch {
            failure.* = Failure.make(.store_failed);
            failure.err = written.err;
            failure.errno = written.errno;
            return error.Failed;
        };
        return;
    };
}

/// Takes the record `text` for the tree `tree` a peer sent, if the tree is whole here. See the
/// file comment for the checks, the order and what is kept.
pub fn import_record(
    store: *Store,
    memory: *Memory,
    text: []const u8,
    tree: Digest,
    options: Options,
    failure: *Failure,
) Error!Imported {
    assert(store.root_len > 1);
    assert(options.entries_max > 0);
    try read_record(memory, text, tree, options, failure);
    lock.hold(store, .shared, "import_image") catch |err| {
        failure.* = Failure.make(if (err == error.Busy) .busy else .store_failed);
        if (err == error.Failed) failure.err = store.lock_error;
        failure.errno = store.lock_errno;
        return error.Failed;
    };
    defer lock.release(store);
    var counted: Completeness = undefined;
    try check_complete(store, memory, tree, options.entries_max, &counted, failure);
    const exists = try load_existing(store, memory, failure);
    merge(memory, exists, store.host.time_now(), options.tags);
    // The image record first: it alone keeps the tree for gc, so a failure of the root that
    // follows leaves a tree that is kept, never a root with nothing behind it.
    var written: fs_mod.Failure = undefined;
    images.save(store, &memory.image, &written) catch {
        failure.* = Failure.make(.store_failed);
        failure.err = written.err;
        failure.errno = written.errno;
        return error.Failed;
    };
    try save_root(store, tree, &counted, failure);
    return .{
        .manifest = memory.image.manifest,
        .tree = tree,
        .files = counted.files,
        .bytes = counted.bytes,
        .created = !exists,
    };
}
