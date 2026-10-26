//! The store: a deduplicated, verifiable store of file trees, written by zbx and only by zbx,
//! from inside the user's user namespace so that ownership round-trips. A root filesystem is
//! imported into it, run by digest, committed back and compared; the store keeps what roots
//! reach and nothing else.
//!
//! ## Layout
//!
//! The store is per user: `$XDG_DATA_HOME/zbx/store`, or `~/.local/share/zbx/store`.
//!
//!     store.zon                       .{ .format = 1 }: refused if newer than this zbx knows
//!     objects/ab/<62 hex>             a file object: the file itself, with its real mode, owner,
//!                                     attributes and the fixed mtime (`store_mtime_seconds`)
//!     objects/ab/<62 hex>.chunks      the chunk hashes of an object longer than one chunk
//!     trees/ab/<62 hex>               a tree object: the canonical encoding of one directory
//!     roots/<64 hex>                  a root record: why a tree is kept
//!     cache/                          materialized trees, hardlink farms of objects (slice 2)
//!     trash/<gc id>/                  what gc removed, until it expires (slice 4)
//!     tmp/<pid>-<n>                   files being written; a crash leaves them here
//!
//! `ab` is the first byte of the id in hex. Ids and digests are BLAKE3 (std, unkeyed), shown as
//! `b3:` and 64 lowercase hex digits; a prefix of 12 digits or more may be given and is never
//! guessed at.
//!
//! ## Identity
//!
//!   - A **file object** is one per (content, metadata) pair. Its id is the hash of a header
//!     (content hash, mode, uid, gid, sorted attributes), not of the bytes: `object.zig`.
//!   - A **tree** is a directory: entries sorted by name with kind, mode, owner, attributes, and
//!     the file's size, content hash and object id, or the symlink's target, or the subtree's
//!     digest. Its digest is the hash of its encoding, so a root's digest is the identity of
//!     everything below it: `tree.zig`. Times are not recorded.
//!   - **Ids are the container's.** Ownership is recorded as a container sees it, under the map
//!     `zbx run --rootfs` uses (the full range when this host has one, else only the user, as 0
//!     and with every owner recorded as 0).
//!
//! ## Writes
//!
//! Every write is atomic: a new file in `tmp/`, written whole and flushed, renamed to its name,
//! and the directory flushed (`fs.zig`, `write_atomic`). A killed process leaves files in `tmp/`
//! and nothing under an id that is not whole. The tests crash the simulated file system at every
//! write point (`fs_sim.zig`) and check that the store holds only whole objects, trees and
//! roots (`test_support.zig`), and that the same command, repeated, finishes the work.
//!
//! ## For Zigcube
//!
//! This module is part of the `zigbox` library. Storage belongs to the caller (a `Store` and a
//! `Workspace`); nothing is global. The work must run in the namespace child (`namespace.zig`,
//! or the caller's own child with the same id map), which is single-threaded.

const std = @import("std");

pub const digest = @import("digest.zig");
pub const tree = @import("tree.zig");
pub const xattrs = @import("xattrs.zig");
pub const fs = @import("fs.zig");
pub const fs_sim = @import("fs_sim.zig");
pub const layout = @import("layout.zig");
pub const open = @import("open.zig");
pub const object = @import("object.zig");
pub const trees = @import("trees.zig");
pub const roots = @import("roots.zig");
pub const import = @import("import.zig");
pub const usage = @import("usage.zig");
pub const walk = @import("walk.zig");
pub const namespace = @import("namespace.zig");
pub const diagnose = @import("diagnose.zig");

pub const Digest = digest.Digest;
pub const Prefix = digest.Prefix;
pub const Store = layout.Store;

/// The chunk hashes of an object (the `chunks(object_id)` of Zigcube's contract).
pub const chunks = object.chunk_hashes;

/// A tree object's bytes, checked against its digest (the `get_tree` of Zigcube's contract).
pub const get_tree = trees.load;

test {
    _ = digest;
    _ = tree;
    _ = xattrs;
    _ = fs;
    _ = fs_sim;
    _ = layout;
    _ = open;
    _ = object;
    _ = trees;
    _ = roots;
    _ = import;
    _ = usage;
    _ = walk;
    _ = namespace;
    _ = diagnose;
    _ = @import("names.zig");
    _ = @import("sets.zig");
    _ = @import("import_tests.zig");
    _ = @import("usage_tests.zig");
    _ = @import("test_support.zig");
}

test "the library surface Zigcube's C2 uses" {
    // Goal: a rename or removal fails here, loudly. Method: name each entry point.
    _ = Digest;
    _ = Prefix;
    _ = Store;
    _ = chunks;
    _ = get_tree;
    _ = import.import;
    try std.testing.expect(std.mem.eql(u8, Digest.of("").text()[0..3], "b3:"));
}
