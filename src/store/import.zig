//! `store import`: walk a directory, put every file into the store as an object, write a tree
//! object for every directory, and make the root directory's tree a root. The root tree's
//! digest is the identity of the whole directory.
//!
//! The walk is iterative (docs/STYLE.md bans recursion): a stack of frames, one per directory
//! being read, at most `store_depth_max` deep. A frame holds the names of its directory, sorted
//! by bytes, and the tree encoding it is building; a subdirectory's entry is begun in the parent
//! (everything but the subtree's digest), the child's frame is pushed, and when the child is
//! finished its digest completes the parent's entry. All of it lives in one arena of
//! `store_arena_bytes_max` bytes, used as a stack: a child's memory starts where the parent's
//! encoding ends, and is free again when the child is done. A directory that does not fit is
//! refused (`ZBX-E0415`), never cut.
//!
//! What goes into the digest: names, kinds, modes, owners, attributes, file contents and symlink
//! targets. Not times, not the order the file system lists a directory in, not inode numbers,
//! not the metadata of the imported directory itself (it is the mount point, not content), and
//! not hardlinks (two names for one inode are two entries; they become one object if their
//! bytes and metadata agree). Importing the same directory twice therefore gives one digest,
//! whatever the mtimes, and whatever order the files were created in.
//!
//! Each file is read twice: once to learn its content hash and its chunks, and only if the store
//! lacks the object, a second time to copy it, checking that the bytes are the same (`E0418`
//! otherwise). An import that is killed leaves only files in `tmp/`; a second run skips every
//! object that is already complete.
//!
//! The same walk makes a commit (`commit` below; docs/briefs/M3-store.md, "Commit and diff"):
//! the directory is a container's upper layer and `Options.parent` is the tree the container
//! started from. Each directory is then the merge of two sorted lists, the upper's names and the
//! parent tree's entries:
//!   - a name only in the parent is copied through unchanged (a directory by its subtree digest,
//!     so nothing below it is read);
//!   - a name in the upper wins over the parent's, except that a directory in the upper which is
//!     not opaque is merged with the parent's directory of that name;
//!   - a whiteout in the upper (a character device 0/0, or a file with `user.overlay.whiteout`)
//!     removes the name outright: no entry, so the new tree has no trace of it;
//!   - a directory with `user.overlay.opaque` replaces the parent's directory of that name.
//! An upper layer that uses redirects or metadata-only copy-up (`user.overlay.redirect`,
//! `user.overlay.metacopy`) is refused: the container's changes can not be told from the upper
//! alone then.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("diagnose.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const names_mod = @import("names.zig");
const object = @import("object.zig");
const roots = @import("roots.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");
const xattrs = @import("xattrs.zig");

const Digest = digest_mod.Digest;
const NameList = names_mod.NameList;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

/// The import failed; the reason is in the `Diag`.
pub const Error = error{Failed};

/// A warning, handed over as it happens. The diagnostic is only valid during the call.
pub const Warn = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, diag: *const Diag) void,
};

pub const Options = struct {
    /// Record every owner as 0, as the container sees a host that maps only its own id
    /// (W0201): ids other than 0 do not exist there.
    squash_owner: bool,
    warn: ?Warn,
    /// Set for a commit: the tree the walked directory (an upper layer) is applied to.
    parent: ?Digest = null,
};

pub const Result = struct {
    digest: Digest,
    files: u64,
    directories: u64,
    symlinks: u64,
    /// Entries left out (devices, FIFOs, sockets), and attributes left out.
    skipped: u64,
    /// A commit: names the upper layer removed from the parent (whiteouts it holds).
    whiteouts: u64,
    xattrs_skipped: u64,
    /// Entries whose owner or group showed as the overflow id, 65534: the namespace could not
    /// map it. They are recorded as 65534.
    unmapped_uids: u64,
    unmapped_gids: u64,
    /// The sum of the files' lengths.
    bytes: u64,
    objects_new: u64,
    objects_reused: u64,
    /// Bytes of the objects that were new.
    bytes_new: u64,
    trees_new: u64,
    trees_reused: u64,
};

const Frame = struct {
    path_len: u32,
    names: NameList,
    offsets: []const u32,
    next: u32,
    out_at: u32,
    writer: tree.Writer,
    /// A commit: the parent's directory, decoded one entry ahead (`peek`, valid if `has_peek`).
    /// Empty for an import, and for a directory that is new or opaque.
    parent: tree.Decoder,
    peek: tree.Entry,
    has_peek: bool,
    parent_digest: Digest,
};

/// What overlayfs says about a file in an upper layer, by its `user.overlay.*` attributes.
const Marks = struct {
    whiteout: bool,
    opaque_dir: bool,
    /// Redirects and metadata-only copy-ups, which a commit does not follow.
    unsupported: ?[]const u8,

    const none: Marks = .{ .whiteout = false, .opaque_dir = false, .unsupported = null };
};

/// The caller's memory for an import, about 17 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    arena: [constants.store_arena_bytes_max]u8 align(8),
    io: [constants.store_io_buffer_bytes]u8,
    chunks: [constants.store_chunks_max]Digest,
    scratch: [constants.store_chunks_max]Digest,
    frames: [constants.store_depth_max + 1]Frame,
    path: [constants.path_bytes_max + 1]u8,
    builder: xattrs.Builder,
    blob: [constants.store_xattr_blob_bytes_max]u8,
    xattr_names: [8192]u8,
    xattr_value: [constants.store_xattr_value_bytes_max + 1]u8,
    link_target: [constants.store_symlink_target_bytes_max + 1]u8,
    /// The path of the first entry with an unmapped owner or group.
    unmapped_path: [constants.path_bytes_max]u8,
};

const Run = struct {
    store: *Store,
    ws: *Workspace,
    options: Options,
    result: *Result,
    diag: *Diag,
    depth: u32,
    warning: Diag,
    warnings_shown: u32,
    warnings_hidden: u32,
    unmapped_path_len: u32,
    /// A commit: the walk merges with a parent tree and obeys overlayfs's marks.
    merging: bool,
    marks: Marks,

    fn path_text(run: *const Run, length: u32) [:0]const u8 {
        assert(length > 0);
        assert(length <= constants.path_bytes_max);
        assert(run.ws.path[length] == 0);
        return run.ws.path[0..length :0];
    }

    /// The directory's path for a message. Unlike `path_text` it does not need the NUL, which
    /// deeper entries overwrite.
    fn path_slice(run: *const Run, length: u32) []const u8 {
        assert(length > 0);
        assert(length <= constants.path_bytes_max);
        return run.ws.path[0..length];
    }

    // ---- Failures: each fills the diagnostic and returns the one error ----------------------

    fn source_failure(
        run: *Run,
        operation: []const u8,
        path: []const u8,
        err: host_mod.Error,
        errno: u16,
    ) Error {
        assert(operation.len > 0);
        assert(path.len > 0);
        if (err == error.NotFound and run.depth > 0) return run.vanished(path);
        diagnose.source_unreadable(run.diag, path, operation, .{
            .failed = .{ .err = err, .errno = errno },
        });
        return error.Failed;
    }

    fn vanished(run: *Run, path: []const u8) Error {
        assert(path.len > 0);
        assert(run.diag.code == null);
        diagnose.changed_while_importing(run.diag, path);
        return error.Failed;
    }

    fn limit(run: *Run, which: diagnose.Limit, path: []const u8) Error {
        assert(path.len > 0);
        assert(run.diag.code == null);
        diagnose.too_big(run.diag, which, path);
        return error.Failed;
    }

    fn store_failure(run: *Run, operation: []const u8, err: host_mod.Error, errno: u16) Error {
        assert(operation.len > 0);
        assert(run.diag.code == null);
        diagnose.write_failed(run.diag, run.store, operation, err, errno);
        return error.Failed;
    }

    fn put_failed(
        run: *Run,
        err: object.PutError,
        path: []const u8,
        failure: *const object.Failure,
    ) Error {
        assert(path.len > 0);
        assert(run.diag.code == null);
        switch (err) {
            error.SourceFailed => return run.source_failure(
                "reading",
                path,
                failure.err,
                failure.errno,
            ),
            error.Changed => return run.vanished(path),
            error.StoreFailed => return run.store_failure(
                "writing to the store",
                failure.err,
                failure.errno,
            ),
        }
    }

    /// The tree encoding did not fit: the arena, or the limit on one tree object.
    fn writer_full(run: *Run, frame: *const Frame) Error {
        assert(frame.writer.len <= frame.writer.buffer.len);
        assert(run.diag.code == null);
        const which: diagnose.Limit = if (frame.writer.buffer.len < constants.store_tree_bytes_max)
            .arena
        else
            .tree_bytes;
        return run.limit(which, run.path_slice(frame.path_len));
    }

    // ---- Warnings ---------------------------------------------------------------------------

    /// True if this warning is among the first few, which are shown; the rest are counted.
    fn may_show(run: *Run) bool {
        assert(run.warnings_shown <= constants.store_warnings_shown_max);
        assert(run.depth <= constants.store_depth_max + 1);
        if (run.options.warn == null) return false;
        if (run.warnings_shown < constants.store_warnings_shown_max) {
            run.warnings_shown += 1;
            return true;
        }
        run.warnings_hidden += 1;
        return false;
    }

    fn emit(run: *Run) void {
        assert(run.warnings_shown <= constants.store_warnings_shown_max);
        assert(run.warning.code != null);
        const warn = run.options.warn.?;
        warn.call(warn.context, &run.warning);
    }

    fn warn_file(run: *Run, path: []const u8, kind: fs_mod.FileKind) void {
        assert(path.len > 0);
        assert(kind != .file);
        run.result.skipped += 1;
        if (!run.may_show()) return;
        run.warning.reset();
        const word: []const u8 = switch (kind) {
            .char_device => "character device",
            .block_device => "block device",
            .fifo => "FIFO",
            .socket => "socket",
            .file, .dir, .symlink => unreachable, // Only the kinds the store leaves out come here.
        };
        diagnose.skipped_file(&run.warning, path, word);
        run.emit();
    }

    fn warn_xattr(run: *Run, path: []const u8, name: []const u8, fault: diagnose.XattrFault) void {
        assert(path.len > 0);
        assert(name.len > 0);
        run.result.xattrs_skipped += 1;
        if (!run.may_show()) return;
        run.warning.reset();
        diagnose.skipped_xattr(&run.warning, path, name, fault);
        run.emit();
    }

    /// Counts an entry whose owner or group is the overflow id; the first one's path is kept.
    fn note_owner(run: *Run, path: []const u8, stat: *const fs_mod.Stat) void {
        assert(path.len > 0);
        assert(path.len <= constants.path_bytes_max);
        if (run.options.squash_owner) return; // Every owner is 0 by request; nothing is lost.
        const uid = stat.uid == constants.store_overflow_id;
        const gid = stat.gid == constants.store_overflow_id;
        if (!uid and !gid) return;
        if (run.unmapped_path_len == 0) {
            @memcpy(run.ws.unmapped_path[0..path.len], path);
            run.unmapped_path_len = @intCast(path.len);
        }
        if (uid) run.result.unmapped_uids += 1;
        if (gid) run.result.unmapped_gids += 1;
    }

    /// After the walk: one warning, whatever the count, for owners that could not be mapped.
    fn warn_unmapped(run: *Run) void {
        if (run.unmapped_path_len == 0) return;
        assert(run.result.unmapped_uids + run.result.unmapped_gids > 0);
        if (run.options.warn == null) return;
        run.warning.reset();
        diagnose.unmapped_owners(
            &run.warning,
            run.result.unmapped_uids,
            run.result.unmapped_gids,
            run.ws.unmapped_path[0..run.unmapped_path_len],
        );
        run.emit();
    }

    /// After the walk: one more warning that says how many were not shown.
    fn flush_warnings(run: *Run) void {
        assert(run.warnings_shown <= constants.store_warnings_shown_max);
        assert(run.depth == 0);
        run.warn_unmapped();
        if (run.warnings_hidden == 0) return;
        run.warning.reset();
        diagnose.more_skipped(&run.warning, run.warnings_hidden);
        run.emit();
    }

    // ---- The walk ---------------------------------------------------------------------------

    fn begin(run: *Run, source: []const u8) Error!void {
        assert(source.len > 0);
        assert(run.depth == 0);
        const ws = run.ws;
        var length: u32 = @intCast(source.len);
        while (length > 1 and source[length - 1] == '/') length -= 1;
        if (length > constants.path_bytes_max) return run.limit(.path, source[0..64]);
        @memcpy(ws.path[0..length], source[0..length]);
        ws.path[length] = 0;
        const path = run.path_text(length);
        const fs = run.store.fs;
        const stat = fs.lstat(path) catch |err| {
            return run.source_failure("lstat of", path, err, fs.last_errno());
        };
        switch (stat.kind) {
            .dir => {},
            .symlink => {
                diagnose.source_unreadable(run.diag, path, "", .symlink);
                return error.Failed;
            },
            else => {
                diagnose.source_unreadable(run.diag, path, "", .not_directory);
                return error.Failed;
            },
        }
        try run.push_frame(length, run.options.parent);
    }

    /// Reads the directory at the current path and starts a frame for it.
    fn push_frame(run: *Run, path_len: u32, below: ?Digest) Error!void {
        assert(path_len > 0);
        const ws = run.ws;
        assert(run.depth <= constants.store_depth_max);
        const path = run.path_text(path_len);
        const base: u32 = if (run.depth == 0) 0 else blk: {
            const parent = &ws.frames[run.depth - 1];
            break :blk align_up(parent.out_at + parent.writer.len, 8);
        };
        if (base + 4096 > ws.arena.len) return run.limit(.arena, path);
        var names = NameList.init(ws.arena[base..], constants.store_dir_entries_max);
        const fs = run.store.fs;
        fs.read_dir(path, names.visitor()) catch |err| {
            return run.source_failure("reading the directory", path, err, fs.last_errno());
        };
        if (names.too_many) return run.limit(.entries, path);
        if (names.too_long) return run.limit(.name, path);
        if (names.full) return run.limit(.arena, path);
        const offsets_at = align_up(base + names.used, 4);
        const offsets_end = offsets_at + names.count * 4;
        const parent_at = align_up(offsets_end, 8);
        const parent_bytes = try run.load_parent(below, parent_at, path);
        const out_at = align_up(parent_at + @as(u32, @intCast(parent_bytes.len)), 8);
        if (out_at + 256 > ws.arena.len) return run.limit(.arena, path);
        const region: []align(4) u8 = @alignCast(ws.arena[offsets_at..offsets_end]);
        const offsets: []u32 = std.mem.bytesAsSlice(u32, region);
        const frame = &ws.frames[run.depth];
        frame.* = .{
            .path_len = path_len,
            .names = names,
            .offsets = names.sorted(offsets),
            .next = 0,
            .out_at = out_at,
            .writer = tree.Writer.init(ws.arena[out_at..]),
            .parent = undefined,
            .peek = undefined,
            .has_peek = false,
            .parent_digest = below orelse tree.zero_digest,
        };
        if (below != null) {
            frame.parent.init(parent_bytes) catch return run.parent_damaged(frame);
            try run.advance_parent(frame);
        }
        run.depth += 1;
        run.result.directories += 1;
    }

    /// A commit: reads the parent's directory into the arena at `at`. Empty for no parent.
    fn load_parent(run: *Run, parent: ?Digest, at: u32, path: [:0]const u8) Error![]const u8 {
        assert(at <= run.ws.arena.len);
        const digest = parent orelse return &.{};
        const arena = &run.ws.arena;
        if (at + constants.store_tree_bytes_max + 256 > arena.len) return run.limit(.arena, path);
        var errno: u16 = 0;
        const room = arena[at..][0..constants.store_tree_bytes_max];
        const loaded = trees.load(run.store, digest, room, &errno);
        return loaded catch |err| {
            diagnose.tree_load_failed(run.diag, run.store, digest, err, errno);
            return error.Failed;
        };
    }

    fn parent_damaged(run: *Run, frame: *const Frame) Error {
        assert(run.diag.code == null);
        diagnose.tree_damaged(run.diag, frame.parent_digest, "does not decode");
        return error.Failed;
    }

    /// Reads the parent's next entry into `peek`.
    fn advance_parent(run: *Run, frame: *Frame) Error!void {
        assert(run.merging);
        frame.has_peek = frame.parent.next(&frame.peek) catch return run.parent_damaged(frame);
    }

    fn step(run: *Run) Error!void {
        assert(run.depth <= constants.store_depth_max + 1);
        assert(run.depth > 0);
        const frame = &run.ws.frames[run.depth - 1];
        const upper_left = frame.next < frame.offsets.len;
        if (!upper_left and !frame.has_peek) return run.finish_frame();
        if (!frame.has_peek) {
            const name = frame.names.at(frame.offsets[frame.next]);
            frame.next += 1;
            return run.entry(frame, name, null);
        }
        const order: std.math.Order = if (!upper_left)
            .gt
        else
            std.mem.order(u8, frame.names.at(frame.offsets[frame.next]), frame.peek.name);
        if (order == .gt) { // Only in the parent: it stays as it is.
            try run.copy_parent(frame);
            return run.advance_parent(frame);
        }
        const name = frame.names.at(frame.offsets[frame.next]);
        frame.next += 1;
        const matched: ?tree.Entry = if (order == .eq) frame.peek else null;
        if (order == .eq) try run.advance_parent(frame);
        try run.entry(frame, name, matched);
    }

    /// The parent's entry, written again unchanged: for a file the same object, for a directory
    /// the same subtree (so nothing below it is read).
    fn copy_parent(run: *Run, frame: *Frame) Error!void {
        assert(run.merging);
        assert(frame.has_peek);
        const entry_ = frame.peek;
        frame.writer.begin(
            entry_.name,
            entry_.kind,
            entry_.mode,
            entry_.uid,
            entry_.gid,
            entry_.xattrs,
        ) catch return run.writer_full(frame);
        switch (entry_.kind) {
            .file => frame.writer.end_file(entry_.size, entry_.content, entry_.object) catch {
                return run.writer_full(frame);
            },
            .symlink => frame.writer.end_symlink(entry_.target) catch return run.writer_full(frame),
            .dir => frame.writer.end_dir(entry_.subtree) catch return run.writer_full(frame),
        }
    }

    /// One name of the top directory: its path is built in `ws.path`, and its kind decides.
    fn entry(run: *Run, frame: *Frame, name: []const u8, matched: ?tree.Entry) Error!void {
        assert(name.len > 0);
        assert(frame.path_len > 0);
        const ws = run.ws;
        var length = frame.path_len;
        const slash: u32 = if (ws.path[length - 1] == '/') 0 else 1;
        if (length + slash + name.len > constants.path_bytes_max) {
            return run.limit(.path, ws.path[0..length]);
        }
        if (slash == 1) ws.path[length] = '/';
        length += slash;
        @memcpy(ws.path[length..][0..name.len], name);
        length += @intCast(name.len);
        ws.path[length] = 0;
        const path = run.path_text(length);
        const fs = run.store.fs;
        const stat = fs.lstat(path) catch |err| {
            return run.source_failure("lstat of", path, err, fs.last_errno());
        };
        switch (stat.kind) {
            .file => try run.file_entry(frame, name, path, &stat),
            .symlink => try run.symlink_entry(frame, name, path, &stat),
            .dir => try run.dir_entry(frame, name, path, &stat, matched),
            .char_device => if (run.merging and stat.rdev_major == 0 and stat.rdev_minor == 0) {
                run.result.whiteouts += 1; // A deletion: no entry, and the parent's is gone.
            } else {
                run.warn_file(path, stat.kind);
            },
            .block_device, .fifo, .socket => run.warn_file(path, stat.kind),
        }
    }

    fn attrs_of(run: *const Run, stat: *const fs_mod.Stat, blob: []const u8) object.Attrs {
        assert(stat.mode <= 0o7777);
        assert(xattrs.validate(blob) == .none);
        return .{
            .mode = stat.mode,
            .uid = if (run.options.squash_owner) 0 else stat.uid,
            .gid = if (run.options.squash_owner) 0 else stat.gid,
            .xattrs = blob,
        };
    }

    fn file_entry(
        run: *Run,
        frame: *Frame,
        name: []const u8,
        path: [:0]const u8,
        stat: *const fs_mod.Stat,
    ) Error!void {
        assert(stat.kind == .file);
        assert(name.len > 0);
        const blob = try run.gather_xattrs(path);
        if (run.merging) {
            try run.check_marks(path);
            if (run.marks.whiteout) { // A deletion, as a file (a mount made by a user namespace).
                run.result.whiteouts += 1;
                return;
            }
        }
        const content = try run.hash_file(path, stat);
        run.note_owner(path, stat);
        const attrs = run.attrs_of(stat, blob);
        const id = object.object_id(content.hash, attrs);
        try run.ensure_object(path, &content, attrs, id);
        frame.writer.begin(name, .file, attrs.mode, attrs.uid, attrs.gid, blob) catch {
            return run.writer_full(frame);
        };
        frame.writer.end_file(content.size, content.hash, id) catch return run.writer_full(frame);
        run.result.files += 1;
        run.result.bytes += content.size;
    }

    fn symlink_entry(
        run: *Run,
        frame: *Frame,
        name: []const u8,
        path: [:0]const u8,
        stat: *const fs_mod.Stat,
    ) Error!void {
        assert(stat.kind == .symlink);
        assert(name.len > 0);
        const fs = run.store.fs;
        const blob = try run.gather_xattrs(path);
        if (run.merging) try run.check_marks(path);
        const target = fs.read_link(path, &run.ws.link_target) catch |err| {
            if (err == error.FileTooLarge) return run.limit(.target, path);
            return run.source_failure("readlink of", path, err, fs.last_errno());
        };
        if (target.len == 0) return run.vanished(path);
        run.note_owner(path, stat);
        const attrs = run.attrs_of(stat, blob);
        frame.writer.begin(name, .symlink, attrs.mode, attrs.uid, attrs.gid, blob) catch {
            return run.writer_full(frame);
        };
        frame.writer.end_symlink(target) catch return run.writer_full(frame);
        run.result.symlinks += 1;
    }

    fn dir_entry(
        run: *Run,
        frame: *Frame,
        name: []const u8,
        path: [:0]const u8,
        stat: *const fs_mod.Stat,
        matched: ?tree.Entry,
    ) Error!void {
        assert(stat.kind == .dir);
        assert(name.len > 0);
        // The root is level 0; `frames` has room for `store_depth_max` levels below it.
        if (run.depth > constants.store_depth_max) return run.limit(.depth, path);
        const blob = try run.gather_xattrs(path);
        if (run.merging) try run.check_marks(path);
        // Merged with the parent's directory of that name, unless it replaces it (opaque) or
        // the parent has something else there.
        var below: ?Digest = null;
        if (matched) |found| {
            if (found.kind == .dir and !run.marks.opaque_dir) below = found.subtree;
        }
        run.note_owner(path, stat);
        const attrs = run.attrs_of(stat, blob);
        frame.writer.begin(name, .dir, attrs.mode, attrs.uid, attrs.gid, blob) catch {
            return run.writer_full(frame);
        };
        try run.push_frame(@intCast(path.len), below);
    }

    /// The top directory is done: its encoding becomes a tree object, and its digest completes
    /// the entry in the parent (or is the result, for the root).
    fn finish_frame(run: *Run) Error!void {
        assert(run.depth > 0);
        assert(run.diag.code == null);
        const frame = &run.ws.frames[run.depth - 1];
        const bytes = if (run.depth == 1) try run.finish_root(frame) else frame.writer.finish();
        const digest = Digest.of(bytes);
        var failure: object.Failure = undefined;
        const created = trees.put(run.store, digest, bytes, &failure) catch |err| {
            return run.put_failed(err, run.path_slice(frame.path_len), &failure);
        };
        if (created) run.result.trees_new += 1 else run.result.trees_reused += 1;
        run.depth -= 1;
        if (run.depth == 0) {
            run.result.digest = digest;
            return;
        }
        const parent = &run.ws.frames[run.depth - 1];
        parent.writer.end_dir(digest) catch return run.writer_full(parent);
    }

    /// The root directory's tree: its entries and its own mode, owner and attributes, which
    /// become the container's `/`. They are read now, after its contents, so that what the
    /// digest holds is what is on disk when the walk ends.
    fn finish_root(run: *Run, frame: *Frame) Error![]const u8 {
        assert(run.depth == 1);
        assert(frame.path_len > 0);
        const ws = run.ws;
        ws.path[frame.path_len] = 0; // Deeper entries overwrote it.
        const path = run.path_text(frame.path_len);
        const fs = run.store.fs;
        const stat = fs.lstat(path) catch |err| {
            return run.source_failure("lstat of", path, err, fs.last_errno());
        };
        if (stat.kind != .dir) return run.vanished(path);
        const blob = try run.gather_xattrs(path);
        run.note_owner(path, &stat);
        const attrs = run.attrs_of(&stat, blob);
        return frame.writer.finish_with(.{
            .mode = attrs.mode,
            .uid = attrs.uid,
            .gid = attrs.gid,
            .xattrs = attrs.xattrs,
        }) catch return run.writer_full(frame);
    }

    // ---- Files ------------------------------------------------------------------------------

    /// The first pass over a file: its length, its hash and the hash of each chunk.
    fn hash_file(run: *Run, path: [:0]const u8, stat: *const fs_mod.Stat) Error!object.Content {
        assert(stat.kind == .file);
        assert(path.len > 0);
        const fs = run.store.fs;
        const ws = run.ws;
        const size_max = @as(u64, run.store.chunk_bytes) * constants.store_chunks_max;
        if (stat.size > size_max) return run.limit(.file_size, path);
        const fd = fs.open_read(path) catch |err| {
            return run.source_failure("opening", path, err, fs.last_errno());
        };
        defer fs.close(fd);
        var reader = object.Reader.init(run.store.chunk_bytes);
        // Each read that returns bytes makes progress, and the reader refuses a file past the
        // limit, so the loop ends after at most `size_max / 1 + 1` reads; in practice 256 KiB each.
        while (true) {
            const count = fs.read(fd, &ws.io) catch |err| {
                return run.source_failure("reading", path, err, fs.last_errno());
            };
            if (count == 0) break;
            if (!reader.update(ws.io[0..count], &ws.chunks)) return run.limit(.file_size, path);
        }
        if (reader.size != stat.size) return run.vanished(path);
        const hash = reader.finish(&ws.chunks);
        return .{ .size = reader.size, .hash = hash, .chunks = ws.chunks[0..reader.count] };
    }

    /// Puts the object in the store unless an object with that id is already there.
    fn ensure_object(
        run: *Run,
        path: [:0]const u8,
        content: *const object.Content,
        attrs: object.Attrs,
        id: Digest,
    ) Error!void {
        assert(content.chunks.len <= constants.store_chunks_max);
        assert(attrs.mode <= 0o7777);
        const store = run.store;
        var storage: PathBuf = undefined;
        if (store.fs.lstat(store.object_path(&storage, id))) |_| {
            run.result.objects_reused += 1;
            return;
        } else |err| {
            if (err != error.NotFound) {
                return run.store_failure("looking for an object", err, store.fs.last_errno());
            }
        }
        var failure: object.Failure = undefined;
        object.put(
            store,
            &run.ws.io,
            &run.ws.scratch,
            path,
            content,
            attrs,
            id,
            &failure,
        ) catch |err| {
            return run.put_failed(err, path, &failure);
        };
        run.result.objects_new += 1;
        run.result.bytes_new += content.size;
    }

    // ---- Extended attributes ----------------------------------------------------------------

    /// The canonical attribute section of the file at `path`, in `ws.blob`. What the store does
    /// not keep is left out with a warning; nothing here fails the import except a file that
    /// vanished.
    fn gather_xattrs(run: *Run, path: [:0]const u8) Error![]const u8 {
        assert(path.len > 0);
        assert(run.ws.xattr_names.len > 0);
        const ws = run.ws;
        ws.builder.reset();
        run.marks = Marks.none;
        const listed = run.store.fs.list_xattrs(path, &ws.xattr_names) catch |err| {
            if (err == error.NotFound) return run.vanished(path);
            run.warn_xattr(path, "(the list)", .unreadable);
            return &xattrs.empty;
        };
        var start: usize = 0;
        while (start < listed.len) {
            const end = std.mem.indexOfScalarPos(u8, listed, start, 0) orelse break;
            if (end > start) try run.collect(path, listed[start..end :0]);
            start = end + 1;
        }
        return ws.builder.finish(&ws.blob);
    }

    /// Overlayfs's own attributes are never imported, but a commit reads what they say.
    fn note_overlay(run: *Run, path: [:0]const u8, name: [:0]const u8) Error!void {
        assert(name.len > 0);
        if (!run.merging) return;
        const marks = &run.marks;
        if (std.mem.eql(u8, name, "user.overlay.whiteout")) marks.whiteout = true;
        if (std.mem.eql(u8, name, "user.overlay.redirect")) marks.unsupported = "redirect";
        if (std.mem.eql(u8, name, "user.overlay.metacopy")) marks.unsupported = "metacopy";
        if (!std.mem.eql(u8, name, "user.overlay.opaque")) return;
        const value = run.store.fs.get_xattr(path, name, &run.ws.xattr_value) catch |err| {
            if (err == error.NotFound) return run.vanished(path);
            return;
        };
        marks.opaque_dir = std.mem.eql(u8, value, "y");
    }

    /// A commit can not follow a redirect or a metadata-only copy-up.
    fn check_marks(run: *Run, path: [:0]const u8) Error!void {
        const feature = run.marks.unsupported orelse return;
        assert(run.diag.code == null);
        diagnose.overlay_feature(run.diag, path, feature);
        return error.Failed;
    }

    fn collect(run: *Run, path: [:0]const u8, name: [:0]const u8) Error!void {
        assert(name.len > 0);
        assert(path.len > 0);
        const ws = run.ws;
        switch (xattrs.class_of(name)) {
            .overlay => return run.note_overlay(path, name),
            .unsupported => return run.warn_xattr(path, name, .namespace),
            .keep => {},
        }
        const value = run.store.fs.get_xattr(path, name, &ws.xattr_value) catch |err| switch (err) {
            error.NotFound => return run.vanished(path),
            error.FileTooLarge => return run.warn_xattr(path, name, .value_too_long),
            else => return run.warn_xattr(path, name, .unreadable),
        };
        ws.builder.add(name, value) catch |err| switch (err) {
            error.TooMany => run.warn_xattr(path, name, .too_many),
            error.NameTooLong => run.warn_xattr(path, name, .name_too_long),
            error.ValueTooLong => run.warn_xattr(path, name, .value_too_long),
        };
    }

    // ---- The root ---------------------------------------------------------------------------

    fn save_root(run: *Run, source: []const u8) Error!void {
        assert(source.len > 0);
        assert(run.depth == 0);
        var root: roots.Root = undefined;
        root.digest = run.result.digest;
        root.kind = .import;
        root.time = run.store.host.time_now();
        root.files = run.result.files;
        root.bytes = run.result.bytes;
        root.set_source(source);
        root.parent = null;
        var failure: object.Failure = undefined;
        roots.save(run.store, &root, &failure) catch {
            return run.store_failure("writing the root record", failure.err, failure.errno);
        };
    }
};

/// Imports `source` and records it as a root. `source` is a path as the user gave it.
pub fn import(
    store: *Store,
    ws: *Workspace,
    source: []const u8,
    options: Options,
    result: *Result,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(source.len > 0);
    assert(options.parent == null);
    var run = try walk(store, ws, source, options, result, diag);
    try run.save_root(source);
    assert(run.depth == 0);
}

/// Applies the upper layer at `upper` to the tree `options.parent`: the new tree is in
/// `result.digest`, written to the store, and is not yet a root (the caller records one, with
/// the totals only it has). Nothing in `upper` is changed.
pub fn commit(
    store: *Store,
    ws: *Workspace,
    upper: []const u8,
    options: Options,
    result: *Result,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(upper.len > 0);
    assert(options.parent != null);
    const run = try walk(store, ws, upper, options, result, diag);
    assert(run.depth == 0);
}

fn walk(
    store: *Store,
    ws: *Workspace,
    source: []const u8,
    options: Options,
    result: *Result,
    diag: *Diag,
) Error!Run {
    result.* = std.mem.zeroes(Result);
    var run: Run = .{
        .store = store,
        .ws = ws,
        .options = options,
        .result = result,
        .diag = diag,
        .depth = 0,
        .warning = undefined,
        .warnings_shown = 0,
        .warnings_hidden = 0,
        .unmapped_path_len = 0,
        .merging = options.parent != null,
        .marks = Marks.none,
    };
    try run.begin(source);
    // Each step handles one entry or finishes one directory; the walk ends because every entry
    // is handled once and the stack is at most `store_depth_max` deep.
    while (run.depth > 0) try run.step();
    run.flush_warnings();
    return run;
}

fn align_up(value: u32, alignment: u32) u32 {
    assert(alignment > 0);
    assert(alignment & (alignment - 1) == 0); // A power of two.
    return (value + alignment - 1) & ~(alignment - 1);
}

comptime {
    assert(constants.store_arena_bytes_max % 8 == 0);
    assert(constants.store_xattr_blob_bytes_max > 0);
}
