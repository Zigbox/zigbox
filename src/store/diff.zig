//! `store diff`: what differs between two trees, as a list of paths (docs/briefs/M3-store.md,
//! "Commit and diff").
//!
//! Two sorted lists are merged, directory by directory, with an explicit stack (docs/STYLE.md
//! bans recursion). A name in both is compared by what the tree records: for a file its content,
//! mode, owner and attributes, for a symlink its target, mode, owner and attributes, for a
//! directory its mode, owner and attributes. Two directories with the same subtree digest are
//! the same all the way down and are not read. A name in one tree only is `added` or `removed`,
//! and so is every path below it (a directory that appears is listed with its contents, because
//! the question is which files changed). A name that has another kind on the other side is
//! `changed` with the attribute `type`, and the contents of the side that is a directory are
//! listed as added or removed.
//!
//! The paths come in sorted order, a directory before what is in it. The root directory's own
//! mode, owner and attributes are reported first, as the path "/".
//!
//! The trees of the stack live in one arena, as in `import.zig`: a frame's two trees start where
//! its parent frame's end, and are free again when it is popped.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const diagnose = @import("diagnose.zig");
const digest_mod = @import("digest.zig");
const layout = @import("layout.zig");
const tree = @import("tree.zig");
const trees = @import("trees.zig");

const Digest = digest_mod.Digest;
const Store = layout.Store;

/// The diff failed; the reason is in the `Diag`.
pub const Error = error{Failed};

pub const What = enum { added, removed, changed };

/// What differs about a path that is `changed`. A path that is added or removed has none set.
pub const Attrs = struct {
    content: bool = false,
    mode: bool = false,
    owner: bool = false,
    xattrs: bool = false,
    target: bool = false,
    /// The kind (file, directory, symlink) is not the same on both sides.
    kind: bool = false,

    pub fn any(attrs: Attrs) bool {
        return attrs.content or attrs.mode or attrs.owner or attrs.xattrs or attrs.target or
            attrs.kind;
    }
};

/// One line of the answer. `kind` is the entry's kind in the second tree, or in the first for a
/// removed path.
pub const Change = struct {
    what: What,
    path: []const u8,
    kind: tree.Kind,
    attrs: Attrs,
};

/// Receives each change. It returns false if it could not take it (and has put the reason in
/// the diagnostic), which ends the diff.
pub const Sink = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, change: *const Change, diag: *Diag) bool,
};

pub const Summary = struct {
    added: u64 = 0,
    removed: u64 = 0,
    changed: u64 = 0,
};

/// One side of a directory being compared: its tree, read one entry ahead.
const Side = struct {
    present: bool,
    digest: Digest,
    decoder: tree.Decoder,
    peek: tree.Entry,
    has: bool,
};

const Frame = struct {
    a: Side,
    b: Side,
    /// The length of this directory's path in `Workspace.path`; zero for the root.
    path_len: u32,
    /// Where the arena is free again for a child.
    end: u32,
};

/// The caller's memory besides the arena: about 40 KiB.
pub const Workspace = struct {
    frames: [constants.store_depth_max + 1]Frame,
    path: [constants.path_bytes_max + 1]u8,
};

const Run = struct {
    store: *const Store,
    ws: *Workspace,
    arena: []align(8) u8,
    sink: Sink,
    summary: *Summary,
    diag: *Diag,
    depth: u32,

    fn failed(run: *Run, digest: Digest, err: anyerror, errno: u16) Error {
        diagnose.tree_load_failed(run.diag, run.store, digest, err, errno);
        return error.Failed;
    }

    /// Reads a tree into the arena at `at`; the bytes end where the slice does.
    fn load(run: *Run, digest: Digest, at: u32) Error![]const u8 {
        if (at + constants.store_tree_bytes_max + 256 > run.arena.len) {
            diagnose.too_big(run.diag, .arena, "the trees being compared");
            return error.Failed;
        }
        var errno: u16 = 0;
        const room = run.arena[at..][0..constants.store_tree_bytes_max];
        return trees.load(run.store, digest, room, &errno) catch |err| {
            return run.failed(digest, err, errno);
        };
    }

    fn damaged(run: *Run, digest: Digest) Error {
        assert(run.diag.code == null);
        diagnose.tree_damaged(run.diag, digest, "does not decode");
        return error.Failed;
    }

    fn advance(run: *Run, side: *Side) Error!void {
        assert(run.depth <= constants.store_depth_max + 1);
        if (!side.present) return;
        side.has = side.decoder.next(&side.peek) catch return run.damaged(side.digest);
    }

    /// Reads one side into the arena from `at`; a side with no digest is empty. Returns the end.
    fn open_side(run: *Run, side: *Side, digest: ?Digest, at: u32) Error!u32 {
        side.has = false;
        side.present = digest != null;
        side.digest = digest orelse tree.zero_digest;
        const found = digest orelse return at;
        const bytes = try run.load(found, at);
        side.decoder.init(bytes) catch return run.damaged(found);
        try run.advance(side);
        return std.mem.alignForward(u32, at + @as(u32, @intCast(bytes.len)), 8);
    }

    fn push(run: *Run, a: ?Digest, b: ?Digest, path_len: u32) Error!void {
        assert(run.depth <= constants.store_depth_max);
        if (a == null) assert(b != null);
        const at: u32 = if (run.depth == 0) 0 else run.ws.frames[run.depth - 1].end;
        const frame = &run.ws.frames[run.depth];
        frame.path_len = path_len;
        const middle = try run.open_side(&frame.a, a, at);
        frame.end = try run.open_side(&frame.b, b, middle);
        run.depth += 1;
    }

    fn emit(
        run: *Run,
        frame: *const Frame,
        what: What,
        name: []const u8,
        kind: tree.Kind,
        attrs: Attrs,
    ) Error!u32 {
        const ws = run.ws;
        const slash: u32 = 1;
        const length: u32 = frame.path_len + slash + @as(u32, @intCast(name.len));
        if (length > constants.path_bytes_max) {
            diagnose.too_big(run.diag, .path, ws.path[0..64]);
            return error.Failed;
        }
        ws.path[frame.path_len] = '/';
        @memcpy(ws.path[frame.path_len + slash ..][0..name.len], name);
        const change: Change = .{
            .what = what,
            .path = ws.path[0..length],
            .kind = kind,
            .attrs = attrs,
        };
        switch (what) {
            .added => run.summary.added += 1,
            .removed => run.summary.removed += 1,
            .changed => run.summary.changed += 1,
        }
        if (!run.sink.call(run.sink.context, &change, run.diag)) return error.Failed;
        return length;
    }

    /// An entry on one side only: listed, and if it is a directory, so is all that is in it.
    fn lone(run: *Run, frame: *Frame, entry_: tree.Entry, what: What) Error!void {
        assert(what != .changed);
        const length = try run.emit(frame, what, entry_.name, entry_.kind, .{});
        if (entry_.kind != .dir) return;
        if (run.depth > constants.store_depth_max) {
            diagnose.too_big(run.diag, .depth, run.ws.path[0..length]);
            return error.Failed;
        }
        if (what == .added) {
            try run.push(null, entry_.subtree, length);
        } else {
            try run.push(entry_.subtree, null, length);
        }
    }

    fn both(run: *Run, frame: *Frame, old: tree.Entry, new: tree.Entry) Error!void {
        assert(std.mem.eql(u8, old.name, new.name));
        var attrs = compare(old, new);
        if (old.kind != new.kind) attrs.kind = true;
        // Directories with the same subtree digest are the same all the way down.
        const same_below = old.kind == .dir and new.kind == .dir and old.subtree.eql(new.subtree);
        var length: u32 = 0;
        if (attrs.any()) length = try run.emit(frame, .changed, new.name, new.kind, attrs);
        if (same_below) return;
        if (old.kind != .dir and new.kind != .dir) return;
        if (attrs.kind) { // One of them is a directory: its contents are all added or removed.
            assert(length > 0);
            if (run.depth > constants.store_depth_max) {
                diagnose.too_big(run.diag, .depth, run.ws.path[0..length]);
                return error.Failed;
            }
            if (new.kind == .dir) return run.push(null, new.subtree, length);
            return run.push(old.subtree, null, length);
        }
        if (length == 0) length = try run.path_of(frame, new.name);
        if (run.depth > constants.store_depth_max) {
            diagnose.too_big(run.diag, .depth, run.ws.path[0..length]);
            return error.Failed;
        }
        try run.push(old.subtree, new.subtree, length);
    }

    /// The path of `name` in `frame`, written into `ws.path`, without reporting anything.
    fn path_of(run: *Run, frame: *const Frame, name: []const u8) Error!u32 {
        const ws = run.ws;
        const length: u32 = frame.path_len + 1 + @as(u32, @intCast(name.len));
        if (length > constants.path_bytes_max) {
            diagnose.too_big(run.diag, .path, ws.path[0..64]);
            return error.Failed;
        }
        ws.path[frame.path_len] = '/';
        @memcpy(ws.path[frame.path_len + 1 ..][0..name.len], name);
        return length;
    }

    /// The root directory's mode, owner and attributes, compared before anything else.
    fn root_own(run: *Run, a: Digest, b: Digest) Error!void {
        const bytes_a = try run.load(a, 0);
        const own_a = own_of(bytes_a) catch return run.damaged(a);
        // `b` is read after `a`, whose own is already copied out of the way.
        const saved: tree.Own = own_a;
        var attrs_copy: [constants.store_xattr_blob_bytes_max]u8 = undefined;
        @memcpy(attrs_copy[0..saved.xattrs.len], saved.xattrs);
        const bytes_b = try run.load(b, 0);
        const own_b = own_of(bytes_b) catch return run.damaged(b);
        var attrs: Attrs = .{};
        attrs.mode = saved.mode != own_b.mode;
        attrs.owner = saved.uid != own_b.uid or saved.gid != own_b.gid;
        attrs.xattrs = !std.mem.eql(u8, attrs_copy[0..saved.xattrs.len], own_b.xattrs);
        if (!attrs.any()) return;
        const change: Change = .{ .what = .changed, .path = "/", .kind = .dir, .attrs = attrs };
        run.summary.changed += 1;
        if (!run.sink.call(run.sink.context, &change, run.diag)) return error.Failed;
    }

    /// One step: an entry of the top directory is handled, or the directory is finished.
    fn step(run: *Run) Error!void {
        assert(run.depth > 0);
        const frame = &run.ws.frames[run.depth - 1];
        if (!frame.a.has and !frame.b.has) {
            run.depth -= 1;
            return;
        }
        const order: std.math.Order = if (!frame.a.has)
            .gt
        else if (!frame.b.has)
            .lt
        else
            std.mem.order(u8, frame.a.peek.name, frame.b.peek.name);
        const old = frame.a.peek;
        const new = frame.b.peek;
        switch (order) {
            .lt => {
                try run.advance(&frame.a);
                try run.lone(frame, old, .removed);
            },
            .gt => {
                try run.advance(&frame.b);
                try run.lone(frame, new, .added);
            },
            .eq => {
                try run.advance(&frame.a);
                try run.advance(&frame.b);
                try run.both(frame, old, new);
            },
        }
    }
};

/// What differs between two entries of the same name, other than their kind.
fn compare(old: tree.Entry, new: tree.Entry) Attrs {
    var attrs: Attrs = .{};
    attrs.mode = old.mode != new.mode;
    attrs.owner = old.uid != new.uid or old.gid != new.gid;
    attrs.xattrs = !std.mem.eql(u8, old.xattrs, new.xattrs);
    if (old.kind != new.kind) return attrs;
    switch (new.kind) {
        .file => attrs.content = !old.content.eql(new.content),
        .symlink => attrs.target = !std.mem.eql(u8, old.target, new.target),
        .dir => {},
    }
    return attrs;
}

/// The root directory's own record of a tree, found by reading it to its end.
fn own_of(bytes: []const u8) tree.Malformed!tree.Own {
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    var scratch: tree.Entry = undefined;
    while (try decoder.next(&scratch)) {}
    return decoder.own;
}

/// Reports the differences between the trees `a` and `b` to `sink`, in path order.
pub fn diff(
    store: *const Store,
    ws: *Workspace,
    arena: []align(8) u8,
    a: Digest,
    b: Digest,
    sink: Sink,
    summary: *Summary,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(arena.len >= 2 * constants.store_tree_bytes_max + 512);
    summary.* = .{};
    if (a.eql(b)) return;
    var run: Run = .{
        .store = store,
        .ws = ws,
        .arena = arena,
        .sink = sink,
        .summary = summary,
        .diag = diag,
        .depth = 0,
    };
    try run.root_own(a, b);
    try run.push(a, b, 0);
    // Each step handles one entry or pops one directory, and every entry is handled once.
    while (run.depth > 0) try run.step();
}
