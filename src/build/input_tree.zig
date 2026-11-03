//! A step's inputs as one store tree: what the step sees at `/src` and what its cache key
//! hashes (docs/briefs/M7-build.md, slice 2). Each declared input keeps its path: `src/main.go`
//! is `src/main.go` in the tree, and the directories above it are made up (mode 0755, owner 0).
//! Nothing that was not declared is in the tree, so an undeclared README cannot change the key.
//!
//! Everything is read beneath the project directory's descriptor with `Fs.open_beneath`
//! (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`): no path can leave the project, whatever the disk
//! does while the build reads it. A declared input's links are followed (beneath; `inputs.zig`
//! has already refused one that leads out). Inside a directory input nothing is followed: a link
//! is imported as a link, its text in the tree and so in the key. A device, a FIFO or a socket is
//! refused (E0803). The key is computed from what was read, never from a second look.
//!
//! What the tree records is normalised, so that two checkouts of one commit give one key: every
//! owner is 0, no extended attribute is kept, a directory is 0755, a file is 0755 if its owner
//! may run it and 0644 if not, and a link is 0777. Times are never in a tree.
//!
//! The walk is the store importer's (`store/import.zig`): iterative, one frame per directory on
//! a stack at most `store_depth_max` deep, the frames' names and encodings in one arena used as
//! a stack. A made-up directory is a frame whose entries come from the declared inputs, which
//! are walked in component order (`a/b` before `a-b`, as the tree's byte order of names needs).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const file_mod = @import("file.zig");
const inputs_mod = @import("inputs.zig");
const digest_mod = @import("../store/digest.zig");
const store_diagnose = @import("../store/diagnose.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const names_mod = @import("../store/names.zig");
const object = @import("../store/object.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const xattrs = @import("../store/xattrs.zig");

const BuildFile = file_mod.BuildFile;
const Text = file_mod.Text;
const Digest = digest_mod.Digest;
const Fd = fs_mod.Fd;
const NameList = names_mod.NameList;
const PathBuf = fs_mod.PathBuf;
const Problem = inputs_mod.Problem;
const Store = layout.Store;

/// `Refused`: `problem` says which input and why (E0803). `Failed`: `diag` is filled.
pub const Error = error{ Refused, Failed };

pub const directory_mode: u16 = 0o755;
pub const symlink_mode: u16 = 0o777;

/// A file's mode in the tree: 0755 if its owner may run it, 0644 if not.
pub fn file_mode(mode: u16) u16 {
    assert(mode <= 0o7777);
    return if (mode & 0o100 != 0) 0o755 else 0o644;
}

pub const Request = struct {
    store: *Store,
    /// The project directory, open (`Fs.open_directory`).
    project: Fd,
    file: *const BuildFile,
    step: u8,
};

const Frame = struct {
    /// The directory's path below the project (0 for the tree's root), in `Workspace.path`.
    path_len: u32,
    /// A directory that was read; a made-up one has no names of its own.
    walked: bool,
    names: NameList,
    offsets: []const u32,
    next: u32,
    out_at: u32,
    writer: tree.Writer,
};

/// The caller's memory for an import, about 17 MiB; keep it in static or heap storage.
pub const Workspace = struct {
    arena: [constants.store_arena_bytes_max]u8 align(8),
    io: [constants.store_io_buffer_bytes]u8,
    chunks: [constants.store_chunks_max]Digest,
    scratch: [constants.store_chunks_max]Digest,
    frames: [constants.store_depth_max + 1]Frame,
    path: [constants.path_bytes_max + 1]u8,
    link_target: [constants.store_symlink_target_bytes_max + 1]u8,
    order: [constants.build_step_inputs_max]u32,
};

/// Imports the inputs of step `request.step` and returns the tree's digest. The tree is in the
/// store, but not a root: the caller roots what it keeps.
pub fn import(request: Request, ws: *Workspace, problem: *Problem, diag: *Diag) Error!Digest {
    assert(request.step < request.file.steps_count);
    assert(diag.code == null);
    var run: Run = .{
        .request = request,
        .ws = ws,
        .problem = problem,
        .diag = diag,
        .depth = 0,
        .input = undefined,
    };
    return run.go();
}

const Run = struct {
    request: Request,
    ws: *Workspace,
    problem: *Problem,
    diag: *Diag,
    depth: u32,
    /// The declared input being imported, for a refusal.
    input: Text,

    fn go(run: *Run) Error!Digest {
        const inputs = run.request.file.steps[run.request.step].inputs.slice();
        assert(inputs.len <= run.ws.order.len);
        const order = run.ws.order[0..inputs.len];
        for (order, 0..) |*slot, index| slot.* = @intCast(index);
        std.sort.insertion(u32, order, run, input_less);
        try run.push_made_up(0);
        for (order) |index| {
            run.input = inputs[index];
            const text = run.request.file.text(run.input);
            assert(inputs_mod.is_plain_relative(text));
            try run.close_to(text);
            try run.open_parents(text);
            try run.entry(@intCast(text.len), true);
            try run.drain();
        }
        try run.close_to("");
        assert(run.depth == 1);
        return run.finish_root();
    }

    fn input_less(run: *Run, left: u32, right: u32) bool {
        const inputs = run.request.file.steps[run.request.step].inputs.slice();
        assert(left < inputs.len);
        assert(right < inputs.len);
        return component_less(run.request.file.text(inputs[left]), run.request.file.text(
            inputs[right],
        ));
    }

    // ---- Failures ---------------------------------------------------------------------------

    fn refuse(
        run: *Run,
        kind: inputs_mod.ProblemKind,
        path_len: u32,
        file_kind: ?fs_mod.FileKind,
    ) Error {
        assert(path_len > 0);
        assert(path_len <= constants.path_bytes_max);
        const resolved = &run.problem.resolved;
        @memcpy(resolved.bytes[0..path_len], run.ws.path[0..path_len]);
        resolved.bytes[path_len] = 0;
        resolved.len = path_len;
        run.problem.kind = kind;
        run.problem.step = run.request.step;
        run.problem.input = run.input;
        run.problem.file_kind = file_kind orelse .file;
        return error.Refused;
    }

    /// A source call failed: gone, swapped or out of reach is a change under the build;
    /// anything else is an input that cannot be read.
    fn source_failed(run: *Run, err: host_mod.Error, path_len: u32) Error {
        assert(path_len > 0);
        const fs = run.request.store.fs;
        const errno = fs.last_errno();
        const changed = err == error.NotFound or errno == errno_xdev or errno == errno_loop or
            errno == errno_notdir;
        return run.refuse(if (changed) .changed else .unreadable, path_len, null);
    }

    const errno_notdir: u16 = 20;
    const errno_xdev: u16 = 18;
    const errno_loop: u16 = 40;

    fn limit(run: *Run, which: store_diagnose.Limit, path_len: u32) Error {
        assert(run.diag.code == null);
        assert(path_len <= constants.path_bytes_max);
        const shown: []const u8 = if (path_len == 0) "." else run.ws.path[0..path_len];
        store_diagnose.too_big(run.diag, which, shown);
        return error.Failed;
    }

    /// The top frame's tree writer ran out of room. Its room is the tree's bound, or less when
    /// the frames below it left the arena short: then the arena is the limit that was reached.
    fn writer_full(run: *Run, path_len: u32) Error {
        assert(run.depth > 0);
        const writer = &run.ws.frames[run.depth - 1].writer;
        assert(writer.len <= writer.buffer.len);
        const short = writer.buffer.len < constants.store_tree_bytes_max;
        return run.limit(if (short) .arena else .tree_bytes, path_len);
    }

    fn store_failed(run: *Run, operation: []const u8, failure: *const object.Failure) Error {
        assert(operation.len > 0);
        assert(run.diag.code == null);
        store_diagnose.write_failed(
            run.diag,
            run.request.store,
            operation,
            failure.err,
            failure.errno,
        );
        return error.Failed;
    }

    // ---- The made-up directories above the declared inputs ----------------------------------

    /// Pops every frame whose directory does not hold `text` (the root holds everything).
    fn close_to(run: *Run, text: []const u8) Error!void {
        assert(run.depth > 0);
        for (0..constants.store_depth_max + 1) |_| {
            if (run.depth == 1) return;
            const top = &run.ws.frames[run.depth - 1];
            assert(!top.walked);
            if (holds(run.ws.path[0..top.path_len], text)) return;
            try run.pop_frame();
        }
        unreachable;
    }

    /// Puts `text` in the path and pushes a made-up frame for each of its parts above the last
    /// that the stack does not have yet.
    fn open_parents(run: *Run, text: []const u8) Error!void {
        assert(text.len > 0);
        if (text.len > constants.path_bytes_max) return run.limit(.path, 0);
        const top_len = run.ws.frames[run.depth - 1].path_len;
        assert(top_len < text.len);
        @memcpy(run.ws.path[top_len..text.len], text[top_len..]);
        run.ws.path[text.len] = 0;
        var at: u32 = if (top_len == 0) 0 else top_len + 1;
        for (0..constants.store_depth_max + 1) |_| {
            const slash = std.mem.indexOfScalarPos(u8, text, at, '/') orelse return;
            const name = text[at..slash];
            const writer = &run.ws.frames[run.depth - 1].writer;
            writer.begin(name, .dir, directory_mode, 0, 0, &xattrs.empty) catch
                return run.writer_full(@intCast(slash));
            try run.push_made_up(@intCast(slash));
            at = @intCast(slash + 1);
        }
        return run.limit(.depth, @intCast(text.len));
    }

    fn frame_base(run: *const Run) u32 {
        assert(run.depth <= constants.store_depth_max + 1);
        if (run.depth == 0) return 0;
        const parent = &run.ws.frames[run.depth - 1];
        assert(parent.out_at % 8 == 0);
        return align_up(parent.out_at + parent.writer.len, 8);
    }

    fn push_made_up(run: *Run, path_len: u32) Error!void {
        assert(path_len <= constants.path_bytes_max);
        if (run.depth > constants.store_depth_max) return run.limit(.depth, path_len);
        const base = run.frame_base();
        if (base + 4096 > run.ws.arena.len) return run.limit(.arena, path_len);
        run.ws.frames[run.depth] = .{
            .path_len = path_len,
            .walked = false,
            .names = NameList.init(run.ws.arena[base..base], 1),
            .offsets = &.{},
            .next = 0,
            .out_at = base,
            .writer = tree.Writer.init(run.ws.arena[base..]),
        };
        run.depth += 1;
    }

    // ---- One entry --------------------------------------------------------------------------

    /// Imports the entry at `ws.path[0..path_len]` into the top frame. `declared`: it is a
    /// declared input, whose links are followed; inside a directory input none is.
    fn entry(run: *Run, path_len: u32, declared: bool) Error!void {
        assert(path_len > 0);
        assert(run.ws.path[path_len] == 0);
        const fs = run.request.store.fs;
        const path = run.ws.path[0..path_len :0];
        const how: fs_mod.Beneath = if (declared) .path_follow else .path_entry;
        const handle = fs.open_beneath(run.request.project, path, how) catch |err|
            return run.source_failed(err, path_len);
        defer fs.close(handle);
        const stat = fs.fstat(handle) catch |err| return run.source_failed(err, path_len);
        const name = base_name(path);
        const writer = &run.ws.frames[run.depth - 1].writer;
        switch (stat.kind) {
            .file => try run.entry_file(path_len, &stat),
            .dir => {
                writer.begin(name, .dir, directory_mode, 0, 0, &xattrs.empty) catch
                    return run.writer_full(path_len);
                try run.push_walked(path_len, stat.inode);
            },
            .symlink => {
                assert(!declared); // `path_follow` resolved every link.
                const target = fs.read_link_fd(handle, &run.ws.link_target) catch |err| {
                    if (err == error.FileTooLarge) return run.limit(.target, path_len);
                    return run.source_failed(err, path_len);
                };
                if (target.len == 0) return run.refuse(.changed, path_len, null);
                if (target.len > constants.store_symlink_target_bytes_max) {
                    return run.limit(.target, path_len);
                }
                writer.begin(name, .symlink, symlink_mode, 0, 0, &xattrs.empty) catch
                    return run.writer_full(path_len);
                writer.end_symlink(target) catch return run.writer_full(path_len);
            },
            else => return run.refuse(
                if (declared) .bad_kind else .holds_bad_kind,
                path_len,
                stat.kind,
            ),
        }
    }

    fn entry_file(run: *Run, path_len: u32, stat: *const fs_mod.Stat) Error!void {
        assert(stat.kind == .file);
        const store = run.request.store;
        const path = run.ws.path[0..path_len :0];
        var content: object.Content = undefined;
        const mode = try run.hash_file(path_len, stat.inode, &content);
        const attrs: object.Attrs = .{ .mode = mode, .uid = 0, .gid = 0, .xattrs = &xattrs.empty };
        const id = object.object_id(content.hash, attrs);
        const writer = &run.ws.frames[run.depth - 1].writer;
        writer.begin(base_name(path), .file, mode, 0, 0, &xattrs.empty) catch
            return run.writer_full(path_len);
        writer.end_file(content.size, content.hash, id) catch
            return run.writer_full(path_len);
        var failure: object.Failure = undefined;
        var storage: PathBuf = undefined;
        if (store.fs.lstat(store.object_path(&storage, id))) |_| return else |err| {
            if (err != error.NotFound) {
                failure = .{ .err = err, .errno = store.fs.last_errno() };
                return run.store_failed("looking for an object", &failure);
            }
        }
        const project = run.request.project;
        const source: object.Source = .{ .beneath = .{ .dir = project, .path = path } };
        const ws = run.ws;
        const io = &ws.io;
        object.put_from(store, io, &ws.scratch, source, &content, attrs, id, &failure) catch |err|
            return switch (err) {
                error.Changed => run.refuse(.changed, path_len, null),
                error.SourceFailed => run.refuse(.unreadable, path_len, null),
                error.StoreFailed => run.store_failed("writing an object", &failure),
            };
    }

    /// The first read of a file: its size, hash and chunks into `content`; returns its mode in
    /// the tree. The descriptor must be the inode the entry's handle saw.
    fn hash_file(run: *Run, path_len: u32, inode: u64, content: *object.Content) Error!u16 {
        const store = run.request.store;
        const fs = store.fs;
        const path = run.ws.path[0..path_len :0];
        const fd = fs.open_beneath(run.request.project, path, .read) catch |err|
            return run.source_failed(err, path_len);
        defer fs.close(fd);
        const stat = fs.fstat(fd) catch |err| return run.source_failed(err, path_len);
        if (stat.kind != .file) return run.refuse(.changed, path_len, null);
        if (stat.inode != inode) return run.refuse(.changed, path_len, null);
        var reader = object.Reader.init(store.chunk_bytes);
        const calls_max = stat.size / run.ws.io.len + constants.store_chunks_max + 2;
        for (0..calls_max) |_| {
            const count = fs.read(fd, &run.ws.io) catch |err| {
                return run.source_failed(err, path_len);
            };
            if (count == 0) break;
            if (!reader.update(run.ws.io[0..count], &run.ws.chunks)) {
                return run.limit(.file_size, path_len);
            }
        } else return run.refuse(.changed, path_len, null);
        const hash = reader.finish(&run.ws.chunks);
        const chunks = run.ws.chunks[0..reader.count];
        content.* = .{ .size = reader.size, .hash = hash, .chunks = chunks };
        return file_mode(stat.mode);
    }

    // ---- Directories that are read ----------------------------------------------------------

    fn push_walked(run: *Run, path_len: u32, inode: u64) Error!void {
        assert(path_len > 0);
        if (run.depth > constants.store_depth_max) return run.limit(.depth, path_len);
        const fs = run.request.store.fs;
        const path = run.ws.path[0..path_len :0];
        const base = run.frame_base();
        if (base + 4096 > run.ws.arena.len) return run.limit(.arena, path_len);
        var names = NameList.init(run.ws.arena[base..], constants.store_dir_entries_max);
        {
            const fd = fs.open_beneath(run.request.project, path, .directory) catch |err|
                return run.source_failed(err, path_len);
            defer fs.close(fd);
            const stat = fs.fstat(fd) catch |err| return run.source_failed(err, path_len);
            if (stat.kind != .dir) return run.refuse(.changed, path_len, null);
            if (stat.inode != inode) return run.refuse(.changed, path_len, null);
            fs.read_dir_fd(fd, names.visitor()) catch |err| return run.source_failed(err, path_len);
        }
        if (names.too_many) return run.limit(.entries, path_len);
        if (names.too_long) return run.limit(.name, path_len);
        if (names.full) return run.limit(.arena, path_len);
        const offsets_at = align_up(base + names.used, 4);
        const offsets_end = offsets_at + names.count * 4;
        const out_at = align_up(offsets_end, 8);
        if (out_at + 256 > run.ws.arena.len) return run.limit(.arena, path_len);
        const region: []align(4) u8 = @alignCast(run.ws.arena[offsets_at..offsets_end]);
        const offsets: []u32 = std.mem.bytesAsSlice(u32, region);
        run.ws.frames[run.depth] = .{
            .path_len = path_len,
            .walked = true,
            .names = names,
            .offsets = names.sorted(offsets),
            .next = 0,
            .out_at = out_at,
            .writer = tree.Writer.init(run.ws.arena[out_at..]),
        };
        run.depth += 1;
    }

    /// Walks the directory input just pushed (if any) to its end.
    fn drain(run: *Run) Error!void {
        assert(run.depth > 0);
        const steps_max = constants.store_walk_entries_max + constants.store_depth_max + 2;
        for (0..steps_max) |_| {
            const top = &run.ws.frames[run.depth - 1];
            if (!top.walked) return;
            if (top.next == top.offsets.len) {
                try run.pop_frame();
                continue;
            }
            const name = top.names.at(top.offsets[top.next]);
            top.next += 1;
            const path_len = top.path_len + 1 + @as(u32, @intCast(name.len));
            if (path_len > constants.path_bytes_max) return run.limit(.path, top.path_len);
            run.ws.path[top.path_len] = '/';
            @memcpy(run.ws.path[top.path_len + 1 .. path_len], name);
            run.ws.path[path_len] = 0;
            try run.entry(path_len, false);
        }
        unreachable; // The store's bounds on entries and depth end the walk first.
    }

    /// Finishes the top frame's tree, puts it, and completes its entry in the parent.
    fn pop_frame(run: *Run) Error!void {
        assert(run.depth > 1);
        const top = &run.ws.frames[run.depth - 1];
        const bytes = top.writer.finish();
        const digest = Digest.of(bytes);
        var failure: object.Failure = undefined;
        _ = trees.put(run.request.store, digest, bytes, &failure) catch
            return run.store_failed("writing a tree", &failure);
        const path_len = top.path_len;
        run.depth -= 1;
        const parent = &run.ws.frames[run.depth - 1];
        parent.writer.end_dir(digest) catch return run.writer_full(path_len);
    }

    fn finish_root(run: *Run) Error!Digest {
        assert(run.depth == 1);
        const root = &run.ws.frames[0];
        assert(!root.walked);
        const own: tree.Own = .{
            .mode = directory_mode,
            .uid = 0,
            .gid = 0,
            .xattrs = &xattrs.empty,
        };
        const bytes = root.writer.finish_with(own) catch return run.writer_full(0);
        const digest = Digest.of(bytes);
        var failure: object.Failure = undefined;
        _ = trees.put(run.request.store, digest, bytes, &failure) catch
            return run.store_failed("writing a tree", &failure);
        run.depth = 0;
        return digest;
    }
};

/// True if the directory `directory` (a path below the project, "" for the project) holds
/// `path` somewhere below it.
fn holds(directory: []const u8, path: []const u8) bool {
    assert(directory.len <= constants.path_bytes_max);
    if (directory.len == 0) return true;
    if (path.len <= directory.len) return false;
    if (!std.mem.startsWith(u8, path, directory)) return false;
    return path[directory.len] == '/';
}

/// Orders paths part by part: a slash sorts before every byte, so `a/b` comes before `a-b`,
/// as the tree's byte order of the names `a` and `a-b` needs.
pub fn component_less(left: []const u8, right: []const u8) bool {
    assert(left.len > 0);
    assert(right.len > 0);
    const shared = @min(left.len, right.len);
    for (left[0..shared], right[0..shared]) |a, b| {
        const ka: u16 = if (a == '/') 0 else @as(u16, a) + 1;
        const kb: u16 = if (b == '/') 0 else @as(u16, b) + 1;
        if (ka != kb) return ka < kb;
    }
    return left.len < right.len;
}

fn base_name(path: []const u8) []const u8 {
    assert(path.len > 0);
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    assert(slash + 1 < path.len);
    return path[slash + 1 ..];
}

fn align_up(value: u32, alignment: u32) u32 {
    assert(alignment > 0);
    assert(std.math.isPowerOfTwo(alignment));
    return (value + alignment - 1) & ~(alignment - 1);
}

test "component order puts a directory's contents before a longer sibling name" {
    try std.testing.expect(component_less("a/b", "a-b"));
    try std.testing.expect(!component_less("a-b", "a/b"));
    try std.testing.expect(component_less("a", "a-b"));
    try std.testing.expect(component_less("a", "b"));
    try std.testing.expect(!component_less("b", "b"));
}

test "a file's mode is normalised by its owner's execute bit" {
    try std.testing.expectEqual(@as(u16, 0o755), file_mode(0o700));
    try std.testing.expectEqual(@as(u16, 0o644), file_mode(0o600));
    try std.testing.expectEqual(@as(u16, 0o644), file_mode(0o4677));
    try std.testing.expectEqual(@as(u16, 0o755), file_mode(0o4711));
}
