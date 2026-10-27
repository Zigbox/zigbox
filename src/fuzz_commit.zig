//! The `commit` fuzzer: `commit` and `diff` against the simulated file system, with the same
//! faults as the `store` fuzzer.
//!
//! Each iteration builds a random tree `/src` and a second copy of it, `/dst`, which it then
//! changes at random: files deleted, rewritten or given another mode, symlinks retargeted,
//! directories deleted, given another mode or replaced by a new directory, and new names added.
//! The same changes are written as an overlay's upper layer (`/upper`): a deletion is a
//! character device 0/0 or a file with `user.overlay.whiteout`, a replaced directory is marked
//! `user.overlay.opaque`, and every directory above a change is in the layer with the metadata
//! it has in `/src`, as overlayfs's copy-up makes it. The oracle is independent of the merge:
//! the digest of importing `/dst` in a clean file system. Properties:
//!   1. A commit of `/upper` onto the import of `/src`, under any fault that lets it succeed,
//!      has the oracle's digest.
//!   2. A commit that fails, or a crash (after the restart), leaves a store that is whole
//!      (`test_support.check_whole`), and the same commit then succeeds with the oracle's digest.
//!   3. The diff of the two trees is the same list the other way round with added and removed
//!      swapped, is empty exactly when the digests are equal, and has no two lines for one path.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const fs_mod = @import("store/fs.zig");
const Diag = @import("diag/diag.zig").Diag;
const diff = @import("store/diff.zig");
const digest_mod = @import("store/digest.zig");
const fs_sim = @import("store/fs_sim.zig");
const fuzz_store = @import("fuzz_store.zig");
const host_sim = @import("host_sim.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");

const Digest = digest_mod.Digest;
const SimFs = fs_sim.SimFs;

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: SimFs = undefined;
var reference_files: SimFs = undefined;
var store: layout.Store = undefined;
var workspace: import.Workspace = undefined;
var diff_workspace: diff.Workspace = undefined;
var diag: Diag = undefined;

/// Relative paths of the directories the changes removed or replaced; nothing below them is
/// looked at again.
const Path = [constants.sim_fs_path_bytes_max]u8;

const Gone = struct {
    names: [16][48]u8 = undefined,
    lengths: [16]u8 = undefined,
    count: u32 = 0,

    fn add(gone: *Gone, rel: []const u8) void {
        if (gone.count == gone.names.len) return;
        if (rel.len > gone.names[0].len) return;
        @memcpy(gone.names[gone.count][0..rel.len], rel);
        gone.lengths[gone.count] = @intCast(rel.len);
        gone.count += 1;
    }

    fn covers(gone: *const Gone, rel: []const u8) bool {
        for (0..gone.count) |at| {
            const name = gone.names[at][0..gone.lengths[at]];
            if (rel.len > name.len and std.mem.startsWith(u8, rel, name)) {
                if (rel[name.len] == '/') return true;
            }
        }
        return false;
    }
};

fn path_of(buffer: *Path, root: []const u8, rel: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ root, rel }) catch {
        unreachable; // The generated names are a few bytes.
    };
}

/// Puts into the upper layer every directory above `rel`, as copied up from `/src`.
fn put_ancestors(fs: *SimFs, rel: []const u8) void {
    var at: usize = 1;
    while (std.mem.indexOfScalarPos(u8, rel, at, '/')) |slash| : (at = slash + 1) {
        var upper: Path = undefined;
        var origin: Path = undefined;
        const target = path_of(&upper, "/upper", rel[0..slash]);
        if (fs.kind_of(target) != null) continue;
        const stat = fs.stat_of(path_of(&origin, "/src", rel[0..slash])).?;
        fs.put(target, .dir, stat.mode, .{ stat.uid, stat.gid }, "");
    }
}

/// Removes `rel` from `/dst`, with everything below it.
fn remove_below(fs: *SimFs, rel: []const u8) void {
    var prefix: Path = undefined;
    const base = path_of(&prefix, "/dst", rel);
    var index: u32 = 0;
    while (index < fs.count) : (index += 1) {
        const path = fs.alive_path(index) orelse continue;
        if (path.len <= base.len) continue;
        if (!std.mem.startsWith(u8, path, base)) continue;
        if (path[base.len] == '/') fs.remove_path(path);
    }
}

const Change = enum { delete, rewrite, chmod, opaque_dir, retarget };

/// One change to `rel`, in `/dst` and, if `with_upper`, in `/upper`.
fn apply(
    fs: *SimFs,
    change: Change,
    rel: []const u8,
    number: u32,
    flavour: bool,
    upper: bool,
) void {
    var dst_buffer: Path = undefined;
    var src_buffer: Path = undefined;
    var up_buffer: Path = undefined;
    const dst = path_of(&dst_buffer, "/dst", rel);
    const stat = fs.stat_of(path_of(&src_buffer, "/src", rel)).?;
    const owner: [2]u32 = .{ stat.uid, stat.gid };
    const marked = if (fs.xattrs_of(path_of(&src_buffer, "/src", rel))) |blob|
        std.mem.indexOf(u8, blob, "user.k") != null
    else
        false;
    var text: [24]u8 = undefined;
    const content = std.fmt.bufPrint(&text, "changed {d}", .{number}) catch unreachable; // Short.
    const mode: u16 = if (stat.mode == 0o700) 0o711 else 0o700;
    if (upper) put_ancestors(fs, rel);
    const target = path_of(&up_buffer, "/upper", rel);
    switch (change) {
        .delete => {
            remove_below(fs, rel);
            fs.remove_path(dst);
            if (!upper) return;
            if (flavour) {
                fs.put(target, .char_device, 0, .{ 0, 0 }, "");
            } else {
                fs.put(target, .file, 0, .{ 0, 0 }, "");
                fs.put_xattr(target, "user.overlay.whiteout", "");
            }
        },
        .rewrite => {
            fs.remove_path(dst);
            fs.put(dst, .file, stat.mode, owner, content);
            if (marked) fs.put_xattr(dst, "user.k", "v");
            if (!upper) return;
            fs.put(target, .file, stat.mode, owner, content);
            if (marked) fs.put_xattr(target, "user.k", "v");
        },
        .chmod => {
            fs.set_mode_of(dst, mode);
            if (upper) fs.put(target, .dir, mode, owner, "");
        },
        .opaque_dir => {
            remove_below(fs, rel);
            var fresh: Path = undefined;
            fs.put(path_of(&fresh, dst, "/fresh"), .file, 0o644, owner, content);
            if (!upper) return;
            fs.put(target, .dir, stat.mode, owner, "");
            fs.put_xattr(target, "user.overlay.opaque", "y");
            fs.put(path_of(&fresh, target, "/fresh"), .file, 0o644, owner, content);
        },
        .retarget => {
            fs.remove_path(dst);
            fs.put_symlink(dst, content);
            if (upper) fs.put_symlink(target, content);
        },
    }
}

/// Which change a node gets, if any: a function of the roll and the kind.
fn choose(kind: fs_mod.FileKind, roll: u8) ?Change {
    return switch (kind) {
        .dir => if (roll < 8)
            .delete
        else if (roll < 14)
            .opaque_dir
        else if (roll < 22)
            .chmod
        else
            null,
        .file => if (roll < 10) .delete else if (roll < 30) .rewrite else null,
        .symlink => if (roll < 10) .delete else if (roll < 20) .retarget else null,
        else => null,
    };
}

/// Builds `/dst` and (if `upper`) `/upper` from `/src` by the changes `seed` chooses. The
/// choices do not depend on `upper`, so the two file systems that call it agree.
fn mutate(fs: *SimFs, seed: u64, upper: bool) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    if (upper) fs.put_dir("/upper", 0o755);
    var gone: Gone = .{};
    const nodes = fs.count;
    var number: u32 = 0;
    var index: u32 = 1;
    while (index < nodes) : (index += 1) {
        const path = fs.alive_path(index) orelse continue;
        if (!std.mem.startsWith(u8, path, "/src/")) continue;
        const rel = path[4..];
        if (gone.covers(rel)) continue;
        const stat = fs.stat_of(path).?;
        const roll = random.uintLessThan(u8, 100);
        const flavour = random.boolean();
        const change = choose(stat.kind, roll) orelse continue;
        number += 1;
        var kept: [48]u8 = undefined;
        if (rel.len > kept.len) continue;
        @memcpy(kept[0..rel.len], rel);
        apply(fs, change, kept[0..rel.len], number, flavour, upper);
        if (change == .delete or change == .opaque_dir) gone.add(kept[0..rel.len]);
    }
    // Names that are new.
    fs.put_file("/dst/added", 0o644, "added");
    if (upper) fs.put_file("/upper/added", 0o644, "added");
}

fn import_tree(target: *layout.Store, path: []const u8) Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    import.import(target, &workspace, path, options, &result, &diag) catch {
        unreachable; // A clean import of a valid tree.
    };
    return result.digest;
}

fn commit(parent: Digest) import.Error!Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null, .parent = parent };
    try import.commit(&store, &workspace, "/upper", options, &result, &diag);
    return result.digest;
}

/// Counts the lines of a diff and remembers the last path, to see that paths are not repeated.
const Counter = struct {
    summary: diff.Summary = .{},
    last: [256]u8 = undefined,
    last_len: u32 = 0,

    fn call(context: *anyopaque, change: *const diff.Change, _: *Diag) bool {
        const self: *Counter = @ptrCast(@alignCast(context));
        assert(change.path.len > 0);
        assert(change.path.len <= self.last.len);
        // Paths come in order, so a repeat could only be the line before.
        const same = std.mem.eql(u8, self.last[0..self.last_len], change.path);
        assert(!same);
        @memcpy(self.last[0..change.path.len], change.path);
        self.last_len = @intCast(change.path.len);
        return true;
    }
};

fn count_diff(a: Digest, b: Digest) diff.Summary {
    var counter: Counter = .{};
    const sink: diff.Sink = .{ .context = &counter, .call = Counter.call };
    var summary: diff.Summary = undefined;
    diag.reset();
    diff.diff(&store, &diff_workspace, &workspace.arena, a, b, sink, &summary, &diag) catch {
        unreachable; // The trees are in the store.
    };
    return summary;
}

fn check_diff(parent: Digest, committed: Digest) void {
    const forward = count_diff(parent, committed);
    const back = count_diff(committed, parent);
    assert(forward.added == back.removed);
    assert(forward.removed == back.added);
    assert(forward.changed == back.changed);
    const none = forward.added + forward.removed + forward.changed == 0;
    assert(none == parent.eql(committed));
    const same = count_diff(committed, committed);
    assert(same.added + same.removed + same.changed == 0);
}

const Fault = enum { none, harmless, fail_point, crash_point };

pub fn fuzz_commit(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const tree_seed = random.int(u64);
    const mutation_seed = random.int(u64);
    const chunk_sizes = [_]u32{ 8, 16, 4096 };
    const chunk_bytes = chunk_sizes[random.uintLessThan(usize, chunk_sizes.len)];

    // The oracle: importing the changed copy in a clean file system.
    sim.init(seed, &.{});
    reference_files.init(seed +% 1);
    reference_files.put_dir("/data", 0o755);
    support.make_store_directories(&reference_files, root_path);
    fuzz_store.build_tree(tree_seed, &reference_files, "/src");
    fuzz_store.build_tree(tree_seed, &reference_files, "/dst");
    mutate(&reference_files, mutation_seed, false);
    sim.store_fs = &reference_files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    const oracle = import_tree(&store, "/dst");

    // The file system under test: the original imported, the layer ready.
    files.init(seed);
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    fuzz_store.build_tree(tree_seed, &files, "/src");
    fuzz_store.build_tree(tree_seed, &files, "/dst");
    mutate(&files, mutation_seed, true);
    sim.store_fs = &files;
    store.at(sim.interface(), root_path);
    store.chunk_bytes = chunk_bytes;
    const parent = import_tree(&store, "/src");
    run_commit(random, parent, oracle, chunk_bytes);
    check_diff(parent, oracle);
}

fn run_commit(random: std.Random, parent: Digest, oracle: Digest, chunk_bytes: u32) void {
    const fault = random.enumValue(Fault);
    switch (fault) {
        .none => {},
        .harmless => {
            files.faults.interrupt_per_mille = random.uintLessThan(u16, 400);
            files.faults.short_read_per_mille = random.uintLessThan(u16, 1000);
            files.faults.short_write_per_mille = random.uintLessThan(u16, 1000);
        },
        .fail_point => files.faults.fail_mutation = files.mutations +
            random.uintLessThan(u32, 24),
        .crash_point => files.faults.crash_mutation = files.mutations +
            random.uintLessThan(u32, 24),
    }
    if (commit(parent)) |digest| {
        assert(digest.eql(oracle));
    } else |_| {
        assert(diag.code != null);
        assert(fault != .none); // Only a fault makes a commit fail.
    }
    files.restart();
    files.faults = .{};
    assert(files.open_count() == 0);
    support.check_whole(&files, root_path, chunk_bytes) catch unreachable; // The property.
    const again = commit(parent) catch unreachable; // Nothing is wrong any more.
    assert(again.eql(oracle));
    support.check_whole(&files, root_path, chunk_bytes) catch unreachable; // The property.
    assert(files.open_count() == 0);
}
