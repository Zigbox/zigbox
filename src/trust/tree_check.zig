//! The uncached soundness check of a tree, for `zbx sign` and `zbx verify`: every file object
//! the tree names is checked against its name (`verify.check_object_alone`), because a
//! signature over, or a verdict about, a tree with a missing or damaged file would vouch for
//! something nobody can run. One function, so the two commands cannot drift apart.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const layout = @import("../store/layout.zig");
const verify = @import("../store/verify.zig");
const walk = @import("../store/walk.zig");
const diagnose = @import("diagnose.zig");
const Digest = @import("../store/digest.zig").Digest;

const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

/// What the check works in: a tree object, the walk's stack and `verify`'s scratch.
pub const Work = struct {
    verify: verify.Workspace,
    tree_buffer: [constants.store_tree_bytes_max]u8,
    stack: [constants.image_import_stack_max]Digest,
};

/// Why a tree is not sound: the refusal and the errno (0 when there is none).
pub const Fault = struct { why: diagnose.Refusal, errno: u16 };

/// Checks every file object a tree names, the first damage ending the walk's use.
const Checker = struct {
    store: *const Store,
    ws: *verify.Workspace,
    /// Null while the tree is sound.
    found: ?Fault = null,

    pub fn object(checker: *Checker, ref: *const walk.ObjectRef) void {
        if (checker.found != null) return;
        const fs = checker.store.fs;
        var path: PathBuf = undefined;
        const listed = fs.lstat(checker.store.chunks_path(&path, ref.id));
        if (listed) |_| {
            return checker.check(ref, true);
        } else |err| {
            if (err == error.NotFound) return checker.check(ref, false);
            checker.found = .{ .why = .unreadable, .errno = fs.last_errno() };
        }
    }

    fn check(checker: *Checker, ref: *const walk.ObjectRef, has_list: bool) void {
        if (checker.found != null) return;
        var bytes: u64 = 0;
        const damage = verify.check_object_alone(
            checker.store,
            &checker.ws.scratch,
            ref.id,
            has_list,
            &bytes,
        ) orelse return;
        checker.found = switch (damage.kind) {
            // The walk reports a missing tree itself but not a missing file object, which
            // `check_object_alone` meets as a failed `lstat`.
            .unreadable => if (damage.errno != 0 and
                host_mod.error_for_errno(damage.errno) == error.NotFound)
                .{ .why = .object_missing, .errno = 0 }
            else
                .{ .why = .unreadable, .errno = damage.errno },
            else => .{ .why = .object_damaged, .errno = 0 },
        };
    }
};

/// Walks `tree` and checks each file object; null when the tree is whole and sound.
pub fn check(store: *const Store, work: *Work, tree: Digest) ?Fault {
    assert(store.root_len > 1);
    var checker: Checker = .{ .store = store, .ws = &work.verify };
    var failure: walk.Failure = undefined;
    walk.objects(
        store,
        &work.tree_buffer,
        &work.stack,
        null,
        tree,
        &checker,
        constants.store_walk_entries_max,
        &failure,
    ) catch {
        return switch (failure.kind) {
            .missing => .{ .why = .object_missing, .errno = 0 },
            .damaged => .{ .why = .object_damaged, .errno = 0 },
            .unreadable => .{ .why = .unreadable, .errno = failure.errno },
            .too_many_entries, .stack_full => .{ .why = .too_large, .errno = 0 },
        };
    };
    return checker.found;
}
