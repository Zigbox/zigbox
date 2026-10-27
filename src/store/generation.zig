//! The store's generation counter: one number in `<store>/generation`, which every operation that
//! writes to the store raises before it starts. A gc plan hashes it together with the ids it
//! would remove, so a plan made before an import, a commit, a root's removal, a restore or
//! another gc can not be confirmed after it: whatever changed, the number did.
//!
//! The file is written atomically like everything else (`write_atomic`). A store without one is
//! at generation 0. Two writers racing on the raise may both write the same number; that is
//! harmless for what the number is for (the ids in the plan changed too), and the store is not
//! built for concurrent writers (docs/demos/m3.md, "Cuts").

const std = @import("std");
const assert = std.debug.assert;
const host_mod = @import("../host.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");

const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const file_name = "generation";

/// The current generation; 0 for a store that has none yet. A file that is not a number is
/// `IoFailed`: the store is damaged, and refusing is safer than starting again from 0.
pub fn read(store: *const Store) host_mod.Error!u64 {
    assert(store.root_len > 1);
    assert(store.root_len > 1);
    var path: PathBuf = undefined;
    var bytes: [32]u8 = undefined;
    const text = store.fs.read_whole(store.path(&path, &.{ "/", file_name }), &bytes) catch |err| {
        if (err == error.NotFound) return 0;
        if (err == error.FileTooLarge) return error.IoFailed;
        return err;
    };
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch error.IoFailed;
}

/// Raises the generation by one.
pub fn bump(store: *Store, failure: *fs_mod.Failure) host_mod.Error!void {
    assert(@intFromPtr(failure) != 0);
    assert(store.root_len > 1);
    const current = read(store) catch |err| return store.fs.note(failure, err);
    var text: [32]u8 = undefined;
    // Cannot fail: a number of at most 20 digits and a newline fit 32 bytes.
    const bytes = std.fmt.bufPrint(&text, "{d}\n", .{current +| 1}) catch unreachable;
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = store.path(&final, &.{ "/", file_name });
    try store.fs.write_atomic(temporary_path, final_path, store.root_text(), bytes, 0o644, failure);
}

const testing = std.testing;
const host_sim = @import("../host_sim.zig");
const fs_sim = @import("fs_sim.zig");

var test_host: host_sim.HostSim = undefined;
var test_files: fs_sim.SimFs = undefined;

test "the generation starts at zero, rises by one, and a damaged file is not read as zero" {
    // Goal: a plan's hash really moves with every write. Method: read, raise twice, damage.
    test_host.init(1, &.{});
    test_files.init(1);
    test_host.store_fs = &test_files;
    test_files.put_dir("/s", 0o755);
    test_files.put_dir("/s/tmp", 0o755);
    var store: Store = undefined;
    store.at(test_host.interface(), "/s");
    var failure: fs_mod.Failure = undefined;
    try testing.expectEqual(@as(u64, 0), try read(&store));
    try bump(&store, &failure);
    try testing.expectEqual(@as(u64, 1), try read(&store));
    try bump(&store, &failure);
    try testing.expectEqual(@as(u64, 2), try read(&store));
    test_files.remove_path("/s/generation");
    test_files.put_file("/s/generation", 0o644, "x\n");
    try testing.expectError(error.IoFailed, read(&store));
    try testing.expectError(error.IoFailed, bump(&store, &failure));
    test_files.remove_path("/s/generation");
    test_files.put_file("/s/generation", 0o644, "99999999999999999999999999\n");
    try testing.expectError(error.IoFailed, read(&store));
}
