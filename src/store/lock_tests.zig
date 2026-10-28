//! Tests of the store lock (`lock.zig`): its semantics on the simulated file system, the race it
//! exists to prevent (an import that reuses an object while a gc moves it away), and, on a real
//! kernel, two processes.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_real = @import("../host_real.zig");
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const gc = @import("gc.zig");
const import = @import("import.zig");
const layout = @import("layout.zig");
const lock = @import("lock.zig");
const roots = @import("roots.zig");
const support = @import("test_support.zig");
const verify = @import("verify.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const Store = layout.Store;

const root_path = "/data/store";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: Store = undefined;
var other: Store = undefined;
var workspace: import.Workspace = undefined;
var gc_workspace: gc.Workspace = undefined;
var gc_tables: [16 * 1024 * 1024]u8 align(8) = @splat(0);
var verify_workspace: verify.Workspace = undefined;
var diag: Diag = undefined;

fn start() void {
    gc_workspace.tables = &gc_tables;
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    other.at(sim.interface(), root_path);
    store.chunk_bytes = 8;
    other.chunk_bytes = 8;
    store.lock_wait_ms = 100;
    other.lock_wait_ms = 100;
    sim.world.now = 1_800_000_000;
    diag.reset();
}

test "shared holds share, an exclusive hold is alone, and a refusal names the holder" {
    // Goal: flock semantics as the store uses them. Method: two Store values (two descriptors,
    // as two processes would have) on one file system.
    start();
    try lock.hold(&store, .shared, "import");
    try lock.hold(&other, .shared, "commit");
    try testing.expectEqual(@as(u32, 2), files.open_count());
    // The writers keep an exclusive taker out; nobody wrote a record, so none is named.
    var third: Store = undefined;
    third.at(sim.interface(), root_path);
    third.lock_wait_ms = 0;
    try testing.expectError(error.Busy, lock.hold(&third, .exclusive, "gc"));
    try testing.expectEqualStrings("", lock.holder(&third));
    lock.release(&store);
    lock.release(&other);
    try lock.hold(&third, .exclusive, "gc");
    // An exclusive holder keeps shared takers out, and its record is named: pid and command.
    try testing.expectError(error.Busy, lock.hold(&store, .shared, "import"));
    var expected: [32]u8 = undefined;
    const want = try std.fmt.bufPrint(&expected, "{d} gc", .{sim.interface().own_pid()});
    try testing.expectEqualStrings(want, lock.holder(&store));
    try testing.expectError(error.Busy, lock.hold(&other, .exclusive, "restore"));
    try testing.expectEqualStrings(want, lock.holder(&other));
    lock.release(&third);
    try lock.hold(&store, .shared, "import");
    // The record of a finished exclusive holder is not named for shared holders that block.
    try testing.expectError(error.Busy, lock.hold(&other, .exclusive, "restore"));
    try testing.expectEqualStrings("", lock.holder(&other));
    lock.release(&store);
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "holds nest, a wait is bounded in time, and a crash frees the lock" {
    start();
    try lock.hold(&store, .exclusive, "gc");
    try lock.hold(&store, .shared, "import"); // Inside the same operation: counted.
    try testing.expectEqual(@as(u32, 2), store.lock_depth);
    try testing.expectEqual(@as(u32, 1), files.open_count());
    lock.release(&store);
    try testing.expectEqual(@as(u32, 1), files.open_count());
    // Another process waits 100 ms in 20 ms steps and gives up; the clock moved by about that.
    const began = sim.world.now_ms;
    try testing.expectError(error.Busy, lock.hold(&other, .shared, "import"));
    const waited = sim.world.now_ms - began;
    try testing.expect(waited >= 100 and waited < 140);
    // The machine dies: every descriptor goes, and with them the lock.
    files.restart();
    store.lock_depth = 0;
    try lock.hold(&other, .shared, "import");
    lock.release(&other);
}

test "an unusable lock file is a failure of the file system, not a busy store" {
    start();
    store.lock_wait_ms = 0;
    // A directory where the file belongs.
    files.put_dir(root_path ++ "/lock", 0o755);
    try testing.expectError(error.Failed, lock.hold(&store, .shared, "import"));
    try testing.expect(store.lock_error != error.WouldBlock);
}

var race_ran: bool = false;
var race_error: ?gc.ApplyError = null;
var race_failure: gc.Failure = undefined;

/// What a second zbx would do at that moment: read the plan as the store is, and confirm it.
fn gc_in_the_middle(context: *anyopaque) void {
    _ = context;
    race_ran = true;
    other.lock_wait_ms = 60;
    var planned: gc.Plan = undefined;
    gc.plan(&other, &gc_workspace, &workspace.arena, &.{}, &planned, &race_failure) catch {
        unreachable; // A plan reads and takes no lock.
    };
    assert(planned.counts.total() > 0); // The reused objects look dead: no root names them yet.
    var applied: gc.Applied = undefined;
    gc.apply(
        &other,
        &gc_workspace,
        &workspace.arena,
        &.{},
        planned.hash,
        &applied,
        &race_failure,
    ) catch |err| {
        race_error = err;
    };
}

fn import_source() !Digest {
    var result: import.Result = undefined;
    diag.reset();
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &workspace, "/src", options, &result, &diag);
    return result.digest;
}

fn verify_totals() verify.Totals {
    var totals: verify.Totals = undefined;
    var failure: verify.Failure = undefined;
    verify.verify(&store, &verify_workspace, &workspace.arena, &totals, &failure) catch {
        unreachable; // The simulated store lists.
    };
    return totals;
}

test "a gc cannot move what an import is reusing: without the lock this tree names nothing" {
    // Goal: the race the lock closes. A tree is imported and its root dropped, so every object
    // and tree is there and unreachable. The same directory is imported again, which reuses all
    // of them; just before the new root record is written, a second program makes a plan (the
    // reused things look dead: no root names them yet) and confirms it. Without the lock the
    // apply moves them all to the trash and the import then records a root whose tree is gone;
    // with it the apply finds the store busy, changes nothing, and verify is clean.
    start();
    support.make_source(&files, 0);
    const first = try import_source();
    try roots.remove(&store, first);
    race_ran = false;
    race_error = null;
    files.hook = .{
        .rename_to_contains = "/roots/",
        .context = &race_ran,
        .call = gc_in_the_middle,
    };
    const second = try import_source();
    try testing.expect(race_ran);
    try testing.expect(second.eql(first));
    try testing.expectEqual(@as(?gc.ApplyError, error.Failed), race_error);
    try testing.expectEqualStrings("applying the gc plan", race_failure.busy);
    const totals = verify_totals();
    try testing.expectEqual(@as(u64, 0), totals.damaged);
    try testing.expectEqual(@as(u64, 1), totals.roots);
    try support.check_whole(&files, root_path, store.chunk_bytes);
    // And a gc after the import sees the tree as kept.
    var planned: gc.Plan = undefined;
    var failure: gc.Failure = undefined;
    try gc.plan(&store, &gc_workspace, &workspace.arena, &.{}, &planned, &failure);
    try testing.expectEqual(@as(u64, 0), planned.counts.total());
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "a restore waits for writers like a gc, and gives up with a name for what it waited on" {
    start();
    support.make_source(&files, 0);
    _ = try import_source();
    try lock.hold(&other, .shared, "commit");
    var restored: gc.Restored = undefined;
    var failure: gc.Failure = undefined;
    const id = "aaaaaaaaaaaa".*;
    const result = gc.restore(&store, &gc_workspace, &workspace.arena, id, &restored, &failure);
    try testing.expectError(error.Failed, result);
    try testing.expectEqualStrings("restoring a trash", failure.busy);
    lock.release(&other);
    try testing.expectError(
        error.NoSuchTrash,
        gc.restore(&store, &gc_workspace, &workspace.arena, "aaaaaaaaaaaa".*, &restored, &failure),
    );
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

// ---- Two processes on a real kernel -------------------------------------------------------

fn raw_ok(result: usize) bool {
    return linux.errno(result) == .SUCCESS;
}

test "two real processes: an exclusive holder keeps a shared taker out until it ends" {
    // Goal: flock between processes, which the simulator only models. Method: a child takes
    // the exclusive lock on a store in /tmp, says so through a pipe, and keeps it until the
    // parent closes the other pipe. The parent, with a short wait, is refused and told the
    // child's pid and command; once the child is gone the parent gets the lock.
    var real: host_real.HostReal = .{};
    const subject = real.interface();
    var path_storage: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&path_storage, "/tmp/zbx-lock-test-{d}", .{linux.getpid()});
    path_storage[text.len] = 0;
    const directory: [:0]const u8 = path_storage[0..text.len :0];
    const fs = subject.filesystem();
    try fs.make_directory(directory, true);
    defer {
        var lock_file: [96:0]u8 = @splat(0);
        const written = std.fmt.bufPrint(&lock_file, "{s}/lock", .{directory}) catch "";
        if (written.len > 0) fs.unlink(lock_file[0..written.len :0]) catch {};
        fs.remove_directory(directory) catch {};
    }
    var ready: [2]i32 = undefined;
    var release: [2]i32 = undefined;
    try testing.expect(raw_ok(linux.pipe2(&ready, .{ .CLOEXEC = true })));
    try testing.expect(raw_ok(linux.pipe2(&release, .{ .CLOEXEC = true })));
    const forked = linux.fork();
    try testing.expect(raw_ok(forked));
    if (forked == 0) child(subject, directory, ready, release);
    const child_pid: i32 = @intCast(forked);
    _ = linux.close(ready[1]);
    _ = linux.close(release[0]);
    var byte: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), linux.read(ready[0], &byte, 1));
    try testing.expectEqual(@as(u8, 'k'), byte[0]);

    var parent: Store = undefined;
    parent.at(subject, directory);
    parent.lock_wait_ms = 100;
    try testing.expectError(error.Busy, lock.hold(&parent, .shared, "import"));
    var expected: [32]u8 = undefined;
    const want = try std.fmt.bufPrint(&expected, "{d} gc", .{child_pid});
    try testing.expectEqualStrings(want, lock.holder(&parent));

    _ = linux.close(release[1]); // The child reads the end of file and exits.
    var status: i32 = 0;
    try testing.expectEqual(@as(usize, @intCast(child_pid)), linux.waitpid(child_pid, &status, 0));
    try testing.expectEqual(@as(i32, 0), status); // Exited with 0.
    try lock.hold(&parent, .shared, "import");
    lock.release(&parent);
    _ = linux.close(ready[0]);
    try testing.expectEqual(@as(u32, 0), real.open_count);
}

/// The child: take the exclusive lock, tell the parent, wait for its release, leave. It never
/// returns into the test framework.
fn child(
    subject: @import("../host.zig").Host,
    directory: [:0]const u8,
    ready: [2]i32,
    release: [2]i32,
) noreturn {
    // Only its own ends: a copy of the release pipe's write end would keep the wait for ever.
    _ = linux.close(ready[0]);
    _ = linux.close(release[1]);
    const tell = ready[1];
    const wait = release[0];
    var held: Store = undefined;
    held.at(subject, directory);
    held.lock_wait_ms = 0;
    lock.hold(&held, .exclusive, "gc") catch linux.exit_group(1);
    _ = linux.write(tell, "k", 1);
    var byte: [1]u8 = undefined;
    _ = linux.read(wait, &byte, 1);
    linux.exit_group(0);
}
