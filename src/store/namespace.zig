//! The child that does the store's work. Every operation on the store (import, listing,
//! verifying, collecting, materializing) runs in a single-threaded child inside the user's
//! user namespace, mapped the way `zbx run --rootfs` maps it: with the full range of subordinate
//! ids when this host has the ranges and the helpers, the user as root and the range as ids 1
//! and up; otherwise (ZBX-W0201) only the user, as root. So `chown` of an object to a
//! container id works, a file readable only by a subordinate id can be read, and every id the
//! store records is the one a container sees.
//!
//! The parent here only waits. It makes the child with `clone3` (new user namespace only), writes
//! the id maps (itself for the one-id map, through `newuidmap` and `newgidmap` for the full one),
//! lets the child go with one byte, and reaps it. The child's exit code is the command's: it
//! writes its own result to stdout and its own diagnostics to stderr, since it inherited both,
//! and the parent passes the code on. A child that is killed, or that cannot be set up, is
//! ZBX-E0419 in the parent.
//!
//! Single-threaded, as docs/SPEC.md requires of everything that makes a namespace: the caller is
//! a program with one thread, or a thread that is the only one using this process's host.
//!
//! ## For Zigcube (Z6)
//!
//! A program that writes the store (a fetch worker: `put_chunk`, `put_tree`, `import_image`)
//! calls `run` itself and does all of one batch of writes in the `Work` it passes (`call` returns
//! an exit code), with a `doctor.Facts` it owns.
//!
//! - **Owner.** Only the tree import, `store/import.zig`'s `Options.squash_owner`, takes an
//!   owner: set it from the `squash_owner` argument of `call`, since a host with the one-id map
//!   records every owner as 0. `put_chunk`, `put_tree` and `import_image` take no owner: the ids
//!   they store come from the file system they run on, which inside `run` is the mapped one.
//! - **One process, one thread, one batch.** `run` makes its child with `clone3`, and a
//!   namespace may only be made by a single-threaded process. So each batch of store writes
//!   needs a fresh process that has started no thread: start the worker by re-exec (a new
//!   `zbx` or agent process), never by `fork` from a multi-threaded parent, and call `run` from
//!   its main thread before any pool exists. The cost is one `clone3` and one id map (a
//!   `newuidmap` and `newgidmap` run on a host with the subordinate ranges) for every `run`.
//!   A worker that needs many writes does them all in one `Work`.
//! - **Results.** The child is a copy of the parent, so what it sets in memory is not seen by
//!   the parent. It returns an exit code, what it wrote to the store (the parent reads that
//!   afterwards) or bytes through a pipe the caller made before `run` (handles are inherited):
//!
//!   ```zig
//!   const pipe = try host.pipe();                  // before `run`, in the parent
//!   // in `call`, in the child:  host.write_handle_all(pipe.write, &digest.bytes) catch return 1;
//!   const code = try run(host, &facts, work, null, &diag);
//!   host.close(pipe.write);                        // the parent's copy, so read sees the end
//!   const count = try host.read_some(pipe.read, &buffer); // the child's bytes (0 if none)
//!   host.close(pipe.read);
//!   ```
//!
//! - **Reading outside.** A reader that cannot enter the namespace (Zigcube's peer server, which
//!   has threads) sees host ids. Before its first `read_chunk` it sets
//!   `store.owners = .{ .outside = outside_owners(host, &facts).map }`, so the owner of a one-chunk
//!   object is mapped back to the container's ids its id commits to
//!   (`decisions/2026-11-04-z9-chunk-read-outside.md`).
//!
//! There is no long-lived store process: a second call to `run` is a second child.
//! `decisions/2026-11-04-z6-store-namespace.md` gives the reasons.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const ids = @import("../runtime/ids.zig");
const plan_mod = @import("../runtime/plan.zig");
const diagnose = @import("diagnose.zig");
const owners_mod = @import("owners.zig");

const Host = host_mod.Host;

pub const Error = error{Failed};

/// What the child does once its namespace is set up. `call` returns the child's exit code.
pub const Work = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, squash_owner: bool) u8,
};

/// Tells the caller of `run` about a warning (the one-id map).
pub const Warn = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, diag: *const Diag) void,
};

/// The store's id map seen from the host, for a reader outside the namespace (Zigcube's peer
/// server: `store.owners = .{ .outside = outside_owners(host, &facts).map }`). It is the map
/// `run` would write now, from the same choice, so the two cannot disagree. `fallback` is the
/// W0201 case: the choice fell back to the one-id map (range moved, or `newuidmap`/`newgidmap`
/// missing or not setuid), so only objects owned by container root verify; the caller may log it.
pub fn outside_owners(host: Host, facts: *doctor.Facts) Outside {
    var choice: ids.Choice = undefined;
    ids.choose(host, facts, &choice);
    const map: owners_mod.Map = .{
        .uid = host.uid(),
        .gid = host.gid(),
        .range = switch (choice.mapping) {
            .single => null,
            .full => |helpers| .{
                .uid_start = helpers.uid_start,
                .gid_start = helpers.gid_start,
            },
        },
    };
    if (choice.mapping == .single) assert(map.range == null);
    if (choice.mapping == .full) assert(map.range != null);
    assert(choice.warned == (choice.mapping == .single));
    return .{ .map = map, .fallback = choice.warned };
}

pub const Outside = struct {
    map: owners_mod.Map,
    fallback: bool,
};

const go_ahead: u8 = 1;
const setup_failed: u8 = constants.child_exit_setup_failed;

const ChildContext = struct {
    host: Host,
    ready: host_mod.Pipe,
    work: Work,
    squash_owner: bool,
};

/// The body of the child: wait for the id maps, then do the work.
fn child_entry(context: *anyopaque) u8 {
    const child: *const ChildContext = @ptrCast(@alignCast(context));
    const host = child.host;
    host.close(child.ready.write);
    // If the parent dies the child must not go on writing to the store alone.
    host.die_with_parent() catch return setup_failed;
    var byte: [1]u8 = undefined;
    const count = host.read_some(child.ready.read, &byte) catch return setup_failed;
    host.close(child.ready.read);
    if (count == 0) return setup_failed; // The parent gave up.
    assert(byte[0] == go_ahead);
    const code = child.work.call(child.work.context, child.squash_owner);
    assert(code != setup_failed); // A command's own code never collides with the setup's.
    return code;
}

/// Runs `work` in the namespace and returns its exit code, or fails with E0419 in `diag`.
pub fn run(
    host: Host,
    facts: *doctor.Facts,
    work: Work,
    warn: ?Warn,
    diag: *Diag,
) Error!u8 {
    assert(@intFromPtr(work.context) != 0);
    assert(diag.code == null);
    var choice: ids.Choice = undefined;
    ids.choose(host, facts, &choice);
    if (choice.warned) {
        if (warn) |sink| sink.call(sink.context, &choice.warning);
    }
    const ready = host.pipe() catch |err| return setup_error(host, diag, "pipe", err);
    var child: ChildContext = .{
        .host = host,
        .ready = ready,
        .work = work,
        .squash_owner = choice.mapping == .single,
    };
    const flags: host_mod.SpawnFlags = .{
        .user = true,
        .mount = false,
        .pid = false,
        .uts = false,
        .ipc = false,
        .net = false,
    };
    const pid = host.spawn(flags, child_entry, &child) catch |err| {
        host.close(ready.read);
        host.close(ready.write);
        return setup_error(host, diag, "clone3(CLONE_NEWUSER)", err);
    };
    // The child has its own copy of the read end; ours closed, end of file reaches it if we die.
    host.close(ready.read);
    host.ignore_broken_pipe(true);
    defer host.ignore_broken_pipe(false);
    release(host, pid, ready.write, choice.mapping, diag) catch {
        abandon(host, pid, ready.write);
        return error.Failed;
    };
    const status = host.wait_for(pid) catch |err| return setup_error(host, diag, "wait", err);
    switch (status) {
        .exited => |code| {
            if (code == setup_failed) {
                diagnose.worker_ended(diag, .{ .step = .{
                    .name = "setting up the store worker",
                    .err = error.IoFailed,
                    .errno = 0,
                } });
                return error.Failed;
            }
            return code;
        },
        .signaled => |number| {
            diagnose.worker_ended(diag, .{ .signaled = number });
            return error.Failed;
        },
    }
}

fn setup_error(host: Host, diag: *Diag, name: []const u8, err: host_mod.Error) Error {
    assert(name.len > 0);
    assert(diag.code == null);
    diagnose.worker_ended(diag, .{ .step = .{
        .name = name,
        .err = err,
        .errno = host.last_errno(),
    } });
    return error.Failed;
}

/// Writes the id maps and lets the child go. A failure is already in `diag`.
fn release(
    host: Host,
    pid: host_mod.Pid,
    ready_write: host_mod.Handle,
    mapping: plan_mod.Mapping,
    diag: *Diag,
) Error!void {
    assert(pid > 0);
    assert(diag.code == null);
    const uid = host.uid();
    const gid = host.gid();
    switch (mapping) {
        .single => try write_single(host, pid, uid, gid, diag),
        .full => |helpers| try write_full(host, pid, uid, gid, helpers, diag),
    }
    const byte = [1]u8{go_ahead};
    host.write_handle_all(ready_write, &byte) catch |err| {
        return setup_error(host, diag, "releasing the store worker", err);
    };
    host.close(ready_write);
}

/// The one-id map: setgroups denied (an unprivileged writer may not map groups otherwise), then
/// the group and user map, each written whole by the parent.
fn write_single(host: Host, pid: host_mod.Pid, uid: u32, gid: u32, diag: *Diag) Error!void {
    assert(pid > 0);
    assert(diag.code == null);
    var line: [constants.id_map_line_bytes_max]u8 = undefined;
    host.write_id_map(pid, .setgroups, "deny") catch |err| {
        return setup_error(host, diag, "writing setgroups", err);
    };
    // Cannot fail: "0 4294967295 1\n" is 15 bytes and the buffer is 32.
    const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{gid}) catch unreachable; // Same bound.
    host.write_id_map(pid, .gid_map, gid_line) catch |err| {
        return setup_error(host, diag, "writing gid_map", err);
    };
    const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{uid}) catch unreachable; // Same bound.
    host.write_id_map(pid, .uid_map, uid_line) catch |err| {
        return setup_error(host, diag, "writing uid_map", err);
    };
}

fn write_full(
    host: Host,
    pid: host_mod.Pid,
    uid: u32,
    gid: u32,
    helpers: plan_mod.Helpers,
    diag: *Diag,
) Error!void {
    assert(pid > 0);
    assert(helpers.newuidmap.len > 0);
    var words: [constants.helper_map_bytes_max]u8 = undefined;
    const range = constants.subid_range_min;
    // Cannot fail: six numbers of at most ten digits and the spaces fit 64 bytes.
    const uid_words = std.fmt.bufPrint(&words, "0 {d} 1 1 {d} {d}", .{
        uid, helpers.uid_start, range,
    }) catch unreachable; // Same bound.
    try run_helper(host, helpers.newuidmap, pid, uid_words, diag);
    const gid_words = std.fmt.bufPrint(&words, "0 {d} 1 1 {d} {d}", .{
        gid, helpers.gid_start, range,
    }) catch unreachable; // Same bound.
    try run_helper(host, helpers.newgidmap, pid, gid_words, diag);
}

/// Runs `newuidmap` or `newgidmap`: its name, the child's pid and the map's words.
fn run_helper(
    host: Host,
    path: []const u8,
    pid: host_mod.Pid,
    words_text: []const u8,
    diag: *Diag,
) Error!void {
    assert(path.len > 0);
    assert(words_text.len > 0);
    var path_storage: [constants.state_path_bytes_max]u8 = undefined;
    if (path.len >= path_storage.len) return setup_error(host, diag, path, error.PathTooLong);
    @memcpy(path_storage[0..path.len], path);
    path_storage[path.len] = 0;
    const path_z: [:0]const u8 = path_storage[0..path.len :0];
    var storage: [constants.helper_map_bytes_max + 16]u8 = undefined;
    var argv: [constants.helper_words_max]?[*:0]const u8 = undefined;
    const base = std.fs.path.basename(path);
    argv[0] = @ptrCast(path_z.ptr + (path.len - base.len));
    // Cannot fail: a pid has at most ten digits and the storage holds 16 bytes more.
    const pid_text = std.fmt.bufPrint(&storage, "{d}", .{pid}) catch unreachable; // Same bound.
    storage[pid_text.len] = 0;
    argv[1] = @ptrCast(&storage[0]);
    var used: usize = pid_text.len + 1;
    var count: usize = 2;
    var words = std.mem.splitScalar(u8, words_text, ' ');
    while (words.next()) |word| {
        assert(word.len > 0);
        assert(count + 1 < argv.len);
        @memcpy(storage[used..][0..word.len], word);
        storage[used + word.len] = 0;
        argv[count] = @ptrCast(&storage[used]);
        count += 1;
        used += word.len + 1;
    }
    argv[count] = null;
    const none = [_:null]?[*:0]const u8{};
    var output: [constants.helper_output_bytes_max]u8 = undefined;
    const result = host.run_helper(.{
        .path = path_z,
        .argv = @ptrCast(&argv),
        .envp = &none,
    }, &output) catch |err| return setup_error(host, diag, path, err);
    switch (result.status) {
        .exited => |code| if (code == 0) return,
        .signaled => {},
    }
    diagnose.worker_ended(diag, .{ .helper = .{
        .name = base,
        .status = result.status,
        .output = output[0..result.output_len],
    } });
    return error.Failed;
}

/// A step failed after the child was made: it is killed and reaped, and the pipe closed.
fn abandon(host: Host, pid: host_mod.Pid, ready_write: host_mod.Handle) void {
    assert(pid > 0);
    assert(pid != host.own_pid());
    host.signal(pid, constants.signal_kill) catch {}; // It may be gone already.
    _ = host.wait_for(pid) catch {}; // Nothing more can be done about a wait that fails.
    host.close(ready_write);
}

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const sim_run = @import("../runtime/sim_run.zig");

var test_facts: doctor.Facts = undefined;

/// A piece of work that records how it was called and returns the code it was given.
const Probe = struct {
    code: u8,
    calls: u32 = 0,
    squash: bool = false,

    fn call(context: *anyopaque, squash_owner: bool) u8 {
        const probe: *Probe = @ptrCast(@alignCast(context));
        probe.calls += 1;
        probe.squash = squash_owner;
        return probe.code;
    }

    fn work(probe: *Probe) Work {
        return .{ .context = probe, .call = call };
    }
};

test "the work runs once, after the maps, and its exit code is the result" {
    // Goal: the child's contract on a host that maps a full range. Method: a probe that returns
    // 7; the simulator's rules (setgroups before gid_map, one write of each map) are enforced by
    // the helpers' model, so a run that gets this far wrote them in order.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    var probe: Probe = .{ .code = 7 };
    var diag: Diag = undefined;
    diag.reset();
    const code = try run(sim.interface(), &test_facts, probe.work(), null, &diag);
    try testing.expectEqual(@as(u8, 7), code);
    try testing.expectEqual(@as(u32, 1), probe.calls);
    try testing.expect(!probe.squash);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a host that can map one id only tells the work to record every owner as 0, and warns" {
    // Goal: W0201 reaches the caller and the work learns the map. Method: the single-id host.
    var sim: HostSim = undefined;
    sim_run.init_single(&sim, 1);
    var probe: Probe = .{ .code = 0 };
    var warned: u32 = 0;
    const Sink = struct {
        fn call(context: *anyopaque, warning: *const Diag) void {
            const count: *u32 = @ptrCast(@alignCast(context));
            count.* += 1;
            std.debug.assert(warning.code.? == .W0201);
        }
    };
    var diag: Diag = undefined;
    diag.reset();
    const sink: Warn = .{ .context = &warned, .call = Sink.call };
    const code = try run(sim.interface(), &test_facts, probe.work(), sink, &diag);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(probe.squash);
    try testing.expectEqual(@as(u32, 1), warned);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "the map a reader outside sees is the one run writes: the range, or the user's ids only" {
    // Goal: `outside_owners` and `run` make the same choice. Method: the host with a range
    // (alice, 1000, range at 100000) and the single-id host; the map's ids are the host's.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    const full = outside_owners(sim.interface(), &test_facts).map;
    try testing.expect(!outside_owners(sim.interface(), &test_facts).fallback);
    try testing.expectEqual(@as(u32, 1000), full.uid);
    try testing.expectEqual(@as(u32, 1000), full.gid);
    try testing.expectEqual(@as(u32, 100000), full.range.?.uid_start);
    try testing.expectEqual(@as(u32, 100000), full.range.?.gid_start);
    sim_run.init_single(&sim, 1);
    const single_outside = outside_owners(sim.interface(), &test_facts);
    try testing.expect(single_outside.fallback);
    const single = single_outside.map;
    try testing.expectEqual(@as(u32, 1000), single.uid);
    try testing.expectEqual(@as(?owners_mod.Range, null), single.range);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a helper that refuses the map is E0419, the child is reaped, and nothing runs" {
    // Goal: a failed setup never runs the work and leaks nothing. Method: newuidmap exits 1.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    sim.world.helper_fails_with = 1;
    var probe: Probe = .{ .code = 0 };
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(
        error.Failed,
        run(sim.interface(), &test_facts, probe.work(), null, &diag),
    );
    try testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0419), diag.code);
    try testing.expectEqual(@as(u32, 0), probe.calls);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    try testing.expectEqual(@as(u32, 0), sim.world.unreaped_children());
}

const image_peer = @import("image_peer.zig");
const images = @import("images.zig");
const layout = @import("layout.zig");
const store_support = @import("test_support.zig");
const trees = @import("trees.zig");
const tree_mod = @import("tree.zig");
const fs_sim = @import("fs_sim.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

var store_files: fs_sim.SimFs = undefined;
var store_memory: image_peer.Memory = undefined;

/// Work that writes the store in the child: a tree, then an image record for it.
const StoreWork = struct {
    store: *layout.Store,
    tree: *const @import("digest.zig").Digest,
    bytes: []const u8,
    text: []const u8,
    squash: bool = false,

    fn call(context: *anyopaque, squash_owner: bool) u8 {
        const job: *StoreWork = @ptrCast(@alignCast(context));
        job.squash = squash_owner;
        var failure: @import("object.zig").Failure = undefined;
        _ = trees.put_checked(job.store, job.tree.*, job.bytes, &failure) catch return 1;
        var refusal: image_peer.Failure = undefined;
        const options: image_peer.Options = .{
            .expected_manifest = Sha256.of("manifest"),
            .tags = .drop,
            .entries_max = 16,
        };
        const text = job.text;
        const memory = &store_memory;
        const tree = job.tree.*;
        const taken = image_peer.import_record(job.store, memory, text, tree, options, &refusal);
        _ = taken catch return 2;
        return 0;
    }
};

test "store writes done in the child are in the store the parent reads afterwards" {
    // Goal: the API shape of Z6: a `Work` that writes the store compiles against `run`, gets
    // its `squash_owner`, and its writes are readable by the caller. Method: a fetch-worker-like
    // `Work` puts a tree and imports an image record for it inside `run`; the parent then finds
    // both through the same store. This does NOT prove isolation: the simulated host runs the
    // child in this process, sharing memory, so a missing child would pass too. The real
    // `clone3` and id maps are what the VM demos run.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    store_files.init(1);
    sim.store_fs = &store_files;
    store_files.put_dir("/data", 0o755);
    store_support.make_store_directories(&store_files, "/data/store");
    var store: layout.Store = undefined;
    store.at(sim.interface(), "/data/store");
    var bytes: [64]u8 = undefined;
    var writer = tree_mod.Writer.init(&bytes);
    const empty = writer.finish();
    const whole = @import("digest.zig").Digest.of(empty);
    var image: images.Image = undefined;
    image.tag_count = 0;
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = whole;
    image.time = 1;
    image.layer_count = 0;
    image.settings.clear();
    var text: [constants.image_record_bytes_max]u8 = undefined;
    var job: StoreWork = .{
        .store = &store,
        .tree = &whole,
        .bytes = empty,
        .text = images.render(&image, &text),
    };
    var diag: Diag = undefined;
    diag.reset();
    const work: Work = .{ .context = &job, .call = StoreWork.call };
    const code = try run(sim.interface(), &test_facts, work, null, &diag);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(!job.squash);
    try testing.expect(try trees.has(&store, whole));
    var loaded: images.Image = undefined;
    var errno: u16 = 0;
    try images.load(&store, image.manifest, &loaded, &errno);
    try testing.expect(loaded.tree.eql(whole));
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}
