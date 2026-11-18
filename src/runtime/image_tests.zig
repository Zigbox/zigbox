//! Tests of a run of a tree from the store against the simulator: the digest or prefix is
//! resolved, the tree is materialized in the store's child, the container gets its directory,
//! and the plan mounts the overlay. The real kernel's agreement is the VM check
//! (docs/demos/m3.md); these show the code does what the plan says and refuses what it must.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const lazy_mod = @import("../lazy/lazy.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const digest_mod = @import("../store/digest.zig");
const fs_sim = @import("../store/fs_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const open = @import("../store/open.zig");
const support = @import("../store/test_support.zig");
const image = @import("image.zig");
const records = @import("records.zig");
const lib = @import("run.zig");
const sim_run = @import("sim_run.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const HostSim = host_sim.HostSim;

var sim: HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_ws: import.Workspace = undefined;
var image_ws: image.Workspace = undefined;

const state = "/home/alice/.local/state/zbx/containers";

/// A host with a store that holds the sample tree; returns its digest.
fn setup(seed: u64) !Digest {
    sim_run.init(&sim, seed);
    files.init(seed);
    sim.store_fs = &files;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), support.user_store);
    var result: import.Result = undefined;
    var diag: Diag = undefined;
    diag.reset();
    try import.import(
        &store,
        &import_ws,
        "/src",
        .{ .squash_owner = false, .warn = null },
        &result,
        &diag,
    );
    return result.digest;
}

/// The merged directory in the container model, with what the overlay would show of the tree:
/// the model's file system is not the store's, so the shell the command runs is put here.
fn world_dirs(name: []const u8) void {
    var path: [200]u8 = undefined;
    var inner: [220]u8 = undefined;
    const merged = std.fmt.bufPrint(
        &path,
        state ++ "/{s}/merged",
        .{name},
    ) catch unreachable; // Short.
    sim.world.add_node(merged, .dir);
    var net_path: [220]u8 = undefined;
    const net_format = state ++ "/{s}/net";
    const net = std.fmt.bufPrint(&net_path, net_format, .{name}) catch unreachable; // Short.
    sim.world.add_node(net, .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        const text = std.fmt.bufPrint(
            &inner,
            "{s}{s}",
            .{ merged, suffix },
        ) catch unreachable; // Short.
        sim.world.add_node(text, .dir);
    }
    const shell = std.fmt.bufPrint(&inner, "{s}/bin/sh", .{merged}) catch unreachable; // Short.
    sim.world.add_node(shell, .file);
    // The overlay shows the mount points of the generated files, which are in the net layer.
    for ([_][]const u8{ "/etc/hosts", "/etc/resolv.conf", "/etc/hostname" }) |suffix| {
        const joined = std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix });
        sim.world.add_node(joined catch unreachable, .file); // Short.
    }
}

fn spec_for(digest_text: []const u8, name: []const u8, read_only: bool) lib.Spec {
    return .{
        .image = digest_text,
        .name = name,
        .command = &.{ "/bin/sh", "-c", "true" },
        .read_only = read_only,
    };
}

fn start(spec: *const lib.Spec, started: *lib.Handle, diag: *Diag) !void {
    diag.reset();
    try lib.start(sim.interface(), spec, .{ .image_workspace = &image_ws }, started, diag);
}

var handle: lib.Handle = undefined;

test "a run by digest materializes the tree, makes the container's layers and mounts the overlay" {
    // Goal: the whole path. Method: run by a 12-digit prefix; the farm is in the cache, the
    // container has merged, upper and work with the tree's root attributes on the upper, the
    // child's mount table has an overlay at merged whose data names the farm as lower, and the
    // record keeps the tree and the upper.
    const digest = try setup(1);
    files.set_mode_of("/src", 0o711); // Not the sample's: it is imported after this change.
    var result: import.Result = undefined;
    var diag: Diag = undefined;
    diag.reset();
    try import.import(
        &store,
        &import_ws,
        "/src",
        .{ .squash_owner = false, .warn = null },
        &result,
        &diag,
    );
    const tree = result.digest;
    try testing.expect(!tree.eql(digest));
    world_dirs("img-1");
    const text = tree.text();
    const spec = spec_for(text[3..15], "img-1", false);
    try start(&spec, &handle, &diag);
    try testing.expectEqual(lib.Status.running, lib.inspect(&handle));
    // The farm and the layers.
    const hex = tree.hex();
    var farm: [200]u8 = undefined;
    const cache = std.fmt.bufPrint(
        &farm,
        support.user_store ++ "/cache/{s}",
        .{&hex},
    ) catch unreachable; // Short.
    try testing.expect(files.kind_of(cache) == .dir);
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/img-1/merged"),
    );
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/img-1/work"),
    );
    const upper = files.stat_of(state ++ "/img-1/upper").?;
    try testing.expectEqual(@as(u16, 0o711), upper.mode);
    // The overlay, mounted by the container's child where the rootfs would have been bound.
    const child = &sim.world.processes[1];
    const table = &sim.world.tables[child.table];
    try testing.expect(table.has(.overlay, state ++ "/img-1/merged"));
    try testing.expect(!table.has(.bind_tree, state ++ "/img-1/merged"));
    // The record.
    var parsed: records.Parsed = undefined;
    const record = sim.world.read_written(sim_run.runs_path ++ "/img-1.zon").?;
    try records.parse(record, &parsed);
    try testing.expectEqualStrings(&text, parsed.tree_slice());
    try testing.expectEqualStrings(state ++ "/img-1/upper", parsed.upper_slice());
    _ = lib.wait(&handle);
    // The layers outlive the container: `commit` needs them after exit.
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/img-1/upper"),
    );
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "the net layer's etc says what the tree's etc says" {
    // Goal: the net layer is the top lower layer, so its etc shows through for /etc. Method:
    // a tree whose /etc is 0750 and owned by 5:6; after the run's preparation the layer's etc
    // has that mode and owner and the tree's time.
    const known = try setup(1);
    _ = known;
    files.set_mode_of("/src/etc", 0o750);
    files.set_owner_of("/src/etc", 5, 6);
    var result: import.Result = undefined;
    var diag: Diag = undefined;
    diag.reset();
    try import.import(
        &store,
        &import_ws,
        "/src",
        .{ .squash_owner = false, .warn = null },
        &result,
        &diag,
    );
    world_dirs("img-etc");
    const text = result.digest.text();
    const spec = spec_for(text[3..15], "img-etc", false);
    try start(&spec, &handle, &diag);
    const layer = files.stat_of(state ++ "/img-etc/net/etc").?;
    try testing.expectEqual(@as(u16, 0o750), layer.mode);
    try testing.expectEqual(@as(u32, 5), layer.uid);
    try testing.expectEqual(@as(u32, 6), layer.gid);
    _ = lib.wait(&handle);
}

test "a read-only run has no upper layer and no work directory" {
    // Goal: `--read-only` with a digest is an overlay without an upper. Method: the container's
    // directory has merged and empty only, and the record has no upper.
    const digest = try setup(2);
    world_dirs("img-ro");
    var diag: Diag = undefined;
    const text = digest.text();
    const spec = spec_for(&text, "img-ro", true);
    try start(&spec, &handle, &diag);
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/img-ro/empty"),
    );
    try testing.expect(files.kind_of(state ++ "/img-ro/upper") == null);
    try testing.expect(files.kind_of(state ++ "/img-ro/work") == null);
    var parsed: records.Parsed = undefined;
    try records.parse(sim.world.read_written(sim_run.runs_path ++ "/img-ro.zon").?, &parsed);
    try testing.expectEqual(@as(usize, 0), parsed.upper_slice().len);
    try testing.expectEqualStrings(&text, parsed.tree_slice());
    _ = lib.wait(&handle);
}

test "a digest the store lacks is E0410 before anything is created" {
    // Goal: Zigcube's start_failed for an unknown digest, and nothing left behind. Method: an
    // unknown prefix, a malformed one, and a store that does not exist.
    _ = try setup(3);
    var diag: Diag = undefined;
    diag.reset();
    const unknown = spec_for("ffffffffffff", "img-2", false);
    try testing.expectError(error.StartFailed, lib.start(sim.interface(), &unknown, .{
        .image_workspace = &image_ws,
    }, &handle, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0410), diag.code);
    try testing.expect(files.kind_of(state ++ "/img-2") == null);
    try testing.expectEqual(@as(?u8, null), lib.failed_start(&diag).code());
    diag.reset();
    const bad = spec_for("Not A Digest", "img-2", false);
    try testing.expectError(error.StartFailed, lib.start(sim.interface(), &bad, .{
        .image_workspace = &image_ws,
    }, &handle, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0412), diag.code);
    // A lowercase word is a name, and nothing was pulled as it.
    diag.reset();
    const name = spec_for("not-a-digest", "img-2", false);
    try testing.expectError(error.StartFailed, lib.start(sim.interface(), &name, .{
        .image_workspace = &image_ws,
    }, &handle, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0522), diag.code);
    // No store at all: the same refusal as an unknown tree.
    sim_run.init(&sim, 4);
    files.init(4);
    sim.store_fs = &files;
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    diag.reset();
    try testing.expectError(error.StartFailed, lib.start(sim.interface(), &unknown, .{
        .image_workspace = &image_ws,
    }, &handle, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0410), diag.code);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a kernel that refuses the overlay is E0425, naming zbx doctor" {
    // Goal: the coded refusal when overlayfs can't be mounted. Method: the model refuses it.
    const digest = try setup(5);
    world_dirs("img-3");
    sim.world.overlay_refused = true;
    var diag: Diag = undefined;
    const text = digest.text();
    const spec = spec_for(&text, "img-3", false);
    try testing.expectError(error.StartFailed, start(&spec, &handle, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0425), diag.code);
    var found = false;
    for (diag.fixes.slice()) |fix| {
        if (std.mem.eql(u8, fix.command.slice(), "zbx doctor")) found = true;
    }
    try testing.expect(found);
    try testing.expectEqual(@as(u8, 125), diag.exit_code_in(.container_run));
}

test "a second run with the name starts from a fresh upper layer" {
    // Goal: an earlier run's layers do not leak into a run of the same name. Method: put a
    // file in the upper of the first, run again, and it is gone.
    const digest = try setup(6);
    world_dirs("img-4");
    var diag: Diag = undefined;
    const text = digest.text();
    const spec = spec_for(&text, "img-4", false);
    try start(&spec, &handle, &diag);
    _ = lib.wait(&handle);
    files.put_file(state ++ "/img-4/upper/left-behind", 0o644, "old");
    files.put_dir(state ++ "/img-4/upper/dir", 0o755);
    files.put_file(state ++ "/img-4/upper/dir/deep", 0o644, "old");
    // The host starts over (a new process), the store's files stay.
    sim_run.init(&sim, 66);
    sim.store_fs = &files;
    world_dirs("img-4");
    try start(&spec, &handle, &diag);
    try testing.expect(files.kind_of(state ++ "/img-4/upper/left-behind") == null);
    try testing.expect(files.kind_of(state ++ "/img-4/upper/dir") == null);
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/img-4/upper"),
    );
    _ = lib.wait(&handle);
}

test "removing a container's layers takes everything and is no error when there are none" {
    // Goal: what a pruned record's layers go through. Method: remove a container with a deep
    // upper; remove one that never existed.
    const digest = try setup(7);
    world_dirs("img-5");
    var diag: Diag = undefined;
    const text = digest.text();
    const spec = spec_for(&text, "img-5", false);
    try start(&spec, &handle, &diag);
    _ = lib.wait(&handle);
    files.put_dir(state ++ "/img-5/upper/a", 0o755);
    files.put_file(state ++ "/img-5/upper/a/b", 0o644, "x");
    diag.reset();
    try image.remove_container(sim.interface(), &handle.facts, &image_ws, "img-5", &diag);
    try testing.expect(files.kind_of(state ++ "/img-5") == null);
    try image.remove_container(sim.interface(), &handle.facts, &image_ws, "img-5", &diag);
    try image.remove_container(sim.interface(), &handle.facts, &image_ws, "never", &diag);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

/// A lazy run's server in the model: counts the calls, and closes the descriptor it is given.
const FakeLazy = struct {
    prepared: u32 = 0,
    served: u32 = 0,
    tree: ?Digest = null,
    refuse_prepare: bool = false,
    refuse_serve: bool = false,

    fn lazy(fake: *FakeLazy) lib.Lazy {
        return .{ .context = fake, .prepare = prepare, .serve = serve };
    }

    fn prepare(context: *anyopaque, tree: Digest, diag: *Diag) bool {
        const fake: *FakeLazy = @ptrCast(@alignCast(context));
        fake.prepared += 1;
        fake.tree = tree;
        if (!fake.refuse_prepare) return true;
        diag.raise(.E0422);
        diag.cause("the fake refuses", .{});
        return false;
    }

    fn serve(context: *anyopaque, device: @import("../host.zig").Handle) !void {
        const fake: *FakeLazy = @ptrCast(@alignCast(context));
        fake.served += 1;
        sim.interface().close(device);
        if (fake.refuse_serve) return error.Unsupported;
    }
};

fn start_lazy(spec: *const lib.Spec, fake: *FakeLazy, diag: *Diag) !void {
    diag.reset();
    const options: lib.StartOptions = .{ .image_workspace = &image_ws, .lazy = fake.lazy() };
    try lib.start(sim.interface(), spec, options, &handle, diag);
}

test "a lazy run serves the tree: nothing is materialized, the lower layer is the mount point" {
    // Goal: S2 slice 4's run path. Method: the server is prepared with the tree's digest and
    // served once, the farm is never made, the container has a lower directory, and the overlay
    // is mounted; the run ends with nothing left open.
    const digest = try setup(40);
    world_dirs("lazy-1");
    var fake: FakeLazy = .{};
    var diag: Diag = undefined;
    const text = digest.text();
    const spec = spec_for(&text, "lazy-1", false);
    try start_lazy(&spec, &fake, &diag);
    try testing.expectEqual(@as(u32, 1), fake.prepared);
    try testing.expectEqual(@as(u32, 1), fake.served);
    try testing.expect(fake.tree.?.eql(digest));
    const hex = digest.hex();
    var farm: [200]u8 = undefined;
    const cache = std.fmt.bufPrint(&farm, support.user_store ++ "/cache/{s}", .{&hex});
    try testing.expect(files.kind_of(cache catch unreachable) == null); // Short.
    try testing.expectEqual(
        @as(?@import("../store/fs.zig").FileKind, .dir),
        files.kind_of(state ++ "/lazy-1/lower"),
    );
    const child = &sim.world.processes[1];
    try testing.expect(sim.world.tables[child.table].has(.overlay, state ++ "/lazy-1/merged"));
    _ = lib.wait(&handle);
    try testing.expect(!sim.world.listener_leaked);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a lazy run refused: by its server, by the kernel's FUSE, or by a serve that fails" {
    // Goal: every refusal is a coded start failure with nothing left open. Method: a prepare
    // that refuses (its own code, and nothing spawned), a kernel without FUSE (E0205 naming the
    // mount step, never served), and a serve that fails (E0205 naming the serving step and why).
    var diag: Diag = undefined;
    {
        const digest = try setup(41);
        world_dirs("lazy-2");
        var fake: FakeLazy = .{ .refuse_prepare = true };
        const text = digest.text();
        const spec = spec_for(&text, "lazy-2", false);
        try testing.expectError(error.StartFailed, start_lazy(&spec, &fake, &diag));
        try testing.expectEqual(@as(?codes.Code, .E0422), diag.code);
        try testing.expectEqual(@as(u32, 0), fake.served);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
    }
    {
        const digest = try setup(42);
        world_dirs("lazy-3");
        sim.world.fuse_refused = true;
        var fake: FakeLazy = .{};
        const text = digest.text();
        const spec = spec_for(&text, "lazy-3", false);
        try testing.expectError(error.StartFailed, start_lazy(&spec, &fake, &diag));
        // The kernel's refusal of the mount is the host's lack of lazy start: E1201, not E0205.
        try testing.expectEqual(@as(?codes.Code, .E1201), diag.code);
        try testing.expectEqual(@as(u32, 2), diag.causes.count);
        try testing.expectEqualStrings(
            "mounting the image's tree over FUSE failed: operation not permitted (EPERM)",
            diag.causes.items[0].slice(),
        );
        try testing.expectEqualStrings(
            "the kernel refused the FUSE mount in the user namespace",
            diag.last_cause().?,
        );
        try testing.expectEqual(@as(u32, 0), fake.served);
        try testing.expect(!sim.world.listener_leaked);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
    }
    {
        const digest = try setup(43);
        world_dirs("lazy-4");
        var fake: FakeLazy = .{ .refuse_serve = true };
        const text = digest.text();
        const spec = spec_for(&text, "lazy-4", false);
        try testing.expectError(error.StartFailed, start_lazy(&spec, &fake, &diag));
        try testing.expectEqual(@as(?codes.Code, .E0205), diag.code);
        try testing.expectEqual(@as(u32, 1), diag.causes.count);
        try testing.expectEqualStrings(
            "serving the image's tree to the container over FUSE failed: the kernel's FUSE is " ++
                "older than protocol 7.31, or its first request was not INIT",
            diag.last_cause().?,
        );
        try testing.expectEqual(@as(u32, 1), fake.served);
        try testing.expect(!sim.world.listener_leaked);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
    }
}

/// A peer source that is never asked: the runs below are refused before any fetch.
fn never_fetch(
    _: *anyopaque,
    _: *const lazy_mod.Request,
    _: []u8,
) lazy_mod.FetchError!lazy_mod.Fetched {
    unreachable; // The refusals come first.
}

fn never_lied(_: *anyopaque, _: *const lazy_mod.Request, _: lazy_mod.PeerToken) void {
    unreachable; // As `never_fetch`.
}

test "E1208: peer sources a lazy run cannot take are refused at start, never asserted" {
    // Goal: the review's SHOULD 7 for S2 slice 5: a library caller's `lazy_sources` given to a
    // lazy server with no peers hook, or to a run that is not lazy, is a coded refusal with
    // nothing made, not an assertion in `prepare_lazy`. Method: both through `start`; the
    // server is never prepared and nothing is left open.
    var diag: Diag = undefined;
    var fake: FakeLazy = .{};
    const source: lazy_mod.Source = .{
        .context = &fake,
        .name = "swarm",
        .fetch = never_fetch,
        .lied = never_lied,
    };
    const sources = [_]lazy_mod.Source{source};
    const digest = try setup(44);
    world_dirs("lazy-6");
    const text = digest.text();
    const spec = spec_for(&text, "lazy-6", false);
    const cases = [_]lib.StartOptions{
        .{ .image_workspace = &image_ws, .lazy = fake.lazy(), .lazy_sources = &sources },
        .{ .image_workspace = &image_ws, .lazy_sources = &sources },
    };
    for (cases) |options| {
        diag.reset();
        const started = lib.start(sim.interface(), &spec, options, &handle, &diag);
        try testing.expectError(error.StartFailed, started);
        try testing.expectEqual(@as(?codes.Code, .E1208), diag.code);
        try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, "1 peer sources") != null);
        try testing.expectEqual(@as(u32, 0), fake.prepared);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
    }
}

test "a lazy run with a failure at every host call ends coded, with nothing left open" {
    // Goal: no leak on any path of the lazy plan. Method: count a good run's calls, then fail
    // each in turn: the start fails with a code or the run ends, and no descriptor stays open.
    var fake: FakeLazy = .{};
    var diag: Diag = undefined;
    const digest = try setup(44);
    world_dirs("lazy-5");
    const text = digest.text();
    const spec = spec_for(&text, "lazy-5", false);
    const calls_before = sim.call_count;
    try start_lazy(&spec, &fake, &diag);
    _ = lib.wait(&handle);
    const calls = sim.call_count - calls_before;
    try testing.expect(calls > 10);
    var index: u32 = 0;
    while (index < calls) : (index += 1) {
        _ = try setup(44);
        world_dirs("lazy-5");
        fake = .{};
        sim.faults.fail_call_index = sim.call_count + index;
        sim.faults.fail_call_error = error.IoFailed;
        if (start_lazy(&spec, &fake, &diag)) {
            _ = lib.wait(&handle);
        } else |_| {
            testing.expect(diag.code != null) catch |failure| {
                std.debug.print("call {d}: no code\n", .{index});
                return failure;
            };
        }
        sim.faults.fail_call_index = null;
        // A faulted final wait leaves its one child unreaped (the model has no retry); the
        // parent's descriptors, the FUSE one included, are closed all the same.
        testing.expect(sim.world.unreaped_children() <= 1) catch |failure| {
            std.debug.print("call {d}: {d} unreaped\n", .{ index, sim.world.unreaped_children() });
            return failure;
        };
        testing.expect(!sim.world.listener_leaked) catch |failure| {
            std.debug.print("call {d}: listener leaked\n", .{index});
            return failure;
        };
        testing.expectEqual(@as(u32, 0), sim.open_count()) catch |failure| {
            std.debug.print("call {d}: leaked\n", .{index});
            return failure;
        };
    }
}
