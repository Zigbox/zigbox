//! Tests of `pull.pull`, the library call, from callers other than the command line: a caller
//! that brings its own memory, request and progress callback, against the simulated host and the
//! test registry on the simulated network (the CLI's own pull tests are in `pull_tests.zig`).
//! They check the store and the image's record, that no `zbx.lock` is made, that the environment
//! is the caller's to read, that a failure is the coded diagnostic, and that two callers on two
//! threads share nothing.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("diag/codes.zig");
const constants = @import("constants.zig");
const doctor = @import("doctor.zig");
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const images = @import("store/images.zig");
const import = @import("store/import.zig");
const net_sim = @import("registry/net_sim.zig");
const pull = @import("pull.zig");
const sim_run = @import("runtime/sim_run.zig");
const support = @import("store/test_support.zig");
const test_registry = @import("registry/test_registry.zig");
const Diag = @import("diag/diag.zig").Diag;
const Store = @import("store/layout.zig").Store;

const testing = std.testing;
const HostSim = host_sim.HostSim;

const project = "/home/alice/project";
const store_root = "/home/alice/.local/share/zbx/store";

/// Everything one caller of the library owns, so that two callers share nothing. About 40 MiB,
/// made on the heap: it is the caller's job to keep a pull's memory off a small stack.
const Caller = struct {
    sim: HostSim,
    registry: test_registry.TestRegistry,
    wire: net_sim.SimNet,
    files: fs_sim.SimFs,
    workspace: pull.Workspace,
    import_workspace: import.Workspace,
    facts: doctor.Facts,
    result: pull.Result,
    record: images.Image,
    diag: Diag,
    blobs_seen: u32,
    warnings_seen: u32,
    last_warning: ?codes.Code,
    ok: bool,

    fn create(seed: u64) !*Caller {
        const caller = try std.heap.page_allocator.create(Caller);
        caller.setup(seed);
        return caller;
    }

    fn destroy(caller: *Caller) void {
        std.heap.page_allocator.destroy(caller);
    }

    fn setup(caller: *Caller, seed: u64) void {
        sim_run.init(&caller.sim, seed);
        caller.registry.init();
        caller.wire.init(seed, caller.registry.responder());
        caller.sim.wire = &caller.wire;
        caller.files.init(seed);
        caller.files.put_dir("/home", 0o755);
        caller.files.put_dir("/home/alice", 0o755);
        caller.files.put_dir(project, 0o755);
        caller.sim.store_fs = &caller.files;
        _ = caller.sim.world.processes[0].cwd.set(project);
        caller.blobs_seen = 0;
        caller.warnings_seen = 0;
        caller.last_warning = null;
        caller.ok = false;
        caller.diag.reset();
    }

    fn on_event(context: *anyopaque, event: pull.Event) void {
        const caller: *Caller = @ptrCast(@alignCast(context));
        switch (event) {
            .resolved => {},
            .blob => |blob| {
                assert(blob.index < blob.of);
                caller.blobs_seen += 1;
            },
            .warning => |diag| {
                caller.warnings_seen += 1;
                caller.last_warning = diag.code;
            },
        }
    }

    /// One pull of `reference`, the way a library caller makes it.
    fn pull_once(caller: *Caller, reference: []const u8, platform: pull.Platform) bool {
        const request: pull.Request = .{
            .reference = reference,
            .platform = platform,
            .mirrors = "",
        };
        const progress: pull.Progress = .{ .context = caller, .call = on_event };
        caller.diag.reset();
        pull.pull(
            caller.sim.interface(),
            &caller.facts,
            &request,
            progress,
            &caller.workspace,
            &caller.import_workspace,
            &caller.result,
            &caller.diag,
        ) catch return false;
        return true;
    }
};

fn zbx_lock_files(caller: *const Caller) u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (caller.files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.endsWith(u8, path, "zbx.lock")) count += 1;
    }
    return count;
}

test "a library caller pulls an image: the result, the record, the store, and no zbx.lock" {
    // Goal: the contract of `pull.pull` from a caller that is not the CLI. Method: pull the
    // fixture by tag; the result names the manifest the registry gave this platform, the tree
    // the image's record names, the platform and the settings; the store is whole; the
    // progress callback saw the config and both layers and the unsupported-attribute warning;
    // and no zbx.lock exists anywhere, though the working directory is a project.
    const caller = try Caller.create(1);
    defer caller.destroy();
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expect(caller.pull_once(reference, .{}));
    const result = &caller.result;
    const expected = &caller.registry.fixture.oci.amd64.digest;
    try testing.expectEqualStrings(expected, &result.manifest_digest.text());
    try testing.expectEqualStrings("linux/amd64", result.platform());
    try testing.expectEqual(@as(u32, 2), result.layer_count);
    try testing.expectEqual(@as(u32, 3), caller.blobs_seen);
    try testing.expectEqual(@as(?codes.Code, .W0502), caller.last_warning);
    try testing.expectEqual(@as(u32, 1), caller.warnings_seen);
    try testing.expectEqual(@as(u32, 0), result.warnings_dropped);
    try testing.expect(result.counts.files > 0);
    try testing.expect(result.counts.directories > 0);

    var store: Store = undefined;
    try testing.expect(store.locate(caller.sim.interface()));
    var errno: u16 = 0;
    try images.load(&store, result.manifest_digest, &caller.record, &errno);
    try testing.expect(caller.record.tree.eql(result.tree));
    try testing.expectEqualStrings("linux/amd64", caller.record.platform_text());
    try testing.expectEqual(@as(usize, 1), @as(usize, caller.record.tag_count));
    try testing.expectEqualStrings(reference, caller.record.tag_text(0));
    try testing.expect(caller.record.config.eql(result.config_digest));
    try testing.expectEqual(
        result.settings.count(.cmd),
        caller.record.settings.count(.cmd),
    );
    try support.check_whole(&caller.files, store_root, 1 << 20);
    try testing.expectEqual(@as(u32, 0), zbx_lock_files(caller));

    // A second pull is the same image from the cache, and still no lock.
    caller.wire.requests = 0;
    try testing.expect(caller.pull_once(reference, .{}));
    try testing.expect(caller.result.tree.eql(result.tree));
    try testing.expectEqual(@as(u32, 2), caller.wire.requests);
    try testing.expectEqual(@as(u32, 0), zbx_lock_files(caller));
}

test "the library reads no environment variable of its own: the request is the caller's" {
    // Goal: ZBX_PLATFORM, its fallback and ZBX_REGISTRY_MIRRORS are the caller's to read. Method:
    // a host whose environment names an arm64 platform and a mirror that does not exist; the
    // library pulls amd64 from the registry, and asks no mirror. The same pull with the platform
    // in the request is the arm64 image.
    const caller = try Caller.create(2);
    defer caller.destroy();
    const environment = [_]host_sim.EnvironmentVariable{
        .{ .name = "HOME", .value = "/home/alice" },
        .{ .name = "ZBX_PLATFORM", .value = "linux/arm64" },
        .{ .name = "ZBX_PLATFORM_FALLBACK", .value = "linux/arm64" },
        .{ .name = "ZBX_REGISTRY_MIRRORS", .value = "mirror.invalid" },
    };
    caller.sim.environment_variables = &environment;
    const reference = test_registry.TestRegistry.reference(.open);
    try testing.expect(caller.pull_once(reference, .{}));
    try testing.expectEqualStrings("linux/amd64", caller.result.platform());
    var index: u32 = 0;
    while (caller.wire.logged(index)) |entry| : (index += 1) {
        try testing.expect(std.mem.indexOf(u8, entry.target_text(), "mirror") == null);
    }
    try testing.expect(caller.pull_once(reference, .{ .architecture = .arm64 }));
    try testing.expectEqualStrings("linux/arm64", caller.result.platform());
    const arm = &caller.registry.fixture.oci.arm64.digest;
    try testing.expectEqualStrings(arm, &caller.result.manifest_digest.text());
}

test "a refused image is the coded diagnostic of the command, and the store stays whole" {
    // Goal: every failure is the same coded Diag. Method: a layer that would write outside its
    // root (E0515, raised in the store's child and carried through its report) and a damaged one
    // (E0516); then a reference that is not one (E0xxx from the parent), and an unreachable
    // registry (E0503); each leaves the store whole and no lock.
    const caller = try Caller.create(3);
    defer caller.destroy();
    try testing.expect(!caller.pull_once(test_registry.TestRegistry.reference(.unsafe), .{}));
    try testing.expectEqual(@as(?codes.Code, .E0515), caller.diag.code);
    try testing.expect(caller.diag.last_cause() != null);
    try testing.expect(std.mem.indexOf(u8, caller.diag.last_cause().?, "/etc/passwd") != null);
    try support.check_whole(&caller.files, store_root, 1 << 20);
    try testing.expect(!caller.pull_once(test_registry.TestRegistry.reference(.damaged), .{}));
    try testing.expectEqual(@as(?codes.Code, .E0516), caller.diag.code);
    try testing.expect(!caller.pull_once("", .{}));
    try testing.expect(caller.diag.code != null);
    caller.sim.wire = null;
    try testing.expect(!caller.pull_once(test_registry.TestRegistry.reference(.open), .{}));
    try testing.expectEqual(@as(?codes.Code, .E0503), caller.diag.code);
    try testing.expectEqual(@as(u32, 0), zbx_lock_files(caller));
}

fn thread_work(caller: *Caller, reference: []const u8) void {
    caller.ok = caller.pull_once(reference, .{});
}

test "two callers on two threads pull into two stores and share nothing" {
    // Goal: the library promises no process-wide state, here for pull. Method: two callers, each
    // with its own host, disk, wire, memory and store, pull at once, several times over; both
    // succeed, each store holds the image and is whole, and each result is the same tree (the
    // image is the same, so a result that is the other caller's would not show, but a record or
    // a blob in the wrong store, or a shared static that two threads corrupt, would).
    const first = try Caller.create(10);
    defer first.destroy();
    const second = try Caller.create(11);
    defer second.destroy();
    const reference = test_registry.TestRegistry.reference(.open);
    const config: std.Thread.SpawnConfig = .{ .stack_size = 8 * 1024 * 1024 };
    for (0..3) |round| {
        if (round > 0) {
            first.files.init(10);
            second.files.init(11);
            for ([_]*Caller{ first, second }) |caller| {
                caller.files.put_dir("/home", 0o755);
                caller.files.put_dir("/home/alice", 0o755);
                caller.files.put_dir(project, 0o755);
            }
        }
        first.ok = false;
        second.ok = false;
        const one = try std.Thread.spawn(config, thread_work, .{ first, reference });
        const two = try std.Thread.spawn(config, thread_work, .{ second, reference });
        one.join();
        two.join();
        try testing.expect(first.ok);
        try testing.expect(second.ok);
        try testing.expect(first.result.tree.eql(second.result.tree));
        for ([_]*Caller{ first, second }) |caller| {
            try support.check_whole(&caller.files, store_root, 1 << 20);
            var store: Store = undefined;
            try testing.expect(store.locate(caller.sim.interface()));
            var errno: u16 = 0;
            try images.load(&store, caller.result.manifest_digest, &caller.record, &errno);
            try testing.expect(caller.record.tree.eql(caller.result.tree));
        }
    }
}
