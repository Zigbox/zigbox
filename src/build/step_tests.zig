//! `run_step` (step.zig) against the simulator: every way a step can end. The model's container
//! does not write to the store's file system, so a test stands in for the command's writes to
//! `/out` with the simulated store's hook, which runs just before the log is renamed into place:
//! after the command ended and before the output is imported, which is when a real command's
//! files are all there. Whether the real kernel agrees is the VM demo (docs/demos/m7.md).

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const sim_run = @import("../runtime/sim_run.zig");
const sim_world = @import("../sim_world.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const import_mod = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const materialize = @import("../store/materialize.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const key_mod = @import("key.zig");
const step = @import("step.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

const store_root = support.user_store;
const state = "/home/alice/.local/state/zbx/containers";
const work_root = store_root ++ "/build/work";
const log_path = store_root ++ "/build/logs/fetch.log";

var sim: host_sim.HostSim = undefined;
var twin: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var disk: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_ws: import_mod.Workspace = undefined;
var workspace: step.Workspace = undefined;
var facts: doctor.Facts = undefined;
var result: step.Result = undefined;
var diag: Diag = undefined;
var host_files: [sim_run.files.len + 2]host_sim.File = undefined;
var farm_text: [constants.store_path_bytes_max]u8 = undefined;
var out_text: [constants.store_path_bytes_max]u8 = undefined;
const dir: u32 = 0o040755;
var roots_at_start: u32 = 0;
var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;

/// A store with two trees: the base (a root file system with a shell) and the step's input.
const Fixture = struct {
    base: Digest,
    input: Digest,
    /// The container name `run_step` will pick: the host's random bytes are the seed's.
    name: [constants.container_name_bytes_max]u8,
    name_len: u32,

    fn name_text(fixture: *const Fixture) []const u8 {
        return fixture.name[0..fixture.name_len];
    }
};

fn import_tree(root: []const u8) !Digest {
    var imported: import_mod.Result = undefined;
    diag.reset();
    try import_mod.import(
        &store,
        &import_ws,
        root,
        .{ .squash_owner = false, .warn = null },
        &imported,
        &diag,
    );
    return imported.digest;
}

fn setup(seed: u64, step_name: []const u8) !Fixture {
    sim_run.init(&sim, seed);
    files.init(seed);
    sim.store_fs = &files;
    disk.init(seed);
    disk.put_dir("/home", 0o755);
    disk.put_dir("/home/alice", 0o755);
    sim.log_fs = &disk; // Where the run's log is kept, apart from the store.
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), store_root);
    const base = try import_tree("/src");
    files.put_file("/src/main.c", 0o644, "int main;\n");
    const input = try import_tree("/src");
    assert(!base.eql(input));
    roots_at_start = support.count_files(&files, store_root ++ "/roots");
    var fixture: Fixture = .{ .base = base, .input = input, .name = undefined, .name_len = 0 };
    // The name is made from the host's first random bytes, so a twin host with the same seed
    // says it before the step runs, and the container model gets its directories in time.
    sim_run.init(&twin, seed);
    var random: [8]u8 = undefined;
    try twin.interface().random_bytes(&random);
    const hex = std.fmt.bytesToHex(random, .lower);
    const name = try std.fmt.bufPrint(&fixture.name, "build-{s}-{s}", .{ step_name, &hex });
    fixture.name_len = @intCast(name.len);
    world_dirs(&fixture);
    return fixture;
}

/// What the container model needs of the host: the merged directory with a shell in it, the
/// net layer's mount points, and the farm and the work directory the step binds.
fn world_dirs(fixture: *const Fixture) void {
    var path: [256]u8 = undefined;
    const name = fixture.name_text();
    const merged = text_of(&path, state ++ "/{s}/merged", .{name});
    sim.world.add_node(merged, .dir);
    var inner: [300]u8 = undefined;
    const net = text_of(&inner, state ++ "/{s}/net", .{name});
    sim.world.add_node(net, .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin", "/src", "/out", "/in" }) |suffix| {
        const text = text_of(&inner, "{s}{s}", .{ merged, suffix });
        sim.world.add_node(text, .dir);
    }
    for ([_][]const u8{ "/bin/sh", "/etc/hosts", "/etc/resolv.conf" }) |suffix| {
        const text = text_of(&inner, "{s}{s}", .{ merged, suffix });
        sim.world.add_node(text, .file);
    }
    // The host's own view of the paths the run binds (`mounts.look` stats them): the input farm
    // and the work directory's `out`, which the store's child makes in the store's file system.
    var farm: fs_mod.PathBuf = undefined;
    _ = materialize.farm_path(&store, &farm, fixture.input);
    @memcpy(farm_text[0..farm.len], farm.text());
    const out = text_of(&out_text, work_root ++ "/{s}/out", .{name});
    sim.world.add_node(farm.text(), .dir);
    sim.world.add_node(out, .dir);
    host_files[0..sim_run.files.len].* = sim_run.files;
    host_files[sim_run.files.len] = .{ .path = farm_text[0..farm.len], .content = "", .mode = dir };
    host_files[sim_run.files.len + 1] = .{ .path = out, .content = "", .mode = dir };
    sim.files = &host_files;
}

fn spec_for(fixture: *const Fixture) key_mod.Spec {
    return .{
        .platform = "linux/amd64",
        .base_tree = fixture.base,
        .base_env = &.{"PATH=/usr/bin:/bin"},
        .input_tree = fixture.input,
        .needs = &.{},
        .argv = &.{ "/bin/sh", "-c", "make" },
        .env = &.{},
        .network = false,
        .name = "fetch",
    };
}

fn run_it(spec: *const key_mod.Spec) step.Error!void {
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = spec,
        .file = "zbx.build.zon",
    };
    diag.reset();
    return step.run_step(&request, &workspace, &result, &diag);
}

/// What the command left in `/out`, written when the hook fires.
const Output = struct {
    fifo: bool = false,

    fn write(context: *anyopaque) void {
        const output: *const Output = @ptrCast(@alignCast(context));
        const out = find_out().?;
        var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
        files.put_dir(join(&path, out, "/bin"), 0o755);
        files.put_file(join(&path, out, "/bin/tool"), 0o755, "#!tool\n");
        files.put_file(join(&path, out, "/README"), 0o644, "built\n");
        if (output.fifo) {
            files.put_dir(join(&path, out, "/run"), 0o755);
            files.put(join(&path, out, "/run/control"), .fifo, 0o644, .{ 0, 0 }, "");
        }
    }
};

/// Formats a short test path; the buffers are far larger than any of them.
fn text_of(buffer: []u8, comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(buffer, format, args) catch unreachable; // Short test paths.
}

fn join(buffer: []u8, base: []const u8, tail: []const u8) []const u8 {
    return text_of(buffer, "{s}{s}", .{ base, tail });
}

/// The step's `out` directory in the store, while it exists.
fn find_out() ?[]const u8 {
    var index: u32 = 0;
    while (files.alive_path(index)) |path| : (index += 1) {
        const in_work = std.mem.startsWith(u8, path, work_root ++ "/");
        if (in_work and std.mem.endsWith(u8, path, "/out")) return path;
    }
    return null;
}

fn arm(output: *Output) void {
    files.hook = .{
        .rename_to_contains = "fetch.log",
        .context = output,
        .call = Output.write,
    };
}

fn work_dirs() u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.startsWith(u8, path, work_root ++ "/")) count += 1;
    }
    return count;
}

fn record_exists(fixture: *const Fixture) bool {
    var path: [256]u8 = undefined;
    const where = text_of(&path, sim_run.runs_path ++ "/{s}.zon", .{fixture.name_text()});
    return sim.world.find_written(where) != null;
}

/// Nothing a failed or finished step may leave: the work directory, the run's record, a held
/// descriptor, or a host change.
fn expect_clean(fixture: *const Fixture, before: *const sim_run.Baseline) !void {
    try testing.expectEqual(@as(u32, 0), work_dirs());
    // The step roots nothing: the cache entry does.
    try testing.expectEqual(roots_at_start, support.count_files(&files, store_root ++ "/roots"));
    try testing.expect(!record_exists(fixture));
    try testing.expectEqual(@as(?[]const u8, null), sim_run.leak(&sim, before));
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

fn expect_tree_in_store(digest: Digest) !void {
    var errno: u16 = 0;
    const bytes = try trees.load(&store, digest, &tree_buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    var entry: tree.Entry = undefined;
    var names: u32 = 0;
    while (try decoder.next(&entry)) names += 1;
    try testing.expect(names >= 2);
}

fn set_output(chunks: []const sim_world.OutChunk) void {
    sim.world.out_script = chunks;
    sim.world.out_at = 0;
}

test "a step that exits 0 imports /out, keeps its log, and leaves nothing" {
    // Goal: the clean path. Method: the command prints two lines and writes three entries to
    // /out; the result names a tree that is in the store with them, the log holds the output
    // in order, and the work directory, the run's record and every descriptor are gone.
    const fixture = try setup(1, "fetch");
    const before = sim_run.baseline(&sim);
    const chunks = [_]sim_world.OutChunk{
        .{ .stream = .stdout, .bytes = "compiling\n" },
        .{ .stream = .stderr, .bytes = "done\n" },
    };
    set_output(&chunks);
    var output: Output = .{};
    arm(&output);
    const spec = spec_for(&fixture);
    try run_it(&spec);
    try testing.expectEqual(@as(?codes.Code, null), diag.code);
    try testing.expectEqual(@as(u64, 2), result.files);
    try expect_tree_in_store(result.output);
    try testing.expectEqualStrings("compiling\ndone\n", files.content_of(log_path).?);
    try expect_clean(&fixture, &before);
}

test "a step that exits non-zero is E0805 with its last line, and keeps its log" {
    // Goal: the failure path. Method: exit 2 after output; the diagnostic's headline names the
    // step and the code, its newest cause is the last line of output, the log is kept, nothing
    // was imported, and the work directory is gone.
    const fixture = try setup(2, "fetch");
    const before = sim_run.baseline(&sim);
    sim.world.command_exit = .{ .exited = 2 };
    const chunks = [_]sim_world.OutChunk{
        .{ .stream = .stdout, .bytes = "step 1\n" },
        .{ .stream = .stderr, .bytes = "make: *** no rule\n" },
    };
    set_output(&chunks);
    var output: Output = .{};
    arm(&output); // The command left files, but a failed step's are not imported.
    const spec = spec_for(&fixture);
    try testing.expectError(error.Failed, run_it(&spec));
    try testing.expectEqual(@as(?codes.Code, .E0805), diag.code);
    try testing.expectEqualStrings("build step \"fetch\" failed: exit 2", diag.headline.slice());
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.startsWith(u8, cause, "make: *** no rule"));
    try testing.expectEqualStrings("step 1\nmake: *** no rule\n", files.content_of(log_path).?);
    try expect_clean(&fixture, &before);
}

test "a FIFO left in /out is E0806 naming its path below /out" {
    // Goal: an output holds only files, directories and links. Method: the command leaves
    // /out/run/control as a FIFO beside good files; the import refuses, the diagnostic names
    // /out/run/control, and the work directory is removed all the same.
    const fixture = try setup(3, "fetch");
    const before = sim_run.baseline(&sim);
    var output: Output = .{ .fifo = true };
    arm(&output);
    const spec = spec_for(&fixture);
    try testing.expectError(error.Failed, run_it(&spec));
    try testing.expectEqual(@as(?codes.Code, .E0806), diag.code);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "/out/run/control") != null);
    try testing.expect(std.mem.indexOf(u8, cause, "FIFO") != null);
    try expect_clean(&fixture, &before);
}

const End = struct {
    exit: host_mod.ExitStatus,
    oom: u32 = 0,
    runs_ms: u32 = 0,
    headline: []const u8,
};

test "a signal, an OOM kill and a timeout are E0805, each in its own words" {
    // Goal: every way the command can end other than by exiting. Method: the model ends the
    // command with SIGTERM; with an OOM kill in its cgroup; and after the step's timeout
    // (the model's clock only moves when the run waits, so no real time passes).
    const cases = [_]End{
        .{ .exit = .{ .signaled = 15 }, .headline = "signal 15 (SIGTERM)" },
        .{ .exit = .{ .signaled = 9 }, .oom = 1, .headline = "out of memory" },
        .{
            .exit = .{ .exited = 0 },
            .runs_ms = constants.build_step_timeout_ms + 1,
            .headline = "timed out",
        },
    };
    for (cases, 0..) |case, index| {
        const fixture = try setup(10 + index, "fetch");
        const before = sim_run.baseline(&sim);
        sim.world.command_exit = case.exit;
        sim.world.oom_kills = case.oom;
        sim.world.command_runs_ms = case.runs_ms;
        const spec = spec_for(&fixture);
        try testing.expectError(error.Failed, run_it(&spec));
        try testing.expectEqual(@as(?codes.Code, .E0805), diag.code);
        var expected: [96]u8 = undefined;
        const headline = try std.fmt.bufPrint(&expected, "build step \"fetch\" failed: {s}", .{
            case.headline,
        });
        try testing.expectEqualStrings(headline, diag.headline.slice());
        try expect_clean(&fixture, &before);
    }
}

test "a work directory that cannot be made is one coded diagnostic and nothing starts" {
    // Goal: a fault in the preparation. Method: a plain file where /build should be, so the
    // store's namespace child cannot make the work directory; the diagnostic is the store's
    // write failure, no container was started (no record, no log, no mounts), and nothing
    // leaked.
    const fixture = try setup(20, "fetch");
    files.put_file(store_root ++ "/build", 0o644, "in the way");
    const before = sim_run.baseline(&sim);
    const spec = spec_for(&fixture);
    try testing.expectError(error.Failed, run_it(&spec));
    try testing.expectEqual(@as(?codes.Code, .E0417), diag.code);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "making a build step's work directory") != null);
    try testing.expectEqual(@as(u32, 0), work_dirs());
    try testing.expect(files.kind_of(log_path) == null);
    try testing.expect(!record_exists(&fixture));
    try testing.expectEqual(@as(?[]const u8, null), sim_run.leak(&sim, &before));
    try testing.expectEqual(@as(u32, 0), files.open_count());
}
