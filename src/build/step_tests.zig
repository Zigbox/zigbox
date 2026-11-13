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
const lock = @import("../store/lock.zig");
const materialize = @import("../store/materialize.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const key_mod = @import("key.zig");
const step = @import("step.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

pub const store_root = support.user_store;
pub const state = "/home/alice/.local/state/zbx/containers";
const work_root = store_root ++ "/build/work";
pub const group = "0123456789abcdef";
const log_path = store_root ++ "/build/logs/" ++ group ++ "/fetch.log";

pub var sim: host_sim.HostSim = undefined;
var twin: host_sim.HostSim = undefined;
pub var files: fs_sim.SimFs = undefined;
var disk: fs_sim.SimFs = undefined;
pub var store: layout.Store = undefined;
pub var import_ws: import_mod.Workspace = undefined;
pub var workspace: step.Workspace = undefined;
pub var facts: doctor.Facts = undefined;
pub var result: step.Result = undefined;
pub var diag: Diag = undefined;
var host_files: [sim_run.files.len + 2]host_sim.File = undefined;
var farm_text: [constants.store_path_bytes_max]u8 = undefined;
var out_text: [constants.store_path_bytes_max]u8 = undefined;
var need_text: [constants.store_path_bytes_max]u8 = undefined;
const dir: u32 = 0o040755;
var roots_at_start: u32 = 0;
pub var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;

/// A store with two trees: the base (a root file system with a shell) and the step's input.
pub const Fixture = struct {
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

pub fn setup(seed: u64, step_name: []const u8) !Fixture {
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
    for ([_][]const u8{ "/bin/sh", "/etc/hosts", "/etc/resolv.conf", "/etc/hostname" }) |suffix| {
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

pub fn spec_for(fixture: *const Fixture) key_mod.Spec {
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

pub fn run_it(spec: *const key_mod.Spec) step.Error!void {
    return run_streaming(spec, false);
}

fn run_streaming(spec: *const key_mod.Spec, stream: bool) step.Error!void {
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = spec,
        .file = "zbx.build.zon",
        .group = group,
        .stream = stream,
    };
    diag.reset();
    return step.run_step(&request, &workspace, &result, &diag);
}

/// What the command left in `/out`, written when the hook fires.
const Output = struct {
    fifo: bool = false,

    fn write(context: *anyopaque) void {
        const output: *const Output = @ptrCast(@alignCast(context));
        capture_container();
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
pub fn text_of(buffer: []u8, comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(buffer, format, args) catch unreachable; // Short test paths.
}

pub fn join(buffer: []u8, base: []const u8, tail: []const u8) []const u8 {
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
pub fn expect_clean(fixture: *const Fixture, before: *const sim_run.Baseline) !void {
    try testing.expectEqual(@as(u32, 0), work_dirs());
    // A step that imported roots its output as `build:<step>` until the parent writes the cache
    // entry (N8); a step that failed roots nothing.
    const rooted: u32 = if (diag.code == null) 1 else 0;
    const roots_now = support.count_files(&files, store_root ++ "/roots");
    try testing.expectEqual(roots_at_start + rooted, roots_now);
    try testing.expect(!record_exists(fixture));
    try testing.expectEqual(@as(?[]const u8, null), sim_run.leak(&sim, before));
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

pub fn expect_tree_in_store(digest: Digest) !void {
    var errno: u16 = 0;
    const bytes = try trees.load(&store, digest, &tree_buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    var entry: tree.Entry = undefined;
    var names: u32 = 0;
    while (try decoder.next(&entry)) names += 1;
    try testing.expect(names >= 2);
}

pub fn set_output(chunks: []const sim_world.OutChunk) void {
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
    var root_path: [128]u8 = undefined;
    const hex = result.output.hex();
    const rooted_at = try std.fmt.bufPrint(&root_path, store_root ++ "/roots/{s}", .{&hex});
    const record = files.content_of(rooted_at) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, record, "build:fetch") != null);
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

/// What the hook saw of the step's command, which is gone by the time the step returns.
var captured_env: [2048]u8 = undefined;
var captured_len: usize = 0;
var captured_stdin_null = false;
var captured_found = false;

/// Copies the step's command process: the one whose environment names the step.
fn capture_container() void {
    captured_found = false;
    for (&sim.world.processes) |*process| {
        if (std.mem.indexOf(u8, process.envp(), "ZBX_BUILD_STEP=fetch") == null) continue;
        captured_len = process.envp().len;
        @memcpy(captured_env[0..captured_len], process.envp());
        captured_stdin_null = process.stdin_null;
        captured_found = true;
    }
}

fn has_entry(bytes: []const u8, entry: []const u8) bool {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trimEnd(u8, line, "\x00"), entry)) return true;
    }
    return false;
}

test "the host's TERM never reaches a step: the same environment under two terminals" {
    // Goal: a step's environment (and so its key) does not depend on the developer's terminal.
    // Method: the same step run with the host's TERM set to two values; the command's
    // environment is byte for byte the same, and says TERM=dumb.
    var first: [2048]u8 = undefined;
    var first_len: usize = 0;
    const terms = [_][]const u8{ "xterm-256color", "screen" };
    for (terms, 0..) |term, index| {
        const fixture = try setup(30, "fetch");
        var variables: [8]host_sim.EnvironmentVariable = undefined;
        const kept = sim.environment_variables;
        @memcpy(variables[0..kept.len], kept);
        variables[kept.len] = .{ .name = "TERM", .value = term };
        sim.environment_variables = variables[0 .. kept.len + 1];
        var output: Output = .{};
        arm(&output);
        const spec = spec_for(&fixture);
        try run_it(&spec);
        try testing.expect(captured_found);
        const bytes = captured_env[0..captured_len];
        try testing.expect(has_entry(bytes, "TERM=dumb"));
        try testing.expect(std.mem.indexOf(u8, bytes, term) == null);
        if (index == 0) {
            first_len = bytes.len;
            @memcpy(first[0..bytes.len], bytes);
        } else {
            try testing.expectEqualStrings(first[0..first_len], bytes);
        }
    }
}

test "a step's command has /dev/null for standard input" {
    // Goal: a step never reads the developer's terminal. Method: after a clean step the
    // command's process was born with stdin_null.
    const fixture = try setup(31, "fetch");
    var output: Output = .{};
    arm(&output);
    const spec = spec_for(&fixture);
    try run_it(&spec);
    try testing.expect(captured_found);
    try testing.expect(captured_stdin_null);
}

test "a failed start after the record began leaves no run record" {
    // Goal: a step whose command cannot start (E0202) discards the record the start saved.
    // Method: a command that is not in the image; the step fails with the run's own code, and
    // the record, the work directory and the descriptors are gone.
    const fixture = try setup(32, "fetch");
    const before = sim_run.baseline(&sim);
    var spec = spec_for(&fixture);
    spec.argv = &.{"nothere"};
    try testing.expectError(error.Failed, run_it(&spec));
    try testing.expect(diag.code != null);
    try expect_clean(&fixture, &before);
}

test "a pid limit is E0805 in its own words" {
    // Goal: the process limit has its wording. Method: the model reports forks refused.
    const fixture = try setup(33, "fetch");
    const before = sim_run.baseline(&sim);
    sim.world.pids_max_hits = 3;
    const spec = spec_for(&fixture);
    try testing.expectError(error.Failed, run_it(&spec));
    try testing.expectEqual(@as(?codes.Code, .E0805), diag.code);
    try testing.expect(std.mem.indexOf(u8, diag.headline.slice(), "process limit reached") != null);
    try expect_clean(&fixture, &before);
}

test "network = true gives the container the user network, and none otherwise" {
    // Goal: the network flag reaches the run. Method: one step without the flag and one with;
    // the run's handle says which network each was given.
    const wants = [_]bool{ false, true };
    for (wants, 0..) |network, index| {
        const fixture = try setup(34 + index * 100, "fetch");
        var output: Output = .{};
        arm(&output);
        var spec = spec_for(&fixture);
        spec.network = network;
        try run_it(&spec);
        const expected: @TypeOf(workspace.handle.network) = if (network) .user else .none;
        try testing.expect(workspace.handle.network == expected);
    }
}

test "a need's output is mounted at /in/<name>" {
    // Goal: `needs` reaches the container. Method: a need whose farm the step's store makes;
    // the step runs and the mount list held by the run names /in/deps.
    const fixture = try setup(35, "fetch");
    var output: Output = .{};
    arm(&output);
    var spec = spec_for(&fixture);
    const needs = [_]key_mod.Need{.{ .name = "deps", .output = fixture.base }};
    spec.needs = &needs;
    var farm: fs_mod.PathBuf = undefined;
    _ = materialize.farm_path(&store, &farm, fixture.base);
    @memcpy(need_text[0..farm.len], farm.text());
    sim.world.add_node(farm.text(), .dir);
    var extra: [sim_run.files.len + 3]host_sim.File = undefined;
    @memcpy(extra[0..host_files.len], &host_files);
    extra[host_files.len] = .{ .path = need_text[0..farm.len], .content = "", .mode = dir };
    sim.files = &extra;
    try run_it(&spec);
    try testing.expectEqual(@as(?codes.Code, null), diag.code);
    var seen = false;
    for (workspace.mounts[0..3]) |mount| {
        if (std.mem.eql(u8, mount.target, "/in/deps")) seen = true;
    }
    try testing.expect(seen);
}

test "an environment of 64 variables runs and one of 65 is refused naming the step" {
    // Goal: the run's limit is the build layer's diagnostic. Method: a base environment sized
    // so the merged one (with the fixed variables and the step's name) is 64, then 65.
    const fixed = key_mod.fixed_env.len + 1;
    var storage: [constants.env_vars_count_max + 1][16]u8 = undefined;
    var base: [constants.env_vars_count_max + 1][]const u8 = undefined;
    for (0..base.len) |index| {
        base[index] = std.fmt.bufPrint(&storage[index], "V{d}=x", .{index}) catch
            unreachable; // Short names.
    }
    const fits = constants.env_vars_count_max - fixed;
    const sizes = [_]usize{ fits, fits + 1 };
    for (sizes, 0..) |size, index| {
        const fixture = try setup(36 + index, "fetch");
        const before = sim_run.baseline(&sim);
        var output: Output = .{};
        arm(&output);
        var spec = spec_for(&fixture);
        spec.base_env = base[0..size];
        if (index == 0) {
            try run_it(&spec);
        } else {
            try testing.expectError(error.Failed, run_it(&spec));
            try testing.expectEqual(@as(?codes.Code, .E0805), diag.code);
            const headline = diag.headline.slice();
            try testing.expect(std.mem.indexOf(u8, headline, "\"fetch\"") != null);
            try testing.expect(std.mem.indexOf(u8, headline, "environment is too large") != null);
            try expect_clean(&fixture, &before);
        }
    }
}

test "a sweep clears what a killed step left, and a live step's lock stops it" {
    // Goal: leftovers of a crashed build (a work directory with its log temporary) are removed
    // by the next build's sweep, and a sweep never runs under a step in flight. A real SIGKILL
    // of zbx leaves exactly these files; the VM demo kills a real build. Method: plant two
    // work directories; a shared hold makes the sweep do nothing; without it they are gone.
    const fixture = try setup(40, "fetch");
    files.put_dir(store_root ++ "/build", 0o755);
    files.put_dir(work_root, 0o755);
    files.put_dir(work_root ++ "/build-old-1", 0o755);
    files.put_dir(work_root ++ "/build-old-1/out", 0o755);
    files.put_file(work_root ++ "/build-old-1/log", 0o644, "partial");
    files.put_dir(work_root ++ "/build-old-2", 0o755);
    const spec = spec_for(&fixture);
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = &spec,
        .file = "zbx.build.zon",
        .group = group,
    };
    var other: layout.Store = undefined;
    other.at(sim.interface(), store_root);
    try lock.hold(&other, .shared, "build");
    diag.reset();
    try step.sweep(&request, &workspace, &diag);
    try testing.expectEqual(@as(u32, 4), work_dirs());
    lock.release(&other);
    try step.sweep(&request, &workspace, &diag);
    try testing.expectEqual(@as(u32, 0), work_dirs());
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "clear-caches empties this group's caches under the exclusive lock; busy is E0436" {
    // Goal: `zbx build --clear-caches` removes `build/caches/<group>` and nothing of another
    // group, and never under a running step. Method: plant two groups' caches; a shared hold
    // refuses with E0436 and removes nothing; without it the group's directory is gone.
    const fixture = try setup(43, "fetch");
    const mine = store_root ++ "/build/caches/" ++ group;
    const theirs = store_root ++ "/build/caches/fedcba9876543210";
    files.put_dir(store_root ++ "/build", 0o755);
    files.put_dir(store_root ++ "/build/caches", 0o755);
    inline for ([_][]const u8{ mine, theirs }) |path| {
        files.put_dir(path, 0o755);
        files.put_dir(path ++ "/go", 0o755);
        files.put_file(path ++ "/go/entry", 0o644, "cached");
    }
    const spec = spec_for(&fixture);
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = &spec,
        .file = "zbx.build.zon",
        .group = group,
    };
    var other: layout.Store = undefined;
    other.at(sim.interface(), store_root);
    try lock.hold(&other, .shared, "build");
    diag.reset();
    try testing.expectError(error.Failed, step.clear_caches(&request, &workspace, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0436), diag.code);
    try testing.expect(files.kind_of(mine ++ "/go/entry") != null);
    lock.release(&other);
    diag.reset();
    try step.clear_caches(&request, &workspace, &diag);
    try testing.expect(diag.code == null);
    try testing.expect(files.kind_of(mine) == null);
    try testing.expect(files.kind_of(theirs ++ "/go/entry") != null);
    try step.clear_caches(&request, &workspace, &diag); // Nothing left: not an error.
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "a sweep of a store that does not exist yet is not an error" {
    // Goal: a clean machine's first `zbx build` has no store directory, so no lock file; the
    // sweep finds nothing and says nothing (the VM demo's second machine was refused with E0417).
    // Method: the sweep on a simulated host whose store filesystem is empty.
    sim_run.init(&sim, 41);
    files.init(41);
    sim.store_fs = &files;
    const fixture: Fixture = .{
        .base = Digest.of("base"),
        .input = Digest.of("input"),
        .name = undefined,
        .name_len = 0,
    };
    const spec = spec_for(&fixture);
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = &spec,
        .file = "zbx.build.zon",
        .group = group,
    };
    diag.reset();
    const live_before = files.live_count();
    try step.sweep(&request, &workspace, &diag);
    try testing.expect(diag.code == null);
    // The sweep must not create the store (or its lock file) to take the lock.
    try testing.expectEqual(live_before, files.live_count());
    try testing.expectEqual(@as(u32, 0), files.open_count());
}

test "a sweep whose lock file cannot be opened is E0417, not silence" {
    // Goal: only a store that does not exist yet is skipped; a lock file that exists and is
    // refused (EACCES) is a real fault the user must hear of. Method: the store's lock file
    // exists and is unreadable.
    const fixture = try setup(42, "fetch");
    files.set_unreadable(store_root ++ "/lock");
    const spec = spec_for(&fixture);
    const request: step.Request = .{
        .host = sim.interface(),
        .facts = &facts,
        .spec = &spec,
        .file = "zbx.build.zon",
        .group = group,
    };
    diag.reset();
    try testing.expectError(error.Failed, step.sweep(&request, &workspace, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0417), diag.code);
    try testing.expectEqual(@as(u32, 0), files.open_count());
    diag.reset();
}

test "with stream on, each step's output is on stderr behind its name, and stdout is untouched" {
    // Goal: `--verbose` for two steps, through `run_step` and the run's log sink. Method: two
    // steps (each its own simulated host, as the model resets between them) write lines on both
    // streams, cut in the middle of a line, the last without a newline. Stderr must hold whole
    // lines each behind `<step> | `, the unfinished one closed with a newline, stdout nothing,
    // and the log the exact bytes. Removing the `stream_lines` call or `.stream` fails it.
    const names = [_][]const u8{ "fetch", "pack" };
    for (names, 0..) |name, index| {
        const fixture = try setup(30 + index, name);
        const chunks = [_]sim_world.OutChunk{
            .{ .stream = .stdout, .bytes = "compil" },
            .{ .stream = .stdout, .bytes = "ing\nsecond\n" },
            .{ .stream = .stderr, .bytes = "warn: x\n" },
            .{ .stream = .stdout, .bytes = "no newline" },
        };
        set_output(&chunks);
        var spec = spec_for(&fixture);
        spec.name = name;
        sim.world.command_exit = .{ .exited = 1 };
        try testing.expectError(error.Failed, run_streaming(&spec, true));
        var expected: [256]u8 = undefined;
        const lines = try std.fmt.bufPrint(
            &expected,
            "{0s} | compiling\n{0s} | second\n{0s} | warn: x\n{0s} | no newline\n",
            .{name},
        );
        try testing.expectEqualStrings(lines, sim.stderr());
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        var log: [128]u8 = undefined;
        const log_format = store_root ++ "/build/logs/" ++ group ++ "/{s}.log";
        const log_text = text_of(&log, log_format, .{name});
        try testing.expectEqualStrings(
            "compiling\nsecond\nwarn: x\nno newline",
            files.content_of(log_text).?,
        );
    }
}

test "a stderr that returns EPIPE stops the streaming and never fails the step" {
    // Goal: `zbx build --verbose 2>&1 | head` must not kill zbx or fail the build. Method:
    // every write to stderr fails with EPIPE (the simulator notes whether SIGPIPE was ignored
    // when that happened); the step still succeeds, its output is imported and its log is whole.
    const fixture = try setup(40, "fetch");
    const chunks = [_]sim_world.OutChunk{
        .{ .stream = .stdout, .bytes = "one\n" },
        .{ .stream = .stdout, .bytes = "two\n" },
    };
    set_output(&chunks);
    var output: Output = .{};
    arm(&output);
    sim.faults.write_error_per_mille = 1000;
    sim.faults.write_fault_stream = .stderr;
    sim.faults.write_errno = sim_world.errno_pipe;
    const spec = spec_for(&fixture);
    try run_streaming(&spec, true);
    try testing.expectEqual(@as(?codes.Code, null), diag.code);
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqualStrings("one\ntwo\n", files.content_of(log_path).?);
    try testing.expect(!sim.sigpipe_would_kill);
    try testing.expect(!sim.world.broken_pipe_ignored); // Back to the default at the end.
}

test {
    _ = @import("step_root_tests.zig");
}
