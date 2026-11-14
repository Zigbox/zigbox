//! Tests of `zigbox.build`, the library surface, from callers other than the command line: a
//! caller that brings its own memory, reads the build file, orders its steps, works out their
//! keys and drives them with the scheduler, through the names `zigbox.zig` exports and nothing
//! else (the simulated host and store, and the test fixtures that fill them, are the same ones
//! `pull_library_tests.zig` uses). They check that two callers on two threads share nothing and
//! agree on every key, that a refusal is a position and not a crash, that the scheduler runs a
//! caller's own executor, and that two callers on two threads each run a step with
//! `run_step` on a simulated store of their own, stream its output, and agree on the tree it
//! made. `run_step` is not exported (it starts its base ungated: `zigbox.zig`), so that test
//! reaches it through `build/step.zig`, as the command line does.

const std = @import("std");
const assert = std.debug.assert;
const zigbox = @import("zigbox.zig");
const sim_run = @import("runtime/sim_run.zig");
const sim_world = @import("sim_world.zig");
const support = @import("store/test_support.zig");
const step_file = @import("build/step.zig");

const testing = std.testing;
const build = zigbox.build;
const Digest = zigbox.store.Digest;
const HostSim = zigbox.host_sim.HostSim;
const SimFs = zigbox.store.fs_sim.SimFs;
const Diag = zigbox.diag.Diag;
const Facts = @typeInfo(std.meta.fieldInfo(build.step.Request, .facts).type).pointer.child;

/// A build file a caller of the library might read: two steps and an image.
const example =
    \\.{
    \\    .version = 1,
    \\    .steps = .{
    \\        .{ .name = "compile", .base = "alpine:3.20", .inputs = .{"a"}, .run = .{"true"} },
    \\        .{ .name = "notice", .base = "alpine:3.20", .inputs = .{"a"}, .run = .{"true"} },
    \\    },
    \\    .image = .{
    \\        .add = .{
    \\            .{ .from = "compile", .to = "/usr/bin" },
    \\            .{ .from = "notice", .to = "/etc" },
    \\        },
    \\    },
    \\}
    \\
;

/// Everything one caller of the library owns, on the heap: the file, its graph and its keys.
const Caller = struct {
    file: build.file.BuildFile,
    problem: build.file.Problem,
    graph: build.graph.Graph,
    graph_problem: build.graph.Problem,
    keys: [2]build.key.Key,
    ok: bool,

    fn create() !*Caller {
        const caller = try std.heap.page_allocator.create(Caller);
        caller.ok = false;
        return caller;
    }

    fn destroy(caller: *Caller) void {
        std.heap.page_allocator.destroy(caller);
    }

    /// The caller's whole job: read, order, and key each step with the input tree it chose.
    fn work(caller: *Caller, input: []const u8) void {
        const parsed = build.file.parse(example, &caller.file, &caller.problem);
        assert(parsed == .parsed);
        const ordered = build.graph.order(&caller.file, &caller.graph, &caller.graph_problem);
        assert(ordered == .ordered);
        for (caller.graph.order_slice(), 0..) |index, at| {
            const step = &caller.file.steps[index];
            const spec: build.key.Spec = .{
                .platform = "linux/amd64",
                .base_tree = Digest.of("base"),
                .base_env = &.{"PATH=/usr/bin:/bin"},
                .input_tree = Digest.of(input),
                .needs = &.{},
                .argv = &.{ "/bin/sh", "-c", "true" },
                .env = &.{},
                .network = step.network,
                .name = caller.file.text(step.name),
            };
            build.key.compute(&spec, &caller.keys[at]) catch unreachable; // Short spec.
        }
        caller.ok = true;
    }
};

fn work_on(caller: *Caller, input: []const u8) void {
    caller.work(input);
}

test "two callers on two threads read, order and key the same file alike" {
    // Goal: the library keeps no state of its own. Method: two callers, two threads, the same
    // file and the same inputs; the orders and the keys agree. A third with another input tree
    // gets other keys, so the keys are not constant.
    const first = try Caller.create();
    defer first.destroy();
    const second = try Caller.create();
    defer second.destroy();
    const third = try Caller.create();
    defer third.destroy();
    const thread = try std.Thread.spawn(.{}, work_on, .{ second, "tree" });
    first.work("tree");
    thread.join();
    third.work("other tree");
    try testing.expect(first.ok and second.ok and third.ok);
    try testing.expectEqualSlices(u8, first.graph.order_slice(), second.graph.order_slice());
    for (first.keys, second.keys, third.keys) |a, b, c| {
        try testing.expect(a.digest.eql(b.digest));
        try testing.expect(!a.digest.eql(c.digest));
    }
}

test "a refused file is a position, and the caller's memory is reusable" {
    // Goal: a caller feeding bad text gets the problem's place, not a crash. Method: parse a
    // broken file, then the good one into the same memory; the second parse is whole.
    const caller = try Caller.create();
    defer caller.destroy();
    const bad = build.file.parse(".{ .steps = .{ 1 } }", &caller.file, &caller.problem);
    try testing.expect(bad == .refused);
    try testing.expectEqual(@as(u32, 1), caller.problem.line);
    caller.work("tree");
    try testing.expect(caller.ok);
}

/// A caller's own executor: every step runs and ends in the order it began.
const Counting = struct {
    began: u8 = 0,
    ended: u8 = 0,

    fn begin(context: *anyopaque, index: u8) build.schedule.Error!build.schedule.Begin {
        const counting: *Counting = @ptrCast(@alignCast(context));
        _ = index;
        counting.began += 1;
        return .running;
    }

    fn wait(context: *anyopaque) build.schedule.Error!build.schedule.Ended {
        const counting: *Counting = @ptrCast(@alignCast(context));
        assert(counting.ended < counting.began);
        counting.ended += 1;
        return .{ .index = counting.ended - 1, .ok = true };
    }

    fn abort(context: *anyopaque) void {
        _ = context;
        unreachable;
    }
};

test "the scheduler drives an executor the caller wrote" {
    // Goal: `build.schedule.run` needs nothing of the CLI. Method: a plan of three independent
    // steps and a bound of one; the caller's executor sees three starts and three ends.
    var plan: build.schedule.Plan = undefined;
    plan.count = 3;
    plan.order[0..3].* = .{ 0, 1, 2 };
    plan.needs_count[0..3].* = .{ 0, 0, 0 };
    var counting: Counting = .{};
    const result = build.schedule.run(&plan, 1, .{
        .context = &counting,
        .begin = Counting.begin,
        .wait = Counting.wait,
        .abort = Counting.abort,
    });
    try testing.expect(result.failed == null);
    try testing.expectEqual(@as(u8, 3), result.built);
    try testing.expectEqual(@as(u8, 3), counting.ended);
}

const store_root = support.user_store;
const state_root = "/home/alice/.local/state/zbx/containers";
const work_root = store_root ++ "/build/work";
const log_group = "0123456789abcdef";
const directory_mode: u32 = 0o040755;

/// Everything one caller that runs a step owns, on the heap (a step's workspace is large): its
/// simulated host and store, the store's two trees (the base with a shell, the step's input),
/// and what it got back.
const StepCaller = struct {
    sim: HostSim,
    twin: HostSim,
    files: SimFs,
    disk: SimFs,
    store: zigbox.store.Store,
    workspace: build.step.Workspace,
    facts: Facts,
    result: build.step.Result,
    diag: Diag,
    host_files: [sim_run.files.len + 2]zigbox.host_sim.File,
    farm_text: [512]u8,
    out_text: [512]u8,
    base: Digest,
    input: Digest,
    ok: bool,

    fn create() !*StepCaller {
        const caller = try std.heap.page_allocator.create(StepCaller);
        caller.ok = false;
        return caller;
    }

    fn destroy(caller: *StepCaller) void {
        std.heap.page_allocator.destroy(caller);
    }

    fn import_tree(caller: *StepCaller) Digest {
        var imported: zigbox.store.import.Result = undefined;
        caller.diag.reset();
        const options: zigbox.store.import.Options = .{ .squash_owner = false, .warn = null };
        zigbox.store.import.import(
            &caller.store,
            &caller.workspace.import,
            "/src",
            options,
            &imported,
            &caller.diag,
        ) catch unreachable; // The sample tree imports.
        return imported.digest;
    }

    /// The caller's world: a store holding the base and the input, and the directories the
    /// container model binds (as `step_tests.zig` sets them up, for the same reasons).
    fn setup(caller: *StepCaller, seed: u64) void {
        sim_run.init(&caller.sim, seed);
        caller.files.init(seed);
        caller.sim.store_fs = &caller.files;
        caller.disk.init(seed);
        caller.disk.put_dir("/home", 0o755);
        caller.disk.put_dir("/home/alice", 0o755);
        caller.sim.log_fs = &caller.disk;
        support.make_user_store(&caller.files, ".{\n    .format = 1,\n}\n");
        support.make_source(&caller.files, 0);
        caller.store.at(caller.sim.interface(), store_root);
        caller.base = caller.import_tree();
        caller.files.put_file("/src/main.c", 0o644, "int main;\n");
        caller.input = caller.import_tree();
        assert(!caller.base.eql(caller.input));
        // The container's name is made from the host's first random bytes: a twin with the same
        // seed says it before the step runs.
        sim_run.init(&caller.twin, seed);
        var random: [8]u8 = undefined;
        caller.twin.interface().random_bytes(&random) catch unreachable; // The sim has bytes.
        const hex = std.fmt.bytesToHex(random, .lower);
        var name: [64]u8 = undefined;
        // 12 + 16 bytes fit in 64.
        const text = std.fmt.bufPrint(&name, "build-fetch-{s}", .{&hex}) catch unreachable;
        caller.world_dirs(text);
    }

    fn world_dirs(caller: *StepCaller, name: []const u8) void {
        const sim = &caller.sim;
        var path: [256]u8 = undefined;
        const merged = text_of(&path, state_root ++ "/{s}/merged", .{name});
        sim.world.add_node(merged, .dir);
        var inner: [300]u8 = undefined;
        sim.world.add_node(text_of(&inner, state_root ++ "/{s}/net", .{name}), .dir);
        for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin", "/src", "/out", "/in" }) |tail| {
            sim.world.add_node(text_of(&inner, "{s}{s}", .{ merged, tail }), .dir);
        }
        for ([_][]const u8{ "/bin/sh", "/etc/hosts", "/etc/resolv.conf", "/etc/hostname" }) |tail| {
            sim.world.add_node(text_of(&inner, "{s}{s}", .{ merged, tail }), .file);
        }
        var farm: zigbox.store.fs.PathBuf = undefined;
        _ = zigbox.store.materialize.farm_path(&caller.store, &farm, caller.input);
        @memcpy(caller.farm_text[0..farm.len], farm.text());
        const out = text_of(&caller.out_text, work_root ++ "/{s}/out", .{name});
        sim.world.add_node(farm.text(), .dir);
        sim.world.add_node(out, .dir);
        caller.host_files[0..sim_run.files.len].* = sim_run.files;
        caller.host_files[sim_run.files.len] = .{
            .path = caller.farm_text[0..farm.len],
            .content = "",
            .mode = directory_mode,
        };
        caller.host_files[sim_run.files.len + 1] = .{
            .path = out,
            .content = "",
            .mode = directory_mode,
        };
        sim.files = &caller.host_files;
    }

    /// What the command leaves in `/out`, written just before the log is renamed into place.
    fn write_output(context: *anyopaque) void {
        const caller: *StepCaller = @ptrCast(@alignCast(context));
        var index: u32 = 0;
        while (caller.files.alive_path(index)) |path| : (index += 1) {
            if (!std.mem.startsWith(u8, path, work_root ++ "/")) continue;
            if (!std.mem.endsWith(u8, path, "/out")) continue;
            var made: [512]u8 = undefined;
            caller.files.put_dir(text_of(&made, "{s}/bin", .{path}), 0o755);
            caller.files.put_file(text_of(&made, "{s}/bin/tool", .{path}), 0o755, "#!tool\n");
            caller.files.put_file(text_of(&made, "{s}/README", .{path}), 0o644, "built\n");
            return;
        }
        unreachable; // The step's `out` exists when its command has ended.
    }

    /// The caller's whole job: one step through `run_step`, streaming.
    fn work(caller: *StepCaller, seed: u64) void {
        caller.setup(seed);
        const chunks = [_]sim_world.OutChunk{
            .{ .stream = .stdout, .bytes = "compiling\n" },
            .{ .stream = .stderr, .bytes = "done\n" },
        };
        caller.sim.world.out_script = &chunks;
        caller.sim.world.out_at = 0;
        caller.files.hook = .{
            .rename_to_contains = "fetch.log",
            .context = caller,
            .call = write_output,
        };
        const spec: build.key.Spec = .{
            .platform = "linux/amd64",
            .base_tree = caller.base,
            .base_env = &.{"PATH=/usr/bin:/bin"},
            .input_tree = caller.input,
            .needs = &.{},
            .argv = &.{ "/bin/sh", "-c", "make" },
            .env = &.{},
            .network = false,
            .name = "fetch",
        };
        const request: build.step.Request = .{
            .host = caller.sim.interface(),
            .facts = &caller.facts,
            .spec = &spec,
            .file = "zbx.build.zon",
            .group = log_group,
            .stream = true,
        };
        caller.diag.reset();
        step_file.run_step(&request, &caller.workspace, &caller.result, &caller.diag) catch return;
        caller.ok = true;
    }
};

fn text_of(buffer: []u8, comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(buffer, format, args) catch unreachable; // Short test paths.
}

fn step_on(caller: *StepCaller, seed: u64) void {
    caller.work(seed);
}

test "two callers on two threads each run a step on a store of their own and agree on its tree" {
    // Goal: `run_step` works for a caller that is not the command line, and shares
    // nothing between callers. Method: two callers, two threads, a simulated host and store each
    // (different seeds, so different container names); each streams the step, which writes the
    // same three entries to `/out`. Each must succeed, show its output on its own stderr behind
    // `fetch | ` with nothing on stdout, and make the same tree.
    const first = try StepCaller.create();
    defer first.destroy();
    const second = try StepCaller.create();
    defer second.destroy();
    const thread = try std.Thread.spawn(.{}, step_on, .{ second, 2 });
    first.work(1);
    thread.join();
    for ([_]*StepCaller{ first, second }) |caller| {
        try testing.expect(caller.ok);
        try testing.expectEqual(@as(u64, 2), caller.result.files);
        try testing.expectEqualStrings("fetch | compiling\nfetch | done\n", caller.sim.stderr());
        try testing.expectEqual(@as(usize, 0), caller.sim.stdout().len);
    }
    try testing.expect(first.result.output.eql(second.result.output));
}
