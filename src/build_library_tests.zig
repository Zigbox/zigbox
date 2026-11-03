//! Tests of `zigbox.build`, the library surface, from callers other than the command line: a
//! caller that brings its own memory, reads the build file, orders its steps, works out their
//! keys and drives them with the scheduler, through the names `zigbox.zig` exports and nothing
//! else. They check that two callers on two threads share nothing and agree on every key, that a
//! refusal is a position and not a crash, and that the scheduler runs a caller's own executor.
//! Running a step is `step_tests.zig`'s (it needs the simulated store); the second caller does
//! not run one, which `docs/demos/m7.md` records.

const std = @import("std");
const assert = std.debug.assert;
const zigbox = @import("zigbox.zig");
const file_tests = @import("build/file_tests.zig");
const Digest = @import("store/digest.zig").Digest;

const testing = std.testing;
const build = zigbox.build;

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
        const parsed = build.file.parse(file_tests.example, &caller.file, &caller.problem);
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
