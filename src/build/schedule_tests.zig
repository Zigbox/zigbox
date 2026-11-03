//! The scheduler over random graphs with a fake executor (docs/briefs/M7-build.md, slice 3):
//! no step starts before its needs, the bound is used fully and never exceeded, a hit starts
//! nothing, a failure starts nothing new and the first failure to end is the build's, a failed
//! start or wait is handled (a failed wait aborts what runs), and the outputs are a function of
//! the graph and the steps' outcomes only, whatever order the running steps end in.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const schedule = @import("schedule.zig");

const testing = std.testing;

const steps_max = constants.build_steps_max;

/// What a step does: found cached, runs and succeeds, runs and fails, or fails to start.
const Outcome = enum { hit, ok, fail, begin_fail };

const Fake = struct {
    plan: *const schedule.Plan,
    random: std.Random,
    bound: u8,
    outcome: [steps_max]Outcome,
    running: [steps_max]bool,
    done: [steps_max]bool,
    began: [steps_max]bool,
    output: [steps_max]u64,
    running_count: u8,
    /// The step that failed first, by the order the failures happened in (a failed start, or a
    /// failed step's end): the scheduler must name this one.
    first_failed: ?u8,
    began_after_failure: bool,
    began_before_needs: bool,
    over_bound: bool,
    under_used: bool,
    ended_unstarted: bool,
    begin_order: [steps_max]u8,
    begin_count: u8,
    ended_ok: u8,
    hits_began: u8,
    /// The wait call (counted from 0) that fails; null: none does.
    wait_fails_at: ?u32,
    waits: u32,
    aborts: u32,

    fn output_of(fake: *const Fake, step: u8) u64 {
        var hasher = std.hash.Wyhash.init(step);
        for (fake.plan.needs_of(step)) |need| hasher.update(std.mem.asBytes(&fake.output[need]));
        return hasher.final();
    }

    fn needs_done(fake: *const Fake, step: u8) bool {
        for (fake.plan.needs_of(step)) |need| {
            if (!fake.done[need]) return false;
        }
        return true;
    }

    fn begin(context: *anyopaque, index: u8) schedule.Error!schedule.Begin {
        const fake: *Fake = @ptrCast(@alignCast(context));
        if (fake.first_failed != null) fake.began_after_failure = true;
        if (!fake.needs_done(index)) fake.began_before_needs = true;
        assert(!fake.began[index]);
        fake.began[index] = true;
        fake.begin_order[fake.begin_count] = index;
        fake.begin_count += 1;
        switch (fake.outcome[index]) {
            .hit => {
                fake.done[index] = true;
                fake.output[index] = fake.output_of(index);
                fake.hits_began += 1;
                return .hit;
            },
            .begin_fail => {
                fake.first_failed = fake.first_failed orelse index;
                return error.Failed;
            },
            .ok, .fail => {
                fake.running[index] = true;
                fake.running_count += 1;
                if (fake.running_count > fake.bound) fake.over_bound = true;
                return .running;
            },
        }
    }

    /// The bound is used fully while a step could start: when the scheduler waits, either the
    /// bound's worth runs or no step is both unstarted and ready (and nothing has failed).
    fn check_use(fake: *Fake) void {
        if (fake.first_failed != null) return;
        if (fake.running_count == fake.bound) return;
        for (0..fake.plan.count) |step| {
            if (!fake.began[step] and fake.needs_done(@intCast(step))) fake.under_used = true;
        }
    }

    fn wait(context: *anyopaque) schedule.Error!schedule.Ended {
        const fake: *Fake = @ptrCast(@alignCast(context));
        assert(fake.running_count > 0);
        fake.check_use();
        defer fake.waits += 1;
        if (fake.wait_fails_at == fake.waits) return error.Failed;
        // Any running step may end first.
        var pick = fake.random.uintLessThan(u8, fake.running_count);
        for (0..fake.plan.count) |step| {
            if (!fake.running[step]) continue;
            if (pick > 0) {
                pick -= 1;
                continue;
            }
            // Only a step that began as running can end: a hit never ran.
            if (!fake.began[step]) fake.ended_unstarted = true;
            fake.running[step] = false;
            fake.running_count -= 1;
            const index: u8 = @intCast(step);
            if (fake.outcome[step] == .fail) {
                fake.first_failed = fake.first_failed orelse index;
                return .{ .index = index, .ok = false };
            }
            fake.done[step] = true;
            fake.output[step] = fake.output_of(index);
            fake.ended_ok += 1;
            return .{ .index = index, .ok = true };
        }
        unreachable;
    }

    fn abort(context: *anyopaque) void {
        const fake: *Fake = @ptrCast(@alignCast(context));
        assert(fake.running_count > 0);
        fake.aborts += 1;
        fake.running = @splat(false);
        fake.running_count = 0;
    }
};

/// A random graph: step i may need any earlier step (up to the needs bound); the order is the
/// index order, with neighbours swapped where they do not depend on each other. Mostly small,
/// and sometimes as big as a build file can be.
fn random_plan(random: std.Random, plan: *schedule.Plan) void {
    const big = random.uintLessThan(u8, 40) == 0;
    plan.count = if (big) steps_max else random.intRangeAtMost(u8, 1, 14);
    for (0..plan.count) |step| {
        var count: u8 = 0;
        for (0..step) |earlier| {
            if (count < constants.build_step_needs_max and random.uintLessThan(u8, 4) == 0) {
                plan.needs[step][count] = @intCast(earlier);
                count += 1;
            }
        }
        plan.needs_count[step] = count;
    }
    for (0..plan.count) |step| plan.order[step] = @intCast(step);
    // Swap neighbours that do not depend on each other: still topological.
    for (0..4 * @as(usize, plan.count)) |_| {
        const at = random.uintLessThan(u8, plan.count);
        if (at + 1 >= plan.count) continue;
        const first = plan.order[at];
        const second = plan.order[at + 1];
        const depends = for (plan.needs_of(second)) |need| {
            if (need == first) break true;
        } else false;
        if (!depends) {
            plan.order[at] = second;
            plan.order[at + 1] = first;
        }
    }
}

fn fake_for(plan: *const schedule.Plan, random: std.Random, bound: u8) Fake {
    return .{
        .plan = plan,
        .random = random,
        .bound = bound,
        .outcome = @splat(.ok),
        .running = @splat(false),
        .done = @splat(false),
        .began = @splat(false),
        .output = @splat(0),
        .running_count = 0,
        .first_failed = null,
        .began_after_failure = false,
        .began_before_needs = false,
        .over_bound = false,
        .under_used = false,
        .ended_unstarted = false,
        .begin_order = @splat(0),
        .begin_count = 0,
        .ended_ok = 0,
        .hits_began = 0,
        .wait_fails_at = null,
        .waits = 0,
        .aborts = 0,
    };
}

fn executor(fake: *Fake) schedule.Executor {
    return .{ .context = fake, .begin = Fake.begin, .wait = Fake.wait, .abort = Fake.abort };
}

/// What every step's output must be, worked out in index order (every step needs only earlier
/// ones), with no scheduler: the oracle for a build that succeeded.
fn oracle_outputs(fake: *const Fake, expected: *[steps_max]u64) void {
    var again = fake.*;
    for (0..fake.plan.count) |step| {
        again.output[step] = again.output_of(@intCast(step));
        expected[step] = again.output[step];
    }
}

fn expect_guarantees(fake: *const Fake, result: schedule.Outcome) !void {
    const plan = fake.plan;
    try testing.expect(!fake.began_before_needs);
    try testing.expect(!fake.over_bound);
    try testing.expect(!fake.under_used);
    try testing.expect(!fake.ended_unstarted);
    try testing.expect(!fake.began_after_failure);
    try testing.expectEqual(@as(u8, 0), fake.running_count);
    // The first failure by time is the build's, not one a later wait happened to find.
    try testing.expectEqual(fake.first_failed, result.failed);
    // A hit counts when it began, a build when it ended well; nothing is counted twice.
    try testing.expectEqual(fake.hits_began, result.hits);
    try testing.expectEqual(fake.ended_ok, result.built);
    // With one worker the starts are the plan's order, as far as the build got.
    if (fake.bound == 1) {
        const started = plan.order[0..fake.begin_count];
        try testing.expectEqualSlices(u8, started, fake.begin_order[0..fake.begin_count]);
    }
    if (result.failed == null and !result.aborted) {
        for (0..plan.count) |step| try testing.expect(fake.done[step]);
        try testing.expectEqual(plan.count, result.hits + result.built);
        var expected: [steps_max]u64 = undefined;
        oracle_outputs(fake, &expected);
        try testing.expectEqualSlices(u64, expected[0..plan.count], fake.output[0..plan.count]);
    }
}

test "random graphs: order, bound, hits, failures and outputs hold over a sweep of seeds" {
    // Goal: the scheduler's guarantees hold for any graph, bound, outcome and ending order.
    // Method: 3000 seeds; graphs of 1 to 14 steps, now and then 64; hits, failed steps, failed
    // starts and failed waits injected; `expect_guarantees` checks each run against the fake's
    // own record of what happened, and successful ones against an oracle for the outputs.
    var seed: u64 = 1;
    var aborted: u32 = 0;
    var failed_start: u32 = 0;
    while (seed <= 3000) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        var plan: schedule.Plan = undefined;
        random_plan(random, &plan);
        try testing.expect(plan.valid());
        const bound = random.intRangeAtMost(u8, 1, constants.build_parallel_max);
        var fake = fake_for(&plan, random, bound);
        const with_failure = random.uintLessThan(u8, 3) == 0;
        for (0..plan.count) |step| {
            const roll = random.uintLessThan(u8, 20);
            fake.outcome[step] = if (roll < 6) .hit else .ok;
            if (with_failure and roll == 19) fake.outcome[step] = .fail;
            if (with_failure and roll == 18) fake.outcome[step] = .begin_fail;
        }
        if (random.uintLessThan(u8, 8) == 0) fake.wait_fails_at = random.uintLessThan(u32, 4);
        const result = schedule.run(&plan, bound, executor(&fake));
        try expect_guarantees(&fake, result);
        if (result.aborted) {
            aborted += 1;
            try testing.expectEqual(@as(u32, 1), fake.aborts);
        } else {
            try testing.expectEqual(@as(u32, 0), fake.aborts);
        }
        if (result.failed) |step| {
            if (fake.outcome[step] == .begin_fail) failed_start += 1;
        }
    }
    // The sweep reaches the paths it exists for.
    try testing.expect(aborted > 0);
    try testing.expect(failed_start > 0);
}

test "one worker builds in the plan's order" {
    // Goal: with a bound of 1 the scheduler is the serial loop of slice 2. Method: a plan whose
    // order is not the index order; the fake's record of starts is that order exactly.
    var plan: schedule.Plan = undefined;
    plan.count = 3;
    plan.order[0..3].* = .{ 1, 0, 2 };
    plan.needs_count[0..3].* = .{ 0, 0, 2 };
    plan.needs[2][0] = 0;
    plan.needs[2][1] = 1;
    var prng = std.Random.DefaultPrng.init(7);
    var fake = fake_for(&plan, prng.random(), 1);
    const result = schedule.run(&plan, 1, executor(&fake));
    try testing.expect(result.failed == null);
    try testing.expectEqual(@as(u8, 3), result.built);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 2 }, fake.begin_order[0..3]);
}

test "a failed start is the build's failure and starts nothing new" {
    // Goal: `begin` that errors (the executor has said why) stops the build. Method: the
    // second step cannot start; the first, already running, is waited for; the third never begins.
    var plan: schedule.Plan = undefined;
    plan.count = 3;
    plan.order[0..3].* = .{ 0, 1, 2 };
    plan.needs_count[0..3].* = .{ 0, 0, 0 };
    var prng = std.Random.DefaultPrng.init(3);
    var fake = fake_for(&plan, prng.random(), 4);
    fake.outcome[1] = .begin_fail;
    const result = schedule.run(&plan, 4, executor(&fake));
    try testing.expectEqual(@as(?u8, 1), result.failed);
    try testing.expect(!result.aborted);
    try testing.expectEqual(@as(u8, 1), result.built);
    try testing.expect(!fake.began[2]);
    try testing.expectEqual(@as(u8, 0), fake.running_count);
}

test "a failed wait aborts what runs and blames no step" {
    // Goal: no worker outlives a build whose wait failed. Method: four running steps, the first
    // wait fails; the fake's abort is called once and leaves nothing running.
    var plan: schedule.Plan = undefined;
    plan.count = 5;
    for (0..5) |step| plan.order[step] = @intCast(step);
    plan.needs_count[0..5].* = .{ 0, 0, 0, 0, 0 };
    var prng = std.Random.DefaultPrng.init(5);
    var fake = fake_for(&plan, prng.random(), 4);
    fake.wait_fails_at = 0;
    const result = schedule.run(&plan, 4, executor(&fake));
    try testing.expect(result.aborted);
    try testing.expect(result.failed == null);
    try testing.expectEqual(@as(u32, 1), fake.aborts);
    try testing.expectEqual(@as(u8, 0), fake.running_count);
    try testing.expect(!fake.began[4]);
}

test "the biggest graphs: 64 steps, wide and as a chain, at the bound" {
    // Goal: the bounds hold at `build_steps_max`. Method: 64 steps with no needs at each bound
    // (the bound is used fully: `expect_guarantees` checks it), and 64 in a chain.
    var plan: schedule.Plan = undefined;
    plan.count = steps_max;
    for (0..steps_max) |step| plan.order[step] = @intCast(step);
    @memset(plan.needs_count[0..steps_max], 0);
    var prng = std.Random.DefaultPrng.init(11);
    for (1..constants.build_parallel_max + 1) |bound| {
        var fake = fake_for(&plan, prng.random(), @intCast(bound));
        const result = schedule.run(&plan, @intCast(bound), executor(&fake));
        try expect_guarantees(&fake, result);
        try testing.expectEqual(@as(u8, steps_max), result.built);
    }
    for (1..steps_max) |step| {
        plan.needs[step][0] = @intCast(step - 1);
        plan.needs_count[step] = 1;
    }
    var chain = fake_for(&plan, prng.random(), constants.build_parallel_max);
    const result = schedule.run(&plan, constants.build_parallel_max, executor(&chain));
    try expect_guarantees(&chain, result);
    try testing.expectEqual(@as(u8, steps_max), result.built);
}
