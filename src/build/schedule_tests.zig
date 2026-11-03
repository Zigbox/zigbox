//! The scheduler over random graphs with a fake executor (docs/briefs/M7-build.md, slice 3):
//! no step starts before its needs, never more than the bound run at once, a hit starts
//! nothing, a failure starts nothing new, and the outputs are a function of the graph and the
//! steps' outcomes only, whatever order the running steps end in.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const schedule = @import("schedule.zig");

const testing = std.testing;

const Outcome = enum { hit, ok, fail };

const Fake = struct {
    plan: *const schedule.Plan,
    random: std.Random,
    bound: u8,
    outcome: [constants.build_steps_max]Outcome,
    running: [constants.build_steps_max]bool,
    done: [constants.build_steps_max]bool,
    began: [constants.build_steps_max]bool,
    output: [constants.build_steps_max]u64,
    running_count: u8,
    failed_seen: bool,
    began_after_failure: bool,
    began_before_needs: bool,
    over_bound: bool,
    hit_ran: bool,

    fn output_of(fake: *const Fake, step: u8) u64 {
        var hasher = std.hash.Wyhash.init(step);
        for (fake.plan.needs_of(step)) |need| hasher.update(std.mem.asBytes(&fake.output[need]));
        return hasher.final();
    }

    fn begin(context: *anyopaque, index: u8) schedule.Error!schedule.Begin {
        const fake: *Fake = @ptrCast(@alignCast(context));
        if (fake.failed_seen) fake.began_after_failure = true;
        for (fake.plan.needs_of(index)) |need| {
            if (!fake.done[need]) fake.began_before_needs = true;
        }
        assert(!fake.began[index]);
        fake.began[index] = true;
        switch (fake.outcome[index]) {
            .hit => {
                fake.done[index] = true;
                fake.output[index] = fake.output_of(index);
                return .hit;
            },
            .ok, .fail => {
                fake.running[index] = true;
                fake.running_count += 1;
                if (fake.running_count > fake.bound) fake.over_bound = true;
                return .running;
            },
        }
    }

    fn wait(context: *anyopaque) schedule.Error!schedule.Ended {
        const fake: *Fake = @ptrCast(@alignCast(context));
        assert(fake.running_count > 0);
        // Any running step may end first.
        var pick = fake.random.uintLessThan(u8, fake.running_count);
        for (0..fake.plan.count) |step| {
            if (!fake.running[step]) continue;
            if (pick > 0) {
                pick -= 1;
                continue;
            }
            // Only a step that began as running can end: a hit never ran.
            if (fake.outcome[step] == .hit) fake.hit_ran = true;
            fake.running[step] = false;
            fake.running_count -= 1;
            const index: u8 = @intCast(step);
            if (fake.outcome[step] == .fail) {
                fake.failed_seen = true;
                return .{ .index = index, .ok = false };
            }
            fake.done[step] = true;
            fake.output[step] = fake.output_of(index);
            return .{ .index = index, .ok = true };
        }
        unreachable;
    }
};

/// A random graph: step i may need any earlier step (up to the needs bound); the order is the
/// index order, with ties broken by a shuffle of the ready steps (here, a random valid order).
fn random_plan(random: std.Random, plan: *schedule.Plan) void {
    plan.count = random.intRangeAtMost(u8, 1, 14);
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
    for (0..40) |_| {
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
        .failed_seen = false,
        .began_after_failure = false,
        .began_before_needs = false,
        .over_bound = false,
        .hit_ran = false,
    };
}

fn executor(fake: *Fake) schedule.Executor {
    return .{ .context = fake, .begin = Fake.begin, .wait = Fake.wait };
}

test "random graphs: order, bound, hits, failures and outputs hold over a sweep of seeds" {
    // Goal: the scheduler's guarantees hold for any graph, bound, outcome and ending order.
    var seed: u64 = 1;
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
            const roll = random.uintLessThan(u8, 10);
            const fails = with_failure and roll == 9;
            fake.outcome[step] = if (roll < 3) .hit else if (fails) .fail else .ok;
        }
        const result = schedule.run(&plan, bound, executor(&fake));
        try testing.expect(!fake.began_before_needs);
        try testing.expect(!fake.over_bound);
        try testing.expect(!fake.began_after_failure);
        try testing.expectEqual(@as(u8, 0), fake.running_count);
        if (result.failed == null) {
            for (0..plan.count) |step| try testing.expect(fake.done[step]);
            try testing.expectEqual(plan.count, result.hits + result.built);
            // The same graph and outcomes with one worker and another ending order: the same
            // outputs.
            var again = fake_for(&plan, random, 1);
            again.outcome = fake.outcome;
            const serial = schedule.run(&plan, 1, executor(&again));
            try testing.expect(serial.failed == null);
            const want = fake.output[0..plan.count];
            try testing.expectEqualSlices(u64, want, again.output[0..plan.count]);
        } else {
            try testing.expect(fake.outcome[result.failed.?] == .fail);
        }
        // A hit never runs: every step the fake counted as a hit was never `running`.
        try testing.expect(!fake.hit_ran);
    }
}

test "one worker builds in the plan's order" {
    // Goal: with a bound of 1 the scheduler is the serial loop of slice 2.
    var plan: schedule.Plan = undefined;
    plan.count = 3;
    plan.order[0..3].* = .{ 1, 0, 2 };
    plan.needs_count[0..3].* = .{ 0, 0, 2 };
    plan.needs[2][0] = 0;
    plan.needs[2][1] = 1;
    var prng = std.Random.DefaultPrng.init(7);
    var fake = fake_for(&plan, prng.random(), 1);
    for (0..3) |step| fake.outcome[step] = .ok;
    const result = schedule.run(&plan, 1, executor(&fake));
    try testing.expect(result.failed == null);
    try testing.expectEqual(@as(u8, 3), result.built);
}
