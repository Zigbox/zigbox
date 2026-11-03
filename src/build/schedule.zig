//! The scheduler of `zbx build` (docs/briefs/M7-build.md, "Running the graph"): which steps start
//! when. It is a pure loop over an `Executor` that does the work, so the real executor (worker
//! processes waited on with pidfds, `compose.zig`) and a test's fake one run the same code.
//!
//! - A step starts only when every step it needs is done, and at most `bound` run at once.
//! - `begin` may answer `hit`: the step is done at once and nothing ran.
//! - After a failure nothing new starts; the steps already running are waited for, and the first
//!   failure to end is the build's.
//! - A wait that fails cannot say which worker ended: the executor aborts every running worker
//!   (kills, reaps, closes) and the build is `aborted`, with the executor's diagnostic.
//! - Steps are tried in the plan's order (topological, ties by name), so a run with one worker
//!   builds exactly what the serial loop of slice 2 built, in the same order.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Error = error{Failed};

/// The graph as the scheduler needs it: `order` is a topological order of `count` steps.
pub const Plan = struct {
    count: u8,
    order: [constants.build_steps_max]u8,
    needs: [constants.build_steps_max][constants.build_step_needs_max]u8,
    needs_count: [constants.build_steps_max]u8,

    pub fn needs_of(plan: *const Plan, step: u8) []const u8 {
        assert(step < plan.count);
        return plan.needs[step][0..plan.needs_count[step]];
    }

    /// Whether `order` is a topological order of the needs, each step once.
    pub fn valid(plan: *const Plan) bool {
        var seen: [constants.build_steps_max]bool = @splat(false);
        for (plan.order[0..plan.count]) |step| {
            if (step >= plan.count or seen[step]) return false;
            for (plan.needs_of(step)) |need| {
                if (need >= plan.count or !seen[need]) return false;
            }
            seen[step] = true;
        }
        return true;
    }
};

pub const Begin = enum { hit, running };

pub const Ended = struct {
    index: u8,
    ok: bool,
};

pub const Executor = struct {
    context: *anyopaque,
    /// Starts step `index` (or finds it cached). Error: it failed before it ran, and the
    /// executor has said why.
    begin: *const fn (context: *anyopaque, index: u8) Error!Begin,
    /// Blocks until one running step ends; the executor records its output if it succeeded.
    wait: *const fn (context: *anyopaque) Error!Ended,
    /// Ends every running step, reaped and its resources released, after a `wait` that failed.
    /// Called at most once, and only with steps running; it cannot fail (best effort).
    abort: *const fn (context: *anyopaque) void,
};

pub const Outcome = struct {
    /// The first step to end in failure, or whose start failed, if any.
    failed: ?u8,
    /// A wait failed and the running steps were aborted; no step is to blame.
    aborted: bool,
    hits: u8,
    built: u8,
};

const State = enum(u8) { pending, running, done, failed };

pub fn run(plan: *const Plan, bound: u8, executor: Executor) Outcome {
    assert(plan.valid());
    assert(bound >= 1);
    assert(bound <= constants.build_parallel_max);
    var state: [constants.build_steps_max]State = @splat(.pending);
    var outcome: Outcome = .{ .failed = null, .aborted = false, .hits = 0, .built = 0 };
    var running: u8 = 0;
    var finished: u8 = 0;
    // Each pass either starts a step or waits for one, so the loop is bounded by twice the steps.
    for (0..2 * @as(usize, plan.count) + 2) |_| {
        var progress = true;
        while (progress and outcome.failed == null) {
            progress = false;
            for (plan.order[0..plan.count]) |step| {
                if (outcome.failed != null or running == bound) break;
                if (state[step] != .pending) continue;
                if (!ready(plan, &state, step)) continue;
                const began = executor.begin(executor.context, step) catch {
                    state[step] = .failed;
                    outcome.failed = step;
                    break;
                };
                progress = true;
                switch (began) {
                    .hit => {
                        state[step] = .done;
                        outcome.hits += 1;
                        finished += 1;
                    },
                    .running => {
                        state[step] = .running;
                        running += 1;
                    },
                }
            }
        }
        if (running == 0) break;
        const ended = executor.wait(executor.context) catch {
            // A wait that cannot say which step ended: the build stops, and every worker still
            // running is ended, so none outlives the build. No step is blamed.
            executor.abort(executor.context);
            running = 0;
            outcome.aborted = true;
            break;
        };
        assert(ended.index < plan.count);
        assert(state[ended.index] == .running);
        running -= 1;
        if (ended.ok) {
            state[ended.index] = .done;
            outcome.built += 1;
            finished += 1;
        } else {
            state[ended.index] = .failed;
            outcome.failed = outcome.failed orelse ended.index;
        }
        if (finished == plan.count) break;
    }
    if (running != 0) assert(outcome.failed != null);
    if (outcome.aborted) assert(running == 0);
    return outcome;
}

fn ready(plan: *const Plan, state: *const [constants.build_steps_max]State, step: u8) bool {
    for (plan.needs_of(step)) |need| {
        if (state[need] != .done) return false;
    }
    return true;
}

comptime {
    assert(constants.build_parallel_max >= 1);
    assert(constants.build_steps_max <= std.math.maxInt(u8));
}
