//! The step graph of a build file: what only the whole file can tell. Every `needs` entry and
//! every `add.from` must name a step of the file, a step name is used once, and the steps must
//! not need themselves round a cycle. `order` checks all of it and gives the steps in
//! topological order, ties broken by name, which is the order `zbx build --graph` prints and the
//! order a build would start them in on one core. A cycle is named, as the steps in it in need
//! order (`a -> b -> a`: a needs b, b needs a), starting at the smallest name in it.
//!
//! Steps are indexes into the file's steps (`u8`: at most `build_steps_max`). The work is
//! quadratic in the steps, which is at most 64.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("file.zig");

const BuildFile = file_mod.BuildFile;
const Text = file_mod.Text;

comptime {
    assert(constants.build_steps_max <= std.math.maxInt(u8));
}

pub const ProblemKind = enum {
    /// Two steps have the same name; `step` is the second, `other` the first.
    duplicate_step,
    /// `step` needs a name that no step has (`at` is the entry).
    unknown_need,
    /// `step` lists the same need twice.
    need_twice,
    /// An `image.add` takes from a name that no step has.
    unknown_add,
    /// The steps in `cycle` need each other round.
    cycle,
};

pub const Problem = struct {
    kind: ProblemKind,
    /// The step the problem is in (not for `unknown_add`).
    step: u8,
    other: u8,
    /// The text the problem points at: a name, a need, an add's `from`.
    at: Text,
    /// For `cycle`: the steps in it, in need order, without the first repeated at the end.
    cycle: [constants.build_steps_max]u8,
    cycle_len: u8,

    pub fn cycle_slice(problem: *const Problem) []const u8 {
        assert(problem.kind == .cycle);
        assert(problem.cycle_len >= 1);
        return problem.cycle[0..problem.cycle_len];
    }
};

pub const Graph = struct {
    /// Each step's needs, as step indexes, in the file's order.
    needs: [constants.build_steps_max][constants.build_step_needs_max]u8,
    /// The steps in topological order.
    order: [constants.build_steps_max]u8,
    count: u8,
    /// Each add's step.
    adds: [constants.build_image_adds_max]u8,
    adds_count: u8,

    pub fn order_slice(graph: *const Graph) []const u8 {
        assert(graph.count <= constants.build_steps_max);
        return graph.order[0..graph.count];
    }

    pub fn needs_slice(graph: *const Graph, file: *const BuildFile, step: u8) []const u8 {
        assert(step < file.steps_count);
        return graph.needs[step][0..file.steps[step].needs.count];
    }
};

pub const Result = enum { ordered, refused };

/// Checks the graph of a parsed `file` and orders it into `graph`; on a refusal, `problem` says
/// what and where.
pub fn order(file: *const BuildFile, graph: *Graph, problem: *Problem) Result {
    assert(file.steps_count <= constants.build_steps_max);
    assert(file.version == file_mod.version);
    graph.count = 0;
    graph.adds_count = 0;
    if (check_names(file, problem) == .refused) return .refused;
    if (resolve_needs(file, graph, problem) == .refused) return .refused;
    if (resolve_adds(file, graph, problem) == .refused) return .refused;
    var done: [constants.build_steps_max]bool = @splat(false);
    while (graph.count < file.steps_count) {
        const next = smallest_ready(file, graph, &done) orelse {
            name_cycle(file, graph, &done, problem);
            return .refused;
        };
        done[next] = true;
        graph.order[graph.count] = next;
        graph.count += 1;
    }
    assert(graph.count == file.steps_count);
    return .ordered;
}

/// The step named `name`, or null.
pub fn step_named(file: *const BuildFile, name: []const u8) ?u8 {
    assert(file.steps_count <= constants.build_steps_max);
    for (file.steps_slice(), 0..) |*step, index| {
        if (std.mem.eql(u8, file.text(step.name), name)) return @intCast(index);
    }
    return null;
}

fn check_names(file: *const BuildFile, problem: *Problem) Result {
    const steps = file.steps_slice();
    for (steps, 0..) |*step, index| {
        const first = step_named(file, file.text(step.name)).?;
        assert(first <= index);
        if (first != index) {
            refuse(problem, .duplicate_step, @intCast(index), first, step.name);
            return .refused;
        }
    }
    return .ordered;
}

fn resolve_needs(file: *const BuildFile, graph: *Graph, problem: *Problem) Result {
    for (file.steps_slice(), 0..) |*step, index| {
        const needs = step.needs.slice();
        assert(needs.len <= constants.build_step_needs_max);
        for (needs, 0..) |need, need_index| {
            const target = step_named(file, file.text(need)) orelse {
                refuse(problem, .unknown_need, @intCast(index), 0, need);
                return .refused;
            };
            for (graph.needs[index][0..need_index]) |earlier| {
                if (earlier == target) {
                    refuse(problem, .need_twice, @intCast(index), target, need);
                    return .refused;
                }
            }
            graph.needs[index][need_index] = target;
        }
    }
    return .ordered;
}

fn resolve_adds(file: *const BuildFile, graph: *Graph, problem: *Problem) Result {
    for (file.adds_slice()) |add| {
        const target = step_named(file, file.text(add.from)) orelse {
            refuse(problem, .unknown_add, 0, 0, add.from);
            return .refused;
        };
        graph.adds[graph.adds_count] = target;
        graph.adds_count += 1;
    }
    assert(graph.adds_count == file.image.adds_count);
    return .ordered;
}

fn refuse(problem: *Problem, kind: ProblemKind, step: u8, other: u8, at: Text) void {
    assert(kind != .cycle);
    assert(at.line >= 1);
    problem.* = .{
        .kind = kind,
        .step = step,
        .other = other,
        .at = at,
        .cycle = undefined,
        .cycle_len = 0,
    };
}

/// Of the steps not done whose needs are all done, the one with the smallest name.
fn smallest_ready(file: *const BuildFile, graph: *const Graph, done: []const bool) ?u8 {
    assert(done.len == constants.build_steps_max);
    var best: ?u8 = null;
    for (0..file.steps_count) |index_usize| {
        const index: u8 = @intCast(index_usize);
        if (done[index]) continue;
        const ready = for (graph.needs_slice(file, index)) |need| {
            if (!done[need]) break false;
        } else true;
        if (!ready) continue;
        if (best == null or name_less(file, index, best.?)) best = index;
    }
    return best;
}

fn name_less(file: *const BuildFile, a: u8, b: u8) bool {
    assert(a < file.steps_count);
    assert(b < file.steps_count);
    return std.mem.lessThan(u8, file.text(file.steps[a].name), file.text(file.steps[b].name));
}

/// Every step not done needs one not done, so walking from the smallest name to its smallest
/// unmet need, again and again, comes back to a step already walked: that loop is the cycle.
fn name_cycle(
    file: *const BuildFile,
    graph: *const Graph,
    done: []const bool,
    problem: *Problem,
) void {
    var walk: [constants.build_steps_max]u8 = undefined;
    var position: [constants.build_steps_max]?u8 = @splat(null);
    var length: u8 = 0;
    var current = smallest_not_done(file, done);
    while (position[current] == null) {
        position[current] = length;
        walk[length] = current;
        length += 1;
        current = smallest_unmet_need(file, graph, done, current);
    }
    const cycle = walk[position[current].?..length];
    assert(cycle.len >= 1);
    // Rotate it to start at its smallest name.
    var start: usize = 0;
    for (cycle, 0..) |step, index| {
        if (name_less(file, step, cycle[start])) start = index;
    }
    problem.* = .{
        .kind = .cycle,
        .step = cycle[start],
        .other = cycle[(start + 1) % cycle.len],
        .at = undefined,
        .cycle = undefined,
        .cycle_len = @intCast(cycle.len),
    };
    for (0..cycle.len) |index| problem.cycle[index] = cycle[(start + index) % cycle.len];
    problem.at = need_text(file, graph, problem.step, problem.other);
}

fn smallest_not_done(file: *const BuildFile, done: []const bool) u8 {
    var best: ?u8 = null;
    for (0..file.steps_count) |index| {
        if (done[index]) continue;
        if (best == null or name_less(file, @intCast(index), best.?)) best = @intCast(index);
    }
    assert(best != null);
    return best.?;
}

fn smallest_unmet_need(
    file: *const BuildFile,
    graph: *const Graph,
    done: []const bool,
    step: u8,
) u8 {
    var best: ?u8 = null;
    for (graph.needs_slice(file, step)) |need| {
        if (done[need]) continue;
        if (best == null or name_less(file, need, best.?)) best = need;
    }
    assert(best != null); // A step not done and not ready has a need not done.
    return best.?;
}

/// The entry of `step`'s needs that names `need`.
fn need_text(file: *const BuildFile, graph: *const Graph, step: u8, need: u8) Text {
    for (graph.needs_slice(file, step), 0..) |target, index| {
        if (target == need) return file.steps[step].needs.items[index];
    }
    unreachable; // `need` was taken from `step`'s needs.
}

const testing = std.testing;

var test_file: BuildFile = undefined;
var test_graph: Graph = undefined;

/// Parses a file of steps given as `name:need,need` words, then orders it.
fn order_steps(comptime steps: []const []const u8, problem: *Problem) !Result {
    comptime var text: []const u8 = ".{ .version = 1, .image = .{}, .steps = .{\n";
    inline for (steps) |spec| {
        comptime var parts = std.mem.splitScalar(u8, spec, ':');
        const name = comptime parts.next().?;
        const needs = comptime parts.next() orelse "";
        comptime var quoted: []const u8 = "";
        comptime var names = std.mem.tokenizeScalar(u8, needs, ',');
        inline while (comptime names.next()) |need| quoted = quoted ++ "\"" ++ need ++ "\",";
        text = text ++ ".{ .name = \"" ++ name ++ "\", .base = \"a\", .run = .{\"x\"}, " ++
            ".needs = .{" ++ quoted ++ "} },\n";
    }
    text = text ++ "} }";
    var parse_problem: file_mod.Problem = undefined;
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(text, &test_file, &parse_problem),
    );
    return order(&test_file, &test_graph, problem);
}

fn expect_order(comptime steps: []const []const u8, expected: []const []const u8) !void {
    var problem: Problem = undefined;
    try testing.expectEqual(Result.ordered, try order_steps(steps, &problem));
    try testing.expectEqual(expected.len, test_graph.count);
    for (expected, test_graph.order_slice()) |name, step| {
        try testing.expectEqualStrings(name, test_file.text(test_file.steps[step].name));
    }
}

fn expect_cycle(comptime steps: []const []const u8, expected: []const []const u8) !void {
    var problem: Problem = undefined;
    try testing.expectEqual(Result.refused, try order_steps(steps, &problem));
    try testing.expectEqual(ProblemKind.cycle, problem.kind);
    try testing.expectEqual(expected.len, problem.cycle_len);
    for (expected, problem.cycle_slice()) |name, step| {
        try testing.expectEqualStrings(name, test_file.text(test_file.steps[step].name));
    }
    try testing.expectEqualStrings(expected[1 % expected.len], test_file.text(problem.at));
}

test "steps come in need order, ties broken by name" {
    // Goal: the order is topological and, among the ready steps, by name; the file's order
    // does not matter. Method: a diamond written backwards, independent steps, no steps.
    try expect_order(&.{ "d:b,c", "c:a", "b:a", "a" }, &.{ "a", "b", "c", "d" });
    try expect_order(
        &.{ "zeta", "alpha", "mid:zeta", "beta" },
        &.{ "alpha", "beta", "zeta", "mid" },
    );
    try expect_order(&.{ "b:z", "z", "a:b" }, &.{ "z", "b", "a" });
    try expect_order(&.{}, &.{});
}

test "a cycle is named in need order from its smallest name" {
    // Goal: the cycle, and only the cycle, is named, whatever leads into it. Method: a self
    // need, two steps, three steps entered from a step outside the cycle.
    try expect_cycle(&.{"a:a"}, &.{"a"});
    try expect_cycle(&.{ "b:a", "a:b" }, &.{ "a", "b" });
    try expect_cycle(&.{ "a:x", "x:z", "z:y", "y:x", "ok" }, &.{ "x", "z", "y" });
}

test "a graph is refused for a duplicate step, an unknown need or add, a need twice" {
    // Goal: the negative space of the graph. Method: one file per refusal.
    var problem: Problem = undefined;
    try testing.expectEqual(Result.refused, try order_steps(&.{ "a", "b", "a" }, &problem));
    try testing.expectEqual(ProblemKind.duplicate_step, problem.kind);
    try testing.expectEqual(@as(u8, 2), problem.step);
    try testing.expectEqual(@as(u8, 0), problem.other);
    try testing.expectEqual(Result.refused, try order_steps(&.{ "a:b", "c" }, &problem));
    try testing.expectEqual(ProblemKind.unknown_need, problem.kind);
    try testing.expectEqualStrings("b", test_file.text(problem.at));
    try testing.expectEqual(Result.refused, try order_steps(&.{ "a:b,b", "b" }, &problem));
    try testing.expectEqual(ProblemKind.need_twice, problem.kind);
    try testing.expectEqual(@as(u32, 60), problem.at.column);
    var parse_problem: file_mod.Problem = undefined;
    const text = ".{ .version = 1, .image = .{ .add = .{ .{ .from = \"nope\", .to = \"/\" } } } }";
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(text, &test_file, &parse_problem),
    );
    try testing.expectEqual(Result.refused, order(&test_file, &test_graph, &problem));
    try testing.expectEqual(ProblemKind.unknown_add, problem.kind);
    try testing.expectEqualStrings("nope", test_file.text(problem.at));
}
