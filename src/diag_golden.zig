//! Golden tests for diagnostics (DIAGNOSTICS.md, "Testing"): for every registered code, one case
//! triggers the condition through the real CLI against the simulated host and compares the
//! default, verbose and JSON output with the checked-in files in src/testdata/diag/.
//!
//! Changing a message means updating the golden file in the same commit. The files for a code
//! NAME are NAME.txt, NAME.verbose.txt and NAME.json.txt.
//!
//! A second test runs the same cases (and every doctor fixture) and fails if any output shows a
//! stack trace or a raw Zig error name. The goldens are also what the demo checks against.

const std = @import("std");
const assert = std.debug.assert;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const panic = @import("diag/panic.zig");
const render = @import("diag/render.zig");
const test_util = @import("test_util.zig");
const fixtures = @import("doctor_fixtures.zig");
const HostSim = @import("host_sim.zig").HostSim;

const testing = std.testing;

const Case = struct {
    code: codes.Code,
    /// The arguments after the program name, without the global options.
    args: []const [:0]const u8,
    /// Fail every write to stdout, as `> /dev/full` does.
    stdout_full: bool = false,
    /// The exit code the case must end with.
    exit: u8,
};

const many_arguments: [constants.args_count_max + 1][:0]const u8 = @splat("a");

/// One case per code that the command line can trigger. B0001 is a panic and has its own test.
const cases = [_]Case{
    .{ .code = .E0001, .args = &.{"frobnicate"}, .exit = 1 },
    .{ .code = .E0002, .args = &.{}, .exit = 1 },
    .{ .code = .E0003, .args = &.{ "help", "me" }, .exit = 1 },
    .{ .code = .E0004, .args = &.{"--frobnicate"}, .exit = 1 },
    .{ .code = .E0005, .args = &.{ "--output", "xml", "doctor" }, .exit = 1 },
    .{ .code = .E0006, .args = &.{"explain"}, .exit = 1 },
    .{ .code = .E0007, .args = &.{ "explain", "E9999" }, .exit = 1 },
    .{ .code = .E0008, .args = &many_arguments, .exit = 1 },
    .{ .code = .E0009, .args = &.{"help"}, .stdout_full = true, .exit = 2 },
};

const Style = enum { default, verbose, json };

/// Runs `case` with the global options for `style` placed before its arguments.
fn run_style(sim: *HostSim, case: *const Case, style: Style) !u8 {
    var items: [constants.args_count_max + 8][:0]const u8 = undefined;
    var count: u32 = 0;
    items[0] = "zbx";
    count += 1;
    const flags: []const [:0]const u8 = switch (style) {
        .default => &.{},
        .verbose => &.{"-v"},
        .json => &.{ "--output", "json" },
    };
    for (flags) |flag| {
        items[count] = flag;
        count += 1;
    }
    for (case.args) |argument| {
        items[count] = argument;
        count += 1;
    }
    sim.init(1, &.{});
    if (case.stdout_full) {
        sim.faults.write_error_per_mille = 1000;
        sim.faults.write_fault_stream = .stdout;
    }
    var iterator: SliceIterator = .{ .items = items[0..count] };
    const code = cli.run_from_iterator(sim.interface(), &iterator);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    pub fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

test "golden: every command line code in default, verbose and JSON output" {
    // Goal: the text of each diagnostic is part of the product. Method: trigger each code
    // through run_from_iterator and compare stderr byte for byte; stdout stays empty, the exit
    // code is the blame's, and the code in the header is the case's.
    var sim: HostSim = undefined;
    inline for (cases) |case| {
        const name = @tagName(case.code);
        const expected = [_][]const u8{
            @embedFile("testdata/diag/" ++ name ++ ".txt"),
            @embedFile("testdata/diag/" ++ name ++ ".verbose.txt"),
            @embedFile("testdata/diag/" ++ name ++ ".json.txt"),
        };
        for (std.enums.values(Style), expected) |style, golden| {
            const code = try run_style(&sim, &case, style);
            try testing.expectEqualStrings(golden, sim.stderr());
            try testing.expectEqual(case.exit, code);
            try testing.expectEqual(codes.exit_code(codes.entry(case.code).blame), code);
            try testing.expectEqual(@as(usize, 0), sim.stdout().len);
            const full = codes.full_name(case.code);
            try testing.expect(std.mem.indexOf(u8, sim.stderr(), full) != null);
            if (style == .json) {
                try testing.expect(try test_util.json_is_valid(std.mem.trimEnd(u8, golden, "\n")));
            }
        }
    }
}

test "golden: a panic, in default, verbose and JSON output" {
    // Goal: B0001 as the panic handler writes it. Method: call respond (the handler minus the
    // raw write and the exit) with a fixed message in each mode. The default text hides the
    // message; verbose and JSON show it; none shows a trace.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const message = "index out of bounds: index 5, len 3";
    const names = [_][]const u8{
        @embedFile("testdata/diag/B0001.txt"),
        @embedFile("testdata/diag/B0001.verbose.txt"),
        @embedFile("testdata/diag/B0001.json.txt"),
    };
    for ([_]render.Mode{ .text, .verbose, .json }, names) |mode, golden| {
        var state: panic.State = .{};
        panic.configure(&state, mode);
        const output = panic.respond(&state, message, &buffer).?;
        try testing.expectEqualStrings(golden, output);
        try testing.expect(!render.contains_raw_error(output));
    }
}

test "no raw errors: no diagnostic or doctor report shows a trace or a Zig error name" {
    // Goal: DIAGNOSTICS.md, "No stack traces for users". Method: every case in every style,
    // and the doctor against every fixture; neither stdout nor stderr may match the detector.
    var sim: HostSim = undefined;
    for (&cases) |*case| {
        for (std.enums.values(Style)) |style| {
            _ = try run_style(&sim, case, style);
            try testing.expect(!render.contains_raw_error(sim.stderr()));
            try testing.expect(!render.contains_raw_error(sim.stdout()));
        }
    }
    for (fixtures.all) |fixture| {
        sim.init(7, fixture.files);
        fixture.apply(&sim);
        var iterator: SliceIterator = .{ .items = &.{ "zbx", "-v", "doctor" } };
        _ = cli.run_from_iterator(sim.interface(), &iterator);
        try testing.expect(!render.contains_raw_error(sim.stderr()));
        try testing.expect(!render.contains_raw_error(sim.stdout()));
    }
}

test "every registered code has a case or is the panic" {
    // Goal: the registry cannot gain a code without a golden test. B0001 is covered by the
    // panic test above; the E01xx codes arrive with the doctor diagnostics in slice 5.
    for (codes.registry) |item| {
        if (item.code == .B0001) continue;
        const covered = for (cases) |case| {
            if (case.code == item.code) break true;
        } else false;
        try testing.expect(covered);
    }
}
