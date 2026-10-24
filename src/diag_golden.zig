//! Golden tests for diagnostics (DIAGNOSTICS.md, "Testing"): for every registered code, one case
//! triggers the condition through the real CLI against the simulated host and compares the
//! default, verbose and JSON output with the checked-in files in src/testdata/diag/. A doctor
//! code (E01xx) is triggered by a named fixture, and its golden is that code's block among the
//! blocks the doctor writes.
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
const plan_mod = @import("runtime/plan.zig");
const sim_run = @import("runtime/sim_run.zig");
const HostSim = @import("host_sim.zig").HostSim;

const testing = std.testing;

const Case = struct {
    code: codes.Code,
    /// The arguments after the program name, without the global options.
    args: []const [:0]const u8,
    /// Fail every write to stdout, as `> /dev/full` does.
    stdout_full: bool = false,
    /// The name of a doctor fixture (doctor_fixtures.zig) to run against; null for no files.
    fixture: ?[]const u8 = null,
    /// Sets the simulator up after it is initialised (a container host and a failure to inject).
    prepare: ?*const fn (sim: *HostSim) void = null,
    /// The command writes its result to stdout (a path), so stdout is not empty.
    prints: bool = false,
    /// The code is a warning: the run goes on, so the exit code is the command's, not the blame's.
    warning: bool = false,
    /// The exit code the case must end with.
    exit: u8,
};

/// The index of the first step of `kind` in a plan for a host that maps a full range of ids.
fn step_of(kind: plan_mod.Kind) u32 {
    return sim_run.step_index(kind, true);
}

fn prepare_container(sim: *HostSim) void {
    sim_run.init(sim, 1);
}

fn prepare_helper_refuses(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.helper_fails_with = 1;
}

fn prepare_single(sim: *HostSim) void {
    sim_run.init_single(sim, 1);
}

fn prepare_disk_full(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.disk_full = true;
}

/// A runs directory over the limit, with a record that is damaged and one from a newer zbx.
fn prepare_records_unreadable(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.add_node(sim_run.runs_path, .dir);
    const future = ".{\n    .version = 9,\n    .name = \"future\",\n    .started = 5,\n}\n";
    assert(sim.world.write_file(sim_run.runs_path ++ "/damaged.zon", "garbage") == null);
    assert(sim.world.write_file(sim_run.runs_path ++ "/future.zon", future) == null);
    for (0..constants.runs_max - 1) |number| {
        var path: [64]u8 = undefined;
        const format = sim_run.runs_path ++ "/old-{d:0>2}.zon";
        const where = std.fmt.bufPrint(&path, format, .{number}) catch unreachable; // Short.
        var body: [96]u8 = undefined;
        const text = ".{{\n    .name = \"old-{d:0>2}\",\n    .started = {d},\n}}\n";
        const args = .{ number, 1000 + number };
        // Cannot fail: the body is a few dozen bytes.
        const record = std.fmt.bufPrint(&body, text, args) catch unreachable;
        assert(sim.world.write_file(where, record) == null);
    }
}

fn prepare_proc_refused(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.faults.fail_step = step_of(.mount_proc);
    sim.faults.fail_step_errno = 1; // EPERM
}

/// Ubuntu 24.04 as installed: AppArmor restricts user namespaces, so clone3 is refused.
const run_restricted = fixtures.build(.{
    .name = "run_restricted",
    .apparmor_restrict = "1\n",
    .probes = .{ .userns = .denied, .overlay = .setup_denied },
    .extra_files = &sim_run.extra_files,
});

fn prepare_namespaces_refused(sim: *HostSim) void {
    sim.init(1, run_restricted.files);
    run_restricted.apply(sim);
    sim.world.seed_container_host(sim_run.rootfs_path);
    sim.world.add_node(sim_run.home_path, .dir);
    sim.environment_variables = &sim_run.env_home;
    sim.faults.fail_step = step_of(.spawn);
    sim.faults.fail_step_errno = 13; // EACCES
}

const many_arguments: [constants.args_count_max + 1][:0]const u8 = @splat("a");

/// One case per code that the command line can trigger. B0001 is a panic and has its own test.
const cases = base_cases ++ bundle_cases;

const base_cases = [_]Case{
    .{ .code = .E0001, .args = &.{"frobnicate"}, .exit = 1 },
    .{ .code = .E0002, .args = &.{}, .exit = 1 },
    .{ .code = .E0003, .args = &.{ "help", "me" }, .exit = 1 },
    .{ .code = .E0004, .args = &.{"--frobnicate"}, .exit = 1 },
    .{ .code = .E0005, .args = &.{ "--output", "xml", "doctor" }, .exit = 1 },
    .{ .code = .E0006, .args = &.{"explain"}, .exit = 1 },
    .{ .code = .E0007, .args = &.{ "explain", "E9999" }, .exit = 1 },
    .{ .code = .E0008, .args = &many_arguments, .exit = 1 },
    .{ .code = .E0009, .args = &.{"help"}, .stdout_full = true, .exit = 2 },
    .{ .code = .E0101, .args = &.{"doctor"}, .fixture = "ubuntu_2404_restricted", .exit = 2 },
    .{ .code = .E0102, .args = &.{"doctor"}, .fixture = "old_kernel", .exit = 2 },
    .{ .code = .E0103, .args = &.{"doctor"}, .fixture = "cgroup_missing_controllers", .exit = 2 },
    .{ .code = .E0104, .args = &.{"doctor"}, .fixture = "overlay_denied", .exit = 2 },
    .{ .code = .E0105, .args = &.{"doctor"}, .fixture = "subid_missing_entry", .exit = 2 },
    .{ .code = .E0106, .args = &.{"doctor"}, .fixture = "seccomp_absent", .exit = 2 },
    .{
        .code = .E0201,
        .args = &.{ "run", "--rootfs", "./alpine", "--", "/bin/sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .E0202,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/nothere" },
        .prepare = prepare_container,
        .exit = 127,
    },
    .{
        .code = .E0203,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_namespaces_refused,
        .exit = 125,
    },
    .{
        .code = .E0204,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_helper_refuses,
        .exit = 125,
    },
    .{
        .code = .E0205,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_proc_refused,
        .exit = 125,
    },
    .{
        .code = .E0206,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "Web_1", "--", "/bin/sh" },
        .prepare = prepare_container,
        .exit = 125,
    },
    .{
        .code = .W0201,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_single,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0202,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_disk_full,
        .warning = true,
        .exit = 0,
    },
    .{
        .code = .W0203,
        .args = &.{ "run", "--rootfs", "/srv/alpine", "--name", "web-1", "--", "/bin/sh" },
        .prepare = prepare_records_unreadable,
        .warning = true,
        .exit = 0,
    },
};

fn prepare_no_state(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.environment_variables = &.{};
}

fn prepare_with_record(sim: *HostSim) void {
    sim_run.init(sim, 1);
    sim.world.now = 1_792_873_384;
    sim_run.put_record(sim, &sim_run.sample_view("web-1", 1_792_873_000));
}

fn prepare_bundle_disk_full(sim: *HostSim) void {
    prepare_with_record(sim);
    sim.world.disk_full = true;
}

const bundle_cases = [_]Case{
    .{ .code = .E0701, .args = &.{ "bundle", "--last" }, .prepare = prepare_no_state, .exit = 2 },
    .{
        .code = .E0702,
        .args = &.{ "bundle", "--last" },
        .prepare = prepare_bundle_disk_full,
        .exit = 2,
    },
    .{ .code = .E0703, .args = &.{ "bundle", "nothere" }, .prepare = prepare_container, .exit = 1 },
    .{ .code = .E0704, .args = &.{ "bundle", "--last" }, .prepare = prepare_container, .exit = 1 },
    .{
        .code = .W0701,
        .args = &.{ "bundle", "--last", "--no-redact" },
        .prepare = prepare_with_record,
        .prints = true,
        .warning = true,
        .exit = 0,
    },
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
    if (case.fixture) |name| {
        const fixture = fixtures.find(name).?;
        sim.init(1, fixture.files);
        fixture.apply(sim);
    }
    if (case.prepare) |prepare| prepare(sim);
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

/// The part of the doctor's stderr that is the diagnostic of `code`: its block in text, its
/// line in JSON. Blocks are separated by a blank line and JSON objects by a newline.
fn block_of(stderr: []const u8, code: codes.Code, style: Style) []const u8 {
    const full = codes.full_name(code);
    var header_storage: [32]u8 = undefined;
    const header = switch (style) {
        .json => std.fmt.bufPrint(&header_storage, "{{\"code\":\"{s}\"", .{full}),
        else => std.fmt.bufPrint(&header_storage, "error[{s}]", .{full}),
    } catch unreachable; // A code is nine bytes.
    var start: usize = 0;
    while (start < stderr.len) {
        const end = std.mem.indexOfScalarPos(u8, stderr, start, '\n').? + 1;
        if (std.mem.startsWith(u8, stderr[start..], header)) {
            if (style == .json) return stderr[start..end];
            const blank = std.mem.indexOfPos(u8, stderr, start, "\n\n");
            return stderr[start..if (blank) |at| at + 1 else stderr.len];
        }
        start = end;
    }
    unreachable; // The case's fixture is chosen to raise this code.
}

test "golden: every code in default, verbose and JSON output" {
    // Goal: the text of each diagnostic is part of the product. Method: trigger each code
    // through run_from_iterator (the E01xx ones by a doctor fixture) and compare stderr, or the
    // code's block of it, byte for byte; the exit code is the blame's, and the code in the
    // header is the case's. A command line code leaves stdout empty; a doctor code leaves the
    // report there, with the code on its FAIL line.
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
            const shown = if (case.fixture == null) sim.stderr() else block_of(
                sim.stderr(),
                case.code,
                style,
            );
            try testing.expectEqualStrings(golden, shown);
            try testing.expectEqual(case.exit, code);
            const is_run = case.args.len > 0 and std.mem.eql(u8, case.args[0], "run");
            if (!case.warning and !is_run) {
                try testing.expectEqual(codes.exit_code(codes.entry(case.code).blame), code);
            }
            if (!case.warning and is_run) try testing.expect(code >= 125);
            const full = codes.full_name(case.code);
            if (case.prints) {
                try testing.expect(sim.stdout().len > 0);
            } else if (case.fixture == null) {
                try testing.expectEqual(@as(usize, 0), sim.stdout().len);
            } else {
                var tag: [16]u8 = undefined;
                const line_end = try std.fmt.bufPrint(&tag, "  [{s}]\n", .{full});
                try testing.expect(std.mem.indexOf(u8, sim.stdout(), line_end) != null);
            }
            try testing.expect(std.mem.indexOf(u8, sim.stderr(), full) != null);
            if (style == .json) {
                // One JSON object per line: a warning, then the run's end, are two lines.
                var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, golden, "\n"), '\n');
                while (lines.next()) |line| try testing.expect(try test_util.json_is_valid(line));
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
        panic.configure(&state, mode, .standard);
        const output = panic.respond(&state, message, &buffer).?;
        try testing.expectEqualStrings(golden, output);
        try testing.expect(!render.contains_raw_error(output));
        try testing.expectEqual(@as(u8, 70), panic.exit_code(&state));
        // A panic on a `zbx run` line is 125, so it cannot be mistaken for a container's 70.
        var run_state: panic.State = .{};
        panic.configure(&run_state, mode, .container_run);
        try testing.expectEqual(@as(u8, 125), panic.exit_code(&run_state));
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
    const doctor_args = [_][]const [:0]const u8{
        &.{ "zbx", "doctor" },
        &.{ "zbx", "-v", "doctor" },
        &.{ "zbx", "--output", "json", "doctor" },
    };
    for (fixtures.all) |fixture| {
        for (doctor_args) |args| {
            sim.init(7, fixture.files);
            fixture.apply(&sim);
            var iterator: SliceIterator = .{ .items = args };
            _ = cli.run_from_iterator(sim.interface(), &iterator);
            try testing.expect(!render.contains_raw_error(sim.stderr()));
            try testing.expect(!render.contains_raw_error(sim.stdout()));
        }
    }
    // The host with no files at all is a doctor case of its own (not a fixture).
    for (doctor_args) |args| {
        sim.init(7, &.{});
        var iterator: SliceIterator = .{ .items = args };
        _ = cli.run_from_iterator(sim.interface(), &iterator);
        try testing.expect(!render.contains_raw_error(sim.stderr()));
        try testing.expect(!render.contains_raw_error(sim.stdout()));
    }
}

test "every registered code has a case or is the panic" {
    // Goal: the registry cannot gain a code without a golden test. B0001 is covered by the
    // panic test above; every E01xx code is triggered by a doctor fixture.
    for (codes.registry) |item| {
        if (item.code == .B0001) continue;
        const covered = for (cases) |case| {
            if (case.code == item.code) break true;
        } else false;
        try testing.expect(covered);
    }
}
