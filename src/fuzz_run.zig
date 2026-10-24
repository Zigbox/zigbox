//! The run fuzzer: `zig build fuzz -- run`. It runs `zbx run` from the command line down against
//! the simulated host, with a failure injected into one chosen step of the plan (or none), and
//! checks the three properties docs/briefs/M1-shell.md asks of the setup:
//!
//!   1. the parent reports exactly one coded diagnostic, and it names the step that failed;
//!   2. nothing leaked onto the host model: no mount, no hostname change, no process left
//!      unreaped, no descriptor held, SIGPIPE as it was;
//!   3. the exit code matches the blame of the diagnostic (or, when the command ran, is its own).
//!
//! The oracle is independent of the code under test: it knows which code each kind of step
//! should give (E0203 for the namespaces and their maps, E0202 for the command, E0205 for the
//! rest, nothing for the one step that may fail) and reads the output by its text, not by the
//! renderer's own functions. A run with no injected failure must succeed, and a container that
//! started must look the way the plan promises (sim_run.started).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const host_sim = @import("host_sim.zig");
const codes = @import("diag/codes.zig");
const render = @import("diag/render.zig");
const diag_fuzz = @import("fuzz_diag.zig");
const plan_mod = @import("runtime/plan.zig");
const sim_run = @import("runtime/sim_run.zig");
const repeat = @import("test_util.zig").repeat;

const HostSim = host_sim.HostSim;

const CommandShape = enum { shell_path, shell_bare, shell_args, missing_path, missing_bare };

const NameShape = enum { none, valid, invalid };

const RootfsShape = enum { good, missing, a_file, empty, too_long };

const valid_names = [_][:0]const u8{ "a", "web-1", "0", "zbx-123456", repeat('n', 63) };
const invalid_names = [_][:0]const u8{ "", "Web", "a_b", "-a", "a-", repeat('a', 64), "\xc3\xa9" };

/// What the oracle expects of one run.
const Verdict = union(enum) {
    /// The command started and ended with this status.
    started: host_mod.ExitStatus,
    /// A diagnostic with this code, and (for a failed step) the index of the step it must name.
    refused: struct { code: codes.Code, step: ?u32 },
};

const Scenario = struct {
    command: CommandShape,
    name: NameShape,
    name_text: [:0]const u8,
    rootfs: RootfsShape,
    term: bool,
    command_exit: host_mod.ExitStatus,
    fault_step: ?u32,
    fault_errno: u16,
    devpts_refused: bool,
    interrupts_per_mille: u16,
    short_writes: bool,
    uid: u32,
    gid: u32,
    verbose: bool,
    json: bool,
};

/// Errnos a step can fail with: the ones mounts, pipes, forks and execs really return.
const errnos = [_]u16{ 1, 2, 5, 11, 12, 13, 16, 19, 20, 22, 24, 28, 30, 38 };

fn random_scenario(random: std.Random) Scenario {
    var scenario: Scenario = undefined;
    scenario.command = random.enumValue(CommandShape);
    scenario.name = switch (random.uintLessThan(u8, 10)) {
        0...4 => .none,
        5...8 => .valid,
        else => .invalid,
    };
    scenario.name_text = switch (scenario.name) {
        .none => "",
        .valid => valid_names[random.uintLessThan(usize, valid_names.len)],
        .invalid => invalid_names[random.uintLessThan(usize, invalid_names.len)],
    };
    scenario.rootfs = if (random.uintLessThan(u8, 10) < 8) .good else random.enumValue(RootfsShape);
    scenario.term = random.boolean();
    scenario.command_exit = if (random.boolean())
        .{ .exited = random.int(u8) }
    else
        .{ .signaled = random.intRangeAtMost(u8, 1, 31) };
    scenario.fault_step = if (random.uintLessThan(u8, 4) == 0)
        null
    else
        random.uintLessThan(u32, plan_mod.steps_count);
    scenario.fault_errno = errnos[random.uintLessThan(usize, errnos.len)];
    scenario.devpts_refused = random.uintLessThan(u8, 4) == 0;
    scenario.interrupts_per_mille = if (random.boolean()) 0 else random.uintLessThan(u16, 200);
    scenario.short_writes = random.boolean();
    scenario.uid = ids[random.uintLessThan(usize, ids.len)];
    scenario.gid = ids[random.uintLessThan(usize, ids.len)];
    scenario.verbose = random.boolean();
    scenario.json = random.uintLessThan(u8, 4) == 0;
    return scenario;
}

const ids = [_]u32{ 0, 1, 1000, 65534, std.math.maxInt(u32) - 1 };

/// The exit code the oracle expects for a diagnostic: the blame decides, nothing else.
fn exit_for(code: codes.Code) u8 {
    return codes.exit_code(codes.entry(code).blame);
}

/// A plan for the oracle's own questions. Its steps are the same for every command and name.
fn oracle_plan(plan: *plan_mod.Plan) void {
    plan.build(&.{
        .rootfs = sim_run.rootfs_path,
        .name = "oracle",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
    });
}

/// The kind of step a plan has at `index`.
fn kind_at(index: u32) plan_mod.Kind {
    var plan: plan_mod.Plan = undefined;
    oracle_plan(&plan);
    assert(index < plan.count);
    return plan.steps[index].kind;
}

/// The index of the step that runs the command.
fn exec_index() u32 {
    var plan: plan_mod.Plan = undefined;
    oracle_plan(&plan);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == .exec) return @intCast(index);
    }
    unreachable; // Every plan has one.
}

/// What the run must do, decided from the scenario alone.
fn verdict_of(scenario: *const Scenario) Verdict {
    if (scenario.name == .invalid) return .{ .refused = .{ .code = .E0206, .step = null } };
    if (scenario.rootfs != .good) return .{ .refused = .{ .code = .E0201, .step = null } };
    const missing = scenario.command == .missing_path or scenario.command == .missing_bare;
    if (scenario.fault_step) |index| {
        const kind = kind_at(index);
        if (step_failure(scenario, kind)) |code| {
            return .{ .refused = .{ .code = code, .step = index } };
        }
    }
    if (missing) return .{ .refused = .{ .code = .E0202, .step = exec_index() } };
    return .{ .started = scenario.command_exit };
}

/// The code a fault in a step of `kind` gives, or null if the run goes on past it.
fn step_failure(scenario: *const Scenario, kind: plan_mod.Kind) ?codes.Code {
    switch (kind) {
        .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => return .E0203,
        .mount_pts => return null, // The one step that may fail: skipped with a note.
        .exec => {
            // A shell looks on: a missing or unrunnable first candidate is not the end while
            // another directory of PATH may have the program.
            const err = host_mod.error_for_errno(scenario.fault_errno);
            const looks_on = err == error.NotFound or err == error.AccessDenied;
            const bare = scenario.command == .shell_bare or scenario.command == .missing_bare;
            if (looks_on and bare) return null;
            return .E0202;
        },
        else => return .E0205,
    }
}

/// Whether the devpts mount was skipped: the model refused it, or a failure was injected into it.
fn devpts_skipped(scenario: *const Scenario) bool {
    if (scenario.devpts_refused) return true;
    const index = scenario.fault_step orelse return false;
    return kind_at(index) == .mount_pts;
}

fn command_words(scenario: *const Scenario, storage: *[3][:0]const u8) []const [:0]const u8 {
    switch (scenario.command) {
        .shell_path => storage[0] = "/bin/sh",
        .shell_bare => storage[0] = "sh",
        .shell_args => {
            storage.* = .{ "/bin/sh", "-c", "echo hi" };
            return storage[0..3];
        },
        .missing_path => storage[0] = "/bin/nothere",
        .missing_bare => storage[0] = "nothere",
    }
    return storage[0..1];
}

/// One byte past the longest rootfs. A container-level constant, so a slice of it is static.
const too_long_rootfs: [:0]const u8 = "/" ++ repeat('r', constants.rootfs_bytes_max);

fn rootfs_text(scenario: *const Scenario) [:0]const u8 {
    return switch (scenario.rootfs) {
        .good => sim_run.rootfs_path,
        .missing => "/srv/nope",
        .a_file => sim_run.regular_file_path,
        .empty => "",
        .too_long => too_long_rootfs,
    };
}

/// One run: set the simulator up, run the command line, and check everything.
pub fn fuzz_run(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const scenario = random_scenario(random);

    var sim: HostSim = undefined;
    sim_run.init(&sim, random.int(u64));
    sim.uid_value = scenario.uid;
    sim.gid_value = scenario.gid;
    sim.world.command_exit = scenario.command_exit;
    sim.world.devpts_refused = scenario.devpts_refused;
    sim.faults.interrupt_per_mille = scenario.interrupts_per_mille;
    if (scenario.short_writes) sim.faults.short_write_per_mille = 500;
    if (scenario.fault_step) |index| {
        sim.faults.fail_step = index;
        sim.faults.fail_step_errno = scenario.fault_errno;
    }
    const term = [_]host_sim.EnvironmentVariable{.{ .name = "TERM", .value = "xterm" }};
    if (scenario.term) sim.environment_variables = &term;
    const before = sim_run.baseline(&sim);

    var words_storage: [3][:0]const u8 = undefined;
    const words = command_words(&scenario, &words_storage);
    var args: [16][:0]const u8 = undefined;
    var count: usize = 0;
    const prefix = [_][:0]const u8{"zbx"};
    for (prefix) |item| push(&args, &count, item);
    if (scenario.verbose) push(&args, &count, "-v");
    if (scenario.json) {
        push(&args, &count, "--output");
        push(&args, &count, "json");
    }
    push(&args, &count, "run");
    if (scenario.rootfs == .empty) {
        push(&args, &count, "--rootfs=");
    } else {
        push(&args, &count, "--rootfs");
        push(&args, &count, rootfs_text(&scenario));
    }
    if (scenario.name != .none) {
        push(&args, &count, "--name");
        push(&args, &count, scenario.name_text);
    }
    push(&args, &count, "--");
    for (words) |word| push(&args, &count, word);
    const code = sim_run.run_cli(&sim, args[0..count]);

    check(&sim, &scenario, &before, code);
}

fn push(args: *[16][:0]const u8, count: *usize, item: [:0]const u8) void {
    args[count.*] = item;
    count.* += 1;
}

fn check(
    sim: *const HostSim,
    scenario: *const Scenario,
    before: *const sim_run.Baseline,
    code: u8,
) void {
    // Property 2, for every run: nothing leaked, however it ended.
    assert(sim_run.leak(sim, before) == null);
    assert(std.mem.indexOfScalar(u8, sim.stderr(), 0x1b) == null);
    assert(!render.contains_raw_error(sim.stderr()));
    assert(sim.stdout().len == 0); // zbx's own output; the container's goes to the real stdout.
    const found = diag_fuzz.find_diagnostics(sim.stderr());
    assert(found.unregistered == 0);
    switch (verdict_of(scenario)) {
        .started => |status| check_started(sim, scenario, status, found, code),
        .refused => |refusal| check_refused(sim, scenario, refusal.code, refusal.step, found, code),
    }
}

fn check_started(
    sim: *const HostSim,
    scenario: *const Scenario,
    status: host_mod.ExitStatus,
    found: diag_fuzz.Found,
    code: u8,
) void {
    // Property 3 when the command ran: its code, 128 plus the signal, never a zbx code mix-up.
    assert(found.count == 0);
    const expected: u8 = switch (status) {
        .exited => |n| n,
        .signaled => |n| constants.exit_signal_offset + n,
    };
    assert(code == expected);
    const name = sim.world.hostnames[sim.world.processes[1].uts].slice();
    if (scenario.name == .valid) assert(std.mem.eql(u8, name, scenario.name_text));
    if (scenario.name == .none) {
        assert(std.mem.startsWith(u8, name, constants.container_name_prefix));
    }
    const devpts = !devpts_skipped(scenario);
    assert(sim_run.started(sim, .{ .name = name, .devpts = devpts }) == null);
    check_started_output(sim, scenario, status);
}

fn check_started_output(
    sim: *const HostSim,
    scenario: *const Scenario,
    status: host_mod.ExitStatus,
) void {
    const stderr = sim.stderr();
    const skipped = std.mem.count(u8, stderr, "zbx: note: skipped");
    if (scenario.json) {
        assert(std.mem.startsWith(u8, stderr, "{\"container_exit\":{"));
        assert(std.mem.count(u8, stderr, "\n") == 1);
        return;
    }
    assert(skipped == @intFromBool(scenario.verbose and devpts_skipped(scenario)));
    const killed = std.mem.count(u8, stderr, "the container was killed by signal");
    assert(killed == @intFromBool(status == .signaled));
}

fn check_refused(
    sim: *const HostSim,
    scenario: *const Scenario,
    code: codes.Code,
    step: ?u32,
    found: diag_fuzz.Found,
    exit: u8,
) void {
    // Property 1: exactly one diagnostic, with the code the step's kind gives.
    assert(found.count == 1);
    assert(found.code.? == code);
    // Property 3: the blame decides the exit code, and nothing else does.
    assert(exit == exit_for(code));
    assert(exit != constants.exit_ok);
    assert(exit != constants.exit_internal);
    if (step == null) {
        // Refused before anything was created.
        assert(sim.world.processes[1].state == .unused);
        return;
    }
    // The diagnostic names the step in the output a person (or a script) can read. The default
    // text output leaves the context out; verbose and JSON show it.
    if (!scenario.verbose and !scenario.json) return;
    const kind = @tagName(kind_at(step.?));
    var needle: [96]u8 = undefined;
    const position = .{ kind, step.? + 1, plan_mod.steps_count };
    const text = if (scenario.json)
        std.fmt.bufPrint(&needle, "\"step\":\"{s} ({d} of {d})\"", position)
    else
        std.fmt.bufPrint(&needle, "\n  step   {s} ({d} of {d})\n", position);
    // Cannot fail: a kind name and two small numbers.
    const found_text = text catch unreachable;
    assert(std.mem.indexOf(u8, sim.stderr(), found_text) != null);
}
