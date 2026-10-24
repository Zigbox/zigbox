//! The run fuzzer: `zig build fuzz -- run`. It runs `zbx run` from the command line down against
//! the simulated host, with a failure injected into one chosen step of the plan (or none), and
//! checks the three properties docs/briefs/M1-shell.md asks of the setup:
//!
//!   1. the parent reports one coded diagnostic for the failure, and it names the step that
//!      failed;
//!   2. nothing leaked onto the host model: mounts, hostname, unreaped children, descriptors,
//!      SIGPIPE;
//!   3. the exit code is the blame's, or, when the command ran, its own (128+s for a signal).
//!
//! Around those it varies what slice 2 added: a host that can map a full range of ids or cannot
//! (and then must warn), helpers that refuse, signals that arrive while the command runs (and a
//! PID 1 that handles some of them), a state directory that is full, missing, or holds too many
//! records and some that cannot be read. Every run must also leave the run record, and the
//! warnings, that the scenario implies.
//!
//! The oracle is independent of the code under test: it knows which code each kind of step
//! should give, the order in which things fail (the parent's early steps, then the child's, then
//! the wait), and reads the output by its text, not by the renderer's own functions.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const host_sim = @import("host_sim.zig");
const codes = @import("diag/codes.zig");
const render = @import("diag/render.zig");
const diag_fuzz = @import("fuzz_diag.zig");
const plan_mod = @import("runtime/plan.zig");
const records = @import("runtime/records.zig");
const sim_run = @import("runtime/sim_run.zig");
const repeat = @import("test_util.zig").repeat;

const HostSim = host_sim.HostSim;

const CommandShape = enum { shell_path, shell_bare, shell_args, missing_path, missing_bare };

const NameShape = enum { none, valid, invalid };

const RootfsShape = enum { good, missing, a_file, empty, too_long };

/// What is already in the state directory.
const Preloaded = enum { nothing, few_unreadable, full_and_unreadable };

const valid_names = [_][:0]const u8{ "a", "web-1", "0", "zbx-123456", repeat('n', 63) };
const invalid_names = [_][:0]const u8{ "", "Web", "a_b", "-a", "a-", repeat('a', 64), "\xc3\xa9" };

/// What the oracle expects of one run.
const Verdict = union(enum) {
    /// The command started and ended with this status.
    started: host_mod.ExitStatus,
    /// A diagnostic with this code, and (for a failed step) the index of the step it must name.
    /// `begun` is whether the run record was begun before it failed; `lost` that the failure was
    /// the wait (the command had started, and the run is recorded as lost).
    refused: struct {
        code: codes.Code,
        step: ?u32,
        begun: bool,
        lost: bool,
        /// For E0202: the command was not found (127), not merely unrunnable (126).
        command_missing: bool,
    },
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
    /// The host can map a full range of ids.
    full: bool,
    /// The helpers fail, with this exit code.
    helper_fails: ?u8,
    script: [3]u8,
    script_len: u32,
    caught: u64,
    ignored: u64,
    disk_full: bool,
    home: bool,
    preloaded: Preloaded,
};

/// Errnos a step can fail with: the ones mounts, pipes, forks and execs really return.
const errnos = [_]u16{ 1, 2, 5, 11, 12, 13, 16, 19, 20, 22, 24, 28, 30, 38 };
const ids = [_]u32{ 0, 1, 1000, 65534, std.math.maxInt(u32) - 1 };
const signal_numbers = [_]u8{ 1, 2, 3, 15 };

fn bit(number: u8) u64 {
    return @as(u64, 1) << @intCast(number - 1);
}

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
    const faulted = random.uintLessThan(u8, 4) != 0;
    scenario.fault_step = if (faulted) random.uintLessThan(u32, 44) else null;
    scenario.fault_errno = errnos[random.uintLessThan(usize, errnos.len)];
    scenario.devpts_refused = random.uintLessThan(u8, 4) == 0;
    scenario.interrupts_per_mille = if (random.boolean()) 0 else random.uintLessThan(u16, 200);
    scenario.short_writes = random.boolean();
    scenario.full = random.uintLessThan(u8, 4) != 0;
    // The sim host's subuid entry is for the user "alice", uid 1000: any other user has no range.
    scenario.uid = if (scenario.full) 1000 else ids[random.uintLessThan(usize, ids.len)];
    scenario.gid = ids[random.uintLessThan(usize, ids.len)];
    scenario.verbose = random.boolean();
    scenario.json = random.uintLessThan(u8, 4) == 0;
    scenario.helper_fails = if (random.uintLessThan(u8, 8) == 0) random.intRangeAtMost(
        u8,
        1,
        127,
    ) else null;
    scenario.script_len = if (random.uintLessThan(u8, 3) == 0) random.uintAtMost(u32, 3) else 0;
    scenario.script = .{ 0, 0, 0 };
    for (scenario.script[0..scenario.script_len]) |*number| {
        number.* = signal_numbers[random.uintLessThan(usize, signal_numbers.len)];
    }
    scenario.caught = 0;
    scenario.ignored = 0;
    for (signal_numbers) |number| {
        if (random.boolean()) scenario.caught |= bit(number);
        if (random.uintLessThan(u8, 4) == 0) scenario.ignored |= bit(number);
    }
    scenario.disk_full = random.uintLessThan(u8, 8) == 0;
    scenario.home = random.uintLessThan(u8, 8) != 0;
    scenario.preloaded = switch (random.uintLessThan(u8, 8)) {
        0 => .few_unreadable,
        1 => .full_and_unreadable,
        else => .nothing,
    };
    return scenario;
}

/// The exit code the oracle expects for a failure of `zbx run`, written out on its own rather than
/// through `codes`: 126 or 127 for the command that could not start, 125 for everything else.
fn exit_for(code: codes.Code, command_missing: bool) u8 {
    if (code != .E0202) return 125;
    return if (command_missing) 127 else 126;
}

fn plan_for(plan: *plan_mod.Plan, scenario: *const Scenario) void {
    sim_run.sample_plan(plan, scenario.full);
}

/// The kind of step a plan has at `index`.
fn kind_at(scenario: *const Scenario, index: u32) plan_mod.Kind {
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    assert(index < plan.count);
    return plan.steps[index].kind;
}

fn index_of(scenario: *const Scenario, kind: plan_mod.Kind) u32 {
    return sim_run.step_index(kind, scenario.full);
}

/// Where in the run a step's failure shows up. The parent's steps up to the go-ahead fail at
/// once; reading the child's report comes next, and the child's steps happen inside it; the wait
/// is last, after the command started.
const Phase = enum { early, report, child, wait };

fn phase_of(kind: plan_mod.Kind) Phase {
    return switch (kind) {
        .await_report => .report,
        .reap => .wait,
        else => if (plan_mod.side_of(kind) == .child) .child else .early,
    };
}

/// What the run must do, decided from the scenario alone.
fn verdict_of(scenario: *const Scenario) Verdict {
    if (scenario.name == .invalid) return refusal(.E0206, null, false);
    if (scenario.rootfs != .good) return refusal(.E0201, null, false);
    const fault = fault_at(scenario);
    // The parent's early steps: the first of a failed step and a failed helper wins.
    var early: ?Verdict = null;
    if (fault) |found| {
        if (phase_of(found.kind) == .early) early = refusal(found.code, found.index, true);
    }
    if (scenario.full and scenario.helper_fails != null) {
        const helper = index_of(scenario, .run_newuidmap);
        const sooner = if (early) |event| helper < event.refused.step.? else true;
        if (sooner) early = refusal(.E0204, helper, true);
    }
    if (early) |event| return event;
    if (fault) |found| {
        if (phase_of(found.kind) == .report) return refusal(found.code, found.index, true);
    }
    // The child's steps in order; its command missing is its last.
    var child: ?Verdict = null;
    if (fault) |found| {
        if (phase_of(found.kind) == .child) {
            child = refusal(found.code, found.index, true);
            if (found.kind == .exec) {
                const err = host_mod.error_for_errno(scenario.fault_errno);
                child.?.refused.command_missing = err == error.NotFound;
            }
        }
    }
    if (scenario.command == .missing_path or scenario.command == .missing_bare) {
        const exec = index_of(scenario, .exec);
        const sooner = if (child) |event| exec < event.refused.step.? else true;
        if (sooner) {
            child = refusal(.E0202, exec, true);
            // Looking on through PATH remembers a permission error from an earlier directory,
            // as a shell does: the command is then reported as unrunnable, not missing.
            child.?.refused.command_missing = !exec_denied_on_the_way(scenario);
        }
    }
    if (child) |event| return event;
    if (fault) |found| {
        if (phase_of(found.kind) == .wait) {
            return .{
                .refused = .{
                    .code = found.code,
                    .step = found.index,
                    .begun = true,
                    .lost = true,
                    .command_missing = false,
                },
            };
        }
    }
    return .{ .started = final_status(scenario) };
}

fn refusal(code: codes.Code, step: ?u32, begun: bool) Verdict {
    return .{ .refused = .{
        .code = code,
        .step = step,
        .begun = begun,
        .lost = false,
        .command_missing = false,
    } };
}

/// Whether a failure injected into the exec step is a permission error, which a search through
/// PATH keeps and reports if no later directory has the program.
fn exec_denied_on_the_way(scenario: *const Scenario) bool {
    const index = scenario.fault_step orelse return false;
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    if (index >= plan.count) return false;
    if (plan.steps[index].kind != .exec) return false;
    return host_mod.error_for_errno(scenario.fault_errno) == error.AccessDenied;
}

const Fault = struct { index: u32, kind: plan_mod.Kind, code: codes.Code };

/// The injected failure, if it fails its step (a step that may fail, or one a shell looks past,
/// is no failure).
fn fault_at(scenario: *const Scenario) ?Fault {
    const index = scenario.fault_step orelse return null;
    // The single-id plan has one step more than the full one; a fault past the end of the plan
    // that runs is no fault at all.
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    if (index >= plan.count) return null;
    const kind = plan.steps[index].kind;
    const code = step_failure(scenario, kind) orelse return null;
    return .{ .index = index, .kind = kind, .code = code };
}

/// The code a fault in a step of `kind` gives, or null if the run goes on past it.
fn step_failure(scenario: *const Scenario, kind: plan_mod.Kind) ?codes.Code {
    switch (kind) {
        .spawn, .deny_setgroups, .write_gid_map, .write_uid_map => return .E0203,
        .run_newuidmap, .run_newgidmap => return .E0204,
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

/// How the command ends once it is running: its own status, unless a signal it cannot handle
/// arrives first. The container is then killed in that signal's place.
fn final_status(scenario: *const Scenario) host_mod.ExitStatus {
    for (scenario.script[0..scenario.script_len]) |number| {
        if (!handles(scenario, number)) return .{ .signaled = number };
    }
    return scenario.command_exit;
}

fn handles(scenario: *const Scenario, number: u8) bool {
    return (scenario.caught | scenario.ignored) & bit(number) != 0;
}

/// The signals the command should have received: each one as sent while it handles them, then
/// SIGKILL in place of the first it does not.
fn expected_received(scenario: *const Scenario, out: *[8]u8) []const u8 {
    var count: usize = 0;
    for (scenario.script[0..scenario.script_len]) |number| {
        if (handles(scenario, number)) {
            out[count] = number;
            count += 1;
        } else {
            out[count] = constants.signal_kill;
            count += 1;
            break;
        }
    }
    return out[0..count];
}

/// Whether the devpts mount was skipped: the model refused it, or a failure was injected into it.
fn devpts_skipped(scenario: *const Scenario) bool {
    if (scenario.devpts_refused) return true;
    const found = scenario.fault_step orelse return false;
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    if (found >= plan.count) return false;
    return plan.steps[found].kind == .mount_pts;
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

/// Puts the scenario's state directory in place: records that are fine, and ones that are not.
fn preload(sim: *HostSim, scenario: *const Scenario) void {
    if (scenario.preloaded == .nothing) return;
    sim.world.add_node(sim_run.runs_path, .dir);
    const damaged = sim.world.write_file(sim_run.runs_path ++ "/damaged.zon", "garbage");
    assert(damaged == null);
    const future_text = ".{\n    .version = 9,\n    .name = \"future\",\n    .started = 5,\n}\n";
    assert(sim.world.write_file(sim_run.runs_path ++ "/future.zon", future_text) == null);
    if (scenario.preloaded == .few_unreadable) return;
    for (0..constants.runs_max - 1) |number| {
        var path: [64]u8 = undefined;
        const where = std.fmt.bufPrint(
            &path,
            sim_run.runs_path ++ "/old-{d:0>2}.zon",
            .{number},
        ) catch
            unreachable; // A short fixed path.
        var body: [96]u8 = undefined;
        const format = ".{{\n    .name = \"old-{d:0>2}\",\n    .started = {d},\n}}\n";
        // Cannot fail: the body is a few dozen bytes.
        const text = std.fmt.bufPrint(&body, format, .{ number, 1000 + number }) catch unreachable;
        assert(sim.world.write_file(where, text) == null);
    }
}

/// One run: set the simulator up, run the command line, and check everything.
pub fn fuzz_run(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const scenario = random_scenario(random);

    var sim: HostSim = undefined;
    if (scenario.full) sim_run.init(&sim, random.int(u64)) else sim_run.init_single(
        &sim,
        random.int(u64),
    );
    sim.uid_value = scenario.uid;
    sim.gid_value = scenario.gid;
    sim.world.command_exit = scenario.command_exit;
    sim.world.devpts_refused = scenario.devpts_refused;
    sim.world.disk_full = false;
    sim.world.helper_fails_with = scenario.helper_fails;
    sim.world.script = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    @memcpy(sim.world.script[0..3], &scenario.script);
    sim.world.script_len = scenario.script_len;
    sim.world.command_caught = scenario.caught;
    sim.world.command_ignored = scenario.ignored;
    sim.faults.interrupt_per_mille = scenario.interrupts_per_mille;
    if (scenario.short_writes) sim.faults.short_write_per_mille = 500;
    if (scenario.fault_step) |index| {
        sim.faults.fail_step = index;
        sim.faults.fail_step_errno = scenario.fault_errno;
    }
    var variables: [2]host_sim.EnvironmentVariable = undefined;
    var variables_count: usize = 0;
    if (scenario.home) {
        variables[variables_count] = sim_run.env_home[0];
        variables_count += 1;
    }
    if (scenario.term) {
        variables[variables_count] = .{ .name = "TERM", .value = "xterm" };
        variables_count += 1;
    }
    sim.environment_variables = variables[0..variables_count];
    preload(&sim, &scenario);
    sim.world.disk_full = scenario.disk_full;
    const before = sim_run.baseline(&sim);

    var words_storage: [3][:0]const u8 = undefined;
    const words = command_words(&scenario, &words_storage);
    var args: [16][:0]const u8 = undefined;
    var count: usize = 0;
    push(&args, &count, "zbx");
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
    const verdict = verdict_of(scenario);
    check_warnings(scenario, &verdict, found);
    switch (verdict) {
        .started => |status| check_started(sim, scenario, status, code),
        .refused => |refusal_found| {
            check_refused(sim, scenario, refusal_found, found, code);
            check_record(sim, scenario, &verdict);
        },
    }
}

/// The warnings, in the order they are written, then the error if the run failed: the host that
/// cannot map a full range warns first; a record that cannot be kept warns once; records that
/// cannot be read warn when there are too many to keep. Nothing is warned about a run that was
/// refused before it began.
fn check_warnings(scenario: *const Scenario, verdict: *const Verdict, found: diag_fuzz.Found) void {
    var expected: [4]codes.Code = undefined;
    var count: usize = 0;
    const began = switch (verdict.*) {
        .started => true,
        .refused => |refusal_found| refusal_found.begun,
    };
    // Warnings are written once the request has passed its checks, which a refusal with no step
    // (a name or rootfs problem) has not.
    const reached_ids = began;
    if (reached_ids and !scenario.full) {
        expected[count] = .W0201;
        count += 1;
    }
    if (reached_ids and (!scenario.home or scenario.disk_full)) {
        expected[count] = .W0202;
        count += 1;
    }
    if (reached_ids and scenario.home and scenario.preloaded == .full_and_unreadable) {
        expected[count] = .W0203;
        count += 1;
    }
    switch (verdict.*) {
        .refused => |refusal_found| {
            expected[count] = refusal_found.code;
            count += 1;
        },
        .started => {},
    }
    assert(found.count == count);
    assert(std.mem.eql(codes.Code, found.in_order(), expected[0..count]));
}

fn check_started(
    sim: *const HostSim,
    scenario: *const Scenario,
    status: host_mod.ExitStatus,
    code: u8,
) void {
    // Property 3 when the command ran: its code, 128 plus the signal, never a zbx code mix-up.
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
    assert(
        sim_run.started(sim, .{ .name = name, .devpts = devpts, .full = scenario.full }) == null,
    );
    var received_storage: [8]u8 = undefined;
    const received = expected_received(scenario, &received_storage);
    assert(std.mem.eql(u8, sim.world.received[0..sim.world.received_count], received));
    assert(sim.world.helper_runs == if (scenario.full) @as(u32, 2) else 0);
    check_started_output(sim, scenario, status);
    check_record(sim, scenario, &.{ .started = status });
}

fn check_started_output(
    sim: *const HostSim,
    scenario: *const Scenario,
    status: host_mod.ExitStatus,
) void {
    const stderr = sim.stderr();
    if (scenario.json) {
        // Warnings are JSON lines of their own; the run ends with the container_exit line.
        assert(std.mem.indexOf(u8, stderr, "{\"container_exit\":{") != null);
        assert(std.mem.endsWith(u8, stderr, "}}\n"));
        return;
    }
    const skipped = std.mem.count(u8, stderr, "zbx: note: skipped");
    assert(skipped == @intFromBool(scenario.verbose and devpts_skipped(scenario)));
    const killed = std.mem.count(u8, stderr, "the container was killed by signal");
    assert(killed == @intFromBool(status == .signaled));
}

fn check_refused(
    sim: *const HostSim,
    scenario: *const Scenario,
    refusal_found: @FieldType(Verdict, "refused"),
    found: diag_fuzz.Found,
    exit: u8,
) void {
    const code = refusal_found.code;
    const step = refusal_found.step;
    // Property 1: the failure's diagnostic is the last one written, with the step's code.
    assert(found.code.? == code);
    // Property 3: a run's own failure never exits with a code a container could be mistaken for
    // (1, 2, 3, 70): it is 125, or 126 and 127 for the command, and nothing else decides.
    assert(exit == exit_for(code, refusal_found.command_missing));
    assert(exit >= 125);
    assert(exit <= 127);
    if (step == null) {
        // Refused before anything was created.
        assert(sim.world.processes[1].state == .unused);
        return;
    }
    // The diagnostic names the step in the output a person (or a script) can read. The default
    // text output leaves the context out; verbose and JSON show it.
    if (!scenario.verbose and !scenario.json) return;
    const kind = @tagName(kind_at(scenario, step.?));
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    var needle: [96]u8 = undefined;
    const position = .{ kind, step.? + 1, plan.count };
    const text = if (scenario.json)
        std.fmt.bufPrint(&needle, "\"step\":\"{s} ({d} of {d})\"", position)
    else
        std.fmt.bufPrint(&needle, "\n  step   {s} ({d} of {d})\n", position);
    // Cannot fail: a kind name and two small numbers.
    const found_text = text catch unreachable;
    assert(std.mem.indexOf(u8, sim.stderr(), found_text) != null);
}

/// The run record, when one can have been kept: exactly one record of this run exists (the
/// others in the directory are older), it says how the run ended, and none exists when the
/// state could not be kept.
fn check_record(sim: *const HostSim, scenario: *const Scenario, verdict: *const Verdict) void {
    const kept = scenario.home and !scenario.disk_full;
    const began = switch (verdict.*) {
        .started => true,
        .refused => |refusal_found| refusal_found.begun,
    };
    var parsed: records.Parsed = undefined;
    var candidate: records.Parsed = undefined;
    var found: u32 = 0;
    for (sim.world.written[0..sim.world.written_count]) |*file| {
        if (!file.path.under(sim_run.runs_path)) continue;
        records.parse(file.content[0..file.len], &candidate) catch continue;
        if (candidate.started != sim.world.now) continue;
        parsed = candidate;
        found += 1;
    }
    assert(found == @intFromBool(began and kept));
    if (found == 0) return;
    if (scenario.name == .valid) assert(std.mem.eql(u8, parsed.name_slice(), scenario.name_text));
    const expected: records.Exit = switch (verdict.*) {
        .started => |status| switch (status) {
            .exited => |n| .{ .exited = n },
            .signaled => |n| .{ .signaled = n },
        },
        .refused => |refusal_found| if (refusal_found.lost)
            .lost
        else
            .{ .start_failed = refusal_found.code },
    };
    assert(std.meta.eql(parsed.exit, expected));
    assert(parsed.ids.? == if (scenario.full) records.IdsMode.full else records.IdsMode.single);
    assert(parsed.ended != null);
}
