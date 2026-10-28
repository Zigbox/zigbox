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
//! M2 adds the cgroup scope: the user's bus may be fine, absent, without systemd or refusing the
//! user (then a run with a limit is refused, E0307, and one without warns, W0301), may fail in
//! the scope step in nine ways (each with its code), and the limits may be valid or not (E0306).
//! The limits of a scope that started must be what the flags said, or in the cgroup files when
//! the systemd is too old for the property.
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

/// The user's bus when the run begins (what the probe finds).
const BusShape = enum { fine, no_socket, no_systemd, auth_rejected, no_environment };

/// A fault in the scope step, after a perfect probe.
const StepFault = enum {
    none,
    no_socket,
    auth_rejected,
    hello_refused,
    no_systemd,
    start_refused,
    name_taken,
    job_failed,
    job_never,
    garbage,
    oversized,
    truncated,
    hang_up,
    silent,
};

/// When the manager removes a scope whose last process has gone (`sim_bus.Model.scope_removal`).
const Removal = enum { lazily, promptly, never };
const NetChoice = enum { default, none, host };

/// What goes wrong when the scope that stays is stopped.
const StopFault = enum { none, refused, canceled, stays };

/// The address the environment carries for the user's bus: none, another user's socket that
/// refuses at connect or at authentication, or a socket that does not exist.
const Inherited = enum { none, denied, auth, stale };

/// The text of a limit flag and what it must read as, or null for text that must be refused.
const LimitText = struct { text: [:0]const u8, value: ?u64 };

const memory_texts = [_]LimitText{
    .{ .text = "128m", .value = 128 << 20 },
    .{ .text = "4m", .value = 4 << 20 },
    .{ .text = "1G", .value = 1 << 30 },
    .{ .text = "4194304", .value = 4 << 20 },
    .{ .text = "4096k", .value = 4 << 20 },
    .{ .text = "0", .value = null },
    .{ .text = "", .value = null },
    .{ .text = "abc", .value = null },
    .{ .text = "3m", .value = null },
    .{ .text = "1025g", .value = null },
    .{ .text = "1.5m", .value = null },
};
const pids_texts = [_]LimitText{
    .{ .text = "1", .value = 1 },
    .{ .text = "64", .value = 64 },
    .{ .text = "4194304", .value = 4194304 },
    .{ .text = "0", .value = null },
    .{ .text = "", .value = null },
    .{ .text = "x", .value = null },
    .{ .text = "4194305", .value = null },
};
const cpus_texts = [_]LimitText{
    .{ .text = "0.5", .value = 500 },
    .{ .text = "2", .value = 2000 },
    .{ .text = "0.01", .value = 10 },
    .{ .text = "1024", .value = 1024000 },
    .{ .text = "1.25", .value = 1250 },
    .{ .text = "0", .value = null },
    .{ .text = "a", .value = null },
    .{ .text = "0.001", .value = null },
    .{ .text = "1024.5", .value = null },
    .{ .text = "1.2345", .value = null },
    .{ .text = ".", .value = null },
};

/// Another user's bus, which the inherited address names. No scenario user has this id.
const foreign_socket = "/run/user/4242/bus";

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
        /// The request got as far as the ids, whose warning (W0201) was already written. True
        /// for every refusal after the name, rootfs and limit checks.
        reached_ids: bool,
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
    bus: BusShape,
    step_fault: StepFault,
    /// systemd 230, which cannot set memory limits itself, instead of 255.
    old_systemd: bool,
    memory: ?LimitText,
    pids: ?LimitText,
    cpus: ?LimitText,
    /// The kernel counted an OOM kill, or a refused fork, in the container's cgroup.
    oom: bool,
    pids_hit: bool,
    /// The scope's keeper cannot be forked (the run is refused), or ends the moment its scope is
    /// up (the manager may then remove the scope, and its counters, before they are read).
    keeper_fork_fails: bool,
    keeper_dies: bool,
    removal: Removal,
    stop_fault: StopFault,
    inherited: Inherited,
    /// `--read-only`: the rootfs is read-only with tmpfs at /tmp and /run.
    read_only: bool,
    /// The root is a tree of the store, run on an overlay, instead of a directory.
    image: bool,
    /// `--net`: not given (none, with the hint when the command fails), none, or host.
    net: NetChoice,

    /// Whether the probe finds a bus: the run then has a scope and the plan a step for it. A
    /// stale inherited address is not permission trouble, so nothing falls back from it.
    fn scoped(scenario: *const Scenario) bool {
        return scenario.bus == .fine and scenario.inherited != .stale;
    }

    /// The stop fault that can matter: only a scope that stays is ever stopped.
    fn stop_effective(scenario: *const Scenario) StopFault {
        return if (scenario.removal == .never) scenario.stop_fault else .none;
    }

    /// Whether the counters of the cgroup can be read after the container ends.
    fn events_readable(scenario: *const Scenario) bool {
        if (!scenario.scoped()) return false;
        // The keeper holds the scope open until the counters are read, so a manager that
        // removes a scope the moment it is empty still leaves them readable, unless the keeper
        // is already gone.
        return scenario.removal != .promptly or !scenario.keeper_dies;
    }

    /// Whether the cleanup after the run ends in the warning that the scope was left behind.
    fn lingers(scenario: *const Scenario) bool {
        return scenario.scoped() and scenario.stop_effective() != .none;
    }

    /// The scope's name for a container called `name`, in the record and on the bus.
    fn counts_as_oom(scenario: *const Scenario) bool {
        return scenario.events_readable() and scenario.oom;
    }

    fn counts_as_pid_limit(scenario: *const Scenario) bool {
        return scenario.events_readable() and scenario.pids_hit and !scenario.oom;
    }

    /// Whether any limit flag is given (valid or not).
    fn has_limit(scenario: *const Scenario) bool {
        return scenario.memory != null or scenario.pids != null or scenario.cpus != null;
    }

    /// The first limit text that must be refused, if any.
    fn limit_invalid(scenario: *const Scenario) bool {
        inline for (.{ "memory", "pids", "cpus" }) |name| {
            if (@field(scenario, name)) |item| {
                if (item.value == null) return true;
            }
        }
        return false;
    }
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
    scenario.fault_step = if (faulted) random.uintLessThan(u32, 56) else null;
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
    scenario.bus = if (random.uintLessThan(u8, 5) == 0) random.enumValue(BusShape) else .fine;
    scenario.step_fault = .none;
    if (scenario.bus == .fine and random.uintLessThan(u8, 3) == 0) {
        scenario.step_fault = random.enumValue(StepFault);
    }
    scenario.old_systemd = random.uintLessThan(u8, 5) == 0;
    scenario.memory = random_limit(random, &memory_texts);
    scenario.pids = random_limit(random, &pids_texts);
    scenario.cpus = random_limit(random, &cpus_texts);
    random_cgroup(random, &scenario);
    return scenario;
}

/// What the cgroup counted and how the manager treats the scope after the run.
fn random_cgroup(random: std.Random, scenario: *Scenario) void {
    scenario.oom = random.uintLessThan(u8, 6) == 0;
    scenario.pids_hit = random.uintLessThan(u8, 6) == 0;
    scenario.keeper_fork_fails = random.uintLessThan(u8, 10) == 0;
    scenario.keeper_dies = random.uintLessThan(u8, 5) == 0;
    // Scope cleanup and inherited-address faults are drawn only where nothing else is failing,
    // so that every warning and every connection of the run can be accounted for.
    const calm = scenario.fault_step == null and scenario.step_fault == .none and
        scenario.helper_fails == null;
    scenario.read_only = random.uintLessThan(u8, 4) == 0;
    scenario.net = random.enumValue(NetChoice);
    // A fifth of the good roots are trees of the store. The name is then a valid one: the
    // container's directory is made under it.
    scenario.image = scenario.rootfs == .good and scenario.name != .invalid and
        random.uintLessThan(u8, 5) == 0;
    if (scenario.image) scenario.home = true; // The store and the layers live under it.
    if (scenario.image and scenario.name == .none) {
        scenario.name = .valid;
        scenario.name_text = valid_names[random.uintLessThan(usize, valid_names.len)];
    }
    scenario.removal = .lazily;
    scenario.stop_fault = .none;
    scenario.inherited = .none;
    if (calm and random.uintLessThan(u8, 3) == 0) {
        scenario.removal = random.enumValue(Removal);
        scenario.stop_fault = random.enumValue(StopFault);
    }
    if (calm and scenario.bus != .no_environment and random.uintLessThan(u8, 4) == 0) {
        scenario.inherited = random.enumValue(Inherited);
    }
}

fn random_limit(random: std.Random, table: []const LimitText) ?LimitText {
    if (random.uintLessThan(u8, 3) != 0) return null;
    return table[random.uintLessThan(usize, table.len)];
}

/// The exit code the oracle expects for a failure of `zbx run`, written out on its own rather than
/// through `codes`: 126 or 127 for the command that could not start, 125 for everything else.
fn exit_for(code: codes.Code, command_missing: bool) u8 {
    if (code != .E0202) return 125;
    return if (command_missing) 127 else 126;
}

fn plan_for(plan: *plan_mod.Plan, scenario: *const Scenario) void {
    sim_run.sample_plan_image(
        plan,
        scenario.full,
        scenario.scoped(),
        scenario.read_only,
        scenario.image,
        if (scenario.net == .host) .host else .none,
    );
}

/// The kind of step a plan has at `index`.
fn kind_at(scenario: *const Scenario, index: u32) plan_mod.Kind {
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    assert(index < plan.count);
    return plan.steps[index].kind;
}

fn index_of(scenario: *const Scenario, kind: plan_mod.Kind) u32 {
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == kind) return @intCast(index);
    }
    unreachable; // Every kind asked for is in the plan of its scenario.
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

/// The parent's early steps: the first of a failed step, a failed helper and a failed scope wins.
fn early_verdict(scenario: *const Scenario, fault: ?Fault) ?Verdict {
    var early: ?Verdict = null;
    if (fault) |found| {
        if (phase_of(found.kind) == .early) early = refusal(found.code, found.index, true);
    }
    if (scenario.full and scenario.helper_fails != null) {
        const helper = index_of(scenario, .run_newuidmap);
        const sooner = if (early) |event| helper < event.refused.step.? else true;
        if (sooner) early = refusal(.E0204, helper, true);
    }
    if (scenario.scoped() and scenario.keeper_fork_fails) {
        const at = index_of(scenario, .spawn_keeper);
        const sooner = if (early) |event| at < event.refused.step.? else true;
        if (sooner) early = refusal(.E0205, at, true);
    }
    if (scenario.scoped()) {
        if (scope_fault_code(scenario)) |code| {
            const at = index_of(scenario, .start_scope);
            const sooner = if (early) |event| at < event.refused.step.? else true;
            if (sooner) early = refusal(code, at, true);
        }
    }
    return early;
}

/// What the run must do, decided from the scenario alone.
fn verdict_of(scenario: *const Scenario) Verdict {
    // The command line reads the limits first, then the library checks name and rootfs.
    if (scenario.limit_invalid()) return early_refusal(.E0306);
    if (scenario.name == .invalid) return early_refusal(.E0206);
    if (scenario.rootfs != .good) return early_refusal(.E0201);
    // The ids come next (and their warning), then the scope: a limit with no bus is refused.
    if (!scenario.scoped() and scenario.has_limit()) {
        var verdict = refusal(.E0307, null, false);
        verdict.refused.reached_ids = true;
        return verdict;
    }
    // A tree is prepared in the store's worker before the plan, and its helper is refused too.
    if (scenario.image and scenario.full and scenario.helper_fails != null) {
        return refusal(.E0419, null, false);
    }
    const fault = fault_at(scenario);
    if (early_verdict(scenario, fault)) |event| return event;
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
                    .reached_ids = true,
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
        .reached_ids = true,
    } };
}

/// A refusal before the ids: nothing has been warned about yet.
fn early_refusal(code: codes.Code) Verdict {
    var verdict = refusal(code, null, false);
    verdict.refused.reached_ids = false;
    return verdict;
}

/// The code the scope step fails with, from the fault the model gives it.
fn scope_fault_code(scenario: *const Scenario) ?codes.Code {
    return switch (scenario.step_fault) {
        .none => null,
        .no_socket, .no_systemd => .E0301,
        .auth_rejected, .hello_refused => .E0302,
        .start_refused, .job_failed, .job_never => .E0304,
        .name_taken => .E0305,
        .garbage, .oversized, .truncated, .hang_up, .silent => .E0303,
    };
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
        .start_scope => return .E0301, // Its first call is the connect to the bus.
        .restrict_capabilities, .clear_ambient => return .E0207,
        .set_no_new_privs, .install_seccomp => return .E0208,
        .make_tmp_dir, .mount_tmp, .make_run_dir, .mount_run, .remount_readonly => return .E0209,
        .mount_overlay => return .E0425,
        // The steps that may fail: skipped with a note.
        .mount_pts, .make_sys_dir, .bind_sys, .remount_sys, .mount_sysfs => return null,
        .make_etc_dir, .create_etc_file, .stage_etc_file => return null,
        .bind_etc_file, .remount_etc_file, .unstage_etc_file => return null,
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

/// The exit code zbx ends with when the command started: its own, 128 plus its signal, or 137
/// for an OOM kill.
fn final_code(scenario: *const Scenario, status: host_mod.ExitStatus) u8 {
    if (scenario.counts_as_oom()) return 137;
    return switch (status) {
        .exited => |code| code,
        .signaled => |number| constants.exit_signal_offset + number,
    };
}

/// Whether a failure was injected into a step of the /sys or the generated /etc files, which is
/// then skipped with a note.
fn net_steps_skipped(scenario: *const Scenario) bool {
    const found = scenario.fault_step orelse return false;
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    if (found >= plan.count) return false;
    const kind = plan.steps[found].kind;
    return plan_mod.is_sys(kind) or plan_mod.is_etc(kind);
}

/// How many steps were skipped with a note, which `--verbose` prints: the devpts mount, and the
/// /sys steps. A failure in the directory step leaves nothing to bind, so the bind and the remount
/// fail after it (both are tolerant); a failure in the bind leaves nothing to remount.
fn skipped_notes(scenario: *const Scenario) u32 {
    var count: u32 = @intFromBool(devpts_skipped(scenario));
    const found = scenario.fault_step orelse return count;
    var plan: plan_mod.Plan = undefined;
    plan_for(&plan, scenario);
    if (found >= plan.count) return count;
    count += switch (plan.steps[found].kind) {
        .make_sys_dir => if (plan.isolated()) @as(u32, 2) else 3,
        .bind_sys => 2,
        .remount_sys, .mount_sysfs => 1,
        .make_etc_dir => 2, // The second file's mount point has no directory to be made in.
        .create_etc_file, .stage_etc_file, .bind_etc_file, .remount_etc_file => 1,
        // Removing a staged copy that is not there is no failure: only the others count.
        .unstage_etc_file => @intFromBool(!removal_finds_nothing(scenario)),
        else => 0,
    };
    return count;
}

/// A failure injected into the removal of a staged file that says the file is not there.
fn removal_finds_nothing(scenario: *const Scenario) bool {
    return host_mod.error_for_errno(scenario.fault_errno) == error.NotFound;
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

// ---- A run of a tree from the store ----

const store_fs = @import("store/fs_sim.zig");
const store_import = @import("store/import.zig");
const store_layout = @import("store/layout.zig");
const store_support = @import("store/test_support.zig");

var image_files: store_fs.SimFs = undefined;
var image_store: store_layout.Store = undefined;
var image_workspace: store_import.Workspace = undefined;
var image_prefix: [12:0]u8 = undefined;
const containers = "/home/alice/.local/state/zbx/containers";

fn image_argument() [:0]const u8 {
    return &image_prefix;
}

fn merged_path(buffer: *[constants.sim_path_bytes_max]u8, name: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer, containers ++ "/{s}/merged", .{name}) catch
        unreachable; // The name is at most 63 bytes.
}

/// A store that holds a small tree, and the container model's view of the merged directory.
fn prepare_image(sim: *HostSim, scenario: *const Scenario) void {
    image_files.init(1);
    sim.store_fs = &image_files;
    store_support.make_user_store(&image_files, ".{\n    .format = 1,\n}\n");
    image_files.put_dir("/src", 0o755);
    image_files.put_file("/src/hello", 0o644, "hello\n");
    image_store.at(sim.interface(), store_support.user_store);
    var result: store_import.Result = undefined;
    var diag: @import("diag/diag.zig").Diag = undefined;
    diag.reset();
    const options: store_import.Options = .{ .squash_owner = false, .warn = null };
    store_import.import(&image_store, &image_workspace, "/src", options, &result, &diag) catch
        unreachable; // A tiny tree imports.
    const text = result.digest.text();
    @memcpy(image_prefix[0..12], text[3..15]);
    var buffer: [constants.sim_path_bytes_max]u8 = undefined;
    const merged = merged_path(&buffer, scenario.name_text);
    sim.world.add_node(merged, .dir);
    var inner: [constants.sim_path_bytes_max]u8 = undefined;
    // The layer with the mount points of the generated /etc files, beside the merged directory.
    sim.world.add_node(std.fmt.bufPrint(&inner, containers ++ "/{s}/net", .{
        scenario.name_text,
    }) catch unreachable, .dir); // Short.
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        sim.world.add_node(std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix }) catch
            unreachable, .dir); // Short.
    }
    // The overlay shows the mount points of the generated files, which are in the net layer.
    for ([_][]const u8{ "/bin/sh", "/bin/sleep", "/etc/hosts", "/etc/resolv.conf" }) |suffix| {
        sim.world.add_node(std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix }) catch
            unreachable, .file); // Short.
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
    var environment: Environment = undefined;
    sim.environment_variables = environment.fill(&scenario);
    set_bus(&sim, &scenario);
    preload(&sim, &scenario);
    if (scenario.image) prepare_image(&sim, &scenario);
    sim.world.disk_full = scenario.disk_full;
    const before = sim_run.baseline(&sim);

    var args: [28][:0]const u8 = undefined;
    const count = command_line(&scenario, &args);
    const code = sim_run.run_cli(&sim, args[0..count]);

    check(&sim, &scenario, &before, code);
}

/// The simulated process's environment: what the scenario says it has.
const Environment = struct {
    variables: [4]host_sim.EnvironmentVariable,
    count: u32,
    runtime_dir: [32]u8,

    fn fill(
        environment: *Environment,
        scenario: *const Scenario,
    ) []const host_sim.EnvironmentVariable {
        environment.count = 0;
        if (scenario.home) environment.add(sim_run.env_home[0]);
        if (scenario.bus != .no_environment) {
            // The user's runtime directory is named by the user's own id.
            const format = "/run/user/{d}";
            const text = std.fmt.bufPrint(&environment.runtime_dir, format, .{scenario.uid}) catch
                unreachable; // A u32 has ten digits.
            environment.add(.{ .name = "XDG_RUNTIME_DIR", .value = text });
        }
        if (scenario.term) environment.add(.{ .name = "TERM", .value = "xterm" });
        switch (scenario.inherited) {
            .none => {},
            .denied, .auth => environment.add(.{
                .name = "DBUS_SESSION_BUS_ADDRESS",
                .value = "unix:path=" ++ foreign_socket,
            }),
            .stale => environment.add(.{
                .name = "DBUS_SESSION_BUS_ADDRESS",
                .value = "unix:path=/run/user/4243/bus",
            }),
        }
        return environment.variables[0..environment.count];
    }

    fn add(environment: *Environment, variable: host_sim.EnvironmentVariable) void {
        environment.variables[environment.count] = variable;
        environment.count += 1;
    }
};

/// The command line of the scenario, after the program name; returns how many words.
fn command_line(scenario: *const Scenario, args: *[28][:0]const u8) usize {
    var words_storage: [3][:0]const u8 = undefined;
    const words = command_words(scenario, &words_storage);
    var count: usize = 0;
    push(args, &count, "zbx");
    if (scenario.verbose) push(args, &count, "-v");
    if (scenario.json) {
        push(args, &count, "--output");
        push(args, &count, "json");
    }
    push(args, &count, "run");
    if (scenario.read_only) push(args, &count, "--read-only");
    switch (scenario.net) {
        .default => {},
        .none => push_pair(args, &count, "--net", "none"),
        .host => push_pair(args, &count, "--net", "host"),
    }
    push_limit(args, &count, "--memory", scenario.memory);
    push_limit(args, &count, "--pids", scenario.pids);
    push_limit(args, &count, "--cpus", scenario.cpus);
    if (scenario.image) {
        push(args, &count, image_argument());
    } else if (scenario.rootfs == .empty) {
        push(args, &count, "--rootfs=");
    } else {
        push(args, &count, "--rootfs");
        push(args, &count, rootfs_text(scenario));
    }
    if (scenario.name != .none) {
        push(args, &count, "--name");
        push(args, &count, scenario.name_text);
    }
    push(args, &count, "--");
    for (words) |word| push(args, &count, word);
    return count;
}

fn push_limit(args: *[28][:0]const u8, count: *usize, flag: [:0]const u8, item: ?LimitText) void {
    const given = item orelse return;
    push(args, count, flag);
    push(args, count, given.text);
}

/// The bus the scenario describes: broken from the start (the probe finds it so), or perfect for
/// the probe and broken for the scope step.
fn set_bus(sim: *HostSim, scenario: *const Scenario) void {
    const model = &sim.world.bus.model;
    if (scenario.old_systemd) model.version = "230.1";
    switch (scenario.bus) {
        .fine, .no_environment => {},
        .no_socket => model.present = false,
        .no_systemd => model.systemd_present = false,
        .auth_rejected => model.auth = .reject,
    }
    model.scope_removal = switch (scenario.removal) {
        .lazily => .lazily,
        .promptly => .promptly,
        .never => .never,
    };
    switch (scenario.stop_effective()) {
        .none, .stays => {},
        .refused => model.stop_error = "org.freedesktop.DBus.Error.AccessDenied",
        .canceled => model.stop_result = "canceled",
    }
    sim.world.cgroup_stays = scenario.stop_effective() == .stays;
    sim.world.oom_kills = @intFromBool(scenario.oom);
    sim.world.keeper_dies_early = scenario.keeper_dies;
    if (scenario.keeper_fork_fails) sim.world.keeper_fork_errno = 11;
    sim.world.pids_max_hits = @intFromBool(scenario.pids_hit);
    switch (scenario.inherited) {
        .none, .stale => {},
        .denied => model.foreign_socket = foreign_socket,
        .auth => {
            model.foreign_socket = foreign_socket;
            model.foreign_rejects = true;
        },
    }
    if (scenario.step_fault == .none) return;
    model.quiet_connections = 1;
    model.perfect_from = 2; // The cleanup after the scope step has a bus that works.
    switch (scenario.step_fault) {
        .none => unreachable,
        .no_socket => model.present = false,
        .auth_rejected => model.auth = .reject,
        .hello_refused => model.hello_error = "org.freedesktop.DBus.Error.AccessDenied",
        .no_systemd => model.systemd_present = false,
        .start_refused => model.start_error = "org.freedesktop.DBus.Error.AccessDenied",
        .name_taken => model.unit_taken = true,
        .job_failed => model.job_result = "failed",
        .job_never => model.job_removed = false,
        .garbage => model.misbehave = .{ .at_call = 3, .how = .garbage_reply },
        .oversized => model.misbehave = .{ .at_call = 3, .how = .oversized_reply },
        .truncated => model.misbehave = .{ .at_call = 3, .how = .truncated_reply },
        .hang_up => model.misbehave = .{ .at_call = 3, .how = .hang_up },
        .silent => model.misbehave = .{ .at_call = 3, .how = .silent },
    }
}

fn push(args: *[28][:0]const u8, count: *usize, item: [:0]const u8) void {
    args[count.*] = item;
    count.* += 1;
}

fn push_pair(args: *[28][:0]const u8, count: *usize, name: [:0]const u8, value: [:0]const u8) void {
    push(args, count, name);
    push(args, count, value);
}

fn check(
    sim: *const HostSim,
    scenario: *const Scenario,
    before: *const sim_run.Baseline,
    code: u8,
) void {
    // Property 2, for every run: nothing leaked, however it ended. A scope the manager refuses
    // to stop is the one thing left behind, and the run said so (ZBX-W0302, checked below).
    var allowed = before.*;
    const made = scenario.scoped() and sim.world.bus.scopes_started > 0;
    const refused_stop = scenario.stop_effective() == .refused or
        scenario.stop_effective() == .canceled;
    allowed.scopes_allowed = @intFromBool(made and refused_stop);
    assert(sim_run.leak(sim, &allowed) == null);
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
    var expected: [7]codes.Code = undefined;
    var count: usize = 0;
    const began = switch (verdict.*) {
        .started => true,
        .refused => |refusal_found| refusal_found.begun,
    };
    // The ids' warning is written once the request has passed the name, rootfs and limit checks;
    // the scope's after it (a limit with no bus is refused instead of warned about); the record's
    // when the run is recorded.
    const reached_ids = switch (verdict.*) {
        .started => true,
        .refused => |refusal_found| refusal_found.reached_ids,
    };
    if (reached_ids and !scenario.full) {
        expected[count] = .W0201;
        count += 1;
    }
    if (reached_ids and !scenario.scoped() and !scenario.has_limit()) {
        expected[count] = .W0301;
        count += 1;
    }
    if (began and (!scenario.home or scenario.disk_full)) {
        expected[count] = .W0202;
        count += 1;
    }
    if (began and scenario.home and scenario.preloaded == .full_and_unreadable) {
        expected[count] = .W0203;
        count += 1;
    }
    // The cleanup after the container: only a run whose scope was made gets there.
    const scope_made = switch (verdict.*) {
        .started => true,
        .refused => |refusal_found| refusal_found.code == .E0202,
    };
    if (scope_made and scenario.lingers()) {
        expected[count] = .W0302;
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
    // An OOM kill in the cgroup is exit 137 whatever the command did; a refused fork keeps it.
    const own: u8 = switch (status) {
        .exited => |n| n,
        .signaled => |n| constants.exit_signal_offset + n,
    };
    const expected: u8 = if (scenario.counts_as_oom()) 137 else own;
    assert(code == expected);
    const name = sim.world.hostnames[sim.world.processes[1].uts].slice();
    if (scenario.name == .valid) assert(std.mem.eql(u8, name, scenario.name_text));
    if (scenario.name == .none) {
        assert(std.mem.startsWith(u8, name, constants.container_name_prefix));
    }
    const devpts = !devpts_skipped(scenario);
    var merged_storage: [constants.sim_path_bytes_max]u8 = undefined;
    const container: sim_run.Started = .{
        .name = name,
        .devpts = devpts,
        .full = scenario.full,
        .read_only = scenario.read_only,
        .merged = if (scenario.image) merged_path(&merged_storage, name) else null,
        .network = if (scenario.net == .host) .host else .none,
        .network_mounts = !net_steps_skipped(scenario),
    };
    assert(sim_run.started(sim, container) == null);
    var received_storage: [8]u8 = undefined;
    const received = expected_received(scenario, &received_storage);
    assert(std.mem.eql(u8, sim.world.received[0..sim.world.received_count], received));
    // A run of a tree has the store's worker map its ids first: the helpers run twice.
    const helper_runs: u32 = if (scenario.full) (if (scenario.image) 4 else 2) else 0;
    assert(sim.world.helper_runs == helper_runs);
    check_scope(sim, scenario, name);
    check_started_output(sim, scenario, status);
    check_record(sim, scenario, &.{ .started = status });
}

/// A run that started had its scope made before its command, with the container's pid in it and
/// the limits the flags gave: as unit properties, or in the cgroup files for an old systemd.
fn check_scope(sim: *const HostSim, scenario: *const Scenario, name: []const u8) void {
    if (!scenario.scoped()) {
        assert(sim.world.bus.scopes_started == 0);
        return;
    }
    assert(sim.world.bus.scopes_started == 1);
    const scope = &sim.world.bus.last_scope;
    assert(scope.pid == sim.world.processes[1].pid);
    assert(scope.delegate);
    assert(scope.accounting == 4);
    var unit: [96]u8 = undefined;
    // Cannot fail: a 63-byte name and ten more bytes.
    const unit_name = std.fmt.bufPrint(&unit, "zbx-{s}.scope", .{name}) catch unreachable;
    assert(std.mem.eql(u8, scope.name.slice(), unit_name));
    const memory: ?u64 = if (scenario.memory) |item| item.value else null;
    const pids: ?u64 = if (scenario.pids) |item| item.value else null;
    const cpus: ?u64 = if (scenario.cpus) |item| item.value else null;
    // systemd 227 has TasksMax, so both versions use it; the keeper takes one pid of it.
    assert(scope.tasks_max == if (pids) |count| count + constants.scope_keeper_tasks else null);
    assert(scope.cpu_quota_usec == if (cpus) |millis| millis * 1000 else null);
    if (!scenario.old_systemd) {
        assert(std.mem.eql(u8, scope.slice.slice(), "app.slice"));
        assert(scope.memory_max == memory);
        assert(scope.memory_swap_max == if (memory != null) @as(?u64, 0) else null);
        return;
    }
    assert(scope.slice.len == 0);
    assert(scope.memory_max == null);
    assert(scope.memory_swap_max == null);
    // The scope and its files are gone by now; the world kept what memory.max held.
    if (memory) |bytes| {
        var digits: [24]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "{d}", .{bytes}) catch unreachable; // A u64.
        assert(std.mem.eql(u8, sim.world.last_memory_max().?, text));
    } else {
        assert(sim.world.last_memory_max() == null);
    }
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
        const reason = if (scenario.counts_as_oom())
            "oom"
        else if (scenario.counts_as_pid_limit())
            "pid_limit"
        else if (status == .signaled)
            "signal"
        else
            "exited";
        var needle: [48]u8 = undefined;
        // Cannot fail: a reason word in 48 bytes.
        const text = std.fmt.bufPrint(&needle, "\"reason\":\"{s}\"", .{reason}) catch unreachable;
        assert(std.mem.indexOf(u8, stderr, text) != null);
        const word = if (scenario.net == .host) "\"network\":\"host\"" else "\"network\":\"none\"";
        assert(std.mem.indexOf(u8, stderr, word) != null);
        assert(std.mem.indexOf(u8, stderr, "grant with --net") == null); // Text mode's note.
        return;
    }
    // The hint: a failed run that was not given --net, once, last.
    const hints = std.mem.count(u8, stderr, "zbx: network: none (grant with --net)\n");
    const failed = final_code(scenario, status) != 0;
    assert(hints == @intFromBool(failed and scenario.net == .default));
    if (hints == 1) assert(std.mem.endsWith(u8, stderr, "(grant with --net)\n"));
    const skipped = std.mem.count(u8, stderr, "zbx: note: skipped");
    assert(skipped == if (scenario.verbose) skipped_notes(scenario) else 0);
    const oom = scenario.counts_as_oom();
    const limited = scenario.counts_as_pid_limit();
    const killed = std.mem.count(u8, stderr, "the container was killed by signal");
    assert(killed == @intFromBool(status == .signaled and !oom and !limited));
    assert(std.mem.count(u8, stderr, "zbx: killed: out of memory") == @intFromBool(oom));
    assert(std.mem.count(u8, stderr, "zbx: stopped: process limit reached") ==
        @intFromBool(limited));
    const turned_away = std.mem.count(u8, stderr, "); connected to ");
    const fell_back = scenario.scoped() and scenario.verbose and scenario.inherited != .none;
    assert(turned_away == @intFromBool(fell_back));
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
        // (A tree's worker is a process too; it was reaped, and leak() checks that.)
        if (!scenario.image) assert(sim.world.processes[1].state == .unused);
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

/// The version 2 fields of a record: why the run ended, the limits, the scope, not detached.
fn check_record_v2(
    scenario: *const Scenario,
    verdict: *const Verdict,
    parsed: *const records.Parsed,
) void {
    assert(parsed.version == constants.record_version);
    const reason: records.EndReason = switch (verdict.*) {
        .refused => .none,
        .started => |status| if (scenario.counts_as_oom())
            .oom
        else if (scenario.counts_as_pid_limit())
            .pid_limit
        else if (status == .signaled)
            .signal
        else
            .exited,
    };
    assert(parsed.reason == reason);
    assert(!parsed.detached);
    const memory: ?u64 = if (scenario.memory) |item| item.value else null;
    assert(parsed.limits.memory_bytes == memory);
    const pids: ?u32 = if (scenario.pids) |item| @intCast(item.value.?) else null;
    const cpus: ?u32 = if (scenario.cpus) |item| @intCast(item.value.?) else null;
    assert(parsed.limits.pids == pids);
    assert(parsed.limits.cpu_millis == cpus);
    if (scenario.scoped()) {
        var unit: [96]u8 = undefined;
        // Cannot fail: a 63-byte name and ten more bytes.
        const format = "zbx-{s}.scope";
        const name = std.fmt.bufPrint(&unit, format, .{parsed.name_slice()}) catch
            unreachable; // Same bound as above.
        assert(std.mem.eql(u8, parsed.scope_slice(), name));
    } else {
        assert(parsed.scope_slice().len == 0);
    }
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
    check_record_v2(scenario, verdict, &parsed);
    assert(parsed.ids.? == if (scenario.full) records.IdsMode.full else records.IdsMode.single);
    assert(parsed.ended != null);
}
