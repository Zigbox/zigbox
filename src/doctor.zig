//! `zbx doctor`: tells, truthfully, whether this machine can run Zigbox.
//!
//! Three phases (docs/briefs/M0-doctor.md):
//!   gather    reads raw facts through the `Host` into a fixed-size `Facts`. No policy: it records
//!             what each read returned, including the error, and nothing else.
//!   evaluate  a pure function from `Facts` to `Report`. Every question of policy (what counts as
//!             ok, which fix to name) is decided here, by the `evaluate_*` functions.
//!   render    a pure function from `Report` to text.
//!
//! Status and exit code:
//!   ok    the requirement is met.
//!   FAIL  the requirement is not met, or could not be checked. A failed read, a probe that
//!         could not run and a malformed file are all FAIL with the reason: a fault is never
//!         reported as ok, and never as warn. A FAIL carries a diagnostic (DIAGNOSTICS.md):
//!         its check's own code (ZBX-E0101 to E0106, blame environment), its causes, and at
//!         least one fix, with a runnable command where the fix is one. A check that could not
//!         run uses its own code too, and its cause says that it could not run, and why.
//!   warn  the requirement is demonstrably met by a direct test, yet a related setting says it
//!         should not be. Today that is one situation: the user-namespace probe succeeded but
//!         a sysctl (`kernel.unprivileged_userns_clone=0` or
//!         `kernel.apparmor_restrict_unprivileged_userns=1`) says unconfined users are refused,
//!         which happens when this process runs under an AppArmor profile that allows it. A warn
//!         has no fix line, because nothing has to be fixed for this process.
//!   The exit code is 0 if no check is FAIL, 2 (the environment's) otherwise. A warn does not
//!   change it. This file renders only the stdout report; the diagnostic of each FAIL is
//!   rendered by cli.zig, on stderr, in check order.
//!
//! Running as root proves nothing about ordinary users, so nothing here lets uid 0 pass:
//! probes run in a child that drops to an unprivileged id first (host_real.zig), the subid
//! check needs a range for the real uid or user name whoever that is, and file owners and
//! modes are read from the files, not inferred from the caller.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const scope_mod = @import("runtime/scope.zig");
const scope_text = @import("runtime/scope_text.zig");
const parse = @import("parse.zig");
const text_util = @import("text.zig");
const diag_codes = @import("diag/codes.zig");
const diag_errors = @import("diag/errors.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;

pub const Status = enum { ok, fail, warn };

pub const CheckId = enum { kernel, userns, cgroup, overlay, subid, seccomp, net };

pub const Detail = text_util.Bounded(constants.detail_bytes_max);
/// The diagnostic code of each check: one per check, so a FAIL line and its block name the same
/// code. All are errors blamed on the environment (the host, not the command line).
pub fn code_of(id: CheckId) diag_codes.Code {
    const code: diag_codes.Code = switch (id) {
        .kernel => .E0102,
        .userns => .E0101,
        .cgroup => .E0103,
        .overlay => .E0104,
        .subid => .E0105,
        .seccomp => .E0106,
        // The net check only ever warns (a missing pasta fails nothing), so it has no code.
        .net => unreachable, // `Check.problem` is never called for it.
    };
    assert(diag_codes.entry(code).blame == .environment);
    assert(diag_codes.entry(code).severity == .@"error");
    return code;
}

/// A failed host call: the coarse error and the errno the kernel really returned (0 if none).
const Failure = struct {
    err: host_mod.Error,
    errno: u16,
};

pub const Check = struct {
    id: CheckId,
    status: Status,
    /// The text of the stdout line. For a FAIL it is the symptom in one line.
    detail: Detail,
    /// The diagnostic of a FAIL (stderr). Unclassified (`code == null`) for ok and warn.
    diag: Diag,
    /// The FAIL is that the check could not look (a read or a probe failed), not that it looked
    /// and found a setting that forbids what zbx needs.
    could_not_run: bool,

    fn start(check: *Check, id: CheckId) void {
        check.id = id;
        check.status = .ok;
        check.detail = .{};
        check.could_not_run = false;
        check.diag.reset();
        assert(check.detail.len == 0);
        assert(check.diag.code == null);
    }

    fn pass(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.diag.code == null); // A passing check never carries a diagnostic.
        check.status = .ok;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
    }

    fn warning(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.diag.code == null); // A warning has nothing to fix.
        check.status = .warn;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
    }

    /// Records the failure: the stdout line, this check's code, and what was being done. Follow
    /// with `cause`s (symptom first, real cause last: default output shows only the last) and
    /// at least one `fix`.
    fn problem(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.diag.code == null); // One failure per check.
        check.status = .fail;
        check.detail.print(format, args);
        assert(check.detail.len > 0);
        check.diag.raise(code_of(check.id));
        check.diag.while_("running the {s} check of zbx doctor", .{@tagName(check.id)});
        assert(check.diag.whiles.count == 1);
    }

    fn cause(check: *Check, comptime format: []const u8, args: anytype) void {
        assert(check.status == .fail);
        check.diag.cause(format, args);
    }

    /// The stdout symptom as the first cause, for failures whose real cause is added after it.
    fn cause_symptom(check: *Check) void {
        assert(check.status == .fail);
        assert(check.diag.causes.count == 0); // Symptom first.
        check.diag.cause("{s}", .{check.detail.slice()});
    }

    /// The cause of a check that could not run: "the <check> check could not run: <what>
    /// failed: <reason> (<ENAME>)". The errno is the one the kernel returned, or the cause says
    /// it is unknown (diag/errors.zig).
    fn cause_could_not_run(check: *Check, what: []const u8, failure: Failure) void {
        assert(check.status == .fail);
        assert(what.len > 0);
        assert(what.len <= 160);
        check.could_not_run = true;
        var buffer: [256]u8 = undefined;
        const format = "the {s} check could not run: {s}";
        // Cannot fail: the check name is at most 7 bytes and `what` at most 160.
        const operation = std.fmt.bufPrint(&buffer, format, .{ @tagName(check.id), what }) catch
            unreachable; // Same bound as above.
        const diag = &check.diag;
        diag_errors.cause_host_error(diag, operation, failure.err, failure.errno);
    }

    fn context_path(check: *Check, path: []const u8) void {
        assert(check.status == .fail);
        assert(path.len > 0);
        check.diag.context("path", "{s}", .{path});
    }

    /// A fix. `command` is runnable as written, or empty when the fix is prose only.
    fn fix(check: *Check, sentence: []const u8, command: []const u8) void {
        assert(check.status == .fail);
        assert(sentence.len > 0);
        check.diag.fix(.{ .sentence = sentence, .command = command });
        assert(check.diag.fixes.count > 0);
    }

    /// A fix whose command is formatted from run-time text.
    fn fix_with(
        check: *Check,
        sentence: []const u8,
        comptime command_format: []const u8,
        command_args: anytype,
    ) void {
        assert(check.status == .fail);
        check.diag.fix_with(sentence, command_format, command_args);
        assert(check.diag.fixes.count > 0);
    }
};

pub const Report = struct {
    checks: [constants.doctor_checks_count]Check,

    /// The exit code is the blame of the first failing check's diagnostic: the one place that
    /// decides it (diag/codes.zig). Every failure here is the environment's.
    pub fn exit_code(report: *const Report) u8 {
        // The checks are always in the fixed order the renderer and the fuzzers rely on.
        assert(report.checks[0].id == .kernel);
        assert(report.checks[report.checks.len - 1].id == .net);
        for (report.checks) |check| {
            if (check.status == .fail) return check.diag.exit_code();
        }
        return constants.exit_ok;
    }

    /// Structural invariants every report must satisfy, whatever the host looked like.
    pub fn validate(report: *const Report) void {
        for (&report.checks, 0..) |*check, index| {
            assert(@backingInt(check.id) == index);
            assert(check.detail.len > 0);
            switch (check.status) {
                .ok, .warn => assert(check.diag.code == null),
                .fail => validate_failure(check),
            }
        }
    }

    fn validate_failure(check: *const Check) void {
        assert(check.status == .fail);
        assert(check.diag.code.? == code_of(check.id)); // The line and the block agree.
        assert(check.diag.entry().blame == .environment);
        assert(check.diag.causes.count > 0);
        assert(check.diag.fixes.count > 0);
        assert(check.diag.exit_code() == constants.exit_environment);
    }
};

// ---- Facts ---------------------------------------------------------------------------------

/// One file read: the bytes and length on success, the error otherwise.
fn Slot(comptime capacity: u32) type {
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        len: u32 = 0,
        err: ?host_mod.Error = null,
        /// The errno the kernel really returned for `err`, or 0 if there was none (see
        /// `Host.last_errno`). Diagnostics name it; they never guess one.
        errno: u16 = 0,
        attempted: bool = false,

        fn reset(slot: *Self) void {
            slot.len = 0;
            slot.err = null;
            slot.errno = 0;
            slot.attempted = false;
        }

        fn load(slot: *Self, host: Host, path: []const u8) void {
            assert(path.len > 0);
            slot.reset();
            slot.attempted = true;
            const content = host.read_file(path, &slot.bytes) catch |err| {
                slot.err = err;
                slot.errno = host.last_errno();
                return;
            };
            slot.len = @intCast(content.len);
            assert(slot.len <= capacity);
            assert(slot.err == null);
        }

        fn text(slot: *const Self) []const u8 {
            assert(slot.attempted);
            assert(slot.err == null);
            return slot.bytes[0..slot.len];
        }
    };
}

const ProbeFact = struct {
    outcome: host_mod.ProbeOutcome = .ok,
    err: ?host_mod.Error = null,
    errno: u16 = 0,

    /// True if the probe ran and gave exactly this outcome.
    fn is(fact: ProbeFact, outcome: host_mod.ProbeOutcome) bool {
        if (fact.err != null) return false;
        return fact.outcome == outcome;
    }

    fn run(fact: *ProbeFact, host: Host, kind: host_mod.ProbeKind) void {
        fact.err = null;
        fact.errno = 0;
        fact.outcome = host.probe(kind) catch |err| {
            fact.err = err;
            fact.errno = host.last_errno();
            // A probe never reads a file, so it cannot report the size-limit error.
            assert(err != error.FileTooLarge);
            return;
        };
        assert(fact.err == null);
    }
};

/// One `stat` of a path: the result or the error.
const StatFact = struct {
    stat: host_mod.Stat = .{ .mode = 0, .uid = 0 },
    err: ?host_mod.Error = null,
    errno: u16 = 0,
    attempted: bool = false,
};

/// What the look for `pasta` found: where it is on PATH, and what `pasta --version` said.
const PastaFact = struct {
    attempted: bool = false,
    found: bool = false,
    path: text_util.Bounded(constants.pasta_path_bytes_max) = .{},
    /// `--version` was run; how it ended (null if it could not be run at all), and the first
    /// line it wrote.
    ran: bool = false,
    status: ?host_mod.ExitStatus = null,
    version: text_util.Bounded(constants.pasta_version_bytes_max) = .{},
};

/// A candidate location of newuidmap or newgidmap.
const Binary = struct {
    stat: host_mod.Stat = .{ .mode = 0, .uid = 0 },
    stat_err: ?host_mod.Error = null,
    stat_errno: u16 = 0,
    capability: [constants.capability_bytes_max]u8 = undefined,
    capability_len: u32 = 0,
    capability_err: ?host_mod.Error = null,
    capability_errno: u16 = 0,

    fn load(binary: *Binary, host: Host, path: []const u8) void {
        binary.* = .{};
        binary.stat = host.stat(path) catch |err| {
            binary.stat_err = err;
            binary.stat_errno = host.last_errno();
            return;
        };
        const bytes = host.read_capability(path, &binary.capability) catch |err| {
            binary.capability_err = err;
            binary.capability_errno = host.last_errno();
            return;
        };
        binary.capability_len = @intCast(bytes.len);
        assert(binary.capability_len <= constants.capability_bytes_max);
        assert(binary.capability_err == null);
    }
};

const binary_directories = [constants.binary_candidates_count][]const u8{
    "/usr/bin/",
    "/bin/",
    "/usr/local/bin/",
};
const program_names = [2][]const u8{ "newuidmap", "newgidmap" };

comptime {
    // Facts is 200 KiB: far more than a small `ulimit -s` or a thread's stack. Every user is
    // handed one by its caller (a run's `Handle` holds one, so does the bundle workspace), so
    // two threads never share it.
    assert(@sizeOf(Facts) <= constants.facts_bytes_max);
    assert(constants.facts_bytes_max > 64 * 1024);
}

/// What the probe of the user's bus found: the systemd version, or why there is none.
pub const BusFact = struct {
    /// The probe ran: the user manager's cgroup exists, so there may be a bus to ask.
    attempted: bool = false,
    ok: bool = false,
    version: u32 = 0,
    version_text: client_text = .{},
    problem: scope_mod.Problem = .no_address,
};

const client_text = @import("dbus/client.zig").Text;

pub const Facts = struct {
    uname: ?host_mod.Uname,
    uname_err: ?host_mod.Error,
    uname_errno: u16,

    max_user_namespaces: Slot(constants.sysctl_bytes_max),
    unprivileged_userns_clone: Slot(constants.sysctl_bytes_max),
    apparmor_restrict: Slot(constants.sysctl_bytes_max),
    probe_userns: ProbeFact,

    cgroup_root: Slot(constants.cgroup_list_bytes_max),
    /// `user@UID.service` below /sys/fs/cgroup: the cgroup systemd delegates to the user.
    cgroup_user: StatFact,
    cgroup_controllers: Slot(constants.cgroup_list_bytes_max),
    /// The systemd user manager on the user's D-Bus, which zbx asks for each container's scope.
    bus: BusFact,

    probe_overlay: ProbeFact,

    uid: u32,
    passwd: Slot(constants.passwd_bytes_max),
    subuid: Slot(constants.subid_bytes_max),
    subgid: Slot(constants.subid_bytes_max),
    binaries: [2][constants.binary_candidates_count]Binary,

    status: Slot(constants.status_bytes_max),
    seccomp: ?u32,
    seccomp_err: ?host_mod.Error,
    seccomp_errno: u16,

    /// `pasta`, which `--net user` and `--publish` need.
    pasta: PastaFact,

    /// Clears every flag and result; the byte buffers are left as they are. Facts is large, so
    /// it is initialised in place rather than by assigning a struct value.
    pub fn reset(facts: *Facts) void {
        facts.uname = null;
        facts.uname_err = null;
        facts.uname_errno = 0;
        facts.max_user_namespaces.reset();
        facts.unprivileged_userns_clone.reset();
        facts.apparmor_restrict.reset();
        facts.probe_userns = .{};
        facts.cgroup_root.reset();
        facts.cgroup_user = .{};
        facts.cgroup_controllers.reset();
        facts.bus = .{};
        facts.probe_overlay = .{};
        facts.uid = 0;
        facts.passwd.reset();
        facts.subuid.reset();
        facts.subgid.reset();
        facts.binaries = @splat(@splat(.{}));
        facts.status.reset();
        facts.seccomp = null;
        facts.seccomp_err = null;
        facts.seccomp_errno = 0;
        facts.pasta = .{};
    }
};

// ---- Gather --------------------------------------------------------------------------------

pub fn gather(host: Host, facts: *Facts) void {
    for (std.enums.values(CheckId)) |id| gather_one(host, facts, id);
    // Every check's facts were gathered, whatever the reads returned.
    assert(facts.cgroup_user.attempted);
    assert(facts.passwd.attempted);
    if (facts.seccomp_err == null) assert(facts.seccomp != null);
}

/// Gathers the facts one check needs. Public so tests can attribute injected faults to checks.
pub fn gather_one(host: Host, facts: *Facts, id: CheckId) void {
    switch (id) {
        .kernel => gather_kernel(host, facts),
        .userns => gather_userns(host, facts),
        .cgroup => gather_cgroup(host, facts),
        .overlay => facts.probe_overlay.run(host, .overlay),
        .subid => gather_subid(host, facts),
        .seccomp => gather_seccomp(host, facts),
        .net => gather_net(host, facts),
    }
    // Each id ran its own gather step, not a neighbour's.
    switch (id) {
        .kernel => if (facts.uname_err == null) assert(facts.uname != null),
        .userns => assert(facts.max_user_namespaces.attempted),
        .cgroup => assert(facts.cgroup_user.attempted),
        .overlay => {}, // The probe fact holds either an outcome or an error; both are valid.
        .subid => assert(facts.subgid.attempted),
        .seccomp => assert(facts.status.attempted),
        .net => assert(facts.pasta.attempted),
    }
}

fn gather_kernel(host: Host, facts: *Facts) void {
    facts.uname_err = null;
    facts.uname_errno = 0;
    facts.uname = host.uname() catch |err| {
        facts.uname_err = err;
        facts.uname_errno = host.last_errno();
        return;
    };
    assert(facts.uname != null);
    assert(facts.uname_err == null);
}

fn gather_userns(host: Host, facts: *Facts) void {
    facts.max_user_namespaces.load(host, "/proc/sys/user/max_user_namespaces");
    facts.unprivileged_userns_clone.load(host, "/proc/sys/kernel/unprivileged_userns_clone");
    facts.apparmor_restrict.load(host, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    facts.probe_userns.run(host, .userns);
    assert(facts.max_user_namespaces.attempted);
    assert(facts.apparmor_restrict.attempted);
}

/// Where systemd keeps the cgroup it delegates to a user: the user manager's service cgroup.
fn user_manager_path(buffer: []u8, uid: u32) []const u8 {
    assert(buffer.len >= 100); // The longest path is 86 bytes plus two ten-digit uids.
    const format = "/sys/fs/cgroup/user.slice/user-{d}.slice/user@{d}.service";
    // Cannot fail: a u32 has at most ten digits, and the buffers passed in are far larger.
    const path = std.fmt.bufPrint(buffer, format, .{ uid, uid }) catch unreachable;
    assert(path.len > "/sys/fs/cgroup/".len);
    assert(std.mem.endsWith(u8, path, ".service"));
    return path;
}

fn gather_cgroup(host: Host, facts: *Facts) void {
    facts.uid = host.uid();
    facts.cgroup_root.load(host, "/sys/fs/cgroup/cgroup.controllers");
    facts.cgroup_controllers.reset();
    facts.cgroup_user = .{ .attempted = true };
    facts.bus = .{};
    var buffer: [160]u8 = undefined;
    const directory = user_manager_path(&buffer, facts.uid);
    facts.cgroup_user.stat = host.stat(directory) catch |err| {
        facts.cgroup_user.err = err;
        facts.cgroup_user.errno = host.last_errno();
        return;
    };
    // The controllers file is only read where the directory exists; evaluate reports why not.
    var file_buffer: [192]u8 = undefined;
    const file = std.fmt.bufPrint(&file_buffer, "{s}/cgroup.controllers", .{directory});
    // Cannot fail: the directory path is under 160 bytes, so the file path fits 192.
    facts.cgroup_controllers.load(host, file catch unreachable);
    assert(facts.cgroup_root.attempted);
    assert(facts.cgroup_controllers.attempted);
    gather_bus(host, facts);
}

/// Asks the user's bus for the systemd `Version` (read-only): zbx makes each container's scope
/// there. Only where the user manager exists, since without it there is no bus to ask.
fn gather_bus(host: Host, facts: *Facts) void {
    assert(facts.cgroup_user.attempted);
    assert(!facts.bus.attempted);
    if (facts.cgroup_user.err != null) return;
    var probe: scope_mod.Probe = undefined;
    facts.bus.attempted = true;
    facts.bus.ok = scope_mod.probe(host, &probe, &facts.bus.problem);
    if (!facts.bus.ok) return;
    facts.bus.version = probe.version;
    facts.bus.version_text = probe.version_text;
    assert(facts.bus.version > 0);
}

fn gather_subid(host: Host, facts: *Facts) void {
    facts.uid = host.uid();
    assert(facts.binaries.len == program_names.len);
    facts.passwd.load(host, "/etc/passwd");
    facts.subuid.load(host, "/etc/subuid");
    facts.subgid.load(host, "/etc/subgid");
    for (program_names, 0..) |name, program| {
        for (binary_directories, 0..) |directory, candidate| {
            var buffer: [64]u8 = undefined;
            const joined = std.fmt.bufPrint(&buffer, "{s}{s}", .{ directory, name });
            // Cannot fail: directory and program names are short constants.
            const path = joined catch unreachable;
            facts.binaries[program][candidate].load(host, path);
        }
    }
    assert(facts.passwd.attempted);
    assert(facts.subuid.attempted);
}

fn gather_seccomp(host: Host, facts: *Facts) void {
    facts.status.load(host, "/proc/self/status");
    facts.seccomp_err = null;
    facts.seccomp_errno = 0;
    facts.seccomp = host.seccomp_mode() catch |err| {
        facts.seccomp_err = err;
        facts.seccomp_errno = host.last_errno();
        return;
    };
    assert(facts.status.attempted);
    assert(facts.seccomp_err == null);
}

/// Looks for `pasta` in the directories of PATH, as a shell would, and asks the first one for its
/// version. Nothing here fails the doctor: the evaluation decides what a missing or broken
/// pasta means.
fn gather_net(host: Host, facts: *Facts) void {
    facts.pasta = .{ .attempted = true };
    const default_path = "/usr/local/bin:/usr/bin:/bin";
    const search = host.environment("PATH", constants.path_bytes_max) orelse default_path;
    var directories = std.mem.splitScalar(u8, search, ':');
    var tried: u32 = 0;
    while (directories.next()) |directory| {
        if (directory.len == 0 or directory[0] != '/') continue;
        tried += 1;
        if (tried > constants.pasta_path_dirs_max) break;
        var buffer: [constants.pasta_path_bytes_max + 1]u8 = undefined;
        if (directory.len + "/pasta".len >= constants.pasta_path_bytes_max) continue;
        const joined = std.fmt.bufPrintSentinel(&buffer, "{s}/pasta", .{directory}, 0);
        const path = joined catch unreachable; // The length was checked against the buffer.
        const found = host.stat(path) catch continue;
        const is_file = found.mode & std.posix.S.IFMT == std.posix.S.IFREG;
        if (!is_file or found.mode & 0o111 == 0) continue;
        facts.pasta.found = true;
        facts.pasta.path.print("{s}", .{path});
        break;
    }
    if (facts.pasta.found) ask_pasta_version(host, facts);
    assert(facts.pasta.attempted);
    if (!facts.pasta.found) assert(!facts.pasta.ran);
}

fn ask_pasta_version(host: Host, facts: *Facts) void {
    assert(facts.pasta.found);
    assert(facts.pasta.path.len > 0);
    var path_storage: [constants.pasta_path_bytes_max + 1]u8 = undefined;
    @memcpy(path_storage[0..facts.pasta.path.len], facts.pasta.path.slice());
    path_storage[facts.pasta.path.len] = 0;
    const path: [:0]const u8 = path_storage[0..facts.pasta.path.len :0];
    const argv = [_:null]?[*:0]const u8{ "pasta", "--version" };
    const none = [_:null]?[*:0]const u8{};
    var output: [constants.pasta_version_bytes_max]u8 = undefined;
    const result = host.run_helper(.{
        .path = path,
        .argv = &argv,
        .envp = &none,
    }, &output) catch return;
    facts.pasta.ran = true;
    facts.pasta.status = result.status;
    const text = output[0..result.output_len];
    const line_end = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    facts.pasta.version.append_sanitised(std.mem.trim(u8, text[0..line_end], " \t\r"), 80);
}

// ---- Evaluate ------------------------------------------------------------------------------
//
// All policy lives here: what counts as ok, and for each failure the code's cause and fixes.
// Each failing site states the symptom (`problem`), the causes (the real one last), and the
// fixes, with a runnable command wherever the fix is one.

pub fn evaluate(facts: *const Facts, report: *Report) void {
    // The facts must have been gathered; a zero uid with no passwd attempt means they were not.
    assert(facts.passwd.attempted);
    assert(facts.status.attempted);
    for (std.enums.values(CheckId), 0..) |id, index| {
        const check = &report.checks[index];
        check.start(id);
        switch (id) {
            .kernel => evaluate_kernel(facts, check),
            .userns => evaluate_userns(facts, check),
            .cgroup => evaluate_cgroup(facts, check),
            .overlay => evaluate_overlay(facts, check),
            .subid => evaluate_subid(facts, check),
            .seccomp => evaluate_seccomp(facts, check),
            .net => evaluate_net(facts, check),
        }
        if (check.status == .fail) add_context(facts, check);
    }
    report.validate();
}

/// Facts that help read any failure in `--verbose`: the kernel, and who the check ran as for
/// the checks that depend on the user. Only what was really gathered is shown.
fn add_context(facts: *const Facts, check: *Check) void {
    assert(check.status == .fail);
    assert(check.diag.code != null);
    if (facts.uname) |names| {
        var storage: [constants.uname_field_bytes]u8 = undefined;
        check.diag.context("kernel", "{s}", .{text_util.sanitise(&storage, names.release.slice())});
    }
    switch (check.id) {
        .cgroup, .subid => check.diag.context("uid", "{d}", .{facts.uid}),
        .kernel, .userns, .overlay, .seccomp, .net => {},
    }
}

fn error_reason(err: host_mod.Error) []const u8 {
    const reason: []const u8 = switch (err) {
        error.NotFound => "not found",
        error.AccessDenied => "permission denied",
        error.Interrupted => "interrupted",
        error.WouldBlock => "would block",
        error.NoSpace => "no space",
        error.OutOfMemory => "out of memory",
        error.PathTooLong, error.InvalidPath => "invalid path",
        error.FileTooLarge => "larger than the size limit",
        error.Stalled => "made no progress",
        error.Unsupported => "not supported by this kernel",
        error.NoData => "no such attribute",
        error.TimedOut => "timed out",
        error.IoFailed => "input/output error",
    };
    assert(reason.len > 0);
    assert(reason.len < 40); // One short phrase inside a sentence.
    return reason;
}

const Access = enum { read, stat };

/// A read or stat that failed. `path` is shown to the user; the fix is the same for every file.
fn read_failed(check: *Check, access: Access, path: []const u8, failure: Failure) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(path.len > 0);
    assert(path.len <= 120); // Every path is a constant or built from a uid.
    check.problem("cannot read {s}: {s}", .{ path, error_reason(failure.err) });
    var what: [160]u8 = undefined;
    const verb = if (access == .read) "read" else "stat";
    // Cannot fail: the path is at most 120 bytes, the verb at most 4, and the buffer 160.
    const operation = std.fmt.bufPrint(&what, "{s}({s})", .{ verb, path }) catch unreachable;
    check.cause_could_not_run(operation, failure);
    check.context_path(path);
    const sentence = "check the file, then retry:";
    check.fix_with(sentence, "ls -l {s}", .{path});
    assert(check.status == .fail);
    assert(check.diag.fixes.count == 1);
}

fn probe_problem(check: *Check, name: []const u8, fact: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (fact.err == null) assert(fact.outcome != .ok);
    if (fact.err) |err| {
        check.problem("the {s} probe could not run: {s}", .{ name, error_reason(err) });
        var what: [64]u8 = undefined;
        const format = "starting the {s} probe";
        // Cannot fail: `name` is a short constant.
        const operation = std.fmt.bufPrint(&what, format, .{name}) catch unreachable; // Same.
        check.cause_could_not_run(operation, .{ .err = err, .errno = fact.errno });
        const sentence = "check the process limits:";
        check.fix(sentence, "ulimit -u");
        return;
    }
    switch (fact.outcome) {
        .timed_out => {
            check.problem("the {s} probe did not finish in {d} ms and was killed", .{
                name, constants.probe_timeout_ms,
            });
            check.cause(
                "the {s} probe child made no progress for {d} ms, so zbx killed it and could " ++
                    "not tell whether this host allows the operation",
                .{ name, constants.probe_timeout_ms },
            );
        },
        .signaled => {
            check.problem("the {s} probe child was killed by a signal", .{name});
            check.cause("the {s} probe child was ended by a signal before it reported a result, " ++
                "so zbx could not tell whether this host allows the operation", .{name});
        },
        else => {
            check.problem("the {s} probe child failed unexpectedly", .{name});
            check.cause("the {s} probe child ended with a result zbx does not recognise, so it " ++
                "could not tell whether this host allows the operation", .{name});
        },
    }
    check.fix("look in the kernel log:", "sudo dmesg | tail -n 50");
}

// kernel

/// 5.15 is the oldest kernel the project supports. Overlayfs mounts inside user namespaces
/// arrived in 5.11 (per the 5.11 release notes), and 5.15 is the oldest long-term-support
/// kernel that has them, so it is the oldest one still widely deployed with the feature.
fn evaluate_kernel(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (facts.uname_err == null) assert(facts.uname != null); // gather_kernel ran.
    if (facts.uname_err) |err| {
        check.problem("cannot read the kernel release: {s}", .{error_reason(err)});
        check.cause_could_not_run("uname()", .{ .err = err, .errno = facts.uname_errno });
        check.fix("check that uname works:", "uname -r");
        return;
    }
    const names = facts.uname.?;
    var storage: [constants.uname_field_bytes]u8 = undefined;
    const release = text_util.sanitise(&storage, names.release.slice());
    const version = parse.parse_kernel_release(names.release.slice()) catch {
        check.problem("unrecognised kernel release '{s}'", .{release});
        check.cause("the release '{s}' does not start with a major.minor version, and zbx " ++
            "does not guess", .{release});
        check.fix("see what this kernel reports:", "uname -r");
        check.fix("run Linux 5.15 or newer", "");
        return;
    };
    const minimum = [2]u32{ constants.kernel_major_min, constants.kernel_minor_min };
    if (kernel_at_least(version, minimum)) {
        var machine_storage: [constants.uname_field_bytes]u8 = undefined;
        const machine = text_util.sanitise(&machine_storage, names.machine.slice());
        check.pass("{s} {s} (minimum {d}.{d})", .{ release, machine, minimum[0], minimum[1] });
        return;
    }
    check.problem("kernel {s} is older than {d}.{d}", .{ release, minimum[0], minimum[1] });
    check.cause_symptom();
    check.cause("zbx needs Linux {d}.{d} or newer: overlayfs mounts in user namespaces arrived " ++
        "in 5.11, and {d}.{d} is the oldest long-term kernel that has them", .{
        minimum[0], minimum[1], minimum[0], minimum[1],
    });
    var sentence: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&sentence, "upgrade to Linux {d}.{d} or newer", .{
        minimum[0], minimum[1],
    }) catch unreachable; // Two small numbers fit 64 bytes.
    check.fix(text, "");
}

fn kernel_at_least(version: parse.KernelVersion, minimum: [2]u32) bool {
    assert(version.major <= 999_999_999); // The parser accepts at most nine digits.
    assert(minimum[1] < 1000);
    if (version.major > minimum[0]) return true;
    if (version.major < minimum[0]) return false;
    return version.minor >= minimum[1];
}

// userns

/// The sysctl values that bear on user namespaces; `null` for a sysctl the kernel lacks.
const UsernsSysctls = struct {
    max_user_namespaces: u32,
    clone: ?u32,
    restrict: ?u32,
};

/// A sysctl file that holds something other than a number: damaged, or not a sysctl at all.
fn not_a_number(check: *Check, path: []const u8) void {
    assert(check.detail.len == 0);
    assert(path.len > 0);
    check.problem("{s} holds something other than a number", .{path});
    check.cause("the kernel only ever writes a decimal number to this sysctl, so the file is " ++
        "damaged or is not the sysctl", .{});
    check.context_path(path);
    check.fix_with("look at the file:", "cat {s}", .{path});
}

/// Reads a sysctl slot that must exist. Reports a failure on `check` and returns null.
fn required_sysctl(check: *Check, slot: anytype, path: []const u8) ?u32 {
    assert(slot.attempted);
    assert(path.len > 0);
    if (slot.err) |err| {
        if (err == error.NotFound) {
            check.problem("{s} does not exist", .{path});
            check.cause_symptom();
            check.cause("this kernel was built without user namespaces (CONFIG_USER_NS)", .{});
            check.context_path(path);
            check.fix("use a kernel built with CONFIG_USER_NS=y", "");
        } else {
            read_failed(check, .read, path, .{ .err = err, .errno = slot.errno });
        }
        return null;
    }
    return parse.parse_sysctl_uint(slot.text()) catch {
        not_a_number(check, path);
        return null;
    };
}

/// Reads a sysctl that older or other kernels do not have: absence is an answer, any other
/// failure is not.
fn optional_sysctl(check: *Check, slot: anytype, path: []const u8) error{Failed}!?u32 {
    assert(slot.attempted);
    assert(path.len > 0);
    if (slot.err) |err| {
        if (err == error.NotFound) return null;
        read_failed(check, .read, path, .{ .err = err, .errno = slot.errno });
        return error.Failed;
    }
    return parse.parse_sysctl_uint(slot.text()) catch {
        not_a_number(check, path);
        return error.Failed;
    };
}

fn evaluate_userns(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.max_user_namespaces.attempted); // gather_userns ran.
    assert(facts.unprivileged_userns_clone.attempted);
    assert(facts.apparmor_restrict.attempted);
    const max_path = "/proc/sys/user/max_user_namespaces";
    const clone_path = "/proc/sys/kernel/unprivileged_userns_clone";
    const restrict_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    const max = required_sysctl(check, facts.max_user_namespaces, max_path) orelse return;
    const clone = optional_sysctl(check, facts.unprivileged_userns_clone, clone_path) catch return;
    const restrict = optional_sysctl(check, facts.apparmor_restrict, restrict_path) catch return;
    const sysctls: UsernsSysctls = .{
        .max_user_namespaces = max,
        .clone = clone,
        .restrict = restrict,
    };
    userns_verdict(check, sysctls, facts.probe_userns);
}

fn userns_verdict(check: *Check, sysctls: UsernsSysctls, probe: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const probe_ran = probe.err == null;
    const probe_ok = probe_ran and probe.outcome == .ok;
    if (sysctls.max_user_namespaces == 0) {
        check.problem("user.max_user_namespaces is 0, so no user namespace can be created", .{});
        check.cause_symptom();
        check.cause("the sysctl user.max_user_namespaces = 0 caps the user namespaces this " ++
            "system allows at none, for every user", .{});
        check.fix("allow user namespaces:", "sudo sysctl -w user.max_user_namespaces=15000");
        return;
    }
    assert(sysctls.max_user_namespaces != 0); // The zero case returned above.
    if (sysctls.clone == 0) {
        if (probe_ok) return restricted_but_working(check, "kernel.unprivileged_userns_clone=0");
        check.problem("kernel.unprivileged_userns_clone is 0 (unprivileged refused)", .{});
        check.cause_symptom();
        check.cause("this kernel refuses user namespaces to unprivileged users while " ++
            "kernel.unprivileged_userns_clone = 0", .{});
        check.fix("allow them:", "sudo sysctl -w kernel.unprivileged_userns_clone=1");
        return;
    }
    if (sysctls.restrict) |restrict| {
        if (restrict != 0) return userns_restricted(check, probe_ok);
    }
    if (!probe_ok) return userns_probe_verdict(check, probe);
    check.pass("user.max_user_namespaces={d}, unshare(CLONE_NEWUSER) works", .{
        sysctls.max_user_namespaces,
    });
}

fn userns_restricted(check: *Check, probe_ok: bool) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const setting = "kernel.apparmor_restrict_unprivileged_userns=1";
    if (probe_ok) return restricted_but_working(check, setting);
    check.problem("AppArmor restricts unprivileged user namespaces", .{});
    check.cause_symptom();
    check.cause("this host restricts unprivileged user namespaces through AppArmor " ++
        "(kernel.apparmor_restrict_unprivileged_userns = 1)", .{});
    const setting_off = "kernel.apparmor_restrict_unprivileged_userns=0";
    check.fix("allow them system-wide:", "sudo sysctl -w " ++ setting_off);
    const persist = "echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | " ++
        "sudo tee /etc/sysctl.d/60-zigbox-userns.conf";
    check.fix("keep it after a reboot:", persist);
}

fn restricted_but_working(check: *Check, setting: []const u8) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    check.warning("unshare works for this process, but {s} refuses unconfined users", .{setting});
}

const dmesg_policy = "sudo dmesg | grep -iE 'apparmor|seccomp|selinux|userns'";

/// The sysctls say yes but the probe said otherwise: the interesting case.
fn userns_probe_verdict(check: *Check, probe: ProbeFact) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    if (probe.is(.denied)) {
        check.problem("sysctls allow it, but unshare(CLONE_NEWUSER) was refused", .{});
        check.cause_symptom();
        check.cause("no sysctl forbids user namespaces here, so a security policy (AppArmor, " ++
            "SELinux or a seccomp filter) is refusing the call", .{});
        check.fix("look for the policy that denies it:", dmesg_policy);
        return;
    }
    if (probe.is(.map_denied)) return map_denied(check);
    assert(!probe.is(.ok)); // Only reached when the probe did not succeed.
    probe_problem(check, "user namespace", probe);
}

/// The namespace was created, but writing setgroups/gid_map/uid_map was refused.
fn map_denied(check: *Check) void {
    assert(check.status == .ok);
    assert(check.diag.code == null);
    check.problem("a user namespace can be created, but writing its id map was refused", .{});
    check.cause_symptom();
    check.cause("the kernel created the namespace and then refused the write to its uid_map, " ++
        "gid_map or setgroups file; an LSM policy can forbid that, and only the user's own id " ++
        "may be mapped without newuidmap", .{});
    check.fix("look for the policy that denies it:", dmesg_policy);
    // Ubuntu's AppArmor restriction shows up like this in the overlay probe, next to a userns
    // FAIL: the namespace exists but has no privilege to write its map.
    if (check.id == .overlay) {
        check.fix("if the userns check failed too, fix it first (ZBX-E0101)", "");
    }
}

// cgroup

const required_controllers = [_]parse.Controller{ .cpu, .memory, .pids };

/// Three runnable steps that delegate the controllers to user services: the drop-in directory,
/// the drop-in, and the reload. A fresh login restarts the user manager with them.
fn delegate_fixes(check: *Check) void {
    assert(check.status == .fail);
    assert(check.diag.fixes.count == 0); // The three steps are the whole fix.
    const directory = "/etc/systemd/system/user@.service.d";
    check.fix("create the drop-in directory:", "sudo mkdir -p " ++ directory);
    const write = "printf '[Service]\\nDelegate=cpu cpuset io memory pids\\n' | " ++
        "sudo tee " ++ directory ++ "/delegate.conf";
    check.fix("delegate the controllers:", write);
    check.fix("reload, then log in again:", "sudo systemctl daemon-reload");
    assert(check.diag.fixes.count == 3);
}

/// The file below a user manager directory that lists the controllers it offers.
fn controllers_path(buffer: []u8, directory: []const u8) []const u8 {
    assert(buffer.len >= 192);
    assert(directory.len < 160);
    // Cannot fail: the directory path is under 160 bytes, so the file path fits 192.
    const path = std.fmt.bufPrint(buffer, "{s}/cgroup.controllers", .{directory}) catch unreachable;
    assert(std.mem.endsWith(u8, path, "/cgroup.controllers"));
    return path;
}

/// What zbx will rely on (M2 creates its scope under the systemd user manager) is the cgroup
/// systemd delegates to the user: `user@UID.service`. It must exist, belong to the user, and
/// offer cpu, memory and pids. The process's own cgroup (an ssh session scope, say) is not the
/// one that matters, so /proc/self/cgroup is not consulted.
fn evaluate_cgroup(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.cgroup_root.attempted); // gather_cgroup ran.
    assert(facts.cgroup_user.attempted);
    if (facts.cgroup_root.err) |err| {
        const root_file = "/sys/fs/cgroup/cgroup.controllers";
        const failure: Failure = .{ .err = err, .errno = facts.cgroup_root.errno };
        if (err != error.NotFound) return read_failed(check, .read, root_file, failure);
        return cgroup_v2_missing(check);
    }
    var buffer: [160]u8 = undefined;
    const directory = user_manager_path(&buffer, facts.uid);
    if (facts.cgroup_user.err) |err| {
        const failure: Failure = .{ .err = err, .errno = facts.cgroup_user.errno };
        if (err != error.NotFound) return read_failed(check, .stat, directory, failure);
        return user_manager_missing(check, facts.uid, directory);
    }
    if (!cgroup_owned_directory(check, facts, directory)) return;
    var file_buffer: [192]u8 = undefined;
    const file = controllers_path(&file_buffer, directory);
    if (facts.cgroup_controllers.err) |err| {
        const failure: Failure = .{ .err = err, .errno = facts.cgroup_controllers.errno };
        return read_failed(check, .read, file, failure);
    }
    const offered = parse.parse_controller_list(facts.cgroup_controllers.text()) catch {
        check.problem("cgroup.controllers of the user manager is malformed", .{});
        check.cause("the kernel writes cgroup.controllers as space-separated lowercase names, " ++
            "and this file does not look like that", .{});
        check.context_path(file);
        check.fix_with("look at the file:", "cat {s}", .{file});
        return;
    };
    cgroup_verdict(check, facts.uid, offered, &facts.bus);
}

fn cgroup_v2_missing(check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    check.problem("cgroup v2 is not mounted at /sys/fs/cgroup (cgroup v1 or hybrid host)", .{});
    check.cause_symptom();
    check.cause("/sys/fs/cgroup/cgroup.controllers exists only on the unified cgroup v2 " ++
        "hierarchy, so this host runs cgroup v1 or the hybrid layout", .{});
    check.fix("check the mount (cgroup2fs is v2):", "stat -fc %T /sys/fs/cgroup");
    check.fix("boot with systemd.unified_cgroup_hierarchy=1, or use a cgroup v2 distro", "");
    assert(check.diag.fixes.count == 2);
}

fn user_manager_missing(check: *Check, uid: u32, directory: []const u8) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    check.problem("no systemd user manager for uid {d}: {s} does not exist", .{ uid, directory });
    check.cause_symptom();
    check.cause("systemd starts user@{d}.service when the user has a login session or lingering " ++
        "enabled, and neither is active", .{uid});
    check.context_path(directory);
    check.fix("keep the manager running:", "sudo loginctl enable-linger $(id -un)");
    check.fix("or log in through a systemd (logind) session, such as ssh or a console", "");
}

/// True if the user manager's cgroup is a directory owned by the user; otherwise reports.
fn cgroup_owned_directory(check: *Check, facts: *const Facts, directory: []const u8) bool {
    assert(check.status == .ok);
    assert(facts.cgroup_user.attempted);
    assert(directory.len > 0);
    assert(facts.cgroup_user.err == null);
    const stat = facts.cgroup_user.stat;
    if (stat.mode & std.posix.S.IFMT != std.posix.S.IFDIR) {
        check.problem("{s} is not a directory", .{directory});
        check.cause("a cgroup is a directory, so this path cannot be the cgroup systemd " ++
            "delegates to the user", .{});
        check.context_path(directory);
        delegate_fixes(check);
        return false;
    }
    if (stat.uid == facts.uid) return true;
    check.problem("{s} is owned by uid {d}, not by uid {d}: it is not delegated to this user", .{
        directory, stat.uid, facts.uid,
    });
    check.cause_symptom();
    check.cause("only the owner of a cgroup can hand parts of it to unprivileged code, and " ++
        "uid {d} does not own this one", .{facts.uid});
    check.context_path(directory);
    delegate_fixes(check);
    return false;
}

fn cgroup_verdict(
    check: *Check,
    uid: u32,
    offered: parse.ControllerSet,
    bus: *const BusFact,
) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    var missing: Detail = .{};
    for (required_controllers) |controller| {
        if (!offered.has(controller)) missing.print(" {s}", .{@tagName(controller)});
    }
    if (missing.len > 0) {
        check.problem("the cgroup delegated to uid {d} lacks controllers:{s}", .{
            uid, missing.slice(),
        });
        check.cause_symptom();
        check.cause("systemd delegates only some controllers to user services by default, and " ++
            "the cgroup.controllers of this user's manager does not list these:{s}", .{
            missing.slice(),
        });
        delegate_fixes(check);
        return;
    }
    if (!bus_usable(check, bus)) return;
    check.detail.print("cgroup v2, user@{d}.service delegated to uid {d}:", .{ uid, uid });
    append_controllers(&check.detail, offered);
    check.detail.print("; systemd {s} on the user bus", .{bus.version_text.slice()});
    check.status = .ok;
}

/// True if the user's bus answered. Otherwise this is the check's failure: zbx cannot make a
/// container's scope without it, whatever the cgroup offers.
fn bus_usable(check: *Check, bus: *const BusFact) bool {
    assert(check.status == .ok);
    assert(bus.attempted); // The manager's cgroup exists, or we would not be here.
    if (bus.ok) return true;
    check.problem("{s}: containers cannot get a cgroup scope", .{
        scope_text.problem_short(&bus.problem),
    });
    check.cause_symptom();
    scope_text.problem_causes(&check.diag, &bus.problem);
    switch (scope_text.problem_code(&bus.problem)) {
        .E0302 => {
            const inherited = "unset an address inherited from another user:";
            check.fix(inherited, "unset DBUS_SESSION_BUS_ADDRESS");
            check.fix("or log in again as this user, through a systemd (logind) session", "");
        },
        .E0301 => {
            check.fix("keep the user manager running:", "sudo loginctl enable-linger $(id -un)");
            check.fix("or log in through a systemd (logind) session, such as ssh or a console", "");
        },
        else => check.fix("look at the user manager:", "systemctl --user status"),
    }
    return false;
}

fn append_controllers(detail: *Detail, set: parse.ControllerSet) void {
    assert(detail.len > 0); // Called after the sentence it extends.
    if (set.is_empty()) detail.print(" none", .{});
    for (std.enums.values(parse.Controller)) |controller| {
        if (set.has(controller)) detail.print(" {s}", .{@tagName(controller)});
    }
    if (set.unknown > 0) detail.print(" +{d} other", .{set.unknown});
    if (detail.truncated) assert(detail.len == constants.detail_bytes_max);
}

// overlay

fn evaluate_overlay(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const probe = facts.probe_overlay;
    if (probe.is(.ok)) {
        check.pass("overlayfs mounts inside a user and mount namespace", .{});
        return;
    }
    if (probe.is(.denied)) {
        check.problem("an overlayfs mount inside a user namespace was refused", .{});
        check.cause_symptom();
        check.cause("the namespaces were created but mount(overlay) was refused: the overlay " ++
            "module may be missing or not loaded, or a security policy forbids the mount", .{});
        check.fix("load the overlay module:", "sudo modprobe overlay");
        check.fix("or use Linux 5.11 or newer built with CONFIG_OVERLAY_FS", "");
        return;
    }
    if (probe.is(.map_denied)) return map_denied(check);
    if (probe.is(.setup_denied)) {
        check.problem("could not enter the user and mount namespaces the probe needs", .{});
        check.cause_symptom();
        check.cause("the overlay probe needs a user namespace first and the kernel refused " ++
            "to create one, so overlayfs itself was never tried (see the userns check)", .{});
        check.fix("fix the userns check first (ZBX-E0101); overlay needs the same permission", "");
        check.fix("then check again:", "zbx doctor");
        return;
    }
    assert(!probe.is(.ok)); // Every success and named refusal returned above.
    if (probe.err == null) assert(probe.outcome != .denied);
    probe_problem(check, "overlay", probe);
}

// subid

const Program = enum(u1) { newuidmap, newgidmap };

const BinaryState = union(enum) {
    /// Privileged by setuid root (true) or by file capabilities (false).
    privileged: bool,
    /// Present but neither setuid root nor carrying the capability.
    unprivileged,
    missing,
    fault: Failure,
};

fn binary_state(facts: *const Facts, program: Program) BinaryState {
    const row = &facts.binaries[@backingInt(program)];
    // Faults first, over every candidate: a failed look at any of them is never ignored just
    // because another candidate turned out to be fine.
    for (row) |*binary| {
        if (binary.stat_err) |err| {
            if (err != error.NotFound) {
                return .{ .fault = .{ .err = err, .errno = binary.stat_errno } };
            }
        } else if (binary.capability_err) |err| {
            if (err != error.NoData) {
                return .{ .fault = .{ .err = err, .errno = binary.capability_errno } };
            }
        }
    }
    var found_unprivileged = false;
    for (row) |*binary| {
        if (binary.stat_err) |err| {
            assert(err == error.NotFound); // The fault scan above returned any other.
            continue;
        }
        if (binary.capability_err) |err| assert(err == error.NoData);
        const privilege = candidate_privilege(binary, program);
        if (privilege) |by_setuid| return .{ .privileged = by_setuid };
        found_unprivileged = true;
    }
    return if (found_unprivileged) .unprivileged else .missing;
}

/// null if the candidate is not privileged; otherwise whether it is by setuid root.
fn candidate_privilege(binary: *const Binary, program: Program) ?bool {
    assert(binary.stat_err == null); // Only called for candidates that exist.
    assert(binary.capability_len <= constants.capability_bytes_max);
    const regular = binary.stat.mode & std.posix.S.IFMT == std.posix.S.IFREG;
    if (!regular) return null;
    const setuid_bit = binary.stat.mode & 0o4000 != 0;
    if (setuid_bit) {
        if (binary.stat.uid == 0) return true;
    }
    if (binary.capability_err != null) return null;
    const bits = parse.decode_capability(binary.capability[0..binary.capability_len]) catch {
        return null;
    };
    if (bits.root_id != 0) return null; // Applies only inside a namespace, not on the host.
    const has = if (program == .newuidmap) bits.setuid else bits.setgid;
    return if (has) false else null;
}

fn evaluate_subid(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.subuid.attempted); // gather_subid ran.
    assert(facts.subgid.attempted);
    // Failed reads come first: a fault must never be answered from partial information.
    if (facts.passwd.err) |err| {
        const failure: Failure = .{ .err = err, .errno = facts.passwd.errno };
        if (err != error.NotFound) return read_failed(check, .read, "/etc/passwd", failure);
    }
    const files = [2]struct { path: []const u8, slot: *const Slot(constants.subid_bytes_max) }{
        .{ .path = "/etc/subuid", .slot = &facts.subuid },
        .{ .path = "/etc/subgid", .slot = &facts.subgid },
    };
    for (files) |file| {
        if (file.slot.err) |err| {
            const failure: Failure = .{ .err = err, .errno = file.slot.errno };
            if (err != error.NotFound) return read_failed(check, .read, file.path, failure);
        }
    }
    const user = lookup_user(facts);
    var ranges: [2]parse.SubidRanges = undefined;
    for (files, 0..) |file, index| {
        const content = if (file.slot.err == null) file.slot.text() else "";
        ranges[index] = parse.parse_subid(content, user.name, facts.uid);
    }
    subid_verdict(facts, check, user, ranges);
}

const UserLookup = struct {
    name: ?[]const u8,
    /// True if /etc/passwd was readable (so a missing name means "no entry").
    passwd_present: bool,
};

fn lookup_user(facts: *const Facts) UserLookup {
    assert(facts.passwd.attempted);
    if (facts.passwd.err != null) return .{ .name = null, .passwd_present = false };
    const found = parse.parse_passwd_name(facts.passwd.text(), facts.uid);
    if (found.name) |name| assert(name.len > 0);
    return .{ .name = found.name, .passwd_present = true };
}

fn user_label(user: UserLookup, uid: u32, buffer: *Detail) void {
    assert(buffer.len == 0);
    if (user.name) |name| {
        var storage: [constants.user_name_bytes_max]u8 = undefined;
        buffer.print("{s} (uid {d})", .{ text_util.sanitise(&storage, name), uid });
    } else {
        buffer.print("uid {d} (no passwd entry, matched by uid only)", .{uid});
    }
    assert(buffer.len > 0);
}

/// What is wrong with the subid setup, collected so that one run names every problem.
const SubidProblems = struct {
    ranges: bool = false,
    missing: bool = false,
    unprivileged: bool = false,

    fn any(problems: SubidProblems) bool {
        if (problems.ranges) return true;
        if (problems.missing) return true;
        return problems.unprivileged;
    }
};

fn subid_verdict(
    facts: *const Facts,
    check: *Check,
    user: UserLookup,
    ranges: [2]parse.SubidRanges,
) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    const programs = [2]Program{ .newuidmap, .newgidmap };
    var states: [2]BinaryState = undefined;
    for (programs, 0..) |program, index| {
        states[index] = binary_state(facts, program);
        if (states[index] == .fault) {
            return binary_fault(check, program_names[index], states[index].fault);
        }
    }
    var who: Detail = .{};
    user_label(user, facts.uid, &who);
    assert(who.len > 0);
    var problems: SubidProblems = .{};
    var found: Detail = .{};
    const kinds = [2][]const u8{ "subuid", "subgid" };
    for (ranges, kinds) |range, kind| {
        if (range.best_count >= constants.subid_range_min) continue;
        problems.ranges = true;
        found.print("; no {s} range of {d} ids (largest: {d})", .{
            kind, constants.subid_range_min, range.best_count,
        });
    }
    for (states, program_names) |state, name| {
        switch (state) {
            .missing => {
                problems.missing = true;
                found.print("; {s} not found", .{name});
            },
            .unprivileged => {
                problems.unprivileged = true;
                found.print(
                    "; {s} is neither setuid root nor has a usable file capability",
                    .{name},
                );
            },
            else => {},
        }
    }
    if (problems.any()) {
        check.problem("{s}{s}", .{ who.slice(), found.slice() });
        subid_causes(check, problems);
        subid_fixes(check, problems);
        return;
    }
    check.pass("{s}: subuid {d} ids, subgid {d} ids;", .{
        who.slice(), ranges[0].best_count, ranges[1].best_count,
    });
    for (states, program_names, 0..) |state, name, index| {
        const how = if (state.privileged) "setuid root" else "file capability";
        const lead = if (index == 0) " " else ", ";
        check.detail.print("{s}{s}: {s}", .{ lead, name, how });
    }
}

/// A look at newuidmap or newgidmap failed for a reason other than "not there".
fn binary_fault(check: *Check, name: []const u8, failure: Failure) void {
    assert(check.detail.len == 0);
    assert(name.len > 0);
    check.problem("cannot inspect {s}: {s}", .{ name, error_reason(failure.err) });
    var what: [64]u8 = undefined;
    // Cannot fail: the name is "newuidmap" or "newgidmap".
    const operation = std.fmt.bufPrint(&what, "inspecting {s}", .{name}) catch unreachable;
    check.cause_could_not_run(operation, failure);
    check.fix_with("retry; check the permissions of the file:", "ls -l /usr/bin/{s}", .{name});
}

/// One explanation per kind of problem, then the whole list last: default output shows only
/// the last cause, and with two problems it must name both.
fn subid_causes(check: *Check, problems: SubidProblems) void {
    assert(problems.any());
    assert(check.status == .fail);
    if (problems.ranges) {
        check.cause("a rootless container needs {d} subordinate ids for its users, and the " ++
            "user has no such range in /etc/subuid or /etc/subgid", .{constants.subid_range_min});
    }
    if (problems.missing) {
        check.cause("newuidmap and newgidmap are the setuid helpers that write a rootless " ++
            "container's id maps, and at least one is not installed", .{});
    }
    if (problems.unprivileged) {
        check.cause("a helper that is neither setuid root nor given the capability cannot " ++
            "write the id maps of a rootless container", .{});
    }
    check.cause("{s}", .{check.detail.slice()}); // The whole list, last: it is what default shows.
}

fn subid_fixes(check: *Check, problems: SubidProblems) void {
    assert(problems.any());
    assert(check.diag.fixes.count == 0);
    if (problems.ranges) {
        const usermod = "sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 " ++
            "$(id -un)";
        check.fix("give this user id ranges:", usermod);
    }
    if (problems.missing) {
        // No `os-release` is read: the two commands are the same package under its two names, and
        // a fix for each family is true wherever the check runs, with no new host fact to fake.
        check.fix("install on Debian, Ubuntu:", "sudo apt install uidmap");
        check.fix("install on Fedora:", "sudo dnf install shadow-utils");
    }
    if (problems.unprivileged) {
        const command = "$(command -v newuidmap newgidmap)";
        check.fix("make the helpers setuid root:", "sudo chown root: " ++ command ++
            " && sudo chmod u+s " ++ command);
    }
    assert(check.diag.fixes.count > 0);
}

// seccomp

const seccomp_build = "grep -E 'CONFIG_SECCOMP(_FILTER)?=' /boot/config-$(uname -r)";

fn evaluate_seccomp(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.status.attempted); // gather_seccomp ran.
    if (facts.seccomp_err == null) assert(facts.seccomp != null);
    if (facts.status.err) |err| {
        const failure: Failure = .{ .err = err, .errno = facts.status.errno };
        return read_failed(check, .read, "/proc/self/status", failure);
    }
    if (facts.seccomp_err) |err| {
        check.problem("prctl(PR_GET_SECCOMP) failed: {s}", .{error_reason(err)});
        const failure: Failure = .{ .err = err, .errno = facts.seccomp_errno };
        check.cause_could_not_run("prctl(PR_GET_SECCOMP)", failure);
        check.fix("see how this kernel was built:", seccomp_build);
        check.fix("use a kernel built with CONFIG_SECCOMP=y", "");
        return;
    }
    const from_status = parse.parse_seccomp_status(facts.status.text()) catch {
        check.problem("no usable Seccomp: line in /proc/self/status", .{});
        check.cause_symptom();
        check.cause("the kernel prints the Seccomp: line only when it is built with " ++
            "CONFIG_SECCOMP, so this kernel was built without it", .{});
        check.fix("see how this kernel was built:", seccomp_build);
        check.fix("use a kernel built with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y", "");
        return;
    };
    const from_prctl = facts.seccomp.?;
    if (from_status != from_prctl) {
        check.problem("/proc/self/status says seccomp mode {d} but prctl says {d}", .{
            from_status, from_prctl,
        });
        check.cause("the two ways of asking the kernel about this process's seccomp mode " ++
            "disagree, so neither answer can be trusted", .{});
        check.fix("run the check again:", "zbx doctor");
        return;
    }
    const mode = switch (from_status) {
        0 => "disabled for this process",
        1 => "strict",
        else => "filter",
    };
    check.pass("seccomp is supported (current mode: {s})", .{mode});
}

// net

const pasta_install = "apt install passt";

/// `--net none` and `--net host` need nothing from the host, so this check never fails: a pasta
/// that is missing, or does not run, is a warning that says how to get one.
fn evaluate_net(facts: *const Facts, check: *Check) void {
    assert(check.detail.len == 0);
    assert(check.status == .ok);
    assert(facts.pasta.attempted); // gather_net ran.
    const pasta = &facts.pasta;
    if (!pasta.found) {
        check.warning(
            "pasta not found: --net user and --publish need it ({s})",
            .{pasta_install},
        );
        return;
    }
    var ended_well = false;
    if (pasta.status) |status| {
        if (status == .exited) ended_well = status.exited == 0;
    }
    if (!pasta.ran or !ended_well) {
        check.warning("pasta at {s} did not report its version: reinstall it ({s})", .{
            pasta.path.slice(), pasta_install,
        });
        return;
    }
    if (pasta.version.len == 0) {
        check.pass("pasta at {s}", .{pasta.path.slice()});
        return;
    }
    check.pass("{s} at {s}", .{ pasta.version.slice(), pasta.path.slice() });
}

// ---- Render --------------------------------------------------------------------------------

const Style = struct {
    label: []const u8,
    color: []const u8,
};

fn style_of(status: Status) Style {
    const style: Style = switch (status) {
        .ok => .{ .label = "ok  ", .color = "\x1b[32m" },
        .fail => .{ .label = "FAIL", .color = "\x1b[31m" },
        .warn => .{ .label = "warn", .color = "\x1b[33m" },
    };
    assert(style.label.len == 4); // The columns after the label line up.
    return style;
}

/// Renders the report, one line per check. Colour only when asked (stdout is a terminal).
pub fn render(report: *const Report, color: bool, buffer: []u8) []const u8 {
    assert(buffer.len > 0);
    report.validate();
    var writer = std.Io.Writer.fixed(buffer);
    for (report.checks) |check| render_line(&writer, check, color);
    const output = writer.buffered();
    assert(output.len > 0);
    assert(output[output.len - 1] == '\n');
    return output;
}

fn render_line(writer: *std.Io.Writer, check: Check, color: bool) void {
    assert(check.detail.len > 0);
    if (check.status == .fail) assert(check.diag.code.? == code_of(check.id));
    const style = style_of(check.status);
    // Cannot fail: constants.zig asserts, at comptime, that six maximal lines fit the buffer.
    if (color) writer.writeAll(style.color) catch unreachable;
    writer.writeAll(style.label) catch unreachable; // Same.
    if (color) writer.writeAll("\x1b[0m") catch unreachable; // Same.
    const line = .{ @tagName(check.id), check.detail.slice() };
    writer.print(" {s}  {s}", line) catch unreachable; // Same.
    if (check.status == .fail) {
        // The code ties the line to its diagnostic block on stderr.
        const code = diag_codes.full_name(check.diag.code.?);
        writer.print("  [{s}]", .{code}) catch unreachable; // Same.
    }
    writer.writeAll("\n") catch unreachable; // Same.
}

// ---- Entry point ---------------------------------------------------------------------------

/// Runs the doctor against `host`, fills `report`, and prints the stdout report: one line per
/// check. A stdout that cannot be written is `ZBX-E0009` in `diag`. The diagnostic of each FAIL
/// stays in `report` for the caller (cli.zig) to render on stderr, and the exit code is
/// `report.exit_code()`.
pub fn run(host: Host, facts: *Facts, report: *Report, diag: *Diag) error{OutputFailed}!void {
    inspect(host, facts, report);

    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render(report, host.color_enabled(.stdout), &buffer);
    assert(output.len > 0);
    host.write_all(.stdout, output) catch |err| {
        diag_errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
    assert(output.len <= buffer.len);
}

/// The doctor's checks without any output: for a bundle, which keeps the report as JSON.
pub fn inspect(host: Host, facts: *Facts, report: *Report) void {
    facts.reset();
    gather(host, facts);
    evaluate(facts, report);
    assert(report.checks[0].id == .kernel);
}

/// For a container run that could not create its namespaces: runs the user-namespace check on
/// the same facts `zbx doctor` gathers and, if it FAILs, adds that check's real cause and its
/// first two fixes to `diag`. Adds nothing when the check passes: the host then has no setting
/// that explains the refusal, and the caller's own cause stands. The caller raised the code.
pub fn explain_userns(host: Host, facts: *Facts, diag: *Diag) void {
    assert(diag.code != null);
    facts.reset();
    gather_one(host, facts, .userns);
    var check: Check = undefined;
    check.start(.userns);
    evaluate_userns(facts, &check);
    if (check.status != .fail) return;
    // A check that could not look says nothing about the host that the caller does not know.
    if (check.could_not_run) return;
    if (check.diag.last_cause()) |cause| diag.cause("{s}", .{cause});
    const fixes = check.diag.fixes.slice();
    for (fixes[0..@min(fixes.len, 2)]) |fix| {
        diag.fix(.{ .sentence = fix.sentence.slice(), .command = fix.command.slice() });
    }
    assert(diag.causes.count > 0);
}

/// What the doctor's subid check says about mapping a full range of ids: whether it can, and if
/// so where the ranges start and which helpers to run. If it cannot, `diag` holds the check's
/// diagnostic (unclassified when it can).
pub const SubidAnswer = struct {
    usable: bool,
    uid_start: u32,
    gid_start: u32,
    newuidmap: []const u8,
    newgidmap: []const u8,
    diag: Diag,
};

const helper_paths = blk: {
    var paths: [2][constants.binary_candidates_count][]const u8 = undefined;
    for (program_names, 0..) |name, program| {
        for (binary_directories, 0..) |directory, candidate| {
            paths[program][candidate] = directory ++ name;
        }
    }
    break :blk paths;
};

/// The path of the first candidate of `program` that is privileged, as `binary_state` judges.
fn privileged_path(facts: *const Facts, program: Program) ?[]const u8 {
    const row = &facts.binaries[@backingInt(program)];
    for (row, 0..) |*binary, candidate| {
        if (binary.stat_err != null) continue;
        if (candidate_privilege(binary, program) != null) {
            return helper_paths[@backingInt(program)][candidate];
        }
    }
    return null;
}

/// Runs the subid check on the same facts `zbx doctor` gathers and answers for a container run.
pub fn subid_answer(host: Host, facts: *Facts, answer: *SubidAnswer) void {
    facts.reset();
    gather_one(host, facts, .subid);
    var check: Check = undefined;
    check.start(.subid);
    evaluate_subid(facts, &check);
    answer.diag.reset();
    answer.usable = false;
    if (check.status == .fail) {
        answer.diag = check.diag;
        assert(answer.diag.code != null);
        return;
    }
    // The check passed: both ranges are at least the minimum and both helpers are privileged.
    const user = lookup_user(facts);
    const uid_ranges = parse.parse_subid(facts.subuid.text(), user.name, facts.uid);
    const gid_ranges = parse.parse_subid(facts.subgid.text(), user.name, facts.uid);
    assert(uid_ranges.best_count >= constants.subid_range_min);
    assert(gid_ranges.best_count >= constants.subid_range_min);
    answer.newuidmap = privileged_path(facts, .newuidmap).?;
    answer.newgidmap = privileged_path(facts, .newgidmap).?;
    answer.uid_start = uid_ranges.best_start;
    answer.gid_start = gid_ranges.best_start;
    answer.usable = true;
}

// ---- Tests ---------------------------------------------------------------------------------

/// The tests run one at a time, so one set of facts serves them all.
var test_facts: Facts = undefined;

const testing = std.testing;
const cli = @import("cli.zig");
const HostSim = @import("host_sim.zig").HostSim;
const fixtures = @import("doctor_fixtures.zig");

/// Runs `zbx doctor` end to end (the CLI, so the stderr blocks too) against a fixture and
/// returns the exit code; the output stays in `target`.
fn run_fixture(target: *HostSim, fixture: *const fixtures.Fixture) u8 {
    target.init(7, fixture.files);
    fixture.apply(target);
    const code = run_exit_code(target);
    assert(target.open_count() == 0);
    return code;
}

/// What the process would exit with.
fn run_exit_code(target: *HostSim) u8 {
    const code = cli.run(target.interface(), &.{"doctor"});
    assert(code <= constants.exit_internal);
    return code;
}

/// Counts the lines of `text` that start with `prefix`.
fn count_lines(text: []const u8, prefix: []const u8) u32 {
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) count += 1;
    }
    return count;
}

test "snapshot: every fixture's report, its diagnostic blocks and its exit code" {
    // Goal: the user-visible output for each simulated host is exactly the checked-in text:
    // src/testdata/doctor/NAME.txt is stdout and NAME.stderr.txt is the stderr blocks (empty
    // when nothing failed). The exit code is 0 exactly when nothing is FAIL, and every FAIL
    // line has its block, in check order, with the same code.
    @setEvalBranchQuota(100_000);
    var target: HostSim = undefined;
    inline for (fixtures.all) |fixture| {
        const expected = @embedFile("testdata/doctor/" ++ fixture.name ++ ".txt");
        const expected_stderr = @embedFile("testdata/doctor/" ++ fixture.name ++ ".stderr.txt");
        const code = run_fixture(&target, &fixture);
        try testing.expectEqualStrings(expected, target.stdout());
        try testing.expectEqualStrings(expected_stderr, target.stderr());
        const fails = count_lines(expected, "FAIL ");
        try testing.expectEqual(fails, count_lines(expected_stderr, "error[ZBX-E01"));
        try testing.expectEqual(fails, std.mem.count(u8, expected, "  [ZBX-E01"));
        const expected_code = if (fails > 0) constants.exit_environment else constants.exit_ok;
        try testing.expectEqual(expected_code, code);
    }
}

test "the healthy fixtures pass and warn does not change the exit code" {
    // Goal: pin which fixtures exit 0, so a changed policy cannot flip one unnoticed.
    const passing = [_][]const u8{
        "ubuntu_2404",            "fedora_40",
        "pasta_missing",          "restricted_but_working",
        "subid_by_uid",           "no_passwd_entry",
        "kernel_exactly_minimum", "kernel_newer_major_lower_minor",
    };
    var target: HostSim = undefined;
    for (fixtures.all) |fixture| {
        const expect_pass = for (passing) |name| {
            if (std.mem.eql(u8, name, fixture.name)) break true;
        } else false;
        const code = run_fixture(&target, &fixture);
        try testing.expectEqual(expect_pass, code == constants.exit_ok);
        if (expect_pass) try testing.expectEqual(@as(usize, 0), target.stderr().len);
    }
}

test "uid 0 gets no free pass: root is judged like anyone else" {
    // Goal: a root user on a healthy host still fails subid (root has no subuid range), and
    // without a user manager it also fails cgroup. Method: gather and evaluate, then compare the
    // status of every check.
    const cases = [_]struct { name: []const u8, failing: []const CheckId }{
        .{ .name = "ubuntu_2404_as_root", .failing = &.{.subid} },
        .{ .name = "ubuntu_2404_as_root_no_manager", .failing = &.{ .cgroup, .subid } },
    };
    var target: HostSim = undefined;
    var facts: Facts = undefined;
    var report: Report = undefined;
    for (cases) |case| {
        for (fixtures.all) |fixture| {
            if (!std.mem.eql(u8, fixture.name, case.name)) continue;
            target.init(1, fixture.files);
            fixture.apply(&target);
            facts.reset();
            gather(target.interface(), &facts);
            evaluate(&facts, &report);
            for (report.checks) |check| {
                const listed = std.mem.indexOfScalar(CheckId, case.failing, check.id) != null;
                // The net check never fails: these hosts have no pasta, so it warns.
                const passing = if (check.id == .net) Status.warn else Status.ok;
                try testing.expectEqual(if (listed) Status.fail else passing, check.status);
            }
        }
    }
}

test "every check has its own code, and a FAIL's diagnostic is blamed on the environment" {
    // Goal: the mapping from check to code is total and distinct (one code per check, E0101 to
    // E0106), and a failing check carries a diagnostic with a cause, a fix and the exit code
    // of its blame. Method: the empty host fails every check.
    // The net check only warns, so it has no code.
    var seen: [constants.doctor_checks_count]diag_codes.Code = undefined;
    var index: usize = 0;
    for (std.enums.values(CheckId)) |id| {
        if (id == .net) continue;
        seen[index] = code_of(id);
        for (seen[0..index]) |earlier| try testing.expect(earlier != seen[index]);
        try testing.expect(std.mem.startsWith(u8, @tagName(seen[index]), "E01"));
        index += 1;
    }
    var target: HostSim = undefined;
    target.init(1, &.{});
    var facts: Facts = undefined;
    facts.reset();
    gather(target.interface(), &facts);
    var report: Report = undefined;
    evaluate(&facts, &report);
    var failures: u32 = 0;
    for (report.checks) |check| {
        // The simulator's defaults let the kernel and overlay checks pass; the rest read files.
        const expected = check.id != .kernel and check.id != .overlay and check.id != .net;
        try testing.expectEqual(expected, check.status == .fail);
        if (!expected) continue;
        failures += 1;
        try testing.expectEqual(code_of(check.id), check.diag.code.?);
        try testing.expect(check.diag.causes.count > 0);
        try testing.expect(check.diag.fixes.count > 0);
        try testing.expectEqual(@as(u8, constants.exit_environment), check.diag.exit_code());
    }
    try testing.expectEqual(@as(u32, 4), failures);
}

test "a check that could not run says so, names the real errno, and keeps its own code" {
    // Goal: the brief's rule for faults. An unreadable /etc/subuid is a FAIL of the subid check
    // (E0105, environment); the last cause (the one default output shows) says the check could
    // not run and names EACCES, the errno the simulator's model reports for it.
    var target: HostSim = undefined;
    for (fixtures.all) |fixture| {
        if (!std.mem.eql(u8, fixture.name, "subuid_unreadable")) continue;
        _ = run_fixture(&target, &fixture);
        var facts: Facts = undefined;
        facts.reset();
        target.init(1, fixture.files);
        fixture.apply(&target);
        gather(target.interface(), &facts);
        var report: Report = undefined;
        evaluate(&facts, &report);
        const check = report.checks[@backingInt(CheckId.subid)];
        try testing.expectEqual(diag_codes.Code.E0105, check.diag.code.?);
        const expected = "the subid check could not run: read(/etc/subuid) failed: " ++
            "permission denied (EACCES)";
        try testing.expectEqualStrings(expected, check.diag.last_cause().?);
    }
}

test "colour is applied only when asked and does not change the text" {
    // Goal: with colour the report is the plain report plus escape sequences; without it there
    // is no escape byte at all.
    var target: HostSim = undefined;
    const fixture = fixtures.all[1]; // ubuntu_2404_restricted: ok and FAIL lines.
    target.init(1, fixture.files);
    fixture.apply(&target);
    target.terminal = true;
    _ = run_exit_code(&target);
    const coloured = target.stdout();
    try testing.expect(std.mem.indexOf(u8, coloured, "\x1b[31mFAIL\x1b[0m") != null);
    try testing.expect(std.mem.indexOf(u8, coloured, "\x1b[32mok  \x1b[0m") != null);

    var plain_sim: HostSim = undefined;
    _ = run_fixture(&plain_sim, &fixture);
    try testing.expect(std.mem.indexOfScalar(u8, plain_sim.stdout(), 0x1b) == null);
    var stripped: [constants.output_bytes_max]u8 = undefined;
    const without = @import("diag/render.zig").strip_colour(&stripped, coloured);
    try testing.expectEqualStrings(plain_sim.stdout(), without);
}

test "a failed read at every step of the healthy host is a FAIL, never ok" {
    // Goal: crash at any step. Method: fail host call 0, 1, 2, ... of the healthy Ubuntu run
    // with each error kind; whatever the failing call was (a read, a stat, a probe, the final
    // write), the exit code is 2, the report is well formed, and no handle leaks.
    const kinds = [_]host_mod.Error{ error.IoFailed, error.AccessDenied, error.OutOfMemory };
    const fixture = fixtures.all[0];
    var target: HostSim = undefined;
    var calls_total: u32 = 0;
    // The calls of the six checks that can fail; the net check after them only ever warns, so
    // a fault in one of its calls leaves the exit code alone.
    var facts: Facts = undefined;
    target.init(3, fixture.files);
    fixture.apply(&target);
    facts.reset();
    for (std.enums.values(CheckId)) |id| {
        if (id != .net) gather_one(target.interface(), &facts, id);
    }
    const calls_before_net = target.call_count;
    for (kinds) |kind| {
        for (0..64) |index| {
            target.init(3, fixture.files);
            fixture.apply(&target);
            target.faults.fail_call_index = @intCast(index);
            target.faults.fail_call_error = kind;
            const code = run_exit_code(&target);
            try testing.expectEqual(@as(u32, 0), target.open_count());
            const injected = target.hard_errors_injected;
            if (injected == 0) {
                calls_total = @max(calls_total, @as(u32, @intCast(index)));
                try testing.expectEqual(constants.exit_ok, code);
            } else if (index < calls_before_net) {
                try testing.expectEqual(constants.exit_environment, code);
            } else {
                try testing.expect(code == constants.exit_ok or code == constants.exit_environment);
            }
        }
    }
    try testing.expect(calls_total >= 30); // The healthy run makes dozens of calls.
}

test "gather is exactly the per-check gather steps in order" {
    // Goal: the fuzzers drive gather_one per check; this pins that doing so equals gather().
    var target_a: HostSim = undefined;
    var target_b: HostSim = undefined;
    const fixture = fixtures.all[0];
    target_a.init(5, fixture.files);
    fixture.apply(&target_a);
    target_b.init(5, fixture.files);
    fixture.apply(&target_b);
    var facts_a: Facts = undefined;
    var facts_b: Facts = undefined;
    facts_a.reset();
    facts_b.reset();
    gather(target_a.interface(), &facts_a);
    for (std.enums.values(CheckId)) |id| gather_one(target_b.interface(), &facts_b, id);
    var report_a: Report = undefined;
    var report_b: Report = undefined;
    evaluate(&facts_a, &report_a);
    evaluate(&facts_b, &report_b);
    for (report_a.checks, report_b.checks) |a, b| {
        try testing.expectEqualStrings(a.detail.slice(), b.detail.slice());
    }
    try testing.expectEqual(target_a.call_count, target_b.call_count);
}

test "explain_userns adds the host's reason to a refused clone, or nothing" {
    // Goal: the E0203 cause comes from the same facts as the doctor's userns check. Method: the
    // AppArmor-restricted fixture gives the AppArmor cause and its two fixes; a healthy host gives
    // nothing; a host where the check itself could not run gives nothing either, because "the
    // check could not look" is no reason for the refusal.
    const Case = struct { name: []const u8, causes: u32, fixes: u32 };
    const cases = [_]Case{
        .{ .name = "ubuntu_2404_restricted", .causes = 2, .fixes = 2 },
        .{ .name = "userns_disabled", .causes = 2, .fixes = 1 },
        .{ .name = "ubuntu_2404", .causes = 1, .fixes = 0 },
        .{ .name = "probe_cannot_fork", .causes = 1, .fixes = 0 },
        .{ .name = "restricted_but_working", .causes = 1, .fixes = 0 },
    };
    for (cases) |case| {
        const fixture = fixtures.find(case.name).?;
        var target: HostSim = undefined;
        target.init(1, fixture.files);
        fixture.apply(&target);
        var diag: Diag = undefined;
        diag.reset();
        diag.raise(.E0203);
        diag.cause("clone3 failed", .{});
        explain_userns(target.interface(), &test_facts, &diag);
        try testing.expectEqual(case.causes, diag.causes.count);
        try testing.expectEqual(case.fixes, diag.fixes.count);
        try testing.expectEqual(@as(u32, 0), target.open_count());
    }
}
