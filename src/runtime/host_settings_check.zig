//! `--require-host` against the host (docs/briefs/M2b-workload-knobs.md, item 5): reading the
//! four settings through the host, checking a run's requirements against them, and the codes
//! (ZBX-E0319 to ZBX-E0321). The run's parent calls `preflight` before the scope, the namespaces
//! or any process; the doctor reads every setting with `read_one`. zbx only reads the settings,
//! never writes one.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const errors = @import("../diag/errors.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const host_settings = @import("host_settings.zig");

const Host = host_mod.Host;
const HostSetting = host_settings.HostSetting;
const HostSettings = host_settings.HostSettings;
const HostRequirement = host_settings.HostRequirement;

pub const Error = error{StartFailed};

/// One setting as read from its file.
pub const Read = union(enum) {
    value: u64,
    /// The file is not there: the host does not expose the setting.
    absent,
    unreadable: struct { err: host_mod.Error, errno: u16 },
    /// The file holds something that is not the setting's value.
    malformed,
};

/// The files are a count and a newline, or THP's three words, one bracketed.
const file_bytes_max: u32 = 64;

pub fn read_one(host: Host, setting: HostSetting) Read {
    var buffer: [file_bytes_max]u8 = undefined;
    const contents = host.read_file(setting.path(), &buffer) catch |err| {
        if (err == error.NotFound) return .absent;
        return .{ .unreadable = .{ .err = err, .errno = host.last_errno() } };
    };
    assert(contents.len <= buffer.len);
    const value = host_settings.parse_file(setting, contents) orelse return .malformed;
    return .{ .value = value };
}

/// Reads the settings `wanted` names into `out`; the others are left as they are. A setting the
/// host does not expose is null; one that is there but can't be read, or reads as nonsense, is
/// ZBX-E0321 (whether it meets a requirement can't be known).
pub fn read(host: Host, out: *HostSettings, wanted: []const HostSetting, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(wanted.len <= host_settings.settings_count);
    for (wanted) |setting| {
        switch (read_one(host, setting)) {
            .value => |value| out.set(setting, value),
            .absent => out.set(setting, null),
            .unreadable => |failure| {
                unreadable(diag, setting, failure.err, failure.errno);
                return error.StartFailed;
            },
            .malformed => {
                malformed(diag, setting);
                return error.StartFailed;
            },
        }
    }
    assert(diag.code == null);
}

/// `zigbox.host_settings_read`: every setting, for a caller that reports them (a node's facts).
pub fn host_settings_read(host: Host, out: *HostSettings, diag: *Diag) Error!void {
    assert(diag.code == null);
    out.* = .{};
    try read(host, out, std.enums.values(HostSetting), diag);
    assert(diag.code == null);
}

/// `zigbox.host_requirements_check`: pure. A list that is not one well-formed requirement per
/// setting is ZBX-E0320; a setting the host does not expose is ZBX-E0321; the first requirement
/// not met is ZBX-E0319.
pub fn host_requirements_check(
    settings: *const HostSettings,
    requirements: []const HostRequirement,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    if (host_settings.list_problem(requirements)) |problem| {
        list_invalid(diag, requirements, problem);
        return error.StartFailed;
    }
    const miss = host_settings.first_miss(settings, requirements) orelse return;
    const requirement = requirements[miss.index];
    if (miss.value) |value| {
        not_met(diag, requirement, value);
    } else {
        absent(diag, requirement.setting);
    }
    assert(diag.code != null);
    return error.StartFailed;
}

/// One read per setting, indexed by `HostSetting`.
pub const Reads = [host_settings.settings_count]Read;

/// The run's check: only the settings the requirements name are read (one the run does not ask
/// about can't refuse it), then `check_reads`.
pub fn preflight(host: Host, requirements: []const HostRequirement, diag: *Diag) Error!void {
    assert(diag.code == null);
    if (requirements.len == 0) return;
    var reads: Reads = @splat(.absent);
    for (requirements) |requirement| {
        reads[@backingInt(requirement.setting)] = read_one(host, requirement.setting);
    }
    try check_reads(&reads, requirements, diag);
    assert(diag.code == null);
}

/// The requirements against settings already read (the run's preflight, and the doctor's
/// host-settings line): the list's own problems first (ZBX-E0320), then a required setting
/// that could not be read (ZBX-E0321), then the comparison. Reads of settings no requirement
/// names are not looked at.
pub fn check_reads(
    reads: *const Reads,
    requirements: []const HostRequirement,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(reads.len == host_settings.settings_count);
    if (host_settings.list_problem(requirements)) |problem| {
        list_invalid(diag, requirements, problem);
        return error.StartFailed;
    }
    var settings: HostSettings = .{};
    for (requirements) |requirement| {
        const setting = requirement.setting;
        switch (reads[@backingInt(setting)]) {
            .value => |value| settings.set(setting, value),
            .absent => settings.set(setting, null),
            .unreadable => |failure| {
                unreadable(diag, setting, failure.err, failure.errno);
                return error.StartFailed;
            },
            .malformed => {
                malformed(diag, setting);
                return error.StartFailed;
            },
        }
    }
    try host_requirements_check(&settings, requirements, diag);
    assert(diag.code == null);
}

/// ZBX-E0320: a `--require-host` whose text does not parse.
pub fn requirement_invalid(
    diag: *Diag,
    text: []const u8,
    kind: host_settings.RequirementProblem,
    setting: ?HostSetting,
) void {
    assert(diag.code == null);
    assert(text.len <= constants.arg_bytes_max);
    diag.raise(.E0320);
    diag.while_("reading --require-host", .{});
    diag.context("arg", "{s}", .{text});
    switch (kind) {
        .no_operator => diag.cause("'{s}' has no >= or =: write <setting><op><value>", .{text}),
        .unknown_setting => diag.cause("zbx checks only vm.max_map_count, fs.aio-max-nr, " ++
            "vm.overcommit_memory and transparent_hugepage", .{}),
        .wrong_operator => wrong_operator(diag, setting.?),
        .value_empty => diag.cause("the requirement has no value", .{}),
        .not_a_number => diag.cause("{s} takes a count: digits only", .{setting.?.key()}),
        .unknown_value => unknown_value(diag, setting.?),
        .repeated => diag.cause("{s} is required twice: give one requirement per setting", .{
            setting.?.key(),
        }),
    }
    example_fix(diag);
    assert(diag.code.? == .E0320);
}

fn wrong_operator(diag: *Diag, setting: HostSetting) void {
    assert(diag.code.? == .E0320);
    if (setting.is_minimum()) {
        diag.cause("{s} takes a minimum, written >=", .{setting.key()});
    } else {
        diag.cause("{s} takes the values it may be, written =", .{setting.key()});
    }
}

fn unknown_value(diag: *Diag, setting: HostSetting) void {
    assert(diag.code.? == .E0320);
    assert(!setting.is_minimum());
    const words = setting.words();
    assert(words.len == 3);
    diag.cause("{s} is one of {s}, {s} or {s}, or a comma list of them", .{
        setting.key(),
        words[0],
        words[1],
        words[2],
    });
}

fn example_fix(diag: *Diag) void {
    assert(diag.code.? == .E0320);
    diag.fix(.{
        .sentence = "a valid requirement looks like this (quote it, or the shell reads > " ++
            "as a redirection):",
        .command = "zbx run --rootfs ./alpine --require-host 'vm.max_map_count>=262144' " ++
            "-- /bin/sh",
        .template = true,
    });
    assert(diag.fixes.count == 1);
}

/// ZBX-E0320 for a library caller's list: a setting twice, or fields that do not fit it.
fn list_invalid(
    diag: *Diag,
    requirements: []const HostRequirement,
    problem: host_settings.ListProblem,
) void {
    assert(diag.code == null);
    diag.raise(.E0320);
    diag.while_("checking the run's host requirements", .{});
    switch (problem) {
        .repeated => |index| {
            const key = requirements[index].setting.key();
            diag.context("key", "{s}", .{key});
            diag.cause("{s} is required twice: give one requirement per setting", .{key});
        },
        .malformed => |index| {
            const setting = requirements[index].setting;
            diag.context("key", "{s}", .{setting.key()});
            if (setting.is_minimum()) {
                diag.cause("a minimum setting takes no allowed values", .{});
            } else {
                diag.cause("a value setting needs allowed values, among its own, and no " ++
                    "minimum", .{});
            }
        },
    }
    example_fix(diag);
    assert(diag.code.? == .E0320);
}

/// ZBX-E0319: the host's value does not meet the requirement. The one line names the setting,
/// the host's value and what is needed; the fix sets it on the host, which zbx never does.
fn not_met(diag: *Diag, requirement: HostRequirement, value: u64) void {
    assert(diag.code == null);
    assert(!requirement.met(value));
    const setting = requirement.setting;
    var value_buffer: [20]u8 = undefined;
    const host_value = host_settings.render_value(setting, value, &value_buffer);
    var needed_buffer: [host_settings.text_bytes_max]u8 = undefined;
    const needed = host_settings.render_needed(requirement, &needed_buffer);
    diag.raise(.E0319);
    diag.set_headline("{s} is {s}, needs {s}", .{ setting.key(), host_value, needed });
    diag.context("key", "{s}", .{setting.key()});
    diag.context("host", "{s}", .{host_value});
    diag.context("needed", "{s}", .{needed});
    diag.cause("--require-host asks for {s}{s}, and this host's is {s}", .{
        setting.key(),
        needed,
        host_value,
    });
    set_fix(diag, requirement);
    diag.fix(.{ .sentence = "check every setting:", .command = "zbx doctor" });
    assert(diag.code.? == .E0319);
}

/// The command that sets the least value the requirement accepts: its minimum, or the first of
/// its allowed values.
fn set_fix(diag: *Diag, requirement: HostRequirement) void {
    assert(diag.code.? == .E0319);
    const setting = requirement.setting;
    if (setting.is_minimum()) {
        diag.fix_with(sysctl_sentence, "sudo sysctl -w {s}={d}", .{
            setting.key(),
            requirement.minimum,
        });
        return;
    }
    const word = first_allowed(requirement);
    if (setting == .transparent_hugepage) {
        diag.fix_with(
            "set it on the host (until the next boot; transparent_hugepage= on the kernel " ++
                "command line keeps it):",
            "echo {s} | sudo tee {s}",
            .{ word, setting.path() },
        );
    } else {
        diag.fix_with(sysctl_sentence, "sudo sysctl -w {s}={s}", .{ setting.key(), word });
    }
}

const sysctl_sentence = "set it on the host (a file in /etc/sysctl.d/ keeps it across boots):";

fn first_allowed(requirement: HostRequirement) []const u8 {
    assert(!requirement.setting.is_minimum());
    for (requirement.setting.words(), 0..) |word, index| {
        if (requirement.allowed.contains(index)) return word;
    }
    unreachable; // A well-formed set requirement allows at least one value.
}

/// ZBX-E0321: the host does not expose the setting.
fn absent(diag: *Diag, setting: HostSetting) void {
    assert(diag.code == null);
    raise_unreadable(diag, setting);
    if (setting == .transparent_hugepage) {
        diag.cause("{s} is not there: this kernel has no transparent hugepages", .{
            setting.path(),
        });
    } else {
        diag.cause("{s} is not there: this kernel does not expose {s}", .{
            setting.path(),
            setting.key(),
        });
    }
    doctor_fix(diag);
}

fn unreadable(diag: *Diag, setting: HostSetting, err: host_mod.Error, errno: u16) void {
    assert(diag.code == null);
    raise_unreadable(diag, setting);
    var operation_buffer: [host_settings.path_bytes_max + 16]u8 = undefined;
    const operation = std.fmt.bufPrint(&operation_buffer, "reading {s}", .{setting.path()}) catch
        unreachable; // Every path is shorter than `path_bytes_max`.
    errors.cause_host_error(diag, operation, err, errno);
    doctor_fix(diag);
}

fn malformed(diag: *Diag, setting: HostSetting) void {
    assert(diag.code == null);
    raise_unreadable(diag, setting);
    diag.cause("{s} holds something that is not a value of {s}", .{
        setting.path(),
        setting.key(),
    });
    doctor_fix(diag);
}

fn raise_unreadable(diag: *Diag, setting: HostSetting) void {
    assert(diag.code == null);
    diag.raise(.E0321);
    diag.while_("reading the host's {s} for --require-host", .{setting.key()});
    diag.context("key", "{s}", .{setting.key()});
    assert(diag.code.? == .E0321);
}

fn doctor_fix(diag: *Diag) void {
    assert(diag.code.? == .E0321);
    diag.fix(.{ .sentence = "see what this host has:", .command = "zbx doctor" });
    assert(diag.fixes.count > 0);
}

const testing = std.testing;

test "host_requirements_check: met, not met, absent, and a list refused" {
    // Goal: each outcome raises its code, and the miss's one line names the setting, the host's
    // value and the needed value.
    var diag: Diag = undefined;
    diag.reset();
    const map = host_settings.parse_requirement("vm.max_map_count>=262144").ok;
    const thp = host_settings.parse_requirement("transparent_hugepage=never,madvise").ok;
    var settings: HostSettings = .{ .max_map_count = 262144, .transparent_hugepage = .never };
    try host_requirements_check(&settings, &.{ map, thp }, &diag);
    try testing.expect(diag.code == null);

    settings.max_map_count = 65530;
    try testing.expectError(error.StartFailed, host_requirements_check(&settings, &.{map}, &diag));
    try testing.expectEqual(.E0319, diag.code.?);
    try testing.expectEqualStrings(
        "vm.max_map_count is 65530, needs >=262144",
        diag.headline.slice(),
    );
    const fix = diag.fixes.slice()[0];
    try testing.expectEqualStrings("sudo sysctl -w vm.max_map_count=262144", fix.command.slice());

    diag.reset();
    settings.transparent_hugepage = null;
    try testing.expectError(error.StartFailed, host_requirements_check(&settings, &.{thp}, &diag));
    try testing.expectEqual(.E0321, diag.code.?);

    diag.reset();
    try testing.expectError(error.StartFailed, host_requirements_check(
        &settings,
        &.{ thp, thp },
        &diag,
    ));
    try testing.expectEqual(.E0320, diag.code.?);
}

test "the THP fix writes the first allowed word" {
    // Goal: THP is not a sysctl, so its fix writes the file, with the least word allowed.
    var diag: Diag = undefined;
    diag.reset();
    const thp = host_settings.parse_requirement("transparent_hugepage=never,madvise").ok;
    const settings: HostSettings = .{ .transparent_hugepage = .always };
    try testing.expectError(error.StartFailed, host_requirements_check(&settings, &.{thp}, &diag));
    try testing.expectEqualStrings(
        "echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
        diag.fixes.slice()[0].command.slice(),
    );
    try testing.expectEqualStrings(
        "transparent_hugepage is always, needs =madvise,never",
        diag.headline.slice(),
    );
}
