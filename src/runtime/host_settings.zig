//! The host settings `--require-host` checks before a run (docs/briefs/M2b-workload-knobs.md,
//! item 5): four values a container cannot set for itself, which some workloads need the host to
//! have. Pure: the types, the parser of a requirement's text, the parsers of the four files'
//! contents, and the comparison of a requirement with the host's value. Reading the files is
//! `host_settings_check.zig`'s, through the host; the codes are raised there.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// The settings a run may require of its host.
pub const HostSetting = enum(u8) {
    max_map_count,
    aio_max_nr,
    overcommit_memory,
    transparent_hugepage,

    /// The name the flag and the messages use: the sysctl's key, or THP's own name.
    pub fn key(setting: HostSetting) []const u8 {
        const result: []const u8 = switch (setting) {
            .max_map_count => "vm.max_map_count",
            .aio_max_nr => "fs.aio-max-nr",
            .overcommit_memory => "vm.overcommit_memory",
            .transparent_hugepage => "transparent_hugepage",
        };
        assert(result.len > 0);
        assert(result.len <= setting_key_bytes_max);
        return result;
    }

    /// The file the host's value is read from.
    pub fn path(setting: HostSetting) []const u8 {
        const result: []const u8 = switch (setting) {
            .max_map_count => "/proc/sys/vm/max_map_count",
            .aio_max_nr => "/proc/sys/fs/aio-max-nr",
            .overcommit_memory => "/proc/sys/vm/overcommit_memory",
            .transparent_hugepage => "/sys/kernel/mm/transparent_hugepage/enabled",
        };
        assert(result[0] == '/');
        assert(result.len < path_bytes_max);
        return result;
    }

    /// Whether the requirement is a minimum (`>=`), else a set of allowed values (`=`).
    pub fn is_minimum(setting: HostSetting) bool {
        return setting == .max_map_count or setting == .aio_max_nr;
    }

    /// The words a set setting's value may be, in value order (a value is its index).
    pub fn words(setting: HostSetting) []const []const u8 {
        assert(!setting.is_minimum());
        const result: []const []const u8 = switch (setting) {
            .overcommit_memory => &.{ "0", "1", "2" },
            .transparent_hugepage => &.{ "always", "madvise", "never" },
            .max_map_count, .aio_max_nr => unreachable, // Asserted above.
        };
        assert(result.len <= value_words_max);
        return result;
    }

    /// The operator a requirement on it is written with.
    pub fn operator(setting: HostSetting) []const u8 {
        return if (setting.is_minimum()) ">=" else "=";
    }
};

/// Longer than the longest file's path, THP's.
pub const path_bytes_max: u32 = 64;

pub const settings_count: u32 = std.enums.values(HostSetting).len;

/// The longest key: `vm.overcommit_memory` and `transparent_hugepage`.
pub const setting_key_bytes_max: u32 = 20;

/// The most words a set setting has (THP's three, overcommit's three).
pub const value_words_max: u32 = 3;

/// THP's modes, in the order `/sys/kernel/mm/transparent_hugepage/enabled` lists them.
pub const Thp = enum(u8) { always, madvise, never };

/// A set of allowed values of a set setting: bit `i` is the value with index `i`.
pub const HostValueSet = struct {
    bits: u8 = 0,

    pub fn with(set: HostValueSet, value: u64) HostValueSet {
        assert(value < value_words_max);
        const result: HostValueSet = .{ .bits = set.bits | bit(value) };
        assert(result.contains(value));
        return result;
    }

    pub fn contains(set: HostValueSet, value: u64) bool {
        if (value >= value_words_max) return false;
        return set.bits & bit(value) != 0;
    }

    pub fn empty(set: HostValueSet) bool {
        return set.bits == 0;
    }

    /// Whether every bit is a value the setting has.
    pub fn valid(set: HostValueSet) bool {
        const all: u8 = (1 << value_words_max) - 1;
        return set.bits & ~all == 0;
    }

    fn bit(value: u64) u8 {
        assert(value < value_words_max);
        return @as(u8, 1) << @intCast(value);
    }
};

/// What a run requires of one host setting. A minimum setting uses `minimum` and leaves
/// `allowed` empty; a set setting uses `allowed` and leaves `minimum` zero.
pub const HostRequirement = struct {
    setting: HostSetting,
    minimum: u64 = 0,
    allowed: HostValueSet = .{},

    /// Whether the fields fit the setting (a library caller's value may not).
    pub fn well_formed(requirement: HostRequirement) bool {
        if (requirement.setting.is_minimum()) return requirement.allowed.empty();
        if (requirement.minimum != 0) return false;
        if (requirement.allowed.empty()) return false;
        return requirement.allowed.valid();
    }

    /// Whether the host's value meets it.
    pub fn met(requirement: HostRequirement, value: u64) bool {
        assert(requirement.well_formed());
        if (requirement.setting.is_minimum()) return value >= requirement.minimum;
        return requirement.allowed.contains(value);
    }
};

/// The host's values. Null is a setting the host does not expose (no THP support, a kernel
/// without the file). Overcommit's value is 0, 1 or 2; THP's is a `Thp`.
pub const HostSettings = struct {
    max_map_count: ?u64 = null,
    aio_max_nr: ?u64 = null,
    overcommit_memory: ?u64 = null,
    transparent_hugepage: ?Thp = null,

    pub fn value(settings: *const HostSettings, setting: HostSetting) ?u64 {
        return switch (setting) {
            .max_map_count => settings.max_map_count,
            .aio_max_nr => settings.aio_max_nr,
            .overcommit_memory => settings.overcommit_memory,
            .transparent_hugepage => if (settings.transparent_hugepage) |thp|
                @backingInt(thp)
            else
                null,
        };
    }

    pub fn set(settings: *HostSettings, setting: HostSetting, new: ?u64) void {
        if (new) |known| {
            if (!setting.is_minimum()) assert(known < value_words_max);
        }
        switch (setting) {
            .max_map_count => settings.max_map_count = new,
            .aio_max_nr => settings.aio_max_nr = new,
            .overcommit_memory => settings.overcommit_memory = new,
            .transparent_hugepage => settings.transparent_hugepage = if (new) |known|
                @fromBackingInt(@intCast(known))
            else
                null,
        }
        assert(std.meta.eql(settings.value(setting), new));
    }
};

/// Why a requirement's text is refused (ZBX-E0320).
pub const RequirementProblem = enum(u8) {
    /// No `>=` or `=` in it.
    no_operator,
    /// The name before the operator is not one of the four.
    unknown_setting,
    /// `=` on a minimum setting, or `>=` on a set one.
    wrong_operator,
    value_empty,
    /// A minimum's value is not a decimal count that fits 64 bits.
    not_a_number,
    /// A word of a set's value is not one the setting has.
    unknown_value,
    /// The setting was required already: one requirement per setting. The flag's reader finds
    /// it across flags; `parse_requirement` never returns it.
    repeated,
};

pub const Parsed = union(enum) {
    ok: HostRequirement,
    problem: struct { kind: RequirementProblem, setting: ?HostSetting },
};

/// Parses `<setting><op><value>`: `vm.max_map_count>=262144`, `vm.overcommit_memory=1`,
/// `transparent_hugepage=never,madvise`.
pub fn parse_requirement(text: []const u8) Parsed {
    assert(text.len <= constants.arg_bytes_max);
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return problem(.no_operator, null);
    const minimum_form = equals > 0 and text[equals - 1] == '>';
    const name = text[0 .. equals - @intFromBool(minimum_form)];
    const value = text[equals + 1 ..];
    const setting = lookup(name) orelse return problem(.unknown_setting, null);
    if (minimum_form != setting.is_minimum()) return problem(.wrong_operator, setting);
    if (value.len == 0) return problem(.value_empty, setting);
    if (setting.is_minimum()) {
        const minimum = parse_count(value) orelse return problem(.not_a_number, setting);
        return .{ .ok = .{ .setting = setting, .minimum = minimum } };
    }
    var allowed: HostValueSet = .{};
    var items = std.mem.splitScalar(u8, value, ',');
    while (items.next()) |item| {
        const index = word_index(setting, item) orelse return problem(.unknown_value, setting);
        allowed = allowed.with(index);
    }
    const result: HostRequirement = .{ .setting = setting, .allowed = allowed };
    assert(result.well_formed());
    return .{ .ok = result };
}

fn problem(kind: RequirementProblem, setting: ?HostSetting) Parsed {
    return .{ .problem = .{ .kind = kind, .setting = setting } };
}

pub fn lookup(name: []const u8) ?HostSetting {
    for (std.enums.values(HostSetting)) |setting| {
        if (std.mem.eql(u8, setting.key(), name)) return setting;
    }
    return null;
}

fn word_index(setting: HostSetting, word: []const u8) ?u64 {
    assert(!setting.is_minimum());
    for (setting.words(), 0..) |known, index| {
        if (std.mem.eql(u8, known, word)) return index;
    }
    return null;
}

/// A decimal count of at most 20 digits that fits 64 bits; no sign, no spaces.
pub fn parse_count(text: []const u8) ?u64 {
    if (text.len == 0 or text.len > 20) return null;
    var result: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
        const times = @mulWithOverflow(result, 10);
        if (times[1] != 0) return null;
        const plus = @addWithOverflow(times[0], byte - '0');
        if (plus[1] != 0) return null;
        result = plus[0];
    }
    return result;
}

/// Why a list of requirements is refused (ZBX-E0320), and at which one.
pub const ListProblem = union(enum) {
    /// A library caller's requirement whose fields do not fit its setting.
    malformed: u32,
    /// The same setting twice: one requirement per setting.
    repeated: u32,
};

/// The first problem of a run's requirements, in the caller's order. More than one per setting
/// is refused, so the list is never longer than `settings_count` when it passes.
pub fn list_problem(list: []const HostRequirement) ?ListProblem {
    assert(list.len <= std.math.maxInt(u32));
    for (list, 0..) |requirement, position| {
        const index: u32 = @intCast(position);
        if (!requirement.well_formed()) return .{ .malformed = index };
        for (list[0..position]) |earlier| {
            if (earlier.setting == requirement.setting) return .{ .repeated = index };
        }
    }
    assert(list.len <= settings_count);
    return null;
}

/// Parses the contents of a setting's file. A sysctl file holds a count and a newline;
/// overcommit's count is 0, 1 or 2. THP's lists the modes with the current one in brackets:
/// `always [madvise] never`. Null is contents that are none of these.
pub fn parse_file(setting: HostSetting, contents: []const u8) ?u64 {
    const line = std.mem.trimEnd(u8, contents, "\n");
    if (setting == .transparent_hugepage) return parse_thp(line);
    const count = parse_count(line) orelse return null;
    if (setting == .overcommit_memory and count >= value_words_max) return null;
    if (!setting.is_minimum()) assert(count < value_words_max);
    return count;
}

/// The bracketed word of THP's line, which must be the only one bracketed and a known mode.
fn parse_thp(line: []const u8) ?u64 {
    var found: ?u64 = null;
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    while (words.next()) |word| {
        if (word.len < 2 or word[0] != '[') continue;
        if (word[word.len - 1] != ']') return null;
        if (found != null) return null;
        found = word_index(.transparent_hugepage, word[1 .. word.len - 1]) orelse return null;
    }
    if (found) |index| assert(index < value_words_max);
    return found;
}

/// The longest requirement or value as text: a key, `>=` and a 20-digit count.
pub const text_bytes_max: u32 = setting_key_bytes_max + 2 + 20;

/// `<op><value>`: `>=262144`, `=never,madvise` (in value order).
pub fn render_needed(requirement: HostRequirement, buffer: *[text_bytes_max]u8) []const u8 {
    assert(requirement.well_formed());
    var writer: std.Io.Writer = .fixed(buffer);
    writer.writeAll(requirement.setting.operator()) catch unreachable; // Fits: 2 bytes.
    if (requirement.setting.is_minimum()) {
        writer.print("{d}", .{requirement.minimum}) catch unreachable; // 20 digits at most.
    } else {
        var first = true;
        for (requirement.setting.words(), 0..) |word, index| {
            if (!requirement.allowed.contains(index)) continue;
            if (!first) writer.writeByte(',') catch unreachable; // Fits: 3 words, 2 commas.
            writer.writeAll(word) catch unreachable; // Same.
            first = false;
        }
    }
    assert(writer.end > 1);
    return writer.buffered();
}

/// The whole requirement as the flag takes it: `vm.max_map_count>=262144`.
pub fn render_requirement(requirement: HostRequirement, buffer: *[text_bytes_max]u8) []const u8 {
    assert(requirement.well_formed());
    var needed_buffer: [text_bytes_max]u8 = undefined;
    const needed = render_needed(requirement, &needed_buffer);
    const key = requirement.setting.key();
    const result = std.fmt.bufPrint(buffer, "{s}{s}", .{ key, needed }) catch
        unreachable; // A key and a minimum or the three words fit `text_bytes_max`.
    assert(result.len > key.len);
    return result;
}

/// A host value as text: a count, or a set setting's word.
pub fn render_value(setting: HostSetting, value: u64, buffer: *[20]u8) []const u8 {
    if (setting.is_minimum()) {
        return std.fmt.bufPrint(buffer, "{d}", .{value}) catch unreachable; // 20 digits.
    }
    assert(value < value_words_max);
    return setting.words()[@intCast(value)];
}

/// The first requirement the host's values do not meet, in the caller's order.
pub const Miss = struct {
    index: u32,
    /// The host's value, or null when the host does not expose the setting.
    value: ?u64,
};

pub fn first_miss(settings: *const HostSettings, list: []const HostRequirement) ?Miss {
    assert(list_problem(list) == null);
    for (list, 0..) |requirement, position| {
        const index: u32 = @intCast(position);
        const value = settings.value(requirement.setting) orelse
            return .{ .index = index, .value = null };
        if (!requirement.met(value)) return .{ .index = index, .value = value };
    }
    return null;
}

const testing = std.testing;

test "parse_requirement: the brief's three forms" {
    // Goal: each setting reads as the brief writes it, and renders back the same.
    const map = parse_requirement("vm.max_map_count>=262144").ok;
    try testing.expectEqual(HostSetting.max_map_count, map.setting);
    try testing.expectEqual(@as(u64, 262144), map.minimum);
    const overcommit = parse_requirement("vm.overcommit_memory=1").ok;
    try testing.expect(overcommit.allowed.contains(1));
    try testing.expect(!overcommit.allowed.contains(0));
    const thp = parse_requirement("transparent_hugepage=never,madvise").ok;
    try testing.expect(thp.allowed.contains(@backingInt(Thp.never)));
    try testing.expect(thp.allowed.contains(@backingInt(Thp.madvise)));
    try testing.expect(!thp.allowed.contains(@backingInt(Thp.always)));
    var buffer: [text_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("transparent_hugepage=madvise,never", render_requirement(
        thp,
        &buffer,
    ));
    const aio = parse_requirement("fs.aio-max-nr>=18446744073709551615").ok;
    try testing.expectEqual(std.math.maxInt(u64), aio.minimum);
    try testing.expectEqualStrings("fs.aio-max-nr>=18446744073709551615", render_requirement(
        aio,
        &buffer,
    ));
}

test "parse_requirement: every refusal" {
    // Goal: each problem is found, with the setting when the name was known.
    const P = RequirementProblem;
    const cases = .{
        .{ "vm.max_map_count", P.no_operator, null },
        .{ "", P.no_operator, null },
        .{ "=1", P.unknown_setting, null },
        .{ ">=1", P.unknown_setting, null },
        .{ "vm.swappiness=1", P.unknown_setting, null },
        .{ "vm.max_map_count=1", P.wrong_operator, .max_map_count },
        .{ "vm.overcommit_memory>=1", P.wrong_operator, .overcommit_memory },
        .{ "fs.aio-max-nr>=", P.value_empty, .aio_max_nr },
        .{ "fs.aio-max-nr>=1k", P.not_a_number, .aio_max_nr },
        .{ "fs.aio-max-nr>= 1", P.not_a_number, .aio_max_nr },
        .{ "fs.aio-max-nr>=18446744073709551616", P.not_a_number, .aio_max_nr },
        .{ "fs.aio-max-nr>=-1", P.not_a_number, .aio_max_nr },
        .{ "vm.overcommit_memory=3", P.unknown_value, .overcommit_memory },
        .{ "transparent_hugepage=never,", P.unknown_value, .transparent_hugepage },
        .{ "transparent_hugepage=Never", P.unknown_value, .transparent_hugepage },
    };
    inline for (cases) |case| {
        const found = parse_requirement(case[0]).problem;
        try testing.expectEqual(case[1], found.kind);
        try testing.expectEqual(@as(?HostSetting, case[2]), found.setting);
    }
}

test "parse_file: each file's contents, and what is not one" {
    // Goal: the four files as a kernel writes them read as values; anything else is null.
    try testing.expectEqual(@as(?u64, 65530), parse_file(.max_map_count, "65530\n"));
    try testing.expectEqual(@as(?u64, 0), parse_file(.aio_max_nr, "0"));
    try testing.expectEqual(@as(?u64, 2), parse_file(.overcommit_memory, "2\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(.overcommit_memory, "3\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(.max_map_count, ""));
    try testing.expectEqual(@as(?u64, null), parse_file(.max_map_count, "1 2\n"));
    const madvise: u64 = @backingInt(Thp.madvise);
    const thp = HostSetting.transparent_hugepage;
    try testing.expectEqual(@as(?u64, madvise), parse_file(thp, "always [madvise] never\n"));
    try testing.expectEqual(@as(?u64, 0), parse_file(thp, "[always] madvise never\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(thp, "always madvise never\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(thp, "[always] [never]\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(thp, "[sometimes] never\n"));
    try testing.expectEqual(@as(?u64, null), parse_file(thp, "[always never\n"));
}

test "list_problem and first_miss: one per setting, the first miss in order" {
    // Goal: a repeated setting is refused at its second place; the check names the first
    // requirement not met, and a setting the host lacks is a miss with no value.
    const map = parse_requirement("vm.max_map_count>=262144").ok;
    const thp = parse_requirement("transparent_hugepage=never").ok;
    try testing.expectEqual(ListProblem{ .repeated = 2 }, list_problem(&.{ map, thp, map }).?);
    const bad: HostRequirement = .{ .setting = .overcommit_memory };
    try testing.expectEqual(ListProblem{ .malformed = 1 }, list_problem(&.{ map, bad }).?);
    try testing.expectEqual(@as(?ListProblem, null), list_problem(&.{ map, thp }));

    var settings: HostSettings = .{ .max_map_count = 65530 };
    try testing.expectEqual(Miss{ .index = 0, .value = 65530 }, first_miss(&settings, &.{
        map,
        thp,
    }).?);
    settings.set(.max_map_count, 262144);
    try testing.expectEqual(Miss{ .index = 1, .value = null }, first_miss(&settings, &.{
        map,
        thp,
    }).?);
    settings.set(.transparent_hugepage, @backingInt(Thp.never));
    try testing.expectEqual(@as(?Miss, null), first_miss(&settings, &.{ map, thp }));
}
