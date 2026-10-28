//! The `-e` option of `zbx run` (M6): `-e NAME=VALUE` sets a variable in the container,
//! `-e NAME` copies it from zbx's own environment, and an error if it is unset there. Both
//! override the image's variable of the same name. The option is repeatable.
//!
//! A value is where passwords go (`-e POSTGRES_PASSWORD=demo`), so a value is used once, to build
//! the container's environment, and is never stored or printed: the run record, a bundle, `ps`
//! and every JSON document carry the names only, and no diagnostic here echoes a value. The
//! tests search the bytes of a record and a bundle for a marker value.
//!
//! Two stages, so that a usage error is found before anything starts:
//!   - `parse` reads one option's text when the command line is read (a bad name, a name
//!     given twice, too many options: ZBX-E0010).
//!   - `resolve` runs when the container is about to start: it reads the `-e NAME` variables from
//!     the host's environment (ZBX-E0011 if one is unset) and merges everything over the image's
//!     variables into the caller's fixed storage.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const spec = @import("runtime/spec.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;
const Label = spec.Label;

comptime {
    assert(constants.arg_bytes_max <= constants.env_value_bytes_max + 2);
}

/// One `-e` as typed: the name, and the value if the option had an `=`.
pub const Setting = struct {
    name: []const u8,
    /// Null for `-e NAME`: copied from zbx's environment when the run starts.
    value: ?[]const u8,
};

pub const Problem = enum {
    not_a_name,
    name_too_long,
    twice,
    too_many,

    pub fn sentence(problem: Problem) []const u8 {
        const result: []const u8 = switch (problem) {
            .not_a_name => "the name is not a letter or underscore followed by letters, " ++
                "digits and underscores",
            .name_too_long => "the name is longer than 64 characters",
            .twice => "that variable is already set by another -e",
            .too_many => "-e is given more than 16 times",
        };
        assert(result.len > 0);
        assert(result[result.len - 1] != '.');
        comptime assert(constants.env_name_bytes_max == 64);
        comptime assert(constants.run_env_count_max == 16);
        return result;
    }
};

pub const Parse = union(enum) {
    ok: Setting,
    /// The problem, and the name part of the text (never the value) for the message.
    problem: struct { kind: Problem, name: []const u8 },
};

/// Reads one `-e` text. `earlier` are the settings read before it: a name may be set once.
pub fn parse(text: []const u8, earlier: []const Setting) Parse {
    assert(text.len <= constants.arg_bytes_max);
    assert(earlier.len <= constants.run_env_count_max);
    const equals = std.mem.indexOfScalar(u8, text, '=');
    const name = if (equals) |at| text[0..at] else text;
    const value: ?[]const u8 = if (equals) |at| text[at + 1 ..] else null;
    if (earlier.len == constants.run_env_count_max) {
        return .{ .problem = .{ .kind = .too_many, .name = name } };
    }
    if (name.len > constants.env_name_bytes_max) {
        return .{ .problem = .{ .kind = .name_too_long, .name = name } };
    }
    if (!spec.env_name_valid(name)) return .{ .problem = .{ .kind = .not_a_name, .name = name } };
    // A value cannot be over its bound: it is part of one argument, and the bound of an argument
    // leaves it less than the bound of a value (`NAME=` takes two bytes at least).
    if (value) |given| assert(given.len <= constants.env_value_bytes_max);
    for (earlier) |setting| {
        if (std.mem.eql(u8, setting.name, name)) {
            return .{ .problem = .{ .kind = .twice, .name = name } };
        }
    }
    return .{ .ok = .{ .name = name, .value = value } };
}

/// Refuses an unset `-e NAME` (ZBX-E0011) before anything slow starts, such as a pull.
pub fn check_set(host: Host, settings: []const Setting, diag: *Diag) ResolveError!void {
    assert(settings.len <= constants.run_env_count_max);
    assert(diag.code == null);
    for (settings) |setting| {
        if (setting.value != null) continue;
        const limit = constants.env_value_bytes_max;
        if (host.environment(setting.name, limit) == null) return unset(diag, setting.name);
    }
}

/// What `resolve` leaves: the environment to start with, and the names that `-e` set.
pub const Resolved = struct {
    env: []const Label,
    names: []const []const u8,
};

/// The caller's room: the merged variables and the names. Fixed size, no allocation.
pub const Storage = struct {
    env: [constants.env_vars_count_max]Label,
    names: [constants.run_env_count_max][]const u8,
};

pub const ResolveError = error{Refused};

/// Merges `settings` over `image_env`: a setting replaces the image's variable of the same name
/// in place, and a new one goes last. `-e NAME` is read from the host's environment here. On
/// failure the diagnostic is in `diag` (ZBX-E0011 for an unset variable, ZBX-E0010 when the
/// merged list would not fit).
pub fn resolve(
    host: Host,
    settings: []const Setting,
    image_env: []const Label,
    storage: *Storage,
    diag: *Diag,
) ResolveError!Resolved {
    assert(settings.len <= constants.run_env_count_max);
    assert(image_env.len <= constants.env_vars_count_max);
    assert(diag.code == null);
    @memcpy(storage.env[0..image_env.len], image_env);
    var count: usize = image_env.len;
    for (settings, 0..) |setting, index| {
        // The limit is the one a value may have, so a longer host value counts as unset: say so.
        const value = setting.value orelse host.environment(
            setting.name,
            constants.env_value_bytes_max,
        ) orelse return unset(diag, setting.name);
        assert(value.len <= constants.env_value_bytes_max);
        storage.names[index] = setting.name;
        const at = position_of(storage.env[0..count], setting.name) orelse blk: {
            if (count == storage.env.len) return merged_too_many(diag, setting.name);
            count += 1;
            break :blk count - 1;
        };
        storage.env[at] = .{ .key = setting.name, .value = value };
    }
    assert(count <= constants.env_vars_count_max);
    assert(spec.env_names_problem(storage.names[0..settings.len]) == null);
    return .{ .env = storage.env[0..count], .names = storage.names[0..settings.len] };
}

fn position_of(env: []const Label, name: []const u8) ?usize {
    for (env, 0..) |variable, index| {
        if (std.mem.eql(u8, variable.key, name)) return index;
    }
    return null;
}

/// ZBX-E0010 for a text `parse` refused. Never quotes a value.
pub fn refuse_text(diag: *Diag, kind: Problem, name: []const u8) void {
    assert(diag.code == null);
    var shown: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&shown, name);
    diag.raise(.E0010);
    diag.while_("reading the command line", .{});
    diag.cause("-e '{s}': {s}", .{ echo, kind.sentence() });
    diag.context("name", "{s}", .{echo});
    diag_fix(diag);
}

fn diag_fix(diag: *Diag) void {
    diag.fix(.{
        .sentence = "give a name, and a value after =, or just the name to copy it:",
        .command = "zbx run -e POSTGRES_PASSWORD=demo postgres:16",
        .template = true,
    });
}

fn merged_too_many(diag: *Diag, name: []const u8) ResolveError {
    assert(diag.code == null);
    var shown: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&shown, name);
    diag.raise(.E0010);
    diag.while_("setting the container's environment", .{});
    diag.cause("the image's variables and -e together are more than {d}", .{
        constants.env_vars_count_max,
    });
    diag.context("name", "{s}", .{echo});
    diag.fix(.{ .sentence = "give fewer -e options, or use an image with fewer variables" });
    return error.Refused;
}

fn unset(diag: *Diag, name: []const u8) ResolveError {
    assert(diag.code == null);
    var shown: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&shown, name);
    diag.raise(.E0011);
    diag.while_("setting the container's environment", .{});
    diag.cause("-e {s} copies {s} from zbx's environment, and it is not set there (or is " ++
        "longer than {d} bytes)", .{ echo, echo, constants.env_value_bytes_max });
    diag.context("name", "{s}", .{echo});
    diag.fix(.{
        .sentence = "give it a value:",
        .command = "zbx run -e NAME=VALUE ...",
        .template = true,
    });
    diag.fix(.{
        .sentence = "or set it for this one command:",
        .command = "NAME=VALUE zbx run -e NAME ...",
        .template = true,
    });
    return error.Refused;
}

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, text: []const u8) []const u8 {
    const used = @min(text.len, storage.len);
    @memcpy(storage[0..used], text[0..used]);
    return storage[0..used];
}

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;

test "parse: NAME=VALUE and NAME, and the value may be empty or hold '='" {
    // Goal: the two forms and what each keeps. Method: right and odd inputs.
    const plain = parse("A=b", &.{}).ok;
    try testing.expectEqualStrings("A", plain.name);
    try testing.expectEqualStrings("b", plain.value.?);
    const bare = parse("A", &.{}).ok;
    try testing.expect(bare.value == null);
    const empty = parse("A=", &.{}).ok;
    try testing.expectEqualStrings("", empty.value.?);
    const equals = parse("A=b=c", &.{}).ok;
    try testing.expectEqualStrings("b=c", equals.value.?);
}

test "parse: every refusal, at the bound and one past it, and none names a value" {
    // Goal: the bounds of constants.zig are exact. Method: names and values of exactly the
    // bound and one more; the problem's name is the part before '='.
    const name_max = repeated('N', constants.env_name_bytes_max);
    try testing.expect(parse(name_max, &.{}) == .ok);
    const name_over = repeated('N', constants.env_name_bytes_max + 1);
    try testing.expectEqual(Problem.name_too_long, parse(name_over, &.{}).problem.kind);
    // The longest value an argument can hold: the whole argument less "A=".
    const value_max = "A=" ++ repeated('v', constants.arg_bytes_max - 2);
    try testing.expect(parse(value_max, &.{}) == .ok);
    for ([_][]const u8{ "", "=x", "1A=x", "a-b=x", "a b", "é=x" }) |text| {
        try testing.expectEqual(Problem.not_a_name, parse(text, &.{}).problem.kind);
    }
    const earlier = [_]Setting{.{ .name = "A", .value = "1" }};
    const twice = parse("A=secret-value", &earlier).problem;
    try testing.expectEqual(Problem.twice, twice.kind);
    try testing.expectEqualStrings("A", twice.name);
    const full: [constants.run_env_count_max]Setting = @splat(.{ .name = "B", .value = null });
    try testing.expectEqual(Problem.too_many, parse("C", &full).problem.kind);
    try testing.expect(parse("C", full[0 .. full.len - 1]) == .ok);
}

fn repeated(comptime byte: u8, comptime count: usize) *const [count]u8 {
    const array: [count]u8 = @splat(byte);
    return &array;
}

fn sim_with(sim: *HostSim, variables: []const @import("host_sim.zig").EnvironmentVariable) void {
    sim.init(1, &.{});
    sim.environment_variables = variables;
}

test "resolve: a setting replaces the image's variable in place, a new one goes last" {
    // Goal: -e overrides the image's env. Method: an image with two variables; -e replaces the
    // first, adds a third, and copies a fourth from the host's environment.
    var sim: HostSim = undefined;
    sim_with(&sim, &.{.{ .name = "FROM_HOST", .value = "host-value" }});
    var storage: Storage = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const image = [_]Label{ .{ .key = "A", .value = "image" }, .{ .key = "B", .value = "kept" } };
    const settings = [_]Setting{
        .{ .name = "A", .value = "new" },
        .{ .name = "C", .value = "" },
        .{ .name = "FROM_HOST", .value = null },
    };
    const got = try resolve(sim.interface(), &settings, &image, &storage, &diag);
    try testing.expectEqual(@as(usize, 4), got.env.len);
    try testing.expectEqualStrings("new", got.env[0].value);
    try testing.expectEqualStrings("kept", got.env[1].value);
    try testing.expectEqualStrings("C", got.env[2].key);
    try testing.expectEqualStrings("host-value", got.env[3].value);
    try testing.expectEqual(@as(usize, 3), got.names.len);
    try testing.expectEqualStrings("FROM_HOST", got.names[2]);
}

test "resolve: an unset -e NAME is E0011 and names the variable, not any value" {
    // Goal: the error for an unset variable. Method: a host without it, and another that has an
    // over-long one (counted as unset); the diagnostic mentions the name only.
    var sim: HostSim = undefined;
    sim_with(&sim, &.{.{ .name = "OTHER", .value = "marker-value-123" }});
    var storage: Storage = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const settings = [_]Setting{.{ .name = "MISSING", .value = null }};
    const host = sim.interface();
    try testing.expectError(error.Refused, resolve(host, &settings, &.{}, &storage, &diag));
    try testing.expectEqual(@import("diag/codes.zig").Code.E0011, diag.code.?);
    var carried: [constants.diag_carry_bytes_max]u8 = undefined;
    const text = diag.encode(&carried);
    try testing.expect(std.mem.indexOf(u8, text, "MISSING") != null);
    try testing.expect(std.mem.indexOf(u8, text, "marker-value-123") == null);
}

test "resolve: the image's variables and -e together are bounded" {
    // Goal: the merged list never overflows its storage. Method: an image that fills it, then
    // one more new name is refused (E0010) and a replacement is not.
    var sim: HostSim = undefined;
    sim_with(&sim, &.{});
    var storage: Storage = undefined;
    var diag: Diag = undefined;
    diag.reset();
    var image: [constants.env_vars_count_max]Label = undefined;
    var names: [constants.env_vars_count_max][8]u8 = undefined;
    for (&image, &names, 0..) |*variable, *name, index| {
        const text = std.fmt.bufPrint(name, "V{d}", .{index}) catch unreachable; // Short.
        variable.* = .{ .key = text, .value = "x" };
    }
    const replace = [_]Setting{.{ .name = "V0", .value = "y" }};
    const got = try resolve(sim.interface(), &replace, &image, &storage, &diag);
    try testing.expectEqual(@as(usize, constants.env_vars_count_max), got.env.len);
    const extra = [_]Setting{.{ .name = "EXTRA", .value = "y" }};
    const refused = resolve(sim.interface(), &extra, &image, &storage, &diag);
    try testing.expectError(error.Refused, refused);
    try testing.expectEqual(@import("diag/codes.zig").Code.E0010, diag.code.?);
}
