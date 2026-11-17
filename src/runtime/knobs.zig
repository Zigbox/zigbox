//! The workload knobs of M2b (docs/briefs/M2b-workload-knobs.md): resource limits (`--ulimit`),
//! the size of `/dev/shm` (`--shm-size`) and the container's own sysctls (`--sysctl`). Pure: the
//! types, the parsers of the flags' text, and the sysctl allowlist from `policy/sysctls.zon`.
//! What the host allows (the user's hard limits, `MemTotal`) is checked by `run.zig` against
//! what it reads through the host; a problem found here is the user's.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const policy_file = @import("policy/sysctls.zon");

/// A limit with no bound, as the kernel writes it (`RLIM_INFINITY`).
pub const unlimited: u64 = std.math.maxInt(u64);

/// The resources `--ulimit` sets. The others (`core`, `rtprio`, ...) are not asked for.
pub const Resource = enum(u8) {
    nofile,
    nproc,
    memlock,
    stack,

    /// Whether the value is a size in bytes (else a count).
    pub fn is_size(resource: Resource) bool {
        return resource == .memlock or resource == .stack;
    }

    /// The property that sets it on the user's systemd manager (`user@<uid>.service`).
    pub fn systemd_property(resource: Resource) []const u8 {
        const result: []const u8 = switch (resource) {
            .nofile => "LimitNOFILE",
            .nproc => "LimitNPROC",
            .memlock => "LimitMEMLOCK",
            .stack => "LimitSTACK",
        };
        assert(std.mem.startsWith(u8, result, "Limit"));
        return result;
    }
};

pub const resources_count: u32 = std.enums.values(Resource).len;
comptime {
    assert(resources_count == constants.ulimit_resources_count);
}

/// A soft and a hard limit; `unlimited` is no bound. The soft one is never above the hard one.
pub const Rlimit = struct {
    soft: u64,
    hard: u64,
};

/// The limits a run sets. A null one is inherited from the caller, as without `--ulimit`.
pub const Rlimits = struct {
    nofile: ?Rlimit = null,
    nproc: ?Rlimit = null,
    memlock: ?Rlimit = null,
    stack: ?Rlimit = null,

    pub fn get(rlimits: *const Rlimits, resource: Resource) ?Rlimit {
        return switch (resource) {
            .nofile => rlimits.nofile,
            .nproc => rlimits.nproc,
            .memlock => rlimits.memlock,
            .stack => rlimits.stack,
        };
    }

    pub fn set(rlimits: *Rlimits, resource: Resource, value: Rlimit) void {
        assert(value.soft <= value.hard);
        switch (resource) {
            .nofile => rlimits.nofile = value,
            .nproc => rlimits.nproc = value,
            .memlock => rlimits.memlock = value,
            .stack => rlimits.stack = value,
        }
        assert(rlimits.get(resource) != null);
    }

    pub fn count(rlimits: *const Rlimits) u32 {
        var result: u32 = 0;
        for (std.enums.values(Resource)) |resource| {
            result += @intFromBool(rlimits.get(resource) != null);
        }
        assert(result <= resources_count);
        return result;
    }

    /// The first resource whose soft limit is above its hard one, for library callers.
    pub fn problem(rlimits: *const Rlimits) ?Resource {
        for (std.enums.values(Resource)) |resource| {
            const value = rlimits.get(resource) orelse continue;
            if (value.soft > value.hard) return resource;
        }
        return null;
    }
};

/// Why a `--ulimit` value is refused (ZBX-E0310).
pub const UlimitProblem = enum {
    /// No `=`: `nofile` alone.
    no_value,
    unknown_name,
    /// Not digits, not a size, not `unlimited`, or an empty soft or hard part.
    not_a_number,
    /// A number past what the kernel can hold.
    too_large,
    soft_above_hard,
    /// `nofile=unlimited`: the kernel caps `RLIMIT_NOFILE` at `fs.nr_open`, so it refuses
    /// `RLIM_INFINITY` for it, even for root.
    nofile_unlimited,
    /// The same name twice.
    repeated,
};

pub const Ulimit = struct { resource: Resource, limit: Rlimit };

pub const UlimitParse = union(enum) {
    ok: Ulimit,
    problem: UlimitProblem,
};

/// `<name>=<soft>[:<hard>]`. One value sets both, as Docker does.
pub fn parse_ulimit(text: []const u8) UlimitParse {
    assert(text.len <= constants.arg_bytes_max);
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return .{ .problem = .no_value };
    const resource = std.meta.stringToEnum(Resource, text[0..equals]) orelse
        return .{ .problem = .unknown_name };
    const values = text[equals + 1 ..];
    const colon = std.mem.indexOfScalar(u8, values, ':');
    const soft_text = if (colon) |at| values[0..at] else values;
    const hard_text = if (colon) |at| values[at + 1 ..] else values;
    const soft = parse_value(resource, soft_text) catch |err| {
        return .{ .problem = problem_of(err) };
    };
    const hard = parse_value(resource, hard_text) catch |err| {
        return .{ .problem = problem_of(err) };
    };
    if (resource == .nofile) {
        if (hard == unlimited) return .{ .problem = .nofile_unlimited };
    }
    if (soft > hard) return .{ .problem = .soft_above_hard };
    if (resource == .nofile) assert(hard < unlimited);
    return .{ .ok = .{ .resource = resource, .limit = .{ .soft = soft, .hard = hard } } };
}

const ValueError = error{ NotANumber, TooLarge };

fn problem_of(err: ValueError) UlimitProblem {
    return switch (err) {
        error.NotANumber => .not_a_number,
        error.TooLarge => .too_large,
    };
}

/// A count, a size with a binary unit (`memlock` and `stack`), or `unlimited`. Zero is a value:
/// the kernel takes it, and the user asked for it.
fn parse_value(resource: Resource, text: []const u8) ValueError!u64 {
    assert(text.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, text, "unlimited")) return unlimited;
    var digits = text;
    var multiplier: u64 = 1;
    if (resource.is_size() and text.len > 0) {
        switch (std.ascii.toLower(text[text.len - 1])) {
            'k' => multiplier = 1 << 10,
            'm' => multiplier = 1 << 20,
            'g' => multiplier = 1 << 30,
            else => {},
        }
        if (multiplier != 1) digits = text[0 .. text.len - 1];
    }
    if (digits.len == 0) return error.NotANumber;
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return error.NotANumber;
    }
    if (digits.len > 18) return error.TooLarge; // Nothing below overflows.
    const count = std.fmt.parseUnsigned(u64, digits, 10) catch unreachable; // Digits, 18 or fewer.
    const value = std.math.mul(u64, count, multiplier) catch return error.TooLarge;
    assert(value < unlimited); // A number is never the kernel's "no bound".
    return value;
}

// ---- /dev/shm -------------------------------------------------------------------------------

/// A `--shm-size`: digits with an optional binary unit (`k`, `m`, `g`), as `--memory` takes it.
/// Null if it is not one; the bounds are `shm_problem`'s and the run's.
pub fn parse_size(text: []const u8) ?u64 {
    assert(text.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, text, "unlimited")) return null;
    const value = parse_value(.stack, text) catch return null;
    assert(value < unlimited);
    return value;
}

/// Why a `--shm-size` is refused, after it parsed.
pub const ShmProblem = enum {
    /// Larger than `--memory` (ZBX-E0314): its pages are charged to the container's memory.
    above_memory,
    /// Larger than the host's memory, with no `--memory` (ZBX-E0313).
    above_host,
};

/// What refuses a `/dev/shm` of `shm_bytes`, given `--memory` and the host's `MemTotal`.
pub fn shm_problem(shm_bytes: u64, memory_bytes: ?u64, host_bytes: u64) ?ShmProblem {
    assert(shm_bytes >= constants.shm_bytes_min);
    assert(host_bytes > 0);
    if (memory_bytes) |memory| {
        if (shm_bytes > memory) return .above_memory;
        return null; // Equal is allowed.
    }
    if (shm_bytes > host_bytes) return .above_host;
    return null;
}

// ---- Sysctls --------------------------------------------------------------------------------

/// One `--sysctl key=value`: the key in dot form.
pub const Sysctl = struct {
    key: []const u8,
    value: []const u8,
};

/// The namespace a key belongs to: the container has its own ipc namespace on every run, and its
/// own network namespace on every run but `--net host`.
pub const Namespace = enum { ipc, net };

pub const Entry = struct {
    key: []const u8,
    namespace: Namespace,
    why: []const u8,
};

/// The keys a container may set, in the order of the file.
pub const allowlist: [policy_file.keys.len]Entry = list: {
    @setEvalBranchQuota(100_000);
    var result: [policy_file.keys.len]Entry = undefined;
    for (policy_file.keys, 0..) |item, index| {
        const namespace = std.meta.stringToEnum(Namespace, item.namespace) orelse
            @compileError("sysctls.zon: unknown namespace " ++ item.namespace);
        if (key_problem(item.key)) @compileError("sysctls.zon: malformed key " ++ item.key);
        const net = std.mem.startsWith(u8, item.key, "net.");
        if (net != (namespace == .net)) @compileError("sysctls.zon: namespace of " ++ item.key);
        if (item.why.len == 0) @compileError("sysctls.zon: no why for " ++ item.key);
        for (result[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.key, item.key)) {
                @compileError("sysctls.zon: twice " ++ item.key);
            }
        }
        result[index] = .{ .key = item.key, .namespace = namespace, .why = item.why };
    }
    break :list result;
};

/// The longest key on the list, and so the longest path a write opens.
pub const key_bytes_max: u32 = longest: {
    var result: u32 = 0;
    for (allowlist) |entry| result = @max(result, entry.key.len);
    break :longest result;
};
pub const proc_path_prefix = "/proc/sys/";
pub const proc_path_bytes_max: u32 = proc_path_prefix.len + key_bytes_max;
comptime {
    // `constants.zig` sizes the plan's text for a sysctl path, with its NUL.
    assert(proc_path_bytes_max < constants.sysctl_proc_path_bytes_max);
    assert(key_bytes_max > 0);
}

/// The host settings `--require-host` checks (slice 2): a key among them is pointed there when
/// `--sysctl` refuses it.
pub const host_setting_keys = [_][]const u8{
    "vm.max_map_count",
    "fs.aio-max-nr",
    "vm.overcommit_memory",
};

comptime {
    @setEvalBranchQuota(100_000);
    assert(allowlist.len == 28); // Every key the brief named passed the VM check.
    assert(key_bytes_max < constants.arg_bytes_max);
    for (host_setting_keys) |key| {
        assert(!key_problem(key));
        assert(lookup(key) == null); // A host setting is never on the list.
    }
}

pub fn lookup(key: []const u8) ?*const Entry {
    assert(key.len <= constants.arg_bytes_max);
    for (&allowlist) |*entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry;
    }
    return null;
}

pub fn is_host_setting(key: []const u8) bool {
    for (host_setting_keys) |known| {
        if (std.mem.eql(u8, known, key)) return true;
    }
    return false;
}

/// Whether a key is not in dot form: empty, a character other than letters, digits, `_` and
/// `-`, or an empty part (a leading, trailing or doubled dot). A slash is never part of one.
pub fn key_problem(key: []const u8) bool {
    if (key.len == 0 or key.len > constants.arg_bytes_max) return true;
    var parts = std.mem.splitScalar(u8, key, '.');
    while (parts.next()) |part| {
        if (part.len == 0) return true;
        for (part) |byte| {
            const plain = std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-';
            if (!plain) return true;
        }
    }
    return false;
}

/// Why a `--sysctl` is malformed (ZBX-E0315).
pub const SysctlProblem = enum {
    no_value,
    key_malformed,
    value_empty,
    value_too_long,
    /// A byte outside printable ASCII: a newline would end the write early.
    value_not_printable,
};

pub const SysctlParse = union(enum) {
    ok: Sysctl,
    problem: SysctlProblem,
};

/// `key=value`; the value may itself hold `=`.
pub fn parse_sysctl(text: []const u8) SysctlParse {
    assert(text.len <= constants.arg_bytes_max);
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return .{ .problem = .no_value };
    const sysctl: Sysctl = .{ .key = text[0..equals], .value = text[equals + 1 ..] };
    if (form_problem(sysctl)) |found| return .{ .problem = found };
    return .{ .ok = sysctl };
}

pub fn form_problem(sysctl: Sysctl) ?SysctlProblem {
    if (key_problem(sysctl.key)) return .key_malformed;
    if (sysctl.value.len == 0) return .value_empty;
    if (sysctl.value.len > constants.sysctl_value_bytes_max) return .value_too_long;
    for (sysctl.value) |byte| {
        if (byte < 0x20 or byte > 0x7e) return .value_not_printable;
    }
    return null;
}

/// Why a list of sysctls is refused, and at which one.
pub const ListProblem = union(enum) {
    /// More than `sysctls_max` (ZBX-E0315).
    too_many,
    malformed: struct { index: u32, problem: SysctlProblem },
    /// The same key twice (ZBX-E0315).
    repeated: u32,
    /// Not on the allowlist: a host setting (ZBX-E0316).
    host_setting: u32,
    /// A `net.*` key on a run that shares the host's network namespace (ZBX-E0317).
    shared_network: u32,
};

/// The first problem of a run's sysctls. `isolated` is whether the run has a network namespace
/// of its own. The order is the user's: the earliest entry with a problem is named.
pub fn list_problem(list: []const Sysctl, isolated: bool) ?ListProblem {
    if (list.len > constants.sysctls_max) return .too_many;
    for (list, 0..) |sysctl, position| {
        const index: u32 = @intCast(position);
        if (form_problem(sysctl)) |found| {
            return .{ .malformed = .{ .index = index, .problem = found } };
        }
        for (list[0..position]) |earlier| {
            if (std.mem.eql(u8, earlier.key, sysctl.key)) return .{ .repeated = index };
        }
        const entry = lookup(sysctl.key) orelse return .{ .host_setting = index };
        if (entry.namespace == .net and !isolated) return .{ .shared_network = index };
    }
    return null;
}

/// `/proc/sys/<key with dots as slashes>`, for a key on the list.
pub fn proc_path(key: []const u8, buffer: *[proc_path_bytes_max]u8) []const u8 {
    assert(lookup(key) != null);
    assert(key.len <= key_bytes_max);
    @memcpy(buffer[0..proc_path_prefix.len], proc_path_prefix);
    const rest = buffer[proc_path_prefix.len..][0..key.len];
    for (key, rest) |byte, *out| out.* = if (byte == '.') '/' else byte;
    return buffer[0 .. proc_path_prefix.len + key.len];
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "parse_ulimit: one value sets both, two set soft and hard, sizes take units" {
    // Goal: each accepted form reads as the kernel's numbers, as Docker reads it.
    const one = parse_ulimit("nofile=65536").ok;
    try testing.expectEqual(Resource.nofile, one.resource);
    try testing.expectEqual(Rlimit{ .soft = 65536, .hard = 65536 }, one.limit);
    const two = parse_ulimit("nofile=4096:8192").ok;
    try testing.expectEqual(Rlimit{ .soft = 4096, .hard = 8192 }, two.limit);
    const memlock = parse_ulimit("memlock=64m:unlimited").ok;
    try testing.expectEqual(Rlimit{ .soft = 64 << 20, .hard = unlimited }, memlock.limit);
    try testing.expectEqual(@as(u64, 8 << 10), parse_ulimit("stack=8K").ok.limit.soft);
    try testing.expectEqual(@as(u64, 0), parse_ulimit("nproc=0").ok.limit.hard);
    const both = parse_ulimit("stack=unlimited").ok.limit;
    try testing.expectEqual(Rlimit{ .soft = unlimited, .hard = unlimited }, both);
    const nproc = parse_ulimit("nproc=unlimited").ok.limit; // Only nofile refuses it.
    try testing.expectEqual(Rlimit{ .soft = unlimited, .hard = unlimited }, nproc);
}

test "parse_ulimit: every refusal, at the edges" {
    // Goal: each problem is found, and the largest number accepted is one below overflow.
    const cases = .{
        .{ "nofile", UlimitProblem.no_value },
        .{ "core=0", UlimitProblem.unknown_name },
        .{ "NOFILE=1", UlimitProblem.unknown_name },
        .{ "nofile=", UlimitProblem.not_a_number },
        .{ "nofile=1:", UlimitProblem.not_a_number },
        .{ "nofile=:1", UlimitProblem.not_a_number },
        .{ "nofile=1k", UlimitProblem.not_a_number }, // A count takes no unit.
        .{ "nofile=-1", UlimitProblem.not_a_number },
        .{ "stack=m", UlimitProblem.not_a_number },
        .{ "nofile=1:2:3", UlimitProblem.not_a_number },
        .{ "nofile=1234567890123456789", UlimitProblem.too_large },
        .{ "memlock=999999999999999999g", UlimitProblem.too_large },
        .{ "nofile=8192:4096", UlimitProblem.soft_above_hard },
        .{ "nofile=unlimited:1", UlimitProblem.soft_above_hard },
        // The kernel caps nofile at fs.nr_open, so it never takes unlimited (review of #178).
        .{ "nofile=unlimited", UlimitProblem.nofile_unlimited },
        .{ "nofile=1024:unlimited", UlimitProblem.nofile_unlimited },
    };
    inline for (cases) |case| {
        try testing.expectEqual(case[1], parse_ulimit(case[0]).problem);
    }
    const largest = parse_ulimit("nproc=999999999999999999").ok.limit;
    try testing.expectEqual(@as(u64, 999_999_999_999_999_999), largest.soft);
    const huge = parse_ulimit("stack=17179869183g").ok.limit.soft;
    try testing.expectEqual(@as(u64, 17179869183 << 30), huge);
    try testing.expectEqual(UlimitProblem.too_large, parse_ulimit("stack=17179869184g").problem);
}

test "parse_size: units in any case, bare bytes, and every other form refused" {
    try testing.expectEqual(@as(?u64, 256 << 20), parse_size("256m"));
    try testing.expectEqual(@as(?u64, 1 << 30), parse_size("1G"));
    try testing.expectEqual(@as(?u64, 4096), parse_size("4096"));
    try testing.expectEqual(@as(?u64, 4 << 10), parse_size("4k"));
    try testing.expectEqual(@as(?u64, null), parse_size(""));
    try testing.expectEqual(@as(?u64, null), parse_size("unlimited"));
    try testing.expectEqual(@as(?u64, null), parse_size("1t"));
    try testing.expectEqual(@as(?u64, null), parse_size("-1m"));
    try testing.expectEqual(@as(?u64, null), parse_size("999999999999999999g"));
}

test "Rlimits: set, get, count and the soft-above-hard check" {
    var rlimits: Rlimits = .{};
    try testing.expectEqual(@as(u32, 0), rlimits.count());
    try testing.expect(rlimits.problem() == null);
    rlimits.set(.stack, .{ .soft = 1, .hard = 2 });
    try testing.expectEqual(@as(u32, 1), rlimits.count());
    try testing.expectEqual(@as(u64, 2), rlimits.get(.stack).?.hard);
    rlimits.nproc = .{ .soft = 3, .hard = 2 }; // A library caller's value, not through `set`.
    try testing.expectEqual(Resource.nproc, rlimits.problem().?);
}

test "shm_problem: equal to --memory passes, one byte over does not; MemTotal without it" {
    const page = constants.shm_bytes_min;
    try testing.expect(shm_problem(64 << 20, 64 << 20, 1 << 30) == null);
    const over = shm_problem((64 << 20) + 1, 64 << 20, 1 << 40).?;
    try testing.expectEqual(ShmProblem.above_memory, over);
    try testing.expect(shm_problem(1 << 30, null, 1 << 30) == null);
    try testing.expectEqual(ShmProblem.above_host, shm_problem((1 << 30) + 1, null, 1 << 30).?);
    try testing.expect(shm_problem(page, null, page) == null);
}

test "the allowlist: 28 keys, ipc and net, each with a path under /proc/sys" {
    // Goal: the file loads as the decision recorded it, and every key maps to its path.
    var ipc: u32 = 0;
    var buffer: [proc_path_bytes_max]u8 = undefined;
    for (allowlist) |entry| {
        ipc += @intFromBool(entry.namespace == .ipc);
        const path = proc_path(entry.key, &buffer);
        try testing.expect(std.mem.startsWith(u8, path, "/proc/sys/"));
        try testing.expect(std.mem.indexOfScalar(u8, path, '.') == null);
    }
    try testing.expectEqual(@as(u32, 13), ipc);
    const path = proc_path("net.ipv6.conf.all.disable_ipv6", &buffer);
    try testing.expectEqualStrings("/proc/sys/net/ipv6/conf/all/disable_ipv6", path);
    try testing.expect(lookup("vm.max_map_count") == null);
    try testing.expect(lookup("kernel.shmmax_next_id") == null);
    try testing.expect(is_host_setting("vm.max_map_count"));
    try testing.expect(!is_host_setting("net.core.somaxconn"));
}

test "parse_sysctl: forms, and the value's bound at 256 and 257 bytes" {
    const ok = parse_sysctl("kernel.sem=250 32000 32 128").ok;
    try testing.expectEqualStrings("kernel.sem", ok.key);
    try testing.expectEqualStrings("250 32000 32 128", ok.value);
    try testing.expectEqualStrings("a=b", parse_sysctl("x.y=a=b").ok.value);
    const at_bound = "net.core.somaxconn=" ++ repeat('1', constants.sysctl_value_bytes_max);
    try testing.expect(parse_sysctl(at_bound) == .ok);
    const past = "net.core.somaxconn=" ++ repeat('1', constants.sysctl_value_bytes_max + 1);
    try testing.expectEqual(SysctlProblem.value_too_long, parse_sysctl(past).problem);
    const cases = .{
        .{ "net.core.somaxconn", SysctlProblem.no_value },
        .{ "=1", SysctlProblem.key_malformed },
        .{ ".net.core=1", SysctlProblem.key_malformed },
        .{ "net..core=1", SysctlProblem.key_malformed },
        .{ "net/core/somaxconn=1", SysctlProblem.key_malformed },
        .{ "net.core.somaxconn=", SysctlProblem.value_empty },
        .{ "net.core.somaxconn=1\n", SysctlProblem.value_not_printable },
        .{ "net.core.somaxconn=\x7f", SysctlProblem.value_not_printable },
    };
    inline for (cases) |case| {
        try testing.expectEqual(case[1], parse_sysctl(case[0]).problem);
    }
}

test "list_problem: count bound, repeats, host settings, and net keys under --net host" {
    const somaxconn: Sysctl = .{ .key = "net.core.somaxconn", .value = "8192" };
    const shmmax: Sysctl = .{ .key = "kernel.shmmax", .value = "1" };
    try testing.expect(list_problem(&.{ somaxconn, shmmax }, true) == null);
    try testing.expect(list_problem(&.{shmmax}, false) == null); // ipc is always the container's.
    const shared = list_problem(&.{ shmmax, somaxconn }, false).?.shared_network;
    try testing.expectEqual(@as(u32, 1), shared);
    try testing.expectEqual(@as(u32, 1), list_problem(&.{ shmmax, shmmax }, true).?.repeated);
    const host: Sysctl = .{ .key = "vm.max_map_count", .value = "262144" };
    try testing.expectEqual(@as(u32, 0), list_problem(&.{host}, true).?.host_setting);
    const bad: Sysctl = .{ .key = "kernel.shmmax", .value = "" };
    const malformed = list_problem(&.{bad}, true).?.malformed;
    try testing.expectEqual(SysctlProblem.value_empty, malformed.problem);
    var full: [constants.sysctls_max + 1]Sysctl = undefined;
    for (&full, 0..) |*item, index| item.* = .{ .key = allowlist[index].key, .value = "1" };
    try testing.expect(list_problem(full[0..constants.sysctls_max], true) == null);
    try testing.expectEqual(ListProblem.too_many, list_problem(&full, true).?);
}
