//! What a run is asked to do, and the checks that decide whether it can be planned. Pure: no
//! kernel, no allocation. A problem found here is the user's (a bad name, a missing rootfs, a
//! command that does not fit); `run.zig` turns each into its diagnostic.
//!
//! The root file system is either a directory (`rootfs`, read and written in place) or a tree
//! from the store (`image`, a digest or a unique prefix of at least 12 hex digits), which runs
//! on an overlay: the tree is the read-only lower layer and the container's writes go to its
//! own upper layer. The `Runtime` contract of Zigcube holds an image digest: it is `image`.

const std = @import("std");
const assert = std.debug.assert;
const volume = @import("../state/volume.zig");
const constants = @import("../constants.zig");

/// A key and a value kept in the run record, for whoever started the container to find it by.
pub const Label = struct {
    key: []const u8,
    value: []const u8,
};

/// What a container may use. A null limit is none. The values are checked against the bounds in
/// `constants.zig` by `limits_problem`; `parse_memory`, `parse_pids` and `parse_cpus` read the
/// text of the flags.
pub const Limits = struct {
    memory_bytes: ?u64 = null,
    pids: ?u32 = null,
    /// Thousandths of a CPU: 500 is half of one.
    cpu_millis: ?u32 = null,

    pub fn any(limits: Limits) bool {
        const result = limits.memory_bytes != null or limits.pids != null or
            limits.cpu_millis != null;
        if (!result) assert(limits.memory_bytes == null);
        return result;
    }
};

/// How a container reaches the network (docs/briefs/M5-network.md, "The network modes"). `none`
/// is the default: the container has a network namespace of its own with only `lo`. `host`
/// shares the host's namespace. `user` is a namespace of its own that `pasta` connects to the
/// host's network as the user, with no privilege and no change to the host's firewall.
pub const Network = enum {
    none,
    host,
    user,

    pub fn word(network: Network) []const u8 {
        const result: []const u8 = switch (network) {
            .none => "none",
            .host => "host",
            .user => "user",
        };
        assert(result.len > 0);
        assert(std.mem.eql(u8, result, @tagName(network)));
        return result;
    }

    /// Whether the container has a network namespace of its own (every mode but `host`).
    pub fn isolated(network: Network) bool {
        const result = network != .host;
        if (network == .none) assert(result);
        return result;
    }
};

/// One `--publish HOST:CONTAINER`: a TCP port of the host forwarded to one of the container's.
pub const Publish = struct {
    host: u16,
    container: u16,

    /// "HOST:CONTAINER", the way it was typed and the way `pasta -t` takes it.
    pub fn text(publish: Publish, buffer: *[publish_text_bytes_max]u8) []const u8 {
        assert(publish.host > 0);
        assert(publish.container > 0);
        // Cannot fail: two numbers of at most five digits and a colon fit eleven bytes.
        const ports = .{ publish.host, publish.container };
        const result = std.fmt.bufPrint(buffer, "{d}:{d}", ports) catch unreachable; // Above.
        assert(result.len >= 3);
        return result;
    }
};

/// The longest text of a `Publish`: "65535:65535".
pub const publish_text_bytes_max: u32 = 11;

/// Why a `--publish` value does not parse (ZBX-E0600).
pub const PublishProblem = enum {
    /// No colon, or more than one.
    not_host_colon_container,
    /// A side that is empty, or holds anything but digits.
    not_a_number,
    /// A port of 0, or above 65535.
    out_of_range,

    pub fn sentence(problem: PublishProblem) []const u8 {
        const result: []const u8 = switch (problem) {
            .not_host_colon_container => "it is not HOST:CONTAINER, two ports and a colon",
            .not_a_number => "a port is not a number",
            .out_of_range => "a port is outside 1 to 65535",
        };
        assert(result.len > 0);
        assert(result[result.len - 1] != '.');
        return result;
    }
};

pub const PublishParse = union(enum) {
    ok: Publish,
    problem: PublishProblem,
};

/// Reads "HOST:CONTAINER". Only what `Publish.text` writes parses: decimal digits, no sign, no
/// space, no protocol suffix (every forward is TCP), each port 1 to 65535. Leading zeros are
/// refused too, since the text they would render back is a different one.
pub fn parse_publish(value: []const u8) PublishParse {
    assert(value.len <= constants.arg_bytes_max);
    if (std.mem.count(u8, value, ":") != 1) return .{ .problem = .not_host_colon_container };
    const colon = std.mem.indexOfScalar(u8, value, ':').?;
    const host_port = switch (parse_port(value[0..colon])) {
        .port => |port| port,
        .problem => |problem| return .{ .problem = problem },
    };
    const container_port = switch (parse_port(value[colon + 1 ..])) {
        .port => |port| port,
        .problem => |problem| return .{ .problem = problem },
    };
    const result: Publish = .{ .host = host_port, .container = container_port };
    assert(result.host > 0);
    assert(result.container > 0);
    return .{ .ok = result };
}

fn parse_port(text: []const u8) union(enum) { port: u16, problem: PublishProblem } {
    if (text.len == 0) return .{ .problem = .not_a_number };
    for (text) |byte| {
        if (byte < '0' or byte > '9') return .{ .problem = .not_a_number };
    }
    if (text.len > 5) return .{ .problem = .out_of_range };
    if (text[0] == '0') {
        return .{ .problem = if (text.len == 1) .out_of_range else .not_a_number };
    }
    // Cannot fail: one to five decimal digits fit a u32.
    const number = std.fmt.parseInt(u32, text, 10) catch unreachable;
    if (number > std.math.maxInt(u16)) return .{ .problem = .out_of_range };
    assert(number > 0);
    return .{ .port = @intCast(number) };
}

/// What is wrong with a list of forwards as a whole: too many, or one host port twice (pasta
/// could bind it only once).
pub const PublishListProblem = union(enum) {
    too_many,
    host_port_twice: u16,
};

pub fn publish_problem(network: Network, list: []const Publish) ?PublishListProblem {
    if (list.len > 0) assert(network == .user); // `--publish` implies `--net user`.
    if (list.len > constants.publish_count_max) return .too_many;
    for (list, 0..) |publish, index| {
        assert(publish.host > 0);
        for (list[0..index]) |earlier| {
            if (earlier.host == publish.host) return .{ .host_port_twice = publish.host };
        }
    }
    return null;
}

/// A user and group id inside the container.
pub const User = struct {
    uid: u32,
    gid: u32,
};

pub const Spec = struct {
    /// The directory to use as the container's root, read and written in place. Empty when
    /// `image` is set; exactly one of the two is.
    rootfs: []const u8 = "",
    /// A tree of the store to run on an overlay (M3): its digest, or a unique prefix of at least
    /// 12 hex digits, with or without "b3:".
    image: ?[]const u8 = null,
    /// The container's name, also its hostname. Null: a generated `zbx-xxxxxx`.
    name: ?[]const u8,
    /// The program and its arguments. Never empty; the first word is the program.
    command: []const []const u8,
    /// Kept in the run record. At most `labels_count_max`, with bounded keys and values.
    labels: []const Label = &.{},
    /// Resource limits, applied through the container's cgroup scope.
    limits: Limits = .{},
    /// The rootfs is remounted read-only, with a tmpfs at /tmp and /run.
    read_only: bool = false,
    /// Variables added to the container's environment (PATH, HOME, HOSTNAME and TERM are always
    /// there; one of these with the same name replaces it). Not kept in the run record: a value
    /// may be a secret.
    env: []const Label = &.{},
    /// The names of the variables the caller set with `-e` (a subset of `env`'s keys): the run
    /// record keeps these names and never a value. At most `run_env_count_max`.
    env_names: []const []const u8 = &.{},
    /// The directory the command starts in, absolute; made if the root file system lacks it.
    /// Empty: the root.
    workdir: []const u8 = "",
    /// The user and group the command runs as. Null: root (id 0). Any other needs the full id
    /// map; a run with only root mapped refuses it.
    user: ?User = null,
    /// What the container can reach. Nothing, unless granted.
    network: Network = .none,
    /// The host's TCP ports forwarded to the container's (`--publish`); only with `user`.
    publish: []const Publish = &.{},
    /// The state volumes it mounts (`--state`): each made on first use, held for the run's whole
    /// life (one writer, or readers), and named in the run record.
    state: []const volume.Mount = &.{},
};

/// Null if `path` can be a working directory: absolute, no NUL, no ".." part, and short.
pub fn workdir_problem(path: []const u8) bool {
    assert(path.len <= constants.arg_bytes_max * 4);
    if (path.len == 0) return false;
    if (path.len > constants.rootfs_bytes_max or path[0] != '/') return true;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return true;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

/// The index of the first label that does not fit, or null. Too many labels is reported at the
/// index of the first one past the bound. A key is non-empty printable ASCII without '='.
pub fn labels_problem(labels: []const Label) ?u32 {
    if (labels.len > constants.labels_count_max) return constants.labels_count_max;
    for (labels, 0..) |label, index| {
        const key_ok = label.key.len > 0 and label.key.len <= constants.label_key_bytes_max;
        if (!key_ok) return @intCast(index);
        if (label.value.len > constants.label_value_bytes_max) return @intCast(index);
        for (label.key) |byte| {
            if (byte <= 0x20 or byte >= 0x7f or byte == '=') return @intCast(index);
        }
    }
    return null;
}

pub const NameProblem = union(enum) {
    empty,
    too_long,
    /// A character outside lowercase letters, digits and '-', at this index.
    bad_character: u32,
    /// A hostname label cannot start or end with '-'.
    hyphen_at_edge,
};

/// Null if `name` is a valid container name: a hostname label of lowercase letters, digits
/// and '-', one to 63 characters, not starting or ending with '-'.
pub fn name_problem(name: []const u8) ?NameProblem {
    if (name.len == 0) return .empty;
    if (name.len > constants.container_name_bytes_max) return .too_long;
    assert(name.len > 0);
    for (name, 0..) |byte, index| {
        const allowed = std.ascii.isDigit(byte) or std.ascii.isLower(byte) or byte == '-';
        if (!allowed) return .{ .bad_character = @intCast(index) };
    }
    if (name[0] == '-' or name[name.len - 1] == '-') return .hyphen_at_edge;
    assert(name.len <= constants.container_name_bytes_max);
    return null;
}

/// Null if `path` can be a layer of an overlay mount: the kernel reads the mount data as text
/// and splits it at commas and colons, with a backslash to escape; a path with any of the three
/// would be misread, so it is refused instead.
pub fn overlay_path_problem(path: []const u8) ?u8 {
    assert(path.len <= constants.file_bytes_max);
    for (path) |byte| {
        if (byte == ',' or byte == ':' or byte == '\\') return byte;
    }
    return null;
}

pub const RootfsProblem = enum { empty, too_long };

pub fn rootfs_problem(rootfs: []const u8) ?RootfsProblem {
    if (rootfs.len == 0) return .empty;
    if (rootfs.len > constants.rootfs_bytes_max) return .too_long;
    assert(rootfs.len > 0);
    assert(std.mem.indexOfScalar(u8, rootfs, 0) == null); // Arguments are C strings.
    return null;
}

pub const CommandProblem = union(enum) {
    /// No program was given.
    empty,
    too_many_words,
    /// The word at this index is longer than `command_word_bytes_max`.
    word_too_long: u32,
    /// The words and the environment together exceed `exec_strings_bytes_max`.
    too_many_bytes,
};

/// The bytes the command's words take in the exec image: each word and its NUL.
pub fn command_bytes(command: []const []const u8) u32 {
    assert(command.len <= constants.command_words_count_max);
    var total: u32 = 0;
    for (command) |word| {
        assert(word.len <= constants.command_word_bytes_max);
        total += @intCast(word.len + 1);
    }
    return total;
}

/// The most bytes the container's environment can take: PATH, HOME, HOSTNAME and TERM, each
/// "NAME=value" and a NUL.
pub const environment_bytes_max: u32 = ("PATH=".len + constants.container_path.len + 1) +
    ("HOME=/root".len + 1) +
    ("HOSTNAME=".len + constants.container_name_bytes_max + 1) +
    ("TERM=".len + constants.term_bytes_max + 1);

pub fn command_problem(command: []const []const u8) ?CommandProblem {
    if (command.len == 0) return .empty;
    if (command[0].len == 0) return .empty;
    if (command.len > constants.command_words_count_max) return .too_many_words;
    var total: u64 = environment_bytes_max;
    for (command, 0..) |word, index| {
        if (word.len > constants.command_word_bytes_max) {
            return .{ .word_too_long = @intCast(index) };
        }
        total += word.len + 1;
    }
    if (total > constants.exec_strings_bytes_max) return .too_many_bytes;
    assert(command.len > 0);
    return null;
}

test "labels: the bounds are exact and a key is a plain word" {
    // Goal: the boundary where a label stops fitting.
    const repeat_text = @import("../test_util.zig").repeat;
    try testing.expect(labels_problem(&.{}) == null);
    try testing.expect(labels_problem(&.{.{ .key = "app", .value = "" }}) == null);
    const key = repeat_text('k', constants.label_key_bytes_max);
    const value = repeat_text('v', constants.label_value_bytes_max);
    try testing.expect(labels_problem(&.{.{ .key = key, .value = value }}) == null);
    const long_key = repeat_text('k', constants.label_key_bytes_max + 1);
    const long_value = repeat_text('v', constants.label_value_bytes_max + 1);
    try testing.expectEqual(
        @as(?u32, 1),
        labels_problem(&.{ .{ .key = "a", .value = "" }, .{ .key = long_key, .value = "" } }),
    );
    try testing.expectEqual(@as(?u32, 0), labels_problem(&.{.{ .key = "a", .value = long_value }}));
    try testing.expectEqual(@as(?u32, 0), labels_problem(&.{.{ .key = "", .value = "x" }}));
    try testing.expectEqual(@as(?u32, 0), labels_problem(&.{.{ .key = "a=b", .value = "x" }}));
    try testing.expectEqual(@as(?u32, 0), labels_problem(&.{.{ .key = "a b", .value = "x" }}));
    const many: [constants.labels_count_max + 1]Label = @splat(.{ .key = "k", .value = "v" });
    try testing.expect(labels_problem(many[0..constants.labels_count_max]) == null);
    try testing.expectEqual(@as(?u32, constants.labels_count_max), labels_problem(&many));
}

/// The index of the first variable that does not fit, or null; too many is reported at the index
/// of the first one past the bound. A name is non-empty printable ASCII without '='; a value
/// holds no NUL. The command, the defaults and these together must fit the exec image.
pub fn env_problem(env: []const Label, command: []const []const u8) ?u32 {
    assert(command_problem(command) == null);
    if (env.len > constants.env_vars_count_max) return constants.env_vars_count_max;
    var total: u64 = environment_bytes_max + command_bytes(command);
    for (env, 0..) |variable, index| {
        const name_ok = variable.key.len > 0 and variable.key.len <= constants.env_name_bytes_max;
        if (!name_ok) return @intCast(index);
        if (variable.value.len > constants.env_value_bytes_max) return @intCast(index);
        for (variable.key) |byte| {
            if (byte <= 0x20 or byte >= 0x7f or byte == '=') return @intCast(index);
        }
        if (std.mem.indexOfScalar(u8, variable.value, 0) != null) return @intCast(index);
        total += variable.key.len + variable.value.len + 2;
        if (total > constants.exec_strings_bytes_max) return @intCast(index);
    }
    return null;
}

comptime {
    assert(environment_bytes_max < constants.exec_strings_bytes_max);
}

/// A POSIX variable name: a letter or underscore, then letters, digits and underscores, at most
/// `env_name_bytes_max`. `-e` accepts these only (the image's own may be looser).
pub fn env_name_valid(name: []const u8) bool {
    assert(constants.env_name_bytes_max <= 255);
    if (name.len == 0 or name.len > constants.env_name_bytes_max) return false;
    for (name, 0..) |byte, index| {
        const letter = std.ascii.isAlphabetic(byte) or byte == '_';
        if (index == 0 and !letter) return false;
        if (!letter and !std.ascii.isDigit(byte)) return false;
    }
    return true;
}

/// The index of the first name of `names` that `-e` could not have set (not a POSIX name, or
/// one that came before), or `run_env_count_max` if there are too many; null if all are good.
pub fn env_names_problem(names: []const []const u8) ?u32 {
    if (names.len > constants.run_env_count_max) return constants.run_env_count_max;
    for (names, 0..) |name, index| {
        if (!env_name_valid(name)) return @intCast(index);
        for (names[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier, name)) return @intCast(index);
        }
    }
    return null;
}

test "env_name_valid: POSIX names, at the bound and one past it" {
    // Goal: the one definition `-e` and the run record share. Method: good and bad shapes, and
    // the length bound exactly.
    try testing.expect(env_name_valid("A"));
    try testing.expect(env_name_valid("_x9"));
    try testing.expect(env_name_valid("POSTGRES_PASSWORD"));
    try testing.expect(!env_name_valid(""));
    try testing.expect(!env_name_valid("9a"));
    try testing.expect(!env_name_valid("a-b"));
    try testing.expect(!env_name_valid("a=b"));
    try testing.expect(!env_name_valid("a b"));
    try testing.expect(!env_name_valid("\xc3\xa9"));
    const longest = repeat('n', constants.env_name_bytes_max);
    try testing.expect(env_name_valid(longest));
    try testing.expect(!env_name_valid(repeat('n', constants.env_name_bytes_max + 1)));
}

test "env_names_problem: a repeat, a bad name and one past the count" {
    // Goal: the record's rules for the names of `-e`. Method: each problem at its index.
    try testing.expect(env_names_problem(&.{}) == null);
    try testing.expect(env_names_problem(&.{ "A", "B" }) == null);
    try testing.expectEqual(@as(?u32, 1), env_names_problem(&.{ "A", "A" }));
    try testing.expectEqual(@as(?u32, 1), env_names_problem(&.{ "A", "1" }));
    const count = constants.run_env_count_max + 1;
    const names: [count][]const u8 = @splat("A");
    const expected: ?u32 = constants.run_env_count_max;
    try testing.expectEqual(expected, env_names_problem(&names));
}

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;

test "name_problem accepts hostname labels and refuses everything else, at the boundaries" {
    // Goal: the exact set of valid names. Method: the longest and shortest valid names, one byte
    // over, each class of bad character at its index, and the edge hyphens.
    try testing.expect(name_problem("a") == null);
    try testing.expect(name_problem("zbx-a1b2c3") == null);
    try testing.expect(name_problem("web-1") == null);
    try testing.expect(name_problem("0") == null);
    try testing.expect(name_problem(repeat('a', constants.container_name_bytes_max)) == null);
    try testing.expectEqual(NameProblem.too_long, name_problem(repeat('a', 64)).?);
    try testing.expectEqual(NameProblem.empty, name_problem("").?);
    try testing.expectEqual(@as(u32, 3), name_problem("web_1").?.bad_character);
    try testing.expectEqual(@as(u32, 0), name_problem("Web").?.bad_character);
    try testing.expectEqual(@as(u32, 3), name_problem("web.1").?.bad_character);
    try testing.expectEqual(@as(u32, 1), name_problem("a b").?.bad_character);
    try testing.expectEqual(@as(u32, 1), name_problem("a\xc3\xa9").?.bad_character);
    try testing.expectEqual(NameProblem.hyphen_at_edge, name_problem("-web").?);
    try testing.expectEqual(NameProblem.hyphen_at_edge, name_problem("web-").?);
    try testing.expectEqual(NameProblem.hyphen_at_edge, name_problem("-").?);
    try testing.expect(name_problem("w-e-b") == null);
}

test "env_problem: the bounds are exact and a name is a plain word" {
    // Goal: where a variable stops fitting. Method: the longest name and value, one byte over,
    // each bad character, the count, and the exec image's total.
    const command: []const []const u8 = &.{"ls"};
    const name = repeat('k', constants.env_name_bytes_max);
    const value = repeat('v', constants.env_value_bytes_max);
    try testing.expect(env_problem(&.{}, command) == null);
    try testing.expect(env_problem(&.{.{ .key = name, .value = value }}, command) == null);
    const long_name = repeat('k', constants.env_name_bytes_max + 1);
    const long_value = repeat('v', constants.env_value_bytes_max + 1);
    const second_bad = [2]Label{
        .{ .key = "A", .value = "" },
        .{ .key = long_name, .value = "" },
    };
    try testing.expectEqual(@as(?u32, 1), env_problem(&second_bad, command));
    const bad_ones = [_]Label{
        .{ .key = "A", .value = long_value },
        .{ .key = "", .value = "x" },
        .{ .key = "A=B", .value = "x" },
        .{ .key = "A B", .value = "x" },
        .{ .key = "A", .value = "x\x00y" },
    };
    for (&bad_ones) |*bad| {
        try testing.expectEqual(@as(?u32, 0), env_problem(bad[0..1], command));
    }
    const many: [constants.env_vars_count_max + 1]Label = @splat(.{ .key = "K", .value = "v" });
    try testing.expect(env_problem(many[0..constants.env_vars_count_max], command) == null);
    try testing.expectEqual(@as(?u32, constants.env_vars_count_max), env_problem(&many, command));
    // Eight maximal values do not fit the exec image with the defaults.
    const big: [8]Label = @splat(.{ .key = "K", .value = value });
    try testing.expect(env_problem(big[0..6], command) == null);
    try testing.expectEqual(@as(?u32, 7), env_problem(&big, command));
}

test "rootfs_problem and command_problem: the limits are exact" {
    // Goal: one byte past a bound is a problem and the bound itself is not.
    try testing.expect(rootfs_problem(repeat('r', constants.rootfs_bytes_max)) == null);
    try testing.expectEqual(RootfsProblem.too_long, rootfs_problem(repeat('r', 1025)).?);
    try testing.expectEqual(RootfsProblem.empty, rootfs_problem("").?);

    const word = repeat('w', constants.command_word_bytes_max);
    try testing.expect(command_problem(&.{ "/bin/sh", "-c", "true" }) == null);
    try testing.expect(command_problem(&.{word}) == null);
    const too_long = command_problem(&.{ "ls", repeat('w', constants.command_word_bytes_max + 1) });
    try testing.expectEqual(@as(u32, 1), too_long.?.word_too_long);
    try testing.expectEqual(CommandProblem.empty, command_problem(&.{}).?);
    try testing.expectEqual(CommandProblem.empty, command_problem(&.{""}).?);

    const many: [constants.command_words_count_max + 1][]const u8 = @splat("x");
    try testing.expect(command_problem(many[0..constants.command_words_count_max]) == null);
    try testing.expectEqual(CommandProblem.too_many_words, command_problem(&many).?);

    // Eight maximal words and the environment fit the exec image; a ninth does not.
    const heavy: [9][]const u8 = @splat(word);
    try testing.expectEqual(CommandProblem.too_many_bytes, command_problem(&heavy).?);
    const fits: [8][]const u8 = @splat(word);
    try testing.expect(command_problem(&fits) == null);
}

// ---- Limits --------------------------------------------------------------------------------

/// Which limit a value is for.
pub const LimitKind = enum { memory, pids, cpus };

/// Why a limit's value is not accepted. The bound is in `constants.zig`.
pub const LimitProblem = error{
    Empty,
    /// Not a number (or a unit that is not k, m or g).
    NotANumber,
    Zero,
    TooSmall,
    TooLarge,
    /// More than three decimals for a CPU count, which `CPUQuota` could not honour.
    TooPrecise,
};

/// The bytes in a memory size: digits and an optional binary unit, `k`, `m` or `g` (any case).
/// A bare number is bytes. 128m is 128 MiB.
pub fn parse_memory(text: []const u8) LimitProblem!u64 {
    assert(constants.limit_memory_bytes_min >= 1 << 20);
    if (text.len == 0) return error.Empty;
    if (text.len > constants.limit_text_bytes_max) return error.NotANumber;
    var digits = text;
    var multiplier: u64 = 1;
    switch (std.ascii.toLower(text[text.len - 1])) {
        'k' => multiplier = 1 << 10,
        'm' => multiplier = 1 << 20,
        'g' => multiplier = 1 << 30,
        else => {},
    }
    if (multiplier != 1) digits = text[0 .. text.len - 1];
    const count = parse_count(digits) catch |err| return err;
    if (count == 0) return error.Zero;
    const bytes = std.math.mul(u64, count, multiplier) catch return error.TooLarge;
    if (bytes < constants.limit_memory_bytes_min) return error.TooSmall;
    if (bytes > constants.limit_memory_bytes_max) return error.TooLarge;
    assert(bytes >= constants.limit_memory_bytes_min);
    return bytes;
}

pub fn parse_pids(text: []const u8) LimitProblem!u32 {
    assert(constants.limit_pids_max <= std.math.maxInt(u32));
    if (text.len == 0) return error.Empty;
    if (text.len > constants.limit_text_bytes_max) return error.NotANumber;
    const count = parse_count(text) catch |err| return err;
    if (count == 0) return error.Zero;
    if (count > constants.limit_pids_max) return error.TooLarge;
    assert(count >= constants.limit_pids_min);
    return @intCast(count);
}

/// CPUs as a decimal with at most three places ("0.5", "2", "1.25"), as thousandths.
pub fn parse_cpus(text: []const u8) LimitProblem!u32 {
    assert(constants.limit_cpu_millis_max <= std.math.maxInt(u32));
    if (text.len == 0) return error.Empty;
    if (text.len > constants.limit_text_bytes_max) return error.NotANumber;
    const dot = std.mem.indexOfScalar(u8, text, '.');
    const whole_text = if (dot) |at| text[0..at] else text;
    const fraction_text = if (dot) |at| text[at + 1 ..] else "";
    if (dot != null and fraction_text.len == 0) return error.NotANumber;
    if (fraction_text.len > 3) return error.TooPrecise;
    const whole = if (whole_text.len == 0) 0 else parse_count(whole_text) catch |err| return err;
    var fraction: u64 = 0;
    if (fraction_text.len > 0) fraction = try parse_count(fraction_text);
    for (0..3 - fraction_text.len) |_| fraction *= 10;
    if (whole_text.len == 0 and dot == null) return error.Empty;
    const millis = std.math.mul(u64, whole, 1000) catch return error.TooLarge;
    const total = millis + fraction;
    if (total == 0) return error.Zero;
    if (total < constants.limit_cpu_millis_min) return error.TooSmall;
    if (total > constants.limit_cpu_millis_max) return error.TooLarge;
    assert(total <= constants.limit_cpu_millis_max);
    return @intCast(total);
}

/// A non-empty run of decimal digits, at most 18 of them (so that nothing overflows).
fn parse_count(digits: []const u8) LimitProblem!u64 {
    assert(digits.len <= constants.arg_bytes_max);
    if (digits.len == 0) return error.NotANumber;
    if (digits.len > 18) return error.TooLarge;
    var value: u64 = 0;
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return error.NotANumber;
        value = value * 10 + (digit - '0');
    }
    return value;
}

pub const LimitFound = struct { kind: LimitKind, problem: LimitProblem };

fn found(kind: LimitKind, problem: LimitProblem) LimitFound {
    assert(@intFromError(problem) != 0);
    return .{ .kind = kind, .problem = problem };
}

/// The first limit of a typed `Limits` that is outside its bounds, for callers of the library
/// that did not go through the flags.
pub fn limits_problem(limits: Limits) ?LimitFound {
    assert(constants.limit_memory_bytes_min > 0);
    assert(constants.limit_pids_min > 0);
    if (limits.memory_bytes) |value| {
        if (value == 0) return .{ .kind = .memory, .problem = error.Zero };
        if (value < constants.limit_memory_bytes_min) return found(.memory, error.TooSmall);
        if (value > constants.limit_memory_bytes_max) return found(.memory, error.TooLarge);
    }
    if (limits.pids) |value| {
        if (value == 0) return .{ .kind = .pids, .problem = error.Zero };
        if (value > constants.limit_pids_max) return .{ .kind = .pids, .problem = error.TooLarge };
    }
    if (limits.cpu_millis) |value| {
        if (value == 0) return .{ .kind = .cpus, .problem = error.Zero };
        if (value < constants.limit_cpu_millis_min) return found(.cpus, error.TooSmall);
        if (value > constants.limit_cpu_millis_max) return found(.cpus, error.TooLarge);
    }
    return null;
}

test "memory sizes: units, bare bytes, and both ends of the bound" {
    // Goal: binary units in any case, the exact minimum and maximum, and one either side.
    try testing.expectEqual(@as(u64, 128 << 20), try parse_memory("128m"));
    try testing.expectEqual(@as(u64, 128 << 20), try parse_memory("128M"));
    try testing.expectEqual(@as(u64, 1 << 30), try parse_memory("1g"));
    try testing.expectEqual(@as(u64, 4096 << 10), try parse_memory("4096k"));
    try testing.expectEqual(@as(u64, 4 << 20), try parse_memory("4194304"));
    try testing.expectEqual(@as(u64, 4 << 20), try parse_memory("4m"));
    try testing.expectError(error.TooSmall, parse_memory("4194303"));
    try testing.expectError(error.TooSmall, parse_memory("3m"));
    try testing.expectEqual(@as(u64, 1 << 40), try parse_memory("1024g"));
    try testing.expectError(error.TooLarge, parse_memory("1025g"));
    try testing.expectError(error.TooLarge, parse_memory("999999999999999999g"));
    try testing.expectError(error.Zero, parse_memory("0"));
    try testing.expectError(error.Zero, parse_memory("0m"));
    try testing.expectError(error.Empty, parse_memory(""));
    try testing.expectError(error.NotANumber, parse_memory("m"));
    try testing.expectError(error.NotANumber, parse_memory("12x"));
    try testing.expectError(error.NotANumber, parse_memory("-5m"));
    try testing.expectError(error.NotANumber, parse_memory("1.5g"));
    try testing.expectError(error.NotANumber, parse_memory("1 m"));
    try testing.expectError(error.TooLarge, parse_memory("1234567890123456789012"));
}

test "pids: one to the kernel's maximum" {
    try testing.expectEqual(@as(u32, 1), try parse_pids("1"));
    try testing.expectEqual(@as(u32, 64), try parse_pids("64"));
    try testing.expectEqual(@as(u32, 4_194_304), try parse_pids("4194304"));
    try testing.expectError(error.TooLarge, parse_pids("4194305"));
    try testing.expectError(error.Zero, parse_pids("0"));
    try testing.expectError(error.Zero, parse_pids("000"));
    try testing.expectError(error.Empty, parse_pids(""));
    try testing.expectError(error.NotANumber, parse_pids("-1"));
    try testing.expectError(error.NotANumber, parse_pids("6 4"));
    try testing.expectError(error.NotANumber, parse_pids("0x40"));
}

test "cpus: decimals to thousandths, and the edges" {
    try testing.expectEqual(@as(u32, 500), try parse_cpus("0.5"));
    try testing.expectEqual(@as(u32, 500), try parse_cpus(".5"));
    try testing.expectEqual(@as(u32, 2000), try parse_cpus("2"));
    try testing.expectEqual(@as(u32, 1250), try parse_cpus("1.25"));
    try testing.expectEqual(@as(u32, 10), try parse_cpus("0.01"));
    try testing.expectEqual(@as(u32, 1_024_000), try parse_cpus("1024"));
    try testing.expectError(error.TooSmall, parse_cpus("0.009"));
    try testing.expectError(error.TooLarge, parse_cpus("1024.001"));
    try testing.expectError(error.Zero, parse_cpus("0"));
    try testing.expectError(error.Zero, parse_cpus("0.0"));
    try testing.expectError(error.TooPrecise, parse_cpus("0.1234"));
    try testing.expectError(error.NotANumber, parse_cpus("1."));
    try testing.expectError(error.NotANumber, parse_cpus("."));
    try testing.expectError(error.NotANumber, parse_cpus("a"));
    try testing.expectError(error.NotANumber, parse_cpus("1,5"));
    try testing.expectError(error.Empty, parse_cpus(""));
    try testing.expectError(error.TooLarge, parse_cpus("99999999999999999999"));
}

test "typed limits are checked against the same bounds" {
    // Goal: a library caller that skips the flags meets the same refusals.
    try testing.expect(limits_problem(.{}) == null);
    const fine: Limits = .{ .memory_bytes = 128 << 20, .pids = 64, .cpu_millis = 500 };
    try testing.expect(limits_problem(fine) == null);
    try testing.expect(limits_problem(.{ .memory_bytes = 0 }).?.problem == error.Zero);
    try testing.expect(limits_problem(.{ .memory_bytes = 1 }).?.problem == error.TooSmall);
    try testing.expect(limits_problem(.{ .pids = 0 }).?.kind == .pids);
    try testing.expect(limits_problem(.{ .cpu_millis = 2_000_000 }).?.problem == error.TooLarge);
    try testing.expect(!(Limits{}).any());
    try testing.expect((Limits{ .pids = 3 }).any());
}

test "publish: HOST:CONTAINER parses, and only what renders back the same" {
    // Goal: the parser accepts exactly the texts `Publish.text` writes. Method: valid values
    // round-trip; each kind of bad value names its problem; the edges 1, 65535 and 65536.
    const cases = [_][]const u8{ "8080:80", "1:1", "65535:65535", "443:8443" };
    for (cases) |case| {
        const parsed = parse_publish(case).ok;
        var buffer: [publish_text_bytes_max]u8 = undefined;
        try std.testing.expectEqualStrings(case, parsed.text(&buffer));
    }
    const Case = struct { text: []const u8, problem: PublishProblem };
    const bad = [_]Case{
        .{ .text = "8080", .problem = .not_host_colon_container },
        .{ .text = "1:2:3", .problem = .not_host_colon_container },
        .{ .text = "", .problem = .not_host_colon_container },
        .{ .text = ":80", .problem = .not_a_number },
        .{ .text = "80:", .problem = .not_a_number },
        .{ .text = "8o:80", .problem = .not_a_number },
        .{ .text = "+80:80", .problem = .not_a_number },
        .{ .text = "080:80", .problem = .not_a_number },
        .{ .text = "80:80/tcp", .problem = .not_a_number },
        .{ .text = "0:80", .problem = .out_of_range },
        .{ .text = "80:0", .problem = .out_of_range },
        .{ .text = "65536:80", .problem = .out_of_range },
        .{ .text = "999999:80", .problem = .out_of_range },
    };
    for (bad) |case| {
        try std.testing.expectEqual(case.problem, parse_publish(case.text).problem);
    }
}

test "publish list: the bound, and one host port twice" {
    // Goal: the list checks. Method: at the bound and one past it; a repeated host port; a
    // repeated container port, which is fine.
    var list: [constants.publish_count_max + 1]Publish = undefined;
    for (&list, 0..) |*publish, index| {
        publish.* = .{ .host = @intCast(9000 + index), .container = 80 };
    }
    try std.testing.expect(publish_problem(.user, list[0..constants.publish_count_max]) == null);
    try std.testing.expect(publish_problem(.user, &list).? == .too_many);
    const twice = [_]Publish{
        .{ .host = 8080, .container = 80 },
        .{ .host = 8080, .container = 81 },
    };
    try std.testing.expectEqual(@as(u16, 8080), publish_problem(.user, &twice).?.host_port_twice);
    try std.testing.expect(publish_problem(.none, &.{}) == null);
}
