//! What a run is asked to do, and the checks that decide whether it can be planned. Pure: no
//! kernel, no allocation. A problem found here is the user's (a bad name, a missing rootfs, a
//! command that does not fit); `run.zig` turns each into its diagnostic.
//!
//! In M1 the root file system is a directory. The `Runtime` contract of Zigcube holds an image
//! digest where `rootfs` is; the field is replaced in M4, when images exist.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// A key and a value kept in the run record, for whoever started the container to find it by.
pub const Label = struct {
    key: []const u8,
    value: []const u8,
};

pub const Spec = struct {
    /// The directory to use as the container's root, read and written in place.
    rootfs: []const u8,
    /// The container's name, also its hostname. Null: a generated `zbx-xxxxxx`.
    name: ?[]const u8,
    /// The program and its arguments. Never empty; the first word is the program.
    command: []const []const u8,
    /// Kept in the run record. At most `labels_count_max`, with bounded keys and values.
    labels: []const Label = &.{},
};

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

comptime {
    assert(environment_bytes_max < constants.exec_strings_bytes_max);
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
