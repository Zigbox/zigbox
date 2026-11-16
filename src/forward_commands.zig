//! Which commands the macOS `zbx` forwards to the Linux `zbx` in the machine, and how it reads the
//! command line to decide. Pure functions of the words, with nothing from macOS, so that their
//! tests run on Linux (`forward_commands_tests.zig` ties the tables to the Linux command line).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const lock_file = @import("lock_file.zig");

/// The Linux `zbx` commands: forwarded into the VM, whole, to the zbx that runs there.
pub const linux_commands = [_][]const u8{
    "run",  "ps",  "stop", "commit", "store", "state",  "lock",  "pull",   "bundle",  "logs",
    "exec", "key", "sign", "verify", "trust", "policy", "build", "import", "inspect",
};

/// The commands that may ask for a key's passphrase on a terminal. On the Mac they run with no
/// terminal, so the Linux zbx refuses (ZBX-E0911) instead of prompting through the relay: a key
/// there uses `--passphrase-file` under the shared home, or `--no-passphrase`.
pub const no_terminal_commands = [_][]const u8{ "key", "sign" };

/// The commands the Linux zbx refuses `--platform` for (it is an unknown option there), so the Mac
/// leaves it in their command line rather than taking it out as it does for `run` and `pull`.
pub const platform_kept_commands = [_][]const u8{ "build", "import", "inspect" };

/// The commands that read the project: its lock, and paths the Mac must share (`project_paths`).
pub const project_commands = [_][]const u8{ "build", "import" };

/// The first operand: the word past the global options (`-v`, `--verbose`, `--output <format>`,
/// `--output=<format>`). Null when there is none, or when an option this table does not know comes
/// first, which is a command line for the Mac's own parser. The one walk that every decision
/// below shares, so a new global option is added here and nowhere else.
pub fn first_operand(words: []const []const u8) ?[]const u8 {
    assert(words.len <= constants.args_count_max);
    var index: usize = 0;
    while (index < words.len) : (index += 1) {
        const word = words[index];
        if (std.mem.eql(u8, word, "--output")) {
            index += 1;
        } else if (std.mem.eql(u8, word, "-v") or std.mem.eql(u8, word, "--verbose") or
            std.mem.eql(u8, word, "--output=json"))
        {
            continue;
        } else if (std.mem.startsWith(u8, word, "-")) {
            return null;
        } else {
            return word;
        }
    }
    return null;
}

fn listed(names: []const []const u8, word: []const u8) bool {
    assert(names.len > 0);
    assert(word.len <= constants.arg_bytes_max);
    for (names) |name| {
        if (std.mem.eql(u8, name, word)) return true;
    }
    return false;
}

/// True if the command line is one for the Linux zbx in the VM.
pub fn forwarded(words: []const []const u8) bool {
    assert(linux_commands.len > 0);
    const operand = first_operand(words) orelse return false;
    assert(!std.mem.startsWith(u8, operand, "-")); // `first_operand` never returns an option.
    return listed(&linux_commands, operand);
}

/// True if the command is a `run` or an `exec`, which end with 125 when zbx or the machine failed.
pub fn runs_container(words: []const []const u8) bool {
    assert(words.len <= constants.args_count_max);
    const operand = first_operand(words) orelse return false;
    assert(listed(&linux_commands, "run"));
    assert(listed(&linux_commands, "exec"));
    return std.mem.eql(u8, operand, "run") or std.mem.eql(u8, operand, "exec");
}

/// False if the command is one of `no_terminal_commands`.
pub fn has_terminal(words: []const []const u8) bool {
    assert(words.len <= constants.args_count_max);
    const operand = first_operand(words) orelse return true;
    assert(!std.mem.startsWith(u8, operand, "-")); // `first_operand` never returns an option.
    return !listed(&no_terminal_commands, operand);
}

/// True if the Mac takes `--platform` out of the command line (and sets `ZBX_PLATFORM`); false for
/// the commands that refuse it on Linux, which then refuse it on the Mac the same way.
pub fn takes_platform(words: []const []const u8) bool {
    assert(words.len <= constants.args_count_max);
    const operand = first_operand(words) orelse return true;
    assert(!std.mem.startsWith(u8, operand, "-")); // `first_operand` never returns an option.
    return !listed(&platform_kept_commands, operand);
}

/// True if the command is a `build` or an `import`, which read the project's lock and paths.
pub fn reads_project(words: []const []const u8) bool {
    assert(words.len <= constants.args_count_max);
    const operand = first_operand(words) orelse return false;
    assert(!std.mem.startsWith(u8, operand, "-")); // `first_operand` never returns an option.
    return listed(&project_commands, operand);
}

/// The paths a `build` or an `import` names with `-o`, `-f` and `--context`, one by one. The
/// machine shares the home and nothing else, so each must be under it.
pub const ProjectPaths = struct {
    words: []const []const u8,
    index: u32,

    pub fn next(paths: *ProjectPaths) ?[]const u8 {
        assert(paths.index <= paths.words.len);
        while (paths.index < paths.words.len) {
            const word = paths.words[paths.index];
            paths.index += 1;
            if (std.mem.startsWith(u8, word, "--context=")) return word["--context=".len..];
            const takes_path = std.mem.eql(u8, word, "-o") or std.mem.eql(u8, word, "-f") or
                std.mem.eql(u8, word, "--context");
            if (!takes_path) continue;
            if (paths.index == paths.words.len) return null; // The Linux zbx refuses it.
            const value = paths.words[paths.index];
            paths.index += 1;
            return value;
        }
        return null;
    }
};

/// The paths of `-o`, `-f` and `--context` in a `build` or `import`; none for another command.
pub fn project_paths(words: []const []const u8) ProjectPaths {
    assert(words.len <= constants.args_count_max);
    if (!reads_project(words)) return .{ .words = &.{}, .index = 0 };
    return .{ .words = words, .index = 0 };
}

/// `path` as an absolute path with no `.`, `..` or empty parts, read against `directory` when it
/// is relative; by its words only, not the file system (a `..` above the root stays at the root).
/// Null when the result does not fit `buffer`.
pub fn resolve(directory: []const u8, path: []const u8, buffer: []u8) ?[]const u8 {
    assert(directory.len > 0);
    assert(directory[0] == '/'); // From `getcwd`.
    assert(buffer.len > 0);
    buffer[0] = '/';
    var length: usize = 1;
    const parts = [_][]const u8{ if (path.len > 0 and path[0] == '/') "" else directory, path };
    for (parts) |part| {
        var names = std.mem.tokenizeScalar(u8, part, '/');
        while (names.next()) |name| {
            if (std.mem.eql(u8, name, ".")) continue;
            if (std.mem.eql(u8, name, "..")) {
                const slash = std.mem.lastIndexOfScalar(u8, buffer[0..length], '/').?;
                length = @max(slash, 1);
                continue;
            }
            const separator: usize = if (length > 1) 1 else 0;
            if (length + separator + name.len > buffer.len) return null;
            if (separator == 1) buffer[length] = '/';
            @memcpy(buffer[length + separator ..][0..name.len], name);
            length += separator + name.len;
        }
    }
    assert(length >= 1);
    assert(buffer[0] == '/');
    return buffer[0..length];
}

/// The parse of a project's lock, for `pins_amd64` (the Mac zbx runs one command, on one thread).
var lock_read: lock_file.Lock = undefined;

/// True if `text` is a lock with an entry for linux/amd64, which needs Rosetta in the machine.
/// False for a text that is not a lock: the Linux zbx says what is wrong with it.
pub fn pins_amd64(text: []const u8) bool {
    if (text.len > constants.lock_file_bytes_max) return false;
    if (lock_file.parse(text, &lock_read) != null) return false;
    assert(lock_read.count <= constants.lock_entries_max);
    for (lock_read.entries[0..lock_read.count]) |*entry| {
        if (std.mem.eql(u8, entry.platform_text(), "linux/amd64")) return true;
    }
    return false;
}

test "the trust, build, import and inspect commands are forwarded, explain is not" {
    // Goal: the forwarding table. Method: each name, bare and after global options.
    const names = [_][]const u8{
        "key", "sign", "verify", "trust",  "policy",
        "run", "exec", "build",  "import", "inspect",
    };
    for (names) |name| {
        try std.testing.expect(forwarded(&.{name}));
        try std.testing.expect(forwarded(&.{ "--output", "json", name }));
        try std.testing.expect(forwarded(&.{ "-v", "--output=json", name }));
    }
    try std.testing.expect(!forwarded(&.{"explain"}));
    try std.testing.expect(!forwarded(&.{"vm"}));
    try std.testing.expect(!forwarded(&.{ "--bogus", "key" }));
    try std.testing.expect(!forwarded(&.{}));
}

test "key and sign run with no terminal, the others keep it" {
    // Goal: only the commands that can ask for a passphrase lose the terminal. Method: command
    // lines with and without global options, and `key` as an argument of another command.
    try std.testing.expect(!has_terminal(&.{ "key", "new", "ci" }));
    try std.testing.expect(!has_terminal(&.{ "--output", "json", "sign", "web" }));
    try std.testing.expect(!has_terminal(&.{ "-v", "key", "new" }));
    try std.testing.expect(has_terminal(&.{ "verify", "web" }));
    try std.testing.expect(has_terminal(&.{ "trust", "key" }));
    try std.testing.expect(has_terminal(&.{ "run", "alpine", "key" }));
    try std.testing.expect(has_terminal(&.{}));
}

test "run and exec end with 125, whatever global options come before them" {
    // Goal: the exit scope follows the command, not its position. Method: options, then a command.
    try std.testing.expect(runs_container(&.{ "run", "alpine" }));
    try std.testing.expect(runs_container(&.{ "--output", "json", "exec", "web" }));
    try std.testing.expect(runs_container(&.{ "-v", "run", "alpine" }));
    try std.testing.expect(!runs_container(&.{ "--output", "json" }));
    try std.testing.expect(!runs_container(&.{ "pull", "run" }));
}

test "--platform is taken for run and pull, and left for build, import and inspect to refuse" {
    // Goal: the Linux zbx refuses `--platform` for these three; the Mac must not hide it from
    // it. Method: each command, bare and after global options.
    try std.testing.expect(takes_platform(&.{ "run", "--platform", "linux/amd64", "alpine" }));
    try std.testing.expect(takes_platform(&.{ "-v", "pull", "--platform", "linux/arm64", "a" }));
    try std.testing.expect(takes_platform(&.{}));
    for (platform_kept_commands) |name| {
        try std.testing.expect(listed(&linux_commands, name));
        try std.testing.expect(!takes_platform(&.{ name, "--platform", "linux/amd64" }));
        try std.testing.expect(!takes_platform(&.{ "--output", "json", name }));
    }
}

test "the paths of build and import are their -o, -f and --context values, nothing else" {
    // Goal: every path option is checked, and no other word is. Method: command lines with each
    // form, a missing value, and the same options on a command that is not build or import.
    var paths = project_paths(&.{
        "-v",       "import",        "Dockerfile", "--context", "/tmp/c", "-o",
        "../x.zon", "--context=sub", "--target",   "-o",        "-f",
    });
    try std.testing.expectEqualStrings("/tmp/c", paths.next().?);
    try std.testing.expectEqualStrings("../x.zon", paths.next().?);
    try std.testing.expectEqualStrings("sub", paths.next().?);
    try std.testing.expectEqualStrings("-f", paths.next().?); // `--target -o` reads as `-o -f`.
    try std.testing.expect(paths.next() == null);
    var build = project_paths(&.{ "build", "-f", "/etc/b.zon" });
    try std.testing.expectEqualStrings("/etc/b.zon", build.next().?);
    try std.testing.expect(build.next() == null);
    var other = project_paths(&.{ "run", "-f", "/etc/x" });
    try std.testing.expect(other.next() == null);
    var missing = project_paths(&.{ "build", "-f" });
    try std.testing.expect(missing.next() == null);
}

test "resolve reads a path against the directory, by its words" {
    // Goal: a relative path that climbs out of the home is caught as well as an absolute one.
    // Method: each kind of part, and a result too long for the buffer.
    var buffer: [64]u8 = undefined;
    const cases = [_][3][]const u8{
        .{ "/Users/ada/p", "x.zon", "/Users/ada/p/x.zon" },
        .{ "/Users/ada/p", "../../b/x", "/Users/b/x" },
        .{ "/Users/ada/p", "/tmp/./x//y/", "/tmp/x/y" },
        .{ "/Users/ada/p", ".", "/Users/ada/p" },
        .{ "/Users/ada/p", "", "/Users/ada/p" },
        .{ "/Users/ada/p", "../../../../..", "/" },
        .{ "/", "a/../b", "/b" },
    };
    for (cases) |case| {
        try std.testing.expectEqualStrings(case[2], resolve(case[0], case[1], &buffer).?);
    }
    const long: [64]u8 = @splat('a');
    try std.testing.expect(resolve("/", &long, &buffer) == null);
}

test "a lock pins linux/amd64 only when an entry says so" {
    // Goal: the Rosetta check of a forwarded build. Method: the M9 project's lock (amd64), the
    // same with arm64, an empty lock and a text that is not a lock.
    const amd64 = @embedFile("testing/vm/m9_project/zbx.lock");
    try std.testing.expect(pins_amd64(amd64));
    var buffer: [1024]u8 = undefined;
    const replaced = std.mem.replace(u8, amd64, "linux/amd64", "linux/arm64", &buffer);
    try std.testing.expect(replaced > 0);
    try std.testing.expect(!pins_amd64(buffer[0..amd64.len]));
    try std.testing.expect(!pins_amd64(".{\n    .version = 1,\n    .images = .{},\n}\n"));
    try std.testing.expect(!pins_amd64("linux/amd64"));
}
