//! Which commands the macOS `zbx` forwards to the Linux `zbx` in the machine, and how it reads the
//! command line to decide. Pure functions of the words, with nothing from macOS, so that their
//! tests run on Linux (`forward_commands_tests.zig` ties the tables to the Linux command line).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// The Linux `zbx` commands: forwarded into the VM, whole, to the zbx that runs there.
pub const linux_commands = [_][]const u8{
    "run",  "ps",  "stop", "commit", "store", "state",  "lock", "pull", "bundle", "logs",
    "exec", "key", "sign", "verify", "trust", "policy",
};

/// The commands that may ask for a key's passphrase on a terminal. On the Mac they run with no
/// terminal, so the Linux zbx refuses (ZBX-E0911) instead of prompting through the relay: a key
/// there uses `--passphrase-file` under the shared home, or `--no-passphrase`.
pub const no_terminal_commands = [_][]const u8{ "key", "sign" };

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
    assert(listed(&linux_commands, "run") and listed(&linux_commands, "exec"));
    return std.mem.eql(u8, operand, "run") or std.mem.eql(u8, operand, "exec");
}

/// False if the command is one of `no_terminal_commands`.
pub fn has_terminal(words: []const []const u8) bool {
    assert(words.len <= constants.args_count_max);
    const operand = first_operand(words) orelse return true;
    assert(!std.mem.startsWith(u8, operand, "-")); // `first_operand` never returns an option.
    return !listed(&no_terminal_commands, operand);
}

test "the trust commands are forwarded, build and inspect are not" {
    // Goal: the forwarding table. Method: each name, bare and after global options.
    for ([_][]const u8{ "key", "sign", "verify", "trust", "policy", "run", "exec" }) |name| {
        try std.testing.expect(forwarded(&.{name}));
        try std.testing.expect(forwarded(&.{ "--output", "json", name }));
        try std.testing.expect(forwarded(&.{ "-v", "--output=json", name }));
    }
    try std.testing.expect(!forwarded(&.{"build"}));
    try std.testing.expect(!forwarded(&.{"inspect"}));
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
