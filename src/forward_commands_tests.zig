//! Ties the macOS forwarding tables (`forward_commands.zig`) to the Linux command line and to the
//! commands that read a passphrase. Not part of the Mac test root: it needs the Linux `cli.zig`.

const std = @import("std");
const cli = @import("cli.zig");
const forward_commands = @import("forward_commands.zig");

test "every forwarded command is a command the Linux zbx accepts" {
    // Goal: a typo in the table (`polcy`) must fail here, not on a Mac. Method: parse each name
    // as a command line of its own; the Linux parser refuses an unknown command as E0001 or a
    // usage code, but never "unknown command" for a name it has. An unknown name is told apart by
    // the parser's own table, `command_named`.
    for (forward_commands.linux_commands) |name| {
        try std.testing.expect(cli.command_named(name) != null);
    }
    for (forward_commands.no_terminal_commands) |name| {
        try std.testing.expect(cli.command_named(name) != null);
        try std.testing.expect(forward_commands.forwarded(&.{name}));
    }
    try std.testing.expect(cli.command_named("polcy") == null);
}

/// The sources of the commands a Mac may forward, each with the command it implements.
const command_sources = [_]struct { command: []const u8, source: []const u8 }{
    .{ .command = "key", .source = @embedFile("trust/key_commands.zig") },
    .{ .command = "sign", .source = @embedFile("trust/sign_commands.zig") },
    .{ .command = "verify", .source = @embedFile("trust/verify_commands.zig") },
    .{ .command = "trust", .source = @embedFile("trust/trust_commands.zig") },
    .{ .command = "policy", .source = @embedFile("trust/policy_commands.zig") },
    .{ .command = "exec", .source = @embedFile("exec_commands.zig") },
    .{ .command = "run", .source = @embedFile("trust/exec_gate.zig") },
    .{ .command = "bundle", .source = @embedFile("bundle.zig") },
    .{ .command = "pull", .source = @embedFile("trust/gate.zig") },
    .{ .command = "build", .source = @embedFile("build_commands.zig") },
    .{ .command = "import", .source = @embedFile("import_commands.zig") },
    .{ .command = "inspect", .source = @embedFile("inspect_commands.zig") },
};

test "every forwarded command that can ask for a passphrase runs with no terminal" {
    // Goal: a command that reaches `passphrase.acquire` would prompt through the relay, which the
    // brief cut. Method: a command whose source calls `acquire` must be in `no_terminal_commands`.
    // The list above names the sources of the forwarded commands; a new command that asks for a
    // passphrase adds its source there (the limit of a check that reads source text).
    for (command_sources) |entry| {
        const asks = std.mem.indexOf(u8, entry.source, "passphrase_mod.acquire(") != null or
            std.mem.indexOf(u8, entry.source, "passphrase.acquire(") != null;
        const lacks_terminal = !forward_commands.has_terminal(&.{entry.command});
        try std.testing.expectEqual(asks, lacks_terminal);
    }
}

test "every command the Mac leaves --platform in refuses it on Linux" {
    // Goal: `build`, `import` and `inspect` refuse `--platform` on a Mac exactly as on Linux,
    // because the Mac passes it through (`takes_platform`). Method: the Linux parser on each,
    // with the option and without it, so the refusal is the option's.
    const Diag = @import("diag/diag.zig").Diag;
    const lines = [_][]const []const u8{
        &.{"build"}, &.{"import"}, &.{ "inspect", "b3:0" },
    };
    for (forward_commands.platform_kept_commands, lines) |name, line| {
        try std.testing.expect(forward_commands.forwarded(&.{name}));
        try std.testing.expectEqualStrings(name, line[0]);
        var invocation: cli.Invocation = undefined;
        var diag: Diag = undefined;
        diag.reset();
        try cli.parse(line, &invocation, &diag);
        var words: [4][]const u8 = undefined;
        @memcpy(words[0..line.len], line);
        words[line.len] = "--platform";
        words[line.len + 1] = "linux/amd64";
        diag.reset();
        const refused = cli.parse(words[0 .. line.len + 2], &invocation, &diag);
        try std.testing.expectError(error.UnknownOption, refused);
        try std.testing.expectEqual(@import("diag/codes.zig").Code.E0004, diag.code.?);
    }
}

test "demo-mac's Rosetta check reads the line the Mac's doctor prints" {
    // Goal: `demo-mac` skips its amd64 steps by the doctor's words, which live in a Mac-only
    // file. Method: both sources hold the line (`render_text` puts two spaces after the name).
    const demo = @embedFile("testing/mac_demo.zig");
    const doctor = @embedFile("mac/doctor.zig");
    const said = "installed: linux/amd64 images can run";
    try std.testing.expect(std.mem.indexOf(u8, demo, "\"rosetta  " ++ said ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, doctor, "\"" ++ said ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, doctor, "\"{s} {s}  {s}\"") != null);
}
