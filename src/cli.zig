//! Hand-written command line parser and dispatcher. Pure with respect to the kernel: all
//! output goes through the `Host`, so snapshot tests can capture it from the simulator.
//!
//! Contract (docs/briefs/M0-diagnostics.md): commands `doctor`, `explain <code>`, `help`,
//! `--version`; global options `-v`/`--verbose` and `--output text|json`, which may come before
//! or after the command. Every refusal is a diagnostic (`E00xx`, blame user), rendered here, at
//! the boundary, and nowhere below. The exit code comes from the diagnostic's blame, once, in
//! `fail`.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const doctor = @import("doctor.zig");
const text_util = @import("text.zig");
const codes = @import("diag/codes.zig");
const errors = @import("diag/errors.zig");
const explain = @import("diag/explain.zig");
const panic = @import("diag/panic.zig");
const render = @import("diag/render.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;

const help_text =
    \\zbx - rootless container runtime
    \\
    \\usage: zbx [options] <command>
    \\
    \\commands:
    \\  doctor          check that this host can run zbx (a diagnostic per failing check)
    \\  explain <code>  explain a diagnostic code offline, for example E0001
    \\  help            show this text
    \\  --version       print the version
    \\
    \\options (before or after the command):
    \\  -v, --verbose   show the full cause chain and context of a failure
    \\  --output json   write each failure to stderr as one JSON object per line
    \\
    \\exit codes: 0 ok, 1 usage error, 2 this host cannot run zbx, 70 a bug in zbx
    \\
;

const version_text = "zbx " ++ build_options.version ++ "\n";

comptime {
    // Fixed messages must fit the one buffer every message is rendered into.
    assert(help_text.len < constants.output_bytes_max);
    assert(version_text.len < constants.output_bytes_max);
    assert(help_text[help_text.len - 1] == '\n');
    assert(version_text[version_text.len - 1] == '\n');
}

pub const Command = enum { doctor, explain, help, version };

pub const OutputFormat = enum { text, json };

/// The global options. Defaults are what a run with no options gets.
pub const Options = struct {
    verbose: bool = false,
    output: OutputFormat = .text,

    /// json always carries everything; verbose only changes the text rendering.
    pub fn mode(options: Options) render.Mode {
        const result: render.Mode = if (options.output == .json)
            .json
        else if (options.verbose)
            .verbose
        else
            .text;
        assert((result == .json) == (options.output == .json));
        if (result == .verbose) assert(options.verbose);
        return result;
    }
};

pub const Invocation = struct {
    command: Command,
    /// The one operand of `explain`; null for commands that take none.
    operand: ?[]const u8,
    options: Options,
};

pub const ParseError = error{
    MissingCommand,
    UnknownCommand,
    UnexpectedArgument,
    UnknownOption,
    BadOptionValue,
    MissingArgument,
};

pub const CollectError = error{
    TooManyArguments,
    ArgumentTooLong,
};

pub const RunError = error{
    UnknownCode,
    OutputFailed,
};

/// What one argument is, decided by its shape alone. Shared by `scan_options` and `parse` so
/// that they cannot disagree about where an option's value is.
const Token = union(enum) {
    verbose,
    /// `--output`, whose value is the next argument.
    output_next,
    /// `--output=<value>`.
    output_inline: []const u8,
    unknown_option,
    operand,
};

fn classify(argument: []const u8) Token {
    assert(argument.len <= constants.arg_bytes_max);
    assert(std.mem.indexOfScalar(u8, argument, 0) == null); // Arguments are C strings.
    if (std.mem.eql(u8, argument, "-v")) return .verbose;
    if (std.mem.eql(u8, argument, "--verbose")) return .verbose;
    if (std.mem.eql(u8, argument, "--output")) return .output_next;
    const inline_prefix = "--output=";
    if (std.mem.startsWith(u8, argument, inline_prefix)) {
        return .{ .output_inline = argument[inline_prefix.len..] };
    }
    // "--help" and "--version" are commands that look like options; a lone "-" and the empty
    // string are operands, so they reach the "unknown command" error with their text.
    if (command_named(argument) != null) return .operand;
    if (argument.len > 1) {
        if (argument[0] == '-') return .unknown_option;
    }
    return .operand;
}

fn output_format_named(value: []const u8) ?OutputFormat {
    assert(value.len <= constants.arg_bytes_max);
    assert(std.mem.indexOfScalar(u8, value, 0) == null);
    if (std.mem.eql(u8, value, "text")) return .text;
    if (std.mem.eql(u8, value, "json")) return .json;
    return null;
}

/// Exact match only: near misses such as `Help` or `version` are unknown commands.
fn command_named(name: []const u8) ?Command {
    assert(name.len <= constants.arg_bytes_max); // collect() refuses longer arguments.
    var found: ?Command = null;
    if (std.mem.eql(u8, name, "doctor")) found = .doctor;
    if (std.mem.eql(u8, name, "explain")) found = .explain;
    if (std.mem.eql(u8, name, "help")) found = .help;
    if (std.mem.eql(u8, name, "--help")) found = .help;
    if (std.mem.eql(u8, name, "--version")) found = .version;
    if (found != null) assert(name.len > 0); // The empty string is never a command.
    return found;
}

fn operands_count(command: Command) u32 {
    const count: u32 = switch (command) {
        .doctor, .help, .version => 0,
        .explain => 1,
    };
    assert(count <= 1);
    return count;
}

/// Reads the global options leniently, ignoring anything wrong with them. It runs before the
/// strict `parse` so that a failure of any kind is already rendered in the requested mode: a
/// script that asked for JSON gets JSON even when it also mistyped the command.
pub fn scan_options(args: []const []const u8) Options {
    assert(args.len <= constants.args_count_max);
    var options: Options = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        switch (classify(args[index])) {
            .verbose => options.verbose = true,
            .output_inline => |value| {
                if (output_format_named(value)) |format| options.output = format;
            },
            .output_next => {
                if (index + 1 < args.len) {
                    if (output_format_named(args[index + 1])) |format| options.output = format;
                    index += 1;
                }
            },
            .unknown_option, .operand => {},
        }
    }
    assert(index <= args.len + 1);
    return options;
}

/// Maps the arguments after the program name to an invocation. Pure; on failure the diagnostic
/// is in `diag` and the caller renders it.
pub fn parse(
    args: []const []const u8,
    invocation: *Invocation,
    diag: *Diag,
) ParseError!void {
    assert(args.len <= constants.args_count_max);
    assert(diag.code == null);
    var operands: [constants.args_count_max][]const u8 = undefined;
    var count: u32 = 0;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        switch (classify(argument)) {
            .verbose => {},
            .output_inline => |value| try check_output_value(diag, value),
            .output_next => {
                if (index + 1 == args.len) return bad_output_value(diag, null);
                index += 1;
                try check_output_value(diag, args[index]);
            },
            .unknown_option => return unknown_option(diag, argument),
            .operand => {
                operands[count] = argument;
                count += 1;
            },
        }
    }
    assert(count <= args.len);
    invocation.options = scan_options(args);
    try resolve(args, operands[0..count], invocation, diag);
}

/// Turns the operands (everything that is not an option) into a command and its argument.
fn resolve(
    args: []const []const u8,
    operands: []const []const u8,
    invocation: *Invocation,
    diag: *Diag,
) ParseError!void {
    assert(operands.len <= constants.args_count_max);
    if (operands.len == 0) return missing_command(diag, args.len);
    const command = command_named(operands[0]) orelse return unknown_command(diag, operands[0]);
    const wanted = operands_count(command);
    const given: u32 = @intCast(operands.len - 1);
    if (given > wanted) return unexpected_argument(diag, command, operands[1 + wanted]);
    if (given < wanted) return missing_argument(diag, command);
    invocation.command = command;
    invocation.operand = if (wanted == 1) operands[1] else null;
    if (invocation.operand == null) assert(wanted == 0);
}

// ---- The usage diagnostics ----------------------------------------------------------------

fn echo_of(storage: *[constants.arg_echo_bytes_max]u8, argument: []const u8) []const u8 {
    assert(argument.len <= constants.arg_bytes_max);
    const echo = text_util.sanitise(storage, argument);
    assert(echo.len <= constants.arg_echo_bytes_max);
    return echo;
}

fn missing_command(diag: *Diag, args_count: usize) ParseError {
    assert(diag.code == null);
    diag.raise(.E0002);
    diag.while_("reading the command line", .{});
    // The summary already says "no command"; the cause says what zbx actually saw.
    if (args_count == 0) {
        diag.cause("zbx was run with no arguments at all", .{});
    } else {
        diag.cause("only options were given, and the first word after them must be a command", .{});
    }
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    diag.fix(.{ .sentence = "check this host:", .command = "zbx doctor" });
    assert(diag.fixes.count == 2);
    return error.MissingCommand;
}

fn unknown_command(diag: *Diag, argument: []const u8) ParseError {
    assert(diag.code == null);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    diag.raise(.E0001);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not a zbx command", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    assert(diag.code.? == .E0001);
    return error.UnknownCommand;
}

fn unexpected_argument(diag: *Diag, command: Command, argument: []const u8) ParseError {
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    assert(diag.code == null);
    const name = @tagName(command);
    diag.raise(.E0003);
    diag.while_("reading the command line", .{});
    if (operands_count(command) == 0) {
        diag.cause("'{s}' takes no arguments, but '{s}' was also given", .{ name, echo });
    } else {
        diag.cause("'{s}' takes one argument, but '{s}' was also given", .{ name, echo });
    }
    diag.context("cmd", "{s}", .{name});
    diag.context("arg", "{s}", .{echo});
    if (operands_count(command) == 0) {
        diag.fix_with("run it on its own:", "zbx {s}", .{name});
    } else {
        diag.fix_with("pass one code:", "zbx {s} E0001", .{name});
    }
    assert(diag.code.? == .E0003);
    return error.UnexpectedArgument;
}

fn missing_argument(diag: *Diag, command: Command) ParseError {
    assert(command == .explain); // The only command with an operand.
    diag.raise(.E0006);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' needs a diagnostic code", .{@tagName(command)});
    diag.context("cmd", "{s}", .{@tagName(command)});
    diag.fix(.{ .sentence = "pass the code from a diagnostic:", .command = "zbx explain E0001" });
    assert(diag.code.? == .E0006);
    return error.MissingArgument;
}

fn unknown_option(diag: *Diag, argument: []const u8) ParseError {
    assert(diag.code == null);
    assert(argument.len > 1);
    var storage: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = echo_of(&storage, argument);
    diag.raise(.E0004);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not an option zbx knows", .{echo});
    diag.context("arg", "{s}", .{echo});
    diag.fix(.{ .sentence = "see the options:", .command = "zbx help" });
    assert(diag.code.? == .E0004);
    return error.UnknownOption;
}

fn check_output_value(diag: *Diag, value: []const u8) ParseError!void {
    assert(diag.code == null);
    assert(value.len <= constants.arg_bytes_max);
    if (output_format_named(value) == null) return bad_output_value(diag, value);
}

/// `value` is null when `--output` was the last argument.
fn bad_output_value(diag: *Diag, value: ?[]const u8) ParseError {
    assert(diag.code == null);
    if (value) |given| assert(output_format_named(given) == null);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    if (value) |given| {
        var storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const echo = echo_of(&storage, given);
        diag.cause("--output takes text or json, not '{s}'", .{echo});
        diag.context("value", "{s}", .{echo});
    } else {
        diag.cause("--output needs a value, text or json, and none follows it", .{});
    }
    diag.fix(.{ .sentence = "choose text or json:", .command = "zbx --output json doctor" });
    assert(diag.code.? == .E0005);
    return error.BadOptionValue;
}

/// Copies the iterator's remaining arguments into fixed storage, refusing rather than
/// truncating when a limit is exceeded. A refusal is `ZBX-E0008` in `diag`. `collected` is how
/// many arguments were stored, also on failure, so the options among them can still be honoured
/// when the failure is rendered.
pub fn collect(
    storage: *[constants.args_count_max][]const u8,
    collected: *u32,
    iterator: anytype,
    diag: *Diag,
) CollectError![]const []const u8 {
    var count: u32 = 0;
    collected.* = 0;
    defer collected.* = count;
    while (iterator.next()) |argument| {
        if (count == constants.args_count_max) {
            diag.raise(.E0008);
            diag.while_("reading the command line", .{});
            diag.cause("more than {d} arguments were given", .{constants.args_count_max});
            diag.fix(.{ .sentence = "pass fewer arguments" });
            return error.TooManyArguments;
        }
        if (argument.len > constants.arg_bytes_max) {
            diag.raise(.E0008);
            diag.while_("reading the command line", .{});
            const size = .{ count + 1, constants.arg_bytes_max };
            diag.cause("argument {d} is longer than {d} bytes", size);
            diag.fix(.{ .sentence = "pass a shorter argument" });
            return error.ArgumentTooLong;
        }
        assert(argument.len <= constants.arg_bytes_max);
        storage[count] = argument;
        count += 1;
    }
    assert(count <= constants.args_count_max);
    if (count > 0) assert(storage[count - 1].len <= constants.arg_bytes_max);
    return storage[0..count];
}

// ---- Running -------------------------------------------------------------------------------

/// Entry point: skips the program name, collects, parses, runs. Returns the exit code.
pub fn run_from_iterator(host: Host, iterator: anytype) u8 {
    _ = iterator.next(); // Program name; absent only in a malformed exec, which is harmless.
    var diag: Diag = undefined;
    diag.reset();
    var storage: [constants.args_count_max][]const u8 = undefined;
    var collected: u32 = 0;
    const args = collect(&storage, &collected, iterator, &diag) catch {
        assert(collected <= constants.args_count_max);
        // Whatever was collected before the limit was hit may hold --output or --verbose.
        const options = scan_options(storage[0..collected]);
        panic.configure(&panic.state, options.mode());
        return fail(host, &diag, options);
    };
    assert(args.len <= constants.args_count_max);
    const code = run(host, args);
    assert(code <= constants.exit_internal);
    return code;
}

pub fn run(host: Host, args: []const []const u8) u8 {
    assert(args.len <= constants.args_count_max);
    var diag: Diag = undefined;
    diag.reset();
    const options = scan_options(args);
    panic.configure(&panic.state, options.mode());
    var invocation: Invocation = undefined;
    parse(args, &invocation, &diag) catch return fail(host, &diag, options);
    assert(invocation.options.verbose == options.verbose);
    const code = dispatch(host, &invocation, &diag) catch return fail(host, &diag, options);
    assert(code <= constants.exit_internal);
    return code;
}

fn dispatch(host: Host, invocation: *const Invocation, diag: *Diag) RunError!u8 {
    assert(diag.code == null);
    if (invocation.command == .explain) assert(invocation.operand != null);
    if (invocation.command != .explain) assert(invocation.operand == null);
    switch (invocation.command) {
        .help => try print(host, help_text, diag),
        .version => try print(host, version_text, diag),
        .explain => try run_explain(host, invocation.operand.?, diag),
        .doctor => return run_doctor(host, invocation.options, diag),
    }
    return constants.exit_ok;
}

/// Runs the doctor: its report goes to stdout, then the diagnostic of each FAIL goes to stderr,
/// in check order, in the requested mode. Text blocks are separated by a blank line; JSON is
/// one object per line. The exit code is the blame of the failures' diagnostics (the
/// environment's) and, if stderr cannot be written, the same: there is nowhere to say so.
fn run_doctor(host: Host, options: Options, diag: *Diag) RunError!u8 {
    assert(diag.code == null);
    var report: doctor.Report = undefined;
    try doctor.run(host, &report, diag);
    const mode = options.mode();
    const color = mode != .json and host.color_enabled(.stderr);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var blocks: u32 = 0;
    for (&report.checks) |*check| {
        if (check.status != .fail) continue;
        const separator = blocks > 0 and mode != .json;
        if (separator) host.write_all(.stderr, "\n") catch return constants.exit_environment;
        const block = render.render(&check.diag, mode, color, &buffer);
        host.write_all(.stderr, block) catch return constants.exit_environment;
        blocks += 1;
    }
    const code = report.exit_code();
    // A failure has a block and an environment exit code; no failure has neither.
    assert((blocks > 0) == (code == constants.exit_environment));
    if (blocks == 0) assert(code == constants.exit_ok);
    return code;
}

fn run_explain(host: Host, operand: []const u8, diag: *Diag) RunError!void {
    assert(operand.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const code = codes.parse(operand) orelse {
        var storage: [constants.arg_echo_bytes_max]u8 = undefined;
        const echo = echo_of(&storage, operand);
        diag.raise(.E0007);
        diag.while_("looking up a diagnostic code", .{});
        diag.cause("'{s}' is not a diagnostic code zbx has", .{echo});
        diag.context("arg", "{s}", .{echo});
        diag.fix(.{ .sentence = "codes look like this:", .command = "zbx explain E0001" });
        return error.UnknownCode;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    try print(host, explain.render(code, &buffer), diag);
}

/// Writes a message to stdout. A failed write is `ZBX-E0009` in `diag`.
fn print(host: Host, text: []const u8, diag: *Diag) RunError!void {
    assert(text.len > 0);
    assert(text.len <= constants.output_bytes_max);
    assert(diag.code == null);
    host.write_all(.stdout, text) catch |err| {
        errors.output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

/// The one place a failure becomes output and an exit code: renders `diag` to stderr in the
/// requested mode and returns the exit code its blame decides. A diagnostic nobody classified
/// is a bug in zbx and is reported as one. If stderr itself cannot be written there is nowhere
/// to say so, and the exit code is the environment's.
pub fn fail(host: Host, diag: *Diag, options: Options) u8 {
    if (diag.code == null) {
        diag.raise(.B0001);
        diag.cause("a failure reached the command line with no diagnostic", .{});
    }
    assert(diag.code != null);
    const mode = options.mode();
    const color = mode != .json and host.color_enabled(.stderr);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const output = render.render(diag, mode, color, &buffer);
    host.write_all(.stderr, output) catch return constants.exit_environment;
    const code = diag.exit_code();
    assert(code != constants.exit_ok);
    return code;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;
const repeat = @import("test_util.zig").repeat;

const SliceIterator = struct {
    items: []const [:0]const u8,
    index: u32 = 0,

    fn next(iterator: *SliceIterator) ?[:0]const u8 {
        if (iterator.index == iterator.items.len) return null;
        defer iterator.index += 1;
        return iterator.items[iterator.index];
    }
};

/// Runs the CLI against a fresh simulator and returns it with the exit code.
fn run_case(sim: *HostSim, args: []const [:0]const u8) !u8 {
    sim.init(1, &.{});
    var iterator: SliceIterator = .{ .items = args };
    const code = run_from_iterator(sim.interface(), &iterator);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    return code;
}

/// Parses `args` (without the program name) and returns the error and the diagnostic's code.
fn parse_case(args: []const []const u8, invocation: *Invocation) !?codes.Code {
    var diag: Diag = undefined;
    diag.reset();
    parse(args, invocation, &diag) catch return diag.code.?;
    try testing.expect(diag.code == null);
    return null;
}

test "snapshot: help text on stdout, exit 0" {
    // Goal: the user-visible help is exactly the checked-in text. Method: compare byte for byte
    // against src/testdata/help.stdout.txt; update that file deliberately when help changes.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--help" }));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
    // Options before and after the command do not change what help prints.
    const decorated = [_][:0]const u8{ "zbx", "-v", "help", "--output=json" };
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &decorated));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}

test "snapshot: --version prints the pinned version on stdout, exit 0" {
    // Goal: one line, "zbx <version>", where the version is build.zig.zon's.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "--version" }));
    try testing.expectEqualStrings("zbx " ++ build_options.version ++ "\n", sim.stdout());
    try testing.expect(std.mem.startsWith(u8, sim.stdout(), "zbx 0."));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
}

test "snapshot: explain prints the registry text on stdout, exit 0" {
    // Goal: `explain` accepts E0001 and ZBX-E0001 in any case and prints the same text; an
    // unknown code is E0007, a missing one E0006, and neither prints anything to stdout.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "explain", "E0001" }));
    try testing.expectEqualStrings(@embedFile("testdata/explain_E0001.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    try testing.expectEqual(@as(u8, 0), try run_case(&sim, &.{ "zbx", "explain", "zbx-e0001" }));
    try testing.expectEqualStrings(@embedFile("testdata/explain_E0001.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "explain", "E9999" }));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0007]: "));
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "explain" }));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0006]: "));
}

test "parse: options come before or after the command and never change the command" {
    // Goal: the global flags are position-independent, and each combination parses to the same
    // command. Method: every placement of -v and --output json around `doctor`.
    const placements = [_][]const []const u8{
        &.{ "-v", "doctor" },
        &.{ "doctor", "-v" },
        &.{ "--verbose", "doctor", "--output", "json" },
        &.{ "--output", "json", "doctor" },
        &.{ "--output=json", "-v", "doctor" },
        &.{ "doctor", "--output=text" },
    };
    var invocation: Invocation = undefined;
    for (placements) |args| {
        try testing.expect(try parse_case(args, &invocation) == null);
        try testing.expectEqual(Command.doctor, invocation.command);
        try testing.expect(invocation.operand == null);
    }
    try testing.expect(try parse_case(&.{ "explain", "-v", "E0001" }, &invocation) == null);
    try testing.expectEqualStrings("E0001", invocation.operand.?);
    try testing.expect(invocation.options.verbose);
    try testing.expect(try parse_case(&.{ "doctor", "--output=json" }, &invocation) == null);
    try testing.expectEqual(OutputFormat.json, invocation.options.output);
    try testing.expectEqual(render.Mode.json, invocation.options.mode());
}

test "parse: every usage error has its code, at the exact boundary" {
    // Goal: each way a command line is wrong maps to exactly one code. Near misses of real
    // commands are unknown, not accepted: parsing is exact.
    var invocation: Invocation = undefined;
    const cases = [_]struct { args: []const []const u8, code: codes.Code }{
        .{ .args = &.{}, .code = .E0002 },
        .{ .args = &.{"-v"}, .code = .E0002 },
        .{ .args = &.{ "--output", "json" }, .code = .E0002 },
        .{ .args = &.{"frobnicate"}, .code = .E0001 },
        .{ .args = &.{"Help"}, .code = .E0001 },
        .{ .args = &.{"version"}, .code = .E0001 },
        .{ .args = &.{""}, .code = .E0001 },
        .{ .args = &.{"-"}, .code = .E0001 },
        .{ .args = &.{ "help", "me" }, .code = .E0003 },
        .{ .args = &.{ "doctor", "-v", "now" }, .code = .E0003 },
        .{ .args = &.{ "explain", "E0001", "E0002" }, .code = .E0003 },
        .{ .args = &.{"explain"}, .code = .E0006 },
        .{ .args = &.{ "explain", "-v" }, .code = .E0006 },
        .{ .args = &.{"--frobnicate"}, .code = .E0004 },
        .{ .args = &.{ "doctor", "-x" }, .code = .E0004 },
        .{ .args = &.{ "doctor", "--" }, .code = .E0004 },
        .{ .args = &.{ "doctor", "--output" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output", "xml" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output=" }, .code = .E0005 },
        .{ .args = &.{ "doctor", "--output", "-v" }, .code = .E0005 },
    };
    for (cases) |case| {
        const found = try parse_case(case.args, &invocation);
        try testing.expectEqual(@as(?codes.Code, case.code), found);
    }
}

test "snapshot: the usage errors exit 1 with one diagnostic on stderr and nothing on stdout" {
    // Goal: every usage error is a user-blamed diagnostic (exit 1, not the old 2), rendered on
    // stderr only. The full text of each is in the golden files (diag_golden.zig).
    var sim: HostSim = undefined;
    const bad = [_][]const [:0]const u8{
        &.{"zbx"},
        &.{ "zbx", "frobnicate" },
        &.{ "zbx", "help", "me" },
        &.{ "zbx", "--nope" },
        &.{ "zbx", "--output", "xml", "help" },
        &.{ "zbx", "explain" },
        &.{ "zbx", "explain", "Z" },
    };
    for (bad) |args| {
        try testing.expectEqual(@as(u8, 1), try run_case(&sim, args));
        try testing.expectEqual(@as(usize, 0), sim.stdout().len);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error[ZBX-E00"));
    }
}

test "an echoed argument cannot inject terminal escapes or overflow the line" {
    // Goal: negative space. Control bytes and non-ASCII become '?', long text is truncated.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "\x1b[31mred\n\xff" }));
    const echoed = "'?[31mred??' is not a zbx command";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), echoed) != null);
    try testing.expect(std.mem.indexOfScalar(u8, sim.stderr(), 0x1b) == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "error["));

    const long = repeat('x', constants.arg_bytes_max);
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", long }));
    const expected_echo = repeat('x', constants.arg_echo_bytes_max - 3) ++ "...";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "'" ++ expected_echo ++ "'") != null);
}

test "argument limits are refused, at the exact boundary" {
    // Goal: args_count_max arguments are accepted by collect; one more is refused; an argument
    // of arg_bytes_max bytes is accepted and one byte more is refused. A refusal is E0008, and
    // an option among the arguments that were collected still applies to how it is shown.
    const at_limit: [constants.args_count_max][:0]const u8 = @splat("a");
    var storage: [constants.args_count_max][]const u8 = undefined;
    var collected: u32 = undefined;
    var diag: Diag = undefined;
    diag.reset();
    var iterator: SliceIterator = .{ .items = &at_limit };
    const accepted = try collect(&storage, &collected, &iterator, &diag);
    try testing.expectEqual(@as(usize, constants.args_count_max), accepted.len);
    try testing.expect(diag.code == null);

    const over_limit: [constants.args_count_max + 1][:0]const u8 = @splat("a");
    iterator = .{ .items = &over_limit };
    const refused = collect(&storage, &collected, &iterator, &diag);
    try testing.expectError(error.TooManyArguments, refused);
    try testing.expectEqual(codes.Code.E0008, diag.code.?);
    try testing.expectEqual(@as(u32, constants.args_count_max), collected);

    diag.reset();
    const longest: [:0]const u8 = repeat('y', constants.arg_bytes_max);
    iterator = .{ .items = &.{longest} };
    _ = try collect(&storage, &collected, &iterator, &diag);
    const too_long: [:0]const u8 = repeat('y', constants.arg_bytes_max + 1);
    iterator = .{ .items = &.{too_long} };
    const too_long_refused = collect(&storage, &collected, &iterator, &diag);
    try testing.expectError(error.ArgumentTooLong, too_long_refused);
    try testing.expectEqual(@as(u32, 0), collected);

    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 1), try run_case(&sim, &.{ "zbx", "--output=json", too_long }));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-E0008\""));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sim.stderr(), "\n"));
}

test "colour only on a terminal with NO_COLOR unset, and the words do not change" {
    // Goal: the colour rule of the standard. Method: the same failure on a plain stream, on a
    // terminal, and on a terminal with NO_COLOR; stripping the escapes from the coloured text
    // gives the plain text exactly. JSON is never coloured.
    var plain: HostSim = undefined;
    _ = try run_case(&plain, &.{ "zbx", "frobnicate" });
    try testing.expect(std.mem.indexOfScalar(u8, plain.stderr(), 0x1b) == null);

    var coloured: HostSim = undefined;
    coloured.init(1, &.{});
    coloured.terminal = true;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expect(std.mem.indexOfScalar(u8, coloured.stderr(), 0x1b) != null);
    var stripped: [constants.output_bytes_max]u8 = undefined;
    const without_escapes = render.strip_colour(&stripped, coloured.stderr());
    try testing.expectEqualStrings(plain.stderr(), without_escapes);

    coloured.init(1, &.{});
    coloured.terminal = true;
    coloured.no_color_value = true;
    iterator = .{ .items = &.{ "zbx", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expectEqualStrings(plain.stderr(), coloured.stderr());

    coloured.init(1, &.{});
    coloured.terminal = true;
    iterator = .{ .items = &.{ "zbx", "--output", "json", "frobnicate" } };
    _ = run_from_iterator(coloured.interface(), &iterator);
    try testing.expect(std.mem.indexOfScalar(u8, coloured.stderr(), 0x1b) == null);
}

test "snapshot: doctor on a host with no readable files fails four checks, exit 2" {
    // Goal: faults and absences are FAIL with a reason, never ok. The simulator here has no
    // files at all, so every check that reads one must fail; the stdout report and the four
    // stderr blocks (in check order) are checked in. The exit code is the environment's (2),
    // not the user's.
    var sim: HostSim = undefined;
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "doctor" }));
    try testing.expectEqualStrings(@embedFile("testdata/doctor/empty_host.txt"), sim.stdout());
    const blocks = @embedFile("testdata/doctor/empty_host.stderr.txt");
    try testing.expectEqualStrings(blocks, sim.stderr());
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, sim.stderr(), "error[ZBX-E01"));

    // The options apply to the blocks and not to the report on stdout.
    const stdout = try testing.allocator.dupe(u8, sim.stdout());
    defer testing.allocator.free(stdout);
    const as_json = [_][:0]const u8{ "zbx", "doctor", "--output", "json" };
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &as_json));
    try testing.expectEqualStrings(stdout, sim.stdout());
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, sim.stderr(), "\n"));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "{\"code\":\"ZBX-E0101\""));
    try testing.expectEqual(@as(u8, 2), try run_case(&sim, &.{ "zbx", "-v", "doctor" }));
    try testing.expectEqualStrings(stdout, sim.stdout());
    const while_line = "  while  running the userns check of zbx doctor\n";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), while_line) != null);
}

test "a failing stdout is E0009 on stderr and exit 2; a failing stderr is exit 2 alone" {
    // Goal: stdout closed or full must not panic and must not be silent. Method: fail only
    // stdout (as `zbx help > /dev/full` does): the diagnostic still reaches stderr. Then fail
    // everything: there is nowhere to say so, and the exit code still says "environment".
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    sim.faults.write_error_per_mille = 1000;
    sim.faults.write_fault_stream = .stdout;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    const header = "error[ZBX-E0009]: can't write output\n";
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), header));

    sim.init(1, &.{});
    sim.faults.write_error_per_mille = 1000;
    iterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    iterator = .{ .items = &.{ "zbx", "frobnicate" } };
    try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
}

test "a failing write names the real errno: EBADF and ENOSPC from the simulator" {
    // Goal: principle 4 for output failures. Method: inject each errno on stdout writes only;
    // the E0009 cause must name exactly that errno (EBADF is how `zbx help >&-` fails; the host
    // collapses it to IoFailed, so the errno has to travel separately), exit 2 both times.
    const cases = [_]struct { errno: u16, cause: []const u8 }{
        .{ .errno = 9, .cause = "write(stdout) failed: bad file descriptor (EBADF)" },
        .{ .errno = 28, .cause = "write(stdout) failed: no space left on the device (ENOSPC)" },
        .{ .errno = 32, .cause = "write(stdout) failed: broken pipe (EPIPE)" },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        sim.init(1, &.{});
        sim.faults.write_error_per_mille = 1000;
        sim.faults.write_fault_stream = .stdout;
        sim.faults.write_errno = case.errno;
        var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
        try testing.expectEqual(@as(u8, 2), run_from_iterator(sim.interface(), &iterator));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0009]"));
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), case.cause) != null);
    }
}

test "output survives short writes" {
    // Goal: the help text arrives whole even when the kernel accepts one fragment at a time.
    var sim: HostSim = undefined;
    sim.init(5, &.{});
    sim.faults.short_write_per_mille = 1000;
    var iterator: SliceIterator = .{ .items = &.{ "zbx", "help" } };
    try testing.expectEqual(@as(u8, 0), run_from_iterator(sim.interface(), &iterator));
    try testing.expectEqualStrings(@embedFile("testdata/help.stdout.txt"), sim.stdout());
}

test "an unclassified failure is reported as a bug, never dropped" {
    // Goal: a layer that returned an error without raising a code is our bug, and the user
    // still gets exactly one diagnostic, with exit 70.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectEqual(@as(u8, 70), fail(sim.interface(), &diag, .{}));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "bug[ZBX-B0001]: "));
}
