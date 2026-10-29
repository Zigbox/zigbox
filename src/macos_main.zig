//! The macOS `zbx`. Containers run only on a Linux kernel, so on a Mac `zbx` drives a small Linux
//! virtual machine through Apple's Virtualization.framework and, from the next slice, forwards
//! its commands into it. This slice carries the machine itself: `zbx vm start | stop | status |
//! config`, plus `schema`, `explain`, `help` and `--version`, which need no machine.
//!
//! It is a different program from the Linux `zbx`: it links libSystem (macOS requires it), and
//! shares with it the diagnostics (registry, rendering, exit codes), the constants and the
//! schemas.

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const commands = @import("mac/commands.zig");
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const explain = @import("diag/explain.zig");
const files = @import("mac/files.zig");
const host = @import("mac/host.zig");
const objc = @import("mac/objc.zig");
const panic_report = @import("diag/panic.zig");
const paths_mod = @import("mac/paths.zig");
const render = @import("diag/render.zig");
const schemas = @import("schemas.zig");
const settings_file = @import("mac/settings_file.zig");
const text_util = @import("text.zig");
const Diag = @import("diag/diag.zig").Diag;

pub const panic = std.debug.FullPanic(panic_handler);

pub const std_options: std.Options = .{ .enable_segfault_handler = false };

fn panic_handler(message: []const u8, first_trace_addr: ?usize) noreturn {
    assert(message.len < constants.output_bytes_max);
    assert(constants.output_bytes_max > 0);
    _ = first_trace_addr;
    var buffer: [constants.output_bytes_max]u8 = undefined;
    if (panic_report.respond(&panic_report.state, message, &buffer)) |bytes| {
        files.write_all(2, bytes) catch {};
    }
    std.c._exit(panic_report.exit_code(&panic_report.state));
}

const help_text =
    \\zbx - rootless container runtime (macOS)
    \\
    \\usage: zbx [options] <command>
    \\
    \\On a Mac, containers run in a small Linux virtual machine that zbx starts by itself when a
    \\command needs it and stops when it has been idle. These commands look after the machine:
    \\
    \\commands:
    \\  vm status       is the machine running, from which image, with how many CPUs and how
    \\                  much memory (--output json: see zbx schema vm-status)
    \\  vm config       show the machine's size; with --cpus <n> and/or --memory <size> (2G,
    \\                  4096M) set it for the next boot (--output json: zbx schema vm-config)
    \\  vm start        start the machine now, to have it warm; it is never required
    \\  vm stop         stop the machine (done already, and exit 0, if none runs)
    \\  schema <cmd>    print the JSON schema of a command's output
    \\  explain <code>  explain a diagnostic code offline, for example E1001
    \\  help            show this text
    \\  --version       print the version
    \\
    \\options:
    \\  -v, --verbose   show the full cause chain and context of a failure
    \\  --output json   write each result to stdout, and each failure to stderr, as JSON
    \\
    \\exit codes: 0 ok, 1 usage error, 2 this Mac cannot run the machine, 3 an external service,
    \\70 a bug
    \\
;

const version_text = "zbx " ++ build_options.version ++ " (macOS)\n";

comptime {
    assert(help_text.len < constants.output_bytes_max);
    assert(help_text[help_text.len - 1] == '\n');
}

const Command = enum {
    vm_start,
    vm_stop,
    vm_status,
    vm_config,
    vm_serve,
    schema,
    explain,
    help,
    version,
};

const Invocation = struct {
    command: Command = .help,
    operand: ?[]const u8 = null,
    verbose: bool = false,
    json: bool = false,
    cpus: ?[]const u8 = null,
    memory: ?[]const u8 = null,
    report_fd: i32 = -1,

    fn mode(invocation: *const Invocation) render.Mode {
        assert(@backingInt(invocation.command) <= @backingInt(Command.version));
        assert(invocation.report_fd >= -1);
        if (invocation.json) return .json;
        if (invocation.verbose) return .verbose;
        return .text;
    }
};

/// The names of Linux `zbx` commands this build does not forward yet.
const linux_commands = [_][]const u8{
    "run", "ps", "stop", "commit", "store", "state", "lock", "pull", "bundle", "doctor",
};

pub fn main(init: std.process.Init.Minimal) u8 {
    assert(constants.args_count_max > 0);
    assert(constants.arg_bytes_max > 0);
    const pool = objc.Pool.push();
    defer pool.pop();
    var words: [constants.args_count_max][]const u8 = undefined;
    var count: u32 = 0;
    var arguments = init.args.iterate();
    _ = arguments.next();
    while (arguments.next()) |argument| {
        if (count == words.len or argument.len > constants.arg_bytes_max) break;
        words[count] = argument;
        count += 1;
    }
    var diag: Diag = undefined;
    diag.reset();
    var invocation: Invocation = .{};
    panic_report.configure(&panic_report.state, .text, .standard);
    parse(words[0..count], &invocation, &diag) catch return fail(&diag, &invocation);
    panic_report.configure(&panic_report.state, invocation.mode(), .standard);
    dispatch(&invocation, &diag) catch return fail(&diag, &invocation);
    return constants.exit_ok;
}

fn fail(diag: *Diag, invocation: *const Invocation) u8 {
    assert(invocation.report_fd >= -1);
    assert(constants.output_bytes_max > 0);
    if (diag.code == null) {
        diag.raise(.B0001);
        diag.cause("a failure reached the command line with no diagnostic", .{});
    }
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const color = !invocation.json and std.c.isatty(2) == 1 and std.c.getenv("NO_COLOR") == null;
    const text = render.render(diag, invocation.mode(), color, &buffer);
    files.write_all(2, text) catch return constants.exit_environment;
    return diag.exit_code();
}

// ---- The command line ----------------------------------------------------------------

const ParseError = error{Usage};

fn parse(words: []const []const u8, invocation: *Invocation, diag: *Diag) ParseError!void {
    assert(invocation.cpus == null);
    assert(invocation.memory == null);
    assert(words.len <= constants.args_count_max);
    assert(diag.code == null);
    var operands: [4][]const u8 = undefined;
    var operand_count: usize = 0;
    var index: usize = 0;
    while (index < words.len) : (index += 1) {
        const word = words[index];
        if (std.mem.eql(u8, word, "-v") or std.mem.eql(u8, word, "--verbose")) {
            invocation.verbose = true;
        } else if (std.mem.eql(u8, word, "--output")) {
            index += 1;
            if (index == words.len) return bad_value(diag, "--output", "text or json");
            invocation.json = try output_is_json(diag, words[index]);
        } else if (std.mem.startsWith(u8, word, "--output=")) {
            invocation.json = try output_is_json(diag, word["--output=".len..]);
        } else if (std.mem.eql(u8, word, "--cpus") or std.mem.eql(u8, word, "--memory")) {
            index += 1;
            if (index == words.len) return bad_value(diag, word, "a value");
            const value = words[index];
            if (word[2] == 'c') invocation.cpus = value else invocation.memory = value;
        } else if (std.mem.eql(u8, word, "--report-fd")) {
            index += 1;
            if (index == words.len) return bad_value(diag, word, "a descriptor");
            invocation.report_fd = std.fmt.parseInt(i32, words[index], 10) catch
                return bad_value(diag, word, "a descriptor");
        } else if (std.mem.eql(u8, word, "--version")) {
            invocation.command = .version;
            return;
        } else if (std.mem.startsWith(u8, word, "-")) {
            return unknown_option(diag, word);
        } else {
            if (operand_count == operands.len) return unexpected(diag, word);
            operands[operand_count] = word;
            operand_count += 1;
        }
    }
    try choose(operands[0..operand_count], invocation, diag);
}

fn choose(operands: []const []const u8, invocation: *Invocation, diag: *Diag) ParseError!void {
    assert(invocation.operand == null);
    assert(operands.len <= 4);
    assert(diag.code == null);
    if (operands.len == 0) return missing_command(diag);
    const first = operands[0];
    if (std.mem.eql(u8, first, "help")) {
        invocation.command = .help;
    } else if (std.mem.eql(u8, first, "vm")) {
        try choose_vm(operands[1..], invocation, diag);
        return;
    } else if (std.mem.eql(u8, first, "schema") or std.mem.eql(u8, first, "explain")) {
        if (operands.len < 2) return missing_operand(diag, first);
        invocation.command = if (first[0] == 's') .schema else .explain;
        invocation.operand = operands[1];
        if (operands.len > 2) return unexpected(diag, operands[2]);
        return;
    } else {
        return unknown_command(diag, first);
    }
    if (operands.len > 1) return unexpected(diag, operands[1]);
}

fn choose_vm(operands: []const []const u8, invocation: *Invocation, diag: *Diag) ParseError!void {
    assert(invocation.operand == null);
    assert(operands.len <= 3);
    assert(diag.code == null);
    if (operands.len == 0) return missing_operand(diag, "vm");
    const names = [_][]const u8{ "start", "stop", "status", "config", "serve" };
    const commands_of = [_]Command{ .vm_start, .vm_stop, .vm_status, .vm_config, .vm_serve };
    for (names, commands_of) |name, command| {
        if (!std.mem.eql(u8, operands[0], name)) continue;
        invocation.command = command;
        if (operands.len > 1) return unexpected(diag, operands[1]);
        const sizing = invocation.cpus != null or invocation.memory != null;
        const sizing_option: []const u8 = if (invocation.cpus != null) "--cpus" else "--memory";
        if (sizing and command != .vm_config) return unknown_option(diag, sizing_option);
        return;
    }
    var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = text_util.sanitise(&buffer, operands[0]);
    diag.raise(.E0001);
    diag.while_("reading the command line", .{});
    diag.cause("'vm {s}' is not a zbx command", .{echo});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    return error.Usage;
}

fn output_is_json(diag: *Diag, value: []const u8) ParseError!bool {
    assert(diag.code == null);
    assert(value.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, value, "json")) return true;
    if (std.mem.eql(u8, value, "text")) return false;
    return bad_value(diag, "--output", "text or json");
}

fn bad_value(diag: *Diag, option: []const u8, wants: []const u8) ParseError {
    assert(diag.whiles.count == 0);
    assert(option.len > 0);
    assert(wants.len > 0);
    assert(diag.code == null);
    diag.raise(.E0005);
    diag.while_("reading the command line", .{});
    diag.cause("{s} takes {s}, and none valid follows it", .{ option, wants });
    diag.fix(.{ .sentence = "see the options:", .command = "zbx help" });
    return error.Usage;
}

fn unknown_option(diag: *Diag, word: []const u8) ParseError {
    assert(diag.whiles.count == 0);
    assert(word.len > 0);
    assert(word[0] == '-');
    assert(diag.code == null);
    var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.raise(.E0004);
    diag.while_("reading the command line", .{});
    diag.cause("'{s}' is not an option this command knows", .{text_util.sanitise(&buffer, word)});
    diag.fix(.{ .sentence = "see the options:", .command = "zbx help" });
    return error.Usage;
}

fn unexpected(diag: *Diag, word: []const u8) ParseError {
    assert(diag.whiles.count == 0);
    assert(word.len > 0);
    assert(diag.code == null);
    assert(diag.code == null);
    var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.raise(.E0003);
    diag.while_("reading the command line", .{});
    const echo = text_util.sanitise(&buffer, word);
    diag.cause("'{s}' follows a command that takes nothing more", .{echo});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    return error.Usage;
}

fn missing_command(diag: *Diag) ParseError {
    assert(diag.code == null);
    assert(diag.fixes.count == 0);
    assert(diag.causes.count == 0);
    assert(diag.code == null);
    diag.raise(.E0002);
    diag.while_("reading the command line", .{});
    diag.cause("zbx was run with no command", .{});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    return error.Usage;
}

fn missing_operand(diag: *Diag, command: []const u8) ParseError {
    assert(diag.code == null);
    assert(command.len > 0);
    assert(diag.fixes.count == 0);
    assert(diag.code == null);
    var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
    diag.raise(.E0006);
    diag.while_("reading the command line", .{});
    diag.cause("{s} needs a word after it", .{text_util.sanitise(&buffer, command)});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    return error.Usage;
}

fn unknown_command(diag: *Diag, word: []const u8) ParseError {
    assert(diag.whiles.count == 0);
    assert(word.len > 0);
    assert(diag.causes.count == 0);
    assert(diag.code == null);
    var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
    const echo = text_util.sanitise(&buffer, word);
    diag.raise(.E0001);
    diag.while_("reading the command line", .{});
    for (linux_commands) |name| {
        if (!std.mem.eql(u8, name, word)) continue;
        diag.cause("'{s}' is a zbx command that the macOS build does not forward yet", .{echo});
        diag.fix(.{ .sentence = "see what this build does:", .command = "zbx help" });
        return error.Usage;
    }
    diag.cause("'{s}' is not a zbx command", .{echo});
    diag.fix(.{ .sentence = "see the commands:", .command = "zbx help" });
    return error.Usage;
}

// ---- Running a command -------------------------------------------------------------

const RunError = error{Failed};

fn dispatch(invocation: *const Invocation, diag: *Diag) RunError!void {
    assert(diag.causes.count == 0);
    assert(diag.code == null);
    assert(invocation.report_fd >= -1);
    switch (invocation.command) {
        .help => commands.print(help_text),
        .version => commands.print(version_text),
        .schema => try run_schema(invocation.operand.?, diag),
        .explain => try run_explain(invocation, diag),
        else => try run_vm(invocation, diag),
    }
}

fn run_schema(topic: []const u8, diag: *Diag) RunError!void {
    assert(topic.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const text = schemas.of(topic) orelse {
        var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
        diag.raise(.E0406);
        diag.while_("looking up a schema", .{});
        diag.cause("'{s}' has no JSON schema; the macOS zbx has vm-status and vm-config", .{
            text_util.sanitise(&buffer, topic),
        });
        diag.fix(.{ .sentence = "print one:", .command = "zbx schema vm-status" });
        return error.Failed;
    };
    commands.print(text);
    commands.print("\n");
}

fn run_explain(invocation: *const Invocation, diag: *Diag) RunError!void {
    assert(diag.causes.count == 0);
    assert(invocation.operand != null);
    assert(invocation.command == .explain);
    assert(diag.code == null);
    const operand = invocation.operand.?;
    const code = codes.parse(operand) orelse {
        var buffer: [constants.arg_echo_bytes_max]u8 = undefined;
        diag.raise(.E0007);
        diag.while_("looking up a diagnostic code", .{});
        const echo = text_util.sanitise(&buffer, operand);
        diag.cause("'{s}' is not a diagnostic code zbx has", .{echo});
        diag.fix(.{ .sentence = "codes look like this:", .command = "zbx explain E1001" });
        return error.Failed;
    };
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = if (invocation.json)
        explain.render_json(code, &buffer)
    else
        explain.render(code, &buffer);
    commands.print(text);
}

fn run_vm(invocation: *const Invocation, diag: *Diag) RunError!void {
    assert(invocation.command != .help);
    assert(invocation.command != .version);
    assert(diag.code == null);
    assert(invocation.operand == null);
    const home = std.c.getenv("HOME") orelse "";
    var paths: paths_mod.Paths = .{};
    if (home[0..std.mem.len(home)].len == 0 or home[0] != '/') {
        diagnose_home(diag);
        return error.Failed;
    }
    paths.init(std.mem.span(home), image_version()) catch {
        diagnose_home(diag);
        return error.Failed;
    };
    const context: commands.Context = .{
        .paths = &paths,
        .json = invocation.json,
        .mode = invocation.mode(),
        .color = false,
    };
    const cpus = files.host_cpus();
    const result = switch (invocation.command) {
        .vm_status => commands.run_status(&context, cpus, diag),
        .vm_stop => commands.run_stop(&context, cpus, diag),
        .vm_start => commands.run_start(&context, cpus, diag),
        .vm_config => commands.run_config(&context, sizing_of(invocation), cpus, diag),
        .vm_serve => return serve(invocation, &paths, cpus, diag),
        else => unreachable, // `dispatch` sends only the vm commands here.
    };
    return result catch error.Failed;
}

fn sizing_of(invocation: *const Invocation) commands.ConfigRequest {
    assert(@sizeOf(commands.ConfigRequest) > 0);
    assert(invocation.command == .vm_config);
    assert(invocation.report_fd >= -1);
    return .{ .cpus = invocation.cpus, .memory = invocation.memory };
}

fn image_version() []const u8 {
    assert(@import("mac/image.zig").version.len == constants.vm_image_version_bytes);
    assert(constants.vm_image_version_bytes == 16);
    return @import("mac/image.zig").version;
}

fn diagnose_home(diag: *Diag) void {
    assert(diag.code == null);
    assert(diag.causes.count == 0);
    const reason = "is not set to an absolute path";
    @import("mac/diagnose.zig").directory(diag, "finding the user's Library", "$HOME", reason);
}

/// `zbx vm serve`: the detached host. It tells whoever started it (`--report-fd`) how the boot
/// went, then serves until the machine is off. Run by hand it reports on stderr.
fn serve(
    invocation: *const Invocation,
    paths: *const paths_mod.Paths,
    cpus: u32,
    diag: *Diag,
) RunError!void {
    assert(paths.socket.length > 0);
    assert(invocation.command == .vm_serve);
    assert(cpus >= 1);
    host.install_signal_handlers();
    const loaded = settings_file.load(paths, cpus, diag) catch {
        return report(invocation, diag, false);
    };
    const request: host.Request = .{ .paths = paths, .values = loaded.values };
    var running = host.boot(&request, diag) catch return report(invocation, diag, false);
    report(invocation, diag, true) catch {};
    _ = host.run(&running, paths);
}

fn report(invocation: *const Invocation, diag: *Diag, ok: bool) RunError!void {
    assert(diag.fixes.count <= constants.diag_fixes_count_max);
    assert(invocation.command == .vm_serve);
    if (!ok) assert(diag.code != null);
    if (invocation.report_fd < 0) {
        if (ok) return;
        return error.Failed;
    }
    var message: [constants.diag_carry_bytes_max + 1]u8 = undefined;
    var length: usize = 1;
    if (ok) {
        message[0] = commands.report_ok;
    } else {
        message[0] = commands.report_failed;
        var carried: [constants.diag_carry_bytes_max]u8 = undefined;
        const bytes = diag.encode(&carried);
        @memcpy(message[1..][0..bytes.len], bytes);
        length += bytes.len;
    }
    files.write_all(invocation.report_fd, message[0..length]) catch {};
    files.close(invocation.report_fd);
    if (!ok) return error.Failed;
}

test {
    _ = @import("mac/objc.zig");
    _ = @import("mac/vz.zig");
    _ = @import("mac/image.zig");
    _ = @import("mac/files.zig");
    _ = @import("mac/paths.zig");
    _ = @import("mac/settings.zig");
    _ = @import("mac/control.zig");
    _ = @import("mac/diagnose.zig");
    _ = @import("mac/commands.zig");
    _ = @import("vm_protocol.zig");
    _ = @import("schemas.zig");
    _ = @import("mac/vm_golden.zig");
}
