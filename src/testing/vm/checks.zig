//! The demo's assertions as pure functions over bytes and text, so each can be unit-tested,
//! including with deliberately wrong input: a check that cannot fail proves nothing.

const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");

pub const CheckError = error{
    NotElf,
    NotStatic,
    WrongMachine,
    TooBig,
    Truncated,
    ReportMalformed,
    CheckNotOk,
    CheckNotFailed,
    /// The FAIL line has no `[ZBX-E01xx]` code, or the wrong one.
    CodeMissing,
    /// The FAIL line still carries the old `— fix:` text: the fix belongs in the stderr block.
    FixOnStdout,
    /// No `error[ZBX-E01xx]: <summary>` block on stderr for the failing check.
    BlockMissing,
    /// The block has no `cause` line.
    CauseMissing,
    FixMissing,
    /// The number of FAIL lines on stdout and of blocks on stderr differ.
    BlocksMismatch,
    ExitCodeWrong,
    /// The console output has no (or more than one) stderr marker.
    StreamsNotSplit,
    StderrNotEmpty,
    StdoutNotEmpty,
};

// ---- ELF -----------------------------------------------------------------------------------

pub const Machine = enum(u16) { x86_64 = 62, aarch64 = 183 };

const pt_dynamic: u32 = 2;
const pt_interp: u32 = 3;
const dt_needed: u64 = 1;
const dt_null: u64 = 0;

fn read_u16(bytes: []const u8, offset: usize) CheckError!u16 {
    if (offset + 2 > bytes.len) return error.Truncated;
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn read_u32(bytes: []const u8, offset: usize) CheckError!u32 {
    if (offset + 4 > bytes.len) return error.Truncated;
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn read_u64(bytes: []const u8, offset: usize) CheckError!u64 {
    if (offset + 8 > bytes.len) return error.Truncated;
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

/// Checks that `bytes` is a little-endian 64-bit ELF executable for `machine`, under the size
/// limit, with no interpreter (PT_INTERP) and no needed shared library (DT_NEEDED): the
/// definition of "static, no libc dependency" the milestone asks for.
pub fn check_static_elf(bytes: []const u8, machine: Machine) CheckError!void {
    if (bytes.len < 64) return error.NotElf;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.NotElf;
    if (bytes[4] != 2 or bytes[5] != 1) return error.NotElf; // 64-bit, little-endian.
    if (bytes.len >= limits.binary_bytes_max) return error.TooBig;
    if (try read_u16(bytes, 18) != @backingInt(machine)) return error.WrongMachine;

    const header_offset = try read_u64(bytes, 32);
    const header_size = try read_u16(bytes, 54);
    const header_count = try read_u16(bytes, 56);
    if (header_count > limits.program_headers_max) return error.NotElf;
    if (header_size < 56) return error.NotElf;
    for (0..header_count) |index| {
        const at = header_offset + index * header_size;
        if (at > bytes.len) return error.Truncated;
        const kind = try read_u32(bytes, @intCast(at));
        if (kind == pt_interp) return error.NotStatic;
        if (kind == pt_dynamic) try check_no_needed(bytes, @intCast(at));
    }
}

fn check_no_needed(bytes: []const u8, header_at: usize) CheckError!void {
    const offset = try read_u64(bytes, header_at + 8);
    const size = try read_u64(bytes, header_at + 32);
    const entries = @min(size / 16, limits.dynamic_entries_max);
    for (0..entries) |index| {
        const at = offset + index * 16;
        if (at + 16 > bytes.len) return error.Truncated;
        const tag = try read_u64(bytes, @intCast(at));
        if (tag == dt_null) return;
        if (tag == dt_needed) return error.NotStatic;
    }
}

// ---- The streams ---------------------------------------------------------------------------
//
// The guest's serial console merges stdout and stderr, so the harness cannot tell them apart by
// order alone. The command it types redirects the program's stderr to a file in the guest and
// prints that file after a marker line, once the program has ended; `split_streams` cuts the
// console text at the marker. The program's own exit status is kept (`exit $ZBX_S`).

/// The marker line, as the harness reads it. In the typed command it is written in two quoted
/// halves, so that an echo of the command line itself can never be mistaken for it.
pub const stderr_marker = "ZBX-STDERR-FOLLOWS";
const stderr_file = "/tmp/zbx-stderr";

/// The command that runs `command` with its stderr kept apart (see above).
pub fn split_command(buffer: []u8, command: []const u8) std.fmt.BufPrintError![]const u8 {
    assert(command.len > 0);
    assert(std.mem.indexOfScalar(u8, command, '\n') == null);
    const format = "{s} 2>" ++ stderr_file ++ "; ZBX_S=$?; echo ZBX-STDERR\"\"-FOLLOWS; " ++
        "cat " ++ stderr_file ++ "; exit $ZBX_S";
    return std.fmt.bufPrint(buffer, format, .{command});
}

pub const Streams = struct {
    stdout: []const u8,
    stderr: []const u8,
};

/// Cuts the console output of a `split_command` at its marker line. Trailing newlines are the
/// session's to trim, so the stderr part may or may not end in one. The marker may follow spaces
/// on its line: when readline redraws the echo of a long typed command, the padding it writes
/// before a carriage return is left in front of the next output once the session drops the `\r`
/// (seen in CI under KVM, where the output can race the redraw).
pub fn split_streams(combined: []const u8) CheckError!Streams {
    var found: ?usize = null;
    var found_line: usize = 0;
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, combined, offset, stderr_marker)) |at| : (offset = at + 1) {
        var line: usize = at;
        while (line > 0 and combined[line - 1] == ' ') line -= 1;
        const line_start = line == 0 or combined[line - 1] == '\n';
        const after = at + stderr_marker.len;
        const line_end = after == combined.len or combined[after] == '\n';
        if (!line_start or !line_end) continue;
        if (found != null) return error.StreamsNotSplit; // Twice: the output is not ours.
        found = at;
        found_line = line;
    }
    const at = found orelse return error.StreamsNotSplit;
    assert(found_line <= at);
    const rest = combined[@min(at + stderr_marker.len + 1, combined.len)..];
    return .{ .stdout = combined[0..found_line], .stderr = rest };
}

// ---- The doctor report ---------------------------------------------------------------------

pub const check_names = [_][]const u8{
    "kernel", "userns", "cgroup", "overlay", "subid", "seccomp",
};

/// One parsed line of a doctor report (stdout).
pub const Line = struct {
    ok: bool,
    name: []const u8,
    text: []const u8,
};

/// Parses `ok   <name>  <detail>` / `FAIL <name>  <detail>  [ZBX-E01xx]` lines into `out`,
/// requiring exactly the six checks in order. Anything else is `ReportMalformed`.
pub fn parse_report(output: []const u8, out: *[check_names.len]Line) CheckError!void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    var count: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (count == check_names.len) return error.ReportMalformed;
        const ok = std.mem.startsWith(u8, line, "ok   ");
        const warn = std.mem.startsWith(u8, line, "warn ");
        const fail = std.mem.startsWith(u8, line, "FAIL ");
        if (!ok and !warn and !fail) return error.ReportMalformed;
        const rest = line[5..];
        const name = check_names[count];
        if (!std.mem.startsWith(u8, rest, name)) return error.ReportMalformed;
        if (!std.mem.startsWith(u8, rest[name.len..], "  ")) return error.ReportMalformed;
        out[count] = .{ .ok = ok or warn, .name = name, .text = line };
        count += 1;
    }
    if (count != check_names.len) return error.ReportMalformed;
}

/// Demo step 1: every check is `ok`, nothing is written to stderr, and the exit code is 0.
pub fn check_all_ok(streams: Streams, exit_code: u8) CheckError!void {
    var report: [check_names.len]Line = undefined;
    try parse_report(streams.stdout, &report);
    for (report) |line| {
        if (!std.mem.startsWith(u8, line.text, "ok   ")) return error.CheckNotOk;
    }
    if (std.mem.trim(u8, streams.stderr, " \r\n").len != 0) return error.StderrNotEmpty;
    if (exit_code != 0) return error.ExitCodeWrong;
}

/// What a failing check must look like: the line on stdout, the block on stderr.
pub const Failure = struct {
    /// The check's name on its line: "userns".
    name: []const u8,
    /// The code in brackets at the end of the line and in the block's header: "ZBX-E0101".
    code: []const u8,
    /// The block header's summary: "can't create a user namespace".
    summary: []const u8,
    /// Text the block's fix lines must contain, to tie the fix to the cause (the sysctl).
    fix_contains: []const u8,
};

/// Demo step 2: the named check FAILs with its code on the stdout line (and no fix text there),
/// stderr holds its `error[<code>]: <summary>` block with a cause and a fix that contains
/// `fix_contains`, there is one block per FAIL line, and the exit code is 2 (the environment's,
/// DIAGNOSTICS.md).
pub fn check_fails_with_fix(streams: Streams, exit_code: u8, failure: Failure) CheckError!void {
    var report: [check_names.len]Line = undefined;
    try parse_report(streams.stdout, &report);
    var found = false;
    var fails: usize = 0;
    for (report) |line| {
        if (std.mem.startsWith(u8, line.text, "FAIL ")) fails += 1;
        if (!std.mem.eql(u8, line.name, failure.name)) continue;
        if (!std.mem.startsWith(u8, line.text, "FAIL ")) return error.CheckNotFailed;
        if (std.mem.indexOf(u8, line.text, " \u{2014} fix:") != null) return error.FixOnStdout;
        var suffix_buffer: [32]u8 = undefined;
        const suffix = std.fmt.bufPrint(&suffix_buffer, "  [{s}]", .{failure.code}) catch
            return error.CodeMissing;
        if (!std.mem.endsWith(u8, line.text, suffix)) return error.CodeMissing;
        found = true;
    }
    if (!found) return error.ReportMalformed;
    if (count_blocks(streams.stderr) != fails) return error.BlocksMismatch;
    try check_block(streams.stderr, failure);
    if (exit_code != 2) return error.ExitCodeWrong;
}

/// The number of doctor diagnostic blocks (headers `error[ZBX-E01xx]`) in `stderr`.
fn count_blocks(stderr: []const u8) usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "error[ZBX-E01")) count += 1;
    }
    return count;
}

/// Finds the failure's block in `stderr` and checks its cause and fix lines.
fn check_block(stderr: []const u8, failure: Failure) CheckError!void {
    var header_buffer: [128]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buffer, "error[{s}]: {s}", .{
        failure.code, failure.summary,
    }) catch return error.BlockMissing;
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |line| {
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, line, "\r"), header)) continue;
        var has_cause = false;
        var in_fix = false;
        var fix_ok = false;
        while (lines.next()) |body| {
            if (body.len == 0 or !std.mem.startsWith(u8, body, "  ")) break; // The block ended.
            if (std.mem.startsWith(u8, body, "  cause ")) has_cause = true;
            const labelled = body.len > 2 and body[2] != ' ';
            if (labelled) in_fix = std.mem.startsWith(u8, body, "  fix ");
            if (in_fix and std.mem.indexOf(u8, body, failure.fix_contains) != null) fix_ok = true;
        }
        if (!has_cause) return error.CauseMissing;
        if (!fix_ok) return error.FixMissing;
        return;
    }
    return error.BlockMissing;
}

/// Demo step 4: a mistyped command is a usage error: `error[ZBX-E0001]` on stderr, nothing on
/// stdout, exit code 1 (the user's).
pub fn check_unknown_command(streams: Streams, exit_code: u8) CheckError!void {
    const header = "error[ZBX-E0001]: unknown command";
    var lines = std.mem.splitScalar(u8, streams.stderr, '\n');
    const first = lines.next() orelse return error.BlockMissing;
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, first, "\r"), header)) return error.BlockMissing;
    if (std.mem.trim(u8, streams.stdout, " \r\n").len != 0) return error.StdoutNotEmpty;
    if (exit_code != 1) return error.ExitCodeWrong;
}

/// `file` must describe a statically linked ELF executable.
pub fn check_file_says_static(file_output: []const u8) CheckError!void {
    if (std.mem.indexOf(u8, file_output, "ELF 64-bit") == null) return error.NotElf;
    if (std.mem.indexOf(u8, file_output, "statically linked") == null) return error.NotStatic;
    if (std.mem.indexOf(u8, file_output, "dynamically linked") != null) return error.NotStatic;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

const good_report =
    "ok   kernel  6.8.0-45-generic x86_64 (minimum 5.15)\n" ++
    "ok   userns  user.max_user_namespaces=63488, unshare(CLONE_NEWUSER) works\n" ++
    "ok   cgroup  cgroup v2, user@1000.service delegated to uid 1000: cpu memory pids\n" ++
    "ok   overlay  overlayfs mounts inside a user and mount namespace\n" ++
    "ok   subid  demo (uid 1000): subuid 65536 ids, subgid 65536 ids\n" ++
    "ok   seccomp  seccomp is supported (current mode: disabled for this process)\n";

/// The doctor with user.max_user_namespaces=0: userns and (needing a namespace) overlay fail.
const userns_failed_stdout =
    "ok   kernel  6.8.0-45-generic x86_64 (minimum 5.15)\n" ++
    "FAIL userns  user.max_user_namespaces is 0, so no user namespace can be created  " ++
    "[ZBX-E0101]\n" ++
    "ok   cgroup  c\nFAIL overlay  could not enter the user and mount namespaces  [ZBX-E0104]\n" ++
    "ok   subid  s\nok   seccomp  s\n";

const userns_failed_stderr =
    "error[ZBX-E0101]: can't create a user namespace\n" ++
    "  cause  the sysctl user.max_user_namespaces = 0 caps the user namespaces\n" ++
    "         this system allows at none, for every user\n" ++
    "  fix    allow user namespaces:   sudo sysctl -w user.max_user_namespaces=15000\n" ++
    "  more   zbx explain E0101 \u{b7} rerun with --verbose for the full cause chain\n" ++
    "  docs   https://zigbox.github.io/zigbox/errors/E0101.html\n" ++
    "\n" ++
    "error[ZBX-E0104]: can't mount overlayfs in a user namespace\n" ++
    "  cause  the overlay probe needs a user namespace first\n" ++
    "  fix    fix the userns check first (ZBX-E0101)\n" ++
    "  more   zbx explain E0104\n" ++
    "  docs   https://zigbox.github.io/zigbox/errors/E0104.html\n";

const userns_failure: Failure = .{
    .name = "userns",
    .code = "ZBX-E0101",
    .summary = "can't create a user namespace",
    .fix_contains = "user.max_user_namespaces",
};

const failed: Streams = .{ .stdout = userns_failed_stdout, .stderr = userns_failed_stderr };

test "streams: the console output is cut at the marker, and only at a marker line" {
    // Goal: stdout and stderr come apart exactly, even when one is empty, and text that merely
    // contains the marker (an echo of the typed command, or output of another program) is not
    // taken for it.
    const both = split_streams("out one\nout two\n" ++ stderr_marker ++ "\nerr one\nerr two");
    try testing.expectEqualStrings("out one\nout two\n", (try both).stdout);
    try testing.expectEqualStrings("err one\nerr two", (try both).stderr);
    const no_stderr = try split_streams("out\n" ++ stderr_marker);
    try testing.expectEqualStrings("out\n", no_stderr.stdout);
    try testing.expectEqualStrings("", no_stderr.stderr);
    const no_stdout = try split_streams(stderr_marker ++ "\nerr\n");
    try testing.expectEqualStrings("", no_stdout.stdout);
    try testing.expectEqualStrings("err\n", no_stdout.stderr);

    // The padding a readline redraw leaves in front of the marker (CI run 40378288342).
    const padding: [52]u8 = @splat(' ');
    const padded = try split_streams("out\n" ++ padding ++ stderr_marker ++ "\nerr\n");
    try testing.expectEqualStrings("out\n", padded.stdout);
    try testing.expectEqualStrings("err\n", padded.stderr);

    try testing.expectError(error.StreamsNotSplit, split_streams("no marker at all"));
    try testing.expectError(error.StreamsNotSplit, split_streams("echo " ++ stderr_marker ++ "\n"));
    try testing.expectError(
        error.StreamsNotSplit,
        split_streams("a\n" ++ stderr_marker ++ "\nb\n" ++ stderr_marker ++ "\n"),
    );
    try testing.expectError(error.StreamsNotSplit, split_streams(stderr_marker ++ "x\n"));
}

test "split_command keeps the exit status and never contains the marker whole" {
    // Goal: the typed command prints the marker only when run (the quotes split it), and the
    // program's own status is the command's status.
    var buffer: [256]u8 = undefined;
    const typed = try split_command(&buffer, "zbx doctor");
    try testing.expect(std.mem.startsWith(u8, typed, "zbx doctor 2>/tmp/zbx-stderr;"));
    try testing.expect(std.mem.endsWith(u8, typed, "exit $ZBX_S"));
    try testing.expect(std.mem.indexOf(u8, typed, stderr_marker) == null);
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, split_command(&tiny, "zbx doctor"));
}

test "step 1: a report with every check ok, an empty stderr and exit 0 passes" {
    // Goal: the positive case, then each way it can be wrong must be refused.
    const ok: Streams = .{ .stdout = good_report, .stderr = "" };
    try check_all_ok(ok, 0);
    try check_all_ok(.{ .stdout = good_report, .stderr = "\n" }, 0);
    try testing.expectError(error.ExitCodeWrong, check_all_ok(ok, 1));
    try testing.expectError(error.CheckNotOk, check_all_ok(failed, 0));
    const noisy: Streams = .{ .stdout = good_report, .stderr = "error[ZBX-E0101]: x\n" };
    try testing.expectError(error.StderrNotEmpty, check_all_ok(noisy, 0));
    const nothing: Streams = .{ .stdout = "", .stderr = "" };
    try testing.expectError(error.ReportMalformed, check_all_ok(nothing, 0));
    const doubled: Streams = .{ .stdout = good_report ++ good_report, .stderr = "" };
    try testing.expectError(error.ReportMalformed, check_all_ok(doubled, 0));
    const warned = "warn kernel  x\n" ++ good_report[good_report.len - 0 ..];
    const with_warn: Streams = .{ .stdout = warned, .stderr = "" };
    try testing.expectError(error.ReportMalformed, check_all_ok(with_warn, 0));
}

test "step 2: the FAIL line, the stderr block, the fix and the exit code must all be right" {
    // Goal: a report that says ok for the check (the bug the demo exists to catch) fails the
    // demo, as does each part of the new contract going missing or wrong: the code on the line,
    // the block, its cause and fix, one block per FAIL line, and exit code 2.
    try check_fails_with_fix(failed, 2, userns_failure);
    const ok: Streams = .{ .stdout = good_report, .stderr = "" };
    try testing.expectError(error.CheckNotFailed, check_fails_with_fix(ok, 2, userns_failure));
    try testing.expectError(error.ExitCodeWrong, check_fails_with_fix(failed, 0, userns_failure));
    // The old doctor exit code (1) is the user's now, and must not satisfy the demo.
    try testing.expectError(error.ExitCodeWrong, check_fails_with_fix(failed, 1, userns_failure));

    var other = userns_failure;
    other.fix_contains = "apparmor";
    try testing.expectError(error.FixMissing, check_fails_with_fix(failed, 2, other));
    other = userns_failure;
    other.name = "cgroup";
    try testing.expectError(error.CheckNotFailed, check_fails_with_fix(failed, 2, other));
    other = userns_failure;
    other.code = "ZBX-E0102";
    try testing.expectError(error.CodeMissing, check_fails_with_fix(failed, 2, other));
    other = userns_failure;
    other.summary = "something else";
    try testing.expectError(error.BlockMissing, check_fails_with_fix(failed, 2, other));
}

test "step 2: each way the new output can regress is refused" {
    // Goal: the old line format, a missing block, a block with no cause or no fix, a fix that
    // is not under the `fix` label, and blocks that do not match the FAIL lines.
    const old_line = "FAIL userns  broken \u{2014} fix: sudo sysctl -w a.b=1  [ZBX-E0101]\n";
    const old_format = "ok   kernel  k\n" ++ old_line ++
        "ok   cgroup  c\nok   overlay  o\nok   subid  s\nok   seccomp  s\n";
    const old: Streams = .{ .stdout = old_format, .stderr = userns_failed_stderr };
    try testing.expectError(error.FixOnStdout, check_fails_with_fix(old, 2, userns_failure));

    const no_code = "ok   kernel  k\nFAIL userns  broken\nok   cgroup  c\n" ++
        "ok   overlay  o\nok   subid  s\nok   seccomp  s\n";
    const bare: Streams = .{ .stdout = no_code, .stderr = userns_failed_stderr };
    try testing.expectError(error.CodeMissing, check_fails_with_fix(bare, 2, userns_failure));

    const empty: Streams = .{ .stdout = userns_failed_stdout, .stderr = "" };
    try testing.expectError(error.BlocksMismatch, check_fails_with_fix(empty, 2, userns_failure));
    const split_at = std.mem.indexOf(u8, userns_failed_stderr, "\n\n").?;
    const one_block = userns_failed_stderr[0 .. split_at + 1];
    const short: Streams = .{ .stdout = userns_failed_stdout, .stderr = one_block };
    try testing.expectError(error.BlocksMismatch, check_fails_with_fix(short, 2, userns_failure));

    const without_cause = "error[ZBX-E0101]: can't create a user namespace\n" ++
        "  fix    allow user namespaces:   sudo sysctl -w user.max_user_namespaces=15000\n" ++
        "\nerror[ZBX-E0104]: can't mount overlayfs in a user namespace\n  cause  x\n  fix    y\n";
    const causeless: Streams = .{ .stdout = userns_failed_stdout, .stderr = without_cause };
    try testing.expectError(error.CauseMissing, check_fails_with_fix(causeless, 2, userns_failure));

    // The sysctl appears in the cause but not under the fix label: not a fix.
    const wrong_place = "error[ZBX-E0101]: can't create a user namespace\n" ++
        "  cause  user.max_user_namespaces is 0\n  fix    do something\n" ++
        "  more   user.max_user_namespaces\n" ++
        "\nerror[ZBX-E0104]: can't mount overlayfs in a user namespace\n  cause  x\n  fix    y\n";
    const misplaced: Streams = .{ .stdout = userns_failed_stdout, .stderr = wrong_place };
    try testing.expectError(error.FixMissing, check_fails_with_fix(misplaced, 2, userns_failure));
}

test "step 4: a mistyped command is E0001 on stderr, nothing on stdout, exit 1" {
    // Goal: the usage-error contract (exit 1 is the user's), and the refusals of each part.
    const block = "error[ZBX-E0001]: unknown command\n  cause  'frobnicate' is not a zbx command\n";
    const good: Streams = .{ .stdout = "", .stderr = block };
    try check_unknown_command(good, 1);
    try testing.expectError(error.ExitCodeWrong, check_unknown_command(good, 2));
    const silent: Streams = .{ .stdout = "", .stderr = "" };
    try testing.expectError(error.BlockMissing, check_unknown_command(silent, 1));
    const other: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0002]: no command given\n" };
    try testing.expectError(error.BlockMissing, check_unknown_command(other, 1));
    const printed: Streams = .{ .stdout = "usage\n", .stderr = block };
    try testing.expectError(error.StdoutNotEmpty, check_unknown_command(printed, 1));
}

/// A minimal 64-bit little-endian ELF with one program header of `kind`.
fn elf_with(buffer: *[512]u8, machine: u16, kind: u32) []const u8 {
    @memset(buffer, 0);
    @memcpy(buffer[0..4], "\x7fELF");
    buffer[4] = 2;
    buffer[5] = 1;
    std.mem.writeInt(u16, buffer[18..20], machine, .little);
    std.mem.writeInt(u64, buffer[32..40], 64, .little);
    std.mem.writeInt(u16, buffer[54..56], 56, .little);
    std.mem.writeInt(u16, buffer[56..58], 1, .little);
    std.mem.writeInt(u32, buffer[64..68], kind, .little);
    return buffer[0..512];
}

test "ELF: a plain static executable passes; interpreter, needed libs, wrong machine fail" {
    // Goal: PT_LOAD-only passes; PT_INTERP (a dynamic loader) and a DT_NEEDED entry both mean
    // dynamically linked; the machine must match; garbage and truncation are errors.
    var buffer: [512]u8 = undefined;
    try check_static_elf(elf_with(&buffer, 62, 1), .x86_64);
    const plain = elf_with(&buffer, 62, 1);
    try testing.expectError(error.WrongMachine, check_static_elf(plain, .aarch64));
    const interpreted = elf_with(&buffer, 62, pt_interp);
    try testing.expectError(error.NotStatic, check_static_elf(interpreted, .x86_64));

    // A PT_DYNAMIC segment at offset 128 with a DT_NEEDED entry, then with only DT_NULL.
    const with_dynamic = elf_with(&buffer, 183, pt_dynamic);
    std.mem.writeInt(u64, buffer[72..80], 128, .little); // p_offset
    std.mem.writeInt(u64, buffer[96..104], 32, .little); // p_filesz
    std.mem.writeInt(u64, buffer[128..136], dt_needed, .little);
    try testing.expectError(error.NotStatic, check_static_elf(with_dynamic, .aarch64));
    std.mem.writeInt(u64, buffer[128..136], dt_null, .little);
    try check_static_elf(with_dynamic, .aarch64);

    const text = "not an elf at all, just text, padded out to a length that is long enough!!";
    try testing.expectError(error.NotElf, check_static_elf(text, .x86_64));
    try testing.expectError(error.NotElf, check_static_elf("short", .x86_64));
    try testing.expectError(error.Truncated, check_static_elf(buffer[0..100], .aarch64));
}

test "ELF: a binary at or over 2 MiB is too big" {
    // Goal: the boundary of the milestone's size limit, exact.
    var header: [512]u8 = undefined;
    _ = elf_with(&header, 62, 1);
    const big = try testing.allocator.alloc(u8, limits.binary_bytes_max);
    defer testing.allocator.free(big);
    @memcpy(big[0..512], &header);
    @memset(big[512..], 0);
    try testing.expectError(error.TooBig, check_static_elf(big, .x86_64));
    try check_static_elf(big[0 .. big.len - 1], .x86_64);
}

test "file output: only an ELF that is statically linked passes" {
    const static_line = "/home/demo/zbx: ELF 64-bit LSB executable, x86-64, statically linked";
    try check_file_says_static(static_line);
    try testing.expectError(
        error.NotStatic,
        check_file_says_static("zbx: ELF 64-bit LSB pie executable, dynamically linked"),
    );
    try testing.expectError(error.NotElf, check_file_says_static("zbx: ASCII text"));
}
