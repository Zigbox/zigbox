//! What demo-m2b asserts, as pure functions of what the guest printed, each with a unit test:
//! the six steps of the M2b spec read back from inside the container (text mode, as a person
//! runs them), the refusals' first lines, the doctor's host-settings line, and the scripted
//! agent's reading of the same steps through `--output json` alone: the refused value, the host
//! value and the fix command come from the diagnostic's fields, never from its prose.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");

const Streams = checks.Streams;
const Diagnostic = agent_json.Diagnostic;

pub const Error = error{
    ExitCodeWrong,
    /// The program printed something other than the step's lines.
    OutputWrong,
    /// A refusal that is not the code's one line, or that ran something.
    RefusalWrong,
    /// A number the step reads (a hard limit, a count of blocks) is missing or not a number.
    NumberWrong,
    /// The doctor's host-settings line is missing or shows another value.
    DoctorWrong,
    /// The cgroup view shows the host's tree, or not the scope's own files.
    ViewWrong,
} || agent_json.Error;

/// The lines of the probe under zbx's seccomp filter: the four policy calls are allowed, the
/// two page movers stay out and get the filter's answer.
pub const probe_lines = [_][]const u8{
    "mbind ok",
    "set_mempolicy ok",
    "set_mempolicy_home_node ok",
    "get_mempolicy ok",
    "move_pages EPERM",
    "migrate_pages EPERM",
};

/// The program exited 0 and its stdout is `expected`, line by line (blank lines skipped, ends
/// trimmed).
pub fn check_lines(streams: Streams, status: u8, expected: []const []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    try lines_are(streams.stdout, expected);
}

fn lines_are(text: []const u8, expected: []const []const u8) Error!void {
    assert(expected.len > 0);
    var lines = std.mem.splitScalar(u8, text, '\n');
    var index: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        if (index == expected.len) return error.OutputWrong;
        if (!std.mem.eql(u8, line, expected[index])) return error.OutputWrong;
        index += 1;
    }
    if (index != expected.len) return error.OutputWrong;
}

/// The user's hard limit, from the last line `ulimit -Hn` printed. `unlimited` is refused: the
/// demo asks for one more than the limit.
pub fn parse_hard_limit(output: []const u8) Error!u64 {
    const trimmed = std.mem.trimEnd(u8, output, " \r\n\t");
    const start = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |at| at + 1 else 0;
    const line = std.mem.trim(u8, trimmed[start..], " \r\t");
    const limit = std.fmt.parseInt(u64, line, 10) catch return error.NumberWrong;
    if (limit == 0 or limit == std.math.maxInt(u64)) return error.NumberWrong;
    return limit;
}

/// A refusal in text mode: exit 125, nothing on stdout, the first line of stderr is the code's
/// headline (`error[<code>]: ...`), and each of `needles` is somewhere in what follows.
pub fn check_text_refusal(
    streams: Streams,
    status: u8,
    code: []const u8,
    needles: []const []const u8,
) Error!void {
    assert(std.mem.startsWith(u8, code, "ZBX-E"));
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.RefusalWrong;
    const stderr = std.mem.trimStart(u8, streams.stderr, " \r\n\t");
    const end = std.mem.indexOfScalar(u8, stderr, '\n') orelse stderr.len;
    const first = stderr[0..end];
    if (!std.mem.startsWith(u8, first, "error[")) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, first["error[".len..], code)) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, first["error[".len + code.len ..], "]: ")) {
        return error.RefusalWrong;
    }
    for (needles) |needle| {
        if (std.mem.indexOf(u8, stderr, needle) == null) return error.RefusalWrong;
    }
    // Refused before start: no container was reported.
    if (std.mem.indexOf(u8, stderr, "zbx: killed") != null) return error.RefusalWrong;
}

/// `df -k /dev/shm` (busybox): the line of `/dev/shm` has `blocks` 1K-blocks in its second field.
pub fn check_df_blocks(streams: Streams, status: u8, blocks: u64) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.endsWith(u8, line, " /dev/shm")) continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse return error.OutputWrong;
        const text = fields.next() orelse return error.OutputWrong;
        const found = std.fmt.parseInt(u64, text, 10) catch return error.NumberWrong;
        if (found != blocks) return error.OutputWrong;
        return;
    }
    return error.OutputWrong;
}

/// The doctor's text report has a host-settings line, and on it `key` shows `value`, followed
/// by the next setting (`, `) or the end of the line.
pub fn check_doctor_value(output: []const u8, key: []const u8, value: []const u8) Error!void {
    assert(key.len > 0);
    assert(value.len > 0);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.indexOf(u8, line, " host-settings ") == null) continue;
        const at = std.mem.indexOf(u8, line, key) orelse return error.DoctorWrong;
        const rest = line[at + key.len ..];
        if (!std.mem.startsWith(u8, rest, " ")) return error.DoctorWrong;
        const shown = rest[1..];
        if (!std.mem.startsWith(u8, shown, value)) return error.DoctorWrong;
        const after = shown[value.len..];
        if (after.len != 0 and !std.mem.startsWith(u8, after, ",") and
            !std.mem.startsWith(u8, after, " ")) return error.DoctorWrong;
        return;
    }
    return error.DoctorWrong;
}

/// A command inside the container failed (any non-zero exit) and said `reason` on stderr.
pub fn check_failed_with(streams: Streams, status: u8, reason: []const u8) Error!void {
    if (status == 0 or status == 125) return error.ExitCodeWrong;
    if (std.mem.indexOf(u8, streams.stderr, reason) == null) return error.OutputWrong;
}

/// The cgroup view, read from inside by `view_probe` (main_m2b.zig): `/proc/self/cgroup` is
/// `0::/`, `memory.max` is the scope's `memory_max`, and no host entry (a slice, `init.scope`) is
/// in `/sys/fs/cgroup`. The probe prints `LS:` and each entry, then `MEMORY:`, then `CGROUP:`.
pub fn check_view(streams: Streams, status: u8, memory_max: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var saw_memory = false;
    var saw_cgroup = false;
    var entries: u32 = 0;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "LS:")) {
            const entry = line["LS:".len..];
            entries += 1;
            if (std.mem.endsWith(u8, entry, ".slice")) return error.ViewWrong;
            if (std.mem.eql(u8, entry, "init.scope")) return error.ViewWrong;
            if (std.mem.endsWith(u8, entry, ".service")) return error.ViewWrong;
        } else if (std.mem.startsWith(u8, line, "MEMORY:")) {
            if (!std.mem.eql(u8, line["MEMORY:".len..], memory_max)) return error.ViewWrong;
            saw_memory = true;
        } else if (std.mem.startsWith(u8, line, "CGROUP:")) {
            if (!std.mem.eql(u8, line["CGROUP:".len..], "0::/")) return error.ViewWrong;
            saw_cgroup = true;
        }
    }
    if (!saw_memory or !saw_cgroup) return error.ViewWrong;
    // The scope's own files: cgroup.procs, memory.max and the rest.
    if (entries < 4) return error.ViewWrong;
}

// ---- The scripted agent: --output json and zbx explain only -----------------------------

/// The first diagnostic of a refusal: exit 125, nothing on stdout, an error with `code`.
pub fn refusal(arena: Allocator, streams: Streams, status: u8, code: []const u8) Error!Diagnostic {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.DiagnosticWrong;
    const all = try agent_json.diagnostics(arena, streams.stderr);
    if (all.len == 0) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, all[0].code, code)) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, all[0].severity, "error")) return error.DiagnosticWrong;
    return all[0];
}

/// The summary `zbx explain` gives for the diagnostic's code. A code whose instance sets a
/// headline (E0319: "vm.max_map_count is 65530, needs >=262144") carries the instance's text in
/// its summary, and explain gives the catalog's; every other code carries the catalog's own. The
/// harness cannot import the catalog, so a drift in it fails the demo here.
pub fn explain_summary(diagnostic: Diagnostic) []const u8 {
    if (std.mem.eql(u8, diagnostic.code, "ZBX-E0319")) return summary_e0319;
    return diagnostic.summary;
}

const summary_e0319 = "a host setting is not what --require-host asks";

/// The string `key` of the diagnostic's context.
pub fn context_text(diagnostic: Diagnostic, key: []const u8) Error![]const u8 {
    if (diagnostic.context != .object) return error.DiagnosticWrong;
    const member = diagnostic.context.object.get(key) orelse return error.DiagnosticWrong;
    if (member != .string) return error.DiagnosticWrong;
    return member.string;
}

/// The context member `key` is `wanted`.
pub fn expect_context(diagnostic: Diagnostic, key: []const u8, wanted: []const u8) Error!void {
    const found = try context_text(diagnostic, key);
    if (!std.mem.eql(u8, found, wanted)) return error.DiagnosticWrong;
}

/// The command of fix `index`, which must have one.
pub fn fix_at(diagnostic: Diagnostic, index: usize) Error![]const u8 {
    if (index >= diagnostic.fixes.len) return error.FixWrong;
    return diagnostic.fixes[index].command orelse return error.FixWrong;
}

/// The command a person runs as root to apply a fix that needs it: the fix's command without
/// its `sudo `. The fix must say it needs root and must not be a template.
pub fn root_command(diagnostic: Diagnostic, index: usize) Error![]const u8 {
    const command = try fix_at(diagnostic, index);
    const fix = diagnostic.fixes[index];
    if (!fix.needs_root or fix.template) return error.FixWrong;
    if (!std.mem.startsWith(u8, command, "sudo ")) return error.FixWrong;
    return command["sudo ".len..];
}

/// The `container_exit` line of a run that exited 0, parsed whole, for the M2b members.
pub fn exit_object(arena: Allocator, streams: Streams, status: u8) Error!std.json.ObjectMap {
    try agent_json.check_exited(arena, streams, status, 0);
    var lines = std.mem.splitScalar(u8, streams.stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "{\"container_exit\":")) continue;
        const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
        const parsed = std.json.parseFromSliceLeaky(Value, arena, line, options) catch {
            return error.JsonWrong;
        };
        if (parsed != .object) return error.JsonWrong;
        const inner = parsed.object.get("container_exit") orelse return error.JsonWrong;
        if (inner != .object) return error.JsonWrong;
        return inner.object;
    }
    return error.ExitLineWrong;
}

fn integer_at(object: std.json.ObjectMap, key: []const u8) Error!i64 {
    const member = object.get(key) orelse return error.JsonWrong;
    if (member != .integer) return error.JsonWrong;
    return member.integer;
}

/// `container_exit.ulimits.<name>` is `{soft, hard}`.
pub fn check_exit_ulimit(
    exit: std.json.ObjectMap,
    name: []const u8,
    soft: i64,
    hard: i64,
) Error!void {
    const ulimits = exit.get("ulimits") orelse return error.JsonWrong;
    if (ulimits != .object) return error.JsonWrong;
    const one = ulimits.object.get(name) orelse return error.JsonWrong;
    if (one != .object) return error.JsonWrong;
    if (try integer_at(one.object, "soft") != soft) return error.JsonWrong;
    if (try integer_at(one.object, "hard") != hard) return error.JsonWrong;
}

/// `container_exit.shm_bytes` is `bytes`.
pub fn check_exit_shm(exit: std.json.ObjectMap, bytes: i64) Error!void {
    if (try integer_at(exit, "shm_bytes") != bytes) return error.JsonWrong;
}

/// `container_exit.sysctls` is the one `{key, value}`.
pub fn check_exit_sysctl(exit: std.json.ObjectMap, key: []const u8, value: []const u8) Error!void {
    const list = exit.get("sysctls") orelse return error.JsonWrong;
    if (list != .array or list.array.items.len != 1) return error.JsonWrong;
    const one = list.array.items[0];
    if (one != .object) return error.JsonWrong;
    const said_key = one.object.get("key") orelse return error.JsonWrong;
    const said_value = one.object.get("value") orelse return error.JsonWrong;
    if (said_key != .string or said_value != .string) return error.JsonWrong;
    if (!std.mem.eql(u8, said_key.string, key)) return error.JsonWrong;
    if (!std.mem.eql(u8, said_value.string, value)) return error.JsonWrong;
}

/// A run whose program failed: `container_exit` says `exited` with a code that is not 0, and
/// zbx's own status is that code.
pub fn check_program_failed(arena: Allocator, streams: Streams, status: u8) Error!void {
    if (status == 0 or status == 125) return error.ExitCodeWrong;
    const line = try agent_json.container_exit(arena, streams.stderr);
    if (!std.mem.eql(u8, line.reason, "exited")) return error.ExitLineWrong;
    if (line.code != status) return error.ExitLineWrong;
}

/// `zbx --output json doctor`: the `host_settings` object has `key` at `value`. The doctor's
/// status is not judged: a check that only warns in the VM must not fail the agent's read.
pub fn doctor_host_value(arena: Allocator, stdout: []const u8, key: []const u8) Error!i64 {
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const parsed = std.json.parseFromSliceLeaky(Value, arena, stdout, options) catch {
        return error.JsonWrong;
    };
    if (parsed != .object) return error.JsonWrong;
    const settings = parsed.object.get("host_settings") orelse return error.JsonWrong;
    if (settings != .object) return error.JsonWrong;
    return integer_at(settings.object, key);
}

const testing = std.testing;

fn streams_of(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

test "check_lines: the program's lines in order, and nothing else" {
    const both = [_][]const u8{ "4096", "8192" };
    try check_lines(streams_of("4096\n8192\n", ""), 0, &both);
    try check_lines(streams_of("\n4096\r\n8192", ""), 0, &both);
    try testing.expectError(error.OutputWrong, check_lines(streams_of("4096\n", ""), 0, &both));
    const extra = streams_of("4096\n8192\n1\n", "");
    try testing.expectError(error.OutputWrong, check_lines(extra, 0, &both));
    const swapped = streams_of("8192\n4096\n", "");
    try testing.expectError(error.OutputWrong, check_lines(swapped, 0, &both));
    const failed = streams_of("4096\n8192\n", "");
    try testing.expectError(error.ExitCodeWrong, check_lines(failed, 1, &both));
    try check_lines(streams_of(
        "mbind ok\nset_mempolicy ok\nset_mempolicy_home_node ok\nget_mempolicy ok\n" ++
            "move_pages EPERM\nmigrate_pages EPERM\n",
        "",
    ), 0, &probe_lines);
    const allowed_mover = streams_of(
        "mbind ok\nset_mempolicy ok\nset_mempolicy_home_node ok\nget_mempolicy ok\n" ++
            "move_pages ok\nmigrate_pages EPERM\n",
        "",
    );
    try testing.expectError(error.OutputWrong, check_lines(allowed_mover, 0, &probe_lines));
}

test "parse_hard_limit: the last line, a finite number" {
    try testing.expectEqual(@as(u64, 524288), try parse_hard_limit("524288\n"));
    try testing.expectEqual(@as(u64, 1048576), try parse_hard_limit("noise\n1048576\r\n"));
    try testing.expectError(error.NumberWrong, parse_hard_limit("unlimited\n"));
    try testing.expectError(error.NumberWrong, parse_hard_limit(""));
    try testing.expectError(error.NumberWrong, parse_hard_limit("0\n"));
}

const e0311_text =
    "error[ZBX-E0311]: --ulimit is above your own hard limit\n" ++
    "  cause  --ulimit nofile asks for a hard limit of 524289, above your own,\n" ++
    "         524288; a rootless run can't raise it\n" ++
    "  fix    raise it for logins (then log in again):    echo \"$(id -un) hard nofile " ++
    "524289\" | sudo tee -a /etc/security/limits.conf\n" ++
    "         or for the user manager, under [Service]:   sudo systemctl edit " ++
    "user@1000.service\n";

test "check_text_refusal: exit 125, the code's headline first, the needles after" {
    const needles = [_][]const u8{ "524288", "limits.conf", "user@1000.service" };
    try check_text_refusal(streams_of("", e0311_text), 125, "ZBX-E0311", &needles);
    const leading = streams_of("", "\n" ++ e0311_text);
    try check_text_refusal(leading, 125, "ZBX-E0311", &needles);
    const other_code = check_text_refusal(streams_of("", e0311_text), 125, "ZBX-E0310", &needles);
    try testing.expectError(error.RefusalWrong, other_code);
    const ran = check_text_refusal(streams_of("x\n", e0311_text), 125, "ZBX-E0311", &needles);
    try testing.expectError(error.RefusalWrong, ran);
    const status = check_text_refusal(streams_of("", e0311_text), 1, "ZBX-E0311", &needles);
    try testing.expectError(error.ExitCodeWrong, status);
    const missing = [_][]const u8{"LimitNPROC"};
    const lacks = check_text_refusal(streams_of("", e0311_text), 125, "ZBX-E0311", &missing);
    try testing.expectError(error.RefusalWrong, lacks);
    const warned_first = streams_of("", "zbx: warning: x\n" ++ e0311_text);
    const warning = check_text_refusal(warned_first, 125, "ZBX-E0311", &needles);
    try testing.expectError(error.RefusalWrong, warning);
}

test "check_df_blocks: the /dev/shm line's 1K-blocks" {
    const df = "Filesystem           1K-blocks      Used Available Use% Mounted on\n" ++
        "shm                     262144         0    262144   0% /dev/shm\n";
    try check_df_blocks(streams_of(df, ""), 0, 262144);
    try testing.expectError(error.OutputWrong, check_df_blocks(streams_of(df, ""), 0, 65536));
    try testing.expectError(error.ExitCodeWrong, check_df_blocks(streams_of(df, ""), 1, 262144));
    const other = "tmpfs 262144 0 262144 0% /tmp\n";
    try testing.expectError(error.OutputWrong, check_df_blocks(streams_of(other, ""), 0, 262144));
}

test "check_doctor_value: the host-settings line shows the value" {
    const line = "ok   kernel         6.8.0\n" ++
        "ok   host-settings  vm.max_map_count 65530, fs.aio-max-nr 65536, " ++
        "vm.overcommit_memory 0, transparent_hugepage madvise\n";
    try check_doctor_value(line, "vm.max_map_count", "65530");
    try check_doctor_value(line, "transparent_hugepage", "madvise");
    const prefix = check_doctor_value(line, "vm.max_map_count", "6553");
    try testing.expectError(error.DoctorWrong, prefix);
    const other = check_doctor_value(line, "vm.max_map_count", "262144");
    try testing.expectError(error.DoctorWrong, other);
    const none = check_doctor_value("ok   kernel 6.8.0\n", "vm.max_map_count", "65530");
    try testing.expectError(error.DoctorWrong, none);
}

test "check_failed_with: a non-zero exit with the reason on stderr" {
    const said = "sh: can't create /sys/fs/cgroup/memory.max: Read-only file system\n";
    try check_failed_with(streams_of("", said), 1, "Read-only file system");
    const wrote = check_failed_with(streams_of("", ""), 0, "Read-only file system");
    try testing.expectError(error.ExitCodeWrong, wrote);
    const refused = check_failed_with(streams_of("", said), 125, "Read-only file system");
    try testing.expectError(error.ExitCodeWrong, refused);
    const other = check_failed_with(streams_of("", "Permission denied\n"), 1, "Read-only");
    try testing.expectError(error.OutputWrong, other);
}

test "check_view: the scope's own files, no host entry" {
    const own = "LS:cgroup.controllers\nLS:cgroup.procs\nLS:cpu.max\nLS:memory.max\n" ++
        "MEMORY:268435456\nCGROUP:0::/\n";
    try check_view(streams_of(own, ""), 0, "268435456");
    try testing.expectError(error.ViewWrong, check_view(streams_of(own, ""), 0, "max"));
    const host = "LS:cgroup.procs\nLS:init.scope\nLS:memory.max\nLS:user.slice\n" ++
        "MEMORY:268435456\nCGROUP:0::/\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(host, ""), 0, "268435456"));
    const path = "LS:a\nLS:b\nLS:c\nLS:d\nMEMORY:268435456\n" ++
        "CGROUP:0::/user.slice/user-1000.slice\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(path, ""), 0, "268435456"));
    const empty = "MEMORY:268435456\nCGROUP:0::/\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(empty, ""), 0, "268435456"));
}

const e0319_json = "{\"code\":\"ZBX-E0319\",\"severity\":\"error\",\"blame\":\"environment\"," ++
    "\"summary\":\"vm.max_map_count is 65530, needs >=262144\",\"causes\":[],\"while\":[]," ++
    "\"context\":{\"key\":\"vm.max_map_count\",\"host\":\"65530\",\"needed\":\">=262144\"}," ++
    "\"fixes\":[{\"sentence\":\"set it on the host:\",\"command\":\"sudo sysctl -w " ++
    "vm.max_map_count=262144\",\"needs_root\":true},{\"sentence\":\"check every setting:\"," ++
    "\"command\":\"zbx doctor\"}]," ++
    "\"docs\":\"https://zigbox.github.io/zigbox/errors/E0319.html\"}\n";

test "the agent reads a refusal's fields: the host value, the needed value, the fix" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try refusal(arena, streams_of("", e0319_json), 125, "ZBX-E0319");
    try expect_context(found, "host", "65530");
    try expect_context(found, "needed", ">=262144");
    try testing.expectError(error.DiagnosticWrong, expect_context(found, "host", "1048576"));
    try testing.expectError(error.DiagnosticWrong, context_text(found, "asked"));
    try testing.expectEqualStrings("sysctl -w vm.max_map_count=262144", try root_command(found, 0));
    try testing.expectError(error.FixWrong, root_command(found, 1));
    try testing.expectEqualStrings("zbx doctor", try fix_at(found, 1));
    try testing.expectError(error.FixWrong, fix_at(found, 2));
    const other = refusal(arena, streams_of("", e0319_json), 125, "ZBX-E0316");
    try testing.expectError(error.DiagnosticWrong, other);
    const status = refusal(arena, streams_of("", e0319_json), 0, "ZBX-E0319");
    try testing.expectError(error.ExitCodeWrong, status);
}

test "explain_summary: the catalog's summary for a headline code, the diagnostic's otherwise" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try refusal(arena, streams_of("", e0319_json), 125, "ZBX-E0319");
    try testing.expectEqualStrings(summary_e0319, explain_summary(found));
    var other = found;
    other.code = "ZBX-E0316";
    try testing.expectEqualStrings(found.summary, explain_summary(other));
}

test "the agent reads the knobs back from container_exit" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\"," ++
        "\"published\":[],\"shm_bytes\":268435456,\"ulimits\":{\"nofile\":{\"soft\":4096," ++
        "\"hard\":8192}},\"sysctls\":[{\"key\":\"net.core.somaxconn\",\"value\":\"8192\"}]}}\n";
    const exit = try exit_object(arena, streams_of("", line), 0);
    try check_exit_ulimit(exit, "nofile", 4096, 8192);
    try testing.expectError(error.JsonWrong, check_exit_ulimit(exit, "nofile", 4096, 4096));
    try testing.expectError(error.JsonWrong, check_exit_ulimit(exit, "nproc", 1, 1));
    try check_exit_shm(exit, 268435456);
    try testing.expectError(error.JsonWrong, check_exit_shm(exit, 67108864));
    try check_exit_sysctl(exit, "net.core.somaxconn", "8192");
    const wrong = check_exit_sysctl(exit, "net.core.somaxconn", "4096");
    try testing.expectError(error.JsonWrong, wrong);
    const failed = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1}}\n";
    try check_program_failed(arena, streams_of("", failed), 1);
    try testing.expectError(error.ExitCodeWrong, exit_object(arena, streams_of("", failed), 1));
    const ok = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0}}\n";
    const quiet = streams_of("", ok);
    try testing.expectError(error.ExitCodeWrong, check_program_failed(arena, quiet, 0));
}

test "doctor_host_value: the host_settings object of zbx.doctor/1" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const doc = "{\"schema\":\"zbx.doctor/1\",\"checks\":[],\"host_settings\":{" ++
        "\"vm.max_map_count\":262144,\"fs.aio-max-nr\":65536,\"vm.overcommit_memory\":0," ++
        "\"transparent_hugepage\":\"madvise\"}}\n";
    const value = try doctor_host_value(arena, doc, "vm.max_map_count");
    try testing.expectEqual(@as(i64, 262144), value);
    const thp = doctor_host_value(arena, doc, "transparent_hugepage");
    try testing.expectError(error.JsonWrong, thp);
    try testing.expectError(error.JsonWrong, doctor_host_value(arena, "not json", "x"));
}
