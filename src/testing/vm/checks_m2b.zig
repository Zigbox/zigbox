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
const recorded = @import("recorded_m2b.zig");

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
    /// `ps` or a run record does not show a container the way the upgrade step left it.
    RecordWrong,
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

/// The command of fix `index`, which must say it needs root and must not be a template.
fn root_fix(diagnostic: Diagnostic, index: usize) Error![]const u8 {
    const command = try fix_at(diagnostic, index);
    const fix = diagnostic.fixes[index];
    if (!fix.needs_root or fix.template) return error.FixWrong;
    return command;
}

/// The command a person runs as root to apply a fix that needs it: the fix's command without
/// its `sudo `. The fix must say it needs root and must not be a template.
pub fn root_command(diagnostic: Diagnostic, index: usize) Error![]const u8 {
    const command = try root_fix(diagnostic, index);
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

/// `doctor_host_value` is `wanted`; a read that fails is that failure, never a wrong value.
pub fn check_doctor_reads(
    arena: Allocator,
    stdout: []const u8,
    key: []const u8,
    wanted: i64,
) Error!void {
    assert(key.len > 0);
    assert(wanted >= 0);
    if (try doctor_host_value(arena, stdout, key) != wanted) return error.DoctorWrong;
}

/// A command that must succeed (provisioning, a fix applied as root): exit 0.
pub fn check_ran(status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
}

/// A text-mode run of a program that prints nothing: exit 0, and neither the program nor zbx
/// said anything on either stream.
pub fn check_quiet(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (std.mem.trim(u8, streams.stdout, " \r\n\t").len != 0) return error.OutputWrong;
    if (std.mem.trim(u8, streams.stderr, " \r\n\t").len != 0) return error.OutputWrong;
}

/// The write to the cgroup view failed in the program (`check_program_failed`), and the reason
/// on stderr is the read-only mount, not a permission or a missing file.
pub fn check_read_only_write(arena: Allocator, streams: Streams, status: u8) Error!void {
    try check_program_failed(arena, streams, status);
    if (std.mem.indexOf(u8, streams.stderr, "Read-only file system") == null) {
        return error.OutputWrong;
    }
}

/// E0311 as the agent reads it for `--ulimit nofile=<hard + 1>`: the context's asked, hard and
/// unit; the limits.conf line for the asked value; the user manager's unit for `uid`, whose
/// sentence names the line to add there. Both fixes need root and are no templates.
pub fn check_e0311(diagnostic: Diagnostic, hard: u64, uid: u32) Error!void {
    assert(hard > 0);
    assert(hard < std.math.maxInt(u64));
    var buffers: [5][128]u8 = undefined;
    const asked = text_of(&buffers[0], "{d}", .{hard + 1});
    const own = text_of(&buffers[1], "{d}", .{hard});
    const unit = text_of(&buffers[2], "LimitNOFILE={s}", .{asked});
    const login = text_of(&buffers[3], "echo \"$(id -un) hard nofile {s}\" | " ++
        "sudo tee -a /etc/security/limits.conf", .{asked});
    const manager = text_of(&buffers[4], "sudo systemctl edit user@{d}.service", .{uid});
    try expect_context(diagnostic, "asked", asked);
    try expect_context(diagnostic, "hard", own);
    try expect_context(diagnostic, "unit", unit);
    if (diagnostic.fixes.len != 2) return error.FixWrong;
    if (!std.mem.eql(u8, try root_fix(diagnostic, 0), login)) return error.FixWrong;
    if (!std.mem.eql(u8, try root_fix(diagnostic, 1), manager)) return error.FixWrong;
    const sentence = diagnostic.fixes[1].sentence;
    if (std.mem.indexOf(u8, sentence, unit) == null) return error.FixWrong;
    if (std.mem.indexOf(u8, sentence, "[Service]") == null) return error.FixWrong;
}

/// `check_e0311`'s expected texts: a u64 or u32 in a short constant, well under 128 bytes.
fn text_of(buffer: *[128]u8, comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(buffer, format, args) catch unreachable; // Sized above.
}

/// E0316's second fix points at `--require-host` for the refused key, as a template the agent
/// fills in: `--require-host '<key>>=<value>'`, which needs no root.
pub fn check_require_host_pointer(diagnostic: Diagnostic, key: []const u8) Error!void {
    assert(key.len > 0);
    assert(std.mem.indexOfScalar(u8, key, '\'') == null);
    const command = try fix_at(diagnostic, 1);
    const fix = diagnostic.fixes[1];
    if (!fix.template or fix.needs_root) return error.FixWrong;
    const prefix = "--require-host '";
    const suffix = ">=<value>'";
    if (command.len != prefix.len + key.len + suffix.len) return error.FixWrong;
    if (!std.mem.startsWith(u8, command, prefix)) return error.FixWrong;
    if (!std.mem.eql(u8, command[prefix.len..][0..key.len], key)) return error.FixWrong;
    if (!std.mem.endsWith(u8, command, suffix)) return error.FixWrong;
}

/// The view of `--net user`: `check_view`, and the `SYSCTL:` line the probe adds is `value`,
/// the one the run set: pasta, which set the network up after zbx wrote it, left it alone.
pub fn check_view_sysctl(
    streams: Streams,
    status: u8,
    memory_max: []const u8,
    value: []const u8,
) Error!void {
    assert(value.len > 0);
    try check_view(streams, status, memory_max);
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    var seen: u32 = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "SYSCTL:")) continue;
        if (!std.mem.eql(u8, line["SYSCTL:".len..], value)) return error.ViewWrong;
        seen += 1;
    }
    if (seen != 1) return error.ViewWrong;
}

// ---- The upgrade step ------------------------------------------------------------------------

/// `zbx-old run -d ... --name <name>`: exit 0, and stdout is the name alone.
pub fn check_detached(streams: Streams, status: u8, name: []const u8) Error!void {
    assert(name.len > 0);
    if (status != 0) return error.ExitCodeWrong;
    const said = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!std.mem.eql(u8, said, name)) return error.OutputWrong;
}

/// `zbx stop <name>`: exit 0, and stdout's line is `<name> stopped ...`.
pub fn check_stopped(streams: Streams, status: u8, name: []const u8) Error!void {
    assert(name.len > 0);
    if (status != 0) return error.ExitCodeWrong;
    const said = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!std.mem.startsWith(u8, said, name)) return error.OutputWrong;
    if (!std.mem.startsWith(u8, said[name.len..], " stopped")) return error.OutputWrong;
    if (std.mem.indexOfScalar(u8, said, '\n') != null) return error.OutputWrong;
}

/// The entry `zbx --output json ps` gives for `name`, or null when it lists none by that name.
fn ps_entry(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    name: []const u8,
) Error!?std.json.ObjectMap {
    assert(name.len > 0);
    if (status != 0) return error.ExitCodeWrong;
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    const parsed = std.json.parseFromSliceLeaky(Value, arena, stdout, options) catch {
        return error.JsonWrong;
    };
    if (parsed != .object) return error.JsonWrong;
    const schema = parsed.object.get("schema") orelse return error.JsonWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.ps/1")) return error.JsonWrong;
    const list = parsed.object.get("containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |item| {
        if (item != .object) return error.JsonWrong;
        const found = item.object.get("name") orelse return error.JsonWrong;
        if (found != .string) return error.JsonWrong;
        if (std.mem.eql(u8, found.string, name)) return item.object;
    }
    return null;
}

fn string_is(object: std.json.ObjectMap, key: []const u8, wanted: []const u8) bool {
    const member = object.get(key) orelse return false;
    return member == .string and std.mem.eql(u8, member.string, wanted);
}

/// After `zbx stop`, `ps` lists `name` no longer running, with the exit code it ended with; a
/// listing without it at all is a stop that took effect too.
pub fn check_not_running(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    name: []const u8,
) Error!void {
    const entry = try ps_entry(arena, stdout, status, name) orelse return;
    const state = entry.get("state") orelse return error.RecordWrong;
    if (state != .string or std.mem.eql(u8, state.string, "running")) return error.RecordWrong;
    const code = entry.get("exit_code") orelse return error.RecordWrong;
    if (code != .integer) return error.RecordWrong;
}

/// `ps` lists `name`, started by the older zbx with `--net user --publish <host>:<container>`,
/// running
/// with that one forward.
pub fn check_old_published(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    name: []const u8,
    forward: [2]i64,
) Error!void {
    assert(forward[0] > 0);
    assert(forward[1] > 0);
    const entry = try ps_entry(arena, stdout, status, name) orelse return error.RecordWrong;
    if (!string_is(entry, "state", "running")) return error.RecordWrong;
    if (!string_is(entry, "network", "user")) return error.RecordWrong;
    const published = entry.get("published") orelse return error.RecordWrong;
    if (published != .array or published.array.items.len != 1) return error.RecordWrong;
    const one = published.array.items[0];
    if (one != .object) return error.RecordWrong;
    if (try integer_at(one.object, "host") != forward[0]) return error.RecordWrong;
    if (try integer_at(one.object, "container") != forward[1]) return error.RecordWrong;
}

/// A run record (`cat <name>.zon`) has `line` as one of its lines, spaces around it trimmed.
pub fn check_record_line(output: []const u8, line: []const u8) Error!void {
    assert(line.len > 0);
    assert(std.mem.indexOfScalar(u8, line, '\n') == null);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), line)) return;
    }
    return error.RecordWrong;
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
    const longer = streams_of("40960\n8192\n", "");
    try testing.expectError(error.OutputWrong, check_lines(longer, 0, &both));
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
    try testing.expectError(error.NumberWrong, parse_hard_limit("18446744073709551615\n"));
}

test "check_text_refusal: the recorded E0311 and E0319, and what is not them" {
    const needles = [_][]const u8{ "1048576", "limits.conf", "user@1000.service" };
    try check_text_refusal(streams_of("", recorded.e0311_text), 125, "ZBX-E0311", &needles);
    const leading = streams_of("", "\n" ++ recorded.e0311_text);
    try check_text_refusal(leading, 125, "ZBX-E0311", &needles);
    const host = [_][]const u8{ "65530", "sysctl -w vm.max_map_count=262144" };
    try check_text_refusal(streams_of("", recorded.e0319_text), 125, "ZBX-E0319", &host);
    const text = streams_of("", recorded.e0311_text);
    try testing.expectError(error.RefusalWrong, check_text_refusal(text, 125, "ZBX-E0310", &.{}));
    const ran = streams_of("x\n", recorded.e0311_text);
    try testing.expectError(error.RefusalWrong, check_text_refusal(ran, 125, "ZBX-E0311", &.{}));
    try testing.expectError(error.ExitCodeWrong, check_text_refusal(text, 1, "ZBX-E0311", &.{}));
    const missing = [_][]const u8{"LimitNPROC"};
    const lacks = check_text_refusal(text, 125, "ZBX-E0311", &missing);
    try testing.expectError(error.RefusalWrong, lacks);
    const warned_first = streams_of("", "zbx: warning: x\n" ++ recorded.e0311_text);
    const warning = check_text_refusal(warned_first, 125, "ZBX-E0311", &.{});
    try testing.expectError(error.RefusalWrong, warning);
    const warning_code = streams_of("", "warning[ZBX-E0311]: x\n");
    const not_error = check_text_refusal(warning_code, 125, "ZBX-E0311", &.{});
    try testing.expectError(error.RefusalWrong, not_error);
    const longer_code = streams_of("", "error[ZBX-E03110]: x\n");
    const other = check_text_refusal(longer_code, 125, "ZBX-E0311", &.{});
    try testing.expectError(error.RefusalWrong, other);
    const killed = streams_of("", recorded.e0311_text ++ "zbx: killed (SIGKILL)\n");
    try testing.expectError(error.RefusalWrong, check_text_refusal(killed, 125, "ZBX-E0311", &.{}));
}

test "check_df_blocks: the recorded /dev/shm line's 1K-blocks" {
    const df = streams_of(recorded.df_shm, "");
    try check_df_blocks(df, 0, 262144);
    try testing.expectError(error.OutputWrong, check_df_blocks(df, 0, 65536));
    try testing.expectError(error.ExitCodeWrong, check_df_blocks(df, 1, 262144));
    const other = "tmpfs 262144 0 262144 0% /tmp\n";
    try testing.expectError(error.OutputWrong, check_df_blocks(streams_of(other, ""), 0, 262144));
    const lone = streams_of("/dev/shm\n", "");
    try testing.expectError(error.OutputWrong, check_df_blocks(lone, 0, 262144));
    const word = streams_of("tmpfs many 0 0 0% /dev/shm\n", "");
    try testing.expectError(error.NumberWrong, check_df_blocks(word, 0, 262144));
}

test "check_doctor_value: the recorded host-settings line shows the value" {
    const line = "ok   kernel         6.8.0\n" ++ recorded.doctor_text;
    try check_doctor_value(line, "vm.max_map_count", "65530");
    try check_doctor_value(line, "transparent_hugepage", "madvise");
    const prefix = check_doctor_value(line, "vm.max_map_count", "6553");
    try testing.expectError(error.DoctorWrong, prefix);
    const other = check_doctor_value(line, "vm.max_map_count", "262144");
    try testing.expectError(error.DoctorWrong, other);
    const none = check_doctor_value("ok   kernel 6.8.0\n", "vm.max_map_count", "65530");
    try testing.expectError(error.DoctorWrong, none);
    const glued = "ok   host-settings  vm.max_map_count:65530\n";
    const glued_read = check_doctor_value(glued, "vm.max_map_count", "65530");
    try testing.expectError(error.DoctorWrong, glued_read);
    // The first host-settings line is the doctor's; a later one is not read.
    const two = "ok   host-settings  fs.aio-max-nr 65536\n" ++ recorded.doctor_text;
    const two_read = check_doctor_value(two, "vm.max_map_count", "65530");
    try testing.expectError(error.DoctorWrong, two_read);
}

test "check_failed_with and check_read_only_write: the recorded refused write" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try check_failed_with(streams_of("", recorded.read_only), 1, "Read-only file system");
    const wrote = check_failed_with(streams_of("", ""), 0, "Read-only file system");
    try testing.expectError(error.ExitCodeWrong, wrote);
    const refused = check_failed_with(streams_of("", recorded.read_only), 125, "Read-only");
    try testing.expectError(error.ExitCodeWrong, refused);
    const other = check_failed_with(streams_of("", "Permission denied\n"), 1, "Read-only");
    try testing.expectError(error.OutputWrong, other);
    const both = streams_of("", recorded.read_only ++ recorded.exit_failed);
    try check_read_only_write(arena, both, 1);
    const permission = "sh: can't create x: Permission denied\n";
    const denied = streams_of("", permission ++ recorded.exit_failed);
    try testing.expectError(error.OutputWrong, check_read_only_write(arena, denied, 1));
    const zero = streams_of("", recorded.read_only ++ recorded.exit_ulimit);
    try testing.expectError(error.ExitCodeWrong, check_read_only_write(arena, zero, 0));
}

test "check_view: the scope's own files, no host entry" {
    const own = "LS:cgroup.controllers\nLS:cgroup.procs\nLS:cpu.max\nLS:memory.max\n" ++
        "MEMORY:268435456\nCGROUP:0::/\n";
    try check_view(streams_of(own, ""), 0, "268435456");
    try testing.expectError(error.ExitCodeWrong, check_view(streams_of(own, ""), 1, "268435456"));
    try testing.expectError(error.ViewWrong, check_view(streams_of(own, ""), 0, "max"));
    const hosts = [_][]const u8{ "user.slice", "init.scope", "systemd-journald.service" };
    for (hosts) |entry| {
        var buffer: [256]u8 = undefined;
        const view = try std.fmt.bufPrint(&buffer, "{s}LS:{s}\n", .{ own, entry });
        const host = check_view(streams_of(view, ""), 0, "268435456");
        try testing.expectError(error.ViewWrong, host);
    }
    const path = "LS:a\nLS:b\nLS:c\nLS:d\nMEMORY:268435456\n" ++
        "CGROUP:0::/user.slice/user-1000.slice\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(path, ""), 0, "268435456"));
    const empty = "MEMORY:268435456\nCGROUP:0::/\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(empty, ""), 0, "268435456"));
    const three = "LS:a\nLS:b\nLS:c\nMEMORY:268435456\nCGROUP:0::/\n";
    try testing.expectError(error.ViewWrong, check_view(streams_of(three, ""), 0, "268435456"));
    const no_memory = "LS:a\nLS:b\nLS:c\nLS:d\nCGROUP:0::/\n";
    const memory = check_view(streams_of(no_memory, ""), 0, "268435456");
    try testing.expectError(error.ViewWrong, memory);
    const no_cgroup = "LS:a\nLS:b\nLS:c\nLS:d\nMEMORY:268435456\n";
    const cgroup = check_view(streams_of(no_cgroup, ""), 0, "268435456");
    try testing.expectError(error.ViewWrong, cgroup);
}

test "check_view_sysctl: the view and the one value pasta left alone" {
    const view = "LS:a\nLS:b\nLS:c\nLS:d\nMEMORY:max\nCGROUP:0::/\n";
    try check_view_sysctl(streams_of(view ++ "SYSCTL:8192\n", ""), 0, "max", "8192");
    const reset = streams_of(view ++ "SYSCTL:4096\n", "");
    try testing.expectError(error.ViewWrong, check_view_sysctl(reset, 0, "max", "8192"));
    const none = streams_of(view, "");
    try testing.expectError(error.ViewWrong, check_view_sysctl(none, 0, "max", "8192"));
    const twice = streams_of(view ++ "SYSCTL:8192\nSYSCTL:8192\n", "");
    try testing.expectError(error.ViewWrong, check_view_sysctl(twice, 0, "max", "8192"));
    const host = streams_of("LS:user.slice\n" ++ view ++ "SYSCTL:8192\n", "");
    try testing.expectError(error.ViewWrong, check_view_sysctl(host, 0, "max", "8192"));
}

test "check_quiet and check_ran: exit 0 and nothing said" {
    try check_quiet(streams_of("", ""), 0);
    try check_quiet(streams_of("\n", " \n"), 0);
    try testing.expectError(error.ExitCodeWrong, check_quiet(streams_of("", ""), 1));
    try testing.expectError(error.OutputWrong, check_quiet(streams_of("x\n", ""), 0));
    const said = streams_of("", "zbx: warning: x\n");
    try testing.expectError(error.OutputWrong, check_quiet(said, 0));
    try check_ran(0);
    try testing.expectError(error.ExitCodeWrong, check_ran(1));
    try testing.expectError(error.ExitCodeWrong, check_ran(125));
}

fn parsed_one(arena: Allocator, line: []const u8) !Diagnostic {
    return refusal(arena, streams_of("", line), 125, line["{\"code\":\"".len..][0..9]);
}

test "refusal: the recorded first diagnostic, an error with the code" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const json = streams_of("", recorded.e0319_json);
    const found = try refusal(arena, json, 125, "ZBX-E0319");
    try testing.expectEqualStrings("ZBX-E0319", found.code);
    try testing.expectError(error.DiagnosticWrong, refusal(arena, json, 125, "ZBX-E0316"));
    try testing.expectError(error.ExitCodeWrong, refusal(arena, json, 0, "ZBX-E0319"));
    const printed = streams_of("x\n", recorded.e0319_json);
    try testing.expectError(error.DiagnosticWrong, refusal(arena, printed, 125, "ZBX-E0319"));
    const none = streams_of("", "zbx: something\n");
    try testing.expectError(error.DiagnosticWrong, refusal(arena, none, 125, "ZBX-E0319"));
    const warning = streams_of("", "{\"code\":\"ZBX-E0319\",\"severity\":\"warning\"," ++
        "\"blame\":\"user\",\"summary\":\"s\",\"context\":{},\"fixes\":[],\"docs\":\"d\"}\n");
    try testing.expectError(error.DiagnosticWrong, refusal(arena, warning, 125, "ZBX-E0319"));
}

test "the agent reads the recorded E0319's fields: the host value, the needed value, the fix" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try parsed_one(arena, recorded.e0319_json);
    try expect_context(found, "host", "65530");
    try expect_context(found, "needed", ">=262144");
    try testing.expectError(error.DiagnosticWrong, expect_context(found, "host", "1048576"));
    try testing.expectError(error.DiagnosticWrong, context_text(found, "asked"));
    try testing.expectEqualStrings("sysctl -w vm.max_map_count=262144", try root_command(found, 0));
    try testing.expectError(error.FixWrong, root_command(found, 1));
    try testing.expectEqualStrings("zbx doctor", try fix_at(found, 1));
    try testing.expectError(error.FixWrong, fix_at(found, 2));
    var flat = found;
    flat.context = .{ .string = "65530" };
    try testing.expectError(error.DiagnosticWrong, context_text(flat, "host"));
    const integer = try parsed_one(arena, "{\"code\":\"ZBX-E0319\",\"severity\":\"error\"," ++
        "\"blame\":\"user\",\"summary\":\"s\",\"context\":{\"host\":65530},\"fixes\":[]," ++
        "\"docs\":\"d\"}\n");
    try testing.expectError(error.DiagnosticWrong, context_text(integer, "host"));
    var fixes = [_]agent_json.Fix{found.fixes[0]};
    var copy = found;
    copy.fixes = &fixes;
    fixes[0].needs_root = false;
    try testing.expectError(error.FixWrong, root_command(copy, 0));
    fixes[0].needs_root = true;
    fixes[0].template = true;
    try testing.expectError(error.FixWrong, root_command(copy, 0));
    fixes[0].template = false;
    fixes[0].command = "sysctl -w vm.max_map_count=262144";
    try testing.expectError(error.FixWrong, root_command(copy, 0));
}

test "explain_summary: the catalog's summary for a headline code, the diagnostic's otherwise" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try parsed_one(arena, recorded.e0319_json);
    try testing.expectEqualStrings(summary_e0319, explain_summary(found));
    var other = found;
    other.code = "ZBX-E0316";
    try testing.expectEqualStrings(found.summary, explain_summary(other));
}

test "check_e0311: the recorded E0311's context, both fixes, the unit in the sentence" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try parsed_one(arena, recorded.e0311_json);
    try check_e0311(found, 1048576, 1000);
    try testing.expectError(error.DiagnosticWrong, check_e0311(found, 524288, 1000));
    try testing.expectError(error.FixWrong, check_e0311(found, 1048576, 1001));
    var fixes = [_]agent_json.Fix{ found.fixes[0], found.fixes[1] };
    var copy = found;
    copy.fixes = &fixes;
    fixes[1].sentence = "or for the user manager, under [Service]:";
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
    fixes[1].sentence = found.fixes[1].sentence;
    fixes[1].needs_root = false;
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
    fixes[1] = found.fixes[1];
    fixes[0].command = "echo \"$(id -un) hard nofile 1048577\" | tee -a /etc/security/limits.conf";
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
    copy.fixes = fixes[0..1];
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
}

test "check_require_host_pointer: the recorded E0316's second fix, a template" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try parsed_one(arena, recorded.e0316_json);
    try check_require_host_pointer(found, "vm.max_map_count");
    try testing.expectError(error.FixWrong, check_require_host_pointer(found, "vm.max_map"));
    try testing.expectError(error.FixWrong, check_require_host_pointer(found, "fs.aio-max-nr"));
    var fixes = [_]agent_json.Fix{ found.fixes[0], found.fixes[1] };
    var copy = found;
    copy.fixes = &fixes;
    fixes[1].template = false;
    try testing.expectError(error.FixWrong, check_require_host_pointer(copy, "vm.max_map_count"));
    fixes[1].template = true;
    fixes[1].needs_root = true;
    try testing.expectError(error.FixWrong, check_require_host_pointer(copy, "vm.max_map_count"));
    fixes[1].needs_root = false;
    fixes[1].command = "--require-host 'vm.max_map_count>=262144'";
    try testing.expectError(error.FixWrong, check_require_host_pointer(copy, "vm.max_map_count"));
    copy.fixes = fixes[0..1];
    try testing.expectError(error.FixWrong, check_require_host_pointer(copy, "vm.max_map_count"));
}

test "the agent reads the knobs back from the recorded container_exit lines" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ulimit = try exit_object(arena, streams_of("", recorded.exit_ulimit), 0);
    try check_exit_ulimit(ulimit, "nofile", 4096, 8192);
    try testing.expectError(error.JsonWrong, check_exit_ulimit(ulimit, "nofile", 4096, 4096));
    try testing.expectError(error.JsonWrong, check_exit_ulimit(ulimit, "nofile", 8192, 8192));
    try testing.expectError(error.JsonWrong, check_exit_ulimit(ulimit, "nproc", 1, 1));
    const shm = try exit_object(arena, streams_of("", recorded.exit_shm), 0);
    try check_exit_shm(shm, 268435456);
    try testing.expectError(error.JsonWrong, check_exit_shm(shm, 67108864));
    try testing.expectError(error.JsonWrong, check_exit_shm(ulimit, 268435456));
    const sysctl = try exit_object(arena, streams_of("", recorded.exit_sysctl), 0);
    try check_exit_sysctl(sysctl, "net.core.somaxconn", "8192");
    const wrong = check_exit_sysctl(sysctl, "net.core.somaxconn", "4096");
    try testing.expectError(error.JsonWrong, wrong);
    const key = check_exit_sysctl(sysctl, "net.ipv4.ip_forward", "8192");
    try testing.expectError(error.JsonWrong, key);
    try testing.expectError(error.JsonWrong, check_exit_sysctl(shm, "net.core.somaxconn", "8192"));
    const before = "{\"other\":1}\n" ++ recorded.exit_shm;
    const after_noise = try exit_object(arena, streams_of("", before), 0);
    try check_exit_shm(after_noise, 268435456);
    const failed = streams_of("", recorded.exit_failed);
    try testing.expectError(error.ExitCodeWrong, exit_object(arena, failed, 1));
}

test "check_exit_sysctl: one entry, string key and value" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"sysctls\":[";
    const two = head ++ "{\"key\":\"net.core.somaxconn\",\"value\":\"8192\"}," ++
        "{\"key\":\"net.core.somaxconn\",\"value\":\"8192\"}]}}\n";
    const doubled = try exit_object(arena, streams_of("", two), 0);
    const listed = check_exit_sysctl(doubled, "net.core.somaxconn", "8192");
    try testing.expectError(error.JsonWrong, listed);
    const integer = head ++ "{\"key\":\"net.core.somaxconn\",\"value\":8192}]}}\n";
    const number = try exit_object(arena, streams_of("", integer), 0);
    const typed = check_exit_sysctl(number, "net.core.somaxconn", "8192");
    try testing.expectError(error.JsonWrong, typed);
}

test "check_program_failed: the recorded exit 1, and what is not a failed program" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const failed = streams_of("", recorded.exit_failed);
    try check_program_failed(arena, failed, 1);
    try testing.expectError(error.ExitCodeWrong, check_program_failed(arena, failed, 0));
    try testing.expectError(error.ExitCodeWrong, check_program_failed(arena, failed, 125));
    try testing.expectError(error.ExitLineWrong, check_program_failed(arena, failed, 2));
    const killed = streams_of("", "{\"container_exit\":{\"reason\":\"signaled\",\"code\":1}}\n");
    try testing.expectError(error.ExitLineWrong, check_program_failed(arena, killed, 1));
}

test "doctor_host_value and check_doctor_reads: the recorded zbx.doctor/1" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const doc = recorded.doctor_json;
    const value = try doctor_host_value(arena, doc, "vm.max_map_count");
    try testing.expectEqual(@as(i64, 262144), value);
    try check_doctor_reads(arena, doc, "vm.max_map_count", 262144);
    const low = check_doctor_reads(arena, doc, "vm.max_map_count", 65530);
    try testing.expectError(error.DoctorWrong, low);
    const thp = check_doctor_reads(arena, doc, "transparent_hugepage", 0);
    try testing.expectError(error.JsonWrong, thp);
    try testing.expectError(error.JsonWrong, doctor_host_value(arena, "not json", "x"));
    try testing.expectError(error.JsonWrong, doctor_host_value(arena, "[1]", "x"));
    const flat = "{\"host_settings\":[]}";
    try testing.expectError(error.JsonWrong, doctor_host_value(arena, flat, "vm.max_map_count"));
    const absent = "{\"checks\":[]}";
    try testing.expectError(error.JsonWrong, doctor_host_value(arena, absent, "vm.max_map_count"));
}

test "check_detached and check_stopped: the recorded upgrade lines" {
    try check_detached(streams_of("m2bold\n", ""), 0, "m2bold");
    const failed = check_detached(streams_of("m2bold\n", ""), 1, "m2bold");
    try testing.expectError(error.ExitCodeWrong, failed);
    const longer = check_detached(streams_of("m2bold2\n", ""), 0, "m2bold");
    try testing.expectError(error.OutputWrong, longer);
    try testing.expectError(error.OutputWrong, check_detached(streams_of("", ""), 0, "m2bold"));
    const stopped = streams_of(recorded.stopped, "");
    try check_stopped(stopped, 0, "m2bold");
    try testing.expectError(error.ExitCodeWrong, check_stopped(stopped, 1, "m2bold"));
    try testing.expectError(error.OutputWrong, check_stopped(stopped, 0, "m2b"));
    try testing.expectError(error.OutputWrong, check_stopped(stopped, 0, "m2bpub"));
    const twice = streams_of(recorded.stopped ++ recorded.stopped, "");
    try testing.expectError(error.OutputWrong, check_stopped(twice, 0, "m2bold"));
    const refused = streams_of("m2bold not stopped\n", "");
    try testing.expectError(error.OutputWrong, check_stopped(refused, 0, "m2bold"));
}

const ps_head = "{\"schema\":\"zbx.ps/1\",\"containers\":[";

test "check_not_running: the stop took effect" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const running = check_not_running(arena, recorded.ps_old, 0, "m2bold");
    try testing.expectError(error.RecordWrong, running);
    try check_not_running(arena, recorded.ps_old, 0, "m2bnone");
    for ([_][]const u8{ "m2bold", "m2bpub", "m2bdev" }) |name| {
        try check_not_running(arena, recorded.ps_all, 0, name);
    }
    try testing.expectError(error.ExitCodeWrong, check_not_running(arena, recorded.ps_old, 1, "x"));
    const ended = ps_head ++ "{\"name\":\"m2bold\",\"state\":\"exited\",\"exit_code\":137}]}";
    try check_not_running(arena, ended, 0, "m2bold");
    const open = ps_head ++ "{\"name\":\"m2bold\",\"state\":\"exited\",\"exit_code\":null}]}";
    try testing.expectError(error.RecordWrong, check_not_running(arena, open, 0, "m2bold"));
    const stateless = ps_head ++ "{\"name\":\"m2bold\",\"exit_code\":137}]}";
    try testing.expectError(error.RecordWrong, check_not_running(arena, stateless, 0, "m2bold"));
    const schema = "{\"schema\":\"zbx.images/1\",\"containers\":[]}";
    try testing.expectError(error.JsonWrong, check_not_running(arena, schema, 0, "m2bold"));
    const unnamed = ps_head ++ "{\"state\":\"running\"}]}";
    try testing.expectError(error.JsonWrong, check_not_running(arena, unnamed, 0, "m2bold"));
    try testing.expectError(error.JsonWrong, check_not_running(arena, "[]", 0, "m2bold"));
}

test "check_old_published: running under --net user with the one forward" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const entry = "{\"name\":\"m2bpub\",\"state\":\"running\",\"network\":\"user\",\"published\":";
    const one = ps_head ++ entry ++ "[{\"host\":18080,\"container\":80}]}]}";
    try check_old_published(arena, one, 0, "m2bpub", .{ 18080, 80 });
    const swapped = check_old_published(arena, one, 0, "m2bpub", .{ 80, 18080 });
    try testing.expectError(error.RecordWrong, swapped);
    const other = check_old_published(arena, one, 0, "m2bold", .{ 18080, 80 });
    try testing.expectError(error.RecordWrong, other);
    const none = check_old_published(arena, recorded.ps_old, 0, "m2bold", .{ 18080, 80 });
    try testing.expectError(error.RecordWrong, none);
    const two = ps_head ++ entry ++ "[{\"host\":18080,\"container\":80}," ++
        "{\"host\":18081,\"container\":81}]}]}";
    const extra = check_old_published(arena, two, 0, "m2bpub", .{ 18080, 80 });
    try testing.expectError(error.RecordWrong, extra);
    const stopped = ps_head ++ "{\"name\":\"m2bpub\",\"state\":\"exited\",\"network\":\"user\"," ++
        "\"published\":[{\"host\":18080,\"container\":80}]}]}";
    const ended = check_old_published(arena, stopped, 0, "m2bpub", .{ 18080, 80 });
    try testing.expectError(error.RecordWrong, ended);
}

test "check_record_line: one whole line of the record" {
    const record = ".{\n    .version = 9,\n    .publish = .{ \"18080:80\" },\n}\n";
    try check_record_line(record, ".publish = .{ \"18080:80\" },");
    try testing.expectError(error.RecordWrong, check_record_line(record, ".publish = .{"));
    const devices = check_record_line(record, ".devices = \"/dev/fuse\",");
    try testing.expectError(error.RecordWrong, devices);
}

/// `text` with its one `old` replaced by `new`, for a test input one value away from recorded.
fn replaced(arena: Allocator, text: []const u8, old: []const u8, new: []const u8) ![]const u8 {
    assert(std.mem.count(u8, text, old) == 1);
    return std.mem.replaceOwned(u8, arena, text, old, new);
}

test "check_e0311: each context value and each fix wrong on its own" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // One value off, in the context only: the sentence keeps the recorded unit.
    const contexts = [_][2][]const u8{
        .{ "\"asked\":\"1048577\"", "\"asked\":\"1048578\"" },
        .{ "\"hard\":\"1048576\"", "\"hard\":\"1048575\"" },
        .{ "\"unit\":\"LimitNOFILE=1048577\"", "\"unit\":\"LimitNOFILE=1048578\"" },
    };
    for (contexts) |context| {
        const json = try replaced(arena, recorded.e0311_json, context[0], context[1]);
        const wrong = try parsed_one(arena, json);
        try testing.expectError(error.DiagnosticWrong, check_e0311(wrong, 1048576, 1000));
    }
    const found = try parsed_one(arena, recorded.e0311_json);
    var fixes = [_]agent_json.Fix{ found.fixes[0], found.fixes[1], found.fixes[1] };
    var copy = found;
    copy.fixes = &fixes;
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
    copy.fixes = fixes[0..2];
    try check_e0311(copy, 1048576, 1000);
    fixes[0].needs_root = false;
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
    fixes[0] = found.fixes[0];
    fixes[1].sentence = "or for the user manager, add LimitNOFILE=1048577:";
    try testing.expectError(error.FixWrong, check_e0311(copy, 1048576, 1000));
}

test "check_text_refusal: another six-byte word, or the header split over two lines" {
    const shouted = streams_of("", "Error[ZBX-E0311]: x\n");
    const refused = check_text_refusal(shouted, 125, "ZBX-E0311", &.{});
    try testing.expectError(error.RefusalWrong, refused);
    const split = streams_of("", "error[\nZBX-E0311]: x\n");
    const broken = check_text_refusal(split, 125, "ZBX-E0311", &.{});
    try testing.expectError(error.RefusalWrong, broken);
}

test "check_require_host_pointer: the prefix, the key and the suffix each wrong at its length" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try parsed_one(arena, recorded.e0316_json);
    var fixes = [_]agent_json.Fix{ found.fixes[0], found.fixes[1] };
    var copy = found;
    copy.fixes = &fixes;
    const commands = [_][]const u8{
        "--require-hosT 'vm.max_map_count>=<value>'",
        "--require-host 'vm.max_map_counT>=<value>'",
        "--require-host 'vm.max_map_count>=<valuE>'",
    };
    for (commands) |command| {
        assert(command.len == found.fixes[1].command.?.len);
        fixes[1].command = command;
        const pointer = check_require_host_pointer(copy, "vm.max_map_count");
        try testing.expectError(error.FixWrong, pointer);
    }
}

test "check_exit_ulimit: ulimits that are not an object" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"ulimits\":[]}}\n";
    const exit = try exit_object(arena, streams_of("", line), 0);
    try testing.expectError(error.JsonWrong, check_exit_ulimit(exit, "nofile", 4096, 8192));
}

test "check_not_running: containers that are not a list, a running entry with a code" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const object = "{\"schema\":\"zbx.ps/1\",\"containers\":{}}";
    try testing.expectError(error.JsonWrong, check_not_running(arena, object, 0, "m2bold"));
    const coded = ps_head ++ "{\"name\":\"m2bold\",\"state\":\"running\",\"exit_code\":137}]}";
    try testing.expectError(error.RecordWrong, check_not_running(arena, coded, 0, "m2bold"));
}

test "check_old_published: the network, the host port and the container port each wrong" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const running = "{\"name\":\"m2bpub\",\"state\":\"running\",\"network\":";
    const entries = [_][]const u8{
        "\"none\",\"published\":[{\"host\":18080,\"container\":80}]}]}",
        "\"user\",\"published\":[{\"host\":18081,\"container\":80}]}]}",
        "\"user\",\"published\":[{\"host\":18080,\"container\":81}]}]}",
    };
    for (entries) |entry| {
        const stdout = try std.mem.concat(arena, u8, &.{ ps_head, running, entry });
        const published = check_old_published(arena, stdout, 0, "m2bpub", .{ 18080, 80 });
        try testing.expectError(error.RecordWrong, published);
    }
}

test {
    _ = recorded;
}
