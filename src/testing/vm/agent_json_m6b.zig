//! What the scripted agent of demo-m6b (agent_m6b.zig) reads: the documents of the dev loop, as
//! JSON and nothing else. The writable mounts and the user of `run -d` and `ps`, the `exec_exit`
//! line of `exec`, the `zbx.logs/1` lines of `logs`, and the refusals of the dev loop (E0212,
//! E0213, E0220, E0402) with the member of their context the agent acts on. Its pure parts, each
//! unit-tested with right and wrong input. The refusals' fixtures are the binary's own output
//! (`zbx --output json ...` of the built binary, and the goldens in src/testdata/diag).
//!
//! The rule of the agent test: what the agent needs and cannot read from these is a finding
//! (docs/demos/m6b.md, "The agent test"), not something to guess.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = agent_json.Error || error{
    /// A document lacks the writable mount or the user, or says another thing.
    MountWrong,
    /// The `exec_exit` line is missing or says another thing than the process did.
    ExecExitWrong,
    /// A log line breaks its schema, or the log lacks the requests.
    LogWrong,
};

fn parse_value(arena: Allocator, text: []const u8) Error!Value {
    return std.json.parseFromSliceLeaky(Value, arena, text, .{}) catch return error.JsonWrong;
}

fn member(value: Value, name: []const u8) ?Value {
    if (value != .object) return null;
    return value.object.get(name);
}

fn string_of(value: Value, name: []const u8) ?[]const u8 {
    const found = member(value, name) orelse return null;
    if (found != .string) return null;
    return found.string;
}

// ---- Writable mounts and the user ----------------------------------------------------------

/// What a document says of the one `--mount` of a run: the resolved host path and the target,
/// and the user the command ran as.
pub const Mount = struct {
    host: []const u8,
    target: []const u8,
    uid: i64,
    gid: i64,
};

fn mount_of(entry: Value) Error!Mount {
    const mounts = member(entry, "writable_mounts") orelse return error.MountWrong;
    if (mounts != .array or mounts.array.items.len != 1) return error.MountWrong;
    const one = mounts.array.items[0];
    const host = string_of(one, "host") orelse return error.MountWrong;
    const target = string_of(one, "target") orelse return error.MountWrong;
    const user = member(entry, "user") orelse return error.MountWrong;
    const uid = member(user, "uid") orelse return error.MountWrong;
    const gid = member(user, "gid") orelse return error.MountWrong;
    if (uid != .integer or gid != .integer) return error.MountWrong;
    return .{ .host = host, .target = target, .uid = uid.integer, .gid = gid.integer };
}

/// `run -d --output json`: `zbx.run/1` with the container `name` and its mount and user.
pub fn detached_mount(
    arena: Allocator,
    streams: Streams,
    status: u8,
    name: []const u8,
) Error!Mount {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_value(arena, streams.stdout);
    const schema = string_of(doc, "schema") orelse return error.JsonWrong;
    if (!std.mem.eql(u8, schema, "zbx.run/1")) return error.JsonWrong;
    const container = member(doc, "container") orelse return error.JsonWrong;
    const found = string_of(container, "name") orelse return error.JsonWrong;
    if (!std.mem.eql(u8, found, name)) return error.JsonWrong;
    return mount_of(container);
}

/// The running container `name` in `ps --output json`, with its mount and user.
pub fn ps_mount(arena: Allocator, stdout: []const u8, name: []const u8) Error!Mount {
    const doc = try parse_value(arena, stdout);
    const list = member(doc, "containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |entry| {
        const found = string_of(entry, "name") orelse continue;
        if (!std.mem.eql(u8, found, name)) continue;
        const state = string_of(entry, "state") orelse return error.JsonWrong;
        if (!std.mem.eql(u8, state, "running")) return error.JsonWrong;
        return mount_of(entry);
    }
    return error.JsonWrong;
}

/// The mount is the one asked for, inside `project` (the agent checks the rule itself from what
/// the document says), and the command ran as root, the host user inside the container.
pub fn check_mount(mount: Mount, project: []const u8, target: []const u8) Error!void {
    if (!std.mem.eql(u8, mount.target, target)) return error.MountWrong;
    if (mount.host.len <= project.len + 1) return error.MountWrong;
    if (!std.mem.startsWith(u8, mount.host, project)) return error.MountWrong;
    if (mount.host[project.len] != '/') return error.MountWrong;
    if (std.mem.indexOf(u8, mount.host, "..") != null) return error.MountWrong;
    if (mount.uid != 0 or mount.gid != 0) return error.MountWrong;
}

/// The mount is at `host`, the path the agent's own directory resolves to, exactly.
pub fn check_resolved(mount: Mount, host: []const u8) Error!void {
    std.debug.assert(host.len > 0);
    if (!std.mem.eql(u8, mount.host, host)) return error.MountWrong;
}

/// The state `ps --output json` gives the container `name`, found by its name among them all.
pub fn ps_state(arena: Allocator, stdout: []const u8, name: []const u8) Error![]const u8 {
    std.debug.assert(name.len > 0);
    const doc = try parse_value(arena, stdout);
    const schema = string_of(doc, "schema") orelse return error.JsonWrong;
    if (!std.mem.eql(u8, schema, "zbx.ps/1")) return error.JsonWrong;
    const list = member(doc, "containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |entry| {
        const found = string_of(entry, "name") orelse return error.JsonWrong;
        if (!std.mem.eql(u8, found, name)) continue;
        return string_of(entry, "state") orelse error.JsonWrong;
    }
    return error.JsonWrong;
}

/// `ps --all` says the container `name` (not any other) is in `wanted`.
pub fn check_ps_state(
    arena: Allocator,
    stdout: []const u8,
    name: []const u8,
    wanted: []const u8,
) Error!void {
    const state = try ps_state(arena, stdout, name);
    if (!std.mem.eql(u8, state, wanted)) return error.JsonWrong;
}

/// The schema the agent read describes `name` as an object under `properties`: how it knows a
/// document with no `schema` member (the `exec_exit` line of `exec`) by the member's name. A
/// word in a description is not a member.
pub fn check_describes(arena: Allocator, schema_text: []const u8, name: []const u8) Error!void {
    std.debug.assert(name.len > 0);
    const doc = try parse_value(arena, schema_text);
    const properties = member(doc, "properties") orelse return error.JsonWrong;
    const described = member(properties, name) orelse return error.JsonWrong;
    const kind = string_of(described, "type") orelse return error.JsonWrong;
    if (!std.mem.eql(u8, kind, "object")) return error.JsonWrong;
}

// ---- exec ----------------------------------------------------------------------------------

/// `exec --output json` ended as the command did: the process status is `wanted`, and the last
/// line of stderr is `exec_exit` for `container`, reason `exited`, the same code, and the
/// container still running.
pub fn check_exec_exit(
    arena: Allocator,
    streams: Streams,
    status: u8,
    container: []const u8,
    wanted: u8,
) Error!void {
    if (status != wanted) return error.ExitCodeWrong;
    var last: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, streams.stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len > 0) last = line;
    }
    const line = last orelse return error.ExecExitWrong;
    const doc = try parse_value(arena, line);
    const exit = member(doc, "exec_exit") orelse return error.ExecExitWrong;
    const named = string_of(exit, "container") orelse return error.ExecExitWrong;
    if (!std.mem.eql(u8, named, container)) return error.ExecExitWrong;
    const reason = string_of(exit, "reason") orelse return error.ExecExitWrong;
    if (!std.mem.eql(u8, reason, "exited")) return error.ExecExitWrong;
    const code = member(exit, "code") orelse return error.ExecExitWrong;
    if (code != .integer or code.integer != wanted) return error.ExecExitWrong;
    const ended = member(exit, "container_ended") orelse return error.ExecExitWrong;
    if (ended != .bool or ended.bool) return error.ExecExitWrong;
}

// ---- logs ----------------------------------------------------------------------------------

/// `logs --output json` is lines of `zbx.logs/1`, each following `schema_text` as it is. The
/// number of records of the stream `stream` whose text holds `needle` is returned: the agent
/// counts requests from the stream and the text, parsing no message.
pub fn count_log_records(
    arena: Allocator,
    schema_text: []const u8,
    streams: Streams,
    status: u8,
    stream: []const u8,
    needle: []const u8,
) Error!u32 {
    if (status != 0) return error.ExitCodeWrong;
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, streams.stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        if (try agent_json.violation(arena, schema_text, line)) |_| return error.LogWrong;
        const doc = try parse_value(arena, line);
        const named = string_of(doc, "stream") orelse return error.LogWrong;
        const text = string_of(doc, "text") orelse return error.LogWrong;
        if (!std.mem.eql(u8, named, stream)) continue;
        if (std.mem.indexOf(u8, text, needle) != null) count += 1;
    }
    return count;
}

/// The log has exactly `wanted` records of `stream` holding `needle` (see count_log_records).
pub fn check_log_records(
    arena: Allocator,
    schema_text: []const u8,
    streams: Streams,
    status: u8,
    stream: []const u8,
    needle: []const u8,
    wanted: u32,
) Error!void {
    const counted = try count_log_records(arena, schema_text, streams, status, stream, needle);
    if (counted != wanted) return error.LogWrong;
}

// ---- Refusals ------------------------------------------------------------------------------

/// What an agent expects of a refusal: the code, the member of the context it acts on (with the
/// value it must have, or `null` for any value but `not_value`), and whether the first fix that
/// has a command is a template (an example to adapt) or a command to run, and a word of it.
pub const Want = struct {
    code: []const u8,
    exit: u8,
    key: []const u8,
    value: ?[]const u8 = null,
    not_value: ?[]const u8 = null,
    fix_template: bool,
    fix_has: []const u8,
};

/// The refusal as an agent reads it: exit `want.exit` and nothing on stdout; the first diagnostic
/// is an error blamed on the user with `want.code`; its context has `want.key` as wanted; the
/// first fix with a command is `zbx ...`, a template or not as wanted, and holds `want.fix_has`;
/// and the docs link ends with the code's page.
pub fn check_refusal(
    arena: Allocator,
    streams: Streams,
    status: u8,
    want: Want,
) Error!agent_json.Diagnostic {
    if (status != want.exit) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.DiagnosticWrong;
    const all = try agent_json.diagnostics(arena, streams.stderr);
    if (all.len == 0) return error.DiagnosticWrong;
    const first = all[0];
    if (!std.mem.eql(u8, first.code, want.code)) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, first.severity, "error")) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, first.blame, "user")) return error.DiagnosticWrong;
    const said = string_of(first.context, want.key) orelse return error.DiagnosticWrong;
    if (want.value) |value| {
        if (!std.mem.eql(u8, said, value)) return error.DiagnosticWrong;
    }
    if (want.not_value) |value| {
        if (std.mem.eql(u8, said, value)) return error.DiagnosticWrong;
    }
    const fix = first_fix_with_command(first) orelse return error.FixWrong;
    const command = fix.command.?;
    if (!std.mem.startsWith(u8, command, "zbx ")) return error.FixWrong;
    if (fix.template != want.fix_template) return error.FixWrong;
    if (std.mem.indexOf(u8, command, want.fix_has) == null) return error.FixWrong;
    const page = try std.fmt.allocPrint(arena, "/errors/{s}.html", .{want.code[4..]});
    if (!std.mem.endsWith(u8, first.docs, page)) return error.DiagnosticWrong;
    return first;
}

fn first_fix_with_command(found: agent_json.Diagnostic) ?agent_json.Fix {
    for (found.fixes) |fix| {
        if (fix.command != null) return fix;
    }
    return null;
}

/// The context member `key` of a diagnostic, as text.
pub fn context_of(found: agent_json.Diagnostic, key: []const u8) ?[]const u8 {
    return string_of(found.context, key);
}

/// The context member `key` is `wanted`.
pub fn check_context(found: agent_json.Diagnostic, key: []const u8, wanted: []const u8) Error!void {
    std.debug.assert(key.len > 0);
    const said = context_of(found, key) orelse return error.DiagnosticWrong;
    if (!std.mem.eql(u8, said, wanted)) return error.DiagnosticWrong;
}

/// From a fix that is a template, the flag `flag` with the value it gives (`--user 0`): the
/// part the agent takes, to add to its own command. Null when the fix does not name the flag,
/// or names it with no value or with a placeholder (`<...>`) the agent could not fill.
pub fn flag_from_fix(command: []const u8, flag: []const u8) ?[]const u8 {
    std.debug.assert(std.mem.startsWith(u8, flag, "--"));
    var words = std.mem.tokenizeScalar(u8, command, ' ');
    while (words.next()) |word| {
        if (!std.mem.eql(u8, word, flag)) continue;
        const value = words.next() orelse return null;
        if (value[0] == '<' or value[0] == '-') return null;
        const begin = @intFromPtr(word.ptr) - @intFromPtr(command.ptr);
        const end = @intFromPtr(value.ptr) - @intFromPtr(command.ptr) + value.len;
        std.debug.assert(end <= command.len);
        return command[begin..end];
    }
    return null;
}

/// The command of the first fix that has one: what the agent runs when it is not a template.
pub fn fix_command(found: agent_json.Diagnostic) ?[]const u8 {
    const fix = first_fix_with_command(found) orelse return null;
    return fix.command;
}

const testing = std.testing;

fn scratch() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

const detached_text = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web\",\"pid\":412," ++
    "\"scope\":null,\"detached\":true,\"network\":\"user\"," ++
    "\"published\":[{\"host\":18090,\"container\":8000}],\"env\":[]," ++
    "\"writable_mounts\":[{\"host\":\"/home/demo/p/site\",\"target\":\"/srv\"}]," ++
    "\"user\":{\"uid\":0,\"gid\":0}},\"ran\":{\"kind\":\"image\"}}\n";

test "the mount and the user are read from the detached document and from ps" {
    // Goal: the agent learns the resolved mount and the user from JSON. Wrong: another name, no
    // mount, two mounts, a host path outside the project (or one that only starts like it), a
    // user that is not root, another target, a stopped container in ps.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const mount = try detached_mount(arena, captured(detached_text, ""), 0, "web");
    try check_mount(mount, "/home/demo/p", "/srv");
    try testing.expectEqualStrings("/home/demo/p/site", mount.host);
    const other = detached_mount(arena, captured(detached_text, ""), 0, "other");
    try testing.expectError(error.JsonWrong, other);
    const failed = detached_mount(arena, captured(detached_text, ""), 1, "web");
    try testing.expectError(error.ExitCodeWrong, failed);
    const bare = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web\"}}";
    try testing.expectError(error.MountWrong, detached_mount(arena, captured(bare, ""), 0, "web"));
    try testing.expectError(error.MountWrong, check_mount(mount, "/home/demo/q", "/srv"));
    try testing.expectError(error.MountWrong, check_mount(mount, "/home/demo/p/si", "/srv"));
    try testing.expectError(error.MountWrong, check_mount(mount, "/home/demo/p", "/x"));
    var user = mount;
    user.uid = 1000;
    try testing.expectError(error.MountWrong, check_mount(user, "/home/demo/p", "/srv"));
    var up = mount;
    up.host = "/home/demo/p/../q";
    try testing.expectError(error.MountWrong, check_mount(up, "/home/demo/p", "/srv"));
    const entry = "{\"name\":\"web\",\"state\":\"running\",\"pid\":412,\"writable_mounts\":" ++
        "[{\"host\":\"/home/demo/p/site\",\"target\":\"/srv\"}],\"user\":{\"uid\":0,\"gid\":0}}";
    const listed = "{\"schema\":\"zbx.ps/1\",\"containers\":[" ++ entry ++ "]}";
    const from_ps = try ps_mount(arena, listed, "web");
    try testing.expectEqualStrings("/srv", from_ps.target);
    const stopped = try std.mem.replaceOwned(u8, arena, listed, "running", "stopped");
    try testing.expectError(error.JsonWrong, ps_mount(arena, stopped, "web"));
    try testing.expectError(error.JsonWrong, ps_mount(arena, listed, "absent"));
}

const exec_line = "{\"exec_exit\":{\"container\":\"web\",\"reason\":\"exited\",\"code\":3," ++
    "\"container_ended\":false}}\n";

test "the exec_exit line agrees with the process" {
    // Goal: the agent reads how the command ended from the last stderr line. Wrong: another
    // status, another container, a signal, a code that differs, the container ended, no line.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    try check_exec_exit(arena, captured("", exec_line), 3, "web", 3);
    const note = "{\"code\":\"ZBX-W0207\"}\n" ++ exec_line;
    try check_exec_exit(arena, captured("", note), 3, "web", 3);
    const status = check_exec_exit(arena, captured("", exec_line), 4, "web", 3);
    try testing.expectError(error.ExitCodeWrong, status);
    const named = check_exec_exit(arena, captured("", exec_line), 3, "other", 3);
    try testing.expectError(error.ExecExitWrong, named);
    const signal = try std.mem.replaceOwned(u8, arena, exec_line, "exited", "signal");
    try testing.expectError(
        error.ExecExitWrong,
        check_exec_exit(arena, captured("", signal), 3, "web", 3),
    );
    const code = try std.mem.replaceOwned(u8, arena, exec_line, "\"code\":3", "\"code\":4");
    try testing.expectError(
        error.ExecExitWrong,
        check_exec_exit(arena, captured("", code), 3, "web", 3),
    );
    const ended = try std.mem.replaceOwned(u8, arena, exec_line, "false", "true");
    try testing.expectError(
        error.ExecExitWrong,
        check_exec_exit(arena, captured("", ended), 3, "web", 3),
    );
    try testing.expectError(
        error.ExecExitWrong,
        check_exec_exit(arena, captured("", ""), 3, "web", 3),
    );
}

const request_line = "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":1793236000," ++
    "\"text\":\"127.0.0.1 - - [30/Oct/2026 10:00:00] \\\"GET /index.html HTTP/1.1\\\" 200 -\\n" ++
    "\"}\n";

fn count_in(arena: Allocator, log: []const u8, stream: []const u8, needle: []const u8) !u32 {
    return count_log_records(arena, logs_schema, captured(log, ""), 0, stream, needle);
}

test "requests are counted from the stream and the text of the records" {
    // Goal: the agent counts requests in the JSON log. Wrong: a line that breaks the schema, a
    // record of the other stream (not counted), a failed command.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const two = request_line ++ request_line;
    const counted = try count_in(arena, two, "stderr", "GET /index.html");
    try testing.expectEqual(@as(u32, 2), counted);
    const stdout_only = try count_in(arena, two, "stdout", "GET /index.html");
    try testing.expectEqual(@as(u32, 0), stdout_only);
    const other = try count_in(arena, two, "stderr", "GET /other");
    try testing.expectEqual(@as(u32, 0), other);
    const broken = "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":\"late\"," ++
        "\"text\":\"x\"}\n";
    const bad = count_log_records(arena, logs_schema, captured(broken, ""), 0, "stderr", "x");
    try testing.expectError(error.LogWrong, bad);
    const failed = count_log_records(arena, logs_schema, captured(two, ""), 1, "stderr", "x");
    try testing.expectError(error.ExitCodeWrong, failed);
}

// Real output of the built binary: E0212 and E0402 from `zbx --output json`, E0213 and E0220
// from the goldens (src/testdata/diag).
const e0212 = "{\"code\":\"ZBX-E0212\",\"severity\":\"error\",\"blame\":\"user\",\"summary\":" ++
    "\"a --mount source is outside the project\",\"causes\":[\"--mount ../outside-agent is " ++
    "/tmp/h/outside-agent, outside the project /tmp/h/p; a writable mount stays inside it\"]," ++
    "\"while\":[\"checking\"],\"context\":{\"within\":\"/tmp/h/p\",\"real\":" ++
    "\"/tmp/h/outside-agent\"},\"fixes\":[{\"sentence\":\"run zbx from the project's " ++
    "directory\",\"command\":null},{\"sentence\":\"or give a directory elsewhere " ++
    "read-only:\",\"command\":\"zbx run --bind /path/to/dir:/dir <image>\",\"template\":true}]," ++
    "\"docs\":\"https://zigbox.github.io/zigbox/errors/E0212.html\",\"omitted\":{}}\n";
const e0213 = "{\"code\":\"ZBX-E0213\",\"severity\":\"error\",\"blame\":\"user\",\"summary\":" ++
    "\"a --mount needs the container to run as root\",\"causes\":[\"the container would run as " ++
    "app:staff (uid 1000, gid 50)\"],\"while\":[\"checking\"],\"context\":{\"uid\":\"1000\"," ++
    "\"gid\":\"50\"},\"fixes\":[{\"sentence\":\"run it as root, which is you inside the " ++
    "container:\",\"command\":\"zbx run --user 0 --mount ./site:/srv <image>\",\"template\":" ++
    "true},{\"sentence\":\"or give the directory read-only:\",\"command\":\"zbx run --bind " ++
    "./site:/srv <image>\",\"template\":true}],\"docs\":" ++
    "\"https://zigbox.github.io/zigbox/errors/E0213.html\",\"omitted\":{}}\n";
const e0220 = "{\"code\":\"ZBX-E0220\",\"severity\":\"error\",\"blame\":\"user\",\"summary\":" ++
    "\"the container is not running\",\"causes\":[\"the container web-1 is stopped: it exited " ++
    "with code 3\"],\"while\":[\"looking\"],\"context\":{\"name\":\"web-1\",\"state\":" ++
    "\"stopped\"},\"fixes\":[{\"sentence\":\"see the containers and their states:\",\"command\":" ++
    "\"zbx ps --all\"},{\"sentence\":\"start it again, then exec into it:\",\"command\":" ++
    "\"zbx run -d --name web alpine -- sleep 1000\",\"template\":true}],\"docs\":" ++
    "\"https://zigbox.github.io/zigbox/errors/E0220.html\",\"omitted\":{}}\n";
const e0402 = "{\"code\":\"ZBX-E0402\",\"severity\":\"error\",\"blame\":\"user\",\"summary\":" ++
    "\"no container with that name\",\"causes\":[\"no run record is called 'nosuch'\"]," ++
    "\"while\":[\"looking\"],\"context\":{\"name\":\"nosuch\"},\"fixes\":[{\"sentence\":" ++
    "\"see the containers:\",\"command\":\"zbx ps --all\"}],\"docs\":" ++
    "\"https://zigbox.github.io/zigbox/errors/E0402.html\",\"omitted\":{}}\n";

fn refused(
    arena: Allocator,
    wanted: anyerror,
    out: []const u8,
    err: []const u8,
    status: u8,
    want: Want,
) !void {
    try testing.expectError(wanted, check_refusal(arena, captured(out, err), status, want));
}

test "refusals are read by code, context member and fix" {
    // Goal: the agent acts on a refusal from members alone. E0212: the project in `within`, the
    // fix is a template. E0213: the user's id, a template to adapt with `--user 0`. E0220: the
    // state, a fix that is a command to run. Wrong: another exit, another code, a missing or
    // other context value, a template where a command is expected, the other way round.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const outside: Want = .{
        .code = "ZBX-E0212",
        .exit = 125,
        .key = "within",
        .value = "/tmp/h/p",
        .fix_template = true,
        .fix_has = "--bind",
    };
    const found = try check_refusal(arena, captured("", e0212), 125, outside);
    try testing.expectEqualStrings("/tmp/h/outside-agent", context_of(found, "real").?);
    const root: Want = .{
        .code = "ZBX-E0213",
        .exit = 125,
        .key = "uid",
        .not_value = "0",
        .fix_template = true,
        .fix_has = "--user 0",
    };
    _ = try check_refusal(arena, captured("", e0213), 125, root);
    const stopped: Want = .{
        .code = "ZBX-E0220",
        .exit = 125,
        .key = "state",
        .value = "stopped",
        .fix_template = false,
        .fix_has = "ps --all",
    };
    const ps = try check_refusal(arena, captured("", e0220), 125, stopped);
    try testing.expectEqualStrings("zbx ps --all", fix_command(ps).?);
    const missing: Want = .{
        .code = "ZBX-E0402",
        .exit = 1,
        .key = "name",
        .value = "nosuch",
        .fix_template = false,
        .fix_has = "ps --all",
    };
    _ = try check_refusal(arena, captured("", e0402), 1, missing);
    try refused(arena, error.ExitCodeWrong, "", e0402, 125, missing);
    try refused(arena, error.DiagnosticWrong, "x", e0402, 1, missing);
    try refused(arena, error.DiagnosticWrong, "", e0220, 1, missing);
    var other_value = missing;
    other_value.value = "another";
    try refused(arena, error.DiagnosticWrong, "", e0402, 1, other_value);
    var no_key = missing;
    no_key.key = "holder";
    try refused(arena, error.DiagnosticWrong, "", e0402, 1, no_key);
    var not_zero = root;
    not_zero.not_value = "1000";
    try refused(arena, error.DiagnosticWrong, "", e0213, 125, not_zero);
    var template = stopped;
    template.fix_template = true;
    try refused(arena, error.FixWrong, "", e0220, 125, template);
    var word = root;
    word.fix_has = "--net";
    try refused(arena, error.FixWrong, "", e0213, 125, word);
    try refused(arena, error.DiagnosticWrong, "", "", 125, root);
}

// Text captured from real runs of this demo in the KVM guest (vm runs 41076069695 and, for the
// schema, the refusal of a non-root image and `ps --all`, 41079428757): not what the code above
// is believed to print. `ps --all` is cut to three of its 21 entries, each as printed.
const real_ps = "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"agentweb\",\"state\":" ++
    "\"running\",\"pid\":3350,\"supervisor\":3345,\"scope\":\"zbx-agentweb.scope\",\"detached\":" ++
    "true,\"timed_out\":false,\"started\":1793372526,\"ended\":null,\"reason\":\"none\"," ++
    "\"exit_code\":null,\"command\":[\"python\",\"-m\",\"http.server\",\"-d\",\"/srv\"," ++
    "\"8000\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":" ++
    "null},\"network\":\"user\",\"published\":[{\"host\":18090,\"container\":8000}],\"env\":[]," ++
    "\"writable_mounts\":[{\"host\":\"/home/demo/agent-project/agentsite\",\"target\":" ++
    "\"/srv\"}],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"lg2\",\"state\":\"lost\",\"pid\":" ++
    "2935,\"supervisor\":2929,\"scope\":\"zbx-lg2.scope\",\"detached\":false,\"timed_out\":" ++
    "false,\"started\":1793372506,\"ended\":null,\"reason\":\"none\",\"exit_code\":null," ++
    "\"command\":[\"sh\",\"-c\",\"echo before-the-kill; sleep 600\"],\"labels\":[],\"limits\":" ++
    "{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\"," ++
    "\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{\"uid\":0,\"gid\":0}}]}\n";
const real_log = "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":1793372527," ++
    "\"text\":\"127.0.0.1 - - [30/Oct/2026 15:02:07] \\\"GET /index.html HTTP/1.1\\\" 200 " ++
    "-\\n\"}\n" ++
    "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":1793372528,\"text\":" ++
    "\"127.0.0.1 - - [30/Oct/2026 15:02:08] \\\"GET /index.html HTTP/1.1\\\" 200 -\\n\"}\n";
const real_exec = "{\"exec_exit\":{\"container\":\"agentweb\",\"reason\":\"exited\",\"code\":3," ++
    "\"container_ended\":false}}\n";

test "text the binary printed in the guest passes the checks" {
    // Goal: the agent's checks accept what the binary really printed, so the modelled inputs of
    // the tests above are not the only thing they were tried on. Method: the captured documents,
    // each through the check that reads it in the demo, and the wrong name or state where a
    // check selects one.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const mount = try ps_mount(arena, real_ps, "agentweb");
    try check_mount(mount, "/home/demo/agent-project", "/srv");
    try testing.expectEqualStrings("/home/demo/agent-project/agentsite", mount.host);
    try testing.expectError(error.JsonWrong, ps_mount(arena, real_ps, "lg2"));
    const counted = try count_in(arena, real_log, "stderr", "GET /index.html");
    try testing.expectEqual(@as(u32, 2), counted);
    try check_exec_exit(arena, captured("", real_exec), 3, "agentweb", 3);
}

const real_ps_all = "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"zbx-ab74b6\",\"state\"" ++
    ":\"stopped\",\"pid\":3442,\"supervisor\":3438,\"scope\":\"zbx-zbx-ab74b6.scope\",\"detached" ++
    "\":false,\"timed_out\":false,\"started\":1793373899,\"ended\":1793373899,\"reason\":\"exite" ++
    "d\",\"exit_code\":0,\"command\":[\"docker-entrypoint.sh\",\"id\",\"-u\"],\"labels\":[],\"li" ++
    "mits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":\"none\",\"pub" ++
    "lished\":[],\"env\":[],\"writable_mounts\":[{\"host\":\"/home/demo/agent-project/agentsite" ++
    "\",\"target\":\"/srv\"}],\"user\":{\"uid\":0,\"gid\":0}},{\"name\":\"agentweb\",\"state\":" ++
    "\"stopped\",\"pid\":3350,\"supervisor\":3345,\"scope\":\"zbx-agentweb.scope\",\"detached\":" ++
    "true,\"timed_out\":false,\"started\":1793373895,\"ended\":1793373899,\"reason\":\"signal\"," ++
    "\"exit_code\":137,\"command\":[\"python\",\"-m\",\"http.server\",\"-d\",\"/srv\",\"8000\"]," ++
    "\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"networ" ++
    "k\":\"user\",\"published\":[{\"host\":18090,\"container\":8000}],\"env\":[],\"writable_moun" ++
    "ts\":[{\"host\":\"/home/demo/agent-project/agentsite\",\"target\":\"/srv\"}],\"user\":{\"ui" ++
    "d\":0,\"gid\":0}},{\"name\":\"pd1\",\"state\":\"lost\",\"pid\":3257,\"supervisor\":3251,\"s" ++
    "cope\":\"zbx-pd1.scope\",\"detached\":false,\"timed_out\":false,\"started\":1793373887,\"en" ++
    "ded\":null,\"reason\":\"none\",\"exit_code\":null,\"command\":[\"docker-entrypoint.sh\",\"s" ++
    "leep\",\"611\"],\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis" ++
    "\":null},\"network\":\"none\",\"published\":[],\"env\":[],\"writable_mounts\":[],\"user\":{" ++
    "\"uid\":11211,\"gid\":11211}}]}\n";
const real_exec_schema = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\n\"$id" ++
    "\":\"https://zigbox.github.io/zigbox/schema/exec/1\",\"version\":1,\n\"title\":\"zbx exec -" ++
    "-output json\",\n\"description\":\"stderr: diagnostics, then exec_exit. The command's own o" ++
    "utput is its own.\",\n\"type\":\"object\",\n\"properties\":{\"code\":{\"type\":\"string\"," ++
    "\"pattern\":\"^ZBX-[EWB][0-9]{4}$\"},\n\"severity\":{\"enum\":[\"error\",\"warning\",\"bug" ++
    "\"]},\"blame\":{\"enum\":[\"user\",\"environment\",\n\"external\",\"internal\",\"bug\"]},\n" ++
    "\"summary\":{\"type\":\"string\"},\"causes\":{\"type\":\"array\",\"items\":{\"type\":\"stri" ++
    "ng\"}},\n\"while\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},\"context\":{\"type" ++
    "\":\"object\"},\n\"fixes\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties" ++
    "\":{\n\"sentence\":{\"type\":\"string\"},\"command\":{\"type\":[\"string\",\"null\"]},\n\"n" ++
    "eeds_root\":{\"type\":\"boolean\",\"description\":\"M6: only when true; the command needs r" ++
    "oot\"},\n\"template\":{\"type\":\"boolean\",\n\"description\":\"M6: only when true; an exam" ++
    "ple to adapt, not to run as written\"}}}},\n\"docs\":{\"type\":\"string\"},\"saved\":{\"typ" ++
    "e\":\"string\"},\"omitted\":{\"type\":\"object\"},\"exec_exit\":{\"type\":\"object\",\"requ" ++
    "ired\":[\"container\",\"reason\",\"code\",\"container_ended\"],\n\"properties\":{\"containe" ++
    "r\":{\"type\":\"string\"},\"reason\":{\"enum\":[\"exited\",\"signal\"]},\n\"code\":{\"type" ++
    "\":\"integer\",\"minimum\":0,\"maximum\":255,\n\"description\":\"the command's exit code, o" ++
    "r 128 plus its signal; zbx exits with it\"},\n\"signal\":{\"type\":\"integer\",\"descriptio" ++
    "n\":\"only for reason signal\"},\n\"container_ended\":{\"type\":\"boolean\",\n\"description" ++
    "\":\"the command was killed because its container ended\"}}}},\n\"oneOf\":[{\"required\":[" ++
    "\"code\",\"severity\",\"blame\",\"summary\",\"causes\",\"docs\"]},{\"required\":[\"exec_exi" ++
    "t\"]}]}\n";
// `zbx schema logs`, as the built binary prints it.
const logs_schema = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\n\"$id\":" ++
    "\"https://zigbox.github.io/zigbox/schema/logs/1\",\"version\":1,\n\"titl" ++
    "e\":\"zbx logs --output json\",\n\"description\":\"stdout: a line per re" ++
    "cord (a write of up to 4096 bytes). stderr: diagnostics.\",\n\"$comment" ++
    "\":\"One object schema, no $ref: oneOf names the members that tell them " ++
    "apart.\",\n\"type\":\"object\",\n\"properties\":{\"schema\":{\"const\":" ++
    "\"zbx.logs/1\"},\n\"stream\":{\"enum\":[\"stdout\",\"stderr\"]},\n\"time" ++
    "\":{\"type\":\"integer\",\"description\":\"seconds since the epoch when " ++
    "zbx read the write\"},\n\"text\":{\"type\":\"string\",\"description\":\"" ++
    "the bytes; not UTF-8 becomes U+FFFD and lossy\"},\n\"lossy\":{\"const\":" ++
    "true,\"description\":\"only when text had bytes that are not UTF-8\"},\n" ++
    "\"dropped_bytes\":{\"type\":\"integer\",\"minimum\":1,\n\"description\":" ++
    "\"first record only: bytes of older output the 5 MiB cap dropped\"},\"co" ++
    "de\":{\"type\":\"string\",\"pattern\":\"^ZBX-[EWB][0-9]{4}$\"},\n\"sever" ++
    "ity\":{\"enum\":[\"error\",\"warning\",\"bug\"]},\"blame\":{\"enum\":[\"" ++
    "user\",\"environment\",\n\"external\",\"internal\",\"bug\"]},\n\"summary" ++
    "\":{\"type\":\"string\"},\"causes\":{\"type\":\"array\",\"items\":{\"typ" ++
    "e\":\"string\"}},\n\"while\":{\"type\":\"array\",\"items\":{\"type\":\"s" ++
    "tring\"}},\"context\":{\"type\":\"object\"},\n\"fixes\":{\"type\":\"arra" ++
    "y\",\"items\":{\"type\":\"object\",\"properties\":{\n\"sentence\":{\"typ" ++
    "e\":\"string\"},\"command\":{\"type\":[\"string\",\"null\"]},\n\"needs_r" ++
    "oot\":{\"type\":\"boolean\",\"description\":\"M6: only when true; the co" ++
    "mmand needs root\"},\n\"template\":{\"type\":\"boolean\",\n\"description" ++
    "\":\"M6: only when true; an example to adapt, not to run as written\"}}}" ++
    "},\n\"docs\":{\"type\":\"string\"},\"saved\":{\"type\":\"string\"},\"omi" ++
    "tted\":{\"type\":\"object\"}},\n\"oneOf\":[{\"required\":[\"schema\",\"s" ++
    "tream\",\"time\",\"text\"]},{\"required\":[\"code\",\"severity\",\"blame" ++
    "\",\"summary\",\"causes\",\"docs\"]}]}\n";
const real_e0213 = "{\"code\":\"ZBX-E0213\",\"severity\":\"error\",\"blame\":\"user\",\"summary" ++
    "\":\"a --mount needs the container to run as root\",\"causes\":[\"the container would run a" ++
    "s memcache (uid 11211, gid 11211), and what it writes through --mount would belong to an id" ++
    " that is not yours\"],\"while\":[\"checking the user of a run with --mount\"],\"context\":{" ++
    "\"uid\":\"11211\",\"gid\":\"11211\"},\"fixes\":[{\"sentence\":\"run it as root, which is yo" ++
    "u inside the container:\",\"command\":\"zbx run --user 0 --mount ./site:/srv <image>\",\"te" ++
    "mplate\":true},{\"sentence\":\"or give the directory read-only:\",\"command\":\"zbx run --b" ++
    "ind ./site:/srv <image>\",\"template\":true}],\"docs\":\"https://zigbox.github.io/zigbox/er" ++
    "rors/E0213.html\",\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

test "the agent reads the state of its own container among all of them" {
    // Goal: `ps --all` is read for the one container the agent stopped, not for any entry that
    // is stopped. Method: the captured `ps --all`, where other containers are stopped (and one
    // lost) too: agentweb's entry changed to running fails, and so does a list without it.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    try check_ps_state(arena, real_ps_all, "agentweb", "stopped");
    try testing.expectEqualStrings("lost", try ps_state(arena, real_ps_all, "pd1"));
    const running = try std.mem.replaceOwned(
        u8,
        arena,
        real_ps_all,
        "{\"name\":\"agentweb\",\"state\":\"stopped\"",
        "{\"name\":\"agentweb\",\"state\":\"running\"",
    );
    try testing.expect(!std.mem.eql(u8, running, real_ps_all));
    const wrong = check_ps_state(arena, running, "agentweb", "stopped");
    try testing.expectError(error.JsonWrong, wrong);
    const absent = check_ps_state(arena, real_ps_all, "no-such", "stopped");
    try testing.expectError(error.JsonWrong, absent);
    try testing.expectError(error.JsonWrong, check_ps_state(arena, "nope", "agentweb", "stopped"));
}

test "the logs schema describes a record and a refusal, and nothing else" {
    // Goal: an agent validates every document `logs --output json` prints against `zbx schema
    // logs`. Method: the captured E0402 and a captured record pass; a refusal without its docs
    // member, a record without its text, and a mix of the two fail.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const refusal_line = std.mem.trim(u8, e0402, "\n");
    try testing.expect((try agent_json.violation(arena, logs_schema, refusal_line)) == null);
    const record = std.mem.trim(u8, request_line, "\n");
    try testing.expect((try agent_json.violation(arena, logs_schema, record)) == null);
    const no_docs = try std.mem.replaceOwned(u8, arena, refusal_line, "\"docs\"", "\"doc\"");
    try testing.expect((try agent_json.violation(arena, logs_schema, no_docs)) != null);
    const no_text = try std.mem.replaceOwned(u8, arena, record, "\"text\"", "\"txt\"");
    try testing.expect((try agent_json.violation(arena, logs_schema, no_text)) != null);
    const mixed = try std.mem.replaceOwned(u8, arena, record, "\"stream\"", "\"code\"");
    try testing.expect((try agent_json.violation(arena, logs_schema, mixed)) != null);
}

test "the exec schema is known by the member it describes, not by a word in it" {
    // Goal: the agent finds that the exec schema describes `exec_exit` as a member. Method: the
    // captured schema passes; with the member renamed (the word still in its descriptions) it
    // fails, and so does the logs schema, which has no such member.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    try check_describes(arena, real_exec_schema, "exec_exit");
    const renamed = try std.mem.replaceOwned(
        u8,
        arena,
        real_exec_schema,
        "\"exec_exit\":{\"type\"",
        "\"exit\":{\"type\"",
    );
    try testing.expect(std.mem.indexOf(u8, renamed, "exec_exit") != null);
    try testing.expectError(error.JsonWrong, check_describes(arena, renamed, "exec_exit"));
    try testing.expectError(error.JsonWrong, check_describes(arena, logs_schema, "exec_exit"));
    try testing.expectError(error.JsonWrong, check_describes(arena, "[]", "exec_exit"));
}

test "the agent takes the flag from the template, and the exact values it acts on" {
    // Goal: the agent adapts E0213's fix by the flag it names, and compares the path, the
    // context and the count it reads exactly. Method: the captured refusal gives `--user 0`; a
    // fix without the flag, with a placeholder, or with the flag last gives nothing; another
    // path, context value or count fails.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const root: Want = .{
        .code = "ZBX-E0213",
        .exit = 125,
        .key = "uid",
        .not_value = "0",
        .fix_template = true,
        .fix_has = "--user 0",
    };
    const found = try check_refusal(arena, captured("", real_e0213), 125, root);
    try testing.expectEqualStrings("--user 0", flag_from_fix(fix_command(found).?, "--user").?);
    const none = [_][]const u8{
        "zbx run --bind ./site:/srv <image>",
        "zbx run --user <id> --mount ./site:/srv <image>",
        "zbx run --mount ./site:/srv --user",
        "zbx run --userx 0 <image>",
    };
    for (none) |fix| try testing.expect(flag_from_fix(fix, "--user") == null);
    try check_context(found, "uid", "11211");
    try testing.expectError(error.DiagnosticWrong, check_context(found, "uid", "1121"));
    try testing.expectError(error.DiagnosticWrong, check_context(found, "real", "11211"));
    const mount = try ps_mount(arena, real_ps, "agentweb");
    try check_resolved(mount, "/home/demo/agent-project/agentsite");
    const other = check_resolved(mount, "/home/demo/agent-project/agentsite2");
    try testing.expectError(error.MountWrong, other);
    const log = captured(real_log, "");
    try check_log_records(arena, logs_schema, log, 0, "stderr", "GET /index.html", 2);
    const three = check_log_records(arena, logs_schema, log, 0, "stderr", "GET /index.html", 3);
    try testing.expectError(error.LogWrong, three);
    const one = check_log_records(arena, logs_schema, log, 0, "stderr", "GET /index.html", 1);
    try testing.expectError(error.LogWrong, one);
}
