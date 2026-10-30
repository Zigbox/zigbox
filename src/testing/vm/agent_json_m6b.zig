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

const logs_schema = "{\"type\":\"object\"," ++
    "\"required\":[\"schema\",\"stream\",\"time\",\"text\"]," ++
    "\"properties\":{\"schema\":{\"const\":\"zbx.logs/1\"},\"stream\":{\"enum\":[\"stdout\"," ++
    "\"stderr\"]},\"time\":{\"type\":\"integer\"},\"text\":{\"type\":\"string\"}}}";
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
