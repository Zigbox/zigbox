//! What the scripted agent of demo-m5 (agent_m5.zig) reads: the network members of `zbx run
//! --output json` and `ps`, the ZBX-E0601 diagnostic and the doctor's report, as JSON and nothing
//! else. Its pure parts, each unit-tested with right and wrong input. M5's agent test found six
//! things the agent could not read (docs/demos/m5.md, "The agent test"); M6 slice 1 closed them,
//! and the functions below check what closed them: the hint of a failure, the network in
//! `run -d` and `ps`, the flags of a fix, the doctor's document, a schema without `$ref`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");

const Streams = checks.Streams;
pub const Error = agent_json.Error || error{
    /// A failure with the default network carries no hint.
    HintMissing,
    /// An explicit `--net none`, or a run that worked, carries one.
    HintUnexpected,
    /// The flags of a fix, the document of `run -d` or `ps`, or the doctor's report, are wrong.
    FlagsWrong,
    ReachWrong,
    DoctorWrong,
};

pub const Published = struct { host: u32, container: u32 };

/// The members of the `container_exit` object that the network adds (zbx.run/1).
pub const NetExit = struct {
    reason: []const u8,
    code: u32,
    network: ?[]const u8 = null,
    /// M6: `network_none` when the failure may have been the network.
    hint: ?[]const u8 = null,
    published: ?[]const Published = null,
};

const ExitLine = struct { container_exit: NetExit };

fn parse_options() std.json.ParseOptions {
    return .{ .ignore_unknown_fields = true, .allocate = .alloc_always };
}

/// The `container_exit` line of a foreground run, with its network members.
pub fn net_exit(arena: Allocator, stderr: []const u8) Error!NetExit {
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (!std.mem.startsWith(u8, line, "{\"container_exit\":")) continue;
        const parsed = std.json.parseFromSliceLeaky(ExitLine, arena, line, parse_options());
        return (parsed catch return error.JsonWrong).container_exit;
    }
    return error.ExitLineWrong;
}

/// The `container_exit` line of a foreground run, as text, to check it against `zbx schema run`.
pub fn exit_line(stderr: []const u8) Error![]const u8 {
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "{\"container_exit\":")) return line;
    }
    return error.ExitLineWrong;
}

fn same_published(found: ?[]const Published, wanted: []const Published) bool {
    const list = found orelse return wanted.len == 0;
    if (list.len != wanted.len) return false;
    for (list, wanted) |left, right| {
        if (left.host != right.host or left.container != right.container) return false;
    }
    return true;
}

/// A run that failed with no network granted, read from JSON alone: the program failed (a
/// non-zero code the process status repeats), the line says the network was `none` with nothing
/// published, and carries `"hint":"network_none"`: the agent grants a network from the hint, not
/// from a guess. The text note of the text mode is not there.
pub fn check_failed_without_network(arena: Allocator, streams: Streams, status: u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    const line = try net_exit(arena, streams.stderr);
    if (!std.mem.eql(u8, line.reason, "exited")) return error.ExitLineWrong;
    if (line.code != status) return error.ExitLineWrong;
    const network = line.network orelse return error.ExitLineWrong;
    if (!std.mem.eql(u8, network, "none")) return error.ExitLineWrong;
    if (!same_published(line.published, &.{})) return error.ExitLineWrong;
    const hint = line.hint orelse return error.HintMissing;
    if (!std.mem.eql(u8, hint, "network_none")) return error.ExitLineWrong;
    if (std.mem.indexOf(u8, streams.stderr, "grant with --net") != null) return error.ExitLineWrong;
}

/// A run that failed with an explicit `--net none`: the network was asked for, so it is not the
/// likely cause and the line carries no hint.
pub fn check_failed_with_explicit_none(arena: Allocator, streams: Streams, status: u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    const line = try net_exit(arena, streams.stderr);
    if (line.code != status) return error.ExitLineWrong;
    const network = line.network orelse return error.ExitLineWrong;
    if (!std.mem.eql(u8, network, "none")) return error.ExitLineWrong;
    if (line.hint != null) return error.HintUnexpected;
}

/// A run that ended 0 on `network` with exactly the forwards in `published`.
pub fn check_granted(
    arena: Allocator,
    streams: Streams,
    status: u8,
    network: []const u8,
    published: []const Published,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const line = try net_exit(arena, streams.stderr);
    if (!std.mem.eql(u8, line.reason, "exited")) return error.ExitLineWrong;
    if (line.code != 0) return error.ExitLineWrong;
    const said = line.network orelse return error.ExitLineWrong;
    if (!std.mem.eql(u8, said, network)) return error.ExitLineWrong;
    if (line.hint != null) return error.HintUnexpected; // A run that worked has no failure to hint.
    if (!same_published(line.published, published)) return error.ExitLineWrong;
}

/// A run refused because pasta is missing, read from its diagnostic: exit 125, nothing on
/// stdout, no `container_exit` line (no container ran), code ZBX-E0601, blamed on the
/// environment, and fixes: the first an install command, and one that runs with the host's
/// network.
pub fn check_pasta_missing(
    arena: Allocator,
    streams: Streams,
    status: u8,
) Error!agent_json.Diagnostic {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.DiagnosticWrong;
    if (std.mem.indexOf(u8, streams.stderr, "{\"container_exit\":") != null) {
        return error.DiagnosticWrong;
    }
    const all = try agent_json.diagnostics(arena, streams.stderr);
    if (all.len != 1) return error.DiagnosticWrong;
    const first = all[0];
    if (!std.mem.eql(u8, first.code, "ZBX-E0601")) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, first.severity, "error")) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, first.blame, "environment")) return error.DiagnosticWrong;
    if (first.fixes.len < 2) return error.FixWrong;
    const install = first.fixes[0].command orelse return error.FixWrong;
    if (!std.mem.eql(u8, install, "sudo apt install passt")) return error.FixWrong;
    // M6: the fixes say what they need. The install needs root and is to be run as it is; the
    // second is an example, which the agent must adapt and not run.
    if (!first.fixes[0].needs_root or first.fixes[0].template) return error.FlagsWrong;
    if (first.fixes[1].needs_root or !first.fixes[1].template) return error.FlagsWrong;
    return first;
}

/// A run with `-e NAME=VALUE` and `-e NAME`: it ended 0, the program's own output (stdout) shows
/// both values, which is how the agent knows they reached the container, and zbx's line on stderr
/// holds neither.
pub fn check_env_reached(
    streams: Streams,
    status: u8,
    value: []const u8,
    copied: []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (std.mem.indexOf(u8, streams.stdout, value) == null) return error.ReachWrong;
    if (std.mem.indexOf(u8, streams.stdout, copied) == null) return error.ReachWrong;
    if (std.mem.indexOf(u8, streams.stderr, value) != null) return error.ReachWrong;
    if (std.mem.indexOf(u8, streams.stderr, copied) != null) return error.ReachWrong;
    if (std.mem.indexOf(u8, streams.stderr, "{\"container_exit\":") == null) {
        return error.ExitLineWrong;
    }
}

/// `-e NAME` with NAME unset: exit 125, nothing on stdout, one diagnostic ZBX-E0011 blamed on the
/// user, naming the variable in its context, and every fix a command to adapt (a template that
/// does not need root).
pub fn check_env_unset(
    arena: Allocator,
    streams: Streams,
    status: u8,
) Error!agent_json.Diagnostic {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.DiagnosticWrong;
    const all = try agent_json.diagnostics(arena, streams.stderr);
    if (all.len != 1) return error.DiagnosticWrong;
    const found = all[0];
    if (!std.mem.eql(u8, found.code, "ZBX-E0011")) return error.DiagnosticWrong;
    if (!std.mem.eql(u8, found.blame, "user")) return error.DiagnosticWrong;
    const named = member(found.context, "name") orelse return error.DiagnosticWrong;
    if (named != .string or !std.mem.eql(u8, named.string, "AGENT_NOT_SET")) {
        return error.DiagnosticWrong;
    }
    if (found.fixes.len == 0) return error.FixWrong;
    for (found.fixes) |fix| {
        if (fix.command == null) return error.FixWrong;
        if (!fix.template or fix.needs_root) return error.FlagsWrong;
    }
    return found;
}

/// The network mode a fix of `diagnostic` runs with: `host` when a fix that is marked a template
/// has a `zbx run --net host ...` command. The agent applies that flag to its own command; the
/// template itself (`alpine -- sh`) it must not run, and the flag tells it so. A fix that needs
/// root is never one the agent takes the mode from.
pub fn fix_net_mode(diagnostic: agent_json.Diagnostic) Error![]const u8 {
    for (diagnostic.fixes) |fix| {
        const command = fix.command orelse continue;
        if (!fix.template) continue;
        if (fix.needs_root) continue;
        if (!std.mem.startsWith(u8, command, "zbx run ")) continue;
        if (std.mem.indexOf(u8, command, " --net host ") != null) return "host";
    }
    return error.FixWrong;
}

fn parse_value(arena: Allocator, text: []const u8) Error!Value {
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    return std.json.parseFromSliceLeaky(Value, arena, text, options) catch return error.JsonWrong;
}

fn member(value: Value, name: []const u8) ?Value {
    if (value != .object) return null;
    return value.object.get(name);
}

/// The agent reads `zbx schema run` before it relies on `network`, `hint` and `published`, and
/// it reads them as they are: one object schema with no `$ref` anywhere, whose `properties`
/// hold `container_exit`, and in it `network` (with `none`, `host` and `user`), `hint`
/// (`network_none`) and `published`, an array of objects that require `host` and `container`.
pub fn schema_describes_network(arena: Allocator, schema_text: []const u8) Error!void {
    if (std.mem.indexOf(u8, schema_text, "\"$ref\"") != null) return error.JsonWrong;
    const schema = try parse_value(arena, schema_text);
    const outer = member(schema, "properties") orelse return error.JsonWrong;
    const exit = member(outer, "container_exit") orelse return error.JsonWrong;
    const properties = member(exit, "properties") orelse return error.JsonWrong;
    const network = member(properties, "network") orelse return error.JsonWrong;
    try enum_has(network, &.{ "none", "host", "user" });
    const hint = member(properties, "hint") orelse return error.JsonWrong;
    try enum_has(hint, &.{"network_none"});
    const published = member(properties, "published") orelse return error.JsonWrong;
    const kind = member(published, "type") orelse return error.JsonWrong;
    if (kind != .string or !std.mem.eql(u8, kind.string, "array")) return error.JsonWrong;
    const items = member(published, "items") orelse return error.JsonWrong;
    const required = member(items, "required") orelse return error.JsonWrong;
    if (required != .array or required.array.items.len != 2) return error.JsonWrong;
    // The detached document's members are in the same schema, under `container`.
    const container = member(outer, "container") orelse return error.JsonWrong;
    const inner = member(container, "properties") orelse return error.JsonWrong;
    for ([_][]const u8{ "network", "published", "env" }) |name| {
        if (member(inner, name) == null) return error.JsonWrong;
    }
}

fn enum_has(schema: Value, wanted: []const []const u8) Error!void {
    const options = member(schema, "enum") orelse return error.JsonWrong;
    if (options != .array) return error.JsonWrong;
    for (wanted) |word| {
        var found = false;
        for (options.array.items) |option| {
            if (option == .string and std.mem.eql(u8, option.string, word)) found = true;
        }
        if (!found) return error.JsonWrong;
    }
}

/// What a container's document says it can reach: `run -d`'s `container` object and an entry of
/// `ps`. `network` is null for a record an older zbx kept.
pub const Reach = struct {
    network: ?[]const u8,
    published: []const Published,
    env: []const []const u8,
};

pub const Detached = struct { name: []const u8, reach: Reach };

fn read_reach(arena: Allocator, value: Value) Error!Reach {
    const network = member(value, "network") orelse return error.ReachWrong;
    const list = member(value, "published") orelse return error.ReachWrong;
    const env = member(value, "env") orelse return error.ReachWrong;
    if (list != .array or env != .array) return error.ReachWrong;
    var published: std.ArrayList(Published) = .empty;
    for (list.array.items) |item| {
        const host = member(item, "host") orelse return error.ReachWrong;
        const container = member(item, "container") orelse return error.ReachWrong;
        if (host != .integer or container != .integer) return error.ReachWrong;
        const forward: Published = .{
            .host = std.math.cast(u32, host.integer) orelse return error.ReachWrong,
            .container = std.math.cast(u32, container.integer) orelse return error.ReachWrong,
        };
        try published.append(arena, forward);
    }
    var names: std.ArrayList([]const u8) = .empty;
    for (env.array.items) |item| {
        if (item != .string) return error.ReachWrong;
        try names.append(arena, item.string);
    }
    if (network != .string and network != .null) return error.ReachWrong;
    return .{
        .network = if (network == .string) network.string else null,
        .published = published.items,
        .env = names.items,
    };
}

/// `run -d --output json` printed `zbx.run/1` on stdout with the container's name and, since M6,
/// what it can reach: the network, the forwards and the names of the `-e` variables.
pub fn check_detached(arena: Allocator, streams: Streams, status: u8) Error!Detached {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_value(arena, streams.stdout);
    const schema = member(doc, "schema") orelse return error.JsonWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.run/1")) return error.JsonWrong;
    const container = member(doc, "container") orelse return error.JsonWrong;
    const name = member(container, "name") orelse return error.JsonWrong;
    if (name != .string or name.string.len == 0) return error.JsonWrong;
    const detached = member(container, "detached") orelse return error.JsonWrong;
    if (detached != .bool or !detached.bool) return error.JsonWrong;
    if (member(doc, "ran") == null) return error.JsonWrong;
    return .{ .name = name.string, .reach = try read_reach(arena, container) };
}

/// The entry of the container `name` in `ps --output json`: running, and with what it can reach.
pub fn ps_reach(arena: Allocator, stdout: []const u8, name: []const u8) Error!Reach {
    const doc = try parse_value(arena, stdout);
    const list = member(doc, "containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |entry| {
        const found = member(entry, "name") orelse continue;
        if (found != .string or !std.mem.eql(u8, found.string, name)) continue;
        const state = member(entry, "state") orelse return error.JsonWrong;
        if (state != .string or !std.mem.eql(u8, state.string, "running")) return error.JsonWrong;
        return read_reach(arena, entry);
    }
    return error.JsonWrong;
}

/// `reach` is the network `network`, the forwards `published` in order, and the `-e` names.
pub fn check_reach(
    reach: Reach,
    network: []const u8,
    published: []const Published,
    env: []const []const u8,
) Error!void {
    const said = reach.network orelse return error.ReachWrong;
    if (!std.mem.eql(u8, said, network)) return error.ReachWrong;
    if (!same_published(reach.published, published)) return error.ReachWrong;
    if (reach.env.len != env.len) return error.ReachWrong;
    for (reach.env, env) |found, wanted| {
        if (!std.mem.eql(u8, found, wanted)) return error.ReachWrong;
    }
}

/// `stop --output json` is `zbx.stop/1` for `name`, and the container was stopped.
pub fn check_stopped(arena: Allocator, streams: Streams, status: u8, name: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_value(arena, streams.stdout);
    const schema = member(doc, "schema") orelse return error.JsonWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.stop/1")) return error.JsonWrong;
    const stopped = member(doc, "name") orelse return error.JsonWrong;
    if (stopped != .string or !std.mem.eql(u8, stopped.string, name)) return error.JsonWrong;
    const result = member(doc, "result") orelse return error.JsonWrong;
    if (result != .string) return error.JsonWrong;
    if (std.mem.eql(u8, result.string, "graceful")) return;
    if (std.mem.eql(u8, result.string, "killed")) return;
    return error.JsonWrong;
}

/// What the agent reads of the doctor's net check: its code and the diagnostic it carries, the
/// same object a failure prints on stderr.
pub const DoctorNet = struct { code: []const u8, diagnostic: agent_json.Diagnostic };

/// `doctor --output json` is the `zbx.doctor/1` document on stdout, nothing on stderr (a warning
/// is not a failure: exit 0), and it follows `schema_text`, the output of `zbx schema doctor`.
/// It lists the seven checks in order, a code only for the ones that are not ok; the `net` check
/// warns with a `ZBX-W` code and a diagnostic whose first fix has a command and says whether
/// it needs root.
pub fn check_doctor_net(
    arena: Allocator,
    streams: Streams,
    status: u8,
    schema_text: []const u8,
) Error!DoctorNet {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.DoctorWrong;
    if (try agent_json.violation(arena, schema_text, streams.stdout)) |_| {
        return error.SchemaViolated;
    }
    const doc = try parse_value(arena, streams.stdout);
    const schema = member(doc, "schema") orelse return error.DoctorWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.doctor/1")) {
        return error.DoctorWrong;
    }
    const list = member(doc, "checks") orelse return error.DoctorWrong;
    if (list != .array or list.array.items.len != 7) return error.DoctorWrong;
    const ids = [_][]const u8{ "kernel", "userns", "cgroup", "overlay", "subid", "seccomp", "net" };
    for (list.array.items, ids) |check, id| {
        const found = member(check, "id") orelse return error.DoctorWrong;
        if (found != .string or !std.mem.eql(u8, found.string, id)) return error.DoctorWrong;
        const state = member(check, "status") orelse return error.DoctorWrong;
        if (state != .string) return error.DoctorWrong;
        const ok = std.mem.eql(u8, state.string, "ok");
        if (ok != (member(check, "code") == null)) return error.DoctorWrong;
        if (!std.mem.eql(u8, id, "net")) continue;
        if (!std.mem.eql(u8, state.string, "warn")) return error.DoctorWrong;
        return try net_warning(arena, check);
    }
    unreachable; // Seven checks were counted, and the last is net.
}

fn net_warning(arena: Allocator, check: Value) Error!DoctorNet {
    const code = member(check, "code") orelse return error.DoctorWrong;
    if (code != .string or !std.mem.startsWith(u8, code.string, "ZBX-W")) return error.DoctorWrong;
    const value = member(check, "diagnostic") orelse return error.DoctorWrong;
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const Diagnostic = agent_json.Diagnostic;
    const diagnostic = std.json.parseFromValueLeaky(Diagnostic, arena, value, options) catch {
        return error.DoctorWrong;
    };
    if (!std.mem.eql(u8, diagnostic.code, code.string)) return error.DoctorWrong;
    if (!std.mem.eql(u8, diagnostic.severity, "warning")) return error.DoctorWrong;
    if (diagnostic.fixes.len == 0) return error.DoctorWrong;
    if (diagnostic.fixes[0].command == null) return error.DoctorWrong;
    return .{ .code = code.string, .diagnostic = diagnostic };
}

/// `explain --output json` for the code the doctor gave agrees with the diagnostic it carried.
pub fn check_explain_of_net(
    arena: Allocator,
    streams: Streams,
    status: u8,
    net: DoctorNet,
) Error!void {
    return agent_json.check_explain(arena, streams, status, net.diagnostic);
}

const testing = std.testing;

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

fn scratch() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

const none_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1,\"network\":\"none\"," ++
    "\"hint\":\"network_none\",\"published\":[]},\"ran\":{\"kind\":\"image\"}}\n";
const explicit_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1," ++
    "\"network\":\"none\"," ++
    "\"published\":[]},\"ran\":{\"kind\":\"image\"}}\n";
const user_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"user\"," ++
    "\"published\":[{\"host\":18091,\"container\":80}]},\"ran\":{\"kind\":\"image\"}}\n";

test "a failed run with no network is read from the exit line's hint" {
    // Goal: the agent's refusal check is JSON-only and needs the hint (M5 finding 1). Method:
    // right; the text note present; no hint (what M5 printed); the wrong network; a code that
    // disagrees with the status; a run that succeeded; the explicit --net none has no hint.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    try check_failed_without_network(arena, captured("", none_line), 1);
    const noted = captured("", none_line ++ "zbx: network: none (grant with --net)\n");
    try testing.expectError(error.ExitLineWrong, check_failed_without_network(arena, noted, 1));
    try testing.expectError(
        error.HintMissing,
        check_failed_without_network(arena, captured("", explicit_line), 1),
    );
    const host = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1,\"network\":\"host\"}}\n";
    try testing.expectError(
        error.ExitLineWrong,
        check_failed_without_network(arena, captured("", host), 1),
    );
    try testing.expectError(
        error.ExitLineWrong,
        check_failed_without_network(arena, captured("", none_line), 2),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_failed_without_network(arena, captured("", none_line), 0),
    );
    // Without the member (a release before M5) there is nothing to read.
    const old = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1}}\n";
    try testing.expectError(
        error.ExitLineWrong,
        check_failed_without_network(arena, captured("", old), 1),
    );
    try check_failed_with_explicit_none(arena, captured("", explicit_line), 1);
    try testing.expectError(
        error.HintUnexpected,
        check_failed_with_explicit_none(arena, captured("", none_line), 1),
    );
}

test "a granted run names its network and its forwards, and has no hint" {
    // Goal: the published ports are read from JSON. Method: right; another port; a missing
    // forward; none expected but one found; a member left out reads as none; a hint on a run
    // that worked is wrong.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const wanted = [_]Published{.{ .host = 18091, .container = 80 }};
    try check_granted(arena, captured("", user_line), 0, "user", &wanted);
    const other = [_]Published{.{ .host = 18092, .container = 80 }};
    try testing.expectError(
        error.ExitLineWrong,
        check_granted(arena, captured("", user_line), 0, "user", &other),
    );
    try testing.expectError(
        error.ExitLineWrong,
        check_granted(arena, captured("", user_line), 0, "user", &.{}),
    );
    try testing.expectError(
        error.ExitLineWrong,
        check_granted(arena, captured("", user_line), 0, "host", &wanted),
    );
    const bare = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"host\"}}\n";
    try check_granted(arena, captured("", bare), 0, "host", &.{});
    const failed = check_granted(arena, captured("", bare), 1, "host", &.{});
    try testing.expectError(error.ExitCodeWrong, failed);
    const hinted = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"none\"," ++
        "\"hint\":\"network_none\"}}\n";
    try testing.expectError(
        error.HintUnexpected,
        check_granted(arena, captured("", hinted), 0, "none", &.{}),
    );
}

// Captured from src/testdata/diag/E0601.json.txt, which the golden test renders.
const missing_pasta = "{\"code\":\"ZBX-E0601\",\"severity\":\"error\",\"blame\":\"environment\"," ++
    "\"summary\":\"pasta is not installed\",\"causes\":[\"no executable named pasta in the " ++
    "directories of PATH\"],\"while\":[\"connecting the container to the network " ++
    "(--net user)\"]," ++
    "\"context\":{},\"fixes\":[{\"sentence\":\"install pasta (Debian, Ubuntu):\"," ++
    "\"command\":\"sudo apt install passt\",\"needs_root\":true}," ++
    "{\"sentence\":\"or run with the host's network:\"," ++
    "\"command\":\"zbx run --net host alpine -- sh\",\"template\":true}]," ++
    "\"docs\":\"https://zigbox.github.io/zigbox/errors/E0601.html\"," ++
    "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

test "a missing pasta is read from the diagnostic's code and fixes, and their flags" {
    // Goal: the agent needs no text, and the fixes say what they need (M5 finding 4). Method:
    // the golden; a run that started; another code; the wrong exit; only one fix; the flags
    // swapped or missing (what M5 printed); the fix's mode only from a template.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const found = try check_pasta_missing(arena, captured("", missing_pasta), 125);
    try testing.expectEqualStrings("ZBX-E0601", found.code);
    try testing.expectEqualStrings("host", try fix_net_mode(found));
    try testing.expectError(
        error.ExitCodeWrong,
        check_pasta_missing(arena, captured("", missing_pasta), 1),
    );
    const started = captured("", missing_pasta ++ none_line);
    try testing.expectError(error.DiagnosticWrong, check_pasta_missing(arena, started, 125));
    const other = try std.mem.replaceOwned(u8, arena, missing_pasta, "E0601", "E0603");
    try testing.expectError(
        error.DiagnosticWrong,
        check_pasta_missing(arena, captured("", other), 125),
    );
    const lone = "{\"code\":\"ZBX-E0601\",\"severity\":\"error\",\"blame\":\"environment\"," ++
        "\"summary\":\"s\",\"causes\":[\"c\"],\"context\":{},\"fixes\":[{\"sentence\":\"i\"," ++
        "\"command\":\"sudo apt install passt\"}],\"docs\":\"d\"}\n";
    try testing.expectError(error.FixWrong, check_pasta_missing(arena, captured("", lone), 125));
    const root_flag = ",\"needs_root\":true";
    const unflagged = try std.mem.replaceOwned(u8, arena, missing_pasta, root_flag, "");
    try testing.expectError(
        error.FlagsWrong,
        check_pasta_missing(arena, captured("", unflagged), 125),
    );
    const swapped = try std.mem.replaceOwned(u8, arena, missing_pasta, "template", "needs_root");
    try testing.expectError(
        error.FlagsWrong,
        check_pasta_missing(arena, captured("", swapped), 125),
    );
    const no_host = try found_without_host(arena);
    try testing.expectError(error.FixWrong, fix_net_mode(no_host));
    // A fix of M5 had no flags: the agent could not tell a template from a command to run.
    const plain = try std.mem.replaceOwned(u8, arena, missing_pasta, ",\"template\":true", "");
    const m5 = try agent_json.diagnostics(arena, plain);
    try testing.expectError(error.FixWrong, fix_net_mode(m5[0]));
}

fn found_without_host(arena: Allocator) !agent_json.Diagnostic {
    const fixes = try arena.dupe(agent_json.Fix, &.{
        .{ .sentence = "install", .command = "sudo apt install passt", .needs_root = true },
        .{ .sentence = "run", .command = "zbx run alpine -- sh", .template = true },
    });
    return .{
        .code = "ZBX-E0601",
        .severity = "error",
        .blame = "environment",
        .summary = "s",
        .context = .null,
        .fixes = fixes,
        .docs = "d",
    };
}

test "the run schema describes the network members without a $ref" {
    // Goal: the agent relies on a member only after the schema names it, and reads the schema as
    // it is (M5 finding 6). Method: the shape of src/schemas.zig's run schema; the same without
    // `published`; with a short enum; with a `$ref` left in it.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const right =
        \\{"properties":{"container_exit":{"properties":{
        \\"network":{"enum":["none","host","user"]},"hint":{"enum":["network_none"]},
        \\"published":{"type":"array","items":{"type":"object","required":["host","container"]}}
        \\}},"container":{"properties":{"network":{},"published":{},"env":{}}}}}
    ;
    try schema_describes_network(arena, right);
    const short = try std.mem.replaceOwned(u8, arena, right, ",\"user\"", "");
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, short));
    const cut_from = "\"published\":{\"type";
    const cut = try std.mem.replaceOwned(u8, arena, right, cut_from, "\"forwarded\":{\"type");
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, cut));
    const no_hint = try std.mem.replaceOwned(u8, arena, right, "network_none", "other");
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, no_hint));
    const ref = "\"env\":{\"$ref\":\"#/x\"}";
    const refs = try std.mem.replaceOwned(u8, arena, right, "\"env\":{}", ref);
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, refs));
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, "{}"));
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, "not json"));
}

test "a detached run and ps say the network, the forwards and the names, and stop is read" {
    // Goal: M5 findings 2 and 3 are closed. Method: documents shaped like src/cli.zig's and
    // src/commands.zig's; a document without the members (M5's); a wrong name; a stopped
    // container; a bad stop result.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const detached = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web-1\",\"pid\":502," ++
        "\"scope\":null,\"detached\":true,\"network\":\"user\"," ++
        "\"published\":[{\"host\":18092,\"container\":80}],\"env\":[\"A_B\"]}," ++
        "\"ran\":{\"kind\":\"image\"}}\n";
    const read = try check_detached(arena, captured(detached, ""), 0);
    try testing.expectEqualStrings("web-1", read.name);
    const forwards = [_]Published{.{ .host = 18092, .container = 80 }};
    try check_reach(read.reach, "user", &forwards, &.{"A_B"});
    const wrong_mode = check_reach(read.reach, "host", &forwards, &.{"A_B"});
    try testing.expectError(error.ReachWrong, wrong_mode);
    try testing.expectError(error.ReachWrong, check_reach(read.reach, "user", &.{}, &.{"A_B"}));
    try testing.expectError(error.ReachWrong, check_reach(read.reach, "user", &forwards, &.{}));
    const m5 = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web-1\",\"pid\":502," ++
        "\"scope\":null,\"detached\":true},\"ran\":{\"kind\":\"image\"}}\n";
    try testing.expectError(error.ReachWrong, check_detached(arena, captured(m5, ""), 0));
    try testing.expectError(error.JsonWrong, check_detached(arena, captured("{}", ""), 0));
    const ps = "{\"schema\":\"zbx.ps/1\",\"containers\":[" ++
        "{\"name\":\"web-1\",\"state\":\"running\",\"network\":\"user\"," ++
        "\"published\":[{\"host\":18092,\"container\":80}],\"env\":[\"A_B\"]}," ++
        "{\"name\":\"old\",\"state\":\"stopped\",\"network\":null,\"published\":[],\"env\":[]}]}\n";
    try check_reach(try ps_reach(arena, ps, "web-1"), "user", &forwards, &.{"A_B"});
    try testing.expectError(error.JsonWrong, ps_reach(arena, ps, "old"));
    try testing.expectError(error.JsonWrong, ps_reach(arena, ps, "gone"));
    const bare = "{\"containers\":[{\"name\":\"web-1\",\"state\":\"running\"}]}";
    try testing.expectError(error.ReachWrong, ps_reach(arena, bare, "web-1"));
    const stop = "{\"schema\":\"zbx.stop/1\",\"name\":\"web-1\",\"result\":\"graceful\"}\n";
    try check_stopped(arena, captured(stop, ""), 0, "web-1");
    try testing.expectError(error.JsonWrong, check_stopped(arena, captured(stop, ""), 0, "web-2"));
    const odd = "{\"schema\":\"zbx.stop/1\",\"name\":\"web-1\",\"result\":\"already_stopped\"}\n";
    try testing.expectError(error.JsonWrong, check_stopped(arena, captured(odd, ""), 0, "web-1"));
}

const doctor_schema_text =
    \\{"type":"object","properties":{"schema":{"const":"zbx.doctor/1"},"ok":{"type":"boolean"},
    \\"checks":{"type":"array","items":{"type":"object","required":["id","status","detail"],
    \\"properties":{"status":{"enum":["ok","warn","fail"]}}}}},
    \\"oneOf":[{"required":["schema","ok","checks"]},{"required":["code","severity"]}]}
;

fn doctor_document(arena: Allocator, net: []const u8) ![]const u8 {
    const ids = [_][]const u8{ "kernel", "userns", "cgroup", "overlay", "subid", "seccomp" };
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, "{\"schema\":\"zbx.doctor/1\",\"ok\":true,\"checks\":[");
    for (ids) |id| {
        const format = "{{\"id\":\"{s}\",\"status\":\"ok\",\"detail\":\"fine\"}},";
        try text.print(arena, format, .{id});
    }
    try text.appendSlice(arena, net);
    try text.appendSlice(arena, "]}\n");
    return text.items;
}

const net_warning_check = "{\"id\":\"net\",\"status\":\"warn\",\"detail\":\"pasta not found\"," ++
    "\"code\":\"ZBX-W0102\",\"diagnostic\":{\"code\":\"ZBX-W0102\",\"severity\":\"warning\"," ++
    "\"blame\":\"environment\",\"summary\":\"s\",\"causes\":[\"c\"],\"context\":{},\"fixes\":" ++
    "[{\"sentence\":\"install pasta:\",\"command\":\"sudo apt install passt\"," ++
    "\"needs_root\":true}],\"docs\":\"d\"}}";

test "doctor's json carries the net warning with a code and a fix that needs root" {
    // Goal: M5 finding 5 is closed. Method: the document with a net warning; the same with the
    // check ok (no code); a code on an ok check; stderr noise; a failed exit; the schema broken.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const good = try doctor_document(arena, net_warning_check);
    const net = try check_doctor_net(arena, captured(good, ""), 0, doctor_schema_text);
    try testing.expectEqualStrings("ZBX-W0102", net.code);
    try testing.expectEqualStrings("sudo apt install passt", net.diagnostic.fixes[0].command.?);
    try testing.expect(net.diagnostic.fixes[0].needs_root);
    const healthy = "{\"id\":\"net\",\"status\":\"ok\",\"detail\":\"pasta at /usr/bin/pasta\"}";
    const ok_doc = try doctor_document(arena, healthy);
    try testing.expectError(
        error.DoctorWrong,
        check_doctor_net(arena, captured(ok_doc, ""), 0, doctor_schema_text),
    );
    const text_report = "ok   kernel  6.8\nwarn net  pasta not found\n";
    try testing.expectError(
        error.JsonWrong,
        check_doctor_net(arena, captured(text_report, ""), 0, doctor_schema_text),
    );
    try testing.expectError(
        error.DoctorWrong,
        check_doctor_net(arena, captured(good, "x\n"), 0, doctor_schema_text),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_doctor_net(arena, captured(good, ""), 2, doctor_schema_text),
    );
    const bad_status = try std.mem.replaceOwned(u8, arena, good, "\"warn\"", "\"maybe\"");
    try testing.expectError(
        error.SchemaViolated,
        check_doctor_net(arena, captured(bad_status, ""), 0, doctor_schema_text),
    );
    const coded = "\"code\":\"ZBX-W0102\",\"diagnostic";
    const no_code = try std.mem.replaceOwned(u8, arena, good, coded, "\"diagnostic");
    try testing.expectError(
        error.DoctorWrong,
        check_doctor_net(arena, captured(no_code, ""), 0, doctor_schema_text),
    );
}

test "-e values reach the container, not zbx's output; an unset -e NAME is E0011" {
    // Goal: the agent's -e checks. Method: right; a value on stderr; a value missing from the
    // program's output; and the refusal with its flags, a wrong code, a fix that is not a
    // template.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0}}\n";
    try check_env_reached(captured("v-1 c-2\n", line), 0, "v-1", "c-2");
    const leaked = line ++ "zbx: v-1\n";
    const both = "v-1 c-2\n";
    const on_stderr = check_env_reached(captured(both, leaked), 0, "v-1", "c-2");
    try testing.expectError(error.ReachWrong, on_stderr);
    const one_only = check_env_reached(captured("v-1\n", line), 0, "v-1", "c-2");
    try testing.expectError(error.ReachWrong, one_only);
    const bad_exit = check_env_reached(captured(both, line), 1, "v-1", "c-2");
    try testing.expectError(error.ExitCodeWrong, bad_exit);
    const no_line = check_env_reached(captured(both, ""), 0, "v-1", "c-2");
    try testing.expectError(error.ExitLineWrong, no_line);

    const refusal = "{\"code\":\"ZBX-E0011\",\"severity\":\"error\",\"blame\":\"user\"," ++
        "\"summary\":\"s\",\"causes\":[\"c\"],\"context\":{\"name\":\"AGENT_NOT_SET\"}," ++
        "\"fixes\":[{\"sentence\":\"a\",\"command\":\"zbx run -e NAME=VALUE ...\"," ++
        "\"template\":true}]," ++
        "\"docs\":\"d\"}\n";
    const found = try check_env_unset(arena, captured("", refusal), 125);
    try testing.expectEqualStrings("ZBX-E0011", found.code);
    try testing.expectError(error.ExitCodeWrong, check_env_unset(arena, captured("", refusal), 1));
    const other = try std.mem.replaceOwned(u8, arena, refusal, "E0011", "E0010");
    const wrong_code = check_env_unset(arena, captured("", other), 125);
    try testing.expectError(error.DiagnosticWrong, wrong_code);
    const plain = try std.mem.replaceOwned(u8, arena, refusal, ",\"template\":true", "");
    try testing.expectError(error.FlagsWrong, check_env_unset(arena, captured("", plain), 125));
    const both_flags = "\"needs_root\":true,\"template\":true";
    const rooted = try std.mem.replaceOwned(u8, arena, refusal, "\"template\":true", both_flags);
    try testing.expectError(error.FlagsWrong, check_env_unset(arena, captured("", rooted), 125));
    const elsewhere = try std.mem.replaceOwned(u8, arena, refusal, "AGENT_NOT_SET", "OTHER");
    const wrong_name = check_env_unset(arena, captured("", elsewhere), 125);
    try testing.expectError(error.DiagnosticWrong, wrong_name);
}
