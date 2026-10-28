//! What the scripted agent of demo-m5 (agent_m5.zig) reads: the network members of `zbx run
//! --output json` and the ZBX-E0601 diagnostic, as JSON and nothing else. Its pure parts, each
//! unit-tested with right and wrong input. What the agent needs and cannot read from JSON is a
//! finding (docs/demos/m5.md, "The agent test"); the `*_in_json` functions below answer "is it
//! there?" with a bool so that the demo records the finding without failing on it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");

const Streams = checks.Streams;
pub const Error = agent_json.Error;

pub const Published = struct { host: u32, container: u32 };

/// The members of the `container_exit` object that the network adds (zbx.run/1).
pub const NetExit = struct {
    reason: []const u8,
    code: u32,
    network: ?[]const u8 = null,
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
/// published, and the text note of the text mode is not there. The agent decides to grant a
/// network from `network` and the code; it has no member that says the network was the cause.
pub fn check_failed_without_network(arena: Allocator, streams: Streams, status: u8) Error!void {
    if (status == 0) return error.ExitCodeWrong;
    const line = try net_exit(arena, streams.stderr);
    if (!std.mem.eql(u8, line.reason, "exited")) return error.ExitLineWrong;
    if (line.code != status) return error.ExitLineWrong;
    const network = line.network orelse return error.ExitLineWrong;
    if (!std.mem.eql(u8, network, "none")) return error.ExitLineWrong;
    if (!same_published(line.published, &.{})) return error.ExitLineWrong;
    if (std.mem.indexOf(u8, streams.stderr, "grant with --net") != null) return error.ExitLineWrong;
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
    return first;
}

/// The network mode a fix of `diagnostic` runs with: `host` when one fix's command is a
/// `zbx run --net host ...` line. The agent applies that flag to its own command; the fix's
/// command itself is a placeholder (`alpine -- sh`) that it must not run.
pub fn fix_net_mode(diagnostic: agent_json.Diagnostic) Error![]const u8 {
    for (diagnostic.fixes) |fix| {
        const command = fix.command orelse continue;
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

/// The agent reads `zbx schema run` before it relies on `network` and `published`: the
/// `container_exit` object lists `network` (with `none`, `host` and `user`) and `published`, an
/// array of objects that require `host` and `container`.
pub fn schema_describes_network(arena: Allocator, schema_text: []const u8) Error!void {
    const schema = try parse_value(arena, schema_text);
    const defs = member(schema, "$defs") orelse return error.JsonWrong;
    const exit = member(defs, "container_exit") orelse return error.JsonWrong;
    const outer = member(exit, "properties") orelse return error.JsonWrong;
    const inner = member(outer, "container_exit") orelse return error.JsonWrong;
    const properties = member(inner, "properties") orelse return error.JsonWrong;
    const network = member(properties, "network") orelse return error.JsonWrong;
    const options = member(network, "enum") orelse return error.JsonWrong;
    if (options != .array) return error.JsonWrong;
    for ([_][]const u8{ "none", "host", "user" }) |wanted| {
        var found = false;
        for (options.array.items) |option| {
            if (option == .string and std.mem.eql(u8, option.string, wanted)) found = true;
        }
        if (!found) return error.JsonWrong;
    }
    const published = member(properties, "published") orelse return error.JsonWrong;
    const kind = member(published, "type") orelse return error.JsonWrong;
    if (kind != .string or !std.mem.eql(u8, kind.string, "array")) return error.JsonWrong;
    const items = member(published, "items") orelse return error.JsonWrong;
    const required = member(items, "required") orelse return error.JsonWrong;
    if (required != .array or required.array.items.len != 2) return error.JsonWrong;
}

pub const Detached = struct { name: []const u8, network_in_json: bool };

fn has_network_member(value: Value) bool {
    return member(value, "network") != null or member(value, "published") != null;
}

/// `run -d --output json` printed `zbx.run/1` on stdout with the container's name; the second
/// field says whether the document says anything about the network (it does not: a finding).
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
    const ran = member(doc, "ran") orelse return error.JsonWrong;
    const said = has_network_member(doc) or has_network_member(container) or
        has_network_member(ran);
    return .{ .name = name.string, .network_in_json = said };
}

/// Whether `ps --output json` says anything about the network of the container `name` (the
/// finding is that it does not). The container must be listed, and running.
pub fn ps_network_in_json(arena: Allocator, stdout: []const u8, name: []const u8) Error!bool {
    const doc = try parse_value(arena, stdout);
    const list = member(doc, "containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |entry| {
        const found = member(entry, "name") orelse continue;
        if (found != .string or !std.mem.eql(u8, found.string, name)) continue;
        const state = member(entry, "state") orelse return error.JsonWrong;
        if (state != .string or !std.mem.eql(u8, state.string, "running")) return error.JsonWrong;
        return has_network_member(entry);
    }
    return error.JsonWrong;
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

/// Whether `doctor --output json` carries the `net` check in any machine-readable form: a
/// diagnostic on stderr that names pasta, or a JSON document on stdout. It does not (the net
/// check only warns, and a warning is a line of the text report): a finding.
pub fn doctor_net_in_json(arena: Allocator, streams: Streams, status: u8) Error!bool {
    if (status != 0) return error.ExitCodeWrong;
    const all = try agent_json.diagnostics(arena, streams.stderr);
    for (all) |one| {
        if (std.mem.indexOf(u8, one.summary, "pasta") != null) return true;
    }
    const text = std.mem.trim(u8, streams.stdout, " \r\n\t");
    return std.mem.startsWith(u8, text, "{") and std.mem.indexOf(u8, text, "pasta") != null;
}

const testing = std.testing;

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

fn scratch() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

const none_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":1,\"network\":\"none\"," ++
    "\"published\":[]},\"ran\":{\"kind\":\"image\"}}\n";
const user_line = "{\"container_exit\":{\"reason\":\"exited\",\"code\":0,\"network\":\"user\"," ++
    "\"published\":[{\"host\":18091,\"container\":80}]},\"ran\":{\"kind\":\"image\"}}\n";

test "a failed run with no network is read from the exit line alone" {
    // Goal: the agent's refusal check is JSON-only. Method: right; the text note present; the
    // wrong network; a code that disagrees with the status; a run that succeeded.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    try check_failed_without_network(arena, captured("", none_line), 1);
    const noted = captured("", none_line ++ "zbx: network: none (grant with --net)\n");
    try testing.expectError(error.ExitLineWrong, check_failed_without_network(arena, noted, 1));
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
}

test "a granted run names its network and its forwards" {
    // Goal: the published ports are read from JSON. Method: right; another port; a missing
    // forward; none expected but one found; a member left out reads as none.
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
}

// Captured from src/testdata/diag/E0601.json.txt, which the golden test renders.
const missing_pasta = "{\"code\":\"ZBX-E0601\",\"severity\":\"error\",\"blame\":\"environment\"," ++
    "\"summary\":\"pasta is not installed\",\"causes\":[\"no executable named pasta in the " ++
    "directories of PATH\"],\"while\":[\"connecting the container to the network " ++
    "(--net user)\"]," ++
    "\"context\":{},\"fixes\":[{\"sentence\":\"install pasta (Debian, Ubuntu):\"," ++
    "\"command\":\"sudo apt install passt\"},{\"sentence\":\"or run with the host's network:\"," ++
    "\"command\":\"zbx run --net host alpine -- sh\"}]," ++
    "\"docs\":\"https://zigbox.github.io/zigbox/errors/E0601.html\"," ++
    "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

test "a missing pasta is read from the diagnostic's code and fixes" {
    // Goal: the agent needs no text. Method: the golden; a run that started; another code; the
    // wrong exit; only one fix; the fix's mode.
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
    const no_host = try found_without_host(arena);
    try testing.expectError(error.FixWrong, fix_net_mode(no_host));
}

fn found_without_host(arena: Allocator) !agent_json.Diagnostic {
    const fixes = try arena.dupe(agent_json.Fix, &.{
        .{ .sentence = "install", .command = "sudo apt install passt" },
        .{ .sentence = "run", .command = "zbx run alpine -- sh" },
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

test "the run schema describes the network members" {
    // Goal: the agent relies on a member only after the schema names it. Method: the shape of
    // src/schemas.zig's run schema; the same without `published`; with a short enum.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const right =
        \\{"$defs":{"container_exit":{"properties":{"container_exit":{"properties":{
        \\"network":{"enum":["none","host","user"]},
        \\"published":{"type":"array","items":{"type":"object","required":["host","container"]}}
        \\}}}}}}
    ;
    try schema_describes_network(arena, right);
    const short = try std.mem.replaceOwned(u8, arena, right, ",\"user\"", "");
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, short));
    const cut = try std.mem.replaceOwned(u8, arena, right, "published", "forwarded");
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, cut));
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, "{}"));
    try testing.expectError(error.JsonWrong, schema_describes_network(arena, "not json"));
}

test "a detached run, ps and stop are read for the container, and the network is not in them" {
    // Goal: the findings are measured, not assumed. Method: the documents of src/cli.zig's tests;
    // the same with a network member; a wrong name; a stopped container; a bad stop result.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const detached = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web-1\",\"pid\":502," ++
        "\"scope\":null,\"detached\":true},\"ran\":{\"kind\":\"image\"}}\n";
    const read = try check_detached(arena, captured(detached, ""), 0);
    try testing.expectEqualStrings("web-1", read.name);
    try testing.expect(!read.network_in_json);
    const said = "{\"schema\":\"zbx.run/1\",\"container\":{\"name\":\"web-1\",\"pid\":502," ++
        "\"scope\":null,\"detached\":true,\"network\":\"user\"},\"ran\":{\"kind\":\"image\"}}\n";
    try testing.expect((try check_detached(arena, captured(said, ""), 0)).network_in_json);
    try testing.expectError(error.JsonWrong, check_detached(arena, captured("{}", ""), 0));
    const ps = "{\"schema\":\"zbx.ps/1\",\"containers\":" ++
        "[{\"name\":\"web-1\",\"state\":\"running\"}," ++
        "{\"name\":\"old\",\"state\":\"stopped\"}]}\n";
    try testing.expect(!try ps_network_in_json(arena, ps, "web-1"));
    try testing.expectError(error.JsonWrong, ps_network_in_json(arena, ps, "old"));
    try testing.expectError(error.JsonWrong, ps_network_in_json(arena, ps, "gone"));
    const stop = "{\"schema\":\"zbx.stop/1\",\"name\":\"web-1\",\"result\":\"graceful\"}\n";
    try check_stopped(arena, captured(stop, ""), 0, "web-1");
    try testing.expectError(error.JsonWrong, check_stopped(arena, captured(stop, ""), 0, "web-2"));
    const odd = "{\"schema\":\"zbx.stop/1\",\"name\":\"web-1\",\"result\":\"already_stopped\"}\n";
    try testing.expectError(error.JsonWrong, check_stopped(arena, captured(odd, ""), 0, "web-1"));
}

test "doctor's json does not carry the net warning" {
    // Goal: the finding about doctor. Method: the text report alone; a diagnostic that names
    // pasta; a failed doctor.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const report = "ok   seccomp  s\nwarn net  pasta not found: --net user (apt install passt)\n";
    try testing.expect(!try doctor_net_in_json(arena, captured(report, ""), 0));
    const named = "is not installed";
    const diagnostic = try std.mem.replaceOwned(u8, arena, missing_pasta, named, "pasta x");
    try testing.expect(try doctor_net_in_json(arena, captured(report, diagnostic), 0));
    const failed = doctor_net_in_json(arena, captured(report, ""), 2);
    try testing.expectError(error.ExitCodeWrong, failed);
}
