//! What the scripted agent of demo-m6 (agent_m6.zig) reads: the documents of M6's state volumes,
//! as JSON and nothing else. `state ls`, `state rm`, `state restore` and `state export -o`, the
//! pid of a container in `ps`, the refusals of the `07xx` codes and the W0703 note of an export.
//! Its pure parts, each unit-tested with right and wrong input. The fixtures that a zbx wrote
//! (`state ls`, `rm`, `restore`, `export`, the `E0706`, `E0707` and `W0703` lines) were captured
//! from the built binary, and the diagnostics from the goldens in src/testdata/diag.
//!
//! The rule of the agent test: what the agent needs and cannot read from these is a finding
//! (docs/demos/m6.md, "The agent test"), not something to guess. `holder_in_context` and
//! `entry_has_any` exist so that the agent can tell a finding from a regression.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");

const Streams = checks.Streams;
pub const Error = agent_json.Error || error{
    /// A `state ls`, `rm`, `restore` or `export` document says something it should not.
    StateWrong,
    /// A container has no pid the agent can signal.
    PidWrong,
    /// A refusal lacks its code, its exit status or the volume in its context.
    RefusalWrong,
};

fn parse_value(arena: Allocator, text: []const u8) Error!Value {
    const options: std.json.ParseOptions = .{ .allocate = .alloc_always };
    return std.json.parseFromSliceLeaky(Value, arena, text, options) catch return error.JsonWrong;
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

fn integer_of(value: Value, name: []const u8) ?i64 {
    const found = member(value, name) orelse return null;
    if (found != .integer) return null;
    return found.integer;
}

/// The document is the object `schema_id` names, on stdout, with nothing on stderr.
fn document(arena: Allocator, streams: Streams, status: u8, schema_id: []const u8) Error!Value {
    if (status != 0) return error.ExitCodeWrong;
    if (streams.stderr.len != 0) return error.StateWrong;
    const doc = try parse_value(arena, streams.stdout);
    const said = string_of(doc, "schema") orelse return error.StateWrong;
    if (!std.mem.eql(u8, said, schema_id)) return error.StateWrong;
    return doc;
}

/// A schema the agent follows as it is: no `$ref` to resolve.
pub fn check_flat(schema_text: []const u8) Error!void {
    if (std.mem.indexOf(u8, schema_text, "\"$ref\"") != null) return error.JsonWrong;
}

// ---- ps -----------------------------------------------------------------------------------

/// The pid of the running container `name` in `ps --output json`: the process the agent signals.
pub fn ps_pid(arena: Allocator, stdout: []const u8, name: []const u8) Error!u32 {
    const entry = try ps_entry(arena, stdout, name);
    const state = string_of(entry, "state") orelse return error.PidWrong;
    if (!std.mem.eql(u8, state, "running")) return error.PidWrong;
    const pid = integer_of(entry, "pid") orelse return error.PidWrong;
    if (pid <= 1) return error.PidWrong; // Never init, never the agent's own shell.
    return std.math.cast(u32, pid) orelse error.PidWrong;
}

fn ps_entry(arena: Allocator, stdout: []const u8, name: []const u8) Error!Value {
    const doc = try parse_value(arena, stdout);
    const list = member(doc, "containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |entry| {
        const found = string_of(entry, "name") orelse continue;
        if (std.mem.eql(u8, found, name)) return entry;
    }
    return error.PidWrong;
}

/// Whether the entry of `name` in `ps` has any of the members `keys`. The agent asks it to know
/// whether `ps` can say which volumes a container mounts (it cannot: a finding).
pub fn entry_has_any(
    arena: Allocator,
    stdout: []const u8,
    name: []const u8,
    keys: []const []const u8,
) Error!bool {
    const entry = try ps_entry(arena, stdout, name);
    for (keys) |key| {
        if (member(entry, key) != null) return true;
    }
    return false;
}

// ---- refusals -----------------------------------------------------------------------------

/// A refusal read from JSON: the process status is `exit`, nothing is on stdout, one diagnostic
/// on stderr has `code`, is an error blamed on the user, names `volume` in its `context`, and has
/// a fix with a command.
pub fn check_refusal(
    arena: Allocator,
    streams: Streams,
    status: u8,
    exit: u8,
    code: []const u8,
    volume: []const u8,
) Error!agent_json.Diagnostic {
    if (status != exit) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.RefusalWrong;
    const all = try agent_json.diagnostics(arena, streams.stderr);
    if (all.len != 1) return error.RefusalWrong;
    const found = all[0];
    if (!std.mem.eql(u8, found.code, code)) return error.RefusalWrong;
    if (!std.mem.eql(u8, found.severity, "error")) return error.RefusalWrong;
    if (!std.mem.eql(u8, found.blame, "user")) return error.RefusalWrong;
    const named = member(found.context, "volume") orelse return error.RefusalWrong;
    if (named != .string or !std.mem.eql(u8, named.string, volume)) return error.RefusalWrong;
    if (found.fixes.len == 0) return error.FixWrong;
    if (found.fixes[0].command == null) return error.FixWrong;
    return found;
}

/// The container that holds the volume, if the refusal's `context` names it: a `holder` member,
/// or a `container` member. E0706's context names the volume only (a finding), so the agent
/// learns the holder from `state ls`.
pub fn holder_in_context(found: agent_json.Diagnostic) ?[]const u8 {
    if (string_of(found.context, "holder")) |holder| return holder;
    return string_of(found.context, "container");
}

/// The trash entry a refusal of `restore` names in its context (E0708, E0710).
pub fn trash_in_context(found: agent_json.Diagnostic) ?[]const u8 {
    return string_of(found.context, "trash");
}

// ---- state ls -----------------------------------------------------------------------------

/// What the agent reads of one volume in `state ls`.
pub const Volume = struct {
    disk_bytes: ?i64,
    files: ?i64,
    last_container: ?[]const u8,
    in_use: bool,
    /// The first container in `used_by`: who holds it now.
    holder: ?[]const u8,
};

/// `state ls --output json` is `zbx.state.ls/1`, and lists the volume `name`.
pub fn read_volume(arena: Allocator, streams: Streams, status: u8, name: []const u8) Error!Volume {
    const doc = try document(arena, streams, status, "zbx.state.ls/1");
    const volumes = member(doc, "volumes") orelse return error.StateWrong;
    if (volumes != .array) return error.StateWrong;
    for (volumes.array.items) |item| {
        const found = string_of(item, "name") orelse return error.StateWrong;
        if (!std.mem.eql(u8, found, name)) continue;
        return volume_of(item);
    }
    return error.StateWrong;
}

fn volume_of(item: Value) Error!Volume {
    const in_use = member(item, "in_use") orelse return error.StateWrong;
    if (in_use != .bool) return error.StateWrong;
    const users = member(item, "used_by") orelse return error.StateWrong;
    if (users != .array) return error.StateWrong;
    // In use means a holder is named, and the other way round.
    if (in_use.bool != (users.array.items.len > 0)) return error.StateWrong;
    var holder: ?[]const u8 = null;
    if (users.array.items.len > 0) holder = string_of(users.array.items[0], "container");
    if (in_use.bool and holder == null) return error.StateWrong;
    return .{
        .disk_bytes = integer_of(item, "disk_bytes"),
        .files = integer_of(item, "files"),
        .last_container = string_of(item, "last_container"),
        .in_use = in_use.bool,
        .holder = holder,
    };
}

/// `state ls` lists no volume called `name`.
pub fn check_unlisted(arena: Allocator, streams: Streams, status: u8, name: []const u8) Error!void {
    if (read_volume(arena, streams, status, name)) |_| {
        return error.StateWrong;
    } else |err| switch (err) {
        error.StateWrong => {},
        else => return err,
    }
    // The error above is also what a malformed listing gives: tell the two apart.
    const doc = try document(arena, streams, status, "zbx.state.ls/1");
    const volumes = member(doc, "volumes") orelse return error.StateWrong;
    if (volumes != .array) return error.StateWrong;
    for (volumes.array.items) |item| {
        const found = string_of(item, "name") orelse return error.StateWrong;
        if (std.mem.eql(u8, found, name)) return error.StateWrong;
    }
}

pub const Trash = struct { entry: []const u8, removed: i64, expires: i64, expired: bool };

/// The newest entry of the trash that holds the volume `name`, in `state ls --output json`.
pub fn read_trash(arena: Allocator, streams: Streams, status: u8, name: []const u8) Error!Trash {
    const doc = try document(arena, streams, status, "zbx.state.ls/1");
    const list = member(doc, "trash") orelse return error.StateWrong;
    if (list != .array) return error.StateWrong;
    var newest: ?Trash = null;
    for (list.array.items) |item| {
        const found = string_of(item, "name") orelse return error.StateWrong;
        if (!std.mem.eql(u8, found, name)) continue;
        const flag = member(item, "expired") orelse return error.StateWrong;
        const entry: Trash = .{
            .entry = string_of(item, "entry") orelse return error.StateWrong,
            .removed = integer_of(item, "removed") orelse return error.StateWrong,
            .expires = integer_of(item, "expires") orelse return error.StateWrong,
            .expired = flag == .bool and flag.bool,
        };
        if (flag != .bool) return error.StateWrong;
        if (newest == null or entry.removed > newest.?.removed) newest = entry;
    }
    return newest orelse error.StateWrong;
}

// ---- rm, restore, export -------------------------------------------------------------------

pub const Removed = struct { entry: []const u8, removed: i64, expires: i64 };

/// `state rm NAME --output json` is `zbx.state.rm/1`: the entry in the trash is `NAME@<removed>`
/// and it expires after it was removed.
pub fn check_rm(arena: Allocator, streams: Streams, status: u8, name: []const u8) Error!Removed {
    const doc = try document(arena, streams, status, "zbx.state.rm/1");
    const named = string_of(doc, "name") orelse return error.StateWrong;
    if (!std.mem.eql(u8, named, name)) return error.StateWrong;
    const entry = string_of(doc, "entry") orelse return error.StateWrong;
    const removed = integer_of(doc, "removed") orelse return error.StateWrong;
    const expires = integer_of(doc, "expires") orelse return error.StateWrong;
    const emptied = integer_of(doc, "emptied") orelse return error.StateWrong;
    if (emptied < 0) return error.StateWrong;
    if (removed <= 0 or expires <= removed) return error.StateWrong;
    var expect: [96]u8 = undefined;
    const text = std.fmt.bufPrint(&expect, "{s}@{d}", .{ name, removed }) catch {
        return error.StateWrong;
    };
    if (!std.mem.eql(u8, entry, text)) return error.StateWrong;
    return .{ .entry = entry, .removed = removed, .expires = expires };
}

/// `state restore NAME --output json` is `zbx.state.restore/1` and brings back `entry`.
pub fn check_restore(
    arena: Allocator,
    streams: Streams,
    status: u8,
    name: []const u8,
    entry: []const u8,
) Error!void {
    const doc = try document(arena, streams, status, "zbx.state.restore/1");
    const named = string_of(doc, "name") orelse return error.StateWrong;
    if (!std.mem.eql(u8, named, name)) return error.StateWrong;
    const brought = string_of(doc, "entry") orelse return error.StateWrong;
    if (!std.mem.eql(u8, brought, entry)) return error.StateWrong;
    if ((integer_of(doc, "removed") orelse 0) <= 0) return error.StateWrong;
}

pub const Exported = struct { files: i64, bytes: i64, archive_bytes: i64 };

/// `state export NAME -o FILE --output json` is `zbx.state.export/1`: it names the file asked for,
/// counts at least `files_min` files, an archive that is not empty, and `skipped` files left out.
pub fn check_export(
    arena: Allocator,
    streams: Streams,
    status: u8,
    name: []const u8,
    file: []const u8,
    skipped: i64,
) Error!Exported {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.endsWith(u8, std.mem.trimEnd(u8, streams.stdout, "\n"), "}")) {
        return error.StateWrong;
    }
    const doc = try parse_value(arena, std.mem.trimEnd(u8, streams.stdout, "\n"));
    const said = string_of(doc, "schema") orelse return error.StateWrong;
    if (!std.mem.eql(u8, said, "zbx.state.export/1")) return error.StateWrong;
    const named = string_of(doc, "name") orelse return error.StateWrong;
    if (!std.mem.eql(u8, named, name)) return error.StateWrong;
    const written = string_of(doc, "file") orelse return error.StateWrong;
    if (!std.mem.eql(u8, written, file)) return error.StateWrong;
    const left_out = integer_of(doc, "skipped") orelse return error.StateWrong;
    if (left_out != skipped) return error.StateWrong;
    const files = integer_of(doc, "files") orelse return error.StateWrong;
    const bytes = integer_of(doc, "bytes") orelse return error.StateWrong;
    const archive = integer_of(doc, "archive_bytes") orelse return error.StateWrong;
    if (files < 1 or bytes < 0 or archive <= 0) return error.StateWrong;
    return .{ .files = files, .bytes = bytes, .archive_bytes = archive };
}

/// The export left a file out and said so once, as a warning on stderr (`ZBX-W0703`) whose
/// context names the path inside the volume (`path`), never the host's.
pub fn check_skip_warning(arena: Allocator, stderr: []const u8, path: []const u8) Error!void {
    const all = try agent_json.diagnostics(arena, stderr);
    if (all.len != 1) return error.RefusalWrong;
    const found = all[0];
    if (!std.mem.eql(u8, found.code, "ZBX-W0703")) return error.RefusalWrong;
    if (!std.mem.eql(u8, found.severity, "warning")) return error.RefusalWrong;
    const named = string_of(found.context, "path") orelse return error.RefusalWrong;
    if (!std.mem.eql(u8, named, path)) return error.RefusalWrong;
}

/// No text of `shown` holds `value`: a password given with `-e` reaches the container and no
/// document.
pub fn check_absent(shown: []const []const u8, value: []const u8) Error!void {
    for (shown) |text| {
        if (std.mem.indexOf(u8, text, value) != null) return error.StateWrong;
    }
}

const testing = std.testing;

fn captured(stdout: []const u8, stderr: []const u8) Streams {
    return .{ .stdout = stdout, .stderr = stderr };
}

fn scratch() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

// Real output of the built binary (state ls, rm, restore, export), with a volume and a fifo.
const ls_text = "{\"schema\":\"zbx.state.ls/1\",\"directory\":\"/h/.local/share/zbx/state\"," ++
    "\"volumes\":[{\"name\":\"demo\",\"bytes\":3,\"disk_bytes\":8192,\"files\":1," ++
    "\"record\":\"ok\",\"created\":1793236000,\"last_used\":1793236100," ++
    "\"last_container\":\"pg\",\"last_path\":\"/data\",\"last_read_only\":false," ++
    "\"in_use\":true,\"used_by\":[{\"container\":\"pg\",\"read_only\":false}]}," ++
    "{\"name\":\"idle\",\"bytes\":null,\"disk_bytes\":null,\"files\":null," ++
    "\"record\":\"missing\",\"created\":null,\"last_used\":null,\"last_container\":null," ++
    "\"last_path\":null,\"last_read_only\":null,\"in_use\":false,\"used_by\":[]}]," ++
    "\"trash\":[{\"name\":\"old\",\"entry\":\"old@1793236338\",\"removed\":1793236338," ++
    "\"expires\":1793841138,\"expired\":false},{\"name\":\"old\",\"entry\":\"old@1793236400\"," ++
    "\"removed\":1793236400,\"expires\":1793841200,\"expired\":true}],\"truncated\":false}\n";

test "state ls is read for a volume, its size, last container and holder, and the trash" {
    // Goal: the agent reads the facts of step 4 from JSON. Method: a listing in the shape the
    // binary printed; a volume in use, one never recorded; a name that is not listed; a listing
    // whose use and holder disagree; the trash with two entries of one name (the newest wins).
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const ls = captured(ls_text, "");
    const found = try read_volume(arena, ls, 0, "demo");
    try testing.expectEqual(@as(?i64, 8192), found.disk_bytes);
    try testing.expectEqualStrings("pg", found.last_container.?);
    try testing.expectEqualStrings("pg", found.holder.?);
    try testing.expect(found.in_use);
    const idle = try read_volume(arena, ls, 0, "idle");
    try testing.expectEqual(@as(?i64, null), idle.disk_bytes);
    try testing.expect(idle.holder == null and !idle.in_use);
    try testing.expectError(error.StateWrong, read_volume(arena, ls, 0, "no"));
    try testing.expectError(error.ExitCodeWrong, read_volume(arena, ls, 1, "demo"));
    const noisy = captured(ls_text, "x");
    try testing.expectError(error.StateWrong, read_volume(arena, noisy, 0, "demo"));
    const flag = "\"in_use\":";
    const disagree = std.mem.replaceOwned(u8, arena, ls_text, flag ++ "true", flag ++ "false");
    try testing.expectError(
        error.StateWrong,
        read_volume(arena, captured(try disagree, ""), 0, "demo"),
    );
    try check_unlisted(arena, ls, 0, "gone");
    try testing.expectError(error.StateWrong, check_unlisted(arena, ls, 0, "demo"));
    try testing.expectError(error.JsonWrong, check_unlisted(arena, captured("{", ""), 0, "demo"));
    const trash = try read_trash(arena, ls, 0, "old");
    try testing.expectEqualStrings("old@1793236400", trash.entry);
    try testing.expect(trash.expired);
    try testing.expectError(error.StateWrong, read_trash(arena, ls, 0, "demo"));
}

test "state rm, restore and export are read from their documents" {
    // Goal: the agent reads the results of step 6 and 7 from JSON. Method: the documents the
    // binary printed; a wrong name, entry, schema, count and status for each.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const rm = "{\"schema\":\"zbx.state.rm/1\",\"name\":\"demo\",\"entry\":\"demo@1793236338\"," ++
        "\"removed\":1793236338,\"expires\":1793841138,\"emptied\":0}\n";
    const removed = try check_rm(arena, captured(rm, ""), 0, "demo");
    try testing.expectEqualStrings("demo@1793236338", removed.entry);
    try testing.expectEqual(@as(i64, 604800), removed.expires - removed.removed);
    try testing.expectError(error.StateWrong, check_rm(arena, captured(rm, ""), 0, "other"));
    try testing.expectError(error.ExitCodeWrong, check_rm(arena, captured(rm, ""), 1, "demo"));
    const odd = std.mem.replaceOwned(u8, arena, rm, "demo@1793236338", "demo@1793236339");
    try testing.expectError(error.StateWrong, check_rm(arena, captured(try odd, ""), 0, "demo"));
    const restore = "{\"schema\":\"zbx.state.restore/1\",\"name\":\"demo\"," ++
        "\"entry\":\"demo@1793236338\",\"removed\":1793236338}\n";
    try check_restore(arena, captured(restore, ""), 0, "demo", "demo@1793236338");
    const other = check_restore(arena, captured(restore, ""), 0, "demo", "demo@1");
    try testing.expectError(error.StateWrong, other);
    const not_restore = check_restore(arena, captured(rm, ""), 0, "demo", "x");
    try testing.expectError(error.StateWrong, not_restore);
    const export_text = "{\"schema\":\"zbx.state.export/1\",\"name\":\"demo\"," ++
        "\"file\":\"/h/x.tgz\"," ++
        "\"directories\":1,\"files\":1,\"symlinks\":0,\"hard_links\":0,\"skipped\":1," ++
        "\"bytes\":3,\"archive_bytes\":124}\n";
    const sent = try check_export(arena, captured(export_text, ""), 0, "demo", "/h/x.tgz", 1);
    try testing.expectEqual(@as(i64, 124), sent.archive_bytes);
    const wrong_file = check_export(arena, captured(export_text, ""), 0, "demo", "/h/y.tgz", 1);
    try testing.expectError(error.StateWrong, wrong_file);
    const wrong_skip = check_export(arena, captured(export_text, ""), 0, "demo", "/h/x.tgz", 0);
    try testing.expectError(error.StateWrong, wrong_skip);
    const empty = std.mem.replaceOwned(u8, arena, export_text, "\"files\":1", "\"files\":0");
    const none = check_export(arena, captured(try empty, ""), 0, "demo", "/h/x.tgz", 1);
    try testing.expectError(error.StateWrong, none);
    const bare = check_export(arena, captured("not json", ""), 0, "demo", "/h/x.tgz", 1);
    try testing.expectError(error.StateWrong, bare);
}

const e0706 = "{\"code\":\"ZBX-E0706\",\"severity\":\"error\",\"blame\":\"user\"," ++
    "\"summary\":\"the state volume is in use\",\"causes\":[\"pg (process 4242) holds the " ++
    "volume pgdata for writing\"],\"while\":[\"taking the state volume pgdata\"]," ++
    "\"context\":{\"volume\":\"pgdata\"},\"fixes\":[{\"sentence\":\"stop the container that " ++
    "holds it, then run again:\",\"command\":\"zbx stop pg\"},{\"sentence\":\"or, if this run " ++
    "only reads it, mount it with NAME:PATH:ro\",\"command\":null}],\"docs\":" ++
    "\"https://zigbox.github.io/zigbox/errors/E0706.html\"," ++
    "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";

test "a refusal is read from its code and context, and the holder is not in the context" {
    // Goal: the agent reads E0706 by code and learns what the context offers. Method: the
    // golden's line; a wrong exit status, code and volume; a line with a holder member; a
    // second diagnostic; text on stdout.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const found = try check_refusal(arena, captured("", e0706), 125, 125, "ZBX-E0706", "pgdata");
    try testing.expect(holder_in_context(found) == null);
    try testing.expect(trash_in_context(found) == null);
    const status = check_refusal(arena, captured("", e0706), 1, 125, "ZBX-E0706", "pgdata");
    try testing.expectError(error.ExitCodeWrong, status);
    const code = check_refusal(arena, captured("", e0706), 125, 125, "ZBX-E0707", "pgdata");
    try testing.expectError(error.RefusalWrong, code);
    const volume = check_refusal(arena, captured("", e0706), 125, 125, "ZBX-E0706", "other");
    try testing.expectError(error.RefusalWrong, volume);
    const out = check_refusal(arena, captured("x", e0706), 125, 125, "ZBX-E0706", "pgdata");
    try testing.expectError(error.RefusalWrong, out);
    const two = captured("", e0706 ++ e0706);
    const twice = check_refusal(arena, two, 125, 125, "ZBX-E0706", "pgdata");
    try testing.expectError(error.RefusalWrong, twice);
    const with_holder = try std.mem.replaceOwned(
        u8,
        arena,
        e0706,
        "\"context\":{\"volume\":\"pgdata\"}",
        "\"context\":{\"volume\":\"pgdata\",\"holder\":\"pg\"}",
    );
    const named = captured("", with_holder);
    const better = try check_refusal(arena, named, 125, 125, "ZBX-E0706", "pgdata");
    try testing.expectEqualStrings("pg", holder_in_context(better).?);
    const stop_pg = "\"command\":\"zbx stop pg\"";
    const bare = try std.mem.replaceOwned(u8, arena, e0706, stop_pg, "\"command\":null");
    const no_fix = check_refusal(arena, captured("", bare), 125, 125, "ZBX-E0706", "pgdata");
    try testing.expectError(error.FixWrong, no_fix);
}

test "the skip warning names the path inside the volume" {
    // Goal: W0703's context is the user's view (`/p`), not the host's layout. Method: the line
    // the binary prints with the path inside; the host's path; a second warning; an error.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const line = "{\"code\":\"ZBX-W0703\",\"severity\":\"warning\",\"blame\":\"user\"," ++
        "\"summary\":\"a file was left out of the export\",\"causes\":[\"/p is a fifo, which " ++
        "the archive does not keep\"],\"while\":[\"exporting a state volume\"]," ++
        "\"context\":{\"path\":\"/p\"},\"fixes\":[{\"sentence\":\"nothing to do\"," ++
        "\"command\":null}],\"docs\":\"https://zigbox.github.io/zigbox/errors/W0703.html\"," ++
        "\"omitted\":{\"causes\":0,\"while\":0,\"context\":0,\"fixes\":0}}\n";
    try check_skip_warning(arena, line, "/p");
    try testing.expectError(error.RefusalWrong, check_skip_warning(arena, line, "/q"));
    const inside = "\"path\":\"/p\"";
    const host = try std.mem.replaceOwned(u8, arena, line, inside, "\"path\":\"/h/lk/data/p\"");
    try testing.expectError(error.RefusalWrong, check_skip_warning(arena, host, "/p"));
    try testing.expectError(error.RefusalWrong, check_skip_warning(arena, line ++ line, "/p"));
    try testing.expectError(error.RefusalWrong, check_skip_warning(arena, "", "/p"));
    const error_line = try std.mem.replaceOwned(u8, arena, line, "\"warning\"", "\"error\"");
    try testing.expectError(error.RefusalWrong, check_skip_warning(arena, error_line, "/p"));
}

test "ps gives the pid of a running container, and says what members an entry has" {
    // Goal: the agent kills the pid ps names, and can tell that ps lists no volumes. Method: a
    // listing shaped like the binary's; a stopped container, pid 1, a missing name; keys.
    var state = scratch();
    defer state.deinit();
    const arena = state.allocator();
    const ps = "{\"schema\":\"zbx.ps/1\",\"containers\":[" ++
        "{\"name\":\"pg\",\"state\":\"running\",\"pid\":4242,\"network\":\"user\",\"env\":[]}," ++
        "{\"name\":\"old\",\"state\":\"stopped\",\"pid\":77},{\"name\":\"odd\",\"state\":" ++
        "\"running\",\"pid\":1},{\"name\":\"nopid\",\"state\":\"running\"}]}\n";
    try testing.expectEqual(@as(u32, 4242), try ps_pid(arena, ps, "pg"));
    try testing.expectError(error.PidWrong, ps_pid(arena, ps, "old"));
    try testing.expectError(error.PidWrong, ps_pid(arena, ps, "odd"));
    try testing.expectError(error.PidWrong, ps_pid(arena, ps, "nopid"));
    try testing.expectError(error.PidWrong, ps_pid(arena, ps, "gone"));
    try testing.expectError(error.JsonWrong, ps_pid(arena, "[", "pg"));
    try testing.expect(!try entry_has_any(arena, ps, "pg", &.{ "state_volumes", "mounts" }));
    try testing.expect(try entry_has_any(arena, ps, "pg", &.{ "mounts", "env" }));
}

test "a schema with a $ref is not one the agent follows; a value is absent from the documents" {
    // Goal: the two small checks. Method: right and wrong input for each.
    try check_flat("{\"type\":\"object\"}");
    try testing.expectError(error.JsonWrong, check_flat("{\"$ref\":\"#/$defs/x\"}"));
    try check_absent(&.{ "a", "b" }, "secret");
    try testing.expectError(error.StateWrong, check_absent(&.{ "a", "has secret" }, "secret"));
}
