//! The assertions of the M6b upgrade test (the merged M6 `zbx`, the commit `m6b_commit` in
//! `old_release.zon`, starts a detached container with a `--state` volume that this `zbx` then
//! reads, execs into and stops), as pure functions over the text the guest printed. The store,
//! lock and pull checks are checks_upgrade_m5.zig's (M6 wrote the same image record version);
//! this file adds what changed since: run records of version 7 beside this binary's own, and the
//! `ps` entry of a container that this binary did not start.

const std = @import("std");
const up5 = @import("checks_upgrade_m5.zig");

const Allocator = std.mem.Allocator;
const Streams = @import("checks.zig").Streams;

pub const Error = up5.Error || error{
    /// `ps --output json` does not show the old container as running and complete.
    RecordWrong,
};

/// The version of the run record each `zbx` writes: M6 wrote 7; this one writes 8 (it added the
/// writable mounts and the user). Image records are still version 2.
pub const run_record_version_m6: u32 = 7;
pub const run_record_version = up5.run_record_version;
pub const image_record_version = up5.image_record_version_m5;

comptime {
    std.debug.assert(run_record_version_m6 + 1 == run_record_version);
}

pub const Running = struct { pid: u32, scope: []const u8 };

/// `ps --output json` lists `name` as running, started by the older `zbx`: it has a pid that is
/// not 1, a scope, `detached`, its network `none` and no forward. `writable_mounts`, which only
/// this binary writes, is absent or an empty list: nothing is invented for an old record.
pub fn check_old_running(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    name: []const u8,
) Error!Running {
    if (status != 0) return error.ExitCodeWrong;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, stdout, .{}) catch {
        return error.JsonWrong;
    };
    if (parsed != .object) return error.JsonWrong;
    const schema = parsed.object.get("schema") orelse return error.JsonWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.ps/1")) return error.JsonWrong;
    const list = parsed.object.get("containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (list.array.items) |item| {
        if (item != .object) return error.JsonWrong;
        const found = item.object.get("name") orelse continue;
        if (found != .string or !std.mem.eql(u8, found.string, name)) continue;
        return check_entry(item.object);
    }
    return error.RecordWrong;
}

fn check_entry(entry: std.json.ObjectMap) Error!Running {
    const state = entry.get("state") orelse return error.RecordWrong;
    if (state != .string or !std.mem.eql(u8, state.string, "running")) return error.RecordWrong;
    const pid = entry.get("pid") orelse return error.RecordWrong;
    if (pid != .integer or pid.integer <= 1) return error.RecordWrong;
    const scope = entry.get("scope") orelse return error.RecordWrong;
    if (scope != .string or scope.string.len == 0) return error.RecordWrong;
    const detached = entry.get("detached") orelse return error.RecordWrong;
    if (detached != .bool or !detached.bool) return error.RecordWrong;
    const network = entry.get("network") orelse return error.RecordWrong;
    if (network != .string or !std.mem.eql(u8, network.string, "none")) return error.RecordWrong;
    const published = entry.get("published") orelse return error.RecordWrong;
    if (published != .array or published.array.items.len != 0) return error.RecordWrong;
    if (entry.get("writable_mounts")) |mounts| {
        if (mounts != .array or mounts.array.items.len != 0) return error.RecordWrong;
    }
    return .{ .pid = @intCast(pid.integer), .scope = scope.string };
}

/// `zbx logs` of a container that has a record and no log: ZBX-E0217 on the first line of stderr
/// (`logs` ends a refusal with 1, where `run` and `exec` end it with 125), naming the container
/// and saying why, and nothing on stdout.
pub fn check_no_log(streams: Streams, status: u8, name: []const u8) Error!void {
    if (status != 1) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.RecordWrong;
    if (!std.mem.startsWith(u8, streams.stderr, "error[ZBX-E0217]")) return error.RecordWrong;
    var wanted: [96]u8 = undefined;
    const named = std.fmt.bufPrint(&wanted, "'{s}' has a run record and no log", .{name}) catch
        return error.RecordWrong;
    if (std.mem.indexOf(u8, streams.stderr, named) == null) return error.RecordWrong;
    if (std.mem.indexOf(u8, streams.stderr, "ran before logs were kept") == null) {
        return error.RecordWrong;
    }
    if (std.mem.indexOf(u8, streams.stderr, "errno") != null) return error.RecordWrong;
}

const testing = std.testing;

fn doc(comptime items: []const u8) []const u8 {
    return "{\"schema\":\"zbx.ps/1\",\"containers\":[" ++ items ++ "]}\n";
}

fn wrap(arena: Allocator, item: []const u8) ![]const u8 {
    const pattern = "{{\"schema\":\"zbx.ps/1\",\"containers\":[{s}]}}";
    return std.fmt.allocPrint(arena, pattern, .{item});
}

const running_item = "{\"name\":\"m6bold\",\"state\":\"running\",\"pid\":2490," ++
    "\"supervisor\":2484,\"scope\":\"zbx-m6bold.scope\",\"detached\":true," ++
    "\"timed_out\":false,\"started\":1793227669,\"command\":[\"sh\",\"-c\",\"sleep 1000\"]," ++
    "\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null}," ++
    "\"network\":\"none\",\"published\":[],\"env\":[]}";

test "an old container still running is read with its pid and scope" {
    // Goal: the entry of a container the M6 binary started is complete. Wrong: stopped, pid 1 or
    // none, no scope, not detached, a network, a forward, an invented mount, another name.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const found = try check_old_running(arena, doc(running_item), 0, "m6bold");
    try testing.expectEqual(@as(u32, 2490), found.pid);
    try testing.expectEqualStrings("zbx-m6bold.scope", found.scope);
    const edits = [_][2][]const u8{
        .{ "\"state\":\"running\"", "\"state\":\"stopped\"" },
        .{ "\"pid\":2490", "\"pid\":1" },
        .{ "\"scope\":\"zbx-m6bold.scope\"", "\"scope\":\"\"" },
        .{ "\"detached\":true", "\"detached\":false" },
        .{ "\"network\":\"none\"", "\"network\":\"user\"" },
        .{ "\"published\":[]", "\"published\":[{\"host\":1,\"container\":2}]" },
        .{ "\"env\":[]", "\"env\":[],\"writable_mounts\":[{\"host\":\"/x\",\"target\":\"/y\"}]" },
    };
    for (edits) |edit| {
        const changed = try std.mem.replaceOwned(u8, arena, running_item, edit[0], edit[1]);
        const wrong = check_old_running(arena, try wrap(arena, changed), 0, "m6bold");
        try testing.expectError(error.RecordWrong, wrong);
    }
    const good = doc(running_item);
    try testing.expectError(error.RecordWrong, check_old_running(arena, good, 0, "other"));
    try testing.expectError(error.ExitCodeWrong, check_old_running(arena, good, 1, "m6bold"));
    try testing.expectError(error.JsonWrong, check_old_running(arena, "nope", 0, "m6bold"));
    // An empty list of mounts is what a record without any reads as; it is not wrong.
    const bare = "\"env\":[]";
    const with_list = bare ++ ",\"writable_mounts\":[]";
    const empty = try std.mem.replaceOwned(u8, arena, running_item, bare, with_list);
    _ = try check_old_running(arena, try wrap(arena, empty), 0, "m6bold");
}

test "the versions are the ones the formats have" {
    try up5.check_record_version("    .version = 7,\n", run_record_version_m6);
    try up5.check_record_version("    .version = 8,\n", run_record_version);
    try testing.expectError(
        error.LineMissing,
        up5.check_record_version("    .version = 7,\n", run_record_version),
    );
}

test "a container without a log is a coded refusal, and each lie is caught" {
    // Goal: the check passes on E0217 as the binary prints it, and fails on another code, the
    // exit status of a run's refusal (125), text on stdout, another name, an errno dump.
    const text = "error[ZBX-E0217]: the container has no log\n" ++
        "  cause  'm6bold' has a run record and no log: it ran before logs were kept, its log " ++
        "could not be written, or it was " ++
        "removed\n";
    const right: Streams = .{ .stdout = "", .stderr = text };
    try check_no_log(right, 1, "m6bold");
    try testing.expectError(error.ExitCodeWrong, check_no_log(right, 125, "m6bold"));
    try testing.expectError(error.RecordWrong, check_no_log(right, 1, "other"));
    const shown: Streams = .{ .stdout = "x", .stderr = text };
    try testing.expectError(error.RecordWrong, check_no_log(shown, 1, "m6bold"));
    const code: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0402]: no container\n" };
    try testing.expectError(error.RecordWrong, check_no_log(code, 1, "m6bold"));
    const dump: Streams = .{ .stdout = "", .stderr = text ++ "errno 2\n" };
    try testing.expectError(error.RecordWrong, check_no_log(dump, 1, "m6bold"));
}
