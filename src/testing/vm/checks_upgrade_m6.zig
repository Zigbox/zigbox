//! The assertions of the M6 upgrade test (the merged M5 `zbx`, the commit `m6_commit` in
//! `old_release.zon`, leaves a store, run records and a lock that this `zbx` reads), as pure
//! functions over the text the guest printed. The store, lock and pull checks are
//! checks_upgrade_m5.zig's (M5 wrote the same image record version, 2, that this zbx does); this
//! file adds the one thing that changed since: run records of two versions side by side.

const std = @import("std");
const up5 = @import("checks_upgrade_m5.zig");

const Allocator = std.mem.Allocator;

pub const Error = up5.Error || error{
    /// `ps --all --output json` does not show a record as it should.
    RecordWrong,
};

/// What each record on disk says in its `.version` line. M5 wrote image records as version 2
/// (this zbx still does) and run records as version 4. (Version 5, the network, the forwards and
/// the names of `-e`, came with M6 slice 1; version 6 added the state volumes; this zbx writes 7,
/// with the tmpfs, bind and secret mounts.)
pub const image_record_version = up5.image_record_version_m5;
pub const run_record_version_m5: u32 = 4;
pub const run_record_version = up5.run_record_version;

comptime {
    std.debug.assert(run_record_version_m5 < run_record_version);
}

/// A container the listing must show: its `network` member is a word, or `null` for a record of a
/// zbx that did not keep it (M5's version 4), and no variable name is listed for it.
pub const Want = struct {
    name: []const u8,
    network: ?[]const u8,
};

/// `zbx --output json ps --all` lists each of `wants`, stopped, with its network as said, and
/// every record reads: `published` and `env` are lists (empty for M5's record).
pub fn check_ps_records(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    wants: []const Want,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, stdout, .{}) catch {
        return error.JsonWrong;
    };
    if (parsed != .object) return error.JsonWrong;
    const schema = parsed.object.get("schema") orelse return error.JsonWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.ps/1")) return error.JsonWrong;
    const list = parsed.object.get("containers") orelse return error.JsonWrong;
    if (list != .array) return error.JsonWrong;
    for (wants) |want| try check_one(list.array.items, want);
}

fn check_one(items: []const std.json.Value, want: Want) Error!void {
    for (items) |item| {
        if (item != .object) return error.JsonWrong;
        const name = item.object.get("name") orelse return error.JsonWrong;
        if (name != .string or !std.mem.eql(u8, name.string, want.name)) continue;
        const state = item.object.get("state") orelse return error.RecordWrong;
        if (state != .string or !std.mem.eql(u8, state.string, "stopped")) {
            return error.RecordWrong;
        }
        const network = item.object.get("network") orelse return error.RecordWrong;
        if (want.network) |word| {
            if (network != .string or !std.mem.eql(u8, network.string, word)) {
                return error.RecordWrong;
            }
        } else if (network != .null) {
            return error.RecordWrong;
        }
        const published = item.object.get("published") orelse return error.RecordWrong;
        const env = item.object.get("env") orelse return error.RecordWrong;
        if (published != .array or env != .array) return error.RecordWrong;
        return;
    }
    return error.RecordWrong;
}

const testing = std.testing;

fn doc(comptime items: []const u8) []const u8 {
    return "{\"schema\":\"zbx.ps/1\",\"containers\":[" ++ items ++ "]}\n";
}

const old_item = "{\"name\":\"m5up1\",\"state\":\"stopped\",\"network\":null," ++
    "\"published\":[],\"env\":[]}";
const new_item = "{\"name\":\"m6up2\",\"state\":\"stopped\",\"network\":\"none\"," ++
    "\"published\":[],\"env\":[]}";

test "a run record of M5 and one of this zbx are listed side by side" {
    // Goal: M5's record has no network (null), this zbx's says it. Wrong: the reverse, a
    // record missing, one still running, the members absent, another schema, a failed command.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const wants = [_]Want{
        .{ .name = "m5up1", .network = null },
        .{ .name = "m6up2", .network = "none" },
    };
    try check_ps_records(arena, doc(old_item ++ "," ++ new_item), 0, &wants);
    const swapped = [_]Want{
        .{ .name = "m5up1", .network = "none" },
        .{ .name = "m6up2", .network = "none" },
    };
    const wrong = check_ps_records(arena, doc(old_item ++ "," ++ new_item), 0, &swapped);
    try testing.expectError(error.RecordWrong, wrong);
    const lone = check_ps_records(arena, doc(new_item), 0, &wants);
    try testing.expectError(error.RecordWrong, lone);
    const running = "{\"name\":\"m5up1\",\"state\":\"running\",\"network\":null," ++
        "\"published\":[],\"env\":[]}";
    const live = check_ps_records(arena, doc(running ++ "," ++ new_item), 0, &wants);
    try testing.expectError(error.RecordWrong, live);
    const bare = "{\"name\":\"m5up1\",\"state\":\"stopped\"}";
    const cut = check_ps_records(arena, doc(bare ++ "," ++ new_item), 0, &wants);
    try testing.expectError(error.RecordWrong, cut);
    const other = "{\"schema\":\"zbx.x/1\",\"containers\":[]}";
    try testing.expectError(error.JsonWrong, check_ps_records(arena, other, 0, &wants));
    try testing.expectError(error.JsonWrong, check_ps_records(arena, "", 0, &wants));
    const failed = check_ps_records(arena, doc(old_item ++ "," ++ new_item), 1, &wants);
    try testing.expectError(error.ExitCodeWrong, failed);
}

test "the versions are the ones the formats have" {
    try up5.check_record_version("    .version = 4,\n", run_record_version_m5);
    try up5.check_record_version("    .version = 7,\n", run_record_version);
    try up5.check_record_version(".version = 2,\n", image_record_version);
}

// Text captured from a real run of this demo in the KVM guest (vm run 40781853563, the M5 binary
// built from fd48d38 and this one): not what the code above is believed to print.
const real_m5_item = "{\"name\":\"m5up1\",\"state\":\"stopped\",\"pid\":2490," ++
    "\"supervisor\":2484," ++
    "\"scope\":\"zbx-m5up1.scope\",\"detached\":false,\"timed_out\":false," ++
    "\"started\":1793227669," ++
    "\"ended\":1793227669,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"sh\",\"-c\"," ++
    "\"wget -qO /dev/null https://example.com && echo upgraded > /marker\"],\"labels\":[]," ++
    "\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null},\"network\":null," ++
    "\"published\":[],\"env\":[]}";
const real_m6_item = "{\"name\":\"m6up2\",\"state\":\"stopped\",\"pid\":2610," ++
    "\"supervisor\":2606," ++
    "\"scope\":\"zbx-m6up2.scope\",\"detached\":false,\"timed_out\":false," ++
    "\"started\":1793227705," ++
    "\"ended\":1793227705,\"reason\":\"exited\",\"exit_code\":0,\"command\":[\"true\"]," ++
    "\"labels\":[],\"limits\":{\"memory_bytes\":null,\"pids\":null,\"cpu_millis\":null}," ++
    "\"network\":\"none\",\"published\":[],\"env\":[]}";

test "text the M5 binary's record and this one's produced in the guest passes the check" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const wants = [_]Want{
        .{ .name = "m5up1", .network = null },
        .{ .name = "m6up2", .network = "none" },
    };
    try check_ps_records(arena, doc(real_m6_item ++ "," ++ real_m5_item), 0, &wants);
    const swapped = [_]Want{.{ .name = "m5up1", .network = "none" }};
    const wrong = check_ps_records(arena, doc(real_m5_item), 0, &swapped);
    try testing.expectError(error.RecordWrong, wrong);
}
