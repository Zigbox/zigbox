//! The assertions of M6's state volumes (slice 2) as pure functions over the text the guest
//! printed, each unit-tested with right and wrong input. The commands that print it are in
//! state_m6.zig, a part of demo-m5 until demo-m6 exists (slice 4).

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A refusal lacks its code, or does not name the holder.
    RefusalWrong,
    /// psql did not print the row that was written before the container was killed.
    RowMissing,
    /// The data directory's owner or mode inside the container is not what postgres makes it.
    OwnerWrong,
    /// `state ls --output json` does not say what it should about the volume.
    ListingWrong,
    /// A volume's lock is still held after its run ended.
    LockHeld,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// A run refused because the volume is held: exit 125, `ZBX-E0706`, and the holder named.
pub fn check_in_use(streams: Streams, status: u8, holder: []const u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0706]: the state volume is in use")) {
        return error.RefusalWrong;
    }
    if (!contains(streams.stderr, holder)) return error.RefusalWrong;
}

/// `psql -tAc 'select v from t'`: the row is there.
pub fn check_row(output: []const u8, status: u8, row: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r\t"), row)) return;
    }
    return error.RowMissing;
}

/// `stat -c '%u %g %a'` of the data directory inside the container: postgres's uid 999 (its
/// entrypoint runs `chown postgres`, the group stays the volume's) and mode 700 (its `chmod 700`;
/// nothing made it 777).
pub fn check_owner(stdout: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, std.mem.trim(u8, line, " \r\t"), ' ');
        const uid = words.next() orelse continue;
        _ = words.next() orelse continue;
        const mode = words.next() orelse continue;
        if (words.next() != null) continue;
        if (std.mem.eql(u8, uid, "999") and std.mem.eql(u8, mode, "700")) return;
    }
    return error.OwnerWrong;
}

pub const Expect = struct {
    name: []const u8,
    last_container: []const u8,
    in_use: bool,
    /// The volume's size on the disk is at least this.
    disk_bytes_min: i64,
    /// The container named as using it now, when `in_use`.
    user: []const u8 = "",
};

/// `zbx state ls --output json`: the volume with its size, last container and use.
pub fn check_listing(allocator: std.mem.Allocator, stdout: []const u8, expect: Expect) Error!void {
    const line = first_object_line(stdout) orelse return error.ListingWrong;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch
        return error.ListingWrong;
    defer parsed.deinit();
    if (parsed.value != .object) return error.ListingWrong;
    const schema = parsed.value.object.get("schema") orelse return error.ListingWrong;
    if (schema != .string or !std.mem.eql(u8, schema.string, "zbx.state.ls/1")) {
        return error.ListingWrong;
    }
    const volumes = parsed.value.object.get("volumes") orelse return error.ListingWrong;
    if (volumes != .array) return error.ListingWrong;
    for (volumes.array.items) |item| {
        if (item != .object) return error.ListingWrong;
        const name = item.object.get("name") orelse continue;
        if (name != .string or !std.mem.eql(u8, name.string, expect.name)) continue;
        return check_volume(item.object, expect);
    }
    return error.ListingWrong;
}

fn check_volume(volume: std.json.ObjectMap, expect: Expect) Error!void {
    const last = volume.get("last_container") orelse return error.ListingWrong;
    if (last != .string or !std.mem.eql(u8, last.string, expect.last_container)) {
        return error.ListingWrong;
    }
    const size = volume.get("disk_bytes") orelse return error.ListingWrong;
    if (size != .integer or size.integer < expect.disk_bytes_min) return error.ListingWrong;
    const in_use = volume.get("in_use") orelse return error.ListingWrong;
    if (in_use != .bool or in_use.bool != expect.in_use) return error.ListingWrong;
    if (!expect.in_use) return;
    const users = volume.get("used_by") orelse return error.ListingWrong;
    if (users != .array or users.array.items.len == 0) return error.ListingWrong;
    const first = users.array.items[0];
    if (first != .object) return error.ListingWrong;
    const container = first.object.get("container") orelse return error.ListingWrong;
    if (container != .string or !std.mem.eql(u8, container.string, expect.user)) {
        return error.ListingWrong;
    }
}

fn first_object_line(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len > 0 and line[0] == '{') return line;
    }
    return null;
}

/// `flock -n -x <lock> echo free || echo held`: nobody holds the volume.
pub fn check_free(output: []const u8) Error!void {
    if (contains(output, "held")) return error.LockHeld;
    if (!contains(output, "free")) return error.LockHeld;
}

const testing = std.testing;

test "a refusal names its code and the holder, and nothing else passes" {
    const refused: Streams = .{
        .stdout = "",
        .stderr = "error[ZBX-E0706]: the state volume is in use\n" ++
            "  cause  the container pg is writing to the volume pgdata, so it is not free\n",
    };
    try check_in_use(refused, 125, "pg");
    try testing.expectError(error.ExitCodeWrong, check_in_use(refused, 0, "pg"));
    try testing.expectError(error.RefusalWrong, check_in_use(refused, 125, "web"));
    const other: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0705]: not a valid" };
    try testing.expectError(error.RefusalWrong, check_in_use(other, 125, "pg"));
}

test "the row, the owner and the lock read from what the guest printed" {
    try check_row("kept-across-sigkill\n", 0, "kept-across-sigkill");
    try testing.expectError(error.RowMissing, check_row("\n", 0, "kept-across-sigkill"));
    try testing.expectError(error.ExitCodeWrong, check_row("x", 2, "x"));
    try check_owner("999 999 700\n", 0);
    try check_owner("999 0 700\n", 0); // As the guest printed it (vm run 40768184682).
    try testing.expectError(error.OwnerWrong, check_owner("999 0 777\n", 0));
    try testing.expectError(error.OwnerWrong, check_owner("0 0 777\n", 0));
    try testing.expectError(error.OwnerWrong, check_owner("100998 100998 700\n", 0));
    try check_free("free\n");
    try testing.expectError(error.LockHeld, check_free("held\n"));
    try testing.expectError(error.LockHeld, check_free(""));
}

test "the listing: the volume, its size, its last container and who uses it" {
    const text =
        \\{"schema":"zbx.state.ls/1","directory":"/x","volumes":[{"name":"pgdata","bytes":10,
    ++
        \\"disk_bytes":40960000,"files":3,"record":"ok","created":1,"last_used":2,
    ++
        \\"last_container":"pg","last_path":"/d","last_read_only":false,"in_use":true,
    ++
        \\"used_by":[{"container":"pg","read_only":false}]}],"trash":[],"truncated":false}
    ++ "\n";
    const in_use: Expect = .{
        .name = "pgdata",
        .last_container = "pg",
        .in_use = true,
        .disk_bytes_min = 1 << 20,
        .user = "pg",
    };
    try check_listing(testing.allocator, text, in_use);
    var wrong = in_use;
    wrong.last_container = "web";
    try testing.expectError(error.ListingWrong, check_listing(testing.allocator, text, wrong));
    wrong = in_use;
    wrong.in_use = false;
    try testing.expectError(error.ListingWrong, check_listing(testing.allocator, text, wrong));
    wrong = in_use;
    wrong.disk_bytes_min = 1 << 30;
    try testing.expectError(error.ListingWrong, check_listing(testing.allocator, text, wrong));
    wrong = in_use;
    wrong.name = "other";
    try testing.expectError(error.ListingWrong, check_listing(testing.allocator, text, wrong));
    try testing.expectError(error.ListingWrong, check_listing(testing.allocator, "nope", in_use));
}
