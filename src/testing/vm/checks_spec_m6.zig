//! The assertions of demo-m6's SPEC part (the spec's five steps of M6, spec_m6.zig) as pure
//! functions over the text the guest printed, each unit-tested with right and wrong input. The
//! row, the owner, the listing and the lock are checks_state_m6.zig's; this file adds what the
//! five steps need beyond them: what `psql` prints for a write, the text of `zbx state ls`, the
//! state a killed container's record is left in, the processes it leaves, and the proof that a
//! run without `--state` keeps nothing.

const std = @import("std");
const checks = @import("checks.zig");

const Allocator = std.mem.Allocator;
const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// `psql` did not confirm the table and the row.
    WriteWrong,
    /// `zbx state ls` in text does not show the volume as it should.
    TextWrong,
    /// A JSON document is not what the step expects.
    JsonWrong,
    /// A killed container is not recorded as stopped by a signal, or a process of it is left.
    KillWrong,
    /// A run without `--state` left its data behind, or the volume it did not name changed.
    DataKept,
    /// A volume is listed that was removed.
    VolumeListed,
};

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r\t"), wanted)) return true;
    }
    return false;
}

/// Step 2: `psql -c 'create table t (v text)' -c "insert into t values ('...')"` exits 0 and
/// prints both command tags, `CREATE TABLE` and `INSERT 0 1` (one row).
pub fn check_write(stdout: []const u8, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(stdout, "CREATE TABLE")) return error.WriteWrong;
    if (!has_line(stdout, "INSERT 0 1")) return error.WriteWrong;
}

/// Bytes of `number unit` as `zbx state ls` writes a size (`size_words`): "412 B", "38.5 MiB".
fn size_bytes(number: []const u8, unit: []const u8) ?f64 {
    const value = std.fmt.parseFloat(f64, number) catch return null;
    if (!(value >= 0)) return null;
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var scale: f64 = 1;
    for (units) |known| {
        if (std.mem.eql(u8, known, unit)) return value * scale;
        scale *= 1024;
    }
    return null;
}

/// Step 4, in text: `zbx state ls` has a row that starts with the volume's name, then its size,
/// at least `bytes_min`, two times (each a date and a clock), and the last container.
///   NAME  SIZE  CREATED  LAST USED  LAST CONTAINER  IN USE BY
pub fn check_ls_text(
    stdout: []const u8,
    status: u8,
    name: []const u8,
    last_container: []const u8,
    bytes_min: u64,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(stdout, "LAST CONTAINER")) return error.TextWrong;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \r\t");
        const first = words.next() orelse continue;
        if (!std.mem.eql(u8, first, name)) continue;
        const number = words.next() orelse return error.TextWrong;
        const unit = words.next() orelse return error.TextWrong;
        const size = size_bytes(number, unit) orelse return error.TextWrong;
        if (size < @as(f64, @floatFromInt(bytes_min))) return error.TextWrong;
        // Created and last used: a date and a clock each.
        for (0..4) |_| _ = words.next() orelse return error.TextWrong;
        const last = words.next() orelse return error.TextWrong;
        if (!std.mem.eql(u8, last, last_container)) return error.TextWrong;
        return;
    }
    return error.TextWrong;
}

/// A container in `ps --all --output json`, found by name.
fn container_of(
    arena: Allocator,
    stdout: []const u8,
    name: []const u8,
) Error!std.json.ObjectMap {
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
        const found = item.object.get("name") orelse return error.JsonWrong;
        if (found == .string and std.mem.eql(u8, found.string, name)) return item.object;
    }
    return error.KillWrong;
}

fn string_member(object: std.json.ObjectMap, key: []const u8) Error![]const u8 {
    const value = object.get(key) orelse return error.JsonWrong;
    if (value != .string) return error.JsonWrong;
    return value.string;
}

/// Step 3: after SIGKILL of the container, its record says it is stopped, by a signal.
pub fn check_killed_record(
    arena: Allocator,
    stdout: []const u8,
    status: u8,
    name: []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const container = try container_of(arena, stdout, name);
    if (!std.mem.eql(u8, try string_member(container, "state"), "stopped")) return error.KillWrong;
    if (!std.mem.eql(u8, try string_member(container, "reason"), "signal")) return error.KillWrong;
}

/// Step 3: `pgrep -c` printed a count of zero: none of the container's processes is left. (The
/// guest runs one postgres at a time; the parts before this one stop theirs.)
pub fn check_none_left(output: []const u8) Error!void {
    const text = std.mem.trim(u8, output, " \r\n\t");
    if (!std.mem.eql(u8, text, "0")) return error.KillWrong;
}

/// Step 5: a second run of postgres without `--state` finds no table: the first one's data went
/// with it. `psql -c 'select v from t'` ended with an error that names the table, not with a
/// row, and not with a refusal of another kind (a postgres that did not start would also fail).
pub fn check_data_gone(streams: Streams, status: u8, row: []const u8) Error!void {
    if (status == 0) return error.DataKept;
    if (contains(streams.stdout, row)) return error.DataKept;
    if (!contains(streams.stderr, "relation \"t\" does not exist")) return error.DataKept;
}

/// Step 5: `psql -tAc 'select v from t'` in the run before it printed the row it wrote, so that
/// the absence in the next is the data's, not the table's never having been made.
pub fn check_data_there(stdout: []const u8, status: u8, row: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(stdout, row)) return error.DataKept;
}

/// `state ls --output json` lists no volume called `name` (it was removed to the trash).
pub fn check_volume_absent(arena: Allocator, stdout: []const u8, name: []const u8) Error!void {
    const line = first_object_line(stdout) orelse return error.JsonWrong;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch {
        return error.JsonWrong;
    };
    if (parsed != .object) return error.JsonWrong;
    const volumes = parsed.object.get("volumes") orelse return error.JsonWrong;
    if (volumes != .array) return error.JsonWrong;
    for (volumes.array.items) |item| {
        if (item != .object) return error.JsonWrong;
        const found = item.object.get("name") orelse return error.JsonWrong;
        if (found == .string and std.mem.eql(u8, found.string, name)) return error.VolumeListed;
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

const testing = std.testing;

test "a write is confirmed by both command tags, and nothing less" {
    // Goal: step 2 cannot pass for a psql that made the table and no row, or the reverse.
    try check_write("CREATE TABLE\nINSERT 0 1\n", 0);
    try testing.expectError(error.WriteWrong, check_write("CREATE TABLE\n", 0));
    try testing.expectError(error.WriteWrong, check_write("INSERT 0 1\n", 0));
    try testing.expectError(error.WriteWrong, check_write("CREATE TABLE\nINSERT 0 0\n", 0));
    try testing.expectError(error.ExitCodeWrong, check_write("CREATE TABLE\nINSERT 0 1\n", 3));
    try testing.expectError(error.WriteWrong, check_write("", 0));
}

const ls_head = "NAME                           SIZE  CREATED              LAST USED" ++
    "            LAST CONTAINER       IN USE BY\n";

test "the text listing shows the volume, its size and its last container" {
    // Goal: step 4 in text. Right: a row with a size past the bound, in each unit. Wrong: a size
    // below the bound, another last container, another volume, a unit that is not one, a row
    // cut short, no header, and a failed command.
    const row = "pgdata                      38.5 MiB  2026-10-23 10:00:01  2026-10-23 10:05:09" ++
        "  pg                   pg\n";
    try check_ls_text(ls_head ++ row, 0, "pgdata", "pg", 1 << 20);
    try check_ls_text(ls_head ++ row, 0, "pgdata", "pg", 38 * (1 << 20));
    try testing.expectError(
        error.TextWrong,
        check_ls_text(ls_head ++ row, 0, "pgdata", "pg", 39 * (1 << 20)),
    );
    try testing.expectError(error.TextWrong, check_ls_text(ls_head ++ row, 0, "pgdata", "web", 1));
    try testing.expectError(error.TextWrong, check_ls_text(ls_head ++ row, 0, "other", "pg", 1));
    const failed = check_ls_text(ls_head ++ row, 1, "pgdata", "pg", 1);
    try testing.expectError(error.ExitCodeWrong, failed);
    try testing.expectError(error.TextWrong, check_ls_text(row, 0, "pgdata", "pg", 1));
    const bytes = "pgdata  900 B  2026-10-23 10:00:01  2026-10-23 10:05:09  pg  -\n";
    const wrong_9998 = check_ls_text(ls_head ++ bytes, 0, "pgdata", "pg", 1000);
    try testing.expectError(error.TextWrong, wrong_9998);
    try check_ls_text(ls_head ++ bytes, 0, "pgdata", "pg", 900);
    const odd = "pgdata  1.5 XiB  2026-10-23 10:00:01  2026-10-23 10:05:09  pg  -\n";
    try testing.expectError(error.TextWrong, check_ls_text(ls_head ++ odd, 0, "pgdata", "pg", 1));
    const short = "pgdata  38.5 MiB  2026-10-23 10:00:01\n";
    try testing.expectError(error.TextWrong, check_ls_text(ls_head ++ short, 0, "pgdata", "pg", 1));
    // A volume whose record cannot be read shows "-" for its times: not a listing of a use.
    const unread = "pgdata  38.5 MiB  -  -  -  -\n";
    const wrong_10660 = check_ls_text(ls_head ++ unread, 0, "pgdata", "pg", 1);
    try testing.expectError(error.TextWrong, wrong_10660);
}

fn ps_doc(comptime state: []const u8, comptime reason: []const u8) []const u8 {
    return "{\"schema\":\"zbx.ps/1\",\"containers\":[{\"name\":\"other\",\"state\":\"running\"," ++
        "\"reason\":\"none\"},{\"name\":\"pg\",\"state\":\"" ++ state ++ "\",\"reason\":\"" ++
        reason ++ "\"}]}\n";
}

test "a killed container is recorded as stopped by a signal" {
    // Goal: step 3. Right: stopped, signal. Wrong: still running, stopped by a clean exit, a
    // container that is not listed, another schema, and text that is not JSON.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    try check_killed_record(arena, ps_doc("stopped", "signal"), 0, "pg");
    const running = check_killed_record(arena, ps_doc("running", "none"), 0, "pg");
    try testing.expectError(error.KillWrong, running);
    const exited = check_killed_record(arena, ps_doc("stopped", "exited"), 0, "pg");
    try testing.expectError(error.KillWrong, exited);
    const absent = check_killed_record(arena, ps_doc("stopped", "signal"), 0, "pg2");
    try testing.expectError(error.KillWrong, absent);
    const failed = check_killed_record(arena, ps_doc("stopped", "signal"), 1, "pg");
    try testing.expectError(error.ExitCodeWrong, failed);
    try testing.expectError(error.JsonWrong, check_killed_record(arena, "nope", 0, "pg"));
    const schema = "{\"schema\":\"zbx.other/1\",\"containers\":[]}";
    try testing.expectError(error.JsonWrong, check_killed_record(arena, schema, 0, "pg"));
}

test "no process of the container is left only when pgrep counted zero" {
    try check_none_left("0\n");
    try testing.expectError(error.KillWrong, check_none_left("7\n"));
    try testing.expectError(error.KillWrong, check_none_left(""));
    try testing.expectError(error.KillWrong, check_none_left("pgrep: not found\n"));
}

test "a run without state keeps nothing, and only a missing table says so" {
    // Goal: step 5. Right: an error that names the table. Wrong: the row came back, the query
    // worked, or the failure is something else (the server was not up).
    const missing: Streams = .{
        .stdout = "",
        .stderr = "ERROR:  relation \"t\" does not exist\nLINE 1: select v from t\n",
    };
    try check_data_gone(missing, 1, "ephemeral");
    const kept: Streams = .{ .stdout = "ephemeral\n", .stderr = "" };
    try testing.expectError(error.DataKept, check_data_gone(kept, 0, "ephemeral"));
    const both: Streams = .{ .stdout = "ephemeral\n", .stderr = missing.stderr };
    try testing.expectError(error.DataKept, check_data_gone(both, 1, "ephemeral"));
    const down: Streams = .{ .stdout = "", .stderr = "psql: error: connection refused\n" };
    try testing.expectError(error.DataKept, check_data_gone(down, 2, "ephemeral"));
    try check_data_there("ephemeral\n", 0, "ephemeral");
    try testing.expectError(error.DataKept, check_data_there("\n", 0, "ephemeral"));
    try testing.expectError(error.ExitCodeWrong, check_data_there("ephemeral\n", 2, "ephemeral"));
}

test "a removed volume is no longer listed" {
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const gone = "{\"schema\":\"zbx.state.ls/1\",\"directory\":\"/x\",\"volumes\":[" ++
        "{\"name\":\"upstate\"}],\"trash\":[{\"name\":\"pgdata\"}],\"truncated\":false}\n";
    try check_volume_absent(arena, gone, "pgdata");
    const listed = "{\"schema\":\"zbx.state.ls/1\",\"volumes\":[{\"name\":\"pgdata\"}]}\n";
    try testing.expectError(error.VolumeListed, check_volume_absent(arena, listed, "pgdata"));
    try testing.expectError(error.JsonWrong, check_volume_absent(arena, "", "pgdata"));
    try testing.expectError(error.JsonWrong, check_volume_absent(arena, "{\"x\":1}", "pgdata"));
}
