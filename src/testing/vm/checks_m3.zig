//! The M3 demo's assertions as pure functions over the text the guest printed, each unit-tested
//! with right and wrong input. The commands that print the text are in main_m3.zig, and so are
//! the markers (`STORE-SAME`, `ROOT-MODE:`, ...).

const std = @import("std");
const checks = @import("checks.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// A line the step must print is missing or wrong.
    LineMissing,
    DigestWrong,
    /// The store changed while a container ran.
    StoreChanged,
    StderrNotEmpty,
    ReportWrong,
};

fn has_line(text: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), wanted)) return true;
    }
    return false;
}

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// `b3:` and 64 lowercase hex digits.
pub fn is_digest(text: []const u8) bool {
    if (text.len != 67) return false;
    if (!std.mem.startsWith(u8, text, "b3:")) return false;
    for (text[3..]) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// `zbx store import` prints the digest alone on stdout, and exits 0.
pub fn check_import(streams: Streams, status: u8) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    const digest = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!is_digest(digest)) return error.DigestWrong;
    return digest;
}

/// The step prints `scribbled` when the container's script ran to its end: it wrote, changed
/// modes and owners, and deleted across the tree.
pub fn check_scribbled(streams: Streams, status: u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(streams.stdout, "scribbled")) return error.LineMissing;
}

/// The guest compares the store's listing and sums before and after (`cmp`), and prints which.
pub fn check_store_same(output: []const u8) Error!void {
    if (has_line(output, "STORE-DIFFERS")) return error.StoreChanged;
    if (!has_line(output, "STORE-SAME")) return error.LineMissing;
}

/// The container's writes are in its own upper layer: the guest prints how many entries it
/// has, and it must have some.
pub fn check_upper_written(output: []const u8, at_least: u32) Error!void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        const marker = "UPPER-ENTRIES:";
        if (!std.mem.startsWith(u8, line, marker)) continue;
        const count = std.fmt.parseInt(u32, line[marker.len..], 10) catch return error.LineMissing;
        if (count < at_least) return error.LineMissing;
        return;
    }
    return error.LineMissing;
}

/// `--read-only` with a digest: the write is refused by the file system, the one to /tmp works.
pub fn check_read_only(
    refused: Streams,
    refused_status: u8,
    allowed: Streams,
    status: u8,
) Error!void {
    if (refused_status == 0 or refused_status == 125) return error.ExitCodeWrong;
    if (!contains(refused.stderr, "Read-only file system")) return error.LineMissing;
    if (status != 0) return error.ExitCodeWrong;
    if (!has_line(allowed.stdout, "tmp-ok")) return error.LineMissing;
}

/// `stat -c '%a %u %g' /` inside a run of a tree whose root was imported as 711.
pub fn check_root(output: []const u8, mode_owner_group: []const u8) Error!void {
    var expected: [64]u8 = undefined;
    // Cannot fail: a mode and two ids fit 64 bytes.
    const line = std.fmt.bufPrint(&expected, "ROOT:{s}", .{mode_owner_group}) catch unreachable;
    if (!has_line(output, line)) return error.LineMissing;
}

/// A digest the store lacks: ZBX-E0410 on stderr and 125, nothing on stdout.
pub fn check_unknown_digest(streams: Streams, status: u8) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (!contains(streams.stderr, "error[ZBX-E0410]")) return error.ReportWrong;
    if (streams.stdout.len != 0) return error.ReportWrong;
}

/// The run record names the tree and the upper layer.
pub fn check_record(output: []const u8, digest: []const u8) Error!void {
    if (!contains(output, digest)) return error.LineMissing;
    if (!contains(output, "/upper")) return error.LineMissing;
}

const testing = std.testing;

fn repeat(comptime byte: u8, comptime count: usize) [count]u8 {
    return @splat(byte);
}

test "a digest is b3: and 64 lowercase hex digits" {
    // Goal: the import check cannot pass on a path or a diagnostic. Method: good and bad text.
    const good = "b3:" ++ repeat('a', 64);
    try testing.expect(is_digest(good));
    try testing.expect(!is_digest(good[0..66]));
    try testing.expect(!is_digest("b3:" ++ repeat('G', 64)));
    try testing.expect(!is_digest("sha:" ++ repeat('0', 63)));
    try testing.expect(!is_digest(""));
}

test "an import prints the digest alone and exits 0" {
    const good = "b3:" ++ repeat('b', 64);
    const ok = try check_import(.{ .stdout = good ++ "\n", .stderr = "" }, 0);
    try testing.expectEqualStrings(good, ok);
    const bare: Streams = .{ .stdout = good, .stderr = "" };
    try testing.expectError(error.ExitCodeWrong, check_import(bare, 2));
    try testing.expectError(error.DigestWrong, check_import(.{ .stdout = "x\n", .stderr = "" }, 0));
    try testing.expectError(error.DigestWrong, check_import(.{ .stdout = "", .stderr = "" }, 0));
}

test "the scribble step needs its marker and a clean exit" {
    const done: Streams = .{ .stdout = "scribbled\n", .stderr = "" };
    try check_scribbled(done, 0);
    try testing.expectError(error.ExitCodeWrong, check_scribbled(done, 1));
    try testing.expectError(error.LineMissing, check_scribbled(.{ .stdout = "", .stderr = "" }, 0));
}

test "the store is the same only if the guest says so" {
    try check_store_same("x\nSTORE-SAME\n");
    try testing.expectError(error.StoreChanged, check_store_same("STORE-DIFFERS\n"));
    try testing.expectError(error.LineMissing, check_store_same("nothing\n"));
}

test "the upper layer has the container's writes" {
    try check_upper_written("UPPER-ENTRIES:120\n", 20);
    try testing.expectError(error.LineMissing, check_upper_written("UPPER-ENTRIES:3\n", 20));
    try testing.expectError(error.LineMissing, check_upper_written("none\n", 1));
}

test "read-only: the write is refused by the file system and /tmp works" {
    const refused: Streams = .{ .stdout = "", .stderr = "touch: /x: Read-only file system\n" };
    const allowed: Streams = .{ .stdout = "tmp-ok\n", .stderr = "" };
    try check_read_only(refused, 1, allowed, 0);
    try testing.expectError(error.ExitCodeWrong, check_read_only(refused, 0, allowed, 0));
    try testing.expectError(error.ExitCodeWrong, check_read_only(refused, 125, allowed, 0));
    const other: Streams = .{ .stdout = "", .stderr = "touch: /x: Permission denied\n" };
    try testing.expectError(error.LineMissing, check_read_only(other, 1, allowed, 0));
    const silent: Streams = .{ .stdout = "", .stderr = "" };
    try testing.expectError(error.LineMissing, check_read_only(refused, 1, silent, 0));
}

test "the root's mode and owner are the recorded ones" {
    try check_root("ROOT:711 0 0\n", "711 0 0");
    try testing.expectError(error.LineMissing, check_root("ROOT:755 0 0\n", "711 0 0"));
}

test "an unknown digest is E0410 and 125 with nothing on stdout" {
    const text = "error[ZBX-E0410]: no tree with that digest\n";
    const shown: Streams = .{ .stdout = "", .stderr = text };
    try check_unknown_digest(shown, 125);
    try testing.expectError(error.ExitCodeWrong, check_unknown_digest(shown, 1));
    const wrong: Streams = .{ .stdout = "", .stderr = "error[ZBX-E0412]" };
    try testing.expectError(error.ReportWrong, check_unknown_digest(wrong, 125));
    const noisy: Streams = .{ .stdout = "x", .stderr = text };
    try testing.expectError(error.ReportWrong, check_unknown_digest(noisy, 125));
}

test "the record names the tree and the upper layer" {
    try check_record("tree = \"b3:ab\"\nupper = \"/x/upper\"", "b3:ab");
    try testing.expectError(error.LineMissing, check_record("tree = \"b3:ab\"", "b3:ab"));
    try testing.expectError(error.LineMissing, check_record("upper = \"/x/upper\"", "b3:ab"));
}
