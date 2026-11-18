//! demo-s2's measured numbers (docs/briefs/S2-lazy-start.md, "The demo"): the guest script prints
//! one `s2: recorded <key> <value>` line per number, and the harness collects them here and checks
//! every bound again on the runner, so a bound cannot pass only because the script's own test was
//! wrong, and every number is printed as recorded whether it passed or not.

const std = @import("std");
const assert = std.debug.assert;
const fixture = @import("fixture_s2.zig");

const mib: u64 = 1024 * 1024;

pub const Key = enum(u8) {
    /// Step 2: from the command to its `ready` line.
    lazy_ms,
    /// Step 2: what the registry had served when the `ready` line came.
    lazy_bytes_at_ready,
    /// Step 2: the bytes zbx's summary line says the registry sent, and what the registry's
    /// counter says it served as chunks; the two must agree to the byte.
    lazy_sent_bytes,
    registry_chunk_bytes,
    /// Step 3: the whole pull.
    pull_ms,
    /// Step 4: from `run -d --lazy` to `local_percent` 100.
    fill_ms,
    /// Step 5: what the registry served for `lazy:3g-v2` next to a whole `lazy:3g`.
    source_bytes,
    /// Step 7: the first read once the registry is down, the second, and the read once it is up.
    cut_first_ms,
    cut_second_ms,
    cut_recover_ms,
};

pub const key_count = @typeInfo(Key).@"enum".field_names.len;

/// The brief's bounds, each a strict upper bound unless named otherwise.
pub const lazy_ms_max: u64 = 10_000;
pub const lazy_bytes_at_ready_max: u64 = 64 * mib;
pub const pull_ms_min: u64 = fixture.full_pull_seconds_min * 1000;
pub const fill_ms_max: u64 = 300_000; // Inclusive: the wait's own bound.
pub const source_bytes_max: u64 = 20 * mib;
pub const cut_first_ms_max: u64 = 35_000;
pub const cut_second_ms_max: u64 = 7_000;
pub const cut_recover_ms_max: u64 = 10_000;

pub const Recorded = struct {
    values: [key_count]?u64 = @splat(null),

    pub fn get(recorded: *const Recorded, key: Key) ?u64 {
        return recorded.values[@backingInt(key)];
    }
};

/// Takes every `s2: recorded <key> <value>` line of `output`; a key that is not known, a value
/// that is not a number or a key recorded twice is an error, not a skipped line.
pub fn collect(recorded: *Recorded, output: []const u8) !void {
    assert(output.len <= 1 << 30);
    const prefix = "s2: recorded ";
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        var words = std.mem.splitScalar(u8, line[prefix.len..], ' ');
        const name = words.next() orelse return error.BadRecordedLine;
        const text = words.next() orelse return error.BadRecordedLine;
        if (words.next() != null) return error.BadRecordedLine;
        const key = std.meta.stringToEnum(Key, name) orelse return error.UnknownRecordedKey;
        const value = std.fmt.parseInt(u64, text, 10) catch return error.BadRecordedLine;
        const slot = &recorded.values[@backingInt(key)];
        if (slot.* != null) return error.RecordedTwice;
        slot.* = value;
    }
}

/// Null when every number is present and inside its bound; otherwise the first failure, as a
/// line for the log.
pub fn verdict(recorded: *const Recorded, buffer: []u8) ?[]const u8 {
    assert(buffer.len >= 128);
    for (0..key_count) |at| {
        const key: Key = @fromBackingInt(@intCast(at));
        if (recorded.get(key) == null) {
            return std.fmt.bufPrint(buffer, "{s} was not recorded", .{@tagName(key)}) catch
                "a number was not recorded";
        }
    }
    const value = struct {
        fn of(from: *const Recorded, key: Key) u64 {
            return from.get(key).?;
        }
    }.of;
    const below = [_]struct { Key, u64 }{
        .{ .lazy_ms, lazy_ms_max },
        .{ .lazy_bytes_at_ready, lazy_bytes_at_ready_max },
        .{ .fill_ms, fill_ms_max + 1 },
        .{ .source_bytes, source_bytes_max },
        .{ .cut_first_ms, cut_first_ms_max },
        .{ .cut_second_ms, cut_second_ms_max },
        .{ .cut_recover_ms, cut_recover_ms_max },
    };
    for (below) |rule| {
        if (value(recorded, rule[0]) >= rule[1]) {
            return std.fmt.bufPrint(buffer, "{s} {d} is not under {d}", .{
                @tagName(rule[0]), value(recorded, rule[0]), rule[1],
            }) catch "a number is over its bound";
        }
    }
    if (value(recorded, .pull_ms) <= pull_ms_min) return "the full pull took no more than 75 s";
    // Implied by the two bounds above (10 s against 75 s), and checked as the brief states it.
    if (value(recorded, .lazy_ms) * 4 >= value(recorded, .pull_ms)) {
        return "the lazy start took no less than a quarter of the full pull";
    }
    if (value(recorded, .lazy_sent_bytes) != value(recorded, .registry_chunk_bytes)) {
        return "zbx's summary and the registry's counter disagree on the bytes sent";
    }
    return null;
}

const testing = std.testing;

const passing =
    \\s2: lazy: ready: ok
    \\s2: recorded lazy_ms 3100
    \\s2: recorded lazy_bytes_at_ready 41000000
    \\s2: recorded lazy_sent_bytes 120000000
    \\s2: recorded registry_chunk_bytes 120000000
    \\s2: recorded pull_ms 80500
    \\s2: recorded fill_ms 90000
    \\s2: recorded source_bytes 18000000
    \\s2: recorded cut_first_ms 31000
    \\s2: recorded cut_second_ms 40
    \\s2: recorded cut_recover_ms 2500
    \\
;

test "checks_s2: a run inside every bound passes" {
    // Goal: the numbers of a good run are all taken and pass.
    // Method: collect a hand-written log with every key and no other recorded line.
    var recorded: Recorded = .{};
    try collect(&recorded, passing);
    var buffer: [256]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), verdict(&recorded, &buffer));
    try testing.expectEqual(@as(?u64, 80500), recorded.get(.pull_ms));
}

test "checks_s2: each bound fails on its own" {
    // Goal: every bound of the brief is checked, at its edge.
    // Method: from the passing log, move one number to its bound and expect a failure naming it.
    const cases = [_]struct { Key, u64, []const u8 }{
        .{ .lazy_ms, lazy_ms_max, "lazy_ms" },
        .{ .lazy_bytes_at_ready, lazy_bytes_at_ready_max, "lazy_bytes_at_ready" },
        .{ .fill_ms, fill_ms_max + 1, "fill_ms" },
        .{ .source_bytes, source_bytes_max, "source_bytes" },
        .{ .cut_first_ms, cut_first_ms_max, "cut_first_ms" },
        .{ .cut_second_ms, cut_second_ms_max, "cut_second_ms" },
        .{ .cut_recover_ms, cut_recover_ms_max, "cut_recover_ms" },
        .{ .pull_ms, pull_ms_min, "75 s" },
        .{ .registry_chunk_bytes, 120_000_001, "disagree" },
    };
    for (cases) |case| {
        var recorded: Recorded = .{};
        try collect(&recorded, passing);
        recorded.values[@backingInt(case[0])] = case[1];
        var buffer: [256]u8 = undefined;
        const failure = verdict(&recorded, &buffer) orelse return error.TestExpectedFailure;
        try testing.expect(std.mem.indexOf(u8, failure, case[2]) != null);
    }
}

test "checks_s2: a missing, unknown, doubled or malformed number is refused" {
    // Goal: a script that forgot a number, or printed one the harness does not know, fails.
    // Method: collect logs with each fault.
    var buffer: [256]u8 = undefined;
    var missing: Recorded = .{};
    try collect(&missing, "s2: recorded lazy_ms 3100\n");
    try testing.expect(std.mem.indexOf(u8, verdict(&missing, &buffer).?, "not recorded") != null);
    var recorded: Recorded = .{};
    try testing.expectError(error.UnknownRecordedKey, collect(&recorded, "s2: recorded x 1\n"));
    try testing.expectError(error.BadRecordedLine, collect(&recorded, "s2: recorded lazy_ms\n"));
    try testing.expectError(error.BadRecordedLine, collect(&recorded, "s2: recorded lazy_ms 1s\n"));
    var twice: Recorded = .{};
    const doubled = "s2: recorded pull_ms 1\ns2: recorded pull_ms 2\n";
    try testing.expectError(error.RecordedTwice, collect(&twice, doubled));
}
