//! What the child tells the parent through the report pipe: fixed-size records, so the child
//! never formats text after `clone3`. A record is the kind, the plan step it is about, and the
//! errno the kernel returned. The parent turns a record into a diagnostic; the child only
//! writes four bytes.
//!
//! The pipe is close-on-exec, so a successful `exec` closes it. End of file with no failure
//! record is therefore how the parent learns that the command started.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Kind = enum(u8) {
    /// A step that is allowed to fail did: the run goes on, and the parent keeps the note.
    note = 1,
    /// A step failed and the child ended. The last record of a pipe.
    failure = 2,
};

pub const Record = struct {
    kind: Kind,
    step: u8,
    errno: u16,

    pub fn encode(record: Record) [constants.sync_record_bytes]u8 {
        assert(record.errno != 0);
        assert(record.errno < 4096);
        const errno_low: u8 = @truncate(record.errno);
        const errno_high: u8 = @intCast(record.errno >> 8);
        return .{ @backingInt(record.kind), record.step, errno_low, errno_high };
    }

    /// Null if the bytes are not a record. The parent treats that as a bug in the child.
    pub fn decode(bytes: *const [constants.sync_record_bytes]u8) ?Record {
        assert(bytes.len == constants.sync_record_bytes);
        const kind = std.enums.fromInt(Kind, bytes[0]) orelse return null;
        const errno: u16 = @as(u16, bytes[2]) | (@as(u16, bytes[3]) << 8);
        if (errno == 0) return null;
        if (errno >= 4096) return null;
        return .{ .kind = kind, .step = bytes[1], .errno = errno };
    }
};

/// The first record `exec`'s joiner writes when it has forked the command: a tag byte that no
/// `Kind` uses, and the command's pid as the host sees it in the three bytes after (a pid is at
/// most 2^22 on Linux, `PID_MAX_LIMIT`). A joiner that fails writes a `failure` record instead.
pub const forked_tag: u8 = 0xf0;

pub fn encode_forked(pid: u32) [constants.sync_record_bytes]u8 {
    assert(pid > 1);
    assert(pid < 1 << 24);
    return .{ forked_tag, @truncate(pid), @truncate(pid >> 8), @truncate(pid >> 16) };
}

/// The pid of a forked record, or null if the bytes are not one.
pub fn decode_forked(bytes: *const [constants.sync_record_bytes]u8) ?u32 {
    assert(bytes.len == 4);
    assert(std.enums.fromInt(Kind, forked_tag) == null); // Never a record's kind.
    if (bytes[0] != forked_tag) return null;
    const pid = @as(u32, bytes[1]) | (@as(u32, bytes[2]) << 8) | (@as(u32, bytes[3]) << 16);
    if (pid <= 1) return null;
    return pid;
}

/// What the parent learned from the pipe.
pub const Report = struct {
    notes: [constants.sync_records_max]Record,
    notes_count: u32,
    failure: ?Record,

    pub fn reset(report: *Report) void {
        report.notes_count = 0;
        report.failure = null;
        assert(report.note_slice().len == 0);
        assert(report.failure == null);
    }

    pub fn note_slice(report: *const Report) []const Record {
        assert(report.notes_count <= constants.sync_records_max);
        return report.notes[0..report.notes_count];
    }

    /// Reads whole records from `bytes`. False if a record is malformed, a failure is followed
    /// by anything, or the child wrote more records than it can have.
    pub fn parse(report: *Report, bytes: []const u8) bool {
        assert(bytes.len <= constants.sync_record_bytes * (constants.sync_records_max + 1));
        report.reset();
        if (bytes.len % constants.sync_record_bytes != 0) return false;
        var at: usize = 0;
        while (at < bytes.len) : (at += constants.sync_record_bytes) {
            const record = Record.decode(bytes[at..][0..constants.sync_record_bytes]) orelse
                return false;
            if (report.failure != null) return false; // Nothing follows a failure.
            switch (record.kind) {
                .note => {
                    if (report.notes_count == constants.sync_records_max) return false;
                    report.notes[report.notes_count] = record;
                    report.notes_count += 1;
                },
                .failure => report.failure = record,
            }
        }
        assert(report.notes_count <= constants.sync_records_max);
        return true;
    }
};

const testing = std.testing;

test "a record survives the pipe, at the edges of every field" {
    // Goal: encode and decode are inverse for the smallest and largest step and errno.
    const cases = [_]Record{
        .{ .kind = .note, .step = 0, .errno = 1 },
        .{ .kind = .failure, .step = 255, .errno = 4095 },
        .{ .kind = .failure, .step = 17, .errno = 256 },
        .{ .kind = .note, .step = 43, .errno = 13 },
    };
    for (cases) |record| {
        const bytes = record.encode();
        const decoded = Record.decode(&bytes).?;
        try testing.expectEqual(record, decoded);
    }
}

test "a forked record carries the pid and is never a record" {
    // Goal: the joiner's pid record round-trips at its bounds and cannot be read as a failure.
    for ([_]u32{ 2, 256, 4_194_304, (1 << 24) - 1 }) |pid| {
        const bytes = encode_forked(pid);
        try testing.expectEqual(@as(?u32, pid), decode_forked(&bytes));
        try testing.expect(Record.decode(&bytes) == null);
    }
    try testing.expect(decode_forked(&.{ 2, 5, 13, 0 }) == null);
    try testing.expect(decode_forked(&.{ forked_tag, 1, 0, 0 }) == null);
}

test "decode refuses bytes that are not a record" {
    // Goal: the negative space: a zero errno, an errno past the kernel's range and an unknown
    // kind are not records.
    try testing.expect(Record.decode(&.{ 2, 5, 0, 0 }) == null);
    try testing.expect(Record.decode(&.{ 2, 5, 0, 16 }) == null);
    try testing.expect(Record.decode(&.{ 0, 5, 13, 0 }) == null);
    try testing.expect(Record.decode(&.{ 3, 5, 13, 0 }) == null);
    try testing.expect(Record.decode(&.{ 1, 5, 13, 0 }) != null);
}

test "a report keeps the notes in order and ends at a failure" {
    // Goal: the parse rules: whole records only, nothing after a failure, a bounded number of
    // notes, and an empty pipe is an empty report (the command started).
    var report: Report = undefined;
    try testing.expect(report.parse(""));
    try testing.expectEqual(@as(u32, 0), report.notes_count);
    try testing.expect(report.failure == null);

    const note = (Record{ .kind = .note, .step = 22, .errno = 1 }).encode();
    const failure = (Record{ .kind = .failure, .step = 30, .errno = 2 }).encode();
    try testing.expect(report.parse(&(note ++ failure)));
    try testing.expectEqual(@as(u32, 1), report.notes_count);
    try testing.expectEqual(@as(u8, 22), report.note_slice()[0].step);
    try testing.expectEqual(@as(u8, 30), report.failure.?.step);

    try testing.expect(!report.parse(&(failure ++ note)));
    try testing.expect(!report.parse(note[0..3]));
    try testing.expect(!report.parse(&(failure ++ failure)));
    var many: [constants.sync_record_bytes * constants.sync_records_max]u8 = undefined;
    for (0..constants.sync_records_max) |index| {
        const at = index * constants.sync_record_bytes;
        @memcpy(many[at..][0..constants.sync_record_bytes], &note);
    }
    try testing.expect(report.parse(&many));
    var one_more: [many.len + constants.sync_record_bytes]u8 = undefined;
    @memcpy(one_more[0..many.len], &many);
    @memcpy(one_more[many.len..], &note);
    try testing.expect(!report.parse(&one_more));
}
