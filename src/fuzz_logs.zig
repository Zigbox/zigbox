//! The container-log fuzzer: `zig build fuzz -- logs`. Each iteration builds a log on the
//! simulated disk with the real writer (random records, a random small file size so the cap
//! drops the oldest ones, short writes and interrupts), and checks the reader gives back exactly
//! a contiguous run of the newest records, with `dropped_bytes` the size of the records before
//! it. It then crashes the machine at a random write point and checks the same after a restart;
//! and damages the one file of a log that fits (flips of up to four bytes, a cut, a zeroed or
//! garbage tail) and checks the reader returns only records that were written, in order,
//! stopping at or before the damage. The writer's record list is the oracle.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const logfile = @import("runtime/logfile.zig");
const records = @import("runtime/records.zig");
const SimFs = @import("store/fs_sim.zig").SimFs;

const payload_bytes_max: u32 = 40;
const records_max: u32 = 160;
const logs_dir = "/s/zbx/logs";

var disk: SimFs = undefined;

const Written = struct {
    stream: logfile.Stream,
    time: u64,
    len: u32,
    bytes: [payload_bytes_max]u8,
};

var oracle: [records_max]Written = undefined;

fn dir() records.Dir {
    var out: records.Dir = undefined;
    @memcpy(out.path[0..logs_dir.len], logs_dir);
    out.path[logs_dir.len] = 0;
    out.len = logs_dir.len;
    out.existing_len = 0;
    return out;
}

fn random_record(random: std.Random, index: u32) Written {
    var made: Written = undefined;
    made.stream = if (random.boolean()) .stdout else .stderr;
    made.time = random.uintLessThan(u64, constants.log_time_max);
    made.len = random.intRangeAtMost(u32, 1, payload_bytes_max);
    random.bytes(&made.bytes);
    made.bytes[0] = @truncate(index); // Records differ even when the random bytes do not.
    return made;
}

const Outcome = struct {
    /// Records the writer finished before it stopped (a crash or a fault).
    done: u32,
    options: logfile.WriterOptions,
};

fn write_log(random: std.Random, total: u32, options: logfile.WriterOptions) Outcome {
    assert(total <= records_max);
    const directory = dir();
    var writer: logfile.Writer = undefined;
    var done: u32 = 0;
    writer.open(disk.interface(), &directory, "web", options) catch {
        return .{ .done = 0, .options = options };
    };
    for (0..total) |index| {
        oracle[index] = random_record(random, @intCast(index));
        const record = &oracle[index];
        writer.append(record.stream, record.time, record.bytes[0..record.len]) catch break;
        done += 1;
    }
    writer.close();
    return .{ .done = done, .options = options };
}

/// What the reader returned, checked against the oracle: the records are
/// `oracle[first..][0..count]`.
const Found = struct { first: u32, count: u32, dropped: u64 };

fn read_log(total: u32, expect_all: bool) ?Found {
    const directory = dir();
    var reader: logfile.Reader = undefined;
    reader.open(disk.interface(), &directory, "web") catch return null;
    defer reader.close();
    var count: u32 = 0;
    var first: u32 = 0;
    while (true) {
        const found = switch (reader.next()) {
            .record => |item| item,
            .end, .damaged => break,
            .failed => @panic("the simulated disk failed a read"),
        };
        const wanted = find_at(found.payload, found.time, found.stream, total) orelse
            @panic("the reader returned a record that was never written");
        if (count == 0) {
            first = wanted;
        } else if (wanted != first + count) {
            @panic("the reader skipped or repeated a record");
        }
        count += 1;
    }
    if (expect_all and count > 0) assert(first + count == total);
    return .{ .first = first, .count = count, .dropped = reader.dropped_bytes };
}

/// The index of the record in the oracle that has these contents; the first byte carries the
/// index, so the match is unique.
fn find_at(payload: []const u8, time: u64, stream: logfile.Stream, total: u32) ?u32 {
    if (payload.len == 0) return null;
    const index: u32 = payload[0];
    for (0..total) |candidate| {
        if (candidate & 0xff != index) continue;
        const record = &oracle[candidate];
        if (record.len != payload.len) continue;
        if (record.time != time or record.stream != stream) continue;
        if (!std.mem.eql(u8, record.bytes[0..record.len], payload)) continue;
        return @intCast(candidate);
    }
    return null;
}

fn payload_of_records(from: u32, to: u32) u64 {
    var size: u64 = 0;
    for (from..to) |index| size += oracle[index].len;
    return size;
}

fn size_of_records(from: u32, to: u32) u64 {
    var size: u64 = 0;
    for (from..to) |index| size += constants.log_record_header_bytes + oracle[index].len;
    return size;
}

fn fresh_disk(random: std.Random) void {
    disk.init(random.int(u64));
    disk.put_dir("/s", 0o755);
    disk.put_dir("/s/zbx", 0o755);
    disk.put_dir("/s/zbx/logs", 0o755);
}

/// A log without faults: the newest records, contiguous, ending at the last, and the dropped
/// bytes add up.
fn check_cap(random: std.Random) void {
    fresh_disk(random);
    const total = random.intRangeAtMost(u32, 1, records_max);
    const record_max = random.intRangeAtMost(u32, payload_bytes_max, 64);
    const segment = constants.log_header_bytes + constants.log_record_header_bytes + record_max +
        random.uintLessThan(u32, 400);
    const options: logfile.WriterOptions = .{
        .segment_bytes_max = segment,
        .record_bytes_max = record_max,
    };
    if (random.boolean()) disk.faults.short_write_per_mille = random.uintLessThan(u16, 1000);
    disk.faults.interrupt_per_mille = random.uintLessThan(u16, 300);
    const outcome = write_log(random, total, options);
    assert(outcome.done == total);
    disk.faults.short_write_per_mille = 0;
    const found = read_log(total, true) orelse @panic("a log that was written cannot be opened");
    assert(found.count > 0);
    assert(found.first + found.count == total);
    assert(found.dropped == payload_of_records(0, found.first));
    // Two files hold at most twice the file size, and the window starts at a file boundary.
    const size = size_of_records(found.first, total);
    assert(size <= 2 * @as(u64, segment));
    assert(disk.open_count() == 0);
}

/// The machine dies at a random write point; after a restart the log is a contiguous run of
/// whole records, none from the future.
fn check_crash(random: std.Random) void {
    fresh_disk(random);
    const total = random.intRangeAtMost(u32, 1, records_max / 2);
    const options: logfile.WriterOptions = .{
        .segment_bytes_max = constants.log_header_bytes + constants.log_record_header_bytes +
            payload_bytes_max + random.uintLessThan(u32, 300),
        .record_bytes_max = payload_bytes_max,
    };
    disk.faults.crash_mutation = random.uintLessThan(u32, total * 3 + 4);
    disk.faults.short_write_per_mille = random.uintLessThan(u16, 700);
    const outcome = write_log(random, total, options);
    disk.faults.short_write_per_mille = 0;
    disk.restart();
    const found = read_log(total, false) orelse return;
    if (found.count > 0) assert(found.first + found.count <= outcome.done);
    assert(disk.open_count() == 0);
}

/// Damage to the one file of a log that fits, and the records that must survive it.
fn check_damage(random: std.Random) void {
    fresh_disk(random);
    const total = random.intRangeAtMost(u32, 1, 60);
    const outcome = write_log(random, total, .{});
    assert(outcome.done == total);
    const path = logs_dir ++ "/web.log";
    const whole = disk.content_of(path).?;
    const copy_bytes = constants.log_header_bytes +
        60 * (constants.log_record_header_bytes + payload_bytes_max);
    var copy: [copy_bytes]u8 = undefined;
    @memcpy(copy[0..whole.len], whole);
    var length = whole.len;
    switch (random.uintLessThan(u8, 4)) {
        0 => {
            const at = random.uintLessThan(usize, length);
            const burst = @min(random.intRangeAtMost(usize, 1, 4), length - at);
            for (copy[at..][0..burst]) |*byte| byte.* ^= random.intRangeAtMost(u8, 1, 255);
        },
        1 => length = random.uintAtMost(usize, length),
        2 => {
            const at = random.uintLessThan(usize, length);
            @memset(copy[at..length], 0);
        },
        else => {
            const at = random.uintLessThan(usize, length);
            random.bytes(copy[at..length]);
        },
    }
    // The earliest byte that is not what was written: records that end before it must survive,
    // and none that ends after it may be returned (a zeroed run over bytes that were zero
    // changes nothing, so the first difference is looked for, not assumed).
    var touched = length;
    for (copy[0..length], whole[0..length], 0..) |now, before, at| {
        if (now != before) {
            touched = at;
            break;
        }
    }
    disk.remove_path(path);
    disk.put_file(path, 0o600, copy[0..length]);
    const found = read_log(total, false) orelse return;
    assert(found.first == 0);
    if (touched >= constants.log_header_bytes) {
        assert(found.dropped == 0);
        // Every record the reader returns lies wholly before the first damaged byte.
        assert(constants.log_header_bytes + size_of_records(0, found.count) <= touched);
    }
}

pub fn fuzz_logs(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_cap(random);
    check_crash(random);
    check_damage(random);
}
