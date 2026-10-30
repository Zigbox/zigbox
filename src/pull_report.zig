//! What the pull's child tells its parent. The child runs in a user namespace in a process of its
//! own (`store/namespace.zig`), so nothing it computes reaches the parent but its exit code and
//! what it writes to a pipe. The library prints nothing, so the child does not either: it writes
//! a report, and the parent turns it into the caller's progress events, diagnostic and result.
//!
//! The report is records, each a kind (one byte), the length of its payload (two bytes, little
//! endian) and the payload:
//!
//!   - `warning`: a diagnostic as `Diag.encode` writes it, any number, in the order raised;
//!   - `failure`: the diagnostic that ended the child, last, and only with a non-zero exit;
//!   - `result`: the tree's digest, six counts and how many warnings did not fit; last, and only
//!     with exit 0.
//!
//! The parent reads the pipe after the child has ended, so the child never waits for it: a report
//! is at most `pull_report_bytes_max` bytes, well under a pipe's capacity. The warnings share
//! `pull_report_warnings_bytes_max` of it and the rest is kept for the last record, which
//! therefore always fits; a warning that does not fit is counted in the result, not sent.
//!
//! Both ends are here so that they are tested against each other, and the reader accepts only
//! what the writer writes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;

const Host = host_mod.Host;

pub const Kind = enum(u8) { warning = 1, failure = 2, result = 3 };

/// What the child counted, for the result of the pull.
pub const Counts = struct {
    files: u64,
    directories: u64,
    symlinks: u64,
    bytes: u64,
    special_skipped: u64,
    xattrs_skipped: u64,
};

/// The result record.
pub const Done = struct {
    tree: Digest,
    counts: Counts,
    /// Warnings the child raised that the report had no room for.
    warnings_dropped: u32,
};

pub const Record = union(Kind) {
    /// The payload is `Diag.encode`'s text; it is valid as long as the report's bytes are.
    warning: []const u8,
    failure: []const u8,
    result: Done,
};

pub const Malformed = error{Malformed};

// ---- The child's end -----------------------------------------------------------------------

pub const Writer = struct {
    host: Host,
    pipe: host_mod.Handle,
    used: u32,
    warnings_used: u32,
    dropped: u32,
    ended: bool,

    pub fn init(writer: *Writer, host: Host, pipe: host_mod.Handle) void {
        writer.* = .{
            .host = host,
            .pipe = pipe,
            .used = 0,
            .warnings_used = 0,
            .dropped = 0,
            .ended = false,
        };
        assert(writer.used == 0);
    }

    /// Sends a warning if it fits the warnings' share of the report, else counts it.
    pub fn warning(writer: *Writer, diag: *const Diag) void {
        assert(diag.code != null);
        assert(!writer.ended);
        var payload: [constants.diag_carry_bytes_max]u8 = undefined;
        const text = diag.encode(&payload);
        const size: u32 = @intCast(constants.pull_report_header_bytes + text.len);
        const fits = writer.warnings_used + size <= constants.pull_report_warnings_bytes_max;
        if (!fits) {
            writer.dropped +|= 1;
            return;
        }
        if (!writer.send(.warning, text)) {
            writer.dropped +|= 1;
            return;
        }
        writer.warnings_used += size;
        assert(writer.warnings_used <= constants.pull_report_warnings_bytes_max);
    }

    /// The last record of a child that failed. If the pipe cannot be written the parent says only
    /// that the worker failed.
    pub fn failure(writer: *Writer, diag: *const Diag) void {
        assert(diag.code != null);
        assert(!writer.ended);
        var payload: [constants.diag_carry_bytes_max]u8 = undefined;
        const text = diag.encode(&payload);
        _ = writer.send(.failure, text);
        writer.ended = true;
    }

    /// The last record of a child that finished.
    pub fn result(writer: *Writer, tree: Digest, counts: Counts) void {
        assert(!writer.ended);
        var payload: [constants.pull_report_result_bytes]u8 = undefined;
        const done: Done = .{ .tree = tree, .counts = counts, .warnings_dropped = writer.dropped };
        const bytes = encode_done(&payload, &done);
        assert(bytes.len == constants.pull_report_result_bytes);
        _ = writer.send(.result, bytes);
        writer.ended = true;
    }

    fn send(writer: *Writer, kind: Kind, payload: []const u8) bool {
        assert(payload.len > 0);
        assert(payload.len <= constants.diag_carry_bytes_max);
        const size: u32 = @intCast(constants.pull_report_header_bytes + payload.len);
        assert(writer.used + size <= constants.pull_report_bytes_max);
        var record: [constants.pull_report_header_bytes + constants.diag_carry_bytes_max]u8 =
            undefined;
        record[0] = @backingInt(kind);
        std.mem.writeInt(u16, record[1..3], @intCast(payload.len), .little);
        @memcpy(record[3..][0..payload.len], payload);
        writer.host.write_handle_all(writer.pipe, record[0..size]) catch return false;
        writer.used += size;
        return true;
    }
};

fn encode_done(out: *[constants.pull_report_result_bytes]u8, done: *const Done) []const u8 {
    @memcpy(out[0..constants.store_digest_bytes], &done.tree.bytes);
    const counts = done.counts;
    const numbers = [6]u64{
        counts.files,
        counts.directories,
        counts.symlinks,
        counts.bytes,
        counts.special_skipped,
        counts.xattrs_skipped,
    };
    var at: usize = constants.store_digest_bytes;
    for (numbers) |number| {
        std.mem.writeInt(u64, out[at..][0..8], number, .little);
        at += 8;
    }
    std.mem.writeInt(u32, out[at..][0..4], done.warnings_dropped, .little);
    at += 4;
    assert(at == out.len);
    return out[0..at];
}

fn decode_done(bytes: []const u8) Malformed!Done {
    if (bytes.len != constants.pull_report_result_bytes) return error.Malformed;
    var done: Done = undefined;
    @memcpy(&done.tree.bytes, bytes[0..constants.store_digest_bytes]);
    var numbers: [6]u64 = undefined;
    var at: usize = constants.store_digest_bytes;
    for (&numbers) |*number| {
        number.* = std.mem.readInt(u64, bytes[at..][0..8], .little);
        at += 8;
    }
    done.counts = .{
        .files = numbers[0],
        .directories = numbers[1],
        .symlinks = numbers[2],
        .bytes = numbers[3],
        .special_skipped = numbers[4],
        .xattrs_skipped = numbers[5],
    };
    done.warnings_dropped = std.mem.readInt(u32, bytes[at..][0..4], .little);
    return done;
}

// ---- The parent's end ----------------------------------------------------------------------

/// Reads a report record by record. After a failure or a result nothing may follow.
pub const Reader = struct {
    bytes: []const u8,
    at: u32,
    ended: bool,
    /// The bytes of the warnings so far: the writer sends no more than its share.
    warnings_used: u32,

    pub fn init(bytes: []const u8) Reader {
        assert(bytes.len <= constants.pull_report_bytes_max);
        return .{ .bytes = bytes, .at = 0, .ended = false, .warnings_used = 0 };
    }

    /// The next record, or null at the end of a report that ended where a record ends.
    pub fn next(reader: *Reader) Malformed!?Record {
        assert(reader.at <= reader.bytes.len);
        if (reader.at == reader.bytes.len) return null;
        if (reader.ended) return error.Malformed;
        const rest = reader.bytes[reader.at..];
        if (rest.len < constants.pull_report_header_bytes) return error.Malformed;
        const length = std.mem.readInt(u16, rest[1..3], .little);
        if (length == 0 or length > constants.diag_carry_bytes_max) return error.Malformed;
        const size = constants.pull_report_header_bytes + @as(u32, length);
        if (rest.len < size) return error.Malformed;
        const payload = rest[constants.pull_report_header_bytes..size];
        const kind = std.enums.fromInt(Kind, rest[0]) orelse return error.Malformed;
        reader.at += size;
        switch (kind) {
            .warning => {
                // The writer counts a warning past its share instead of sending it.
                reader.warnings_used += size;
                if (reader.warnings_used > constants.pull_report_warnings_bytes_max) {
                    return error.Malformed;
                }
                return .{ .warning = payload };
            },
            .failure => {
                reader.ended = true;
                return .{ .failure = payload };
            },
            .result => {
                reader.ended = true;
                return .{ .result = try decode_done(payload) };
            },
        }
    }
};

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const HostSim = @import("host_sim.zig").HostSim;
const sim_run = @import("runtime/sim_run.zig");

/// A simulated host with a pipe, and a writer on it: for the tests of this file and of the parent
/// that reads the report (`pull.zig`), which builds reports with the real writer.
pub const Rig = struct {
    sim: HostSim,
    pipe: host_mod.Pipe,
    writer: Writer,

    pub fn setup(rig: *Rig) void {
        sim_run.init(&rig.sim, 1);
        rig.pipe = rig.sim.interface().pipe() catch unreachable; // A fresh simulator has room.
        rig.writer.init(rig.sim.interface(), rig.pipe.write);
    }

    /// Everything written so far, read back.
    pub fn report(rig: *Rig, out: *[constants.pull_report_bytes_max]u8) []const u8 {
        const host = rig.sim.interface();
        host.close(rig.pipe.write);
        var length: usize = 0;
        while (length < out.len) {
            const count = host.read_some(rig.pipe.read, out[length..]) catch break;
            if (count == 0) break;
            length += count;
        }
        host.close(rig.pipe.read);
        return out[0..length];
    }
};

pub fn warning_of(code: @import("diag/codes.zig").Code, word: []const u8) Diag {
    var diag: Diag = undefined;
    diag.reset();
    diag.raise(code);
    diag.cause("{s}", .{word});
    return diag;
}

test "warnings, then a result, read back as written" {
    // Goal: the two ends agree. Method: two warnings and a result with every count different, so
    // a swapped field shows; the reader gives them in order and then the end.
    var rig: Rig = undefined;
    rig.setup();
    const first = warning_of(.W0501, "first");
    const second = warning_of(.W0502, "second");
    rig.writer.warning(&first);
    rig.writer.warning(&second);
    var tree: Digest = undefined;
    @memset(&tree.bytes, 0xab);
    const counts: Counts = .{
        .files = 1,
        .directories = 2,
        .symlinks = 3,
        .bytes = 1 << 40,
        .special_skipped = 5,
        .xattrs_skipped = 6,
    };
    rig.writer.result(tree, counts);
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    var reader = Reader.init(rig.report(&buffer));
    var decoded: Diag = undefined;
    decoded.reset();
    try testing.expect(decoded.decode((try reader.next()).?.warning));
    try testing.expectEqual(@as(?@import("diag/codes.zig").Code, .W0501), decoded.code);
    decoded.reset();
    try testing.expect(decoded.decode((try reader.next()).?.warning));
    try testing.expectEqualStrings("second", decoded.last_cause().?);
    const done = (try reader.next()).?.result;
    try testing.expect(done.tree.eql(tree));
    try testing.expectEqual(counts, done.counts);
    try testing.expectEqual(@as(u32, 0), done.warnings_dropped);
    try testing.expectEqual(@as(?Record, null), try reader.next());
}

test "a failure carries its diagnostic, and ends the report" {
    // Goal: the child's diagnostic reaches the parent whole. Method: a failure with a cause and a
    // fix; the reader returns it, and bytes after it are refused.
    var rig: Rig = undefined;
    rig.setup();
    var diag = warning_of(.E0515, "an entry would leave the root");
    diag.fix(.{ .sentence = "pull another image:", .command = "zbx pull alpine:3.20" });
    rig.writer.failure(&diag);
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const bytes = rig.report(&buffer);
    var reader = Reader.init(bytes);
    var back: Diag = undefined;
    back.reset();
    try testing.expect(back.decode((try reader.next()).?.failure));
    try testing.expectEqual(@as(?@import("diag/codes.zig").Code, .E0515), back.code);
    try testing.expectEqual(@as(usize, 1), back.fixes.slice().len);
    try testing.expectEqual(@as(?Record, null), try reader.next());
    var longer: [constants.pull_report_bytes_max]u8 = undefined;
    @memcpy(longer[0..bytes.len], bytes);
    @memcpy(longer[bytes.len..][0..bytes.len], bytes);
    var again = Reader.init(longer[0 .. 2 * bytes.len]);
    _ = try again.next();
    try testing.expectError(error.Malformed, again.next());
}

test "warnings stop at their share, are counted, and the last record still fits" {
    // Goal: the bound and one past it. Method: warnings of the largest size a diagnostic can
    // carry until some are refused; the report stays within its maximum, the dropped warnings
    // are counted in the result, and a failure after them is still written whole.
    var rig: Rig = undefined;
    rig.setup();
    var big: Diag = undefined;
    big.reset();
    big.raise(.W0501);
    var line: [constants.diag_field_bytes_max]u8 = @splat('x');
    for (0..constants.diag_causes_count_max) |_| big.cause("{s}", .{&line});
    var sent: u32 = 0;
    while (sent < 64 and rig.writer.dropped == 0) : (sent += 1) rig.writer.warning(&big);
    try testing.expect(rig.writer.dropped == 1);
    try testing.expect(sent >= 2);
    try testing.expect(rig.writer.warnings_used <= constants.pull_report_warnings_bytes_max);
    var tree: Digest = undefined;
    @memset(&tree.bytes, 1);
    var failing = big;
    rig.writer.failure(&failing);
    try testing.expect(rig.writer.used <= constants.pull_report_bytes_max);
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    var reader = Reader.init(rig.report(&buffer));
    var count: u32 = 0;
    var last_was_failure = false;
    while (try reader.next()) |record| : (count += 1) last_was_failure = record == .failure;
    // `sent` calls ended at the first dropped one, so `sent - 1` warnings were written, and then
    // the failure.
    try testing.expectEqual(sent, count);
    try testing.expect(last_was_failure);
}

test "a report that is cut, padded or mislabelled is refused" {
    // Goal: the reader accepts only what the writer writes. Method: a valid report, each prefix
    // that does not end at a record, a zero length, an unknown kind and a result of the wrong
    // size.
    var rig: Rig = undefined;
    rig.setup();
    const warn = warning_of(.W0501, "w");
    rig.writer.warning(&warn);
    var tree: Digest = undefined;
    @memset(&tree.bytes, 2);
    rig.writer.result(tree, std.mem.zeroes(Counts));
    var buffer: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    const bytes = rig.report(&buffer);
    for (1..bytes.len) |cut| {
        var reader = Reader.init(bytes[0..cut]);
        var failed = false;
        var records: u32 = 0;
        while (true) {
            const record = reader.next() catch {
                failed = true;
                break;
            };
            if (record == null) break;
            records += 1;
        }
        // A cut at the end of the first record is a whole report of one warning; any other cut is
        // refused.
        const first_length = bytes[1] | @as(usize, bytes[2]) << 8;
        const first_end = constants.pull_report_header_bytes + first_length;
        try testing.expectEqual(cut != first_end, failed);
    }
    var altered: [constants.pull_report_bytes_max]u8 = undefined;
    @memcpy(altered[0..bytes.len], bytes);
    altered[0] = 9; // Not a kind.
    var unknown = Reader.init(altered[0..bytes.len]);
    try testing.expectError(error.Malformed, unknown.next());
    altered[0] = 1;
    altered[1] = 0;
    altered[2] = 0; // A zero length.
    var empty = Reader.init(altered[0..bytes.len]);
    try testing.expectError(error.Malformed, empty.next());
    var small: [4]u8 = .{ 3, 1, 0, 7 }; // A result of one byte.
    var short = Reader.init(&small);
    try testing.expectError(error.Malformed, short.next());
}

test "warnings past the writer's share are refused by the reader" {
    // Goal: the reader refuses what the writer never writes (the bound, and one past it).
    // Method: records of maximal warnings built by hand, each sized as the writer sizes them;
    // as many as fit the share are read, one more is Malformed, and a result after the last
    // that fits is read.
    const payload_len = constants.diag_carry_bytes_max;
    const record_len = constants.pull_report_header_bytes + payload_len;
    const fitting = @divFloor(constants.pull_report_warnings_bytes_max, record_len);
    assert(fitting >= 1);
    var bytes: [constants.pull_report_bytes_max]u8 = @splat(0x55);
    var at: usize = 0;
    for (0..fitting + 1) |_| {
        bytes[at] = @backingInt(Kind.warning);
        std.mem.writeInt(u16, bytes[at + 1 ..][0..2], payload_len, .little);
        at += record_len;
    }
    var reader = Reader.init(bytes[0..at]);
    for (0..fitting) |_| try testing.expect((try reader.next()).? == .warning);
    // One more warning than the share holds, unless the share holds the rest of the report.
    const over = fitting * record_len + record_len > constants.pull_report_warnings_bytes_max;
    try testing.expect(over);
    try testing.expectError(error.Malformed, reader.next());
}
