//! The `pull_report` fuzzer: `zig build fuzz -- pull_report`. What a pull's child tells its parent
//! is read by `pull.read_report` from bytes the parent cannot trust to be whole: the child may
//! die half way, and the pipe is only as honest as the code that wrote it. Each iteration has the
//! real `Writer` write a random valid report (some warnings, then a result, a failure or
//! nothing), reads it with the exit code that goes with it, then damages the bytes (a cut, flipped
//! bytes, a byte appended, noise) and reads those with any exit code.
//!
//! Properties, every iteration:
//!   1. An undamaged report with its matching exit code gives what the writer wrote: the result,
//!      or the child's failure diagnostic, and every warning that was sent, in order.
//!   2. An undamaged report with a wrong exit code, or no last record, is E0419.
//!   3. Damaged bytes never crash the reader. It accepts them (the pull succeeds) only if the
//!      exit code is 0 and the bytes are what a writer can write: warnings within their share,
//!      then exactly one result record, nothing after it.
//!   4. Any refusal of the worker is E0419, a failure the child sent is its own code, and a
//!      refused report leaves a diagnostic with a cause.

const std = @import("std");
const assert = std.debug.assert;
const codes = @import("diag/codes.zig");
const constants = @import("constants.zig");
const pull = @import("pull.zig");
const report_mod = @import("pull_report.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;

var rig: report_mod.Rig = undefined;
var buffer: [constants.pull_report_bytes_max]u8 = undefined;
var damaged: [constants.pull_report_bytes_max]u8 = undefined;
var diag: Diag = undefined;
var done: report_mod.Done = undefined;

const Ending = enum { none, result, failure };

const Seen = struct {
    warnings: u32 = 0,

    fn on_event(context: *anyopaque, event: pull.Event) void {
        const seen: *Seen = @ptrCast(@alignCast(context));
        switch (event) {
            .warning => seen.warnings += 1,
            .resolved, .blob => {},
        }
    }
};

/// What the writer wrote: the bytes, how many warnings were sent, and how it ended.
const Made = struct {
    bytes: []const u8,
    warnings_sent: u32,
    ending: Ending,
};

fn random_diag(random: std.Random, code: codes.Code) Diag {
    var made: Diag = undefined;
    made.reset();
    made.raise(code);
    const causes = random.intRangeAtMost(u32, 1, 3);
    var line: [constants.diag_field_bytes_max]u8 = undefined;
    for (0..causes) |_| {
        const length = random.intRangeAtMost(usize, 1, line.len);
        for (line[0..length]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'z');
        made.cause("{s}", .{line[0..length]});
    }
    if (random.boolean()) made.fix(.{ .sentence = "pull another image:", .command = "zbx pull a" });
    return made;
}

fn make_report(random: std.Random) Made {
    rig.setup();
    const count = random.intRangeAtMost(u32, 0, 40);
    for (0..count) |_| {
        const code: codes.Code = if (random.boolean()) .W0501 else .W0502;
        const warning = random_diag(random, code);
        rig.writer.warning(&warning);
    }
    const sent = count - rig.writer.dropped;
    const ending = random.enumValue(Ending);
    switch (ending) {
        .none => {},
        .result => {
            var tree: Digest = undefined;
            random.bytes(&tree.bytes);
            var counts = std.mem.zeroes(report_mod.Counts);
            counts.files = random.int(u64);
            counts.bytes = random.int(u64);
            rig.writer.result(tree, counts);
        },
        .failure => {
            const failing = random_diag(random, .E0515);
            rig.writer.failure(&failing);
        },
    }
    return .{ .bytes = rig.report(&buffer), .warnings_sent = sent, .ending = ending };
}

/// Reads `bytes` as the parent does; returns whether the pull is accepted.
fn read(code: u8, bytes: []const u8, seen: *Seen) bool {
    const progress: pull.Progress = .{ .context = seen, .call = Seen.on_event };
    const sink: pull.Sink = .{ .progress = progress };
    diag.reset();
    pull.read_report(code, bytes, &sink, &done, &diag) catch {
        assert(diag.code != null); // A refusal is always a diagnostic.
        assert(diag.last_cause() != null);
        return false;
    };
    assert(diag.code == null);
    return true;
}

fn check_undamaged(random: std.Random, made: Made) void {
    var seen: Seen = .{};
    const fail_code: u8 = random.intRangeAtMost(u8, 1, 255);
    switch (made.ending) {
        .result => {
            assert(read(constants.exit_ok, made.bytes, &seen));
            assert(seen.warnings == made.warnings_sent);
            seen = .{};
            assert(!read(fail_code, made.bytes, &seen));
            assert(diag.code.? == .E0419);
        },
        .failure => {
            assert(!read(fail_code, made.bytes, &seen));
            assert(diag.code.? == .E0515); // The child's own.
            assert(seen.warnings == made.warnings_sent);
            seen = .{};
            assert(!read(constants.exit_ok, made.bytes, &seen));
            assert(diag.code.? == .E0419);
        },
        .none => {
            for ([_]u8{ constants.exit_ok, fail_code }) |code| {
                seen = .{};
                assert(!read(code, made.bytes, &seen));
                assert(diag.code.? == .E0419);
            }
        },
    }
}

/// Whether `bytes` is a report a writer can write that ends in a result: warnings within their
/// share, one result record, nothing after it. Written apart from the reader.
fn writer_could_write(bytes: []const u8) bool {
    const header = constants.pull_report_header_bytes;
    var at: usize = 0;
    var warnings_bytes: usize = 0;
    while (at < bytes.len) {
        if (bytes.len - at < header) return false;
        const length = @as(usize, bytes[at + 1]) | @as(usize, bytes[at + 2]) << 8;
        if (length == 0) return false;
        if (length > constants.diag_carry_bytes_max) return false;
        if (bytes.len - at < header + length) return false;
        const kind = bytes[at];
        at += header + length;
        if (kind == 3) return length == constants.pull_report_result_bytes and at == bytes.len;
        if (kind != 1) return false;
        warnings_bytes += header + length;
        if (warnings_bytes > constants.pull_report_warnings_bytes_max) return false;
    }
    return false;
}

fn damage(random: std.Random, made: Made) []const u8 {
    const original = made.bytes;
    @memcpy(damaged[0..original.len], original);
    switch (random.uintLessThan(u32, 4)) {
        0 => { // A cut.
            if (original.len == 0) return original;
            return damaged[0..random.uintLessThan(usize, original.len)];
        },
        1 => { // Flipped bytes.
            if (original.len == 0) return original;
            for (0..random.intRangeAtMost(u32, 1, 3)) |_| {
                damaged[random.uintLessThan(usize, original.len)] ^= random.int(u8) | 1;
            }
            return damaged[0..original.len];
        },
        2 => { // A byte appended, when there is room.
            if (original.len == damaged.len) return original;
            damaged[original.len] = random.int(u8);
            return damaged[0 .. original.len + 1];
        },
        else => { // Noise.
            const length = random.uintLessThan(usize, 64);
            random.bytes(damaged[0..length]);
            return damaged[0..length];
        },
    }
}

fn check_damaged(random: std.Random, made: Made) void {
    const bytes = damage(random, made);
    const code: u8 = if (random.boolean()) constants.exit_ok else random.int(u8);
    var seen: Seen = .{};
    const accepted = read(code, bytes, &seen);
    if (accepted) {
        assert(code == constants.exit_ok);
        assert(writer_could_write(bytes));
    } else {
        const found = diag.code.?;
        // The child's own failure, or the parent's word on the worker.
        assert(found == .E0419 or found == .E0515);
    }
}

pub fn fuzz_pull_report(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    const made = make_report(random);
    check_undamaged(random, made);
    check_damaged(random, made);
}
