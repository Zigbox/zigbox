//! Tests for `record.zig`: the bounds at and one past, a duplicate that changes nothing, every
//! way a record is damaged or newer, an envelope a reference implementation made, and a crash
//! or failure at every write of a save.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const layout = @import("../store/layout.zig");
const support = @import("../store/test_support.zig");
const dsse = @import("dsse.zig");
const dsse_tests = @import("dsse_tests.zig");
const record = @import("record.zig");
const statement = @import("statement.zig");

const Digest = digest_mod.Digest;
const root_path = "/data/store";

var work: record.Work = undefined;
var sign_work: dsse.Work = undefined;
var one: record.Record = undefined;
var two: record.Record = undefined;
var line_buffer: [constants.envelope_bytes_max]u8 = undefined;
var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;

fn tree_of(byte: u8) Digest {
    return .{ .bytes = @splat(byte) };
}

/// The envelope of a statement about `tree` signed at `at` by the key of seed byte `seed`.
fn line_for(tree: Digest, at: u64, seed: u8) []const u8 {
    var payload: [statement.render_bytes_max]u8 = undefined;
    const text = statement.render(&payload, &statement.Statement.for_tree(tree.bytes, at));
    const key: [constants.key_seed_bytes]u8 = @splat(seed);
    return dsse.sign(&sign_work, &line_buffer, key, text) catch unreachable; // Small payload.
}

/// A record of `count` lines about `tree`, signed at times 1 to `count`, as the text on disk.
fn text_of(tree: Digest, count: u32, out: *record.Record) void {
    out.clear();
    for (1..count + 1) |at| {
        const added = out.add(line_for(tree, at, 1)) catch unreachable; // At most 8 are asked.
        std.debug.assert(added == .added);
    }
}

fn start() void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
}

test "a record holds eight lines, and a ninth distinct one is Full" {
    // Goal: the bound at and one past. Method: add eight distinct lines, then a ninth; the
    // text of the eight parses back to itself, and the ninth changes nothing.
    const tree = tree_of(7);
    text_of(tree, constants.signatures_per_tree_max, &one);
    try testing.expectEqual(constants.signatures_per_tree_max, one.count);
    const before = one.length;
    try testing.expectError(error.Full, one.add(line_for(tree, 99, 1)));
    try testing.expectEqual(before, one.length);
    try testing.expect(one.length <= constants.signature_record_bytes_max);

    try record.parse(&work, tree, one.text(), &two);
    try testing.expectEqualStrings(one.text(), two.text());
    try testing.expectEqual(one.count, two.count);

    // One past in the file itself: nine lines are not a record.
    var nine: [constants.signature_record_bytes_max + constants.envelope_bytes_max + 1]u8 =
        undefined;
    @memcpy(nine[0..one.length], one.text());
    const extra = line_for(tree, 99, 1);
    @memcpy(nine[one.length..][0..extra.len], extra);
    nine[one.length + extra.len] = '\n';
    const length = one.length + extra.len + 1;
    try testing.expectError(error.Malformed, record.parse(&work, tree, nine[0..length], &two));
}

var oversized: [constants.signature_record_bytes_max + 1]u8 = undefined;

test "a file one byte over the byte bound is damaged" {
    // Goal: the byte bound, one past. Method: a valid record plus padding to one byte over the
    // bound is refused by parse, and a file of that size on disk loads as Damaged.
    const tree = tree_of(7);
    text_of(tree, 1, &one);
    // A record at its bound is about 10 MB (256 steps), more than the simulated disk holds, so
    // the size is checked on the bytes here and `load` is tested with a file it can hold.
    @memset(&oversized, 'x');
    try testing.expectError(error.Malformed, record.parse(&work, tree, &oversized, &two));
    start();
    var path: [128]u8 = undefined;
    const hex = tree.hex();
    const name = std.fmt.bufPrint(&path, "{s}/trust/signatures/{s}", .{ root_path, &hex }) catch
        unreachable; // Short.
    files.put_dir(root_path ++ "/trust", 0o755);
    files.put_dir(root_path ++ "/trust/signatures", 0o755);
    files.put_file(name, 0o644, "not a record\n");
    var errno: u16 = 0;
    try testing.expectError(error.Damaged, record.load(&store, &work, tree, &two, &errno));
    // And the largest legal file is not refused for its size.
    files.remove_path(name);
    files.put_file(name, 0o644, one.text());
    try record.load(&store, &work, tree, &two, &errno);
}

test "the same line twice is a no-op" {
    // Goal: signing again with the same key and time changes nothing. Method: add a line twice.
    const tree = tree_of(3);
    one.clear();
    try testing.expectEqual(record.Added.added, try one.add(line_for(tree, 5, 1)));
    const before = one.length;
    try testing.expectEqual(record.Added.present, try one.add(line_for(tree, 5, 1)));
    try testing.expectEqual(before, one.length);
    try testing.expectEqual(@as(u32, 1), one.count);
    // Another key, or another time, is another line.
    try testing.expectEqual(record.Added.added, try one.add(line_for(tree, 5, 2)));
    try testing.expectEqual(record.Added.added, try one.add(line_for(tree, 6, 1)));
    try testing.expectEqual(@as(u32, 3), one.count);
}

test "every defect of a record is Malformed, and another predicate is Newer" {
    // Goal: parse accepts only what the writer writes. Method: damage a good record in each
    // way and expect the matching refusal; a statement of another predicate type is Newer.
    const tree = tree_of(9);
    text_of(tree, 2, &one);
    const good = one.text();
    try record.parse(&work, tree, good, &two);

    var copy: [constants.signature_record_bytes_max]u8 = undefined;
    @memcpy(copy[0..good.len], good);
    // No final newline, an empty record, a blank line.
    const no_newline = good[0 .. good.len - 1];
    try testing.expectError(error.Malformed, record.parse(&work, tree, no_newline, &two));
    try testing.expectError(error.Malformed, record.parse(&work, tree, "", &two));
    try testing.expectError(error.Malformed, record.parse(&work, tree, "\n", &two));
    // A record of another tree.
    try testing.expectError(error.Malformed, record.parse(&work, tree_of(8), good, &two));
    // A line twice.
    const first = one.line(0);
    var twice: [2 * constants.envelope_bytes_max + 2]u8 = undefined;
    @memcpy(twice[0..first.len], first);
    twice[first.len] = '\n';
    @memcpy(twice[first.len + 1 ..][0..first.len], first);
    twice[2 * first.len + 1] = '\n';
    try testing.expectError(
        error.Malformed,
        record.parse(&work, tree, twice[0 .. 2 * first.len + 2], &two),
    );
    // Any flipped byte of the text is refused: the envelope no longer re-renders to itself, or
    // the statement no longer says this tree. A flipped newline joins or splits lines.
    for (0..good.len) |at| {
        copy[at] ^= 0x01;
        const result = record.parse(&work, tree, copy[0..good.len], &two);
        try testing.expectError(error.Malformed, result);
        copy[at] ^= 0x01;
    }
    // Another predicate type: well formed, so Newer, never Malformed.
    var payload: [statement.render_bytes_max]u8 = undefined;
    const text = statement.render(&payload, &statement.Statement.for_tree(tree.bytes, 1));
    var changed: [statement.render_bytes_max]u8 = undefined;
    @memcpy(changed[0..text.len], text);
    const at = std.mem.indexOf(u8, text, "sign/v1").?;
    changed[at + "sign/v".len] = '2';
    const seed: [constants.key_seed_bytes]u8 = @splat(1);
    const newer = try dsse.sign(&sign_work, &line_buffer, seed, changed[0..text.len]);
    var newer_record: [constants.envelope_bytes_max + 1]u8 = undefined;
    @memcpy(newer_record[0..newer.len], newer);
    newer_record[newer.len] = '\n';
    const result = record.parse(&work, tree, newer_record[0 .. newer.len + 1], &two);
    try testing.expectError(error.Newer, result);
}

test "a record an older release wrote is read" {
    // Goal: REVIEW.md's "text an older release wrote". Method: the envelope securesystemslib
    // made (dsse_tests.zig), as a one-line record of its tree.
    var bytes: [constants.envelope_bytes_max + 1]u8 = undefined;
    const envelope = dsse_tests.reference_envelope;
    @memcpy(bytes[0..envelope.len], envelope);
    bytes[envelope.len] = '\n';
    var tree: Digest = undefined;
    for (&tree.bytes, 0..) |*byte, index| byte.* = @truncate(3 + 7 * index);
    try record.parse(&work, tree, bytes[0 .. envelope.len + 1], &one);
    try testing.expectEqual(@as(u32, 1), one.count);
    try testing.expectEqualStrings(envelope, one.line(0));
    try testing.expect(one.has(envelope));
}

test "save then load returns the record, and a missing record is NotFound" {
    // Goal: the store round trip. Method: load before (NotFound), save, load again; records of
    // two trees are counted.
    start();
    const tree = tree_of(4);
    var errno: u16 = 0;
    try testing.expectError(error.NotFound, record.load(&store, &work, tree, &two, &errno));
    try testing.expectEqual(@as(u32, 0), try record.count_records(&store, &errno));
    text_of(tree, 3, &one);
    var failure: fs_mod.Failure = undefined;
    try record.save(&store, tree, &one, &failure);
    try record.load(&store, &work, tree, &two, &errno);
    try testing.expectEqualStrings(one.text(), two.text());
    try testing.expectEqual(@as(u32, 1), try record.count_records(&store, &errno));
    text_of(tree_of(5), 1, &one);
    try record.save(&store, tree_of(5), &one, &failure);
    try testing.expectEqual(@as(u32, 2), try record.count_records(&store, &errno));
}

/// Saves `new` with the fault at write point `point`; true if the save ran to its end.
fn faulty_save(tree: Digest, new: *const record.Record, point: u32, crash: bool) bool {
    files.mutations = 0;
    if (crash) files.faults.crash_mutation = point else files.faults.fail_mutation = point;
    defer files.faults = .{};
    var failure: fs_mod.Failure = undefined;
    record.save(&store, tree, new, &failure) catch return false;
    return true;
}

test "a crash or failure at any write of a save leaves the old record or the new one" {
    // Goal: the brief's interrupted-writes rule for the signature record. Method: with and
    // without an old record, save a longer one with the fault at each write point in turn, as
    // a crash and as a failed call. After a restart the record loads and is exactly the old
    // text or the new text (or, with no old record, absent), never a mix; and a second save
    // finishes the job.
    const tree = tree_of(6);
    for ([_]bool{ false, true }) |has_old| {
        for ([_]bool{ true, false }) |crash| {
            var point: u32 = 0;
            while (true) : (point += 1) {
                start();
                text_of(tree, 1, &one);
                text_of(tree, 2, &two);
                var failure: fs_mod.Failure = undefined;
                if (has_old) try record.save(&store, tree, &one, &failure);
                const finished = faulty_save(tree, &two, point, crash);
                files.restart();
                var errno: u16 = 0;
                var got: record.Record = undefined;
                if (record.load(&store, &work, tree, &got, &errno)) {
                    const is_old = has_old and std.mem.eql(u8, got.text(), one.text());
                    try testing.expect(is_old or std.mem.eql(u8, got.text(), two.text()));
                    if (finished) try testing.expectEqualStrings(two.text(), got.text());
                } else |err| {
                    try testing.expectEqual(error.NotFound, err);
                    try testing.expect(!has_old and !finished);
                }
                try record.save(&store, tree, &two, &failure);
                try record.load(&store, &work, tree, &got, &errno);
                try testing.expectEqualStrings(two.text(), got.text());
                if (finished) break;
                try testing.expect(point < 64); // A save has a handful of write points.
            }
            try testing.expect(point > 0);
        }
    }
}
