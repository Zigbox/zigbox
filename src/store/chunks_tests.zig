//! Tests of the verified chunk write (`chunks.zig`): good chunks in any order assemble the same
//! object an import makes; corrupted, short, long, out-of-range, duplicate and reordered
//! chunks, and a lying `Wanted`, are refused or harmless; and a crash at any write leaves the
//! store whole and the work finishable.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_sim = @import("../host_sim.zig");
const chunks = @import("chunks.zig");
const digest_mod = @import("digest.zig");
const fs_sim = @import("fs_sim.zig");
const layout = @import("layout.zig");
const object = @import("object.zig");
const support = @import("test_support.zig");
const xattrs = @import("xattrs.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;
const HostSim = host_sim.HostSim;
const SimFs = fs_sim.SimFs;
const Store = layout.Store;
const Wanted = chunks.Wanted;

const root_path = "/data/store";

var sim: HostSim = undefined;
var files: SimFs = undefined;
var store: Store = undefined;
var io: [constants.store_io_buffer_bytes]u8 = undefined;
var hashes: [16]Digest = undefined;

fn start() void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    files.put_dir("/data", 0o755);
    support.make_store_directories(&files, root_path);
    store.at(sim.interface(), root_path);
    store.chunk_bytes = 8;
}

const attrs: object.Attrs = .{ .mode = 0o640, .uid = 5, .gid = 6, .xattrs = &xattrs.empty };

/// What a caller knows about `content`: its hashes by chunk of 8 bytes.
fn wanted_for(content: []const u8) Wanted {
    var reader = object.Reader.init(store.chunk_bytes);
    if (content.len > 0) _ = reader.update(content, &hashes);
    const whole = reader.finish(&hashes);
    return .{
        .id = object.object_id(whole, attrs),
        .attrs = attrs,
        .size = content.len,
        .content = whole,
        .hashes = hashes[0..reader.count],
    };
}

fn piece(content: []const u8, index: u32) []const u8 {
    const start_at = index * store.chunk_bytes;
    return content[start_at..@min(start_at + store.chunk_bytes, content.len)];
}

fn put(wanted: *const Wanted, content: []const u8, index: u32) chunks.Error!chunks.Progress {
    var failure: chunks.Failure = undefined;
    return chunks.put_chunk(&store, &io, wanted, index, piece(content, index), &failure);
}

fn object_file(wanted: *const Wanted) [constants.sim_fs_path_bytes_max]u8 {
    var buffer: [constants.sim_fs_path_bytes_max]u8 = @splat(0);
    const hex = wanted.id.hex();
    _ = std.fmt.bufPrint(
        &buffer,
        root_path ++ "/objects/{s}/{s}",
        .{ hex[0..2], hex[2..] },
    ) catch unreachable; // Short.
    return buffer;
}

fn expect_object(wanted: *const Wanted, content: []const u8) !void {
    const path_buffer = object_file(wanted);
    const path = std.mem.sliceTo(&path_buffer, 0);
    try testing.expectEqualSlices(u8, content, files.content_of(path).?);
    const stat = files.stat_of(path).?;
    try testing.expectEqual(attrs.mode, stat.mode);
    try testing.expectEqual(attrs.uid, stat.uid);
    try testing.expectEqual(attrs.gid, stat.gid);
    try testing.expectEqual(@as(?u64, constants.store_mtime_seconds), files.mtime_of(path));
    try support.check_whole(&files, root_path, store.chunk_bytes);
}

const long = "0123456789abcdefghijklmnopqrstuvwxyz"; // 36 bytes: four full chunks and a short one.

test "chunks in any order assemble the object an import would make" {
    // Goal: the contract. Method: reversed order, then each shape of file.
    const cases = [_][]const u8{ long, "01234567", "0123456789", "short", "" };
    for (cases) |content| {
        start();
        const wanted = wanted_for(content);
        const total: u32 = @intCast(wanted.hashes.len);
        var index = total;
        var last: chunks.Progress = .{
            .have = 0,
            .total = 0,
            .complete = false,
            .duplicate = false,
        };
        if (total == 0) {
            var failure: chunks.Failure = undefined;
            last = try chunks.finish(&store, &io, &wanted, &failure);
        }
        while (index > 0) {
            index -= 1;
            last = try put(&wanted, content, index);
            try testing.expectEqual(index == 0, last.complete);
        }
        try testing.expect(last.complete);
        try expect_object(&wanted, content);
        try testing.expectEqual(
            object.list_is_stored(content.len, 8),
            files.kind_of(root_path ++ "/objects/zz") == null and total > 1,
        );
        // The chunks are gone, and the stored list is the hashes.
        try testing.expect(support.count_files(&files, root_path ++ "/partial") == 0);
    }
}

test "the chunk list the assembly stores is the one chunk_hashes reports" {
    start();
    const wanted = wanted_for(long);
    for (0..5) |index| _ = try put(&wanted, long, @intCast(index));
    var out: [constants.store_chunks_max]Digest = undefined;
    var scratch: [constants.store_io_buffer_bytes]u8 = undefined;
    const found = try object.chunk_hashes(&store, wanted.id, &scratch, &out);
    try testing.expectEqual(@as(usize, 5), found.len);
    for (found, wanted.hashes) |have, want| try testing.expect(have.eql(want));
}

test "corrupted, short, long and out-of-range chunks are refused, and nothing is written" {
    start();
    const wanted = wanted_for(long);
    var failure: chunks.Failure = undefined;
    var bad: [8]u8 = undefined;
    @memcpy(&bad, piece(long, 1));
    bad[3] ^= 1;
    try testing.expectError(
        error.HashMismatch,
        chunks.put_chunk(&store, &io, &wanted, 1, &bad, &failure),
    );
    try testing.expectError(
        error.WrongLength,
        chunks.put_chunk(&store, &io, &wanted, 1, bad[0..7], &failure),
    );
    var longer: [9]u8 = undefined;
    @memcpy(longer[0..8], piece(long, 1));
    longer[8] = 'x';
    try testing.expectError(
        error.WrongLength,
        chunks.put_chunk(&store, &io, &wanted, 1, &longer, &failure),
    );
    try testing.expectError(
        error.WrongLength,
        chunks.put_chunk(&store, &io, &wanted, 4, piece(long, 3), &failure),
    );
    try testing.expectError(
        error.WrongLength,
        chunks.put_chunk(&store, &io, &wanted, 4, "", &failure),
    );
    try testing.expectError(
        error.IndexOutOfRange,
        chunks.put_chunk(&store, &io, &wanted, 5, piece(long, 4), &failure),
    );
    // The right bytes for the wrong index are the wrong hash.
    try testing.expectError(
        error.HashMismatch,
        chunks.put_chunk(&store, &io, &wanted, 0, piece(long, 1), &failure),
    );
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/partial"));
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/objects"));
}

test "a duplicate chunk is accepted once, and a finished object is complete at once" {
    start();
    const wanted = wanted_for(long);
    const first = try put(&wanted, long, 2);
    try testing.expect(!first.duplicate);
    try testing.expectEqual(@as(u32, 1), first.have);
    const again = try put(&wanted, long, 2);
    try testing.expect(again.duplicate);
    try testing.expectEqual(@as(u32, 1), again.have);
    for ([_]u32{ 0, 1, 3, 4 }) |index| _ = try put(&wanted, long, index);
    const late = try put(&wanted, long, 1);
    try testing.expect(late.complete and late.duplicate);
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/partial"));
    try expect_object(&wanted, long);
}

test "a held chunk that was damaged is replaced, not trusted" {
    start();
    const wanted = wanted_for(long);
    _ = try put(&wanted, long, 0);
    var held: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const hex = wanted.id.hex();
    const path = std.fmt.bufPrint(
        &held,
        root_path ++ "/partial/{s}/0",
        .{hex},
    ) catch unreachable; // Short.
    files.flip_byte(path, 2);
    const again = try put(&wanted, long, 0);
    try testing.expect(!again.duplicate);
    for (1..5) |index| _ = try put(&wanted, long, @intCast(index));
    try expect_object(&wanted, long);
}

test "a wanted that lies is refused: its id, its count, its one-chunk hash" {
    start();
    const wanted = wanted_for(long);
    var failure: chunks.Failure = undefined;
    var wrong_id = wanted;
    wrong_id.id.bytes[0] ^= 1;
    try testing.expectError(
        error.BadWanted,
        chunks.put_chunk(&store, &io, &wrong_id, 0, piece(long, 0), &failure),
    );
    var short = wanted;
    short.hashes = wanted.hashes[0..4];
    try testing.expectError(
        error.BadWanted,
        chunks.put_chunk(&store, &io, &short, 0, piece(long, 0), &failure),
    );
    var other_attrs = wanted;
    other_attrs.attrs.mode = 0o600; // The id no longer matches the attributes.
    try testing.expectError(
        error.BadWanted,
        chunks.put_chunk(&store, &io, &other_attrs, 0, piece(long, 0), &failure),
    );
    const small = wanted_for("tiny");
    var lying = small;
    lying.hashes = &.{Digest.of("not tiny")};
    try testing.expectError(
        error.BadWanted,
        chunks.put_chunk(&store, &io, &lying, 0, "tiny", &failure),
    );
    const empty = wanted_for("");
    var not_empty = empty;
    not_empty.content = Digest.of("x");
    try testing.expectError(error.BadWanted, chunks.finish(&store, &io, &not_empty, &failure));
}

test "chunk hashes that lie about the content are caught when the object is assembled" {
    // Goal: the content hash is the anchor. Method: hashes of other bytes of the right length,
    // the right content hash: every chunk is accepted, and the assembly refuses.
    start();
    const real = wanted_for(long);
    const fake = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var lying = real;
    var fake_hashes: [5]Digest = undefined;
    for (0..5) |index| fake_hashes[index] = Digest.of(piece(fake, @intCast(index)));
    lying.hashes = &fake_hashes;
    for (0..4) |index| _ = try put(&lying, fake, @intCast(index));
    try testing.expectError(error.ContentMismatch, put(&lying, fake, 4));
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/objects"));
    try testing.expectEqual(@as(u32, 0), support.count_files(&files, root_path ++ "/partial"));
}

test "a crash or failure at any write leaves the store whole, and the chunks can be put again" {
    for ([_]bool{ true, false }) |crash| {
        var point: u32 = 0;
        while (true) : (point += 1) {
            start();
            const wanted = wanted_for(long);
            files.mutations = 0;
            if (crash) files.faults.crash_mutation = point else files.faults.fail_mutation = point;
            var fired = false;
            for ([_]u32{ 3, 0, 4, 1, 2 }) |index| {
                _ = put(&wanted, long, index) catch {
                    fired = true;
                    break;
                };
            }
            files.faults = .{};
            if (crash and fired) files.restart();
            try support.check_whole(&files, root_path, store.chunk_bytes);
            if (!fired) break;
            for ([_]u32{ 3, 0, 4, 1, 2 }) |index| _ = try put(&wanted, long, index);
            try expect_object(&wanted, long);
        }
        try testing.expect(point > 10);
    }
}
