//! The verified-record fuzzer: `zig build fuzz -- verified`. The record `trust/verified/<tree>`
//! (`trust/tamper.zig`) is read from the store, where anyone with the store's owner's rights
//! could have written it, so it is only ever a cache. Each iteration builds a random record,
//! damages it, and checks what the reader and the check do with it.
//!
//! Properties, every iteration:
//!   1. Round trip: a record of sorted, distinct ids reads back as its entry count, up to the
//!      bound `trust_verified_entries_max`; one entry past the bound, an unsorted or repeated
//!      id, a wrong length, magic or version read as no record.
//!   2. Canonical: damaged or random bytes never crash `parse`; if it accepts them they are
//!      exactly the header `write_header` writes for the count it returned, then that many
//!      entries in strictly increasing id order.
//!   3. Never trusted for more than equality: a real record of a real tree, damaged, then an
//!      object of the tree damaged (its change time moves): the check refuses; and with nothing
//!      damaged it passes and leaves the one canonical record the next release also reads.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Diag = @import("diag/diag.zig").Diag;
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const import = @import("store/import.zig");
const layout = @import("store/layout.zig");
const support = @import("store/test_support.zig");
const verify = @import("store/verify.zig");
const Digest = @import("store/digest.zig").Digest;
const tamper = @import("trust/tamper.zig");

const header_bytes = tamper.header_bytes;
const entry_bytes = tamper.entry_bytes;
const entries_cap = tamper.entries_cap;

var big: [header_bytes + (entries_cap + 1) * entry_bytes]u8 = undefined;
var small: [header_bytes + 48 * entry_bytes]u8 = undefined;
var damaged: [header_bytes + 48 * entry_bytes + 64]u8 = undefined;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var workspace: tamper.Workspace = undefined;
var scratch: verify.Scratch = undefined;
var tree_buffer: [constants.store_tree_bytes_max]u8 = undefined;
var stack: [constants.image_import_stack_max]Digest = undefined;

fn id_less(_: void, first: [32]u8, second: [32]u8) bool {
    return std.mem.order(u8, &first, &second) == .lt;
}

/// A record of `count` entries with strictly increasing ids (the oracle's own order).
fn render_sorted(random: std.Random, buffer: []u8, count: u32) []u8 {
    assert(count <= 48);
    var ids: [48][32]u8 = undefined;
    var made: u32 = 0;
    while (made < count) : (made += 1) random.bytes(&ids[made]);
    std.mem.sortUnstable([32]u8, ids[0..count], {}, id_less);
    var index: u32 = 1;
    while (index < count) : (index += 1) {
        if (std.mem.order(u8, &ids[index - 1], &ids[index]) != .lt) ids[index][31] +%= 1;
    }
    // Only a repeat that was nudged out of order can remain; the sorted check below says so.
    tamper.write_header(buffer, count);
    for (ids[0..count], 0..) |id, at| {
        const entry = buffer[tamper.entry_at(@intCast(at))..][0..entry_bytes];
        @memcpy(entry[0..32], &id);
        random.bytes(entry[32..]);
    }
    return buffer[0 .. header_bytes + @as(usize, count) * entry_bytes];
}

fn strictly_sorted(bytes: []const u8, count: u32) bool {
    var index: u32 = 1;
    while (index < count) : (index += 1) {
        const before = bytes[tamper.entry_at(index - 1)..][0..32];
        const after = bytes[tamper.entry_at(index)..][0..32];
        if (std.mem.order(u8, before, after) != .lt) return false;
    }
    return true;
}

/// What `parse` accepted is canonical: the header it would write, then sorted entries.
fn assert_canonical(bytes: []const u8) u32 {
    const count = tamper.parse(bytes);
    if (count == 0) return 0;
    assert(count <= entries_cap);
    assert(bytes.len == header_bytes + @as(usize, count) * entry_bytes);
    var header: [header_bytes]u8 = undefined;
    tamper.write_header(&header, count);
    assert(std.mem.eql(u8, bytes[0..header_bytes], &header));
    assert(strictly_sorted(bytes, count));
    return count;
}

fn check_round_trip(random: std.Random) void {
    const count = random.uintAtMost(u32, 48);
    const text = render_sorted(random, &small, count);
    if (strictly_sorted(text, count)) {
        assert(tamper.parse(text) == count);
    } else {
        assert(tamper.parse(text) == 0);
    }
    _ = assert_canonical(text);
}

fn damage(random: std.Random, text: []const u8) []const u8 {
    var length = text.len;
    @memcpy(damaged[0..length], text);
    const rounds = random.intRangeAtMost(u32, 1, 4);
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        switch (random.uintLessThan(u8, 6)) {
            0 => if (length > 0) {
                damaged[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
            },
            1 => length = random.uintAtMost(usize, length),
            2 => if (length + 8 <= damaged.len) {
                random.bytes(damaged[length..][0..8]);
                length += 8;
            },
            3 => if (length >= header_bytes) {
                std.mem.writeInt(u32, damaged[12..16], random.int(u32), .little);
            },
            4 => if (length >= header_bytes + 2 * entry_bytes) {
                // Two entries swapped: unsorted unless they were alike.
                var tmp: [entry_bytes]u8 = undefined;
                @memcpy(&tmp, damaged[tamper.entry_at(0)..][0..entry_bytes]);
                const first = tamper.entry_at(0);
                const second = tamper.entry_at(1);
                @memcpy(damaged[first..][0..entry_bytes], damaged[second..][0..entry_bytes]);
                @memcpy(damaged[second..][0..entry_bytes], &tmp);
            },
            else => if (length >= header_bytes + entry_bytes) {
                // The first entry repeated over the second.
                const first = tamper.entry_at(0);
                const second = tamper.entry_at(1);
                @memcpy(damaged[second..][0..entry_bytes], damaged[first..][0..entry_bytes]);
            },
        }
    }
    return damaged[0..length];
}

fn check_damage(random: std.Random) void {
    const count = random.intRangeAtMost(u32, 2, 48);
    const text = render_sorted(random, &small, count);
    _ = assert_canonical(damage(random, text));
    // Random bytes with a plausible header: never crashes, canonical if accepted.
    const length = random.uintAtMost(usize, small.len);
    random.bytes(small[0..length]);
    if (length >= header_bytes and random.boolean()) {
        tamper.write_header(small[0..length], random.uintAtMost(u32, 4));
    }
    _ = assert_canonical(small[0..length]);
}

fn fill_big(count: u32) []const u8 {
    assert(count <= entries_cap + 1);
    tamper.write_header(&big, @min(count, entries_cap));
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const entry = big[tamper.entry_at_unbounded(index)..][0..entry_bytes];
        @memset(entry, 0xa5);
        std.mem.writeInt(u32, entry[0..4], index, .big);
        @memset(entry[4..32], 0);
    }
    if (count > entries_cap) std.mem.writeInt(u32, big[12..16], count, .little);
    return big[0 .. header_bytes + @as(usize, count) * entry_bytes];
}

fn check_bounds() void {
    assert(tamper.parse(fill_big(entries_cap)) == entries_cap);
    assert(tamper.parse(fill_big(entries_cap + 1)) == 0);
    assert(tamper.parse(fill_big(1)) == 1);
    assert(tamper.parse(fill_big(0)) == 0);
    // A header that says more than the bytes hold, and one that says fewer.
    const full = fill_big(3);
    assert(tamper.parse(full[0 .. full.len - 1]) == 0);
    assert(tamper.parse(big[0 .. full.len + 1]) == 0);
}

fn record_path(buffer: []u8, tree: Digest) []const u8 {
    const hex = tree.hex();
    // The buffer holds the store path, the directory and a 64-digit hex.
    return std.fmt.bufPrint(buffer, "{s}/{s}/{s}", .{
        support.user_store, tamper.directory_name, &hex,
    }) catch unreachable; // The buffer fits the path.
}

fn run_check(tree: Digest, diag: *Diag) !void {
    diag.reset();
    const lent: tamper.Lent = .{
        .scratch = &scratch,
        .tree_buffer = &tree_buffer,
        .stack = &stack,
    };
    try tamper.check(&store, &workspace, lent, tree, false, diag);
}

/// The object of the file at `/etc/passwd` is the one a record entry covers; a flip moves its
/// change time, which no record content can excuse.
fn passwd_object() []const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (files.kind_of(path) != .file) continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (std.mem.endsWith(u8, path, ".chunks")) continue;
        if (std.mem.eql(u8, files.content_of(path).?, "root:x:0:0\n")) return path;
    }
    unreachable; // The source tree has /etc/passwd.
}

fn check_store(random: std.Random, seed: u64) !void {
    sim.init(seed, &.{});
    files.init(seed);
    sim.store_fs = &files;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &import_work, "/src", options, &made, &diag);
    try run_check(made.digest, &diag);
    var path_buffer: [256]u8 = undefined;
    const path = record_path(&path_buffer, made.digest);
    const real = files.content_of(path).?;
    assert(assert_canonical(real) > 0);
    // The record, damaged or replaced by random bytes; an intact tree passes and the record is
    // canonical again afterwards.
    var copy: [header_bytes + 48 * entry_bytes]u8 = undefined;
    @memcpy(copy[0..real.len], real);
    const bad = if (random.boolean()) damage(random, copy[0..real.len]) else random_bytes(random);
    var bad_copy: [damaged.len]u8 = undefined;
    @memcpy(bad_copy[0..bad.len], bad);
    files.remove_path(path);
    files.put_file(path, 0o644, bad_copy[0..bad.len]);
    try run_check(made.digest, &diag);
    assert(assert_canonical(files.content_of(path).?) > 0);
    // Now a damaged object: refused whatever the record says.
    files.remove_path(path);
    files.put_file(path, 0o644, bad_copy[0..bad.len]);
    files.flip_byte(passwd_object(), 0);
    if (run_check(made.digest, &diag)) |_| unreachable else |_| assert(diag.code.? == .E0907);
}

fn random_bytes(random: std.Random) []const u8 {
    const length = random.uintAtMost(usize, 200);
    random.bytes(small[0..length]);
    return small[0..length];
}

pub fn fuzz_verified(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    check_round_trip(random);
    check_damage(random);
    check_bounds();
    // Cannot fail: the simulated store and the tree are fixed, the faults none.
    check_store(random, seed) catch unreachable;
}
