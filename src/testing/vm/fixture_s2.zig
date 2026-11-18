//! demo-s2's fixture images (docs/briefs/S2-lazy-start.md, "The demo"): every file `lazy:3g` and
//! `lazy:3g-v2` add to the pinned Alpine minirootfs, generated from one fixed seed. Pure: the
//! guest's tool (`tool_s2.zig`) writes the files from it, and the harness computes the expected
//! hashes from the same code, so neither trusts the other's copy.
//!
//! Every byte of bulk content is a xoshiro256++ stream, which deflate cannot shrink: the layer's
//! compressed size is the files' size, and a full pull at the registry's 40 MiB/s takes over 75 s
//! (`bulk_bytes` below, asserted at comptime).

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Blake3 = std.crypto.hash.Blake3;

pub const seed: u64 = 0x7a62_7832_6c61_7a79;
const mib: u64 = 1024 * 1024;
pub const weights_bytes: u64 = 2048 * mib;
pub const data_bytes: u64 = 100 * mib;
pub const data_names = "abcdef";
pub const boot_bytes: u64 = 16 * mib;
pub const site_files: u32 = 20_000;
pub const site_dirs: u32 = 100;
/// A small file is 1 to this many bytes, evenly: 20 000 of them average about 400 MiB.
pub const site_file_bytes_max: u32 = 41_942;
/// The bytes `/app/start` hashes from the front of the weights.
pub const weights_hashed_bytes: u64 = 4 * mib;
/// The store's chunk (`constants.store_chunk_bytes`), and the chunk of `/data/c.bin` step 6
/// corrupts in transit.
pub const chunk_bytes: u64 = mib;
pub const corrupt_chunk: u64 = 3;
/// What a stream hands out per call. A multiple of 8, so that a stream read in blocks is the same
/// stream however it is cut (xoshiro's `fill` discards the rest of a word at the end of a call).
pub const block_bytes: usize = 64 * 1024;
/// The registry's throttle and the full pull's floor (step 3).
pub const throttle_bytes_per_second: u64 = 40 * mib;
pub const full_pull_seconds_min: u64 = 75;
/// The longest path `path_of` writes.
pub const path_bytes_max: usize = 32;

/// Weights, data and boot: the bulk, without the small files (whose sum is checked by a test).
const bulk_bytes: u64 = weights_bytes + data_names.len * data_bytes + boot_bytes;

comptime {
    assert(block_bytes % 8 == 0);
    assert(chunk_bytes % block_bytes == 0);
    assert(boot_bytes % block_bytes == 0);
    assert(weights_hashed_bytes % block_bytes == 0);
    assert((corrupt_chunk + 1) * chunk_bytes <= data_bytes);
    assert(site_files % site_dirs == 0);
    // The small files add about 400 MiB; even without them the pull is close to the floor, so
    // the throttle must have no burst (registry_disk_s2.zig).
    const site_floor = 380 * mib;
    assert((bulk_bytes + site_floor) / throttle_bytes_per_second > full_pull_seconds_min);
}

pub const Variant = enum(u8) { v1, v2 };

pub const Kind = enum(u8) { stream, config, start };

/// One file of the fixture: where, how big, and where its bytes come from.
pub const File = struct {
    kind: Kind,
    /// The stream's id (`Stream.init`), for a stream file.
    stream: u64,
    size: u64,
    /// 0o755 for `/app/start`, 0o644 otherwise.
    mode: u32,
    path_buffer: [path_bytes_max]u8,
    path_len: u8,

    pub fn path(file: *const File) []const u8 {
        assert(file.path_len > 0);
        assert(file.path_buffer[0] == '/');
        return file.path_buffer[0..file.path_len];
    }
};

/// `/app/config`: the same in both variants.
pub const config_text = "name=lazy-3g\nseed=7a6278326c617a79\n";

/// `/app/start`: `ready` and the SHA-256 of the config, `boot.bin`'s SHA-256 and that of the
/// weights' first 4 MiB, each on a line (`ready_hex` computes the same).
pub const start_text =
    \\#!/bin/sh
    \\set -e
    \\c=$(cat /app/config)
    \\b=$(sha256sum /app/boot.bin | cut -d' ' -f1)
    \\w=$(head -c 4194304 /models/weights.bin | sha256sum | cut -d' ' -f1)
    \\echo "ready $(printf '%s\n%s\n%s\n' "$c" "$b" "$w" | sha256sum | cut -d' ' -f1)"
    \\
;

comptime {
    assert(config_text[config_text.len - 1] == '\n');
    assert(std.mem.indexOf(u8, start_text, "4194304") != null);
    assert(weights_hashed_bytes == 4194304);
}

/// The files: the weights, the small files, the data files, `boot.bin`, the config and `start`.
pub const file_count: u32 = 1 + site_files + data_names.len + 3;

/// Stream ids: one per stream file, never reused (`boot.bin` has one per variant).
const stream_weights: u64 = 1;
const stream_data: u64 = 16;
const stream_boot: u64 = 32;
const stream_site: u64 = 1024;

/// The `index`th file of `variant`, in the order the tool writes them.
pub fn file_at(index: u32, variant: Variant) File {
    assert(index < file_count);
    var file: File = .{
        .kind = .stream,
        .stream = 0,
        .size = 0,
        .mode = 0o644,
        .path_buffer = undefined,
        .path_len = 0,
    };
    const data_first = 1 + site_files;
    const boot_index = data_first + data_names.len;
    if (index == 0) {
        file.stream = stream_weights;
        file.size = weights_bytes;
        set_path(&file, "/models/weights.bin", .{});
    } else if (index < data_first) {
        const site = index - 1;
        file.stream = stream_site + site;
        file.size = site_size(site);
        set_path(&file, "/lib/site/d{d:0>2}/f{d:0>5}.bin", .{ site % site_dirs, site });
    } else if (index < boot_index) {
        const data = index - data_first;
        file.stream = stream_data + data;
        file.size = data_bytes;
        set_path(&file, "/data/{c}.bin", .{data_names[data]});
    } else if (index == boot_index) {
        file.stream = stream_boot + @backingInt(variant);
        file.size = boot_bytes;
        set_path(&file, "/app/boot.bin", .{});
    } else if (index == boot_index + 1) {
        file.kind = .config;
        file.size = config_text.len;
        set_path(&file, "/app/config", .{});
    } else {
        file.kind = .start;
        file.size = start_text.len;
        file.mode = 0o755;
        set_path(&file, "/app/start", .{});
    }
    assert(file.path_len > 0);
    return file;
}

fn set_path(file: *File, comptime format: []const u8, args: anytype) void {
    assert(format[0] == '/');
    const written = std.fmt.bufPrint(&file.path_buffer, format, args) catch unreachable; // Fits.
    file.path_len = @intCast(written.len);
}

/// The directories `file_at`'s paths need, parents first.
pub fn directory_at(index: u32, buffer: *[path_bytes_max]u8) []const u8 {
    assert(index < directory_count);
    const fixed = [_][]const u8{ "/models", "/lib", "/lib/site", "/data", "/app" };
    if (index < fixed.len) return fixed[index];
    const site = index - fixed.len;
    assert(site < site_dirs);
    return std.fmt.bufPrint(buffer, "/lib/site/d{d:0>2}", .{site}) catch unreachable; // Fits.
}

pub const directory_count: u32 = 5 + site_dirs;

/// A small file's size: 1 to `site_file_bytes_max`, from the seed and its number alone.
pub fn site_size(site: u32) u64 {
    assert(site < site_files);
    var state: u64 = seed ^ (@as(u64, site) *% 0x9e37_79b9_7f4a_7c15);
    const value = splitmix(&state);
    const size = 1 + value % site_file_bytes_max;
    assert(size >= 1 and size <= site_file_bytes_max);
    return size;
}

fn splitmix(state: *u64) u64 {
    state.* +%= 0x9e37_79b9_7f4a_7c15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

/// One file's bytes, in blocks.
pub const Stream = struct {
    prng: std.Random.Xoshiro256,
    left: u64,

    pub fn init(stream: u64, size: u64) Stream {
        assert(stream != 0);
        assert(size > 0);
        return .{ .prng = .init(seed ^ (stream *% 0xd1b5_4a32_d192_ed03)), .left = size };
    }

    /// The next `block_bytes` (or the rest), or an empty slice at the end.
    pub fn next(stream: *Stream, buffer: *[block_bytes]u8) []const u8 {
        const length: usize = @intCast(@min(stream.left, block_bytes));
        stream.prng.fill(buffer[0..length]);
        stream.left -= length;
        assert(length == block_bytes or stream.left == 0);
        return buffer[0..length];
    }
};

/// The SHA-256 of the first `size` bytes of stream `stream`, as hex.
pub fn stream_sha256(stream: u64, size: u64) [64]u8 {
    assert(size > 0);
    var hash = Sha256.init(.{});
    var reader: Stream = .init(stream, size);
    var buffer: [block_bytes]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const block = reader.next(&buffer);
        if (block.len == 0) break;
        hash.update(block);
        total += block.len;
    }
    assert(total == size);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

/// The line `/app/start` prints, without `ready `: the shell's own composition of the config
/// (its trailing newline kept, as `printf '%s\n'` puts it back) and the two hashes.
pub fn ready_hex(boot_hex: *const [64]u8, weights_hex: *const [64]u8) [64]u8 {
    assert(config_text.len > 0);
    var hash = Sha256.init(.{});
    hash.update(config_text);
    hash.update(boot_hex);
    hash.update("\n");
    hash.update(weights_hex);
    hash.update("\n");
    const result = std.fmt.bytesToHex(hash.finalResult(), .lower);
    assert(result.len == 64);
    return result;
}

/// The BLAKE3 of the `ordinal`th 1 MiB chunk of stream `stream`: how the lazy index names it.
pub fn chunk_blake3(stream: u64, ordinal: u64) [32]u8 {
    assert(stream != 0);
    var reader: Stream = .init(stream, (ordinal + 1) * chunk_bytes);
    var buffer: [block_bytes]u8 = undefined;
    var hash = Blake3.init(.{});
    var at: u64 = 0;
    while (true) {
        const block = reader.next(&buffer);
        if (block.len == 0) break;
        if (at >= ordinal * chunk_bytes) hash.update(block);
        at += block.len;
    }
    assert(at == (ordinal + 1) * chunk_bytes);
    var out: [32]u8 = undefined;
    hash.final(&out);
    return out;
}

/// What the demo asserts against, from the generator alone.
pub const Expected = struct {
    ready: [64]u8,
    data_c: [64]u8,
    data_e: [64]u8,
    /// Chunk `corrupt_chunk` of `/data/c.bin`, as the index names it.
    corrupt_chunk_hash: [32]u8,
};

pub fn expected(variant: Variant) Expected {
    const boot = stream_sha256(stream_boot + @backingInt(variant), boot_bytes);
    const weights = stream_sha256(stream_weights, weights_hashed_bytes);
    const c_index = std.mem.indexOfScalar(u8, data_names, 'c').?;
    const e_index = std.mem.indexOfScalar(u8, data_names, 'e').?;
    return .{
        .ready = ready_hex(&boot, &weights),
        .data_c = stream_sha256(stream_data + c_index, data_bytes),
        .data_e = stream_sha256(stream_data + e_index, data_bytes),
        .corrupt_chunk_hash = chunk_blake3(stream_data + c_index, corrupt_chunk),
    };
}

test "fixture: the file list is the brief's, in sizes and paths" {
    // Goal: the image is the brief's, about 3.0 GiB, with every bulk byte from a stream.
    // Method: walk every file of v1, total the sizes and look at the named ones.
    var total: u64 = 0;
    var site_total: u64 = 0;
    var index: u32 = 0;
    while (index < file_count) : (index += 1) {
        const file = file_at(index, .v1);
        try std.testing.expect(file.size > 0);
        total += file.size;
        if (std.mem.startsWith(u8, file.path(), "/lib/site/")) site_total += file.size;
    }
    try std.testing.expect(site_total > 380 * mib);
    try std.testing.expect(site_total < 420 * mib);
    try std.testing.expect(total > 3000 * mib);
    try std.testing.expect(total < 3100 * mib);
    // The pull floor of the brief's step 3, with the small files counted.
    try std.testing.expect(total / throttle_bytes_per_second > full_pull_seconds_min);
    try std.testing.expectEqualStrings("/models/weights.bin", file_at(0, .v1).path());
    try std.testing.expectEqualStrings("/lib/site/d07/f00007.bin", file_at(8, .v1).path());
    try std.testing.expectEqualStrings("/data/c.bin", file_at(1 + site_files + 2, .v1).path());
    const start = file_at(file_count - 1, .v1);
    try std.testing.expectEqualStrings("/app/start", start.path());
    try std.testing.expectEqual(@as(u32, 0o755), start.mode);
}

test "fixture: the variants differ only in boot.bin" {
    // Goal: lazy:3g-v2 is lazy:3g with another /app/boot.bin.
    // Method: compare every file of the two variants by path, size and stream.
    var index: u32 = 0;
    var differing: u32 = 0;
    while (index < file_count) : (index += 1) {
        const one = file_at(index, .v1);
        const two = file_at(index, .v2);
        try std.testing.expectEqualStrings(one.path(), two.path());
        try std.testing.expectEqual(one.size, two.size);
        if (one.stream != two.stream) {
            differing += 1;
            try std.testing.expectEqualStrings("/app/boot.bin", one.path());
        }
    }
    try std.testing.expectEqual(@as(u32, 1), differing);
}

test "fixture: streams are deterministic and cut-independent" {
    // Goal: the guest's copy and the harness's hashes agree: a stream is a function of its id.
    // Method: hash a stream twice, compare with a hand-assembled block read, and see another id
    // and a longer read differ only where they should.
    const one = stream_sha256(stream_data, 3 * block_bytes + 5);
    const two = stream_sha256(stream_data, 3 * block_bytes + 5);
    try std.testing.expectEqualSlices(u8, &one, &two);
    const other = stream_sha256(stream_data + 1, 3 * block_bytes + 5);
    try std.testing.expect(!std.mem.eql(u8, &one, &other));
    var reader: Stream = .init(stream_data, 2 * block_bytes);
    var buffer: [block_bytes]u8 = undefined;
    var whole: [2 * block_bytes]u8 = undefined;
    @memcpy(whole[0..block_bytes], reader.next(&buffer));
    @memcpy(whole[block_bytes..], reader.next(&buffer));
    try std.testing.expectEqual(@as(usize, 0), reader.next(&buffer).len);
    var hash: [32]u8 = undefined;
    Sha256.hash(&whole, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    try std.testing.expectEqualSlices(u8, &hex, &stream_sha256(stream_data, 2 * block_bytes));
}

test "fixture: the ready line is the start script's composition" {
    // Goal: `ready_hex` is what `/app/start` prints, byte for byte.
    // Method: assemble the shell's input by hand (config, boot hash, weights hash, each on a
    // line) and hash it; sizes and the expected chunk hash are checked on known small inputs.
    const boot: [64]u8 = @splat('b');
    const weights: [64]u8 = @splat('w');
    const text = config_text ++ &boot ++ "\n" ++ &weights ++ "\n";
    var hash: [32]u8 = undefined;
    Sha256.hash(text, &hash, .{});
    const want = std.fmt.bytesToHex(hash, .lower);
    try std.testing.expectEqualSlices(u8, &want, &ready_hex(&boot, &weights));
    try std.testing.expectEqual(site_size(17), site_size(17));
    var reader: Stream = .init(stream_data, 2 * chunk_bytes);
    var buffer: [block_bytes]u8 = undefined;
    var blake = Blake3.init(.{});
    var at: u64 = 0;
    while (at < 2 * chunk_bytes) : (at += block_bytes) {
        const block = reader.next(&buffer);
        if (at >= chunk_bytes) blake.update(block);
    }
    var chunk: [32]u8 = undefined;
    blake.final(&chunk);
    try std.testing.expectEqualSlices(u8, &chunk, &chunk_blake3(stream_data, 1));
}
