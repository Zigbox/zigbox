//! BLAKE3 chaining values of aligned subtrees: what anchors each chunk of a many-chunk file to
//! the file's content hash (`docs/decisions/2026-11-14-s2-chunk-anchor.md`).
//!
//! BLAKE3 hashes 1 KiB pieces (its own "chunks", here called pieces to keep "chunk" for the
//! store's 1 MiB chunks) and joins their chaining values pairwise, the left subtree always
//! holding the largest power of two of pieces that leaves the right one at least a byte. So a
//! piece run that starts at a multiple of `chunk_bytes` (a power of two, at least one piece) and
//! is `chunk_bytes` long, or is the input's last and shorter, is one subtree of the whole hash.
//! `Subtree` hashes such a run to its chaining value (never the root flag: it is a subtree), and
//! `Joiner` joins the runs' values in order into the content hash, as BLAKE3's own tree does.
//!
//! std's `Blake3` keeps its compression function and its tree private, so this file has its own
//! portable copy of both, checked against std's root hash by the tests below and by the
//! `chaining` fuzzer. Pure: no store, no I/O.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Digest = @import("../store/digest.zig").Digest;

pub const piece_bytes: u32 = 1024;
pub const block_bytes: u32 = 64;
const blocks_per_piece: u32 = piece_bytes / block_bytes;
/// Deep enough for 2^54 pieces, BLAKE3's own bound; far beyond `store_file_bytes_max`.
const stack_max: u32 = 54;

const flag_chunk_start: u32 = 1;
const flag_chunk_end: u32 = 2;
const flag_parent: u32 = 4;
const flag_root: u32 = 8;

const iv: [8]u32 = .{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const permutation: [16]u8 = .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

comptime {
    assert(constants.store_chunk_bytes % piece_bytes == 0);
    assert(std.math.isPowerOfTwo(constants.store_chunk_bytes));
    assert(constants.store_digest_bytes == 32);
    assert(@as(u64, 1) << stack_max > constants.store_file_bytes_max / piece_bytes);
}

const Words = [8]u32;

fn mix(state: *[16]u32, a: u8, b: u8, c: u8, d: u8, x: u32, y: u32) void {
    state[a] = state[a] +% state[b] +% x;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 16);
    state[c] = state[c] +% state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 12);
    state[a] = state[a] +% state[b] +% y;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 8);
    state[c] = state[c] +% state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 7);
}

/// What one compression is given beside its chaining value and block.
const Block = struct {
    /// The bytes of the block that are input (the rest is zero).
    length: u32,
    counter: u64,
    flags: u32,
};

/// BLAKE3's compression function, keeping only the eight words a chaining value needs.
fn compress(cv: *const Words, block: *const [block_bytes]u8, how: Block) Words {
    assert(how.length <= block_bytes);
    assert(how.flags <= flag_chunk_start | flag_chunk_end | flag_parent | flag_root);
    var message: [16]u32 = undefined;
    for (&message, 0..) |*word, at| word.* = read_word(block, at);
    const counter_low: u32 = @truncate(how.counter);
    const counter_high: u32 = @truncate(how.counter >> 32);
    var state: [16]u32 = .{
        cv[0],       cv[1],        cv[2],      cv[3],
        cv[4],       cv[5],        cv[6],      cv[7],
        iv[0],       iv[1],        iv[2],      iv[3],
        counter_low, counter_high, how.length, how.flags,
    };
    for (0..7) |round| {
        mix(&state, 0, 4, 8, 12, message[0], message[1]);
        mix(&state, 1, 5, 9, 13, message[2], message[3]);
        mix(&state, 2, 6, 10, 14, message[4], message[5]);
        mix(&state, 3, 7, 11, 15, message[6], message[7]);
        mix(&state, 0, 5, 10, 15, message[8], message[9]);
        mix(&state, 1, 6, 11, 12, message[10], message[11]);
        mix(&state, 2, 7, 8, 13, message[12], message[13]);
        mix(&state, 3, 4, 9, 14, message[14], message[15]);
        if (round == 6) break;
        var permuted: [16]u32 = undefined;
        for (&permuted, permutation) |*word, from| word.* = message[from];
        message = permuted;
    }
    var out: Words = undefined;
    for (&out, 0..) |*word, at| word.* = state[at] ^ state[at + 8];
    return out;
}

fn parent(left: *const Words, right: *const Words, root: bool) Words {
    assert(left.len == 8);
    assert(right.len == 8);
    var block: [block_bytes]u8 = undefined;
    for (left, 0..) |word, at| std.mem.writeInt(u32, block[at * 4 ..][0..4], word, .little);
    for (right, 0..) |word, at| std.mem.writeInt(u32, block[32 + at * 4 ..][0..4], word, .little);
    const flags = flag_parent | if (root) flag_root else 0;
    return compress(&iv, &block, .{ .length = block_bytes, .counter = 0, .flags = flags });
}

fn read_word(bytes: []const u8, at: usize) u32 {
    assert(at * 4 + 4 <= bytes.len);
    assert(bytes.len % 4 == 0);
    return std.mem.readInt(u32, bytes[at * 4 ..][0..4], .little);
}

fn to_digest(words: *const Words) Digest {
    var digest: Digest = undefined;
    for (words, 0..) |word, at| std.mem.writeInt(u32, digest.bytes[at * 4 ..][0..4], word, .little);
    return digest;
}

fn from_digest(digest: *const Digest) Words {
    var words: Words = undefined;
    for (&words, 0..) |*word, at| word.* = read_word(&digest.bytes, at);
    return words;
}

/// The stack of BLAKE3's incremental tree: completed left subtrees, largest first.
const Stack = struct {
    values: [stack_max]Words,
    len: u32,

    /// Adds the value of the `total`th leaf (counted from 1) and joins every subtree it closes:
    /// one per trailing zero bit of `total`.
    fn add(stack: *Stack, value: Words, total: u64) void {
        assert(total >= 1);
        assert(stack.len < stack_max);
        var joined = value;
        var count = total;
        while (count & 1 == 0) : (count >>= 1) {
            assert(stack.len >= 1);
            stack.len -= 1;
            joined = parent(&stack.values[stack.len], &joined, false);
        }
        stack.values[stack.len] = joined;
        stack.len += 1;
    }

    /// Joins `last`, the final leaf's value, with everything on the stack; the root flag goes
    /// on the final parent only when `root`.
    fn fold(stack: *Stack, last: Words, root: bool) Words {
        assert(stack.len >= 1);
        assert(stack.len <= stack_max);
        var joined = last;
        while (stack.len > 0) {
            stack.len -= 1;
            joined = parent(&stack.values[stack.len], &joined, root and stack.len == 0);
        }
        return joined;
    }
};

/// The chaining value of one aligned run of input, fed in pieces of any length.
pub const Subtree = struct {
    stack: Stack,
    piece_cv: Words,
    block: [block_bytes]u8,
    block_len: u32,
    /// Blocks of the current piece already compressed.
    blocks_done: u32,
    /// BLAKE3's piece counter for the current piece: the run's offset in pieces, plus pieces done.
    counter: u64,
    pieces_done: u64,
    total: u64,
    run_bytes_max: u64,

    /// Starts the run of `run_bytes_max` (at most) bytes that begins at byte
    /// `ordinal * run_bytes_max` of the input; `run_bytes_max` is a power of two, at least a piece.
    pub fn init(subtree: *Subtree, ordinal: u64, run_bytes_max: u32) void {
        assert(std.math.isPowerOfTwo(run_bytes_max));
        assert(run_bytes_max >= piece_bytes);
        subtree.* = .{
            .stack = .{ .values = undefined, .len = 0 },
            .piece_cv = iv,
            .block = @splat(0),
            .block_len = 0,
            .blocks_done = 0,
            .counter = ordinal * (run_bytes_max / piece_bytes),
            .pieces_done = 0,
            .total = 0,
            .run_bytes_max = run_bytes_max,
        };
    }

    pub fn update(subtree: *Subtree, bytes: []const u8) void {
        assert(subtree.total + bytes.len <= subtree.run_bytes_max);
        assert(subtree.block_len <= block_bytes);
        var rest = bytes;
        while (rest.len > 0) {
            if (subtree.block_len == block_bytes) subtree.compress_block();
            const take = @min(rest.len, block_bytes - subtree.block_len);
            @memcpy(subtree.block[subtree.block_len..][0..take], rest[0..take]);
            subtree.block_len += @intCast(take);
            rest = rest[take..];
        }
        subtree.total += bytes.len;
    }

    /// Compresses the full block held, knowing more input follows it.
    fn compress_block(subtree: *Subtree) void {
        assert(subtree.block_len == block_bytes);
        assert(subtree.blocks_done < blocks_per_piece);
        var flags: u32 = if (subtree.blocks_done == 0) flag_chunk_start else 0;
        const piece_ends = subtree.blocks_done == blocks_per_piece - 1;
        if (piece_ends) flags |= flag_chunk_end;
        subtree.piece_cv = compress(&subtree.piece_cv, &subtree.block, .{
            .length = block_bytes,
            .counter = subtree.counter,
            .flags = flags,
        });
        subtree.block = @splat(0);
        subtree.block_len = 0;
        subtree.blocks_done += 1;
        if (!piece_ends) return;
        subtree.pieces_done += 1;
        subtree.stack.add(subtree.piece_cv, subtree.pieces_done);
        subtree.piece_cv = iv;
        subtree.blocks_done = 0;
        subtree.counter += 1;
    }

    /// The run's chaining value. With `root`, the hash of the input instead: right only when the
    /// run is the whole input (ordinal 0); the tests use it to check this file against std.
    pub fn final(subtree: *Subtree, root: bool) Digest {
        if (!root) assert(subtree.total >= 1);
        assert(subtree.block_len <= block_bytes);
        var flags: u32 = flag_chunk_end;
        if (subtree.blocks_done == 0) flags |= flag_chunk_start;
        const alone = subtree.stack.len == 0;
        if (root and alone) flags |= flag_root;
        const last = compress(&subtree.piece_cv, &subtree.block, .{
            .length = subtree.block_len,
            .counter = subtree.counter,
            .flags = flags,
        });
        if (alone) return to_digest(&last);
        const joined = subtree.stack.fold(last, root);
        return to_digest(&joined);
    }
};

/// The chaining value of `bytes`, the run at `ordinal` of `run_bytes_max`-byte runs.
pub fn run_value(bytes: []const u8, ordinal: u64, run_bytes_max: u32) Digest {
    assert(bytes.len >= 1);
    assert(bytes.len <= run_bytes_max);
    var subtree: Subtree = undefined;
    subtree.init(ordinal, run_bytes_max);
    subtree.update(bytes);
    return subtree.final(false);
}

/// Joins the chaining values of an input's runs, first to last, into the input's BLAKE3: what a
/// many-chunk file's chunk values must join to.
pub const Joiner = struct {
    stack: Stack,
    count: u64,

    pub fn init() Joiner {
        return .{ .stack = .{ .values = undefined, .len = 0 }, .count = 0 };
    }

    /// Adds a run's value that is not the last.
    pub fn add(joiner: *Joiner, value: *const Digest) void {
        assert(joiner.count < std.math.maxInt(u64));
        joiner.count += 1;
        joiner.stack.add(from_digest(value), joiner.count);
        assert(joiner.stack.len >= 1);
    }

    /// The root hash, `last` being the final run's value; at least two runs in all.
    pub fn root(joiner: *Joiner, last: *const Digest) Digest {
        assert(joiner.count >= 1);
        assert(joiner.stack.len >= 1);
        const joined = joiner.stack.fold(from_digest(last), true);
        return to_digest(&joined);
    }
};

const testing = std.testing;

/// A file of `count` runs of `run_bytes` (the last `short` bytes shorter), joined through its
/// runs' values, must hash as std hashes it; and a changed run value must not.
fn expect_joined(bytes: []const u8, run_bytes: u32) !void {
    const count = std.math.divCeil(usize, bytes.len, run_bytes) catch unreachable; // Not zero.
    if (count == 1) {
        var subtree: Subtree = undefined;
        subtree.init(0, run_bytes);
        subtree.update(bytes);
        try testing.expect(subtree.final(true).eql(Digest.of(bytes)));
        return;
    }
    var joiner = Joiner.init();
    var forged = Joiner.init();
    var ordinal: usize = 0;
    while (ordinal + 1 < count) : (ordinal += 1) {
        const value = run_value(bytes[ordinal * run_bytes ..][0..run_bytes], ordinal, run_bytes);
        joiner.add(&value);
        var changed = value;
        if (ordinal == 0) changed.bytes[5] ^= 1;
        forged.add(&changed);
    }
    const last = run_value(bytes[ordinal * run_bytes ..], ordinal, run_bytes);
    try testing.expect(joiner.root(&last).eql(Digest.of(bytes)));
    try testing.expect(!forged.root(&last).eql(Digest.of(bytes)));
}

test "one run with the root flag is std's hash, from nothing to a few pieces" {
    // Goal: the compression function and the piece tree are BLAKE3's. Method: every length
    // around the block and piece edges, hashed whole as one run with the root flag.
    var bytes: [4 * piece_bytes + 3]u8 = undefined;
    for (&bytes, 0..) |*byte, at| byte.* = @truncate(at *% 251 +% 7);
    const lengths = [_]usize{ 0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3000, 4096, bytes.len };
    for (lengths) |length| {
        var subtree: Subtree = undefined;
        subtree.init(0, 8 * piece_bytes);
        subtree.update(bytes[0..length]);
        try testing.expect(subtree.final(true).eql(Digest.of(bytes[0..length])));
    }
}

test "store chunks of 1, 2, 3, 5 and 8 join into the content hash, the last one partial" {
    // Goal: the anchor's claim, at the store's real chunk size: each 1 MiB-aligned chunk's
    // chaining value joins into std's BLAKE3 of the file, with a full and a partial last chunk,
    // and one changed value does not. Method: `expect_joined` on files of those chunk counts.
    const chunk = constants.store_chunk_bytes;
    const bytes = try testing.allocator.alloc(u8, 8 * chunk);
    defer testing.allocator.free(bytes);
    var prng = std.Random.Xoshiro256.init(0x5eed);
    prng.random().bytes(bytes);
    for ([_]usize{ 1, 2, 3, 5, 8 }) |count| {
        try expect_joined(bytes[0 .. count * chunk], chunk);
        try expect_joined(bytes[0 .. count * chunk - 777], chunk);
    }
    try expect_joined(bytes[0 .. chunk + 1], chunk);
    try expect_joined(bytes[0 .. 4 * chunk + 1024], chunk);
}

test "a run's value depends on where it sits, and fed in any pieces it is the same" {
    // Goal: the counter offset is part of the value (a chunk moved to another place does not
    // pass), and `update`'s splits do not change it.
    var bytes: [3 * piece_bytes + 5]u8 = undefined;
    for (&bytes, 0..) |*byte, at| byte.* = @truncate(at *% 13);
    const whole = run_value(&bytes, 2, 4 * piece_bytes);
    try testing.expect(!whole.eql(run_value(&bytes, 3, 4 * piece_bytes)));
    var subtree: Subtree = undefined;
    subtree.init(2, 4 * piece_bytes);
    subtree.update(bytes[0..1]);
    subtree.update(bytes[1..64]);
    subtree.update(bytes[64..2000]);
    subtree.update(bytes[2000..]);
    try testing.expect(subtree.final(false).eql(whole));
}
