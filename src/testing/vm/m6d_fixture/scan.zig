//! demo-m6d's fifth step: a streaming byte search for secrets, fed a file in chunks. A match that
//! spans two chunks is found once (the scanner keeps the last `longest - 1` bytes of the window),
//! and a hit names the needle by its index and the offset in the file, never the bytes it matched.
//! Pure: the guest helper (helper.zig) feeds it files, and the harness's unit tests feed it text.

const std = @import("std");
const assert = std.debug.assert;

pub const needles_max = 8;
/// A GitHub OIDC token is a JWT of about 1 KiB; Google's access tokens are shorter.
pub const needle_bytes_max = 4096;
/// The shortest needle: `ya29.`, the prefix of every Google access and federated token.
pub const needle_bytes_min = 5;
pub const chunk_bytes = 64 * 1024;

pub const Hit = struct {
    needle: u8,
    /// Where the match starts, from the start of the file.
    offset: u64,
};

pub const Scanner = struct {
    needles: [needles_max][]const u8 = undefined,
    count: u8 = 0,
    longest: u32 = 0,
    window: [needle_bytes_max - 1 + chunk_bytes]u8 = undefined,
    /// Bytes at the front of `window` kept from the chunks before.
    kept: u32 = 0,
    /// The file offset of `window[0]`.
    base: u64 = 0,
    first: ?Hit = null,

    /// `needles` are borrowed and must outlive the scanner.
    pub fn init(scanner: *Scanner, needles: []const []const u8) void {
        assert(needles.len > 0);
        assert(needles.len <= needles_max);
        scanner.count = @intCast(needles.len);
        scanner.longest = 0;
        for (needles, 0..) |needle, index| {
            assert(needle.len >= needle_bytes_min);
            assert(needle.len <= needle_bytes_max);
            scanner.needles[index] = needle;
            scanner.longest = @max(scanner.longest, @as(u32, @intCast(needle.len)));
        }
        scanner.reset();
    }

    /// Starts a new file.
    pub fn reset(scanner: *Scanner) void {
        assert(scanner.count > 0);
        scanner.kept = 0;
        scanner.base = 0;
        scanner.first = null;
        assert(scanner.longest >= needle_bytes_min);
    }

    /// Searches `chunk`, the next bytes of the file. Returns the file's first hit so far.
    pub fn feed(scanner: *Scanner, chunk: []const u8) ?Hit {
        assert(chunk.len <= chunk_bytes);
        assert(scanner.kept < scanner.longest);
        const length: u32 = scanner.kept + @as(u32, @intCast(chunk.len));
        @memcpy(scanner.window[scanner.kept..length], chunk);
        const text = scanner.window[0..length];
        for (scanner.needles[0..scanner.count], 0..) |needle, index| {
            var from: usize = 0;
            while (std.mem.indexOfPos(u8, text, from, needle)) |at| : (from = at + 1) {
                // A match that ends in the kept bytes was seen with the chunk before.
                if (at + needle.len <= scanner.kept) continue;
                scanner.note(.{ .needle = @intCast(index), .offset = scanner.base + at });
                break;
            }
        }
        const keep: u32 = @min(scanner.longest - 1, length);
        std.mem.copyForwards(u8, scanner.window[0..keep], text[length - keep ..]);
        scanner.base += length - keep;
        scanner.kept = keep;
        return scanner.first;
    }

    fn note(scanner: *Scanner, hit: Hit) void {
        assert(hit.needle < scanner.count);
        if (scanner.first) |first| {
            if (first.offset <= hit.offset) return;
        }
        scanner.first = hit;
    }
};

/// The shapes every token of its kind has, searched besides the exact secrets: a Google access
/// or federated token's prefix, and the start of the registry realm's Basic value
/// (`oauth2accesstoken:` in base64).
pub const shapes = [_][]const u8{ "ya29.", "b2F1dGgyYWNjZXNzdG9rZW46" };

/// Whether step 5 leaves `path` out: the secrets directory itself and what is under it (not a
/// sibling whose name only starts the same), and each path in the comma-separated `excludes`.
pub fn excluded(path: []const u8, secrets: []const u8, excludes: []const u8) bool {
    assert(secrets.len > 0);
    assert(secrets[secrets.len - 1] != '/');
    if (std.mem.startsWith(u8, path, secrets)) {
        if (path.len == secrets.len) return true;
        if (path[secrets.len] == '/') return true;
    }
    var list = std.mem.splitScalar(u8, excludes, ',');
    while (list.next()) |exclude| {
        if (exclude.len == 0) continue;
        if (std.mem.eql(u8, path, exclude)) return true;
    }
    return false;
}

const testing = std.testing;

fn scan_in_pieces(scanner: *Scanner, text: []const u8, piece: usize) ?Hit {
    scanner.reset();
    var at: usize = 0;
    var hit: ?Hit = null;
    while (at < text.len) : (at += piece) {
        hit = scanner.feed(text[at..@min(at + piece, text.len)]);
    }
    return hit;
}

test "a needle split across chunks is found once, at its offset, in any chunking" {
    // Goal: the carry between chunks loses no match and reports none twice. Method: put each
    // needle at a known offset and feed the text in every piece size from 1 to 40 bytes.
    const needles = [_][]const u8{ "secret-token-one", "ya29.", "b2F1dGgyYWNjZXNzdG9rZW46" };
    const scanner = try testing.allocator.create(Scanner);
    defer testing.allocator.destroy(scanner);
    scanner.* = .{};
    scanner.init(&needles);
    const text = "the store's record........secret-token-one....and the rest";
    var piece: usize = 1;
    while (piece <= 40) : (piece += 1) {
        const hit = scan_in_pieces(scanner, text, piece) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(@as(u8, 0), hit.needle);
        try testing.expectEqual(@as(u64, 26), hit.offset);
    }
    const shaped = "Authorization: Basic b2F1dGgyYWNjZXNzdG9rZW46eWEyOS5h";
    const basic = scan_in_pieces(scanner, shaped, 7) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 2), basic.needle);
    try testing.expectEqual(@as(u64, 21), basic.offset);
}

test "clean text has no hit; a near miss is not a hit; the earliest of two hits wins" {
    const needles = [_][]const u8{ "secret-token-one", "ya29." };
    const scanner = try testing.allocator.create(Scanner);
    defer testing.allocator.destroy(scanner);
    scanner.* = .{};
    scanner.init(&needles);
    try testing.expectEqual(@as(?Hit, null), scan_in_pieces(scanner, "ya29 secret-token-on", 3));
    const both = "..ya29.x..secret-token-one";
    const hit = scan_in_pieces(scanner, both, 4) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 1), hit.needle);
    try testing.expectEqual(@as(u64, 2), hit.offset);
    // A second file starts clean.
    try testing.expectEqual(@as(?Hit, null), scan_in_pieces(scanner, "nothing here", 5));
}

test "a whole chunk of filler between two halves of a long needle" {
    // Goal: the carry is the longest needle's length less one, so a needle as long as the bound,
    // cut at a chunk boundary after full chunks, is still found.
    var needle: [needle_bytes_max]u8 = undefined;
    for (&needle, 0..) |*byte, index| byte.* = 'a' + @as(u8, @intCast(index % 26));
    const needles = [_][]const u8{&needle};
    const scanner = try testing.allocator.create(Scanner);
    defer testing.allocator.destroy(scanner);
    scanner.* = .{};
    scanner.init(&needles);
    const filler = try testing.allocator.alloc(u8, chunk_bytes - 100);
    defer testing.allocator.free(filler);
    @memset(filler, '.');
    try testing.expectEqual(@as(?Hit, null), scanner.feed(filler));
    try testing.expectEqual(@as(?Hit, null), scanner.feed(needle[0..100]));
    const hit = scanner.feed(needle[100..]) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, chunk_bytes - 100), hit.offset);
}

/// Feeds `chunk_bytes - before` bytes of filler, then the needle and filler to fill the next
/// chunk, so the needle starts `before` bytes before the first chunk boundary.
fn hit_across_boundary(scanner: *Scanner, needle: []const u8, before: usize) !?Hit {
    assert(before <= needle.len);
    const text = try testing.allocator.alloc(u8, 2 * chunk_bytes);
    defer testing.allocator.free(text);
    @memset(text, '.');
    @memcpy(text[chunk_bytes - before ..][0..needle.len], needle);
    scanner.reset();
    _ = scanner.feed(text[0..chunk_bytes]);
    return scanner.feed(text[chunk_bytes..]);
}

test "a needle as long as the bound, with one byte past the chunk boundary, is found" {
    // Goal: the carry is exactly `longest - 1`, so a needle whose last byte alone is in the next
    // chunk is found (a carry of `longest - 2` loses it). Method: put a needle of
    // `needle_bytes_max` bytes `longest - 1` and `longest` bytes before the boundary, and wholly
    // after it.
    var needle: [needle_bytes_max]u8 = undefined;
    for (&needle, 0..) |*byte, index| byte.* = 'a' + @as(u8, @intCast(index % 26));
    const needles = [_][]const u8{&needle};
    const scanner = try testing.allocator.create(Scanner);
    defer testing.allocator.destroy(scanner);
    scanner.* = .{};
    scanner.init(&needles);
    const cases = [_]usize{ needle_bytes_max - 1, needle_bytes_max - 2, 1 };
    for (cases) |before| {
        const hit = try hit_across_boundary(scanner, &needle, before) orelse
            return error.TestUnexpectedResult;
        try testing.expectEqual(@as(u64, chunk_bytes - before), hit.offset);
    }
    // Wholly in the first chunk: found by the first feed, and not again by the second.
    const whole = try hit_across_boundary(scanner, &needle, needle_bytes_max) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, chunk_bytes - needle_bytes_max), whole.offset);
}

test "the secrets directory is excluded, a sibling that shares its prefix is not" {
    // Goal: step 5 skips only what it must. Method: paths under, at, and beside the directory.
    const secrets = "/home/demo/m6d-secrets";
    const excludes = "/home/demo/zbx,/home/demo/m6d-helper";
    try testing.expect(excluded("/home/demo/m6d-secrets", secrets, excludes));
    try testing.expect(excluded("/home/demo/m6d-secrets/oidc-0", secrets, excludes));
    try testing.expect(!excluded("/home/demo/m6d-secrets-cache/x", secrets, excludes));
    try testing.expect(!excluded("/home/demo/m6d-secretsx", secrets, excludes));
    try testing.expect(excluded("/home/demo/zbx", secrets, excludes));
    try testing.expect(excluded("/home/demo/m6d-helper", secrets, excludes));
    try testing.expect(!excluded("/home/demo/zbx.lock", secrets, excludes));
    try testing.expect(!excluded("/home/demo/project/zbx", secrets, ",,"));
}
