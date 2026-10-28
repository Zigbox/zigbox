//! The `lock` fuzzer: `zig build fuzz -- lock`. The two text formats an image brings home are
//! read from disk by a later process, and a person edits one of them: `zbx.lock` and the image
//! record (with the settings of the image's configuration). Each iteration makes a lock of random
//! entries and an image record of random settings, writes them, reads them back, then damages
//! the text and reads that.
//!
//! Properties, every iteration:
//!   1. What was written is read back exactly: the entries (sorted), the settings (in order).
//!   2. A lock that parses and is written again is the same bytes (a fixed point); the same for
//!      the record's settings.
//!   3. Damaged text never crashes the reader. If it still parses, writing it and reading that
//!      again gives the same entries.
//!   4. Noise of any bytes, including NUL and bytes over 127, never crashes either reader.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const digest_mod = @import("store/digest.zig");
const images = @import("store/images.zig");
const lock_file = @import("lock_file.zig");
const Sha256 = @import("registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;

var first: lock_file.Lock = undefined;
var second: lock_file.Lock = undefined;
var text: [constants.lock_file_bytes_max]u8 = undefined;
var again: [constants.lock_file_bytes_max]u8 = undefined;
var damaged: [constants.lock_file_bytes_max]u8 = undefined;
var record_text: [constants.image_record_bytes_max]u8 = undefined;
var record_damaged: [constants.image_record_bytes_max]u8 = undefined;
var image: images.Image = undefined;
var back: images.Image = undefined;

const digest_text = "abababababababababababababababababababababababababababababababab";

const references = [_][]const u8{
    "alpine:3.20",
    "docker.io/library/alpine:3.20",
    "python:3.12-slim",
    "ghcr.io/owner/image:v1",
    "registry.test:5000/team/app@sha256:" ++ digest_text,
    "a",
    "b/c:1",
    "x\"y",
    "back\\slash",
};

const words = [_][]const u8{
    "/bin/sh", "-c",       "echo \"hi\"", "PATH=/usr/bin:/bin", "LANG=C",
    "",        "a b",      "ta\tb",       "back\\slash",
    "ünï",
    "=",       "FOO=bar=", "/srv/app",    "app:staff",          "1000:1000",
};

fn random_digest(random: std.Random) Digest {
    var bytes: [32]u8 = undefined;
    random.bytes(&bytes);
    return Digest.of(&bytes);
}

fn random_manifest(random: std.Random) Sha256 {
    var bytes: [32]u8 = undefined;
    random.bytes(&bytes);
    return Sha256.of(&bytes);
}

fn same_lock(one: *const lock_file.Lock, other: *const lock_file.Lock) bool {
    if (one.count != other.count) return false;
    for (one.entries[0..one.count], other.entries[0..other.count]) |*left, *right| {
        if (!std.mem.eql(u8, one.reference(left), other.reference(right))) return false;
        if (!left.manifest.eql(right.manifest) or !left.tree.eql(right.tree)) return false;
        if (!std.mem.eql(u8, left.platform_text(), right.platform_text())) return false;
    }
    return true;
}

fn fuzz_lock_text(random: std.Random) void {
    first.clear();
    const wanted = random.uintAtMost(u32, 12);
    for (0..wanted) |_| {
        const reference = references[random.uintLessThan(usize, references.len)];
        const platform: []const u8 = if (random.boolean()) "linux/amd64" else "linux/arm64";
        first.put(reference, random_manifest(random), platform, random_digest(random)) catch {
            unreachable; // Twelve entries of short references fit.
        };
    }
    const written = lock_file.render(&first, &text);
    // 1. Written and read back.
    assert(lock_file.parse(written, &second) == null);
    assert(same_lock(&first, &second));
    // 2. A fixed point.
    assert(std.mem.eql(u8, written, lock_file.render(&second, &again)));
    // 3. Damaged text.
    for (0..4) |_| {
        const length = damage(written, &damaged, random);
        if (lock_file.parse(damaged[0..length], &second) != null) continue;
        const rewritten = lock_file.render(&second, &again);
        var third: lock_file.Lock = undefined;
        assert(lock_file.parse(rewritten, &third) == null);
        assert(same_lock(&second, &third));
    }
    // 4. Noise.
    var noise: [600]u8 = undefined;
    random.bytes(&noise);
    _ = lock_file.parse(noise[0..random.uintAtMost(usize, noise.len)], &second);
}

/// Copies `source` into `out` with a few random edits: flipped bytes, a cut, a duplicated or
/// removed line.
fn damage(source: []const u8, out: []u8, random: std.Random) usize {
    assert(source.len <= out.len);
    @memcpy(out[0..source.len], source);
    var length = source.len;
    const edits = random.uintAtMost(u32, 4);
    for (0..edits) |_| {
        if (length == 0) break;
        switch (random.uintLessThan(u8, 4)) {
            0 => out[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
            1 => length = random.uintLessThan(usize, length),
            2 => length = remove_line(out, length, random),
            else => out[random.uintLessThan(usize, length)] = random.int(u8),
        }
    }
    return length;
}

fn remove_line(buffer: []u8, length: usize, random: std.Random) usize {
    assert(length <= buffer.len);
    const at = random.uintLessThan(usize, length);
    const start = if (std.mem.lastIndexOfScalar(u8, buffer[0..at], '\n')) |found| found + 1 else 0;
    const end = (std.mem.indexOfScalarPos(u8, buffer[0..length], at, '\n') orelse length - 1) + 1;
    std.mem.copyForwards(u8, buffer[start..], buffer[end..length]);
    return length - (end - start);
}

fn fill_image(random: std.Random) void {
    image.reference_len = 11;
    @memcpy(image.reference[0..11], "alpine:3.20");
    image.manifest = random_manifest(random);
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = random_manifest(random);
    image.tree = random_digest(random);
    image.time = random.uintLessThan(u64, 1 << 40);
    image.layer_count = random.uintAtMost(u32, 4);
    for (image.layers[0..image.layer_count]) |*layer| layer.* = random_manifest(random);
    image.settings.clear();
    const lists = [_]images.Settings.List{ .entrypoint, .cmd, .env };
    for (lists) |list| {
        for (0..random.uintAtMost(u32, 6)) |_| {
            const word = words[random.uintLessThan(usize, words.len)];
            if (list == .env and std.mem.indexOfScalar(u8, word, '=') == null) continue;
            _ = image.settings.add(list, word);
        }
    }
    _ = image.settings.set(.workdir, if (random.boolean()) "" else "/srv/app");
    _ = image.settings.set(.user, if (random.boolean()) "" else "app:staff");
}

fn same_settings(one: *const images.Settings, other: *const images.Settings) bool {
    const lists = [_]images.Settings.List{ .entrypoint, .cmd, .env };
    for (lists) |list| {
        if (one.count(list) != other.count(list)) return false;
        for (0..one.count(list)) |index| {
            const at: u32 = @intCast(index);
            if (!std.mem.eql(u8, one.word(list, at), other.word(list, at))) return false;
        }
    }
    const singles = [_]images.Settings.Single{ .workdir, .user };
    for (singles) |single| {
        if (!std.mem.eql(u8, one.get(single), other.get(single))) return false;
    }
    return true;
}

fn fuzz_record_text(random: std.Random) void {
    fill_image(random);
    const written = images.render(&image, &record_text);
    // 1. Written and read back, settings in order.
    assert(images.parse(written, &back) == .ok);
    assert(same_settings(&image.settings, &back.settings));
    assert(back.layer_count == image.layer_count);
    assert(back.tree.eql(image.tree));
    // 2. A fixed point.
    var rewritten: [constants.image_record_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, written, images.render(&back, &rewritten)));
    // 3. Damaged text: never a crash; if it reads, it writes and reads again the same.
    for (0..4) |_| {
        const length = damage(written, &record_damaged, random);
        if (images.parse(record_damaged[0..length], &back) != .ok) continue;
        var copy: images.Image = back;
        const out = images.render(&copy, &rewritten);
        assert(images.parse(out, &back) == .ok);
        assert(same_settings(&copy.settings, &back.settings));
    }
}

pub fn fuzz_lock(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    fuzz_lock_text(random);
    fuzz_record_text(random);
}
