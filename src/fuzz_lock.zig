//! The `lock` fuzzer: `zig build fuzz -- lock`. The two text formats an image brings home are
//! read from disk by a later process, and a person edits one of them: `zbx.lock` and the image
//! record (with the settings of the image's configuration). Each iteration makes a lock of random
//! entries and an image record of random settings, writes them, reads them back, then damages
//! the text and reads that.
//!
//! Properties, every iteration:
//!   1. What was written is read back exactly: the entries (sorted), the settings (in order), the
//!      tags of the record (in order, at most the bound, a repeat of a reference merged).
//!   2. A lock that parses and is written again is the same bytes (a fixed point); the same for
//!      the record's settings.
//!   3. Damaged text never crashes the reader. If it still parses, writing it and reading that
//!      again gives the same entries.
//!   4. Noise of any bytes, including NUL and bytes over 127, never crashes either reader.
//!   5. A lock with pins (M9 slice 3c) is version 2 and its pins read back exactly, sorted by
//!      file then step; a lock without pins is version 1.
//!   6. A record with one tag, written as M4's version 1 (`.reference`), reads as that one tag.

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

const pin_files = [_][]const u8{ "zbx.build.zon", "drift.build.zon", "sub/a b.zon", "q\"z" };
const pin_steps = [_][]const u8{ "fetch", "use", "a", "steady-1" };

fn same_pins(one: *const lock_file.Lock, other: *const lock_file.Lock) bool {
    if (one.pin_count != other.pin_count) return false;
    for (one.pins[0..one.pin_count], other.pins[0..other.pin_count]) |*left, *right| {
        if (!std.mem.eql(u8, one.pin_file(left), other.pin_file(right))) return false;
        if (!std.mem.eql(u8, one.pin_step(left), other.pin_step(right))) return false;
        if (!left.key.eql(right.key) or !left.output.eql(right.output)) return false;
    }
    return true;
}

fn same_lock(one: *const lock_file.Lock, other: *const lock_file.Lock) bool {
    if (!same_pins(one, other)) return false;
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
    const pins_wanted = if (random.boolean()) 0 else random.uintAtMost(u32, 10);
    for (0..pins_wanted) |_| {
        const file = pin_files[random.uintLessThan(usize, pin_files.len)];
        const step = pin_steps[random.uintLessThan(usize, pin_steps.len)];
        first.put_pin(file, step, random_digest(random), random_digest(random)) catch {
            unreachable; // Ten pins of short names fit.
        };
    }
    for (first.pins[0..first.pin_count], 0..) |*after, index| {
        if (index == 0) continue;
        const before = &first.pins[index - 1];
        const files = std.mem.order(u8, first.pin_file(before), first.pin_file(after));
        assert(files != .gt);
        if (files == .eq) {
            assert(std.mem.order(u8, first.pin_step(before), first.pin_step(after)) == .lt);
        }
    }
    const written = lock_file.render(&first, &text);
    // 5. The version follows the pins.
    const shown: []const u8 = if (first.pin_count == 0) "version = 1," else "version = 2,";
    assert(std.mem.indexOf(u8, written, shown) != null);
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

/// Copies `source` into `out` with a few random edits: flipped bytes, a cut, a removed line, a
/// line copied elsewhere, or a lock line inserted.
fn damage(source: []const u8, out: []u8, random: std.Random) usize {
    assert(source.len <= out.len);
    @memcpy(out[0..source.len], source);
    var length = source.len;
    const edits = random.uintAtMost(u32, 4);
    for (0..edits) |_| {
        if (length == 0) break;
        switch (random.uintLessThan(u8, 6)) {
            0 => out[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3),
            1 => length = random.uintLessThan(usize, length),
            2 => length = remove_line(out, length, random),
            3 => length = copy_line(out, length, random),
            4 => length = insert_line(out, length, random),
            else => out[random.uintLessThan(usize, length)] = random.int(u8),
        }
    }
    return length;
}

/// Lines a hand edit could add: each field of a lock or record, given again.
const inserted_lines = [_][]const u8{
    "    .version = 1,\n",
    "    .version = 2,\n",
    "    .pins = .{\n",
    "    .images = .{\n",
    "        .{\n",
    "        },\n",
    "            .file = \"zbx.build.zon\",\n",
    "            .step = \"fetch\",\n",
    "            .reference = \"alpine:3.20\",\n",
    "            .platform = \"linux/amd64\",\n",
};

/// The start of the line holding `at`.
fn line_start(buffer: []const u8, at: usize) usize {
    assert(at <= buffer.len);
    return if (std.mem.lastIndexOfScalar(u8, buffer[0..at], '\n')) |found| found + 1 else 0;
}

/// Puts `line` at the start of a random line of `buffer[0..length]`, if it fits.
fn put_line(buffer: []u8, length: usize, line: []const u8, random: std.Random) usize {
    assert(length <= buffer.len);
    assert(line.len > 0);
    if (length + line.len > buffer.len) return length;
    const at = line_start(buffer[0..length], random.uintAtMost(usize, length));
    std.mem.copyBackwards(u8, buffer[at + line.len ..], buffer[at..length]);
    @memcpy(buffer[at..][0..line.len], line);
    return length + line.len;
}

/// Copies a random line of `buffer[0..length]` to the start of another random line.
fn copy_line(buffer: []u8, length: usize, random: std.Random) usize {
    assert(length > 0);
    assert(length <= buffer.len);
    const at = random.uintLessThan(usize, length);
    const start = line_start(buffer[0..length], at);
    const end = (std.mem.indexOfScalarPos(u8, buffer[0..length], at, '\n') orelse length - 1) + 1;
    var line: [512]u8 = undefined;
    if (end - start > line.len) return length;
    @memcpy(line[0 .. end - start], buffer[start..end]);
    return put_line(buffer, length, line[0 .. end - start], random);
}

fn insert_line(buffer: []u8, length: usize, random: std.Random) usize {
    assert(length <= buffer.len);
    const line = inserted_lines[random.uintLessThan(usize, inserted_lines.len)];
    return put_line(buffer, length, line, random);
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
    image.tag_count = 0;
    // More pulls than the record keeps, so the bound and the merging of a repeat are exercised.
    for (0..random.uintAtMost(u32, constants.image_tags_max + 3)) |_| {
        const reference = references[random.uintLessThan(usize, references.len)];
        // A digest is never a tag: the record keeps only what the pull was typed as.
        if (std.mem.indexOfScalar(u8, reference, '@') == null) image.add_tag(reference);
        assert(image.tag_count <= constants.image_tags_max);
    }
    image.manifest = random_manifest(random);
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = random_manifest(random);
    image.tree = random_digest(random);
    image.time = random.uintLessThan(u64, 1 << 40);
    image.layer_count = random.uintAtMost(u32, 4);
    for (image.layers[0..image.layer_count]) |*layer| layer.* = random_manifest(random);
    image.settings.clear();
    image.labels.clear();
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
    fill_labels(random);
    image.partial = random.uintLessThan(u32, 4) == 0;
}

/// Labels: none, some in any order (the record keeps them sorted), or unknown.
fn fill_labels(random: std.Random) void {
    image.labels.clear();
    const names = [_][]const u8{ "org.zigbox.tree", "a", "b.c", "quote\"", "z" };
    const texts = [_][]const u8{ "", "v", "two words", "back\\slash", "\"" };
    for (0..random.uintAtMost(u32, 5)) |_| {
        const name = names[random.uintLessThan(usize, names.len)];
        _ = image.labels.add(name, texts[random.uintLessThan(usize, texts.len)]);
    }
    if (random.uintLessThan(u32, 8) == 0) image.labels.forget();
}

fn same_labels(one: *const images.Labels, other: *const images.Labels) bool {
    if (one.known != other.known or one.count() != other.count()) return false;
    for (0..one.count()) |index| {
        const at: u32 = @intCast(index);
        if (!std.mem.eql(u8, one.key(at), other.key(at))) return false;
        if (!std.mem.eql(u8, one.value(at), other.value(at))) return false;
    }
    return true;
}

fn same_tags(one: *const images.Image, other: *const images.Image) bool {
    if (one.tag_count != other.tag_count) return false;
    for (0..one.tag_count) |index| {
        const at: u32 = @intCast(index);
        if (!std.mem.eql(u8, one.tag_text(at), other.tag_text(at))) return false;
    }
    return true;
}

/// The record as M4 wrote it: version 1 and `.reference` for the one tag. Only for a record
/// with exactly one tag.
fn as_version_one(written: []const u8, out: []u8) []const u8 {
    assert(image.tag_count == 1);
    const version_at = std.mem.indexOf(u8, written, "version = 3").?;
    const tags_at = std.mem.indexOf(u8, written, ".tags = ").?;
    assert(version_at < tags_at);
    var length: usize = 0;
    const pieces = [_][]const u8{
        written[0..version_at],              "version = 1",
        written[version_at + 11 .. tags_at], ".reference = ",
        written[tags_at + 8 ..],
    };
    for (pieces) |piece| {
        @memcpy(out[length..][0..piece.len], piece);
        length += piece.len;
    }
    return out[0..length];
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
    assert(same_labels(&image.labels, &back.labels));
    assert(back.layer_count == image.layer_count);
    assert(back.tree.eql(image.tree));
    assert(same_tags(&image, &back));
    assert(back.partial == image.partial);
    // 2. A fixed point.
    var rewritten: [constants.image_record_bytes_max]u8 = undefined;
    assert(std.mem.eql(u8, written, images.render(&back, &rewritten)));
    // 5. M4's version 1 reads as the one tag, and is written as version 2.
    const plain = !image.partial and image.labels.known and image.labels.count() == 0;
    if (image.tag_count == 1 and plain) {
        const old = as_version_one(written, &record_damaged);
        assert(images.parse(old, &back) == .ok);
        assert(same_tags(&image, &back));
        assert(!back.labels.known); // An old record has none to derive from.
        back.labels.clear();
        assert(std.mem.eql(u8, written, images.render(&back, &rewritten)));
    }
    // 3. Damaged text: never a crash; if it reads, it writes and reads again the same.
    for (0..4) |_| {
        const length = damage(written, &record_damaged, random);
        if (images.parse(record_damaged[0..length], &back) != .ok) continue;
        var copy: images.Image = back;
        const out = images.render(&copy, &rewritten);
        assert(images.parse(out, &back) == .ok);
        assert(same_settings(&copy.settings, &back.settings));
        assert(same_labels(&copy.labels, &back.labels));
        assert(same_tags(&copy, &back));
    }
}

pub fn fuzz_lock(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    fuzz_lock_text(random);
    fuzz_record_text(random);
}
