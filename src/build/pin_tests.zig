//! Tests of output pins (`pin.zig`): which steps are pinned, what a step's key holds, how a
//! pin is judged in each mode, and which step `--hermetic` refuses.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const file_mod = @import("file.zig");
const lock_file = @import("../lock_file.zig");
const pin = @import("pin.zig");
const Digest = @import("../store/digest.zig").Digest;

const BuildFile = file_mod.BuildFile;

/// Three steps: `fetch` (network, no pin in the file), `cached` (network and a cache mount)
/// and `offline` (no network).
const three =
    \\.{ .version = 1, .image = .{}, .steps = .{
    \\  .{ .name = "fetch", .base = "x", .run = .{ "true" }, .network = true },
    \\  .{ .name = "cached", .base = "x", .run = .{ "true" }, .network = true,
    \\     .caches = .{ .{ .id = "c", .path = "/c" } } },
    \\  .{ .name = "offline", .base = "x", .run = .{ "true" } },
    \\} }
;

var test_file: BuildFile = undefined;
var test_lock: lock_file.Lock = undefined;

fn parsed(text: []const u8) !*const BuildFile {
    var problem: file_mod.Problem = undefined;
    if (file_mod.parse(text, &test_file, &problem) == .refused) return error.TestUnexpectedResult;
    return &test_file;
}

fn empty_lock() *lock_file.Lock {
    test_lock.clear();
    return &test_lock;
}

test "only a network step without caches is pinnable, and only it takes a lock pin" {
    // Goal: the cache rule (a cache is outside the key, so its step is never pinned). Method: a
    // lock with a pin for every step; only `fetch` finds one.
    const file = try parsed(three);
    const lock = empty_lock();
    for ([_][]const u8{ "fetch", "cached", "offline" }) |name| {
        try lock.put_pin("zbx.build.zon", name, Digest.of("key"), Digest.of("out"));
    }
    const steps = file.steps_slice();
    try testing.expect(pin.pinnable(&steps[0]));
    try testing.expect(!pin.pinnable(&steps[1]));
    try testing.expect(!pin.pinnable(&steps[2]));
    try testing.expect(pin.lock_pin(lock, "zbx.build.zon", file, &steps[0]) != null);
    try testing.expect(pin.lock_pin(lock, "zbx.build.zon", file, &steps[1]) == null);
    try testing.expect(pin.lock_pin(lock, "zbx.build.zon", file, &steps[2]) == null);
    // Another build file's pin is not this one's.
    try testing.expect(pin.lock_pin(lock, "other/zbx.build.zon", file, &steps[0]) == null);
}

test "the key holds the excludes only for a step that is or may be pinned" {
    // Goal: an unpinned step's key is the one it had before pins existed. Method: every mode
    // and lock-pin state for each kind of step.
    const file = try parsed(three);
    const steps = file.steps_slice();
    try testing.expect(!pin.keyed(&steps[0], false, .plain));
    try testing.expect(!pin.keyed(&steps[0], false, .locked));
    try testing.expect(pin.keyed(&steps[0], true, .plain));
    try testing.expect(pin.keyed(&steps[0], false, .pin));
    try testing.expect(!pin.keyed(&steps[1], false, .pin));
    try testing.expect(!pin.keyed(&steps[2], false, .pin));
    var paths: [constants.build_output_excludes_max][]const u8 = undefined;
    try testing.expect(pin.excludes(file, &steps[0], false, &paths) == null);
    const defaults = pin.excludes(file, &steps[0], true, &paths).?;
    try testing.expectEqual(pin.default_excludes.len, defaults.len);
    try testing.expectEqualStrings("/var/lib/apt/lists", defaults[2]);
}

test "a written output exclude replaces the defaults and keys even an unpinned step" {
    const file = try parsed(
        \\.{ .version = 1, .image = .{}, .steps = .{
        \\  .{ .name = "a", .base = "x", .run = .{ "true" }, .output_exclude = .{ "/var/tmp" } },
        \\} }
    );
    const step = &file.steps_slice()[0];
    try testing.expect(pin.keyed(step, false, .plain));
    var paths: [constants.build_output_excludes_max][]const u8 = undefined;
    const written = pin.excludes(file, step, true, &paths).?;
    try testing.expectEqual(@as(usize, 1), written.len);
    try testing.expectEqualStrings("/var/tmp", written[0]);
}

test "a pin is judged by its key, and a stale one is refused only when the mode enforces" {
    // Goal: `.expect` wins; a current lock pin is expected; a stale one is E0822 under
    // `--locked` and `--hermetic` and is otherwise left for `--pin` to replace.
    const file = try parsed(three);
    const lock = empty_lock();
    try lock.put_pin("zbx.build.zon", "fetch", Digest.of("key"), Digest.of("out"));
    const step = &file.steps_slice()[0];
    const found = pin.lock_pin(lock, "zbx.build.zon", file, step).?;
    const key = Digest.of("key");
    const other = Digest.of("other key");
    const expected = pin.Judged{ .want = .{ .expect = Digest.of("out") } };
    try testing.expectEqual(expected, pin.judge(step, null, found, key, .plain));
    try testing.expectEqual(expected, pin.judge(step, null, found, key, .locked));
    const written = pin.judge(step, Digest.of("written"), found, other, .locked);
    const stale = pin.Judged{ .stale = key };
    const unpinned = pin.Judged{ .want = .none };
    try testing.expectEqual(pin.Judged{ .want = .{ .expect = Digest.of("written") } }, written);
    try testing.expectEqual(stale, pin.judge(step, null, found, other, .locked));
    try testing.expectEqual(
        pin.Judged{ .stale = key },
        pin.judge(step, null, found, other, .hermetic),
    );
    try testing.expectEqual(unpinned, pin.judge(step, null, found, other, .plain));
    try testing.expectEqual(
        pin.Judged{ .want = .pinning },
        pin.judge(step, null, found, other, .pin),
    );
    try testing.expectEqual(pin.Judged{ .want = .none }, pin.judge(step, null, null, key, .locked));
    try testing.expectEqual(pin.Judged{ .want = .pinning }, pin.judge(step, null, null, key, .pin));
    const offline = &file.steps_slice()[2];
    try testing.expectEqual(pin.Judged{ .want = .none }, pin.judge(offline, null, null, key, .pin));
}

test "--hermetic refuses the first cache mount or unpinned network step, and nothing else" {
    // Goal: E0814's subject. Method: the three steps refuse at `fetch`; with `fetch` pinned
    // they refuse at `cached`; a file with only a pinned network step and an offline step
    // passes.
    const file = try parsed(three);
    const lock = empty_lock();
    const unpinned = pin.hermetic_refusal(lock, "zbx.build.zon", file).?;
    try testing.expectEqual(@as(u8, 0), unpinned.index);
    try testing.expect(!unpinned.cache);
    try lock.put_pin("zbx.build.zon", "fetch", Digest.of("key"), Digest.of("out"));
    const cached = pin.hermetic_refusal(lock, "zbx.build.zon", file).?;
    try testing.expectEqual(@as(u8, 1), cached.index);
    try testing.expect(cached.cache);
    const pinned = try parsed(
        \\.{ .version = 1, .image = .{}, .steps = .{
        \\  .{ .name = "fetch", .base = "x", .run = .{ "true" }, .network = true },
        \\  .{ .name = "offline", .base = "x", .run = .{ "true" } },
        \\} }
    );
    try testing.expect(pin.hermetic_refusal(lock, "zbx.build.zon", pinned) == null);
}
