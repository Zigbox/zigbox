//! Output pins (M9 slice 3c, docs/briefs/M9-dockerfile-import.md "Output pins"): which steps
//! are pinned, what their output is checked against, and the output excludes their key holds.
//!
//! A pin is the output digest a network step is expected to produce: `.expect` in the build
//! file, or a pin in `zbx.lock` found by the build file's path (as the lock's directory shows
//! it) and the step's name. A lock pin is current when its key is the step's key, computed with
//! the output excludes applied; a pin of another key is stale. A step with `.caches` is never
//! pinned: its output depends on a cache that is outside its key.
//!
//! Pure: no host, store or I/O. `compose.zig` asks, and acts on the answers.

const std = @import("std");
const assert = std.debug.assert;

const constants = @import("../constants.zig");
const file_mod = @import("file.zig");
const lock_file = @import("../lock_file.zig");
const Digest = @import("../store/digest.zig").Digest;

/// What `zbx build` does with pins: `--pin`, `--locked`, `--hermetic`, or none of them.
pub const Mode = enum {
    plain,
    pin,
    locked,
    hermetic,

    /// Drift and stale pins fail the build (E0822) rather than warn.
    pub fn enforces(mode: Mode) bool {
        return mode == .locked or mode == .hermetic;
    }
};

/// What a pinned step without `.output_exclude` leaves out of its output: what changes from
/// run to run without being what the step made (logs, caches, package indexes, scratch).
/// Package databases are content and are not here.
pub const default_excludes = [_][]const u8{
    "/var/log",
    "/var/cache",
    "/var/lib/apt/lists",
    "/tmp",
};

comptime {
    assert(default_excludes.len <= constants.build_output_excludes_max);
}

/// What a step's output is checked against once it is known.
pub const Want = union(enum) {
    /// Not pinned: any output is used.
    none,
    /// `.expect`, or a current lock pin: the output must be this digest.
    expect: Digest,
    /// `--pin` records the output, with the step's key, once the build succeeds.
    pinning,
};

/// The lock's pin for the step, if the step can be pinned at all (network, no caches).
pub fn lock_pin(
    lock: *const lock_file.Lock,
    file_name: []const u8,
    file: *const file_mod.BuildFile,
    step: *const file_mod.Step,
) ?*const lock_file.Pin {
    assert(file_name.len > 0);
    assert(step.name.len > 0);
    if (!pinnable(step)) return null;
    return lock.find_pin(file_name, file.text(step.name));
}

/// Whether the step's key holds output excludes: a written `.output_exclude`, or a step that
/// is pinned (or may be: a lock pin, current or stale, keeps the defaults in the key, so the
/// defaults never make a pin look stale).
pub fn keyed(step: *const file_mod.Step, has_lock_pin: bool, mode: Mode) bool {
    if (has_lock_pin) assert(pinnable(step));
    if (step.output_exclude.given) return true;
    if (!pinnable(step)) return false;
    return step.expect != null or has_lock_pin or mode == .pin;
}

/// The step's output excludes for its key and its output: the written list, or the defaults,
/// or null when `keyed` says none. The texts live in `file`; `paths` holds the slice.
pub fn excludes(
    file: *const file_mod.BuildFile,
    step: *const file_mod.Step,
    is_keyed: bool,
    paths: *[constants.build_output_excludes_max][]const u8,
) ?[]const []const u8 {
    if (!is_keyed) return null;
    if (!step.output_exclude.given) return &default_excludes;
    const texts = file.texts(step.output_exclude);
    assert(texts.len <= paths.len);
    for (texts, 0..) |text, at| paths[at] = file.text(text);
    return paths[0..texts.len];
}

/// What judging a step's pin found, once its key is known.
pub const Judged = union(enum) {
    want: Want,
    /// A lock pin recorded for another key (the step changed): E0822 when `mode` enforces.
    stale: Digest,
};

/// The step's pin, given its key: `.expect` wins; a lock pin of this key is current; a stale
/// pin is refused when the mode enforces pins, and otherwise left alone (re-pinned by `--pin`).
pub fn judge(
    step: *const file_mod.Step,
    expect: ?Digest,
    pin: ?*const lock_file.Pin,
    key: Digest,
    mode: Mode,
) Judged {
    if (expect != null) assert(step.network);
    if (pin != null) assert(pinnable(step));
    if (expect) |digest| return .{ .want = .{ .expect = digest } };
    if (pin) |found| {
        if (found.key.eql(key)) return .{ .want = .{ .expect = found.output } };
        if (mode.enforces()) return .{ .stale = found.key };
    }
    if (mode == .pin and pinnable(step)) return .{ .want = .pinning };
    return .{ .want = .none };
}

/// The step `--hermetic` refuses before anything runs (E0814): the first with a cache mount,
/// or with the network and no pin at all (`.expect` or a lock pin; a stale one is E0822 when
/// the step's key is known). Null: none.
pub fn hermetic_refusal(
    lock: *const lock_file.Lock,
    file_name: []const u8,
    file: *const file_mod.BuildFile,
) ?struct { index: u8, cache: bool } {
    assert(file.steps_count <= constants.build_steps_max);
    assert(file_name.len > 0);
    for (file.steps_slice(), 0..) |*step, index| {
        if (step.caches.count > 0) return .{ .index = @intCast(index), .cache = true };
        if (!step.network or step.expect != null) continue;
        if (lock_pin(lock, file_name, file, step) == null) {
            return .{ .index = @intCast(index), .cache = false };
        }
    }
    return null;
}

/// A network step without caches: the only kind `--pin` pins and a lock pin applies to.
pub fn pinnable(step: *const file_mod.Step) bool {
    return step.network and step.caches.count == 0;
}
