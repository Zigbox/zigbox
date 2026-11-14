//! Step 8 of the M9 demo (docs/briefs/M9-dockerfile-import.md, "Pin, then drift"), on
//! `m9_drift/`: a network step `fetch` whose output is a fresh uuid each run, and `use`, which
//! needs it. In the first VM (`step_pin`): `--pin` writes one pin and a version 2 lock, and
//! `--locked` is all hits with the lock unchanged. In the second VM, a fresh store
//! (`step_drift`): `--locked` is E0822 naming both digests, `use` never runs and the lock is
//! unchanged; without `--locked` the build passes with W0803 naming the same digests, and `use`
//! misses. The uuid stands in for a changed download (recorded in docs/demos/m9.md).
//!
//! Every assertion is a function of checks_pins_m9.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const checks = @import("checks_pins_m9.zig");
const m7 = @import("checks_m7.zig");
const m9 = @import("checks_m9.zig");
const common = @import("common_m4.zig");
const harness = @import("harness.zig");
const hello = @import("hello_m9.zig");
const hello_m7 = @import("hello_m7.zig");
const session_mod = @import("session.zig");
const state = @import("state_m6.zig");

const Session = session_mod.Session;
const H = harness;
const fail_step = common.fail_step;

const drift_dir = "/home/demo/drift";
const zd = H.as_demo ++ "/home/demo/zd";
const lock_path = drift_dir ++ "/zbx.lock";
const build_file = @embedFile("m9_drift/drift.build.zon");
const first_lock = @embedFile("m9_drift/zbx.lock");
const step8 = "HELLO9 8";

const pin_build = zd ++ " build -f drift.build.zon --pin";
const locked_build = zd ++ " build -f drift.build.zon --locked";
const plain_build = zd ++ " build -f drift.build.zon";

/// The lock `--pin` wrote in the first VM, for the second. A fixed buffer.
var pinned_storage: [2048]u8 = undefined;
var pinned_length: usize = 0;

fn install(session: *Session, out: *Io.Writer, lock: []const u8) !void {
    const made = "rm -rf " ++ drift_dir ++ " && mkdir -p " ++ drift_dir ++ " && chown demo:demo " ++
        drift_dir;
    _ = try common.expect_exit(session, out, step8, made, 0);
    try hello_m7.put_text(session, drift_dir ++ "/drift.build.zon", build_file);
    try hello_m7.put_text(session, lock_path, lock);
    try hello_m7.make_wrapper(session, drift_dir, "/home/demo/zd");
}

fn expect_lock(session: *Session, out: *Io.Writer, want: []const u8) !void {
    const lock = try hello.read_file(session, out, step8, lock_path);
    m9.check_same_bytes(lock, want) catch |err| {
        return fail_step(out, step8, "expected zbx.lock byte for byte unchanged", err);
    };
}

pub fn step_pin(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: --pin records the network step's output\n", .{
        H.demo_name, step8,
    });
    try install(session, out, first_lock);
    _ = try state.expect_long_split(session, out, pin_build, 0, hello.build_timeout_s);
    const lock = try hello.read_file(session, out, step8, lock_path);
    checks.check_pinned_lock(lock) catch |err| {
        return fail_step(out, step8, "expected a version 2 lock with one pin, for fetch", err);
    };
    if (lock.len > pinned_storage.len) {
        return fail_step(out, step8, "expected a lock that fits 2048 bytes", error.PinWrong);
    }
    @memcpy(pinned_storage[0..lock.len], lock);
    pinned_length = lock.len;
    const pinned = pinned_storage[0..pinned_length];
    const again = try state.expect_long_split(session, out, locked_build, 0, hello.short_s);
    const report = m7.parse_text(again.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the text build report", err);
    };
    if (report.misses != 0 or report.hits != 3) {
        return fail_step(out, step8, "expected --locked to hit every step", error.CacheWrong);
    }
    try expect_lock(session, out, pinned);
    try timer.lap(out, "pin9");
}

/// In the second VM: a store that never ran `fetch`, so its output is another uuid.
pub fn step_drift(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: a fresh store drifts: E0822 under --locked, else W0803\n", .{
        H.demo_name, step8,
    });
    if (pinned_length == 0) {
        return fail_step(out, step8, "no lock from the first VM", error.PinWrong);
    }
    const pinned = pinned_storage[0..pinned_length];
    try install(session, out, pinned);
    const refused = try common.run_shown(session, out, locked_build);
    const drift = checks.check_drift_refused(
        refused.streams.stdout,
        refused.streams.stderr,
        refused.status,
    ) catch |err| {
        return fail_step(out, step8, "expected E0822 naming fetch and both digests", err);
    };
    try expect_lock(session, out, pinned);
    const warned = try state.expect_long_split(session, out, plain_build, 0, hello.short_s);
    const report = m7.parse_text(warned.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the text build report", err);
    };
    checks.check_drift_warned(&report, warned.streams.stderr, warned.status, &drift) catch |err| {
        return fail_step(out, step8, "expected W0803 naming the same digests, use a miss", err);
    };
    try expect_lock(session, out, pinned);
    try timer.lap(out, "drift9");
}

test {
    // Goal: the files this part puts in the guest fit what the guest accepts, and the build
    // file is the brief's. Method: sizes against `put_file`'s limit, and the fields it needs.
    try std.testing.expect(build_file.len <= 1536);
    try std.testing.expect(first_lock.len <= 1536);
    try std.testing.expect(std.mem.indexOf(u8, build_file, ".network = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, build_file, "random/uuid > /out/id") != null);
    try std.testing.expect(std.mem.indexOf(u8, first_lock, ".version = 1,") != null);
}
