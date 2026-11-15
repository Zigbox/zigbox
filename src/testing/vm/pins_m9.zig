//! Step 8 of the M9 demo (docs/briefs/M9-dockerfile-import.md, "Pin, then drift"), on
//! `m9_drift/`: a network step `fetch` whose output is a fresh uuid each run, and `use`, which
//! needs it. In the first VM (`step_pin`): `--pin` writes one pin and a version 2 lock, and
//! `--locked` is all hits with the lock unchanged. In the second VM, a fresh store
//! (`step_drift`): `--locked` is E0822 naming both digests, `use` never runs and the lock is
//! unchanged; without `--locked` the build passes with W0803 naming the same pin, and `use`
//! misses. The refused output is not cached, so that build runs `fetch` again: a new uuid.
//!
//! Every assertion is a function of checks_pins_m9.zig with a unit test.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
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
const steady_path = drift_dir ++ "/steady.build.zon";
const build_file = @embedFile("m9_drift/drift.build.zon");
const first_lock = @embedFile("m9_drift/zbx.lock");
const step8 = "HELLO9 8";

const pin_build = zd ++ " build -f drift.build.zon --pin";
const locked_build = zd ++ " build -f drift.build.zon --locked";
const plain_build = zd ++ " build -f drift.build.zon";
const locked_json = zd ++ " build -f drift.build.zon --locked --output json";
const both_build = zd ++ " build -f drift.build.zon --pin --locked";
const steady_pin = zd ++ " build -f steady.build.zon --pin";
const steady_locked = zd ++ " build -f steady.build.zon --locked --output json";
const hello_locked = hello.zh ++ " build --locked";

/// The lock `--pin` wrote in the first VM, for the second. A fixed buffer.
var pinned_storage: [2048]u8 = undefined;
var pinned_length: usize = 0;
/// `steady` as the first VM built it, for the second.
var first_steady: ?checks.Steady = null;

/// `steady` writes a constant, and the date under /var/log, which a pinned step's output
/// leaves out; `after` needs it. With `expect`, `steady` is held to that digest.
fn steady_file(buffer: []u8, expect: []const u8) []const u8 {
    if (expect.len > 0) assert(expect.len == "b3:".len + 64);
    const expect_line_head = "            .expect = \"";
    var line_buffer: [expect_line_head.len + 72]u8 = undefined;
    const line = if (expect.len == 0) "" else std.fmt.bufPrint(
        &line_buffer,
        expect_line_head ++ "{s}\",\n",
        .{expect},
    ) catch unreachable; // The buffer holds the head, a digest and the tail.
    const head =
        \\.{
        \\    .version = 1,
        \\    .steps = .{
        \\        .{
        \\            .name = "steady",
        \\            .base = "alpine:3.20",
        \\            .network = true,
        \\
    ;
    const tail =
        \\            .run = .{
        \\                "/bin/sh",
        \\                "-c",
        \\                "echo 1 >/out/c && mkdir -p /out/var/log && date >/out/var/log/when",
        \\            },
        \\        },
        \\        .{
        \\            .name = "after",
        \\            .base = "alpine:3.20",
        \\            .needs = .{"steady"},
        \\            .run = .{ "/bin/sh", "-c", "cp /in/steady/c /out/c" },
        \\        },
        \\    },
        \\    .image = .{
        \\        .base = "alpine:3.20",
        \\        .add = .{
        \\            .{ .from = "after", .to = "/srv" },
        \\        },
        \\    },
        \\}
        \\
    ;
    return std.fmt.bufPrint(buffer, "{s}{s}{s}", .{ head, line, tail }) catch {
        unreachable; // The caller's buffer holds the file with the longest expect line.
    };
}

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
    const pin = checks.check_pinned_lock(lock) catch |err| {
        return fail_step(out, step8, "expected a version 2 lock with one pin, for fetch", err);
    };
    if (lock.len > pinned_storage.len) {
        return fail_step(out, step8, "expected a lock that fits 2048 bytes", error.PinWrong);
    }
    @memcpy(pinned_storage[0..lock.len], lock);
    pinned_length = lock.len;
    const pinned = pinned_storage[0..pinned_length];
    const again = try state.expect_long_split(session, out, locked_json, 0, hello.short_s);
    const report = m7.parse_json(session.scratch_allocator(), again.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the JSON build report", err);
    };
    if (report.misses != 0 or report.hits < 2) {
        return fail_step(out, step8, "expected --locked to hit every step", error.CacheWrong);
    }
    checks.check_pin_committed(&report, "fetch", &pin) catch |err| {
        return fail_step(out, step8, "expected the pin to be fetch's key and output", err);
    };
    try expect_lock(session, out, pinned);
    const both = try common.run_shown(session, out, both_build);
    const named = [_][]const u8{"--pin and --locked"};
    m9.check_refused(both.streams.stderr, both.status, "ZBX-E0005", &named) catch |err| {
        return fail_step(out, step8, "expected --pin --locked to be E0005", err);
    };
    try expect_lock(session, out, pinned);
    try timer.lap(out, "pin9");
    try steady_first(session, out, timer);
}

/// `steady` pinned in the first VM: its pin, then `--locked` all hits with that output.
fn steady_first(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    var buffer: [1536]u8 = undefined;
    try hello_m7.put_text(session, steady_path, steady_file(&buffer, ""));
    _ = try state.expect_long_split(session, out, steady_pin, 0, hello.build_timeout_s);
    // The lock's text lives in the session's scratch, which the next command reuses: take
    // the pin out of it first.
    const lock = try hello.read_file(session, out, step8, lock_path);
    const pin = checks.pin_of(lock, "steady") orelse {
        return fail_step(out, step8, "expected the lock to pin steady", error.PinWrong);
    };
    const again = try state.expect_long_split(session, out, steady_locked, 0, hello.short_s);
    const report = m7.parse_json(session.scratch_allocator(), again.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the JSON build report", err);
    };
    first_steady = checks.steady_of(&report, &pin) catch |err| {
        return fail_step(out, step8, "expected steady pinned, then hit with its pin", err);
    };
    try timer.lap(out, "steady9");
}

/// `steady` with `.expect` set to the first VM's pin: the same output in this store, minutes
/// later, and `after` with the same key; the lock, which has no pin for it, is unchanged.
fn steady_second(session: *Session, out: *Io.Writer, pinned: []const u8) !void {
    const first = first_steady orelse {
        return fail_step(out, step8, "no steady from the first VM", error.PinWrong);
    };
    var buffer: [1536]u8 = undefined;
    try hello_m7.put_text(session, steady_path, steady_file(&buffer, &first.output));
    const done = try state.expect_long_split(session, out, steady_locked, 0, hello.build_timeout_s);
    const report = m7.parse_json(session.scratch_allocator(), done.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the JSON build report", err);
    };
    checks.check_steady_same(&report, done.streams.stderr, done.status, &first) catch |err| {
        return fail_step(out, step8, "expected steady's .expect output, after's key", err);
    };
    try expect_lock(session, out, pinned);
}

/// `--locked` in ~/hello (after HELLO's step 5): all hits, and its lock, which has no pins,
/// byte for byte the version 1 lock it was.
pub fn step_hello_locked(session: *Session, out: *Io.Writer, timer: *H.Timer) !void {
    try out.print("\n{s}: {s}: --locked in ~/hello is all hits, its lock unchanged\n", .{
        H.demo_name, step8,
    });
    const done = try state.expect_long_split(session, out, hello_locked, 0, hello.short_s);
    const report = m7.parse_text(done.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the text build report", err);
    };
    if (report.misses != 0 or report.hits == 0) {
        return fail_step(out, step8, "expected --locked to hit every step", error.CacheWrong);
    }
    const lock = try hello.read_file(session, out, step8, hello.project_dir ++ "/zbx.lock");
    m9.check_same_bytes(lock, hello.lock_text) catch |err| {
        return fail_step(out, step8, "expected ~/hello's zbx.lock byte for byte unchanged", err);
    };
    try timer.lap(out, "hello9l");
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
    const pin = checks.pin_of(pinned, "fetch") orelse {
        return fail_step(out, step8, "no pin for fetch in the first VM's lock", error.PinWrong);
    };
    const drift = checks.check_drift_refused(
        refused.streams.stdout,
        refused.streams.stderr,
        refused.status,
        &pin,
    ) catch |err| {
        return fail_step(out, step8, "expected E0822 naming fetch and both digests", err);
    };
    try expect_lock(session, out, pinned);
    const warned = try state.expect_long_split(session, out, plain_build, 0, hello.short_s);
    const report = m7.parse_text(warned.streams.stdout) catch |err| {
        return fail_step(out, step8, "expected the text build report", err);
    };
    checks.check_drift_warned(&report, warned.streams.stderr, warned.status, &drift) catch |err| {
        return fail_step(out, step8, "expected W0803 naming the same pin, use a miss", err);
    };
    try expect_lock(session, out, pinned);
    try steady_second(session, out, pinned);
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
    var buffer: [1536]u8 = undefined;
    const plain = steady_file(&buffer, "");
    try std.testing.expect(std.mem.indexOf(u8, plain, ".expect") == null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "/out/var/log/when") != null);
    const digest = "b3:" ++ @as([64]u8, @splat('5'));
    const held = steady_file(&buffer, digest);
    try std.testing.expect(std.mem.indexOf(u8, held, ".expect = \"" ++ digest ++ "\",\n") != null);
}
