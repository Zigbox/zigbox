//! The exec fuzzer: `zig build fuzz -- exec`. Two parts each iteration.
//!
//! The history (`runtime/exec_history.zig`): a random history (commands of random bytes, exits
//! of every kind, times at the bounds) renders and parses back equal; then its text is damaged
//! (flipped bytes, a cut, a line dropped or doubled, garbage) and parsed: a damaged text that is
//! accepted is one `render` could have written, so rendering what was read gives the same text
//! back, and it never holds more entries than the bound.
//!
//! The exec itself: a running container in the simulator, then an exec of random shape (a
//! terminal or not, a user or not, `--workdir` or not, the cgroupfs driver or the bus) with a
//! random step failed by a random errno, or none. It starts and is waited for, with the
//! command's exit, or it fails with one registered code; either way nothing of it is left: its
//! children are reaped, its namespace files closed, zbx's terminal put back, and the container
//! still runs.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const codes = @import("diag/codes.zig");
const exec = @import("runtime/exec.zig");
const exec_history = @import("runtime/exec_history.zig");
const exec_plan = @import("runtime/exec_plan.zig");
const host_sim = @import("host_sim.zig");
const run = @import("runtime/run.zig");
const sim_run = @import("runtime/sim_run.zig");
const Diag = @import("diag/diag.zig").Diag;

const HostSim = host_sim.HostSim;

var sim: HostSim = undefined;
var container: run.Handle = undefined;
var handle: exec.Handle = undefined;
var history: exec_history.History = undefined;
var parsed: exec_history.History = undefined;
var text_buffer: [exec_history.file_bytes_max]u8 = undefined;
var again_buffer: [exec_history.file_bytes_max]u8 = undefined;
var damaged: [exec_history.file_bytes_max + 64]u8 = undefined;

pub fn fuzz_exec(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    fuzz_history(random);
    fuzz_start(random, seed);
}

fn random_entry(random: std.Random, entry: *exec_history.Entry) void {
    const time_max: u64 = (1 << 40) - 1;
    entry.started = if (random.boolean()) time_max else random.uintAtMost(u64, time_max);
    entry.ended = entry.started + random.uintAtMost(u64, time_max - entry.started);
    entry.exit = switch (random.uintLessThan(u8, 3)) {
        0 => .{ .exited = random.int(u8) },
        1 => .{ .signaled = random.intRangeAtMost(u8, 1, constants.signal_number_max - 1) },
        else => .lost,
    };
    var storage: [8][64]u8 = undefined;
    var words: [8][]const u8 = undefined;
    const count = random.intRangeAtMost(usize, 1, words.len);
    for (0..count) |at| {
        random.bytes(&storage[at]);
        const length = random.uintAtMost(usize, storage[at].len);
        words[at] = storage[at][0..length];
    }
    entry.set_command(words[0..count]);
    assert(entry.command_len > 0);
}

fn fuzz_history(random: std.Random) void {
    history.count = 0;
    const count = random.uintAtMost(u32, constants.exec_history_entries_max + 4);
    for (0..count) |_| {
        var entry: exec_history.Entry = undefined;
        random_entry(random, &entry);
        history.push(&entry);
    }
    assert(history.count <= constants.exec_history_entries_max);
    const text = exec_history.render(&history, &text_buffer);
    exec_history.parse(text, &parsed) catch unreachable; // What render writes is read back.
    assert(parsed.count == history.count);
    for (history.slice(), parsed.slice()) |*want, *got| {
        assert(std.mem.eql(u8, want.command_text(), got.command_text()));
        assert(want.started == got.started);
        assert(want.ended == got.ended);
        assert(std.meta.eql(want.exit, got.exit));
    }
    const broken = damage(random, text);
    exec_history.parse(broken, &parsed) catch return;
    assert(parsed.count <= constants.exec_history_entries_max);
    const again = exec_history.render(&parsed, &again_buffer);
    assert(std.mem.eql(u8, again, broken));
}

/// The text with one kind of damage.
fn damage(random: std.Random, text: []const u8) []const u8 {
    assert(text.len >= exec_history.header.len);
    @memcpy(damaged[0..text.len], text);
    var length = text.len;
    switch (random.uintLessThan(u8, 4)) {
        0 => for (0..random.intRangeAtMost(u32, 1, 4)) |_| {
            damaged[random.uintLessThan(usize, length)] = random.int(u8);
        },
        1 => length = random.uintAtMost(usize, length),
        2 => {
            // A line doubled at the end: an entry past the bound, or one more within it.
            const start = std.mem.lastIndexOfScalar(u8, text[0 .. text.len - 1], '\n') orelse 0;
            const line = text[start + 1 ..];
            const room = damaged.len - length;
            const copied = @min(line.len, room);
            @memcpy(damaged[length..][0..copied], line[0..copied]);
            length += copied;
        },
        else => {
            const at = random.uintAtMost(usize, length);
            const tail = @min(random.uintAtMost(usize, 16), damaged.len - at);
            random.bytes(damaged[at..][0..tail]);
            length = at + tail;
        },
    }
    return damaged[0..length];
}

fn fuzz_start(random: std.Random, seed: u64) void {
    if (random.boolean()) sim_run.init(&sim, seed) else sim_run.init_cgroupfs(&sim, seed);
    sim.world.command_runs_ms = 60_000;
    var diag: Diag = undefined;
    diag.reset();
    const spec: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web",
        .command = &.{"/bin/sh"},
    };
    run.start(sim.interface(), &spec, .{}, &container, &diag) catch unreachable; // The model's
    // host starts a container.
    container.session.release_output();
    const children = sim.world.unreaped_children();
    var exec_spec: exec.Spec = .{ .name = "web", .command = &.{"/bin/sh"} };
    exec_spec.terminal = random.boolean();
    if (exec_spec.terminal) {
        sim.terminal = true;
        sim.terminal_only = .stdout;
        sim.world.input_terminal = true;
        sim.world.input = "typed\r";
    }
    if (random.boolean()) exec_spec.user = "1000:1000";
    if (random.boolean()) exec_spec.workdir = if (random.boolean()) "/bin" else "/nowhere";
    if (random.boolean()) {
        sim.faults.fail_step = random.uintLessThan(u32, exec_plan.steps_max);
        sim.faults.fail_step_errno = random.intRangeAtMost(u16, 1, 133);
    }
    sim.world.command_exit = .{ .exited = random.int(u8) };
    diag.reset();
    if (exec.start(sim.interface(), &exec_spec, .{}, &handle, &diag)) |_| {
        const ending = random.enumValue(Ending);
        if (ending == .container) sim.world.pid1_exit_ms = random.uintAtMost(u32, 120_000);
        end_early(ending, container.pid);
        const before_ms = sim.world.now_ms;
        const exit = exec.wait(&handle);
        if (exit.code() == null) assert(handle.lost_diag.code != null);
        check_ending(ending, exit, before_ms);
    } else |_| {
        const code = diag.code.?;
        assert(codes.entry(code).severity == .@"error");
    }
    assert(sim.world.unreaped_children() == children);
    for (sim.world.namespace_handles) |entry| assert(entry == null);
    assert(!sim.world.input_is_raw);
    assert(container.status == .running);
    container.session.release_keeper();
}

/// How the exec'd command ends: by itself, by a SIGKILL of its own, or with its container, whose
/// PID 1 may take a while to exit (`pid1_exit_ms`).
const Ending = enum { itself, command, container };

fn end_early(ending: Ending, container_pid: u32) void {
    assert(container_pid != 0);
    assert(handle.pid != null);
    switch (ending) {
        .itself => {},
        .command => assert(sim.world.kill(handle.pid.?, constants.signal_kill) == null),
        .container => assert(sim.world.kill(container_pid, constants.signal_kill) == null),
    }
}

/// A command killed with its container says so, and one killed alone does not; neither waits.
fn check_ending(ending: Ending, exit: exec.Exit, before_ms: u64) void {
    if (ending == .itself) return;
    if (exit == .lost) return; // A fault in the reap step: nothing is known of how it ended.
    assert(exit == .signaled);
    assert(exit.signaled == constants.signal_kill);
    assert(handle.container_ended == (ending == .container));
    assert(sim.world.now_ms == before_ms);
}
