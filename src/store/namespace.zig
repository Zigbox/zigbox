//! The child that does the store's work. Every operation on the store (import, listing,
//! verifying, collecting, materializing) runs in a single-threaded child inside the user's
//! user namespace, mapped the way `zbx run --rootfs` maps it: with the full range of subordinate
//! ids when this host has the ranges and the helpers, the user as root and the range as ids 1
//! and up; otherwise (ZBX-W0201) only the user, as root. So `chown` of an object to a
//! container id works, a file readable only by a subordinate id can be read, and every id the
//! store records is the one a container sees.
//!
//! The parent here only waits. It makes the child with `clone3` (new user namespace only), writes
//! the id maps (itself for the one-id map, through `newuidmap` and `newgidmap` for the full one),
//! lets the child go with one byte, and reaps it. The child's exit code is the command's: it
//! writes its own result to stdout and its own diagnostics to stderr, since it inherited both,
//! and the parent passes the code on. A child that is killed, or that cannot be set up, is
//! ZBX-E0419 in the parent.
//!
//! Single-threaded, as docs/SPEC.md requires of everything that makes a namespace: the caller is
//! a program with one thread, or a thread that is the only one using this process's host.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const ids = @import("../runtime/ids.zig");
const plan_mod = @import("../runtime/plan.zig");
const diagnose = @import("diagnose.zig");

const Host = host_mod.Host;

pub const Error = error{Failed};

/// What the child does once its namespace is set up. `call` returns the child's exit code.
pub const Work = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, squash_owner: bool) u8,
};

/// Tells the caller of `run` about a warning (the one-id map).
pub const Warn = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, diag: *const Diag) void,
};

const go_ahead: u8 = 1;
const setup_failed: u8 = constants.child_exit_setup_failed;

const ChildContext = struct {
    host: Host,
    ready: host_mod.Pipe,
    work: Work,
    squash_owner: bool,
};

/// The body of the child: wait for the id maps, then do the work.
fn child_entry(context: *anyopaque) u8 {
    const child: *const ChildContext = @ptrCast(@alignCast(context));
    const host = child.host;
    host.close(child.ready.write);
    // If the parent dies the child must not go on writing to the store alone.
    host.die_with_parent() catch return setup_failed;
    var byte: [1]u8 = undefined;
    const count = host.read_some(child.ready.read, &byte) catch return setup_failed;
    host.close(child.ready.read);
    if (count == 0) return setup_failed; // The parent gave up.
    assert(byte[0] == go_ahead);
    const code = child.work.call(child.work.context, child.squash_owner);
    assert(code != setup_failed); // A command's own code never collides with the setup's.
    return code;
}

/// Runs `work` in the namespace and returns its exit code, or fails with E0419 in `diag`.
pub fn run(
    host: Host,
    facts: *doctor.Facts,
    work: Work,
    warn: ?Warn,
    diag: *Diag,
) Error!u8 {
    assert(@intFromPtr(work.context) != 0);
    assert(diag.code == null);
    var choice: ids.Choice = undefined;
    ids.choose(host, facts, &choice);
    if (choice.warned) {
        if (warn) |sink| sink.call(sink.context, &choice.warning);
    }
    const ready = host.pipe() catch |err| return setup_error(host, diag, "pipe", err);
    var child: ChildContext = .{
        .host = host,
        .ready = ready,
        .work = work,
        .squash_owner = choice.mapping == .single,
    };
    const flags: host_mod.SpawnFlags = .{
        .user = true,
        .mount = false,
        .pid = false,
        .uts = false,
        .ipc = false,
        .net = false,
    };
    const pid = host.spawn(flags, child_entry, &child) catch |err| {
        host.close(ready.read);
        host.close(ready.write);
        return setup_error(host, diag, "clone3(CLONE_NEWUSER)", err);
    };
    // The child has its own copy of the read end; ours closed, end of file reaches it if we die.
    host.close(ready.read);
    host.ignore_broken_pipe(true);
    defer host.ignore_broken_pipe(false);
    release(host, pid, ready.write, choice.mapping, diag) catch {
        abandon(host, pid, ready.write);
        return error.Failed;
    };
    const status = host.wait_for(pid) catch |err| return setup_error(host, diag, "wait", err);
    switch (status) {
        .exited => |code| {
            if (code == setup_failed) {
                diagnose.worker_ended(diag, .{ .step = .{
                    .name = "setting up the store worker",
                    .err = error.IoFailed,
                    .errno = 0,
                } });
                return error.Failed;
            }
            return code;
        },
        .signaled => |number| {
            diagnose.worker_ended(diag, .{ .signaled = number });
            return error.Failed;
        },
    }
}

fn setup_error(host: Host, diag: *Diag, name: []const u8, err: host_mod.Error) Error {
    assert(name.len > 0);
    assert(diag.code == null);
    diagnose.worker_ended(diag, .{ .step = .{
        .name = name,
        .err = err,
        .errno = host.last_errno(),
    } });
    return error.Failed;
}

/// Writes the id maps and lets the child go. A failure is already in `diag`.
fn release(
    host: Host,
    pid: host_mod.Pid,
    ready_write: host_mod.Handle,
    mapping: plan_mod.Mapping,
    diag: *Diag,
) Error!void {
    assert(pid > 0);
    assert(diag.code == null);
    const uid = host.uid();
    const gid = host.gid();
    switch (mapping) {
        .single => try write_single(host, pid, uid, gid, diag),
        .full => |helpers| try write_full(host, pid, uid, gid, helpers, diag),
    }
    const byte = [1]u8{go_ahead};
    host.write_handle_all(ready_write, &byte) catch |err| {
        return setup_error(host, diag, "releasing the store worker", err);
    };
    host.close(ready_write);
}

/// The one-id map: setgroups denied (an unprivileged writer may not map groups otherwise), then
/// the group and user map, each written whole by the parent.
fn write_single(host: Host, pid: host_mod.Pid, uid: u32, gid: u32, diag: *Diag) Error!void {
    assert(pid > 0);
    assert(diag.code == null);
    var line: [constants.id_map_line_bytes_max]u8 = undefined;
    host.write_id_map(pid, .setgroups, "deny") catch |err| {
        return setup_error(host, diag, "writing setgroups", err);
    };
    // Cannot fail: "0 4294967295 1\n" is 15 bytes and the buffer is 32.
    const gid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{gid}) catch unreachable; // Same bound.
    host.write_id_map(pid, .gid_map, gid_line) catch |err| {
        return setup_error(host, diag, "writing gid_map", err);
    };
    const uid_line = std.fmt.bufPrint(&line, "0 {d} 1\n", .{uid}) catch unreachable; // Same bound.
    host.write_id_map(pid, .uid_map, uid_line) catch |err| {
        return setup_error(host, diag, "writing uid_map", err);
    };
}

fn write_full(
    host: Host,
    pid: host_mod.Pid,
    uid: u32,
    gid: u32,
    helpers: plan_mod.Helpers,
    diag: *Diag,
) Error!void {
    assert(pid > 0);
    assert(helpers.newuidmap.len > 0);
    var words: [constants.helper_map_bytes_max]u8 = undefined;
    const range = constants.subid_range_min;
    // Cannot fail: six numbers of at most ten digits and the spaces fit 64 bytes.
    const uid_words = std.fmt.bufPrint(&words, "0 {d} 1 1 {d} {d}", .{
        uid, helpers.uid_start, range,
    }) catch unreachable; // Same bound.
    try run_helper(host, helpers.newuidmap, pid, uid_words, diag);
    const gid_words = std.fmt.bufPrint(&words, "0 {d} 1 1 {d} {d}", .{
        gid, helpers.gid_start, range,
    }) catch unreachable; // Same bound.
    try run_helper(host, helpers.newgidmap, pid, gid_words, diag);
}

/// Runs `newuidmap` or `newgidmap`: its name, the child's pid and the map's words.
fn run_helper(
    host: Host,
    path: []const u8,
    pid: host_mod.Pid,
    words_text: []const u8,
    diag: *Diag,
) Error!void {
    assert(path.len > 0);
    assert(words_text.len > 0);
    var path_storage: [constants.state_path_bytes_max]u8 = undefined;
    if (path.len >= path_storage.len) return setup_error(host, diag, path, error.PathTooLong);
    @memcpy(path_storage[0..path.len], path);
    path_storage[path.len] = 0;
    const path_z: [:0]const u8 = path_storage[0..path.len :0];
    var storage: [constants.helper_map_bytes_max + 16]u8 = undefined;
    var argv: [constants.helper_words_max]?[*:0]const u8 = undefined;
    const base = std.fs.path.basename(path);
    argv[0] = @ptrCast(path_z.ptr + (path.len - base.len));
    // Cannot fail: a pid has at most ten digits and the storage holds 16 bytes more.
    const pid_text = std.fmt.bufPrint(&storage, "{d}", .{pid}) catch unreachable; // Same bound.
    storage[pid_text.len] = 0;
    argv[1] = @ptrCast(&storage[0]);
    var used: usize = pid_text.len + 1;
    var count: usize = 2;
    var words = std.mem.splitScalar(u8, words_text, ' ');
    while (words.next()) |word| {
        assert(word.len > 0);
        assert(count + 1 < argv.len);
        @memcpy(storage[used..][0..word.len], word);
        storage[used + word.len] = 0;
        argv[count] = @ptrCast(&storage[used]);
        count += 1;
        used += word.len + 1;
    }
    argv[count] = null;
    const none = [_:null]?[*:0]const u8{};
    var output: [constants.helper_output_bytes_max]u8 = undefined;
    const result = host.run_helper(.{
        .path = path_z,
        .argv = @ptrCast(&argv),
        .envp = &none,
    }, &output) catch |err| return setup_error(host, diag, path, err);
    switch (result.status) {
        .exited => |code| if (code == 0) return,
        .signaled => {},
    }
    diagnose.worker_ended(diag, .{ .helper = .{
        .name = base,
        .status = result.status,
        .output = output[0..result.output_len],
    } });
    return error.Failed;
}

/// A step failed after the child was made: it is killed and reaped, and the pipe closed.
fn abandon(host: Host, pid: host_mod.Pid, ready_write: host_mod.Handle) void {
    assert(pid > 0);
    assert(pid != host.own_pid());
    host.signal(pid, constants.signal_kill) catch {}; // It may be gone already.
    _ = host.wait_for(pid) catch {}; // Nothing more can be done about a wait that fails.
    host.close(ready_write);
}

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const sim_run = @import("../runtime/sim_run.zig");

var test_facts: doctor.Facts = undefined;

/// A piece of work that records how it was called and returns the code it was given.
const Probe = struct {
    code: u8,
    calls: u32 = 0,
    squash: bool = false,

    fn call(context: *anyopaque, squash_owner: bool) u8 {
        const probe: *Probe = @ptrCast(@alignCast(context));
        probe.calls += 1;
        probe.squash = squash_owner;
        return probe.code;
    }

    fn work(probe: *Probe) Work {
        return .{ .context = probe, .call = call };
    }
};

test "the work runs once, after the maps, and its exit code is the result" {
    // Goal: the child's contract on a host that maps a full range. Method: a probe that returns
    // 7; the simulator's rules (setgroups before gid_map, one write of each map) are enforced by
    // the helpers' model, so a run that gets this far wrote them in order.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    var probe: Probe = .{ .code = 7 };
    var diag: Diag = undefined;
    diag.reset();
    const code = try run(sim.interface(), &test_facts, probe.work(), null, &diag);
    try testing.expectEqual(@as(u8, 7), code);
    try testing.expectEqual(@as(u32, 1), probe.calls);
    try testing.expect(!probe.squash);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a host that can map one id only tells the work to record every owner as 0, and warns" {
    // Goal: W0201 reaches the caller and the work learns the map. Method: the single-id host.
    var sim: HostSim = undefined;
    sim_run.init_single(&sim, 1);
    var probe: Probe = .{ .code = 0 };
    var warned: u32 = 0;
    const Sink = struct {
        fn call(context: *anyopaque, warning: *const Diag) void {
            const count: *u32 = @ptrCast(@alignCast(context));
            count.* += 1;
            std.debug.assert(warning.code.? == .W0201);
        }
    };
    var diag: Diag = undefined;
    diag.reset();
    const sink: Warn = .{ .context = &warned, .call = Sink.call };
    const code = try run(sim.interface(), &test_facts, probe.work(), sink, &diag);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(probe.squash);
    try testing.expectEqual(@as(u32, 1), warned);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a helper that refuses the map is E0419, the child is reaped, and nothing runs" {
    // Goal: a failed setup never runs the work and leaks nothing. Method: newuidmap exits 1.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    sim.world.helper_fails_with = 1;
    var probe: Probe = .{ .code = 0 };
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(
        error.Failed,
        run(sim.interface(), &test_facts, probe.work(), null, &diag),
    );
    try testing.expectEqual(@as(?@import("../diag/codes.zig").Code, .E0419), diag.code);
    try testing.expectEqual(@as(u32, 0), probe.calls);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    try testing.expectEqual(@as(u32, 0), sim.world.unreaped_children());
}
