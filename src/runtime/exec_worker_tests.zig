//! `zigbox.exec` from a worker that did not start the container (Zigcube's ZB-2): a supervisor
//! starts the container detached and keeps its `run.Handle`; a worker in another process, with
//! only the agent's environment, execs into it with no terminal. The exec finds the container by
//! its record under the state directory and its PID 1 under /proc, never through the supervisor's
//! handle, so the worker needs the same state directory, the same cgroup driver's environment and
//! the same uid, and nothing else. In the simulator the worker is a second `exec.Handle` and a
//! second environment on the same host; the VM (demo-m6b) runs `zbx exec` as a process of its own
//! against a `zbx run -d` container.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const exec = @import("exec.zig");
const exec_history = @import("exec_history.zig");
const host_sim = @import("../host_sim.zig");
const logfile = @import("logfile.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");
const Diag = @import("../diag/diag.zig").Diag;
const SimFs = @import("../store/fs_sim.zig").SimFs;

const HostSim = host_sim.HostSim;
const testing = std.testing;

var disk: SimFs = undefined;
var supervisor_handle: run.Handle = undefined;
var worker_handle: exec.Handle = undefined;

/// The supervisor's environment: the agent's, with variables a worker does not get.
const supervisor_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = sim_run.home_path },
    .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
    .{ .name = "TERM", .value = "xterm-256color" },
    .{ .name = "ZCUBE_ROLE", .value = "supervisor" },
};

/// The worker's environment: the agent's state directory (through HOME) and the user's bus
/// (through XDG_RUNTIME_DIR), and nothing of the supervisor's.
const worker_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = sim_run.home_path },
    .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
};

/// A worker of another user's home: it has no state directory of the agent's.
const stranger_env = [_]host_sim.EnvironmentVariable{
    .{ .name = "HOME", .value = "/home/bob" },
    .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/1000" },
};

/// Starts `web` detached, as Zigcube's supervisor does, then forgets the supervisor's handle and
/// gives the host the worker's environment.
fn supervisor_starts(sim: *HostSim, seed: u64) !u32 {
    sim_run.init(sim, seed);
    disk.init(seed);
    disk.put_dir("/home", 0o755);
    disk.put_dir(sim_run.home_path, 0o755);
    sim.log_fs = &disk;
    sim.world.command_runs_ms = 60_000;
    sim.environment_variables = &supervisor_env;
    var diag: Diag = undefined;
    diag.reset();
    const spec: run.Spec = .{
        .rootfs = sim_run.rootfs_path,
        .name = "web",
        .command = &.{"/bin/sh"},
    };
    try run.start(sim.interface(), &spec, .{ .detached = true }, &supervisor_handle, &diag);
    try testing.expectEqual(run.Status.running, run.inspect(&supervisor_handle));
    const pid = supervisor_handle.pid;
    std.debug.assert(pid > 1);
    supervisor_handle = undefined;
    sim.environment_variables = &worker_env;
    return pid;
}

/// The call Zigcube's worker makes: no terminal, no history entry, the worker's own handle.
fn worker_execs(sim: *HostSim, command: []const []const u8, diag: *Diag) exec.Error!void {
    std.debug.assert(command.len > 0);
    std.debug.assert(diag.code == null);
    const spec: exec.Spec = .{ .name = "web", .command = command, .terminal = false };
    const options: exec.Options = .{ .keep_history = false };
    return exec.start(sim.interface(), &spec, options, &worker_handle, diag);
}

test "a worker with the agent's state directory execs into a supervisor's container" {
    // Goal: ZB-2's first case. Method: the supervisor starts `web` detached and drops its
    // handle; a worker with only HOME and XDG_RUNTIME_DIR execs `/bin/sh -c true` with no
    // terminal; the command is in the container's PID namespace and cgroup, sees the container's
    // environment rather than the worker's, ends with 0, and leaves no terminal and no history.
    var sim: HostSim = undefined;
    const container_pid = try supervisor_starts(&sim, 31);
    var diag: Diag = undefined;
    diag.reset();
    try worker_execs(&sim, &.{ "/bin/sh", "-c", "true" }, &diag);
    const command = sim.world.find_process(worker_handle.pid.?).?;
    try testing.expectEqual(container_pid, command.pid_namespace);
    try testing.expect(command.in_scope);
    try testing.expect(command.in_scope_before_run);
    try testing.expect(std.mem.indexOf(u8, command.envp(), "ZCUBE_ROLE") == null);
    try testing.expect(std.mem.indexOf(u8, command.envp(), "HOSTNAME=web\n") != null);
    try testing.expect(!sim.world.input_is_raw);
    const exit = exec.wait(&worker_handle);
    try testing.expectEqual(exec.Exit{ .exited = 0 }, exit);
    try testing.expectEqual(@as(?u8, 0), exit.code());
    try testing.expect(!worker_handle.container_ended);
    var runs: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &runs));
    const logs = logfile.dir_of(&runs).?;
    var scratch: exec_history.Scratch = undefined;
    try exec_history.read(disk.interface(), &logs, "web", &scratch);
    try testing.expectEqual(@as(u32, 0), scratch.history.count);
}

test "a worker's exec ends with SIGKILL and container_ended when the container ends first" {
    // Goal: ZB-2's second case: what `exec_wait` returns when the supervisor's container ends
    // while the worker's command runs. Method: the worker starts `/bin/sleep 1000`, the
    // container's PID 1 is killed; the wait returns at once with `.signaled = 9` (code 137)
    // and `container_ended`, without hanging.
    var sim: HostSim = undefined;
    const container_pid = try supervisor_starts(&sim, 32);
    var diag: Diag = undefined;
    diag.reset();
    try worker_execs(&sim, &.{ "/bin/sleep", "1000" }, &diag);
    try testing.expect(sim.world.kill(container_pid, constants.signal_kill) == null);
    const exit = exec.wait(&worker_handle);
    try testing.expectEqual(exec.Exit{ .signaled = constants.signal_kill }, exit);
    try testing.expectEqual(@as(?u8, 137), exit.code());
    try testing.expect(worker_handle.container_ended);
}

test "a worker's exec into a container that already ended, or without the state, is refused" {
    // Goal: the refusals a worker sees before anything is made. Method: a worker without the
    // agent's state directory gets E0402 (no such container) while the container runs; once
    // PID 1 is gone, a worker with it gets E0220 (not running). Neither leaves a child.
    var sim: HostSim = undefined;
    const container_pid = try supervisor_starts(&sim, 33);
    var diag: Diag = undefined;
    diag.reset();
    sim.environment_variables = &stranger_env;
    try testing.expectError(error.StartFailed, worker_execs(&sim, &.{"/bin/sh"}, &diag));
    try testing.expectEqual(codes.Code.E0402, diag.code.?);
    sim.environment_variables = &worker_env;
    try testing.expect(sim.world.kill(container_pid, constants.signal_kill) == null);
    diag.reset();
    try testing.expectError(error.StartFailed, worker_execs(&sim, &.{"/bin/sh"}, &diag));
    try testing.expectEqual(codes.Code.E0220, diag.code.?);
    try testing.expectEqual(@as(u32, 0), sim.world.unreaped_children());
}
