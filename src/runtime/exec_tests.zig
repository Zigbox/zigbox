//! `zbx exec` against the simulator (docs/briefs/M6b-dev-loop.md, slice 3): the command joins
//! every namespace of a running container in the kernel's order, is put in its cgroup before it
//! runs (the bus driver and the cgroupfs one), and gains nothing the container lacks: the same
//! capability set, `no_new_privs` and filter, its user, its environment and working directory.
//! Then the refusals (a stopped container, a missing one, every failed step), the terminal, the
//! death of the container, and the history. The VM shows the kernel does what the model says.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const capabilities = @import("capabilities.zig");
const codes = @import("../diag/codes.zig");
const exec = @import("exec.zig");
const exec_history = @import("exec_history.zig");
const exec_plan = @import("exec_plan.zig");
const host_sim = @import("../host_sim.zig");
const logfile = @import("logfile.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");
const sim_world = @import("../sim_world.zig");
const Diag = @import("../diag/diag.zig").Diag;
const SimFs = @import("../store/fs_sim.zig").SimFs;

const HostSim = host_sim.HostSim;
const testing = std.testing;

var disk: SimFs = undefined;
var container_handle: run.Handle = undefined;
var exec_handle: exec.Handle = undefined;

/// A host with a log disk and a container `web` that runs (its command lasts a minute of the
/// simulator's clock), started through the library as a detached run would be.
fn start_container(sim: *HostSim, seed: u64, spec_in: run.Spec) !u32 {
    disk.init(seed);
    disk.put_dir("/home", 0o755);
    disk.put_dir("/home/alice", 0o755);
    sim.log_fs = &disk;
    sim.world.command_runs_ms = 60_000;
    var diag: Diag = undefined;
    diag.reset();
    var spec = spec_in;
    spec.name = "web";
    try run.start(sim.interface(), &spec, .{}, &container_handle, &diag);
    container_handle.session.release_output();
    return container_handle.pid;
}

fn default_spec() run.Spec {
    return .{
        .rootfs = sim_run.rootfs_path,
        .name = "web",
        .command = &.{"/bin/sh"},
        .env = &.{.{ .key = "APP", .value = "one" }},
        .env_names = &.{"APP"},
    };
}

fn exec_spec(command: []const []const u8) exec.Spec {
    return .{ .name = "web", .command = command };
}

/// What the exec'd command must look like to the model once it started: in every namespace of
/// the container, in its cgroup before it ran, and with exactly the container's hardening.
fn joined(sim: *HostSim, container_pid: u32, pid: u32) ?[]const u8 {
    const container = sim.world.find_process(container_pid).?;
    const command = sim.world.find_process(pid) orelse return "no command";
    if (!command.execd) return "the command was not started";
    if (command.table != container.table) return "not in the container's mount namespace";
    if (command.uts != container.uts) return "not in the container's UTS namespace";
    if (!command.new_user) return "not in the container's user namespace";
    if (!command.new_ipc) return "not in the container's IPC namespace";
    if (command.new_net != container.new_net) return "not in the container's network";
    if (command.pid_namespace != container_pid) return "not in the container's PID namespace";
    if (!command.root.?.eql(container.root.?.slice())) return "not in the container's root";
    if (!command.in_scope) return "not in the container's cgroup";
    if (!command.in_scope_before_run) return "put in the cgroup after it ran";
    if (command.capabilities != capabilities.keep_mask) return "not the container's capabilities";
    if (!command.ambient_cleared) return "ambient capabilities left";
    if (!command.no_new_privs) return "no no_new_privs";
    if (!command.seccomp) return "no seccomp filter";
    if (!command.sealed) return "descriptors not sealed";
    if (!command.die_with_parent) return "not tied to zbx";
    return null;
}

fn expect_joined(sim: *HostSim, container_pid: u32, pid: u32) !void {
    if (joined(sim, container_pid, pid)) |problem| {
        std.debug.print("exec: {s}\n", .{problem});
        return error.TestUnexpectedResult;
    }
}

test "exec joins the container's namespaces and cgroup and gains nothing it lacks" {
    // Goal: the brief's "joins, gains nothing", in the model. Method: start a container through
    // the library, exec `/bin/sh` in it, and look at the command's process: every namespace the
    // container's, the cgroup joined while the command waited, the same capability set, the
    // same filter and `no_new_privs`, the container's environment with the run's `-e`, and the
    // container's working directory. The joiner joined user first; it is reaped.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    const container_pid = try start_container(&sim, 1, default_spec());
    var diag: Diag = undefined;
    diag.reset();
    const spec = exec_spec(&.{ "/bin/sh", "-c", "id" });
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    const pid = exec_handle.pid.?;
    try expect_joined(&sim, container_pid, pid);
    const command = sim.world.find_process(pid).?;
    try testing.expect(std.mem.indexOf(u8, command.envp(), "APP=one\n") != null);
    try testing.expect(std.mem.indexOf(u8, command.envp(), "HOSTNAME=web\n") != null);
    const container_cwd = sim.world.find_process(container_pid).?.cwd.slice();
    try testing.expectEqualStrings(container_cwd, command.cwd.slice());
    try testing.expectEqual(@as(u32, 1), sim.world.bus.attach_count);
    const exit = exec.wait(&exec_handle);
    try testing.expectEqual(@as(?u8, 0), exit.code());
    try testing.expect(!exec_handle.container_ended);
    try testing.expectEqual(@as(u32, 0), exec_open(&sim));
}

/// Handles the exec left open: the container's own are not counted (its run is still going).
fn exec_open(sim: *const HostSim) u32 {
    var count: u32 = 0;
    for (sim.world.namespace_handles) |entry| count += @intFromBool(entry != null);
    return count + @intFromBool(sim.world.input_is_raw);
}

test "exec's -e, --user and --workdir are for its command only" {
    // Goal: the overrides, and that the container's record is untouched. Method: an exec with
    // `-e APP=two`, a user by number and a directory the container has.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 2);
    _ = try start_container(&sim, 2, default_spec());
    sim.world.add_node(sim_run.rootfs_path ++ "/srv", .dir);
    var diag: Diag = undefined;
    diag.reset();
    var spec = exec_spec(&.{"/bin/sh"});
    spec.env = &.{.{ .key = "APP", .value = "two" }};
    spec.user = "1000:1000";
    spec.workdir = "/srv";
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    const command = sim.world.find_process(exec_handle.pid.?).?;
    try testing.expect(std.mem.indexOf(u8, command.envp(), "APP=two\n") != null);
    try testing.expect(std.mem.indexOf(u8, command.envp(), "APP=one") == null);
    try testing.expectEqual(@as(?[2]u32, .{ 1000, 1000 }), command.user_set);
    try testing.expectEqualStrings(sim_run.rootfs_path ++ "/srv", command.cwd.slice());
    _ = exec.wait(&exec_handle);
}

test "exec with the cgroupfs driver writes the command's pid to the container's cgroup" {
    // Goal: the M4b driver (the macOS VM): no bus, the pid written to the container's cgroup's
    // `cgroup.procs` while the command waits.
    var sim: HostSim = undefined;
    sim_run.init_cgroupfs(&sim, 3);
    const container_pid = try start_container(&sim, 3, default_spec());
    var diag: Diag = undefined;
    diag.reset();
    const spec = exec_spec(&.{"/bin/sh"});
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    try expect_joined(&sim, container_pid, exec_handle.pid.?);
    try testing.expectEqual(@as(u32, 0), sim.world.bus.attach_count);
    _ = exec.wait(&exec_handle);
}

test "exec into a stopped container names its state; a missing one is E0402" {
    // Goal: the refusals before anything is made. Method: a finished record, then no record.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 4);
    const view = sim_run.sample_view("web", 1000);
    sim_run.put_record(&sim, &view);
    var diag: Diag = undefined;
    diag.reset();
    const spec = exec_spec(&.{"/bin/sh"});
    const stopped = exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    try testing.expectError(error.StartFailed, stopped);
    try testing.expectEqual(codes.Code.E0220, diag.code.?);
    try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, "exited with code 3") != null);
    diag.reset();
    var other = exec_spec(&.{"/bin/sh"});
    other.name = "nobody";
    const missing = exec.start(sim.interface(), &other, .{}, &exec_handle, &diag);
    try testing.expectError(error.StartFailed, missing);
    try testing.expectEqual(codes.Code.E0402, diag.code.?);
    try testing.expectEqual(@as(u32, 0), sim.world.unreaped_children());
}

test "the exec'd command dies with its container, and zbx says so" {
    // Goal: the brief's lifetime: the command is in the container's PID namespace, so when the
    // container's PID 1 ends the kernel kills it; `wait` returns (no hang) with SIGKILL and
    // says the container ended.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 5);
    const container_pid = try start_container(&sim, 5, default_spec());
    var diag: Diag = undefined;
    diag.reset();
    const spec = exec_spec(&.{ "/bin/sleep", "1000" });
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    try testing.expect(sim.world.kill(container_pid, constants.signal_kill) == null);
    const exit = exec.wait(&exec_handle);
    try testing.expectEqual(exec.Exit{ .signaled = constants.signal_kill }, exit);
    try testing.expectEqual(@as(?u8, 137), exit.code());
    try testing.expect(exec_handle.container_ended);
}

const terminal_chunks = [_]sim_world.OutChunk{
    .{ .stream = .stdout, .bytes = "prompt$ " },
    .{ .stream = .stdout, .bytes = "ls\r\nbin dev\r\n" },
};

test "with a terminal the command gets a pseudo-terminal of its own, sized and resized" {
    // Goal: the pseudo-terminal path. Method: the keys on zbx's input reach the master, what the
    // command writes on its terminal reaches zbx's output, a SIGWINCH copies the size again,
    // zbx's terminal is raw while it runs and put back after, and nothing is left open.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 6);
    _ = try start_container(&sim, 6, default_spec());
    sim.world.input = "ls\r";
    sim.world.out_script = &terminal_chunks;
    sim.world.out_at = 0;
    sim.world.script[0] = constants.signal_winch;
    sim.world.script_len = 1;
    sim.world.script_at = 0;
    var diag: Diag = undefined;
    diag.reset();
    var spec = exec_spec(&.{"/bin/sh"});
    spec.terminal = true;
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    const command = sim.world.find_process(exec_handle.pid.?).?;
    try testing.expect(command.terminal);
    try testing.expect(sim.world.input_is_raw);
    _ = exec.wait(&exec_handle);
    try testing.expect(!sim.world.input_is_raw);
    try testing.expectEqual(@as(u32, 2), sim.world.window_copies);
    const typed = sim.world.terminal_typed[0..sim.world.terminal_typed_len];
    try testing.expectEqualStrings("ls\r", typed);
    try testing.expect(std.mem.endsWith(u8, sim.stdout(), "prompt$ ls\r\nbin dev\r\n"));
    try testing.expectEqual(@as(u32, 0), exec_open(&sim));
}

test "every step that fails is one coded diagnostic, and nothing is left behind" {
    // Goal: every exit path of the start (REVIEW.md). Method: for each step of the parent, the
    // joiner and the command (the plan with a terminal and a user, the longest), fail its first
    // host call; the start fails with the code that step's kind has, the children are reaped,
    // the namespace files closed and zbx's terminal put back.
    var plan: exec_plan.Plan = undefined;
    const input: exec_plan.Input = .{
        .command = &.{"/bin/sh"},
        .environ = "",
        .env = &.{},
        .term = null,
        .workdir = "",
        .user = .{ .uid = 1000, .gid = 1000 },
        .namespaces = 0x3f,
        .terminal = true,
        .cgroup = true,
    };
    plan.build(&input);
    for (plan.steps[0..plan.count], 0..) |step, index| {
        if (step.kind == .reap) continue;
        var sim: HostSim = undefined;
        sim_run.init(&sim, 100 + index);
        _ = try start_container(&sim, 100 + index, default_spec());
        const children = sim.world.unreaped_children();
        sim.faults.fail_step = @intCast(index);
        var diag: Diag = undefined;
        diag.reset();
        var spec = exec_spec(&.{"/bin/sh"});
        spec.terminal = true;
        spec.user = "1000";
        const result = exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
        if (result) |_| {
            std.debug.print("step {s} did not fail the start\n", .{@tagName(step.kind)});
            return error.TestUnexpectedResult;
        } else |_| {}
        if (expected_code(step.kind) != diag.code.? or
            children != sim.world.unreaped_children())
        {
            std.debug.print("step {d} {s}: {s}, children {d} then {d}\n", .{
                index,                         @tagName(step.kind),
                @tagName(diag.code.?),         children,
                sim.world.unreaped_children(),
            });
            return error.TestUnexpectedResult;
        }
        try testing.expectEqual(@as(u32, 0), exec_open(&sim));
    }
}

fn expected_code(kind: exec_plan.Kind) codes.Code {
    return switch (kind) {
        .exec => .E0202,
        .enter_workdir => .E0223,
        .open_terminal, .attach_terminal => .E0224,
        .restrict_capabilities, .clear_ambient => .E0207,
        .set_no_new_privs, .install_seccomp => .E0208,
        .join_cgroup => .E0222,
        else => .E0221,
    };
}

test "exec leaves a history of the command and its exit, never a value of -e" {
    // Goal: the bounded list beside the log. Method: two execs, one with a secret-shaped value;
    // the history has both commands and exits, oldest first, and no byte of the value.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 7);
    _ = try start_container(&sim, 7, default_spec());
    var diag: Diag = undefined;
    diag.reset();
    var spec = exec_spec(&.{ "/bin/sh", "-c", "exit 3" });
    spec.env = &.{.{ .key = "TOKEN", .value = "secret-marker-OMEGA" }};
    sim.world.command_exit = .{ .exited = 3 };
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    try testing.expectEqual(@as(?u8, 3), exec.wait(&exec_handle).code());
    sim.world.command_exit = .{ .exited = 0 };
    const second = exec_spec(&.{ "/bin/sleep", "1" });
    try exec.start(sim.interface(), &second, .{}, &exec_handle, &diag);
    _ = exec.wait(&exec_handle);
    var runs: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &runs));
    const logs = logfile.dir_of(&runs).?;
    var scratch: exec_history.Scratch = undefined;
    try exec_history.read(disk.interface(), &logs, "web", &scratch);
    try testing.expectEqual(@as(u32, 2), scratch.history.count);
    const first = &scratch.history.entries[0];
    try testing.expectEqualStrings("\"/bin/sh\" \"-c\" \"exit 3\"", first.command_text());
    try testing.expectEqual(exec_history.Exit{ .exited = 3 }, first.exit);
    var text: [exec_history.file_bytes_max]u8 = undefined;
    const rendered = exec_history.render(&scratch.history, &text);
    try testing.expect(std.mem.indexOf(u8, rendered, "secret-marker-OMEGA") == null);
}

test "a --user the container lacks is E0216; a user in a container with only root is E0523" {
    // Goal: --user is looked up in the container's own files, and the single-id map has no
    // user but root.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 8);
    const container_pid = try start_container(&sim, 8, default_spec());
    var path: [64]u8 = undefined;
    const passwd = try std.fmt.bufPrint(&path, "/proc/{d}/root/etc/passwd", .{container_pid});
    sim.world.put_raw(passwd, "root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n");
    var diag: Diag = undefined;
    diag.reset();
    var spec = exec_spec(&.{"/bin/sh"});
    spec.user = "alice";
    const unknown = exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    try testing.expectError(error.StartFailed, unknown);
    try testing.expectEqual(codes.Code.E0216, diag.code.?);
    diag.reset();
    spec.user = "nobody";
    try exec.start(sim.interface(), &spec, .{}, &exec_handle, &diag);
    const command = sim.world.find_process(exec_handle.pid.?).?;
    try testing.expectEqual(@as(?[2]u32, .{ 65534, 65534 }), command.user_set);
    _ = exec.wait(&exec_handle);

    var single: HostSim = undefined;
    sim_run.init_single(&single, 9);
    _ = try start_container(&single, 9, default_spec());
    diag.reset();
    spec.user = "1000";
    const only_root = exec.start(single.interface(), &spec, .{}, &exec_handle, &diag);
    try testing.expectError(error.StartFailed, only_root);
    try testing.expectEqual(codes.Code.E0523, diag.code.?);
}

comptime {
    assert(@sizeOf(exec.Handle) <= constants.exec_handle_bytes_max);
}
