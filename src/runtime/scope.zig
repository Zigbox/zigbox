//! The container's cgroup scope (docs/DECISIONS.md, "How a container gets its cgroup"): whether a
//! run can have one, the request for it, and the limits systemd is too old to take as unit
//! properties, which are written to the scope's cgroupfs files instead.
//!
//! Two moments. Before anything is created, `probe` connects to the user's bus, says Hello and
//! reads the systemd `Version`: a run with a limit flag stops here if there is no manager, and a
//! run without one goes on, warning, with no scope. Then, in the plan's `start_scope` step, after
//! the child exists and before it may run, `start` asks for the scope with the child's pid and
//! waits for its job. The pid is inside the scope when it returns, so nothing the container
//! does ever happens outside its limits.
//!
//! Nothing here words a failure: it returns a `Problem` that `diagnose.zig` turns into a code.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const auth = @import("../dbus/auth.zig");
const client = @import("../dbus/client.zig");
const host_mod = @import("../host.zig");
const systemd = @import("../dbus/systemd.zig");
const text_util = @import("../text.zig");
const plan_mod = @import("plan.zig");
const spec = @import("spec.zig");

const Host = host_mod.Host;

/// The kernel error of a host call that failed.
pub const Io = struct {
    err: host_mod.Error,
    errno: u16,
};

pub const CgroupWrite = struct {
    /// The file name, "memory.max".
    file: text_util.Bounded(24),
    io: Io,
};

pub const PathText = text_util.Bounded(constants.dbus_socket_path_bytes_max);

/// A bus that was tried first and turned this user away.
pub const Refused = struct {
    path: PathText,
    failure: client.Failure,
};

/// The bus at a second address, `/run/user/<own uid>/bus`, was tried after the inherited one
/// refused this user; it failed too.
pub const Retried = struct {
    refused: Refused,
    own_path: PathText,
    failure: client.Failure,
};

/// How the bus was reached, for `--verbose`: `refused` is set when the inherited address did
/// not work and the user's own bus did.
pub const Via = struct {
    refused: ?Refused,
    own_path: PathText,
};

/// Why a scope could not be had.
pub const Problem = union(enum) {
    /// Neither `DBUS_SESSION_BUS_ADDRESS` nor `XDG_RUNTIME_DIR` says where the bus is.
    no_address,
    /// The address is not a `unix:path=` one, or is malformed.
    bad_address: auth.AddressError,
    /// The conversation with the bus failed (client.zig has the details).
    bus: client.Failure,
    /// The inherited bus turned this user away and the user's own bus failed as well.
    bus_retried: Retried,
    /// Stopping the scope did not make its cgroup go away.
    scope_left,
    /// The scope is up but `/proc/<pid>/cgroup` does not say where its cgroup is.
    no_cgroup_path: Io,
    /// A limit systemd could not take was not written to the scope's cgroup file.
    cgroup_write: CgroupWrite,
};

pub const Probe = struct {
    version: u32,
    version_text: client.Text,
    via: Via,
};

/// The path of the user's bus socket: the address in `DBUS_SESSION_BUS_ADDRESS`, or else
/// `$XDG_RUNTIME_DIR/bus`.
pub fn bus_path(
    host: Host,
    buffer: *[constants.dbus_socket_path_bytes_max]u8,
    problem: *Problem,
) ?[]const u8 {
    assert(buffer.len == constants.dbus_socket_path_bytes_max);
    if (host.environment("DBUS_SESSION_BUS_ADDRESS", constants.dbus_address_bytes_max)) |address| {
        return auth.socket_path(buffer, address) catch |err| {
            problem.* = .{ .bad_address = err };
            return null;
        };
    }
    const limit = constants.dbus_socket_path_bytes_max;
    const runtime = host.environment("XDG_RUNTIME_DIR", limit) orelse {
        problem.* = .no_address;
        return null;
    };
    if (runtime.len == 0 or runtime[0] != '/') {
        problem.* = .no_address;
        return null;
    }
    const suffix = "/bus";
    if (runtime.len + suffix.len > buffer.len) {
        problem.* = .{ .bad_address = error.TooLong };
        return null;
    }
    @memcpy(buffer[0..runtime.len], runtime);
    @memcpy(buffer[runtime.len..][0..suffix.len], suffix);
    return buffer[0 .. runtime.len + suffix.len];
}

/// Connects, authenticates as the user and says Hello. On failure `problem` says why and the
/// connection is closed.
///
/// An address inherited through `su` or `sudo` names someone else's bus. If connecting to it is
/// refused for lack of permission, or authentication on it fails, and it is not this user's own
/// socket (`/run/user/<uid>/bus`), that one is tried, once. `via` says which one worked.
fn open_bus(host: Host, conn: *client.Connection, problem: *Problem, via: *Via) bool {
    assert(host.uid() != std.math.maxInt(u32));
    var path_buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    const path = bus_path(host, &path_buffer, problem) orelse return false;
    conn.init(host);
    via.refused = null;
    via.own_path = .{};
    via.own_path.print("{s}", .{path});
    if (open_steps(conn, path, host.uid())) return true;
    const first = conn.failure;
    conn.close();
    var own_buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    const own = own_path(host.uid(), &own_buffer);
    if (!worth_retrying(&first) or std.mem.eql(u8, path, own)) {
        problem.* = .{ .bus = first };
        return false;
    }
    var refused: Refused = .{ .path = .{}, .failure = first };
    refused.path.print("{s}", .{path});
    conn.init(host);
    if (open_steps(conn, own, host.uid())) {
        via.refused = refused;
        via.own_path = .{};
        via.own_path.print("{s}", .{own});
        return true;
    }
    problem.* = .{ .bus_retried = .{
        .refused = refused,
        .own_path = .{},
        .failure = conn.failure,
    } };
    problem.bus_retried.own_path.print("{s}", .{own});
    conn.close();
    return false;
}

/// `/run/user/<uid>/bus`: where a login session puts the user's bus.
fn own_path(uid: u32, buffer: *[constants.dbus_socket_path_bytes_max]u8) []const u8 {
    assert(buffer.len == constants.dbus_socket_path_bytes_max);
    assert(uid != std.math.maxInt(u32));
    // Cannot fail: "/run/user/4294967295/bus" is 24 bytes.
    return std.fmt.bufPrint(buffer, "/run/user/{d}/bus", .{uid}) catch unreachable;
}

/// The bus was reachable but not by this user: permission was refused at connect, or the
/// authentication was. Anything else (no socket, nobody listening) would not be different at
/// another address of the same user.
fn worth_retrying(failure: *const client.Failure) bool {
    assert(failure.errno < 4096);
    assert(failure.name.len <= constants.dbus_error_text_bytes_max);
    return switch (failure.kind) {
        .no_bus => failure.errno == errno_access or failure.errno == errno_perm,
        .auth_refused => true,
        else => false,
    };
}

const errno_perm: u16 = 1;
const errno_access: u16 = 13;

fn open_steps(conn: *client.Connection, path: []const u8, uid: u32) bool {
    assert(path.len > 0);
    assert(path.len <= constants.dbus_socket_path_bytes_max);
    conn.connect(path) catch return false;
    conn.authenticate(uid) catch return false;
    conn.hello() catch return false;
    return true;
}

/// Reads the bus and the systemd on it. Opens its own connection and closes it; a write to a bus
/// that hangs up is an error here, not a signal, for the length of the call.
pub fn probe(host: Host, out: *Probe, problem: *Problem) bool {
    assert(@intFromPtr(problem) != @intFromPtr(out));
    host.ignore_broken_pipe(true);
    defer host.ignore_broken_pipe(false);
    var conn: client.Connection = undefined;
    if (!open_bus(host, &conn, problem, &out.via)) return false;
    defer conn.close();
    var version: systemd.Version = undefined;
    systemd.read_version(&conn, &version) catch {
        problem.* = .{ .bus = conn.failure };
        return false;
    };
    out.version = version.number;
    out.version_text = version.text;
    assert(out.version > 0);
    return true;
}

/// The request for `plan`'s scope with the container's `pid` in it. A limit goes to the unit
/// only if the systemd that was probed has the property; the rest is `fallback`'s.
pub fn request_for(plan: *const plan_mod.Plan, pid: u32) systemd.ScopeRequest {
    assert(plan.scoped);
    assert(pid > 1);
    const version = plan.scope_version;
    const limits = plan.scope_limits;
    const memory = limits.memory_bytes;
    assert(plan.scope_name.len > 0);
    const request: systemd.ScopeRequest = .{
        .name = plan.text(plan.scope_name),
        .description = plan.text(plan.scope_description),
        .pid = pid,
        .slice = if (systemd.supports(version, .app_slice)) "app.slice" else null,
        .memory_max = if (systemd.supports(version, .memory_max)) memory else null,
        .memory_swap_zero = memory != null and systemd.supports(version, .memory_swap_max),
        .tasks_max = if (systemd.supports(version, .tasks_max)) tasks_max(limits) else null,
        .cpu_quota_usec = if (!systemd.supports(version, .cpu_quota)) null else cpu_quota(limits),
    };
    assert(request.pid == pid);
    return request;
}

fn tasks_max(limits: spec.Limits) ?u64 {
    const pids = limits.pids orelse return null;
    assert(pids >= constants.limit_pids_min);
    return pids;
}

/// `CPUQuotaPerSecUSec`: microseconds of CPU per second, 1000 for each thousandth of a CPU.
fn cpu_quota(limits: spec.Limits) ?u64 {
    const millis = limits.cpu_millis orelse return null;
    assert(millis >= constants.limit_cpu_millis_min);
    return @as(u64, millis) * 1000;
}

/// A cgroup control file and the text to write to it.
pub const FileWrite = struct {
    name: []const u8,
    value: text_util.Bounded(constants.cgroup_file_bytes_max),
};

pub const fallback_files_max: u32 = 4;

/// The limits the probed systemd cannot take as properties, as cgroupfs writes.
pub fn fallback(
    version: u32,
    limits: spec.Limits,
    out: *[fallback_files_max]FileWrite,
) u32 {
    assert(version > 0);
    var count: u32 = 0;
    if (limits.memory_bytes) |bytes| {
        if (!systemd.supports(version, .memory_max)) {
            out[count] = .{ .name = "memory.max", .value = .{} };
            out[count].value.print("{d}", .{bytes});
            count += 1;
        }
        if (!systemd.supports(version, .memory_swap_max)) {
            out[count] = .{ .name = "memory.swap.max", .value = .{} };
            out[count].value.print("0", .{});
            count += 1;
        }
    }
    if (limits.pids) |pids| {
        if (!systemd.supports(version, .tasks_max)) {
            out[count] = .{ .name = "pids.max", .value = .{} };
            out[count].value.print("{d}", .{pids});
            count += 1;
        }
    }
    if (limits.cpu_millis) |millis| {
        if (!systemd.supports(version, .cpu_quota)) {
            // cpu.max is "<quota> <period>" in microseconds; a 100 ms period is the default.
            out[count] = .{ .name = "cpu.max", .value = .{} };
            out[count].value.print("{d} 100000", .{@as(u64, millis) * 100});
            count += 1;
        }
    }
    assert(count <= fallback_files_max);
    return count;
}

/// The scope's cgroup directory under /sys/fs/cgroup; empty if it could not be found.
pub const Directory = text_util.Bounded(constants.cgroup_path_bytes_max);

/// Asks for the scope with `pid` in it, waits for the job, and writes the limits systemd could
/// not take. Returns true with the pid inside the scope and `directory` set to its cgroup (empty
/// if `/proc` would not say, which matters only when a limit has to be written there);
/// otherwise `problem` says why.
pub fn start(
    host: Host,
    plan: *const plan_mod.Plan,
    pid: u32,
    directory: *Directory,
    problem: *Problem,
) bool {
    assert(pid > 1);
    assert(plan.scoped);
    directory.* = .{};
    var conn: client.Connection = undefined;
    var via: Via = undefined;
    if (!open_bus(host, &conn, problem, &via)) return false;
    defer conn.close();
    const request = request_for(plan, pid);
    systemd.start_scope(&conn, &request) catch {
        problem.* = .{ .bus = conn.failure };
        return false;
    };
    var buffer: [constants.cgroup_path_bytes_max]u8 = undefined;
    var lookup: Problem = undefined;
    const found = cgroup_directory(host, pid, &buffer, &lookup);
    if (found) |text| directory.print("{s}", .{text});
    var files: [fallback_files_max]FileWrite = undefined;
    const count = fallback(plan.scope_version, plan.scope_limits, &files);
    if (count == 0) return true;
    if (found == null) {
        problem.* = lookup;
        return false;
    }
    return write_fallback(host, directory.slice(), files[0..count], problem);
}

fn write_fallback(
    host: Host,
    directory: []const u8,
    files: []const FileWrite,
    problem: *Problem,
) bool {
    assert(directory.len > 0);
    assert(files.len > 0);
    for (files) |*file| {
        var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
        const text = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ directory, file.name }) catch {
            problem.* = .{ .no_cgroup_path = .{ .err = error.PathTooLong, .errno = 0 } };
            return false;
        };
        if (text.len == path_buffer.len) {
            problem.* = .{ .no_cgroup_path = .{ .err = error.PathTooLong, .errno = 0 } };
            return false;
        }
        path_buffer[text.len] = 0;
        const path: [:0]const u8 = path_buffer[0..text.len :0];
        host.write_file(path, file.value.slice()) catch |err| {
            var written: CgroupWrite = .{
                .file = .{},
                .io = .{ .err = err, .errno = host.last_errno() },
            };
            written.file.print("{s}", .{file.name});
            problem.* = .{ .cgroup_write = written };
            return false;
        };
    }
    return true;
}

// ---- After the container ends ---------------------------------------------------------------

/// What the kernel counted in the scope's cgroup. A count is null if its file could not be read:
/// the controller is not delegated, or the cgroup is already gone.
pub const Events = struct {
    /// `oom_kill` of `memory.events`: processes killed by the OOM killer.
    oom_kill: ?u64,
    /// `max` of `pids.events`: forks refused because the limit was reached.
    pids_max: ?u64,
};

/// Reads the scope's `memory.events` and `pids.events`. Call it as soon as the container's
/// PID 1 is reaped: the manager removes the cgroup once nothing is left in it, and a cgroup that
/// is gone has no events to read (the result is then all null, and the run is reported as the
/// plain exit it was).
pub fn read_events(host: Host, directory: []const u8) Events {
    assert(directory.len <= constants.cgroup_path_bytes_max);
    if (directory.len > 0) assert(directory[0] == '/');
    if (directory.len == 0) return .{ .oom_kill = null, .pids_max = null };
    return .{
        .oom_kill = event_count(host, directory, "memory.events", "oom_kill"),
        .pids_max = event_count(host, directory, "pids.events", "max"),
    };
}

fn event_count(host: Host, directory: []const u8, file: []const u8, key: []const u8) ?u64 {
    assert(directory.len > 0);
    assert(file.len > 0);
    assert(key.len > 0);
    var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ directory, file }) catch return null;
    var text_buffer: [512]u8 = undefined;
    const text = host.read_file(path, &text_buffer) catch return null;
    return event_value(text, key);
}

/// The number on the line `<key> <number>` of a cgroup events file.
pub fn event_value(text: []const u8, key: []const u8) ?u64 {
    assert(key.len > 0);
    assert(std.mem.indexOfScalar(u8, key, ' ') == null);
    assert(text.len <= 4096);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        if (line.len <= key.len or line[key.len] != ' ') continue;
        return std.fmt.parseInt(u64, std.mem.trim(u8, line[key.len + 1 ..], " \t\r"), 10) catch
            return null;
    }
    return null;
}

/// Whether the scope's cgroup is still there. Any answer but "no such file" counts as there: a
/// directory that cannot be looked at has not been seen to go.
pub fn cgroup_exists(host: Host, directory: []const u8) bool {
    assert(directory.len > 0);
    assert(directory[0] == '/');
    var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "{s}/cgroup.events", .{directory}) catch
        return true;
    var text_buffer: [256]u8 = undefined;
    _ = host.read_file(path, &text_buffer) catch |err| return err != error.NotFound;
    return true;
}

/// How the scope came to be gone.
pub const Cleaned = enum {
    /// Its cgroup was already removed when looked at.
    already_gone,
    /// The cgroup was there, but the manager no longer knew the unit (`NoSuchUnit`): it was on its
    /// way out, and was gone by the next look.
    manager_done,
    /// The manager still had the unit; its stop job ended "done" and the cgroup went.
    stopped,
};

/// Makes sure the scope is gone once its container has ended. The manager removes a scope by
/// itself when its last process exits, so the common case costs one look at the cgroup. If it
/// is still there the manager is asked to stop the unit (a scope that already went is
/// `NoSuchUnit`, the good answer), and the cgroup is looked at again. Null if it is not gone,
/// with `problem` saying why.
pub fn cleanup(
    host: Host,
    name: []const u8,
    directory: []const u8,
    problem: *Problem,
) ?Cleaned {
    assert(std.mem.endsWith(u8, name, constants.scope_suffix));
    assert(directory.len <= constants.cgroup_path_bytes_max);
    if (directory.len > 0 and !cgroup_exists(host, directory)) return .already_gone;
    host.ignore_broken_pipe(true);
    defer host.ignore_broken_pipe(false);
    var conn: client.Connection = undefined;
    var via: Via = undefined;
    if (!open_bus(host, &conn, problem, &via)) return null;
    defer conn.close();
    const stopped = stop_steps(&conn, name) orelse {
        problem.* = .{ .bus = conn.failure };
        return null;
    };
    if (directory.len > 0 and cgroup_exists(host, directory)) {
        problem.* = .scope_left;
        return null;
    }
    return if (stopped == .gone) .manager_done else .stopped;
}

fn stop_steps(conn: *client.Connection, name: []const u8) ?systemd.Stopped {
    assert(conn.is_open);
    assert(name.len > constants.scope_suffix.len);
    systemd.watch_jobs(conn) catch return null;
    return systemd.stop_scope(conn, name) catch null;
}

/// Where the scope's cgroup is: the unified line (`0::<path>`) of `/proc/<pid>/cgroup`, under
/// /sys/fs/cgroup.
fn cgroup_directory(
    host: Host,
    pid: u32,
    buffer: *[constants.cgroup_path_bytes_max]u8,
    problem: *Problem,
) ?[]const u8 {
    assert(pid > 1);
    assert(buffer.len == constants.cgroup_path_bytes_max);
    var path_buffer: [32]u8 = undefined;
    // Cannot fail: "/proc/4294967295/cgroup" is 23 bytes.
    const path = std.fmt.bufPrint(&path_buffer, "/proc/{d}/cgroup", .{pid}) catch unreachable;
    var text_buffer: [1024]u8 = undefined;
    const text = host.read_file(path, &text_buffer) catch |err| {
        problem.* = .{ .no_cgroup_path = .{ .err = err, .errno = host.last_errno() } };
        return null;
    };
    const relative = unified_path(text) orelse {
        problem.* = .{ .no_cgroup_path = .{ .err = error.NotFound, .errno = 0 } };
        return null;
    };
    const prefix = "/sys/fs/cgroup";
    if (prefix.len + relative.len > buffer.len) {
        problem.* = .{ .no_cgroup_path = .{ .err = error.PathTooLong, .errno = 0 } };
        return null;
    }
    @memcpy(buffer[0..prefix.len], prefix);
    @memcpy(buffer[prefix.len..][0..relative.len], relative);
    return buffer[0 .. prefix.len + relative.len];
}

/// The path on the line `0::<path>` of a `/proc/<pid>/cgroup`, or null if there is none or it is
/// not an absolute path without a `..`.
pub fn unified_path(text: []const u8) ?[]const u8 {
    assert(text.len <= 1024);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "0::")) continue;
        const path = line[3..];
        if (path.len < 2) return null;
        if (path[0] != '/') return null;
        if (std.mem.indexOf(u8, path, "..") != null) return null;
        return path;
    }
    return null;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const sim_run = @import("sim_run.zig");

fn scoped_plan(plan: *plan_mod.Plan, version: u32, limits: spec.Limits) void {
    plan.build(&.{
        .rootfs = "/srv/alpine",
        .name = "web-1",
        .command = &.{"sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = .single,
        .scope = .{ .version = version, .limits = limits },
    });
}

test "the bus is where the address says, else at the runtime directory" {
    // Goal: the two ways to find it and each way to fail, with the problem that names it.
    var sim: HostSim = undefined;
    sim.init(1, &.{});
    var buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    var problem: Problem = undefined;
    const bus_variable = "DBUS_SESSION_BUS_ADDRESS";
    sim.environment_variables = &.{.{ .name = bus_variable, .value = "unix:path=/x/bus" }};
    try testing.expectEqualStrings("/x/bus", bus_path(sim.interface(), &buffer, &problem).?);
    sim.environment_variables = &.{.{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/7" }};
    const runtime_bus = bus_path(sim.interface(), &buffer, &problem).?;
    try testing.expectEqualStrings("/run/user/7/bus", runtime_bus);
    sim.environment_variables = &.{};
    try testing.expect(bus_path(sim.interface(), &buffer, &problem) == null);
    try testing.expect(problem == .no_address);
    sim.environment_variables = &.{.{ .name = "XDG_RUNTIME_DIR", .value = "relative" }};
    try testing.expect(bus_path(sim.interface(), &buffer, &problem) == null);
    try testing.expect(problem == .no_address);
    sim.environment_variables = &.{.{ .name = bus_variable, .value = "unix:abstract=x" }};
    try testing.expect(bus_path(sim.interface(), &buffer, &problem) == null);
    try testing.expectEqual(auth.AddressError.Unsupported, problem.bad_address);
    // An address wins over the runtime directory even when the address is bad.
    sim.environment_variables = &.{
        .{ .name = "DBUS_SESSION_BUS_ADDRESS", .value = "tcp:host=x" },
        .{ .name = "XDG_RUNTIME_DIR", .value = "/run/user/7" },
    };
    try testing.expect(bus_path(sim.interface(), &buffer, &problem) == null);
}

test "limits go to the unit when systemd has the property, and to cgroupfs when it does not" {
    // Goal: every limit on both sides of its version boundary, and the slice.
    var plan: plan_mod.Plan = undefined;
    const limits: spec.Limits = .{ .memory_bytes = 128 << 20, .pids = 64, .cpu_millis = 500 };
    scoped_plan(&plan, 255, limits);
    const modern = request_for(&plan, 77);
    try testing.expectEqualStrings("zbx-web-1.scope", modern.name);
    try testing.expectEqualStrings("zbx: web-1", modern.description);
    try testing.expectEqualStrings("app.slice", modern.slice.?);
    try testing.expectEqual(@as(?u64, 128 << 20), modern.memory_max);
    try testing.expect(modern.memory_swap_zero);
    try testing.expectEqual(@as(?u64, 64), modern.tasks_max);
    try testing.expectEqual(@as(?u64, 500_000), modern.cpu_quota_usec);
    var files: [fallback_files_max]FileWrite = undefined;
    try testing.expectEqual(@as(u32, 0), fallback(255, limits, &files));

    scoped_plan(&plan, 230, limits);
    const old = request_for(&plan, 77);
    try testing.expect(old.slice == null);
    try testing.expect(old.memory_max == null);
    try testing.expect(!old.memory_swap_zero);
    try testing.expect(old.tasks_max != null); // 227 has TasksMax.
    try testing.expect(old.cpu_quota_usec != null);
    const count = fallback(230, limits, &files);
    try testing.expectEqual(@as(u32, 2), count);
    try testing.expectEqualStrings("memory.max", files[0].name);
    try testing.expectEqualStrings("134217728", files[0].value.slice());
    try testing.expectEqualStrings("memory.swap.max", files[1].name);
    try testing.expectEqualStrings("0", files[1].value.slice());

    scoped_plan(&plan, 200, limits);
    try testing.expectEqual(@as(u32, 4), fallback(200, limits, &files));
    try testing.expectEqualStrings("pids.max", files[2].name);
    try testing.expectEqualStrings("64", files[2].value.slice());
    try testing.expectEqualStrings("cpu.max", files[3].name);
    try testing.expectEqualStrings("50000 100000", files[3].value.slice());
}

test "no limits means no property and no file" {
    var plan: plan_mod.Plan = undefined;
    scoped_plan(&plan, 255, .{});
    const request = request_for(&plan, 9);
    try testing.expect(request.memory_max == null);
    try testing.expect(!request.memory_swap_zero);
    try testing.expect(request.tasks_max == null);
    try testing.expect(request.cpu_quota_usec == null);
    var files: [fallback_files_max]FileWrite = undefined;
    try testing.expectEqual(@as(u32, 0), fallback(100, .{}, &files));
}

test "the unified line of /proc/<pid>/cgroup is the scope's cgroup" {
    // Goal: cgroup v2 (0::), skipping v1 lines, and refusing what is not a path.
    const hybrid = "12:pids:/user.slice\n0::/user.slice/user-1000.slice/app.slice/zbx-a.scope\n";
    try testing.expectEqualStrings(
        "/user.slice/user-1000.slice/app.slice/zbx-a.scope",
        unified_path(hybrid).?,
    );
    try testing.expect(unified_path("") == null);
    try testing.expect(unified_path("12:pids:/x\n") == null);
    try testing.expect(unified_path("0::\n") == null);
    try testing.expect(unified_path("0::/\n") == null);
    try testing.expect(unified_path("0::relative\n") == null);
    try testing.expect(unified_path("0::/a/../b\n") == null);
}

test "an old systemd's limits are written to the scope's own cgroup files" {
    // Goal: the whole fallback against the simulator: the scope is started without the limits it
    // lacks, `/proc/<pid>/cgroup` says where the cgroup is, and the files hold the values.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    sim.world.bus.model.version = "230.1";
    var plan: plan_mod.Plan = undefined;
    scoped_plan(&plan, 230, .{ .memory_bytes = 64 << 20, .pids = 8 });
    var problem: Problem = undefined;
    var directory: Directory = undefined;
    try testing.expect(start(sim.interface(), &plan, 600, &directory, &problem));
    const scope = sim.world.bus.find_scope("zbx-web-1.scope").?;
    try testing.expect(scope.memory_max == null);
    try testing.expectEqual(@as(?u64, 8), scope.tasks_max);
    const base = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service";
    const memory = sim.world.read_written(base ++ "/zbx-web-1.scope/memory.max");
    try testing.expectEqualStrings("67108864", memory.?);
    const swap = sim.world.read_written(base ++ "/zbx-web-1.scope/memory.swap.max");
    try testing.expectEqualStrings("0", swap.?);
    try testing.expect(sim.world.read_written(base ++ "/zbx-web-1.scope/pids.max") == null);
}

test "a limit that cannot be written is a cgroup_write problem naming the file" {
    // Goal: E0308's input: the file and the errno of the refused write.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    sim.world.bus.model.version = "230.1";
    // A directory where the file belongs: the write is refused, as a controller that is not
    // delegated refuses it.
    const base = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service";
    sim.world.add_node(base ++ "/zbx-web-1.scope/memory.max", .dir);
    var plan: plan_mod.Plan = undefined;
    scoped_plan(&plan, 230, .{ .memory_bytes = 64 << 20 });
    var problem: Problem = undefined;
    var directory: Directory = undefined;
    try testing.expect(!start(sim.interface(), &plan, 600, &directory, &problem));
    try testing.expectEqualStrings("memory.max", problem.cgroup_write.file.slice());
    try testing.expectEqual(host_mod.Error.NotFound, problem.cgroup_write.io.err);
}

test "probe reads the version, and says why when it cannot" {
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    var found: Probe = undefined;
    var problem: Problem = undefined;
    try testing.expect(probe(sim.interface(), &found, &problem));
    try testing.expectEqual(@as(u32, 255), found.version);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    sim.world.bus.model.present = false;
    try testing.expect(!probe(sim.interface(), &found, &problem));
    try testing.expectEqual(client.FailureKind.no_bus, problem.bus.kind);
    sim.world.bus.model.present = true;
    sim.environment_variables = &.{};
    try testing.expect(!probe(sim.interface(), &found, &problem));
    try testing.expect(problem == .no_address);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
    try testing.expect(!sim.world.broken_pipe_ignored);
}
