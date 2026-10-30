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
const parse = @import("../parse.zig");
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
    /// No cgroup v2 is mounted at `/sys/fs/cgroup` (a cgroup v1 or hybrid layout): there is no
    /// cgroup anywhere that zbx could limit a container with, whatever a bus would say.
    no_cgroup2,
    /// cgroup v2 is mounted but its root does not offer all of `required_controllers`; `missing`
    /// names the ones it lacks.
    cgroup2_lacks: parse.ControllerSet,
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
    /// The cgroupfs driver (no systemd): a step of the container's cgroup failed.
    cgroupfs: Cgroupfs,
};

/// What the cgroupfs driver was doing when a call failed.
pub const CgroupStep = enum { make, join, limit, remove };

pub const Cgroupfs = struct {
    step: CgroupStep,
    /// The directory, or for `limit` the file.
    path: text_util.Bounded(constants.cgroup_path_bytes_max + 32),
    io: Io,
};

/// Which way a run gets its cgroup: from the user's systemd manager over the bus, or, in the
/// macOS VM (no systemd), by making one child cgroup per container in a delegated cgroup v2
/// directory named by `ZBX_CGROUP_ROOT`, as runc's and Podman's cgroupfs drivers do. The second
/// only when there is no user bus to ask: a host with systemd behaves as it always did.
pub const Driver = enum { systemd, cgroupfs };

/// The systemd version the cgroupfs driver reports: none of the limits is a unit property there,
/// so every one is written to a cgroup file (`fallback`).
pub const cgroupfs_version: u32 = 1;

pub fn driver(host: Host, root: *Directory) Driver {
    var buffer: [constants.dbus_socket_path_bytes_max]u8 = undefined;
    var problem: Problem = undefined;
    if (bus_path(host, &buffer, &problem) != null) return .systemd;
    const value = host.environment(constants.cgroup_root_variable, constants.cgroup_path_bytes_max);
    const text = value orelse return .systemd;
    if (text.len < 2 or text[0] != '/') return .systemd;
    root.* = .{};
    root.print("{s}", .{text});
    assert(root.slice().len == text.len); // Not cut: the variable fits the buffer.
    assert(root.slice()[0] == '/');
    return .cgroupfs;
}

/// What a limit needs from the kernel: the controllers the cgroup v2 root must offer.
pub const required_controllers = [_]parse.Controller{ .cpu, .memory, .pids };

/// The file whose presence says the unified (v2) hierarchy is what `/sys/fs/cgroup` is.
pub const cgroup_root_controllers_path = "/sys/fs/cgroup/cgroup.controllers";

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
///
/// When there is no scope to be had, the cause that comes first is the one that would stay even
/// with a perfect bus: a host without a usable cgroup v2 (`cgroup2_shortfall`) is reported as
/// that, not as a missing user bus. A host where the bus works is not second-guessed here.
pub fn probe(host: Host, out: *Probe, problem: *Problem) bool {
    assert(@intFromPtr(problem) != @intFromPtr(out));
    if (probe_driver(host, out, problem)) return true;
    if (root_shortfall(host, problem)) assert(problem.* != .bus);
    return false;
}

fn probe_driver(host: Host, out: *Probe, problem: *Problem) bool {
    var root: Directory = .{};
    if (driver(host, &root) == .cgroupfs) {
        out.version = cgroupfs_version;
        out.version_text = .{};
        out.version_text.print("cgroupfs {s}", .{root.slice()});
        out.via = .{ .refused = null, .own_path = .{} };
        return true;
    }
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

/// True, with the cause in `problem`, if the cgroup v2 root cannot carry a limit: it is not there
/// (`read_err` is `NotFound`, the v1 and hybrid layouts) or it lacks a required controller. The
/// doctor calls this with the read it already made; a run reads the file itself
/// (`root_shortfall`). A read that failed for another reason, or text that does not parse, says
/// nothing about the layout, so it is not a shortfall: the doctor reports those itself.
pub fn cgroup2_shortfall(
    read_err: ?host_mod.Error,
    text: []const u8,
    problem: *Problem,
) bool {
    assert(text.len <= constants.cgroup_list_bytes_max);
    if (read_err) |err| {
        assert(text.len == 0);
        if (err != error.NotFound) return false;
        problem.* = .no_cgroup2;
        assert(problem.* == .no_cgroup2);
        return true;
    }
    const offered = parse.parse_controller_list(text) catch return false;
    var missing: parse.ControllerSet = .{};
    for (required_controllers) |controller| {
        if (offered.has(controller)) continue;
        missing.bits |= @as(u16, 1) << @backingInt(controller);
    }
    if (missing.is_empty()) return false;
    assert(missing.unknown == 0); // Only known controllers are required.
    problem.* = .{ .cgroup2_lacks = missing };
    assert(problem.* == .cgroup2_lacks);
    return true;
}

/// `cgroup2_shortfall` for the root's `cgroup.controllers` as the host has it.
fn root_shortfall(host: Host, problem: *Problem) bool {
    var buffer: [constants.cgroup_list_bytes_max]u8 = undefined;
    const text = host.read_file(cgroup_root_controllers_path, &buffer) catch |err| {
        return cgroup2_shortfall(err, "", problem);
    };
    return cgroup2_shortfall(null, text, problem);
}

/// The request for `plan`'s scope with the container's `pid` and the scope's keeper in it. A
/// limit goes to the unit only if the systemd that was probed has the property; the rest is
/// `fallback`'s.
pub fn request_for(plan: *const plan_mod.Plan, pid: u32, keeper_pid: u32) systemd.ScopeRequest {
    assert(plan.scoped);
    assert(pid > 1);
    assert(keeper_pid > 1);
    assert(keeper_pid != pid);
    const version = plan.scope_version;
    const limits = plan.scope_limits;
    const memory = limits.memory_bytes;
    assert(plan.scope_name.len > 0);
    const request: systemd.ScopeRequest = .{
        .name = plan.text(plan.scope_name),
        .description = plan.text(plan.scope_description),
        .pid = pid,
        .keeper_pid = keeper_pid,
        .slice = if (systemd.supports(version, .app_slice)) "app.slice" else null,
        .memory_max = if (systemd.supports(version, .memory_max)) memory else null,
        .memory_swap_zero = memory != null and systemd.supports(version, .memory_swap_max),
        .tasks_max = if (systemd.supports(version, .tasks_max)) tasks_max(limits) else null,
        .cpu_quota_usec = if (!systemd.supports(version, .cpu_quota)) null else cpu_quota(limits),
    };
    assert(request.pid == pid);
    return request;
}

/// `TasksMax`: the pids the container asked for, plus the one the keeper takes. The keeper is a
/// process of the scope and counts against its limit, so without the extra one the container
/// would get a pid fewer than `--pids` says (and `pids.events` would count refusals one fork
/// early).
fn tasks_max(limits: spec.Limits) ?u64 {
    const pids = limits.pids orelse return null;
    assert(pids >= constants.limit_pids_min);
    return @as(u64, pids) + constants.scope_keeper_tasks;
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
            out[count].value.print("{d}", .{@as(u64, pids) + constants.scope_keeper_tasks});
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

/// Asks for the scope with `pid` and `keeper_pid` in it, waits for the job, and writes the limits
/// systemd could not take. Returns true with the pids inside the scope and `directory` set to its
/// cgroup (empty if `/proc` would not say, which matters only when a limit has to be written
/// there); otherwise `problem` says why.
pub fn start(
    host: Host,
    plan: *const plan_mod.Plan,
    pid: u32,
    keeper_pid: u32,
    directory: *Directory,
    problem: *Problem,
) bool {
    assert(pid > 1);
    assert(keeper_pid > 1);
    assert(plan.scoped);
    directory.* = .{};
    var root: Directory = .{};
    if (driver(host, &root) == .cgroupfs) {
        const members: Members = .{ .pid = pid, .keeper_pid = keeper_pid };
        return start_cgroupfs(host, plan, members, root.slice(), directory, problem);
    }
    var conn: client.Connection = undefined;
    var via: Via = undefined;
    if (!open_bus(host, &conn, problem, &via)) return false;
    defer conn.close();
    const request = request_for(plan, pid, keeper_pid);
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

/// Puts `pid` (an exec'd command, waiting to run) in the cgroup of the running container whose
/// PID 1 is `container_pid` and whose scope is `name`: with systemd, the manager moves it into
/// the scope (`AttachProcessesToUnit`); with the cgroupfs driver, its pid is written to the
/// container's cgroup, found through `/proc/<container_pid>/cgroup`.
pub fn attach(
    host: Host,
    name: []const u8,
    container_pid: u32,
    pid: u32,
    problem: *Problem,
) bool {
    assert(std.mem.endsWith(u8, name, constants.scope_suffix));
    assert(pid > 1);
    assert(container_pid != pid);
    var root: Directory = .{};
    if (driver(host, &root) == .cgroupfs) {
        var buffer: [constants.cgroup_path_bytes_max]u8 = undefined;
        const directory = cgroup_directory(host, container_pid, &buffer, problem) orelse
            return false;
        return join_cgroup(host, directory, pid, problem);
    }
    var conn: client.Connection = undefined;
    var via: Via = undefined;
    if (!open_bus(host, &conn, problem, &via)) return false;
    defer conn.close();
    systemd.attach_process(&conn, name, pid) catch {
        problem.* = .{ .bus = conn.failure };
        return false;
    };
    return true;
}

// ---- The cgroupfs driver --------------------------------------------------------------------

const Members = struct { pid: u32, keeper_pid: u32 };

fn cgroupfs_problem(step: CgroupStep, path: []const u8, host: Host, err: host_mod.Error) Problem {
    assert(path.len > 0);
    const io: Io = .{ .err = err, .errno = host.last_errno() };
    var result: Cgroupfs = .{ .step = step, .path = .{}, .io = io };
    result.path.print("{s}", .{path});
    assert(result.path.slice().len > 0);
    assert(result.io.errno < 4096);
    return .{ .cgroupfs = result };
}

/// Makes `<root>/<scope name>`, moves the container and the keeper into it, and writes the
/// limits. The child is still waiting for its go-ahead, so nothing it does happens outside the
/// limits (the order the systemd driver keeps). `directory` is set as soon as the cgroup exists,
/// so that cleanup finds it even when a later step fails.
fn start_cgroupfs(
    host: Host,
    plan: *const plan_mod.Plan,
    members: Members,
    root: []const u8,
    directory: *Directory,
    problem: *Problem,
) bool {
    assert(root.len >= 2);
    assert(members.pid != members.keeper_pid);
    var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
    const name = plan.text(plan.scope_name);
    const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ root, name }) catch {
        problem.* = cgroupfs_problem(.make, root, host, error.PathTooLong);
        return false;
    };
    if (path.len >= constants.cgroup_path_bytes_max) {
        problem.* = cgroupfs_problem(.make, root, host, error.PathTooLong);
        return false;
    }
    path_buffer[path.len] = 0;
    const path_z: [:0]const u8 = path_buffer[0..path.len :0];
    host.make_directory(path_z, false) catch |err| {
        problem.* = cgroupfs_problem(.make, path, host, err);
        return false;
    };
    directory.print("{s}", .{path});
    for ([_]u32{ members.pid, members.keeper_pid }) |member| {
        if (!join_cgroup(host, path, member, problem)) return false;
    }
    var files: [fallback_files_max]FileWrite = undefined;
    const count = fallback(cgroupfs_version, plan.scope_limits, &files);
    const limits = plan.scope_limits;
    // Under this driver every limit is a file: memory.max and its swap file, pids.max, cpu.max.
    const expected: u32 = (if (limits.memory_bytes != null) @as(u32, 2) else 0) +
        @intFromBool(limits.pids != null) + @intFromBool(limits.cpu_millis != null);
    assert(count == expected);
    assert(directory.slice().len == path.len);
    return write_cgroupfs_limits(host, path, files[0..count], problem);
}

fn join_cgroup(host: Host, directory: []const u8, pid: u32, problem: *Problem) bool {
    assert(directory.len > 0);
    assert(pid > 1);
    var file_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
    const procs = "{s}/cgroup.procs";
    const file = std.fmt.bufPrint(&file_buffer, procs, .{directory}) catch return false;
    assert(file.len > directory.len); // The directory and the name of the file.
    file_buffer[file.len] = 0;
    const file_z: [:0]const u8 = file_buffer[0..file.len :0];
    var number: [16]u8 = undefined;
    const text = std.fmt.bufPrint(&number, "{d}", .{pid}) catch unreachable; // A pid is short.
    host.write_file(file_z, text) catch |err| {
        problem.* = cgroupfs_problem(.join, file, host, err);
        return false;
    };
    return true;
}

fn write_cgroupfs_limits(
    host: Host,
    directory: []const u8,
    files: []const FileWrite,
    problem: *Problem,
) bool {
    assert(directory.len > 0);
    assert(files.len <= fallback_files_max);
    for (files) |file| {
        var path_buffer: [constants.cgroup_path_bytes_max + 32]u8 = undefined;
        const name = file.name;
        const path = std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ directory, name }) catch {
            problem.* = cgroupfs_problem(.limit, directory, host, error.PathTooLong);
            return false;
        };
        assert(file.value.slice().len > 0); // A limit file is never written empty.
        path_buffer[path.len] = 0;
        const path_z: [:0]const u8 = path_buffer[0..path.len :0];
        host.write_file(path_z, file.value.slice()) catch |err| {
            // memory.swap.max is best effort: the VM has no swap to forbid, and a kernel
            // without swap accounting has the file absent or not writable.
            const swap = std.mem.eql(u8, file.name, "memory.swap.max");
            if (swap) continue;
            problem.* = cgroupfs_problem(.limit, path, host, err);
            return false;
        };
    }
    return true;
}

/// Removes the container's cgroup. It is empty once the container and the keeper are reaped, but
/// the kernel may take a moment to say so: EBUSY is tried again a few times.
fn cleanup_cgroupfs(host: Host, directory: []const u8, problem: *Problem) ?Cleaned {
    assert(directory.len > 0);
    assert(directory[0] == '/');
    assert(directory.len <= constants.cgroup_path_bytes_max); // It fits the buffer below.
    var path_buffer: [constants.cgroup_path_bytes_max + 1]u8 = undefined;
    @memcpy(path_buffer[0..directory.len], directory);
    path_buffer[directory.len] = 0;
    const path_z: [:0]const u8 = path_buffer[0..directory.len :0];
    var tries: u32 = 0;
    while (tries < constants.cgroup_remove_tries_max) : (tries += 1) {
        if (host.remove_directory(path_z)) |_| {
            return .removed;
        } else |err| {
            if (err == error.NotFound) return .already_gone;
            const busy = host.last_errno() == errno_busy;
            assert(tries < constants.cgroup_remove_tries_max);
            if (!busy or tries + 1 == constants.cgroup_remove_tries_max) {
                problem.* = cgroupfs_problem(.remove, directory, host, err);
                return null;
            }
            host.sleep_ms(constants.cgroup_remove_wait_ms);
        }
    }
    unreachable; // The last try returns above.
}

const errno_busy: u16 = 16;

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

/// Reads the scope's `memory.events` and `pids.events`. Call it after the container's PID 1 is
/// reaped and before the scope's keeper is released (`Session.release_keeper`): the keeper is
/// still in the cgroup, so the manager cannot have removed it, and the counters are there. The
/// manager removes a cgroup the moment nothing is left in it, with its counters; if the keeper
/// is gone already (something killed it, or the fork was refused and the run went on) the
/// result can be all null, and the run is reported as the plain exit it was.
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
    /// The cgroupfs driver removed the empty cgroup itself.
    removed,
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
    var root: Directory = .{};
    if (driver(host, &root) == .cgroupfs) {
        if (directory.len == 0) return .already_gone; // The cgroup was never made.
        return cleanup_cgroupfs(host, directory, problem);
    }
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
    const modern = request_for(&plan, 77, 78);
    try testing.expectEqualStrings("zbx-web-1.scope", modern.name);
    try testing.expectEqualStrings("zbx: web-1", modern.description);
    try testing.expectEqualStrings("app.slice", modern.slice.?);
    try testing.expectEqual(@as(?u64, 128 << 20), modern.memory_max);
    try testing.expect(modern.memory_swap_zero);
    try testing.expectEqual(@as(?u64, 65), modern.tasks_max); // 64 and the keeper.
    try testing.expectEqual(@as(u32, 78), modern.keeper_pid);
    try testing.expectEqual(@as(?u64, 500_000), modern.cpu_quota_usec);
    var files: [fallback_files_max]FileWrite = undefined;
    try testing.expectEqual(@as(u32, 0), fallback(255, limits, &files));

    scoped_plan(&plan, 230, limits);
    const old = request_for(&plan, 77, 78);
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
    try testing.expectEqualStrings("65", files[2].value.slice()); // 64 and the keeper.
    try testing.expectEqualStrings("cpu.max", files[3].name);
    try testing.expectEqualStrings("50000 100000", files[3].value.slice());
}

test "no limits means no property and no file" {
    var plan: plan_mod.Plan = undefined;
    scoped_plan(&plan, 255, .{});
    const request = request_for(&plan, 9, 10);
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
    try testing.expect(start(sim.interface(), &plan, 600, 601, &directory, &problem));
    const scope = sim.world.bus.find_scope("zbx-web-1.scope").?;
    try testing.expect(scope.memory_max == null);
    try testing.expectEqual(@as(?u64, 9), scope.tasks_max);
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
    try testing.expect(!start(sim.interface(), &plan, 600, 601, &directory, &problem));
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
