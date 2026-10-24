//! The two conversations zbx has with the user's systemd manager over `client.zig`:
//! reading its `Version` (the doctor's probe, and the choice between unit properties and
//! cgroupfs files), and `StartTransientUnit` for a container's scope, followed by the wait for
//! the job that creates it.
//!
//! The design follows runc's systemd driver (docs/DECISIONS.md): one transient `.scope` per
//! container, the container's pid in `PIDs`, `Delegate=true` so the container's own cgroup tree
//! belongs to the user, accounting on, and the limits as unit properties wherever the running
//! systemd has them. What zbx drops from runc is OCI-only (`cgroupsPath`, annotations): the
//! unit's name is `zbx-<container>.scope` and nothing else names it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const client = @import("client.zig");
const wire = @import("wire.zig");

const Connection = client.Connection;
const CallError = client.CallError;

const systemd_name = "org.freedesktop.systemd1";
const manager_path = "/org/freedesktop/systemd1";
const manager_interface = "org.freedesktop.systemd1.Manager";

/// What the running systemd can do through unit properties. Each feature carries the first
/// systemd version that has it (from systemd's NEWS: `TasksMax=` 227, `MemoryMax=` 231 and
/// `MemorySwapMax=` 232 for cgroup v2, `CPUQuotaPerSecUSec` 213, `app.slice` in the user
/// manager 247); an older systemd gets the same limit written to the scope's cgroupfs file.
pub const Feature = enum { cpu_quota, tasks_max, memory_max, memory_swap_max, app_slice };

pub fn minimum_version(feature: Feature) u32 {
    const version: u32 = switch (feature) {
        .cpu_quota => 213,
        .tasks_max => 227,
        .memory_max => 231,
        .memory_swap_max => 232,
        .app_slice => 247,
    };
    assert(version > 0);
    assert(version < 1000);
    return version;
}

pub fn supports(version: u32, feature: Feature) bool {
    assert(version < 100_000);
    return version >= minimum_version(feature);
}

/// The leading number of a `Version` such as "255.4-1ubuntu8.4" or "v254". Null if it has none.
pub fn parse_version(text: []const u8) ?u32 {
    assert(text.len <= constants.dbus_string_bytes_max);
    var start: usize = 0;
    if (text.len > 0 and text[0] == 'v') start = 1;
    assert(start <= text.len);
    var end = start;
    while (end < text.len and std.ascii.isDigit(text[end])) end += 1;
    if (end == start) return null;
    if (end - start > 6) return null; // A version number, not a date or a hash.
    return std.fmt.parseInt(u32, text[start..end], 10) catch null;
}

pub const Version = struct {
    number: u32,
    text: client.Text,
};

/// Reads the manager's `Version` property. The connection has said Hello. A bus without
/// `org.freedesktop.systemd1` on it answers with an error, which the caller reads from
/// `conn.failure`.
pub fn read_version(conn: *Connection, out: *Version) CallError!void {
    assert(conn.is_open);
    assert(conn.failure.name.len <= constants.dbus_error_text_bytes_max);
    var body_buffer: [256]u8 = undefined;
    var writer = wire.Writer.init(&body_buffer);
    writer.string(manager_interface);
    writer.string("Version");
    const body = writer.finish() catch |err| return protocol(conn, err);
    const reply = try conn.call(.{
        .destination = systemd_name,
        .path = manager_path,
        .interface = "org.freedesktop.DBus.Properties",
        .member = "Get",
        .signature = "ss",
        .body = body,
    }, .call);
    if (!std.mem.eql(u8, reply.signature, "v")) return protocol(conn, error.BadSignature);
    var reader = reply.body_reader();
    const inner = reader.signature() catch |err| return protocol(conn, err);
    if (!std.mem.eql(u8, inner, "s")) return protocol(conn, error.BadSignature);
    const text = reader.string() catch |err| return protocol(conn, err);
    out.number = parse_version(text) orelse return protocol(conn, error.BadValue);
    out.text = .{};
    out.text.append_sanitised(text, constants.systemd_version_text_bytes_max);
    assert(out.number > 0);
    assert(out.text.len > 0);
}

fn protocol(conn: *Connection, problem: wire.WireError) CallError {
    assert(conn.is_open);
    assert(@intFromError(problem) != 0);
    conn.failure.kind = .protocol;
    conn.failure.stage = .call;
    conn.failure.wire = problem;
    conn.failure.name = .{};
    conn.failure.text = .{};
    return error.Failed;
}

/// What the scope is made with. A limit that is null is not set; one that the running systemd
/// lacks is left null here too, and written to cgroupfs by the caller.
pub const ScopeRequest = struct {
    /// "zbx-<container>.scope".
    name: []const u8,
    /// "zbx: <container>".
    description: []const u8,
    pid: u32,
    /// The user manager's `app.slice`, or null for the manager's default.
    slice: ?[]const u8,
    memory_max: ?u64,
    /// `MemorySwapMax=0`, so that the memory limit is a limit.
    memory_swap_zero: bool,
    tasks_max: ?u64,
    /// `CPUQuotaPerSecUSec`: microseconds of CPU per second.
    cpu_quota_usec: ?u64,
};

/// Starts the scope and waits for its job. On success the container's pid is inside the scope.
/// A taken name is the remote error `org.freedesktop.systemd1.UnitExists`; any other refusal,
/// and a job that ends in anything but "done", are failures the caller diagnoses.
pub fn start_scope(conn: *Connection, request: *const ScopeRequest) CallError!void {
    assert(request.pid > 1);
    assert(std.mem.endsWith(u8, request.name, constants.scope_suffix));
    assert(conn.is_open);
    assert(request.description.len > 0);
    try conn.add_match("type='signal',sender='org.freedesktop.systemd1'," ++
        "interface='org.freedesktop.systemd1.Manager',member='JobRemoved'");
    var body_buffer: [2048]u8 = undefined;
    const body = marshal_scope(&body_buffer, request) catch |err| return protocol(conn, err);
    const reply = try conn.call(.{
        .destination = systemd_name,
        .path = manager_path,
        .interface = manager_interface,
        .member = "StartTransientUnit",
        .signature = "ssa(sv)a(sa(sv))",
        .body = body,
    }, .call);
    if (!std.mem.eql(u8, reply.signature, "o")) return protocol(conn, error.BadSignature);
    var reader = reply.body_reader();
    var job_path_buffer: [96]u8 = undefined;
    const job = reader.object_path() catch |err| return protocol(conn, err);
    if (job.len > job_path_buffer.len) return protocol(conn, error.TooLong);
    @memcpy(job_path_buffer[0..job.len], job);
    const result = try conn.wait_job(job_path_buffer[0..job.len]);
    if (std.mem.eql(u8, result, "done")) return;
    conn.failure.kind = .remote;
    conn.failure.stage = .job;
    conn.failure.name = .{};
    conn.failure.name.append_sanitised(result, constants.dbus_error_text_bytes_max);
    conn.failure.text = .{};
    return error.Failed;
}

/// The body of `StartTransientUnit(name, "fail", properties, [])`. "fail" means: an existing
/// unit of that name is an error, never silently reused.
pub fn marshal_scope(buffer: []u8, request: *const ScopeRequest) wire.WireError![]const u8 {
    assert(buffer.len >= 1024);
    assert(request.name.len > 0);
    var writer = wire.Writer.init(buffer);
    writer.string(request.name);
    writer.string("fail");
    const properties = writer.array_begin(8);
    var count: u32 = 0;
    property_string(&writer, "Description", request.description, &count);
    if (request.slice) |slice| property_string(&writer, "Slice", slice, &count);
    const accounting = [_][]const u8{
        "Delegate",
        "CPUAccounting",
        "MemoryAccounting",
        "IOAccounting",
        "TasksAccounting",
    };
    for (accounting) |name| property_bool(&writer, name, true, &count);
    property_pids(&writer, request.pid, &count);
    if (request.memory_max) |value| property_u64(&writer, "MemoryMax", value, &count);
    if (request.memory_swap_zero) property_u64(&writer, "MemorySwapMax", 0, &count);
    if (request.tasks_max) |value| property_u64(&writer, "TasksMax", value, &count);
    if (request.cpu_quota_usec) |value| {
        property_u64(&writer, "CPUQuotaPerSecUSec", value, &count);
    }
    writer.array_end(properties);
    assert(count <= constants.scope_properties_max);
    const unit_aux = writer.array_begin(8); // No auxiliary units.
    writer.array_end(unit_aux);
    return writer.finish();
}

fn property_start(
    writer: *wire.Writer,
    name: []const u8,
    value_signature: []const u8,
    count: *u32,
) void {
    assert(name.len > 0);
    assert(value_signature.len > 0);
    count.* += 1;
    assert(count.* <= constants.scope_properties_max);
    writer.struct_begin();
    writer.string(name);
    writer.variant_begin(value_signature);
}

fn property_string(writer: *wire.Writer, name: []const u8, value: []const u8, count: *u32) void {
    assert(name.len > 0);
    assert(value.len > 0);
    property_start(writer, name, "s", count);
    writer.string(value);
}

fn property_bool(writer: *wire.Writer, name: []const u8, value: bool, count: *u32) void {
    assert(name.len > 0);
    assert(count.* < constants.scope_properties_max);
    property_start(writer, name, "b", count);
    writer.boolean(value);
}

fn property_u64(writer: *wire.Writer, name: []const u8, value: u64, count: *u32) void {
    assert(name.len > 0);
    assert(count.* < constants.scope_properties_max);
    property_start(writer, name, "t", count);
    writer.uint64(value);
}

fn property_pids(writer: *wire.Writer, pid: u32, count: *u32) void {
    assert(pid > 1);
    assert(count.* < constants.scope_properties_max);
    property_start(writer, "PIDs", "au", count);
    const array = writer.array_begin(4);
    writer.uint32(pid);
    writer.array_end(array);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

test "versions: the leading number of what systemd reports" {
    // Goal: real Version strings parse, and text that is not a version does not.
    try testing.expectEqual(@as(?u32, 255), parse_version("255.4-1ubuntu8.4"));
    try testing.expectEqual(@as(?u32, 254), parse_version("v254"));
    try testing.expectEqual(@as(?u32, 219), parse_version("219"));
    try testing.expectEqual(@as(?u32, null), parse_version(""));
    try testing.expectEqual(@as(?u32, null), parse_version("v"));
    try testing.expectEqual(@as(?u32, null), parse_version("abc"));
    try testing.expectEqual(@as(?u32, null), parse_version("20261024-git"));
}

test "a feature needs its version, and the table is ordered by what was added when" {
    // Goal: the boundary of each feature, one version below and at.
    for (std.enums.values(Feature)) |feature| {
        const needed = minimum_version(feature);
        try testing.expect(supports(needed, feature));
        try testing.expect(!supports(needed - 1, feature));
    }
    try testing.expect(minimum_version(.memory_swap_max) > minimum_version(.memory_max));
    try testing.expect(minimum_version(.app_slice) > minimum_version(.memory_swap_max));
    try testing.expect(supports(255, .app_slice));
}

test "the scope request marshals into the body StartTransientUnit takes" {
    // Goal: the exact layout of ssa(sv)a(sa(sv)): two strings, the property array of
    // structs aligned to 8, and an empty second array. Method: marshal, then read it back with
    // the reader following the signature.
    var buffer: [2048]u8 = undefined;
    const body = try marshal_scope(&buffer, &.{
        .name = "zbx-web.scope",
        .description = "zbx: web",
        .pid = 4242,
        .slice = "app.slice",
        .memory_max = 128 * 1024 * 1024,
        .memory_swap_zero = true,
        .tasks_max = 64,
        .cpu_quota_usec = 500_000,
    });
    var reader = wire.Reader.init(body, .little);
    try testing.expectEqualStrings("zbx-web.scope", try reader.string());
    try testing.expectEqualStrings("fail", try reader.string());
    const end = try reader.array_begin(8);
    var names: [constants.scope_properties_max][]const u8 = undefined;
    var count: usize = 0;
    while (reader.at < end) : (count += 1) {
        try reader.align_to(8);
        names[count] = try reader.string();
        const kind = try reader.signature();
        switch (kind[0]) {
            's' => _ = try reader.string(),
            'b' => _ = try reader.boolean(),
            't' => _ = try reader.uint64(),
            'a' => {
                const array_end = try reader.array_begin(4);
                while (reader.at < array_end) _ = try reader.uint32();
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(end, reader.at);
    const expected = [_][]const u8{
        "Description",      "Slice",         "Delegate",        "CPUAccounting",
        "MemoryAccounting", "IOAccounting",  "TasksAccounting", "PIDs",
        "MemoryMax",        "MemorySwapMax", "TasksMax",        "CPUQuotaPerSecUSec",
    };
    try testing.expectEqual(expected.len, count);
    for (expected, names[0..count]) |want, got| try testing.expectEqualStrings(want, got);
    const aux_end = try reader.array_begin(8);
    try testing.expectEqual(reader.at, aux_end);
    try testing.expectEqual(@as(u32, 0), reader.remaining());
}

test "a request with no limits and no slice has only the always-on properties" {
    // Goal: nothing optional is written when it is not asked for.
    var buffer: [2048]u8 = undefined;
    const body = try marshal_scope(&buffer, &.{
        .name = "zbx-a.scope",
        .description = "zbx: a",
        .pid = 7,
        .slice = null,
        .memory_max = null,
        .memory_swap_zero = false,
        .tasks_max = null,
        .cpu_quota_usec = null,
    });
    try testing.expect(std.mem.indexOf(u8, body, "MemoryMax") == null);
    try testing.expect(std.mem.indexOf(u8, body, "Slice") == null);
    try testing.expect(std.mem.indexOf(u8, body, "Delegate") != null);
    try testing.expect(std.mem.indexOf(u8, body, "PIDs") != null);
}
