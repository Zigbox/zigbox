//! The workload knobs of a run against the simulator (M2b slice 1): each `--ulimit` and
//! `--sysctl` reaches the container's process before it runs, and each refusal is its code
//! before anything is created. The VM demo shows the real kernel.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const knobs = @import("knobs.zig");
const sim_run = @import("sim_run.zig");
const run = @import("run.zig");

const HostSim = host_sim.HostSim;
const testing = std.testing;
const rootfs = sim_run.rootfs_path;

/// Storage for a handle: far too big for a test's stack.
var handle_storage: ?*run.Handle = null;

fn handle_get() *run.Handle {
    if (handle_storage == null) {
        handle_storage = std.heap.page_allocator.create(run.Handle) catch @panic("out of memory");
    }
    return handle_storage.?;
}

fn no_leak(sim: *const HostSim, before: *const sim_run.Baseline) !void {
    if (sim_run.leak(sim, before)) |text| {
        std.debug.print("the host leaked: {s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

fn knob_spec() run.Spec {
    return .{ .rootfs = rootfs, .name = "db-1", .command = &.{"/bin/sh"} };
}

const two_sysctls = [_]knobs.Sysctl{
    .{ .key = "net.core.somaxconn", .value = "8192" },
    .{ .key = "kernel.shmmax", .value = "68719476736" },
};

test "the knobs reach the container: its limits and its sysctls, set before it runs" {
    // Goal: the success path. Method: a run with two limits and two sysctls; the container's
    // process holds exactly the limits asked for, the others inherited, and wrote both sysctls.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 1);
    const before = sim_run.baseline(&sim);
    var container = knob_spec();
    container.rlimits.set(.nofile, .{ .soft = 4096, .hard = 65536 });
    container.rlimits.set(.stack, .{ .soft = 16 << 20, .hard = 16 << 20 });
    container.sysctls = &two_sysctls;
    container.limits.shm_bytes = 256 << 20;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &container, .{}, handle_get(), &diag);
    const child = &sim.world.processes[1];
    try testing.expect(child.execd);
    const nofile = child.rlimits[@backingInt(knobs.Resource.nofile)];
    try testing.expectEqual(knobs.Rlimit{ .soft = 4096, .hard = 65536 }, nofile);
    const stack = child.rlimits[@backingInt(knobs.Resource.stack)];
    try testing.expectEqual(knobs.Rlimit{ .soft = 16 << 20, .hard = 16 << 20 }, stack);
    const nproc = child.rlimits[@backingInt(knobs.Resource.nproc)];
    try testing.expectEqual(sim.world.processes[0].rlimits[1], nproc); // Inherited.
    try testing.expectEqual(@as(u8, 2), child.sysctls_written);
    _ = run.wait(handle_get());
    try no_leak(&sim, &before);
}

const Case = struct {
    code: codes.Code,
    /// Text the diagnostic says, to tell the refusals of one code apart.
    says: []const u8,
    rlimit: ?struct { resource: knobs.Resource, limit: knobs.Rlimit } = null,
    shm_bytes: ?u64 = null,
    memory_bytes: ?u64 = null,
    sysctls: []const knobs.Sysctl = &.{},
    network: @import("spec.zig").Network = .none,
};

const host_key = [_]knobs.Sysctl{.{ .key = "vm.max_map_count", .value = "262144" }};
const net_key = [_]knobs.Sysctl{.{ .key = "net.core.somaxconn", .value = "8192" }};
const twice = [_]knobs.Sysctl{ net_key[0], net_key[0] };
const newline = [_]knobs.Sysctl{.{ .key = "kernel.sem", .value = "1 2\n3 4" }};
const too_many: [17]knobs.Sysctl = @splat(net_key[0]);

const cases = [_]Case{
    .{ .code = .E0311, .says = "above your own, 524288", .rlimit = .{
        .resource = .nofile,
        .limit = .{ .soft = 1024, .hard = 524289 },
    } },
    .{ .code = .E0311, .says = "memlock", .rlimit = .{
        .resource = .memlock,
        .limit = .{ .soft = 0, .hard = knobs.unlimited },
    } },
    .{ .code = .E0310, .says = "soft limit is above", .rlimit = .{
        .resource = .nproc,
        .limit = .{ .soft = 2, .hard = 1 },
    } },
    .{ .code = .E0313, .says = "one page", .shm_bytes = (4 << 10) - 1 },
    .{ .code = .E0313, .says = "the host has", .shm_bytes = 1 << 40 },
    .{ .code = .E0314, .says = "charged", .shm_bytes = (64 << 20) + 1, .memory_bytes = 64 << 20 },
    .{ .code = .E0316, .says = "host setting", .sysctls = &host_key },
    .{ .code = .E0317, .says = "--net host", .sysctls = &net_key, .network = .host },
    .{ .code = .E0315, .says = "set twice", .sysctls = &twice },
    .{ .code = .E0315, .says = "printable", .sysctls = &newline },
    .{ .code = .E0315, .says = "at most 16", .sysctls = &too_many },
};

test "each refused knob is its code, before anything is created" {
    // Goal: every parent refusal, at its edge: one past the user's hard limit, one byte below a
    // page and above --memory, a host key, a net key on the host's network, and the list's
    // forms. Method: nothing was spawned or written, and the cause says which.
    for (cases, 0..) |case, index| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 10 + index);
        const before = sim_run.baseline(&sim);
        var container = knob_spec();
        if (case.rlimit) |pair| {
            container.rlimits = .{};
            switch (pair.resource) {
                inline else => |resource| @field(container.rlimits, @tagName(resource)) =
                    pair.limit,
            }
        }
        container.limits.shm_bytes = case.shm_bytes;
        container.limits.memory_bytes = case.memory_bytes;
        container.sysctls = case.sysctls;
        container.network = case.network;
        var diag: Diag = undefined;
        diag.reset();
        const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
        try testing.expectError(error.StartFailed, result);
        try testing.expectEqual(case.code, diag.code.?);
        const cause = diag.last_cause().?;
        const said = std.mem.indexOf(u8, cause, case.says) != null or
            std.mem.indexOf(u8, diag.causes.items[0].slice(), case.says) != null;
        if (!said) std.debug.print("case {d}: {s}\n", .{ index, cause });
        try testing.expect(said);
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expectEqual(@as(u32, 0), sim.world.written_count);
        try no_leak(&sim, &before);
    }
}

test "a sysctl value the kernel refuses is E0318, naming the key and the value" {
    // Goal: the child's write failing (EINVAL) stops the run before the command, coded.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 30);
    const before = sim_run.baseline(&sim);
    sim.world.sysctl_refused = true;
    var container = knob_spec();
    container.sysctls = &net_key;
    var diag: Diag = undefined;
    diag.reset();
    const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
    try testing.expectError(error.StartFailed, result);
    try testing.expectEqual(codes.Code.E0318, diag.code.?);
    const cause = diag.causes.items[0].slice();
    try testing.expect(std.mem.indexOf(u8, cause, "net.core.somaxconn=8192") != null);
    try testing.expect(!sim.world.processes[1].execd);
    try no_leak(&sim, &before);
}
