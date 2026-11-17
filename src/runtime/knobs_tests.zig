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

test "E0311's limits.conf fix is in KiB for memlock and stack, and systemd's in bytes" {
    // Goal: the review of #178 found the limits.conf line in bytes, which pam_limits reads as
    // KiB, granting 1024 times what was asked. Method: a memlock one past the user's 8 MiB, and
    // a stack size that is not a whole KiB; each fix and the unit line give the asked limit in
    // the unit their reader takes, and a count (nofile) is left as it is.
    const Expect = struct {
        resource: knobs.Resource,
        hard: u64,
        login: []const u8,
        unit: []const u8,
    };
    const expects = [_]Expect{
        .{
            .resource = .memlock,
            .hard = 64 << 20,
            .login = "hard memlock 65536\"",
            .unit = "LimitMEMLOCK=67108864",
        },
        .{
            .resource = .memlock,
            .hard = (8 << 20) + 1,
            .login = "hard memlock 8193\"",
            .unit = "LimitMEMLOCK=8388609",
        },
        .{
            .resource = .nofile,
            .hard = 524289,
            .login = "hard nofile 524289\"",
            .unit = "LimitNOFILE=524289",
        },
    };
    for (expects, 0..) |expect, index| {
        var sim: HostSim = undefined;
        sim_run.init(&sim, 40 + index);
        var container = knob_spec();
        container.rlimits.set(expect.resource, .{ .soft = 0, .hard = expect.hard });
        var diag: Diag = undefined;
        diag.reset();
        const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
        try testing.expectError(error.StartFailed, result);
        try testing.expectEqual(codes.Code.E0311, diag.code.?);
        const login = diag.fixes.slice()[0].command.slice();
        if (std.mem.indexOf(u8, login, expect.login) == null) std.debug.print("{s}\n", .{login});
        try testing.expect(std.mem.indexOf(u8, login, expect.login) != null);
        var unit_found = false;
        for (diag.pairs.slice()) |*pair| {
            if (std.mem.eql(u8, pair.value.slice(), expect.unit)) unit_found = true;
        }
        try testing.expect(unit_found);
    }
}

test "a limit zbx can't read is E0312 before anything is created, not a late child failure" {
    // Goal: the review of #178 found a failed read of the user's own limit skipped, so the run
    // went on to fail in the child. Method: the sim refuses prlimit64 reads (a sandbox's
    // seccomp filter); the run is refused, nothing was spawned or written, and the cause names
    // the read and the resource.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 50);
    const before = sim_run.baseline(&sim);
    sim.world.rlimit_read_refused = true;
    var container = knob_spec();
    container.rlimits.set(.nofile, .{ .soft = 1024, .hard = 4096 });
    var diag: Diag = undefined;
    diag.reset();
    const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
    try testing.expectError(error.StartFailed, result);
    try testing.expectEqual(codes.Code.E0312, diag.code.?);
    const cause = diag.causes.items[0].slice();
    try testing.expect(std.mem.indexOf(u8, cause, "reading your nofile limit") != null);
    try testing.expect(sim.world.processes[1].state == .unused);
    try testing.expectEqual(@as(u32, 0), sim.world.written_count);
    try no_leak(&sim, &before);
}

test "a library caller's unlimited nofile is E0310, as the flag's is" {
    // Goal: the kernel never takes unlimited for nofile, so a Spec that asks for it is refused
    // with the flag's code and cause rather than an E0311 whose fix can't work.
    var sim: HostSim = undefined;
    sim_run.init(&sim, 51);
    var container = knob_spec();
    container.rlimits.set(.nofile, .{ .soft = 1024, .hard = knobs.unlimited });
    var diag: Diag = undefined;
    diag.reset();
    const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
    try testing.expectError(error.StartFailed, result);
    try testing.expectEqual(codes.Code.E0310, diag.code.?);
    const cause = diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "fs.nr_open") != null);
    try testing.expect(sim.world.processes[1].state == .unused);
}

const host_settings = @import("host_settings.zig");

/// A host with a full range of ids whose vm.max_map_count is Ubuntu's default; it has no THP.
const settings_files = sim_run.files ++ [_]host_sim.File{
    .{ .path = host_settings.HostSetting.max_map_count.path(), .content = "65530\n" },
};

const map_count_met = [_]host_settings.HostRequirement{
    .{ .setting = .max_map_count, .minimum = 65530 },
};
const map_count_unmet = [_]host_settings.HostRequirement{
    .{ .setting = .max_map_count, .minimum = 262144 },
};
const thp_any = [_]host_settings.HostRequirement{
    .{ .setting = .transparent_hugepage, .allowed = .{ .bits = 0b111 } },
};

test "--require-host met: the run starts as it would without it" {
    // Goal: the positive space of the preflight. Method: a host whose vm.max_map_count equals
    // the minimum; the command runs and the host is left as it was.
    var sim: HostSim = undefined;
    sim_run.start(&sim, 60, &settings_files);
    const before = sim_run.baseline(&sim);
    var container = knob_spec();
    container.host_requirements = &map_count_met;
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &container, .{}, handle_get(), &diag);
    try testing.expect(diag.code == null);
    try testing.expect(sim.world.processes[1].execd);
    try testing.expect(sim.world.bus.connections > 0);
    _ = run.wait(handle_get());
    try no_leak(&sim, &before);
}

test "--require-host refused (E0319, E0321): no bus, no scope, no process, nothing left" {
    // Goal: the preflight runs before the scope and any process, so a refused run leaves
    // nothing to clean up. A preflight moved after `prepare_scope` would probe the user's bus,
    // and one moved later would start a scope or spawn the child. Method: a minimum above the
    // host's value (E0319, naming the setting and both values) and a setting the host does not
    // expose (E0321); each is refused with no connection to the bus, no scope, no cgroup, no
    // process and nothing written.
    const Refused = struct {
        requirements: []const host_settings.HostRequirement,
        code: codes.Code,
        says: []const u8,
    };
    const refused_cases = [_]Refused{
        .{
            .requirements = &map_count_unmet,
            .code = .E0319,
            .says = "vm.max_map_count is 65530, needs >=262144",
        },
        .{ .requirements = &thp_any, .code = .E0321, .says = "transparent_hugepage" },
    };
    for (refused_cases, 0..) |case, index| {
        var sim: HostSim = undefined;
        sim_run.start(&sim, 61 + index, &settings_files);
        const before = sim_run.baseline(&sim);
        var container = knob_spec();
        container.limits.memory_bytes = 64 << 20; // A scoped run, with a limit to enforce.
        container.host_requirements = case.requirements;
        var diag: Diag = undefined;
        diag.reset();
        const result = run.start(sim.interface(), &container, .{}, handle_get(), &diag);
        try testing.expectError(error.StartFailed, result);
        try testing.expectEqual(case.code, diag.code.?);
        const said = std.mem.indexOf(u8, diag.headline.slice(), case.says) != null or
            std.mem.indexOf(u8, diag.last_cause().?, case.says) != null;
        if (!said) std.debug.print("case {d}: {s}\n", .{ index, diag.last_cause().? });
        try testing.expect(said);
        try testing.expectEqual(@as(u32, 0), sim.world.bus.connections);
        try testing.expectEqual(@as(u32, 0), sim.world.bus.scopes_started);
        try testing.expectEqual(@as(u32, 0), sim.world.bus.scope_count());
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expectEqual(@as(u32, 0), sim.world.written_count);
        try no_leak(&sim, &before);
    }
}
