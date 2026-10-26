//! Choosing how the container's ids are mapped: the full range through the setuid helpers when
//! this host has the ranges and the helpers, else the single-id map and a warning (ZBX-W0201).
//!
//! The answer is the doctor's own (`doctor.subid_answer`, the subid check of `zbx doctor`), so
//! `zbx run` and `zbx doctor` cannot disagree about whether a full map is possible, and the
//! warning's fix is the one the doctor prints for ZBX-E0105.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const doctor = @import("../doctor.zig");
const host_mod = @import("../host.zig");
const Diag = @import("../diag/diag.zig").Diag;
const plan_mod = @import("plan.zig");

pub const Choice = struct {
    mapping: plan_mod.Mapping,
    /// True if the single-id map was chosen for want of a full one; `warning` says why.
    warned: bool,
    warning: Diag,
};

/// Fills `choice`. Never fails: a host that cannot give a full map gets the single-id map.
pub fn choose(host: host_mod.Host, facts: *doctor.Facts, choice: *Choice) void {
    var answer: doctor.SubidAnswer = undefined;
    doctor.subid_answer(host, facts, &answer);
    choice.warning.reset();
    if (answer.usable) {
        choice.warned = false;
        choice.mapping = .{ .full = .{
            .newuidmap = answer.newuidmap,
            .newgidmap = answer.newgidmap,
            .uid_start = answer.uid_start,
            .gid_start = answer.gid_start,
        } };
        assert(answer.newuidmap.len > 0);
        assert(answer.diag.code == null);
        return;
    }
    choice.warned = true;
    choice.mapping = .single;
    describe_fallback(&choice.warning, &answer.diag);
    assert(choice.warning.code.? == .W0201);
    assert(choice.warning.fixes.count > 0);
}

/// The warning: what the container gets instead, then the doctor's reason (its newest cause,
/// which is what default output shows) and its fixes.
fn describe_fallback(warning: *Diag, reason: *const Diag) void {
    assert(warning.code == null);
    assert(reason.code != null);
    warning.raise(.W0201);
    warning.while_("choosing the container's id map", .{});
    warning.cause("the container will map only its root, to your own id; " ++
        "other ids will not exist inside it", .{});
    if (reason.last_cause()) |cause| warning.cause("{s}", .{cause});
    for (reason.fixes.slice()) |fix| {
        warning.fix(.{ .sentence = fix.sentence.slice(), .command = fix.command.slice() });
    }
    // The doctor always gives a fix; if that ever changed, the warning still points at it.
    if (warning.fixes.count == 0) {
        warning.fix(.{ .sentence = "see what is missing:", .command = "zbx doctor" });
    }
    assert(warning.causes.count >= 1);
}

/// The tests run one at a time, so one set of facts serves them all.
var test_facts: doctor.Facts = undefined;

const testing = std.testing;
const HostSim = @import("../host_sim.zig").HostSim;
const fixtures = @import("../doctor_fixtures.zig");

test "a host with ranges and privileged helpers gets the full map, from the first range" {
    // Goal: the start of the range and the helpers' paths come from the files and the stat, not
    // from constants. Method: the stock Ubuntu fixture (alice, range at 100000).
    const fixture = fixtures.find("ubuntu_2404").?;
    var sim: HostSim = undefined;
    sim.init(1, fixture.files);
    fixture.apply(&sim);
    var choice: Choice = undefined;
    choose(sim.interface(), &test_facts, &choice);
    try testing.expect(!choice.warned);
    const full = choice.mapping.full;
    try testing.expectEqual(@as(u32, 100000), full.uid_start);
    try testing.expectEqual(@as(u32, 100000), full.gid_start);
    try testing.expectEqualStrings("/usr/bin/newuidmap", full.newuidmap);
    try testing.expectEqualStrings("/usr/bin/newgidmap", full.newgidmap);
    try testing.expectEqual(@as(u32, 0), sim.open_count());
}

test "a host without a range or a helper gets the single-id map and one warning with the fix" {
    // Goal: every way the subid check fails is a fallback, never an error, and the warning's
    // fix is the doctor's. Method: three fixtures that fail it differently.
    const names = [_][]const u8{
        "subid_missing_entry",
        "newuidmap_missing",
        "container_cgroup_v1",
    };
    for (names) |name| {
        const fixture = fixtures.find(name).?;
        var sim: HostSim = undefined;
        sim.init(1, fixture.files);
        fixture.apply(&sim);
        var choice: Choice = undefined;
        choose(sim.interface(), &test_facts, &choice);
        try testing.expect(choice.warned);
        try testing.expect(choice.mapping == .single);
        try testing.expectEqual(
            @as(@import("../diag/codes.zig").Code, .W0201),
            choice.warning.code.?,
        );
        try testing.expect(choice.warning.fixes.count > 0);
        try testing.expectEqual(@as(u32, 0), sim.open_count());
    }
}
