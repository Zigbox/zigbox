//! `--mount` in a run, against the simulator (docs/briefs/M6b-dev-loop.md, "Writable mounts"):
//! the project directory and the rule that a writable mount stays inside it (`../other`, a
//! symbolic link that points out, `/`), the user who must be root, the plan's steps, the record
//! and the JSON. The VM shows the kernel agrees (a server serving the mounted directory, a file
//! written inside owned by the host user); these tests show the code does what its rules say on
//! every path, and refuses before anything is made.

const std = @import("std");
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const host_sim = @import("../host_sim.zig");
const Diag = @import("../diag/diag.zig").Diag;
const mounts_mod = @import("mounts.zig");
const plan_mod = @import("plan.zig");
const records = @import("records.zig");
const run = @import("run.zig");
const sim_run = @import("sim_run.zig");
const spec_mod = @import("spec.zig");
const SimFs = @import("../store/fs_sim.zig").SimFs;
const FileKind = @import("../store/fs.zig").FileKind;

const HostSim = host_sim.HostSim;
const MountKind = @import("../host.zig").MountKind;
const testing = std.testing;

const rootfs = sim_run.rootfs_path;
const project = "/home/alice/proj";
const outside = "/home/alice/other";

var files: SimFs = undefined;
var handle: run.Handle = undefined;

/// A host with a project (its lock, a site with a page, a link that goes out, a link that
/// stays in, a socket), a directory beside it, and the container's model of the host's paths.
fn setup(sim: *HostSim, seed: u64) void {
    sim_run.init(sim, seed);
    files.init(seed);
    sim.store_fs = &files;
    for ([_][]const u8{
        "/home",
        "/home/alice",
        project,
        project ++ "/site",
        project ++ "/site/deep",
        outside,
        "/etc",
    }) |directory| files.put_dir(directory, 0o755);
    files.put_file(project ++ "/zbx.lock", 0o644, "");
    files.put_file(project ++ "/site/index.html", 0o644, "hello\n");
    files.put_file(outside ++ "/secret", 0o644, "x");
    files.put_symlink(project ++ "/escape", "/etc");
    files.put_symlink(project ++ "/up", "../other");
    files.put_symlink(project ++ "/in", "site");
    files.put_symlink(project ++ "/site/out", "../../other");
    files.put(project ++ "/socket", .socket, 0o644, .{ 0, 0 }, "");
    _ = sim.world.processes[0].cwd.set(project);
    sim.world.add_node(project ++ "/site", .dir);
    sim.world.add_node(project ++ "/site/index.html", .file);
    sim.world.add_node(project, .dir);
    sim_run.add_mount_sources(sim);
}

fn run_line(sim: *HostSim, words: []const [:0]const u8) u8 {
    var items: [64][:0]const u8 = undefined;
    items[0] = "zbx";
    for (words, 1..) |word, index| items[index] = word;
    return sim_run.run_cli(sim, items[0 .. words.len + 1]);
}

fn mount_run(comptime middle: []const [:0]const u8) []const [:0]const u8 {
    const head = [_][:0]const u8{ "run", "--rootfs", rootfs, "--name", "w-1" };
    return &(head ++ middle[0..middle.len].* ++ [_][:0]const u8{ "--", "sh" });
}

/// A run of `sh` with the one `--mount` value `source`.
fn run_source(sim: *HostSim, source: [:0]const u8) u8 {
    const words = [_][:0]const u8{
        "run", "--rootfs", rootfs, "--name", "w-1", "--mount", source, "--", "sh",
    };
    return run_line(sim, &words);
}

/// A start that is refused: the diagnostic's code, and nothing made.
fn refused_code(sim: *HostSim, container: *const spec_mod.Spec) !?codes.Code {
    var diag: Diag = undefined;
    diag.reset();
    const started = run.start(sim.interface(), container, .{}, &handle, &diag);
    try testing.expectError(error.StartFailed, started);
    return diag.code;
}

fn record_text(sim: *const HostSim) ?[]const u8 {
    return sim.world.read_written(sim_run.runs_path ++ "/w-1.zon");
}

test "a --mount of the project's site is bound writable where the container reads its path" {
    // Goal: the success path. Method: a run mounting a relative directory; the container's
    // table has a bind at the target that was never made read-only, the stage is gone, nothing
    // leaked, and the record keeps the resolved path and the user.
    var sim: HostSim = undefined;
    setup(&sim, 1);
    const before = sim_run.baseline(&sim);
    try testing.expectEqual(@as(u8, 0), run_line(&sim, mount_run(&.{ "--mount", "site:/srv" })));
    try testing.expectEqual(@as(usize, 0), sim.stderr().len);
    if (sim_run.leak(&sim, &before)) |problem| {
        std.debug.print("leak: {s}\n", .{problem});
        return error.TestUnexpectedResult;
    }
    const table = &sim.world.tables[sim.world.processes[1].table];
    const at = table.find(rootfs ++ "/srv").?;
    try testing.expectEqual(@as(?MountKind, .bind_tree), table.mounts[at].kind);
    try testing.expect(!table.mounts[at].read_only);
    try testing.expect(sim.world.find_node(rootfs ++ "/dev/.zbx-mount-0") == null);
    var parsed: records.Parsed = undefined;
    try records.parse(record_text(&sim).?, &parsed);
    try testing.expectEqual(@as(u8, 1), parsed.mounts_count);
    try testing.expectEqual(mounts_mod.Kind.mount, parsed.mount_at(0).kind);
    try testing.expectEqualStrings(project ++ "/site", parsed.mount_at(0).source);
    try testing.expectEqualStrings("/srv", parsed.mount_at(0).target);
    try testing.expectEqual(@as(?spec_mod.User, .{ .uid = 0, .gid = 0 }), parsed.user);
}

test "a --mount of a file, and the project itself, are bound writable too" {
    // Goal: a file or the project directory is a valid source. Method: the page as a file, the
    // project as `.`, and a link that stays inside (`in` is `site`).
    var sim: HostSim = undefined;
    setup(&sim, 2);
    const words = mount_run(&.{
        "--mount", "site/index.html:/srv/index.html", "--mount", ".:/work", "--mount", "in:/in",
    });
    try testing.expectEqual(@as(u8, 0), run_line(&sim, words));
    const table = &sim.world.tables[sim.world.processes[1].table];
    const page = table.find(rootfs ++ "/srv/index.html").?;
    try testing.expectEqual(@as(?MountKind, .bind_file), table.mounts[page].kind);
    try testing.expect(!table.mounts[page].read_only);
    try testing.expect(!table.mounts[table.find(rootfs ++ "/work").?].read_only);
    var parsed: records.Parsed = undefined;
    try records.parse(record_text(&sim).?, &parsed);
    try testing.expectEqualStrings(project ++ "/site/index.html", parsed.mount_at(0).source);
    try testing.expectEqualStrings(project, parsed.mount_at(1).source);
    try testing.expectEqualStrings(project ++ "/site", parsed.mount_at(2).source);
}

test "outside the project is refused with the project and the rule, before anything is made" {
    // Goal: the guardrail. Method: `../other`, a link in the project that points to /etc, one
    // that goes up and out, one two levels deep, an absolute path outside, and `/`; each is
    // E0212 naming the project directory, exit 125, no child, no record, nothing leaked.
    const sources = [_][:0]const u8{
        "../../alice/other:/x",
        "../other:/x",
        "escape:/x",
        "up:/x",
        "site/out:/x",
        "site/out/secret:/x",
        "escape/hosts:/x",
        "/etc:/x",
        "/home/alice:/x",
        "/:/x",
        "..:/x",
    };
    for (sources) |source| {
        var sim: HostSim = undefined;
        setup(&sim, 3);
        files.put_file("/etc/hosts", 0o644, "");
        const before = sim_run.baseline(&sim);
        try testing.expectEqual(@as(u8, 125), run_source(&sim, source));
        if (!std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0212]")) {
            std.debug.print("source {s}: {s}\n", .{ source, sim.stderr() });
            return error.TestUnexpectedResult;
        }
        try testing.expect(std.mem.indexOf(u8, sim.stderr(), project) != null);
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expect(record_text(&sim) == null);
        try testing.expect(sim_run.leak(&sim, &before) == null);
    }
}

test "the project is the directory of the nearest zbx.lock, else the working directory" {
    // Goal: found as `zbx run` finds the lock. Method: from a subdirectory of the project a
    // mount of `..` is the project and allowed; from a directory with no lock above it, `..`
    // is outside; from the root with no lock, every writable mount is refused.
    var sim: HostSim = undefined;
    setup(&sim, 4);
    _ = sim.world.processes[0].cwd.set(project ++ "/site/deep");
    sim.world.add_node(project ++ "/site/deep", .dir);
    try testing.expectEqual(@as(u8, 0), run_line(&sim, mount_run(&.{ "--mount", "../..:/p" })));
    var parsed: records.Parsed = undefined;
    try records.parse(record_text(&sim).?, &parsed);
    try testing.expectEqualStrings(project, parsed.mount_at(0).source);
    setup(&sim, 5);
    _ = sim.world.processes[0].cwd.set(outside);
    sim.world.add_node(outside, .dir);
    try testing.expectEqual(@as(u8, 125), run_line(&sim, mount_run(&.{ "--mount", "..:/p" })));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0212]"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "/home/alice/other") != null);
    try testing.expectEqual(@as(u8, 0), run_line(&sim, mount_run(&.{ "--mount", ".:/p" })));
    setup(&sim, 6);
    _ = sim.world.processes[0].cwd.set("/");
    try testing.expectEqual(@as(u8, 125), run_line(&sim, mount_run(&.{ "--mount", "etc:/p" })));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0212]"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "project directory is /") != null);
}

test "a source that is missing, of another kind, or a loop is E0214 and is never made" {
    // Goal: it must exist and be a directory or a regular file. Method: a missing name, a name
    // below a file, a socket, and a link to itself.
    files.init(7);
    const cases = [_][:0]const u8{ "missing:/x", "site/index.html/x:/x", "socket:/x", "loop:/x" };
    for (cases) |source| {
        var sim: HostSim = undefined;
        setup(&sim, 7);
        files.put_symlink(project ++ "/loop", "loop");
        try testing.expectEqual(@as(u8, 125), run_source(&sim, source));
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0214]"));
        try testing.expectEqual(@as(?FileKind, null), files.kind_of(project ++ "/missing"));
        try testing.expect(sim.world.processes[1].state == .unused);
    }
}

test "the value is held to the shared rules: E0014, E0013, and the count" {
    // Goal: the target rules and the count are --bind's. Method: a value with no colon, a
    // target over /proc, two mounts on one path, one inside the other, and nine mounts.
    const Case = struct { words: []const [:0]const u8, code: []const u8 };
    const cases = [_]Case{
        .{ .words = mount_run(&.{ "--mount", "site" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", ":/x" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", "site:x" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", "site:/proc/x" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", "a b:/x" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", "site:/a/../b" }), .code = "E0014" },
        .{ .words = mount_run(&.{ "--mount", "site:/x", "--mount", ".:/x" }), .code = "E0013" },
        .{ .words = mount_run(&.{ "--mount", "site:/x", "--tmpfs", "/x/y" }), .code = "E0013" },
        .{
            .words = mount_run(&.{ "--bind", "/srv/data:/x", "--mount", "site:/x" }),
            .code = "E0013",
        },
    };
    for (cases) |case| {
        var sim: HostSim = undefined;
        setup(&sim, 8);
        try testing.expectEqual(@as(u8, 125), run_line(&sim, case.words));
        var wanted: [16]u8 = undefined;
        const format = "error[ZBX-{s}]";
        const header = std.fmt.bufPrint(&wanted, format, .{case.code}) catch unreachable; // Short.
        try testing.expect(std.mem.startsWith(u8, sim.stderr(), header));
        try testing.expect(sim.world.processes[1].state == .unused);
    }
    var sim: HostSim = undefined;
    setup(&sim, 9);
    var words: [32][:0]const u8 = undefined;
    const targets = [_][:0]const u8{
        "/t0", "/t1", "/t2", "/t3", "/t4", "/t5", "/t6", "/t7", "/t8",
    };
    const head = [_][:0]const u8{ "run", "--rootfs", rootfs, "--name", "w-1" };
    for (head, 0..) |word, at| words[at] = word;
    // Nine distinct targets: "site:/tN" values.
    var values: [9][16]u8 = undefined;
    var count: usize = 5;
    for (targets, 0..) |target, at| {
        const format = "site:{s}";
        // Cannot fail: a short value in sixteen bytes.
        const value = std.fmt.bufPrintSentinel(&values[at], format, .{target}, 0) catch unreachable;
        words[count] = "--mount";
        words[count + 1] = value;
        count += 2;
    }
    words[count] = "--";
    words[count + 1] = "sh";
    try testing.expectEqual(@as(u8, 125), run_line(&sim, words[0 .. count + 2]));
    try testing.expect(std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0013]"));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "--mount") != null);
}

test "the user must be root, user and group, or the run is refused before it is made" {
    // Goal: no file owned by a subordinate id lands in the project. Method: the library's start
    // with a user of 1000:1000, 0:1000 and 1000:0 is E0213 (the ids and the name in the message,
    // both fixes); root as null and as 0:0 starts; a read-only --bind is fine for any user.
    var sim: HostSim = undefined;
    const sources = [_]mounts_mod.Mount{
        .{ .kind = .mount, .source = "site", .target = "/srv", .size_bytes = 0 },
    };
    const refused = [_]spec_mod.User{
        .{ .uid = 1000, .gid = 1000 },
        .{ .uid = 0, .gid = 1000 },
        .{ .uid = 1000, .gid = 0 },
    };
    for (refused) |user| {
        setup(&sim, 10);
        const before = sim_run.baseline(&sim);
        var diag: Diag = undefined;
        diag.reset();
        const container: spec_mod.Spec = .{
            .rootfs = rootfs,
            .name = "w-1",
            .command = &.{"/bin/sh"},
            .mounts = &sources,
            .user = user,
            .user_text = "app:staff",
        };
        try testing.expectEqual(@as(?codes.Code, .E0213), try refused_code(&sim, &container));
        try testing.expect(sim.world.processes[1].state == .unused);
        try testing.expect(record_text(&sim) == null);
        try testing.expect(sim_run.leak(&sim, &before) == null);
    }
    const allowed = [_]?spec_mod.User{ null, .{ .uid = 0, .gid = 0 } };
    for (allowed) |user| {
        setup(&sim, 11);
        var diag: Diag = undefined;
        diag.reset();
        const container: spec_mod.Spec = .{
            .rootfs = rootfs,
            .name = "w-1",
            .command = &.{"/bin/sh"},
            .mounts = &sources,
            .user = user,
        };
        try run.start(sim.interface(), &container, .{}, &handle, &diag);
        _ = run.wait(&handle);
        try testing.expectEqual(@as(?codes.Code, null), diag.code);
    }
    // A bind needs no root: the container's user is whatever the image says.
    setup(&sim, 12);
    var diag: Diag = undefined;
    diag.reset();
    const bind = [_]mounts_mod.Mount{
        .{ .kind = .bind, .source = "/srv/data", .target = "/srv", .size_bytes = 0 },
    };
    const container: spec_mod.Spec = .{
        .rootfs = rootfs,
        .name = "w-1",
        .command = &.{"/bin/sh"},
        .mounts = &bind,
        .user = .{ .uid = 1000, .gid = 1000 },
    };
    try run.start(sim.interface(), &container, .{}, &handle, &diag);
    _ = run.wait(&handle);
}

test "a library caller's project is the one it names, and its relative source is resolved" {
    // Goal: Spec.project overrides the nearest lock. Method: the project named as the site
    // directory, from a working directory elsewhere: `index.html` is inside, `../other` is not.
    var sim: HostSim = undefined;
    setup(&sim, 13);
    _ = sim.world.processes[0].cwd.set(project ++ "/site");
    const inside = [_]mounts_mod.Mount{
        .{ .kind = .mount, .source = "index.html", .target = "/i", .size_bytes = 0 },
    };
    const container: spec_mod.Spec = .{
        .rootfs = rootfs,
        .name = "w-1",
        .command = &.{"/bin/sh"},
        .mounts = &inside,
        .project = project ++ "/site",
    };
    var diag: Diag = undefined;
    diag.reset();
    try run.start(sim.interface(), &container, .{}, &handle, &diag);
    _ = run.wait(&handle);
    try testing.expectEqualStrings(project ++ "/site/index.html", handle.mounts[0].source);
    setup(&sim, 14);
    _ = sim.world.processes[0].cwd.set(project ++ "/site");
    const out = [_]mounts_mod.Mount{
        .{ .kind = .mount, .source = "../site/../up", .target = "/i", .size_bytes = 0 },
    };
    var again = container;
    again.mounts = &out;
    try testing.expectEqual(@as(?codes.Code, .E0212), try refused_code(&sim, &again));
}

test "the steps of a writable mount: staged and bound, then moved; no read-only remount" {
    // Goal: the plan's order and count. Method: one writable directory and one file.
    var plan: plan_mod.Plan = undefined;
    const inputs = [_]plan_mod.MountInput{
        .{ .shape = .mount_dir, .source = "/p/site", .target = "/srv", .size_bytes = 0 },
        .{ .shape = .mount_file, .source = "/p/a", .target = "/etc/a", .size_bytes = 0 },
    };
    plan.build(&.{
        .rootfs = "/srv/alpine",
        .name = "w-1",
        .command = &.{"/bin/sh"},
        .term = null,
        .uid = 1000,
        .gid = 1000,
        .mapping = .single,
        .mounts = &inputs,
    });
    var order: [16]plan_mod.Kind = undefined;
    var count: usize = 0;
    for (plan.steps[0..plan.count]) |step| {
        if (!plan_mod.is_mount(step.kind)) continue;
        order[count] = step.kind;
        count += 1;
    }
    const K = plan_mod.Kind;
    const expected = [_]K{
        .make_mount_stage_dir,    .bind_mount_dir,         .make_mount_stage_file,
        .bind_mount_file,         .make_mount_target_dir,  .move_mount,
        .remove_mount_stage_dir,  .make_mount_target_file, .move_mount,
        .remove_mount_stage_file,
    };
    try testing.expectEqualSlices(K, &expected, order[0..count]);
    try testing.expectEqual(plan.steps_expected(), plan.count);
    try testing.expectEqual(@as(u32, 5), plan_mod.mount_steps_writable);
}

test "a mount step the kernel refuses is one coded error, E0215, and starts nothing" {
    // Goal: E0215 for each step of a --mount. Method: fail every step in turn, one run each;
    // the runs that end in E0215 are the writable mount's five steps, and each leaves nothing.
    var sim: HostSim = undefined;
    var tried: u32 = 0;
    for (0..constants.plan_steps_max) |index| {
        setup(&sim, 15);
        const before = sim_run.baseline(&sim);
        sim.faults.fail_step = @intCast(index);
        sim.faults.fail_step_errno = 13;
        const code = run_line(&sim, mount_run(&.{ "--mount", "site:/srv" }));
        if (!std.mem.startsWith(u8, sim.stderr(), "error[ZBX-E0215]")) continue;
        try testing.expectEqual(@as(u8, 125), code);
        try testing.expect(sim_run.leak(&sim, &before) == null);
        tried += 1;
    }
    try testing.expectEqual(plan_mod.mount_steps_writable, tried);
}

test "run --output json lists each writable mount and the user; ps does too" {
    // Goal: the additive members, from the run and from the record. Method: a detached run and
    // a foreground one with a --mount and a --bind (only the --mount is listed), then ps.
    var sim: HostSim = undefined;
    setup(&sim, 16);
    const words = mount_run(&.{
        "--output", "json", "--mount", "site:/srv", "--bind", "/srv/data:/d",
    });
    try testing.expectEqual(@as(u8, 0), run_line(&sim, words));
    const listed = "\"writable_mounts\":[{\"host\":\"" ++ project ++
        "/site\",\"target\":\"/srv\"}],\"user\":{\"uid\":0,\"gid\":0}}";
    const tail = listed ++ ",\"ran\"";
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), tail) != null);
    try testing.expectEqual(@as(u8, 0), run_line(&sim, &.{ "ps", "--all", "--output", "json" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), listed) != null);
}
