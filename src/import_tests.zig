//! `zbx import` through the command line, on a simulated host and disk: a Dockerfile that needs
//! no image (FROM scratch, settings only) becomes a build file; each refusal has its code and
//! writes nothing; an existing output is kept unless `--force`.

const std = @import("std");
const cli = @import("cli.zig");
const host_sim = @import("host_sim.zig");
const fs_sim = @import("store/fs_sim.zig");
const sim_run = @import("runtime/sim_run.zig");

const testing = std.testing;

const project = "/home/alice/app";
const output_path = project ++ "/zbx.build.zon";
const dockerfile_path = project ++ "/Dockerfile";

/// The simulated disk has no working directory for relative paths, so every run names its files.
const base = [_][:0]const u8{ "zbx", "import", dockerfile_path, "--context", project };

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;

fn world(seed: u64, dockerfile: []const u8) void {
    sim_run.init(&sim, seed);
    files.init(seed);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir(project, 0o755);
    files.put_file(project ++ "/Dockerfile", 0o644, dockerfile);
    sim.store_fs = &files;
    _ = sim.world.processes[0].cwd.set(project);
}

fn run(args: []const [:0]const u8) u8 {
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    var iterator: sim_run.SliceIterator = .{ .items = args };
    return cli.run_from_iterator(sim.interface(), &iterator);
}

fn expect_stderr(code: []const u8) !void {
    const stderr = sim.stderr();
    if (std.mem.indexOf(u8, stderr, code) != null) return;
    std.debug.print("STDERR: {s}\n", .{stderr});
    return error.TestUnexpectedResult;
}

const settings_only = "FROM scratch\nENV A=1\nLABEL x=y\nCMD [\"/bin/app\"]\n";

test "import writes the build file, keeps it, and --force replaces it" {
    // Goal: the output is written once, a second import refuses (E0816) and leaves it alone,
    // and `--force` replaces it. Method: a settings-only Dockerfile, three runs.
    world(1, settings_only);
    try testing.expectEqual(@as(u8, 0), run(&base));
    const first = files.content_of(output_path) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, first, "Dockerfile") != null);
    try testing.expectEqual(@as(u8, 1), run(&base));
    try expect_stderr("E0816");
    try testing.expectEqualStrings(first, files.content_of(output_path).?);
    try testing.expectEqual(@as(u8, 0), run(&(base ++ .{"--force"})));
}

test "a refusal exits 1 with its code and writes nothing" {
    // Goal: a Dockerfile zbx cannot honour is refused with the Dockerfile line and no file.
    // Method: steps on `FROM scratch` (E0811), a missing Dockerfile (E0810), a bad option value.
    world(2, "FROM scratch\nRUN true\n");
    try testing.expectEqual(@as(u8, 1), run(&base));
    try expect_stderr("E0811");
    try testing.expect(files.content_of(output_path) == null);
    const missing = project ++ "/Missing.Dockerfile";
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "import", missing }));
    try expect_stderr("E0810");
    try testing.expectEqual(@as(u8, 1), run(&(base ++ .{ "--network", "bogus" })));
    try expect_stderr("E0005");
    try testing.expect(files.content_of(output_path) == null);
}

test "an empty Dockerfile name or -o value is refused, not a crash" {
    // Goal: `zbx import ''` and `zbx import -o ''` name no file, so each is a usage refusal with
    // exit 1 (the cli fuzzer found both asserting), whose cause names the empty value and whose
    // fix fits the command. Method: each run on a world with a Dockerfile, and no file written.
    world(3, settings_only);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "import", "", "--context", project }));
    try expect_stderr("E0810");
    try expect_stderr("'' is not a path zbx can follow");
    try testing.expectEqual(@as(u8, 1), run(&(base ++ .{ "-o", "" })));
    try expect_stderr("E0005");
    try expect_stderr("-o is given an empty value, which names no file");
    try expect_stderr("zbx import -o build/zbx.build.zon");
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "state export") == null);
    try testing.expectEqual(@as(u8, 1), run(&(base ++ .{"-o"})));
    try expect_stderr("-o needs a value, and none follows it");
    try expect_stderr("zbx import -o build/zbx.build.zon");
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "state", "export", "v", "-o", "" }));
    try expect_stderr("E0005");
    try expect_stderr("-o is given an empty value, which names no file");
    try expect_stderr("zbx state export pgdata -o pgdata.tar.gz");
    try testing.expect(files.content_of(output_path) == null);
}
