//! `zbx build --graph` through the command line, on a simulated host and disk: the graph of a
//! good project as text and as `zbx.build_graph/1`, and each kind of refusal with its code.

const std = @import("std");
const cli = @import("cli.zig");
const host_sim = @import("host_sim.zig");
const fs_sim = @import("store/fs_sim.zig");
const sim_run = @import("runtime/sim_run.zig");
const test_util = @import("test_util.zig");
const file_tests = @import("build/file_tests.zig");

const testing = std.testing;

const project = "/home/alice/hello";
const build_path = project ++ "/zbx.build.zon";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;

/// The demo project's files, the brief's build file, and the working directory in it.
fn world(seed: u64) void {
    sim_run.init(&sim, seed);
    files.init(seed);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir(project, 0o755);
    files.put_file(project ++ "/zbx.lock", 0o644, ".{ .version = 1, .images = .{} }\n");
    files.put_file(project ++ "/go.mod", 0o644, "module hello\n");
    files.put_file(project ++ "/main.go", 0o644, "package main\n");
    files.put_file(project ++ "/VERSION", 0o644, "1.0.0\n");
    files.put_file(project ++ "/LICENSE", 0o644, "MIT\n");
    files.put_file(build_path, 0o644, file_tests.example);
    sim.store_fs = &files;
    _ = sim.world.processes[0].cwd.set(project);
}

fn run(args: []const [:0]const u8) u8 {
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    var iterator: sim_run.SliceIterator = .{ .items = args };
    return cli.run_from_iterator(sim.interface(), &iterator);
}

fn overwrite(path: []const u8, text: []const u8) void {
    files.remove_path(path);
    files.put_file(path, 0o644, text);
}

fn expect_refused(code: []const u8, needle: []const u8) !void {
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build", "--graph" }));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    const stderr = sim.stderr();
    if (std.mem.indexOf(u8, stderr, code) == null or std.mem.indexOf(u8, stderr, needle) == null) {
        std.debug.print("STDERR: {s}\n", .{stderr});
        return error.TestUnexpectedResult;
    }
}

test "build --graph prints the steps in order, then the image, as text and as JSON" {
    // Goal: the brief's example graph, exactly; the JSON form is valid and has the same nodes in
    // the same order, and every edge. Method: the brief's project on a simulated disk.
    world(1);
    try testing.expectEqual(@as(u8, 0), run(&.{ "zbx", "build", "--graph" }));
    try testing.expectEqualStrings(@embedFile("testdata/build_graph.stdout.txt"), sim.stdout());
    try testing.expectEqual(@as(u8, 0), run(&.{ "zbx", "--output", "json", "build", "--graph" }));
    try testing.expectEqualStrings(@embedFile("testdata/build_graph.json.txt"), sim.stdout());
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    // `-f` names the same file from the working directory.
    const named = run(&.{ "zbx", "build", "--graph", "-f", "zbx.build.zon" });
    try testing.expectEqual(@as(u8, 0), named);
    try testing.expectEqualStrings(@embedFile("testdata/build_graph.stdout.txt"), sim.stdout());
}

test "build --graph refuses a file that cannot be read, parsed, ordered or have its inputs" {
    // Goal: each stage's refusal is its code, naming the file, the place and what is wrong, and
    // prints nothing on stdout. Method: one damage per stage on the brief's project.
    world(2);
    files.remove_path(build_path);
    try expect_refused("ZBX-E0801", "'zbx.build.zon' is not there");
    files.put_file(build_path, 0o644, ".{ .version = 1, .steps = .{}, .image = .{}, .colour = 1 }");
    try expect_refused("ZBX-E0801", "line 1, column 46: the file has no field .colour");
    overwrite(build_path, ".{ .version = 1, .image = .{}, .steps = .{ " ++
        ".{ .name = \"a\", .base = \"x\", .run = .{\"x\"}, .needs = .{\"b\"} }, " ++
        ".{ .name = \"b\", .base = \"x\", .run = .{\"x\"}, .needs = .{\"a\"} } } }");
    try expect_refused("ZBX-E0802", "the steps need each other round: a");
    overwrite(build_path, ".{ .version = 1, .image = .{ .config = .{ .user = \"root\" } }, " ++
        ".steps = .{} }");
    try expect_refused("ZBX-E0807", "image.config .user \"root\"");
    files.put_file("/home/alice/secret", 0o600, "key\n");
    files.put_symlink(project ++ "/escape", "../secret");
    overwrite(build_path, ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", " ++
        ".base = \"x\", .run = .{\"x\"}, .inputs = .{\"escape\"} } } }");
    try expect_refused("ZBX-E0803", "resolves to '/home/alice/secret', outside");
    overwrite(build_path, ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", " ++
        ".base = \"x\", .run = .{\"x\"}, .inputs = .{\"nowhere.go\"} } } }");
    try expect_refused("ZBX-E0803", "input \"nowhere.go\" of step \"a\" is not there");
}

test "build -f must name a file inside the project, and build alone says what it does" {
    // Goal: `-f` outside the project is E0801 naming both; `build` without `--graph` is E0006
    // with the --graph fix; `--graph` on another command is E0004. Method: the CLI on the sim.
    world(3);
    files.put_dir("/home/alice/other", 0o755);
    files.put_file("/home/alice/other/zbx.build.zon", 0o644, file_tests.example);
    const outside = [_][:0]const u8{ "zbx", "build", "--graph", "-f", "../other/zbx.build.zon" };
    try testing.expectEqual(@as(u8, 1), run(&outside));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0801") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "outside the project") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0006") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "zbx build --graph") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "ps", "--graph" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0004") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build", "--graph", "-f" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0005") != null);
}
