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
    // Goal: `-f` outside the project is E0801 naming both; `build` alone looks for the file and
    // names it when it is missing; `--graph` on another command is E0004. Method: the CLI on the sim.
    world(3);
    files.put_dir("/home/alice/other", 0o755);
    files.put_file("/home/alice/other/zbx.build.zon", 0o644, file_tests.example);
    const outside = [_][:0]const u8{ "zbx", "build", "--graph", "-f", "../other/zbx.build.zon" };
    try testing.expectEqual(@as(u8, 1), run(&outside));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0801") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "outside the project") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build" }));
    // With no build file in the project, `build` looks for it like `--graph` does.
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0006") == null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "zbx.build.zon") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "ps", "--graph" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0004") != null);
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build", "--graph", "-f" }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0005") != null);
}

fn expect_stderr(needle: []const u8) !void {
    if (std.mem.indexOf(u8, sim.stderr(), needle) == null) {
        std.debug.print("STDERR: {s}\n", .{sim.stderr()});
        return error.TestUnexpectedResult;
    }
}

test "a project at / is refused, whatever the build file names" {
    // Goal: with no zbx.lock above, a build from `/` would let the file name any host path as
    // an input; it is E0801 before the file is read. Method: the working directory `/`, a build
    // file below it that names /etc/shadow, as the review's repro did.
    world(4);
    files.put_dir("/tmp", 0o755);
    files.put_dir("/tmp/x", 0o755);
    files.put_dir("/etc", 0o755);
    files.put_file("/etc/shadow", 0o600, "root:x\n");
    files.put_file("/tmp/x/root.zon", 0o644, ".{ .version = 1, .image = .{}, .steps = .{ " ++
        ".{ .name = \"a\", .base = \"x\", .run = .{\"x\"}, .inputs = .{\"etc/shadow\"} } } }");
    _ = sim.world.processes[0].cwd.set("/");
    const args = [_][:0]const u8{ "zbx", "build", "--graph", "-f", "tmp/x/root.zon" };
    try testing.expectEqual(@as(u8, 1), run(&args));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try expect_stderr("ZBX-E0801");
    try expect_stderr("the project directory is /");
    try expect_stderr("create zbx.lock there");
}

test "-f given twice, and -f through a link out, are refused naming what was given" {
    // Goal: a second -f is its own one-line refusal; a -f link that leads out of the project
    // names the given path and where it led. Method: the CLI on the sim.
    world(5);
    const twice = [_][:0]const u8{ "zbx", "build", "--graph", "-f", "a.zon", "-f", "b.zon" };
    try testing.expectEqual(@as(u8, 1), run(&twice));
    try expect_stderr("ZBX-E0003");
    try expect_stderr("-f given twice");
    files.put_dir("/home/alice/other", 0o755);
    files.put_file("/home/alice/other/real.zon", 0o644, file_tests.example);
    files.put_symlink(project ++ "/link.zon", "../other/real.zon");
    try testing.expectEqual(@as(u8, 1), run(&.{ "zbx", "build", "--graph", "-f", "link.zon" }));
    try expect_stderr("ZBX-E0801");
    try expect_stderr("'link.zon' leads to '/home/alice/other/real.zon', outside the project");
}

test "an input that names the project directory, or overlaps another, is refused" {
    // Goal: `ln -s . self2` listed as an input is E0803 (the whole project); two inputs that
    // resolve to one object, or one inside the other, are E0803 naming both. Method: the CLI on
    // the sim with links to the project and to a file.
    world(6);
    files.put_symlink(project ++ "/self2", ".");
    files.put_symlink(project ++ "/again.go", "main.go");
    files.put_dir(project ++ "/src", 0o755);
    files.put_file(project ++ "/src/a.go", 0o644, "package a\n");
    const head = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"x\", " ++
        ".run = .{\"x\"}, .inputs = .{";
    overwrite(build_path, head ++ "\"self2\"} } } }");
    try expect_refused("ZBX-E0803", "input \"self2\" of step \"a\" names the whole project");
    overwrite(build_path, head ++ "\"main.go\", \"again.go\"} } } }");
    try expect_refused("ZBX-E0803", "input \"again.go\" of step \"a\" overlaps input \"main.go\"");
    overwrite(build_path, head ++ "\"src/a.go\", \"src\"} } } }");
    try expect_refused("ZBX-E0803", "input \"src\" of step \"a\" overlaps input \"src/a.go\"");
    overwrite(build_path, head ++ "\"src\", \"src\"} } } }");
    try expect_refused("ZBX-E0803", "input \"src\" of step \"a\" overlaps input \"src\"");
    overwrite(build_path, head ++ "\"src\", \"main.go\"} } } }");
    try testing.expectEqual(@as(u8, 0), run(&.{ "zbx", "build", "--graph" }));
}
