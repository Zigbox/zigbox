//! A step's inputs on the disk: each must be a file or a directory inside the project
//! directory, and is refused before anything runs if it is not (docs/briefs/M7-build.md,
//! "Inputs"). An input is written as a plain relative path (`src/main.go`: no leading `/`, no
//! empty, `.` or `..` part, no trailing `/`), since it is also where the step sees it, under
//! `/src`. It is resolved with `project.resolve`, every link followed, and what it resolves to
//! must be inside the project: a link that leads out is refused naming where it leads.
//!
//! An input written with `..` or as an absolute path is resolved too, so that one that leads out
//! is refused as outside (what the user needs to know), and one that stays in is refused as not
//! plain.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("file.zig");
const project = @import("../runtime/project.zig");
const fs_mod = @import("../store/fs.zig");

const BuildFile = file_mod.BuildFile;
const Text = file_mod.Text;
const Fs = fs_mod.Fs;
const Path = project.Path;

pub const ProblemKind = enum {
    /// Not a plain relative path, though it stays in the project.
    not_plain,
    /// It resolves outside the project directory; `resolved` is where.
    outside,
    /// A part of it is not there.
    missing,
    /// A part of it cannot be looked at.
    unreadable,
    /// Its links lead round, or past `symlinks_followed_max`.
    loop,
    /// It, or what its links make of it, is longer than `path_bytes_max`.
    too_long,
    /// Not a file or a directory (`kind`).
    bad_kind,
    /// It resolves to the project directory itself, which holds the build's own state.
    whole_project,
    /// The step lists it twice, or two of its inputs overlap once resolved: the same object, or
    /// one inside the other (`src` and `src/main.go`). `other` is the earlier one.
    input_twice,
    /// A directory input holds `resolved`, a `file_kind` that is not a file, a directory or a
    /// link (found while it is imported).
    holds_bad_kind,
    /// `resolved` changed while the build read it: it went away, or was swapped for something
    /// else, between two looks.
    changed,
};

pub const Problem = struct {
    kind: ProblemKind,
    step: u8,
    input: Text,
    /// For `outside` and `bad_kind`: what the input resolved to.
    resolved: Path,
    /// For `input_twice`: the earlier input it overlaps, and room to resolve it.
    other: Text,
    other_resolved: Path,
    /// For `bad_kind`.
    file_kind: fs_mod.FileKind,
};

pub const Result = enum { ok, refused };

pub const Error = error{
    NotPlain,
    Outside,
    WholeProject,
    Missing,
    Unreadable,
    Loop,
    TooLong,
    BadKind,
};

/// Resolves one input, written `input` in the build file, against the resolved `project_path`
/// into `out`, and sets `kind` to what it is (also on `BadKind`). The next slice imports it
/// from `out`.
pub fn resolve_input(
    fs: Fs,
    project_path: []const u8,
    input: []const u8,
    out: *Path,
    kind: *fs_mod.FileKind,
) Error!void {
    assert(project_path.len > 0);
    assert(project_path[0] == '/');
    // `load.locate` refuses a project at `/`, inside which every path is.
    assert(project_path.len > 1);
    if (input.len == 0) return error.NotPlain;
    if (input.len > constants.path_bytes_max) return error.TooLong;
    project.resolve(fs, project_path, input, out) catch |err| return switch (err) {
        error.NotFound => error.Missing,
        error.Unreadable => error.Unreadable,
        error.Loop => error.Loop,
        error.TooLong => error.TooLong,
    };
    if (!project.is_inside(project_path, out.text())) return error.Outside;
    if (std.mem.eql(u8, out.text(), project_path)) return error.WholeProject;
    if (!is_plain_relative(input)) return error.NotPlain;
    const stat = fs.lstat(out.text()) catch |err| return switch (err) {
        error.NotFound => error.Missing,
        else => error.Unreadable,
    };
    // `resolve` followed every link, so what it gives is never one.
    assert(stat.kind != .symlink);
    kind.* = stat.kind;
    if (stat.kind != .file and stat.kind != .dir) return error.BadKind;
}

/// Checks every input of every step of `file`, in the file's order.
pub fn check(fs: Fs, project_path: []const u8, file: *const BuildFile, problem: *Problem) Result {
    assert(project_path.len > 0);
    for (file.steps_slice(), 0..) |*step, step_index| {
        const inputs = step.inputs.slice();
        for (inputs, 0..) |input, index| {
            const text = file.text(input);
            problem.step = @intCast(step_index);
            problem.input = input;
            const resolved = &problem.resolved;
            resolve_input(fs, project_path, text, resolved, &problem.file_kind) catch |err| {
                problem.kind = kind_of(err);
                return .refused;
            };
            assert(switch (problem.file_kind) {
                .file, .dir => true,
                else => false,
            });
            if (overlap(fs, project_path, file, inputs[0..index], problem)) |earlier| {
                problem.kind = .input_twice;
                problem.other = earlier;
                return .refused;
            }
        }
    }
    return .ok;
}

/// The earlier input that `problem.resolved` overlaps once resolved: the same path, or one
/// inside the other. Each earlier input is resolved again, into `problem.other_resolved`, to
/// keep no path per input: at most `build_step_inputs_max` squared resolutions, all cached by
/// the kernel. An earlier input resolved before, so it resolves again unless the disk changed;
/// if it no longer does, it is no overlap here, and slice 2's import refuses it.
fn overlap(
    fs: Fs,
    project_path: []const u8,
    file: *const BuildFile,
    earlier: []const Text,
    problem: *Problem,
) ?Text {
    assert(earlier.len < constants.build_step_inputs_max);
    const resolved = problem.resolved.text();
    assert(project.is_inside(project_path, resolved));
    for (earlier) |input| {
        var kind: fs_mod.FileKind = undefined;
        const other = &problem.other_resolved;
        resolve_input(fs, project_path, file.text(input), other, &kind) catch continue;
        if (project.is_inside(other.text(), resolved)) return input;
        if (project.is_inside(resolved, other.text())) return input;
    }
    return null;
}

fn kind_of(err: Error) ProblemKind {
    return switch (err) {
        error.NotPlain => .not_plain,
        error.Outside => .outside,
        error.WholeProject => .whole_project,
        error.Missing => .missing,
        error.Unreadable => .unreadable,
        error.Loop => .loop,
        error.TooLong => .too_long,
        error.BadKind => .bad_kind,
    };
}

/// `a/b`: not absolute, no empty, `.` or `..` part, no trailing `/`.
pub fn is_plain_relative(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text[0] == '/') return false;
    var parts = std.mem.splitScalar(u8, text, '/');
    while (parts.next()) |part| {
        if (part.len == 0) return false;
        if (std.mem.eql(u8, part, ".")) return false;
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

const testing = std.testing;
const SimFs = @import("../store/fs_sim.zig").SimFs;

var files: SimFs = undefined;
var test_file: BuildFile = undefined;

const proj = "/home/alice/proj";

fn tree() void {
    files.init(1);
    files.put_dir("/home", 0o755);
    files.put_dir("/home/alice", 0o755);
    files.put_dir(proj, 0o755);
    files.put_dir(proj ++ "/src", 0o755);
    files.put_file(proj ++ "/src/main.go", 0o644, "package main\n");
    files.put_file(proj ++ "/go.mod", 0o644, "module hello\n");
    files.put_file("/home/alice/secret", 0o600, "key\n");
    files.put_symlink(proj ++ "/escape", "../secret");
    files.put_symlink(proj ++ "/etc", "/etc");
    files.put_symlink(proj ++ "/inner", "src/main.go");
    files.put_symlink(proj ++ "/dangling", "nowhere");
    files.put_symlink(proj ++ "/self", "self");
    files.put_symlink(proj ++ "/here", ".");
    files.put_symlink(proj ++ "/src/up", "..");
    files.put(proj ++ "/pipe", .fifo, 0o644, .{ 0, 0 }, "");
    files.put_dir("/etc", 0o755);
}

fn input_kind(input: []const u8) Error!fs_mod.FileKind {
    var path: Path = undefined;
    var kind: fs_mod.FileKind = undefined;
    try resolve_input(files.interface(), proj, input, &path, &kind);
    return kind;
}

test "an input is a file or a directory in the project, written plainly" {
    // Goal: what is accepted, and each refusal of the disk and of the spelling. Method: a
    // simulated project with links out, in, dangling and round, and a FIFO.
    tree();
    try testing.expectEqual(fs_mod.FileKind.file, try input_kind("go.mod"));
    try testing.expectEqual(fs_mod.FileKind.dir, try input_kind("src"));
    try testing.expectEqual(fs_mod.FileKind.file, try input_kind("src/main.go"));
    try testing.expectEqual(fs_mod.FileKind.file, try input_kind("inner"));
    try testing.expectError(error.Outside, input_kind("escape"));
    try testing.expectError(error.Outside, input_kind("etc"));
    try testing.expectError(error.Outside, input_kind("../secret"));
    try testing.expectError(error.Outside, input_kind("/etc"));
    try testing.expectError(error.NotPlain, input_kind("src/../go.mod"));
    try testing.expectError(error.NotPlain, input_kind("./go.mod"));
    try testing.expectError(error.NotPlain, input_kind("src/"));
    try testing.expectError(error.NotPlain, input_kind(proj ++ "/go.mod"));
    try testing.expectError(error.NotPlain, input_kind(""));
    try testing.expectError(error.Missing, input_kind("main.go"));
    try testing.expectError(error.Missing, input_kind("dangling"));
    try testing.expectError(error.Loop, input_kind("self"));
    try testing.expectError(error.BadKind, input_kind("pipe"));
    try testing.expectError(error.WholeProject, input_kind("here"));
    try testing.expectError(error.WholeProject, input_kind("src/up"));
    try testing.expectError(error.WholeProject, input_kind("."));
    files.crashed = true; // Every call fails with EIO until restart.
    try testing.expectError(error.Unreadable, input_kind("src/main.go"));
}

fn check_inputs(comptime inputs: []const u8, problem: *Problem) !Result {
    const text = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"a\", " ++
        ".run = .{\"x\"} }, .{ .name = \"b\", .base = \"a\", .run = .{\"x\"}, .inputs = .{" ++
        inputs ++ "} } } }";
    var parse_problem: file_mod.Problem = undefined;
    const parsed = file_mod.parse(text, &test_file, &parse_problem);
    try testing.expectEqual(file_mod.ParseResult.parsed, parsed);
    return check(files.interface(), proj, &test_file, problem);
}

test "the inputs of a file are checked step by step and named when refused" {
    // Goal: `check` names the step, the input and what it resolved to. Method: a good list, a
    // link out, an input twice, a FIFO, a crash of the disk.
    tree();
    var problem: Problem = undefined;
    try testing.expectEqual(Result.ok, try check_inputs("\"go.mod\", \"src\"", &problem));
    try testing.expectEqual(Result.refused, try check_inputs("\"go.mod\", \"escape\"", &problem));
    try testing.expectEqual(ProblemKind.outside, problem.kind);
    try testing.expectEqual(@as(u8, 1), problem.step);
    try testing.expectEqualStrings("escape", test_file.text(problem.input));
    try testing.expectEqualStrings("/home/alice/secret", problem.resolved.text());
    try testing.expectEqual(Result.refused, try check_inputs("\"src\", \"src\"", &problem));
    try testing.expectEqual(ProblemKind.input_twice, problem.kind);
    try testing.expectEqualStrings("src", test_file.text(problem.other));
    try testing.expectEqual(Result.refused, try check_inputs("\"src\", \"inner\"", &problem));
    try testing.expectEqual(ProblemKind.input_twice, problem.kind);
    try testing.expectEqualStrings("inner", test_file.text(problem.input));
    try testing.expectEqualStrings("src", test_file.text(problem.other));
    try testing.expectEqual(Result.refused, try check_inputs("\"inner\", \"src\"", &problem));
    try testing.expectEqualStrings("inner", test_file.text(problem.other));
    try testing.expectEqual(Result.ok, try check_inputs("\"src\", \"go.mod\"", &problem));
    try testing.expectEqual(Result.refused, try check_inputs("\"pipe\"", &problem));
    try testing.expectEqual(ProblemKind.bad_kind, problem.kind);
    try testing.expectEqual(fs_mod.FileKind.fifo, problem.file_kind);
    files.crashed = true;
    try testing.expectEqual(Result.refused, try check_inputs("\"go.mod\"", &problem));
    try testing.expectEqual(ProblemKind.unreadable, problem.kind);
}
