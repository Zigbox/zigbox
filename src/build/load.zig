//! Reading a project's build file and checking all of it that can be checked without running
//! anything: the file's grammar and values (`file.zig`), its graph (`graph.zig`) and its inputs
//! on the disk (`inputs.zig`). `zbx build --graph` stops here; a build goes on from here.
//!
//! The file is `zbx.build.zon` in the project directory (`project.directory`), or `-f PATH`:
//! resolved from the working directory with every link followed, and refused unless it is
//! inside the project directory, since every path in it is the project's.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const project = @import("../runtime/project.zig");
const fs_mod = @import("../store/fs.zig");
const file_mod = @import("file.zig");
const graph_mod = @import("graph.zig");
const inputs_mod = @import("inputs.zig");
const diagnose = @import("diagnose.zig");
const Diag = @import("../diag/diag.zig").Diag;

const Host = host_mod.Host;
const Fs = fs_mod.Fs;
const Path = project.Path;

pub const Error = error{Failed};

/// Everything a loaded build file is: the caller's, since it is too big for the stack.
pub const Workspace = struct {
    project: Path,
    /// The build file, resolved.
    path: Path,
    text: [constants.build_file_bytes_max]u8,
    text_len: u32,
    file: file_mod.BuildFile,
    graph: graph_mod.Graph,
    parse_problem: file_mod.Problem,
    graph_problem: graph_mod.Problem,
    input_problem: inputs_mod.Problem,

    /// The build file's path as the project sees it: `zbx.build.zon`, `build/other.zon`.
    pub fn shown(workspace: *const Workspace) []const u8 {
        return shown_path(workspace.project.text(), workspace.path.text());
    }
};

/// Loads and checks the build file; `given` is `-f`'s value, empty for the default. A refusal
/// is in `diag`.
pub fn load(host: Host, fs: Fs, given: []const u8, workspace: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    assert(given.len <= constants.arg_bytes_max);
    try locate(host, fs, given, workspace, diag);
    const text = try read(fs, workspace, diag);
    const file = &workspace.file;
    if (file_mod.parse(text, file, &workspace.parse_problem) == .refused) {
        diagnose.parse_problem(diag, workspace.shown(), &workspace.parse_problem);
        return error.Failed;
    }
    if (graph_mod.order(file, &workspace.graph, &workspace.graph_problem) == .refused) {
        diagnose.graph_problem(diag, workspace.shown(), file, &workspace.graph_problem);
        return error.Failed;
    }
    const directory = workspace.project.text();
    if (inputs_mod.check(fs, directory, file, &workspace.input_problem) == .refused) {
        diagnose.input_problem(diag, directory, file, &workspace.input_problem);
        return error.Failed;
    }
    assert(workspace.graph.count == file.steps_count);
    assert(diag.code == null);
}

/// The project directory and the build file in it, both resolved.
fn locate(host: Host, fs: Fs, given: []const u8, workspace: *Workspace, diag: *Diag) Error!void {
    assert(diag.code == null);
    const shown_given = if (given.len > 0) given else file_mod.file_name;
    project.directory(host, fs, "", &workspace.project) catch {
        diagnose.read_failure(diag, shown_given, "", .no_project);
        return error.Failed;
    };
    const directory = workspace.project.text();
    assert(directory[0] == '/');
    var base_buffer: [constants.path_bytes_max + 1]u8 = undefined;
    const base = if (given.len > 0)
        host.working_directory(&base_buffer) catch {
            diagnose.read_failure(diag, shown_given, directory, .no_project);
            return error.Failed;
        }
    else
        directory;
    const name = if (given.len > 0) given else file_mod.file_name;
    if (name.len > constants.path_bytes_max) {
        diagnose.read_failure(diag, shown_given, directory, .bad_path);
        return error.Failed;
    }
    project.resolve(fs, base, name, &workspace.path) catch |err| {
        const failure: diagnose.ReadFailure = switch (err) {
            error.NotFound => .missing,
            error.Unreadable => .unreadable,
            error.Loop, error.TooLong => .bad_path,
        };
        diagnose.read_failure(diag, shown_given, directory, failure);
        return error.Failed;
    };
    if (!project.is_inside(directory, workspace.path.text())) {
        diagnose.read_failure(diag, shown_given, directory, .outside);
        return error.Failed;
    }
}

fn read(fs: Fs, workspace: *Workspace, diag: *Diag) Error![]const u8 {
    assert(diag.code == null);
    assert(workspace.path.len > 0);
    const path = workspace.path.text();
    const directory = workspace.project.text();
    const stat = fs.lstat(path) catch |err| {
        const failure: diagnose.ReadFailure = if (err == error.NotFound) .missing else .unreadable;
        diagnose.read_failure(diag, workspace.shown(), directory, failure);
        return error.Failed;
    };
    if (stat.kind != .file) {
        diagnose.read_failure(diag, workspace.shown(), directory, .not_file);
        return error.Failed;
    }
    const text = fs.read_whole(path, &workspace.text) catch |err| {
        const failure: diagnose.ReadFailure = switch (err) {
            error.FileTooLarge => .too_large,
            error.NotFound => .missing,
            else => .unreadable,
        };
        diagnose.read_failure(diag, workspace.shown(), directory, failure);
        return error.Failed;
    };
    workspace.text_len = @intCast(text.len);
    assert(text.len <= constants.build_file_bytes_max);
    return text;
}

/// `path` below `directory`, without the directory: both are resolved, and `path` is inside.
pub fn shown_path(directory: []const u8, path: []const u8) []const u8 {
    assert(directory.len > 0);
    assert(path.len > 0);
    if (!project.is_inside(directory, path)) return path;
    if (directory.len == 1) return if (path.len == 1) path else path[1..];
    if (path.len == directory.len) return path;
    assert(path[directory.len] == '/');
    return path[directory.len + 1 ..];
}

const testing = std.testing;

test "the build file is shown as the project sees it" {
    // Goal: the path in a message is the one the user wrote in the project.
    try testing.expectEqualStrings("zbx.build.zon", shown_path("/p", "/p/zbx.build.zon"));
    try testing.expectEqualStrings("a/b.zon", shown_path("/p", "/p/a/b.zon"));
    try testing.expectEqualStrings("p/x.zon", shown_path("/", "/p/x.zon"));
    try testing.expectEqualStrings("/q/x.zon", shown_path("/p", "/q/x.zon"));
}
