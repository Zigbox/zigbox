//! The translator's acceptance set: each fixture under `src/build/dockerfile_fixtures/` with its
//! golden translation (`.zon`) or golden refusal (`.refused`), through a table resolver
//! (docs/briefs/M9-dockerfile-import.md, "The fixtures"). Changing the translation means
//! updating the golden in the same commit.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const constants = @import("../constants.zig");
const translate = @import("translate.zig");
const report_mod = @import("report.zig");

pub const fixtures = "../build/dockerfile_fixtures/";

/// What the table resolver says of every image: Docker's default `PATH`, and a workdir for the
/// images that set one. A reference that starts with `missing/` is not found.
pub const Table = struct {
    resolved: u32 = 0,

    fn resolve(context: *anyopaque, reference: []const u8) error{Unresolved}!translate.ImageFacts {
        const table: *Table = @ptrCast(@alignCast(context));
        if (std.mem.startsWith(u8, reference, "missing/")) return error.Unresolved;
        table.resolved += 1;
        const path = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        if (std.mem.startsWith(u8, reference, "golang:")) {
            return .{ .env = &.{ "PATH=/go/bin:/usr/local/go/bin:/usr/sbin:/usr/bin", "GOPATH=/go" }, .workdir = "/go" };
        }
        return .{ .env = &.{path}, .workdir = "" };
    }
};

pub const Case = struct {
    dockerfile: []const u8,
    /// The golden's name, without `.zon` or `.refused`.
    golden: []const u8,
    dockerignore: []const u8 = "",
    build_args: []const translate.BuildArg = &.{},
    target: ?[]const u8 = null,
    network: translate.NetworkRule = .detect,
    hermetic: bool = false,
};

pub const cases = [_]Case{
    .{ .dockerfile = "arg_from", .golden = "arg_from" },
    .{
        .dockerfile = "arg_from",
        .golden = "arg_from.build_arg",
        .build_args = &.{ .{ .name = "ARCH", .value = "arm64" }, .{ .name = "OS", .value = "linux" } },
    },
    .{ .dockerfile = "arg_from_no_default", .golden = "arg_from_no_default" },
    .{
        .dockerfile = "arg_from_no_default",
        .golden = "arg_from_no_default.build_arg",
        .build_args = &.{.{ .name = "GO_VERSION", .value = "1.22" }},
    },
    .{ .dockerfile = "arg_paths_user", .golden = "arg_paths_user" },
    .{ .dockerfile = "add_url", .golden = "add_url" },
    .{ .dockerfile = "add_git", .golden = "add_git" },
    .{ .dockerfile = "heredoc_run", .golden = "heredoc_run" },
    .{ .dockerfile = "shell_logic", .golden = "shell_logic" },
    .{ .dockerfile = "shell_instruction", .golden = "shell_instruction" },
    .{ .dockerfile = "copy_from_stage_glob", .golden = "copy_from_stage_glob" },
    .{ .dockerfile = "copy_from_image_platform", .golden = "copy_from_image_platform" },
    .{ .dockerfile = "mounts", .golden = "mounts" },
    .{ .dockerfile = "mounts", .golden = "mounts.hermetic", .hermetic = true },
    .{ .dockerfile = "secret_mount", .golden = "secret_mount" },
    .{ .dockerfile = "user_forms", .golden = "user_forms" },
    .{
        .dockerfile = "dockerignore",
        .golden = "dockerignore",
        .dockerignore = @embedFile(fixtures ++ "dockerignore.dockerignore"),
    },
    .{ .dockerfile = "target_skips", .golden = "target_skips", .target = "app" },
    .{ .dockerfile = "target_skips", .golden = "target_skips.last" },
    .{ .dockerfile = "escape_backtick", .golden = "escape_backtick" },
    .{ .dockerfile = "labels", .golden = "labels" },
    .{ .dockerfile = "label_key", .golden = "label_key" },
    .{ .dockerfile = "onbuild", .golden = "onbuild" },
    .{ .dockerfile = "stage_collision", .golden = "stage_collision" },
};

pub fn options_of(case: *const Case, dockerfile: []const u8, table: *Table) translate.Options {
    return .{
        .dockerfile = dockerfile,
        .dockerfile_name = "Dockerfile",
        .dockerignore = case.dockerignore,
        .build_args = case.build_args,
        .target = case.target,
        .platform = .{ .os = "linux", .architecture = "amd64", .variant = "" },
        .network = case.network,
        .hermetic = case.hermetic,
        .resolver = .{ .context = table, .resolve = Table.resolve },
    };
}

/// The translation as a golden holds it: the build file, or the refusal's code, line and two
/// sentences.
pub fn outcome(ws: *translate.Workspace, options: *const translate.Options, buffer: []u8) ![]const u8 {
    const output = translate.translate(ws, options) catch |err| {
        assert(err == error.Refused);
        const refusal = &ws.refusal;
        return std.fmt.bufPrint(buffer, "{t} Dockerfile:{d}\n{s}\n{s}\n", .{
            refusal.code, refusal.line, refusal.what_text(), refusal.fix_text(),
        });
    };
    return output;
}

fn workspace() !*translate.Workspace {
    return testing.allocator.create(translate.Workspace);
}

test "every fixture translates to its golden, or is refused as its golden says" {
    // Goal: the acceptance set: the survey's hard patterns, each pinned to the bytes zbx
    // writes. Method: each case through a table resolver, compared with its checked-in golden.
    const ws = try workspace();
    defer testing.allocator.destroy(ws);
    var buffer: [1024]u8 = undefined;
    inline for (cases) |case| {
        var table: Table = .{};
        const dockerfile = @embedFile(fixtures ++ case.dockerfile ++ ".Dockerfile");
        const options = options_of(&case, dockerfile, &table);
        const got = try outcome(ws, &options, &buffer);
        const want = golden(case.golden);
        if (!std.mem.eql(u8, got, want)) {
            std.debug.print("fixture {s}: golden differs; got:\n{s}\n", .{ case.golden, got });
            return error.TestUnexpectedResult;
        }
    }
}

fn golden(comptime name: []const u8) []const u8 {
    const zon = fixtures ++ name ++ ".zon";
    const refused = fixtures ++ name ++ ".refused";
    return if (comptime exists(name)) @embedFile(zon) else @embedFile(refused);
}

/// Whether the golden is a translation: the refusal goldens are listed here.
fn exists(comptime name: []const u8) bool {
    const refusals = [_][]const u8{
        "arg_from_no_default", "add_url",   "add_git",  "secret_mount", "mounts.hermetic",
        "target_skips.last",   "label_key", "onbuild", "stage_collision",
    };
    for (refusals) |refused| {
        if (std.mem.eql(u8, refused, name)) return false;
    }
    return true;
}

test "a translation is the same bytes every time, and the workspace carries nothing over" {
    // Goal: the pure-function promise: a workspace reused after another translation, or after
    // a refusal, gives the same bytes. Method: translate A, then a refusal, then A again.
    const ws = try workspace();
    defer testing.allocator.destroy(ws);
    var table: Table = .{};
    const case: Case = .{ .dockerfile = "mounts", .golden = "mounts" };
    const options = options_of(&case, @embedFile(fixtures ++ "mounts.Dockerfile"), &table);
    var first: [constants.build_render_bytes_max]u8 = undefined;
    const once = try translate.translate(ws, &options);
    @memcpy(first[0..once.len], once);
    const refused_case: Case = .{ .dockerfile = "onbuild", .golden = "onbuild" };
    const refused = options_of(&refused_case, @embedFile(fixtures ++ "onbuild.Dockerfile"), &table);
    try testing.expectError(error.Refused, translate.translate(ws, &refused));
    const again = try translate.translate(ws, &options);
    try testing.expectEqualStrings(first[0..once.len], again);
}

test "the step bound is E0815 one past it, and the bound itself translates" {
    // Goal: E0815 at build_steps_max + 1 steps, not before. Method: a generated Dockerfile of
    // exactly the bound, then one more.
    const ws = try workspace();
    defer testing.allocator.destroy(ws);
    var text: [16 * 1024]u8 = undefined;
    var table: Table = .{};
    const case: Case = .{ .dockerfile = "generated", .golden = "generated" };
    for ([_]u32{ constants.build_steps_max, constants.build_steps_max + 1 }) |steps| {
        var writer: std.Io.Writer = .fixed(&text);
        try writer.writeAll("FROM alpine:3.20\n");
        for (0..steps) |index| try writer.print("RUN echo {d}\n", .{index});
        const options = options_of(&case, writer.buffered(), &table);
        if (steps == constants.build_steps_max) {
            _ = try translate.translate(ws, &options);
            try testing.expectEqual(constants.build_steps_max, ws.report.steps_count);
        } else {
            try testing.expectError(error.Refused, translate.translate(ws, &options));
            try testing.expectEqual(.E0815, ws.refusal.code);
            try testing.expectEqual(steps + 1, ws.refusal.line);
        }
    }
}

test "an unresolved base stops the translation with the resolver's error" {
    // Goal: the resolver's refusal reaches the caller unchanged. Method: a base the table
    // does not know.
    const ws = try workspace();
    defer testing.allocator.destroy(ws);
    var table: Table = .{};
    const case: Case = .{ .dockerfile = "generated", .golden = "generated" };
    const options = options_of(&case, "FROM missing/base:1\nRUN true\n", &table);
    try testing.expectError(error.Unresolved, translate.translate(ws, &options));
}

test "the report names each step's line, its network reason and what was dropped" {
    // Goal: the report agrees with the build file. Method: the mounts fixture's report.
    const ws = try workspace();
    defer testing.allocator.destroy(ws);
    var table: Table = .{};
    const case: Case = .{ .dockerfile = "mounts", .golden = "mounts" };
    const options = options_of(&case, @embedFile(fixtures ++ "mounts.Dockerfile"), &table);
    _ = try translate.translate(ws, &options);
    const steps = ws.report.steps_slice();
    try testing.expectEqual(3, steps.len);
    try testing.expectEqualStrings("deps-1", steps[0].name_text());
    try testing.expectEqual(report_mod.Kind.copy, steps[0].kind);
    try testing.expectEqualStrings("go mod download", steps[1].network.?);
    try testing.expect(steps[1].cache);
    try testing.expect(steps[2].cache and steps[2].bind);
    try testing.expectEqual(null, steps[2].network);
    try testing.expectEqual(1, ws.report.dropped_slice().len);
}
