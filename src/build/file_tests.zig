//! Tests of the build file parser (`file.zig`): the brief's example, every refusal with its
//! position, and each bound at its limit and one past it.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const constants = @import("../constants.zig");
const file_mod = @import("file.zig");

const BuildFile = file_mod.BuildFile;
const Problem = file_mod.Problem;
const ProblemKind = file_mod.ProblemKind;

/// The brief's example, as the demo project has it.
pub const example =
    \\.{
    \\    .version = 1,
    \\    .steps = .{
    \\        .{
    \\            .name = "compile",
    \\            .base = "golang:1.23-alpine",
    \\            .inputs = .{ "go.mod", "main.go" },
    \\            .env = .{ "CGO_ENABLED=0", "GOFLAGS=-trimpath -buildvcs=false", "GOPROXY=off" },
    \\            .run = .{ "go", "build", "-ldflags=-s -w -buildid=", "-o", "/out/hello", "." },
    \\        },
    \\        .{
    \\            .name = "notice",
    \\            .base = "alpine:3.20",
    \\            .inputs = .{ "VERSION", "LICENSE" },
    \\            .run = .{ "sh", "-c", "mkdir -p /out/etc/hello && cp VERSION LICENSE /out/" },
    \\        },
    \\    },
    \\    .image = .{
    \\        .base = "alpine:3.20",
    \\        .add = .{
    \\            .{ .from = "compile", .to = "/usr/local/bin" },
    \\            .{ .from = "notice", .to = "/" },
    \\        },
    \\        // Optional; every field optional. Part of the result's identity.
    \\        .config = .{
    \\            .entrypoint = .{ "/usr/local/bin/hello" },
    \\            .env = .{ "GREETING_STYLE=plain" },
    \\            .workdir = "/",
    \\            .user = "0:0",
    \\            .labels = .{ .{ "org.opencontainers.image.source", "https://github.com/x/y" } },
    \\        },
    \\    },
    \\}
    \\
;

var test_file: BuildFile = undefined;
var test_text: [constants.build_render_bytes_max]u8 = undefined;

fn parse_ok(text: []const u8) !*const BuildFile {
    var problem: Problem = undefined;
    const result = file_mod.parse(text, &test_file, &problem);
    if (result == .refused) {
        std.debug.print(
            "refused: {t} at {d}:{d}\n",
            .{ problem.kind, problem.line, problem.column },
        );
        return error.TestUnexpectedResult;
    }
    return &test_file;
}

fn expect_refused(text: []const u8, kind: ProblemKind, line: u32, column: u32) !void {
    var problem: Problem = undefined;
    try testing.expectEqual(
        file_mod.ParseResult.refused,
        file_mod.parse(text, &test_file, &problem),
    );
    try testing.expectEqual(kind, problem.kind);
    try testing.expectEqual(line, problem.line);
    try testing.expectEqual(column, problem.column);
}

/// Refused at the first `needle` in `text`, which must hold one.
fn refused_at(text: []const u8, kind: ProblemKind, needle: []const u8) !void {
    const index = std.mem.indexOf(u8, text, needle).?;
    const line_start = if (std.mem.lastIndexOfScalar(u8, text[0..index], '\n')) |at| at + 1 else 0;
    const line = 1 + std.mem.count(u8, text[0..index], "\n");
    try expect_refused(text, kind, @intCast(line), @intCast(index - line_start + 1));
}

test "the brief's example is read whole" {
    // Goal: every field of the schema lands where it belongs. Method: the brief's example.
    const file = try parse_ok(example);
    try testing.expectEqual(@as(u32, 1), file.version);
    const steps = file.steps_slice();
    try testing.expectEqual(@as(usize, 2), steps.len);
    try testing.expectEqualStrings("compile", file.text(steps[0].name));
    try testing.expectEqualStrings("golang:1.23-alpine", file.text(steps[0].base));
    try testing.expectEqual(@as(u32, 2), steps[0].inputs.count);
    try testing.expectEqual(@as(u32, 3), steps[0].env.count);
    try testing.expectEqualStrings("-ldflags=-s -w -buildid=", file.text(steps[0].run.items[2]));
    try testing.expect(!steps[0].network);
    try testing.expect(!steps[0].needs.given);
    try testing.expectEqual(@as(u32, 4), steps[0].line);
    try testing.expectEqual(@as(u32, 9), steps[0].column);
    const adds = file.adds_slice();
    try testing.expectEqual(@as(usize, 2), adds.len);
    try testing.expectEqualStrings("/usr/local/bin", file.text(adds[0].to));
    const config = &file.image.config;
    try testing.expect(config.present);
    try testing.expect(!config.cmd.given);
    try testing.expectEqualStrings("0:0", file.text(config.user.?));
    try testing.expectEqualStrings("/", file.text(config.workdir.?));
    const labels = file.labels_slice();
    try testing.expectEqual(@as(usize, 1), labels.len);
    try testing.expectEqualStrings("https://github.com/x/y", file.text(labels[0].value));
}

test "the smallest file is a version and an empty image" {
    // Goal: what is optional is optional. Method: no steps, an image with nothing, escapes.
    const file = try parse_ok(".{ .version = 1, .image = .{} }");
    try testing.expectEqual(@as(u32, 0), file.steps_count);
    try testing.expect(file.image.base == null);
    try testing.expect(!file.image.config.present);
    const escaped = try parse_ok(
        \\.{.image=.{.config=.{.cmd=.{"a\"b\\c\n\x41é",},},},.version=1,}
    );
    try testing.expectEqualStrings("a\"b\\c\nAé", escaped.text(escaped.image.config.cmd.items[0]));
}

test "each refusal names its kind, line and column" {
    // Goal: the negative space of the grammar and of every value check, with positions.
    // Method: one small file per refusal.
    const head = ".{ .version = 1, .image = .{ ";
    try expect_refused("", .syntax, 1, 1);
    try refused_at(".{ .version = 1, .image = .{} } x", .syntax, "x");
    try refused_at(".{ .version = 1 .image = .{} }", .syntax, ".image");
    try refused_at(".{ .version = 1, .image = .{}, .colour = 1 }", .unknown_field, ".colour");
    try refused_at(".{ .version = 1, .version = 1 }", .duplicate_field, ".version = 1 }");
    try refused_at(".{ .image = .{} }", .missing_field, ".{");
    try refused_at(".{ .version = 1 }", .missing_field, ".{");
    try refused_at(".{ .version = 0, .image = .{} }", .bad_version, "0");
    try refused_at(".{ .version = 12345, .image = .{} }", .bad_version, "1");
    try refused_at(".{ .version = 2, .image = .{} }", .newer_version, "2");
    try refused_at(head ++ ".base = \"a\\q\" } }", .bad_escape, "\"");
    try refused_at(head ++ ".base = \"a\tb\" } }", .bad_string, "\"");
    try refused_at(head ++ ".base = \"a\xffb\" } }", .bad_string, "\"");
    try refused_at(head ++ ".base = \"a\\x00\" } }", .nul_byte, "\"");
    try refused_at(head ++ ".base = \"Bad Ref\" } }", .bad_reference, "\"");
    try refused_at(head ++ ".base = \"\" } }", .bad_reference, "\"");
    const add = head ++ ".add = .{ .{ ";
    try refused_at(add ++ ".from = \"a\", .to = \"usr\" } } } }", .bad_target, "\"usr");
    try refused_at(add ++ ".from = \"a\", .to = \"/a/../b\" } } } }", .bad_target, "\"/a");
    try refused_at(add ++ ".to = \"/\" } } } }", .missing_field, ".{ .to");
    const config = head ++ ".config = .{ ";
    try refused_at(config ++ ".workdir = \"tmp\" } } }", .config_workdir, "\"");
    try refused_at(config ++ ".user = \"root\" } } }", .config_user, "\"");
    try refused_at(config ++ ".user = \"0:99999999999\" } } }", .config_user, "\"");
    try refused_at(config ++ ".env = .{ \"A\", } } } }", .config_env, "\"");
    try refused_at(config ++ ".labels = .{ .{ \"A\", \"b\" } } } } }", .config_label_key, "\"");
    try refused_at(
        config ++ ".labels = .{ .{ \"a\", \"b\" }, .{ \"a\", \"c\" } } } } }",
        .config_label_twice,
        "\"a\", \"c",
    );
}

test "each step refusal names its kind, line and column" {
    // Goal: the checks on a step's own fields. Method: one step per refusal.
    const head = ".{ .version = 1, .image = .{}, .steps = .{ .{ ";
    const named = head ++ ".name = \"a\", .base = \"a\", ";
    const run = ", .base = \"a\", .run = .{\"x\"} } } }";
    try refused_at(head ++ ".name = \"Big\"" ++ run, .bad_step_name, "\"");
    try refused_at(head ++ ".name = \"\"" ++ run, .bad_step_name, "\"");
    try refused_at(head ++ ".name = \"image\"" ++ run, .reserved_step_name, "\"");
    try refused_at(named ++ ".run = .{} } } }", .empty_run, ".{ .name");
    try refused_at(named ++ ".run = .{\"\"} } } }", .empty_run, "\"\"");
    try refused_at(named ++ ".env = .{\"=b\"} } } }", .bad_env, "\"=b");
    try refused_at(named[0 .. named.len - 2] ++ " } } }", .missing_field, ".{ .name");
    try refused_at(head ++ ".name = \"a\", .network = 1 } } }", .syntax, "1 }");
    try refused_at(".{ .steps = .{ 1 } }", .syntax, "1");
}

fn write_steps(count: u32) []const u8 {
    var writer: std.Io.Writer = .fixed(&test_text);
    writer.writeAll(".{ .version = 1, .image = .{}, .steps = .{\n") catch unreachable; // Fits.
    for (0..count) |index| {
        writer.print(
            ".{{ .name = \"s{d}\", .base = \"a\", .run = .{{ \"x\" }} }},\n",
            .{index},
        ) catch
            unreachable; // 64 steps of 50 bytes fit the buffer.
    }
    writer.writeAll("} }\n") catch unreachable; // Fits.
    return writer.buffered();
}

fn write_string(length: u32) []const u8 {
    var writer: std.Io.Writer = .fixed(&test_text);
    writer.writeAll(
        ".{ .version = 1, .image = .{ .config = .{ .cmd = .{ \"",
    ) catch unreachable; // Fits.
    writer.splatByteAll('a', length) catch unreachable; // A string bound fits the buffer.
    writer.writeAll("\" } } } }") catch unreachable; // Fits.
    return writer.buffered();
}

test "the bounds hold at their limit and refuse one past it" {
    // Goal: every count and length bound is exact. Method: steps, a string, needs and the pool,
    // each at its limit and one more.
    _ = try parse_ok(write_steps(constants.build_steps_max));
    try expect_refused(write_steps(constants.build_steps_max + 1), .list_too_long, 66, 1);
    _ = try parse_ok(write_string(constants.build_string_bytes_max));
    const long = write_string(constants.build_string_bytes_max + 1);
    try refused_at(long, .string_too_long, "\"");
    const step = ".{ .version = 1, .image = .{}, .steps = .{ .{ " ++
        ".name = \"a\", .base = \"a\", .run = .{\"x\"}, ";
    comptime assert(constants.build_step_needs_max == 6);
    _ = try parse_ok(step ++ ".needs = .{\"a\",\"b\",\"c\",\"d\",\"e\",\"f\"} } } }");
    const needs = step ++ ".needs = .{\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\"} } } }";
    try refused_at(needs, .too_many_needs, "\"g");
}

test "every string together is bounded by the pool" {
    // Goal: the pool bound, which no one string reaches. Method: config cmd entries of the
    // longest string until the pool is full, then one byte more.
    var writer: std.Io.Writer = .fixed(&test_text);
    const per_string = constants.build_string_bytes_max;
    const count = constants.build_pool_bytes / per_string;
    comptime assert(count <= constants.build_config_argv_max);
    writer.writeAll(
        ".{ .version = 1, .image = .{ .config = .{ .cmd = .{\n",
    ) catch unreachable; // Fits.
    for (0..count) |_| {
        writer.writeByte('"') catch unreachable; // The pool's bytes fit the render buffer.
        writer.splatByteAll('a', per_string) catch unreachable; // Same.
        writer.writeAll("\",\n") catch unreachable; // Same.
    }
    const full = writer.buffered().len;
    writer.writeAll("} } } }") catch unreachable; // Fits.
    _ = try parse_ok(writer.buffered());
    writer.end = full;
    writer.writeAll("\"a\" } } } }") catch unreachable; // Fits.
    try expect_refused(writer.buffered(), .text_too_long, count + 2, 1);
}

test "a file cut short anywhere is refused at its end, inside a list too" {
    // Goal: the end of the text inside a list, an object or a value is a syntax refusal at the
    // end, not an assertion (the `build_file` fuzzer found the list case). Method: the brief's
    // example cut at every byte.
    for (0..example.len - 2) |length| {
        var problem: Problem = undefined;
        const result = file_mod.parse(example[0..length], &test_file, &problem);
        try testing.expectEqual(file_mod.ParseResult.refused, result);
    }
    try expect_refused(".{ .version = 1, .image = .{ .add = .{", .syntax, 1, 39);
}
