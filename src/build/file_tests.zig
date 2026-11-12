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
    try refused_at(config ++ ".user = \"a b\" } } }", .config_user, "\"");
    // M7 took `uid:gid` with leading zeros in `config.user`; it still parses.
    // The whole file goes through the parser, so dropping `parse_config`'s numeric arm fails it.
    const old = try parse_ok(config ++ ".user = \"01000:01000\" } } }");
    try testing.expectEqualStrings("01000:01000", old.text(old.image.config.user));
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
    try refused_at(named[0 .. named.len - 2] ++ " } } }", .run_or_copy, ".{ .name");
    try refused_at(head ++ ".base = \"a\", .run = .{\"x\"} } } }", .missing_field, ".{ .base");
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
    const over = write_steps(constants.build_steps_max + 1);
    try expect_refused(over, .list_too_long, constants.build_steps_max + 2, 1);
    _ = try parse_ok(write_string(constants.build_string_bytes_max));
    const long = write_string(constants.build_string_bytes_max + 1);
    try refused_at(long, .string_too_long, "\"");
    const step = ".{ .version = 1, .image = .{}, .steps = .{ .{ " ++
        ".name = \"a\", .base = \"a\", .run = .{\"x\"}, ";
    comptime assert(constants.build_step_needs_max == 6);
    _ = try parse_ok(step ++ ".needs = .{\"a\",\"b\",\"c\",\"d\",\"e\",\"f\"} } } }");
    const needs = step ++ ".needs = .{\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\"} } } }";
    try refused_at(needs, .too_many_needs, "\"g");
    // Needs, binds and caches share the run's mounts beside `/src` and `/out`.
    comptime assert(constants.mounts_max == 8);
    const four = step ++ ".needs = .{\"a\",\"b\",\"c\",\"d\"}, ";
    const bind = ".binds = .{ .{ .source = \"x\", .to = \"/b\" } }, ";
    const caches = ".caches = .{ .{ .id = \"c1\", .path = \"/c1\" }";
    _ = try parse_ok(four ++ bind ++ caches ++ " } } } }");
    const second = ", .{ .id = \"c2\", .path = \"/c2\" } } } } }";
    try refused_at(four ++ bind ++ caches ++ second, .too_many_mounts, ".{ .name");
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
    writer.writeAll("}, .env = .{ \"A=b\" } } } }") catch unreachable; // Fits.
    try expect_refused(writer.buffered(), .text_too_long, count + 2, 14);
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

test "a string is UTF-8 once decoded, and only arguments and env values hold control bytes" {
    // Goal: an escape cannot make what the raw text may not hold: bytes that are not UTF-8
    // anywhere, or a control byte outside an argv or an env value. Method: `\x80`, a whole
    // UTF-8 sequence written as escapes, and `\n` in every kind of field.
    const head = ".{ .version = 1, .image = .{ ";
    const config = head ++ ".config = .{ ";
    try refused_at(config ++ ".cmd = .{ \"a\\x80\" } } } }", .bad_string, "\"a");
    try refused_at(config ++ ".cmd = .{ \"\\xc3\" } } } }", .bad_string, "\"\\");
    const accented = try parse_ok(config ++ ".cmd = .{ \"\\xc3\\xa9\" } } } }");
    try testing.expectEqualStrings("é", accented.text(accented.image.config.cmd.items[0]));
    _ = try parse_ok(config ++ ".entrypoint = .{ \"a\\nb\\t\" }, .env = .{ \"A=\\n\" } } } }");
    try refused_at(config ++ ".workdir = \"/a\\nb\" } } }", .bad_string, "\"");
    try refused_at(config ++ ".labels = .{ .{ \"a\", \"b\\n\" } } } } }", .bad_string, "\"b");
    try refused_at(config ++ ".labels = .{ .{ \"a\\x7f\", \"b\" } } } } }", .bad_string, "\"a");
    const add = head ++ ".add = .{ .{ ";
    try refused_at(add ++ ".from = \"a\", .to = \"/a\\tb\" } } } }", .bad_string, "\"/");
    try refused_at(add ++ ".from = \"a\\r\", .to = \"/\" } } } }", .bad_string, "\"a");
    const step = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"a\", ";
    _ = try parse_ok(step ++ ".run = .{ \"sh\", \"-c\", \"a\\nb\" }, .env = .{ \"A=\\t\" } } } }");
    const inputs = step ++ ".run = .{\"x\"}, .inputs = .{ \"a\\nb\" } } } }";
    try refused_at(inputs, .bad_string, "\"a\\n");
    try refused_at(step ++ ".run = .{\"x\"}, .needs = .{ \"a\\n\" } } } }", .bad_string, "\"a\\n");
}

test "an escape is exactly two hex digits, and .version is written as render writes it" {
    // Goal: parse accepts only what render writes. Method: `\x` with a sign, one digit or a
    // non-hex letter; `.version` with a leading zero.
    const config = ".{ .version = 1, .image = .{ .config = .{ ";
    try refused_at(config ++ ".cmd = .{ \"\\x+f\" } } } }", .bad_escape, "\"");
    try refused_at(config ++ ".cmd = .{ \"\\x-0\" } } } }", .bad_escape, "\"");
    try refused_at(config ++ ".cmd = .{ \"\\xg0\" } } } }", .bad_escape, "\"");
    try refused_at(config ++ ".cmd = .{ \"\\x4\" } } } }", .bad_escape, "\"");
    const upper = try parse_ok(config ++ ".cmd = .{ \"\\x4A\\x4a\" } } } }");
    try testing.expectEqualStrings("JJ", upper.text(upper.image.config.cmd.items[0]));
    try refused_at(".{ .version = 01, .image = .{} }", .bad_version, "01");
    try refused_at(".{ .version = 00, .image = .{} }", .bad_version, "00");
}

test "an env list has plain keys, each once, and a step cannot set the fixed environment" {
    // Goal: the key rule `[A-Za-z_][A-Za-z0-9_]*`, a key twice in one list, and the fixed keys
    // in a step's env (allowed in image.config's, which is the image's own). Method: one list
    // per refusal, at both levels.
    const step = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"a\", " ++
        ".run = .{\"x\"}, .env = .{ ";
    try refused_at(step ++ "\"1A=b\" } } } }", .bad_env, "\"1A");
    try refused_at(step ++ "\"A-B=c\" } } } }", .bad_env, "\"A-B");
    try refused_at(step ++ "\"ü=c\" } } } }", .bad_env, "\"ü");
    try refused_at(step ++ "\"A=1\", \"B=2\", \"A=3\" } } } }", .env_twice, "\"A=3");
    inline for (file_mod.fixed_env) |key| {
        var buffer: [256]u8 = undefined;
        const format = "{s}\"_x9=1\", \"{s}=1\" }} }} }} }}";
        const text = try std.fmt.bufPrint(&buffer, format, .{ step, key });
        try refused_at(text, .env_fixed, "\"" ++ key);
    }
    _ = try parse_ok(step ++ "\"_x9=1\", \"PATH=/usr/bin\", \"A=\" } } } }");
    const config = ".{ .version = 1, .image = .{ .config = .{ .env = .{ ";
    try refused_at(config ++ "\"A B=c\" } } } }", .config_env, "\"A B");
    try refused_at(config ++ "\"A=1\", \"A=1\" } } } }", .env_twice, "\"A=1\" }");
    _ = try parse_ok(config ++ "\"HOME=/home/app\", \"TZ=UTC\" } } } }");
}

/// A file with `count` entries of a list, one per line after the first: the entry past a
/// bound is refused at line `count + 1`, column 1. `entry` takes the entry's index as `{d}`.
fn write_list(
    comptime head: []const u8,
    comptime entry: []const u8,
    comptime tail: []const u8,
    count: u32,
) []const u8 {
    var writer: std.Io.Writer = .fixed(&test_text);
    writer.writeAll(head ++ "\n") catch unreachable; // Fits.
    for (0..count) |index| {
        // At most 65 entries of under 64 bytes fit the render buffer.
        writer.print(entry ++ ",\n", .{index}) catch unreachable;
    }
    writer.writeAll(tail) catch unreachable; // Fits.
    return writer.buffered();
}

fn expect_list_bound(
    comptime head: []const u8,
    comptime entry: []const u8,
    comptime tail: []const u8,
    max: u32,
    kind: ProblemKind,
) !void {
    _ = try parse_ok(write_list(head, entry, tail, max));
    try expect_refused(write_list(head, entry, tail, max + 1), kind, max + 2, 1);
}

test "every list bound of a step holds at its limit and refuses one past it" {
    // Goal: the lists of a step are bounded exactly by their constants. Method: each list
    // written at its bound and one past, entries distinct.
    const step = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"a\", ";
    const run = ".run = .{\"x\"}, ";
    const close_step = "} } } }";
    try expect_list_bound(
        step ++ run ++ ".inputs = .{",
        "\"i{d}\"",
        close_step,
        constants.build_step_inputs_max,
        .list_too_long,
    );
    try expect_list_bound(
        step ++ ".run = .{",
        "\"a{d}\"",
        close_step,
        constants.build_step_argv_max,
        .list_too_long,
    );
    try expect_list_bound(
        step ++ run ++ ".env = .{",
        "\"K{d}=v\"",
        close_step,
        constants.build_step_env_max,
        .list_too_long,
    );
}

test "every list bound of the image holds at its limit and refuses one past it" {
    // Goal: as above, for the image's lists. Method: each written at its bound and one past.
    const image = ".{ .version = 1, .image = .{ ";
    try expect_list_bound(
        image ++ ".add = .{",
        ".{{ .from = \"a\", .to = \"/{d}\" }}",
        "} } }",
        constants.build_image_adds_max,
        .list_too_long,
    );
    const config = image ++ ".config = .{ ";
    const close_config = "} } } }";
    try expect_list_bound(
        config ++ ".labels = .{",
        ".{{ \"k{d}\", \"v\" }}",
        close_config,
        constants.build_config_labels_max,
        .list_too_long,
    );
    try expect_list_bound(
        config ++ ".entrypoint = .{",
        "\"e{d}\"",
        close_config,
        constants.build_config_argv_max,
        .list_too_long,
    );
    try expect_list_bound(
        config ++ ".cmd = .{",
        "\"c{d}\"",
        close_config,
        constants.build_config_argv_max,
        .list_too_long,
    );
    try expect_list_bound(
        config ++ ".env = .{",
        "\"K{d}=v\"",
        close_config,
        constants.build_config_env_max,
        .list_too_long,
    );
}

test "a step name holds at its bound and is refused one past it" {
    // Goal: the name bound is the constant. Method: a name at the bound and one byte longer.
    const name_max = constants.build_step_name_bytes_max;
    const long_name: [name_max + 1]u8 = @splat('a');
    const tail = "\", .base = \"a\", .run = .{\"x\"} } } }";
    const named = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"";
    _ = try parse_ok(named ++ long_name[0..name_max] ++ tail);
    try refused_at(named ++ long_name ++ tail, .bad_step_name, "\"a");
}

fn kind_of(text: []const u8) ProblemKind {
    var problem: Problem = undefined;
    const result = file_mod.parse(text, &test_file, &problem);
    if (result == .parsed) return .syntax; // Not refused: the callers expect another kind.
    return problem.kind;
}

const m9_head = ".{ .version = 1, .image = .{}, .steps = .{ .{ .name = \"a\", .base = \"x\", ";

test "the M9 fields are read whole and each is kept" {
    // Goal: every builder addition parses and reads back. Method: one step with all of them,
    // then one with copy and a step base.
    const run = try parse_ok(
        \\.{ .version = 1, .exclude = .{ ".git", "*.log" },
        \\  .image = .{ .base = "step:b", .config = .{ .user = "app:app" } },
        \\  .steps = .{
        \\    .{ .name = "b", .base = "alpine:3.20", .run = .{ "true" }, .output = .root },
        \\    .{ .name = "a", .base = "step:b", .user = "app", .workdir = "/w",
        \\       .inputs = .{ "src/**/*.go", "go.mod" }, .exclude = .{ "**/*_test.go" },
        \\       .caches = .{ .{ .id = "gomod", .path = "/go/pkg", .mode = "0755", .uid = 1000 } },
        \\       .binds = .{ .{ .from = "step:b", .source = "/usr/bin", .to = "/tools" } },
        \\       .run = .{ "true" } },
        \\    .{ .name = "c", .base = "alpine:3.20",
        \\       .copy = .{ .{ .src = .{ "a*" }, .to = "/d/", .chown = "1:1", .chmod = "644" } } },
        \\  },
        \\}
    );
    try testing.expectEqual(@as(u32, 3), run.steps_count);
    try testing.expectEqual(file_mod.Output.root, run.steps[0].output);
    try testing.expectEqual(@as(u32, 1), run.steps[2].copy.count);
    try testing.expectEqual(@as(u32, 1), run.steps[1].caches.count);
    try testing.expectEqual(@as(u32, 1), run.steps[1].binds.count);
}

fn step_refused(comptime fields: []const u8, kind: ProblemKind) !void {
    try testing.expectEqual(kind, kind_of(m9_head ++ fields ++ " } } }"));
}

test "each M9 refusal names its kind" {
    // Goal: the negative space of the builder additions. Method: one step per refusal.
    const run = ".run = .{\"x\"}, ";
    const copy = ".copy = .{ .{ .src = .{\"a\"}, .to = ";
    try step_refused(run ++ ".output = .both", .bad_output);
    try step_refused(run ++ copy ++ "\"/\" } }", .run_or_copy);
    try step_refused(run ++ ".user = \"a b\"", .bad_user);
    try step_refused(run ++ ".user = \"007\"", .bad_user); // One id, two spellings.
    try step_refused(run ++ ".user = \"1:08\"", .bad_user);
    try step_refused(".copy = .{}", .empty_list); // Copies nothing.
    try step_refused(".copy = .{ .{ .src = .{}, .to = \"/x\" } }", .empty_list);
    try step_refused(run ++ ".workdir = \"w\"", .bad_path);
    try step_refused(copy ++ "\"x\" } }", .bad_copy_to);
    try step_refused(copy ++ "\"/x\", .chmod = \"9\" } }", .bad_mode);
    try step_refused(run ++ ".exclude = .{ \"[a\" }", .bad_pattern);
    try step_refused(
        ".copy = .{ .{ .from = \"Bad Ref\", .src = .{\"a\"}, .to = \"/x\" } }",
        .bad_from,
    );
    const cache = ".caches = .{ .{ .id = ";
    try step_refused(run ++ cache ++ "\"a b\", .path = \"/c\" } }", .bad_cache_id);
    try step_refused(
        run ++ cache ++ "\"a\", .path = \"/c\" }, .{ .id = \"b\", .path = \"/c\" } }",
        .mount_twice,
    );
    try step_refused(run ++ ".binds = .{ .{ .source = \"../a\", .to = \"/b\" } }", .bad_source);
}
