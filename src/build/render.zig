//! The canonical form of a build file: `render` writes a `BuildFile` back as text that `parse`
//! reads to an equal file (`equal`), and rendering that again gives the same bytes. The fuzzer
//! holds the parser to this; the form is also what a later slice can show a user.
//!
//! The form: four spaces per level, fields in `Level.allowed` order, string lists inline
//! (`.{ "a", "b" }`), structs one field per line with a trailing comma, labels one per line.
//! What is absent or default is not written: no steps, an empty step list, `network = false`,
//! no adds, no `config`. A `config` list is written when it was given, even empty, since an
//! empty list given replaces the base's. In a string, `"` and `\` are escaped, `\n \r \t` are
//! written as such, other control bytes and bytes that are not UTF-8 as `\xNN`, and valid UTF-8
//! as it is.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const file_mod = @import("file.zig");

const BuildFile = file_mod.BuildFile;
const Text = file_mod.Text;
const Writer = std.Io.Writer;

/// Writes `file` in its canonical form. The form is at most `build_render_bytes_max` bytes.
pub fn render(file: *const BuildFile, writer: *Writer) Writer.Error!void {
    assert(file.version == file_mod.version);
    assert(file.pool_len <= constants.build_pool_bytes);
    try writer.print(".{{\n    .version = {d},\n", .{file.version});
    if (file.steps_count > 0) {
        try writer.writeAll("    .steps = .{\n");
        for (file.steps_slice()) |*step| try render_step(file, step, writer);
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("    .image = .{\n");
    const image = &file.image;
    if (image.base) |base| try render_field(file, 2, "base", base, writer);
    if (image.adds_count > 0) {
        try writer.writeAll("        .add = .{\n");
        for (file.adds_slice()) |add| {
            try writer.writeAll("            .{ .from = ");
            try render_string(file.text(add.from), writer);
            try writer.writeAll(", .to = ");
            try render_string(file.text(add.to), writer);
            try writer.writeAll(" },\n");
        }
        try writer.writeAll("        },\n");
    }
    if (image.config.present) try render_config(file, writer);
    try writer.writeAll("    },\n}\n");
}

fn render_step(file: *const BuildFile, step: *const file_mod.Step, writer: *Writer) !void {
    assert(step.run.count > 0);
    try writer.writeAll("        .{\n");
    try render_field(file, 3, "name", step.name, writer);
    try render_field(file, 3, "base", step.base, writer);
    if (step.inputs.count > 0) try render_list(file, 3, "inputs", step.inputs.slice(), writer);
    if (step.needs.count > 0) try render_list(file, 3, "needs", step.needs.slice(), writer);
    if (step.env.count > 0) try render_list(file, 3, "env", step.env.slice(), writer);
    try render_list(file, 3, "run", step.run.slice(), writer);
    if (step.network) try writer.writeAll("            .network = true,\n");
    try writer.writeAll("        },\n");
}

fn render_config(file: *const BuildFile, writer: *Writer) !void {
    const config = &file.image.config;
    assert(config.present);
    try writer.writeAll("        .config = .{\n");
    if (config.entrypoint.given) {
        try render_list(file, 3, "entrypoint", config.entrypoint.slice(), writer);
    }
    if (config.cmd.given) try render_list(file, 3, "cmd", config.cmd.slice(), writer);
    if (config.env.given) try render_list(file, 3, "env", config.env.slice(), writer);
    if (config.workdir) |workdir| try render_field(file, 3, "workdir", workdir, writer);
    if (config.user) |user| try render_field(file, 3, "user", user, writer);
    if (config.labels_given) {
        try writer.writeAll("            .labels = .{");
        if (config.labels_count > 0) try writer.writeByte('\n');
        for (file.labels_slice()) |label| {
            try writer.writeAll("                .{ ");
            try render_string(file.text(label.key), writer);
            try writer.writeAll(", ");
            try render_string(file.text(label.value), writer);
            try writer.writeAll(" },\n");
        }
        if (config.labels_count > 0) try writer.writeAll("            ");
        try writer.writeAll("},\n");
    }
    try writer.writeAll("        },\n");
}

fn render_field(
    file: *const BuildFile,
    depth: u32,
    name: []const u8,
    value: Text,
    writer: *Writer,
) !void {
    assert(depth >= 1);
    assert(depth <= 3);
    try writer.splatByteAll(' ', depth * 4);
    try writer.print(".{s} = ", .{name});
    try render_string(file.text(value), writer);
    try writer.writeAll(",\n");
}

fn render_list(
    file: *const BuildFile,
    depth: u32,
    name: []const u8,
    items: []const Text,
    writer: *Writer,
) !void {
    assert(depth >= 1);
    assert(depth <= 3);
    try writer.splatByteAll(' ', depth * 4);
    try writer.print(".{s} = .{{", .{name});
    for (items, 0..) |item, index| {
        try writer.writeAll(if (index == 0) " " else ", ");
        try render_string(file.text(item), writer);
    }
    try writer.writeAll(if (items.len == 0) "},\n" else " },\n");
}

/// A string in quotes, escaped so that `parse` decodes it to the same bytes.
pub fn render_string(text: []const u8, writer: *Writer) Writer.Error!void {
    assert(text.len <= constants.build_string_bytes_max);
    try writer.writeByte('"');
    var index: usize = 0;
    while (index < text.len) {
        const byte = text[index];
        if (byte >= 0x80) {
            if (file_mod.utf8_length(text[index..])) |length| {
                try writer.writeAll(text[index..][0..length]);
                index += length;
                continue;
            }
        }
        index += 1;
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11, 12, 14...0x1f, 0x7f...0xff => try writer.print("\\x{x:0>2}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    assert(index == text.len);
    try writer.writeByte('"');
}

/// Whether two files say the same thing: the same values, wherever they sit in the pools.
pub fn equal(a: *const BuildFile, b: *const BuildFile) bool {
    if (a.version != b.version) return false;
    if (a.steps_count != b.steps_count) return false;
    for (a.steps_slice(), b.steps_slice()) |*step_a, *step_b| {
        if (!same_text(a, b, step_a.name, step_b.name)) return false;
        if (!same_text(a, b, step_a.base, step_b.base)) return false;
        if (!same_list(a, b, step_a.inputs.slice(), step_b.inputs.slice())) return false;
        if (!same_list(a, b, step_a.needs.slice(), step_b.needs.slice())) return false;
        if (!same_list(a, b, step_a.env.slice(), step_b.env.slice())) return false;
        if (!same_list(a, b, step_a.run.slice(), step_b.run.slice())) return false;
        if (step_a.network != step_b.network) return false;
    }
    if (!same_optional(a, b, a.image.base, b.image.base)) return false;
    if (a.image.adds_count != b.image.adds_count) return false;
    for (a.adds_slice(), b.adds_slice()) |add_a, add_b| {
        if (!same_text(a, b, add_a.from, add_b.from)) return false;
        if (!same_text(a, b, add_a.to, add_b.to)) return false;
    }
    return equal_config(a, b);
}

fn equal_config(a: *const BuildFile, b: *const BuildFile) bool {
    const config_a = &a.image.config;
    const config_b = &b.image.config;
    if (config_a.present != config_b.present) return false;
    if (config_a.entrypoint.given != config_b.entrypoint.given) return false;
    if (config_a.cmd.given != config_b.cmd.given) return false;
    if (config_a.env.given != config_b.env.given) return false;
    if (config_a.labels_given != config_b.labels_given) return false;
    if (!same_list(a, b, config_a.entrypoint.slice(), config_b.entrypoint.slice())) return false;
    if (!same_list(a, b, config_a.cmd.slice(), config_b.cmd.slice())) return false;
    if (!same_list(a, b, config_a.env.slice(), config_b.env.slice())) return false;
    if (!same_optional(a, b, config_a.workdir, config_b.workdir)) return false;
    if (!same_optional(a, b, config_a.user, config_b.user)) return false;
    if (config_a.labels_count != config_b.labels_count) return false;
    for (a.labels_slice(), b.labels_slice()) |label_a, label_b| {
        if (!same_text(a, b, label_a.key, label_b.key)) return false;
        if (!same_text(a, b, label_a.value, label_b.value)) return false;
    }
    return true;
}

fn same_text(a: *const BuildFile, b: *const BuildFile, text_a: Text, text_b: Text) bool {
    return std.mem.eql(u8, a.text(text_a), b.text(text_b));
}

fn same_optional(a: *const BuildFile, b: *const BuildFile, text_a: ?Text, text_b: ?Text) bool {
    if (text_a == null) return text_b == null;
    if (text_b == null) return false;
    return same_text(a, b, text_a.?, text_b.?);
}

fn same_list(
    a: *const BuildFile,
    b: *const BuildFile,
    list_a: []const Text,
    list_b: []const Text,
) bool {
    if (list_a.len != list_b.len) return false;
    for (list_a, list_b) |text_a, text_b| {
        if (!same_text(a, b, text_a, text_b)) return false;
    }
    return true;
}

const testing = std.testing;
const file_tests = @import("file_tests.zig");

var first: BuildFile = undefined;
var second: BuildFile = undefined;
var rendered: [constants.build_render_bytes_max]u8 = undefined;
var rendered_again: [constants.build_render_bytes_max]u8 = undefined;

fn round_trip(text: []const u8) ![]const u8 {
    var problem: file_mod.Problem = undefined;
    try testing.expectEqual(file_mod.ParseResult.parsed, file_mod.parse(text, &first, &problem));
    var writer: Writer = .fixed(&rendered);
    try render(&first, &writer);
    const canonical = writer.buffered();
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(canonical, &second, &problem),
    );
    try testing.expect(equal(&first, &second));
    var again: Writer = .fixed(&rendered_again);
    try render(&second, &again);
    try testing.expectEqualStrings(canonical, again.buffered());
    return canonical;
}

test "the canonical form reads back to the same file and is a fixed point" {
    // Goal: render, then parse, gives an equal file, and rendering that gives the same bytes.
    // Method: the brief's example, a file with every optional field, and awkward strings.
    _ = try round_trip(file_tests.example);
    const canonical = try round_trip(
        \\.{ .image = .{ .config = .{ .cmd = .{}, .labels = .{},
        \\  .entrypoint = .{"a\x01\x7f\"\\\té"} } }, .version = 1,
        \\  .steps = .{ .{ .network = true, .run = .{"x"}, .base = "a", .name = "s",
        \\  .needs = .{}, }, }, }
    );
    try testing.expectEqualStrings(
        \\.{
        \\    .version = 1,
        \\    .steps = .{
        \\        .{
        \\            .name = "s",
        \\            .base = "a",
        \\            .run = .{ "x" },
        \\            .network = true,
        \\        },
        \\    },
        \\    .image = .{
        \\        .config = .{
        \\            .entrypoint = .{ "a\x01\x7f\"\\\té" },
        \\            .cmd = .{},
        \\            .labels = .{},
        \\        },
        \\    },
        \\}
        \\
    , canonical);
}

test "equal tells files apart by each value" {
    // Goal: `equal` is not vacuous. Method: the example against itself with one value changed.
    var problem: file_mod.Problem = undefined;
    const changed = [_][]const u8{
        "\"go.mod\"", "\"main.go\"", "\"0:0\"", "\"/usr/local/bin\"", "\"GREETING_STYLE=plain\"",
    };
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(file_tests.example, &first, &problem),
    );
    for (changed) |needle| {
        var buffer: [file_tests.example.len + 1]u8 = undefined;
        // A `1` before the closing quote: still valid, and different.
        const index = std.mem.indexOf(u8, file_tests.example, needle).? + needle.len - 2;
        @memcpy(buffer[0 .. index + 1], file_tests.example[0 .. index + 1]);
        buffer[index + 1] = '1';
        @memcpy(buffer[index + 2 ..], file_tests.example[index + 1 ..]);
        const result = file_mod.parse(&buffer, &second, &problem);
        try testing.expectEqual(file_mod.ParseResult.parsed, result);
        try testing.expect(!equal(&first, &second));
    }
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(file_tests.example, &second, &problem),
    );
    try testing.expect(equal(&first, &second));
}
