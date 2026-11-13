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
    return render_with(file, null, writer);
}

/// Comments for `render_noted`: a header before the file, and one line before each step.
pub const Notes = struct {
    /// Whole `//` lines, each ending in a newline.
    header: []const u8,
    /// One per step, without the `// ` or a newline.
    steps: []const []const u8,
};

/// `render` with comments: what `zbx import` writes. The comments do not change what the file
/// parses to.
pub fn render_noted(file: *const BuildFile, notes: *const Notes, writer: *Writer) Writer.Error!void {
    assert(notes.steps.len == file.steps_count);
    for (notes.steps) |note| assert(std.mem.indexOfScalar(u8, note, '\n') == null);
    return render_with(file, notes, writer);
}

fn render_with(file: *const BuildFile, notes: ?*const Notes, writer: *Writer) Writer.Error!void {
    assert(file.version == file_mod.version);
    assert(file.pool_len <= constants.build_pool_bytes);
    if (notes) |n| try writer.writeAll(n.header);
    try writer.print(".{{\n    .version = {d},\n", .{file.version});
    if (file.exclude.given) try render_span(file, 1, "exclude", file.exclude, writer);
    if (file.steps_count > 0) {
        try writer.writeAll("    .steps = .{\n");
        for (file.steps_slice(), 0..) |*step, index| {
            if (notes) |n| try writer.print("        // {s}\n", .{n.steps[index]});
            try render_step(file, step, writer);
        }
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
    assert(step.run.given != step.copy.given);
    try writer.writeAll("        .{\n");
    try render_field(file, 3, "name", step.name, writer);
    try render_field(file, 3, "base", step.base, writer);
    if (step.inputs.count > 0) try render_list(file, 3, "inputs", step.inputs.slice(), writer);
    if (step.needs.count > 0) try render_list(file, 3, "needs", step.needs.slice(), writer);
    if (step.env.count > 0) try render_list(file, 3, "env", step.env.slice(), writer);
    if (step.run.given) try render_list(file, 3, "run", step.run.slice(), writer);
    if (step.network) try writer.writeAll("            .network = true,\n");
    if (step.output == .root) try writer.writeAll("            .output = .root,\n");
    if (step.user) |user| try render_field(file, 3, "user", user, writer);
    if (step.workdir) |workdir| try render_field(file, 3, "workdir", workdir, writer);
    if (step.copy.given) try render_copies(file, step, writer);
    if (step.caches.given) try render_caches(file, step, writer);
    if (step.binds.given) try render_binds(file, step, writer);
    if (step.exclude.given) try render_span(file, 3, "exclude", step.exclude, writer);
    try writer.writeAll("        },\n");
}

fn render_span(
    file: *const BuildFile,
    depth: u32,
    name: []const u8,
    span: file_mod.Span,
    writer: *Writer,
) !void {
    assert(span.given);
    try render_list(file, depth, name, file.texts(span), writer);
}

/// A list of entries, one per line, each `.{ .field = value, ... }` on one line.
fn render_entries_open(name: []const u8, count: usize, writer: *Writer) !void {
    assert(name.len > 0);
    try writer.print("            .{s} = .{{", .{name});
    if (count > 0) try writer.writeByte('\n');
}

fn render_entries_close(count: usize, writer: *Writer) !void {
    if (count > 0) try writer.writeAll("            ");
    try writer.writeAll("},\n");
}

fn render_copies(file: *const BuildFile, step: *const file_mod.Step, writer: *Writer) !void {
    const entries = file.copy_entries(step);
    try render_entries_open("copy", entries.len, writer);
    for (entries) |entry| {
        try writer.writeAll("                .{ ");
        if (entry.from) |from| try render_pair(file, "from", from, ", ", writer);
        try render_inline_list(file, "src", file.texts(entry.src), writer);
        try render_next(file, "to", entry.to, writer);
        if (entry.chown) |chown| try render_next(file, "chown", chown, writer);
        if (entry.chmod) |chmod| try render_next(file, "chmod", chmod, writer);
        if (entry.exclude.given) {
            try writer.writeAll(", ");
            try render_inline_list(file, "exclude", file.texts(entry.exclude), writer);
        }
        try writer.writeAll(" },\n");
    }
    try render_entries_close(entries.len, writer);
}

fn render_caches(file: *const BuildFile, step: *const file_mod.Step, writer: *Writer) !void {
    const entries = file.step_caches(step);
    try render_entries_open("caches", entries.len, writer);
    for (entries) |entry| {
        try writer.writeAll("                .{ ");
        try render_pair(file, "id", entry.id, "", writer);
        try render_next(file, "path", entry.path, writer);
        if (entry.ro) try writer.writeAll(", .ro = true");
        if (entry.mode) |mode| try render_next(file, "mode", mode, writer);
        if (entry.uid) |uid| try writer.print(", .uid = {d}", .{uid});
        if (entry.gid) |gid| try writer.print(", .gid = {d}", .{gid});
        try writer.writeAll(" },\n");
    }
    try render_entries_close(entries.len, writer);
}

fn render_binds(file: *const BuildFile, step: *const file_mod.Step, writer: *Writer) !void {
    const entries = file.step_binds(step);
    try render_entries_open("binds", entries.len, writer);
    for (entries) |entry| {
        try writer.writeAll("                .{ ");
        if (entry.from) |from| try render_pair(file, "from", from, ", ", writer);
        try render_pair(file, "source", entry.source, "", writer);
        try render_next(file, "to", entry.to, writer);
        try writer.writeAll(" },\n");
    }
    try render_entries_close(entries.len, writer);
}

/// `, .name = "value"`: a field after another.
fn render_next(file: *const BuildFile, name: []const u8, value: Text, writer: *Writer) !void {
    try writer.writeAll(", ");
    try render_pair(file, name, value, "", writer);
}

/// `.name = "value"` then `after`. A field that follows another brings its own ", " before
/// it, so the first field of an entry is written with `render_pair` too and `after` empty.
fn render_pair(
    file: *const BuildFile,
    name: []const u8,
    value: Text,
    after: []const u8,
    writer: *Writer,
) !void {
    assert(name.len > 0);
    assert(after.len <= 2);
    try writer.print(".{s} = ", .{name});
    try render_string(file.text(value), writer);
    try writer.writeAll(after);
}

fn render_inline_list(
    file: *const BuildFile,
    name: []const u8,
    items: []const Text,
    writer: *Writer,
) !void {
    assert(name.len > 0);
    try writer.print(".{s} = .{{", .{name});
    for (items, 0..) |item, index| {
        try writer.writeAll(if (index == 0) " " else ", ");
        try render_string(file.text(item), writer);
    }
    try writer.writeAll(if (items.len == 0) "}" else " }");
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
        if (!equal_step_more(a, b, step_a, step_b)) return false;
    }
    if (!same_span(a, b, a.exclude, b.exclude)) return false;
    if (!same_optional(a, b, a.image.base, b.image.base)) return false;
    if (a.image.adds_count != b.image.adds_count) return false;
    for (a.adds_slice(), b.adds_slice()) |add_a, add_b| {
        if (!same_text(a, b, add_a.from, add_b.from)) return false;
        if (!same_text(a, b, add_a.to, add_b.to)) return false;
    }
    return equal_config(a, b);
}

fn equal_step_more(
    a: *const BuildFile,
    b: *const BuildFile,
    step_a: *const file_mod.Step,
    step_b: *const file_mod.Step,
) bool {
    if (step_a.output != step_b.output) return false;
    if (!same_optional(a, b, step_a.user, step_b.user)) return false;
    if (!same_optional(a, b, step_a.workdir, step_b.workdir)) return false;
    if (!same_span(a, b, step_a.exclude, step_b.exclude)) return false;
    if (step_a.copy.given != step_b.copy.given) return false;
    if (step_a.run.given != step_b.run.given) return false;
    if (step_a.caches.given != step_b.caches.given) return false;
    if (step_a.binds.given != step_b.binds.given) return false;
    const copies_a = a.copy_entries(step_a);
    const copies_b = b.copy_entries(step_b);
    if (copies_a.len != copies_b.len) return false;
    for (copies_a, copies_b) |entry_a, entry_b| {
        if (!same_optional(a, b, entry_a.from, entry_b.from)) return false;
        if (!same_text(a, b, entry_a.to, entry_b.to)) return false;
        if (!same_optional(a, b, entry_a.chown, entry_b.chown)) return false;
        if (!same_optional(a, b, entry_a.chmod, entry_b.chmod)) return false;
        if (!same_span(a, b, entry_a.src, entry_b.src)) return false;
        if (!same_span(a, b, entry_a.exclude, entry_b.exclude)) return false;
    }
    return equal_mounts(a, b, step_a, step_b);
}

fn equal_mounts(
    a: *const BuildFile,
    b: *const BuildFile,
    step_a: *const file_mod.Step,
    step_b: *const file_mod.Step,
) bool {
    const caches_a = a.step_caches(step_a);
    const caches_b = b.step_caches(step_b);
    if (caches_a.len != caches_b.len) return false;
    for (caches_a, caches_b) |cache_a, cache_b| {
        if (!same_text(a, b, cache_a.id, cache_b.id)) return false;
        if (!same_text(a, b, cache_a.path, cache_b.path)) return false;
        if (cache_a.ro != cache_b.ro) return false;
        if (!same_optional(a, b, cache_a.mode, cache_b.mode)) return false;
        if (cache_a.uid != cache_b.uid or cache_a.gid != cache_b.gid) return false;
    }
    const binds_a = a.step_binds(step_a);
    const binds_b = b.step_binds(step_b);
    if (binds_a.len != binds_b.len) return false;
    for (binds_a, binds_b) |bind_a, bind_b| {
        if (!same_optional(a, b, bind_a.from, bind_b.from)) return false;
        if (!same_text(a, b, bind_a.source, bind_b.source)) return false;
        if (!same_text(a, b, bind_a.to, bind_b.to)) return false;
    }
    return true;
}

fn same_span(
    a: *const BuildFile,
    b: *const BuildFile,
    span_a: file_mod.Span,
    span_b: file_mod.Span,
) bool {
    if (span_a.given != span_b.given) return false;
    return same_list(a, b, a.texts(span_a), b.texts(span_b));
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
        "\"go.mod\"", "\"main.go\"", "\"/usr/local/bin\"", "\"GREETING_STYLE=plain\"",
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
    // A user's last byte changes in place: a `1` appended would be a leading zero, refused.
    var user: [file_tests.example.len]u8 = undefined;
    @memcpy(&user, file_tests.example);
    user[std.mem.indexOf(u8, file_tests.example, "\"0:0\"").? + 3] = '1';
    try testing.expectEqual(file_mod.ParseResult.parsed, file_mod.parse(&user, &second, &problem));
    try testing.expect(!equal(&first, &second));
    try testing.expectEqual(
        file_mod.ParseResult.parsed,
        file_mod.parse(file_tests.example, &second, &problem),
    );
    try testing.expect(equal(&first, &second));
}

const m9_file =
    \\.{ .version = 1, .exclude = .{ ".git", "!keep.log" },
    \\  .image = .{ .base = "step:b", .config = .{ .user = "app:app" } },
    \\  .steps = .{
    \\    .{ .name = "b", .base = "alpine:3.20", .run = .{ "true" }, .output = .root },
    \\    .{ .name = "a", .base = "step:b", .user = "app", .workdir = "/w", .exclude = .{},
    \\       .inputs = .{ "src/**/*.go" }, .run = .{ "true" },
    \\       .caches = .{ .{ .id = "c", .path = "/c", .ro = true, .mode = "0755",
    \\                      .uid = 1, .gid = 2 } },
    \\       .binds = .{ .{ .from = "step:b", .source = "/usr/bin", .to = "/tools" } } },
    \\    .{ .name = "c", .base = "alpine:3.20",
    \\       .copy = .{ .{ .from = "step:a", .src = .{ "a*" }, .to = "/d/", .chown = "app",
    \\                     .chmod = "644", .exclude = .{ "*.o" } } } },
    \\  },
    \\}
;

test "every builder addition is printed, read back equal and printed the same" {
    // Goal: the canonical form carries the M9 fields. Method: one file with all of them, round
    // tripped, with each field's printed text looked for; then each value changed once.
    const canonical = try round_trip(m9_file);
    const printed = [_][]const u8{
        ".output = .root,",       ".user = \"app\",",    ".workdir = \"/w\",",
        ".exclude = .{},",        ".base = \"step:b\",", ".ro = true",
        ".mode = \"0755\"",       ".uid = 1, .gid = 2",  ".from = \"step:b\", .source",
        ".chown = \"app\"",       ".chmod = \"644\"",    ".exclude = .{ \"*.o\" }",
        ".exclude = .{ \".git\"", ".user = \"app:app\"",
    };
    for (printed) |needle| {
        if (std.mem.indexOf(u8, canonical, needle) == null) {
            std.debug.print("not printed: {s}\n{s}\n", .{ needle, canonical });
            return error.TestUnexpectedResult;
        }
    }
    const changed = [_][2][]const u8{
        .{ ".output = .root", ".output = .out" }, .{ "\"app\", .workdir", "\"bpp\", .workdir" },
        .{ "\"/w\"", "\"/x\"" },                  .{ ".ro = true", ".ro = false" },
        .{ ".uid = 1", ".uid = 3" },              .{ "\"0755\"", "\"0700\"" },
        .{ "\"/tools\"", "\"/tool\"" },           .{ "\"644\"", "\"640\"" },
        .{ "\"*.o\"", "\"*.p\"" },                .{ "\"!keep.log\"", "\"keep.log\"" },
        .{ "\"app:app\"", "\"app:bpp\"" },        .{ "\"src/**/*.go\"", "\"src/*.go\"" },
        .{ ".exclude = .{},", "" },
    };
    var buffer: [m9_file.len + 16]u8 = undefined;
    for (changed) |pair| {
        const at = std.mem.indexOf(u8, m9_file, pair[0]).?;
        const head = at;
        const tail = m9_file[at + pair[0].len ..];
        @memcpy(buffer[0..head], m9_file[0..head]);
        @memcpy(buffer[head..][0..pair[1].len], pair[1]);
        @memcpy(buffer[head + pair[1].len ..][0..tail.len], tail);
        const length = head + pair[1].len + tail.len;
        var problem: file_mod.Problem = undefined;
        try testing.expectEqual(
            file_mod.ParseResult.parsed,
            file_mod.parse(m9_file, &first, &problem),
        );
        const result = file_mod.parse(buffer[0..length], &second, &problem);
        try testing.expectEqual(file_mod.ParseResult.parsed, result);
        if (equal(&first, &second)) {
            std.debug.print("equal after: {s} -> {s}\n", .{ pair[0], pair[1] });
            return error.TestUnexpectedResult;
        }
    }
}
