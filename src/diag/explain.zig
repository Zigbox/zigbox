//! The text of `zbx explain <code>`: the registry's long explanation, offline. Pure, so the same
//! text can later be generated into `site/errors/<code>.html` (DIAGNOSTICS.md, "Codes").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");
const Product = @import("product.zig").Product;

/// One explanation as plain data: what `zbx explain` prints for a code. A second product builds
/// one from its own registry and renders it with `render_entry`, so the two products' `explain`
/// cannot drift apart in layout.
pub const ExplainEntry = struct {
    /// "ZBX-E0001".
    full_name: []const u8,
    severity: codes.Severity,
    blame: codes.Blame,
    /// At most `diag_summary_bytes_max`.
    summary: []const u8,
    /// Hard-wrapped, at most `diag_explanation_bytes_max`.
    explanation: []const u8,
    /// How the exit code reads, such as "1" or "1 (126 or 127 in zbx run)"; at most
    /// `codes.exit_text_bytes_max`.
    exit_text: []const u8,
};

/// Renders the explanation of `code` into `buffer` and returns the used prefix. The buffer must
/// be `output_bytes_max` bytes; constants.zig proves the longest explanation plus the header fit.
pub fn render(code: codes.Code, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    const entry = codes.entry(code);
    var exit_buffer: [codes.exit_text_bytes_max]u8 = undefined;
    return render_entry(.{
        .full_name = codes.full_name(code),
        .severity = entry.severity,
        .blame = entry.blame,
        .summary = entry.summary,
        .explanation = entry.explanation,
        .exit_text = codes.exit_text(code, &exit_buffer),
    }, buffer);
}

/// Renders `entry` into `buffer` and returns the used prefix. The caller keeps the entry within
/// its bounds (asserted), which is what makes the writes below unable to fail.
pub fn render_entry(entry: ExplainEntry, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    assert(entry.full_name.len <= constants.diag_code_bytes);
    assert(entry.summary.len <= constants.diag_summary_bytes_max);
    assert(entry.explanation.len <= constants.diag_explanation_bytes_max);
    assert(entry.exit_text.len <= codes.exit_text_bytes_max);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the longest explanation (a comptime-checked bound) plus a short header is
    // far below the buffer size.
    writer.print("{s}: {s}\n", .{ entry.full_name, entry.summary }) catch unreachable;
    writer.print("{s}, blame: {s}, exit code {s}\n\n", .{
        @tagName(entry.severity),
        @tagName(entry.blame),
        entry.exit_text,
    }) catch unreachable; // Same.
    writer.print("{s}\n", .{entry.explanation}) catch unreachable; // Same.
    const output = writer.buffered();
    assert(output.len > entry.explanation.len);
    assert(output[output.len - 1] == '\n');
    return output;
}

/// The JSON document `zbx explain <code> --output json` prints, `zbx.explain/1`: one object on
/// one line with the code, severity, blame, summary, explanation and the docs page. The buffer
/// must be `output_bytes_max` bytes.
pub fn render_json(code: codes.Code, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    const entry = codes.entry(code);
    var url: [constants.docs_url_bytes_max]u8 = undefined;
    return render_json_entry(.{
        .full_name = codes.full_name(code),
        .severity = entry.severity,
        .blame = entry.blame,
        .summary = entry.summary,
        .explanation = entry.explanation,
        .exit_text = "",
    }, Product.zbx.docs_url(&url, codes.full_name(code)), buffer);
}

/// `render_json` for an entry given as data, with the address of its page.
pub fn render_json_entry(entry: ExplainEntry, docs: []const u8, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    assert(entry.explanation.len <= constants.diag_explanation_bytes_max);
    assert(docs.len <= constants.docs_url_bytes_max);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the longest explanation escaped (twice its length at the worst: a newline
    // and a quote are two bytes) and a short header and docs address fit far below the buffer.
    writer.writeAll("{\"schema\":\"zbx.explain/1\",\"code\":") catch unreachable; // Same.
    write_json_text(&writer, entry.full_name);
    writer.print(",\"severity\":\"{s}\",\"blame\":\"{s}\",\"summary\":", .{
        @tagName(entry.severity), @tagName(entry.blame),
    }) catch unreachable; // Same.
    write_json_text(&writer, entry.summary);
    writer.writeAll(",\"explanation\":") catch unreachable; // Same.
    write_json_text(&writer, entry.explanation);
    writer.writeAll(",\"docs\":") catch unreachable; // Same.
    write_json_text(&writer, docs);
    writer.writeAll("}\n") catch unreachable; // Same.
    const output = writer.buffered();
    assert(output[output.len - 1] == '\n');
    assert(std.mem.indexOfScalar(u8, output[0 .. output.len - 1], '\n') == null);
    return output;
}

/// A JSON string of printable ASCII and newlines, which is what registry text is made of.
fn write_json_text(writer: *std.Io.Writer, text: []const u8) void {
    assert(writer.buffer.len >= constants.output_bytes_max);
    // Cannot fail: see `render_json_entry`.
    writer.writeByte('"') catch unreachable; // Same.
    for (text) |byte| {
        switch (byte) {
            '"', '\\' => {
                writer.writeByte('\\') catch unreachable; // Same.
                writer.writeByte(byte) catch unreachable; // Same.
            },
            '\n' => writer.writeAll("\\n") catch unreachable, // Same.
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => {
                writer.writeByte(byte) catch unreachable; // Same.
            },
            else => writer.print("\\u{x:0>4}", .{byte}) catch unreachable, // Same.
        }
    }
    writer.writeByte('"') catch unreachable; // Same.
}

test "explain prints the code, summary, blame, exit code and the long text" {
    // Goal: the exact shape of one explanation, and that every registered code can be explained
    // without overflowing the buffer. Method: render E0001 fully, then all codes.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render(.E0001, &buffer);
    const expected_start = "ZBX-E0001: unknown command\nerror, blame: user, exit code 1\n\n";
    try std.testing.expect(std.mem.startsWith(u8, text, expected_start));
    try std.testing.expect(std.mem.endsWith(u8, text, "after the command.\n"));
    // A code `zbx run` can report also says what a run exits with instead.
    const run_text = render(.E0202, &buffer);
    const run_header = "error, blame: user, exit code 1 (126 or 127 in zbx run)\n";
    try std.testing.expect(std.mem.indexOf(u8, run_text, run_header) != null);
    for (codes.registry) |item| {
        const each = render(item.code, &buffer);
        try std.testing.expect(std.mem.indexOf(u8, each, item.explanation) != null);
    }
}

test "the JSON form of every code is one valid line that says what the text form does" {
    // Goal: `render_json` never overflows and never breaks the JSON, for every registered code.
    // Method: parse each; the code, summary and explanation come back as the registry has them.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    for (codes.registry) |item| {
        const line = render_json(item.code, &buffer);
        const valid = try @import("../test_util.zig").json_is_valid(line[0 .. line.len - 1]);
        try std.testing.expect(valid);
        const allocator = std.testing.allocator;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
        defer parsed.deinit();
        const object = parsed.value.object;
        try std.testing.expectEqualStrings("zbx.explain/1", object.get("schema").?.string);
        try std.testing.expectEqualStrings(codes.full_name(item.code), object.get("code").?.string);
        try std.testing.expectEqualStrings(item.summary, object.get("summary").?.string);
        try std.testing.expectEqualStrings(item.explanation, object.get("explanation").?.string);
        const severity = object.get("severity").?.string;
        try std.testing.expectEqualStrings(@tagName(item.severity), severity);
        try std.testing.expectEqualStrings(@tagName(item.blame), object.get("blame").?.string);
        const docs = object.get("docs").?.string;
        try std.testing.expect(std.mem.startsWith(u8, docs, constants.docs_url_base));
        try std.testing.expect(std.mem.endsWith(u8, docs, ".html"));
    }
}

test "render_entry renders an entry given as data the way a registered code reads" {
    // Goal: a second product's entry, built by hand, gets the layout of the first's. Method:
    // rebuild E0001's entry from its parts and compare with `render`; then a foreign one.
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var other: [constants.output_bytes_max]u8 = undefined;
    const entry = codes.entry(.E0001);
    const rebuilt = render_entry(.{
        .full_name = "ZBX-E0001",
        .severity = entry.severity,
        .blame = entry.blame,
        .summary = entry.summary,
        .explanation = entry.explanation,
        .exit_text = "1",
    }, &other);
    try std.testing.expectEqualStrings(render(.E0001, &buffer), rebuilt);

    const foreign = render_entry(.{
        .full_name = "ZC-E0201",
        .severity = .warning,
        .blame = .environment,
        .summary = "node unreachable",
        .explanation = "The agent could not reach the node.\n",
        .exit_text = "2",
    }, &buffer);
    try std.testing.expectEqualStrings(
        "ZC-E0201: node unreachable\nwarning, blame: environment, exit code 2\n\n" ++
            "The agent could not reach the node.\n\n",
        foreign,
    );
}
