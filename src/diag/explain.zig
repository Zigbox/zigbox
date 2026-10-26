//! The text of `zbx explain <code>`: the registry's long explanation, offline. Pure, so the same
//! text can later be generated into `site/errors/<code>.html` (DIAGNOSTICS.md, "Codes").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");

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
