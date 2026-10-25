//! The text of `zbx explain <code>`: the registry's long explanation, offline. Pure, so the same
//! text can later be generated into `site/errors/<code>.html` (DIAGNOSTICS.md, "Codes").

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const codes = @import("codes.zig");

/// Renders the explanation of `code` into `buffer` and returns the used prefix. The buffer must
/// be `output_bytes_max` bytes; constants.zig proves the longest explanation plus the header fit.
pub fn render(code: codes.Code, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.output_bytes_max);
    const entry = codes.entry(code);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the longest explanation (a comptime-checked bound) plus a short header is
    // far below the buffer size.
    writer.print("{s}: {s}\n", .{ codes.full_name(code), entry.summary }) catch unreachable;
    var exit_buffer: [codes.exit_text_bytes_max]u8 = undefined;
    writer.print("{s}, blame: {s}, exit code {s}\n\n", .{
        @tagName(entry.severity),
        @tagName(entry.blame),
        codes.exit_text(code, &exit_buffer),
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
