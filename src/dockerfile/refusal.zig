//! Why an import was refused: a registered code, the Dockerfile line, one sentence saying what
//! was refused and one saying what to write instead. The translator is pure, so it fills this
//! and returns; the CLI turns it into a diagnostic (`import_diagnose.zig`).

const std = @import("std");
const assert = std.debug.assert;

/// The import's codes (docs/briefs/M9-dockerfile-import.md, "Diagnostics").
pub const Code = enum { E0810, E0811, E0812, E0813, E0814, E0815, E0816 };

pub const what_bytes_max = 480;
pub const fix_bytes_max = 320;

pub const Refusal = struct {
    code: Code,
    /// The Dockerfile line (1-based); 0 when the refusal is not about one line.
    line: u32,
    what: [what_bytes_max]u8,
    what_len: u32,
    fix: [fix_bytes_max]u8,
    fix_len: u32,

    pub fn what_text(refusal: *const Refusal) []const u8 {
        assert(refusal.what_len <= what_bytes_max);
        assert(refusal.what_len > 0);
        return refusal.what[0..refusal.what_len];
    }

    pub fn fix_text(refusal: *const Refusal) []const u8 {
        assert(refusal.fix_len <= fix_bytes_max);
        assert(refusal.fix_len > 0);
        return refusal.fix[0..refusal.fix_len];
    }
};

pub const Refused = error{Refused};

/// Fills `refusal` and returns `error.Refused`. A sentence too long for its buffer is cut, with
/// `...` at the end, so a long word in a Dockerfile never fails the report.
pub fn refuse(
    refusal: *Refusal,
    code: Code,
    line: u32,
    comptime what: []const u8,
    what_args: anytype,
    comptime fix: []const u8,
    fix_args: anytype,
) Refused {
    refusal.code = code;
    refusal.line = line;
    refusal.what_len = format(&refusal.what, what, what_args);
    refusal.fix_len = format(&refusal.fix, fix, fix_args);
    assert(refusal.what_len > 0);
    assert(refusal.fix_len > 0);
    return error.Refused;
}

fn format(buffer: []u8, comptime text: []const u8, args: anytype) u32 {
    assert(buffer.len > 8);
    const written = std.fmt.bufPrint(buffer, text, args) catch {
        @memcpy(buffer[buffer.len - 3 ..], "...");
        return @intCast(buffer.len);
    };
    assert(written.len <= buffer.len);
    return @intCast(written.len);
}

test "a refusal too long for its buffer is cut, never lost" {
    // Goal: a huge word does not fail the report; method: refuse with a word longer than the
    // buffer and check the sentence ends in `...`.
    var refusal: Refusal = undefined;
    const long: [1000]u8 = @splat('x');
    const result = refuse(&refusal, .E0811, 3, "word {s}", .{&long}, "fix {d}", .{1});
    try std.testing.expectEqual(error.Refused, result);
    try std.testing.expect(std.mem.endsWith(u8, refusal.what_text(), "..."));
    try std.testing.expectEqualStrings("fix 1", refusal.fix_text());
    try std.testing.expectEqual(@as(u32, 3), refusal.line);
}
