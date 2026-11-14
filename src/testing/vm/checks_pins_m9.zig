//! What the M9 demo's step 8 asserts (docs/briefs/M9-dockerfile-import.md, "Pin, then drift"),
//! as pure functions of the commands' output, each with a unit test. pins_m9.zig runs the
//! commands.

const std = @import("std");
const assert = std.debug.assert;
const m7 = @import("checks_m7.zig");
const m9 = @import("checks_m9.zig");

pub const Error = m9.Error || error{
    /// The lock, the drift refusal or the drift warning is not what the brief shows.
    PinWrong,
};

const digest_text_bytes = "b3:".len + 64;

/// `zbx build --pin` wrote a version 2 lock with one pin, for `fetch` of `drift.build.zon`,
/// and the image entry it had.
pub fn check_pinned_lock(lock: []const u8) Error!void {
    if (!std.mem.startsWith(u8, lock, ".{\n    .version = 2,\n")) return error.PinWrong;
    if (std.mem.count(u8, lock, ".step = ") != 1) return error.PinWrong;
    const wants = [_][]const u8{
        ".file = \"drift.build.zon\",",
        ".step = \"fetch\",",
        ".reference = \"alpine:3.20\",",
    };
    if (!m9.contains_all(lock, &wants)) return error.PinWrong;
}

/// The two digests of a drift: the pin, and the output the step gave.
pub const Drift = struct {
    pinned: [digest_text_bytes]u8,
    output: [digest_text_bytes]u8,
};

/// The digest that follows `after` in `text` once white space is folded (a cause wraps).
fn digest_after(flat: []const u8, after: []const u8, into: *[digest_text_bytes]u8) bool {
    const at = std.mem.indexOf(u8, flat, after) orelse return false;
    const rest = flat[at + after.len ..];
    if (rest.len < digest_text_bytes) return false;
    if (!m7.is_digest(rest[0..digest_text_bytes])) return false;
    @memcpy(into, rest[0..digest_text_bytes]);
    return true;
}

/// The drift a diagnostic names: "step fetch produced <output>, and its pin is <pinned>".
pub fn drift_of(stderr: []const u8) ?Drift {
    var buffer: [8192]u8 = undefined;
    const flat = m7.normalize(&buffer, stderr);
    var drift: Drift = undefined;
    if (!digest_after(flat, "step fetch produced ", &drift.output)) return null;
    if (!digest_after(flat, "and its pin is ", &drift.pinned)) return null;
    if (std.mem.eql(u8, &drift.output, &drift.pinned)) return null;
    return drift;
}

/// `--locked` in a fresh store: exit 3, E0822 first, naming `fetch` and both digests; `use`
/// never ran, so the report has no row for it.
pub fn check_drift_refused(stdout: []const u8, stderr: []const u8, status: u8) Error!Drift {
    if (status != 3) return error.RefusalWrong;
    if (!std.mem.startsWith(u8, stderr, "error[ZBX-E0822]: ")) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    if (has_row(stdout, "use")) return error.PinWrong;
    return drift_of(stderr) orelse error.PinWrong;
}

/// Without `--locked`: exit 0, W0803 naming the same two digests, and `use` missed.
pub fn check_drift_warned(
    report: *const m9.Report,
    stderr: []const u8,
    status: u8,
    refused: *const Drift,
) Error!void {
    if (status != 0) return error.ReportWrong;
    try m9.check_warnings(stderr, &.{"ZBX-W0803"});
    const drift = drift_of(stderr) orelse return error.PinWrong;
    if (!std.mem.eql(u8, &drift.pinned, &refused.pinned)) return error.PinWrong;
    if (!std.mem.eql(u8, &drift.output, &refused.output)) return error.PinWrong;
    const use = report.row("use") orelse return error.ReportWrong;
    if (use.hit) return error.PinWrong;
}

/// A row of the text report names the step: the line's first word after its indent.
fn has_row(stdout: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const first = words.next() orelse continue;
        if (std.mem.eql(u8, first, name)) return true;
    }
    return false;
}

const testing = std.testing;
const pinned_text = "b3:" ++ repeat('1');
const output_text = "b3:" ++ repeat('2');

fn repeat(comptime byte: u8) *const [64]u8 {
    comptime {
        const bytes: [64]u8 = @splat(byte);
        return &bytes;
    }
}

const refusal = "error[ZBX-E0822]: step fetch gave an output that is not its pin\n" ++
    "  while checking step fetch against its pin\n  cause: step fetch produced " ++
    output_text ++ ",\n    and its pin is " ++ pinned_text ++ "\n";

test "the pinned lock: version 2, one pin for fetch, the image kept" {
    const lock =
        \\.{
        \\    .version = 2,
        \\    .images = .{
        \\        .{
        \\            .reference = "alpine:3.20",
        \\        },
        \\    },
        \\    .pins = .{
        \\        .{
        \\            .file = "drift.build.zon",
        \\            .step = "fetch",
        \\        },
        \\    },
        \\}
        \\
    ;
    try check_pinned_lock(lock);
    const one = try std.mem.replaceOwned(u8, testing.allocator, lock, "= 2", "= 1");
    defer testing.allocator.free(one);
    try testing.expectError(error.PinWrong, check_pinned_lock(one));
    const other = try std.mem.replaceOwned(u8, testing.allocator, lock, "fetch", "use");
    defer testing.allocator.free(other);
    try testing.expectError(error.PinWrong, check_pinned_lock(other));
}

test "the drift refusal names both digests, even wrapped, and use never ran" {
    const drift = try check_drift_refused("  fetch   miss   0.10 s  net\n", refusal, 3);
    try testing.expectEqualStrings(pinned_text, &drift.pinned);
    try testing.expectEqualStrings(output_text, &drift.output);
    try testing.expectError(error.RefusalWrong, check_drift_refused("", refusal, 1));
    try testing.expectError(error.RefusalWrong, check_drift_refused("", refusal[1..], 3));
    const ran = "  fetch   miss   0.10 s  net\n  use   miss   0.01 s\n";
    try testing.expectError(error.PinWrong, check_drift_refused(ran, refusal, 3));
    const same = "error[ZBX-E0822]: step fetch produced " ++ pinned_text ++ ", and its pin is " ++
        pinned_text ++ "\n";
    try testing.expectError(error.PinWrong, check_drift_refused("", same, 3));
}

test "the drift warning names the refusal's digests, and use misses" {
    const drift = try check_drift_refused("", refusal, 3);
    var report: m9.Report = .{
        .rows = undefined,
        .count = 1,
        .digest = "",
        .hits = 0,
        .misses = 1,
        .elapsed_ms = 0,
    };
    report.rows[0] = .{
        .name = "use",
        .hit = false,
        .network = false,
        .start_ms = 0,
        .end_ms = 0,
        .key = "",
        .output = "",
    };
    const warned = "warning[ZBX-W0803]: x\n  cause: step fetch produced " ++ output_text ++
        ", and its pin is " ++ pinned_text ++ "\n";
    try check_drift_warned(&report, warned, 0, &drift);
    try testing.expectError(error.ReportWrong, check_drift_warned(&report, warned, 1, &drift));
    try testing.expectError(error.ReportWrong, check_drift_warned(&report, refusal, 0, &drift));
    var other = drift;
    other.output[3] = '3';
    try testing.expectError(error.PinWrong, check_drift_warned(&report, warned, 0, &other));
    report.rows[0].hit = true;
    try testing.expectError(error.PinWrong, check_drift_warned(&report, warned, 0, &drift));
}
