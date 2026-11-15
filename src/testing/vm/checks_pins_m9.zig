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

/// A pin of the lock, as text: the step's key and the output it is held to.
pub const Pin = struct {
    key: [digest_text_bytes]u8,
    output: [digest_text_bytes]u8,
};

/// The quoted digest of the first `<field> = "..."` line in `text`.
fn quoted_digest(text: []const u8, field: []const u8, into: *[digest_text_bytes]u8) bool {
    var buffer: [32]u8 = undefined;
    const head = std.fmt.bufPrint(&buffer, "{s} = \"", .{field}) catch return false;
    const at = std.mem.indexOf(u8, text, head) orelse return false;
    const rest = text[at + head.len ..];
    if (rest.len < digest_text_bytes + 1) return false;
    if (!m7.is_digest(rest[0..digest_text_bytes])) return false;
    if (rest[digest_text_bytes] != '"') return false;
    @memcpy(into, rest[0..digest_text_bytes]);
    return true;
}

/// The pin of `step` in `lock`: the `.key` and `.output` that follow its `.step` line.
pub fn pin_of(lock: []const u8, step: []const u8) ?Pin {
    var buffer: [64]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, ".step = \"{s}\",\n", .{step}) catch return null;
    const at = std.mem.indexOf(u8, lock, line) orelse return null;
    const entry = lock[at + line.len ..];
    const end = std.mem.indexOf(u8, entry, "}") orelse return null;
    var pin: Pin = undefined;
    if (!quoted_digest(entry[0..end], ".key", &pin.key)) return null;
    if (!quoted_digest(entry[0..end], ".output", &pin.output)) return null;
    return pin;
}

/// `zbx build --pin` wrote a version 2 lock with one pin, for `fetch` of `drift.build.zon`,
/// with its key and output, and the image entry it had.
pub fn check_pinned_lock(lock: []const u8) Error!Pin {
    if (!std.mem.startsWith(u8, lock, ".{\n    .version = 2,\n")) return error.PinWrong;
    if (std.mem.count(u8, lock, ".step = ") != 1) return error.PinWrong;
    const wants = [_][]const u8{
        ".file = \"drift.build.zon\",",
        ".step = \"fetch\",",
        ".reference = \"alpine:3.20\",",
    };
    if (!m9.contains_all(lock, &wants)) return error.PinWrong;
    return pin_of(lock, "fetch") orelse error.PinWrong;
}

/// The pin is the step's own: a later `--locked` build hits `step` with the pin's key, and its
/// committed output is the pin's output.
pub fn check_pin_committed(report: *const m9.Report, step: []const u8, pin: *const Pin) Error!void {
    const row = report.row(step) orelse return error.ReportWrong;
    if (!row.hit) return error.PinWrong;
    if (!std.mem.eql(u8, row.key, &pin.key)) return error.PinWrong;
    if (!std.mem.eql(u8, row.output, &pin.output)) return error.PinWrong;
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

/// The refusal's headline. W0801 (the build uses the network) may come before it.
const refusal_head = "error[ZBX-E0822]: a pinned step's output differs from its pin\n";

/// `--locked` in a fresh store: exit 3, E0822 naming `fetch` and both digests, the pinned one
/// the lock's and the produced one another, and no other error; `use` never ran, so the report
/// has no row for it.
pub fn check_drift_refused(
    stdout: []const u8,
    stderr: []const u8,
    status: u8,
    pin: *const Pin,
) Error!Drift {
    if (status != 3) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, refusal_head) == null) return error.RefusalWrong;
    if (std.mem.count(u8, stderr, "error[") != 1) return error.RefusalWrong;
    if (std.mem.indexOf(u8, stderr, "errno") != null) return error.RefusalWrong;
    if (has_row(stdout, "use")) return error.PinWrong;
    const drift = drift_of(stderr) orelse return error.PinWrong;
    if (!std.mem.eql(u8, &drift.pinned, &pin.output)) return error.PinWrong;
    if (std.mem.eql(u8, &drift.output, &pin.output)) return error.PinWrong;
    return drift;
}

/// `steady` has `.expect`: in a store a VM away (and minutes later), it gives the output the
/// first VM pinned, so no drift is named, and `after`, which needs it, has the first VM's key.
pub fn check_steady_same(
    report: *const m9.Report,
    stderr: []const u8,
    status: u8,
    first: *const Steady,
) Error!void {
    if (status != 0) return error.ReportWrong;
    if (std.mem.indexOf(u8, stderr, "E0822") != null) return error.PinWrong;
    if (std.mem.indexOf(u8, stderr, "W0803") != null) return error.PinWrong;
    const steady = report.row("steady") orelse return error.ReportWrong;
    const after = report.row("after") orelse return error.ReportWrong;
    if (!std.mem.eql(u8, steady.output, &first.output)) return error.PinWrong;
    if (!std.mem.eql(u8, after.key, &first.after_key)) return error.PinWrong;
}

/// What the first VM learned of `steady`: the output it pinned, and the key of `after`.
pub const Steady = struct {
    output: [digest_text_bytes]u8,
    after_key: [digest_text_bytes]u8,
};

/// The first VM's `steady`, from its pin in the lock and an all-hits `--locked` JSON report.
pub fn steady_of(report: *const m9.Report, pin: *const Pin) Error!Steady {
    try check_pin_committed(report, "steady", pin);
    const after = report.row("after") orelse return error.ReportWrong;
    if (!after.hit) return error.CacheWrong;
    if (!m7.is_digest(after.key) or after.key.len != digest_text_bytes) return error.ReportWrong;
    var steady: Steady = .{ .output = pin.output, .after_key = undefined };
    @memcpy(&steady.after_key, after.key);
    return steady;
}

/// Without `--locked`: exit 0, W0803 naming the same pin and an output that is not it, and `use`
/// missed. The refused output was not cached, so this build ran the step again: in the VM a
/// fresh uuid, so its output need not be the refused one.
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
    if (std.mem.eql(u8, &drift.output, &drift.pinned)) return error.PinWrong;
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

const key_text = "b3:" ++ repeat('4');

/// E0822 laid out as the renderer lays it out (src/testdata/diag/E0822.txt, which
/// build_tests.zig also runs through `check_drift_refused`), after the network warning.
const refusal = "warning[ZBX-W0801]: the build has steps that use the network\n" ++
    refusal_head ++ "  cause  step fetch produced\n         " ++ output_text ++
    ",\n         and its pin is\n         " ++ pinned_text ++
    "\n  fix    build without --locked to see the new output\n";

const pinned_lock =
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
    \\            .key = "
++ key_text ++
    \\",
    \\            .output = "
++ pinned_text ++
    \\",
    \\        },
    \\    },
    \\}
    \\
;

const the_pin: Pin = .{ .key = key_text.*, .output = pinned_text.* };

fn one_row(name: []const u8, hit: bool, key: []const u8, output: []const u8) m9.Report {
    var report: m9.Report = .{
        .rows = undefined,
        .count = 1,
        .digest = "",
        .hits = @intFromBool(hit),
        .misses = @intFromBool(!hit),
        .elapsed_ms = 0,
    };
    report.rows[0] = .{
        .name = name,
        .hit = hit,
        .network = false,
        .start_ms = 0,
        .end_ms = 0,
        .key = key,
        .output = output,
    };
    return report;
}

test "the pinned lock: version 2, one pin for fetch with its key and output, the image kept" {
    const pin = try check_pinned_lock(pinned_lock);
    try testing.expectEqualStrings(key_text, &pin.key);
    try testing.expectEqualStrings(pinned_text, &pin.output);
    const one = try std.mem.replaceOwned(u8, testing.allocator, pinned_lock, "= 2", "= 1");
    defer testing.allocator.free(one);
    try testing.expectError(error.PinWrong, check_pinned_lock(one));
    const other = try std.mem.replaceOwned(u8, testing.allocator, pinned_lock, "fetch", "use");
    defer testing.allocator.free(other);
    try testing.expectError(error.PinWrong, check_pinned_lock(other));
    const keyless = try std.mem.replaceOwned(u8, testing.allocator, pinned_lock, ".key", ".kye");
    defer testing.allocator.free(keyless);
    try testing.expectError(error.PinWrong, check_pinned_lock(keyless));
    const short = try std.mem.replaceOwned(u8, testing.allocator, pinned_lock, "1\"", "\"");
    defer testing.allocator.free(short);
    try testing.expectError(error.PinWrong, check_pinned_lock(short));
}

test "the pin is the step's own: its key and committed output, on a hit" {
    var report = one_row("fetch", true, key_text, pinned_text);
    try check_pin_committed(&report, "fetch", &the_pin);
    try testing.expectError(error.ReportWrong, check_pin_committed(&report, "use", &the_pin));
    report.rows[0].key = pinned_text; // Another step's key, say step 0's.
    try testing.expectError(error.PinWrong, check_pin_committed(&report, "fetch", &the_pin));
    report.rows[0].key = key_text;
    report.rows[0].output = output_text;
    try testing.expectError(error.PinWrong, check_pin_committed(&report, "fetch", &the_pin));
    report.rows[0].output = pinned_text;
    report.rows[0].hit = false;
    try testing.expectError(error.PinWrong, check_pin_committed(&report, "fetch", &the_pin));
}

test "the drift refusal names both digests, the lock's pin second, and use never ran" {
    const drift = try check_drift_refused("  fetch   miss   0.10 s  net\n", refusal, 3, &the_pin);
    try testing.expectEqualStrings(pinned_text, &drift.pinned);
    try testing.expectEqualStrings(output_text, &drift.output);
    try testing.expectError(error.RefusalWrong, check_drift_refused("", refusal, 1, &the_pin));
    const other = "error[ZBX-E0801]: x\n" ++ refusal;
    try testing.expectError(error.RefusalWrong, check_drift_refused("", other, 3, &the_pin));
    const headless = refusal_head[0 .. refusal_head.len - 2];
    try testing.expectError(error.RefusalWrong, check_drift_refused("", headless, 3, &the_pin));
    const ran = "  fetch   miss   0.10 s  net\n  use   miss   0.01 s\n";
    try testing.expectError(error.PinWrong, check_drift_refused(ran, refusal, 3, &the_pin));
    const same = refusal_head ++ "step fetch produced " ++ pinned_text ++ ", and its pin is " ++
        pinned_text ++ "\n";
    try testing.expectError(error.PinWrong, check_drift_refused("", same, 3, &the_pin));
    // The digests swapped: the pin named is not the lock's.
    const swapped = refusal_head ++ "step fetch produced " ++ pinned_text ++ ", and its pin is " ++
        output_text ++ "\n";
    try testing.expectError(error.PinWrong, check_drift_refused("", swapped, 3, &the_pin));
}

test "the drift warning names the refusal's digests, and use misses" {
    const drift = try check_drift_refused("", refusal, 3, &the_pin);
    var report = one_row("use", false, "", "");
    const warned = "warning[ZBX-W0801]: x\nwarning[ZBX-W0803]: y\n  cause  step fetch produced " ++
        output_text ++
        ", and its pin is " ++ pinned_text ++ "\n";
    try check_drift_warned(&report, warned, 0, &drift);
    try testing.expectError(error.ReportWrong, check_drift_warned(&report, warned, 1, &drift));
    try testing.expectError(error.ReportWrong, check_drift_warned(&report, refusal, 0, &drift));
    var other = drift;
    other.output[3] = '3';
    try check_drift_warned(&report, warned, 0, &other);
    other.pinned[3] = '3';
    try testing.expectError(error.PinWrong, check_drift_warned(&report, warned, 0, &other));
    report.rows[0].hit = true;
    try testing.expectError(error.PinWrong, check_drift_warned(&report, warned, 0, &drift));
}

test "steady: the first VM's pin and after's key, then the same in the second VM" {
    const steady_lock =
        try std.mem.replaceOwned(u8, testing.allocator, pinned_lock, "\"fetch\"", "\"steady\"");
    defer testing.allocator.free(steady_lock);
    var report = one_row("steady", true, key_text, pinned_text);
    report.count = 2;
    report.rows[1] = report.rows[0];
    report.rows[1].name = "after";
    report.rows[1].key = output_text;
    var pin = pin_of(steady_lock, "steady").?;
    try testing.expect(pin_of(pinned_lock, "steady") == null);
    const first = try steady_of(&report, &pin);
    try testing.expectEqualStrings(pinned_text, &first.output);
    try testing.expectEqualStrings(output_text, &first.after_key);
    pin.key = pin.output;
    try testing.expectError(error.PinWrong, steady_of(&report, &pin));
    report.rows[0].hit = false;
    report.rows[1].hit = false;
    try check_steady_same(&report, "warning[ZBX-W0801]: x\n", 0, &first);
    try testing.expectError(error.ReportWrong, check_steady_same(&report, "", 3, &first));
    const drifted = "warning[ZBX-W0803]: y\n";
    try testing.expectError(error.PinWrong, check_steady_same(&report, drifted, 0, &first));
    report.rows[1].key = key_text;
    try testing.expectError(error.PinWrong, check_steady_same(&report, "", 0, &first));
    report.rows[1].key = output_text;
    report.rows[0].output = output_text;
    try testing.expectError(error.PinWrong, check_steady_same(&report, "", 0, &first));
}
