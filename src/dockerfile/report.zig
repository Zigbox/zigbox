//! What an import tells its user: one line per step with its Dockerfile line and its flags,
//! then what did not carry over as an instruction, then the counts. Text for a person,
//! `zbx.import/1` JSON for a program (`zbx schema import`).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const Writer = std.Io.Writer;

pub const schema = "zbx.import/1";

pub const Kind = enum { run, copy };

pub const Step = struct {
    name: [constants.build_step_name_bytes_max]u8,
    name_len: u8,
    line: u32,
    kind: Kind,
    /// The table phrase that matched (`apk add`), `--network all`, or null for no network.
    network: ?[]const u8,
    cache: bool,
    bind: bool,

    pub fn name_text(step: *const Step) []const u8 {
        assert(step.name_len > 0);
        return step.name[0..step.name_len];
    }

    pub fn flagged(step: *const Step) bool {
        return step.network != null or step.cache or step.bind;
    }
};

pub const note_bytes_max = 96;

/// A part of the Dockerfile that did not become an instruction of the build file.
pub const Dropped = struct {
    line: u32,
    /// What it was: `EXPOSE`, `# syntax`, `ARG BUILDKIT_INLINE_CACHE`.
    what: [note_bytes_max]u8,
    what_len: u8,
    /// What became of it: `label org.zigbox.import.expose`, `ignored`.
    became: [note_bytes_max]u8,
    became_len: u8,

    pub fn what_text(dropped: *const Dropped) []const u8 {
        return dropped.what[0..dropped.what_len];
    }

    pub fn became_text(dropped: *const Dropped) []const u8 {
        return dropped.became[0..dropped.became_len];
    }
};

pub const Report = struct {
    dockerfile: []const u8,
    target: []const u8,
    stages_count: u32,
    steps: [constants.build_steps_max]Step,
    steps_count: u32,
    dropped: [constants.import_report_lines_max]Dropped,
    dropped_count: u32,

    pub fn steps_slice(report: *const Report) []const Step {
        assert(report.steps_count <= constants.build_steps_max);
        return report.steps[0..report.steps_count];
    }

    pub fn dropped_slice(report: *const Report) []const Dropped {
        assert(report.dropped_count <= constants.import_report_lines_max);
        return report.dropped[0..report.dropped_count];
    }

    pub fn flagged_count(report: *const Report) u32 {
        var count: u32 = 0;
        for (report.steps_slice()) |*step| count += @intFromBool(step.flagged());
        return count;
    }

    /// Notes a dropped part; a note past the report's bound is counted as the last line says.
    pub fn drop(report: *Report, line: u32, what: []const u8, became: []const u8) void {
        if (report.dropped_count == constants.import_report_lines_max) return;
        const entry = &report.dropped[report.dropped_count];
        entry.line = line;
        entry.what_len = copy_cut(&entry.what, what);
        entry.became_len = copy_cut(&entry.became, became);
        report.dropped_count += 1;
        assert(report.dropped_count <= constants.import_report_lines_max);
    }
};

fn copy_cut(buffer: *[note_bytes_max]u8, text: []const u8) u8 {
    const length = @min(text.len, note_bytes_max);
    @memcpy(buffer[0..length], text[0..length]);
    for (buffer[0..length]) |*byte| {
        if (byte.* < 0x20 or byte.* >= 0x7f) byte.* = '?';
    }
    return @intCast(length);
}

/// The text report: the step lines, the dropped parts, and the counts. The warnings that close
/// it (W0810, W0811) are the caller's, as diagnostics.
pub fn render_text(report: *const Report, output: []const u8, writer: *Writer) !void {
    assert(report.steps_count <= constants.build_steps_max);
    for (report.steps_slice()) |*step| {
        try writer.print("{s}  {s}:{d}  {t}", .{
            step.name_text(), report.dockerfile, step.line, step.kind,
        });
        if (step.network) |phrase| try writer.print("  net (matched \"{s}\")", .{phrase});
        if (step.cache) try writer.writeAll("  cache");
        if (step.bind) try writer.writeAll("  bind");
        try writer.writeAll("\n");
    }
    if (report.dropped_count > 0) try writer.writeAll("not carried over as instructions:\n");
    for (report.dropped_slice()) |*dropped| {
        try writer.print("  {s}:{d}  {s}: {s}\n", .{
            report.dockerfile, dropped.line, dropped.what_text(), dropped.became_text(),
        });
    }
    try writer.print("imported {d} steps from {d} stages (target {s}) to {s}; {d} flagged\n", .{
        report.steps_count, report.stages_count, report.target, output, report.flagged_count(),
    });
}

/// The `zbx.import/1` document.
pub fn render_json(report: *const Report, output: []const u8, writer: *Writer) !void {
    assert(report.steps_count <= constants.build_steps_max);
    try writer.print("{{\"schema\":\"{s}\",\"dockerfile\":", .{schema});
    try std.json.Stringify.encodeJsonString(report.dockerfile, .{}, writer);
    try writer.writeAll(",\"output\":");
    try std.json.Stringify.encodeJsonString(output, .{}, writer);
    try writer.writeAll(",\"target\":");
    try std.json.Stringify.encodeJsonString(report.target, .{}, writer);
    try writer.print(",\"stages\":{d},\"steps\":[", .{report.stages_count});
    for (report.steps_slice(), 0..) |*step, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("{{\"name\":\"{s}\",\"line\":{d},\"kind\":\"{t}\",\"network\":", .{
            step.name_text(), step.line, step.kind,
        });
        if (step.network) |phrase| {
            try std.json.Stringify.encodeJsonString(phrase, .{}, writer);
        } else try writer.writeAll("null");
        try writer.print(",\"cache\":{},\"bind\":{}}}", .{ step.cache, step.bind });
    }
    try writer.writeAll("],\"dropped\":[");
    for (report.dropped_slice(), 0..) |*dropped, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.print("{{\"line\":{d},\"what\":", .{dropped.line});
        try std.json.Stringify.encodeJsonString(dropped.what_text(), .{}, writer);
        try writer.writeAll(",\"became\":");
        try std.json.Stringify.encodeJsonString(dropped.became_text(), .{}, writer);
        try writer.writeAll("}");
    }
    try writer.print("],\"flagged\":{d}}}\n", .{report.flagged_count()});
}

const testing = std.testing;

test "the report shows each step's line and flags, then what was dropped" {
    // Goal: the text and JSON forms carry the same facts. Method: a report with a flagged
    // step and a dropped line, rendered both ways and searched.
    var report: Report = undefined;
    report.dockerfile = "Dockerfile";
    report.target = "tools";
    report.stages_count = 1;
    report.dropped_count = 0;
    report.steps_count = 1;
    report.steps[0] = .{
        .name = undefined, .name_len = 7, .line = 11, .kind = .run,
        .network = "apk add", .cache = true, .bind = false,
    };
    @memcpy(report.steps[0].name[0..7], "tools-1");
    report.drop(9, "EXPOSE", "label org.zigbox.import.expose");
    var buffer: [1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render_text(&report, "t.zon", &writer);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "tools-1  Dockerfile:11  run  net (matched " ++
        "\"apk add\")  cache\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Dockerfile:9  EXPOSE: label") != null);
    var json_buffer: [1024]u8 = undefined;
    var json_writer: Writer = .fixed(&json_buffer);
    try render_json(&report, "t.zon", &json_writer);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator,
        json_writer.buffered(), .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 1), parsed.value.object.get("flagged").?.integer);
}
