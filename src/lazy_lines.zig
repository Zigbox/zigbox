//! What a lazy run shows (S2 slice 5): the resolver's events as coded lines on stderr (`W1202`,
//! `E1203`, `E1206`), at most `lazy_errors_shown_max` a run and then one count line; the progress
//! line when the server starts and the summary line after the run.
//!
//! A line names the object's id and the chunk, not the file: the catalog has no paths (a cut,
//! recorded in docs/demos/s2.md).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const lazy = @import("lazy/lazy.zig");
const lazy_diagnose = @import("fuse/diagnose.zig");
const render = @import("diag/render.zig");
const size_words = @import("store_commands.zig").size_words;
const Diag = @import("diag/diag.zig").Diag;
const Host = @import("host.zig").Host;

/// Room for "registry: timed out; peer ...: not found" over every source.
const tried_bytes_max = 512;
pub const line_bytes_max = 256;

/// The run's lines. Events come from the resolver's threads: the count is atomic, and each line
/// is one write.
pub const Lines = struct {
    host: Host,
    mode: render.Mode,
    color: bool,
    /// Events seen; those past `lazy_errors_shown_max` are counted, not shown.
    seen: std.atomic.Value(u64),

    pub fn init(host: Host, mode: render.Mode, color: bool) Lines {
        return .{ .host = host, .mode = mode, .color = color, .seen = .init(0) };
    }

    pub fn log(lines: *Lines) lazy.Log {
        return .{ .context = lines, .event = event };
    }

    /// Events not shown: past `lazy_errors_shown_max`, or dropped by the resolver.
    pub fn hidden(lines: *const Lines, report: *const lazy.Report) u64 {
        const seen = lines.seen.load(.monotonic);
        return seen -| constants.lazy_errors_shown_max + report.events_dropped;
    }

    fn event(context: *anyopaque, given: *const lazy.Event) void {
        const lines: *Lines = @ptrCast(@alignCast(context));
        const at = lines.seen.fetchAdd(1, .monotonic);
        if (at >= constants.lazy_errors_shown_max) return;
        var diag: Diag = undefined;
        diag.reset();
        describe(&diag, given);
        var buffer: [constants.output_bytes_max]u8 = undefined;
        const text = render.render(&diag, lines.mode, lines.color, &buffer);
        // A line that cannot be written is lost; the read already got `EIO`.
        lines.host.write_all(.stderr, text) catch return;
    }

    /// The progress line, once (`started`): the index's size and what is not yet local.
    pub fn progress(lines: *const Lines, index_bytes: u64, report: *const lazy.Report) void {
        var buffer: [line_bytes_max]u8 = undefined;
        const text = progress_text(&buffer, index_bytes, report);
        lines.host.write_all(.stderr, text) catch return;
    }

    /// After the run: the summary line, and the count of lines not shown when there are any.
    pub fn summary(
        lines: *const Lines,
        report: *const lazy.Report,
        names: []const []const u8,
    ) void {
        var buffer: [line_bytes_max * 2]u8 = undefined;
        const text = summary_text(&buffer, report, names, lines.hidden(report));
        lines.host.write_all(.stderr, text) catch return;
    }
};

/// The diagnostic of one event.
pub fn describe(diag: *Diag, given: *const lazy.Event) void {
    assert(diag.code == null);
    assert(given.sources_count <= constants.lazy_sources_max);
    switch (given.kind) {
        .lied => lazy_diagnose.chunk_lied(diag, given.source, given.id, given.chunk),
        .unavailable => {
            var buffer: [tried_bytes_max]u8 = undefined;
            const tried = tried_text(&buffer, given);
            lazy_diagnose.chunk_unavailable(diag, given.id, given.chunk, tried);
        },
        .store_full => lazy_diagnose.store_full(diag, given.id, given.chunk),
    }
    assert(diag.code != null);
}

/// What each source did: "registry: timed out; peer 10.0.0.3: not found". Cut at the buffer.
pub fn tried_text(buffer: *[tried_bytes_max]u8, given: *const lazy.Event) []const u8 {
    assert(given.sources_count <= constants.lazy_sources_max);
    var writer = std.Io.Writer.fixed(buffer);
    for (0..given.sources_count) |at| {
        const separator: []const u8 = if (at == 0) "" else "; ";
        const name = given.names[at];
        writer.print("{s}{s}: {s}", .{ separator, name, given.outcomes[at].text() }) catch break;
    }
    const text = writer.buffered();
    if (text.len == 0) return "no source to ask";
    return text;
}

/// "lazy: index 2.1 MiB, starting (3.0 GiB not yet local)\n"
pub fn progress_text(
    buffer: *[line_bytes_max]u8,
    index_bytes: u64,
    report: *const lazy.Report,
) []const u8 {
    assert(report.bytes_local <= report.bytes_total);
    var index_words: [32]u8 = undefined;
    var missing_words: [32]u8 = undefined;
    const missing = report.bytes_total - report.bytes_local;
    return std.fmt.bufPrint(buffer, "lazy: index {s}, starting ({s} not yet local)\n", .{
        size_words(&index_words, index_bytes),
        size_words(&missing_words, missing),
    }) catch unreachable; // Two sizes of at most 32 bytes each.
}

/// "lazy: 41.0 MiB fetched on first read, 0 B in the background; image 38% local;
/// registry sent 43012345 bytes\n", then "lazy: 3 more lines not shown\n" when some were not.
/// The exact counts of bytes each source sent are the ones its own counter can be checked
/// against.
pub fn summary_text(
    buffer: *[line_bytes_max * 2]u8,
    report: *const lazy.Report,
    names: []const []const u8,
    hidden: u64,
) []const u8 {
    assert(names.len <= constants.lazy_sources_max);
    assert(report.bytes_local <= report.bytes_total);
    var writer = std.Io.Writer.fixed(buffer);
    var demand_words: [32]u8 = undefined;
    var fill_words: [32]u8 = undefined;
    const percent = if (report.bytes_total == 0) 100 else report.bytes_local * 100 /
        report.bytes_total;
    writer.print("lazy: {s} fetched on first read, {s} in the background; image {d}% local", .{
        size_words(&demand_words, report.fetched_on_demand_bytes),
        size_words(&fill_words, report.fetched_fill_bytes),
        percent,
    }) catch unreachable; // Far under the buffer.
    for (names, 0..) |name, at| {
        // A name too long for the line is cut with the rest; the counts above stand.
        writer.print("; {s} sent {d} bytes", .{ name, report.source_bytes[at] }) catch break;
    }
    writer.writeAll("\n") catch {
        buffer[buffer.len - 1] = '\n';
        return buffer;
    };
    if (hidden > 0) writer.print("lazy: {d} more lines not shown\n", .{hidden}) catch {};
    return writer.buffered();
}

const testing = std.testing;

fn report_of(local: u64, total: u64) lazy.Report {
    var report = std.mem.zeroes(lazy.Report);
    report.bytes_local = local;
    report.bytes_total = total;
    return report;
}

test "progress line" {
    var buffer: [line_bytes_max]u8 = undefined;
    const report = report_of(1 << 30, 4 << 30);
    const text = progress_text(&buffer, 2202009, &report);
    try testing.expectEqualStrings("lazy: index 2.1 MiB, starting (3.0 GiB not yet local)\n", text);
}

test "summary line, with the lines not shown" {
    var buffer: [line_bytes_max * 2]u8 = undefined;
    var report = report_of(38, 100);
    report.fetched_on_demand_bytes = 41 << 20;
    report.source_bytes[0] = 43012345;
    const text = summary_text(&buffer, &report, &.{"registry"}, 3);
    try testing.expectEqualStrings(
        "lazy: 41.0 MiB fetched on first read, 0 B in the background; image 38% local; " ++
            "registry sent 43012345 bytes\nlazy: 3 more lines not shown\n",
        text,
    );
}

test "an empty image is all local" {
    var buffer: [line_bytes_max * 2]u8 = undefined;
    const report = report_of(0, 0);
    const text = summary_text(&buffer, &report, &.{}, 0);
    try testing.expectEqualStrings(
        "lazy: 0 B fetched on first read, 0 B in the background; image 100% local\n",
        text,
    );
}

test "the sources tried, in order" {
    const names: [constants.lazy_sources_max][]const u8 = @splat("registry");
    var given: lazy.Event = .{
        .kind = .unavailable,
        .object = 0,
        .id = undefined,
        .chunk = 3,
        .source = "",
        .outcomes = @splat(.not_tried),
        .sources_count = 0,
        .names = &names,
    };
    var buffer: [tried_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("no source to ask", tried_text(&buffer, &given));
    given.sources_count = 1;
    given.outcomes[0] = .timed_out;
    try testing.expectEqualStrings("registry: timed out", tried_text(&buffer, &given));
}

test "lines past the bound are counted, not shown" {
    var lines = Lines.init(undefined, .text, false);
    var report = report_of(0, 0);
    lines.seen.store(constants.lazy_errors_shown_max, .monotonic);
    try testing.expectEqual(@as(u64, 0), lines.hidden(&report));
    lines.seen.store(constants.lazy_errors_shown_max + 1, .monotonic);
    try testing.expectEqual(@as(u64, 1), lines.hidden(&report));
    report.events_dropped = 2;
    try testing.expectEqual(@as(u64, 3), lines.hidden(&report));
}
