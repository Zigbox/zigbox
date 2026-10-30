//! `zbx logs NAME [--follow] [--tail N] [--stream stdout|stderr] [--output json]`: shows what a
//! container wrote to its standard output and error, from the log `runtime/logfile.zig` keeps.
//!
//! Text is the bytes as the container wrote them, both streams in the order they arrived. With
//! `--output json` each record is one line of the `zbx.logs/1` schema. `--tail N` is the last N
//! lines (found by counting newlines in a first pass over the log, so nothing is held in
//! memory). `--follow` goes on reading as the container writes, and ends, exit 0, when the
//! container has ended and what it wrote has been shown.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const diagnose = @import("runtime/diagnose.zig");
const lifecycle = @import("runtime/lifecycle.zig");
const logfile = @import("runtime/logfile.zig");
const records = @import("runtime/records.zig");
const run = @import("runtime/run.zig");
const Diag = @import("diag/diag.zig").Diag;
const errors = @import("diag/errors.zig");

const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// A line of JSON for one record is at most this: 4096 bytes each escaped to six, and the
/// members around them.
pub const line_bytes_max: u32 = constants.log_record_bytes_max * 6 + 256;

/// The command's memory: the reader's two windows, the record of the container (for `--follow`,
/// to see when it has ended) and the output buffer.
pub const Workspace = struct {
    reader: logfile.Reader,
    record: records.Parsed,
    out: [2 * line_bytes_max]u8,
    out_len: u32,
};

pub const Options = struct {
    name: []const u8,
    follow: bool = false,
    /// The last N lines only; null shows everything.
    tail: ?u32 = null,
    stream: ?logfile.Stream = null,
    json: bool = false,
    /// Where a warning goes (the dropped output of a full log).
    warn: ?run.Warn = null,
};

/// A value of `--tail`: a whole number of lines from 0 to the bound.
pub fn parse_tail(text: []const u8) ?u32 {
    assert(constants.log_tail_lines_max < std.math.maxInt(u32));
    assert(text.len <= constants.arg_bytes_max);
    if (text.len == 0 or text.len > 10) return null;
    const value = std.fmt.parseInt(u32, text, 10) catch return null;
    if (value > constants.log_tail_lines_max) return null;
    return value;
}

pub fn parse_stream(text: []const u8) ?logfile.Stream {
    assert(text.len <= constants.arg_bytes_max);
    assert(@tagName(logfile.Stream.stdout).len == 6);
    if (std.mem.eql(u8, text, "stdout")) return .stdout;
    if (std.mem.eql(u8, text, "stderr")) return .stderr;
    return null;
}

pub fn run_logs(host: Host, ws: *Workspace, options: Options, diag: *Diag) Error!void {
    assert(options.name.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    ws.out_len = 0;
    var runs: records.Dir = undefined;
    if (!records.locate(host, &runs)) {
        diagnose.no_such_container(diag, options.name, .no_state);
        return error.Failed;
    }
    records.load(host, &runs, options.name, &ws.record) catch |err| {
        const missing = err == error.NotFound;
        const why: diagnose.NoContainer = if (missing) .no_record else .unreadable_record;
        diagnose.no_such_container(diag, options.name, why);
        return error.Failed;
    };
    const logs = logfile.dir_of(&runs) orelse return no_log(diag, options.name);
    const fs = host.log_files();
    var skip: Skip = .{ .lines = 0, .end = 0 };
    if (options.tail) |lines| skip = try lines_to_skip(fs, &logs, ws, options, lines, diag);
    try open_reader(fs, &logs, ws, options.name, diag);
    defer ws.reader.close();
    var show: Shown = .{
        .skip_lines = skip.lines,
        .first = true,
        .snapshot_end = skip.end,
        .from_start = skip.lines == 0,
    };
    note_dropped(ws, options, skip.lines);
    try show_available(host, ws, options, &show, diag);
    if (options.follow) try follow(host, ws, options, &show, diag);
    try flush(host, ws, diag);
}

fn no_log(diag: *Diag, name: []const u8) Error {
    assert(diag.code == null);
    assert(name.len > 0);
    diagnose.no_log(diag, name);
    return error.Failed;
}

fn open_reader(
    fs: logfile.Fs,
    logs: *const records.Dir,
    ws: *Workspace,
    name: []const u8,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    assert(name.len > 0);
    ws.reader.open(fs, logs, name) catch |err| switch (err) {
        error.NoLog => return no_log(diag, name),
        error.Newer => {
            diagnose.log_unreadable(diag, name, .newer, null);
            return error.Failed;
        },
        error.Damaged => {
            diagnose.log_unreadable(diag, name, .damaged, null);
            return error.Failed;
        },
        error.Unreadable => {
            const failure: diagnose.Failure = .{
                .step = 0,
                .err = error.IoFailed,
                .errno = fs.last_errno(),
            };
            diagnose.log_unreadable(diag, name, .unreadable, failure);
            return error.Failed;
        },
    };
}

/// How many lines of the log come before its last `lines`: the newlines of the selected stream
/// counted over the whole log, a last line without a newline counting as one.
fn lines_to_skip(
    fs: logfile.Fs,
    logs: *const records.Dir,
    ws: *Workspace,
    options: Options,
    lines: u32,
    diag: *Diag,
) Error!Skip {
    assert(lines <= constants.log_tail_lines_max);
    assert(options.tail != null);
    try open_reader(fs, logs, ws, options.name, diag);
    defer ws.reader.close();
    var newlines: u64 = 0;
    var last: u8 = '\n';
    var end: u64 = 0;
    for (0..records_bound) |_| {
        const found = switch (ws.reader.next()) {
            .record => |item| item,
            .end, .damaged => break,
            .failed => break,
        };
        end = found.offset + found.payload.len;
        if (!selected(options, found.stream)) continue;
        newlines += std.mem.count(u8, found.payload, "\n");
        last = found.payload[found.payload.len - 1];
    }
    const total = newlines + @intFromBool(last != '\n');
    assert(total >= newlines);
    return .{ .lines = total -| lines, .end = end };
}

/// What `--tail` found: how many lines of the log to skip, and where the log ended then.
const Skip = struct { lines: u64, end: u64 };

/// More records than a log can hold (the cap over the smallest record).
const records_bound: u32 = constants.log_segment_bytes_max;

fn selected(options: Options, stream: logfile.Stream) bool {
    assert(@backingInt(stream) >= 1);
    assert(@backingInt(stream) <= 2);
    const wanted = options.stream orelse return true;
    return wanted == stream;
}

/// Where the output is: lines still to skip for `--tail`, and whether nothing has been shown.
const Shown = struct {
    skip_lines: u64,
    first: bool,
    /// `--tail` counted the lines of the log as it was when the count was made, which ends here
    /// in the stream: what the container wrote after that is shown whole, never skipped.
    snapshot_end: u64,
    /// Nothing at the start of the log is skipped, so its dropped output is the reader's to say.
    from_start: bool,
};

/// The bytes of `payload` after `skip` newlines have been passed (all of them if there are
/// fewer); `skip` is what is left to pass.
fn after_skipped(payload: []const u8, skip: *u64) []const u8 {
    assert(payload.len <= constants.log_record_bytes_max);
    const before = skip.*;
    defer assert(skip.* <= before);
    var rest = payload;
    while (skip.* > 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse return rest[rest.len..];
        skip.* -= 1;
        rest = rest[at + 1 ..];
    }
    return rest;
}

/// A log that dropped output says so (a warning on stderr), unless `--tail` showed only the end
/// of it. The JSON records carry the number too.
fn note_dropped(ws: *Workspace, options: Options, skip: u64) void {
    assert(options.name.len > 0);
    assert(@backingInt(ws.reader.stage) <= 1);
    if (skip > 0) return;
    const dropped = ws.reader.dropped_bytes;
    if (dropped == 0) return;
    const warn = options.warn orelse return;
    var warning: Diag = undefined;
    warning.reset();
    diagnose.logs_dropped(&warning, options.name, dropped);
    warn.call(warn.context, &warning);
}

/// Shows every record that is there now. Ends at the end of the log, a torn record included.
fn show_available(
    host: Host,
    ws: *Workspace,
    options: Options,
    show: *Shown,
    diag: *Diag,
) Error!void {
    assert(show.skip_lines <= constants.log_bytes_max);
    assert(ws.out_len <= ws.out.len);
    for (0..records_bound) |_| {
        const found = switch (ws.reader.next()) {
            .record => |item| item,
            .end, .damaged, .failed => return,
        };
        if (!selected(options, found.stream)) continue;
        const payload = if (found.offset >= show.snapshot_end)
            found.payload
        else
            after_skipped(found.payload, &show.skip_lines);
        if (payload.len == 0) continue;
        try emit(host, ws, options, show, found, payload, diag);
    }
}

fn emit(
    host: Host,
    ws: *Workspace,
    options: Options,
    show: *Shown,
    found: logfile.Record,
    payload: []const u8,
    diag: *Diag,
) Error!void {
    assert(payload.len > 0);
    assert(payload.len <= found.payload.len);
    assert(ws.out_len <= ws.out.len);
    if (ws.out_len + line_bytes_max > ws.out.len) try flush(host, ws, diag);
    var writer = std.Io.Writer.fixed(ws.out[ws.out_len..]);
    if (options.json) {
        const dropped = if (show.first and show.from_start) ws.reader.dropped_bytes else 0;
        // Cannot fail: a record's line is at most `line_bytes_max` and the buffer has that much
        // room after the flush above.
        write_json_line(&writer, found, payload, dropped) catch unreachable;
    } else {
        writer.writeAll(payload) catch unreachable; // Same bound: a record is under a line's.
    }
    ws.out_len += @intCast(writer.buffered().len);
    show.first = false;
}

pub fn write_json_line(
    writer: *std.Io.Writer,
    found: logfile.Record,
    payload: []const u8,
    dropped_bytes: u64,
) std.Io.Writer.Error!void {
    assert(payload.len > 0);
    assert(payload.len <= constants.log_record_bytes_max);
    assert(found.time < constants.log_time_max);
    var lossy = false;
    var probe = payload;
    while (probe.len > 0) {
        const step = utf8_step(probe);
        if (step.bad) lossy = true;
        probe = probe[step.length..];
    }
    try writer.print("{{\"schema\":\"zbx.logs/1\",\"stream\":\"{s}\",\"time\":{d},\"text\":\"", .{
        found.stream.word(), found.time,
    });
    var rest = payload;
    while (rest.len > 0) {
        const step = utf8_step(rest);
        if (step.bad) {
            try writer.writeAll("\u{fffd}");
        } else {
            try write_json_piece(writer, rest[0..step.length]);
        }
        rest = rest[step.length..];
    }
    try writer.writeByte('"');
    if (lossy) try writer.writeAll(",\"lossy\":true");
    if (dropped_bytes > 0) try writer.print(",\"dropped_bytes\":{d}", .{dropped_bytes});
    try writer.writeAll("}\n");
}

const Step = struct { length: usize, bad: bool };

/// The next character of `bytes` as UTF-8: its length, or one byte that is not part of one.
fn utf8_step(bytes: []const u8) Step {
    assert(bytes.len > 0);
    assert(bytes.len <= constants.log_record_bytes_max);
    const bad: Step = .{ .length = 1, .bad = true };
    const length = std.unicode.utf8ByteSequenceLength(bytes[0]) catch return bad;
    if (length > bytes.len) return .{ .length = 1, .bad = true };
    if (!std.unicode.utf8ValidateSlice(bytes[0..length])) return .{ .length = 1, .bad = true };
    return .{ .length = length, .bad = false };
}

fn write_json_piece(writer: *std.Io.Writer, piece: []const u8) std.Io.Writer.Error!void {
    assert(piece.len > 0);
    assert(piece.len <= 4);
    if (piece.len > 1) return writer.writeAll(piece);
    switch (piece[0]) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try writer.print("\\u{x:0>4}", .{piece[0]}),
        else => try writer.writeByte(piece[0]),
    }
}

fn flush(host: Host, ws: *Workspace, diag: *Diag) Error!void {
    assert(ws.out_len <= ws.out.len);
    assert(diag.code == null);
    if (ws.out_len == 0) return;
    // The host writes at most `output_bytes_max` at a time.
    var at: u32 = 0;
    while (at < ws.out_len) {
        const piece = @min(ws.out_len - at, constants.output_bytes_max);
        host.write_all(.stdout, ws.out[at..][0..piece]) catch |err| {
            errors.output_failed(diag, .stdout, err, host.last_errno());
            return error.OutputFailed;
        };
        at += piece;
    }
    ws.out_len = 0;
}

/// Goes on reading as the container writes, until it has ended and what it wrote is shown. The
/// loop ends with the container, not by a count: a container can run for ever.
fn follow(host: Host, ws: *Workspace, options: Options, show: *Shown, diag: *Diag) Error!void {
    assert(options.follow);
    assert(diag.code == null);
    while (true) {
        try flush(host, ws, diag);
        if (container_ended(host, ws, options.name)) {
            // What it wrote just before it ended, and a rotation the last look may have missed.
            try finish_rotation(host, ws, options, show, diag);
            try show_available(host, ws, options, show, diag);
            return;
        }
        host.sleep_ms(constants.log_follow_poll_ms);
        try finish_rotation(host, ws, options, show, diag);
        try show_available(host, ws, options, show, diag);
    }
}

/// If the log was rotated, the rest of the file this reader has open is shown, and then the new
/// one is taken up.
fn finish_rotation(
    host: Host,
    ws: *Workspace,
    options: Options,
    show: *Shown,
    diag: *Diag,
) Error!void {
    assert(options.follow);
    assert(show.skip_lines <= constants.log_bytes_max);
    if (!ws.reader.follow_look()) return;
    try show_available(host, ws, options, show, diag);
    _ = ws.reader.follow_switch();
}

fn container_ended(host: Host, ws: *Workspace, name: []const u8) bool {
    assert(name.len > 0);
    assert(name.len <= constants.container_name_bytes_max);
    var runs: records.Dir = undefined;
    if (!records.locate(host, &runs)) return true;
    records.load(host, &runs, name, &ws.record) catch return true;
    return lifecycle.state_of(host, &ws.record) != .running;
}

const testing = std.testing;

test "parse_tail and parse_stream accept what the options mean and nothing else" {
    // Goal: the bounds of --tail (0 to one million, digits only) and the two stream names.
    try testing.expectEqual(@as(?u32, 0), parse_tail("0"));
    try testing.expectEqual(@as(?u32, 1_000_000), parse_tail("1000000"));
    try testing.expectEqual(@as(?u32, null), parse_tail("1000001"));
    try testing.expectEqual(@as(?u32, null), parse_tail(""));
    try testing.expectEqual(@as(?u32, null), parse_tail("-1"));
    try testing.expectEqual(@as(?u32, null), parse_tail("ten"));
    try testing.expectEqual(@as(?u32, null), parse_tail("99999999999"));
    try testing.expectEqual(logfile.Stream.stderr, parse_stream("stderr").?);
    try testing.expect(parse_stream("both") == null);
    try testing.expect(parse_stream("") == null);
}

test "after_skipped passes whole lines and keeps the rest" {
    var skip: u64 = 2;
    try testing.expectEqualStrings("c\nd", after_skipped("a\nb\nc\nd", &skip));
    try testing.expectEqual(@as(u64, 0), skip);
    skip = 3;
    try testing.expectEqualStrings("", after_skipped("a\nb\n", &skip));
    try testing.expectEqual(@as(u64, 1), skip);
    skip = 0;
    try testing.expectEqualStrings("x", after_skipped("x", &skip));
}

test "a JSON line escapes controls, keeps UTF-8 and marks bytes that are not" {
    // Goal: the line is valid JSON for any bytes, and says when it had to change them.
    var storage: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const found: logfile.Record = .{ .stream = .stderr, .time = 42, .payload = "", .offset = 0 };
    try write_json_line(&writer, found, "a\"b\\c\n\x01\xc3\xa9\xff", 7);
    const expected = "{\"schema\":\"zbx.logs/1\",\"stream\":\"stderr\",\"time\":42," ++
        "\"text\":\"a\\\"b\\\\c\\n\\u0001\u{e9}\u{fffd}\",\"lossy\":true,\"dropped_bytes\":7}\n";
    try testing.expectEqualStrings(expected, writer.buffered());
    const text = writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("zbx.logs/1", parsed.value.object.get("schema").?.string);
}

test "the longest record fits the line bound" {
    // Goal: the worst case, every byte escaped to six, is inside `line_bytes_max`.
    var storage: [line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    var payload: [constants.log_record_bytes_max]u8 = @splat(0x01);
    const found: logfile.Record = .{ .stream = .stdout, .time = 1, .payload = "", .offset = 0 };
    try write_json_line(&writer, found, &payload, std.math.maxInt(u64));
    try testing.expect(writer.buffered().len < line_bytes_max);
}
