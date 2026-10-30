//! The commands that look at containers after they have started: `ps`, `stop` and `schema`
//! (`run -d` and its supervisor are in `cli.zig`, beside `run`). Each takes the host and what
//! the command line said, writes its result to stdout (text, or one JSON object with
//! `--output json`; the schemas are `schemas.zig`), and reports a failure as a diagnostic. None
//! of them prompts.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const diagnose = @import("runtime/diagnose.zig");
const lifecycle = @import("runtime/lifecycle.zig");
const records = @import("runtime/records.zig");
const run = @import("runtime/run.zig");
const schemas = @import("schemas.zig");
const Diag = @import("diag/diag.zig").Diag;

const Host = host_mod.Host;

pub const Error = error{ Failed, OutputFailed };

/// A whole number of milliseconds from `min` to the longest wait, or null.
pub fn parse_millis(text: []const u8, min: u32) ?u32 {
    assert(min <= 1);
    assert(constants.wait_timeout_ms_max > 0);
    if (text.len == 0 or text.len > 10) return null;
    const value = std.fmt.parseInt(u32, text, 10) catch return null;
    if (value < min or value > constants.wait_timeout_ms_max) return null;
    return value;
}

fn write(host: Host, text: []const u8, diag: *Diag) Error!void {
    assert(text.len > 0);
    assert(text.len <= constants.output_bytes_max + 4096);
    host.write_all(.stdout, text) catch |err| {
        @import("diag/errors.zig").output_failed(diag, .stdout, err, host.last_errno());
        return error.OutputFailed;
    };
}

// ---- schema ---------------------------------------------------------------------------------

pub fn run_schema(host: Host, topic: []const u8, diag: *Diag) Error!void {
    assert(topic.len <= constants.arg_bytes_max);
    assert(diag.code == null);
    const text = schemas.of(topic) orelse {
        diagnose.no_schema(diag, topic);
        return error.Failed;
    };
    try write(host, text, diag);
    try write(host, "\n", diag);
}

// ---- ps -------------------------------------------------------------------------------------

/// `prefix` and a number; the caller's buffer is at least 32 bytes.
fn number_words(buffer: []u8, prefix: []const u8, number: u32) []const u8 {
    assert(prefix.len > 0);
    assert(buffer.len >= 32);
    assert(prefix.len <= 8);
    // Cannot fail: a prefix of at most eight bytes and ten digits fit 32 bytes.
    return std.fmt.bufPrint(buffer, "{s}{d}", .{ prefix, number }) catch unreachable;
}

/// The words for how a container ended or where it is: "running", "exited:0", "oom", ...
fn state_words(entry: *const lifecycle.Entry, buffer: []u8) []const u8 {
    assert(buffer.len >= 32);
    assert(entry.name().len > 0);
    const record = &entry.record;
    // Cannot fail: a few words and a number fit 32 bytes.
    switch (entry.state) {
        .running => return "running",
        .lost => return "lost",
        .stopped => {},
    }
    return switch (record.reason) {
        .oom => "oom",
        .pid_limit => "pid_limit",
        else => if (record.timed_out) "timed_out" else switch (record.exit) {
            .exited => |code| number_words(buffer, "exited:", code),
            .signaled => |number| number_words(buffer, "signal:", number),
            .start_failed => "start_failed",
            .running, .lost => "lost",
        },
    };
}

/// "2026-10-26 12:30:05" for seconds since the epoch.
pub fn clock_text(seconds: u64, buffer: *[19]u8) []const u8 {
    assert(buffer.len == 19);
    assert(seconds < 1 << 40); // Year 36000: a corrupt record, not a clock.
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const day = epoch.getEpochDay().calculateYearDay();
    const month_day = day.calculateMonthDay();
    const in_day = epoch.getDaySeconds();
    // Cannot fail: nineteen bytes for the fixed-width fields.
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        in_day.getHoursIntoDay(),
        in_day.getMinutesIntoHour(),
        in_day.getSecondsIntoMinute(),
    }) catch unreachable; // Same bound.
}

fn shown(entry: *const lifecycle.Entry, all: bool) bool {
    assert(entry.name().len > 0);
    assert(entry.name().len <= constants.container_name_bytes_max);
    return all or entry.state != .stopped;
}

pub fn run_ps(
    host: Host,
    entries: []lifecycle.Entry,
    json: bool,
    all: bool,
    diag: *Diag,
) Error!void {
    assert(entries.len > 0);
    assert(entries.len <= constants.runs_max + constants.scopes_listed_max);
    const count = lifecycle.list(host, entries) catch |err| {
        const why: diagnose.NoContainer = switch (err) {
            error.NoState => .no_state,
            else => .unreadable_state,
        };
        diagnose.no_such_container(diag, "", why);
        return error.Failed;
    };
    if (json) return ps_json(host, entries[0..count], all, diag);
    var line: [constants.output_bytes_max]u8 = undefined;
    const head = std.fmt.bufPrint(&line, "{s: <24} {s: <12} {s: >8}  {s: <19}  {s}\n", .{
        "NAME", "STATE", "PID", "STARTED", "COMMAND",
    }) catch unreachable; // A short fixed line.
    try write(host, head, diag);
    for (entries[0..count]) |*entry| {
        if (!shown(entry, all)) continue;
        const text = ps_row(entry, &line);
        try write(host, text, diag);
    }
}

fn ps_row(entry: *const lifecycle.Entry, line: *[constants.output_bytes_max]u8) []const u8 {
    assert(entry.record.command_words <= constants.command_words_count_max);
    assert(line.len >= 512);
    var state_storage: [32]u8 = undefined;
    var when_storage: [19]u8 = undefined;
    const record = &entry.record;
    const started = if (record.started == 0) "-" else clock_text(record.started, &when_storage);
    var writer = std.Io.Writer.fixed(line);
    // Cannot fail: the buffer is a whole message and the row is bounded (name, state, command cut).
    writer.print("{s: <24} {s: <12} {d: >8}  {s: <19}  ", .{
        entry.name(),
        state_words(entry, &state_storage),
        record.pid,
        started,
    }) catch unreachable; // Same bound.
    var words: u32 = 0;
    while (words < record.command_words and writer.end < 200) : (words += 1) {
        if (words > 0) writer.writeByte(' ') catch unreachable; // Same bound as above.
        writer.writeAll(record.command_word(words)) catch unreachable; // Same.
    }
    writer.writeByte('\n') catch unreachable; // Same.
    return writer.buffered();
}

const json_string = @import("bundle.zig").write_json_string;

fn ps_json(host: Host, entries: []const lifecycle.Entry, all: bool, diag: *Diag) Error!void {
    assert(entries.len <= constants.runs_max + constants.scopes_listed_max);
    assert(diag.code == null);
    try write(host, "{\"schema\":\"zbx.ps/1\",\"containers\":[", diag);
    var buffer: [constants.output_bytes_max]u8 = undefined;
    var first = true;
    for (entries) |*entry| {
        if (!shown(entry, all)) continue;
        var writer = std.Io.Writer.fixed(&buffer);
        if (!first) writer.writeByte(',') catch unreachable; // A bounded entry in a whole message.
        first = false;
        entry_json(&writer, entry) catch unreachable; // Same bound.
        try write(host, writer.buffered(), diag);
    }
    try write(host, "]}\n", diag);
}

fn optional_number(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    assert(@typeInfo(@TypeOf(value)) == .optional);
    assert(writer.buffer.len > 0);
    if (value) |number| try writer.print("{d}", .{number}) else try writer.writeAll("null");
}

fn entry_json(writer: *std.Io.Writer, entry: *const lifecycle.Entry) std.Io.Writer.Error!void {
    assert(entry.name().len > 0);
    assert(entry.record.labels_count <= constants.labels_count_max);
    const record = &entry.record;
    var state_storage: [32]u8 = undefined;
    _ = &state_storage;
    try writer.writeAll("{\"name\":");
    try json_string(writer, entry.name());
    const state = switch (entry.state) {
        .running => "running",
        .stopped => "stopped",
        .lost => "lost",
    };
    try writer.print(",\"state\":\"{s}\",\"pid\":{d},\"supervisor\":{d},\"scope\":", .{
        state, record.pid, record.supervisor,
    });
    if (record.scope_len == 0) {
        try writer.writeAll("null");
    } else {
        try json_string(writer, record.scope_slice());
    }
    try writer.print(",\"detached\":{s},\"timed_out\":{s},\"started\":{d},\"ended\":", .{
        if (record.detached) "true" else "false",
        if (record.timed_out) "true" else "false",
        record.started,
    });
    try optional_number(writer, record.ended);
    const reason = if (entry.state == .stopped) @tagName(record.reason) else "none";
    try writer.print(",\"reason\":\"{s}\",\"exit_code\":", .{reason});
    if (entry.state == .stopped) {
        const ended = lifecycle.exit_reason_of(record);
        try optional_number(writer, ended.code());
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"command\":[");
    for (0..record.command_words) |at| {
        if (at > 0) try writer.writeByte(',');
        try json_string(writer, record.command_word(@intCast(at)));
    }
    try writer.writeAll("],\"labels\":[");
    for (0..record.labels_count) |at| {
        if (at > 0) try writer.writeByte(',');
        const pair = record.label(@intCast(at));
        try writer.writeAll("{\"key\":");
        try json_string(writer, pair[0]);
        try writer.writeAll(",\"value\":");
        try json_string(writer, pair[1]);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"limits\":{\"memory_bytes\":");
    try optional_number(writer, record.limits.memory_bytes);
    try writer.writeAll(",\"pids\":");
    try optional_number(writer, record.limits.pids);
    try writer.writeAll(",\"cpu_millis\":");
    try optional_number(writer, record.limits.cpu_millis);
    try writer.writeAll("}");
    try network_json(writer, record);
    try writer.writeAll("}");
}

/// The members M6 added to a container: `network` (null for a record of a zbx that did not keep
/// it), `published` (the forwards, as `run --output json` writes them) and `env`, the names of
/// the variables set with `-e`. A value is never in a record, so never here.
fn network_json(writer: *std.Io.Writer, record: *const records.Parsed) std.Io.Writer.Error!void {
    assert(record.publish_count <= constants.publish_count_max);
    assert(record.env_names_count <= constants.run_env_count_max);
    try writer.writeAll(",\"network\":");
    if (record.network) |network| {
        try writer.print("\"{s}\"", .{network.word()});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"published\":[");
    for (record.publish_slice(), 0..) |forward, index| {
        if (index > 0) try writer.writeByte(',');
        const format = "{{\"host\":{d},\"container\":{d}}}";
        try writer.print(format, .{ forward.host, forward.container });
    }
    try writer.writeAll("],\"env\":[");
    for (0..record.env_names_count) |index| {
        if (index > 0) try writer.writeByte(',');
        try json_string(writer, record.env_name(@intCast(index)));
    }
    try writer.writeAll("]");
    try writable_json(writer, record);
}

/// The members M6b added: `writable_mounts` (each `--mount` by its resolved host path and its
/// target; empty for a record of an older zbx) and `user` (the user the command ran as, null for
/// a record that did not say).
fn writable_json(writer: *std.Io.Writer, record: *const records.Parsed) std.Io.Writer.Error!void {
    assert(record.mounts_count <= constants.mounts_max);
    try writer.writeAll(",\"writable_mounts\":[");
    assert((record.mounts_len > 0) == (record.mounts_count > 0));
    var first = true;
    for (0..record.mounts_count) |index| {
        const mount = record.mount_at(@intCast(index));
        if (mount.kind != .mount) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"host\":");
        try json_string(writer, mount.source);
        try writer.writeAll(",\"target\":");
        try json_string(writer, mount.target);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"user\":");
    if (record.user) |user| {
        try writer.print("{{\"uid\":{d},\"gid\":{d}}}", .{ user.uid, user.gid });
    } else {
        try writer.writeAll("null");
    }
}

// ---- stop -----------------------------------------------------------------------------------

pub const StopOptions = struct {
    name: []const u8,
    grace_ms: u32 = constants.stop_grace_ms_default,
    /// The most time the command takes in all; null: the grace and the wait for SIGKILL.
    timeout_ms: ?u32 = null,
    json: bool,
};

/// Stops a container by its name. A container that is not running is already stopped (exit 0,
/// said so); an unknown name, a pid that cannot be signalled and a container that survives
/// SIGKILL are diagnostics.
pub fn run_stop(host: Host, options: StopOptions, diag: *Diag) Error!void {
    assert(options.name.len <= constants.arg_bytes_max);
    assert(options.grace_ms <= constants.wait_timeout_ms_max);
    var ref: lifecycle.Ref = undefined;
    var state: lifecycle.State = undefined;
    lifecycle.adopt(host, options.name, &ref, &state) catch |err| {
        const why: diagnose.NoContainer = switch (err) {
            error.NoState => .no_state,
            error.NoSuchContainer => .no_record,
            error.BadRecord => .unreadable_record,
        };
        diagnose.no_such_container(diag, options.name, why);
        return error.Failed;
    };
    var result: lifecycle.Stopped = .already_stopped;
    if (state == .running) {
        const total = options.timeout_ms;
        const grace = if (total) |limit| @min(options.grace_ms, limit) else options.grace_ms;
        const after = if (total) |limit| @max(limit - grace, 500) else lifecycle.kill_wait_ms;
        result = lifecycle.stop(&ref, grace, after) catch |err| {
            const failure: diagnose.Failure = .{
                .step = 0,
                .err = err_of(err),
                .errno = host.last_errno(),
            };
            if (err == error.Stuck) {
                diagnose.did_not_stop(diag, options.name, ref.pid, after);
            } else {
                diagnose.cannot_signal(diag, options.name, ref.pid, failure);
            }
            return error.Failed;
        };
    }
    return report_stop(host, options, ref, result, diag);
}

fn err_of(err: anyerror) host_mod.Error {
    assert(@errorName(err).len > 0);
    assert(err != error.OutOfMemory);
    return switch (err) {
        error.NotPermitted => error.AccessDenied,
        error.NotFound => error.NotFound,
        else => error.IoFailed,
    };
}

fn report_stop(
    host: Host,
    options: StopOptions,
    ref: lifecycle.Ref,
    result: lifecycle.Stopped,
    diag: *Diag,
) Error!void {
    assert(options.name.len > 0);
    assert(ref.pid > 0);
    var ended: lifecycle.WaitResult = .timeout;
    var reason_name: []const u8 = "none";
    var code: ?u8 = null;
    lifecycle.wait_adopted(&ref, 0, &ended) catch {};
    switch (ended) {
        .ended => |*record| {
            const found = lifecycle.exit_reason_of(record);
            reason_name = @tagName(record.reason);
            if (record.reason == .none) reason_name = "none";
            code = found.code();
        },
        .timeout => {},
    }
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // Cannot fail: a name of at most 63 bytes and a few words in 512.
    if (options.json) {
        writer.writeAll("{\"schema\":\"zbx.stop/1\",\"name\":") catch unreachable; // Bound above.
        json_string(&writer, options.name) catch unreachable; // Same bound.
        writer.print(",\"result\":\"{s}\",\"reason\":\"{s}\",\"exit_code\":", .{
            @tagName(result),
            reason_name,
        }) catch unreachable; // Same bound.
        optional_number(&writer, code) catch unreachable; // Same.
        writer.writeAll("}\n") catch unreachable; // Same.
    } else {
        const how: []const u8 = switch (result) {
            .already_stopped => "was not running",
            .graceful => "stopped",
            .killed => "stopped (killed)",
        };
        writer.print("{s} {s}", .{ options.name, how }) catch unreachable; // Same bound.
        if (code) |value| writer.print(", exit code {d}", .{value}) catch unreachable; // Same.
        writer.writeByte('\n') catch unreachable; // Same.
    }
    try write(host, writer.buffered(), diag);
}
