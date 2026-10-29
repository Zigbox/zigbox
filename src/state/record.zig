//! A volume's record, `<state>/<name>/state.zon`: when it was made, when a run last took it, the
//! container that did and where it was mounted. ZON in one shape (one field per line), read by a
//! line reader that does not allocate, as the run records are.
//!
//! The format has a version. A reader takes every version up to `state_record_version` and
//! refuses a newer one (`Newer`), never misreading it. Unknown fields are ignored, so a later zbx
//! may add some. `parse` accepts only what `render` can write: every bound `render` asserts (a
//! time under `state_time_max`, a name, a container name, a target) is checked by `parse` and
//! refused as `Malformed`, so a damaged record never reaches a write that would crash on it
//! (REVIEW.md; `zig build fuzz -- state` damages records and renders what parses again).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const spec_mod = @import("../runtime/spec.zig");
const volume = @import("volume.zig");

pub const Record = struct {
    name: [constants.state_name_bytes_max]u8,
    name_len: u8,
    /// Seconds since the epoch, below `state_time_max`.
    created: u64,
    last_used: u64,
    /// The container that last took the volume; empty when none has yet.
    last_container: [constants.container_name_bytes_max]u8,
    last_container_len: u8,
    /// Where that container mounted it, and whether read-only; empty with the container.
    last_target: [constants.state_target_bytes_max]u8,
    last_target_len: u16,
    last_read_only: bool,

    pub fn name_slice(record: *const Record) []const u8 {
        assert(record.name_len > 0);
        return record.name[0..record.name_len];
    }

    pub fn container_slice(record: *const Record) []const u8 {
        assert(record.last_container_len <= record.last_container.len);
        return record.last_container[0..record.last_container_len];
    }

    pub fn target_slice(record: *const Record) []const u8 {
        assert(record.last_target_len <= record.last_target.len);
        return record.last_target[0..record.last_target_len];
    }

    /// A record for a volume made now, not yet used by a container.
    pub fn init(record: *Record, name: []const u8, now: u64) void {
        assert(volume.name_problem(name) == null);
        assert(now < constants.state_time_max);
        @memcpy(record.name[0..name.len], name);
        record.name_len = @intCast(name.len);
        record.created = now;
        record.last_used = now;
        record.last_container_len = 0;
        record.last_target_len = 0;
        record.last_read_only = false;
    }

    /// Notes that `container` took the volume at `now`, mounted at `mount.target`.
    pub fn use(record: *Record, container: []const u8, mount: *const volume.Mount, now: u64) void {
        assert(spec_mod.name_problem(container) == null);
        assert(volume.target_problem(mount.target) == null);
        assert(now < constants.state_time_max);
        @memcpy(record.last_container[0..container.len], container);
        record.last_container_len = @intCast(container.len);
        @memcpy(record.last_target[0..mount.target.len], mount.target);
        record.last_target_len = @intCast(mount.target.len);
        record.last_read_only = mount.read_only;
        record.last_used = @max(now, record.created);
        assert(record.last_used >= record.created);
    }
};

// ---- Writing --------------------------------------------------------------------------------

/// The record as ZON text in `buffer`. The worst case fits (constants.zig proves it): every
/// string byte escaped to four.
pub fn render(record: *const Record, buffer: *[constants.state_record_bytes_max]u8) []const u8 {
    assert(volume.name_problem(record.name_slice()) == null);
    assert(record.created < constants.state_time_max);
    assert(record.last_used < constants.state_time_max);
    assert(record.last_used >= record.created);
    assert((record.last_container_len == 0) == (record.last_target_len == 0));
    if (record.last_container_len > 0) {
        assert(spec_mod.name_problem(record.container_slice()) == null);
        assert(volume.target_problem(record.target_slice()) == null);
    }
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail, any of these: the buffer holds the worst record (constants.zig).
    writer.print(".{{\n    .version = {d},\n", .{constants.state_record_version}) catch
        unreachable; // Same bound.
    write_string_field(&writer, "name", record.name_slice());
    writer.print("    .created = {d},\n    .last_used = {d},\n", .{
        record.created, record.last_used,
    }) catch unreachable; // Same bound.
    write_string_field(&writer, "last_container", record.container_slice());
    write_string_field(&writer, "last_target", record.target_slice());
    const read_only = if (record.last_read_only) "true" else "false";
    writer.print("    .last_read_only = {s},\n}}\n", .{read_only}) catch
        unreachable; // Same bound.
    return writer.buffered();
}

fn write_string_field(writer: *std.Io.Writer, key: []const u8, value: []const u8) void {
    assert(key.len > 0);
    assert(value.len <= constants.state_target_bytes_max);
    // Cannot fail, any of these: the buffer holds the worst record (constants.zig).
    writer.print("    .{s} = \"", .{key}) catch unreachable; // Same bound.
    for (value) |byte| {
        switch (byte) {
            '"' => writer.writeAll("\\\"") catch unreachable, // Same bound.
            '\\' => writer.writeAll("\\\\") catch unreachable, // Same bound.
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => writer.writeByte(byte) catch
                unreachable, // Same bound.
            else => writer.print("\\x{x:0>2}", .{byte}) catch unreachable, // Same bound.
        }
    }
    writer.writeAll("\",\n") catch unreachable; // Same bound.
}

// ---- Reading --------------------------------------------------------------------------------

pub const ParseError = error{
    /// Not a record this reader can use.
    Malformed,
    /// Written by a newer zbx.
    Newer,
};

/// Reads a record. Never reads past `text`, never allocates. A record must have every field
/// version 1 writes; a field given twice is refused (render writes each once).
pub fn parse(text: []const u8, out: *Record) ParseError!void {
    assert(text.len <= constants.file_bytes_max);
    out.name_len = 0;
    out.last_container_len = 0;
    out.last_target_len = 0;
    out.last_read_only = false;
    var seen: Seen = .{};
    var version: ?u32 = null;
    var opened = false;
    var closed = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!opened) {
            if (!std.mem.eql(u8, line, ".{")) return error.Malformed;
            opened = true;
            continue;
        }
        if (closed) return error.Malformed;
        if (std.mem.eql(u8, line, "}")) {
            closed = true;
            continue;
        }
        try parse_field(line, out, &seen, &version);
    }
    if (!opened or !closed) return error.Malformed;
    const found = version orelse return error.Malformed;
    if (found > constants.state_record_version) return error.Newer;
    if (found == 0) return error.Malformed;
    try check(out, &seen);
}

/// Which fields were read, so that a missing or repeated one is refused.
const Seen = struct {
    name: bool = false,
    created: bool = false,
    last_used: bool = false,
    last_container: bool = false,
    last_target: bool = false,
    last_read_only: bool = false,
};

/// The bounds `render` asserts, checked here so that what parses can be written again.
fn check(out: *const Record, seen: *const Seen) ParseError!void {
    const all = seen.name and seen.created and seen.last_used and seen.last_container and
        seen.last_target and seen.last_read_only;
    if (!all) return error.Malformed;
    if (out.name_len == 0) return error.Malformed;
    if (volume.name_problem(out.name_slice()) != null) return error.Malformed;
    if (out.created >= constants.state_time_max) return error.Malformed;
    if (out.last_used >= constants.state_time_max) return error.Malformed;
    if (out.last_used < out.created) return error.Malformed;
    if ((out.last_container_len == 0) != (out.last_target_len == 0)) return error.Malformed;
    if (out.last_container_len == 0) {
        if (out.last_read_only) return error.Malformed; // Render writes false with no container.
        return;
    }
    if (spec_mod.name_problem(out.container_slice()) != null) return error.Malformed;
    if (volume.target_problem(out.target_slice()) != null) return error.Malformed;
}

fn parse_field(line: []const u8, out: *Record, seen: *Seen, version: *?u32) ParseError!void {
    assert(line.len > 0);
    if (line[0] != '.') return error.Malformed;
    const equals = std.mem.indexOf(u8, line, " = ") orelse return error.Malformed;
    const key = line[1..equals];
    var value = line[equals + 3 ..];
    if (value.len < 2 or value[value.len - 1] != ',') return error.Malformed;
    value = value[0 .. value.len - 1];
    if (std.mem.eql(u8, key, "version")) {
        if (version.* != null) return error.Malformed;
        version.* = parse_number(u32, value) orelse return error.Malformed;
    } else if (std.mem.eql(u8, key, "name")) {
        try once(&seen.name);
        out.name_len = @intCast(parse_string(value, &out.name) orelse return error.Malformed);
    } else if (std.mem.eql(u8, key, "created")) {
        try once(&seen.created);
        out.created = parse_number(u64, value) orelse return error.Malformed;
    } else if (std.mem.eql(u8, key, "last_used")) {
        try once(&seen.last_used);
        out.last_used = parse_number(u64, value) orelse return error.Malformed;
    } else if (std.mem.eql(u8, key, "last_container")) {
        try once(&seen.last_container);
        const length = parse_string(value, &out.last_container) orelse return error.Malformed;
        out.last_container_len = @intCast(length);
    } else if (std.mem.eql(u8, key, "last_target")) {
        try once(&seen.last_target);
        const length = parse_string(value, &out.last_target) orelse return error.Malformed;
        out.last_target_len = @intCast(length);
    } else if (std.mem.eql(u8, key, "last_read_only")) {
        try once(&seen.last_read_only);
        const yes = std.mem.eql(u8, value, "true");
        if (!yes and !std.mem.eql(u8, value, "false")) return error.Malformed;
        out.last_read_only = yes;
    }
    // Any other field is ignored: a later zbx may add some.
}

fn once(flag: *bool) ParseError!void {
    if (flag.*) return error.Malformed;
    flag.* = true;
}

/// Decimal digits only, one spelling per number (no sign, no leading zero), as `render` writes.
fn parse_number(comptime Int: type, value: []const u8) ?Int {
    assert(@typeInfo(Int) == .int);
    if (value.len == 0 or value.len > 20) return null;
    if (value[0] == '0' and value.len > 1) return null;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    return std.fmt.parseInt(Int, value, 10) catch null;
}

/// A ZON string literal with the writer's escapes only (`\"`, `\\`, `\xNN`) into `out`; its
/// length, or null if it is not one or does not fit.
fn parse_string(literal: []const u8, out: []u8) ?usize {
    if (literal.len < 2) return null;
    if (literal[0] != '"' or literal[literal.len - 1] != '"') return null;
    const body = literal[1 .. literal.len - 1];
    var length: usize = 0;
    var at: usize = 0;
    while (at < body.len) : (at += 1) {
        if (length == out.len) return null;
        var byte = body[at];
        if (byte == '"') return null;
        if (byte == '\\') {
            at += 1;
            if (at == body.len) return null;
            switch (body[at]) {
                '"', '\\' => byte = body[at],
                'x' => {
                    if (at + 2 >= body.len) return null;
                    const high = std.fmt.charToDigit(body[at + 1], 16) catch return null;
                    const low = std.fmt.charToDigit(body[at + 2], 16) catch return null;
                    byte = high * 16 + low;
                    at += 2;
                },
                else => return null,
            }
        }
        out[length] = byte;
        length += 1;
    }
    return length;
}

const testing = std.testing;

/// A version 1 record as this zbx's first release wrote it, kept as text (not rendered by the
/// code under test), so that a later change to `render` cannot hide a reader that stopped
/// reading it (REVIEW.md).
pub const version_1_text =
    \\.{
    \\    .version = 1,
    \\    .name = "pgdata",
    \\    .created = 1761645600,
    \\    .last_used = 1761649200,
    \\    .last_container = "pg",
    \\    .last_target = "/var/lib/postgresql/data",
    \\    .last_read_only = false,
    \\}
    \\
;

test "a record renders and reads back, and version 1 text reads" {
    // Goal: the round trip and the fixed text of version 1. Method: a used record, then the
    // text kept above.
    var record: Record = undefined;
    record.init("pgdata", 1761645600);
    const mount: volume.Mount = .{
        .name = "pgdata",
        .target = "/var/lib/postgresql/data",
        .read_only = false,
    };
    record.use("pg", &mount, 1761649200);
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    const text = render(&record, &buffer);
    try testing.expectEqualStrings(version_1_text, text);
    var back: Record = undefined;
    try parse(version_1_text, &back);
    try testing.expectEqualStrings("pgdata", back.name_slice());
    try testing.expectEqualStrings("pg", back.container_slice());
    try testing.expectEqualStrings("/var/lib/postgresql/data", back.target_slice());
    try testing.expectEqual(@as(u64, 1761645600), back.created);
    try testing.expectEqual(@as(u64, 1761649200), back.last_used);
    try testing.expect(!back.last_read_only);
}

test "a newer version is refused as newer, and damage as malformed" {
    // Goal: a reader never misreads. Method: one edit per bound render asserts.
    var back: Record = undefined;
    const Case = struct { from: []const u8, to: []const u8 };
    const malformed = [_]Case{
        .{ .from = "1761645600,", .to = "1099511627776," }, // created at 2^40
        .{ .from = "1761649200,", .to = "1761645599," }, // used before it was made
        .{ .from = "\"pg\"", .to = "\"Pg\"" },
        .{ .from = "\"pgdata\"", .to = "\".pg\"" },
        .{ .from = "\"/var", .to = "\"var" },
        .{ .from = "\"pg\"", .to = "\"\"" }, // a target with no container
        .{ .from = "false", .to = "maybe" },
        .{ .from = "1761645600,", .to = "01761645600," },
        .{ .from = "    .version = 1,\n", .to = "" },
        .{ .from = "    .version = 1,\n", .to = "    .version = 0,\n" },
        .{ .from = "    .created", .to = "    .last_used = 5,\n    .created" },
        .{ .from = "}\n", .to = "" },
    };
    for (malformed) |case| {
        var edited: [512]u8 = undefined;
        const size = std.mem.replacementSize(u8, version_1_text, case.from, case.to);
        _ = std.mem.replace(u8, version_1_text, case.from, case.to, &edited);
        try testing.expectError(error.Malformed, parse(edited[0..size], &back));
    }
    var newer: [512]u8 = undefined;
    const size = std.mem.replacementSize(u8, version_1_text, "= 1,", "= 2,");
    _ = std.mem.replace(u8, version_1_text, "= 1,", "= 2,", &newer);
    try testing.expectError(error.Newer, parse(newer[0..size], &back));
    // A field a later zbx adds is ignored.
    var later: [512]u8 = undefined;
    const added = std.mem.replacementSize(u8, version_1_text, "}\n", "    .more = 1,\n}\n");
    _ = std.mem.replace(u8, version_1_text, "}\n", "    .more = 1,\n}\n", &later);
    try parse(later[0..added], &back);
}

test "the longest record fits, with every byte of its strings escaped" {
    // Goal: the comptime bound is the real one. Method: a record at every bound.
    var record: Record = undefined;
    const repeat = @import("../test_util.zig").repeat;
    const name = "a" ++ repeat('_', constants.state_name_bytes_max - 1);
    record.init(name, constants.state_time_max - 2);
    const container = "a" ++ repeat('-', constants.container_name_bytes_max - 2) ++ "b";
    const target = "/" ++ repeat('"', constants.state_target_bytes_max - 1);
    const mount: volume.Mount = .{ .name = name, .target = target, .read_only = true };
    record.use(container, &mount, constants.state_time_max - 1);
    var buffer: [constants.state_record_bytes_max]u8 = undefined;
    const text = render(&record, &buffer);
    var back: Record = undefined;
    try parse(text, &back);
    try testing.expectEqualStrings(target, back.target_slice());
    try testing.expect(back.last_read_only);
}
