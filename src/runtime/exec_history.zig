//! The recent execs of a container (M6b slice 3): `<state>/zbx/logs/<name>.exec`, beside the
//! container's log, which `zbx bundle` notes. An exec is not a container: `ps` never lists it,
//! and it has no run record. Its entry is the command and how it ended, never the environment.
//!
//! The file is text, one entry per line under a version line, newest last:
//!
//!   zbx-exec-history 1
//!   <started> <ended> <exit> "<word>" "<word>" ...
//!
//! `<started>` and `<ended>` are seconds since the epoch (under 2^40), `<exit>` is `exited:N`,
//! `signal:N` or `lost`, and each word is quoted with `\"`, `\\` and `\xHH` for any byte that is
//! not printable ASCII. At most `history_entries_max` entries are kept: an append past that
//! drops the oldest. An append takes the file's lock (`<name>.exec.lock`, `flock`), reads the
//! file, and writes the new one atomically (a temporary file renamed over it), so two execs that
//! end at once keep both entries, and a crash leaves the old file or the new one. It is removed
//! with the container's log, on every path that removes a run record, and emptied when a new run
//! takes the name.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const records = @import("records.zig");
const store_fs = @import("../store/fs.zig");

const Host = host_mod.Host;

pub const header = "zbx-exec-history 1\n";
pub const version: u32 = 1;
pub const suffix = ".exec";
pub const lock_suffix = ".exec.lock";

/// What an entry keeps of the command: its words, quoted as the file has them, cut at a whole
/// word (`truncated`). A line is the times, the exit and this.
pub const command_bytes_max: u32 = constants.record_command_bytes_max;
pub const line_bytes_max: u32 = command_bytes_max + 64;
pub const file_bytes_max: u32 = header.len + constants.exec_history_entries_max * line_bytes_max;
const time_max: u64 = 1 << 40;

pub const Exit = union(enum) {
    exited: u8,
    signaled: u8,
    /// zbx could not wait for the command to the end.
    lost,
};

pub const Entry = struct {
    started: u64,
    ended: u64,
    exit: Exit,
    /// The quoted words, separated by spaces.
    command: [command_bytes_max]u8,
    command_len: u32,

    pub fn command_text(entry: *const Entry) []const u8 {
        assert(entry.command_len > 0);
        assert(entry.command_len <= command_bytes_max);
        return entry.command[0..entry.command_len];
    }

    /// Sets the command from its words, quoting each; words past the room are left out.
    pub fn set_command(entry: *Entry, words: []const []const u8) void {
        assert(words.len > 0);
        entry.command_len = 0;
        for (words) |word| {
            var quoted: [command_bytes_max]u8 = undefined;
            const text = quote(&quoted, word) orelse break;
            const space: u32 = @intFromBool(entry.command_len > 0);
            if (entry.command_len + space + text.len > command_bytes_max) break;
            if (space == 1) entry.command[entry.command_len] = ' ';
            entry.command_len += space;
            @memcpy(entry.command[entry.command_len..][0..text.len], text);
            entry.command_len += @intCast(text.len);
        }
        assert(entry.command_len <= command_bytes_max);
    }
};

pub const History = struct {
    entries: [constants.exec_history_entries_max]Entry,
    count: u32,

    pub fn slice(history: *const History) []const Entry {
        assert(history.entries.len == constants.exec_history_entries_max);
        assert(history.count <= constants.exec_history_entries_max);
        return history.entries[0..history.count];
    }

    /// Adds `entry` as the newest, dropping the oldest when full.
    pub fn push(history: *History, entry: *const Entry) void {
        assert(history.count <= constants.exec_history_entries_max);
        if (history.count == constants.exec_history_entries_max) {
            const kept = history.entries[1..history.count];
            std.mem.copyForwards(Entry, history.entries[0 .. history.count - 1], kept);
            history.count -= 1;
        }
        history.entries[history.count] = entry.*;
        history.count += 1;
        assert(history.count > 0);
    }
};

/// The memory of an append: the history and the file's text.
pub const Scratch = struct {
    history: History,
    text: [file_bytes_max]u8,
};

/// `"word"` with escapes, or null if it does not fit `buffer`.
fn quote(buffer: []u8, word: []const u8) ?[]const u8 {
    assert(buffer.len >= 2);
    var at: usize = 0;
    buffer[at] = '"';
    at += 1;
    for (word) |byte| {
        if (at + 5 > buffer.len) return null;
        switch (byte) {
            '"', '\\' => {
                buffer[at] = '\\';
                buffer[at + 1] = byte;
                at += 2;
            },
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => {
                buffer[at] = byte;
                at += 1;
            },
            else => {
                // Cannot fail: four bytes of room were checked above.
                _ = std.fmt.bufPrint(buffer[at..][0..4], "\\x{x:0>2}", .{byte}) catch unreachable;
                at += 4;
            },
        }
    }
    if (at + 1 > buffer.len) return null;
    buffer[at] = '"';
    at += 1;
    assert(at >= 2);
    return buffer[0..at];
}

/// The file's text for `history`.
pub fn render(history: *const History, buffer: *[file_bytes_max]u8) []const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the buffer holds the header and every entry at its longest.
    writer.writeAll(header) catch unreachable;
    for (history.slice()) |*entry| {
        assert(entry.started < time_max);
        assert(entry.ended < time_max);
        assert(entry.command_len > 0);
        writer.print("{d} {d} ", .{ entry.started, entry.ended }) catch unreachable; // Same.
        switch (entry.exit) {
            .exited => |code| writer.print("exited:{d}", .{code}) catch unreachable, // Same.
            // Cannot fail: as above.
            .signaled => |number| writer.print("signal:{d}", .{number}) catch unreachable,
            .lost => writer.writeAll("lost") catch unreachable, // Same.
        }
        writer.print(" {s}\n", .{entry.command_text()}) catch unreachable; // Same.
    }
    return writer.buffered();
}

pub const ParseError = error{ Malformed, Newer };

/// Reads the file's text. It accepts only what `render` can write: a damaged file is
/// `Malformed`, never half read; one of a later version is `Newer`.
pub fn parse(text: []const u8, history: *History) ParseError!void {
    assert(constants.exec_history_entries_max > 0);
    assert(@intFromPtr(history) != 0);
    history.count = 0;
    if (text.len > file_bytes_max) return error.Malformed;
    if (!std.mem.startsWith(u8, text, header)) {
        if (newer_version(text)) return error.Newer;
        return error.Malformed;
    }
    const body = text[header.len..];
    if (body.len > 0 and body[body.len - 1] != '\n') return error.Malformed;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) {
            if (lines.index != null) return error.Malformed; // Only the end is empty.
            break;
        }
        if (history.count == constants.exec_history_entries_max) return error.Malformed;
        try parse_line(line, &history.entries[history.count]);
        history.count += 1;
    }
    assert(history.count <= constants.exec_history_entries_max);
}

/// A version line of a version above this one: `zbx-exec-history N` with N > 1, and its newline.
fn newer_version(text: []const u8) bool {
    assert(text.len <= file_bytes_max);
    assert(version > 0);
    const prefix = "zbx-exec-history ";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    const end = std.mem.indexOfScalar(u8, text, '\n') orelse return false;
    const number = std.fmt.parseInt(u32, text[prefix.len..end], 10) catch return false;
    return number > version;
}

fn parse_line(line: []const u8, entry: *Entry) ParseError!void {
    assert(line.len > 0);
    assert(line.len > 0);
    if (line.len > line_bytes_max) return error.Malformed;
    var fields = std.mem.splitScalar(u8, line, ' ');
    entry.started = try parse_time(fields.next());
    entry.ended = try parse_time(fields.next());
    if (entry.ended < entry.started) return error.Malformed;
    entry.exit = try parse_exit(fields.next() orelse return error.Malformed);
    const command = fields.rest();
    if (command.len == 0 or command.len > command_bytes_max) return error.Malformed;
    try check_words(command);
    @memcpy(entry.command[0..command.len], command);
    entry.command_len = @intCast(command.len);
}

fn parse_time(field: ?[]const u8) ParseError!u64 {
    assert(time_max > 0);
    assert(time_max == 1 << 40);
    const text = field orelse return error.Malformed;
    if (text.len == 0 or text.len > 13) return error.Malformed;
    if (text.len > 1 and text[0] == '0') return error.Malformed;
    for (text) |byte| if (byte < '0' or byte > '9') return error.Malformed;
    const value = std.fmt.parseInt(u64, text, 10) catch return error.Malformed;
    if (value >= time_max) return error.Malformed;
    return value;
}

fn parse_exit(text: []const u8) ParseError!Exit {
    assert(text.len > 0);
    assert(constants.signal_number_max > 1);
    if (std.mem.eql(u8, text, "lost")) return .lost;
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.Malformed;
    const number_text = text[colon + 1 ..];
    if (number_text.len == 0 or number_text.len > 3) return error.Malformed;
    if (number_text.len > 1 and number_text[0] == '0') return error.Malformed;
    for (number_text) |byte| if (byte < '0' or byte > '9') return error.Malformed;
    const number = std.fmt.parseInt(u8, number_text, 10) catch return error.Malformed;
    const kind = text[0..colon];
    if (std.mem.eql(u8, kind, "exited")) return .{ .exited = number };
    if (!std.mem.eql(u8, kind, "signal")) return error.Malformed;
    if (number == 0 or number >= constants.signal_number_max) return error.Malformed;
    return .{ .signaled = number };
}

/// The words as `quote` writes them, separated by one space.
fn check_words(text: []const u8) ParseError!void {
    assert(text.len > 0);
    assert(constants.command_words_count_max > 0);
    var at: usize = 0;
    var words: u32 = 0;
    while (at < text.len) {
        if (words > 0) {
            if (text[at] != ' ') return error.Malformed;
            at += 1;
        }
        if (at >= text.len or text[at] != '"') return error.Malformed;
        at += 1;
        at = try word_end(text, at);
        words += 1;
        if (words > constants.command_words_count_max) return error.Malformed;
    }
    if (words == 0) return error.Malformed;
}

/// The index after the closing quote of a word whose content starts at `start`.
fn word_end(text: []const u8, start: usize) ParseError!usize {
    assert(start > 0);
    assert(start <= text.len);
    var at = start;
    while (at < text.len) {
        const byte = text[at];
        switch (byte) {
            '"' => return at + 1,
            '\\' => {
                if (at + 1 >= text.len) return error.Malformed;
                const next = text[at + 1];
                if (next == '"' or next == '\\') {
                    at += 2;
                    continue;
                }
                if (next != 'x' or at + 4 > text.len) return error.Malformed;
                const value = std.fmt.parseInt(u8, text[at + 2 .. at + 4], 16) catch
                    return error.Malformed;
                // Only what `quote` escapes is escaped, in lower case.
                if (value >= 0x20 and value <= 0x7e) return error.Malformed;
                if (std.ascii.isUpper(text[at + 2]) or std.ascii.isUpper(text[at + 3])) {
                    return error.Malformed;
                }
                at += 4;
            },
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => at += 1,
            else => return error.Malformed,
        }
    }
    return error.Malformed;
}

// ---- The file -------------------------------------------------------------------------------

pub const Error = host_mod.Error;

const Paths = struct {
    file: [constants.state_path_bytes_max + 96]u8,
    file_len: u32,
    temporary: [constants.state_path_bytes_max + 96]u8,
    temporary_len: u32,
    lock: [constants.state_path_bytes_max + 96]u8,
    lock_len: u32,

    fn set(paths: *Paths, dir: *const records.Dir, name: []const u8) void {
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        const base = dir.text();
        // Cannot fail: a bounded directory, a name of at most 63 bytes and a short suffix.
        const file = std.fmt.bufPrintSentinel(&paths.file, "{s}/{s}{s}", .{
            base, name, suffix,
        }, 0) catch unreachable; // Same bound as above.
        paths.file_len = @intCast(file.len);
        const temporary = std.fmt.bufPrintSentinel(&paths.temporary, "{s}/.{s}{s}.tmp", .{
            base, name, suffix,
        }, 0) catch unreachable; // Same bound as above.
        paths.temporary_len = @intCast(temporary.len);
        const lock = std.fmt.bufPrintSentinel(&paths.lock, "{s}/{s}{s}", .{
            base, name, lock_suffix,
        }, 0) catch unreachable; // Same bound as above.
        paths.lock_len = @intCast(lock.len);
    }

    fn file_text(paths: *const Paths) [:0]const u8 {
        assert(paths.file_len > 0);
        assert(paths.file[paths.file_len] == 0);
        return paths.file[0..paths.file_len :0];
    }
};

/// Reads the history of the container `name` in the logs directory `dir`. A missing file is an
/// empty history.
pub fn read(
    fs: store_fs.Fs,
    dir: *const records.Dir,
    name: []const u8,
    scratch: *Scratch,
) (Error || ParseError)!void {
    assert(dir.len > 0);
    assert(name.len > 0);
    var paths: Paths = undefined;
    paths.set(dir, name);
    scratch.history.count = 0;
    const text = fs.read_whole(paths.file_text(), &scratch.text) catch |err| {
        if (err == error.NotFound) return;
        if (err == error.FileTooLarge) return error.Malformed;
        return err;
    };
    try parse(text, &scratch.history);
}

/// Adds `entry` to the container's history, under the file's lock. A history that cannot be
/// read (damaged, newer) is started again: it is a convenience, never a record to keep.
pub fn append(
    host: Host,
    dir: *const records.Dir,
    name: []const u8,
    entry: *const Entry,
    scratch: *Scratch,
) Error!void {
    assert(entry.command_len > 0);
    assert(name.len > 0);
    const fs = host.log_files();
    var paths: Paths = undefined;
    paths.set(dir, name);
    const lock = try take_lock(host, fs, paths.lock[0..paths.lock_len :0]);
    defer fs.close(lock);
    read(fs, dir, name, scratch) catch |err| switch (err) {
        error.Malformed, error.Newer => scratch.history.count = 0,
        else => |other| return other,
    };
    scratch.history.push(entry);
    var bytes: [file_bytes_max]u8 = undefined;
    const text = render(&scratch.history, &bytes);
    var failure: store_fs.Failure = undefined;
    try fs.write_atomic_stamped(
        paths.temporary[0..paths.temporary_len :0],
        paths.file_text(),
        dir.text(),
        text,
        0o600,
        false,
        &failure,
    );
}

/// The lock, waiting up to `exec_history_lock_tries_max` tries for another exec to finish.
fn take_lock(host: Host, fs: store_fs.Fs, path: [:0]const u8) Error!store_fs.Fd {
    assert(path.len > 0);
    assert(constants.exec_history_lock_tries_max > 0);
    for (0..constants.exec_history_lock_tries_max) |_| {
        return fs.lock(path, true, "zbx exec") catch |err| {
            if (err != error.WouldBlock) return err;
            host.sleep_ms(constants.exec_history_lock_wait_ms);
            continue;
        };
    }
    return error.WouldBlock;
}

/// Removes the history and its lock. Best effort for each; the first real failure is returned.
pub fn remove(fs: store_fs.Fs, dir: *const records.Dir, name: []const u8) Error!void {
    assert(name.len > 0);
    assert(dir.len > 0);
    var paths: Paths = undefined;
    paths.set(dir, name);
    var failure: ?Error = null;
    for ([_][:0]const u8{ paths.file_text(), paths.lock[0..paths.lock_len :0] }) |path| {
        fs.unlink(path) catch |err| {
            if (err != error.NotFound) failure = failure orelse err;
        };
    }
    if (failure) |err| return err;
}

comptime {
    assert(line_bytes_max > command_bytes_max + 2 * 13 + 12);
    assert(file_bytes_max <= constants.lock_file_bytes_max);
}

const testing = std.testing;

fn test_entry(words: []const []const u8, exit: Exit) Entry {
    var entry: Entry = undefined;
    entry.started = 1_760_000_000;
    entry.ended = 1_760_000_005;
    entry.exit = exit;
    entry.set_command(words);
    return entry;
}

test "a history round-trips, with quoting, and keeps the newest entries" {
    // Goal: render and parse are inverse, a word with quotes, a backslash and a control byte
    // survives, and the oldest entry goes past the bound.
    var history: History = undefined;
    history.count = 0;
    const words = [_][]const u8{ "sh", "-c", "echo \"hi\\\" \x01" };
    for (0..constants.exec_history_entries_max + 1) |index| {
        var entry = test_entry(&words, .{ .exited = @intCast(index) });
        entry.started += index;
        entry.ended += index;
        history.push(&entry);
    }
    try testing.expectEqual(constants.exec_history_entries_max, history.count);
    try testing.expectEqual(@as(u8, 1), history.entries[0].exit.exited);
    var buffer: [file_bytes_max]u8 = undefined;
    const text = render(&history, &buffer);
    var parsed: History = undefined;
    try parse(text, &parsed);
    try testing.expectEqual(history.count, parsed.count);
    for (history.slice(), parsed.slice()) |*want, *got| {
        try testing.expectEqualStrings(want.command_text(), got.command_text());
        try testing.expectEqual(want.started, got.started);
        try testing.expectEqual(want.exit, got.exit);
    }
    const first = parsed.entries[0].command_text();
    try testing.expectEqualStrings("\"sh\" \"-c\" \"echo \\\"hi\\\\\\\" \\x01\"", first);
}

test "parse refuses what render never writes" {
    // Goal: the negative space of the format: each line damaged one way is Malformed, a later
    // version is Newer, and the empty history is valid.
    var history: History = undefined;
    try parse(header, &history);
    try testing.expectEqual(@as(u32, 0), history.count);
    try parse(header ++ "5 6 signal:9 \"ls\"\n", &history);
    try testing.expectEqual(@as(u32, 1), history.count);
    const bad = [_][]const u8{
        "",
        "zbx-exec-history 1",
        header ++ "5 6 signal:9 \"ls\"",
        header ++ "6 5 exited:0 \"ls\"\n",
        header ++ "05 6 exited:0 \"ls\"\n",
        header ++ "5 6 exited:256 \"ls\"\n",
        header ++ "5 6 signal:0 \"ls\"\n",
        header ++ "5 6 stopped:1 \"ls\"\n",
        header ++ "5 6 exited:0 ls\n",
        header ++ "5 6 exited:0 \"l\\x41\"\n",
        header ++ "5 6 exited:0 \"l\\x0A\"\n",
        header ++ "5 6 exited:0 \"ls\"  \"x\"\n",
        header ++ "5 6 exited:0 \"ls\n",
        header ++ "5 6 exited:0 \"ls\"\n\n",
        header ++ "1099511627776 1099511627777 exited:0 \"ls\"\n",
    };
    for (bad) |text| try testing.expectError(error.Malformed, parse(text, &history));
    try testing.expectError(error.Newer, parse("zbx-exec-history 2\n", &history));
}

test "an entry keeps whole words within its bound" {
    // Goal: a command longer than the bound keeps the words that fit, whole, and still parses.
    const long: [command_bytes_max]u8 = @splat('a');
    const words = [_][]const u8{ "sh", long[0 .. command_bytes_max / 2], &long };
    const entry = test_entry(&words, .lost);
    try testing.expect(entry.command_len < command_bytes_max);
    try testing.expect(std.mem.startsWith(u8, entry.command_text(), "\"sh\" \"aaa"));
    var history: History = undefined;
    history.count = 0;
    history.push(&entry);
    var buffer: [file_bytes_max]u8 = undefined;
    var parsed: History = undefined;
    try parse(render(&history, &buffer), &parsed);
    try testing.expectEqualStrings(entry.command_text(), parsed.entries[0].command_text());
}
