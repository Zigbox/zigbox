//! The log of a container: everything it wrote to standard output and standard error, in order,
//! with the time of each write, kept beside its run record (`<state>/zbx/logs/<name>.log`).
//!
//! The format (version 1; the constants are in `constants.zig`):
//!
//!   file    = header record*
//!   header  = version (1 byte) | seven zero bytes | base (u64, little endian)
//!   record  = stream (1 byte: 1 stdout, 2 stderr) | time (5 bytes, seconds) | length (2 bytes,
//!             1 to 4096) | crc (4 bytes: CRC-32 of the first 8 bytes and the payload) | payload
//!
//! `base` is the number of bytes of records that came before this file's first record, counted
//! over everything the container ever wrote: the log is a window onto a stream whose start the
//! cap may have moved. The reader reports the oldest file's `base` as `dropped_bytes`.
//!
//! Why two files, rotated, and not one file compacted: at the cap the log must forget its oldest
//! records. Two files of half the cap do it with one `rename` (the older file is replaced by the
//! current one, and a new current file is made), so a drop costs no copying and, if the writer
//! dies at any step, the disk holds either the files before the rename or the files after it,
//! each made of whole records. A compaction copies up to the cap on every drop and needs a
//! temporary file and a rename too. The price is that the log holds between half the cap and the
//! cap, not always the cap.
//!
//! A reader never trusts what it cannot check. A record is accepted when its header is in
//! range and its CRC matches; the first record that fails ends the file (a torn tail, from a
//! writer that died in the middle of a write or from a machine that lost the unwritten end).
//! Nothing after a bad record is read, because the format has no way to find the next one.
//!
//! The writer never writes to a file after one of its writes failed: a short or failed write
//! leaves a torn tail, and a record behind it would be lost to every reader.
//!
//! Everything goes through `store/fs.zig`, so the simulator can tear a write or crash at any
//! write point. No allocation: the reader's windows and the writer's paths are in the structs.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const records = @import("records.zig");

pub const Fs = fs_mod.Fs;
pub const Fd = fs_mod.Fd;
const Error = host_mod.Error;

pub const Stream = enum(u8) {
    stdout = 1,
    stderr = 2,

    pub fn word(stream: Stream) []const u8 {
        assert(@backingInt(stream) >= 1);
        assert(@backingInt(stream) <= 2);
        return switch (stream) {
            .stdout => "stdout",
            .stderr => "stderr",
        };
    }

    fn from_byte(byte: u8) ?Stream {
        assert(std.enums.values(Stream).len == 2);
        const found: ?Stream = switch (byte) {
            1 => .stdout,
            2 => .stderr,
            else => null,
        };
        if (found) |stream| assert(@backingInt(stream) == byte);
        return found;
    }
};

const path_bytes: u32 = constants.state_path_bytes_max + 80;
const record_bytes_total_max: u32 =
    constants.log_record_header_bytes + constants.log_record_bytes_max;

// ---- The format ----------------------------------------------------------------------------

pub fn encode_header(base: u64, out: *[constants.log_header_bytes]u8) void {
    out.* = @splat(0);
    out[0] = constants.log_version;
    std.mem.writeInt(u64, out[8..16], base, .little);
    assert(out[0] == constants.log_version);
    assert(std.mem.readInt(u64, out[8..16], .little) == base);
}

pub const HeaderResult = union(enum) {
    /// A header this reader knows: the offset of the file's first record.
    ok: u64,
    /// Fewer bytes than a header: a file that was made and not yet given its header.
    short,
    /// Not a header of any version this program writes.
    bad,
    /// A version above the one this program reads.
    newer,
};

pub fn parse_header(bytes: []const u8) HeaderResult {
    assert(constants.log_header_bytes == 16);
    assert(bytes.len <= constants.log_read_bytes);
    if (bytes.len < constants.log_header_bytes) return .short;
    for (bytes[1..8]) |byte| {
        if (byte != 0) return .bad;
    }
    // Text or binary that is not ours has a first byte far above any version we will write.
    if (bytes[0] > constants.log_version and bytes[0] <= 32) return .newer;
    if (bytes[0] != constants.log_version) return .bad;
    return .{ .ok = std.mem.readInt(u64, bytes[8..16], .little) };
}

/// Writes one record into `out` and returns its bytes. The payload is 1 to `record_bytes_max`
/// bytes and the time is below 2^40: what `parse_record` accepts is exactly this.
pub fn encode_record(
    out: *[record_bytes_total_max]u8,
    stream: Stream,
    time: u64,
    payload: []const u8,
) []const u8 {
    assert(payload.len > 0);
    assert(payload.len <= constants.log_record_bytes_max);
    assert(time < constants.log_time_max);
    out[0] = @backingInt(stream);
    std.mem.writeInt(u40, out[1..6], @intCast(time), .little);
    std.mem.writeInt(u16, out[6..8], @intCast(payload.len), .little);
    @memcpy(out[constants.log_record_header_bytes..][0..payload.len], payload);
    const checksum = checksum_of(out[0..8], payload);
    std.mem.writeInt(u32, out[8..12], checksum, .little);
    const total = constants.log_record_header_bytes + payload.len;
    assert(parse_record(out[0..total]) == .record);
    return out[0..total];
}

fn checksum_of(head: []const u8, payload: []const u8) u32 {
    assert(payload.len <= constants.log_record_bytes_max);
    assert(head.len == 8);
    var state = std.hash.Crc32.init();
    state.update(head);
    state.update(payload);
    return state.final();
}

pub const Record = struct {
    stream: Stream,
    /// Seconds since the epoch.
    time: u64,
    /// Into the bytes given to `parse_record`, or the cursor's window: valid until the next call.
    payload: []const u8,
    /// Where the record starts in the stream of everything the container wrote.
    offset: u64,
};

pub const RecordResult = union(enum) {
    /// A whole record at the start of the bytes; `size` is its header and payload.
    record: struct { stream: Stream, time: u64, payload: []const u8, size: u32 },
    /// The bytes are a prefix of a record that may yet be completed.
    incomplete,
    /// The bytes are not the start of a record: nothing can complete them.
    bad,
};

pub fn parse_record(bytes: []const u8) RecordResult {
    assert(constants.log_record_header_bytes == 12);
    const head = constants.log_record_header_bytes;
    if (bytes.len < head) {
        // A prefix that already breaks the format cannot be completed into a record.
        if (bytes.len >= 1 and Stream.from_byte(bytes[0]) == null) return .bad;
        return .incomplete;
    }
    const stream = Stream.from_byte(bytes[0]) orelse return .bad;
    const length = std.mem.readInt(u16, bytes[6..8], .little);
    if (length == 0) return .bad;
    if (length > constants.log_record_bytes_max) return .bad;
    const size: u32 = head + length;
    if (bytes.len < size) return .incomplete;
    const payload = bytes[head..size];
    const expected = std.mem.readInt(u32, bytes[8..12], .little);
    if (checksum_of(bytes[0..8], payload) != expected) return .bad;
    const time: u64 = std.mem.readInt(u40, bytes[1..6], .little);
    assert(time < constants.log_time_max);
    return .{ .record = .{ .stream = stream, .time = time, .payload = payload, .size = size } };
}

// ---- Where a log is -------------------------------------------------------------------------

/// The logs directory beside a runs directory: the same path with "logs" for its last part.
pub fn dir_of(runs: *const records.Dir) ?records.Dir {
    const text = runs.text();
    if (!std.mem.endsWith(u8, text, "/runs")) return null;
    var out = runs.*;
    @memcpy(out.path[out.len - "runs".len .. out.len], "logs");
    assert(out.path[out.len] == 0);
    assert(std.mem.endsWith(u8, out.text(), "/logs"));
    return out;
}

pub const Paths = struct {
    current: [path_bytes]u8,
    current_len: u32,
    older: [path_bytes]u8,
    older_len: u32,

    pub fn set(paths: *Paths, dir: *const records.Dir, name: []const u8) void {
        assert(name.len > 0);
        assert(name.len <= constants.container_name_bytes_max);
        const base = dir.text();
        // Cannot fail: a directory of at most state_path_bytes_max, a name of at most 63 bytes
        // and a suffix of six leave room in 80 spare bytes.
        const current = std.fmt.bufPrintSentinel(
            &paths.current,
            "{s}/{s}{s}",
            .{ base, name, constants.log_suffix },
            0,
        ) catch unreachable; // Cannot fail: the bound above.
        const older = std.fmt.bufPrintSentinel(
            &paths.older,
            "{s}/{s}{s}",
            .{ base, name, constants.log_older_suffix },
            0,
        ) catch unreachable; // Same bound.
        paths.current_len = @intCast(current.len);
        paths.older_len = @intCast(older.len);
    }

    pub fn current_text(paths: *const Paths) [:0]const u8 {
        assert(paths.current_len > 0);
        assert(paths.current[paths.current_len] == 0);
        return paths.current[0..paths.current_len :0];
    }

    pub fn older_text(paths: *const Paths) [:0]const u8 {
        assert(paths.older_len > paths.current_len);
        assert(paths.older[paths.older_len] == 0);
        return paths.older[0..paths.older_len :0];
    }
};

/// Makes the logs directory and every directory above it that is missing.
pub fn ensure_directory(fs: Fs, dir: *const records.Dir) Error!void {
    assert(dir.len > dir.existing_len);
    var at: u32 = dir.existing_len;
    while (at < dir.len) {
        const next = std.mem.indexOfScalarPos(u8, dir.path[0..dir.len], at + 1, '/') orelse dir.len;
        var prefix: [constants.state_path_bytes_max + 1]u8 = undefined;
        @memcpy(prefix[0..next], dir.path[0..next]);
        prefix[next] = 0;
        try fs.make_directory(prefix[0..next :0], true);
        at = @intCast(next);
    }
    assert(at == dir.len);
}

/// Removes a container's log, both files. Files that are not there are not an error; the first
/// real failure is returned after both were tried.
pub fn remove(fs: Fs, dir: *const records.Dir, name: []const u8) Error!void {
    assert(name.len > 0);
    assert(dir.len > 0);
    var paths: Paths = undefined;
    paths.set(dir, name);
    var failure: ?Error = null;
    for ([_][:0]const u8{ paths.current_text(), paths.older_text() }) |path| {
        fs.unlink(path) catch |err| {
            if (err != error.NotFound) failure = failure orelse err;
        };
    }
    if (failure) |err| return err;
}

// ---- The writer -----------------------------------------------------------------------------

pub const WriterOptions = struct {
    /// The most one file holds, header included. Tests make it small.
    segment_bytes_max: u32 = constants.log_segment_bytes_max,
    /// The most one record holds; a longer write is cut into several.
    record_bytes_max: u32 = constants.log_record_bytes_max,
};

pub const Writer = struct {
    fs: Fs,
    fd: Fd,
    paths: Paths,
    /// The offset of the current file's first record in the stream.
    base: u64,
    /// The bytes in the current file, its header included.
    size: u32,
    options: WriterOptions,
    state: enum { closed, open, failed },
    /// Whether `fd` is a descriptor this writer still has to close.
    fd_open: bool,

    /// Starts a log for `name`: whatever an earlier run of that name left is removed, and a
    /// current file with its header is made. On an error nothing is open.
    pub fn open(
        writer: *Writer,
        fs: Fs,
        dir: *const records.Dir,
        name: []const u8,
        options: WriterOptions,
    ) Error!void {
        assert(options.record_bytes_max > 0);
        assert(options.record_bytes_max <= constants.log_record_bytes_max);
        assert(options.segment_bytes_max <= constants.log_segment_bytes_max);
        const smallest = constants.log_header_bytes + constants.log_record_header_bytes +
            options.record_bytes_max;
        assert(options.segment_bytes_max >= smallest);
        assert(options.segment_bytes_max >= constants.log_header_bytes);
        assert(name.len > 0);
        writer.state = .closed;
        writer.fd_open = false;
        writer.fs = fs;
        writer.options = options;
        writer.paths.set(dir, name);
        try ensure_directory(fs, dir);
        try remove(fs, dir, name);
        try writer.start_file(0);
        assert(writer.state == .open);
    }

    fn start_file(writer: *Writer, base: u64) Error!void {
        assert(!writer.fd_open);
        assert(writer.state != .open);
        const fs = writer.fs;
        const fd = try fs.create(writer.paths.current_text(), 0o600);
        var header: [constants.log_header_bytes]u8 = undefined;
        encode_header(base, &header);
        fs.write_all(fd, &header) catch |err| {
            fs.close(fd);
            writer.state = .failed;
            return err;
        };
        writer.fd = fd;
        writer.fd_open = true;
        writer.base = base;
        writer.size = constants.log_header_bytes;
        writer.state = .open;
    }

    /// Adds what the container wrote, cut into records of at most `record_bytes_max`. The first
    /// error stops the log for good: the caller keeps the container running and says so once.
    pub fn append(writer: *Writer, stream: Stream, time: u64, bytes: []const u8) Error!void {
        assert(time < constants.log_time_max);
        assert(writer.state != .closed);
        if (writer.state == .failed) return error.IoFailed;
        var rest = bytes;
        while (rest.len > 0) {
            const take = @min(rest.len, writer.options.record_bytes_max);
            writer.append_record(stream, time, rest[0..take]) catch |err| {
                writer.state = .failed;
                return err;
            };
            rest = rest[take..];
        }
    }

    fn append_record(writer: *Writer, stream: Stream, time: u64, payload: []const u8) Error!void {
        assert(payload.len > 0);
        assert(payload.len <= writer.options.record_bytes_max);
        var storage: [record_bytes_total_max]u8 = undefined;
        const record = encode_record(&storage, stream, time, payload);
        if (writer.size + record.len > writer.options.segment_bytes_max) try writer.rotate();
        assert(writer.size + record.len <= writer.options.segment_bytes_max);
        try writer.fs.write_all(writer.fd, record);
        writer.size += @intCast(record.len);
    }

    /// The current file becomes the older one (replacing it: the oldest records are dropped, as
    /// a whole file), and a new current file begins where the old one ended.
    fn rotate(writer: *Writer) Error!void {
        const fs = writer.fs;
        assert(writer.state == .open);
        const next_base = writer.base + (writer.size - constants.log_header_bytes);
        // The file that is about to be the only one of its age should be whole on the disk. A
        // failed sync is not a reason to lose the log: the reader copes with a torn end.
        fs.fsync(writer.fd) catch {};
        fs.close(writer.fd);
        writer.fd_open = false;
        writer.state = .failed; // Until the new file is open: a failure leaves it so.
        try fs.rename(writer.paths.current_text(), writer.paths.older_text());
        try writer.start_file(next_base);
        assert(writer.base == next_base);
    }

    pub fn close(writer: *Writer) void {
        assert(writer.options.segment_bytes_max > 0);
        assert(writer.size <= writer.options.segment_bytes_max);
        if (writer.fd_open) writer.fs.close(writer.fd);
        writer.fd_open = false;
        writer.state = .closed;
    }
};

// ---- The reader -----------------------------------------------------------------------------

pub const OpenResult = enum { opened, missing, short, bad, newer, failed };

pub const NextResult = union(enum) {
    record: Record,
    /// No whole record is there now. In a file still being written, more may come.
    end,
    /// A record failed its check: the file ends here for good.
    damaged,
    /// The file could not be read.
    failed,
};

/// One file of a log, read record by record through a window.
pub const Cursor = struct {
    fs: Fs,
    fd: Fd,
    is_open: bool,
    /// The offset of the file's first record in the stream.
    base: u64,
    /// The bytes of records handed out so far.
    consumed: u64,
    window: [constants.log_read_bytes]u8,
    window_at: u32,
    window_len: u32,
    damaged: bool,

    pub fn open(cursor: *Cursor, fs: Fs, path: [:0]const u8) OpenResult {
        assert(path.len > 0);
        assert(@intFromPtr(fs.vtable) != 0);
        cursor.is_open = false;
        cursor.damaged = false;
        const fd = fs.open_read(path) catch |err| {
            return if (err == error.NotFound) .missing else .failed;
        };
        var header: [constants.log_header_bytes]u8 = undefined;
        const have = read_up_to(fs, fd, &header) catch {
            fs.close(fd);
            return .failed;
        };
        switch (parse_header(header[0..have])) {
            .ok => |base| {
                cursor.fs = fs;
                cursor.fd = fd;
                cursor.is_open = true;
                cursor.base = base;
                cursor.consumed = 0;
                cursor.window_at = 0;
                cursor.window_len = 0;
                return .opened;
            },
            .short => {
                fs.close(fd);
                return .short;
            },
            .bad => {
                fs.close(fd);
                return .bad;
            },
            .newer => {
                fs.close(fd);
                return .newer;
            },
        }
    }

    pub fn close(cursor: *Cursor) void {
        assert(cursor.window_at <= cursor.window_len);
        assert(cursor.window_len <= cursor.window.len);
        if (cursor.is_open) cursor.fs.close(cursor.fd);
        cursor.is_open = false;
    }

    /// The next whole record. `end` leaves the cursor where it was: asking again later returns
    /// what has been written since.
    pub fn next(cursor: *Cursor) NextResult {
        assert(cursor.is_open);
        assert(cursor.window_at <= cursor.window_len);
        if (cursor.damaged) return .damaged;
        for (0..constants.log_drain_reads_max) |_| {
            const unread = cursor.window[cursor.window_at..cursor.window_len];
            switch (parse_record(unread)) {
                .record => |found| {
                    const offset = cursor.base + cursor.consumed;
                    cursor.window_at += found.size;
                    cursor.consumed += found.size;
                    return .{ .record = .{
                        .stream = found.stream,
                        .time = found.time,
                        .payload = found.payload,
                        .offset = offset,
                    } };
                },
                .bad => {
                    cursor.damaged = true;
                    return .damaged;
                },
                .incomplete => if (!cursor.fill()) return .end,
            }
        }
        return .failed;
    }

    /// Reads more into the window, after moving the unread bytes to its start. False at the end
    /// of the file (or on an error, which reads as the end here and fails the next look).
    fn fill(cursor: *Cursor) bool {
        assert(cursor.is_open);
        assert(cursor.window_len <= cursor.window.len);
        const unread = cursor.window_len - cursor.window_at;
        if (cursor.window_at > 0) {
            const unread_bytes = cursor.window[cursor.window_at..][0..unread];
            std.mem.copyForwards(u8, cursor.window[0..unread], unread_bytes);
            cursor.window_at = 0;
            cursor.window_len = unread;
        }
        assert(cursor.window_len < cursor.window.len);
        const room = cursor.window[cursor.window_len..];
        const count = cursor.fs.read(cursor.fd, room) catch return false;
        cursor.window_len += count;
        return count > 0;
    }
};

/// Reads until the buffer is full or the file ends; the count read.
fn read_up_to(fs: Fs, fd: Fd, buffer: []u8) Error!u32 {
    assert(buffer.len > 0);
    assert(buffer.len <= constants.log_read_bytes);
    var have: u32 = 0;
    for (0..buffer.len + constants.store_io_retries_max + 1) |_| {
        if (have == buffer.len) break;
        const count = try fs.read(fd, buffer[have..]);
        if (count == 0) break;
        have += count;
    }
    return have;
}

pub const ReadError = error{
    /// Neither file exists.
    NoLog,
    /// A file is from a newer zbx.
    Newer,
    /// A file is there and is not a log.
    Damaged,
    /// A file could not be opened or read.
    Unreadable,
};

/// A whole log: the older file, then the current one, as one run of records.
pub const Reader = struct {
    fs: Fs,
    paths: Paths,
    older: Cursor,
    current: Cursor,
    stage: enum { older, current },
    has_older: bool,
    has_current: bool,
    /// The bytes of the container's output that came before the first record this reader
    /// returns, and that the cap had dropped by the time the log was opened.
    dropped_bytes: u64,

    /// Opens the current file first and the older one second: a rotation between the two opens
    /// shows as two files of one base (the old current, twice), never as a hole.
    pub fn open(
        reader: *Reader,
        fs: Fs,
        dir: *const records.Dir,
        name: []const u8,
    ) ReadError!void {
        assert(name.len > 0);
        assert(dir.len > 0);
        reader.fs = fs;
        reader.paths.set(dir, name);
        reader.has_older = false;
        reader.has_current = false;
        reader.dropped_bytes = 0;
        const now = reader.current.open(fs, reader.paths.current_text());
        const before = reader.older.open(fs, reader.paths.older_text());
        errdefer reader.close();
        reader.has_current = now == .opened;
        reader.has_older = before == .opened;
        if (now == .newer or before == .newer) return error.Newer;
        if (now == .failed or before == .failed) return error.Unreadable;
        if (!reader.has_current and !reader.has_older) {
            if (now == .missing and before == .missing) return error.NoLog;
            // A file with no header yet is an empty log; one with a wrong header is no log.
            if (now == .bad or before == .bad) return error.Damaged;
        }
        if (reader.has_current and reader.has_older) {
            // One file seen twice (a rotation between the opens), or an order no writer makes.
            if (reader.older.base >= reader.current.base) {
                reader.older.close();
                reader.has_older = false;
            }
        }
        reader.stage = if (reader.has_older) .older else .current;
        if (reader.has_older) reader.dropped_bytes = reader.older.base;
        if (!reader.has_older and reader.has_current) reader.dropped_bytes = reader.current.base;
        if (reader.has_older) assert(reader.dropped_bytes == reader.older.base);
        if (!reader.has_older) assert(reader.stage == .current);
    }

    pub fn close(reader: *Reader) void {
        if (reader.has_older) assert(reader.older.is_open);
        if (reader.has_current) assert(reader.current.is_open);
        if (reader.has_older) reader.older.close();
        if (reader.has_current) reader.current.close();
        reader.has_older = false;
        reader.has_current = false;
    }

    /// The next record, or `end` when none is there now. With `end` returned, `follow_look`
    /// finds out whether the log was rotated, and `next` can be asked again.
    pub fn next(reader: *Reader) NextResult {
        if (reader.stage == .older) assert(reader.has_older);
        if (!reader.has_current) {
            if (reader.stage == .older) assert(reader.has_older);
        }
        if (reader.stage == .older) {
            switch (reader.older.next()) {
                .record => |found| return .{ .record = found },
                .failed => return .failed,
                // The older file is complete: its end, torn or whole, is the end of it.
                .end, .damaged => reader.stage = .current,
            }
        }
        if (!reader.has_current) return .end;
        return reader.current.next();
    }

    /// For a log still being written: looks whether the current file was replaced by a new one.
    /// If it was, whatever is left in the file this reader has open is delivered first (the
    /// writer closed it before it renamed it, so nothing more will be added), and then the new
    /// file takes its place. Returns true when it did.
    pub fn follow_look(reader: *Reader) bool {
        if (reader.stage == .current and reader.has_older) assert(reader.older.is_open);
        if (reader.stage != .current) return false;
        if (!reader.has_current) return reader.adopt_new_current();
        if (reader.current.damaged) return false;
        var probe: *Cursor = &reader.older;
        if (reader.has_older) reader.older.close();
        reader.has_older = false;
        const found = probe.open(reader.fs, reader.paths.current_text());
        if (found != .opened) return false;
        if (probe.base <= reader.current.base) {
            probe.close();
            return false;
        }
        // Rotated. The file we hold is the older one now; finish it before switching.
        probe.close();
        return true;
    }

    /// After `follow_look` returned true and `next` ran dry: switches to the new current file.
    pub fn follow_switch(reader: *Reader) bool {
        assert(reader.stage == .current);
        assert(!reader.older.is_open);
        const found = reader.older.open(reader.fs, reader.paths.current_text());
        if (found != .opened) return false;
        reader.current.close();
        std.mem.swap(Cursor, &reader.current, &reader.older);
        reader.has_current = true;
        reader.has_older = false;
        assert(reader.current.is_open);
        assert(!reader.older.is_open);
        return true;
    }

    fn adopt_new_current(reader: *Reader) bool {
        assert(!reader.has_current);
        assert(reader.stage == .current);
        const found = reader.current.open(reader.fs, reader.paths.current_text());
        if (found != .opened) return false;
        reader.has_current = true;
        assert(reader.current.is_open);
        return true;
    }
};

// ---- Tests ----------------------------------------------------------------------------------

const testing = std.testing;
const fs_sim = @import("../store/fs_sim.zig");

var sim_disk: fs_sim.SimFs = undefined;

fn test_dir(runs_text: []const u8) records.Dir {
    var dir: records.Dir = undefined;
    @memcpy(dir.path[0..runs_text.len], runs_text);
    dir.path[runs_text.len] = 0;
    dir.len = @intCast(runs_text.len);
    dir.existing_len = 0;
    return dir;
}

test "a record round-trips, and the parser accepts only what the encoder writes" {
    // Goal: the frame is fixed. Method: encode, parse, then break every byte and every length of
    // the encoded bytes and check the parser never returns a record that was not written.
    var storage: [record_bytes_total_max]u8 = @splat(0xAA);
    const record = encode_record(&storage, .stderr, 1_700_000_000, "hello\n");
    try testing.expectEqual(@as(usize, 12 + 6), record.len);
    const parsed = parse_record(record).record;
    try testing.expectEqual(Stream.stderr, parsed.stream);
    try testing.expectEqual(@as(u64, 1_700_000_000), parsed.time);
    try testing.expectEqualStrings("hello\n", parsed.payload);
    try testing.expectEqual(@as(u32, 18), parsed.size);
    for (0..record.len) |cut| {
        const result = parse_record(record[0..cut]);
        try testing.expect(result == .incomplete or (cut >= 1 and result == .bad));
    }
    var copy: [64]u8 = undefined;
    for (0..record.len) |at| {
        @memcpy(copy[0..record.len], record);
        copy[at] ^= 0x40;
        try testing.expect(parse_record(copy[0..record.len]) != .record);
    }
    // The bounds: the longest payload, and one byte past it.
    var big: [constants.log_record_bytes_max + 1]u8 = @splat('x');
    const longest = encode_record(&storage, .stdout, constants.log_time_max - 1, big[0..4096]);
    try testing.expectEqual(@as(usize, 4096 + 12), longest.len);
    try testing.expect(parse_record(longest) == .record);
    std.mem.writeInt(u16, storage[6..8], 4097, .little);
    try testing.expect(parse_record(storage[0..longest.len]) == .bad);
    std.mem.writeInt(u16, storage[6..8], 0, .little);
    try testing.expect(parse_record(storage[0..longest.len]) == .bad);
}

test "the header: version, zero bytes, base" {
    // Goal: only a header the writer makes is accepted; a newer version is told apart.
    var header: [16]u8 = undefined;
    encode_header(123456789012, &header);
    try testing.expectEqual(@as(u64, 123456789012), parse_header(&header).ok);
    try testing.expect(parse_header(header[0..15]) == .short);
    try testing.expect(parse_header("") == .short);
    header[3] = 1;
    try testing.expect(parse_header(&header) == .bad);
    header[3] = 0;
    header[0] = 2;
    try testing.expect(parse_header(&header) == .newer);
    header[0] = 0;
    try testing.expect(parse_header(&header) == .bad);
}

test "paths: the current file and the older one, beside the pasta log's name space" {
    const dir = test_dir("/s/zbx/logs");
    var paths: Paths = undefined;
    paths.set(&dir, "web");
    try testing.expectEqualStrings("/s/zbx/logs/web.log", paths.current_text());
    try testing.expectEqualStrings("/s/zbx/logs/web.log.1", paths.older_text());
    const runs = test_dir("/s/zbx/runs");
    try testing.expectEqualStrings("/s/zbx/logs", dir_of(&runs).?.text());
    const odd = test_dir("/s/zbx/other");
    try testing.expect(dir_of(&odd) == null);
}

/// What the tests write: record `index` has a stream, a time and a payload that tell its index.
fn payload_of(index: u32, out: *[24]u8) []const u8 {
    // Cannot fail: the text is 24 bytes, the size of the buffer.
    const text = std.fmt.bufPrint(out, "line {d:0>6} of the test\n", .{index}) catch unreachable;
    return text[0..@min(text.len, 24)];
}

fn stream_of(index: u32) Stream {
    return if (index % 3 == 0) .stderr else .stdout;
}

fn read_all(
    fs: Fs,
    dir: *const records.Dir,
    name: []const u8,
    indexes: *[4096]u32,
) ReadError!struct { count: u32, dropped: u64 } {
    var reader: Reader = undefined;
    try reader.open(fs, dir, name);
    defer reader.close();
    var count: u32 = 0;
    while (true) {
        switch (reader.next()) {
            .record => |found| {
                var expected: [24]u8 = undefined;
                const number = std.fmt.parseInt(u32, found.payload[5..11], 10) catch
                    return error.Damaged;
                const text = payload_of(number, &expected);
                if (!std.mem.eql(u8, text, found.payload)) return error.Damaged;
                if (found.stream != stream_of(number)) return error.Damaged;
                if (found.time != 1000 + number) return error.Damaged;
                indexes[count] = number;
                count += 1;
            },
            .end, .damaged => break,
            .failed => return error.Unreadable,
        }
    }
    return .{ .count = count, .dropped = reader.dropped_bytes };
}

fn write_numbered(writer: *Writer, from: u32, to: u32) Error!void {
    var index = from;
    while (index < to) : (index += 1) {
        var out: [24]u8 = undefined;
        try writer.append(stream_of(index), 1000 + index, payload_of(index, &out));
    }
}

const small: WriterOptions = .{
    .segment_bytes_max = 16 + 4 * (12 + 24) + 10,
    .record_bytes_max = 24,
};

test "a log that fits one file reads back whole and drops nothing" {
    // Goal: the plain path. Method: write ten records, read them, expect all, in order.
    sim_disk.init(1);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", .{});
    try write_numbered(&writer, 0, 10);
    writer.close();
    var indexes: [4096]u32 = @splat(0xFFFF_FFFF);
    const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
    try testing.expectEqual(@as(u32, 10), got.count);
    try testing.expectEqual(@as(u64, 0), got.dropped);
    for (0..10) |at| try testing.expectEqual(@as(u32, @intCast(at)), indexes[at]);
    try testing.expectEqual(@as(u32, 0), sim_disk.open_count());
}

test "at the cap the oldest whole file goes, and the reader says how many bytes" {
    // Goal: the cap mechanism. Method: a small segment, many records; the log keeps a window
    // of the newest records, contiguous, ending at the last one, and `dropped` is the bytes of
    // the records before the window.
    sim_disk.init(2);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", small);
    try write_numbered(&writer, 0, 100);
    writer.close();
    var indexes: [4096]u32 = @splat(0xFFFF_FFFF);
    const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
    try testing.expect(got.count > 4);
    try testing.expect(got.count <= 8);
    try testing.expectEqual(@as(u32, 99), indexes[got.count - 1]);
    for (1..got.count) |at| try testing.expectEqual(indexes[at - 1] + 1, indexes[at]);
    try testing.expectEqual(@as(u64, indexes[0]) * (12 + 24), got.dropped);
    // The disk holds two files, none over the segment size.
    const current = sim_disk.stat_of("/s/zbx/logs/web.log").?;
    const older = sim_disk.stat_of("/s/zbx/logs/web.log.1").?;
    try testing.expect(current.size <= small.segment_bytes_max);
    try testing.expect(older.size <= small.segment_bytes_max);
    try testing.expectEqual(@as(u32, 0), sim_disk.open_count());
}

test "a new log of a name removes what the earlier run left" {
    // Goal: a name used again starts an empty log. Method: fill past the cap, open again.
    sim_disk.init(3);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", small);
    try write_numbered(&writer, 0, 50);
    writer.close();
    try testing.expect(sim_disk.kind_of("/s/zbx/logs/web.log.1") != null);
    try writer.open(sim_disk.interface(), &dir, "web", small);
    try write_numbered(&writer, 0, 1);
    writer.close();
    try testing.expect(sim_disk.kind_of("/s/zbx/logs/web.log.1") == null);
    var indexes: [4096]u32 = undefined;
    const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
    try testing.expectEqual(@as(u32, 1), got.count);
}

test "remove takes both files, and a missing log is not an error" {
    sim_disk.init(4);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", small);
    try write_numbered(&writer, 0, 50);
    writer.close();
    try remove(sim_disk.interface(), &dir, "web");
    try testing.expect(sim_disk.kind_of("/s/zbx/logs/web.log") == null);
    try testing.expect(sim_disk.kind_of("/s/zbx/logs/web.log.1") == null);
    try remove(sim_disk.interface(), &dir, "web");
    var reader: Reader = undefined;
    try testing.expectError(error.NoLog, reader.open(sim_disk.interface(), &dir, "web"));
}

test "a long write is cut into records of the bound, and every byte comes back in order" {
    // Goal: a write of 10000 bytes is three records (4096, 4096, 1808) of one stream and time.
    sim_disk.init(5);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", .{});
    var long: [10_000]u8 = undefined;
    for (&long, 0..) |*byte, at| byte.* = @intCast('a' + at % 26);
    try writer.append(.stdout, 77, &long);
    writer.close();
    var reader: Reader = undefined;
    try reader.open(sim_disk.interface(), &dir, "web");
    defer reader.close();
    var total: usize = 0;
    var records_seen: u32 = 0;
    while (true) {
        switch (reader.next()) {
            .record => |found| {
                const want = long[total..][0..found.payload.len];
                try testing.expectEqualSlices(u8, want, found.payload);
                try testing.expectEqual(@as(u64, 77), found.time);
                total += found.payload.len;
                records_seen += 1;
            },
            else => break,
        }
    }
    try testing.expectEqual(@as(usize, 10_000), total);
    try testing.expectEqual(@as(u32, 3), records_seen);
}

test "a torn tail is skipped and what came before it is read" {
    // Goal: the reader of a log whose writer died mid-record. Method: cut the current file at
    // every length inside its last record and read: the whole records before it come back and
    // nothing else.
    sim_disk.init(6);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", .{});
    try write_numbered(&writer, 0, 5);
    writer.close();
    const whole = sim_disk.content_of("/s/zbx/logs/web.log").?;
    var copy: [512]u8 = undefined;
    @memcpy(copy[0..whole.len], whole);
    const record_size: usize = 12 + 24;
    var cut = whole.len - record_size;
    while (cut < whole.len) : (cut += 1) {
        sim_disk.remove_path("/s/zbx/logs/web.log");
        sim_disk.put_file("/s/zbx/logs/web.log", 0o600, copy[0..cut]);
        var indexes: [4096]u32 = undefined;
        const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
        try testing.expectEqual(@as(u32, 4), got.count);
    }
}

test "damage inside a record ends the file there, and never yields a record that was not written" {
    // Goal: a flipped byte anywhere after the header is caught by the CRC or the ranges.
    sim_disk.init(7);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", .{});
    try write_numbered(&writer, 0, 5);
    writer.close();
    const whole = sim_disk.content_of("/s/zbx/logs/web.log").?;
    var copy: [512]u8 = undefined;
    @memcpy(copy[0..whole.len], whole);
    for (16..whole.len) |at| {
        copy[at] ^= 0x01;
        sim_disk.remove_path("/s/zbx/logs/web.log");
        sim_disk.put_file("/s/zbx/logs/web.log", 0o600, copy[0..whole.len]);
        var indexes: [4096]u32 = undefined;
        const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
        const record_size: usize = 12 + 24;
        try testing.expectEqual(@as(u32, @intCast((at - 16) / record_size)), got.count);
        copy[at] ^= 0x01;
    }
}

test "a file from a newer version and a file that is not a log are told apart" {
    sim_disk.init(8);
    const dir = test_dir("/s/zbx/logs");
    sim_disk.put_dir("/s", 0o755);
    sim_disk.put_dir("/s/zbx", 0o755);
    sim_disk.put_dir("/s/zbx/logs", 0o755);
    var header: [16]u8 = undefined;
    encode_header(0, &header);
    header[0] = 2;
    sim_disk.put_file("/s/zbx/logs/web.log", 0o600, &header);
    var reader: Reader = undefined;
    try testing.expectError(error.Newer, reader.open(sim_disk.interface(), &dir, "web"));
    sim_disk.remove_path("/s/zbx/logs/web.log");
    sim_disk.put_file("/s/zbx/logs/web.log", 0o600, "this is not a log, it is text\n");
    try testing.expectError(error.Damaged, reader.open(sim_disk.interface(), &dir, "web"));
    sim_disk.remove_path("/s/zbx/logs/web.log");
    sim_disk.put_file("/s/zbx/logs/web.log", 0o600, header[0..9]);
    try reader.open(sim_disk.interface(), &dir, "web"); // Made, header not yet written: empty.
    defer reader.close();
    try testing.expect(reader.next() == .end);
}

/// One run of the crash test: write `total` records with a crash at write point `crash_at`,
/// restart, and check what the disk kept. Returns the number of write points the run had.
fn crash_run(crash_at: ?u32, seed: u64, total: u32) !u32 {
    sim_disk.init(seed);
    const dir = test_dir("/s/zbx/logs");
    sim_disk.faults.crash_mutation = crash_at;
    sim_disk.faults.short_write_per_mille = 300;
    var writer: Writer = undefined;
    var written: u32 = 0;
    opened: {
        writer.open(sim_disk.interface(), &dir, "web", small) catch break :opened;
        var index: u32 = 0;
        while (index < total) : (index += 1) {
            write_numbered(&writer, index, index + 1) catch break;
            written += 1;
        }
        writer.close();
    }
    const points = sim_disk.mutations;
    sim_disk.restart();
    var reader: Reader = undefined;
    reader.open(sim_disk.interface(), &dir, "web") catch |err| {
        // Nothing on the disk yet: only a crash before the first file was made.
        try testing.expect(err == error.NoLog);
        try testing.expect(crash_at != null);
        return points;
    };
    defer reader.close();
    var indexes: [4096]u32 = undefined;
    sim_disk.faults.short_write_per_mille = 0;
    const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
    // Whole records only (read_all checks each against what was written), contiguous, none
    // from the future, and a window that ends no earlier than what a sync made durable.
    if (got.count > 0) {
        for (1..got.count) |at| try testing.expectEqual(indexes[at - 1] + 1, indexes[at]);
        try testing.expect(indexes[got.count - 1] < written + 1);
    }
    if (crash_at == null) try testing.expectEqual(total - 1, indexes[got.count - 1]);
    return points;
}

test "a crash at any write point leaves a log of whole records" {
    // Goal: the brief's proof. Method: run the writer to the end once to count its write points,
    // then again with the machine dying at each point (and again with torn short writes), with
    // several seeds for the bytes a crash keeps; after each restart the log reads as a
    // contiguous run of whole records, each equal to what was written.
    const total: u32 = 40;
    const points = try crash_run(null, 100, total);
    try testing.expect(points > 40);
    var seed: u64 = 0;
    while (seed < 4) : (seed += 1) {
        var point: u32 = 0;
        while (point < points) : (point += 1) _ = try crash_run(point, 200 + seed, total);
    }
}

test "a write that fails stops the log for good" {
    // Goal: after an error nothing more is written, so no record sits behind a torn one.
    sim_disk.init(9);
    const dir = test_dir("/s/zbx/logs");
    var writer: Writer = undefined;
    try writer.open(sim_disk.interface(), &dir, "web", .{});
    try write_numbered(&writer, 0, 3);
    sim_disk.faults.bytes_max = sim_disk.bytes_live; // The disk is full from here.
    try testing.expectError(error.NoSpace, write_numbered(&writer, 3, 4));
    sim_disk.faults.bytes_max = null;
    try testing.expectError(error.IoFailed, write_numbered(&writer, 4, 5));
    writer.close();
    var indexes: [4096]u32 = undefined;
    const got = try read_all(sim_disk.interface(), &dir, "web", &indexes);
    try testing.expectEqual(@as(u32, 3), got.count);
    try testing.expectEqual(@as(u32, 0), sim_disk.open_count());
}
