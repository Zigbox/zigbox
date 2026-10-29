//! The archive of `zbx state export`: a gzip-compressed POSIX tar of a volume's `data`, written
//! with std's `std.compress.flate.Compress` (gzip container) and the header type of
//! `std.tar.Writer`. It runs in the store's namespace child, where the owners of the files are
//! the ones a container sees (postgres's 999, not the host's subordinate ids).
//!
//! Why the header is built here and not by `std.tar.Writer.writeFileStream` and its siblings:
//! those write no owner (the uid and gid fields stay zero) and know no hard link, and the
//! archive must restore anywhere with its owners, modes, times, symlinks and hard links. The
//! `Header` type, the name splitting, and the compressor are std's.
//!
//! What goes in, in this order, with names as `tar -czf x.tar.gz -C data .` makes them (`./`,
//! `./dir/`, `./dir/file`): every directory before what is in it, regular files with their bytes,
//! symlinks, and a second name of a file as a hard link to the first (`typeflag` 1). Devices,
//! sockets and fifos are left out, each with a note to the caller.
//!
//! The walk is iterative with an explicit stack of directories, as `usage.zig`'s. Past a bound
//! (depth, entries, hard-linked files, the room for their paths) the export stops and says which;
//! it never cuts. A file whose bytes change while they are read, or whose owner a ustar header
//! cannot hold, stops it too. Whoever asked for the file removes the part that was written.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const fs_mod = @import("../store/fs.zig");
const names_mod = @import("../store/names.zig");

const Fs = fs_mod.Fs;
const Io = std.Io;
const NameList = names_mod.NameList;
const Header = std.tar.Writer.Header;
const flate = std.compress.flate;

pub const Stop = enum {
    unreadable,
    too_deep,
    too_many_entries,
    too_many_links,
    names_too_big,
    /// A file ended before, or went on after, the size it had when the walk looked at it.
    changed,
    /// An owner of more than seven octal digits.
    owner_too_big,
    /// A file of more than eleven octal digits of bytes (8 GiB).
    file_too_big,
    /// The archive could not be written (the sink's failure is in `Failure.err`).
    write,

    pub fn sentence(stop: Stop) []const u8 {
        assert(@tagName(stop).len > 0);
        return switch (stop) {
            .unreadable => "a file or directory in it could not be read",
            .too_deep => "it is nested deeper than 64 directories",
            .too_many_entries => "it has more than 4194304 entries",
            .too_many_links => "it has more than 16384 files with several names, or their paths " ++
                "do not fit the room the export keeps",
            .names_too_big => "a directory's names do not fit the room the export has",
            .changed => "a file changed while it was read",
            .owner_too_big => "a file's owner is a number a tar header cannot hold",
            .file_too_big => "a file is larger than 8 GiB, which a tar header cannot hold",
            .write => "the archive could not be written",
        };
    }
};

comptime {
    // The sentences above say so.
    assert(constants.store_depth_max == 64);
    assert(constants.state_walk_entries_max == 4194304);
    assert(constants.state_walk_links_max == 16384);
}

pub const Failure = struct {
    stop: Stop,
    err: host_mod.Error,
    errno: u16,
    /// The path in the volume that was being read (empty for a write failure); valid until the
    /// workspace is used again.
    path: []const u8,
};

/// What was written.
pub const Totals = struct {
    directories: u64,
    files: u64,
    symlinks: u64,
    hard_links: u64,
    skipped: u64,
    /// The bytes of the regular files, before compression.
    bytes: u64,
    /// The bytes of the archive, after.
    archive_bytes: u64,
};

/// Told of each file left out, as it is found.
pub const Skip = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, path: []const u8, kind: fs_mod.FileKind) void,
};

/// Where the archive goes: standard output (through `write`), or an open file.
pub const Target = union(enum) {
    stdout: host_mod.Host,
    file: fs_mod.Fd,
};

const Frame = struct {
    path_len: u32,
    base: u32,
    names: NameList,
    at: u32,
};

const table_slots: u32 = constants.state_walk_links_max * 2;

/// The caller's memory, about 7 MiB: keep it in static or heap storage.
pub const Workspace = struct {
    path: [constants.path_bytes_max + 1]u8,
    frames: [constants.store_depth_max + 1]Frame,
    arena: [constants.state_walk_arena_bytes]u8,
    /// The inodes of files with several names, open addressing, zero is empty; where the first
    /// name's archive path is in `link_paths`.
    links: [table_slots]u64,
    link_offsets: [table_slots]u32,
    link_paths: [constants.state_export_links_bytes]u8,
    link_used: u32,
    links_count: u32,
    name: [constants.path_bytes_max + 4]u8,
    link_name: [constants.path_bytes_max + 4]u8,
    io: [constants.state_export_buffer_bytes]u8,
    out: [constants.state_export_buffer_bytes]u8,
    window: [flate.max_window_len]u8,
    sink: Sink,
    gzip: flate.Compress,
};

/// An `Io.Writer` that sends what it is given to the target, in the pieces it is drained in.
const Sink = struct {
    writer: Io.Writer,
    target: Target,
    fs: Fs,
    failed: ?host_mod.Error,
    errno: u16,
    bytes: u64,

    fn init(sink: *Sink, target: Target, fs: Fs, buffer: []u8) void {
        sink.* = .{
            .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } },
            .target = target,
            .fs = fs,
            .failed = null,
            .errno = 0,
            .bytes = 0,
        };
    }

    fn put(sink: *Sink, bytes: []const u8) Io.Writer.Error!void {
        if (bytes.len == 0) return;
        if (sink.failed != null) return error.WriteFailed;
        const result = switch (sink.target) {
            .stdout => |host| host.write_all(.stdout, bytes),
            .file => |fd| sink.fs.write_all(fd, bytes),
        };
        result catch |err| {
            sink.failed = err;
            sink.errno = switch (sink.target) {
                .stdout => |host| host.last_errno(),
                .file => sink.fs.last_errno(),
            };
            return error.WriteFailed;
        };
        sink.bytes += bytes.len;
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        assert(data.len > 0);
        const sink: *Sink = @fieldParentPtr("writer", w);
        try sink.put(w.buffer[0..w.end]);
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |piece| {
            try sink.put(piece);
            consumed += piece.len;
        }
        const last = data[data.len - 1];
        if (last.len == 1) {
            var chunk: [256]u8 = undefined;
            @memset(&chunk, last[0]);
            var left = splat;
            while (left > 0) {
                const count = @min(left, chunk.len);
                try sink.put(chunk[0..count]);
                left -= count;
            }
            consumed += splat;
        } else {
            for (0..splat) |_| {
                try sink.put(last);
                consumed += last.len;
            }
        }
        return consumed;
    }
};

pub const Error = error{Stopped};

const block: usize = 512;

const Walk = struct {
    fs: Fs,
    ws: *Workspace,
    totals: *Totals,
    failure: *Failure,
    skip: Skip,
    archive: *Io.Writer,
    root_len: u32,
    depth: u32,
    entries: u64,

    fn stop(walk: *Walk, reason: Stop, err: host_mod.Error, path_len: u32) Error {
        walk.failure.* = .{
            .stop = reason,
            .err = err,
            .errno = walk.fs.last_errno(),
            .path = walk.ws.path[0..path_len],
        };
        return error.Stopped;
    }

    fn text(walk: *const Walk, length: u32) [:0]const u8 {
        assert(length > 0);
        walk.ws.path[length] = 0;
        return walk.ws.path[0..length :0];
    }

    /// A failed write of the archive: the sink says why.
    fn write_failed(walk: *Walk) Error {
        const sink = &walk.ws.sink;
        walk.failure.* = .{
            .stop = .write,
            .err = sink.failed orelse error.IoFailed,
            .errno = sink.errno,
            .path = "",
        };
        return error.Stopped;
    }

    fn push(walk: *Walk, length: u32) Error!void {
        if (walk.depth > constants.store_depth_max) {
            return walk.stop(.too_deep, error.IoFailed, length);
        }
        const base: u32 = if (walk.depth == 0) 0 else blk: {
            const parent = &walk.ws.frames[walk.depth - 1];
            break :blk parent.base + parent.names.used;
        };
        const frame = &walk.ws.frames[walk.depth];
        frame.* = .{
            .path_len = length,
            .base = base,
            .names = NameList.init(walk.ws.arena[base..], constants.store_dir_entries_max),
            .at = 0,
        };
        walk.fs.read_dir(walk.text(length), frame.names.visitor()) catch |err| {
            return walk.stop(.unreadable, err, length);
        };
        if (!frame.names.complete()) return walk.stop(.names_too_big, error.IoFailed, length);
        walk.depth += 1;
    }

    fn step(walk: *Walk) Error!void {
        assert(walk.depth > 0);
        const frame = &walk.ws.frames[walk.depth - 1];
        if (frame.at == frame.names.used) {
            walk.depth -= 1;
            return;
        }
        const name = frame.names.at(frame.at);
        frame.at += @intCast(1 + name.len);
        if (frame.path_len + 1 + name.len > constants.path_bytes_max) {
            return walk.stop(.too_deep, error.PathTooLong, frame.path_len);
        }
        const length: u32 = frame.path_len + 1 + @as(u32, @intCast(name.len));
        walk.ws.path[frame.path_len] = '/';
        @memcpy(walk.ws.path[frame.path_len + 1 ..][0..name.len], name);
        try walk.entry(length);
    }

    /// The archive name of the path being read: `.` and what is below the root; a directory's
    /// ends in a slash.
    fn archive_name(walk: *Walk, length: u32, is_dir: bool) []const u8 {
        const relative = walk.ws.path[walk.root_len..length];
        const name = &walk.ws.name;
        name[0] = '.';
        @memcpy(name[1..][0..relative.len], relative);
        var used = 1 + relative.len;
        if (is_dir) {
            name[used] = '/';
            used += 1;
        }
        return name[0..used];
    }

    fn entry(walk: *Walk, length: u32) Error!void {
        walk.entries += 1;
        if (walk.entries > constants.state_walk_entries_max) {
            return walk.stop(.too_many_entries, error.IoFailed, length);
        }
        const found = walk.fs.lstat(walk.text(length)) catch |err| {
            return walk.stop(.unreadable, err, length);
        };
        switch (found.kind) {
            .dir => {
                const name = walk.archive_name(length, true);
                try walk.put_header(.directory, name, "", &found, length);
                walk.totals.directories += 1;
                try walk.push(length);
            },
            .file => try walk.file_entry(length, &found),
            .symlink => try walk.symlink_entry(length, &found),
            .char_device, .block_device, .fifo, .socket => {
                walk.totals.skipped += 1;
                // The note names the path inside the volume (`/p`), not the host's layout.
                const inside = walk.ws.path[walk.root_len..length];
                walk.skip.call(walk.skip.context, inside, found.kind);
            },
        }
    }

    fn symlink_entry(walk: *Walk, length: u32, found: *const fs_mod.Stat) Error!void {
        const target = walk.fs.read_link(walk.text(length), &walk.ws.link_name) catch |err| {
            return walk.stop(.unreadable, err, length);
        };
        const name = walk.archive_name(length, false);
        try walk.put_header(.symlink, name, target, found, length);
        walk.totals.symlinks += 1;
    }

    fn file_entry(walk: *Walk, length: u32, found: *const fs_mod.Stat) Error!void {
        if (found.size > file_bytes_max) {
            return walk.stop(.file_too_big, error.FileTooLarge, length);
        }
        const name = walk.archive_name(length, false);
        if (found.links > 1) {
            if (try walk.remembered(found.inode, name, length)) |first| {
                try walk.put_header(.hard_link, name, first, found, length);
                walk.totals.hard_links += 1;
                return;
            }
        }
        try walk.put_header(.regular, name, "", found, length);
        try walk.put_contents(length, found.size);
        walk.totals.files += 1;
        walk.totals.bytes += found.size;
    }

    /// The archive path of the first name of the inode, if it was written already; else it is
    /// remembered as `name`.
    fn remembered(walk: *Walk, inode: u64, name: []const u8, length: u32) Error!?[]const u8 {
        assert(inode != 0);
        const ws = walk.ws;
        var slot: u32 = @intCast(std.hash.int(inode) % table_slots);
        // The table is at most half full, so a free slot is found.
        for (0..table_slots) |_| {
            if (ws.links[slot] == inode) {
                const rest = ws.link_paths[ws.link_offsets[slot]..];
                return rest[0..std.mem.indexOfScalar(u8, rest, 0).?];
            }
            if (ws.links[slot] == 0) {
                const room = ws.link_paths.len - ws.link_used;
                if (ws.links_count == constants.state_walk_links_max or room < name.len + 1) {
                    return walk.stop(.too_many_links, error.IoFailed, length);
                }
                ws.links[slot] = inode;
                ws.link_offsets[slot] = ws.link_used;
                @memcpy(ws.link_paths[ws.link_used..][0..name.len], name);
                ws.link_paths[ws.link_used + name.len] = 0;
                ws.link_used += @intCast(name.len + 1);
                ws.links_count += 1;
                return null;
            }
            slot = (slot + 1) % table_slots;
        }
        unreachable; // At most half the slots are used.
    }

    fn put_header(
        walk: *Walk,
        kind: EntryKind,
        name: []const u8,
        link: []const u8,
        found: *const fs_mod.Stat,
        length: u32,
    ) Error!void {
        write_header(walk.archive, kind, name, link, found) catch |err| switch (err) {
            error.WriteFailed => return walk.write_failed(),
            error.OwnerTooBig => return walk.stop(.owner_too_big, error.IoFailed, length),
        };
    }

    /// The file's bytes, exactly `size` of them, then the padding to a whole block.
    fn put_contents(walk: *Walk, length: u32, size: u64) Error!void {
        const ws = walk.ws;
        const fd = walk.fs.open_read(walk.text(length)) catch |err| {
            return walk.stop(.unreadable, err, length);
        };
        defer walk.fs.close(fd);
        var left = size;
        while (left > 0) {
            const want: usize = @intCast(@min(left, ws.io.len));
            const count = walk.fs.read(fd, ws.io[0..want]) catch |err| {
                return walk.stop(.unreadable, err, length);
            };
            if (count == 0) return walk.stop(.changed, error.IoFailed, length);
            walk.archive.writeAll(ws.io[0..count]) catch return walk.write_failed();
            left -= count;
        }
        // The file must end where it did: a longer file is one that changed.
        const more = walk.fs.read(fd, ws.io[0..1]) catch |err| {
            return walk.stop(.unreadable, err, length);
        };
        if (more != 0) return walk.stop(.changed, error.IoFailed, length);
        pad(walk.archive, size) catch return walk.write_failed();
    }
};

pub const EntryKind = enum { directory, regular, symlink, hard_link };

pub const HeaderError = error{ WriteFailed, OwnerTooBig };

fn pad(writer: *Io.Writer, size: u64) Io.Writer.Error!void {
    const rest: usize = @intCast(size % block);
    if (rest == 0) return;
    try writer.splatByteAll(0, block - rest);
}

/// Fills `field` with `value` in octal, zero-padded on the left; false if it does not fit.
fn fill_octal(field: []u8, value: u64) bool {
    var rest = value;
    var at = field.len;
    @memset(field, '0');
    while (rest > 0) {
        if (at == 0) return false;
        at -= 1;
        field[at] = '0' + @as(u8, @intCast(rest % 8));
        rest /= 8;
    }
    return true;
}

/// A GNU long name or long link record: the text that did not fit the header, as a file.
fn write_extended(writer: *Io.Writer, kind: Header.FileType, text: []const u8) HeaderError!void {
    assert(kind != .regular);
    assert(kind != .directory);
    var header: Header = .init(kind);
    // The name GNU tar gives these records; a reader that stops at an empty name must not.
    const record_name = "././@LongLink";
    @memcpy(header.name[0..record_name.len], record_name);
    header.setSize(text.len) catch unreachable; // A path of at most 4100 bytes.
    header.write(writer) catch |err| switch (err) {
        error.WriteFailed => return error.WriteFailed,
        error.OctalOverflow => unreachable, // The checksum of a header is far below 8^7.
    };
    writer.writeAll(text) catch return error.WriteFailed;
    pad(writer, text.len) catch return error.WriteFailed;
}

/// One entry's header (and the long-name records before it that it needs).
pub fn write_header(
    writer: *Io.Writer,
    kind: EntryKind,
    name: []const u8,
    link: []const u8,
    found: *const fs_mod.Stat,
) HeaderError!void {
    assert(name.len > 0);
    assert((kind == .symlink or kind == .hard_link) == (link.len > 0));
    var header: Header = .init(switch (kind) {
        .directory => .directory,
        .symlink => .symbolic_link,
        .regular, .hard_link => .regular,
    });
    // A tar header holds seven octal digits of owner: a larger id cannot be written.
    const owner_max: u64 = constants.state_export_id_max;
    if (found.uid > owner_max or found.gid > owner_max) return error.OwnerTooBig;
    const fitted = [3]bool{
        fill_octal(&header.uid, found.uid),
        fill_octal(&header.gid, found.gid),
        fill_octal(&header.mode, found.mode),
    };
    assert(fitted[0]); // Seven digits hold the largest owner checked above, and any mode.
    assert(fitted[1]);
    assert(fitted[2]);
    const size: u64 = if (kind == .regular) found.size else 0;
    header.setSize(size) catch unreachable; // Eleven octal digits hold 8 GiB; see below.
    // Cannot fail: the time is cut to eleven octal digits.
    header.setMtime(@min(found.mtime, constants.state_export_time_max)) catch unreachable; // Same.
    if (kind == .hard_link) {
        // `Header.FileType` has no hard link, but the byte is the format's: '1'.
        const bytes: *[block]u8 = @ptrCast(&header);
        bytes[156] = '1';
    }
    header.setPath("", name) catch |err| switch (err) {
        error.NameTooLong => {
            try write_extended(writer, .gnu_long_name, name);
            // As GNU tar does: the header carries the first bytes, for readers without the record.
            @memcpy(&header.name, name[0..header.name.len]);
        },
        else => unreachable, // `setPath` fails only on the length.
    };
    if (link.len > 0) {
        header.setLinkname(link) catch |err| switch (err) {
            error.NameTooLong => {
                try write_extended(writer, .gnu_long_link, link);
                @memcpy(&header.linkname, link[0..header.linkname.len]);
            },
            else => unreachable, // Same.
        };
    }
    header.write(writer) catch |err| switch (err) {
        error.WriteFailed => return error.WriteFailed,
        error.OctalOverflow => unreachable, // Same as above.
    };
}

comptime {
    // `setSize` holds eleven octal digits: files past 8 GiB-1 are refused by the walk below.
    assert(@typeInfo(@TypeOf(@as(Header, .{}).size)).array.len == 11);
}

/// The largest file an archive of this kind holds: eleven octal digits.
pub const file_bytes_max: u64 = 0o77777777777;

/// Writes the archive of everything under `root` (a directory) to `target`, and fills `totals`.
/// The part of the archive written before a stop is not undone: that is the caller's.
pub fn write(
    fs: Fs,
    ws: *Workspace,
    root: [:0]const u8,
    target: Target,
    skip: Skip,
    totals: *Totals,
    failure: *Failure,
) Error!void {
    assert(root.len > 1);
    assert(root.len <= constants.path_bytes_max);
    totals.* = std.mem.zeroes(Totals);
    @memset(&ws.links, 0);
    ws.link_used = 0;
    ws.links_count = 0;
    ws.sink.init(target, fs, &ws.out);
    ws.gzip = flate.Compress.init(&ws.sink.writer, &ws.window, .gzip, .default) catch {
        failure.* = .{
            .stop = .write,
            .err = ws.sink.failed orelse error.IoFailed,
            .errno = ws.sink.errno,
            .path = "",
        };
        return error.Stopped;
    };
    var walk: Walk = .{
        .fs = fs,
        .ws = ws,
        .totals = totals,
        .failure = failure,
        .skip = skip,
        .archive = &ws.gzip.writer,
        .root_len = @intCast(root.len),
        .depth = 0,
        .entries = 0,
    };
    @memcpy(ws.path[0..root.len], root);
    const top = fs.lstat(root) catch |err| return walk.stop(.unreadable, err, @intCast(root.len));
    if (top.kind != .dir) return walk.stop(.unreadable, error.NotFound, @intCast(root.len));
    try walk.put_header(.directory, "./", "", &top, @intCast(root.len));
    totals.directories += 1;
    try walk.push(@intCast(root.len));
    // Each step reads one entry or finishes one directory, and every entry is read once: the
    // loop ends, bounded by `state_walk_entries_max` and the depth.
    while (walk.depth > 0) try walk.step();
    walk.archive.splatByteAll(0, 2 * block) catch return walk.write_failed();
    ws.gzip.finish() catch return walk.write_failed();
    ws.sink.writer.flush() catch return walk.write_failed();
    totals.archive_bytes = ws.sink.bytes;
}

const testing = std.testing;
