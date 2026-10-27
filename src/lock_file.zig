//! `zbx.lock`: which image each reference of a project means. One entry per reference: the
//! reference as it was written, the digest of the image manifest it resolved to, the platform,
//! and the tree digest the image became. The lock lives in the project directory, which is the
//! nearest directory up from the working directory that has one, or else the working directory.
//!
//! The file is ZON, versioned, sorted by reference, and written atomically. It is written one
//! field a line, in this shape, and read line by line (a hand edit of a digest is the use case):
//!
//!   .{
//!       .version = 1,
//!       .images = .{
//!           .{
//!               .reference = "alpine:3.20",
//!               .manifest = "sha256:...",
//!               .platform = "linux/amd64",
//!               .tree = "b3:...",
//!           },
//!       },
//!   }
//!
//! Two references that mean the same image (`alpine:3.20`, `docker.io/library/alpine:3.20`) are
//! one entry. The lock never records where bytes came from: a mirror (`ZBX_REGISTRY_MIRRORS`) is
//! not in it.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host_mod = @import("host.zig");
const reference_mod = @import("registry/reference.zig");
const digest_mod = @import("store/digest.zig");
const fs_mod = @import("store/fs.zig");
const roots = @import("store/roots.zig");
const Sha256 = @import("registry/digest.zig").Sha256;

const Digest = digest_mod.Digest;
const Fs = fs_mod.Fs;
const Host = host_mod.Host;

pub const file_name = "zbx.lock";
pub const version: u32 = 1;

pub const Entry = struct {
    reference_at: u32,
    reference_len: u16,
    manifest: Sha256,
    tree: Digest,
    platform: [16]u8,
    platform_len: u8,

    pub fn platform_text(entry: *const Entry) []const u8 {
        assert(entry.platform_len > 0);
        assert(entry.platform_len <= entry.platform.len);
        return entry.platform[0..entry.platform_len];
    }
};

pub const Lock = struct {
    entries: [constants.lock_entries_max]Entry,
    count: u32,
    pool: [constants.lock_pool_bytes]u8,
    pool_len: u32,

    pub fn clear(lock: *Lock) void {
        assert(lock.pool.len == constants.lock_pool_bytes);
        assert(lock.entries.len == constants.lock_entries_max);
        lock.count = 0;
        lock.pool_len = 0;
    }

    pub fn reference(lock: *const Lock, entry: *const Entry) []const u8 {
        assert(entry.reference_at + @as(u32, entry.reference_len) <= lock.pool_len);
        return lock.pool[entry.reference_at..][0..entry.reference_len];
    }

    /// The index of the entry that means the same image as `written`, or null.
    pub fn find(lock: *const Lock, written: []const u8) ?u32 {
        assert(written.len <= constants.arg_bytes_max);
        for (lock.entries[0..lock.count], 0..) |*entry, index| {
            if (same_reference(lock.reference(entry), written)) return @intCast(index);
        }
        return null;
    }

    pub const PutError = error{ Full, BadReference };

    /// Adds the entry or replaces the one for the same image (it keeps the reference as it was
    /// first written). The entries stay sorted by reference.
    pub fn put(
        lock: *Lock,
        written: []const u8,
        manifest: Sha256,
        platform: []const u8,
        tree: Digest,
    ) PutError!void {
        assert(lock.count <= constants.lock_entries_max);
        assert(platform.len > 0);
        assert(platform.len <= 16);
        if (written.len == 0 or written.len > constants.reference_bytes_max) {
            return error.BadReference;
        }
        if (lock.find(written)) |index| {
            const entry = &lock.entries[index];
            entry.manifest = manifest;
            entry.tree = tree;
            @memcpy(entry.platform[0..platform.len], platform);
            entry.platform_len = @intCast(platform.len);
            return;
        }
        if (lock.count == constants.lock_entries_max) return error.Full;
        if (lock.pool_len + written.len > lock.pool.len) return error.Full;
        const at = lock.pool_len;
        @memcpy(lock.pool[at..][0..written.len], written);
        lock.pool_len += @intCast(written.len);
        var entry: Entry = .{
            .reference_at = at,
            .reference_len = @intCast(written.len),
            .manifest = manifest,
            .tree = tree,
            .platform = undefined,
            .platform_len = @intCast(platform.len),
        };
        @memcpy(entry.platform[0..platform.len], platform);
        var place: u32 = lock.count;
        while (place > 0 and std.mem.order(
            u8,
            lock.reference(&lock.entries[place - 1]),
            written,
        ) == .gt) {
            lock.entries[place] = lock.entries[place - 1];
            place -= 1;
        }
        lock.entries[place] = entry;
        lock.count += 1;
    }
};

/// True if the two references name the same image: the same registry, repository, tag and
/// digest. Text that is not a reference is equal only to itself.
pub fn same_reference(first: []const u8, second: []const u8) bool {
    assert(first.len <= constants.reference_bytes_max);
    assert(second.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, first, second)) return true;
    var one: reference_mod.Reference = undefined;
    var other: reference_mod.Reference = undefined;
    reference_mod.parse(first, &one) catch return false;
    reference_mod.parse(second, &other) catch return false;
    var one_text: reference_mod.Formatted = undefined;
    var other_text: reference_mod.Formatted = undefined;
    return std.mem.eql(u8, one.format(&one_text), other.format(&other_text));
}

// ---- Writing -------------------------------------------------------------------------------

/// The lock as text; the buffer is `constants.lock_file_bytes_max`.
pub fn render(lock: *const Lock, buffer: []u8) []const u8 {
    assert(buffer.len >= constants.lock_file_bytes_max);
    assert(lock.count <= constants.lock_entries_max);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: 256 entries of a reference (1024 bytes at the most, 64 KiB together; escaped
    // four bytes a byte at the worst, 256 KiB: the pool bounds it below) and 300 bytes of fixed
    // text each; the constants assert the sum.
    const head = ".{{\n    .version = {d},\n    .images = .{{\n";
    writer.print(head, .{version}) catch unreachable; // Sized above.
    for (lock.entries[0..lock.count]) |*entry| {
        writer.writeAll("        .{\n            .reference = ") catch unreachable; // Same bound.
        put_text(&writer, lock.reference(entry));
        writer.print(
            ",\n            .manifest = \"{s}\",\n",
            .{&entry.manifest.text()},
        ) catch unreachable; // Sized above.
        writer.print(
            "            .platform = \"{s}\",\n",
            .{entry.platform_text()},
        ) catch unreachable; // Sized above.
        writer.print(
            "            .tree = \"{s}\",\n        }},\n",
            .{entry.tree.text()},
        ) catch unreachable; // Sized above.
    }
    writer.writeAll("    },\n}\n") catch unreachable; // Same bound.
    return writer.buffered();
}

/// A reference is printable ASCII; anything else (a hand edit gone wrong) is escaped.
fn put_text(writer: *std.Io.Writer, text: []const u8) void {
    assert(text.len <= constants.reference_bytes_max);
    var shown: [constants.reference_bytes_max * 4 + 2]u8 = undefined;
    var inner = std.Io.Writer.fixed(&shown);
    for (text) |byte| {
        switch (byte) {
            '"' => inner.writeAll("\\\"") catch unreachable, // Sized: four bytes a byte.
            '\\' => inner.writeAll("\\\\") catch unreachable, // Same.
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => {
                inner.writeByte(byte) catch unreachable; // Same.
            },
            else => inner.print("\\x{x:0>2}", .{byte}) catch unreachable, // Same.
        }
    }
    writer.writeAll("\"") catch unreachable; // The caller's bound.
    writer.writeAll(inner.buffered()) catch unreachable; // Same.
    writer.writeAll("\"") catch unreachable; // Same.
}

// ---- Reading -------------------------------------------------------------------------------

pub const ProblemKind = enum {
    /// A line that is none of the lines of a lock.
    unknown_line,
    /// A value that is not a quoted string, a digest or a platform of the right shape.
    bad_value,
    /// An entry without one of its four fields, or a field twice.
    incomplete_entry,
    /// No `.version`.
    no_version,
    /// A newer version than this zbx reads.
    newer,
    /// Two entries for one image.
    duplicate,
    /// More entries or bytes than a lock holds.
    too_big,
};

pub const Problem = struct {
    kind: ProblemKind,
    /// The line, counting from 1; 0 for the file as a whole.
    line: u32,
};

const Fields = packed struct(u8) {
    reference: bool = false,
    manifest: bool = false,
    platform: bool = false,
    tree: bool = false,
    _unused: u4 = 0,

    fn complete(fields: Fields) bool {
        return fields.reference and fields.manifest and fields.platform and fields.tree;
    }
};

/// Reads `text` into `lock`; null if it is a lock, else what is wrong and where.
pub fn parse(text: []const u8, lock: *Lock) ?Problem {
    assert(text.len <= constants.lock_file_bytes_max);
    lock.clear();
    var version_seen: u32 = 0;
    var open: ?Entry = null;
    var fields: Fields = .{};
    var number: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (is_structure(line)) continue;
        const equals = std.mem.indexOf(u8, line, " = ");
        if (line[0] != '.' or equals == null) return .{ .kind = .unknown_line, .line = number };
        const key = line[1..equals.?];
        var value = line[equals.? + 3 ..];
        if (value.len > 0 and value[value.len - 1] == ',') value = value[0 .. value.len - 1];
        if (std.mem.eql(u8, key, "version")) {
            version_seen = std.fmt.parseInt(u32, value, 10) catch {
                return .{ .kind = .bad_value, .line = number };
            };
            if (version_seen > version) return .{ .kind = .newer, .line = number };
        } else if (std.mem.eql(u8, key, "images")) {
            continue;
        } else if (std.mem.eql(u8, key, "reference")) {
            if (finish_entry(lock, &open, fields, number)) |problem| return problem;
            fields = .{ .reference = true };
            open = start_entry(lock, value) orelse return .{ .kind = .bad_value, .line = number };
        } else if (open) |*entry| {
            if (set_field(entry, &fields, key, value) == false) {
                return .{ .kind = .bad_value, .line = number };
            }
        } else {
            return .{ .kind = .unknown_line, .line = number };
        }
    }
    if (finish_entry(lock, &open, fields, number)) |problem| return problem;
    if (version_seen == 0) return .{ .kind = .no_version, .line = 0 };
    return null;
}

/// The lines that only shape the file: braces and the `.images = .{` opener.
fn is_structure(line: []const u8) bool {
    assert(line.len > 0);
    const names = [_][]const u8{ ".{", "}", "},", "}," };
    for (names) |name| {
        if (std.mem.eql(u8, line, name)) return true;
    }
    return false;
}

fn start_entry(lock: *Lock, value: []const u8) ?Entry {
    assert(lock.count <= constants.lock_entries_max);
    var word: [constants.reference_bytes_max]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return null;
    if (length == 0) return null;
    if (lock.pool_len + length > lock.pool.len) return null;
    const at = lock.pool_len;
    @memcpy(lock.pool[at..][0..length], word[0..length]);
    lock.pool_len += @intCast(length);
    return .{
        .reference_at = at,
        .reference_len = @intCast(length),
        .manifest = undefined,
        .tree = undefined,
        .platform = undefined,
        .platform_len = 0,
    };
}

fn set_field(entry: *Entry, fields: *Fields, key: []const u8, value: []const u8) bool {
    assert(entry.reference_len > 0);
    var word: [constants.store_digest_text_bytes + 8]u8 = undefined;
    const length = roots.parse_string(value, &word) orelse return false;
    const text = word[0..length];
    if (std.mem.eql(u8, key, "manifest")) {
        if (fields.manifest) return false;
        entry.manifest = Sha256.parse(text) orelse return false;
        fields.manifest = true;
    } else if (std.mem.eql(u8, key, "tree")) {
        if (fields.tree) return false;
        entry.tree = Digest.parse(text) orelse return false;
        fields.tree = true;
    } else if (std.mem.eql(u8, key, "platform")) {
        if (fields.platform) return false;
        if (text.len == 0 or text.len > entry.platform.len) return false;
        @memcpy(entry.platform[0..text.len], text);
        entry.platform_len = @intCast(text.len);
        fields.platform = true;
    } else {
        return false;
    }
    return true;
}

/// Adds the entry being read, if there is one: it must have its four fields and be new.
fn finish_entry(lock: *Lock, open: *?Entry, fields: Fields, number: u32) ?Problem {
    assert(number > 0);
    const entry = open.* orelse return null;
    open.* = null;
    if (!fields.complete()) return .{ .kind = .incomplete_entry, .line = number };
    if (lock.count == constants.lock_entries_max) return .{ .kind = .too_big, .line = number };
    const written = lock.pool[entry.reference_at..][0..entry.reference_len];
    // The reference was copied into the pool when the entry began, so the lock holds it; look
    // among the entries before this one.
    for (lock.entries[0..lock.count]) |*other| {
        if (same_reference(lock.reference(other), written)) {
            return .{ .kind = .duplicate, .line = number };
        }
    }
    var place: u32 = lock.count;
    while (place > 0 and std.mem.order(
        u8,
        lock.reference(&lock.entries[place - 1]),
        written,
    ) == .gt) {
        lock.entries[place] = lock.entries[place - 1];
        place -= 1;
    }
    lock.entries[place] = entry;
    lock.count += 1;
    return null;
}

// ---- Where it is, and the file -------------------------------------------------------------

/// The path of the lock to use.
pub const Located = struct {
    path: [constants.path_bytes_max + 1]u8,
    len: u32,
    /// The directory of the lock, without the file name or the last slash ("" for the root).
    directory_len: u32,
    /// Whether the file is there.
    exists: bool,

    pub fn text(located: *const Located) [:0]const u8 {
        assert(located.len > 0);
        assert(located.path[located.len] == 0);
        return located.path[0..located.len :0];
    }

    pub fn directory(located: *const Located) []const u8 {
        assert(located.directory_len < located.len);
        return located.path[0..located.directory_len];
    }

    fn set(located: *Located, directory_text: []const u8) bool {
        assert(directory_text.len < constants.path_bytes_max);
        // The root's directory is "": the path is "/zbx.lock".
        const trimmed = std.mem.trimEnd(u8, directory_text, "/");
        const total = trimmed.len + 1 + file_name.len;
        if (total > constants.path_bytes_max) return false;
        @memcpy(located.path[0..trimmed.len], trimmed);
        located.path[trimmed.len] = '/';
        @memcpy(located.path[trimmed.len + 1 ..][0..file_name.len], file_name);
        located.path[total] = 0;
        located.len = @intCast(total);
        located.directory_len = @intCast(trimmed.len);
        return true;
    }
};

pub const LocateError = error{ NoDirectory, TooLong };

/// The lock of the project: the nearest `zbx.lock` from the working directory up, else the
/// place for one in the working directory.
pub fn locate(host: Host, fs: Fs, located: *Located) LocateError!void {
    assert(located.path.len > constants.path_bytes_max);
    var cwd_storage: [constants.path_bytes_max]u8 = undefined;
    const cwd = host.working_directory(&cwd_storage) catch return error.NoDirectory;
    var directory: []const u8 = cwd;
    while (true) {
        if (!located.set(directory)) return error.TooLong;
        if (fs.lstat(located.text())) |stat| {
            if (stat.kind == .file) {
                located.exists = true;
                return;
            }
        } else |_| {}
        if (directory.len <= 1) break;
        const slash = std.mem.lastIndexOfScalar(u8, directory, '/') orelse break;
        directory = directory[0..slash];
    }
    if (!located.set(cwd)) return error.TooLong;
    located.exists = false;
}

pub const ReadError = error{ Unreadable, TooBig };

/// Reads the file at `located` into `lock`. `buffer` is `constants.lock_file_bytes_max`. A lock
/// that is not there is an empty one; whether the text is a lock is `parse`'s answer.
pub fn read(fs: Fs, located: *const Located, buffer: []u8, lock: *Lock) ReadError!?Problem {
    assert(buffer.len >= constants.lock_file_bytes_max);
    if (!located.exists) {
        lock.clear();
        return null;
    }
    const text = fs.read_whole(
        located.text(),
        buffer[0..constants.lock_file_bytes_max],
    ) catch |err| {
        return if (err == error.FileTooLarge) error.TooBig else error.Unreadable;
    };
    return parse(text, lock);
}

/// Writes the lock atomically: a temporary file in the same directory, flushed, renamed over.
pub fn write(
    host: Host,
    fs: Fs,
    located: *const Located,
    lock: *const Lock,
    buffer: []u8,
    failure: *fs_mod.Failure,
) host_mod.Error!void {
    assert(buffer.len >= constants.lock_file_bytes_max);
    const text = render(lock, buffer);
    var temporary: [constants.path_bytes_max + 1]u8 = undefined;
    const made = std.fmt.bufPrintSentinel(&temporary, "{s}/.{s}.{d}", .{
        located.directory(), file_name, host.own_pid(),
    }, 0) catch return fs.note(failure, error.FileTooLarge);
    // The directory to flush: its path, or "/" for the root.
    var directory_storage: [constants.path_bytes_max + 1]u8 = undefined;
    const shown = if (located.directory_len == 0) "/" else located.directory();
    const directory = std.fmt.bufPrintSentinel(&directory_storage, "{s}", .{shown}, 0) catch {
        return fs.note(failure, error.FileTooLarge);
    };
    try fs.write_atomic_stamped(made, located.text(), directory, text, 0o644, false, failure);
}

/// The lock of the project and the memory to read and write it in; the caller's.
pub const Workspace = struct {
    lock: Lock,
    text: [constants.lock_file_bytes_max]u8,
    located: Located,
};

/// Why the lock could not be opened or saved.
pub const Failure = union(enum) {
    /// The working directory is not known, or the lock's path is too long.
    no_directory,
    unreadable,
    problem: Problem,
    full,
    write: fs_mod.Failure,
};

pub const Error = error{Failed};

/// Finds the project's lock and reads it into `workspace.lock` (empty if there is none).
pub fn open_project(host: Host, fs: Fs, workspace: *Workspace, failure: *Failure) Error!void {
    assert(workspace.text.len == constants.lock_file_bytes_max);
    locate(host, fs, &workspace.located) catch {
        failure.* = .no_directory;
        return error.Failed;
    };
    const found = read(fs, &workspace.located, &workspace.text, &workspace.lock) catch {
        failure.* = .unreadable;
        return error.Failed;
    };
    if (found) |problem| {
        failure.* = .{ .problem = problem };
        return error.Failed;
    }
}

/// Writes `workspace.lock` to its place, atomically.
pub fn save(host: Host, fs: Fs, workspace: *Workspace, failure: *Failure) Error!void {
    assert(workspace.located.len > 0);
    var raised: fs_mod.Failure = undefined;
    write(host, fs, &workspace.located, &workspace.lock, &workspace.text, &raised) catch {
        failure.* = .{ .write = raised };
        return error.Failed;
    };
    workspace.located.exists = true;
}

const testing = std.testing;

fn digest_of(text: []const u8) Sha256 {
    return Sha256.of(text);
}

fn filled() Lock {
    var lock: Lock = undefined;
    lock.clear();
    return lock;
}

test "entries are kept sorted, and one image is one entry" {
    // Goal: put sorts; a second spelling of the same image replaces, and keeps the first text.
    var lock = filled();
    try lock.put("python:3.12-slim", digest_of("p"), "linux/amd64", Digest.of("pt"));
    try lock.put("alpine:3.20", digest_of("a"), "linux/amd64", Digest.of("at"));
    try lock.put("ghcr.io/o/i:v1", digest_of("g"), "linux/arm64", Digest.of("gt"));
    try testing.expectEqual(@as(u32, 3), lock.count);
    try testing.expectEqualStrings("alpine:3.20", lock.reference(&lock.entries[0]));
    try testing.expectEqualStrings("ghcr.io/o/i:v1", lock.reference(&lock.entries[1]));
    try testing.expectEqualStrings("python:3.12-slim", lock.reference(&lock.entries[2]));
    try lock.put("docker.io/library/alpine:3.20", digest_of("a2"), "linux/amd64", Digest.of("at2"));
    try testing.expectEqual(@as(u32, 3), lock.count);
    try testing.expectEqualStrings("alpine:3.20", lock.reference(&lock.entries[0]));
    try testing.expect(lock.entries[0].manifest.eql(digest_of("a2")));
    try testing.expectEqual(@as(?u32, 0), lock.find("docker.io/library/alpine:3.20"));
    try testing.expectEqual(@as(?u32, null), lock.find("alpine:3.19"));
    try testing.expectEqual(@as(?u32, null), lock.find("not a reference"));
}

test "a lock round-trips, and what it writes is ZON in the documented shape" {
    // Goal: render then parse gives the same entries; the text is the shape the header shows.
    var lock = filled();
    try lock.put("b:2", digest_of("b"), "linux/amd64", Digest.of("bt"));
    try lock.put("a:1", digest_of("a"), "linux/arm64", Digest.of("at"));
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    try testing.expect(std.mem.startsWith(u8, text, ".{\n    .version = 1,\n    .images = .{\n"));
    try testing.expect(std.mem.indexOf(u8, text, ".reference = \"a:1\"").? <
        std.mem.indexOf(u8, text, ".reference = \"b:2\"").?);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, 2), back.count);
    try testing.expectEqualStrings("a:1", back.reference(&back.entries[0]));
    try testing.expect(back.entries[1].tree.eql(Digest.of("bt")));
    try testing.expectEqualStrings("linux/arm64", back.entries[0].platform_text());
    // Writing what was read gives the same bytes.
    var again: [constants.lock_file_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(text, render(&back, &again));
}

fn problem_of(text: []const u8) ?Problem {
    var lock = filled();
    return parse(text, &lock);
}

fn entry_text(manifest: []const u8, tree: []const u8) [512]u8 {
    var out: [512]u8 = @splat(0);
    _ = std.fmt.bufPrint(&out, ".{{\n    .version = 1,\n    .images = .{{\n        .{{\n" ++
        "            .reference = \"a:1\",\n            .manifest = \"{s}\",\n" ++
        "            .platform = \"linux/amd64\",\n            .tree = \"{s}\",\n        }},\n" ++
        "    }},\n}}\n", .{ manifest, tree }) catch unreachable; // Short.
    return out;
}

test "a lock that is not one is refused, with the line" {
    // Goal: every ProblemKind, each at the right line.
    const good_manifest = digest_of("m").text();
    const good_tree = Digest.of("t").text();
    const ok = entry_text(&good_manifest, &good_tree);
    try testing.expectEqual(@as(?Problem, null), problem_of(std.mem.sliceTo(&ok, 0)));
    const bad_tree = entry_text(&good_manifest, "b3:12");
    const bad = problem_of(std.mem.sliceTo(&bad_tree, 0)).?;
    try testing.expectEqual(ProblemKind.bad_value, bad.kind);
    try testing.expectEqual(@as(u32, 8), problem_of(std.mem.sliceTo(&bad_tree, 0)).?.line);
    const wrong = entry_text("sha256:abc", &good_tree);
    try testing.expectEqual(@as(u32, 6), problem_of(std.mem.sliceTo(&wrong, 0)).?.line);
    try testing.expectEqual(ProblemKind.no_version, problem_of("").?.kind);
    try testing.expectEqual(ProblemKind.newer, problem_of(".{\n    .version = 2,\n}\n").?.kind);
    try testing.expectEqual(ProblemKind.unknown_line, problem_of(".{\n    hello\n}\n").?.kind);
    const cut = ".{\n    .version = 1,\n    .images = .{\n        .{\n" ++
        "            .reference = \"a:1\",\n";
    try testing.expectEqual(ProblemKind.incomplete_entry, problem_of(cut).?.kind);
    const twice = std.mem.sliceTo(&ok, 0)[0..std.mem.indexOf(u8, &ok, "    },\n}").?];
    var double_buffer: [1200]u8 = undefined;
    const doubled = try std.fmt.bufPrint(&double_buffer, "{s}{s}    }},\n}}\n", .{
        twice, twice[std.mem.indexOf(u8, twice, "        .{").?..],
    });
    try testing.expectEqual(ProblemKind.duplicate, problem_of(doubled).?.kind);
}

test "an edit by hand with other spacing still reads" {
    // Goal: the use case of the demo: a person changes a digest, maybe reformats.
    const good_manifest = digest_of("m").text();
    const good_tree = Digest.of("t").text();
    var buffer: [600]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, ".{{\r\n\t.version = 1,\r\n\t.images = .{{\r\n" ++
        "\t\t.{{ \r\n\t\t\t.reference = \"a:1\",\r\n\t\t\t.tree = \"{s}\",\r\n" ++
        "\t\t\t.manifest = \"{s}\",\r\n\t\t\t.platform = \"linux/amd64\"\r\n" ++
        "\t\t}},\r\n\t}},\r\n}}\r\n", .{
        &good_tree, &good_manifest,
    });
    var lock = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &lock));
    try testing.expectEqual(@as(u32, 1), lock.count);
}

test "the lock is full at its bounds" {
    // Goal: the entry bound is exact and says Full.
    var lock = filled();
    var name: [32]u8 = undefined;
    for (0..constants.lock_entries_max) |index| {
        const text = try std.fmt.bufPrint(&name, "img{d:0>4}:1", .{index});
        try lock.put(text, digest_of("x"), "linux/amd64", Digest.of("y"));
    }
    const more = lock.put("one-more:1", digest_of("x"), "linux/amd64", Digest.of("y"));
    try testing.expectError(error.Full, more);
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    var back = filled();
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u32, constants.lock_entries_max), back.count);
}

test "the worst reference still renders" {
    // Goal: the render buffer holds a lock of the longest, all-escaped references.
    var lock = filled();
    var long: [constants.reference_bytes_max]u8 = @splat('"');
    try lock.put(&long, digest_of("x"), "linux/amd64", Digest.of("y"));
    var buffer: [constants.lock_file_bytes_max]u8 = undefined;
    const text = render(&lock, &buffer);
    var back = filled();
    // The reference is not a valid one, but the file format carries any text.
    try testing.expectEqual(@as(?Problem, null), parse(text, &back));
    try testing.expectEqual(@as(u16, constants.reference_bytes_max), back.entries[0].reference_len);
}
