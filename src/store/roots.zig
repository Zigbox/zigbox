//! Roots: why a tree is in the store. A tree stays while it is a root (gc, slice 4, removes what
//! no root reaches). A root is one small ZON file, `roots/<64 hex>`, written atomically:
//!
//!   .{
//!       .version = 1,
//!       .kind = "import",
//!       .time = 1792873384,
//!       .files = 1483,
//!       .bytes = 7814022,
//!       .source = "./alpine",
//!   }
//!
//! `kind` is `import` (from `store import`; `source` is the path as given), `commit` (slice 3;
//! `parent` is the tree it started from and `container` the container) or `container` (the tree
//! of a live container). One record per tree: importing the same tree again overwrites the
//! record, so its time and source are those of the latest import. `files` and `bytes` are the
//! tree's logical totals, kept here so that `ls` need not walk the trees.
//!
//! The reader is a line reader for the shape the writer produces, as in `records.zig`; unknown
//! fields are ignored so that a later zbx may add some, and a version newer than this one is
//! skipped, never misread.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const host_mod = @import("../host.zig");
const digest_mod = @import("digest.zig");
const fs_mod = @import("fs.zig");
const layout = @import("layout.zig");
const names_mod = @import("names.zig");

const Digest = digest_mod.Digest;
const PathBuf = fs_mod.PathBuf;
const Store = layout.Store;

pub const record_version: u32 = 1;

pub const Kind = enum {
    import,
    commit,
    container,

    pub fn word(kind: Kind) []const u8 {
        assert(@tagName(kind).len > 0);
        assert(@tagName(kind).len < 16);
        return @tagName(kind);
    }
};

pub const Root = struct {
    digest: Digest,
    kind: Kind,
    time: u64,
    files: u64,
    bytes: u64,
    source: [constants.store_source_bytes_max]u8,
    source_len: u16,
    parent: ?Digest,

    pub fn source_text(root: *const Root) []const u8 {
        assert(@sizeOf(Root) >= constants.store_source_bytes_max);
        assert(root.source_len <= constants.store_source_bytes_max);
        return root.source[0..root.source_len];
    }

    pub fn set_source(root: *Root, text: []const u8) void {
        assert(text.len > 0);
        assert(text.len <= constants.file_bytes_max);
        const length = @min(text.len, constants.store_source_bytes_max);
        @memcpy(root.source[0..length], text[0..length]);
        root.source_len = @intCast(length);
    }
};

// ---- Writing -------------------------------------------------------------------------------

pub fn put_string(writer: *std.Io.Writer, text: []const u8) void {
    assert(writer.buffer.len >= constants.store_root_record_bytes_max);
    assert(text.len <= constants.store_source_bytes_max);
    writer.writeAll(
        "\"",
    ) catch unreachable; // Cannot fail: `render` proves the buffer is big enough.
    for (text) |byte| {
        switch (byte) {
            '"' => writer.writeAll("\\\"") catch unreachable, // Same bound.
            '\\' => writer.writeAll("\\\\") catch unreachable, // Same.
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => writer.writeByte(
                byte,
            ) catch unreachable, // Same.
            else => writer.print("\\x{x:0>2}", .{byte}) catch unreachable, // Same.
        }
    }
    writer.writeAll("\"") catch unreachable; // Same.
}

/// The record's text. The buffer holds the longest record: a source of
/// `store_source_bytes_max` bytes all escaped (four bytes each) is the worst case.
pub fn render(root: *const Root, buffer: *[constants.store_root_record_bytes_max]u8) []const u8 {
    assert(root.source_len <= constants.store_source_bytes_max);
    assert(root.time < 1 << 40);
    var writer = std.Io.Writer.fixed(buffer);
    // Cannot fail: the fixed fields are under 200 bytes and the source is cut to fit below.
    writer.print(".{{\n    .version = {d},\n    .kind = \"{s}\",\n    .time = {d},\n", .{
        record_version, root.kind.word(), root.time,
    }) catch unreachable; // Same bound.
    writer.print("    .files = {d},\n    .bytes = {d},\n    .source = ", .{
        root.files, root.bytes,
    }) catch unreachable; // Same bound.
    put_string(&writer, root.source_text());
    writer.writeAll(",\n") catch unreachable; // Same bound.
    if (root.parent) |parent| {
        writer.print("    .parent = \"{s}\",\n", .{parent.text()}) catch unreachable; // Same.
    }
    writer.writeAll("}\n") catch unreachable; // Same bound.
    assert(writer.end <= buffer.len);
    return writer.buffered();
}

// ---- Reading -------------------------------------------------------------------------------

fn hex_value(byte: u8) ?u8 {
    const value: ?u8 = switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
    if (value) |digit| assert(digit < 16);
    if (value == null) {
        if (std.ascii.isLower(byte)) assert(byte > 'f'); // Of the letters only a to f are digits.
    }
    return value;
}

/// Reads a quoted string with the escapes `put_string` writes into `out`; the length, or null.
pub fn parse_string(literal: []const u8, out: []u8) ?usize {
    assert(out.len > 0);
    assert(literal.len <= constants.file_bytes_max);
    if (literal.len < 2) return null;
    if (literal[0] != '"' or literal[literal.len - 1] != '"') return null;
    const body = literal[1 .. literal.len - 1];
    var length: usize = 0;
    var at: usize = 0;
    while (at < body.len) {
        if (length == out.len) return null;
        const byte = body[at];
        if (byte != '\\') {
            if (byte == '"') return null;
            out[length] = byte;
            length += 1;
            at += 1;
            continue;
        }
        if (at + 1 >= body.len) return null;
        switch (body[at + 1]) {
            '"', '\\' => {
                out[length] = body[at + 1];
                at += 2;
            },
            'x' => {
                if (at + 3 >= body.len) return null;
                const high = hex_value(body[at + 2]) orelse return null;
                const low = hex_value(body[at + 3]) orelse return null;
                out[length] = high << 4 | low;
                at += 4;
            },
            else => return null,
        }
        length += 1;
    }
    return length;
}

pub const ParseResult = enum { ok, malformed, newer };

/// Reads a record. `root.digest` is the caller's (it is the file's name).
pub fn parse(text: []const u8, root: *Root) ParseResult {
    assert(text.len <= constants.store_root_record_bytes_max);
    assert(@intFromPtr(root) != 0);
    root.kind = .import;
    root.time = 0;
    root.files = 0;
    root.bytes = 0;
    root.source_len = 0;
    root.parent = null;
    var version: u32 = 0;
    var seen_kind = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " ");
        if (!std.mem.startsWith(u8, line, ".")) continue;
        const equals = std.mem.indexOf(u8, line, " = ") orelse continue;
        const key = line[1..equals];
        var value = line[equals + 3 ..];
        if (value.len > 0 and value[value.len - 1] == ',') value = value[0 .. value.len - 1];
        if (std.mem.eql(u8, key, "version")) {
            version = std.fmt.parseInt(u32, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "kind")) {
            var word: [16]u8 = undefined;
            const length = parse_string(value, &word) orelse return .malformed;
            root.kind = std.meta.stringToEnum(Kind, word[0..length]) orelse return .malformed;
            seen_kind = true;
        } else if (std.mem.eql(u8, key, "time")) {
            root.time = std.fmt.parseInt(u64, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "files")) {
            root.files = std.fmt.parseInt(u64, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "bytes")) {
            root.bytes = std.fmt.parseInt(u64, value, 10) catch return .malformed;
        } else if (std.mem.eql(u8, key, "source")) {
            const length = parse_string(value, &root.source) orelse return .malformed;
            root.source_len = @intCast(length);
        } else if (std.mem.eql(u8, key, "parent")) {
            var word: [constants.store_digest_text_bytes]u8 = undefined;
            const length = parse_string(value, &word) orelse return .malformed;
            root.parent = Digest.parse(word[0..length]) orelse return .malformed;
        }
    }
    if (version == 0) return .malformed;
    if (version > record_version) return .newer;
    if (!seen_kind) return .malformed;
    return .ok;
}

// ---- In the store --------------------------------------------------------------------------

/// Writes the root's record atomically. A second record for the same tree replaces the first.
pub fn save(store: *Store, root: *const Root, failure: *fs_mod.Failure) host_mod.Error!void {
    assert(root.source_len <= constants.store_source_bytes_max);
    assert(root.time < 1 << 40);
    var bytes: [constants.store_root_record_bytes_max]u8 = undefined;
    const text = render(root, &bytes);
    var temporary: PathBuf = undefined;
    var final: PathBuf = undefined;
    var directory: PathBuf = undefined;
    const temporary_path = store.tmp_path(&temporary);
    const final_path = store.root_record_path(&final, root.digest);
    const directory_path = store.directory_path(&directory, "roots");
    try store.fs.write_atomic(temporary_path, final_path, directory_path, text, 0o644, failure);
}

pub const LoadError = error{ NotFound, Unreadable, Damaged, Newer };

/// Reads the record of the root `digest`.
pub fn load(store: *const Store, digest: Digest, root: *Root, errno: *u16) LoadError!void {
    assert(@intFromPtr(root) != 0);
    assert(@intFromPtr(errno) != 0);
    var path: PathBuf = undefined;
    var bytes: [constants.store_root_record_bytes_max]u8 = undefined;
    const text = store.fs.read_whole(store.root_record_path(&path, digest), &bytes) catch |err| {
        errno.* = store.fs.last_errno();
        return switch (err) {
            error.NotFound => error.NotFound,
            error.FileTooLarge => error.Damaged,
            else => error.Unreadable,
        };
    };
    root.digest = digest;
    switch (parse(text, root)) {
        .ok => {},
        .malformed => return error.Damaged,
        .newer => return error.Newer,
    }
}

/// Drops the root's record. The tree stays until gc.
pub fn remove(store: *const Store, digest: Digest) host_mod.Error!void {
    assert(store.root_len > 1);
    assert(digest.bytes.len == constants.store_digest_bytes);
    var path: PathBuf = undefined;
    var directory: PathBuf = undefined;
    try store.fs.unlink(store.root_record_path(&path, digest));
    try store.fs.sync_directory(store.directory_path(&directory, "roots"));
}

/// The roots of the store, newest first (ties by digest), up to `out.len`. `arena` holds the
/// names while they are read. `skipped` counts records that could not be used.
pub const Listing = struct {
    count: u32,
    skipped: u32,
    /// There are more roots than `out` holds.
    truncated: bool,
};

pub fn list(store: *const Store, arena: []u8, out: []Root) host_mod.Error!Listing {
    assert(out.len > 0);
    assert(out.len <= constants.store_roots_max);
    var directory: PathBuf = undefined;
    var names = names_mod.NameList.init(arena, constants.store_roots_max + 1);
    store.fs.read_dir(store.directory_path(&directory, "roots"), names.visitor()) catch |err| {
        if (err == error.NotFound) return .{ .count = 0, .skipped = 0, .truncated = false };
        return err;
    };
    var result: Listing = .{ .count = 0, .skipped = 0, .truncated = names.count > out.len };
    var at: u32 = 0;
    while (at < names.used) {
        const name = names.at(at);
        at += @intCast(1 + name.len);
        const digest = Digest.from_hex(name) orelse {
            result.skipped += 1; // Not a root record (a temporary file, or a stray).
            continue;
        };
        if (result.count == out.len) break;
        var errno: u16 = 0;
        load(store, digest, &out[result.count], &errno) catch {
            result.skipped += 1;
            continue;
        };
        result.count += 1;
    }
    std.mem.sortUnstable(Root, out[0..result.count], {}, newer_first);
    return result;
}

fn newer_first(context: void, first: Root, second: Root) bool {
    assert(first.source_len <= constants.store_source_bytes_max);
    assert(second.source_len <= constants.store_source_bytes_max);
    _ = context;
    if (first.time != second.time) return first.time > second.time;
    return first.digest.less_than(second.digest);
}

const testing = std.testing;

fn sample() Root {
    var root: Root = undefined;
    root.digest = Digest.of("tree");
    root.kind = .import;
    root.time = 1792873384;
    root.files = 12;
    root.bytes = 3456;
    root.set_source("./alpine");
    root.parent = null;
    return root;
}

test "a root record reads back what was written, including awkward source paths" {
    // Goal: render and parse are a pair. Method: a plain path, one with quotes, backslashes,
    // a newline and non-ASCII bytes, and the longest path.
    var bytes: [constants.store_root_record_bytes_max]u8 = undefined;
    const paths = [_][]const u8{
        "./alpine",
        "a \"b\" \\ c\nd \xff\xfe",
        @import("../test_util.zig").repeat('p', constants.store_source_bytes_max),
    };
    for (paths) |path| {
        var root = sample();
        root.set_source(path);
        root.parent = Digest.of("parent");
        const text = render(&root, &bytes);
        var back: Root = undefined;
        back.digest = root.digest;
        try testing.expectEqual(ParseResult.ok, parse(text, &back));
        try testing.expectEqualStrings(path, back.source_text());
        try testing.expectEqual(root.time, back.time);
        try testing.expectEqual(root.files, back.files);
        try testing.expectEqual(root.bytes, back.bytes);
        try testing.expect(back.parent.?.eql(root.parent.?));
        try testing.expectEqual(Kind.import, back.kind);
    }
}

test "a record that is malformed or newer is not misread" {
    // Goal: the negative space. Method: no version, a bad number, an unknown kind, a version one
    // past ours (skipped as newer), and an unknown field (ignored).
    var back: Root = undefined;
    try testing.expectEqual(ParseResult.malformed, parse("", &back));
    try testing.expectEqual(
        ParseResult.malformed,
        parse(".{\n    .kind = \"import\",\n}\n", &back),
    );
    const bad_number = ".{\n    .version = 1,\n    .kind = \"import\",\n    .time = x,\n}\n";
    try testing.expectEqual(ParseResult.malformed, parse(bad_number, &back));
    const bad_kind = ".{\n    .version = 1,\n    .kind = \"nope\",\n}\n";
    try testing.expectEqual(ParseResult.malformed, parse(bad_kind, &back));
    const newer = ".{\n    .version = 2,\n    .kind = \"import\",\n}\n";
    try testing.expectEqual(ParseResult.newer, parse(newer, &back));
    const extra = ".{\n    .version = 1,\n    .kind = \"import\",\n    .flavour = \"x\",\n}\n";
    try testing.expectEqual(ParseResult.ok, parse(extra, &back));
}
