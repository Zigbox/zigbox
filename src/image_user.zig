//! The user an image runs as: its configuration's `User` string resolved against the image's own
//! `/etc/passwd` and `/etc/group`, read from the tree in the store. The forms are Docker's:
//!
//!   ""                 root, nothing to set
//!   "1000"             uid 1000; its group is the one /etc/passwd gives it, else 0
//!   "1000:1000"        both numbers, used as they are
//!   "www-data"         looked up in /etc/passwd: its uid and primary group
//!   "www-data:staff"   the user from /etc/passwd, the group from /etc/group
//!   "1000:staff"       a number and a group looked up
//!
//! A number is never looked up for itself (it need not be in the file); a name that is not found
//! is `E0521`, naming the file. Supplementary groups are not set: a process of the container
//! has its one group.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const image_diagnose = @import("image_diagnose.zig");
const spec = @import("runtime/spec.zig");
const tree = @import("store/tree.zig");
const trees = @import("store/trees.zig");
const layout = @import("store/layout.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;

const Store = layout.Store;

pub const Error = error{Failed};

/// The memory resolving reads in: a tree directory and a file.
pub const Workspace = struct {
    tree: [constants.store_tree_bytes_max]u8,
    file: [file_bytes_max]u8,
};

pub const file_bytes_max: u32 = 256 * 1024;

pub const passwd = "/etc/passwd";
pub const group = "/etc/group";

// ---- The text of the files -----------------------------------------------------------------

const Line = struct {
    name: []const u8,
    id: u32,
    /// For /etc/passwd the primary group; for /etc/group unused.
    gid: u32,
    /// For /etc/passwd the home directory; empty for a group.
    home: []const u8 = "",
};

/// What a `User` resolves to: the ids and the user's home directory ("/" when the image's files
/// do not say).
pub const Resolved = struct {
    user: spec.User,
    home: [home_bytes_max]u8,
    home_len: u8,

    pub fn home_text(self: *const Resolved) []const u8 {
        assert(self.home_len > 0);
        return self.home[0..self.home_len];
    }

    fn with_home(user: spec.User, text: []const u8) Resolved {
        var result: Resolved = .{ .user = user, .home = undefined, .home_len = 1 };
        const usable = text.len > 0 and text.len <= home_bytes_max and text[0] == '/';
        if (!usable) {
            result.home[0] = '/';
            return result;
        }
        @memcpy(result.home[0..text.len], text);
        result.home_len = @intCast(text.len);
        return result;
    }
};

pub const home_bytes_max = 200;

/// The fields of a line of passwd (name:x:uid:gid:...) or group (name:x:gid:...), or null for a
/// comment, a blank line or one that is not either.
fn parse_line(text: []const u8, is_passwd: bool) ?Line {
    assert(text.len <= file_bytes_max);
    const trimmed = std.mem.trim(u8, text, " \t\r");
    if (trimmed.len == 0 or trimmed[0] == '#') return null;
    var fields = std.mem.splitScalar(u8, trimmed, ':');
    const name = fields.next() orelse return null;
    _ = fields.next() orelse return null; // The password field.
    const id_text = fields.next() orelse return null;
    const id = std.fmt.parseInt(u32, id_text, 10) catch return null;
    if (name.len == 0) return null;
    if (!is_passwd) return .{ .name = name, .id = id, .gid = 0 };
    const gid_text = fields.next() orelse return null;
    const gid = std.fmt.parseInt(u32, gid_text, 10) catch return null;
    _ = fields.next() orelse return .{ .name = name, .id = id, .gid = gid }; // GECOS.
    const home = fields.next() orelse "";
    return .{ .name = name, .id = id, .gid = gid, .home = home };
}

/// The first line of `file` for `name`.
fn find_name(file: []const u8, name: []const u8, is_passwd: bool) ?Line {
    var lines = std.mem.splitScalar(u8, file, '\n');
    while (lines.next()) |text| {
        const line = parse_line(text, is_passwd) orelse continue;
        if (std.mem.eql(u8, line.name, name)) return line;
    }
    return null;
}

/// The first line of passwd for `uid`.
fn find_uid(file: []const u8, uid: u32) ?Line {
    var lines = std.mem.splitScalar(u8, file, '\n');
    while (lines.next()) |text| {
        const line = parse_line(text, true) orelse continue;
        if (line.id == uid) return line;
    }
    return null;
}

fn is_number(text: []const u8) ?u32 {
    if (text.len == 0 or text.len > 10) return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(u32, text, 10) catch null;
}

/// Resolves `user_text` against the text of the two files (null: the file is not there).
pub fn resolve_text(
    user_text: []const u8,
    passwd_file: ?[]const u8,
    group_file: ?[]const u8,
    diag: *Diag,
) Error!Resolved {
    assert(user_text.len <= constants.image_settings_bytes_max);
    if (user_text.len == 0) return Resolved.with_home(.{ .uid = 0, .gid = 0 }, "/root");
    const colon = std.mem.indexOfScalar(u8, user_text, ':');
    const user_part = if (colon) |at| user_text[0..at] else user_text;
    const group_part: ?[]const u8 = if (colon) |at| user_text[at + 1 ..] else null;
    var result: spec.User = .{ .uid = 0, .gid = 0 };
    var home: []const u8 = "";
    if (is_number(user_part)) |uid| {
        result.uid = uid;
        if (passwd_file) |file| {
            if (find_uid(file, uid)) |line| {
                result.gid = line.gid;
                home = line.home;
            }
        }
    } else {
        const line = if (passwd_file) |file| find_name(file, user_part, true) else null;
        const found = line orelse {
            image_diagnose.unknown_user(diag, user_part, passwd, false);
            return error.Failed;
        };
        result = .{ .uid = found.id, .gid = found.gid };
        home = found.home;
    }
    if (group_part) |name| {
        if (is_number(name)) |gid| {
            result.gid = gid;
        } else {
            const line = if (group_file) |file| find_name(file, name, false) else null;
            const found = line orelse {
                image_diagnose.unknown_user(diag, name, group, true);
                return error.Failed;
            };
            result.gid = found.id;
        }
    }
    return Resolved.with_home(result, home);
}

// ---- The tree ------------------------------------------------------------------------------

/// The directory entry `name` of the tree `digest`: the subtree of a directory, or the object of
/// a file; null if it is absent or another kind.
fn child_of(
    store: *const Store,
    buffer: []u8,
    digest: Digest,
    name: []const u8,
    want_dir: bool,
) ?Digest {
    var errno: u16 = 0;
    const bytes = trees.load(store, digest, buffer, &errno) catch return null;
    var decoder: tree.Decoder = undefined;
    decoder.init(bytes) catch return null;
    var entry: tree.Entry = undefined;
    while (decoder.next(&entry) catch return null) {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (want_dir and entry.kind == .dir) return entry.subtree;
        if (!want_dir and entry.kind == .file) return entry.object;
        return null;
    }
    return null;
}

/// The text of a file of the tree at `/directory/name`, or null if it is not a plain file there
/// (a symlink is not followed) or is longer than the buffer.
fn file_of(
    store: *const Store,
    workspace: *Workspace,
    root: Digest,
    directory: []const u8,
    name: []const u8,
) ?[]const u8 {
    const subtree = child_of(store, &workspace.tree, root, directory, true) orelse return null;
    const object = child_of(store, &workspace.tree, subtree, name, false) orelse return null;
    var path: @import("store/fs.zig").PathBuf = undefined;
    const where = store.id_path(&path, "objects", object, "");
    return store.fs.read_whole(where, &workspace.file) catch null;
}

/// The ids the image's `User` names; `E0521` if a name is not in the image.
pub fn resolve(
    store: *const Store,
    workspace: *Workspace,
    root: Digest,
    user_text: []const u8,
    diag: *Diag,
) Error!Resolved {
    assert(diag.code == null);
    if (user_text.len == 0) return Resolved.with_home(.{ .uid = 0, .gid = 0 }, "/root");
    // Both files are needed at once, so the first is copied aside: the second read reuses the
    // buffer. Passwd is cut to the half of the buffer, group to the other.
    const half = file_bytes_max / 2;
    const first = file_of(store, workspace, root, "etc", "passwd");
    var kept: [half]u8 = undefined;
    var passwd_file: ?[]const u8 = null;
    if (first) |text| {
        if (text.len <= half) {
            @memcpy(kept[0..text.len], text);
            passwd_file = kept[0..text.len];
        }
    }
    const second = file_of(store, workspace, root, "etc", "group");
    return resolve_text(user_text, passwd_file, second, diag);
}

const testing = std.testing;

const sample_passwd =
    \\root:x:0:0:root:/root:/bin/sh
    \\# a comment
    \\
    \\www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    \\nobody:x:65534:65534:nobody:/:/sbin/nologin
    \\app:x:1000:2000::/home/app:/bin/sh
    \\broken line
    \\
;

const sample_group =
    \\root:x:0:
    \\staff:x:50:app
    \\www-data:x:33:
    \\
;

fn resolved(user_text: []const u8) Error!spec.User {
    var diag: Diag = undefined;
    diag.reset();
    return (try resolve_text(user_text, sample_passwd, sample_group, &diag)).user;
}

test "the home directory comes from passwd, and is / when it does not say" {
    // Goal: HOME for a user that is not root.
    var diag: Diag = undefined;
    diag.reset();
    const app = try resolve_text("app", sample_passwd, sample_group, &diag);
    try testing.expectEqualStrings("/home/app", app.home_text());
    const nobody = try resolve_text("nobody", sample_passwd, sample_group, &diag);
    try testing.expectEqualStrings("/", nobody.home_text());
    const plain = try resolve_text("4242", sample_passwd, sample_group, &diag);
    try testing.expectEqualStrings("/", plain.home_text());
    const root = try resolve_text("", null, null, &diag);
    try testing.expectEqualStrings("/root", root.home_text());
}

test "the forms of User, with the files of an image" {
    // Goal: Docker's forms, one by one.
    try testing.expectEqual(spec.User{ .uid = 0, .gid = 0 }, try resolved(""));
    try testing.expectEqual(spec.User{ .uid = 1000, .gid = 2000 }, try resolved("1000"));
    try testing.expectEqual(spec.User{ .uid = 4242, .gid = 0 }, try resolved("4242"));
    try testing.expectEqual(spec.User{ .uid = 1000, .gid = 1234 }, try resolved("1000:1234"));
    try testing.expectEqual(spec.User{ .uid = 33, .gid = 33 }, try resolved("www-data"));
    try testing.expectEqual(spec.User{ .uid = 1000, .gid = 50 }, try resolved("app:staff"));
    try testing.expectEqual(spec.User{ .uid = 33, .gid = 7 }, try resolved("www-data:7"));
    try testing.expectEqual(spec.User{ .uid = 7, .gid = 50 }, try resolved("7:staff"));
    try testing.expectEqual(spec.User{ .uid = 0, .gid = 0 }, try resolved("root"));
}

test "an unknown name is refused, naming the file; a number never is" {
    // Goal: E0521 for a user, for a group, and for a missing file; numbers need no file.
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.Failed, resolve_text("ghost", sample_passwd, sample_group, &diag));
    try testing.expectEqual(@as(?@import("diag/codes.zig").Code, .E0521), diag.code);
    diag.reset();
    try testing.expectError(error.Failed, resolve_text("app:nogroup", sample_passwd, sample_group, &diag));
    try testing.expectEqual(@as(?@import("diag/codes.zig").Code, .E0521), diag.code);
    diag.reset();
    try testing.expectError(error.Failed, resolve_text("app", null, null, &diag));
    diag.reset();
    const plain = try resolve_text("1000:1000", null, null, &diag);
    try testing.expectEqual(spec.User{ .uid = 1000, .gid = 1000 }, plain.user);
}

test "lines that are not entries are skipped, and the first match wins" {
    // Goal: a comment, a blank, a broken line and a duplicate name.
    const file = "x:x:notnumber:1\nroot:x:0:0\nroot:x:5:5\n";
    try testing.expectEqual(@as(u32, 0), find_name(file, "root", true).?.id);
    try testing.expect(find_name(file, "x", true) == null);
    try testing.expect(find_uid(file, 5).?.gid == 5);
    try testing.expect(is_number("12a") == null);
    try testing.expect(is_number("") == null);
    try testing.expect(is_number("99999999999") == null);
}
