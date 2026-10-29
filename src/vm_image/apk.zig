//! Reads an Alpine package (.apk): three gzip members one after another, the signature, the
//! control data and the files, each a tar stream. Only the last member's files are returned.
//! Build-host tooling: it allocates from the arena it is given.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const flate = std.compress.flate;

pub const Kind = enum { file, symlink, directory };

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    /// The file's bytes, or a symlink's target.
    data: []const u8,
};

const member_bytes_max: usize = 32 << 20;
const members_max: u32 = 8;
const path_bytes_max: usize = 512;

/// The files of the package's last member, in the order the archive lists them.
pub fn unpack(arena: std.mem.Allocator, apk: []const u8) ![]Entry {
    var input: Io.Reader = .fixed(apk);
    var window: [flate.max_window_len]u8 = undefined;
    var last: []u8 = &.{};
    var members: u32 = 0;
    while (input.seek < apk.len) {
        if (members == members_max) return error.TooManyMembers;
        var decompress: flate.Decompress = .init(&input, .gzip, &window);
        last = try decompress.reader.allocRemaining(arena, .limited(member_bytes_max));
        members += 1;
    }
    if (members < 3) return error.NotAnApk;
    return entries_of(arena, last);
}

fn entries_of(arena: std.mem.Allocator, tar_bytes: []const u8) ![]Entry {
    var reader: Io.Reader = .fixed(tar_bytes);
    var name_buffer: [path_bytes_max]u8 = undefined;
    var link_buffer: [path_bytes_max]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader, .{
        .file_name_buffer = &name_buffer,
        .link_name_buffer = &link_buffer,
    });
    var list: std.ArrayList(Entry) = .empty;
    while (try iterator.next()) |file| {
        // Alpine marks control files with a leading dot; they are not the package's files.
        if (std.mem.startsWith(u8, file.name, ".")) continue;
        const data = switch (file.kind) {
            .file => try arena.alloc(u8, @intCast(file.size)),
            .sym_link => try arena.dupe(u8, file.link_name),
            .directory => &[0]u8{},
        };
        if (file.kind == .file) try reader.readSliceAll(@constCast(data));
        iterator.unread_file_bytes = 0;
        try list.append(arena, .{
            .path = try arena.dupe(u8, std.mem.trimEnd(u8, file.name, "/")),
            .kind = switch (file.kind) {
                .file => .file,
                .sym_link => .symlink,
                .directory => .directory,
            },
            .mode = file.mode & 0o7777,
            .data = data,
        });
    }
    return list.items;
}
