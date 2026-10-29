//! The VM image carried inside this binary (the kernel and the initramfs, embedded by the build)
//! and its unpacking into the user's Library. The version is a digest over both, so a binary
//! cannot carry a version that is not its own image, and an upgrade is a file swap: a new binary
//! unpacks a new directory beside the old one.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const files = @import("files.zig");
const protocol = @import("../vm_protocol.zig");
const paths_mod = @import("paths.zig");

pub const kernel_bytes = @embedFile("vm_kernel");
pub const initramfs_bytes = @embedFile("vm_initramfs");
pub const version = @embedFile("vm_image_version");

comptime {
    assert(version.len == constants.vm_image_version_bytes);
    assert(kernel_bytes.len > 0);
    assert(initramfs_bytes.len > 0);
    assert(kernel_bytes.len <= constants.vm_image_file_bytes_max);
    assert(initramfs_bytes.len <= constants.vm_image_file_bytes_max);
}

/// Makes sure the image's directory holds exactly this binary's kernel and initramfs: a missing,
/// short or damaged file (an interrupted unpack, a changed byte) is written again.
pub fn ensure(paths: *const paths_mod.Paths) files.Error!void {
    assert(paths.image_dir.length > 0);
    assert(protocol.is_version(version));
    try files.make_directories(paths.image_dir.slice());
    try ensure_file(paths.kernel.slice(), kernel_bytes);
    try ensure_file(paths.initramfs.slice(), initramfs_bytes);
}

fn ensure_file(path: []const u8, expected: []const u8) files.Error!void {
    assert(expected.len > 0);
    if (matches(path, expected)) return;
    try files.write_file_atomically(path, expected, 0o600);
    assert(matches(path, expected));
}

extern "c" fn opendir(path: [*:0]const u8) ?*anyopaque;
extern "c" fn readdir(handle: *anyopaque) ?*Dirent;
extern "c" fn closedir(handle: *anyopaque) c_int;

/// macOS's `struct dirent` (64-bit inodes): the name starts at byte 21.
const Dirent = extern struct {
    inode: u64,
    offset: u64,
    record_length: u16,
    name_length: u16,
    kind: u8,
    name: [1024]u8,
};

const old_images_max: usize = 32;

/// An older image directory: its name (a version) and when it was last changed.
pub const Old = struct {
    name: [constants.vm_image_version_bytes]u8,
    changed: i64,
};

/// Which of `old` is the newest, the one to keep beside the current image (a binary rolled back
/// finds its image there); null when there are none.
pub fn newest(old: []const Old) ?usize {
    assert(old.len <= old_images_max);
    var best: ?usize = null;
    for (old, 0..) |entry, index| {
        if (best == null or entry.changed > old[best.?].changed) best = index;
    }
    if (best) |index| assert(index < old.len);
    return best;
}

/// Lists the names in `path` into `out`; returns how many were kept (the rest are dropped).
fn list_directory(path: []const u8, names: *[old_images_max + 8][255:0]u8) usize {
    assert(path.len > 0);
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = files.terminate(&terminated, path) catch return 0;
    const handle = opendir(text.ptr) orelse return 0;
    defer _ = closedir(handle);
    var count: usize = 0;
    while (readdir(handle)) |entry| {
        const name = std.mem.sliceTo(&entry.name, 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        if (count == names.len or name.len > 255) break;
        @memcpy(names[count][0..name.len], name);
        names[count][name.len] = 0;
        count += 1;
    }
    return count;
}

/// Removes the image directories of older versions at host start, keeping the current one and the
/// newest older one. Only directories named like a version (sixteen hex digits) are looked at, and
/// only the files directly in them are removed: store.img, vm-settings and everything else in the
/// Library directory are never touched, and a directory holding anything else stays.
pub fn prune(paths: *const paths_mod.Paths) void {
    assert(paths.vm_dir.length > 0);
    assert(protocol.is_version(version));
    var names: [old_images_max + 8][255:0]u8 = undefined;
    const count = list_directory(paths.vm_dir.slice(), &names);
    var old: [old_images_max]Old = undefined;
    var old_count: usize = 0;
    for (names[0..count]) |*name| {
        const text = std.mem.sliceTo(name, 0);
        if (text.len != constants.vm_image_version_bytes) continue;
        if (!protocol.is_version(text[0..constants.vm_image_version_bytes])) continue;
        if (std.mem.eql(u8, text, version)) continue;
        if (old_count == old.len) break;
        old[old_count] = .{
            .name = text[0..constants.vm_image_version_bytes].*,
            .changed = changed_time(paths, text),
        };
        old_count += 1;
    }
    const keep = newest(old[0..old_count]);
    for (old[0..old_count], 0..) |entry, index| {
        if (index == keep) continue;
        remove_image_directory(paths, &entry.name);
    }
}

fn changed_time(paths: *const paths_mod.Paths, name: []const u8) i64 {
    assert(name.len > 0);
    var buffer: [constants.vm_path_bytes_max]u8 = undefined;
    const vm_dir = paths.vm_dir.slice();
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ vm_dir, name }) catch return 0;
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = files.terminate(&terminated, path) catch return 0;
    var status: std.c.Stat = undefined;
    if (std.c.stat(text.ptr, &status) != 0) return 0;
    return status.mtime().sec;
}

fn remove_image_directory(paths: *const paths_mod.Paths, name: []const u8) void {
    assert(paths.vm_dir.length > 0);
    assert(name.len == constants.vm_image_version_bytes);
    var directory: [constants.vm_path_bytes_max]u8 = undefined;
    const vm_dir = paths.vm_dir.slice();
    const base = std.fmt.bufPrint(&directory, "{s}/{s}", .{ vm_dir, name }) catch return;
    var names: [old_images_max + 8][255:0]u8 = undefined;
    const count = list_directory(base, &names);
    for (names[0..count]) |*entry| {
        var buffer: [constants.vm_path_bytes_max]u8 = undefined;
        const leaf = std.mem.sliceTo(entry, 0);
        const file = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ base, leaf }) catch continue;
        var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
        const text = files.terminate(&terminated, file) catch continue;
        _ = std.c.unlink(text.ptr);
    }
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = files.terminate(&terminated, base) catch return;
    _ = std.c.rmdir(text.ptr);
}

/// True if the file at `path` holds exactly `expected`, compared in chunks.
pub fn matches(path: []const u8, expected: []const u8) bool {
    assert(expected.len > 0);
    var chunk: [64 * 1024]u8 = undefined;
    var terminated: [constants.vm_path_bytes_max:0]u8 = undefined;
    const text = files.terminate(&terminated, path) catch return false;
    const descriptor = std.c.open(text.ptr, .{ .ACCMODE = .RDONLY });
    if (descriptor < 0) return false;
    defer files.close(descriptor);
    var offset: usize = 0;
    while (offset < expected.len) {
        const wanted = @min(chunk.len, expected.len - offset);
        const count = std.c.read(descriptor, &chunk, wanted);
        if (count <= 0) return false;
        const got: usize = @intCast(count);
        if (!std.mem.eql(u8, chunk[0..got], expected[offset..][0..got])) return false;
        offset += got;
    }
    // Nothing more: a file longer than the image is not the image.
    const extra = std.c.read(descriptor, &chunk, 1);
    return extra == 0;
}

test "the newest older image is kept and the rest are removed, and nothing else is touched" {
    // Goal: the pruning rule. Method: the choice among versions by time, then a real directory
    // with three old versions, the current one, a settings file and a stray directory.
    const old = [_]Old{
        .{ .name = "aaaaaaaaaaaaaaaa".*, .changed = 10 },
        .{ .name = "bbbbbbbbbbbbbbbb".*, .changed = 30 },
        .{ .name = "cccccccccccccccc".*, .changed = 20 },
    };
    try std.testing.expectEqual(@as(?usize, 1), newest(&old));
    try std.testing.expectEqual(@as(?usize, null), newest(&.{}));
    var home: [96]u8 = undefined;
    const base = try std.fmt.bufPrint(&home, "/tmp/zbx-prune-test-{d}", .{files.now_ms()});
    var paths: paths_mod.Paths = .{};
    try paths.init(base, version);
    const names = [_][]const u8{
        "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc", "not-a-version",
    };
    for (names) |name| {
        var directory: [constants.vm_path_bytes_max]u8 = undefined;
        const path = try std.fmt.bufPrint(&directory, "{s}/{s}", .{ paths.vm_dir.slice(), name });
        try files.make_directories(path);
        var file: [constants.vm_path_bytes_max]u8 = undefined;
        const image_file = try std.fmt.bufPrint(&file, "{s}/Image", .{path});
        try files.write_file_atomically(image_file, "x", 0o600);
    }
    try ensure(&paths);
    try files.write_file_atomically(paths.settings.slice(), "keep", 0o600);
    prune(&paths);
    var survivors: usize = 0;
    for (names) |name| {
        var directory: [constants.vm_path_bytes_max]u8 = undefined;
        const vm_dir = paths.vm_dir.slice();
        const path = try std.fmt.bufPrint(&directory, "{s}/{s}/Image", .{ vm_dir, name });
        if (files.file_size(path) > 0) survivors += 1;
    }
    // One old version (the newest by time, whichever the clock says), and the stray directory.
    try std.testing.expectEqual(@as(usize, 2), survivors);
    try std.testing.expect(files.file_size(paths.kernel.slice()) > 0);
    try std.testing.expectEqual(@as(u64, 4), files.file_size(paths.settings.slice()));
}

test "matches is true only for a file that holds exactly the expected bytes" {
    // Goal: the check that decides whether the unpacked image is rewritten. Method: a file
    // that is equal, one byte changed, shorter, longer and missing.
    var directory: [96]u8 = undefined;
    const base = try std.fmt.bufPrint(&directory, "/tmp/zbx-image-test-{d}", .{files.now_ms()});
    try files.make_directories(base);
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/file", .{base});
    const expected = "kernel bytes, long enough to differ";
    try files.write_file_atomically(path, expected, 0o600);
    try std.testing.expect(matches(path, expected));
    try std.testing.expect(!matches(path, "kernel bytes, long enough to differ!"));
    try std.testing.expect(!matches(path, "kernel bytes"));
    try files.write_file_atomically(path, "kernel bytes, long enough to diffeR", 0o600);
    try std.testing.expect(!matches(path, expected));
    try files.write_file_atomically(path, expected ++ "x", 0o600);
    try std.testing.expect(!matches(path, expected));
    try std.testing.expect(!matches("/nonexistent/zbx-image", expected));
}
