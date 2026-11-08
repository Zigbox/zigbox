//! The pinned base image: find it in the cache, verify its SHA-256, download it if absent
//! (with std.http, no curl), and make a throwaway qcow2 overlay for each run so the base is
//! never modified.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const limits = @import("limits.zig");
const pinned = @import("image.zon");
const guests = @import("guests.zon");
const http_server = @import("http_server.zig");

pub const hex_len = 64;

pub fn to_hex(digest: [32]u8) [hex_len]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

/// SHA-256 of the file at `path`, streamed through a fixed buffer.
pub fn sha256_file(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [limits.download_chunk_bytes]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var chunk: [limits.download_chunk_bytes]u8 = undefined;
    while (true) {
        const count = try reader.interface.readSliceShort(&chunk);
        hasher.update(chunk[0..count]);
        if (count < chunk.len) break;
    }
    return hasher.finalResult();
}

/// Returns true if the file exists and matches the pinned hash. A mismatch is reported on
/// `log` and the file is left alone (the caller decides).
fn verified(io: Io, path: []const u8, sha256: []const u8, log: *Io.Writer) !bool {
    _ = Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const digest = try sha256_file(io, path);
    const actual = to_hex(digest);
    if (std.mem.eql(u8, &actual, sha256)) return true;
    try log.print("vm: {s} has sha256 {s}, expected {s}\n", .{ path, actual, sha256 });
    return false;
}

/// A file pinned by URL and SHA-256.
pub const Pin = struct {
    url: []const u8,
    sha256: []const u8,
    file_name: []const u8,
};

/// The base image of the VM: a dated release of the Ubuntu 24.04 LTS cloud image (`image.zon`).
pub const ubuntu_noble: Pin = .{
    .url = pinned.url,
    .sha256 = pinned.sha256,
    .file_name = pinned.file_name,
};

/// The other guests, pinned the same way (`guests.zon`): Debian 12 `genericcloud`, the current
/// Fedora `Cloud Base Generic` and Rocky 9 `GenericCloud`. Their package managers are `apt`
/// (Debian) and `dnf` (the other two).
pub const debian_12: Pin = .{
    .url = guests.debian_12.url,
    .sha256 = guests.debian_12.sha256,
    .file_name = guests.debian_12.file_name,
};
pub const fedora_45: Pin = .{
    .url = guests.fedora_45.url,
    .sha256 = guests.fedora_45.sha256,
    .file_name = guests.fedora_45.file_name,
};
pub const rocky_9: Pin = .{
    .url = guests.rocky_9.url,
    .sha256 = guests.rocky_9.sha256,
    .file_name = guests.rocky_9.file_name,
};

/// Makes sure `cache_dir/<file_name>` exists and matches the pinned SHA-256; downloads it
/// otherwise. Returns the path (owned by `arena`).
pub fn ensure_pin(
    init: std.process.Init,
    cache_dir: []const u8,
    log: *Io.Writer,
    pin: Pin,
) ![]const u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    try Io.Dir.cwd().createDirPath(io, cache_dir);
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ cache_dir, pin.file_name });
    if (try verified(io, path, pin.sha256, log)) {
        try log.print("vm: {s} verified (sha256 {s})\n", .{ path, pin.sha256 });
        return path;
    }
    try log.print("vm: downloading {s}\n", .{pin.url});
    try log.flush();
    const partial = try std.fmt.allocPrint(arena, "{s}.part", .{path});
    try download(io, init.gpa, arena, init.environ_map, pin.url, partial);
    if (!try verified(io, partial, pin.sha256, log)) {
        Io.Dir.cwd().deleteFile(io, partial) catch {};
        return error.ImageHashMismatch;
    }
    try Io.Dir.cwd().rename(partial, Io.Dir.cwd(), path, io);
    assert(path.len > cache_dir.len);
    try log.print("vm: downloaded and verified {s}\n", .{path});
    return path;
}

pub fn download(
    io: Io,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    url: []const u8,
    destination: []const u8,
) !void {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    try client.initDefaultProxies(arena, environ_map);

    const file = try Io.Dir.cwd().createFile(io, destination, .{});
    defer file.close(io);
    var buffer: [limits.download_chunk_bytes]u8 = undefined;
    var writer = file.writer(io, &buffer);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer.interface,
    });
    try writer.interface.flush();
    if (result.status != .ok) return error.DownloadFailed;
}

/// Creates a qcow2 overlay on top of the base image, using qemu-img (part of QEMU, the one
/// external program the harness is allowed). The overlay lives in `cache_dir` and is deleted
/// by the caller. It is `limits.overlay_size_text` big.
pub fn make_overlay(init: std.process.Init, base: []const u8, overlay: []const u8) !void {
    return make_overlay_sized(init, base, overlay, limits.overlay_size_text);
}

/// The same with a size of the caller's choice (`12G`): a guest image whose own virtual size is
/// larger than `limits.overlay_size_text` (Rocky's is 10 GiB) must not be cut short by its
/// overlay, which would put the end of its partition table beyond the disk.
pub fn make_overlay_sized(
    init: std.process.Init,
    base: []const u8,
    overlay: []const u8,
    size_text: []const u8,
) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    assert(size_text.len > 0);
    const base_absolute = try Io.Dir.cwd().realPathFileAlloc(io, base, arena);
    Io.Dir.cwd().deleteFile(io, overlay) catch {};
    const argv = [_][]const u8{
        "qemu-img", "create",      "-q", "-f",    "qcow2",
        "-b",       base_absolute, "-F", "qcow2", overlay,
        size_text,
    };
    var child = try std.process.spawn(io, .{ .argv = &argv });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.OverlayFailed,
        else => return error.OverlayFailed,
    }
}

/// Makes a raw disk image at `path` if it is not there: sparse, `size_text` big (`1G`). A disk
/// kept between runs (a cache) is made once; the guest formats it on first use.
pub fn ensure_raw_disk(init: std.process.Init, path: []const u8, size_text: []const u8) !void {
    const io = init.io;
    if (Io.Dir.cwd().statFile(io, path, .{})) |_| return else |_| {}
    if (std.fs.path.dirname(path)) |parent| try Io.Dir.cwd().createDirPath(io, parent);
    const argv = [_][]const u8{ "qemu-img", "create", "-q", "-f", "raw", path, size_text };
    var child = try std.process.spawn(io, .{ .argv = &argv });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.CacheDiskFailed,
        else => return error.CacheDiskFailed,
    }
}

test "the pinned image identifies a dated release and a SHA-256" {
    // Goal: the pin cannot silently become a moving target or a malformed hash.
    try std.testing.expect(std.mem.startsWith(u8, pinned.url, "https://"));
    try std.testing.expect(std.mem.indexOf(u8, pinned.url, "/release-2") != null);
    try std.testing.expect(!std.mem.endsWith(u8, pinned.url, "/current"));
    try std.testing.expect(std.mem.endsWith(u8, pinned.url, pinned.file_name));
    try std.testing.expectEqual(@as(usize, hex_len), pinned.sha256.len);
    for (pinned.sha256) |byte| {
        try std.testing.expect(std.ascii.isHex(byte));
        try std.testing.expect(!std.ascii.isUpper(byte));
    }
}

test "the Debian, Fedora and Rocky pins are dated https releases with a SHA-256" {
    // Goal: no guest pin can become a moving target ("latest", "current") or a bad hash.
    // Method: each pin's URL ends in its file name, names a dated release, and its hash is 64
    // lowercase hex digits; the four file names (with Ubuntu's) are distinct cache entries.
    const all = [_]Pin{ ubuntu_noble, debian_12, fedora_45, rocky_9 };
    for (all, 0..) |pin, index| {
        try std.testing.expect(std.mem.startsWith(u8, pin.url, "https://"));
        try std.testing.expect(std.mem.endsWith(u8, pin.url, pin.file_name));
        try std.testing.expect(std.mem.indexOf(u8, pin.url, "latest") == null);
        try std.testing.expect(std.mem.indexOf(u8, pin.url, "current") == null);
        try std.testing.expectEqual(@as(usize, hex_len), pin.sha256.len);
        for (pin.sha256) |byte| {
            try std.testing.expect(std.ascii.isHex(byte));
            try std.testing.expect(!std.ascii.isUpper(byte));
        }
        for (all[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, pin.file_name, other.file_name));
            try std.testing.expect(!std.mem.eql(u8, pin.sha256, other.sha256));
        }
    }
    try std.testing.expect(std.mem.indexOf(u8, debian_12.url, "/bookworm/2026") != null);
    try std.testing.expect(std.mem.indexOf(u8, fedora_45.url, "/releases/45/") != null);
    try std.testing.expect(std.mem.indexOf(u8, rocky_9.url, "-9.8-2026") != null);
}

test "to_hex renders lowercase hex" {
    var digest: [32]u8 = @splat(0xab);
    digest[0] = 0x01;
    const text = to_hex(digest);
    try std.testing.expectEqualStrings("01abab", text[0..6]);
}

const ServeContext = struct {
    server: *http_server.Server,
    stop: std.atomic.Value(bool) = .init(false),

    fn run(context: *ServeContext) void {
        var sink: Io.Writer.Discarding = .init(&.{});
        while (!context.stop.load(.acquire)) {
            var entries: [1 + limits.http_connections_max]std.os.linux.pollfd = undefined;
            const count = context.server.poll_entries(&entries);
            _ = std.os.linux.poll(&entries, count, 10);
            context.server.handle(entries[0..count], &sink.writer);
        }
    }
};

test "download fetches a file over HTTP and the digest matches" {
    // Goal: the download path (std.http client, writer, flush) works end to end against a local
    // server, and sha256_file agrees with the hash of the same bytes computed directly.
    // HTTPS is the same client over TLS and is exercised by CI, not here.
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var environ_map = std.process.Environ.Map.init(gpa);
    defer environ_map.deinit();

    var content: [300_000]u8 = undefined;
    for (&content, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    var server: http_server.Server = .{};
    try server.start();
    defer server.stop();
    server.add_route("/image", &content);
    var context: ServeContext = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, ServeContext.run, .{&context});

    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/image", .{server.port});
    const path = ".zig-cache/zbx-vm-download-test.bin";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const outcome = download(io, gpa, arena_state.allocator(), &environ_map, url, path);
    context.stop.store(true, .release);
    thread.join();
    try outcome;

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&content, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &(try sha256_file(io, path)));
}
