//! Builds the VM image's initramfs and names the image: a build-host program run by `zig build`.
//!
//!     make_image --kernel <Image> --init <exe> --zbx <exe> [--label <text>]
//!                --out-initramfs <file> --out-version <file>
//!
//! The initramfs holds the guest's init as /init, the Linux `zbx` as /usr/bin/zbx, the console and
//! null device nodes, the mount points init needs, and /etc/zbx-image-version. The version is the
//! first 16 hex digits of a SHA-256 over the kernel's digest and, for every entry in order, its
//! path, mode and content digest (the version file itself is not in it: it would name itself).
//! The same inputs always make the same bytes and the same version. `--label` is for development:
//! it is part of the image, so two builds can be told apart.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const apk = @import("vm_image/apk.zig");
const cpio = @import("vm_image/cpio.zig");
const constants = @import("constants.zig");

const file_bytes_max: usize = 64 << 20;

const Arguments = struct {
    kernel: []const u8 = "",
    kernel_sha256: []const u8 = "",
    init: []const u8 = "",
    zbx: []const u8 = "",
    label: []const u8 = "",
    out_initramfs: []const u8 = "",
    out_version: []const u8 = "",
    apk_cache: []const u8 = "",
    apk_mirror: []const u8 = "",
    packages: [16]Package = undefined,
    package_count: u32 = 0,
};

/// An Alpine package to take files from: its name, where it is, and the SHA-256 of the file.
const Package = struct { name: []const u8, url: []const u8, sha256: []const u8 };

pub fn main(init: std.process.Init) !u8 {
    var buffer: [512]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const log = &file_writer.interface;
    defer log.flush() catch {};
    const arguments = parse_arguments(init) orelse {
        try log.print("usage: make_image --kernel F --kernel-sha256 H --init F --zbx F\n", .{});
        try log.print("  --out-initramfs F --out-version F [--label T]\n", .{});
        return 2;
    };
    run(init, &arguments) catch |err| {
        try log.print("make_image: failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn parse_arguments(init: std.process.Init) ?Arguments {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var result: Arguments = .{};
    while (iterator.next()) |name| {
        if (std.mem.eql(u8, name, "--apk")) {
            if (result.package_count == result.packages.len) return null;
            const package_name = iterator.next() orelse return null;
            const url = iterator.next() orelse return null;
            const digest = iterator.next() orelse return null;
            result.packages[result.package_count] = .{
                .name = package_name,
                .url = url,
                .sha256 = digest,
            };
            result.package_count += 1;
            continue;
        }
        const value = iterator.next() orelse return null;
        if (std.mem.eql(u8, name, "--apk-cache")) result.apk_cache = value;
        if (std.mem.eql(u8, name, "--apk-mirror")) result.apk_mirror = value;
        if (std.mem.eql(u8, name, "--kernel")) result.kernel = value;
        if (std.mem.eql(u8, name, "--kernel-sha256")) result.kernel_sha256 = value;
        if (std.mem.eql(u8, name, "--init")) result.init = value;
        if (std.mem.eql(u8, name, "--zbx")) result.zbx = value;
        if (std.mem.eql(u8, name, "--label")) result.label = value;
        if (std.mem.eql(u8, name, "--out-initramfs")) result.out_initramfs = value;
        if (std.mem.eql(u8, name, "--out-version")) result.out_version = value;
    }
    const inputs = result.kernel.len > 0 and result.init.len > 0 and result.zbx.len > 0;
    if (!inputs or result.out_initramfs.len == 0 or result.out_version.len == 0) return null;
    return result;
}

fn run(init: std.process.Init, arguments: *const Arguments) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const limit: Io.Limit = .limited(file_bytes_max);
    const kernel = Io.Dir.cwd().readFileAlloc(io, arguments.kernel, arena, limit) catch |err| {
        var buffer: [256]u8 = undefined;
        var file_writer: Io.File.Writer = .init(.stderr(), io, &buffer);
        try file_writer.interface.print(
            "make_image: cannot read the VM kernel {s}: {s}\n" ++
                "  build it first: zig build vm-kernel-docker\n",
            .{ arguments.kernel, @errorName(err) },
        );
        try file_writer.interface.flush();
        return err;
    };
    try check_pin(io, kernel, arguments.kernel_sha256);
    const init_binary = try Io.Dir.cwd().readFileAlloc(io, arguments.init, arena, limit);
    const zbx_binary = try Io.Dir.cwd().readFileAlloc(io, arguments.zbx, arena, limit);
    var entries: std.ArrayList(cpio.Entry) = .empty;
    try add_fixed(&entries, arena, init_binary, zbx_binary, arguments.label);
    try add_packages(init, arguments, &entries);
    const version = version_of(kernel, entries.items);
    try entries.append(arena, .{
        .path = "etc/zbx-image-version",
        .kind = .file,
        .mode = 0o444,
        .data = try std.fmt.allocPrint(arena, "{s}\n", .{&version}),
    });
    std.mem.sort(cpio.Entry, entries.items, {}, path_less);
    const archive = try cpio.build(arena, entries.items);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = arguments.out_initramfs, .data = archive });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = arguments.out_version, .data = &version });
}

/// The kernel must be the pinned one, byte for byte: the image's version would otherwise name a
/// kernel nobody can rebuild from the repository.
fn check_pin(io: Io, kernel: []const u8, pinned: []const u8) !void {
    assert(kernel.len > 0);
    if (pinned.len == 0) return;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(kernel, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (std.mem.eql(u8, &hex, pinned)) return;
    var buffer: [512]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), io, &buffer);
    try file_writer.interface.print(
        "make_image: the kernel has sha256 {s}, vm/kernel/pin.zon says {s}\n" ++
            "  rebuild it: zig build vm-kernel-docker\n",
        .{ hex, pinned },
    );
    try file_writer.interface.flush();
    return error.KernelIsNotThePinnedOne;
}

fn path_less(_: void, left: cpio.Entry, right: cpio.Entry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

/// Everything in the initramfs except the version file.
fn add_fixed(
    entries: *std.ArrayList(cpio.Entry),
    arena: std.mem.Allocator,
    init_binary: []const u8,
    zbx_binary: []const u8,
    label: []const u8,
) !void {
    const directories = [_][]const u8{
        "dev",     "etc",           "proc", "run", "sys", "tmp", "usr", "usr/bin", "lib", "usr/lib",
        "etc/ssl", "etc/ssl/certs", "bin",  "mnt",
    };
    for (directories) |path| {
        try entries.append(arena, .{ .path = path, .kind = .directory, .mode = 0o755 });
    }
    try entries.append(arena, .{
        .path = "init",
        .kind = .file,
        .mode = 0o755,
        .data = init_binary,
    });
    try entries.append(arena, .{
        .path = "usr/bin/zbx",
        .kind = .file,
        .mode = 0o755,
        .data = zbx_binary,
    });
    const console: cpio.Entry = .{
        .path = "dev/console",
        .kind = .character_device,
        .mode = 0o600,
        .major = 5,
        .minor = 1,
    };
    try entries.append(arena, console);
    const null_device: cpio.Entry = .{
        .path = "dev/null",
        .kind = .character_device,
        .mode = 0o666,
        .major = 1,
        .minor = 3,
    };
    try entries.append(arena, null_device);
    if (label.len > 0) {
        const text = try std.fmt.allocPrint(arena, "{s}\n", .{label});
        try entries.append(arena, .{
            .path = "etc/zbx-image-label",
            .kind = .file,
            .mode = 0o444,
            .data = text,
        });
    }
}

/// The image version: see the file comment. Entries are hashed in sorted order of path, so the
/// order they were added in does not matter.
fn version_of(kernel: []const u8, entries: []cpio.Entry) [constants.vm_image_version_bytes]u8 {
    assert(kernel.len > 0);
    std.mem.sort(cpio.Entry, entries, {}, path_less);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var kernel_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(kernel, &kernel_digest, .{});
    hasher.update(&kernel_digest);
    for (entries) |entry| {
        var content: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(entry.data, &content, .{});
        hasher.update(entry.path);
        hasher.update(&.{0});
        hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, entry.mode)));
        hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, entry.major)));
        hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, entry.minor)));
        hasher.update(&content);
    }
    const digest = hasher.finalResult();
    const hex = std.fmt.bytesToHex(digest, .lower);
    return hex[0..constants.vm_image_version_bytes].*;
}

test "the version depends on the kernel, a file's bytes and the order-free set of entries" {
    // Goal: one changed input changes the version, and the order entries are added in does not.
    // Method: a base set, then each kind of change, then the base reversed.
    var base = [_]cpio.Entry{
        .{ .path = "a", .kind = .file, .mode = 0o644, .data = "one" },
        .{ .path = "b", .kind = .file, .mode = 0o644, .data = "two" },
    };
    const first = version_of("kernel", &base);
    try std.testing.expectEqual(first, version_of("kernel", &base));
    try std.testing.expect(!std.mem.eql(u8, &first, &version_of("kernel2", &base)));
    var changed = base;
    changed[1].data = "twp";
    try std.testing.expect(!std.mem.eql(u8, &first, &version_of("kernel", &changed)));
    var mode = base;
    mode[0].mode = 0o755;
    try std.testing.expect(!std.mem.eql(u8, &first, &version_of("kernel", &mode)));
    var reversed = [_]cpio.Entry{ base[1], base[0] };
    try std.testing.expectEqual(first, version_of("kernel", &reversed));
}

/// The files of each pinned Alpine package that the VM needs, and no others.
fn wanted(path: []const u8) bool {
    const exact = [_][]const u8{
        "lib/ld-musl-aarch64.so.1",
        "lib/libc.musl-aarch64.so.1",
        "usr/bin/newuidmap",
        "usr/bin/newgidmap",
        "etc/ssl/certs/ca-certificates.crt",
        "etc/ssl/cert.pem",
    };
    for (exact) |name| {
        if (std.mem.eql(u8, name, path)) return true;
    }
    return std.mem.startsWith(u8, path, "usr/lib/libbsd.so") or
        std.mem.startsWith(u8, path, "usr/lib/libmd.so");
}

fn add_packages(
    init: std.process.Init,
    arguments: *const Arguments,
    entries: *std.ArrayList(cpio.Entry),
) !void {
    const arena = init.arena.allocator();
    for (arguments.packages[0..arguments.package_count]) |package| {
        const bytes = try fetch_package(init, arguments, package);
        for (try apk.unpack(arena, bytes)) |file| {
            if (file.kind == .directory or !wanted(file.path)) continue;
            // newuidmap and newgidmap are setuid root: they write another process's id map.
            const setuid = std.mem.endsWith(u8, file.path, "/newuidmap") or
                std.mem.endsWith(u8, file.path, "/newgidmap");
            try entries.append(arena, .{
                .path = file.path,
                .kind = if (file.kind == .symlink) .symlink else .file,
                .mode = if (setuid) file.mode | 0o4000 else file.mode,
                .data = file.data,
            });
        }
    }
}

/// The package file from the cache, if it is there and is the pinned one; otherwise from the
/// mirror and then from its original URL. A file that fails its SHA-256 is refused (and removed),
/// whichever source it came from. If no source gives the pinned file, one line names the package
/// and both URLs.
fn fetch_package(
    init: std.process.Init,
    arguments: *const Arguments,
    package: Package,
) ![]const u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    try Io.Dir.cwd().createDirPath(io, arguments.apk_cache);
    const name = std.fs.path.basename(package.url);
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ arguments.apk_cache, name });
    if (read_pinned(io, arena, path, package.sha256)) |bytes| return bytes;
    const mirror_url = try std.fmt.allocPrint(arena, "{s}/{s}", .{ arguments.apk_mirror, name });
    const sources = [_][]const u8{ mirror_url, package.url };
    const partial = try std.fmt.allocPrint(arena, "{s}.part", .{path});
    for (sources) |source| {
        if (arguments.apk_mirror.len == 0 and source.ptr == mirror_url.ptr) continue;
        download(init, source, partial) catch {
            note(io, "make_image: {s}: no file at {s}\n", .{ package.name, source });
            continue;
        };
        if (read_pinned(io, arena, partial, package.sha256)) |bytes| {
            try Io.Dir.cwd().rename(partial, Io.Dir.cwd(), path, io);
            note(io, "make_image: {s} from {s}\n", .{ package.name, source });
            return bytes;
        }
        const refused = "make_image: {s}: the file at {s} is not the pinned one; refused\n";
        note(io, refused, .{ package.name, source });
        Io.Dir.cwd().deleteFile(io, partial) catch {};
    }
    note(io, "make_image: cannot get {s}: neither {s} nor {s} gave the pinned file\n", .{
        package.name, mirror_url, package.url,
    });
    return error.PackageUnavailable;
}

/// The file's bytes if it exists and has the SHA-256; a file that does not is removed.
fn read_pinned(io: Io, arena: std.mem.Allocator, path: []const u8, sha256: []const u8) ?[]const u8 {
    const limit: Io.Limit = .limited(file_bytes_max);
    const bytes = Io.Dir.cwd().readFileAlloc(io, path, arena, limit) catch return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (std.mem.eql(u8, &hex, sha256)) return bytes;
    Io.Dir.cwd().deleteFile(io, path) catch {};
    return null;
}

fn note(io: Io, comptime format: []const u8, args: anytype) void {
    var buffer: [768]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), io, &buffer);
    file_writer.interface.print(format, args) catch return;
    file_writer.interface.flush() catch return;
}

fn download(init: std.process.Init, url: []const u8, destination: []const u8) !void {
    const arena = init.arena.allocator();
    var client: std.http.Client = .{ .allocator = init.gpa, .io = init.io };
    defer client.deinit();
    try client.initDefaultProxies(arena, init.environ_map);
    const file = try Io.Dir.cwd().createFile(init.io, destination, .{});
    defer file.close(init.io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = file.writer(init.io, &buffer);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer.interface,
    });
    try writer.interface.flush();
    if (result.status != .ok) return error.DownloadFailed;
}

test "read_pinned returns the pinned file and removes any other" {
    // Goal: a file that fails its SHA-256 (a bad mirror, a damaged cache) is refused. Method: a
    // file with the right digest, then the same path with a wrong one.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const path = ".zig-cache/zbx-read-pinned-test";
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "pinned bytes" });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("pinned bytes", &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings("pinned bytes", read_pinned(io, arena, path, &hex).?);
    const wrong: [64]u8 = @splat(0x30);
    try std.testing.expect(read_pinned(io, arena, path, &wrong) == null);
    try std.testing.expect(read_pinned(io, arena, path, &hex) == null); // It was removed.
}
