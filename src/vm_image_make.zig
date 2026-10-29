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
};

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
        const value = iterator.next() orelse return null;
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
        "dev", "etc", "proc", "run", "sys", "tmp", "usr", "usr/bin",
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
