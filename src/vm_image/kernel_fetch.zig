//! `zig build vm-kernel-fetch`: downloads the VM's kernel Image from the repository's release
//! (`release_url` in vm/kernel/pin.zon) instead of building it, for a machine with neither the
//! toolchain nor Docker. The bytes are checked against the pin's `image_sha256` before they are
//! put where the build expects the Image, so the release is trusted for nothing: a wrong file
//! is refused and removed.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const pin = @import("build_options");

const image_bytes_max: usize = 256 << 20;

/// What to tell a person about an HTTP answer that is not the file.
pub fn refusal(status: u16) []const u8 {
    assert(status != 200);
    if (status == 404) {
        return "no Image there yet: the release is not published. Build the kernel instead " ++
            "with `zig build vm-kernel-docker` (needs Docker) or `zig build vm-kernel` " ++
            "(needs an arm64 Ubuntu 24.04 host)";
    }
    return "the server did not give the file";
}

pub fn main(init: std.process.Init) !u8 {
    var buffer: [1024]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const log = &file_writer.interface;
    defer log.flush() catch {};
    const out = destination(init) orelse {
        try log.print("kernel_fetch: usage: --out PATH\n", .{});
        return 2;
    };
    run(init, out, log) catch |err| {
        try log.print("kernel_fetch: stopped: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn destination(init: std.process.Init) ?[]const u8 {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |word| {
        if (std.mem.eql(u8, word, "--out")) return iterator.next();
    }
    return null;
}

fn run(init: std.process.Init, out: []const u8, log: *Io.Writer) !void {
    assert(out.len > 0);
    const io = init.io;
    const arena = init.arena.allocator();
    const dir = Io.Dir.cwd();
    if (std.fs.path.dirname(out)) |parent| try dir.createDirPath(io, parent);
    var client: std.http.Client = .{ .allocator = init.gpa, .io = io };
    defer client.deinit();
    try client.initDefaultProxies(arena, init.environ_map);
    var body: Io.Writer.Allocating = .init(arena);
    try log.print("kernel_fetch: {s}\n", .{pin.release_url});
    try log.flush();
    const result = try client.fetch(.{
        .location = .{ .url = pin.release_url },
        .response_writer = &body.writer,
    });
    if (result.status != .ok) {
        const code = @backingInt(result.status);
        try log.print("kernel_fetch: HTTP {d}: {s}\n", .{ code, refusal(code) });
        return error.DownloadFailed;
    }
    const bytes = body.written();
    if (bytes.len == 0 or bytes.len > image_bytes_max) return error.UnexpectedSize;
    const hex = digest_hex(bytes);
    if (!std.mem.eql(u8, &hex, pin.image_sha256)) {
        try log.print("kernel_fetch: the file has sha256 {s}, but the pin (vm/kernel/pin.zon) " ++
            "says {s}; not used\n", .{ &hex, pin.image_sha256 });
        return error.DigestMismatch;
    }
    const part = try std.fmt.allocPrint(arena, "{s}.part", .{out});
    try dir.writeFile(io, .{ .sub_path = part, .data = bytes });
    try dir.rename(part, dir, out, io);
    try log.print("kernel_fetch: {s} matches the pin ({d} bytes)\n", .{ out, bytes.len });
}

pub fn digest_hex(bytes: []const u8) [64]u8 {
    assert(bytes.len > 0);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "a 404 names the two ways to build the kernel, and any other status is short" {
    // Goal: the message the 404 path prints. Method: the two answers.
    try std.testing.expect(std.mem.indexOf(u8, refusal(404), "vm-kernel-docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, refusal(404), "zig build vm-kernel`") != null);
    try std.testing.expect(std.mem.indexOf(u8, refusal(503), "did not give") != null);
}

test "the digest is the sha256 in lower-case hex" {
    // Goal: the check against the pin compares what the pin is written in. Method: the digest of
    // "abc", which is known.
    const expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    try std.testing.expectEqualStrings(expected, &digest_hex("abc"));
}
