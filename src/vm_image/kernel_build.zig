//! Builds the VM's kernel: the pinned upstream Linux source, the checked-in config fragment, the
//! uncompressed arm64 `Image` that Virtualization.framework boots. A build-host program, not part
//! of `zbx`; run it on an arm64 Ubuntu 24.04 host (CI's `ubuntu-24.04-arm` runner, or a container
//! on a Mac: `zig build vm-kernel-docker`).
//!
//!     kernel_build --config <fragment> --cache <dir> --work <dir> --out <Image> [--jobs <n>]
//!                  [--install-deps]
//!
//! Steps: fetch the tarball (std.http) into <cache> and check it against the pinned SHA-256;
//! unpack into <work>; `make allnoconfig` with the fragment as KCONFIG_ALLCONFIG; fail unless
//! every option the fragment names ended up as written (allnoconfig drops an option whose
//! dependencies are missing, silently); build `Image` with a fixed build timestamp, user, host
//! and version; write it to <out> and compare its SHA-256 with the pin.
//!
//! The pin names the tool chain the digest was made with. A different compiler is a different
//! kernel image; the mismatch is reported with both digests and is not hidden.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const builtin = @import("builtin");
const pin = @import("build_options");

const chunk_bytes: u32 = 64 * 1024;
const config_bytes_max: u32 = 1024 * 1024;
const jobs_max: u32 = 64;
const options_max: u32 = 512;

/// The environment of a reproducible kernel build (Documentation/kbuild/reproducible-builds).
const build_environment = [_][2][]const u8{
    .{ "KBUILD_BUILD_TIMESTAMP", "Thu Jan  1 00:00:00 UTC 1970" },
    .{ "KBUILD_BUILD_USER", "zigbox" },
    .{ "KBUILD_BUILD_HOST", "zigbox" },
    .{ "KBUILD_BUILD_VERSION", "1" },
    .{ "LANG", "C" },
    .{ "LC_ALL", "C" },
};

const packages = [_][]const u8{
    "build-essential", "bc",      "bison",    "flex",            "libssl-dev",
    "libelf-dev",      "python3", "xz-utils", "ca-certificates", "perl",
};

const Arguments = struct {
    config: []const u8,
    cache: []const u8,
    work: []const u8,
    out: []const u8,
    jobs: u32,
    install_deps: bool,
};

pub fn main(init: std.process.Init) !u8 {
    var buffer: [1024]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), init.io, &buffer);
    const log = &file_writer.interface;
    defer log.flush() catch {};
    const arguments = parse_arguments(init) orelse {
        try log.print("usage: kernel_build --config F --cache D --work D --out F\n", .{});
        try log.print("  [--jobs N] [--install-deps]\n", .{});
        return 2;
    };
    run(init, &arguments, log) catch |err| {
        try log.print("kernel_build: failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn parse_arguments(init: std.process.Init) ?Arguments {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var result: Arguments = .{
        .config = "",
        .cache = "",
        .work = "",
        .out = "",
        .jobs = 4,
        .install_deps = false,
    };
    while (iterator.next()) |name| {
        if (std.mem.eql(u8, name, "--install-deps")) {
            result.install_deps = true;
            continue;
        }
        const value = iterator.next() orelse return null;
        if (std.mem.eql(u8, name, "--config")) result.config = value;
        if (std.mem.eql(u8, name, "--cache")) result.cache = value;
        if (std.mem.eql(u8, name, "--work")) result.work = value;
        if (std.mem.eql(u8, name, "--out")) result.out = value;
        if (std.mem.eql(u8, name, "--jobs")) {
            result.jobs = std.fmt.parseInt(u32, value, 10) catch return null;
        }
    }
    const complete = result.config.len > 0 and result.cache.len > 0;
    if (!complete or result.work.len == 0 or result.out.len == 0) return null;
    if (result.jobs == 0 or result.jobs > jobs_max) return null;
    return result;
}

fn run(init: std.process.Init, arguments: *const Arguments, log: *Io.Writer) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    if (arguments.install_deps) try install_dependencies(io, arena, log);
    const tarball = try fetch_tarball(init, arguments.cache, log);
    try Io.Dir.cwd().deleteTree(io, arguments.work);
    try Io.Dir.cwd().createDirPath(io, arguments.work);
    const source = try std.fmt.allocPrint(arena, "{s}/src", .{arguments.work});
    try Io.Dir.cwd().createDirPath(io, source);
    try log.print("kernel_build: unpacking {s}\n", .{tarball});
    try log.flush();
    const unpack = [_][]const u8{ "tar", "-xf", tarball, "-C", source, "--strip-components=1" };
    try exec(io, &unpack, null, null);
    var environment = try init.environ_map.clone(arena);
    for (build_environment) |pair| try environment.put(pair[0], pair[1]);
    const config_absolute = try Io.Dir.cwd().realPathFileAlloc(io, arguments.config, arena);
    try environment.put("KCONFIG_ALLCONFIG", config_absolute);
    try configure(io, arena, arguments, source, &environment, log);
    try compile(io, arena, arguments, source, &environment, log);
    try publish(io, arena, arguments, source, log);
}

fn install_dependencies(io: Io, arena: std.mem.Allocator, log: *Io.Writer) !void {
    try log.print("kernel_build: installing the tool chain with apt-get\n", .{});
    try log.flush();
    try exec(io, &.{ "apt-get", "update", "-qq" }, null, null);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "apt-get", "install", "-y", "-qq", "--no-install-recommends" });
    try argv.appendSlice(arena, &packages);
    try exec(io, argv.items, null, null);
}

/// The tarball in <cache>, downloaded if absent, and always checked against the pin.
fn fetch_tarball(init: std.process.Init, cache: []const u8, log: *Io.Writer) ![]const u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    try Io.Dir.cwd().createDirPath(io, cache);
    const name = std.fs.path.basename(pin.url);
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ cache, name });
    if (Io.Dir.cwd().statFile(io, path, .{})) |_| {} else |_| {
        try log.print("kernel_build: downloading {s}\n", .{pin.url});
        try log.flush();
        const partial = try std.fmt.allocPrint(arena, "{s}.part", .{path});
        try download(init, pin.url, partial);
        try Io.Dir.cwd().rename(partial, Io.Dir.cwd(), path, io);
    }
    const digest = try sha256_file(io, path);
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &hex, pin.tarball_sha256)) {
        try log.print("kernel_build: {s} has sha256 {s}, the pin says {s}\n", .{
            path, hex, pin.tarball_sha256,
        });
        return error.TarballDigestMismatch;
    }
    try log.print("kernel_build: tarball verified (sha256 {s})\n", .{hex});
    return path;
}

fn download(init: std.process.Init, url: []const u8, destination: []const u8) !void {
    const arena = init.arena.allocator();
    var client: std.http.Client = .{ .allocator = init.gpa, .io = init.io };
    defer client.deinit();
    try client.initDefaultProxies(arena, init.environ_map);
    const file = try Io.Dir.cwd().createFile(init.io, destination, .{});
    defer file.close(init.io);
    var buffer: [chunk_bytes]u8 = undefined;
    var writer = file.writer(init.io, &buffer);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer.interface,
    });
    try writer.interface.flush();
    if (result.status != .ok) return error.DownloadFailed;
}

fn sha256_file(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [chunk_bytes]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var chunk: [chunk_bytes]u8 = undefined;
    while (true) {
        const count = try reader.interface.readSliceShort(&chunk);
        hasher.update(chunk[0..count]);
        if (count < chunk.len) break;
    }
    return hasher.finalResult();
}

fn make_arguments(
    arena: std.mem.Allocator,
    arguments: *const Arguments,
    source: []const u8,
    goals: []const []const u8,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    const output = try std.fmt.allocPrint(arena, "O={s}/build", .{arguments.work});
    const jobs = try std.fmt.allocPrint(arena, "-j{d}", .{arguments.jobs});
    try argv.appendSlice(arena, &.{ "make", "-C", source, output, "ARCH=arm64", "LOCALVERSION=" });
    if (builtin.cpu.arch != .aarch64) try argv.append(arena, "CROSS_COMPILE=aarch64-linux-gnu-");
    try argv.append(arena, jobs);
    try argv.appendSlice(arena, goals);
    return argv.items;
}

fn configure(
    io: Io,
    arena: std.mem.Allocator,
    arguments: *const Arguments,
    source: []const u8,
    environment: *const std.process.Environ.Map,
    log: *Io.Writer,
) !void {
    const argv = try make_arguments(arena, arguments, source, &.{"allnoconfig"});
    try exec(io, argv, null, environment);
    const final_path = try std.fmt.allocPrint(arena, "{s}/build/.config", .{arguments.work});
    const final = try Io.Dir.cwd().readFileAlloc(io, final_path, arena, .limited(config_bytes_max));
    const limit: Io.Limit = .limited(config_bytes_max);
    const wanted = try Io.Dir.cwd().readFileAlloc(io, arguments.config, arena, limit);
    const missing = try verify_options(arena, wanted, final, log);
    if (missing > 0) {
        const said = "option(s) did not end up as the fragment says";
        try log.print("kernel_build: {d} {s}\n", .{ missing, said });
        return error.OptionsMissing;
    }
    try log.print("kernel_build: every option of the fragment is in the final .config\n", .{});
}

/// Counts (and names on `log`) the options in `wanted` that `final` does not hold exactly as
/// written. A `CONFIG_X=value` line must appear as a whole line; `# CONFIG_X is not set` is met
/// by that line, or by the option being absent.
fn verify_options(
    arena: std.mem.Allocator,
    wanted: []const u8,
    final: []const u8,
    log: *Io.Writer,
) !u32 {
    var missing: u32 = 0;
    var lines = std.mem.splitScalar(u8, wanted, '\n');
    var checked: u32 = 0;
    while (lines.next()) |line| {
        if (is_not_set_line(line)) {
            // "Not set" holds if the final config says so, or has no such option at all (an
            // option whose dependencies are missing is left out of the file).
            checked += 1;
            if (set_in(final, line["# ".len .. line.len - " is not set".len])) {
                try log.print("kernel_build: set, but the fragment says it is not: {s}\n", .{line});
                missing += 1;
            }
            continue;
        }
        if (!std.mem.startsWith(u8, line, "CONFIG_")) continue;
        checked += 1;
        assert(checked <= options_max);
        const needle = try std.fmt.allocPrint(arena, "\n{s}\n", .{line});
        if (std.mem.indexOf(u8, final, needle) != null) continue;
        if (std.mem.startsWith(u8, final, needle[1..])) continue;
        try log.print("kernel_build: missing: {s}\n", .{line});
        missing += 1;
    }
    assert(checked > 0);
    return missing;
}

/// `# CONFIG_X is not set`.
fn is_not_set_line(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "# CONFIG_") and std.mem.endsWith(u8, line, " is not set");
}

/// True if the final config has `<name>=` at the start of a line.
fn set_in(final: []const u8, name: []const u8) bool {
    assert(std.mem.startsWith(u8, name, "CONFIG_"));
    var lines = std.mem.splitScalar(u8, final, '\n');
    while (lines.next()) |line| {
        if (line.len > name.len and std.mem.startsWith(u8, line, name) and line[name.len] == '=') {
            return true;
        }
    }
    return false;
}

fn compile(
    io: Io,
    arena: std.mem.Allocator,
    arguments: *const Arguments,
    source: []const u8,
    environment: *const std.process.Environ.Map,
    log: *Io.Writer,
) !void {
    try log.print("kernel_build: building Image with {d} jobs\n", .{arguments.jobs});
    try log.flush();
    const argv = try make_arguments(arena, arguments, source, &.{"Image"});
    try exec(io, argv, null, environment);
}

fn publish(
    io: Io,
    arena: std.mem.Allocator,
    arguments: *const Arguments,
    source: []const u8,
    log: *Io.Writer,
) !void {
    _ = source;
    const image_path = "{s}/build/arch/arm64/boot/Image";
    const built = try std.fmt.allocPrint(arena, image_path, .{arguments.work});
    if (std.fs.path.dirname(arguments.out)) |parent| try Io.Dir.cwd().createDirPath(io, parent);
    try Io.Dir.cwd().copyFile(built, Io.Dir.cwd(), arguments.out, io, .{});
    const digest = try sha256_file(io, arguments.out);
    const hex = std.fmt.bytesToHex(digest, .lower);
    try log.print("kernel_build: Image {s} sha256 {s}\n", .{ arguments.out, hex });
    if (!std.mem.eql(u8, &hex, pin.image_sha256)) {
        try log.print("kernel_build: the pin (vm/kernel/pin.zon) says {s}\n", .{pin.image_sha256});
        try log.print("kernel_build: built with: {s}\n", .{pin.toolchain});
        return error.ImageDigestMismatch;
    }
    try log.print("kernel_build: the Image matches the pin\n", .{});
}

/// Runs `argv` to the end, in `cwd` if given, with `environment` if given; fails unless it exits
/// 0. Its output goes to ours, so a failed build shows the compiler's own words.
fn exec(
    io: Io,
    argv: []const []const u8,
    cwd: ?[]const u8,
    environment: ?*const std.process.Environ.Map,
) !void {
    assert(argv.len > 0);
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .environ_map = environment,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return error.CommandFailed;
}

test "verify_options finds a missing option and accepts a present one" {
    // Goal: the check that makes allnoconfig's silent drops loud. Method: a final config that
    // holds one wanted option and lacks another; only the lacking one is counted.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sink: Io.Writer.Allocating = .init(arena);
    const wanted = "# a comment\nCONFIG_A=y\nCONFIG_B=y\nCONFIG_NR=16\n";
    const final = "CONFIG_A=y\nCONFIG_C=y\nCONFIG_NR=16\n";
    const missing = try verify_options(arena, wanted, final, &sink.writer);
    try std.testing.expectEqual(@as(u32, 1), missing);
    try std.testing.expect(std.mem.indexOf(u8, sink.written(), "CONFIG_B=y") != null);
}

test "verify_options accepts an option that is not set, and refuses one that is" {
    // Goal: the check for "# CONFIG_X is not set" lines. Method: the option set, listed as not set
    // and left out of the file.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sink: Io.Writer.Allocating = .init(arena);
    const wanted = "# CONFIG_LOOP is not set\n";
    const writer = &sink.writer;
    const listed = try verify_options(arena, wanted, "# CONFIG_LOOP is not set\n", writer);
    try std.testing.expectEqual(@as(u32, 0), listed);
    const absent = try verify_options(arena, wanted, "CONFIG_A=y\n", writer);
    try std.testing.expectEqual(@as(u32, 0), absent);
    const set = try verify_options(arena, wanted, "CONFIG_LOOP=y\n", writer);
    try std.testing.expectEqual(@as(u32, 1), set);
    const longer = try verify_options(arena, wanted, "CONFIG_LOOP_X=y\n", writer);
    try std.testing.expectEqual(@as(u32, 0), longer);
}
