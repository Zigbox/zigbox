//! Tests of `zigbox.package`, the package writer, from a caller other than `zig build packages`:
//! a second product that builds its own packages from its own bytes, in its own memory, and
//! assembles its own apt and dnf trees. The writer's own tests are under `package/`; the zbx tree
//! is `package_release.zig`'s.

const std = @import("std");
const testing = std.testing;
const zigbox = @import("zigbox.zig");
const package_check = @import("package_check.zig");

const pkg = zigbox.package;
const architectures = [_]pkg.Architecture{ .x86_64, .aarch64 };

/// A tiny package of the second caller's own: one binary and one unit file.
fn tiny(architecture: pkg.Architecture, files: []const pkg.File) pkg.Package {
    std.debug.assert(files.len > 0);
    std.debug.assert(@backingInt(architecture) < architectures.len);
    return .{
        .name = "zigcube-agent",
        .version = "0.1.0",
        .architecture = architecture,
        .summary = "A tiny package built through the exported writer",
        .description = "Built by a second caller to prove the writer needs no build system.",
        .license = "MIT",
        .homepage = "https://example.org",
        .maintainer = "Second Caller <caller@example.org>",
        .files = files,
    };
}

/// Prefixes each file of `tree` with `prefix` and appends it to `out`, as a caller places its
/// trees under one root.
fn place(
    memory: std.mem.Allocator,
    out: *std.ArrayList(pkg.TreeFile),
    prefix: []const u8,
    tree: []const pkg.TreeFile,
) !void {
    std.debug.assert(prefix.len > 0);
    std.debug.assert(tree.len > 0);
    for (tree) |file| {
        const path = try std.fmt.allocPrint(memory, "{s}{s}", .{ prefix, file.path });
        try out.append(memory, .{ .path = path, .bytes = file.bytes });
    }
}

/// Writes a deb and an rpm of `tiny` for each architecture, and the apt and dnf trees around them.
fn build_tree(memory: std.mem.Allocator, files: []const pkg.File) ![]pkg.TreeFile {
    var debs: [architectures.len]pkg.Built = undefined;
    var rpms: [architectures.len]pkg.Built = undefined;
    for (architectures, 0..) |architecture, index| {
        const package = try memory.create(pkg.Package);
        package.* = tiny(architecture, files);
        try pkg.validate(package);
        debs[index] = .{ .package = package, .bytes = try pkg.deb.write(memory, package) };
        rpms[index] = .{ .package = package, .bytes = try pkg.rpm.write(memory, package, .{}) };
    }
    var out: std.ArrayList(pkg.TreeFile) = .empty;
    try place(memory, &out, "apt/", try pkg.apt.write(memory, &debs, null));
    for (architectures, 0..) |architecture, index| {
        const prefix = try std.fmt.allocPrint(memory, "rpm/{s}/", .{architecture.rpm_name()});
        const tree = try pkg.dnf.write(memory, architecture, rpms[index..][0..1]);
        try place(memory, &out, prefix, tree);
    }
    std.debug.assert(out.items.len > debs.len + rpms.len);
    return out.items;
}

test "a second caller builds unsigned packages through zigbox.package, and the check reads them" {
    // Goal: the writer is usable from the `zigbox` module with the caller's memory and bytes
    // alone, and its output is what `packages-check` accepts. Method: build a tiny deb and rpm
    // per architecture, assemble the trees as `package_release` does, check them unsigned; then
    // flip one byte of a placed deb and expect the check to name the mismatch.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const files = [_]pkg.File{
        .{ .path = "/usr/bin/zigcube-agent", .mode = 0o755, .bytes = "\x7fELF agent" },
        .{
            .path = "/usr/lib/systemd/system/zigcube-agent.service",
            .mode = 0o644,
            .bytes = "[Service]\nExecStart=/usr/bin/zigcube-agent\n",
        },
    };
    const tree = try build_tree(memory, &files);
    var sink: std.Io.Writer.Allocating = .init(memory);
    var source: package_check.TreeSource = .{ .files = tree };
    const loose: package_check.Options = .{ .signatures_required = false, .test_key = false };
    try package_check.check(source.source(), memory, &sink.writer, loose);
    try testing.expectEqual(@as(usize, 0), sink.written().len);

    const again = try build_tree(memory, &files);
    try testing.expectEqual(tree.len, again.len);
    for (tree, again) |first, second| {
        try testing.expectEqualStrings(first.path, second.path);
        try testing.expectEqualSlices(u8, first.bytes, second.bytes);
    }

    const tampered = try memory.dupe(pkg.TreeFile, tree);
    const index = for (tampered, 0..) |file, at| {
        if (std.mem.endsWith(u8, file.path, ".deb")) break at;
    } else unreachable;
    const copy = try memory.dupe(u8, tampered[index].bytes);
    copy[copy.len - 1] ^= 1;
    tampered[index].bytes = copy;
    source = .{ .files = tampered };
    try testing.expectError(
        error.CheckFailed,
        package_check.check(source.source(), memory, &sink.writer, loose),
    );
    try testing.expect(std.mem.indexOf(u8, sink.written(), "zigcube-agent") != null);
}

test "a second caller's invalid package is refused with the writer's own error" {
    // Goal: a caller's mistake surfaces as `zigbox.package.Error` with a one-line description,
    // not a malformed package. Method: a relative path is refused before anything is written.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const files = [_]pkg.File{.{ .path = "usr/bin/agent", .mode = 0o755, .bytes = "x" }};
    const package = tiny(.x86_64, &files);
    const refused = pkg.deb.write(memory, &package);
    try testing.expect(std.meta.isError(refused));
    const err = pkg.validate(&package);
    try testing.expect(std.meta.isError(err));
    if (err) |_| unreachable else |e| try testing.expect(pkg.describe(e).len > 0);
}
