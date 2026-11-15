//! What `zig build packages` writes: the `zigbox` deb and rpm for each architecture, the apt and
//! dnf trees around them, the files an owner signs, and the check that every placed file agrees
//! with the metadata that names it. Pure: bytes in, bytes out. `package_main.zig` does the I/O.
//! The package writer in `src/package/` knows nothing about `zbx`; this file does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const constants = @import("constants.zig");
const package = @import("package.zig");
const model = package.model;
const apt = package.apt;
const dnf = package.dnf;
const deb = package.deb;
const rpm = package.rpm;
const openpgp = package.openpgp;

pub const Error = model.Error || openpgp.Error;

pub const architectures = [_]model.Architecture{ .x86_64, .aarch64 };

pub const Inputs = struct {
    version: []const u8,
    /// The release `zbx` of each architecture, in `architectures` order.
    zbx: [architectures.len][]const u8,
    license: []const u8,
};

/// Detached OpenPGP signatures (binary packets) the owner made in the two rounds of signing.
pub const Signatures = struct {
    /// Over each rpm's main header, in `architectures` order (round 1).
    header: [architectures.len]?[]const u8 = @splat(null),
    /// A clearsigned `Release`, a detached armored signature of it, and of each `repomd.xml`
    /// (round 2).
    in_release: ?[]const u8 = null,
    release_gpg: ?[]const u8 = null,
    repomd_asc: [architectures.len]?[]const u8 = @splat(null),
};

pub const Options = struct {
    signatures: Signatures = .{},
    /// Sign everything with the fixed test key instead (CI; the key vouches for nothing).
    test_key: bool = false,
    /// The signing time (seconds since the epoch) written as `Release`'s `Date`, with
    /// `Valid-Until` 21 days later. Null: the fixed build date and no `Valid-Until`.
    signed_at: ?u64 = null,
};

pub const apt_release_path = "apt/dists/" ++ apt.suite ++ "/Release";
pub const apt_in_release_path = "apt/dists/" ++ apt.suite ++ "/InRelease";
pub const apt_release_gpg_path = "apt/dists/" ++ apt.suite ++ "/Release.gpg";
pub const test_key_armored_path = "zigbox-test-key.asc";
pub const test_key_binary_path = "zigbox-test-key.gpg";

/// Zigbox's apt repository, as its `Release` names it; apt pins and unattended-upgrades on
/// users' hosts match these, so they never change.
pub const apt_identity: apt.Identity = .{
    .origin = "Zigbox",
    .label = "Zigbox",
    .description = "Zigbox packages",
};
/// The build host every Zigbox rpm names, so that the file does not depend on the machine.
pub const rpm_build_host = "zigbox-build";

const Flavor = enum { deb, rpm };

/// The package for one architecture: `zbx` and the licence, which the two formats place apart.
fn describe(
    memory: Allocator,
    inputs: *const Inputs,
    index: usize,
    flavor: Flavor,
) Error!*const model.Package {
    const files = try memory.alloc(model.File, 2);
    files[0] = .{ .path = "/usr/bin/zbx", .mode = 0o755, .bytes = inputs.zbx[index] };
    files[1] = .{
        .path = switch (flavor) {
            .deb => "/usr/share/doc/zigbox/copyright",
            .rpm => "/usr/share/licenses/zigbox/LICENSE",
        },
        .mode = 0o644,
        .bytes = inputs.license,
    };
    const result = try memory.create(model.Package);
    result.* = .{
        .name = "zigbox",
        .version = inputs.version,
        .architecture = architectures[index],
        .summary = "Rootless, daemonless container runtime, image store and builder",
        .description = "Zigbox runs Linux containers without a daemon and without root, and\n" ++
            "keeps an image store and a builder beside the runtime.\n\n" ++
            "The package holds the static zbx binary. It does not touch /etc/subuid or\n" ++
            "/etc/subgid, and removing it leaves the image store alone.",
        .license = "MIT",
        .homepage = "https://zigbox.org",
        .maintainer = constants.package_maintainer,
        .recommends_deb = &.{ "uidmap", "passt" },
        .recommends_rpm = &.{ "shadow-utils", "passt" },
        .files = files,
    };
    return result;
}

/// The path an rpm's header is written to for signing, and the name its signature has in a
/// signatures directory.
pub fn header_path(memory: Allocator, rpm_file: []const u8) Error![]u8 {
    return std.fmt.allocPrint(memory, "to-sign/{s}.header", .{rpm_file}) catch
        return error.OutOfMemory;
}

pub fn header_signature_name(memory: Allocator, rpm_file: []const u8) Error![]u8 {
    return std.fmt.allocPrint(memory, "{s}.header.sig", .{rpm_file}) catch
        return error.OutOfMemory;
}

pub fn repomd_path(memory: Allocator, index: usize) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(memory, "rpm/{s}/repodata/repomd.xml", .{
        architectures[index].rpm_name(),
    }) catch return error.OutOfMemory;
}

pub fn repomd_signature_name(memory: Allocator, index: usize) Error![]u8 {
    return std.fmt.allocPrint(memory, "repomd.{s}.xml.asc", .{
        architectures[index].rpm_name(),
    }) catch return error.OutOfMemory;
}

pub fn rpm_file_name(memory: Allocator, inputs: *const Inputs, index: usize) Error![]u8 {
    return rpm.file_name(memory, try describe(memory, inputs, index, .rpm));
}

/// The path of each architecture's deb and rpm under the output directory, the files a release
/// attaches beside the archive.
pub fn deb_tree_path(memory: Allocator, inputs: *const Inputs, index: usize) Error![]u8 {
    const pool = try apt.pool_path(memory, try describe(memory, inputs, index, .deb));
    return std.fmt.allocPrint(memory, "apt/{s}", .{pool}) catch return error.OutOfMemory;
}

pub fn rpm_tree_path(memory: Allocator, inputs: *const Inputs, index: usize) Error![]u8 {
    return std.fmt.allocPrint(memory, "rpm/{s}/{s}", .{
        architectures[index].rpm_name(), try rpm_file_name(memory, inputs, index),
    }) catch return error.OutOfMemory;
}

fn add(
    memory: Allocator,
    files: *std.ArrayList(model.TreeFile),
    path: []const u8,
    bytes: []const u8,
) Error!void {
    try files.append(memory, .{ .path = path, .bytes = bytes });
    assert(files.items.len <= constants.repo_files_max);
}

fn add_tree(
    memory: Allocator,
    files: *std.ArrayList(model.TreeFile),
    prefix: []const u8,
    tree: []const model.TreeFile,
) Error!void {
    for (tree) |file| {
        const path = try std.fmt.allocPrint(memory, "{s}{s}", .{ prefix, file.path });
        try add(memory, files, path, file.bytes);
    }
}

fn find(files: []const model.TreeFile, path: []const u8) ?[]const u8 {
    for (files) |file| {
        if (std.mem.eql(u8, file.path, path)) return file.bytes;
    }
    return null;
}

/// Every file under the output directory, by path relative to it. Before the signing rounds the
/// rpms are unsigned and the signature files are absent; each round adds what it was given.
pub fn build(memory: Allocator, inputs: *const Inputs, options: Options) Error![]model.TreeFile {
    var files: std.ArrayList(model.TreeFile) = .empty;
    var debs: [architectures.len]model.Built = undefined;
    var rpms: [architectures.len]model.Built = undefined;
    const key = openpgp.test_key();
    for (architectures, 0..) |_, index| {
        const deb_package = try describe(memory, inputs, index, .deb);
        const rpm_package = try describe(memory, inputs, index, .rpm);
        const header = try rpm.header_bytes(memory, rpm_package, rpm_build_host);
        const signature = if (options.test_key)
            try openpgp.sign_detached(memory, key, header)
        else
            options.signatures.header[index];
        const rpm_bytes = try rpm.write(memory, rpm_package, .{
            .build_host = rpm_build_host,
            .header_signature = signature,
        });
        const rpm_file = try rpm.file_name(memory, rpm_package);
        try add(memory, &files, try header_path(memory, rpm_file), header);
        debs[index] = .{ .package = deb_package, .bytes = try deb.write(memory, deb_package) };
        rpms[index] = .{ .package = rpm_package, .bytes = rpm_bytes };
    }
    const apt_tree = try apt.write(memory, &debs, options.signed_at, &apt_identity);
    try add_tree(memory, &files, "apt/", apt_tree);
    for (architectures, 0..) |architecture, index| {
        const prefix = try std.fmt.allocPrint(memory, "rpm/{s}/", .{architecture.rpm_name()});
        const tree = try dnf.write(memory, architecture, rpms[index..][0..1]);
        try add_tree(memory, &files, prefix, tree);
    }
    try add_signatures(memory, &files, options);
    return files.items;
}

fn add_signatures(
    memory: Allocator,
    files: *std.ArrayList(model.TreeFile),
    options: Options,
) Error!void {
    const release = find(files.items, apt_release_path).?;
    const key = openpgp.test_key();
    if (options.test_key) {
        const detached = try openpgp.sign_detached(memory, key, release);
        try add(memory, files, apt_in_release_path, try openpgp.clearsign(memory, key, release));
        const release_gpg = try openpgp.armor(memory, "PGP SIGNATURE", detached);
        try add(memory, files, apt_release_gpg_path, release_gpg);
        const public = try openpgp.public_key_packets(memory, key);
        try add(memory, files, test_key_binary_path, public);
        const armored = try openpgp.armor(memory, "PGP PUBLIC KEY BLOCK", public);
        try add(memory, files, test_key_armored_path, armored);
    } else {
        if (options.signatures.in_release) |bytes| {
            try add(memory, files, apt_in_release_path, bytes);
        }
        if (options.signatures.release_gpg) |bytes| {
            try add(memory, files, apt_release_gpg_path, bytes);
        }
    }
    for (0..architectures.len) |index| {
        const path = try repomd_path(memory, index);
        const signature_path = try std.fmt.allocPrint(memory, "{s}.asc", .{path});
        if (options.test_key) {
            const detached = try openpgp.sign_detached(memory, key, find(files.items, path).?);
            const armored = try openpgp.armor(memory, "PGP SIGNATURE", detached);
            try add(memory, files, signature_path, armored);
        } else if (options.signatures.repomd_asc[index]) |bytes| {
            try add(memory, files, signature_path, bytes);
        }
    }
}

/// How far along the two rounds of signing a build is, for the commands the tool prints next.
pub const Round = enum { trees, done };

pub fn round_of(files: []const model.TreeFile) Round {
    if (find(files, apt_in_release_path) == null) return .trees;
    if (find(files, apt_release_gpg_path) == null) return .trees;
    for (0..architectures.len) |index| {
        var buffer: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, "rpm/{s}/repodata/repomd.xml.asc", .{
            architectures[index].rpm_name(),
        }) catch unreachable; // The name is a fixed short string; the buffer is 128 bytes.
        if (find(files, path) == null) return .trees;
    }
    return .done;
}

test "build gives the same bytes twice and names the files of both architectures" {
    // Goal: reproducibility and layout of the whole output with the test key.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const inputs: Inputs = .{
        .version = "1.2.3",
        .zbx = .{ "x86 binary", "arm binary" },
        .license = "MIT licence\n",
    };
    const first = try build(memory, &inputs, .{ .test_key = true });
    const second = try build(memory, &inputs, .{ .test_key = true });
    try std.testing.expectEqual(first.len, second.len);
    for (first, second) |left, right| {
        try std.testing.expectEqualStrings(left.path, right.path);
        try std.testing.expectEqualSlices(u8, left.bytes, right.bytes);
    }
    try std.testing.expect(find(first, "apt/pool/main/z/zigbox/zigbox_1.2.3_amd64.deb") != null);
    try std.testing.expect(find(first, "apt/pool/main/z/zigbox/zigbox_1.2.3_arm64.deb") != null);
    try std.testing.expect(find(first, "rpm/x86_64/zigbox-1.2.3-1.x86_64.rpm") != null);
    try std.testing.expect(find(first, "rpm/aarch64/zigbox-1.2.3-1.aarch64.rpm") != null);
    try std.testing.expect(find(first, "to-sign/zigbox-1.2.3-1.aarch64.rpm.header") != null);
    try std.testing.expectEqual(Round.done, round_of(first));
    const unsigned = try build(memory, &inputs, .{});
    try std.testing.expectEqual(Round.trees, round_of(unsigned));
    try std.testing.expect(find(unsigned, apt_in_release_path) == null);
}
