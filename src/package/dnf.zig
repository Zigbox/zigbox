//! The dnf repository writer, for one `$basearch` tree: the rpms and `repodata/` with
//! `primary.xml.gz`, `filelists.xml.gz`, `other.xml.gz` and `repomd.xml`, every sum SHA-256. The
//! metadata files are named by their checksum, as `createrepo_c` names them. `repomd.xml.asc` is
//! signed by the owner's gpg and placed by the caller.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const model = @import("model.zig");
const archive = @import("archive.zig");
const rpm = @import("rpm.zig");

const Allocator = std.mem.Allocator;
const Output = std.Io.Writer.Allocating;
pub const Error = model.Error;

const xml_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

fn put(writer: *std.Io.Writer, bytes: []const u8) Error!void {
    writer.writeAll(bytes) catch return error.WriteFailed;
}

/// Text content or attribute value, escaped.
fn put_escaped(writer: *std.Io.Writer, text: []const u8) Error!void {
    for (text) |byte| switch (byte) {
        '&' => try put(writer, "&amp;"),
        '<' => try put(writer, "&lt;"),
        '>' => try put(writer, "&gt;"),
        '"' => try put(writer, "&quot;"),
        else => try put(writer, &.{byte}),
    };
}

fn print(writer: *std.Io.Writer, comptime format: []const u8, args: anytype) Error!void {
    writer.print(format, args) catch return error.WriteFailed;
}

/// What `createrepo_c` puts in primary.xml: paths in `bin` directories and under `/etc`.
fn in_primary(path: []const u8) bool {
    const prefixes = [_][]const u8{ "/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/" };
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return std.mem.eql(u8, path, "/usr/lib/sendmail");
}

fn put_files(
    writer: *std.Io.Writer,
    entries: []const model.Entry,
    primary_only: bool,
    indent: []const u8,
) Error!void {
    for (entries) |entry| {
        if (primary_only and !in_primary(entry.path)) continue;
        try put(writer, indent);
        try put(writer, if (entry.file == null) "<file type=\"dir\">" else "<file>");
        try put_escaped(writer, entry.path);
        try put(writer, "</file>\n");
    }
}

fn provides_xml(
    memory: Allocator,
    writer: *std.Io.Writer,
    package: *const model.Package,
) Error!void {
    const abi = package.architecture.rpm_abi();
    const provided = [2][]const u8{
        package.name,
        try std.fmt.allocPrint(memory, "{s}({s})", .{ package.name, abi }),
    };
    try put(writer, "    <rpm:provides>\n");
    for (provided) |name| {
        try print(
            writer,
            "      <rpm:entry name=\"{s}\" flags=\"EQ\" epoch=\"0\" ver=\"{s}\" rel=\"{s}\"/>\n",
            .{ name, package.version, package.revision },
        );
    }
    try put(writer, "    </rpm:provides>\n");
}

fn package_xml(
    memory: Allocator,
    writer: *std.Io.Writer,
    built: model.Built,
    pkgid: []const u8,
) Error!void {
    const package = built.package;
    const parts = rpm.split(built.bytes) orelse
        unreachable; // `write` refused every rpm `check_built` does not accept.
    const entries = try model.layout(memory, package, true);
    const epoch = constants.package_source_date_epoch;
    const rpm_arch = package.architecture.rpm_name();
    try put(writer, "<package type=\"rpm\">\n  <name>");
    try put_escaped(writer, package.name);
    try print(writer, "</name>\n  <arch>{s}</arch>\n", .{rpm_arch});
    try print(
        writer,
        "  <version epoch=\"0\" ver=\"{s}\" rel=\"{s}\"/>\n",
        .{ package.version, package.revision },
    );
    try print(
        writer,
        "  <checksum type=\"sha256\" pkgid=\"YES\">{s}</checksum>\n  <summary>",
        .{pkgid},
    );
    try put_escaped(writer, package.summary);
    try put(writer, "</summary>\n  <description>");
    try put_escaped(writer, package.description);
    try put(writer, "</description>\n  <packager></packager>\n  <url>");
    try put_escaped(writer, package.homepage);
    try print(writer, "</url>\n  <time file=\"{d}\" build=\"{d}\"/>\n", .{ epoch, epoch });
    try print(writer, "  <size package=\"{d}\" installed=\"{d}\" archive=\"{d}\"/>\n", .{
        built.bytes.len, model.content_bytes(package), try rpm.archive_bytes(memory, package),
    });
    const file_name = try rpm.file_name(memory, package);
    try print(writer, "  <location href=\"{s}\"/>\n  <format>\n    <rpm:license>", .{file_name});
    try put_escaped(writer, package.license);
    try put(
        writer,
        "</rpm:license>\n    <rpm:vendor></rpm:vendor>\n    <rpm:group>Unspecified</rpm:group>\n",
    );
    const build_host = rpm.build_host_of(parts.main_header) orelse
        unreachable; // `check_built` found the build host in this main header.
    try put(writer, "    <rpm:buildhost>");
    try put_escaped(writer, build_host);
    try put(writer, "</rpm:buildhost>\n");
    try print(
        writer,
        "    <rpm:sourcerpm>{s}-{s}-{s}.src.rpm</rpm:sourcerpm>\n",
        .{ package.name, package.version, package.revision },
    );
    try print(
        writer,
        "    <rpm:header-range start=\"{d}\" end=\"{d}\"/>\n",
        .{ parts.header_start, parts.header_end },
    );
    try provides_xml(memory, writer, package);
    if (package.recommends_rpm.len > 0) {
        try put(writer, "    <rpm:recommends>\n");
        for (package.recommends_rpm) |name| {
            try put(writer, "      <rpm:entry name=\"");
            try put_escaped(writer, name);
            try put(writer, "\"/>\n");
        }
        try put(writer, "    </rpm:recommends>\n");
    }
    try put_files(writer, entries, true, "    ");
    try put(writer, "  </format>\n</package>\n");
}

fn filelists_xml(
    memory: Allocator,
    writer: *std.Io.Writer,
    built: model.Built,
    pkgid: []const u8,
) Error!void {
    const package = built.package;
    try print(writer, "<package pkgid=\"{s}\" name=\"{s}\" arch=\"{s}\">\n", .{
        pkgid, package.name, package.architecture.rpm_name(),
    });
    try print(
        writer,
        "  <version epoch=\"0\" ver=\"{s}\" rel=\"{s}\"/>\n",
        .{ package.version, package.revision },
    );
    try put_files(writer, try model.layout(memory, package, true), false, "  ");
    try put(writer, "</package>\n");
}

fn other_xml(writer: *std.Io.Writer, built: model.Built, pkgid: []const u8) Error!void {
    const package = built.package;
    try print(writer, "<package pkgid=\"{s}\" name=\"{s}\" arch=\"{s}\">\n", .{
        pkgid, package.name, package.architecture.rpm_name(),
    });
    try print(
        writer,
        "  <version epoch=\"0\" ver=\"{s}\" rel=\"{s}\"/>\n</package>\n",
        .{ package.version, package.revision },
    );
}

const Document = enum { primary, filelists, other };

fn document(memory: Allocator, kind: Document, packages: []const model.Built) Error![]u8 {
    var out = Output.init(memory);
    const writer = &out.writer;
    try put(writer, xml_header);
    const count = packages.len;
    switch (kind) {
        .primary => try print(
            writer,
            "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" " ++
                "xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{d}\">\n",
            .{count},
        ),
        .filelists => try print(
            writer,
            "<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" " ++
                "packages=\"{d}\">\n",
            .{count},
        ),
        .other => try print(writer, "<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" " ++
            "packages=\"{d}\">\n", .{count}),
    }
    for (packages) |built| {
        const pkgid = &model.digest_hex(built.bytes);
        switch (kind) {
            .primary => try package_xml(memory, writer, built, pkgid),
            .filelists => try filelists_xml(memory, writer, built, pkgid),
            .other => try other_xml(writer, built, pkgid),
        }
    }
    try put(writer, switch (kind) {
        .primary => "</metadata>",
        .filelists => "</filelists>",
        .other => "</otherdata>",
    });
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn built_less(_: void, left: model.Built, right: model.Built) bool {
    const by_name = std.mem.order(u8, left.package.name, right.package.name);
    if (by_name != .eq) return by_name == .lt;
    return std.mem.order(u8, left.package.version, right.package.version) == .lt;
}

/// `built.bytes` is the rpm `rpm.write` makes for `built.package` on `architecture`: it splits,
/// names a build host, and its main header is the one that package and build host give. The
/// signature header is not compared, since the caller may have placed a header signature there.
/// Anything else is `ForeignRpm`, a refusal: the bytes come from the caller.
fn check_built(
    memory: Allocator,
    architecture: model.Architecture,
    built: model.Built,
) Error!void {
    if (built.package.architecture != architecture) return error.ForeignRpm;
    const parts = rpm.split(built.bytes) orelse return error.ForeignRpm;
    const build_host = rpm.build_host_of(parts.main_header) orelse return error.ForeignRpm;
    model.check_line(build_host) catch return error.ForeignRpm;
    const expected = try rpm.header_bytes(memory, built.package, build_host);
    if (!std.mem.eql(u8, expected, parts.main_header)) return error.ForeignRpm;
}

/// The tree of one architecture: paths are relative to `rpm/<basearch>/`. Every rpm must be one
/// `rpm.write` made for its package and `architecture`; any other bytes are `ForeignRpm`.
pub fn write(
    memory: Allocator,
    architecture: model.Architecture,
    built: []const model.Built,
) Error![]model.TreeFile {
    if (built.len == 0 or built.len > constants.repo_packages_max) return error.TooManyFiles;
    for (built) |item| try check_built(memory, architecture, item);
    const sorted = try memory.dupe(model.Built, built);
    std.mem.sort(model.Built, sorted, {}, built_less);
    var files: std.ArrayList(model.TreeFile) = .empty;
    var repomd = Output.init(memory);
    try put(&repomd.writer, xml_header ++
        "<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" " ++
        "xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n");
    try print(
        &repomd.writer,
        "  <revision>{d}</revision>\n",
        .{constants.package_source_date_epoch},
    );
    for (sorted) |item| {
        assert(item.package.architecture == architecture); // `check_built` refused the others.
        try files.append(
            memory,
            .{ .path = try rpm.file_name(memory, item.package), .bytes = item.bytes },
        );
    }
    for ([_]Document{ .primary, .filelists, .other }) |kind| {
        const plain = try document(memory, kind, sorted);
        const gzipped = try archive.gzip(memory, plain);
        const sum = try memory.dupe(u8, &model.digest_hex(gzipped));
        const href = try std.fmt.allocPrint(
            memory,
            "repodata/{s}-{s}.xml.gz",
            .{ sum, @tagName(kind) },
        );
        try files.append(memory, .{ .path = href, .bytes = gzipped });
        try print(&repomd.writer, "  <data type=\"{s}\">\n", .{@tagName(kind)});
        try print(&repomd.writer, "    <checksum type=\"sha256\">{s}</checksum>\n", .{sum});
        try print(
            &repomd.writer,
            "    <open-checksum type=\"sha256\">{s}</open-checksum>\n",
            .{&model.digest_hex(plain)},
        );
        try print(&repomd.writer, "    <location href=\"{s}\"/>\n", .{href});
        try print(
            &repomd.writer,
            "    <timestamp>{d}</timestamp>\n",
            .{constants.package_source_date_epoch},
        );
        try print(
            &repomd.writer,
            "    <size>{d}</size>\n    <open-size>{d}</open-size>\n  </data>\n",
            .{ gzipped.len, plain.len },
        );
    }
    try put(&repomd.writer, "</repomd>\n");
    try files.append(
        memory,
        .{ .path = "repodata/repomd.xml", .bytes = try repomd.toOwnedSlice() },
    );
    assert(files.items.len <= constants.repo_files_max);
    return files.items;
}

test "the tree has the rpm, three checksum-named metadata files and repomd.xml" {
    // Goal: layout, and every sum in repomd.xml equals the placed bytes.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const sample = &@import("deb.zig").sample;
    const bytes = try rpm.write(memory, sample, .{ .build_host = "zigbox-build" });
    const built = [_]model.Built{.{ .package = sample, .bytes = bytes }};
    const files = try write(memory, .x86_64, &built);
    try std.testing.expectEqual(@as(usize, 5), files.len);
    try std.testing.expectEqualStrings("sample-1.2.3-1.x86_64.rpm", files[0].path);
    const repomd = files[4].bytes;
    for (files[1..4]) |file| {
        const sum = &model.digest_hex(file.bytes);
        try std.testing.expect(std.mem.indexOf(u8, repomd, sum) != null);
        try std.testing.expect(std.mem.indexOf(u8, file.path, sum) != null);
    }
}

test "bytes rpm.write did not make for the package are refused, not trusted" {
    // Goal: `dnf.write` takes its rpms from the caller, so foreign bytes are a refusal
    // (`ForeignRpm`), never a panic or a tree that describes other bytes. Method: empty bytes,
    // a deb, a cut rpm, one flipped byte in the main header, another package's rpm, an rpm of
    // the other architecture; then an rpm whose signature header changed (as a placed header
    // signature changes it) is still accepted.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const sample = &@import("deb.zig").sample;
    const good = try rpm.write(memory, sample, .{ .build_host = "zigbox-build" });
    const parts = rpm.split(good).?;

    var other = sample.*;
    other.version = "1.2.4";
    var aarch64 = sample.*;
    aarch64.architecture = .aarch64;
    const flipped = try memory.dupe(u8, good);
    flipped[parts.header_start + parts.main_header.len / 2] ^= 0x20;
    const foreign = [_][]const u8{
        "",
        try @import("deb.zig").write(memory, sample),
        good[0 .. parts.header_end - 1],
        flipped,
        try rpm.write(memory, &other, .{ .build_host = "zigbox-build" }),
    };
    for (foreign) |bytes| {
        const built = [_]model.Built{.{ .package = sample, .bytes = bytes }};
        try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &built));
    }
    const elsewhere = try rpm.write(memory, &aarch64, .{ .build_host = "zigbox-build" });
    const wrong_tree = [_]model.Built{.{ .package = &aarch64, .bytes = elsewhere }};
    try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &wrong_tree));

    const resigned = try memory.dupe(u8, good);
    resigned[parts.header_start - 1] ^= 0x01; // Padding or data of the signature header.
    const accepted = [_]model.Built{.{ .package = sample, .bytes = resigned }};
    _ = try write(memory, .x86_64, &accepted);
}
