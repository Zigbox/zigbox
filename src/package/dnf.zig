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

/// `built.bytes` is the rpm `rpm.write` makes for `built.package` on `architecture`, byte for
/// byte, with the build host its main header names and the header signature, if any, its
/// signature header carries (both are the caller's to choose). The rpm is written again with
/// those and compared whole, so a changed lead, header, digest or payload is caught, not only a
/// changed main header. Anything else is `ForeignRpm`, a refusal: the bytes come from the caller.
/// The rewrite runs in its own arena, freed on return, so a tree holds the intermediates (cpio,
/// gzip output, headers) of one rpm at a time, not of every rpm until the caller frees `memory`.
fn check_built(
    memory: Allocator,
    architecture: model.Architecture,
    built: model.Built,
) Error!void {
    if (built.package.architecture != architecture) return error.ForeignRpm;
    const parts = rpm.split(built.bytes) orelse return error.ForeignRpm;
    const build_host = rpm.build_host_of(parts.main_header) orelse return error.ForeignRpm;
    model.check_line(build_host) catch return error.ForeignRpm;
    const signature = rpm.binary_tag(parts.signature_header, rpm.sig_tag.rsa);
    if (signature) |bytes| {
        if (bytes.len > constants.openpgp_signature_bytes_max) return error.ForeignRpm;
    }
    const options: rpm.Options = .{ .build_host = build_host, .header_signature = signature };
    var rewrite: std.heap.ArenaAllocator = .init(memory);
    defer rewrite.deinit();
    const expected = try rpm.write(rewrite.allocator(), built.package, options);
    assert(expected.len > 0);
    if (!std.mem.eql(u8, expected, built.bytes)) return error.ForeignRpm;
}

/// The tree of one architecture: paths are relative to `rpm/<basearch>/`. Every rpm must be one
/// `rpm.write` made for its package and `architecture`; any other bytes are `ForeignRpm`. That is
/// this build's `rpm.write`: an rpm an earlier Zigbox made can differ (its payload compression or
/// a header field), so rpms kept across a Zigbox upgrade are refused; write them again.
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
    // a deb, a cut rpm, one flipped byte in each of the main header, the signature header, the
    // build host and the payload, another package's rpm, an rpm of the other architecture; then
    // an rpm carrying a header signature, as the caller places one, is accepted.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const sample = &@import("deb.zig").sample;
    const good = try rpm.write(memory, sample, .{ .build_host = "zigbox-build" });
    const parts = rpm.split(good).?;
    const host_at = std.mem.indexOf(u8, good, "zigbox-build").?;
    assert(host_at >= parts.header_start);

    var other = sample.*;
    other.version = "1.2.4";
    var aarch64 = sample.*;
    aarch64.architecture = .aarch64;
    const flips = [_]usize{
        parts.header_start + parts.main_header.len / 2,
        parts.header_start - 1,
        host_at + "zigbox".len, // "zigbox=build": a build host rpm.write would take.
        good.len - 1,
    };
    for (flips) |at| {
        const flipped = try memory.dupe(u8, good);
        flipped[at] ^= 0x10;
        const built = [_]model.Built{.{ .package = sample, .bytes = flipped }};
        try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &built));
    }
    const foreign = [_][]const u8{
        "",
        try @import("deb.zig").write(memory, sample),
        good[0 .. parts.header_end - 1],
        try rpm.write(memory, &other, .{ .build_host = "zigbox-build" }),
    };
    for (foreign) |bytes| {
        const built = [_]model.Built{.{ .package = sample, .bytes = bytes }};
        try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &built));
    }
    const elsewhere = try rpm.write(memory, &aarch64, .{ .build_host = "zigbox-build" });
    const wrong_tree = [_]model.Built{.{ .package = &aarch64, .bytes = elsewhere }};
    try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &wrong_tree));

    const signature: [120]u8 = @splat(0x88); // Opaque here: `check_tree` reads signatures.
    const signed = try rpm.write(
        memory,
        sample,
        .{ .build_host = "other-build", .header_signature = &signature },
    );
    const accepted = [_]model.Built{.{ .package = sample, .bytes = signed }};
    _ = try write(memory, .x86_64, &accepted);
}

test "a header signature of 1024 bytes is accepted, one of 1025 is refused, not a crash" {
    // Goal: the bound `rpm.write` asserts (`openpgp_signature_bytes_max`) is checked before the
    // rewrite, so a caller's rpm past it is `ForeignRpm`, not a panic. Method: an rpm with a
    // 1024-byte signature is accepted; the same rpm with its signature entry widened to 1025
    // bytes of the signature header's data is refused. Without the length check in
    // `check_built` this test panicked in `rpm.signature_header`.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const sample = &@import("deb.zig").sample;
    const signature: [constants.openpgp_signature_bytes_max]u8 = @splat(0x88);
    const options: rpm.Options = .{ .build_host = "zigbox-build", .header_signature = &signature };
    const good = try rpm.write(memory, sample, options);
    const at_bound = [_]model.Built{.{ .package = sample, .bytes = good }};
    _ = try write(memory, .x86_64, &at_bound);

    const wide = try memory.dupe(u8, good);
    const header = rpm.split(wide).?.signature_header;
    const entries = std.mem.readInt(u32, header[8..12], .big);
    const entry_at = for (0..entries) |index| {
        const at = 16 + index * 16;
        if (std.mem.readInt(u32, header[at..][0..4], .big) == rpm.sig_tag.rsa) break at;
    } else unreachable; // `rpm.write` placed the signature.
    const field_at = (header.ptr - wide.ptr) + entry_at;
    std.mem.writeInt(u32, wide[field_at + 8 ..][0..4], 0, .big);
    std.mem.writeInt(u32, wide[field_at + 12 ..][0..4], signature.len + 1, .big);
    const read = rpm.binary_tag(header, rpm.sig_tag.rsa).?;
    try std.testing.expectEqual(constants.openpgp_signature_bytes_max + 1, read.len);
    const past_bound = [_]model.Built{.{ .package = sample, .bytes = wide }};
    try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &past_bound));
}

test "a build host that rpm.write would refuse is ForeignRpm, not the writer's own error" {
    // Goal: `check_built` checks the build host as `rpm.write` does before rewriting, so a
    // damaged one is `ForeignRpm` as documented. Method: a control byte (0x01) in the build host
    // of a good rpm. Without the `check_line` guard this test got `rpm.write`'s own error.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const sample = &@import("deb.zig").sample;
    const good = try rpm.write(memory, sample, .{ .build_host = "zigbox-build" });
    const damaged = try memory.dupe(u8, good);
    const host_at = std.mem.indexOf(u8, damaged, "zigbox-build").?;
    damaged[host_at + "zigbox".len] = 0x01;
    const host = damaged[host_at..][0.."zigbox-build".len];
    try std.testing.expectError(error.BadText, model.check_line(host));
    const built = [_]model.Built{.{ .package = sample, .bytes = damaged }};
    try std.testing.expectError(error.ForeignRpm, write(memory, .x86_64, &built));
}
