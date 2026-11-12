//! The release assets that are not packages: one tarball of `zbx` per architecture, the
//! `SHA256SUMS` over every asset, and a CycloneDX 1.5 software bill of materials. Pure: bytes in,
//! bytes out, and the same inputs give the same bytes (the tarball has fixed times, owners and
//! order, and gzip writes no time). `release_assets_main.zig` does the I/O.
//! See docs/releases/packaging.md, "Release assets".

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const constants = @import("constants.zig");
const model = @import("package/model.zig");
const archive = @import("package/archive.zig");

pub const Error = error{
    OutOfMemory,
    WriteFailed,
    /// A version, name, toolchain version or licence id has a byte outside `[A-Za-z0-9._+-]`.
    BadName,
    /// An asset is not a plain file name `SHA256SUMS` can carry, or two share a name.
    BadAsset,
    TooManyAssets,
    FileTooLarge,
    BadTime,
};

pub fn describe(err: Error) []const u8 {
    return switch (err) {
        error.OutOfMemory => "out of memory",
        error.WriteFailed => "an output buffer could not grow",
        error.BadName => "a version, toolchain version or licence id has an unusable byte",
        error.BadAsset => "an asset name is not a plain file name, or two assets share one",
        error.TooManyAssets => "more assets than the bound allows",
        error.FileTooLarge => "a file is larger than the bound allows",
        error.BadTime => "the source date is out of range",
    };
}

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn name(self: Architecture) []const u8 {
        return @tagName(self);
    }
};

pub const architectures = [_]Architecture{ .x86_64, .aarch64 };

pub const Inputs = struct {
    version: []const u8,
    /// The release `zbx` of each architecture, in `architectures` order.
    zbx: [architectures.len][]const u8,
    license: []const u8,
    /// The SPDX identifier of `license`, as written in the SBOM.
    license_id: []const u8,
    /// The Zig version that built the binaries (`zig version`).
    zig_version: []const u8,
    /// Seconds since the epoch for every tar entry and for the SBOM's timestamp.
    source_date_epoch: u64,
};

fn name_ok(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text.len > constants.package_name_bytes_max) return false;
    for (text) |byte| {
        const plain = std.ascii.isAlphanumeric(byte);
        if (!plain and byte != '.' and byte != '_' and byte != '+' and byte != '-') return false;
    }
    return true;
}

fn validate(inputs: *const Inputs) Error!void {
    if (!name_ok(inputs.version)) return error.BadName;
    if (!name_ok(inputs.zig_version)) return error.BadName;
    if (!name_ok(inputs.license_id)) return error.BadName;
    if (inputs.source_date_epoch < constants.apt_signed_at_min) return error.BadTime;
    if (inputs.source_date_epoch > constants.apt_signed_at_max) return error.BadTime;
    for (inputs.zbx) |bytes| {
        if (bytes.len > constants.package_file_bytes_max) return error.FileTooLarge;
    }
    if (inputs.license.len > constants.package_description_bytes_max) return error.FileTooLarge;
}

pub fn tarball_name(memory: Allocator, version: []const u8, index: usize) Error![]u8 {
    return std.fmt.allocPrint(memory, "zbx-{s}-linux-{s}.tar.gz", .{
        version, architectures[index].name(),
    }) catch return error.OutOfMemory;
}

pub fn sbom_name(memory: Allocator, version: []const u8) Error![]u8 {
    return std.fmt.allocPrint(memory, "zbx-{s}.cdx.json", .{version}) catch
        return error.OutOfMemory;
}

fn readme_text(memory: Allocator, inputs: *const Inputs, index: usize) Error![]u8 {
    return std.fmt.allocPrint(
        memory,
        "zbx {s} for linux-{s}\n\n" ++
            "zbx is a rootless, daemonless Linux container runtime, image store and builder.\n" ++
            "The binary is static and needs no libc; put it anywhere on your PATH.\n\n" ++
            "  ./zbx doctor     checks what this machine can do and says how to fix the rest\n\n" ++
            "Verify this file against SHA256SUMS (and SHA256SUMS.asc, signed by the Zigbox\n" ++
            "release key; see https://zigbox.org). The licence is in LICENSE.\n" ++
            "https://zigbox.org\n",
        .{ inputs.version, architectures[index].name() },
    ) catch return error.OutOfMemory;
}

/// One ustar entry, always owned by root with the fixed time. A tar that sorts and stamps its
/// entries itself is the whole reproducibility story here.
fn tar_entry(
    writer: *std.Io.Writer,
    path: []const u8,
    mode: u32,
    bytes: []const u8,
    epoch: u64,
    directory: bool,
) Error!void {
    var header = std.tar.Writer.Header.init(if (directory) .directory else .regular);
    // The defaults are octal digits ('0000664'); a short number would leave them in place.
    @memset(&header.mode, '0');
    header.setPath("", path) catch return error.BadAsset;
    header.setMode(mode) catch return error.BadAsset;
    header.setSize(bytes.len) catch return error.FileTooLarge;
    header.setMtime(epoch) catch return error.BadTime;
    @memcpy(header.uname[0..4], "root");
    @memcpy(header.gname[0..4], "root");
    if (directory) assert(bytes.len == 0);
    header.write(writer) catch return error.WriteFailed;
    writer.writeAll(bytes) catch return error.WriteFailed;
    const tail = bytes.len % 512;
    if (tail != 0) writer.splatByteAll(0, 512 - tail) catch return error.WriteFailed;
}

/// `zbx-<v>-linux-<arch>.tar.gz`: a directory of the same name holding `zbx`, `LICENSE` and
/// `README.txt`, in that order.
pub fn tarball(memory: Allocator, inputs: *const Inputs, index: usize) Error![]u8 {
    try validate(inputs);
    assert(index < architectures.len);
    const directory = try std.fmt.allocPrint(memory, "zbx-{s}-linux-{s}", .{
        inputs.version, architectures[index].name(),
    });
    var out: std.Io.Writer.Allocating = .init(memory);
    const writer = &out.writer;
    const epoch = inputs.source_date_epoch;
    const dir_path = try std.fmt.allocPrint(memory, "{s}/", .{directory});
    try tar_entry(writer, dir_path, 0o755, "", epoch, true);
    const members = [_]struct { []const u8, u32, []const u8 }{
        .{ "zbx", 0o755, inputs.zbx[index] },
        .{ "LICENSE", 0o644, inputs.license },
        .{ "README.txt", 0o644, try readme_text(memory, inputs, index) },
    };
    for (members) |member| {
        const path = try std.fmt.allocPrint(memory, "{s}/{s}", .{ directory, member[0] });
        try tar_entry(writer, path, member[1], member[2], epoch, false);
    }
    writer.splatByteAll(0, 1024) catch return error.WriteFailed;
    const tar_bytes = out.toOwnedSlice() catch return error.OutOfMemory;
    return archive.gzip(memory, tar_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.WriteFailed,
    };
}

pub const Asset = struct { name: []const u8, bytes: []const u8 };

fn asset_less(_: void, left: Asset, right: Asset) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

/// The text of `SHA256SUMS`: `<hex>  <name>` per asset in byte order of name, the format
/// `sha256sum -c` reads. `assets` is sorted in place.
pub fn sums(memory: Allocator, assets: []Asset) Error![]u8 {
    if (assets.len > constants.release_assets_max) return error.TooManyAssets;
    std.mem.sort(Asset, assets, {}, asset_less);
    var out: std.Io.Writer.Allocating = .init(memory);
    for (assets, 0..) |asset, index| {
        if (!name_ok(asset.name)) return error.BadAsset;
        if (std.mem.startsWith(u8, asset.name, "SHA256SUMS")) return error.BadAsset;
        if (index > 0) {
            if (std.mem.eql(u8, assets[index - 1].name, asset.name)) return error.BadAsset;
        }
        out.writer.print("{s}  {s}\n", .{ &model.digest_hex(asset.bytes), asset.name }) catch
            return error.WriteFailed;
    }
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// A CycloneDX 1.5 BOM of the release: `zbx` with one file component (and its SHA-256) per
/// binary, the Zig toolchain as the build tool, and an explicit statement that there are no
/// dependencies. Every interpolated value passed `name_ok`, so none needs JSON escaping.
pub fn sbom(memory: Allocator, inputs: *const Inputs) Error![]u8 {
    try validate(inputs);
    const calendar = model.Calendar.from_epoch(inputs.source_date_epoch);
    var out: std.Io.Writer.Allocating = .init(memory);
    const writer = &out.writer;
    writer.print(
        \\{{
        \\  "bomFormat": "CycloneDX",
        \\  "specVersion": "1.5",
        \\  "version": 1,
        \\  "metadata": {{
        \\    "timestamp": "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        \\    "tools": {{
        \\      "components": [
        \\        {{ "type": "application", "name": "zig", "version": "{s}", "supplier": {{ "name": "Zig Software Foundation", "url": ["https://ziglang.org"] }} }}
        \\      ]
        \\    }},
        \\    "component": {{
        \\      "type": "application",
        \\      "bom-ref": "zbx",
        \\      "name": "zbx",
        \\      "version": "{s}",
        \\      "description": "Rootless, daemonless Linux container runtime, image store and builder",
        \\      "licenses": [ {{ "license": {{ "id": "{s}" }} }} ],
        \\      "purl": "pkg:github/zigbox/zigbox@v{s}",
        \\      "externalReferences": [ {{ "type": "website", "url": "https://zigbox.org" }}, {{ "type": "vcs", "url": "https://github.com/Zigbox/zigbox" }} ]
        \\    }},
        \\    "properties": [
        \\      {{ "name": "zigbox:dependencies", "value": "none: standard library only, no libc, no third-party components" }}
        \\    ]
        \\  }},
        \\  "components": [
        \\
    , .{
        calendar.year,
        calendar.month,
        calendar.day,
        calendar.seconds_of_day / 3600,
        calendar.seconds_of_day % 3600 / 60,
        calendar.seconds_of_day % 60,
        inputs.zig_version,
        inputs.version,
        inputs.license_id,
        inputs.version,
    }) catch return error.WriteFailed;
    for (architectures, 0..) |architecture, index| {
        const separator: []const u8 = if (index + 1 < architectures.len) "," else "";
        writer.print(
            \\    {{
            \\      "type": "file",
            \\      "bom-ref": "zbx-linux-{s}",
            \\      "name": "zbx",
            \\      "version": "{s}",
            \\      "description": "static ReleaseSafe binary for linux-{s}",
            \\      "hashes": [ {{ "alg": "SHA-256", "content": "{s}" }} ]
            \\    }}{s}
            \\
        , .{
            architecture.name(),
            inputs.version,
            architecture.name(),
            &model.digest_hex(inputs.zbx[index]),
            separator,
        }) catch return error.WriteFailed;
    }
    writer.writeAll(
        \\  ],
        \\  "dependencies": [
        \\    { "ref": "zbx", "dependsOn": [] },
        \\    { "ref": "zbx-linux-x86_64", "dependsOn": [] },
        \\    { "ref": "zbx-linux-aarch64", "dependsOn": [] }
        \\  ],
        \\  "compositions": [
        \\    { "aggregate": "complete", "assemblies": ["zbx-linux-x86_64", "zbx-linux-aarch64"], "dependencies": ["zbx"] }
        \\  ]
        \\}
        \\
    ) catch return error.WriteFailed;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

const sample: Inputs = .{
    .version = "1.2.3",
    .zbx = .{ "x86 binary", "arm binary" },
    .license = "MIT License\n",
    .license_id = "MIT",
    .zig_version = "0.17.0",
    .source_date_epoch = 1_794_148_734,
};

test "tarball and sbom give the same bytes twice, and the tarball holds the four entries" {
    // Goal: reproducibility (same inputs, same bytes) and layout; gunzip and read the tar back.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    for (0..architectures.len) |index| {
        const first = try tarball(memory, &sample, index);
        const second = try tarball(memory, &sample, index);
        try std.testing.expectEqualSlices(u8, first, second);
        // gzip header: magic, deflate, no flags, and a zero time (bytes 4..8).
        try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0 }, first[0..8]);
        var input: std.Io.Reader = .fixed(first);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);
        var tar_bytes: std.Io.Writer.Allocating = .init(memory);
        _ = try decompress.reader.streamRemaining(&tar_bytes.writer);
        // The first header: mtime (octal, bytes 136..147) is the fixed epoch, the owner is root.
        const head = tar_bytes.written()[0..512];
        const mtime = try std.fmt.parseInt(u64, std.mem.trimEnd(u8, head[136..147], &.{0}), 8);
        try std.testing.expectEqual(sample.source_date_epoch, mtime);
        try std.testing.expectEqualStrings("root", std.mem.sliceTo(head[265..297], 0));
        var reader: std.Io.Reader = .fixed(tar_bytes.written());
        var names_buffer: [std.fs.max_path_bytes]u8 = undefined;
        var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
        var iterator: std.tar.Iterator = .init(&reader, .{
            .file_name_buffer = &names_buffer,
            .link_name_buffer = &link_buffer,
        });
        const expected = [_][]const u8{ "", "/zbx", "/LICENSE", "/README.txt" };
        var seen: usize = 0;
        while (try iterator.next()) |entry| : (seen += 1) {
            const prefix = try std.fmt.allocPrint(memory, "zbx-1.2.3-linux-{s}", .{
                architectures[index].name(),
            });
            const want = try std.fmt.allocPrint(memory, "{s}{s}", .{ prefix, expected[seen] });
            try std.testing.expectEqualStrings(want, std.mem.trimEnd(u8, entry.name, "/"));
        }
        try std.testing.expectEqual(@as(usize, 4), seen);
    }
    const one = try sbom(memory, &sample);
    try std.testing.expectEqualSlices(u8, one, try sbom(memory, &sample));
}

test "the sbom is valid JSON that says what is in the build and that nothing else is" {
    // Goal: the document parses; has the version, purl, licence, both hashes and the toolchain;
    // lists no component besides zbx's two binaries; states there are no dependencies.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    const text = try sbom(memory, &sample);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, memory, text, .{});
    const root = parsed.object;
    try std.testing.expectEqualStrings("CycloneDX", root.get("bomFormat").?.string);
    try std.testing.expectEqualStrings("1.5", root.get("specVersion").?.string);
    const main = root.get("metadata").?.object.get("component").?.object;
    try std.testing.expectEqualStrings("pkg:github/zigbox/zigbox@v1.2.3", main.get("purl").?.string);
    try std.testing.expectEqualStrings("1.2.3", main.get("version").?.string);
    const id = main.get("licenses").?.array.items[0].object.get("license").?.object.get("id");
    try std.testing.expectEqualStrings("MIT", id.?.string);
    const tools = root.get("metadata").?.object.get("tools").?.object.get("components").?;
    try std.testing.expectEqualStrings("0.17.0", tools.array.items[0].object.get("version").?.string);
    const components = root.get("components").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), components.len);
    for (components, 0..) |component, index| {
        const hash = component.object.get("hashes").?.array.items[0].object;
        try std.testing.expectEqualStrings("SHA-256", hash.get("alg").?.string);
        const want = model.digest_hex(sample.zbx[index]);
        try std.testing.expectEqualStrings(&want, hash.get("content").?.string);
    }
    for (root.get("dependencies").?.array.items) |dependency| {
        try std.testing.expectEqual(@as(usize, 0), dependency.object.get("dependsOn").?.array.items.len);
    }
    try std.testing.expect(std.mem.indexOf(u8, text, "no third-party components") != null);
}

test "sums sorts by name, matches sha256sum's format, and refuses bad or repeated names" {
    // Goal: the text is exactly what `sha256sum -c` reads; negative space of every refusal.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    var assets = [_]Asset{
        .{ .name = "b.tar.gz", .bytes = "b" },
        .{ .name = "a.deb", .bytes = "" },
    };
    const empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const text = try sums(memory, &assets);
    const b_digest = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";
    const want = empty_digest ++ "  a.deb\n" ++ b_digest ++ "  b.tar.gz\n";
    try std.testing.expectEqualStrings(want, text);
    var spaced = [_]Asset{.{ .name = "a b", .bytes = "" }};
    try std.testing.expectError(error.BadAsset, sums(memory, &spaced));
    var self_reference = [_]Asset{.{ .name = "SHA256SUMS.asc", .bytes = "" }};
    try std.testing.expectError(error.BadAsset, sums(memory, &self_reference));
    var twice = [_]Asset{ .{ .name = "a", .bytes = "" }, .{ .name = "a", .bytes = "x" } };
    try std.testing.expectError(error.BadAsset, sums(memory, &twice));
}

test "a bad version, toolchain, licence id or date is refused" {
    // Goal: every interpolated value is checked before it reaches the SBOM or a path.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const memory = arena.allocator();
    var bad = sample;
    bad.version = "1.2/3";
    try std.testing.expectError(error.BadName, tarball(memory, &bad, 0));
    bad = sample;
    bad.zig_version = "0.17 0";
    try std.testing.expectError(error.BadName, sbom(memory, &bad));
    bad = sample;
    bad.license_id = "";
    try std.testing.expectError(error.BadName, sbom(memory, &bad));
    bad = sample;
    bad.source_date_epoch = constants.apt_signed_at_max + 1;
    try std.testing.expectError(error.BadTime, sbom(memory, &bad));
}
