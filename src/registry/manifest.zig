//! Image indexes and manifests, in the two families registries speak: the OCI image index and
//! manifest, and Docker's v2 manifest list and manifest. Everything here is a pure function from
//! the bytes of a body to a decision: which kind of document it is, which entry of an index is
//! this host's platform, what the layers of a manifest are. The network is `client.zig`'s.
//!
//! A media type is matched exactly, after cutting off any parameters, and an unknown one is
//! refused with its name: the older Docker schema 1, a Helm chart, a WebAssembly module, a layer
//! type this version cannot unpack. Nothing is guessed from the shape of the JSON. When a body
//! and the registry's Content-Type both name a type, they must agree.
//!
//! JSON is read with `std.json` into small typed structs with `ignore_unknown_fields`, in a
//! caller-owned arena of fixed size, so a hostile body can at worst fill the arena and be refused.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("digest.zig");
const text_util = @import("../text.zig");

const Sha256 = digest_mod.Sha256;

pub const media_oci_index = "application/vnd.oci.image.index.v1+json";
pub const media_oci_manifest = "application/vnd.oci.image.manifest.v1+json";
pub const media_docker_list = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const media_docker_manifest = "application/vnd.docker.distribution.manifest.v2+json";
const media_oci_config = "application/vnd.oci.image.config.v1+json";
const media_docker_config = "application/vnd.docker.container.image.v1+json";
const media_oci_layer_tar = "application/vnd.oci.image.layer.v1.tar";
const media_oci_layer_gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
const media_oci_layer_zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
const media_docker_layer = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The Accept header of a manifest request: every type this module reads, and no other.
pub const accept = media_oci_index ++ "," ++ media_oci_manifest ++ "," ++ media_docker_list ++
    "," ++ media_docker_manifest;

pub const MediaType = enum {
    oci_index,
    oci_manifest,
    docker_list,
    docker_manifest,

    pub fn is_index(media: MediaType) bool {
        const result = media == .oci_index or media == .docker_list;
        if (result) assert(@tagName(media).len > 0);
        assert(@backingInt(media) <= @backingInt(MediaType.docker_manifest));
        return result;
    }
};

/// The type named by `text` (a Content-Type value or a `mediaType` member), or null.
pub fn media_type_of(text: []const u8) ?MediaType {
    assert(text.len <= constants.registry_header_bytes_max * 4);
    const semicolon = std.mem.indexOfScalar(u8, text, ';');
    const bare = std.mem.trim(u8, if (semicolon) |at| text[0..at] else text, " \t");
    assert(bare.len <= text.len);
    if (std.ascii.eqlIgnoreCase(bare, media_oci_index)) return .oci_index;
    if (std.ascii.eqlIgnoreCase(bare, media_oci_manifest)) return .oci_manifest;
    if (std.ascii.eqlIgnoreCase(bare, media_docker_list)) return .docker_list;
    if (std.ascii.eqlIgnoreCase(bare, media_docker_manifest)) return .docker_manifest;
    return null;
}

pub const Architecture = enum {
    amd64,
    arm64,

    pub fn name(architecture: Architecture) []const u8 {
        const text = @tagName(architecture);
        assert(text.len > 0);
        assert(text.len < 8);
        return text;
    }
};

/// A platform as a person writes it, `linux/amd64` or `linux/arm64`; null for anything else.
pub fn architecture_of_platform(text: []const u8) ?Architecture {
    assert(text.len <= constants.arg_bytes_max);
    if (std.mem.eql(u8, text, "linux/amd64")) return .amd64;
    if (std.mem.eql(u8, text, "linux/arm64")) return .arm64;
    return null;
}

/// The platform of a machine as `uname` names it; null for one this build does not run on.
pub fn architecture_of_machine(machine: []const u8) ?Architecture {
    assert(machine.len < constants.uname_field_bytes);
    assert(std.mem.indexOfScalar(u8, machine, 0) == null);
    if (std.mem.eql(u8, machine, "x86_64")) return .amd64;
    if (std.mem.eql(u8, machine, "aarch64")) return .arm64;
    if (std.mem.eql(u8, machine, "arm64")) return .arm64;
    return null;
}

pub const LayerKind = enum { tar, tar_gzip, tar_zstd };

pub const Layer = struct {
    digest: Sha256,
    size: u64,
    kind: LayerKind,
};

/// What resolving a reference found: the image to pull.
pub const Resolved = struct {
    /// The digest of the index the reference named, when it named one.
    index_digest: ?Sha256,
    /// The digest of the manifest of this host's platform: what the lock file records.
    manifest_digest: Sha256,
    manifest_size: u64,
    config_digest: Sha256,
    config_size: u64,
    architecture: Architecture,
    layer_count: u32,
    layers: [constants.registry_layers_max]Layer,
};

/// Why a body was not accepted. The code that reports it is chosen by the client.
pub const ParseError = error{
    /// Not JSON, or JSON of the wrong shape (a number where a string belongs, a duplicate key).
    Malformed,
    /// More nesting or text than the arena holds.
    TooComplex,
    /// A media type this version does not read; the name is in the problem text.
    UnknownMediaType,
    /// The body and the registry name two different types.
    MediaTypeMismatch,
    TooManyEntries,
    TooManyLayers,
    /// A digest that is not `sha256:` and 64 lowercase hex digits, or a size of zero or beyond
    /// its bound.
    BadDescriptor,
};

/// The detail a refusal reports: a media type, a digest, or a count, as short text.
pub const Problem = struct {
    text: text_util.Bounded(120) = .{},
};

const PlatformJson = struct {
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
    variant: ?[]const u8 = null,
};

const DescriptorJson = struct {
    mediaType: ?[]const u8 = null,
    digest: ?[]const u8 = null,
    size: ?u64 = null,
    platform: ?PlatformJson = null,
};

const DocumentJson = struct {
    schemaVersion: ?i64 = null,
    mediaType: ?[]const u8 = null,
    manifests: ?[]const DescriptorJson = null,
    config: ?DescriptorJson = null,
    layers: ?[]const DescriptorJson = null,
};

/// A document read: which kind, and its entries or its config and layers, valid until the arena
/// is reused.
pub const Document = struct {
    media: MediaType,
    json: DocumentJson,
};

fn parse_json(arena: std.mem.Allocator, body: []const u8) ParseError!DocumentJson {
    assert(body.len <= constants.registry_manifest_bytes_max);
    assert(@intFromPtr(arena.vtable) != 0);
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    return std.json.parseFromSliceLeaky(DocumentJson, arena, body, options) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.TooComplex,
            else => error.Malformed,
        };
    };
}

/// Reads a body: decides its type from `mediaType` and the Content-Type, then checks it is the
/// shape of that type. `content_type` is the registry's header, null when it sent none.
pub fn parse_document(
    arena: std.mem.Allocator,
    body: []const u8,
    content_type: ?[]const u8,
    problem: *Problem,
) ParseError!Document {
    assert(body.len <= constants.registry_manifest_bytes_max);
    problem.* = .{}; // An entry point: whatever an earlier call said is not this call's.
    const json = try parse_json(arena, body);
    const media = try decide_media(json.mediaType, content_type, problem);
    if (json.schemaVersion) |version| {
        if (version != 2) {
            problem.text.print("schemaVersion {d}", .{version});
            return error.UnknownMediaType;
        }
    }
    if (media.is_index()) {
        const entries = json.manifests orelse return error.Malformed;
        if (entries.len > constants.registry_index_entries_max) return error.TooManyEntries;
    } else {
        if (json.config == null) return error.Malformed;
    }
    assert(problem.text.len == 0);
    return .{ .media = media, .json = json };
}

fn name_media(problem: *Problem, text: ?[]const u8) void {
    assert(problem.text.len == 0);
    const shown = text orelse "(none)";
    problem.text.append_sanitised(shown, 100);
    assert(problem.text.len > 0);
}

fn decide_media(
    declared: ?[]const u8,
    content_type: ?[]const u8,
    problem: *Problem,
) ParseError!MediaType {
    assert(problem.text.len == 0);
    const from_header: ?MediaType = if (content_type) |text| media_type_of(text) else null;
    if (declared) |text| {
        const from_body = media_type_of(text) orelse {
            name_media(problem, text);
            return error.UnknownMediaType;
        };
        if (from_header) |other| {
            if (other != from_body) {
                problem.text.print("{s} and {s}", .{ @tagName(from_body), @tagName(other) });
                return error.MediaTypeMismatch;
            }
        }
        return from_body;
    }
    if (from_header) |known| return known;
    name_media(problem, content_type);
    return error.UnknownMediaType;
}

/// An entry of an index chosen for this host.
pub const Selected = struct {
    digest: Sha256,
    size: u64,
};

/// The platforms an index offers, for a refusal: the first few, and how many there were.
pub const Offered = struct {
    labels: [constants.registry_platforms_listed_max][32]u8 = undefined,
    label_lens: [constants.registry_platforms_listed_max]u8 = undefined,
    listed: u32 = 0,
    total: u32 = 0,

    pub fn label(offered: *const Offered, index: u32) []const u8 {
        assert(index < offered.listed);
        assert(offered.listed <= offered.total);
        return offered.labels[index][0..offered.label_lens[index]];
    }

    fn add(offered: *Offered, os: []const u8, architecture: []const u8, variant: ?[]const u8) void {
        assert(offered.listed <= offered.labels.len);
        assert(offered.total < std.math.maxInt(u32));
        offered.total += 1;
        if (offered.listed == offered.labels.len) return;
        var storage: [32]u8 = undefined;
        var writer = std.Io.Writer.fixed(&storage);
        // A label is cut to the storage: a long one is only for display.
        writer.print("{s}/{s}", .{ os, architecture }) catch {};
        if (variant) |text| writer.print("/{s}", .{text}) catch {};
        var shown: [32]u8 = undefined;
        const clean = text_util.sanitise(&shown, writer.buffered());
        @memcpy(offered.labels[offered.listed][0..clean.len], clean);
        offered.label_lens[offered.listed] = @intCast(clean.len);
        offered.listed += 1;
    }
};

fn platform_matches(wanted: Architecture, entry: DescriptorJson) bool {
    assert(wanted.name().len > 0);
    const platform = entry.platform orelse return false;

    const os = platform.os orelse return false;
    const architecture = platform.architecture orelse return false;
    if (!std.mem.eql(u8, os, "linux")) return false;
    if (!std.mem.eql(u8, architecture, wanted.name())) return false;
    const variant = platform.variant orelse return true;
    return switch (wanted) {
        .arm64 => std.mem.eql(u8, variant, "v8"),
        .amd64 => std.mem.eql(u8, variant, "v1"),
    };
}

/// Finds this host's entry in an index. Null means none matches, and `offered` lists what the
/// index has. A matching entry of a type that is not a manifest, or with a bad descriptor, is
/// refused rather than skipped: the index says this is the image, and it cannot be used.
pub fn select_platform(
    document: *const Document,
    wanted: Architecture,
    offered: *Offered,
    problem: *Problem,
) ParseError!?Selected {
    assert(document.media.is_index());
    problem.* = .{};
    const entries = document.json.manifests.?;
    assert(entries.len <= constants.registry_index_entries_max);
    var found: ?Selected = null;
    for (entries) |entry| {
        const platform = entry.platform orelse continue;
        const os = platform.os orelse "?";
        const architecture = platform.architecture orelse "?";
        if (std.mem.eql(u8, os, "unknown")) continue; // Attestations and other non-images.
        offered.add(os, architecture, platform.variant);
        if (found != null) continue;
        if (!platform_matches(wanted, entry)) continue;
        const media_text = entry.mediaType orelse "(none)";
        const media = media_type_of(media_text) orelse {
            name_media(problem, media_text);
            return error.UnknownMediaType;
        };
        if (media.is_index()) {
            name_media(problem, media_text);
            return error.UnknownMediaType;
        }
        const digest = try descriptor_digest(entry, problem);
        const size = entry.size orelse return error.BadDescriptor;
        if (size == 0 or size > constants.registry_manifest_bytes_max) {
            problem.text.print("size {d}", .{size});
            return error.BadDescriptor;
        }
        found = .{ .digest = digest, .size = size };
    }
    assert(offered.listed <= offered.total);
    if (found) |selected| assert(selected.size > 0);
    return found;
}

/// What `select_platform_or` chose: the entry, and the architecture it is for.
pub const Picked = struct {
    selected: Selected,
    architecture: Architecture,
};

/// `select_platform` for `wanted`; when the index has none and `fallback` is another platform
/// (the machine can run it through a translator), the entry for that. `offered` lists the index
/// once, whichever was chosen.
pub fn select_platform_or(
    document: *const Document,
    wanted: Architecture,
    fallback: ?Architecture,
    offered: *Offered,
    problem: *Problem,
) ParseError!?Picked {
    if (try select_platform(document, wanted, offered, problem)) |selected| {
        return .{ .selected = selected, .architecture = wanted };
    }
    const other = fallback orelse return null;
    if (other == wanted) return null;
    var scratch: Offered = .{}; // The same entries again: the first list is the one reported.
    const selected = (try select_platform(document, other, &scratch, problem)) orelse return null;
    assert(scratch.total == offered.total);
    return .{ .selected = selected, .architecture = other };
}

fn descriptor_digest(descriptor: DescriptorJson, problem: *Problem) ParseError!Sha256 {
    assert(problem.text.len == 0);
    const text = descriptor.digest orelse {
        problem.text.print("a descriptor has no digest", .{});
        return error.BadDescriptor;
    };
    return Sha256.parse(text) orelse {
        problem.text.append_sanitised(text, 100);
        return error.BadDescriptor;
    };
}

fn layer_kind_of(text: []const u8) ?LayerKind {
    assert(text.len <= constants.registry_header_bytes_max * 4);
    assert(media_docker_layer.len > media_oci_layer_tar.len);
    if (std.mem.eql(u8, text, media_oci_layer_tar)) return .tar;
    if (std.mem.eql(u8, text, media_oci_layer_gzip)) return .tar_gzip;
    if (std.mem.eql(u8, text, media_docker_layer)) return .tar_gzip;
    if (std.mem.eql(u8, text, media_oci_layer_zstd)) return .tar_zstd;
    return null;
}

fn is_config_type(text: []const u8) bool {
    assert(text.len <= constants.registry_header_bytes_max * 4);
    assert(!std.mem.eql(u8, media_oci_config, media_docker_config));
    return std.mem.eql(u8, text, media_oci_config) or std.mem.eql(u8, text, media_docker_config);
}

/// Fills `resolved` from an image manifest: the config and every layer, each with a known type, a
/// sha256 digest and a size. The caller sets `index_digest`, `manifest_digest`, `manifest_size`
/// and `architecture`.
pub fn read_manifest(
    document: *const Document,
    resolved: *Resolved,
    problem: *Problem,
) ParseError!void {
    assert(!document.media.is_index());
    problem.* = .{};
    const config = document.json.config.?;

    const config_media = config.mediaType orelse "(none)";
    if (!is_config_type(config_media)) {
        name_media(problem, config_media);
        return error.UnknownMediaType;
    }
    resolved.config_digest = try descriptor_digest(config, problem);
    resolved.config_size = config.size orelse return error.BadDescriptor;
    if (resolved.config_size == 0) return error.BadDescriptor;
    if (resolved.config_size > constants.registry_manifest_bytes_max) return error.BadDescriptor;
    const layers = document.json.layers orelse &.{};
    if (layers.len > constants.registry_layers_max) {
        problem.text.print("{d} layers", .{layers.len});
        return error.TooManyLayers;
    }
    for (layers, 0..) |layer, index| {
        const media = layer.mediaType orelse "(none)";
        const kind = layer_kind_of(media) orelse {
            name_media(problem, media);
            return error.UnknownMediaType;
        };
        const size = layer.size orelse return error.BadDescriptor;
        if (size == 0) return error.BadDescriptor;
        resolved.layers[index] = .{
            .digest = try descriptor_digest(layer, problem),
            .size = size,
            .kind = kind,
        };
    }
    resolved.layer_count = @intCast(layers.len);
    assert(resolved.layer_count <= constants.registry_layers_max);
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const repeat = @import("../test_util.zig").repeat;
const comptime_print = std.fmt.comptimePrint;

const zero = "sha256:" ++ repeat('0', 64);
const one = "sha256:" ++ repeat('1', 64);

/// `{"mediaType":..,"digest":..,"size":..}`, the shape of a config, a layer and an index entry.
fn describe(
    comptime media: []const u8,
    comptime digest: []const u8,
    comptime size: u64,
) []const u8 {
    const format = "{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}";
    return comptime_print(format, .{ media, digest, size });
}

/// An index entry: a manifest descriptor with a platform.
fn entry_of(
    comptime digest: []const u8,
    comptime size: u64,
    comptime architecture: []const u8,
    comptime os: []const u8,
    comptime variant: []const u8,
) []const u8 {
    const platform = comptime_print(
        ",\"platform\":{{\"architecture\":\"{s}\",\"os\":\"{s}\"{s}}}}}",
        .{ architecture, os, variant },
    );
    return describe(media_oci_manifest, digest, size) ++ platform;
}

const variant_v7 = ",\"variant\":\"v7\"";
const variant_v8 = ",\"variant\":\"v8\"";

const index_prefix = "{\"schemaVersion\":2,\"manifests\":[";

/// Parses; the arena goes away with the call, so a test reads only the verdict and the type.
fn parse_with(body: []const u8, content_type: ?[]const u8, problem: *Problem) !Document {
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    return parse_document(fixed.allocator(), body, content_type, problem);
}

test "media types are matched exactly, with parameters cut" {
    // Goal: the four types are known in any letter case with a charset; near misses are not.
    try testing.expectEqual(MediaType.oci_index, media_type_of(media_oci_index).?);
    try testing.expectEqual(MediaType.docker_list, media_type_of(media_docker_list).?);
    const with_parameter = media_oci_manifest ++ "; charset=utf-8";
    try testing.expectEqual(MediaType.oci_manifest, media_type_of(with_parameter).?);
    const padded = " " ++ media_docker_manifest;
    try testing.expectEqual(MediaType.docker_manifest, media_type_of(padded).?);
    const schema_one = "application/vnd.docker.distribution.manifest.v1+prettyjws";
    try testing.expect(media_type_of("application/json") == null);
    try testing.expect(media_type_of(media_oci_index ++ "x") == null);
    try testing.expect(media_type_of(schema_one) == null);
    try testing.expect(media_type_of("") == null);
}

test "the declared type and the header must agree, and one must exist" {
    // Goal: each way to decide the type, and the refusals with their problem text.
    var problem: Problem = .{};
    const typed = "{\"schemaVersion\":2,\"mediaType\":\"" ++ media_oci_index ++ "\",";
    const index_body = typed ++ "\"manifests\":[]}";
    const document = try parse_with(index_body, null, &problem);
    try testing.expectEqual(MediaType.oci_index, document.media);
    _ = try parse_with(index_body, media_oci_index, &problem);
    _ = try parse_with(index_body, "application/json", &problem);
    const clash = parse_with(index_body, media_docker_list, &problem);
    try testing.expectError(error.MediaTypeMismatch, clash);

    const bare = "{\"schemaVersion\":2,\"manifests\":[]}";
    _ = try parse_with(bare, media_oci_index, &problem);
    problem = .{};
    try testing.expectError(error.UnknownMediaType, parse_with(bare, "text/plain", &problem));
    try testing.expectEqualStrings("text/plain", problem.text.slice());
    problem = .{};
    try testing.expectError(error.UnknownMediaType, parse_with(bare, null, &problem));
    try testing.expectEqualStrings("(none)", problem.text.slice());
    problem = .{};
    const unknown = "{\"mediaType\":\"application/vnd.example+json\",\"manifests\":[]}";
    const refused = parse_with(unknown, media_oci_index, &problem);
    try testing.expectError(error.UnknownMediaType, refused);
    try testing.expectEqualStrings("application/vnd.example+json", problem.text.slice());
    problem = .{};
    const old_head = "{\"schemaVersion\":1,\"mediaType\":\"" ++ media_docker_manifest;
    const old = old_head ++ "\",\"config\":{}}";
    try testing.expectError(error.UnknownMediaType, parse_with(old, null, &problem));
    try testing.expectEqualStrings("schemaVersion 1", problem.text.slice());
}

test "bodies that are not documents" {
    // Goal: JSON of the wrong shape, duplicate keys, a document of the wrong kind, and more
    // entries than the arena holds are refused with a reason, not a crash.
    var problem: Problem = .{};
    const kinds = [_][]const u8{ "not json", "[]", "{\"manifests\":5}", "{}" };
    for (kinds) |body| {
        try testing.expectError(error.Malformed, parse_with(body, media_oci_index, &problem));
    }
    const twice = "{\"manifests\":[],\"manifests\":[]}";
    try testing.expectError(error.Malformed, parse_with(twice, media_oci_index, &problem));
    const layers_only = "{\"layers\":[]}";
    try testing.expectError(error.Malformed, parse_with(layers_only, media_oci_manifest, &problem));
    // Many small entries need more memory than the arena has: refused as too complex.
    var many: [100_000]u8 = undefined;
    var writer = std.Io.Writer.fixed(&many);
    try writer.writeAll("{\"manifests\":[{}");
    for (0..20_000) |_| try writer.writeAll(",{}");
    try writer.writeAll("]}");
    const crowded = parse_with(writer.buffered(), media_oci_index, &problem);
    try testing.expectError(error.TooComplex, crowded);
    // Deep nesting inside a member the reader ignores costs one bit a level: it is read through.
    var nested: [200_000]u8 = undefined;
    var deep = std.Io.Writer.fixed(&nested);
    try deep.writeAll("{\"x\":");
    for (0..60_000) |_| try deep.writeAll("[");
    for (0..60_000) |_| try deep.writeAll("]");
    try deep.writeAll(",\"manifests\":[]}");
    _ = try parse_with(deep.buffered(), media_oci_index, &problem);
}

fn select_in(body: []const u8, wanted: Architecture, offered: *Offered) !?Selected {
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var problem: Problem = .{};
    const document = try parse_document(fixed.allocator(), body, media_oci_index, &problem);
    return select_platform(&document, wanted, offered, &problem);
}

const arm_entry = entry_of(zero, 10, "arm", "linux", variant_v7);
const select_entries = arm_entry ++ "," ++
    entry_of(one, 20, "arm64", "linux", variant_v8) ++ "," ++
    entry_of(zero, 30, "amd64", "linux", "") ++ "," ++
    entry_of(zero, 40, "unknown", "unknown", "");

test "platform selection: the host's entry, variants, attestations and the offer list" {
    // Goal: amd64 and arm64 (variant v8 or none) select; arm v7 and unknown/unknown never do; the
    // offer lists the real platforms, not the attestations.
    const body = index_prefix ++ select_entries ++ "]}";
    var offered: Offered = .{};
    const picked = (try select_in(body, .arm64, &offered)).?;
    try testing.expectEqual(@as(u64, 20), picked.size);
    try testing.expectEqualStrings(one, &picked.digest.text());
    try testing.expectEqual(@as(u32, 3), offered.total);
    try testing.expectEqualStrings("linux/arm/v7", offered.label(0));
    try testing.expectEqualStrings("linux/arm64/v8", offered.label(1));
    try testing.expectEqualStrings("linux/amd64", offered.label(2));
    offered = .{};
    const amd = (try select_in(body, .amd64, &offered)).?;
    try testing.expectEqual(@as(u64, 30), amd.size);

    offered = .{};
    const only_arm = index_prefix ++ arm_entry ++ "]}";
    try testing.expect((try select_in(only_arm, .amd64, &offered)) == null);
    try testing.expectEqual(@as(u32, 1), offered.total);
}

test "a platform that is not native is chosen only when the native one is missing" {
    // Goal: the fallback (images with no arm64 build, run through Rosetta) never replaces a
    // native entry. Method: an index with both, one with only amd64, one with neither.
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var problem: Problem = .{};
    const both = index_prefix ++ select_entries ++ "]}";
    const only_amd = index_prefix ++ entry_of(zero, 30, "amd64", "linux", "") ++ "]}";
    const neither = index_prefix ++ arm_entry ++ "]}";
    const bodies = [_][]const u8{ both, only_amd, neither };
    const expected = [_]?Architecture{ .arm64, .amd64, null };
    const missing_natively = [_]bool{ false, true, true };
    for (bodies, expected, missing_natively) |body, want, missing| {
        var fixed = std.heap.FixedBufferAllocator.init(&storage);
        const document = try parse_document(fixed.allocator(), body, media_oci_index, &problem);
        var offered: Offered = .{};
        const picked = try select_platform_or(&document, .arm64, .amd64, &offered, &problem);
        if (want) |architecture| {
            try testing.expectEqual(architecture, picked.?.architecture);
        } else {
            try testing.expect(picked == null);
        }
        offered = .{};
        const without = try select_platform_or(&document, .arm64, null, &offered, &problem);
        try testing.expectEqual(missing, without == null);
    }
    try testing.expectEqual(Architecture.amd64, architecture_of_platform("linux/amd64").?);
    try testing.expectEqual(Architecture.arm64, architecture_of_platform("linux/arm64").?);
    try testing.expect(architecture_of_platform("linux/arm") == null);
    try testing.expect(architecture_of_platform("amd64") == null);
}

const amd_platform = ",\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}}";

const Unusable = struct { descriptor: []const u8, expected: ParseError };

const unusable_entries = [_]Unusable{
    .{ .descriptor = describe("x/y", zero, 5), .expected = error.UnknownMediaType },
    .{ .descriptor = describe(media_oci_index, zero, 5), .expected = error.UnknownMediaType },
    .{ .descriptor = describe(media_oci_manifest, "sha512:a", 5), .expected = error.BadDescriptor },

    .{ .descriptor = describe(media_oci_manifest, zero, 0), .expected = error.BadDescriptor },
    .{ .descriptor = describe(media_oci_manifest, zero, 2000000), .expected = error.BadDescriptor },
};

test "a matching entry that cannot be used is refused, not skipped" {
    // Goal: an unknown media type, a nested index, a bad digest and a zero or huge size on the
    // chosen entry, and a missing size.
    inline for (unusable_entries) |case| {
        var offered: Offered = .{};
        const body = index_prefix ++ case.descriptor ++ amd_platform ++ "]}";
        try testing.expectError(case.expected, select_in(body, .amd64, &offered));
    }
    const no_size = index_prefix ++ "{\"mediaType\":\"" ++ media_oci_manifest ++
        "\",\"digest\":\"" ++ zero ++ "\"" ++ amd_platform ++ "]}";
    var offered: Offered = .{};
    try testing.expectError(error.BadDescriptor, select_in(no_size, .amd64, &offered));
}

fn read_in(body: []const u8, resolved: *Resolved, problem: *Problem) !void {
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const document = try parse_document(fixed.allocator(), body, media_oci_manifest, problem);
    return read_manifest(&document, resolved, problem);
}

const config_member = "\"config\":" ++ describe(media_oci_config, zero, 7) ++ "}";

test "a manifest gives its config and layers, with their kinds" {
    // Goal: OCI and Docker layer types map to kinds; the config is read; counts are exact.
    const body = comptime "{\"schemaVersion\":2," ++ config_member ++ ",\"layers\":[" ++
        describe(media_oci_layer_gzip, one, 11) ++ "}," ++
        describe(media_oci_layer_zstd, zero, 12) ++ "}," ++
        describe(media_docker_layer, one, 13) ++ "}," ++
        describe(media_oci_layer_tar, one, 14) ++ "}]}";
    var resolved: Resolved = undefined;
    var problem: Problem = .{};
    try read_in(body, &resolved, &problem);
    try testing.expectEqual(@as(u32, 4), resolved.layer_count);
    try testing.expectEqual(@as(u64, 7), resolved.config_size);
    try testing.expectEqual(LayerKind.tar_gzip, resolved.layers[0].kind);
    try testing.expectEqual(LayerKind.tar_zstd, resolved.layers[1].kind);
    try testing.expectEqual(LayerKind.tar_gzip, resolved.layers[2].kind);
    try testing.expectEqual(LayerKind.tar, resolved.layers[3].kind);
    try testing.expectEqual(@as(u64, 14), resolved.layers[3].size);
}

test "a manifest with a type, digest or size it cannot use is refused" {
    // Goal: unknown config and layer types are named; bad digests, zero sizes and too many layers
    // are refused.
    var resolved: Resolved = undefined;
    var problem: Problem = .{};
    const helm = "application/vnd.cncf.helm.config.v1+json";
    const bad_config = comptime "{\"config\":" ++ describe(helm, zero, 7) ++ "}}";
    try testing.expectError(error.UnknownMediaType, read_in(bad_config, &resolved, &problem));
    try testing.expectEqualStrings(helm, problem.text.slice());
    problem = .{};
    const foreign_type = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";
    const foreign_layer = comptime describe(foreign_type, one, 9);
    const foreign = comptime "{" ++ config_member ++ ",\"layers\":[" ++ foreign_layer ++ "}]}";

    try testing.expectError(error.UnknownMediaType, read_in(foreign, &resolved, &problem));
    const layers = comptime "{" ++ config_member ++ ",\"layers\":[";
    const bad_digest = comptime layers ++ describe(media_oci_layer_gzip, "sha256:xyz", 9) ++ "}]}";
    try testing.expectError(error.BadDescriptor, read_in(bad_digest, &resolved, &problem));
    const empty = comptime layers ++ describe(media_oci_layer_gzip, one, 0) ++ "}]}";
    try testing.expectError(error.BadDescriptor, read_in(empty, &resolved, &problem));
    try read_in("{" ++ config_member ++ "}", &resolved, &problem);
    try testing.expectEqual(@as(u32, 0), resolved.layer_count);

    const layer = comptime describe(media_oci_layer_gzip, one, 9) ++ "}";
    var text: [64 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try writer.writeAll(layers);
    for (0..constants.registry_layers_max + 1) |index| {
        if (index > 0) try writer.writeAll(",");
        try writer.writeAll(layer);
    }
    try writer.writeAll("]}");
    problem = .{};
    try testing.expectError(error.TooManyLayers, read_in(writer.buffered(), &resolved, &problem));
    try testing.expectEqualStrings("129 layers", problem.text.slice());
}

test "the host's machine names the platform" {
    // Goal: uname's x86_64 and aarch64 map, anything else is null.
    try testing.expectEqual(Architecture.amd64, architecture_of_machine("x86_64").?);
    try testing.expectEqual(Architecture.arm64, architecture_of_machine("aarch64").?);
    try testing.expect(architecture_of_machine("riscv64") == null);
    try testing.expect(architecture_of_machine("") == null);
}
