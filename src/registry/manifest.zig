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
        return media == .oci_index or media == .docker_list;
    }
};

/// The type named by `text` (a Content-Type value or a `mediaType` member), or null.
pub fn media_type_of(text: []const u8) ?MediaType {
    assert(text.len <= constants.registry_header_bytes_max * 4);
    const semicolon = std.mem.indexOfScalar(u8, text, ';');
    const bare = std.mem.trim(u8, if (semicolon) |at| text[0..at] else text, " \t");
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
        return @tagName(architecture);
    }
};

/// The platform of a machine as `uname` names it; null for one this build does not run on.
pub fn architecture_of_machine(machine: []const u8) ?Architecture {
    assert(machine.len < constants.uname_field_bytes);
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
    return .{ .media = media, .json = json };
}

fn name_media(problem: *Problem, text: ?[]const u8) void {
    assert(problem.text.len == 0);
    const shown = text orelse "(none)";
    problem.text.append_sanitised(shown, 100);
}

fn decide_media(
    declared: ?[]const u8,
    content_type: ?[]const u8,
    problem: *Problem,
) ParseError!MediaType {
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
        return offered.labels[index][0..offered.label_lens[index]];
    }

    fn add(offered: *Offered, os: []const u8, architecture: []const u8, variant: ?[]const u8) void {
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
    const entries = document.json.manifests.?;
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
    return found;
}

fn descriptor_digest(descriptor: DescriptorJson, problem: *Problem) ParseError!Sha256 {
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
    if (std.mem.eql(u8, text, media_oci_layer_tar)) return .tar;
    if (std.mem.eql(u8, text, media_oci_layer_gzip)) return .tar_gzip;
    if (std.mem.eql(u8, text, media_docker_layer)) return .tar_gzip;
    if (std.mem.eql(u8, text, media_oci_layer_zstd)) return .tar_zstd;
    return null;
}

fn is_config_type(text: []const u8) bool {
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

const zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const one = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn parse_with(body: []const u8, content_type: ?[]const u8, problem: *Problem) !Document {
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    // The arena dies with this function; tests read the document through `Document.json`
    // slices that point into `body`, and the entries into the arena, so each test below copies
    // what it needs before returning. This helper therefore only checks the verdict.
    return parse_document(fixed.allocator(), body, content_type, problem);
}

test "media types are matched exactly, with parameters cut" {
    // Goal: the four types are known in any letter case with a charset; near misses are not.
    try testing.expectEqual(MediaType.oci_index, media_type_of(media_oci_index).?);
    try testing.expectEqual(MediaType.docker_list, media_type_of(media_docker_list).?);
    const with_parameter = media_oci_manifest ++ "; charset=utf-8";
    try testing.expectEqual(MediaType.oci_manifest, media_type_of(with_parameter).?);
    try testing.expectEqual(MediaType.docker_manifest, media_type_of(" " ++ media_docker_manifest).?);
    try testing.expect(media_type_of("application/json") == null);
    try testing.expect(media_type_of(media_oci_index ++ "x") == null);
    try testing.expect(media_type_of("application/vnd.docker.distribution.manifest.v1+prettyjws") == null);
    try testing.expect(media_type_of("") == null);
}

test "the declared type and the header must agree, and one must exist" {
    // Goal: each way to decide the type, and the refusals with their problem text.
    var problem: Problem = .{};
    const index_body = "{\"schemaVersion\":2,\"mediaType\":\"" ++ media_oci_index ++ "\",\"manifests\":[]}";
    const document = try parse_with(index_body, null, &problem);
    try testing.expectEqual(MediaType.oci_index, document.media);
    _ = try parse_with(index_body, media_oci_index, &problem);
    _ = try parse_with(index_body, "application/json", &problem);
    try testing.expectError(error.MediaTypeMismatch, parse_with(index_body, media_docker_list, &problem));

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
    try testing.expectError(error.UnknownMediaType, parse_with(unknown, media_oci_index, &problem));
    try testing.expectEqualStrings("application/vnd.example+json", problem.text.slice());
    problem = .{};
    const schema_one = "{\"schemaVersion\":1,\"mediaType\":\"" ++ media_docker_manifest ++ "\",\"config\":{}}";
    try testing.expectError(error.UnknownMediaType, parse_with(schema_one, null, &problem));
    try testing.expectEqualStrings("schemaVersion 1", problem.text.slice());
}

test "bodies that are not documents" {
    // Goal: JSON of the wrong shape, duplicate keys, a document of the wrong kind, and nesting
    // beyond the arena are all refused with a reason, not a crash.
    var problem: Problem = .{};
    try testing.expectError(error.Malformed, parse_with("not json", media_oci_index, &problem));
    try testing.expectError(error.Malformed, parse_with("[]", media_oci_index, &problem));
    try testing.expectError(error.Malformed, parse_with("{\"manifests\":5}", media_oci_index, &problem));
    try testing.expectError(error.Malformed, parse_with("{\"manifests\":[],\"manifests\":[]}", media_oci_index, &problem));
    try testing.expectError(error.Malformed, parse_with("{}", media_oci_index, &problem));
    try testing.expectError(error.Malformed, parse_with("{\"layers\":[]}", media_oci_manifest, &problem));
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
    @memset(&nested, '[');
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

const index_prefix = "{\"schemaVersion\":2,\"manifests\":[";

test "platform selection: the host's entry, variants, attestations and the offer list" {
    // Goal: amd64 and arm64 (variant v8 or none) select; arm v7, s390x and unknown/unknown never
    // do; the offer lists the real platforms, not the attestations.
    const arm_entry =
        "{\"mediaType\":\"" ++ media_oci_manifest ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":10," ++
        "\"platform\":{\"architecture\":\"arm\",\"os\":\"linux\",\"variant\":\"v7\"}}";
    const entries = arm_entry ++ "," ++
        "{\"mediaType\":\"" ++ media_oci_manifest ++ "\",\"digest\":\"" ++ one ++ "\",\"size\":20," ++
        "\"platform\":{\"architecture\":\"arm64\",\"os\":\"linux\",\"variant\":\"v8\"}}," ++
        "{\"mediaType\":\"" ++ media_oci_manifest ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":30," ++
        "\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}}," ++
        "{\"mediaType\":\"" ++ media_oci_manifest ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":40," ++
        "\"platform\":{\"architecture\":\"unknown\",\"os\":\"unknown\"}}";
    const body = index_prefix ++ entries ++ "]}";
    var offered: Offered = .{};
    const arm = (try select_in(body, .arm64, &offered)).?;
    try testing.expectEqual(@as(u64, 20), arm.size);
    try testing.expectEqualStrings(one, &arm.digest.text());
    try testing.expectEqual(@as(u32, 3), offered.total);
    try testing.expectEqualStrings("linux/arm/v7", offered.label(0));
    try testing.expectEqualStrings("linux/arm64/v8", offered.label(1));
    try testing.expectEqualStrings("linux/amd64", offered.label(2));
    offered = .{};
    const amd = (try select_in(body, .amd64, &offered)).?;
    try testing.expectEqual(@as(u64, 30), amd.size);

    const only_arm = index_prefix ++ arm_entry ++ "]}";
    offered = .{};
    try testing.expect((try select_in(only_arm, .amd64, &offered)) == null);
    try testing.expectEqual(@as(u32, 1), offered.total);
}

test "a matching entry that cannot be used is refused, not skipped" {
    // Goal: an unknown media type, a bad digest and a zero or huge size on the chosen entry.
    const platform = "\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}";
    var offered: Offered = .{};
    const unknown = index_prefix ++ "{\"mediaType\":\"x/y\",\"digest\":\"" ++ zero ++ "\",\"size\":5," ++ platform ++ "}]}";
    try testing.expectError(error.UnknownMediaType, select_in(unknown, .amd64, &offered));
    const nested = index_prefix ++ "{\"mediaType\":\"" ++ media_oci_index ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":5," ++ platform ++ "}]}";
    try testing.expectError(error.UnknownMediaType, select_in(nested, .amd64, &offered));
    const media = "{\"mediaType\":\"" ++ media_oci_manifest ++ "\",";
    const bad_digest = index_prefix ++ media ++ "\"digest\":\"sha512:ab\",\"size\":5," ++ platform ++ "}]}";
    try testing.expectError(error.BadDescriptor, select_in(bad_digest, .amd64, &offered));
    const no_size = index_prefix ++ media ++ "\"digest\":\"" ++ zero ++ "\"," ++ platform ++ "}]}";
    try testing.expectError(error.BadDescriptor, select_in(no_size, .amd64, &offered));
    const zero_size = index_prefix ++ media ++ "\"digest\":\"" ++ zero ++ "\",\"size\":0," ++ platform ++ "}]}";
    try testing.expectError(error.BadDescriptor, select_in(zero_size, .amd64, &offered));
    const huge = index_prefix ++ media ++ "\"digest\":\"" ++ zero ++ "\",\"size\":2000000," ++ platform ++ "}]}";
    try testing.expectError(error.BadDescriptor, select_in(huge, .amd64, &offered));
}

fn read_in(body: []const u8, resolved: *Resolved, problem: *Problem) !void {
    var storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const document = try parse_document(fixed.allocator(), body, media_oci_manifest, problem);
    return read_manifest(&document, resolved, problem);
}

test "a manifest gives its config and layers, with their kinds" {
    // Goal: OCI and Docker layer types map to kinds; the config is read; counts are exact.
    const body =
        "{\"schemaVersion\":2,\"config\":{\"mediaType\":\"" ++ media_oci_config ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":7}," ++
        "\"layers\":[{\"mediaType\":\"" ++ media_oci_layer_gzip ++ "\",\"digest\":\"" ++ one ++ "\",\"size\":11}," ++
        "{\"mediaType\":\"" ++ media_oci_layer_zstd ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":12}," ++
        "{\"mediaType\":\"" ++ media_docker_layer ++ "\",\"digest\":\"" ++ one ++ "\",\"size\":13}," ++
        "{\"mediaType\":\"" ++ media_oci_layer_tar ++ "\",\"digest\":\"" ++ one ++ "\",\"size\":14}]}";
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
    const config = "\"config\":{\"mediaType\":\"" ++ media_oci_config ++ "\",\"digest\":\"" ++ zero ++ "\",\"size\":7}";
    var resolved: Resolved = undefined;
    var problem: Problem = .{};
    const bad_config = "{\"config\":{\"mediaType\":\"application/vnd.cncf.helm.config.v1+json\",\"digest\":\"" ++ zero ++ "\",\"size\":7}}";
    try testing.expectError(error.UnknownMediaType, read_in(bad_config, &resolved, &problem));
    try testing.expectEqualStrings("application/vnd.cncf.helm.config.v1+json", problem.text.slice());
    problem = .{};
    const foreign = "{" ++ config ++ ",\"layers\":[{\"mediaType\":\"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip\",\"digest\":\"" ++ one ++ "\",\"size\":9}]}";
    try testing.expectError(error.UnknownMediaType, read_in(foreign, &resolved, &problem));
    const layer_head = "{\"mediaType\":\"" ++ media_oci_layer_gzip ++ "\",";
    const bad_digest = "{" ++ config ++ ",\"layers\":[" ++ layer_head ++ "\"digest\":\"sha256:xyz\",\"size\":9}]}";
    try testing.expectError(error.BadDescriptor, read_in(bad_digest, &resolved, &problem));
    const empty = "{" ++ config ++ ",\"layers\":[" ++ layer_head ++ "\"digest\":\"" ++ one ++ "\",\"size\":0}]}";
    try testing.expectError(error.BadDescriptor, read_in(empty, &resolved, &problem));
    const none = "{" ++ config ++ "}";
    try read_in(none, &resolved, &problem);
    try testing.expectEqual(@as(u32, 0), resolved.layer_count);

    var many: [constants.registry_layers_max + 1][]const u8 = undefined;
    @memset(&many, layer_head ++ "\"digest\":\"" ++ one ++ "\",\"size\":9}");
    var text: [64 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try writer.print("{{{s},\"layers\":[", .{config});
    for (many, 0..) |layer, index| {
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
