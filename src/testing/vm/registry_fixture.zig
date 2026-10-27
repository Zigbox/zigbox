//! A small registry that serves fixtures and faults: the test registry of M4 (docs/briefs/
//! M4-pull.md). It answers what a registry answers (a manifest list, a manifest, a token) and
//! misbehaves on demand, so every test of the pull code runs with no internet.
//!
//! It is a pure function from a request to an answer (`Fixture.answer`), with no sockets, so two
//! things serve it: the simulator's network (`src/registry/test_registry.zig`), which adds seeded
//! faults of the wire, and the TCP server of this directory (`registry_server.zig`), which lets
//! the real network code talk to it over loopback. The file uses only `std`, so the VM harness
//! can serve it too.
//!
//! Which fault a request gets is named by its repository: `fixture/<scenario>`. A tag is any
//! text, and the same image answers every tag of a repository. The scenarios:
//!
//!   open        an OCI index (linux/amd64, linux/arm64 v8, linux/arm v7, an attestation entry)
//!   docker      the same image as a Docker v2 manifest list and manifests
//!   single      the tag names one OCI manifest directly, not an index
//!   bearer      open, behind an anonymous token (401, then a token from /token, then 200)
//!   limited     bearer, then 429 with Retry-After on every manifest
//!   tokenlimited the token endpoint answers 429
//!   denied      the token endpoint refuses (401)
//!   private     401 with a challenge even with a token
//!   badsum      the platform manifest is served with one byte changed
//!   badindex    the index is served with one byte changed (its header says the right digest)
//!   cut         the index body ends halfway, under its declared length
//!   media       the index has a media type nobody knows
//!   layermedia  the manifest has a layer of a media type nobody knows
//!   nomatch     an index with only linux/arm v7 and linux/ppc64le
//!   missing     404 for every manifest
//!   broken      503 for every manifest
//!   huge        a manifest that declares two mebibytes
//!   redirect    307 to the open repository, with a relative Location
//!   redirectfar 307 to another host, which must not get the token
//!
//! The blobs of an image are served too, at `/v2/fixture/<scenario>/blobs/<digest>`, honouring
//! `Range`. The layers are real archives: the first a gzip tar with a directory tree, a hard
//! link and a symlink, the second a zstd tar with whiteouts, an opaque directory and extended
//! attributes (one the store keeps, one it does not). Scenarios for blobs:
//!
//!   norange     a single manifest (as `single`), and the blobs ignore Range (always 200)
//!   cdn         a single manifest; a blob request is answered 307 to /cdn/<digest> on the other
//!               host, which serves it without a token
//!   badblob     a single manifest; the first layer is served with one byte changed
//!   unsafe      a single manifest whose layer has an entry with an absolute path
//!   damaged     a single manifest whose layer is a tar with a wrong header checksum
//!   special     a single manifest whose layer has only devices, and one file

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const layers = @import("layer_fixture.zig");

pub const Scenario = enum {
    open,
    docker,
    single,
    bearer,
    limited,
    tokenlimited,
    denied,
    private,
    badsum,
    badindex,
    cut,
    media,
    layermedia,
    nomatch,
    missing,
    broken,
    huge,
    redirect,
    redirectfar,
    norange,
    cdn,
    badblob,
    unsafe,
    damaged,
    special,
};

/// What a client asked for.
pub const Query = struct {
    /// The Host the client addressed, without a port.
    host: []const u8,
    /// Path and query.
    target: []const u8,
    /// The bearer token the client presented; empty for none.
    bearer: []const u8,
    /// The offset of a `Range: bytes=N-` request; zero for none.
    range_from: u64 = 0,
};

/// What the registry says. All slices are borrowed from the fixture.
pub const Answer = struct {
    status: u16 = 200,
    content_length: ?u64 = null,
    content_type: []const u8 = "",
    www_authenticate: []const u8 = "",
    retry_after: []const u8 = "",
    content_digest: []const u8 = "",
    location: []const u8 = "",
    content_range: []const u8 = "",
    body: []const u8 = "",
    /// Body bytes that arrive before the connection drops; null for all.
    deliver: ?u64 = null,
};

pub const media_oci_index = "application/vnd.oci.image.index.v1+json";
pub const media_oci_manifest = "application/vnd.oci.image.manifest.v1+json";
pub const media_oci_config = "application/vnd.oci.image.config.v1+json";
pub const media_oci_layer_gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const media_oci_layer_zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const media_docker_list = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const media_docker_manifest = "application/vnd.docker.distribution.manifest.v2+json";
pub const media_docker_config = "application/vnd.docker.container.image.v1+json";
pub const media_docker_layer = "application/vnd.docker.image.rootfs.diff.tar.gzip";
pub const media_unknown = "application/vnd.example.unknown.v9+json";

const body_bytes_max = 16384;
const challenge_format = "Bearer realm=\"{s}\",service=\"fixture.registry\"," ++
    "scope=\"repository:fixture/{s}:pull\"{s}";
pub const token_text =
    "FAKEtoken.eyJzdWIiOiJmaXh0dXJlIn0.FAKEsignature0123456789";
const huge_declared_bytes: u64 = 2 * 1024 * 1024;

/// One blob or manifest: its bytes and its digest, in text.
pub const Item = struct {
    bytes: [body_bytes_max]u8 = undefined,
    len: u32 = 0,
    /// "sha256:" and 64 hex digits.
    digest: [71]u8 = undefined,

    pub fn slice(item: *const Item) []const u8 {
        assert(item.len <= body_bytes_max);
        return item.bytes[0..item.len];
    }

    fn set(item: *Item, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.bufPrint(&item.bytes, format, args) catch unreachable; // Bounded.
        item.len = @intCast(text.len);
        item.seal();
    }

    fn set_bytes(item: *Item, bytes: []const u8) void {
        assert(bytes.len <= body_bytes_max);
        @memcpy(item.bytes[0..bytes.len], bytes);
        item.len = @intCast(bytes.len);
        item.seal();
    }

    fn seal(item: *Item) void {
        var sum: [32]u8 = undefined;
        Sha256.hash(item.slice(), &sum, .{});
        const hex = std.fmt.bytesToHex(sum, .lower);
        @memcpy(item.digest[0..7], "sha256:");
        @memcpy(item.digest[7..], &hex);
    }
};

/// One image in one family of media types.
pub const Image = struct {
    config: Item = .{},
    layer_gzip: Item = .{},
    layer_zstd: Item = .{},
    amd64: Item = .{},
    arm64: Item = .{},
    index: Item = .{},
    /// The index of `nomatch`.
    index_nomatch: Item = .{},
    /// The manifest with a layer of an unknown type.
    amd64_layermedia: Item = .{},
    index_layermedia: Item = .{},
    /// The index with an unknown media type.
    index_media: Item = .{},
    /// The manifest the arm/v7 and ppc64le entries name, and the attestation's; never served.
    other: Item = .{},
    nothing: Item = .{},
    /// The layers of the scenarios `unsafe`, `damaged` and `special`, and the manifests that
    /// name each as the image's only layer.
    layer_unsafe: Item = .{},
    layer_damaged: Item = .{},
    layer_special: Item = .{},
    amd64_unsafe: Item = .{},
    amd64_damaged: Item = .{},
    amd64_special: Item = .{},
    families: Family,
};

pub const Family = struct {
    index: []const u8,
    manifest: []const u8,
    config: []const u8,
    layer_gzip: []const u8,
    layer_zstd: []const u8,
};

const oci_family: Family = .{
    .index = media_oci_index,
    .manifest = media_oci_manifest,
    .config = media_oci_config,
    .layer_gzip = media_oci_layer_gzip,
    .layer_zstd = media_oci_layer_zstd,
};

const docker_family: Family = .{
    .index = media_docker_list,
    .manifest = media_docker_manifest,
    .config = media_docker_config,
    .layer_gzip = media_docker_layer,
    .layer_zstd = media_docker_layer,
};

const manifest_format =
    \\{{"schemaVersion":2,"mediaType":"{s}",
    \\"config":{{"mediaType":"{s}","digest":"{s}","size":{d}}},
    \\"layers":[{{"mediaType":"{s}","digest":"{s}","size":{d}}},
    \\{{"mediaType":"{s}","digest":"{s}","size":{d}}}],"annotations":{{"arch":"{s}"}}}}
;

fn build_manifest(
    image: *Image,
    item: *Item,
    architecture: []const u8,
    layer_media: []const u8,
) void {
    const family = image.families;
    const config = &image.config;
    const gzip = &image.layer_gzip;
    const zstd = &image.layer_zstd;
    item.set(manifest_format, .{
        family.manifest, family.config, &config.digest, config.len,
        layer_media,     &gzip.digest,  gzip.len,       family.layer_zstd,
        &zstd.digest,    zstd.len,      architecture,
    });
}

/// One entry of an index.
const Entry = struct {
    item: *const Item,
    architecture: []const u8,
    os: []const u8,
    /// `,"variant":"v8"` or empty.
    variant: []const u8 = "",
    /// Members a reader must ignore, as the attestation entry of a buildx image has.
    extra: []const u8 = "",
};

const entry_format =
    \\{{"mediaType":"{s}","digest":"{s}","size":{d},
    \\"platform":{{"architecture":"{s}","os":"{s}"{s}}}{s}}}
;

fn build_index(image: *Image, item: *Item, media: []const u8, entries: []const Entry) void {
    var writer = std.Io.Writer.fixed(&item.bytes);
    const open = "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[";
    // Cannot fail: the buffer holds the largest index (four entries of about 300 bytes).
    writer.print(open, .{media}) catch unreachable;
    for (entries, 0..) |entry, at| {
        if (at > 0) writer.writeAll(",") catch unreachable; // The same bound.
        const kept = entry.item;
        writer.print(entry_format, .{
            image.families.manifest, &kept.digest,  kept.len,    entry.architecture,
            entry.os,                entry.variant, entry.extra,
        }) catch unreachable; // The same bound.
    }
    writer.writeAll("]}") catch unreachable; // The same bound.
    item.len = @intCast(writer.buffered().len);
    item.seal();
}

const variant_v7 = ",\"variant\":\"v7\"";
const variant_v8 = ",\"variant\":\"v8\"";
const attestation = ",\"annotations\":{\"vnd.docker.reference.type\":\"attestation-manifest\"}";

/// A manifest with the config and one layer.
const one_layer_format =
    \\{{"schemaVersion":2,"mediaType":"{s}",
    \\"config":{{"mediaType":"{s}","digest":"{s}","size":{d}}},
    \\"layers":[{{"mediaType":"{s}","digest":"{s}","size":{d}}}]}}
;

fn build_one_layer(image: *Image, item: *Item, layer: *const Item) void {
    const family = image.families;
    item.set(one_layer_format, .{
        family.manifest,   family.config, &image.config.digest, image.config.len,
        family.layer_gzip, &layer.digest, layer.len,
    });
}

/// The first layer: a root file system's worth of every kind of entry.
fn build_layer_one(item: *Item) void {
    var storage: [12 * 1024]u8 = undefined;
    var tar = layers.Tar.init(&storage);
    tar.add(.{ .name = "./", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "etc/", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "etc/os-release", .data = "NAME=Fixture\n", .mode = 0o644 });
    tar.add(.{ .name = "bin/", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "bin/hello", .data = "#!/bin/hello\n", .mode = 0o755 });
    tar.add(.{ .name = "bin/hi", .kind = .hardlink, .link = "bin/hello" });
    tar.add(.{ .name = "lib/", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "lib/libx.so.1", .data = "ELF libx", .mode = 0o644 });
    tar.add(.{ .name = "lib/libx.so", .kind = .symlink, .link = "libx.so.1", .mode = 0o777 });
    tar.add(.{ .name = "tmp/", .kind = .directory, .mode = 0o1777 });
    tar.add(.{ .name = "tmp/gone", .data = "to be removed", .mode = 0o644 });
    tar.add(.{ .name = "usr/old/", .kind = .directory, .mode = 0o755 });
    tar.add(.{ .name = "usr/old/a", .data = "a", .mode = 0o644 });
    tar.add(.{ .name = "home/user/", .kind = .directory, .mode = 0o700, .uid = 1000, .gid = 1000 });
    tar.finish();
    var gz: [16 * 1024]u8 = undefined;
    item.set_bytes(layers.gzip(&gz, tar.bytes()));
}

/// The second layer: replaces, removes, empties a directory, and has attributes to keep and drop.
fn build_layer_two(item: *Item) void {
    var storage: [8 * 1024]u8 = undefined;
    var tar = layers.Tar.init(&storage);
    tar.add(.{ .name = "etc/os-release", .data = "NAME=Fixture 2\n", .mode = 0o644 });
    tar.add(.{ .name = "tmp/.wh.gone", .data = "" });
    tar.add(.{ .name = "usr/old/.wh..wh..opq", .data = "" });
    tar.add(.{ .name = "usr/old/new", .data = "new", .mode = 0o644 });
    tar.add(.{ .name = "bin/ping", .data = "ping", .mode = 0o755, .xattrs = &.{
        .{ .name = "user.note", .value = "kept" },
        .{ .name = "trusted.private", .value = "dropped" },
    } });
    tar.finish();
    var raw: [16 * 1024]u8 = undefined;
    item.set_bytes(layers.zstd(&raw, tar.bytes()));
}

fn build_variant_layers(image: *Image) void {
    var storage: [4096]u8 = undefined;
    var tar = layers.Tar.init(&storage);
    tar.add(.{ .name = "/etc/passwd", .data = "evil" });
    tar.finish();
    var gz: [8192]u8 = undefined;
    image.layer_unsafe.set_bytes(layers.gzip(&gz, tar.bytes()));
    tar = layers.Tar.init(&storage);
    tar.add(.{ .name = "ok", .data = "fine", .bad_checksum = true });
    tar.finish();
    image.layer_damaged.set_bytes(layers.gzip(&gz, tar.bytes()));
    tar = layers.Tar.init(&storage);
    tar.add(.{ .name = "dev/tty", .kind = .char_device, .mode = 0o666 });
    tar.add(.{ .name = "run/fifo", .kind = .fifo, .mode = 0o600 });
    tar.add(.{ .name = "only", .data = "file" });
    tar.finish();
    image.layer_special.set_bytes(layers.gzip(&gz, tar.bytes()));
    build_one_layer(image, &image.amd64_unsafe, &image.layer_unsafe);
    build_one_layer(image, &image.amd64_damaged, &image.layer_damaged);
    build_one_layer(image, &image.amd64_special, &image.layer_special);
}

fn build_image(image: *Image, family: Family) void {
    image.families = family;
    image.config.set_bytes(
        \\{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/hello"],
        \\"Cmd":["world"],"Env":["PATH=/bin:/usr/bin","LANG=C"],"WorkingDir":"/srv/app",
        \\"User":""}}
    );
    build_layer_one(&image.layer_gzip);
    build_layer_two(&image.layer_zstd);
    build_variant_layers(image);
    image.other.set_bytes("a manifest nobody serves");
    image.nothing.set_bytes("an attestation nobody serves");
    build_manifest(image, &image.amd64, "amd64", family.layer_gzip);
    build_manifest(image, &image.arm64, "arm64", family.layer_gzip);
    build_manifest(image, &image.amd64_layermedia, "amd64", media_unknown);
    const arm64: Entry = .{
        .item = &image.arm64,
        .architecture = "arm64",
        .os = "linux",
        .variant = variant_v8,
    };
    const arm: Entry = .{
        .item = &image.other,
        .architecture = "arm",
        .os = "linux",
        .variant = variant_v7,
    };
    const amd64: Entry = .{ .item = &image.amd64, .architecture = "amd64", .os = "linux" };
    const ppc64: Entry = .{ .item = &image.other, .architecture = "ppc64le", .os = "linux" };
    const buildx: Entry = .{
        .item = &image.nothing,
        .architecture = "unknown",
        .os = "unknown",
        .extra = attestation,
    };
    const bad_layer: Entry = .{
        .item = &image.amd64_layermedia,
        .architecture = "amd64",
        .os = "linux",
    };
    build_index(image, &image.index, family.index, &.{ arm64, arm, amd64, buildx });
    build_index(image, &image.index_media, media_unknown, &.{ arm64, arm, amd64, buildx });
    build_index(image, &image.index_layermedia, family.index, &.{bad_layer});
    build_index(image, &image.index_nomatch, family.index, &.{ arm, ppc64 });
}

pub const Fixture = struct {
    oci: Image,
    docker: Image,
    /// Where the registry is, as a URL without a path: the Location of a redirect and the
    /// realm of the token endpoint are built from it.
    base: [96]u8,
    base_len: u8,
    other_base: [96]u8,
    other_base_len: u8,
    realm: [128]u8,
    realm_len: u8,
    scratch: [512]u8,
    range_text: [96]u8,
    corrupted: Item,

    /// Builds the images. `base` is the registry's own URL ("http://127.0.0.1:5000"); `other_base`
    /// is a different host a redirect may point at.
    pub fn init(fixture: *Fixture, base: []const u8, other_base: []const u8) void {
        assert(base.len > 0);
        assert(base.len <= fixture.base.len);
        assert(other_base.len <= fixture.other_base.len);
        build_image(&fixture.oci, oci_family);
        build_image(&fixture.docker, docker_family);
        @memcpy(fixture.base[0..base.len], base);
        fixture.base_len = @intCast(base.len);
        @memcpy(fixture.other_base[0..other_base.len], other_base);
        fixture.other_base_len = @intCast(other_base.len);
        // Cannot fail: the realm buffer holds a base of at most 96 bytes.
        const realm = std.fmt.bufPrint(&fixture.realm, "{s}/token", .{base}) catch unreachable;
        fixture.realm_len = @intCast(realm.len);
    }

    fn base_text(fixture: *const Fixture) []const u8 {
        return fixture.base[0..fixture.base_len];
    }

    fn realm_text(fixture: *const Fixture) []const u8 {
        return fixture.realm[0..fixture.realm_len];
    }

    /// The image a scenario serves.
    pub fn image(fixture: *const Fixture, scenario: Scenario) *const Image {
        return if (scenario == .docker) &fixture.docker else &fixture.oci;
    }

    /// The platform manifest a resolve of the scenario ends at, and how many layers it names.
    pub fn manifest_of(fixture: *const Fixture, scenario: Scenario) *const Item {
        const used = fixture.image(scenario);
        return switch (scenario) {
            .unsafe => &used.amd64_unsafe,
            .damaged => &used.amd64_damaged,
            .special => &used.amd64_special,
            else => &used.amd64,
        };
    }

    pub fn layers_of(fixture: *const Fixture, scenario: Scenario) u32 {
        _ = fixture;
        return switch (scenario) {
            .unsafe, .damaged, .special => 1,
            else => 2,
        };
    }

    /// What the registry answers for `query`.
    pub fn answer(fixture: *Fixture, query: Query, out: *Answer) void {
        out.* = .{};
        if (std.mem.startsWith(u8, query.target, "/token")) return fixture.answer_token(query, out);
        if (std.mem.startsWith(u8, query.target, "/cdn/")) return fixture.serve_cdn(query, out);
        const route = parse_route(query.target) orelse return not_found(out);
        if (route.scenario == .tokenlimited or route.scenario == .denied) {
            // These two repositories hand out no usable token; the manifest asks for one.
            return fixture.challenge(route, query, out);
        }
        const needs_token = switch (route.scenario) {
            .bearer, .limited, .private, .redirectfar, .cdn => true,
            else => false,
        };
        if (needs_token and !std.mem.eql(u8, query.bearer, token_text)) {
            return fixture.challenge(route, query, out);
        }
        if (route.scenario == .private) return fixture.challenge(route, query, out);
        if (route.scenario == .limited) return limited(out);
        if (route.blob) return fixture.serve_blob(route, query, out);
        fixture.serve_manifest(route, out);
    }

    fn challenge(fixture: *Fixture, route: Route, query: Query, out: *Answer) void {
        const invalid: []const u8 = if (query.bearer.len > 0) ",error=\"invalid_token\"" else "";
        const text = std.fmt.bufPrint(
            &fixture.scratch,
            challenge_format,
            .{ fixture.realm_text(), route.name, invalid },
        ) catch unreachable; // Bounded: the realm is at most 128 bytes.
        out.status = 401;
        out.www_authenticate = text;
        out.body = "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}";
        out.content_type = "application/json";
    }

    fn answer_token(fixture: *Fixture, query: Query, out: *Answer) void {
        _ = fixture;
        out.content_type = "application/json";
        const encoded = std.mem.indexOf(u8, query.target, "scope=repository%3Afixture%2F");
        const plain = std.mem.indexOf(u8, query.target, "scope=repository:fixture/");
        const found = encoded orelse plain orelse return not_found(out);
        const rest = query.target[found..];
        if (std.mem.indexOf(u8, rest, "tokenlimited") != null) {
            out.status = 429;
            out.retry_after = "30";
            out.body = "{\"errors\":[{\"code\":\"TOOMANYREQUESTS\"}]}";
            return;
        }
        if (std.mem.indexOf(u8, rest, "denied") != null) {
            out.status = 401;
            out.body = "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}";
            return;
        }
        out.body = "{\"token\":\"" ++ token_text ++ "\",\"access_token\":\"" ++ token_text ++
            "\",\"expires_in\":300,\"issued_at\":\"2026-10-27T00:00:00Z\"}";
    }

    fn serve_manifest(fixture: *Fixture, route: Route, out: *Answer) void {
        const scenario = route.scenario;
        switch (scenario) {
            .missing => return missing(out),
            .broken => return broken(out),
            .huge => {
                out.content_length = huge_declared_bytes;
                out.content_type = media_oci_index;
                out.deliver = 0;
                return;
            },
            .redirect, .redirectfar => return fixture.redirect(route, out),
            else => {},
        }
        const image_used = fixture.image(scenario);
        const item = pick(image_used, scenario, route.manifest) orelse return missing(out);
        out.content_type = content_type_of(image_used, scenario, route.manifest);
        out.content_digest = &item.digest;
        out.body = item.slice();
        if (scenario == .badsum and is_digest(route.manifest) and item == &image_used.amd64) {
            fixture.corrupted = item.*;
            fixture.corrupted.bytes[10] ^= 0x01;
            out.body = fixture.corrupted.slice();
        }
        if (scenario == .badindex and item == &image_used.index) {
            fixture.corrupted = item.*;
            fixture.corrupted.bytes[10] ^= 0x01;
            out.body = fixture.corrupted.slice();
        }
        if (scenario == .cut and item == &image_used.index) {
            out.content_length = item.len;
            out.deliver = item.len / 2;
        }
    }

    /// The blob a digest names in the image of a scenario; null for one nobody serves.
    fn blob_item(image_used: *const Image, name: []const u8) ?*const Item {
        const candidates = [_]*const Item{
            &image_used.config,       &image_used.layer_gzip,    &image_used.layer_zstd,
            &image_used.layer_unsafe, &image_used.layer_damaged, &image_used.layer_special,
        };
        for (candidates) |item| {
            if (std.mem.eql(u8, name, &item.digest)) return item;
        }
        return null;
    }

    fn serve_blob(fixture: *Fixture, route: Route, query: Query, out: *Answer) void {
        const scenario = route.scenario;
        const image_used = fixture.image(scenario);
        const item = blob_item(image_used, route.manifest) orelse return missing_blob(out);
        if (scenario == .cdn) {
            const far = fixture.other_base[0..fixture.other_base_len];
            const format = "{s}/cdn/{s}";
            const text = std.fmt.bufPrint(&fixture.scratch, format, .{ far, route.manifest });
            out.status = 307;
            out.location = text catch unreachable; // Bounded: a base and a digest.
            return;
        }
        fixture.send_blob(item, scenario, query, out);
    }

    /// The content delivery host: a blob by digest, with no token.
    fn serve_cdn(fixture: *Fixture, query: Query, out: *Answer) void {
        const name = query.target["/cdn/".len..];
        const item = blob_item(&fixture.oci, name) orelse return missing_blob(out);
        fixture.send_blob(item, .cdn, query, out);
    }

    fn send_blob(
        fixture: *Fixture,
        item: *const Item,
        scenario: Scenario,
        query: Query,
        out: *Answer,
    ) void {
        out.content_type = "application/octet-stream";
        out.content_digest = &item.digest;
        var body = item.slice();
        const first_layer = std.mem.eql(u8, &item.digest, &fixture.oci.layer_gzip.digest);
        if (scenario == .badblob and first_layer) {
            fixture.corrupted = item.*;
            fixture.corrupted.bytes[item.len / 2] ^= 0x01;
            body = fixture.corrupted.slice();
        }
        const from = query.range_from;
        if (from == 0 or scenario == .norange) {
            out.body = body;
            return;
        }
        if (from >= body.len) {
            out.status = 416;
            out.body = "";
            return;
        }
        out.status = 206;
        out.body = body[@intCast(from)..];
        out.content_range = std.fmt.bufPrint(&fixture.range_text, "bytes {d}-{d}/{d}", .{
            from, body.len - 1, body.len,
        }) catch unreachable; // Bounded: three numbers.
    }

    fn redirect(fixture: *Fixture, route: Route, out: *Answer) void {
        const far = fixture.other_base[0..fixture.other_base_len];
        const base: []const u8 = if (route.scenario == .redirectfar) far else "";
        const text = std.fmt.bufPrint(
            &fixture.scratch,
            "{s}/v2/fixture/open/manifests/{s}",
            .{ base, route.manifest },
        ) catch unreachable; // Bounded: a name is at most 128 bytes.
        out.status = 307;
        out.location = text;
    }
};

const Route = struct {
    /// A blob (the name is its digest) rather than a manifest.
    blob: bool,
    scenario: Scenario,
    /// The scenario's name as written, for a scope.
    name: []const u8,
    /// The tag or digest asked for.
    manifest: []const u8,
};

fn parse_route(target: []const u8) ?Route {
    const prefix = "/v2/fixture/";
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    const rest = target[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const name = rest[0..slash];
    const scenario = std.meta.stringToEnum(Scenario, name) orelse return null;
    const tail = rest[slash..];
    const manifests = "/manifests/";
    const blobs = "/blobs/";
    if (std.mem.startsWith(u8, tail, blobs)) {
        return .{ .blob = true, .scenario = scenario, .name = name, .manifest = tail[blobs.len..] };
    }
    if (!std.mem.startsWith(u8, tail, manifests)) return null;
    return .{
        .blob = false,
        .scenario = scenario,
        .name = name,
        .manifest = tail[manifests.len..],
    };
}

fn is_digest(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "sha256:");
}

/// The item a tag or digest names in a scenario; null for a digest nobody serves.
fn pick(image: *const Image, scenario: Scenario, name: []const u8) ?*const Item {
    if (!is_digest(name)) return tag_item(image, scenario);
    const candidates = [_]*const Item{
        &image.index,            &image.amd64,         &image.arm64,
        &image.index_media,      &image.index_nomatch, &image.amd64_layermedia,
        &image.index_layermedia, &image.amd64_unsafe,  &image.amd64_damaged,
        &image.amd64_special,
    };
    for (candidates) |item| {
        if (std.mem.eql(u8, name, &item.digest)) return item;
    }
    return null;
}

fn tag_item(image: *const Image, scenario: Scenario) *const Item {
    return switch (scenario) {
        .single, .norange, .cdn, .badblob => &image.amd64,
        .unsafe => &image.amd64_unsafe,
        .damaged => &image.amd64_damaged,
        .special => &image.amd64_special,
        .media => &image.index_media,
        .nomatch => &image.index_nomatch,
        .layermedia => &image.index_layermedia,
        else => &image.index,
    };
}

fn content_type_of(image: *const Image, scenario: Scenario, name: []const u8) []const u8 {
    const item = pick(image, scenario, name).?;
    if (item == &image.index or item == &image.index_nomatch or item == &image.index_layermedia) {
        return image.families.index;
    }
    if (item == &image.index_media) return media_unknown;
    return image.families.manifest;
}

fn not_found(out: *Answer) void {
    out.status = 404;
    out.body = "404 page not found";
}

fn missing_blob(out: *Answer) void {
    out.status = 404;
    out.content_type = "application/json";
    out.body = "{\"errors\":[{\"code\":\"BLOB_UNKNOWN\",\"message\":\"blob unknown\"}]}";
}

fn missing(out: *Answer) void {
    out.status = 404;
    out.content_type = "application/json";
    out.body = "{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\",\"message\":\"manifest unknown\"}]}";
}

fn broken(out: *Answer) void {
    out.status = 503;
    out.content_type = "text/plain";
    out.body = "Service Unavailable";
}

fn limited(out: *Answer) void {
    out.status = 429;
    out.retry_after = "30";
    out.content_type = "application/json";
    out.body =
        \\{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your pull rate limit."}]}
    ;
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;

fn ask(fixture: *Fixture, target: []const u8, bearer: []const u8, out: *Answer) void {
    fixture.answer(.{ .host = "registry.test", .target = target, .bearer = bearer }, out);
}

test "the open repository answers an index, and the manifests by digest" {
    // Goal: tags give the index, digests give what they name, and the digest header is the
    // digest of the body.
    var fixture: Fixture = undefined;
    fixture.init("http://registry.test", "http://other.test");
    var out: Answer = .{};
    ask(&fixture, "/v2/fixture/open/manifests/3.20", "", &out);
    try testing.expectEqual(@as(u16, 200), out.status);
    try testing.expectEqualStrings(media_oci_index, out.content_type);
    try testing.expectEqualStrings(&fixture.oci.index.digest, out.content_digest);
    var sum: [32]u8 = undefined;
    Sha256.hash(out.body, &sum, .{});
    const hex = std.fmt.bytesToHex(sum, .lower);
    try testing.expectEqualStrings(out.content_digest[7..], &hex);

    var target: [128]u8 = undefined;
    const amd64 = &fixture.oci.amd64.digest;
    const by_digest = try std.fmt.bufPrint(&target, "/v2/fixture/open/manifests/{s}", .{amd64});
    ask(&fixture, by_digest, "", &out);
    try testing.expectEqualStrings(media_oci_manifest, out.content_type);
    try testing.expectEqualStrings(fixture.oci.amd64.slice(), out.body);
    ask(&fixture, "/v2/fixture/open/manifests/sha256:0000", "", &out);
    try testing.expectEqual(@as(u16, 404), out.status);
}

test "the token flow: a challenge, a token, then the manifest" {
    // Goal: bearer repositories refuse without the token and name the realm; the token endpoint
    // hands the token out; a wrong token is called invalid.
    var fixture: Fixture = undefined;
    fixture.init("http://registry.test", "http://other.test");
    var out: Answer = .{};
    ask(&fixture, "/v2/fixture/bearer/manifests/1", "", &out);
    try testing.expectEqual(@as(u16, 401), out.status);
    const realm = "Bearer realm=\"http://registry.test/token\"";
    try testing.expect(std.mem.startsWith(u8, out.www_authenticate, realm));
    try testing.expect(std.mem.indexOf(u8, out.www_authenticate, "invalid_token") == null);
    ask(&fixture, "/v2/fixture/bearer/manifests/1", "wrong", &out);
    try testing.expect(std.mem.indexOf(u8, out.www_authenticate, "invalid_token") != null);
    ask(&fixture, "/token?service=fixture.registry&scope=repository:fixture/bearer:pull", "", &out);
    try testing.expectEqual(@as(u16, 200), out.status);
    try testing.expect(std.mem.indexOf(u8, out.body, token_text) != null);
    ask(&fixture, "/v2/fixture/bearer/manifests/1", token_text, &out);
    try testing.expectEqual(@as(u16, 200), out.status);
    ask(&fixture, "/v2/fixture/limited/manifests/1", token_text, &out);
    try testing.expectEqual(@as(u16, 429), out.status);
    try testing.expectEqualStrings("30", out.retry_after);
    ask(&fixture, "/token?scope=repository%3Afixture%2Fdenied%3Apull", "", &out);
    try testing.expectEqual(@as(u16, 401), out.status);
    ask(&fixture, "/token?scope=repository%3Afixture%2Ftokenlimited%3Apull", "", &out);
    try testing.expectEqual(@as(u16, 429), out.status);
}

test "the faults: wrong digest, cut body, huge, redirects, missing" {
    // Goal: each fault is what its name says.
    var fixture: Fixture = undefined;
    fixture.init("http://registry.test", "http://other.test");
    var out: Answer = .{};
    var target: [160]u8 = undefined;
    const amd64 = &fixture.oci.amd64.digest;
    const by_digest = try std.fmt.bufPrint(&target, "/v2/fixture/badsum/manifests/{s}", .{amd64});
    ask(&fixture, by_digest, "", &out);
    try testing.expect(!std.mem.eql(u8, out.body, fixture.oci.amd64.slice()));
    try testing.expectEqual(fixture.oci.amd64.len, out.body.len);
    ask(&fixture, "/v2/fixture/badindex/manifests/1", "", &out);
    try testing.expectEqualStrings(&fixture.oci.index.digest, out.content_digest);
    try testing.expect(!std.mem.eql(u8, out.body, fixture.oci.index.slice()));
    ask(&fixture, "/v2/fixture/cut/manifests/1", "", &out);
    try testing.expectEqual(@as(?u64, fixture.oci.index.len), out.content_length);
    try testing.expectEqual(@as(?u64, fixture.oci.index.len / 2), out.deliver);
    ask(&fixture, "/v2/fixture/huge/manifests/1", "", &out);
    try testing.expectEqual(@as(?u64, huge_declared_bytes), out.content_length);
    ask(&fixture, "/v2/fixture/redirect/manifests/1", "", &out);
    try testing.expectEqual(@as(u16, 307), out.status);
    try testing.expectEqualStrings("/v2/fixture/open/manifests/1", out.location);
    ask(&fixture, "/v2/fixture/redirectfar/manifests/1", token_text, &out);
    try testing.expectEqualStrings("http://other.test/v2/fixture/open/manifests/1", out.location);
    ask(&fixture, "/v2/fixture/missing/manifests/1", "", &out);
    try testing.expectEqual(@as(u16, 404), out.status);
    ask(&fixture, "/v2/elsewhere/open/manifests/1", "", &out);
    try testing.expectEqual(@as(u16, 404), out.status);
}
