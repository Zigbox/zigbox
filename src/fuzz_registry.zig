//! The `registry` fuzzer: `zig build fuzz -- registry`. The pull code reads what a registry sends,
//! which is untrusted, so each iteration attacks one reader of it, chosen by the seed:
//!
//!   1. `challenge`: a `WWW-Authenticate` header (random, or a real one with edits). The parser
//!      never crashes; a challenge it accepts has a realm, and the token URL built from it either
//!      fits its buffer or is refused as too long, and always starts with the realm.
//!   2. `document`: a manifest or index (the test registry's, with edits). The reader never
//!      crashes; what it accepts has a size and a sha256 digest in every descriptor it returns,
//!      at most the layers and entries the bounds allow, and every layer a known kind.
//!   3. `resolve`: the whole client against the test registry whose answers are cut, failed or
//!      changed by the seed. The integrity property: a resolve that succeeds returns exactly the
//!      digest of the platform manifest the registry really has, whatever was changed on the
//!      way, because every manifest is hashed before it is used. It never makes more requests
//!      than one flow and one repeat, and a failure is always an E05xx diagnostic.
//!   4. `upload`: a push to the test registry (any of its faults, with or without a mount from a
//!      repository that holds the blobs, in pieces of a random size) whose answers are made worse
//!      by the seed: an error status, a `Location` that is relative, absolute, on another origin
//!      or made of random bytes, a `Range` that is valid, short, not from 0 or malformed, an
//!      error body of random bytes (up to past its bound), and failed and cut requests. The upload
//!      property: a push that succeeds leaves the manifest and both blobs in the registry, and
//!      the manifest was never put before they were there; one that fails is E0555, E0556 or
//!      another E05xx code, never a crash.

const std = @import("std");
const assert = std.debug.assert;
const auth = @import("registry/auth.zig");
const client_mod = @import("registry/client.zig");
const codes = @import("diag/codes.zig");
const constants = @import("constants.zig");
const manifest = @import("registry/manifest.zig");
const net = @import("registry/net.zig");
const net_sim = @import("registry/net_sim.zig");
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const images = @import("store/images.zig");
const import_mod = @import("store/import.zig");
const layout = @import("store/layout.zig");
const pack = @import("push/pack.zig");
const push_registry = @import("registry/push_registry.zig");
const support = @import("store/test_support.zig");
const credentials_mod = @import("push/credentials.zig");
const upload = @import("push/upload.zig");
const reference_mod = @import("registry/reference.zig");
const test_registry = @import("registry/test_registry.zig");
const Diag = @import("diag/diag.zig").Diag;

const input_bytes_max = 4096;

var workspace: client_mod.Workspace = undefined;
var registry: test_registry.TestRegistry = undefined;
var registry_ready = false;

fn fixture() *test_registry.TestRegistry {
    if (!registry_ready) {
        registry.init();
        registry_ready = true;
    }
    return &registry;
}

const interesting = "\"',=; \t\\/:?&#%\x00\xff{}[]0aA";

/// Applies a few random edits to `buffer[0..length]`; returns the new length.
fn mutate(random: std.Random, buffer: []u8, length_in: usize) usize {
    var length = length_in;
    const edits = random.intRangeAtMost(u8, 1, 6);
    for (0..edits) |_| {
        if (length == 0) break;
        const at = random.uintLessThan(usize, length);
        switch (random.uintLessThan(u8, 5)) {
            0 => buffer[at] = interesting[random.uintLessThan(usize, interesting.len)],
            1 => buffer[at] = random.int(u8),
            2 => {
                @memmove(buffer[at .. length - 1], buffer[at + 1 .. length]);
                length -= 1;
            },
            3 => length = at,
            else => if (length < buffer.len) {
                @memmove(buffer[at + 1 .. length + 1], buffer[at..length]);
                buffer[at] = interesting[random.uintLessThan(usize, interesting.len)];
                length += 1;
            },
        }
    }
    return length;
}

const challenges = [_][]const u8{
    "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"," ++
        "scope=\"repository:library/alpine:pull\"",
    "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:o/i:pull\"",
    "Basic realm=\"x\", Bearer realm=\"https://a/t\", service=s, error=\"invalid_token\"",
    "bearer realm = \"https://a/t?x=1\" , scope=\"a b\"",
};

fn fuzz_challenge(random: std.Random) void {
    var buffer: [constants.registry_challenge_bytes_max]u8 = undefined;
    var length: usize = 0;
    if (random.uintLessThan(u8, 4) == 0) {
        length = random.uintAtMost(usize, 120);
        random.bytes(buffer[0..length]);
    } else {
        const sample = challenges[random.uintLessThan(usize, challenges.len)];
        @memcpy(buffer[0..sample.len], sample);
        length = mutate(random, &buffer, sample.len);
    }
    const found = auth.parse_challenge(buffer[0..length]) catch return;
    assert(found.realm.len > 0);
    var url: [constants.registry_url_bytes_max * 2]u8 = undefined;
    const built = auth.token_url(&found, "library/alpine", &url) catch return;
    assert(std.mem.startsWith(u8, built, found.realm));
    assert(std.mem.indexOf(u8, built, "scope=") != null);
    for (built[found.realm.len..]) |byte| {
        assert(byte > 0x20);
        assert(byte < 0x7f);
    }
}

fn fuzz_document(random: std.Random) void {
    const items = &fixture().fixture.oci;
    const samples = [_][]const u8{
        items.index.slice(),       items.amd64.slice(),            items.index_nomatch.slice(),
        items.index_media.slice(), items.amd64_layermedia.slice(),
    };
    var buffer: [input_bytes_max]u8 = undefined;
    const sample = samples[random.uintLessThan(usize, samples.len)];
    @memcpy(buffer[0..sample.len], sample);
    const length = if (random.boolean()) mutate(random, &buffer, sample.len) else sample.len;
    var arena_storage: [constants.registry_json_arena_bytes]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&arena_storage);
    var problem: manifest.Problem = .{};
    const content_type: ?[]const u8 = if (random.boolean()) manifest.media_oci_index else null;
    const text = buffer[0..length];
    const parsed = manifest.parse_document(arena.allocator(), text, content_type, &problem);
    const document = parsed catch return;
    if (document.media.is_index()) {
        var offered: manifest.Offered = .{};
        const arch: manifest.Architecture = if (random.boolean()) .amd64 else .arm64;
        const chosen = manifest.select_platform(&document, arch, &offered, &problem) catch return;
        assert(offered.listed <= offered.total);
        if (chosen) |selected| {
            assert(selected.size > 0);
            assert(selected.size <= constants.registry_manifest_bytes_max);
        }
        return;
    }
    var resolved: manifest.Resolved = undefined;
    manifest.read_manifest(&document, &resolved, &problem) catch return;
    assert(resolved.layer_count <= constants.registry_layers_max);
    assert(resolved.config_size > 0);
    for (resolved.layers[0..resolved.layer_count]) |layer| assert(layer.size > 0);
}

/// Serves the test registry and changes what a seed says to change: the bytes of any body.
const Meddler = struct {
    inner: net_sim.Responder,
    random: std.Random,
    flip_per_mille: u16,
    scratch: [input_bytes_max]u8 = undefined,

    fn responder(meddler: *Meddler) net_sim.Responder {
        return .{ .context = meddler, .answer = answer };
    }

    fn answer(
        context: *anyopaque,
        request: *const net.Request,
        received: []const u8,
        served: *net_sim.Served,
    ) void {
        const meddler: *Meddler = @ptrCast(@alignCast(context));
        meddler.inner.answer(meddler.inner.context, request, received, served);
        if (served.status != 200) return;
        if (served.body.len == 0 or served.body.len > meddler.scratch.len) return;
        if (meddler.random.uintLessThan(u16, 1000) >= meddler.flip_per_mille) return;
        @memcpy(meddler.scratch[0..served.body.len], served.body);
        const at = meddler.random.uintLessThan(usize, served.body.len);
        meddler.scratch[at] ^= @as(u8, 1) << meddler.random.int(u3);
        served.body = meddler.scratch[0..served.body.len];
    }
};

fn fuzz_resolve(random: std.Random, seed: u64) void {
    const scenarios = [_]test_registry.Scenario{
        .open, .bearer, .docker, .redirect, .single, .redirectfar,
    };
    const scenario = scenarios[random.uintLessThan(usize, scenarios.len)];
    var meddler: Meddler = .{
        .inner = fixture().responder(),
        .random = random,
        .flip_per_mille = random.uintLessThan(u16, 600),
    };
    var wire: net_sim.SimNet = undefined;
    wire.init(seed, meddler.responder());
    wire.faults.fail_per_mille = random.uintLessThan(u16, 200);
    wire.faults.cut_per_mille = random.uintLessThan(u16, 200);
    wire.faults.chunk_bytes_max = random.intRangeAtMost(u32, 1, 600);
    var text: [96]u8 = undefined;
    const format = "registry.test/fixture/{s}:3.20";
    // Cannot fail: the buffer holds the longest scenario name.
    const written = std.fmt.bufPrint(&text, format, .{@tagName(scenario)}) catch unreachable;

    var reference: reference_mod.Reference = undefined;
    reference_mod.parse(written, &reference) catch unreachable; // A fixed, valid reference.
    var client = client_mod.Client.init(wire.interface(), &workspace, "x86_64");
    var resolved: manifest.Resolved = undefined;
    var diag: Diag = undefined;
    diag.reset();
    if (client_mod.resolve(&client, &reference, &resolved, &diag)) |_| {
        // The integrity property: only the genuine platform manifest can be accepted.
        const image = fixture().fixture.image(scenario);
        assert(std.mem.eql(u8, &resolved.manifest_digest.text(), &image.amd64.digest));
        assert(resolved.layer_count == 2);
    } else |_| {
        const code = diag.code.?;
        assert(std.mem.startsWith(u8, @tagName(code), "E05"));
        assert(diag.last_cause() != null);
    }
    assert(wire.requests <= 40);
}

/// A store with one packed image, made once and kept; the registry and the wire are new each time.
const Pushing = struct {
    host: host_sim.HostSim,
    files: fs_sim.SimFs,
    store: layout.Store,
    imports: import_mod.Workspace,
    packing: pack.Workspace,
    uploading: upload.Workspace,
    wire: net_sim.SimNet,
    registry: push_registry.PushRegistry,
    settings: images.Settings,
    made: pack.Packed,
};

var pushing: ?*Pushing = null;

fn pushing_ready() *Pushing {
    if (pushing) |ready| return ready;
    const rig = std.heap.page_allocator.create(Pushing) catch @panic("out of memory");
    rig.host.init(1, &.{});
    rig.files.init(1);
    rig.host.store_fs = &rig.files;
    rig.files.put_dir("/data", 0o755);
    support.make_store_directories(&rig.files, "/data/store");
    rig.store.at(rig.host.interface(), "/data/store");
    support.make_source(&rig.files, 0);
    rig.settings.clear();
    var diag: Diag = undefined;
    diag.reset();
    var result: import_mod.Result = undefined;
    const options: import_mod.Options = .{ .squash_owner = false, .warn = null };
    import_mod.import(&rig.store, &rig.imports, "/src", options, &result, &diag) catch {
        @panic("the fuzzer's source does not import");
    };
    const input: pack.Input = .{ .tree = result.digest, .settings = &rig.settings, .labels = null };
    var failure: pack.Failure = undefined;
    rig.packing.piece = 4096;
    pack.pack(&rig.store, &rig.packing, input, &rig.made, &failure) catch {
        @panic("the fuzzer's image does not pack");
    };
    pushing = rig;
    return rig;
}

/// Serves the push registry and makes one answer in a few worse.
const Spoiler = struct {
    inner: net_sim.Responder,
    random: std.Random,
    spoil_per_mille: u16,
    /// How many answers were made worse: a registry that lies can leave a blob it never stored.
    spoiled: u32 = 0,
    location: [location_bytes]u8 = undefined,
    /// Where junk is made before it is copied into `location`.
    scratch: [location_bytes]u8 = undefined,
    range: [range_bytes]u8 = undefined,
    body: [constants.push_error_body_bytes + 64]u8 = undefined,

    const location_bytes = 400;
    const range_bytes = 64;

    fn responder(spoiler: *Spoiler) net_sim.Responder {
        return .{ .context = spoiler, .answer = answer };
    }

    fn answer(
        context: *anyopaque,
        request: *const net.Request,
        received: []const u8,
        served: *net_sim.Served,
    ) void {
        const spoiler: *Spoiler = @ptrCast(@alignCast(context));
        spoiler.inner.answer(spoiler.inner.context, request, received, served);
        if (spoiler.random.uintLessThan(u16, 1000) >= spoiler.spoil_per_mille) return;
        spoiler.spoiled += 1;
        switch (spoiler.random.uintLessThan(u8, 4)) {
            0 => {
                const statuses = [_]u16{ 400, 401, 403, 404, 416, 429, 500, 503 };
                served.status = statuses[spoiler.random.uintLessThan(usize, statuses.len)];
            },
            1 => spoiler.spoil_location(served),
            2 => spoiler.spoil_range(served),
            else => spoiler.spoil_body(served),
        }
    }

    fn text(spoiler: *Spoiler, buffer: []u8, parts: []const []const u8) []const u8 {
        _ = spoiler;
        var at: usize = 0;
        for (parts) |part| {
            const count = @min(part.len, buffer.len - at);
            @memcpy(buffer[at..][0..count], part[0..count]);
            at += count;
        }
        return buffer[0..at];
    }

    /// A `Location` that is valid, odd or hostile.
    fn spoil_location(spoiler: *Spoiler, served: *net_sim.Served) void {
        const random = spoiler.random;
        const buffer = &spoiler.location;
        const session = "/v2/push/ok/blobs/uploads/1";
        served.location = switch (random.uintLessThan(u8, 10)) {
            0 => "",
            1 => session,
            2 => "https://registry.test" ++ session,
            3 => "https://other.test:8443" ++ session ++ "?state=a",
            4 => "http://registry.test" ++ session, // A downgrade.
            5 => "//other.test" ++ session, // Protocol-relative.
            6 => "v2/push/ok/blobs/uploads/1", // No leading slash.
            7 => spoiler.text(buffer, &.{ "https://", spoiler.junk(&spoiler.scratch), "/x" }),
            8 => spoiler.text(buffer, &.{ "/", spoiler.junk(&spoiler.scratch) }),
            else => spoiler.text(buffer, &.{
                "https://registry.test/",
                spoiler.junk(&spoiler.scratch),
            }),
        };
    }

    /// Random bytes (any byte, or only URL-ish ones) of a random length in `buffer`.
    fn junk(spoiler: *Spoiler, buffer: []u8) []const u8 {
        const random = spoiler.random;
        const length = random.uintAtMost(usize, buffer.len);
        const url_like = random.boolean();
        const alphabet = "abcdef0123456789/:?&=.-_%";
        for (buffer[0..length]) |*byte| {
            byte.* = if (url_like)
                alphabet[random.uintLessThan(usize, alphabet.len)]
            else
                random.int(u8);
        }
        return buffer[0..length];
    }

    /// A `Range` that is valid, short, not from 0 or malformed.
    fn spoil_range(spoiler: *Spoiler, served: *net_sim.Served) void {
        const random = spoiler.random;
        const buffer = &spoiler.range;
        const number = random.int(u64) >> random.uintLessThan(u6, 63);
        const forms = [_][]const u8{
            "", //
            "-", //
            "0-", //
            "-0", //
            "0", //
            "bytes=", //
            "bytes=0-x", //
            "0-x", //
            "5-100", //
            "bytes=1-63", //
            "0--1", //
            " 0-63", //
            "0-63 ", //
            "00-63", //
            "0-63-64", //
            "0-18446744073709551615", //
            "0-18446744073709551616", //
            "0-99999999999999999999999", //
        };
        served.range = switch (random.uintLessThan(u8, 4)) {
            0 => forms[random.uintLessThan(usize, forms.len)],
            1 => std.fmt.bufPrint(buffer, "0-{d}", .{number}) catch unreachable, // 2 + 20 digits.
            2 => std.fmt.bufPrint(buffer, "bytes=0-{d}", .{number}) catch unreachable, // 8 + 20.
            else => spoiler.junk(buffer),
        };
    }

    /// A refusal with an error body of random bytes, a truncated JSON error, or a long one.
    fn spoil_body(spoiler: *Spoiler, served: *net_sim.Served) void {
        const random = spoiler.random;
        const buffer = &spoiler.body;
        const bound = constants.push_error_body_bytes;
        const length = switch (random.uintLessThan(u8, 4)) {
            0 => random.uintAtMost(usize, 64),
            1 => bound - random.uintAtMost(usize, 1),
            2 => bound + random.uintAtMost(usize, 1),
            else => random.uintAtMost(usize, buffer.len),
        };
        const json = "{\"errors\":[{\"code\":\"BLOB_UPLOAD_INVALID\",\"message\":\"x\"}]}";
        const shape = random.uintLessThan(u8, 4);
        if (shape == 0) {
            random.bytes(buffer[0..length]);
        } else {
            @memset(buffer[0..length], ' ');
            const kept = @min(length, random.uintAtMost(usize, json.len));
            @memcpy(buffer[0..kept], json[0..kept]); // Cut anywhere, even inside the key.
            if (shape == 3 and length > 8) @memcpy(buffer[length - 8 ..][0..8], "\"code\":\"");
        }
        const statuses = [_]u16{ 400, 404, 416, 429, 500, 503 };
        served.status = statuses[random.uintLessThan(usize, statuses.len)];
        served.content_type = "application/json";
        served.body = buffer[0..length];
        served.content_length = null;
    }
};

/// Pushes to a repository that holds both blobs, with no faults: a mount may come from it.
fn seed_holder(rig: *Pushing, holder: []const u8) void {
    assert(holder.len > 0);
    var report: upload.Report = undefined;
    var diag: Diag = undefined;
    diag.reset();
    const source: upload.Destination = .{
        .origin = .{ .scheme = .https, .host = push_registry.registry_host, .port = 443 },
        .repository = holder,
        .tag = "v1",
    };
    const wire = rig.wire.interface();
    upload.push(&rig.store, &rig.uploading, wire, source, &rig.made, .{}, &report, &diag) catch
        @panic("a push with no fault failed");
}

const secret = "fz-secret-password";

/// The bytes a fuzzed challenge or token answer is made of: the real syntax, a realm the rule
/// refuses, one it allows, and noise.
const challenge_pieces = [_][]const u8{
    "Bearer ",                 "Basic ",                       "bearer ",
    "realm=\"",                "realm=",                       "https://registry.test/token",
    "https://evil.test/t",     "http://registry.test/t",       "http://127.0.0.1/x",
    "https://user@evil.test/", "\",",                          "service=\"s\"",
    "scope=\"a:b:pull\"",      "error=\"insufficient_scope\"", "\"",
    ",",                       "{\"token\":\"",                "{\"access_token\":\"",
    "\",\"expires_in\":",      "99999999999999999999",         "}",
    "\\u0041",
};

fn fuzz_text(random: std.Random, buffer: []u8) []const u8 {
    var length: usize = 0;
    while (length < buffer.len and random.uintLessThan(u8, 12) != 0) {
        const piece = challenge_pieces[random.uintLessThan(usize, challenge_pieces.len)];
        if (random.uintLessThan(u8, 5) == 0) {
            const noise = @min(random.uintAtMost(usize, 12), buffer.len - length);
            random.bytes(buffer[length..][0..noise]);
            length += noise;
        } else if (length + piece.len <= buffer.len) {
            @memcpy(buffer[length..][0..piece.len], piece);
            length += piece.len;
        }
    }
    return buffer[0..length];
}

/// The memory a fuzzed challenge and token answer live in, for as long as the push.
const Fuzzed = struct {
    challenge: [220]u8 = undefined,
    token_body: [220]u8 = undefined,
};

/// Makes the registry ask for credentials, in a mode picked at random; sometimes it changes its
/// scheme part-way, and sometimes its challenge and its token answer are fuzzed bytes.
fn require_login(rig: *Pushing, random: std.Random, fuzzed: *Fuzzed) void {
    const modes = [_]push_registry.Mode{ .basic, .bearer, .pull_only, .far_realm, .expiring };
    const mode = modes[random.uintLessThan(usize, modes.len)];
    assert(mode != .open);
    rig.registry.require(mode, secret);
    if (random.uintLessThan(u8, 3) == 0) {
        rig.registry.switch_after = random.intRangeAtMost(u32, 1, 8);
        rig.registry.switch_to = if (random.boolean()) .basic else .bearer;
    }
    if (random.uintLessThan(u8, 3) == 0) {
        rig.registry.challenge_override = fuzz_text(random, &fuzzed.challenge);
    }
    if (random.uintLessThan(u8, 3) == 0) {
        rig.registry.token_body_override = fuzz_text(random, &fuzzed.token_body);
    }
}

/// Whether any logged request carried both kinds of credential.
fn sent_both(rig: *const Pushing) bool {
    var index: u32 = 0;
    while (rig.wire.logged(index)) |entry| : (index += 1) {
        if (entry.basic_len > 0 and entry.bearer_len > 0) return true;
    }
    return false;
}

fn fuzz_upload(random: std.Random, seed: u64) void {
    const rig = pushing_ready();
    rig.wire.init(seed, rig.registry.responder());
    rig.registry.init(&rig.wire);
    const fault = random.enumValue(push_registry.Fault);
    var repository: [48]u8 = undefined;
    const name = std.fmt.bufPrint(&repository, "push/{s}", .{@tagName(fault)}) catch
        unreachable; // 48 bytes hold "push/" and the longest fault name
    const holder = "push/ok-src";
    var report: upload.Report = undefined;
    var diag: Diag = undefined;
    if (random.boolean()) seed_holder(rig, holder);
    var spoiler: Spoiler = .{
        .inner = rig.registry.responder(),
        .random = random,
        .spoil_per_mille = random.uintLessThan(u16, 300),
    };
    rig.wire.init(seed, spoiler.responder());
    rig.wire.received = &rig.registry.drained;
    rig.wire.faults.fail_per_mille = random.uintLessThan(u16, 100);
    rig.wire.faults.cut_per_mille = random.uintLessThan(u16, 100);
    const destination: upload.Destination = .{
        .origin = .{ .scheme = .https, .host = push_registry.registry_host, .port = 443 },
        .repository = name,
        .tag = "v1",
    };
    // Half the pushes log in, in a mode the registry picks at random; the secret must not leave.
    var credentials = credentials_mod.Credentials.of(push_registry.test_user, secret);
    defer credentials.wipe();
    var fuzzed: Fuzzed = .{};
    if (random.boolean()) require_login(rig, random, &fuzzed);
    const options: upload.Options = .{
        .chunk_bytes = random.intRangeAtMost(u32, 16, 4096),
        .mount_from = if (random.boolean()) holder else "",
        .credential = if (random.boolean()) .{ .basic = &credentials } else .none,
    };
    diag.reset();
    const store = &rig.store;
    const wire = rig.wire.interface();
    const pushed = upload.push(
        store,
        &rig.uploading,
        wire,
        destination,
        &rig.made,
        options,
        &report,
        &diag,
    );
    if (pushed) |_| {
        const held = &rig.registry.fixture;
        assert(held.has_blob(name, &rig.made.layer.text()));
        assert(held.has_blob(name, &rig.made.config.text()));
        assert(held.tag_digest(name, "v1") != null);
    } else |_| {
        assert(std.mem.startsWith(u8, @tagName(diag.code.?), "E05"));
    }
    // The registry told the truth unless it was spoiled; then a manifest may name a missing blob.
    if (spoiler.spoiled == 0) assert(rig.registry.fixture.unknown_refusals == 0);
    assert(rig.registry.leaked == 0); // a credential reached no host but the registry's
    assert(!sent_both(rig)); // Basic and Bearer are never sent together
    assert(std.mem.indexOf(u8, std.mem.asBytes(&diag), secret) == null);
}

pub fn fuzz_registry(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    switch (random.uintLessThan(u8, 4)) {
        0 => fuzz_challenge(random),
        1 => fuzz_document(random),
        2 => fuzz_upload(random, seed),
        else => fuzz_resolve(random, seed),
    }
}
