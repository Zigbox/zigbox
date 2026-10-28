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

const std = @import("std");
const assert = std.debug.assert;
const auth = @import("registry/auth.zig");
const client_mod = @import("registry/client.zig");
const codes = @import("diag/codes.zig");
const constants = @import("constants.zig");
const manifest = @import("registry/manifest.zig");
const net = @import("registry/net.zig");
const net_sim = @import("registry/net_sim.zig");
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

    fn answer(context: *anyopaque, request: *const net.Request, served: *net_sim.Served) void {
        const meddler: *Meddler = @ptrCast(@alignCast(context));
        meddler.inner.answer(meddler.inner.context, request, served);
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

pub fn fuzz_registry(seed: u64) void {
    var prng = std.Random.Xoshiro256.init(seed);
    const random = prng.random();
    switch (random.uintLessThan(u8, 3)) {
        0 => fuzz_challenge(random),
        1 => fuzz_document(random),
        else => fuzz_resolve(random, seed),
    }
}
