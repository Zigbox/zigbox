//! A build step's cache key (docs/briefs/M7-build.md, "The cache"): BLAKE3 over a canonical,
//! length-prefixed encoding of everything the step can see. The encoding itself, the preimage,
//! is kept beside the output in the cache entry, so M8 can write provenance without rebuilding.
//!
//! What it holds, in this order, each field once: the step-format version, the platform, the
//! base's tree digest and its config's `env`, the input tree's digest, each needed step's name
//! (its mount is `/in/<name>`) and output tree digest sorted by name, the argv, the build file's
//! `env` for the step, `network`, and the fixed environment, `ZBX_BUILD_STEP` included. What it
//! leaves out: the step's position in the file, the file's other text, file times, the host,
//! the time. A needed step enters by its output's digest, not its key, so a rebuild that makes
//! the same bytes stops there.
//!
//! Every field starts with a tag byte; every string is a u32 length (little-endian) and its
//! bytes, every list a u32 count and its strings. No field can then be read as another, and no
//! two different steps encode to the same bytes.
//!
//! Pure: no host, no store. Zigcube's C8 computes the same keys from the same `Spec`.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const digest_mod = @import("../store/digest.zig");

const Digest = digest_mod.Digest;

pub const magic = "zbx-build-key\x00";

/// A step this key's step needs: the name it is mounted under and its output tree.
pub const Need = struct {
    name: []const u8,
    output: Digest,
};

/// Everything a step sees, resolved: the build file's text plus what the store says.
pub const Spec = struct {
    /// `linux/amd64` or `linux/arm64`: the platform the base was pulled for.
    platform: []const u8,
    base_tree: Digest,
    /// The base image's `env`, in the image's order.
    base_env: []const []const u8,
    input_tree: Digest,
    /// In any order; the key sorts them by name.
    needs: []const Need,
    argv: []const []const u8,
    /// The build file's `env` for the step, in the file's order (a later entry wins in the
    /// container, so the order is part of what the step sees).
    env: []const []const u8,
    network: bool,
    /// The step's name: the step sees it as `ZBX_BUILD_STEP`.
    name: []const u8,
};

const Tag = enum(u8) {
    platform = 1,
    base_tree = 2,
    base_env = 3,
    input_tree = 4,
    needs = 5,
    argv = 6,
    env = 7,
    network = 8,
    fixed_env = 9,
    image_adds = 10,
    image_config = 11,
};

/// The fixed environment a step sees after the image's and the build file's, as `KEY=VALUE`.
/// `ZBX_BUILD_STEP=<name>` follows these.
pub const fixed_env = [_][]const u8{
    "HOME=/root",
    "TZ=UTC",
    "LC_ALL=C",
    // The run adds the host's TERM unless the environment sets one, which would make the same
    // key give different outputs on a laptop and on CI.
    "TERM=dumb",
    std.fmt.comptimePrint("SOURCE_DATE_EPOCH={d}", .{constants.build_source_date_epoch}),
};
pub const step_variable = "ZBX_BUILD_STEP=";

/// The preimage of a key, and the key.
pub const Key = struct {
    bytes: [constants.build_key_preimage_bytes_max]u8,
    len: u32,
    digest: Digest,

    pub fn preimage(key: *const Key) []const u8 {
        assert(key.len <= key.bytes.len);
        assert(key.len >= magic.len + 4);
        return key.bytes[0..key.len];
    }
};

pub const Error = error{TooLong};

const Encoder = struct {
    out: []u8,
    len: u32,

    fn bytes(encoder: *Encoder, data: []const u8) Error!void {
        assert(encoder.len <= encoder.out.len);
        if (data.len > encoder.out.len - encoder.len) return error.TooLong;
        @memcpy(encoder.out[encoder.len..][0..data.len], data);
        encoder.len += @intCast(data.len);
    }

    fn int(encoder: *Encoder, value: u32) Error!void {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, value, .little);
        try encoder.bytes(&word);
    }

    fn tag(encoder: *Encoder, value: Tag) Error!void {
        assert(@backingInt(value) > 0);
        try encoder.bytes(&.{@backingInt(value)});
    }

    fn string(encoder: *Encoder, text: []const u8) Error!void {
        assert(text.len <= std.math.maxInt(u32));
        try encoder.int(@intCast(text.len));
        try encoder.bytes(text);
    }

    fn list(encoder: *Encoder, items: []const []const u8) Error!void {
        assert(items.len <= std.math.maxInt(u32));
        try encoder.int(@intCast(items.len));
        for (items) |item| try encoder.string(item);
    }

    fn digest(encoder: *Encoder, value: Digest) Error!void {
        try encoder.bytes(&value.bytes);
    }
};

/// Fills `key` with the preimage of `spec` and its digest. `TooLong` only for a spec past the
/// bounds the build file and the image record already hold (a caller other than the CLI).
pub fn compute(spec: *const Spec, key: *Key) Error!void {
    assert(spec.name.len > 0);
    assert(spec.name.len <= constants.build_step_name_bytes_max);
    assert(spec.argv.len > 0);
    if (spec.needs.len > constants.build_step_needs_max) return error.TooLong;
    var encoder: Encoder = .{ .out = &key.bytes, .len = 0 };
    try encoder.bytes(magic);
    try encoder.int(constants.build_step_format_version);
    try encoder.tag(.platform);
    try encoder.string(spec.platform);
    try encoder.tag(.base_tree);
    try encoder.digest(spec.base_tree);
    try encoder.tag(.base_env);
    try encoder.list(spec.base_env);
    try encoder.tag(.input_tree);
    try encoder.digest(spec.input_tree);
    try encode_needs(&encoder, spec.needs);
    try encoder.tag(.argv);
    try encoder.list(spec.argv);
    try encoder.tag(.env);
    try encoder.list(spec.env);
    try encoder.tag(.network);
    try encoder.bytes(&.{@intFromBool(spec.network)});
    try encoder.tag(.fixed_env);
    try encoder.int(fixed_env.len + 1);
    for (fixed_env) |entry| try encoder.string(entry);
    try encoder.int(@intCast(step_variable.len + spec.name.len));
    try encoder.bytes(step_variable);
    try encoder.bytes(spec.name);
    key.len = encoder.len;
    key.digest = Digest.of(key.preimage());
    assert(key.len > magic.len);
}

/// What the image step sees: the base's tree (the zero digest for no base), each `image.add`
/// in the file's order (a later add merges over the earlier ones, so the order counts) as the
/// source step's output and the destination, and the digest of the image config's encoding.
pub const ImageAdd = struct {
    source: Digest,
    to: []const u8,
};

pub const ImageSpec = struct {
    base_tree: Digest,
    adds: []const ImageAdd,
    /// `Digest.of` the config's bytes (the result record without its tree).
    config: Digest,
};

/// Fills `key` with the preimage of the image step and its digest. The preimage starts with
/// `magic` like a step's, so a cache entry's reader needs one check for both.
pub fn compute_image(spec: *const ImageSpec, key: *Key) Error!void {
    assert(spec.adds.len <= constants.build_image_adds_max);
    var encoder: Encoder = .{ .out = &key.bytes, .len = 0 };
    try encoder.bytes(magic);
    try encoder.int(constants.build_step_format_version);
    try encoder.tag(.base_tree);
    try encoder.digest(spec.base_tree);
    try encoder.tag(.image_adds);
    try encoder.int(@intCast(spec.adds.len));
    for (spec.adds) |add| {
        try encoder.digest(add.source);
        try encoder.string(add.to);
    }
    try encoder.tag(.image_config);
    try encoder.digest(spec.config);
    key.len = encoder.len;
    key.digest = Digest.of(key.preimage());
    assert(key.len > magic.len);
}

/// The needs, sorted by name, each with its mount path's name and output digest. Sorting a
/// copy of six indexes keeps the caller's slice as it is.
fn encode_needs(encoder: *Encoder, needs: []const Need) Error!void {
    assert(needs.len <= constants.build_step_needs_max);
    var order: [constants.build_step_needs_max]u8 = undefined;
    for (order[0..needs.len], 0..) |*slot, index| slot.* = @intCast(index);
    std.mem.sortUnstable(u8, order[0..needs.len], needs, need_less);
    try encoder.tag(.needs);
    try encoder.int(@intCast(needs.len));
    for (order[0..needs.len], 0..) |index, position| {
        const need = needs[index];
        assert(need.name.len > 0);
        // Names are unique within a file; two needs of one name are a caller's bug.
        if (position > 0) assert(need_less(needs, order[position - 1], index));
        try encoder.string(need.name);
        try encoder.digest(need.output);
    }
}

fn need_less(needs: []const Need, a: u8, b: u8) bool {
    return std.mem.order(u8, needs[a].name, needs[b].name) == .lt;
}

comptime {
    assert(constants.build_key_preimage_bytes_max >= constants.build_pool_bytes);
    assert(constants.build_step_format_version > 0);
}

// ---- Tests ------------------------------------------------------------------------------------

const testing = std.testing;

fn sample_digest(byte: u8) Digest {
    var digest: Digest = undefined;
    @memset(&digest.bytes, byte);
    return digest;
}

const sample_needs = [_]Need{
    .{ .name = "notice", .output = undefined },
    .{ .name = "compile", .output = undefined },
};

fn sample(needs: []const Need) Spec {
    return .{
        .platform = "linux/amd64",
        .base_tree = sample_digest(1),
        .base_env = &.{"PATH=/usr/bin:/bin"},
        .input_tree = sample_digest(2),
        .needs = needs,
        .argv = &.{ "go", "build", "-o", "/out/hello", "." },
        .env = &.{ "CGO_ENABLED=0", "GOPROXY=off" },
        .network = false,
        .name = "link",
    };
}

var key_storage: [2]Key = undefined;

fn key_of(spec: *const Spec, slot: u1) !Digest {
    try compute(spec, &key_storage[slot]);
    return key_storage[slot].digest;
}

test "key: the order of needs does not change the key; their outputs do" {
    // Goal: a key is a function of what the step sees, not of the order the file lists needs
    // in. Method: the same needs in both orders, then one output changed.
    var forward = sample_needs;
    forward[0].output = sample_digest(7);
    forward[1].output = sample_digest(8);
    const backward = [_]Need{ forward[1], forward[0] };
    const first = try key_of(&sample(&forward), 0);
    try testing.expect(first.eql(try key_of(&sample(&backward), 1)));
    try testing.expectEqualSlices(u8, key_storage[0].preimage(), key_storage[1].preimage());
    var changed = forward;
    changed[1].output = sample_digest(9);
    try testing.expect(!first.eql(try key_of(&sample(&changed), 1)));
}

test "key: every field it covers changes it" {
    // Goal: no field of `Spec` is left out of the key. Method: change each field alone and
    // check the key differs from the sample's; a field the encoder forgot would compare equal.
    const base = sample(&.{});
    const first = try key_of(&base, 0);
    var variants: [10]Spec = @splat(base);
    variants[0].platform = "linux/arm64";
    variants[1].base_tree = sample_digest(3);
    variants[2].base_env = &.{"PATH=/bin"};
    variants[3].input_tree = sample_digest(4);
    variants[4].needs = &.{.{ .name = "notice", .output = sample_digest(5) }};
    variants[5].argv = &.{ "go", "build", "-o", "/out/hello" };
    variants[6].env = &.{ "GOPROXY=off", "CGO_ENABLED=0" };
    variants[7].network = true;
    variants[8].name = "linker";
    variants[9].base_env = &.{};
    for (&variants) |*variant| {
        try testing.expect(!first.eql(try key_of(variant, 1)));
    }
}

test "key: length prefixes keep neighbouring strings apart" {
    // Goal: moving bytes from one argv entry to the next, or from argv into env, changes the
    // key. Method: two specs whose strings concatenate to the same bytes.
    var a = sample(&.{});
    var b = sample(&.{});
    a.argv = &.{ "sh", "-c", "ab" };
    b.argv = &.{ "sh", "-ca", "b" };
    try testing.expect(!(try key_of(&a, 0)).eql(try key_of(&b, 1)));
    a.argv = &.{ "sh", "X=1" };
    a.env = &.{};
    b.argv = &.{"sh"};
    b.env = &.{"X=1"};
    try testing.expect(!(try key_of(&a, 0)).eql(try key_of(&b, 1)));
}

test "key: the preimage is stable" {
    // Goal: the encoding is the contract a cache entry and M8 rely on; a change to it must be a
    // deliberate one with a new step-format version. Method: a fixed spec's key, checked in.
    const spec = sample(&.{});
    try compute(&spec, &key_storage[0]);
    const preimage = key_storage[0].preimage();
    try testing.expect(std.mem.startsWith(u8, preimage, magic));
    try testing.expect(std.mem.endsWith(u8, preimage, "ZBX_BUILD_STEP=link"));
    const hex = key_storage[0].digest.hex();
    try testing.expectEqualStrings(golden_key_hex, &hex);
}

const golden_key_hex = "194ac22196c404210391daba27f1cf37063c58587354af771b84a9bdf46aab99";

test "key: a spec past the bounds is refused, at the bound it is not" {
    // Goal: an oversized spec from a library caller is an error, never an overflow. Method: an
    // argv entry that fills the preimage exactly would need knowing the overhead, so the test
    // instead grows one entry until it is refused and checks the last accepted one fits.
    var big: [constants.build_key_preimage_bytes_max]u8 = undefined;
    @memset(&big, 'x');
    var spec = sample(&.{});
    var length: usize = constants.build_key_preimage_bytes_max - 512;
    var accepted: usize = 0;
    while (length <= big.len) : (length += 1) {
        const argv = [_][]const u8{big[0..length]};
        spec.argv = &argv;
        compute(&spec, &key_storage[0]) catch {
            break;
        };
        accepted = length;
    }
    try testing.expect(accepted > 0);
    try testing.expect(accepted < big.len);
    try testing.expectEqual(@as(u32, constants.build_key_preimage_bytes_max), key_storage[0].len);
}

test "key: the image key changes with the base, each add, its order and the config" {
    const adds = [_]ImageAdd{
        .{ .source = sample_digest(5), .to = "/usr/bin" },
        .{ .source = sample_digest(6), .to = "/etc" },
    };
    var spec: ImageSpec = .{ .base_tree = sample_digest(1), .adds = &adds, .config = sample_digest(9) };
    const first = try image_key_of(&spec, 0);
    try testing.expect(first.eql(try image_key_of(&spec, 1)));
    try testing.expect(key_storage[0].len > magic.len);
    try testing.expect(std.mem.startsWith(u8, key_storage[0].preimage(), magic));
    var other = spec;
    other.base_tree = sample_digest(2);
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
    other = spec;
    other.config = sample_digest(8);
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
    const moved = [_]ImageAdd{ adds[0], .{ .source = adds[1].source, .to = "/etc/x" } };
    other.adds = &moved;
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
    const swapped = [_]ImageAdd{ adds[1], adds[0] };
    other.adds = &swapped;
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
    const sourced = [_]ImageAdd{ .{ .source = sample_digest(7), .to = "/usr/bin" }, adds[1] };
    other.adds = &sourced;
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
    other.adds = adds[0..1];
    try testing.expect(!first.eql(try image_key_of(&other, 1)));
}

fn image_key_of(spec: *const ImageSpec, slot: u1) !Digest {
    try compute_image(spec, &key_storage[slot]);
    return key_storage[slot].digest;
}
