//! The M4 demo's assertions as pure functions over the text the guest printed, each unit-tested
//! with right and wrong input. The commands that print the text are in main_m4.zig.

const std = @import("std");
const checks = @import("checks.zig");
const checks_m3 = @import("checks_m3.zig");

const Streams = checks.Streams;

pub const Error = error{
    ExitCodeWrong,
    /// The digest a pull prints is missing or is not one.
    DigestWrong,
    /// A line the step must print is missing.
    LineMissing,
    /// A refusal that should name both digests does not, or has another code.
    RefusalWrong,
    StderrNotEmpty,
    /// The output is not the JSON document the step expects.
    JsonWrong,
    /// The document parses but a field is missing, empty or of another shape.
    FieldWrong,
    /// The second image costs too much, or shares too little.
    DedupWrong,
    /// The pull killed halfway cut nothing, or the next pull did not resume it.
    ResumeWrong,
    /// An image's tree digest is not how the store, the lock and the pull name it.
    IdentityWrong,
    /// The store an older zbx left is not what this zbx lists, or does not verify.
    StoreWrong,
};

const Allocator = std.mem.Allocator;

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_manifest_digest(text: []const u8) bool {
    if (text.len != 71) return false;
    if (!std.mem.startsWith(u8, text, "sha256:")) return false;
    for (text[7..]) |byte| {
        const hex = (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
        if (!hex) return false;
    }
    return true;
}

/// `zbx pull` prints the manifest digest alone on stdout and exits 0. Warnings may be on stderr.
pub fn check_pull(streams: Streams, status: u8) Error![]const u8 {
    if (status != 0) return error.ExitCodeWrong;
    const digest = std.mem.trim(u8, streams.stdout, " \r\n\t");
    if (!is_manifest_digest(digest)) return error.DigestWrong;
    return digest;
}

/// A run's stdout holds `wanted`, and it ended with 0.
pub fn check_output_has(streams: Streams, status: u8, wanted: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!contains(streams.stdout, wanted)) return error.LineMissing;
}

/// A run's stdout is exactly the line `wanted`.
pub fn check_output_is(streams: Streams, status: u8, wanted: []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, streams.stdout, " \r\n\t"), wanted)) {
        return error.LineMissing;
    }
}

/// The run was refused by `code` (exit 125, nothing on stdout), and its message names each of
/// `digests`.
pub fn check_refusal(
    streams: Streams,
    status: u8,
    code: []const u8,
    digests: []const []const u8,
) Error!void {
    if (status != 125) return error.ExitCodeWrong;
    if (streams.stdout.len != 0) return error.RefusalWrong;
    if (!contains(streams.stderr, code)) return error.RefusalWrong;
    for (digests) |digest| {
        if (!contains(streams.stderr, digest)) return error.RefusalWrong;
    }
}

// ---- Slice 5: JSON documents, dedup, resume, identity, upgrade ------------------------------

/// The text of `zbx --output json pull`, the members the checks read (`zbx schema pull`).
pub const PullDoc = struct {
    schema: []const u8,
    reference: []const u8,
    manifest_digest: []const u8,
    platform: []const u8,
    tree: []const u8,
    config: Blob,
    layers: []const Layer,
    lock: ?struct { path: []const u8, created: bool } = null,
};

pub const Blob = struct { digest: []const u8, cache: []const u8 };
pub const Layer = struct { digest: []const u8, size: u64, cache: []const u8 };

fn parse_json(comptime T: type, arena: Allocator, text: []const u8) Error!T {
    // Copies: the text is the session's scratch buffer, which the next command overwrites.
    const options: std.json.ParseOptions = .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    };
    return std.json.parseFromSliceLeaky(T, arena, text, options) catch return error.JsonWrong;
}

fn is_cache_word(word: []const u8) bool {
    const words = [_][]const u8{ "cached", "downloaded", "resumed" };
    for (words) |wanted| {
        if (std.mem.eql(u8, word, wanted)) return true;
    }
    return false;
}

/// The pull's JSON on stdout: the schema's name, the reference as typed, a manifest digest, a
/// tree digest, this machine's platform, and a cache word for every blob.
pub fn check_pull_json(
    arena: Allocator,
    streams: Streams,
    status: u8,
    reference: []const u8,
) Error!PullDoc {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_json(PullDoc, arena, streams.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.pull/1")) return error.FieldWrong;
    if (!std.mem.eql(u8, doc.reference, reference)) return error.FieldWrong;
    if (!is_manifest_digest(doc.manifest_digest)) return error.FieldWrong;
    if (!checks_m3.is_digest(doc.tree)) return error.FieldWrong;
    const platforms = [_][]const u8{ "linux/amd64", "linux/arm64" };
    var known = false;
    for (platforms) |platform| known = known or std.mem.eql(u8, doc.platform, platform);
    if (!known) return error.FieldWrong;
    if (!is_manifest_digest(doc.config.digest)) return error.FieldWrong;
    if (!is_cache_word(doc.config.cache)) return error.FieldWrong;
    if (doc.layers.len == 0) return error.FieldWrong;
    for (doc.layers) |layer| {
        if (!is_manifest_digest(layer.digest)) return error.FieldWrong;
        if (!is_cache_word(layer.cache)) return error.FieldWrong;
        if (layer.size == 0) return error.FieldWrong;
    }
    return doc;
}

/// A tag and a digest of the same image are two names of one tree: the same manifest, the same
/// tree digest, and not the same spelling.
pub fn check_alias(first: PullDoc, second: PullDoc) Error!void {
    if (std.mem.eql(u8, first.reference, second.reference)) return error.IdentityWrong;
    if (!std.mem.eql(u8, first.manifest_digest, second.manifest_digest)) return error.IdentityWrong;
    if (!std.mem.eql(u8, first.tree, second.tree)) return error.IdentityWrong;
}

pub const DuImage = struct {
    tags: []const []const u8,
    manifest: []const u8,
    tree: []const u8,
    files: u64,
    logical_bytes: u64,
    compressed_bytes: u64,
    stored_bytes: u64,
    shared_bytes: u64,
};

const DuDoc = struct { schema: []const u8, images: []const DuImage };

/// What the second image costs once the first is stored, as a share of what it was to download:
/// `unique_bytes` (what only it uses) is at most this many percent of its compressed size. The
/// objects are stored whole and uncompressed, and a Python is mostly its own library, so the
/// measured share is about 65 (python 3.13-slim after 3.12-slim: 28.4 MB against 43.3 MB); the
/// bound leaves room for a new patch release and is far from 100, which no sharing would give.
pub const unique_percent_of_compressed_max: u64 = 75;
/// And at least this many percent of the second image's stored bytes are shared (measured: 75).
pub const shared_percent_of_stored_min: u64 = 60;

pub const Dedup = struct {
    unique_bytes: u64,
    compressed_bytes: u64,
    shared_bytes: u64,
    stored_bytes: u64,
};

fn find_image(images: []const DuImage, reference: []const u8) Error!DuImage {
    for (images) |image| {
        if (has_tag(image.tags, reference)) return image;
    }
    return error.DedupWrong;
}

fn has_tag(tags: []const []const u8, reference: []const u8) bool {
    for (tags) |tag| {
        if (std.mem.eql(u8, tag, reference)) return true;
    }
    return false;
}

/// `zbx --output json store du --by-image` after pulling `first` and then `second`: the second
/// costs far less than its compressed size, because most of what it holds is stored once.
/// A ratio, never exact bytes: the images move with every patch release.
pub fn check_dedup(
    arena: Allocator,
    streams: Streams,
    status: u8,
    first_reference: []const u8,
    second_reference: []const u8,
) Error!Dedup {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_json(DuDoc, arena, streams.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.store.du/1")) return error.FieldWrong;
    const first = try find_image(doc.images, first_reference);
    const second = try find_image(doc.images, second_reference);
    if (std.mem.eql(u8, first.tree, second.tree)) return error.DedupWrong;
    if (second.compressed_bytes == 0) return error.DedupWrong;
    if (second.stored_bytes == 0) return error.DedupWrong;
    if (second.shared_bytes > second.stored_bytes) return error.DedupWrong;
    const unique = second.stored_bytes - second.shared_bytes;
    const unique_scaled = unique * 100;
    if (unique_scaled > second.compressed_bytes * unique_percent_of_compressed_max) {
        return error.DedupWrong;
    }
    if (second.shared_bytes * 100 < second.stored_bytes * shared_percent_of_stored_min) {
        return error.DedupWrong;
    }
    return .{
        .unique_bytes = unique,
        .compressed_bytes = second.compressed_bytes,
        .shared_bytes = second.shared_bytes,
        .stored_bytes = second.stored_bytes,
    };
}

/// What `blobs/` held after a pull was killed: one line for each file, `complete <hex>` for
/// `blobs/sha256/<hex>` and `partial <hex> <bytes>` for `blobs/partial/<hex>`.
pub const BlobState = struct {
    hex: []const u8,
    complete: bool,
    partial_bytes: u64,
};

pub fn parse_blob_listing(arena: Allocator, text: []const u8) Error![]const BlobState {
    var states: std.ArrayList(BlobState) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = words.next() orelse return error.ResumeWrong;
        const hex = words.next() orelse return error.ResumeWrong;
        if (hex.len != 64) return error.ResumeWrong;
        // Copied: the listing is the session's scratch buffer, which the next command overwrites.
        const kept = arena.dupe(u8, hex) catch return error.ResumeWrong;
        if (std.mem.eql(u8, kind, "complete")) {
            states.append(arena, .{ .hex = kept, .complete = true, .partial_bytes = 0 }) catch {
                return error.ResumeWrong;
            };
        } else if (std.mem.eql(u8, kind, "partial")) {
            const size_text = words.next() orelse return error.ResumeWrong;
            const size = std.fmt.parseInt(u64, size_text, 10) catch return error.ResumeWrong;
            states.append(arena, .{ .hex = kept, .complete = false, .partial_bytes = size }) catch {
                return error.ResumeWrong;
            };
        } else return error.ResumeWrong;
    }
    return states.items;
}

pub const ResumeFacts = struct { resumed: u32, cached: u32, downloaded: u32 };

fn state_of(states: []const BlobState, digest: []const u8) ?BlobState {
    if (!std.mem.startsWith(u8, digest, "sha256:")) return null;
    for (states) |state| {
        if (std.mem.eql(u8, state.hex, digest[7..])) return state;
    }
    return null;
}

/// The pull that follows one killed halfway (`states` is what the kill left): a blob that was
/// complete is `cached`, so it is not downloaded again; a blob with bytes in `partial/` is
/// `resumed`; at least one blob was cut, or the kill proved nothing.
pub fn check_resume(
    arena: Allocator,
    streams: Streams,
    status: u8,
    reference: []const u8,
    states: []const BlobState,
) Error!ResumeFacts {
    const doc = try check_pull_json(arena, streams, status, reference);
    var cut: u32 = 0;
    for (states) |state| {
        if (!state.complete and state.partial_bytes > 0) cut += 1;
    }
    if (cut == 0) return error.ResumeWrong;
    var facts: ResumeFacts = .{ .resumed = 0, .cached = 0, .downloaded = 0 };
    var blobs: std.ArrayList(Blob) = .empty;
    blobs.append(arena, doc.config) catch return error.ResumeWrong;
    for (doc.layers) |layer| {
        blobs.append(arena, .{ .digest = layer.digest, .cache = layer.cache }) catch {
            return error.ResumeWrong;
        };
    }
    for (blobs.items) |blob| {
        const state = state_of(states, blob.digest);
        if (state) |known| {
            const wanted: []const u8 = if (known.complete) "cached" else "resumed";
            if (!known.complete and known.partial_bytes == 0) continue;
            if (!std.mem.eql(u8, blob.cache, wanted)) return error.ResumeWrong;
        }
        if (std.mem.eql(u8, blob.cache, "resumed")) facts.resumed += 1;
        if (std.mem.eql(u8, blob.cache, "cached")) facts.cached += 1;
        if (std.mem.eql(u8, blob.cache, "downloaded")) facts.downloaded += 1;
    }
    if (facts.resumed == 0) return error.ResumeWrong;
    return facts;
}

const LsDoc = struct {
    schema: []const u8,
    roots: []const struct { digest: []const u8, kind: []const u8, source: []const u8 },
    images: []const struct {
        tags: []const []const u8,
        manifest: []const u8,
        platform: []const u8,
        tree: []const u8,
    },
};

/// The image is its tree: the pull, `store ls` (a record by manifest, and a root) and the lock
/// name the same tree digest for it, and the lock also holds the manifest digest. The record
/// keeps `tag`, the name the image was first pulled as, although it was pulled by digest after.
pub fn check_identity(
    arena: Allocator,
    ls: Streams,
    status: u8,
    pull: PullDoc,
    tag: []const u8,
    lock_text: []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_json(LsDoc, arena, ls.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.store.ls/1")) return error.FieldWrong;
    // The record is keyed by the image, not by the spelling: a pull by digest of the same
    // manifest leaves the one record and every tag it had. So it is found by its manifest, its
    // tree must be the pull's, and it still lists the tag.
    var recorded = false;
    for (doc.images) |image| {
        if (!std.mem.eql(u8, image.manifest, pull.manifest_digest)) continue;
        if (!std.mem.eql(u8, image.tree, pull.tree)) return error.IdentityWrong;
        if (!has_tag(image.tags, tag)) return error.IdentityWrong;
        recorded = true;
    }
    if (!recorded) return error.IdentityWrong;
    var rooted = false;
    for (doc.roots) |root| rooted = rooted or std.mem.eql(u8, root.digest, pull.tree);
    if (!rooted) return error.IdentityWrong;
    if (!contains(lock_text, pull.tree)) return error.IdentityWrong;
    if (!contains(lock_text, pull.manifest_digest)) return error.IdentityWrong;
}

/// The store an older zbx left: `store ls` lists each of `roots` (trees the old binary made).
pub fn check_old_roots(
    arena: Allocator,
    ls: Streams,
    status: u8,
    roots: []const []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_json(LsDoc, arena, ls.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.store.ls/1")) return error.FieldWrong;
    for (roots) |wanted| {
        var found = false;
        for (doc.roots) |root| found = found or std.mem.eql(u8, root.digest, wanted);
        if (!found) return error.StoreWrong;
    }
}

const VerifyDoc = struct { schema: []const u8, ok: bool, damaged: u64, roots: u64 };

/// `zbx --output json store verify` found nothing wrong in at least `roots_min` roots.
pub fn check_verify_ok(
    arena: Allocator,
    streams: Streams,
    status: u8,
    roots_min: u64,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try parse_json(VerifyDoc, arena, streams.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.store.verify/1")) return error.FieldWrong;
    if (!doc.ok) return error.StoreWrong;
    if (doc.damaged != 0) return error.StoreWrong;
    if (doc.roots < roots_min) return error.StoreWrong;
}

/// `store du --by-image` in text: exit 0, and a row that names each of `references`. The numbers
/// are read from the JSON (`check_dedup`), never from this table.
pub fn check_table_lists(streams: Streams, status: u8, references: []const []const u8) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    for (references) |reference| {
        if (!contains(streams.stdout, reference)) return error.LineMissing;
    }
}

/// The script that kills a pull (accept_m4.zig) prints `killed` once it has seen bytes in
/// `blobs/partial/` and sent SIGKILL. Any other word means the pull ended before it could be
/// cut (`finished-before-kill`) or never began a download (`no-partial`).
pub fn check_killed(output: []const u8, status: u8) Error!void {
    if (status != 0) return error.ResumeWrong;
    if (!std.mem.eql(u8, std.mem.trim(u8, output, " \r\n\t"), "killed")) return error.ResumeWrong;
}

/// The layers of `later` that `earlier` does not have: the blobs a pull of `later` has to fetch
/// when `earlier` is stored, in the order of the manifest. At most `out.len` are returned.
pub fn layers_only_in(
    earlier: PullDoc,
    later: PullDoc,
    out: [][]const u8,
) Error![]const []const u8 {
    var count: usize = 0;
    for (later.layers) |layer| {
        var shared = false;
        for (earlier.layers) |known| shared = shared or std.mem.eql(u8, known.digest, layer.digest);
        if (shared) continue;
        if (count == out.len) return error.ResumeWrong;
        out[count] = layer.digest;
        count += 1;
    }
    if (count == 0) return error.ResumeWrong;
    return out[0..count];
}

const testing = std.testing;

const hex_a: [64]u8 = @splat('a');
const hex_0: [64]u8 = @splat('0');
const hex_1: [64]u8 = @splat('1');
const hex_upper: [64]u8 = @splat('A');

test "a pull prints the manifest digest and nothing else" {
    // Goal: right and wrong input of the first step.
    const good = "sha256:" ++ hex_a ++ "\n";
    const ok = try check_pull(.{ .stdout = good, .stderr = "warning[ZBX-W0201]: x\n" }, 0);
    try testing.expectEqualStrings("sha256:" ++ hex_a, ok);
    try testing.expectError(error.ExitCodeWrong, check_pull(.{ .stdout = good, .stderr = "" }, 3));
    try testing.expectError(
        error.DigestWrong,
        check_pull(.{ .stdout = "b3:" ++ hex_a, .stderr = "" }, 0),
    );
    try testing.expectError(
        error.DigestWrong,
        check_pull(.{ .stdout = "sha256:abc\n", .stderr = "" }, 0),
    );
    try testing.expectError(error.DigestWrong, check_pull(.{ .stdout = "", .stderr = "" }, 0));
    const upper = "sha256:" ++ hex_upper;
    try testing.expectError(error.DigestWrong, check_pull(.{ .stdout = upper, .stderr = "" }, 0));
}

test "a run's output is checked as a whole or in part" {
    // Goal: the second and fourth steps.
    const os_release = "NAME=\"Alpine Linux\"\nID=alpine\n";
    try check_output_has(.{ .stdout = os_release, .stderr = "" }, 0, "ID=alpine");
    try testing.expectError(
        error.LineMissing,
        check_output_has(.{ .stdout = os_release, .stderr = "" }, 0, "ID=debian"),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_output_has(.{ .stdout = os_release, .stderr = "" }, 1, "ID=alpine"),
    );
    try check_output_is(
        .{ .stdout = "1267650600228229401496703205376\n", .stderr = "" },
        0,
        "1267650600228229401496703205376",
    );
    try testing.expectError(
        error.LineMissing,
        check_output_is(
            .{ .stdout = "126765060022822940149670320537\n", .stderr = "" },
            0,
            "1267650600228229401496703205376",
        ),
    );
}

test "the refusal of a lock that disagrees names the code and both digests" {
    // Goal: step 5. Right: 125, empty stdout, the code and both digests in the message.
    const expected = "b3:" ++ hex_0;
    const actual = "b3:" ++ hex_1;
    const message = "error[ZBX-E0519]: zbx.lock and the store disagree\n" ++
        "  cause  zbx.lock has tree " ++ expected ++ "; the store has tree " ++ actual ++ "\n";
    const digests = [_][]const u8{ expected, actual };
    try check_refusal(.{ .stdout = "", .stderr = message }, 125, "ZBX-E0519", &digests);
    try testing.expectError(
        error.ExitCodeWrong,
        check_refusal(.{ .stdout = "", .stderr = message }, 1, "ZBX-E0519", &digests),
    );
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "output", .stderr = message }, 125, "ZBX-E0519", &digests),
    );
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "", .stderr = message }, 125, "ZBX-E0520", &digests),
    );
    const one = "error[ZBX-E0519]: x\n  cause  " ++ expected ++ "\n";
    try testing.expectError(
        error.RefusalWrong,
        check_refusal(.{ .stdout = "", .stderr = one }, 125, "ZBX-E0519", &digests),
    );
}

fn pull_json(comptime tree: []const u8, comptime cache: []const u8) []const u8 {
    return pull_json_layers(tree, "cached", cache);
}

fn pull_json_layers(
    comptime tree: []const u8,
    comptime first_cache: []const u8,
    comptime second_cache: []const u8,
) []const u8 {
    return "{\"schema\":\"zbx.pull/1\",\"reference\":\"python:3.13-slim\"," ++
        "\"registry\":\"docker.io\",\"repository\":\"library/python\"," ++
        "\"manifest_digest\":\"sha256:" ++ hex_a ++ "\",\"platform\":\"linux/amd64\"," ++
        "\"tree\":\"" ++ tree ++ "\"," ++
        "\"config\":{\"digest\":\"sha256:" ++ hex_1 ++ "\",\"cache\":\"cached\"}," ++
        "\"layers\":[{\"digest\":\"sha256:" ++ hex_0 ++ "\",\"size\":10,\"cache\":\"" ++
        first_cache ++ "\"},{\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":99," ++
        "\"cache\":\"" ++ second_cache ++ "\"}]," ++
        "\"files\":3,\"lock\":{\"path\":\"/p/zbx.lock\",\"created\":false}}";
}

const tree_a = "b3:" ++ hex_a;
const image313 = "python:3.13-slim";

fn only_stdout(text: []const u8) Streams {
    return .{ .stdout = text, .stderr = "" };
}

test "the pull's JSON is read for its tree, and a wrong shape is refused" {
    // Goal: steps 1 and 3 through `--output json`. Right: a whole document. Wrong: a non-zero
    // exit, another image313, a tree that is a manifest digest, a cache word nobody knows,
    // and text.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const good = only_stdout(pull_json(tree_a, "downloaded"));
    const doc = try check_pull_json(arena, good, 0, image313);
    try testing.expectEqualStrings(tree_a, doc.tree);
    try testing.expectEqual(@as(usize, 2), doc.layers.len);
    try testing.expectError(error.ExitCodeWrong, check_pull_json(arena, good, 1, image313));
    const other = check_pull_json(arena, good, 0, "python:3.12-slim");
    try testing.expectError(error.FieldWrong, other);
    const manifest_as_tree = only_stdout(pull_json("sha256:" ++ hex_a, "downloaded"));
    const swapped = check_pull_json(arena, manifest_as_tree, 0, image313);
    try testing.expectError(error.FieldWrong, swapped);
    const bad_word = only_stdout(pull_json(tree_a, "fetched"));
    try testing.expectError(error.FieldWrong, check_pull_json(arena, bad_word, 0, image313));
    const text = only_stdout("sha256:" ++ hex_a ++ "\n");
    try testing.expectError(error.JsonWrong, check_pull_json(arena, text, 0, image313));
}

test "a tag and a digest name one tree; two trees or one spelling are refused" {
    // Goal: "tags are only aliases". Right: same manifest and tree, two spellings.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const cached = only_stdout(pull_json(tree_a, "cached"));
    const first = try check_pull_json(arena, cached, 0, image313);
    var second = first;
    second.reference = "python@sha256:" ++ hex_a;
    try check_alias(first, second);
    second.tree = "b3:" ++ hex_1;
    try testing.expectError(error.IdentityWrong, check_alias(first, second));
    second.tree = first.tree;
    second.manifest_digest = "sha256:" ++ hex_1;
    try testing.expectError(error.IdentityWrong, check_alias(first, second));
    second.manifest_digest = first.manifest_digest;
    second.reference = first.reference;
    try testing.expectError(error.IdentityWrong, check_alias(first, second));
}

fn du_json(comptime stored: []const u8, comptime shared: []const u8) []const u8 {
    return "{\"schema\":\"zbx.store.du/1\",\"images\":[" ++
        "{\"tags\":[\"python:3.12-slim\"],\"manifest\":\"sha256:" ++ hex_0 ++ "\"," ++
        "\"platform\":\"linux/amd64\",\"tree\":\"b3:" ++ hex_0 ++ "\",\"files\":4413," ++
        "\"logical_bytes\":119829928,\"compressed_bytes\":43517772," ++
        "\"stored_bytes\":115410138,\"shared_bytes\":85862291}," ++
        "{\"tags\":[\"python:3.13-slim\"],\"manifest\":\"sha256:" ++ hex_1 ++ "\"," ++
        "\"platform\":\"linux/amd64\",\"tree\":\"b3:" ++ hex_1 ++ "\",\"files\":4446," ++
        "\"logical_bytes\":118710716,\"compressed_bytes\":43320189," ++
        "\"stored_bytes\":" ++ stored ++ ",\"shared_bytes\":" ++ shared ++ "}]}";
}

test "the second image costs a share of its compressed size, by ratio" {
    // Goal: step 3. Right: the numbers measured for python 3.13-slim after 3.12-slim (28.4 MB
    // unique of 43.3 MB compressed, 75 percent shared). Wrong: nothing shared; a cost above the
    // compressed size; an image that is missing; a bad exit.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const first = "python:3.12-slim";
    const real = only_stdout(du_json("114227815", "85862291"));
    const facts = try check_dedup(arena, real, 0, first, image313);
    try testing.expectEqual(@as(u64, 28365524), facts.unique_bytes);
    try testing.expectError(error.ExitCodeWrong, check_dedup(arena, real, 2, first, image313));
    const alone = only_stdout(du_json("114227815", "0"));
    try testing.expectError(error.DedupWrong, check_dedup(arena, alone, 0, first, image313));
    // 50 MB unique of 43.3 MB compressed is more than the image costs to download.
    const costly = only_stdout(du_json("150000000", "100000000"));
    try testing.expectError(error.DedupWrong, check_dedup(arena, costly, 0, first, image313));
    // At the bound: 75 percent of 43,320,189 is 32,490,141.75, so 32,490,141 passes.
    const edge_in = only_stdout(du_json("132490141", "100000000"));
    _ = try check_dedup(arena, edge_in, 0, first, image313);
    const edge_out = only_stdout(du_json("132490143", "100000000"));
    try testing.expectError(error.DedupWrong, check_dedup(arena, edge_out, 0, first, image313));
    const missing = check_dedup(arena, real, 0, first, "python:3.14-slim");
    try testing.expectError(error.DedupWrong, missing);
    const impossible = only_stdout(du_json("100", "200"));
    try testing.expectError(error.DedupWrong, check_dedup(arena, impossible, 0, first, image313));
}

test "a blob listing is read line by line, and nonsense is refused" {
    // Goal: the kill's evidence is parsed strictly.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const text = "complete " ++ hex_0 ++ "\npartial " ++ hex_a ++ " 4096\n\n";
    const states = try parse_blob_listing(arena, text);
    try testing.expectEqual(@as(usize, 2), states.len);
    try testing.expect(states[0].complete);
    try testing.expectEqual(@as(u64, 4096), states[1].partial_bytes);
    const none = try parse_blob_listing(arena, "");
    try testing.expectEqual(@as(usize, 0), none.len);
    try testing.expectError(error.ResumeWrong, parse_blob_listing(arena, "partial " ++ hex_a));
    try testing.expectError(error.ResumeWrong, parse_blob_listing(arena, "complete abc"));
    try testing.expectError(error.ResumeWrong, parse_blob_listing(arena, "other " ++ hex_a));
    try testing.expectError(
        error.ResumeWrong,
        parse_blob_listing(arena, "partial " ++ hex_a ++ " many"),
    );
}

test "a pull after a kill resumes the cut blob and downloads none that was complete" {
    // Goal: "interrupted pulls resume". The kill left the first layer complete and the second
    // cut. Right: cached, resumed. Wrong: the cut one downloaded again, the complete one
    // downloaded again, and a kill that cut nothing.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const listing = "complete " ++ hex_0 ++ "\npartial " ++ hex_a ++ " 5029888\n";
    const states = try parse_blob_listing(arena, listing);
    const resumed = only_stdout(pull_json(tree_a, "resumed"));
    const facts = try check_resume(arena, resumed, 0, image313, states);
    try testing.expectEqual(@as(u32, 1), facts.resumed);
    try testing.expectEqual(@as(u32, 2), facts.cached);
    const again = only_stdout(pull_json(tree_a, "downloaded"));
    try testing.expectError(error.ResumeWrong, check_resume(arena, again, 0, image313, states));
    const redone = only_stdout(pull_json_layers(tree_a, "downloaded", "resumed"));
    try testing.expectError(error.ResumeWrong, check_resume(arena, redone, 0, image313, states));
    const nothing_cut = try parse_blob_listing(arena, "complete " ++ hex_0 ++ "\n");
    const cached = only_stdout(pull_json(tree_a, "cached"));
    const idle = check_resume(arena, cached, 0, image313, nothing_cut);
    try testing.expectError(error.ResumeWrong, idle);
    const empty_cut = try parse_blob_listing(arena, "partial " ++ hex_a ++ " 0\n");
    const empty = check_resume(arena, resumed, 0, image313, empty_cut);
    try testing.expectError(error.ResumeWrong, empty);
}

fn ls_json(comptime tree: []const u8, comptime image_tree: []const u8) []const u8 {
    return "{\"schema\":\"zbx.store.ls/1\",\"roots\":[{\"digest\":\"" ++ tree ++
        "\",\"kind\":\"import\",\"time\":1,\"files\":3,\"bytes\":9,\"source\":\"x\"," ++
        "\"parent\":null}],\"images\":[{\"tags\":[\"python:3.13-slim\"]," ++
        "\"manifest\":\"sha256:" ++ hex_a ++ "\",\"platform\":\"linux/amd64\"," ++
        "\"tree\":\"" ++ image_tree ++ "\",\"time\":1}]}";
}

test "the pull, the store and the lock name an image by one tree digest" {
    // Goal: "every image is identified by its tree digest". Wrong: the record names another
    // tree, there is no root of that tree, the lock does not have it.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const output = only_stdout(pull_json(tree_a, "cached"));
    const pull = try check_pull_json(arena, output, 0, image313);
    const lock = ".{ .tree = \"" ++ tree_a ++ "\", .manifest = \"sha256:" ++ hex_a ++ "\" }";
    const other = "b3:" ++ hex_1;
    try check_identity(arena, only_stdout(ls_json(tree_a, tree_a)), 0, pull, image313, lock);
    var alias = pull;
    alias.reference = "python@sha256:" ++ hex_a;
    try check_identity(arena, only_stdout(ls_json(tree_a, tree_a)), 0, alias, image313, lock);
    const split = only_stdout(ls_json(tree_a, other));
    const pulled = check_identity(arena, split, 0, pull, image313, lock);
    try testing.expectError(error.IdentityWrong, pulled);
    const rootless = only_stdout(ls_json(other, tree_a));
    const unrooted = check_identity(arena, rootless, 0, pull, image313, lock);
    try testing.expectError(error.IdentityWrong, unrooted);
    const good = only_stdout(ls_json(tree_a, tree_a));
    const lock_other = ".{ .tree = \"" ++ other ++ "\", .manifest = \"sha256:" ++ hex_a ++ "\" }";
    const moved = check_identity(arena, good, 0, pull, image313, lock_other);
    try testing.expectError(error.IdentityWrong, moved);
    const bad_exit = check_identity(arena, good, 1, pull, image313, lock);
    try testing.expectError(error.ExitCodeWrong, bad_exit);
    // The tag the record lost (the M4 behaviour: a pull by digest replaced it) is refused.
    const renamed = check_identity(arena, good, 0, pull, "python:3.12-slim", lock);
    try testing.expectError(error.IdentityWrong, renamed);
}

test "the roots an older zbx left are listed, and a store that verifies clean is ok" {
    // Goal: the upgrade test. Wrong: a root missing; a damaged store; too few roots.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const ls = only_stdout(ls_json(tree_a, tree_a));
    try check_old_roots(arena, ls, 0, &.{tree_a});
    const absent = check_old_roots(arena, ls, 0, &.{ tree_a, "b3:" ++ hex_1 });
    try testing.expectError(error.StoreWrong, absent);
    const clean = only_stdout("{\"schema\":\"zbx.store.verify/1\",\"ok\":true," ++
        "\"objects\":5,\"damaged\":0,\"trees\":2,\"roots\":2}");
    try check_verify_ok(arena, clean, 0, 2);
    try testing.expectError(error.StoreWrong, check_verify_ok(arena, clean, 0, 3));
    const damaged = only_stdout("{\"schema\":\"zbx.store.verify/1\",\"ok\":false," ++
        "\"damaged\":1,\"roots\":2}");
    try testing.expectError(error.StoreWrong, check_verify_ok(arena, damaged, 0, 2));
    try testing.expectError(error.ExitCodeWrong, check_verify_ok(arena, clean, 2, 2));
}

test "the kill script must say it killed a pull that had bytes" {
    // Goal: a pull that finished first, or never downloaded, proves nothing about resuming.
    try check_killed("killed\n", 0);
    try testing.expectError(error.ResumeWrong, check_killed("finished-before-kill\n", 3));
    try testing.expectError(error.ResumeWrong, check_killed("no-partial", 4));
    try testing.expectError(error.ResumeWrong, check_killed("finished-before-kill\n", 0));
    try testing.expectError(error.ResumeWrong, check_killed("killed\n", 1));
}

test "the layers to cut are those the earlier image lacks" {
    // Goal: only blobs that no stored image shares are deleted before the kill. Right: the
    // second layer is the later image's own. Wrong: none of its own; more than the buffer.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const output = only_stdout(pull_json(tree_a, "cached"));
    const earlier = try check_pull_json(arena, output, 0, image313);
    var later = earlier;
    const own = [_]Layer{
        earlier.layers[0],
        .{ .digest = "sha256:" ++ hex_1, .size = 5, .cache = "cached" },
    };
    later.layers = &own;
    var buffer: [4][]const u8 = undefined;
    const only = try layers_only_in(earlier, later, &buffer);
    try testing.expectEqual(@as(usize, 1), only.len);
    try testing.expectEqualStrings("sha256:" ++ hex_1, only[0]);
    try testing.expectError(error.ResumeWrong, layers_only_in(earlier, earlier, &buffer));
    var none: [0][]const u8 = .{};
    try testing.expectError(error.ResumeWrong, layers_only_in(earlier, later, &none));
}

test "the text table names each image" {
    // Goal: step 3's table is shown and has a row per image; the numbers are the JSON's.
    const table = "image   files\npython:3.12-slim 4413\npython:3.13-slim 4446\n";
    const rows = [_][]const u8{ "python:3.12-slim", "python:3.13-slim" };
    try check_table_lists(.{ .stdout = table, .stderr = "" }, 0, &rows);
    try testing.expectError(
        error.LineMissing,
        check_table_lists(.{ .stdout = "python:3.12-slim\n", .stderr = "" }, 0, &rows),
    );
    try testing.expectError(
        error.ExitCodeWrong,
        check_table_lists(.{ .stdout = table, .stderr = "" }, 1, &rows),
    );
}
