//! The assertions of the M5 upgrade test (the merged M4 `zbx`, the commit in `old_release.zon`,
//! leaves a store, records and a lock that this `zbx` reads), as pure functions over the text the
//! guest printed, each unit-tested with right and wrong input. The commands that print the text
//! are in upgrade_m5.zig.

const std = @import("std");
const agent_json = @import("agent_json.zig");
const checks = @import("checks.zig");
const m3 = @import("checks_m3.zig");
const m4 = @import("checks_m4.zig");

const Allocator = std.mem.Allocator;
const Streams = checks.Streams;
const PullDoc = m4.PullDoc;

pub const Error = m4.Error || m3.Error || error{
    /// The image's record does not list the tags it must (or lists a digest as a tag).
    TagsWrong,
    /// `lock show` does not name the lock, or the entry differs from what the pull said.
    LockWrong,
    /// Two pulls of one image disagree about it, or the second downloaded what the first stored.
    PullWrong,
    /// A path or a reference could not be built from a digest that is not one.
    DigestWrong,
};

/// What each record on disk says in its `.version` line. M4 wrote image records as version 1 and
/// M5 slice 1 writes version 2 (tags). Run records were version 4 in both; M6 slice 1 wrote
/// version 5 (the network, the forwards and the names of `-e`), slice 2 version 6 (the state
/// volumes), and this zbx still reads M4's and M5's.
pub const image_record_version_m4: u32 = 1;
pub const image_record_version_m5: u32 = 2;
pub const run_record_version_old: u32 = 4;
pub const run_record_version: u32 = 6;

/// The image record for `manifest` (`sha256:<hex>`) in a store at `store_dir`:
/// `<store_dir>/images/<hex>`, as `store/images.zig` names it.
pub fn record_path(buffer: []u8, store_dir: []const u8, manifest: []const u8) Error![]const u8 {
    if (!m4.is_manifest_digest(manifest)) return error.DigestWrong;
    return std.fmt.bufPrint(buffer, "{s}/images/{s}", .{ store_dir, manifest[7..] }) catch {
        return error.DigestWrong;
    };
}

/// `repository@sha256:<hex>`: the reference that names an image by its manifest.
pub fn digest_reference(
    buffer: []u8,
    repository: []const u8,
    manifest: []const u8,
) Error![]const u8 {
    if (!m4.is_manifest_digest(manifest)) return error.DigestWrong;
    if (repository.len == 0) return error.DigestWrong;
    return std.fmt.bufPrint(buffer, "{s}@{s}", .{ repository, manifest }) catch {
        return error.DigestWrong;
    };
}

fn contains(text: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, text, part) != null;
}

/// `zbx --output json store ls` lists the image `pull` made, once, by its manifest: the same tree
/// and platform, exactly `tags` in that order (oldest first; none after a pull by digest, because
/// a digest is never a tag), and `reference` is the newest tag, or null with none. Each of
/// `roots` is listed too.
pub fn check_image_listed(
    arena: Allocator,
    ls: Streams,
    status: u8,
    pull: PullDoc,
    tags: []const []const u8,
    roots: []const []const u8,
) Error!void {
    if (status != 0) return error.ExitCodeWrong;
    const doc = try m4.parse_json(m4.LsDoc, arena, ls.stdout);
    if (!std.mem.eql(u8, doc.schema, "zbx.store.ls/1")) return error.FieldWrong;
    var found: u32 = 0;
    for (doc.images) |image| {
        if (!std.mem.eql(u8, image.manifest, pull.manifest_digest)) continue;
        found += 1;
        if (!std.mem.eql(u8, image.tree, pull.tree)) return error.StoreWrong;
        if (!std.mem.eql(u8, image.platform, pull.platform)) return error.StoreWrong;
        try check_tags(image.reference, image.tags, tags);
    }
    if (found != 1) return error.StoreWrong;
    for (roots) |wanted| {
        var listed = false;
        for (doc.roots) |root| listed = listed or std.mem.eql(u8, root.digest, wanted);
        if (!listed) return error.StoreWrong;
    }
}

fn check_tags(
    reference: ?[]const u8,
    listed: []const []const u8,
    wanted: []const []const u8,
) Error!void {
    if (listed.len != wanted.len) return error.TagsWrong;
    for (listed, wanted) |have, want| {
        if (!std.mem.eql(u8, have, want)) return error.TagsWrong;
        if (contains(have, "@")) return error.TagsWrong;
    }
    if (!m4.reference_is_newest(reference, listed)) return error.TagsWrong;
}

/// `lock show --output json` (`entry` is the one for `pull`'s reference, read by
/// `agent_json.check_lock_show`): the lock is the file at `path`, and its entry holds what the
/// pull printed. This is M4's `zbx.lock`, read by this binary.
pub fn check_lock_entry(shown: agent_json.LockShown, path: []const u8, pull: PullDoc) Error!void {
    if (!std.mem.eql(u8, shown.path, path)) return error.LockWrong;
    if (!std.mem.eql(u8, shown.entry.reference, pull.reference)) return error.LockWrong;
    if (!std.mem.eql(u8, shown.entry.manifest, pull.manifest_digest)) return error.LockWrong;
    if (!std.mem.eql(u8, shown.entry.platform, pull.platform)) return error.LockWrong;
    if (!std.mem.eql(u8, shown.entry.tree, pull.tree)) return error.LockWrong;
}

/// Two pulls of one image, the second made by another binary: the same manifest, platform, tree
/// and blobs, and the second downloaded nothing, because the first left every blob in the store.
pub fn check_same_image(first: PullDoc, second: PullDoc) Error!void {
    if (!std.mem.eql(u8, first.manifest_digest, second.manifest_digest)) return error.PullWrong;
    if (!std.mem.eql(u8, first.platform, second.platform)) return error.PullWrong;
    if (!std.mem.eql(u8, first.tree, second.tree)) return error.PullWrong;
    if (!std.mem.eql(u8, first.config.digest, second.config.digest)) return error.PullWrong;
    if (!std.mem.eql(u8, second.config.cache, "cached")) return error.PullWrong;
    if (first.layers.len != second.layers.len) return error.PullWrong;
    for (first.layers, second.layers) |before, after| {
        if (!std.mem.eql(u8, before.digest, after.digest)) return error.PullWrong;
        if (!std.mem.eql(u8, after.cache, "cached")) return error.PullWrong;
    }
}

/// A record file's version line: `grep -h '\.version' <file>` printed `.version = <n>,`.
pub fn check_record_version(output: []const u8, version: u32) Error!void {
    try m3.check_record_version(output, version);
}

const testing = std.testing;

const hex_a: [64]u8 = @splat('a');
const hex_b: [64]u8 = @splat('b');
const hex_c: [64]u8 = @splat('c');
const manifest_a = "sha256:" ++ hex_a;
const tree = "b3:" ++ hex_b;
const other_tree = "b3:" ++ hex_c;
const tag = "alpine:3.20";

fn pull_doc(comptime cache: []const u8) []const u8 {
    return "{\"schema\":\"zbx.pull/1\",\"reference\":\"alpine:3.20\"," ++
        "\"registry\":\"docker.io\",\"repository\":\"library/alpine\"," ++
        "\"manifest_digest\":\"" ++ manifest_a ++ "\",\"platform\":\"linux/amd64\"," ++
        "\"tree\":\"" ++ tree ++ "\"," ++
        "\"config\":{\"digest\":\"sha256:" ++ hex_b ++ "\",\"cache\":\"" ++ cache ++ "\"}," ++
        "\"layers\":[{\"digest\":\"sha256:" ++ hex_c ++ "\",\"size\":3500000,\"cache\":\"" ++
        cache ++ "\"}],\"files\":19,\"lock\":{\"path\":\"/home/demo/project/zbx.lock\"," ++
        "\"created\":true}}";
}

fn parse_pull(arena: Allocator, comptime cache: []const u8) !PullDoc {
    const text: Streams = .{ .stdout = pull_doc(cache), .stderr = "" };
    return m4.check_pull_json(arena, text, 0, tag);
}

fn ls_doc(comptime image_fields: []const u8) []const u8 {
    return "{\"schema\":\"zbx.store.ls/1\",\"roots\":[" ++
        "{\"digest\":\"" ++ tree ++ "\",\"kind\":\"import\",\"time\":1,\"files\":19," ++
        "\"bytes\":7,\"source\":\"alpine:3.20\",\"parent\":null}," ++
        "{\"digest\":\"" ++ other_tree ++ "\",\"kind\":\"commit\",\"time\":2,\"files\":20," ++
        "\"bytes\":8,\"source\":\"up1\",\"parent\":\"" ++ tree ++ "\"}]," ++
        "\"images\":[{" ++ image_fields ++ "\"manifest\":\"" ++ manifest_a ++
        "\",\"platform\":\"linux/amd64\",\"tree\":\"" ++ tree ++ "\",\"time\":1}]}";
}

const tagged = ls_doc("\"reference\":\"alpine:3.20\",\"tags\":[\"alpine:3.20\"],");
const untagged = ls_doc("\"reference\":null,\"tags\":[],");

fn streams_of(text: []const u8) Streams {
    return .{ .stdout = text, .stderr = "" };
}

test "the store lists the image an older zbx pulled, with its tag, and its roots" {
    // Goal: the upgrade test's `store ls`. Right: the tagged record and both roots. Wrong: a
    // tag that is missing, an extra one, a digest spelled as a tag, another tree, a missing
    // root, a missing image, a failed command.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const pull = try parse_pull(arena, "downloaded");
    const roots = [_][]const u8{ tree, other_tree };
    try check_image_listed(arena, streams_of(tagged), 0, pull, &.{tag}, &roots);
    try check_image_listed(arena, streams_of(untagged), 0, pull, &.{}, &roots);
    const missing = check_image_listed(arena, streams_of(untagged), 0, pull, &.{tag}, &roots);
    try testing.expectError(error.TagsWrong, missing);
    const extra = check_image_listed(arena, streams_of(tagged), 0, pull, &.{}, &roots);
    try testing.expectError(error.TagsWrong, extra);
    const pair = [_][]const u8{ tag, "alpine:3" };
    const two = check_image_listed(arena, streams_of(tagged), 0, pull, &pair, &roots);
    try testing.expectError(error.TagsWrong, two);
    const spelled = ls_doc("\"reference\":\"alpine@" ++ manifest_a ++ "\",\"tags\":[\"alpine@" ++
        manifest_a ++ "\"],");
    const as_tag = "alpine@" ++ manifest_a;
    const digest_tag = check_image_listed(arena, streams_of(spelled), 0, pull, &.{as_tag}, &roots);
    try testing.expectError(error.TagsWrong, digest_tag);
    const stale = ls_doc("\"reference\":\"alpine:3.19\",\"tags\":[\"alpine:3.20\"],");
    const reference_wrong = check_image_listed(arena, streams_of(stale), 0, pull, &.{tag}, &roots);
    try testing.expectError(error.TagsWrong, reference_wrong);
    const no_root = [_][]const u8{ tree, "b3:" ++ hex_a };
    const absent = check_image_listed(arena, streams_of(tagged), 0, pull, &.{tag}, &no_root);
    try testing.expectError(error.StoreWrong, absent);
    const failed = check_image_listed(arena, streams_of(tagged), 1, pull, &.{tag}, &roots);
    try testing.expectError(error.ExitCodeWrong, failed);
    const nothing = check_image_listed(arena, streams_of(""), 0, pull, &.{}, &.{});
    try testing.expectError(error.JsonWrong, nothing);
}

test "an image of another tree or manifest is not the one the older zbx pulled" {
    // Goal: the record is found by manifest and must hold the pull's tree; two records for one
    // manifest cannot happen and are refused.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const pull = try parse_pull(arena, "downloaded");
    var moved = pull;
    moved.tree = other_tree;
    const wrong_tree = check_image_listed(arena, streams_of(tagged), 0, moved, &.{tag}, &.{});
    try testing.expectError(error.StoreWrong, wrong_tree);
    moved = pull;
    moved.manifest_digest = "sha256:" ++ hex_c;
    const wrong_manifest = check_image_listed(arena, streams_of(tagged), 0, moved, &.{tag}, &.{});
    try testing.expectError(error.StoreWrong, wrong_manifest);
    moved = pull;
    moved.platform = "linux/arm64";
    const wrong_platform = check_image_listed(arena, streams_of(tagged), 0, moved, &.{tag}, &.{});
    try testing.expectError(error.StoreWrong, wrong_platform);
}

test "the lock M4 wrote is shown with the pull's entry at the project's path" {
    // Goal: `lock show` reads M4's zbx.lock. Wrong: another path, another digest, no entry.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const pull = try parse_pull(arena, "downloaded");
    const path = "/home/demo/project/zbx.lock";
    const text = "{\"schema\":\"zbx.lock/1\",\"path\":\"" ++ path ++ "\",\"images\":[" ++
        "{\"reference\":\"alpine:3.20\",\"manifest\":\"" ++ manifest_a ++
        "\",\"platform\":\"linux/amd64\",\"tree\":\"" ++ tree ++ "\"}]}\n";
    const shown = try agent_json.check_lock_show(arena, streams_of(text), 0, tag);
    try check_lock_entry(shown, path, pull);
    try testing.expectError(error.LockWrong, check_lock_entry(shown, "/tmp/zbx.lock", pull));
    var moved = pull;
    moved.tree = other_tree;
    try testing.expectError(error.LockWrong, check_lock_entry(shown, path, moved));
    moved = pull;
    moved.manifest_digest = "sha256:" ++ hex_c;
    try testing.expectError(error.LockWrong, check_lock_entry(shown, path, moved));
    moved = pull;
    moved.platform = "linux/arm64";
    try testing.expectError(error.LockWrong, check_lock_entry(shown, path, moved));
    const absent = agent_json.check_lock_show(arena, streams_of(text), 0, "alpine:3.19");
    try testing.expectError(error.LockWrong, absent);
}

test "a second pull by another binary is the same image and downloads nothing" {
    // Goal: this zbx finds the blobs the older one left. Wrong: another tree, a layer that was
    // downloaded again, a layer list that differs.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const first = try parse_pull(arena, "downloaded");
    const again = try parse_pull(arena, "cached");
    try check_same_image(first, again);
    try testing.expectError(error.PullWrong, check_same_image(first, first));
    var moved = again;
    moved.tree = other_tree;
    try testing.expectError(error.PullWrong, check_same_image(first, moved));
    moved = again;
    moved.manifest_digest = "sha256:" ++ hex_c;
    try testing.expectError(error.PullWrong, check_same_image(first, moved));
    moved = again;
    moved.layers = &.{};
    try testing.expectError(error.PullWrong, check_same_image(first, moved));
    var layers = [_]m4.Layer{.{ .digest = "sha256:" ++ hex_a, .size = 1, .cache = "cached" }};
    moved = again;
    moved.layers = &layers;
    try testing.expectError(error.PullWrong, check_same_image(first, moved));
}

test "record paths and digest references are built from manifest digests only" {
    // Goal: a path or a reference is never built from text that is not a digest. Boundary: the
    // buffer is one byte short.
    var buffer: [256]u8 = undefined;
    const path = try record_path(&buffer, "/s", manifest_a);
    try testing.expectEqualStrings("/s/images/" ++ hex_a, path);
    try testing.expectError(error.DigestWrong, record_path(&buffer, "/s", "b3:" ++ hex_a));
    try testing.expectError(error.DigestWrong, record_path(&buffer, "/s", "sha256:abc"));
    try testing.expectEqual(@as(usize, 74), path.len);
    var short: [73]u8 = undefined;
    try testing.expectError(error.DigestWrong, record_path(&short, "/s", manifest_a));
    const spelled = try digest_reference(&buffer, "alpine", manifest_a);
    try testing.expectEqualStrings("alpine@" ++ manifest_a, spelled);
    try testing.expectError(error.DigestWrong, digest_reference(&buffer, "", manifest_a));
    try testing.expectError(error.DigestWrong, digest_reference(&buffer, "alpine", "sha256:x"));
}

test "a record's version line is read as it is written" {
    // Goal: the text an older zbx wrote (see store/images.zig's real M4 text), not what this
    // code renders. Wrong: the other version.
    const old = ".{\n    .version = 1,\n    .reference = \"alpine:3.20\",\n}\n";
    try check_record_version(old, image_record_version_m4);
    try testing.expectError(error.LineMissing, check_record_version(old, image_record_version_m5));
    try check_record_version("    .version = 4,\n", run_record_version_old);
    try check_record_version("    .version = 6,\n", run_record_version);
    try testing.expectError(
        error.LineMissing,
        check_record_version("    .version = 4,\n", run_record_version),
    );
}

// Text captured from a real run of this demo in the KVM guest (vm run 40728292575, the M4 binary
// built from cd5adbc and this one): not what the code above is believed to print.
const real_manifest = "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";
const real_tree = "b3:2e478596e56b3c0f1748d14e505d5d289ead0bb0526cbd53b325baff01afe599";
const real_child = "b3:8d9d08cc7873038b9fb7fb6403f4e36c17db9f0b9374cea00061564f425336be";
const real_pull = "{\"schema\":\"zbx.pull/1\",\"reference\":\"alpine:3.20\"," ++
    "\"registry\":\"docker.io\",\"repository\":\"library/alpine\"," ++
    "\"manifest_digest\":\"" ++ real_manifest ++ "\"," ++
    "\"platform\":\"linux/amd64\",\"tree\":\"" ++ real_tree ++ "\",\"config\":{\"digest\":" ++
    "\"sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731\"," ++
    "\"cache\":\"downloaded\"},\"layers\":[{\"digest\":\"sha256:25f1d6b1951ac8eb3740558fe94cb83d" ++
    "377bdadf95fd9f98b50d2e1b96130471\",\"size\":3630321,\"cache\":\"downloaded\"}]," ++
    "\"files\":87,\"directories\":97,\"symlinks\":334,\"bytes\":7802737,\"special_skipped\":0," ++
    "\"xattrs_skipped\":0,\"image\":{\"entrypoint\":[],\"cmd\":[\"/bin/sh\"]," ++
    "\"env\":[\"PATH=/usr" ++
    "/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"workdir\":\"/\",\"user\":" ++
    "\"\"},\"lock\":{\"path\":\"/home/demo/project/zbx.lock\",\"created\":true}}";
const real_roots = "{\"schema\":\"zbx.store.ls/1\",\"roots\":[{\"digest\":\"" ++ real_tree ++
    "\",\"kind\":\"import\",\"time\":1793205847,\"files\":87,\"bytes\":7802737,\"source\":" ++
    "\"alpine:3.20\",\"parent\":null},{\"digest\":\"" ++ real_child ++ "\",\"kind\":\"commit\"," ++
    "\"time\":1793205847,\"files\":88,\"bytes\":7802746,\"source\":\"up1\",\"parent\":\"" ++
    real_tree ++ "\"}],\"images\":[";
const real_image = "\"manifest\":\"" ++ real_manifest ++ "\",\"platform\":\"linux/amd64\"," ++
    "\"tree\":\"" ++ real_tree ++ "\",\"time\":1793205847}]}";
const real_tagged = real_roots ++ "{\"reference\":\"alpine:3.20\",\"tags\":[\"alpine:3.20\"]," ++
    real_image;
const real_untagged = real_roots ++ "{\"reference\":null,\"tags\":[]," ++ real_image;
const real_lock = "{\"schema\":\"zbx.lock/1\",\"path\":\"/home/demo/project/zbx.lock\"," ++
    "\"images\":[{\"reference\":\"alpine:3.20\",\"manifest\":\"" ++ real_manifest ++
    "\",\"platform\":\"linux/amd64\",\"tree\":\"" ++ real_tree ++ "\"}]}\n";

test "text the M4 binary and this one printed in the guest passes the checks" {
    // Goal: the fixtures above are real output. Right: each check on it. Wrong: the tagged
    // listing where none is wanted, and the untagged where one is.
    var state = std.heap.ArenaAllocator.init(testing.allocator);
    defer state.deinit();
    const arena = state.allocator();
    const pull = try m4.check_pull_json(arena, streams_of(real_pull), 0, tag);
    const roots = [_][]const u8{ real_tree, real_child };
    try check_image_listed(arena, streams_of(real_tagged), 0, pull, &.{tag}, &roots);
    try check_image_listed(arena, streams_of(real_untagged), 0, pull, &.{}, &roots);
    const stale = check_image_listed(arena, streams_of(real_untagged), 0, pull, &.{tag}, &roots);
    try testing.expectError(error.TagsWrong, stale);
    const extra = check_image_listed(arena, streams_of(real_tagged), 0, pull, &.{}, &roots);
    try testing.expectError(error.TagsWrong, extra);
    const shown = try agent_json.check_lock_show(arena, streams_of(real_lock), 0, tag);
    try check_lock_entry(shown, "/home/demo/project/zbx.lock", pull);
    var buffer: [128]u8 = undefined;
    const path = try record_path(&buffer, "/s", pull.manifest_digest);
    try testing.expectEqualStrings("/s/images/" ++ real_manifest[7..], path);
}
