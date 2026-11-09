//! Tests of `zbx verify` and `zbx trust export|import|prune` (`verify_commands.zig`,
//! `trust_commands.zig`) against the simulated host and store: the links, the refusals, the
//! round trip of a bundle, and that none of it touches the network. The diagnostics' own text is
//! in the golden tests; the record-level rules are in `peer_tests.zig`.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const fs_sim = @import("../store/fs_sim.zig");
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const net_sim = @import("../registry/net_sim.zig");
const sim_run = @import("../runtime/sim_run.zig");
const support = @import("../store/test_support.zig");
const roots = @import("../store/roots.zig");
const test_util = @import("../test_util.zig");
const Diag = @import("../diag/diag.zig").Diag;
const fs_mod = @import("../store/fs.zig");
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const result = @import("../build/result.zig");
const Digest = @import("../store/digest.zig").Digest;

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};
const signatures = support.user_store ++ "/trust/signatures";
const bundle_path = "/home/alice/bundle.jsonl";

/// The big pieces live on the heap: the static data of the test binary is limited to 2 GiB.
const World = struct {
    sim: host_sim.HostSim,
    files: fs_sim.SimFs,
    wire: net_sim.SimNet,
    import_work: import.Workspace,
};

var world: *World = undefined;
var sim: *host_sim.HostSim = undefined;
var files: *fs_sim.SimFs = undefined;
var wire: *net_sim.SimNet = undefined;
var store: layout.Store = undefined;
var tree: Digest = undefined;

fn refuse_everything(
    _: *anyopaque,
    _: *const @import("../registry/net.zig").Request,
    _: []const u8,
    served: *net_sim.Served,
) void {
    served.status = 500;
}

var responder_context: u8 = 0;

/// A store holding the sample tree `/src`, signed by the key `ci`, on a host whose network
/// counts its requests.
fn start() !void {
    world = try std.heap.page_allocator.create(World);
    errdefer std.heap.page_allocator.destroy(world);
    sim = &world.sim;
    files = &world.files;
    wire = &world.wire;
    sim.init(1, &.{});
    files.init(1);
    wire.init(1, .{ .context = &responder_context, .answer = refuse_everything });
    sim.wire = wire;
    sim.store_fs = files;
    sim.environment_variables = &home;
    support.make_user_store(files, ".{\n    .format = 1,\n}\n");
    support.make_source(files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &world.import_work, "/src", options, &made, &diag);
    tree = made.digest;
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "ci", "--no-passphrase" }));
}

fn command(args: []const [:0]const u8) u8 {
    var items: [12][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(sim, items[0 .. 1 + args.len]);
}

fn has(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// The tree's digest as text a command line can carry.
var tree_text: [constants.store_digest_text_bytes:0]u8 = undefined;

fn tree_operand() [:0]const u8 {
    @memcpy(tree_text[0..constants.store_digest_text_bytes], &tree.text());
    tree_text[constants.store_digest_text_bytes] = 0;
    return &tree_text;
}

fn sign_tree() !void {
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", tree_operand() }));
}

/// The path of the tree's signature record.
fn record_path(buffer: *[512]u8) []const u8 {
    const text = tree.text();
    const name = text[3..]; // Without "b3:".
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ signatures, name }) catch unreachable; // Short.
}

fn finish() void {
    std.heap.page_allocator.destroy(world);
}

/// Requests the simulated network was asked for: verify and trust never make one.
fn requests() u32 {
    return wire.requests;
}

test "verify passes a signed tree offline, and says so in text and JSON" {
    // Goal: the plain path and the no-network rule. Method: sign, verify naming the key, in
    // both modes; the network sees no request and stderr stays empty.
    try start();
    defer finish();
    try sign_tree();
    try testing.expectEqual(@as(u8, 0), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "1 signatures: ok"));
    try testing.expect(has(sim.stdout(), "2 signer: ok"));
    try testing.expect(has(sim.stdout(), "3 tree: ok"));
    try testing.expectEqualStrings("", sim.stderr());
    try testing.expectEqual(@as(u8, 0), command(&.{
        "verify", tree_operand(), "--key", "ci", "--output", "json",
    }));
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    try testing.expect(has(sim.stdout(), "\"schema\":\"zbx.verify/1\""));
    try testing.expect(has(sim.stdout(), "\"ok\":true"));
    try testing.expectEqual(@as(u32, 0), requests());
}

test "verify refuses with one line of cause when a link is broken" {
    // Goal: each refusal names its link. Method: no signature; a signer nobody trusts; a
    // required provenance that is not there. Each exits 1 with E0908 and the report before it.
    try start();
    defer finish();
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand() }));
    try testing.expect(has(sim.stderr(), "ZBX-E0908"));
    try testing.expect(has(sim.stdout(), "1 signatures: FAILED"));
    try sign_tree();
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand() }));
    try testing.expect(has(sim.stdout(), "2 signer: FAILED"));
    try testing.expect(has(sim.stdout(), "3 tree: not reached"));
    const strict = command(&.{ "verify", tree_operand(), "--key", "ci", "--require-provenance" });
    try testing.expectEqual(@as(u8, 1), strict);
    try testing.expect(has(sim.stdout(), "4 provenance: FAILED"));
    try testing.expect(has(sim.stderr(), "ZBX-E0908"));
    try testing.expectEqual(@as(u32, 0), requests());
}

test "a record with a byte flipped does not verify" {
    // Goal: tampering with the record is refused as damage, not a crash. Method: flip one byte in
    // the stored record, verify.
    try start();
    defer finish();
    try sign_tree();
    var buffer: [512]u8 = undefined;
    files.flip_byte(record_path(&buffer), 40);
    // A damaged record is the store's fault, not the tree's: exit 2 and E0903, not E0908.
    try testing.expectEqual(@as(u8, 2), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    try testing.expect(has(sim.stderr(), "ZBX-E0903"));
}

test "a bundle exported from one record imports into a store that lost it" {
    // Goal: the round trip. Method: export, delete the record, import the bundle, verify; then
    // import it again (nothing new) and a corrupted copy (refused, record unchanged).
    try start();
    defer finish();
    try sign_tree();
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "export", tree_operand() }));
    const exported = try testing.allocator.dupe(u8, sim.stdout());
    defer testing.allocator.free(exported);
    try testing.expect(exported.len > 0);
    var buffer: [512]u8 = undefined;
    files.remove_path(record_path(&buffer));
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    files.put_file(bundle_path, 0o644, exported);
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "import", bundle_path }));
    try testing.expect(has(sim.stdout(), "imported "));
    try testing.expect(has(sim.stdout(), "1 new signature"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "import", bundle_path }));
    try testing.expect(has(sim.stdout(), "0 new signature"));
    const damaged = try testing.allocator.dupe(u8, exported);
    defer testing.allocator.free(damaged);
    damaged[60] ^= 1;
    files.remove_path(bundle_path);
    files.put_file(bundle_path, 0o644, damaged);
    const before = files.content_of(record_path(&buffer)).?;
    const kept = try testing.allocator.dupe(u8, before);
    defer testing.allocator.free(kept);
    try testing.expectEqual(@as(u8, 1), command(&.{ "trust", "import", bundle_path }));
    try testing.expect(has(sim.stderr(), "ZBX-E0909"));
    try testing.expectEqualStrings(kept, files.content_of(record_path(&buffer)).?);
    try testing.expectEqual(@as(u32, 0), requests());
}

test "trust export of a tree with no record, and import of a missing file, refuse" {
    // Goal: the two E0909 entrances that are not a bad bundle. Method: export an unsigned tree,
    // import a path that is not there.
    try start();
    defer finish();
    try testing.expectEqual(@as(u8, 1), command(&.{ "trust", "export", tree_operand() }));
    try testing.expect(has(sim.stderr(), "ZBX-E0909"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "trust", "import", "/home/alice/nothing" }));
    try testing.expect(has(sim.stderr(), "ZBX-E0909"));
}

test "prune lists nothing on a sound store and reports the JSON schema" {
    // Goal: the dry run on a store with no orphans. Method: sign, prune in both modes.
    try start();
    defer finish();
    try sign_tree();
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "prune" }));
    try testing.expect(has(sim.stdout(), "0 orphan"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "prune", "--output", "json" }));
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    try testing.expect(has(sim.stdout(), "\"schema\":\"zbx.trust-prune/1\""));
    try testing.expect(has(sim.stdout(), "\"orphans\":0"));
    try testing.expectEqual(@as(u32, 0), requests());
}

/// Collects the unreachable tree: drops the root the import made, then plans and confirms a gc.
fn collect_garbage() !void {
    try roots.remove(&store, tree);
    try testing.expectEqual(@as(u8, 0), command(&.{ "store", "gc", "--output", "json" }));
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
    defer parsed.deinit();
    const plan = parsed.value.object.get("plan").?.string;
    var hash: [constants.store_digest_text_bytes:0]u8 = undefined;
    @memcpy(hash[0..plan.len], plan);
    hash[plan.len] = 0;
    try testing.expectEqual(@as(u8, 0), command(&.{ "store", "gc", "--confirm", &hash }));
}

test "prune removes the records of trees that gc moved away, and gc says they are there" {
    // Goal: the orphan life cycle. Method: sign a tree no root keeps, gc it away; gc then
    // counts one orphan (JSON field and text line naming prune); prune lists it without
    // removing; `--apply` removes it; the verify of the gone tree is refused.
    try start();
    defer finish();
    try sign_tree();
    try testing.expectEqual(@as(u8, 0), command(&.{ "store", "gc", "--output", "json" }));
    try testing.expect(has(sim.stdout(), "\"trust_orphans\":0"));
    try collect_garbage();
    try testing.expectEqual(@as(u8, 0), command(&.{ "store", "gc", "--output", "json" }));
    try testing.expect(has(sim.stdout(), "\"trust_orphans\":1"));
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    try testing.expectEqual(@as(u8, 0), command(&.{ "store", "gc" }));
    try testing.expect(has(sim.stdout(), "zbx trust prune"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "prune" }));
    try testing.expect(has(sim.stdout(), "orphan signature "));
    try testing.expect(has(sim.stdout(), "1 orphan"));
    var buffer: [512]u8 = undefined;
    try testing.expect(files.kind_of(record_path(&buffer)) != null);
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "prune", "--apply" }));
    try testing.expect(files.kind_of(record_path(&buffer)) == null);
    try testing.expectEqual(@as(u8, 0), command(&.{ "trust", "prune", "--output", "json" }));
    try testing.expect(has(sim.stdout(), "\"orphans\":0"));
    try testing.expectEqual(@as(u32, 0), requests());
}

// ---- Links 2 to 6 ----

const project = "/proj";
const build_text = "build file, as signed\n";
const lock_text = "lock, as signed\n";
const policy_path = "/home/alice/.config/zbx/policy.zon";
var provenance_record: provenance.Record = undefined;
var provenance_bytes: [constants.statement_bytes_max]u8 = undefined;
var result_bytes: [constants.build_result_bytes_max]u8 = undefined;
var result_text: [constants.store_digest_text_bytes:0]u8 = undefined;

/// Makes `/proj` the working directory, holding the build file and the lock as the provenance
/// will say they were.
fn make_project() !void {
    files.put_dir(project, 0o755);
    files.put_file(project ++ "/zbx.build.zon", 0o644, build_text);
    files.put_file(project ++ "/zbx.lock", 0o644, lock_text);
    try testing.expect(sim.world.processes[0].cwd.set(project));
}

/// A second tree, which is no input of anything unless a test makes it one: its only file has
/// content no other object in the store has.
fn import_other() !Digest {
    files.put_dir("/other", 0o755);
    files.put_file("/other/file", 0o644, "content only the other tree has\n");
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &world.import_work, "/other", options, &made, &diag);
    return made.digest;
}

/// Stores a result of the sample tree (`label` tells two results of it apart) and a provenance
/// record for it whose single base is `base`, whose steps run over the sample tree, and whose
/// build file is `build_file`; signs it with `ci`. The result's digest as an operand.
fn sign_built(label: []const u8, base: Digest, build_file: []const u8) ![:0]const u8 {
    var saved: result.Record = undefined;
    saved.config.clear();
    if (label.len > 0) _ = saved.config.add_label("label", label).?;
    saved.tree = tree;
    var failed: result.Failure = undefined;
    const digest = try result.save(&store, &saved, &result_bytes, &failed);
    const made = &provenance_record;
    made.clear();
    made.tree = tree.bytes;
    made.result = digest.bytes;
    made.set_build_file(build_file);
    made.build_file_digest = Digest.of(build_text).bytes;
    made.lock = Digest.of(lock_text).bytes;
    const filled: provenance.Digest = @splat(0x5a);
    const at = made.add_base("alpine:3.20", filled, base.bytes);
    const step = made.add_step("compile");
    step.base = at;
    step.key = filled;
    step.input = tree.bytes;
    step.output = tree.bytes;
    step.network = false;
    made.image_key = filled;
    made.image_base = at;
    made.set_version("0.4.0", "linux/amd64");
    made.zbx = filled;
    made.started = 1000;
    made.finished = 1042;
    const bytes = provenance.render(&provenance_bytes, made);
    var saving: fs_mod.Failure = undefined;
    try provenance_store.save(&store, digest, bytes, &saving);
    @memcpy(result_text[0..constants.store_digest_text_bytes], &digest.text());
    result_text[constants.store_digest_text_bytes] = 0;
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &result_text, "--key", "ci" }));
    return &result_text;
}

fn verify_built(operand: [:0]const u8, extra: []const [:0]const u8) u8 {
    var items: [8][:0]const u8 = undefined;
    items[0] = "verify";
    items[1] = operand;
    @memcpy(items[2 .. 2 + extra.len], extra);
    return command(items[0 .. 2 + extra.len]);
}

/// The path of the object holding `content`.
fn object_of(content: []const u8) []const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (files.kind_of(path) != .file) continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (std.mem.endsWith(u8, path, ".chunks")) continue;
        if (std.mem.eql(u8, files.content_of(path).?, content)) return path;
    }
    unreachable;
}

test "verify walks links 4 to 6 of a signed build, and says what it checked" {
    // Goal: the full chain passes. Method: a result with signed provenance whose inputs are in
    // the store and whose build file and lock are in the working directory.
    try start();
    defer finish();
    try make_project();
    const operand = try sign_built("", tree, "zbx.build.zon");
    try testing.expectEqual(@as(u8, 0), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "4 provenance: ok (stored record: same)"));
    try testing.expect(has(sim.stdout(), "5 inputs: ok (1 trees checked, 0 not in the store)"));
    try testing.expect(has(sim.stdout(), "6 build_file: ok (build file: ok, zbx.lock: ok)"));
    try testing.expectEqualStrings("", sim.stderr());
    try testing.expectEqual(@as(u8, 0), verify_built(operand, &.{
        "--key", "ci", "--strict", "--require-provenance", "--output", "json",
    }));
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    try testing.expect(has(sim.stdout(), "\"build_file\":\"ok\",\"lock\":\"ok\""));
    try testing.expectEqual(@as(u32, 0), requests());
}

test "an absent input is W0903 and exit 0, and E0908 under --strict" {
    // Goal: the absent-input rule. Method: a base tree the store does not hold.
    try start();
    defer finish();
    try make_project();
    const operand = try sign_built("", Digest.of("a base nobody pulled"), "zbx.build.zon");
    try testing.expectEqual(@as(u8, 0), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stderr(), "ZBX-W0903"));
    try testing.expect(has(sim.stdout(), "5 inputs: ok (1 trees checked, 1 not in the store)"));
    try testing.expectEqual(@as(u8, 1), verify_built(operand, &.{ "--key", "ci", "--strict" }));
    try testing.expect(has(sim.stderr(), "ZBX-E0908"));
    try testing.expect(has(sim.stderr(), "the base alpine:3.20"));
    try testing.expect(has(sim.stdout(), "5 inputs: FAILED"));
    try testing.expect(has(sim.stdout(), "6 build_file: not reached"));
}

test "a damaged input is E0908 without --strict, not W0903" {
    // Goal: damage is never absence. Method: a base tree that is in the store, one of whose
    // objects has a byte flipped.
    try start();
    defer finish();
    try make_project();
    const other = try import_other();
    const operand = try sign_built("", other, "zbx.build.zon");
    files.flip_byte(object_of("content only the other tree has\n"), 3);
    try testing.expectEqual(@as(u8, 1), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stderr(), "ZBX-E0908"));
    try testing.expect(has(sim.stderr(), "is damaged in the store"));
    try testing.expect(!has(sim.stderr(), "W0903"));
    try testing.expect(has(sim.stdout(), "5 inputs: FAILED"));
}

test "link 3 breaks on a flipped object byte of the verified tree" {
    // Goal: the tree is hashed, not trusted. Method: flip a byte of one of its objects.
    try start();
    defer finish();
    try sign_tree();
    files.flip_byte(object_of("#!shell\n"), 1);
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "3 tree: FAILED"));
    try testing.expect(has(sim.stderr(), "ZBX-E0908"));
}

test "a changed build file or lock is E0908, and one that is not there is reported" {
    // Goal: link 6. Method: change each file, then remove them.
    try start();
    defer finish();
    try make_project();
    const operand = try sign_built("", tree, "zbx.build.zon");
    files.remove_path(project ++ "/zbx.build.zon");
    files.put_file(project ++ "/zbx.build.zon", 0o644, "another build file\n");
    try testing.expectEqual(@as(u8, 1), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "6 build_file: FAILED"));
    try testing.expect(has(sim.stderr(), "the build file differs from what was signed"));
    files.remove_path(project ++ "/zbx.build.zon");
    files.put_file(project ++ "/zbx.build.zon", 0o644, build_text);
    files.remove_path(project ++ "/zbx.lock");
    files.put_file(project ++ "/zbx.lock", 0o644, "another lock\n");
    try testing.expectEqual(@as(u8, 1), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "6 build_file: FAILED"));
    try testing.expect(has(sim.stderr(), "zbx.lock differs from what was signed"));
    files.remove_path(project ++ "/zbx.build.zon");
    files.remove_path(project ++ "/zbx.lock");
    try testing.expectEqual(@as(u8, 0), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "6 build_file: skipped"));
}

test "a build file path too long for the store's path buffer skips link 6, and does not crash" {
    // Goal: the `undefined` path the review found. Method: a working directory of 250 bytes and
    // a relative build file name of 400, so the two together do not fit a path.
    try start();
    defer finish();
    const long_name: [400]u8 = @splat('b');
    const operand = try sign_built("", tree, &long_name);
    var directory: [250]u8 = undefined;
    @memset(&directory, 'd');
    directory[0] = '/';
    try testing.expect(sim.world.processes[0].cwd.set(&directory));
    try testing.expectEqual(@as(u8, 0), verify_built(operand, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "6 build_file: skipped"));
    try testing.expect(has(sim.stdout(), "5 inputs: ok"));
}

/// The text of the public half of the key `name`.
fn public_text_of(name: []const u8) !key.PublicText {
    var paths: key_store.Paths = undefined;
    try testing.expect(key_store.locate(sim.interface(), &paths));
    var failure: key_store.Failure = undefined;
    const file = try key_store.read_pub(sim.interface().filesystem(), &paths, name, &failure);
    return key.public_text(file.public);
}

test "--public trusts a key as --key does, when no policy file is present" {
    // Goal: the second spelling. Method: the key's text, and a text of another key.
    try start();
    defer finish();
    try sign_tree();
    const text = try public_text_of("ci");
    var argument: [constants.key_public_text_bytes + 1]u8 = undefined;
    @memcpy(argument[0..text.len], &text);
    argument[text.len] = 0;
    const named: [:0]const u8 = argument[0..text.len :0];
    try testing.expectEqual(@as(u8, 0), command(&.{ "verify", tree_operand(), "--public", named }));
    try testing.expect(has(sim.stdout(), "2 signer: ok"));
    const other = key.public_text(@splat(7));
    var wrong: [constants.key_public_text_bytes + 1]u8 = undefined;
    @memcpy(wrong[0..other.len], &other);
    wrong[other.len] = 0;
    const unknown: [:0]const u8 = wrong[0..other.len :0];
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--public", unknown }));
    try testing.expect(has(sim.stdout(), "2 signer: FAILED"));
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--public", "junk" }));
}

test "a policy file decides trust: --key and --public do not add to it" {
    // Goal: verify agrees with the gate. Method: a policy that lists only another key; `--key ci`
    // must fail link 2. A policy that lists `ci` passes with no flag at all.
    try start();
    defer finish();
    try sign_tree();
    const other = key.public_text(@splat(7));
    var text: [512]u8 = undefined;
    const elsewhere = try std.fmt.bufPrint(
        &text,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"release\", .public = \"{s}\" }} }} }}",
        .{&other},
    );
    files.put_file(policy_path, 0o644, elsewhere);
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "2 signer: FAILED"));
    const public = try public_text_of("ci");
    var argument: [constants.key_public_text_bytes + 1]u8 = undefined;
    @memcpy(argument[0..public.len], &public);
    argument[public.len] = 0;
    const named: [:0]const u8 = argument[0..public.len :0];
    try testing.expectEqual(@as(u8, 1), command(&.{ "verify", tree_operand(), "--public", named }));
    const trusting = try std.fmt.bufPrint(
        &text,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"ci\", .public = \"{s}\" }} }} }}",
        .{&public},
    );
    files.remove_path(policy_path);
    files.put_file(policy_path, 0o644, trusting);
    try testing.expectEqual(@as(u8, 0), command(&.{ "verify", tree_operand() }));
    try testing.expect(has(sim.stdout(), "2 signer: ok"));
}

test "provenance of another result of the same tree is skipped, and refused only when required" {
    // Goal: link 4 is "provenance for this result". Method: two results of one tree, only the
    // first signed with provenance; the second verifies with link 4 skipped.
    try start();
    defer finish();
    try make_project();
    const first = try sign_built("first", tree, "zbx.build.zon");
    var first_text: [constants.store_digest_text_bytes:0]u8 = undefined;
    @memcpy(first_text[0..constants.store_digest_text_bytes], first);
    first_text[constants.store_digest_text_bytes] = 0;
    var saved: result.Record = undefined;
    saved.config.clear();
    _ = saved.config.add_label("label", "second").?;
    saved.tree = tree;
    var failed: result.Failure = undefined;
    const second = try result.save(&store, &saved, &result_bytes, &failed);
    var second_text: [constants.store_digest_text_bytes:0]u8 = undefined;
    @memcpy(second_text[0..constants.store_digest_text_bytes], &second.text());
    second_text[constants.store_digest_text_bytes] = 0;
    try testing.expectEqual(@as(u8, 0), verify_built(&second_text, &.{ "--key", "ci" }));
    try testing.expect(has(sim.stdout(), "4 provenance: skipped"));
    try testing.expectEqual(@as(u8, 1), verify_built(&second_text, &.{
        "--key", "ci", "--require-provenance",
    }));
    try testing.expect(has(sim.stdout(), "4 provenance: FAILED"));
    try testing.expect(!has(sim.stderr(), "()"));
    try testing.expect(has(sim.stderr(), first_text[0..24]));
}
