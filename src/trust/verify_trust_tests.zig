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
