//! Tests of `zbx sign` (`sign_commands.zig`) against the simulated host and store: what each
//! kind of operand signs, what is written, and every way it refuses. The diagnostics' own text
//! is in the golden tests.

const std = @import("std");
const testing = std.testing;
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const result = @import("../build/result.zig");
const test_util = @import("../test_util.zig");
const sim_run = @import("../runtime/sim_run.zig");
const dsse = @import("dsse.zig");
const record = @import("record.zig");
const sign_commands = @import("sign_commands.zig");
const statement = @import("statement.zig");
const Digest = @import("../store/digest.zig").Digest;

const manifest_hex = "abababababababababababababababababababababababababababababababab";
const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};
const records_directory = support.user_store ++ "/trust/signatures";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var workspace: sign_commands.Workspace = undefined;
var loaded: record.Record = undefined;
var loading: record.Work = undefined;
var save_buffer: [constants.build_result_bytes_max]u8 = undefined;
var tree: Digest = undefined;

/// A store holding the sample tree `/src`, and the keys `ci` (and `deploy`, when `second`).
fn start(second: bool) !void {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    sim.environment_variables = &home;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &import_work, "/src", options, &made, &diag);
    tree = made.digest;
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "ci", "--no-passphrase" }));
    if (second) {
        const made_second = command(&.{ "key", "new", "deploy", "--no-passphrase" });
        try testing.expectEqual(@as(u8, 0), made_second);
    }
}

fn command(args: []const [:0]const u8) u8 {
    var items: [12][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

/// Signs `operand` with the extra arguments; the code of the diagnostic, if it refused.
fn sign(operand: []const u8, json: bool, key: ?[]const u8) ?codes.Code {
    var diag: Diag = undefined;
    diag.reset();
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    const args: sign_commands.Args = .{ .operand = operand, .key = key };
    const output: sign_commands.Output = .{ .json = json };
    const code = sign_commands.run(sim.interface(), &workspace, args, output, &diag) catch
        return diag.code.?;
    std.debug.assert(code == 0);
    return null;
}

fn record_of(digest: Digest) !*const record.Record {
    var errno: u16 = 0;
    try record.load(&store, &loading, digest, &loaded, &errno);
    return &loaded;
}

var zed_buffer: [constants.store_digest_text_bytes:0]u8 = undefined;

/// The digest as text a command line can carry.
fn zed(digest: Digest) [:0]const u8 {
    @memcpy(zed_buffer[0..constants.store_digest_text_bytes], &digest.text());
    zed_buffer[constants.store_digest_text_bytes] = 0;
    return &zed_buffer;
}

fn has(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// A build result of the tree, saved in the store; its digest as text.
fn save_result() !Digest {
    var saved: result.Record = undefined;
    saved.config.clear();
    saved.tree = tree;
    var failure: result.Failure = undefined;
    return try result.save(&store, &saved, &save_buffer, &failure);
}

test "signing a tree writes one record line, and signing again changes nothing" {
    // Goal: the plain path and idempotence. Method: sign the tree by its digest twice; the
    // record has one line, the first output says "signed", the second says it was already so.
    try start(false);
    const text = tree.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, null));
    try testing.expect(has(sim.stdout(), "signed "));
    try testing.expect(has(sim.stdout(), "binding: none"));
    try testing.expect(has(sim.stdout(), "key: ci  "));
    try testing.expect(has(sim.stdout(), "signatures: 1\n"));
    const before = (try record_of(tree)).count;
    try testing.expectEqual(@as(u32, 1), before);
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, null));
    try testing.expect(has(sim.stdout(), "already signed by this key"));
    try testing.expectEqual(@as(u32, 1), (try record_of(tree)).count);
}

test "the JSON form is one valid document of the schema, and says what was added" {
    // Goal: `zbx.sign/1`. Method: sign with --output json, parse it, then sign again.
    try start(false);
    const text = tree.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, true, "ci"));
    try testing.expect(try test_util.json_is_valid(sim.stdout()));
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("zbx.sign/1", root.get("schema").?.string);
    try testing.expectEqualStrings(&text, root.get("tree").?.string);
    try testing.expectEqualStrings("none", root.get("binding").?.string);
    try testing.expectEqualStrings("ci", root.get("key").?.string);
    try testing.expect(root.get("added").?.bool);
    try testing.expectEqual(@as(i64, 1), root.get("signatures").?.integer);
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, true, "ci"));
    var again = try std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
    defer again.deinit();
    try testing.expect(!again.value.object.get("added").?.bool);
}

test "a build result binds the config, and two keys make two lines" {
    // Goal: the result operand and a second signer. Method: sign a saved result with `ci` and
    // `deploy`; the record is about the result's tree with two lines, bound to the result.
    try start(true);
    const digest = try save_result();
    const text = digest.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    try testing.expect(has(sim.stdout(), "binding: result"));
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "deploy"));
    try testing.expect(has(sim.stdout(), "signatures: 2\n"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
    // The tree alone is another statement, so a third line.
    const tree_text = tree.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&tree_text, false, "ci"));
    try testing.expectEqual(@as(u32, 3), (try record_of(tree)).count);
}

test "without --key the only key signs, and none or many are E0006" {
    // Goal: the key choice. Method: no key, one key, two keys.
    try start(false);
    const text = tree.text();
    files.remove_path("/home/alice/.config/zbx/keys/ci.key");
    files.remove_path("/home/alice/.config/zbx/keys/ci.pub");
    try testing.expectEqual(@as(?codes.Code, .E0006), sign(&text, false, null));
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "ci", "--no-passphrase" }));
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, null));
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "deploy", "--no-passphrase" }));
    try testing.expectEqual(@as(?codes.Code, .E0006), sign(&text, false, null));
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "deploy"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
}

test "an operand that is no digest, or names nothing in the store, is refused" {
    // Goal: the operand's refusals. Method: a word, a digest with no tree, an image reference
    // whose manifest the store does not know.
    try start(false);
    try testing.expectEqual(@as(?codes.Code, .E0412), sign("alpine", false, null));
    const absent = Digest.of("nothing").text();
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&absent, false, null));
    const image = "alpine:3.20@sha256:" ++ manifest_hex;
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(image, false, null));
    const operand = "@sha256:" ++ manifest_hex;
    try testing.expectEqual(@as(?codes.Code, .E0501), sign(operand, false, null));
    try testing.expect(files.kind_of(records_directory) == null);
}

test "a missing or damaged object of the tree is refused, and nothing is written" {
    // Goal: only a whole, intact tree is signed. Method: flip a byte of one object, then
    // remove another.
    try start(false);
    const text = tree.text();
    var found: ?[]const u8 = null;
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (!has(path, "/objects/")) continue;
        if (files.kind_of(path).? != .file) continue;
        if (files.content_of(path).?.len == 0) continue;
        found = path;
        break;
    }
    const path = found.?;
    files.flip_byte(path, 0);
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&text, false, null));
    const said = sim.stderr();
    try testing.expect(has(said, "damaged") or has(said, "differ") or said.len == 0);
    files.remove_path(path);
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&text, false, null));
    try testing.expect(files.kind_of(records_directory) == null);
}

test "a damaged record is E0903 and is left as it was; a full record is E0910" {
    // Goal: the record's two refusals. Method: write garbage as the tree's record, sign; then
    // write eight lines of other keys and sign with a ninth.
    try start(false);
    const text = tree.text();
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    const where = try std.fmt.bufPrint(&path, records_directory ++ "/{s}", .{&tree.hex()});
    files.put_dir(support.user_store ++ "/trust", 0o755);
    files.put_dir(records_directory, 0o755);
    files.put_file(where, 0o644, "garbage\n");
    try testing.expectEqual(@as(?codes.Code, .E0903), sign(&text, false, null));
    try testing.expectEqualStrings("garbage\n", files.content_of(where).?);
    files.remove_path(where);
    var payload: [statement.render_bytes_max]u8 = undefined;
    var line: [constants.envelope_bytes_max]u8 = undefined;
    var dsse_work: dsse.Work = undefined;
    loaded.clear();
    for (0..constants.signatures_per_tree_max) |at| {
        const seed: [constants.key_seed_bytes]u8 = @splat(@intCast(at + 50));
        const body = statement.render(&payload, &statement.Statement.for_tree(tree.bytes, at));
        _ = try loaded.add(try dsse.sign(&dsse_work, &line, seed, body));
    }
    files.put_file(where, 0o644, loaded.text());
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&text, false, null));
    try testing.expectEqualStrings(loaded.text(), files.content_of(where).?);
}

test "the store holds at most trust_records_max signed trees" {
    // Goal: the bound at and one past (a simulated disk cannot hold that many files).
    try testing.expect(!sign_commands.is_full(constants.trust_records_max - 1));
    try testing.expect(sign_commands.is_full(constants.trust_records_max));
}

test "the command line signs, takes --key in both forms, and refuses what is not its" {
    // Goal: the parse. Method: through `zbx sign`.
    try start(true);
    const text = zed(tree);
    try testing.expectEqual(@as(u8, 1), command(&.{"sign"}));
    try testing.expectEqual(@as(u8, 1), command(&.{ "sign", text }));
    try testing.expect(has(sim.stderr(), "E0006"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", text, "--key", "ci" }));
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", "--key=deploy", text }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "sign", text, "--key", "a", "--key=b" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "sign", text, "--key" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "sign", text, "extra", "--key", "ci" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "key", "list", "--key", "ci" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "--key", "ci", "key", "list" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "sign", text, "--no-passphrase" }));
}
