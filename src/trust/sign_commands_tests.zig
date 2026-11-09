//! Tests of `zbx sign` (`sign_commands.zig`) against the simulated host and store: what each
//! kind of operand signs, what is written, and every way it refuses. The diagnostics' own text
//! is in the golden tests.

const std = @import("std");
const testing = std.testing;
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const images = @import("../store/images.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const result = @import("../build/result.zig");
const test_util = @import("../test_util.zig");
const sim_run = @import("../runtime/sim_run.zig");
const dsse = @import("dsse.zig");
const fs_mod = @import("../store/fs.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const key_commands = @import("key_commands.zig");
const record = @import("record.zig");
const sign_commands = @import("sign_commands.zig");
const statement = @import("statement.zig");
const Digest = @import("../store/digest.zig").Digest;
const Sha256 = @import("../registry/digest.zig").Sha256;

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
    return sign_with(.{ .operand = operand, .key = key }, json);
}

/// The last diagnostic `sign_with` raised, to check its cause.
var last_diag: Diag = undefined;

fn sign_with(args: sign_commands.Args, json: bool) ?codes.Code {
    last_diag.reset();
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    const output: sign_commands.Output = .{ .json = json };
    const run = sign_commands.run(sim.interface(), &workspace, args, output, &last_diag);
    const code = run catch return last_diag.code.?;
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
    const first_line = try testing.allocator.dupe(u8, (try record_of(tree)).text());
    defer testing.allocator.free(first_line);
    // A day later the statement's `signedAt` differs, but it says the same thing.
    sim.world.now += 86_400;
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, null));
    try testing.expect(has(sim.stdout(), "already signed by this key"));
    try testing.expect(has(sim.stdout(), "signatures: 1 (already"));
    try testing.expectEqual(@as(u32, 1), (try record_of(tree)).count);
    try testing.expectEqualStrings(first_line, loaded.text());
    // Another key is not the same signer, so it adds a line, and its own repeat does not.
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "deploy", "--no-passphrase" }));
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "deploy"));
    sim.world.now += 1;
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "deploy"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
    try testing.expect(std.mem.startsWith(u8, loaded.text(), first_line));
}

test "signing again with the clock moving never fills the record" {
    // Goal: the failure the review found: a CI job signing on every build locked out the
    // other signers. Method: sign the same tree ten times, a second apart, then with a second
    // key, which still has room.
    try start(true);
    const text = tree.text();
    for (0..10) |_| {
        sim.world.now += 1;
        try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    }
    try testing.expectEqual(@as(u32, 1), (try record_of(tree)).count);
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "deploy"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
}

test "two spellings of one image reference are one subject, under the canonical name" {
    // Goal: REVIEW.md's "two spellings of one reference are one reference". Method: an image
    // record in the store, signed as three spellings, a day apart; one line, and its subject
    // name is the canonical, tagless one.
    try start(false);
    var image: images.Image = undefined;
    image.tag_count = 0;
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = tree;
    image.time = 1_800_000_000;
    image.layer_count = 0;
    image.settings.clear();
    image.labels.clear();
    var failure: @import("../store/fs.zig").Failure = undefined;
    try images.save(&store, &image, &failure);
    const hex = std.fmt.bytesToHex(image.manifest.bytes, .lower);
    const spellings = [_][]const u8{
        "alpine@sha256:" ++ hex,
        "docker.io/library/alpine@sha256:" ++ hex,
        "alpine:3.20@sha256:" ++ hex,
    };
    for (spellings) |operand| {
        sim.world.now += 86_400;
        try testing.expectEqual(@as(?codes.Code, null), sign(operand, false, null));
    }
    const found = try record_of(tree);
    try testing.expectEqual(@as(u32, 1), found.count);
    var dsse_work: dsse.Work = undefined;
    const envelope = try dsse.parse(&dsse_work, found.line(0));
    const said = try statement.parse(envelope.payload);
    try testing.expectEqualStrings("docker.io/library/alpine@sha256:" ++ hex, said.reference());
    try testing.expect(std.meta.activeTag(said.binding) == .manifest);
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

/// The path of some file object of the sample tree that has content.
fn some_object() []const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (!has(path, "/objects/")) continue;
        if (files.kind_of(path).? != .file) continue;
        if (files.content_of(path).?.len == 0) continue;
        return path;
    }
    unreachable; // The sample tree has a file with content.
}

test "a missing or damaged object of the tree is refused, and nothing is written" {
    // Goal: only a whole, intact tree is signed, and the cause names what is wrong. Method:
    // flip a byte of one object, then remove it.
    try start(false);
    const text = tree.text();
    const path = some_object();
    files.flip_byte(path, 0);
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&text, false, null));
    try testing.expect(has(last_diag.last_cause().?, "damaged"));
    files.remove_path(path);
    try testing.expectEqual(@as(?codes.Code, .E0910), sign(&text, false, null));
    try testing.expect(has(last_diag.last_cause().?, "missing"));
    try testing.expect(!has(last_diag.last_cause().?, "No such file"));
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

/// Makes the key `sealed`, with the passphrase `phrase` in `/home/alice/pass` (mode 0600).
fn make_sealed_key(phrase: []const u8) !void {
    files.put_file("/home/alice/pass", 0o600, phrase);
    var diag: Diag = undefined;
    diag.reset();
    const args: key_commands.Args = .{
        .action = .new,
        .name = "sealed",
        .passphrase_file = "/home/alice/pass",
    };
    const cheap: key_commands.Cost = .{ .t = 1, .m_kib = 8, .p = 1 };
    const made = try key_commands.run(sim.interface(), args, .{ .json = false }, cheap, &diag);
    try testing.expectEqual(@as(u8, 0), made);
}

test "a sealed key signs with its passphrase file, and a wrong or missing one writes nothing" {
    // Goal: the passphrase path of `sign`: right file signs; wrong file, and no file with no
    // terminal, are E0911 with no record written and no read of standard input. Method: a
    // sealed key made at the cheap cost, then each way of giving the passphrase.
    try start(false);
    try make_sealed_key("correct horse\n");
    const text = tree.text();
    sim.world.input = "stolen\nstolen\n";
    const missing: sign_commands.Args = .{ .operand = &text, .key = "sealed" };
    try testing.expectEqual(@as(?codes.Code, .E0911), sign_with(missing, false));
    try testing.expect(has(last_diag.last_cause().?, "no terminal"));
    try testing.expect(sim.world.input_handle == null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(files.kind_of(records_directory) == null);
    files.remove_path("/home/alice/pass");
    files.put_file("/home/alice/pass", 0o600, "wrong horse\n");
    const wrong: sign_commands.Args = .{
        .operand = &text,
        .key = "sealed",
        .passphrase_file = "/home/alice/pass",
    };
    try testing.expectEqual(@as(?codes.Code, .E0911), sign_with(wrong, false));
    try testing.expect(has(last_diag.last_cause().?, "does not open the key"));
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
    try testing.expect(files.kind_of(records_directory) == null);
    files.remove_path("/home/alice/pass");
    files.put_file("/home/alice/pass", 0o600, "correct horse\n");
    try testing.expectEqual(@as(?codes.Code, null), sign_with(wrong, false));
    try testing.expect(has(sim.stdout(), "key: sealed  "));
    try testing.expectEqual(@as(u32, 1), (try record_of(tree)).count);
}

var provenance_record: provenance.Record = undefined;
var provenance_bytes: [constants.statement_bytes_max]u8 = undefined;

/// Stores a provenance record for `digest`, a result of `tree`; its bytes.
fn save_provenance(digest: Digest) ![]const u8 {
    const filled: provenance.Digest = @splat(0x5a);
    const made = &provenance_record;
    made.clear();
    made.tree = tree.bytes;
    made.result = digest.bytes;
    made.set_build_file("zbx.build.zon");
    made.build_file_digest = filled;
    made.lock = filled;
    const base = made.add_base("alpine:3.20", filled, filled);
    const step = made.add_step("compile");
    step.base = base;
    step.key = filled;
    step.input = filled;
    step.output = filled;
    step.network = false;
    made.image_key = filled;
    made.image_base = base;
    made.set_version("0.4.0", "linux/amd64");
    made.zbx = filled;
    made.started = 1000;
    made.finished = 1042;
    const bytes = provenance.render(&provenance_bytes, made);
    var failure: fs_mod.Failure = undefined;
    try provenance_store.save(&store, digest, bytes, &failure);
    return bytes;
}

test "a result with a provenance record signs the record's bytes, and one without signs sign/v1" {
    // Goal: `zbx sign` wraps the stored record exactly, and falls back for a result built
    // before provenance. Method: sign a result with no record (the statement is not a
    // provenance one), then store a record and sign again: the second line's payload is the
    // record's bytes; signing again adds nothing.
    try start(false);
    const digest = try save_result();
    const text = digest.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    var dsse_work: dsse.Work = undefined;
    var envelope = try dsse.parse(&dsse_work, (try record_of(tree)).line(0));
    try testing.expectEqual(statement.Kind.sign, (try statement.parse(envelope.payload)).kind);
    const bytes = try save_provenance(digest);
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
    envelope = try dsse.parse(&dsse_work, (try record_of(tree)).line(1));
    try testing.expectEqualSlices(u8, bytes, envelope.payload);
    const head = try statement.parse(envelope.payload);
    try testing.expectEqual(statement.Kind.provenance, head.kind);
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, true, "ci"));
    try testing.expectEqual(@as(u32, 2), (try record_of(tree)).count);
}

test "signing a rebuilt record again by the same key adds no line, so the tree never fills" {
    // Goal: an all-hit rebuild rewrites the record with new times, and a CI job that signs after
    // every build must not fill the tree's lines (docs/decisions/2026-11-08-sign-idempotence.md).
    // Method: sign, rebuild with new times and sign again, more often than a record holds lines;
    // the count stays one and no sign is refused.
    try start(false);
    const digest = try save_result();
    const text = digest.text();
    _ = try save_provenance(digest);
    for (0..constants.signatures_per_tree_max + 4) |_| {
        try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
        provenance_record.finished += 1;
        var failure: fs_mod.Failure = undefined;
        const later = provenance.render(&provenance_bytes, &provenance_record);
        try provenance_store.save(&store, digest, later, &failure);
    }
    try testing.expectEqual(@as(u32, 1), (try record_of(tree)).count);
}

test "inspect --provenance lists no signer of another result of the same tree" {
    // Goal: the signer list is about this result only. Method: two results of one tree (they
    // differ in a label); only the second has its provenance signed. Inspecting the first shows
    // no signer, inspecting the second shows one.
    try start(false);
    const first = try save_result();
    var saved: result.Record = undefined;
    saved.config.clear();
    saved.config.add_label("name", "second").?;
    saved.tree = tree;
    var failure: result.Failure = undefined;
    const second = try result.save(&store, &saved, &save_buffer, &failure);
    try testing.expect(!std.mem.eql(u8, &first.bytes, &second.bytes));
    _ = try save_provenance(first);
    _ = try save_provenance(second);
    const text = second.text();
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "inspect", "--provenance", zed(first) }));
    try testing.expect(!has(sim.stdout(), "this record"));
    try testing.expect(!has(sim.stdout(), "an earlier build"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "inspect", "--provenance", zed(second) }));
    try testing.expect(has(sim.stdout(), "this record"));
}

test "inspect --provenance shows the record and who signed it, in text and JSON" {
    // Goal: the view. Method: a result with no record is E0005; with one, the text has the
    // result and the step, no signer; after signing the signer is "this record"; a later
    // record makes it "an earlier build"; the JSON parses and names its schema.
    try start(false);
    const digest = try save_result();
    const text = digest.text();
    try testing.expectEqual(@as(u8, 1), command(&.{ "inspect", "--provenance", zed(digest) }));
    try testing.expect(has(sim.stderr(), "E0005"));
    _ = try save_provenance(digest);
    try testing.expectEqual(@as(u8, 0), command(&.{ "inspect", "--provenance", zed(digest) }));
    try testing.expect(has(sim.stdout(), "step        compile"));
    try testing.expect(!has(sim.stdout(), "signed"));
    try testing.expectEqual(@as(?codes.Code, null), sign(&text, false, "ci"));
    try testing.expectEqual(@as(u8, 0), command(&.{ "inspect", "--provenance", zed(digest) }));
    try testing.expect(has(sim.stdout(), "this record"));
    const as_json = command(&.{ "inspect", "--provenance", zed(digest), "--output", "json" });
    try testing.expectEqual(@as(u8, 0), as_json);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, sim.stdout(), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("zbx.provenance/1", parsed.value.object.get("schema").?.string);
    provenance_record.finished += 1;
    var failure: fs_mod.Failure = undefined;
    const later = provenance.render(&provenance_bytes, &provenance_record);
    try provenance_store.save(&store, digest, later, &failure);
    try testing.expectEqual(@as(u8, 0), command(&.{ "inspect", "--provenance", zed(digest) }));
    try testing.expect(has(sim.stdout(), "an earlier build"));
}
