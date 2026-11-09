//! The gate as `zbx run` builds its subject: which tree and which binding a run of a full tree,
//! a prefix or a build result is judged by (`cli.zig`, `gate_subject_of`). Each test runs the
//! command line against the simulated host and store with a policy file that trusts one key.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const result = @import("../build/result.zig");
const sim_run = @import("../runtime/sim_run.zig");
const Digest = @import("../store/digest.zig").Digest;
const images = @import("../store/images.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");

const policy_path = "/home/alice/.config/zbx/policy.zon";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var record: result.Record = undefined;
var record_bytes: [constants.build_result_bytes_max]u8 = undefined;
var tree: Digest = undefined;
var built: Digest = undefined;

fn command(args: []const [:0]const u8) u8 {
    var items: [14][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

/// A store with the sample tree and a build result whose tree it is, the key `ci`, and a policy
/// that requires a signature by it.
fn start() !void {
    sim_run.init(&sim, 3);
    files.init(3);
    sim.store_fs = &files;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    support.make_source(&files, 0);
    store.at(sim.interface(), support.user_store);
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &import_work, "/src", options, &made, &diag);
    tree = made.digest;
    record.config.clear();
    _ = record.config.settings.add(.entrypoint, "/bin/sh");
    record.tree = tree;
    var failure: result.Failure = undefined;
    built = try result.save(&store, &record, &record_bytes, &failure);
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "ci", "--no-passphrase" }));
    var key_failure: key_store.Failure = undefined;
    var paths: key_store.Paths = undefined;
    try testing.expect(key_store.locate(sim.interface(), &paths));
    const fs = sim.interface().filesystem();
    const pub_file = try key_store.read_pub(fs, &paths, "ci", &key_failure);
    const public = key.public_text(pub_file.public);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"ci\", .public = \"{s}\" }} }}, " ++
            ".require_signature = true }}",
        .{public},
    );
    files.put_file(policy_path, 0o644, text);
}

/// The digest's text with the terminator the command line wants.
fn terminated(digest: Digest) [constants.store_digest_text_bytes:0]u8 {
    var out: [constants.store_digest_text_bytes:0]u8 = undefined;
    const text = digest.text();
    @memcpy(out[0..text.len], &text);
    out[text.len] = 0;
    return out;
}

fn run_of(operand: [:0]const u8) u8 {
    return command(&.{ "run", operand, "--", "/bin/sh" });
}

fn refused_as_unsigned() !void {
    try testing.expectEqual(@as(u8, 125), run_of_last);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0905") != null);
    try testing.expect(sim.world.bus.scope_started == null);
}

var run_of_last: u8 = 0;

fn passes_gate() !void {
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E09") == null);
}

test "a run of a result signed with its binding passes; the bare tree of it is refused" {
    // Goal: a result-bound signature admits that result only. Method: sign the result; run the
    // result (passes the gate), then its tree with a command (E0905, bound to another result).
    try start();
    const result_text = terminated(built);
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &result_text, "--key", "ci" }));
    _ = run_of(&result_text);
    try passes_gate();
    const tree_text = terminated(tree);
    run_of_last = run_of(&tree_text);
    try refused_as_unsigned();
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "bound to another result") != null);
}

test "an unsigned full tree is refused before anything starts, naming the digest" {
    // Goal: the plain refusal. Method: run an unsigned tree; the fix names the full digest.
    try start();
    const tree_text = terminated(tree);
    run_of_last = run_of(&tree_text);
    try refused_as_unsigned();
    const fix = try std.fmt.allocPrint(testing.allocator, "zbx sign {s}", .{&tree_text});
    defer testing.allocator.free(fix);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), fix) != null);
}

test "a tree signed alone passes, by full digest, by prefix and as a result's tree" {
    // Goal: a tree-only signature counts for any run of that tree, and a prefix is resolved to
    // the tree before the gate. Method: sign the tree; run it whole, by 12 digits, and by the
    // result.
    try start();
    const tree_text = terminated(tree);
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &tree_text, "--key", "ci" }));
    _ = run_of(&tree_text);
    try passes_gate();
    var prefix: [12:0]u8 = undefined;
    @memcpy(&prefix, tree_text[3..15]);
    _ = run_of(&prefix);
    try passes_gate();
    const result_text = terminated(built);
    _ = run_of(&result_text);
    try passes_gate();
}

test "an unsigned tree given by a prefix is refused naming the full digest" {
    // Goal: E0905's fix works for a prefix run. Method: run by prefix; the message has the
    // full digest, not the prefix.
    try start();
    const tree_text = terminated(tree);
    var prefix: [12:0]u8 = undefined;
    @memcpy(&prefix, tree_text[3..15]);
    run_of_last = run_of(&prefix);
    try refused_as_unsigned();
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), &tree_text) != null);
}

/// Saves the image record of a pulled image of `tree`, with the settings of `record` and
/// known (or forgotten) labels, and returns the operand that names it by manifest.
fn save_pulled(known: bool) ![:0]const u8 {
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
    _ = image.settings.add(.entrypoint, "/bin/sh");
    image.labels.clear();
    if (!known) image.labels.forget();
    var failure: @import("../store/fs.zig").Failure = undefined;
    try images.save(&store, &image, &failure);
    const hex = std.fmt.bytesToHex(image.manifest.bytes, .lower);
    const text = try std.fmt.bufPrint(&pulled_operand, "alpine@sha256:{s}", .{&hex});
    pulled_operand[text.len] = 0;
    return pulled_operand[0..text.len :0];
}

var pulled_operand: [128]u8 = undefined;

test "a pulled image passes require_provenance on the signed result it derives" {
    // Goal: slice 14 end to end: run_image -> gate subject -> verdict carry `derived`. Method: a
    // result signed with its binding; the image of that tree, settings and labels is run by its
    // manifest (passes); the same image with unknown labels is refused as `not_derived`.
    try start();
    const result_text = terminated(built);
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &result_text, "--key", "ci" }));
    const operand = try save_pulled(true);
    _ = run_of(operand);
    try passes_gate();
    _ = try save_pulled(false);
    run_of_last = run_of(operand);
    try refused_as_unsigned();
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "pull the image again") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "bound to another result") == null);
}

test "a pulled image passes require_provenance on the result built, signed with provenance" {
    // Goal: slice 4 meets slice 14 end to end through `zbx run`. Method: a policy that requires
    // provenance; the result has a stored record, signed by the listed key; its image, run by
    // manifest, passes. With no record stored it is refused as E0906, not as "not a result".
    try start();
    const public = try policy_public();
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"ci\", .public = \"{s}\" }} }}, " ++
            ".require_provenance = true }}",
        .{public},
    );
    files.remove_path(policy_path);
    files.put_file(policy_path, 0o644, text);
    const operand = try save_pulled(true);
    run_of_last = run_of(operand);
    try testing.expectEqual(@as(u8, 125), run_of_last);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0906") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "has none stored") != null);
    try save_provenance_of_built();
    const result_text = terminated(built);
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &result_text, "--key", "ci" }));
    _ = run_of(operand);
    try passes_gate();
}

fn policy_public() ![constants.key_public_text_bytes]u8 {
    var key_failure: key_store.Failure = undefined;
    var paths: key_store.Paths = undefined;
    try testing.expect(key_store.locate(sim.interface(), &paths));
    const fs = sim.interface().filesystem();
    const pub_file = try key_store.read_pub(fs, &paths, "ci", &key_failure);
    return key.public_text(pub_file.public);
}

var provenance_record: provenance.Record = undefined;
var provenance_bytes: [constants.statement_bytes_max]u8 = undefined;

fn save_provenance_of_built() !void {
    const filled: provenance.Digest = @splat(0x5a);
    const made = &provenance_record;
    made.clear();
    made.tree = tree.bytes;
    made.result = built.bytes;
    made.set_build_file("zbx.build.zon");
    made.build_file_digest = filled;
    made.lock = filled;
    const base = made.add_base("alpine:3.20", filled, filled);
    const step = made.add_step("compile");
    step.base = base;
    step.key = filled;
    step.input = filled;
    step.output = filled;
    made.image_key = filled;
    made.image_base = base;
    made.set_version("0.4.0", "linux/amd64");
    made.zbx = filled;
    var failure: @import("../store/fs.zig").Failure = undefined;
    const bytes = provenance.render(&provenance_bytes, made);
    try provenance_store.save(&store, built, bytes, &failure);
}
