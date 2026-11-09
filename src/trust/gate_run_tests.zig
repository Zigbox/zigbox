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
const key = @import("key.zig");
const key_store = @import("key_store.zig");

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
