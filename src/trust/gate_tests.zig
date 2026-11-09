//! Tests of the run gate (`gate.zig`) against the simulated host and store: with no policy the
//! gate is silent, a policy that cannot be read refuses, a rule is met by a signature of a
//! listed key and by nothing else. The diagnostics' own text is in the golden tests.

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
const sim_run = @import("../runtime/sim_run.zig");
const Digest = @import("../store/digest.zig").Digest;
const gate = @import("gate.zig");
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const record = @import("record.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const fs_mod = @import("../store/fs.zig");
const result_mod = @import("../build/result.zig");
const sign_commands = @import("sign_commands.zig");

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};
const policy_path = "/home/alice/.config/zbx/policy.zon";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var workspace: sign_commands.Workspace = undefined;
var memory: gate.Memory = undefined;
var tree: Digest = undefined;
var last_diag: Diag = undefined;

/// A store holding the sample tree, and the keys `ci` and `other` (neither passphrased).
fn start() !void {
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
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "other", "--no-passphrase" }));
}

fn command(args: []const [:0]const u8) u8 {
    var items: [12][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

fn sign_as(name: []const u8) !void {
    const text = tree.text();
    const args: sign_commands.Args = .{ .operand = &text, .key = name };
    last_diag.reset();
    const output: sign_commands.Output = .{ .json = false };
    const done = try sign_commands.run(sim.interface(), &workspace, args, output, &last_diag);
    try testing.expectEqual(@as(u8, 0), done);
}

/// The public key of `name`, as the policy file spells it.
fn public_text_of(name: []const u8) ![constants.key_public_text_bytes]u8 {
    var paths: key_store.Paths = undefined;
    try testing.expect(key_store.locate(sim.interface(), &paths));
    var failure: key_store.Failure = undefined;
    const pub_file = try key_store.read_pub(sim.interface().filesystem(), &paths, name, &failure);
    return key.public_text(pub_file.public);
}

fn write_policy(text: []const u8) void {
    // The keys made by `key new` have made the directories; the file may be there already.
    if (files.kind_of(policy_path) != null) files.remove_path(policy_path);
    files.put_file(policy_path, 0o644, text);
}

fn write_trusting(name: []const u8) !void {
    var buffer: [512]u8 = undefined;
    const public = try public_text_of(name);
    const text = try std.fmt.bufPrint(
        &buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"{s}\", .public = \"{s}\" }} }}, " ++
            ".require_signature = true }}",
        .{ name, public },
    );
    write_policy(text);
}

/// What the gate says of running `subject`: the diagnostic's code if it refused.
fn gate_says(subject: gate.Subject) ?codes.Code {
    last_diag.reset();
    gate.load(sim.interface(), &memory, &last_diag) catch return last_diag.code.?;
    const rec = &workspace.record;
    const work = &workspace.record_work;
    gate.judge_all(sim.interface(), &memory, rec, work, subject, &last_diag) catch {
        return last_diag.code.?;
    };
    return null;
}

fn tree_subject() gate.Subject {
    return .{ .tree = tree, .binding = .none, .text = "b3:sample" };
}

test "with no policy file, or one that asks nothing, the gate lets any run through" {
    // Goal: a user with no policy sees no change. Method: gate an unsigned tree with no file,
    // then with a file that only has a version.
    try start();
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
    try testing.expectEqual(@as(u32, 0), memory.count);
    write_policy(".{ .version = 1 }");
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
    try testing.expectEqual(@as(u32, 1), memory.count);
    try testing.expect(!gate.any_checks(&memory));
}

test "a policy file that is not a policy refuses every run, as E0904" {
    // Goal: a policy that cannot be read is never taken for "no rules". Method: a file with
    // an unknown field, then one that is not ZON at all.
    try start();
    write_policy(".{ .version = 1, .extra = true }");
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
    write_policy("not a policy");
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
}

test "a rule is met by a signature of a listed key, and by nothing else" {
    // Goal: require_signature's verdict end to end. Method: an unsigned tree is refused; a
    // signature by a key the policy does not list is refused; one by the listed key passes.
    try start();
    try write_trusting("ci");
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(tree_subject()));
    try sign_as("other");
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(tree_subject()));
    try sign_as("ci");
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
}

test "a directory has no tree to sign, so a signature rule refuses it" {
    // Goal: `--rootfs` cannot slip past require_signature. Method: gate a subject with no tree.
    try start();
    try write_trusting("ci");
    const subject: gate.Subject = .{ .tree = null, .binding = .none, .text = "" };
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(subject));
}

test "require_provenance: a directory is E0905 no-tree; an underived image has its cause" {
    // Goal: E0906 never prints an empty digest or blames a signed provenance that does not
    // exist. Method: gate a directory (no tree) under a policy with only require_provenance:
    // E0905, whose cause names the rule and the directory. Gate a manifest binding and a bare
    // tree: E0906, the image's cause (its record keeps no labels) and the tree's (not a result).
    try start();
    try write_requiring_provenance("ci");
    const directory: gate.Subject = .{ .tree = null, .binding = .none, .text = "" };
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(directory));
    const cause = last_diag.last_cause().?;
    const asks = "signed provenance (require_provenance)";
    try testing.expect(std.mem.indexOf(u8, cause, asks) != null);
    try testing.expect(std.mem.indexOf(u8, cause, "a directory has no tree to sign") != null);
    const pulled: gate.Subject = .{
        .tree = tree,
        .binding = .{ .manifest = @splat(7) },
        .text = "docker.io/library/alpine@sha256:abc",
    };
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(pulled));
    try testing.expect(std.mem.indexOf(u8, last_diag.last_cause().?, "labels") != null);
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(tree_subject()));
    try testing.expect(std.mem.indexOf(u8, last_diag.last_cause().?, "not a build result") != null);
}

test "a damaged record is E0903, not an unsigned tree" {
    // Goal: damage is never taken for absence. Method: sign, then flip a byte of the record.
    try start();
    try write_trusting("ci");
    try sign_as("ci");
    var path: @import("../store/fs.zig").PathBuf = undefined;
    const where = record.record_path(&store, &path, tree);
    files.flip_byte(where, 10);
    try testing.expectEqual(@as(?codes.Code, .E0903), gate_says(tree_subject()));
}

const system_path = "/etc/zbx/policy.zon";

fn write_system(text: []const u8, mode: u16, uid: u32) void {
    if (files.kind_of("/etc") == null) files.put_dir("/etc", 0o755);
    if (files.kind_of("/etc/zbx") == null) files.put_dir("/etc/zbx", 0o755);
    if (files.kind_of(system_path) != null) files.remove_path(system_path);
    files.put_file(system_path, mode, text);
    files.set_owner_of(system_path, uid, 0);
}

fn trusting_text(buffer: []u8, name: []const u8) ![]const u8 {
    const public = try public_text_of(name);
    return std.fmt.bufPrint(
        buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"{s}\", .public = \"{s}\" }} }}, " ++
            ".require_signature = true }}",
        .{ name, public },
    );
}

/// The text of the refusal the last `gate_says` left.
fn refusal_text(buffer: []u8) []const u8 {
    const render = @import("../diag/render.zig");
    return render.render(&last_diag, .verbose, false, buffer);
}

test "the system policy applies with no user file at all" {
    // Goal: the system file is read. Method: it requires a signature; no user file; the tree is
    // unsigned, then signed by the listed key.
    try start();
    var buffer: [512]u8 = undefined;
    write_system(try trusting_text(&buffer, "ci"), 0o644, 0);
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(tree_subject()));
    var out: [constants.output_bytes_max]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, refusal_text(&out), system_path) != null);
    try sign_as("ci");
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
}

test "both policy files apply; the user's keys cannot satisfy the system's rule" {
    // Goal: a user cannot loosen the system rule. Method: the system file trusts `ci`, the user
    // file trusts `other`; a tree signed by `other` only is refused, naming the system file; by
    // `ci` only, refused by the user file; by both, it passes.
    try start();
    var out: [constants.output_bytes_max]u8 = undefined;
    var buffer: [512]u8 = undefined;
    write_system(try trusting_text(&buffer, "ci"), 0o644, 0);
    var second: [512]u8 = undefined;
    write_policy(try trusting_text(&second, "other"));
    try sign_as("other");
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(tree_subject()));
    try testing.expect(std.mem.indexOf(u8, refusal_text(&out), system_path) != null);
    try testing.expectEqual(@as(u32, 2), memory.count);
    // The other order, in a fresh store: signed by `ci` only.
    try start();
    write_system(try trusting_text(&buffer, "ci"), 0o644, 0);
    write_policy(try trusting_text(&second, "other"));
    try sign_as("ci");
    try testing.expectEqual(@as(?codes.Code, .E0905), gate_says(tree_subject()));
    try testing.expect(std.mem.indexOf(u8, refusal_text(&out), policy_path) != null);
    try sign_as("other");
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
}

test "a system policy that cannot be used refuses, whatever the user's file says" {
    // Goal: a bad system file is never "no rules". Method: with a permissive user file, a
    // malformed system file; one that is not root's; one that others can write; each is E0904,
    // and the cause names the fix. A root-owned 0644 file is accepted.
    try start();
    write_policy(".{ .version = 1 }");
    write_system("not a policy", 0o644, 0);
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
    write_system(".{ .version = 1 }", 0o644, 0);
    try testing.expectEqual(@as(?codes.Code, null), gate_says(tree_subject()));
    var out: [constants.output_bytes_max]u8 = undefined;
    write_system(".{ .version = 1 }", 0o644, 1000);
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
    const owned = refusal_text(&out);
    try testing.expect(std.mem.indexOf(u8, owned, "owned by uid 1000") != null);
    try testing.expect(std.mem.indexOf(u8, owned, "chown root:root") != null);
    write_system(".{ .version = 1 }", 0o666, 0);
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
    try testing.expect(std.mem.indexOf(u8, refusal_text(&out), "mode 0666") != null);
    write_system(".{ .version = 1 }", 0o664, 0);
    try testing.expectEqual(@as(?codes.Code, .E0904), gate_says(tree_subject()));
}

fn write_requiring_provenance(name: []const u8) !void {
    var buffer: [512]u8 = undefined;
    const public = try public_text_of(name);
    const text = try std.fmt.bufPrint(
        &buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"{s}\", .public = \"{s}\" }} }}, " ++
            ".require_provenance = true }}",
        .{ name, public },
    );
    write_policy(text);
}

var result_buffer: [constants.build_result_bytes_max]u8 = undefined;
var provenance_record: provenance.Record = undefined;
var provenance_bytes: [constants.statement_bytes_max]u8 = undefined;

fn save_provenance(result: Digest) !void {
    const filled: provenance.Digest = @splat(0x5a);
    const made = &provenance_record;
    made.clear();
    made.tree = tree.bytes;
    made.result = result.bytes;
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
    var failure: fs_mod.Failure = undefined;
    const bytes = provenance.render(&provenance_bytes, made);
    try provenance_store.save(&store, result, bytes, &failure);
}

test "require_provenance: no record, an unsigned record, a stranger's signature and the right one" {
    // Goal: E0906's causes and its satisfaction. Method: a result of the tree, run as the
    // subject. Nothing stored: refused (missing). A record stored but unsigned: refused. A
    // record signed by a key the policy does not list: refused. Signed by the listed key: runs.
    // A signature of the tree alone (not provenance) never satisfies the rule.
    try start();
    try write_requiring_provenance("ci");
    var saved: result_mod.Record = undefined;
    saved.config.clear();
    saved.tree = tree;
    var failure: result_mod.Failure = undefined;
    const result = try result_mod.save(&store, &saved, &result_buffer, &failure);
    const text = result.text();
    var zeroed: [constants.store_digest_text_bytes:0]u8 = undefined;
    @memcpy(zeroed[0..text.len], &text);
    zeroed[text.len] = 0;
    const subject: gate.Subject = .{
        .tree = tree,
        .binding = .{ .result = result.bytes },
        .text = &text,
    };
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try sign_as("ci"); // The tree alone: a signature, but not provenance.
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try save_provenance(result);
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &zeroed, "--key", "other" }));
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &zeroed, "--key", "ci" }));
    try testing.expectEqual(@as(?codes.Code, null), gate_says(subject));
    // The same signature does not cover another result of the tree.
    const other: gate.Subject = .{
        .tree = tree,
        .binding = .{ .result = @splat(9) },
        .text = "b3:other",
    };
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(other));
}

/// A result of the sample tree whose provenance record is stored, and the subject of a run of
/// an image whose record derives that result (a pulled or pushed one).
fn derived_subject() !gate.Subject {
    var saved: result_mod.Record = undefined;
    saved.config.clear();
    saved.tree = tree;
    var failure: result_mod.Failure = undefined;
    const built = try result_mod.save(&store, &saved, &result_buffer, &failure);
    try save_provenance(built);
    return .{
        .tree = tree,
        .binding = .{ .manifest = @splat(7) },
        .derived = built.bytes,
        .text = "docker.io/library/app@sha256:abc",
    };
}

fn text_of_derived(subject: gate.Subject) [constants.store_digest_text_bytes:0]u8 {
    var out: [constants.store_digest_text_bytes:0]u8 = undefined;
    const text = (Digest{ .bytes = subject.derived.? }).text();
    @memcpy(out[0..text.len], &text);
    out[text.len] = 0;
    return out;
}

test "require_provenance: an image that derives a result is judged as that result" {
    // Goal: E0906's cause for a pulled or pushed image is the result's own (slice 14). Method:
    // an image subject deriving a result with a stored record: unsigned, then signed by a key the
    // policy does not list, then signed by the listed one (runs). A subject deriving another
    // result than the signed one: the signed provenance is not of it.
    try start();
    try write_requiring_provenance("ci");
    const subject = try derived_subject();
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    const cause = last_diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "no listed key signed") != null);
    const zeroed = text_of_derived(subject);
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &zeroed, "--key", "other" }));
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", &zeroed, "--key", "ci" }));
    try testing.expectEqual(@as(?codes.Code, null), gate_says(subject));
    var other = subject;
    other.derived = @splat(9);
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(other));
    try testing.expect(std.mem.indexOf(u8, last_diag.last_cause().?, "is not of") != null);
}

test "require_provenance: an image deriving a result with no record has none stored" {
    // Goal: the `missing` cause holds for a derived result as for a built one. Method: derive a
    // result nothing recorded.
    try start();
    try write_requiring_provenance("ci");
    const subject: gate.Subject = .{
        .tree = tree,
        .binding = .{ .manifest = @splat(7) },
        .derived = @splat(9),
        .text = "docker.io/library/app@sha256:abc",
    };
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(subject));
    try testing.expect(std.mem.indexOf(u8, last_diag.last_cause().?, "has none stored") != null);
}

test "require_provenance: an image whose record cannot derive says so; a build base does not" {
    // Goal: only a manifest-bound run that could derive, and cannot, is `not_derived`; a build
    // step's base never derives (slice 14's cut) and stays "not a build result", as a bare tree.
    try start();
    try write_requiring_provenance("ci");
    const image: gate.Subject = .{
        .tree = tree,
        .binding = .{ .manifest = @splat(7) },
        .text = "docker.io/library/app@sha256:abc",
    };
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(image));
    const cause = last_diag.last_cause().?;
    try testing.expect(std.mem.indexOf(u8, cause, "does not keep its labels") != null);
    try testing.expect(std.mem.indexOf(u8, cause, "not a build result") == null);
    var base = image;
    base.step = "compile";
    try testing.expectEqual(@as(?codes.Code, .E0906), gate_says(base));
    try testing.expect(std.mem.indexOf(u8, last_diag.last_cause().?, "not a build result") != null);
}
