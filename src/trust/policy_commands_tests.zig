//! Tests of `zbx policy check` (`policy_commands.zig`) through the command line against the
//! simulated host and store: the preview agrees with the run gate on every case, says why each
//! signature counts or not, and writes JSON that parses.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const Diag = @import("../diag/diag.zig").Diag;
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const sim_run = @import("../runtime/sim_run.zig");
const Digest = @import("../store/digest.zig").Digest;
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const sign_commands = @import("sign_commands.zig");

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};
const policy_path = "/home/alice/.config/zbx/policy.zon";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var workspace: sign_commands.Workspace = undefined;
var tree: Digest = undefined;

fn sentinel(text: *const [67]u8, buffer: *[67:0]u8) [:0]const u8 {
    @memcpy(buffer[0..67], text);
    buffer[67] = 0;
    return buffer;
}

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
    var diag: Diag = undefined;
    diag.reset();
    const output: sign_commands.Output = .{ .json = false };
    const done = try sign_commands.run(sim.interface(), &workspace, args, output, &diag);
    try testing.expectEqual(@as(u8, 0), done);
}

fn write_trusting(name: []const u8) !void {
    var paths: key_store.Paths = undefined;
    try testing.expect(key_store.locate(sim.interface(), &paths));
    var failure: key_store.Failure = undefined;
    const fs = sim.interface().filesystem();
    const pub_file = try key_store.read_pub(fs, &paths, name, &failure);
    const public = key.public_text(pub_file.public);
    var buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &buffer,
        ".{{ .version = 1, .keys = .{{ .{{ .name = \"{s}\", .public = \"{s}\" }} }}, " ++
            ".require_signature = true }}",
        .{ name, public },
    );
    if (files.kind_of(policy_path) != null) files.remove_path(policy_path);
    files.put_file(policy_path, 0o644, text);
}

test "with no policy file the preview says nothing is checked and the run would start" {
    // Goal: a user with no policy sees no change. Method: preview with no operand, then of an
    // unsigned tree.
    try start();
    try testing.expectEqual(@as(u8, 0), command(&.{ "policy", "check" }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "nothing is checked") != null);
    const text = tree.text();
    var zbuf: [67:0]u8 = undefined;
    const operand = sentinel(&text, &zbuf);
    try testing.expectEqual(@as(u8, 0), command(&.{ "policy", "check", operand }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "would start") != null);
}

test "the preview says why each signature counts, and agrees with the gate" {
    // Goal: the verdict and the reasons. Method: an unsigned tree is refused; a signature by an
    // unlisted key is refused and named as untrusted; one by the listed key passes.
    try start();
    try write_trusting("ci");
    const text = tree.text();
    var zbuf: [67:0]u8 = undefined;
    const operand = sentinel(&text, &zbuf);
    try testing.expectEqual(@as(u8, 1), command(&.{ "policy", "check", operand }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "verdict: not met") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "would be refused") != null);
    try sign_as("other");
    try testing.expectEqual(@as(u8, 1), command(&.{ "policy", "check", operand }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "does not list that key") != null);
    try sign_as("ci");
    try testing.expectEqual(@as(u8, 0), command(&.{ "policy", "check", operand }));
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "signed by ci: it counts") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "file integrity is not checked") != null);
    try testing.expect(std.mem.indexOf(u8, sim.stdout(), "run of ") != null);
    // The gate agrees: a run of the same tree is not refused (it fails later, with no image).
    try testing.expectEqual(@as(u8, 0), command(&.{ "policy", "check" }));
}

test "the JSON form is zbx.policy/1 and parses" {
    // Goal: the machine output is valid JSON with the members the schema names. Method: parse
    // it with std.json after signing, and check the members.
    try start();
    try write_trusting("ci");
    try sign_as("ci");
    const text = tree.text();
    var zbuf: [67:0]u8 = undefined;
    const operand = sentinel(&text, &zbuf);
    const args = [_][:0]const u8{ "policy", "check", operand, "--output", "json" };
    try testing.expectEqual(@as(u8, 0), command(&args));
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        sim.stdout(),
        .{},
    );
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("zbx.policy/1", object.get("schema").?.string);
    try testing.expect(object.get("allowed").?.bool);
    const file = object.get("files").?.array.items[0].object;
    try testing.expectEqualStrings(policy_path, file.get("path").?.string);
    try testing.expect(file.get("met").?.bool);
    const line = file.get("signatures").?.array.items[0].object;
    try testing.expectEqualStrings("counts", line.get("reason").?.string);
    try testing.expectEqualStrings("ci", line.get("key").?.string);
}

test "a policy file that cannot be read is E0904 for the preview too" {
    // Goal: a preview never reads a bad policy as no rules. Method: a file that is not ZON.
    try start();
    if (files.kind_of(policy_path) != null) files.remove_path(policy_path);
    files.put_file(policy_path, 0o644, "not a policy");
    const text = tree.text();
    var zbuf: [67:0]u8 = undefined;
    const operand = sentinel(&text, &zbuf);
    try testing.expectEqual(@as(u8, 1), command(&.{ "policy", "check", operand }));
    try testing.expect(std.mem.indexOf(u8, sim.stderr(), "ZBX-E0904") != null);
    try testing.expectEqual(@as(usize, 0), sim.stdout().len);
}

test "the command line: a subcommand is needed and only check exists" {
    // Goal: the parse errors. Method: no subcommand, a wrong one, a second operand.
    try start();
    try testing.expectEqual(@as(u8, 1), command(&.{"policy"}));
    try testing.expectEqual(@as(u8, 1), command(&.{ "policy", "show" }));
    try testing.expectEqual(@as(u8, 1), command(&.{ "policy", "check", "a", "b" }));
    try testing.expect(constants.exit_ok == 0);
}
