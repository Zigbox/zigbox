//! `run_image.prepare_result`: a build result digest as the operand of `run` (slice 3b-ii).

const std = @import("std");
const constants = @import("constants.zig");
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const layout = @import("store/layout.zig");
const result = @import("build/result.zig");
const run_image = @import("run_image.zig");
const support = @import("store/test_support.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;

const testing = std.testing;

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var ws: run_image.Workspace = undefined;
var record: result.Record = undefined;
var buffer: [constants.build_result_bytes_max]u8 = undefined;
var diag: Diag = undefined;
var prepared: run_image.Prepared = undefined;

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};

/// A store holding one record, whose entrypoint is /usr/bin/hello; returns its digest.
fn saved() !Digest {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    sim.environment_variables = &home;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    store.at(sim.interface(), support.user_store);
    record.config.clear();
    _ = record.config.settings.add(.entrypoint, "/usr/bin/hello");
    _ = record.config.settings.add(.env, "GREETING=hi");
    _ = record.config.settings.set(.workdir, "/srv");
    record.tree = Digest.of("a tree");
    var failure: result.Failure = undefined;
    const digest = try result.save(&store, &record, &buffer, &failure);
    diag.reset();
    prepared = .{ .tree = "", .command = &.{}, .env = &.{}, .workdir = "", .user = null };
    return digest;
}

test "a result digest runs its tree with its entrypoint, env and workdir" {
    // Goal: the record is the image. Method: save one, prepare it with and without a command.
    const digest = try saved();
    const text = digest.text();
    const ran = try run_image.prepare_result(sim.interface(), &ws, &text, &.{}, &prepared, &diag);
    try testing.expect(ran);
    try testing.expectEqualStrings(&record.tree.text(), prepared.tree);
    try testing.expectEqual(1, prepared.command.len);
    try testing.expectEqualStrings("/usr/bin/hello", prepared.command[0]);
    try testing.expectEqualStrings("GREETING", prepared.env[0].key);
    try testing.expectEqualStrings("/srv", prepared.workdir);
    try testing.expect(prepared.manifest == null);
    const given = [_][]const u8{ "--flag", "x" };
    _ = try run_image.prepare_result(sim.interface(), &ws, &text, &given, &prepared, &diag);
    try testing.expectEqual(3, prepared.command.len);
    try testing.expectEqualStrings("--flag", prepared.command[1]);
}

test "a digest with no record, and a name that is no digest, are not results" {
    // Goal: the fall-through to a plain tree. Method: an unknown digest and an image name.
    _ = try saved();
    const other = Digest.of("nothing").text();
    const ran = try run_image.prepare_result(sim.interface(), &ws, &other, &.{}, &prepared, &diag);
    try testing.expect(!ran);
    const host = sim.interface();
    const named = try run_image.prepare_result(host, &ws, "alpine", &.{}, &prepared, &diag);
    try testing.expect(!named);
    try testing.expect(diag.code == null);
}

test "a record whose bytes do not hash to its name is refused" {
    // Goal: damage is an error, not a plain tree. Method: flip a byte of the record's file.
    const digest = try saved();
    var path: @import("store/fs.zig").PathBuf = undefined;
    files.flip_byte(store.build_result_path(&path, digest), 3);
    const text = digest.text();
    const failed = run_image.prepare_result(sim.interface(), &ws, &text, &.{}, &prepared, &diag);
    try testing.expectError(error.Failed, failed);
    try testing.expect(diag.code != null);
}
