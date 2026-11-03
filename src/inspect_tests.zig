//! `zbx inspect <result digest>` (`inspect_commands.zig`) in the simulated store.

const std = @import("std");
const constants = @import("constants.zig");
const inspect = @import("inspect_commands.zig");
const result = @import("build/result.zig");
const Diag = @import("diag/diag.zig").Diag;
const Digest = @import("store/digest.zig").Digest;
const Workspace = inspect.Workspace;
const run = inspect.run;
const render_json = inspect.render_json;
const render_text = inspect.render_text;
const Store = @import("store/layout.zig").Store;

const testing = std.testing;
const fs_sim = @import("store/fs_sim.zig");
const host_sim = @import("host_sim.zig");
const support = @import("store/test_support.zig");
const test_util = @import("test_util.zig");

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: Store = undefined;
var ws: Workspace = undefined;
var record: result.Record = undefined;
var save_buffer: [constants.build_result_bytes_max]u8 = undefined;
var diag: Diag = undefined;

const home = [_]host_sim.EnvironmentVariable{.{ .name = "HOME", .value = "/home/alice" }};

fn saved() !Digest {
    sim.init(1, &.{});
    files.init(1);
    sim.store_fs = &files;
    sim.environment_variables = &home;
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    store.at(sim.interface(), support.user_store);
    record.config.clear();
    _ = record.config.settings.add(.entrypoint, "/usr/bin/hello");
    _ = record.config.settings.add(.env, "A=\"quoted\"");
    _ = record.config.settings.set(.user, "5:5");
    _ = record.config.add_label("org.example/key", "va\nlue");
    record.tree = Digest.of("tree");
    var failure: result.Failure = undefined;
    diag.reset();
    return try result.save(&store, &record, &save_buffer, &failure);
}

test "inspect prints the tree and the config, as text and as one JSON line" {
    // Goal: both forms. Method: save a record, inspect it, parse the JSON.
    const digest = try saved();
    const text = digest.text();
    try run(sim.interface(), &ws, &text, false, &diag);
    const out = sim.stdout();
    try testing.expect(std.mem.indexOf(u8, out, &record.tree.text()) != null);
    try testing.expect(std.mem.indexOf(u8, out, "entrypoint /usr/bin/hello\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "va?lue") != null); // Control bytes are cut.
    _ = try saved();
    try run(sim.interface(), &ws, &text, true, &diag);
    const line = sim.stdout();
    try testing.expect(try test_util.json_is_valid(line));
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("zbx.build_result/1", root.get("schema").?.string);
    try testing.expectEqualStrings(&digest.text(), root.get("digest").?.string);
    const config = root.get("config").?.object;
    const entrypoint = config.get("entrypoint").?.array.items;
    try testing.expectEqualStrings("/usr/bin/hello", entrypoint[0].string);
    try testing.expectEqualStrings("5:5", config.get("user").?.string);
    const labels = config.get("labels").?.object;
    try testing.expectEqualStrings("va\nlue", labels.get("org.example/key").?.string);
}

test "inspect refuses what is no digest and what is not in the store" {
    // Goal: E0005 for both. Method: a name, then a well-formed digest with no record.
    _ = try saved();
    try testing.expectError(error.Failed, run(sim.interface(), &ws, "alpine", false, &diag));
    try testing.expectEqual(.E0005, diag.code.?);
    diag.reset();
    const absent = Digest.of("nothing").text();
    try testing.expectError(error.Failed, run(sim.interface(), &ws, &absent, false, &diag));
    try testing.expectEqual(.E0005, diag.code.?);
    try testing.expect(std.mem.indexOf(u8, diag.last_cause().?, "no build result") != null);
}

test "the largest escaped config fits the output buffer" {
    // Goal: `inspect_output_bytes_max` at the bound. Method: control bytes (six bytes each
    // escaped) fill the settings block and one label value to their limits.
    record.config.clear();
    const filler: [constants.image_settings_bytes_max / 2]u8 = @splat(1);
    _ = record.config.settings.add(.cmd, &filler);
    _ = record.config.settings.add(.cmd, filler[0 .. filler.len - 64]);
    var big: [constants.build_result_label_bytes_max - 8]u8 = @splat(2);
    _ = record.config.add_label("k", &big);
    record.tree = Digest.of("tree");
    var writer = std.Io.Writer.fixed(&ws.out);
    try render_json(&writer, Digest.of("record"), &record);
    try testing.expect(writer.buffered().len > 6 * big.len);
    try testing.expect(writer.buffered().len <= constants.inspect_output_bytes_max);
    var again = std.Io.Writer.fixed(&ws.out);
    try render_text(&again, Digest.of("record"), &record);
}
