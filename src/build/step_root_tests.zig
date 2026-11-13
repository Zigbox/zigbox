//! A root step's output (`.output = .root`) through `run_step` on the simulator: the step's
//! upper layer, committed onto its base tree, is the output. What the commit does with every
//! kind of layer entry is `store/commit_tests.zig`; here the step's own part: no `/out`, the
//! commit happens before the container's directories go, a failed step commits nothing, and a
//! device, FIFO or socket in the layer is E0806. The command's writes are stood in for by the
//! store's hook, as in `step_tests.zig`.

const std = @import("std");
const codes = @import("../diag/codes.zig");
const constants = @import("../constants.zig");
const sim_run = @import("../runtime/sim_run.zig");
const sim_world = @import("../sim_world.zig");
const digest_mod = @import("../store/digest.zig");
const support = @import("../store/test_support.zig");
const tree = @import("../store/tree.zig");
const trees = @import("../store/trees.zig");
const key_mod = @import("key.zig");
const step = @import("step.zig");
const tests = @import("step_tests.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

/// What the command leaves in its upper layer, written when the hook fires.
const Layer = struct {
    kind: enum { added, deleted, fifo, nothing },

    fn write(context: *anyopaque) void {
        const layer: *const Layer = @ptrCast(@alignCast(context));
        const upper = find_upper().?;
        var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
        switch (layer.kind) {
            .nothing => {},
            .added => {
                tests.files.put_dir(tests.join(&path, upper, "/opt"), 0o755);
                tests.files.put_file(tests.join(&path, upper, "/opt/tool"), 0o755, "#!tool\n");
                tests.files.put_dir(tests.join(&path, upper, "/etc"), 0o755);
                tests.files.put_file(tests.join(&path, upper, "/etc/new"), 0o644, "new\n");
            },
            .deleted => {
                tests.files.put_dir(tests.join(&path, upper, "/bin"), 0o755);
                const ls = tests.join(&path, upper, "/bin/ls");
                tests.files.put(ls, .char_device, 0, .{ 0, 0 }, "");
            },
            .fifo => {
                tests.files.put(tests.join(&path, upper, "/pipe"), .fifo, 0o644, .{ 0, 0 }, "");
            },
        }
    }
};

/// The step's upper layer, while the container's directory exists.
fn find_upper() ?[]const u8 {
    var index: u32 = 0;
    while (tests.files.alive_path(index)) |path| : (index += 1) {
        if (std.mem.startsWith(u8, path, tests.state ++ "/") and
            std.mem.endsWith(u8, path, "/upper")) return path;
    }
    return null;
}

fn root_spec(fixture: *const tests.Fixture) key_mod.Spec {
    var spec = tests.spec_for(fixture);
    spec.root_output = true;
    return spec;
}

/// Whether the tree `root` holds `path` (relative, `/`-separated, no leading slash).
fn has(root: Digest, path: []const u8) !bool {
    var buffer: [constants.store_tree_bytes_max]u8 = undefined;
    var errno: u16 = 0;
    const bytes = try trees.load(&tests.store, root, &buffer, &errno);
    var decoder: tree.Decoder = undefined;
    try decoder.init(bytes);
    const slash = std.mem.indexOfScalar(u8, path, '/');
    const head = if (slash) |at| path[0..at] else path;
    var entry: tree.Entry = undefined;
    while (try decoder.next(&entry)) {
        if (!std.mem.eql(u8, entry.name, head)) continue;
        const at = slash orelse return true;
        if (entry.kind != .dir) return false;
        return has(entry.subtree, path[at + 1 ..]);
    }
    return false;
}

const Ran = struct { fixture: tests.Fixture, before: sim_run.Baseline };

/// Runs the root step with `kind` in its layer; the outcome is in `tests.diag` and `tests.result`.
fn run_root(
    seed: u64,
    kind: @TypeOf(@as(Layer, undefined).kind),
    exit: @import("../host.zig").ExitStatus,
) !Ran {
    const fixture = try tests.setup(seed, "fetch");
    tests.sim.world.command_exit = exit;
    const before = sim_run.baseline(&tests.sim);
    var layer: Layer = .{ .kind = kind };
    tests.files.hook = .{
        .rename_to_contains = "fetch.log",
        .context = &layer,
        .call = Layer.write,
    };
    const spec = root_spec(&fixture);
    const request: step.Request = .{
        .host = tests.sim.interface(),
        .facts = &tests.facts,
        .spec = &spec,
        .file = "zbx.build.zon",
        .group = tests.group,
        .stream = false,
    };
    tests.diag.reset();
    step.run_step(&request, &tests.workspace, &tests.result, &tests.diag) catch {};
    return .{ .fixture = fixture, .before = before };
}

test "a root step's output is its layer on its base: the base's files and the command's" {
    // Goal: the output of a root step is the committed upper layer. Method: the command adds
    // /opt/tool and /etc/new; the output holds them and the base's own files, is not the base,
    // and the step leaves nothing behind (no /out, no work directory, one `build:fetch` root).
    const ran = try run_root(11, .added, .{ .exited = 0 });
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    const output = tests.result.output;
    try testing.expect(!output.eql(ran.fixture.base));
    try testing.expect(try has(output, "opt/tool"));
    try testing.expect(try has(output, "etc/new"));
    try testing.expect(try has(output, "etc/passwd"));
    try testing.expect(try has(output, "bin/sh"));
    try tests.expect_clean(&ran.fixture, &ran.before);
}

test "a root step that changes nothing has its base as its output" {
    // Goal: an output is a function of what changed. Method: an empty layer commits to the
    // base's own digest, which the user's root already holds: no `build:` root is added.
    const ran = try run_root(12, .nothing, .{ .exited = 0 });
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(tests.result.output.eql(ran.fixture.base));
    // The base's and the input's roots, from the fixture.
    try testing.expectEqual(@as(u32, 2), support.count_files(&tests.files, tests.store_root ++ "/roots"));
    try testing.expectEqual(@as(?[]const u8, null), sim_run.leak(&tests.sim, &ran.before));
}

test "a file the command deleted is not in a root step's output" {
    // Goal: a deletion (a 0/0 device in the layer) is applied, not kept as a whiteout.
    // Method: /bin/ls goes; /bin/sh stays; no device is in the output.
    const ran = try run_root(13, .deleted, .{ .exited = 0 });
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(!(try has(tests.result.output, "bin/ls")));
    try testing.expect(try has(tests.result.output, "bin/sh"));
    try tests.expect_clean(&ran.fixture, &ran.before);
}

test "a FIFO the command made is E0806 and nothing is rooted" {
    // Goal: an output holds only files, directories and links, a root step's too. Method: a
    // FIFO in the layer; the step fails naming it and leaves no root.
    const ran = try run_root(14, .fifo, .{ .exited = 0 });
    try testing.expectEqual(@as(?codes.Code, .E0806), tests.diag.code);
    try tests.expect_clean(&ran.fixture, &ran.before);
}

test "a root step that exits non-zero commits nothing" {
    // Goal: a failed step's layer is not an output. Method: exit 2 with files in the layer; the
    // step is E0805 and the store holds no new root.
    const ran = try run_root(15, .added, .{ .exited = 2 });
    try testing.expectEqual(@as(?codes.Code, .E0805), tests.diag.code);
    try tests.expect_clean(&ran.fixture, &ran.before);
}
