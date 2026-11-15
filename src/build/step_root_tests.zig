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
const pin = @import("pin.zig");
const import_mod = @import("../store/import.zig");

const testing = std.testing;
const Digest = digest_mod.Digest;

/// What the command leaves in its upper layer, written when the hook fires.
const Layer = struct {
    kind: enum { added, deleted, fifo, nothing, excluded, rosetta, rosetta_and_own },

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
            .excluded => write_excluded(upper),
            .rosetta, .rosetta_and_own => {
                tests.files.put_dir(tests.join(&path, upper, "/root"), 0o700);
                tests.files.put_dir(tests.join(&path, upper, "/root/.cache"), 0o755);
                tests.files.put_dir(tests.join(&path, upper, "/root/.cache/rosetta"), 0o755);
                if (layer.kind == .rosetta_and_own) {
                    const own = tests.join(&path, upper, "/root/.cache/own");
                    tests.files.put_file(own, 0o644, "the step's\n");
                }
            },
        }
    }
};

/// What a pinned step writes besides its content: a log under /var/log (a default exclude) and
/// a file under /skip (a written one), next to /opt/tool, which is content.
fn write_excluded(top: []const u8) void {
    var path: [constants.sim_fs_path_bytes_max]u8 = undefined;
    tests.files.put_dir(tests.join(&path, top, "/opt"), 0o755);
    tests.files.put_file(tests.join(&path, top, "/opt/tool"), 0o755, "#!tool\n");
    tests.files.put_dir(tests.join(&path, top, "/var"), 0o755);
    tests.files.put_dir(tests.join(&path, top, "/var/log"), 0o755);
    tests.files.put_file(tests.join(&path, top, "/var/log/fetch.log"), 0o644, "12:00:01\n");
    tests.files.put_dir(tests.join(&path, top, "/skip"), 0o755);
    tests.files.put_file(tests.join(&path, top, "/skip/stamp"), 0o644, "12:00:02\n");
}

/// The command's writes to `/out`, for a step that is not a root step.
fn write_out_excluded(context: *anyopaque) void {
    _ = context;
    write_excluded(tests.find_out().?);
}

/// A pinned step's excludes: the default list, which has /var/log, and a written path.
const pinned_excludes = pin.default_excludes ++ [_][]const u8{"/skip"};

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
    return run_root_excluding(seed, kind, exit, null);
}

fn run_root_excluding(
    seed: u64,
    kind: @TypeOf(@as(Layer, undefined).kind),
    exit: @import("../host.zig").ExitStatus,
    output_exclude: ?[]const []const u8,
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
    var spec = root_spec(&fixture);
    spec.output_exclude = output_exclude;
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
    const roots = support.count_files(&tests.files, tests.store_root ++ "/roots");
    try testing.expectEqual(@as(u32, 2), roots);
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

test "a pinned root step's output leaves out /var/log and its written excludes" {
    // Goal: the excludes reach the commit (`commit_output`). Method: the layer adds /opt/tool,
    // /var/log/fetch.log and /skip/stamp; with the default excludes and /skip, only /opt/tool
    // is in the output. Without excludes all three are, so the check can fail.
    const ran = try run_root_excluding(16, .excluded, .{ .exited = 0 }, &pinned_excludes);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(try has(tests.result.output, "opt/tool"));
    try testing.expect(!(try has(tests.result.output, "var/log/fetch.log")));
    try testing.expect(!(try has(tests.result.output, "skip")));
    try tests.expect_clean(&ran.fixture, &ran.before);
    _ = try run_root_excluding(16, .excluded, .{ .exited = 0 }, null);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(try has(tests.result.output, "var/log/fetch.log"));
    try testing.expect(try has(tests.result.output, "skip/stamp"));
}

test "a pinned step's /out leaves out /var/log and its written excludes" {
    // Goal: the excludes reach the import of /out (`import_output`). Method: the command writes
    // /opt/tool, /var/log/fetch.log and /skip/stamp to /out; with the excludes only /opt/tool
    // is in the output, and without them all three are.
    for ([_]?[]const []const u8{ &pinned_excludes, null }) |output_exclude| {
        const fixture = try tests.setup(17, "fetch");
        const before = sim_run.baseline(&tests.sim);
        var unused: u8 = 0;
        tests.files.hook = .{
            .rename_to_contains = "fetch.log",
            .context = &unused,
            .call = write_out_excluded,
        };
        var spec = tests.spec_for(&fixture);
        spec.output_exclude = output_exclude;
        try tests.run_it(&spec);
        try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
        const kept = output_exclude == null;
        try testing.expect(try has(tests.result.output, "opt/tool"));
        try testing.expectEqual(kept, try has(tests.result.output, "var/log/fetch.log"));
        try testing.expectEqual(kept, try has(tests.result.output, "skip/stamp"));
        try tests.expect_clean(&fixture, &before);
    }
}

/// The platform that is not the simulated machine's (`x86_64`): a step on it is foreign, as a
/// linux/amd64 step under Rosetta is on a Mac.
const foreign_platform = "linux/arm64";

/// A base with /root, as an image's is, and /root/.cache/kept when `with_cache`.
fn import_home_base(with_cache: bool) !Digest {
    const top = if (with_cache) "/cached" else "/homed";
    var path: [64]u8 = undefined;
    tests.files.put_dir(top, 0o755);
    tests.files.put_dir(tests.join(&path, top, "/root"), 0o700);
    if (with_cache) {
        tests.files.put_dir(tests.join(&path, top, "/root/.cache"), 0o755);
        tests.files.put_file(tests.join(&path, top, "/root/.cache/kept"), 0o644, "the base's\n");
    }
    var imported: import_mod.Result = undefined;
    tests.diag.reset();
    const options: import_mod.Options = .{ .squash_owner = false, .warn = null };
    try import_mod.import(&tests.store, &tests.import_ws, top, options, &imported, &tests.diag);
    return imported.digest;
}

/// Runs the root step with `kind` in its layer on `platform`, on a base with /root (and
/// /root/.cache when `with_cache`); returns that base.
fn run_on(
    seed: u64,
    kind: @TypeOf(@as(Layer, undefined).kind),
    platform: []const u8,
    with_cache: bool,
) !Digest {
    const fixture = try tests.setup(seed, "fetch");
    const base = try import_home_base(with_cache);
    tests.sim.world.command_exit = .{ .exited = 0 };
    var layer: Layer = .{ .kind = kind };
    tests.files.hook = .{
        .rename_to_contains = "fetch.log",
        .context = &layer,
        .call = Layer.write,
    };
    var spec = root_spec(&fixture);
    spec.platform = platform;
    spec.base_tree = base;
    try tests.run_it(&spec);
    return base;
}

test "a foreign root step's output leaves out Rosetta's cache and the .cache it made" {
    // Goal: Rosetta's `/root/.cache/rosetta` is the machine's, not the step's (Mac run
    // 43747691774: the two directories changed demo-m9's digest). Method: a foreign step whose
    // layer holds only them has its base as its output; the same layer on the machine's own
    // platform keeps both, so the check can fail.
    const base = try run_on(18, .rosetta, foreign_platform, false);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(tests.result.output.eql(base));
    const native = try run_on(18, .rosetta, "linux/amd64", false);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(!tests.result.output.eql(native));
    try testing.expect(try has(tests.result.output, "root/.cache/rosetta"));
}

test "a foreign root step keeps its own files in .cache, without Rosetta's" {
    // Goal: only Rosetta's directory goes. Method: the layer adds /root/.cache/own next to the
    // cache; the output has it and its .cache, and not the cache.
    _ = try run_on(19, .rosetta_and_own, foreign_platform, false);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(try has(tests.result.output, "root/.cache/own"));
    try testing.expect(!(try has(tests.result.output, "root/.cache/rosetta")));
}

test "a foreign root step whose base has .cache keeps it as the base has it" {
    // Goal: a `.cache` the base has is not the step's to drop, nor Rosetta's. Method: a base
    // with /root/.cache/kept; the layer holds the copied-up .cache and Rosetta's cache; the
    // output is that base, so .cache and its file are there unchanged.
    const base = try run_on(20, .rosetta, foreign_platform, true);
    try testing.expectEqual(@as(?codes.Code, null), tests.diag.code);
    try testing.expect(tests.result.output.eql(base));
    try testing.expect(try has(tests.result.output, "root/.cache/kept"));
}
