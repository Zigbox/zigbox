//! The library's start behind the trust gate (`start_gate.zig`, docs/briefs/library-trust-gate.md)
//! against the simulated host and store: the same image and policy give the same verdict through
//! `zbx run` and through `zigbox.start`, the refusal is the diagnostic `zbx run` prints, and with
//! no policy file the gate reads nothing beyond the policy lookup.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const constants = @import("../constants.zig");
const codes = @import("../diag/codes.zig");
const Diag = @import("../diag/diag.zig").Diag;
const render = @import("../diag/render.zig");
const host_mod = @import("../host.zig");
const host_sim = @import("../host_sim.zig");
const import = @import("../store/import.zig");
const layout = @import("../store/layout.zig");
const fs_mod = @import("../store/fs.zig");
const fs_sim = @import("../store/fs_sim.zig");
const support = @import("../store/test_support.zig");
const result = @import("../build/result.zig");
const image_mod = @import("../runtime/image.zig");
const records = @import("../runtime/records.zig");
const run = @import("../runtime/run.zig");
const sim_run = @import("../runtime/sim_run.zig");
const spec_mod = @import("../runtime/spec.zig");
const Digest = @import("../store/digest.zig").Digest;
const key = @import("key.zig");
const key_store = @import("key_store.zig");
const provenance = @import("provenance.zig");
const provenance_store = @import("provenance_store.zig");
const start_gate = @import("start_gate.zig");
const images = @import("../store/images.zig");
const exec = @import("../runtime/exec.zig");
const Sha256 = @import("../registry/digest.zig").Sha256;

const policy_path = "/home/alice/.config/zbx/policy.zon";
const state = "/home/alice/.local/state/zbx/containers";

var sim: host_sim.HostSim = undefined;
var files: fs_sim.SimFs = undefined;
var store: layout.Store = undefined;
var import_work: import.Workspace = undefined;
var image_ws: image_mod.Workspace = undefined;
var gate_ws: start_gate.Workspace = undefined;
var handle: run.Handle = undefined;
var record: result.Record = undefined;
var record_bytes: [constants.build_result_bytes_max]u8 = undefined;
var tree: Digest = undefined;
var built: Digest = undefined;
var tree_text: [constants.store_digest_text_bytes:0]u8 = undefined;
var built_text: [constants.store_digest_text_bytes:0]u8 = undefined;

fn command(args: []const [:0]const u8) u8 {
    var items: [14][:0]const u8 = undefined;
    items[0] = "zbx";
    @memcpy(items[1 .. 1 + args.len], args);
    sim.stdout_len = 0;
    sim.stderr_len = 0;
    return sim_run.run_cli(&sim, items[0 .. 1 + args.len]);
}

/// A store with the sample tree, a build result of it, and the key `ci`; no policy file yet.
fn setup(seed: u64) !void {
    sim_run.init(&sim, seed);
    files.init(seed);
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
    tree_text = terminated(tree);
    built_text = terminated(built);
    try testing.expectEqual(@as(u8, 0), command(&.{ "key", "new", "ci", "--no-passphrase" }));
}

fn terminated(digest: Digest) [constants.store_digest_text_bytes:0]u8 {
    var out: [constants.store_digest_text_bytes:0]u8 = undefined;
    const text = digest.text();
    @memcpy(out[0..text.len], &text);
    out[text.len] = 0;
    return out;
}

/// Writes the user's policy file: the key `ci` listed, and `rule` (`require_signature` or
/// `require_provenance`) set.
fn write_policy(rule: []const u8) !void {
    try write_policy_at(policy_path, rule);
}

/// Writes the policy file at `path` as `write_policy` does.
fn write_policy_at(path: []const u8, rule: []const u8) !void {
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
            ".{s} = true }}",
        .{ public, rule },
    );
    files.put_file(path, 0o644, text);
}

/// The trust code `zbx run` refused `operand` with, or null when the gate let it through.
fn verdict_of_cli(operand: [:0]const u8) ?codes.Code {
    const status = command(&.{ "run", operand, "--", "/bin/sh" });
    const stderr = sim.stderr();
    const at = std.mem.indexOf(u8, stderr, "ZBX-E09") orelse return null;
    assert(at + "ZBX-E0900".len <= stderr.len);
    assert(status == 125);
    return std.meta.stringToEnum(codes.Code, stderr[at + 4 .. at + 9]);
}

/// `head` then `tail` in `buffer`.
fn join(buffer: []u8, head: []const u8, tail: []const u8) []const u8 {
    assert(head.len + tail.len <= buffer.len);
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ head, tail }) catch unreachable; // Fits.
}

/// The merged directory in the container model, as the overlay would show the tree.
fn world_dirs(name: []const u8) void {
    var path: [200]u8 = undefined;
    var container: [200]u8 = undefined;
    var inner: [220]u8 = undefined;
    const base = join(&container, state ++ "/", name);
    const merged = join(&path, base, "/merged");
    sim.world.add_node(merged, .dir);
    sim.world.add_node(join(&inner, base, "/net"), .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        sim.world.add_node(join(&inner, merged, suffix), .dir);
    }
    sim.world.add_node(join(&inner, merged, "/bin/sh"), .file);
    for ([_][]const u8{ "/etc/hosts", "/etc/resolv.conf", "/etc/hostname" }) |suffix| {
        sim.world.add_node(join(&inner, merged, suffix), .file);
    }
}

fn spec_of(image: []const u8, name: []const u8, binding: spec_mod.Binding) spec_mod.Spec {
    return .{
        .image = image,
        .name = name,
        .command = &.{ "/bin/sh", "-c", "true" },
        .binding = binding,
    };
}

/// The trust code the library's start refused `spec` with, or null when the gate let it
/// through (the start may still fail later, for the simulator's reasons, never a trust code).
fn verdict_of_library(spec: *const spec_mod.Spec, diag: *Diag) ?codes.Code {
    return verdict_with(spec, null, diag);
}

/// `verdict_of_library`, with the caller's own tree check `check`.
fn verdict_with(spec: *const spec_mod.Spec, check: ?image_mod.Check, diag: *Diag) ?codes.Code {
    world_dirs(spec.name.?);
    diag.reset();
    const options: run.StartOptions = .{ .image_workspace = &image_ws, .tree_check = check };
    start_gate.start(sim.interface(), spec, options, &handle, &gate_ws, diag) catch {
        const code = diag.code.?;
        const name = @tagName(code);
        if (std.mem.startsWith(u8, name, "E090")) return code;
        return null;
    };
    assert(diag.code == null);
    return null;
}

const Case = struct {
    title: []const u8,
    /// The rule of the policy file; null: no file at all.
    rule: ?[]const u8,
    /// Run as the build result (bound to it) rather than as the bare tree.
    as_result: bool,
    sign_tree: bool = false,
    sign_result: bool = false,
    store_provenance: bool = false,
    want: ?codes.Code,
};

const cases = [_]Case{
    .{ .title = "no policy", .rule = null, .as_result = false, .want = null },
    .{
        .title = "unsigned refused",
        .rule = "require_signature",
        .as_result = false,
        .want = .E0905,
    },
    .{
        .title = "signed accepted",
        .rule = "require_signature",
        .as_result = false,
        .sign_tree = true,
        .want = null,
    },
    .{
        .title = "provenance required, none stored",
        .rule = "require_provenance",
        .as_result = true,
        .sign_result = true,
        .want = .E0906,
    },
    .{
        .title = "provenance required, stored and signed",
        .rule = "require_provenance",
        .as_result = true,
        .sign_result = true,
        .store_provenance = true,
        .want = null,
    },
};

test "zbx run and the library start give the same verdict for the same image and policy" {
    // Goal: one judge for both doors (the owner's 2026-11-13 decision). Method: for each case, a
    // fresh store and policy; `zbx run` of the tree (or the result) and the library start of the
    // same tree (bound to the result when the command line would be) give the same trust code.
    for (cases, 0..) |case, index| {
        errdefer std.debug.print("case: {s}\n", .{case.title});
        try setup(40 + index);
        if (case.rule) |rule| try write_policy(rule);
        // A stored provenance record is signed with the result, so it comes first.
        if (case.store_provenance) try save_provenance_of_built();
        if (case.sign_tree) try sign(&tree_text);
        if (case.sign_result) try sign(&built_text);
        const operand: [:0]const u8 = if (case.as_result) &built_text else &tree_text;
        const from_cli = verdict_of_cli(operand);
        const binding: spec_mod.Binding = if (case.as_result)
            .{ .result = built.bytes }
        else
            .none;
        const spec = spec_of(&tree_text, "lib-1", binding);
        var diag: Diag = undefined;
        const from_library = verdict_of_library(&spec, &diag);
        try testing.expectEqual(case.want, from_cli);
        try testing.expectEqual(case.want, from_library);
    }
}

fn sign(operand: [:0]const u8) !void {
    try testing.expectEqual(@as(u8, 0), command(&.{ "sign", operand, "--key", "ci" }));
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
    var failure: fs_mod.Failure = undefined;
    const bytes = provenance.render(&provenance_bytes, made);
    try provenance_store.save(&store, built, bytes, &failure);
}

test "a library start refused by the policy reports what zbx run prints and makes nothing" {
    // Goal: the refusal is the same diagnostic at both doors, and nothing is made. Method: an
    // unsigned tree under require_signature, given to the library by a 12-digit prefix; the
    // rendered diagnostic is `zbx run`'s stderr for the full digest, it names the full digest in
    // its fix, no scope started, no run record was written, and the handle is still starting.
    try setup(50);
    try write_policy("require_signature");
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_cli(&tree_text));
    var printed: [constants.output_bytes_max]u8 = undefined;
    const cli_text = sim.stderr();
    @memcpy(printed[0..cli_text.len], cli_text);
    const spec = spec_of(tree_text[3..15], "lib-2", .none);
    var diag: Diag = undefined;
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_library(&spec, &diag));
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(&diag, .text, false, &buffer);
    try testing.expectEqualStrings(printed[0..cli_text.len], text);
    const fix = "zbx sign " ++ tree_text;
    try testing.expect(std.mem.indexOf(u8, text, fix) != null);
    try testing.expect(std.mem.indexOf(u8, text, "{") == null);
    try testing.expect(sim.world.bus.scope_started == null);
    try testing.expect(files.kind_of(state ++ "/lib-2") == null);
    var dir: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &dir));
    var parsed: records.Parsed = undefined;
    const loaded = records.load(sim.interface(), &dir, "lib-2", &parsed);
    try testing.expectError(error.NotFound, loaded);
    try testing.expectEqual(run.Phase.starting, handle.status);
}

/// The paths the gate's host read through, in the no-policy test.
var touched: [16][constants.path_bytes_max]u8 = undefined;
var touched_len: [16]u16 = undefined;
var touched_count: u32 = 0;
var inner_vtable: *const fs_mod.VTable = undefined;
var counting_vtable: fs_mod.VTable = undefined;
var counting_host_vtable: host_mod.VTable = undefined;
var sim_filesystem: *const fn (context: *anyopaque) fs_mod.Fs = undefined;

fn touch(path: []const u8) void {
    assert(touched_count < touched.len);
    assert(path.len <= constants.path_bytes_max);
    @memcpy(touched[touched_count][0..path.len], path);
    touched_len[touched_count] = @intCast(path.len);
    touched_count += 1;
}

fn counting_filesystem(context: *anyopaque) fs_mod.Fs {
    const inner = sim_filesystem(context);
    inner_vtable = inner.vtable;
    counting_vtable = inner.vtable.*;
    counting_vtable.lstat = counting_lstat;
    counting_vtable.read_dir = counting_read_dir;
    counting_vtable.open_read = counting_open_read;
    counting_vtable.open_directory = counting_open_directory;
    counting_vtable.create = counting_create;
    counting_vtable.make_directory = counting_make_directory;
    return .{ .context = inner.context, .vtable = &counting_vtable };
}

fn counting_lstat(context: *anyopaque, path: [:0]const u8) fs_mod.Error!fs_mod.Stat {
    touch(path);
    return inner_vtable.lstat(context, path);
}

fn counting_read_dir(
    context: *anyopaque,
    path: [:0]const u8,
    visitor: fs_mod.Visitor,
) fs_mod.Error!void {
    touch(path);
    return inner_vtable.read_dir(context, path, visitor);
}

fn counting_open_read(context: *anyopaque, path: [:0]const u8) fs_mod.Error!fs_mod.Fd {
    touch(path);
    return inner_vtable.open_read(context, path);
}

fn counting_open_directory(context: *anyopaque, path: [:0]const u8) fs_mod.Error!fs_mod.Fd {
    touch(path);
    return inner_vtable.open_directory(context, path);
}

fn counting_create(context: *anyopaque, path: [:0]const u8, mode: u16) fs_mod.Error!fs_mod.Fd {
    touch(path);
    return inner_vtable.create(context, path, mode);
}

fn counting_make_directory(
    context: *anyopaque,
    path: [:0]const u8,
    exist_ok: bool,
) fs_mod.Error!void {
    touch(path);
    return inner_vtable.make_directory(context, path, exist_ok);
}

fn counting_host_open_read(
    context: *anyopaque,
    path: [:0]const u8,
) host_mod.Error!host_mod.Handle {
    touch(path);
    return sim_host_open_read(context, path);
}

fn counting_host_stat(context: *anyopaque, path: [:0]const u8) host_mod.Error!host_mod.Stat {
    touch(path);
    return sim_host_stat(context, path);
}

var sim_host_open_read: @FieldType(host_mod.VTable, "open_read") = undefined;
var sim_host_stat: @FieldType(host_mod.VTable, "stat") = undefined;

/// The simulated host, with every path it opens, lists or makes recorded in `touched`.
fn counting_host() host_mod.Host {
    const plain = sim.interface();
    counting_host_vtable = plain.vtable.*;
    sim_filesystem = plain.vtable.filesystem;
    sim_host_open_read = plain.vtable.open_read;
    sim_host_stat = plain.vtable.stat;
    counting_host_vtable.filesystem = counting_filesystem;
    counting_host_vtable.open_read = counting_host_open_read;
    counting_host_vtable.stat = counting_host_stat;
    touched_count = 0;
    return .{ .context = plain.context, .vtable = &counting_host_vtable };
}

test "with no policy file the library's gate reads nothing beyond the policy lookup" {
    // Goal: no policy costs nothing and changes nothing. Method: the gate alone (`admit`) on a
    // host that records every path it opens, lists or makes, for a tree given by a prefix and
    // bound to a manifest (which, judged, would read the store and the image record); only the
    // two policy files were looked up, the Spec is unchanged, and the options are the caller's.
    try setup(60);
    const host = counting_host();
    var spec = spec_of(tree_text[3..15], "lib-3", .{ .manifest = @splat(0xab) });
    const before = spec;
    var diag: Diag = undefined;
    diag.reset();
    const options: run.StartOptions = .{ .image_workspace = &image_ws };
    const gated = try start_gate.admit(host, &spec, options, &gate_ws, &diag);
    try testing.expectEqual(@as(u32, 2), touched_count);
    const system = touched[0][0..touched_len[0]];
    const user = touched[1][0..touched_len[1]];
    try testing.expectEqualStrings(constants.policy_system_path, system);
    try testing.expectEqualStrings(policy_path, user);
    try testing.expectEqual(before.image.?.ptr, spec.image.?.ptr);
    try testing.expect(gated.tree_check == null);
    try testing.expect(gated.image_workspace == options.image_workspace);
    try testing.expect(diag.code == null);
}

/// The path of the stored object whose bytes are `content`.
fn object_with(content: []const u8) []const u8 {
    var index: u32 = 0;
    while (index < files.count) : (index += 1) {
        const path = files.alive_path(index) orelse continue;
        if (files.kind_of(path) != .file) continue;
        if (std.mem.indexOf(u8, path, "/objects/") == null) continue;
        if (std.mem.endsWith(u8, path, ".chunks")) continue;
        if (std.mem.eql(u8, files.content_of(path).?, content)) return path;
    }
    unreachable; // The sample tree has an object of each content the tests name.
}

test "a damaged stored object is refused at both doors, whatever the policy asks" {
    // Goal: the tamper check (E0907) is on in the library whenever a policy file exists, as it
    // is in `zbx run`. Method: a policy file that asks nothing, then one that requires a
    // signature with the tree signed; a byte of a stored object is flipped; both doors refuse
    // with E0907. With the byte flipped back both admit it.
    for ([_]bool{ false, true }, 0..) |signed, index| {
        try setup(70 + index);
        if (signed) {
            try write_policy("require_signature");
            try sign(&tree_text);
        } else {
            files.put_file(policy_path, 0o644, ".{ .version = 1 }");
        }
        const object = object_with("root:x:0:0\n");
        files.flip_byte(object, 0);
        const spec = spec_of(&tree_text, "lib-4", .none);
        var diag: Diag = undefined;
        try testing.expectEqual(@as(?codes.Code, .E0907), verdict_of_cli(&tree_text));
        try testing.expectEqual(@as(?codes.Code, .E0907), verdict_of_library(&spec, &diag));
        files.flip_byte(object, 0);
        try testing.expectEqual(@as(?codes.Code, null), verdict_of_cli(&tree_text));
        const again = spec_of(&tree_text, "lib-5", .none);
        try testing.expectEqual(@as(?codes.Code, null), verdict_of_library(&again, &diag));
    }
}

/// A caller's own tree check, which notes the tree it was asked about.
const CallerCheck = struct {
    calls: u32 = 0,
    tree: ?Digest = null,

    fn check(self: *CallerCheck) image_mod.Check {
        return .{ .context = self, .call = call };
    }

    fn call(context: *anyopaque, _: *layout.Store, checked: Digest, diag: *Diag) bool {
        const self: *CallerCheck = @ptrCast(@alignCast(context));
        assert(diag.code == null);
        self.calls += 1;
        self.tree = checked;
        return true;
    }
};

test "the caller's own tree check runs after the tamper check, on the tree judged" {
    // Goal: the gate keeps the caller's `tree_check` and runs it after its own, and the start
    // runs the tree the gate judged. Method: a tree given by a prefix, with and without a policy
    // file; `admit` rewrites the image to the full digest when a policy asks for something, the
    // caller's check is called once with the tree, and with a damaged object (policy present) it
    // is not called at all, since the tamper check refuses first.
    for ([_]bool{ false, true }, 0..) |policy, index| {
        try setup(80 + index);
        if (policy) try write_policy("require_signature");
        if (policy) try sign(&tree_text);
        var caller: CallerCheck = .{};
        const spec = spec_of(tree_text[3..15], "lib-6", .none);
        var diag: Diag = undefined;
        try testing.expectEqual(@as(?codes.Code, null), verdict_with(&spec, caller.check(), &diag));
        try testing.expectEqual(@as(u32, 1), caller.calls);
        try testing.expect(caller.tree.?.eql(tree));
        if (!policy) continue;
        var judged = spec_of(tree_text[3..15], "lib-7", .none);
        diag.reset();
        const options: run.StartOptions = .{ .image_workspace = &image_ws };
        _ = try start_gate.admit(sim.interface(), &judged, options, &gate_ws, &diag);
        try testing.expectEqualStrings(&tree_text, judged.image.?);
        caller = .{};
        files.flip_byte(object_with("setuid\n"), 0);
        const damaged = spec_of(&tree_text, "lib-8", .none);
        const refused = verdict_with(&damaged, caller.check(), &diag);
        try testing.expectEqual(@as(?codes.Code, .E0907), refused);
        try testing.expectEqual(@as(u32, 0), caller.calls);
    }
}

var tree_other: Digest = undefined;
var other_text: [constants.store_digest_text_bytes:0]u8 = undefined;

/// A second tree in the store: the sample tree with one more file.
fn import_other() !void {
    files.put_file("/src/etc/other", 0o644, "other\n");
    var diag: Diag = undefined;
    diag.reset();
    var made: import.Result = undefined;
    const options: import.Options = .{ .squash_owner = false, .warn = null };
    try import.import(&store, &import_work, "/src", options, &made, &diag);
    tree_other = made.digest;
    assert(!tree_other.eql(tree));
    other_text = terminated(tree_other);
}

var image_record: images.Image = undefined;
var reference_buffer: [200:0]u8 = undefined;

/// Saves a pulled image of the sample tree, with the result record's config so that it derives
/// `built`, and returns the reference by digest `zbx run` takes without a lock.
fn save_image() ![:0]const u8 {
    const image = &image_record;
    image.tag_count = 0;
    image.manifest = Sha256.of("manifest");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = Sha256.of("config");
    image.tree = tree;
    image.time = 1;
    image.layer_count = 0;
    image.settings = record.config.settings;
    image.labels.clear();
    var failure: fs_mod.Failure = undefined;
    try images.save(&store, image, &failure);
    try testing.expect(result.derive(tree, &image.settings, &image.labels).?.eql(built));
    const manifest = image.manifest.text();
    const text = try std.fmt.bufPrint(&reference_buffer, "docker.io/library/alpine@{s}", .{
        &manifest,
    });
    reference_buffer[text.len] = 0;
    return reference_buffer[0..text.len :0];
}

test "a binding the store does not back counts for nothing" {
    // Goal: the library never admits what `zbx run` refuses for the same tree: a caller's
    // binding to a result or a manifest whose record names another tree is dropped. Method: the
    // result and the image of the sample tree are signed, a second tree is not; `zbx run` of the
    // second tree is refused, and so is the library start of it bound to that result or that
    // manifest, or to a result no record has. Bound to its own tree's result it is admitted.
    try setup(90);
    try import_other();
    const reference = try save_image();
    try write_policy("require_signature");
    try sign(&built_text);
    try sign(reference);
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_cli(&other_text));
    try testing.expectEqual(@as(?codes.Code, null), verdict_of_cli(&built_text));
    try testing.expectEqual(@as(?codes.Code, null), verdict_of_cli(reference));
    const bindings = [_]spec_mod.Binding{
        .{ .result = built.bytes },
        .{ .manifest = image_record.manifest.bytes },
        .{ .result = Digest.of("no such result").bytes },
    };
    var diag: Diag = undefined;
    for (bindings) |binding| {
        const spec = spec_of(&other_text, "lib-9", binding);
        try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_library(&spec, &diag));
    }
    const own = spec_of(&tree_text, "lib-10", .{ .result = built.bytes });
    try testing.expectEqual(@as(?codes.Code, null), verdict_of_library(&own, &diag));
}

test "an image named by digest gets the verdict zbx run gives it, bound or by name" {
    // Goal: the manifest and the result it derives count at both doors alike. Method: a pulled
    // image of the sample tree; under require_signature, unsigned then signed by reference;
    // under require_provenance, with the provenance of the result the image derives. Each time
    // `zbx run <reference>`, the library start of the reference with no binding, and of the
    // tree bound to the manifest agree, and the start runs the tree by its full digest.
    const Step = enum { unsigned, signed, provenance };
    const wants = [_]?codes.Code{ .E0905, null, null };
    for ([_]Step{ .unsigned, .signed, .provenance }, 0..) |step, index| {
        errdefer std.debug.print("step: {s}\n", .{@tagName(step)});
        try setup(100 + index);
        const reference = try save_image();
        if (step == .provenance) try save_provenance_of_built();
        try write_policy(if (step == .provenance) "require_provenance" else "require_signature");
        if (step != .unsigned) try sign(reference);
        if (step == .provenance) try sign(&built_text);
        try testing.expectEqual(wants[index], verdict_of_cli(reference));
        var diag: Diag = undefined;
        const by_name = spec_of(reference, "lib-11", .none);
        try testing.expectEqual(wants[index], verdict_of_library(&by_name, &diag));
        const manifest: spec_mod.Binding = .{ .manifest = image_record.manifest.bytes };
        const bound = spec_of(&tree_text, "lib-12", manifest);
        try testing.expectEqual(wants[index], verdict_of_library(&bound, &diag));
        var judged = spec_of(reference, "lib-13", .none);
        diag.reset();
        const options: run.StartOptions = .{ .image_workspace = &image_ws };
        _ = start_gate.admit(sim.interface(), &judged, options, &gate_ws, &diag) catch {};
        try testing.expectEqualStrings(&tree_text, judged.image.?);
        try testing.expect(std.meta.eql(judged.binding, manifest));
    }
}

test "the node's own policy file binds the library as it binds zbx run" {
    // Goal: `/etc/zbx/policy.zon` is read by the library's gate, not only the user's file.
    // Method: the system file alone requires a signature; both doors refuse the unsigned tree.
    try setup(110);
    if (files.kind_of("/etc") == null) files.put_dir("/etc", 0o755);
    files.put_dir("/etc/zbx", 0o755);
    try write_policy_at(constants.policy_system_path, "require_signature");
    try testing.expect(files.kind_of(policy_path) == null);
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_cli(&tree_text));
    const spec = spec_of(&tree_text, "lib-14", .none);
    var diag: Diag = undefined;
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_library(&spec, &diag));
}

test "a refusal of a result names the result, as zbx run's does" {
    // Goal: the subject a result-bound refusal names is the result's digest. Method: provenance
    // required, none stored, the result signed; the library start of the tree bound to the
    // result renders exactly what `zbx run <result>` printed.
    try setup(120);
    try write_policy("require_provenance");
    try sign(&built_text);
    try testing.expectEqual(@as(?codes.Code, .E0906), verdict_of_cli(&built_text));
    var printed: [constants.output_bytes_max]u8 = undefined;
    const cli_text = sim.stderr();
    @memcpy(printed[0..cli_text.len], cli_text);
    const spec = spec_of(&tree_text, "lib-15", .{ .result = built.bytes });
    var diag: Diag = undefined;
    try testing.expectEqual(@as(?codes.Code, .E0906), verdict_of_library(&spec, &diag));
    var buffer: [constants.output_bytes_max]u8 = undefined;
    const text = render.render(&diag, .text, false, &buffer);
    try testing.expectEqualStrings(printed[0..cli_text.len], text);
    try testing.expect(std.mem.indexOf(u8, text, &built_text) != null);
}

var exec_handle: exec.Handle = undefined;

/// The trust code the library's exec in `name` was refused with, or null when the gate let it
/// through (the exec may still fail later, for the simulator's reasons).
fn verdict_of_exec(name: []const u8, diag: *Diag) ?codes.Code {
    const command_spec: exec.Spec = .{ .name = name, .command = &.{"/bin/true"} };
    diag.reset();
    start_gate.exec_start(sim.interface(), &command_spec, .{}, &exec_handle, &gate_ws, diag) catch {
        const code = diag.code.?;
        if (std.mem.startsWith(u8, @tagName(code), "E090")) return code;
        return null;
    };
    assert(diag.code == null);
    return null;
}

test "the library's exec meets the policy as zbx exec does" {
    // Goal: `zigbox.exec_start` is gated. Method: a container started with no policy; then a
    // policy requires a signature; the library's exec in it is refused with E0905 and nothing
    // started, and once the tree is signed it is let through.
    try setup(130);
    const spec = spec_of(&tree_text, "lib-16", .none);
    var diag: Diag = undefined;
    try testing.expectEqual(@as(?codes.Code, null), verdict_of_library(&spec, &diag));
    var dir: records.Dir = undefined;
    try testing.expect(records.locate(sim.interface(), &dir));
    var parsed: records.Parsed = undefined;
    try records.load(sim.interface(), &dir, "lib-16", &parsed);
    try write_policy("require_signature");
    try testing.expectEqual(@as(?codes.Code, .E0905), verdict_of_exec("lib-16", &diag));
    try sign(&tree_text);
    try testing.expectEqual(@as(?codes.Code, null), verdict_of_exec("lib-16", &diag));
}

test "the run record keeps the binding the gate judged, not the caller's" {
    // Goal: an unbacked binding never reaches the run record, where `zbx exec`'s gate would read
    // it back. Method: a signed tree under require_signature, started bound to a result no
    // record has; it is admitted, and its run record has no binding. Bound to its own result,
    // the record keeps that result.
    try setup(140);
    try write_policy("require_signature");
    try sign(&tree_text);
    const bindings = [_]spec_mod.Binding{
        .{ .result = Digest.of("no such result").bytes },
        .{ .result = built.bytes },
    };
    const names = [_][]const u8{ "lib-17", "lib-18" };
    var diag: Diag = undefined;
    for (bindings, names, 0..) |binding, name, index| {
        const spec = spec_of(&tree_text, name, binding);
        try testing.expectEqual(@as(?codes.Code, null), verdict_of_library(&spec, &diag));
        var dir: records.Dir = undefined;
        try testing.expect(records.locate(sim.interface(), &dir));
        var parsed: records.Parsed = undefined;
        try records.load(sim.interface(), &dir, name, &parsed);
        const kept: spec_mod.Binding = parsed.binding orelse .none;
        if (index == 0) {
            try testing.expect(kept == .none);
        } else {
            try testing.expectEqualSlices(u8, &built.bytes, &kept.result);
        }
    }
}
