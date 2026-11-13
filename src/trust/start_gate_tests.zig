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
    files.put_file(policy_path, 0o644, text);
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

/// The merged directory in the container model, as the overlay would show the tree.
fn world_dirs(name: []const u8) void {
    var path: [200]u8 = undefined;
    var inner: [220]u8 = undefined;
    const merged = std.fmt.bufPrint(&path, state ++ "/{s}/merged", .{name}) catch unreachable;
    sim.world.add_node(merged, .dir);
    const net = std.fmt.bufPrint(&inner, state ++ "/{s}/net", .{name}) catch unreachable;
    sim.world.add_node(net, .dir);
    for ([_][]const u8{ "/bin", "/proc", "/dev", "/usr/bin" }) |suffix| {
        const text = std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix }) catch unreachable;
        sim.world.add_node(text, .dir);
    }
    const shell = std.fmt.bufPrint(&inner, "{s}/bin/sh", .{merged}) catch unreachable;
    sim.world.add_node(shell, .file);
    for ([_][]const u8{ "/etc/hosts", "/etc/resolv.conf", "/etc/hostname" }) |suffix| {
        const text = std.fmt.bufPrint(&inner, "{s}{s}", .{ merged, suffix }) catch unreachable;
        sim.world.add_node(text, .file);
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
    world_dirs(spec.name.?);
    diag.reset();
    const options: run.StartOptions = .{ .image_workspace = &image_ws };
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
