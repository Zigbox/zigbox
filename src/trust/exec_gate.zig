//! The policy gate at `zbx exec` (docs/briefs/M8-trust.md, "Where the checks run"): a command
//! started in a running container is judged by the policy as the run itself was, because the
//! policy may have changed since. The tree and what it is bound to come from the container's
//! run record (version 9 keeps the binding); nothing is re-hashed, so the check costs what the
//! run's did.
//!
//! A record older than version 9 has no binding, so only a statement of the tree alone counts
//! for it: the gate fails closed. A container that has no record, or none that can be read, is
//! left to `exec` to report, as before. With no policy that asks anything the record is not
//! read at all.

const std = @import("std");
const assert = std.debug.assert;
const Diag = @import("../diag/diag.zig").Diag;
const host_mod = @import("../host.zig");
const constants = @import("../constants.zig");
const records = @import("../runtime/records.zig");
const statement = @import("statement.zig");
const digest_mod = @import("../store/digest.zig");
const gate = @import("gate.zig");
const images = @import("../store/images.zig");
const result = @import("../build/result.zig");
const Store = @import("../store/layout.zig").Store;
const record_mod = @import("record.zig");

const Host = host_mod.Host;

pub const Error = error{Refused};

/// What a run of this container's tree was judged on: its tree (null for a directory) and its
/// binding. `text` points into `parsed`.
pub fn subject_of(parsed: *const records.Parsed) gate.Subject {
    const text = parsed.tree_slice();
    const tree = digest_mod.Digest.parse(text);
    if (tree != null) assert(text.len > 0);
    assert(parsed.version <= constants.record_version);
    return .{
        .tree = tree,
        .binding = binding_of(parsed.binding),
        .text = if (tree != null) text else "",
    };
}

/// A record with no binding says nothing, which no statement of a result or an image matches.
fn binding_of(found: ?records.Binding) statement.Binding {
    const binding = found orelse return .none;
    assert(@backingInt(binding) <= 2);
    return switch (binding) {
        .none => .none,
        .result => |bytes| .{ .result = bytes },
        .manifest => |bytes| .{ .manifest = bytes },
    };
}

/// Judges the container called `name` against every policy file. On a refusal `diag` is E0905
/// (or E0904, or E0903 for a damaged signature record).
pub fn check(
    host: Host,
    memory: *gate.Memory,
    record: *record_mod.Record,
    work: *record_mod.Work,
    image: *images.Image,
    name: []const u8,
    diag: *Diag,
) Error!void {
    assert(diag.code == null);
    gate.load(host, memory, diag) catch return error.Refused;
    if (!gate.any_checks(memory)) return;
    var dir: records.Dir = undefined;
    if (!records.locate(host, &dir)) return;
    var parsed: records.Parsed = undefined;
    records.load(host, &dir, name, &parsed) catch return;
    var subject = subject_of(&parsed);
    subject.derived = derived_of(host, subject.binding, image);
    gate.judge_all(host, memory, record, work, subject, diag) catch {
        return error.Refused;
    };
}

/// The result the image record of a manifest-bound container derives, as the record is now (a
/// re-pull since the run may have given it labels, which the run's gate lacked);
/// null when the record cannot be read or gives none, which only narrows what counts.
pub fn derived_of(host: Host, binding: statement.Binding, image: *images.Image) ?[32]u8 {
    const manifest = switch (binding) {
        .manifest => |bytes| bytes,
        else => return null,
    };
    assert(@intFromPtr(image) != 0);
    assert(manifest.len == constants.oci_digest_bytes);
    var store: Store = undefined;
    if (!store.locate(host)) return null;
    var errno: u16 = 0;
    images.load(&store, .{ .bytes = manifest }, image, &errno) catch return null;
    const found = result.derive(image.tree, &image.settings, &image.labels) orelse return null;
    return found.bytes;
}

test "a version 8 record has no binding, so only a tree-only statement could count" {
    // Goal: fail closed. Method: parse a v8 record and a v9 one bound to a result.
    var parsed: records.Parsed = undefined;
    const old = ".{\n    .version = 8,\n    .name = \"x\",\n    .started = 5,\n}\n";
    try records.parse(old, &parsed);
    try std.testing.expectEqual(statement.Binding.none, subject_of(&parsed).binding);
    const bound = std.fmt.comptimePrint(
        ".{{\n    .version = 9,\n    .name = \"x\",\n    .started = 5,\n" ++
            "    .binding = \"result:{s}\",\n}}\n",
        .{"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},
    );
    try records.parse(bound, &parsed);
    const got = subject_of(&parsed).binding;
    try std.testing.expect(got == .result);
    try std.testing.expectEqual(@as(u8, 0xcd), got.result[0]);
}

test "exec counts the result a re-pulled image record derives" {
    // Goal: the exec gate reads the image record as it is now. Method: a v3 record in a temp
    // store; its derived result is the one `result.derive` gives; a manifest-less binding gives
    // none.
    const host_sim = @import("../host_sim.zig");
    var sim: host_sim.HostSim = undefined;
    var files: @import("../store/fs_sim.zig").SimFs = undefined;
    @import("../runtime/sim_run.zig").init(&sim, 9);
    files.init(9);
    sim.store_fs = &files;
    const support = @import("../store/test_support.zig");
    support.make_user_store(&files, ".{\n    .format = 1,\n}\n");
    var store: Store = undefined;
    store.at(sim.interface(), support.user_store);
    var image: images.Image = undefined;
    image.tag_count = 0;
    image.manifest = @import("../registry/digest.zig").Sha256.of("m");
    image.platform_len = 11;
    @memcpy(image.platform[0..11], "linux/amd64");
    image.config = image.manifest;
    image.tree = digest_mod.Digest.of("tree");
    image.time = 1;
    image.layer_count = 0;
    image.settings.clear();
    image.labels.clear();
    var failure: @import("../store/fs.zig").Failure = undefined;
    try images.save(&store, &image, &failure);
    const binding: statement.Binding = .{ .manifest = image.manifest.bytes };
    var loaded: images.Image = undefined;
    const got = derived_of(sim.interface(), binding, &loaded).?;
    const want = result.derive(image.tree, &image.settings, &image.labels).?;
    try std.testing.expectEqualSlices(u8, &want.bytes, &got);
    try std.testing.expect(derived_of(sim.interface(), .none, &loaded) == null);
}
