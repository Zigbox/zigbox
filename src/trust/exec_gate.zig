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
const records = @import("../runtime/records.zig");
const statement = @import("statement.zig");
const digest_mod = @import("../store/digest.zig");
const gate = @import("gate.zig");
const record_mod = @import("record.zig");

const Host = host_mod.Host;

pub const Error = error{Refused};

/// What a run of this container's tree was judged on: its tree (null for a directory) and its
/// binding. `text` points into `parsed`.
pub fn subject_of(parsed: *const records.Parsed) gate.Subject {
    const text = parsed.tree_slice();
    const tree = digest_mod.Digest.parse(text);
    return .{
        .tree = tree,
        .binding = binding_of(parsed.binding),
        .text = if (tree != null) text else "",
    };
}

/// A record with no binding says nothing, which no statement of a result or an image matches.
fn binding_of(found: ?records.Binding) statement.Binding {
    const binding = found orelse return .none;
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
    gate.judge_all(host, memory, record, work, subject_of(&parsed), diag) catch {
        return error.Refused;
    };
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
