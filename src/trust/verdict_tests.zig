//! Tests for `verdict.zig`: each way a line fails to count, the binding rule for every pair of
//! statement and subject, and that one counting line is enough.

const std = @import("std");
const testing = std.testing;
const constants = @import("../constants.zig");
const dsse = @import("dsse.zig");
const key = @import("key.zig");
const policy_mod = @import("policy.zig");
const record = @import("record.zig");
const statement = @import("statement.zig");
const verdict = @import("verdict.zig");

var work: dsse.Work = undefined;
var one: record.Record = undefined;
var policy: policy_mod.Policy = undefined;
var report: verdict.Report = undefined;
var payload_buffer: [statement.render_bytes_max]u8 = undefined;
var line_buffers: [4][constants.envelope_bytes_max]u8 = undefined;

fn digest_of(byte: u8) statement.Digest {
    return @splat(byte);
}

fn seed_of(byte: u8) [constants.key_seed_bytes]u8 {
    return @splat(byte);
}

/// A policy that requires a signature and trusts the keys of the given seed bytes.
fn trust(seeds: []const u8) void {
    policy.clear();
    policy.require_signature = true;
    for (seeds) |seed| {
        policy.keys[policy.key_count] = .{
            .name = @splat('k'),
            .name_length = 1,
            .public = key.public_of_seed(seed_of(seed)),
        };
        policy.key_count += 1;
    }
}

fn sign(slot: usize, said: statement.Statement, seed: u8) []const u8 {
    const text = statement.render(&payload_buffer, &said);
    const seed_bytes = seed_of(seed);
    // A statement is far under the payload bound, and a seed of the OS is no identity key.
    return dsse.sign(&work, &line_buffers[slot], seed_bytes, text) catch unreachable;
}

fn record_of(lines: []const []const u8) void {
    one.clear();
    for (lines) |line| _ = one.add(line) catch unreachable; // At most eight lines.
}

fn run(subject: verdict.Subject) bool {
    return verdict.judge(&work, &policy, &one, subject, &report);
}

test "a trusted key's statement about the tree counts, and any other does not" {
    // Goal: the check order and the reason for each failure. Method: one record per case.
    const tree = digest_of(7);
    const none: verdict.Subject = .{ .tree = tree, .binding = .none };
    trust(&.{1});
    record_of(&.{sign(0, statement.Statement.for_tree(tree, 5), 1)});
    try testing.expect(run(none));
    try testing.expectEqual(verdict.Reason.counts, report.lines[0].reason);

    record_of(&.{sign(0, statement.Statement.for_tree(tree, 5), 2)});
    try testing.expect(!run(none));
    try testing.expectEqual(verdict.Reason.untrusted_key, report.lines[0].reason);

    record_of(&.{sign(0, statement.Statement.for_tree(digest_of(8), 5), 1)});
    try testing.expect(!run(none));
    try testing.expectEqual(verdict.Reason.other_tree, report.lines[0].reason);

    // A flipped byte of the signature: the first signature character of the line.
    var damaged: [constants.envelope_bytes_max]u8 = undefined;
    const good = sign(0, statement.Statement.for_tree(tree, 5), 1);
    @memcpy(damaged[0..good.len], good);
    const at = std.mem.indexOf(u8, good, "\"sig\":\"").? + 7;
    damaged[at] = if (damaged[at] == 'A') 'B' else 'A';
    record_of(&.{damaged[0..good.len]});
    try testing.expect(!run(none));
    try testing.expectEqual(verdict.Reason.bad_signature, report.lines[0].reason);

    record_of(&.{"not an envelope"});
    try testing.expect(!run(none));
    try testing.expectEqual(verdict.Reason.malformed, report.lines[0].reason);
}

test "another predicate type does not count" {
    // Goal: a statement of a predicate this release does not know never satisfies the rule.
    // Method: sign a payload whose predicate type is one version up.
    const tree = digest_of(7);
    trust(&.{1});
    var text: [statement.render_bytes_max]u8 = undefined;
    const rendered = statement.render(&payload_buffer, &statement.Statement.for_tree(tree, 5));
    const at = std.mem.indexOf(u8, rendered, "sign/v1").?;
    @memcpy(text[0..rendered.len], rendered);
    text[at + 6] = '2';
    const line = dsse.sign(&work, &line_buffers[0], seed_of(1), text[0..rendered.len]) catch
        unreachable;
    record_of(&.{line});
    try testing.expect(!run(.{ .tree = tree, .binding = .none }));
    try testing.expectEqual(verdict.Reason.other_predicate, report.lines[0].reason);
}

test "a statement's binding counts only for a subject it fits" {
    // Goal: the binding rule for every pairing. Method: three statements against three subjects.
    const tree = digest_of(7);
    const result = digest_of(1);
    const manifest = digest_of(2);
    const none: statement.Binding = .none;
    const by_result: statement.Binding = .{ .result = result };
    const by_manifest: statement.Binding = .{ .manifest = manifest };
    const other: statement.Binding = .{ .result = digest_of(9) };
    try testing.expect(verdict.binding_fits(none, none));
    try testing.expect(verdict.binding_fits(none, by_result));
    try testing.expect(verdict.binding_fits(none, by_manifest));
    try testing.expect(verdict.binding_fits(by_result, by_result));
    try testing.expect(!verdict.binding_fits(by_result, none));
    try testing.expect(!verdict.binding_fits(by_result, other));
    try testing.expect(!verdict.binding_fits(by_result, by_manifest));
    try testing.expect(verdict.binding_fits(by_manifest, by_manifest));
    try testing.expect(!verdict.binding_fits(by_manifest, by_result));
    try testing.expect(!verdict.binding_fits(by_manifest, none));
    trust(&.{1});
    record_of(&.{sign(0, statement.Statement.for_result(tree, result, 5), 1)});
    try testing.expect(run(.{ .tree = tree, .binding = by_result }));
    try testing.expect(!run(.{ .tree = tree, .binding = none }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
}

test "a result-bound statement counts for the result derived from a pulled image" {
    // Goal: slice 14. Method: the subject has no binding of its own, only a derived result.
    const tree = digest_of(7);
    const result = digest_of(1);
    const by_result: statement.Binding = .{ .result = result };
    try testing.expect(verdict.derived_fits(by_result, result));
    try testing.expect(!verdict.derived_fits(by_result, digest_of(2)));
    try testing.expect(!verdict.derived_fits(by_result, null));
    try testing.expect(!verdict.derived_fits(.none, result));
    try testing.expect(!verdict.derived_fits(.{ .manifest = result }, result));
    trust(&.{1});
    record_of(&.{sign(0, statement.Statement.for_result(tree, result, 5), 1)});
    try testing.expect(run(.{ .tree = tree, .binding = .none, .derived = result }));
    try testing.expect(!run(.{ .tree = tree, .binding = .none, .derived = digest_of(2) }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
    try testing.expect(!run(.{ .tree = tree, .binding = .none, .derived = null }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
}

test "a result-bound line for a pulled image with no derived result says why" {
    // Goal: slice 14 fix. A record that cannot derive (v2, labels past the bound) must not read as
    // "bound to another result"; a manifest-bound subject says `not_derived`, the rest do not.
    const tree = digest_of(7);
    const result = digest_of(1);
    trust(&.{1});
    record_of(&.{sign(0, statement.Statement.for_result(tree, result, 5), 1)});
    const pulled: statement.Binding = .{ .manifest = digest_of(3) };
    try testing.expect(!run(.{ .tree = tree, .binding = pulled, .derived = null }));
    try testing.expectEqual(verdict.Reason.not_derived, report.lines[0].reason);
    try testing.expect(!run(.{ .tree = tree, .binding = pulled, .derived = digest_of(2) }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
    try testing.expect(run(.{ .tree = tree, .binding = pulled, .derived = result }));
    try testing.expect(!run(.{ .tree = tree, .binding = pulled, .derives = false }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
    // A manifest-bound statement for another manifest is still another binding.
    record_of(&.{sign(0, statement.Statement.for_manifest(tree, "x", digest_of(4), 5), 1)});
    try testing.expect(!run(.{ .tree = tree, .binding = pulled, .derived = null }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
}

test "a manifest-bound line judged for a bare tree is another binding, not a crash" {
    // Goal: `zbx run b3:<tree>`, `policy check <tree>` and exec on a 0.3.1 container judge a
    // subject with no binding. Method: a manifest-bound line against `.none`, with and without
    // a derived result; it must refuse as `other_binding` (E0905), never assert.
    const tree = digest_of(7);
    trust(&.{1});
    record_of(&.{sign(0, statement.Statement.for_manifest(tree, "x", digest_of(4), 5), 1)});
    try testing.expect(!run(.{ .tree = tree, .binding = .none }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
    try testing.expect(!run(.{ .tree = tree, .binding = .none, .derived = digest_of(2) }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
    try testing.expect(!run(.{ .tree = tree, .binding = .none, .derives = false }));
    try testing.expectEqual(verdict.Reason.other_binding, report.lines[0].reason);
}

test "one counting line is enough, and a policy that asks for nothing is met" {
    // Goal: the rule is "at least one", and an empty rule set passes. Method: a record of a bad
    // line and a good one; then a policy with no rule against an empty record.
    const tree = digest_of(7);
    trust(&.{1});
    record_of(&.{
        sign(0, statement.Statement.for_tree(tree, 5), 2),
        sign(1, statement.Statement.for_tree(tree, 6), 1),
    });
    try testing.expect(run(.{ .tree = tree, .binding = .none }));
    try testing.expectEqual(@as(u32, 2), report.count);
    try testing.expectEqual(@as(u32, 1), report.counted);
    one.clear();
    try testing.expect(!run(.{ .tree = tree, .binding = .none }));
    policy.require_signature = false;
    try testing.expect(run(.{ .tree = tree, .binding = .none }));
}

test "provenance_met: needs a counted provenance line only when the policy asks" {
    // Goal: the provenance rule is its own. Method: a report with a counted signature that is
    // not provenance, then one that is; a policy that does not ask is met by both.
    policy.clear();
    report.clear();
    try testing.expect(verdict.provenance_met(&policy, &report));
    policy.require_provenance = true;
    try testing.expect(!verdict.provenance_met(&policy, &report));
    report.count = 1;
    report.counted = 1;
    report.lines[0] = .{ .public = @splat(0), .reason = .counts, .provenance = false };
    try testing.expect(!verdict.provenance_met(&policy, &report));
    report.provenance_counted = 1;
    report.lines[0].provenance = true;
    try testing.expect(verdict.provenance_met(&policy, &report));
    try testing.expect(!report.provenance_with(.other_binding));
    report.lines[0].reason = .other_binding;
    try testing.expect(report.provenance_with(.other_binding));
}
