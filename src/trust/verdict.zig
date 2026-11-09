//! The verdict (docs/briefs/M8-trust.md, "The policy file"): does a signature record satisfy a
//! policy for one subject? A pure function of its arguments, with no store, no clock and no
//! environment, so the run gate, `zbx policy check` and the push gate (slice 14) all ask the
//! same question the same way.
//!
//! A line counts when, in this order: its envelope parses and its signature verifies, its key
//! is one the policy lists, its statement is of this release's `sign/v1` form about the
//! subject's tree, and its binding fits the subject. A statement about the tree alone counts for
//! any run; one bound to a result counts only for a run of that result, and one bound to a
//! manifest only for a run of that manifest. The first reason a line does not count is the one
//! reported. `require_signature` is met when at least one line counts. `require_provenance` is
//! met when at least one line that counts is a signed provenance statement (`provenance.zig`):
//! it is a signature, by a trusted key, over the SLSA record of this tree, bound to the result
//! that is to run. An unsigned stored record counts for nothing; a store is not asked here.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const dsse = @import("dsse.zig");
const policy_mod = @import("policy.zig");
const record_mod = @import("record.zig");
const statement = @import("statement.zig");

pub const Subject = struct {
    tree: statement.Digest,
    binding: statement.Binding,
};

pub const Reason = enum {
    /// The line satisfies the rule.
    counts,
    /// Not an envelope this release reads, or a statement of the wrong form.
    malformed,
    bad_signature,
    /// Signed by a key the policy does not list.
    untrusted_key,
    /// A statement about another tree.
    other_tree,
    /// A predicate type this release does not know.
    other_predicate,
    /// Bound to another result or manifest than the subject's.
    other_binding,
};

pub const Examined = struct {
    public: [constants.key_public_bytes]u8,
    reason: Reason,
    /// The line's statement is a provenance statement. Known for every line whose signature
    /// verifies, whatever else is wrong with it.
    provenance: bool = false,
};

pub const Report = struct {
    count: u32,
    lines: [constants.signatures_per_tree_max]Examined,
    /// How many lines counted.
    counted: u32,
    /// How many of those are provenance statements.
    provenance_counted: u32,

    pub fn clear(report: *Report) void {
        report.count = 0;
        report.counted = 0;
        report.provenance_counted = 0;
    }

    /// Whether some provenance line was judged `reason`.
    pub fn provenance_with(report: *const Report, reason: Reason) bool {
        for (report.lines[0..report.count]) |line| {
            if (line.provenance and line.reason == reason) return true;
        }
        return false;
    }
};

/// True when `record` satisfies `policy` for `subject`. `report` says what each line was. A
/// policy that asks for nothing is satisfied by any record, an empty one included.
pub fn judge(
    work: *dsse.Work,
    policy: *const policy_mod.Policy,
    record: *const record_mod.Record,
    subject: Subject,
    report: *Report,
) bool {
    assert(record.count <= constants.signatures_per_tree_max);
    assert(policy.key_count <= constants.policy_keys_max);
    report.clear();
    var index: u32 = 0;
    while (index < record.count) : (index += 1) {
        const examined = examine(work, policy, record.line(index), subject);
        report.lines[report.count] = examined;
        report.count += 1;
        if (examined.reason == .counts) report.counted += 1;
        if (examined.reason == .counts and examined.provenance) report.provenance_counted += 1;
    }
    assert(report.counted <= report.count);
    assert(report.provenance_counted <= report.counted);
    if (!policy.require_signature) return true;
    return report.counted > 0;
}

/// Whether the policy's provenance rule is met by what `judge` reported.
pub fn provenance_met(policy: *const policy_mod.Policy, report: *const Report) bool {
    assert(report.provenance_counted <= report.counted);
    if (!policy.require_provenance) return true;
    return report.provenance_counted > 0;
}

/// One line against the policy and the subject.
pub fn examine(
    work: *dsse.Work,
    policy: *const policy_mod.Policy,
    line: []const u8,
    subject: Subject,
) Examined {
    assert(line.len <= constants.envelope_bytes_max);
    var result: Examined = .{ .public = @splat(0), .reason = .malformed };
    const envelope = dsse.parse(work, line) catch return result;
    result.public = envelope.public;
    dsse.verify(work, &envelope) catch {
        result.reason = .bad_signature;
        return result;
    };
    if (statement.parse(envelope.payload)) |head| {
        result.provenance = head.kind == .provenance;
    } else |_| {}
    if (policy.trusted(&envelope.public) == null) {
        result.reason = .untrusted_key;
        return result;
    }
    const found = statement.parse(envelope.payload) catch |err| {
        result.reason = switch (err) {
            error.UnknownPredicate => .other_predicate,
            error.Malformed => .malformed,
        };
        return result;
    };
    if (!std.mem.eql(u8, &found.tree, &subject.tree)) {
        result.reason = .other_tree;
        return result;
    }
    result.reason = if (binding_fits(found.binding, subject.binding)) .counts else .other_binding;
    return result;
}

/// Whether a statement bound as `said` counts for a subject bound as `have`.
pub fn binding_fits(said: statement.Binding, have: statement.Binding) bool {
    switch (said) {
        .none => return true,
        .result => |wanted| switch (have) {
            .result => |found| return std.mem.eql(u8, &wanted, &found),
            else => return false,
        },
        .manifest => |wanted| switch (have) {
            .manifest => |found| return std.mem.eql(u8, &wanted, &found),
            else => return false,
        },
    }
}
