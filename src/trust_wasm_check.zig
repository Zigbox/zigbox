//! Compiled by `zig build trust-wasm` for `wasm32-freestanding` with no libc and no OS: proves
//! `zigbox.trust` needs nothing the target lacks. The exports are the calls Zigcube's core makes,
//! so the checker analyses everything they reach (a plain `_ =` would skip function bodies).

const std = @import("std");
const trust = @import("trust_export.zig");

export fn trust_judge(
    work: *trust.dsse.Work,
    policy: *const trust.policy.Policy,
    record: *const trust.signature_record.Record,
    subject: *const trust.verdict.Subject,
    report: *trust.verdict.Report,
) bool {
    return trust.verdict.judge(work, policy, record, subject.*, report);
}

export fn trust_policy_parse(bytes: [*]const u8, len: usize, out: *trust.policy.Policy) bool {
    return trust.policy.parse(bytes[0..len], out) == null;
}

export fn trust_envelope_parse(work: *trust.dsse.Work, bytes: [*]const u8, len: usize) bool {
    const envelope = trust.dsse.parse(work, bytes[0..len]) catch return false;
    return envelope.payload.len > 0;
}

export fn trust_statement_parse(bytes: [*]const u8, len: usize) bool {
    _ = trust.statement.parse(bytes[0..len]) catch return false;
    return true;
}

comptime {
    std.debug.assert(trust.limits.signatures_per_tree_max >= 1);
}
