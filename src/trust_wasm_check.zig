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

export fn trust_provenance_met(
    policy: *const trust.policy.Policy,
    report: *const trust.verdict.Report,
) bool {
    return trust.verdict.provenance_met(policy, report);
}

export fn trust_envelope_sign(
    work: *trust.dsse.Work,
    out: [*]u8,
    out_len: usize,
    seed: *const [32]u8,
    payload: [*]const u8,
    len: usize,
) usize {
    const text = trust.dsse.sign(work, out[0..out_len], seed.*, payload[0..len]) catch return 0;
    return text.len;
}

export fn trust_envelope_render(
    work: *trust.dsse.Work,
    out: [*]u8,
    out_len: usize,
    envelope: *const trust.dsse.Envelope,
) usize {
    return trust.dsse.render(work, out[0..out_len], envelope).len;
}

export fn trust_envelope_verify(work: *trust.dsse.Work, envelope: *const trust.dsse.Envelope) bool {
    trust.dsse.verify(work, envelope) catch return false;
    return true;
}

export fn trust_statement_render(
    out: [*]u8,
    out_len: usize,
    statement: *const trust.statement.Statement,
) usize {
    return trust.statement.render(out[0..out_len], statement).len;
}

export fn trust_record_add(
    record: *trust.signature_record.Record,
    bytes: [*]const u8,
    len: usize,
) bool {
    record.clear();
    const added = record.add(bytes[0..len]) catch return false;
    return added == .added and record.has(bytes[0..len]) and record.line(0).len == len;
}

export fn trust_key_parse(bytes: [*]const u8, len: usize, out: *trust.key.Record) bool {
    out.* = trust.key.parse(bytes[0..len]) catch return false;
    return true;
}

export fn trust_key_parse_pub(bytes: [*]const u8, len: usize) bool {
    return trust.key.parse_pub(bytes[0..len]) != null;
}

export fn trust_key_seal_open(
    heap: [*]u8,
    heap_len: usize,
    seed: *const [32]u8,
    public: *const [32]u8,
    kdf: *const trust.key.Kdf,
    nonce: *const [24]u8,
    out: *[32]u8,
) bool {
    var fixed = std.heap.FixedBufferAllocator.init(heap[0..heap_len]);
    const sealed = trust.key.seal(fixed.allocator(), "x", seed.*, public.*, kdf.*, nonce.*) catch
        return false;
    const record: trust.key.Record = .{ .public = public.*, .body = .{ .passphrase = sealed } };
    out.* = trust.key.open(fixed.allocator(), &record, "x") catch return false;
    return true;
}

export fn trust_key_ids(seed: *const [32]u8, out: *[64]u8) bool {
    const public = trust.key.public_of_seed(seed.*);
    out.* = trust.key.key_id(public);
    const text = trust.key.public_text(public);
    return trust.key.parse_public_text(&text) != null;
}

comptime {
    std.debug.assert(trust.limits.signatures_per_tree_max >= 1);
}
