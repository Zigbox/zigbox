//! `zigbox.trust` (docs/decisions/2026-11-12-zigbox-trust-export.md): the pure parts needed to
//! judge a signed tree, for a caller that is not the command line and, through
//! `zig build trust-wasm`, for `wasm32-freestanding`: Zigcube's core runs the same verdict as the
//! run gate. Nothing here touches the host, the store or the clock, prints, or keeps state.
//!
//! The question: `verdict.judge(work, policy, record, subject, report)` is true when `record`
//! satisfies `policy` for `subject`. The caller supplies all storage:
//!   - `dsse.Work` (873,894 bytes, `@sizeOf(dsse.Work)`), reused between calls; the 6 MiB
//!     `record.Work` is not needed, it belongs to reading a record from the store;
//!   - a `signature_record.Record` (2,800,336 bytes: `limits.signature_record_bytes_max` and two counters)
//!     holding the lines, filled with `Record.add` from envelopes the caller read;
//!   - a `policy.Policy`, filled by `policy.parse`; a `verdict.Report`.
//! Envelopes are parsed with `dsse.parse` and statements with `statement.parse`. Keys are in
//! `key` (public-key text, key ids). Not exported: `record.zig` (reads a record file through the
//! store's layout), `provenance.zig`, the key store and every command.

pub const policy = @import("trust/policy.zig");
pub const verdict = @import("trust/verdict.zig");
pub const dsse = @import("trust/dsse.zig");
pub const statement = @import("trust/statement.zig");
pub const key = @import("trust/key.zig");
/// The record's type: `signature_record.Record`, the one `verdict.judge` takes.
pub const signature_record = @import("trust/signature_record.zig");

const constants = @import("constants.zig");

/// The bounds a caller sizes its input by, read from the one place they are defined.
pub const limits = struct {
    pub const envelope_bytes_max = constants.envelope_bytes_max;
    pub const signatures_per_tree_max = constants.signatures_per_tree_max;
    pub const signature_record_bytes_max = constants.signature_record_bytes_max;
    pub const statement_bytes_max = constants.statement_bytes_max;
    pub const policy_keys_max = constants.policy_keys_max;
};
