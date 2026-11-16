# The diagnostic kept in a run record: 3056 bytes, not 3072

*Decided 2026-11-15, by the supervisor, on S2 slice 5b's question.*

## Problem

Run record version 11 (`src/runtime/records.zig`) adds the `.lazy` line of a lazy run: at most
159 bytes (local share, fetched bytes, errors, sources). The record's bound,
`record_bytes_max`, is checked at compile time against the worst case of every field, and the
largest field is the diagnostic zbx printed, kept as its JSON line and escaped again in the
record (up to four bytes per byte). With the `.lazy` line, the worst case was 43 bytes over.

## Decision

`diag_json_bytes_max` goes from 3072 to 3056 (option (a)). Sixteen bytes fewer, escaped four
times, is 64 bytes back, which covers the 43. A diagnostic line longer than 3056 bytes is kept as
`{"code":"ZBX-Ennnn","truncated":true}`, as one longer than 3072 was before; real diagnostics
are far shorter (the longest golden is under 1.5 KB).

Not (b), raising `record_bytes_max`: the record is read with the same `file_bytes_max` buffer
that bounds every `/proc`, `/sys` and `/etc` read, so raising it raises them all.

## Tests

`src/runtime/run.zig`, "a diagnostic line of diag_json_bytes_max bytes is kept whole, and one
byte more is cut": a 3056-byte line is kept whole, a 3057-byte line becomes the short object.
