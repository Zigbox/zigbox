# M8 slice 2: derived constants (supervisor-approved)

The constants `signed_at_text_bytes` (20), `signed_at_seconds_max` (end of year 9999),
`payload_base64_bytes_max`, `envelope_overhead_bytes` (512), `envelope_bytes_max`,
`signature_record_bytes_max` and `sign_predicate_path` are derived from the brief's bounds
(`statement_bytes_max`, `signatures_per_tree_max`) and live in `src/constants.zig` with comptime
relations. The supervisor approved them before part 2b.
