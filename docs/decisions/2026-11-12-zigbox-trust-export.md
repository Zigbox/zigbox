# Zigbox exports the pure trust surface

*Decided 2026-11-12, by the slice (implementing Zigcube's docs/decisions/2026-11-12-zigbox-exports-trust-surface.md).*

## Decision

- `zigbox.trust` (`src/trust_export.zig`) exports `policy`, `verdict`, `dsse`, `statement`, `key`
  and `signature_record`, plus `limits` (the bounds a caller sizes input by). Nothing in it touches
  the host, the store or the clock.
- `record.zig` reads a record file and needs the store's layout and provenance, so it is not
  exported. Its pure part, the `Record` type with `add`, `has`, `line`, moved to
  `src/trust/signature_record.zig`; `record.zig` re-exports it, so no caller changes.
- The verdict already took caller-supplied scratch: `judge(work: *dsse.Work, ...)`. The 6 MiB
  `record.Work` belongs to reading a record, not to judging. No behaviour changed. What a caller
  supplies: `dsse.Work` 873,894 bytes, `Record` 2,800,336, `Report` 284, `Policy` 1,096.
- `zig build trust-wasm` compiles the surface for `wasm32-freestanding` (no libc) and is a gate of
  `zig build check`. The compile cannot see an import that nothing calls, so a unit test in
  `zigbox.zig` also reads each exported file's `@import` lines and refuses the host, the store,
  provenance and `record.zig`.

## Values for Zigcube's B5

`envelope_bytes_max` is 350,040 (not 2048): an envelope carries a statement of up to
`statement_bytes_max` = 262,144 bytes (the SLSA provenance record), base64-encoded, plus 512.
`signatures_per_tree_max` is 8 (not 4). A job signature line that is only a sign statement is a
few hundred bytes, but the judge and `Record` take the bounds above. Zigbox changes no bound;
Zigcube's B5 slice 1 must decide whether to cap what it accepts below these.
