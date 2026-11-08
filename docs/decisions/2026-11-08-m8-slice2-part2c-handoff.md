# M8 slice 2, part 2b done: handoff to the next part

Supersedes nothing; follows `2026-11-08-m8-slice2-part2b-handoff.md`.

## Done

Record tests and crash simulation, codes E0903 and E0910, `zbx sign` (`src/trust/sign_commands.zig`,
cli wiring, `zbx.sign/1`), record fuzzing in `src/fuzz_trust.zig`, and the sign section of
`docs/demos/m8.md`, with the provenance cut recorded there.

## Decisions and traps

- `sign` always writes a `sign/v1` statement; signing a provenance record waits for slice 4.
- `trust_records_max` (4096) cannot be reached in the sim fs (640 nodes), so `is_full` is tested at
  4095 and 4096 directly.
- A multi-line string in `schemas.zig` must not break inside a JSON string, and tidy counts
  `\\` lines against the 100 columns: split between members instead.
- Golden regeneration: append a test to `diag_golden.zig` that prints `direct_block`, run
  `zig build test`, restore the file.

## Next

`verify` and the gate (slices 2 to 3), `demo-m8` and the VM run, then provenance in slice 4.
The VM has not run `sign`.
