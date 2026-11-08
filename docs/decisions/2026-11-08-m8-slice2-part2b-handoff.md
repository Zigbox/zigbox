# M8 slice 2 part 2b: handoff (partial)

Done and committed (7e9a7ea, `zig build test` green; `zig build check` NOT run):
- `src/trust/record.zig`: parse/add/has/load/save/count_records, wired into main.zig tests.
  Only the basic compile is proven; it has no tests of its own yet.
- `src/store/verify.zig`: `check_object_alone(store, ws, id, has_list, bytes) ?ObjectDamage`
  factored out of `check_object` for the uncached tree check.
- origin/main merged (8cf1587).

Not done (next implementer, in this order):
1. record tests: bounds (8 lines, byte bound, one past), duplicate no-op, damaged/newer,
   old-release golden envelope, crash-at-every-write simulation (`fs_sim` `crash_mutation`).
2. Codes E0903, E0910 (enum and registry in the same order, after E0902 / before E0911;
   false list; `diagnose.zig`; goldens in `src/testdata/diag`; `diag_golden.zig`;
   `zig build errors-site`).
3. `src/trust/sign_commands.zig` and cli wiring (enum, name table, operand count, options
   `--key`/`--passphrase-file`, dispatch, Storage workspace, help). Operand order: build result,
   tree, `name@sha256:` manifest. Uncached tree check via `walk.objects` + `check_object_alone`.
   Lock, load record, add (Full = E0910), `trust_records_max` check on a new record, save.
4. `zbx.sign/1` schema (`schemas.zig`, `schema_sign.stdout.txt`), record fuzzing in `fuzz_trust.zig`.
5. `docs/demos/m8.md`: sign section; record the cut of provenance statements to slice 4.
6. REVIEW.md pass, `zig build check`, trust fuzzers.
