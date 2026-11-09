# M8 slice 3, part 2: handoff

Branch `claude/m8-slice3-part2` (from `claude/m8-slice3-policy`, part 1).

## Done

1. `zbx policy check [operand]` (`zbx.policy/1`, help, schema, goldens). Exit 1 when a policy
   would refuse; usage errors exit 1. A tag operand goes through `prepare_image` and can pull; a
   non-digest operand has no tree.
2. Build-step gate (`build/compose.zig` `check_base`): a miss checks the base before the step's
   container starts; the refusal names the step (`gate.Subject.step`, `Unsigned.step`). Cache hits
   are not checked. Part 1's E0905 digest echo was widened to the full 67-byte digest so the
   `zbx sign` fix line is complete (`diagnose.digest_echo_bytes`).
3. Exec gate (`trust/exec_gate.zig`, called from `cli.run_exec`) and the run record's binding:
   `record_version` 9 (see `2026-11-08-run-record-binding.md`).

## Not done

4. Tamper check E0907: the walk in the store child, `trust/verified/<tree hex>`
   (object id, inode, size, ctime_ns; equality on all four), `verify = "always"`, gc removing
   `verified` entries, the code's goldens/page/index/explanation, simulation tests (a tampered
   object is always found with and without the cache; a ctime change re-hashes that object).
   Start from `store/verify.zig` (`check_object_alone`, `verify_objects`) for the shared code,
   and `docs/briefs/M8-trust.md` "The tamper check".
5. The VM part in `src/testing/vm/main_m8.zig`, `m8` in `vm.yml`, `build.zig` demo table and
   `ci-changes.sh`; push to `vm/m8-slice3`.

## Traps

- `tidy` counts assertion density over `shipped_files` only; adding functions to a shipped file
  without two asserts each trips it.
- `**` after a `}` or string literal in a test can hit "whitespace on one side"; use
  `test_util.repeat` or `@splat`.
- Tests that pin `.version = 9` as "newer" now use 10.
