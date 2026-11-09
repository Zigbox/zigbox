# M8 slice 5 (Verify): handoff after the library part

Status: partial. Committed on `claude/m8-slice5-verify` (46a0de0); `zig build test` and
`zig build tidy` pass on it. `zig build check`, the VM check and the PR have NOT been run.

## Done
- `src/trust/tree_check.zig`: the uncached tree check, shared by `sign` and (next) `verify`.
- `src/trust/peer.zig`: `export_record`, `import_record`, `prune_records`, `count_orphans`,
  `scan_limited`, exposed as `store.export_trust`, `store.import_trust`, `store.prune_trust`.
  `constants.trust_prune_entries_max = 2 * trust_records_max` (new internal bound).
- `src/trust/peer_tests.zig`: round trip, every byte flipped refused whole, refusal reasons,
  prune dry run/apply, damaged records, crash at every unlink, the scan bound.

## Not done (the brief's remaining slice 5 list)
1. Diagnostics: E0908, E0909, W0902, W0903 in `src/diag/codes.zig`, builders in
   `src/trust/diagnose.zig`, goldens (`diag_golden.zig` `key_cases`, `src/testdata/diag/`),
   `explain` text, error pages (`zig build errors-site`, `errors-site-check`).
2. `src/trust/verify_commands.zig` (six links, `--strict`, `--require-provenance`, `--key`,
   `--public`, run in the store's user-namespace child like `sign_commands.run_in_namespace`),
   and a trust command module for `export|import|prune [--apply]`.
3. `cli.zig` wiring (Command enum, options, dispatch, Storage, help) and `schemas.zig`
   (`zbx.verify/1`, `zbx.trust/1`, `zbx.trust-prune/1`, schema goldens).
4. gc orphan count naming `zbx trust prune` (`store_commands.zig`; additive `trust_orphans`
   JSON field, update `zbx.store.gc/1`); use `peer.count_orphans`.
5. Tests: verify links, no network/registry call, random-store prune property, peer fuzzer
   property (bundle with any byte flipped is refused whole or re-verifies), command tests.
6. VM check in `src/testing/vm/main_m8.zig` (verify offline, link down); `docs/demos/m8.md`.

## Decisions and traps
- W0901 already means "provenance store is full" (slice 4), so verify's absent-input warning
  is W0903 and prune's is W0902. The brief names W0902 only: the supervisor must confirm W0903.
- Test binary static data is within ~1 GiB of the 2 GiB relocation limit: a test file with its
  own `var files: SimFs` fails to link. Heap-allocate `SimFs`, `HostSim` and workspaces in tests
  (see `peer_tests.zig` `start`).
- SimFs holds at most 640 nodes, so the `trust_records_max` bound test lowers the limit through
  `scan_limited` instead of creating 4096 orphans (a cut; say so in `docs/demos/m8.md`).
  Import's `store_full` (4096 records) mirrors sign's `is_full` and is not tested in the sim.
- A damaged/newer result record is "unknown": prune keeps its provenance. A damaged signature
  record of a present tree is kept and warned (W0902); of an absent tree it is removed.
- Verify design: operand = result, tree or `name@sha256:`; link 1 record loads and verifies;
  link 2 signer trusted by policy files (`gate.load`) and/or `--key`/`--public`; link 3
  `tree_check.check`; link 4 first trusted provenance line that fits is compared with the
  stored record; link 5 bases, step inputs/outputs present and sound (absent: W0903, failure
  only with `--strict`; damaged: E0908); link 6 build file and lock digests if present.
  Derived-result binding (slice 14) is cut for verify. Sim hosts report owner 0, so only the
  VM proves the tree check's object ids.
