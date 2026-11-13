# M9 slice 2: root-output tests, the commit-roots fix, and two unrooted-tree gaps

Date: 2026-11-13. Branch: `claude/m9-slice2-tests`.

## Decisions

- `import.commit` now saves the label root itself when `options.save_root` and `options.label` are set
  (`src/store/import.zig`). Before, a root step's committed output (`step.commit_output` sets all three)
  was never rooted, so a later `store gc` could take it. `store_commands.zig` callers set no label and
  are unaffected. Test: `src/build/step_root_tests.zig`, root-count assertions.
- Root-output tests go in a new file, `step_root_tests.zig`, chained from `step_tests.zig`
  (not `main.zig`, whose `test` block is at the 70-line tidy limit).
- Fuzzer `build_chain` (`src/fuzz_build_chain.zig`, registered in `src/fuzz.zig`): random chains of root
  and copy steps, a clean run for expected digests, a crash-at-mutation run that restarts, runs
  `check_whole` and reruns to the same digests, a purity check and a key check.
  `zig build fuzz -- build_chain 7 10000` passes.

## Known gaps, not closed

- A copy's selection tree has no root between its write and the cache entry. Pinned by the test
  "KNOWN GAP: a copy's selection tree has no root ..." in `src/build/compose_tests.zig`, which asserts
  0 roots at the first rename into `/build/cache`. When the gap is closed the count becomes 1: turn the
  test round then. Closing it means rooting in `compose.copy_select` and dropping it in `unroot`;
  it touches the code the other M9 slice 2 session is changing, so it is left for after that merge.
- A command step's input tree is unrooted between its write and use. No test yet; same fix shape
  (`input_job.root_input`).
