# M9 slice 2: handoff after the input-tree root (items 3, 6 and 7 not started)

*Written 2026-11-13 by the implementer that did item 1 and stopped at the turn ceiling.*

## Done

- **Item 1, input trees.** `input_job.import` roots a copy entry's source tree (`root_input`: kind
  `import`, source `build:<step>`, written only when the digest has no record, so a root the user
  made is kept) before the import child exits. `Context.begin_copy` drops it with `unroot` once the
  selection is made (`defer ... if (entry.from == null)`). Tests in `compose_tests.zig`: root
  between import and selection and a user's root kept; a finished copy leaves none; a failing root
  write is one diagnostic.
- **The premise was off.** The task said "as for a command step's". A command step's imported
  input tree is *not* rooted: `begin` imports it, then looks it up and forks the worker, and the
  worker's `prepare` reads the tree later. The same window exists there; it was left alone
  (not asked for). Rooting it is the same two calls around `import_inputs(index, null)` in
  `Context.begin`, dropped in `settle`/`abort_step`.
- **Still unrooted:** the copy's *selection* tree (the `copy_select` result) between its write
  and `copy_assemble`. Fix with the same pattern if review wants it.
- Branch trap: the local `claude/m9-slice2` ref was 14 commits behind origin and HEAD was
  detached; `git checkout -B claude/m9-slice2 <commit>` fixed it. Check `git status -sb` first.

## Not done (in the order the task gave)

### Item 3: `.caches`, `.binds`, `--clear-caches`

Nothing written. Parse, key (`key.Bind`, tag 15) and the file-level mount sum (`check_mounts`)
exist. What is missing is all of the plumbing:

1. `runtime/mounts.zig`: `Kind.cache`, writable, exempt from the writable-inside-project rule only
   for a source under the store's caches root (decision `2026-11-12-m9-cache-mount-kind.md`).
2. `step.zig`: `mounts_count` becomes `constants.mounts_max` (the parser already holds the sum of
   needs, binds, caches and `/src` `/out` to 8); `build_mounts` appends binds (read-only) and
   caches. `prepare` makes `build/caches/<project hash>/<id>` (mode and uid/gid from the cache
   entry, in container ids, applied only when first made), then chowns it to the step's mapped
   user before start. Non-root `.user` with a writable `/out` is refused by `needs_root` today:
   `/out` should use the `cache`-style exemption too, or a dedicated kind (not decided).
3. `key.Spec` gets no cache field (the brief: not in the key). `binds` comes from `step.binds`:
   a project path is imported as a tree (`input_job` with a bind variant, like a copy entry) and
   a `step:` source is that step's output, its subpath selected the way `copy_select` does. A
   locked-image source is not built: refuse it and record the cut in `docs/demos/m9.md`.
4. `compose.make_plan`: add an edge between every pair of steps that share a cache id, in file
   order, so they run one at a time. `schedule.Plan.needs` has `build_step_edges_max` slots; check
   the sum still fits.
5. `report`: the `cache` marker beside `net`, an additive JSON member (document it in
   `schemas.zig`, update the testdata golden; `zbx.build/1` only grows). `warn_caches` once per
   build with the registered `W0802` (`diagnose.cache_steps` exists; model it on `warn_network`).
6. `--clear-caches` in `cli`, help and the schema; it empties `build/caches/<project hash>`.
   Cuttable per the brief if time is short: say so in `docs/demos/m9.md`.
7. Remove the `.caches` and `.binds` lines from `graph.unrunnable` last, once a build runs them.

No new code or user-visible bound is needed by this design. The copy cuts (`.chown`, `.chmod`,
locked-image source, `.exclude` on a `step:` source) are still refused, as asked.

### Item 6: root-output tests. Not started (the doc comment in `step.zig` was done earlier).

### Item 7: the random-chain simulator with crashes at every write

Not started. The brief frames it as a simulator ("random chains of root and copy steps with
crashes at every write; a copy is a pure function of its sources; a cache never changes a key").
Do it as a seeded fuzzer: a new `src/fuzz_<name>.zig`, registered in `src/fuzz.zig`, using
`fs_sim.Faults.crash_mutation` as `src/fuzz_store.zig` does; run `zig build fuzz -- all`.

## Next implementer

Start from the brief, this branch and this note. One slice's worth is item 3 (it needs the
runtime mount kind first), then 6 and 7. `docs/demos/m9.md` still says input trees are unrooted:
update that line for the copy source.
