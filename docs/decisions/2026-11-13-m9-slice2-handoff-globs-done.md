# M9 slice 2, third implementer: handoff

*Decided 2026-11-13, by the slice.*

Built and pushed on `claude/m9-slice2` (commit `d1d7623` and the note commit after it):
the E0818 registration with the glob pool bound and the copy-chown decision
(`2026-11-12-m9-glob-pool-and-copy-chown.md`), and item 2, input globs and `.exclude`.

## Item 2, what it is

- `input_tree.Request` gained `inputs` and `exclude` (both optional; null means the step's own).
- A fixed pool, `Matches` (`build_glob_matches_max` entries, `build_glob_pool_bytes_max` bytes), holds
  every matched path. `collect` fills it (globs by an iterative scan stack, plain inputs as they
  are), the order is heap-sorted by `component_less`, and `drop_covered` merges overlaps. A full
  pool is E0818. A glob with no match is refused as `.missing`.
- Exclude lines are the file's, the step's and a third span (for a copy entry), read as one list
  (`build_exclude_chain_max`); the last matching line wins, parent directories count.
- **Divergence to document in `docs/demos/m9.md`:** with no `!` line an excluded directory is
  skipped wholesale; with any `!` line present excluded directories are still entered, so empty
  directories can result.
- `graph.unrunnable` no longer refuses `.exclude` or glob inputs. Tests are in
  `input_tree_tests.zig`. `zig build test` and `zig build tidy` pass on `d1d7623`.

## Not built (still refused with E0802 where a guard exists)

Item 1 copy steps; item 3 `.caches`, `.binds`, `--clear-caches`; item 4 `image.base = "step:"`
and a named `config.user`; item 6 step.zig doc comment and root-output tests; item 7 simulator and
`docs/demos/m9.md`; item 8 `vm.yml` m9 entry. `zig build check` was NOT run on the final commit and
no VM demo was run.

## Design for item 1 (unchanged from the previous plan, with the supervisor's answers)

- Copy steps are keyed and cached in the parent in `compose.begin`, with no container, in a new
  `copy.zig` and a new synchronous-miss `schedule.Begin` outcome. They use `spec.root_output = true`
  and the empty-inputs digest (`key.compute` asserts `argv.len + copies.len > 0`).
- A project source is imported by `input_job` in the user-namespace child using `Request.inputs` and
  the entry's `src` patterns, with the three exclude spans; an owner/mode override at import is not
  in `Request` yet. A `step:` source uses that step's output tree; a locked image uses its tree.
- `copy.select` re-matches the src patterns on the source tree and layers results with a
  replace-merge: give `assemble` a `replace: bool` so a non-dir/dir conflict emits the later entry
  while dir+dir still merges.
- Chown is never done in the parent; writes that set owners go through the child job.
- Suggested cut, to record in `docs/demos/m9.md`: a copy from a `step:` or image source with
  `.chown`, `.chmod` or `.exclude` stays guarded (E0802).
- Item 3 follows `2026-11-12-m9-cache-mount-kind.md`; `step.zig`'s `mounts_count` must grow with a
  comptime assert against `mounts_max`. Remove each `unrunnable` guard as its feature lands.

## Traps found

- `zig build test` and `zig build` take over two minutes: run them in the background to a file.
- `git push -u origin claude/m9-slice2` is rejected by a push-tool quirk; use
  `git push origin HEAD:refs/heads/claude/m9-slice2`.
- tidy rejects `assert(a and b)` and `catch unreachable` without a comment on the same or previous
  line; run the tidy binary directly (`./.zig-cache/o/<hash>/tidy`) to see every violation, as
  `zig build tidy` output truncates them.
- In the input-tree tests, `entry_of` leaves `out` pointing at the last decoded entry when it
  returns false; use the `has(root, "a/b")` helper instead of chaining `entry.subtree`.
