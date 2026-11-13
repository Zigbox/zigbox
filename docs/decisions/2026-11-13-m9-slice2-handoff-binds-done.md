# M9 slice 2 handoff: binds, clear-caches, cache marker, W0802 done

Date: 2026-11-13. Branch `claude/m9-slice2`. Follows `2026-11-13-m9-slice2-handoff-caches-binds.md`.

## Built

- **`.binds` from a `step:` output** (`compose.zig` `resolve_binds`, `bind_select`): the bind's
  `.source` is selected in the earlier step's output with `copy.select`; the selection digest
  is in `key.Spec.binds` and `step.zig` mounts it read-only at `.to`. Nothing matched is E0803
  (`diagnose.bind_nothing`).
- **Still E0802, for good** (`graph.zig` `bind_unrunnable`): a bind from the project's files, from
  an image, and a `.binds` on a copy step. The explain text and `site/errors/E0802.html` say so.
- **`--clear-caches`** (`cli.zig`, `compose.Options.clear_caches`, `step.clear_caches`): empties
  `build/caches/<group>` in the namespace child under the exclusive store lock; busy is E0436.
  `--graph --clear-caches` is accepted and clears nothing (documented in `docs/demos/m9.md`).
- **Report marker**: `cache` after `net` in text; `"caches":true` in JSON only for such steps
  (additive; `schemas.zig` and the goldens updated). **W0802** is printed once on stderr.
- `Action` in `step.zig` gained `clear_caches`; `is_store_wide` covers it and `sweep`.

## Traps

- A project bind's `.source` is a relative project path, a `step:` bind's is absolute (parser).
- The help text is within about 100 bytes of its 16 KiB bound: the next help addition must trim.
- `compose.Context.resolve_binds` is `pub` only so `compose_tests.zig` can call it.
- A single-file bind source mounts a directory holding that file (recorded in `m9.md`).

## Not done / not run

- No VM demo (the cloud container is no test host). Item 6 (root-output tests) and item 7
  (random-chain fuzzer) belong to `claude/m9-slice2-tests`.
- A non-root `.user` with a writable `/out` stays `needs_root` (decision file of this date).
