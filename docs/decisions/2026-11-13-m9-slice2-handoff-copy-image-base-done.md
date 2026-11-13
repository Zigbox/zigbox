# M9 slice 2: handoff after copy steps, `image.base = "step:"` and named `config.user`

Branch `claude/m9-slice2`. Built and unit-tested here; no VM demo ran; `zig build check` result is
in the report that came with this file.

## Done since the globs handoff

- **Copy steps** (item 1). `copy.zig` selects a source tree's matches under `.to`
  (`normalise`, `collect` with a resumable frame stack, `place`); `assemble.Context.replace` makes
  a later non-directory entry replace an earlier one (two directories still merge);
  `compose.begin_copy` imports a project source through `input_job` (`Request.entry` passes the
  entry's `.src` and `.exclude`), uses a `step:` source's output, keys the selection digests
  (`key.Copy`, `root_output = true`), looks up, assembles over the base under one shared lock,
  records, and returns `.hit` (the row says `miss` the first time: `report(.., false, ..)`).
  Guarded as E0802 in `graph.copy_unrunnable`: `.chown`, `.chmod`, a locked-image source, an
  `.exclude` on a `step:` source.
- **`image.base = "step:"`** (item 4): `build_image` takes the step's output as the base tree and
  the chain start's image for the config; provenance names the chain start (`graph.chain_start`).
- **Named `config.user`** (item 4): `Context.numeric_user` resolves it in the result's tree after
  the lookup (hit or miss) and stores `uid:gid`; E0817 if absent. The key has the name.
- Item 6: the `step.zig` doc comment. Root-output tests were not added.
- Item 7: `docs/demos/m9.md` (cuts and deviations), a purity test for `copy.select`.

## Not done

- **Item 3** (`.caches`, `.binds`, `--clear-caches`) is untouched: still E0802. Follow
  `2026-11-12-m9-cache-mount-kind.md`.
- **Copy `.chown`/`.chmod`**, image sources, step-source `.exclude`: guarded. Needs a write in the
  namespace child (owner is part of the object id).
- **The simulator** (random chains of root and copy steps, crashes at every write) was not
  written; only unit tests and the purity test.
- **Item 8** (`vm.yml` m9 entry): not added. `demo-m9` does not exist in `build.zig` (it is slice
  4's), so an entry would run a missing target. No `vm/m9-slice2` push was made.
- The slice's VM check (adduser, copy with `--chown`, run as the user) needs the above.

## Traps

- A copy step has no `/src` input: `begin` skips `import_inputs` for it and sets the key's
  `input_tree` to the zero digest.
- `schedule.Begin.hit` from `begin_copy` is synchronous; `report` counts the miss itself.
- `fs_sim.put_file` asserts the path is free: use `remove_path` first.
- `zig build test` takes about 2 minutes; run it with output to a file.
