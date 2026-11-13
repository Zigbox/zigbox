# M9 slice 2, part 1: root output, `.user`, `.workdir` and `step:` bases run

Status: part 1 of slice 2 (the rest is not built). Written for the next implementer.

## Decisions

- **A root step commits its upper layer before `run.discard`.** `step.zig` has a new `commit`
  action that calls `import.commit` with the step's base tree as parent, the mount points as the
  exclude list, `refuse_special` (E0806), `save_root` and `keep_existing_root`. A root step skips
  the `/out` import and has no `/src` or `/out` mounts; its workdir is `/` unless `.workdir`.
- **`.user` is resolved in the worker against the step's base tree** with `image_user.resolve`.
  A missing name is E0817, raised when the step is about to start (a miss), not when the file is
  loaded: a `step:` base exists only after earlier steps ran. `HOME` comes from the resolved
  home (`/` if the passwd entry has none). The key already carries the `.user` text and the base
  tree digest, so a name's meaning cannot change under a hit.
- **A step with `.user` gets a writable `/out`** (mode 0777), so a non-root user can write it.
- **`step:` bases.** `compose.resolve_base` follows `graph.base_step` to the chain's start; the
  tree is the earlier step's output, the platform and environment come from the start image.
  The trust gate (`check_base`) runs only for a locked-image base: a derived tree has no
  statement of its own, and the gate judged the start image when it was first used.
- **The scheduler plan** is fed from `graph.after_slice`, so a base or a copy source orders a
  step after the one that makes it. `Plan.needs` is wider (`build_step_edges_max`).
- **E0802 guards removed** for `.output = .root`, `.user`, `.workdir` and a `step:` base.
  Still guarded: `.exclude` (file and step), `image.base = "step:"`, a named `config.user`,
  `.copy`, `.caches`, `.binds`, input globs.
- **E0817's wording** already says the refusal can come mid-build; the explanation, error page
  and goldens agree.
- The PR #122 review SHOULDs are done (`.dockerignore` matcher gaps in `glob.zig` and the fuzzer;
  the `config.user` test).

## Not built (next slices of this work)

1. `copy` steps: a new module over store trees. `assemble.zig` merges without overwriting and
   refuses a conflict, so copies need their own replace-merge (later files win), glob and
   `.exclude` against the source tree, `.chown` names against the destination tree, `.chmod`,
   missing parents `0755 0:0`, and a `key.Copy.source` that is the digest of the kept subtree.
2. Input globs and `.exclude` (file- and step-level) in `inputs.zig` / `input_tree.zig`.
3. `.caches` (dir under `build/caches/<project hash>/<id>`, one runner per id, report mark
   `cache`, W0802 once per build, `--clear-caches`) and `.binds`. `step.zig`'s `mounts_count` is
   still `build_step_needs_max + 2`: grow it for binds and caches, with a comptime assert on
   `mounts_max`.
4. `image.base = "step:"` and named `config.user` (result.zig / assemble.zig).
5. The simulator (random root and copy chains, crashes at every write), the VM check and its
   harness (`demo-m9`, a `m9` case in `.github/workflows/vm.yml`), `docs/demos/m9.md`,
   `zbx explain`/error pages for anything new, and `--clear-caches` help and schema.
6. A bare `.from = "build"` that finds no image should hint `step:build` when such a step exists.

## Open question for the supervisor (blocks item 3)

A `.caches` step with a non-root `.user`: the run refuses writable `.mount` kind mounts whose
source is outside `project` (`check_user`), and the cache directories live under the store, not
the project. Options: (a) a new mount kind for caches that skips that rule; (b) relax the rule
for sources under the store's caches root; (c) refuse the combination with a new code. (c) needs
a registered code, so it needs the owner's answer.

## Traps

- `key.Spec` has defaults for the M9 fields: build it with a literal, never `= undefined`.
- `run.discard` removes the layers: anything that reads the upper layer must come before it.
- `image_user.Workspace` is about 4.25 MiB; `step.Workspace` now holds one.
