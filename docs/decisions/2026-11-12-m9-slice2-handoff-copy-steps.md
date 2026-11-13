# M9 slice 2, second implementer: handoff

*Decided 2026-11-12, by the slice.*

Built and pushed on `claude/m9-slice2`: the cache-mount-kind decision
(`2026-11-12-m9-cache-mount-kind.md`) and item 5 (E0804 gets a second fix, `.from = "step:NAME"`,
when the unlocked base is a step's name; `diagnose.step_name_hint`, called from
`Context.load_base`). Unit tests pass; `zig build check` was not run on the final commit.

Not built, in the brief's order: copy steps and their replace-merge; input globs and `.exclude`;
`.caches`, `.binds`, `--clear-caches` (use the cache mount kind); `image.base = "step:"` and a
named `config.user`; the simulator coverage; the step.zig doc comment and root-output tests;
`docs/demos/m9.md`; the `vm.yml` m9 entry. `graph.unrunnable` still refuses each of these (E0802).

Plan found for the next implementer: generalise `input_tree.Request` to take an explicit input
list and exclude lines (file, step and entry), expand globs on disk before the walk and skip
excluded paths in `drain`, so item 2 and a copy from the project share one path. Then `copy.zig`:
`select` lays out the kept entries under `to`, and `key.Copy.source` is the digest of that
selection, so an excluded file never changes the key. The replace-merge is `assemble.zig`'s merge
with dir+dir merged and anything else replaced by the later source. A matched-path pool is a new
bound: ask the supervisor first. Tree writes run in the parent as `assemble_image` does (under the
store's shared lock); confirm before relying on it for chown.
