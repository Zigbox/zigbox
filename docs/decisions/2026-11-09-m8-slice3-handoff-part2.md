# M8 slice 3, part 2: handoff

Decisions:
- The tamper check is a callback (`image.Check`) in `StartOptions.tree_check`, called in the store
  child after the tree is found and before `materialize.ensure`; runtime does not import trust.
- It runs whenever any policy file is loaded (even with no rules); the strictest `verify` wins.
- Order: verdict, then tamper, then start. Only `run` is wired; `exec` and build steps are not.
- The record is a cache: written with `write_atomic`, no store lock, errors ignored, bad files
  ignored. The entry keeps the stat from before the hash.
- Only E0907 was registered. E0906 is not (slice 4).

Traps: tidy counts asserts only in `shipped_files` (trust files are not); the golden generator is
not a tool, so a change to the E0907 text needs the goldens rewritten from the test's failure.
Merge note: part 1's review fixes remove the E0904/E0905 claims that `exec` and `build` are
gated; this branch still has them, so they conflict or need re-adding at merge.
Next: tamper check in `exec`/build steps, demo steps 3 and 4, README and site status.

## `zbx sign` runs in the store's namespace (found by the VM, fixed here)

VM run 131 showed `zbx sign` refusing a freshly pulled tree with E0910 ("a file of the tree in
the store is damaged"). Cause, a slice-2 bug that no simulation could show: `sign` opened the
store in the parent, where `lstat` gives the real owner (uid 1000), while object ids are hashed
with the container's owners (0), so `check_object_alone` rehashed every file of any tree an
ordinary user had pulled to a different id. `store verify`, `run` and the tamper check already
run in the store's namespace child. `sign_commands.run_in_namespace` now does the same: the
whole command runs in the child, which renders its own failure as `store` does. `Output` gained
`mode` and `color` (defaults keep the tests unchanged). Lesson: the simulation hosts report
owner 0, so a test of any command that rehashes objects needs the VM to be believed.
