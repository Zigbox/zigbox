# The tamper check compares the materialized farm with the tree

Date: 2026-11-09. Context: review of PR #74 (M8 slice 3 part 2), MUST at `image.zig:372`.

## Problem

The brief ("The tamper check") says one inode and one check cover both the store's objects and
the farm `cache/<tree hex>`, because the farm hardlinks the objects. That is true only for an
edit in place. `materialize.ensure` reuses an existing farm without looking at it, and the farm is
the overlay lower layer, so a directory operation on the farm changed what runs without E0907:
a file replaced by rename (new inode), an entry added, an entry removed, a symlink retargeted.

## Decision

After the objects pass, `tamper.check` compares the farm with the tree, on every checked run
(`verify = "cached"` too): per entry one `lstat` (a file must be the same inode as its object; a
link must have the tree's owner and target; a directory the tree's mode and owner), and per
directory one `read_dir` whose name count must equal the tree's. The root's own mode and owner are
compared as well. A difference is E0907 with cause "in the image's materialized directory"; a
tree past the walk bounds is E0907 `too_large` with a fix line naming the limit.

The check refuses and never repairs: removing a farm that a running container has as its overlay
lowerdir is unsafe. The fix line tells the user to remove the directory under `cache/` and run again.

## Limits (also in the E0907 explanation and `docs/demos/m8.md`)

- Extended attributes and times of directories and links are not compared.
- A change between the check and the container start is not seen (as for objects).
- The brief's "one inode covers both" is wrong for directory operations; it is not edited (merged
  briefs are never edited), this file corrects it.

## Tests and the bound

`src/trust/tamper_tests.zig`: one test per farm change, a test that the record is believed (a
change with no ctime bump passes cached, fails with `always`), and a partial-collector test
(no re-sort once full: `Workspace.compactions`). The bound at 65536/65537 uses a test-only
`tamper.check_capped(cap)` (the same code path as `check`, which passes
`trust_verified_entries_max`): real 65537-file trees are too slow in the simulation. The fuzzer
`verified` (`src/fuzz_verified.zig`, run by `zig build fuzz -- all`) covers the record format
(canonical-or-ignored, exact bound, store integration).
