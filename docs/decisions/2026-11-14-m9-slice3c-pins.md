# M9 slice 3c: output pins, the implementer's picks

*Decided 2026-11-14 by the slice 3c implementer, within the rulings of
[2026-11-14-m9-pinned-fetches-and-output-pins.md](2026-11-14-m9-pinned-fetches-and-output-pins.md).
Review may overturn any of them.*

- **Key tag 20 is `output_exclude`.** Tags 17 to 19 are left for slice 3b's fetch fields, so the
  two slices do not collide when merged.
- **A pin's `.file` is the build file's path relative to the project directory** (`shown()`), not
  an absolute path, so the lock stays valid when the project moves.
- **`.output_exclude` on a step whose output is a copy is refused** (a new problem kind,
  `output_exclude_on_copy`, under the existing build file code E0801): a copy's output is what
  it copies, so a path is left out by not copying it.
- **`--locked` with `--hermetic` is `--hermetic`**; both refuse drift (E0822). Only `--pin` with
  `--locked` is E0005.
- **A stale pin's fix names `zbx build --pin`**, which replaces it; there is no `--repin`.
- **A lock with no pins is written as version 1**, byte for byte M7's, so a project that never
  pins sees no change.
