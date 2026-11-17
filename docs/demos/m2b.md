# M2b demo: workload knobs

This document grows slice by slice. Slice 3 writes the demo (`zig build demo-m2b`) and the rest
of this document. Slice 2's fix records its cuts and an upgrade note here first.

## Cuts and deviations

- **The cgroup view under `--net host` sits on a cover, not on a partial bind of /sys**
  (slice 2). The brief's fallback, if the view could not be mounted over the bound host `/sys`,
  was to bind only the parts of `/sys` that are not `fs/cgroup`. Slice 2 instead covers
  `/sys/fs/cgroup` with a small read-only tmpfs and mounts the view on it, in every network mode
  ([decision](../decisions/2026-11-17-m2b-cgroup-cover.md)).
- **Under `--net host`, the host's cgroup2 stays listed in mountinfo** beneath the cover and the
  view, with the root `/../../../../..`. The view is the last entry on `/sys/fs/cgroup`, with root
  `/`, and the only one a path lookup reaches. A tool that takes the first cgroup2 line for that
  path reads the host's entry instead.

## Upgrade notes

- **`zbx doctor --json` (`zbx.doctor/1`): `checks` grows.** Slice 2 adds the `host-settings`
  check, in the middle of the array, and a new value of the `id` enum; earlier checks after it
  move one place down. Readers should find a check by its `id`, never by its position, and accept
  `id` values they do not know. The new top-level `host_settings` object is additive. Upgrading
  `zbx` alone is enough; no stored record changes.
- **`zbx exec` joins the container's cgroup namespace** (slice 2). An exec'd command in a scoped
  container reads `0::/` in `/proc/self/cgroup` and sees the view, as the container's own command
  does. A container started by a release before slice 2 has no cgroup namespace of its own, so
  an exec into it stays in zbx's, as before; restart the container to give it one. demo-m6b's
  EXEC 3 checks for `0::/` now, where it checked for the scope's host path before.
