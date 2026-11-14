# M9: a build file's log and cache group is hex only

*Decided 2026-11-14, by M9 slice 4 (branch `claude/m9-slice4`), on the supervisor's ruling.*

`step.log_group` named a build file's group with the first 16 bytes of `Digest.text()`: `b3:`
and 13 hex digits. The group names `build/logs/<group>/` and, since M9 slice 2,
`build/caches/<group>/`, whose entries are mounted into a step. A mount's host path may not hold
a `:` (`state/volume.zig`, `path_problem`), so every step with a cache mount was refused with
E0012. The first VM run of `demo-m9` that reached the `tools` stage showed it (run 43539794957).
The unit tests did not, because they used a made-up group, `0123456789abcdef`.

- **The group is the first 16 hex digits of the digest of the build file's absolute path**,
  without `b3:`. `log_group` asserts that it holds no `:`. A test checks that the cache path
  passes the mount check and fails without the fix, and the `--clear-caches` test takes its
  groups from `log_group`.
- **Readers.** Only `step.zig` builds these paths: the run's log copy, the cache mounts and
  `--clear-caches` (`remove_caches`), all through `request.group`. gc does not walk
  `build/logs` or `build/caches`, and no command lists them.
- **Existing stores.** Cache directories exist only from M9 slice 2 on, which no release has
  (v0.5.0 does not contain it), so no store holds a `b3:` cache directory. v0.5.0 does write
  `build/logs/b3:<13 hex>/`. Those directories are now never written or read again. Each holds
  one plain-text log per step, the last run's, so they are left in place: not worth a migration.
  Removing `build/logs` by hand is safe.
