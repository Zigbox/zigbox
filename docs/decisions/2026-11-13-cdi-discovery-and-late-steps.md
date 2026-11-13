# CDI: spec directory order, late ldconfig, read-only refusal

Date: 2026-11-13. Context: review of PR 130 (M10 slice 2).

- **Order.** Specs are read from `$XDG_CONFIG_HOME/cdi` (else `$HOME/.config/cdi`), then
  `/var/run/cdi`, then `/etc/cdi`; a device in an earlier directory wins, as in the reference
  implementation. At most 64 spec files in all (`cdi_dir_entries_max`), in name order; more is
  E0226. The old limit of 16 was a silent cut.
- **ldconfig.** The `update-ldcache` hook runs as the last step before `exec`, after sealing,
  capabilities and seccomp, with a 10 second alarm. A failure or timeout falls back to
  `LD_LIBRARY_PATH` (W0208). The earlier placement ran before sealing, with no time bound.
- **Read-only.** Mount targets cannot be created in a read-only root, so `--read-only` with a
  device that has mounts is refused before anything starts, with E0227. No new code is registered.
