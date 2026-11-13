# M10 slice 3: `--gpu` is a keyword in the device list

Decided 2026-11-13 (implementer, slice 3; assumption, no owner answer).

- `--gpu all|dri` is carried as `gpu=all` or `gpu=dri` in the existing device list. The run
  record, `ps`, `inspect`, `exec` and `restart` therefore need no format change, and the record
  keeps what was asked. Record v10's vocabulary grew with no version bump. v0.5.0 also writes v10 and ignores unknown
  fields, so a record with `gpu=...` read by 0.5.0 (a downgrade, or a shared store) starts the
  container with no devices and no diagnostic. Upgrade zbx everywhere before using `--gpu`; the
  gap began with slice 1's `.devices` and is not made worse by the keywords.
- Expansion (`gpu.expand`, a pure function; `run.zig` `expand_gpu` is its one caller in a run)
  happens at start. A run with no keyword takes no host look, so it is unchanged byte for byte.
  More than `run_devices_max` (16) devices after expansion is E0225.
- `all` is every `nvidia.com/gpu` CDI device if a spec offers any, else `dri`. E0230 (no such
  spec) falls back to `dri`; **E0225 and E0227 stay raised**, because a spec that names a device
  the host cannot give, or edits we refuse, is a fault to report, not one to hide behind a
  render node. E0226 (a spec file that cannot be used) stays raised only when the host has the
  NVIDIA driver (`/proc/driver/nvidia/version` or `/dev/nvidiactl`): there nvidia-drm makes a
  render node, so a YAML or stale NVIDIA spec would start the run with no driver (review of
  #135). With no NVIDIA driver the file is another vendor's, so `all` falls back to `dri`, and
  if that finds nothing E0228 names the unusable spec as a cause (re-review of #135).
- Only `all` reads the CDI specs. `dri` is the render nodes with no vendor tooling, so no spec,
  usable or not, can refuse it.
- `inspect` shows what was asked only; see `docs/demos/m10.md` (deviation).
- Mac: `macos_main.zig` scans a container run's arguments for `--device` and `--gpu` (with `=`)
  and raises E0229.
