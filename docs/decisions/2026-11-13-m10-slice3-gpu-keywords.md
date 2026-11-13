# M10 slice 3: `--gpu` is a keyword in the device list

Decided 2026-11-13 (implementer, slice 3; assumption, no owner answer).

- `--gpu all|dri` is carried as `gpu=all` or `gpu=dri` in the existing device list. The run
  record, `ps`, `inspect`, `exec` and `restart` therefore need no format change, and the record
  keeps what was asked. Record v10's vocabulary grew with no version bump: no release tag exists.
- Expansion (`gpu.expand`, a pure function; `run.zig` `expand_gpu` is its one caller in a run)
  happens at start. A run with no keyword takes no host look, so it is unchanged byte for byte.
  More than `run_devices_max` (16) devices after expansion is E0225.
- `all` is every `nvidia.com/gpu` CDI device if a spec offers any, else `dri`. E0230 (no such
  spec) and E0226 (spec trouble) fall back to `dri`; **E0225 and E0227 stay raised**, because a
  spec that names a device the host cannot give, or edits we refuse, is a fault to report, not
  one to hide behind a render node.
- `inspect` shows what was asked only; see `docs/demos/m10.md` (deviation).
- Mac: `macos_main.zig` scans a container run's arguments for `--device` and `--gpu` (with `=`)
  and raises E0229.
